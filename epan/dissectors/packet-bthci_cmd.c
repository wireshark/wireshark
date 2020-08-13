/* packet-bthci-cmd.c
 * Routines for the Bluetooth HCI Command dissection
 * Copyright 2002, Christoph Scholz <scholz@cs.uni-bonn.de>
 *  From: http://affix.sourceforge.net/archive/ethereal_affix-3.patch
 *
 * Refactored for wireshark checkin
 *   Ronnie Sahlberg 2006
 *
 * Updated to HCI specification 2.1 + EDR
 *   Allan M. Madsen 2007
 * Updated to HCI specification 3.0+HS & 4.0
 *   Allan M. Madsen 2012
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/decode_as.h>
#include <epan/tap.h>
#include <epan/proto_data.h>

#include <wsutil/utf8_entities.h>

#include "packet-bluetooth.h"
#include "packet-bthci_cmd.h"
#include "packet-bthci_evt.h"
#include "packet-btsdp.h"
#include "packet-btatt.h"

static int proto_bthci_cmd = -1;

static int hf_bthci_cmd_opcode = -1;
static int hf_bthci_cmd_ogf = -1;
static int hf_bthci_cmd_ocf = -1;
static int hf_bthci_cmd_ocf_link_control = -1;
static int hf_bthci_cmd_ocf_link_policy = -1;
static int hf_bthci_cmd_ocf_host_controller_and_baseband = -1;
static int hf_bthci_cmd_ocf_informational = -1;
static int hf_bthci_cmd_ocf_status = -1;
static int hf_bthci_cmd_ocf_testing = -1;
static int hf_bthci_cmd_ocf_logo_testing = -1;
static int hf_bthci_cmd_ocf_low_energy = -1;
static int hf_bthci_cmd_param_length = -1;
static int hf_bthci_cmd_lap = -1;
static int hf_bthci_cmd_inq_length = -1;
static int hf_bthci_cmd_num_responses = -1;
static int hf_bthci_cmd_encrypt_mode = -1;
static int hf_bthci_cmd_bd_addr = -1;
static int hf_bthci_cmd_packet_type = -1;
static int hf_bthci_cmd_packet_type_dh5 = -1;
static int hf_bthci_cmd_packet_type_dm5 = -1;
static int hf_bthci_cmd_packet_type_3dh5 = -1;
static int hf_bthci_cmd_packet_type_2dh5 = -1;
static int hf_bthci_cmd_packet_type_dh3 = -1;
static int hf_bthci_cmd_packet_type_dm3 = -1;
static int hf_bthci_cmd_packet_type_3dh3 = -1;
static int hf_bthci_cmd_packet_type_2dh3 = -1;
static int hf_bthci_cmd_packet_type_reserved_5_7 = -1;
static int hf_bthci_cmd_packet_type_dh1 = -1;
static int hf_bthci_cmd_packet_type_dm1 = -1;
static int hf_bthci_cmd_packet_type_3dh1 = -1;
static int hf_bthci_cmd_packet_type_2dh1 = -1;
static int hf_bthci_cmd_packet_type_reserved_0 = -1;
static int hf_bthci_cmd_clock_offset = -1;
static int hf_bthci_cmd_clock_offset_valid = -1;
static int hf_bthci_cmd_allow_role_switch = -1;
static int hf_bthci_cmd_page_scan_mode = -1;
static int hf_bthci_cmd_page_scan_repetition_mode = -1;
static int hf_bthci_cmd_page_scan_period_mode = -1;
static int hf_bthci_cmd_max_period_length = -1;
static int hf_bthci_cmd_min_period_length = -1;
static int hf_bthci_cmd_connection_handle = -1;
static int hf_bthci_cmd_reason = -1;
static int hf_bthci_cmd_num_link_keys = -1;
static int hf_bthci_cmd_link_key = -1;
static int hf_bthci_cmd_packet_type_hv1 = -1;
static int hf_bthci_cmd_packet_type_hv2 = -1;
static int hf_bthci_cmd_packet_type_hv3 = -1;
static int hf_bthci_cmd_role = -1;
static int hf_bthci_cmd_acr_role = -1;
static int hf_bthci_cmd_pin_code_length = -1;
static int hf_bthci_cmd_pin_code = -1;
static int hf_bthci_cmd_pin_type = -1;
static int hf_bthci_cmd_encryption_enable = -1;
static int hf_bthci_cmd_key_flag = -1;
static int hf_bthci_cmd_max_interval_hold = -1;
static int hf_bthci_cmd_min_interval_hold = -1;
static int hf_bthci_cmd_max_interval_sniff = -1;
static int hf_bthci_cmd_min_interval_sniff = -1;
static int hf_bthci_cmd_sniff_attempt = -1;
static int hf_bthci_cmd_timeout = -1;
static int hf_bthci_cmd_max_interval_beacon = -1;
static int hf_bthci_cmd_min_interval_beacon = -1;
static int hf_bthci_cmd_flags = -1;
static int hf_bthci_cmd_flow_direction = -1;
static int hf_bthci_cmd_service_type = -1;
static int hf_bthci_cmd_token_rate = -1;
static int hf_bthci_cmd_token_bucket_size = -1;
static int hf_bthci_cmd_peak_bandwidth = -1;
static int hf_bthci_cmd_latency = -1;
static int hf_bthci_cmd_delay_variation = -1;
static int hf_bthci_cmd_link_policy_setting_switch = -1;
static int hf_bthci_cmd_link_policy_setting_hold = -1;
static int hf_bthci_cmd_link_policy_setting_sniff = -1;
static int hf_bthci_cmd_link_policy_setting_park = -1;
static int hf_bthci_cmd_filter_type = -1;
static int hf_bthci_cmd_inquiry_result_filter_condition_type = -1;
static int hf_bthci_cmd_connection_setup_filter_condition_type = -1;
static int hf_bthci_cmd_cod_class_of_device_mask = -1;
static int hf_bthci_cmd_cod_minor_device_class_mask= -1;
static int hf_bthci_cmd_cod_format_type_mask = -1;
static int hf_bthci_cmd_cod_major_service_class_information_mask = -1;
static int hf_bthci_cmd_cod_major_service_class_telephony_mask = -1;
static int hf_bthci_cmd_cod_major_service_class_audio_mask = -1;
static int hf_bthci_cmd_cod_major_service_class_object_transfer_mask = -1;
static int hf_bthci_cmd_cod_major_service_class_capturing_mask = -1;
static int hf_bthci_cmd_cod_major_service_class_rendering_mask = -1;
static int hf_bthci_cmd_cod_major_service_class_networking_mask = -1;
static int hf_bthci_cmd_cod_major_service_class_positioning_mask = -1;
static int hf_bthci_cmd_cod_major_service_class_reserved_mask = -1;
static int hf_bthci_cmd_cod_major_service_class_limited_discoverable_mode_mask = -1;
static int hf_bthci_cmd_cod_major_device_class_mask = -1;
static int hf_bthci_cmd_auto_acc_flag = -1;
static int hf_bthci_cmd_read_all_flag = -1;
static int hf_bthci_cmd_delete_all_flag = -1;
static int hf_bthci_cmd_authentication_enable = -1;
static int hf_bthci_cmd_input_unused = -1;
static int hf_bthci_cmd_input_coding = -1;
static int hf_bthci_cmd_input_data_format = -1;
static int hf_bthci_cmd_input_sample_size = -1;
static int hf_bthci_cmd_linear_pcm_bit_pos = -1;
static int hf_bthci_cmd_air_coding_format = -1;
static int hf_bthci_cmd_num_broadcast_retransmissions = -1;
static int hf_bthci_cmd_hold_mode_act_page = -1;
static int hf_bthci_cmd_hold_mode_act_inquiry = -1;
static int hf_bthci_cmd_hold_mode_act_periodic = -1;
static int hf_bthci_cmd_scan_enable = -1;
static int hf_bthci_cmd_interval = -1;
static int hf_bthci_cmd_window = -1;
static int hf_bthci_cmd_device_name = -1;
static int hf_bthci_cmd_num_curr_iac = -1;
static int hf_bthci_cmd_iac_lap = -1;
static int hf_bthci_cmd_evt_mask_00 = -1;
static int hf_bthci_cmd_evt_mask_01 = -1;
static int hf_bthci_cmd_evt_mask_02 = -1;
static int hf_bthci_cmd_evt_mask_03 = -1;
static int hf_bthci_cmd_evt_mask_04 = -1;
static int hf_bthci_cmd_evt_mask_05 = -1;
static int hf_bthci_cmd_evt_mask_06 = -1;
static int hf_bthci_cmd_evt_mask_07 = -1;
static int hf_bthci_cmd_evt_mask_10 = -1;
static int hf_bthci_cmd_evt_mask_11 = -1;
static int hf_bthci_cmd_evt_mask_12 = -1;
static int hf_bthci_cmd_evt_mask_13 = -1;
static int hf_bthci_cmd_evt_mask_14 = -1;
static int hf_bthci_cmd_evt_mask_17 = -1;
static int hf_bthci_cmd_evt_mask_20 = -1;
static int hf_bthci_cmd_evt_mask_21 = -1;
static int hf_bthci_cmd_evt_mask_23 = -1;
static int hf_bthci_cmd_evt_mask_24 = -1;
static int hf_bthci_cmd_evt_mask_25 = -1;
static int hf_bthci_cmd_evt_mask_26 = -1;
static int hf_bthci_cmd_evt_mask_27 = -1;
static int hf_bthci_cmd_evt_mask_30 = -1;
static int hf_bthci_cmd_evt_mask_31 = -1;
static int hf_bthci_cmd_evt_mask_32 = -1;
static int hf_bthci_cmd_evt_mask_33 = -1;
static int hf_bthci_cmd_evt_mask_34 = -1;
static int hf_bthci_cmd_evt_mask_35 = -1;
static int hf_bthci_cmd_evt_mask_36 = -1;
static int hf_bthci_cmd_evt_mask_37 = -1;
static int hf_bthci_cmd_evt_mask_40 = -1;
static int hf_bthci_cmd_evt_mask_41 = -1;
static int hf_bthci_cmd_evt_mask_42 = -1;
static int hf_bthci_cmd_evt_mask_53 = -1;
static int hf_bthci_cmd_evt_mask_54 = -1;
static int hf_bthci_cmd_evt_mask_55 = -1;
static int hf_bthci_cmd_evt_mask_56 = -1;
static int hf_bthci_cmd_evt_mask_57 = -1;
static int hf_bthci_cmd_evt_mask_60 = -1;
static int hf_bthci_cmd_evt_mask_61 = -1;
static int hf_bthci_cmd_evt_mask_62 = -1;
static int hf_bthci_cmd_evt_mask_63 = -1;
static int hf_bthci_cmd_evt_mask_64 = -1;
static int hf_bthci_cmd_evt_mask_65 = -1;
static int hf_bthci_cmd_evt_mask_67 = -1;
static int hf_bthci_cmd_evt_mask_70 = -1;
static int hf_bthci_cmd_evt_mask_72 = -1;
static int hf_bthci_cmd_evt_mask_73 = -1;
static int hf_bthci_cmd_sco_flow_control = -1;
static int hf_bthci_cmd_num_handles = -1;
static int hf_bthci_cmd_num_compl_packets = -1;
static int hf_bthci_cmd_flow_contr_enable = -1;
static int hf_bthci_cmd_host_data_packet_length_acl = -1;
static int hf_bthci_cmd_host_data_packet_length_sco = -1;
static int hf_bthci_cmd_host_total_num_acl_data_packets = -1;
static int hf_bthci_cmd_host_total_num_sco_data_packets = -1;
static int hf_bthci_cmd_loopback_mode = -1;
static int hf_bthci_cmd_page_number = -1;
static int hf_bthci_cmd_transmit_bandwidth = -1;
static int hf_bthci_cmd_receive_bandwidth = -1;
static int hf_bthci_cmd_max_latency_ms = -1;
static int hf_bthci_cmd_max_latency = -1;
static int hf_bthci_cmd_retransmission_effort = -1;
static int hf_bthci_cmd_scan_type = -1;
static int hf_bthci_cmd_inq_mode = -1;
static int hf_bthci_cmd_fec_required = -1;
static int hf_bthci_cmd_err_data_reporting = -1;
static int hf_bthci_cmd_tx_power = -1;
static int hf_bthci_cmd_sco_packet_type = -1;
static int hf_bthci_cmd_sco_packet_type_hv1 = -1;
static int hf_bthci_cmd_sco_packet_type_hv2 = -1;
static int hf_bthci_cmd_sco_packet_type_hv3 = -1;
static int hf_bthci_cmd_sco_packet_type_ev3 = -1;
static int hf_bthci_cmd_sco_packet_type_ev4 = -1;
static int hf_bthci_cmd_sco_packet_type_ev5 = -1;
static int hf_bthci_cmd_sco_packet_type_2ev3 = -1;
static int hf_bthci_cmd_sco_packet_type_3ev3 = -1;
static int hf_bthci_cmd_sco_packet_type_2ev5 = -1;
static int hf_bthci_cmd_sco_packet_type_3ev5 = -1;
static int hf_bthci_cmd_sco_packet_type_reserved = -1;
static int hf_bthci_cmd_min_remote_timeout = -1;
static int hf_bthci_cmd_min_local_timeout = -1;
static int hf_bthci_cmd_flush_packet_type = -1;
static int hf_bthci_cmd_afh_ch_assessment_mode = -1;
static int hf_bthci_cmd_afh_ch_classification = -1;
static int hf_bthci_cmd_which_clock = -1;
static int hf_bthci_cmd_io_capability = -1;
static int hf_bthci_cmd_oob_data_present = -1;
static int hf_bthci_cmd_auth_requirements = -1;
static int hf_bthci_cmd_passkey = -1;
static int hf_bthci_cmd_randomizer_r = -1;
static int hf_bthci_cmd_hash_c = -1;
static int hf_bthci_cmd_simple_pairing_mode = -1;
static int hf_bthci_cmd_simple_pairing_debug_mode = -1;
static int hf_bthci_cmd_notification_type = -1;
static int hf_bthci_cmd_physical_link_handle = -1;
static int hf_bthci_cmd_dedicated_amp_key_length = -1;
static int hf_bthci_cmd_dedicated_amp_key_type = -1;
static int hf_bthci_cmd_dedicated_amp_key = -1;
static int hf_bthci_cmd_flow_spec = -1;
static int hf_bthci_cmd_flow_spec_identifier = -1;
static int hf_bthci_cmd_flow_spec_service_type = -1;
static int hf_bthci_cmd_flow_spec_sdu_size = -1;
static int hf_bthci_cmd_flow_spec_sdu_arrival_time = -1;
static int hf_bthci_cmd_flow_spec_access_latency = -1;
static int hf_bthci_cmd_flush_to_us = -1;
static int hf_bthci_cmd_logical_link_handle = -1;
static int hf_bthci_cmd_evt_mask2_00 = -1;
static int hf_bthci_cmd_evt_mask2_01 = -1;
static int hf_bthci_cmd_evt_mask2_02 = -1;
static int hf_bthci_cmd_evt_mask2_03 = -1;
static int hf_bthci_cmd_evt_mask2_04 = -1;
static int hf_bthci_cmd_evt_mask2_05 = -1;
static int hf_bthci_cmd_evt_mask2_06 = -1;
static int hf_bthci_cmd_evt_mask2_07 = -1;
static int hf_bthci_cmd_evt_mask2_10 = -1;
static int hf_bthci_cmd_evt_mask2_11 = -1;
static int hf_bthci_cmd_evt_mask2_12 = -1;
static int hf_bthci_cmd_evt_mask2_13 = -1;
static int hf_bthci_cmd_evt_mask2_14 = -1;
static int hf_bthci_cmd_evt_mask2_15 = -1;
static int hf_bthci_cmd_location_domain_aware = -1;
static int hf_bthci_cmd_location_domain = -1;
static int hf_bthci_cmd_location_domain_options = -1;
static int hf_bthci_cmd_location_options = -1;
static int hf_bthci_cmd_flow_control_mode = -1;
static int hf_bthci_cmd_tx_power_level_type = -1;
static int hf_bthci_cmd_short_range_mode = -1;
static int hf_bthci_cmd_le_supported_host = -1;
static int hf_bthci_cmd_le_simultaneous_host = -1;
static int hf_bthci_cmd_enable_amp_recv_reports = -1;
static int hf_bthci_cmd_amp_recv_report_interval = -1;
static int hf_bthci_cmd_length_so_far = -1;
static int hf_bthci_cmd_amp_assoc_length = -1;
static int hf_bthci_cmd_amp_remaining_assoc_length = -1;
static int hf_bthci_cmd_amp_assoc_fragment = -1;
static int hf_bthci_cmd_le_event_mask = -1;
static int hf_bthci_cmd_le_event_mask_le_reserved = -1;
static int hf_bthci_cmd_le_event_mask_le_biginfo_advertising_report = -1;
static int hf_bthci_cmd_le_event_mask_le_transmit_power_reporting = -1;
static int hf_bthci_cmd_le_event_mask_le_path_loss_threshold = -1;
static int hf_bthci_cmd_le_event_mask_le_request_peer_sca_complete = -1;
static int hf_bthci_cmd_le_event_mask_le_big_sync_lost = -1;
static int hf_bthci_cmd_le_event_mask_le_big_sync_established = -1;
static int hf_bthci_cmd_le_event_mask_le_terminate_big_complete = -1;
static int hf_bthci_cmd_le_event_mask_le_create_big_complete = -1;
static int hf_bthci_cmd_le_event_mask_le_cis_request = -1;
static int hf_bthci_cmd_le_event_mask_le_cis_established = -1;
static int hf_bthci_cmd_le_event_mask_le_periodic_advertising_sync_transfer_received = -1;
static int hf_bthci_cmd_le_event_mask_le_cte_request_failed = -1;
static int hf_bthci_cmd_le_event_mask_le_connection_iq_report = -1;
static int hf_bthci_cmd_le_event_mask_le_connectionless_iq_report = -1;
static int hf_bthci_cmd_le_event_mask_le_channel_selection_algorithm = -1;
static int hf_bthci_cmd_le_event_mask_le_scan_request_received = -1;
static int hf_bthci_cmd_le_event_mask_le_extended_advertising_set_terminated = -1;
static int hf_bthci_cmd_le_event_mask_le_extended_scan_timeout = -1;
static int hf_bthci_cmd_le_event_mask_le_periodic_advertising_sync_lost = -1;
static int hf_bthci_cmd_le_event_mask_le_periodic_advertising_report = -1;
static int hf_bthci_cmd_le_event_mask_le_periodic_advertising_sync_established = -1;
static int hf_bthci_cmd_le_event_mask_le_extended_advertising_report = -1;
static int hf_bthci_cmd_le_event_mask_le_phy_update_complete = -1;
static int hf_bthci_cmd_le_event_mask_le_direct_advertising_report  = -1;
static int hf_bthci_cmd_le_event_mask_le_enhanced_connection_complete = -1;
static int hf_bthci_cmd_le_event_mask_le_generate_dhkey_complete = -1;
static int hf_bthci_cmd_le_event_mask_le_read_local_p256_public_key_complete = -1;
static int hf_bthci_cmd_le_event_mask_le_data_length_change = -1;
static int hf_bthci_cmd_le_event_mask_le_remote_connection_parameter_request = -1;
static int hf_bthci_cmd_le_event_mask_le_long_term_key_request = -1;
static int hf_bthci_cmd_le_event_mask_le_read_remote_features_complete = -1;
static int hf_bthci_cmd_le_event_mask_le_connection_update_complete = -1;
static int hf_bthci_cmd_le_event_mask_le_advertising_report = -1;
static int hf_bthci_cmd_le_event_mask_le_connection_complete = -1;
static int hf_bthci_cmd_le_advts_interval_min = -1;
static int hf_bthci_cmd_le_advts_interval_max = -1;
static int hf_bthci_cmd_le_advts_type = -1;
static int hf_bthci_cmd_le_own_address_type = -1;
static int hf_bthci_cmd_le_direct_address_type = -1;
static int hf_bthci_cmd_le_advts_channel_map_1 = -1;
static int hf_bthci_cmd_le_advts_channel_map_2 = -1;
static int hf_bthci_cmd_le_advts_channel_map_3 = -1;
static int hf_bthci_cmd_le_advts_filter_policy = -1;
static int hf_bthci_cmd_le_data_length = -1;
static int hf_bthci_cmd_le_advts_enable = -1;
static int hf_bthci_cmd_le_scan_enable = -1;
static int hf_bthci_cmd_le_filter_duplicates = -1;
static int hf_bthci_cmd_le_scan_type = -1;
static int hf_bthci_cmd_le_scan_interval = -1;
static int hf_bthci_cmd_le_scan_window = -1;
static int hf_bthci_cmd_le_scan_filter_policy = -1;
static int hf_bthci_cmd_le_initiator_filter_policy = -1;
static int hf_bthci_cmd_le_peer_address_type = -1;
static int hf_bthci_cmd_le_peer_identity_address_type = -1;
static int hf_bthci_cmd_le_con_interval_min = -1;
static int hf_bthci_cmd_le_con_interval_max = -1;
static int hf_bthci_cmd_le_con_latency = -1;
static int hf_bthci_cmd_le_supervision_timeout = -1;
static int hf_bthci_cmd_le_min_ce_length = -1;
static int hf_bthci_cmd_le_max_ce_length = -1;
static int hf_bthci_cmd_le_address_type = -1;
static int hf_bthci_cmd_le_channel_map = -1;
static int hf_bthci_cmd_key = -1;
static int hf_bthci_cmd_plaintext_data = -1;
static int hf_bthci_cmd_random_number = -1;
static int hf_bthci_cmd_encrypted_diversifier = -1;
static int hf_bthci_cmd_le_long_term_key = -1;
static int hf_bthci_cmd_rx_frequency = -1;
static int hf_bthci_cmd_tx_frequency = -1;
static int hf_bthci_cmd_test_data_length = -1;
static int hf_bthci_cmd_test_packet_payload = -1;
static int hf_bthci_cmd_parameter = -1;
static int hf_response_in_frame = -1;
static int hf_command_response_time_delta = -1;
static int hf_pending_in_frame = -1;
static int hf_command_pending_time_delta = -1;
static int hf_bthci_cmd_le_tx_octets = -1;
static int hf_bthci_cmd_le_tx_time = -1;
static int hf_bthci_cmd_le_suggested_max_tx_octets = -1;
static int hf_bthci_cmd_le_suggested_max_tx_time = -1;
static int hf_bthci_cmd_le_remote_p_256_public_key = -1;
static int hf_bthci_cmd_le_peer_irk = -1;
static int hf_bthci_cmd_le_local_irk = -1;
static int hf_bthci_cmd_le_address_resolution_enable = -1;
static int hf_bthci_cmd_le_rpa_timeout = -1;
static int hf_bthci_cmd_advertising_ext_interval_min = -1;
static int hf_bthci_cmd_advertising_ext_interval_max = -1;
static int hf_bthci_cmd_advertising_handle = -1;
static int hf_bthci_cmd_advertising_properties = -1;
static int hf_bthci_cmd_advertising_properties_reserved = -1;
static int hf_bthci_cmd_advertising_properties_connectable = -1;
static int hf_bthci_cmd_advertising_properties_scannable = -1;
static int hf_bthci_cmd_advertising_properties_directed = -1;
static int hf_bthci_cmd_advertising_properties_hdc_connectable_directed = -1;
static int hf_bthci_cmd_advertising_properties_legacy_adv = -1;
static int hf_bthci_cmd_advertising_properties_anonymous_adv = -1;
static int hf_bthci_cmd_advertising_properties_incl_txpower = -1;
static int hf_bthci_cmd_periodic_advertising_properties = -1;
static int hf_bthci_cmd_periodic_advertising_properties_reserved = -1;
static int hf_bthci_cmd_primary_advertising_phy = -1;
static int hf_bthci_cmd_sec_adv_max_skip = -1;
static int hf_bthci_cmd_secondary_advertising_phy = -1;
static int hf_bthci_cmd_advertising_sid = -1;
static int hf_bthci_cmd_scan_req_notif_en = -1;
static int hf_bthci_cmd_le_adv_data_operation = -1;
static int hf_bthci_cmd_le_adv_data_frag_pref = -1;
static int hf_bthci_cmd_le_adv_set = -1;
static int hf_bthci_cmd_le_adv_en_sets = -1;
static int hf_bthci_cmd_le_adv_duration = -1;
static int hf_bthci_cmd_le_adv_max_extended_events = -1;
static int hf_bthci_cmd_all_phys = -1;
static int hf_bthci_cmd_all_phys_tx_pref = -1;
static int hf_bthci_cmd_all_phys_rx_pref = -1;
static int hf_bthci_cmd_all_phys_reserved = -1;
static int hf_bthci_cmd_tx_phys = -1;
static int hf_bthci_cmd_rx_phys = -1;
static int hf_bthci_cmd_phys_pref_le_1m = -1;
static int hf_bthci_cmd_phys_pref_le_2m = -1;
static int hf_bthci_cmd_phys_pref_le_coded = -1;
static int hf_bthci_cmd_phys_pref_reserved = -1;
static int hf_bthci_cmd_phy_options = -1;
static int hf_bthci_cmd_phy_options_coding =-1;
static int hf_bthci_cmd_phy_options_reserved =- 1;
static int hf_bthci_cmd_phy = -1;
static int hf_bthci_cmd_modulation_index = -1;
static int hf_bthci_cmd_le_scan_phys = -1;
static int hf_bthci_cmd_le_scan_phys_reserved = -1;
static int hf_bthci_cmd_le_scan_phys_le_coded = -1;
static int hf_bthci_cmd_le_scan_phys_le_1m = -1;
static int hf_bthci_cmd_le_scan_phy_param = -1;
static int hf_bthci_cmd_le_scan_duration = -1;
static int hf_bthci_cmd_le_scan_period = -1;
static int hf_bthci_cmd_le_init_phys = -1;
static int hf_bthci_cmd_le_phys_reserved = -1;
static int hf_bthci_cmd_le_phys_le_coded = -1;
static int hf_bthci_cmd_le_phys_le_2m = -1;
static int hf_bthci_cmd_le_phys_le_1m = -1;
static int hf_bthci_cmd_le_init_phy_param = -1;
static int hf_bthci_cmd_le_privacy_mode = -1;
static int hf_bthci_cmd_sync_filter_policy = -1;
static int hf_bthci_cmd_skip = -1;
static int hf_bthci_cmd_rf_tx_path_compensation_value = -1;
static int hf_bthci_cmd_rf_rx_path_compensation_value = -1;
static int hf_bthci_cmd_sync_handle = -1;
static int hf_bthci_cmd_cte_length = -1;
static int hf_bthci_cmd_cte_type = -1;
static int hf_bthci_cmd_slot_durations = -1;
static int hf_bthci_cmd_antenna_switching_pattern_length = -1;
static int hf_bthci_cmd_antenna_switching_pattern = -1;
static int hf_bthci_cmd_antenna_id = -1;
static int hf_bthci_cmd_cte_count = -1;
static int hf_bthci_cmd_cte_enable = -1;
static int hf_bthci_cmd_iq_sampling_enable = -1;
static int hf_bthci_cmd_max_sampled_ctes = -1;
static int hf_bthci_cmd_cte_request_interval = -1;
static int hf_bthci_cmd_reporting_enable = -1;
static int hf_bthci_cmd_service_data_past = -1;
static int hf_bthci_cmd_sync_mode = -1;
static int hf_bthci_cmd_key_type = -1;
static int hf_bthci_cmd_sca_action = -1;
static int hf_bthci_cmd_sync_cte_type = -1;
static int hf_bthci_cmd_sync_cte_type_no_sync_aoa = -1;
static int hf_bthci_cmd_sync_cte_type_no_sync_aod_1us = -1;
static int hf_bthci_cmd_sync_cte_type_no_sync_aod_2us = -1;
static int hf_bthci_cmd_sync_cte_type_sync_only_with_cte = -1;
static int hf_bthci_cmd_sync_cte_type_reserved = -1;
static int hf_bthci_cmd_cte_types = -1;
static int hf_bthci_cmd_cte_types_reserved = -1;
static int hf_bthci_cmd_cte_types_aod_2us = -1;
static int hf_bthci_cmd_cte_types_aod_1us = -1;
static int hf_bthci_cmd_cte_types_aoa = -1;
static int hf_bthci_cmd_cig_id = -1;
static int hf_bthci_cmd_sdu_interval_m_to_s = -1;
static int hf_bthci_cmd_sdu_interval_s_to_m = -1;
static int hf_bthci_cmd_sdu_interval = -1;
static int hf_bthci_cmd_slaves_clock_accuracy = -1;
static int hf_bthci_cmd_packing = -1;
static int hf_bthci_cmd_framing = -1;
static int hf_bthci_cmd_ft_m_to_s = -1;
static int hf_bthci_cmd_ft_s_to_m = -1;
static int hf_bthci_cmd_iso_interval = -1;
static int hf_bthci_cmd_cis_count = -1;
static int hf_bthci_cmd_cis_params = -1;
static int hf_bthci_cmd_cis_id = -1;
static int hf_bthci_cmd_nse = -1;
static int hf_bthci_cmd_max_sdu_m_to_s = -1;
static int hf_bthci_cmd_max_sdu_s_to_m = -1;
static int hf_bthci_cmd_max_sdu = -1;
static int hf_bthci_cmd_max_pdu_m_to_s = -1;
static int hf_bthci_cmd_max_pdu_s_to_m = -1;
static int hf_bthci_cmd_max_pdu = -1;
static int hf_bthci_cmd_phy_m_to_s = -1;
static int hf_bthci_cmd_phy_s_to_m = -1;
static int hf_bthci_cmd_bn_m_to_s = -1;
static int hf_bthci_cmd_bn_s_to_m = -1;
static int hf_bthci_cmd_bn = -1;
static int hf_bthci_cmd_max_transport_latency_m_to_s = -1;
static int hf_bthci_cmd_max_transport_latency_s_to_m = -1;
static int hf_bthci_cmd_max_transport_latency = -1;
static int hf_bthci_cmd_rtn_m_to_s = -1;
static int hf_bthci_cmd_rtn_s_to_m = -1;
static int hf_bthci_cmd_rtn = -1;
static int hf_bthci_cmd_cis_handle = -1;
static int hf_bthci_cmd_big_handle = -1;
static int hf_bthci_cmd_cis_bis_handle = -1;
static int hf_bthci_cmd_num_bis = -1;
static int hf_bthci_cmd_irc = -1;
static int hf_bthci_cmd_pto = -1;
static int hf_bthci_cmd_encryption = -1;
static int hf_bthci_cmd_broadcast_code = -1;
static int hf_bthci_cmd_mse = -1;
static int hf_bthci_cmd_bis_index = -1;
static int hf_bthci_cmd_sync_timeout = -1;
static int hf_bthci_cmd_data_path_direction = -1;
static int hf_bthci_cmd_data_path_id = -1;
static int hf_bthci_cmd_coding_format = -1;
static int hf_bthci_cmd_controller_delay = -1;
static int hf_bthci_cmd_codec_config_length = -1;
static int hf_bthci_cmd_codec_config = -1;
static int hf_bthci_cmd_payload_type = -1;
static int hf_bthci_cmd_feature_bit_number = -1;
static int hf_bthci_cmd_feature_bit_value = -1;
static int hf_bthci_cmd_phy_and_coding = -1;
static int hf_bthci_cmd_high_threshold = -1;
static int hf_bthci_cmd_high_hysteresis = -1;
static int hf_bthci_cmd_low_threshold = -1;
static int hf_bthci_cmd_low_hysteresis = -1;
static int hf_bthci_cmd_min_time_spent = -1;
static int hf_bthci_cmd_local_reporting_enable = -1;
static int hf_bthci_cmd_remote_reporting_enable = -1;
static int hf_bthci_cmd_triggered_clock_capture = -1;
static int hf_bthci_cmd_lpo_allowed = -1;
static int hf_bthci_cmd_number_of_clock_captures_to_filter = -1;
static int hf_bthci_cmd_amp_controller_type = -1;
static int hf_bthci_cmd_esco_loopback_mode = -1;
static int hf_bthci_cmd_dm1_acl_u_mode = -1;
static int hf_bthci_cmd_codec_id = -1;
static int hf_bthci_cmd_company_id = -1;
static int hf_bthci_cmd_vendor_codec_id = -1;
static int hf_bthci_cmd_transmit_coding_format = -1;
static int hf_bthci_cmd_receive_coding_format = -1;
static int hf_bthci_cmd_input_coding_format = -1;
static int hf_bthci_cmd_output_coding_format = -1;
static int hf_bthci_cmd_transmit_codec_frame_size = -1;
static int hf_bthci_cmd_receive_codec_frame_size = -1;
static int hf_bthci_cmd_input_bandwidth = -1;
static int hf_bthci_cmd_output_bandwidth = -1;
static int hf_bthci_cmd_input_coded_data_size = -1;
static int hf_bthci_cmd_output_coded_data_size = -1;
static int hf_bthci_cmd_input_pcm_data_format = -1;
static int hf_bthci_cmd_output_pcm_data_format = -1;
static int hf_bthci_cmd_input_pcm_sample_payload_msb_position = -1;
static int hf_bthci_cmd_output_pcm_sample_payload_msb_position = -1;
static int hf_bthci_cmd_input_data_path = -1;
static int hf_bthci_cmd_output_data_path = -1;
static int hf_bthci_cmd_input_transport_unit_size = -1;
static int hf_bthci_cmd_output_transport_unit_size = -1;
static int hf_bthci_cmd_connectionless_slave_broadcast = -1;
static int hf_bthci_cmd_lt_addr = -1;
static int hf_bthci_cmd_interval_min = -1;
static int hf_bthci_cmd_interval_max = -1;
static int hf_bthci_cmd_csb_supervision_to = -1;
static int hf_bthci_cmd_connectionless_slave_broadcast_receive = -1;
static int hf_bthci_cmd_clock_offset_32 = -1;
static int hf_bthci_cmd_next_csb_clock = -1;
static int hf_bthci_cmd_remote_timing_accuracy = -1;
static int hf_bthci_cmd_csb_skip = -1;
static int hf_bthci_cmd_afh_channel_map = -1;
static int hf_bthci_cmd_synchronization_scan_to = -1;
static int hf_bthci_cmd_c192 = -1;
static int hf_bthci_cmd_r192 = -1;
static int hf_bthci_cmd_c256 = -1;
static int hf_bthci_cmd_r256 = -1;
static int hf_bthci_mws_channel = -1;
static int hf_bthci_mws_rx_center_frequency = -1;
static int hf_bthci_mws_tx_center_frequency = -1;
static int hf_bthci_mws_rx_channel_bandwidth = -1;
static int hf_bthci_mws_tx_channel_bandwidth = -1;
static int hf_bthci_mws_channel_type = -1;
static int hf_bthci_external_frame_duration = -1;
static int hf_bthci_external_frame_sync_assert_offset = -1;
static int hf_bthci_external_frame_sync_assert_jitter = -1;
static int hf_bthci_external_frame_number_of_periods = -1;
static int hf_bthci_external_frame_periods = -1;
static int hf_bthci_external_frame_period = -1;
static int hf_bthci_external_frame_period_duration = -1;
static int hf_bthci_external_frame_period_type = -1;
static int hf_bthci_mws_rx_assert_offset = -1;
static int hf_bthci_mws_rx_assert_jitter = -1;
static int hf_bthci_mws_rx_deassert_offset = -1;
static int hf_bthci_mws_rx_deassert_jitter = -1;
static int hf_bthci_mws_tx_assert_offset = -1;
static int hf_bthci_mws_tx_assert_jitter = -1;
static int hf_bthci_mws_tx_deassert_offset = -1;
static int hf_bthci_mws_tx_deassert_jitter = -1;
static int hf_bthci_mws_pattern_assert_offset = -1;
static int hf_bthci_mws_pattern_assert_jitter = -1;
static int hf_bthci_mws_inactivity_duration_assert_offset = -1;
static int hf_bthci_mws_inactivity_duration_assert_jitter = -1;
static int hf_bthci_mws_scan_frequency_assert_offset = -1;
static int hf_bthci_mws_scan_frequency_assert_jitter = -1;
static int hf_bthci_mws_priority_assert_offset_request = -1;
static int hf_bthci_mws_transport_layer = -1;
static int hf_bthci_mws_to_baud_rate = -1;
static int hf_bthci_mws_from_baud_rate = -1;
static int hf_bthci_mws_number_of_frequencies = -1;
static int hf_bthci_mws_scan_frequency_table = -1;
static int hf_bthci_mws_scan_frequency_table_item = -1;
static int hf_bthci_mws_scan_frequency_table_item_low = -1;
static int hf_bthci_mws_scan_frequency_table_item_high = -1;
static int hf_bthci_mws_pattern_index = -1;
static int hf_bthci_mws_pattern_number_of_intervals = -1;
static int hf_bthci_mws_patterns = -1;
static int hf_bthci_mws_pattern = -1;
static int hf_bthci_mws_pattern_duration = -1;
static int hf_bthci_mws_pattern_type = -1;
static int hf_bthci_cmd_sync_train_to = -1;
static int hf_bthci_cmd_service_data = -1;
static int hf_bthci_cmd_secure_connection_host_support = -1;
static int hf_bthci_cmd_csb_fragment = -1;
static int hf_bthci_cmd_csb_data_length = -1;
static int hf_bthci_cmd_csb_data = -1;
static int hf_bthci_cmd_authenticated_payload_timeout = -1;
static int hf_bthci_cmd_extended_inquiry_length = -1;


static int * const hfx_bthci_cmd_le_event_mask[] = {
    &hf_bthci_cmd_le_event_mask_le_reserved,
    &hf_bthci_cmd_le_event_mask_le_biginfo_advertising_report,
    &hf_bthci_cmd_le_event_mask_le_transmit_power_reporting,
    &hf_bthci_cmd_le_event_mask_le_path_loss_threshold,
    &hf_bthci_cmd_le_event_mask_le_request_peer_sca_complete,
    &hf_bthci_cmd_le_event_mask_le_big_sync_lost,
    &hf_bthci_cmd_le_event_mask_le_big_sync_established,
    &hf_bthci_cmd_le_event_mask_le_terminate_big_complete,
    &hf_bthci_cmd_le_event_mask_le_create_big_complete,
    &hf_bthci_cmd_le_event_mask_le_cis_request,
    &hf_bthci_cmd_le_event_mask_le_cis_established,
    &hf_bthci_cmd_le_event_mask_le_periodic_advertising_sync_transfer_received,
    &hf_bthci_cmd_le_event_mask_le_cte_request_failed,
    &hf_bthci_cmd_le_event_mask_le_connection_iq_report,
    &hf_bthci_cmd_le_event_mask_le_connectionless_iq_report,
    &hf_bthci_cmd_le_event_mask_le_channel_selection_algorithm,
    &hf_bthci_cmd_le_event_mask_le_scan_request_received,
    &hf_bthci_cmd_le_event_mask_le_extended_advertising_set_terminated,
    &hf_bthci_cmd_le_event_mask_le_extended_scan_timeout,
    &hf_bthci_cmd_le_event_mask_le_periodic_advertising_sync_lost,
    &hf_bthci_cmd_le_event_mask_le_periodic_advertising_report,
    &hf_bthci_cmd_le_event_mask_le_periodic_advertising_sync_established,
    &hf_bthci_cmd_le_event_mask_le_extended_advertising_report,
    &hf_bthci_cmd_le_event_mask_le_phy_update_complete,
    &hf_bthci_cmd_le_event_mask_le_direct_advertising_report ,
    &hf_bthci_cmd_le_event_mask_le_enhanced_connection_complete,
    &hf_bthci_cmd_le_event_mask_le_generate_dhkey_complete,
    &hf_bthci_cmd_le_event_mask_le_read_local_p256_public_key_complete,
    &hf_bthci_cmd_le_event_mask_le_data_length_change,
    &hf_bthci_cmd_le_event_mask_le_remote_connection_parameter_request,
    &hf_bthci_cmd_le_event_mask_le_long_term_key_request,
    &hf_bthci_cmd_le_event_mask_le_read_remote_features_complete,
    &hf_bthci_cmd_le_event_mask_le_connection_update_complete,
    &hf_bthci_cmd_le_event_mask_le_advertising_report,
    &hf_bthci_cmd_le_event_mask_le_connection_complete,
    NULL
};

static int * const hfx_bthci_cmd_adv_properties[] = {
    &hf_bthci_cmd_advertising_properties_reserved,
    &hf_bthci_cmd_advertising_properties_incl_txpower,
    &hf_bthci_cmd_advertising_properties_anonymous_adv,
    &hf_bthci_cmd_advertising_properties_legacy_adv,
    &hf_bthci_cmd_advertising_properties_hdc_connectable_directed,
    &hf_bthci_cmd_advertising_properties_directed,
    &hf_bthci_cmd_advertising_properties_scannable,
    &hf_bthci_cmd_advertising_properties_connectable,
    NULL
};

static int * const hfx_bthci_cmd_periodic_adv_properties[] = {
    &hf_bthci_cmd_periodic_advertising_properties_reserved,
    &hf_bthci_cmd_advertising_properties_incl_txpower,
    NULL
};

static int * const hfx_btcmd_all_phys[] = {
    &hf_bthci_cmd_all_phys_reserved,
    &hf_bthci_cmd_all_phys_rx_pref,
    &hf_bthci_cmd_all_phys_tx_pref,
    NULL
};

static int * const hfx_btcmd_phys_pref[] = {
    &hf_bthci_cmd_phys_pref_reserved,
    &hf_bthci_cmd_phys_pref_le_coded,
    &hf_bthci_cmd_phys_pref_le_2m,
    &hf_bthci_cmd_phys_pref_le_1m,
    NULL
};

static int * const hfx_btcmd_phy_options[] = {
    &hf_bthci_cmd_phy_options_reserved,
    &hf_bthci_cmd_phy_options_coding,
    NULL
};

static int * const hfx_btcmd_le_scan_phys[] = {
    &hf_bthci_cmd_le_scan_phys_reserved,
    &hf_bthci_cmd_le_scan_phys_le_coded,
    &hf_bthci_cmd_le_scan_phys_le_1m,
    NULL
};

static int * const hfx_btcmd_le_phys[] = {
    &hf_bthci_cmd_le_phys_reserved,
    &hf_bthci_cmd_le_phys_le_coded,
    &hf_bthci_cmd_le_phys_le_2m,
    &hf_bthci_cmd_le_phys_le_1m,
    NULL
};

static int * const hfx_btcmd_sync_cte_type[] = {
    &hf_bthci_cmd_sync_cte_type_reserved,
    &hf_bthci_cmd_sync_cte_type_sync_only_with_cte,
    &hf_bthci_cmd_sync_cte_type_no_sync_aod_2us,
    &hf_bthci_cmd_sync_cte_type_no_sync_aod_1us,
    &hf_bthci_cmd_sync_cte_type_no_sync_aoa,
    NULL
};

static int * const hfx_btcmd_cte_types[] = {
    &hf_bthci_cmd_cte_types_reserved,
    &hf_bthci_cmd_cte_types_aod_2us,
    &hf_bthci_cmd_cte_types_aod_1us,
    &hf_bthci_cmd_cte_types_aoa,
    NULL
};

static int * const hfx_bthci_cmd_sco_packet_type[] = {
    &hf_bthci_cmd_sco_packet_type_reserved,
    &hf_bthci_cmd_sco_packet_type_3ev5,
    &hf_bthci_cmd_sco_packet_type_2ev5,
    &hf_bthci_cmd_sco_packet_type_3ev3,
    &hf_bthci_cmd_sco_packet_type_2ev3,
    &hf_bthci_cmd_sco_packet_type_ev5,
    &hf_bthci_cmd_sco_packet_type_ev4,
    &hf_bthci_cmd_sco_packet_type_ev3,
    &hf_bthci_cmd_sco_packet_type_hv3,
    &hf_bthci_cmd_sco_packet_type_hv2,
    &hf_bthci_cmd_sco_packet_type_hv1,
    NULL
};

static int * const hfx_bthci_cmd_packet_type[] = {
    &hf_bthci_cmd_packet_type_dh5,
    &hf_bthci_cmd_packet_type_dm5,
    &hf_bthci_cmd_packet_type_3dh5,
    &hf_bthci_cmd_packet_type_2dh5,
    &hf_bthci_cmd_packet_type_dh3,
    &hf_bthci_cmd_packet_type_dm3,
    &hf_bthci_cmd_packet_type_3dh3,
    &hf_bthci_cmd_packet_type_2dh3,
    &hf_bthci_cmd_packet_type_reserved_5_7,
    &hf_bthci_cmd_packet_type_dh1,
    &hf_bthci_cmd_packet_type_dm1,
    &hf_bthci_cmd_packet_type_3dh1,
    &hf_bthci_cmd_packet_type_2dh1,
    &hf_bthci_cmd_packet_type_reserved_0,
    NULL
};

static expert_field ei_command_undecoded                              = EI_INIT;
static expert_field ei_command_unknown_command                        = EI_INIT;
static expert_field ei_command_parameter_unexpected                   = EI_INIT;

static dissector_table_t vendor_dissector_table;
static dissector_table_t hci_vendor_table;

/* Initialize the subtree pointers */
static gint ett_bthci_cmd = -1;
static gint ett_opcode = -1;
static gint ett_cod_mask = -1;
static gint ett_flow_spec_subtree = -1;
static gint ett_le_channel_map = -1;
static gint ett_le_event_mask = -1;
static gint ett_adv_properties = -1;
static gint ett_adv_sets = -1;
static gint ett_phys_flags = -1;
static gint ett_phy_param = -1;
static gint ett_sync_cte_type = -1;
static gint ett_coding_format = -1;
static gint ett_packet_type = -1;
static gint ett_sco_packet_type = -1;
static gint ett_periods = -1;
static gint ett_period = -1;
static gint ett_table = -1;
static gint ett_table_item = -1;
static gint ett_patterns = -1;
static gint ett_pattern = -1;
static gint ett_cis_params = -1;

static gint proto_btcommon = -1;
static gint hf_btcommon_eir_ad_entry = -1;
static gint hf_btcommon_eir_ad_advertising_data = -1;
static gint hf_btcommon_eir_ad_extended_inquiry_response_data = -1;
static gint hf_btcommon_eir_ad_unused = -1;
static gint hf_btcommon_eir_ad_data = -1;
static gint hf_btcommon_eir_ad_length = -1;
static gint hf_btcommon_eir_ad_type = -1;
static gint hf_btcommon_eir_ad_company_id = -1;
static gint hf_btcommon_eir_ad_flags_reserved = -1;
static gint hf_btcommon_eir_ad_flags_le_bredr_support_host = -1;
static gint hf_btcommon_eir_ad_flags_le_bredr_support_controller = -1;
static gint hf_btcommon_eir_ad_flags_bredr_not_support = -1;
static gint hf_btcommon_eir_ad_flags_le_general_discoverable_mode = -1;
static gint hf_btcommon_eir_ad_flags_le_limited_discoverable_mode = -1;
static gint hf_btcommon_eir_ad_uuid_16 = -1;
static gint hf_btcommon_eir_ad_uuid_32 = -1;
static gint hf_btcommon_eir_ad_uuid_128 = -1;
static gint hf_btcommon_eir_ad_custom_uuid_32 = -1;
static gint hf_btcommon_eir_ad_custom_uuid_128 = -1;
static gint hf_btcommon_eir_ad_name = -1;
static gint hf_btcommon_eir_ad_tx_power = -1;
static gint hf_btcommon_eir_ad_ssp_oob_length = -1;
static gint hf_btcommon_eir_ad_bd_addr = -1;
static gint hf_btcommon_eir_ad_le_bd_addr_reserved = -1;
static gint hf_btcommon_eir_ad_le_bd_addr_type = -1;
static gint hf_btcommon_eir_ad_le_role = -1;
static gint hf_btcommon_eir_ad_service_data = -1;
static gint hf_btcommon_eir_ad_did_vendor_id = -1;
static gint hf_btcommon_eir_ad_did_vendor_id_bluetooth_sig = -1;
static gint hf_btcommon_eir_ad_did_vendor_id_usb_forum = -1;
static gint hf_btcommon_eir_ad_did_product_id = -1;
static gint hf_btcommon_eir_ad_did_version = -1;
static gint hf_btcommon_eir_ad_did_vendor_id_source = -1;
static gint hf_btcommon_eir_ad_3ds_association_notification = -1;
static gint hf_btcommon_eir_ad_3ds_battery_level_reporting = -1;
static gint hf_btcommon_eir_ad_3ds_send_battery_level_report_on_startup = -1;
static gint hf_btcommon_eir_ad_3ds_reserved = -1;
static gint hf_btcommon_eir_ad_3ds_factory_test_mode = -1;
static gint hf_btcommon_eir_ad_3ds_path_loss_threshold = -1;
static gint hf_btcommon_eir_ad_3ds_legacy_fixed = -1;
static gint hf_btcommon_eir_ad_3ds_legacy_3d_capable_tv = -1;
static gint hf_btcommon_eir_ad_3ds_legacy_ignored_1_3 = -1;
static gint hf_btcommon_eir_ad_3ds_legacy_fixed_4 = -1;
static gint hf_btcommon_eir_ad_3ds_legacy_ignored_5 = -1;
static gint hf_btcommon_eir_ad_3ds_legacy_fixed_6 = -1;
static gint hf_btcommon_eir_ad_3ds_legacy_test_mode = -1;
static gint hf_btcommon_eir_ad_3ds_legacy_path_loss_threshold = -1;
static gint hf_btcommon_eir_ad_advertising_interval = -1;
static gint hf_btcommon_eir_ad_appearance = -1;
static gint hf_btcommon_eir_ad_hash_c = -1;
static gint hf_btcommon_eir_ad_randomizer_r = -1;
static gint hf_btcommon_eir_ad_le_secure_confirmation_value = -1;
static gint hf_btcommon_eir_ad_le_secure_random_value = -1;
static gint hf_btcommon_eir_ad_oob_flags_data_present = -1;
static gint hf_btcommon_eir_ad_oob_flags_le_supported_host = -1;
static gint hf_btcommon_eir_ad_oob_flags_le_bredr_support = -1;
static gint hf_btcommon_eir_ad_oob_flags_address_type = -1;
static gint hf_btcommon_eir_ad_oob_flags_reserved = -1;
static gint hf_btcommon_eir_ad_connection_interval_min = -1;
static gint hf_btcommon_eir_ad_connection_interval_max = -1;
static gint hf_btcommon_eir_ad_uri = -1;
static gint hf_btcommon_eir_ad_ips_flags = -1;
static gint hf_btcommon_eir_ad_ips_flags_reserved = -1;
static gint hf_btcommon_eir_ad_ips_flags_location_name = -1;
static gint hf_btcommon_eir_ad_ips_flags_uncertainty = -1;
static gint hf_btcommon_eir_ad_ips_flags_floor_number = -1;
static gint hf_btcommon_eir_ad_ips_flags_altitude = -1;
static gint hf_btcommon_eir_ad_ips_flags_tx_power = -1;
static gint hf_btcommon_eir_ad_ips_flags_coordinate_system = -1;
static gint hf_btcommon_eir_ad_ips_flags_coordinates = -1;
static gint hf_btcommon_eir_ad_ips_uncertainty = -1;
static gint hf_btcommon_eir_ad_ips_uncertainty_reserved = -1;
static gint hf_btcommon_eir_ad_ips_uncertainty_precision = -1;
static gint hf_btcommon_eir_ad_ips_uncertainty_update_time = -1;
static gint hf_btcommon_eir_ad_ips_uncertainty_stationary = -1;
static gint hf_btcommon_eir_ad_ips_latitude = -1;
static gint hf_btcommon_eir_ad_ips_longitude = -1;
static gint hf_btcommon_eir_ad_ips_local_north_coordinate = -1;
static gint hf_btcommon_eir_ad_ips_local_east_coordinate = -1;
static gint hf_btcommon_eir_ad_ips_tx_power_level = -1;
static gint hf_btcommon_eir_ad_ips_floor_number = -1;
static gint hf_btcommon_eir_ad_ips_altitude = -1;
static gint hf_btcommon_eir_ad_tds_organization_id = -1;
static gint hf_btcommon_eir_ad_tds_flags = -1;
static gint hf_btcommon_eir_ad_tds_flags_reserved = -1;
static gint hf_btcommon_eir_ad_tds_flags_transport_state = -1;
static gint hf_btcommon_eir_ad_tds_flags_transport_data_incomplete = -1;
static gint hf_btcommon_eir_ad_tds_flags_role = -1;
static gint hf_btcommon_eir_ad_tds_data_length = -1;
static gint hf_btcommon_eir_ad_tds_data = -1;
static gint hf_btcommon_eir_ad_le_features = -1;
static gint hf_btcommon_eir_ad_le_channel_map = -1;
static gint hf_btcommon_eir_ad_instant = -1;
static gint hf_btcommon_eir_ad_le_features_encryption = -1;
static gint hf_btcommon_eir_ad_le_features_connection_parameters_request_procedure = -1;
static gint hf_btcommon_eir_ad_le_features_extended_reject_indication = -1;
static gint hf_btcommon_eir_ad_le_features_slave_initiated_features_exchange = -1;
static gint hf_btcommon_eir_ad_le_features_ping = -1;
static gint hf_btcommon_eir_ad_le_features_data_packet_length_extension = -1;
static gint hf_btcommon_eir_ad_le_features_ll_privacy = -1;
static gint hf_btcommon_eir_ad_le_features_extended_scanner_filter_policies = -1;
static gint hf_btcommon_eir_ad_le_features_2m_phy = -1;
static gint hf_btcommon_eir_ad_le_features_stable_modulation_index_tx =-1;
static gint hf_btcommon_eir_ad_le_features_stable_modulation_index_rx = -1;
static gint hf_btcommon_eir_ad_le_features_coded_phy = -1;
static gint hf_btcommon_eir_ad_le_features_extended_advertising = -1;
static gint hf_btcommon_eir_ad_le_features_periodic_advertising = -1;
static gint hf_btcommon_eir_ad_le_features_channel_selection_algorithm_2 = -1;
static gint hf_btcommon_eir_ad_le_features_power_class_1 = -1;
static gint hf_btcommon_eir_ad_le_features_minimum_number_of_used_channels_procedure = -1;
static gint hf_btcommon_eir_ad_le_features_reserved_1_7 = -1;
static gint hf_btcommon_eir_ad_le_features_reserved = -1;
static gint hf_btcommon_cod_class_of_device = -1;
static gint hf_btcommon_cod_format_type = -1;
static gint hf_btcommon_cod_major_service_class_information = -1;
static gint hf_btcommon_cod_major_service_class_telephony = -1;
static gint hf_btcommon_cod_major_service_class_audio = -1;
static gint hf_btcommon_cod_major_service_class_object_transfer = -1;
static gint hf_btcommon_cod_major_service_class_capturing = -1;
static gint hf_btcommon_cod_major_service_class_rendering = -1;
static gint hf_btcommon_cod_major_service_class_networking = -1;
static gint hf_btcommon_cod_major_service_class_positioning = -1;
static gint hf_btcommon_cod_major_service_class_reserved = -1;
static gint hf_btcommon_cod_major_service_class_limited_discoverable_mode = -1;
static gint hf_btcommon_cod_major_device_class = -1;
static gint hf_btcommon_cod_minor_device_class_computer = -1;
static gint hf_btcommon_cod_minor_device_class_phone = -1;
static gint hf_btcommon_cod_minor_device_class_lan_net_load_factor = -1;
static gint hf_btcommon_cod_minor_device_class_lan_net_type = -1;
static gint hf_btcommon_cod_minor_device_class_audio_video = -1;
static gint hf_btcommon_cod_minor_device_class_peripheral_class = -1;
static gint hf_btcommon_cod_minor_device_class_peripheral_type = -1;
static gint hf_btcommon_cod_minor_device_class_imaging_class_printer = -1;
static gint hf_btcommon_cod_minor_device_class_imaging_class_scanner = -1;
static gint hf_btcommon_cod_minor_device_class_imaging_class_camera = -1;
static gint hf_btcommon_cod_minor_device_class_imaging_class_display = -1;
static gint hf_btcommon_cod_minor_device_class_imaging_type = -1;
static gint hf_btcommon_cod_minor_device_class_wearable = -1;
static gint hf_btcommon_cod_minor_device_class_toy = -1;
static gint hf_btcommon_cod_minor_device_class_health = -1;
static gint hf_btcommon_cod_minor_device_class_unknown = -1;
static gint hf_btcommon_le_channel_map_0 = -1;
static gint hf_btcommon_le_channel_map_1 = -1;
static gint hf_btcommon_le_channel_map_2 = -1;
static gint hf_btcommon_le_channel_map_3 = -1;
static gint hf_btcommon_le_channel_map_4 = -1;
static gint hf_btcommon_le_channel_map_5 = -1;
static gint hf_btcommon_le_channel_map_6 = -1;
static gint hf_btcommon_le_channel_map_7 = -1;
static gint hf_btcommon_le_channel_map_8 = -1;
static gint hf_btcommon_le_channel_map_9 = -1;
static gint hf_btcommon_le_channel_map_10 = -1;
static gint hf_btcommon_le_channel_map_11 = -1;
static gint hf_btcommon_le_channel_map_12 = -1;
static gint hf_btcommon_le_channel_map_13 = -1;
static gint hf_btcommon_le_channel_map_14 = -1;
static gint hf_btcommon_le_channel_map_15 = -1;
static gint hf_btcommon_le_channel_map_16 = -1;
static gint hf_btcommon_le_channel_map_17 = -1;
static gint hf_btcommon_le_channel_map_18 = -1;
static gint hf_btcommon_le_channel_map_19 = -1;
static gint hf_btcommon_le_channel_map_20 = -1;
static gint hf_btcommon_le_channel_map_21 = -1;
static gint hf_btcommon_le_channel_map_22 = -1;
static gint hf_btcommon_le_channel_map_23 = -1;
static gint hf_btcommon_le_channel_map_24 = -1;
static gint hf_btcommon_le_channel_map_25 = -1;
static gint hf_btcommon_le_channel_map_26 = -1;
static gint hf_btcommon_le_channel_map_27 = -1;
static gint hf_btcommon_le_channel_map_28 = -1;
static gint hf_btcommon_le_channel_map_29 = -1;
static gint hf_btcommon_le_channel_map_30 = -1;
static gint hf_btcommon_le_channel_map_31 = -1;
static gint hf_btcommon_le_channel_map_32 = -1;
static gint hf_btcommon_le_channel_map_33 = -1;
static gint hf_btcommon_le_channel_map_34 = -1;
static gint hf_btcommon_le_channel_map_35 = -1;
static gint hf_btcommon_le_channel_map_36 = -1;
static gint hf_btcommon_le_channel_map_37 = -1;
static gint hf_btcommon_le_channel_map_38 = -1;
static gint hf_btcommon_le_channel_map_39 = -1;
static gint hf_btcommon_eir_ad_mesh_msg = -1;
static gint hf_btcommon_eir_ad_mesh_pbadv = -1;
static gint hf_btcommon_eir_ad_mesh_beacon = -1;

static int * const hfx_btcommon_eir_ad_ips_flags[] = {
    &hf_btcommon_eir_ad_ips_flags_reserved,
    &hf_btcommon_eir_ad_ips_flags_location_name,
    &hf_btcommon_eir_ad_ips_flags_uncertainty,
    &hf_btcommon_eir_ad_ips_flags_floor_number,
    &hf_btcommon_eir_ad_ips_flags_altitude,
    &hf_btcommon_eir_ad_ips_flags_tx_power,
    &hf_btcommon_eir_ad_ips_flags_coordinate_system,
    &hf_btcommon_eir_ad_ips_flags_coordinates,
    NULL
};

static int * const hfx_btcommon_eir_ad_ips_uncertainty[] = {
    &hf_btcommon_eir_ad_ips_uncertainty_reserved,
    &hf_btcommon_eir_ad_ips_uncertainty_precision,
    &hf_btcommon_eir_ad_ips_uncertainty_update_time,
    &hf_btcommon_eir_ad_ips_uncertainty_stationary,
    NULL
};

static int * const hfx_btcommon_eir_ad_tds_flags[] = {
    &hf_btcommon_eir_ad_tds_flags_reserved,
    &hf_btcommon_eir_ad_tds_flags_transport_state,
    &hf_btcommon_eir_ad_tds_flags_transport_data_incomplete,
    &hf_btcommon_eir_ad_tds_flags_role,
    NULL
};

static int * const hfx_btcommon_eir_ad_le_features_0[] = {
    &hf_btcommon_eir_ad_le_features_encryption,
    &hf_btcommon_eir_ad_le_features_connection_parameters_request_procedure,
    &hf_btcommon_eir_ad_le_features_extended_reject_indication,
    &hf_btcommon_eir_ad_le_features_slave_initiated_features_exchange,
    &hf_btcommon_eir_ad_le_features_ping,
    &hf_btcommon_eir_ad_le_features_data_packet_length_extension,
    &hf_btcommon_eir_ad_le_features_ll_privacy,
    &hf_btcommon_eir_ad_le_features_extended_scanner_filter_policies,
    NULL
};

static int * const hfx_btcommon_eir_ad_le_features_1[] = {
    &hf_btcommon_eir_ad_le_features_2m_phy,
    &hf_btcommon_eir_ad_le_features_stable_modulation_index_tx,
    &hf_btcommon_eir_ad_le_features_stable_modulation_index_rx,
    &hf_btcommon_eir_ad_le_features_coded_phy,
    &hf_btcommon_eir_ad_le_features_extended_advertising,
    &hf_btcommon_eir_ad_le_features_periodic_advertising,
    &hf_btcommon_eir_ad_le_features_channel_selection_algorithm_2,
    &hf_btcommon_eir_ad_le_features_power_class_1,
    NULL
};

static int * const hfx_btcommon_eir_ad_le_features_2[] = {
    &hf_btcommon_eir_ad_le_features_minimum_number_of_used_channels_procedure,
    &hf_btcommon_eir_ad_le_features_reserved_1_7,
    NULL
};

static int * const hfx_btcommon_eir_ad_le_features_reserved[] = {
    &hf_btcommon_eir_ad_le_features_reserved,
    NULL
};

static int * const *hfx_btcommon_eir_ad_le_features[] = {
    hfx_btcommon_eir_ad_le_features_0,
    hfx_btcommon_eir_ad_le_features_1,
    hfx_btcommon_eir_ad_le_features_2,
    hfx_btcommon_eir_ad_le_features_reserved,
    hfx_btcommon_eir_ad_le_features_reserved,
    hfx_btcommon_eir_ad_le_features_reserved,
    hfx_btcommon_eir_ad_le_features_reserved,
    hfx_btcommon_eir_ad_le_features_reserved
};

static gint ett_cod = -1;
static gint ett_eir_ad = -1;
static gint ett_eir_ad_entry = -1;
static gint ett_eir_ad_le_features = -1;

static expert_field ei_eir_ad_undecoded                               = EI_INIT;
static expert_field ei_eir_ad_unknown                                 = EI_INIT;
static expert_field ei_eir_ad_not_used                                = EI_INIT;
static expert_field ei_eir_ad_invalid_length                          = EI_INIT;

static dissector_handle_t btcommon_cod_handle;
static dissector_handle_t btcommon_eir_handle;
static dissector_handle_t btcommon_ad_handle;
static dissector_handle_t btcommon_le_channel_map_handle;
static dissector_handle_t bthci_cmd_handle;
static dissector_handle_t btmesh_handle;
static dissector_handle_t btmesh_pbadv_handle;
static dissector_handle_t btmesh_beacon_handle;
static dissector_handle_t gaen_handle;

static dissector_table_t  bluetooth_eir_ad_manufacturer_company_id;
static dissector_table_t  bluetooth_eir_ad_tds_organization_id;

wmem_tree_t *bthci_cmds = NULL;

extern value_string_ext ext_usb_vendors_vals;
extern value_string_ext ext_usb_products_vals;
extern value_string_ext did_vendor_id_source_vals_ext;

static const value_string bthci_cmd_ogf_vals[] = {
    { 0x01,  "Link Control Commands" },
    { 0x02,  "Link Policy Commands" },
    { 0x03,  "Host Controller & Baseband Commands" },
    { 0x04,  "Informational Parameters" },
    { 0x05,  "Status Parameters" },
    { 0x06,  "Testing Commands" },
    { 0x08,  "LE Controller Commands" },
    { 0x3E,  "Bluetooth Logo Testing Commands" },
    { 0x3F,  "Vendor-Specific Commands" },
    { 0, NULL }
};
value_string_ext bthci_cmd_ogf_vals_ext = VALUE_STRING_EXT_INIT(bthci_cmd_ogf_vals);

# define LINK_CONTROL_VALS(base) \
/* Bluetooth Core 4.0 */ \
    { (base) | 0x001,  "Inquiry" }, \
    { (base) | 0x002,  "Inquiry Cancel" }, \
    { (base) | 0x003,  "Periodic Inquiry Mode" }, \
    { (base) | 0x004,  "Exit Periodic Inquiry Mode" }, \
    { (base) | 0x005,  "Create Connection" }, \
    { (base) | 0x006,  "Disconnect" }, \
    { (base) | 0x007,  "Add SCO Connection" }, \
    { (base) | 0x008,  "Create Connection Cancel" }, \
    { (base) | 0x009,  "Accept Connection Request" }, \
    { (base) | 0x00A,  "Reject Connection Request" }, \
    { (base) | 0x00B,  "Link Key Request Reply" }, \
    { (base) | 0x00C,  "Link Key Request Negative Reply" }, \
    { (base) | 0x00D,  "PIN Code Request Reply" }, \
    { (base) | 0x00E,  "PIN Code Request Negative Reply" }, \
    { (base) | 0x00F,  "Change Connection Packet Type" }, \
    { (base) | 0x011,  "Authentication Requested" }, \
    { (base) | 0x013,  "Set Connection Encryption" }, \
    { (base) | 0x015,  "Change Connection Link Key" }, \
    { (base) | 0x017,  "Master Link Key" }, \
    { (base) | 0x019,  "Remote Name Request" }, \
    { (base) | 0x01A,  "Remote Name Request Cancel" }, \
    { (base) | 0x01B,  "Read Remote Supported Features" }, \
    { (base) | 0x01C,  "Read Remote Extended Features" }, \
    { (base) | 0x01D,  "Read Remote Version Information" }, \
    { (base) | 0x01F,  "Read Clock offset" }, \
    { (base) | 0x020,  "Read LMP Handle" }, \
    { (base) | 0x028,  "Setup Synchronous Connection" }, \
    { (base) | 0x029,  "Accept Synchronous Connection Request" }, \
    { (base) | 0x02A,  "Reject Synchronous Connection Request" }, \
    { (base) | 0x02B,  "IO Capability Request Reply" }, \
    { (base) | 0x02C,  "User Confirmation Request Reply" }, \
    { (base) | 0x02D,  "User Confirmation Request Negative Reply" }, \
    { (base) | 0x02E,  "User Passkey Request Reply" }, \
    { (base) | 0x02F,  "User Passkey Request Negative Reply" }, \
    { (base) | 0x030,  "Remote OOB Data Request Reply" }, \
    { (base) | 0x033,  "Remote OOB Data Request Negative Reply" }, \
    { (base) | 0x034,  "IO Capability Request Negative Reply" }, \
    { (base) | 0x035,  "Create Physical Link" }, \
    { (base) | 0x036,  "Accept Physical Link" }, \
    { (base) | 0x037,  "Disconnect Physical Link" }, \
    { (base) | 0x038,  "Create Logical Link" }, \
    { (base) | 0x039,  "Accept Logical Link" }, \
    { (base) | 0x03A,  "Disconnect Logical Link" }, \
    { (base) | 0x03B,  "Logical Link Cancel" }, \
    { (base) | 0x03C,  "Flow Spec Modify" }, \
/* Bluetooth Core Specification Addendum 2 */ \
    { (base) | 0x03D,  "Enhanced Setup Synchronous Connection" }, \
    { (base) | 0x03E,  "Enhanced Accept Synchronous Connection Request" }, \
/* Bluetooth Core Specification Addendum 4 */ \
    { (base) | 0x03F,  "Truncated Page" }, \
    { (base) | 0x040,  "Truncated Page Cancel" }, \
    { (base) | 0x041,  "Set Connectionless Slave Broadcast" }, \
    { (base) | 0x042,  "Set Connectionless Slave Broadcast Receive" }, \
    { (base) | 0x043,  "Start Synchronization Train" }, \
    { (base) | 0x044,  "Receive Synchronization Train" }, \
    { (base) | 0x045,  "Remote OOB Extended Data Request Reply" } \

static const value_string bthci_cmd_ocf_link_control_vals[] = {
    LINK_CONTROL_VALS(0x0), \
    { 0, NULL }
};

value_string_ext bthci_cmd_ocf_link_control_vals_ext = VALUE_STRING_EXT_INIT(bthci_cmd_ocf_link_control_vals);

#define LINK_POLICY_VALS(base) \
/* Bluetooth Core 4.0 */              \
    { (base) | 0x001,  "Hold Mode" }, \
    { (base) | 0x003,  "Sniff Mode" }, \
    { (base) | 0x004,  "Exit Sniff Mode" }, \
    { (base) | 0x005,  "Park Mode" }, \
    { (base) | 0x006,  "Exit Park Mode" }, \
    { (base) | 0x007,  "QoS Setup" }, \
    { (base) | 0x009,  "Role Discovery" }, \
    { (base) | 0x00b,  "Switch Role" }, \
    { (base) | 0x00c,  "Read Link Policy Settings" }, \
    { (base) | 0x00d,  "Write Link Policy Settings" }, \
    { (base) | 0x00e,  "Read Default Link Policy Settings" }, \
    { (base) | 0x00f,  "Write Default Link Policy Settings" }, \
    { (base) | 0x010,  "Flow Specification" }, \
    { (base) | 0x011,  "Sniff Subrating" }

static const value_string bthci_cmd_ocf_link_policy_vals[] = {
LINK_POLICY_VALS(0x0),
    { 0, NULL }
};

value_string_ext bthci_cmd_ocf_link_policy_vals_ext = VALUE_STRING_EXT_INIT(bthci_cmd_ocf_link_policy_vals);

#define HOST_CONTROLLER_AND_BASEBAND_VALS(base) \
/* Bluetooth Core 4.0 */ \
    { (base) | 0x001,  "Set Event Mask" }, \
    { (base) | 0x003,  "Reset" }, \
    { (base) | 0x005,  "Set Event Filter" }, \
    { (base) | 0x008,  "Flush" }, \
    { (base) | 0x009,  "Read PIN Type" }, \
    { (base) | 0x00A,  "Write PIN Type" }, \
    { (base) | 0x00B,  "Create New Unit Key" }, \
    { (base) | 0x00D,  "Read Stored Link Key" }, \
    { (base) | 0x011,  "Write Stored Link Key" }, \
    { (base) | 0x012,  "Delete Stored Link Key" }, \
    { (base) | 0x013,  "Change Local Name" }, \
    { (base) | 0x014,  "Read Local Name" }, \
    { (base) | 0x015,  "Read Connection Accept Timeout" }, \
    { (base) | 0x016,  "Write Connection Accept Timeout" }, \
    { (base) | 0x017,  "Read Page Timeout" }, \
    { (base) | 0x018,  "Write Page Timeout" }, \
    { (base) | 0x019,  "Read Scan Enable" }, \
    { (base) | 0x01A,  "Write Scan Enable" }, \
    { (base) | 0x01B,  "Read Page Scan Activity" }, \
    { (base) | 0x01C,  "Write Page Scan Activity" }, \
    { (base) | 0x01D,  "Read Inquiry Scan Activity" }, \
    { (base) | 0x01E,  "Write Inquiry Scan Activity" }, \
    { (base) | 0x01F,  "Read Authentication Enable" }, \
    { (base) | 0x020,  "Write Authentication Enable" }, \
    { (base) | 0x021,  "Read Encryption Mode" }, \
    { (base) | 0x022,  "Write Encryption Mode" }, \
    { (base) | 0x023,  "Read Class of Device" }, \
    { (base) | 0x024,  "Write Class of Device" }, \
    { (base) | 0x025,  "Read Voice Setting" }, \
    { (base) | 0x026,  "Write Voice Setting" }, \
    { (base) | 0x027,  "Read Automatic Flush Timeout" }, \
    { (base) | 0x028,  "Write Automatic Flush Timeout" }, \
    { (base) | 0x029,  "Read Num Broadcast Retransmissions" }, \
    { (base) | 0x02A,  "Write Num Broadcast Retransmissions" }, \
    { (base) | 0x02B,  "Read Hold Mode Activity" }, \
    { (base) | 0x02C,  "Write Hold Mode Activity" }, \
    { (base) | 0x02D,  "Read Tx Power Level" }, \
    { (base) | 0x02E,  "Read SCO Flow Control Enable" }, \
    { (base) | 0x02F,  "Write SCO Flow Control Enable" }, \
    { (base) | 0x031,  "Set Host Controller To Host Flow Control" }, \
    { (base) | 0x033,  "Host Buffer Size" }, \
    { (base) | 0x035,  "Host Number of Completed Packets" }, \
    { (base) | 0x036,  "Read Link Supervision Timeout" }, \
    { (base) | 0x037,  "Write Link Supervision Timeout" }, \
    { (base) | 0x038,  "Read Number of Supported IAC" }, \
    { (base) | 0x039,  "Read Current IAC LAP" }, \
    { (base) | 0x03A,  "Write Current IAC LAP" }, \
    { (base) | 0x03B,  "Read Page Scan Period Mode" }, \
    { (base) | 0x03C,  "Write Page Scan Period Mode" }, \
    { (base) | 0x03D,  "Read Page Scan Mode" }, \
    { (base) | 0x03E,  "Write Page Scan Mode" }, \
    { (base) | 0x03F,  "Set AFH Host Channel Classification" }, \
    { (base) | 0x042,  "Read Inquiry Scan Type" }, \
    { (base) | 0x043,  "Write Inquiry Scan Type" }, \
    { (base) | 0x044,  "Read Inquiry Mode" }, \
    { (base) | 0x045,  "Write Inquiry Mode" }, \
    { (base) | 0x046,  "Read Page Scan Type" }, \
    { (base) | 0x047,  "Write Page Scan Type" }, \
    { (base) | 0x048,  "Read AFH Channel Assessment Mode" }, \
    { (base) | 0x049,  "Write AFH Channel Assessment Mode" }, \
    { (base) | 0x051,  "Read Extended Inquiry Response" }, \
    { (base) | 0x052,  "Write Extended Inquiry Response" }, \
    { (base) | 0x053,  "Refresh Encryption Key" }, \
    { (base) | 0x055,  "Read Simple Pairing Mode" }, \
    { (base) | 0x056,  "Write Simple Pairing Mode" }, \
    { (base) | 0x057,  "Read Local OOB Data" }, \
    { (base) | 0x058,  "Read Inquiry Response Tx Power Level" }, \
    { (base) | 0x059,  "Write Inquiry Tx Power Level" }, \
    { (base) | 0x05A,  "Read Default Erroneous Data Reporting" }, \
    { (base) | 0x05B,  "Write Default Erroneous Data Reporting" }, \
    { (base) | 0x05F,  "Enhanced Flush" }, \
    { (base) | 0x060,  "Send Keypress Notification" }, \
    { (base) | 0x061,  "Read Logical Link Accept Timeout" }, \
    { (base) | 0x062,  "Write Logical Link Accept Timeout" }, \
    { (base) | 0x063,  "Set Event Mask Page 2" }, \
    { (base) | 0x064,  "Read Location Data" }, \
    { (base) | 0x065,  "Write Location Data" }, \
    { (base) | 0x066,  "Read Flow Control Mode" }, \
    { (base) | 0x067,  "Write Flow Control Mode" }, \
    { (base) | 0x068,  "Read Enhanced Transmit Power Level" }, \
    { (base) | 0x069,  "Read Best Effort Flush Timeout" }, \
    { (base) | 0x06A,  "Write Best Effort Flush Timeout" }, \
    { (base) | 0x06B,  "Short Range Mode" }, \
    { (base) | 0x06C,  "Read LE Host Supported" }, \
    { (base) | 0x06D,  "Write LE Host Supported" }, \
/* Bluetooth Core Specification Addendum 3 */ \
    { (base) | 0x06E,  "Set MWS Channel Parameters"}, \
    { (base) | 0x06F,  "Set External Frame Configuration"}, \
    { (base) | 0x070,  "Set MWS Signaling"}, \
    { (base) | 0x071,  "Set MWS Transport Layer"}, \
    { (base) | 0x072,  "Set MWS Scan Frequency Table"}, \
    { (base) | 0x073,  "Set MWS Pattern Configuration"}, \
/* Bluetooth Core Specification Addendum 4 */ \
    { (base) | 0x074,  "Set Reserved LT_ADDR" }, \
    { (base) | 0x075,  "Delete Reserved LT_ADDR" }, \
    { (base) | 0x076,  "Set Connectionless Slave Broadcast Data" }, \
    { (base) | 0x077,  "Read Synchronization Train Parameters" }, \
    { (base) | 0x078,  "Write Synchronization Train Parameters" }, \
    { (base) | 0x079,  "Read Secure Connections Host Support" }, \
    { (base) | 0x07A,  "Write Secure Connections Host Support" }, \
    { (base) | 0x07B,  "Read Authenticated Payload Timeout" }, \
    { (base) | 0x07C,  "Write Authenticated Payload Timeout" }, \
    { (base) | 0x07D,  "Read Local OOB Extended Data" }, \
    { (base) | 0x07E,  "Read Extended Page Timeout" }, \
    { (base) | 0x07F,  "Write Extended Page Timeout" }, \
    { (base) | 0x080,  "Read Extended Inquiry Length" }, \
    { (base) | 0x081,  "Write Extended Inquiry Length" }

static const value_string bthci_cmd_ocf_host_controller_and_baseband_vals[] = {
    HOST_CONTROLLER_AND_BASEBAND_VALS(0x0),
    { 0, NULL }
};

value_string_ext bthci_cmd_ocf_host_controller_and_baseband_vals_ext = VALUE_STRING_EXT_INIT(bthci_cmd_ocf_host_controller_and_baseband_vals);

#define INFORMATIONAL_VALS(base) \
/* Bluetooth Core 4.0 */ \
    { (base) | 0x001,  "Read Local Version Information" }, \
    { (base) | 0x002,  "Read Local Supported Commands" }, \
    { (base) | 0x003,  "Read Local Supported Features" }, \
    { (base) | 0x004,  "Read Local Extended Features" }, \
    { (base) | 0x005,  "Read Buffer Size" }, \
    { (base) | 0x007,  "Read Country Code" }, \
    { (base) | 0x009,  "Read BD ADDR" }, \
    { (base) | 0x00A,  "Read Data Block Size" }, \
/* Bluetooth Core Specification Addendum 2 */ \
    { (base) | 0x00B,  "Read Local Supported Codecs" }, \
/* Bluetooth Core 5.1 */ \
    { (base) | 0x00C,  "Read Local Simple Pairing Options" }

static const value_string bthci_cmd_ocf_informational_vals[] = {
    INFORMATIONAL_VALS(0x0),
    { 0, NULL }
};

value_string_ext bthci_cmd_ocf_informational_vals_ext = VALUE_STRING_EXT_INIT(bthci_cmd_ocf_informational_vals);


#define STATUS_VALS(base) \
/* Bluetooth Core 4.0 */ \
    { (base) | 0x001, "Read Failed Contact Counter" }, \
    { (base) | 0x002, "Reset Failed Contact Counter" }, \
    { (base) | 0x003, "Read Link Quality" }, \
    { (base) | 0x005, "Read RSSI" }, \
    { (base) | 0x006, "Read AFH Channel Map" }, \
    { (base) | 0x007, "Read Clock" }, \
    { (base) | 0x008, "Read Encryption Key Size" }, \
    { (base) | 0x009, "Read Local AMP Info" }, \
    { (base) | 0x00A, "Read Local AMP Assoc" }, \
    { (base) | 0x00B, "Write Remote AMP Assoc" }, \
/* Bluetooth Core Specification Addendum 3 */ \
    { (base) | 0x00C,  "Get MWS Transport Layer Configuration" }, \
/* Bluetooth Core Specification Addendum 4 */ \
    { (base) | 0x00D,  "Set Triggered Clock Capture" }

static const value_string bthci_cmd_ocf_status_vals[] = {
    STATUS_VALS(0x0),
    { 0, NULL }
};

value_string_ext bthci_cmd_ocf_status_vals_ext = VALUE_STRING_EXT_INIT(bthci_cmd_ocf_status_vals);

#define TESTING_VALS(base) \
/* Bluetooth Core 4.0 */ \
    { (base) | 0x001,  "Read Loopback Mode" }, \
    { (base) | 0x002,  "Write Loopback Mode" }, \
    { (base) | 0x003,  "Enable Device Under Test Mode" }, \
    { (base) | 0x004,  "Write Simple Pairing Debug Mode" }, \
    { (base) | 0x007,  "Enable AMP Receiver Reports" }, \
    { (base) | 0x008,  "AMP Test End" }, \
    { (base) | 0x009,  "AMP Test" }, \
    { (base) | 0x00A,  "Write Secure Connections Test Mode" }

static const value_string bthci_cmd_ocf_testing_vals[] = {
    TESTING_VALS(0x0),
    { 0, NULL }
};

value_string_ext bthci_cmd_ocf_testing_vals_ext = VALUE_STRING_EXT_INIT(bthci_cmd_ocf_testing_vals);

#define LOW_ENERGY_VALS(base)\
/* Bluetooth Core 4.0 */ \
    { (base) | 0x001,  "LE Set Event Mask" }, \
    { (base) | 0x002,  "LE Read Buffer Size [v1]" }, \
    { (base) | 0x003,  "LE Read Local Supported Features" }, \
    { (base) | 0x005,  "LE Set Random Address" }, \
    { (base) | 0x006,  "LE Set Advertising Parameters" }, \
    { (base) | 0x007,  "LE Read Advertising Channel Tx Power" }, \
    { (base) | 0x008,  "LE Set Advertising Data" }, \
    { (base) | 0x009,  "LE Set Scan Response Data" }, \
    { (base) | 0x00A,  "LE Set Advertise Enable" }, \
    { (base) | 0x00B,  "LE Set Scan Parameters" }, \
    { (base) | 0x00C,  "LE Set Scan Enable" }, \
    { (base) | 0x00D,  "LE Create Connection" }, \
    { (base) | 0x00E,  "LE Create Connection Cancel" }, \
    { (base) | 0x00F,  "LE Read White List Size" }, \
    { (base) | 0x010,  "LE Clear White List" }, \
    { (base) | 0x011,  "LE Add Device To White List" }, \
    { (base) | 0x012,  "LE Remove Device From White List" }, \
    { (base) | 0x013,  "LE Connection Update" }, \
    { (base) | 0x014,  "LE Set Host Channel Classification" }, \
    { (base) | 0x015,  "LE Read Channel Map" }, \
    { (base) | 0x016,  "LE Read Remote Features" }, \
    { (base) | 0x017,  "LE Encrypt" }, \
    { (base) | 0x018,  "LE Rand" }, \
    { (base) | 0x019,  "LE Start Encryption" }, \
    { (base) | 0x01A,  "LE Long Term Key Request Reply" }, \
    { (base) | 0x01B,  "LE Long Term Key Request Negative Reply" }, \
    { (base) | 0x01C,  "LE Read Supported States" }, \
    { (base) | 0x01D,  "LE Receiver Test [v1]" }, \
    { (base) | 0x01E,  "LE Transmitter Test [v1]" }, \
    { (base) | 0x01F,  "LE Test End" }, \
/* Bluetooth Core 4.1 */ \
    { (base) | 0x020,  "LE Remote Connection Parameter Request Reply" }, \
    { (base) | 0x021,  "LE Remote Connection Parameter Request Negative Reply" }, \
/* Bluetooth Core 4.2 */ \
    { (base) | 0x022,  "LE Set Data Length" }, \
    { (base) | 0x023,  "LE Read Suggested Default Data Length" }, \
    { (base) | 0x024,  "LE Write Suggested Default Data Length" }, \
    { (base) | 0x025,  "LE Read Local P-256 Public Key" }, \
    { (base) | 0x026,  "LE Generate DHKey [v1]" }, \
    { (base) | 0x027,  "LE Add Device to Resolving List" }, \
    { (base) | 0x028,  "LE Remove Device From Resolving List" }, \
    { (base) | 0x029,  "LE Clear Resolving List" }, \
    { (base) | 0x02A,  "LE Read Resolving List Size" }, \
    { (base) | 0x02B,  "LE Read Peer Resolvable Address" }, \
    { (base) | 0x02C,  "LE Read Local Resolvable Address" }, \
    { (base) | 0x02D,  "LE Set Address Resolution Enable" }, \
    { (base) | 0x02E,  "LE Set Resolvable Private Address Timeout" }, \
    { (base) | 0x02F,  "LE Read Maximum Data Length" }, \
/* Bluetooth Core 5.0 */ \
    { (base) | 0x030,  "LE Read PHY" }, \
    { (base) | 0x031,  "LE Set Default PHY" }, \
    { (base) | 0x032,  "LE Set PHY" }, \
    { (base) | 0x033,  "LE Receiver Test [v2]" }, \
    { (base) | 0x034,  "LE Transmitter Test [v2]" }, \
    { (base) | 0x035,  "LE Set Advertising Set Random Address" }, \
    { (base) | 0x036,  "LE Set Extended Advertising Parameters" }, \
    { (base) | 0x037,  "LE Set Extended Advertising Data" }, \
    { (base) | 0x038,  "LE Set Extended Scan Response Data" }, \
    { (base) | 0x039,  "LE Set Extended Advertising Enable" }, \
    { (base) | 0x03A,  "LE Read Maximum Advertising Data Length" }, \
    { (base) | 0x03B,  "LE Read Number of Supported Advertising Sets" }, \
    { (base) | 0x03C,  "LE Remove Advertising Set" }, \
    { (base) | 0x03D,  "LE Clear Advertising Sets" }, \
    { (base) | 0x03E,  "LE Set Periodic Advertising Parameters" }, \
    { (base) | 0x03F,  "LE Set Periodic Advertising Data" }, \
    { (base) | 0x040,  "LE Set Periodic Advertising Enable" }, \
    { (base) | 0x041,  "LE Set Extended Scan Parameters" }, \
    { (base) | 0x042,  "LE Set Extended Scan Enable" }, \
    { (base) | 0x043,  "LE Extended Create Connection" }, \
    { (base) | 0x044,  "LE Periodic Advertising Create Sync" }, \
    { (base) | 0x045,  "LE Periodic Advertising Create Sync Cancel" }, \
    { (base) | 0x046,  "LE Periodic Advertising Terminate Sync" }, \
    { (base) | 0x047,  "LE Add Device To Periodic Advertiser List" }, \
    { (base) | 0x048,  "LE Remove Device From Periodic Advertiser List" }, \
    { (base) | 0x049,  "LE Clear Periodic Advertiser List" }, \
    { (base) | 0x04A,  "LE Read Periodic Advertiser List Size" }, \
    { (base) | 0x04B,  "LE Read Transmit Power" }, \
    { (base) | 0x04C,  "LE Read RF Path Compensation" }, \
    { (base) | 0x04D,  "LE Write RF Path Compensation" }, \
    { (base) | 0x04E,  "LE Set Privacy Mode" }, \
/* Bluetooth Core 5.1 */ \
    { (base) | 0x04F,  "LE Receiver Test [v3]" }, \
    { (base) | 0x050,  "LE Transmitter Test [v3]" }, \
    { (base) | 0x051,  "LE Set Connectionless CTE Transmit Parameters" }, \
    { (base) | 0x052,  "LE Set Connectionless CTE Transmit Enable" }, \
    { (base) | 0x053,  "LE Set Connectionless IQ Sampling Enable" }, \
    { (base) | 0x054,  "LE Set Connection CTE Receive Parameters" }, \
    { (base) | 0x055,  "LE Set Connection CTE Transmit Parameters" }, \
    { (base) | 0x056,  "LE Connection CTE Request Enable" }, \
    { (base) | 0x057,  "LE Connection CTE Response Enable" }, \
    { (base) | 0x058,  "LE Read Antenna Information" }, \
    { (base) | 0x059,  "LE Set Periodic Advertising Receive Enable" }, \
    { (base) | 0x05A,  "LE Periodic Advertising Sync Transfer" }, \
    { (base) | 0x05B,  "LE Periodic Advertising Set Info Transfer" }, \
    { (base) | 0x05C,  "LE Set Periodic Advertising Sync Transfer Parameters" }, \
    { (base) | 0x05D,  "LE Set Default Periodic Advertising Sync Transfer Parameters" }, \
    { (base) | 0x05E,  "LE Generate DHKey [v2]" }, \
    { (base) | 0x05F,  "LE Modify Sleep Clock Accuracy" }, \
/* Bluetooth Core 5.2 */ \
    { (base) | 0x060,  "LE Read Buffer Size [v2]" }, \
    { (base) | 0x061,  "LE Read ISO Tx Sync" }, \
    { (base) | 0x062,  "LE Set CIG Parameters" }, \
    { (base) | 0x063,  "LE Set CIG Parameters Test" }, \
    { (base) | 0x064,  "LE Create CIS" }, \
    { (base) | 0x065,  "LE Remove CIG" }, \
    { (base) | 0x066,  "LE Accept CIS Request" }, \
    { (base) | 0x067,  "LE Reject CIS Request" }, \
    { (base) | 0x068,  "LE Create BIG" }, \
    { (base) | 0x069,  "LE Create BIG Test" }, \
    { (base) | 0x06A,  "LE Terminate BIG" }, \
    { (base) | 0x06B,  "LE BIG Create Sync" }, \
    { (base) | 0x06C,  "LE BIG Terminate Sync" }, \
    { (base) | 0x06D,  "LE Request Peer SCA" }, \
    { (base) | 0x06E,  "LE Setup ISO Data Path" }, \
    { (base) | 0x06F,  "LE Remove ISO Data Path" }, \
    { (base) | 0x070,  "LE ISO Transmit Test" }, \
    { (base) | 0x071,  "LE ISO Receive Test" }, \
    { (base) | 0x072,  "LE ISO Read Test Counters" }, \
    { (base) | 0x073,  "LE ISO Test End" }, \
    { (base) | 0x074,  "LE Set Host Feature" }, \
    { (base) | 0x075,  "LE Read ISO Link Quality" }, \
    { (base) | 0x076,  "LE Enhanced Read Transmit Power Level" }, \
    { (base) | 0x077,  "LE Read Remote Transmit Power Level" }, \
    { (base) | 0x078,  "LE Set Path Loss Reporting Parameters" }, \
    { (base) | 0x079,  "LE Set Path Loss Reporting Enable" }, \
    { (base) | 0x07A,  "LE Set Transmit Power Reporting Enable" }, \
    { (base) | 0x07B,  "LE Transmitter Test [v4]" }

static const value_string bthci_cmd_ocf_low_energy_vals[] = {
    LOW_ENERGY_VALS(0x0),
    { 0, NULL }
};

value_string_ext bthci_cmd_ocf_low_energy_vals_ext = VALUE_STRING_EXT_INIT(bthci_cmd_ocf_low_energy_vals);


static const value_string bthci_cmd_opcode_vals[] = {
    {0x0, "No Operation"},
    LINK_CONTROL_VALS(0x01 << 10),
    LINK_POLICY_VALS(0x02 << 10),
    HOST_CONTROLLER_AND_BASEBAND_VALS(0x03 << 10),
    INFORMATIONAL_VALS(0x04 << 10),
    STATUS_VALS(0x05 << 10),
    TESTING_VALS(0x06 << 10),
    LOW_ENERGY_VALS(0x08 << 10),
    { 0, NULL }
};

value_string_ext bthci_cmd_opcode_vals_ext = VALUE_STRING_EXT_INIT(bthci_cmd_opcode_vals);

static const value_string bthci_cmd_status_vals[] = {
    {0x00, "Success"},
    {0x01, "Unknown HCI Command"},
    {0x02, "Unknown Connection Identifier"},
    {0x03, "Hardware Failure"},
    {0x04, "Page Timeout"},
    {0x05, "Authentication Failure"},
    {0x06, "PIN or Key Missing"},
    {0x07, "Memory Capacity Exceeded"},
    {0x08, "Connection Timeout"},
    {0x09, "Connection Limit Exceeded"},
    {0x0A, "Synchronous Connection Limit To A Device Exceeded"},
    {0x0B, "ACL Connection Already Exists"},
    {0x0C, "Command Disallowed"},
    {0x0D, "Connection Rejected due to Limited Resources"},
    {0x0E, "Connection Rejected due To Security Reasons"},
    {0x0F, "Connection Rejected due to Unacceptable BD_ADDR"},
    {0x10, "Connection Accept Timeout Exceeded"},
    {0x11, "Unsupported Feature or Parameter Value"},
    {0x12, "Invalid HCI Command Parameters"},
    {0x13, "Remote User Terminated Connection"},
    {0x14, "Remote Device Terminated Connection due to Low Resources"},
    {0x15, "Remote Device Terminated Connection due to Power Off"},
    {0x16, "Connection Terminated by Local Host"},
    {0x17, "Repeated Attempts"},
    {0x18, "Pairing Not Allowed"},
    {0x19, "Unknown LMP PDU"},
    {0x1A, "Unsupported Remote/LMP Feature"},
    {0x1B, "SCO Offset Rejected"},
    {0x1C, "SCO Interval Rejected"},
    {0x1D, "SCO Air Mode Rejected"},
    {0x1E, "Invalid LMP/LL Parameters"},
    {0x1F, "Unspecified Error"},
    {0x20, "Unsupported LMP/LL Parameter Value"},
    {0x21, "Role Change Not Allowed"},
    {0x22, "LMP/LL Response Timeout"},
    {0x23, "LMP Error Transaction Collision/LL Procedure Collision"},
    {0x24, "LMP PDU Not Allowed"},
    {0x25, "Encryption Mode Not Acceptable"},
    {0x26, "Link Key cannot be Changed"},
    {0x27, "Requested QoS Not Supported"},
    {0x28, "Instant Passed"},
    {0x29, "Pairing with Unit Key Not Supported"},
    {0x2A, "Different Transaction Collision"},
    {0x2C, "QoS Unacceptable Parameter"},
    {0x2D, "QoS Rejected"},
    {0x2E, "Channel Classification Not Supported"},
    {0x2F, "Insufficient Security"},
    {0x30, "Parameter Out Of Mandatory Range"},
    {0x32, "Role Switch Pending"},
    {0x34, "Reserved Slot Violation"},
    {0x35, "Role Switch Failed"},
    {0x36, "Extended Inquiry Response Too Large"},
    {0x37, "Secure Simple Pairing Not Supported By Host"},
    {0x38, "Host Busy - Pairing"},
    {0x39, "Connection Rejected due to No Suitable Channel Found"},
    {0x3A, "Controller Busy"},
    {0x3B, "Unacceptable Connection Parameters"},
    {0x3C, "Directed Advertising Timeout"},
    {0x3D, "Connection Terminated due to MIC Failure"},
    {0x3E, "Connection Failed to be Established"},
    {0x3F, "MAC Connection Failed"},
    {0x40, "Coarse Clock Adjustment Rejected but Will Try to Adjust Using Clock Dragging"},
    {0x41, "Type0 Submap Not Defined"},
    {0x42, "Unknown Advertising Identifier"},
    {0x43, "Limit Reached"},
    {0x44, "Operation Cancelled by Host"},
    {0x45, "Packet Too Long"},
    {0, NULL }
};
value_string_ext bthci_cmd_status_vals_ext = VALUE_STRING_EXT_INIT(bthci_cmd_status_vals);

static const value_string bthci_cmd_cod_major_device_class_vals[] = {
    {0x00, "Miscellaneous"},
    {0x01, "Computer"},
    {0x02, "Phone"},
    {0x03, "LAN/Network Access Point"},
    {0x04, "Audio/Video"},
    {0x05, "Peripheral (HID)"},
    {0x06, "Imaging"},
    {0x07, "Wearable"},
    {0x08, "Toy"},
    {0x09, "Health"},
    {0x1F, "Uncategorized: device code not specified"},
    {0, NULL }
};
value_string_ext bthci_cmd_cod_major_device_class_vals_ext = VALUE_STRING_EXT_INIT(bthci_cmd_cod_major_device_class_vals);

static const value_string bthci_cmd_cod_minor_device_class_computer_vals[] = {
    { 0x00,  "Uncategorized, code for device not assigned" },
    { 0x01,  "Desktop workstation" },
    { 0x02,  "Server-class computer" },
    { 0x03,  "Laptop" },
    { 0x04,  "Handheld PC/PDA (clamshell)" },
    { 0x05,  "Palm-size PC/PDA" },
    { 0x06,  "Wearable computer (watch size)" },
    { 0x07,  "Tablet" },
    { 0, NULL }
};
value_string_ext bthci_cmd_cod_minor_device_class_computer_vals_ext = VALUE_STRING_EXT_INIT(bthci_cmd_cod_minor_device_class_computer_vals);

static const value_string bthci_cmd_cod_minor_device_class_phone_vals[] = {
    { 0x00,  "Uncategorized, code for device not assigned" },
    { 0x01,  "Cellular" },
    { 0x02,  "Cordless" },
    { 0x03,  "Smartphone" },
    { 0x04,  "Wired modem or voice gateway" },
    { 0x05,  "Common ISDN access" },
    { 0, NULL }
};
value_string_ext bthci_cmd_cod_minor_device_class_phone_vals_ext = VALUE_STRING_EXT_INIT(bthci_cmd_cod_minor_device_class_phone_vals);

static const value_string bthci_cmd_cod_minor_device_class_lan_net_load_factor_vals[] = {
    { 0x00,  "Fully available" },
    { 0x01,  "1% to 17% utilized" },
    { 0x02,  "17% to 33% utilized" },
    { 0x03,  "33% to 50% utilized" },
    { 0x04,  "50% to 67% utilized" },
    { 0x05,  "67% to 83% utilized" },
    { 0x06,  "83% to 99% utilized" },
    { 0x07,  "No service available" },
    { 0, NULL }
};
value_string_ext bthci_cmd_cod_minor_device_class_lan_net_load_factor_vals_ext = VALUE_STRING_EXT_INIT(bthci_cmd_cod_minor_device_class_lan_net_load_factor_vals);

static const value_string bthci_cmd_cod_minor_device_class_lan_net_type_vals[] = {
    { 0x00,  "Uncategorized (used if no others apply)" },
    { 0, NULL }
};
value_string_ext bthci_cmd_cod_minor_device_class_lan_net_type_vals_ext = VALUE_STRING_EXT_INIT(bthci_cmd_cod_minor_device_class_lan_net_type_vals);

static const value_string bthci_cmd_cod_minor_device_class_audio_video_vals[] = {
    { 0x00,  "Uncategorized, code not assigned" },
    { 0x01,  "Wearable Headset Device" },
    { 0x02,  "Hands-free Device" },
    { 0x04,  "Microphone" },
    { 0x05,  "Loudspeaker" },
    { 0x06,  "Headphones" },
    { 0x07,  "Portable Audio" },
    { 0x08,  "Car audio" },
    { 0x09,  "Set-top box" },
    { 0x0A,  "HiFi Audio Device" },
    { 0x0B,  "VCR" },
    { 0x0C,  "Video Camera" },
    { 0x0D,  "Camcorder" },
    { 0x0E,  "Video Monitor" },
    { 0x0F,  "Video Display and Loudspeaker" },
    { 0x10,  "Video Conferencing" },
    { 0x12,  "Gaming/Toy" },
    { 0, NULL }
};
value_string_ext bthci_cmd_cod_minor_device_class_audio_video_vals_ext = VALUE_STRING_EXT_INIT(bthci_cmd_cod_minor_device_class_audio_video_vals);

static const value_string bthci_cmd_cod_minor_device_class_peripheral_class_vals[] = {
    { 0x00,  "Not Keyboard / Not Pointing Device" },
    { 0x01,  "Keyboard" },
    { 0x02,  "Pointing device" },
    { 0x03,  "Combo keyboard/pointing device" },
    { 0, NULL }
};
value_string_ext bthci_cmd_cod_minor_device_class_peripheral_class_vals_ext = VALUE_STRING_EXT_INIT(bthci_cmd_cod_minor_device_class_peripheral_class_vals);

static const value_string bthci_cmd_cod_minor_device_class_peripheral_type_vals[] = {
    { 0x00,  "Uncategorized device" },
    { 0x01,  "Joystick" },
    { 0x02,  "Gamepad" },
    { 0x03,  "Remote control" },
    { 0x04,  "Sensing device" },
    { 0x05,  "Digitizer tablet" },
    { 0x06,  "Card Reader" },
    { 0x07,  "Digital Pen" },
    { 0x08,  "Handheld scanner for bar-codes" },
    { 0x09,  "Handheld gestural input device" },
    { 0, NULL }
};
value_string_ext bthci_cmd_cod_minor_device_class_peripheral_type_vals_ext = VALUE_STRING_EXT_INIT(bthci_cmd_cod_minor_device_class_peripheral_type_vals);


static const value_string bthci_cmd_cod_minor_device_class_imaging_type_vals[] = {
    { 0x00,  "Uncategorized, default" },
    { 0, NULL }
};
value_string_ext bthci_cmd_cod_minor_device_class_imaging_type_vals_ext = VALUE_STRING_EXT_INIT(bthci_cmd_cod_minor_device_class_imaging_type_vals);

static const value_string bthci_cmd_cod_minor_device_class_wearable_vals[] = {
    { 0x01,  "Wristwatch" },
    { 0x02,  "Pager" },
    { 0x03,  "Jacket" },
    { 0x04,  "Helmet" },
    { 0x05,  "Glasses" },
    { 0, NULL }
};
value_string_ext bthci_cmd_cod_minor_device_class_wearable_vals_ext = VALUE_STRING_EXT_INIT(bthci_cmd_cod_minor_device_class_wearable_vals);

static const value_string bthci_cmd_cod_minor_device_class_toy_vals[] = {
    { 0x01,  "Robot" },
    { 0x02,  "Vehicle" },
    { 0x03,  "Doll / Action figure" },
    { 0x04,  "Controller" },
    { 0x05,  "Game" },
    { 0, NULL }
};
value_string_ext bthci_cmd_cod_minor_device_class_toy_vals_ext = VALUE_STRING_EXT_INIT(bthci_cmd_cod_minor_device_class_toy_vals);

static const value_string bthci_cmd_cod_minor_device_class_health_vals[] = {
    { 0x00,  "Undefined" },
    { 0x01,  "Blood Pressure Monitor" },
    { 0x02,  "Thermometer" },
    { 0x03,  "Weighing Scale" },
    { 0x04,  "Glucose Meter" },
    { 0x05,  "Pulse Oximeter" },
    { 0x06,  "Heart/Pulse Rate Monitor" },
    { 0x07,  "Health Data Display" },
    { 0x08,  "Step Counter" },
    { 0x09,  "Body Composition Analyzer" },
    { 0x0A,  "Peak Flow Monitor" },
    { 0x0B,  "Medication Monitor" },
    { 0x0C,  "Knee Prosthesis" },
    { 0x0D,  "Ankle Prosthesis" },
    { 0x0E,  "Generic Health Manager" },
    { 0x0F,  "Personal Mobility Device" },
    { 0, NULL }
};
value_string_ext bthci_cmd_cod_minor_device_class_health_vals_ext = VALUE_STRING_EXT_INIT(bthci_cmd_cod_minor_device_class_health_vals);

/* https://www.bluetooth.com/specifications/assigned-numbers/generic-access-profile */
static const value_string bthci_cmd_eir_data_type_vals[] = {
    {0x01, "Flags" },
    {0x02, "16-bit Service Class UUIDs (incomplete)" },
    {0x03, "16-bit Service Class UUIDs" },
    {0x04, "32-bit Service Class UUIDs (incomplete)" },
    {0x05, "32-bit Service Class UUIDs" },
    {0x06, "128-bit Service Class UUIDs (incomplete)" },
    {0x07, "128-bit Service Class UUIDs" },
    {0x08, "Device Name (shortened)" },
    {0x09, "Device Name" },
    {0x0A, "Tx Power Level" },
    {0x0B, "OOB Optional Data Length" },
    {0x0C, "BD_ADDR" },
    {0x0D, "Class Of Device" },
    {0x0E, "Simple Pairing Hash C" },
    {0x0F, "Simple Pairing Randomizer R" },
    {0x10, "Device ID / Security Manager TK Value" },
    {0x11, "Security Manager Out of Band Flags" },
    {0x12, "Slave Connection Interval Range" },
    {0x14, "List of 16-bit Service Solicitation UUIDs" },
    {0x15, "List of 128-bit Service Solicitation UUIDs" },
    {0x16, "Service Data - 16 bit UUID" },
    {0x17, "Public Target Address" },
    {0x18, "Random Target Address" },
    {0x19, "Appearance" },
    {0x1A, "Advertising Interval" },
    {0x1B, "LE Bluetooth Device Address" },
    {0x1C, "LE Role" },
    {0x1D, "Simple Pairing Hash C-256" },
    {0x1E, "Simple Pairing Randomizer R-256" },
    {0x1F, "List of 32-bit Service Solicitation UUIDs" },
    {0x20, "Service Data - 32 bit UUID" },
    {0x21, "Service Data - 128 bit UUID" },
    {0x22, "LE Secure Connections Confirmation Value" },
    {0x23, "LE Secure Connections Random Value" },
    {0x24, "URI" },
    {0x25, "Indoor Positioning" },
    {0x26, "Transport Discovery Data" },
    {0x27, "LE Supported Features" },
    {0x28, "Channel Map Update Indication" },
    {0x29, "PB-ADV" },
    {0x2A, "Mesh Message" },
    {0x2B, "Mesh Beacon" },
    {0x3D, "3D Information Data" },
    {0xFF, "Manufacturer Specific" },
    {   0, NULL }
};
value_string_ext bthci_cmd_eir_data_type_vals_ext = VALUE_STRING_EXT_INIT(bthci_cmd_eir_data_type_vals);

/* Updating based on https://developer.bluetooth.org/gatt/characteristics/Pages/CharacteristicViewer.aspx?u=org.bluetooth.characteristic.gap.appearance.xml  */
static const value_string bthci_cmd_appearance_vals[] = {
    {    0,  "Unknown" },
    {   64,  "Generic Phone" },
    {  128,  "Generic Computer" },
    {  192,  "Generic Watch" },
    {  193,  "Watch: Sports Watch" },
    {  256,  "Generic Clock" },
    {  320,  "Generic Display" },
    {  384,  "Generic Remote Control" },
    {  448,  "Generic Eye-glasses" },
    {  512,  "Generic Tag" },
    {  576,  "Generic Keyring" },
    {  640,  "Generic Media Player" },
    {  704,  "Generic Barcode Scanner" },
    {  768,  "Generic Thermometer" },
    {  769,  "Thermometer: Ear" },
    {  832,  "Generic Heart rate Sensor" },
    {  833,  "Heart Rate Sensor: Heart Rate Belt" },
    {  896,  "Generic Blood Pressure" },
    {  897,  "Blood Pressure: Arm" },
    {  898,  "Blood Pressure: Wrist" },
    {  960,  "Human Interface Device (HID)" },
    {  961,  "Keyboard" },
    {  962,  "Mouse" },
    {  963,  "Joystick" },
    {  964,  "Gamepad" },
    {  965,  "Digitizer Tablet" },
    {  966,  "Card Reader" },
    {  967,  "Digital Pen" },
    {  968,  "Barcode Scanner" },
    { 1024,  "Generic Glucose Meter" },
    { 1088,  "Generic: Running Walking Sensor" },
    { 1089,  "Running Walking Sensor: In-Shoe" },
    { 1090,  "Running Walking Sensor: On-Shoe" },
    { 1091,  "Running Walking Sensor: On-Hip" },
    { 1152,  "Generic: Cycling" },
    { 1153,  "Cycling: Cycling Computer" },
    { 1154,  "Cycling: Speed Sensor" },
    { 1155,  "Cycling: Cadence Sensor" },
    { 1156,  "Cycling: Power Sensor" },
    { 1157,  "Cycling: Speed and Cadence Sensor" },
    { 1216,  "Generic Control Device" },
    { 1217,  "Switch" },
    { 1218,  "Multi-switch" },
    { 1219,  "Button" },
    { 1220,  "Slider" },
    { 1221,  "Rotary" },
    { 1222,  "Touch-panel" },
    { 1280,  "Generic Network Device" },
    { 1281,  "Access Point" },
    { 1344,  "Generic Sensor" },
    { 1345,  "Motion Sensor" },
    { 1346,  "Air Quality Sensor" },
    { 1347,  "Temperature Sensor" },
    { 1348,  "Humidity Sensor" },
    { 1349,  "Leak Sensor" },
    { 1350,  "Smoke Sensor" },
    { 1351,  "Occupancy Sensor" },
    { 1352,  "Contact Sensor" },
    { 1353,  "Carbon Monoxide Sensor" },
    { 1354,  "Carbon Dioxide Sensor" },
    { 1355,  "Ambient Light Sensor" },
    { 1356,  "Energy Sensor" },
    { 1357,  "Color Light Sensor" },
    { 1358,  "Rain Sensor" },
    { 1359,  "Fire Sensor" },
    { 1360,  "Wind Sensor" },
    { 1361,  "Proximity Sensor" },
    { 1362,  "Multi-Sensor" },
    { 1408,  "Generic Light Fixtures" },
    { 1409,  "Wall Light" },
    { 1410,  "Ceiling Light" },
    { 1411,  "Floor Light" },
    { 1412,  "Cabinet Light" },
    { 1413,  "Desk Light" },
    { 1414,  "Troffer Light" },
    { 1415,  "Pendant Light" },
    { 1416,  "In-ground Light" },
    { 1417,  "Flood Light" },
    { 1418,  "Underwater Light" },
    { 1419,  "Bollard with Light" },
    { 1420,  "Pathway Light" },
    { 1421,  "Garden Light" },
    { 1422,  "Pole-top Light" },
    { 1423,  "Spotlight" },
    { 1424,  "Linear Light" },
    { 1425,  "Street Light" },
    { 1426,  "Shelves Light" },
    { 1427,  "High-bay / Low-bay Light" },
    { 1428,  "Emergency Exit Light" },
    { 1472,  "Generic Fan" },
    { 1473,  "Ceiling Fan" },
    { 1474,  "Axial Fan" },
    { 1475,  "Exhaust Fan" },
    { 1476,  "Pedestal Fan" },
    { 1477,  "Desk Fan" },
    { 1478,  "Wall Fan" },
    { 1536,  "Generic HVAC" },
    { 1537,  "Thermostat" },
    { 1600,  "Generic Air Conditioning" },
    { 1664,  "Generic Humidifier" },
    { 1728,  "Generic Heating" },
    { 1729,  "Radiator" },
    { 1730,  "Boiler" },
    { 1731,  "Heat Pump" },
    { 1732,  "Infrared Heater" },
    { 1733,  "Radiant Panel Heater" },
    { 1734,  "Fan Heater" },
    { 1735,  "Air Curtain" },
    { 1792,  "Generic Access Control" },
    { 1793,  "Access Door" },
    { 1794,  "Garage Door" },
    { 1795,  "Emergency Exit Door" },
    { 1796,  "Access Lock" },
    { 1797,  "Elevator" },
    { 1798,  "Window" },
    { 1799,  "Entrance Gate" },
    { 1856,  "Generic Motorized Device" },
    { 1857,  "Motorized Gate" },
    { 1858,  "Awning" },
    { 1859,  "Blinds or Shades" },
    { 1860,  "Curtains" },
    { 1861,  "Screen" },
    { 1920,  "Generic Power Device" },
    { 1921,  "Power Outlet" },
    { 1922,  "Power Strip" },
    { 1923,  "Plug" },
    { 1924,  "Power Supply" },
    { 1925,  "LED Driver" },
    { 1926,  "Fluorescent Lamp Gear" },
    { 1927,  "HID Lamp Gear" },
    { 1984,  "Generic Light Source" },
    { 1985,  "Incandescent Light Bulb" },
    { 1986,  "LED Bulb" },
    { 1987,  "HID Lamp" },
    { 1988,  "Fluorescent Lamp" },
    { 1989,  "LED Array" },
    { 1990,  "Multi-Color LED Array" },
    { 3136,  "Generic: Pulse Oximeter" },
    { 3137,  "Fingertip" },
    { 3138,  "Wrist Worn" },
    { 3200,  "Generic: Weight Scale" },
    { 3264,  "Generic Personal Mobility Device" },
    { 3265,  "Powered Wheelchair" },
    { 3266,  "Mobility Scooter" },
    { 3328,  "Generic Continuous Glucose Monitor" },
    { 5184,  "Generic: Outdoor Sports Activity" },
    { 5185,  "Location Display Device" },
    { 5186,  "Location and Navigation Display Device" },
    { 5187,  "Location Pod" },
    { 5188,  "Location and Navigation Pod" },
    { 0, NULL }
};
value_string_ext bthci_cmd_appearance_vals_ext = VALUE_STRING_EXT_INIT(bthci_cmd_appearance_vals);

const value_string bthci_cmd_io_capability_vals[] = {
    {0x00, "Display Only" },
    {0x01, "Display Yes/No" },
    {0x02, "Keyboard Only" },
    {0x03, "No Input, No Output" },
    {   0, NULL }
};

const value_string bthci_cmd_oob_data_present_vals[] = {
    {0x00, "OOB Authentication Data Not Present" },
    {0x01, "OOB Authentication Data From Remote Device Present" },
    {   0, NULL }
};

static const value_string bthci_cmd_auth_req_vals[] = {
    {0x00, "MITM Protection Not Required - No Bonding. Numeric Comparison, Automatic Accept Allowed, No Secure Connection" },
    {0x01, "MITM Protection Required - No Bonding. Use IO Capabilty To Determine Procedure, No Secure Connection" },
    {0x02, "MITM Protection Not Required - Dedicated Bonding. Numeric Comparison, Automatic Accept Allowed, No Secure Connection" },
    {0x03, "MITM Protection Required - Dedicated Bonding. Use IO Capabilty To Determine Procedure, No Secure Connection" },
    {0x04, "MITM Protection Not Required - General Bonding. Numeric Comparison, Automatic Accept Allowed, No Secure Connection" },
    {0x05, "MITM Protection Required - General Bonding. Use IO Capabilty To Determine Procedure, No Secure Connection" },
    {0x08, "MITM Protection Not Required - No Bonding. Numeric Comparison, Automatic Accept Allowed, Secure Connection" },
    {0x09, "MITM Protection Required - No Bonding. Use IO Capabilty To Determine Procedure, Secure Connection" },
    {0x0A, "MITM Protection Not Required - Dedicated Bonding. Numeric Comparison, Automatic Accept Allowed,  Secure Connection" },
    {0x0B, "MITM Protection Required - Dedicated Bonding. Use IO Capabilty To Determine Procedure, Secure Connection " },
    {0x0C, "MITM Protection Not Required - General Bonding. Numeric Comparison, Automatic Accept Allowed, Secure Connection" },
    {0x0D, "MITM Protection Required - General Bonding. Use IO Capabilty To Determine Procedure, Secure Connection" },
    {   0, NULL }
};
value_string_ext bthci_cmd_auth_req_vals_ext = VALUE_STRING_EXT_INIT(bthci_cmd_auth_req_vals);

const value_string bthci_cmd_address_types_vals[] = {
    { 0x00, "Public Device Address" },
    { 0x01, "Random Device Address" },
    { 0x02, "Public Identity Address (Corresponds to Resolved Private Address)" },
    { 0x03, "Random (Static) Identity Address (Corresponds to Resolved Private Address)" },
    { 0, NULL }
};

const value_string bthci_cmd_identity_address_types_vals[] = {
    { 0x00, "Public Identity Address" },
    { 0x01, "Random (Static) Identity Address" },
    { 0, NULL }
};

static const value_string cmd_role_vals[] = {
    {0x00, "Change own Role to Master for this BD_ADDR"},
    {0x01, "Change own Role to Slave for this BD_ADDR"},
    {0, NULL }
};

static const value_string cmd_acr_role_vals[] = {
    {0x00, "Become the Master for this connection. The LM will perform the role switch."},
    {0x01, "Remain the Slave for this connection. The LM will NOT perform the role switch."},
    {0, NULL }
};

static const value_string cmd_pin_types[] = {
    {0x00, "Variable PIN" },
    {0x01, "Fixed PIN" },
    {0, NULL }
};

static const value_string cmd_encryption_enable[] = {
    {0x00, "Link Level Encryption is OFF"},
    {0x01, "Link Level Encryption is ON"},
    {0, NULL }
};

static const value_string cmd_key_flag[] = {
    {0x00, "Using Semi-permanent Link Key"},
    {0x01, "Using Temporary Link Key"},
    {0, NULL }
};

static const value_string cmd_filter_types[] = {
    {0x00, "Clear all Filters" },
    {0x01, "Inquiry Result" },
    {0x02, "Connection Setup" },
    {0, NULL }
};

static const value_string cmd_inquiry_result_filter_condition_types[] = {
    {0x00, "A new device responded" },
    {0x01, "A device with the specified Class of Device responded" },
    {0x02, "A device with the specified BD_ADDR responded" },
    {0, NULL }
};

static const value_string cmd_flow_directions[] = {
    {0x00, "Outgoing Flow" },
    {0x01, "Incoming Flow" },
    {0, NULL }
};

static const value_string cmd_service_types[] = {
    {0x00, "No Traffic"},
    {0x01, "Best Effort"},
    {0x02, "Guaranteed"},
    {0, NULL }
};

static const value_string cmd_connection_setup_filter_condition_types[] = {
    {0x00, "Allow Connections from all devices" },
    {0x01, "Allow Connections from a device with a specific Class of Device" },
    {0x02, "Allow Connections from a device with a specific BD_ADDR" },
    {0, NULL }
};

static const value_string cmd_auto_acc_flag_values[] = {
    {0x01, "Do NOT Auto accept" },
    {0x02, "Do Auto accept, role switch disabled" },
    {0x03, "Do Auto accept, role switch enabled" },
    {0, NULL }
};

static const value_string cmd_read_all_flag_values[] = {
    {0x00, "Return Link Key for specified BD_ADDR" },
    {0x01, "Return all stored Link Keys" },
    {0, NULL }
};

static const value_string cmd_delete_all_flag_values[] = {
    {0x00, "Delete only Link Key for specified BD_ADDR" },
    {0x01, "Delete all stored Link Keys" },
    {0, NULL }
};

const value_string bthci_cmd_scan_enable_values[] = {
    {0x00, "No Scans enabled" },
    {0x01, "Inquiry Scan enabled/Page Scan disable" },
    {0x02, "Inquiry Scan disabled/Page Scan enabled" },
    {0x03, "Inquiry Scan enabled/Page Scan enabled" },
    {0, NULL }
};

const value_string bthci_cmd_authentication_enable_values[] = {
    {0x00, "Authentication disabled" },
    {0x01, "Authentication enabled for all connection" },
    {0, NULL }
};

static const value_string cmd_input_coding_values[] = {
    {0x0, "Linear" },
    {0x1, UTF8_MICRO_SIGN "-law" },
    {0x2, "A-law" },
    {0, NULL }
};
value_string_ext bthci_cmd_input_coding_vals_ext = VALUE_STRING_EXT_INIT(cmd_input_coding_values);

static const value_string cmd_input_data_format_values[] = {
    {0x0, "1's complement" },
    {0x1, "2's complement" },
    {0x2, "Sign-Magnitude" },
    {0x3, "Unsigned" },
    {0, NULL }
};
value_string_ext bthci_cmd_input_data_format_vals_ext = VALUE_STRING_EXT_INIT(cmd_input_data_format_values);

static const value_string cmd_input_sample_size_values[] = {
    {0x0, "8 bit (only for Linear PCM)" },
    {0x1, "16 bit (only for Linear PCM)" },
    {0, NULL }
};
value_string_ext bthci_cmd_input_sample_size_vals_ext = VALUE_STRING_EXT_INIT(cmd_input_sample_size_values);

static const value_string cmd_air_coding_format_values[] = {
    {0x0, "CVSD" },
    {0x1, UTF8_MICRO_SIGN "-law" },
    {0x2, "A-law" },
    {0x3, "Transparent" },
    {0, NULL }
};
value_string_ext bthci_cmd_air_coding_format_vals_ext = VALUE_STRING_EXT_INIT(cmd_air_coding_format_values);

static const value_string cmd_en_disabled[] = {
    {0x00, "disabled" },
    {0x01, "enabled" },
    {0, NULL }
};

static const value_string cmd_flow_contr_enable[] = {
    {0x00, "Flow control off in direction from Host Controller to Host." },
    {0x01, "ON - HCI ACL Data Packets / OFF - HCI SCO Data Packets" },
    {0x02, "OFF - HCI ACL Data Packets / ON - HCI SCO Data Packets" },
    {0x03, "ON - HCI ACL Data Packets / ON - HCI SCO Data Packets" },
    {0, NULL }
};

static const value_string cmd_power_level_types[] = {
    {0x00, "Current Tx Power Level" },
    {0x01, "Maximum Tx Power Level" },
    {0, NULL }
};

static const value_string cmd_loopback_modes[] = {
    {0x00, "No Loopback mode enabled" },
    {0x01, "Enable Local Loopback" },
    {0x02, "Enable Remote Loopback" },
    {0, NULL }
};

const value_string bthci_cmd_encrypt_mode_vals[] = {
    { 0x00, "Encryption Disabled" },
    { 0x01, "Encryption only for Point-To-Point Packets" },
    { 0x02, "Encryption for Point-To-Point and Broadcast Packets" },
    { 0, NULL }
};

static const value_string cmd_boolean[] = {
    {0, "false" },
    {1, "true" },
    {0, NULL }
};

const value_string bthci_cmd_page_scan_modes[] = {
    {0, "Mandatory Page Scan Mode"},
    {1, "Optional Page Scan Mode I"},
    {2, "Optional Page Scan Mode II"},
    {3, "Optional Page Scan Mode III"},
    {0, NULL }
};

const value_string bthci_cmd_page_scan_repetition_modes[] = {
    {0, "R0"},
    {1, "R1"},
    {2, "R2"},
    {0, NULL }
};

const value_string bthci_cmd_page_scan_period_modes[] = {
    {0, "P0"},
    {1, "P1"},
    {2, "P2"},
    {0, NULL }
};

static const value_string cmd_role_switch_modes[] = {
    {0, "Local device will be master, and will not accept a master-slave switch request." },
    {1, "Local device may be master, or may become slave after accepting a master slave switch." },
    {0, NULL }
};

static const value_string cmd_rtx_effort[] = {
    {0x00, "No Retransmission" },
    {0x01, "At least 1 retransmission, optimize for power consumption" },
    {0x02, "At least 1 retransmission, optimize for link quality" },
    {0xFF, "Don't Care" },
    {   0, NULL }
};

static const value_string cmd_scan_types[] = {
    {0x00, "Standard Scan" },
    {0x01, "Interlaced Scan" },
    {   0, NULL }
};

const value_string bthci_cmd_inq_modes[] = {
    {0x00, "Standard Results" },
    {0x01, "Results With RSSI" },
    {0x02, "Results With RSSI or Extended Results" },
    {   0, NULL }
};

static const value_string cmd_flush_pkt_type[] = {
    {0x00, "Automatically Flushable Only" },
    {   0, NULL }
};

static const value_string cmd_which_clock[] = {
    {0x00, "Local" },
    {0x01, "Piconet" },
    {   0, NULL }
};

const value_string bthci_cmd_notification_types[] = {
    {0x00, "Passkey Entry Started" },
    {0x01, "Passkey Digit Entered" },
    {0x02, "Passkey Digit Erased" },
    {0x03, "Passkey Cleared" },
    {0x04, "Passkey Entry Completed" },
    {   0, NULL }
};

static const value_string bthci_cmd_amp_key_type[] = {
  {0x03, "Debug Combination Key" },
  {0x04, "Authenticated Combination Key" },
  {0x05, "Unauthenticated Combination Key" },
  {   0, NULL }
};

static const value_string cmd_flow_spec_servicetype[] = {
    { 0x00, "No traffic" },
    { 0x01, "Best effort (Default)" },
    { 0x02, "Guaranteed" },
    { 0, NULL }
};

static const value_string  cmd_flow_ctrl_mode[] = {
    { 0x00, "Packet based" },
    { 0x01, "Data Block based" },
    { 0, NULL }
};

static const value_string cmd_le_advertising_types[] = {
    { 0x00, "Connectable Undirected Advertising" },
    { 0x01, "Connectable Directed Advertising" },
    { 0x02, "Scannable Undirected Advertising" },
    { 0x03, "Non-Connectable Undirected Advertising" },
    { 0, NULL }
};

static const value_string cmd_le_advertising_filter_policy[] = {
    { 0x00, "Allow Scan Req from Any, Allow Connect Req from Any" },
    { 0x01, "Allow Scan Req from White List Only, Allow Connect Req from Any" },
    { 0x02, "Allow Scan Req from Any, Allow Connect Req from White List Only" },
    { 0x03, "Allow Scan Req from White List Only, Allow Connect Req from White List Only." },
    { 0, NULL }
};

static const value_string cmd_le_scan_types[] = {
    { 0x00, "Passive" },
    { 0x01, "Active" },
    { 0, NULL }
};

static const value_string cmd_le_scan_filter_policy[] = {
    { 0x00, "Accept all advertisements, except directed advertisements not addressed to this device" },
    { 0x01, "Accept only advertisements from devices in the White List. Ignore directed advertisements not addressed to this device" },
    { 0x02, "Accept all advertisements, except directed advertisements not addressed to this device (but accept those with resolvable addresses that can not be resolved)" },
    { 0x03, "Accept only advertisements from devices in the White List. Ignore directed advertisements not addressed to this device (but accept those with resolvable addresses that can not be resolved)" },
    { 0, NULL }
};

static const value_string cmd_init_filter_policy[] = {
    { 0x00, "Use Peer Address" },
    { 0x01, "Use White List. Ignore Peer Address" },
    { 0, NULL }
};

static const value_string cmd_sync_filter_policy[] = {
    { 0x00, "Use Peer Address" },
    { 0x01, "Use Periodic Advertiser List. Ignore Peer Address" },
    { 0, NULL }
};

static const value_string cmd_privacy_mode[] = {
    { 0x00, "Use Network Privacy Mode" },
    { 0x01, "Use Device Privacy Mode" },
    { 0, NULL }
};

static const value_string cmd_le_test_pkt_payload[] = {
    { 0x00, "Pseudo-Random Sequence 9" },
    { 0x01, "Pattern Of Alternating Bits '11110000'" },
    { 0x02, "Pattern Of Alternating Bits '10101010'" },
    { 0x03, "Pseudo-Random Sequence 15" },
    { 0x04, "Pattern Of All '1' bits" },
    { 0x05, "Pattern Of All '0' bits" },
    { 0x06, "Pattern Of Alternating Bits '00001111'" },
    { 0x07, "Pattern Of Alternating Bits '0101'" },
    { 0, NULL }
};

static const value_string cmd_le_address_resolution_enable[] = {
    { 0x00, "Address Resolution in controller disabled (default)" },
    { 0x01, "Address Resolution in controller enabled" },
    { 0, NULL }
};

static const value_string le_role_vals[] = {
    { 0x00, "Only Peripheral Role Supported" },
    { 0x01, "Only Central Role Supported" },
    { 0x02, "Peripheral and Central Role supported, Peripheral Role preferred for connection establishment" },
    { 0x03, "Peripheral and Central Role supported, Central Role preferred for connection establishment" },
    { 0, NULL }
};

static const value_string tds_role_vals[] = {
    { 0x00, "Not Specified" },
    { 0x01, "Seeker Only" },
    { 0x02, "Provider Only" },
    { 0x03, "Both Seeker and Provider" },
    {0, NULL }
};

static const value_string tds_transport_state_vals[] = {
    { 0x00, "Off" },
    { 0x01, "On" },
    { 0x02, "Temporarily Unavailable" },
    { 0x03, "RFU" },
    {0, NULL }
};

static const value_string cmd_le_adv_data_operation[] = {
    { 0x00, "Intermediate fragment of fragmented data" },
    { 0x01, "First fragment of fragmented data" },
    { 0x02, "Last fragment of fragmented data" },
    { 0x03, "Complete scan response data" },
    { 0x04, "Unchanged Data, DID update only" },
    { 0, NULL }
};

static const value_string cmd_le_adv_data_frag_pref[] = {
    { 0x00, "The Controller may fragment all Host data" },
    { 0x01, "The Controller should not fragment or should minimize fragmentation of Host data" },
    { 0, NULL }
};

static const value_string cmd_le_phy_options_vals[] = {
    { 0x00, "The Host has no preferred coding on the LE Coded PHY" },
    { 0x01, "The Host prefers S=2 coding on the LE Coded PHY" },
    { 0x02, "The Host prefers S=8 coding on the LE Coded PHY" },
    { 0, NULL }
};

static const value_string cmd_le_phy_vals[] = {
    { 0x01, "LE 1M" },
    { 0x02, "LE 2M" },
    { 0x03, "LE Coded" },
    { 0, NULL }
};
value_string_ext bthci_cmd_le_phy_vals_ext = VALUE_STRING_EXT_INIT(cmd_le_phy_vals);

static const value_string cmd_le_modulation_index_vals[] = {
    { 0x00, "Assume transmitter will have a standard modulation index" },
    { 0x01, "Assume transmitter will have a stable modulation index" },
    { 0, NULL }
};

static const value_string cmd_cte_type_vals[] = {
    { 0x00,  "AoA Constant Tone Extension" },
    { 0x01,  "AoD Constant Tone Extension with 1 usec slots" },
    { 0x02,  "AoD Constant Tone Extension with 2 usec slots" },
    { 0xFF,  "No Constant Tone Extension" },
    { 0, NULL }
};
value_string_ext bthci_cmd_cte_type_vals_ext = VALUE_STRING_EXT_INIT(cmd_cte_type_vals);

static const value_string cmd_slot_durations_vals[] = {
    { 0x01, "Switching and sampling slots are 1 usec each" },
    { 0x02, "Switching and sampling slots are 2 usec each" },
    { 0, NULL }
};
value_string_ext bthci_cmd_slot_durations_vals_ext = VALUE_STRING_EXT_INIT(cmd_slot_durations_vals);

static const value_string cmd_sync_mode_vals[] = {
    { 0x00, "No synchronize attempt, no LE Periodic Advertising Sync Transfer Received event sent to Host" },
    { 0x01, "LE Periodic Advertising Sync Transfer Received event sent to Host. LE Periodic Advertising Report events disabled" },
    { 0x02, "LE Periodic Advertising Sync Transfer Received event sent to Host. LE Periodic Advertising Report events enabled" },
    { 0, NULL }
};

static const value_string cmd_key_type_vals[] = {
    { 0x00, "Use the generated private key" },
    { 0x01, "Use the debug private key" },
    { 0, NULL }
};

static const value_string cmd_sca_action_vals[] = {
    { 0x00, "Switch to a more accurate clock" },
    { 0x01, "Switch to a less accurate clock" },
    { 0, NULL }
};

static const value_string cmd_clock_accuray_vals[] = {
    { 0x00, "251-500 ppm" },
    { 0x01, "151-250 ppm" },
    { 0x02, "101-150 ppm" },
    { 0x03, "76-100 ppm" },
    { 0x04, "51-75 ppm" },
    { 0x05, "31-50 ppm" },
    { 0x06, "21-30 ppm" },
    { 0x07, "0-20 ppm" },
    { 0, NULL }
};
value_string_ext bthci_cmd_clock_accuray_vals_ext = VALUE_STRING_EXT_INIT(cmd_clock_accuray_vals);

static const value_string cmd_packing_vals[] = {
    { 0x00, "Sequential" },
    { 0x01, "Interleaved" },
    { 0, NULL }
};

static const value_string cmd_framing_vals[] = {
    { 0x00, "Unframed" },
    { 0x01, "Framed" },
    { 0, NULL }
};
value_string_ext bthci_cmd_framing_vals_ext = VALUE_STRING_EXT_INIT(cmd_framing_vals);

static const value_string cmd_data_path_direction_vals[] = {
    { 0x00, "Input (Host to Controller)" },
    { 0x01, "Output (Controller to Host)" },
    { 0, NULL }
};

static const value_string cmd_payload_type_vals[] = {
    { 0x00, "Zero Length" },
    { 0x01, "Variable Length" },
    { 0x02, "Maximum Length" },
    { 0, NULL }
};

static const value_string cmd_host_enabled_feature_bit_vals[] = {
    { 32, "Isochronous Channels, Host Support" },
    { 0, NULL }
};

static const value_string cmd_phy_and_coding_vals[] = {
    { 0x01, "LE 1M" },
    { 0x02, "LE 2M" },
    { 0x03, "LE Coded, S=8" },
    { 0x04, "LE Coded, S=2" },
    { 0, NULL }
};
value_string_ext bthci_cmd_phy_and_coding_vals_ext = VALUE_STRING_EXT_INIT(cmd_phy_and_coding_vals);

static const value_string disable_enable_vals[] = {
    { 0x00, "Disable" },
    { 0x01, "Enable" },
    {0, NULL }
};

static const value_string lpo_allowed_vals[] = {
    { 0x00, "Controller shall not sleep (+20ppm)" },
    { 0x01, "Controller may sleep (+250ppm)" },
    {0, NULL }
};

static const value_string pcm_data_format_vals[] = {
    { 0x00, "N/A" },
    { 0x01, "1's complement" },
    { 0x02, "2's complement" },
    { 0x03, "Sign-Magnitude" },
    { 0x04, "Unsigned" },
    {0, NULL }
};

static const range_string audio_data_path_rvals[] = {
    { 0x00, 0x00, "HCI" },
    { 0x01, 0xFE, "Vendor Specific" },
    { 0xFF, 0xFF, "Audio Test Mode" },
    { 0, 0, NULL }
};

static const value_string mws_channel_type_vals[] = {
    { 0x00, "TDD" },
    { 0x01, "FDD" },
    {0, NULL }
};

static const value_string external_frame_period_type_vals[] = {
    { 0x00, "Downlink" },
    { 0x01, "Uplink" },
    { 0x02, "Bi-Directional" },
    { 0x03, "Guard Period" },
    {0, NULL }
};

static const value_string mws_pattern_type_vals[] = {
    { 0x00, "Neither Transmission nor Reception is Allowed" },
    { 0x01, "Transmission is Allowed" },
    { 0x02, "Reception is Allowed" },
    { 0x03, "Both Transmission and Reception are Allowed" },
    { 0x04, "Interval Defined by HCI Command" },
    {0, NULL }
};

static const value_string csb_fragment_vals[] = {
    { 0x00, "Continuation" },
    { 0x01, "Start" },
    { 0x02, "End" },
    { 0x03, "No" },
    {0, NULL }
};


void proto_register_bthci_cmd(void);
void proto_reg_handoff_bthci_cmd(void);
void proto_register_btcommon(void);
void proto_reg_handoff_btcommon(void);

static void bthci_cmd_vendor_prompt(packet_info *pinfo _U_, gchar* result)
{
    g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Vendor as");
}

static gint dissect_coding_format(proto_tree *tree, int hf_x, tvbuff_t *tvb, gint offset, gint ett_x)
{
    proto_item *sub_item;
    proto_tree *sub_tree;

    sub_item = proto_tree_add_item(tree, hf_x, tvb, offset, 5, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_x);

    proto_tree_add_item(sub_tree, hf_bthci_cmd_codec_id, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(sub_tree, hf_bthci_cmd_company_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(sub_tree, hf_bthci_cmd_vendor_codec_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
}

static int
dissect_bthci_cmd_cod_mask(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_item  *cod_mask_item;
    proto_item  *cod_mask_tree;

    cod_mask_item = proto_tree_add_item(tree, hf_bthci_cmd_cod_class_of_device_mask, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    cod_mask_tree = proto_item_add_subtree(cod_mask_item, ett_cod_mask);

    proto_tree_add_item(cod_mask_tree, hf_bthci_cmd_cod_minor_device_class_mask, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cod_mask_tree, hf_bthci_cmd_cod_format_type_mask, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    proto_tree_add_item(cod_mask_tree, hf_bthci_cmd_cod_major_service_class_information_mask, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cod_mask_tree, hf_bthci_cmd_cod_major_service_class_telephony_mask, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cod_mask_tree, hf_bthci_cmd_cod_major_service_class_audio_mask, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cod_mask_tree, hf_bthci_cmd_cod_major_service_class_object_transfer_mask, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cod_mask_tree, hf_bthci_cmd_cod_major_service_class_capturing_mask, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cod_mask_tree, hf_bthci_cmd_cod_major_service_class_rendering_mask, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cod_mask_tree, hf_bthci_cmd_cod_major_service_class_networking_mask, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cod_mask_tree, hf_bthci_cmd_cod_major_service_class_positioning_mask, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cod_mask_tree, hf_bthci_cmd_cod_major_service_class_reserved_mask, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cod_mask_tree, hf_bthci_cmd_cod_major_service_class_limited_discoverable_mode_mask, tvb, offset, 2, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(cod_mask_tree, hf_bthci_cmd_cod_major_device_class_mask, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
}

static int
dissect_bthci_cmd_flow_spec(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, gboolean tx)
{
    proto_item *ti_flow_spec;
    proto_tree *ti_flow_spec_subtree;

    ti_flow_spec = proto_tree_add_none_format(tree, hf_bthci_cmd_flow_spec, tvb, offset, 16, tx?"Tx Flow Spec ":"Rx Flow Spec");
    ti_flow_spec_subtree = proto_item_add_subtree(ti_flow_spec, ett_flow_spec_subtree);

    proto_tree_add_item(ti_flow_spec_subtree, hf_bthci_cmd_flow_spec_identifier, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;
    proto_tree_add_item(ti_flow_spec_subtree, hf_bthci_cmd_flow_spec_service_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;
    proto_tree_add_item(ti_flow_spec_subtree, hf_bthci_cmd_flow_spec_sdu_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset+=2;
    proto_tree_add_item(ti_flow_spec_subtree, hf_bthci_cmd_flow_spec_sdu_arrival_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset+=4;
    proto_tree_add_item(ti_flow_spec_subtree, hf_bthci_cmd_flow_spec_access_latency, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset+=4;
    proto_tree_add_item(ti_flow_spec_subtree, hf_bthci_cmd_flush_to_us, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset+=4;

    return offset;
}

static int
dissect_antenna_switching_pattern(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    guint8 length_antenna_pattern;

    proto_tree_add_item(tree, hf_bthci_cmd_antenna_switching_pattern_length, tvb, offset, 1, ENC_NA);
    length_antenna_pattern = tvb_get_guint8(tvb, offset);
    offset += 1;

    if (length_antenna_pattern > 0) {
        proto_item *sub_item;
        proto_tree *sub_tree;

        sub_item = proto_tree_add_item(tree, hf_bthci_cmd_antenna_switching_pattern, tvb, offset, length_antenna_pattern, ENC_NA);
        sub_tree = proto_item_add_subtree(sub_item, ett_pattern);
        proto_item_append_text(sub_item, ": ");

        while (length_antenna_pattern > 0) {
            proto_tree_add_item(sub_tree, hf_bthci_cmd_antenna_id, tvb, offset, 1, ENC_NA);
            proto_item_append_text(sub_item, "%d ", tvb_get_guint8(tvb, offset));
            offset++;
            length_antenna_pattern--;
        }
    }
    return offset;
}

static int
dissect_link_control_cmd(tvbuff_t *tvb, int offset, packet_info *pinfo,
        proto_tree *tree, guint16 cmd_ocf, bluetooth_data_t *bluetooth_data)
{
    proto_item *item;
    guint32     clock_value;

    switch (cmd_ocf) {
        case 0x0001: /* Inquiry */
            proto_tree_add_item(tree, hf_bthci_cmd_lap, tvb, offset, 3, ENC_LITTLE_ENDIAN);
            offset+=3;
            item = proto_tree_add_item(tree, hf_bthci_cmd_inq_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g sec)", 1.28*tvb_get_guint8(tvb, offset));
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_num_responses, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x0003: /* Periodic Inquiry Mode */
            item = proto_tree_add_item(tree, hf_bthci_cmd_max_period_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g sec)", 1.28*tvb_get_letohs(tvb, offset));
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_min_period_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g sec)", 1.28*tvb_get_letohs(tvb, offset));
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_lap, tvb, offset, 3, ENC_LITTLE_ENDIAN);
            offset+=3;
            item = proto_tree_add_item(tree, hf_bthci_cmd_inq_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g sec)", 1.28*tvb_get_guint8(tvb, offset));
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_num_responses, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x0005: /* Create Connection */
            {
            guint8  bd_addr[6];

            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, bd_addr);

            proto_tree_add_bitmask(tree, tvb, offset, hf_bthci_cmd_packet_type, ett_packet_type, hfx_bthci_cmd_packet_type, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_bthci_cmd_page_scan_repetition_mode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;

            proto_tree_add_item(tree, hf_bthci_cmd_page_scan_mode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;

            item = proto_tree_add_item(tree, hf_bthci_cmd_clock_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            clock_value = tvb_get_letohs(tvb, 13) & 32767; /* only bit0-14 are valid  */
            proto_item_append_text(item, " (%g msec)", 1.25*clock_value);
            proto_tree_add_item(tree, hf_bthci_cmd_clock_offset_valid , tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;

            proto_tree_add_item(tree, hf_bthci_cmd_allow_role_switch, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;

            if (!pinfo->fd->visited) {
                guint32           interface_id;
                guint32           adapter_id;
                guint32           bd_addr_oui;
                guint32           bd_addr_id;
                guint32           frame_number;
                wmem_tree_key_t   key[6];
                device_role_t    *device_role;

                interface_id = bluetooth_data->interface_id;
                adapter_id   = bluetooth_data->adapter_id;
                frame_number = pinfo->num;
                bd_addr_oui  = bd_addr[0] << 16 | bd_addr[1] << 8 | bd_addr[2];
                bd_addr_id   = bd_addr[3] << 16 | bd_addr[4] << 8 | bd_addr[5];

                key[0].length = 1;
                key[0].key    = &interface_id;
                key[1].length = 1;
                key[1].key    = &adapter_id;
                key[2].length = 1;
                key[2].key    = &bd_addr_id;
                key[3].length = 1;
                key[3].key    = &bd_addr_oui;
                key[4].length = 1;
                key[4].key    = &frame_number;
                key[5].length = 0;
                key[5].key    = NULL;

                device_role = (device_role_t *) wmem_new(wmem_file_scope(), device_role_t);
                device_role->change_in_frame = frame_number;
                device_role->role = ROLE_SLAVE;

                wmem_tree_insert32_array(bluetooth_data->bdaddr_to_role, key, device_role);
            }
            }
            break;

        case 0x0006: /* Disconnect */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_reason, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x0007: /* Add SCO Connection */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_packet_type_hv1, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_packet_type_hv2, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_packet_type_hv3, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            break;

        case 0x0008: /* Create Connection Cancel Request */
            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);
            break;

        case 0x0009: /* Accept Connection Request */ {
            guint8  bd_addr[6];

            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, bd_addr);

            proto_tree_add_item(tree, hf_bthci_cmd_acr_role, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            if (!pinfo->fd->visited) {
                guint32           interface_id;
                guint32           adapter_id;
                guint32           bd_addr_oui;
                guint32           bd_addr_id;
                guint32           frame_number;
                wmem_tree_key_t   key[6];
                device_role_t    *device_role;

                interface_id = bluetooth_data->interface_id;
                adapter_id   = bluetooth_data->adapter_id;
                frame_number = pinfo->num;
                bd_addr_oui  = bd_addr[0] << 16 | bd_addr[1] << 8 | bd_addr[2];
                bd_addr_id   = bd_addr[3] << 16 | bd_addr[4] << 8 | bd_addr[5];

                key[0].length = 1;
                key[0].key    = &interface_id;
                key[1].length = 1;
                key[1].key    = &adapter_id;
                key[2].length = 1;
                key[2].key    = &bd_addr_id;
                key[3].length = 1;
                key[3].key    = &bd_addr_oui;
                key[4].length = 1;
                key[4].key    = &frame_number;
                key[5].length = 0;
                key[5].key    = NULL;

                device_role = (device_role_t *) wmem_new(wmem_file_scope(), device_role_t);
                device_role->change_in_frame = frame_number;
                device_role->role = ROLE_MASTER;

                wmem_tree_insert32_array(bluetooth_data->bdaddr_to_role, key, device_role);
            }
            }
            break;

        case 0x000a: /* Reject Connection Request */
            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);

            proto_tree_add_item(tree, hf_bthci_cmd_reason, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x000b: /* Link Key Request Reply */
            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);

            proto_tree_add_item(tree, hf_bthci_cmd_link_key, tvb, offset, 16, ENC_NA);
            offset+=16;
            break;

        case 0x000c: /* Link Key Request Negative Reply */
            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);
            break;

        case 0x000d: /* PIN Code Request Reply */
            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);

            proto_tree_add_item(tree, hf_bthci_cmd_pin_code_length ,tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_pin_code ,tvb, offset, 16, ENC_ASCII|ENC_NA);
            offset+=16;
            break;

        case 0x000e: /* PIN Code Request Negative Reply */
            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);
            break;

        case 0x000f: /* Change Connection Packet Type */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;

            proto_tree_add_bitmask(tree, tvb, offset, hf_bthci_cmd_packet_type, ett_packet_type, hfx_bthci_cmd_packet_type, ENC_LITTLE_ENDIAN);
            offset += 2;

            break;

        case 0x0011: /* Authentication Request */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            break;

        case 0x0013: /* Set Connection Encryption */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_encryption_enable, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x0017: /* Master Link Key */
            proto_tree_add_item(tree, hf_bthci_cmd_key_flag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x0019: /* Remote Name Request */
            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);

            proto_tree_add_item(tree, hf_bthci_cmd_page_scan_repetition_mode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;

            proto_tree_add_item(tree, hf_bthci_cmd_page_scan_mode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;

            item = proto_tree_add_item(tree, hf_bthci_cmd_clock_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            clock_value = tvb_get_letohs(tvb, offset) & 32767; /* only bit0-14 are valid  */
            proto_item_append_text(item, " (%g msec)", 1.25*clock_value);
            proto_tree_add_item(tree, hf_bthci_cmd_clock_offset_valid , tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            break;

        case 0x001a: /* Remote Name Request Cancel */
            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);
            break;

        case 0x001c: /* Read Remote Extended Features */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_page_number, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x0028: /* Setup Synchronous Connection */
        case 0x0029: /* Accept Synchronous Connection Request */
            if (cmd_ocf == 0x0028) {
                proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset+=2;
            } else {
                offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);
            }

            proto_tree_add_item(tree, hf_bthci_cmd_transmit_bandwidth, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;

            proto_tree_add_item(tree, hf_bthci_cmd_receive_bandwidth, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;

            proto_tree_add_item(tree, hf_bthci_cmd_max_latency_ms, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;

            proto_tree_add_item(tree, hf_bthci_cmd_input_unused, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_input_coding, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_input_data_format, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_input_sample_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_linear_pcm_bit_pos, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_air_coding_format, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;

            proto_tree_add_item(tree, hf_bthci_cmd_retransmission_effort, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;

            proto_tree_add_bitmask(tree, tvb, offset, hf_bthci_cmd_sco_packet_type, ett_sco_packet_type, hfx_bthci_cmd_sco_packet_type, ENC_LITTLE_ENDIAN);
            offset += 2;

            break;
        case 0x002a: /* Reject Synchronous Connection Request */
            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);

            proto_tree_add_item(tree, hf_bthci_cmd_reason, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x0015: /* Change Connection Link Key */
        case 0x001b: /* Read Remote Supported Features */
        case 0x001d: /* Read Remote Version Information */
        case 0x001f: /* Read Clock Offset*/
        case 0x0020: /* Read LMP Handle */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            break;

        case 0x002b: /* IO Capability Response */
            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);

            proto_tree_add_item(tree, hf_bthci_cmd_io_capability, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_oob_data_present, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_auth_requirements, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x0034: /* IO Capability Request Negative Reply */
            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);
            proto_tree_add_item(tree, hf_bthci_cmd_reason, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x002c: /* User Confirmation Request Reply */
        case 0x002d: /* User Confirmation Request Negative Reply */
        case 0x002f: /* User Passkey Request Negative Reply */
        case 0x0033: /* Remote OOB Data Request Negative Reply */
            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);
            break;

        case 0x002e: /* User Passkey Request Reply */
            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);

            proto_tree_add_item(tree, hf_bthci_cmd_passkey, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
            break;

        case 0x0030: /* Remote OOB Data Request Reply */
            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);

            proto_tree_add_item(tree, hf_bthci_cmd_hash_c, tvb, offset, 16, ENC_NA);
            offset+=16;
            proto_tree_add_item(tree, hf_bthci_cmd_randomizer_r, tvb, offset, 16, ENC_NA);
            offset+=16;
            break;

        case 0x0035: /* Create Physical Link */
        case 0x0036: /* Accept Physical Link */
            proto_tree_add_item(tree, hf_bthci_cmd_physical_link_handle, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_dedicated_amp_key_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_dedicated_amp_key_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_dedicated_amp_key, tvb, offset, -1, ENC_NA);
            offset+=tvb_reported_length_remaining(tvb, offset);
            break;

        case 0x0037: /* Disconnect Physical Link */
            proto_tree_add_item(tree, hf_bthci_cmd_physical_link_handle, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_reason, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x0038: /* Create Logical Link */
        case 0x0039: /* Accept Logical Link */
            proto_tree_add_item(tree, hf_bthci_cmd_physical_link_handle, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            offset = dissect_bthci_cmd_flow_spec(tvb, offset, pinfo, tree, TRUE);
            offset = dissect_bthci_cmd_flow_spec(tvb, offset, pinfo, tree, FALSE);
            break;

        case 0x003a: /* Disconnect Logical Link */
            proto_tree_add_item(tree, hf_bthci_cmd_logical_link_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            break;

        case 0x003b: /* Logical Link Cancel */
            proto_tree_add_item(tree, hf_bthci_cmd_physical_link_handle, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_flow_spec_identifier, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x003c: /* Flow Spec Modify */
            proto_tree_add_item(tree, hf_bthci_cmd_logical_link_handle, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            offset = dissect_bthci_cmd_flow_spec(tvb, offset, pinfo, tree, TRUE);
            offset = dissect_bthci_cmd_flow_spec(tvb, offset, pinfo, tree, FALSE);
            break;

        case 0x003D: /* Enhanced Setup Synchronous Connection */
        case 0x003E: /* Enhanced Accept Synchronous Connection Request */
            if (cmd_ocf == 0x003D) {
                proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
            } else {
                offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);
            }

            proto_tree_add_item(tree, hf_bthci_cmd_transmit_bandwidth, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(tree, hf_bthci_cmd_receive_bandwidth, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            offset = dissect_coding_format(tree, hf_bthci_cmd_transmit_coding_format, tvb, offset, ett_coding_format);

            offset = dissect_coding_format(tree, hf_bthci_cmd_receive_coding_format, tvb, offset, ett_coding_format);

            proto_tree_add_item(tree, hf_bthci_cmd_transmit_codec_frame_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_bthci_cmd_receive_codec_frame_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_bthci_cmd_input_bandwidth, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(tree, hf_bthci_cmd_output_bandwidth, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            offset = dissect_coding_format(tree, hf_bthci_cmd_input_coding_format, tvb, offset, ett_coding_format);

            offset = dissect_coding_format(tree, hf_bthci_cmd_output_coding_format, tvb, offset, ett_coding_format);

            proto_tree_add_item(tree, hf_bthci_cmd_input_coded_data_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_bthci_cmd_output_coded_data_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_bthci_cmd_input_pcm_data_format, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(tree, hf_bthci_cmd_output_pcm_data_format, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(tree, hf_bthci_cmd_input_pcm_sample_payload_msb_position, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(tree, hf_bthci_cmd_output_pcm_sample_payload_msb_position, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(tree, hf_bthci_cmd_input_data_path, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(tree, hf_bthci_cmd_output_data_path, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(tree, hf_bthci_cmd_input_transport_unit_size, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(tree, hf_bthci_cmd_output_transport_unit_size, tvb, offset, 1, ENC_NA);
            offset += 1;

/* TODO: Improve this range field output: 0x0000-0x0003 reserved, 0x0004-0xFFFE value in ms,  0xFFFF - "Do not care"*/
            proto_tree_add_item(tree, hf_bthci_cmd_max_latency_ms, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_bitmask(tree, tvb, offset, hf_bthci_cmd_sco_packet_type, ett_sco_packet_type, hfx_bthci_cmd_sco_packet_type, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_bthci_cmd_retransmission_effort, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 0x003F: /* Truncated Page */
            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);

            proto_tree_add_item(tree, hf_bthci_cmd_page_scan_repetition_mode, tvb, offset, 1, ENC_NA);
            offset += 1;

            item = proto_tree_add_item(tree, hf_bthci_cmd_clock_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            clock_value = tvb_get_letohs(tvb, 13) & 32767; /* only bit0-14 are valid  */
            proto_item_append_text(item, " (%g msec)", 1.25 * clock_value);

            proto_tree_add_item(tree, hf_bthci_cmd_clock_offset_valid , tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            break;
        case 0x0040: /* Truncated Page Cancel */
            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);

            break;

        case 0x0002: /* Inquiry Cancel */
        case 0x0004: /* Exit Periodic Inquiry Mode */
        case 0x0043: /* Start Synchronization Train */
            /* NOTE: No parameters */
            break;

        case 0x0041: /* Set Connectionless Slave Broadcast */
            proto_tree_add_item(tree, hf_bthci_cmd_connectionless_slave_broadcast, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(tree, hf_bthci_cmd_lt_addr, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(tree, hf_bthci_cmd_lpo_allowed, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_bitmask(tree, tvb, offset, hf_bthci_cmd_packet_type, ett_packet_type, hfx_bthci_cmd_packet_type, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_bthci_cmd_interval_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_bthci_cmd_interval_max, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_bthci_cmd_csb_supervision_to, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            break;
        case 0x0042: /* Set Connectionless Slave Broadcast Receive */
            proto_tree_add_item(tree, hf_bthci_cmd_connectionless_slave_broadcast_receive, tvb, offset, 1, ENC_NA);
            offset += 1;

            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);

            proto_tree_add_item(tree, hf_bthci_cmd_lt_addr, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(tree, hf_bthci_cmd_interval, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_bthci_cmd_clock_offset_32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(tree, hf_bthci_cmd_next_csb_clock, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(tree, hf_bthci_cmd_csb_supervision_to, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_bthci_cmd_remote_timing_accuracy, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(tree, hf_bthci_cmd_csb_skip, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_bitmask(tree, tvb, offset, hf_bthci_cmd_packet_type, ett_packet_type, hfx_bthci_cmd_packet_type, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_bthci_cmd_afh_channel_map, tvb, offset, 10, ENC_NA);
            offset += 10;

            break;
        case 0x0044: /* Receive Synchronization Train */
            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);

            proto_tree_add_item(tree, hf_bthci_cmd_synchronization_scan_to, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_bthci_cmd_window, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_bthci_cmd_interval, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            break;
        case 0x0045: /* Remote OOB Extended Data Request Reply */
            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);

            proto_tree_add_item(tree, hf_bthci_cmd_c192, tvb, offset, 16, ENC_NA);
            offset += 16;

            proto_tree_add_item(tree, hf_bthci_cmd_r192, tvb, offset, 16, ENC_NA);
            offset += 16;

            proto_tree_add_item(tree, hf_bthci_cmd_c256, tvb, offset, 16, ENC_NA);
            offset += 16;

            proto_tree_add_item(tree, hf_bthci_cmd_r256, tvb, offset, 16, ENC_NA);
            offset += 16;

            break;
        default:
            proto_tree_add_expert(tree, pinfo, &ei_command_unknown_command, tvb, offset, -1);
            offset += tvb_reported_length_remaining(tvb, offset);
    }

    return offset;
}

static int
dissect_link_policy_cmd(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint16 cmd_ocf, bluetooth_data_t *bluetooth_data)
{
    proto_item *item;
    guint16     timeout;

    switch (cmd_ocf) {
        case 0x0001: /* Hold Mode */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_max_interval_hold, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            timeout = tvb_get_letohs(tvb, offset);
            proto_item_append_text(item, " slots (%g msec)", timeout*0.625);
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_min_interval_hold, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            timeout = tvb_get_letohs(tvb, offset);
            proto_item_append_text(item, " slots (%g msec)", timeout*0.625);
            offset+=2;
            break;

        case 0x0003: /* sniff mode */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_max_interval_sniff, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " slots (%g msec)",  tvb_get_letohs(tvb, offset)*0.625);
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_min_interval_sniff, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " slots (%g msec)",  tvb_get_letohs(tvb, offset)*0.625);
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_sniff_attempt, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            timeout = tvb_get_letohs(tvb, offset);
            if (timeout>0) {
                proto_item_append_text(item, " (%g msec)", (2*timeout-1)*0.625);
            } else {
                proto_item_append_text(item, " (0 msec)");
            }
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_timeout, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " slots (%g msec)",  tvb_get_letohs(tvb, offset)*1.25);
            offset+=2;
            break;

        case 0x0005: /* Park Mode */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_max_interval_beacon, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            timeout = tvb_get_letohs(tvb, offset);
            proto_item_append_text(item, " slots (%g msec)", timeout*0.625);
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_min_interval_beacon, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            timeout = tvb_get_letohs(tvb, offset);
            proto_item_append_text(item, " slots (%g msec)", timeout*0.625);
            offset+=2;
            break;

        case 0x0007: /* QoS Setup */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_flags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_service_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_token_rate, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
            proto_tree_add_item(tree, hf_bthci_cmd_peak_bandwidth, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
            proto_tree_add_item(tree, hf_bthci_cmd_latency, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
            proto_tree_add_item(tree, hf_bthci_cmd_delay_variation, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
            break;

        case 0x000b: /* Switch Role */
            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);

            proto_tree_add_item(tree, hf_bthci_cmd_role, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x0004: /* Exit Sniff Mode */
        case 0x0006: /* Exit Park Mode */
        case 0x0009: /* Role Discovery */
        case 0x000c: /* Read Link Policy Settings */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            break;

        case 0x000d: /* Write Link Policy Settings */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            /* FALL THROUGH */
        case 0x000f: /* Write Default Link Policy Settings */
            proto_tree_add_item(tree, hf_bthci_cmd_link_policy_setting_switch, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_link_policy_setting_hold  , tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_link_policy_setting_sniff , tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_link_policy_setting_park  , tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            break;

        case 0x0010: /* Flow Specification */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_flags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_flow_direction, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_service_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_token_rate, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
            proto_tree_add_item(tree, hf_bthci_cmd_token_bucket_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
            proto_tree_add_item(tree, hf_bthci_cmd_peak_bandwidth, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
            proto_tree_add_item(tree, hf_bthci_cmd_latency, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
            break;

        case 0x0011: /* Sniff Subrating */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;

            item = proto_tree_add_item(tree, hf_bthci_cmd_max_latency, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " slots (%g msec)",  tvb_get_letohs(tvb, offset)*0.625);
            offset+=2;

            item = proto_tree_add_item(tree, hf_bthci_cmd_min_remote_timeout, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " slots (%g msec)",  tvb_get_letohs(tvb, offset)*0.625);
            offset+=2;

            item = proto_tree_add_item(tree, hf_bthci_cmd_min_local_timeout, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " slots (%g msec)",  tvb_get_letohs(tvb, offset)*0.625);
            offset+=2;
            break;

        case 0x00e: /* Read Default Link Policy Setting */
            /* NOTE: No parameters */
            break;

        default:
            proto_tree_add_expert(tree, pinfo, &ei_command_unknown_command, tvb, offset, -1);
            offset += tvb_reported_length_remaining(tvb, offset);
    }

    return offset;
}

static int
dissect_host_controller_baseband_cmd(tvbuff_t *tvb, int offset, packet_info *pinfo,
        proto_tree *tree, guint16 cmd_ocf, bluetooth_data_t *bluetooth_data,
        bthci_cmd_data_t  *bthci_cmd_data)
{
    proto_item *item;
    guint16     timeout;
    guint8      filter_type, filter_condition_type, num8;
    int         i;

    switch (cmd_ocf) {
        case 0x0001: /* Set Event Mask */
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_00, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_01, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_02, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_03, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_04, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_05, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_06, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_07, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;

            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_10, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_11, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_12, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_13, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_14, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_17, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;

            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_20, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_21, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_23, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_24, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_25, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_26, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_27, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;

            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_30, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_31, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_32, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_33, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_34, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_35, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_36, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_37, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;

            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_40, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_41, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_42, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;

            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_53, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_54, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_55, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_56, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_57, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;

            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_60, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_61, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_62, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_63, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_64, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_65, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_67, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;

            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_70, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_72, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_73, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x0005: /* Set Event Filter */
            proto_tree_add_item(tree, hf_bthci_cmd_filter_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            filter_type = tvb_get_guint8(tvb, 3);
            offset++;
            switch (filter_type) {

                case 0x01: /* Inquiry Result Filter */
                    proto_tree_add_item(tree, hf_bthci_cmd_inquiry_result_filter_condition_type,
                            tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    filter_condition_type = tvb_get_guint8(tvb, offset);
                    offset++;
                    switch (filter_condition_type) {
                        case 0x01:
                            call_dissector(btcommon_cod_handle, tvb_new_subset_length(tvb, offset, 3), pinfo, tree);
                            offset += 3;

                            offset=dissect_bthci_cmd_cod_mask(tvb, offset, pinfo, tree);
                            break;

                        case 0x02:
                            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);
                            break;

                        default:
                            break;

                    }
                    break;

                case 0x02: /* Connection Setup Filter */
                    proto_tree_add_item(tree, hf_bthci_cmd_connection_setup_filter_condition_type,
                            tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    filter_condition_type = tvb_get_guint8(tvb, offset);
                    offset++;
                    switch (filter_condition_type) {
                        case 0x00:
                            proto_tree_add_item(tree, hf_bthci_cmd_auto_acc_flag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                            offset++;
                            break;

                        case 0x01:
                            call_dissector(btcommon_cod_handle, tvb_new_subset_length(tvb, offset, 3), pinfo, tree);
                            offset += 3;

                            offset=dissect_bthci_cmd_cod_mask(tvb, offset, pinfo, tree);

                            proto_tree_add_item(tree, hf_bthci_cmd_auto_acc_flag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                            offset++;
                            break;

                        case 0x02:
                            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);

                            proto_tree_add_item(tree, hf_bthci_cmd_auto_acc_flag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                            offset++;
                            break;

                        default:
                            break;

                    }
                    break;

                default:
                    break;

            }

            break;
        case 0x000a: /* Write PIN Type */
            proto_tree_add_item(tree, hf_bthci_cmd_pin_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x000d: /* Read Stored Link Key */
            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);

            proto_tree_add_item(tree, hf_bthci_cmd_read_all_flag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x0011: /* Write Stored Link Key */
            proto_tree_add_item(tree, hf_bthci_cmd_num_link_keys, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            num8 = tvb_get_guint8(tvb, offset);
            offset += 1;

            for (i = 0; i < num8; i++) {
                offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);
                proto_tree_add_item(tree, hf_bthci_cmd_link_key, tvb, offset, 16, ENC_NA);
                offset += 16;
            }
            break;

        case 0x0012: /* Delete Stored Link Key */
            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);

            proto_tree_add_item(tree, hf_bthci_cmd_delete_all_flag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x0013: /* Change Local Name */
            proto_tree_add_item(tree, hf_bthci_cmd_device_name, tvb, offset, 248, ENC_UTF_8 | ENC_NA);
            if (!pinfo->fd->visited && bthci_cmd_data) {
                bthci_cmd_data->data.name = tvb_get_string_enc(wmem_file_scope(), tvb, offset, 248, ENC_UTF_8);
            }
            offset += 248;
            break;

        case 0x0016: /* Write Connection Accept Timeout */
            item = proto_tree_add_item(tree, hf_bthci_cmd_timeout, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            timeout = tvb_get_letohs(tvb, offset);
            proto_item_append_text(item, " slots (%g msec)", timeout*0.625);
            offset+=2;
            break;

        case 0x0018: /* Write Page Timeout */
            item = proto_tree_add_item(tree, hf_bthci_cmd_timeout, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            timeout = tvb_get_letohs(tvb, offset);
            if (timeout > 0) {
                proto_item_append_text(item, " slots (%g msec)", timeout*0.625);
            } else {
                proto_item_append_text(item, " Illegal Page Timeout");
            }
            if (!pinfo->fd->visited && bthci_cmd_data) {
                bthci_cmd_data->data.page_timeout = timeout;
            }
            offset+=2;
            break;

        case 0x001a: /* Write Scan Enable */
            proto_tree_add_item(tree, hf_bthci_cmd_scan_enable,
                    tvb, offset, 1, ENC_LITTLE_ENDIAN);
            if (!pinfo->fd->visited && bthci_cmd_data) {
                bthci_cmd_data->data.scan = tvb_get_guint8(tvb, offset);
            }
            offset++;
            break;

        case 0x0020: /* Write Authentication Enable */
            proto_tree_add_item(tree, hf_bthci_cmd_authentication_enable,
                    tvb, offset, 1, ENC_LITTLE_ENDIAN);
            if (!pinfo->fd->visited && bthci_cmd_data) {
                bthci_cmd_data->data.authentication = tvb_get_guint8(tvb, offset);
            }
            offset++;
            break;

        case 0x0022: /* Write Encryption Mode */
            proto_tree_add_item(tree, hf_bthci_cmd_encrypt_mode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            if (!pinfo->fd->visited && bthci_cmd_data) {
                bthci_cmd_data->data.encryption = tvb_get_guint8(tvb, offset);
            }
            offset++;
            break;

        case 0x0024: /* Write Class of Device */
            call_dissector(btcommon_cod_handle, tvb_new_subset_length(tvb, offset, 3), pinfo, tree);
            if (!pinfo->fd->visited && bthci_cmd_data) {
                bthci_cmd_data->data.class_of_device = tvb_get_guint24(tvb, offset, ENC_LITTLE_ENDIAN);
            }
            offset += 3;
            break;

        case 0x0026: /* Write Voice Setting */
            proto_tree_add_item(tree, hf_bthci_cmd_input_unused,
                    tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_input_coding,
                    tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_input_data_format,
                    tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_input_sample_size,
                    tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_linear_pcm_bit_pos,
                    tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_air_coding_format,
                    tvb, offset, 2, ENC_LITTLE_ENDIAN);
            if (!pinfo->fd->visited && bthci_cmd_data) {
                bthci_cmd_data->data.voice_setting = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
            }
            offset+=2;
            break;

        case 0x0028: /* Write Automatic Flush Timeout */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_timeout, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            timeout = tvb_get_letohs(tvb, offset);
            if (timeout>0) {
                proto_item_append_text(item, " slots (%g msec)", timeout*0.625);
            } else {
                proto_item_append_text(item, " (= No Automatic Flush )");
            }
            offset+=2;
            break;

        case 0x002a: /* Write Num of Broadcast Retransmissions */
            proto_tree_add_item(tree, hf_bthci_cmd_num_broadcast_retransmissions,
                    tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x002c: /* Write Hold Mode Activity */
            proto_tree_add_item(tree, hf_bthci_cmd_hold_mode_act_page,
                    tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_hold_mode_act_inquiry,
                    tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_hold_mode_act_periodic,
                    tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x002d: /* Read Transmit Power Level */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle,
                    tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_tx_power_level_type,
                    tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x002f: /* Write SCO Flow Control Enable */
            proto_tree_add_item(tree, hf_bthci_cmd_sco_flow_control,
                    tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x0031: /* Set Host Controller To Host Flow Control */
            proto_tree_add_item(tree, hf_bthci_cmd_flow_contr_enable,
                    tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x0033: /* Host Buffer Size */
            proto_tree_add_item(tree, hf_bthci_cmd_host_data_packet_length_acl,
                    tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_host_data_packet_length_sco,
                    tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_host_total_num_acl_data_packets,
                    tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_host_total_num_sco_data_packets,
                    tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;

            if (!pinfo->fd->visited && bthci_cmd_data) {
                bthci_cmd_data->data.mtus.acl_mtu     = tvb_get_guint16(tvb, offset - 7, ENC_LITTLE_ENDIAN);
                bthci_cmd_data->data.mtus.sco_mtu     = tvb_get_guint8(tvb,  offset - 5);
                bthci_cmd_data->data.mtus.acl_packets = tvb_get_guint16(tvb, offset - 4, ENC_LITTLE_ENDIAN);
                bthci_cmd_data->data.mtus.sco_packets = tvb_get_guint16(tvb, offset - 2, ENC_LITTLE_ENDIAN);
            }
            break;

        case 0x0035: /* Host Number Of Completed Packets */
            proto_tree_add_item(tree, hf_bthci_cmd_num_handles,
                    tvb, offset, 1, ENC_LITTLE_ENDIAN);
            num8 = tvb_get_guint8(tvb, offset);
            offset++;

            for (i=0; i<num8; i++) {
                proto_tree_add_item(tree, hf_bthci_cmd_connection_handle,
                        tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(tree, hf_bthci_cmd_num_compl_packets,
                        tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
            }
            break;

        case 0x0037: /* Write Link Supervision Timeout */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle,
                    tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_timeout,
                    tvb, offset, 2, ENC_LITTLE_ENDIAN);
            timeout = tvb_get_letohs(tvb, offset);
            if (timeout>0) {
                proto_item_append_text(item, " slots (%g msec)", timeout*0.625);
            } else {
                proto_item_append_text(item, " (= No Link Supervision Timeout)");
            }
            offset+=2;
            break;

        case 0x003a: /* Write Current IAC LAP */
            proto_tree_add_item(tree, hf_bthci_cmd_num_curr_iac, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            num8 = tvb_get_guint8(tvb, offset);
            offset++;
            for (i=0; i<num8; i++) {
                proto_tree_add_item(tree, hf_bthci_cmd_iac_lap, tvb, offset+(i*3), 3, ENC_LITTLE_ENDIAN);
            }
            offset += num8 * 3;
            break;

        case 0x003c: /* Write Page Scan Period Mode */
            proto_tree_add_item(tree, hf_bthci_cmd_page_scan_period_mode,
                    tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x003e: /* Write Page Scan Mode */
            proto_tree_add_item(tree, hf_bthci_cmd_page_scan_mode,
                    tvb, 3, 1, ENC_LITTLE_ENDIAN);
            break;

        case 0x003f: /* Set AFH Host Channel Classification */
            proto_tree_add_item(tree, hf_bthci_cmd_afh_ch_classification, tvb, offset, 10, ENC_NA);
            offset+=10;
            break;

        case 0x0008: /* Flush */
        case 0x0027: /* Read Automatic Flush Timeout */
        case 0x0036: /* Read Link Supervision Timeout */
        case 0x0007B: /* Read Authenticated Payload Timeout */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            break;

        case 0x001c: /* Write Page Scan Activity */
        case 0x001e: /* Write Inquiry Scan Activity */
            item = proto_tree_add_item(tree, hf_bthci_cmd_interval, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " slots (%g msec)",  tvb_get_letohs(tvb, offset)*0.625);
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_window, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " slots (%g msec)",  tvb_get_letohs(tvb, offset)*0.625);
            offset+=2;
            break;


        case 0x0043: /* Write Inquiry Scan Type */
            proto_tree_add_item(tree, hf_bthci_cmd_scan_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x0045: /* Write Inquiry Mode */
            proto_tree_add_item(tree, hf_bthci_cmd_inq_mode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            if (!pinfo->fd->visited && bthci_cmd_data) {
                bthci_cmd_data->data.inquiry_mode = tvb_get_guint8(tvb, offset);
            }
            offset++;
            break;

        case 0x0047: /* Write Page Scan Type */
            proto_tree_add_item(tree, hf_bthci_cmd_scan_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x0049: /* Write AFH Channel Assessment Mode */
            proto_tree_add_item(tree, hf_bthci_cmd_afh_ch_assessment_mode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x0052: /* Write Extended Inquiry Response */
            {
            bluetooth_eir_ad_data_t *eir_data;

            eir_data = wmem_new0(wmem_packet_scope(), bluetooth_eir_ad_data_t);
            eir_data->interface_id = bluetooth_data->interface_id;
            eir_data->adapter_id = bluetooth_data->adapter_id;
            eir_data->bd_addr = NULL;

            proto_tree_add_item(tree, hf_bthci_cmd_fec_required, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;

            call_dissector_with_data(btcommon_eir_handle, tvb_new_subset_length(tvb, offset, 240), pinfo, tree, eir_data);
            save_local_device_name_from_eir_ad(tvb, offset, pinfo, 240, bluetooth_data);
            offset += 240;

            }
            break;

        case 0x0053: /* Refresh Encryption Key */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            break;

        case 0x0056: /* Write Simple Pairing Mode */
            proto_tree_add_item(tree, hf_bthci_cmd_simple_pairing_mode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            if (!pinfo->fd->visited && bthci_cmd_data) {
                bthci_cmd_data->data.simple_pairing_mode = tvb_get_guint8(tvb, offset);
            }
            offset++;
            break;

        case 0x0059: /* Write Inquiry Tx Response Power Level */
            proto_tree_add_item(tree, hf_bthci_cmd_tx_power, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x005b: /* Write Default Erroneous Data Reporting */
            proto_tree_add_item(tree, hf_bthci_cmd_err_data_reporting, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x005f: /* Enhanced Flush */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_flush_packet_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x0060: /* Send Keypress Notification */
            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);

            proto_tree_add_item(tree, hf_bthci_cmd_notification_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x0062: /* Write Logical Link Accept Timeout */
            item =  proto_tree_add_item(tree, hf_bthci_cmd_timeout, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " slots (%g msec)",  tvb_get_letohs(tvb, offset)*0.625);
            offset+=2;
            break;

        case 0x0063: /* Set Event Mask Page 2 */
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask2_00, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask2_01, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask2_02, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask2_03, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask2_04, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask2_05, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask2_06, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask2_07, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;

            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask2_10, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask2_11, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask2_12, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask2_13, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask2_14, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_evt_mask2_15, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset+=7;
            break;

        case 0x0065: /* Write Location Data */
            proto_tree_add_item(tree, hf_bthci_cmd_location_domain_aware, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_location_domain, tvb, offset, 2, ENC_ASCII | ENC_NA);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_location_domain_options, tvb, offset, 1, ENC_ASCII | ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_location_options, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x0067: /* Write Flow Control Mode */
            proto_tree_add_item(tree, hf_bthci_cmd_flow_control_mode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x0068: /* Read Enhanced Tx Power Level */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_tx_power_level_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x0069: /* Read Best Effort Flush Timeout */
            proto_tree_add_item(tree, hf_bthci_cmd_logical_link_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            break;

        case 0x006a: /* Write Best Effort Flush Timeout */
            proto_tree_add_item(tree, hf_bthci_cmd_logical_link_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_flush_to_us, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
            break;

        case 0x006b: /* Short Range Mode */
            proto_tree_add_item(tree, hf_bthci_cmd_physical_link_handle, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_short_range_mode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x006d: /* Write LE Host Supported */
            proto_tree_add_item(tree, hf_bthci_cmd_le_supported_host, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_le_simultaneous_host, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x003: /* Reset */
        case 0x009: /* Read PIN Type */
        case 0x00B: /* Create New Unit Key */
        case 0x014: /* Read Local Name */
        case 0x015: /* Read Connection Accept Timeout */
        case 0x017: /* Read Page Timeout */
        case 0x019: /* Read Scan Enable */
        case 0x01B: /* Read Page Scan Activity */
        case 0x01D: /* Read Inquiry Scan Activity */
        case 0x01F: /* Read Authentication Enable */
        case 0x021: /* Read Encryption Mode */
        case 0x023: /* Read Class of Device */
        case 0x025: /* Read Voice Setting */
        case 0x029: /* Read Num Broadcast Retransmissions */
        case 0x02B: /* Read Hold Mode Activity */
        case 0x02E: /* Read SCO Flow Control Enable */
        case 0x038: /* Read Number of Supported IAC */
        case 0x039: /* Read Current IAC LAP */
        case 0x03B: /* Read Page Scan Period Mode */
        case 0x03D: /* Read Page Scan Mode */
        case 0x042: /* Read Inquiry Scan Type */
        case 0x044: /* Read Inquiry Mode */
        case 0x046: /* Read Page Scan Type */
        case 0x048: /* Read AFH Channel Assessment Mode */
        case 0x051: /* Read Extended Inquiry Response */
        case 0x055: /* Read Simple Pairing Mode */
        case 0x057: /* Read Local OOB Data */
        case 0x058: /* Read Inquiry Response Tx Power Level */
        case 0x05A: /* Read Default Erroneous Data Reporting */
        case 0x061: /* Read Logical Link Accept Timeout */
        case 0x064: /* Read Location Data */
        case 0x066: /* Read Flow Control Mode */
        case 0x06C: /* Read LE Host Supported */
        case 0x077: /* Read Synchronization Train Parameters */
        case 0x079: /* Read Secure Connections Host Support */
        case 0x07D: /* Read Local OOB Extended Data */
        case 0x07E: /* Read Extended Page Timeout */
        case 0x080: /* Read Extended Inquiry Length */
            /* NOTE: No parameters */
            break;

        case 0x06E: /* Set MWS Channel Parameters */
            proto_tree_add_item(tree, hf_bthci_mws_channel, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(tree, hf_bthci_mws_rx_center_frequency, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_bthci_mws_tx_center_frequency, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_bthci_mws_rx_channel_bandwidth, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_bthci_mws_tx_channel_bandwidth, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_bthci_mws_channel_type, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 0x06F: /* Set External Frame Configuration */
            {
            proto_item *sub_item;
            proto_tree *sub_tree;
            guint32     number_of_periods;
            gint        i_item = 1;

            proto_tree_add_item(tree, hf_bthci_external_frame_duration, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_bthci_external_frame_sync_assert_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_bthci_external_frame_sync_assert_jitter, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item_ret_uint(tree, hf_bthci_external_frame_number_of_periods, tvb, offset, 1, ENC_NA, &number_of_periods);
            offset += 1;

            sub_item = proto_tree_add_item(tree, hf_bthci_external_frame_periods, tvb, offset, -1, ENC_NA);
            sub_tree = proto_item_add_subtree(sub_item, ett_periods);

            while (number_of_periods--) {
                proto_item *entry_item;
                proto_tree *entry_tree;

                entry_item = proto_tree_add_item(sub_tree, hf_bthci_external_frame_period, tvb, offset, 3, ENC_LITTLE_ENDIAN);
                entry_tree = proto_item_add_subtree(entry_item, ett_period);
                proto_item_append_text(entry_item, " #%u", i_item);

                proto_tree_add_item(entry_tree, hf_bthci_external_frame_period_duration, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(entry_tree, hf_bthci_external_frame_period_type, tvb, offset, 1, ENC_NA);
                offset += 1;

                i_item += 1;
            }

            }
            break;
        case 0x070: /* Set MWS Signaling */
            proto_tree_add_item(tree, hf_bthci_mws_rx_assert_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_bthci_mws_rx_assert_jitter, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_bthci_mws_rx_deassert_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_bthci_mws_rx_deassert_jitter, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;


            proto_tree_add_item(tree, hf_bthci_mws_tx_assert_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_bthci_mws_tx_assert_jitter, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_bthci_mws_tx_deassert_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_bthci_mws_tx_deassert_jitter, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;


            proto_tree_add_item(tree, hf_bthci_mws_pattern_assert_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_bthci_mws_pattern_assert_jitter, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;


            proto_tree_add_item(tree, hf_bthci_mws_inactivity_duration_assert_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_bthci_mws_inactivity_duration_assert_jitter, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;


            proto_tree_add_item(tree, hf_bthci_mws_scan_frequency_assert_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_bthci_mws_scan_frequency_assert_jitter, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;


            proto_tree_add_item(tree, hf_bthci_mws_priority_assert_offset_request, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            break;
        case 0x071: /* Set MWS Transport Layer */
            proto_tree_add_item(tree, hf_bthci_mws_transport_layer, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(tree, hf_bthci_mws_to_baud_rate, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(tree, hf_bthci_mws_from_baud_rate, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            break;
        case 0x072: /* Set MWS Scan Frequency Table */
            {
            proto_item *sub_item;
            proto_tree *sub_tree;
            guint32     number_of_frequencies;
            gint        i_item = 1;

            proto_tree_add_item_ret_uint(tree, hf_bthci_mws_number_of_frequencies, tvb, offset, 1, ENC_NA, &number_of_frequencies);
            offset += 1;

            sub_item = proto_tree_add_item(tree, hf_bthci_mws_scan_frequency_table, tvb, offset, -1, ENC_NA);
            sub_tree = proto_item_add_subtree(sub_item, ett_table);

            while (number_of_frequencies--) {
                proto_item *entry_item;
                proto_tree *entry_tree;

                entry_item = proto_tree_add_item(sub_tree, hf_bthci_mws_scan_frequency_table_item, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                entry_tree = proto_item_add_subtree(entry_item, ett_table_item);
                proto_item_append_text(entry_item, " #%u", i_item);

                proto_tree_add_item(entry_tree, hf_bthci_mws_scan_frequency_table_item_low, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(entry_tree, hf_bthci_mws_scan_frequency_table_item_high, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                i_item += 1;
            }

            }
            break;
        case 0x073: /* Set MWS Pattern Configuration */
            {
            proto_item *sub_item;
            proto_tree *sub_tree;
            guint32     number_of_intervals;
            gint        i_item = 1;

            proto_tree_add_item(tree, hf_bthci_mws_pattern_index, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item_ret_uint(tree, hf_bthci_mws_pattern_number_of_intervals, tvb, offset, 1, ENC_NA, &number_of_intervals);
            offset += 1;

            sub_item = proto_tree_add_item(tree, hf_bthci_mws_patterns, tvb, offset, -1, ENC_NA);
            sub_tree = proto_item_add_subtree(sub_item, ett_patterns);

            while (number_of_intervals--) {
                proto_item *entry_item;
                proto_tree *entry_tree;

                entry_item = proto_tree_add_item(sub_tree, hf_bthci_mws_pattern, tvb, offset, 3, ENC_LITTLE_ENDIAN);
                entry_tree = proto_item_add_subtree(entry_item, ett_pattern);
                proto_item_append_text(entry_item, " #%u", i_item);

                proto_tree_add_item(entry_tree, hf_bthci_mws_pattern_duration, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(entry_tree, hf_bthci_mws_pattern_type, tvb, offset, 1, ENC_NA);
                offset += 1;

                i_item += 1;
            }

            }

            break;
        case 0x074: /* Set Reserved LT_ADDR */
        case 0x075: /* Delete Reserved LT_ADDR */
            proto_tree_add_item(tree, hf_bthci_cmd_lt_addr, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 0x076: /* Set Connectionless Slave Broadcast Data */
            {
            guint32  data_length;

            proto_tree_add_item(tree, hf_bthci_cmd_lt_addr, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(tree, hf_bthci_cmd_csb_fragment, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item_ret_uint(tree, hf_bthci_cmd_csb_data_length, tvb, offset, 1, ENC_NA, &data_length);
            offset += 1;

            proto_tree_add_item(tree, hf_bthci_cmd_csb_data, tvb, offset, data_length, ENC_NA);
            offset += data_length;

            }
            break;
        case 0x078: /* Write Synchronization Train Parameters */
            proto_tree_add_item(tree, hf_bthci_cmd_interval_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_bthci_cmd_interval_max, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_bthci_cmd_sync_train_to, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(tree, hf_bthci_cmd_service_data, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 0x07A: /* Write Secure Connections Host Support */
            proto_tree_add_item(tree, hf_bthci_cmd_secure_connection_host_support, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 0x07C: /* Write Authenticated Payload Timeout */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            item = proto_tree_add_item(tree, hf_bthci_cmd_authenticated_payload_timeout, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g sec)", tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN) * 0.01);
            offset += 2;

            break;
        case 0x07F: /* Write Extended Page Timeout */
            proto_tree_add_item(tree, hf_bthci_cmd_timeout, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            break;
        case 0x081: /* Write Extended Inquiry Length */
            proto_tree_add_item(tree, hf_bthci_cmd_extended_inquiry_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            break;
        default:
            proto_tree_add_expert(tree, pinfo, &ei_command_unknown_command, tvb, offset, -1);
            offset += tvb_reported_length_remaining(tvb, offset);
    }

    return offset;
}

static int
dissect_informational_parameters_cmd(tvbuff_t *tvb, int offset, packet_info *pinfo,
        proto_tree *tree, guint16 cmd_ocf)
{
    switch (cmd_ocf) {

        case 0x0004: /* Read Local Extended Features */
            proto_tree_add_item(tree, hf_bthci_cmd_page_number, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x001: /* Read Local Version Information */
        case 0x002: /* Read Local Supported Commands */
        case 0x003: /* Read Local Supported Features */
        case 0x005: /* Read Buffer Size */
        case 0x007: /* Read Country Code */
        case 0x009: /* Read BD ADDR */
        case 0x00A: /* Read Data Block Size */
        case 0x00B: /* Read Local Supported Codecs */
        case 0x00C: /* Read Local Simple Pairing Options */
            /* NOTE: No parameters */
            break;

        default:
            proto_tree_add_expert(tree, pinfo, &ei_command_unknown_command, tvb, offset, -1);
            offset += tvb_reported_length_remaining(tvb, offset);
    }

    return offset;
}

static int
dissect_status_parameters_cmd(tvbuff_t *tvb, int offset, packet_info *pinfo,
        proto_tree *tree, guint16 cmd_ocf)
{
    switch (cmd_ocf) {

        case 0x0001: /* Read Failed Contact Counter */
        case 0x0002: /* Reset Failed Contact Counter */
        case 0x0003: /* Get Link Quality */
        case 0x0005: /* Read RSSI */
        case 0x0006: /* Read AFH Channel Map */
        case 0x0008: /* Read Encryption Key Size */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            break;

        case 0x0007: /* Read Clock */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_which_clock, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x0009: /* Read Local AMP Info */
            break;

        case 0x000a: /* Read Local AMP Assoc */
            proto_tree_add_item(tree, hf_bthci_cmd_physical_link_handle, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_length_so_far, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_amp_assoc_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            break;

        case 0x000b: /* Write Remote AMP Assoc */
            proto_tree_add_item(tree, hf_bthci_cmd_physical_link_handle, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_length_so_far, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_amp_remaining_assoc_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_amp_assoc_fragment, tvb, offset, -1, ENC_NA);
            offset+=tvb_reported_length_remaining(tvb, offset);
            break;


        case 0x000C: /* Get MWS Transport Layer Configuration */
            /* NOTE: No parameters */
            break;

        case 0x000D: /* Set Triggered Clock Capture */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_bthci_cmd_triggered_clock_capture, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(tree, hf_bthci_cmd_which_clock, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(tree, hf_bthci_cmd_lpo_allowed, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(tree, hf_bthci_cmd_number_of_clock_captures_to_filter, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;

        default:
            proto_tree_add_expert(tree, pinfo, &ei_command_unknown_command, tvb, offset, -1);
            offset += tvb_reported_length_remaining(tvb, offset);
    }

    return offset;
}

static int
dissect_testing_cmd(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint16 cmd_ocf)
{
    switch (cmd_ocf) {

        case 0x0002: /* Write Loopback Mode */
            proto_tree_add_item(tree, hf_bthci_cmd_loopback_mode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x0004: /* Write Simple Pairing Debug Mode */
            proto_tree_add_item(tree, hf_bthci_cmd_simple_pairing_debug_mode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x0007: /* Enable AMP Receiver Reports */
            proto_tree_add_item(tree, hf_bthci_cmd_enable_amp_recv_reports, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_amp_recv_report_interval, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x001: /* Read Loopback Mode */
        case 0x003: /* Enable Device Under Test Mode */
        case 0x008: /* AMP Test End */
            /* NOTE: No parameters */
            break;

        case 0x009: /* AMP Test */
            proto_tree_add_item(tree, hf_bthci_cmd_amp_controller_type, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 0x00A: /* Write Secure Connections Test Mode */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_bthci_cmd_dm1_acl_u_mode, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(tree, hf_bthci_cmd_esco_loopback_mode, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        default:
            proto_tree_add_expert(tree, pinfo, &ei_command_unknown_command, tvb, offset, -1);
            offset += tvb_reported_length_remaining(tvb, offset);
    }

    return offset;
}

static gint
dissect_le_cmd(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint16 cmd_ocf, bluetooth_data_t *bluetooth_data)
{
    proto_item  *item;
    proto_item  *sub_item;
    proto_tree  *sub_tree;

    switch(cmd_ocf) {

        case 0x0001: /* LE Set Event Mask */
            proto_tree_add_bitmask(tree, tvb, offset, hf_bthci_cmd_le_event_mask, ett_le_event_mask, hfx_bthci_cmd_le_event_mask, ENC_LITTLE_ENDIAN);
            offset += 8;
            break;

        case 0x0005: /* LE Set Random Address */
            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);
            break;

        case 0x0006: /* LE Set Advertising Parameters */
            item = proto_tree_add_item(tree, hf_bthci_cmd_le_advts_interval_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g msec)",  tvb_get_letohs(tvb, offset)*0.625);
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_le_advts_interval_max, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g msec)",  tvb_get_letohs(tvb, offset)*0.625);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_le_advts_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_le_own_address_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_le_direct_address_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);
            proto_tree_add_item(tree, hf_bthci_cmd_le_advts_channel_map_1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_le_advts_channel_map_2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_le_advts_channel_map_3, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_le_advts_filter_policy, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x0008: /* LE Set Advertising Data */
        case 0x0009: /* LE Set Scan Response Data */
            {
            bluetooth_eir_ad_data_t *ad_data;

            ad_data = wmem_new0(wmem_packet_scope(), bluetooth_eir_ad_data_t);
            ad_data->interface_id = bluetooth_data->interface_id;
            ad_data->adapter_id = bluetooth_data->adapter_id;
            ad_data->bd_addr = NULL;

            proto_tree_add_item(tree, hf_bthci_cmd_le_data_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;

            call_dissector_with_data(btcommon_ad_handle, tvb_new_subset_length(tvb, offset, 31), pinfo, tree, ad_data);
            save_local_device_name_from_eir_ad(tvb, offset, pinfo, 31, bluetooth_data);
            offset += 31;

            }
            break;

        case 0x000a: /* LE Set Advertise Enable */
            proto_tree_add_item(tree, hf_bthci_cmd_le_advts_enable, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x000b: /* LE Set Scan Parameters */
            proto_tree_add_item(tree, hf_bthci_cmd_le_scan_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            item = proto_tree_add_item(tree, hf_bthci_cmd_le_scan_interval, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g msec)",  tvb_get_letohs(tvb, offset)*0.625);
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_le_scan_window, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g msec)",  tvb_get_letohs(tvb, offset)*0.625);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_le_own_address_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_le_scan_filter_policy, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x000c: /* LE Set Scan Enable */
            proto_tree_add_item(tree, hf_bthci_cmd_le_scan_enable, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_le_filter_duplicates, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x000d: /* LE Create Connection */
            item = proto_tree_add_item(tree, hf_bthci_cmd_le_scan_interval, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g msec)",  tvb_get_letohs(tvb, offset)*0.625);
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_le_scan_window, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g msec)",  tvb_get_letohs(tvb, offset)*0.625);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_le_initiator_filter_policy, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_le_peer_address_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);
            proto_tree_add_item(tree, hf_bthci_cmd_le_own_address_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            item = proto_tree_add_item(tree, hf_bthci_cmd_le_con_interval_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g msec)",  tvb_get_letohs(tvb, offset)*1.25);
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_le_con_interval_max, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g msec)",  tvb_get_letohs(tvb, offset)*1.25);
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_le_con_latency, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (number events)");
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_le_supervision_timeout, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g sec)",  tvb_get_letohs(tvb, offset)*0.01);
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_le_min_ce_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g msec)",  tvb_get_letohs(tvb, offset)*0.625);
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_le_max_ce_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g msec)",  tvb_get_letohs(tvb, offset)*0.625);
            offset+=2;
            break;

        case 0x0011: /* LE Add Device To White List */
        case 0x0012: /* LE Remove Device From White List */
            proto_tree_add_item(tree, hf_bthci_cmd_le_address_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);
            break;

        case 0x0013: /* LE Connection Update */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_le_con_interval_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g msec)",  tvb_get_letohs(tvb, offset)*1.25);
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_le_con_interval_max, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g msec)",  tvb_get_letohs(tvb, offset)*1.25);
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_le_con_latency, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (number events)");
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_le_supervision_timeout, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g sec)",  tvb_get_letohs(tvb, offset)*0.01);
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_le_min_ce_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g msec)",  tvb_get_letohs(tvb, offset)*0.625);
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_le_max_ce_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g msec)",  tvb_get_letohs(tvb, offset)*0.625);
            offset+=2;
            break;

        case 0x0014: /* LE Set Host Channel Classification */
            sub_item = proto_tree_add_item(tree, hf_bthci_cmd_le_channel_map, tvb, offset, 5, ENC_NA);
            sub_tree = proto_item_add_subtree(sub_item, ett_le_channel_map);

            call_dissector(btcommon_le_channel_map_handle, tvb_new_subset_length(tvb, offset, 5), pinfo, sub_tree);
            offset += 5;

            break;

        case 0x0015: /* LE Read Channel Map */
        case 0x0016: /* LE Read Remote Features */
        case 0x001b: /* LE Long Term Key Request Negative Reply */
        case 0x0030: /* LE Read PHY */
        case 0x006D: /* LE Request Peer SCA */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            break;

        case 0x0017: /* LE Encrypt */
            proto_tree_add_item(tree, hf_bthci_cmd_key, tvb, offset, 16, ENC_NA);
            offset+=16;
            proto_tree_add_item(tree, hf_bthci_cmd_plaintext_data, tvb, offset, 16, ENC_NA);
            offset+=16;
            break;

        case 0x0019: /* LE Start Encryption */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_random_number, tvb, offset, 8, ENC_NA);
            offset+=8;
            proto_tree_add_item(tree, hf_bthci_cmd_encrypted_diversifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_le_long_term_key, tvb, offset, 16, ENC_NA);
            offset+=16;
            break;

        case 0x001a: /* LE Long Term Key Request Reply */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_le_long_term_key, tvb, offset, 16, ENC_NA);
            offset+=16;
            break;

        case 0x001d: /* LE Receiver Test [v1] */
            item = proto_tree_add_item(tree, hf_bthci_cmd_rx_frequency, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%d MHz)",  2402 + 2*tvb_get_guint8(tvb, offset));
            offset++;
            break;

        case 0x001e: /* LE Transmitter Test [v1] */
            item = proto_tree_add_item(tree, hf_bthci_cmd_tx_frequency, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%d MHz)",  2402 + 2*tvb_get_guint8(tvb, offset));
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_test_data_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_test_packet_payload, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x0020: /*LE Remote Connection Parameter Request Reply */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_le_con_interval_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g msec)",  tvb_get_letohs(tvb, offset)*1.25);
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_le_con_interval_max, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g msec)",  tvb_get_letohs(tvb, offset)*1.25);
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_le_con_latency, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (number events)");
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_le_supervision_timeout, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g sec)",  tvb_get_letohs(tvb, offset)*0.01);
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_le_min_ce_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g msec)",  tvb_get_letohs(tvb, offset)*0.625);
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_le_max_ce_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g msec)",  tvb_get_letohs(tvb, offset)*0.625);
            offset+=2;
            break;

        case 0x0021: /* LE Remote Connection Parameter Request Negative Reply */
        case 0x0067: /* LE Reject CIS Request */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_reason, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x0022: /* LE Set Data Length */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_le_tx_octets, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_le_tx_time, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            break;

        case 0x0024: /* LE Write Suggested Default Data Length */
            proto_tree_add_item(tree, hf_bthci_cmd_le_suggested_max_tx_octets, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_le_suggested_max_tx_time, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            break;

        case 0x0026: /* LE Generate DHKey [v1] */
            proto_tree_add_item(tree, hf_bthci_cmd_le_remote_p_256_public_key, tvb, offset, 64, ENC_NA);
            offset+=64;
            break;

        case 0x0027:  /* LE Add Device to Resolving List */
            proto_tree_add_item(tree, hf_bthci_cmd_le_peer_identity_address_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);
            proto_tree_add_item(tree, hf_bthci_cmd_le_peer_irk, tvb, offset, 16, ENC_NA);
            offset+=16;
            proto_tree_add_item(tree, hf_bthci_cmd_le_local_irk, tvb, offset, 16, ENC_NA);
            offset+=16;
            break;

        case 0x0028: /*  LE Remove Device From Resolving List */
            proto_tree_add_item(tree, hf_bthci_cmd_le_peer_identity_address_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);
            break;

        case 0x002B: /*   LE Read Peer Resolvable Address */
            proto_tree_add_item(tree, hf_bthci_cmd_le_peer_identity_address_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);
            break;

        case 0x002C: /*      LE Read Local Resolvable Address" */
            proto_tree_add_item(tree, hf_bthci_cmd_le_peer_identity_address_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);
            break;

        case 0x002D: /* Set Address Resolution Enable */
            proto_tree_add_item(tree, hf_bthci_cmd_le_address_resolution_enable, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x002E: /* LE Set Resolvable Private Address Timeout */
            proto_tree_add_item(tree, hf_bthci_cmd_le_rpa_timeout, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            break;

        case 0x0031: /* LE Set Default PHY */
            proto_tree_add_bitmask(tree, tvb, offset, hf_bthci_cmd_all_phys, ett_phys_flags, hfx_btcmd_all_phys, ENC_NA);
            offset += 1;
            proto_tree_add_bitmask(tree, tvb, offset, hf_bthci_cmd_tx_phys, ett_phys_flags, hfx_btcmd_phys_pref, ENC_NA);
            offset+=1;
            proto_tree_add_bitmask(tree, tvb, offset, hf_bthci_cmd_rx_phys, ett_phys_flags, hfx_btcmd_phys_pref, ENC_NA);
            offset+=1;
            break;

        case 0x0032: /* LE Set PHY */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_bitmask(tree, tvb, offset, hf_bthci_cmd_all_phys, ett_phys_flags, hfx_btcmd_all_phys, ENC_NA);
            offset += 1;
            proto_tree_add_bitmask(tree, tvb, offset, hf_bthci_cmd_tx_phys, ett_phys_flags, hfx_btcmd_phys_pref, ENC_NA);
            offset+=1;
            proto_tree_add_bitmask(tree, tvb, offset, hf_bthci_cmd_rx_phys, ett_phys_flags, hfx_btcmd_phys_pref, ENC_NA);
            offset+=1;
            proto_tree_add_bitmask(tree, tvb, offset, hf_bthci_cmd_phy_options, ett_phys_flags, hfx_btcmd_phy_options, ENC_LITTLE_ENDIAN);
            offset+=2;
            break;

        case 0x0033: /* LE Receiver Test [v2] */
            item = proto_tree_add_item(tree, hf_bthci_cmd_rx_frequency, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%d MHz)",  2402 + 2*tvb_get_guint8(tvb, offset));
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_phy, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_modulation_index, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x0034: /* LE Transmitter Test [v2] */
            item = proto_tree_add_item(tree, hf_bthci_cmd_tx_frequency, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%d MHz)",  2402 + 2*tvb_get_guint8(tvb, offset));
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_test_data_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_test_packet_payload, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_phy, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x0035: /* LE Set Advertising Set Random Address */
            proto_tree_add_item(tree, hf_bthci_cmd_advertising_handle, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset+=1;
            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);
            break;

        case 0x0036: /* LE Set Extended Advertising Parameters */
            proto_tree_add_item(tree, hf_bthci_cmd_advertising_handle, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset+=1;
            proto_tree_add_bitmask(tree, tvb, offset, hf_bthci_cmd_advertising_properties, ett_adv_properties, hfx_bthci_cmd_adv_properties, ENC_LITTLE_ENDIAN);
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_advertising_ext_interval_min, tvb, offset, 3, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g msec)",  tvb_get_letoh24(tvb, offset)*0.625);
            offset+=3;
            item = proto_tree_add_item(tree, hf_bthci_cmd_advertising_ext_interval_max, tvb, offset, 3, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g msec)",  tvb_get_letoh24(tvb, offset)*0.625);
            offset+=3;
            proto_tree_add_item(tree, hf_bthci_cmd_le_advts_channel_map_1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_le_advts_channel_map_2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_bthci_cmd_le_advts_channel_map_3, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_le_own_address_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_le_peer_address_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);
            proto_tree_add_item(tree, hf_bthci_cmd_le_advts_filter_policy, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_tx_power, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_primary_advertising_phy, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_sec_adv_max_skip, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_secondary_advertising_phy, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_advertising_sid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_scan_req_notif_en, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            break;

        case 0x0037: /* LE Set Extended Advertising Data */
        case 0x0038: /* LE Set Extended Scan Response Data */
            {
            proto_tree_add_item(tree, hf_bthci_cmd_advertising_handle, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset+=1;
            proto_tree_add_item(tree, hf_bthci_cmd_le_adv_data_operation, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset+=1;
            proto_tree_add_item(tree, hf_bthci_cmd_le_adv_data_frag_pref, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset+=1;

            bluetooth_eir_ad_data_t *ad_data;
            ad_data = wmem_new0(wmem_packet_scope(), bluetooth_eir_ad_data_t);
            ad_data->interface_id = bluetooth_data->interface_id;
            ad_data->adapter_id = bluetooth_data->adapter_id;
            ad_data->bd_addr = NULL;

            guint8 data_length = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(tree, hf_bthci_cmd_le_data_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            call_dissector_with_data(btcommon_ad_handle, tvb_new_subset_length(tvb, offset, data_length), pinfo, tree, ad_data);
            save_local_device_name_from_eir_ad(tvb, offset, pinfo, data_length, bluetooth_data);
            offset += data_length;
            }
            break;

        case 0x0039: /* LE Set Extended Advertising Enable */
            {
            proto_tree_add_item(tree, hf_bthci_cmd_le_advts_enable, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;

            guint8 number_of_sets = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(tree, hf_bthci_cmd_le_adv_en_sets, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;

            for (int i = 0; i< number_of_sets; i++) {
                sub_item = proto_tree_add_none_format(tree, hf_bthci_cmd_le_adv_set, tvb, offset, 4, "Set, Handle: %u", tvb_get_guint8(tvb, offset));
                sub_tree = proto_item_add_subtree(sub_item, ett_adv_sets);
                proto_tree_add_item(sub_tree, hf_bthci_cmd_advertising_handle, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset+=1;
                item = proto_tree_add_item(sub_tree, hf_bthci_cmd_le_adv_duration, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                proto_item_append_text(item, " (%g msec)",  tvb_get_letohs(tvb, offset)*10.0);
                offset+=2;
                proto_tree_add_item(sub_tree, hf_bthci_cmd_le_adv_max_extended_events, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset+=1;
            }
            }
            break;

        case 0x003C: /* LE Remove Advertising Set */
            proto_tree_add_item(tree, hf_bthci_cmd_advertising_handle, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset+=1;
            break;

        case 0x003E: /* LE Set Periodic Advertising Parameters */
                proto_tree_add_item(tree, hf_bthci_cmd_advertising_handle, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset+=1;
            item = proto_tree_add_item(tree, hf_bthci_cmd_le_advts_interval_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g msec)",  tvb_get_letohs(tvb, offset)*1.25);
                offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_le_advts_interval_max, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g msec)",  tvb_get_letohs(tvb, offset)*1.25);
            offset+=2;
            proto_tree_add_bitmask(tree, tvb, offset, hf_bthci_cmd_periodic_advertising_properties, ett_adv_properties,
                                                      hfx_bthci_cmd_periodic_adv_properties, ENC_LITTLE_ENDIAN);
            offset+=2;
            break;

        case 0x003F: /* LE Set Periodic Advertising Data */
            {
            proto_tree_add_item(tree, hf_bthci_cmd_advertising_handle, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset+=1;
            proto_tree_add_item(tree, hf_bthci_cmd_le_adv_data_operation, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset+=1;

            bluetooth_eir_ad_data_t *ad_data;
            ad_data = wmem_new0(wmem_packet_scope(), bluetooth_eir_ad_data_t);
            ad_data->interface_id = bluetooth_data->interface_id;
            ad_data->adapter_id = bluetooth_data->adapter_id;
            ad_data->bd_addr = NULL;

            guint8 data_length = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(tree, hf_bthci_cmd_le_data_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            call_dissector_with_data(btcommon_ad_handle, tvb_new_subset_length(tvb, offset, data_length), pinfo, tree, ad_data);
            save_local_device_name_from_eir_ad(tvb, offset, pinfo, data_length, bluetooth_data);
            offset += data_length;
            }
            break;

        case 0x0040: /* LE Set Periodic Advertising Enable */
            proto_tree_add_item(tree, hf_bthci_cmd_le_advts_enable, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_advertising_handle, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset+=1;
            break;

        case 0x0041: /* LE Set Extended Scan Parameters */
            {
            guint8 scanning_phys, phy = 0;
            proto_tree_add_item(tree, hf_bthci_cmd_le_own_address_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_le_scan_filter_policy, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            scanning_phys = tvb_get_guint8(tvb, offset);
            proto_tree_add_bitmask(tree, tvb, offset, hf_bthci_cmd_le_scan_phys, ett_phy_param, hfx_btcmd_le_scan_phys, ENC_NA);
            offset += 1;
            for (int i = 1; i < 0x08; i <<=1) {
                phy++;
                if (scanning_phys & i) {
                    sub_item = proto_tree_add_none_format(tree, hf_bthci_cmd_le_scan_phy_param, tvb, offset, 5, "Scanning PHY: %s",
                                                                                        val_to_str_const(phy, cmd_le_phy_vals, "Unknown"));
                    sub_tree = proto_item_add_subtree(sub_item, ett_phy_param);
                    proto_tree_add_item(sub_tree, hf_bthci_cmd_le_scan_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    offset++;
                    item = proto_tree_add_item(sub_tree, hf_bthci_cmd_le_scan_interval, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    proto_item_append_text(item, " (%g msec)",  tvb_get_letohs(tvb, offset)*0.625);
                    offset+=2;
                    item = proto_tree_add_item(sub_tree, hf_bthci_cmd_le_scan_window, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    proto_item_append_text(item, " (%g msec)",  tvb_get_letohs(tvb, offset)*0.625);
                    offset+=2;
                }
            }
            }
            break;

        case 0x0042: /* LE Set Extended Scan Enable */
            proto_tree_add_item(tree, hf_bthci_cmd_le_scan_enable, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_le_filter_duplicates, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            item = proto_tree_add_item(tree, hf_bthci_cmd_le_scan_duration, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g msec)",  tvb_get_letohs(tvb, offset)*10.0);
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_le_scan_period, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g sec)",  tvb_get_letohs(tvb, offset)*1.28);
            offset+=2;
            break;

        case 0x0043: /* LE Extended Create Connection */
            {
            guint8 initiating_phys, phy = 0;
            proto_tree_add_item(tree, hf_bthci_cmd_le_initiator_filter_policy, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_le_own_address_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_le_peer_address_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);
            initiating_phys = tvb_get_guint8(tvb, offset);
            proto_tree_add_bitmask(tree, tvb, offset, hf_bthci_cmd_le_init_phys, ett_phy_param, hfx_btcmd_le_phys, ENC_NA);
            offset += 1;
            for (int i = 1; i < 0x08; i <<=1) {
                phy++;
                if (initiating_phys & i) {
                    sub_item = proto_tree_add_none_format(tree, hf_bthci_cmd_le_init_phy_param, tvb, offset, 16, "Initiating PHY: %s",
                                                                                        val_to_str_const(phy, cmd_le_phy_vals, "Unknown"));
                    sub_tree = proto_item_add_subtree(sub_item, ett_phy_param);
                    item = proto_tree_add_item(sub_tree, hf_bthci_cmd_le_scan_interval, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    proto_item_append_text(item, " (%g msec)",  tvb_get_letohs(tvb, offset)*0.625);
                    offset+=2;
                    item = proto_tree_add_item(sub_tree, hf_bthci_cmd_le_scan_window, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    proto_item_append_text(item, " (%g msec)",  tvb_get_letohs(tvb, offset)*0.625);
                    offset+=2;
                    item = proto_tree_add_item(sub_tree, hf_bthci_cmd_le_con_interval_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    proto_item_append_text(item, " (%g msec)",  tvb_get_letohs(tvb, offset)*1.25);
                    offset+=2;
                    item = proto_tree_add_item(sub_tree, hf_bthci_cmd_le_con_interval_max, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    proto_item_append_text(item, " (%g msec)",  tvb_get_letohs(tvb, offset)*1.25);
                    offset+=2;
                    item = proto_tree_add_item(sub_tree, hf_bthci_cmd_le_con_latency, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    proto_item_append_text(item, " (number events)");
                    offset+=2;
                    item = proto_tree_add_item(sub_tree, hf_bthci_cmd_le_supervision_timeout, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    proto_item_append_text(item, " (%g sec)",  tvb_get_letohs(tvb, offset)*0.01);
                    offset+=2;
                    item = proto_tree_add_item(sub_tree, hf_bthci_cmd_le_min_ce_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    proto_item_append_text(item, " (%g msec)",  tvb_get_letohs(tvb, offset)*0.625);
                    offset+=2;
                    item = proto_tree_add_item(sub_tree, hf_bthci_cmd_le_max_ce_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    proto_item_append_text(item, " (%g msec)",  tvb_get_letohs(tvb, offset)*0.625);
                    offset+=2;
                }
            }
            }
            break;

        case 0x0044: /* LE Periodic Advertising Create Sync */
            proto_tree_add_item(tree, hf_bthci_cmd_sync_filter_policy, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_advertising_sid, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_le_peer_address_type, tvb, offset, 1, ENC_NA);
            offset++;
            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);
            proto_tree_add_item(tree, hf_bthci_cmd_skip, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_le_supervision_timeout, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g sec)",  tvb_get_letohs(tvb, offset)*0.01);
            offset+=2;
            proto_tree_add_bitmask(tree, tvb, offset, hf_bthci_cmd_sync_cte_type, ett_sync_cte_type, hfx_btcmd_sync_cte_type, ENC_NA);
            offset++;
            break;

        case 0x0046: /* LE Periodic Advertising Terminate Sync */
            proto_tree_add_item(tree, hf_bthci_cmd_sync_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            break;

        case 0x0047: /* LE Add Device To Periodic Advertiser List */
        case 0x0048: /* LE Remove Device From Periodic Advertiser List */
            proto_tree_add_item(tree, hf_bthci_cmd_le_peer_address_type, tvb, offset, 1, ENC_NA);
            offset++;
            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);
            proto_tree_add_item(tree, hf_bthci_cmd_advertising_sid, tvb, offset, 1, ENC_NA);
            offset++;
            break;

        case 0x004D: /* LE Write RF Path Compensation */
            item = proto_tree_add_item(tree, hf_bthci_cmd_rf_tx_path_compensation_value, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g dB)", tvb_get_letohis(tvb, offset)*0.1);
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_rf_rx_path_compensation_value, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g dB)", tvb_get_letohis(tvb, offset)*0.1);
            offset+=2;
            break;

        case 0x004E: /* LE Set Privacy Mode */
            proto_tree_add_item(tree, hf_bthci_cmd_le_peer_identity_address_type, tvb, offset, 1, ENC_NA);
            offset++;
            offset = dissect_bd_addr(hf_bthci_cmd_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);
            proto_tree_add_item(tree, hf_bthci_cmd_le_privacy_mode, tvb, offset, 1, ENC_NA);
            offset++;
            break;

        case 0x004F: /* LE Receiver Test [v3] */
            item = proto_tree_add_item(tree, hf_bthci_cmd_rx_frequency, tvb, offset, 1, ENC_NA);
            proto_item_append_text(item, " (%d MHz)",  2402 + 2*tvb_get_guint8(tvb, offset));
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_phy, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_modulation_index, tvb, offset, 1, ENC_NA);
            offset++;
            item = proto_tree_add_item(tree, hf_bthci_cmd_cte_length, tvb, offset, 1, ENC_NA);
            proto_item_append_text(item, " (%d usec)", tvb_get_guint8(tvb, offset)*8);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_cte_type, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_slot_durations, tvb, offset, 1, ENC_NA);
            offset++;
            offset = dissect_antenna_switching_pattern(tvb, offset, tree);
            break;

       case 0x0050: /* LE Transmitter Test [v3] */
            item = proto_tree_add_item(tree, hf_bthci_cmd_tx_frequency, tvb, offset, 1, ENC_NA);
            proto_item_append_text(item, " (%d MHz)",  2402 + 2*tvb_get_guint8(tvb, offset));
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_test_data_length, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_test_packet_payload, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_phy, tvb, offset, 1, ENC_NA);
            offset++;
            item = proto_tree_add_item(tree, hf_bthci_cmd_cte_length, tvb, offset, 1, ENC_NA);
            proto_item_append_text(item, " (%d usec)", tvb_get_guint8(tvb, offset)*8);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_cte_type, tvb, offset, 1, ENC_NA);
            offset++;
            offset = dissect_antenna_switching_pattern(tvb, offset, tree);
            break;

        case 0x0051: /* LE Set Connectionless CTE Transmit Parameters */
            proto_tree_add_item(tree, hf_bthci_cmd_advertising_handle, tvb, offset, 1, ENC_NA);
            offset++;
            item = proto_tree_add_item(tree, hf_bthci_cmd_cte_length, tvb, offset, 1, ENC_NA);
            proto_item_append_text(item, " (%d usec)", tvb_get_guint8(tvb, offset)*8);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_cte_type, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_cte_count, tvb, offset, 1, ENC_NA);
            offset++;
            offset = dissect_antenna_switching_pattern(tvb, offset, tree);
            break;

        case 0x0052: /* LE Set Connectionless CTE Transmit Enable */
            proto_tree_add_item(tree, hf_bthci_cmd_advertising_handle, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_cte_enable, tvb, offset, 1, ENC_NA);
            offset++;
            break;

        case 0x0053: /* LE Set Connectionless IQ Sampling Enable */
            proto_tree_add_item(tree, hf_bthci_cmd_sync_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_iq_sampling_enable, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_slot_durations, tvb, offset, 1, ENC_NA);
            offset++;
            item = proto_tree_add_item(tree, hf_bthci_cmd_max_sampled_ctes, tvb, offset, 1, ENC_NA);
            if (tvb_get_guint8(tvb, offset) == 0)
                proto_item_append_text(item, " (Sample and report all available CTEs)");
            offset++;
            offset = dissect_antenna_switching_pattern(tvb, offset, tree);
            break;

        case 0x0054: /* LE Set Connection CTE Receive Parameters */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_iq_sampling_enable, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_slot_durations, tvb, offset, 1, ENC_NA);
            offset++;
            offset = dissect_antenna_switching_pattern(tvb, offset, tree);
            break;

        case 0x0055: /* LE Set Connection CTE Transmit Parameters */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_bitmask(tree, tvb, offset, hf_bthci_cmd_cte_types, ett_sync_cte_type, hfx_btcmd_cte_types, ENC_NA);
            offset++;
            offset = dissect_antenna_switching_pattern(tvb, offset, tree);
            break;

        case 0x0056: /* LE Connection CTE Request Enable */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_cte_enable, tvb, offset, 1, ENC_NA);
            offset++;
            item = proto_tree_add_item(tree, hf_bthci_cmd_cte_request_interval, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            if (tvb_get_letohs(tvb, offset) == 0)
                proto_item_append_text(item, " (Initiate once, at earliest opportunity)");
            else
                proto_item_append_text(item, " (Connection Events)");
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_cte_length, tvb, offset, 1, ENC_NA);
            proto_item_append_text(item, " (%d usec)", tvb_get_guint8(tvb, offset)*8);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_cte_type, tvb, offset, 1, ENC_NA);
            offset++;
            break;

        case 0x0057: /* LE Connection CTE Response Enable */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_cte_enable, tvb, offset, 1, ENC_NA);
            offset++;
            break;

        case 0x0059: /* LE Set Periodic Advertising Receive Enable */
            proto_tree_add_item(tree, hf_bthci_cmd_sync_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_reporting_enable, tvb, offset, 1, ENC_NA);
            offset++;
            break;

        case 0x005A: /* LE Periodic Advertising Sync Transfer */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_service_data_past, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_sync_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            break;

        case 0x005B: /* LE Periodic Advertising Set Info Transfer */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_service_data_past, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_advertising_handle, tvb, offset, 1, ENC_NA);
            offset++;
            break;

        case 0x005C: /* LE Set Periodic Advertising Sync Transfer Parameters */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            /* FALL THROUGH */

        case 0x005D: /* LE Set Default Periodic Advertising Sync Transfer Parameters */
            proto_tree_add_item(tree, hf_bthci_cmd_sync_mode, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_skip, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            item = proto_tree_add_item(tree, hf_bthci_cmd_le_supervision_timeout, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g sec)",  tvb_get_letohs(tvb, offset)*0.01);
            offset+=2;
            proto_tree_add_bitmask(tree, tvb, offset, hf_bthci_cmd_sync_cte_type, ett_sync_cte_type, hfx_btcmd_sync_cte_type, ENC_NA);
            offset++;
            break;

        case 0x005E: /* LE Generate DHKey [v2] */
            proto_tree_add_item(tree, hf_bthci_cmd_le_remote_p_256_public_key, tvb, offset, 64, ENC_NA);
            offset+=64;
            proto_tree_add_item(tree, hf_bthci_cmd_key_type, tvb, offset, 1, ENC_NA);
            offset++;
            break;

        case 0x005F: /* LE Modify Sleep Clock Accuracy */
            proto_tree_add_item(tree, hf_bthci_cmd_sca_action, tvb, offset, 1, ENC_NA);
            offset++;
            break;

        case 0x0061: /* LE Read ISO Tx Sync */
        case 0x0072: /* LE ISO Read Test Counters */
        case 0x0073: /* LE ISO Test End */
        case 0x0075: /* LE Read ISO Link Quality */
            proto_tree_add_item(tree, hf_bthci_cmd_cis_bis_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            break;

        case 0x0062: /* LE Set CIG Parameters */
            {
            guint8 cis_count;
            proto_tree_add_item(tree, hf_bthci_cmd_cig_id, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_sdu_interval_m_to_s, tvb, offset, 3, ENC_LITTLE_ENDIAN);
            offset+=3;
            proto_tree_add_item(tree, hf_bthci_cmd_sdu_interval_s_to_m, tvb, offset, 3, ENC_LITTLE_ENDIAN);
            offset+=3;
            proto_tree_add_item(tree, hf_bthci_cmd_slaves_clock_accuracy, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_packing, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_framing, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_max_transport_latency_m_to_s, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_max_transport_latency_s_to_m, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_cis_count, tvb, offset, 1, ENC_NA);
            cis_count = tvb_get_guint8(tvb, offset);
            offset++;

            for (int i = 0; i < cis_count; i++) {
                sub_item = proto_tree_add_none_format(tree, hf_bthci_cmd_cis_params, tvb, offset, 9, "CIS Parameters, CIS Id: 0x%x", tvb_get_guint8(tvb, offset));
                sub_tree = proto_item_add_subtree(sub_item, ett_cis_params);
                proto_tree_add_item(sub_tree, hf_bthci_cmd_cis_id, tvb, offset, 1, ENC_NA);
                offset++;
                proto_tree_add_item(sub_tree, hf_bthci_cmd_max_sdu_m_to_s, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset+=2;
                proto_tree_add_item(sub_tree, hf_bthci_cmd_max_sdu_s_to_m, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset+=2;
                proto_tree_add_bitmask(sub_tree, tvb, offset, hf_bthci_cmd_phy_m_to_s, ett_phy_param, hfx_btcmd_le_phys, ENC_NA);
                offset++;
                proto_tree_add_bitmask(sub_tree, tvb, offset, hf_bthci_cmd_phy_s_to_m, ett_phy_param, hfx_btcmd_le_phys, ENC_NA);
                offset++;
                proto_tree_add_item(sub_tree, hf_bthci_cmd_rtn_m_to_s, tvb, offset, 1, ENC_NA);
                offset++;
                proto_tree_add_item(sub_tree, hf_bthci_cmd_rtn_s_to_m, tvb, offset, 1, ENC_NA);
                offset++;
            }
            }
            break;

        case 0x0063: /* LE Set CIG Parameters Test */
            {
            guint8 cis_count;
            proto_tree_add_item(tree, hf_bthci_cmd_cig_id, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_sdu_interval_m_to_s, tvb, offset, 3, ENC_LITTLE_ENDIAN);
            offset+=3;
            proto_tree_add_item(tree, hf_bthci_cmd_sdu_interval_s_to_m, tvb, offset, 3, ENC_LITTLE_ENDIAN);
            offset+=3;
            item = proto_tree_add_item(tree, hf_bthci_cmd_ft_m_to_s, tvb, offset, 1, ENC_NA);
            proto_item_append_text(item, " ISO Intervals");
            offset++;
            item = proto_tree_add_item(tree, hf_bthci_cmd_ft_s_to_m, tvb, offset, 1, ENC_NA);
            proto_item_append_text(item, " ISO Intervals");
            offset++;
            item = proto_tree_add_item(tree, hf_bthci_cmd_iso_interval, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g msec)", tvb_get_letohs(tvb, offset) * 1.25);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_slaves_clock_accuracy, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_packing, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_framing, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_cis_count, tvb, offset, 1, ENC_NA);
            cis_count = tvb_get_guint8(tvb, offset);
            offset++;

            for (int i = 0; i < cis_count; i++) {
                sub_item = proto_tree_add_none_format(tree, hf_bthci_cmd_cis_params, tvb, offset, 14, "CIS Parameters, CIS Id: 0x%x", tvb_get_guint8(tvb, offset));
                sub_tree = proto_item_add_subtree(sub_item, ett_cis_params);
                proto_tree_add_item(sub_tree, hf_bthci_cmd_cis_id, tvb, offset, 1, ENC_NA);
                offset++;
                proto_tree_add_item(sub_tree, hf_bthci_cmd_nse, tvb, offset, 1, ENC_NA);
                offset++;
                proto_tree_add_item(sub_tree, hf_bthci_cmd_max_sdu_m_to_s, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset+=2;
                proto_tree_add_item(sub_tree, hf_bthci_cmd_max_sdu_s_to_m, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset+=2;
                proto_tree_add_item(sub_tree, hf_bthci_cmd_max_pdu_m_to_s, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset+=2;
                proto_tree_add_item(sub_tree, hf_bthci_cmd_max_pdu_s_to_m, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset+=2;
                proto_tree_add_bitmask(sub_tree, tvb, offset, hf_bthci_cmd_phy_m_to_s, ett_phy_param, hfx_btcmd_le_phys, ENC_NA);
                offset++;
                proto_tree_add_bitmask(sub_tree, tvb, offset, hf_bthci_cmd_phy_s_to_m, ett_phy_param, hfx_btcmd_le_phys, ENC_NA);
                offset++;
                item = proto_tree_add_item(sub_tree, hf_bthci_cmd_bn_m_to_s, tvb, offset, 1, ENC_NA);
                if (tvb_get_guint8(tvb, offset) == 0)
                    proto_item_append_text(item, " (No data)");
                offset++;
                proto_tree_add_item(sub_tree, hf_bthci_cmd_bn_s_to_m, tvb, offset, 1, ENC_NA);
                if (tvb_get_guint8(tvb, offset) == 0)
                    proto_item_append_text(item, " (No data)");
                offset++;
            }
            }
            break;

        case 0x0064: /* LE Create CIS */
            {
            guint8 cis_count;
            proto_tree_add_item(tree, hf_bthci_cmd_cis_count, tvb, offset, 1, ENC_NA);
            cis_count = tvb_get_guint8(tvb, offset);
            offset++;
            for (int i = 0; i < cis_count; i++) {
                sub_item = proto_tree_add_none_format(tree, hf_bthci_cmd_cis_params, tvb, offset, 4, "CIS Handle: 0x%03x, Connection Handle: 0x%03x",
                                                      tvb_get_letohs(tvb, offset), tvb_get_letohs(tvb, offset+2));
                sub_tree = proto_item_add_subtree(sub_item, ett_cis_params);
                proto_tree_add_item(sub_tree, hf_bthci_cmd_cis_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset+=2;
                proto_tree_add_item(sub_tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset+=2;
            }
            }
            break;

        case 0x0065: /* LE Remove CIG */
            proto_tree_add_item(tree, hf_bthci_cmd_cig_id, tvb, offset, 1, ENC_NA);
            offset++;
            break;

        case 0x0066: /* LE Accept CIS Request */
            proto_tree_add_item(tree, hf_bthci_cmd_cis_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            break;

        case 0x0068: /* LE Create BIG */
            proto_tree_add_item(tree, hf_bthci_cmd_big_handle, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_advertising_handle, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_num_bis, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_sdu_interval, tvb, offset, 3, ENC_LITTLE_ENDIAN);
            offset+=3;
            proto_tree_add_item(tree, hf_bthci_cmd_max_sdu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_max_transport_latency, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_rtn, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_bitmask(tree, tvb, offset, hf_bthci_cmd_phy, ett_phy_param, hfx_btcmd_le_phys, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_packing, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_framing, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_encryption, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_broadcast_code, tvb, offset, 16, ENC_NA);
            offset+=16;
            break;

        case 0x0069: /* LE Create BIG Test */
            proto_tree_add_item(tree, hf_bthci_cmd_big_handle, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_advertising_handle, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_num_bis, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_sdu_interval, tvb, offset, 3, ENC_LITTLE_ENDIAN);
            offset+=3;
            item = proto_tree_add_item(tree, hf_bthci_cmd_iso_interval, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g msec)", tvb_get_letohs(tvb, offset) * 1.25);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_nse, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_max_sdu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_max_pdu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_bitmask(tree, tvb, offset, hf_bthci_cmd_phy, ett_phy_param, hfx_btcmd_le_phys, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_packing, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_framing, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_bn, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_irc, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_pto, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_encryption, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_broadcast_code, tvb, offset, 16, ENC_NA);
            offset+=16;
            break;

        case 0x006A: /* LE Terminate BIG */
            proto_tree_add_item(tree, hf_bthci_cmd_big_handle, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_reason, tvb, offset, 1, ENC_NA);
            offset++;
            break;

        case 0x006B: /* LE BIG Create Sync */
            {
            guint8 num_bis;

            proto_tree_add_item(tree, hf_bthci_cmd_big_handle, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_sync_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_encryption, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_broadcast_code, tvb, offset, 16, ENC_NA);
            offset+=16;
            proto_tree_add_item(tree, hf_bthci_cmd_mse, tvb, offset, 1, ENC_NA);
            offset++;
            item = proto_tree_add_item(tree, hf_bthci_cmd_sync_timeout, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(item, " (%g sec)",  tvb_get_letohs(tvb, offset)*0.01);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_num_bis, tvb, offset, 1, ENC_NA);
            num_bis = tvb_get_guint8(tvb, offset);
            offset++;
            for (int i = 0; i < num_bis; i++) {
                proto_tree_add_item(tree, hf_bthci_cmd_bis_index, tvb, offset, 1, ENC_NA);
            offset++;
            }
            }
            break;

        case 0x006C: /* LE BIG Terminate Sync */
            proto_tree_add_item(tree, hf_bthci_cmd_big_handle, tvb, offset, 1, ENC_NA);
            offset++;
            break;

        case 0x006E: /* LE Setup ISO Data Path */
            {
            guint8 codec_length;
            const char *str = "Disabled";

            proto_tree_add_item(tree, hf_bthci_cmd_cis_bis_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_data_path_direction, tvb, offset, 1, ENC_NA);
            offset++;
            item = proto_tree_add_item(tree, hf_bthci_cmd_data_path_id, tvb, offset, 1, ENC_NA);
            if (tvb_get_guint8(tvb, offset) == 0)
                str = "HCI";
            else if (tvb_get_guint8(tvb, offset) < 0xff)
                str = "Logical Channel Number";
            proto_item_append_text(item, " (%s)", str);
            offset++;
            offset = dissect_coding_format(tree, hf_bthci_cmd_coding_format, tvb, offset, ett_coding_format);
            proto_tree_add_item(tree, hf_bthci_cmd_controller_delay, tvb, offset, 3, ENC_LITTLE_ENDIAN);
            offset+=3;
            codec_length = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(tree, hf_bthci_cmd_codec_config_length, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_codec_config, tvb, offset, codec_length, ENC_NA);
            offset += codec_length;
            }
            break;

        case 0x006F: /* LE Remove ISO Data Path */
            proto_tree_add_item(tree, hf_bthci_cmd_cis_bis_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_data_path_direction, tvb, offset, 1, ENC_NA);
            offset++;
            break;

        case 0x0070: /* LE ISO Transmit Test */
        case 0x0071: /* LE ISO Receive Test */
            proto_tree_add_item(tree, hf_bthci_cmd_cis_bis_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_payload_type, tvb, offset, 1, ENC_NA);
            offset++;
            break;

        case 0x0074: /* LE Set Host Feature */
            proto_tree_add_item(tree, hf_bthci_cmd_feature_bit_number, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_feature_bit_value, tvb, offset, 1, ENC_NA);
            offset++;
            break;

        case 0x0076: /* LE Enhanced Read Transmit Power Level */
        case 0x0077: /* LE Read Remote Transmit Power Level */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_phy_and_coding, tvb, offset, 1, ENC_NA);
            offset++;
            break;

        case 0x0078: /* LE Set Path Loss Reporting Parameters */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_high_threshold, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_high_hysteresis, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_low_threshold, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_low_hysteresis, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_min_time_spent, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            break;

        case 0x0079: /* LE Set Path Loss Reporting Enable */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_reporting_enable, tvb, offset, 1, ENC_NA);
            offset++;
            break;

        case 0x007A: /* LE Set Transmit Power Reporting Enable */
            proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_bthci_cmd_local_reporting_enable, tvb, offset, 1, ENC_NA);
            offset++;
            proto_tree_add_item(tree, hf_bthci_cmd_remote_reporting_enable, tvb, offset, 1, ENC_NA);
            offset++;
            break;

        case 0x0002: /* LE Read Buffer Size [v1] */
        case 0x0003: /* LE Read Local Supported Features */
        case 0x0007: /* LE Read Advertising Channel Tx Power */
        case 0x000E: /* LE Create Connection Cancel */
        case 0x000F: /* LE Read White List Size */
        case 0x0010: /* LE Clear White List */
        case 0x0018: /* LE Rand */
        case 0x001C: /* LE Read Supported States */
        case 0x001F: /* LE Test End */
        case 0x0023: /* LE Read Suggested Default Data Length */
        case 0x0025: /* LE Read Local P-256 Public Key */
        case 0x0029: /* LE Clear Resolving List */
        case 0x002A: /* LE Read Resolving List Size */
        case 0x002F: /* LE Read Maximum Data Length */
        case 0x003A: /* LE Read Maximum Advertising Data Length */
        case 0x003B: /* LE Read Number of Supported Advertising Sets */
        case 0x003D: /* LE Clear Advertising Sets */
        case 0x0045: /* LE Periodic Advertising Create Sync Cancel */
        case 0x0049: /* LE Clear Periodic Advertiser List */
        case 0x004A: /* LE Read Periodic Advertiser List Size */
        case 0x004B: /* LE Read Transmit Power */
        case 0x004C: /* LE Read RF Path Compensation */
        case 0x0058: /* LE Read Antenna Information */
        case 0x0060: /* LE Read Buffer Size [v2] */

            /* NOTE: No parameters */
            break;

        default:
            proto_tree_add_expert(tree, pinfo, &ei_command_unknown_command, tvb, offset, -1);
            offset += tvb_reported_length_remaining(tvb, offset);
    }

    return offset;
}

/* Code to actually dissect the packets */
static gint
dissect_bthci_cmd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item        *ti_cmd;
    proto_tree        *bthci_cmd_tree;
    guint32            opcode;
    guint16            ocf;
    guint8             param_length;
    guint8             ogf;
    gint               offset = 0;
    proto_item        *ti_opcode;
    proto_tree        *opcode_tree;
    gint               hfx;
    bluetooth_data_t  *bluetooth_data;
    guint32            interface_id;
    guint32            adapter_id;
    guint32            frame_number;
    wmem_tree_key_t    key[5];
    bthci_cmd_data_t  *bthci_cmd_data = NULL;
    proto_tree        *sub_item;
    wmem_tree_t       *subtree;


    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    bluetooth_data = (bluetooth_data_t *) data;

    interface_id = bluetooth_data->interface_id;
    adapter_id   = bluetooth_data->adapter_id;
    frame_number = pinfo->num;

    ti_cmd = proto_tree_add_item(tree, proto_bthci_cmd, tvb, offset, -1, ENC_NA);
    bthci_cmd_tree = proto_item_add_subtree(ti_cmd, ett_bthci_cmd);

    switch (pinfo->p2p_dir) {
        case P2P_DIR_SENT:
            col_set_str(pinfo->cinfo, COL_INFO, "Sent ");
            break;
        case P2P_DIR_RECV:
            col_set_str(pinfo->cinfo, COL_INFO, "Rcvd ");
            break;
        default:
            col_set_str(pinfo->cinfo, COL_INFO, "UnknownDirection ");
            break;
    }

    set_address(&pinfo->src,     AT_STRINGZ,  5, "host");
    set_address(&pinfo->dst,     AT_STRINGZ, 11, "controller");
    set_address(&pinfo->net_src, AT_STRINGZ,  5, "host");
    set_address(&pinfo->net_dst, AT_STRINGZ, 11, "controller");
    set_address(&pinfo->dl_src,  AT_STRINGZ,  5, "host");
    set_address(&pinfo->dl_dst,  AT_STRINGZ, 11, "controller");
    if (!pinfo->fd->visited) {
        address *addr;

        addr = (address *) wmem_memdup(wmem_file_scope(), &pinfo->dl_src, sizeof(address));
        addr->data =  wmem_memdup(wmem_file_scope(), pinfo->dl_src.data, pinfo->dl_src.len);
        p_add_proto_data(wmem_file_scope(), pinfo, proto_bluetooth, BLUETOOTH_DATA_SRC, addr);

        addr = (address *) wmem_memdup(wmem_file_scope(), &pinfo->dl_dst, sizeof(address));
        addr->data =  wmem_memdup(wmem_file_scope(), pinfo->dl_dst.data, pinfo->dl_dst.len);
        p_add_proto_data(wmem_file_scope(), pinfo, proto_bluetooth, BLUETOOTH_DATA_DST, addr);
    }

    opcode = tvb_get_letohs(tvb, offset);
    ocf = opcode & 0x03ff;
    ogf = (guint8) (opcode >> 10);

    if (ogf == HCI_OGF_VENDOR_SPECIFIC)
        proto_item_append_text(ti_cmd," - %s", val_to_str_ext(opcode, &bthci_cmd_opcode_vals_ext, "Vendor Command 0x%04x"));
    else
        proto_item_append_text(ti_cmd," - %s", val_to_str_ext(opcode, &bthci_cmd_opcode_vals_ext, "Unknown 0x%04x"));

    if (have_tap_listener(bluetooth_hci_summary_tap)) {
        bluetooth_hci_summary_tap_t  *tap_hci_summary;

        tap_hci_summary = wmem_new(wmem_packet_scope(), bluetooth_hci_summary_tap_t);

        tap_hci_summary->interface_id  = bluetooth_data->interface_id;
        tap_hci_summary->adapter_id    = bluetooth_data->adapter_id;

        tap_hci_summary->type = BLUETOOTH_HCI_SUMMARY_OPCODE;
        tap_hci_summary->ogf = ogf;
        tap_hci_summary->ocf = ocf;
        if (try_val_to_str_ext(opcode, &bthci_cmd_opcode_vals_ext))
            tap_hci_summary->name = val_to_str_ext(opcode, &bthci_cmd_opcode_vals_ext, "Unknown 0x%04x");
        else
            tap_hci_summary->name = NULL;
        tap_queue_packet(bluetooth_hci_summary_tap, pinfo, tap_hci_summary);
    }

    if (!pinfo->fd->visited) {
        bthci_cmd_data = (bthci_cmd_data_t *) wmem_new(wmem_file_scope(), bthci_cmd_data_t);
        bthci_cmd_data->opcode = opcode;
        bthci_cmd_data->command_in_frame = frame_number;
        bthci_cmd_data->command_abs_ts = pinfo->abs_ts;
        bthci_cmd_data->pending_in_frame = max_disconnect_in_frame;
        bthci_cmd_data->pending_abs_ts = pinfo->abs_ts;
        bthci_cmd_data->response_in_frame = max_disconnect_in_frame;
        bthci_cmd_data->response_abs_ts = pinfo->abs_ts;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HCI_CMD");

    ti_opcode = proto_tree_add_item(bthci_cmd_tree, hf_bthci_cmd_opcode, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    opcode_tree = proto_item_add_subtree(ti_opcode, ett_opcode);
    proto_tree_add_item(opcode_tree, hf_bthci_cmd_ogf, tvb, offset, 2, ENC_LITTLE_ENDIAN);

    if (ogf == HCI_OGF_LINK_CONTROL)
        hfx = hf_bthci_cmd_ocf_link_control;
    else if (ogf == HCI_OGF_LINK_POLICY)
        hfx = hf_bthci_cmd_ocf_link_policy;
    else if (ogf == HCI_OGF_HOST_CONTROLLER)
        hfx = hf_bthci_cmd_ocf_host_controller_and_baseband;
    else if (ogf == HCI_OGF_INFORMATIONAL)
        hfx = hf_bthci_cmd_ocf_informational;
    else if (ogf == HCI_OGF_STATUS)
        hfx = hf_bthci_cmd_ocf_status;
    else if (ogf == HCI_OGF_TESTING)
        hfx = hf_bthci_cmd_ocf_testing;
    else if (ogf == HCI_OGF_LOW_ENERGY)
        hfx = hf_bthci_cmd_ocf_low_energy;
    else if (ogf == HCI_OGF_LOGO_TESTING)
        hfx = hf_bthci_cmd_ocf_logo_testing;
    else
        hfx = hf_bthci_cmd_ocf;
    proto_tree_add_item(opcode_tree, hfx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset+=2;

    proto_tree_add_item(bthci_cmd_tree, hf_bthci_cmd_param_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    param_length = tvb_get_guint8(tvb, offset);
    offset++;

    if (ogf == HCI_OGF_VENDOR_SPECIFIC) {
        col_append_fstr(pinfo->cinfo, COL_INFO, "Vendor Command 0x%04X (opcode 0x%04X)", ocf, opcode);

        if (!dissector_try_payload_new(vendor_dissector_table, tvb, pinfo, tree, TRUE, bluetooth_data)) {
            if (bluetooth_data) {
                hci_vendor_data_t  *hci_vendor_data;

                key[0].length = 1;
                key[0].key    = &interface_id;
                key[1].length = 1;
                key[1].key    = &adapter_id;
                key[2].length = 0;
                key[2].key    = NULL;

                hci_vendor_data = (hci_vendor_data_t *) wmem_tree_lookup32_array(bluetooth_data->hci_vendors, key);
                if (hci_vendor_data) {
                    gint sub_offset;

                    sub_offset = dissector_try_uint_new(hci_vendor_table, hci_vendor_data->manufacturer, tvb, pinfo, tree, TRUE, bluetooth_data);

                    if (sub_offset > 0 && sub_offset < tvb_captured_length_remaining(tvb, offset))
                        proto_tree_add_expert(bthci_cmd_tree, pinfo, &ei_command_parameter_unexpected, tvb, offset + sub_offset, tvb_captured_length_remaining(tvb, sub_offset + offset));
                }
            }
        }

        proto_tree_add_item(bthci_cmd_tree, hf_bthci_cmd_parameter, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA);
    } else {
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_ext(opcode, &bthci_cmd_opcode_vals_ext, "Unknown 0x%04x"));

        if (param_length > 0) {
            switch (ogf) {
                case HCI_OGF_LINK_CONTROL:
                    offset = dissect_link_control_cmd(tvb, offset, pinfo, bthci_cmd_tree, ocf, bluetooth_data);
                    break;

                case HCI_OGF_LINK_POLICY:
                    offset = dissect_link_policy_cmd(tvb, offset, pinfo, bthci_cmd_tree, ocf, bluetooth_data);
                    break;

                case HCI_OGF_HOST_CONTROLLER:
                    offset = dissect_host_controller_baseband_cmd(tvb, offset, pinfo, bthci_cmd_tree, ocf, bluetooth_data, bthci_cmd_data);
                    break;

                case HCI_OGF_INFORMATIONAL:
                    offset = dissect_informational_parameters_cmd(tvb, offset, pinfo, bthci_cmd_tree, ocf);
                    break;

                case HCI_OGF_STATUS:
                    offset = dissect_status_parameters_cmd(tvb, offset, pinfo, bthci_cmd_tree, ocf);
                    break;

                case HCI_OGF_TESTING:
                    offset = dissect_testing_cmd(tvb, offset, pinfo, bthci_cmd_tree, ocf);
                    break;

                case HCI_OGF_LOW_ENERGY:
                    offset = dissect_le_cmd(tvb, offset, pinfo, bthci_cmd_tree, ocf, bluetooth_data);
                    break;
                default:
                    proto_tree_add_expert(bthci_cmd_tree, pinfo, &ei_command_unknown_command, tvb, 3, -1);
                    offset += tvb_reported_length_remaining(tvb, offset);
                    break;
            }
        }
    }

    if (!pinfo->fd->visited && bthci_cmd_data) {
        key[0].length = 1;
        key[0].key    = &interface_id;
        key[1].length = 1;
        key[1].key    = &adapter_id;
        key[2].length = 1;
        key[2].key    = &opcode;
        key[3].length = 1;
        key[3].key    = &frame_number;
        key[4].length = 0;
        key[4].key    = NULL;

        wmem_tree_insert32_array(bthci_cmds, key, bthci_cmd_data);
    }

    if (ogf != HCI_OGF_VENDOR_SPECIFIC && tvb_reported_length_remaining(tvb, offset) > 0) {
        proto_tree_add_expert(bthci_cmd_tree, pinfo, &ei_command_parameter_unexpected, tvb, offset, -1);
        offset += tvb_reported_length_remaining(tvb, offset);
    }

    key[0].length = 1;
    key[0].key    = &interface_id;
    key[1].length = 1;
    key[1].key    = &adapter_id;
    key[2].length = 1;
    key[2].key    = &opcode;
    key[3].length = 0;
    key[3].key    = NULL;

    subtree = (wmem_tree_t *) wmem_tree_lookup32_array(bthci_cmds, key);
    bthci_cmd_data = (subtree) ? (bthci_cmd_data_t *) wmem_tree_lookup32_le(subtree, pinfo->num) : NULL;
    if (bthci_cmd_data && bthci_cmd_data->pending_in_frame < max_disconnect_in_frame) {
        nstime_t  delta;

        sub_item = proto_tree_add_uint(bthci_cmd_tree, hf_pending_in_frame, tvb, 0, 0, bthci_cmd_data->pending_in_frame);
        proto_item_set_generated(sub_item);

        nstime_delta(&delta, &bthci_cmd_data->pending_abs_ts, &bthci_cmd_data->command_abs_ts);
        sub_item = proto_tree_add_double(bthci_cmd_tree, hf_command_pending_time_delta, tvb, 0, 0, nstime_to_msec(&delta));
        proto_item_set_generated(sub_item);
    }
    if (bthci_cmd_data && bthci_cmd_data->response_in_frame < max_disconnect_in_frame) {
        nstime_t  delta;

        sub_item = proto_tree_add_uint(bthci_cmd_tree, hf_response_in_frame, tvb, 0, 0, bthci_cmd_data->response_in_frame);
        proto_item_set_generated(sub_item);

        nstime_delta(&delta, &bthci_cmd_data->response_abs_ts, &bthci_cmd_data->command_abs_ts);
        sub_item = proto_tree_add_double(bthci_cmd_tree, hf_command_response_time_delta, tvb, 0, 0, nstime_to_msec(&delta));
        proto_item_set_generated(sub_item);
    }

    return offset;
}


/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
   */
void
proto_register_bthci_cmd(void)
{
    module_t         *module;
    expert_module_t  *expert_bthci_cmd;

    /* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_bthci_cmd_opcode,
          { "Command Opcode",               "bthci_cmd.opcode",
            FT_UINT16, BASE_HEX|BASE_EXT_STRING, &bthci_cmd_opcode_vals_ext, 0x0,
            "HCI Command Opcode", HFILL }
        },
        { &hf_bthci_cmd_ogf,
          { "Opcode Group Field",           "bthci_cmd.opcode.ogf",
            FT_UINT16, BASE_HEX|BASE_EXT_STRING, &bthci_cmd_ogf_vals_ext, 0xfc00,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_ocf_link_control,
          { "Opcode Command Field",           "bthci_cmd.opcode.ocf",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bthci_cmd_ocf_link_control_vals_ext, 0x03ff,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_ocf_link_policy,
          { "Opcode Command Field",           "bthci_cmd.opcode.ocf",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bthci_cmd_ocf_link_policy_vals_ext, 0x03ff,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_ocf_host_controller_and_baseband,
          { "Opcode Command Field",           "bthci_cmd.opcode.ocf",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bthci_cmd_ocf_host_controller_and_baseband_vals_ext, 0x03ff,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_ocf_informational,
          { "Opcode Command Field",           "bthci_cmd.opcode.ocf",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bthci_cmd_ocf_informational_vals_ext, 0x03ff,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_ocf_status,
          { "Opcode Command Field",           "bthci_cmd.opcode.ocf",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bthci_cmd_ocf_status_vals_ext, 0x03ff,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_ocf_testing,
          { "Opcode Command Field",           "bthci_cmd.opcode.ocf",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bthci_cmd_ocf_testing_vals_ext, 0x03ff,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_ocf_low_energy,
          { "Opcode Command Field",           "bthci_cmd.opcode.ocf",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bthci_cmd_ocf_low_energy_vals_ext, 0x03ff,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_ocf_logo_testing,
          { "Opcode Command Field",           "bthci_cmd.opcode.ocf",
            FT_UINT16, BASE_HEX, NULL, 0x03ff,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_ocf,
          { "Opcode Command Field",           "bthci_cmd.opcode.ocf",
            FT_UINT16, BASE_HEX, NULL, 0x03ff,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_param_length,
          { "Parameter Total Length",           "bthci_cmd.param_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_lap,
          { "LAP",           "bthci_cmd.lap",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            "LAP for the inquiry access code", HFILL }
        },
        { &hf_bthci_cmd_inq_length,
          { "Inquiry Length",           "bthci_cmd.inq_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Inquiry Length (*1.28s)", HFILL }
        },
        { &hf_bthci_cmd_num_responses,
          { "Num Responses",           "bthci_cmd.num_responses",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Number of Responses", HFILL }
        },
        { &hf_bthci_cmd_encrypt_mode,
          { "Encryption Mode",           "bthci_cmd.encrypt_mode",
            FT_UINT8, BASE_HEX, VALS(bthci_cmd_encrypt_mode_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_bd_addr,
          { "BD_ADDR",          "bthci_cmd.bd_addr",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            "Bluetooth Device Address", HFILL}
        },
        { &hf_bthci_cmd_packet_type,
          { "Packet Type",        "bthci_cmd.packet_type",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_packet_type_reserved_0,
          { "Reserved",        "bthci_cmd.packet_type.reserved.0",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_packet_type_2dh1,
          { "2-DH1",        "bthci_cmd.packet_type.2dh1",
            FT_BOOLEAN, 16, NULL, 0x0002,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_packet_type_3dh1,
          { "3-DH1",        "bthci_cmd.packet_type.3dh1",
            FT_BOOLEAN, 16, NULL, 0x0004,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_packet_type_dm1,
          { "DM1",        "bthci_cmd.packet_type.dm1",
            FT_BOOLEAN, 16, NULL, 0x0008,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_packet_type_dh1,
          { "DH1",        "bthci_cmd.packet_type.dh1",
            FT_BOOLEAN, 16, NULL, 0x0010,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_packet_type_reserved_5_7,
          { "Reserved",        "bthci_cmd.packet_type.reserved.5_7",
            FT_UINT16, BASE_HEX, NULL, 0x00E0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_packet_type_2dh3,
          { "2-DH3",        "bthci_cmd.packet_type.2dh3",
            FT_BOOLEAN, 16, NULL, 0x0100,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_packet_type_3dh3,
          { "3-DH3",        "bthci_cmd.packet_type.3dh3",
            FT_BOOLEAN, 16, NULL, 0x0200,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_packet_type_dm3,
          { "DM3",        "bthci_cmd.packet_type.dm3",
            FT_BOOLEAN, 16, NULL, 0x0400,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_packet_type_dh3,
          { "DH3",        "bthci_cmd.packet_type.dh3",
            FT_BOOLEAN, 16, NULL, 0x0800,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_packet_type_2dh5,
          { "2-DH5",        "bthci_cmd.packet_type.2dh5",
            FT_BOOLEAN, 16, NULL, 0x1000,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_packet_type_3dh5,
          { "3-DH5",        "bthci_cmd.packet_type.3dh5",
            FT_BOOLEAN, 16, NULL, 0x2000,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_packet_type_dm5,
          { "DM5",        "bthci_cmd.packet_type.dm5",
            FT_BOOLEAN, 16, NULL, 0x4000,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_packet_type_dh5,
          { "DH5",        "bthci_cmd.packet_type.dh5",
            FT_BOOLEAN, 16, NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_page_scan_mode,
          { "Page Scan Mode",        "bthci_cmd.page_scan_mode",
            FT_UINT8, BASE_HEX, VALS(bthci_cmd_page_scan_modes), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_page_scan_repetition_mode,
          { "Page Scan Repetition Mode",        "bthci_cmd.page_scan_repetition_mode",
            FT_UINT8, BASE_HEX, VALS(bthci_cmd_page_scan_repetition_modes), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_page_scan_period_mode,
          { "Page Scan Period Mode",        "bthci_cmd.page_scan_period_mode",
            FT_UINT8, BASE_HEX, VALS(bthci_cmd_page_scan_period_modes), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_clock_offset,
          { "Clock Offset",        "bthci_cmd.clock_offset",
            FT_UINT16, BASE_HEX, NULL, 0x7FFF,
            "Bit 2-16 of the Clock Offset between CLKmaster-CLKslave", HFILL }
        },
        { &hf_bthci_cmd_clock_offset_valid,
          { "Clock_Offset_Valid_Flag",     "bthci_cmd.clock_offset_valid",
            FT_UINT16, BASE_DEC, VALS(cmd_boolean), 0x8000,
            "Indicates if clock offset is valid", HFILL }
        },
        { &hf_bthci_cmd_allow_role_switch,
          { "Allow Role Switch",         "bthci_cmd.allow_role_switch",
            FT_UINT8, BASE_HEX, VALS(cmd_role_switch_modes), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_max_period_length,
          { "Max Period Length",           "bthci_cmd.max_period_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Maximum amount of time specified between consecutive inquiries.", HFILL }
        },
        { &hf_bthci_cmd_min_period_length,
          { "Min Period Length",           "bthci_cmd.min_period_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Minimum amount of time specified between consecutive inquiries.", HFILL }
        },
        { &hf_bthci_cmd_connection_handle,
          { "Connection Handle",             "bthci_cmd.connection_handle",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_reason,
          { "Reason",           "bthci_cmd.reason",
            FT_UINT8, BASE_HEX|BASE_EXT_STRING, &bthci_cmd_status_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_num_link_keys,
          { "Number of Link Keys", "bthci_cmd.num_link_keys",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_link_key,
          { "Link Key",        "bthci_cmd.link_key",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Link Key for the associated BD_ADDR", HFILL }
        },
        { &hf_bthci_cmd_packet_type_hv1,
          { "Packet Type HV1",        "bthci_cmd.packet_type_hv1",
            FT_UINT16, BASE_DEC, VALS(cmd_boolean), 0x0020,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_packet_type_hv2,
          { "Packet Type HV2",        "bthci_cmd.packet_type_hv2",
            FT_UINT16, BASE_DEC, VALS(cmd_boolean), 0x0040,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_packet_type_hv3,
          { "Packet Type HV3",        "bthci_cmd.packet_type_hv3",
            FT_UINT16, BASE_DEC, VALS(cmd_boolean), 0x0080,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_role,
          { "Role",        "bthci_cmd.role",
            FT_UINT8, BASE_HEX, VALS(cmd_role_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_acr_role,
          { "Role",        "bthci_cmd.acr.role",
            FT_UINT8, BASE_HEX, VALS(cmd_acr_role_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_pin_code_length,
          { "PIN Code Length",        "bthci_cmd.pin_code_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_pin_code,
          { "PIN Code",        "bthci_cmd.pin_code",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_pin_type,
          { "PIN Type", "bthci_cmd.pin_type",
            FT_UINT8, BASE_HEX, VALS(cmd_pin_types), 0x0,
            "PIN Types", HFILL }
        },
        { &hf_bthci_cmd_encryption_enable,
          { "Encryption Enable",        "bthci_cmd.encryption_enable",
            FT_UINT8, BASE_HEX, VALS(cmd_encryption_enable), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_key_flag,
          { "Key Flag",        "bthci_cmd.key_flag",
            FT_UINT8, BASE_HEX, VALS(cmd_key_flag), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_max_interval_hold,
          { "Hold Mode Max Interval",        "bthci_cmd.hold_mode_max_int",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Maximal acceptable number of Baseband slots to wait in Hold Mode.", HFILL }
        },
        { &hf_bthci_cmd_min_interval_hold,
          { "Hold Mode Min Interval",        "bthci_cmd.hold_mode_min_int",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Minimum acceptable number of Baseband slots to wait in Hold Mode.", HFILL }
        },
        { &hf_bthci_cmd_max_interval_sniff,
          { "Sniff Max Interval",        "bthci_cmd.sniff_max_int",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Maximal acceptable number of Baseband slots between each sniff period.", HFILL }
        },
        { &hf_bthci_cmd_min_interval_sniff,
          { "Sniff Min Interval",        "bthci_cmd.sniff_min_int",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Minimum acceptable number of Baseband slots between each sniff period.", HFILL }
        },
        { &hf_bthci_cmd_sniff_attempt,
          { "Sniff Attempt",        "bthci_cmd.sniff_attempt",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Number of Baseband receive slots for sniff attempt.", HFILL }
        },
        { &hf_bthci_cmd_timeout,
          { "Timeout",        "bthci_cmd.timeout",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Number of Baseband slots for timeout.", HFILL }
        },
        { &hf_bthci_cmd_max_interval_beacon,
          { "Beacon Max Interval",        "bthci_cmd.beacon_max_int",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Maximal acceptable number of Baseband slots between consecutive beacons.", HFILL }
        },
        { &hf_bthci_cmd_min_interval_beacon,
          { "Beacon Min Interval",        "bthci_cmd.beacon_min_int",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Minimum acceptable number of Baseband slots between consecutive beacons.", HFILL }
        },
        { &hf_bthci_cmd_flags,
          { "Flags",        "bthci_cmd.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_flow_direction,
          { "Flow Direction",        "bthci_cmd.flow_direction",
            FT_UINT8, BASE_HEX, VALS(cmd_flow_directions), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_service_type,
          { "Service Type",        "bthci_cmd.service_type",
            FT_UINT8, BASE_HEX, VALS(cmd_service_types), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_token_rate,
          { "Available Token Rate",        "bthci_cmd.token_rate",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Token Rate, in bytes per second", HFILL }
        },
        { &hf_bthci_cmd_token_bucket_size,
          { "Available Token Bucket Size",        "bthci_cmd.token_bucket_size",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Token Bucket Size in bytes", HFILL }
        },
        { &hf_bthci_cmd_peak_bandwidth,
          { "Peak Bandwidth",        "bthci_cmd.peak_bandwidth",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Peak Bandwidth, in bytes per second", HFILL }
        },
        { &hf_bthci_cmd_latency,
          { "Latency",        "bthci_cmd.latency",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Latency, in microseconds", HFILL }
        },
        { &hf_bthci_cmd_delay_variation,
          { "Delay Variation",        "bthci_cmd.delay_variation",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Delay Variation, in microseconds", HFILL }
        },
        { &hf_bthci_cmd_link_policy_setting_switch,
          { "Enable Master Slave Switch", "bthci_cmd.link_policy_switch",
            FT_UINT16, BASE_DEC, VALS(cmd_boolean), 0x0001,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_link_policy_setting_hold,
          { "Enable Hold Mode", "bthci_cmd.link_policy_hold",
            FT_UINT16, BASE_DEC, VALS(cmd_boolean), 0x0002,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_link_policy_setting_sniff,
          { "Enable Sniff Mode", "bthci_cmd.link_policy_sniff",
            FT_UINT16, BASE_DEC, VALS(cmd_boolean), 0x0004,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_link_policy_setting_park,
          { "Enable Park Mode", "bthci_cmd.link_policy_park",
            FT_UINT16, BASE_DEC, VALS(cmd_boolean), 0x0008,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_filter_type,
          { "Filter Type", "bthci_cmd.filter_type",
            FT_UINT8, BASE_HEX, VALS(cmd_filter_types), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_inquiry_result_filter_condition_type,
          { "Filter Condition Type", "bthci_cmd.filter_condition_type",
            FT_UINT8, BASE_HEX, VALS(cmd_inquiry_result_filter_condition_types), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_connection_setup_filter_condition_type,
          { "Filter Condition Type", "bthci_cmd.filter_condition_type",
            FT_UINT8, BASE_HEX, VALS(cmd_connection_setup_filter_condition_types), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_cod_class_of_device_mask,
          { "Class of Device Mask", "bthci_cmd.class_of_device_mask",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            "Bit Mask used to determine which bits of the Class of Device parameter are of interest.", HFILL }
        },
        { &hf_bthci_cmd_cod_major_device_class_mask,
          { "Major Device Class Mask", "bthci_cmd.class_of_device_mask.major_device_class",
            FT_UINT16, BASE_HEX, NULL, 0x1F,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_cod_major_service_class_information_mask,
          { "Major Service Classes Mask: Information", "bthci_cmd.class_of_device_mask.major_service_classes.information",
            FT_BOOLEAN, 16, NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_cod_major_service_class_telephony_mask,
          { "Major Service Classes Mask: Telephony", "bthci_cmd.class_of_device_mask.major_service_classes.telephony",
            FT_BOOLEAN, 16, NULL, 0x4000,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_cod_major_service_class_audio_mask,
          { "Major Service Classes Mask: Audio", "bthci_cmd.class_of_device_mask.major_service_classes.audio",
            FT_BOOLEAN, 16, NULL, 0x2000,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_cod_major_service_class_object_transfer_mask,
          { "Major Service Classes Mask: Object Transfer", "bthci_cmd.class_of_device_mask.major_service_classes.object_transfer",
            FT_BOOLEAN, 16, NULL, 0x1000,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_cod_major_service_class_capturing_mask,
          { "Major Service Classes Mask: Capturing", "bthci_cmd.class_of_device_mask.major_service_classes.capturing",
            FT_BOOLEAN, 16, NULL, 0x0800,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_cod_major_service_class_rendering_mask,
          { "Major Service Classes Mask: Rendering", "bthci_cmd.class_of_device_mask.major_service_classes.rendering",
            FT_BOOLEAN, 16, NULL, 0x0400,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_cod_major_service_class_networking_mask,
          { "Major Service Classes Mask: Networking", "bthci_cmd.class_of_device_mask.major_service_classes.networking",
            FT_BOOLEAN, 16, NULL, 0x0200,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_cod_major_service_class_positioning_mask,
          { "Major Service Classes Mask: Positioning", "bthci_cmd.class_of_device_mask.major_service_classes.positioning",
            FT_BOOLEAN, 16, NULL, 0x0100,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_cod_major_service_class_reserved_mask,
          { "Major Service Classes Mask: Reserved", "bthci_cmd.class_of_device_mask.major_service_classes.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x00C0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_cod_major_service_class_limited_discoverable_mode_mask,
          { "Major Service Classes Mask: Limited Discoverable Mode", "bthci_cmd.class_of_device_mask.major_service_classes.limited_discoverable_mode",
            FT_BOOLEAN, 16, NULL, 0x0020,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_cod_minor_device_class_mask,
          { "Minor Device Class Mask", "bthci_cmd.class_of_device_mask.minor_device_class",
            FT_UINT8, BASE_HEX, NULL, 0xFC,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_cod_format_type_mask,
          { "Format Type Mask", "bthci_cmd.class_of_device_mask.format_type",
            FT_UINT8, BASE_HEX, NULL, 0x03,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_auto_acc_flag,
          { "Auto Accept Flag", "bthci_cmd.auto_accept_flag",
            FT_UINT8, BASE_HEX, VALS(cmd_auto_acc_flag_values), 0x0,
            "Class of Device of Interest", HFILL }
        },
        { &hf_bthci_cmd_read_all_flag,
          { "Read All Flag", "bthci_cmd.read_all_flag",
            FT_UINT8, BASE_HEX, VALS(cmd_read_all_flag_values), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_delete_all_flag,
          { "Delete All Flag", "bthci_cmd.delete_all_flag",
            FT_UINT8, BASE_HEX, VALS(cmd_delete_all_flag_values), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_authentication_enable,
          { "Authentication Enable", "bthci_cmd.auth_enable",
            FT_UINT8, BASE_HEX, VALS(bthci_cmd_authentication_enable_values), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_input_unused,
          { "Unused bits", "bthci_cmd.voice.unused",
            FT_UINT16, BASE_HEX, NULL, 0xfc00,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_input_coding,
          { "Input Coding", "bthci_cmd.voice.input_coding",
            FT_UINT16, BASE_DEC, VALS(cmd_input_coding_values), 0x0300,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_input_data_format,
          { "Input Data Format", "bthci_cmd.voice.input_data_format",
            FT_UINT16, BASE_DEC, VALS(cmd_input_data_format_values), 0x00c0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_input_sample_size,
          { "Input Sample Size", "bthci_cmd.voice.input_sample_size",
            FT_UINT16, BASE_DEC, VALS(cmd_input_sample_size_values), 0x0020,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_linear_pcm_bit_pos,
          { "Linear PCM Bit Position", "bthci_cmd.voice.linear_pcm_bit_pos",
            FT_UINT16, BASE_DEC, NULL, 0x001c,
            "# bit pos. that MSB of sample is away from starting at MSB", HFILL }
        },
        { &hf_bthci_cmd_air_coding_format,
          { "Air Coding Format", "bthci_cmd.voice.air_coding_format",
            FT_UINT16, BASE_DEC, VALS(cmd_air_coding_format_values), 0x0003,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_num_broadcast_retransmissions,
          { "Num Broadcast Retran", "bthci_cmd.num_broad_retran",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Number of Broadcast Retransmissions", HFILL }
        },
        { &hf_bthci_cmd_hold_mode_act_page,
          { "Suspend Page Scan", "bthci_cmd.hold_mode_page",
            FT_UINT8, BASE_DEC, VALS(cmd_boolean), 0x1,
            "Device can enter low power state", HFILL }
        },
        { &hf_bthci_cmd_hold_mode_act_inquiry,
          { "Suspend Inquiry Scan", "bthci_cmd.hold_mode_inquiry",
            FT_UINT8, BASE_DEC, VALS(cmd_boolean), 0x2,
            "Device can enter low power state", HFILL }
        },
        { &hf_bthci_cmd_hold_mode_act_periodic,
          { "Suspend Periodic Inquiries", "bthci_cmd.hold_mode_periodic",
            FT_UINT8, BASE_DEC, VALS(cmd_boolean), 0x4,
            "Device can enter low power state", HFILL }
        },
        { &hf_bthci_cmd_scan_enable,
          { "Scan Enable", "bthci_cmd.scan_enable",
            FT_UINT8, BASE_HEX, VALS(bthci_cmd_scan_enable_values), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_interval,
          { "Interval", "bthci_cmd.interval",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_window,
          { "Window", "bthci_cmd.window",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_device_name,
          { "Device Name",           "bthci_cmd.device_name",
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            "Userfriendly descriptive name for the device", HFILL }
        },
        { &hf_bthci_cmd_num_curr_iac,
          { "Number of Current IAC", "bthci_cmd.num_curr_iac",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Number of IACs which are currently in use", HFILL }
        },
        { &hf_bthci_cmd_iac_lap,
          { "IAC LAP", "bthci_cmd.num_curr_iac",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            "LAP(s)used to create IAC", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_00,
          { "Inquiry Complete", "bthci_cmd.evt_mask_00",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x01,
            "Inquiry Complete Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_01,
          { "Inquiry Result", "bthci_cmd.evt_mask_01",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x02,
            "Inquiry Result Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_02,
          { "Connect Complete", "bthci_cmd.evt_mask_02",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x04,
            "Connection Complete Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_03,
          { "Connect Request", "bthci_cmd.evt_mask_03",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x08,
            "Connect Request Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_04,
          { "Disconnect Complete", "bthci_cmd.evt_mask_04",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x10,
            "Disconnect Complete Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_05,
          { "Auth Complete", "bthci_cmd.evt_mask_05",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x20,
            "Auth Complete Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_06,
          { "Remote Name Req Complete", "bthci_cmd.evt_mask_06",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x40,
            "Remote Name Req Complete Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_07,
          { "Encrypt Change", "bthci_cmd.evt_mask_07",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x80,
            "Encrypt Change Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_10,
          { "Change Connection Link Key Complete", "bthci_cmd.evt_mask_10",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x01,
            "Change Connection Link Key Complete Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_11,
          { "Master Link Key Complete", "bthci_cmd.evt_mask_11",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x02,
            "Master Link Key Complete Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_12,
          { "Read Remote Supported Features", "bthci_cmd.evt_mask_12",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x04,
            "Read Remote Supported Features Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_13,
          { "Read Remote Ver Info Complete", "bthci_cmd.evt_mask_13",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x08,
            "Read Remote Ver Info Complete Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_14,
          { "QoS Setup Complete", "bthci_cmd.evt_mask_14",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x10,
            "QoS Setup Complete Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_17,
          { "Hardware Error", "bthci_cmd.evt_mask_17",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x80,
            "Hardware Error Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_20,
          { "Flush Occurred", "bthci_cmd.evt_mask_20",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x01,
            "Flush Occurred Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_21,
          { "Role Change", "bthci_cmd.evt_mask_21",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x02,
            "Role Change Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_23,
          { "Mode Change", "bthci_cmd.evt_mask_23",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x08,
            "Mode Change Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_24,
          { "Return Link Keys", "bthci_cmd.evt_mask_24",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x10,
            "Return Link Keys Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_25,
          { "PIN Code Request", "bthci_cmd.evt_mask_25",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x20,
            "PIN Code Request Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_26,
          { "Link Key Request", "bthci_cmd.evt_mask_26",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x40,
            "Link Key Request Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_27,
          { "Link Key Notification", "bthci_cmd.evt_mask_27",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x80,
            "Link Key Notification Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_30,
          { "Loopback Command", "bthci_cmd.evt_mask_30",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x01,
            "Loopback Command Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_31,
          { "Data Buffer Overflow" , "bthci_cmd.evt_mask_31",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x02,
            "Data Buffer Overflow Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_32,
          { "Max Slots Change", "bthci_cmd.evt_mask_32",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x04,
            "Max Slots Change Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_33,
          { "Read Clock Offset Complete", "bthci_cmd.evt_mask_33",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x08,
            "Read Clock Offset Complete Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_34,
          { "Connection Packet Type Changed", "bthci_cmd.evt_mask_34",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x10,
            "Connection Packet Type Changed Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_35,
          { "QoS Violation", "bthci_cmd.evt_mask_35",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x20,
            "QoS Violation Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_36,
          { "Page Scan Mode Change", "bthci_cmd.evt_mask_36",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x40,
            "Page Scan Mode Change Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_37,
          { "Page Scan Repetition Mode Change", "bthci_cmd.evt_mask_37",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x80,
            "Page Scan Repetition Mode Change Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_40,
          { "Flow Specification Complete", "bthci_cmd.evt_mask_40",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x01,
            "Flow Specification Complete Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_41,
          { "Inquiry Result With RSSI", "bthci_cmd.evt_mask_41",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x02,
            "Inquiry Result With RSSI Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_42,
          { "Read Remote Ext. Features Complete", "bthci_cmd.evt_mask_42",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x04,
            "Read Remote Ext. Features Complete Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_53,
          { "Synchronous Connection Complete", "bthci_cmd.evt_mask_53",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x08,
            "Synchronous Connection Complete Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_54,
          { "Synchronous Connection Changed", "bthci_cmd.evt_mask_54",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x10,
            "Synchronous Connection Changed Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_55,
          { "Sniff Subrate", "bthci_cmd.evt_mask_55",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x20,
            "Sniff Subrate Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_56,
          { "Extended Inquiry Result", "bthci_cmd.evt_mask_56",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x40,
            "Extended Inquiry Result Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_57,
          { "Encryption Key Refresh Complete", "bthci_cmd.evt_mask_57",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x80,
            "Encryption Key Refresh Complete Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_60,
          { "IO Capability Request", "bthci_cmd.evt_mask_60",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x01,
            "IO Capability Request Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_61,
          { "IO Capability Response", "bthci_cmd.evt_mask_61",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x02,
            "IO Capability Response Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_62,
          { "User Confirmation Request", "bthci_cmd.evt_mask_62",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x04,
            "User Confirmation Request Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_63,
          { "User Passkey Request", "bthci_cmd.evt_mask_63",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x08,
            "User Passkey Request Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_64,
          { "Remote OOB Data Request", "bthci_cmd.evt_mask_64",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x10,
            "Remote OOB Data Request Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_65,
          { "Simple Pairing Complete", "bthci_cmd.evt_mask_65",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x20,
            "Simple Pairing Complete Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_67,
          { "Link Supervision Timeout Changed", "bthci_cmd.evt_mask_67",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x80,
            "Link Supervision Timeout Changed Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_70,
          { "Enhanced Flush Complete", "bthci_cmd.evt_mask_70",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x01,
            "Enhanced Flush Complete Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_72,
          { "User Passkey Notification", "bthci_cmd.evt_mask_72",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x04,
            "User Passkey Notification Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask_73,
          { "Keypress Notification", "bthci_cmd.evt_mask_73",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x08,
            "Keypress Notification Bit", HFILL }
        },
        { &hf_bthci_cmd_sco_flow_control,
          { "SCO Flow Control","bthci_cmd.flow_control",
            FT_UINT8, BASE_HEX, VALS(cmd_en_disabled), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_num_handles,
          { "Number of Connection Handles", "bthci_cmd.num_handles",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_bthci_cmd_num_compl_packets,
          { "Number of Completed Packets", "bthci_cmd.num_compl_packets",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Number of Completed HCI Data Packets", HFILL }
        },
        { &hf_bthci_cmd_flow_contr_enable,
          { "Flow Control Enable", "bthci_cmd.flow_contr_enable",
            FT_UINT8, BASE_HEX, VALS(cmd_flow_contr_enable), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_host_data_packet_length_acl,
          {"Host ACL Data Packet Length (bytes)", "bthci_cmd.max_data_length_acl",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           "Max Host ACL Data Packet length of data portion host is able to accept", HFILL }
        },
        { &hf_bthci_cmd_host_data_packet_length_sco,
          {"Host SCO Data Packet Length (bytes)", "bthci_cmd.max_data_length_sco",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           "Max Host SCO Data Packet length of data portion host is able to accept", HFILL }
        },
        { &hf_bthci_cmd_host_total_num_acl_data_packets,
          {"Host Total Num ACL Data Packets", "bthci_cmd.max_data_num_acl",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           "Total Number of HCI ACL Data Packets that can be stored in the data buffers of the Host", HFILL }
        },
        { &hf_bthci_cmd_host_total_num_sco_data_packets,
          {"Host Total Num SCO Data Packets", "bthci_cmd.max_data_num_sco",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           "Total Number of HCI SCO Data Packets that can be stored in the data buffers of the Host", HFILL }
        },
        { &hf_bthci_cmd_loopback_mode,
          {"Loopback Mode", "bthci_cmd.loopback_mode",
           FT_UINT8, BASE_HEX, VALS(cmd_loopback_modes), 0x0,
           NULL, HFILL}
        },
        { &hf_bthci_cmd_page_number,
          {"Page Number", "bthci_cmd.page_number",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_bthci_cmd_transmit_bandwidth,
          {"Tx Bandwidth (bytes/s)", "bthci_cmd.tx_bandwidth",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           "Tx Bandwidth", HFILL}
        },
        { &hf_bthci_cmd_receive_bandwidth,
          {"Rx Bandwidth (bytes/s)", "bthci_cmd.rx_bandwidth",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           "Rx Bandwidth", HFILL}
        },
        { &hf_bthci_cmd_max_latency_ms,
          {"Max. Latency (ms)", "bthci_cmd.max_latency_ms",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_bthci_cmd_max_latency,
          {"Max. Latency", "bthci_cmd.max_latency",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           "Max. Latency in baseband slots", HFILL}
        },
        { &hf_bthci_cmd_retransmission_effort,
          {"Retransmission Effort", "bthci_cmd.retransmission_effort",
           FT_UINT8, BASE_DEC, VALS(cmd_rtx_effort), 0x0,
           NULL, HFILL}
        },
        { &hf_bthci_cmd_scan_type,
          {"Scan Type", "bthci_cmd.inq_scan_type",
           FT_UINT8, BASE_DEC, VALS(cmd_scan_types), 0x0,
           NULL, HFILL}
        },
        { &hf_bthci_cmd_inq_mode,
          {"Inquiry Mode", "bthci_cmd.inq_scan_type",
           FT_UINT8, BASE_DEC, VALS(bthci_cmd_inq_modes), 0x0,
           NULL, HFILL}
        },
        { &hf_bthci_cmd_fec_required,
          {"FEC Required", "bthci_cmd.fec_required",
           FT_UINT8, BASE_DEC, VALS(cmd_boolean), 0x0,
           NULL, HFILL}
        },
        { &hf_bthci_cmd_err_data_reporting,
          {"Erroneous Data Reporting", "bthci_cmd.err_data_reporting",
           FT_UINT8, BASE_DEC, VALS(cmd_en_disabled), 0x0,
           NULL, HFILL}
        },
        { &hf_bthci_cmd_tx_power,
          {"Power Level (dBm)", "bthci_cmd.power_level",
           FT_INT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_bthci_cmd_sco_packet_type,
          { "Packet Type", "bthci_cmd.sco_packet_type",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_sco_packet_type_hv1,
          { "HV1 may be used",        "bthci_cmd.sco_packet_type.hv1",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_sco_packet_type_hv2,
          { "HV2 may be used",        "bthci_cmd.sco_packet_type.hv2",
            FT_BOOLEAN, 16, NULL, 0x0002,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_sco_packet_type_hv3,
          { "HV3 may be used",        "bthci_cmd.sco_packet_type.hv3",
            FT_BOOLEAN, 16, NULL, 0x0004,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_sco_packet_type_ev3,
          { "EV3 may be used",        "bthci_cmd.sco_packet_type.ev3",
            FT_BOOLEAN, 16, NULL, 0x0008,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_sco_packet_type_ev4,
          { "EV4 may be used",        "bthci_cmd.sco_packet_type.ev4",
            FT_BOOLEAN, 16, NULL, 0x0010,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_sco_packet_type_ev5,
          { "EV5 may be used",        "bthci_cmd.sco_packet_type.ev5",
            FT_BOOLEAN, 16, NULL, 0x0020,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_sco_packet_type_2ev3,
          { "2-EV3 may NOT be used",        "bthci_cmd.sco_packet_type.2ev3",
            FT_BOOLEAN, 16, NULL, 0x0040,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_sco_packet_type_3ev3,
          { "3-EV3 may NOT be used",        "bthci_cmd.sco_packet_type.3ev3",
            FT_BOOLEAN, 16, NULL, 0x0080,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_sco_packet_type_2ev5,
          { "2-EV5 may NOT be used",        "bthci_cmd.sco_packet_type.2ev5",
            FT_BOOLEAN, 16, NULL, 0x0100,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_sco_packet_type_3ev5,
          { "3-EV5 may NOT be used",        "bthci_cmd.sco_packet_type.3ev5",
            FT_BOOLEAN, 16, NULL, 0x0200,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_sco_packet_type_reserved,
          { "Reserved",        "bthci_cmd.sco_packet_type.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xFC00,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_min_remote_timeout,
          {"Min. Remote Timeout", "bthci_cmd.min_remote_timeout",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           "Min. Remote Timeout in baseband slots", HFILL}
        },
        { &hf_bthci_cmd_min_local_timeout,
          {"Min. Local Timeout", "bthci_cmd.min_local_timeout",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           "Min. Local Timeout in baseband slots", HFILL}
        },
        { &hf_bthci_cmd_flush_packet_type,
          {"Packet Type", "bthci_cmd.flush_packet_type",
           FT_UINT8, BASE_DEC, VALS(cmd_flush_pkt_type), 0x0,
           NULL, HFILL}
        },
        { &hf_bthci_cmd_afh_ch_assessment_mode,
          {"AFH Channel Assessment Mode", "bthci_cmd.afh_ch_assessment_mode",
           FT_UINT8, BASE_DEC, VALS(cmd_en_disabled), 0x0,
           NULL, HFILL}
        },
        { &hf_bthci_cmd_afh_ch_classification,
          { "Channel Classification",           "bthci_cmd.afh_ch_classification",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_which_clock,
          {"Which Clock", "bthci_cmd.which_clock",
           FT_UINT8, BASE_DEC, VALS(cmd_which_clock), 0x0,
           NULL, HFILL}
        },
        { &hf_bthci_cmd_io_capability,
          {"IO Capability", "bthci_cmd.io_capability",
           FT_UINT8, BASE_DEC, VALS(bthci_cmd_io_capability_vals), 0x0,
           NULL, HFILL}
        },
        { &hf_bthci_cmd_oob_data_present,
          {"OOB Data Present", "bthci_cmd.oob_data_present",
           FT_UINT8, BASE_DEC, VALS(bthci_cmd_oob_data_present_vals), 0x0,
           NULL, HFILL}
        },
        { &hf_bthci_cmd_auth_requirements,
          {"Authentication Requirements", "bthci_cmd.auth_requirements",
           FT_UINT8, BASE_DEC|BASE_EXT_STRING, &bthci_cmd_auth_req_vals_ext, 0x0,
           NULL, HFILL}
        },
        { &hf_bthci_cmd_passkey,
          {"Passkey", "bthci_cmd.passkey",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_bthci_cmd_hash_c,
          {"Hash C", "bthci_cmd.hash_c",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_bthci_cmd_randomizer_r,
          {"Randomizer R", "bthci_cmd.randomizer_r",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_bthci_cmd_simple_pairing_mode,
          {"Simple Pairing Mode", "bthci_cmd.simple_pairing_mode",
           FT_UINT8, BASE_DEC, VALS(cmd_en_disabled), 0x0,
           NULL, HFILL}
        },
        { &hf_bthci_cmd_simple_pairing_debug_mode,
          {"Simple Pairing Debug Mode", "bthci_cmd.simple_pairing_debug_mode",
           FT_UINT8, BASE_DEC, VALS(cmd_en_disabled), 0x0,
           NULL, HFILL}
        },
        { &hf_bthci_cmd_notification_type,
          {"Notification Type", "bthci_cmd.notification_type",
           FT_UINT8, BASE_DEC, VALS(bthci_cmd_notification_types), 0x0,
           NULL, HFILL}
        },
        { &hf_bthci_cmd_physical_link_handle,
          {"Physical Link Handle", "bthci_cmd.physical_link_handle",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_bthci_cmd_dedicated_amp_key_length,
          {"Dedicated AMP Key Length", "bthci_cmd.dedicated_amp_key_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_bthci_cmd_dedicated_amp_key_type,
          {"Dedicated AMP Key Type", "bthci_cmd.dedicated_amp_key_type",
            FT_UINT8, BASE_DEC, VALS(bthci_cmd_amp_key_type), 0x0,
            NULL, HFILL}
        },
        { &hf_bthci_cmd_dedicated_amp_key,
          {"Dedicated AMP Key Type", "bthci_cmd.dedicated_amp_key",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_bthci_cmd_flow_spec,
          { "Flow Spec", "bthci_cmd.flow_spec",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_flow_spec_sdu_size,
          { "Maximum SDU Size", "bthci_cmd.sdu_size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_flow_spec_sdu_arrival_time,
          { "SDU Inter-arrival Time (us)", "bthci_cmd.sdu_arrival_time",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_flow_spec_identifier,
          { "Identifier", "bthci_cmd.ident",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_flow_spec_access_latency,
          { "Access Latency (us)", "bthci_cmd.access_latency",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_flow_spec_service_type,
          { "Service Type", "bthci_cmd.servicetype",
            FT_UINT8, BASE_HEX, VALS(cmd_flow_spec_servicetype), 0x0,
            "Level of service required", HFILL }
        },
        { &hf_bthci_cmd_flush_to_us,
          { "Flush Timeout (us)", "bthci_cmd.flushto",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_logical_link_handle,
          { "Logical Link Handle", "bthci_cmd.logical_link_handle",
            FT_UINT16, BASE_HEX, NULL, 0x0FFF,
            NULL, HFILL }
        },

        { &hf_bthci_cmd_evt_mask2_00,
          { "Physical Link Complete", "bthci_cmd.evt_mask2_00",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x01,
            "Physical Link Complete Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask2_01,
          { "Channel Selected", "bthci_cmd.evt_mask2_01",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x02,
            "Channel Selected Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask2_02,
          { "Disconnection Physical Link", "bthci_cmd.evt_mask2_02",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x04,
            "Disconnection Physical Link Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask2_03,
         { "Physical Link Loss Early Warning", "bthci_cmd.evt_mask2_03",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x08,
            "Physical Link Loss Early Warning Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask2_04,
          { "Physical Link Recovery", "bthci_cmd.evt_mask2_04",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x10,
            "Physical Link Recovery Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask2_05,
          { "Logical Link Complete", "bthci_cmd.evt_mask2_05",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x20,
            "Logical Link Complete Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask2_06,
          { "Disconnection Logical Link Complete", "bthci_cmd.evt_mask2_06",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x40,
            "Disconnection Logical Link Complete Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask2_07,
          { "Flow Spec Modify Complete", "bthci_cmd.evt_mask2_07",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x80,
            "Flow Spec Modify Complete Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask2_10,
          { "Number Of Completed Data Blocks", "bthci_cmd.evt_mask2_10",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x01,
            "Number Of Completed Data Blocks Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask2_11,
          { "AMP Start Test", "bthci_cmd.evt_mask2_11",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x02,
            "AMP Start Test Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask2_12,
          { "AMP Test End", "bthci_cmd.evt_mask2_12",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x04,
            "AMP Test End Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask2_13,
          { "AMP Receiver Report", "bthci_cmd.evt_mask2_13",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x08,
            "AMP Receiver Report Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask2_14,
          { "Short Range Mode Change Complete", "bthci_cmd.evt_mask2_14",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x10,
            "Short Range Mode Change Complete Bit", HFILL }
        },
        { &hf_bthci_cmd_evt_mask2_15,
          { "AMP Status Change", "bthci_cmd.evt_mask2_15",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x20,
            "AMP Status Change Bit", HFILL }
        },
        { &hf_bthci_cmd_location_domain_aware,
          { "Location Domain Aware", "bthci_cmd.location_domain_aware",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_location_domain,
          { "Location Domain", "bthci_cmd.location_domain",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "ISO 3166-1 Country Code", HFILL }
        },
        { &hf_bthci_cmd_location_domain_options,
          { "Location Domain Options", "bthci_cmd.location_domain_options",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_location_options,
          { "Location Options", "bthci_cmd.location_options",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_flow_control_mode,
          { "Flow Control Mode", "bthci_cmd.flow_control_mode",
            FT_UINT8, BASE_HEX, VALS(cmd_flow_ctrl_mode), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_tx_power_level_type,
          { "Tx Power Level Type", "bthci_cmd.tx_power_level_type",
            FT_UINT8, BASE_HEX, VALS(cmd_power_level_types), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_short_range_mode,
          { "Short Range Mode", "bthci_cmd.short_range_mode",
            FT_UINT8, BASE_HEX, VALS(cmd_en_disabled), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_enable_amp_recv_reports,
          { "Enable AMP Receiver Reports", "bthci_cmd.enable_amp_recv_reports",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_amp_recv_report_interval,
          { "AMP Receiver Report Interval (s)", "bthci_cmd.amp_recv_report_interval",
            FT_UINT8, BASE_DEC, 0x0, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_length_so_far,
          { "Length So Far", "bthci_cmd.length_so_far",
            FT_UINT16, BASE_DEC, 0x0, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_amp_assoc_length,
          { "AMP Assoc Length", "bthci_cmd.amp_assoc_length",
            FT_UINT16, BASE_DEC, 0x0, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_amp_remaining_assoc_length,
          { "AMP Remaining Assoc Length", "bthci_cmd.amp_remaining_assoc_length",
            FT_UINT16, BASE_DEC, 0x0, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_amp_assoc_fragment,
          { "AMP Assoc Fragment", "bthci_cmd.amp_assoc_fragment",
            FT_BYTES, BASE_NONE, 0x0, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_supported_host,
          { "LE Supported Host", "bthci_cmd.le_supported_host",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_simultaneous_host,
          { "Simultaneous LE Host", "bthci_cmd.le_simlutaneous_host",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x0,
            "Support for both LE and BR/EDR to same device", HFILL }
        },
        { &hf_bthci_cmd_le_event_mask,
          { "LE Event Mask",                               "bthci_cmd.le_event_mask",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_event_mask_le_connection_complete,
          { "LE Connection Complete",                      "bthci_cmd.le_event_mask.le_connection_complete",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x01),
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_event_mask_le_advertising_report,
          { "LE Advertising Report",                       "bthci_cmd.le_event_mask.le_advertising_report",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x02),
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_event_mask_le_connection_update_complete,
          { "LE Connection Update Complete",               "bthci_cmd.le_event_mask.le_connection_update_complete",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x04),
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_event_mask_le_read_remote_features_complete,
          { "LE Read Remote Features Complete",       "bthci_cmd.le_event_mask.le_read_remote_features_complete",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x08),
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_event_mask_le_long_term_key_request,
          { "LE Long Term Key Request",                    "bthci_cmd.le_event_mask.le_long_term_key_request",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x10),
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_event_mask_le_remote_connection_parameter_request,
          { "LE Remote Connection Parameter Request",      "bthci_cmd.le_event_mask.le_remote_connection_parameter_request",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x20),
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_event_mask_le_data_length_change,
          { "LE Data Length Change",                       "bthci_cmd.le_event_mask.le_data_length_change",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x40),
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_event_mask_le_read_local_p256_public_key_complete,
          { "LE Read Local P-256 Public Key Complete",     "bthci_cmd.le_event_mask.le_read_local_p256_public_key_complete",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x80),
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_event_mask_le_generate_dhkey_complete,
          { "LE Generate DHKey Complete",                  "bthci_cmd.le_event_mask.le_generate_dhkey_complete",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x100),
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_event_mask_le_enhanced_connection_complete,
          { "LE Enhanced Connection Complete",             "bthci_cmd.le_event_mask.le_enhanced_connection_complete",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x200),
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_event_mask_le_direct_advertising_report,
          { "LE Direct Advertising Report",                "bthci_cmd.le_event_mask.le_direct_advertising_report",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x400),
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_event_mask_le_phy_update_complete,
          { "LE PHY Update Complete",                "bthci_cmd.le_event_mask.le_phy_update_complete",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x800),
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_event_mask_le_extended_advertising_report,
          { "LE Extended Advertising Report",              "bthci_cmd.le_event_mask.le_extended_advertising_report",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x1000),
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_event_mask_le_periodic_advertising_sync_established,
          { "LE Periodic Advertising Sync Established",    "bthci_cmd.le_event_mask.le_periodic_advertising_sync_established",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x2000),
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_event_mask_le_periodic_advertising_report,
          { "LE Periodic Advertising Report",              "bthci_cmd.le_event_mask.le_periodic_advertising_report",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x4000),
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_event_mask_le_periodic_advertising_sync_lost,
          { "LE Periodic Advertising Sync Lost",           "bthci_cmd.le_event_mask.le_periodic_advertising_sync_lost",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x8000),
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_event_mask_le_extended_scan_timeout,
          { "LE Extended Scan Timeout",                    "bthci_cmd.le_event_mask.le_extended_scan_timeout",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x10000),
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_event_mask_le_extended_advertising_set_terminated,
          { "LE Extended Advertising Set Terminated",      "bthci_cmd.le_event_mask.le_extended_advertising_set_terminated",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x20000),
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_event_mask_le_scan_request_received,
          { "LE Scan Request Received",                    "bthci_cmd.le_event_mask.le_scan_request_received",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x40000),
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_event_mask_le_channel_selection_algorithm,
          { "LE Channel Selection Algorithm",              "bthci_cmd.le_event_mask.le_channel_selection_algorithm",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x80000),
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_event_mask_le_connectionless_iq_report,
          { "LE Connectionless IQ Report", "bthci_cmd.le_event_mask.le_connectionless_iq_report",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x100000),
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_event_mask_le_connection_iq_report,
          { "LE Connection IQ Report", "bthci_cmd.le_event_mask.le_connection_iq_report",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x200000),
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_event_mask_le_cte_request_failed,
          { "LE CTE Request Failed", "bthci_cmd.le_event_mask.le_cte_request_failed",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x400000),
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_event_mask_le_periodic_advertising_sync_transfer_received,
          { "LE Periodic Advertising Sync Transfer Received", "bthci_cmd.le_event_mask.le_periodic_advertising_sync_transfer_received",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x800000),
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_event_mask_le_cis_established,
          { "LE CIS Established", "bthci_cmd.le_event_mask.le_cis_established",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x1000000),
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_event_mask_le_cis_request,
          { "LE CIS Request", "bthci_cmd.le_event_mask.le_cis_request",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x2000000),
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_event_mask_le_create_big_complete,
          { "LE Create BIG Complete", "bthci_cmd.le_event_mask.le_create_big_complete",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x4000000),
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_event_mask_le_terminate_big_complete,
          { "LE Terminate BIG Complete", "bthci_cmd.le_event_mask.le_terminate_big_complete",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x8000000),
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_event_mask_le_big_sync_established,
          { "LE BIG Sync Established", "bthci_cmd.le_event_mask.le_big_sync_established",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x10000000),
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_event_mask_le_big_sync_lost,
          { "LE BIG Sync Lost", "bthci_cmd.le_event_mask.le_big_sync_lost",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x20000000),
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_event_mask_le_request_peer_sca_complete,
          { "LE Request Peer SCA Complete", "bthci_cmd.le_event_mask.le_request_peer_sca_complete",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x40000000),
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_event_mask_le_path_loss_threshold,
          { "LE Path Loss Threshold", "bthci_cmd.le_event_mask.le_path_loss_threshold",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x80000000),
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_event_mask_le_transmit_power_reporting,
          { "LE Transmit Power Reporting", "bthci_cmd.le_event_mask.le_transmit_power_reporting",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x100000000),
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_event_mask_le_biginfo_advertising_report,
          { "LE BIGInfo Advertising Report", "bthci_cmd.le_event_mask.le_biginfo_advertising_report",
            FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x200000000),
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_event_mask_le_reserved,
          { "Reserved",                                    "bthci_cmd.le_event_mask.reserved",
            FT_UINT64, BASE_HEX, NULL, G_GUINT64_CONSTANT(0xFFFFFFFC00000000),
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_advts_interval_min,
          { "Advertising Interval Min", "bthci_cmd.le_advts_interval_min",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_advts_interval_max,
          { "Advertising Interval Max", "bthci_cmd.le_advts_interval_max",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_advts_type,
          { "Advertising Type", "bthci_cmd.le_advts_type",
            FT_UINT8, BASE_HEX, VALS(cmd_le_advertising_types), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_address_type,
          { "Address Type", "bthci_cmd.le_address_type",
            FT_UINT8, BASE_HEX, VALS(bthci_cmd_address_types_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_own_address_type,
          { "Own Address Type", "bthci_cmd.le_own_address_type",
            FT_UINT8, BASE_HEX, VALS(bthci_cmd_address_types_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_peer_address_type,
          { "Peer Address Type", "bthci_cmd.le_peer_address_type",
            FT_UINT8, BASE_HEX, VALS(bthci_cmd_address_types_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_peer_identity_address_type,
          { "Peer Identity Address Type", "bthci_cmd.le_peer_identity_address_type",
            FT_UINT8, BASE_HEX, VALS(bthci_cmd_identity_address_types_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_direct_address_type,
          { "Direct Address Type", "bthci_cmd.le_direct_address_type",
            FT_UINT8, BASE_HEX, VALS(bthci_cmd_address_types_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_advts_channel_map_1,
          { "Channel 37", "bthci_cmd.le_advts_ch_map_1",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x01,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_advts_channel_map_2,
          { "Channel 38", "bthci_cmd.le_advts_ch_map_2",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x02,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_advts_channel_map_3,
          { "Channel 39", "bthci_cmd.le_advts_ch_map_3",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x04,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_advts_filter_policy,
          { "Advertising Filter Policy", "bthci_cmd.le_advts_filter_policy",
            FT_UINT8, BASE_HEX, VALS(cmd_le_advertising_filter_policy), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_data_length,
          { "Data Length", "bthci_cmd.le_data_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_advts_enable,
          { "Advertising Enable", "bthci_cmd.le_advts_enable",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_scan_enable,
          { "Scan Enable", "bthci_cmd.le_scan_enable",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_filter_duplicates,
          { "Filter Duplicates", "bthci_cmd.le_filter_duplicates",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_scan_type,
          { "Scan Type", "bthci_cmd.le_scan_type",
            FT_UINT8, BASE_HEX, VALS(cmd_le_scan_types), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_scan_interval,
          { "Scan Interval", "bthci_cmd.le_scan_interval",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_scan_window,
          { "Scan Window", "bthci_cmd.le_scan_window",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_scan_filter_policy,
          { "Scan Filter Policy", "bthci_cmd.le_scan_filter_policy",
            FT_UINT8, BASE_HEX, VALS(cmd_le_scan_filter_policy), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_initiator_filter_policy,
          { "Initiator Filter Policy", "bthci_cmd.le_initiator_filter_policy",
            FT_UINT8, BASE_HEX, VALS(cmd_init_filter_policy), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_con_interval_min,
          { "Connection Interval Min", "bthci_cmd.le_con_interval_min",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_con_interval_max,
          { "Connection Interval Max", "bthci_cmd.le_con_interval_max",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_con_latency,
          { "Connection Latency", "bthci_cmd.le_con_latency",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_supervision_timeout,
          { "Supervision Timeout", "bthci_cmd.le_supv_timeout",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_min_ce_length,
          { "Min CE Length", "bthci_cmd.le_min_ce_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Min. Connection Event Length", HFILL }
        },
        { &hf_bthci_cmd_le_max_ce_length,
          { "Max CE Length", "bthci_cmd.le_max_ce_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Max. Connection Event Length", HFILL }
        },
        { &hf_bthci_cmd_le_channel_map,
          { "Channel Map", "bthci_cmd.le_channel_map",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_key,
          { "Key",        "bthci_cmd.le_key",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Encryption Key", HFILL }
        },
        { &hf_bthci_cmd_plaintext_data,
          { "Plaintext",        "bthci_cmd.le_plaintext",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_random_number,
          { "Random Number",        "bthci_cmd.le_random_number",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_encrypted_diversifier,
          { "Encrypted Diversifier", "bthci_cmd.le_encrypted_diversifier",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_long_term_key,
          { "Long Term Key",        "bthci_cmd.le_long_term_key",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_rx_frequency,
          { "Rx Frequency", "bthci_cmd.rx_frequency",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_tx_frequency,
          { "Tx Frequency", "bthci_cmd.tx_frequency",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_test_data_length,
          { "Test Data Length", "bthci_cmd.le_test_data_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_test_packet_payload,
          { "Packet Payload", "bthci_cmd.le_test_data_length",
            FT_UINT8, BASE_HEX, VALS(cmd_le_test_pkt_payload), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_parameter,
          { "Parameter", "bthci_cmd.parameter",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_response_in_frame,
            { "Response in frame",                "bthci_cmd.response_in_frame",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
            NULL, HFILL }
        },
        { &hf_command_response_time_delta,
            { "Command-Response Delta",          "bthci_cmd.command_response_delta",
            FT_DOUBLE, BASE_NONE|BASE_UNIT_STRING, &units_milliseconds, 0x00,
            NULL, HFILL }
        },
        { &hf_pending_in_frame,
            { "Pending in frame",                "bthci_cmd.pending_in_frame",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
            NULL, HFILL }
        },
        { &hf_command_pending_time_delta,
            { "Command-Pending Delta",          "bthci_cmd.command_pending_delta",
            FT_DOUBLE, BASE_NONE|BASE_UNIT_STRING, &units_milliseconds, 0x00,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_tx_octets,
          { "TxOctets", "bthci_cmd.le_tx_octets",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_tx_time,
          { "TxTime", "bthci_cmd.le_tx_time",
            FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_microseconds, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_suggested_max_tx_octets,
          { "SuggestedMaxTxOctets", "bthci_cmd.le_suggested_max_tx_octets",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_suggested_max_tx_time,
          { "SuggestedMaxTxTime", "bthci_cmd.le_suggested_max_tx_time",
            FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_microseconds, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_remote_p_256_public_key,
          { "Remote_P-256_Public_Key", "bthci_cmd.le_remote_p_256_public_key",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_peer_irk,
          { "Peer IRK", "bthci_cmd.le_peer_irk",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_local_irk,
          { "Local IRK", "bthci_cmd.le_local_irk",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_address_resolution_enable,
          { "Address Resolution Enable", "bthci_cmd.le_address_resolution_enable",
            FT_UINT8, BASE_HEX, VALS(cmd_le_address_resolution_enable), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_rpa_timeout,
          { "RPA Timeout", "bthci_cmd.le_rpa_timeout",
            FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_second_seconds, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_advertising_handle,
          { "Advertising Handle", "bthci_cmd.advertising_handle",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_advertising_ext_interval_min,
          { "Advertising Interval Min", "bthci_cmd.le_advts_interval_min",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_advertising_ext_interval_max,
          { "Advertising Interval Max", "bthci_cmd.le_advts_interval_max",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_advertising_properties,
          { "Advertising Event Properties", "bthci_cmd.advertising_properties",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_advertising_properties_incl_txpower,
          { "Include Tx Power", "bthci_cmd.adv_properties.txpower",
            FT_BOOLEAN, 16, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_advertising_properties_anonymous_adv,
          { "Anonymous Advertisement", "bthci_cmd.adv_properties.anonymous_adv",
            FT_BOOLEAN, 16, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_advertising_properties_legacy_adv,
          { "Use Legacy PDUs", "bthci_cmd.adv_properties.legacy_adv",
            FT_BOOLEAN, 16, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_advertising_properties_hdc_connectable_directed,
          { "High Duty Cycle Connectable Directed", "bthci_cmd.adv_properties.hdc_connectable_directed",
            FT_BOOLEAN, 16, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_advertising_properties_directed,
          { "Directed", "bthci_cmd.adv_properties.directed",
            FT_BOOLEAN, 16, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_advertising_properties_scannable,
          { "Scannable", "bthci_cmd.adv_properties.scannable",
            FT_BOOLEAN, 16, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_advertising_properties_connectable,
          { "Connectable", "bthci_cmd.adv_properties.connectable",
            FT_BOOLEAN, 16, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_advertising_properties_reserved,
          { "Reserved", "bthci_cmd.adv_properties.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xFF80,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_periodic_advertising_properties,
          { "Periodic Advertising Properties", "bthci_cmd.periodic_adv_properties",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_periodic_advertising_properties_reserved,
          { "Reserved", "bthci_cmd.periodic_adv_properties.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xFFBF,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_primary_advertising_phy,
          { "Primary Advertising PHY", "bthci_cmd.primary_advertising_phy",
            FT_UINT8, BASE_HEX, VALS(cmd_le_phy_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_sec_adv_max_skip,
          { "Secondary Advertising Max Skip", "bthci_cmd.secondary_advertising_max_skip",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_secondary_advertising_phy,
          { "Secondary Advertising PHY", "bthci_cmd.secondary_advertising_phy",
            FT_UINT8, BASE_HEX, VALS(cmd_le_phy_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_advertising_sid,
          { "Advertising SID", "bthci_cmd.advertising_sid",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_scan_req_notif_en,
          { "Scan Request Notification Enable", "bthci_cmd.scan_request_notification_enable",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_adv_data_operation,
          { "Data Operation", "bthci_cmd.adv_data_operation",
            FT_UINT8, BASE_HEX, VALS(cmd_le_adv_data_operation), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_adv_data_frag_pref,
          { "Fragment Preference", "bthci_cmd.adv_fragment_preference",
            FT_UINT8, BASE_HEX, VALS(cmd_le_adv_data_frag_pref), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_adv_set,
          { "Advertising Set", "bthci_cmd.le_adv_set",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_adv_en_sets,
          { "Number of Sets", "bthci_cmd.adv_num_sets",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_adv_duration,
          { "Duration", "bthci_cmd.adv_duration",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_adv_max_extended_events,
          { "Max Extended Events", "bthci_cmd.max_extended_advertising_events",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        {&hf_bthci_cmd_all_phys,
            {"All PHYs", "bthci_cmd.all_phys",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_bthci_cmd_all_phys_tx_pref,
          { "The Host has no Tx PHY preference", "bthci_cmd.all_phys.tx_preference",
            FT_BOOLEAN, 8, NULL, 0x1,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_all_phys_rx_pref,
          { "The Host has no Rx PHY preference", "bthci_cmd.all_phys.rx_preference",
            FT_BOOLEAN, 8, NULL, 0x2,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_all_phys_reserved,
          { "Reserved", "bthci_cmd.all_phys.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xFC,
            NULL, HFILL }
        },
        {&hf_bthci_cmd_tx_phys,
            {"Tx PHYs", "bthci_cmd.tx_phys",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_bthci_cmd_rx_phys,
            {"Rx PHYs", "bthci_cmd.rx_phys",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_bthci_cmd_phys_pref_le_1m,
          { "The Host prefers LE 1M", "bthci_cmd.phys_pref.le_1m",
            FT_BOOLEAN, 8, NULL, 0x1,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_phys_pref_le_2m,
          { "The Host prefers LE 2M", "bthci_cmd.phys_pref.le_2m",
            FT_BOOLEAN, 8, NULL, 0x2,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_phys_pref_le_coded,
          { "The Host prefers LE Coded", "bthci_cmd.phys_pref.le_coded",
            FT_BOOLEAN, 8, NULL, 0x4,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_phys_pref_reserved,
          { "Reserved", "bthci_cmd.phys_pref.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xF8,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_phy_options,
          { "PHY Options", "bthci_cmd.phy_options",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_phy_options_coding,
          { "Coding", "bthci_cmd.phy_options.coding",
            FT_UINT16, BASE_HEX, VALS(cmd_le_phy_options_vals), 0x3,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_phy_options_reserved,
          { "Reserved", "bthci_cmd.phy_options.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xFFFC,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_phy,
          { "PHY", "bthci_cmd.phy",
            FT_UINT8, BASE_HEX, VALS(cmd_le_phy_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_modulation_index,
          { "Modulation Index", "bthci_cmd.modulation_index",
            FT_UINT8, BASE_HEX, VALS(cmd_le_modulation_index_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_scan_phys,
          { "Scanning PHYs", "bthci_cmd.le_scan_phys",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_scan_phys_le_1m,
          { "LE 1M", "bthci_cmd.le_scan_phys.le_1m",
            FT_BOOLEAN, 8, NULL, 0x1,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_scan_phys_le_coded,
          { "LE Coded", "bthci_cmd.le_scan_phys.le_coded",
            FT_BOOLEAN, 8, NULL, 0x4,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_scan_phys_reserved,
          { "Reserved", "bthci_cmd.le_scan_phys.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xFA,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_scan_phy_param,
          { "Scanning PHY", "bthci_cmd.le_scan_phy_param",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_scan_duration,
          { "Duration", "bthci_cmd.scan_duration",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_scan_period,
          { "Period", "bthci_cmd.scan_period",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_init_phys,
          { "Initiating PHYs", "bthci_cmd.le_init_phys",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_phys_le_1m,
          { "LE 1M", "bthci_cmd.le_phys.le_1m",
            FT_BOOLEAN, 8, NULL, 0x1,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_phys_le_2m,
          { "LE 2M", "bthci_cmd.le_phys.le_2m",
            FT_BOOLEAN, 8, NULL, 0x2,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_phys_le_coded,
          { "LE Coded", "bthci_cmd.le_phys.le_coded",
            FT_BOOLEAN, 8, NULL, 0x4,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_phys_reserved,
          { "Reserved", "bthci_cmd.le_phys.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xF8,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_init_phy_param,
          { "Initiating PHY", "bthci_cmd.le_init_phy_param",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_le_privacy_mode,
          { "Privacy Mode", "bthci_cmd.le_privacy_mode",
            FT_UINT8, BASE_HEX, VALS(cmd_privacy_mode), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_sync_filter_policy,
          { "Filter Policy", "bthci_cmd.le_sync_filter_policy",
            FT_UINT8, BASE_HEX, VALS(cmd_sync_filter_policy), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_skip,
          { "Skip", "bthci_cmd.skip",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_sync_handle,
          { "Sync Handle",             "bthci_cmd.sync_handle",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_rf_tx_path_compensation_value,
          { "RF Tx Path Compensation Value",   "bthci_cmd.rf_tx_path_compensation_value",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_rf_rx_path_compensation_value,
          { "RF Rx Path Compensation Value",   "bthci_cmd.rf_rx_path_compensation_value",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_cte_length,
          { "CTE Length",   "bthci_cmd.cte_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_cte_type,
          { "CTE Type",   "bthci_cmd.cte_type",
            FT_UINT8, BASE_HEX, VALS(cmd_cte_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_slot_durations,
          { "Slot Durations",   "bthci_cmd.slot_durations",
            FT_UINT8, BASE_HEX, VALS(cmd_slot_durations_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_antenna_switching_pattern_length,
          { "Antenna Switching Pattern Length",   "bthci_cmd.antenna_switching_pattern_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_antenna_switching_pattern,
          { "Antenna Switching Pattern",   "bthci_cmd.antenna_switching_pattern",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_antenna_id,
          { "Antenna Id",   "bthci_cmd.antenna_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_cte_count,
          { "CTE Count",   "bthci_cmd.cte_count",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_cte_enable,
          { "CTE Enable",   "bthci_cmd.cte_enable",
            FT_UINT8, BASE_HEX, VALS(disable_enable_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_iq_sampling_enable,
          { "IQ Sampling Enable",   "bthci_cmd.iq_sampling_enable",
            FT_UINT8, BASE_HEX, VALS(disable_enable_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_max_sampled_ctes,
          { "Max Sampled CTEs",   "bthci_cmd.max_sampled_ctes",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_cte_request_interval,
          { "CTE Request Interval",   "bthci_cmd.cte_request_interval",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_reporting_enable,
          { "Reporting Enable", "bthci_cmd.reporting_enable",
            FT_UINT8, BASE_HEX, VALS(disable_enable_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_sync_cte_type,
          { "Sync CTE Type", "bthci_cmd.sync_cte_type",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_sync_cte_type_no_sync_aoa,
          { "No sync to packets with AoA CTE", "bthci_cmd.sync_cte_type.no_sync_aoa",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_sync_cte_type_no_sync_aod_1us,
          { "No sync to packets with AoD 1 usec CTE", "bthci_cmd.sync_cte_type.no_sync_aod_1us",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_sync_cte_type_no_sync_aod_2us,
          { "No sync to packets with AoD 2 usec CTE", "bthci_cmd.sync_cte_type.no_sync_aod_2us",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_sync_cte_type_sync_only_with_cte,
          { "Sync only to packets with CTE", "bthci_cmd.sync_cte_type.sync_only_with_cte",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_sync_cte_type_reserved,
          { "Reserved", "bthci_cmd.sync_cte_type.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xE8,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_cte_types,
          { "Allowed CTE Types", "bthci_cmd.cte_types",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_cte_types_aoa,
          { "AoA", "bthci_cmd.cte_types.aoa",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_cte_types_aod_1us,
          { "AoD 1 usec slots", "bthci_cmd.cte_types.aod_1us",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_cte_types_aod_2us,
          { "AoD 2 usec slots", "bthci_cmd.cte_types.aod_2us",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_cte_types_reserved,
          { "Reserved", "bthci_cmd.cte_types.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xF8,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_service_data_past,
          { "Service Data", "bthci_cmd.service_data_past",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_sync_mode,
          { "Mode",   "bthci_cmd.sync_mode",
            FT_UINT8, BASE_HEX, VALS(cmd_sync_mode_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_key_type,
          { "Key Type",   "bthci_cmd.key_type",
            FT_UINT8, BASE_HEX, VALS(cmd_key_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_sca_action,
          { "Action",   "bthci_cmd.sca_action",
            FT_UINT8, BASE_HEX, VALS(cmd_sca_action_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_cig_id,
          { "CIG Id",   "bthci_cmd.cig_id",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_sdu_interval_m_to_s,
          { "SDU Interval Master to Slave",   "bthci_cmd.sdu_interval_m_to_s",
            FT_UINT24, BASE_DEC|BASE_UNIT_STRING, &units_microseconds, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_sdu_interval_s_to_m,
          { "SDU Interval Slave to Master",   "bthci_cmd.sdu_interval_s_to_m",
            FT_UINT24, BASE_DEC|BASE_UNIT_STRING, &units_microseconds, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_sdu_interval,
          { "SDU Interval",   "bthci_cmd.sdu_interval",
            FT_UINT24, BASE_DEC|BASE_UNIT_STRING, &units_microseconds, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_slaves_clock_accuracy,
          { "Slaves Clock Accuracy", "bthci_cmd.slaves_clock_accuracy",
            FT_UINT8, BASE_HEX, VALS(cmd_clock_accuray_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_packing,
          { "Packing", "bthci_cmd.packing",
            FT_UINT8, BASE_HEX, VALS(cmd_packing_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_framing,
          { "Framing", "bthci_cmd.framing",
            FT_UINT8, BASE_HEX, VALS(cmd_framing_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_ft_m_to_s,
          { "Flush Timeout Master to Slave", "bthci_cmd.ft_m_to_s",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_ft_s_to_m,
          { "Flush Timeout Slave to Master", "bthci_cmd.ft_s_to_m",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_iso_interval,
          { "ISO Interval", "bthci_cmd.iso_interval",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_cis_count,
          { "CIS Count", "bthci_cmd.cis_count",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_cis_params,
          { "CIS Parameters", "bthci_cmd.cis_params",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_cis_id,
          { "CIS Id", "bthci_cmd.cis_id",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_nse,
          { "Number of Sub-Events", "bthci_cmd.nse",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_max_sdu_m_to_s,
          { "Max SDU Master to Slave", "bthci_cmd.max_sdu_m_to_s",
            FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_max_sdu_s_to_m,
          { "Max SDU Slave to Master", "bthci_cmd.max_sdu_s_to_m",
            FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_max_sdu,
          { "Max SDU", "bthci_cmd.max_sdu",
            FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_max_pdu_m_to_s,
          { "Max PDU Master to Slave", "bthci_cmd.max_pdu_m_to_s",
            FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_max_pdu_s_to_m,
          { "Max PDU Slave to Master", "bthci_cmd.max_pdu_s_to_m",
            FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_max_pdu,
          { "Max PDU", "bthci_cmd.max_pdu",
            FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_phy_m_to_s,
          { "PHY Master to Slave", "bthci_cmd.phy_m_to_s",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_phy_s_to_m,
          { "PHY Slave to Master", "bthci_cmd.phy_s_to_m",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_bn_m_to_s,
          { "Burst Number Master to Slave", "bthci_cmd.bn_m_to_s",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_bn_s_to_m,
          { "Burst Number Slave to Master", "bthci_cmd.bn_s_to_m",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_bn,
          { "Burst Number", "bthci_cmd.bn",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_max_transport_latency_m_to_s,
          { "Max Transport Latency Master to Slave", "bthci_cmd.max_transport_latency_m_to_s",
            FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_max_transport_latency_s_to_m,
          { "Max Transport Latency Slave to Master", "bthci_cmd.max_transport_latency_s_to_m",
            FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_max_transport_latency,
          { "Max Transport Latency", "bthci_cmd.max_transport_latency",
            FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_rtn_m_to_s,
          { "Max Retransmissions Master to Slave", "bthci_cmd.rtn_m_to_s",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_rtn_s_to_m,
          { "Max Retransmissions Slave to Master", "bthci_cmd.rtn_s_to_m",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_rtn,
          { "Max Retransmissions", "bthci_cmd.rtn",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_cis_handle,
          { "CIS Handle",             "bthci_cmd.cis_handle",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_big_handle,
          { "BIG Handle",             "bthci_cmd.big_handle",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_cis_bis_handle,
          { "CIS/BIS Handle",             "bthci_cmd.cis_bis_handle",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_num_bis,
          { "Number of BISes", "bthci_cmd.num_bis",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_irc,
          { "Scheduled Payload Retransmissions", "bthci_cmd.irc",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_pto,
          { "Pre-Transmission Offset", "bthci_cmd.pto",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_encryption,
          { "Encryption", "bthci_cmd.encryption",
            FT_UINT8, BASE_HEX, VALS(disable_enable_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_broadcast_code,
          { "Broadcast Code", "bthci_cmd.broadcast_code",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_mse,
          { "Max Sub-Events", "bthci_cmd.mse",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_bis_index,
          { "BIS Index", "bthci_cmd.bis_index",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_sync_timeout,
          { "Sync Timeout", "bthci_cmd.sync_timeout",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_data_path_direction,
          { "Data Path Direction", "bthci_cmd.data_path_direction",
            FT_UINT8, BASE_HEX, VALS(cmd_data_path_direction_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_data_path_id,
          { "Data Path Id", "bthci_cmd.data_path_id",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_coding_format,
          { "Coding Format", "bthci_cmd.coding_format",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_controller_delay,
          { "Controller Delay", "bthci_cmd.controller_delay",
            FT_UINT24, BASE_DEC|BASE_UNIT_STRING, &units_microseconds, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_codec_config_length,
          { "Codec Configuration Length", "bthci_cmd.codec_config_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_codec_config,
          { "Codec Configuration", "bthci_cmd.codec_config",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_payload_type,
          { "Payload Type", "bthci_cmd.payload_type",
            FT_UINT8, BASE_HEX, VALS(cmd_payload_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_feature_bit_number,
          { "Feature Bit Number", "bthci_cmd.feature_bit_number",
            FT_UINT8, BASE_DEC, VALS(cmd_host_enabled_feature_bit_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_feature_bit_value,
          { "Feature Bit Value", "bthci_cmd.feature_bit_value",
            FT_UINT8, BASE_HEX, VALS(cmd_en_disabled), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_phy_and_coding,
          { "PHY", "bthci_cmd.phy_and_coding",
            FT_UINT8, BASE_HEX, VALS(cmd_phy_and_coding_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_high_threshold,
          { "High Threshold", "bthci_cmd.high_threshold",
            FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_decibels, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_high_hysteresis,
          { "High Hysteresis", "bthci_cmd.high_hysteresis",
            FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_decibels, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_low_threshold,
          { "Low Threshold", "bthci_cmd.low_threshold",
            FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_decibels, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_low_hysteresis,
          { "Low Hysteresis", "bthci_cmd.low_hysteresis",
            FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_decibels, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_min_time_spent,
          { "Minimum Observation Time", "bthci_cmd.min_time_spent",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_local_reporting_enable,
          { "Local Reporting Enable", "bthci_cmd.local_reporting_enable",
            FT_UINT8, BASE_HEX, VALS(disable_enable_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_remote_reporting_enable,
          { "Remote Reporting Enable", "bthci_cmd.remote_reporting_enable",
            FT_UINT8, BASE_HEX, VALS(disable_enable_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_triggered_clock_capture,
          { "Triggered Clock Capture", "bthci_cmd.triggered_clock_capture",
            FT_UINT8, BASE_HEX, VALS(disable_enable_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_lpo_allowed,
          { "LPO Allowed", "bthci_cmd.lpo_allowed",
            FT_UINT8, BASE_HEX, VALS(lpo_allowed_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_number_of_clock_captures_to_filter,
          { "Number of Clock Captures to Filter", "bthci_cmd.number_of_clock_captures_to_filter",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_amp_controller_type,
          { "Controller Type", "bthci_cmd.controller_type",
            FT_UINT8, BASE_HEX, VALS(bthci_evt_controller_types), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_dm1_acl_u_mode,
          {"DM1 ACL-U Mode", "bthci_cmd.dm1_acl_u_mode",
           FT_UINT8, BASE_HEX, VALS(disable_enable_vals), 0x0,
           NULL, HFILL}
        },
        { &hf_bthci_cmd_esco_loopback_mode,
          {"eSCO Loopback Mode", "bthci_cmd.esco_loopback_mode",
           FT_UINT8, BASE_HEX, VALS(disable_enable_vals), 0x0,
           NULL, HFILL}
        },
        { &hf_bthci_cmd_transmit_coding_format,
          { "Transmit Coding Format", "bthci_cmd.transmit_coding_format",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_receive_coding_format,
          { "Receive Coding Format", "bthci_cmd.receive_coding_format",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_input_coding_format,
          { "Input Coding Format", "bthci_cmd.input_coding_format",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_output_coding_format,
          { "Output Coding Format", "bthci_cmd.output_coding_format",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_codec_id,
          { "Codec", "bthci_cmd.codec_id",
            FT_UINT8, BASE_HEX, VALS(bthci_evt_codec_id_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_company_id,
          { "Company ID",                        "bthci_cmd.company_id",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bluetooth_company_id_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_vendor_codec_id,
          { "Vendor Codec ID", "bthci_cmd.vendor_codec_id",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_transmit_codec_frame_size,
          { "Transmit Codec Frame Size", "bthci_cmd.transmit_codec_frame_size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_receive_codec_frame_size,
          { "Receive Codec Frame Size", "bthci_cmd.receive_codec_frame_size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_input_bandwidth,
          { "Input Bandwidth", "bthci_cmd.input_bandwidth",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_output_bandwidth,
          { "Output Bandwidth", "bthci_cmd.output_bandwidth",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_input_coded_data_size,
          { "Input Coded Data Size", "bthci_cmd.input_coded_data_size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_output_coded_data_size,
          { "Output Coded Data Size", "bthci_cmd.output_coded_data_size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_input_pcm_data_format,
          { "Input PCM Data Format", "bthci_cmd.input_pcm_data_format",
            FT_UINT8, BASE_HEX, VALS(pcm_data_format_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_output_pcm_data_format,
          { "Output PCM Data Format", "bthci_cmd.output_pcm_data_format",
            FT_UINT8, BASE_HEX, VALS(pcm_data_format_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_input_pcm_sample_payload_msb_position,
          { "Input PCM Sample Payload MSB Position", "bthci_cmd.input_pcm_sample_payload_msb_position",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_output_pcm_sample_payload_msb_position,
          { "Output PCM Sample Payload MSB Position", "bthci_cmd.output_pcm_sample_payload_msb_position",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_input_data_path,
          { "Input Data Path", "bthci_cmd.input_data_path",
            FT_UINT8, BASE_RANGE_STRING, RVALS(audio_data_path_rvals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_output_data_path,
          { "Output Data Path", "bthci_cmd.output_data_path",
            FT_UINT8, BASE_RANGE_STRING, RVALS(audio_data_path_rvals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_input_transport_unit_size,
          { "Input Transport Unit Size", "bthci_cmd.input_transport_unit_size",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_output_transport_unit_size,
          { "Output Transport Unit Size", "bthci_cmd.output_transport_unit_size",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_connectionless_slave_broadcast,
          { "Connectionless Slave Broadcast", "bthci_cmd.connectionless_slave_broadcast",
            FT_UINT8, BASE_HEX, VALS(disable_enable_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_lt_addr,
          { "LT_ADDR", "bthci_cmd.lt_addr",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_interval_min,
          { "Min Interval", "bthci_cmd.interval.min",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_interval_max,
          { "Max Interval", "bthci_cmd.interval.max",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_csb_supervision_to,
          { "Supervision To", "bthci_cmd.csb_supervision_to",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_connectionless_slave_broadcast_receive,
          { "Connectionless Slave Broadcast Receive", "bthci_cmd.connectionless_slave_broadcast_receive",
            FT_UINT8, BASE_HEX, VALS(disable_enable_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_clock_offset_32,
          { "Clock Offset", "bthci_cmd.clock_offset_32",
            FT_UINT32, BASE_HEX, NULL, 0x0FFFFFFF,
            "Bits 0-27 of the Clock Offset between CLKslave-CLK", HFILL }
        },
        { &hf_bthci_cmd_next_csb_clock,
          { "Next CSB Clock", "bthci_cmd.next_csb_clock",
            FT_UINT32, BASE_HEX, NULL, 0x0FFFFFFF,
            "Bits 0-27 of the Clock Offset between CLKslave-CLK", HFILL }
        },
        { &hf_bthci_cmd_remote_timing_accuracy,
          { "Remote Timing Accuracy", "bthci_cmd.remote_timing_accuracy",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_csb_skip,
          { "CSB Skip", "bthci_cmd.csb_skip",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
/* TODO: More detailed dissection */
        { &hf_bthci_cmd_afh_channel_map,
          {"AFH Channel Map", "bthci_cmd.afh_channel_map",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_bthci_cmd_synchronization_scan_to,
          { "Synchronization Scan To", "bthci_cmd.synchronization_scan_to",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_c192,
          { "C 192", "bthci_cmd.c192",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_r192,
          { "R 192", "bthci_cmd.r192",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_c256,
          { "C 256", "bthci_cmd.c256",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_r256,
          { "R 256", "bthci_cmd.r256",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_mws_channel,
          { "MWS Channel", "bthci_cmd.mws_channel",
            FT_UINT8, BASE_HEX, VALS(disable_enable_vals), 0x0,
            NULL, HFILL }
        },
/* TODO: Add units */
        { &hf_bthci_mws_rx_center_frequency,
          { "MWS RX Center Frequency", "bthci_cmd.mws_rx_center_frequency",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_mws_tx_center_frequency,
          { "MWS TX Center Frequency", "bthci_cmd.mws_tx_center_frequency",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
/* TODO: Add units */
        { &hf_bthci_mws_rx_channel_bandwidth,
          { "MWS RX Channel Bandwidth", "bthci_cmd.mws_rx_channel_bandwidth",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_mws_tx_channel_bandwidth,
          { "MWS TX Channel Bandwidth", "bthci_cmd.mws_tx_channel_bandwidth",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_mws_channel_type,
          { "MWS Channel Type", "bthci_cmd.mws_channel_type",
            FT_UINT8, BASE_HEX, VALS(mws_channel_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_external_frame_duration,
          { "Frame Duration", "bthci_cmd.external_frame.duration",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_external_frame_sync_assert_offset,
          { "Frame Duration", "bthci_cmd.external_frame.sync_assert.offset",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_external_frame_sync_assert_jitter,
          { "Frame Sync Assert Jitter", "bthci_cmd.external_frame.sync_assert.jitter",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_external_frame_number_of_periods,
          { "Number of Periods", "bthci_cmd.external_frame.number_of_periods",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_external_frame_periods,
          { "Periods", "bthci_cmd.external_frame.periods",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_external_frame_period,
          { "Period", "bthci_cmd.external_frame.period",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_external_frame_period_duration,
          { "Duration", "bthci_cmd.external_frame.period.duration",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_external_frame_period_type,
          { "Type", "bthci_cmd.external_frame.period.type",
            FT_UINT8, BASE_HEX, VALS(external_frame_period_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_mws_rx_assert_offset,
          { "RX Assert Offset", "bthci_cmd.mws.rx_assert.offset",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_mws_rx_assert_jitter,
          { "RX Assert Jitter", "bthci_cmd.mws.rx_assert.jitter",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_mws_rx_deassert_offset,
          { "RX Deassert Offset", "bthci_cmd.mws.rx_deassert.offset",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_mws_rx_deassert_jitter,
          { "RX Deassert Jitter", "bthci_cmd.mws.rx_deassert.jitter",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_mws_tx_assert_offset,
          { "TX Assert Offset", "bthci_cmd.mws.tx_assert.offset",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_mws_tx_assert_jitter,
          { "TX Assert Jitter", "bthci_cmd.mws.tx_assert.jitter",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_mws_tx_deassert_offset,
          { "TX Deassert Offset", "bthci_cmd.mws.tx_deassert.offset",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_mws_tx_deassert_jitter,
          { "TX Deassert Jitter", "bthci_cmd.mws.tx_deassert.jitter",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_mws_pattern_assert_offset,
          { "Pattern Assert Offset", "bthci_cmd.mws.pattern_assert.offset",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_mws_pattern_assert_jitter,
          { "Pattern Assert Jitter", "bthci_cmd.mws.pattern_assert.jitter",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_mws_inactivity_duration_assert_offset,
          { "Inactivity Duration Assert Offset", "bthci_cmd.mws.inactivity_duration_assert.offset",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_mws_inactivity_duration_assert_jitter,
          { "Inactivity Duration Assert Jitter", "bthci_cmd.mws.inactivity_duration_assert.jitter",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_mws_scan_frequency_assert_offset,
          { "Scan Frequency Assert Offset", "bthci_cmd.mws.scan_frequency_assert.offset",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_mws_scan_frequency_assert_jitter,
          { "Scan Frequency Assert Jitter", "bthci_cmd.mws.scan_frequency_assert.jitter",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_mws_priority_assert_offset_request,
          { "Priority Assert Offset Request", "bthci_cmd.mws.priority_assert_offset_request",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_mws_transport_layer,
          { "Transport Layer",  "bthci_cmd.mws.transport_layer",
            FT_UINT8, BASE_HEX, VALS(bthci_evt_mws_transport_layer_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_mws_to_baud_rate,
          { "To Baud Rate",  "bthci_cmd.mws.to_baud_rate",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_mws_from_baud_rate,
          { "From Baud Rate",  "bthci_cmd.mws.from_baud_rate",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_mws_number_of_frequencies,
          { "Number of Frequencies", "bthci_cmd.mws.number_of_frequencies",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_mws_scan_frequency_table,
          { "Scan Frequency Table",  "bthci_cmd.mws.scan_frequency_table",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_mws_scan_frequency_table_item,
          { "Item",  "bthci_cmd.mws.scan_frequency_table.item",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_mws_scan_frequency_table_item_low,
          { "Low Frequency",  "bthci_cmd.mws.scan_frequency_table.item.low",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_mws_scan_frequency_table_item_high,
          { "High Frequency",  "bthci_cmd.mws.scan_frequency_table.item.high",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_mws_pattern_index,
          { "Index", "bthci_cmd.mws_pattern.index",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_mws_pattern_number_of_intervals,
          { "Number of Intervals", "bthci_cmd.mws_pattern.number_of_intervals",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_mws_patterns,
          { "Patterns",  "bthci_cmd.mws_pattern.patterns",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_mws_pattern,
          { "Pattern",  "bthci_cmd.mws_pattern.pattern",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_mws_pattern_duration,
          { "Duration",  "bthci_cmd.mws_pattern.pattern.duration",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_mws_pattern_type,
          { "Type",  "bthci_cmd.mws_pattern.pattern.type",
            FT_UINT8, BASE_HEX, VALS(mws_pattern_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_sync_train_to,
          { "Synchronization Train To", "bthci_cmd.sync_train_to",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_service_data,
          { "Service Data", "bthci_cmd.service_data",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_secure_connection_host_support,
          { "Secure Connection Host Support", "bthci_cmd.secure_connection_host_support",
            FT_UINT8, BASE_HEX, VALS(disable_enable_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_csb_fragment,
          { "CSB Fragment", "bthci_cmd.csb.fragment",
            FT_UINT8, BASE_HEX, VALS(csb_fragment_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_csb_data_length,
          { "CSB Data Length", "bthci_cmd.csb.data_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_csb_data,
          { "CSB Data", "bthci_cmd.csb.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_authenticated_payload_timeout,
          { "Authenticated Payload Timeout", "bthci_cmd.authenticated_payload_timeout",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_cmd_extended_inquiry_length,
          { "Extended Inquiry Length",           "bthci_cmd.extended_inquiry_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        }
    };

    static ei_register_info ei[] = {
        { &ei_command_unknown_command,      { "bthci_cmd.expert.command.unknown_command", PI_PROTOCOL, PI_WARN, "Unknown command", EXPFILL }},
        { &ei_command_parameter_unexpected, { "bthci_cmd.expert.parameter.unexpected", PI_PROTOCOL, PI_WARN, "Unexpected command parameter", EXPFILL }},
        { &ei_command_undecoded,            { "bthci_cmd.expert.command.undecoded", PI_UNDECODED, PI_NOTE, "Command undecoded", EXPFILL }}
    };

    static gint *ett[] = {
        &ett_bthci_cmd,
        &ett_opcode,
        &ett_cod,
        &ett_cod_mask,
        &ett_flow_spec_subtree,
        &ett_le_channel_map,
        &ett_le_event_mask,
        &ett_adv_properties,
        &ett_adv_sets,
        &ett_phys_flags,
        &ett_phy_param,
        &ett_sync_cte_type,
        &ett_coding_format,
        &ett_packet_type,
        &ett_sco_packet_type,
        &ett_periods,
        &ett_period,
        &ett_table,
        &ett_table_item,
        &ett_patterns,
        &ett_pattern,
        &ett_cis_params
    };

    proto_bthci_cmd = proto_register_protocol("Bluetooth HCI Command", "HCI_CMD", "bthci_cmd");
    bthci_cmd_handle = register_dissector("bthci_cmd", dissect_bthci_cmd, proto_bthci_cmd);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_bthci_cmd, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_bthci_cmd = expert_register_protocol(proto_bthci_cmd);
    expert_register_field_array(expert_bthci_cmd, ei, array_length(ei));

    bthci_cmds = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    module = prefs_register_protocol_subtree("Bluetooth", proto_bthci_cmd, NULL);
    prefs_register_static_text_preference(module, "hci_cmd.version",
            "Bluetooth HCI version: 4.0 (Core)",
            "Version of protocol supported by this dissector.");

    vendor_dissector_table = register_decode_as_next_proto(proto_bthci_cmd, "bthci_cmd.vendor",
                                                           "BT HCI Vendor", bthci_cmd_vendor_prompt);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
   */
void
proto_reg_handoff_bthci_cmd(void)
{
    hci_vendor_table = find_dissector_table("bluetooth.vendor");

    dissector_add_uint("hci_h4.type", HCI_H4_TYPE_CMD, bthci_cmd_handle);
    dissector_add_uint("hci_h1.type", BTHCI_CHANNEL_COMMAND, bthci_cmd_handle);
}

#define PROTO_DATA_BLUETOOTH_EIR_AD_MANUFACTURER_COMPANY_ID  0
#define PROTO_DATA_BLUETOOTH_EIR_AD_TDS_ORGANIZATION_ID      1

static void bluetooth_eir_ad_manufacturer_company_id_prompt(packet_info *pinfo, gchar* result)
{
    guint16 *value_data;

    value_data = (guint16 *) p_get_proto_data(pinfo->pool, pinfo, proto_btcommon, PROTO_DATA_BLUETOOTH_EIR_AD_MANUFACTURER_COMPANY_ID);
    if (value_data)
        g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "EIR/AD Manufacturer Company ID 0x%02x as", (guint) *value_data);
    else
        g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Unknown EIR/AD Manufacturer");
}

static gpointer bluetooth_eir_ad_manufacturer_company_id_value(packet_info *pinfo)
{
    guint16 *value_data;

    value_data = (guint16 *) p_get_proto_data(pinfo->pool, pinfo, proto_btcommon, PROTO_DATA_BLUETOOTH_EIR_AD_MANUFACTURER_COMPANY_ID);

    if (value_data)
        return GUINT_TO_POINTER((gulong)*value_data);

    return NULL;
}

static void bluetooth_eir_ad_tds_organization_id_prompt(packet_info *pinfo, gchar* result)
{
    guint8 *value_data;

    value_data = (guint8 *) p_get_proto_data(pinfo->pool, pinfo, proto_btcommon, PROTO_DATA_BLUETOOTH_EIR_AD_TDS_ORGANIZATION_ID);
    if (value_data)
        g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "TDS Organization ID 0x%02x as", (guint) *value_data);
    else
        g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Unknown TDS Organization ID");
}

static gpointer bluetooth_eir_ad_tds_organization_id_value(packet_info *pinfo)
{
    guint8 *value_data;

    value_data = (guint8 *) p_get_proto_data(pinfo->pool, pinfo, proto_btcommon, PROTO_DATA_BLUETOOTH_EIR_AD_TDS_ORGANIZATION_ID);

    if (value_data)
        return GUINT_TO_POINTER((gulong)*value_data);

    return NULL;
}

static gint
dissect_eir_ad_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, bluetooth_eir_ad_data_t *bluetooth_eir_ad_data)
{
    proto_item  *entry_item;
    proto_tree  *entry_tree;
    proto_item  *sub_item;
    proto_tree  *sub_tree;
    gint         offset = 0;
    gint         offset_start;
    guint8       length;
    guint8       sub_length;
    guint8       type;
    guint8       flags;
    gint         data_size;
    gint64       end_offset;
    gboolean     has_bd_addr = FALSE;
    guint8       bd_addr[6];
    guint8      *name = NULL;
    bluetooth_uuid_t uuid;

    DISSECTOR_ASSERT(bluetooth_eir_ad_data);

    data_size = tvb_reported_length(tvb);

    while (offset < data_size) {
        length = tvb_get_guint8(tvb, offset);
        if (length <= 0) break;

        type = tvb_get_guint8(tvb, offset + 1);

        entry_item = proto_tree_add_none_format(tree, hf_btcommon_eir_ad_entry, tvb, offset, length + 1, "%s",
                val_to_str_const(type, bthci_cmd_eir_data_type_vals, "Unknown"));
        entry_tree = proto_item_add_subtree(entry_item, ett_eir_ad_entry);

        proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_length, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_type, tvb, offset, 1, ENC_NA);
        offset += 1;
        length -= 1;

        offset_start = offset;

        switch (type) {
        case 0x01: /* Flags */
            proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_flags_reserved, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_flags_le_bredr_support_host, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_flags_le_bredr_support_controller, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_flags_bredr_not_support, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_flags_le_general_discoverable_mode, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_flags_le_limited_discoverable_mode, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 0x02: /* 16-bit Service Class UUIDs (incomplete) */
        case 0x03: /* 16-bit Service Class UUIDs */
        case 0x14: /* List of 16-bit Service Solicitation UUIDs */
            end_offset = offset + length;
            while (offset < end_offset) {
                proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_uuid_16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
            }

            break;
        case 0x04: /* 32-bit Service Class UUIDs (incomplete) */
        case 0x05: /* 32-bit Service Class UUIDs */
        case 0x1F: /* List of 32-bit Service Solicitation UUIDs */
            end_offset = offset + length;
            while (offset < end_offset) {
                uuid = get_uuid(tvb, offset, 4);
                if (uuid.bt_uuid) {
                    sub_item = proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_uuid_32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    proto_item_append_text(sub_item, " (%s)", val_to_str_ext_const(uuid.bt_uuid, &bluetooth_uuid_vals_ext, "Unknown"));
                } else {
                    sub_item = proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_custom_uuid_32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    proto_item_append_text(sub_item, " (%s)", print_uuid(&uuid));
                }

                offset += 4;
            }

            break;
        case 0x06: /* 128-bit Service Class UUIDs (incomplete) */
        case 0x07: /* 128-bit Service Class UUIDs */
        case 0x15: /* List of 128-bit Service Solicitation UUIDs */
            end_offset = offset + length;
            while (offset < end_offset) {
                uuid = get_uuid(tvb, offset, 16);
                if (uuid.bt_uuid) {
                    sub_item = proto_tree_add_bytes_format_value(entry_tree, hf_btcommon_eir_ad_uuid_128, tvb, offset, 16, uuid.data, "%s", print_numeric_uuid(&uuid));
                    proto_item_append_text(sub_item, " (%s)", val_to_str_ext_const(uuid.bt_uuid, &bluetooth_uuid_vals_ext, "Unknown"));
                }
                else {
                    sub_item = proto_tree_add_bytes_format_value(entry_tree, hf_btcommon_eir_ad_custom_uuid_128, tvb, offset, 16, uuid.data, "%s", print_numeric_uuid(&uuid));
                    proto_item_append_text(sub_item, " (%s)", print_uuid(&uuid));
                }

                offset += 16;
            }

            break;

        case 0x08: /* Device Name (shortened) */
        case 0x09: /* Device Name */
            proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_name, tvb, offset, length, ENC_UTF_8 | ENC_NA);
            proto_item_append_text(entry_item, ": %s", tvb_format_text(tvb, offset, length));
            if (!name || type == 0x09)
                name = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, length, ENC_UTF_8);
            offset += length;

            break;
        case 0x10: /* Device ID / Security Manager TK Value */
            if (length == 16) { /* little heuristic for recognize Security Manager TK Value */
                sub_item = proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_data, tvb, offset, 16, ENC_NA);
                expert_add_info(pinfo, sub_item, &ei_eir_ad_undecoded);
            }
            else if (length == 8) { /* DID */
                guint16       vendor_id_source;
                guint16       vendor_id;
                guint16       product_id;
                const gchar  *str_val;

                proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_did_vendor_id_source, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                vendor_id_source = tvb_get_letohs(tvb, offset);
                offset += 2;

                if (vendor_id_source == DID_VENDOR_ID_SOURCE_BLUETOOTH_SIG) {
                    proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_did_vendor_id_bluetooth_sig, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                }
                else if (vendor_id_source == DID_VENDOR_ID_SOURCE_USB_FORUM) {
                    proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_did_vendor_id_usb_forum, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                }
                else {
                    proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_did_vendor_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                }
                vendor_id = tvb_get_letohs(tvb, offset);
                offset += 2;

                sub_item = proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_did_product_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                product_id = tvb_get_letohs(tvb, offset);
                offset += 2;

                if (vendor_id_source == DID_VENDOR_ID_SOURCE_USB_FORUM) {
                    str_val = val_to_str_ext_const(vendor_id << 16 | product_id, &ext_usb_products_vals, "Unknown");
                    proto_item_append_text(sub_item, " (%s)", str_val);
                }

                proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_did_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
            }
            else {
                sub_item = proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_data, tvb, offset, length, ENC_NA);
                expert_add_info(pinfo, sub_item, &ei_command_unknown_command);
            }

            break;
        case 0x0A: /* Tx Power Level */
            proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_tx_power, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 0x0B: /* OOB Optional Data Length */
            /* From CSS v3.pdf */
            proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_ssp_oob_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            break;
        case 0x0C: /* BD_ADDR */
            /* From CSS v3.pdf */
            offset = dissect_bd_addr(hf_btcommon_eir_ad_bd_addr, pinfo, tree, tvb, offset, FALSE, bluetooth_eir_ad_data->interface_id, bluetooth_eir_ad_data->adapter_id, bd_addr);
            has_bd_addr = TRUE;
            break;

        case 0x0D: /* Class Of Device */
            call_dissector(btcommon_cod_handle, tvb_new_subset_length(tvb, offset, 3), pinfo, entry_tree);
            offset += 3;

            break;
        case 0x0E: /* Simple Pairing Hash C */
        case 0x1D: /* Simple Pairing Hash C-256 */
            proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_hash_c, tvb, offset, 16, ENC_NA);
            offset += 16;

            break;
        case 0x0F: /* Simple Pairing Randomizer R */
        case 0x1E: /* Simple Pairing Randomizer R-256 */
            proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_randomizer_r, tvb, offset, 16, ENC_NA);
            offset += 16;

            break;
        case 0x11: /* Security Manager Out of Band Flags */
            proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_oob_flags_reserved, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_oob_flags_address_type, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_oob_flags_le_bredr_support, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_oob_flags_le_supported_host, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_oob_flags_data_present, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 0x12: /* Slave Connection Interval Range */
            sub_item = proto_tree_add_item(tree, hf_btcommon_eir_ad_connection_interval_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(sub_item, " (%g msec)", tvb_get_letohs(tvb, offset) * 1.25);
            offset += 2;

            sub_item = proto_tree_add_item(tree, hf_btcommon_eir_ad_connection_interval_max, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(sub_item, " (%g msec)", tvb_get_letohs(tvb, offset) * 1.25);
            offset += 2;

            proto_item_append_text(entry_item, ": %g - %g msec", tvb_get_letohs(tvb, offset - 4) * 1.25, tvb_get_letohs(tvb, offset - 2) * 1.25);

            break;
        case 0x16: /* Service Data - 16 bit UUID  */
            proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_uuid_16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            if (length - 2 > 0) {
                uuid = get_uuid(tvb, offset-2, 2);
                /* XXX A dissector table should be used here if we get many of these*/
                if (uuid.bt_uuid == 0xFD6F) /* GAEN Identifier */
                {
                    call_dissector(gaen_handle, tvb, pinfo, entry_tree);
                }
                else
                {
                    proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_service_data, tvb, offset, length - 2, ENC_NA);
                }
                offset += length - 2;
            }
            break;
        case 0x20: /* Service Data - 32 bit UUID */
            uuid = get_uuid(tvb, offset, 4);
            if (uuid.bt_uuid) {
                sub_item = proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_uuid_32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_item_append_text(sub_item, " (%s)", val_to_str_ext_const(uuid.bt_uuid, &bluetooth_uuid_vals_ext, "Unknown"));
            }
            else {
                sub_item = proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_custom_uuid_32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_item_append_text(sub_item, " (%s)", print_uuid(&uuid));
            }
            offset += 4;

            if (length - 4 > 0) {
                proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_service_data, tvb, offset, length - 4, ENC_NA);
                offset += length - 4;
            }
            break;
        case 0x21: /* Service Data - 128 bit UUID */
            uuid = get_uuid(tvb, offset, 16);
            if (uuid.bt_uuid) {
                sub_item = proto_tree_add_bytes_format_value(entry_tree, hf_btcommon_eir_ad_uuid_128, tvb, offset, 16, uuid.data, "%s", print_numeric_uuid(&uuid));
                proto_item_append_text(sub_item, " (%s)", val_to_str_ext_const(uuid.bt_uuid, &bluetooth_uuid_vals_ext, "Unknown"));
            }
            else {
                sub_item = proto_tree_add_bytes_format_value(entry_tree, hf_btcommon_eir_ad_custom_uuid_128, tvb, offset, 16, uuid.data, "%s", print_numeric_uuid(&uuid));
                proto_item_append_text(sub_item, " (%s)", print_uuid(&uuid));
            }
            offset += 16;

            if (length - 16 > 0) {
                proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_service_data, tvb, offset, length - 16, ENC_NA);
                offset += length - 16;
            }
            break;
        case 0x17: /* Public Target Address */
        case 0x18: /* Random Target Address */
            end_offset = offset + length;
            while (offset < end_offset) {
                offset = dissect_bd_addr(hf_btcommon_eir_ad_bd_addr, pinfo, entry_tree, tvb, offset, FALSE, bluetooth_eir_ad_data->interface_id, bluetooth_eir_ad_data->adapter_id, NULL);
            }

            break;
        case 0x19: /* Appearance */
            proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_appearance, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(entry_item, ": %s", val_to_str(tvb_get_letohs(tvb, offset), bthci_cmd_appearance_vals, "Unknown"));
            offset += 2;

            break;
        case 0x1A: /* Advertising Interval */
            /* From CSS v3.pdf */
            sub_item = proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_advertising_interval, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(sub_item, " (%g msec)", tvb_get_letohs(tvb, offset) * 0.625);
            offset += 2;

            break;
        case 0x1B: /* LE Bluetooth Device Address */
            proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_le_bd_addr_reserved, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_le_bd_addr_type, tvb, offset, 1, ENC_NA);
            offset += 1;

            offset = dissect_bd_addr(hf_btcommon_eir_ad_bd_addr, pinfo, entry_tree, tvb, offset, FALSE, bluetooth_eir_ad_data->interface_id, bluetooth_eir_ad_data->adapter_id, NULL);

            break;
        case 0x1C: /* LE Role */
            proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_le_role, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 0x22: /* LE Secure Connections Confirmation Value" */
            proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_le_secure_confirmation_value, tvb, offset, 16, ENC_NA);
            offset += 16;

            break;
        case 0x23: /* LE Secure Connections Random Value" */
            proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_le_secure_random_value, tvb, offset, 16, ENC_NA);
            offset += 16;

            break;
        case 0x24: /* URI */
            proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_uri, tvb, offset, length, ENC_UTF_8 | ENC_NA);
            offset += length;

            break;
        case 0x25: /* Indoor Positioning */
            if (length == 0)
                break;

            sub_item = proto_tree_add_bitmask(entry_tree, tvb, offset, hf_btcommon_eir_ad_ips_flags, ett_eir_ad_entry, hfx_btcommon_eir_ad_ips_flags, ENC_LITTLE_ENDIAN);
            flags = tvb_get_guint8(tvb, offset);
            offset += 1;

            if (flags & 0x01) {
                proto_tree_add_item(tree, hf_btcommon_eir_ad_ips_latitude, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                proto_tree_add_item(tree, hf_btcommon_eir_ad_ips_longitude, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                proto_tree_add_item(tree, hf_btcommon_eir_ad_ips_local_north_coordinate, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(tree, hf_btcommon_eir_ad_ips_local_east_coordinate, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
            }

            if (flags & 0x04) {
                proto_tree_add_item(tree, hf_btcommon_eir_ad_ips_tx_power_level, tvb, offset, 1, ENC_NA);
                offset += 1;
            }

            if (flags & 0x08) {
                proto_tree_add_item(tree, hf_btcommon_eir_ad_ips_altitude, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
            }

            if (flags & 0x10) {
                proto_tree_add_item(tree, hf_btcommon_eir_ad_ips_floor_number, tvb, offset, 1, ENC_NA);
                offset += 1;
            }

            if (flags & 0x20) {
                proto_tree_add_bitmask(tree, tvb, offset, hf_btcommon_eir_ad_ips_uncertainty, ett_eir_ad_entry, hfx_btcommon_eir_ad_ips_uncertainty, ENC_NA);
                offset += 1;
            }

            if (flags & 0xC0) {
                expert_add_info(pinfo, sub_item, &ei_eir_ad_not_used);
            }

            break;
        case 0x26: /* Transport Discovery Data */
            end_offset = offset + length;
            while (offset < end_offset) {
                guint8 organization_id;

                proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_tds_organization_id, tvb, offset, 1, ENC_NA);
                organization_id = tvb_get_guint8(tvb, offset);
                offset += 1;

                if (p_get_proto_data(pinfo->pool, pinfo, proto_btcommon, PROTO_DATA_BLUETOOTH_EIR_AD_TDS_ORGANIZATION_ID) == NULL) {
                    guint8 *value_data;

                    value_data = wmem_new(wmem_file_scope(), guint8);
                    *value_data = organization_id;

                    p_add_proto_data(pinfo->pool, pinfo, proto_btcommon, PROTO_DATA_BLUETOOTH_EIR_AD_TDS_ORGANIZATION_ID, value_data);
                }

                proto_tree_add_bitmask(entry_tree, tvb, offset, hf_btcommon_eir_ad_tds_flags, ett_eir_ad_entry, hfx_btcommon_eir_ad_tds_flags, ENC_NA);
                offset += 1;

                sub_item = proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_tds_data_length, tvb, offset, 1, ENC_NA);
                sub_length = tvb_get_guint8(tvb, offset);
                offset += 1;

                if (length > 3 && sub_length > length - 3) {
                    expert_add_info(pinfo, sub_item, &ei_eir_ad_invalid_length);
                }

                if (sub_length > 0) {
                    tvbuff_t  *new_tvb;

                    new_tvb = tvb_new_subset_length(tvb, offset, sub_length);

                    if (!dissector_try_uint_new(bluetooth_eir_ad_tds_organization_id, organization_id, new_tvb, pinfo, tree, TRUE, bluetooth_eir_ad_data)) {
                        sub_item = proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_tds_data, tvb, offset, sub_length, ENC_NA);
                        expert_add_info(pinfo, sub_item, &ei_eir_ad_undecoded);
                    }

                    offset += length;
                }

                length -= (3 + sub_length);
            }

            break;
        case 0x27: {/* LE Supported Features */
            for (guint8 i=0; (tvb_captured_length_remaining(tvb, offset) > 0) && (i < 8); i++) {
                proto_tree_add_bitmask(entry_tree, tvb, offset, hf_btcommon_eir_ad_le_features, ett_eir_ad_le_features, hfx_btcommon_eir_ad_le_features[i], ENC_NA);
                offset += 1;
            }

            sub_length = tvb_captured_length_remaining(tvb, offset);
            if (sub_length > 0) {
                sub_item = proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_data, tvb, offset, sub_length, ENC_NA);
                expert_add_info(pinfo, sub_item, &ei_eir_ad_unknown);
                offset += sub_length;
            }
        }
                   break;
        case 0x28: /* Channel Map Update Indication */
            sub_item = proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_le_channel_map, tvb, offset, 5, ENC_NA);
            sub_tree = proto_item_add_subtree(sub_item, ett_le_channel_map);

            call_dissector(btcommon_le_channel_map_handle, tvb_new_subset_length(tvb, offset, 5), pinfo, sub_tree);
            offset += 5;

            proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_instant, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            break;
        case 0x3D: /* 3D Information Data */
            proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_3ds_factory_test_mode, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_3ds_reserved, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_3ds_send_battery_level_report_on_startup, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_3ds_battery_level_reporting, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_3ds_association_notification, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_3ds_path_loss_threshold, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 0x29: /* PB-ADV */
            if (btmesh_pbadv_handle) {
                call_dissector(btmesh_pbadv_handle, tvb_new_subset_length(tvb, offset, length), pinfo, proto_tree_get_root(tree));
            } else {
                proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_mesh_pbadv, tvb, offset, length, ENC_NA);
            }
            offset += length;

            break;
        case 0x2a: /* Mesh Message */
            if (btmesh_handle) {
                call_dissector(btmesh_handle, tvb_new_subset_length(tvb, offset, length), pinfo, proto_tree_get_root(tree));
            } else {
                proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_mesh_msg, tvb, offset, length, ENC_NA);
            }
            offset += length;

            break;
        case 0x2b: /* Mesh Beacon */
            if (btmesh_beacon_handle) {
                call_dissector(btmesh_beacon_handle, tvb_new_subset_length(tvb, offset, length), pinfo, proto_tree_get_root(tree));
            } else {
                proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_mesh_beacon, tvb, offset, length, ENC_NA);
            }
            offset += length;

            break;
        case 0xFF: /* Manufacturer Specific */ {
            guint16  company_id;

            proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_company_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            company_id = tvb_get_letohs(tvb, offset);
            offset += 2;
            length -= 2;

            if (p_get_proto_data(pinfo->pool, pinfo, proto_btcommon, PROTO_DATA_BLUETOOTH_EIR_AD_MANUFACTURER_COMPANY_ID) == NULL) {
                guint16 *value_data;

                value_data = wmem_new(wmem_file_scope(), guint16);
                *value_data = company_id;

                p_add_proto_data(pinfo->pool, pinfo, proto_btcommon, PROTO_DATA_BLUETOOTH_EIR_AD_MANUFACTURER_COMPANY_ID, value_data);
            }

            if (company_id == 0x000F && tvb_get_guint8(tvb, offset) == 0) { /* 3DS profile Legacy Devices */
                proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_3ds_legacy_fixed, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_3ds_legacy_test_mode, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_3ds_legacy_fixed_6, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_3ds_legacy_ignored_5, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_3ds_legacy_fixed_4, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_3ds_legacy_ignored_1_3, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_3ds_legacy_3d_capable_tv, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_3ds_legacy_path_loss_threshold, tvb, offset, 1, ENC_NA);
                offset += 1;
            } else {
                tvbuff_t  *new_tvb;

                new_tvb = tvb_new_subset_length(tvb, offset, length);

                if (!dissector_try_uint_new(bluetooth_eir_ad_manufacturer_company_id, company_id, new_tvb, pinfo, entry_tree, TRUE, bluetooth_eir_ad_data)) {
                    sub_item = proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_data, tvb, offset, length, ENC_NA);
                    expert_add_info(pinfo, sub_item, &ei_eir_ad_undecoded);
                }

                offset += length;
            }
            }
            break;
        default:
            sub_item = proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_data, tvb, offset, length, ENC_NA);
            expert_add_info(pinfo, sub_item, &ei_eir_ad_unknown);
            offset += length;
        }

        if (offset - offset_start > 0 && offset - offset_start < length) {
            sub_item = proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_data, tvb, offset, length - (offset - offset_start), ENC_NA);
            expert_add_info(pinfo, sub_item, &ei_eir_ad_unknown);
            offset += length - (offset - offset_start);
        }
    }

    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        proto_tree_add_item(tree, hf_btcommon_eir_ad_unused, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
        offset = tvb_reported_length(tvb);
    }

    if  (bluetooth_eir_ad_data && bluetooth_eir_ad_data->bd_addr && name && have_tap_listener(bluetooth_device_tap)) {
        bluetooth_device_tap_t  *tap_device;

        tap_device = wmem_new(wmem_packet_scope(), bluetooth_device_tap_t);
        tap_device->interface_id  = bluetooth_eir_ad_data->interface_id;
        tap_device->adapter_id    = bluetooth_eir_ad_data->adapter_id;
        memcpy(tap_device->bd_addr, bluetooth_eir_ad_data->bd_addr, 6);
        tap_device->has_bd_addr = TRUE;
        tap_device->is_local = FALSE;
        tap_device->type = BLUETOOTH_DEVICE_NAME;
        tap_device->data.name = name;
        tap_queue_packet(bluetooth_device_tap, pinfo, tap_device);
    }

    if (has_bd_addr && name && have_tap_listener(bluetooth_device_tap)) {
        bluetooth_device_tap_t  *tap_device;

        tap_device = wmem_new(wmem_packet_scope(), bluetooth_device_tap_t);
        if (bluetooth_eir_ad_data) {
            tap_device->interface_id  = bluetooth_eir_ad_data->interface_id;
            tap_device->adapter_id    = bluetooth_eir_ad_data->adapter_id;
        } else {
            tap_device->interface_id  = HCI_INTERFACE_DEFAULT;
            tap_device->adapter_id    = HCI_ADAPTER_DEFAULT;
        }
        memcpy(tap_device->bd_addr, bd_addr, 6);
        tap_device->has_bd_addr = TRUE;
        tap_device->is_local = FALSE;
        tap_device->type = BLUETOOTH_DEVICE_NAME;
        tap_device->data.name = name;
        tap_queue_packet(bluetooth_device_tap, pinfo, tap_device);
    }

    return offset + data_size;
}

static gint
dissect_btcommon_cod(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item  *cod_item;
    proto_item  *cod_tree;
    guint16      major_service_classes;
    guint8       major_device_class;
    guint8       minor_device_class;
    const gchar *minor_device_class_name;
    gint         offset = 0;

    cod_item = proto_tree_add_item(tree, hf_btcommon_cod_class_of_device, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    cod_tree = proto_item_add_subtree(cod_item, ett_cod);

    major_device_class = tvb_get_guint8(tvb, offset + 1) & 0x1F;
    minor_device_class = tvb_get_guint8(tvb, offset) >> 2;

    switch(major_device_class) {
    case 0x01: /* Computer */
        proto_tree_add_item(cod_tree, hf_btcommon_cod_minor_device_class_computer, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        minor_device_class_name = val_to_str_ext_const(minor_device_class, &bthci_cmd_cod_minor_device_class_computer_vals_ext, "Unknown");
        break;
    case 0x02: /* Phone */
        proto_tree_add_item(cod_tree, hf_btcommon_cod_minor_device_class_phone, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        minor_device_class_name = val_to_str_ext_const(minor_device_class, &bthci_cmd_cod_minor_device_class_phone_vals_ext, "Unknown");
        break;
    case 0x03: /* LAN/Network Access Point */
        proto_tree_add_item(cod_tree, hf_btcommon_cod_minor_device_class_lan_net_load_factor, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cod_tree, hf_btcommon_cod_minor_device_class_lan_net_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        minor_device_class_name = val_to_str_ext_const(minor_device_class, &bthci_cmd_cod_minor_device_class_lan_net_load_factor_vals_ext, "Unknown");
        break;
    case 0x04: /* Audio/Video */
        proto_tree_add_item(cod_tree, hf_btcommon_cod_minor_device_class_audio_video, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        minor_device_class_name = val_to_str_ext_const(minor_device_class, &bthci_cmd_cod_minor_device_class_audio_video_vals_ext, "Unknown");
        break;
    case 0x05: /* Peripheral */
        proto_tree_add_item(cod_tree, hf_btcommon_cod_minor_device_class_peripheral_class, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cod_tree, hf_btcommon_cod_minor_device_class_peripheral_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        minor_device_class_name = val_to_str_ext_const(minor_device_class, &bthci_cmd_cod_minor_device_class_peripheral_class_vals_ext, "Unknown");
        break;
    case 0x06: /* Imaging */
        proto_tree_add_item(cod_tree, hf_btcommon_cod_minor_device_class_imaging_class_printer, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cod_tree, hf_btcommon_cod_minor_device_class_imaging_class_scanner, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cod_tree, hf_btcommon_cod_minor_device_class_imaging_class_camera, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cod_tree, hf_btcommon_cod_minor_device_class_imaging_class_display, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        proto_tree_add_item(cod_tree, hf_btcommon_cod_minor_device_class_imaging_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        minor_device_class_name = val_to_str_ext_const(minor_device_class, &bthci_cmd_cod_minor_device_class_imaging_type_vals_ext, "Unknown");
        break;
    case 0x07: /* Wearable */
        proto_tree_add_item(cod_tree, hf_btcommon_cod_minor_device_class_wearable, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        minor_device_class_name = val_to_str_ext_const(minor_device_class, &bthci_cmd_cod_minor_device_class_wearable_vals_ext, "Unknown");
        break;
    case 0x08: /* Toy */
        proto_tree_add_item(cod_tree, hf_btcommon_cod_minor_device_class_toy, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        minor_device_class_name = val_to_str_ext_const(minor_device_class, &bthci_cmd_cod_minor_device_class_toy_vals_ext, "Unknown");
        break;
    case 0x09: /* Health */
        proto_tree_add_item(cod_tree, hf_btcommon_cod_minor_device_class_health, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        minor_device_class_name = val_to_str_ext_const(minor_device_class, &bthci_cmd_cod_minor_device_class_health_vals_ext, "Unknown");
        break;
    default:
        minor_device_class_name = "Unknown";
        proto_tree_add_item(cod_tree, hf_btcommon_cod_minor_device_class_unknown, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    }

    proto_tree_add_item(cod_tree, hf_btcommon_cod_format_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    proto_tree_add_item(cod_tree, hf_btcommon_cod_major_service_class_information, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cod_tree, hf_btcommon_cod_major_service_class_telephony, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cod_tree, hf_btcommon_cod_major_service_class_audio, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cod_tree, hf_btcommon_cod_major_service_class_object_transfer, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cod_tree, hf_btcommon_cod_major_service_class_capturing, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cod_tree, hf_btcommon_cod_major_service_class_rendering, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cod_tree, hf_btcommon_cod_major_service_class_networking, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cod_tree, hf_btcommon_cod_major_service_class_positioning, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cod_tree, hf_btcommon_cod_major_service_class_reserved, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cod_tree, hf_btcommon_cod_major_service_class_limited_discoverable_mode, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    major_service_classes = tvb_get_letohs(tvb, offset) >> 5;

    proto_tree_add_item(cod_tree, hf_btcommon_cod_major_device_class, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_item_append_text(cod_item, " (%s:%s - services:",
            val_to_str_ext_const(major_device_class, &bthci_cmd_cod_major_device_class_vals_ext, "Unknown"),
            minor_device_class_name);

    if (major_service_classes & 0x001) proto_item_append_text(cod_item, " LimitedDiscoverableMode");
    if (major_service_classes & 0x008) proto_item_append_text(cod_item, " Positioning");
    if (major_service_classes & 0x010) proto_item_append_text(cod_item, " Networking");

    if (major_service_classes & 0x020) proto_item_append_text(cod_item, " Rendering");
    if (major_service_classes & 0x040) proto_item_append_text(cod_item, " Capturing");
    if (major_service_classes & 0x080) proto_item_append_text(cod_item, " ObjectTransfer");
    if (major_service_classes & 0x100) proto_item_append_text(cod_item, " Audio");
    if (major_service_classes & 0x200) proto_item_append_text(cod_item, " Telephony");
    if (major_service_classes & 0x400) proto_item_append_text(cod_item, " Information");

    proto_item_append_text(cod_item, ")");

    return offset;
}

static gint
dissect_btcommon_ad(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item *main_item;
    proto_tree *main_tree;

    main_item = proto_tree_add_item(tree, hf_btcommon_eir_ad_advertising_data, tvb, 0, -1, ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_eir_ad);

    return dissect_eir_ad_data(tvb, pinfo, main_tree, (bluetooth_eir_ad_data_t *) data);
}

static gint
dissect_btcommon_eir(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item *main_item;
    proto_tree *main_tree;

    main_item = proto_tree_add_item(tree, hf_btcommon_eir_ad_extended_inquiry_response_data, tvb, 0, -1, ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_eir_ad);

    return dissect_eir_ad_data(tvb, pinfo, main_tree, (bluetooth_eir_ad_data_t *) data);
}

static gint
dissect_btcommon_le_channel_map(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data)
{
    gint offset = 0;
    gint *reserved_bits_offset = (gint *)data;

    proto_tree_add_item(tree, hf_btcommon_le_channel_map_0, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_btcommon_le_channel_map_1, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_btcommon_le_channel_map_2, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_btcommon_le_channel_map_3, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_btcommon_le_channel_map_4, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_btcommon_le_channel_map_5, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_btcommon_le_channel_map_6, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_btcommon_le_channel_map_7, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_btcommon_le_channel_map_8, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_btcommon_le_channel_map_9, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_btcommon_le_channel_map_10, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_btcommon_le_channel_map_11, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_btcommon_le_channel_map_12, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_btcommon_le_channel_map_13, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_btcommon_le_channel_map_14, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_btcommon_le_channel_map_15, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_btcommon_le_channel_map_16, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_btcommon_le_channel_map_17, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_btcommon_le_channel_map_18, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_btcommon_le_channel_map_19, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_btcommon_le_channel_map_20, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_btcommon_le_channel_map_21, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_btcommon_le_channel_map_22, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_btcommon_le_channel_map_23, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_btcommon_le_channel_map_24, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_btcommon_le_channel_map_25, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_btcommon_le_channel_map_26, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_btcommon_le_channel_map_27, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_btcommon_le_channel_map_28, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_btcommon_le_channel_map_29, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_btcommon_le_channel_map_30, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_btcommon_le_channel_map_31, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_btcommon_le_channel_map_32, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_btcommon_le_channel_map_33, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_btcommon_le_channel_map_34, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_btcommon_le_channel_map_35, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_btcommon_le_channel_map_36, tvb, offset, 1, ENC_NA);

    if (reserved_bits_offset) {
        *reserved_bits_offset = offset;
    } else {
        proto_tree_add_item(tree, hf_btcommon_le_channel_map_37, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_btcommon_le_channel_map_38, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_btcommon_le_channel_map_39, tvb, offset, 1, ENC_NA);
    }

    offset += 1;

    return offset;
}

void
proto_register_btcommon(void)
{
    expert_module_t  *expert_module;

    static hf_register_info hf[] = {
        { &hf_btcommon_eir_ad_extended_inquiry_response_data,
          { "Extended Inquiry Response Data",    "btcommon.eir_ad.extended_inquiry_response_data",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_advertising_data,
          { "Advertising Data",                  "btcommon.eir_ad.advertising_data",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_entry,
          { "Entry",                             "btcommon.eir_ad.entry",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_unused,
        { "Unused",                              "btcommon.eir_ad.unused",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_data,
          {"Data",                               "btcommon.eir_ad.entry.data",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_btcommon_eir_ad_service_data,
          {"Service Data",                       "btcommon.eir_ad.entry.service_data",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_btcommon_eir_ad_length,
          { "Length",                            "btcommon.eir_ad.entry.length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_type,
          { "Type",                              "btcommon.eir_ad.entry.type",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &bthci_cmd_eir_data_type_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_company_id,
          { "Company ID",                        "btcommon.eir_ad.entry.company_id",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bluetooth_company_id_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_flags_reserved,
          { "Reserved",                          "btcommon.eir_ad.entry.flags.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xE0,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_flags_le_bredr_support_host,
          { "Simultaneous LE and BR/EDR to Same Device Capable (Host)",        "btcommon.eir_ad.entry.flags.le_bredr_support_host",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x10,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_flags_le_bredr_support_controller,
          { "Simultaneous LE and BR/EDR to Same Device Capable (Controller)",  "btcommon.eir_ad.entry.flags.le_bredr_support_controller",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x08,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_flags_bredr_not_support,
          { "BR/EDR Not Supported",              "btcommon.eir_ad.entry.flags.bredr_not_supported",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x04,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_flags_le_general_discoverable_mode,
          { "LE General Discoverable Mode",      "btcommon.eir_ad.entry.flags.le_general_discoverable_mode",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x02,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_flags_le_limited_discoverable_mode,
          { "LE Limited Discoverable Mode",      "btcommon.eir_ad.entry.flags.le_limited_discoverable_mode",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x01,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_uuid_16,
            { "UUID 16",                         "btcommon.eir_ad.entry.uuid_16",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bluetooth_uuid_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_uuid_32,
            { "UUID 32",                         "btcommon.eir_ad.entry.uuid_32",
            FT_UINT32, BASE_HEX | BASE_EXT_STRING, &bluetooth_uuid_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_uuid_128,
            { "UUID 128",                        "btcommon.eir_ad.entry.uuid_128",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_custom_uuid_32,
            { "Custom UUID",                     "btcommon.eir_ad.entry.custom_uuid_32",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_custom_uuid_128,
            { "Custom UUID",                     "btcommon.eir_ad.entry.custom_uuid_128",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_name,
          { "Device Name",                       "btcommon.eir_ad.entry.device_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_tx_power,
          {"Power Level (dBm)",                  "btcommon.eir_ad.entry.power_level",
           FT_INT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_btcommon_eir_ad_ssp_oob_length,
          { "SSP OOB Length",                    "btcommon.eir_ad.entry.ssp_oob_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_bd_addr,
            { "BD_ADDR",                         "btcommon.eir_ad.entry.bd_addr",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_le_bd_addr_reserved,
            { "Reserved",                        "btcommon.eir_ad.entry.le_bd_addr.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xFE,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_le_bd_addr_type,
            { "Type",                            "btcommon.eir_ad.entry.le_bd_addr.type",
            FT_UINT8, BASE_HEX, VALS(bluetooth_address_type_vals), 0x01,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_le_role,
            { "Type",                            "btcommon.eir_ad.entry.le_role",
            FT_UINT8, BASE_HEX, VALS(le_role_vals), 0,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_did_vendor_id_source,
            { "Vendor ID Source",                "btcommon.eir_ad.entry.did.vendor_id_source",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &did_vendor_id_source_vals_ext, 0,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_did_vendor_id,
            { "Vendor ID",                       "btcommon.eir_ad.entry.did.vendor_id",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_did_vendor_id_bluetooth_sig,
            { "Vendor ID",                       "btcommon.eir_ad.entry.did.vendor_id",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bluetooth_company_id_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_did_vendor_id_usb_forum,
            { "Vendor ID",                       "btcommon.eir_ad.entry.did.vendor_id",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &ext_usb_vendors_vals, 0x0,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_did_product_id,
            { "Product ID",                      "btcommon.eir_ad.entry.did.product_id",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_did_version,
            { "Version",                         "btcommon.eir_ad.entry.did.version",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_3ds_association_notification,
          { "3DS Association Notification",                "btcommon.eir_ad.entry.3ds.association_notification",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_3ds_battery_level_reporting,
          { "3DS Battery Level Reporting",                 "btcommon.eir_ad.entry.3ds.battery_level_reporting",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_3ds_send_battery_level_report_on_startup,
          { "3DS Send Battery Level Report on Startup",    "btcommon.eir_ad.entry.3ds.send_battery_level_report_on_startup",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_3ds_reserved,
          { "Reserved",                                    "btcommon.eir_ad.entry.3ds.reserved",
            FT_BOOLEAN, 8, NULL, 0x78,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_3ds_factory_test_mode,
          { "3DS Factory Test Mode",                       "btcommon.eir_ad.entry.3ds.factory_test_mode",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_3ds_path_loss_threshold,
          { "3DS Path Loss Threshold",                     "btcommon.eir_ad.entry.3ds.path_loss_threshold",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_3ds_legacy_fixed,
          { "3DS Legacy Fixed",                            "btcommon.eir_ad.entry.3ds_legacy.fixed_byte",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_3ds_legacy_3d_capable_tv,
          { "3DS Legacy Capable TV",                       "btcommon.eir_ad.entry.3ds_legacy.capable_tv",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_3ds_legacy_ignored_1_3,
          { "3DS Legacy Ignored",                          "btcommon.eir_ad.entry.3ds_legacy.ignored.1_3",
            FT_BOOLEAN, 8, NULL, 0x0E,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_3ds_legacy_fixed_4,
          { "3DS Legacy Fixed",                            "btcommon.eir_ad.entry.3ds_legacy.fixed.4",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_3ds_legacy_ignored_5,
          { "3DS Legacy Ignored",                          "btcommon.eir_ad.entry.3ds_legacy.ignored.5",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_3ds_legacy_fixed_6,
          { "3DS Legacy Fixed",                            "btcommon.eir_ad.entry.3ds_legacy.fixed.4",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_3ds_legacy_test_mode,
          { "3DS Legacy Test Mode",                        "btcommon.eir_ad.entry.3ds_legacy.test_mode",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_3ds_legacy_path_loss_threshold,
          { "3DS Legacy Path Loss Threshold",              "btcommon.eir_ad.entry.3ds_legacy.path_loss_threshold",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_advertising_interval,
          { "Advertising Interval",              "btcommon.eir_ad.entry.advertising_interval",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_appearance,
          { "Appearance",                        "btcommon.eir_ad.entry.appearance",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bthci_cmd_appearance_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_hash_c,
          {"Hash C",                             "btcommon.eir_ad.entry.hash_c",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_btcommon_eir_ad_randomizer_r,
          {"Randomizer R",                       "btcommon.eir_ad.entry.randomizer_r",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_btcommon_eir_ad_le_secure_confirmation_value,
          {"LE Secure Connections Confirmation Value", "btcommon.eir_ad.entry.le_secure_confirmation_value",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_btcommon_eir_ad_le_secure_random_value,
          {"LE Secure Connections Random Value", "btcommon.eir_ad.entry.le_secure_random_value",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_btcommon_eir_ad_oob_flags_reserved,
          { "Reserved",                                                   "btcommon.eir_ad.entry.oob_flags.oob_reserved",
            FT_UINT8, BASE_HEX, NULL, 0xF0,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_oob_flags_address_type,
          { "Address Type",                                               "btcommon.eir_ad.entry.oob_flags.oob_address_type",
            FT_UINT8, BASE_HEX, VALS(bthci_cmd_address_types_vals), 0x08,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_oob_flags_le_bredr_support,
          { "Simultaneous LE and BR/EDR to Same Device Capable (Host)",   "btcommon.eir_ad.entry.oob_flags.oob_le_bredr_support",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x04,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_oob_flags_le_supported_host,
          { "LE Supported By Host",                                       "btcommon.eir_ad.entry.oob_flags.oob_le_supported_host",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x02,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_oob_flags_data_present,
          { "OOB Data Present",                                           "btcommon.eir_ad.entry.oob_flags.oob_data_present",
            FT_UINT8, BASE_HEX, VALS(cmd_boolean), 0x01,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_connection_interval_min,
          { "Connection Interval Min",           "btcommon.eir_ad.entry.connection_interval_min",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_connection_interval_max,
          { "Connection Interval Max",           "btcommon.eir_ad.entry.connection_interval_max",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_uri,
          {"URI",                                "btcommon.eir_ad.entry.uri",
           FT_STRING, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_btcommon_eir_ad_ips_flags,
            {"Indoor Positioning Configuration", "btcommon.eir_ad.entry.ips.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btcommon_eir_ad_ips_flags_reserved,
            {"Reserved", "btcommon.eir_ad.entry.ips.flags.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xC0,
            NULL, HFILL}
        },
        {&hf_btcommon_eir_ad_ips_flags_location_name,
            {"Location Name", "btcommon.eir_ad.entry.ips.flags.location_name",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL}
        },
        {&hf_btcommon_eir_ad_ips_flags_uncertainty,
            {"Uncertainty", "btcommon.eir_ad.entry.ips.flags.uncertainty",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL}
        },
        {&hf_btcommon_eir_ad_ips_flags_floor_number,
            {"Floor Number", "btcommon.eir_ad.entry.ips.flags.floor_number",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL}
        },
        {&hf_btcommon_eir_ad_ips_flags_altitude,
            {"Altitude", "btcommon.eir_ad.entry.ips.flags.altitude",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL}
        },
        {&hf_btcommon_eir_ad_ips_flags_tx_power,
            {"Tx Power", "btcommon.eir_ad.entry.ips.flags.tx_power",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL}
        },
        {&hf_btcommon_eir_ad_ips_flags_coordinate_system,
            {"Coordinate System", "btcommon.eir_ad.entry.ips.flags.coordinate_system",
            FT_UINT8, BASE_HEX, VALS(btatt_ips_coordinate_system), 0x02,
            NULL, HFILL}
        },
        {&hf_btcommon_eir_ad_ips_flags_coordinates,
            {"Coordinates", "btcommon.eir_ad.entry.ips.flags.coordinates",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        {&hf_btcommon_eir_ad_ips_uncertainty,
            {"Uncertainty", "btcommon.eir_ad.entry.ips.uncertainty",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btcommon_eir_ad_ips_uncertainty_reserved,
            {"Reserved", "btcommon.eir_ad.entry.ips.uncertainty.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x80,
            NULL, HFILL}
        },
        {&hf_btcommon_eir_ad_ips_uncertainty_precision,
            {"Precision", "btcommon.eir_ad.entry.ips.uncertainty.precision",
            FT_UINT8, BASE_HEX, VALS(btatt_ips_uncertainty_precision_vals), 0x70,
            NULL, HFILL}
        },
        {&hf_btcommon_eir_ad_ips_uncertainty_update_time,
            {"Update Time", "btcommon.eir_ad.entry.ips.uncertainty.update_time",
            FT_UINT8, BASE_HEX, VALS(btatt_ips_uncertainty_update_time_vals), 0x0E,
            NULL, HFILL}
        },
        {&hf_btcommon_eir_ad_ips_uncertainty_stationary,
            {"Stationary", "btcommon.eir_ad.entry.ips.uncertainty.stationary",
            FT_UINT8, BASE_HEX, VALS(btatt_ips_uncertainty_stationary_vals), 0x01,
            NULL, HFILL}
        },
        {&hf_btcommon_eir_ad_ips_latitude,
            {"Latitude", "btcommon.eir_ad.entry.ips.latitude",
            FT_INT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btcommon_eir_ad_ips_longitude,
            {"Longitude", "btcommon.eir_ad.entry.ips.longitude",
            FT_INT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btcommon_eir_ad_ips_local_north_coordinate,
            {"Local North Coordinate", "btcommon.eir_ad.entry.ips.local_north_coordinate",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btcommon_eir_ad_ips_local_east_coordinate,
            {"Local East Coordinate", "btcommon.eir_ad.entry.ips.local_east_coordinate",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btcommon_eir_ad_ips_floor_number,
            {"Floor Number", "btcommon.eir_ad.entry.ips.floor_number",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btcommon_eir_ad_ips_altitude,
            {"Altitude", "btcommon.eir_ad.entry.ips.altitude",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btcommon_eir_ad_ips_tx_power_level,
            {"Tx Power Level", "btcommon.eir_ad.entry.ips.tx_power_level",
            FT_INT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btcommon_eir_ad_tds_organization_id,
            {"Organization ID", "btcommon.eir_ad.entry.tds.organization_id",
            FT_UINT8, BASE_HEX, VALS(tds_organization_id_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btcommon_eir_ad_tds_flags,
            {"Flags", "btcommon.eir_ad.entry.tds.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btcommon_eir_ad_tds_flags_reserved,
            {"Reserved", "btcommon.eir_ad.entry.tds.flags.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xE0,
            NULL, HFILL}
        },
        {&hf_btcommon_eir_ad_tds_flags_transport_state,
            {"Transport State", "btcommon.eir_ad.entry.tds.flags.transport_state",
            FT_UINT8, BASE_HEX, VALS(tds_transport_state_vals), 0x18,
            NULL, HFILL}
        },
        {&hf_btcommon_eir_ad_tds_flags_transport_data_incomplete,
            {"Transport Data Incomplete", "btcommon.eir_ad.entry.tds.flags.transport_data_incomplete",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL}
        },
        {&hf_btcommon_eir_ad_tds_flags_role,
            {"Role", "btcommon.eir_ad.entry.tds.flags.role",
            FT_UINT8, BASE_HEX, VALS(tds_role_vals), 0x03,
            NULL, HFILL}
        },

        {&hf_btcommon_eir_ad_tds_data_length,
            {"Data Length", "btcommon.eir_ad.entry.tds.data_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btcommon_eir_ad_tds_data,
            {"Data", "btcommon.eir_ad.entry.tds.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_btcommon_eir_ad_le_features,
          { "LE Features", "btcommon.eir_ad.entry.le_features",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_le_channel_map,
          { "Channel Map", "btcommon.eir_ad.entry.le_channel_map",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_instant,
          { "Instant", "btcommon.eir_ad.entry.instant",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_le_features_encryption,
          { "LE Encryption",                               "btcommon.eir_ad.le_features.encryption",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_le_features_connection_parameters_request_procedure,
          { "Connection Parameters Request Procedure",     "btcommon.eir_ad.le_features.connection_parameters_request_procedure",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_le_features_extended_reject_indication,
          { "Extended Reject Indication",                  "btcommon.eir_ad.le_features.extended_reject_indication",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_le_features_slave_initiated_features_exchange,
          { "Slave-Initiated Features Exchange",           "btcommon.eir_ad.le_features.slave_initiated_features_exchange",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_le_features_ping,
          { "Ping",                                        "btcommon.eir_ad.le_features.ping",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_le_features_data_packet_length_extension,
          { "Data Packet Length Extension",                "btcommon.eir_ad.le_features.data_packet_length_extension",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_le_features_ll_privacy,
          { "LL Privacy",                                  "btcommon.eir_ad.le_features.ll_privacy",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_le_features_extended_scanner_filter_policies,
          { "Extended Scanner Filter Policies",            "btcommon.eir_ad.le_features.extended_scanner_filter_policies",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_le_features_2m_phy,
          { "LE 2M PHY",            "btcommon.eir_ad.le_features.2m_phy",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_le_features_stable_modulation_index_tx,
          { "Stable Modulation Index - Tx",            "btcommon.eir_ad.le_features.stable_modulation_index_tx",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_le_features_stable_modulation_index_rx,
          { "Stable Modulation Index - Rx",      "btcommon.eir_ad.le_features.stable_modulation_index_rx",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_le_features_coded_phy,
          { "LE Coded PHY",                      "btcommon.eir_ad.le_features.coded_phy",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_le_features_extended_advertising,
          { "LE Extended Advertising",           "btcommon.eir_ad.le_features.extended_advertising",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_le_features_periodic_advertising,
          { "LE Periodic Advertising",           "btcommon.eir_ad.le_features.periodic_advertising",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_le_features_channel_selection_algorithm_2,
          { "Channel Selection Algorithm #2",    "btcommon.eir_ad.le_features.channel_selection_algorithm_2",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_le_features_power_class_1,
          { "Power Class 1",                     "btcommon.eir_ad.le_features.power_class_1",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_le_features_minimum_number_of_used_channels_procedure,
          { "Minimum Number of Used Channels Procedure", "btcommon.eir_ad.entry.le_features.minimum_number_of_used_channels_procedure",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_le_features_reserved_1_7,
          { "Reserved", "btcommon.eir_ad.entry.le_features.reserved.1_7",
            FT_UINT8, BASE_HEX, NULL, 0xFE,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_le_features_reserved,
          { "Reserved", "btcommon.eir_ad.entry.le_features.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xFF,
            NULL, HFILL }
        },
        { &hf_btcommon_cod_class_of_device,
          { "Class of Device", "btcommon.cod.class_of_device",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btcommon_cod_major_service_class_information,
          { "Major Service Classes: Information", "btcommon.cod.major_service_classes.information",
            FT_BOOLEAN, 16, NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_btcommon_cod_major_service_class_telephony,
          { "Major Service Classes: Telephony", "btcommon.cod.major_service_classes.telephony",
            FT_BOOLEAN, 16, NULL, 0x4000,
            NULL, HFILL }
        },
        { &hf_btcommon_cod_major_service_class_audio,
          { "Major Service Classes: Audio", "btcommon.cod.major_service_classes.audio",
            FT_BOOLEAN, 16, NULL, 0x2000,
            NULL, HFILL }
        },
        { &hf_btcommon_cod_major_service_class_object_transfer,
          { "Major Service Classes: Object Transfer", "btcommon.cod.major_service_classes.object_transfer",
            FT_BOOLEAN, 16, NULL, 0x1000,
            NULL, HFILL }
        },
        { &hf_btcommon_cod_major_service_class_capturing,
          { "Major Service Classes: Capturing", "btcommon.cod.major_service_classes.capturing",
            FT_BOOLEAN, 16, NULL, 0x0800,
            NULL, HFILL }
        },
        { &hf_btcommon_cod_major_service_class_rendering,
          { "Major Service Classes: Rendering", "btcommon.cod.major_service_classes.rendering",
            FT_BOOLEAN, 16, NULL, 0x0400,
            NULL, HFILL }
        },
        { &hf_btcommon_cod_major_service_class_networking,
          { "Major Service Classes: Networking", "btcommon.cod.major_service_classes.networking",
            FT_BOOLEAN, 16, NULL, 0x0200,
            NULL, HFILL }
        },
        { &hf_btcommon_cod_major_service_class_positioning,
          { "Major Service Classes: Positioning", "btcommon.cod.major_service_classes.positioning",
            FT_BOOLEAN, 16, NULL, 0x0100,
            NULL, HFILL }
        },
        { &hf_btcommon_cod_major_service_class_reserved,
          { "Major Service Classes: Reserved", "btcommon.cod.major_service_classes.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x00C0,
            NULL, HFILL }
        },
        { &hf_btcommon_cod_major_service_class_limited_discoverable_mode,
          { "Major Service Classes: Limited Discoverable Mode", "btcommon.cod.major_service_classes.limited_discoverable_mode",
            FT_BOOLEAN, 16, NULL, 0x0020,
            NULL, HFILL }
        },
        { &hf_btcommon_cod_major_device_class,
          { "Major Device Class", "btcommon.cod.major_device_class",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bthci_cmd_cod_major_device_class_vals_ext, 0x1F,
            NULL, HFILL }
        },
        { &hf_btcommon_cod_minor_device_class_computer,
          { "Minor Device Class", "btcommon.cod.minor_device_class",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &bthci_cmd_cod_minor_device_class_computer_vals_ext, 0xFC,
            NULL, HFILL }
        },
        { &hf_btcommon_cod_minor_device_class_phone,
          { "Minor Device Class", "btcommon.cod.minor_device_class",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &bthci_cmd_cod_minor_device_class_phone_vals_ext, 0xFC,
            NULL, HFILL }
        },
        { &hf_btcommon_cod_minor_device_class_lan_net_load_factor,
          { "Minor Device Class: Load Factor", "btcommon.cod.minor_device_class.load_factor",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &bthci_cmd_cod_minor_device_class_lan_net_load_factor_vals_ext, 0xE0,
            NULL, HFILL }
        },
        { &hf_btcommon_cod_minor_device_class_lan_net_type,
          { "Minor Device Class: Type", "btcommon.cod.minor_device_class.type",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &bthci_cmd_cod_minor_device_class_lan_net_type_vals_ext, 0x1C,
            NULL, HFILL }
        },
        { &hf_btcommon_cod_minor_device_class_audio_video,
          { "Minor Device Class", "btcommon.cod.minor_device_class",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &bthci_cmd_cod_minor_device_class_audio_video_vals_ext, 0xFC,
            NULL, HFILL }
        },
        { &hf_btcommon_cod_minor_device_class_peripheral_class,
          { "Minor Device Class", "btcommon.cod.minor_device_class",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &bthci_cmd_cod_minor_device_class_peripheral_class_vals_ext, 0xC0,
            NULL, HFILL }
        },
        { &hf_btcommon_cod_minor_device_class_peripheral_type,
          { "Minor Device Class", "btcommon.cod.minor_device_class",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &bthci_cmd_cod_minor_device_class_peripheral_type_vals_ext, 0x3C,
            NULL, HFILL }
        },
        { &hf_btcommon_cod_minor_device_class_imaging_class_printer,
          { "Minor Device Class: Class: Printer", "btcommon.cod.minor_device_class.class.printer",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &bthci_cmd_cod_minor_device_class_imaging_type_vals_ext, 0x80,
            NULL, HFILL }
        },
        { &hf_btcommon_cod_minor_device_class_imaging_class_scanner,
          { "Minor Device Class: Class: Scanner", "btcommon.cod.minor_device_class.class.scanner",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &bthci_cmd_cod_minor_device_class_imaging_type_vals_ext, 0x40,
            NULL, HFILL }
        },
        { &hf_btcommon_cod_minor_device_class_imaging_class_camera,
          { "Minor Device Class: Class: Camera", "btcommon.cod.minor_device_class.class.camera",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &bthci_cmd_cod_minor_device_class_imaging_type_vals_ext, 0x20,
            NULL, HFILL }
        },
        { &hf_btcommon_cod_minor_device_class_imaging_class_display,
          { "Minor Device Class: Class: Display", "btcommon.cod.minor_device_class.class.display",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &bthci_cmd_cod_minor_device_class_imaging_type_vals_ext, 0x10,
            NULL, HFILL }
        },
        { &hf_btcommon_cod_minor_device_class_imaging_type,
          { "Minor Device Class: Type", "btcommon.cod.minor_device_class.type",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &bthci_cmd_cod_minor_device_class_imaging_type_vals_ext, 0x0C,
            NULL, HFILL }
        },
        { &hf_btcommon_cod_minor_device_class_wearable,
          { "Minor Device Class", "btcommon.cod.minor_device_class",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &bthci_cmd_cod_minor_device_class_wearable_vals_ext, 0xFC,
            NULL, HFILL }
        },
        { &hf_btcommon_cod_minor_device_class_toy,
          { "Minor Device Class", "btcommon.cod.minor_device_class",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &bthci_cmd_cod_minor_device_class_toy_vals_ext, 0xFC,
            NULL, HFILL }
        },
        { &hf_btcommon_cod_minor_device_class_health,
          { "Minor Device Class", "btcommon.cod.minor_device_class",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &bthci_cmd_cod_minor_device_class_health_vals_ext, 0xFC,
            NULL, HFILL }
        },
        { &hf_btcommon_cod_minor_device_class_unknown,
          { "Minor Device Class", "btcommon.cod.minor_device_class",
            FT_UINT8, BASE_HEX, NULL, 0xFC,
            NULL, HFILL }
        },
        { &hf_btcommon_cod_format_type,
          { "Format Type", "btcommon.cod.format_type",
            FT_UINT8, BASE_HEX, NULL, 0x03,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_39,
            { "Reserved",                                            "btcommon.le_channel_map.39",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_38,
            { "Reserved",                                            "btcommon.le_channel_map.38",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_37,
            { "Reserved",                                            "btcommon.le_channel_map.37",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_36,
            { "RF Channel 38 (2478 MHz - Data - 36)",                "btcommon.le_channel_map.36",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_35,
            { "RF Channel 37 (2476 MHz - Data - 35)",                "btcommon.le_channel_map.35",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_34,
            { "RF Channel 36 (2474 MHz - Data - 34)",                "btcommon.le_channel_map.34",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_33,
            { "RF Channel 35 (2472 MHz - Data - 33)",                "btcommon.le_channel_map.33",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_32,
            { "RF Channel 34 (2470 MHz - Data - 32)",                "btcommon.le_channel_map.32",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_31,
            { "RF Channel 33 (2468 MHz - Data - 31)",                "btcommon.le_channel_map.31",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_30,
            { "RF Channel 32 (2466 MHz - Data - 30)",                "btcommon.le_channel_map.30",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_29,
            { "RF Channel 31 (2464 MHz - Data - 29)",                "btcommon.le_channel_map.29",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_28,
            { "RF Channel 30 (2462 MHz - Data - 28)",                "btcommon.le_channel_map.28",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_27,
            { "RF Channel 29 (2460 MHz - Data - 27)",                "btcommon.le_channel_map.27",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_26,
            { "RF Channel 28 (2458 MHz - Data - 26)",                "btcommon.le_channel_map.26",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_25,
            { "RF Channel 27 (2456 MHz - Data - 25)",                "btcommon.le_channel_map.25",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_24,
            { "RF Channel 26 (2454 MHz - Data - 24)",                "btcommon.le_channel_map.24",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_23,
            { "RF Channel 25 (2452 MHz - Data - 23)",                "btcommon.le_channel_map.23",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_22,
            { "RF Channel 24 (2450 MHz - Data - 22)",                "btcommon.le_channel_map.22",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_21,
            { "RF Channel 23 (2448 MHz - Data - 21)",                "btcommon.le_channel_map.21",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_20,
            { "RF Channel 22 (2446 MHz - Data - 20)",                "btcommon.le_channel_map.20",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_19,
            { "RF Channel 21 (2444 MHz - Data - 19)",                "btcommon.le_channel_map.19",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_18,
            { "RF Channel 20 (2442 MHz - Data - 18)",                "btcommon.le_channel_map.18",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_17,
            { "RF Channel 19 (2440 MHz - Data - 17)",                "btcommon.le_channel_map.17",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_16,
            { "RF Channel 18 (2438 MHz - Data - 16)",                "btcommon.le_channel_map.16",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_15,
            { "RF Channel 17 (2436 MHz - Data - 15)",                "btcommon.le_channel_map.15",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_14,
            { "RF Channel 16 (2434 MHz - Data - 14)",                "btcommon.le_channel_map.14",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_13,
            { "RF Channel 15 (2432 MHz - Data - 13)",                "btcommon.le_channel_map.13",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_12,
            { "RF Channel 14 (2430 MHz - Data - 12)",                "btcommon.le_channel_map.12",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_11,
            { "RF Channel 13 (2428 MHz - Data - 11)",                "btcommon.le_channel_map.11",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_10,
            { "RF Channel 11 (2424 MHz - Data - 10)",                "btcommon.le_channel_map.10",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_9,
            { "RF Channel 10 (2422 MHz - Data - 9)",                 "btcommon.le_channel_map.9",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_8,
            { "RF Channel 9 (2420 MHz - Data - 8)",                  "btcommon.le_channel_map.8",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_7,
            { "RF Channel 8 (2418 MHz - Data - 7)",                  "btcommon.le_channel_map.7",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_6,
            { "RF Channel 7 (2416 MHz - Data - 6)",                  "btcommon.le_channel_map.6",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_5,
            { "RF Channel 6 (2414 MHz - Data - 5)",                  "btcommon.le_channel_map.5",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_4,
            { "RF Channel 5 (2412 MHz - Data - 4)",                  "btcommon.le_channel_map.4",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_3,
            { "RF Channel 4 (2410 MHz - Data - 3)",                  "btcommon.le_channel_map.3",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_2,
            { "RF Channel 3 (2408 MHz - Data - 2)",                  "btcommon.le_channel_map.2",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_1,
            { "RF Channel 2 (2406 MHz - Data - 1)",                  "btcommon.le_channel_map.1",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_btcommon_le_channel_map_0,
            { "RF Channel 1 (2404 MHz - Data - 0)",                  "btcommon.le_channel_map.0",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_mesh_msg,
            { "Mesh message content",        "btcommon.eir_ad.entry.mesh_msg",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_mesh_pbadv,
            { "Mesh PB-ADV message content",        "btcommon.eir_ad.entry.mesh_pbadv",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_mesh_beacon,
            { "Mesh Beacon message content",        "btcommon.eir_ad.entry.mesh_beacon",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_eir_ad,
        &ett_eir_ad_entry,
        &ett_eir_ad_le_features,
    };

    static ei_register_info ei[] = {
        { &ei_eir_ad_undecoded,       { "btcommon.eir_ad.undecoded",      PI_UNDECODED, PI_NOTE, "Undecoded", EXPFILL }},
        { &ei_eir_ad_unknown,         { "btcommon.eir_ad.unknown",        PI_PROTOCOL,  PI_WARN, "Unknown data", EXPFILL }},
        { &ei_eir_ad_not_used,        { "btcommon.eir_ad.not_used",       PI_PROTOCOL,  PI_WARN, "Value should not be used", EXPFILL }},
        { &ei_eir_ad_invalid_length,  { "btcommon.eir_ad.invalid_length", PI_PROTOCOL,  PI_WARN, "Invalid Length", EXPFILL }},
    };

    static build_valid_func bluetooth_eir_ad_manufacturer_company_id_da_build_value[1] = {bluetooth_eir_ad_manufacturer_company_id_value};
    static decode_as_value_t bluetooth_eir_ad_manufacturer_company_id_da_values = {bluetooth_eir_ad_manufacturer_company_id_prompt, 1, bluetooth_eir_ad_manufacturer_company_id_da_build_value};
    static decode_as_t bluetooth_eir_ad_manufacturer_company_id_da = {"btcommon.eir_ad", "btcommon.eir_ad.manufacturer_company_id", 1, 0, &bluetooth_eir_ad_manufacturer_company_id_da_values, NULL, NULL,
                                 decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

    static build_valid_func bluetooth_eir_ad_tds_organization_id_da_build_value[1] = {bluetooth_eir_ad_tds_organization_id_value};
    static decode_as_value_t bluetooth_eir_ad_tds_organization_id_da_values = {bluetooth_eir_ad_tds_organization_id_prompt, 1, bluetooth_eir_ad_tds_organization_id_da_build_value};
    static decode_as_t bluetooth_eir_ad_tds_organization_id_da = {"btcommon.eir_ad", "btcommon.eir_ad.tds_organization_id", 1, 0, &bluetooth_eir_ad_tds_organization_id_da_values, NULL, NULL,
                                 decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

    proto_btcommon = proto_register_protocol("Bluetooth Common", "BT Common", "btcommon");

    proto_register_field_array(proto_btcommon, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_module = expert_register_protocol(proto_btcommon);
    expert_register_field_array(expert_module, ei, array_length(ei));
    (void )ei_command_undecoded; /* Not needed not, but there is upcoming Bluetooth 5 */

    btcommon_ad_handle  = register_dissector("btcommon.eir_ad.ad",  dissect_btcommon_ad,  proto_btcommon);
    btcommon_eir_handle = register_dissector("btcommon.eir_ad.eir", dissect_btcommon_eir, proto_btcommon);
    btcommon_cod_handle = register_dissector("btcommon.cod",        dissect_btcommon_cod, proto_btcommon);
    btcommon_le_channel_map_handle = register_dissector("btcommon.le_channel_map", dissect_btcommon_le_channel_map, proto_btcommon);

    bluetooth_eir_ad_manufacturer_company_id = register_dissector_table("btcommon.eir_ad.manufacturer_company_id", "BT EIR/AD Manufacturer Company ID", proto_btcommon, FT_UINT16, BASE_HEX);
    bluetooth_eir_ad_tds_organization_id     = register_dissector_table("btcommon.eir_ad.tds_organization_id",     "BT EIR/AD TDS Organization ID", proto_btcommon, FT_UINT8, BASE_HEX);

    register_decode_as(&bluetooth_eir_ad_manufacturer_company_id_da);
    register_decode_as(&bluetooth_eir_ad_tds_organization_id_da);
}

void
proto_reg_handoff_btcommon(void)
{
    btmesh_handle = find_dissector("btmesh.msg");
    btmesh_pbadv_handle = find_dissector("btmesh.pbadv");
    btmesh_beacon_handle = find_dissector("btmesh.beacon");
    gaen_handle = find_dissector("bluetooth.gaen");
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
