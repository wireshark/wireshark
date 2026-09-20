/* packet-bthci_vendor_android.c
 * Routines for the Bluetooth HCI Vendors Commands/Events
 *
 * Copyright 2014, Michal Labedzki for Tieto Corporation
 * Copyright 2024, Jakub Rotkiewicz for Google LLC
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
#include <epan/tap.h>
#include <epan/unit_strings.h>

#include "packet-bluetooth.h"
#include "packet-bthci_cmd.h"
#include "packet-bthci_evt.h"


static int proto_bthci_vendor_android;

static int hf_android_opcode;
static int hf_android_opcode_ogf;
static int hf_android_opcode_ocf;
static int hf_android_parameter_length;
static int hf_android_number_of_allowed_command_packets;
static int hf_android_event_code;
static int hf_android_le_advertising_filter_subcode;
static int hf_android_apcf_enable;
static int hf_android_apcf_action;
static int hf_android_apcf_filter_index;
static int hf_android_apcf_available_spaces;
static int hf_android_apcf_feature_selection;
static int hf_android_apcf_feature_broadcast_address;
static int hf_android_apcf_feature_service_data_change;
static int hf_android_apcf_feature_service_uuid;
static int hf_android_apcf_feature_service_solicitation_uuid;
static int hf_android_apcf_feature_local_name;
static int hf_android_apcf_feature_manufacturer_data;
static int hf_android_apcf_feature_service_data;
static int hf_android_apcf_feature_transport_discovery_service;
static int hf_android_apcf_feature_ad_type;
static int hf_android_apcf_feature_reserved;
static int hf_android_apcf_list_logic;
static int hf_android_apcf_list_logic_broadcast_address;
static int hf_android_apcf_list_logic_service_data_change;
static int hf_android_apcf_list_logic_service_uuid;
static int hf_android_apcf_list_logic_service_solicitation_uuid;
static int hf_android_apcf_list_logic_local_name;
static int hf_android_apcf_list_logic_manufacturer_data;
static int hf_android_apcf_list_logic_service_data;
static int hf_android_apcf_list_logic_transport_discovery_service;
static int hf_android_apcf_list_logic_ad_type;
static int hf_android_apcf_list_logic_reserved;
static int hf_android_apcf_filter_logic_type;
static int hf_android_apcf_rssi_high_threshold;
static int hf_android_apcf_delivery_mode;
static int hf_android_apcf_onfound_timeout;
static int hf_android_apcf_onfound_timeout_count;
static int hf_android_apcf_rssi_low_threshold;
static int hf_android_apcf_onlost_timeout;
static int hf_android_apcf_num_of_tracking_entries;
static int hf_android_apcf_broadcaster_address;
static int hf_android_apcf_application_address_type;
static int hf_android_apcf_uuid;
static int hf_android_apcf_uuid_mask;
static int hf_android_apcf_data;
static int hf_android_apcf_mask;
static int hf_android_apcf_ad_type;
static int hf_android_apcf_ad_data_length;
static int hf_android_apcf_ad_data;
static int hf_android_apcf_ad_data_mask;
static int hf_android_apcf_extended_features;
static int hf_android_apcf_extended_features_transport_discovery_service;
static int hf_android_apcf_extended_features_ad_type;
static int hf_android_apcf_extended_features_reserved;

/* Bluetooth Quality Report (BQR) fields. */
static int hf_android_bqr_link_packet_type;
static int hf_android_bqr_link_connection_handle;
static int hf_android_bqr_link_connection_role;
static int hf_android_bqr_link_tx_power;
static int hf_android_bqr_link_rssi;
static int hf_android_bqr_link_snr;
static int hf_android_bqr_link_unused_afh_channels;
static int hf_android_bqr_link_afh_unideal_channels;
static int hf_android_bqr_link_retransmission_count;
static int hf_android_bqr_link_no_rx_count;
static int hf_android_bqr_link_nak_count;
static int hf_android_bqr_link_flow_off_count;
static int hf_android_bqr_link_buffer_overflow_bytes;
static int hf_android_bqr_link_buffer_underflow_bytes;
static int hf_android_bqr_link_cal_failed_item_count;
static int hf_android_bqr_link_tx_total_packets;
static int hf_android_bqr_link_tx_unacked_packets;
static int hf_android_bqr_link_tx_flushed_packets;
static int hf_android_bqr_link_tx_last_subevent_packets;
static int hf_android_bqr_link_crc_error_packets;
static int hf_android_bqr_link_rx_duplicate_packets;
static int hf_android_bqr_link_rx_unreceived_packets;
static int hf_android_bqr_root_error_code;
static int hf_android_bqr_root_vendor_error_code;
static int hf_android_bqr_energy_average_current;
static int hf_android_bqr_energy_idle_total_time;
static int hf_android_bqr_energy_idle_enter_count;
static int hf_android_bqr_energy_active_total_time;
static int hf_android_bqr_energy_active_enter_count;
static int hf_android_bqr_energy_bredr_tx_total_time;
static int hf_android_bqr_energy_bredr_tx_enter_count;
static int hf_android_bqr_energy_bredr_tx_avg_power;
static int hf_android_bqr_energy_bredr_rx_total_time;
static int hf_android_bqr_energy_bredr_rx_enter_count;
static int hf_android_bqr_energy_le_tx_total_time;
static int hf_android_bqr_energy_le_tx_enter_count;
static int hf_android_bqr_energy_le_tx_avg_power;
static int hf_android_bqr_energy_le_rx_total_time;
static int hf_android_bqr_energy_le_rx_enter_count;
static int hf_android_bqr_energy_report_time_duration;
static int hf_android_bqr_energy_rx_active_one_chain_time;
static int hf_android_bqr_energy_rx_active_two_chain_time;
static int hf_android_bqr_energy_tx_ipa_active_one_chain_time;
static int hf_android_bqr_energy_tx_ipa_active_two_chain_time;
static int hf_android_bqr_energy_tx_epa_active_one_chain_time;
static int hf_android_bqr_energy_tx_epa_active_two_chain_time;
static int hf_android_bqr_energy_bredr_rx_scan_total_time;
static int hf_android_bqr_energy_le_rx_scan_total_time;
static int hf_android_bqr_advanced_extension_info;
static int hf_android_bqr_advanced_report_time_period;
static int hf_android_bqr_advanced_tx_power_ipa_bf;
static int hf_android_bqr_advanced_tx_power_epa_bf;
static int hf_android_bqr_advanced_tx_power_ipa_div;
static int hf_android_bqr_advanced_tx_power_epa_div;
static int hf_android_bqr_advanced_rssi_chain_50;
static int hf_android_bqr_advanced_rssi_chain_50_55;
static int hf_android_bqr_advanced_rssi_chain_55_60;
static int hf_android_bqr_advanced_rssi_chain_60_65;
static int hf_android_bqr_advanced_rssi_chain_65_70;
static int hf_android_bqr_advanced_rssi_chain_70_75;
static int hf_android_bqr_advanced_rssi_chain_75_80;
static int hf_android_bqr_advanced_rssi_chain_80_85;
static int hf_android_bqr_advanced_rssi_chain_85_90;
static int hf_android_bqr_advanced_rssi_chain_90;
static int hf_android_bqr_advanced_rssi_delta_2;
static int hf_android_bqr_advanced_rssi_delta_2_5;
static int hf_android_bqr_advanced_rssi_delta_5_8;
static int hf_android_bqr_advanced_rssi_delta_8_11;
static int hf_android_bqr_advanced_rssi_delta_11;
static int hf_android_bqr_advanced_antenna_switch_count;
static int hf_android_bqr_advanced_retx_ipa_bf;
static int hf_android_bqr_advanced_retx_epa_bf;
static int hf_android_bqr_advanced_retx_ipa_div;
static int hf_android_bqr_advanced_retx_epa_div;
static int hf_android_bqr_advanced_channel_count_good;
static int hf_android_bqr_advanced_channel_count_ok;
static int hf_android_bqr_advanced_channel_count_bad;
static int hf_android_bqr_advanced_channel_count_very_bad;
static int hf_android_bqr_health_packet_count_host_to_controller;
static int hf_android_bqr_health_packet_count_controller_to_host;
static int hf_android_bqr_health_last_packet_length_host_to_controller;
static int hf_android_bqr_health_last_packet_length_controller_to_host;
static int hf_android_bqr_health_total_bt_wake_count;
static int hf_android_bqr_health_total_host_wake_count;
static int hf_android_bqr_health_last_bt_wake_timestamp;
static int hf_android_bqr_health_last_host_wake_timestamp;
static int hf_android_bqr_health_reset_timestamp;
static int hf_android_bqr_health_current_timestamp;
static int hf_android_bqr_health_watchdog_expiring;
static int hf_android_bqr_health_coex_status_mask;
static int hf_android_bqr_health_total_links_bredr_le_active;
static int hf_android_bqr_health_total_links_bredr_sniff;
static int hf_android_bqr_health_total_links_cis;
static int hf_android_bqr_health_is_sco_active;
static int hf_android_bqr_log_connection_handle;
static int hf_android_bqr_lea_big_handle;
static int hf_android_bqr_lea_source_bd_addr_type;
static int hf_android_bqr_lea_source_bd_addr;
static int hf_android_bqr_lea_source_prefer_channel_map;
static int hf_android_bqr_lea_source_used_channel_map;
static int hf_android_bqr_lea_tx_power;
static int hf_android_bqr_lea_subscribed_broadcast_id;
static int hf_android_bqr_lea_receiver_bd_addr_type;
static int hf_android_bqr_lea_receiver_bd_addr;
static int hf_android_bqr_lea_time_duration;
static int hf_android_bqr_lea_bis_choppy_count;
static int hf_android_bqr_lea_per;
static int hf_android_bqr_lea_no_sync;
static int hf_android_bqr_lea_receiver_prefer_channel_map;
static int hf_android_bqr_lea_receiver_tx_power;
static int hf_android_bqr_lea_rssi;
static int hf_android_bqr_lea_reserved;

/* Fields needing custom formatting or nested bitmasks, declared explicitly. */
static int hf_android_bqr_link_lsto;
static int hf_android_bqr_link_piconet_clock;
static int hf_android_bqr_link_last_tx_ack_timestamp;
static int hf_android_bqr_link_last_flow_on_timestamp;
static int hf_android_bqr_lea_timestamp;
static int hf_android_bqr_link_coex_info_mask;
static int hf_android_bqr_link_coex_involvement;
static int hf_android_bqr_link_coex_wl_2g_active;
static int hf_android_bqr_link_coex_wl_2g_connected;
static int hf_android_bqr_link_coex_wl_5g_6g_active;
static int hf_android_bqr_link_coex_reserved;
static int hf_android_bqr_advanced_tx_buffer_queue_count;
static int hf_android_bqr_advanced_tx_buffer_acl_1;
static int hf_android_bqr_advanced_tx_buffer_acl_2;
static int hf_android_bqr_advanced_tx_buffer_leconn_1;
static int hf_android_bqr_advanced_tx_buffer_leconn_2;
static int hf_android_bqr_advanced_tx_buffer_leisoc_1;
static int hf_android_bqr_advanced_tx_buffer_leisoc_2;
static int hf_android_bqr_advanced_tx_buffer_lebroadcast;
static int hf_android_bqr_advanced_tx_buffer_reserved;
static int hf_android_bqr_vendor_data;
static int hf_android_subevent_code;
static int hf_android_quality_report_id;
static int hf_android_bqr_action;
static int hf_android_bqr_minimum_report_interval;
static int hf_android_bqr_vendor_quality_event_mask;
static int hf_android_bqr_vendor_trace_mask;
static int hf_android_bqr_report_interval_multiple;
static int hf_android_quality_event_mask;
static int hf_android_quality_event_mask_quality_monitoring;
static int hf_android_quality_event_mask_approaching_lsto;
static int hf_android_quality_event_mask_a2dp_choppy;
static int hf_android_quality_event_mask_esco_choppy;
static int hf_android_quality_event_mask_root_inflammation;
static int hf_android_quality_event_mask_energy_monitor;
static int hf_android_quality_event_mask_le_audio_choppy;
static int hf_android_quality_event_mask_connect_fail;
static int hf_android_quality_event_mask_advanced_rf_trigger;
static int hf_android_quality_event_mask_advanced_rf_periodic;
static int hf_android_quality_event_mask_controller_health_trigger;
static int hf_android_quality_event_mask_controller_health_periodic;
static int hf_android_quality_event_mask_reserved;
static int hf_android_quality_event_mask_vendor_quality;
static int hf_android_quality_event_mask_lmp_trace;
static int hf_android_quality_event_mask_coex_trace;
static int hf_android_quality_event_mask_controller_debug;
static int hf_android_quality_event_mask_offload_debug_reserved;
static int hf_android_quality_event_mask_uart_history;
static int hf_android_quality_event_mask_reserved_2;
static int hf_android_quality_event_mask_vendor_trace;
static int hf_android_bqr_current_quality_event_mask;
static int hf_android_bqr_current_vendor_quality_event_mask;
static int hf_android_bqr_current_vendor_trace_mask;
static int hf_android_bqr_report_interval;
static int hf_android_status;
static int hf_android_bd_addr;
static int hf_android_data;
static int hf_android_max_advertising_instance;
static int hf_android_max_advertising_instance_reserved;
static int hf_android_resolvable_private_address_offloading;
static int hf_android_resolvable_private_address_offloading_reserved;
static int hf_android_total_scan_results;
static int hf_android_max_irk_list;
static int hf_android_filter_support;
static int hf_android_max_filter;
static int hf_android_energy_support;
static int hf_android_version_support;
static int hf_android_version_major;
static int hf_android_version_minor;
static int hf_android_total_num_of_advt_tracked;
static int hf_android_extended_scan_support;
static int hf_android_debug_logging_support;
static int hf_android_le_address_generation_offloading_support;
static int hf_android_le_address_generation_offloading_support_reserved;
static int hf_android_a2dp_source_offload_capability_mask;
static int hf_android_a2dp_source_offload_capability_mask_sbc;
static int hf_android_a2dp_source_offload_capability_mask_aac;
static int hf_android_a2dp_source_offload_capability_mask_aptx;
static int hf_android_a2dp_source_offload_capability_mask_aptx_hd;
static int hf_android_a2dp_source_offload_capability_mask_ldac;
static int hf_android_a2dp_source_offload_capability_mask_opus;
static int hf_android_a2dp_source_offload_capability_mask_reserved;
static int hf_android_bluetooth_quality_report_support;
static int hf_android_dynamic_audio_buffer_support_mask;
static int hf_android_dynamic_audio_buffer_support_mask_sbc;
static int hf_android_dynamic_audio_buffer_support_mask_aac;
static int hf_android_dynamic_audio_buffer_support_mask_aptx;
static int hf_android_dynamic_audio_buffer_support_mask_aptx_hd;
static int hf_android_dynamic_audio_buffer_support_mask_ldac;
static int hf_android_dynamic_audio_buffer_support_mask_opus;
static int hf_android_dynamic_audio_buffer_support_mask_reserved;
static int hf_android_a2dp_offload_v2_support;
static int hf_android_iso_link_layer_feedback_supported;
static int hf_android_sniff_offload_supported;
static int hf_android_big_channel_map_support;
static int hf_android_big_channel_map_support_bit0;
static int hf_android_big_channel_map_support_reserved;
static int hf_android_vendor_connection_handle_min;
static int hf_android_vendor_connection_handle_max;
static int hf_android_connection_proximity_threshold;
static int hf_android_le_energy_total_rx_time;
static int hf_android_le_energy_total_tx_time;
static int hf_android_le_energy_total_idle_time;
static int hf_android_le_energy_total_energy_used;
static int hf_android_le_batch_scan_subcode;
static int hf_android_le_batch_scan_report_format;
static int hf_android_le_batch_scan_number_of_records;
static int hf_android_le_batch_scan_mode;
static int hf_android_le_batch_scan_enable;
static int hf_android_le_batch_scan_full_max;
static int hf_android_le_batch_scan_truncate_max;
static int hf_android_le_batch_scan_notify_threshold;
static int hf_android_le_batch_scan_window;
static int hf_android_le_batch_scan_interval;
static int hf_android_le_batch_scan_address_type;
static int hf_android_le_batch_scan_discard_rule;
static int hf_android_le_multi_advertising_subcode;
static int hf_android_le_multi_advertising_enable;
static int hf_android_le_multi_advertising_instance_id;
static int hf_android_le_multi_advertising_type;
static int hf_android_le_multi_advertising_min_interval;
static int hf_android_le_multi_advertising_max_interval;
static int hf_android_le_multi_advertising_address_type;
static int hf_android_le_multi_advertising_filter_policy;
static int hf_android_le_multi_advertising_tx_power;
static int hf_android_le_multi_advertising_channel_map;
static int hf_android_le_multi_advertising_channel_map_reserved;
static int hf_android_le_multi_advertising_channel_map_39;
static int hf_android_le_multi_advertising_channel_map_38;
static int hf_android_le_multi_advertising_channel_map_37;
static int hf_android_a2dp_hardware_offload_subcode;
static int hf_android_a2dp_hardware_offload_start_legacy_codec;
static int hf_android_a2dp_hardware_offload_start_legacy_max_latency;
static int hf_android_a2dp_hardware_offload_start_legacy_scms_t_enable_flag;
static int hf_android_a2dp_hardware_offload_start_legacy_scms_t_enable_value;
static int hf_android_a2dp_hardware_offload_start_legacy_scms_t_enable_value_reserved;
static int hf_android_a2dp_hardware_offload_start_legacy_sampling_frequency;
static int hf_android_a2dp_hardware_offload_start_legacy_bits_per_sample;
static int hf_android_a2dp_hardware_offload_start_legacy_channel_mode;
static int hf_android_a2dp_hardware_offload_start_legacy_encoded_audio_bitrate;
static int hf_android_a2dp_hardware_offload_start_legacy_encoded_audio_bitrate_unspecified;
static int hf_android_a2dp_hardware_offload_start_legacy_encoded_audio_bitrate_reserved;
static int hf_android_a2dp_hardware_offload_start_legacy_connection_handle;
static int hf_android_a2dp_hardware_offload_start_legacy_l2cap_cid;
static int hf_android_a2dp_hardware_offload_start_legacy_l2cap_mtu_size;
static int hf_android_a2dp_hardware_offload_start_legacy_codec_information;
static int hf_android_a2dp_hardware_offload_start_legacy_codec_information_sbc_block_length;
static int hf_android_a2dp_hardware_offload_start_legacy_codec_information_sbc_subbands;
static int hf_android_a2dp_hardware_offload_start_legacy_codec_information_sbc_allocation_method;
static int hf_android_a2dp_hardware_offload_start_legacy_codec_information_sbc_min_bitpool;
static int hf_android_a2dp_hardware_offload_start_legacy_codec_information_sbc_max_bitpool;
static int hf_android_a2dp_hardware_offload_start_legacy_codec_information_sbc_sampling_frequency;
static int hf_android_a2dp_hardware_offload_start_legacy_codec_information_sbc_channel_mode;
static int hf_android_a2dp_hardware_offload_start_legacy_codec_information_sbc_reserved;
static int hf_android_a2dp_hardware_offload_start_legacy_codec_information_aac_object_type;
static int hf_android_a2dp_hardware_offload_start_legacy_codec_information_aac_vbr;
static int hf_android_a2dp_hardware_offload_start_legacy_codec_information_aac_reserved;
static int hf_android_a2dp_hardware_offload_start_legacy_codec_information_ldac_vendor_id;
static int hf_android_a2dp_hardware_offload_start_legacy_codec_information_ldac_codec_id;
static int hf_android_a2dp_hardware_offload_start_legacy_codec_information_ldac_bitrate_index;
static int hf_android_a2dp_hardware_offload_start_legacy_codec_information_ldac_bitrate_index_reserved;
static int hf_android_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode_mask;
static int hf_android_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode_mask_stereo;
static int hf_android_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode_mask_dual;
static int hf_android_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode_mask_mono;
static int hf_android_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode_mask_reserved;
static int hf_android_a2dp_hardware_offload_start_legacy_codec_information_ldac_reserved;
static int hf_android_a2dp_hardware_offload_start_legacy_codec_information_reserved;
static int hf_android_a2dp_hardware_offload_start_connection_handle;
static int hf_android_a2dp_hardware_offload_start_l2cap_cid;
static int hf_android_a2dp_hardware_offload_start_data_path_direction;
static int hf_android_a2dp_hardware_offload_start_peer_mtu;
static int hf_android_a2dp_hardware_offload_start_cp_enable_scmst;
static int hf_android_a2dp_hardware_offload_start_cp_header_scmst;
static int hf_android_a2dp_hardware_offload_start_cp_header_scmst_reserved;
static int hf_android_a2dp_hardware_offload_start_vendor_specific_parameters_length;
static int hf_android_a2dp_hardware_offload_start_vendor_specific_parameters;
static int hf_android_a2dp_hardware_offload_stop_connection_handle;
static int hf_android_a2dp_hardware_offload_stop_l2cap_cid;
static int hf_android_a2dp_hardware_offload_stop_data_path_direction;


static int * const hfx_android_le_multi_advertising_channel_map[] = {
    &hf_android_le_multi_advertising_channel_map_reserved,
    &hf_android_le_multi_advertising_channel_map_39,
    &hf_android_le_multi_advertising_channel_map_38,
    &hf_android_le_multi_advertising_channel_map_37,
    NULL
};

static int * const hfx_android_a2dp_source_offload_capability[] = {
    &hf_android_a2dp_source_offload_capability_mask_sbc,
    &hf_android_a2dp_source_offload_capability_mask_aac,
    &hf_android_a2dp_source_offload_capability_mask_aptx,
    &hf_android_a2dp_source_offload_capability_mask_aptx_hd,
    &hf_android_a2dp_source_offload_capability_mask_ldac,
    &hf_android_a2dp_source_offload_capability_mask_opus,
    &hf_android_a2dp_source_offload_capability_mask_reserved,
    NULL
};

static int * const hfx_android_dynamic_audio_buffer_support[] = {
    &hf_android_dynamic_audio_buffer_support_mask_sbc,
    &hf_android_dynamic_audio_buffer_support_mask_aac,
    &hf_android_dynamic_audio_buffer_support_mask_aptx,
    &hf_android_dynamic_audio_buffer_support_mask_aptx_hd,
    &hf_android_dynamic_audio_buffer_support_mask_ldac,
    &hf_android_dynamic_audio_buffer_support_mask_opus,
    &hf_android_dynamic_audio_buffer_support_mask_reserved,
    NULL
};

static int * const hfx_android_big_channel_map_support[] = {
    &hf_android_big_channel_map_support_bit0,
    &hf_android_big_channel_map_support_reserved,
    NULL
};

static int * const hfx_android_apcf_feature_selection[] = {
    &hf_android_apcf_feature_broadcast_address,
    &hf_android_apcf_feature_service_data_change,
    &hf_android_apcf_feature_service_uuid,
    &hf_android_apcf_feature_service_solicitation_uuid,
    &hf_android_apcf_feature_local_name,
    &hf_android_apcf_feature_manufacturer_data,
    &hf_android_apcf_feature_service_data,
    &hf_android_apcf_feature_transport_discovery_service,
    &hf_android_apcf_feature_ad_type,
    &hf_android_apcf_feature_reserved,
    NULL
};

static int * const hfx_android_apcf_list_logic[] = {
    &hf_android_apcf_list_logic_broadcast_address,
    &hf_android_apcf_list_logic_service_data_change,
    &hf_android_apcf_list_logic_service_uuid,
    &hf_android_apcf_list_logic_service_solicitation_uuid,
    &hf_android_apcf_list_logic_local_name,
    &hf_android_apcf_list_logic_manufacturer_data,
    &hf_android_apcf_list_logic_service_data,
    &hf_android_apcf_list_logic_transport_discovery_service,
    &hf_android_apcf_list_logic_ad_type,
    &hf_android_apcf_list_logic_reserved,
    NULL
};

static int * const hfx_android_apcf_extended_features[] = {
    &hf_android_apcf_extended_features_transport_discovery_service,
    &hf_android_apcf_extended_features_ad_type,
    &hf_android_apcf_extended_features_reserved,
    NULL
};

static int * const hfx_android_bqr_link_coex_info_mask[] = {
    &hf_android_bqr_link_coex_involvement,
    &hf_android_bqr_link_coex_wl_2g_active,
    &hf_android_bqr_link_coex_wl_2g_connected,
    &hf_android_bqr_link_coex_wl_5g_6g_active,
    &hf_android_bqr_link_coex_reserved,
    NULL
};

static int * const hfx_android_bqr_advanced_tx_buffer_queue_count[] = {
    &hf_android_bqr_advanced_tx_buffer_acl_1,
    &hf_android_bqr_advanced_tx_buffer_acl_2,
    &hf_android_bqr_advanced_tx_buffer_leconn_1,
    &hf_android_bqr_advanced_tx_buffer_leconn_2,
    &hf_android_bqr_advanced_tx_buffer_leisoc_1,
    &hf_android_bqr_advanced_tx_buffer_leisoc_2,
    &hf_android_bqr_advanced_tx_buffer_lebroadcast,
    &hf_android_bqr_advanced_tx_buffer_reserved,
    NULL
};

static int * const hfx_android_quality_event_mask[] = {
    &hf_android_quality_event_mask_quality_monitoring,
    &hf_android_quality_event_mask_approaching_lsto,
    &hf_android_quality_event_mask_a2dp_choppy,
    &hf_android_quality_event_mask_esco_choppy,
    &hf_android_quality_event_mask_root_inflammation,
    &hf_android_quality_event_mask_energy_monitor,
    &hf_android_quality_event_mask_le_audio_choppy,
    &hf_android_quality_event_mask_connect_fail,
    &hf_android_quality_event_mask_advanced_rf_trigger,
    &hf_android_quality_event_mask_advanced_rf_periodic,
    &hf_android_quality_event_mask_controller_health_trigger,
    &hf_android_quality_event_mask_controller_health_periodic,
    &hf_android_quality_event_mask_reserved,
    &hf_android_quality_event_mask_vendor_quality,
    &hf_android_quality_event_mask_lmp_trace,
    &hf_android_quality_event_mask_coex_trace,
    &hf_android_quality_event_mask_controller_debug,
    &hf_android_quality_event_mask_offload_debug_reserved,
    &hf_android_quality_event_mask_uart_history,
    &hf_android_quality_event_mask_reserved_2,
    &hf_android_quality_event_mask_vendor_trace,
    NULL
};

static int * const hfx_android_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode[] = {
    &hf_android_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode_mask_reserved,
    &hf_android_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode_mask_mono,
    &hf_android_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode_mask_dual,
    &hf_android_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode_mask_stereo,
    NULL
};

static int ett_android;
static int ett_android_opcode;
static int ett_android_channel_map;
static int ett_android_a2dp_source_offload_capability_mask;
static int ett_android_dynamic_audio_buffer_support_mask;
static int ett_android_version_support;
static int ett_android_big_channel_map_support;
static int ett_android_apcf_feature_selection;
static int ett_android_apcf_list_logic;
static int ett_android_apcf_extended_features;
static int ett_android_bqr;
static int ett_android_bqr_link_coex_info_mask;
static int ett_android_bqr_advanced_tx_buffer_queue_count;
static int ett_android_a2dp_hardware_offload_start_legacy_codec_information;
static int ett_android_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode_mask;

static expert_field ei_android_undecoded;
static expert_field ei_android_unexpected_parameter;
static expert_field ei_android_unexpected_data;

static dissector_handle_t bthci_vendor_android_handle;
static dissector_handle_t btcommon_ad_android_handle;

static const uint16_t bthci_vendor_manufacturer_android = 0x00e0; // Google LLC

#define ANDROID_OPCODE_VALS(base) \
    { (base) | 0x0153,  "LE Get Vendor Capabilities" }, \
    { (base) | 0x0154,  "LE Multi Advertising" }, \
    { (base) | 0x0156,  "LE Batch Scan" }, \
    { (base) | 0x0157,  "LE Advertising Packet Content Filter (APCF)" }, \
    { (base) | 0x0158,  "LE Tracking Advertising" }, \
    { (base) | 0x0159,  "LE Get Controller Activity Energy Info" }, \
    { (base) | 0x015D,  "A2DP Hardware Offload" }, \
    { (base) | 0x015E,  "Bluetooth Quality Report" }

static const value_string android_opcode_ocf_vals[] = {
    ANDROID_OPCODE_VALS(0x0),
    { 0, NULL }
};

static const value_string android_opcode_vals[] = {
    ANDROID_OPCODE_VALS(0x3F << 10),
    { 0, NULL }
};

static const value_string android_le_subcode_advertising_filter_vals[] = {
    { 0x00,  "APCF Enable" },
    { 0x01,  "APCF Set Filtering Parameters" },
    { 0x02,  "APCF Broadcaster Address" },
    { 0x03,  "APCF Service UUID" },
    { 0x04,  "APCF Service Solicitation UUID" },
    { 0x05,  "APCF Local Name" },
    { 0x06,  "APCF Manufacturer Data"  },
    { 0x07,  "APCF Service Data" },
    { 0x08,  "APCF Transport Discovery Service" },
    { 0x09,  "APCF AD Type Filter" },
    { 0xFF,  "APCF Read Extended Features" },
    { 0, NULL }
};

static const value_string android_apcf_filter_logic_vals[] = {
    { 0x00,  "OR" },
    { 0x01,  "AND" },
    { 0, NULL }
};

static const true_false_string tfs_apcf_logic = { "AND", "OR" };

static const value_string android_apcf_delivery_mode_vals[] = {
    { 0x00,  "Immediate" },
    { 0x01,  "On Found" },
    { 0x02,  "Batched" },
    { 0, NULL }
};

static const value_string android_apcf_application_address_type_vals[] = {
    { 0x00,  "Public" },
    { 0x01,  "Random" },
    { 0x02,  "NA (ignore the address type)" },
    { 0, NULL }
};

static const value_string android_apcf_action_vals[] = {
    { 0x00,  "Add" },
    { 0x01,  "Delete" },
    { 0x02,  "Clear" },
    { 0, NULL }
};

static const value_string android_bqr_action_vals[] = {
    { 0x00,  "Add" },
    { 0x01,  "Delete" },
    { 0x02,  "Clear" },
    { 0x03,  "One Time Query" },
    { 0, NULL }
};

static const value_string android_bqr_quality_report_id_vals[] = {
    { 0x01, "Quality Monitoring" },
    { 0x02, "Approaching LSTO" },
    { 0x03, "A2DP Audio Choppy" },
    { 0x04, "(e)SCO Voice Choppy" },
    { 0x05, "Root Inflammation" },
    { 0x06, "Energy Monitor" },
    { 0x07, "LE Audio Choppy" },
    { 0x08, "Connect Fail" },
    { 0x09, "Advanced RF Stats Trigger" },
    { 0x0A, "Advanced RF Stats Monitor" },
    { 0x0B, "Controller Health Trigger" },
    { 0x0C, "Controller Health Periodic" },
    { 0x11, "LMP/LL Message Trace" },
    { 0x12, "Multi-link/Coex Trace" },
    { 0x13, "Controller Debug Information" },
    { 0x16, "LEA Broadcast Source" },
    { 0, NULL }
};

static const value_string android_bqr_packet_type_vals[] = {
    { 0x01, "ID" },
    { 0x02, "NULL" },
    { 0x03, "POLL" },
    { 0x04, "FHS" },
    { 0x05, "HV1" },
    { 0x06, "HV2" },
    { 0x07, "HV3" },
    { 0x08, "DV" },
    { 0x09, "EV3" },
    { 0x0A, "EV4" },
    { 0x0B, "EV5" },
    { 0x0C, "2-EV3" },
    { 0x0D, "2-EV5" },
    { 0x0E, "3-EV3" },
    { 0x0F, "3-EV5" },
    { 0x10, "DM1" },
    { 0x11, "DH1" },
    { 0x12, "DM3" },
    { 0x13, "DH3" },
    { 0x14, "DM5" },
    { 0x15, "DH5" },
    { 0x16, "AUX1" },
    { 0x17, "2-DH1" },
    { 0x18, "2-DH3" },
    { 0x19, "2-DH5" },
    { 0x1A, "3-DH1" },
    { 0x1B, "3-DH3" },
    { 0x1C, "3-DH5" },
    { 0x51, "ISO Packet" },
    { 0x52, "1M PHY" },
    { 0x53, "2M PHY" },
    { 0x54, "Codec PHY S=2" },
    { 0x55, "Codec PHY S=8" },
    { 0, NULL }
};

static const value_string android_bqr_extension_info_vals[] = {
    { 0x01, "BQRv6" },
    { 0x02, "BQRv7" },
    { 0x03, "BQRv8" },
    { 0, NULL }
};

static const value_string android_bqr_connection_role_vals[] = {
    { 0x00, "Central" },
    { 0x01, "Peripheral" },
    { 0, NULL }
};

static const value_string android_subevent_code_vals[] = {
    { 0x54, "Storage Threshold Breach" },
    { 0x55, "LE Multi Advertising State Change" },
    { 0x56, "LE Advertisement Tracking" },
    { 0x57, "Controller Debug Information" },
    { 0x58, "Bluetooth Quality Report" },
    { 0x5C, "ISO Link Feedback" },
    { 0, NULL }
};

static const value_string android_le_subcode_batch_scan_vals[] = {
    { 0x01,  "Enable/Disable Customer Feature" },
    { 0x02,  "Set Storage Parameter" },
    { 0x03,  "Set Parameter" },
    { 0x04,  "Read Results" },
    { 0, NULL }
};

static const value_string android_batch_scan_mode_vals[] = {
    { 0x00,  "Disable" },
    { 0x01,  "Pass" },
    { 0x02,  "ACTI" },
    { 0x03,  "Pass ACTI" },
    { 0, NULL }
};

static const value_string android_batch_scan_discard_rule_vals[] = {
    { 0x00,  "Old Items" },
    { 0x01,  "Lower RSSI Items" },
    { 0, NULL }
};

static const value_string android_disable_enable_vals[] = {
    { 0x00,  "Disable" },
    { 0x01,  "Enable" },
    { 0, NULL }
};

static const value_string android_le_subcode_multi_advertising_vals[] = {
    { 0x01,  "Set Parameter" },
    { 0x02,  "Write Advertising Data" },
    { 0x03,  "Write Scan Response Data" },
    { 0x04,  "Set Random Address" },
    { 0x05,  "MultiAdvertising Enable/Disable Customer Feature" },
    { 0, NULL }
};

static const value_string android_le_filter_policy_vals[] = {
    { 0x00,  "All Connections" },
    { 0x01,  "Whitelist Connections All" },
    { 0x02,  "All Connections Whitelist" },
    { 0x03,  "Whitelist Connections" },
    { 0, NULL }
};

static const value_string android_a2dp_hardware_offload_vals[] = {
    { 0x01,  "Start A2DP offload (legacy)" },
    { 0x02,  "Stop A2DP offload (legacy)" },
    { 0x03,  "Start A2DP offload" },
    { 0x04,  "Stop A2DP offload" },
    { 0, NULL }
};

static const value_string android_a2dp_hardware_offload_start_legacy_codec_vals[] = {
    { 0x01,  "SBC" },
    { 0x02,  "AAC" },
    { 0x04,  "APTX" },
    { 0x08,  "APTX HD" },
    { 0x10,  "LDAC" },
    { 0, NULL }
};

static const value_string android_a2dp_hardware_offload_start_legacy_sampling_frequency_vals[] = {
    { 0x00000001,  "44100 Hz" },
    { 0x00000002,  "48000 Hz" },
    { 0x00000004,  "88200 Hz" },
    { 0x00000008,  "96000 Hz" },
    { 0, NULL }
};

static const value_string android_a2dp_hardware_offload_start_legacy_bits_per_sample_vals[] = {
    { 0x01,  "16 bits per sample" },
    { 0x02,  "24 bits per sample" },
    { 0x04,  "32 bits per sample" },
    { 0, NULL }
};

static const value_string android_a2dp_hardware_offload_start_legacy_channel_mode_vals[] = {
    { 0x01,  "Mono" },
    { 0x02,  "Stereo" },
    { 0, NULL }
};

static const value_string android_a2dp_hardware_offload_start_legacy_codec_information_sbc_block_length_vals[] = {
    { 0x01,  "16" },
    { 0x02,  "12" },
    { 0x04,  "8" },
    { 0x08,  "4" },
    { 0, NULL }
};

static const value_string android_a2dp_hardware_offload_start_legacy_codec_information_sbc_subbands_vals[] = {
    { 0x01,  "8" },
    { 0x02,  "4" },
    { 0, NULL }
};

static const value_string android_a2dp_hardware_offload_start_legacy_codec_information_sbc_allocation_method_vals[] = {
    { 0x01,  "Loudness" },
    { 0x02,  "SNR" },
    { 0, NULL }
};

static const value_string android_a2dp_hardware_offload_start_legacy_sbc_sampling_frequency_vals[] = {
    { 0x01,  "48000 Hz" },
    { 0x02,  "44100 Hz" },
    { 0x04,  "32000 Hz" },
    { 0x08,  "16000 Hz" },
    { 0, NULL }
};

static const value_string android_a2dp_hardware_offload_start_legacy_sbc_channel_mode_vals[] = {
    { 0x01,  "Joint Stereo" },
    { 0x02,  "Stereo" },
    { 0x04,  "Dual Channel" },
    { 0x08,  "Mono" },
    { 0, NULL }
};

static const value_string android_a2dp_hardware_offload_data_path_direction_vals[] = {
    { 0x00,  "Output (AVDTP Source/Merge)" },
    { 0x01,  "Input (AVDTP Sink/Split)" },
    { 0, NULL }
};

static const value_string android_a2dp_hardware_offload_start_legacy_aac_object_type_vals[] = {
    { 0x01,  "RFA (b0)" },
    { 0x02,  "RFA (b1)" },
    { 0x04,  "RFA (b2)" },
    { 0x08,  "RFA (b3)" },
    { 0x10,  "MPEG-4 AAC scalable" },
    { 0x20,  "MPEG-4 AAC LTP" },
    { 0x40,  "MPEG-4 AAC LC" },
    { 0x80,  "MPEG-2 AAC LC" },
    { 0, NULL }
};

static const value_string android_a2dp_hardware_offload_start_legacy_codec_information_ldac_bitrate_index_vals[] = {
    { 0x00,  "High" },
    { 0x01,  "Mid" },
    { 0x02,  "Low" },
    { 0x7f,  "ABR (Adaptive Bit Rate)" },
    { 0, NULL }
};

static void
android_version_support_fmt(char *buf, uint32_t value) {
    snprintf(buf, ITEM_LABEL_LENGTH, "V%u.%02u", value >> 8, value & 0xff);
}

/* LSTO: Time = N * 0.625 ms */
static void
android_bqr_lsto_fmt(char *buf, uint32_t value) {
    snprintf(buf, ITEM_LABEL_LENGTH, "%u (%.3f ms)", value, 0.625 * value);
}

/* Bluetooth clock based timestamps: Time = N * 0.3125 ms */
static void
android_bqr_bt_clock_fmt(char *buf, uint32_t value) {
    snprintf(buf, ITEM_LABEL_LENGTH, "%u (%.3f ms)", value, 0.3125 * value);
}

void proto_register_bthci_vendor_android(void);
void proto_reg_handoff_bthci_vendor_android(void);

static unsigned
dissect_android_bqr(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, unsigned offset, uint8_t report_id,
                    uint32_t interface_id, uint32_t adapter_id)
{
    proto_tree *bqr_tree;

    bqr_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_android_bqr, NULL,
                                      "Bluetooth Quality Report");

    if ((report_id >= 0x01 && report_id <= 0x04) || report_id == 0x07 || report_id == 0x08) {
        proto_tree_add_item(bqr_tree, hf_android_bqr_link_packet_type, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(bqr_tree, hf_android_bqr_link_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(bqr_tree, hf_android_bqr_link_connection_role, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(bqr_tree, hf_android_bqr_link_tx_power, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(bqr_tree, hf_android_bqr_link_rssi, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(bqr_tree, hf_android_bqr_link_snr, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(bqr_tree, hf_android_bqr_link_unused_afh_channels, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(bqr_tree, hf_android_bqr_link_afh_unideal_channels, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(bqr_tree, hf_android_bqr_link_lsto, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(bqr_tree, hf_android_bqr_link_piconet_clock, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_link_retransmission_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_link_no_rx_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_link_nak_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_link_last_tx_ack_timestamp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_link_flow_off_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_link_last_flow_on_timestamp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_link_buffer_overflow_bytes, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_link_buffer_underflow_bytes, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        offset = dissect_bd_addr(hf_android_bd_addr, pinfo, bqr_tree, tvb, offset,
                                 false, interface_id, adapter_id, NULL);

        proto_tree_add_item(bqr_tree, hf_android_bqr_link_cal_failed_item_count, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(bqr_tree, hf_android_bqr_link_tx_total_packets, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_link_tx_unacked_packets, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_link_tx_flushed_packets, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_link_tx_last_subevent_packets, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_link_crc_error_packets, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_link_rx_duplicate_packets, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_link_rx_unreceived_packets, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_bitmask(bqr_tree, tvb, offset, hf_android_bqr_link_coex_info_mask,
                               ett_android_bqr_link_coex_info_mask, hfx_android_bqr_link_coex_info_mask, ENC_LITTLE_ENDIAN);
        offset += 2;
    } else if (report_id == 0x05) {
        proto_tree_add_item(bqr_tree, hf_android_bqr_root_error_code, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(bqr_tree, hf_android_bqr_root_vendor_error_code, tvb, offset, 1, ENC_NA);
        offset += 1;
    } else if (report_id == 0x06) {
        proto_tree_add_item(bqr_tree, hf_android_bqr_energy_average_current, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(bqr_tree, hf_android_bqr_energy_idle_total_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_energy_idle_enter_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_energy_active_total_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_energy_active_enter_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_energy_bredr_tx_total_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_energy_bredr_tx_enter_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_energy_bredr_tx_avg_power, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(bqr_tree, hf_android_bqr_energy_bredr_rx_total_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_energy_bredr_rx_enter_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_energy_le_tx_total_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_energy_le_tx_enter_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_energy_le_tx_avg_power, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(bqr_tree, hf_android_bqr_energy_le_rx_total_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_energy_le_rx_enter_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_energy_report_time_duration, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_energy_rx_active_one_chain_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_energy_rx_active_two_chain_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_energy_tx_ipa_active_one_chain_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_energy_tx_ipa_active_two_chain_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_energy_tx_epa_active_one_chain_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_energy_tx_epa_active_two_chain_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_energy_bredr_rx_scan_total_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_energy_le_rx_scan_total_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    } else if (report_id == 0x09 || report_id == 0x0A) {
        proto_tree_add_item(bqr_tree, hf_android_bqr_advanced_extension_info, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(bqr_tree, hf_android_bqr_advanced_report_time_period, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_advanced_tx_power_ipa_bf, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_advanced_tx_power_epa_bf, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_advanced_tx_power_ipa_div, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_advanced_tx_power_epa_div, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_advanced_rssi_chain_50, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_advanced_rssi_chain_50_55, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_advanced_rssi_chain_55_60, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_advanced_rssi_chain_60_65, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_advanced_rssi_chain_65_70, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_advanced_rssi_chain_70_75, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_advanced_rssi_chain_75_80, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_advanced_rssi_chain_80_85, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_advanced_rssi_chain_85_90, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_advanced_rssi_chain_90, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_advanced_rssi_delta_2, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_advanced_rssi_delta_2_5, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_advanced_rssi_delta_5_8, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_advanced_rssi_delta_8_11, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_advanced_rssi_delta_11, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_advanced_antenna_switch_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_advanced_retx_ipa_bf, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_advanced_retx_epa_bf, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_advanced_retx_ipa_div, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_advanced_retx_epa_div, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_advanced_channel_count_good, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(bqr_tree, hf_android_bqr_advanced_channel_count_ok, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(bqr_tree, hf_android_bqr_advanced_channel_count_bad, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(bqr_tree, hf_android_bqr_advanced_channel_count_very_bad, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_bitmask(bqr_tree, tvb, offset, hf_android_bqr_advanced_tx_buffer_queue_count,
                               ett_android_bqr_advanced_tx_buffer_queue_count, hfx_android_bqr_advanced_tx_buffer_queue_count, ENC_LITTLE_ENDIAN);
        offset += 4;
    } else if (report_id == 0x0B || report_id == 0x0C) {
        proto_tree_add_item(bqr_tree, hf_android_bqr_health_packet_count_host_to_controller, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_health_packet_count_controller_to_host, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_health_last_packet_length_host_to_controller, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(bqr_tree, hf_android_bqr_health_last_packet_length_controller_to_host, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(bqr_tree, hf_android_bqr_health_total_bt_wake_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_health_total_host_wake_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_health_last_bt_wake_timestamp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_health_last_host_wake_timestamp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_health_reset_timestamp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_health_current_timestamp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_health_watchdog_expiring, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_health_coex_status_mask, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(bqr_tree, hf_android_bqr_health_total_links_bredr_le_active, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(bqr_tree, hf_android_bqr_health_total_links_bredr_sniff, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(bqr_tree, hf_android_bqr_health_total_links_cis, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(bqr_tree, hf_android_bqr_health_is_sco_active, tvb, offset, 1, ENC_NA);
        offset += 1;
    } else if (report_id == 0x16) {
        /* The two BD_ADDRs are on the wire least significant octet first, so
         * use dissect_bd_addr to reverse them into the displayed byte order. */
        proto_tree_add_item(bqr_tree, hf_android_bqr_lea_big_handle, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(bqr_tree, hf_android_bqr_lea_source_bd_addr_type, tvb, offset, 1, ENC_NA);
        offset += 1;

        offset = dissect_bd_addr(hf_android_bqr_lea_source_bd_addr, pinfo, bqr_tree, tvb, offset,
                                 false, interface_id, adapter_id, NULL);

        proto_tree_add_item(bqr_tree, hf_android_bqr_lea_source_prefer_channel_map, tvb, offset, 5, ENC_NA);
        offset += 5;
        proto_tree_add_item(bqr_tree, hf_android_bqr_lea_source_used_channel_map, tvb, offset, 5, ENC_NA);
        offset += 5;

        proto_tree_add_item(bqr_tree, hf_android_bqr_lea_tx_power, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(bqr_tree, hf_android_bqr_lea_timestamp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_lea_subscribed_broadcast_id, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        offset += 3;
        proto_tree_add_item(bqr_tree, hf_android_bqr_lea_receiver_bd_addr_type, tvb, offset, 1, ENC_NA);
        offset += 1;

        offset = dissect_bd_addr(hf_android_bqr_lea_receiver_bd_addr, pinfo, bqr_tree, tvb, offset,
                                 false, interface_id, adapter_id, NULL);

        proto_tree_add_item(bqr_tree, hf_android_bqr_lea_time_duration, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_lea_bis_choppy_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_lea_per, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(bqr_tree, hf_android_bqr_lea_no_sync, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_item(bqr_tree, hf_android_bqr_lea_receiver_prefer_channel_map, tvb, offset, 5, ENC_NA);
        offset += 5;
        proto_tree_add_item(bqr_tree, hf_android_bqr_lea_receiver_tx_power, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(bqr_tree, hf_android_bqr_lea_rssi, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(bqr_tree, hf_android_bqr_lea_reserved, tvb, offset, 4, ENC_NA);
        offset += 4;
    } else if (report_id >= 0x11 && report_id <= 0x13) {
        proto_tree_add_item(bqr_tree, hf_android_bqr_log_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
    }

    proto_tree_add_item(bqr_tree, hf_android_bqr_vendor_data, tvb, offset, -1, ENC_NA);

    return tvb_reported_length(tvb);
}

static unsigned
dissect_bthci_vendor_android_cmd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *main_tree, void *data, uint16_t ocf)
{
    proto_item        *sub_item;
    proto_item        *codec_information_item;
    proto_tree        *codec_information_tree;
    bluetooth_data_t  *bluetooth_data;
    unsigned           offset = 0;
    uint8_t            subcode;
    const char        *description;
    uint32_t           interface_id;
    uint32_t           adapter_id;

    bluetooth_data = (bluetooth_data_t *) data;
    if (bluetooth_data) {
        interface_id  = bluetooth_data->interface_id;
        adapter_id    = bluetooth_data->adapter_id;
    } else {
        interface_id  = HCI_INTERFACE_DEFAULT;
        adapter_id    = HCI_ADAPTER_DEFAULT;
    }

    switch(ocf) {
    case 0x0154: /* LE Multi Advertising */
        proto_tree_add_item_ret_uint8(main_tree, hf_android_le_multi_advertising_subcode, tvb, offset, 1, ENC_NA, &subcode);
        offset += 1;

        switch (subcode) {
        case 0x01: /* Set Parameter */
            proto_tree_add_item(main_tree, hf_android_le_multi_advertising_min_interval, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(main_tree, hf_android_le_multi_advertising_max_interval, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(main_tree, hf_android_le_multi_advertising_type, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_android_le_multi_advertising_address_type, tvb, offset, 1, ENC_NA);
            offset += 1;

            offset = dissect_bd_addr(hf_android_bd_addr, pinfo, main_tree, tvb, offset, false, interface_id, adapter_id, NULL);

            proto_tree_add_item(main_tree, hf_android_le_multi_advertising_address_type, tvb, offset, 1, ENC_NA);
            offset += 1;

            offset = dissect_bd_addr(hf_android_bd_addr, pinfo, main_tree, tvb, offset, false, interface_id, adapter_id, NULL);

            proto_tree_add_bitmask(main_tree, tvb, offset, hf_android_le_multi_advertising_channel_map, ett_android_channel_map,  hfx_android_le_multi_advertising_channel_map, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_android_le_multi_advertising_filter_policy, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_android_le_multi_advertising_instance_id, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_android_le_multi_advertising_tx_power, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 0x02: /* Write Advertising Data */
        case 0x03: /* Write Scan Response Data */
            call_dissector_with_data(btcommon_ad_android_handle, tvb_new_subset_length(tvb, offset, 31), pinfo, proto_tree_get_parent_tree(main_tree), bluetooth_data);
            save_local_device_name_from_eir_ad(tvb, offset, pinfo, 31, bluetooth_data);
            offset += 31;

            proto_tree_add_item(main_tree, hf_android_le_multi_advertising_instance_id, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 0x04: /* Set Random Address */
            offset = dissect_bd_addr(hf_android_bd_addr, pinfo, main_tree, tvb, offset, false, interface_id, adapter_id, NULL);

            proto_tree_add_item(main_tree, hf_android_le_multi_advertising_instance_id, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 0x05: /* MultiAdvertising Enable/Disable Customer Feature */
            proto_tree_add_item(main_tree, hf_android_le_multi_advertising_enable, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_android_le_multi_advertising_instance_id, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        }

        break;
    case 0x0156: /* LE Batch Scan */
        proto_tree_add_item_ret_uint8(main_tree, hf_android_le_batch_scan_subcode, tvb, offset, 1, ENC_NA, &subcode);
        offset += 1;

        switch (subcode) {
        case 0x01: /* Enable/Disable Customer Feature */
            proto_tree_add_item(main_tree, hf_android_le_batch_scan_enable, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 0x02: /* Set Storage Parameter */
            proto_tree_add_item(main_tree, hf_android_le_batch_scan_full_max, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_android_le_batch_scan_truncate_max, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_android_le_batch_scan_notify_threshold, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 0x03: /* Set Parameter */
            proto_tree_add_item(main_tree, hf_android_le_batch_scan_mode, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_android_le_batch_scan_window, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(main_tree, hf_android_le_batch_scan_interval, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(main_tree, hf_android_le_batch_scan_address_type, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_android_le_batch_scan_discard_rule, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 0x04: /* Read Results */
            proto_tree_add_item(main_tree, hf_android_le_batch_scan_mode, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        }

        break;
    case 0x0157: /* LE Advertising Packet Content Filter (APCF) */ {
        uint8_t     action = 0;

        proto_tree_add_item_ret_uint8(main_tree, hf_android_le_advertising_filter_subcode, tvb, offset, 1, ENC_NA, &subcode);
        offset += 1;

        description = val_to_str_const(subcode, android_le_subcode_advertising_filter_vals, "Unknown");
        col_set_str(pinfo->cinfo, COL_INFO, "Sent Android ");
        col_append_str(pinfo->cinfo, COL_INFO, description);

        switch (subcode) {
        case 0x00: /* Enable */
            if (tvb_reported_length_remaining(tvb, offset) < 1)
                break;
            proto_tree_add_item(main_tree, hf_android_apcf_enable, tvb, offset, 1, ENC_NA);
            col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)",
                            tvb_get_uint8(tvb, offset) == 0x01 ? "Enable" : "Disable");
            offset += 1;
            break;
        case 0x01: /* Set Filtering Parameters */
            if (tvb_reported_length_remaining(tvb, offset) < 2)
                break;
            proto_tree_add_item_ret_uint8(main_tree, hf_android_apcf_action, tvb, offset, 1, ENC_NA, &action);
            offset += 1;
            proto_tree_add_item(main_tree, hf_android_apcf_filter_index, tvb, offset, 1, ENC_NA);
            offset += 1;
            col_append_fstr(pinfo->cinfo, COL_INFO, " (%s %u)",
                            val_to_str_const(action, android_apcf_action_vals, "Unknown"),
                            tvb_get_uint8(tvb, offset - 1));

            /* A Clear action carries no further parameters. */
            if (action == 0x02 || tvb_reported_length_remaining(tvb, offset) < 2)
                break;

            {
                proto_tree_add_bitmask(main_tree, tvb, offset, hf_android_apcf_feature_selection, ett_android_apcf_feature_selection, hfx_android_apcf_feature_selection, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_bitmask(main_tree, tvb, offset, hf_android_apcf_list_logic, ett_android_apcf_list_logic, hfx_android_apcf_list_logic, ENC_LITTLE_ENDIAN);
                offset += 2;
            }

            if (tvb_reported_length_remaining(tvb, offset) < 1)
                break;
            proto_tree_add_item(main_tree, hf_android_apcf_filter_logic_type, tvb, offset, 1, ENC_NA);
            offset += 1;

            if (tvb_reported_length_remaining(tvb, offset) < 1)
                break;
            proto_tree_add_item(main_tree, hf_android_apcf_rssi_high_threshold, tvb, offset, 1, ENC_NA);
            offset += 1;

            if (tvb_reported_length_remaining(tvb, offset) < 1)
                break;
            proto_tree_add_item(main_tree, hf_android_apcf_delivery_mode, tvb, offset, 1, ENC_NA);
            offset += 1;

            if (tvb_reported_length_remaining(tvb, offset) < 2)
                break;
            proto_tree_add_item(main_tree, hf_android_apcf_onfound_timeout, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            if (tvb_reported_length_remaining(tvb, offset) < 1)
                break;
            proto_tree_add_item(main_tree, hf_android_apcf_onfound_timeout_count, tvb, offset, 1, ENC_NA);
            offset += 1;

            if (tvb_reported_length_remaining(tvb, offset) < 1)
                break;
            proto_tree_add_item(main_tree, hf_android_apcf_rssi_low_threshold, tvb, offset, 1, ENC_NA);
            offset += 1;

            if (tvb_reported_length_remaining(tvb, offset) < 2)
                break;
            proto_tree_add_item(main_tree, hf_android_apcf_onlost_timeout, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            if (tvb_reported_length_remaining(tvb, offset) < 2)
                break;
            proto_tree_add_item(main_tree, hf_android_apcf_num_of_tracking_entries, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            break;
        case 0x02: /* Broadcaster Address */
            if (tvb_reported_length_remaining(tvb, offset) < 8)
                break;
            proto_tree_add_item_ret_uint8(main_tree, hf_android_apcf_action, tvb, offset, 1, ENC_NA, &action);
            offset += 1;
            proto_tree_add_item(main_tree, hf_android_apcf_filter_index, tvb, offset, 1, ENC_NA);
            offset += 1;
            col_append_fstr(pinfo->cinfo, COL_INFO, " (%s %u)",
                            val_to_str_const(action, android_apcf_action_vals, "Unknown"),
                            tvb_get_uint8(tvb, offset - 1));

            offset = dissect_bd_addr(hf_android_apcf_broadcaster_address, pinfo, main_tree, tvb, offset, false, interface_id, adapter_id, NULL);

            proto_tree_add_item(main_tree, hf_android_apcf_application_address_type, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;
        case 0x03: /* Service UUID */
        case 0x04: /* Service Solicitation UUID */
        case 0x05: /* Local Name */
        case 0x06: /* Manufacturer Data */
        case 0x07: /* Service Data */
        case 0x09: /* AD Type Filter */ {
            int      remaining;
            uint32_t data_len;

            if (tvb_reported_length_remaining(tvb, offset) < 2)
                break;
            proto_tree_add_item_ret_uint8(main_tree, hf_android_apcf_action, tvb, offset, 1, ENC_NA, &action);
            offset += 1;
            proto_tree_add_item(main_tree, hf_android_apcf_filter_index, tvb, offset, 1, ENC_NA);
            offset += 1;
            col_append_fstr(pinfo->cinfo, COL_INFO, " (%s %u)",
                            val_to_str_const(action, android_apcf_action_vals, "Unknown"),
                            tvb_get_uint8(tvb, offset - 1));

            /* A Clear action carries no further parameters. */
            if (action == 0x02)
                break;

            if (subcode == 0x09) {
                uint8_t ad_data_len;

                if (tvb_reported_length_remaining(tvb, offset) < 2)
                    break;
                proto_tree_add_item(main_tree, hf_android_apcf_ad_type, tvb, offset, 1, ENC_NA);
                offset += 1;
                proto_tree_add_item_ret_uint8(main_tree, hf_android_apcf_ad_data_length, tvb, offset, 1, ENC_NA, &ad_data_len);
                offset += 1;
                if (ad_data_len == 0)
                    break;
                data_len = MIN((uint32_t)ad_data_len, (uint32_t)tvb_reported_length_remaining(tvb, offset) / 2);
                if (data_len == 0)
                    break;
                proto_tree_add_item(main_tree, hf_android_apcf_ad_data, tvb, offset, data_len, ENC_NA);
                offset += data_len;
                proto_tree_add_item(main_tree, hf_android_apcf_ad_data_mask, tvb, offset, data_len, ENC_NA);
                offset += data_len;
                break;
            }

            remaining = tvb_reported_length_remaining(tvb, offset);
            if (remaining <= 0)
                break;

            if (subcode == 0x03 || subcode == 0x04) {
                /* UUID and its mask are equal length: 2, 4 or 16 bytes. */
                data_len = remaining / 2;
                proto_tree_add_item(main_tree, hf_android_apcf_uuid, tvb, offset, data_len, ENC_NA);
                offset += data_len;
                proto_tree_add_item(main_tree, hf_android_apcf_uuid_mask, tvb, offset, data_len, ENC_NA);
                offset += data_len;
            } else if (subcode == 0x05) {
                proto_tree_add_item(main_tree, hf_android_apcf_data, tvb, offset, remaining, ENC_NA);
                offset += remaining;
            } else {
                data_len = remaining / 2;
                proto_tree_add_item(main_tree, hf_android_apcf_data, tvb, offset, data_len, ENC_NA);
                offset += data_len;
                proto_tree_add_item(main_tree, hf_android_apcf_mask, tvb, offset, data_len, ENC_NA);
                offset += data_len;
            }

            break;
        }
        case 0x08: /* Transport Discovery Service */
            if (tvb_reported_length_remaining(tvb, offset) < 2)
                break;
            proto_tree_add_item_ret_uint8(main_tree, hf_android_apcf_action, tvb, offset, 1, ENC_NA, &action);
            offset += 1;
            proto_tree_add_item(main_tree, hf_android_apcf_filter_index, tvb, offset, 1, ENC_NA);
            offset += 1;
            col_append_fstr(pinfo->cinfo, COL_INFO, " (%s %u)",
                            val_to_str_const(action, android_apcf_action_vals, "Unknown"),
                            tvb_get_uint8(tvb, offset - 1));
            break;
        case 0xFF: /* Read Extended Features */
            break;
        default:
            break;
        }

        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            sub_item = proto_tree_add_item(main_tree, hf_android_data, tvb, offset, -1, ENC_NA);
            expert_add_info(pinfo, sub_item, &ei_android_unexpected_data);
            offset = tvb_reported_length(tvb);
        }

        break;
    }
    case 0x015E: /* Bluetooth Quality Report */ {
        uint8_t action;

        if (tvb_reported_length_remaining(tvb, offset) < 1)
            break;
        proto_tree_add_item_ret_uint8(main_tree, hf_android_bqr_action, tvb, offset, 1, ENC_NA, &action);
        offset += 1;

        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)",
                        val_to_str_const(action, android_bqr_action_vals, "Unknown"));

        /* Clear takes no further parameters. */
        if (action == 0x02)
            break;

        if (tvb_reported_length_remaining(tvb, offset) >= 4) {
            proto_tree_add_bitmask(main_tree, tvb, offset, hf_android_quality_event_mask,
                                   ett_android_bqr, hfx_android_quality_event_mask, ENC_LITTLE_ENDIAN);
            offset += 4;
        }
        if (tvb_reported_length_remaining(tvb, offset) >= 2) {
            proto_tree_add_item(main_tree, hf_android_bqr_minimum_report_interval, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        /* Vendor-specific masks are only meaningful for Add/One Time Query. */
        if (tvb_reported_length_remaining(tvb, offset) >= 4) {
            proto_tree_add_item(main_tree, hf_android_bqr_vendor_quality_event_mask, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
        }
        if (tvb_reported_length_remaining(tvb, offset) >= 4) {
            proto_tree_add_item(main_tree, hf_android_bqr_vendor_trace_mask, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
        }
        if (tvb_reported_length_remaining(tvb, offset) >= 4) {
            proto_tree_add_item(main_tree, hf_android_bqr_report_interval_multiple, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
        }

        break;
    }
    case 0x0153: /* LE Get Vendor Capabilities */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            sub_item = proto_tree_add_item(main_tree, hf_android_data, tvb, offset, -1, ENC_NA);
            expert_add_info(pinfo, sub_item, &ei_android_unexpected_parameter);
            offset = tvb_reported_length(tvb);
        }
        break;
    case 0x0159: /* LE Get Controller Activity Energy Info */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            sub_item = proto_tree_add_item(main_tree, hf_android_data, tvb, offset, -1, ENC_NA);
            expert_add_info(pinfo, sub_item, &ei_android_unexpected_parameter);
            offset = tvb_reported_length(tvb);
        }
        break;
    case 0x015D: /* A2DP Hardware Offload */
        proto_tree_add_item_ret_uint8(main_tree, hf_android_a2dp_hardware_offload_subcode, tvb, offset, 1, ENC_NA, &subcode);
        offset += 1;

        switch (subcode) {
        case 0x01: {    /* Start A2DP offload (legacy) */
            int codec_id = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);

            proto_tree_add_item(main_tree, hf_android_a2dp_hardware_offload_start_legacy_codec, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(main_tree, hf_android_a2dp_hardware_offload_start_legacy_max_latency, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            /* Flag is the LSB out of the two, read it first */
            proto_tree_add_item(main_tree, hf_android_a2dp_hardware_offload_start_legacy_scms_t_enable_flag, tvb, offset, 1, ENC_NA);
            offset += 1;

            bool scms_t_enabled = tvb_get_uint8(tvb, offset) == 0x01;
            if (scms_t_enabled) {
                proto_tree_add_item(main_tree, hf_android_a2dp_hardware_offload_start_legacy_scms_t_enable_value, tvb, offset, 1, ENC_NA);
            } else {
                proto_tree_add_item(main_tree, hf_android_a2dp_hardware_offload_start_legacy_scms_t_enable_value_reserved, tvb, offset, 1, ENC_NA);
            }
            offset += 1;

            proto_tree_add_item(main_tree, hf_android_a2dp_hardware_offload_start_legacy_sampling_frequency, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(main_tree, hf_android_a2dp_hardware_offload_start_legacy_bits_per_sample, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_android_a2dp_hardware_offload_start_legacy_channel_mode, tvb, offset, 1, ENC_NA);
            offset += 1;

            uint32_t encoded_audio_bitrate = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);
            if (encoded_audio_bitrate == 0x00000000) {
                proto_tree_add_item(main_tree, hf_android_a2dp_hardware_offload_start_legacy_encoded_audio_bitrate_unspecified, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            } else if (encoded_audio_bitrate >= 0x01000000) {
                proto_tree_add_item(main_tree, hf_android_a2dp_hardware_offload_start_legacy_encoded_audio_bitrate_reserved, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            } else {
                proto_tree_add_item(main_tree, hf_android_a2dp_hardware_offload_start_legacy_encoded_audio_bitrate, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            }
            offset += 4;

            proto_tree_add_item(main_tree, hf_android_a2dp_hardware_offload_start_legacy_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(main_tree, hf_android_a2dp_hardware_offload_start_legacy_l2cap_cid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(main_tree, hf_android_a2dp_hardware_offload_start_legacy_l2cap_mtu_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            codec_information_item = proto_tree_add_item(main_tree, hf_android_a2dp_hardware_offload_start_legacy_codec_information, tvb, offset, 32, ENC_NA);
            codec_information_tree = proto_item_add_subtree(codec_information_item, ett_android_a2dp_hardware_offload_start_legacy_codec_information);

            switch (codec_id) {
                case 0x00000001:  /* SBC */
                    proto_tree_add_item(codec_information_tree, hf_android_a2dp_hardware_offload_start_legacy_codec_information_sbc_block_length, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(codec_information_tree, hf_android_a2dp_hardware_offload_start_legacy_codec_information_sbc_subbands, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(codec_information_tree, hf_android_a2dp_hardware_offload_start_legacy_codec_information_sbc_allocation_method, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    proto_tree_add_item(codec_information_tree, hf_android_a2dp_hardware_offload_start_legacy_codec_information_sbc_min_bitpool, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    proto_tree_add_item(codec_information_tree, hf_android_a2dp_hardware_offload_start_legacy_codec_information_sbc_max_bitpool, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    proto_tree_add_item(codec_information_tree, hf_android_a2dp_hardware_offload_start_legacy_codec_information_sbc_sampling_frequency, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(codec_information_tree, hf_android_a2dp_hardware_offload_start_legacy_codec_information_sbc_channel_mode, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    proto_tree_add_item(codec_information_tree, hf_android_a2dp_hardware_offload_start_legacy_codec_information_sbc_reserved, tvb, offset, 28, ENC_NA);
                    offset += 28;
                break;
                case 0x00000002:  /* AAC */
                    proto_tree_add_item(codec_information_tree, hf_android_a2dp_hardware_offload_start_legacy_codec_information_aac_object_type, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    proto_tree_add_item(codec_information_tree, hf_android_a2dp_hardware_offload_start_legacy_codec_information_aac_vbr, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    proto_tree_add_item(codec_information_tree, hf_android_a2dp_hardware_offload_start_legacy_codec_information_aac_reserved, tvb, offset, 30, ENC_NA);
                    offset += 30;
                break;
                case 0x00000010:  /* LDAC */
                    proto_tree_add_item(codec_information_tree, hf_android_a2dp_hardware_offload_start_legacy_codec_information_ldac_vendor_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    offset += 4;

                    proto_tree_add_item(codec_information_tree, hf_android_a2dp_hardware_offload_start_legacy_codec_information_ldac_codec_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;

                    uint8_t bitrate_index = tvb_get_uint8(tvb, offset);
                    if (bitrate_index >= 0x03 && bitrate_index != 0x7F) {
                        proto_tree_add_item(codec_information_tree, hf_android_a2dp_hardware_offload_start_legacy_codec_information_ldac_bitrate_index_reserved, tvb, offset, 1, ENC_NA);
                    } else {
                        proto_tree_add_item(codec_information_tree, hf_android_a2dp_hardware_offload_start_legacy_codec_information_ldac_bitrate_index, tvb, offset, 1, ENC_NA);
                    }
                    offset += 1;

                    proto_tree_add_bitmask(main_tree, tvb, offset, hf_android_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode_mask,
                                           ett_android_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode_mask, hfx_android_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode, ENC_NA);
                    offset += 1;

                    proto_tree_add_item(codec_information_tree, hf_android_a2dp_hardware_offload_start_legacy_codec_information_ldac_reserved, tvb, offset, 24, ENC_NA);
                    offset += 24;
                break;
                default:    /* All other codecs */
                    proto_tree_add_item(codec_information_tree, hf_android_a2dp_hardware_offload_start_legacy_codec_information_reserved, tvb, offset, 32, ENC_NA);
                    offset += 32;
                break;
            }

            break;
        }
        case 0x02: {    /* Stop A2DP offload (legacy) */
            if (tvb_reported_length_remaining(tvb, offset) > 0) {
                sub_item = proto_tree_add_item(main_tree, hf_android_data, tvb, offset, -1, ENC_NA);
                expert_add_info(pinfo, sub_item, &ei_android_unexpected_parameter);
                offset = tvb_reported_length(tvb);
            }
            break;
        }
        case 0x03: {    /* Start A2DP offload */
            proto_tree_add_item(main_tree, hf_android_a2dp_hardware_offload_start_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(main_tree, hf_android_a2dp_hardware_offload_start_l2cap_cid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(main_tree, hf_android_a2dp_hardware_offload_start_data_path_direction, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_android_a2dp_hardware_offload_start_peer_mtu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            bool cp_enable_scmst = tvb_get_uint8(tvb, offset) == 0x01;
            proto_tree_add_item(main_tree, hf_android_a2dp_hardware_offload_start_cp_enable_scmst, tvb, offset, 1, ENC_NA);
            offset += 1;

            if (cp_enable_scmst) {
                proto_tree_add_item(main_tree, hf_android_a2dp_hardware_offload_start_cp_header_scmst, tvb, offset, 1, ENC_NA);
            } else {
                proto_tree_add_item(main_tree, hf_android_a2dp_hardware_offload_start_cp_header_scmst_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
            }
            offset += 1;

            uint8_t vendor_specific_parameters_length = tvb_get_uint8(tvb, offset);
            proto_tree_add_item(main_tree, hf_android_a2dp_hardware_offload_start_vendor_specific_parameters_length, tvb, offset, 1, ENC_NA);
            offset += 1;

            if (vendor_specific_parameters_length > 0 && vendor_specific_parameters_length <= 128) {
                proto_tree_add_item(main_tree, hf_android_a2dp_hardware_offload_start_vendor_specific_parameters, tvb, offset, vendor_specific_parameters_length, ENC_NA);
                offset += vendor_specific_parameters_length;
            }
            break;
        }
        case 0x04: {    /* Stop A2DP offload */
            proto_tree_add_item(main_tree, hf_android_a2dp_hardware_offload_stop_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(main_tree, hf_android_a2dp_hardware_offload_stop_l2cap_cid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(main_tree, hf_android_a2dp_hardware_offload_stop_data_path_direction, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        }
        default:
            if (tvb_reported_length_remaining(tvb, offset) > 0) {
                sub_item = proto_tree_add_item(main_tree, hf_android_data, tvb, offset, -1, ENC_NA);
                expert_add_info(pinfo, sub_item, &ei_android_unexpected_parameter);
                offset = tvb_reported_length(tvb);
            }
            break;
        }

        break;
    default:
        if (tvb_reported_length_remaining(tvb, offset)) {
            sub_item = proto_tree_add_item(main_tree, hf_android_data, tvb, offset, -1, ENC_NA);
            expert_add_info(pinfo, sub_item, &ei_android_undecoded);
            offset = tvb_reported_length(tvb);
        }
    }

    if (tvb_reported_length_remaining(tvb, offset)) {
        sub_item = proto_tree_add_item(main_tree, hf_android_data, tvb, offset, -1, ENC_NA);
        expert_add_info(pinfo, sub_item, &ei_android_unexpected_parameter);
        offset = tvb_reported_length(tvb);
    }
    return offset;
}

static unsigned
dissect_bthci_vendor_android_evt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *main_tree, void *data, uint8_t event_code)
{
    proto_item        *opcode_item;
    proto_tree        *opcode_tree;
    proto_item        *sub_item;
    bluetooth_data_t  *bluetooth_data;
    unsigned           offset = 0;
    uint16_t           opcode;
    uint16_t           ocf;
    const char        *description;
    uint8_t            status;
    uint8_t            subcode;
    uint32_t           interface_id;
    uint32_t           adapter_id;

    bluetooth_data = (bluetooth_data_t *) data;
    if (bluetooth_data) {
        interface_id  = bluetooth_data->interface_id;
        adapter_id    = bluetooth_data->adapter_id;
    } else {
        interface_id  = HCI_INTERFACE_DEFAULT;
        adapter_id    = HCI_ADAPTER_DEFAULT;
    }

    switch (event_code) {
    case 0x0e: /* Command Complete */
        proto_tree_add_item(main_tree, hf_android_number_of_allowed_command_packets, tvb, offset, 1, ENC_NA);
        offset += 1;

        opcode_item = proto_tree_add_item(main_tree, hf_android_opcode, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        opcode_tree = proto_item_add_subtree(opcode_item, ett_android_opcode);
        opcode = tvb_get_letohs(tvb, offset);
        proto_tree_add_item(opcode_tree, hf_android_opcode_ogf, tvb, offset, 2, ENC_LITTLE_ENDIAN);

        proto_tree_add_item(opcode_tree, hf_android_opcode_ocf, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        ocf = opcode & 0x03ff;
        offset += 2;

        description = val_to_str_const(ocf, android_opcode_ocf_vals, "unknown");
        if (ocf == 0x0157) {
            /* LE Advertising Packet Content Filter (APCF) appends its own detail below. */
        } else if (g_strcmp0(description, "unknown") != 0) {
            col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", description);
        } else {
            col_append_fstr(pinfo->cinfo, COL_INFO, " (Unknown Command 0x%04X [opcode 0x%04X])", ocf, opcode);
        }

        if (have_tap_listener(bluetooth_hci_summary_tap)) {
            bluetooth_hci_summary_tap_t  *tap_hci_summary;

            tap_hci_summary = wmem_new(pinfo->pool, bluetooth_hci_summary_tap_t);
            tap_hci_summary->interface_id  = interface_id;
            tap_hci_summary->adapter_id    = adapter_id;

            tap_hci_summary->type = BLUETOOTH_HCI_SUMMARY_VENDOR_EVENT_OPCODE;
            tap_hci_summary->ogf = opcode >> 10;
            tap_hci_summary->ocf = ocf;
            if (try_val_to_str(ocf, android_opcode_ocf_vals))
                tap_hci_summary->name = description;
            else
                tap_hci_summary->name = NULL;
            tap_queue_packet(bluetooth_hci_summary_tap, pinfo, tap_hci_summary);
        }

        proto_tree_add_item_ret_uint8(main_tree, hf_android_status, tvb, offset, 1, ENC_NA, &status);
        offset += 1;

        switch (ocf) {
        case 0x0153: /* LE Get Vendor Capabilities */
            if (status != STATUS_SUCCESS)
                break;

            uint16_t google_feature_spec_version = tvb_get_uint16(tvb, offset + 8, ENC_LITTLE_ENDIAN);
            if (google_feature_spec_version < 0x0098) {
                proto_tree_add_item(main_tree, hf_android_max_advertising_instance, tvb, offset, 1, ENC_NA);
            } else {
                proto_tree_add_item(main_tree, hf_android_max_advertising_instance_reserved, tvb, offset, 1, ENC_NA);
            }
            offset += 1;

            if (google_feature_spec_version < 0x0098) {
                proto_tree_add_item(main_tree, hf_android_resolvable_private_address_offloading, tvb, offset, 1, ENC_NA);
            } else {
                proto_tree_add_item(main_tree, hf_android_resolvable_private_address_offloading_reserved, tvb, offset, 1, ENC_NA);
            }
            offset += 1;

            proto_tree_add_item(main_tree, hf_android_total_scan_results, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(main_tree, hf_android_max_irk_list, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_android_filter_support, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_android_max_filter, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_android_energy_support, tvb, offset, 1, ENC_NA);
            offset += 1;


            sub_item = proto_tree_add_item(main_tree, hf_android_version_support, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree *version_tree = proto_item_add_subtree(sub_item, ett_android_version_support);
            proto_tree_add_item(version_tree, hf_android_version_major, tvb, offset + 1, 1, ENC_NA);
            proto_tree_add_item(version_tree, hf_android_version_minor, tvb, offset, 1, ENC_NA);
            offset += 2;

            proto_tree_add_item(main_tree, hf_android_total_num_of_advt_tracked, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(main_tree, hf_android_extended_scan_support, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_android_debug_logging_support, tvb, offset, 1, ENC_NA);
            offset += 1;

            if (google_feature_spec_version < 0x0098) {
                proto_tree_add_item(main_tree, hf_android_le_address_generation_offloading_support, tvb, offset, 1, ENC_NA);
            } else {
                proto_tree_add_item(main_tree, hf_android_le_address_generation_offloading_support_reserved, tvb, offset, 1, ENC_NA);
            }
            offset += 1;

            proto_tree_add_bitmask(main_tree, tvb, offset, hf_android_a2dp_source_offload_capability_mask, ett_android_a2dp_source_offload_capability_mask, hfx_android_a2dp_source_offload_capability, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(main_tree, hf_android_bluetooth_quality_report_support, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_bitmask(main_tree, tvb, offset, hf_android_dynamic_audio_buffer_support_mask, ett_android_dynamic_audio_buffer_support_mask, hfx_android_dynamic_audio_buffer_support, ENC_LITTLE_ENDIAN);
            offset += 4;

            if (tvb_reported_length_remaining(tvb, offset) > 0) {
                proto_tree_add_item(main_tree, hf_android_a2dp_offload_v2_support, tvb, offset, 1, ENC_NA);
                offset += 1;
            }

            if (google_feature_spec_version >= 0x0105 && tvb_reported_length_remaining(tvb, offset) >= 2) {
                proto_tree_add_item(main_tree, hf_android_iso_link_layer_feedback_supported, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(main_tree, hf_android_sniff_offload_supported, tvb, offset, 1, ENC_NA);
                offset += 1;
            }

            if (google_feature_spec_version >= 0x0106 && tvb_reported_length_remaining(tvb, offset) >= 7) {
                proto_tree_add_bitmask(main_tree, tvb, offset, hf_android_big_channel_map_support, ett_android_big_channel_map_support, hfx_android_big_channel_map_support, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(main_tree, hf_android_vendor_connection_handle_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(main_tree, hf_android_vendor_connection_handle_max, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(main_tree, hf_android_connection_proximity_threshold, tvb, offset, 1, ENC_NA);
                offset += 1;
            }

            break;
        case 0x0154: /* LE Multi Advertising */
            proto_tree_add_item(main_tree, hf_android_le_multi_advertising_subcode, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 0x0156: /* LE Batch Scan */
            proto_tree_add_item_ret_uint8(main_tree, hf_android_le_batch_scan_subcode, tvb, offset, 1, ENC_NA, &subcode);
            offset += 1;

            if (subcode == 0x04 && status == STATUS_SUCCESS) { /* Read Results*/
                proto_tree_add_item(main_tree, hf_android_le_batch_scan_report_format, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(main_tree, hf_android_le_batch_scan_number_of_records, tvb, offset, 1, ENC_NA);
                offset += 1;
            }


            break;
        case 0x0157: /* LE Advertising Packet Content Filter (APCF) */ {
            uint8_t apcf_enable = 0;
            uint8_t apcf_action = 0;
            uint8_t apcf_spaces = 0;
            const char *apcf_name;

            proto_tree_add_item_ret_uint8(main_tree, hf_android_le_advertising_filter_subcode, tvb, offset, 1, ENC_NA, &subcode);
            offset += 1;
            apcf_name = val_to_str_const(subcode, android_le_subcode_advertising_filter_vals, "Unknown");

            if (status != STATUS_SUCCESS) {
                col_append_fstr(pinfo->cinfo, COL_INFO, " (%s Failed)", apcf_name);
                break;
            }

            switch (subcode) {
            case 0x00: /* Enable */
                if (tvb_reported_length_remaining(tvb, offset) >= 1) {
                    proto_tree_add_item_ret_uint8(main_tree, hf_android_apcf_enable, tvb, offset, 1, ENC_NA, &apcf_enable);
                    offset += 1;
                }
                col_append_fstr(pinfo->cinfo, COL_INFO, " (%s (%s))",
                                apcf_name, apcf_enable == 0x01 ? "Enable" : "Disable");
                break;
            case 0x01: /* Set Filtering Parameters */
            case 0x02: /* Broadcaster Address */
            case 0x03: /* Service UUID */
            case 0x04: /* Service Solicitation UUID */
            case 0x05: /* Local Name */
            case 0x06: /* Manufacturer Data */
            case 0x07: /* Service Data */
            case 0x09: /* AD Type Filter */
                if (tvb_reported_length_remaining(tvb, offset) >= 1) {
                    proto_tree_add_item_ret_uint8(main_tree, hf_android_apcf_action, tvb, offset, 1, ENC_NA, &apcf_action);
                    offset += 1;
                }
                if (tvb_reported_length_remaining(tvb, offset) >= 1) {
                    proto_tree_add_item_ret_uint8(main_tree, hf_android_apcf_available_spaces, tvb, offset, 1, ENC_NA, &apcf_spaces);
                    offset += 1;
                }
                col_append_fstr(pinfo->cinfo, COL_INFO, " (%s %s (%u Available))",
                                apcf_name,
                                val_to_str_const(apcf_action, android_apcf_action_vals, "Unknown"),
                                apcf_spaces);
                break;
            case 0xFF: /* Read Extended Features */
                if (tvb_reported_length_remaining(tvb, offset) >= 2) {
                    proto_tree_add_bitmask(main_tree, tvb, offset, hf_android_apcf_extended_features, ett_android_apcf_extended_features, hfx_android_apcf_extended_features, ENC_LITTLE_ENDIAN);
                    offset += 2;
                }
                col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", apcf_name);
                break;
            default:
                col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", apcf_name);
                break;
            }

            break;
        }
        case 0x015E: /* Bluetooth Quality Report */
            if (status != STATUS_SUCCESS)
                break;

            if (tvb_reported_length_remaining(tvb, offset) >= 4) {
                proto_tree_add_bitmask(main_tree, tvb, offset, hf_android_bqr_current_quality_event_mask,
                                       ett_android_bqr, hfx_android_quality_event_mask, ENC_LITTLE_ENDIAN);
                offset += 4;
            }
            if (tvb_reported_length_remaining(tvb, offset) >= 4) {
                proto_tree_add_item(main_tree, hf_android_bqr_current_vendor_quality_event_mask, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
            }
            if (tvb_reported_length_remaining(tvb, offset) >= 4) {
                proto_tree_add_item(main_tree, hf_android_bqr_current_vendor_trace_mask, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
            }
            if (tvb_reported_length_remaining(tvb, offset) >= 4) {
                proto_tree_add_item(main_tree, hf_android_bqr_report_interval, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
            }

            break;
        case 0x0159: /* LE Get Controller Activity Energy Info */
            if (status == STATUS_SUCCESS) {
                proto_tree_add_item(main_tree, hf_android_le_energy_total_tx_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                proto_tree_add_item(main_tree, hf_android_le_energy_total_rx_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                proto_tree_add_item(main_tree, hf_android_le_energy_total_idle_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                proto_tree_add_item(main_tree, hf_android_le_energy_total_energy_used, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
            }

            break;
        case 0x015D: /* A2DP Hardware Offload */
            proto_tree_add_item(main_tree, hf_android_a2dp_hardware_offload_subcode, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        default:
            if (tvb_reported_length_remaining(tvb, offset) > 0) {
                sub_item = proto_tree_add_item(main_tree, hf_android_data, tvb, offset, -1, ENC_NA);
                expert_add_info(pinfo, sub_item, &ei_android_undecoded);
                offset = tvb_reported_length(tvb);
            }
        }

        break;
    case 0xff: /* Vendor-Specific Event */
        if (tvb_reported_length_remaining(tvb, offset) < 1)
            break;

        proto_tree_add_item_ret_uint8(main_tree, hf_android_subevent_code, tvb, offset, 1, ENC_NA, &subcode);
        offset += 1;

        description = val_to_str_const(subcode, android_subevent_code_vals, "Unknown");
        col_set_str(pinfo->cinfo, COL_INFO, "Rcvd Android ");
        col_append_str(pinfo->cinfo, COL_INFO, description);

        switch (subcode) {
        case 0x58: /* Bluetooth Quality Report */
            if (tvb_reported_length_remaining(tvb, offset) < 1)
                break;
            proto_tree_add_item_ret_uint8(main_tree, hf_android_quality_report_id, tvb, offset, 1, ENC_NA, &subcode);
            offset += 1;
            col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)",
                            val_to_str_const(subcode, android_bqr_quality_report_id_vals, "Unknown"));
            offset = dissect_android_bqr(main_tree, pinfo, tvb, offset, subcode, interface_id, adapter_id);
            break;
        default:
            if (tvb_reported_length_remaining(tvb, offset) > 0) {
                sub_item = proto_tree_add_item(main_tree, hf_android_data, tvb, offset, -1, ENC_NA);
                expert_add_info(pinfo, sub_item, &ei_android_undecoded);
                offset = tvb_reported_length(tvb);
            }
            break;
        }

        break;
    default:
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            sub_item = proto_tree_add_item(main_tree, hf_android_data, tvb, offset, -1, ENC_NA);
            expert_add_info(pinfo, sub_item, &ei_android_undecoded);
            offset = tvb_reported_length(tvb);
        }
    }

    if (tvb_reported_length_remaining(tvb, offset)) {
        sub_item = proto_tree_add_item(main_tree, hf_android_data, tvb, offset, -1, ENC_NA);
        expert_add_info(pinfo, sub_item, &ei_android_unexpected_parameter);
        offset = tvb_reported_length(tvb);
    }
    return offset;
}

static int
dissect_bthci_vendor_android(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item        *main_item;
    proto_tree        *main_tree;
    proto_item        *opcode_item;
    proto_tree        *opcode_tree;
    proto_item        *sub_item;
    bluetooth_data_t  *bluetooth_data;
    int                offset = 0;
    tvbuff_t          *parameter_tvb;
    uint16_t           opcode;
    uint16_t           ocf;
    const char        *description;
    uint8_t            length;
    uint8_t            event_code;
    uint32_t           interface_id;
    uint32_t           adapter_id;

    bluetooth_data = (bluetooth_data_t *) data;
    if (bluetooth_data) {
        interface_id  = bluetooth_data->interface_id;
        adapter_id    = bluetooth_data->adapter_id;
    } else {
        interface_id  = HCI_INTERFACE_DEFAULT;
        adapter_id    = HCI_ADAPTER_DEFAULT;
    }

    main_item = proto_tree_add_item(tree, proto_bthci_vendor_android, tvb, 0, -1, ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_android);

    switch (pinfo->p2p_dir) {

    case P2P_DIR_SENT:
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "HCI_CMD_ANDROID");
        col_set_str(pinfo->cinfo, COL_INFO, "Sent Android ");

        opcode_item = proto_tree_add_item(main_tree, hf_android_opcode, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        opcode_tree = proto_item_add_subtree(opcode_item, ett_android_opcode);
        opcode = tvb_get_letohs(tvb, offset);
        proto_tree_add_item(opcode_tree, hf_android_opcode_ogf, tvb, offset, 2, ENC_LITTLE_ENDIAN);

        proto_tree_add_item(opcode_tree, hf_android_opcode_ocf, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        ocf = opcode & 0x03ff;
        offset+=2;

        description = val_to_str_const(ocf, android_opcode_ocf_vals, "unknown");
        if (g_strcmp0(description, "unknown") != 0)
            col_append_str(pinfo->cinfo, COL_INFO, description);
        else
            col_append_fstr(pinfo->cinfo, COL_INFO, "Unknown Command 0x%04X (opcode 0x%04X)", ocf, opcode);

        if (have_tap_listener(bluetooth_hci_summary_tap)) {
            bluetooth_hci_summary_tap_t  *tap_hci_summary;

            tap_hci_summary = wmem_new(pinfo->pool, bluetooth_hci_summary_tap_t);
            tap_hci_summary->interface_id  = interface_id;
            tap_hci_summary->adapter_id    = adapter_id;

            tap_hci_summary->type = BLUETOOTH_HCI_SUMMARY_VENDOR_OPCODE;
            tap_hci_summary->ogf = opcode >> 10;
            tap_hci_summary->ocf = ocf;
            if (try_val_to_str(ocf, android_opcode_ocf_vals))
                tap_hci_summary->name = description;
            else
                tap_hci_summary->name = NULL;
            tap_queue_packet(bluetooth_hci_summary_tap, pinfo, tap_hci_summary);
        }

        proto_tree_add_item_ret_uint8(main_tree, hf_android_parameter_length, tvb, offset, 1, ENC_NA, &length);
        offset += 1;

        parameter_tvb = tvb_new_subset_length(tvb, offset, length);
        offset += dissect_bthci_vendor_android_cmd(parameter_tvb, pinfo, main_tree, data, ocf);

        break;
    case P2P_DIR_RECV:
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "HCI_EVT_ANDROID");
        col_set_str(pinfo->cinfo, COL_INFO, "Rcvd Android ");

        event_code = tvb_get_uint8(tvb, offset);
        description = val_to_str_ext(pinfo->pool, event_code, &bthci_evt_evt_code_vals_ext, "Unknown 0x%08x");
        col_append_str(pinfo->cinfo, COL_INFO, description);
        proto_tree_add_item(main_tree, hf_android_event_code, tvb, offset, 1, ENC_NA);
        offset += 1;

        if (have_tap_listener(bluetooth_hci_summary_tap)) {
            bluetooth_hci_summary_tap_t  *tap_hci_summary;

            tap_hci_summary = wmem_new(pinfo->pool, bluetooth_hci_summary_tap_t);
            tap_hci_summary->interface_id  = interface_id;
            tap_hci_summary->adapter_id    = adapter_id;

            tap_hci_summary->type = BLUETOOTH_HCI_SUMMARY_VENDOR_EVENT;
            tap_hci_summary->event = event_code;
            if (try_val_to_str_ext(event_code, &bthci_evt_evt_code_vals_ext))
                tap_hci_summary->name = description;
            else
                tap_hci_summary->name = NULL;
            tap_queue_packet(bluetooth_hci_summary_tap, pinfo, tap_hci_summary);
        }

        proto_tree_add_item_ret_uint8(main_tree, hf_android_parameter_length, tvb, offset, 1, ENC_NA, &length);
        offset += 1;

        parameter_tvb = tvb_new_subset_length(tvb, offset, length);
        offset += dissect_bthci_vendor_android_evt(parameter_tvb, pinfo, main_tree, data, event_code);
        break;

    case P2P_DIR_UNKNOWN:
    default:
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "HCI_ANDROID");
        col_set_str(pinfo->cinfo, COL_INFO, "UnknownDirection Android ");

        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(main_tree, hf_android_data, tvb, offset, -1, ENC_NA);
            offset = tvb_reported_length(tvb);
        }
        break;
    }

    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        sub_item = proto_tree_add_item(main_tree, hf_android_data, tvb, offset, -1, ENC_NA);
        expert_add_info(pinfo, sub_item, &ei_android_unexpected_data);
        offset = tvb_reported_length(tvb);
    }

    return offset;
}

void
proto_register_bthci_vendor_android(void)
{
    expert_module_t  *expert_module;

    static hf_register_info hf[] = {
        { &hf_android_opcode,
          { "Command Opcode",                              "bthci_vendor.android.opcode",
            FT_UINT16, BASE_HEX, VALS(android_opcode_vals), 0x0,
            "HCI Command Opcode", HFILL }
        },
        { &hf_android_opcode_ogf,
          { "Opcode Group Field",                          "bthci_vendor.android.opcode.ogf",
            FT_UINT16, BASE_HEX|BASE_EXT_STRING, &bthci_cmd_ogf_vals_ext, 0xfc00,
            NULL, HFILL }
        },
        { &hf_android_opcode_ocf,
          { "Opcode Command Field",                        "bthci_vendor.android.opcode.ocf",
            FT_UINT16, BASE_HEX, VALS(android_opcode_ocf_vals), 0x03ff,
            NULL, HFILL }
        },
        { &hf_android_parameter_length,
          { "Parameter Total Length",                      "bthci_vendor.android.parameter_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_event_code,
          { "Event Code",                                  "bthci_vendor.android.event_code",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &bthci_evt_evt_code_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_android_number_of_allowed_command_packets,
          { "Number of Allowed Command Packets",           "bthci_vendor.android.number_of_allowed_command_packets",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_le_advertising_filter_subcode,
            { "APCF Opcode",                               "bthci_vendor.android.le.advertising_filter.subcode",
            FT_UINT8, BASE_HEX, VALS(android_le_subcode_advertising_filter_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_android_apcf_enable,
            { "APCF Enable",                               "bthci_vendor.android.apcf.enable",
            FT_UINT8, BASE_DEC, VALS(android_disable_enable_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_android_apcf_action,
            { "Action",                                    "bthci_vendor.android.apcf.action",
            FT_UINT8, BASE_DEC, VALS(android_apcf_action_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_android_apcf_filter_index,
            { "Filter Index",                              "bthci_vendor.android.apcf.filter_index",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_apcf_available_spaces,
            { "Number of Available Spaces",               "bthci_vendor.android.apcf.available_spaces",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_apcf_feature_selection,
            { "Feature Selection",                        "bthci_vendor.android.apcf.feature_selection",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_apcf_feature_broadcast_address,
            { "Enable Broadcast Address Filter",          "bthci_vendor.android.apcf.feature_selection.broadcast_address",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL }
        },
        { &hf_android_apcf_feature_service_data_change,
            { "Enable Service Data Change Filter",        "bthci_vendor.android.apcf.feature_selection.service_data_change",
            FT_BOOLEAN, 16, NULL, 0x0002,
            NULL, HFILL }
        },
        { &hf_android_apcf_feature_service_uuid,
            { "Enable Service UUID Check",                "bthci_vendor.android.apcf.feature_selection.service_uuid",
            FT_BOOLEAN, 16, NULL, 0x0004,
            NULL, HFILL }
        },
        { &hf_android_apcf_feature_service_solicitation_uuid,
            { "Enable Service Solicitation UUID Check",   "bthci_vendor.android.apcf.feature_selection.service_solicitation_uuid",
            FT_BOOLEAN, 16, NULL, 0x0008,
            NULL, HFILL }
        },
        { &hf_android_apcf_feature_local_name,
            { "Enable Local Name Check",                  "bthci_vendor.android.apcf.feature_selection.local_name",
            FT_BOOLEAN, 16, NULL, 0x0010,
            NULL, HFILL }
        },
        { &hf_android_apcf_feature_manufacturer_data,
            { "Enable Manufacturer Data Check",           "bthci_vendor.android.apcf.feature_selection.manufacturer_data",
            FT_BOOLEAN, 16, NULL, 0x0020,
            NULL, HFILL }
        },
        { &hf_android_apcf_feature_service_data,
            { "Enable Service Data Check",                "bthci_vendor.android.apcf.feature_selection.service_data",
            FT_BOOLEAN, 16, NULL, 0x0040,
            NULL, HFILL }
        },
        { &hf_android_apcf_feature_transport_discovery_service,
            { "Enable Transport Discovery Service Check", "bthci_vendor.android.apcf.feature_selection.transport_discovery_service",
            FT_BOOLEAN, 16, NULL, 0x0080,
            NULL, HFILL }
        },
        { &hf_android_apcf_feature_ad_type,
            { "Enable AD Type Check",                     "bthci_vendor.android.apcf.feature_selection.ad_type",
            FT_BOOLEAN, 16, NULL, 0x0100,
            NULL, HFILL }
        },
        { &hf_android_apcf_feature_reserved,
            { "Reserved",                                 "bthci_vendor.android.apcf.feature_selection.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xFE00,
            NULL, HFILL }
        },
        { &hf_android_apcf_list_logic,
            { "Feature Selection List Logic",             "bthci_vendor.android.apcf.list_logic",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_apcf_list_logic_broadcast_address,
            { "Broadcast Address Filter Logic",           "bthci_vendor.android.apcf.list_logic.broadcast_address",
            FT_BOOLEAN, 16, TFS(&tfs_apcf_logic), 0x0001,
            NULL, HFILL }
        },
        { &hf_android_apcf_list_logic_service_data_change,
            { "Service Data Change Filter Logic",         "bthci_vendor.android.apcf.list_logic.service_data_change",
            FT_BOOLEAN, 16, TFS(&tfs_apcf_logic), 0x0002,
            NULL, HFILL }
        },
        { &hf_android_apcf_list_logic_service_uuid,
            { "Service UUID Check Logic",                 "bthci_vendor.android.apcf.list_logic.service_uuid",
            FT_BOOLEAN, 16, TFS(&tfs_apcf_logic), 0x0004,
            NULL, HFILL }
        },
        { &hf_android_apcf_list_logic_service_solicitation_uuid,
            { "Service Solicitation UUID Check Logic",    "bthci_vendor.android.apcf.list_logic.service_solicitation_uuid",
            FT_BOOLEAN, 16, TFS(&tfs_apcf_logic), 0x0008,
            NULL, HFILL }
        },
        { &hf_android_apcf_list_logic_local_name,
            { "Local Name Check Logic",                   "bthci_vendor.android.apcf.list_logic.local_name",
            FT_BOOLEAN, 16, TFS(&tfs_apcf_logic), 0x0010,
            NULL, HFILL }
        },
        { &hf_android_apcf_list_logic_manufacturer_data,
            { "Manufacturer Data Check Logic",            "bthci_vendor.android.apcf.list_logic.manufacturer_data",
            FT_BOOLEAN, 16, TFS(&tfs_apcf_logic), 0x0020,
            NULL, HFILL }
        },
        { &hf_android_apcf_list_logic_service_data,
            { "Service Data Check Logic",                 "bthci_vendor.android.apcf.list_logic.service_data",
            FT_BOOLEAN, 16, TFS(&tfs_apcf_logic), 0x0040,
            NULL, HFILL }
        },
        { &hf_android_apcf_list_logic_transport_discovery_service,
            { "Transport Discovery Service Check Logic",  "bthci_vendor.android.apcf.list_logic.transport_discovery_service",
            FT_BOOLEAN, 16, TFS(&tfs_apcf_logic), 0x0080,
            NULL, HFILL }
        },
        { &hf_android_apcf_list_logic_ad_type,
            { "AD Type Check Logic",                      "bthci_vendor.android.apcf.list_logic.ad_type",
            FT_BOOLEAN, 16, TFS(&tfs_apcf_logic), 0x0100,
            NULL, HFILL }
        },
        { &hf_android_apcf_list_logic_reserved,
            { "Reserved",                                 "bthci_vendor.android.apcf.list_logic.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xFE00,
            NULL, HFILL }
        },
        { &hf_android_apcf_filter_logic_type,
            { "Filter Logic Type",                        "bthci_vendor.android.apcf.filter_logic_type",
            FT_UINT8, BASE_DEC, VALS(android_apcf_filter_logic_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_android_apcf_rssi_high_threshold,
            { "RSSI High Threshold",                      "bthci_vendor.android.apcf.rssi_high_threshold",
            FT_INT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_apcf_delivery_mode,
            { "Delivery Mode",                            "bthci_vendor.android.apcf.delivery_mode",
            FT_UINT8, BASE_DEC, VALS(android_apcf_delivery_mode_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_android_apcf_onfound_timeout,
            { "OnFound Timeout",                          "bthci_vendor.android.apcf.onfound_timeout",
            FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
            NULL, HFILL }
        },
        { &hf_android_apcf_onfound_timeout_count,
            { "OnFound Timeout Count",                    "bthci_vendor.android.apcf.onfound_timeout_count",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_apcf_rssi_low_threshold,
            { "RSSI Low Threshold",                       "bthci_vendor.android.apcf.rssi_low_threshold",
            FT_INT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_apcf_onlost_timeout,
            { "OnLost Timeout",                           "bthci_vendor.android.apcf.onlost_timeout",
            FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
            NULL, HFILL }
        },
        { &hf_android_apcf_num_of_tracking_entries,
            { "Number of Tracking Entries",               "bthci_vendor.android.apcf.num_of_tracking_entries",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_apcf_broadcaster_address,
            { "Broadcaster Address",                      "bthci_vendor.android.apcf.broadcaster_address",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_apcf_application_address_type,
            { "Application Address Type",                 "bthci_vendor.android.apcf.application_address_type",
            FT_UINT8, BASE_DEC, VALS(android_apcf_application_address_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_android_apcf_uuid,
            { "UUID",                                     "bthci_vendor.android.apcf.uuid",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_apcf_uuid_mask,
            { "UUID Mask",                                "bthci_vendor.android.apcf.uuid_mask",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_apcf_data,
            { "Data",                                     "bthci_vendor.android.apcf.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_apcf_mask,
            { "Mask",                                     "bthci_vendor.android.apcf.mask",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_apcf_ad_type,
            { "AD Type",                                  "bthci_vendor.android.apcf.ad_type",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_apcf_ad_data_length,
            { "AD Data Length",                           "bthci_vendor.android.apcf.ad_data_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_apcf_ad_data,
            { "AD Data",                                  "bthci_vendor.android.apcf.ad_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_apcf_ad_data_mask,
            { "AD Data Mask",                             "bthci_vendor.android.apcf.ad_data_mask",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_apcf_extended_features,
            { "Extended Features",                        "bthci_vendor.android.apcf.extended_features",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_apcf_extended_features_transport_discovery_service,
            { "Transport Discovery Service Filter Supported", "bthci_vendor.android.apcf.extended_features.transport_discovery_service",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL }
        },
        { &hf_android_apcf_extended_features_ad_type,
            { "AD Type Filter Supported",                 "bthci_vendor.android.apcf.extended_features.ad_type",
            FT_BOOLEAN, 16, NULL, 0x0002,
            NULL, HFILL }
        },
        { &hf_android_apcf_extended_features_reserved,
            { "Reserved",                                 "bthci_vendor.android.apcf.extended_features.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xFFFC,
            NULL, HFILL }
        },
        { &hf_android_bqr_link_packet_type,
            { "Packet Type", "bthci_vendor.android.bqr.link.packet_type",
            FT_UINT8, BASE_HEX, VALS(android_bqr_packet_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_link_connection_handle,
            { "Connection Handle", "bthci_vendor.android.bqr.link.connection_handle",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_link_connection_role,
            { "Connection Role", "bthci_vendor.android.bqr.link.connection_role",
            FT_UINT8, BASE_HEX, VALS(android_bqr_connection_role_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_link_tx_power,
            { "TX Power Level", "bthci_vendor.android.bqr.link.tx_power",
            FT_INT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_link_rssi,
            { "RSSI", "bthci_vendor.android.bqr.link.rssi",
            FT_INT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_link_snr,
            { "SNR", "bthci_vendor.android.bqr.link.snr",
            FT_INT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_link_unused_afh_channels,
            { "Unused AFH Channel Count", "bthci_vendor.android.bqr.link.unused_afh_channel_count",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_link_afh_unideal_channels,
            { "AFH Select Unideal Channel Count", "bthci_vendor.android.bqr.link.afh_unideal_channel_count",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_link_lsto,
            { "LSTO (Link Supervision Timeout)", "bthci_vendor.android.bqr.link.lsto",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(android_bqr_lsto_fmt), 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_link_piconet_clock,
            { "Connection Piconet Clock", "bthci_vendor.android.bqr.link.piconet_clock",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(android_bqr_bt_clock_fmt), 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_link_retransmission_count,
            { "Retransmission Count", "bthci_vendor.android.bqr.link.retransmission_count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_link_no_rx_count,
            { "No RX Count", "bthci_vendor.android.bqr.link.no_rx_count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_link_nak_count,
            { "NAK Count", "bthci_vendor.android.bqr.link.nak_count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_link_last_tx_ack_timestamp,
            { "Last TX ACK Timestamp", "bthci_vendor.android.bqr.link.last_tx_ack_timestamp",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(android_bqr_bt_clock_fmt), 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_link_flow_off_count,
            { "Flow Off Count", "bthci_vendor.android.bqr.link.flow_off_count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_link_last_flow_on_timestamp,
            { "Last Flow On Timestamp", "bthci_vendor.android.bqr.link.last_flow_on_timestamp",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(android_bqr_bt_clock_fmt), 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_link_buffer_overflow_bytes,
            { "Buffer Overflow Bytes", "bthci_vendor.android.bqr.link.buffer_overflow_bytes",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_link_buffer_underflow_bytes,
            { "Buffer Underflow Bytes", "bthci_vendor.android.bqr.link.buffer_underflow_bytes",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_link_cal_failed_item_count,
            { "Calibration Failed Item Count", "bthci_vendor.android.bqr.link.cal_failed_item_count",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_link_tx_total_packets,
            { "TX Total Packets", "bthci_vendor.android.bqr.link.tx_total_packets",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_link_tx_unacked_packets,
            { "TX Unacked Packets", "bthci_vendor.android.bqr.link.tx_unacked_packets",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_link_tx_flushed_packets,
            { "TX Flushed Packets", "bthci_vendor.android.bqr.link.tx_flushed_packets",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_link_tx_last_subevent_packets,
            { "TX Last Subevent Packets", "bthci_vendor.android.bqr.link.tx_last_subevent_packets",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_link_crc_error_packets,
            { "CRC Error Packets", "bthci_vendor.android.bqr.link.crc_error_packets",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_link_rx_duplicate_packets,
            { "RX Duplicate Packets", "bthci_vendor.android.bqr.link.rx_duplicate_packets",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_link_rx_unreceived_packets,
            { "RX Unreceived Packets", "bthci_vendor.android.bqr.link.rx_unreceived_packets",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_link_coex_info_mask,
            { "Coex Info Mask", "bthci_vendor.android.bqr.link.coex_info_mask",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_link_coex_involvement,
            { "Coex Involvement", "bthci_vendor.android.bqr.link.coex_info_mask.coex_involvement",
            FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL }
        },
        { &hf_android_bqr_link_coex_wl_2g_active,
            { "WLAN 2G Radio Active", "bthci_vendor.android.bqr.link.coex_info_mask.wl_2g_active",
            FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL }
        },
        { &hf_android_bqr_link_coex_wl_2g_connected,
            { "WLAN 2G Radio Active and Connected", "bthci_vendor.android.bqr.link.coex_info_mask.wl_2g_connected",
            FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL }
        },
        { &hf_android_bqr_link_coex_wl_5g_6g_active,
            { "WLAN 5G/6G Radio Active", "bthci_vendor.android.bqr.link.coex_info_mask.wl_5g_6g_active",
            FT_BOOLEAN, 16, NULL, 0x0008, NULL, HFILL }
        },
        { &hf_android_bqr_link_coex_reserved,
            { "Reserved", "bthci_vendor.android.bqr.link.coex_info_mask.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xFFF0, NULL, HFILL }
        },
        { &hf_android_bqr_root_error_code,
            { "Error Code", "bthci_vendor.android.bqr.root.error_code",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_root_vendor_error_code,
            { "Vendor Specific Error Code", "bthci_vendor.android.bqr.root.vendor_error_code",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_energy_average_current,
            { "Average Current Consumption", "bthci_vendor.android.bqr.energy.average_current",
            FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliamps), 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_energy_idle_total_time,
            { "Idle Total Time", "bthci_vendor.android.bqr.energy.idle_total_time",
            FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_energy_idle_enter_count,
            { "Idle State Enter Count", "bthci_vendor.android.bqr.energy.idle_enter_count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_energy_active_total_time,
            { "Active Total Time", "bthci_vendor.android.bqr.energy.active_total_time",
            FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_energy_active_enter_count,
            { "Active State Enter Count", "bthci_vendor.android.bqr.energy.active_enter_count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_energy_bredr_tx_total_time,
            { "BR/EDR TX Total Time", "bthci_vendor.android.bqr.energy.br_edr_tx_time",
            FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_energy_bredr_tx_enter_count,
            { "BR/EDR TX State Enter Count", "bthci_vendor.android.bqr.energy.br_edr_tx_count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_energy_bredr_tx_avg_power,
            { "BR/EDR TX Average Power", "bthci_vendor.android.bqr.energy.br_edr_tx_power",
            FT_INT8, BASE_DEC|BASE_UNIT_STRING, UNS(&units_dbm), 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_energy_bredr_rx_total_time,
            { "BR/EDR RX Total Time", "bthci_vendor.android.bqr.energy.br_edr_rx_time",
            FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_energy_bredr_rx_enter_count,
            { "BR/EDR RX State Enter Count", "bthci_vendor.android.bqr.energy.br_edr_rx_count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_energy_le_tx_total_time,
            { "LE TX Total Time", "bthci_vendor.android.bqr.energy.le_tx_time",
            FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_energy_le_tx_enter_count,
            { "LE TX State Enter Count", "bthci_vendor.android.bqr.energy.le_tx_count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_energy_le_tx_avg_power,
            { "LE TX Average Power", "bthci_vendor.android.bqr.energy.le_tx_power",
            FT_INT8, BASE_DEC|BASE_UNIT_STRING, UNS(&units_dbm), 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_energy_le_rx_total_time,
            { "LE RX Total Time", "bthci_vendor.android.bqr.energy.le_rx_time",
            FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_energy_le_rx_enter_count,
            { "LE RX State Enter Count", "bthci_vendor.android.bqr.energy.le_rx_count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_energy_report_time_duration,
            { "Report Time Duration", "bthci_vendor.android.bqr.energy.report_duration",
            FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_energy_rx_active_one_chain_time,
            { "RX Active One Chain Time", "bthci_vendor.android.bqr.energy.rx_one_chain",
            FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_energy_rx_active_two_chain_time,
            { "RX Active Two Chain Time", "bthci_vendor.android.bqr.energy.rx_two_chain",
            FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_energy_tx_ipa_active_one_chain_time,
            { "TX iPA Active One Chain Time", "bthci_vendor.android.bqr.energy.tx_ipa_one_chain",
            FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_energy_tx_ipa_active_two_chain_time,
            { "TX iPA Active Two Chain Time", "bthci_vendor.android.bqr.energy.tx_ipa_two_chain",
            FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_energy_tx_epa_active_one_chain_time,
            { "TX ePA Active One Chain Time", "bthci_vendor.android.bqr.energy.tx_epa_one_chain",
            FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_energy_tx_epa_active_two_chain_time,
            { "TX ePA Active Two Chain Time", "bthci_vendor.android.bqr.energy.tx_epa_two_chain",
            FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_energy_bredr_rx_scan_total_time,
            { "BR/EDR RX Scan Total Time", "bthci_vendor.android.bqr.energy.bredr_scan_time",
            FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_energy_le_rx_scan_total_time,
            { "LE RX Scan Total Time", "bthci_vendor.android.bqr.energy.le_scan_time",
            FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_advanced_extension_info,
            { "Extension Info", "bthci_vendor.android.bqr.advanced.extension_info",
            FT_UINT8, BASE_DEC, VALS(android_bqr_extension_info_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_advanced_report_time_period,
            { "Report Time Period", "bthci_vendor.android.bqr.advanced.report_time_period",
            FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_advanced_tx_power_ipa_bf,
            { "TX Power iPA BF", "bthci_vendor.android.bqr.advanced.tx_power_ipa_bf",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_advanced_tx_power_epa_bf,
            { "TX Power ePA BF", "bthci_vendor.android.bqr.advanced.tx_power_epa_bf",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_advanced_tx_power_ipa_div,
            { "TX Power iPA Div", "bthci_vendor.android.bqr.advanced.tx_power_ipa_div",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_advanced_tx_power_epa_div,
            { "TX Power ePA Div", "bthci_vendor.android.bqr.advanced.tx_power_epa_div",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_advanced_rssi_chain_50,
            { "RSSI Chain > -50", "bthci_vendor.android.bqr.advanced.rssi_chain_50",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_advanced_rssi_chain_50_55,
            { "RSSI Chain -50 to -55", "bthci_vendor.android.bqr.advanced.rssi_chain_50_55",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_advanced_rssi_chain_55_60,
            { "RSSI Chain -55 to -60", "bthci_vendor.android.bqr.advanced.rssi_chain_55_60",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_advanced_rssi_chain_60_65,
            { "RSSI Chain -60 to -65", "bthci_vendor.android.bqr.advanced.rssi_chain_60_65",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_advanced_rssi_chain_65_70,
            { "RSSI Chain -65 to -70", "bthci_vendor.android.bqr.advanced.rssi_chain_65_70",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_advanced_rssi_chain_70_75,
            { "RSSI Chain -70 to -75", "bthci_vendor.android.bqr.advanced.rssi_chain_70_75",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_advanced_rssi_chain_75_80,
            { "RSSI Chain -75 to -80", "bthci_vendor.android.bqr.advanced.rssi_chain_75_80",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_advanced_rssi_chain_80_85,
            { "RSSI Chain -80 to -85", "bthci_vendor.android.bqr.advanced.rssi_chain_80_85",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_advanced_rssi_chain_85_90,
            { "RSSI Chain -85 to -90", "bthci_vendor.android.bqr.advanced.rssi_chain_85_90",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_advanced_rssi_chain_90,
            { "RSSI Chain < -90", "bthci_vendor.android.bqr.advanced.rssi_chain_90",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_advanced_rssi_delta_2,
            { "RSSI Delta < 2", "bthci_vendor.android.bqr.advanced.rssi_delta_2",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_advanced_rssi_delta_2_5,
            { "RSSI Delta 2 to 5", "bthci_vendor.android.bqr.advanced.rssi_delta_2_5",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_advanced_rssi_delta_5_8,
            { "RSSI Delta 5 to 8", "bthci_vendor.android.bqr.advanced.rssi_delta_5_8",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_advanced_rssi_delta_8_11,
            { "RSSI Delta 8 to 11", "bthci_vendor.android.bqr.advanced.rssi_delta_8_11",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_advanced_rssi_delta_11,
            { "RSSI Delta > 11", "bthci_vendor.android.bqr.advanced.rssi_delta_11",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_advanced_antenna_switch_count,
            { "Antenna Switch Count", "bthci_vendor.android.bqr.advanced.antenna_switch_count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_advanced_retx_ipa_bf,
            { "ReTX iPA BF", "bthci_vendor.android.bqr.advanced.retx_ipa_bf",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_advanced_retx_epa_bf,
            { "ReTX ePA BF", "bthci_vendor.android.bqr.advanced.retx_epa_bf",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_advanced_retx_ipa_div,
            { "ReTX iPA Div", "bthci_vendor.android.bqr.advanced.retx_ipa_div",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_advanced_retx_epa_div,
            { "ReTX ePA Div", "bthci_vendor.android.bqr.advanced.retx_epa_div",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_advanced_channel_count_good,
            { "Channel Count Good (Bin-4, RSSI > -50 dBm)", "bthci_vendor.android.bqr.advanced.channel_count_good",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_advanced_channel_count_ok,
            { "Channel Count OK (Bin-3, RSSI -76 to -50 dBm)", "bthci_vendor.android.bqr.advanced.channel_count_ok",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_advanced_channel_count_bad,
            { "Channel Count Bad (Bin-2, RSSI -90 to -76 dBm)", "bthci_vendor.android.bqr.advanced.channel_count_bad",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_advanced_channel_count_very_bad,
            { "Channel Count Very Bad (Bin-1, RSSI < -90 dBm)", "bthci_vendor.android.bqr.advanced.channel_count_very_bad",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_advanced_tx_buffer_queue_count,
            { "TX Buffer Queue Count", "bthci_vendor.android.bqr.advanced.tx_buffer_queue_count",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_advanced_tx_buffer_acl_1,
            { "ACL_1 [0:3]", "bthci_vendor.android.bqr.advanced.tx_buffer_queue_count.acl_1",
            FT_UINT32, BASE_DEC, NULL, 0x0000000F, NULL, HFILL }
        },
        { &hf_android_bqr_advanced_tx_buffer_acl_2,
            { "ACL_2 [4:7]", "bthci_vendor.android.bqr.advanced.tx_buffer_queue_count.acl_2",
            FT_UINT32, BASE_DEC, NULL, 0x000000F0, NULL, HFILL }
        },
        { &hf_android_bqr_advanced_tx_buffer_leconn_1,
            { "LECONN_1 [8:11]", "bthci_vendor.android.bqr.advanced.tx_buffer_queue_count.leconn_1",
            FT_UINT32, BASE_DEC, NULL, 0x00000F00, NULL, HFILL }
        },
        { &hf_android_bqr_advanced_tx_buffer_leconn_2,
            { "LECONN_2 [12:15]", "bthci_vendor.android.bqr.advanced.tx_buffer_queue_count.leconn_2",
            FT_UINT32, BASE_DEC, NULL, 0x0000F000, NULL, HFILL }
        },
        { &hf_android_bqr_advanced_tx_buffer_leisoc_1,
            { "LEISOC_1 [16:19]", "bthci_vendor.android.bqr.advanced.tx_buffer_queue_count.leisoc_1",
            FT_UINT32, BASE_DEC, NULL, 0x000F0000, NULL, HFILL }
        },
        { &hf_android_bqr_advanced_tx_buffer_leisoc_2,
            { "LEISOC_2 [20:23]", "bthci_vendor.android.bqr.advanced.tx_buffer_queue_count.leisoc_2",
            FT_UINT32, BASE_DEC, NULL, 0x00F00000, NULL, HFILL }
        },
        { &hf_android_bqr_advanced_tx_buffer_lebroadcast,
            { "LEBroadcast [24:27]", "bthci_vendor.android.bqr.advanced.tx_buffer_queue_count.lebroadcast",
            FT_UINT32, BASE_DEC, NULL, 0x0F000000, NULL, HFILL }
        },
        { &hf_android_bqr_advanced_tx_buffer_reserved,
            { "Reserved [28:31]", "bthci_vendor.android.bqr.advanced.tx_buffer_queue_count.reserved",
            FT_UINT32, BASE_DEC, NULL, 0xF0000000, NULL, HFILL }
        },
        { &hf_android_bqr_health_packet_count_host_to_controller,
            { "Packets Host to Controller", "bthci_vendor.android.bqr.health.packet_host_to_controller",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_health_packet_count_controller_to_host,
            { "Packets Controller to Host", "bthci_vendor.android.bqr.health.packet_controller_to_host",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_health_last_packet_length_host_to_controller,
            { "Last Packet Length Host to Controller", "bthci_vendor.android.bqr.health.last_packet_host_to_controller",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_health_last_packet_length_controller_to_host,
            { "Last Packet Length Controller to Host", "bthci_vendor.android.bqr.health.last_packet_controller_to_host",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_health_total_bt_wake_count,
            { "BT Wake Count", "bthci_vendor.android.bqr.health.bt_wake_count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_health_total_host_wake_count,
            { "Host Wake Count", "bthci_vendor.android.bqr.health.host_wake_count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_health_last_bt_wake_timestamp,
            { "Last BT Wake Timestamp", "bthci_vendor.android.bqr.health.last_bt_wake_timestamp",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_health_last_host_wake_timestamp,
            { "Last Host Wake Timestamp", "bthci_vendor.android.bqr.health.last_host_wake_timestamp",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_health_reset_timestamp,
            { "Reset Timestamp", "bthci_vendor.android.bqr.health.reset_timestamp",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_health_current_timestamp,
            { "Current Timestamp", "bthci_vendor.android.bqr.health.current_timestamp",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_health_watchdog_expiring,
            { "Watchdog Timer About To Expire", "bthci_vendor.android.bqr.health.watchdog_expiring",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_health_coex_status_mask,
            { "Coex Status Mask", "bthci_vendor.android.bqr.health.coex_status_mask",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_health_total_links_bredr_le_active,
            { "Active BR/EDR/LE Links", "bthci_vendor.android.bqr.health.active_links",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_health_total_links_bredr_sniff,
            { "BR/EDR Sniff Links", "bthci_vendor.android.bqr.health.sniff_links",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_health_total_links_cis,
            { "CIS Links", "bthci_vendor.android.bqr.health.cis_links",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_health_is_sco_active,
            { "SCO Active", "bthci_vendor.android.bqr.health.sco_active",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_log_connection_handle,
            { "Connection Handle", "bthci_vendor.android.bqr.log.connection_handle",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_lea_big_handle,
            { "BIG Handle", "bthci_vendor.android.bqr.lea.big_handle",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_lea_source_bd_addr_type,
            { "Broadcast Source BD_ADDR Type", "bthci_vendor.android.bqr.lea.source_bd_addr_type",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_lea_source_bd_addr,
            { "Broadcast Source BD_ADDR", "bthci_vendor.android.bqr.lea.source_bd_addr",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_lea_source_prefer_channel_map,
            { "BIG Source Preferred Channel Map", "bthci_vendor.android.bqr.lea.source_prefer_channel_map",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_lea_source_used_channel_map,
            { "BIG Source Used Channel Map", "bthci_vendor.android.bqr.lea.source_used_channel_map",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_lea_tx_power,
            { "BIG TX Power", "bthci_vendor.android.bqr.lea.tx_power",
            FT_INT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_lea_timestamp,
            { "Timestamp", "bthci_vendor.android.bqr.lea.timestamp",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(android_bqr_bt_clock_fmt), 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_lea_subscribed_broadcast_id,
            { "Subscribed Broadcast ID", "bthci_vendor.android.bqr.lea.subscribed_broadcast_id",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_lea_receiver_bd_addr_type,
            { "Broadcast Receiver BD_ADDR Type", "bthci_vendor.android.bqr.lea.receiver_bd_addr_type",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_lea_receiver_bd_addr,
            { "Broadcast Receiver BD_ADDR", "bthci_vendor.android.bqr.lea.receiver_bd_addr",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_lea_time_duration,
            { "Time Duration", "bthci_vendor.android.bqr.lea.time_duration",
            FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_lea_bis_choppy_count,
            { "BIS Choppy Count", "bthci_vendor.android.bqr.lea.bis_choppy_count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_lea_per,
            { "PER", "bthci_vendor.android.bqr.lea.per",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_lea_no_sync,
            { "No Sync", "bthci_vendor.android.bqr.lea.no_sync",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_lea_receiver_prefer_channel_map,
            { "Receiver Preferred Channel Map", "bthci_vendor.android.bqr.lea.receiver_prefer_channel_map",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_lea_receiver_tx_power,
            { "Receiver TX Power", "bthci_vendor.android.bqr.lea.receiver_tx_power",
            FT_INT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_lea_rssi,
            { "RSSI", "bthci_vendor.android.bqr.lea.rssi",
            FT_INT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_lea_reserved,
            { "Reserved", "bthci_vendor.android.bqr.lea.reserved",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_vendor_data,
            { "Vendor Specific Data", "bthci_vendor.android.bqr.vendor_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_subevent_code,
            { "Subevent Code", "bthci_vendor.android.subevent_code",
            FT_UINT8, BASE_HEX, VALS(android_subevent_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_android_quality_report_id,
            { "Quality Report ID", "bthci_vendor.android.quality_report_id",
            FT_UINT8, BASE_HEX, VALS(android_bqr_quality_report_id_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_action,
            { "BQR Report Action", "bthci_vendor.android.bqr.action",
            FT_UINT8, BASE_DEC, VALS(android_bqr_action_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_minimum_report_interval,
            { "Minimum Report Interval", "bthci_vendor.android.bqr.minimum_report_interval",
            FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_vendor_quality_event_mask,
            { "Vendor Specific Quality Event Mask", "bthci_vendor.android.bqr.vendor_quality_event_mask",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_vendor_trace_mask,
            { "Vendor Specific Trace Mask", "bthci_vendor.android.bqr.vendor_trace_mask",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_report_interval_multiple,
            { "Report Interval Multiple", "bthci_vendor.android.bqr.report_interval_multiple",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_current_quality_event_mask,
            { "Current Quality Event Mask", "bthci_vendor.android.bqr.current_quality_event_mask",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_current_vendor_quality_event_mask,
            { "Current Vendor Specific Quality Event Mask", "bthci_vendor.android.bqr.current_vendor_quality_event_mask",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_current_vendor_trace_mask,
            { "Current Vendor Specific Trace Mask", "bthci_vendor.android.bqr.current_vendor_trace_mask",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_bqr_report_interval,
            { "BQR Report Interval", "bthci_vendor.android.bqr.report_interval",
            FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
            NULL, HFILL }
        },
        { &hf_android_quality_event_mask,
            { "Quality Event Mask", "bthci_vendor.android.quality_event_mask",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_quality_event_mask_quality_monitoring,
            { "Quality Monitoring Mode", "bthci_vendor.android.quality_event_mask.quality_monitoring",
            FT_BOOLEAN, 32, NULL, 0x00000001, NULL, HFILL }
        },
        { &hf_android_quality_event_mask_approaching_lsto,
            { "Approaching LSTO Event", "bthci_vendor.android.quality_event_mask.approaching_lsto",
            FT_BOOLEAN, 32, NULL, 0x00000002, NULL, HFILL }
        },
        { &hf_android_quality_event_mask_a2dp_choppy,
            { "A2DP Audio Choppy Event", "bthci_vendor.android.quality_event_mask.a2dp_choppy",
            FT_BOOLEAN, 32, NULL, 0x00000004, NULL, HFILL }
        },
        { &hf_android_quality_event_mask_esco_choppy,
            { "(e)SCO Voice Choppy Event", "bthci_vendor.android.quality_event_mask.esco_choppy",
            FT_BOOLEAN, 32, NULL, 0x00000008, NULL, HFILL }
        },
        { &hf_android_quality_event_mask_root_inflammation,
            { "Root Inflammation Event", "bthci_vendor.android.quality_event_mask.root_inflammation",
            FT_BOOLEAN, 32, NULL, 0x00000010, NULL, HFILL }
        },
        { &hf_android_quality_event_mask_energy_monitor,
            { "Energy Monitoring Mode", "bthci_vendor.android.quality_event_mask.energy_monitor",
            FT_BOOLEAN, 32, NULL, 0x00000020, NULL, HFILL }
        },
        { &hf_android_quality_event_mask_le_audio_choppy,
            { "LE Audio Choppy Event", "bthci_vendor.android.quality_event_mask.le_audio_choppy",
            FT_BOOLEAN, 32, NULL, 0x00000040, NULL, HFILL }
        },
        { &hf_android_quality_event_mask_connect_fail,
            { "Connect Fail Event", "bthci_vendor.android.quality_event_mask.connect_fail",
            FT_BOOLEAN, 32, NULL, 0x00000080, NULL, HFILL }
        },
        { &hf_android_quality_event_mask_advanced_rf_trigger,
            { "Advanced RF Stats Trigger", "bthci_vendor.android.quality_event_mask.advanced_rf_trigger",
            FT_BOOLEAN, 32, NULL, 0x00000100, NULL, HFILL }
        },
        { &hf_android_quality_event_mask_advanced_rf_periodic,
            { "Advanced RF Stats Periodic Report", "bthci_vendor.android.quality_event_mask.advanced_rf_periodic",
            FT_BOOLEAN, 32, NULL, 0x00000200, NULL, HFILL }
        },
        { &hf_android_quality_event_mask_controller_health_trigger,
            { "Controller Health Trigger", "bthci_vendor.android.quality_event_mask.controller_health_trigger",
            FT_BOOLEAN, 32, NULL, 0x00000400, NULL, HFILL }
        },
        { &hf_android_quality_event_mask_controller_health_periodic,
            { "Controller Health Periodic Report", "bthci_vendor.android.quality_event_mask.controller_health_periodic",
            FT_BOOLEAN, 32, NULL, 0x00000800, NULL, HFILL }
        },
        { &hf_android_quality_event_mask_reserved,
            { "Reserved", "bthci_vendor.android.quality_event_mask.reserved",
            FT_UINT32, BASE_HEX, NULL, 0x00007000, NULL, HFILL }
        },
        { &hf_android_quality_event_mask_vendor_quality,
            { "Vendor Specific Quality Events", "bthci_vendor.android.quality_event_mask.vendor_quality",
            FT_BOOLEAN, 32, NULL, 0x00008000, NULL, HFILL }
        },
        { &hf_android_quality_event_mask_lmp_trace,
            { "LMP/LL Message Trace", "bthci_vendor.android.quality_event_mask.lmp_trace",
            FT_BOOLEAN, 32, NULL, 0x00010000, NULL, HFILL }
        },
        { &hf_android_quality_event_mask_coex_trace,
            { "Multi-link/Coex Scheduling Trace", "bthci_vendor.android.quality_event_mask.coex_trace",
            FT_BOOLEAN, 32, NULL, 0x00020000, NULL, HFILL }
        },
        { &hf_android_quality_event_mask_controller_debug,
            { "Controller Debug Information", "bthci_vendor.android.quality_event_mask.controller_debug",
            FT_BOOLEAN, 32, NULL, 0x00040000, NULL, HFILL }
        },
        { &hf_android_quality_event_mask_offload_debug_reserved,
            { "Reserved for Offload Debug Information", "bthci_vendor.android.quality_event_mask.offload_debug_reserved",
            FT_BOOLEAN, 32, NULL, 0x00080000, NULL, HFILL }
        },
        { &hf_android_quality_event_mask_uart_history,
            { "UART History Dump Event Trigger", "bthci_vendor.android.quality_event_mask.uart_history",
            FT_BOOLEAN, 32, NULL, 0x00100000, NULL, HFILL }
        },
        { &hf_android_quality_event_mask_reserved_2,
            { "Reserved", "bthci_vendor.android.quality_event_mask.reserved_2",
            FT_UINT32, BASE_HEX, NULL, 0x7FE00000, NULL, HFILL }
        },
        { &hf_android_quality_event_mask_vendor_trace,
            { "Vendor Specific Trace", "bthci_vendor.android.quality_event_mask.vendor_trace",
            FT_BOOLEAN, 32, NULL, 0x80000000, NULL, HFILL }
        },
        { &hf_android_bd_addr,
          { "BD_ADDR",                                     "bthci_vendor.android.bd_addr",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            "Bluetooth Device Address", HFILL}
        },
        { &hf_android_max_advertising_instance,
            { "Max Advertising Instance",                  "bthci_vendor.android.max_advertising_instance",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_max_advertising_instance_reserved,
            { "Max Advertising Instance (Reserved)",       "bthci_vendor.android.max_advertising_instance_reserved",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_resolvable_private_address_offloading,
            { "Resolvable Private Address Offloading",     "bthci_vendor.android.resolvable_private_address_offloading",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_resolvable_private_address_offloading_reserved,
            { "Resolvable Private Address Offloading (Reserved)", "bthci_vendor.android.resolvable_private_address_offloading_reserved",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_total_scan_results,
            { "Total Scan Results",                        "bthci_vendor.android.total_scan_results",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_max_irk_list,
            { "Max IRK List",                              "bthci_vendor.android.max_irk_list",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_filter_support,
            { "Filter Support",                            "bthci_vendor.android.filter_support",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_max_filter,
            { "Max Filter",                                "bthci_vendor.android.max_filter",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_energy_support,
            { "Energy Support",                            "bthci_vendor.android.energy_support",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_version_support,
            { "Version Support",                           "bthci_vendor.android.version_support",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(android_version_support_fmt), 0x0,
            NULL, HFILL }
        },
        { &hf_android_version_major,
            { "Major",                                      "bthci_vendor.android.version_support.major",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_version_minor,
            { "Minor",                                      "bthci_vendor.android.version_support.minor",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_total_num_of_advt_tracked,
            { "Total Number of Advertisers Tracked",       "bthci_vendor.android.total_num_of_advt_tracked",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_extended_scan_support,
            { "Extended Scan Support",                     "bthci_vendor.android.extended_scan_support",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_debug_logging_support,
            { "Debug Logging Support",                     "bthci_vendor.android.debug_logging_support",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_le_address_generation_offloading_support,
            { "LE Address Generation Offloading Support",  "bthci_vendor.android.le_address_generation_offloading_support",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_le_address_generation_offloading_support_reserved,
            { "LE Address Generation Offloading Support (Reserved)", "bthci_vendor.android.le_address_generation_offloading_support_reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_source_offload_capability_mask,
            { "A2DP Source Offload Capability",            "bthci_vendor.android.a2dp_source_offload_capability_mask",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_source_offload_capability_mask_sbc,
          { "SBC",                                         "bthci_vendor.android.a2dp_source_offload_capability_mask.sbc",
            FT_BOOLEAN, 32, NULL, 0x00000001,
            NULL, HFILL }
        },
        { &hf_android_a2dp_source_offload_capability_mask_aac,
          { "AAC",                                         "bthci_vendor.android.a2dp_source_offload_capability_mask.aac",
            FT_BOOLEAN, 32, NULL, 0x00000002,
            NULL, HFILL }
        },
        { &hf_android_a2dp_source_offload_capability_mask_aptx,
          { "APTX",                                        "bthci_vendor.android.a2dp_source_offload_capability_mask.aptx",
            FT_BOOLEAN, 32, NULL, 0x00000004,
            NULL, HFILL }
        },
        { &hf_android_a2dp_source_offload_capability_mask_aptx_hd,
          { "APTX HD",                                     "bthci_vendor.android.a2dp_source_offload_capability_mask.aptx_hd",
            FT_BOOLEAN, 32, NULL, 0x00000008,
            NULL, HFILL }
        },
        { &hf_android_a2dp_source_offload_capability_mask_ldac,
          { "LDAC",                                        "bthci_vendor.android.a2dp_source_offload_capability_mask.ldac",
            FT_BOOLEAN, 32, NULL, 0x00000010,
            NULL, HFILL }
        },
        { &hf_android_a2dp_source_offload_capability_mask_opus,
          { "Opus",                                        "bthci_vendor.android.a2dp_source_offload_capability_mask.opus",
            FT_BOOLEAN, 32, NULL, 0x00000020,
            NULL, HFILL }
        },
        { &hf_android_a2dp_source_offload_capability_mask_reserved,
          { "Reserved",                                    "bthci_vendor.android.a2dp_source_offload_capability_mask.reserved",
            FT_UINT32, BASE_HEX, NULL, UINT32_C(0xFFFFFFC0),
            NULL, HFILL }
        },
        { &hf_android_bluetooth_quality_report_support,
            { "Bluetooth Quality Report Support",          "bthci_vendor.android.bluetooth_quality_report_support",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_dynamic_audio_buffer_support_mask,
            { "Dynamic Audio Buffer Support",              "bthci_vendor.android.dynamic_audio_buffer_support_mask",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_dynamic_audio_buffer_support_mask_sbc,
          { "SBC",                                         "bthci_vendor.android.dynamic_audio_buffer_support_mask.sbc",
            FT_BOOLEAN, 32, NULL, 0x00000001,
            NULL, HFILL }
        },
        { &hf_android_dynamic_audio_buffer_support_mask_aac,
          { "AAC",                                         "bthci_vendor.android.dynamic_audio_buffer_support_mask.aac",
            FT_BOOLEAN, 32, NULL, 0x00000002,
            NULL, HFILL }
        },
        { &hf_android_dynamic_audio_buffer_support_mask_aptx,
          { "APTX",                                        "bthci_vendor.android.dynamic_audio_buffer_support_mask.aptx",
            FT_BOOLEAN, 32, NULL, 0x00000004,
            NULL, HFILL }
        },
        { &hf_android_dynamic_audio_buffer_support_mask_aptx_hd,
          { "APTX HD",                                     "bthci_vendor.android.dynamic_audio_buffer_support_mask.aptx_hd",
            FT_BOOLEAN, 32, NULL, 0x00000008,
            NULL, HFILL }
        },
        { &hf_android_dynamic_audio_buffer_support_mask_ldac,
          { "LDAC",                                        "bthci_vendor.android.dynamic_audio_buffer_support_mask.ldac",
            FT_BOOLEAN, 32, NULL, 0x00000010,
            NULL, HFILL }
        },
        { &hf_android_dynamic_audio_buffer_support_mask_opus,
          { "Opus",                                        "bthci_vendor.android.dynamic_audio_buffer_support_mask.opus",
            FT_BOOLEAN, 32, NULL, 0x00000020,
            NULL, HFILL }
        },
        { &hf_android_dynamic_audio_buffer_support_mask_reserved,
          { "Reserved",                                    "bthci_vendor.android.dynamic_audio_buffer_support_mask.reserved",
            FT_UINT32, BASE_HEX, NULL, UINT32_C(0xFFFFFFC0),
            NULL, HFILL }
        },
        { &hf_android_a2dp_offload_v2_support,
            { "A2DP Offload V2 Support",                   "bthci_vendor.android.a2dp_offload_v2_support",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_iso_link_layer_feedback_supported,
            { "ISO Link Layer Feedback Supported", "bthci_vendor.android.iso_link_layer_feedback_supported",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_android_sniff_offload_supported,
            { "Sniff Offload Supported", "bthci_vendor.android.sniff_offload_supported",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_android_big_channel_map_support,
            { "BIG Channel Map Support", "bthci_vendor.android.big_channel_map_support",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_android_big_channel_map_support_bit0,
            { "Bit 0", "bthci_vendor.android.big_channel_map_support.bit0",
            FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL }
        },
        { &hf_android_big_channel_map_support_reserved,
            { "Reserved", "bthci_vendor.android.big_channel_map_support.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xFFFE, NULL, HFILL }
        },
        { &hf_android_vendor_connection_handle_min,
            { "Vendor Connection Handle Minimum", "bthci_vendor.android.vendor_connection_handle_min",
            FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_android_vendor_connection_handle_max,
            { "Vendor Connection Handle Maximum", "bthci_vendor.android.vendor_connection_handle_max",
            FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_android_connection_proximity_threshold,
            { "Connection Proximity Threshold", "bthci_vendor.android.connection_proximity_threshold",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_android_status,
          { "Status",                                      "bthci_vendor.android.status",
            FT_UINT8, BASE_HEX|BASE_EXT_STRING, &bthci_cmd_status_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_android_le_energy_total_tx_time,
            { "Total TX Time",                             "bthci_vendor.android.le.total_tx_time",
            FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
            NULL, HFILL }
        },
        { &hf_android_le_energy_total_rx_time,
            { "Total RX Time",                             "bthci_vendor.android.le.total_rx_time",
            FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
            NULL, HFILL }
        },
        { &hf_android_le_energy_total_idle_time,
            { "Total Idle Time",                           "bthci_vendor.android.le.total_idle_time",
            FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
            NULL, HFILL }
        },
        { &hf_android_le_energy_total_energy_used,
            { "Total Energy Used (Current(mA) * Voltage(V) * Time(ms))", "bthci_vendor.android.le.total_energy_used",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_le_batch_scan_subcode,
            { "Subcode",                                   "bthci_vendor.android.le.batch_scan.subcode",
            FT_UINT8, BASE_HEX, VALS(android_le_subcode_batch_scan_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_android_le_batch_scan_report_format,
            { "Report Format",                             "bthci_vendor.android.le.batch_scan.report_format",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_le_batch_scan_number_of_records,
            { "Number of Records",                         "bthci_vendor.android.le.batch_scan.number_of_records",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_le_batch_scan_mode,
            { "Mode",                                      "bthci_vendor.android.le.batch_scan.mode",
            FT_UINT8, BASE_HEX, VALS(android_batch_scan_mode_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_android_le_batch_scan_enable,
            { "Enable",                                    "bthci_vendor.android.le.batch_scan.enable",
            FT_UINT8, BASE_HEX, VALS(android_disable_enable_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_android_le_batch_scan_full_max,
            { "Full Max",                                  "bthci_vendor.android.le.batch_scan.full_max",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_le_batch_scan_truncate_max,
            { "Truncate Max",                              "bthci_vendor.android.le.batch_scan.truncate_max",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_le_batch_scan_notify_threshold,
            { "notify_threshold",                         "bthci_vendor.android.le.batch_scan.notify_threshold",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_le_batch_scan_window,
            { "Window",                                    "bthci_vendor.android.le.batch_scan.window",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_le_batch_scan_interval,
            { "Interval",                                  "bthci_vendor.android.le.batch_scan.interval",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_le_batch_scan_address_type,
            { "Address Type",                              "bthci_vendor.android.le.batch_scan.address_type",
            FT_UINT8, BASE_HEX, VALS(bluetooth_address_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_android_le_batch_scan_discard_rule,
            { "Discard Rule",                              "bthci_vendor.android.le.batch_scan.discard_rule",
            FT_UINT8, BASE_HEX, VALS(android_batch_scan_discard_rule_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_android_le_multi_advertising_subcode,
            { "Subcode",                                   "bthci_vendor.android.le.multi_advertising.subcode",
            FT_UINT8, BASE_HEX, VALS(android_le_subcode_multi_advertising_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_android_le_multi_advertising_enable,
            { "Enable",                                    "bthci_vendor.android.le.multi_advertising.enable",
            FT_UINT8, BASE_HEX, VALS(android_disable_enable_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_android_le_multi_advertising_instance_id,
            { "Instance Id",                                  "bthci_vendor.android.le.multi_advertising.instance_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_le_multi_advertising_min_interval,
            { "Min Interval",                              "bthci_vendor.android.le.multi_advertising.min_interval",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_le_multi_advertising_max_interval,
            { "Max Interval",                              "bthci_vendor.android.le.multi_advertising.max_interval",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_le_multi_advertising_address_type,
            { "Address Type",                              "bthci_vendor.android.le.multi_advertising.address_type",
            FT_UINT8, BASE_HEX, VALS(bluetooth_address_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_android_le_multi_advertising_type,
          { "Type",                                        "bthci_vendor.android.le.multi_advertising.type",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &bthci_cmd_eir_data_type_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_android_le_multi_advertising_channel_map,
            { "Channel Map",                               "bthci_vendor.android.le.multi_advertising.channel_map",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_le_multi_advertising_channel_map_reserved,
            { "Reserved",                                  "bthci_vendor.android.le.multi_advertising.channel_map.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xF8,
            NULL, HFILL }
        },
        { &hf_android_le_multi_advertising_channel_map_39,
            { "Channel 39",                                "bthci_vendor.android.le.multi_advertising.channel_map.39",
            FT_UINT8, BASE_HEX, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_android_le_multi_advertising_channel_map_38,
            { "Channel 38",                                "bthci_vendor.android.le.multi_advertising.channel_map.38",
            FT_UINT8, BASE_HEX, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_android_le_multi_advertising_channel_map_37,
            { "Channel 37",                                "bthci_vendor.android.le.multi_advertising.channel_map.37",
            FT_UINT8, BASE_HEX, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_android_le_multi_advertising_filter_policy,
            { "Filter Policy",                             "bthci_vendor.android.le.multi_advertising.filter_policy",
            FT_UINT8, BASE_HEX, VALS(android_le_filter_policy_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_android_le_multi_advertising_tx_power,
            { "Tx power",                                  "bthci_vendor.android.le.multi_advertising.tx_power",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_data,
            { "Data",                                      "bthci_vendor.android.data",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_subcode,
            { "Subcode",                                   "bthci_vendor.android.a2dp_hardware_offload.subcode",
            FT_UINT8, BASE_HEX, VALS(android_a2dp_hardware_offload_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_legacy_codec,
            { "Codec",                                     "bthci_vendor.android.a2dp_hardware_offload.start_legacy.codec",
            FT_UINT32, BASE_HEX, VALS(android_a2dp_hardware_offload_start_legacy_codec_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_legacy_max_latency,
            { "Max Latency",                               "bthci_vendor.android.a2dp_hardware_offload.start_legacy.max_latency",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_legacy_scms_t_enable_flag,
            { "SCMS-T Enable",                             "bthci_vendor.android.a2dp_hardware_offload.start_legacy.scms_t_enable_flag",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_legacy_scms_t_enable_value,
            { "SCMS-T Value",                              "bthci_vendor.android.a2dp_hardware_offload.start_legacy.scms_t_enable_value",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_legacy_scms_t_enable_value_reserved,
            { "Reserved",                                  "bthci_vendor.android.a2dp_hardware_offload.start_legacy.scms_t_enable_value_reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_legacy_sampling_frequency,
            { "Sampling Frequency",                        "bthci_vendor.android.a2dp_hardware_offload.start_legacy.sampling_frequency",
            FT_UINT32, BASE_HEX, VALS(android_a2dp_hardware_offload_start_legacy_sampling_frequency_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_legacy_bits_per_sample,
            { "Bits Per Sample",                           "bthci_vendor.android.a2dp_hardware_offload.start_legacy.bits_per_sample",
            FT_UINT8, BASE_HEX, VALS(android_a2dp_hardware_offload_start_legacy_bits_per_sample_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_legacy_channel_mode,
            { "Channel Mode",                              "bthci_vendor.android.a2dp_hardware_offload.start_legacy.channel_mode",
            FT_UINT8, BASE_HEX, VALS(android_a2dp_hardware_offload_start_legacy_channel_mode_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_legacy_encoded_audio_bitrate,
            { "Encoded Audio Bitrate",                     "bthci_vendor.android.a2dp_hardware_offload.start_legacy.encoded_audio_bitrate",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_legacy_encoded_audio_bitrate_unspecified,
            { "Encoded Audio Bitrate Unspecified/Unused",  "bthci_vendor.android.a2dp_hardware_offload.start_legacy.encoded_audio_bitrate_unspecified",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_legacy_encoded_audio_bitrate_reserved,
            { "Reserved",                                  "bthci_vendor.android.a2dp_hardware_offload.start_legacy.encoded_audio_bitrate_reserved",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_legacy_connection_handle,
            { "Connection Handle",                         "bthci_vendor.android.a2dp_hardware_offload.start_legacy.connection_handle",
            FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_legacy_l2cap_cid,
            { "L2CAP CID",                                 "bthci_vendor.android.a2dp_hardware_offload.start_legacy.l2cap_cid",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_legacy_l2cap_mtu_size,
            { "L2CAP MTU Size",                            "bthci_vendor.android.a2dp_hardware_offload.start_legacy.l2cap_mtu_size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_legacy_codec_information,
            { "Codec Information",                         "bthci_vendor.android.a2dp_hardware_offload.start_legacy.codec_information",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_legacy_codec_information_sbc_block_length,
          { "Block Length",                                "bthci_vendor.android.a2dp_hardware_offload.start_legacy.codec_information.sbc.block_length",
            FT_UINT8, BASE_HEX, VALS(android_a2dp_hardware_offload_start_legacy_codec_information_sbc_block_length_vals), 0xf0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_legacy_codec_information_sbc_subbands,
          { "Subbands",                                    "bthci_vendor.android.a2dp_hardware_offload.start_legacy.codec_information.sbc.subbands",
            FT_UINT8, BASE_HEX, VALS(android_a2dp_hardware_offload_start_legacy_codec_information_sbc_subbands_vals), 0x0c,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_legacy_codec_information_sbc_allocation_method,
          { "Allocation Method",                           "bthci_vendor.android.a2dp_hardware_offload.start_legacy.codec_information.sbc.allocation_method",
            FT_UINT8, BASE_HEX, VALS(android_a2dp_hardware_offload_start_legacy_codec_information_sbc_allocation_method_vals), 0x03,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_legacy_codec_information_sbc_min_bitpool,
          { "Min Bitpool",                                 "bthci_vendor.android.a2dp_hardware_offload.start_legacy.codec_information.sbc.min_bitpool",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_legacy_codec_information_sbc_max_bitpool,
          { "Max Bitpool",                                 "bthci_vendor.android.a2dp_hardware_offload.start_legacy.codec_information.sbc.max_bitpool",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_legacy_codec_information_sbc_sampling_frequency,
          { "Sampling Frequency",                          "bthci_vendor.android.a2dp_hardware_offload.start_legacy.codec_information.sbc.sampling_frequency",
            FT_UINT8, BASE_HEX, VALS(android_a2dp_hardware_offload_start_legacy_sbc_sampling_frequency_vals), 0xf0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_legacy_codec_information_sbc_channel_mode,
          { "Channel Mode",                                "bthci_vendor.android.a2dp_hardware_offload.start_legacy.codec_information.sbc.channel_mode",
            FT_UINT8, BASE_HEX, VALS(android_a2dp_hardware_offload_start_legacy_sbc_channel_mode_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_legacy_codec_information_sbc_reserved,
          { "Reserved",                                    "bthci_vendor.android.a2dp_hardware_offload.start_legacy.codec_information.sbc.reserved",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_legacy_codec_information_aac_object_type,
          { "Object Type",                                 "bthci_vendor.android.a2dp_hardware_offload.start_legacy.codec_information.aac.object_type",
            FT_UINT8, BASE_HEX, VALS(android_a2dp_hardware_offload_start_legacy_aac_object_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_legacy_codec_information_aac_vbr,
          { "VBR",                                         "bthci_vendor.android.a2dp_hardware_offload.start_legacy.codec_information.aac.vbr",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_legacy_codec_information_aac_reserved,
          { "Reserved",                                    "bthci_vendor.android.a2dp_hardware_offload.start_legacy.codec_information.aac.reserved",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_legacy_codec_information_ldac_vendor_id,
          { "Vendor ID",                                   "bthci_vendor.android.a2dp_hardware_offload.start_legacy.codec_information.ldac.vendor_id",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_legacy_codec_information_ldac_codec_id,
          { "Codec ID",                                    "bthci_vendor.android.a2dp_hardware_offload.start_legacy.codec_information.ldac.codec_id",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_legacy_codec_information_ldac_bitrate_index,
            { "Bitrate Index",                             "bthci_vendor.android.a2dp_hardware_offload.start_legacy.codec_information.ldac.bitrate_index",
            FT_UINT8, BASE_HEX, VALS(android_a2dp_hardware_offload_start_legacy_codec_information_ldac_bitrate_index_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_legacy_codec_information_ldac_bitrate_index_reserved,
          { "Reserved",                                    "bthci_vendor.android.a2dp_hardware_offload.start_legacy.codec_information.ldac.bitrate_index.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode_mask,
            { "Channel Mode",                              "bthci_vendor.android.a2dp_hardware_offload.start_legacy.codec_information.ldac.channel_mode_mask",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode_mask_stereo,
          { "Stereo",                                      "bthci_vendor.android.a2dp_hardware_offload.start_legacy.codec_information.ldac.channel_mode_mask.stereo",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode_mask_dual,
          { "Dual",                                         "bthci_vendor.android.a2dp_hardware_offload.start_legacy.codec_information.ldac.channel_mode_mask.dual",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode_mask_mono,
          { "Mono",                                        "bthci_vendor.android.a2dp_hardware_offload.start_legacy.codec_information.ldac.channel_mode_mask.mono",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode_mask_reserved,
          { "Reserved",                                    "bthci_vendor.android.a2dp_hardware_offload.start_legacy.codec_information.ldac.channel_mode_mask.reserved",
            FT_UINT8, BASE_HEX, NULL, UINT32_C(0xF8),
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_legacy_codec_information_ldac_reserved,
          { "Reserved",                                    "bthci_vendor.android.a2dp_hardware_offload.start_legacy.codec_information.ldac.reserved",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_legacy_codec_information_reserved,
          { "Reserved",                                    "bthci_vendor.android.a2dp_hardware_offload.start_legacy.codec_information.reserved",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_connection_handle,
          { "Connection Handle",                           "bthci_vendor.android.a2dp_hardware_offload.start.connection_handle",
            FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_l2cap_cid,
          { "L2CAP CID",                                   "bthci_vendor.android.a2dp_hardware_offload.start.l2cap_cid",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_data_path_direction,
          { "Data Path Direction",                         "bthci_vendor.android.a2dp_hardware_offload.start.data_path_direction",
            FT_UINT8, BASE_HEX, VALS(android_a2dp_hardware_offload_data_path_direction_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_peer_mtu,
          { "Peer MTU",                                    "bthci_vendor.android.a2dp_hardware_offload.start.peer_mtu",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_cp_enable_scmst,
          { "CP Enable SCMS-T",                            "bthci_vendor.android.a2dp_hardware_offload.start.cp_enable_scmst",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_cp_header_scmst,
          { "CP Header SCMS-T",                            "bthci_vendor.android.a2dp_hardware_offload.start.cp_header_scmst",
            FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_cp_header_scmst_reserved,
          { "Reserved",                                    "bthci_vendor.android.a2dp_hardware_offload.start.cp_header_scmst_reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_vendor_specific_parameters_length,
          { "Vendor Specific Parameters Length",           "bthci_vendor.android.a2dp_hardware_offload.start.vendor_specific_parameters_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_start_vendor_specific_parameters,
          { "Vendor Specific Parameters",                  "bthci_vendor.android.a2dp_hardware_offload.start.vendor_specific_parameters",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_stop_connection_handle,
          { "Connection Handle",                           "bthci_vendor.android.a2dp_hardware_offload.stop.connection_handle",
            FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_stop_l2cap_cid,
          { "L2CAP CID",                                   "bthci_vendor.android.a2dp_hardware_offload.stop.l2cap_cid",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_a2dp_hardware_offload_stop_data_path_direction,
          { "Data Path Direction",                         "bthci_vendor.android.a2dp_hardware_offload.stop.data_path_direction",
            FT_UINT8, BASE_HEX, VALS(android_a2dp_hardware_offload_data_path_direction_vals), 0x0,
            NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_android,
        &ett_android_opcode,
        &ett_android_channel_map,
        &ett_android_a2dp_source_offload_capability_mask,
        &ett_android_dynamic_audio_buffer_support_mask,
        &ett_android_version_support,
        &ett_android_big_channel_map_support,
        &ett_android_apcf_feature_selection,
        &ett_android_apcf_list_logic,
        &ett_android_apcf_extended_features,
        &ett_android_bqr,
        &ett_android_bqr_link_coex_info_mask,
        &ett_android_bqr_advanced_tx_buffer_queue_count,
        &ett_android_a2dp_hardware_offload_start_legacy_codec_information,
        &ett_android_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode_mask,
    };

    static ei_register_info ei[] = {
        { &ei_android_undecoded,             { "bthci_vendor.android.undecoded",            PI_UNDECODED, PI_NOTE, "Undecoded", EXPFILL }},
        { &ei_android_unexpected_parameter,  { "bthci_vendor.android.unexpected_parameter", PI_PROTOCOL, PI_WARN,  "Unexpected parameter", EXPFILL }},
        { &ei_android_unexpected_data,       { "bthci_vendor.android.unexpected_data",      PI_PROTOCOL, PI_WARN,  "Unexpected data", EXPFILL }},
    };

    proto_bthci_vendor_android = proto_register_protocol("Bluetooth Android HCI",
            "HCI ANDROID", "bthci_vendor.android");

    bthci_vendor_android_handle = register_dissector("bthci_vendor.android", dissect_bthci_vendor_android, proto_bthci_vendor_android);

    proto_register_field_array(proto_bthci_vendor_android, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_module = expert_register_protocol(proto_bthci_vendor_android);
    expert_register_field_array(expert_module, ei, array_length(ei));
}

void
proto_reg_handoff_bthci_vendor_android(void)
{
    btcommon_ad_android_handle = find_dissector_add_dependency("btcommon.eir_ad.ad", proto_bthci_vendor_android);

    dissector_add_for_decode_as("bthci_cmd.vendor", bthci_vendor_android_handle);

    dissector_add_uint("bluetooth.vendor", bthci_vendor_manufacturer_android, bthci_vendor_android_handle);
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
