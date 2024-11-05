/* packet-bthci_vendor.c
 * Routines for the Bluetooth HCI Vendors Commands/Events
 *
 * Copyright 2014, Michal Labedzki for Tieto Corporation
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

#include "packet-bluetooth.h"
#include "packet-bthci_cmd.h"
#include "packet-bthci_evt.h"

static int proto_bthci_vendor_broadcom;

static int hf_broadcom_opcode;
static int hf_broadcom_opcode_ogf;
static int hf_broadcom_opcode_ocf;
static int hf_broadcom_parameter_length;
static int hf_broadcom_number_of_allowed_command_packets;
static int hf_broadcom_event_code;
static int hf_broadcom_le_advertising_filter_subcode;
static int hf_broadcom_le_scan_condition;
static int hf_broadcom_le_filter_index;
static int hf_broadcom_le_number_of_available_filters;
static int hf_broadcom_mem_data;
static int hf_broadcom_mem_address;
static int hf_broadcom_mem_rdlen;
static int hf_broadcom_baudrate;
static int hf_broadcom_status;
static int hf_broadcom_bd_addr;
static int hf_broadcom_max_advertising_instance;
static int hf_broadcom_max_advertising_instance_reserved;
static int hf_broadcom_resolvable_private_address_offloading;
static int hf_broadcom_resolvable_private_address_offloading_reserved;
static int hf_broadcom_total_scan_results;
static int hf_broadcom_max_irk_list;
static int hf_broadcom_filter_support;
static int hf_broadcom_max_filter;
static int hf_broadcom_energy_support;
static int hf_broadcom_version_support;
static int hf_broadcom_total_num_of_advt_tracked;
static int hf_broadcom_extended_scan_support;
static int hf_broadcom_debug_logging_support;
static int hf_broadcom_le_address_generation_offloading_support;
static int hf_broadcom_le_address_generation_offloading_support_reserved;
static int hf_broadcom_a2dp_source_offload_capability_mask;
static int hf_broadcom_a2dp_source_offload_capability_mask_sbc;
static int hf_broadcom_a2dp_source_offload_capability_mask_aac;
static int hf_broadcom_a2dp_source_offload_capability_mask_aptx;
static int hf_broadcom_a2dp_source_offload_capability_mask_aptx_hd;
static int hf_broadcom_a2dp_source_offload_capability_mask_ldac;
static int hf_broadcom_a2dp_source_offload_capability_mask_reserved;
static int hf_broadcom_bluetooth_quality_report_support;
static int hf_broadcom_dynamic_audio_buffer_support_mask;
static int hf_broadcom_dynamic_audio_buffer_support_mask_sbc;
static int hf_broadcom_dynamic_audio_buffer_support_mask_aac;
static int hf_broadcom_dynamic_audio_buffer_support_mask_aptx;
static int hf_broadcom_dynamic_audio_buffer_support_mask_aptx_hd;
static int hf_broadcom_dynamic_audio_buffer_support_mask_ldac;
static int hf_broadcom_dynamic_audio_buffer_support_mask_reserved;
static int hf_broadcom_a2dp_offload_v2_support;
static int hf_broadcom_connection_handle;
static int hf_broadcom_connection_priority;
static int hf_broadcom_sleep_mode;
static int hf_broadcom_host_stack_idle_threshold;
static int hf_broadcom_host_controller_idle_threshold;
static int hf_broadcom_wake_polarity;
static int hf_broadcom_host_wake_polarity;
static int hf_broadcom_allow_host_sleep_during_sco;
static int hf_broadcom_combine_sleep_mode_and_lpm;
static int hf_broadcom_enable_uart_txd_tri_state;
static int hf_broadcom_sleep_guard_time;
static int hf_broadcom_wakeup_guard_time;
static int hf_broadcom_txd_config;
static int hf_broadcom_pulsed_host_wake;
static int hf_broadcom_uart_clock;
static int hf_broadcom_codec_state;
static int hf_broadcom_codec;
static int hf_broadcom_sco_pcm_routing;
static int hf_broadcom_sco_pcm_interface_clock_rate;
static int hf_broadcom_sco_pcm_interface_frame_type;
static int hf_broadcom_sco_pcm_interface_sync_mode;
static int hf_broadcom_sco_pcm_interface_clock_mode;
static int hf_broadcom_pcm_shift_mode;
static int hf_broadcom_pcm_fill_bits;
static int hf_broadcom_pcm_fill_method;
static int hf_broadcom_pcm_fill_number_of_bits;
static int hf_broadcom_pcm_justify_mode;
static int hf_broadcom_sco_i2s_pcm_interface_mode;
static int hf_broadcom_sco_i2s_pcm_interface_role;
static int hf_broadcom_sco_i2s_pcm_interface_sample_rate;
static int hf_broadcom_sco_i2s_pcm_interface_clock_rate;
static int hf_broadcom_le_energy_total_rx_time;
static int hf_broadcom_le_energy_total_tx_time;
static int hf_broadcom_le_energy_total_idle_time;
static int hf_broadcom_le_energy_total_energy_used;
static int hf_broadcom_le_batch_scan_subcode;
static int hf_broadcom_le_batch_scan_report_format;
static int hf_broadcom_le_batch_scan_number_of_records;
static int hf_broadcom_le_batch_scan_mode;
static int hf_broadcom_le_batch_scan_enable;
static int hf_broadcom_le_batch_scan_full_max;
static int hf_broadcom_le_batch_scan_truncate_max;
static int hf_broadcom_le_batch_scan_notify_threshold;
static int hf_broadcom_le_batch_scan_window;
static int hf_broadcom_le_batch_scan_interval;
static int hf_broadcom_le_batch_scan_address_type;
static int hf_broadcom_le_batch_scan_discard_rule;
static int hf_broadcom_le_multi_advertising_subcode;
static int hf_broadcom_le_multi_advertising_enable;
static int hf_broadcom_le_multi_advertising_instance_id;
static int hf_broadcom_le_multi_advertising_type;
static int hf_broadcom_le_multi_advertising_min_interval;
static int hf_broadcom_le_multi_advertising_max_interval;
static int hf_broadcom_le_multi_advertising_address_type;
static int hf_broadcom_le_multi_advertising_filter_policy;
static int hf_broadcom_le_multi_advertising_tx_power;
static int hf_broadcom_le_multi_advertising_channel_map;
static int hf_broadcom_le_multi_advertising_channel_map_reserved;
static int hf_broadcom_le_multi_advertising_channel_map_39;
static int hf_broadcom_le_multi_advertising_channel_map_38;
static int hf_broadcom_le_multi_advertising_channel_map_37;
static int hf_broadcom_hid_emulation_mode;
static int hf_broadcom_vid;
static int hf_broadcom_pid;
static int hf_broadcom_chip_id;
static int hf_broadcom_target_id;
static int hf_broadcom_build_base;
static int hf_broadcom_build_number;
static int hf_broadcom_data;
static int hf_broadcom_a2dp_hardware_offload_subcode;
static int hf_broadcom_a2dp_hardware_offload_start_legacy_codec;
static int hf_broadcom_a2dp_hardware_offload_start_legacy_max_latency;
static int hf_broadcom_a2dp_hardware_offload_start_legacy_scms_t_enable_flag;
static int hf_broadcom_a2dp_hardware_offload_start_legacy_scms_t_enable_value;
static int hf_broadcom_a2dp_hardware_offload_start_legacy_scms_t_enable_value_reserved;
static int hf_broadcom_a2dp_hardware_offload_start_legacy_sampling_frequency;
static int hf_broadcom_a2dp_hardware_offload_start_legacy_bits_per_sample;
static int hf_broadcom_a2dp_hardware_offload_start_legacy_channel_mode;
static int hf_broadcom_a2dp_hardware_offload_start_legacy_encoded_audio_bitrate;
static int hf_broadcom_a2dp_hardware_offload_start_legacy_encoded_audio_bitrate_unspecified;
static int hf_broadcom_a2dp_hardware_offload_start_legacy_encoded_audio_bitrate_reserved;
static int hf_broadcom_a2dp_hardware_offload_start_legacy_connection_handle;
static int hf_broadcom_a2dp_hardware_offload_start_legacy_l2cap_cid;
static int hf_broadcom_a2dp_hardware_offload_start_legacy_l2cap_mtu_size;
static int hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information;
static int hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_sbc_block_length;
static int hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_sbc_subbands;
static int hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_sbc_allocation_method;
static int hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_sbc_min_bitpool;
static int hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_sbc_max_bitpool;
static int hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_sbc_sampling_frequency;
static int hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_sbc_channel_mode;
static int hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_sbc_reserved;
static int hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_aac_object_type;
static int hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_aac_vbr;
static int hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_aac_reserved;
static int hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_ldac_vendor_id;
static int hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_ldac_codec_id;
static int hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_ldac_bitrate_index;
static int hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_ldac_bitrate_index_reserved;
static int hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode_mask;
static int hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode_mask_stereo;
static int hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode_mask_dual;
static int hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode_mask_mono;
static int hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode_mask_reserved;
static int hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_ldac_reserved;
static int hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_reserved;
static int hf_broadcom_a2dp_hardware_offload_start_connection_handle;
static int hf_broadcom_a2dp_hardware_offload_start_l2cap_cid;
static int hf_broadcom_a2dp_hardware_offload_start_data_path_direction;
static int hf_broadcom_a2dp_hardware_offload_start_peer_mtu;
static int hf_broadcom_a2dp_hardware_offload_start_cp_enable_scmst;
static int hf_broadcom_a2dp_hardware_offload_start_cp_header_scmst;
static int hf_broadcom_a2dp_hardware_offload_start_cp_header_scmst_reserved;
static int hf_broadcom_a2dp_hardware_offload_start_vendor_specific_parameters_length;
static int hf_broadcom_a2dp_hardware_offload_start_vendor_specific_parameters;
static int hf_broadcom_a2dp_hardware_offload_stop_connection_handle;
static int hf_broadcom_a2dp_hardware_offload_stop_l2cap_cid;
static int hf_broadcom_a2dp_hardware_offload_stop_data_path_direction;


static int * const hfx_le_multi_advertising_channel_map[] = {
    &hf_broadcom_le_multi_advertising_channel_map_reserved,
    &hf_broadcom_le_multi_advertising_channel_map_39,
    &hf_broadcom_le_multi_advertising_channel_map_38,
    &hf_broadcom_le_multi_advertising_channel_map_37,
    NULL
};

static int * const hfx_broadcom_a2dp_source_offload_capability[] = {
    &hf_broadcom_a2dp_source_offload_capability_mask_reserved,
    &hf_broadcom_a2dp_source_offload_capability_mask_ldac,
    &hf_broadcom_a2dp_source_offload_capability_mask_aptx_hd,
    &hf_broadcom_a2dp_source_offload_capability_mask_aptx,
    &hf_broadcom_a2dp_source_offload_capability_mask_aac,
    &hf_broadcom_a2dp_source_offload_capability_mask_sbc,
    NULL
};

static int * const hfx_broadcom_dynamic_audio_buffer_support[] = {
    &hf_broadcom_dynamic_audio_buffer_support_mask_reserved,
    &hf_broadcom_dynamic_audio_buffer_support_mask_ldac,
    &hf_broadcom_dynamic_audio_buffer_support_mask_aptx_hd,
    &hf_broadcom_dynamic_audio_buffer_support_mask_aptx,
    &hf_broadcom_dynamic_audio_buffer_support_mask_aac,
    &hf_broadcom_dynamic_audio_buffer_support_mask_sbc,
    NULL
};

static int * const hfx_broadcom_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode[] = {
    &hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode_mask_reserved,
    &hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode_mask_mono,
    &hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode_mask_dual,
    &hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode_mask_stereo,
    NULL
};

static int ett_broadcom;
static int ett_broadcom_opcode;
static int ett_broadcom_channel_map;
static int ett_broadcom_a2dp_source_offload_capability_mask;
static int ett_broadcom_dynamic_audio_buffer_support_mask;
static int ett_broadcom_a2dp_hardware_offload_start_legacy_codec_information;
static int ett_broadcom_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode_mask;

static expert_field ei_broadcom_undecoded;
static expert_field ei_broadcom_unexpected_parameter;
static expert_field ei_broadcom_unexpected_data;

static dissector_handle_t bthci_vendor_broadcom_handle;
static dissector_handle_t btcommon_ad_handle;

#define BROADCOM_OPCODE_VALS(base) \
/* Bluetooth Core 4.0 */ \
    { (base) | 0x0001,  "Write BD ADDR" }, \
    { (base) | 0x0018,  "Update Baudrate" }, \
    { (base) | 0x001C,  "Write SCO PCM INT Parameter" }, \
    { (base) | 0x001E,  "Write PCM Data Format Parameter" }, \
    { (base) | 0x0027,  "Write Sleep Mode" }, \
    { (base) | 0x002E,  "Download MiniDriver" }, \
    { (base) | 0x003B,  "Enable USB HID Emulation" }, \
    { (base) | 0x0045,  "Write UART Clock Setting" }, \
    { (base) | 0x004C,  "Write Memory" }, \
    { (base) | 0x004D,  "Read Memory" }, \
    { (base) | 0x004E,  "Launch RAM" }, \
    { (base) | 0x0057,  "Set ACL Priority" }, \
    { (base) | 0x005A,  "Read VID PID" }, \
    { (base) | 0x006D,  "Write I2S PCM Interface Parameter" }, \
    { (base) | 0x0079,  "Read Verbose Config Version Info" }, \
    { (base) | 0x007E,  "Enable WBS" }, \
    { (base) | 0x0102,  "Enable WBS Modified" }, \
    { (base) | 0x0111,  "Set ConnectionLess Broadcast Stream" }, \
    { (base) | 0x0112,  "Receive ConnectionLess Broadcast Stream" }, \
    { (base) | 0x0113,  "Write ConnectionLess Broadcast Stream Data" }, \
    { (base) | 0x0114,  "ConnectionLess Broadcast Stream Flush" }, \
    { (base) | 0x0153,  "LE Get Vendor Capabilities" }, \
    { (base) | 0x0154,  "LE Multi Advertising" }, \
    { (base) | 0x0156,  "LE Batch Scan" }, \
    { (base) | 0x0157,  "LE Advertising Filter" }, \
    { (base) | 0x0158,  "LE Tracking Advertising" }, \
    { (base) | 0x0159,  "LE Energy Info" }, \
    { (base) | 0x015D,  "A2DP Hardware Offload" }

static const value_string broadcom_opcode_ocf_vals[] = {
    BROADCOM_OPCODE_VALS(0x0),
    { 0, NULL }
};

static const value_string broadcom_opcode_vals[] = {
    BROADCOM_OPCODE_VALS(0x3F << 10),
    { 0, NULL }
};

static const value_string broadcom_le_subcode_advertising_filter_vals[] = {
    { 0x00,  "Enable" },
    { 0x01,  "Feature Select" },
    { 0x02,  "BDADDR" },
    { 0x03,  "UUID" },
    { 0x04,  "Solicitate UUID" },
    { 0x05,  "Local Name" },
    { 0x06,  "Manufacturer Data"  },
    { 0x07,  "Service Data" },
    { 0x08,  "All" },
    { 0, NULL }
};

static const value_string broadcom_le_scan_condition_vals[] = {
    { 0x00,  "Add" },
    { 0x01,  "Delete" },
    { 0x02,  "Clear" },
    { 0, NULL }
};

static const value_string broadcom_uart_clock_vals[] = {
    { 0x01,  "48 MHz" },
    { 0x02,  "24 HHz" },
    { 0, NULL }
};

static const value_string broadcom_sleep_mode_vals[] = {
    { 0x01,  "disable" },
    { 0x02,  "UART" },
    { 0x09,  "H5" },
    { 0, NULL }
};

static const value_string broadcom_wake_polarity_vals[] = {
    { 0x00,  "Active Low" },
    { 0x01,  "Active High" },
    { 0, NULL }
};

static const value_string broadcom_connection_priority_vals[] = {
    { 0x00,  "Normal" },
    { 0xFF,  "High" },
    { 0, NULL }
};

static const value_string broadcom_codec_state_vals[] = {
    { 0x00,  "Disable" },
    { 0x01,  "Enable" },
    { 0, NULL }
};

static const value_string broadcom_codec_vals[] = {
    { 0x00,  "None" },
    { 0x01,  "CVSD" },
    { 0x02,  "mSBC" },
    { 0, NULL }
};

static const value_string broadcom_sco_pcm_routing_vals[] = {
    { 0x00,  "PCM" },
    { 0x01,  "Transport" },
    { 0x02,  "Codec" },
    { 0x03,  "I2S" },
    { 0, NULL }
};

static const value_string broadcom_sco_pcm_interface_clock_rate_vals[] = {
    { 0x00,  "128k" },
    { 0x01,  "256k" },
    { 0x02,  "512k" },
    { 0x03,  "1024k" },
    { 0x04,  "2048k" },
    { 0, NULL }
};

static const value_string broadcom_sco_pcm_interface_frame_type_vals[] = {
    { 0x00,  "Short" },
    { 0x01,  "Long" },
    { 0, NULL }
};

static const value_string broadcom_mode_peripheral_central_vals[] = {
    { 0x00,  "Peripheral" },
    { 0x01,  "Central" },
    { 0, NULL }
};

static const value_string broadcom_pcm_shift_mode_vals[] = {
    { 0x00,  "MSB" },
    { 0x01,  "LSB" },
    { 0, NULL }
};

static const value_string broadcom_pcm_fill_method_vals[] = {
    { 0x00,  "0's" },
    { 0x01,  "1's" },
    { 0x02,  "Signed" },
    { 0x03,  "Programmable" },
    { 0, NULL }
};

static const value_string broadcom_pcm_justify_mode_vals[] = {
    { 0x00,  "Left" },
    { 0x01,  "Right" },
    { 0, NULL }
};

static const value_string broadcom_sco_i2s_pcm_interface_mode_vals[] = {
    { 0x00,  "Disable" },
    { 0x01,  "Enable" },
    { 0, NULL }
};

static const value_string broadcom_sco_i2s_pcm_interface_sample_rate_vals[] = {
    { 0x00,  "8k" },
    { 0x01,  "16k" },
    { 0x02,  "4k" },
    { 0, NULL }
};

static const value_string broadcom_sco_i2s_pcm_interface_clock_rate_vals[] = {
    { 0x00,  "128k" },
    { 0x01,  "256k" },
    { 0x02,  "512k" },
    { 0x03,  "1024k" },
    { 0x04,  "2048k" },
    { 0, NULL }
};

static const value_string broadcom_le_subcode_batch_scan_vals[] = {
    { 0x01,  "Enable/Disable Customer Feature" },
    { 0x02,  "Set Storage Parameter" },
    { 0x03,  "Set Parameter" },
    { 0x04,  "Read Results" },
    { 0, NULL }
};

static const value_string broadcom_batch_scan_mode_vals[] = {
    { 0x00,  "Disable" },
    { 0x01,  "Pass" },
    { 0x02,  "ACTI" },
    { 0x03,  "Pass ACTI" },
    { 0, NULL }
};

static const value_string broadcom_batch_scan_discard_rule_vals[] = {
    { 0x00,  "Old Items" },
    { 0x01,  "Lower RSSI Items" },
    { 0, NULL }
};

static const value_string broadcom_disable_enable_vals[] = {
    { 0x00,  "Disable" },
    { 0x01,  "Enable" },
    { 0, NULL }
};

static const value_string broadcom_le_subcode_multi_advertising_vals[] = {
    { 0x01,  "Set Parameter" },
    { 0x02,  "Write Advertising Data" },
    { 0x03,  "Write Scan Response Data" },
    { 0x04,  "Set Random Address" },
    { 0x05,  "MultiAdvertising Enable/Disable Customer Feature" },
    { 0, NULL }
};

static const value_string broadcom_le_filter_policy_vals[] = {
    { 0x00,  "All Connections" },
    { 0x01,  "Whitelist Connections All" },
    { 0x02,  "All Connections Whitelist" },
    { 0x03,  "Whitelist Connections" },
    { 0, NULL }
};

static const value_string broadcom_hid_emulation_mode_vals[] = {
    { 0x00,  "Bluetooth" },
    { 0x01,  "HID" },
    { 0, NULL }
};

static const value_string broadcom_target_id_vals[] = {
    { 0xFE,  "Invalid" },
    { 0xFF,  "Undefined" },
    { 0, NULL }
};

static const value_string broadcom_a2dp_hardware_offload_vals[] = {
    { 0x01,  "Start A2DP offload (legacy)" },
    { 0x02,  "Stop A2DP offload (legacy)" },
    { 0x03,  "Start A2DP offload" },
    { 0x04,  "Stop A2DP offload" },
    { 0, NULL }
};

static const value_string broadcom_a2dp_hardware_offload_start_legacy_codec_vals[] = {
    { 0x01,  "SBC" },
    { 0x02,  "AAC" },
    { 0x04,  "APTX" },
    { 0x08,  "APTX HD" },
    { 0x10,  "LDAC" },
    { 0, NULL }
};

static const value_string broadcom_a2dp_hardware_offload_start_legacy_sampling_frequency_vals[] = {
    { 0x00000001,  "44100 Hz" },
    { 0x00000002,  "48000 Hz" },
    { 0x00000004,  "88200 Hz" },
    { 0x00000008,  "96000 Hz" },
    { 0, NULL }
};

static const value_string broadcom_a2dp_hardware_offload_start_legacy_bits_per_sample_vals[] = {
    { 0x01,  "16 bits per sample" },
    { 0x02,  "24 bits per sample" },
    { 0x04,  "32 bits per sample" },
    { 0, NULL }
};

static const value_string broadcom_a2dp_hardware_offload_start_legacy_channel_mode_vals[] = {
    { 0x01,  "Mono" },
    { 0x02,  "Stereo" },
    { 0, NULL }
};

static const value_string broadcom_a2dp_hardware_offload_start_legacy_codec_information_sbc_block_length_vals[] = {
    { 0x01,  "16" },
    { 0x02,  "12" },
    { 0x04,  "8" },
    { 0x08,  "4" },
    { 0, NULL }
};

static const value_string broadcom_a2dp_hardware_offload_start_legacy_codec_information_sbc_subbands_vals[] = {
    { 0x01,  "8" },
    { 0x02,  "4" },
    { 0, NULL }
};

static const value_string broadcom_a2dp_hardware_offload_start_legacy_codec_information_sbc_allocation_method_vals[] = {
    { 0x01,  "Loudness" },
    { 0x02,  "SNR" },
    { 0, NULL }
};

static const value_string broadcom_a2dp_hardware_offload_start_legacy_sbc_sampling_frequency_vals[] = {
    { 0x01,  "48000 Hz" },
    { 0x02,  "44100 Hz" },
    { 0x04,  "32000 Hz" },
    { 0x08,  "16000 Hz" },
    { 0, NULL }
};

static const value_string broadcom_a2dp_hardware_offload_start_legacy_sbc_channel_mode_vals[] = {
    { 0x01,  "Joint Stereo" },
    { 0x02,  "Stereo" },
    { 0x04,  "Dual Channel" },
    { 0x08,  "Mono" },
    { 0, NULL }
};

static const value_string broadcom_a2dp_hardware_offload_data_path_direction_vals[] = {
    { 0x00,  "Output (AVDTP Source/Merge)" },
    { 0x01,  "Input (AVDTP Sink/Split)" },
    { 0, NULL }
};

static const value_string broadcom_a2dp_hardware_offload_start_legacy_aac_object_type_vals[] = {
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

static const value_string broadcom_a2dp_hardware_offload_start_legacy_codec_information_ldac_bitrate_index_vals[] = {
    { 0x00,  "High" },
    { 0x01,  "Mid" },
    { 0x02,  "Low" },
    { 0x7f,  "ABR (Adaptive Bit Rate)" },
    { 0, NULL }
};

void proto_register_bthci_vendor_broadcom(void);
void proto_reg_handoff_bthci_vendor_broadcom(void);

static int
dissect_bthci_vendor_broadcom(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item        *main_item;
    proto_tree        *main_tree;
    proto_item        *opcode_item;
    proto_tree        *opcode_tree;
    proto_item        *sub_item;
    bluetooth_data_t  *bluetooth_data;
    int                offset = 0;
    uint16_t           opcode;
    uint16_t           ocf;
    const char        *description;
    uint8_t            length;
    uint8_t            event_code;
    uint8_t            bd_addr[6];
    uint8_t            status;
    uint8_t            subcode;
    uint8_t            condition;
    uint32_t           interface_id;
    uint32_t           adapter_id;
    proto_item        *codec_information_item;
    proto_tree        *codec_information_tree;

    bluetooth_data = (bluetooth_data_t *) data;
    if (bluetooth_data) {
        interface_id  = bluetooth_data->interface_id;
        adapter_id    = bluetooth_data->adapter_id;
    } else {
        interface_id  = HCI_INTERFACE_DEFAULT;
        adapter_id    = HCI_ADAPTER_DEFAULT;
    }

    main_item = proto_tree_add_item(tree, proto_bthci_vendor_broadcom, tvb, 0, -1, ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_broadcom);

    switch (pinfo->p2p_dir) {

    case P2P_DIR_SENT:
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "HCI_CMD_BROADCOM");
        col_set_str(pinfo->cinfo, COL_INFO, "Sent Broadcom ");

        opcode_item = proto_tree_add_item(main_tree, hf_broadcom_opcode, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        opcode_tree = proto_item_add_subtree(opcode_item, ett_broadcom_opcode);
        opcode = tvb_get_letohs(tvb, offset);
        proto_tree_add_item(opcode_tree, hf_broadcom_opcode_ogf, tvb, offset, 2, ENC_LITTLE_ENDIAN);

        proto_tree_add_item(opcode_tree, hf_broadcom_opcode_ocf, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        ocf = opcode & 0x03ff;
        offset+=2;

        description = val_to_str_const(ocf, broadcom_opcode_ocf_vals, "unknown");
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
            if (try_val_to_str(ocf, broadcom_opcode_ocf_vals))
                tap_hci_summary->name = description;
            else
                tap_hci_summary->name = NULL;
            tap_queue_packet(bluetooth_hci_summary_tap, pinfo, tap_hci_summary);
        }

        proto_tree_add_item(main_tree, hf_broadcom_parameter_length, tvb, offset, 1, ENC_NA);
        length = tvb_get_uint8(tvb, offset);
        offset += 1;

        switch(ocf) {
        case 0x0001: /* Write BDADDR */
            offset = dissect_bd_addr(hf_broadcom_bd_addr, pinfo, main_tree, tvb, offset, true, interface_id, adapter_id, bd_addr);

/* TODO: This is command, but in respose (event Command Complete) there is a status for that,
         so write bdaddr can fail, but we store bdaddr as valid for now... */
            if (!pinfo->fd->visited && bluetooth_data) {
                wmem_tree_key_t            key[4];
                uint32_t                   frame_number;
                localhost_bdaddr_entry_t   *localhost_bdaddr_entry;

                frame_number = pinfo->num;

                key[0].length = 1;
                key[0].key    = &interface_id;
                key[1].length = 1;
                key[1].key    = &adapter_id;
                key[2].length = 1;
                key[2].key    = &frame_number;
                key[3].length = 0;
                key[3].key    = NULL;

                localhost_bdaddr_entry = (localhost_bdaddr_entry_t *) wmem_new(wmem_file_scope(), localhost_bdaddr_entry_t);
                localhost_bdaddr_entry->interface_id = interface_id;
                localhost_bdaddr_entry->adapter_id = adapter_id;
                memcpy(localhost_bdaddr_entry->bd_addr, bd_addr, 6);
                wmem_tree_insert32_array(bluetooth_data->localhost_bdaddr, key, localhost_bdaddr_entry);
            }
            break;
        case 0x0018: /* Update Baudrate */
/* TODO: Implement - two unknown parameters... */
            sub_item = proto_tree_add_item(main_tree, hf_broadcom_data, tvb, offset, 1, ENC_NA);
            expert_add_info(pinfo, sub_item, &ei_broadcom_undecoded);
            offset += 1;

            sub_item = proto_tree_add_item(main_tree, hf_broadcom_data, tvb, offset, 1, ENC_NA);
            expert_add_info(pinfo, sub_item, &ei_broadcom_undecoded);
            offset += 1;

            proto_tree_add_item(main_tree, hf_broadcom_baudrate, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            break;
        case 0x001C: /* Write SCO PCM INT Parameter */
            proto_tree_add_item(main_tree, hf_broadcom_sco_pcm_routing, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_broadcom_sco_pcm_interface_clock_rate, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_broadcom_sco_pcm_interface_frame_type, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_broadcom_sco_pcm_interface_sync_mode, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_broadcom_sco_pcm_interface_clock_mode, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 0x001E: /* Write PCM Data Format Parameter */
            proto_tree_add_item(main_tree, hf_broadcom_pcm_shift_mode, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_broadcom_pcm_fill_bits, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_broadcom_pcm_fill_method, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_broadcom_pcm_fill_number_of_bits, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_broadcom_pcm_justify_mode, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 0x0027: /* Write Sleep Mode */
            proto_tree_add_item(main_tree, hf_broadcom_sleep_mode, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_broadcom_host_stack_idle_threshold, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_broadcom_host_controller_idle_threshold, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_broadcom_wake_polarity, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_broadcom_host_wake_polarity, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_broadcom_allow_host_sleep_during_sco, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_broadcom_combine_sleep_mode_and_lpm, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_broadcom_enable_uart_txd_tri_state, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_broadcom_sleep_guard_time, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_broadcom_wakeup_guard_time, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_broadcom_txd_config, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_broadcom_pulsed_host_wake, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 0x003B: /* Enable USB HID Emulation */
            proto_tree_add_item(main_tree, hf_broadcom_hid_emulation_mode, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 0x0045: /* Write UART Clock Setting */
            proto_tree_add_item(main_tree, hf_broadcom_uart_clock, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 0x004C: /* Write Memory */
            proto_tree_add_item(main_tree, hf_broadcom_mem_address, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(main_tree, hf_broadcom_mem_data, tvb, offset, length - 4, ENC_NA);
            offset += length - 4;
            break;
        case 0x004D: /* Read RAM */
            proto_tree_add_item(main_tree, hf_broadcom_mem_address, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(main_tree, hf_broadcom_mem_rdlen, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;
        case 0x004E: /* Launch RAM */
            proto_tree_add_item(main_tree, hf_broadcom_mem_address, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            break;
        case 0x0057: /* Set ACL Priority */
            proto_tree_add_item(main_tree, hf_broadcom_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(main_tree, hf_broadcom_connection_priority, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 0x006D: /* Write I2S PCM Interface Parameter */
            proto_tree_add_item(main_tree, hf_broadcom_sco_i2s_pcm_interface_mode, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_broadcom_sco_i2s_pcm_interface_role, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_broadcom_sco_i2s_pcm_interface_sample_rate, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_broadcom_sco_i2s_pcm_interface_clock_rate, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 0x007E: /* Enable WBS */
            proto_tree_add_item(main_tree, hf_broadcom_codec_state, tvb, offset, 1, ENC_NA);
            status = tvb_get_uint8(tvb, offset);
            offset += 1;

            if (status == 0x01) { /* Enable */
                proto_tree_add_item(main_tree, hf_broadcom_codec, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
            }
            break;
        case 0x0154: /* LE Multi Advertising */
            proto_tree_add_item(main_tree, hf_broadcom_le_multi_advertising_subcode, tvb, offset, 1, ENC_NA);
            subcode = tvb_get_uint8(tvb, offset);
            offset += 1;

            switch (subcode) {
            case 0x01: /* Set Parameter */
                proto_tree_add_item(main_tree, hf_broadcom_le_multi_advertising_min_interval, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(main_tree, hf_broadcom_le_multi_advertising_max_interval, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(main_tree, hf_broadcom_le_multi_advertising_type, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(main_tree, hf_broadcom_le_multi_advertising_address_type, tvb, offset, 1, ENC_NA);
                offset += 1;

                offset = dissect_bd_addr(hf_broadcom_bd_addr, pinfo, main_tree, tvb, offset, false, interface_id, adapter_id, NULL);

                proto_tree_add_item(main_tree, hf_broadcom_le_multi_advertising_address_type, tvb, offset, 1, ENC_NA);
                offset += 1;

                offset = dissect_bd_addr(hf_broadcom_bd_addr, pinfo, main_tree, tvb, offset, false, interface_id, adapter_id, NULL);

                proto_tree_add_bitmask(main_tree, tvb, offset, hf_broadcom_le_multi_advertising_channel_map, ett_broadcom_channel_map,  hfx_le_multi_advertising_channel_map, ENC_NA);
                offset += 1;

                proto_tree_add_item(main_tree, hf_broadcom_le_multi_advertising_filter_policy, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(main_tree, hf_broadcom_le_multi_advertising_instance_id, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(main_tree, hf_broadcom_le_multi_advertising_tx_power, tvb, offset, 1, ENC_NA);
                offset += 1;

                break;
            case 0x02: /* Write Advertising Data */
            case 0x03: /* Write Scan Response Data */
                call_dissector_with_data(btcommon_ad_handle, tvb_new_subset_length(tvb, offset, 31), pinfo, tree, bluetooth_data);
                save_local_device_name_from_eir_ad(tvb, offset, pinfo, 31, bluetooth_data);
                offset += 31;

                proto_tree_add_item(main_tree, hf_broadcom_le_multi_advertising_instance_id, tvb, offset, 1, ENC_NA);
                offset += 1;

                break;
            case 0x04: /* Set Random Address */
                offset = dissect_bd_addr(hf_broadcom_bd_addr, pinfo, main_tree, tvb, offset, false, interface_id, adapter_id, NULL);

                proto_tree_add_item(main_tree, hf_broadcom_le_multi_advertising_instance_id, tvb, offset, 1, ENC_NA);
                offset += 1;

                break;
            case 0x05: /* MultiAdvertising Enable/Disable Customer Feature */
                proto_tree_add_item(main_tree, hf_broadcom_le_multi_advertising_enable, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(main_tree, hf_broadcom_le_multi_advertising_instance_id, tvb, offset, 1, ENC_NA);
                offset += 1;

                break;
            }

            break;
        case 0x0156: /* LE Batch Scan */
            proto_tree_add_item(main_tree, hf_broadcom_le_batch_scan_subcode, tvb, offset, 1, ENC_NA);
            subcode = tvb_get_uint8(tvb, offset);
            offset += 1;

            switch (subcode) {
            case 0x01: /* Enable/Disable Customer Feature */
                proto_tree_add_item(main_tree, hf_broadcom_le_batch_scan_enable, tvb, offset, 1, ENC_NA);
                offset += 1;

                break;
            case 0x02: /* Set Storage Parameter */
                proto_tree_add_item(main_tree, hf_broadcom_le_batch_scan_full_max, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(main_tree, hf_broadcom_le_batch_scan_truncate_max, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(main_tree, hf_broadcom_le_batch_scan_notify_threshold, tvb, offset, 1, ENC_NA);
                offset += 1;

                break;
            case 0x03: /* Set Parameter */
                proto_tree_add_item(main_tree, hf_broadcom_le_batch_scan_mode, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(main_tree, hf_broadcom_le_batch_scan_window, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                proto_tree_add_item(main_tree, hf_broadcom_le_batch_scan_interval, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                proto_tree_add_item(main_tree, hf_broadcom_le_batch_scan_address_type, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(main_tree, hf_broadcom_le_batch_scan_discard_rule, tvb, offset, 1, ENC_NA);
                offset += 1;

                break;
            case 0x04: /* Read Results */
                proto_tree_add_item(main_tree, hf_broadcom_le_batch_scan_mode, tvb, offset, 1, ENC_NA);
                offset += 1;

                break;
            }

            break;
        case 0x0157: /* LE Advertising Filter */
            proto_tree_add_item(main_tree, hf_broadcom_le_advertising_filter_subcode, tvb, offset, 1, ENC_NA);
            subcode = tvb_get_uint8(tvb, offset);
            offset += 1;

            proto_tree_add_item(main_tree, hf_broadcom_le_scan_condition, tvb, offset, 1, ENC_NA);
            condition = tvb_get_uint8(tvb, offset);
            offset += 1;

            proto_tree_add_item(main_tree, hf_broadcom_le_filter_index, tvb, offset, 1, ENC_NA);
            offset += 1;

            if (condition == 0x00) { /* Add */
                switch (subcode) {
                case 0x00: /* Enable */
                case 0x01: /* Feature Select */
                case 0x02: /* BDADDR */
                case 0x03: /* UUID */
                case 0x04: /* Solicitate UUID */
                case 0x05: /* Local Name */
                case 0x06: /* Manufacturer Data */
                case 0x07: /* Service Data */
                case 0x08: /* All */
/* TODO */
                    sub_item = proto_tree_add_item(main_tree, hf_broadcom_data, tvb, offset, length - 3, ENC_NA);
                    expert_add_info(pinfo, sub_item, &ei_broadcom_undecoded);
                    offset += length - 3;

                    break;
                default:
                    sub_item = proto_tree_add_item(main_tree, hf_broadcom_data, tvb, offset, length - 3, ENC_NA);
                    expert_add_info(pinfo, sub_item, &ei_broadcom_unexpected_data);
                    offset += length - 3;
                }
            }

            break;
        case 0x0102: /* Enable WBS Modified */
        case 0x0111: /* Set ConnectionLess Broadcast Stream */
        case 0x0112: /* Receive ConnectionLess Broadcast Stream */
        case 0x0113: /* Write ConnectionLess Broadcast Stream Data */
        case 0x0114: /* ConnectionLess Broadcast Stream Flush */
        case 0x0158: /* LE Tracking Advertising */
            sub_item = proto_tree_add_item(main_tree, hf_broadcom_data, tvb, offset, length, ENC_NA);
            expert_add_info(pinfo, sub_item, &ei_broadcom_undecoded);
            offset += length;

            break;

        case 0x002E: /* Download MiniDriver */
        case 0x005A: /* Read VID PID */
        case 0x0079: /* Read Verbose Config Version Info */
        case 0x0153: /* LE Get Vendor Capabilities */
        case 0x0159: /* LE Energy Info */
            if (tvb_captured_length_remaining(tvb, offset) > 0) {
                sub_item = proto_tree_add_item(main_tree, hf_broadcom_data, tvb, offset, length, ENC_NA);
                expert_add_info(pinfo, sub_item, &ei_broadcom_unexpected_parameter);
            }
            break;
        case 0x015D: /* A2DP Hardware Offload */
            proto_tree_add_item(main_tree, hf_broadcom_a2dp_hardware_offload_subcode, tvb, offset, 1, ENC_NA);
            subcode = tvb_get_uint8(tvb, offset);
            offset += 1;

            switch (subcode) {
            case 0x01: {    /* Start A2DP offload (legacy) */
                int codec_id = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);

                proto_tree_add_item(main_tree, hf_broadcom_a2dp_hardware_offload_start_legacy_codec, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                proto_tree_add_item(main_tree, hf_broadcom_a2dp_hardware_offload_start_legacy_max_latency, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                /* Flag is the LSB out of the two, read it first */
                proto_tree_add_item(main_tree, hf_broadcom_a2dp_hardware_offload_start_legacy_scms_t_enable_flag, tvb, offset, 1, ENC_NA);
                offset += 1;

                bool scms_t_enabled = tvb_get_uint8(tvb, offset) == 0x01;
                if (scms_t_enabled) {
                    proto_tree_add_item(main_tree, hf_broadcom_a2dp_hardware_offload_start_legacy_scms_t_enable_value, tvb, offset, 1, ENC_NA);
                } else {
                    proto_tree_add_item(main_tree, hf_broadcom_a2dp_hardware_offload_start_legacy_scms_t_enable_value_reserved, tvb, offset, 1, ENC_NA);
                }
                offset += 1;

                proto_tree_add_item(main_tree, hf_broadcom_a2dp_hardware_offload_start_legacy_sampling_frequency, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                proto_tree_add_item(main_tree, hf_broadcom_a2dp_hardware_offload_start_legacy_bits_per_sample, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(main_tree, hf_broadcom_a2dp_hardware_offload_start_legacy_channel_mode, tvb, offset, 1, ENC_NA);
                offset += 1;

                uint32_t encoded_audio_bitrate = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);
                if (encoded_audio_bitrate == 0x00000000) {
                    proto_tree_add_item(main_tree, hf_broadcom_a2dp_hardware_offload_start_legacy_encoded_audio_bitrate_unspecified, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                } else if (encoded_audio_bitrate >= 0x01000000) {
                    proto_tree_add_item(main_tree, hf_broadcom_a2dp_hardware_offload_start_legacy_encoded_audio_bitrate_reserved, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                } else {
                    proto_tree_add_item(main_tree, hf_broadcom_a2dp_hardware_offload_start_legacy_encoded_audio_bitrate, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                }
                offset += 4;

                proto_tree_add_item(main_tree, hf_broadcom_a2dp_hardware_offload_start_legacy_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(main_tree, hf_broadcom_a2dp_hardware_offload_start_legacy_l2cap_cid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(main_tree, hf_broadcom_a2dp_hardware_offload_start_legacy_l2cap_mtu_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                codec_information_item = proto_tree_add_item(main_tree, hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information, tvb, offset, 32, ENC_NA);
                codec_information_tree = proto_item_add_subtree(codec_information_item, ett_broadcom_a2dp_hardware_offload_start_legacy_codec_information);

                switch (codec_id) {
                    case 0x00000001:  /* SBC */
                        proto_tree_add_item(codec_information_tree, hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_sbc_block_length, tvb, offset, 1, ENC_NA);
                        proto_tree_add_item(codec_information_tree, hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_sbc_subbands, tvb, offset, 1, ENC_NA);
                        proto_tree_add_item(codec_information_tree, hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_sbc_allocation_method, tvb, offset, 1, ENC_NA);
                        offset += 1;

                        proto_tree_add_item(codec_information_tree, hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_sbc_min_bitpool, tvb, offset, 1, ENC_NA);
                        offset += 1;

                        proto_tree_add_item(codec_information_tree, hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_sbc_max_bitpool, tvb, offset, 1, ENC_NA);
                        offset += 1;

                        proto_tree_add_item(codec_information_tree, hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_sbc_sampling_frequency, tvb, offset, 1, ENC_NA);
                        proto_tree_add_item(codec_information_tree, hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_sbc_channel_mode, tvb, offset, 1, ENC_NA);
                        offset += 1;

                        proto_tree_add_item(codec_information_tree, hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_sbc_reserved, tvb, offset, 28, ENC_NA);
                        offset += 28;
                    break;
                    case 0x00000002:  /* AAC */
                        proto_tree_add_item(codec_information_tree, hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_aac_object_type, tvb, offset, 1, ENC_NA);
                        offset += 1;

                        proto_tree_add_item(codec_information_tree, hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_aac_vbr, tvb, offset, 1, ENC_NA);
                        offset += 1;

                        proto_tree_add_item(codec_information_tree, hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_aac_reserved, tvb, offset, 30, ENC_NA);
                        offset += 30;
                    break;
                    case 0x00000010:  /* LDAC */
                        proto_tree_add_item(codec_information_tree, hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_ldac_vendor_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                        offset += 4;

                        proto_tree_add_item(codec_information_tree, hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_ldac_codec_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        offset += 2;

                        uint8_t bitrate_index = tvb_get_uint8(tvb, offset);
                        if (bitrate_index >= 0x03 && bitrate_index != 0x7F) {
                            proto_tree_add_item(codec_information_tree, hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_ldac_bitrate_index_reserved, tvb, offset, 1, ENC_NA);
                        } else {
                            proto_tree_add_item(codec_information_tree, hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_ldac_bitrate_index, tvb, offset, 1, ENC_NA);
                        }
                        offset += 1;

                        proto_tree_add_bitmask(main_tree, tvb, offset, hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode_mask,
                                               ett_broadcom_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode_mask, hfx_broadcom_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode, ENC_NA);
                        offset += 1;

                        proto_tree_add_item(codec_information_tree, hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_ldac_reserved, tvb, offset, 24, ENC_NA);
                        offset += 24;
                    break;
                    default:    /* All other codecs */
                        proto_tree_add_item(codec_information_tree, hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_reserved, tvb, offset, 32, ENC_NA);
                        offset += 32;
                    break;
                }

                break;
            }
            case 0x02: {    /* Stop A2DP offload (legacy) */
                if (tvb_captured_length_remaining(tvb, offset) > 0) {
                    sub_item = proto_tree_add_item(main_tree, hf_broadcom_data, tvb, offset, length, ENC_NA);
                    expert_add_info(pinfo, sub_item, &ei_broadcom_unexpected_parameter);
                    offset += tvb_captured_length_remaining(tvb, offset);
                }
                break;
            }
            case 0x03: {    /* Start A2DP offload */
                proto_tree_add_item(main_tree, hf_broadcom_a2dp_hardware_offload_start_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(main_tree, hf_broadcom_a2dp_hardware_offload_start_l2cap_cid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(main_tree, hf_broadcom_a2dp_hardware_offload_start_data_path_direction, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(main_tree, hf_broadcom_a2dp_hardware_offload_start_peer_mtu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                bool cp_enable_scmst = tvb_get_uint8(tvb, offset) == 0x01;
                proto_tree_add_item(main_tree, hf_broadcom_a2dp_hardware_offload_start_cp_enable_scmst, tvb, offset, 1, ENC_NA);
                offset += 1;

                if (cp_enable_scmst) {
                    proto_tree_add_item(main_tree, hf_broadcom_a2dp_hardware_offload_start_cp_header_scmst, tvb, offset, 1, ENC_NA);
                } else {
                    proto_tree_add_item(main_tree, hf_broadcom_a2dp_hardware_offload_start_cp_header_scmst_reserved, tvb, offset, 1, ENC_NA);
                }
                offset += 1;

                uint8_t vendor_specific_parameters_length = tvb_get_uint8(tvb, offset);
                proto_tree_add_item(main_tree, hf_broadcom_a2dp_hardware_offload_start_vendor_specific_parameters_length, tvb, offset, 1, ENC_NA);
                offset += 1;

                if (vendor_specific_parameters_length > 0 && vendor_specific_parameters_length <= 128) {
                    proto_tree_add_item(main_tree, hf_broadcom_a2dp_hardware_offload_start_vendor_specific_parameters, tvb, offset, vendor_specific_parameters_length, ENC_NA);
                    offset += vendor_specific_parameters_length;
                }
                break;
            }
            case 0x04: {    /* Stop A2DP offload */
                proto_tree_add_item(main_tree, hf_broadcom_a2dp_hardware_offload_stop_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(main_tree, hf_broadcom_a2dp_hardware_offload_stop_l2cap_cid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(main_tree, hf_broadcom_a2dp_hardware_offload_stop_data_path_direction, tvb, offset, 1, ENC_NA);
                offset += 1;

                break;
            }
            default:
                if (tvb_captured_length_remaining(tvb, offset) > 0) {
                    sub_item = proto_tree_add_item(main_tree, hf_broadcom_data, tvb, offset, length, ENC_NA);
                    expert_add_info(pinfo, sub_item, &ei_broadcom_unexpected_parameter);
                    offset += tvb_captured_length_remaining(tvb, offset);
                }
                break;
            }

            break;
        default:
            if (length > 0) {
                sub_item = proto_tree_add_item(main_tree, hf_broadcom_data, tvb, offset, length, ENC_NA);
                expert_add_info(pinfo, sub_item, &ei_broadcom_undecoded);
                offset += length;
            }
        }

        break;
    case P2P_DIR_RECV:
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "HCI_EVT_BROADCOM");
        col_set_str(pinfo->cinfo, COL_INFO, "Rcvd Broadcom ");

        event_code = tvb_get_uint8(tvb, offset);
        description = val_to_str_ext(event_code, &bthci_evt_evt_code_vals_ext, "Unknown 0x%08x");
        col_append_str(pinfo->cinfo, COL_INFO, description);
        proto_tree_add_item(main_tree, hf_broadcom_event_code, tvb, offset, 1, ENC_NA);
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

        proto_tree_add_item(main_tree, hf_broadcom_parameter_length, tvb, offset, 1, ENC_NA);
        length = tvb_get_uint8(tvb, offset);
        offset += 1;

        switch (event_code) {
        case 0x0e: /* Command Complete */
            proto_tree_add_item(main_tree, hf_broadcom_number_of_allowed_command_packets, tvb, offset, 1, ENC_NA);
            offset += 1;

            opcode_item = proto_tree_add_item(main_tree, hf_broadcom_opcode, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            opcode_tree = proto_item_add_subtree(opcode_item, ett_broadcom_opcode);
            opcode = tvb_get_letohs(tvb, offset);
            proto_tree_add_item(opcode_tree, hf_broadcom_opcode_ogf, tvb, offset, 2, ENC_LITTLE_ENDIAN);

            proto_tree_add_item(opcode_tree, hf_broadcom_opcode_ocf, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            ocf = opcode & 0x03ff;
            offset += 2;

            description = val_to_str_const(ocf, broadcom_opcode_ocf_vals, "unknown");
            if (g_strcmp0(description, "unknown") != 0)
                col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", description);
            else
                col_append_fstr(pinfo->cinfo, COL_INFO, " (Unknown Command 0x%04X [opcode 0x%04X])", ocf, opcode);

            if (have_tap_listener(bluetooth_hci_summary_tap)) {
                bluetooth_hci_summary_tap_t  *tap_hci_summary;

                tap_hci_summary = wmem_new(pinfo->pool, bluetooth_hci_summary_tap_t);
                tap_hci_summary->interface_id  = interface_id;
                tap_hci_summary->adapter_id    = adapter_id;

                tap_hci_summary->type = BLUETOOTH_HCI_SUMMARY_VENDOR_EVENT_OPCODE;
                tap_hci_summary->ogf = opcode >> 10;
                tap_hci_summary->ocf = ocf;
                if (try_val_to_str(ocf, broadcom_opcode_ocf_vals))
                    tap_hci_summary->name = description;
                else
                    tap_hci_summary->name = NULL;
                tap_queue_packet(bluetooth_hci_summary_tap, pinfo, tap_hci_summary);
            }

            proto_tree_add_item(main_tree, hf_broadcom_status, tvb, offset, 1, ENC_NA);
            status = tvb_get_uint8(tvb, offset);
            offset += 1;

            switch (ocf) {
            case 0x004D: /* Read Memory */
                if (status == STATUS_SUCCESS) {
                    proto_tree_add_item(main_tree, hf_broadcom_mem_data, tvb, offset, length, ENC_NA);
                    offset += length;
                }
                break;
            case 0x005A: /* Read VID PID */
                proto_tree_add_item(main_tree, hf_broadcom_vid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(main_tree, hf_broadcom_pid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                break;
            case 0x0079: /* Read Verbose Config Version Info */
                proto_tree_add_item(main_tree, hf_broadcom_chip_id, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(main_tree, hf_broadcom_target_id, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(main_tree, hf_broadcom_build_base, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(main_tree, hf_broadcom_build_number, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                break;
            case 0x0153: /* LE Get Vendor Capabilities */
                if (status != STATUS_SUCCESS)
                    break;

                uint16_t google_feature_spec_version = tvb_get_uint16(tvb, offset + 8, ENC_LITTLE_ENDIAN);
                if (google_feature_spec_version < 0x0098) {
                    proto_tree_add_item(main_tree, hf_broadcom_max_advertising_instance, tvb, offset, 1, ENC_NA);
                } else {
                    proto_tree_add_item(main_tree, hf_broadcom_max_advertising_instance_reserved, tvb, offset, 1, ENC_NA);
                }
                offset += 1;

                if (google_feature_spec_version < 0x0098) {
                    proto_tree_add_item(main_tree, hf_broadcom_resolvable_private_address_offloading, tvb, offset, 1, ENC_NA);
                } else {
                    proto_tree_add_item(main_tree, hf_broadcom_resolvable_private_address_offloading_reserved, tvb, offset, 1, ENC_NA);
                }
                offset += 1;

                proto_tree_add_item(main_tree, hf_broadcom_total_scan_results, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(main_tree, hf_broadcom_max_irk_list, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(main_tree, hf_broadcom_filter_support, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(main_tree, hf_broadcom_max_filter, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(main_tree, hf_broadcom_energy_support, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(main_tree, hf_broadcom_version_support, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(main_tree, hf_broadcom_total_num_of_advt_tracked, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(main_tree, hf_broadcom_extended_scan_support, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(main_tree, hf_broadcom_debug_logging_support, tvb, offset, 1, ENC_NA);
                offset += 1;

                if (google_feature_spec_version < 0x0098) {
                    proto_tree_add_item(main_tree, hf_broadcom_le_address_generation_offloading_support, tvb, offset, 1, ENC_NA);
                } else {
                    proto_tree_add_item(main_tree, hf_broadcom_le_address_generation_offloading_support_reserved, tvb, offset, 1, ENC_NA);
                }
                offset += 1;

                proto_tree_add_bitmask(main_tree, tvb, offset, hf_broadcom_a2dp_source_offload_capability_mask, ett_broadcom_a2dp_source_offload_capability_mask, hfx_broadcom_a2dp_source_offload_capability, ENC_LITTLE_ENDIAN);
                offset += 4;

                proto_tree_add_item(main_tree, hf_broadcom_bluetooth_quality_report_support, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_bitmask(main_tree, tvb, offset, hf_broadcom_dynamic_audio_buffer_support_mask, ett_broadcom_dynamic_audio_buffer_support_mask, hfx_broadcom_dynamic_audio_buffer_support, ENC_LITTLE_ENDIAN);
                offset += 4;

                if (tvb_captured_length_remaining(tvb, offset) > 0) {
                    proto_tree_add_item(main_tree, hf_broadcom_a2dp_offload_v2_support, tvb, offset, 1, ENC_NA);
                    offset += 1;
                }

                break;
            case 0x0154: /* LE Multi Advertising */
                proto_tree_add_item(main_tree, hf_broadcom_le_multi_advertising_subcode, tvb, offset, 1, ENC_NA);
                offset += 1;

                break;
            case 0x0156: /* LE Batch Scan */
                proto_tree_add_item(main_tree, hf_broadcom_le_batch_scan_subcode, tvb, offset, 1, ENC_NA);
                subcode = tvb_get_uint8(tvb, offset);
                offset += 1;

                if (subcode == 0x04 && status == STATUS_SUCCESS) { /* Read Results*/
                    proto_tree_add_item(main_tree, hf_broadcom_le_batch_scan_report_format, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    proto_tree_add_item(main_tree, hf_broadcom_le_batch_scan_number_of_records, tvb, offset, 1, ENC_NA);
                    offset += 1;
                }


                break;
            case 0x0157: /* LE Advertising Filter */
                proto_tree_add_item(main_tree, hf_broadcom_le_advertising_filter_subcode, tvb, offset, 1, ENC_NA);
                offset += 1;

                if (status == STATUS_SUCCESS) {
                    proto_tree_add_item(main_tree, hf_broadcom_le_scan_condition, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    proto_tree_add_item(main_tree, hf_broadcom_le_number_of_available_filters, tvb, offset, 1, ENC_NA);
                    offset += 1;
                }

                break;
            case 0x0159: /* LE Energy Info */
                if (status == STATUS_SUCCESS) {
                    proto_tree_add_item(main_tree, hf_broadcom_le_energy_total_rx_time, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    proto_tree_add_item(main_tree, hf_broadcom_le_energy_total_tx_time, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    proto_tree_add_item(main_tree, hf_broadcom_le_energy_total_idle_time, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    proto_tree_add_item(main_tree, hf_broadcom_le_energy_total_energy_used, tvb, offset, 1, ENC_NA);
                    offset += 1;
                }

                break;
            case 0x015D: /* A2DP Hardware Offload */
                proto_tree_add_item(main_tree, hf_broadcom_a2dp_hardware_offload_subcode, tvb, offset, 1, ENC_NA);
                offset += 1;

                break;
            case 0x0102: /* Enable WBS Modified */
            case 0x0111: /* Set ConnectionLess Broadcast Stream */
            case 0x0112: /* Receive ConnectionLess Broadcast Stream */
            case 0x0113: /* Write ConnectionLess Broadcast Stream Data */
            case 0x0114: /* ConnectionLess Broadcast Stream Flush */
            case 0x0158: /* LE Tracking Advertising */
/* TODO: Implement - parameters not known */
                sub_item = proto_tree_add_item(main_tree, hf_broadcom_data, tvb, offset, length, ENC_NA);
                expert_add_info(pinfo, sub_item, &ei_broadcom_undecoded);
                offset += length;

                break;
            case 0x0001: /* Write BDADDR */
            case 0x0018: /* Update Baudrate */
            case 0x001C: /* Write SCO PCM INT Parameter */
            case 0x001E: /* Write PCM Data Format Parameter */
            case 0x0027: /* Write Sleep Mode */
            case 0x002E: /* Download MiniDriver */
            case 0x003B: /* Enable USB HID Emulation */
            case 0x0045: /* Write UART Clock Setting */
            case 0x004C: /* Write Memory */
            case 0x004E: /* Launch RAM */
            case 0x0057: /* Set ACL Priority */
            case 0x006D: /* Write I2S PCM Interface Parameter */
            case 0x007E: /* Enable WBS */
                if (tvb_captured_length_remaining(tvb, offset) > 0) {
                    sub_item = proto_tree_add_item(main_tree, hf_broadcom_data, tvb, offset, length, ENC_NA);
                    expert_add_info(pinfo, sub_item, &ei_broadcom_unexpected_parameter);
                    offset += tvb_captured_length_remaining(tvb, offset);
                }
                break;
            default:
                if (length > 0) {
                    sub_item = proto_tree_add_item(main_tree, hf_broadcom_data, tvb, offset, length, ENC_NA);
                    expert_add_info(pinfo, sub_item, &ei_broadcom_undecoded);
                    offset += length;
                }
            }

            break;
        default:
            if (length > 0) {
                sub_item = proto_tree_add_item(main_tree, hf_broadcom_data, tvb, offset, length, ENC_NA);
                expert_add_info(pinfo, sub_item, &ei_broadcom_undecoded);
                offset += length;
            }
        }


        break;

    case P2P_DIR_UNKNOWN:
    default:
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "HCI_BROADCOM");
        col_set_str(pinfo->cinfo, COL_INFO, "UnknownDirection Broadcom ");

        if (tvb_captured_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(main_tree, hf_broadcom_data, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA);
            offset += tvb_captured_length_remaining(tvb, offset);
        }
        break;
    }

    if (tvb_captured_length_remaining(tvb, offset) > 0) {
        sub_item = proto_tree_add_item(main_tree, hf_broadcom_data, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA);
        expert_add_info(pinfo, sub_item, &ei_broadcom_unexpected_data);
        offset += tvb_captured_length_remaining(tvb, offset);
    }

    return offset;
}

void
proto_register_bthci_vendor_broadcom(void)
{
    expert_module_t  *expert_module;

    static hf_register_info hf[] = {
        { &hf_broadcom_opcode,
          { "Command Opcode",                              "bthci_vendor.broadcom.opcode",
            FT_UINT16, BASE_HEX, VALS(broadcom_opcode_vals), 0x0,
            "HCI Command Opcode", HFILL }
        },
        { &hf_broadcom_opcode_ogf,
          { "Opcode Group Field",                          "bthci_vendor.broadcom.opcode.ogf",
            FT_UINT16, BASE_HEX|BASE_EXT_STRING, &bthci_cmd_ogf_vals_ext, 0xfc00,
            NULL, HFILL }
        },
        { &hf_broadcom_opcode_ocf,
          { "Opcode Command Field",                        "bthci_vendor.broadcom.opcode.ocf",
            FT_UINT16, BASE_HEX, VALS(broadcom_opcode_ocf_vals), 0x03ff,
            NULL, HFILL }
        },
        { &hf_broadcom_parameter_length,
          { "Parameter Total Length",                      "bthci_vendor.broadcom.parameter_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_event_code,
          { "Event Code",                                  "bthci_vendor.broadcom.event_code",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &bthci_evt_evt_code_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_number_of_allowed_command_packets,
          { "Number of Allowed Command Packets",           "bthci_vendor.broadcom.number_of_allowed_command_packets",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_le_advertising_filter_subcode,
            { "Subcode",                                   "bthci_vendor.broadcom.le.advertising_filter.subcode",
            FT_UINT8, BASE_HEX, VALS(broadcom_le_subcode_advertising_filter_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_le_scan_condition,
            { "Scan Condition",                            "bthci_vendor.broadcom.le.scan_condition",
            FT_UINT8, BASE_HEX, VALS(broadcom_le_scan_condition_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_le_filter_index,
            { "Filter Index",                              "bthci_vendor.broadcom.le.filter_index",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_le_number_of_available_filters,
            { "Number of Available Filters",               "bthci_vendor.broadcom.le.number_of_available_filters",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_mem_address,
            { "Address",                                   "bthci_vendor.broadcom.mem.address",
            FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_mem_data,
            { "Firmware",                                  "bthci_vendor.broadcom.mem.data",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_mem_rdlen,
            { "Length",                                    "bthci_vendor.broadcom.mem.rd_len",
            FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_baudrate,
            { "Baudrate",                                  "bthci_vendor.broadcom.baudrate",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_bd_addr,
          { "BD_ADDR",                                     "bthci_vendor.broadcom.bd_addr",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            "Bluetooth Device Address", HFILL}
        },
        { &hf_broadcom_max_advertising_instance,
            { "Max Advertising Instance",                  "bthci_vendor.broadcom.max_advertising_instance",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_max_advertising_instance_reserved,
            { "Reserved",                                  "bthci_vendor.broadcom.max_advertising_instance_reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_resolvable_private_address_offloading,
            { "Resolvable Private Address Offloading",     "bthci_vendor.broadcom.resolvable_private_address_offloading",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_resolvable_private_address_offloading_reserved,
            { "Reserved",                                  "bthci_vendor.broadcom.resolvable_private_address_offloading_reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_total_scan_results,
            { "Total Scan Results",                        "bthci_vendor.broadcom.total_scan_results",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_max_irk_list,
            { "Max IRK List",                              "bthci_vendor.broadcom.max_irk_list",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_filter_support,
            { "Filter Support",                            "bthci_vendor.broadcom.filter_support",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_max_filter,
            { "Max Filter",                                "bthci_vendor.broadcom.max_filter",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_energy_support,
            { "Energy Support",                            "bthci_vendor.broadcom.energy_support",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_version_support,
            { "Version Support",                           "bthci_vendor.broadcom.version_support",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_total_num_of_advt_tracked,
            { "Total Number of Advertisers Tracked",       "bthci_vendor.broadcom.total_num_of_advt_tracked",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_extended_scan_support,
            { "Extended Scan Support",                     "bthci_vendor.broadcom.extended_scan_support",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_debug_logging_support,
            { "Debug Logging Support",                     "bthci_vendor.broadcom.debug_logging_support",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_le_address_generation_offloading_support,
            { "LE Address Generation Offloading Support",  "bthci_vendor.broadcom.le_address_generation_offloading_support",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_le_address_generation_offloading_support_reserved,
            { "Reserved",                                  "bthci_vendor.broadcom.le_address_generation_offloading_support_reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_source_offload_capability_mask,
            { "A2DP Source Offload Capability",            "bthci_vendor.broadcom.a2dp_source_offload_capability_mask",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_source_offload_capability_mask_sbc,
          { "SBC",                                         "bthci_vendor.broadcom.a2dp_source_offload_capability_mask.sbc",
            FT_BOOLEAN, 32, NULL, 0x00000001,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_source_offload_capability_mask_aac,
          { "AAC",                                         "bthci_vendor.broadcom.a2dp_source_offload_capability_mask.aac",
            FT_BOOLEAN, 32, NULL, 0x00000002,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_source_offload_capability_mask_aptx,
          { "APTX",                                        "bthci_vendor.broadcom.a2dp_source_offload_capability_mask.aptx",
            FT_BOOLEAN, 32, NULL, 0x00000004,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_source_offload_capability_mask_aptx_hd,
          { "APTX HD",                                     "bthci_vendor.broadcom.a2dp_source_offload_capability_mask.aptx_hd",
            FT_BOOLEAN, 32, NULL, 0x00000008,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_source_offload_capability_mask_ldac,
          { "LDAC",                                        "bthci_vendor.broadcom.a2dp_source_offload_capability_mask.ldac",
            FT_BOOLEAN, 32, NULL, 0x00000010,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_source_offload_capability_mask_reserved,
          { "Reserved",                                    "bthci_vendor.broadcom.a2dp_source_offload_capability_mask.reserved",
            FT_UINT32, BASE_HEX, NULL, UINT32_C(0xFFFFFFE0),
            NULL, HFILL }
        },
        { &hf_broadcom_bluetooth_quality_report_support,
            { "Bluetooth Quality Report Support",          "bthci_vendor.broadcom.bluetooth_quality_report_support",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_dynamic_audio_buffer_support_mask,
            { "Dynamic Audio Buffer Support",              "bthci_vendor.broadcom.dynamic_audio_buffer_support_mask",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_dynamic_audio_buffer_support_mask_sbc,
          { "SBC",                                         "bthci_vendor.broadcom.dynamic_audio_buffer_support_mask.sbc",
            FT_BOOLEAN, 32, NULL, 0x00000001,
            NULL, HFILL }
        },
        { &hf_broadcom_dynamic_audio_buffer_support_mask_aac,
          { "AAC",                                         "bthci_vendor.broadcom.dynamic_audio_buffer_support_mask.aac",
            FT_BOOLEAN, 32, NULL, 0x00000002,
            NULL, HFILL }
        },
        { &hf_broadcom_dynamic_audio_buffer_support_mask_aptx,
          { "APTX",                                        "bthci_vendor.broadcom.dynamic_audio_buffer_support_mask.aptx",
            FT_BOOLEAN, 32, NULL, 0x00000004,
            NULL, HFILL }
        },
        { &hf_broadcom_dynamic_audio_buffer_support_mask_aptx_hd,
          { "APTX HD",                                     "bthci_vendor.broadcom.dynamic_audio_buffer_support_mask.aptx_hd",
            FT_BOOLEAN, 32, NULL, 0x00000008,
            NULL, HFILL }
        },
        { &hf_broadcom_dynamic_audio_buffer_support_mask_ldac,
          { "LDAC",                                        "bthci_vendor.broadcom.dynamic_audio_buffer_support_mask.ldac",
            FT_BOOLEAN, 32, NULL, 0x00000010,
            NULL, HFILL }
        },
        { &hf_broadcom_dynamic_audio_buffer_support_mask_reserved,
          { "Reserved",                                    "bthci_vendor.broadcom.dynamic_audio_buffer_support_mask.reserved",
            FT_UINT32, BASE_HEX, NULL, UINT32_C(0xFFFFFFE0),
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_offload_v2_support,
            { "A2DP Offload V2 Support",                   "bthci_vendor.broadcom.a2dp_offload_v2_support",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_uart_clock,
            { "UART Clock",                                "bthci_vendor.broadcom.uart_clock",
            FT_UINT8, BASE_HEX, VALS(broadcom_uart_clock_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_connection_handle,
          { "Connection Handle",                           "bthci_vendor.broadcom.connection_handle",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_connection_priority,
          { "Connection Priority",                         "bthci_vendor.broadcom.connection_priority",
            FT_UINT8, BASE_HEX, VALS(broadcom_connection_priority_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_sleep_mode,
            { "Sleep Mode",                                "bthci_vendor.broadcom.sleep_mode",
            FT_UINT8, BASE_HEX, VALS(broadcom_sleep_mode_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_host_stack_idle_threshold,
            { "Host Stack Idle Threshold",                 "bthci_vendor.broadcom.host_stack_idle_threshold",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_host_controller_idle_threshold,
            { "Host Controller Idle Threshold",            "bthci_vendor.broadcom.host_controller_idle_threshold",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_wake_polarity,
            { "Wake Polarity",                             "bthci_vendor.broadcom.wake_polarity",
            FT_UINT8, BASE_HEX, VALS(broadcom_wake_polarity_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_host_wake_polarity,
            { "Host Wake Polarity",                        "bthci_vendor.broadcom.host_wake_polarity",
            FT_UINT8, BASE_HEX, VALS(broadcom_wake_polarity_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_allow_host_sleep_during_sco,
            { "Allow Host Sleep During SCO",               "bthci_vendor.broadcom.allow_host_sleep_during_sco",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_combine_sleep_mode_and_lpm,
            { "Combine Sleep Mode and LPM",                "bthci_vendor.broadcom.combine_sleep_mode_and_lpm",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_enable_uart_txd_tri_state,
            { "Enable UART TXD Tri-state",                 "bthci_vendor.broadcom.enable_uart_txd_tri_state",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_sleep_guard_time,
            { "Sleep Guard Time",                          "bthci_vendor.broadcom.sleep_guard_time",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_wakeup_guard_time,
            { "Wakeup Guard Time",                         "bthci_vendor.broadcom.wakeup_guard_time",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_txd_config,
            { "TXD Config",                                "bthci_vendor.broadcom.txd_config",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_pulsed_host_wake,
            { "Pulsed Host Wake",                          "bthci_vendor.broadcom.pulsed_host_wake",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_codec_state,
            { "Codec State",                               "bthci_vendor.broadcom.codec_state",
            FT_UINT8, BASE_HEX, VALS(broadcom_codec_state_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_codec,
            { "Codec",                                     "bthci_vendor.broadcom.codec",
            FT_UINT16, BASE_HEX, VALS(broadcom_codec_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_status,
          { "Status",                                      "bthci_vendor.broadcom.status",
            FT_UINT8, BASE_HEX|BASE_EXT_STRING, &bthci_cmd_status_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_sco_pcm_routing,
            { "SCO PCM Routing",                           "bthci_vendor.broadcom.sco.pcm_routing",
            FT_UINT8, BASE_HEX, VALS(broadcom_sco_pcm_routing_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_sco_pcm_interface_clock_rate,
            { "SCO PCM Interface Clock Rate",              "bthci_vendor.broadcom.sco.interface.clock_rate",
            FT_UINT8, BASE_HEX, VALS(broadcom_sco_pcm_interface_clock_rate_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_sco_pcm_interface_frame_type,
            { "SCO PCM Interface Frame Type",              "bthci_vendor.broadcom.sco.interface.frame_type",
            FT_UINT8, BASE_HEX, VALS(broadcom_sco_pcm_interface_frame_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_sco_pcm_interface_sync_mode,
            { "SCO PCM Interface Sync Mode",               "bthci_vendor.broadcom.sco.interface.sync_mode",
            FT_UINT8, BASE_HEX, VALS(broadcom_mode_peripheral_central_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_sco_pcm_interface_clock_mode,
            { "SCO PCM Interface Clock Mode",              "bthci_vendor.broadcom.sco.interface.clock_mode",
            FT_UINT8, BASE_HEX, VALS(broadcom_mode_peripheral_central_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_pcm_shift_mode,
            { "PCM shift_mode",                           "bthci_vendor.broadcom.pcm.shift_mode",
            FT_UINT8, BASE_HEX, VALS(broadcom_pcm_shift_mode_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_pcm_fill_bits,
            { "PCM Fill Bits",                           "bthci_vendor.broadcom.pcm.fill_bits",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_pcm_fill_method,
            { "PCM Fill Method",                           "bthci_vendor.broadcom.pcm.fill_method",
            FT_UINT8, BASE_HEX, VALS(broadcom_pcm_fill_method_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_pcm_fill_number_of_bits,
            { "PCM fill_number_of_bits",                   "bthci_vendor.broadcom.pcm.fill_number_of_bits",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_pcm_justify_mode,
            { "PCM Justify Mode",                          "bthci_vendor.broadcom.pcm.justify_mode",
            FT_UINT8, BASE_HEX, VALS(broadcom_pcm_justify_mode_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_sco_i2s_pcm_interface_mode,
            { "SCO I2S PCM Interface Mode",                "bthci_vendor.broadcom.pcm.i2s_pcm_interface.mode",
            FT_UINT8, BASE_HEX, VALS(broadcom_sco_i2s_pcm_interface_mode_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_sco_i2s_pcm_interface_role,
            { "SCO I2S PCM Interface Role",                "bthci_vendor.broadcom.pcm.i2s_pcm_interface.role",
            FT_UINT8, BASE_HEX, VALS(broadcom_mode_peripheral_central_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_sco_i2s_pcm_interface_sample_rate,
            { "SCO I2S PCM Interface Sample_Rate",         "bthci_vendor.broadcom.sco.i2s_pcm_interface.sample_rate",
            FT_UINT8, BASE_HEX, VALS(broadcom_sco_i2s_pcm_interface_sample_rate_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_sco_i2s_pcm_interface_clock_rate,
            { "SCO I2S PCM Interface Clock Rate",          "bthci_vendor.broadcom.pcm.i2s_pcm_interface.clock_rate",
            FT_UINT8, BASE_HEX, VALS(broadcom_sco_i2s_pcm_interface_clock_rate_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_le_energy_total_rx_time,
            { "Total RX Time",                             "bthci_vendor.broadcom.le.total_rx_time",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_le_energy_total_tx_time,
            { "Total TX Time",                             "bthci_vendor.broadcom.le.total_tx_time",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_le_energy_total_idle_time,
            { "Total Idle Time",                           "bthci_vendor.broadcom.le.total_idle_time",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_le_energy_total_energy_used,
            { "Total Energy Used Time",                    "bthci_vendor.broadcom.le.total_energy_used",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_le_batch_scan_subcode,
            { "Subcode",                                   "bthci_vendor.broadcom.le.batch_scan.subcode",
            FT_UINT8, BASE_HEX, VALS(broadcom_le_subcode_batch_scan_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_le_batch_scan_report_format,
            { "Report Format",                             "bthci_vendor.broadcom.le.batch_scan.report_format",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_le_batch_scan_number_of_records,
            { "Number of Records",                         "bthci_vendor.broadcom.le.batch_scan.number_of_records",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_le_batch_scan_mode,
            { "Mode",                                      "bthci_vendor.broadcom.le.batch_scan.mode",
            FT_UINT8, BASE_HEX, VALS(broadcom_batch_scan_mode_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_le_batch_scan_enable,
            { "Enable",                                    "bthci_vendor.broadcom.le.batch_scan.enable",
            FT_UINT8, BASE_HEX, VALS(broadcom_disable_enable_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_le_batch_scan_full_max,
            { "Full Max",                                  "bthci_vendor.broadcom.le.batch_scan.full_max",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_le_batch_scan_truncate_max,
            { "Truncate Max",                              "bthci_vendor.broadcom.le.batch_scan.truncate_max",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_le_batch_scan_notify_threshold,
            { "notify_threshold",                         "bthci_vendor.broadcom.le.batch_scan.notify_threshold",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_le_batch_scan_window,
            { "Window",                                    "bthci_vendor.broadcom.le.batch_scan.window",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_le_batch_scan_interval,
            { "Interval",                                  "bthci_vendor.broadcom.le.batch_scan.interval",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_le_batch_scan_address_type,
            { "Address Type",                              "bthci_vendor.broadcom.le.batch_scan.address_type",
            FT_UINT8, BASE_HEX, VALS(bluetooth_address_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_le_batch_scan_discard_rule,
            { "Discard Rule",                              "bthci_vendor.broadcom.le.batch_scan.discard_rule",
            FT_UINT8, BASE_HEX, VALS(broadcom_batch_scan_discard_rule_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_le_multi_advertising_subcode,
            { "Subcode",                                   "bthci_vendor.broadcom.le.multi_advertising.subcode",
            FT_UINT8, BASE_HEX, VALS(broadcom_le_subcode_multi_advertising_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_le_multi_advertising_enable,
            { "Enable",                                    "bthci_vendor.broadcom.le.multi_advertising.enable",
            FT_UINT8, BASE_HEX, VALS(broadcom_disable_enable_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_le_multi_advertising_instance_id,
            { "Instance Id",                                  "bthci_vendor.broadcom.le.multi_advertising.instance_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_le_multi_advertising_min_interval,
            { "Min Interval",                              "bthci_vendor.broadcom.le.multi_advertising.min_interval",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_le_multi_advertising_max_interval,
            { "Max Interval",                              "bthci_vendor.broadcom.le.multi_advertising.max_interval",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_le_multi_advertising_address_type,
            { "Address Type",                              "bthci_vendor.broadcom.le.multi_advertising.address_type",
            FT_UINT8, BASE_HEX, VALS(bluetooth_address_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_le_multi_advertising_type,
          { "Type",                                        "bthci_vendor.broadcom.le.multi_advertising.type",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &bthci_cmd_eir_data_type_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_le_multi_advertising_channel_map,
            { "Channel Map",                               "bthci_vendor.broadcom.le.multi_advertising.channel_map",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_le_multi_advertising_channel_map_reserved,
            { "Reserved",                                  "bthci_vendor.broadcom.le.multi_advertising.channel_map.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xF8,
            NULL, HFILL }
        },
        { &hf_broadcom_le_multi_advertising_channel_map_39,
            { "Channel 39",                                "bthci_vendor.broadcom.le.multi_advertising.channel_map.39",
            FT_UINT8, BASE_HEX, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_broadcom_le_multi_advertising_channel_map_38,
            { "Channel 38",                                "bthci_vendor.broadcom.le.multi_advertising.channel_map.38",
            FT_UINT8, BASE_HEX, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_broadcom_le_multi_advertising_channel_map_37,
            { "Channel 37",                                "bthci_vendor.broadcom.le.multi_advertising.channel_map.37",
            FT_UINT8, BASE_HEX, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_broadcom_le_multi_advertising_filter_policy,
            { "Filter Policy",                             "bthci_vendor.broadcom.le.multi_advertising.filter_policy",
            FT_UINT8, BASE_HEX, VALS(broadcom_le_filter_policy_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_le_multi_advertising_tx_power,
            { "Tx power",                                  "bthci_vendor.broadcom.le.multi_advertising.tx_power",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_hid_emulation_mode,
            { "Emulation Mode",                            "bthci_vendor.broadcom.hid_emulation_mode",
            FT_UINT8, BASE_HEX, VALS(broadcom_hid_emulation_mode_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_vid,
            { "VID",                                       "bthci_vendor.broadcom.vid",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_pid,
            { "PID",                                       "bthci_vendor.broadcom.pid",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_chip_id,
            { "Chip ID",                                   "bthci_vendor.broadcom.chip_id",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_target_id,
            { "Target ID",                                 "bthci_vendor.broadcom.target_id",
            FT_UINT8, BASE_HEX, VALS(broadcom_target_id_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_build_base,
            { "Build Base",                                "bthci_vendor.broadcom.build_base",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_build_number,
            { "Build Number",                              "bthci_vendor.broadcom.build_number",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_data,
            { "Data",                                      "bthci_vendor.broadcom.data",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_subcode,
            { "Subcode",                                   "bthci_vendor.broadcom.a2dp_hardware_offload.subcode",
            FT_UINT8, BASE_HEX, VALS(broadcom_a2dp_hardware_offload_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_legacy_codec,
            { "Codec",                                     "bthci_vendor.broadcom.a2dp_hardware_offload.start_legacy.codec",
            FT_UINT32, BASE_HEX, VALS(broadcom_a2dp_hardware_offload_start_legacy_codec_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_legacy_max_latency,
            { "Max Latency",                               "bthci_vendor.broadcom.a2dp_hardware_offload.start_legacy.max_latency",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_legacy_scms_t_enable_flag,
            { "SCMS-T Enable",                             "bthci_vendor.broadcom.a2dp_hardware_offload.start_legacy.scms_t_enable_flag",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_legacy_scms_t_enable_value,
            { "SCMS-T Value",                              "bthci_vendor.broadcom.a2dp_hardware_offload.start_legacy.scms_t_enable_value",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_legacy_scms_t_enable_value_reserved,
            { "Reserved",                                  "bthci_vendor.broadcom.a2dp_hardware_offload.start_legacy.scms_t_enable_value_reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_legacy_sampling_frequency,
            { "Sampling Frequency",                        "bthci_vendor.broadcom.a2dp_hardware_offload.start_legacy.sampling_frequency",
            FT_UINT32, BASE_HEX, VALS(broadcom_a2dp_hardware_offload_start_legacy_sampling_frequency_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_legacy_bits_per_sample,
            { "Bits Per Sample",                           "bthci_vendor.broadcom.a2dp_hardware_offload.start_legacy.bits_per_sample",
            FT_UINT8, BASE_HEX, VALS(broadcom_a2dp_hardware_offload_start_legacy_bits_per_sample_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_legacy_channel_mode,
            { "Channel Mode",                              "bthci_vendor.broadcom.a2dp_hardware_offload.start_legacy.channel_mode",
            FT_UINT8, BASE_HEX, VALS(broadcom_a2dp_hardware_offload_start_legacy_channel_mode_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_legacy_encoded_audio_bitrate,
            { "Encoded Audio Bitrate",                     "bthci_vendor.broadcom.a2dp_hardware_offload.start_legacy.encoded_audio_bitrate",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_legacy_encoded_audio_bitrate_unspecified,
            { "Encoded Audio Bitrate Unspecified/Unused",  "bthci_vendor.broadcom.a2dp_hardware_offload.start_legacy.encoded_audio_bitrate_unspecified",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_legacy_encoded_audio_bitrate_reserved,
            { "Reserved",                                  "bthci_vendor.broadcom.a2dp_hardware_offload.start_legacy.encoded_audio_bitrate_reserved",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_legacy_connection_handle,
            { "Connection Handle",                         "bthci_vendor.broadcom.a2dp_hardware_offload.start_legacy.connection_handle",
            FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_legacy_l2cap_cid,
            { "L2CAP CID",                                 "bthci_vendor.broadcom.a2dp_hardware_offload.start_legacy.l2cap_cid",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_legacy_l2cap_mtu_size,
            { "L2CAP MTU Size",                            "bthci_vendor.broadcom.a2dp_hardware_offload.start_legacy.l2cap_mtu_size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information,
            { "Codec Information",                         "bthci_vendor.broadcom.a2dp_hardware_offload.start_legacy.codec_information",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_sbc_block_length,
          { "Block Length",                                "bthci_vendor.broadcom.a2dp_hardware_offload.start_legacy.codec_information.sbc.block_length",
            FT_UINT8, BASE_HEX, VALS(broadcom_a2dp_hardware_offload_start_legacy_codec_information_sbc_block_length_vals), 0xf0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_sbc_subbands,
          { "Subbands",                                    "bthci_vendor.broadcom.a2dp_hardware_offload.start_legacy.codec_information.sbc.subbands",
            FT_UINT8, BASE_HEX, VALS(broadcom_a2dp_hardware_offload_start_legacy_codec_information_sbc_subbands_vals), 0x0c,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_sbc_allocation_method,
          { "Allocation Method",                           "bthci_vendor.broadcom.a2dp_hardware_offload.start_legacy.codec_information.sbc.allocation_method",
            FT_UINT8, BASE_HEX, VALS(broadcom_a2dp_hardware_offload_start_legacy_codec_information_sbc_allocation_method_vals), 0x03,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_sbc_min_bitpool,
          { "Min Bitpool",                                 "bthci_vendor.broadcom.a2dp_hardware_offload.start_legacy.codec_information.sbc.min_bitpool",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_sbc_max_bitpool,
          { "Max Bitpool",                                 "bthci_vendor.broadcom.a2dp_hardware_offload.start_legacy.codec_information.sbc.max_bitpool",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_sbc_sampling_frequency,
          { "Sampling Frequency",                          "bthci_vendor.broadcom.a2dp_hardware_offload.start_legacy.codec_information.sbc.sampling_frequency",
            FT_UINT8, BASE_HEX, VALS(broadcom_a2dp_hardware_offload_start_legacy_sbc_sampling_frequency_vals), 0xf0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_sbc_channel_mode,
          { "Channel Mode",                                "bthci_vendor.broadcom.a2dp_hardware_offload.start_legacy.codec_information.sbc.channel_mode",
            FT_UINT8, BASE_HEX, VALS(broadcom_a2dp_hardware_offload_start_legacy_sbc_channel_mode_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_sbc_reserved,
          { "Reserved",                                    "bthci_vendor.broadcom.a2dp_hardware_offload.start_legacy.codec_information.sbc.reserved",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_aac_object_type,
          { "Object Type",                                 "bthci_vendor.broadcom.a2dp_hardware_offload.start_legacy.codec_information.aac.object_type",
            FT_UINT8, BASE_HEX, VALS(broadcom_a2dp_hardware_offload_start_legacy_aac_object_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_aac_vbr,
          { "VBR",                                         "bthci_vendor.broadcom.a2dp_hardware_offload.start_legacy.codec_information.aac.vbr",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_aac_reserved,
          { "Reserved",                                    "bthci_vendor.broadcom.a2dp_hardware_offload.start_legacy.codec_information.aac.reserved",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_ldac_vendor_id,
          { "Vendor ID",                                   "bthci_vendor.broadcom.a2dp_hardware_offload.start_legacy.codec_information.ldac.vendor_id",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_ldac_codec_id,
          { "Codec ID",                                    "bthci_vendor.broadcom.a2dp_hardware_offload.start_legacy.codec_information.ldac.codec_id",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_ldac_bitrate_index,
            { "Bitrate Index",                             "bthci_vendor.broadcom.a2dp_hardware_offload.start_legacy.codec_information.ldac.bitrate_index",
            FT_UINT8, BASE_HEX, VALS(broadcom_a2dp_hardware_offload_start_legacy_codec_information_ldac_bitrate_index_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_ldac_bitrate_index_reserved,
          { "Reserved",                                    "bthci_vendor.broadcom.a2dp_hardware_offload.start_legacy.codec_information.ldac.bitrate_index.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode_mask,
            { "Channel Mode",                              "bthci_vendor.broadcom.a2dp_hardware_offload.start_legacy.codec_information.ldac.channel_mode_mask",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode_mask_stereo,
          { "Stereo",                                      "bthci_vendor.broadcom.a2dp_hardware_offload.start_legacy.codec_information.ldac.channel_mode_mask.stereo",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode_mask_dual,
          { "Dual",                                         "bthci_vendor.broadcom.a2dp_hardware_offload.start_legacy.codec_information.ldac.channel_mode_mask.dual",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode_mask_mono,
          { "Mono",                                        "bthci_vendor.broadcom.a2dp_hardware_offload.start_legacy.codec_information.ldac.channel_mode_mask.mono",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode_mask_reserved,
          { "Reserved",                                    "bthci_vendor.broadcom.a2dp_hardware_offload.start_legacy.codec_information.ldac.channel_mode_mask.reserved",
            FT_UINT8, BASE_HEX, NULL, UINT32_C(0xF8),
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_legacy_codec_information_ldac_reserved,
          { "Reserved",                                    "bthci_vendor.broadcom.a2dp_hardware_offload.start_legacy.codec_information.ldac.reserved",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_connection_handle,
          { "Connection Handle",                           "bthci_vendor.broadcom.a2dp_hardware_offload.start.connection_handle",
            FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_l2cap_cid,
          { "L2CAP CID",                                   "bthci_vendor.broadcom.a2dp_hardware_offload.start.l2cap_cid",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_data_path_direction,
          { "Data Path Direction",                         "bthci_vendor.broadcom.a2dp_hardware_offload.start.data_path_direction",
            FT_UINT8, BASE_HEX, VALS(broadcom_a2dp_hardware_offload_data_path_direction_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_peer_mtu,
          { "Peer MTU",                                    "bthci_vendor.broadcom.a2dp_hardware_offload.start.peer_mtu",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_cp_enable_scmst,
          { "CP Enable SCMS-T",                            "bthci_vendor.broadcom.a2dp_hardware_offload.start.cp_enable_scmst",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_cp_header_scmst,
          { "CP Header SCMS-T",                            "bthci_vendor.broadcom.a2dp_hardware_offload.start.cp_header_scmst",
            FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_cp_header_scmst_reserved,
          { "Reserved",                                    "bthci_vendor.broadcom.a2dp_hardware_offload.start.cp_header_scmst_reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_vendor_specific_parameters_length,
          { "Vendor Specific Parameters Length",           "bthci_vendor.broadcom.a2dp_hardware_offload.start.vendor_specific_parameters_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_start_vendor_specific_parameters,
          { "Vendor Specific Parameters",                  "bthci_vendor.broadcom.a2dp_hardware_offload.start.vendor_specific_parameters",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_stop_connection_handle,
          { "Connection Handle",                           "bthci_vendor.broadcom.a2dp_hardware_offload.stop.connection_handle",
            FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_stop_l2cap_cid,
          { "L2CAP CID",                                   "bthci_vendor.broadcom.a2dp_hardware_offload.stop.l2cap_cid",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_broadcom_a2dp_hardware_offload_stop_data_path_direction,
          { "Data Path Direction",                         "bthci_vendor.broadcom.a2dp_hardware_offload.stop.data_path_direction",
            FT_UINT8, BASE_HEX, VALS(broadcom_a2dp_hardware_offload_data_path_direction_vals), 0x0,
            NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_broadcom,
        &ett_broadcom_opcode,
        &ett_broadcom_channel_map,
        &ett_broadcom_a2dp_source_offload_capability_mask,
        &ett_broadcom_dynamic_audio_buffer_support_mask,
        &ett_broadcom_a2dp_hardware_offload_start_legacy_codec_information,
        &ett_broadcom_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode_mask,
    };

    static ei_register_info ei[] = {
        { &ei_broadcom_undecoded,             { "bthci_vendor.broadcom.undecoded",            PI_UNDECODED, PI_NOTE, "Undecoded", EXPFILL }},
        { &ei_broadcom_unexpected_parameter,  { "bthci_vendor.broadcom.unexpected_parameter", PI_PROTOCOL, PI_WARN,  "Unexpected parameter", EXPFILL }},
        { &ei_broadcom_unexpected_data,       { "bthci_vendor.broadcom.unexpected_data",      PI_PROTOCOL, PI_WARN,  "Unexpected data", EXPFILL }},
    };

    proto_bthci_vendor_broadcom = proto_register_protocol("Bluetooth Broadcom HCI",
            "HCI BROADCOM", "bthci_vendor.broadcom");

    bthci_vendor_broadcom_handle = register_dissector("bthci_vendor.broadcom", dissect_bthci_vendor_broadcom, proto_bthci_vendor_broadcom);

    proto_register_field_array(proto_bthci_vendor_broadcom, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_module = expert_register_protocol(proto_bthci_vendor_broadcom);
    expert_register_field_array(expert_module, ei, array_length(ei));
}

void
proto_reg_handoff_bthci_vendor_broadcom(void)
{
    btcommon_ad_handle = find_dissector_add_dependency("btcommon.eir_ad.ad", proto_bthci_vendor_broadcom);

    dissector_add_for_decode_as("bthci_cmd.vendor", bthci_vendor_broadcom_handle);

    dissector_add_uint("bluetooth.vendor", 0x000F, bthci_vendor_broadcom_handle);
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
