/* packet-bthci_vendor.c
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
static int hf_android_le_scan_condition;
static int hf_android_le_filter_index;
static int hf_android_le_number_of_available_filters;
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
static int hf_android_a2dp_source_offload_capability_mask_reserved;
static int hf_android_bluetooth_quality_report_support;
static int hf_android_dynamic_audio_buffer_support_mask;
static int hf_android_dynamic_audio_buffer_support_mask_sbc;
static int hf_android_dynamic_audio_buffer_support_mask_aac;
static int hf_android_dynamic_audio_buffer_support_mask_aptx;
static int hf_android_dynamic_audio_buffer_support_mask_aptx_hd;
static int hf_android_dynamic_audio_buffer_support_mask_ldac;
static int hf_android_dynamic_audio_buffer_support_mask_reserved;
static int hf_android_a2dp_offload_v2_support;
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
    &hf_android_a2dp_source_offload_capability_mask_reserved,
    &hf_android_a2dp_source_offload_capability_mask_ldac,
    &hf_android_a2dp_source_offload_capability_mask_aptx_hd,
    &hf_android_a2dp_source_offload_capability_mask_aptx,
    &hf_android_a2dp_source_offload_capability_mask_aac,
    &hf_android_a2dp_source_offload_capability_mask_sbc,
    NULL
};

static int * const hfx_android_dynamic_audio_buffer_support[] = {
    &hf_android_dynamic_audio_buffer_support_mask_reserved,
    &hf_android_dynamic_audio_buffer_support_mask_ldac,
    &hf_android_dynamic_audio_buffer_support_mask_aptx_hd,
    &hf_android_dynamic_audio_buffer_support_mask_aptx,
    &hf_android_dynamic_audio_buffer_support_mask_aac,
    &hf_android_dynamic_audio_buffer_support_mask_sbc,
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
static int ett_android_a2dp_hardware_offload_start_legacy_codec_information;
static int ett_android_a2dp_hardware_offload_start_legacy_codec_information_ldac_channel_mode_mask;

static expert_field ei_android_undecoded;
static expert_field ei_android_unexpected_parameter;
static expert_field ei_android_unexpected_data;

static dissector_handle_t bthci_vendor_android_handle;
static dissector_handle_t btcommon_ad_android_handle;

#define ANDROID_OPCODE_VALS(base) \
    { (base) | 0x0153,  "LE Get Vendor Capabilities" }, \
    { (base) | 0x0154,  "LE Multi Advertising" }, \
    { (base) | 0x0156,  "LE Batch Scan" }, \
    { (base) | 0x0157,  "LE Advertising Filter" }, \
    { (base) | 0x0158,  "LE Tracking Advertising" }, \
    { (base) | 0x0159,  "LE Energy Info" }, \
    { (base) | 0x015D,  "A2DP Hardware Offload" }

static const value_string android_opcode_ocf_vals[] = {
    ANDROID_OPCODE_VALS(0x0),
    { 0, NULL }
};

static const value_string android_opcode_vals[] = {
    ANDROID_OPCODE_VALS(0x3F << 10),
    { 0, NULL }
};

static const value_string android_le_subcode_advertising_filter_vals[] = {
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

static const value_string android_le_scan_condition_vals[] = {
    { 0x00,  "Add" },
    { 0x01,  "Delete" },
    { 0x02,  "Clear" },
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

void proto_register_bthci_vendor_android(void);
void proto_reg_handoff_bthci_vendor_android(void);

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
    uint16_t           opcode;
    uint16_t           ocf;
    const char        *description;
    uint8_t            length;
    uint8_t            event_code;
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

        proto_tree_add_item(main_tree, hf_android_parameter_length, tvb, offset, 1, ENC_NA);
        length = tvb_get_uint8(tvb, offset);
        offset += 1;

        switch(ocf) {
        case 0x0154: /* LE Multi Advertising */
            proto_tree_add_item(main_tree, hf_android_le_multi_advertising_subcode, tvb, offset, 1, ENC_NA);
            subcode = tvb_get_uint8(tvb, offset);
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
                call_dissector_with_data(btcommon_ad_android_handle, tvb_new_subset_length(tvb, offset, 31), pinfo, tree, bluetooth_data);
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
            proto_tree_add_item(main_tree, hf_android_le_batch_scan_subcode, tvb, offset, 1, ENC_NA);
            subcode = tvb_get_uint8(tvb, offset);
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
        case 0x0157: /* LE Advertising Filter */
            proto_tree_add_item(main_tree, hf_android_le_advertising_filter_subcode, tvb, offset, 1, ENC_NA);
            subcode = tvb_get_uint8(tvb, offset);
            offset += 1;

            proto_tree_add_item(main_tree, hf_android_le_scan_condition, tvb, offset, 1, ENC_NA);
            condition = tvb_get_uint8(tvb, offset);
            offset += 1;

            proto_tree_add_item(main_tree, hf_android_le_filter_index, tvb, offset, 1, ENC_NA);
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
                    sub_item = proto_tree_add_item(main_tree, hf_android_data, tvb, offset, length - 3, ENC_NA);
                    expert_add_info(pinfo, sub_item, &ei_android_undecoded);
                    offset += length - 3;

                    break;
                default:
                    sub_item = proto_tree_add_item(main_tree, hf_android_data, tvb, offset, length - 3, ENC_NA);
                    expert_add_info(pinfo, sub_item, &ei_android_unexpected_data);
                    offset += length - 3;
                }
            }

            break;
        case 0x0153: /* LE Get Vendor Capabilities */
            if (tvb_captured_length_remaining(tvb, offset) > 0) {
                sub_item = proto_tree_add_item(main_tree, hf_android_data, tvb, offset, length, ENC_NA);
                expert_add_info(pinfo, sub_item, &ei_android_unexpected_parameter);
            }
            break;
        case 0x0159: /* LE Energy Info */
            if (tvb_captured_length_remaining(tvb, offset) > 0) {
                sub_item = proto_tree_add_item(main_tree, hf_android_data, tvb, offset, length, ENC_NA);
                expert_add_info(pinfo, sub_item, &ei_android_unexpected_parameter);
            }
            break;
        case 0x015D: /* A2DP Hardware Offload */
            proto_tree_add_item(main_tree, hf_android_a2dp_hardware_offload_subcode, tvb, offset, 1, ENC_NA);
            subcode = tvb_get_uint8(tvb, offset);
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
                if (tvb_captured_length_remaining(tvb, offset) > 0) {
                    sub_item = proto_tree_add_item(main_tree, hf_android_data, tvb, offset, length, ENC_NA);
                    expert_add_info(pinfo, sub_item, &ei_android_unexpected_parameter);
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
                if (tvb_captured_length_remaining(tvb, offset) > 0) {
                    sub_item = proto_tree_add_item(main_tree, hf_android_data, tvb, offset, length, ENC_NA);
                    expert_add_info(pinfo, sub_item, &ei_android_unexpected_parameter);
                }
                break;
            }

            break;
        default:
            if (length > 0) {
                sub_item = proto_tree_add_item(main_tree, hf_android_data, tvb, offset, length, ENC_NA);
                expert_add_info(pinfo, sub_item, &ei_android_undecoded);
                offset += length;
            }
        }

        break;
    case P2P_DIR_RECV:
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "HCI_EVT_ANDROID");
        col_set_str(pinfo->cinfo, COL_INFO, "Rcvd Android ");

        event_code = tvb_get_uint8(tvb, offset);
        description = val_to_str_ext(event_code, &bthci_evt_evt_code_vals_ext, "Unknown 0x%08x");
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

        proto_tree_add_item(main_tree, hf_android_parameter_length, tvb, offset, 1, ENC_NA);
        length = tvb_get_uint8(tvb, offset);
        offset += 1;

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
                if (try_val_to_str(ocf, android_opcode_ocf_vals))
                    tap_hci_summary->name = description;
                else
                    tap_hci_summary->name = NULL;
                tap_queue_packet(bluetooth_hci_summary_tap, pinfo, tap_hci_summary);
            }

            proto_tree_add_item(main_tree, hf_android_status, tvb, offset, 1, ENC_NA);
            status = tvb_get_uint8(tvb, offset);
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

                proto_tree_add_item(main_tree, hf_android_version_support, tvb, offset, 2, ENC_LITTLE_ENDIAN);
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

                if (tvb_captured_length_remaining(tvb, offset) > 0) {
                    proto_tree_add_item(main_tree, hf_android_a2dp_offload_v2_support, tvb, offset, 1, ENC_NA);
                    offset += 1;
                }

                break;
            case 0x0154: /* LE Multi Advertising */
                proto_tree_add_item(main_tree, hf_android_le_multi_advertising_subcode, tvb, offset, 1, ENC_NA);
                offset += 1;

                break;
            case 0x0156: /* LE Batch Scan */
                proto_tree_add_item(main_tree, hf_android_le_batch_scan_subcode, tvb, offset, 1, ENC_NA);
                subcode = tvb_get_uint8(tvb, offset);
                offset += 1;

                if (subcode == 0x04 && status == STATUS_SUCCESS) { /* Read Results*/
                    proto_tree_add_item(main_tree, hf_android_le_batch_scan_report_format, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    proto_tree_add_item(main_tree, hf_android_le_batch_scan_number_of_records, tvb, offset, 1, ENC_NA);
                    offset += 1;
                }


                break;
            case 0x0157: /* LE Advertising Filter */
                proto_tree_add_item(main_tree, hf_android_le_advertising_filter_subcode, tvb, offset, 1, ENC_NA);
                offset += 1;

                if (status == STATUS_SUCCESS) {
                    proto_tree_add_item(main_tree, hf_android_le_scan_condition, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    proto_tree_add_item(main_tree, hf_android_le_number_of_available_filters, tvb, offset, 1, ENC_NA);
                    offset += 1;
                }

                break;
            case 0x0159: /* LE Energy Info */
                if (status == STATUS_SUCCESS) {
                    proto_tree_add_item(main_tree, hf_android_le_energy_total_rx_time, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;

                    proto_tree_add_item(main_tree, hf_android_le_energy_total_tx_time, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;

                    proto_tree_add_item(main_tree, hf_android_le_energy_total_idle_time, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;

                    proto_tree_add_item(main_tree, hf_android_le_energy_total_energy_used, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;
                }

                break;
            case 0x015D: /* A2DP Hardware Offload */
                proto_tree_add_item(main_tree, hf_android_a2dp_hardware_offload_subcode, tvb, offset, 1, ENC_NA);
                offset += 1;

                break;
            default:
                if (length > 0) {
                    sub_item = proto_tree_add_item(main_tree, hf_android_data, tvb, offset, length, ENC_NA);
                    expert_add_info(pinfo, sub_item, &ei_android_undecoded);
                    offset += length;
                }
            }

            break;
        default:
            if (length > 0) {
                sub_item = proto_tree_add_item(main_tree, hf_android_data, tvb, offset, length, ENC_NA);
                expert_add_info(pinfo, sub_item, &ei_android_undecoded);
                offset += length;
            }
        }


        break;

    case P2P_DIR_UNKNOWN:
    default:
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "HCI_ANDROID");
        col_set_str(pinfo->cinfo, COL_INFO, "UnknownDirection Android ");

        if (tvb_captured_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(main_tree, hf_android_data, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA);
            offset += tvb_captured_length_remaining(tvb, offset);
        }
        break;
    }

    if (tvb_captured_length_remaining(tvb, offset) > 0) {
        sub_item = proto_tree_add_item(main_tree, hf_android_data, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA);
        expert_add_info(pinfo, sub_item, &ei_android_unexpected_data);
        offset += tvb_captured_length_remaining(tvb, offset);
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
            { "Subcode",                                   "bthci_vendor.android.le.advertising_filter.subcode",
            FT_UINT8, BASE_HEX, VALS(android_le_subcode_advertising_filter_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_android_le_scan_condition,
            { "Scan Condition",                            "bthci_vendor.android.le.scan_condition",
            FT_UINT8, BASE_HEX, VALS(android_le_scan_condition_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_android_le_filter_index,
            { "Filter Index",                              "bthci_vendor.android.le.filter_index",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_le_number_of_available_filters,
            { "Number of Available Filters",               "bthci_vendor.android.le.number_of_available_filters",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
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
            { "Reserved",                                  "bthci_vendor.android.max_advertising_instance_reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_resolvable_private_address_offloading,
            { "Resolvable Private Address Offloading",     "bthci_vendor.android.resolvable_private_address_offloading",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_resolvable_private_address_offloading_reserved,
            { "Reserved",                                  "bthci_vendor.android.resolvable_private_address_offloading_reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0,
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
            FT_UINT16, BASE_HEX, NULL, 0x0,
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
            { "Reserved",                                  "bthci_vendor.android.le_address_generation_offloading_support_reserved",
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
        { &hf_android_a2dp_source_offload_capability_mask_reserved,
          { "Reserved",                                    "bthci_vendor.android.a2dp_source_offload_capability_mask.reserved",
            FT_UINT32, BASE_HEX, NULL, UINT32_C(0xFFFFFFE0),
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
        { &hf_android_dynamic_audio_buffer_support_mask_reserved,
          { "Reserved",                                    "bthci_vendor.android.dynamic_audio_buffer_support_mask.reserved",
            FT_UINT32, BASE_HEX, NULL, UINT32_C(0xFFFFFFE0),
            NULL, HFILL }
        },
        { &hf_android_a2dp_offload_v2_support,
            { "A2DP Offload V2 Support",                   "bthci_vendor.android.a2dp_offload_v2_support",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_status,
          { "Status",                                      "bthci_vendor.android.status",
            FT_UINT8, BASE_HEX|BASE_EXT_STRING, &bthci_cmd_status_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_android_le_energy_total_rx_time,
            { "Total RX Time",                             "bthci_vendor.android.le.total_rx_time",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_le_energy_total_tx_time,
            { "Total TX Time",                             "bthci_vendor.android.le.total_tx_time",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_le_energy_total_idle_time,
            { "Total Idle Time",                           "bthci_vendor.android.le.total_idle_time",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_android_le_energy_total_energy_used,
            { "Total Energy Used Time",                    "bthci_vendor.android.le.total_energy_used",
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
