/* packet-btle.c
 * Routines for Bluetooth Low Energy Link Layer dissection
 * https://www.bluetooth.org/Technical/Specifications/adopted.htm
 *
 * Copyright 2013, Mike Ryan, mikeryan /at/ isecpartners /dot/ com
 * Copyright 2013, Michal Labedzki for Tieto Corporation
 * Copyright 2014, Christopher D. Kilgour, techie at whiterocker dot com
 * Copyright 2017, Stig Bjorlykke for Nordic Semiconductor
 * Copyright 2021, Thomas Sailer
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
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/reassemble.h>

#include <wiretap/wtap.h>

#include "packet-btle.h"
#include "packet-bthci_cmd.h"
#include "packet-bthci_acl.h"

static int proto_btle = -1;
static int proto_btle_rf = -1;
static int proto_nordic_ble = -1;

static int hf_access_address = -1;
static int hf_coding_indicator = -1;
static int hf_crc = -1;
static int hf_master_bd_addr = -1;
static int hf_slave_bd_addr = -1;
static int hf_length = -1;
static int hf_advertising_header = -1;
static int hf_advertising_header_pdu_type = -1;
static int hf_advertising_header_ch_sel = -1;
static int hf_advertising_header_rfu_1 = -1;
static int hf_advertising_header_rfu_2 = -1;
static int hf_advertising_header_rfu_3 = -1;
static int hf_advertising_header_rfu_4 = -1;
static int hf_advertising_header_randomized_tx = -1;
static int hf_advertising_header_randomized_rx = -1;
static int hf_advertising_header_length = -1;
static int hf_advertising_address = -1;
static int hf_initiator_addresss = -1;
static int hf_target_addresss = -1;
static int hf_scanning_address = -1;
static int hf_scan_response_data = -1;
static int hf_link_layer_data = -1;
static int hf_link_layer_data_access_address = -1;
static int hf_link_layer_data_crc_init = -1;
static int hf_link_layer_data_window_size = -1;
static int hf_link_layer_data_window_offset = -1;
static int hf_link_layer_data_interval = -1;
static int hf_link_layer_data_latency = -1;
static int hf_link_layer_data_timeout = -1;
static int hf_link_layer_data_channel_map = -1;
static int hf_link_layer_data_hop = -1;
static int hf_link_layer_data_sleep_clock_accuracy = -1;
static int hf_extended_advertising_header = -1;
static int hf_extended_advertising_header_length = -1;
static int hf_extended_advertising_mode = -1;
static int hf_extended_advertising_flags = -1;
static int hf_extended_advertising_flags_adva = -1;
static int hf_extended_advertising_flags_targeta = -1;
static int hf_extended_advertising_flags_cte_info = -1;
static int hf_extended_advertising_flags_advdatainfo = -1;
static int hf_extended_advertising_flags_aux_ptr = -1;
static int hf_extended_advertising_flags_sync_info = -1;
static int hf_extended_advertising_flags_tx_power = -1;
static int hf_extended_advertising_flags_reserved = -1;
static int hf_extended_advertising_cte_info = -1;
static int hf_extended_advertising_cte_info_time = -1;
static int hf_extended_advertising_cte_info_rfu = -1;
static int hf_extended_advertising_cte_info_type = -1;
static int hf_extended_advertising_data_info = -1;
static int hf_extended_advertising_data_info_did = -1;
static int hf_extended_advertising_data_info_sid = -1;
static int hf_extended_advertising_aux_ptr = -1;
static int hf_extended_advertising_aux_ptr_channel = -1;
static int hf_extended_advertising_aux_ptr_ca = -1;
static int hf_extended_advertising_aux_ptr_offset_units = -1;
static int hf_extended_advertising_aux_ptr_aux_offset = -1;
static int hf_extended_advertising_aux_ptr_aux_phy = -1;
static int hf_extended_advertising_sync_info = -1;
static int hf_extended_advertising_sync_info_offset = -1;
static int hf_extended_advertising_sync_info_offset_units = -1;
static int hf_extended_advertising_sync_info_offset_adjust = -1;
static int hf_extended_advertising_sync_info_reserved = -1;
static int hf_extended_advertising_sync_info_interval = -1;
static int hf_extended_advertising_sync_info_channel_map = -1;
static int hf_extended_advertising_sync_info_sleep_clock_accuracy = -1;
static int hf_extended_advertising_sync_info_access_address = -1;
static int hf_extended_advertising_sync_info_crc_init = -1;
static int hf_extended_advertising_sync_info_event_counter = -1;
static int hf_extended_advertising_tx_power = -1;
static int hf_extended_advertising_header_acad = -1;
static int hf_extended_advertising_had_fragment = -1;
static int hf_data_header = -1;
static int hf_data_header_length = -1;
static int hf_data_header_rfu = -1;
static int hf_data_header_llid = -1;
static int hf_data_header_llid_connectediso = -1;
static int hf_data_header_llid_broadcastiso = -1;
static int hf_data_header_more_data = -1;
static int hf_data_header_cte_info_present = -1;
static int hf_data_header_sequence_number = -1;
static int hf_data_header_next_expected_sequence_number = -1;
static int hf_data_header_rfu_57 = -1;
static int hf_data_header_rfu_67 = -1;
static int hf_data_header_close_isochronous_event = -1;
static int hf_data_header_null_pdu_indicator = -1;
static int hf_data_header_control_subevent_sequence_number = -1;
static int hf_data_header_control_subevent_transmission_flag = -1;
static int hf_data_header_cte_info = -1;
static int hf_data_header_cte_info_time = -1;
static int hf_data_header_cte_info_rfu = -1;
static int hf_data_header_cte_info_type = -1;
static int hf_control_opcode = -1;
static int hf_l2cap_index = -1;
static int hf_l2cap_fragment = -1;
static int hf_connection_parameters_in = -1;
static int hf_control_reject_opcode = -1;
static int hf_control_error_code = -1;
static int hf_control_unknown_type = -1;
static int hf_control_version_number = -1;
static int hf_control_company_id = -1;
static int hf_control_subversion_number = -1;
static int hf_control_feature_set = -1;
static int hf_control_feature_set_le_encryption = -1;
static int hf_control_feature_set_connection_parameters_request_procedure = -1;
static int hf_control_feature_set_extended_reject_indication = -1;
static int hf_control_feature_set_slave_initiated_features_exchange = -1;
static int hf_control_feature_set_le_ping = -1;
static int hf_control_feature_set_le_pkt_len_ext = -1;
static int hf_control_feature_set_ll_privacy = -1;
static int hf_control_feature_set_ext_scan_flt_pol = -1;
static int hf_control_feature_set_le_2m_phy = -1;
static int hf_control_feature_set_stable_modulation_index_transmitter = -1;
static int hf_control_feature_set_stable_modulation_index_receiver = -1;
static int hf_control_feature_set_le_coded_phy = -1;
static int hf_control_feature_set_le_extended_advertising = -1;
static int hf_control_feature_set_le_periodic_advertising = -1;
static int hf_control_feature_set_channel_selection_algorithm_2 = -1;
static int hf_control_feature_set_le_power_class_1 = -1;
static int hf_control_feature_set_minimum_number_of_used_channels_procedure = -1;
static int hf_control_feature_set_reserved_bits = -1;
static int hf_control_feature_set_reserved = -1;
static int hf_control_window_size = -1;
static int hf_control_window_offset = -1;
static int hf_control_interval = -1;
static int hf_control_latency = -1;
static int hf_control_timeout = -1;
static int hf_control_instant = -1;
static int hf_control_interval_min = -1;
static int hf_control_interval_max = -1;
static int hf_control_preferred_periodicity = -1;
static int hf_control_reference_connection_event_count = -1;
static int hf_control_offset_0 = -1;
static int hf_control_offset_1 = -1;
static int hf_control_offset_2 = -1;
static int hf_control_offset_3 = -1;
static int hf_control_offset_4 = -1;
static int hf_control_offset_5 = -1;
static int hf_control_channel_map = -1;
static int hf_control_random_number = -1;
static int hf_control_encrypted_diversifier = -1;
static int hf_control_master_session_key_diversifier = -1;
static int hf_control_master_session_initialization_vector = -1;
static int hf_control_slave_session_key_diversifier = -1;
static int hf_control_slave_session_initialization_vector = -1;
static int hf_control_max_rx_octets = -1;
static int hf_control_max_rx_time = -1;
static int hf_control_max_tx_octets = -1;
static int hf_control_max_tx_time = -1;
static int hf_control_phys_sender_le_1m_phy = -1;
static int hf_control_phys_sender_le_2m_phy = -1;
static int hf_control_phys_sender_le_coded_phy = -1;
static int hf_control_phys_update_le_1m_phy = -1;
static int hf_control_phys_update_le_2m_phy = -1;
static int hf_control_phys_update_le_coded_phy = -1;
static int hf_control_phys_reserved_bits = -1;
static int hf_control_tx_phys = -1;
static int hf_control_rx_phys = -1;
static int hf_control_m_to_s_phy = -1;
static int hf_control_m_to_s_phy_le_1m_phy = -1;
static int hf_control_m_to_s_phy_le_2m_phy = -1;
static int hf_control_m_to_s_phy_le_coded_phy = -1;
static int hf_control_m_to_s_phy_reserved_bits = -1;
static int hf_control_s_to_m_phy = -1;
static int hf_control_s_to_m_phy_le_1m_phy = -1;
static int hf_control_s_to_m_phy_le_2m_phy = -1;
static int hf_control_s_to_m_phy_le_coded_phy = -1;
static int hf_control_s_to_m_phy_reserved_bits = -1;
static int hf_control_phys = -1;
static int hf_control_phys_le_1m_phy = -1;
static int hf_control_phys_le_2m_phy = -1;
static int hf_control_phys_le_coded_phy = -1;
static int hf_control_min_used_channels = -1;
static int hf_control_cte_min_len_req = -1;
static int hf_control_cte_rfu = -1;
static int hf_control_cte_type_req = -1;
static int hf_control_sync_id = -1;
static int hf_control_sync_info_offset = -1;
static int hf_control_sync_info_offset_units = -1;
static int hf_control_sync_info_offset_adjust = -1;
static int hf_control_sync_info_reserved = -1;
static int hf_control_sync_info_interval = -1;
static int hf_control_sync_info_channel_map = -1;
static int hf_control_sync_info_sleep_clock_accuracy = -1;
static int hf_control_sync_info_access_address = -1;
static int hf_control_sync_info_crc_init = -1;
static int hf_control_sync_info_event_counter = -1;
static int hf_control_sync_conn_event_count = -1;
static int hf_control_sync_last_pa_event_counter = -1;
static int hf_control_sync_sid = -1;
static int hf_control_sync_atype = -1;
static int hf_control_sync_sleep_clock_accuracy = -1;
static int hf_control_sync_sync_conn_event_counter = -1;
static int hf_control_sleep_clock_accuracy = -1;
static int hf_control_cig_id = -1;
static int hf_control_cis_id = -1;
static int hf_control_max_sdu_m_to_s = -1;
static int hf_control_rfu_1 = -1;
static int hf_control_framed = -1;
static int hf_control_max_sdu_s_to_m = -1;
static int hf_control_rfu_2 = -1;
static int hf_control_sdu_interval_m_to_s = -1;
static int hf_control_rfu_3 = -1;
static int hf_control_sdu_interval_s_to_m = -1;
static int hf_control_rfu_4 = -1;
static int hf_control_max_pdu_m_to_s = -1;
static int hf_control_max_pdu_s_to_m = -1;
static int hf_control_num_sub_events = -1;
static int hf_control_sub_interval = -1;
static int hf_control_bn_m_to_s = -1;
static int hf_control_bn_s_to_m = -1;
static int hf_control_ft_m_to_s = -1;
static int hf_control_ft_s_to_m = -1;
static int hf_control_iso_interval = -1;
static int hf_control_cis_offset_min = -1;
static int hf_control_cis_offset_max = -1;
static int hf_control_conn_event_count = -1;
static int hf_control_access_address = -1;
static int hf_control_cis_offset = -1;
static int hf_control_cig_sync_delay = -1;
static int hf_control_cis_sync_delay = -1;
static int hf_control_pwr_phy = -1;
static int hf_control_pwr_phy_le_1m_phy = -1;
static int hf_control_pwr_phy_le_2m_phy = -1;
static int hf_control_pwr_phy_le_coded_s8_phy = -1;
static int hf_control_pwr_phy_le_coded_s2_phy = -1;
static int hf_control_pwr_phy_reserved_bits = -1;
static int hf_control_delta = -1;
static int hf_control_txpwr = -1;
static int hf_control_pwrflags = -1;
static int hf_control_pwrflags_min = -1;
static int hf_control_pwrflags_max = -1;
static int hf_control_pwrflags_reserved_bits = -1;
static int hf_control_acceptable_power_reduction = -1;
static int hf_big_control_opcode = -1;
static int hf_isochronous_data = -1;
static int hf_btle_l2cap_msg_fragments = -1;
static int hf_btle_l2cap_msg_fragment = -1;
static int hf_btle_l2cap_msg_fragment_overlap = -1;
static int hf_btle_l2cap_msg_fragment_overlap_conflicts = -1;
static int hf_btle_l2cap_msg_fragment_multiple_tails = -1;
static int hf_btle_l2cap_msg_fragment_too_long_fragment = -1;
static int hf_btle_l2cap_msg_fragment_error = -1;
static int hf_btle_l2cap_msg_fragment_count = -1;
static int hf_btle_l2cap_msg_reassembled_in = -1;
static int hf_btle_l2cap_msg_reassembled_length = -1;
static int hf_btle_ea_host_advertising_data_fragments = -1;
static int hf_btle_ea_host_advertising_data_fragment = -1;
static int hf_btle_ea_host_advertising_data_fragment_overlap = -1;
static int hf_btle_ea_host_advertising_data_fragment_overlap_conflicts = -1;
static int hf_btle_ea_host_advertising_data_fragment_multiple_tails = -1;
static int hf_btle_ea_host_advertising_data_fragment_too_long_fragment = -1;
static int hf_btle_ea_host_advertising_data_fragment_error = -1;
static int hf_btle_ea_host_advertising_data_fragment_count = -1;
static int hf_btle_ea_host_advertising_data_reassembled_in = -1;
static int hf_btle_ea_host_advertising_data_reassembled_length = -1;

static int hf_request_in_frame = -1;
static int hf_response_in_frame = -1;

static gint ett_btle = -1;
static gint ett_advertising_header = -1;
static gint ett_link_layer_data = -1;
static gint ett_data_header = -1;
static gint ett_data_header_cte_info = -1;
static gint ett_features = -1;
static gint ett_tx_phys = -1;
static gint ett_rx_phys = -1;
static gint ett_m_to_s_phy = -1;
static gint ett_s_to_m_phy = -1;
static gint ett_phys = -1;
static gint ett_pwr_phy = -1;
static gint ett_cte = -1;
static gint ett_channel_map = -1;
static gint ett_scan_response_data = -1;
static gint ett_pwrflags = -1;
static gint ett_btle_l2cap_msg_fragment = -1;
static gint ett_btle_l2cap_msg_fragments = -1;
static gint ett_btle_ea_host_advertising_data_fragment = -1;
static gint ett_btle_ea_host_advertising_data_fragments = -1;
static gint ett_extended_advertising_header = -1;
static gint ett_extended_advertising_flags = -1;
static gint ett_extended_advertising_cte_info = -1;
static gint ett_extended_advertising_data_info = -1;
static gint ett_extended_advertising_aux_pointer = -1;
static gint ett_extended_advertising_sync_info = -1;
static gint ett_extended_advertising_acad = -1;

static int * const hfx_extended_advertising_flags[] = {
    &hf_extended_advertising_flags_adva,
    &hf_extended_advertising_flags_targeta,
    &hf_extended_advertising_flags_cte_info,
    &hf_extended_advertising_flags_advdatainfo,
    &hf_extended_advertising_flags_aux_ptr,
    &hf_extended_advertising_flags_sync_info,
    &hf_extended_advertising_flags_tx_power,
    &hf_extended_advertising_flags_reserved,
    NULL
};

static int * const hfx_control_feature_set_1[] = {
    &hf_control_feature_set_le_encryption,
    &hf_control_feature_set_connection_parameters_request_procedure,
    &hf_control_feature_set_extended_reject_indication,
    &hf_control_feature_set_slave_initiated_features_exchange,
    &hf_control_feature_set_le_ping,
    &hf_control_feature_set_le_pkt_len_ext,
    &hf_control_feature_set_ll_privacy,
    &hf_control_feature_set_ext_scan_flt_pol,
    NULL
};

static int * const hfx_control_feature_set_2[] = {
    &hf_control_feature_set_le_2m_phy,
    &hf_control_feature_set_stable_modulation_index_transmitter,
    &hf_control_feature_set_stable_modulation_index_receiver,
    &hf_control_feature_set_le_coded_phy,
    &hf_control_feature_set_le_extended_advertising,
    &hf_control_feature_set_le_periodic_advertising,
    &hf_control_feature_set_channel_selection_algorithm_2,
    &hf_control_feature_set_le_power_class_1,
    NULL
};

static int * const hfx_control_feature_set_3[] = {
    &hf_control_feature_set_minimum_number_of_used_channels_procedure,
    &hf_control_feature_set_reserved_bits,
    NULL
};

static int * const hfx_control_phys_sender[] = {
    &hf_control_phys_sender_le_1m_phy,
    &hf_control_phys_sender_le_2m_phy,
    &hf_control_phys_sender_le_coded_phy,
    &hf_control_phys_reserved_bits,
    NULL
};

static int * const hfx_control_phys_update[] = {
    &hf_control_phys_update_le_1m_phy,
    &hf_control_phys_update_le_2m_phy,
    &hf_control_phys_update_le_coded_phy,
    &hf_control_phys_reserved_bits,
    NULL
};

static int * const hfx_control_m_to_s_phy[] = {
    &hf_control_m_to_s_phy_le_1m_phy,
    &hf_control_m_to_s_phy_le_2m_phy,
    &hf_control_m_to_s_phy_le_coded_phy,
    &hf_control_m_to_s_phy_reserved_bits,
    NULL
};

static int * const hfx_control_s_to_m_phy[] = {
    &hf_control_s_to_m_phy_le_1m_phy,
    &hf_control_s_to_m_phy_le_2m_phy,
    &hf_control_s_to_m_phy_le_coded_phy,
    &hf_control_s_to_m_phy_reserved_bits,
    NULL
};

static int * const hfx_control_phys[] = {
    &hf_control_phys_le_1m_phy,
    &hf_control_phys_le_2m_phy,
    &hf_control_phys_le_coded_phy,
    &hf_control_phys_reserved_bits,
    NULL
};

static int * const hfx_control_pwr_phy[] = {
    &hf_control_pwr_phy_le_1m_phy,
    &hf_control_pwr_phy_le_2m_phy,
    &hf_control_pwr_phy_le_coded_s8_phy,
    &hf_control_pwr_phy_le_coded_s2_phy,
    &hf_control_pwr_phy_reserved_bits,
    NULL
};

static int * const hfx_control_cte[] = {
    &hf_control_cte_min_len_req,
    &hf_control_cte_rfu,
    &hf_control_cte_type_req,
    NULL
};

static int * const hfx_control_periodicsyncflags[] = {
    &hf_control_sync_sid,
    &hf_control_sync_atype,
    &hf_control_sync_sleep_clock_accuracy,
    NULL
};

static int * const hfx_control_pwrflags[] = {
    &hf_control_pwrflags_min,
    &hf_control_pwrflags_max,
    &hf_control_pwrflags_reserved_bits,
    NULL
};

static expert_field ei_unknown_data = EI_INIT;
static expert_field ei_access_address_matched = EI_INIT;
static expert_field ei_access_address_bit_errors = EI_INIT;
static expert_field ei_access_address_illegal = EI_INIT;
static expert_field ei_crc_cannot_be_determined = EI_INIT;
static expert_field ei_crc_incorrect = EI_INIT;
static expert_field ei_missing_fragment_start = EI_INIT;
static expert_field ei_retransmit = EI_INIT;
static expert_field ei_nack = EI_INIT;
static expert_field ei_control_proc_overlapping = EI_INIT;
static expert_field ei_control_proc_invalid_collision = EI_INIT;
static expert_field ei_control_proc_wrong_seq = EI_INIT;

static dissector_handle_t btle_handle;
static dissector_handle_t btcommon_ad_handle;
static dissector_handle_t btcommon_le_channel_map_handle;
static dissector_handle_t btl2cap_handle;

static wmem_tree_t *connection_info_tree;
static wmem_tree_t *broadcastiso_connection_info_tree;
static wmem_tree_t *connection_parameter_info_tree;
static wmem_tree_t *adi_to_first_frame_tree;
static guint32 l2cap_index;

/* Reassembly */
static reassembly_table btle_l2cap_msg_reassembly_table;

static const fragment_items btle_l2cap_msg_frag_items = {
    /* Fragment subtrees */
    &ett_btle_l2cap_msg_fragment,
    &ett_btle_l2cap_msg_fragments,
    /* Fragment fields */
    &hf_btle_l2cap_msg_fragments,
    &hf_btle_l2cap_msg_fragment,
    &hf_btle_l2cap_msg_fragment_overlap,
    &hf_btle_l2cap_msg_fragment_overlap_conflicts,
    &hf_btle_l2cap_msg_fragment_multiple_tails,
    &hf_btle_l2cap_msg_fragment_too_long_fragment,
    &hf_btle_l2cap_msg_fragment_error,
    &hf_btle_l2cap_msg_fragment_count,
    /* Reassembled in field */
    &hf_btle_l2cap_msg_reassembled_in,
    /* Reassembled length field */
    &hf_btle_l2cap_msg_reassembled_length,
    /* Reassembled data field */
    NULL,
    /* Tag */
    "BTLE L2CAP fragments"
};

/* Extended Advertising Host Advertising Data Reassembly */
static reassembly_table btle_ea_host_advertising_data_reassembly_table;

static const fragment_items btle_ea_host_advertising_data_frag_items = {
    /* Fragment subtrees */
    &ett_btle_ea_host_advertising_data_fragment,
    &ett_btle_ea_host_advertising_data_fragments,
    /* Fragment fields */
    &hf_btle_ea_host_advertising_data_fragments,
    &hf_btle_ea_host_advertising_data_fragment,
    &hf_btle_ea_host_advertising_data_fragment_overlap,
    &hf_btle_ea_host_advertising_data_fragment_overlap_conflicts,
    &hf_btle_ea_host_advertising_data_fragment_multiple_tails,
    &hf_btle_ea_host_advertising_data_fragment_too_long_fragment,
    &hf_btle_ea_host_advertising_data_fragment_error,
    &hf_btle_ea_host_advertising_data_fragment_count,
    /* Reassembled in field */
    &hf_btle_ea_host_advertising_data_reassembled_in,
    /* Reassembled length field */
    &hf_btle_ea_host_advertising_data_reassembled_length,
    /* Reassembled data field */
    NULL,
    /* Tag */
    "BTLE EA HAD fragments"
};

typedef struct _ae_had_info_t {
    guint  fragment_counter;
    guint32 first_frame_num;
    address adv_addr;
} ae_had_info_t;

typedef struct _control_proc_info_t {
    /* Sequence of frame numbers of the control procedure used for request/response matching.
     * The first entry corresponds to the request, the remaining frames are responses.
     * The longest sequence is needed for the encryption start procedure,
     * which consists of 5 frames. */
    guint  frames[5];

    /* Opcode of the first control procedure packet. */
    guint8 proc_opcode;

    /* The frame where the procedure completes. Set to 0 when not yet known.
     * This is used to avoid adding another frame to the control procedure
     * sequence after the procedure was aborted early.
     *
     * This frame number may be ignored in the case where an LL_UNKNOWN_RSP is
     * received after a procedure involving only one packet, like the
     * LL_MIN_USED_CHANNELS_IND. */
    guint  last_frame;

    /* The frame number of the packet containing the instant value.
     * If set to 0, there is no such frame.
     *
     * We need to store this frame number, as any event counter is
     * a valid instant. */
    guint   frame_with_instant_value;

    /* The event counter corresponding to the instant of the control procedure. */
    guint16 instant;
} control_proc_info_t;

/* Store information about a connection direction */
typedef struct _direction_info_t {
    guint    prev_seq_num : 1;          /* Previous sequence number for this direction */
    guint    segmentation_started : 1;  /* 0 = No, 1 = Yes */
    guint    segment_len_rem;           /* The remaining segment length, used to find last segment */
    guint32  l2cap_index;               /* Unique identifier for each L2CAP message */

    wmem_tree_t *control_procs;         /* Control procedures initiated from this direction. */
} direction_info_t;

typedef struct _connection_parameter_info_t {
    guint32 parameters_frame;
} connection_parameter_info_t;

/* Store information about a connection */
typedef struct _connection_info_t {
    /* Address information */
    guint32  interface_id;
    guint32  adapter_id;
    guint32  access_address;

    guint8   master_bd_addr[6];
    guint8   slave_bd_addr[6];

    guint16  connection_parameter_update_instant;
    connection_parameter_info_t *connection_parameter_update_info;

    /* Connection information */
    /* Data used on the first pass to get info from previous frame, result will be in per_packet_data */
    guint    first_data_frame_seen : 1;
    direction_info_t direction_info[3];  /* UNKNOWN, MASTER_SLAVE and SLAVE_MASTER */
} connection_info_t;

/* Store information about a broadcast isochronous connection */
typedef struct _broadcastiso_connection_info_t {
    /* Address information */
    guint32  interface_id;
    guint32  adapter_id;
    guint32  access_address;

    guint8   master_bd_addr[6];
} broadcastiso_connection_info_t;

/* */
typedef struct _btle_frame_info_t {
    guint    retransmit : 1;      /* 0 = No, 1 = Retransmitted frame */
    guint    ack : 1;             /* 0 = Nack, 1 = Ack */
    guint    more_fragments : 1;  /* 0 = Last fragment, 1 = More fragments */
    guint    missing_start : 1;   /* 0 = No, 1 = Missing fragment start */
    guint32  l2cap_index;         /* Unique identifier for each L2CAP message */
} btle_frame_info_t;

static const value_string pdu_type_vals[] = {
    { 0x00, "ADV_IND" },
    { 0x01, "ADV_DIRECT_IND" },
    { 0x02, "ADV_NONCONN_IND" },
    { 0x03, "SCAN_REQ" },
    { 0x04, "SCAN_RSP" },
    { 0x05, "CONNECT_IND" },
    { 0x06, "ADV_SCAN_IND" },
    { 0x07, "ADV_EXT_IND" },
    { 0x08, "AUX_CONNECT_RSP" },
    { 0, NULL }
};
static value_string_ext pdu_type_vals_ext = VALUE_STRING_EXT_INIT(pdu_type_vals);

static const value_string aux_pdu_type_vals[] = {
    { 0x03, "AUX_SCAN_REQ" },
    { 0x05, "AUX_CONNECT_REQ" },
    { 0x07, "AUX_COMMON" },
    { 0x08, "AUX_CONNECT_RSP" },
    { 0, NULL}
};
static value_string_ext aux_pdu_type_vals_ext = VALUE_STRING_EXT_INIT(aux_pdu_type_vals);

static const value_string aux_pdu_common_vals[] = {
    { 0, "AUX_ADV_IND" },
    { 1, "AUX_CHAIN_IND" },
    { 2, "AUX_SYNC_IND" },
    { 3, "AUX_SCAN_RSP" },
    { 0, NULL}
};
static value_string_ext aux_pdu_common_vals_ext = VALUE_STRING_EXT_INIT(aux_pdu_common_vals);

static const value_string le_coding_indicators[] =
{
    { 0, "FEC Block 2 coded using S=8" },
    { 1, "FEC Block 2 coded using S=2" },
    { 2, "Reserved" },
    { 3, "Reserved" },
    { 0, NULL }
};

static const value_string sleep_clock_accuracy_vals[] = {
    { 0x00, "251 ppm to 500 ppm" },
    { 0x01, "151 ppm to 250 ppm" },
    { 0x02, "101 ppm to 150 ppm" },
    { 0x03, "76 ppm to 100 ppm" },
    { 0x04, "51 ppm to 75 ppm" },
    { 0x05, "31 ppm to 50 ppm" },
    { 0x06, "21 ppm to 30 ppm" },
    { 0x07, "0 ppm to 20 ppm" },
    { 0, NULL }
};
static value_string_ext sleep_clock_accuracy_vals_ext = VALUE_STRING_EXT_INIT(sleep_clock_accuracy_vals);

static const value_string llid_codes_vals[] = {
    { 0x01, "Continuation fragment of an L2CAP message, or an Empty PDU" },
    { 0x02, "Start of an L2CAP message or a complete L2CAP message with no fragmentation" },
    { 0x03, "Control PDU" },
    { 0, NULL }
};
static value_string_ext llid_codes_vals_ext = VALUE_STRING_EXT_INIT(llid_codes_vals);

static const value_string llid_connectediso_codes_vals[] = {
    { 0x00, "Unframed CIS Data PDU; end fragment of an SDU or a complete SDU" },
    { 0x01, "Unframed CIS Data PDU; start or continuation fragment of an SDU" },
    { 0x02, "Framed CIS Data PDU; one or more segments of an SDU" },
    { 0, NULL }
};
static value_string_ext llid_connectediso_codes_vals_ext = VALUE_STRING_EXT_INIT(llid_connectediso_codes_vals);

static const value_string llid_broadcastiso_codes_vals[] = {
    { 0x00, "Unframed BIS Data PDU; end fragment of an SDU or a complete SDU" },
    { 0x01, "Unframed BIS Data PDU; start or continuation fragment of an SDU" },
    { 0x02, "Framed BIS Data PDU; one or more segments of an SDU" },
    { 0x03, "BIG Control PDU" },
    { 0, NULL }
};
static value_string_ext llid_broadcastiso_codes_vals_ext = VALUE_STRING_EXT_INIT(llid_broadcastiso_codes_vals);

static const value_string control_opcode_vals[] = {
    { 0x00, "LL_CONNECTION_UPDATE_IND" },
    { 0x01, "LL_CHANNEL_MAP_IND" },
    { 0x02, "LL_TERMINATE_IND" },
    { 0x03, "LL_ENC_REQ" },
    { 0x04, "LL_ENC_RSP" },
    { 0x05, "LL_START_ENC_REQ" },
    { 0x06, "LL_START_ENC_RSP" },
    { 0x07, "LL_UNKNOWN_RSP" },
    { 0x08, "LL_FEATURE_REQ" },
    { 0x09, "LL_FEATURE_RSP" },
    { 0x0A, "LL_PAUSE_ENC_REQ" },
    { 0x0B, "LL_PAUSE_ENC_RSP" },
    { 0x0C, "LL_VERSION_IND" },
    { 0x0D, "LL_REJECT_IND" },
    { 0x0E, "LL_SLAVE_FEATURE_REQ" },
    { 0x0F, "LL_CONNECTION_PARAM_REQ" },
    { 0x10, "LL_CONNECTION_PARAM_RSP" },
    { 0x11, "LL_REJECT_EXT_IND" },
    { 0x12, "LL_PING_REQ" },
    { 0x13, "LL_PING_RSP" },
    { 0x14, "LL_LENGTH_REQ" },
    { 0x15, "LL_LENGTH_RSP" },
    { 0x16, "LL_PHY_REQ" },
    { 0x17, "LL_PHY_RSP" },
    { 0x18, "LL_PHY_UPDATE_IND" },
    { 0x19, "LL_MIN_USED_CHANNELS_IND" },
    { 0x1A, "LL_CTE_REQ" },
    { 0x1B, "LL_CTE_RSP" },
    { 0x1C, "LL_PERIODIC_SYNC_IND" },
    { 0x1D, "LL_CLOCK_ACCURACY_REQ" },
    { 0x1E, "LL_CLOCK_ACCURACY_RSP" },
    { 0x1F, "LL_CIS_REQ" },
    { 0x20, "LL_CIS_RSP" },
    { 0x21, "LL_CIS_IND" },
    { 0x22, "LL_CIS_TERMINATE_IND" },
    { 0x23, "LL_POWER_CONTROL_REQ" },
    { 0x24, "LL_POWER_CONTROL_RSP" },
    { 0x25, "LL_POWER_CHANGE_IND" },
    { 0, NULL }
};
static value_string_ext control_opcode_vals_ext = VALUE_STRING_EXT_INIT(control_opcode_vals);

static const value_string big_control_opcode_vals[] = {
    { 0x00, "BIG_CHANNEL_MAP_IND" },
    { 0x01, "BIG_TERMINATE_IND" },
    { 0, NULL }
};
static value_string_ext big_control_opcode_vals_ext = VALUE_STRING_EXT_INIT(big_control_opcode_vals);

/* Taken from https://www.bluetooth.com/specifications/assigned-numbers/link-layer/ */
static const value_string ll_version_number_vals[] = {
    { 0x06, "4.0"},
    { 0x07, "4.1" },
    { 0x08, "4.2" },
    { 0x09, "5.0" },
    { 0x0A, "5.1" },
    { 0x0B, "5.2" },
    { 0x0C, "5.3" },
    { 0, NULL }
};
static value_string_ext ll_version_number_vals_ext = VALUE_STRING_EXT_INIT(ll_version_number_vals);

static const value_string advertising_mode_vals[] = {
    { 0x00, "Non-connectable Non-scannable" },
    { 0x01, "Connectable Non-scannable" },
    { 0x02, "Non-connectable Scannable"},
    { 0x03, "Reserved for future use"},
    { 0, NULL},
};
static value_string_ext advertising_mode_vals_ext = VALUE_STRING_EXT_INIT(advertising_mode_vals);

static const value_string le_phys[] =
{
    { 0, "LE 1M"    },
    { 1, "LE 2M"    },
    { 2, "LE Coded" },
    { 3, "Reserved" },
    { 4, "Reserved" },
    { 5, "Reserved" },
    { 6, "Reserved" },
    { 7, "Reserved" },
    { 0, NULL }
};

static const value_string le_cte_type_vals[] = {
    { 0, "AoA Constant Tone Extension" },
    { 1, "AoD Constant Tone Extension with 1 usec slots" },
    { 2, "AoD Constant Tone Extension with 2 usec slots" },
    { 3, "Reserved for future use" },
    { 0, NULL }
};

static const true_false_string tfs_ca = {
    "0 ppm to 50 ppm",
    "51 ppm to 500 ppm"
};

static const true_false_string tfs_offset_units = {
    "300 usec",
    "30 usec"
};

static const true_false_string tfs_offset_adjust = {
    "Adjusted 2.4576 seconds",
    "No adjust"
};

static const true_false_string tfs_ch_sel = {
    "#2",
    "#1"
};

static const true_false_string tfs_random_public = {
    "Random",
    "Public"
};

void proto_register_btle(void);
void proto_reg_handoff_btle(void);

static gboolean btle_detect_retransmit = TRUE;

static void
btle_init(void)
{
    l2cap_index = 0;
}

/*
 * Implements Bluetooth Vol 6, Part B, Section 3.1.1 (ref Figure 3.2)
 *
 * At entry: tvb is entire BTLE packet without preamble
 *           payload_len is the Length field from the BTLE PDU header
 *           crc_init as defined in the specifications
 *
 * This implementation operates on nibbles and is therefore
 * endian-neutral.
 */
static guint32
btle_crc(tvbuff_t *tvb, const guint8 payload_len, const guint32 crc_init)
{
    static const guint16 btle_crc_next_state_flips[256] = {
        0x0000, 0x32d8, 0x196c, 0x2bb4, 0x0cb6, 0x3e6e, 0x15da, 0x2702,
        0x065b, 0x3483, 0x1f37, 0x2def, 0x0aed, 0x3835, 0x1381, 0x2159,
        0x065b, 0x3483, 0x1f37, 0x2def, 0x0aed, 0x3835, 0x1381, 0x2159,
        0x0000, 0x32d8, 0x196c, 0x2bb4, 0x0cb6, 0x3e6e, 0x15da, 0x2702,
        0x0cb6, 0x3e6e, 0x15da, 0x2702, 0x0000, 0x32d8, 0x196c, 0x2bb4,
        0x0aed, 0x3835, 0x1381, 0x2159, 0x065b, 0x3483, 0x1f37, 0x2def,
        0x0aed, 0x3835, 0x1381, 0x2159, 0x065b, 0x3483, 0x1f37, 0x2def,
        0x0cb6, 0x3e6e, 0x15da, 0x2702, 0x0000, 0x32d8, 0x196c, 0x2bb4,
        0x196c, 0x2bb4, 0x0000, 0x32d8, 0x15da, 0x2702, 0x0cb6, 0x3e6e,
        0x1f37, 0x2def, 0x065b, 0x3483, 0x1381, 0x2159, 0x0aed, 0x3835,
        0x1f37, 0x2def, 0x065b, 0x3483, 0x1381, 0x2159, 0x0aed, 0x3835,
        0x196c, 0x2bb4, 0x0000, 0x32d8, 0x15da, 0x2702, 0x0cb6, 0x3e6e,
        0x15da, 0x2702, 0x0cb6, 0x3e6e, 0x196c, 0x2bb4, 0x0000, 0x32d8,
        0x1381, 0x2159, 0x0aed, 0x3835, 0x1f37, 0x2def, 0x065b, 0x3483,
        0x1381, 0x2159, 0x0aed, 0x3835, 0x1f37, 0x2def, 0x065b, 0x3483,
        0x15da, 0x2702, 0x0cb6, 0x3e6e, 0x196c, 0x2bb4, 0x0000, 0x32d8,
        0x32d8, 0x0000, 0x2bb4, 0x196c, 0x3e6e, 0x0cb6, 0x2702, 0x15da,
        0x3483, 0x065b, 0x2def, 0x1f37, 0x3835, 0x0aed, 0x2159, 0x1381,
        0x3483, 0x065b, 0x2def, 0x1f37, 0x3835, 0x0aed, 0x2159, 0x1381,
        0x32d8, 0x0000, 0x2bb4, 0x196c, 0x3e6e, 0x0cb6, 0x2702, 0x15da,
        0x3e6e, 0x0cb6, 0x2702, 0x15da, 0x32d8, 0x0000, 0x2bb4, 0x196c,
        0x3835, 0x0aed, 0x2159, 0x1381, 0x3483, 0x065b, 0x2def, 0x1f37,
        0x3835, 0x0aed, 0x2159, 0x1381, 0x3483, 0x065b, 0x2def, 0x1f37,
        0x3e6e, 0x0cb6, 0x2702, 0x15da, 0x32d8, 0x0000, 0x2bb4, 0x196c,
        0x2bb4, 0x196c, 0x32d8, 0x0000, 0x2702, 0x15da, 0x3e6e, 0x0cb6,
        0x2def, 0x1f37, 0x3483, 0x065b, 0x2159, 0x1381, 0x3835, 0x0aed,
        0x2def, 0x1f37, 0x3483, 0x065b, 0x2159, 0x1381, 0x3835, 0x0aed,
        0x2bb4, 0x196c, 0x32d8, 0x0000, 0x2702, 0x15da, 0x3e6e, 0x0cb6,
        0x2702, 0x15da, 0x3e6e, 0x0cb6, 0x2bb4, 0x196c, 0x32d8, 0x0000,
        0x2159, 0x1381, 0x3835, 0x0aed, 0x2def, 0x1f37, 0x3483, 0x065b,
        0x2159, 0x1381, 0x3835, 0x0aed, 0x2def, 0x1f37, 0x3483, 0x065b,
        0x2702, 0x15da, 0x3e6e, 0x0cb6, 0x2bb4, 0x196c, 0x32d8, 0x0000
    };
    gint    offset = 4; /* skip AA, CRC applies over PDU */
    guint32 state = crc_init;
    guint8  bytes_to_go = 2+payload_len; /* PDU includes header and payload */
    while( bytes_to_go-- ) {
        guint8 byte   = tvb_get_guint8(tvb, offset++);
        guint8 nibble = (byte & 0xf);
        guint8 byte_index  = ((state >> 16) & 0xf0) | nibble;
        state  = ((state << 4) ^ btle_crc_next_state_flips[byte_index]) & 0xffffff;
        nibble = ((byte >> 4) & 0xf);
        byte_index  = ((state >> 16) & 0xf0) | nibble;
        state  = ((state << 4) ^ btle_crc_next_state_flips[byte_index]) & 0xffffff;
    }
    return state;
}

static const gchar * adv_pdu_type_str_get(const btle_context_t *btle_context, guint32 pdu_type)
{
    if (!btle_context || !(btle_context->channel < 37)) {
        return val_to_str_ext_const(pdu_type, &pdu_type_vals_ext, "Unknown");
    } else if (pdu_type == 0x07 && btle_context->aux_pdu_type_valid) {
        return val_to_str_ext_const(btle_context->aux_pdu_type, &aux_pdu_common_vals_ext, "Unknown");
    } else {
        return val_to_str_ext_const(pdu_type, &aux_pdu_type_vals_ext, "Unknown");
    }
}

/*
 * Reverses the bits in each byte of a 32-bit word.
 *
 * Needed because CRCs are transmitted in bit-reversed order compared
 * to the rest of the BTLE packet.  See BT spec, Vol 6, Part B,
 * Section 1.2.
 */
static guint32
reverse_bits_per_byte(const guint32 val)
{
    const guint8 nibble_rev[16] = {
        0x0, 0x8, 0x4, 0xc, 0x2, 0xa, 0x6, 0xe,
        0x1, 0x9, 0x5, 0xd, 0x3, 0xb, 0x7, 0xf
    };
    guint32 retval = 0;
    unsigned byte_index;
    for (byte_index=0; byte_index<4; byte_index++) {
        guint shiftA = byte_index*8;
        guint shiftB = shiftA+4;
        retval |= (nibble_rev[((val >> shiftA) & 0xf)] << shiftB);
        retval |= (nibble_rev[((val >> shiftB) & 0xf)] << shiftA);
    }
    return retval;
}

static gint
dissect_feature_set(tvbuff_t *tvb, proto_tree *btle_tree, gint offset)
{
    proto_item           *sub_item;
    proto_tree           *sub_tree;

    sub_item = proto_tree_add_item(btle_tree, hf_control_feature_set, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    sub_tree = proto_item_add_subtree(sub_item, ett_features);

    proto_tree_add_bitmask_list(sub_tree, tvb, offset, 1, hfx_control_feature_set_1, ENC_NA);
    offset += 1;

    proto_tree_add_bitmask_list(sub_tree, tvb, offset, 1, hfx_control_feature_set_2, ENC_NA);
    offset += 1;

    proto_tree_add_bitmask_list(sub_tree, tvb, offset, 1, hfx_control_feature_set_3, ENC_NA);
    offset += 1;

    proto_tree_add_item(sub_tree, hf_control_feature_set_reserved, tvb, offset, 5, ENC_NA);
    offset += 5;

    return offset;
}

static gint
dissect_conn_param_req_rsp(tvbuff_t *tvb, proto_tree *btle_tree, gint offset)
{
    proto_tree_add_item(btle_tree, hf_control_interval_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(btle_tree, hf_control_interval_max, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(btle_tree, hf_control_latency, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(btle_tree, hf_control_timeout, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(btle_tree, hf_control_preferred_periodicity, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    proto_tree_add_item(btle_tree, hf_control_reference_connection_event_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(btle_tree, hf_control_offset_0, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(btle_tree, hf_control_offset_1, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(btle_tree, hf_control_offset_2, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(btle_tree, hf_control_offset_3, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(btle_tree, hf_control_offset_4, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(btle_tree, hf_control_offset_5, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
}

static gint
dissect_length_req_rsp(tvbuff_t *tvb, proto_tree *btle_tree, gint offset)
{
    proto_tree_add_item(btle_tree, hf_control_max_rx_octets, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(btle_tree, hf_control_max_rx_time, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(btle_tree, hf_control_max_tx_octets, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(btle_tree, hf_control_max_tx_time, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
}

static gint
dissect_phy_req_rsp(tvbuff_t *tvb, proto_tree *btle_tree, gint offset)
{
    proto_tree_add_bitmask(btle_tree, tvb, offset, hf_control_tx_phys, ett_tx_phys, hfx_control_phys_sender, ENC_NA);
    offset += 1;

    proto_tree_add_bitmask(btle_tree, tvb, offset, hf_control_rx_phys, ett_rx_phys, hfx_control_phys_sender, ENC_NA);
    offset += 1;

    return offset;
}

static gint
dissect_periodic_sync_ind(tvbuff_t *tvb, proto_tree *btle_tree, gint offset, packet_info *pinfo, guint32 interface_id, guint32 adapter_id)
{
    guint32               sync_offset, interval;
    gint                  reserved_offset;
    guint16               sf;
    guint8                bd_addr[6];
    proto_item           *item;
    proto_item           *sub_item;
    proto_tree           *sub_tree;

    /* ID */
    proto_tree_add_item(btle_tree, hf_control_sync_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* Sync Info */
    sf = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);

    item = proto_tree_add_item_ret_uint(btle_tree, hf_control_sync_info_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN, &sync_offset);
    proto_tree_add_item(btle_tree, hf_control_sync_info_offset_units, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(btle_tree, hf_control_sync_info_offset_adjust, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(btle_tree, hf_control_sync_info_reserved, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    if (sync_offset > 0) {
        proto_item_append_text(item, " (%u usec)", sync_offset * ((sf & 0x2000) != 0 ? 300 : 30) + ((sf & 0x4000) != 0 ? 2457600 : 0));
    } else {
        proto_item_append_text(item, " Cannot be represented");
    }
    offset += 2;

    item = proto_tree_add_item_ret_uint(btle_tree, hf_control_sync_info_interval, tvb, offset, 2, ENC_LITTLE_ENDIAN, &interval);
    proto_item_append_text(item, " (%g msec)", interval * 1.25);
    offset += 2;

    sub_item = proto_tree_add_item(btle_tree, hf_control_sync_info_channel_map, tvb, offset, 5, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_channel_map);

    call_dissector_with_data(btcommon_le_channel_map_handle, tvb_new_subset_length(tvb, offset, 5), pinfo, sub_tree, &reserved_offset);
    proto_tree_add_item(btle_tree, hf_control_sync_info_sleep_clock_accuracy, tvb, reserved_offset, 1, ENC_LITTLE_ENDIAN);
    offset += 5;

    proto_tree_add_item(btle_tree, hf_control_sync_info_access_address, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(btle_tree, hf_control_sync_info_crc_init, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;

    proto_tree_add_item(btle_tree, hf_control_sync_info_event_counter, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* connEv */
    proto_tree_add_item(btle_tree, hf_control_sync_conn_event_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(btle_tree, hf_control_sync_last_pa_event_counter, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_bitmask_list(btle_tree, tvb, offset, 1, hfx_control_periodicsyncflags, ENC_NA);
    offset += 1;

    proto_tree_add_bitmask(btle_tree, tvb, offset, hf_control_phys, ett_phys, hfx_control_phys, ENC_NA);
    offset += 1;

    offset = dissect_bd_addr(hf_advertising_address, pinfo, btle_tree, tvb, offset, TRUE, interface_id, adapter_id, bd_addr);

    proto_tree_add_item(btle_tree, hf_control_sync_sync_conn_event_counter, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
}

static gint
dissect_cis_req(tvbuff_t *tvb, proto_tree *btle_tree, gint offset)
{
    guint32               interval;
    proto_item           *item;

    proto_tree_add_item(btle_tree, hf_control_cig_id, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(btle_tree, hf_control_cis_id, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_bitmask(btle_tree, tvb, offset, hf_control_m_to_s_phy, ett_m_to_s_phy, hfx_control_m_to_s_phy, ENC_NA);
    offset += 1;

    proto_tree_add_bitmask(btle_tree, tvb, offset, hf_control_s_to_m_phy, ett_s_to_m_phy, hfx_control_s_to_m_phy, ENC_NA);
    offset += 1;

    proto_tree_add_item(btle_tree, hf_control_max_sdu_m_to_s, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(btle_tree, hf_control_rfu_1, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(btle_tree, hf_control_framed, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(btle_tree, hf_control_max_sdu_s_to_m, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(btle_tree, hf_control_rfu_2, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(btle_tree, hf_control_sdu_interval_m_to_s, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(btle_tree, hf_control_rfu_3, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;

    proto_tree_add_item(btle_tree, hf_control_sdu_interval_s_to_m, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(btle_tree, hf_control_rfu_4, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;

    proto_tree_add_item(btle_tree, hf_control_max_pdu_m_to_s, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(btle_tree, hf_control_max_pdu_s_to_m, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(btle_tree, hf_control_num_sub_events, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(btle_tree, hf_control_sub_interval, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;

    proto_tree_add_item(btle_tree, hf_control_bn_m_to_s, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(btle_tree, hf_control_bn_s_to_m, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(btle_tree, hf_control_ft_m_to_s, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(btle_tree, hf_control_ft_s_to_m, tvb, offset, 1, ENC_NA);
    offset += 1;

    item = proto_tree_add_item_ret_uint(btle_tree, hf_control_iso_interval, tvb, offset, 2, ENC_LITTLE_ENDIAN, &interval);
    proto_item_append_text(item, " (%g msec)", interval * 1.25);
    offset += 2;

    proto_tree_add_item(btle_tree, hf_control_cis_offset_min, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;

    proto_tree_add_item(btle_tree, hf_control_cis_offset_max, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;

    proto_tree_add_item(btle_tree, hf_control_conn_event_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
}

static gint
dissect_cis_rsp(tvbuff_t *tvb, proto_tree *btle_tree, gint offset)
{
    proto_tree_add_item(btle_tree, hf_control_cis_offset_min, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;

    proto_tree_add_item(btle_tree, hf_control_cis_offset_max, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;

    proto_tree_add_item(btle_tree, hf_control_conn_event_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
}

static gint
dissect_cis_ind(tvbuff_t *tvb, proto_tree *btle_tree, gint offset)
{
    proto_tree_add_item(btle_tree, hf_control_access_address, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(btle_tree, hf_control_cis_offset, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;

    proto_tree_add_item(btle_tree, hf_control_cig_sync_delay, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;

    proto_tree_add_item(btle_tree, hf_control_cis_sync_delay, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;

    proto_tree_add_item(btle_tree, hf_control_conn_event_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
}

static gint
dissect_cis_terminate_ind(tvbuff_t *tvb, proto_tree *btle_tree, gint offset)
{
    proto_tree_add_item(btle_tree, hf_control_cig_id, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(btle_tree, hf_control_cis_id, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(btle_tree, hf_control_error_code, tvb, offset, 1, ENC_NA);
    offset += 1;

    return offset;
}

static gint
dissect_power_control_req(tvbuff_t *tvb, proto_tree *btle_tree, gint offset)
{
    proto_tree_add_bitmask(btle_tree, tvb, offset, hf_control_pwr_phy, ett_pwr_phy, hfx_control_pwr_phy, ENC_NA);
    offset += 1;

    proto_tree_add_item(btle_tree, hf_control_delta, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(btle_tree, hf_control_txpwr, tvb, offset, 1, ENC_NA);
    offset += 1;

    return offset;
}


static gint
dissect_power_control_rsp(tvbuff_t *tvb, proto_tree *btle_tree, gint offset)
{
    proto_tree_add_bitmask(btle_tree, tvb, offset, hf_control_pwrflags, ett_pwrflags, hfx_control_pwrflags, ENC_NA);
    offset += 1;

    proto_tree_add_item(btle_tree, hf_control_delta, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(btle_tree, hf_control_txpwr, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(btle_tree, hf_control_acceptable_power_reduction, tvb, offset, 1, ENC_NA);
    offset += 1;

    return offset;
}

static gint
dissect_power_control_ind(tvbuff_t *tvb, proto_tree *btle_tree, gint offset)
{
    proto_tree_add_bitmask(btle_tree, tvb, offset, hf_control_pwr_phy, ett_pwr_phy, hfx_control_pwr_phy, ENC_NA);
    offset += 1;

    proto_tree_add_bitmask(btle_tree, tvb, offset, hf_control_pwrflags, ett_pwrflags, hfx_control_pwrflags, ENC_NA);
    offset += 1;

    proto_tree_add_item(btle_tree, hf_control_delta, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(btle_tree, hf_control_txpwr, tvb, offset, 1, ENC_NA);
    offset += 1;

    return offset;
}

static gint
dissect_ctrl_pdu_without_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *btle_tree, gint offset)
{
    if (tvb_reported_length_remaining(tvb, offset) > 3) {
        proto_tree_add_expert(btle_tree, pinfo, &ei_unknown_data, tvb, offset, tvb_reported_length_remaining(tvb, offset) - 3);
        offset += tvb_reported_length_remaining(tvb, offset) - 3;
    }

    return offset;
}

/* Mark the start of a new control procedure.
 * At first visit it will create a new control procedure context.
 * Otherwise it will update the existing context.
 *
 * If there is already an ongoing control procedure context, control procedure
 * contexts will not be created or modified.
 *
 * It returns the procedure context in case it exists, otherwise NULL.
 */
static control_proc_info_t *
control_proc_start(tvbuff_t *tvb,
                   packet_info *pinfo,
                   proto_tree *btle_tree,
                   proto_item *control_proc_item,
                   wmem_tree_t *control_proc_tree,
                   guint8 opcode)
{
    control_proc_info_t *proc_info;
    if (!pinfo->fd->visited) {
        /* Check the if there is an existing ongoing procedure. */
        proc_info = (control_proc_info_t *)wmem_tree_lookup32_le(control_proc_tree, pinfo->num);
        if (proc_info && proc_info->last_frame == 0) {
            /* Control procedure violation - initiating new procedure before previous was complete */
            return NULL;
        } else {
            /* Create a new control procedure context. */
            proc_info = wmem_new0(wmem_file_scope(), control_proc_info_t);
            memset(proc_info, 0, sizeof(control_proc_info_t));
            proc_info->frames[0] = pinfo->num;
            proc_info->proc_opcode = opcode;
            wmem_tree_insert32(control_proc_tree, pinfo->num, proc_info);
        }
    } else {
        /* Match the responses with this request. */
        proc_info = (control_proc_info_t *)wmem_tree_lookup32(control_proc_tree, pinfo->num);

        if (proc_info && proc_info->proc_opcode == opcode) {
            proto_item *sub_item;
            for (guint i = 1; i < sizeof(proc_info->frames)/sizeof(proc_info->frames[0]); i++) {
                if (proc_info->frames[i]) {
                    sub_item = proto_tree_add_uint(btle_tree, hf_response_in_frame, tvb, 0, 0, proc_info->frames[i]);
                    proto_item_set_generated(sub_item);
                }
            }
        } else {
            /* The found control procedure does not match the last one.
             * This indicates a protocol violation. */
            expert_add_info(pinfo, control_proc_item, &ei_control_proc_overlapping);

            return NULL;
        }
    }

    return proc_info;
}

/* Checks if it is possible to add the frame at the given index
 * to the given control procedure context.
 *
 * It does not care if the procedure is already marked as completed.
 * Therefore this function can be used to add an LL_UNKNOWN_RSP to
 * a completed connection parameter update procedure.
 */
static gboolean
control_proc_can_add_frame_even_if_complete(packet_info *pinfo,
                                            control_proc_info_t *last_control_proc_info,
                                            guint8 proc_opcode,
                                            guint frame_num)
{
    if (frame_num == 0)
        return FALSE; /* This function must be used to add a frame to an ongoing procedure */

    /* We need to check if the control procedure has been initiated. */
    if (!last_control_proc_info)
        return FALSE;

    /* And that the new frame belongs to this control procedure */
    if (last_control_proc_info->proc_opcode != proc_opcode)
        return FALSE;

    /* Previous frame has not yet been added. */
    if (last_control_proc_info->frames[frame_num - 1] == 0)
        return FALSE;

    /* We need to check if we can add this frame at this index
     * in the control procedure sequence. */

    /* The first time we visit the frame, we just need to check that the
     * spot is empty. */
    if (!pinfo->fd->visited && last_control_proc_info->frames[frame_num])
        return FALSE; /* Another opcode has already been added to the procedure at this index */

    /* At later visits, we need to check that we are not replacing the frame with
     * another frame. */
    if (pinfo->fd->visited && (last_control_proc_info->frames[frame_num] != pinfo->num))
        return FALSE;

    return TRUE;
}

static gboolean
control_proc_is_complete(guint32 frame_num, control_proc_info_t const *last_control_proc_info)
{
    if (last_control_proc_info->last_frame != 0 &&
        frame_num > last_control_proc_info->last_frame)
        return TRUE;

    return FALSE;
}

static gboolean
control_proc_can_add_frame(packet_info *pinfo,
                           control_proc_info_t *last_control_proc_info,
                           guint8 proc_opcode,
                           guint frame_num)
{
    if (!control_proc_can_add_frame_even_if_complete(pinfo,
                                                     last_control_proc_info,
                                                     proc_opcode,
                                                     frame_num))
        return FALSE;

    /* We check that we are not adding a frame to a completed procedure. */
    if (control_proc_is_complete(pinfo->num, last_control_proc_info))
        return FALSE;

    return TRUE;
}

static void
control_proc_complete_if_instant_reached(guint frame_num,
                                         guint16 event_counter,
                                         control_proc_info_t *last_control_proc_info)
{
    /* We need to check if the control procedure has been initiated. */
    if (!last_control_proc_info)
        return;

    if (control_proc_is_complete(frame_num, last_control_proc_info))
        return;

    /* The instant can only be reached if the current frame is after
     * the one containing the instant value. */
    if ((last_control_proc_info->frame_with_instant_value == 0)||
        (frame_num < last_control_proc_info->frame_with_instant_value))
        return;

    if (last_control_proc_info->instant == event_counter) {
        /* Frame matches event counter, mark procedure as complete. */
        last_control_proc_info->last_frame = frame_num;
    }
}

static gboolean
control_proc_contains_instant(guint8 proc_opcode)
{
    switch (proc_opcode)
    {
        case 0x00: /* LL_CONNECTION_UPDATE_IND */
        case 0x01: /* LL_CHANNEL_MAP_UPDATE_IND */
        case 0x0F: /* LL_CONNECTION_PARAM_REQ */
        case 0x16: /* LL_PHY_REQ */
            return TRUE;
        default:
            return FALSE;
    }
}

/* Returns true if this frame contains an collision violating the specification.
 *
 * See Core_v5.2, Vol 6, Part B, Section 5.3 */
static gboolean
control_proc_invalid_collision(packet_info const *pinfo,
                               control_proc_info_t const *control_proc_other,
                               guint8 proc_opcode)
{
    if (!control_proc_other)
        return FALSE;

    if (control_proc_is_complete(pinfo->num, control_proc_other))
        return FALSE;

    /* Both procedures must contain an instant to be marked as incompatible. */
    if (!control_proc_contains_instant(control_proc_other->proc_opcode) ||
        !control_proc_contains_instant(proc_opcode))
        return FALSE;

    /* From the Core Spec:
     *
     * If the peer has already sent at least one PDU as part of procedure A, the
     * device should immediately exit the Connection State and transition to the
     * Standby State.
     *
     * That is, if there exists are response in the other procedure at this point in
     * time, there is a procedure violation.
     */
    if (control_proc_other->frames[1] < pinfo->num)
        return TRUE;
    else
        return FALSE;
}

static void
dissect_ad_eir(tvbuff_t *tvb, guint32 interface_id, guint32 adapter_id, guint32 frame_number, guint8 *src_bd_addr, packet_info *pinfo, proto_tree *tree)
{
    bluetooth_eir_ad_data_t *ad_data = wmem_new0(pinfo->pool, bluetooth_eir_ad_data_t);
    ad_data->interface_id = interface_id;
    ad_data->adapter_id = adapter_id;
    call_dissector_with_data(btcommon_ad_handle, tvb, pinfo, tree, ad_data);
    if (pinfo->fd->visited)
        return;
    for (gint offset = 0;; ) {
        guint remain = tvb_reported_length_remaining(tvb, offset);
        guint length;
        guint8 opcode;
        if (remain < 1)
            break;
        length = tvb_get_guint8(tvb, offset);
        ++offset;
        if (length <= 0)
            continue;
        --remain;
        if (remain < length)
            break;
        opcode = tvb_get_guint8(tvb, offset);
        if (opcode == 0x2c && length >= 34) {
            guint seed_access_address = tvb_get_guint32(tvb, offset + 14, ENC_LITTLE_ENDIAN);
            guint32 trunc_seed_access_address = seed_access_address & 0x0041ffff;
            broadcastiso_connection_info_t *nconnection_info;
            wmem_tree_key_t key[5];

            key[0].length = 1;
            key[0].key = &interface_id;
            key[1].length = 1;
            key[1].key = &adapter_id;
            key[2].length = 1;
            key[2].key = &trunc_seed_access_address;
            key[3].length = 1;
            key[3].key = &frame_number;
            key[4].length = 0;
            key[4].key = NULL;

            nconnection_info = wmem_new0(wmem_file_scope(), broadcastiso_connection_info_t);
            nconnection_info->interface_id   = interface_id;
            nconnection_info->adapter_id     = adapter_id;
            nconnection_info->access_address = seed_access_address;

            if (src_bd_addr)
                memcpy(nconnection_info->master_bd_addr, src_bd_addr, 6);

            wmem_tree_insert32_array(broadcastiso_connection_info_tree, key, nconnection_info);
        }
        offset += length;
    }
}

static gint
dissect_btle(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item           *btle_item;
    proto_tree           *btle_tree;
    proto_item           *sub_item;
    proto_tree           *sub_tree;
    gint                  offset = 0;
    guint32               access_address, length;
    tvbuff_t              *next_tvb;
    guint8                *dst_bd_addr;
    guint8                *src_bd_addr;
    static const guint8    broadcast_addr[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    connection_info_t     *connection_info = NULL;
    wmem_tree_t           *wmem_tree;
    wmem_tree_key_t        key[5], ae_had_key[4];
    guint32                interface_id;
    guint32                adapter_id;
    guint32                connection_access_address;
    guint32                frame_number;
    enum {CRC_INDETERMINATE,
          CRC_CAN_BE_CALCULATED,
          CRC_INCORRECT,
          CRC_CORRECT} crc_status = CRC_INDETERMINATE;
    guint32      crc_init = 0x555555; /* default to advertising channel's value */
    guint32      packet_crc;
    const btle_context_t  *btle_context   = NULL;
    bluetooth_data_t      *bluetooth_data = NULL;
    ubertooth_data_t      *ubertooth_data = NULL;
    gint                   previous_proto;
    wmem_list_frame_t     *list_data;
    proto_item            *item;
    guint                  item_value;
    guint8                 btle_pdu_type = BTLE_PDU_TYPE_UNKNOWN;

    list_data = wmem_list_frame_prev(wmem_list_tail(pinfo->layers));
    if (list_data) {
        previous_proto = GPOINTER_TO_INT(wmem_list_frame_data(list_data));

        if ((previous_proto == proto_btle_rf)||(previous_proto == proto_nordic_ble)) {
            btle_context = (const btle_context_t *) data;
            bluetooth_data = btle_context->previous_protocol_data.bluetooth_data;
        } else if (previous_proto == proto_bluetooth) {
            bluetooth_data = (bluetooth_data_t *) data;
        }

        if (bluetooth_data && bluetooth_data->previous_protocol_data_type == BT_PD_UBERTOOTH_DATA) {
            ubertooth_data = bluetooth_data->previous_protocol_data.ubertooth_data;
        }
    }

    src_bd_addr = (guint8 *) wmem_alloc(pinfo->pool, 6);
    dst_bd_addr = (guint8 *) wmem_alloc(pinfo->pool, 6);

    if (btle_context && btle_context->crc_checked_at_capture) {
        crc_status = btle_context->crc_valid_at_capture ? CRC_CORRECT : CRC_INCORRECT;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LE LL");

    btle_item = proto_tree_add_item(tree, proto_btle, tvb, offset, -1, ENC_NA);
    btle_tree = proto_item_add_subtree(btle_item, ett_btle);

    sub_item = proto_tree_add_item(btle_tree, hf_access_address, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    access_address = tvb_get_letohl(tvb, offset);
    if (btle_context) {
        switch(btle_context->aa_category) {
        case E_AA_MATCHED:
            expert_add_info(pinfo, sub_item, &ei_access_address_matched);
            break;
        case E_AA_ILLEGAL:
            expert_add_info(pinfo, sub_item, &ei_access_address_illegal);
            break;
        case E_AA_BIT_ERRORS:
            expert_add_info(pinfo, sub_item, &ei_access_address_bit_errors);
            break;
        default:
            break;
        }
    }
    offset += 4;

    if (btle_context && btle_context->phy == LE_CODED_PHY) {
        proto_tree_add_item(btle_tree, hf_coding_indicator, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
    }

    if (bluetooth_data)
        interface_id = bluetooth_data->interface_id;
    else if (pinfo->rec->presence_flags & WTAP_HAS_INTERFACE_ID)
        interface_id = pinfo->rec->rec_header.packet_header.interface_id;
    else
        interface_id = HCI_INTERFACE_DEFAULT;

    if (ubertooth_data)
        adapter_id = ubertooth_data->bus_id << 8 | ubertooth_data->device_address;
    else if (bluetooth_data)
        adapter_id = bluetooth_data->adapter_id;
    else
        adapter_id = HCI_ADAPTER_DEFAULT;

    frame_number = pinfo->num;

    if (btle_context) {
        btle_pdu_type = btle_context->pdu_type;
    }

    if (btle_pdu_type == BTLE_PDU_TYPE_UNKNOWN) {
        /* No context to provide us with physical channel pdu type, make an assumption from the access address */
        btle_pdu_type = access_address == ACCESS_ADDRESS_ADVERTISING ? BTLE_PDU_TYPE_ADVERTISING : BTLE_PDU_TYPE_DATA;
    }

    if (btle_pdu_type == BTLE_PDU_TYPE_ADVERTISING) {
        proto_item  *advertising_header_item;
        proto_tree  *advertising_header_tree;
        proto_item  *link_layer_data_item;
        proto_tree  *link_layer_data_tree;
        guint8       header, pdu_type;
        gboolean     ch_sel_valid = FALSE, tx_add_valid = FALSE, rx_add_valid = FALSE;

        if (crc_status == CRC_INDETERMINATE) {
            /* Advertising channel CRCs can aways be calculated, because CRCInit is always known. */
            crc_status = CRC_CAN_BE_CALCULATED;
        }

        key[0].length = 1;
        key[0].key = &interface_id;
        key[1].length = 1;
        key[1].key = &adapter_id;
        key[2].length = 1;
        key[2].key = &access_address;
        key[3].length = 0;
        key[3].key = NULL;

        wmem_tree = (wmem_tree_t *) wmem_tree_lookup32_array(connection_info_tree, key);
        if (wmem_tree) {
            connection_info = (connection_info_t *) wmem_tree_lookup32_le(wmem_tree, pinfo->num);
            if (connection_info) {
                set_address(&pinfo->net_src, AT_ETHER, 6, connection_info->master_bd_addr);
                copy_address_shallow(&pinfo->dl_src, &pinfo->net_src);
                copy_address_shallow(&pinfo->src, &pinfo->net_src);
                memcpy(src_bd_addr, connection_info->master_bd_addr, 6);
            }
        }

        advertising_header_item = proto_tree_add_item(btle_tree, hf_advertising_header, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        advertising_header_tree = proto_item_add_subtree(advertising_header_item, ett_advertising_header);

        header = tvb_get_guint8(tvb, offset);
        pdu_type = header & 0x0F;

        switch (pdu_type) {
        case 0x00: /* ADV_IND */
            ch_sel_valid = TRUE;
            /* Fallthrough */
        case 0x02: /* ADV_NONCONN_IND */
        case 0x06: /* ADV_SCAN_IND */
        case 0x04: /* SCAN_RSP */
            tx_add_valid = TRUE;
            break;
        case 0x07: /* ADV_EXT_IND / AUX_ADV_IND / AUX_SYNC_IND / AUX_CHAIN_IND / AUX_SCAN_RSP */
        case 0x08: /* AUX_CONNECT_RSP */
        {
            /* 0 + header, 1 = len, 2 = ext_len/adv-mode, 3 = flags */
            guint8 ext_header_flags = tvb_get_guint8(tvb, offset + 3);

            ch_sel_valid = FALSE;
            tx_add_valid = (ext_header_flags & 0x01) != 0;
            rx_add_valid = (ext_header_flags & 0x02) != 0;
            break;
        }
        case 0x01: /* ADV_DIRECT_IND */
        case 0x05: /* CONNECT_IND or AUX_CONNECT_REQ */
            if (btle_context && btle_context->channel >= 37) {
                /* CONNECT_IND */
                ch_sel_valid = TRUE;
            }
            /* Fallthrough */
        case 0x03: /* SCAN_REQ or AUX_SCAN_REQ */
            tx_add_valid = TRUE;
            rx_add_valid = TRUE;
            break;
        }

        proto_item_append_text(advertising_header_item, " (PDU Type: %s", adv_pdu_type_str_get(btle_context, pdu_type));
        item = proto_tree_add_item(advertising_header_tree, hf_advertising_header_pdu_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_item_append_text(item, " %s", adv_pdu_type_str_get(btle_context, pdu_type));
        proto_tree_add_item(advertising_header_tree, hf_advertising_header_rfu_1, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        if (ch_sel_valid) {
            proto_item_append_text(advertising_header_item, ", ChSel: %s",
                                   tfs_get_string(header & 0x20, &tfs_ch_sel));
            proto_tree_add_item(advertising_header_tree, hf_advertising_header_ch_sel, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        } else {
            proto_tree_add_item(advertising_header_tree, hf_advertising_header_rfu_2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        }

        if (tx_add_valid) {
            proto_item_append_text(advertising_header_item, ", TxAdd: %s",
                                   tfs_get_string(header & 0x40, &tfs_random_public));
            proto_tree_add_item(advertising_header_tree, hf_advertising_header_randomized_tx, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        } else {
            proto_tree_add_item(advertising_header_tree, hf_advertising_header_rfu_3, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        }

        if (rx_add_valid) {
            proto_item_append_text(advertising_header_item, ", RxAdd: %s",
                                   tfs_get_string(header & 0x80, &tfs_random_public));
            proto_tree_add_item(advertising_header_tree, hf_advertising_header_randomized_rx, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        } else {
            proto_tree_add_item(advertising_header_tree, hf_advertising_header_rfu_4, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        }

        proto_item_append_text(advertising_header_item, ")");

        col_set_str(pinfo->cinfo, COL_INFO, adv_pdu_type_str_get(btle_context, pdu_type));

        offset += 1;

        proto_tree_add_item(advertising_header_tree, hf_advertising_header_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        item = proto_tree_add_item_ret_uint(btle_tree, hf_length, tvb, offset, 1, ENC_LITTLE_ENDIAN, &length);
        proto_item_set_hidden(item);
        offset += 1;

        switch (pdu_type) {
        case 0x00: /* ADV_IND */
        case 0x02: /* ADV_NONCONN_IND */
        case 0x06: /* ADV_SCAN_IND */
            offset = dissect_bd_addr(hf_advertising_address, pinfo, btle_tree, tvb, offset, TRUE, interface_id, adapter_id, src_bd_addr);

            set_address(&pinfo->net_src, AT_ETHER, 6, src_bd_addr);
            copy_address_shallow(&pinfo->dl_src, &pinfo->net_src);
            copy_address_shallow(&pinfo->src, &pinfo->net_src);

            set_address(&pinfo->net_dst, AT_ETHER, 6, broadcast_addr);
            copy_address_shallow(&pinfo->dl_dst, &pinfo->net_dst);
            copy_address_shallow(&pinfo->dst, &pinfo->net_dst);

            if (!pinfo->fd->visited) {
                address *addr;

                addr = (address *) wmem_memdup(wmem_file_scope(), &pinfo->dl_src, sizeof(address));
                addr->data =  wmem_memdup(wmem_file_scope(), pinfo->dl_src.data, pinfo->dl_src.len);
                p_add_proto_data(wmem_file_scope(), pinfo, proto_bluetooth, BLUETOOTH_DATA_SRC, addr);

                addr = (address *) wmem_memdup(wmem_file_scope(), &pinfo->dl_dst, sizeof(address));
                addr->data =  wmem_memdup(wmem_file_scope(), pinfo->dl_dst.data, pinfo->dl_dst.len);
                p_add_proto_data(wmem_file_scope(), pinfo, proto_bluetooth, BLUETOOTH_DATA_DST, addr);
            }

            if (tvb_reported_length_remaining(tvb, offset) > 3) {
                next_tvb = tvb_new_subset_length(tvb, offset, tvb_reported_length_remaining(tvb, offset) - 3);
                dissect_ad_eir(next_tvb, interface_id, adapter_id, frame_number, src_bd_addr, pinfo, btle_tree);
            }

            offset += tvb_reported_length_remaining(tvb, offset) - 3;

            break;
        case 0x01: /* ADV_DIRECT_IND */
            offset = dissect_bd_addr(hf_advertising_address, pinfo, btle_tree, tvb, offset, TRUE, interface_id, adapter_id, src_bd_addr);
            offset = dissect_bd_addr(hf_target_addresss, pinfo, btle_tree, tvb, offset, FALSE, interface_id, adapter_id, dst_bd_addr);

            set_address(&pinfo->net_src, AT_ETHER, 6, src_bd_addr);
            copy_address_shallow(&pinfo->dl_src, &pinfo->net_src);
            copy_address_shallow(&pinfo->src, &pinfo->net_src);

            set_address(&pinfo->net_dst, AT_ETHER, 6, dst_bd_addr);
            copy_address_shallow(&pinfo->dl_dst, &pinfo->net_dst);
            copy_address_shallow(&pinfo->dst, &pinfo->net_dst);

            if (!pinfo->fd->visited) {
                address *addr;

                addr = (address *) wmem_memdup(wmem_file_scope(), &pinfo->dl_src, sizeof(address));
                addr->data =  wmem_memdup(wmem_file_scope(), pinfo->dl_src.data, pinfo->dl_src.len);
                p_add_proto_data(wmem_file_scope(), pinfo, proto_bluetooth, BLUETOOTH_DATA_SRC, addr);

                addr = (address *) wmem_memdup(wmem_file_scope(), &pinfo->dl_dst, sizeof(address));
                addr->data =  wmem_memdup(wmem_file_scope(), pinfo->dl_dst.data, pinfo->dl_dst.len);
                p_add_proto_data(wmem_file_scope(), pinfo, proto_bluetooth, BLUETOOTH_DATA_DST, addr);
            }

            break;
        case 0x03: /* SCAN_REQ */
            offset = dissect_bd_addr(hf_scanning_address, pinfo, btle_tree, tvb, offset, TRUE, interface_id, adapter_id, src_bd_addr);
            offset = dissect_bd_addr(hf_advertising_address, pinfo, btle_tree, tvb, offset, FALSE, interface_id, adapter_id, dst_bd_addr);

            set_address(&pinfo->net_src, AT_ETHER, 6, src_bd_addr);
            copy_address_shallow(&pinfo->dl_src, &pinfo->net_src);
            copy_address_shallow(&pinfo->src, &pinfo->net_src);

            set_address(&pinfo->net_dst, AT_ETHER, 6, dst_bd_addr);
            copy_address_shallow(&pinfo->dl_dst, &pinfo->net_dst);
            copy_address_shallow(&pinfo->dst, &pinfo->net_dst);

            if (!pinfo->fd->visited) {
                address *addr;

                addr = (address *) wmem_memdup(wmem_file_scope(), &pinfo->dl_src, sizeof(address));
                addr->data =  wmem_memdup(wmem_file_scope(), pinfo->dl_src.data, pinfo->dl_src.len);
                p_add_proto_data(wmem_file_scope(), pinfo, proto_bluetooth, BLUETOOTH_DATA_SRC, addr);

                addr = (address *) wmem_memdup(wmem_file_scope(), &pinfo->dl_dst, sizeof(address));
                addr->data =  wmem_memdup(wmem_file_scope(), pinfo->dl_dst.data, pinfo->dl_dst.len);
                p_add_proto_data(wmem_file_scope(), pinfo, proto_bluetooth, BLUETOOTH_DATA_DST, addr);
            }

            break;
        case 0x04: /* SCAN_RSP */
            offset = dissect_bd_addr(hf_advertising_address, pinfo, btle_tree, tvb, offset, TRUE, interface_id, adapter_id, src_bd_addr);

            set_address(&pinfo->net_src, AT_ETHER, 6, src_bd_addr);
            copy_address_shallow(&pinfo->dl_src, &pinfo->net_src);
            copy_address_shallow(&pinfo->src, &pinfo->net_src);

            set_address(&pinfo->net_dst, AT_ETHER, 6, broadcast_addr);
            copy_address_shallow(&pinfo->dl_dst, &pinfo->net_dst);
            copy_address_shallow(&pinfo->dst, &pinfo->net_dst);

            if (!pinfo->fd->visited) {
                address *addr;

                addr = (address *) wmem_memdup(wmem_file_scope(), &pinfo->dl_src, sizeof(address));
                addr->data =  wmem_memdup(wmem_file_scope(), pinfo->dl_src.data, pinfo->dl_src.len);
                p_add_proto_data(wmem_file_scope(), pinfo, proto_bluetooth, BLUETOOTH_DATA_SRC, addr);

                addr = (address *) wmem_memdup(wmem_file_scope(), &pinfo->dl_dst, sizeof(address));
                addr->data =  wmem_memdup(wmem_file_scope(), pinfo->dl_dst.data, pinfo->dl_dst.len);
                p_add_proto_data(wmem_file_scope(), pinfo, proto_bluetooth, BLUETOOTH_DATA_DST, addr);
            }

            sub_item = proto_tree_add_item(btle_tree, hf_scan_response_data, tvb, offset, tvb_reported_length_remaining(tvb, offset) - 3, ENC_NA);
            sub_tree = proto_item_add_subtree(sub_item, ett_scan_response_data);

            if (tvb_reported_length_remaining(tvb, offset) > 3) {
                next_tvb = tvb_new_subset_length(tvb, offset, tvb_reported_length_remaining(tvb, offset) - 3);
                dissect_ad_eir(next_tvb, interface_id, adapter_id, frame_number, src_bd_addr, pinfo, sub_tree);
            }

            offset += tvb_reported_length_remaining(tvb, offset) - 3;

            break;
        case 0x05: /* CONNECT_IND */
            offset = dissect_bd_addr(hf_initiator_addresss, pinfo, btle_tree, tvb, offset, FALSE, interface_id, adapter_id, src_bd_addr);
            offset = dissect_bd_addr(hf_advertising_address, pinfo, btle_tree, tvb, offset, TRUE, interface_id, adapter_id, dst_bd_addr);

            set_address(&pinfo->net_src, AT_ETHER, 6, src_bd_addr);
            copy_address_shallow(&pinfo->dl_src, &pinfo->net_src);
            copy_address_shallow(&pinfo->src, &pinfo->net_src);

            set_address(&pinfo->net_dst, AT_ETHER, 6, dst_bd_addr);
            copy_address_shallow(&pinfo->dl_dst, &pinfo->net_dst);
            copy_address_shallow(&pinfo->dst, &pinfo->net_dst);

            if (!pinfo->fd->visited) {
                address *addr;

                addr = (address *) wmem_memdup(wmem_file_scope(), &pinfo->dl_src, sizeof(address));
                addr->data =  wmem_memdup(wmem_file_scope(), pinfo->dl_src.data, pinfo->dl_src.len);
                p_add_proto_data(wmem_file_scope(), pinfo, proto_bluetooth, BLUETOOTH_DATA_SRC, addr);

                addr = (address *) wmem_memdup(wmem_file_scope(), &pinfo->dl_dst, sizeof(address));
                addr->data =  wmem_memdup(wmem_file_scope(), pinfo->dl_dst.data, pinfo->dl_dst.len);
                p_add_proto_data(wmem_file_scope(), pinfo, proto_bluetooth, BLUETOOTH_DATA_DST, addr);
            }

            link_layer_data_item = proto_tree_add_item(btle_tree, hf_link_layer_data, tvb, offset, 22, ENC_NA);
            link_layer_data_tree = proto_item_add_subtree(link_layer_data_item, ett_link_layer_data);

            proto_tree_add_item(link_layer_data_tree, hf_link_layer_data_access_address, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            connection_access_address = tvb_get_letohl(tvb, offset);
            offset += 4;

            proto_tree_add_item(link_layer_data_tree, hf_link_layer_data_crc_init, tvb, offset, 3, ENC_LITTLE_ENDIAN);
            offset += 3;

            item = proto_tree_add_item_ret_uint(link_layer_data_tree, hf_link_layer_data_window_size, tvb, offset, 1, ENC_LITTLE_ENDIAN, &item_value);
            proto_item_append_text(item, " (%g msec)", item_value*1.25);
            offset += 1;

            item = proto_tree_add_item_ret_uint(link_layer_data_tree, hf_link_layer_data_window_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN, &item_value);
            proto_item_append_text(item, " (%g msec)", item_value*1.25);
            offset += 2;

            item = proto_tree_add_item_ret_uint(link_layer_data_tree, hf_link_layer_data_interval, tvb, offset, 2, ENC_LITTLE_ENDIAN, &item_value);
            proto_item_append_text(item, " (%g msec)", item_value*1.25);
            offset += 2;

            proto_tree_add_item(link_layer_data_tree, hf_link_layer_data_latency, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            item = proto_tree_add_item_ret_uint(link_layer_data_tree, hf_link_layer_data_timeout, tvb, offset, 2, ENC_LITTLE_ENDIAN, &item_value);
            proto_item_append_text(item, " (%u msec)", item_value*10);
            offset += 2;

            sub_item = proto_tree_add_item(link_layer_data_tree, hf_link_layer_data_channel_map, tvb, offset, 5, ENC_NA);
            sub_tree = proto_item_add_subtree(sub_item, ett_channel_map);

            call_dissector(btcommon_le_channel_map_handle, tvb_new_subset_length(tvb, offset, 5), pinfo, sub_tree);
            offset += 5;

            proto_tree_add_item(link_layer_data_tree, hf_link_layer_data_hop, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(link_layer_data_tree, hf_link_layer_data_sleep_clock_accuracy, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            if (!pinfo->fd->visited) {
                connection_parameter_info_t *connection_parameter_info;

                key[0].length = 1;
                key[0].key = &interface_id;
                key[1].length = 1;
                key[1].key = &adapter_id;
                key[2].length = 1;
                key[2].key = &connection_access_address;
                key[3].length = 1;
                key[3].key = &frame_number;
                key[4].length = 0;
                key[4].key = NULL;

                connection_info = wmem_new0(wmem_file_scope(), connection_info_t);
                connection_info->interface_id   = interface_id;
                connection_info->adapter_id     = adapter_id;
                connection_info->access_address = connection_access_address;

                memcpy(connection_info->master_bd_addr, src_bd_addr, 6);
                memcpy(connection_info->slave_bd_addr,  dst_bd_addr, 6);

                /* We don't create control procedure context trees for BTLE_DIR_UNKNOWN,
                 * as the direction must be known for request/response matching. */
                connection_info->direction_info[BTLE_DIR_MASTER_SLAVE].control_procs =
                        wmem_tree_new(wmem_file_scope());
                connection_info->direction_info[BTLE_DIR_SLAVE_MASTER].control_procs =
                        wmem_tree_new(wmem_file_scope());

                wmem_tree_insert32_array(connection_info_tree, key, connection_info);

                connection_parameter_info = wmem_new0(wmem_file_scope(), connection_parameter_info_t);
                connection_parameter_info->parameters_frame = pinfo->num;

                key[3].length = 1;
                key[3].key = &pinfo->num;
                wmem_tree_insert32_array(connection_parameter_info_tree, key, connection_parameter_info);
            }

            break;
        case 0x07: /* ADV_EXT_IND / AUX_ADV_IND / AUX_SYNC_IND / AUX_CHAIN_IND / AUX_SCAN_RSP */
        case 0x08: /* AUX_CONNNECT_RSP */
        {
            guint8 tmp, ext_header_len, flags, acad_len;
            proto_item  *ext_header_item, *ext_flags_item;
            proto_tree  *ext_header_tree, *ext_flags_tree;
            guint32 adi;
            gboolean adi_present = FALSE;
            gboolean aux_pointer_present = FALSE;

            tmp = tvb_get_guint8(tvb, offset);
            ext_header_len = acad_len = tmp & 0x3F;

            ext_header_item = proto_tree_add_item(btle_tree, hf_extended_advertising_header, tvb, offset, ext_header_len + 1, ENC_NA);
            ext_header_tree = proto_item_add_subtree(ext_header_item, ett_extended_advertising_header);

            proto_tree_add_item(ext_header_tree, hf_extended_advertising_header_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ext_header_tree, hf_extended_advertising_mode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            if (ext_header_len > 0) {
                ext_flags_item = proto_tree_add_item(ext_header_tree, hf_extended_advertising_flags, tvb, offset, 1, ENC_NA);
                ext_flags_tree = proto_item_add_subtree(ext_flags_item, ett_extended_advertising_flags);

                proto_tree_add_bitmask_list(ext_flags_tree, tvb, offset, 1, hfx_extended_advertising_flags, ENC_NA);
                flags = tvb_get_guint8(tvb, offset);
                offset += 1;

                acad_len -= 1;
            } else {
                flags = 0;
            }

            if (flags & 0x01) {
                /* Advertiser Address */
                offset = dissect_bd_addr(hf_advertising_address, pinfo, ext_header_tree, tvb, offset, TRUE, interface_id, adapter_id, src_bd_addr);
                set_address(&pinfo->net_src, AT_ETHER, 6, src_bd_addr);
                copy_address_shallow(&pinfo->dl_src, &pinfo->net_src);
                copy_address_shallow(&pinfo->src, &pinfo->net_src);

                acad_len -= 6;
            } else if (!connection_info) {
                const char * anon_str = "Anonymous";
                clear_address(&pinfo->dl_src);
                set_address(&pinfo->net_src, AT_STRINGZ, sizeof(*anon_str), anon_str);
                copy_address_shallow(&pinfo->src, &pinfo->net_src);
            }

            if (flags & 0x02) {
                /* Target Address */
                offset = dissect_bd_addr(hf_target_addresss, pinfo, ext_header_tree, tvb, offset, FALSE, interface_id, adapter_id, dst_bd_addr);
                set_address(&pinfo->net_dst, AT_ETHER, 6, dst_bd_addr);
                copy_address_shallow(&pinfo->dl_dst, &pinfo->net_dst);
                copy_address_shallow(&pinfo->dst, &pinfo->net_dst);

                acad_len -= 6;
            } else {
                set_address(&pinfo->net_dst, AT_ETHER, 6, broadcast_addr);
                copy_address_shallow(&pinfo->dl_dst, &pinfo->net_dst);
                copy_address_shallow(&pinfo->dst, &pinfo->net_dst);
            }

            if (flags & 0x04) {
                guint32 cte_time;

                /* CTE Info */
                sub_item = proto_tree_add_item(ext_header_tree, hf_extended_advertising_cte_info, tvb, offset, 1, ENC_NA);
                sub_tree = proto_item_add_subtree(sub_item, ett_extended_advertising_cte_info);

                item = proto_tree_add_item_ret_uint(sub_tree, hf_extended_advertising_cte_info_time, tvb, offset, 1, ENC_LITTLE_ENDIAN, &cte_time);
                proto_item_append_text(item, " (%u usec)", cte_time * 8);
                proto_tree_add_item(sub_tree, hf_extended_advertising_cte_info_rfu, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(sub_tree, hf_extended_advertising_cte_info_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset += 1;

                acad_len -= 1;
            }

            if (flags & 0x08) {
                /* AdvDataInfo */
                sub_item = proto_tree_add_item_ret_uint(ext_header_tree, hf_extended_advertising_data_info, tvb, offset, 2, ENC_LITTLE_ENDIAN, &adi);
                sub_tree = proto_item_add_subtree(sub_item, ett_extended_advertising_data_info);

                proto_tree_add_item(sub_tree, hf_extended_advertising_data_info_did, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(sub_tree, hf_extended_advertising_data_info_sid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
                adi_present = TRUE;

                acad_len -= 2;
            }

            if (flags & 0x10) {
                guint32 aux_offset;

                /* Aux Pointer */
                sub_item = proto_tree_add_item(ext_header_tree, hf_extended_advertising_aux_ptr, tvb, offset, 3, ENC_NA);
                sub_tree = proto_item_add_subtree(sub_item, ett_extended_advertising_aux_pointer);

                proto_tree_add_item(sub_tree, hf_extended_advertising_aux_ptr_channel, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(sub_tree, hf_extended_advertising_aux_ptr_ca, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(sub_tree, hf_extended_advertising_aux_ptr_offset_units, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                tmp = tvb_get_guint8(tvb, offset);
                offset += 1;

                item = proto_tree_add_item_ret_uint(sub_tree, hf_extended_advertising_aux_ptr_aux_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN, &aux_offset);
                proto_tree_add_item(sub_tree, hf_extended_advertising_aux_ptr_aux_phy, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                proto_item_append_text(item, " (%u usec)", aux_offset * ((tmp & 0x80) != 0 ? 300 : 30));
                offset += 2;
                aux_pointer_present = TRUE;

                acad_len -= 3;
            }

            if (flags & 0x20) {
                guint32 sync_offset, interval;
                proto_item  *sync_info_item;
                proto_tree  *sync_info_tree;
                gint reserved_offset;
                guint16 sf;

                /* Sync Info */
                sync_info_item = proto_tree_add_item(ext_header_tree, hf_extended_advertising_sync_info, tvb, offset, 18, ENC_NA);
                sync_info_tree = proto_item_add_subtree(sync_info_item, ett_extended_advertising_sync_info);

                if (!pinfo->fd->visited) {
                    connection_parameter_info_t *connection_parameter_info;

                    connection_access_address = tvb_get_guint32(tvb, offset + 9, ENC_LITTLE_ENDIAN);

                    key[0].length = 1;
                    key[0].key = &interface_id;
                    key[1].length = 1;
                    key[1].key = &adapter_id;
                    key[2].length = 1;
                    key[2].key = &connection_access_address;
                    key[3].length = 1;
                    key[3].key = &frame_number;
                    key[4].length = 0;
                    key[4].key = NULL;

                    connection_info = wmem_new0(wmem_file_scope(), connection_info_t);
                    connection_info->interface_id   = interface_id;
                    connection_info->adapter_id     = adapter_id;
                    connection_info->access_address = connection_access_address;

                    if (flags & 0x01)
                        memcpy(connection_info->master_bd_addr, src_bd_addr, 6);

                    /* We don't create control procedure context trees for BTLE_DIR_UNKNOWN,
                     * as the direction must be known for request/response matching. */
                    connection_info->direction_info[BTLE_DIR_MASTER_SLAVE].control_procs =
                        wmem_tree_new(wmem_file_scope());
                    connection_info->direction_info[BTLE_DIR_SLAVE_MASTER].control_procs =
                        wmem_tree_new(wmem_file_scope());

                    wmem_tree_insert32_array(connection_info_tree, key, connection_info);

                    connection_parameter_info = wmem_new0(wmem_file_scope(), connection_parameter_info_t);
                    connection_parameter_info->parameters_frame = pinfo->num;

                    key[3].length = 1;
                    key[3].key = &pinfo->num;
                    wmem_tree_insert32_array(connection_parameter_info_tree, key, connection_parameter_info);
                }

                sf = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);

                item = proto_tree_add_item_ret_uint(sync_info_tree, hf_extended_advertising_sync_info_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN, &sync_offset);
                proto_tree_add_item(sync_info_tree, hf_extended_advertising_sync_info_offset_units, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(sync_info_tree, hf_extended_advertising_sync_info_offset_adjust, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(sync_info_tree, hf_extended_advertising_sync_info_reserved, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                if (sync_offset > 0) {
                    proto_item_append_text(item, " (%u usec)", sync_offset * ((sf & 0x2000) != 0 ? 300 : 30) + ((sf & 0x4000) != 0 ? 2457600 : 0));
                } else {
                    proto_item_append_text(item, " Cannot be represented");
                }
                offset += 2;

                item = proto_tree_add_item_ret_uint(sync_info_tree, hf_extended_advertising_sync_info_interval, tvb, offset, 2, ENC_LITTLE_ENDIAN, &interval);
                proto_item_append_text(item, " (%g msec)", interval * 1.25);
                offset += 2;

                sub_item = proto_tree_add_item(sync_info_tree, hf_extended_advertising_sync_info_channel_map, tvb, offset, 5, ENC_NA);
                sub_tree = proto_item_add_subtree(sub_item, ett_channel_map);

                call_dissector_with_data(btcommon_le_channel_map_handle, tvb_new_subset_length(tvb, offset, 5), pinfo, sub_tree, &reserved_offset);
                proto_tree_add_item(sync_info_tree, hf_extended_advertising_sync_info_sleep_clock_accuracy, tvb, offset + reserved_offset, 1, ENC_LITTLE_ENDIAN);
                offset += 5;

                proto_tree_add_item(sync_info_tree, hf_extended_advertising_sync_info_access_address, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                proto_tree_add_item(sync_info_tree, hf_extended_advertising_sync_info_crc_init, tvb, offset, 3, ENC_LITTLE_ENDIAN);
                offset += 3;

                proto_tree_add_item(sync_info_tree, hf_extended_advertising_sync_info_event_counter, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                acad_len -= 18;
            }

            if (flags & 0x40) {
                /* Tx Power */
                proto_tree_add_item(ext_header_tree, hf_extended_advertising_tx_power, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset += 1;

                acad_len -= 1;
            }

            if (acad_len > 0) {
                sub_item = proto_tree_add_item(ext_header_tree, hf_extended_advertising_header_acad, tvb, offset, acad_len, ENC_NA);
                sub_tree = proto_item_add_subtree(sub_item, ett_extended_advertising_acad);

                /* Additional Controller Advertising Data */
                next_tvb = tvb_new_subset_length(tvb, offset, acad_len);
                dissect_ad_eir(next_tvb, interface_id, adapter_id, frame_number, src_bd_addr, pinfo, sub_tree);

                offset += acad_len;
            }
            if (tvb_reported_length_remaining(tvb, offset) > 3) {
                gboolean ad_processed = FALSE;
                if (btle_context && pdu_type == 0x07 && btle_context->aux_pdu_type_valid) {
                    gboolean ad_reassembled = FALSE;
                    ae_had_info_t *ae_had_info = NULL;

                    switch (btle_context->aux_pdu_type) {
                        case 0x00:  /* AUX_ADV_IND */
                        case 0x02:  /* AUX_SYNC_IND */
                        case 0x03:  /* AUX_SCAN_RSP */
                            if (aux_pointer_present) {
                                /* Begining of new sequence of fragments */
                                if (!pinfo->fd->visited && adi_present) {
                                    ae_had_info = wmem_new0(wmem_file_scope(), ae_had_info_t);
                                    ae_had_info->first_frame_num=pinfo->num;

                                    if (flags & 0x01) {
                                        /* Copy Advertiser Address to reassemble AUX_CHAIN_IND */
                                        copy_address_wmem(wmem_file_scope(), &ae_had_info->adv_addr, &pinfo->src);
                                    }

                                    ae_had_key[0].length = 1;
                                    ae_had_key[0].key = &interface_id;
                                    ae_had_key[1].length = 1;
                                    ae_had_key[1].key = &adapter_id;
                                    ae_had_key[2].length = 1;
                                    ae_had_key[2].key = &adi;
                                    ae_had_key[3].length = 0;
                                    ae_had_key[3].key = NULL;

                                    wmem_tree_insert32_array(adi_to_first_frame_tree, ae_had_key, ae_had_info);

                                    fragment_add_seq(&btle_ea_host_advertising_data_reassembly_table,
                                        tvb, offset, pinfo,
                                        ae_had_info->first_frame_num, NULL,
                                        ae_had_info->fragment_counter,
                                        tvb_captured_length_remaining(tvb, offset) - 3,
                                        !ad_reassembled, 0);

                                    ae_had_info->fragment_counter++;
                                }
                                ad_processed = TRUE;
                            }
                            break;
                        case 0x01:  /* AUX_CHAIN_IND */
                            if (!aux_pointer_present) {
                                /* Final fragment */
                                ad_reassembled = TRUE;
                            }
                            if (!pinfo->fd->visited && adi_present) {

                                ae_had_key[0].length = 1;
                                ae_had_key[0].key = &interface_id;
                                ae_had_key[1].length = 1;
                                ae_had_key[1].key = &adapter_id;
                                ae_had_key[2].length = 1;
                                ae_had_key[2].key = &adi;
                                ae_had_key[3].length = 0;
                                ae_had_key[3].key = NULL;

                                ae_had_info = (ae_had_info_t *) wmem_tree_lookup32_array(adi_to_first_frame_tree, ae_had_key);

                                if (ae_had_info != NULL) {
                                    if (!(flags & 0x01) && (ae_had_info->adv_addr.len > 0)) {
                                        /* Copy Advertiser Address from AUX_ADV_IND if not present. */
                                        copy_address_shallow(&pinfo->src, &ae_had_info->adv_addr);
                                    }

                                    fragment_add_seq(&btle_ea_host_advertising_data_reassembly_table,
                                        tvb, offset, pinfo,
                                        ae_had_info->first_frame_num, NULL,
                                        ae_had_info->fragment_counter,
                                        tvb_captured_length_remaining(tvb, offset) - 3,
                                        !ad_reassembled, 0);

                                    ae_had_info->fragment_counter++;
                                    if (ad_reassembled == TRUE) {
                                        p_add_proto_data(wmem_file_scope(), pinfo, proto_btle, (guint32)(pinfo->curr_layer_num) << 8, ae_had_info);
                                    }
                                }
                            }
                            ad_processed = TRUE;
                            break;
                        default:
                            /* This field is 2 bits long, no special action needed */
                            break;
                    }
                    if (ad_processed) {
                        if (pinfo->fd->visited) {
                            /* Host Advertising Data fragment */
                            proto_tree_add_item(btle_tree, hf_extended_advertising_had_fragment, tvb, offset, tvb_captured_length_remaining(tvb, offset) - 3, ENC_NA);
                            if (ad_reassembled) {
                                fragment_head *fd_head = NULL;
                                tvbuff_t *assembled_tvb = NULL;

                                ae_had_info = (ae_had_info_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_btle, (guint32)(pinfo->curr_layer_num) << 8);
                                if (ae_had_info != NULL) {
                                    col_append_str(pinfo->cinfo, COL_INFO, " (EA HAD Reassembled)");

                                    if (!(flags & 0x01) && (ae_had_info->adv_addr.len > 0)) {
                                        /* Copy Advertiser Address from AUX_ADV_IND if not present. */
                                        copy_address_shallow(&pinfo->src, &ae_had_info->adv_addr);
                                    }

                                    fd_head = fragment_get(&btle_ea_host_advertising_data_reassembly_table, pinfo, ae_had_info->first_frame_num, NULL);
                                    assembled_tvb = process_reassembled_data(
                                        tvb, offset, pinfo,
                                        "Reassembled Host Advertising Data", fd_head,
                                        &btle_ea_host_advertising_data_frag_items,
                                        NULL, btle_tree);

                                    if (assembled_tvb) {
                                        dissect_ad_eir(assembled_tvb, interface_id, adapter_id, frame_number, src_bd_addr, pinfo, btle_tree);
                                    }
                                }
                            }
                            else {
                                col_append_str(pinfo->cinfo, COL_INFO, " (EA HAD Fragment)");
                            }
                            offset += tvb_captured_length_remaining(tvb, offset) - 3;
                        }
                    }
                }

                if (tvb_reported_length_remaining(tvb, offset) > 3) {
                    /* Host Advertising Data */
                    next_tvb = tvb_new_subset_length(tvb, offset, tvb_reported_length_remaining(tvb, offset) - 3);

                    if (btle_context && btle_context->aux_pdu_type_valid && btle_context->aux_pdu_type == 3) {
                        /* AUX_SCAN_RSP */
                        sub_item = proto_tree_add_item(btle_tree, hf_scan_response_data, tvb, offset, tvb_reported_length_remaining(tvb, offset) - 3, ENC_NA);
                        sub_tree = proto_item_add_subtree(sub_item, ett_scan_response_data);

                        dissect_ad_eir(next_tvb, interface_id, adapter_id, frame_number, src_bd_addr, pinfo, sub_tree);
                    }
                    else {
                        dissect_ad_eir(next_tvb, interface_id, adapter_id, frame_number, src_bd_addr, pinfo, btle_tree);
                    }

                    offset += tvb_reported_length_remaining(tvb, offset) - 3;
                }
            }
            break;
        }
        default:
            if (tvb_reported_length_remaining(tvb, offset) > 3) {
                proto_tree_add_expert(btle_tree, pinfo, &ei_unknown_data, tvb, offset, tvb_reported_length_remaining(tvb, offset) - 3);
                offset += tvb_reported_length_remaining(tvb, offset) - 3;
            }
        }
    } else if (btle_pdu_type == BTLE_PDU_TYPE_DATA || btle_pdu_type == BTLE_PDU_TYPE_CONNECTEDISO) {
        proto_item  *data_header_item, *seq_item, *control_proc_item;
        proto_tree  *data_header_tree;
        guint8       oct;
        guint8       llid;
        guint8       control_opcode;
        guint32      direction = BTLE_DIR_UNKNOWN;
        guint8       other_direction = BTLE_DIR_UNKNOWN;

        gboolean     add_l2cap_index = FALSE;
        gboolean     retransmit = FALSE;
        gboolean     cte_info_present = FALSE;

        /* Holds the last initiated control procedures for a given direction. */
        control_proc_info_t *last_control_proc[3] = {0};

        if (btle_context) {
            direction = btle_context->direction;
            other_direction = (direction == BTLE_DIR_SLAVE_MASTER) ? BTLE_DIR_MASTER_SLAVE : BTLE_DIR_SLAVE_MASTER;
        }

        btle_frame_info_t *btle_frame_info = NULL;
        fragment_head *frag_btl2cap_msg = NULL;
        btle_frame_info_t empty_btle_frame_info = {0, 0, 0, 0, 0};

        key[0].length = 1;
        key[0].key = &interface_id;
        key[1].length = 1;
        key[1].key = &adapter_id;
        key[2].length = 1;
        key[2].key = &access_address;
        key[3].length = 0;
        key[3].key = NULL;

        oct = tvb_get_guint8(tvb, offset);
        wmem_tree = (wmem_tree_t *) wmem_tree_lookup32_array(connection_info_tree, key);
        if (wmem_tree) {
            connection_info = (connection_info_t *) wmem_tree_lookup32_le(wmem_tree, pinfo->num);
            if (connection_info) {
                gchar  *str_addr_src, *str_addr_dst;
                /* Holds "unknown" + access_address + NULL, which is the longest string */
                int     str_addr_len = 18 + 1;

                str_addr_src = (gchar *) wmem_alloc(pinfo->pool, str_addr_len);
                str_addr_dst = (gchar *) wmem_alloc(pinfo->pool, str_addr_len);

                sub_item = proto_tree_add_ether(btle_tree, hf_master_bd_addr, tvb, 0, 0, connection_info->master_bd_addr);
                proto_item_set_generated(sub_item);

                sub_item = proto_tree_add_ether(btle_tree, hf_slave_bd_addr, tvb, 0, 0, connection_info->slave_bd_addr);
                proto_item_set_generated(sub_item);

                switch (direction) {
                case BTLE_DIR_MASTER_SLAVE:
                    snprintf(str_addr_src, str_addr_len, "Master_0x%08x", connection_info->access_address);
                    snprintf(str_addr_dst, str_addr_len, "Slave_0x%08x", connection_info->access_address);
                    set_address(&pinfo->dl_src, AT_ETHER, sizeof(connection_info->master_bd_addr), connection_info->master_bd_addr);
                    set_address(&pinfo->dl_dst, AT_ETHER, sizeof(connection_info->slave_bd_addr), connection_info->slave_bd_addr);
                    break;
                case BTLE_DIR_SLAVE_MASTER:
                    snprintf(str_addr_src, str_addr_len, "Slave_0x%08x", connection_info->access_address);
                    snprintf(str_addr_dst, str_addr_len, "Master_0x%08x", connection_info->access_address);
                    set_address(&pinfo->dl_src, AT_ETHER, sizeof(connection_info->slave_bd_addr), connection_info->slave_bd_addr);
                    set_address(&pinfo->dl_dst, AT_ETHER, sizeof(connection_info->master_bd_addr), connection_info->master_bd_addr);
                    break;
                default:
                    /* BTLE_DIR_UNKNOWN */
                    snprintf(str_addr_src, str_addr_len, "Unknown_0x%08x", connection_info->access_address);
                    snprintf(str_addr_dst, str_addr_len, "Unknown_0x%08x", connection_info->access_address);
                    clear_address(&pinfo->dl_src);
                    clear_address(&pinfo->dl_dst);
                    break;
                }

                set_address(&pinfo->net_src, AT_STRINGZ, (int)strlen(str_addr_src)+1, str_addr_src);
                copy_address_shallow(&pinfo->src, &pinfo->net_src);

                set_address(&pinfo->net_dst, AT_STRINGZ, (int)strlen(str_addr_dst)+1, str_addr_dst);
                copy_address_shallow(&pinfo->dst, &pinfo->net_dst);

                /* Retrieve the last initiated control procedures. */
                if (btle_pdu_type == BTLE_PDU_TYPE_DATA) {
                    last_control_proc[BTLE_DIR_MASTER_SLAVE] =
                        (control_proc_info_t *)wmem_tree_lookup32_le(connection_info->direction_info[BTLE_DIR_MASTER_SLAVE].control_procs, pinfo->num);
                    last_control_proc[BTLE_DIR_SLAVE_MASTER] =
                        (control_proc_info_t *)wmem_tree_lookup32_le(connection_info->direction_info[BTLE_DIR_SLAVE_MASTER].control_procs, pinfo->num);

                    if (!pinfo->fd->visited && btle_context && btle_context->event_counter_valid) {
                        control_proc_complete_if_instant_reached(pinfo->num,
                                                                 btle_context->event_counter,
                                                                 last_control_proc[BTLE_DIR_MASTER_SLAVE]);
                        control_proc_complete_if_instant_reached(pinfo->num,
                                                                 btle_context->event_counter,
                                                                 last_control_proc[BTLE_DIR_SLAVE_MASTER]);
                    }
                }

                if (!pinfo->fd->visited) {
                    address *addr;

                    btle_frame_info = wmem_new0(wmem_file_scope(), btle_frame_info_t);
                    btle_frame_info->l2cap_index = connection_info->direction_info[direction].l2cap_index;

                    addr = (address *) wmem_memdup(wmem_file_scope(), &pinfo->dl_src, sizeof(address));
                    addr->data =  wmem_memdup(wmem_file_scope(), pinfo->dl_src.data, pinfo->dl_src.len);
                    p_add_proto_data(wmem_file_scope(), pinfo, proto_bluetooth, BLUETOOTH_DATA_SRC, addr);

                    addr = (address *) wmem_memdup(wmem_file_scope(), &pinfo->dl_dst, sizeof(address));
                    addr->data =  wmem_memdup(wmem_file_scope(), pinfo->dl_dst.data, pinfo->dl_dst.len);
                    p_add_proto_data(wmem_file_scope(), pinfo, proto_bluetooth, BLUETOOTH_DATA_DST, addr);

                    if (!connection_info->first_data_frame_seen) {
                        connection_info->first_data_frame_seen = 1;
                        btle_frame_info->retransmit = 0;
                        btle_frame_info->ack = 1;
                        connection_info->direction_info[BTLE_DIR_MASTER_SLAVE].prev_seq_num = 0;
                        connection_info->direction_info[BTLE_DIR_SLAVE_MASTER].prev_seq_num = 1;
                    }
                    else {
                        guint8 seq_num = !!(oct & 0x8), next_expected_seq_num = !!(oct & 0x4);

                        if (seq_num != connection_info->direction_info[direction].prev_seq_num) {
                            /* SN is not equal to previous packet (in same direction) SN */
                            btle_frame_info->retransmit = 0;
                        } else {
                            btle_frame_info->retransmit = 1;
                        }
                        connection_info->direction_info[direction].prev_seq_num = seq_num;

                        if (next_expected_seq_num != connection_info->direction_info[other_direction].prev_seq_num) {
                            /* NESN is not equal to previous packet (in other direction) SN */
                            btle_frame_info->ack = 1;
                        } else {
                            btle_frame_info->ack = 0;
                        }
                    }
                    p_add_proto_data(wmem_file_scope(), pinfo, proto_btle, pinfo->curr_layer_num, btle_frame_info);
                }
                else {
                    /* Not the first pass */
                    btle_frame_info = (btle_frame_info_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_btle, pinfo->curr_layer_num);
                }
            }
        }

        if (btle_frame_info == NULL) {
            btle_frame_info = &empty_btle_frame_info;
        }

        if (btle_pdu_type == BTLE_PDU_TYPE_DATA) {
            cte_info_present = (oct & 0x20) != 0;
        }

        data_header_item = proto_tree_add_item(btle_tree,  hf_data_header, tvb, offset, 2 + cte_info_present, ENC_NA);
        data_header_tree = proto_item_add_subtree(data_header_item, ett_data_header);

        proto_tree_add_item(data_header_tree, (btle_pdu_type == BTLE_PDU_TYPE_CONNECTEDISO) ? hf_data_header_llid_connectediso :hf_data_header_llid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        seq_item = proto_tree_add_item(data_header_tree, hf_data_header_next_expected_sequence_number, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        if (direction != BTLE_DIR_UNKNOWN) {
            /* Unable to check valid NESN without direction */
            if (btle_frame_info->ack == 1) {
                proto_item_append_text(seq_item, " [ACK]");
            } else {
                proto_item_append_text(seq_item, " [Request retransmit]");
                expert_add_info(pinfo, seq_item, &ei_nack);
            }
        }

        seq_item = proto_tree_add_item(data_header_tree, hf_data_header_sequence_number, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        if (direction != BTLE_DIR_UNKNOWN) {
            /* Unable to check valid SN or retransmission without direction */
            if (btle_frame_info->retransmit == 0) {
                proto_item_append_text(seq_item, " [OK]");
            }
            else {
                proto_item_append_text(seq_item, " [Retransmit]");
                if (btle_detect_retransmit) {
                    expert_add_info(pinfo, seq_item, &ei_retransmit);
                    retransmit = TRUE;
                }
            }
        }

        llid = oct & 0x03;
        if (btle_pdu_type == BTLE_PDU_TYPE_CONNECTEDISO) {
            proto_tree_add_item(data_header_tree, hf_data_header_close_isochronous_event, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(data_header_tree, hf_data_header_null_pdu_indicator, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(data_header_tree, hf_data_header_rfu_57, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            llid |= 0x04;
        } else {
            proto_tree_add_item(data_header_tree, hf_data_header_more_data, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(data_header_tree, hf_data_header_cte_info_present, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(data_header_tree, hf_data_header_rfu, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        }
        offset += 1;

        proto_tree_add_item(data_header_tree, hf_data_header_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        item = proto_tree_add_item_ret_uint(btle_tree, hf_length, tvb, offset, 1, ENC_LITTLE_ENDIAN, &length);
        proto_item_set_hidden(item);
        offset += 1;

        if (cte_info_present) {
            guint32 cte_time;

            sub_item = proto_tree_add_item(data_header_tree, hf_data_header_cte_info, tvb, offset, 1, ENC_NA);
            sub_tree = proto_item_add_subtree(sub_item, ett_data_header_cte_info);

            item = proto_tree_add_item_ret_uint(sub_tree, hf_data_header_cte_info_time, tvb, offset, 1, ENC_LITTLE_ENDIAN, &cte_time);
            proto_item_append_text(item, " (%u usec)", cte_time * 8);
            proto_tree_add_item(sub_tree, hf_data_header_cte_info_rfu, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(sub_tree, hf_data_header_cte_info_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
        }

        switch (llid) {
        case 0x01: /* Continuation fragment of an L2CAP message, or an Empty PDU */
            if (length > 0) {
                tvbuff_t *new_tvb = NULL;

                pinfo->fragmented = TRUE;
                if (connection_info && !retransmit) {
                    if (!pinfo->fd->visited) {
                        if (connection_info->direction_info[direction].segmentation_started == 1) {
                            if (connection_info->direction_info[direction].segment_len_rem >= length) {
                                connection_info->direction_info[direction].segment_len_rem = connection_info->direction_info[direction].segment_len_rem - length;
                            } else {
                                /*
                                 * Missing fragment for previous L2CAP and fragment start for this.
                                 * Set more_fragments and increase l2cap_index to avoid reassembly.
                                 */
                                btle_frame_info->more_fragments = 1;
                                btle_frame_info->missing_start = 1;
                                btle_frame_info->l2cap_index = l2cap_index;
                                connection_info->direction_info[direction].l2cap_index = l2cap_index;
                                connection_info->direction_info[direction].segmentation_started = 0;
                                l2cap_index++;
                            }
                            if (connection_info->direction_info[direction].segment_len_rem > 0) {
                                btle_frame_info->more_fragments = 1;
                            }
                            else {
                                btle_frame_info->more_fragments = 0;
                                connection_info->direction_info[direction].segmentation_started = 0;
                                connection_info->direction_info[direction].segment_len_rem = 0;
                            }
                        } else {
                            /*
                             * Missing fragment start.
                             * Set more_fragments and increase l2cap_index to avoid reassembly.
                             */
                            btle_frame_info->more_fragments = 1;
                            btle_frame_info->missing_start = 1;
                            btle_frame_info->l2cap_index = l2cap_index;
                            connection_info->direction_info[direction].l2cap_index = l2cap_index;
                            connection_info->direction_info[direction].segmentation_started = 0;
                            l2cap_index++;
                        }
                    }

                    add_l2cap_index = TRUE;

                    frag_btl2cap_msg = fragment_add_seq_next(&btle_l2cap_msg_reassembly_table,
                        tvb, offset,
                        pinfo,
                        btle_frame_info->l2cap_index,      /* guint32 ID for fragments belonging together */
                        NULL,                              /* data* */
                        length,                            /* Fragment length */
                        btle_frame_info->more_fragments);  /* More fragments */

                    new_tvb = process_reassembled_data(tvb, offset, pinfo,
                        "Reassembled L2CAP",
                        frag_btl2cap_msg,
                        &btle_l2cap_msg_frag_items,
                        NULL,
                        btle_tree);
                }

                if (new_tvb) {
                    bthci_acl_data_t  *acl_data;

                    col_set_str(pinfo->cinfo, COL_INFO, "L2CAP Data");

                    acl_data = wmem_new(pinfo->pool, bthci_acl_data_t);
                    acl_data->interface_id = interface_id;
                    acl_data->adapter_id = adapter_id;
                    acl_data->chandle = 0; /* No connection handle at this layer */
                    acl_data->remote_bd_addr_oui = 0;
                    acl_data->remote_bd_addr_id = 0;
                    acl_data->is_btle = TRUE;
                    acl_data->is_btle_retransmit = retransmit;
                    acl_data->adapter_disconnect_in_frame = &bluetooth_max_disconnect_in_frame;
                    acl_data->disconnect_in_frame = &bluetooth_max_disconnect_in_frame;

                    next_tvb = tvb_new_subset_length(tvb, offset, length);
                    if (next_tvb) {
                        call_dissector_with_data(btl2cap_handle, new_tvb, pinfo, tree, acl_data);
                    }
                    offset += length;
                }
                else {
                    col_set_str(pinfo->cinfo, COL_INFO, "L2CAP Fragment");
                    item = proto_tree_add_item(btle_tree, hf_l2cap_fragment, tvb, offset, length, ENC_NA);
                    if (btle_frame_info->missing_start) {
                        expert_add_info(pinfo, item, &ei_missing_fragment_start);
                    }
                    offset += length;
                }
            } else {
                col_set_str(pinfo->cinfo, COL_INFO, "Empty PDU");
            }

            break;
        case 0x02: /* Start of an L2CAP message or a complete L2CAP message with no fragmentation */
            if (length > 0) {
                guint l2cap_len = tvb_get_letohs(tvb, offset);
                if (l2cap_len + 4 > length) { /* L2CAP PDU Length excludes the 4 octets header */
                    pinfo->fragmented = TRUE;
                    if (connection_info && !retransmit) {
                        if (!pinfo->fd->visited) {
                            connection_info->direction_info[direction].segmentation_started = 1;
                            /* The first two octets in the L2CAP PDU contain the length of the entire
                             * L2CAP PDU in octets, excluding the Length and CID fields(4 octets).
                             */
                            connection_info->direction_info[direction].segment_len_rem = l2cap_len + 4 - length;
                            connection_info->direction_info[direction].l2cap_index = l2cap_index;
                            btle_frame_info->more_fragments = 1;
                            btle_frame_info->l2cap_index = l2cap_index;
                            l2cap_index++;
                        }

                        add_l2cap_index = TRUE;

                        frag_btl2cap_msg = fragment_add_seq_next(&btle_l2cap_msg_reassembly_table,
                            tvb, offset,
                            pinfo,
                            btle_frame_info->l2cap_index,      /* guint32 ID for fragments belonging together */
                            NULL,                              /* data* */
                            length,                            /* Fragment length */
                            btle_frame_info->more_fragments);  /* More fragments */

                        process_reassembled_data(tvb, offset, pinfo,
                            "Reassembled L2CAP",
                            frag_btl2cap_msg,
                            &btle_l2cap_msg_frag_items,
                            NULL,
                            btle_tree);
                    }

                    col_set_str(pinfo->cinfo, COL_INFO, "L2CAP Fragment Start");
                    proto_tree_add_item(btle_tree, hf_l2cap_fragment, tvb, offset, length, ENC_NA);
                    offset += length;
                } else {
                    bthci_acl_data_t  *acl_data;
                    if (connection_info) {
                        /* Add a L2CAP index for completeness */
                        if (!pinfo->fd->visited) {
                            btle_frame_info->l2cap_index = l2cap_index;
                            l2cap_index++;
                        }

                        add_l2cap_index = TRUE;
                    }

                    col_set_str(pinfo->cinfo, COL_INFO, "L2CAP Data");

                    acl_data = wmem_new(pinfo->pool, bthci_acl_data_t);
                    acl_data->interface_id = interface_id;
                    acl_data->adapter_id   = adapter_id;
                    acl_data->chandle      = 0; /* No connection handle at this layer */
                    acl_data->remote_bd_addr_oui = 0;
                    acl_data->remote_bd_addr_id  = 0;
                    acl_data->is_btle = TRUE;
                    acl_data->is_btle_retransmit = retransmit;
                    acl_data->adapter_disconnect_in_frame = &bluetooth_max_disconnect_in_frame;
                    acl_data->disconnect_in_frame = &bluetooth_max_disconnect_in_frame;

                    next_tvb = tvb_new_subset_length(tvb, offset, length);
                    call_dissector_with_data(btl2cap_handle, next_tvb, pinfo, tree, acl_data);
                    offset += length;
                }
            }
            break;
        case 0x03: /* Control PDU */
            control_proc_item = proto_tree_add_item(btle_tree, hf_control_opcode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            control_opcode = tvb_get_guint8(tvb, offset);
            offset += 1;

            col_add_fstr(pinfo->cinfo, COL_INFO, "Control Opcode: %s",
                    val_to_str_ext_const(control_opcode, &control_opcode_vals_ext, "Unknown"));

            switch (control_opcode) {
            case 0x00: /* LL_CONNECTION_UPDATE_IND */
                item = proto_tree_add_item_ret_uint(btle_tree, hf_control_window_size, tvb, offset, 1, ENC_LITTLE_ENDIAN, &item_value);
                proto_item_append_text(item, " (%g msec)", item_value*1.25);
                offset += 1;

                item = proto_tree_add_item_ret_uint(btle_tree, hf_control_window_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN, &item_value);
                proto_item_append_text(item, " (%g msec)", item_value*1.25);
                offset += 2;

                item = proto_tree_add_item_ret_uint(btle_tree, hf_control_interval, tvb, offset, 2, ENC_LITTLE_ENDIAN, &item_value);
                proto_item_append_text(item, " (%g msec)", item_value*1.25);
                offset += 2;

                proto_tree_add_item(btle_tree, hf_control_latency, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                item = proto_tree_add_item_ret_uint(btle_tree, hf_control_timeout, tvb, offset, 2, ENC_LITTLE_ENDIAN, &item_value);
                proto_item_append_text(item, " (%u msec)", item_value*10);
                offset += 2;

                proto_tree_add_item_ret_uint(btle_tree, hf_control_instant, tvb, offset, 2, ENC_LITTLE_ENDIAN, &item_value);
                offset += 2;

                if (!pinfo->fd->visited) {
                    if (connection_info) {
                        connection_parameter_info_t *connection_parameter_info;

                        connection_parameter_info = wmem_new0(wmem_file_scope(), connection_parameter_info_t);
                        connection_parameter_info->parameters_frame = pinfo->num;

                        if (btle_context && btle_context->event_counter_valid) {
                            connection_info->connection_parameter_update_instant = item_value;
                            connection_info->connection_parameter_update_info = connection_parameter_info;
                        } else {
                            /* We don't have event counter information needed to determine the exact time the new
                             * connection parameters will be applied.
                             * Instead just set it as active immediately.
                             */
                            key[0].length = 1;
                            key[0].key = &interface_id;
                            key[1].length = 1;
                            key[1].key = &adapter_id;
                            key[2].length = 1;
                            key[2].key = &access_address;
                            key[3].length = 1;
                            key[3].key = &pinfo->num;
                            key[4].length = 0;
                            key[4].key = NULL;
                            wmem_tree_insert32_array(connection_parameter_info_tree, key, connection_parameter_info);
                        }
                    }
                }

                if (connection_info && !btle_frame_info->retransmit) {
                    /* The LL_CONNECTION_UPDATE_IND can only be sent from master to slave.
                     * It can either be sent as the first packet of the connection update procedure,
                     * or as the last packet in the connection parameter request procedure. */
                    if (direction == BTLE_DIR_MASTER_SLAVE) {
                        if (control_proc_can_add_frame(pinfo,
                                                       last_control_proc[BTLE_DIR_MASTER_SLAVE],
                                                       0x0F, 2)) {
                            last_control_proc[BTLE_DIR_MASTER_SLAVE]->frames[2] = pinfo->num;
                            last_control_proc[BTLE_DIR_MASTER_SLAVE]->last_frame = pinfo->num;

                            sub_item = proto_tree_add_uint(btle_tree, hf_request_in_frame, tvb, 0, 0,
                                                           last_control_proc[BTLE_DIR_MASTER_SLAVE]->frames[0]);
                            proto_item_set_generated(sub_item);
                        } else if (control_proc_can_add_frame(pinfo,
                                                              last_control_proc[BTLE_DIR_SLAVE_MASTER],
                                                              0x0F, 1)) {
                            last_control_proc[BTLE_DIR_SLAVE_MASTER]->frames[1] = pinfo->num;
                            last_control_proc[BTLE_DIR_SLAVE_MASTER]->last_frame = pinfo->num;

                            sub_item = proto_tree_add_uint(btle_tree, hf_request_in_frame, tvb, 0, 0,
                                                           last_control_proc[BTLE_DIR_SLAVE_MASTER]->frames[0]);
                            proto_item_set_generated(sub_item);
                        } else {
                            if (control_proc_invalid_collision(pinfo,
                                                               last_control_proc[other_direction],
                                                               control_opcode)) {
                                expert_add_info(pinfo, control_proc_item, &ei_control_proc_invalid_collision);
                            }

                            control_proc_info_t *proc_info;
                            proc_info = control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                                           connection_info->direction_info[direction].control_procs,
                                                           control_opcode);

                            if (proc_info) {
                                if (btle_context && btle_context->event_counter_valid) {
                                    proc_info->instant = item_value;
                                    proc_info->frame_with_instant_value = pinfo->num;
                                } else {
                                    /* Event counter is not available, assume the procedure completes now. */
                                    proc_info->last_frame = pinfo->num;
                                }
                            }

                        }
                    } else if (direction == BTLE_DIR_SLAVE_MASTER) {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }

                break;
            case 0x01: /* LL_CHANNEL_MAP_REQ */
                sub_item = proto_tree_add_item(btle_tree, hf_control_channel_map, tvb, offset, 5, ENC_NA);
                sub_tree = proto_item_add_subtree(sub_item, ett_channel_map);

                call_dissector(btcommon_le_channel_map_handle, tvb_new_subset_length(tvb, offset, 5), pinfo, sub_tree);
                offset += 5;

                proto_tree_add_item_ret_uint(btle_tree, hf_control_instant, tvb, offset, 2, ENC_LITTLE_ENDIAN, &item_value);
                offset += 2;

                if (connection_info && !btle_frame_info->retransmit) {
                    /* The LL_CHANNEL_MAP_REQ can only be sent from master to slave.
                     * It can either be sent as the first packet of the channel map update procedure,
                     * or as the last packet in the minimum number of used channels procedure. */
                    if (direction == BTLE_DIR_MASTER_SLAVE) {
                        if (control_proc_can_add_frame(pinfo,
                                                       last_control_proc[BTLE_DIR_SLAVE_MASTER],
                                                       0x19, 1)) {
                            last_control_proc[BTLE_DIR_SLAVE_MASTER]->frames[1] = pinfo->num;

                            if (btle_context && btle_context->event_counter_valid) {
                                last_control_proc[BTLE_DIR_SLAVE_MASTER]->instant = item_value;
                                last_control_proc[BTLE_DIR_SLAVE_MASTER]->frame_with_instant_value = pinfo->num;
                            } else {
                                /* Event counter is not available, assume the procedure completes now. */
                                last_control_proc[BTLE_DIR_SLAVE_MASTER]->last_frame = pinfo->num;
                            }

                            sub_item = proto_tree_add_uint(btle_tree, hf_request_in_frame, tvb, 0, 0,
                                                           last_control_proc[BTLE_DIR_SLAVE_MASTER]->frames[0]);
                            proto_item_set_generated(sub_item);
                        } else {
                            if (control_proc_invalid_collision(pinfo,
                                                               last_control_proc[other_direction],
                                                               control_opcode)) {
                                expert_add_info(pinfo, control_proc_item, &ei_control_proc_invalid_collision);
                            }

                            control_proc_info_t *proc_info;
                            proc_info = control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                                           connection_info->direction_info[direction].control_procs,
                                                           control_opcode);

                            if (proc_info) {
                                if (btle_context && btle_context->event_counter_valid) {
                                    proc_info->instant = item_value;
                                    proc_info->frame_with_instant_value = pinfo->num;
                                } else {
                                    /* Event counter is not available, assume the procedure completes now. */
                                    proc_info->last_frame = pinfo->num;
                                }
                            }
                        }
                    } else if (direction == BTLE_DIR_SLAVE_MASTER) {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }

                break;
            case 0x02: /* LL_TERMINATE_IND */
                proto_tree_add_item(btle_tree, hf_control_error_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset += 1;

                /* No need to mark procedure as started, as the procedure only consist
                 * of one packet which may be sent at any time, */

                break;
            case 0x03: /* LL_ENC_REQ */
                proto_tree_add_item(btle_tree, hf_control_random_number, tvb, offset, 8, ENC_LITTLE_ENDIAN);
                offset += 8;

                proto_tree_add_item(btle_tree, hf_control_encrypted_diversifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(btle_tree, hf_control_master_session_key_diversifier, tvb, offset, 8, ENC_LITTLE_ENDIAN);
                offset += 8;

                proto_tree_add_item(btle_tree, hf_control_master_session_initialization_vector, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                if (connection_info && !btle_frame_info->retransmit) {
                    /* The LL_ENC_REQ can only be sent from master to slave. */
                    if (direction == BTLE_DIR_MASTER_SLAVE) {
                        if (control_proc_invalid_collision(pinfo,
                                                           last_control_proc[other_direction],
                                                           control_opcode)) {
                            expert_add_info(pinfo, control_proc_item, &ei_control_proc_invalid_collision);
                        }

                        control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                           connection_info->direction_info[BTLE_DIR_MASTER_SLAVE].control_procs,
                                           control_opcode);
                    } else if (direction == BTLE_DIR_SLAVE_MASTER) {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }

                break;
            case 0x04: /* LL_ENC_RSP */
                proto_tree_add_item(btle_tree, hf_control_slave_session_key_diversifier, tvb, offset, 8, ENC_LITTLE_ENDIAN);
                offset += 8;

                proto_tree_add_item(btle_tree, hf_control_slave_session_initialization_vector, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                if (connection_info && !btle_frame_info->retransmit) {
                    /* The LL_ENC_REQ can only be sent from slave to master. */
                    if (direction == BTLE_DIR_SLAVE_MASTER) {
                        if (control_proc_can_add_frame(pinfo,
                                                       last_control_proc[BTLE_DIR_MASTER_SLAVE],
                                                       0x3, 1)) {
                            last_control_proc[BTLE_DIR_MASTER_SLAVE]->frames[1] = pinfo->num;

                            sub_item = proto_tree_add_uint(btle_tree, hf_request_in_frame, tvb, 0, 0,
                                                           last_control_proc[BTLE_DIR_MASTER_SLAVE]->frames[0]);
                            proto_item_set_generated(sub_item);
                        } else {
                            expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                        }
                    } else if (direction == BTLE_DIR_MASTER_SLAVE) {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }

                break;
            case 0x05: /* LL_START_ENC_REQ */
                offset = dissect_ctrl_pdu_without_data(tvb, pinfo, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit) {
                    /* The LL_START_ENC_REQ can only be sent from slave to master. */
                    if (direction == BTLE_DIR_SLAVE_MASTER) {
                        if (control_proc_can_add_frame(pinfo,
                                                       last_control_proc[BTLE_DIR_MASTER_SLAVE],
                                                       0x3, 2)) {
                            last_control_proc[BTLE_DIR_MASTER_SLAVE]->frames[2] = pinfo->num;

                            sub_item = proto_tree_add_uint(btle_tree, hf_request_in_frame, tvb, 0, 0,
                                                           last_control_proc[BTLE_DIR_MASTER_SLAVE]->frames[0]);
                            proto_item_set_generated(sub_item);
                        } else {
                            expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                        }
                    } else if (direction == BTLE_DIR_MASTER_SLAVE) {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }

                break;

            case 0x06: /* LL_START_ENC_RSP */
                offset = dissect_ctrl_pdu_without_data(tvb, pinfo, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    /* This is either frame 4 or 5 of the procedure */
                    if (direction == BTLE_DIR_MASTER_SLAVE &&
                        control_proc_can_add_frame(pinfo,
                                                   last_control_proc[BTLE_DIR_MASTER_SLAVE],
                                                   0x3, 3)) {
                        last_control_proc[BTLE_DIR_MASTER_SLAVE]->frames[3] = pinfo->num;

                        sub_item = proto_tree_add_uint(btle_tree, hf_request_in_frame, tvb, 0, 0,
                                                       last_control_proc[BTLE_DIR_MASTER_SLAVE]->frames[0]);
                        proto_item_set_generated(sub_item);
                    } else if (direction == BTLE_DIR_SLAVE_MASTER &&
                               control_proc_can_add_frame(pinfo,
                                                          last_control_proc[BTLE_DIR_MASTER_SLAVE],
                                                          0x3, 4)) {
                        last_control_proc[BTLE_DIR_MASTER_SLAVE]->frames[4] = pinfo->num;
                        last_control_proc[BTLE_DIR_MASTER_SLAVE]->last_frame = pinfo->num;

                        sub_item = proto_tree_add_uint(btle_tree, hf_request_in_frame, tvb, 0, 0,
                                                       last_control_proc[BTLE_DIR_MASTER_SLAVE]->frames[0]);
                        proto_item_set_generated(sub_item);
                    } else {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }

                break;

            case 0x07: /* LL_UNKNOWN_RSP */
                proto_tree_add_item(btle_tree, hf_control_unknown_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset += 1;

                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    /* LL_UNKNOWN_RSP can only be sent as the second frame of a procedure. */
                    if (last_control_proc[other_direction] &&
                        control_proc_can_add_frame_even_if_complete(pinfo,
                                                   last_control_proc[other_direction],
                                                   last_control_proc[other_direction]->proc_opcode,
                                                   1)) {
                        last_control_proc[other_direction]->frames[1] = pinfo->num;
                        last_control_proc[other_direction]->last_frame = pinfo->num;

                        sub_item = proto_tree_add_uint(btle_tree, hf_request_in_frame, tvb, 0, 0,
                                                       last_control_proc[other_direction]->frames[0]);
                        proto_item_set_generated(sub_item);
                    } else {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }

                break;
            case 0x08: /* LL_FEATURE_REQ */
                offset = dissect_feature_set(tvb, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit) {
                    /* The LL_FEATURE_REQ can only be sent from master to slave. */
                    if (direction == BTLE_DIR_MASTER_SLAVE) {
                        if (control_proc_invalid_collision(pinfo,
                                                           last_control_proc[other_direction],
                                                           control_opcode)) {
                            expert_add_info(pinfo, control_proc_item, &ei_control_proc_invalid_collision);
                        }

                        control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                           connection_info->direction_info[direction].control_procs,
                                           control_opcode);
                    } else if (direction == BTLE_DIR_SLAVE_MASTER) {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }

                break;
            case 0x09: /* LL_FEATURE_RSP */
                offset = dissect_feature_set(tvb, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    if (control_proc_can_add_frame(pinfo,
                                                   last_control_proc[other_direction],
                                                   0x08, 1) ||
                        control_proc_can_add_frame(pinfo,
                                                   last_control_proc[other_direction],
                                                   0x0E, 1)) {
                        last_control_proc[other_direction]->frames[1] = pinfo->num;
                        last_control_proc[other_direction]->last_frame = pinfo->num;

                        sub_item = proto_tree_add_uint(btle_tree, hf_request_in_frame, tvb, 0, 0,
                                                       last_control_proc[other_direction]->frames[0]);
                        proto_item_set_generated(sub_item);
                    } else {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }

                break;
            case 0x0A: /* LL_PAUSE_ENC_REQ */
                if (tvb_reported_length_remaining(tvb, offset) > 3) {
                    proto_tree_add_expert(btle_tree, pinfo, &ei_unknown_data, tvb, offset, tvb_reported_length_remaining(tvb, offset) - 3);
                    offset += tvb_reported_length_remaining(tvb, offset) - 3;
                }

                if (connection_info && !btle_frame_info->retransmit) {
                    /* The LL_PAUSE_ENC_REQ can only be sent from master to slave. */
                    if (direction == BTLE_DIR_MASTER_SLAVE) {
                        if (control_proc_invalid_collision(pinfo,
                                                           last_control_proc[other_direction],
                                                           control_opcode)) {
                            expert_add_info(pinfo, control_proc_item, &ei_control_proc_invalid_collision);
                        }

                        control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                           connection_info->direction_info[BTLE_DIR_MASTER_SLAVE].control_procs,
                                           control_opcode);
                    } else if (direction == BTLE_DIR_SLAVE_MASTER) {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }

                break;
            case 0x0B: /* LL_PAUSE_ENC_RSP */
                offset = dissect_ctrl_pdu_without_data(tvb, pinfo, btle_tree, offset);

                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    if (direction == BTLE_DIR_SLAVE_MASTER &&
                        control_proc_can_add_frame(pinfo,
                                                   last_control_proc[BTLE_DIR_MASTER_SLAVE],
                                                   0x0A, 1)) {
                        last_control_proc[BTLE_DIR_MASTER_SLAVE]->frames[1] = pinfo->num;

                        sub_item = proto_tree_add_uint(btle_tree, hf_request_in_frame, tvb, 0, 0,
                                                       last_control_proc[BTLE_DIR_MASTER_SLAVE]->frames[0]);
                        proto_item_set_generated(sub_item);
                    } else if (direction == BTLE_DIR_MASTER_SLAVE &&
                               control_proc_can_add_frame(pinfo,
                                                          last_control_proc[BTLE_DIR_MASTER_SLAVE],
                                                          0x0A, 2)) {
                        last_control_proc[BTLE_DIR_MASTER_SLAVE]->frames[2] = pinfo->num;
                        last_control_proc[BTLE_DIR_MASTER_SLAVE]->last_frame = pinfo->num;

                        sub_item = proto_tree_add_uint(btle_tree, hf_request_in_frame, tvb, 0, 0,
                                                       last_control_proc[BTLE_DIR_MASTER_SLAVE]->frames[0]);
                        proto_item_set_generated(sub_item);
                    } else {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }

                break;
            case 0x0C: /* LL_VERSION_IND */
                proto_tree_add_item(btle_tree, hf_control_version_number, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset += 1;

                proto_tree_add_item(btle_tree, hf_control_company_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(btle_tree, hf_control_subversion_number, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    /* The LL_VERSION_IND can be sent as a request or response.
                     * We first check if it is a response. */
                    if (control_proc_can_add_frame(pinfo,
                                                   last_control_proc[other_direction],
                                                   0x0C, 1)) {
                        last_control_proc[other_direction]->frames[1] = pinfo->num;
                        last_control_proc[other_direction]->last_frame = pinfo->num;

                        sub_item = proto_tree_add_uint(btle_tree, hf_request_in_frame, tvb, 0, 0,
                                                       last_control_proc[other_direction]->frames[0]);
                        proto_item_set_generated(sub_item);
                    } else {
                        if (control_proc_invalid_collision(pinfo,
                                                           last_control_proc[other_direction],
                                                           control_opcode)) {
                            expert_add_info(pinfo, control_proc_item, &ei_control_proc_invalid_collision);
                        }

                        control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                           connection_info->direction_info[direction].control_procs,
                                           control_opcode);
                    }
                }

                break;
            case 0x0D: /* LL_REJECT_IND */
                proto_tree_add_item(btle_tree, hf_control_error_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset += 1;

                /* LL_REJECT_IND my be sent as:
                 *  - A response to the LL_ENQ_REQ from the master
                 *  - After the LL_ENC_RSP from the slave */
                if (connection_info && !btle_frame_info->retransmit) {
                    if (direction == BTLE_DIR_SLAVE_MASTER) {
                        if (control_proc_can_add_frame(pinfo,
                                                       last_control_proc[BTLE_DIR_MASTER_SLAVE],
                                                       0x03, 1)) {
                            last_control_proc[BTLE_DIR_MASTER_SLAVE]->frames[1] = pinfo->num;
                            last_control_proc[BTLE_DIR_MASTER_SLAVE]->last_frame = pinfo->num;

                            sub_item = proto_tree_add_uint(btle_tree, hf_request_in_frame, tvb, 0, 0,
                                                           last_control_proc[BTLE_DIR_MASTER_SLAVE]->frames[0]);
                            proto_item_set_generated(sub_item);
                        } else if (control_proc_can_add_frame(pinfo,
                                                              last_control_proc[BTLE_DIR_MASTER_SLAVE],
                                                              0x03, 2)) {
                            last_control_proc[BTLE_DIR_MASTER_SLAVE]->frames[2] = pinfo->num;
                            last_control_proc[BTLE_DIR_MASTER_SLAVE]->last_frame = pinfo->num;

                            sub_item = proto_tree_add_uint(btle_tree, hf_request_in_frame, tvb, 0, 0,
                                                           last_control_proc[BTLE_DIR_MASTER_SLAVE]->frames[0]);
                            proto_item_set_generated(sub_item);
                        } else {
                            expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                        }
                    } else if (direction == BTLE_DIR_MASTER_SLAVE) {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }

                break;
            case 0x0E: /* LL_SLAVE_FEATURE_REQ */
                offset = dissect_feature_set(tvb, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit) {
                    /* The LL_SLAVE_FEATURE_REQ can only be sent from slave to master. */
                    if (direction == BTLE_DIR_SLAVE_MASTER) {
                        if (control_proc_invalid_collision(pinfo,
                                                           last_control_proc[other_direction],
                                                           control_opcode)) {
                            expert_add_info(pinfo, control_proc_item, &ei_control_proc_invalid_collision);
                        }

                        control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                           connection_info->direction_info[direction].control_procs,
                                           control_opcode);
                    } else if (direction == BTLE_DIR_MASTER_SLAVE) {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }
                break;

            case 0x0F: /* LL_CONNECTION_PARAM_REQ */
                offset = dissect_conn_param_req_rsp(tvb, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit) {
                    if (direction != BTLE_DIR_UNKNOWN) {
                        if (control_proc_invalid_collision(pinfo,
                                                           last_control_proc[other_direction],
                                                           control_opcode)) {
                            expert_add_info(pinfo, control_proc_item, &ei_control_proc_invalid_collision);
                        }

                        control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                           connection_info->direction_info[direction].control_procs,
                                           control_opcode);
                    }
                }

                break;
            case 0x10: /* LL_CONNECTION_PARAM_RSP */
                offset = dissect_conn_param_req_rsp(tvb, btle_tree, offset);

                if (connection_info && !btle_frame_info->retransmit) {
                    /* The LL_CONNECTION_PARAM_RSP can only be sent from slave to master
                     * as a response to a master initiated procedure */
                    if (direction == BTLE_DIR_SLAVE_MASTER) {
                        if (control_proc_can_add_frame(pinfo,
                                                       last_control_proc[BTLE_DIR_MASTER_SLAVE],
                                                       0x0F, 1)) {
                            last_control_proc[BTLE_DIR_MASTER_SLAVE]->frames[1] = pinfo->num;

                            sub_item = proto_tree_add_uint(btle_tree, hf_request_in_frame, tvb, 0, 0,
                                                           last_control_proc[BTLE_DIR_MASTER_SLAVE]->frames[0]);
                            proto_item_set_generated(sub_item);
                        } else {
                            expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                        }
                    } else if (direction == BTLE_DIR_MASTER_SLAVE) {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }

                break;
            case 0x11: /* LL_REJECT_EXT_IND */
                proto_tree_add_item(btle_tree, hf_control_reject_opcode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset += 1;

                proto_tree_add_item(btle_tree, hf_control_error_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset += 1;

                /* LL_REJECT_EXT_IND my be sent as:
                 *  - A response to the LL_ENQ_REQ from the master
                 *  - After the LL_ENC_RSP from the slave
                 *  - As a response to LL_CONNECTION_PARAM_REQ
                 *  - As a response to LL_CONNECTION_PARAM_RSP
                 *  - As a response during the phy update procedure.
                 */
                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    if (direction == BTLE_DIR_SLAVE_MASTER &&
                        control_proc_can_add_frame(pinfo,
                                                   last_control_proc[BTLE_DIR_MASTER_SLAVE],
                                                   0x03, 1)) {
                        last_control_proc[BTLE_DIR_MASTER_SLAVE]->frames[1] = pinfo->num;
                        last_control_proc[BTLE_DIR_MASTER_SLAVE]->last_frame = pinfo->num;

                        sub_item = proto_tree_add_uint(btle_tree, hf_request_in_frame, tvb, 0, 0,
                                                       last_control_proc[BTLE_DIR_MASTER_SLAVE]->frames[0]);
                        proto_item_set_generated(sub_item);
                    } else if (direction == BTLE_DIR_SLAVE_MASTER &&
                               control_proc_can_add_frame(pinfo,
                                                          last_control_proc[BTLE_DIR_MASTER_SLAVE],
                                                          0x03, 2)) {
                        last_control_proc[BTLE_DIR_MASTER_SLAVE]->frames[2] = pinfo->num;
                        last_control_proc[BTLE_DIR_MASTER_SLAVE]->last_frame = pinfo->num;

                        sub_item = proto_tree_add_uint(btle_tree, hf_request_in_frame, tvb, 0, 0,
                                                       last_control_proc[BTLE_DIR_MASTER_SLAVE]->frames[0]);
                        proto_item_set_generated(sub_item);

                    } else if (control_proc_can_add_frame(pinfo,
                                                          last_control_proc[other_direction],
                                                          0x0F, 1)) {
                        last_control_proc[other_direction]->frames[1] = pinfo->num;
                        last_control_proc[other_direction]->last_frame = pinfo->num;

                        sub_item = proto_tree_add_uint(btle_tree, hf_request_in_frame, tvb, 0, 0,
                                                       last_control_proc[other_direction]->frames[0]);
                        proto_item_set_generated(sub_item);
                    } else if (control_proc_can_add_frame(pinfo,
                                                          last_control_proc[other_direction],
                                                          0x16, 1)) {
                        last_control_proc[other_direction]->frames[1] = pinfo->num;
                        last_control_proc[other_direction]->last_frame = pinfo->num;

                        sub_item = proto_tree_add_uint(btle_tree, hf_request_in_frame, tvb, 0, 0,
                                                       last_control_proc[other_direction]->frames[0]);
                        proto_item_set_generated(sub_item);
                    } else {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }

                break;
            case 0x12: /* LL_PING_REQ */
                offset = dissect_ctrl_pdu_without_data(tvb, pinfo, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    if (control_proc_invalid_collision(pinfo,
                                                       last_control_proc[other_direction],
                                                       control_opcode)) {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_invalid_collision);
                    }

                    control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                       connection_info->direction_info[direction].control_procs,
                                       control_opcode);
                }
                break;
            case 0x13: /* LL_PING_RSP */
                offset = dissect_ctrl_pdu_without_data(tvb, pinfo, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    if (control_proc_can_add_frame(pinfo,
                                                   last_control_proc[other_direction],
                                                   0x12, 1)) {
                        last_control_proc[other_direction]->frames[1] = pinfo->num;
                        last_control_proc[other_direction]->last_frame = pinfo->num;

                        sub_item = proto_tree_add_uint(btle_tree, hf_request_in_frame, tvb, 0, 0,
                                                       last_control_proc[other_direction]->frames[0]);
                        proto_item_set_generated(sub_item);
                    } else {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }
                break;

            case 0x14: /* LL_LENGTH_REQ */
                dissect_length_req_rsp(tvb, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    if (control_proc_invalid_collision(pinfo,
                                                       last_control_proc[other_direction],
                                                       control_opcode)) {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_invalid_collision);
                    }

                    control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                       connection_info->direction_info[direction].control_procs,
                                       control_opcode);
                }

                break;
            case 0x15: /* LL_LENGTH_RSP */
                dissect_length_req_rsp(tvb, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    if (control_proc_can_add_frame(pinfo,
                                                   last_control_proc[other_direction],
                                                   0x14, 1)) {
                        last_control_proc[other_direction]->frames[1] = pinfo->num;
                        last_control_proc[other_direction]->last_frame = pinfo->num;

                        sub_item = proto_tree_add_uint(btle_tree, hf_request_in_frame, tvb, 0, 0,
                                                       last_control_proc[other_direction]->frames[0]);
                        proto_item_set_generated(sub_item);
                    } else {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }
                break;
            case 0x16: /* LL_PHY_REQ */
                dissect_phy_req_rsp(tvb, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    if (control_proc_invalid_collision(pinfo,
                                                       last_control_proc[other_direction],
                                                       control_opcode)) {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_invalid_collision);
                    }

                    control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                       connection_info->direction_info[direction].control_procs,
                                       control_opcode);
                }

                break;
            case 0x17: /* LL_PHY_RSP */
                dissect_phy_req_rsp(tvb, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit) {
                    /* The LL_PHY_RSP can only be sent from slave to master. */
                    if (direction == BTLE_DIR_SLAVE_MASTER) {
                        if (control_proc_can_add_frame(pinfo,
                                                       last_control_proc[BTLE_DIR_MASTER_SLAVE],
                                                       0x16, 1)) {
                            last_control_proc[BTLE_DIR_MASTER_SLAVE]->frames[1] = pinfo->num;

                            sub_item = proto_tree_add_uint(btle_tree, hf_request_in_frame, tvb, 0, 0,
                                                           last_control_proc[BTLE_DIR_MASTER_SLAVE]->frames[0]);
                            proto_item_set_generated(sub_item);
                        } else {
                            expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                        }
                    } else if (direction == BTLE_DIR_MASTER_SLAVE) {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }

                break;
            case 0x18: /* LL_PHY_UPDATE_IND */
                proto_tree_add_bitmask(btle_tree, tvb, offset, hf_control_m_to_s_phy, ett_m_to_s_phy, hfx_control_phys_update, ENC_NA);
                offset += 1;

                proto_tree_add_bitmask(btle_tree, tvb, offset, hf_control_s_to_m_phy, ett_s_to_m_phy, hfx_control_phys_update, ENC_NA);
                offset += 1;

                proto_tree_add_item_ret_uint(btle_tree, hf_control_instant, tvb, offset, 2, ENC_LITTLE_ENDIAN, &item_value);
                offset += 2;

                if (connection_info && !btle_frame_info->retransmit) {
                    /* The LL_PHY_UPDATE_IND can only be sent from master to slave. */
                    if (direction == BTLE_DIR_MASTER_SLAVE) {
                        if (control_proc_can_add_frame(pinfo,
                                                       last_control_proc[BTLE_DIR_MASTER_SLAVE],
                                                       0x16, 2)) {

                            last_control_proc[BTLE_DIR_MASTER_SLAVE]->frames[2] = pinfo->num;

                            if (btle_context && btle_context->event_counter_valid) {
                                last_control_proc[BTLE_DIR_MASTER_SLAVE]->instant = item_value;
                                last_control_proc[BTLE_DIR_MASTER_SLAVE]->frame_with_instant_value = pinfo->num;
                            } else {
                                /* Event counter is not available, assume the procedure completes now. */
                                last_control_proc[BTLE_DIR_MASTER_SLAVE]->last_frame = pinfo->num;
                            }

                            sub_item = proto_tree_add_uint(btle_tree, hf_request_in_frame, tvb, 0, 0,
                                                       last_control_proc[BTLE_DIR_MASTER_SLAVE]->frames[0]);
                            proto_item_set_generated(sub_item);
                        } else if (control_proc_can_add_frame(pinfo,
                                                              last_control_proc[BTLE_DIR_SLAVE_MASTER],
                                                              0x16, 1)){
                            last_control_proc[BTLE_DIR_SLAVE_MASTER]->frames[1] = pinfo->num;

                            if (btle_context && btle_context->event_counter_valid) {
                                last_control_proc[BTLE_DIR_SLAVE_MASTER]->instant = item_value;
                                last_control_proc[BTLE_DIR_SLAVE_MASTER]->frame_with_instant_value = pinfo->num;
                            } else {
                                /* Event counter is not available, assume the procedure completes now. */
                                last_control_proc[BTLE_DIR_SLAVE_MASTER]->last_frame = pinfo->num;
                            }

                            sub_item = proto_tree_add_uint(btle_tree, hf_request_in_frame, tvb, 0, 0,
                                                           last_control_proc[BTLE_DIR_SLAVE_MASTER]->frames[0]);
                            proto_item_set_generated(sub_item);
                        } else {
                            expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                        }
                    } else if (direction == BTLE_DIR_SLAVE_MASTER) {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }

                break;
            case 0x19: /* LL_MIN_USED_CHANNELS_IND */
                proto_tree_add_bitmask(btle_tree, tvb, offset, hf_control_phys, ett_phys, hfx_control_phys, ENC_NA);
                offset += 1;

                proto_tree_add_item(btle_tree, hf_control_min_used_channels, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset += 1;

                if (connection_info && !btle_frame_info->retransmit) {
                    /* The LL_MIN_USED_CHANNELS_IND can only be sent from slave to master. */
                    if (direction == BTLE_DIR_SLAVE_MASTER) {
                        if (control_proc_invalid_collision(pinfo,
                                                           last_control_proc[other_direction],
                                                           control_opcode)) {
                            expert_add_info(pinfo, control_proc_item, &ei_control_proc_invalid_collision);
                        }

                        control_proc_info_t *proc_info;
                        proc_info = control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                                       connection_info->direction_info[direction].control_procs,
                                                       control_opcode);

                        /* Procedure completes in the same frame. */
                        if (proc_info)
                            proc_info->last_frame = pinfo->num;
                    } else if (direction == BTLE_DIR_MASTER_SLAVE) {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }
                break;
            case 0x1A: /* LL_CTE_REQ */
                proto_tree_add_bitmask(btle_tree, tvb, offset, hf_control_phys, ett_cte, hfx_control_cte, ENC_NA);
                offset += 1;
                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    if (control_proc_invalid_collision(pinfo,
                                                       last_control_proc[other_direction],
                                                       control_opcode)) {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_invalid_collision);
                    }

                    control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                       connection_info->direction_info[direction].control_procs,
                                       control_opcode);
                }
                break;
            case 0x1B: /* LL_CTE_RSP */
                offset = dissect_ctrl_pdu_without_data(tvb, pinfo, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    if (control_proc_can_add_frame(pinfo,
                                                   last_control_proc[other_direction],
                                                   0x1A, 1)) {
                        last_control_proc[other_direction]->frames[1] = pinfo->num;
                        last_control_proc[other_direction]->last_frame = pinfo->num;

                        sub_item = proto_tree_add_uint(btle_tree, hf_request_in_frame, tvb, 0, 0,
                                                       last_control_proc[other_direction]->frames[0]);
                        proto_item_set_generated(sub_item);
                    } else {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }
                break;
            case 0x1C: /* LL_PERIODIC_SYNC_IND */
                offset = dissect_periodic_sync_ind(tvb, btle_tree, offset, pinfo, interface_id, adapter_id);
                break;
            case 0x1D: /* LL_CLOCK_ACCURACY_REQ */
                proto_tree_add_item(btle_tree, hf_control_sleep_clock_accuracy, tvb, offset, 1, ENC_NA);
                offset += 1;
                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    if (control_proc_invalid_collision(pinfo,
                                                       last_control_proc[other_direction],
                                                       control_opcode)) {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_invalid_collision);
                    }

                    control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                       connection_info->direction_info[direction].control_procs,
                                       control_opcode);
                }
                break;
            case 0x1E: /* LL_CLOCK_ACCURACY_RSP */
                proto_tree_add_item(btle_tree, hf_control_sleep_clock_accuracy, tvb, offset, 1, ENC_NA);
                offset += 1;
                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    if (control_proc_can_add_frame(pinfo,
                                                   last_control_proc[other_direction],
                                                   0x1D, 1)) {
                        last_control_proc[other_direction]->frames[1] = pinfo->num;
                        last_control_proc[other_direction]->last_frame = pinfo->num;

                        sub_item = proto_tree_add_uint(btle_tree, hf_request_in_frame, tvb, 0, 0,
                                                       last_control_proc[other_direction]->frames[0]);
                        proto_item_set_generated(sub_item);
                    } else {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }
                break;
            case 0x1F: /* LL_CIS_REQ */
                offset = dissect_cis_req(tvb, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    if (control_proc_invalid_collision(pinfo,
                                                       last_control_proc[other_direction],
                                                       control_opcode)) {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_invalid_collision);
                    }

                    control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                       connection_info->direction_info[direction].control_procs,
                                       control_opcode);
                }
                break;
            case 0x20: /* LL_CIS_RSP */
                offset = dissect_cis_rsp(tvb, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    if (control_proc_can_add_frame(pinfo,
                                                   last_control_proc[other_direction],
                                                   0x1F, 1)) {
                        last_control_proc[other_direction]->frames[1] = pinfo->num;
                        last_control_proc[other_direction]->last_frame = pinfo->num;

                        sub_item = proto_tree_add_uint(btle_tree, hf_request_in_frame, tvb, 0, 0,
                                                       last_control_proc[other_direction]->frames[0]);
                        proto_item_set_generated(sub_item);
                    } else {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }
                break;
            case 0x21: /* LL_CIS_IND */
                if (!pinfo->fd->visited) {
                    connection_info_t *nconnection_info;
                    connection_parameter_info_t *connection_parameter_info;

                    connection_access_address = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);

                    key[0].length = 1;
                    key[0].key = &interface_id;
                    key[1].length = 1;
                    key[1].key = &adapter_id;
                    key[2].length = 1;
                    key[2].key = &connection_access_address;
                    key[3].length = 1;
                    key[3].key = &frame_number;
                    key[4].length = 0;
                    key[4].key = NULL;

                    nconnection_info = wmem_new0(wmem_file_scope(), connection_info_t);
                    nconnection_info->interface_id   = interface_id;
                    nconnection_info->adapter_id     = adapter_id;
                    nconnection_info->access_address = connection_access_address;

                    if (connection_info) {
                        memcpy(nconnection_info->master_bd_addr, connection_info->master_bd_addr, 6);
                        memcpy(nconnection_info->slave_bd_addr,  connection_info->slave_bd_addr,  6);
                    }

                    /* We don't create control procedure context trees for BTLE_DIR_UNKNOWN,
                     * as the direction must be known for request/response matching. */
                    nconnection_info->direction_info[BTLE_DIR_MASTER_SLAVE].control_procs =
                        wmem_tree_new(wmem_file_scope());
                    nconnection_info->direction_info[BTLE_DIR_SLAVE_MASTER].control_procs =
                        wmem_tree_new(wmem_file_scope());

                    wmem_tree_insert32_array(connection_info_tree, key, nconnection_info);

                    connection_parameter_info = wmem_new0(wmem_file_scope(), connection_parameter_info_t);
                    connection_parameter_info->parameters_frame = pinfo->num;

                    key[3].length = 1;
                    key[3].key = &pinfo->num;
                    wmem_tree_insert32_array(connection_parameter_info_tree, key, connection_parameter_info);
                }
                offset = dissect_cis_ind(tvb, btle_tree, offset);
                break;
            case 0x22: /* LL_CIS_TERMINATE_IND */
                offset = dissect_cis_terminate_ind(tvb, btle_tree, offset);
                break;
            case 0x23: /* LL_POWER_CONTROL_REQ */
                offset = dissect_power_control_req(tvb, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    if (control_proc_invalid_collision(pinfo,
                                                       last_control_proc[other_direction],
                                                       control_opcode)) {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_invalid_collision);
                    }

                    control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                       connection_info->direction_info[direction].control_procs,
                                       control_opcode);
                }
                break;
            case 0x24: /* LL_POWER_CONTROL_RSP */
                offset = dissect_power_control_rsp(tvb, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    if (control_proc_can_add_frame(pinfo,
                                                   last_control_proc[other_direction],
                                                   0x23, 1)) {
                        last_control_proc[other_direction]->frames[1] = pinfo->num;
                        last_control_proc[other_direction]->last_frame = pinfo->num;

                        sub_item = proto_tree_add_uint(btle_tree, hf_request_in_frame, tvb, 0, 0,
                                                       last_control_proc[other_direction]->frames[0]);
                        proto_item_set_generated(sub_item);
                    } else {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }
                break;
            case 0x25: /* LL_POWER_CHANGE_IND */
                offset = dissect_power_control_ind(tvb, btle_tree, offset);
                break;
            default:
                offset = dissect_ctrl_pdu_without_data(tvb, pinfo, btle_tree, offset);
                break;
            }

            break;

        case 0x04: /* Unframed CIS Data PDU; end fragment of an SDU or a complete SDU */
        case 0x05: /* Unframed CIS Data PDU; start or continuation fragment of an SDU */
        case 0x06: /* Framed CIS Data PDU; one or more segments of an SDU */
            proto_tree_add_item(btle_tree, hf_isochronous_data, tvb, offset, length, ENC_NA);
            offset += length;
            break;

        default:
            if (tvb_reported_length_remaining(tvb, offset) > 3) {
                proto_tree_add_expert(btle_tree, pinfo, &ei_unknown_data, tvb, offset, tvb_reported_length_remaining(tvb, offset) - 3);
                offset += tvb_reported_length_remaining(tvb, offset) - 3;
            }
        }

        if (add_l2cap_index) {
            item = proto_tree_add_uint(btle_tree, hf_l2cap_index, tvb, 0, 0, btle_frame_info->l2cap_index);
            proto_item_set_generated(item);
        }

        key[0].length = 1;
        key[0].key = &interface_id;
        key[1].length = 1;
        key[1].key = &adapter_id;
        key[2].length = 1;
        key[2].key = &access_address;
        key[3].length = 0;
        key[3].key = NULL;
        wmem_tree = (wmem_tree_t *) wmem_tree_lookup32_array(connection_parameter_info_tree, key);
        if (wmem_tree) {
            connection_parameter_info_t *connection_parameter_info;

            if (connection_info && connection_info->connection_parameter_update_info != NULL &&
                btle_context && btle_context->event_counter_valid) {
                if ( ((gint16)btle_context->event_counter - connection_info->connection_parameter_update_instant) >= 0) {
                    wmem_tree_insert32(wmem_tree, pinfo->num, connection_info->connection_parameter_update_info);
                    connection_info->connection_parameter_update_info = NULL;
                }
            }

            connection_parameter_info = (connection_parameter_info_t *) wmem_tree_lookup32_le(wmem_tree, pinfo->num);
            if (connection_parameter_info) {
                item = proto_tree_add_uint(btle_tree, hf_connection_parameters_in, tvb, 0, 0, connection_parameter_info->parameters_frame);
                proto_item_set_generated(item);
            }
        }

        if ((crc_status == CRC_INDETERMINATE) &&
            btle_context && btle_context->connection_info_valid) {
            /* the surrounding context has provided CRCInit */
            crc_init = btle_context->connection_info.CRCInit;
            crc_status = CRC_CAN_BE_CALCULATED;
        }
    } else if (btle_pdu_type == BTLE_PDU_TYPE_BROADCASTISO) {
        broadcastiso_connection_info_t *broadcastiso_connection_info = NULL;
        guint32      seed_access_address = access_address & 0x0041ffff;
        proto_item  *data_header_item;
        proto_tree  *data_header_tree;
        guint8       llid;
        guint8       control_opcode;

        key[0].length = 1;
        key[0].key = &interface_id;
        key[1].length = 1;
        key[1].key = &adapter_id;
        key[2].length = 1;
        key[2].key = &seed_access_address;
        key[3].length = 0;
        key[3].key = NULL;

        wmem_tree = (wmem_tree_t *) wmem_tree_lookup32_array(broadcastiso_connection_info_tree, key);
        if (wmem_tree) {
            broadcastiso_connection_info = (broadcastiso_connection_info_t *) wmem_tree_lookup32_le(wmem_tree, pinfo->num);
            if (broadcastiso_connection_info) {
                gchar  *str_addr_src;
                /* Holds "Master" + access_address + NULL, which is the longest string */
                int     str_addr_len = 17 + 1;

                str_addr_src = (gchar *) wmem_alloc(pinfo->pool, str_addr_len);

                sub_item = proto_tree_add_ether(btle_tree, hf_master_bd_addr, tvb, 0, 0, broadcastiso_connection_info->master_bd_addr);
                proto_item_set_generated(sub_item);

                snprintf(str_addr_src, str_addr_len, "Master_0x%08x", broadcastiso_connection_info->access_address);
                set_address(&pinfo->dl_src, AT_ETHER, sizeof(broadcastiso_connection_info->master_bd_addr), broadcastiso_connection_info->master_bd_addr);
                clear_address(&pinfo->dl_dst);

                set_address(&pinfo->net_src, AT_STRINGZ, (int)strlen(str_addr_src)+1, str_addr_src);
                copy_address_shallow(&pinfo->src, &pinfo->net_src);

                if (!pinfo->fd->visited) {
                    address *addr;

                    addr = (address *) wmem_memdup(wmem_file_scope(), &pinfo->dl_src, sizeof(address));
                    addr->data =  wmem_memdup(wmem_file_scope(), pinfo->dl_src.data, pinfo->dl_src.len);
                    p_add_proto_data(wmem_file_scope(), pinfo, proto_bluetooth, BLUETOOTH_DATA_SRC, addr);
                }
            }
        }

        set_address(&pinfo->net_dst, AT_ETHER, 6, broadcast_addr);
        copy_address_shallow(&pinfo->dl_dst, &pinfo->net_dst);
        copy_address_shallow(&pinfo->dst, &pinfo->net_dst);

        data_header_item = proto_tree_add_item(btle_tree,  hf_data_header, tvb, offset, 2, ENC_NA);
        data_header_tree = proto_item_add_subtree(data_header_item, ett_data_header);

        proto_tree_add_item(data_header_tree, hf_data_header_llid_broadcastiso, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        llid = tvb_get_guint8(tvb, offset) & 0x03;
        proto_tree_add_item(data_header_tree, hf_data_header_control_subevent_sequence_number, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(data_header_tree, hf_data_header_control_subevent_transmission_flag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(data_header_tree, hf_data_header_rfu_67, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;

        proto_tree_add_item(data_header_tree, hf_data_header_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        item = proto_tree_add_item_ret_uint(btle_tree, hf_length, tvb, offset, 1, ENC_LITTLE_ENDIAN, &length);
        proto_item_set_hidden(item);
        offset += 1;

        switch (llid) {
        case 0x00: /* Unframed BIS Data PDU; end fragment of an SDU or a complete SDU */
        case 0x01: /* Unframed BIS Data PDU; start or continuation fragment of an SDU */
        case 0x02: /* Framed BIS Data PDU; one or more segments of an SDU */
            proto_tree_add_item(btle_tree, hf_isochronous_data, tvb, offset, length, ENC_NA);
            offset += length;
            break;

        case 0x03: /* BIG Control PDU */
            proto_tree_add_item(btle_tree, hf_big_control_opcode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            control_opcode = tvb_get_guint8(tvb, offset);
            offset += 1;

            col_add_fstr(pinfo->cinfo, COL_INFO, "BIG Control Opcode: %s",
                    val_to_str_ext_const(control_opcode, &big_control_opcode_vals_ext, "Unknown"));

            switch (control_opcode) {
            case 0x00: /* BIG_CHANNEL_MAP_IND */
                sub_item = proto_tree_add_item(btle_tree, hf_control_channel_map, tvb, offset, 5, ENC_NA);
                sub_tree = proto_item_add_subtree(sub_item, ett_channel_map);

                call_dissector(btcommon_le_channel_map_handle, tvb_new_subset_length(tvb, offset, 5), pinfo, sub_tree);
                offset += 5;

                proto_tree_add_item_ret_uint(btle_tree, hf_control_instant, tvb, offset, 2, ENC_LITTLE_ENDIAN, &item_value);
                offset += 2;
                break;

            case 0x01: /* BIG_TERMINATE_IND */
                proto_tree_add_item(btle_tree, hf_control_error_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset += 1;
                proto_tree_add_item_ret_uint(btle_tree, hf_control_instant, tvb, offset, 2, ENC_LITTLE_ENDIAN, &item_value);
                offset += 2;
                break;

            default:
                offset = dissect_ctrl_pdu_without_data(tvb, pinfo, btle_tree, offset);
                break;
            }
            break;

        default:
            if (tvb_reported_length_remaining(tvb, offset) > 3) {
                proto_tree_add_expert(btle_tree, pinfo, &ei_unknown_data, tvb, offset, tvb_reported_length_remaining(tvb, offset) - 3);
                offset += tvb_reported_length_remaining(tvb, offset) - 3;
            }
        }

    } else {
        /* Unknown physical channel PDU type */
        if (tvb_reported_length_remaining(tvb, offset) > 3) {
                proto_tree_add_expert(btle_tree, pinfo, &ei_unknown_data, tvb, offset, tvb_reported_length_remaining(tvb, offset) - 3);
                offset += tvb_reported_length_remaining(tvb, offset) - 3;
        }
    }

    /* BT spec Vol 6, Part B, Section 1.2: CRC is big endian and bits in byte are flipped */
    packet_crc = reverse_bits_per_byte(tvb_get_ntoh24(tvb, offset));
    sub_item = proto_tree_add_uint(btle_tree, hf_crc, tvb, offset, 3, packet_crc);
    offset += 3;
    if (crc_status == CRC_CAN_BE_CALCULATED) {
        guint32 crc = btle_crc(tvb, length, crc_init);
        crc_status = (packet_crc == crc) ? CRC_CORRECT : CRC_INCORRECT;
    }
    switch(crc_status) {
    case CRC_INDETERMINATE:
        expert_add_info(pinfo, sub_item, &ei_crc_cannot_be_determined);
        break;
    case CRC_INCORRECT:
        expert_add_info(pinfo, sub_item, &ei_crc_incorrect);
        break;
    case CRC_CORRECT:
    default:
        break;
    }

    return offset;
}

void
proto_register_btle(void)
{
    module_t         *module;
    expert_module_t  *expert_module;

    static hf_register_info hf[] = {
        { &hf_access_address,
            { "Access Address",                  "btle.access_address",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_coding_indicator,
            { "Coding Indicator",                "btle.coding_indicator",
            FT_UINT8, BASE_DEC, VALS(le_coding_indicators), 0x3,
            NULL, HFILL }
        },
        { &hf_master_bd_addr,
            { "Master Address",                  "btle.master_bd_addr",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_slave_bd_addr,
            { "Slave Address",                   "btle.slave_bd_addr",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_length,
            { "Length",                          "btle.length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_advertising_header,
            { "Packet Header",                   "btle.advertising_header",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_advertising_header_pdu_type,
            { "PDU Type",                        "btle.advertising_header.pdu_type",
            FT_UINT8, BASE_HEX, NULL, 0x0F,
            NULL, HFILL }
        },
        { &hf_advertising_header_rfu_1,
            { "Reserved",                        "btle.advertising_header.rfu.1",
            FT_UINT8, BASE_DEC, NULL, 0x10,
            "Reserved for Future Use", HFILL }
        },
        { &hf_advertising_header_ch_sel,
            { "Channel Selection Algorithm",     "btle.advertising_header.ch_sel",
            FT_BOOLEAN, 8, TFS(&tfs_ch_sel), 0x20,
            NULL, HFILL }
        },
        { &hf_advertising_header_rfu_2,
            { "Reserved",                        "btle.advertising_header.rfu.2",
            FT_UINT8, BASE_DEC, NULL, 0x20,
            "Reserved for Future Use", HFILL }
        },
        { &hf_advertising_header_randomized_tx,
            { "Tx Address",                      "btle.advertising_header.randomized_tx",
            FT_BOOLEAN, 8, TFS(&tfs_random_public), 0x40,
            NULL, HFILL }
        },
        { &hf_advertising_header_rfu_3,
            { "Reserved",                        "btle.advertising_header.rfu.3",
            FT_UINT8, BASE_DEC, NULL, 0x40,
            "Reserved for Future Use", HFILL }
        },
        { &hf_advertising_header_randomized_rx,
            { "Rx Address",                      "btle.advertising_header.randomized_rx",
            FT_BOOLEAN, 8, TFS(&tfs_random_public), 0x80,
            NULL, HFILL }
        },
        { &hf_advertising_header_rfu_4,
            { "Reserved",                        "btle.advertising_header.rfu.4",
            FT_UINT8, BASE_DEC, NULL, 0x80,
            "Reserved for Future Use", HFILL }
        },
        { &hf_advertising_header_length,
            { "Length",                          "btle.advertising_header.length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_advertising_address,
            { "Advertising Address",             "btle.advertising_address",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_initiator_addresss,
            { "Initiator Address",               "btle.initiator_address",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_target_addresss,
            { "Target Address",                  "btle.target_address",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_scanning_address,
            { "Scanning Address",                "btle.scanning_address",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_scan_response_data,
            { "Scan Response Data",              "btle.scan_responce_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_link_layer_data,
            { "Link Layer Data",                 "btle.link_layer_data",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_link_layer_data_access_address,
            { "Access Address",                  "btle.link_layer_data.access_address",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_link_layer_data_crc_init,
            { "CRC Init",                        "btle.link_layer_data.crc_init",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_link_layer_data_window_size,
            { "Window Size",                     "btle.link_layer_data.window_size",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_link_layer_data_window_offset,
            { "Window Offset",                   "btle.link_layer_data.window_offset",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_link_layer_data_interval,
            { "Interval",                        "btle.link_layer_data.interval",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_link_layer_data_latency,
            { "Latency",                         "btle.link_layer_data.latency",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_link_layer_data_timeout,
            { "Timeout",                         "btle.link_layer_data.timeout",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_link_layer_data_channel_map,
            { "Channel Map",                     "btle.link_layer_data.channel_map",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_link_layer_data_hop,
            { "Hop",                             "btle.link_layer_data.hop",
            FT_UINT8, BASE_DEC, NULL, 0x1f,
            NULL, HFILL }
        },
        { &hf_link_layer_data_sleep_clock_accuracy,
            { "Sleep Clock Accuracy",            "btle.link_layer_data.sleep_clock_accuracy",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &sleep_clock_accuracy_vals_ext, 0xe0,
            NULL, HFILL }
        },
        { &hf_extended_advertising_header,
            { "Extended Advertising Header",     "btle.extended_advertising_header",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_extended_advertising_header_length,
            { "Extended Header Length",          "btle.extended_advertising_header.length",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_extended_advertising_mode,
            { "Advertising Mode",                "btle.extended_advertising_header.mode",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &advertising_mode_vals_ext, 0xC0,
            NULL, HFILL }
        },
        { &hf_extended_advertising_flags,
            { "Extended Header Flags",           "btle.extended_advertising_header.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_extended_advertising_flags_adva,
            { "Advertiser Address",              "btle.extended_advertising_header.flags.advertiser_address",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
            NULL, HFILL }
        },
        { &hf_extended_advertising_flags_targeta,
            { "Target Address",                  "btle.extended_advertising_header.flags.target_address",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
            NULL, HFILL }
        },
        { &hf_extended_advertising_flags_cte_info,
            { "CTE Info",                        "btle.extended_advertising_header.flags.cte_info",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x04,
            NULL, HFILL }
        },
        { &hf_extended_advertising_flags_advdatainfo,
            { "Advertiser Data Info",            "btle.extended_advertising_header.advertiser_data_info",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x08,
            NULL, HFILL }
        },
        { &hf_extended_advertising_flags_aux_ptr,
            { "Aux pointer",                     "btle.extended_advertising_header.flags.aux_pointer",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x10,
            NULL, HFILL }
        },
        { &hf_extended_advertising_flags_sync_info,
            { "Sync Info",                       "btle.extended_advertising_header.flags.sync_info",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x20,
            NULL, HFILL }
        },
        { &hf_extended_advertising_flags_tx_power,
            { "TX Power",                        "btle.extended_advertising_header.flags.tx_power",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x40,
            NULL, HFILL }
        },
        { &hf_extended_advertising_flags_reserved,
            { "Reserved",                        "btle.extended_advertising_header.flags.reserved",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x80,
            NULL, HFILL }
        },
        { &hf_extended_advertising_cte_info,
            { "CTE Info",                        "btle.extended_advertising_header.cte_info",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_extended_advertising_cte_info_time,
            { "CTE Time",                        "btle.extended_advertising_header.cte_info.time",
            FT_UINT8, BASE_HEX, NULL, 0x1F,
            NULL, HFILL }
        },
        { &hf_extended_advertising_cte_info_rfu,
            { "RFU",                             "btle.extended_advertising_header.cte_info.rfu",
            FT_UINT8, BASE_HEX, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_extended_advertising_cte_info_type,
            { "CTE Type",                        "btle.extended_advertising_header.cte_info.type",
            FT_UINT8, BASE_HEX, VALS(le_cte_type_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_extended_advertising_data_info,
            { "Advertiser Data Info",            "btle.extended_advertising.advertising_data_info",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_extended_advertising_data_info_did,
            { "Advertiser Data Identifier",      "btle.extended_advertising.advertising_data_info.did",
            FT_UINT16, BASE_HEX, NULL, 0x0FFF,
            NULL, HFILL }
        },
        { &hf_extended_advertising_data_info_sid,
            { "Advertiser Set Identifier",       "btle.extended_advertising.advertising_data_info.sid",
            FT_UINT16, BASE_HEX, NULL, 0xF000,
            NULL, HFILL }
        },
        { &hf_extended_advertising_aux_ptr,
            { "Advertiser Aux Pointer",          "btle.extended_advertising.aux_pointer",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_extended_advertising_aux_ptr_channel,
            { "Channel Index",                   "btle.extended_advertising_header.aux_pointer.channel",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_extended_advertising_aux_ptr_ca,
            { "Clock Accuracy",                  "btle.extended_advertising_header.aux_pointer.ca",
            FT_BOOLEAN, 8, TFS(&tfs_ca), 0x40,
            NULL, HFILL }
        },
        { &hf_extended_advertising_aux_ptr_offset_units,
            { "Offset units",                    "btle.extended_advertising_header.aux_pointer.offset_units",
            FT_BOOLEAN, 8, TFS(&tfs_offset_units), 0x80,
            NULL, HFILL }
        },
        { &hf_extended_advertising_aux_ptr_aux_offset,
            { "Aux Offset",                      "btle.extended_advertising_header.aux_pointer.aux_offset",
            FT_UINT16, BASE_HEX, NULL, 0x1FFF,
            NULL, HFILL }
        },
        { &hf_extended_advertising_aux_ptr_aux_phy,
            { "Aux PHY",                         "btle.extended_advertising_header.aux_pointer.aux_phy",
            FT_UINT16, BASE_DEC, VALS(le_phys), 0xE000,
            NULL, HFILL }
        },
        { &hf_extended_advertising_sync_info,
            { "Advertiser Sync Info",            "btle.extended_advertising.sync_info",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_extended_advertising_had_fragment,
            { "Host Advertising Data Fragment",  "btle.extended_advertising.had_fragment",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_extended_advertising_sync_info_offset,
            { "Sync Offset",                     "btle.extended_advertising_header.sync_info.sync_offset",
            FT_UINT16, BASE_HEX, NULL, 0x1FFF,
            NULL, HFILL }
        },
        { &hf_extended_advertising_sync_info_offset_units,
            { "Offset Units",                    "btle.extended_advertising_header.sync_info.offset_units",
            FT_BOOLEAN, 16, TFS(&tfs_offset_units), 0x2000,
            NULL, HFILL }
        },
        { &hf_extended_advertising_sync_info_offset_adjust,
            { "Offset Adjust",                   "btle.extended_advertising_header.sync_info.offset_adjust",
            FT_BOOLEAN, 16, TFS(&tfs_offset_adjust), 0x4000,
            NULL, HFILL }
        },
        { &hf_extended_advertising_sync_info_reserved,
            { "Reserved",                        "btle.extended_advertising_header.sync_info.offset_units",
            FT_BOOLEAN, 16, NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_extended_advertising_sync_info_interval,
            { "Interval",                        "btle.extended_advertising_header.sync_info.interval",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_extended_advertising_sync_info_channel_map,
            { "Channel Map",                     "btle.extended_advertising_header.sync_info.channel_map",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_extended_advertising_sync_info_sleep_clock_accuracy,
            { "Sleep Clock Accuracy",            "btle.extended_advertising_header.sync_info.sleep_clock_accuracy",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &sleep_clock_accuracy_vals_ext, 0xe0,
            NULL, HFILL }
        },
        { &hf_extended_advertising_sync_info_access_address,
            { "Access Address",                  "btle.extended_advertising_header.sync_info.access_address",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_extended_advertising_sync_info_crc_init,
            { "CRC Init",                        "btle.extended_advertising_header.sync_info.crc_init",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_extended_advertising_sync_info_event_counter,
            { "Event counter",                   "btle.extended_advertising_header.sync_info.event_counter",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_extended_advertising_tx_power,
            { "TX Power",                         "btle.extended_advertising_header.tx_power",
            FT_INT8, BASE_DEC | BASE_UNIT_STRING, &units_dbm, 0x0,
            NULL, HFILL }
        },
        { &hf_extended_advertising_header_acad,
            { "Additional Controller Advertising Data",     "btle.extended_advertising_header.acad",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_data_header,
            { "Data Header",                     "btle.data_header",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_data_header_llid,
            { "LLID",                            "btle.data_header.llid",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &llid_codes_vals_ext, 0x03,
            "Logical Link Identifier", HFILL }
        },
        { &hf_data_header_llid_connectediso,
            { "LLID",                            "btle.data_header.llid",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &llid_connectediso_codes_vals_ext, 0x03,
            "Logical Link Identifier", HFILL }
        },
        { &hf_data_header_llid_broadcastiso,
            { "LLID",                            "btle.data_header.llid",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &llid_broadcastiso_codes_vals_ext, 0x03,
            "Logical Link Identifier", HFILL }
        },
        { &hf_data_header_next_expected_sequence_number,
            { "Next Expected Sequence Number",   "btle.data_header.next_expected_sequence_number",
            FT_UINT8, BASE_DEC, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_data_header_sequence_number,
            { "Sequence Number",                 "btle.data_header.sequence_number",
            FT_UINT8, BASE_DEC, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_data_header_more_data,
            { "More Data",                       "btle.data_header.more_data",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_data_header_cte_info_present,
            { "CTE Info",                 "btle.data_header.cte_info_present",
            FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x20,
            NULL, HFILL }
        },
        { &hf_data_header_length,
            { "Length",                          "btle.data_header.length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_data_header_cte_info,
            { "CTE Info",                          "btle.data_header.cte_info",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_data_header_cte_info_time,
            { "CTE Time",                        "btle.data_header.cte_info.time",
            FT_UINT8, BASE_HEX, NULL, 0x1F,
            NULL, HFILL }
        },
        { &hf_data_header_cte_info_rfu,
            { "RFU",                             "btle.data_header.cte_info.rfu",
            FT_UINT8, BASE_HEX, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_data_header_cte_info_type,
            { "CTE Type",                        "btle.data_header.cte_info.type",
            FT_UINT8, BASE_HEX, VALS(le_cte_type_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_data_header_rfu,
            { "RFU",                             "btle.data_header.rfu",
            FT_UINT8, BASE_DEC, NULL, 0xC0,
            "Reserved for Future Use", HFILL }
        },
        { &hf_data_header_rfu_67,
            { "RFU",                             "btle.data_header.rfu",
            FT_UINT8, BASE_DEC, NULL, 0xC0,
            "Reserved for Future Use", HFILL }
        },
        { &hf_data_header_rfu_57,
            { "RFU",                             "btle.data_header.rfu",
            FT_UINT8, BASE_DEC, NULL, 0xA0,
            "Reserved for Future Use", HFILL }
        },
        { &hf_data_header_close_isochronous_event,
            { "Close Isochronous Event",         "btle.data_header.close_isochronous_event",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_data_header_null_pdu_indicator,
            { "Null PDU Indicator",              "btle.data_header.null_pdu_indicator",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_data_header_control_subevent_sequence_number,
            { "Control Subevent Sequence Number", "btle.data_header.control_subevent_sequence_number",
            FT_UINT8, BASE_DEC, NULL, 0x1C,
            NULL, HFILL }
        },
        { &hf_data_header_control_subevent_transmission_flag,
            { "Control Subevent Transmission Flag", "btle.data_header.control_subevent_transmission_flag",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_control_opcode,
            { "Control Opcode",                  "btle.control_opcode",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &control_opcode_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_control_reject_opcode,
            { "Reject Opcode",                   "btle.control.reject_opcode",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &control_opcode_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_control_unknown_type,
            { "Unknown Type",                    "btle.control.unknown_type",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &control_opcode_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_control_error_code,
            { "Error Code",                      "btle.control.error_code",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &bthci_cmd_status_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_control_version_number,
            { "Version Number",                  "btle.control.version_number",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &ll_version_number_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_control_company_id,
            { "Company Id",                      "btle.control.company_id",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bluetooth_company_id_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_control_subversion_number,
            { "Subversion Number",               "btle.control.subversion_number",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_feature_set,
            { "Feature Set",                     "btle.control.feature_set",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_feature_set_le_encryption,
            { "LE Encryption",                   "btle.control.feature_set.le_encryption",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_control_feature_set_connection_parameters_request_procedure,
            { "Connection Parameters Request Procedure",   "btle.control.feature_set.connection_parameters_request_procedure",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_control_feature_set_extended_reject_indication,
            { "Extended Reject Indication",           "btle.control.feature_set.extended_reject_indication",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_control_feature_set_slave_initiated_features_exchange,
            { "Slave Initiated Features Exchange",    "btle.control.feature_set.slave_initiated_features_exchange",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_control_feature_set_le_ping,
            { "LE Ping",                         "btle.control.feature_set.le_ping",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_control_feature_set_le_pkt_len_ext,
        { "LE Data Packet Length Extension",          "btle.control.feature_set.le_pkt_len_ext",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_control_feature_set_ll_privacy,
        { "LL Privacy",          "btle.control.feature_set.le_privacy",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_control_feature_set_ext_scan_flt_pol,
        { "Extended Scanner Filter Policies",          "btle.control.feature_set.ext_scan_flt_pol",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_control_feature_set_le_2m_phy,
        { "LE 2M PHY", "btle.control.feature_set.le_2m_phy",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_control_feature_set_stable_modulation_index_transmitter,
        { "Stable Modulation Index - Transmitter", "btle.control.feature_set.st_mod_idx_tx",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_control_feature_set_stable_modulation_index_receiver,
        { "Stable Modulation Index - Receiver", "btle.control.feature_set.st_mod_idx_rx",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_control_feature_set_le_coded_phy,
        { "LE Coded PHY", "btle.control.feature_set.le_coded_phy",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_control_feature_set_le_extended_advertising,
        { "LE Extended Advertising", "btle.control.feature_set.le_extended_adv",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_control_feature_set_le_periodic_advertising,
        { "LE Periodic Advertising", "btle.control.feature_set.periodic_adv",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_control_feature_set_channel_selection_algorithm_2,
        { "Channel Selection Algorithm #2", "btle.control.feature_set.ch_sel_2",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_control_feature_set_le_power_class_1,
        { "LE Power Class 1", "btle.control.feature_set.le_power_class_1",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_control_feature_set_minimum_number_of_used_channels_procedure,
        { "Minimum Number of Used Channels Procedure", "btle.control.feature_set.min_num_used_ch_proc",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_control_feature_set_reserved_bits,
            { "Reserved", "btle.control.feature_set.reserved_bits",
            FT_UINT8, BASE_DEC, NULL, 0xFE,
            NULL, HFILL }
        },
        { &hf_control_feature_set_reserved,
            { "Reserved",                        "btle.control.feature_set.reserved",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_window_size,
            { "Window Size",                     "btle.control.window_size",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_window_offset,
            { "Window Offset",                   "btle.control.window_offset",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_interval,
            { "Interval",                        "btle.control.interval",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_latency,
            { "Latency",                         "btle.control.latency",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_timeout,
            { "Timeout",                         "btle.control.timeout",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_instant,
            { "Instant",                         "btle.control.instant",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_interval_min,
            { "Interval Min",                    "btle.control.interval.min",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_interval_max,
            { "Interval Max",                    "btle.control.interval.max",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_preferred_periodicity,
            { "Preferred Periodicity",           "btle.control.preferred_periodicity",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_reference_connection_event_count,
            { "Reference Connection Event Count","btle.control.reference_connection_event_count",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_offset_0,
            { "Offset 0",                        "btle.control.offset.0",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_offset_1,
            { "Offset 1",                        "btle.control.offset.1",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_offset_2,
            { "Offset 2",                        "btle.control.offset.2",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_offset_3,
            { "Offset 3",                        "btle.control.offset.3",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_offset_4,
            { "Offset 4",                        "btle.control.offset.4",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_offset_5,
            { "Offset 5",                        "btle.control.offset.5",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_channel_map,
            { "Channel Map",                     "btle.control.channel_map",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_random_number,
            { "Random Number",                   "btle.control.random_number",
            FT_UINT64, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_encrypted_diversifier,
            { "Encrypted Diversifier",           "btle.control.encrypted_diversifier",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_master_session_key_diversifier,
            { "Master Session Key Diversifier",  "btle.control.master_session_key_diversifier",
            FT_UINT64, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_slave_session_key_diversifier,
            { "Slave Session Key Diversifier",   "btle.control.slave_session_key_diversifier",
            FT_UINT64, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_master_session_initialization_vector,
            { "Master Session Initialization Vector",      "btle.control.master_session_initialization_vector",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_slave_session_initialization_vector,
            { "Slave Session Initialization Vector",       "btle.control.slave_session_initialization_vector",
            FT_UINT64, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_max_rx_octets,
            { "Max RX octets",   "btle.control.max_rx_octets",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_max_rx_time,
            { "Max RX time",     "btle.control.max_rx_time",
            FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_microsecond_microseconds, 0x0,
            NULL, HFILL }
        },
        { &hf_control_max_tx_octets,
            { "Max TX octets",   "btle.control.max_tx_octets",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_max_tx_time,
            { "Max TX time",     "btle.control.max_tx_time",
            FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_microsecond_microseconds, 0x0,
            NULL, HFILL }
        },
        { &hf_control_phys_sender_le_1m_phy,
            { "Sender prefers to use the LE 1M PHY", "btle.control.phys.le_1m_phy",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_control_phys_sender_le_2m_phy,
            { "Sender prefers to use the LE 2M PHY", "btle.control.phys.le_2m_phy",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_control_phys_sender_le_coded_phy,
            { "Sender prefers to use the LE Coded PHY", "btle.control.phys.le_coded_phy",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_control_phys_update_le_1m_phy,
            { "The LE 1M PHY shall be used", "btle.control.phys.le_1m_phy",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_control_phys_update_le_2m_phy,
            { "The LE 2M PHY shall be used", "btle.control.phys.le_2m_phy",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_control_phys_update_le_coded_phy,
            { "The LE Coded PHY shall be used", "btle.control.phys.le_coded_phy",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_control_phys_reserved_bits,
            { "Reserved for future use", "btle.control.phys.reserved",
            FT_UINT8, BASE_DEC, NULL, 0xF8,
            NULL, HFILL }
        },
        { &hf_control_tx_phys,
            { "TX PHYs", "btle.control.tx_phys",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_rx_phys,
            { "RX PHYs", "btle.control.rx_phys",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_m_to_s_phy,
            { "Master to Slave PHY", "btle.control.m_to_s_phy",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_m_to_s_phy_le_1m_phy,
            { "LE 1M PHY", "btle.control.m_to_s_phy.le_1m_phy",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_control_m_to_s_phy_le_2m_phy,
            { "LE 2M PHY", "btle.control.m_to_s_phy.le_2m_phy",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_control_m_to_s_phy_le_coded_phy,
            { "LE Coded PHY", "btle.control.m_to_s_phy.le_coded_phy",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_control_m_to_s_phy_reserved_bits,
            { "Reserved for future use", "btle.control.m_to_s_phy.reserved",
            FT_UINT8, BASE_DEC, NULL, 0xF8,
            NULL, HFILL }
        },
        { &hf_control_s_to_m_phy,
            { "Slave to Master PHY", "btle.control.s_to_m_phy",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_s_to_m_phy_le_1m_phy,
            { "LE 1M PHY", "btle.control.s_to_m_phy.le_1m_phy",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_control_s_to_m_phy_le_2m_phy,
            { "LE 2M PHY", "btle.control.s_to_m_phy.le_2m_phy",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_control_s_to_m_phy_le_coded_phy,
            { "LE Coded PHY", "btle.control.s_to_m_phy.le_coded_phy",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_control_s_to_m_phy_reserved_bits,
            { "Reserved for future use", "btle.control.s_to_m_phy.reserved",
            FT_UINT8, BASE_DEC, NULL, 0xF8,
            NULL, HFILL }
        },
        { &hf_control_phys,
            { "PHYs", "btle.control.phys",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_phys_le_1m_phy,
            { "LE 1M PHY", "btle.control.phys.le_1m_phy",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_control_phys_le_2m_phy,
            { "LE 2M PHY", "btle.control.phys.le_2m_phy",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_control_phys_le_coded_phy,
            { "LE Coded PHY", "btle.control.phys.le_coded_phy",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_control_min_used_channels,
            { "Minimum Used Channels", "btle.control.min_used_channels",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_cte_min_len_req,
           { "MinCTELenReq", "btle.control.cte.min_len_req",
            FT_UINT8, BASE_DEC, NULL, 0x1F,
            NULL, HFILL }
        },
        { &hf_control_cte_rfu,
           { "MinCTELenReq", "btle.control.cte.rfu",
            FT_UINT8, BASE_DEC, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_control_cte_type_req,
            { "CTETypeReq", "btle.control.cte.type_req",
            FT_UINT8, BASE_DEC, VALS(le_cte_type_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_control_sync_id,
            { "ID",                              "btle.control.sync.id",
            FT_UINT16, BASE_HEX, NULL, 0xFFFF,
            NULL, HFILL }
        },
        { &hf_control_sync_info_offset,
            { "Sync Offset",                     "btle.control.sync_info.sync_offset",
            FT_UINT16, BASE_HEX, NULL, 0x1FFF,
            NULL, HFILL }
        },
        { &hf_control_sync_info_offset_units,
            { "Offset Units",                    "btle.control.sync_info.offset_units",
            FT_BOOLEAN, 16, TFS(&tfs_offset_units), 0x2000,
            NULL, HFILL }
        },
        { &hf_control_sync_info_offset_adjust,
            { "Offset Adjust",                   "btle.control.sync_info.offset_adjust",
            FT_BOOLEAN, 16, TFS(&tfs_offset_adjust), 0x4000,
            NULL, HFILL }
        },
        { &hf_control_sync_info_reserved,
            { "Reserved",                        "btle.control.sync_info.offset_units",
            FT_BOOLEAN, 16, NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_control_sync_info_interval,
            { "Interval",                        "btle.control.sync_info.interval",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_control_sync_info_channel_map,
            { "Channel Map",                     "btle.control.sync_info.channel_map",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_sync_info_sleep_clock_accuracy,
            { "Sleep Clock Accuracy",            "btle.control.sync_info.sleep_clock_accuracy",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &sleep_clock_accuracy_vals_ext, 0xe0,
            NULL, HFILL }
        },
        { &hf_control_sync_info_access_address,
            { "Access Address",                  "btle.control.sync_info.access_address",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_sync_info_crc_init,
            { "CRC Init",                        "btle.control.sync_info.crc_init",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_sync_info_event_counter,
            { "Event counter",                   "btle.control.sync_info.event_counter",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_sync_conn_event_count,
            { "connEventCount",                  "btle.control.sync.conn_event_count",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_sync_last_pa_event_counter,
            { "lastPaEventCounter",              "btle.control.sync.last_pa_event_counter",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_sync_sid,
            { "SID",                             "btle.control.sync.sid",
            FT_UINT8, BASE_HEX, NULL, 0x0F,
            NULL, HFILL }
        },
        { &hf_control_sync_atype,
            { "AType",                           "btle.control.sync.atype",
            FT_UINT8, BASE_DEC, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_control_sync_sleep_clock_accuracy,
            { "Sleep Clock Accuracy",            "btle.control.sync.sleep_clock_accuracy",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &sleep_clock_accuracy_vals_ext, 0xE0,
            NULL, HFILL }
        },
        { &hf_control_sync_sync_conn_event_counter,
            { "syncConnEventCount",              "btle.control.sync.sync_conn_event_count",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_sleep_clock_accuracy,
            { "Sleep Clock Accuracy",            "btle.control.sleep_clock_accuracy",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &sleep_clock_accuracy_vals_ext, 0xe0,
            NULL, HFILL }
        },
        { &hf_control_cig_id,
            { "CIG_ID",                          "btle.control.cig_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_cis_id,
            { "CIS_ID",                          "btle.control.cis_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_max_sdu_m_to_s,
            { "Max_SDU_M_To_S",                  "btle.control.max_sdu_m_to_s",
            FT_UINT16, BASE_DEC, NULL, 0x0fff,
            NULL, HFILL }
        },
        { &hf_control_rfu_1,
            { "Reserved",                        "btle.control.rfu.1",
            FT_UINT16, BASE_DEC, NULL, 0x7000,
            "Reserved for Future Use", HFILL }
        },
        { &hf_control_framed,
            { "Framed",                          "btle.control.framed",
            FT_BOOLEAN, 16, NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_control_max_sdu_s_to_m,
            { "Max_SDU_S_To_M",                  "btle.control.max_sdu_s_to_m",
            FT_UINT16, BASE_DEC, NULL, 0x0fff,
            NULL, HFILL }
        },
        { &hf_control_rfu_2,
            { "Reserved",                        "btle.control.rfu.2",
            FT_UINT16, BASE_DEC, NULL, 0xf000,
            "Reserved for Future Use", HFILL }
        },
        { &hf_control_sdu_interval_m_to_s,
            { "SDU_Interval_M_To_S",             "btle.control.sdu_interval_m_to_s",
            FT_UINT24, BASE_DEC|BASE_UNIT_STRING, &units_microsecond_microseconds, 0x0fffff,
            NULL, HFILL }
        },
        { &hf_control_rfu_3,
            { "Reserved",                        "btle.control.rfu.3",
            FT_UINT24, BASE_DEC, NULL, 0xf00000,
            "Reserved for Future Use", HFILL }
        },
        { &hf_control_sdu_interval_s_to_m,
            { "SDU_Interval_S_To_M",             "btle.control.sdu_interval_s_to_m",
            FT_UINT24, BASE_DEC|BASE_UNIT_STRING, &units_microsecond_microseconds, 0x0fffff,
            NULL, HFILL }
        },
        { &hf_control_rfu_4,
            { "Reserved",                        "btle.control.rfu.4",
            FT_UINT24, BASE_DEC, NULL, 0xf00000,
            "Reserved for Future Use", HFILL }
        },
        { &hf_control_max_pdu_m_to_s,
            { "Max_PDU_M_To_S",                  "btle.control.max_pdu_m_to_s",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_max_pdu_s_to_m,
            { "Max_PDU_S_To_M",                  "btle.control.max_pdu_s_to_m",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_num_sub_events,
            { "Num_Sub_Events",                  "btle.control.num_sub_events",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_sub_interval,
            { "Sub_Interval",                    "btle.control.sub_interval",
            FT_UINT24, BASE_DEC|BASE_UNIT_STRING, &units_microsecond_microseconds, 0x0,
            NULL, HFILL }
        },
        { &hf_control_bn_m_to_s,
            { "BN_M_To_S",                       "btle.control.bn_m_to_s",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_control_bn_s_to_m,
            { "BN_S_To_M",                       "btle.control.bn_s_to_m",
            FT_UINT8, BASE_DEC, NULL, 0xf0,
            NULL, HFILL }
        },
        { &hf_control_ft_m_to_s,
            { "FT_M_To_S",                       "btle.control.ft_m_to_s",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_ft_s_to_m,
            { "FT_S_To_M",                       "btle.control.ft_s_to_m",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_iso_interval,
            { "ISO_Interval",                    "btle.control.iso_interval",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_cis_offset_min,
            { "CIS_Offset_Min",                  "btle.control.cis_offset_min",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_cis_offset_max,
            { "CIS_Offset_Max",                  "btle.control.cis_offset_max",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_conn_event_count,
            { "connEventCount",                  "btle.control.conn_event_count",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_access_address,
            { "Access Address",                  "btle.control.access_address",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_cis_offset,
            { "CIS_Offset",                      "btle.control.cis_offset",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_cig_sync_delay,
            { "CIG_Sync_Delay",                  "btle.control.cig_sync_delay",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_cis_sync_delay,
            { "CIS_Sync_Delay",                  "btle.control.cis_sync_delay",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_pwr_phy,
            { "Power PHY", "btle.control.pwr_phy",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_pwr_phy_le_1m_phy,
            { "LE 1M PHY", "btle.control.pwr_phy.le_1m_phy",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_control_pwr_phy_le_2m_phy,
            { "LE 2M PHY", "btle.control.pwr_phy.le_2m_phy",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_control_pwr_phy_le_coded_s8_phy,
            { "LE Coded S=8 PHY", "btle.control.pwr_phy.le_coded_s8_phy",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_control_pwr_phy_le_coded_s2_phy,
            { "LE Coded S=2 PHY", "btle.control.pwr_phy.le_coded_s2_phy",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_control_pwr_phy_reserved_bits,
            { "Reserved for future use", "btle.control.pwr_phy.reserved",
            FT_UINT8, BASE_DEC, NULL, 0xF0,
            NULL, HFILL }
        },
        { &hf_control_delta,
            { "Delta", "btle.control.delta",
            FT_INT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_txpwr,
            { "TxPower", "btle.control.txpower",
            FT_INT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_pwrflags,
           { "Power Flags", "btle.control.pwrflags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_pwrflags_min,
            { "Min", "btle.control.min",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_control_pwrflags_max,
            { "Max", "btle.control.max",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_control_pwrflags_reserved_bits,
            { "Reserved for future use", "btle.control.pwrctrl.reserved",
            FT_UINT8, BASE_DEC, NULL, 0xFC,
            NULL, HFILL }
        },
        { &hf_control_acceptable_power_reduction,
            { "Acceptable Power Reduction", "btle.control.acceptable_power_reduction",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_big_control_opcode,
            { "BIG Control Opcode",              "btle.big_control_opcode",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &big_control_opcode_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_l2cap_index,
            { "L2CAP Index",                     "btle.l2cap_index",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_l2cap_fragment,
            { "L2CAP Fragment",                  "btle.l2cap_data",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_connection_parameters_in,
          { "Connection Parameters in",     "btle.connection_parameters_in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_crc,
          { "CRC",                             "btle.crc",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isochronous_data,
          { "Isochronous Data",                "btle.isochronous_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btle_l2cap_msg_fragments,
          { "L2CAP fragments", "btle.l2cap.fragments",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btle_l2cap_msg_fragment,
          { "L2CAP fragment", "btle.l2cap.fragment",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btle_l2cap_msg_fragment_overlap,
          { "L2CAP fragment overlap", "btle.l2cap.fragment.overlap",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btle_l2cap_msg_fragment_overlap_conflicts,
          { "L2CAP fragment overlapping with conflicting data", "btle.l2cap.fragment.overlap.conflicts",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btle_l2cap_msg_fragment_multiple_tails,
          { "L2CAP has multiple tail fragments", "btle.l2cap.fragment.multiple_tails",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btle_l2cap_msg_fragment_too_long_fragment,
          { "L2CAP fragment too long", "btle.l2cap.fragment.too_long_fragment",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btle_l2cap_msg_fragment_error,
          { "L2CAP defragmentation error", "btle.l2cap.fragment.error",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btle_l2cap_msg_fragment_count,
          { "L2CAP fragment count", "btle.l2cap.fragment.count",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btle_l2cap_msg_reassembled_in,
          { "Reassembled in", "btle.l2cap.reassembled.in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btle_l2cap_msg_reassembled_length,
          { "Reassembled L2CAP length", "btle.l2cap.reassembled.length",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btle_ea_host_advertising_data_fragments,
          { "EA HAD fragments", "btle.ea.host_advertising_data.fragments",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btle_ea_host_advertising_data_fragment,
          { "EA HAD fragment", "btle.ea.host_advertising_data.fragment",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btle_ea_host_advertising_data_fragment_overlap,
          { "EA HAD fragment overlap", "btle.ea.host_advertising_data.fragment.overlap",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btle_ea_host_advertising_data_fragment_overlap_conflicts,
          { "EA HAD fragment overlapping with conflicting data", "btle.ea.host_advertising_data.fragment.overlap.conflicts",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btle_ea_host_advertising_data_fragment_multiple_tails,
          { "EA HAD has multiple tail fragments", "btle.ea.host_advertising_data.fragment.multiple_tails",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btle_ea_host_advertising_data_fragment_too_long_fragment,
          { "EA HAD fragment too long", "btle.ea.host_advertising_data.fragment.too_long_fragment",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btle_ea_host_advertising_data_fragment_error,
          { "EA HAD defragmentation error", "btle.ea.host_advertising_data.fragment.error",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btle_ea_host_advertising_data_fragment_count,
          { "EA HAD fragment count", "btle.ea.host_advertising_data.fragment.count",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btle_ea_host_advertising_data_reassembled_in,
          { "Reassembled in", "btle.ea.host_advertising_data.reassembled.in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btle_ea_host_advertising_data_reassembled_length,
          { "Reassembled EA HAD length", "btle.ea.host_advertising_data.reassembled.length",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_request_in_frame,
          {"Request in Frame", "btle.request_in_frame",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
            NULL, HFILL}
        },
        { &hf_response_in_frame,
          {"Response in Frame", "btle.response_in_frame",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
            NULL, HFILL}
        },
    };

    static ei_register_info ei[] = {
        { &ei_unknown_data,
            { "btle.unknown_data",              PI_PROTOCOL, PI_NOTE,  "Unknown data", EXPFILL }},
        { &ei_access_address_matched,
            { "btle.access_address.matched",    PI_PROTOCOL, PI_NOTE,  "AccessAddress matched at capture", EXPFILL }},
        { &ei_access_address_bit_errors,
            { "btle.access_address.bit_errors", PI_PROTOCOL, PI_WARN,  "AccessAddress has errors present at capture", EXPFILL }},
        { &ei_access_address_illegal,
            { "btle.access_address.illegal",    PI_PROTOCOL, PI_ERROR, "AccessAddress has illegal value", EXPFILL }},
        { &ei_control_proc_overlapping,
            { "btle.control_proc_overlapping",  PI_PROTOCOL, PI_ERROR, "Initiating a new control procedure before the previous was complete", EXPFILL }},
        { &ei_control_proc_invalid_collision,
            { "btle.control_proc_incompatible", PI_PROTOCOL, PI_ERROR, "Initiating a new incompatible control procedure after having sent a response to an incompatible control procedure", EXPFILL }},
        { &ei_control_proc_wrong_seq,
            { "btle.control_proc_unknown_seq",  PI_PROTOCOL, PI_ERROR, "Incorrect control procedure packet sequencing or direction", EXPFILL }},
        { &ei_crc_cannot_be_determined,
            { "btle.crc.indeterminate",         PI_CHECKSUM, PI_NOTE,  "CRC unchecked, not all data available", EXPFILL }},
        { &ei_crc_incorrect,
            { "btle.crc.incorrect",             PI_CHECKSUM, PI_WARN,  "Incorrect CRC", EXPFILL }},
        { &ei_missing_fragment_start,
            { "btle.missing_fragment_start",    PI_SEQUENCE, PI_WARN,  "Missing Fragment Start", EXPFILL }},
        { &ei_retransmit,
            { "btle.retransmit",                PI_SEQUENCE, PI_NOTE,  "Retransmission", EXPFILL }},
        { &ei_nack,
            { "btle.nack",                      PI_SEQUENCE, PI_NOTE,  "Not acknowledged", EXPFILL }},
    };

    static gint *ett[] = {
        &ett_btle,
        &ett_advertising_header,
        &ett_link_layer_data,
        &ett_extended_advertising_header,
        &ett_extended_advertising_flags,
        &ett_extended_advertising_cte_info,
        &ett_extended_advertising_data_info,
        &ett_extended_advertising_aux_pointer,
        &ett_extended_advertising_sync_info,
        &ett_extended_advertising_acad,
        &ett_data_header,
        &ett_data_header_cte_info,
        &ett_features,
        &ett_tx_phys,
        &ett_rx_phys,
        &ett_m_to_s_phy,
        &ett_s_to_m_phy,
        &ett_phys,
        &ett_pwr_phy,
        &ett_cte,
        &ett_channel_map,
        &ett_scan_response_data,
        &ett_pwrflags,
        &ett_btle_l2cap_msg_fragment,
        &ett_btle_l2cap_msg_fragments,
        &ett_btle_ea_host_advertising_data_fragment,
        &ett_btle_ea_host_advertising_data_fragments
    };

    connection_info_tree = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    broadcastiso_connection_info_tree = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    connection_parameter_info_tree = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    adi_to_first_frame_tree = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    proto_btle = proto_register_protocol("Bluetooth Low Energy Link Layer",
            "BT LE LL", "btle");
    btle_handle = register_dissector("btle", dissect_btle, proto_btle);

    proto_register_field_array(proto_btle, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_module = expert_register_protocol(proto_btle);
    expert_register_field_array(expert_module, ei, array_length(ei));

    module = prefs_register_protocol_subtree("Bluetooth", proto_btle, NULL);
    prefs_register_static_text_preference(module, "version",
            "Bluetooth LE LL version: 5.0 (Core)",
            "Version of protocol supported by this dissector.");

    prefs_register_bool_preference(module, "detect_retransmit",
                                   "Detect retransmission",
                                   "Detect retransmission based on SN (Sequence Number)",
                                   &btle_detect_retransmit);

    reassembly_table_register(&btle_l2cap_msg_reassembly_table,
        &addresses_reassembly_table_functions);

    reassembly_table_register(&btle_ea_host_advertising_data_reassembly_table,
        &addresses_reassembly_table_functions);

    register_init_routine(btle_init);
}

void
proto_reg_handoff_btle(void)
{
    btcommon_ad_handle = find_dissector_add_dependency("btcommon.eir_ad.ad", proto_btle);
    btcommon_le_channel_map_handle = find_dissector_add_dependency("btcommon.le_channel_map", proto_btle);
    btl2cap_handle = find_dissector_add_dependency("btl2cap", proto_btle);

    proto_btle_rf = proto_get_id_by_filter_name("btle_rf");
    proto_nordic_ble = proto_get_id_by_filter_name("nordic_ble");

    dissector_add_uint("bluetooth.encap", WTAP_ENCAP_BLUETOOTH_LE_LL, btle_handle);
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
