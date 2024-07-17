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

static int proto_btle;
static int proto_btle_rf;
static int proto_nordic_ble;

static int hf_access_address;
static int hf_coding_indicator;
static int hf_crc;
static int hf_central_bd_addr;
static int hf_peripheral_bd_addr;
static int hf_length;
static int hf_advertising_header;
static int hf_advertising_header_pdu_type;
static int hf_advertising_header_ch_sel;
static int hf_advertising_header_rfu_1;
static int hf_advertising_header_rfu_2;
static int hf_advertising_header_rfu_3;
static int hf_advertising_header_rfu_4;
static int hf_advertising_header_randomized_tx;
static int hf_advertising_header_randomized_rx;
static int hf_advertising_header_length;
static int hf_advertising_address;
static int hf_initiator_addresss;
static int hf_target_addresss;
static int hf_scanning_address;
static int hf_scan_response_data;
static int hf_link_layer_data;
static int hf_link_layer_data_access_address;
static int hf_link_layer_data_crc_init;
static int hf_link_layer_data_window_size;
static int hf_link_layer_data_window_offset;
static int hf_link_layer_data_interval;
static int hf_link_layer_data_latency;
static int hf_link_layer_data_timeout;
static int hf_link_layer_data_channel_map;
static int hf_link_layer_data_hop;
static int hf_link_layer_data_sleep_clock_accuracy;
static int hf_extended_advertising_header;
static int hf_extended_advertising_header_length;
static int hf_extended_advertising_mode;
static int hf_extended_advertising_flags;
static int hf_extended_advertising_flags_adva;
static int hf_extended_advertising_flags_targeta;
static int hf_extended_advertising_flags_cte_info;
static int hf_extended_advertising_flags_advdatainfo;
static int hf_extended_advertising_flags_aux_ptr;
static int hf_extended_advertising_flags_sync_info;
static int hf_extended_advertising_flags_tx_power;
static int hf_extended_advertising_flags_reserved;
static int hf_extended_advertising_cte_info;
static int hf_extended_advertising_cte_info_time;
static int hf_extended_advertising_cte_info_rfu;
static int hf_extended_advertising_cte_info_type;
static int hf_extended_advertising_data_info;
static int hf_extended_advertising_data_info_did;
static int hf_extended_advertising_data_info_sid;
static int hf_extended_advertising_aux_ptr;
static int hf_extended_advertising_aux_ptr_channel;
static int hf_extended_advertising_aux_ptr_ca;
static int hf_extended_advertising_aux_ptr_offset_units;
static int hf_extended_advertising_aux_ptr_aux_offset;
static int hf_extended_advertising_aux_ptr_aux_phy;
static int hf_extended_advertising_sync_info;
static int hf_extended_advertising_sync_info_offset;
static int hf_extended_advertising_sync_info_offset_units;
static int hf_extended_advertising_sync_info_offset_adjust;
static int hf_extended_advertising_sync_info_reserved;
static int hf_extended_advertising_sync_info_interval;
static int hf_extended_advertising_sync_info_channel_map;
static int hf_extended_advertising_sync_info_sleep_clock_accuracy;
static int hf_extended_advertising_sync_info_access_address;
static int hf_extended_advertising_sync_info_crc_init;
static int hf_extended_advertising_sync_info_event_counter;
static int hf_extended_advertising_tx_power;
static int hf_extended_advertising_header_acad;
static int hf_extended_advertising_had_fragment;
static int hf_data_header;
static int hf_data_header_length;
static int hf_data_header_rfu;
static int hf_data_header_llid;
static int hf_data_header_llid_connectediso;
static int hf_data_header_llid_broadcastiso;
static int hf_data_header_more_data;
static int hf_data_header_cte_info_present;
static int hf_data_header_sequence_number;
static int hf_data_header_next_expected_sequence_number;
static int hf_data_header_rfu_57;
static int hf_data_header_rfu_67;
static int hf_data_header_close_isochronous_event;
static int hf_data_header_null_pdu_indicator;
static int hf_data_header_control_subevent_sequence_number;
static int hf_data_header_control_subevent_transmission_flag;
static int hf_data_header_cte_info;
static int hf_data_header_cte_info_time;
static int hf_data_header_cte_info_rfu;
static int hf_data_header_cte_info_type;
static int hf_control_opcode;
static int hf_l2cap_index;
static int hf_l2cap_fragment;
static int hf_connection_parameters_in;
static int hf_control_reject_opcode;
static int hf_control_error_code;
static int hf_control_unknown_type;
static int hf_control_version_number;
static int hf_control_company_id;
static int hf_control_subversion_number;
static int hf_control_feature_set;
static int hf_control_feature_set_le_encryption;
static int hf_control_feature_set_connection_parameters_request_procedure;
static int hf_control_feature_set_extended_reject_indication;
static int hf_control_feature_set_peripheral_initiated_features_exchange;
static int hf_control_feature_set_le_ping;
static int hf_control_feature_set_le_pkt_len_ext;
static int hf_control_feature_set_ll_privacy;
static int hf_control_feature_set_ext_scan_flt_pol;
static int hf_control_feature_set_le_2m_phy;
static int hf_control_feature_set_stable_modulation_index_transmitter;
static int hf_control_feature_set_stable_modulation_index_receiver;
static int hf_control_feature_set_le_coded_phy;
static int hf_control_feature_set_le_extended_advertising;
static int hf_control_feature_set_le_periodic_advertising;
static int hf_control_feature_set_channel_selection_algorithm_2;
static int hf_control_feature_set_le_power_class_1;
static int hf_control_feature_set_minimum_number_of_used_channels_procedure;
static int hf_control_feature_set_connection_cte_request;
static int hf_control_feature_set_connection_cte_response;
static int hf_control_feature_set_connectionless_cte_tx;
static int hf_control_feature_set_connectionless_cte_rx;
static int hf_control_feature_set_antenna_switching_tx_aod;
static int hf_control_feature_set_antenna_switching_rx_aoa;
static int hf_control_feature_set_cte_rx;
static int hf_control_feature_set_past_sender;
static int hf_control_feature_set_past_receiver;
static int hf_control_feature_set_sca_updates;
static int hf_control_feature_set_remote_public_key_validation;
static int hf_control_feature_set_cis_central;
static int hf_control_feature_set_cis_peripheral;
static int hf_control_feature_set_iso_broadcast;
static int hf_control_feature_set_synchronized_receiver;
static int hf_control_feature_set_connected_iso_host_support;
static int hf_control_feature_set_le_power_control_request1;
static int hf_control_feature_set_le_power_control_request2;
static int hf_control_feature_set_le_path_loss_monitoring;
static int hf_control_feature_set_le_periodic_adv_adi_support;
static int hf_control_feature_set_connection_subrating;
static int hf_control_feature_set_connection_subrating_host_support;
static int hf_control_feature_set_channel_classification;
static int hf_control_feature_set_adv_coding_selection;
static int hf_control_feature_set_adv_coding_selection_host_support;
static int hf_control_feature_set_periodic_adv_with_responses_advertiser;
static int hf_control_feature_set_periodic_adv_with_responses_scanner;
static int hf_control_feature_set_reserved_bits;
static int hf_control_feature_set_reserved;
static int hf_control_window_size;
static int hf_control_window_offset;
static int hf_control_interval;
static int hf_control_latency;
static int hf_control_timeout;
static int hf_control_instant;
static int hf_control_rfu_5;
static int hf_control_interval_min;
static int hf_control_interval_max;
static int hf_control_preferred_periodicity;
static int hf_control_reference_connection_event_count;
static int hf_control_offset_0;
static int hf_control_offset_1;
static int hf_control_offset_2;
static int hf_control_offset_3;
static int hf_control_offset_4;
static int hf_control_offset_5;
static int hf_control_channel_map;
static int hf_control_random_number;
static int hf_control_encrypted_diversifier;
static int hf_control_central_session_key_diversifier;
static int hf_control_central_session_initialization_vector;
static int hf_control_peripheral_session_key_diversifier;
static int hf_control_peripheral_session_initialization_vector;
static int hf_control_max_rx_octets;
static int hf_control_max_rx_time;
static int hf_control_max_tx_octets;
static int hf_control_max_tx_time;
static int hf_control_phys_sender_le_1m_phy;
static int hf_control_phys_sender_le_2m_phy;
static int hf_control_phys_sender_le_coded_phy;
static int hf_control_phys_update_le_1m_phy;
static int hf_control_phys_update_le_2m_phy;
static int hf_control_phys_update_le_coded_phy;
static int hf_control_phys_reserved_bits;
static int hf_control_tx_phys;
static int hf_control_rx_phys;
static int hf_control_c_to_p_phy;
static int hf_control_c_to_p_phy_le_1m_phy;
static int hf_control_c_to_p_phy_le_2m_phy;
static int hf_control_c_to_p_phy_le_coded_phy;
static int hf_control_c_to_p_phy_reserved_bits;
static int hf_control_p_to_c_phy;
static int hf_control_p_to_c_phy_le_1m_phy;
static int hf_control_p_to_c_phy_le_2m_phy;
static int hf_control_p_to_c_phy_le_coded_phy;
static int hf_control_p_to_c_phy_reserved_bits;
static int hf_control_phys;
static int hf_control_phys_le_1m_phy;
static int hf_control_phys_le_2m_phy;
static int hf_control_phys_le_coded_phy;
static int hf_control_min_used_channels;
static int hf_control_cte_min_len_req;
static int hf_control_cte_rfu;
static int hf_control_cte_type_req;
static int hf_control_sync_id;
static int hf_control_sync_info_offset;
static int hf_control_sync_info_offset_units;
static int hf_control_sync_info_offset_adjust;
static int hf_control_sync_info_reserved;
static int hf_control_sync_info_interval;
static int hf_control_sync_info_channel_map;
static int hf_control_sync_info_sleep_clock_accuracy;
static int hf_control_sync_info_access_address;
static int hf_control_sync_info_crc_init;
static int hf_control_sync_info_event_counter;
static int hf_control_sync_conn_event_count;
static int hf_control_sync_last_pa_event_counter;
static int hf_control_sync_sid;
static int hf_control_sync_atype;
static int hf_control_sync_sleep_clock_accuracy;
static int hf_control_sync_sync_conn_event_counter;
static int hf_control_sleep_clock_accuracy;
static int hf_control_cig_id;
static int hf_control_cis_id;
static int hf_control_max_sdu_c_to_p;
static int hf_control_rfu_1;
static int hf_control_framed;
static int hf_control_max_sdu_p_to_c;
static int hf_control_rfu_2;
static int hf_control_sdu_interval_c_to_p;
static int hf_control_rfu_3;
static int hf_control_sdu_interval_p_to_c;
static int hf_control_rfu_4;
static int hf_control_max_pdu_c_to_p;
static int hf_control_max_pdu_p_to_c;
static int hf_control_num_sub_events;
static int hf_control_sub_interval;
static int hf_control_bn_c_to_p;
static int hf_control_bn_p_to_c;
static int hf_control_ft_c_to_p;
static int hf_control_ft_p_to_c;
static int hf_control_iso_interval;
static int hf_control_cis_offset_min;
static int hf_control_cis_offset_max;
static int hf_control_conn_event_count;
static int hf_control_access_address;
static int hf_control_cis_offset;
static int hf_control_cig_sync_delay;
static int hf_control_cis_sync_delay;
static int hf_control_pwr_phy;
static int hf_control_pwr_phy_le_1m_phy;
static int hf_control_pwr_phy_le_2m_phy;
static int hf_control_pwr_phy_le_coded_s8_phy;
static int hf_control_pwr_phy_le_coded_s2_phy;
static int hf_control_pwr_phy_reserved_bits;
static int hf_control_delta;
static int hf_control_txpwr;
static int hf_control_pwrflags;
static int hf_control_pwrflags_min;
static int hf_control_pwrflags_max;
static int hf_control_pwrflags_reserved_bits;
static int hf_control_acceptable_power_reduction;
static int hf_control_subrate_factor_min;
static int hf_control_subrate_factor_max;
static int hf_control_max_latency;
static int hf_control_continuation_number;
static int hf_control_subrate_factor;
static int hf_control_subrate_base_event;
static int hf_control_channel_reporting_enable;
static int hf_control_channel_reporting_min_spacing;
static int hf_control_channel_reporting_max_delay;
static int hf_control_channel_classification;
static int hf_control_sync_info_rsp_access_address;
static int hf_control_sync_info_num_subevents;
static int hf_control_sync_info_subevent_interval;
static int hf_control_sync_info_response_slot_delay;
static int hf_control_sync_info_response_slot_spacing;
static int hf_big_control_opcode;
static int hf_isochronous_data;
static int hf_btle_l2cap_msg_fragments;
static int hf_btle_l2cap_msg_fragment;
static int hf_btle_l2cap_msg_fragment_overlap;
static int hf_btle_l2cap_msg_fragment_overlap_conflicts;
static int hf_btle_l2cap_msg_fragment_multiple_tails;
static int hf_btle_l2cap_msg_fragment_too_long_fragment;
static int hf_btle_l2cap_msg_fragment_error;
static int hf_btle_l2cap_msg_fragment_count;
static int hf_btle_l2cap_msg_reassembled_in;
static int hf_btle_l2cap_msg_reassembled_length;
static int hf_btle_ea_host_advertising_data_fragments;
static int hf_btle_ea_host_advertising_data_fragment;
static int hf_btle_ea_host_advertising_data_fragment_overlap;
static int hf_btle_ea_host_advertising_data_fragment_overlap_conflicts;
static int hf_btle_ea_host_advertising_data_fragment_multiple_tails;
static int hf_btle_ea_host_advertising_data_fragment_too_long_fragment;
static int hf_btle_ea_host_advertising_data_fragment_error;
static int hf_btle_ea_host_advertising_data_fragment_count;
static int hf_btle_ea_host_advertising_data_reassembled_in;
static int hf_btle_ea_host_advertising_data_reassembled_length;

static int hf_request_in_frame;
static int hf_response_in_frame;

static int ett_btle;
static int ett_advertising_header;
static int ett_link_layer_data;
static int ett_data_header;
static int ett_data_header_cte_info;
static int ett_features;
static int ett_tx_phys;
static int ett_rx_phys;
static int ett_c_to_p_phy;
static int ett_p_to_c_phy;
static int ett_phys;
static int ett_pwr_phy;
static int ett_cte;
static int ett_channel_map;
static int ett_scan_response_data;
static int ett_pwrflags;
static int ett_btle_l2cap_msg_fragment;
static int ett_btle_l2cap_msg_fragments;
static int ett_btle_ea_host_advertising_data_fragment;
static int ett_btle_ea_host_advertising_data_fragments;
static int ett_extended_advertising_header;
static int ett_extended_advertising_flags;
static int ett_extended_advertising_cte_info;
static int ett_extended_advertising_data_info;
static int ett_extended_advertising_aux_pointer;
static int ett_extended_advertising_sync_info;
static int ett_extended_advertising_acad;

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
    &hf_control_feature_set_peripheral_initiated_features_exchange,
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
    &hf_control_feature_set_connection_cte_request,
    &hf_control_feature_set_connection_cte_response,
    &hf_control_feature_set_connectionless_cte_tx,
    &hf_control_feature_set_connectionless_cte_rx,
    &hf_control_feature_set_antenna_switching_tx_aod,
    &hf_control_feature_set_antenna_switching_rx_aoa,
    &hf_control_feature_set_cte_rx,
    NULL
};

static int * const hfx_control_feature_set_4[] = {
    &hf_control_feature_set_past_sender,
    &hf_control_feature_set_past_receiver,
    &hf_control_feature_set_sca_updates,
    &hf_control_feature_set_remote_public_key_validation,
    &hf_control_feature_set_cis_central,
    &hf_control_feature_set_cis_peripheral,
    &hf_control_feature_set_iso_broadcast,
    &hf_control_feature_set_synchronized_receiver,
    NULL
};

static int * const hfx_control_feature_set_5[] = {
    &hf_control_feature_set_connected_iso_host_support,
    &hf_control_feature_set_le_power_control_request1,
    &hf_control_feature_set_le_power_control_request2,
    &hf_control_feature_set_le_path_loss_monitoring,
    &hf_control_feature_set_le_periodic_adv_adi_support,
    &hf_control_feature_set_connection_subrating,
    &hf_control_feature_set_connection_subrating_host_support,
    &hf_control_feature_set_channel_classification,
    NULL
};

static int *const hfx_control_feature_set_6[] = {
    &hf_control_feature_set_adv_coding_selection,
    &hf_control_feature_set_adv_coding_selection_host_support,
    &hf_control_feature_set_periodic_adv_with_responses_advertiser,
    &hf_control_feature_set_periodic_adv_with_responses_scanner,
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

static int * const hfx_control_c_to_p_phy[] = {
    &hf_control_c_to_p_phy_le_1m_phy,
    &hf_control_c_to_p_phy_le_2m_phy,
    &hf_control_c_to_p_phy_le_coded_phy,
    &hf_control_c_to_p_phy_reserved_bits,
    NULL
};

static int * const hfx_control_p_to_c_phy[] = {
    &hf_control_p_to_c_phy_le_1m_phy,
    &hf_control_p_to_c_phy_le_2m_phy,
    &hf_control_p_to_c_phy_le_coded_phy,
    &hf_control_p_to_c_phy_reserved_bits,
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

static expert_field ei_unknown_data;
static expert_field ei_access_address_matched;
static expert_field ei_access_address_bit_errors;
static expert_field ei_access_address_illegal;
static expert_field ei_crc_cannot_be_determined;
static expert_field ei_crc_incorrect;
static expert_field ei_missing_fragment_start;
static expert_field ei_retransmit;
static expert_field ei_nack;
static expert_field ei_control_proc_overlapping;
static expert_field ei_control_proc_invalid_collision;
static expert_field ei_control_proc_wrong_seq;
static expert_field ei_control_proc_invalid_conflict_resolution;

static dissector_handle_t btle_handle;
static dissector_handle_t btcommon_ad_handle;
static dissector_handle_t btcommon_le_channel_map_handle;
static dissector_handle_t btl2cap_handle;

static wmem_tree_t *connection_info_tree;
static wmem_tree_t *periodic_adv_info_tree;
static wmem_tree_t *broadcastiso_connection_info_tree;
static wmem_tree_t *connection_parameter_info_tree;
static wmem_tree_t *adi_to_first_frame_tree;
static uint32_t l2cap_index;

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
    unsigned  fragment_counter;
    uint32_t first_frame_num;
    address adv_addr;
} ae_had_info_t;

typedef struct _control_proc_info_t {
    /* Sequence of frame numbers of the control procedure used for request/response matching.
     * The first entry corresponds to the request, the remaining frames are responses.
     * The longest sequence is needed for the encryption start procedure,
     * which consists of 5 frames. */
    unsigned  frames[5];

    /* Opcode of the first control procedure packet. */
    uint8_t proc_opcode;

    /* The frame where the procedure completes. Set to 0 when not yet known.
     * This is used to avoid adding another frame to the control procedure
     * sequence after the procedure was aborted early.
     *
     * This frame number may be ignored in the case where an LL_UNKNOWN_RSP is
     * received after a procedure involving only one packet, like the
     * LL_MIN_USED_CHANNELS_IND. */
    unsigned  last_frame;

    /* The frame number of the packet containing the instant value.
     * If set to 0, there is no such frame.
     *
     * We need to store this frame number, as any event counter is
     * a valid instant. */
    unsigned   frame_with_instant_value;

    /* The event counter corresponding to the instant of the control procedure. */
    uint16_t instant;
} control_proc_info_t;

/* Store information about a connection direction */
typedef struct _direction_info_t {
    unsigned prev_seq_num : 1;          /* Previous sequence number for this direction */
    unsigned segmentation_started : 1;  /* 0 = No, 1 = Yes */
    unsigned segment_len_rem;           /* The remaining segment length, used to find last segment */
    uint32_t l2cap_index;               /* Unique identifier for each L2CAP message */

    wmem_tree_t *control_procs;         /* Control procedures initiated from this direction. */
} direction_info_t;

typedef struct _connection_parameter_info_t {
    uint32_t parameters_frame;
} connection_parameter_info_t;

/* Store information about a connection */
typedef struct _connection_info_t {
    /* Address information */
    uint32_t interface_id;
    uint32_t adapter_id;
    uint32_t access_address;
    uint32_t crc_init;

    uint8_t  central_bd_addr[6];
    uint8_t  peripheral_bd_addr[6];

    uint16_t connection_parameter_update_instant;
    connection_parameter_info_t *connection_parameter_update_info;

    /* Connection information */
    /* Data used on the first pass to get info from previous frame, result will be in per_packet_data */
    unsigned first_data_frame_seen : 1;
    direction_info_t direction_info[3];  /* UNKNOWN, CENTRAL_PERIPHERAL and PERIPHERAL_CENTRAL */
} connection_info_t;

/* Store information about a broadcast isochronous connection */
typedef struct _broadcastiso_connection_info_t {
    /* Address information */
    uint32_t interface_id;
    uint32_t adapter_id;
    uint32_t access_address;

    uint8_t  central_bd_addr[6];
} broadcastiso_connection_info_t;

/* */
typedef struct _btle_frame_info_t {
    unsigned retransmit : 1;      /* 0 = No, 1 = Retransmitted frame */
    unsigned ack : 1;             /* 0 = Nack, 1 = Ack */
    unsigned more_fragments : 1;  /* 0 = Last fragment, 1 = More fragments */
    unsigned missing_start : 1;   /* 0 = No, 1 = Missing fragment start */
    uint32_t l2cap_index;         /* Unique identifier for each L2CAP message */
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

typedef enum
{
    LL_CTRL_OPCODE_CONNECTION_UPDATE_IND = 0x00,
    LL_CTRL_OPCODE_CHANNEL_MAP_IND = 0x01,
    LL_CTRL_OPCODE_TERMINATE_IND = 0x02,
    LL_CTRL_OPCODE_ENC_REQ = 0x03,
    LL_CTRL_OPCODE_ENC_RSP = 0x04,
    LL_CTRL_OPCODE_START_ENC_REQ = 0x05,
    LL_CTRL_OPCODE_START_ENC_RSP = 0x06,
    LL_CTRL_OPCODE_UNKNOWN_RSP = 0x07,
    LL_CTRL_OPCODE_FEATURE_REQ = 0x08,
    LL_CTRL_OPCODE_FEATURE_RSP = 0x09,
    LL_CTRL_OPCODE_PAUSE_ENC_REQ = 0x0A,
    LL_CTRL_OPCODE_PAUSE_ENC_RSP = 0x0B,
    LL_CTRL_OPCODE_VERSION_IND = 0x0C,
    LL_CTRL_OPCODE_REJECT_IND = 0x0D,
    LL_CTRL_OPCODE_PERIPHERAL_FEATURE_REQ = 0x0E,
    LL_CTRL_OPCODE_CONNECTION_PARAM_REQ = 0x0F,
    LL_CTRL_OPCODE_CONNECTION_PARAM_RSP = 0x10,
    LL_CTRL_OPCODE_REJECT_EXT_IND = 0x11,
    LL_CTRL_OPCODE_PING_REQ = 0x12,
    LL_CTRL_OPCODE_PING_RSP = 0x13,
    LL_CTRL_OPCODE_LENGTH_REQ = 0x14,
    LL_CTRL_OPCODE_LENGTH_RSP = 0x15,
    LL_CTRL_OPCODE_PHY_REQ = 0x16,
    LL_CTRL_OPCODE_PHY_RSP = 0x17,
    LL_CTRL_OPCODE_PHY_UPDATE_IND = 0x18,
    LL_CTRL_OPCODE_MIN_USED_CHANNELS_IND = 0x19,
    LL_CTRL_OPCODE_CTE_REQ = 0x1A,
    LL_CTRL_OPCODE_CTE_RSP = 0x1B,
    LL_CTRL_OPCODE_PERIODIC_SYNC_IND = 0x1C,
    LL_CTRL_OPCODE_CLOCK_ACCURACY_REQ = 0x1D,
    LL_CTRL_OPCODE_CLOCK_ACCURACY_RSP = 0x1E,
    LL_CTRL_OPCODE_CIS_REQ = 0x1F,
    LL_CTRL_OPCODE_CIS_RSP = 0x20,
    LL_CTRL_OPCODE_CIS_IND = 0x21,
    LL_CTRL_OPCODE_CIS_TERMINATE_IND = 0x22,
    LL_CTRL_OPCODE_POWER_CONTROL_REQ = 0x23,
    LL_CTRL_OPCODE_POWER_CONTROL_RSP = 0x24,
    LL_CTRL_OPCODE_POWER_CHANGE_IND = 0x25,
    LL_CTRL_OPCODE_SUBRATE_REQ = 0x26,
    LL_CTRL_OPCODE_SUBRATE_IND = 0x27,
    LL_CTRL_OPCODE_CHANNEL_REPORTING_IND = 0x28,
    LL_CTRL_OPCODE_CHANNEL_STATUS_IND = 0x29,
    LL_CTRL_OPCODE_PERIODIC_SYNC_WR_IND = 0x2A,
} ll_ctrl_proc_opcodes_t;

static const value_string control_opcode_vals[] = {
    { LL_CTRL_OPCODE_CONNECTION_UPDATE_IND, "LL_CONNECTION_UPDATE_IND" },
    { LL_CTRL_OPCODE_CHANNEL_MAP_IND, "LL_CHANNEL_MAP_IND" },
    { LL_CTRL_OPCODE_TERMINATE_IND, "LL_TERMINATE_IND" },
    { LL_CTRL_OPCODE_ENC_REQ, "LL_ENC_REQ" },
    { LL_CTRL_OPCODE_ENC_RSP, "LL_ENC_RSP" },
    { LL_CTRL_OPCODE_START_ENC_REQ, "LL_START_ENC_REQ" },
    { LL_CTRL_OPCODE_START_ENC_RSP, "LL_START_ENC_RSP" },
    { LL_CTRL_OPCODE_UNKNOWN_RSP, "LL_UNKNOWN_RSP" },
    { LL_CTRL_OPCODE_FEATURE_REQ, "LL_FEATURE_REQ" },
    { LL_CTRL_OPCODE_FEATURE_RSP, "LL_FEATURE_RSP" },
    { LL_CTRL_OPCODE_PAUSE_ENC_REQ, "LL_PAUSE_ENC_REQ" },
    { LL_CTRL_OPCODE_PAUSE_ENC_RSP, "LL_PAUSE_ENC_RSP" },
    { LL_CTRL_OPCODE_VERSION_IND, "LL_VERSION_IND" },
    { LL_CTRL_OPCODE_REJECT_IND, "LL_REJECT_IND" },
    { LL_CTRL_OPCODE_PERIPHERAL_FEATURE_REQ, "LL_PERIPHERAL_FEATURE_REQ" },
    { LL_CTRL_OPCODE_CONNECTION_PARAM_REQ, "LL_CONNECTION_PARAM_REQ" },
    { LL_CTRL_OPCODE_CONNECTION_PARAM_RSP, "LL_CONNECTION_PARAM_RSP" },
    { LL_CTRL_OPCODE_REJECT_EXT_IND, "LL_REJECT_EXT_IND" },
    { LL_CTRL_OPCODE_PING_REQ, "LL_PING_REQ" },
    { LL_CTRL_OPCODE_PING_RSP, "LL_PING_RSP" },
    { LL_CTRL_OPCODE_LENGTH_REQ, "LL_LENGTH_REQ" },
    { LL_CTRL_OPCODE_LENGTH_RSP, "LL_LENGTH_RSP" },
    { LL_CTRL_OPCODE_PHY_REQ, "LL_PHY_REQ" },
    { LL_CTRL_OPCODE_PHY_RSP, "LL_PHY_RSP" },
    { LL_CTRL_OPCODE_PHY_UPDATE_IND, "LL_PHY_UPDATE_IND" },
    { LL_CTRL_OPCODE_MIN_USED_CHANNELS_IND, "LL_MIN_USED_CHANNELS_IND" },
    { LL_CTRL_OPCODE_CTE_REQ, "LL_CTE_REQ" },
    { LL_CTRL_OPCODE_CTE_RSP, "LL_CTE_RSP" },
    { LL_CTRL_OPCODE_PERIODIC_SYNC_IND, "LL_PERIODIC_SYNC_IND" },
    { LL_CTRL_OPCODE_CLOCK_ACCURACY_REQ, "LL_CLOCK_ACCURACY_REQ" },
    { LL_CTRL_OPCODE_CLOCK_ACCURACY_RSP, "LL_CLOCK_ACCURACY_RSP" },
    { LL_CTRL_OPCODE_CIS_REQ, "LL_CIS_REQ" },
    { LL_CTRL_OPCODE_CIS_RSP, "LL_CIS_RSP" },
    { LL_CTRL_OPCODE_CIS_IND, "LL_CIS_IND" },
    { LL_CTRL_OPCODE_CIS_TERMINATE_IND, "LL_CIS_TERMINATE_IND" },
    { LL_CTRL_OPCODE_POWER_CONTROL_REQ, "LL_POWER_CONTROL_REQ" },
    { LL_CTRL_OPCODE_POWER_CONTROL_RSP, "LL_POWER_CONTROL_RSP" },
    { LL_CTRL_OPCODE_POWER_CHANGE_IND, "LL_POWER_CHANGE_IND" },
    { LL_CTRL_OPCODE_SUBRATE_REQ, "LL_SUBRATE_REQ" },
    { LL_CTRL_OPCODE_SUBRATE_IND, "LL_SUBRATE_IND" },
    { LL_CTRL_OPCODE_CHANNEL_REPORTING_IND, "LL_CHANNEL_REPORTING_IND" },
    { LL_CTRL_OPCODE_CHANNEL_STATUS_IND, "LL_CHANNEL_STATUS_IND" },
    { LL_CTRL_OPCODE_PERIODIC_SYNC_WR_IND, "LL_PERIODIC_SYNC_WR_IND" },
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
    { 0x0D, "5.4" },
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

static bool btle_detect_retransmit = true;

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
static uint32_t
btle_crc(tvbuff_t *tvb, const uint8_t payload_len, const uint32_t crc_init)
{
    static const uint16_t btle_crc_next_state_flips[256] = {
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
    int     offset = 4; /* skip AA, CRC applies over PDU */
    uint32_t state = crc_init;
    uint8_t bytes_to_go = 2+payload_len; /* PDU includes header and payload */
    while( bytes_to_go-- ) {
        uint8_t byte   = tvb_get_uint8(tvb, offset++);
        uint8_t nibble = (byte & 0xf);
        uint8_t byte_index  = ((state >> 16) & 0xf0) | nibble;
        state  = ((state << 4) ^ btle_crc_next_state_flips[byte_index]) & 0xffffff;
        nibble = ((byte >> 4) & 0xf);
        byte_index  = ((state >> 16) & 0xf0) | nibble;
        state  = ((state << 4) ^ btle_crc_next_state_flips[byte_index]) & 0xffffff;
    }
    return state;
}

static const char * adv_pdu_type_str_get(const btle_context_t *btle_context, uint32_t pdu_type, bool is_periodic_adv)
{
    if (is_periodic_adv) {
        return "AUX_SYNC_IND";
    } else if (!btle_context || !(btle_context->channel < 37)) {
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
static uint32_t
reverse_bits_per_byte(const uint32_t val)
{
    static const uint8_t nibble_rev[16] = {
        0x0, 0x8, 0x4, 0xc, 0x2, 0xa, 0x6, 0xe,
        0x1, 0x9, 0x5, 0xd, 0x3, 0xb, 0x7, 0xf
    };
    uint32_t retval = 0;
    unsigned byte_index;
    for (byte_index=0; byte_index<4; byte_index++) {
        unsigned shiftA = byte_index*8;
        unsigned shiftB = shiftA+4;
        retval |= (nibble_rev[((val >> shiftA) & 0xf)] << shiftB);
        retval |= (nibble_rev[((val >> shiftB) & 0xf)] << shiftA);
    }
    return retval;
}

static int
dissect_feature_set(tvbuff_t *tvb, proto_tree *btle_tree, int offset)
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

    proto_tree_add_bitmask_list(sub_tree, tvb, offset, 1, hfx_control_feature_set_4, ENC_NA);
    offset += 1;

    proto_tree_add_bitmask_list(sub_tree, tvb, offset, 1, hfx_control_feature_set_5, ENC_NA);
    offset += 1;

    proto_tree_add_bitmask_list(sub_tree, tvb, offset, 1, hfx_control_feature_set_6, ENC_NA);
    offset += 1;

    proto_tree_add_item(sub_tree, hf_control_feature_set_reserved, tvb, offset, 3, ENC_NA);
    offset += 2;

    return offset;
}

static int
dissect_conn_param_req_rsp(tvbuff_t *tvb, proto_tree *btle_tree, int offset)
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

static int
dissect_length_req_rsp(tvbuff_t *tvb, proto_tree *btle_tree, int offset)
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

static int
dissect_phy_req_rsp(tvbuff_t *tvb, proto_tree *btle_tree, int offset)
{
    proto_tree_add_bitmask(btle_tree, tvb, offset, hf_control_tx_phys, ett_tx_phys, hfx_control_phys_sender, ENC_NA);
    offset += 1;

    proto_tree_add_bitmask(btle_tree, tvb, offset, hf_control_rx_phys, ett_rx_phys, hfx_control_phys_sender, ENC_NA);
    offset += 1;

    return offset;
}

static int
dissect_periodic_sync_ind(tvbuff_t *tvb, proto_tree *btle_tree, int offset, packet_info *pinfo, uint32_t interface_id, uint32_t adapter_id)
{
    uint32_t              sync_offset, interval;
    int                   reserved_offset;
    uint16_t              sf;
    uint8_t               bd_addr[6];
    proto_item           *item;
    proto_item           *sub_item;
    proto_tree           *sub_tree;

    /* ID */
    proto_tree_add_item(btle_tree, hf_control_sync_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* Sync Info */
    sf = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);

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

    offset = dissect_bd_addr(hf_advertising_address, pinfo, btle_tree, tvb, offset, true, interface_id, adapter_id, bd_addr);

    proto_tree_add_item(btle_tree, hf_control_sync_sync_conn_event_counter, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
}

static int
dissect_cis_req(tvbuff_t *tvb, proto_tree *btle_tree, int offset)
{
    uint32_t              interval;
    proto_item           *item;

    proto_tree_add_item(btle_tree, hf_control_cig_id, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(btle_tree, hf_control_cis_id, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_bitmask(btle_tree, tvb, offset, hf_control_c_to_p_phy, ett_c_to_p_phy, hfx_control_c_to_p_phy, ENC_NA);
    offset += 1;

    proto_tree_add_bitmask(btle_tree, tvb, offset, hf_control_p_to_c_phy, ett_p_to_c_phy, hfx_control_p_to_c_phy, ENC_NA);
    offset += 1;

    proto_tree_add_item(btle_tree, hf_control_max_sdu_c_to_p, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(btle_tree, hf_control_rfu_1, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(btle_tree, hf_control_framed, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(btle_tree, hf_control_max_sdu_p_to_c, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(btle_tree, hf_control_rfu_2, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(btle_tree, hf_control_sdu_interval_c_to_p, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(btle_tree, hf_control_rfu_3, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;

    proto_tree_add_item(btle_tree, hf_control_sdu_interval_p_to_c, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(btle_tree, hf_control_rfu_4, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;

    proto_tree_add_item(btle_tree, hf_control_max_pdu_c_to_p, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(btle_tree, hf_control_max_pdu_p_to_c, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(btle_tree, hf_control_num_sub_events, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(btle_tree, hf_control_sub_interval, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;

    proto_tree_add_item(btle_tree, hf_control_bn_c_to_p, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(btle_tree, hf_control_bn_p_to_c, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(btle_tree, hf_control_ft_c_to_p, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(btle_tree, hf_control_ft_p_to_c, tvb, offset, 1, ENC_NA);
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

static int
dissect_cis_rsp(tvbuff_t *tvb, proto_tree *btle_tree, int offset)
{
    proto_tree_add_item(btle_tree, hf_control_cis_offset_min, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;

    proto_tree_add_item(btle_tree, hf_control_cis_offset_max, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;

    proto_tree_add_item(btle_tree, hf_control_conn_event_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
}

static int
dissect_cis_ind(tvbuff_t *tvb, proto_tree *btle_tree, int offset)
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

static int
dissect_cis_terminate_ind(tvbuff_t *tvb, proto_tree *btle_tree, int offset)
{
    proto_tree_add_item(btle_tree, hf_control_cig_id, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(btle_tree, hf_control_cis_id, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(btle_tree, hf_control_error_code, tvb, offset, 1, ENC_NA);
    offset += 1;

    return offset;
}

static int
dissect_power_control_req(tvbuff_t *tvb, proto_tree *btle_tree, int offset)
{
    proto_tree_add_bitmask(btle_tree, tvb, offset, hf_control_pwr_phy, ett_pwr_phy, hfx_control_pwr_phy, ENC_NA);
    offset += 1;

    proto_tree_add_item(btle_tree, hf_control_delta, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(btle_tree, hf_control_txpwr, tvb, offset, 1, ENC_NA);
    offset += 1;

    return offset;
}


static int
dissect_power_control_rsp(tvbuff_t *tvb, proto_tree *btle_tree, int offset)
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

static int
dissect_power_control_ind(tvbuff_t *tvb, proto_tree *btle_tree, int offset)
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

static int
dissect_subrate_req(tvbuff_t *tvb, proto_tree *btle_tree, int offset)
{
    proto_tree_add_item(btle_tree, hf_control_subrate_factor_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(btle_tree, hf_control_subrate_factor_max, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(btle_tree, hf_control_max_latency, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(btle_tree, hf_control_continuation_number, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(btle_tree, hf_control_timeout, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
}

static int
dissect_subrate_ind(tvbuff_t *tvb, proto_tree *btle_tree, int offset)
{
    proto_tree_add_item(btle_tree, hf_control_subrate_factor, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(btle_tree, hf_control_subrate_base_event, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(btle_tree, hf_control_latency, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(btle_tree, hf_control_continuation_number, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(btle_tree, hf_control_timeout, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
}

static int
dissect_channel_reporting_ind(tvbuff_t *tvb, proto_tree *btle_tree, int offset)
{
    proto_tree_add_item(btle_tree, hf_control_channel_reporting_enable, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(btle_tree, hf_control_channel_reporting_min_spacing, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(btle_tree, hf_control_channel_reporting_max_delay, tvb, offset, 1, ENC_NA);
    offset += 1;

    return offset;
}

static int
dissect_channel_status_ind(tvbuff_t *tvb, proto_tree *btle_tree, int offset)
{
    proto_tree_add_item(btle_tree, hf_control_channel_classification, tvb, offset, 10, ENC_NA);
    offset += 10;

    return offset;
}


static int
dissect_periodic_sync_wr_ind(tvbuff_t *tvb, proto_tree *btle_tree, int offset, packet_info *pinfo, uint32_t interface_id, uint32_t adapter_id)
{
    /* The first part of LL_PERIODIC_SYNC_WR_IND is identical to LL_PERIODIC_SYNC_IND */
    offset += dissect_periodic_sync_ind(tvb, btle_tree, offset, pinfo, interface_id, adapter_id);

    proto_tree_add_item(btle_tree, hf_control_sync_info_rsp_access_address, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(btle_tree, hf_control_sync_info_num_subevents, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    proto_tree_add_item(btle_tree, hf_control_sync_info_subevent_interval, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    proto_tree_add_item(btle_tree, hf_control_sync_info_response_slot_delay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    proto_tree_add_item(btle_tree, hf_control_sync_info_response_slot_spacing, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    return offset;
}

static int
dissect_ctrl_pdu_without_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *btle_tree, int offset)
{
    if (tvb_reported_length_remaining(tvb, offset) > 3) {
        proto_tree_add_expert(btle_tree, pinfo, &ei_unknown_data, tvb, offset, tvb_reported_length_remaining(tvb, offset) - 3);
        offset += tvb_reported_length_remaining(tvb, offset) - 3;
    }

    return offset;
}

static int
dissect_crc(tvbuff_t *tvb,
            proto_tree *btle_tree,
            int offset,
            packet_info *pinfo,
            uint32_t length,
            const connection_info_t *connection_info,
            const btle_context_t *btle_context,
            uint32_t access_address)
{
    /* BT spec Vol 6, Part B, Section 1.2: CRC is big endian and bits in byte are flipped */
    uint32_t packet_crc = reverse_bits_per_byte(tvb_get_ntoh24(tvb, offset));
    proto_item *sub_item = proto_tree_add_uint(btle_tree, hf_crc, tvb, offset, 3, packet_crc);

    if (btle_context && btle_context->crc_checked_at_capture) {
        if (!btle_context->crc_valid_at_capture) {
            expert_add_info(pinfo, sub_item, &ei_crc_incorrect);
        }
    } else if ((access_address == ACCESS_ADDRESS_ADVERTISING) || connection_info)  {
        /* CRC can be calculated */
        uint32_t crc_init;

        if (access_address == ACCESS_ADDRESS_ADVERTISING) {
            crc_init = 0x555555;
        } else {
            crc_init = connection_info->crc_init;
        }

        uint32_t crc = btle_crc(tvb, length, crc_init);
        if (packet_crc != crc) {
            expert_add_info(pinfo, sub_item, &ei_crc_incorrect);
        }
    } else {
        expert_add_info(pinfo, sub_item, &ei_crc_cannot_be_determined);
    }

    return 3;
}

/* Checks if it is possible to add the frame at the given index
 * to the given control procedure context.
 *
 * It does not care if the procedure is already marked as completed.
 * Therefore this function can be used to add an LL_UNKNOWN_RSP to
 * a completed connection parameter update procedure.
 */
static bool
control_proc_can_add_frame_even_if_complete(packet_info *pinfo,
                                            control_proc_info_t *last_control_proc_info,
                                            uint8_t proc_opcode,
                                            unsigned frame_num)
{
    if (frame_num == 0)
        return false; /* This function must be used to add a frame to an ongoing procedure */

    /* We need to check if the control procedure has been initiated. */
    if (!last_control_proc_info)
        return false;

    /* And that the new frame belongs to this control procedure */
    if (last_control_proc_info->proc_opcode != proc_opcode)
        return false;

    /* Previous frame has not yet been added. */
    if (last_control_proc_info->frames[frame_num - 1] == 0)
        return false;

    /* We need to check if we can add this frame at this index
     * in the control procedure sequence. */

    /* The first time we visit the frame, we just need to check that the
     * spot is empty. */
    if (!pinfo->fd->visited && last_control_proc_info->frames[frame_num])
        return false; /* Another opcode has already been added to the procedure at this index */

    /* At later visits, we need to check that we are not replacing the frame with
     * another frame. */
    if (pinfo->fd->visited && (last_control_proc_info->frames[frame_num] != pinfo->num))
        return false;

    return true;
}

static bool
control_proc_is_complete(uint32_t frame_num, control_proc_info_t const *last_control_proc_info)
{
    if (last_control_proc_info->last_frame != 0 &&
        frame_num > last_control_proc_info->last_frame)
        return true;

    return false;
}

static bool
control_proc_can_add_frame(packet_info *pinfo,
                           control_proc_info_t *last_control_proc_info,
                           uint8_t proc_opcode,
                           unsigned frame_num)
{
    if (!control_proc_can_add_frame_even_if_complete(pinfo,
                                                     last_control_proc_info,
                                                     proc_opcode,
                                                     frame_num))
        return false;

    /* We check that we are not adding a frame to a completed procedure. */
    if (control_proc_is_complete(pinfo->num, last_control_proc_info))
        return false;

    return true;
}

static void
control_proc_complete_if_instant_reached(unsigned frame_num,
                                         uint16_t event_counter,
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

static bool
control_proc_contains_instant(uint8_t proc_opcode)
{
    switch (proc_opcode)
    {
        case LL_CTRL_OPCODE_CONNECTION_UPDATE_IND:
        case LL_CTRL_OPCODE_CHANNEL_MAP_IND:
        case LL_CTRL_OPCODE_CONNECTION_PARAM_REQ:
        case LL_CTRL_OPCODE_PHY_REQ:
            return true;
        default:
            return false;
    }
}

/* Returns true if this frame contains an collision violating the specification.
 *
 * See Core_v5.2, Vol 6, Part B, Section 5.3 */
static bool
control_proc_invalid_collision(packet_info const *pinfo,
                               control_proc_info_t const *control_proc_other,
                               uint8_t proc_opcode)
{
    if (!control_proc_other)
        return false;

    if (control_proc_is_complete(pinfo->num, control_proc_other))
        return false;

    /* Both procedures must contain an instant to be marked as incompatible. */
    if (!control_proc_contains_instant(control_proc_other->proc_opcode) ||
        !control_proc_contains_instant(proc_opcode))
        return false;

    /* From the Core Spec:
     *
     * If the peer has already sent at least one PDU as part of procedure A, the
     * device should immediately exit the Connection State and transition to the
     * Standby State.
     *
     * That is, if there exists are response in the other procedure at this point in
     * time, there is a procedure violation.
     */
    if (control_proc_other->frames[1] && (control_proc_other->frames[1] < pinfo->num))
        return true;
    else
        return false;
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
                   control_proc_info_t const *control_proc_other_direction,
                   uint8_t opcode)
{
    if (control_proc_invalid_collision(pinfo,
                                       control_proc_other_direction,
                                       opcode)) {
        expert_add_info(pinfo, control_proc_item, &ei_control_proc_invalid_collision);
    }

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
            for (unsigned i = 1; i < array_length(proc_info->frames); i++) {
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

/* Adds a frame to a control procedure context */
static void control_proc_add_frame(tvbuff_t *tvb,
                                   packet_info *pinfo,
                                   proto_tree *btle_tree,
                                   uint8_t opcode,
                                   uint32_t direction,
                                   control_proc_info_t *last_control_proc_info,
                                   control_proc_info_t const *control_proc_other_direction,
                                   unsigned frame_num)
{
    proto_item *item;

    last_control_proc_info->frames[frame_num] = pinfo->num;

    item = proto_tree_add_uint(btle_tree, hf_request_in_frame, tvb, 0, 0,
                               last_control_proc_info->frames[0]);
    proto_item_set_generated(item);

    if (control_proc_other_direction &&
        !control_proc_is_complete(pinfo->num, control_proc_other_direction) &&
        control_proc_contains_instant(last_control_proc_info->proc_opcode) &&
        control_proc_contains_instant(control_proc_other_direction->proc_opcode)) {
        if (direction == BTLE_DIR_CENTRAL_PERIPHERAL &&
            opcode != LL_CTRL_OPCODE_REJECT_IND &&
            opcode != LL_CTRL_OPCODE_REJECT_EXT_IND) {
          /* Continuing a control procedure when the peer has initiated an incompatible control procedure.
           * The central should have aborted the peripheral initiated procedure.
           * See Core_V5.2, Vol 6, Part B, Section 5.3.
           */
           expert_add_info(pinfo, item, &ei_control_proc_invalid_conflict_resolution);
        }
    }
}

/* Adds a frame to a control procedure context.
 * Marks this frame as the last control procedure packet. */
static void control_proc_add_last_frame(tvbuff_t *tvb,
                                        packet_info *pinfo,
                                        proto_tree *btle_tree,
                                        uint8_t opcode,
                                        uint32_t direction,
                                        control_proc_info_t *last_control_proc_info,
                                        control_proc_info_t const *control_proc_other_direction,
                                        unsigned frame_num)
{
    control_proc_add_frame(tvb,
                           pinfo,
                           btle_tree,
                           opcode,
                           direction,
                           last_control_proc_info,
                           control_proc_other_direction,
                           frame_num);
    last_control_proc_info->last_frame = pinfo->num;
}

/* Adds a frame containing an instant to a control procedure context
 * Marks this frame as the last control procedure packet if the event counter is not available */
static void control_proc_add_frame_with_instant(tvbuff_t *tvb,
                                                packet_info *pinfo,
                                                proto_tree *btle_tree,
                                                const btle_context_t *btle_context,
                                                uint8_t opcode,
                                                uint32_t direction,
                                                control_proc_info_t *last_control_proc_info,
                                                control_proc_info_t const *control_proc_other_direction,
                                                unsigned frame_num,
                                                uint16_t instant)
{
    if (btle_context && btle_context->event_counter_valid) {
        control_proc_add_frame(tvb,
                               pinfo,
                               btle_tree,
                               opcode,
                               direction,
                               last_control_proc_info,
                               control_proc_other_direction,
                               frame_num);
        last_control_proc_info->instant = instant;
        last_control_proc_info->frame_with_instant_value = pinfo->num;
    } else {
        /* Event counter is not available, assume the procedure completes now. */
        control_proc_add_last_frame(tvb,
                                    pinfo,
                                    btle_tree,
                                    opcode,
                                    direction,
                                    last_control_proc_info,
                                    control_proc_other_direction,
                                    frame_num);
    }
}

static void
dissect_ad_eir(tvbuff_t *tvb, uint32_t interface_id, uint32_t adapter_id, uint32_t frame_number, uint8_t *src_bd_addr, packet_info *pinfo, proto_tree *tree)
{
    bluetooth_eir_ad_data_t *ad_data = wmem_new0(pinfo->pool, bluetooth_eir_ad_data_t);
    ad_data->interface_id = interface_id;
    ad_data->adapter_id = adapter_id;
    call_dissector_with_data(btcommon_ad_handle, tvb, pinfo, tree, ad_data);
    if (pinfo->fd->visited)
        return;
    for (int offset = 0;; ) {
        unsigned remain = tvb_reported_length_remaining(tvb, offset);
        unsigned length;
        uint8_t opcode;
        if (remain < 1)
            break;
        length = tvb_get_uint8(tvb, offset);
        ++offset;
        if (length <= 0)
            continue;
        --remain;
        if (remain < length)
            break;
        opcode = tvb_get_uint8(tvb, offset);
        if (opcode == 0x2c && length >= 34) {
            unsigned seed_access_address = tvb_get_uint32(tvb, offset + 14, ENC_LITTLE_ENDIAN);
            uint32_t trunc_seed_access_address = seed_access_address & 0x0041ffff;
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
                memcpy(nconnection_info->central_bd_addr, src_bd_addr, 6);

            wmem_tree_insert32_array(broadcastiso_connection_info_tree, key, nconnection_info);
        }
        offset += length;
    }
}

static uint8_t
guess_btle_pdu_type_from_access(uint32_t interface_id,
                                uint32_t adapter_id,
                                uint32_t access_address)
{
    wmem_tree_key_t key[5];
    wmem_tree_t     *wmem_tree;
    uint32_t broadcast_iso_seed_access_address = access_address & 0x0041ffff;

    /* No context to provide us with physical channel pdu type, make an assumption from the access address */
    if (access_address == ACCESS_ADDRESS_ADVERTISING) {
        return BTLE_PDU_TYPE_ADVERTISING;
    }

    /* Check if it is a connection context. */
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
        /* Connection. */
        return BTLE_PDU_TYPE_DATA;
    }

    wmem_tree = (wmem_tree_t *) wmem_tree_lookup32_array(periodic_adv_info_tree, key);
    if (wmem_tree) {
        /* Periodic advertiser. */
        return BTLE_PDU_TYPE_ADVERTISING;
    }

    key[2].key = &broadcast_iso_seed_access_address;
    wmem_tree = (wmem_tree_t *) wmem_tree_lookup32_array(broadcastiso_connection_info_tree, key);
    if (wmem_tree) {
        /* Broadcast ISO. */
        return BTLE_PDU_TYPE_BROADCASTISO;
    }

    /* Default to data. */
    return BTLE_PDU_TYPE_DATA;
}

static const btle_context_t * get_btle_context(packet_info *pinfo,
                                               void *data,
                                               uint32_t *adapter_id_out,
                                               uint32_t *interface_id_out)
{
    const btle_context_t * btle_context = NULL;
    bluetooth_data_t *bluetooth_data = NULL;
    ubertooth_data_t *ubertooth_data = NULL;

    wmem_list_frame_t * list_data = wmem_list_frame_prev(wmem_list_tail(pinfo->layers));
    if (list_data) {
        int previous_proto = GPOINTER_TO_INT(wmem_list_frame_data(list_data));

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

    if (bluetooth_data)
        *interface_id_out = bluetooth_data->interface_id;
    else if (pinfo->rec->presence_flags & WTAP_HAS_INTERFACE_ID)
        *interface_id_out = pinfo->rec->rec_header.packet_header.interface_id;
    else
        *interface_id_out = HCI_INTERFACE_DEFAULT;

    if (ubertooth_data)
        *adapter_id_out = ubertooth_data->bus_id << 8 | ubertooth_data->device_address;
    else if (bluetooth_data)
        *adapter_id_out = bluetooth_data->adapter_id;
    else
        *adapter_id_out = HCI_ADAPTER_DEFAULT;

    return btle_context;
}

static int
dissect_btle(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item           *btle_item;
    proto_tree           *btle_tree;
    proto_item           *sub_item;
    proto_tree           *sub_tree;
    int                   offset = 0;
    uint32_t              access_address, length;
    tvbuff_t              *next_tvb;
    uint8_t               *dst_bd_addr;
    uint8_t               *src_bd_addr;
    static const uint8_t   broadcast_addr[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    connection_info_t     *connection_info = NULL;
    wmem_tree_t           *wmem_tree;
    wmem_tree_key_t        key[5], ae_had_key[4];

    uint32_t               connection_access_address;
    uint32_t               frame_number;

    proto_item            *item;
    unsigned               item_value;
    uint8_t                btle_pdu_type = BTLE_PDU_TYPE_UNKNOWN;

    uint32_t               interface_id;
    uint32_t               adapter_id;
    const btle_context_t *btle_context = get_btle_context(pinfo,
                                                          data,
                                                          &adapter_id,
                                                          &interface_id);

    src_bd_addr = (uint8_t *) wmem_alloc(pinfo->pool, 6);
    dst_bd_addr = (uint8_t *) wmem_alloc(pinfo->pool, 6);

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

    frame_number = pinfo->num;

    if (btle_context) {
        btle_pdu_type = btle_context->pdu_type;
    }

    if (btle_pdu_type == BTLE_PDU_TYPE_UNKNOWN) {
        /* No context to provide us with physical channel pdu type, make an assumption from the access address */
        btle_pdu_type = guess_btle_pdu_type_from_access(interface_id,
                                                        adapter_id,
                                                        access_address);
    }

    if (btle_pdu_type == BTLE_PDU_TYPE_ADVERTISING) {
        proto_item  *advertising_header_item;
        proto_tree  *advertising_header_tree;
        proto_item  *link_layer_data_item;
        proto_tree  *link_layer_data_tree;
        uint8_t      header, pdu_type;
        bool         ch_sel_valid = false, tx_add_valid = false, rx_add_valid = false;
        bool         is_periodic_adv = false;

        key[0].length = 1;
        key[0].key = &interface_id;
        key[1].length = 1;
        key[1].key = &adapter_id;
        key[2].length = 1;
        key[2].key = &access_address;
        key[3].length = 0;
        key[3].key = NULL;

        wmem_tree = (wmem_tree_t *) wmem_tree_lookup32_array(connection_info_tree, key);
        if (!wmem_tree) {
            /* Check periodic advertising tree */
            wmem_tree = (wmem_tree_t *) wmem_tree_lookup32_array(periodic_adv_info_tree, key);
            if (wmem_tree) {
                is_periodic_adv = true;
            }
        }

        if (wmem_tree) {
            connection_info = (connection_info_t *) wmem_tree_lookup32_le(wmem_tree, pinfo->num);
            if (connection_info) {
                set_address(&pinfo->net_src, AT_ETHER, 6, connection_info->central_bd_addr);
                copy_address_shallow(&pinfo->dl_src, &pinfo->net_src);
                copy_address_shallow(&pinfo->src, &pinfo->net_src);
                memcpy(src_bd_addr, connection_info->central_bd_addr, 6);
            }
        }

        advertising_header_item = proto_tree_add_item(btle_tree, hf_advertising_header, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        advertising_header_tree = proto_item_add_subtree(advertising_header_item, ett_advertising_header);

        header = tvb_get_uint8(tvb, offset);
        pdu_type = header & 0x0F;

        switch (pdu_type) {
        case 0x00: /* ADV_IND */
            ch_sel_valid = true;
            /* Fallthrough */
        case 0x02: /* ADV_NONCONN_IND */
        case 0x06: /* ADV_SCAN_IND */
        case 0x04: /* SCAN_RSP */
            tx_add_valid = true;
            break;
        case 0x07: /* ADV_EXT_IND / AUX_ADV_IND / AUX_SYNC_IND / AUX_CHAIN_IND / AUX_SCAN_RSP */
        case 0x08: /* AUX_CONNECT_RSP */
        {
            /* 0 + header, 1 = len, 2 = ext_len/adv-mode, 3 = flags */
            uint8_t ext_header_flags = tvb_get_uint8(tvb, offset + 3);

            ch_sel_valid = false;
            tx_add_valid = (ext_header_flags & 0x01) != 0;
            rx_add_valid = (ext_header_flags & 0x02) != 0;
            break;
        }
        case 0x01: /* ADV_DIRECT_IND */
        case 0x05: /* CONNECT_IND or AUX_CONNECT_REQ */
            if (btle_context && btle_context->channel >= 37) {
                /* CONNECT_IND */
                ch_sel_valid = true;
            }
            /* Fallthrough */
        case 0x03: /* SCAN_REQ or AUX_SCAN_REQ */
            tx_add_valid = true;
            rx_add_valid = true;
            break;
        }

        proto_item_append_text(advertising_header_item, " (PDU Type: %s", adv_pdu_type_str_get(btle_context, pdu_type, is_periodic_adv));
        item = proto_tree_add_item(advertising_header_tree, hf_advertising_header_pdu_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_item_append_text(item, " %s", adv_pdu_type_str_get(btle_context, pdu_type, is_periodic_adv));
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

        col_set_str(pinfo->cinfo, COL_INFO, adv_pdu_type_str_get(btle_context, pdu_type, is_periodic_adv));

        offset += 1;

        proto_tree_add_item(advertising_header_tree, hf_advertising_header_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        item = proto_tree_add_item_ret_uint(btle_tree, hf_length, tvb, offset, 1, ENC_LITTLE_ENDIAN, &length);
        proto_item_set_hidden(item);
        offset += 1;

        switch (pdu_type) {
        case 0x00: /* ADV_IND */
        case 0x02: /* ADV_NONCONN_IND */
        case 0x06: /* ADV_SCAN_IND */
            offset = dissect_bd_addr(hf_advertising_address, pinfo, btle_tree, tvb, offset, true, interface_id, adapter_id, src_bd_addr);

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
            offset = dissect_bd_addr(hf_advertising_address, pinfo, btle_tree, tvb, offset, true, interface_id, adapter_id, src_bd_addr);
            offset = dissect_bd_addr(hf_target_addresss, pinfo, btle_tree, tvb, offset, false, interface_id, adapter_id, dst_bd_addr);

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
            offset = dissect_bd_addr(hf_scanning_address, pinfo, btle_tree, tvb, offset, true, interface_id, adapter_id, src_bd_addr);
            offset = dissect_bd_addr(hf_advertising_address, pinfo, btle_tree, tvb, offset, false, interface_id, adapter_id, dst_bd_addr);

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
            offset = dissect_bd_addr(hf_advertising_address, pinfo, btle_tree, tvb, offset, true, interface_id, adapter_id, src_bd_addr);

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
        {
            uint32_t connect_ind_crc_init;

            offset = dissect_bd_addr(hf_initiator_addresss, pinfo, btle_tree, tvb, offset, false, interface_id, adapter_id, src_bd_addr);
            offset = dissect_bd_addr(hf_advertising_address, pinfo, btle_tree, tvb, offset, true, interface_id, adapter_id, dst_bd_addr);

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

            proto_tree_add_item_ret_uint(link_layer_data_tree, hf_link_layer_data_crc_init, tvb, offset, 3, ENC_LITTLE_ENDIAN, &connect_ind_crc_init);
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
                connection_info->crc_init       = connect_ind_crc_init;

                memcpy(connection_info->central_bd_addr, src_bd_addr, 6);
                memcpy(connection_info->peripheral_bd_addr,  dst_bd_addr, 6);

                /* We don't create control procedure context trees for BTLE_DIR_UNKNOWN,
                 * as the direction must be known for request/response matching. */
                connection_info->direction_info[BTLE_DIR_CENTRAL_PERIPHERAL].control_procs =
                        wmem_tree_new(wmem_file_scope());
                connection_info->direction_info[BTLE_DIR_PERIPHERAL_CENTRAL].control_procs =
                        wmem_tree_new(wmem_file_scope());

                wmem_tree_insert32_array(connection_info_tree, key, connection_info);

                connection_parameter_info = wmem_new0(wmem_file_scope(), connection_parameter_info_t);
                connection_parameter_info->parameters_frame = pinfo->num;

                key[3].length = 1;
                key[3].key = &pinfo->num;
                wmem_tree_insert32_array(connection_parameter_info_tree, key, connection_parameter_info);
            }

            break;
        }
        case 0x07: /* ADV_EXT_IND / AUX_ADV_IND / AUX_SYNC_IND / AUX_CHAIN_IND / AUX_SCAN_RSP */
        case 0x08: /* AUX_CONNECT_RSP */
        {
            uint8_t tmp, ext_header_len, flags, acad_len;
            proto_item  *ext_header_item, *ext_flags_item;
            proto_tree  *ext_header_tree, *ext_flags_tree;
            uint32_t adi;
            bool adi_present = false;
            bool aux_pointer_present = false;

            tmp = tvb_get_uint8(tvb, offset);
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
                flags = tvb_get_uint8(tvb, offset);
                offset += 1;

                acad_len -= 1;
            } else {
                flags = 0;
            }

            if (flags & 0x01) {
                /* Advertiser Address */
                offset = dissect_bd_addr(hf_advertising_address, pinfo, ext_header_tree, tvb, offset, true, interface_id, adapter_id, src_bd_addr);
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
                offset = dissect_bd_addr(hf_target_addresss, pinfo, ext_header_tree, tvb, offset, false, interface_id, adapter_id, dst_bd_addr);
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
                uint32_t cte_time;

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
                adi_present = true;

                acad_len -= 2;
            }

            if (flags & 0x10) {
                uint32_t aux_offset;

                /* Aux Pointer */
                sub_item = proto_tree_add_item(ext_header_tree, hf_extended_advertising_aux_ptr, tvb, offset, 3, ENC_NA);
                sub_tree = proto_item_add_subtree(sub_item, ett_extended_advertising_aux_pointer);

                proto_tree_add_item(sub_tree, hf_extended_advertising_aux_ptr_channel, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(sub_tree, hf_extended_advertising_aux_ptr_ca, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(sub_tree, hf_extended_advertising_aux_ptr_offset_units, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                tmp = tvb_get_uint8(tvb, offset);
                offset += 1;

                item = proto_tree_add_item_ret_uint(sub_tree, hf_extended_advertising_aux_ptr_aux_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN, &aux_offset);
                proto_tree_add_item(sub_tree, hf_extended_advertising_aux_ptr_aux_phy, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                proto_item_append_text(item, " (%u usec)", aux_offset * ((tmp & 0x80) != 0 ? 300 : 30));
                offset += 2;
                aux_pointer_present = true;

                acad_len -= 3;
            }

            if (flags & 0x20) {
                uint32_t sync_offset, interval;
                proto_item  *sync_info_item;
                proto_tree  *sync_info_tree;
                int reserved_offset;
                uint16_t sf;

                /* Sync Info */
                sync_info_item = proto_tree_add_item(ext_header_tree, hf_extended_advertising_sync_info, tvb, offset, 18, ENC_NA);
                sync_info_tree = proto_item_add_subtree(sync_info_item, ett_extended_advertising_sync_info);

                if (!pinfo->fd->visited) {
                    connection_parameter_info_t *connection_parameter_info;

                    connection_access_address = tvb_get_uint32(tvb, offset + 9, ENC_LITTLE_ENDIAN);

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
                        memcpy(connection_info->central_bd_addr, src_bd_addr, 6);

                    /* We don't create control procedure context trees for BTLE_DIR_UNKNOWN,
                     * as the direction must be known for request/response matching. */
                    connection_info->direction_info[BTLE_DIR_CENTRAL_PERIPHERAL].control_procs =
                        wmem_tree_new(wmem_file_scope());
                    connection_info->direction_info[BTLE_DIR_PERIPHERAL_CENTRAL].control_procs =
                        wmem_tree_new(wmem_file_scope());

                    wmem_tree_insert32_array(periodic_adv_info_tree, key, connection_info);

                    connection_parameter_info = wmem_new0(wmem_file_scope(), connection_parameter_info_t);
                    connection_parameter_info->parameters_frame = pinfo->num;

                    key[3].length = 1;
                    key[3].key = &pinfo->num;
                    wmem_tree_insert32_array(connection_parameter_info_tree, key, connection_parameter_info);
                }

                sf = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);

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
                bool ad_processed = false;
                if (btle_context && pdu_type == 0x07 && btle_context->aux_pdu_type_valid) {
                    bool ad_reassembled = false;
                    ae_had_info_t *ae_had_info = NULL;

                    switch (btle_context->aux_pdu_type) {
                        case 0x00:  /* AUX_ADV_IND */
                        case 0x02:  /* AUX_SYNC_IND */
                        case 0x03:  /* AUX_SCAN_RSP */
                            if (aux_pointer_present) {
                                /* Beginning of new sequence of fragments */
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
                                ad_processed = true;
                            }
                            break;
                        case 0x01:  /* AUX_CHAIN_IND */
                            if (!aux_pointer_present) {
                                /* Final fragment */
                                ad_reassembled = true;
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
                                    if (ad_reassembled == true) {
                                        p_add_proto_data(wmem_file_scope(), pinfo, proto_btle, (uint32_t)(pinfo->curr_layer_num) << 8, ae_had_info);
                                    }
                                }
                            }
                            ad_processed = true;
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

                                ae_had_info = (ae_had_info_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_btle, (uint32_t)(pinfo->curr_layer_num) << 8);
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
        uint8_t      oct;
        uint8_t      llid;
        uint8_t      control_opcode;
        uint32_t     direction = BTLE_DIR_UNKNOWN;
        uint8_t      other_direction = BTLE_DIR_UNKNOWN;

        bool         add_l2cap_index = false;
        bool         retransmit = false;
        bool         cte_info_present = false;

        /* Holds the last initiated control procedures for a given direction. */
        control_proc_info_t *last_control_proc[3] = {0};

        if (btle_context) {
            direction = btle_context->direction;
            other_direction = (direction == BTLE_DIR_PERIPHERAL_CENTRAL) ? BTLE_DIR_CENTRAL_PERIPHERAL : BTLE_DIR_PERIPHERAL_CENTRAL;
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

        oct = tvb_get_uint8(tvb, offset);
        wmem_tree = (wmem_tree_t *) wmem_tree_lookup32_array(connection_info_tree, key);
        if (wmem_tree) {
            connection_info = (connection_info_t *) wmem_tree_lookup32_le(wmem_tree, pinfo->num);
            if (connection_info) {
                char   *str_addr_src, *str_addr_dst;
                /* Holds "unknown" + access_address + NULL, which is the longest string */
                int     str_addr_len = 18 + 1;

                str_addr_src = (char *) wmem_alloc(pinfo->pool, str_addr_len);
                str_addr_dst = (char *) wmem_alloc(pinfo->pool, str_addr_len);

                sub_item = proto_tree_add_ether(btle_tree, hf_central_bd_addr, tvb, 0, 0, connection_info->central_bd_addr);
                proto_item_set_generated(sub_item);

                sub_item = proto_tree_add_ether(btle_tree, hf_peripheral_bd_addr, tvb, 0, 0, connection_info->peripheral_bd_addr);
                proto_item_set_generated(sub_item);

                switch (direction) {
                case BTLE_DIR_CENTRAL_PERIPHERAL:
                    snprintf(str_addr_src, str_addr_len, "Central_0x%08x", connection_info->access_address);
                    snprintf(str_addr_dst, str_addr_len, "Peripheral_0x%08x", connection_info->access_address);
                    set_address(&pinfo->dl_src, AT_ETHER, sizeof(connection_info->central_bd_addr), connection_info->central_bd_addr);
                    set_address(&pinfo->dl_dst, AT_ETHER, sizeof(connection_info->peripheral_bd_addr), connection_info->peripheral_bd_addr);
                    break;
                case BTLE_DIR_PERIPHERAL_CENTRAL:
                    snprintf(str_addr_src, str_addr_len, "Peripheral_0x%08x", connection_info->access_address);
                    snprintf(str_addr_dst, str_addr_len, "Central_0x%08x", connection_info->access_address);
                    set_address(&pinfo->dl_src, AT_ETHER, sizeof(connection_info->peripheral_bd_addr), connection_info->peripheral_bd_addr);
                    set_address(&pinfo->dl_dst, AT_ETHER, sizeof(connection_info->central_bd_addr), connection_info->central_bd_addr);
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
                    last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL] =
                        (control_proc_info_t *)wmem_tree_lookup32_le(connection_info->direction_info[BTLE_DIR_CENTRAL_PERIPHERAL].control_procs, pinfo->num);
                    last_control_proc[BTLE_DIR_PERIPHERAL_CENTRAL] =
                        (control_proc_info_t *)wmem_tree_lookup32_le(connection_info->direction_info[BTLE_DIR_PERIPHERAL_CENTRAL].control_procs, pinfo->num);

                    if (!pinfo->fd->visited && btle_context && btle_context->event_counter_valid) {
                        control_proc_complete_if_instant_reached(pinfo->num,
                                                                 btle_context->event_counter,
                                                                 last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL]);
                        control_proc_complete_if_instant_reached(pinfo->num,
                                                                 btle_context->event_counter,
                                                                 last_control_proc[BTLE_DIR_PERIPHERAL_CENTRAL]);
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
                        connection_info->direction_info[BTLE_DIR_CENTRAL_PERIPHERAL].prev_seq_num = 0;
                        connection_info->direction_info[BTLE_DIR_PERIPHERAL_CENTRAL].prev_seq_num = 1;
                    }
                    else {
                        uint8_t seq_num = !!(oct & 0x8), next_expected_seq_num = !!(oct & 0x4);

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

        data_header_item = proto_tree_add_item(btle_tree,  hf_data_header, tvb, offset, (cte_info_present) ? 3 : 2, ENC_NA);
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
                    retransmit = true;
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
            uint32_t cte_time;

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

                pinfo->fragmented = true;
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

                    add_l2cap_index = true;

                    frag_btl2cap_msg = fragment_add_seq_next(&btle_l2cap_msg_reassembly_table,
                        tvb, offset,
                        pinfo,
                        btle_frame_info->l2cap_index,      /* uint32_t ID for fragments belonging together */
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
                    acl_data->is_btle = true;
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
                unsigned l2cap_len = tvb_get_letohs(tvb, offset);
                if (l2cap_len + 4 > length) { /* L2CAP PDU Length excludes the 4 octets header */
                    pinfo->fragmented = true;
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

                        add_l2cap_index = true;

                        frag_btl2cap_msg = fragment_add_seq_next(&btle_l2cap_msg_reassembly_table,
                            tvb, offset,
                            pinfo,
                            btle_frame_info->l2cap_index,      /* uint32_t ID for fragments belonging together */
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

                        add_l2cap_index = true;
                    }

                    col_set_str(pinfo->cinfo, COL_INFO, "L2CAP Data");

                    acl_data = wmem_new(pinfo->pool, bthci_acl_data_t);
                    acl_data->interface_id = interface_id;
                    acl_data->adapter_id   = adapter_id;
                    acl_data->chandle      = 0; /* No connection handle at this layer */
                    acl_data->remote_bd_addr_oui = 0;
                    acl_data->remote_bd_addr_id  = 0;
                    acl_data->is_btle = true;
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
            control_opcode = tvb_get_uint8(tvb, offset);
            offset += 1;

            col_add_fstr(pinfo->cinfo, COL_INFO, "Control Opcode: %s",
                    val_to_str_ext_const(control_opcode, &control_opcode_vals_ext, "Unknown"));

            switch (control_opcode) {
            case LL_CTRL_OPCODE_CONNECTION_UPDATE_IND:
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
                    /* The LL_CONNECTION_UPDATE_IND can only be sent from central to peripheral.
                     * It can either be sent as the first packet of the connection update procedure,
                     * or as the last packet in the connection parameter request procedure. */
                    if (direction == BTLE_DIR_CENTRAL_PERIPHERAL) {
                        if (control_proc_can_add_frame(pinfo,
                                                       last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                       LL_CTRL_OPCODE_CONNECTION_PARAM_REQ, 2)) {
                            control_proc_add_last_frame(tvb,
                                                        pinfo,
                                                        btle_tree,
                                                        control_opcode,
                                                        direction,
                                                        last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                        last_control_proc[BTLE_DIR_PERIPHERAL_CENTRAL],
                                                        2);
                        } else if (control_proc_can_add_frame(pinfo,
                                                              last_control_proc[BTLE_DIR_PERIPHERAL_CENTRAL],
                                                              LL_CTRL_OPCODE_CONNECTION_PARAM_REQ, 1)) {
                            control_proc_add_last_frame(tvb,
                                                        pinfo,
                                                        btle_tree,
                                                        control_opcode,
                                                        direction,
                                                        last_control_proc[BTLE_DIR_PERIPHERAL_CENTRAL],
                                                        last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                        1);
                        } else {
                            control_proc_info_t *proc_info;
                            proc_info = control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                                           connection_info->direction_info[direction].control_procs,
                                                           last_control_proc[other_direction],
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
                    } else if (direction == BTLE_DIR_PERIPHERAL_CENTRAL) {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }

                break;
            case LL_CTRL_OPCODE_CHANNEL_MAP_IND:
                sub_item = proto_tree_add_item(btle_tree, hf_control_channel_map, tvb, offset, 5, ENC_NA);
                sub_tree = proto_item_add_subtree(sub_item, ett_channel_map);

                call_dissector(btcommon_le_channel_map_handle, tvb_new_subset_length(tvb, offset, 5), pinfo, sub_tree);
                offset += 5;

                proto_tree_add_item_ret_uint(btle_tree, hf_control_instant, tvb, offset, 2, ENC_LITTLE_ENDIAN, &item_value);
                offset += 2;

                if (connection_info && !btle_frame_info->retransmit) {
                    /* The LL_CHANNEL_MAP_REQ can only be sent from central to peripheral.
                     * It can either be sent as the first packet of the channel map update procedure,
                     * or as the last packet in the minimum number of used channels procedure. */
                    if (direction == BTLE_DIR_CENTRAL_PERIPHERAL) {
                        if (control_proc_can_add_frame(pinfo,
                                                       last_control_proc[BTLE_DIR_PERIPHERAL_CENTRAL],
                                                       LL_CTRL_OPCODE_MIN_USED_CHANNELS_IND, 1)) {
                            control_proc_add_frame_with_instant(tvb,
                                                                pinfo,
                                                                btle_tree,
                                                                btle_context,
                                                                control_opcode,
                                                                direction,
                                                                last_control_proc[BTLE_DIR_PERIPHERAL_CENTRAL],
                                                                last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                                1,
                                                                item_value);
                        } else {
                            control_proc_info_t *proc_info;
                            proc_info = control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                                           connection_info->direction_info[direction].control_procs,
                                                           last_control_proc[other_direction],
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
                    } else if (direction == BTLE_DIR_PERIPHERAL_CENTRAL) {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }

                break;
            case LL_CTRL_OPCODE_TERMINATE_IND:
                proto_tree_add_item(btle_tree, hf_control_error_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset += 1;

                /* No need to mark procedure as started, as the procedure only consist
                 * of one packet which may be sent at any time, */

                break;
            case LL_CTRL_OPCODE_ENC_REQ:
                proto_tree_add_item(btle_tree, hf_control_random_number, tvb, offset, 8, ENC_LITTLE_ENDIAN);
                offset += 8;

                proto_tree_add_item(btle_tree, hf_control_encrypted_diversifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(btle_tree, hf_control_central_session_key_diversifier, tvb, offset, 8, ENC_LITTLE_ENDIAN);
                offset += 8;

                proto_tree_add_item(btle_tree, hf_control_central_session_initialization_vector, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                if (connection_info && !btle_frame_info->retransmit) {
                    /* The LL_ENC_REQ can only be sent from central to peripheral. */
                    if (direction == BTLE_DIR_CENTRAL_PERIPHERAL) {
                        control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                           connection_info->direction_info[BTLE_DIR_CENTRAL_PERIPHERAL].control_procs,
                                           last_control_proc[other_direction],
                                           control_opcode);
                    } else if (direction == BTLE_DIR_PERIPHERAL_CENTRAL) {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }

                break;
            case LL_CTRL_OPCODE_ENC_RSP:
                proto_tree_add_item(btle_tree, hf_control_peripheral_session_key_diversifier, tvb, offset, 8, ENC_LITTLE_ENDIAN);
                offset += 8;

                proto_tree_add_item(btle_tree, hf_control_peripheral_session_initialization_vector, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                if (connection_info && !btle_frame_info->retransmit) {
                    /* The LL_ENC_REQ can only be sent from peripheral to central. */
                    if (direction == BTLE_DIR_PERIPHERAL_CENTRAL) {
                        if (control_proc_can_add_frame(pinfo,
                                                       last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                       LL_CTRL_OPCODE_ENC_REQ, 1)) {
                            control_proc_add_frame(tvb,
                                                   pinfo,
                                                   btle_tree,
                                                   control_opcode,
                                                   direction,
                                                   last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                   last_control_proc[BTLE_DIR_PERIPHERAL_CENTRAL],
                                                   1);
                        } else {
                            expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                        }
                    } else if (direction == BTLE_DIR_CENTRAL_PERIPHERAL) {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }

                break;
            case LL_CTRL_OPCODE_START_ENC_REQ:
                offset = dissect_ctrl_pdu_without_data(tvb, pinfo, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit) {
                    /* The LL_START_ENC_REQ can only be sent from peripheral to central. */
                    if (direction == BTLE_DIR_PERIPHERAL_CENTRAL) {
                        if (control_proc_can_add_frame(pinfo,
                                                       last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                       LL_CTRL_OPCODE_ENC_REQ, 2)) {
                            control_proc_add_frame(tvb,
                                                   pinfo,
                                                   btle_tree,
                                                   control_opcode,
                                                   direction,
                                                   last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                   last_control_proc[BTLE_DIR_PERIPHERAL_CENTRAL],
                                                   2);
                        } else {
                            expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                        }
                    } else if (direction == BTLE_DIR_CENTRAL_PERIPHERAL) {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }

                break;

            case LL_CTRL_OPCODE_START_ENC_RSP:
                offset = dissect_ctrl_pdu_without_data(tvb, pinfo, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    /* This is either frame 4 or 5 of the procedure */
                    if (direction == BTLE_DIR_CENTRAL_PERIPHERAL &&
                        control_proc_can_add_frame(pinfo,
                                                   last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                   LL_CTRL_OPCODE_ENC_REQ, 3)) {
                        control_proc_add_frame(tvb,
                                               pinfo,
                                               btle_tree,
                                               control_opcode,
                                               direction,
                                               last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                               last_control_proc[BTLE_DIR_PERIPHERAL_CENTRAL],
                                               3);
                    } else if (direction == BTLE_DIR_PERIPHERAL_CENTRAL &&
                               control_proc_can_add_frame(pinfo,
                                                          last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                          LL_CTRL_OPCODE_ENC_REQ, 4)) {
                        control_proc_add_last_frame(tvb,
                                                    pinfo,
                                                    btle_tree,
                                                    control_opcode,
                                                    direction,
                                                    last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                    last_control_proc[BTLE_DIR_PERIPHERAL_CENTRAL],
                                                    4);
                    } else {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }

                break;

            case LL_CTRL_OPCODE_UNKNOWN_RSP:
                proto_tree_add_item(btle_tree, hf_control_unknown_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset += 1;

                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    /* LL_UNKNOWN_RSP can only be sent as the second frame of a procedure. */
                    if (last_control_proc[other_direction] &&
                        control_proc_can_add_frame_even_if_complete(pinfo,
                                                   last_control_proc[other_direction],
                                                   last_control_proc[other_direction]->proc_opcode,
                                                   1)) {
                        control_proc_add_last_frame(tvb,
                                                    pinfo,
                                                    btle_tree,
                                                    control_opcode,
                                                    direction,
                                                    last_control_proc[other_direction],
                                                    last_control_proc[direction],
                                                    1);
                    } else {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }

                break;
            case LL_CTRL_OPCODE_FEATURE_REQ:
                offset = dissect_feature_set(tvb, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit) {
                    /* The LL_FEATURE_REQ can only be sent from central to peripheral. */
                    if (direction == BTLE_DIR_CENTRAL_PERIPHERAL) {
                        control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                           connection_info->direction_info[direction].control_procs,
                                           last_control_proc[other_direction],
                                           control_opcode);
                    } else if (direction == BTLE_DIR_PERIPHERAL_CENTRAL) {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }

                break;
            case LL_CTRL_OPCODE_FEATURE_RSP:
                offset = dissect_feature_set(tvb, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    if (control_proc_can_add_frame(pinfo,
                                                   last_control_proc[other_direction],
                                                   LL_CTRL_OPCODE_FEATURE_REQ, 1) ||
                        control_proc_can_add_frame(pinfo,
                                                   last_control_proc[other_direction],
                                                   LL_CTRL_OPCODE_PERIPHERAL_FEATURE_REQ, 1)) {
                        control_proc_add_last_frame(tvb,
                                                    pinfo,
                                                    btle_tree,
                                                    control_opcode,
                                                    direction,
                                                    last_control_proc[other_direction],
                                                    last_control_proc[direction],
                                                    1);
                    } else {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }

                break;
            case LL_CTRL_OPCODE_PAUSE_ENC_REQ:
                if (tvb_reported_length_remaining(tvb, offset) > 3) {
                    proto_tree_add_expert(btle_tree, pinfo, &ei_unknown_data, tvb, offset, tvb_reported_length_remaining(tvb, offset) - 3);
                    offset += tvb_reported_length_remaining(tvb, offset) - 3;
                }

                if (connection_info && !btle_frame_info->retransmit) {
                    /* The LL_PAUSE_ENC_REQ can only be sent from central to peripheral. */
                    if (direction == BTLE_DIR_CENTRAL_PERIPHERAL) {
                        control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                           connection_info->direction_info[BTLE_DIR_CENTRAL_PERIPHERAL].control_procs,
                                           last_control_proc[other_direction],
                                           control_opcode);
                    } else if (direction == BTLE_DIR_PERIPHERAL_CENTRAL) {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }

                break;
            case LL_CTRL_OPCODE_PAUSE_ENC_RSP:
                offset = dissect_ctrl_pdu_without_data(tvb, pinfo, btle_tree, offset);

                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    if (direction == BTLE_DIR_PERIPHERAL_CENTRAL &&
                        control_proc_can_add_frame(pinfo,
                                                   last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                   LL_CTRL_OPCODE_PAUSE_ENC_REQ, 1)) {
                        control_proc_add_frame(tvb,
                                               pinfo,
                                               btle_tree,
                                               control_opcode,
                                               direction,
                                               last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                               last_control_proc[BTLE_DIR_PERIPHERAL_CENTRAL],
                                               1);
                    } else if (direction == BTLE_DIR_CENTRAL_PERIPHERAL &&
                               control_proc_can_add_frame(pinfo,
                                                          last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                          LL_CTRL_OPCODE_PAUSE_ENC_REQ, 2)) {
                        control_proc_add_last_frame(tvb,
                                                    pinfo,
                                                    btle_tree,
                                                    control_opcode,
                                                    direction,
                                                    last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                    last_control_proc[BTLE_DIR_PERIPHERAL_CENTRAL],
                                                    2);
                    } else {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }

                break;
            case LL_CTRL_OPCODE_VERSION_IND:
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
                                                   LL_CTRL_OPCODE_VERSION_IND, 1)) {
                        control_proc_add_last_frame(tvb,
                                                    pinfo,
                                                    btle_tree,
                                                    control_opcode,
                                                    direction,
                                                    last_control_proc[other_direction],
                                                    last_control_proc[direction],
                                                    1);
                    } else {
                        control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                           connection_info->direction_info[direction].control_procs,
                                           last_control_proc[other_direction],
                                           control_opcode);
                    }
                }

                break;
            case LL_CTRL_OPCODE_REJECT_IND:
                proto_tree_add_item(btle_tree, hf_control_error_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset += 1;

                /* LL_REJECT_IND my be sent as:
                 *  - A response to the LL_ENQ_REQ from the central
                 *  - After the LL_ENC_RSP from the peripheral */
                if (connection_info && !btle_frame_info->retransmit) {
                    if (direction == BTLE_DIR_PERIPHERAL_CENTRAL) {
                        if (control_proc_can_add_frame(pinfo,
                                                       last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                       LL_CTRL_OPCODE_ENC_REQ, 1)) {
                            control_proc_add_last_frame(tvb,
                                                        pinfo,
                                                        btle_tree,
                                                        control_opcode,
                                                        direction,
                                                        last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                        last_control_proc[BTLE_DIR_PERIPHERAL_CENTRAL],
                                                        1);
                        } else if (control_proc_can_add_frame(pinfo,
                                                              last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                              LL_CTRL_OPCODE_ENC_REQ, 2)) {
                            control_proc_add_last_frame(tvb,
                                                        pinfo,
                                                        btle_tree,
                                                        control_opcode,
                                                        direction,
                                                        last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                        last_control_proc[BTLE_DIR_PERIPHERAL_CENTRAL],
                                                        2);
                        } else {
                            expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                        }
                    } else if (direction == BTLE_DIR_CENTRAL_PERIPHERAL) {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }

                break;
            case LL_CTRL_OPCODE_PERIPHERAL_FEATURE_REQ:
                offset = dissect_feature_set(tvb, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit) {
                    /* The LL_PERIPHERAL_FEATURE_REQ can only be sent from peripheral to central. */
                    if (direction == BTLE_DIR_PERIPHERAL_CENTRAL) {
                        control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                           connection_info->direction_info[direction].control_procs,
                                           last_control_proc[other_direction],
                                           control_opcode);
                    } else if (direction == BTLE_DIR_CENTRAL_PERIPHERAL) {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }
                break;

            case LL_CTRL_OPCODE_CONNECTION_PARAM_REQ:
                offset = dissect_conn_param_req_rsp(tvb, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit) {
                    if (direction != BTLE_DIR_UNKNOWN) {
                        control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                           connection_info->direction_info[direction].control_procs,
                                           last_control_proc[other_direction],
                                           control_opcode);
                    }
                }

                break;
            case LL_CTRL_OPCODE_CONNECTION_PARAM_RSP:
                offset = dissect_conn_param_req_rsp(tvb, btle_tree, offset);

                if (connection_info && !btle_frame_info->retransmit) {
                    /* The LL_CONNECTION_PARAM_RSP can only be sent from peripheral to central
                     * as a response to a central initiated procedure */
                    if (direction == BTLE_DIR_PERIPHERAL_CENTRAL) {
                        if (control_proc_can_add_frame(pinfo,
                                                       last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                       LL_CTRL_OPCODE_CONNECTION_PARAM_REQ, 1)) {
                            control_proc_add_frame(tvb,
                                                   pinfo,
                                                   btle_tree,
                                                   control_opcode,
                                                   direction,
                                                   last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                   last_control_proc[BTLE_DIR_PERIPHERAL_CENTRAL],
                                                   1);
                        } else {
                            expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                        }
                    } else if (direction == BTLE_DIR_CENTRAL_PERIPHERAL) {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }

                break;
            case LL_CTRL_OPCODE_REJECT_EXT_IND:
                proto_tree_add_item(btle_tree, hf_control_reject_opcode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset += 1;

                proto_tree_add_item(btle_tree, hf_control_error_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset += 1;

                /* LL_REJECT_EXT_IND my be sent as:
                 *  - A response to the LL_ENQ_REQ from the central
                 *  - After the LL_ENC_RSP from the peripheral
                 *  - As a response to LL_CONNECTION_PARAM_REQ
                 *  - As a response to LL_CONNECTION_PARAM_RSP
                 *  - As a response during the phy update procedure.
                 *  - As a response during the CTE request procedure.
                 *  - As a response to LL_CIS_REQ
                 *  - As a response to LL_CIS_RSP
                 *  - As a response to LL_POWER_CONTROL_REQ
                 *  - As a response to a LL_SUBRATE_REQ
                 */
                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    if (direction == BTLE_DIR_PERIPHERAL_CENTRAL &&
                        control_proc_can_add_frame(pinfo,
                                                   last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                   LL_CTRL_OPCODE_ENC_REQ, 1)) {
                        control_proc_add_last_frame(tvb,
                                                    pinfo,
                                                    btle_tree,
                                                    control_opcode,
                                                    direction,
                                                    last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                    last_control_proc[BTLE_DIR_PERIPHERAL_CENTRAL],
                                                    1);
                    } else if (direction == BTLE_DIR_PERIPHERAL_CENTRAL &&
                               control_proc_can_add_frame(pinfo,
                                                          last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                          LL_CTRL_OPCODE_ENC_REQ, 2)) {
                        control_proc_add_last_frame(tvb,
                                                    pinfo,
                                                    btle_tree,
                                                    control_opcode,
                                                    direction,
                                                    last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                    last_control_proc[BTLE_DIR_PERIPHERAL_CENTRAL],
                                                    2);
                    } else if (control_proc_can_add_frame(pinfo,
                                                          last_control_proc[other_direction],
                                                          LL_CTRL_OPCODE_CONNECTION_PARAM_REQ, 1)) {
                        control_proc_add_last_frame(tvb,
                                                    pinfo,
                                                    btle_tree,
                                                    control_opcode,
                                                    direction,
                                                    last_control_proc[other_direction],
                                                    last_control_proc[direction],
                                                    1);
                    } else if (control_proc_can_add_frame(pinfo,
                                                          last_control_proc[other_direction],
                                                          LL_CTRL_OPCODE_PHY_REQ, 1)) {
                        control_proc_add_last_frame(tvb,
                                                    pinfo,
                                                    btle_tree,
                                                    control_opcode,
                                                    direction,
                                                    last_control_proc[other_direction],
                                                    last_control_proc[direction],
                                                    1);
                    } else if (control_proc_can_add_frame(pinfo,
                                                          last_control_proc[other_direction],
                                                          LL_CTRL_OPCODE_CTE_REQ, 1)) {
                        control_proc_add_last_frame(tvb,
                                                    pinfo,
                                                    btle_tree,
                                                    control_opcode,
                                                    direction,
                                                    last_control_proc[other_direction],
                                                    last_control_proc[direction],
                                                    1);
                    } else if (control_proc_can_add_frame(pinfo,
                                                          last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                          LL_CTRL_OPCODE_CIS_REQ, 1)) {
                        control_proc_add_last_frame(tvb,
                                                    pinfo,
                                                    btle_tree,
                                                    control_opcode,
                                                    direction,
                                                    last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                    last_control_proc[BTLE_DIR_PERIPHERAL_CENTRAL],
                                                    1);
                    } else if (control_proc_can_add_frame(pinfo,
                                                          last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                          LL_CTRL_OPCODE_CIS_REQ, 2)) {
                        control_proc_add_last_frame(tvb,
                                                    pinfo,
                                                    btle_tree,
                                                    control_opcode,
                                                    direction,
                                                    last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                    last_control_proc[BTLE_DIR_PERIPHERAL_CENTRAL],
                                                    2);
                    } else if (control_proc_can_add_frame(pinfo,
                                                          last_control_proc[other_direction],
                                                          LL_CTRL_OPCODE_POWER_CONTROL_REQ, 1)) {
                        control_proc_add_last_frame(tvb,
                                                    pinfo,
                                                    btle_tree,
                                                    control_opcode,
                                                    direction,
                                                    last_control_proc[other_direction],
                                                    last_control_proc[direction],
                                                    1);
                    } else if (control_proc_can_add_frame(pinfo,
                                                          last_control_proc[BTLE_DIR_PERIPHERAL_CENTRAL],
                                                          LL_CTRL_OPCODE_SUBRATE_REQ, 1)) {
                        control_proc_add_last_frame(tvb,
                                                    pinfo,
                                                    btle_tree,
                                                    control_opcode,
                                                    direction,
                                                    last_control_proc[BTLE_DIR_PERIPHERAL_CENTRAL],
                                                    last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                    1);
                    } else {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }

                break;
            case LL_CTRL_OPCODE_PING_REQ:
                offset = dissect_ctrl_pdu_without_data(tvb, pinfo, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                       connection_info->direction_info[direction].control_procs,
                                       last_control_proc[other_direction],
                                       control_opcode);
                }
                break;
            case LL_CTRL_OPCODE_PING_RSP:
                offset = dissect_ctrl_pdu_without_data(tvb, pinfo, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    if (control_proc_can_add_frame(pinfo,
                                                   last_control_proc[other_direction],
                                                   LL_CTRL_OPCODE_PING_REQ, 1)) {
                        control_proc_add_last_frame(tvb,
                                                    pinfo,
                                                    btle_tree,
                                                    control_opcode,
                                                    direction,
                                                    last_control_proc[other_direction],
                                                    last_control_proc[direction],
                                                    1);
                    } else {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }
                break;

            case LL_CTRL_OPCODE_LENGTH_REQ:
                dissect_length_req_rsp(tvb, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                       connection_info->direction_info[direction].control_procs,
                                       last_control_proc[other_direction],
                                       control_opcode);
                }

                break;
            case LL_CTRL_OPCODE_LENGTH_RSP:
                dissect_length_req_rsp(tvb, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    if (control_proc_can_add_frame(pinfo,
                                                   last_control_proc[other_direction],
                                                   LL_CTRL_OPCODE_LENGTH_REQ, 1)) {
                        control_proc_add_last_frame(tvb,
                                                    pinfo,
                                                    btle_tree,
                                                    control_opcode,
                                                    direction,
                                                    last_control_proc[other_direction],
                                                    last_control_proc[direction],
                                                    1);
                    } else {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }
                break;
            case LL_CTRL_OPCODE_PHY_REQ:
                dissect_phy_req_rsp(tvb, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                       connection_info->direction_info[direction].control_procs,
                                       last_control_proc[other_direction],
                                       control_opcode);
                }

                break;
            case LL_CTRL_OPCODE_PHY_RSP:
                dissect_phy_req_rsp(tvb, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit) {
                    /* The LL_PHY_RSP can only be sent from peripheral to central. */
                    if (direction == BTLE_DIR_PERIPHERAL_CENTRAL) {
                        if (control_proc_can_add_frame(pinfo,
                                                       last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                       LL_CTRL_OPCODE_PHY_REQ, 1)) {
                            control_proc_add_frame(tvb,
                                                   pinfo,
                                                   btle_tree,
                                                   control_opcode,
                                                   direction,
                                                   last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                   last_control_proc[BTLE_DIR_PERIPHERAL_CENTRAL],
                                                   1);
                        } else {
                            expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                        }
                    } else if (direction == BTLE_DIR_CENTRAL_PERIPHERAL) {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }

                break;
            case LL_CTRL_OPCODE_PHY_UPDATE_IND:
            {
                uint64_t phy_c_to_p, phy_p_to_c;

                item = proto_tree_add_bitmask_ret_uint64(btle_tree, tvb, offset, hf_control_c_to_p_phy, ett_c_to_p_phy, hfx_control_phys_update, ENC_NA, &phy_c_to_p);
                if (phy_c_to_p == 0) {
                    proto_item_append_text(item, ", No change");
                }
                offset += 1;

                item = proto_tree_add_bitmask_ret_uint64(btle_tree, tvb, offset, hf_control_p_to_c_phy, ett_p_to_c_phy, hfx_control_phys_update, ENC_NA, &phy_p_to_c);
                if (phy_p_to_c == 0) {
                    proto_item_append_text(item, ", No change");
                }
                offset += 1;

                if (phy_c_to_p != 0 && phy_p_to_c != 0) {
                    proto_tree_add_item_ret_uint(btle_tree, hf_control_instant, tvb, offset, 2, ENC_LITTLE_ENDIAN, &item_value);
                } else {
                    /* If both the PHY_C_TO_P and PHY_P_TO_C fields are zero then there is no
                     * Instant and the Instant field is reserved for future use.
                     */
                    proto_tree_add_item(btle_tree, hf_control_rfu_5, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                }
                offset += 2;

                if (connection_info && !btle_frame_info->retransmit) {
                    /* The LL_PHY_UPDATE_IND can only be sent from central to peripheral. */
                    if (direction == BTLE_DIR_CENTRAL_PERIPHERAL) {
                        if (control_proc_can_add_frame(pinfo,
                                                       last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                       LL_CTRL_OPCODE_PHY_REQ, 2)) {
                            control_proc_add_frame_with_instant(tvb,
                                                                pinfo,
                                                                btle_tree,
                                                                btle_context,
                                                                control_opcode,
                                                                direction,
                                                                last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                                last_control_proc[BTLE_DIR_PERIPHERAL_CENTRAL],
                                                                2,
                                                                item_value);
                        } else if (control_proc_can_add_frame(pinfo,
                                                              last_control_proc[BTLE_DIR_PERIPHERAL_CENTRAL],
                                                              LL_CTRL_OPCODE_PHY_REQ, 1)){
                            control_proc_add_frame_with_instant(tvb,
                                                                pinfo,
                                                                btle_tree,
                                                                btle_context,
                                                                control_opcode,
                                                                direction,
                                                                last_control_proc[BTLE_DIR_PERIPHERAL_CENTRAL],
                                                                last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                                1,
                                                                item_value);
                        } else {
                            expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                        }
                    } else if (direction == BTLE_DIR_PERIPHERAL_CENTRAL) {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }

                break;
            }
            case LL_CTRL_OPCODE_MIN_USED_CHANNELS_IND:
                proto_tree_add_bitmask(btle_tree, tvb, offset, hf_control_phys, ett_phys, hfx_control_phys, ENC_NA);
                offset += 1;

                proto_tree_add_item(btle_tree, hf_control_min_used_channels, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset += 1;

                if (connection_info && !btle_frame_info->retransmit) {
                    /* The LL_MIN_USED_CHANNELS_IND can only be sent from peripheral to central. */
                    if (direction == BTLE_DIR_PERIPHERAL_CENTRAL) {
                        control_proc_info_t *proc_info;
                        proc_info = control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                                       connection_info->direction_info[direction].control_procs,
                                                       last_control_proc[other_direction],
                                                       control_opcode);

                        /* Procedure completes in the same frame. */
                        if (proc_info) {
                            proc_info->last_frame = pinfo->num;
                        }
                    } else if (direction == BTLE_DIR_CENTRAL_PERIPHERAL) {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }
                break;
            case LL_CTRL_OPCODE_CTE_REQ:
                proto_tree_add_bitmask(btle_tree, tvb, offset, hf_control_phys, ett_cte, hfx_control_cte, ENC_NA);
                offset += 1;
                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                       connection_info->direction_info[direction].control_procs,
                                       last_control_proc[other_direction],
                                       control_opcode);
                }
                break;
            case LL_CTRL_OPCODE_CTE_RSP:
                offset = dissect_ctrl_pdu_without_data(tvb, pinfo, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    if (control_proc_can_add_frame(pinfo,
                                                   last_control_proc[other_direction],
                                                   LL_CTRL_OPCODE_CTE_REQ, 1)) {
                        control_proc_add_last_frame(tvb,
                                                    pinfo,
                                                    btle_tree,
                                                    control_opcode,
                                                    direction,
                                                    last_control_proc[other_direction],
                                                    last_control_proc[direction],
                                                    1);
                    } else {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }
                break;
            case LL_CTRL_OPCODE_PERIODIC_SYNC_IND:
                offset = dissect_periodic_sync_ind(tvb, btle_tree, offset, pinfo, interface_id, adapter_id);
                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    control_proc_info_t *proc_info;
                    proc_info = control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                                   connection_info->direction_info[direction].control_procs,
                                                   last_control_proc[other_direction],
                                                   control_opcode);

                    /* Procedure completes in the same frame. */
                    if (proc_info) {
                        proc_info->last_frame = pinfo->num;
                    }
                }
                break;
            case LL_CTRL_OPCODE_CLOCK_ACCURACY_REQ:
                proto_tree_add_item(btle_tree, hf_control_sleep_clock_accuracy, tvb, offset, 1, ENC_NA);
                offset += 1;
                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                       connection_info->direction_info[direction].control_procs,
                                       last_control_proc[other_direction],
                                       control_opcode);
                }
                break;
            case LL_CTRL_OPCODE_CLOCK_ACCURACY_RSP:
                proto_tree_add_item(btle_tree, hf_control_sleep_clock_accuracy, tvb, offset, 1, ENC_NA);
                offset += 1;
                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    if (control_proc_can_add_frame(pinfo,
                                                   last_control_proc[other_direction],
                                                   LL_CTRL_OPCODE_CLOCK_ACCURACY_REQ, 1)) {
                        control_proc_add_last_frame(tvb,
                                                    pinfo,
                                                    btle_tree,
                                                    control_opcode,
                                                    direction,
                                                    last_control_proc[other_direction],
                                                    last_control_proc[direction],
                                                    1);
                    } else {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }
                break;
            case LL_CTRL_OPCODE_CIS_REQ:
                offset = dissect_cis_req(tvb, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit) {
                    if (direction == BTLE_DIR_CENTRAL_PERIPHERAL) {
                        control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                           connection_info->direction_info[BTLE_DIR_CENTRAL_PERIPHERAL].control_procs,
                                           last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                           control_opcode);
                    } else if (direction == BTLE_DIR_PERIPHERAL_CENTRAL) {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }
                break;
            case LL_CTRL_OPCODE_CIS_RSP:
                offset = dissect_cis_rsp(tvb, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    if (control_proc_can_add_frame(pinfo,
                                                   last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                   LL_CTRL_OPCODE_CIS_REQ, 1)) {
                        control_proc_add_frame(tvb,
                                               pinfo,
                                               btle_tree,
                                               control_opcode,
                                               direction,
                                               last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                               last_control_proc[BTLE_DIR_PERIPHERAL_CENTRAL],
                                               1);
                    } else {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }
                break;
            case LL_CTRL_OPCODE_CIS_IND:
                if (!pinfo->fd->visited) {
                    connection_info_t *nconnection_info;
                    connection_parameter_info_t *connection_parameter_info;

                    connection_access_address = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);

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
                        memcpy(nconnection_info->central_bd_addr, connection_info->central_bd_addr, 6);
                        memcpy(nconnection_info->peripheral_bd_addr,  connection_info->peripheral_bd_addr,  6);
                    }

                    /* We don't create control procedure context trees for BTLE_DIR_UNKNOWN,
                     * as the direction must be known for request/response matching. */
                    nconnection_info->direction_info[BTLE_DIR_CENTRAL_PERIPHERAL].control_procs =
                        wmem_tree_new(wmem_file_scope());
                    nconnection_info->direction_info[BTLE_DIR_PERIPHERAL_CENTRAL].control_procs =
                        wmem_tree_new(wmem_file_scope());

                    wmem_tree_insert32_array(connection_info_tree, key, nconnection_info);

                    connection_parameter_info = wmem_new0(wmem_file_scope(), connection_parameter_info_t);
                    connection_parameter_info->parameters_frame = pinfo->num;

                    key[3].length = 1;
                    key[3].key = &pinfo->num;
                    wmem_tree_insert32_array(connection_parameter_info_tree, key, connection_parameter_info);
                }
                offset = dissect_cis_ind(tvb, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    if (control_proc_can_add_frame(pinfo,
                                                   last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                   LL_CTRL_OPCODE_CIS_REQ, 2)) {
                        control_proc_add_last_frame(tvb,
                                                    pinfo,
                                                    btle_tree,
                                                    control_opcode,
                                                    direction,
                                                    last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                    last_control_proc[BTLE_DIR_PERIPHERAL_CENTRAL],
                                                    2);
                    } else {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }
                break;
            case LL_CTRL_OPCODE_CIS_TERMINATE_IND:
                offset = dissect_cis_terminate_ind(tvb, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    control_proc_info_t *proc_info;
                    proc_info = control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                                   connection_info->direction_info[direction].control_procs,
                                                   last_control_proc[other_direction],
                                                   control_opcode);

                    /* Procedure completes in the same frame. */
                    if (proc_info) {
                        proc_info->last_frame = pinfo->num;
                    }
                }
                break;
            case LL_CTRL_OPCODE_POWER_CONTROL_REQ:
                offset = dissect_power_control_req(tvb, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                       connection_info->direction_info[direction].control_procs,
                                       last_control_proc[other_direction],
                                       control_opcode);
                }
                break;
            case LL_CTRL_OPCODE_POWER_CONTROL_RSP:
                offset = dissect_power_control_rsp(tvb, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    if (control_proc_can_add_frame(pinfo,
                                                   last_control_proc[other_direction],
                                                   LL_CTRL_OPCODE_POWER_CONTROL_REQ, 1)) {
                        control_proc_add_last_frame(tvb,
                                                    pinfo,
                                                    btle_tree,
                                                    control_opcode,
                                                    direction,
                                                    last_control_proc[other_direction],
                                                    last_control_proc[direction],
                                                    1);
                    } else {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }
                break;
            case LL_CTRL_OPCODE_POWER_CHANGE_IND:
                offset = dissect_power_control_ind(tvb, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    control_proc_info_t *proc_info;
                    proc_info = control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                                   connection_info->direction_info[direction].control_procs,
                                                   last_control_proc[other_direction],
                                                   control_opcode);

                    /* Procedure completes in the same frame. */
                    if (proc_info) {
                        proc_info->last_frame = pinfo->num;
                    }
                }
                break;
            case LL_CTRL_OPCODE_SUBRATE_REQ:
                offset = dissect_subrate_req(tvb, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit) {
                    if (direction == BTLE_DIR_PERIPHERAL_CENTRAL) {
                        control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                           connection_info->direction_info[BTLE_DIR_PERIPHERAL_CENTRAL].control_procs,
                                           last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                           control_opcode);
                    } else if (direction == BTLE_DIR_CENTRAL_PERIPHERAL) {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }
                break;
            case LL_CTRL_OPCODE_SUBRATE_IND:
                offset = dissect_subrate_ind(tvb, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit) {
                    if (control_proc_can_add_frame(pinfo,
                                                   last_control_proc[BTLE_DIR_PERIPHERAL_CENTRAL],
                                                   LL_CTRL_OPCODE_SUBRATE_REQ, 1)) {
                        control_proc_add_last_frame(tvb,
                                                    pinfo,
                                                    btle_tree,
                                                    control_opcode,
                                                    direction,
                                                    last_control_proc[BTLE_DIR_PERIPHERAL_CENTRAL],
                                                    last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                    1);
                    } else if (direction == BTLE_DIR_CENTRAL_PERIPHERAL) {
                        control_proc_info_t *proc_info;
                        proc_info = control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                                       connection_info->direction_info[BTLE_DIR_CENTRAL_PERIPHERAL].control_procs,
                                                       last_control_proc[BTLE_DIR_PERIPHERAL_CENTRAL],
                                                       control_opcode);

                        /* Procedure completes in the same frame. */
                        if (proc_info) {
                            proc_info->last_frame = pinfo->num;
                        }
                    } else {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }
                break;
            case LL_CTRL_OPCODE_CHANNEL_REPORTING_IND:
                offset = dissect_channel_reporting_ind(tvb, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit) {
                    if (direction == BTLE_DIR_CENTRAL_PERIPHERAL) {
                        control_proc_info_t *proc_info;
                        proc_info = control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                                       connection_info->direction_info[BTLE_DIR_CENTRAL_PERIPHERAL].control_procs,
                                                       last_control_proc[BTLE_DIR_PERIPHERAL_CENTRAL],
                                                       control_opcode);

                        /* Procedure completes in the same frame. */
                        if (proc_info) {
                            proc_info->last_frame = pinfo->num;
                        }
                    } else if (direction == BTLE_DIR_PERIPHERAL_CENTRAL) {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }
                break;
            case LL_CTRL_OPCODE_CHANNEL_STATUS_IND:
                offset = dissect_channel_status_ind(tvb, btle_tree, offset);
                if (connection_info && !btle_frame_info->retransmit) {
                    if (direction == BTLE_DIR_PERIPHERAL_CENTRAL) {
                        control_proc_info_t *proc_info;
                        proc_info = control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                                       connection_info->direction_info[BTLE_DIR_PERIPHERAL_CENTRAL].control_procs,
                                                       last_control_proc[BTLE_DIR_CENTRAL_PERIPHERAL],
                                                       control_opcode);

                        /* Procedure completes in the same frame. */
                        if (proc_info) {
                            proc_info->last_frame = pinfo->num;
                        }
                    } else if (direction == BTLE_DIR_CENTRAL_PERIPHERAL) {
                        expert_add_info(pinfo, control_proc_item, &ei_control_proc_wrong_seq);
                    }
                }
                break;
            case LL_CTRL_OPCODE_PERIODIC_SYNC_WR_IND:
                offset = dissect_periodic_sync_wr_ind(tvb, btle_tree, offset, pinfo, interface_id, adapter_id);
                if (connection_info && !btle_frame_info->retransmit && direction != BTLE_DIR_UNKNOWN) {
                    control_proc_info_t *proc_info;
                    proc_info = control_proc_start(tvb, pinfo, btle_tree, control_proc_item,
                                                   connection_info->direction_info[direction].control_procs,
                                                   last_control_proc[other_direction],
                                                   control_opcode);

                    /* Procedure completes in the same frame. */
                    if (proc_info) {
                        proc_info->last_frame = pinfo->num;
                    }
                }
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
                if ( ((int16_t)btle_context->event_counter - connection_info->connection_parameter_update_instant) >= 0) {
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
    } else if (btle_pdu_type == BTLE_PDU_TYPE_BROADCASTISO) {
        broadcastiso_connection_info_t *broadcastiso_connection_info = NULL;
        uint32_t     seed_access_address = access_address & 0x0041ffff;
        proto_item  *data_header_item;
        proto_tree  *data_header_tree;
        uint8_t      llid;
        uint8_t      control_opcode;

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
                char   *str_addr_src;
                /* Holds "Central" + access_address + NULL, which is the longest string */
                int     str_addr_len = 17 + 1;

                str_addr_src = (char *) wmem_alloc(pinfo->pool, str_addr_len);

                sub_item = proto_tree_add_ether(btle_tree, hf_central_bd_addr, tvb, 0, 0, broadcastiso_connection_info->central_bd_addr);
                proto_item_set_generated(sub_item);

                snprintf(str_addr_src, str_addr_len, "Central_0x%08x", broadcastiso_connection_info->access_address);
                set_address(&pinfo->dl_src, AT_ETHER, sizeof(broadcastiso_connection_info->central_bd_addr), broadcastiso_connection_info->central_bd_addr);
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
        llid = tvb_get_uint8(tvb, offset) & 0x03;
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
            control_opcode = tvb_get_uint8(tvb, offset);
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
        /* Unknown physical channel PDU type. Assume CRC size is 3 bytes */
        if (tvb_reported_length_remaining(tvb, offset) > 3) {
                proto_tree_add_expert(btle_tree, pinfo, &ei_unknown_data, tvb, offset, tvb_reported_length_remaining(tvb, offset) - 3);
                length = tvb_reported_length_remaining(tvb, offset) - 3;
                offset += length;
        } else {
            /* Length is unknown. */
            length = 0;
        }
    }

    offset += dissect_crc(tvb,
                          btle_tree,
                          offset,
                          pinfo,
                          length,
                          connection_info,
                          btle_context,
                          access_address);

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
        { &hf_central_bd_addr,
            { "Central Address",                  "btle.central_bd_addr",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_peripheral_bd_addr,
            { "Peripheral Address",                   "btle.peripheral_bd_addr",
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
            { "Reserved",                        "btle.extended_advertising_header.sync_info.reserved",
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
        { &hf_control_feature_set_peripheral_initiated_features_exchange,
            { "Peripheral Initiated Features Exchange",    "btle.control.feature_set.peripheral_initiated_features_exchange",
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
        { &hf_control_feature_set_connection_cte_request,
        { "Connection CTE Request", "btle.control.feature_set.connection_cte_request",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_control_feature_set_connection_cte_response,
        { "Connection CTE Response", "btle.control.feature_set.connection_cte_response",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_control_feature_set_connectionless_cte_tx,
        { "Connectionless CTE Transmitter", "btle.control.feature_set.connectionless_cte_transmitter",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_control_feature_set_connectionless_cte_rx,
        { "Connectionless CTE Receiver", "btle.control.feature_set.connectionless_cte_receiver",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_control_feature_set_antenna_switching_tx_aod,
        { "Antenna Switching During CTE Transmission (AoD)", "btle.control.feature_set.antenna_switching_tx_aod",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_control_feature_set_antenna_switching_rx_aoa,
        { "Antenna Switching During CTE Reception (AoA)", "btle.control.feature_set.antenna_switching_rx_aoa",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_control_feature_set_cte_rx,
        { "Receiving Constant Tone Extensions", "btle.control.feature_set.cte_rx",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_control_feature_set_past_sender,
        { "Periodic Advertising Sync Transfer - Sender", "btle.control.feature_set.past_sender",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_control_feature_set_past_receiver,
        { "Periodic Advertising Sync Transfer - Receiver", "btle.control.feature_set.past_receiver",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_control_feature_set_sca_updates,
        { "Sleep Clock Accuracy Updates", "btle.control.feature_set.sca_updates",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_control_feature_set_remote_public_key_validation,
        { "Remote Public Key Validation", "btle.control.feature_set.remote_public_key_validation",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_control_feature_set_cis_central,
        { "Connected Isochronous Stream - Central", "btle.control.feature_set.cis_central",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_control_feature_set_cis_peripheral,
        { "Connected Isochronous Stream - Peripheral", "btle.control.feature_set.cis_peripheral",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_control_feature_set_iso_broadcast,
        { "Isochronous Broadcaster", "btle.control.feature_set.iso_broadcast",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_control_feature_set_synchronized_receiver,
        { "Synchronized Receiver", "btle.control.feature_set.synchronized_receiver",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_control_feature_set_connected_iso_host_support,
        { "Connected Isochronous Stream (Host Support)", "btle.control.feature_set.connected_iso_host_support",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_control_feature_set_le_power_control_request1,
        { "LE Power Control Request", "btle.control.feature_set.le_power_control_request",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_control_feature_set_le_power_control_request2,
        { "LE Power Control Request", "btle.control.feature_set.le_power_control_request_bit_2",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_control_feature_set_le_path_loss_monitoring,
        { "LE Path Loss Monitoring", "btle.control.feature_set.le_path_loss_monitoring",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_control_feature_set_le_periodic_adv_adi_support,
        { "Periodic Advertising ADI support", "btle.control.feature_set.le_periodic_adv_adi_support",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_control_feature_set_connection_subrating,
        { "Connection Subrating", "btle.control.feature_set.connection_subrating",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_control_feature_set_connection_subrating_host_support,
        { "Connection Subrating (Host Support)", "btle.control.feature_set.connection_subrating_host_support",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_control_feature_set_channel_classification,
        { "Channel Classification", "btle.control.feature_set.channel_classification",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_control_feature_set_adv_coding_selection,
        { "Advertising Coding Selection", "btle.control.feature_set.adv_coding_selection",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        { &hf_control_feature_set_adv_coding_selection_host_support,
        { "Advertising Coding Selection (Host Support)", "btle.control.feature_set.adv_coding_selection_host_support",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}
        },
        { &hf_control_feature_set_periodic_adv_with_responses_advertiser,
        {"Periodic Advertising with Responses - Advertiser", "btle.control.feature_set.periodic_adv_with_responses_advertiser",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL}
        },
        { &hf_control_feature_set_periodic_adv_with_responses_scanner,
        {"Periodic Advertising with Responses - Scanner", "btle.control.feature_set.adv_with_responses_scanner",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL}
        },
        { &hf_control_feature_set_reserved_bits,
        { "Reserved bits", "btle.control.feature_set.reserved_bits",
            FT_UINT8, BASE_DEC, NULL, 0xF0,
            NULL, HFILL}
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
        { &hf_control_rfu_5,
            { "Reserved for future use",         "btle.control.reserved",
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
        { &hf_control_central_session_key_diversifier,
            { "Central Session Key Diversifier",  "btle.control.central_session_key_diversifier",
            FT_UINT64, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_peripheral_session_key_diversifier,
            { "Peripheral Session Key Diversifier",   "btle.control.peripheral_session_key_diversifier",
            FT_UINT64, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_central_session_initialization_vector,
            { "Central Session Initialization Vector",      "btle.control.central_session_initialization_vector",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_peripheral_session_initialization_vector,
            { "Peripheral Session Initialization Vector",       "btle.control.peripheral_session_initialization_vector",
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
        { &hf_control_c_to_p_phy,
            { "Central to Peripheral PHY", "btle.control.m_to_s_phy",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_c_to_p_phy_le_1m_phy,
            { "LE 1M PHY", "btle.control.m_to_s_phy.le_1m_phy",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_control_c_to_p_phy_le_2m_phy,
            { "LE 2M PHY", "btle.control.m_to_s_phy.le_2m_phy",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_control_c_to_p_phy_le_coded_phy,
            { "LE Coded PHY", "btle.control.m_to_s_phy.le_coded_phy",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_control_c_to_p_phy_reserved_bits,
            { "Reserved for future use", "btle.control.m_to_s_phy.reserved",
            FT_UINT8, BASE_DEC, NULL, 0xF8,
            NULL, HFILL }
        },
        { &hf_control_p_to_c_phy,
            { "Peripheral to Central PHY", "btle.control.s_to_m_phy",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_p_to_c_phy_le_1m_phy,
            { "LE 1M PHY", "btle.control.s_to_m_phy.le_1m_phy",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_control_p_to_c_phy_le_2m_phy,
            { "LE 2M PHY", "btle.control.s_to_m_phy.le_2m_phy",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_control_p_to_c_phy_le_coded_phy,
            { "LE Coded PHY", "btle.control.s_to_m_phy.le_coded_phy",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_control_p_to_c_phy_reserved_bits,
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
           { "Reserved", "btle.control.cte.rfu",
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
            FT_UINT16, BASE_HEX, NULL, 0x0,
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
            { "Reserved",                        "btle.control.sync_info.reserved",
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
        { &hf_control_max_sdu_c_to_p,
            { "Max_SDU_C_To_P",                  "btle.control.max_sdu_c_to_p",
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
        { &hf_control_max_sdu_p_to_c,
            { "Max_SDU_P_To_C",                  "btle.control.max_sdu_p_to_c",
            FT_UINT16, BASE_DEC, NULL, 0x0fff,
            NULL, HFILL }
        },
        { &hf_control_rfu_2,
            { "Reserved",                        "btle.control.rfu.2",
            FT_UINT16, BASE_DEC, NULL, 0xf000,
            "Reserved for Future Use", HFILL }
        },
        { &hf_control_sdu_interval_c_to_p,
            { "SDU_Interval_C_To_P",             "btle.control.sdu_interval_c_to_p",
            FT_UINT24, BASE_DEC|BASE_UNIT_STRING, &units_microsecond_microseconds, 0x0fffff,
            NULL, HFILL }
        },
        { &hf_control_rfu_3,
            { "Reserved",                        "btle.control.rfu.3",
            FT_UINT24, BASE_DEC, NULL, 0xf00000,
            "Reserved for Future Use", HFILL }
        },
        { &hf_control_sdu_interval_p_to_c,
            { "SDU_Interval_P_To_C",             "btle.control.sdu_interval_p_to_c",
            FT_UINT24, BASE_DEC|BASE_UNIT_STRING, &units_microsecond_microseconds, 0x0fffff,
            NULL, HFILL }
        },
        { &hf_control_rfu_4,
            { "Reserved",                        "btle.control.rfu.4",
            FT_UINT24, BASE_DEC, NULL, 0xf00000,
            "Reserved for Future Use", HFILL }
        },
        { &hf_control_max_pdu_c_to_p,
            { "Max_PDU_C_To_P",                  "btle.control.max_pdu_c_to_p",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_max_pdu_p_to_c,
            { "Max_PDU_P_To_C",                  "btle.control.max_pdu_p_to_c",
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
        { &hf_control_bn_c_to_p,
            { "BN_C_To_P",                       "btle.control.bn_c_to_p",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_control_bn_p_to_c,
            { "BN_P_To_C",                       "btle.control.bn_p_to_c",
            FT_UINT8, BASE_DEC, NULL, 0xf0,
            NULL, HFILL }
        },
        { &hf_control_ft_c_to_p,
            { "FT_C_To_P",                       "btle.control.ft_c_to_p",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_ft_p_to_c,
            { "FT_P_To_C",                       "btle.control.ft_p_to_c",
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
        { &hf_control_subrate_factor_min,
            {"Minimum subrating factor", "btle.control.subrate_factor_min",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_subrate_factor_max,
            {"Minimum subrating factor", "btle.control.subrate_factor_max",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_max_latency,
            {"Maximum peripheral latency in subrated events", "btle.control.max_latency",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_continuation_number,
            {"The minimum requested continuation number", "btle.control.continuation_number",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_subrate_factor,
            {"Subrate factor", "btle.control.subrate_factor",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_subrate_base_event,
            {"Subrate base event", "btle.control.subrate_base_event",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_channel_reporting_enable,
            {"Enable channel reporting", "btle.control.channel_reporting_enable",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_channel_reporting_min_spacing,
            {"Channel reporting min spacing (200 ms units)", "btle.control.channel_reporting_min_spacing",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_channel_reporting_max_delay,
            {"Channel reporting max delay (200 ms units)", "btle.control.channel_reporting_max_delay",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_channel_classification,
            {"Channel classification", "btle.control.hf_control_channel_classification",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_control_sync_info_rsp_access_address,
            {"Response Access Address", "btle.control.sync_info.rsp_aa",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_control_sync_info_num_subevents,
            {"Num subevents", "btle.control.sync_info.num_subevents",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_control_sync_info_subevent_interval,
            {"Subevent interval", "btle.control.sync_info.subevent_interval",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL}
        },
        { &hf_control_sync_info_response_slot_delay,
            {"Response slot delay", "btle.control.sync_info.response_slot_delay",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL}
        },
        { &hf_control_sync_info_response_slot_spacing,
            {"Response slot spacing", "btle.control.sync_info.response_slot_spacing",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL}
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
        { &ei_control_proc_invalid_conflict_resolution,
            { "btle.ei_control_proc_invalid_conflict_resolution",
            PI_PROTOCOL, PI_ERROR, "Incorrect control procedure packet collision resolution. See Core_v5.2, Vol 6, Part B, Section 5.3", EXPFILL }},
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

    static int *ett[] = {
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
        &ett_c_to_p_phy,
        &ett_p_to_c_phy,
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
    periodic_adv_info_tree = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
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
            "Bluetooth LE LL version: 5.4 (Core)",
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
