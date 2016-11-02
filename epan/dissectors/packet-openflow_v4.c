/* packet-openflow_v4.c
 * Routines for OpenFlow dissection
 * Copyright 2013, Anders Broman <anders.broman@ericsson.com>
 * Copyright 2013, Zoltan Lajos Kis <zoltan.lajos.kis@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Ref https://www.opennetworking.org/sdn-resources/onf-specifications/openflow
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/expert.h>
#include <epan/ipproto.h>

void proto_register_openflow_v4(void);
void proto_reg_handoff_openflow_v4(void);

static dissector_handle_t eth_withoutfcs_handle;

static int proto_openflow_v4 = -1;
static int hf_openflow_v4_version = -1;
static int hf_openflow_v4_type = -1;
static int hf_openflow_v4_length = -1;
static int hf_openflow_v4_xid = -1;
static int hf_openflow_v4_oxm_class = -1;
static int hf_openflow_v4_oxm_field = -1;
static int hf_openflow_v4_oxm_field_basic = -1;
static int hf_openflow_v4_oxm_hm = -1;
static int hf_openflow_v4_oxm_length = -1;
static int hf_openflow_v4_oxm_experimenter_experimenter = -1;
static int hf_openflow_v4_oxm_experimenter_value = -1;
static int hf_openflow_v4_oxm_value = -1;
static int hf_openflow_v4_oxm_value_etheraddr = -1;
static int hf_openflow_v4_oxm_value_vlan_present = -1;
static int hf_openflow_v4_oxm_value_vlan_vid = -1;
static int hf_openflow_v4_oxm_value_ethertype = -1;
static int hf_openflow_v4_oxm_value_ipv4addr = -1;
static int hf_openflow_v4_oxm_value_ipv6addr = -1;
static int hf_openflow_v4_oxm_value_ipproto = -1;
static int hf_openflow_v4_oxm_value_uint16 = -1;
static int hf_openflow_v4_oxm_value_uint24 = -1;
static int hf_openflow_v4_oxm_value_uint32 = -1;
static int hf_openflow_v4_oxm_mask = -1;
static int hf_openflow_v4_oxm_mask_etheraddr = -1;
static int hf_openflow_v4_oxm_mask_ipv4addr = -1;
static int hf_openflow_v4_oxm_mask_ipv6addr = -1;
static int hf_openflow_v4_match_type = -1;
static int hf_openflow_v4_match_length = -1;
static int hf_openflow_v4_match_pad = -1;
static int hf_openflow_v4_action_type = -1;
static int hf_openflow_v4_action_length = -1;
static int hf_openflow_v4_action_experimenter_experimenter = -1;
static int hf_openflow_v4_action_output_port = -1;
static int hf_openflow_v4_action_output_port_reserved = -1;
static int hf_openflow_v4_action_output_max_len = -1;
static int hf_openflow_v4_action_output_max_len_reserved = -1;
static int hf_openflow_v4_action_output_pad = -1;
static int hf_openflow_v4_action_copy_ttl_out_pad = -1;
static int hf_openflow_v4_action_copy_ttl_in_pad = -1;
static int hf_openflow_v4_action_set_mpls_ttl_ttl = -1;
static int hf_openflow_v4_action_set_mpls_ttl_pad = -1;
static int hf_openflow_v4_action_dec_mpls_ttl_pad = -1;
static int hf_openflow_v4_action_push_vlan_ethertype = -1;
static int hf_openflow_v4_action_push_vlan_pad = -1;
static int hf_openflow_v4_action_pop_vlan_pad = -1;
static int hf_openflow_v4_action_push_mpls_ethertype = -1;
static int hf_openflow_v4_action_push_mpls_pad = -1;
static int hf_openflow_v4_action_pop_mpls_ethertype = -1;
static int hf_openflow_v4_action_pop_mpls_pad = -1;
static int hf_openflow_v4_action_set_queue_queue_id = -1;
static int hf_openflow_v4_action_group_group_id = -1;
static int hf_openflow_v4_action_group_group_id_reserved = -1;
static int hf_openflow_v4_action_set_nw_ttl_ttl = -1;
static int hf_openflow_v4_action_set_nw_ttl_pad = -1;
static int hf_openflow_v4_action_dec_nw_ttl_pad = -1;
static int hf_openflow_v4_action_set_field_pad = -1;
static int hf_openflow_v4_action_push_pbb_ethertype = -1;
static int hf_openflow_v4_action_push_pbb_pad = -1;
static int hf_openflow_v4_action_pop_pbb_pad = -1;
static int hf_openflow_v4_instruction_type = -1;
static int hf_openflow_v4_instruction_length = -1;
static int hf_openflow_v4_instruction_experimenter_experimenter = -1;
static int hf_openflow_v4_instruction_goto_table_table_id = -1;
static int hf_openflow_v4_instruction_goto_table_pad = -1;
static int hf_openflow_v4_instruction_write_metadata_pad = -1;
static int hf_openflow_v4_instruction_write_metadata_value = -1;
static int hf_openflow_v4_instruction_write_metadata_mask = -1;
static int hf_openflow_v4_instruction_actions_pad = -1;
static int hf_openflow_v4_instruction_meter_meter_id = -1;
static int hf_openflow_v4_instruction_meter_meter_id_reserved = -1;
static int hf_openflow_v4_port_port_no = -1;
static int hf_openflow_v4_port_port_no_reserved = -1;
static int hf_openflow_v4_port_pad = -1;
static int hf_openflow_v4_port_hw_addr = -1;
static int hf_openflow_v4_port_pad2 = -1;
static int hf_openflow_v4_port_name = -1;
static int hf_openflow_v4_port_config = -1;
static int hf_openflow_v4_port_config_port_down = -1;
static int hf_openflow_v4_port_config_no_recv = -1;
static int hf_openflow_v4_port_config_no_fwd = -1;
static int hf_openflow_v4_port_config_no_packet_in = -1;
static int hf_openflow_v4_port_state = -1;
static int hf_openflow_v4_port_state_link_down = -1;
static int hf_openflow_v4_port_state_blocked = -1;
static int hf_openflow_v4_port_state_live = -1;
static int hf_openflow_v4_port_current = -1;
static int hf_openflow_v4_port_current_10mb_hd = -1;
static int hf_openflow_v4_port_current_10mb_fd = -1;
static int hf_openflow_v4_port_current_100mb_hd = -1;
static int hf_openflow_v4_port_current_100mb_fd = -1;
static int hf_openflow_v4_port_current_1gb_hd = -1;
static int hf_openflow_v4_port_current_1gb_fd = -1;
static int hf_openflow_v4_port_current_10gb_fd = -1;
static int hf_openflow_v4_port_current_40gb_fd = -1;
static int hf_openflow_v4_port_current_100gb_fd = -1;
static int hf_openflow_v4_port_current_1tb_fd = -1;
static int hf_openflow_v4_port_current_other = -1;
static int hf_openflow_v4_port_current_copper = -1;
static int hf_openflow_v4_port_current_fiber = -1;
static int hf_openflow_v4_port_current_autoneg = -1;
static int hf_openflow_v4_port_current_pause = -1;
static int hf_openflow_v4_port_current_pause_asym = -1;
static int hf_openflow_v4_port_advertised = -1;
static int hf_openflow_v4_port_advertised_10mb_hd = -1;
static int hf_openflow_v4_port_advertised_10mb_fd = -1;
static int hf_openflow_v4_port_advertised_100mb_hd = -1;
static int hf_openflow_v4_port_advertised_100mb_fd = -1;
static int hf_openflow_v4_port_advertised_1gb_hd = -1;
static int hf_openflow_v4_port_advertised_1gb_fd = -1;
static int hf_openflow_v4_port_advertised_10gb_fd = -1;
static int hf_openflow_v4_port_advertised_40gb_fd = -1;
static int hf_openflow_v4_port_advertised_100gb_fd = -1;
static int hf_openflow_v4_port_advertised_1tb_fd = -1;
static int hf_openflow_v4_port_advertised_other = -1;
static int hf_openflow_v4_port_advertised_copper = -1;
static int hf_openflow_v4_port_advertised_fiber = -1;
static int hf_openflow_v4_port_advertised_autoneg = -1;
static int hf_openflow_v4_port_advertised_pause = -1;
static int hf_openflow_v4_port_advertised_pause_asym = -1;
static int hf_openflow_v4_port_supported = -1;
static int hf_openflow_v4_port_supported_10mb_hd = -1;
static int hf_openflow_v4_port_supported_10mb_fd = -1;
static int hf_openflow_v4_port_supported_100mb_hd = -1;
static int hf_openflow_v4_port_supported_100mb_fd = -1;
static int hf_openflow_v4_port_supported_1gb_hd = -1;
static int hf_openflow_v4_port_supported_1gb_fd = -1;
static int hf_openflow_v4_port_supported_10gb_fd = -1;
static int hf_openflow_v4_port_supported_40gb_fd = -1;
static int hf_openflow_v4_port_supported_100gb_fd = -1;
static int hf_openflow_v4_port_supported_1tb_fd = -1;
static int hf_openflow_v4_port_supported_other = -1;
static int hf_openflow_v4_port_supported_copper = -1;
static int hf_openflow_v4_port_supported_fiber = -1;
static int hf_openflow_v4_port_supported_autoneg = -1;
static int hf_openflow_v4_port_supported_pause = -1;
static int hf_openflow_v4_port_supported_pause_asym = -1;
static int hf_openflow_v4_port_peer = -1;
static int hf_openflow_v4_port_peer_10mb_hd = -1;
static int hf_openflow_v4_port_peer_10mb_fd = -1;
static int hf_openflow_v4_port_peer_100mb_hd = -1;
static int hf_openflow_v4_port_peer_100mb_fd = -1;
static int hf_openflow_v4_port_peer_1gb_hd = -1;
static int hf_openflow_v4_port_peer_1gb_fd = -1;
static int hf_openflow_v4_port_peer_10gb_fd = -1;
static int hf_openflow_v4_port_peer_40gb_fd = -1;
static int hf_openflow_v4_port_peer_100gb_fd = -1;
static int hf_openflow_v4_port_peer_1tb_fd = -1;
static int hf_openflow_v4_port_peer_other = -1;
static int hf_openflow_v4_port_peer_copper = -1;
static int hf_openflow_v4_port_peer_fiber = -1;
static int hf_openflow_v4_port_peer_autoneg = -1;
static int hf_openflow_v4_port_peer_pause = -1;
static int hf_openflow_v4_port_peer_pause_asym = -1;
static int hf_openflow_v4_port_curr_speed = -1;
static int hf_openflow_v4_port_max_speed = -1;
static int hf_openflow_v4_meter_band_type = -1;
static int hf_openflow_v4_meter_band_len = -1;
static int hf_openflow_v4_meter_band_rate = -1;
static int hf_openflow_v4_meter_band_burst_size = -1;
static int hf_openflow_v4_meter_band_drop_pad = -1;
static int hf_openflow_v4_meter_band_dscp_remark_prec_level = -1;
static int hf_openflow_v4_meter_band_dscp_remark_pad= -1;
static int hf_openflow_v4_meter_band_experimenter_experimenter = -1;
static int hf_openflow_v4_hello_element_type = -1;
static int hf_openflow_v4_hello_element_length = -1;
static int hf_openflow_v4_hello_element_version_bitmap = -1;
static int hf_openflow_v4_hello_element_pad = -1;
static int hf_openflow_v4_error_type = -1;
static int hf_openflow_v4_error_hello_failed_code = -1;
static int hf_openflow_v4_error_bad_request_code = -1;
static int hf_openflow_v4_error_bad_action_code = -1;
static int hf_openflow_v4_error_bad_instruction_code = -1;
static int hf_openflow_v4_error_bad_match_code = -1;
static int hf_openflow_v4_error_flow_mod_failed_code = -1;
static int hf_openflow_v4_error_group_mod_failed_code = -1;
static int hf_openflow_v4_error_port_mod_failed_code = -1;
static int hf_openflow_v4_error_table_mod_failed_code = -1;
static int hf_openflow_v4_error_queue_op_failed_code = -1;
static int hf_openflow_v4_error_switch_config_failed_code = -1;
static int hf_openflow_v4_error_role_request_failed_code = -1;
static int hf_openflow_v4_error_meter_mod_failed_code = -1;
static int hf_openflow_v4_error_table_features_failed_code = -1;
static int hf_openflow_v4_error_code = -1;
static int hf_openflow_v4_error_data_text = -1;
static int hf_openflow_v4_error_data_body = -1;
static int hf_openflow_v4_error_experimenter = -1;
static int hf_openflow_v4_echo_data = -1;
static int hf_openflow_v4_experimenter_experimenter = -1;
static int hf_openflow_v4_experimenter_exp_type = -1;
static int hf_openflow_v4_switch_features_datapath_id = -1;
static int hf_openflow_v4_switch_features_n_buffers = -1;
static int hf_openflow_v4_switch_features_n_tables = -1;
static int hf_openflow_v4_switch_features_auxiliary_id = -1;
static int hf_openflow_v4_switch_features_pad = -1;
static int hf_openflow_v4_switch_features_capabilities = -1;
static int hf_openflow_v4_switch_features_capabilities_flow_stats = -1;
static int hf_openflow_v4_switch_features_capabilities_table_stats = -1;
static int hf_openflow_v4_switch_features_capabilities_port_stats = -1;
static int hf_openflow_v4_switch_features_capabilities_group_stats = -1;
static int hf_openflow_v4_switch_features_capabilities_ip_reasm = -1;
static int hf_openflow_v4_switch_features_capabilities_queue_stats = -1;
static int hf_openflow_v4_switch_features_capabilities_port_blocked = -1;
static int hf_openflow_v4_switch_features_reserved = -1;
static int hf_openflow_v4_switch_config_flags = -1;
static int hf_openflow_v4_switch_config_flags_fragments = -1;
static int hf_openflow_v4_switch_config_miss_send_len = -1;
static int hf_openflow_v4_switch_config_miss_send_len_reserved = -1;
static int hf_openflow_v4_packet_in_buffer_id = -1;
static int hf_openflow_v4_packet_in_buffer_id_reserved = -1;
static int hf_openflow_v4_packet_in_total_len = -1;
static int hf_openflow_v4_packet_in_reason = -1;
static int hf_openflow_v4_packet_in_table_id = -1;
static int hf_openflow_v4_packet_in_cookie = -1;
static int hf_openflow_v4_packet_in_pad = -1;
static int hf_openflow_v4_flow_removed_cookie = -1;
static int hf_openflow_v4_flow_removed_priority = -1;
static int hf_openflow_v4_flow_removed_reason = -1;
static int hf_openflow_v4_flow_removed_table_id = -1;
static int hf_openflow_v4_flow_removed_duration_sec = -1;
static int hf_openflow_v4_flow_removed_duration_nsec = -1;
static int hf_openflow_v4_flow_removed_idle_timeout = -1;
static int hf_openflow_v4_flow_removed_hard_timeout = -1;
static int hf_openflow_v4_flow_removed_packet_count = -1;
static int hf_openflow_v4_flow_removed_byte_count = -1;
static int hf_openflow_v4_port_status_reason = -1;
static int hf_openflow_v4_port_status_pad = -1;
static int hf_openflow_v4_packet_out_buffer_id = -1;
static int hf_openflow_v4_packet_out_buffer_id_reserved = -1;
static int hf_openflow_v4_packet_out_in_port = -1;
static int hf_openflow_v4_packet_out_in_port_reserved = -1;
static int hf_openflow_v4_packet_out_acts_len = -1;
static int hf_openflow_v4_packet_out_pad = -1;
static int hf_openflow_v4_flowmod_cookie = -1;
static int hf_openflow_v4_flowmod_cookie_mask = -1;
static int hf_openflow_v4_flowmod_table_id = -1;
static int hf_openflow_v4_flowmod_table_id_reserved = -1;
static int hf_openflow_v4_flowmod_command = -1;
static int hf_openflow_v4_flowmod_idle_timeout = -1;
static int hf_openflow_v4_flowmod_hard_timeout = -1;
static int hf_openflow_v4_flowmod_priority = -1;
static int hf_openflow_v4_flowmod_buffer_id = -1;
static int hf_openflow_v4_flowmod_buffer_id_reserved = -1;
static int hf_openflow_v4_flowmod_out_port = -1;
static int hf_openflow_v4_flowmod_out_port_reserved = -1;
static int hf_openflow_v4_flowmod_out_group = -1;
static int hf_openflow_v4_flowmod_out_group_reserved = -1;
static int hf_openflow_v4_flowmod_flags = -1;
static int hf_openflow_v4_flowmod_flags_send_flow_rem = -1;
static int hf_openflow_v4_flowmod_flags_check_overlap = -1;
static int hf_openflow_v4_flowmod_flags_reset_counts = -1;
static int hf_openflow_v4_flowmod_flags_no_packet_counts = -1;
static int hf_openflow_v4_flowmod_flags_no_byte_counts = -1;
static int hf_openflow_v4_flowmod_pad = -1;
static int hf_openflow_v4_bucket_length = -1;
static int hf_openflow_v4_bucket_weight = -1;
static int hf_openflow_v4_bucket_watch_port = -1;
static int hf_openflow_v4_bucket_watch_port_reserved = -1;
static int hf_openflow_v4_bucket_watch_group = -1;
static int hf_openflow_v4_bucket_watch_group_reserved = -1;
static int hf_openflow_v4_bucket_pad = -1;
static int hf_openflow_v4_groupmod_command = -1;
static int hf_openflow_v4_groupmod_type = -1;
static int hf_openflow_v4_groupmod_pad = -1;
static int hf_openflow_v4_groupmod_group_id = -1;
static int hf_openflow_v4_groupmod_group_id_reserved = -1;
static int hf_openflow_v4_portmod_port_no = -1;
static int hf_openflow_v4_portmod_port_no_reserved = -1;
static int hf_openflow_v4_portmod_pad = -1;
static int hf_openflow_v4_portmod_hw_addr = -1;
static int hf_openflow_v4_portmod_pad2 = -1;
static int hf_openflow_v4_portmod_config = -1;
static int hf_openflow_v4_portmod_config_port_down = -1;
static int hf_openflow_v4_portmod_config_no_recv = -1;
static int hf_openflow_v4_portmod_config_no_fwd = -1;
static int hf_openflow_v4_portmod_config_no_packet_in = -1;
static int hf_openflow_v4_portmod_mask = -1;
static int hf_openflow_v4_portmod_mask_port_down = -1;
static int hf_openflow_v4_portmod_mask_no_recv = -1;
static int hf_openflow_v4_portmod_mask_no_fwd = -1;
static int hf_openflow_v4_portmod_mask_no_packet_in = -1;
static int hf_openflow_v4_portmod_advertise = -1;
static int hf_openflow_v4_portmod_advertise_10mb_hd = -1;
static int hf_openflow_v4_portmod_advertise_10mb_fd = -1;
static int hf_openflow_v4_portmod_advertise_100mb_hd = -1;
static int hf_openflow_v4_portmod_advertise_100mb_fd = -1;
static int hf_openflow_v4_portmod_advertise_1gb_hd = -1;
static int hf_openflow_v4_portmod_advertise_1gb_fd = -1;
static int hf_openflow_v4_portmod_advertise_10gb_fd = -1;
static int hf_openflow_v4_portmod_advertise_40gb_fd = -1;
static int hf_openflow_v4_portmod_advertise_100gb_fd = -1;
static int hf_openflow_v4_portmod_advertise_1tb_fd = -1;
static int hf_openflow_v4_portmod_advertise_other = -1;
static int hf_openflow_v4_portmod_advertise_copper = -1;
static int hf_openflow_v4_portmod_advertise_fiber = -1;
static int hf_openflow_v4_portmod_advertise_autoneg = -1;
static int hf_openflow_v4_portmod_advertise_pause = -1;
static int hf_openflow_v4_portmod_advertise_pause_asym = -1;
static int hf_openflow_v4_portmod_pad3 = -1;
static int hf_openflow_v4_tablemod_table_id = -1;
static int hf_openflow_v4_tablemod_table_id_reserved = -1;
static int hf_openflow_v4_tablemod_pad = -1;
static int hf_openflow_v4_tablemod_config = -1;
static int hf_openflow_v4_flow_stats_request_table_id = -1;
static int hf_openflow_v4_flow_stats_request_table_id_reserved = -1;
static int hf_openflow_v4_flow_stats_request_pad = -1;
static int hf_openflow_v4_flow_stats_request_out_port = -1;
static int hf_openflow_v4_flow_stats_request_out_port_reserved = -1;
static int hf_openflow_v4_flow_stats_request_out_group = -1;
static int hf_openflow_v4_flow_stats_request_out_group_reserved = -1;
static int hf_openflow_v4_flow_stats_request_pad2 = -1;
static int hf_openflow_v4_flow_stats_request_cookie = -1;
static int hf_openflow_v4_flow_stats_request_cookie_mask = -1;
static int hf_openflow_v4_aggregate_stats_request_table_id = -1;
static int hf_openflow_v4_aggregate_stats_request_table_id_reserved = -1;
static int hf_openflow_v4_aggregate_stats_request_pad = -1;
static int hf_openflow_v4_aggregate_stats_request_out_port = -1;
static int hf_openflow_v4_aggregate_stats_request_out_port_reserved = -1;
static int hf_openflow_v4_aggregate_stats_request_out_group = -1;
static int hf_openflow_v4_aggregate_stats_request_out_group_reserved = -1;
static int hf_openflow_v4_aggregate_stats_request_pad2 = -1;
static int hf_openflow_v4_aggregate_stats_request_cookie = -1;
static int hf_openflow_v4_aggregate_stats_request_cookie_mask = -1;
static int hf_openflow_v4_table_feature_prop_type = -1;
static int hf_openflow_v4_table_feature_prop_length = -1;
static int hf_openflow_v4_table_feature_prop_next_tables_next_table_id = -1;
static int hf_openflow_v4_table_feature_prop_experimenter_experimenter = -1;
static int hf_openflow_v4_table_feature_prop_experimenter_exp_type = -1;
static int hf_openflow_v4_table_feature_prop_pad = -1;
static int hf_openflow_v4_table_features_length = -1;
static int hf_openflow_v4_table_features_table_id = -1;
static int hf_openflow_v4_table_features_pad = -1;
static int hf_openflow_v4_table_features_name = -1;
static int hf_openflow_v4_table_features_metadata_match = -1;
static int hf_openflow_v4_table_features_metadata_write = -1;
static int hf_openflow_v4_table_features_config = -1;
static int hf_openflow_v4_table_features_max_entries = -1;
static int hf_openflow_v4_port_stats_request_port_no = -1;
static int hf_openflow_v4_port_stats_request_port_no_reserved = -1;
static int hf_openflow_v4_port_stats_request_pad = -1;
static int hf_openflow_v4_queue_stats_request_port_no = -1;
static int hf_openflow_v4_queue_stats_request_port_no_reserved = -1;
static int hf_openflow_v4_queue_stats_request_queue_id = -1;
static int hf_openflow_v4_queue_stats_request_queue_id_reserved = -1;
static int hf_openflow_v4_group_stats_request_group_id = -1;
static int hf_openflow_v4_group_stats_request_group_id_reserved = -1;
static int hf_openflow_v4_group_stats_request_pad = -1;
static int hf_openflow_v4_meter_stats_request_meter_id = -1;
static int hf_openflow_v4_meter_stats_request_meter_id_reserved = -1;
static int hf_openflow_v4_meter_stats_request_pad = -1;
static int hf_openflow_v4_meter_config_request_meter_id = -1;
static int hf_openflow_v4_meter_config_request_meter_id_reserved = -1;
static int hf_openflow_v4_meter_config_request_pad = -1;
static int hf_openflow_v4_multipart_request_type = -1;
static int hf_openflow_v4_multipart_request_flags = -1;
static int hf_openflow_v4_multipart_request_flags_more = -1;
static int hf_openflow_v4_multipart_request_pad = -1;
static int hf_openflow_v4_multipart_request_experimenter_experimenter = -1;
static int hf_openflow_v4_multipart_request_experimenter_exp_type = -1;
static int hf_openflow_v4_switch_description_mfr_desc = -1;
static int hf_openflow_v4_switch_description_hw_desc = -1;
static int hf_openflow_v4_switch_description_sw_desc = -1;
static int hf_openflow_v4_switch_description_serial_num = -1;
static int hf_openflow_v4_switch_description_dp_desc = -1;
static int hf_openflow_v4_flow_stats_length = -1;
static int hf_openflow_v4_flow_stats_table_id = -1;
static int hf_openflow_v4_flow_stats_pad = -1;
static int hf_openflow_v4_flow_stats_duration_sec = -1;
static int hf_openflow_v4_flow_stats_duration_nsec = -1;
static int hf_openflow_v4_flow_stats_priority = -1;
static int hf_openflow_v4_flow_stats_idle_timeout = -1;
static int hf_openflow_v4_flow_stats_hard_timeout = -1;
static int hf_openflow_v4_flow_stats_flags = -1;
static int hf_openflow_v4_flow_stats_flags_send_flow_rem = -1;
static int hf_openflow_v4_flow_stats_flags_check_overlap = -1;
static int hf_openflow_v4_flow_stats_flags_reset_counts = -1;
static int hf_openflow_v4_flow_stats_flags_no_packet_counts = -1;
static int hf_openflow_v4_flow_stats_flags_no_byte_counts = -1;
static int hf_openflow_v4_flow_stats_pad2 = -1;
static int hf_openflow_v4_flow_stats_cookie = -1;
static int hf_openflow_v4_flow_stats_packet_count = -1;
static int hf_openflow_v4_flow_stats_byte_count = -1;
static int hf_openflow_v4_aggregate_stats_packet_count = -1;
static int hf_openflow_v4_aggregate_stats_byte_count = -1;
static int hf_openflow_v4_aggregate_stats_flow_count = -1;
static int hf_openflow_v4_aggregate_stats_pad = -1;
static int hf_openflow_v4_table_stats_table_id = -1;
static int hf_openflow_v4_table_stats_table_id_reserved = -1;
static int hf_openflow_v4_table_stats_pad = -1;
static int hf_openflow_v4_table_stats_active_count = -1;
static int hf_openflow_v4_table_stats_lookup_count = -1;
static int hf_openflow_v4_table_stats_match_count = -1;
static int hf_openflow_v4_port_stats_port_no = -1;
static int hf_openflow_v4_port_stats_port_no_reserved = -1;
static int hf_openflow_v4_port_stats_pad = -1;
static int hf_openflow_v4_port_stats_rx_packets = -1;
static int hf_openflow_v4_port_stats_tx_packets = -1;
static int hf_openflow_v4_port_stats_rx_bytes = -1;
static int hf_openflow_v4_port_stats_tx_bytes = -1;
static int hf_openflow_v4_port_stats_rx_dropped = -1;
static int hf_openflow_v4_port_stats_tx_dropped = -1;
static int hf_openflow_v4_port_stats_rx_errors = -1;
static int hf_openflow_v4_port_stats_tx_errors = -1;
static int hf_openflow_v4_port_stats_rx_frame_error = -1;
static int hf_openflow_v4_port_stats_rx_over_error = -1;
static int hf_openflow_v4_port_stats_rx_crc_error = -1;
static int hf_openflow_v4_port_stats_collisions = -1;
static int hf_openflow_v4_port_stats_duration_sec = -1;
static int hf_openflow_v4_port_stats_duration_nsec = -1;
static int hf_openflow_v4_queue_stats_port_no = -1;
static int hf_openflow_v4_queue_stats_port_no_reserved = -1;
static int hf_openflow_v4_queue_stats_queue_id = -1;
static int hf_openflow_v4_queue_stats_queue_id_reserved = -1;
static int hf_openflow_v4_queue_stats_tx_bytes = -1;
static int hf_openflow_v4_queue_stats_tx_packets = -1;
static int hf_openflow_v4_queue_stats_tx_errors = -1;
static int hf_openflow_v4_queue_stats_duration_sec = -1;
static int hf_openflow_v4_queue_stats_duration_nsec = -1;
static int hf_openflow_v4_bucket_counter_packet_count = -1;
static int hf_openflow_v4_bucket_counter_byte_count = -1;
static int hf_openflow_v4_group_stats_length = -1;
static int hf_openflow_v4_group_stats_pad = -1;
static int hf_openflow_v4_group_stats_group_id = -1;
static int hf_openflow_v4_group_stats_group_id_reserved = -1;
static int hf_openflow_v4_group_stats_ref_count = -1;
static int hf_openflow_v4_group_stats_pad2 = -1;
static int hf_openflow_v4_group_stats_packet_count = -1;
static int hf_openflow_v4_group_stats_byte_count = -1;
static int hf_openflow_v4_group_desc_length = -1;
static int hf_openflow_v4_group_desc_type = -1;
static int hf_openflow_v4_group_desc_pad = -1;
static int hf_openflow_v4_group_desc_group_id = -1;
static int hf_openflow_v4_group_desc_group_id_reserved = -1;
static int hf_openflow_v4_group_features_types = -1;
static int hf_openflow_v4_group_features_types_all = -1;
static int hf_openflow_v4_group_features_types_select = -1;
static int hf_openflow_v4_group_features_types_indirect = -1;
static int hf_openflow_v4_group_features_types_ff = -1;
static int hf_openflow_v4_group_features_capabilities = -1;
static int hf_openflow_v4_group_features_capabilities_select_weight = -1;
static int hf_openflow_v4_group_features_capabilities_select_liveness = -1;
static int hf_openflow_v4_group_features_capabilities_chaining = -1;
static int hf_openflow_v4_group_features_capabilities_chaining_checks = -1;
static int hf_openflow_v4_group_features_max_groups_all = -1;
static int hf_openflow_v4_group_features_max_groups_select = -1;
static int hf_openflow_v4_group_features_max_groups_indirect = -1;
static int hf_openflow_v4_group_features_max_groups_ff = -1;
static int hf_openflow_v4_group_features_actions_all = -1;
static int hf_openflow_v4_group_features_actions_all_output = -1;
static int hf_openflow_v4_group_features_actions_all_copy_ttl_out = -1;
static int hf_openflow_v4_group_features_actions_all_copy_ttl_in = -1;
static int hf_openflow_v4_group_features_actions_all_set_mpls_ttl = -1;
static int hf_openflow_v4_group_features_actions_all_dec_mpls_ttl = -1;
static int hf_openflow_v4_group_features_actions_all_push_vlan = -1;
static int hf_openflow_v4_group_features_actions_all_pop_vlan = -1;
static int hf_openflow_v4_group_features_actions_all_push_mpls = -1;
static int hf_openflow_v4_group_features_actions_all_pop_mpls = -1;
static int hf_openflow_v4_group_features_actions_all_set_queue = -1;
static int hf_openflow_v4_group_features_actions_all_group = -1;
static int hf_openflow_v4_group_features_actions_all_set_nw_ttl = -1;
static int hf_openflow_v4_group_features_actions_all_dec_nw_ttl = -1;
static int hf_openflow_v4_group_features_actions_all_set_field = -1;
static int hf_openflow_v4_group_features_actions_all_push_pbb = -1;
static int hf_openflow_v4_group_features_actions_all_pop_pbb = -1;
static int hf_openflow_v4_group_features_actions_select = -1;
static int hf_openflow_v4_group_features_actions_select_output = -1;
static int hf_openflow_v4_group_features_actions_select_copy_ttl_out = -1;
static int hf_openflow_v4_group_features_actions_select_copy_ttl_in = -1;
static int hf_openflow_v4_group_features_actions_select_set_mpls_ttl = -1;
static int hf_openflow_v4_group_features_actions_select_dec_mpls_ttl = -1;
static int hf_openflow_v4_group_features_actions_select_push_vlan = -1;
static int hf_openflow_v4_group_features_actions_select_pop_vlan = -1;
static int hf_openflow_v4_group_features_actions_select_push_mpls = -1;
static int hf_openflow_v4_group_features_actions_select_pop_mpls = -1;
static int hf_openflow_v4_group_features_actions_select_set_queue = -1;
static int hf_openflow_v4_group_features_actions_select_group = -1;
static int hf_openflow_v4_group_features_actions_select_set_nw_ttl = -1;
static int hf_openflow_v4_group_features_actions_select_dec_nw_ttl = -1;
static int hf_openflow_v4_group_features_actions_select_set_field = -1;
static int hf_openflow_v4_group_features_actions_select_push_pbb = -1;
static int hf_openflow_v4_group_features_actions_select_pop_pbb = -1;
static int hf_openflow_v4_group_features_actions_indirect = -1;
static int hf_openflow_v4_group_features_actions_indirect_output = -1;
static int hf_openflow_v4_group_features_actions_indirect_copy_ttl_out = -1;
static int hf_openflow_v4_group_features_actions_indirect_copy_ttl_in = -1;
static int hf_openflow_v4_group_features_actions_indirect_set_mpls_ttl = -1;
static int hf_openflow_v4_group_features_actions_indirect_dec_mpls_ttl = -1;
static int hf_openflow_v4_group_features_actions_indirect_push_vlan = -1;
static int hf_openflow_v4_group_features_actions_indirect_pop_vlan = -1;
static int hf_openflow_v4_group_features_actions_indirect_push_mpls = -1;
static int hf_openflow_v4_group_features_actions_indirect_pop_mpls = -1;
static int hf_openflow_v4_group_features_actions_indirect_set_queue = -1;
static int hf_openflow_v4_group_features_actions_indirect_group = -1;
static int hf_openflow_v4_group_features_actions_indirect_set_nw_ttl = -1;
static int hf_openflow_v4_group_features_actions_indirect_dec_nw_ttl = -1;
static int hf_openflow_v4_group_features_actions_indirect_set_field = -1;
static int hf_openflow_v4_group_features_actions_indirect_push_pbb = -1;
static int hf_openflow_v4_group_features_actions_indirect_pop_pbb = -1;
static int hf_openflow_v4_group_features_actions_ff = -1;
static int hf_openflow_v4_group_features_actions_ff_output = -1;
static int hf_openflow_v4_group_features_actions_ff_copy_ttl_out = -1;
static int hf_openflow_v4_group_features_actions_ff_copy_ttl_in = -1;
static int hf_openflow_v4_group_features_actions_ff_set_mpls_ttl = -1;
static int hf_openflow_v4_group_features_actions_ff_dec_mpls_ttl = -1;
static int hf_openflow_v4_group_features_actions_ff_push_vlan = -1;
static int hf_openflow_v4_group_features_actions_ff_pop_vlan = -1;
static int hf_openflow_v4_group_features_actions_ff_push_mpls = -1;
static int hf_openflow_v4_group_features_actions_ff_pop_mpls = -1;
static int hf_openflow_v4_group_features_actions_ff_set_queue = -1;
static int hf_openflow_v4_group_features_actions_ff_group = -1;
static int hf_openflow_v4_group_features_actions_ff_set_nw_ttl = -1;
static int hf_openflow_v4_group_features_actions_ff_dec_nw_ttl = -1;
static int hf_openflow_v4_group_features_actions_ff_set_field = -1;
static int hf_openflow_v4_group_features_actions_ff_push_pbb = -1;
static int hf_openflow_v4_group_features_actions_ff_pop_pbb = -1;
static int hf_openflow_v4_meter_band_stats_packet_band_count = -1;
static int hf_openflow_v4_meter_band_stats_byte_band_count = -1;
static int hf_openflow_v4_meter_stats_meter_id = -1;
static int hf_openflow_v4_meter_stats_meter_id_reserved = -1;
static int hf_openflow_v4_meter_stats_len = -1;
static int hf_openflow_v4_meter_stats_pad = -1;
static int hf_openflow_v4_meter_stats_flow_count = -1;
static int hf_openflow_v4_meter_stats_packet_in_count = -1;
static int hf_openflow_v4_meter_stats_byte_in_count = -1;
static int hf_openflow_v4_meter_stats_duration_sec = -1;
static int hf_openflow_v4_meter_stats_duration_nsec = -1;
static int hf_openflow_v4_meter_config_len = -1;
static int hf_openflow_v4_meter_config_flags = -1;
static int hf_openflow_v4_meter_config_flags_kbps = -1;
static int hf_openflow_v4_meter_config_flags_pktps = -1;
static int hf_openflow_v4_meter_config_flags_burst = -1;
static int hf_openflow_v4_meter_config_flags_stats = -1;
static int hf_openflow_v4_meter_config_meter_id = -1;
static int hf_openflow_v4_meter_config_meter_id_reserved = -1;
static int hf_openflow_v4_meter_features_max_meter = -1;
static int hf_openflow_v4_meter_features_band_types = -1;
static int hf_openflow_v4_meter_features_band_types_drop = -1;
static int hf_openflow_v4_meter_features_band_types_dscp_remark = -1;
static int hf_openflow_v4_meter_features_capabilities = -1;
static int hf_openflow_v4_meter_features_capabilities_kbps = -1;
static int hf_openflow_v4_meter_features_capabilities_pktps = -1;
static int hf_openflow_v4_meter_features_capabilities_burst = -1;
static int hf_openflow_v4_meter_features_capabilities_stats = -1;
static int hf_openflow_v4_meter_features_max_bands = -1;
static int hf_openflow_v4_meter_features_max_color = -1;
static int hf_openflow_v4_meter_features_pad = -1;
static int hf_openflow_v4_multipart_reply_type = -1;
static int hf_openflow_v4_multipart_reply_flags = -1;
static int hf_openflow_v4_multipart_reply_flags_more = -1;
static int hf_openflow_v4_multipart_reply_pad = -1;
static int hf_openflow_v4_multipart_reply_experimenter_experimenter = -1;
static int hf_openflow_v4_multipart_reply_experimenter_exp_type = -1;
static int hf_openflow_v4_queue_get_config_request_port = -1;
static int hf_openflow_v4_queue_get_config_request_port_reserved = -1;
static int hf_openflow_v4_queue_get_config_request_pad = -1;
static int hf_openflow_v4_queue_prop_property = -1;
static int hf_openflow_v4_queue_prop_len = -1;
static int hf_openflow_v4_queue_prop_pad = -1;
static int hf_openflow_v4_queue_prop_min_rate_rate = -1;
static int hf_openflow_v4_queue_prop_min_rate_rate_reserved = -1;
static int hf_openflow_v4_queue_prop_min_rate_pad = -1;
static int hf_openflow_v4_queue_prop_max_rate_rate = -1;
static int hf_openflow_v4_queue_prop_max_rate_rate_reserved = -1;
static int hf_openflow_v4_queue_prop_max_rate_pad = -1;
static int hf_openflow_v4_queue_prop_experimenter_experimenter = -1;
static int hf_openflow_v4_queue_prop_experimenter_pad = -1;
static int hf_openflow_v4_packet_queue_queue_id = -1;
static int hf_openflow_v4_packet_queue_queue_id_reserved = -1;
static int hf_openflow_v4_packet_queue_port = -1;
static int hf_openflow_v4_packet_queue_port_reserved = -1;
static int hf_openflow_v4_packet_queue_len = -1;
static int hf_openflow_v4_packet_queue_pad = -1;
static int hf_openflow_v4_queue_get_config_reply_port = -1;
static int hf_openflow_v4_queue_get_config_reply_port_reserved = -1;
static int hf_openflow_v4_queue_get_config_reply_pad = -1;
static int hf_openflow_v4_role_request_role = -1;
static int hf_openflow_v4_role_request_pad = -1;
static int hf_openflow_v4_role_request_generation_id = -1;
static int hf_openflow_v4_role_reply_role = -1;
static int hf_openflow_v4_role_reply_pad = -1;
static int hf_openflow_v4_role_reply_generation_id = -1;
static int hf_openflow_v4_async_config_packet_in_mask_master = -1;
static int hf_openflow_v4_async_config_packet_in_mask_master_no_match = -1;
static int hf_openflow_v4_async_config_packet_in_mask_master_action = -1;
static int hf_openflow_v4_async_config_packet_in_mask_master_invalid_ttl = -1;
static int hf_openflow_v4_async_config_packet_in_mask_slave = -1;
static int hf_openflow_v4_async_config_packet_in_mask_slave_no_match = -1;
static int hf_openflow_v4_async_config_packet_in_mask_slave_action = -1;
static int hf_openflow_v4_async_config_packet_in_mask_slave_invalid_ttl = -1;
static int hf_openflow_v4_async_config_port_status_mask_master = -1;
static int hf_openflow_v4_async_config_port_status_mask_master_add = -1;
static int hf_openflow_v4_async_config_port_status_mask_master_delete = -1;
static int hf_openflow_v4_async_config_port_status_mask_master_modify = -1;
static int hf_openflow_v4_async_config_port_status_mask_slave = -1;
static int hf_openflow_v4_async_config_port_status_mask_slave_add = -1;
static int hf_openflow_v4_async_config_port_status_mask_slave_delete = -1;
static int hf_openflow_v4_async_config_port_status_mask_slave_modify = -1;
static int hf_openflow_v4_async_config_flow_removed_mask_master = -1;
static int hf_openflow_v4_async_config_flow_removed_mask_master_idle_timeout = -1;
static int hf_openflow_v4_async_config_flow_removed_mask_master_hard_timeout = -1;
static int hf_openflow_v4_async_config_flow_removed_mask_master_delete = -1;
static int hf_openflow_v4_async_config_flow_removed_mask_master_group_delete = -1;
static int hf_openflow_v4_async_config_flow_removed_mask_slave = -1;
static int hf_openflow_v4_async_config_flow_removed_mask_slave_idle_timeout = -1;
static int hf_openflow_v4_async_config_flow_removed_mask_slave_hard_timeout = -1;
static int hf_openflow_v4_async_config_flow_removed_mask_slave_delete = -1;
static int hf_openflow_v4_async_config_flow_removed_mask_slave_group_delete = -1;
static int hf_openflow_v4_metermod_command = -1;
static int hf_openflow_v4_metermod_flags = -1;
static int hf_openflow_v4_metermod_flags_kbps = -1;
static int hf_openflow_v4_metermod_flags_pktps = -1;
static int hf_openflow_v4_metermod_flags_burst = -1;
static int hf_openflow_v4_metermod_flags_stats = -1;
static int hf_openflow_v4_metermod_meter_id = -1;
static int hf_openflow_v4_metermod_meter_id_reserved = -1;

static gint ett_openflow_v4 = -1;
static gint ett_openflow_v4_flowmod_flags = -1;
static gint ett_openflow_v4_bucket = -1;
static gint ett_openflow_v4_oxm = -1;
static gint ett_openflow_v4_match = -1;
static gint ett_openflow_v4_action = -1;
static gint ett_openflow_v4_instruction = -1;
static gint ett_openflow_v4_port = -1;
static gint ett_openflow_v4_port_config = -1;
static gint ett_openflow_v4_port_state = -1;
static gint ett_openflow_v4_port_current = -1;
static gint ett_openflow_v4_port_advertised = -1;
static gint ett_openflow_v4_port_supported = -1;
static gint ett_openflow_v4_port_peer = -1;
static gint ett_openflow_v4_meter_band  = -1;
static gint ett_openflow_v4_hello_element = -1;
static gint ett_openflow_v4_error_data = -1;
static gint ett_openflow_v4_switch_features_capabilities = -1;
static gint ett_openflow_v4_switch_config_flags = -1;
static gint ett_openflow_v4_packet_in_data = -1;
static gint ett_openflow_v4_packet_out_data = -1;
static gint ett_openflow_v4_portmod_config = -1;
static gint ett_openflow_v4_portmod_mask = -1;
static gint ett_openflow_v4_portmod_advertise = -1;
static gint ett_openflow_v4_table_features = -1;
static gint ett_openflow_v4_table_feature_prop = -1;
static gint ett_openflow_v4_table_feature_prop_instruction_id = -1;
static gint ett_openflow_v4_table_feature_prop_action_id = -1;
static gint ett_openflow_v4_table_feature_prop_oxm_id = -1;
static gint ett_openflow_v4_multipart_request_flags = -1;
static gint ett_openflow_v4_flow_stats = -1;
static gint ett_openflow_v4_flow_stats_flags = -1;
static gint ett_openflow_v4_table_stats = -1;
static gint ett_openflow_v4_port_stats = -1;
static gint ett_openflow_v4_queue_stats = -1;
static gint ett_openflow_v4_bucket_counter = -1;
static gint ett_openflow_v4_group_stats = -1;
static gint ett_openflow_v4_group_desc = -1;
static gint ett_openflow_v4_group_features_types = -1;
static gint ett_openflow_v4_group_features_capabilities = -1;
static gint ett_openflow_v4_group_features_actions_all = -1;
static gint ett_openflow_v4_group_features_actions_select = -1;
static gint ett_openflow_v4_group_features_actions_indirect = -1;
static gint ett_openflow_v4_group_features_actions_ff = -1;
static gint ett_openflow_v4_meter_band_stats = -1;
static gint ett_openflow_v4_meter_stats = -1;
static gint ett_openflow_v4_meter_config = -1;
static gint ett_openflow_v4_meter_config_flags = -1;
static gint ett_openflow_v4_meter_features_band_types = -1;
static gint ett_openflow_v4_meter_features_capabilities = -1;
static gint ett_openflow_v4_multipart_reply_flags = -1;
static gint ett_openflow_v4_queue_prop = -1;
static gint ett_openflow_v4_packet_queue = -1;
static gint ett_openflow_v4_async_config_packet_in_mask_master = -1;
static gint ett_openflow_v4_async_config_packet_in_mask_slave = -1;
static gint ett_openflow_v4_async_config_port_status_mask_master = -1;
static gint ett_openflow_v4_async_config_port_status_mask_slave = -1;
static gint ett_openflow_v4_async_config_flow_removed_mask_master = -1;
static gint ett_openflow_v4_async_config_flow_removed_mask_slave = -1;
static gint ett_openflow_v4_metermod_flags = -1;

static expert_field ei_openflow_v4_match_undecoded = EI_INIT;
static expert_field ei_openflow_v4_oxm_undecoded = EI_INIT;
static expert_field ei_openflow_v4_action_undecoded = EI_INIT;
static expert_field ei_openflow_v4_instruction_undecoded = EI_INIT;
static expert_field ei_openflow_v4_meter_band_undecoded = EI_INIT;
static expert_field ei_openflow_v4_hello_element_undecoded = EI_INIT;
static expert_field ei_openflow_v4_error_undecoded = EI_INIT;
static expert_field ei_openflow_v4_experimenter_undecoded = EI_INIT;
static expert_field ei_openflow_v4_table_feature_prop_undecoded = EI_INIT;
static expert_field ei_openflow_v4_multipart_request_undecoded = EI_INIT;
static expert_field ei_openflow_v4_multipart_reply_undecoded = EI_INIT;
static expert_field ei_openflow_v4_queue_prop_undecoded = EI_INIT;
static expert_field ei_openflow_v4_message_undecoded = EI_INIT;

static const value_string openflow_v4_version_values[] = {
    { 0x04, "1.3" },
    { 0, NULL }
};

#define OFPT_HELLO                      0
#define OFPT_ERROR                      1
#define OFPT_ECHO_REQUEST               2
#define OFPT_ECHO_REPLY                 3
#define OFPT_EXPERIMENTER               4
#define OFPT_FEATURES_REQUEST           5
#define OFPT_FEATURES_REPLY             6
#define OFPT_GET_CONFIG_REQUEST         7
#define OFPT_GET_CONFIG_REPLY           8
#define OFPT_SET_CONFIG                 9
#define OFPT_PACKET_IN                 10
#define OFPT_FLOW_REMOVED              11
#define OFPT_PORT_STATUS               12
#define OFPT_PACKET_OUT                13
#define OFPT_FLOW_MOD                  14
#define OFPT_GROUP_MOD                 15
#define OFPT_PORT_MOD                  16
#define OFPT_TABLE_MOD                 17
#define OFPT_MULTIPART_REQUEST         18
#define OFPT_MULTIPART_REPLY           19
#define OFPT_BARRIER_REQUEST           20
#define OFPT_BARRIER_REPLY             21
#define OFPT_QUEUE_GET_CONFIG_REQUEST  22
#define OFPT_QUEUE_GET_CONFIG_REPLY    23
#define OFPT_ROLE_REQUEST              24
#define OFPT_ROLE_REPLY                25
#define OFPT_GET_ASYNC_REQUEST         26
#define OFPT_GET_ASYNC_REPLY           27
#define OFPT_SET_ASYNC                 28
#define OFPT_METER_MOD                 29
static const value_string openflow_v4_type_values[] = {
    { OFPT_HELLO,                    "OFPT_HELLO" },
    { OFPT_ERROR,                    "OFPT_ERROR" },
    { OFPT_ECHO_REQUEST,             "OFPT_ECHO_REQUEST" },
    { OFPT_ECHO_REPLY,               "OFPT_ECHO_REPLY" },
    { OFPT_EXPERIMENTER,             "OFPT_EXPERIMENTER" },
    { OFPT_FEATURES_REQUEST,         "OFPT_FEATURES_REQUEST" },
    { OFPT_FEATURES_REPLY,           "OFPT_FEATURES_REPLY" },
    { OFPT_GET_CONFIG_REQUEST,       "OFPT_GET_CONFIG_REQUEST" },
    { OFPT_GET_CONFIG_REPLY,         "OFPT_GET_CONFIG_REPLY" },
    { OFPT_SET_CONFIG,               "OFPT_SET_CONFIG" },
    { OFPT_PACKET_IN,                "OFPT_PACKET_IN" },
    { OFPT_FLOW_REMOVED,             "OFPT_FLOW_REMOVED" },
    { OFPT_PORT_STATUS,              "OFPT_PORT_STATUS" },
    { OFPT_PACKET_OUT,               "OFPT_PACKET_OUT" },
    { OFPT_FLOW_MOD,                 "OFPT_FLOW_MOD" },
    { OFPT_GROUP_MOD,                "OFPT_GROUP_MOD" },
    { OFPT_PORT_MOD,                 "OFPT_PORT_MOD" },
    { OFPT_TABLE_MOD,                "OFPT_TABLE_MOD" },
    { OFPT_MULTIPART_REQUEST,        "OFPT_MULTIPART_REQUEST" },
    { OFPT_MULTIPART_REPLY,          "OFPT_MULTIPART_REPLY" },
    { OFPT_BARRIER_REQUEST,          "OFPT_BARRIER_REQUEST" },
    { OFPT_BARRIER_REPLY,            "OFPT_BARRIER_REPLY" },
    { OFPT_QUEUE_GET_CONFIG_REQUEST, "OFPT_QUEUE_GET_CONFIG_REQUEST" },
    { OFPT_QUEUE_GET_CONFIG_REPLY,   "OFPT_QUEUE_GET_CONFIG_REPLY" },
    { OFPT_ROLE_REQUEST,             "OFPT_ROLE_REQUEST" },
    { OFPT_ROLE_REPLY,               "OFPT_ROLE_REPLY" },
    { OFPT_GET_ASYNC_REQUEST,        "OFPT_GET_ASYNC_REQUEST" },
    { OFPT_GET_ASYNC_REPLY,          "OFPT_GET_ASYNC_REPLY" },
    { OFPT_SET_ASYNC,                "OFPT_SET_ASYNC" },
    { OFPT_METER_MOD,                "OFPT_METER_MOD" },
    { 0,                             NULL }
};
static value_string_ext openflow_v4_type_values_ext = VALUE_STRING_EXT_INIT(openflow_v4_type_values);

static int
dissect_openflow_header_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    /* uint8_t version; */
    proto_tree_add_item(tree, hf_openflow_v4_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* uint8_t type; */
    proto_tree_add_item(tree, hf_openflow_v4_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* uint16_t length; */
    proto_tree_add_item(tree, hf_openflow_v4_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint32_t xid; */
    proto_tree_add_item(tree, hf_openflow_v4_xid, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    return offset;
}

#define OFPP_MAX   0xffffff00  /* Last usable port number. */
static const value_string openflow_v4_port_reserved_values[] = {
    { 0xfffffff8, "OFPP_IN_PORT" },
    { 0xfffffff9, "OFPP_TABLE" },
    { 0xfffffffa, "OFPP_NORMAL" },
    { 0xfffffffb, "OFPP_FLOOD" },
    { 0xfffffffc, "OFPP_ALL" },
    { 0xfffffffd, "OFPP_CONTROLLER" },
    { 0xfffffffe, "OFPP_LOCAL" },
    { 0xffffffff, "OFPP_ANY" },
    { 0,          NULL }
};

#define OFPG_MAX   0xffffff00  /* Last usable group number. */
static const value_string openflow_v4_group_reserved_values[] = {
    { 0xfffffffc, "OFPG_ALL" },
    { 0xffffffff, "OFPG_ANY" },
    { 0,          NULL }
};

#define OFPTT_MAX  254    /* Last usable table number. */
static const value_string openflow_v4_table_reserved_values[] = {
    { 255, "OFPTT_ALL"},
    { 0,   NULL}
};


#define OFP_NO_BUFFER  0xffffffff    /* No buffering. */
static const value_string openflow_v4_buffer_reserved_values[] = {
    { 0xffffffff, "OFP_NO_BUFFER" },
    { 0,          NULL}
};

#define OFPXMC_NXM_0           0x0000  /* Backward compatibility with NXM */
#define OFPXMC_NXM_1           0x0001  /* Backward compatibility with NXM */
#define OFPXMC_OPENFLOW_BASIC  0x8000  /* Basic class for OpenFlow */
#define OFPXMC_EXPERIMENTER    0xFFFF  /* Experimenter class */
static const value_string openflow_v4_oxm_class_values[] = {
    { 0x0000, "OFPXMC_NMX_0" },
    { 0x0001, "OFPXMC_NXM_1" },
    { 0x8000, "OFPXMC_OPENFLOW_BASIC" },
    { 0xFFFF, "OFPXMC_EXPERIMENTER" },
    { 0,      NULL}
};

#define OFPXMT_OFB_IN_PORT          0
#define OFPXMT_OFB_IN_PHY_PORT      1
#define OFPXMT_OFB_METADATA         2
#define OFPXMT_OFB_ETH_DST          3
#define OFPXMT_OFB_ETH_SRC          4
#define OFPXMT_OFB_ETH_TYPE         5
#define OFPXMT_OFB_VLAN_VID         6
#define OFPXMT_OFB_VLAN_PCP         7
#define OFPXMT_OFB_IP_DSCP          8
#define OFPXMT_OFB_IP_ECN           9
#define OFPXMT_OFB_IP_PROTO        10
#define OFPXMT_OFB_IPV4_SRC        11
#define OFPXMT_OFB_IPV4_DST        12
#define OFPXMT_OFB_TCP_SRC         13
#define OFPXMT_OFB_TCP_DST         14
#define OFPXMT_OFB_UDP_SRC         15
#define OFPXMT_OFB_UDP_DST         16
#define OFPXMT_OFB_SCTP_SRC        17
#define OFPXMT_OFB_SCTP_DST        18
#define OFPXMT_OFB_ICMPV4_TYPE     19
#define OFPXMT_OFB_ICMPV4_CODE     20
#define OFPXMT_OFB_ARP_OP          21
#define OFPXMT_OFB_ARP_SPA         22
#define OFPXMT_OFB_ARP_TPA         23
#define OFPXMT_OFB_ARP_SHA         24
#define OFPXMT_OFB_ARP_THA         25
#define OFPXMT_OFB_IPV6_SRC        26
#define OFPXMT_OFB_IPV6_DST        27
#define OFPXMT_OFB_IPV6_FLABEL     28
#define OFPXMT_OFB_ICMPV6_TYPE     29
#define OFPXMT_OFB_ICMPV6_CODE     30
#define OFPXMT_OFB_IPV6_ND_TARGET  31
#define OFPXMT_OFB_IPV6_ND_SLL     32
#define OFPXMT_OFB_IPV6_ND_TLL     33
#define OFPXMT_OFB_MPLS_LABEL      34
#define OFPXMT_OFB_MPLS_TC         35
#define OFPXMT_OFP_MPLS_BOS        36
#define OFPXMT_OFB_PBB_ISID        37
#define OFPXMT_OFB_TUNNEL_ID       38
#define OFPXMT_OFB_IPV6_EXTHDR     39
static const value_string openflow_v4_oxm_basic_field_values[] = {
    {  0, "OFPXMT_OFB_IN_PORT" },
    {  1, "OFPXMT_OFB_IN_PHY_PORT" },
    {  2, "OFPXMT_OFB_METADATA" },
    {  3, "OFPXMT_OFB_ETH_DST" },
    {  4, "OFPXMT_OFB_ETH_SRC" },
    {  5, "OFPXMT_OFB_ETH_TYPE" },
    {  6, "OFPXMT_OFB_VLAN_VID" },
    {  7, "OFPXMT_OFB_VLAN_PCP" },
    {  8, "OFPXMT_OFB_IP_DSCP" },
    {  9, "OFPXMT_OFB_IP_ECN" },
    { 10, "OFPXMT_OFB_IP_PROTO" },
    { 11, "OFPXMT_OFB_IPV4_SRC" },
    { 12, "OFPXMT_OFB_IPV4_DST" },
    { 13, "OFPXMT_OFB_TCP_SRC" },
    { 14, "OFPXMT_OFB_TCP_DST" },
    { 15, "OFPXMT_OFB_UDP_SRC" },
    { 16, "OFPXMT_OFB_UDP_DST" },
    { 17, "OFPXMT_OFB_SCTP_SRC" },
    { 18, "OFPXMT_OFB_SCTP_DST" },
    { 19, "OFPXMT_OFB_ICMPV4_TYPE" },
    { 20, "OFPXMT_OFB_ICMPV4_CODE" },
    { 21, "OFPXMT_OFB_ARP_OP" },
    { 22, "OFPXMT_OFB_ARP_SPA" },
    { 23, "OFPXMT_OFB_ARP_TPA" },
    { 24, "OFPXMT_OFB_ARP_SHA" },
    { 25, "OFPXMT_OFB_ARP_THA" },
    { 26, "OFPXMT_OFB_IPV6_SRC" },
    { 27, "OFPXMT_OFB_IPV6_DST" },
    { 28, "OFPXMT_OFB_IPV6_FLABEL" },
    { 29, "OFPXMT_OFB_ICMPV6_TYPE" },
    { 30, "OFPXMT_OFB_ICMPV6_CODE" },
    { 31, "OFPXMT_OFB_IPV6_ND_TARGET" },
    { 32, "OFPXMT_OFB_IPV6_ND_SLL" },
    { 33, "OFPXMT_OFB_IPV6_ND_TLL" },
    { 34, "OFPXMT_OFB_MPLS_LABEL" },
    { 35, "OFPXMT_OFB_MPLS_TC" },
    { 36, "OFPXMT_OFP_MPLS_BOS" },
    { 37, "OFPXMT_OFB_PBB_ISID" },
    { 38, "OFPXMT_OFB_TUNNEL_ID" },
    { 39, "OFPXMT_OFB_IPV6_EXTHDR" },
    {  0, NULL }
};
static value_string_ext openflow_v4_oxm_basic_field_values_ext = VALUE_STRING_EXT_INIT(openflow_v4_oxm_basic_field_values);

#define OXM_FIELD_MASK   0xfe
#define OXM_FIELD_OFFSET 1
#define OXM_HM_MASK      0x01
static int
dissect_openflow_oxm_header_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    guint16 oxm_class;
    guint8  oxm_length;

    /* oxm_class */
    oxm_class = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_openflow_v4_oxm_class, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* oxm_field */
    if (oxm_class == OFPXMC_OPENFLOW_BASIC) {
        proto_tree_add_bits_item(tree, hf_openflow_v4_oxm_field_basic, tvb, (offset * 8), 7, ENC_NA);
    } else {
        proto_tree_add_bits_item(tree, hf_openflow_v4_oxm_field, tvb, (offset * 8), 7, ENC_NA);
    }

    /* oxm_hm */
    proto_tree_add_bits_item(tree, hf_openflow_v4_oxm_hm, tvb, (offset * 8) + 7, 1, ENC_NA);
    offset+=1;

    /* oxm_length */
    oxm_length = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_openflow_v4_oxm_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset+=1;

    if (oxm_class == OFPXMC_EXPERIMENTER) {
        /* uint32_t experimenter; */
        proto_tree_add_item(tree, hf_openflow_v4_oxm_experimenter_experimenter, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;
        proto_tree_add_item(tree, hf_openflow_v4_oxm_experimenter_value, tvb, offset, oxm_length - 4, ENC_NA);
        offset+=(oxm_length - 4);
    }

    return offset;
}


#define OFPVID_PRESENT  0x1000
static int
dissect_openflow_oxm_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    proto_tree *oxm_tree;
    guint16 oxm_class;
    guint16 oxm_end;
    guint8  oxm_field_hm;
    guint8  oxm_hm;
    guint8  oxm_field;
    guint8  oxm_length;
    guint8  field_length;

    oxm_class = tvb_get_ntohs(tvb, offset);
    oxm_field_hm = tvb_get_guint8(tvb, offset + 2);
    oxm_length = tvb_get_guint8(tvb, offset + 3);
    oxm_end = offset + 4 + oxm_length;

    oxm_field = (oxm_field_hm & OXM_FIELD_MASK) >> OXM_FIELD_OFFSET;
    oxm_hm = oxm_field_hm & OXM_HM_MASK;
    field_length = (oxm_hm == 0) ? oxm_length : (oxm_length / 2);

    oxm_tree = proto_tree_add_subtree(tree, tvb, offset, oxm_length + 4, ett_openflow_v4_oxm, NULL, "OXM field");

    offset = dissect_openflow_oxm_header_v4(tvb, pinfo, oxm_tree, offset, length);

    if (oxm_class == OFPXMC_OPENFLOW_BASIC) {
        switch(oxm_field) {
        case OFPXMT_OFB_IN_PORT:
        case OFPXMT_OFB_IN_PHY_PORT:
            proto_tree_add_item(oxm_tree, hf_openflow_v4_oxm_value_uint32, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;
            break;

        case OFPXMT_OFB_ETH_DST:
        case OFPXMT_OFB_ETH_SRC:
        case OFPXMT_OFB_ARP_SHA:
        case OFPXMT_OFB_ARP_THA:
        case OFPXMT_OFB_IPV6_ND_SLL: /*The source link-layer address option in an IPv6 Neighbor Discovery message */
        case OFPXMT_OFB_IPV6_ND_TLL: /*The target link-layer address option in an IPv6 Neighbor Discovery message */
            proto_tree_add_item(oxm_tree, hf_openflow_v4_oxm_value_etheraddr, tvb, offset, 6, ENC_NA);
            offset+=6;
            if (oxm_hm) {
                proto_tree_add_item(oxm_tree, hf_openflow_v4_oxm_mask_etheraddr, tvb, offset, 6, ENC_NA);
                offset+=6;
            }
            break;

        case OFPXMT_OFB_ETH_TYPE:
            proto_tree_add_item(oxm_tree, hf_openflow_v4_oxm_value_ethertype, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset+=2;
            break;

        case OFPXMT_OFB_VLAN_VID:
            proto_tree_add_item(oxm_tree, hf_openflow_v4_oxm_value_vlan_present, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(oxm_tree, hf_openflow_v4_oxm_value_vlan_vid, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset+=2;
            break;

        case OFPXMT_OFB_IP_PROTO:
            proto_tree_add_item(oxm_tree, hf_openflow_v4_oxm_value_ipproto, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset+=1;
            break;

        case OFPXMT_OFB_IPV4_SRC:
        case OFPXMT_OFB_IPV4_DST:
        case OFPXMT_OFB_ARP_SPA:
        case OFPXMT_OFB_ARP_TPA:
            proto_tree_add_item(oxm_tree, hf_openflow_v4_oxm_value_ipv4addr, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;
            if (oxm_hm) {
                proto_tree_add_item(oxm_tree, hf_openflow_v4_oxm_mask_ipv4addr, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset+=4;
            }
            break;

        case OFPXMT_OFB_TCP_SRC:
        case OFPXMT_OFB_TCP_DST:
        case OFPXMT_OFB_UDP_SRC:
        case OFPXMT_OFB_UDP_DST:
        case OFPXMT_OFB_SCTP_SRC:
        case OFPXMT_OFB_SCTP_DST:
            proto_tree_add_item(oxm_tree, hf_openflow_v4_oxm_value_uint16, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset+=2;
            break;

        case OFPXMT_OFB_IPV6_SRC:
        case OFPXMT_OFB_IPV6_DST:
            proto_tree_add_item(oxm_tree, hf_openflow_v4_oxm_value_ipv6addr, tvb, offset, 16, ENC_NA);
            offset+=16;
            if (oxm_hm) {
                proto_tree_add_item(oxm_tree, hf_openflow_v4_oxm_mask_ipv6addr, tvb, offset, 16, ENC_NA);
                offset+=16;
            }
            break;

        case OFPXMT_OFB_MPLS_LABEL:
            /* size differs in specification and header file */
            if (field_length == 3) {
                proto_tree_add_item(oxm_tree, hf_openflow_v4_oxm_value_uint24, tvb, offset, 3, ENC_BIG_ENDIAN);
                offset+=3;
            } else if (field_length == 4) {
                proto_tree_add_item(oxm_tree, hf_openflow_v4_oxm_value_uint32, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset+=4;
            }
            break;

        default:
            /* value */
            if (field_length > 0) {
                proto_tree_add_item(oxm_tree, hf_openflow_v4_oxm_value, tvb, offset, field_length, ENC_NA);
                offset += field_length;
            }

            /* mask */
            if (field_length > 0 && oxm_hm != 0) {
                proto_tree_add_item(oxm_tree, hf_openflow_v4_oxm_mask, tvb, offset, field_length, ENC_NA);
                offset += field_length;
            }
            break;
        }

        if(oxm_end > offset){
            proto_tree_add_expert_format(oxm_tree, pinfo, &ei_openflow_v4_oxm_undecoded,
                                         tvb, offset, oxm_end-offset, "Undecoded Data");
            offset = oxm_end;
        }

    } else {
        if (oxm_class == OFPXMC_EXPERIMENTER) {
            oxm_length -= 4; /* oxm_length includes experimenter field */
        }
        proto_tree_add_expert_format(oxm_tree, pinfo, &ei_openflow_v4_oxm_undecoded,
                                     tvb, offset, oxm_length, "Unknown OXM body.");
        offset+=oxm_length;
    }

    return offset;
}

#define OFPMT_STANDARD  0  /* Standard Match. Deprecated. */
#define OFPMT_OXM       1  /* OpenFlow Extensible Match */
static const value_string openflow_v4_match_type_values[] = {
    { 0, "OFPMT_STANDARD" },
    { 1, "OFPMT_OXM" },
    { 0, NULL }
};

static int
dissect_openflow_match_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    proto_item *ti;
    proto_tree *match_tree;
    guint16 match_type;
    guint16 match_length;
    gint32 fields_end;
    guint16 pad_length;

    match_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_openflow_v4_match, &ti, "Match");

    /* uint16_t type; */
    match_type = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(match_tree, hf_openflow_v4_match_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint16_t length; (excluding padding) */
    match_length = tvb_get_ntohs(tvb, offset);
    pad_length = (match_length + 7)/8*8 - match_length;
    proto_item_set_len(ti, match_length + pad_length);
    proto_tree_add_item(match_tree, hf_openflow_v4_match_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* body */
    switch (match_type) {
    case OFPMT_STANDARD:
        proto_tree_add_expert_format(match_tree, pinfo, &ei_openflow_v4_match_undecoded,
                                     tvb, offset, match_length - 4, "Standard match body (deprecated).");
        if (match_length > 4)
            offset+=match_length-4;
        break;

    case OFPMT_OXM:
        fields_end = offset + match_length - 4;
        while(offset < fields_end) {
            offset = dissect_openflow_oxm_v4(tvb, pinfo, match_tree, offset, length);
        }
        break;

    default:
        proto_tree_add_expert_format(match_tree, pinfo, &ei_openflow_v4_match_undecoded,
                                     tvb, offset, match_length - 4, "Unknown match body.");
        if (match_length > 4)
            offset+=match_length-4;
        break;
    }

    /* pad; Exactly ((length + 7)/8*8 - length) (between 0 and 7) bytes of all-zero bytes. */
    if (pad_length > 0) {
        proto_tree_add_item(match_tree, hf_openflow_v4_match_pad, tvb, offset, pad_length, ENC_NA);
        offset+=pad_length;
    }

    return offset;
}

#define OFPM_MAX   0xffffff00  /* Last usable meter number. */
static const value_string openflow_v4_meter_id_reserved_values[] = {
    { 0xfffffffd, "OFPM_SLOWPATH" },
    { 0xfffffffe, "OFPM_CONTROLLER" },
    { 0xffffffff, "OFPM_ALL" },
    { 0,          NULL }
};

#define OFPMBT_DROP          1
#define OFPMBT_DSCP_REMARK   2
#define OFPMBT_EXPERIMENTER  0xFFFF
static const value_string openflow_v4_meter_band_type_values[] = {
    { OFPMBT_DROP,         "OFPMBT_DROP" },
    { OFPMBT_DSCP_REMARK,  "OFPMBT_DSCP_REMARK" },
    { OFPMBT_EXPERIMENTER, "OFPMBT_EXPERIMENTER" },
    { 0,                   NULL }
};

#define OFPMF_KBPS   1 << 0
#define OFPMF_PKTPS  1 << 1
#define OFPMF_BURST  1 << 2
#define OFPMF_STATS  1 << 3

static int
dissect_openflow_meter_band_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    proto_item *ti;
    proto_tree *band_tree;
    guint16 band_type;
    guint16 band_len;

    band_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_openflow_v4_meter_band, &ti, "Meter band");

    /* uint16_t type; */
    band_type = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(band_tree, hf_openflow_v4_meter_band_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint16_t len; */
    band_len = tvb_get_ntohs(tvb, offset);
    proto_item_set_len(ti, band_len);
    proto_tree_add_item(band_tree, hf_openflow_v4_meter_band_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint32_t rate; */
    proto_tree_add_item(band_tree, hf_openflow_v4_meter_band_rate, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* uint32_t burst_size; */
    proto_tree_add_item(band_tree, hf_openflow_v4_meter_band_burst_size, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    switch (band_type) {
    case OFPMBT_DROP:
        /* uint8_t pad[4]; */
        proto_tree_add_item(band_tree, hf_openflow_v4_meter_band_drop_pad, tvb, offset, 4, ENC_NA);
        offset+=4;
        break;

    case OFPMBT_DSCP_REMARK:
        /* uint8_t prec_level; */
        proto_tree_add_item(band_tree, hf_openflow_v4_meter_band_dscp_remark_prec_level, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset+=1;

        /* uint8_t pad[3]; */
        proto_tree_add_item(band_tree, hf_openflow_v4_meter_band_dscp_remark_pad, tvb, offset, 3, ENC_NA);
        offset+=3;
        break;

    case OFPMBT_EXPERIMENTER:
        /* uint32_t experimenter; */
        proto_tree_add_item(band_tree, hf_openflow_v4_meter_band_experimenter_experimenter, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;

        /* uint32_t experimenter_data[0]; */
        proto_tree_add_expert_format(band_tree, pinfo, &ei_openflow_v4_meter_band_undecoded,
                                     tvb, offset, offset - 16 + band_len, "Experimenter meter band body.");
        if (band_len > 16)
            offset+=band_len-16;
        break;

    default:
        proto_tree_add_expert_format(band_tree, pinfo, &ei_openflow_v4_meter_band_undecoded,
                                     tvb, offset, offset - 12 + band_len, "Unknown meter band body.");
        if (band_len > 12)
            offset+=band_len-12;
        break;
    }

    return offset;
}


#define OFPHET_VERSIONBITMAP  1
static const value_string openflow_v4_hello_element_type_values[] = {
    { 1, "OFPHET_VERSIONBITMAP" },
    { 0, NULL }
};

static int
dissect_openflow_hello_element_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length)
{
    proto_tree *elem_tree;
    guint16 elem_type;
    guint16 elem_length;
    guint16 pad_length;

    elem_tree = proto_tree_add_subtree(tree, tvb, offset, length - offset, ett_openflow_v4_hello_element, NULL, "Element");

    /* uint16_t type; */
    elem_type = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(elem_tree, hf_openflow_v4_hello_element_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint16_t length; */
    elem_length = tvb_get_ntohs(tvb, offset);
    pad_length = (elem_length + 7)/8*8 - elem_length;
    proto_tree_add_item(elem_tree, hf_openflow_v4_hello_element_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    switch (elem_type) {
    case OFPHET_VERSIONBITMAP:
        /* bitmap */
        proto_tree_add_item(elem_tree, hf_openflow_v4_hello_element_version_bitmap, tvb, offset, elem_length - 4, ENC_NA);
        if (elem_length > 4)
            offset += elem_length - 4;
        break;

    default:
        proto_tree_add_expert_format(tree, pinfo, &ei_openflow_v4_hello_element_undecoded,
                                     tvb, offset, elem_length - 4, "Unknown hello element body.");
        if (elem_length > 4)
            offset += elem_length - 4;
        break;
    }

    if (pad_length > 0) {
        proto_tree_add_item(tree, hf_openflow_v4_hello_element_pad, tvb, offset, pad_length, ENC_NA);
        offset+=pad_length;
    }

    return offset;
}

static void
dissect_openflow_hello_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length)
{

    while (offset < length) {
        offset = dissect_openflow_hello_element_v4(tvb, pinfo, tree, offset, length);
    }
}


#define OFPET_HELLO_FAILED            0
#define OFPET_BAD_REQUEST             1
#define OFPET_BAD_ACTION              2
#define OFPET_BAD_INSTRUCTION         3
#define OFPET_BAD_MATCH               4
#define OFPET_FLOW_MOD_FAILED         5
#define OFPET_GROUP_MOD_FAILED        6
#define OFPET_PORT_MOD_FAILED         7
#define OFPET_TABLE_MOD_FAILED        8
#define OFPET_QUEUE_OP_FAILED         9
#define OFPET_SWITCH_CONFIG_FAILED   10
#define OFPET_ROLE_REQUEST_FAILED    11
#define OFPET_METER_MOD_FAILED       12
#define OFPET_TABLE_FEATURES_FAILED  13
#define OFPET_EXPERIMENTER           0xffff
static const value_string openflow_v4_error_type_values[] = {
    {      0, "OFPET_HELLO_FAILED" },
    {      1, "OFPET_BAD_REQUEST" },
    {      2, "OFPET_BAD_ACTION" },
    {      3, "OFPET_BAD_INSTRUCTION" },
    {      4, "OFPET_BAD_MATCH" },
    {      5, "OFPET_FLOW_MOD_FAILED" },
    {      6, "OFPET_GROUP_MOD_FAILED" },
    {      7, "OFPET_PORT_MOD_FAILED" },
    {      8, "OFPET_TABLE_MOD_FAILED" },
    {      9, "OFPET_QUEUE_OP_FAILED" },
    {     10, "OFPET_SWITCH_CONFIG_FAILED" },
    {     11, "OFPET_ROLE_REQUEST_FAILED" },
    {     12, "OFPET_METER_MOD_FAILED" },
    {     13, "OFPET_TABLE_FEATURES_FAILED" },
    { 0xffff, "OFPET_EXPERIMENTER" },
    {      0, NULL}
};

static const value_string openflow_v4_error_hello_failed_code_values[] = {
    { 0, "OFPHFC_INCOMPATIBLE" },
    { 1, "OFPHFC_EPERM" },
    { 0, NULL }
};

static const value_string openflow_v4_error_bad_request_code_values[] =  {
    {  0, "OFPBRC_BAD_VERSION" },
    {  1, "OFPBRC_BAD_TYPE" },
    {  2, "OFPBRC_BAD_MULTIPART" },
    {  3, "OFPBRC_BAD_EXPERIMENTER" },
    {  4, "OFPBRC_BAD_EXP_TYPE" },
    {  5, "OFPBRC_EPERM" },
    {  6, "OFPBRC_BAD_LEN" },
    {  7, "OFPBRC_BUFFER_EMPTY" },
    {  8, "OFPBRC_BUFFER_UNKNOWN" },
    {  9, "OFPBRC_BAD_TABLE_ID" },
    { 10, "OFPBRC_IS_SLAVE" },
    { 11, "OFPBRC_BAD_PORT" },
    { 12, "OFPBRC_BAD_PACKET" },
    { 13, "OFPBRC_MULTIPART_BUFFER_OVERFLOW" },
    {  0, NULL }
};

static const value_string openflow_v4_error_bad_action_code_values[] =  {
    {  0, "OFPBAC_BAD_TYPE" },
    {  1, "OFPBAC_BAD_LEN" },
    {  2, "OFPBAC_BAD_EXPERIMENTER" },
    {  3, "OFPBAC_BAD_EXP_TYPE" },
    {  4, "OFPBAC_BAD_OUT_PORT" },
    {  5, "OFPBAC_BAD_ARGUMENT" },
    {  6, "OFPBAC_EPERM" },
    {  7, "OFPBAC_TOO_MANY" },
    {  8, "OFPBAC_BAD_QUEUE" },
    {  9, "OFPBAC_BAD_OUT_GROUP" },
    { 10, "OFPBAC_MATCH_INCONSISTENT" },
    { 11, "OFPBAC_UNSUPPORTED_ORDER" },
    { 12, "OFPBAC_BAD_TAG" },
    { 13, "OFPBAC_BAD_SET_TYPE" },
    { 14, "OFPBAC_BAD_SET_LEN" },
    { 15, "OFPBAC_BAD_SET_ARGUMENT" },
    {  0, NULL }
};

static const value_string openflow_v4_error_bad_instruction_code_values[] =  {
    { 0, "OFPBIC_UNKNOWN_INST" },
    { 1, "OFPBIC_UNSUP_INST" },
    { 2, "OFPBIC_BAD_TABLE_ID" },
    { 3, "OFPBIC_UNSUP_METADATA" },
    { 4, "OFPBIC_UNSUP_METADATA_MASK" },
    { 5, "OFPBIC_BAD_EXPERIMENTER" },
    { 6, "OFPBIC_BAD_EXP_TYPE" },
    { 7, "OFPBIC_BAD_LEN" },
    { 8, "OFPBIC_EPERM" },
    { 0, NULL }
};

static const value_string openflow_v4_error_bad_match_code_values[] =  {
    {  0, "OFPBMC_BAD_TYPE" },
    {  1, "OFPBMC_BAD_LEN" },
    {  2, "OFPBMC_BAD_TAG" },
    {  3, "OFPBMC_BAD_DL_ADDR_MASK" },
    {  4, "OFPBMC_BAD_NW_ADDR_MASK" },
    {  5, "OFPBMC_BAD_WILDCARDS" },
    {  6, "OFPBMC_BAD_FIELD" },
    {  7, "OFPBMC_BAD_VALUE" },
    {  8, "OFPBMC_BAD_MASK" },
    {  9, "OFPBMC_BAD_PREREQ" },
    { 10, "OFPBMC_DUP_FIELD" },
    { 11, "OFPBMC_EPERM" },
    {  0, NULL }
};

static const value_string openflow_v4_error_flow_mod_failed_code_values[] =  {
    { 0, "OFPFMFC_UNKNOWN" },
    { 1, "OFPFMFC_TABLE_FULL" },
    { 2, "OFPFMFC_BAD_TABLE_ID" },
    { 3, "OFPFMFC_OVERLAP" },
    { 4, "OFPFMFC_EPERM" },
    { 5, "OFPFMFC_BAD_TIMEOUT" },
    { 6, "OFPFMFC_BAD_COMMAND" },
    { 7, "OFPFMFC_BAD_FLAGS" },
    { 0, NULL }
};

static const value_string openflow_v4_error_group_mod_failed_code_values[] =  {
    {  0, "OFPGMFC_GROUP_EXISTS" },
    {  1, "OFPGMFC_INVALID_GROUP" },
    {  2, "OFPGMFC_WEIGHT_UNSUPPORTED" },
    {  3, "OFPGMFC_OUT_OF_GROUPS" },
    {  4, "OFPGMFC_OUT_OF_BUCKETS" },
    {  5, "OFPGMFC_CHAINING_UNSUPPORTED" },
    {  6, "OFPGMFC_WATCH_UNSUPPORTED" },
    {  7, "OFPGMFC_LOOP" },
    {  8, "OFPGMFC_UNKNOWN_GROUP" },
    {  9, "OFPGMFC_CHAINED_GROUP" },
    { 10, "OFPGMFC_BAD_TYPE" },
    { 11, "OFPGMFC_BAD_COMMAND" },
    { 12, "OFPGMFC_BAD_BUCKET" },
    { 13, "OFPGMFC_BAD_WATCH" },
    { 14, "OFPGMFC_EPERM" },
    {  0, NULL }
};

static const value_string openflow_v4_error_port_mod_failed_code_values[] =  {
    { 0, "OFPPMFC_BAD_PORT" },
    { 1, "OFPPMFC_BAD_HW_ADDR" },
    { 2, "OFPPMFC_BAD_CONFIG" },
    { 3, "OFPPMFC_BAD_ADVERTISE" },
    { 4, "OFPPMFC_EPERM" },
    { 0, NULL }
};

static const value_string openflow_v4_error_table_mod_failed_code_values[] =  {
    { 0, "OFPTMFC_BAD_TABLE" },
    { 1, "OFPTMFC_BAD_CONFIG" },
    { 2, "OFPTMFC_EPERM" },
    { 0, NULL }
};

static const value_string openflow_v4_error_queue_op_failed_code_values[] =  {
    { 0, "OFPQOFC_BAD_PORT" },
    { 1, "OFPQOFC_BAD_QUEUE" },
    { 2, "OFPQOFC_EPERM" },
    { 0, NULL }
};

static const value_string openflow_v4_error_switch_config_failed_code_values[] =  {
    { 0, "OFPSCFC_BAD_FLAGS" },
    { 1, "OFPSCFC_BAD_LEN" },
    { 2, "OFPQCFC_EPERM" },
    { 0, NULL }
};

static const value_string openflow_v4_error_role_request_failed_code_values[] =  {
    { 0, "OFPRRFC_STALE" },
    { 1, "OFPRRFC_UNSUP" },
    { 2, "OFPRRFC_BAD_ROLE" },
    { 0, NULL }
};

static const value_string openflow_v4_error_meter_mod_failed_code_values[] =  {
    {   0, "OFPMMFC_UNKNOWN" },
    {   1, "OFPMMFC_METER_EXISTS" },
    {   2, "OFPMMFC_INVALID_METER" },
    {   3, "OFPMMFC_UNKNOWN_METER" },
    {   4, "OFPMMFC_BAD_COMMAND" },
    {   5, "OFPMMFC_BAD_FLAGS" },
    {   6, "OFPMMFC_BAD_RATE" },
    {   7, "OFPMMFC_BAD_BURST" },
    {   8, "OFPMMFC_BAD_BAND" },
    {   9, "OFPMMFC_BAD_BAND_VALUE" },
    {  10, "OFPMMFC_OUT_OF_METERS" },
    {  11, "OFPMMFC_OUT_OF_BANDS" },
    {  0, NULL }
};

static const value_string openflow_v4_error_table_features_failed_code_values[] =  {
    { 0, "OFPTFFC_BAD_TABLE" },
    { 1, "OFPTFFC_BAD_METADATA" },
    { 2, "OFPTFFC_BAD_TYPE" },
    { 3, "OFPTFFC_BAD_LEN" },
    { 4, "OFPTFFC_BAD_ARGUMENT" },
    { 5, "OFPTFFC_EPERM" },
    { 0, NULL }
};

static void
dissect_openflow_error_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length)
{
    proto_tree *data_tree;
    guint16 error_type;

    /* uint16_t type; */
    error_type = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_openflow_v4_error_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset +=2;

    /* uint16_t code; */
    switch(error_type) {
    case OFPET_HELLO_FAILED:
        proto_tree_add_item(tree, hf_openflow_v4_error_hello_failed_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case OFPET_BAD_REQUEST:
        proto_tree_add_item(tree, hf_openflow_v4_error_bad_request_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case OFPET_BAD_ACTION:
        proto_tree_add_item(tree, hf_openflow_v4_error_bad_action_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case OFPET_BAD_INSTRUCTION:
        proto_tree_add_item(tree, hf_openflow_v4_error_bad_instruction_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case OFPET_BAD_MATCH:
        proto_tree_add_item(tree, hf_openflow_v4_error_bad_match_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case OFPET_FLOW_MOD_FAILED:
        proto_tree_add_item(tree, hf_openflow_v4_error_flow_mod_failed_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case OFPET_GROUP_MOD_FAILED:
        proto_tree_add_item(tree, hf_openflow_v4_error_group_mod_failed_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case OFPET_PORT_MOD_FAILED:
        proto_tree_add_item(tree, hf_openflow_v4_error_port_mod_failed_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case OFPET_TABLE_MOD_FAILED:
        proto_tree_add_item(tree, hf_openflow_v4_error_table_mod_failed_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case OFPET_QUEUE_OP_FAILED:
        proto_tree_add_item(tree, hf_openflow_v4_error_queue_op_failed_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case OFPET_SWITCH_CONFIG_FAILED:
        proto_tree_add_item(tree, hf_openflow_v4_error_switch_config_failed_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case OFPET_ROLE_REQUEST_FAILED:
        proto_tree_add_item(tree, hf_openflow_v4_error_role_request_failed_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case OFPET_METER_MOD_FAILED:
        proto_tree_add_item(tree, hf_openflow_v4_error_meter_mod_failed_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case OFPET_TABLE_FEATURES_FAILED:
        proto_tree_add_item(tree, hf_openflow_v4_error_table_features_failed_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case OFPET_EXPERIMENTER:
    default:
        proto_tree_add_item(tree, hf_openflow_v4_error_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    }
    offset +=2;

    switch(error_type) {
    case OFPET_HELLO_FAILED:
        /* uint8_t data[0]; contains an ASCII text string */
        proto_tree_add_item(tree, hf_openflow_v4_error_data_text, tvb, offset, length - 12, ENC_NA|ENC_ASCII);
        /*offset += length - 12;*/
        break;

    case OFPET_BAD_REQUEST:
    case OFPET_BAD_ACTION:
    case OFPET_BAD_INSTRUCTION:
    case OFPET_BAD_MATCH:
    case OFPET_FLOW_MOD_FAILED:
    case OFPET_GROUP_MOD_FAILED:
    case OFPET_PORT_MOD_FAILED:
    case OFPET_TABLE_MOD_FAILED:
    case OFPET_QUEUE_OP_FAILED:
    case OFPET_SWITCH_CONFIG_FAILED:
    case OFPET_ROLE_REQUEST_FAILED:
    case OFPET_METER_MOD_FAILED:
    case OFPET_TABLE_FEATURES_FAILED:
        /* uint8_t data[0]; contains at least the first 64 bytes of the failed request. */
        data_tree = proto_tree_add_subtree(tree, tvb, offset, length - offset, ett_openflow_v4_error_data, NULL, "Data");

        offset = dissect_openflow_header_v4(tvb, pinfo, data_tree, offset, length);

        proto_tree_add_item(data_tree, hf_openflow_v4_error_data_body, tvb, offset, length - 20, ENC_NA);
        /*offset += length - 12;*/
        break;

    case OFPET_EXPERIMENTER:
        /* uint32_t experimenter */
        proto_tree_add_item(tree, hf_openflow_v4_error_experimenter, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;
        /* uint8_t data[0]; */
        proto_tree_add_expert_format(tree, pinfo, &ei_openflow_v4_error_undecoded,
                                     tvb, offset, length - 16, "Experimenter error body.");
        /*offset += length - 16;*/
        break;

    default:
        /* uint8_t data[0]; */
        proto_tree_add_expert_format(tree, pinfo, &ei_openflow_v4_error_undecoded,
                                     tvb, offset, length - 12, "Unknown error body.");
        /*offset += length - 12;*/
        break;
    }
}


static void
dissect_openflow_echo_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length)
{
    /* data */
    if (offset < length) {
        proto_tree_add_item(tree, hf_openflow_v4_echo_data, tvb, offset, length - offset, ENC_NA);
    }
}


static void
dissect_openflow_experimenter_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length)
{
    /* uint32_t experimenter; */
    proto_tree_add_item(tree, hf_openflow_v4_experimenter_experimenter, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* uint32_t exp_type; */
    proto_tree_add_item(tree, hf_openflow_v4_experimenter_exp_type, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* data */
    if (offset < length) {
        proto_tree_add_expert_format(tree, pinfo, &ei_openflow_v4_experimenter_undecoded,
                                     tvb, offset, length - 16, "Experimenter body.");
    }
}

#define OFPC_FLOW_STATS    1<<0
#define OFPC_TABLE_STATS   1<<1
#define OFPC_PORT_STATS    1<<2
#define OFPC_GROUP_STATS   1<<3
#define OFPC_IP_REASM      1<<5
#define OFPC_QUEUE_STATS   1<<6
#define OFPC_PORT_BLOCKED  1<<8
static void
dissect_openflow_switch_features_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    proto_item *ti;
    proto_tree *cap_tree;

    /* uint64_t datapath_id; */
    proto_tree_add_item(tree, hf_openflow_v4_switch_features_datapath_id, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* uint32_t n_buffers; */
    proto_tree_add_item(tree, hf_openflow_v4_switch_features_n_buffers, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* uint8_t n_tables; */
    proto_tree_add_item(tree, hf_openflow_v4_switch_features_n_tables, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* uint8_t auxiliary_id; */
    proto_tree_add_item(tree, hf_openflow_v4_switch_features_auxiliary_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* uint8_t pad[2]; */
    proto_tree_add_item(tree, hf_openflow_v4_switch_features_pad, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint32_t capabilities; */
    ti = proto_tree_add_item(tree, hf_openflow_v4_switch_features_capabilities, tvb, offset, 4, ENC_BIG_ENDIAN);
    cap_tree = proto_item_add_subtree(ti, ett_openflow_v4_switch_features_capabilities);

    proto_tree_add_item(cap_tree, hf_openflow_v4_switch_features_capabilities_flow_stats, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cap_tree, hf_openflow_v4_switch_features_capabilities_table_stats, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cap_tree, hf_openflow_v4_switch_features_capabilities_port_stats, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cap_tree, hf_openflow_v4_switch_features_capabilities_group_stats, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cap_tree, hf_openflow_v4_switch_features_capabilities_ip_reasm, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cap_tree, hf_openflow_v4_switch_features_capabilities_queue_stats, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cap_tree, hf_openflow_v4_switch_features_capabilities_port_blocked, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* uint32_t reserved; */
    proto_tree_add_item(tree, hf_openflow_v4_switch_features_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    /*offset+=4;*/
}

static const value_string openflow_v4_switch_config_fragments_values[] = {
    { 0, "OFPC_FRAG_NORMAL" },
    { 1, "OFPC_FRAG_DROP" },
    { 2, "OFPC_FRAG_REASM" },
    { 0, NULL }
};

#define OFPCML_MAX   0xffe5  /* Maximum max_len value. */
static const value_string openflow_v4_controller_max_len_reserved_values[] = {
    { 0xffff, "OFPCML_NO_BUFFER" },
    { 0,      NULL }
};

static void
dissect_openflow_switch_config_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    proto_item *ti;
    proto_tree *flags_tree;

    /* uint16_t flags; */
    ti = proto_tree_add_item(tree, hf_openflow_v4_switch_config_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
    flags_tree = proto_item_add_subtree(ti, ett_openflow_v4_switch_config_flags);

    /* fragments */
    proto_tree_add_bits_item(flags_tree, hf_openflow_v4_switch_config_flags_fragments, tvb, (offset * 8) + 14, 2, ENC_NA);
    offset+=2;

    /* uint16_t miss_send_len; */
    if (tvb_get_ntohs(tvb, offset) <= OFPCML_MAX) {
        proto_tree_add_item(tree, hf_openflow_v4_switch_config_miss_send_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(tree, hf_openflow_v4_switch_config_miss_send_len_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    }
    /*offset+=2;*/
}

#define OFPR_NO_MATCH     0
#define OFPR_ACTION       1
#define OFPR_INVALID_TTL  2
static const value_string openflow_v4_packet_in_reason_values[] = {
    { OFPR_NO_MATCH,    "OFPR_NO_MATCH" },
    { OFPR_ACTION,      "OFPR_ACTION" },
    { OFPR_INVALID_TTL, "OFPR_INVALID_TTL" },
    { 0,                NULL }
};

static void
dissect_openflow_packet_in_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    proto_tree *data_tree;
    tvbuff_t *next_tvb;
    gboolean save_writable;
    gboolean save_in_error_pkt;
    address save_dl_src, save_dl_dst, save_net_src, save_net_dst, save_src, save_dst;

    /* uint32_t buffer_id; */
    if (tvb_get_ntohl(tvb, offset) != OFP_NO_BUFFER) {
        proto_tree_add_item(tree, hf_openflow_v4_packet_in_buffer_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(tree, hf_openflow_v4_packet_in_buffer_id_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* uint16_t total_len; */
    proto_tree_add_item(tree, hf_openflow_v4_packet_in_total_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint8_t reason; */
    proto_tree_add_item(tree, hf_openflow_v4_packet_in_reason, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset+=1;

    /* uint8_t table_id; */
    proto_tree_add_item(tree, hf_openflow_v4_packet_in_table_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset+=1;

    /* uint64_t cookie; */
    proto_tree_add_item(tree, hf_openflow_v4_packet_in_cookie, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* struct ofp_match match; */
    offset = dissect_openflow_match_v4(tvb, pinfo, tree, offset, length);

    /* uint8_t pad[2]; */
    proto_tree_add_item(tree, hf_openflow_v4_packet_in_pad, tvb, offset, 2, ENC_NA);
    offset+=2;

    /* uint8_t data[0]; */
    if (offset < length) {
        data_tree = proto_tree_add_subtree(tree, tvb, offset, length - offset, ett_openflow_v4_packet_in_data, NULL, "Data");

        /* save some state */
        save_writable = col_get_writable(pinfo->cinfo, -1);
        save_in_error_pkt = pinfo->flags.in_error_pkt;
        copy_address_shallow(&save_dl_src, &pinfo->dl_src);
        copy_address_shallow(&save_dl_dst, &pinfo->dl_dst);
        copy_address_shallow(&save_net_src, &pinfo->net_src);
        copy_address_shallow(&save_net_dst, &pinfo->net_dst);
        copy_address_shallow(&save_src, &pinfo->src);
        copy_address_shallow(&save_dst, &pinfo->dst);

        /* dissect data */
        col_set_writable(pinfo->cinfo, -1, FALSE);
        next_tvb = tvb_new_subset_length(tvb, offset, length - offset);
        call_dissector(eth_withoutfcs_handle, next_tvb, pinfo, data_tree);

        /* restore saved state */
        col_set_writable(pinfo->cinfo, -1, save_writable);
        pinfo->flags.in_error_pkt = save_in_error_pkt;
        copy_address_shallow(&pinfo->dl_src, &save_dl_src);
        copy_address_shallow(&pinfo->dl_dst, &save_dl_dst);
        copy_address_shallow(&pinfo->net_src, &save_net_src);
        copy_address_shallow(&pinfo->net_dst, &save_net_dst);
        copy_address_shallow(&pinfo->src, &save_src);
        copy_address_shallow(&pinfo->dst, &save_dst);
    }
}


#define OFPRR_IDLE_TIMEOUT  0
#define OFPRR_HARD_TIMEOUT  1
#define OFPRR_DELETE        2
#define OFPRR_GROUP_DELETE  3
static const value_string openflow_v4_flow_removed_reason_values[] = {
    { OFPRR_IDLE_TIMEOUT, "OFPRR_IDLE_TIMEOUT" },
    { OFPRR_HARD_TIMEOUT, "OFPRR_HARD_TIMEOUT" },
    { OFPRR_DELETE,       "OFPRR_DELETE" },
    { OFPRR_GROUP_DELETE, "OFPRR_GROUP_DELETE" },
    { 0,                  NULL }
};

static void
dissect_openflow_flow_removed_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    /* uint64_t cookie; */
    proto_tree_add_item(tree, hf_openflow_v4_flow_removed_cookie, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* uint16_t priority; */
    proto_tree_add_item(tree, hf_openflow_v4_flow_removed_priority, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint8_t reason; */
    proto_tree_add_item(tree, hf_openflow_v4_flow_removed_reason, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset+=1;

    /* uint8_t table_id; */
    proto_tree_add_item(tree, hf_openflow_v4_flow_removed_table_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset+=1;

    /* uint32_t duration_sec; */
    proto_tree_add_item(tree, hf_openflow_v4_flow_removed_duration_sec, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* uint32_t duration_nsec; */
    proto_tree_add_item(tree, hf_openflow_v4_flow_removed_duration_nsec, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* uint16_t idle_timeout; */
    proto_tree_add_item(tree, hf_openflow_v4_flow_removed_idle_timeout, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint16_t hard_timeout; */
    proto_tree_add_item(tree, hf_openflow_v4_flow_removed_hard_timeout, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint64_t packet_count; */
    proto_tree_add_item(tree, hf_openflow_v4_flow_removed_packet_count, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* uint64_t byte_count; */
    proto_tree_add_item(tree, hf_openflow_v4_flow_removed_byte_count, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* struct ofp_match match; */
    dissect_openflow_match_v4(tvb, pinfo, tree, offset, length);
}

#define OFPAT_OUTPUT         0  /* Output to switch port. */
#define OFPAT_COPY_TTL_OUT  11  /* Copy TTL "outwards" */
#define OFPAT_COPY_TTL_IN   12  /* Copy TTL "inwards" */
#define OFPAT_SET_MPLS_TTL  15  /* MPLS TTL */
#define OFPAT_DEC_MPLS_TTL  16  /* Decrement MPLS TTL */
#define OFPAT_PUSH_VLAN     17  /* Push a new VLAN tag */
#define OFPAT_POP_VLAN      18  /* Pop the outer VLAN tag */
#define OFPAT_PUSH_MPLS     19  /* Push a new MPLS tag */
#define OFPAT_POP_MPLS      20  /* Pop the outer MPLS tag */
#define OFPAT_SET_QUEUE     21  /* Set queue id when outputting to a port */
#define OFPAT_GROUP         22  /* Apply group. */
#define OFPAT_SET_NW_TTL    23  /* IP TTL. */
#define OFPAT_DEC_NW_TTL    24  /* Decrement IP TTL. */
#define OFPAT_SET_FIELD     25  /* Set a header field using OXM TLV format. */
#define OFPAT_PUSH_PBB      26  /* Push a new PBB service tag (I-TAG) */
#define OFPAT_POP_PBB       27  /* Pop the outer PBB service tag (I-TAG) */
#define OFPAT_EXPERIMENTER  0xffff

static const value_string openflow_v4_action_type_values[] = {
    {      0, "OFPAT_OUTPUT" },
    {     11, "OFPAT_COPY_TTL_OUT" },
    {     12, "OFPAT_COPY_TTL_IN" },
    {     15, "OFPAT_SET_MPLS_TTL" },
    {     16, "OFPAT_DEC_MPLS_TTL" },
    {     17, "OFPAT_PUSH_VLAN" },
    {     18, "OFPAT_POP_VLAN" },
    {     19, "OFPAT_PUSH_MPLS" },
    {     20, "OFPAT_POP_MPLS" },
    {     21, "OFPAT_SET_QUEUE" },
    {     22, "OFPAT_GROUP" },
    {     23, "OFPAT_SET_NW_TTL" },
    {     24, "OFPAT_DEC_NW_TTL" },
    {     25, "OFPAT_SET_FIELD" },
    {     26, "OFPAT_PUSH_PBB" },
    {     27, "OFPAT_POP_PBB" },
    { 0xffff, "OFPAT_EXPERIMENTER" },
    { 0,      NULL}
};



static int
dissect_openflow_action_header_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    guint16 act_type;

    /* uint16_t type; */
    act_type = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_openflow_v4_action_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint16_t length; */
    proto_tree_add_item(tree, hf_openflow_v4_action_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    if (act_type == OFPAT_EXPERIMENTER) {
        /* uint32_t experimenter; */
        proto_tree_add_item(tree, hf_openflow_v4_action_experimenter_experimenter, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;
    }

    return offset;
}


static int
dissect_openflow_action_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    proto_tree *act_tree;
    guint16 act_type;
    guint16 act_length;
    gint32 act_end;

    act_type = tvb_get_ntohs(tvb, offset);
    act_length = tvb_get_ntohs(tvb, offset + 2);
    act_end = offset + act_length;

    act_tree = proto_tree_add_subtree(tree, tvb, offset, act_length, ett_openflow_v4_action, NULL, "Action");

    offset = dissect_openflow_action_header_v4(tvb, pinfo, act_tree, offset, length);

    switch (act_type) {
    case OFPAT_OUTPUT:
        /* uint32_t port; */
        if (tvb_get_ntohl(tvb, offset) <= OFPP_MAX) {
            proto_tree_add_item(act_tree, hf_openflow_v4_action_output_port, tvb, offset, 4, ENC_BIG_ENDIAN);
        } else {
            proto_tree_add_item(act_tree, hf_openflow_v4_action_output_port_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
        }
        offset+=4;

        /* uint16_t max_len; */
        if (tvb_get_ntohs(tvb, offset) <= OFPCML_MAX) {
            proto_tree_add_item(act_tree, hf_openflow_v4_action_output_max_len, tvb, offset, 2, ENC_BIG_ENDIAN);
        } else {
            proto_tree_add_item(act_tree, hf_openflow_v4_action_output_max_len_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
        }
        offset+=2;

        /* uint8_t pad[6]; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_output_pad, tvb, offset, 6, ENC_NA);
        offset+=6;

        break;

    case OFPAT_COPY_TTL_OUT:
        /* uint8_t pad[4]; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_copy_ttl_out_pad, tvb, offset, 4, ENC_NA);
        offset+=4;
        break;

    case OFPAT_COPY_TTL_IN:
        /* uint8_t pad[4]; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_copy_ttl_in_pad, tvb, offset, 4, ENC_NA);
        offset+=4;
        break;

    case OFPAT_SET_MPLS_TTL:
        /* uint8_t mpls_ttl; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_set_mpls_ttl_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset+=1;

        /* uint8_t pad[3]; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_set_mpls_ttl_pad, tvb, offset, 3, ENC_NA);
        offset+=3;
        break;

    case OFPAT_DEC_MPLS_TTL:
        /* uint8_t pad[4]; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_dec_mpls_ttl_pad, tvb, offset, 4, ENC_NA);
        offset+=4;
        break;

    case OFPAT_PUSH_VLAN:
        /* uint16_t ethertype; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_push_vlan_ethertype, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;

        /* uint8_t pad[2]; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_push_vlan_pad, tvb, offset, 2, ENC_NA);
        offset+=2;
        break;

    case OFPAT_POP_VLAN:
        /* uint8_t pad[4]; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_pop_vlan_pad, tvb, offset, 4, ENC_NA);
        offset+=4;
        break;

    case OFPAT_PUSH_MPLS:
        /* uint16_t ethertype; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_push_mpls_ethertype, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;

        /* uint8_t pad[2]; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_push_mpls_pad, tvb, offset, 2, ENC_NA);
        offset+=2;
        break;

    case OFPAT_POP_MPLS:
        /* uint16_t ethertype; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_pop_mpls_ethertype, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;

        /* uint8_t pad[2]; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_pop_mpls_pad, tvb, offset, 2, ENC_NA);
        offset+=2;
        break;

    case OFPAT_SET_QUEUE:
        /* uint32_t queue_id; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_set_queue_queue_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;
        break;

    case OFPAT_GROUP:
        /* uint32_t group_id; */
        if (tvb_get_ntohl(tvb, offset) <= OFPG_MAX) {
            proto_tree_add_item(act_tree, hf_openflow_v4_action_group_group_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        } else {
            proto_tree_add_item(act_tree, hf_openflow_v4_action_group_group_id_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
        }
        offset+=4;
        break;

    case OFPAT_SET_NW_TTL:
        /* uint8_t nw_ttl; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_set_nw_ttl_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset+=1;

        /* uint8_t pad[3]; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_set_nw_ttl_pad, tvb, offset, 3, ENC_NA);
        offset+=3;
        break;

    case OFPAT_DEC_NW_TTL:
        /* uint8_t pad[4]; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_dec_nw_ttl_pad, tvb, offset, 4, ENC_NA);
        offset+=4;
        break;

    case OFPAT_SET_FIELD:
        offset = dissect_openflow_oxm_v4(tvb, pinfo, act_tree, offset, length);

        /* padded to 64 bits */
        if (offset < act_end) {
            proto_tree_add_item(act_tree, hf_openflow_v4_action_set_field_pad, tvb, offset, act_end - offset, ENC_NA);
            offset = act_end;
        }
        break;

    case OFPAT_PUSH_PBB:
        /* uint16_t ethertype; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_push_pbb_ethertype, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;

        /* uint8_t pad[2]; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_push_pbb_pad, tvb, offset, 2, ENC_NA);
        offset+=2;
        break;

    case OFPAT_POP_PBB:
        /* uint8_t pad[4]; */
        proto_tree_add_item(act_tree, hf_openflow_v4_action_pop_pbb_pad, tvb, offset, 4, ENC_NA);
        offset+=4;
        break;

    case OFPAT_EXPERIMENTER:
        proto_tree_add_expert_format(act_tree, pinfo, &ei_openflow_v4_action_undecoded,
                                     tvb, offset, act_length - 8, "Experimenter action body.");
        if (act_length > 8)
            offset += act_length - 8;
        break;

    default:
        proto_tree_add_expert_format(act_tree, pinfo, &ei_openflow_v4_action_undecoded,
                                     tvb, offset, act_length - 4, "Unknown action body.");
        if (act_length > 4)
            offset += act_length - 4;
        break;
    }

    return offset;
}


#define OFPPC_PORT_DOWN     1 << 0
#define OFPPC_NO_RECV       1 << 2
#define OFPPC_NO_FWD        1 << 5
#define OFPPC_NO_PACKET_IN  1 << 6

#define OFPPS_LINK_DOWN  1 << 0
#define OFPPS_BLOCKED    1 << 1
#define OFPPS_LIVE       1 << 2

#define OFPPF_10MB_HD   1 << 0
#define OFPPF_10MB_FD   1 << 1
#define OFPPF_100MB_HD  1 << 2
#define OFPPF_100MB_FD  1 << 3
#define OFPPF_1GB_HD    1 << 4
#define OFPPF_1GB_FD    1 << 5
#define OFPPF_10GB_FD   1 << 6
#define OFPPF_40GB_FD   1 << 7
#define OFPPF_100GB_FD  1 << 8
#define OFPPF_1TB_FD    1 << 9
#define OFPPF_OTHER     1 << 10

#define OFPPF_COPPER      1 << 11
#define OFPPF_FIBER       1 << 12
#define OFPPF_AUTONEG     1 << 13
#define OFPPF_PAUSE       1 << 14
#define OFPPF_PAUSE_ASYM  1 << 15

#define OFP_ETH_ALEN            6
#define OFP_MAX_PORT_NAME_LEN  16
static int
dissect_openflow_port_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    proto_item *ti;
    proto_tree *port_tree, *conf_tree, *state_tree, *curr_tree, *adv_tree, *supp_tree, *peer_tree;

    port_tree = proto_tree_add_subtree(tree, tvb, offset, 64, ett_openflow_v4_port, NULL, "Port");

    /* uint32_t port_no; */
    if (tvb_get_ntohl(tvb, offset) <= OFPP_MAX) {
        proto_tree_add_item(port_tree, hf_openflow_v4_port_port_no, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(port_tree, hf_openflow_v4_port_port_no_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* uint8_t pad[4]; */
    proto_tree_add_item(port_tree, hf_openflow_v4_port_pad, tvb, offset, 4, ENC_NA);
    offset+=4;

    /* uint8_t hw_addr[OFP_ETH_ALEN]; */
    proto_tree_add_item(port_tree, hf_openflow_v4_port_hw_addr, tvb, offset, OFP_ETH_ALEN, ENC_NA);
    offset+=OFP_ETH_ALEN;

    /* uint8_t pad2[2]; */
    proto_tree_add_item(port_tree, hf_openflow_v4_port_pad2, tvb, offset, 2, ENC_NA);
    offset+=2;

    /* char name[OFP_MAX_PORT_NAME_LEN]; Null-terminated */
    proto_tree_add_item(port_tree, hf_openflow_v4_port_name, tvb, offset, OFP_MAX_PORT_NAME_LEN, ENC_ASCII|ENC_NA);
    offset+=OFP_MAX_PORT_NAME_LEN;

    /* uint32_t config; */
    ti = proto_tree_add_item(port_tree, hf_openflow_v4_port_config, tvb, offset, 4, ENC_BIG_ENDIAN);
    conf_tree = proto_item_add_subtree(ti, ett_openflow_v4_port_config);

    proto_tree_add_item(conf_tree, hf_openflow_v4_port_config_port_down, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(conf_tree, hf_openflow_v4_port_config_no_recv, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(conf_tree, hf_openflow_v4_port_config_no_fwd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(conf_tree, hf_openflow_v4_port_config_no_packet_in, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* uint32_t state; */
    ti = proto_tree_add_item(port_tree, hf_openflow_v4_port_state, tvb, offset, 4, ENC_BIG_ENDIAN);
    state_tree = proto_item_add_subtree(ti, ett_openflow_v4_port_state);

    proto_tree_add_item(state_tree, hf_openflow_v4_port_state_link_down, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(state_tree, hf_openflow_v4_port_state_blocked, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(state_tree, hf_openflow_v4_port_state_live, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* uint32_t curr; */
    ti = proto_tree_add_item(port_tree, hf_openflow_v4_port_current, tvb, offset, 4, ENC_BIG_ENDIAN);
    curr_tree = proto_item_add_subtree(ti, ett_openflow_v4_port_current);

    proto_tree_add_item(curr_tree, hf_openflow_v4_port_current_10mb_hd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(curr_tree, hf_openflow_v4_port_current_10mb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(curr_tree, hf_openflow_v4_port_current_100mb_hd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(curr_tree, hf_openflow_v4_port_current_100mb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(curr_tree, hf_openflow_v4_port_current_1gb_hd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(curr_tree, hf_openflow_v4_port_current_1gb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(curr_tree, hf_openflow_v4_port_current_10gb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(curr_tree, hf_openflow_v4_port_current_40gb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(curr_tree, hf_openflow_v4_port_current_100gb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(curr_tree, hf_openflow_v4_port_current_1tb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(curr_tree, hf_openflow_v4_port_current_other, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(curr_tree, hf_openflow_v4_port_current_copper, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(curr_tree, hf_openflow_v4_port_current_fiber, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(curr_tree, hf_openflow_v4_port_current_autoneg, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(curr_tree, hf_openflow_v4_port_current_pause, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(curr_tree, hf_openflow_v4_port_current_pause_asym, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* uint32_t advertised; */
    ti = proto_tree_add_item(port_tree, hf_openflow_v4_port_advertised, tvb, offset, 4, ENC_BIG_ENDIAN);
    adv_tree = proto_item_add_subtree(ti, ett_openflow_v4_port_advertised);

    proto_tree_add_item(adv_tree, hf_openflow_v4_port_advertised_10mb_hd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(adv_tree, hf_openflow_v4_port_advertised_10mb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(adv_tree, hf_openflow_v4_port_advertised_100mb_hd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(adv_tree, hf_openflow_v4_port_advertised_100mb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(adv_tree, hf_openflow_v4_port_advertised_1gb_hd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(adv_tree, hf_openflow_v4_port_advertised_1gb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(adv_tree, hf_openflow_v4_port_advertised_10gb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(adv_tree, hf_openflow_v4_port_advertised_40gb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(adv_tree, hf_openflow_v4_port_advertised_100gb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(adv_tree, hf_openflow_v4_port_advertised_1tb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(adv_tree, hf_openflow_v4_port_advertised_other, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(adv_tree, hf_openflow_v4_port_advertised_copper, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(adv_tree, hf_openflow_v4_port_advertised_fiber, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(adv_tree, hf_openflow_v4_port_advertised_autoneg, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(adv_tree, hf_openflow_v4_port_advertised_pause, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(adv_tree, hf_openflow_v4_port_advertised_pause_asym, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* uint32_t supported; */
    ti = proto_tree_add_item(port_tree, hf_openflow_v4_port_supported, tvb, offset, 4, ENC_BIG_ENDIAN);
    supp_tree = proto_item_add_subtree(ti, ett_openflow_v4_port_supported);

    proto_tree_add_item(supp_tree, hf_openflow_v4_port_supported_10mb_hd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(supp_tree, hf_openflow_v4_port_supported_10mb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(supp_tree, hf_openflow_v4_port_supported_100mb_hd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(supp_tree, hf_openflow_v4_port_supported_100mb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(supp_tree, hf_openflow_v4_port_supported_1gb_hd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(supp_tree, hf_openflow_v4_port_supported_1gb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(supp_tree, hf_openflow_v4_port_supported_10gb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(supp_tree, hf_openflow_v4_port_supported_40gb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(supp_tree, hf_openflow_v4_port_supported_100gb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(supp_tree, hf_openflow_v4_port_supported_1tb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(supp_tree, hf_openflow_v4_port_supported_other, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(supp_tree, hf_openflow_v4_port_supported_copper, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(supp_tree, hf_openflow_v4_port_supported_fiber, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(supp_tree, hf_openflow_v4_port_supported_autoneg, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(supp_tree, hf_openflow_v4_port_supported_pause, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(supp_tree, hf_openflow_v4_port_supported_pause_asym, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* uint32_t peer; */
    ti = proto_tree_add_item(port_tree, hf_openflow_v4_port_peer, tvb, offset, 4, ENC_BIG_ENDIAN);
    peer_tree = proto_item_add_subtree(ti, ett_openflow_v4_port_peer);

    proto_tree_add_item(peer_tree, hf_openflow_v4_port_peer_10mb_hd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(peer_tree, hf_openflow_v4_port_peer_10mb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(peer_tree, hf_openflow_v4_port_peer_100mb_hd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(peer_tree, hf_openflow_v4_port_peer_100mb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(peer_tree, hf_openflow_v4_port_peer_1gb_hd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(peer_tree, hf_openflow_v4_port_peer_1gb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(peer_tree, hf_openflow_v4_port_peer_10gb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(peer_tree, hf_openflow_v4_port_peer_40gb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(peer_tree, hf_openflow_v4_port_peer_100gb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(peer_tree, hf_openflow_v4_port_peer_1tb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(peer_tree, hf_openflow_v4_port_peer_other, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(peer_tree, hf_openflow_v4_port_peer_copper, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(peer_tree, hf_openflow_v4_port_peer_fiber, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(peer_tree, hf_openflow_v4_port_peer_autoneg, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(peer_tree, hf_openflow_v4_port_peer_pause, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(peer_tree, hf_openflow_v4_port_peer_pause_asym, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* uint32_t curr_speed; */
    proto_tree_add_item(port_tree, hf_openflow_v4_port_curr_speed, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* uint32_t max_speed; */
    proto_tree_add_item(port_tree, hf_openflow_v4_port_max_speed, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    return offset;
}



#define OFPPR_ADD     0
#define OFPPR_DELETE  1
#define OFPPR_MODIFY  2
static const value_string openflow_v4_port_status_reason_values[] = {
    { OFPPR_ADD,    "OFPPR_ADD" },
    { OFPPR_DELETE, "OFPPR_DELETE" },
    { OFPPR_MODIFY, "OFPPR_MODIFY" },
    { 0,            NULL }
};

static void
dissect_openflow_port_status_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    /* uint8_t reason; */
    proto_tree_add_item(tree, hf_openflow_v4_port_status_reason, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset+=1;

    /* uint8_t pad[7]; */
    proto_tree_add_item(tree, hf_openflow_v4_port_status_pad, tvb, offset, 7, ENC_NA);
    offset+=7;

    /* struct ofp_port desc; */
    dissect_openflow_port_v4(tvb, pinfo, tree, offset, length);
}


static void
dissect_openflow_packet_out_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    proto_tree *data_tree;
    guint16 acts_len;
    gint32 acts_end;
    tvbuff_t *next_tvb;
    gboolean save_writable;
    gboolean save_in_error_pkt;
    address save_dl_src, save_dl_dst, save_net_src, save_net_dst, save_src, save_dst;

    /* uint32_t buffer_id; */
    if (tvb_get_ntohl(tvb, offset) != OFP_NO_BUFFER) {
        proto_tree_add_item(tree, hf_openflow_v4_packet_out_buffer_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(tree, hf_openflow_v4_packet_out_buffer_id_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* uint32_t in_port; */
    if (tvb_get_ntohl(tvb, offset) <= OFPP_MAX) {
        proto_tree_add_item(tree, hf_openflow_v4_packet_out_in_port, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(tree, hf_openflow_v4_packet_out_in_port_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* uint16_t actions_len; */
    acts_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_openflow_v4_packet_out_acts_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint8_t pad[6]; */
    proto_tree_add_item(tree, hf_openflow_v4_packet_out_pad, tvb, offset, 6, ENC_NA);
    offset+=6;

    /* struct ofp_action_header actions[0]; */
    acts_end = offset + acts_len;

    while (offset < acts_end) {
        offset = dissect_openflow_action_v4(tvb, pinfo, tree, offset, length);
    }

    /* uint8_t data[0]; */
    if (offset < length) {
        data_tree = proto_tree_add_subtree(tree, tvb, offset, length - offset, ett_openflow_v4_packet_out_data, NULL, "Data");

        /* save some state */
        save_writable = col_get_writable(pinfo->cinfo, -1);
        save_in_error_pkt = pinfo->flags.in_error_pkt;
        copy_address_shallow(&save_dl_src, &pinfo->dl_src);
        copy_address_shallow(&save_dl_dst, &pinfo->dl_dst);
        copy_address_shallow(&save_net_src, &pinfo->net_src);
        copy_address_shallow(&save_net_dst, &pinfo->net_dst);
        copy_address_shallow(&save_src, &pinfo->src);
        copy_address_shallow(&save_dst, &pinfo->dst);

        /* dissect data */
        col_set_writable(pinfo->cinfo, -1, FALSE);
        next_tvb = tvb_new_subset_length(tvb, offset, length - offset);
        call_dissector(eth_withoutfcs_handle, next_tvb, pinfo, data_tree);

        /* restore saved state */
        col_set_writable(pinfo->cinfo, -1, save_writable);
        pinfo->flags.in_error_pkt = save_in_error_pkt;
        copy_address_shallow(&pinfo->dl_src, &save_dl_src);
        copy_address_shallow(&pinfo->dl_dst, &save_dl_dst);
        copy_address_shallow(&pinfo->net_src, &save_net_src);
        copy_address_shallow(&pinfo->net_dst, &save_net_dst);
        copy_address_shallow(&pinfo->src, &save_src);
        copy_address_shallow(&pinfo->dst, &save_dst);
    }
}


#define OFPIT_GOTO_TABLE      1       /* Setup the next table in the lookup */
#define OFPIT_WRITE_METADATA  2       /* Setup the metadata field for use later in */
#define OFPIT_WRITE_ACTIONS   3       /* Write the action(s) onto the datapath action */
#define OFPIT_APPLY_ACTIONS   4       /* Applies the action(s) immediately */
#define OFPIT_CLEAR_ACTIONS   5       /* Clears all actions from the datapath */
#define OFPIT_METER           6       /* Apply meter (rate limiter) */
#define OFPIT_EXPERIMENTER    0xFFFF  /* Experimenter instruction */
static const value_string openflow_v4_instruction_type_values[] = {
    { 0x0001, "OFPIT_GOTO_TABLE" },
    { 0x0002, "OFPIT_WRITE_METADATA" },
    { 0x0003, "OFPIT_WRITE_ACTIONS" },
    { 0x0004, "OFPIT_APPLY_ACTIONS" },
    { 0x0005, "OFPIT_CLEAR_ACTIONS" },
    { 0x0006, "OFPIT_METER" },
    { 0xffff, "OFPIT_EXPERIMENTER = 0xFFFF" },
    { 0,      NULL }
};



static int
dissect_openflow_instruction_header_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    guint16 inst_type;

    /* uint16_t type; */
    inst_type = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_openflow_v4_instruction_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint16_t length; */
    proto_tree_add_item(tree, hf_openflow_v4_instruction_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    if (inst_type == OFPIT_EXPERIMENTER) {
        /* uint32_t experimenter; */
        proto_tree_add_item(tree, hf_openflow_v4_instruction_experimenter_experimenter, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;
    }

    return offset;
}


static int
dissect_openflow_instruction_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    proto_tree *inst_tree;
    guint16 inst_type;
    guint16 inst_length;
    gint32 acts_end;

    inst_type = tvb_get_ntohs(tvb, offset);
    inst_length = tvb_get_ntohs(tvb, offset + 2);

    if (inst_length < 8) {
        inst_length = 8;
    }

    inst_tree = proto_tree_add_subtree(tree, tvb, offset, inst_length, ett_openflow_v4_instruction, NULL, "Instruction");

    offset = dissect_openflow_instruction_header_v4(tvb, pinfo, inst_tree, offset, length);

    switch (inst_type) {
    case OFPIT_GOTO_TABLE:
        /* uint8_t table_id; */
        proto_tree_add_item(inst_tree, hf_openflow_v4_instruction_goto_table_table_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset+=1;

        /* uint8_t pad[3]; */
        proto_tree_add_item(inst_tree, hf_openflow_v4_instruction_goto_table_pad, tvb, offset, 3, ENC_NA);
        offset+=3;
        break;

    case OFPIT_WRITE_METADATA:
        /* uint8_t pad[4]; */
        proto_tree_add_item(inst_tree, hf_openflow_v4_instruction_write_metadata_pad, tvb, offset, 4, ENC_NA);
        offset+=4;

        /* uint64_t metadata; */
        proto_tree_add_item(inst_tree, hf_openflow_v4_instruction_write_metadata_value, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset+=8;

        /* uint64_t metadata_mask; */
        proto_tree_add_item(inst_tree, hf_openflow_v4_instruction_write_metadata_mask, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset+=8;
        break;

    case OFPIT_WRITE_ACTIONS:
    case OFPIT_APPLY_ACTIONS:
    case OFPIT_CLEAR_ACTIONS:
        proto_tree_add_item(inst_tree, hf_openflow_v4_instruction_actions_pad, tvb, offset, 4, ENC_NA);
        offset+=4;

        acts_end = offset + inst_length - 8;
        while (offset < acts_end) {
            offset = dissect_openflow_action_v4(tvb, pinfo, inst_tree, offset, length);
        }
        break;

    case OFPIT_METER:
        /* uint32_t meter_id; */
        if (tvb_get_ntohl(tvb, offset) <= OFPM_MAX) {
            proto_tree_add_item(inst_tree, hf_openflow_v4_instruction_meter_meter_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        } else {
            proto_tree_add_item(inst_tree, hf_openflow_v4_instruction_meter_meter_id_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
        }
        offset+=4;
        break;

    case OFPIT_EXPERIMENTER:
        proto_tree_add_expert_format(inst_tree, pinfo, &ei_openflow_v4_instruction_undecoded,
                                     tvb, offset, inst_length - 8, "Experimenter instruction body.");
        offset += inst_length - 8;
        break;

    default:
        proto_tree_add_expert_format(inst_tree, pinfo, &ei_openflow_v4_instruction_undecoded,
                                     tvb, offset, inst_length - 4, "Unknown instruction body.");
        offset += inst_length - 4;
        break;
    }

    return offset;
}


static const value_string openflow_v4_flowmod_command_values[] = {
    { 0, "OFPFC_ADD" },
    { 1, "OFPFC_MODIFY" },
    { 2, "OFPFC_MODIFY_STRICT" },
    { 3, "OFPFC_DELETE" },
    { 4, "OFPFC_DELETE_STRICT" },
    { 0, NULL }
};

#define OFPFF_SEND_FLOW_REM  1 << 0  /* Send flow removed message when flow expires or is deleted. */
#define OFPFF_CHECK_OVERLAP  1 << 1  /* Check for overlapping entries first. */
#define OFPFF_RESET_COUNTS   1 << 2  /* Reset flow packet and byte counts. */
#define OFPFF_NO_PKT_COUNTS  1 << 3  /* Don't keep track of packet count. */
#define OFPFF_NO_BYT_COUNTS  1 << 4  /* Don't keep track of byte count. */

static void
dissect_openflow_flowmod_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length)
{
    proto_item *ti;
    proto_tree *flags_tree;

    /* uint64_t cookie; */
    proto_tree_add_item(tree, hf_openflow_v4_flowmod_cookie, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* uint64_t cookie_mask; */
    proto_tree_add_item(tree, hf_openflow_v4_flowmod_cookie_mask, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* uint8_t table_id; */
    if (tvb_get_guint8(tvb, offset) <= OFPTT_MAX) {
        proto_tree_add_item(tree, hf_openflow_v4_flowmod_table_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(tree, hf_openflow_v4_flowmod_table_id_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
    offset+=1;

    /* uint8_t command; */
    proto_tree_add_item(tree, hf_openflow_v4_flowmod_command, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset+=1;

    /* uint16_t idle_timeout; */
    proto_tree_add_item(tree, hf_openflow_v4_flowmod_idle_timeout, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint16_t hard_timeout; */
    proto_tree_add_item(tree, hf_openflow_v4_flowmod_hard_timeout, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint16_t priority; */
    proto_tree_add_item(tree, hf_openflow_v4_flowmod_priority, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint32_t buffer_id; */
    if (tvb_get_ntohl(tvb, offset) != OFP_NO_BUFFER) {
        proto_tree_add_item(tree, hf_openflow_v4_flowmod_buffer_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(tree, hf_openflow_v4_flowmod_buffer_id_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* uint32_t out_port; */
    if (tvb_get_ntohl(tvb, offset) <= OFPP_MAX) {
        proto_tree_add_item(tree, hf_openflow_v4_flowmod_out_port, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(tree, hf_openflow_v4_flowmod_out_port_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* uint32_t out_group; */
    if (tvb_get_ntohl(tvb, offset) <= OFPG_MAX) {
        proto_tree_add_item(tree, hf_openflow_v4_flowmod_out_group, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(tree, hf_openflow_v4_flowmod_out_group_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* uint16_t flags; */
    ti = proto_tree_add_item(tree, hf_openflow_v4_flowmod_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
    flags_tree = proto_item_add_subtree(ti, ett_openflow_v4_flowmod_flags);

    proto_tree_add_item(flags_tree, hf_openflow_v4_flowmod_flags_send_flow_rem, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_openflow_v4_flowmod_flags_check_overlap, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_openflow_v4_flowmod_flags_reset_counts,  tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_openflow_v4_flowmod_flags_no_packet_counts, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_openflow_v4_flowmod_flags_no_byte_counts, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint8_t pad[2]; */
    proto_tree_add_item(tree, hf_openflow_v4_flowmod_pad, tvb, offset, 2, ENC_NA);
    offset+=2;

    /* struct ofp_match match; */
    offset = dissect_openflow_match_v4(tvb, pinfo, tree, offset, length);

    /* struct ofp_instruction instructions[0]; */
    while (offset < length) {
        offset = dissect_openflow_instruction_v4(tvb, pinfo, tree, offset, length);
    }
}

static int
dissect_openflow_bucket_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length)
{
    proto_item *ti;
    proto_tree *bucket_tree;
    guint16 bucket_length;
    gint32 acts_end;

    bucket_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_openflow_v4_bucket, &ti, "Bucket");

    /* uint16_t len; */
    bucket_length = tvb_get_ntohs(tvb, offset);
    proto_item_set_len(ti, bucket_length);
    proto_tree_add_item(bucket_tree, hf_openflow_v4_bucket_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    if (bucket_length < 16) {
        bucket_length = 16;
    }

    /* uint16_t weight; */
    proto_tree_add_item(bucket_tree, hf_openflow_v4_bucket_weight, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint32_t watch_port; */
    if (tvb_get_ntohl(tvb, offset) <= OFPP_MAX) {
        proto_tree_add_item(bucket_tree, hf_openflow_v4_bucket_watch_port, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(bucket_tree, hf_openflow_v4_bucket_watch_port_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* uint32_t watch_group; */
    if (tvb_get_ntohl(tvb, offset) <= OFPG_MAX) {
        proto_tree_add_item(bucket_tree, hf_openflow_v4_bucket_watch_group, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(bucket_tree, hf_openflow_v4_bucket_watch_group_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* uint8_t pad[4]; */
    proto_tree_add_item(bucket_tree, hf_openflow_v4_bucket_pad, tvb, offset, 4, ENC_NA);
    offset+=4;

    /*struct ofp_action_header actions[0]; */
    acts_end = offset + bucket_length - 16;
    while (offset < acts_end) {
        offset = dissect_openflow_action_v4(tvb, pinfo, bucket_tree, offset, length);
    }

    return offset;
}


static const value_string openflow_v4_groupmod_command_values[] = {
    { 0, "OFPGC_ADD" },
    { 1, "OFPGC_MODIFY" },
    { 2, "OFPGC_DELETE" },
    { 0, NULL }
};

#define OFPGT_ALL       0
#define OFPGT_SELECT    1
#define OFPGT_INDIRECT  2
#define OFPGT_FF        3
static const value_string openflow_v4_group_type_values[] = {
    { OFPGT_ALL,      "OFPGT_ALL" },
    { OFPGT_SELECT,   "OFPGT_SELECT" },
    { OFPGT_INDIRECT, "OFPGT_INDIRECT" },
    { OFPGT_FF,       "OFPGT_FF" },
    { 0,              NULL }
};

static void
dissect_openflow_groupmod_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length)
{
    /* uint16_t command; */
    proto_tree_add_item(tree, hf_openflow_v4_groupmod_command, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint8_t type; */
    proto_tree_add_item(tree, hf_openflow_v4_groupmod_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset+=1;

    /* uint8_t pad; */
    proto_tree_add_item(tree, hf_openflow_v4_groupmod_pad, tvb, offset, 1, ENC_NA);
    offset+=1;

    /* uint32_t group_id; */
    if (tvb_get_ntohl(tvb, offset) <= OFPG_MAX) {
        proto_tree_add_item(tree, hf_openflow_v4_groupmod_group_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(tree, hf_openflow_v4_groupmod_group_id_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* struct ofp_bucket buckets[0]; */
    while (offset < length) {
        offset = dissect_openflow_bucket_v4(tvb, pinfo, tree, offset, length);
    }
}


static void
dissect_openflow_portmod_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    proto_item *ti;
    proto_tree *conf_tree, *mask_tree, *adv_tree;

    /* uint32_t port_no; */
    if (tvb_get_ntohl(tvb, offset) <= OFPP_MAX) {
        proto_tree_add_item(tree, hf_openflow_v4_portmod_port_no, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(tree, hf_openflow_v4_portmod_port_no_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* uint8_t pad[4]; */
    proto_tree_add_item(tree, hf_openflow_v4_portmod_pad, tvb, offset, 4, ENC_NA);
    offset+=4;

    /* uint8_t hw_addr[OFP_ETH_ALEN]; */
    proto_tree_add_item(tree, hf_openflow_v4_portmod_hw_addr, tvb, offset, OFP_ETH_ALEN, ENC_NA);
    offset+=OFP_ETH_ALEN;

    /* uint8_t pad2[2]; */
    proto_tree_add_item(tree, hf_openflow_v4_portmod_pad2, tvb, offset, 2, ENC_NA);
    offset+=2;

    /* uint32_t config; */
    ti = proto_tree_add_item(tree, hf_openflow_v4_portmod_config, tvb, offset, 4, ENC_BIG_ENDIAN);
    conf_tree = proto_item_add_subtree(ti, ett_openflow_v4_portmod_config);

    proto_tree_add_item(conf_tree, hf_openflow_v4_portmod_config_port_down, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(conf_tree, hf_openflow_v4_portmod_config_no_recv, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(conf_tree, hf_openflow_v4_portmod_config_no_fwd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(conf_tree, hf_openflow_v4_portmod_config_no_packet_in, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* uint32_t mask; */
    ti = proto_tree_add_item(tree, hf_openflow_v4_portmod_mask, tvb, offset, 4, ENC_BIG_ENDIAN);
    mask_tree = proto_item_add_subtree(ti, ett_openflow_v4_portmod_mask);

    proto_tree_add_item(mask_tree, hf_openflow_v4_portmod_mask_port_down, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(mask_tree, hf_openflow_v4_portmod_mask_no_recv, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(mask_tree, hf_openflow_v4_portmod_mask_no_fwd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(mask_tree, hf_openflow_v4_portmod_mask_no_packet_in, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* uint32_t advertise; */
    ti = proto_tree_add_item(tree, hf_openflow_v4_portmod_advertise, tvb, offset, 4, ENC_BIG_ENDIAN);
    adv_tree = proto_item_add_subtree(ti, ett_openflow_v4_portmod_advertise);

    proto_tree_add_item(adv_tree, hf_openflow_v4_portmod_advertise_10mb_hd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(adv_tree, hf_openflow_v4_portmod_advertise_10mb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(adv_tree, hf_openflow_v4_portmod_advertise_100mb_hd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(adv_tree, hf_openflow_v4_portmod_advertise_100mb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(adv_tree, hf_openflow_v4_portmod_advertise_1gb_hd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(adv_tree, hf_openflow_v4_portmod_advertise_1gb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(adv_tree, hf_openflow_v4_portmod_advertise_10gb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(adv_tree, hf_openflow_v4_portmod_advertise_40gb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(adv_tree, hf_openflow_v4_portmod_advertise_100gb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(adv_tree, hf_openflow_v4_portmod_advertise_1tb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(adv_tree, hf_openflow_v4_portmod_advertise_other, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(adv_tree, hf_openflow_v4_portmod_advertise_copper, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(adv_tree, hf_openflow_v4_portmod_advertise_fiber, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(adv_tree, hf_openflow_v4_portmod_advertise_autoneg, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(adv_tree, hf_openflow_v4_portmod_advertise_pause, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(adv_tree, hf_openflow_v4_portmod_advertise_pause_asym, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* uint8_t pad3[4]; */
    proto_tree_add_item(tree, hf_openflow_v4_portmod_pad3, tvb, offset, 4, ENC_NA);
    /*offset+=4;*/
}


static void
dissect_openflow_tablemod_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    /* uint8_t table_id; */
    if (tvb_get_guint8(tvb, offset) <= OFPTT_MAX) {
        proto_tree_add_item(tree, hf_openflow_v4_tablemod_table_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(tree, hf_openflow_v4_tablemod_table_id_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
    offset+=1;

    /* uint8_t pad[3]; */
    proto_tree_add_item(tree, hf_openflow_v4_tablemod_pad, tvb, offset, 3, ENC_NA);
    offset+=3;

    /* uint32_t config; */
    proto_tree_add_item(tree, hf_openflow_v4_tablemod_config, tvb, offset, 4, ENC_NA);
    /*offset+=4;*/
}


static void
dissect_openflow_flow_stats_request_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length)
{

    /* uint8_t table_id; */
    if (tvb_get_guint8(tvb, offset) <= OFPTT_MAX) {
        proto_tree_add_item(tree, hf_openflow_v4_flow_stats_request_table_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(tree, hf_openflow_v4_flow_stats_request_table_id_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
    offset+=1;

    /* uint8_t pad[3]; */
    proto_tree_add_item(tree, hf_openflow_v4_flow_stats_request_pad, tvb, offset, 3, ENC_NA);
    offset+=3;

    /* uint32_t out_port; */
    if (tvb_get_ntohl(tvb, offset) <= OFPP_MAX) {
        proto_tree_add_item(tree, hf_openflow_v4_flow_stats_request_out_port, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(tree, hf_openflow_v4_flow_stats_request_out_port_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* uint32_t out_group; */
    if (tvb_get_ntohl(tvb, offset) <= OFPG_MAX) {
        proto_tree_add_item(tree, hf_openflow_v4_flow_stats_request_out_group, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(tree, hf_openflow_v4_flow_stats_request_out_group_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* uint8_t pad2[4]; */
    proto_tree_add_item(tree, hf_openflow_v4_flow_stats_request_pad2, tvb, offset, 4, ENC_NA);
    offset+=4;

    /* uint64_t cookie; */
    proto_tree_add_item(tree, hf_openflow_v4_flow_stats_request_cookie, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* uint64_t cookie_mask; */
    proto_tree_add_item(tree, hf_openflow_v4_flow_stats_request_cookie_mask, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* struct ofp_match match; */
    dissect_openflow_match_v4(tvb, pinfo, tree, offset, length);
}

static void
dissect_openflow_aggregate_stats_request_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length)
{
    /* uint8_t table_id; */
    if (tvb_get_guint8(tvb, offset) <= OFPTT_MAX) {
        proto_tree_add_item(tree, hf_openflow_v4_aggregate_stats_request_table_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(tree, hf_openflow_v4_aggregate_stats_request_table_id_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
    offset+=1;

    /* uint8_t pad[3]; */
    proto_tree_add_item(tree, hf_openflow_v4_aggregate_stats_request_pad, tvb, offset, 3, ENC_NA);
    offset+=3;

    /* uint32_t out_port; */
    if (tvb_get_ntohl(tvb, offset) <= OFPP_MAX) {
        proto_tree_add_item(tree, hf_openflow_v4_aggregate_stats_request_out_port, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(tree, hf_openflow_v4_aggregate_stats_request_out_port_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* uint32_t out_group; */
    if (tvb_get_ntohl(tvb, offset) <= OFPG_MAX) {
        proto_tree_add_item(tree, hf_openflow_v4_aggregate_stats_request_out_group, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(tree, hf_openflow_v4_aggregate_stats_request_out_group_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* uint8_t pad2[4]; */
    proto_tree_add_item(tree, hf_openflow_v4_aggregate_stats_request_pad2, tvb, offset, 4, ENC_NA);
    offset+=4;

    /* uint64_t cookie; */
    proto_tree_add_item(tree, hf_openflow_v4_aggregate_stats_request_cookie, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* uint64_t cookie_mask; */
    proto_tree_add_item(tree, hf_openflow_v4_aggregate_stats_request_cookie_mask, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* struct ofp_match match; */
    dissect_openflow_match_v4(tvb, pinfo, tree, offset, length);
}


#define OFPTFPT_INSTRUCTIONS          0
#define OFPTFPT_INSTRUCTIONS_MISS     1
#define OFPTFPT_NEXT_TABLES           2
#define OFPTFPT_NEXT_TABLES_MISS      3
#define OFPTFPT_WRITE_ACTIONS         4
#define OFPTFPT_WRITE_ACTIONS_MISS    5
#define OFPTFPT_APPLY_ACTIONS         6
#define OFPTFPT_APPLY_ACTIONS_MISS    7
#define OFPTFPT_MATCH                 8
#define OFPTFPT_WILDCARDS            10
#define OFPTFPT_WRITE_SETFIELD       12
#define OFPTFPT_WRITE_SETFIELD_MISS  13
#define OFPTFPT_APPLY_SETFIELD       14
#define OFPTFPT_APPLY_SETFIELD_MISS  15
#define OFPTFPT_EXPERIMENTER         0xFFFE
#define OFPTFPT_EXPERIMENTER_MISS    0xFFFF
static const value_string openflow_v4_table_feature_prop_type_values[] = {
    { OFPTFPT_INSTRUCTIONS,        "OFPTFPT_INSTRUCTIONS" },
    { OFPTFPT_INSTRUCTIONS_MISS,   "OFPTFPT_INSTRUCTIONS_MISS" },
    { OFPTFPT_NEXT_TABLES,         "OFPTFPT_NEXT_TABLES" },
    { OFPTFPT_NEXT_TABLES_MISS,    "OFPTFPT_NEXT_TABLES_MISS" },
    { OFPTFPT_WRITE_ACTIONS,       "OFPTFPT_WRITE_ACTIONS" },
    { OFPTFPT_WRITE_ACTIONS_MISS,  "OFPTFPT_WRITE_ACTIONS_MISS" },
    { OFPTFPT_APPLY_ACTIONS,       "OFPTFPT_APPLY_ACTIONS" },
    { OFPTFPT_APPLY_ACTIONS_MISS,  "OFPTFPT_APPLY_ACTIONS_MISS" },
    { OFPTFPT_MATCH,               "OFPTFPT_MATCH" },
    { OFPTFPT_WILDCARDS,           "OFPTFPT_WILDCARDS" },
    { OFPTFPT_WRITE_SETFIELD,      "OFPTFPT_WRITE_SETFIELD" },
    { OFPTFPT_WRITE_SETFIELD_MISS, "OFPTFPT_WRITE_SETFIELD_MISS" },
    { OFPTFPT_APPLY_SETFIELD,      "OFPTFPT_APPLY_SETFIELD" },
    { OFPTFPT_APPLY_SETFIELD_MISS, "OFPTFPT_APPLY_SETFIELD_MISS" },
    { OFPTFPT_EXPERIMENTER,        "OFPTFPT_EXPERIMENTER" },
    { OFPTFPT_EXPERIMENTER_MISS,   "OFPTFPT_EXPERIMENTER_MISS" },
    { 0,                           NULL }
};


static int
dissect_openflow_table_feature_prop_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length)
{
    proto_item *ti;
    proto_tree *prop_tree, *elem_tree;
    guint16 prop_type;
    guint16 prop_length;
    guint16 elem_begin;
    gint32 body_end;
    guint16 pad_length;

    prop_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_openflow_v4_table_feature_prop, &ti, "Table feature property");

    /* uint16_t type; */
    prop_type = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(prop_tree, hf_openflow_v4_table_feature_prop_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint16_t length; */
    prop_length = tvb_get_ntohs(tvb, offset);
    proto_item_set_len(ti, prop_length);
    proto_tree_add_item(prop_tree, hf_openflow_v4_table_feature_prop_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    if (prop_length < 4)
        return offset;

    body_end = offset + prop_length - 4;

    /* body */
    switch (prop_type) {
    case OFPTFPT_INSTRUCTIONS:
    case OFPTFPT_INSTRUCTIONS_MISS:
        while (offset < body_end) {
            elem_begin = offset;
            elem_tree = proto_tree_add_subtree(prop_tree, tvb, offset, -1,
                        ett_openflow_v4_table_feature_prop_instruction_id, &ti, "Instruction ID");

            offset = dissect_openflow_instruction_header_v4(tvb, pinfo, elem_tree, offset, length);
            proto_item_set_len(ti, offset - elem_begin);
        }
        break;

    case OFPTFPT_NEXT_TABLES:
    case OFPTFPT_NEXT_TABLES_MISS:
        while (offset < body_end) {
            proto_tree_add_item(prop_tree, hf_openflow_v4_table_feature_prop_next_tables_next_table_id, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset+=1;
        }
        break;

    case OFPTFPT_WRITE_ACTIONS:
    case OFPTFPT_WRITE_ACTIONS_MISS:
    case OFPTFPT_APPLY_ACTIONS:
    case OFPTFPT_APPLY_ACTIONS_MISS:
        while (offset < body_end) {
            elem_begin = offset;
            elem_tree = proto_tree_add_subtree(prop_tree, tvb, offset, -1, ett_openflow_v4_table_feature_prop_action_id, &ti, "Action ID");

            offset = dissect_openflow_action_header_v4(tvb, pinfo, elem_tree, offset, length);
            proto_item_set_len(ti, offset - elem_begin);
        }
        break;

    case OFPTFPT_MATCH:
    case OFPTFPT_WILDCARDS:
    case OFPTFPT_WRITE_SETFIELD:
    case OFPTFPT_WRITE_SETFIELD_MISS:
    case OFPTFPT_APPLY_SETFIELD:
    case OFPTFPT_APPLY_SETFIELD_MISS:
        while (offset < body_end) {
            elem_begin = offset;
            elem_tree = proto_tree_add_subtree(prop_tree, tvb, offset, -1, ett_openflow_v4_table_feature_prop_oxm_id, &ti, "OXM ID");

            offset = dissect_openflow_oxm_header_v4(tvb, pinfo, elem_tree, offset, length);
            proto_item_set_len(ti, offset - elem_begin);
        }
        break;

    case OFPTFPT_EXPERIMENTER:
    case OFPTFPT_EXPERIMENTER_MISS:
        /* uint32_t experimenter; */
        proto_tree_add_item(prop_tree, hf_openflow_v4_table_feature_prop_experimenter_experimenter, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;

        /* uint32_t exp_type; */
        proto_tree_add_item(prop_tree, hf_openflow_v4_table_feature_prop_experimenter_exp_type, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;

        /* uint32_t experimenter_data[0]; */
        proto_tree_add_expert_format(prop_tree, pinfo, &ei_openflow_v4_table_feature_prop_undecoded,
                                     tvb, offset, body_end - offset, "Experimenter table property body.");
        offset = body_end;
        break;

    default:
        proto_tree_add_expert_format(prop_tree, pinfo, &ei_openflow_v4_table_feature_prop_undecoded,
                                     tvb, offset, body_end - offset, "Unknown table property body.");
        offset = body_end;
        break;
    };

    pad_length = (prop_length + 7)/8*8 - prop_length;
    if (pad_length > 0) {
        proto_tree_add_item(prop_tree, hf_openflow_v4_table_feature_prop_pad, tvb, offset, pad_length, ENC_NA);
        offset+=pad_length;
    }

    return offset;
}


#define OFP_MAX_TABLE_NAME_LEN  32
static int
dissect_openflow_table_features_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length)
{
    proto_item *ti;
    proto_tree *feat_tree;
    guint16 feat_length;
    gint32 feat_end;

    feat_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_openflow_v4_table_features, &ti, "Table features");

    /* uint16_t length; */
    feat_length = tvb_get_ntohs(tvb, offset);
    feat_end = offset + feat_length;
    proto_item_set_len(ti, feat_length);
    proto_tree_add_item(feat_tree, hf_openflow_v4_table_features_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint8_t table_id; */
    proto_tree_add_item(feat_tree, hf_openflow_v4_table_features_table_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset+=1;

    /* uint8_t pad[5]; */
    proto_tree_add_item(feat_tree, hf_openflow_v4_table_features_pad, tvb, offset, 5, ENC_NA);
    offset+=5;

    /* char name[OFP_MAX_TABLE_NAME_LEN]; */
    proto_tree_add_item(feat_tree, hf_openflow_v4_table_features_name, tvb, offset, OFP_MAX_TABLE_NAME_LEN, ENC_ASCII|ENC_NA);
    offset+=OFP_MAX_TABLE_NAME_LEN;

    /* uint64_t metadata_match; */
    proto_tree_add_item(feat_tree, hf_openflow_v4_table_features_metadata_match, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* uint64_t metadata_write; */
    proto_tree_add_item(feat_tree, hf_openflow_v4_table_features_metadata_write, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* uint32_t config; */
    proto_tree_add_item(feat_tree, hf_openflow_v4_table_features_config, tvb, offset, 4, ENC_NA);
    offset+=4;

    /* uint32_t max_entries; */
    proto_tree_add_item(feat_tree, hf_openflow_v4_table_features_max_entries, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* struct ofp_table_feature_prop_header properties[0]; */
    while (offset < feat_end) {
        offset = dissect_openflow_table_feature_prop_v4(tvb, pinfo, feat_tree, offset, length);
    }

    return offset;
}


static void
dissect_openflow_port_stats_request_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    /* uint32_t port_no; */
    if (tvb_get_ntohl(tvb, offset) <= OFPP_MAX) {
        proto_tree_add_item(tree, hf_openflow_v4_port_stats_request_port_no, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(tree, hf_openflow_v4_port_stats_request_port_no_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* uint8_t pad[4]; */
    proto_tree_add_item(tree, hf_openflow_v4_port_stats_request_pad, tvb, offset, 4, ENC_NA);
    /*offset+=4;*/
}

#define OFPQ_ALL  0xffffffff
static const value_string openflow_v4_queue_reserved_values[] = {
    { OFPQ_ALL, "OFPQ_ALL" },
    { 0,        NULL }
};

static void
dissect_openflow_queue_stats_request_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    /* uint32_t port_no; */
    if (tvb_get_ntohl(tvb, offset) <= OFPP_MAX) {
        proto_tree_add_item(tree, hf_openflow_v4_queue_stats_request_port_no, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(tree, hf_openflow_v4_queue_stats_request_port_no_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* uint32_t queue_id; */
    if (tvb_get_ntohl(tvb, offset) != OFPQ_ALL) {
        proto_tree_add_item(tree, hf_openflow_v4_queue_stats_request_queue_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(tree, hf_openflow_v4_queue_stats_request_queue_id_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    /*offset+=4;*/
}


static void
dissect_openflow_group_stats_request_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    /* uint32_t group_id; */
    if (tvb_get_ntohl(tvb, offset) <= OFPG_MAX) {
        proto_tree_add_item(tree, hf_openflow_v4_group_stats_request_group_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(tree, hf_openflow_v4_group_stats_request_group_id_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* uint8_t pad[4]; */
    proto_tree_add_item(tree, hf_openflow_v4_group_stats_request_pad, tvb, offset, 4, ENC_NA);
    /*offset+=4;*/
}


static void
dissect_openflow_meter_stats_request_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    /* uint32_t meter_id; */
    if (tvb_get_ntohl(tvb, offset) <= OFPM_MAX) {
        proto_tree_add_item(tree, hf_openflow_v4_meter_stats_request_meter_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(tree, hf_openflow_v4_meter_stats_request_meter_id_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* uint8_t pad[4]; */
    proto_tree_add_item(tree, hf_openflow_v4_meter_stats_request_pad, tvb, offset, 4, ENC_NA);
    /*offset+=4;*/
}


static void
dissect_openflow_meter_config_request_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    /* uint32_t meter_id; */
    if (tvb_get_ntohl(tvb, offset) <= OFPM_MAX) {
        proto_tree_add_item(tree, hf_openflow_v4_meter_config_request_meter_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(tree, hf_openflow_v4_meter_config_request_meter_id_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* uint8_t pad[4]; */
    proto_tree_add_item(tree, hf_openflow_v4_meter_config_request_pad, tvb, offset, 4, ENC_NA);
    /*offset+=4;*/
}


#define OFPMP_DESC             0
#define OFPMP_FLOW             1
#define OFPMP_AGGREGATE        2
#define OFPMP_TABLE            3
#define OFPMP_PORT_STATS       4
#define OFPMP_QUEUE            5
#define OFPMP_GROUP            6
#define OFPMP_GROUP_DESC       7
#define OFPMP_GROUP_FEATURES   8
#define OFPMP_METER            9
#define OFPMP_METER_CONFIG    10
#define OFPMP_METER_FEATURES  11
#define OFPMP_TABLE_FEATURES  12
#define OFPMP_PORT_DESC       13
#define OFPMP_EXPERIMENTER    0xffff
static const value_string openflow_v4_multipart_type_values[] = {
    { OFPMP_DESC,           "OFPMP_DESC" },
    { OFPMP_FLOW,           "OFPMP_FLOW" },
    { OFPMP_AGGREGATE,      "OFPMP_AGGREGATE" },
    { OFPMP_TABLE,          "OFPMP_TABLE" },
    { OFPMP_PORT_STATS,     "OFPMP_PORT_STATS" },
    { OFPMP_QUEUE,          "OFPMP_QUEUE" },
    { OFPMP_GROUP,          "OFPMP_GROUP" },
    { OFPMP_GROUP_DESC,     "OFPMP_GROUP_DESC" },
    { OFPMP_GROUP_FEATURES, "OFPMP_GROUP_FEATURES" },
    { OFPMP_METER,          "OFPMP_METER" },
    { OFPMP_METER_CONFIG,   "OFPMP_METER_CONFIG" },
    { OFPMP_METER_FEATURES, "OFPMP_METER_FEATURES" },
    { OFPMP_TABLE_FEATURES, "OFPMP_TABLE_FEATURES" },
    { OFPMP_PORT_DESC,      "OFPMP_PORT_DESC" },
    { OFPMP_EXPERIMENTER,   "OFPMP_EXPERIMENTER" },
    { 0, NULL }
};

#define OFPMPF_REQ_MORE  1 << 0
static void
dissect_openflow_multipart_request_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length)
{
    proto_item *ti;
    proto_tree *flags_tree;
    guint16 type;

    /* uint16_t type; */
    type = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_openflow_v4_multipart_request_type , tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
                  val_to_str_const(type, openflow_v4_multipart_type_values, "Unknown type"));

    /* uint16_t flags; */
    ti = proto_tree_add_item(tree, hf_openflow_v4_multipart_request_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
    flags_tree = proto_item_add_subtree(ti, ett_openflow_v4_multipart_request_flags);

    proto_tree_add_item(flags_tree, hf_openflow_v4_multipart_request_flags_more, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint8_t pad[4]; */
    proto_tree_add_item(tree, hf_openflow_v4_multipart_request_pad, tvb, offset, 4, ENC_NA);
    offset+=4;

    /* uint8_t body[0]; */
    switch(type){
    case OFPMP_DESC:
        /* The request body is empty. */
        break;
    case OFPMP_FLOW:
        dissect_openflow_flow_stats_request_v4(tvb, pinfo, tree, offset, length);
        break;
    case OFPMP_AGGREGATE:
        dissect_openflow_aggregate_stats_request_v4(tvb, pinfo, tree, offset, length);
        break;
    case OFPMP_TABLE:
         /* The request body is empty. */
        break;
    case OFPMP_PORT_STATS:
        dissect_openflow_port_stats_request_v4(tvb, pinfo, tree, offset, length);
        break;
    case OFPMP_QUEUE:
        dissect_openflow_queue_stats_request_v4(tvb, pinfo, tree, offset, length);
        break;
    case OFPMP_GROUP:
        dissect_openflow_group_stats_request_v4(tvb, pinfo, tree, offset, length);
        break;
    case OFPMP_GROUP_DESC:
        /* The request body is empty. */
        break;
    case OFPMP_GROUP_FEATURES:
        /* The request body is empty. */
        break;
    case OFPMP_METER:
        dissect_openflow_meter_stats_request_v4(tvb, pinfo, tree, offset, length);
        break;
    case OFPMP_METER_CONFIG:
        dissect_openflow_meter_config_request_v4(tvb, pinfo, tree, offset, length);
        break;
    case OFPMP_METER_FEATURES:
        /* The request body is empty. */
        break;
    case OFPMP_TABLE_FEATURES:
        while (offset < length) {
            offset = dissect_openflow_table_features_v4(tvb, pinfo, tree, offset, length);
        }
        break;
    case OFPMP_PORT_DESC:
        /* The request body is empty. */
        break;
    case OFPMP_EXPERIMENTER:
        /* uint32_t experimenter; */
        proto_tree_add_item(tree, hf_openflow_v4_multipart_request_experimenter_experimenter, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;

        /* uint32_t exp_type; */
        proto_tree_add_item(tree, hf_openflow_v4_multipart_request_experimenter_exp_type, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;

        /* uint32_t experimenter_data[0]; */
        if (offset < length) {
            proto_tree_add_expert_format(tree, pinfo, &ei_openflow_v4_multipart_request_undecoded,
                                         tvb, offset, length - offset, "Experimenter multipart request body.");
        }
        break;
    default:
        proto_tree_add_expert_format(tree, pinfo, &ei_openflow_v4_multipart_request_undecoded,
                                     tvb, offset, length - offset, "Unknown multipart request body.");
        break;
    }
}


#define DESC_STR_LEN    256
#define SERIAL_NUM_LEN  32
static void
dissect_openflow_switch_description_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    /* char mfr_desc[DESC_STR_LEN]; */
    proto_tree_add_item(tree, hf_openflow_v4_switch_description_mfr_desc, tvb, offset, DESC_STR_LEN, ENC_ASCII|ENC_NA);
    offset+=DESC_STR_LEN;

    /* char hw_desc[DESC_STR_LEN]; */
    proto_tree_add_item(tree, hf_openflow_v4_switch_description_hw_desc, tvb, offset, DESC_STR_LEN, ENC_ASCII|ENC_NA);
    offset+=DESC_STR_LEN;

    /* char sw_desc[DESC_STR_LEN]; */
    proto_tree_add_item(tree, hf_openflow_v4_switch_description_sw_desc, tvb, offset, DESC_STR_LEN, ENC_ASCII|ENC_NA);
    offset+=DESC_STR_LEN;

    /* char serial_num[SERIAL_NUM_LEN]; */
    proto_tree_add_item(tree, hf_openflow_v4_switch_description_serial_num, tvb, offset, SERIAL_NUM_LEN, ENC_ASCII|ENC_NA);
    offset+=SERIAL_NUM_LEN;

    /* char dp_desc[DESC_STR_LEN]; */
    proto_tree_add_item(tree, hf_openflow_v4_switch_description_dp_desc, tvb, offset, DESC_STR_LEN, ENC_ASCII|ENC_NA);
    /*offset+=DESC_STR_LEN;*/
}


static int
dissect_openflow_flow_stats_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    proto_item *ti;
    proto_tree *stats_tree, *flags_tree;
    guint16 stats_len;
    gint32 stats_end;

    stats_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_openflow_v4_flow_stats, &ti, "Flow stats");

    /* uint16_t length; */
    stats_len = tvb_get_ntohs(tvb, offset);
    stats_end = offset + stats_len;
    proto_item_set_len(ti, stats_len);
    proto_tree_add_item(stats_tree, hf_openflow_v4_flow_stats_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint8_t table_id; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_flow_stats_table_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset+=1;

    /* uint8_t pad; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_flow_stats_pad, tvb, offset, 1, ENC_NA);
    offset+=1;

    /* uint32_t duration_sec; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_flow_stats_duration_sec, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* uint32_t duration_nsec; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_flow_stats_duration_nsec, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* uint16_t priority; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_flow_stats_priority, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint16_t idle_timeout; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_flow_stats_idle_timeout, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint16_t hard_timeout; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_flow_stats_hard_timeout, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint16_t flags; */
    ti = proto_tree_add_item(stats_tree, hf_openflow_v4_flow_stats_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
    flags_tree = proto_item_add_subtree(ti, ett_openflow_v4_flow_stats_flags);

    proto_tree_add_item(flags_tree, hf_openflow_v4_flow_stats_flags_send_flow_rem, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_openflow_v4_flow_stats_flags_check_overlap, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_openflow_v4_flow_stats_flags_reset_counts,  tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_openflow_v4_flow_stats_flags_no_packet_counts, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_openflow_v4_flow_stats_flags_no_byte_counts, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint8_t pad2[4]; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_flow_stats_pad2, tvb, offset, 4, ENC_NA);
    offset+=4;

    /* uint64_t cookie; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_flow_stats_cookie, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* uint64_t packet_count; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_flow_stats_packet_count, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* uint64_t byte_count; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_flow_stats_byte_count, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* struct ofp_match match; */
    offset = dissect_openflow_match_v4(tvb, pinfo, stats_tree, offset, length);

    /* struct ofp_instruction instructions[0]; */
    while (offset < stats_end) {
        offset = dissect_openflow_instruction_v4(tvb, pinfo, stats_tree, offset, length);
    }

    return offset;
}


static void
dissect_openflow_aggregate_stats_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    /* uint64_t packet_count; */
    proto_tree_add_item(tree, hf_openflow_v4_aggregate_stats_packet_count, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* uint64_t byte_count; */
    proto_tree_add_item(tree, hf_openflow_v4_aggregate_stats_byte_count, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* uint32_t flow_count; */
    proto_tree_add_item(tree, hf_openflow_v4_aggregate_stats_flow_count, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* uint8_t pad[4]; */
    proto_tree_add_item(tree, hf_openflow_v4_aggregate_stats_pad, tvb, offset, 4, ENC_NA);
    /*offset+=4;*/
}


static int
dissect_openflow_table_stats_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    proto_tree *stats_tree;

    stats_tree = proto_tree_add_subtree(tree, tvb, offset, 24, ett_openflow_v4_table_stats, NULL, "Table stats");

    /* uint8_t table_id; */
    if (tvb_get_guint8(tvb, offset) <= OFPTT_MAX) {
        proto_tree_add_item(stats_tree, hf_openflow_v4_table_stats_table_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(stats_tree, hf_openflow_v4_table_stats_table_id_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
    offset+=1;

    /* uint8_t pad[3]; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_table_stats_pad, tvb, offset, 3, ENC_NA);
    offset+=3;

    /* uint32_t active_count; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_table_stats_active_count, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* uint64_t lookup_count; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_table_stats_lookup_count, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* uint64_t matched_count; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_table_stats_match_count, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    return offset;
}


static int
dissect_openflow_port_stats_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    proto_tree *stats_tree;

    stats_tree = proto_tree_add_subtree(tree, tvb, offset, 112, ett_openflow_v4_port_stats, NULL, "Port stats");

    /* uint8_t port_no; */
    if (tvb_get_ntohl(tvb, offset) <= OFPP_MAX) {
        proto_tree_add_item(stats_tree, hf_openflow_v4_port_stats_port_no, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(stats_tree, hf_openflow_v4_port_stats_port_no_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* uint8_t pad[4]; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_port_stats_pad, tvb, offset, 4, ENC_NA);
    offset+=4;

    /* uint64_t rx_packets; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_port_stats_rx_packets, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* uint64_t tx_packets; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_port_stats_tx_packets, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* uint64_t rx_bytes; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_port_stats_rx_bytes, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* uint64_t tx_bytes; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_port_stats_tx_bytes, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* uint64_t rx_dropped; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_port_stats_rx_dropped, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* uint64_t tx_dropped; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_port_stats_tx_dropped, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* uint64_t rx_errors; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_port_stats_rx_errors, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* uint64_t tx_errors; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_port_stats_tx_errors, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* uint64_t rx_frame_error; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_port_stats_rx_frame_error, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* uint64_t rx_over_error; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_port_stats_rx_over_error, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* uint64_t rx_crc_error; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_port_stats_rx_crc_error, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* uint64_t collisions; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_port_stats_collisions, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* uint32_t duration_sec; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_port_stats_duration_sec, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* uint32_t duration_nsec; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_port_stats_duration_nsec, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    return offset;
}


static int
dissect_openflow_queue_stats_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    proto_tree *stats_tree;

    stats_tree = proto_tree_add_subtree(tree, tvb, offset, 40, ett_openflow_v4_queue_stats, NULL, "Queue stats");

    /* uint32_t port_no; */
    if (tvb_get_ntohl(tvb, offset) <= OFPP_MAX) {
        proto_tree_add_item(stats_tree, hf_openflow_v4_queue_stats_port_no, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(stats_tree, hf_openflow_v4_queue_stats_port_no_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* uint32_t queue_id; */
    if (tvb_get_ntohl(tvb, offset) != OFPQ_ALL) {
        proto_tree_add_item(stats_tree, hf_openflow_v4_queue_stats_queue_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(stats_tree, hf_openflow_v4_queue_stats_queue_id_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* uint64_t tx_bytes; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_queue_stats_tx_bytes, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* uint64_t tx_packets; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_queue_stats_tx_packets, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* uint64_t tx_errors; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_queue_stats_tx_errors, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* uint32_t duration_sec; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_queue_stats_duration_sec, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* uint32_t duration_nsec; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_queue_stats_duration_nsec, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    return offset;
}


static int
dissect_openflow_bucket_counter_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    proto_tree *counter_tree;

    counter_tree = proto_tree_add_subtree(tree, tvb, offset, 16, ett_openflow_v4_bucket_counter, NULL, "Bucket counter");

    /* uint64_t packet_count; */
    proto_tree_add_item(counter_tree, hf_openflow_v4_bucket_counter_packet_count, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* uint64_t byte_count; */
    proto_tree_add_item(counter_tree, hf_openflow_v4_bucket_counter_byte_count, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    return offset;
}


static int
dissect_openflow_group_stats_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    proto_item *ti;
    proto_tree *stats_tree;
    guint16 stats_len;
    gint32 stats_end;

    stats_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_openflow_v4_group_stats, &ti, "Group stats");

    /* uint16_t length; */
    stats_len = tvb_get_ntohs(tvb, offset);
    stats_end = offset + stats_len;
    proto_item_set_len(ti, stats_len);
    proto_tree_add_item(stats_tree, hf_openflow_v4_group_stats_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint8_t pad[2]; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_group_stats_pad, tvb, offset, 2, ENC_NA);
    offset+=2;

    /* uint32_t group_id; */
    if (tvb_get_ntohl(tvb, offset) <= OFPG_MAX) {
        proto_tree_add_item(stats_tree, hf_openflow_v4_group_stats_group_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(stats_tree, hf_openflow_v4_group_stats_group_id_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* uint32_t ref_count; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_group_stats_ref_count, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* uint8_t pad2[4]; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_group_stats_pad2, tvb, offset, 4, ENC_NA);
    offset+=4;

    /* uint64_t packet_count; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_group_stats_packet_count, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* uint64_t byte_count; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_group_stats_byte_count, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* uint32_t duration_sec; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_flow_stats_duration_sec, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* uint32_t duration_nsec; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_flow_stats_duration_nsec, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* struct ofp_bucket_counter bucket_stats[0]; */
    while (offset < stats_end) {
        offset = dissect_openflow_bucket_counter_v4(tvb, pinfo, stats_tree, offset, length);
    }

    return offset;
}

static int
dissect_openflow_group_desc_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length)
{
    proto_item *ti;
    proto_tree *desc_tree;

    guint16 desc_len;
    gint32 desc_end;

    desc_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_openflow_v4_group_desc, &ti, "Group description");

    /* uint16_t length; */
    desc_len = tvb_get_ntohs(tvb, offset);
    desc_end = offset + desc_len;
    proto_item_set_len(ti, desc_len);
    proto_tree_add_item(desc_tree, hf_openflow_v4_group_desc_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint8_t type; */
    proto_tree_add_item(desc_tree, hf_openflow_v4_group_desc_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset+=1;

    /* uint8_t pad; */
    proto_tree_add_item(desc_tree, hf_openflow_v4_group_desc_pad, tvb, offset, 1, ENC_NA);
    offset+=1;

    /* uint32_t group_id; */
    if (tvb_get_ntohl(tvb, offset) <= OFPG_MAX) {
        proto_tree_add_item(desc_tree, hf_openflow_v4_group_desc_group_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(desc_tree, hf_openflow_v4_group_desc_group_id_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* struct ofp_bucket buckets[0]; */
    while (offset < desc_end) {
        offset = dissect_openflow_bucket_v4(tvb, pinfo, desc_tree, offset, length);
    }

    return offset;
}


#define OFPGFC_SELECT_WEIGHT    1 << 0
#define OFPGFC_SELECT_LIVENESS  1 << 1
#define OFPGFC_CHAINING         1 << 2
#define OFPGFC_CHAINING_CHECKS  1 << 3
static void
dissect_openflow_group_features_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    proto_item *ti;
    proto_tree *types_tree, *caps_tree, *acts_tree;

    /* uint32_t types; */
    ti = proto_tree_add_item(tree, hf_openflow_v4_group_features_types, tvb, offset, 4, ENC_BIG_ENDIAN);
    types_tree = proto_item_add_subtree(ti, ett_openflow_v4_group_features_types);

    proto_tree_add_item(types_tree, hf_openflow_v4_group_features_types_all, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(types_tree, hf_openflow_v4_group_features_types_select, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(types_tree, hf_openflow_v4_group_features_types_indirect, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(types_tree, hf_openflow_v4_group_features_types_ff, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* uint32_t capabilities; */
    ti = proto_tree_add_item(tree, hf_openflow_v4_group_features_capabilities, tvb, offset, 4, ENC_BIG_ENDIAN);
    caps_tree = proto_item_add_subtree(ti, ett_openflow_v4_group_features_capabilities);

    proto_tree_add_item(caps_tree, hf_openflow_v4_group_features_capabilities_select_weight, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(caps_tree, hf_openflow_v4_group_features_capabilities_select_liveness, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(caps_tree, hf_openflow_v4_group_features_capabilities_chaining, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(caps_tree, hf_openflow_v4_group_features_capabilities_chaining_checks, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* max_groups[4]; */
    proto_tree_add_item(tree, hf_openflow_v4_group_features_max_groups_all, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;
    proto_tree_add_item(tree, hf_openflow_v4_group_features_max_groups_select, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;
    proto_tree_add_item(tree, hf_openflow_v4_group_features_max_groups_indirect, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;
    proto_tree_add_item(tree, hf_openflow_v4_group_features_max_groups_ff, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* uint32_t actions[4]; */
    ti = proto_tree_add_item(tree, hf_openflow_v4_group_features_actions_all, tvb, offset, 4, ENC_BIG_ENDIAN);
    acts_tree = proto_item_add_subtree(ti, ett_openflow_v4_group_features_actions_all);

    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_all_output, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_all_copy_ttl_out, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_all_copy_ttl_in, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_all_set_mpls_ttl, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_all_dec_mpls_ttl, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_all_push_vlan, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_all_pop_vlan, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_all_push_mpls, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_all_pop_mpls, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_all_set_queue, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_all_group, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_all_set_nw_ttl, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_all_dec_nw_ttl, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_all_set_field, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_all_push_pbb, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_all_pop_pbb, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    ti = proto_tree_add_item(tree, hf_openflow_v4_group_features_actions_select, tvb, offset, 4, ENC_BIG_ENDIAN);
    acts_tree = proto_item_add_subtree(ti, ett_openflow_v4_group_features_actions_select);

    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_select_output, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_select_copy_ttl_out, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_select_copy_ttl_in, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_select_set_mpls_ttl, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_select_dec_mpls_ttl, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_select_push_vlan, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_select_pop_vlan, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_select_push_mpls, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_select_pop_mpls, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_select_set_queue, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_select_group, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_select_set_nw_ttl, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_select_dec_nw_ttl, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_select_set_field, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_select_push_pbb, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_select_pop_pbb, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    ti = proto_tree_add_item(tree, hf_openflow_v4_group_features_actions_indirect, tvb, offset, 4, ENC_BIG_ENDIAN);
    acts_tree = proto_item_add_subtree(ti, ett_openflow_v4_group_features_actions_indirect);

    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_indirect_output, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_indirect_copy_ttl_out, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_indirect_copy_ttl_in, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_indirect_set_mpls_ttl, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_indirect_dec_mpls_ttl, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_indirect_push_vlan, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_indirect_pop_vlan, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_indirect_push_mpls, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_indirect_pop_mpls, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_indirect_set_queue, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_indirect_group, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_indirect_set_nw_ttl, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_indirect_dec_nw_ttl, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_indirect_set_field, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_indirect_push_pbb, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_indirect_pop_pbb, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    ti = proto_tree_add_item(tree, hf_openflow_v4_group_features_actions_ff, tvb, offset, 4, ENC_BIG_ENDIAN);
    acts_tree = proto_item_add_subtree(ti, ett_openflow_v4_group_features_actions_ff);

    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_ff_output, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_ff_copy_ttl_out, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_ff_copy_ttl_in, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_ff_set_mpls_ttl, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_ff_dec_mpls_ttl, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_ff_push_vlan, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_ff_pop_vlan, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_ff_push_mpls, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_ff_pop_mpls, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_ff_set_queue, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_ff_group, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_ff_set_nw_ttl, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_ff_dec_nw_ttl, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_ff_set_field, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_ff_push_pbb, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(acts_tree, hf_openflow_v4_group_features_actions_ff_pop_pbb, tvb, offset, 4, ENC_BIG_ENDIAN);
    /*offset+=4;*/
}


static int
dissect_openflow_meter_band_stats_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    proto_tree *stats_tree;

    stats_tree = proto_tree_add_subtree(tree, tvb, offset, 16, ett_openflow_v4_meter_band_stats, NULL, "Meter band stats");

    /* uint64_t packet_band_count; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_meter_band_stats_packet_band_count, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* uint64_t byte_band_count; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_meter_band_stats_byte_band_count, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    return offset;
}


static int
dissect_openflow_meter_stats_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    proto_item *ti;
    proto_tree *stats_tree;
    guint16 stats_len;
    guint16 stats_end;

    stats_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_openflow_v4_meter_stats, &ti, "Meter stats");

    /* uint32_t meter_id; */
    if (tvb_get_ntohl(tvb, offset) <= OFPM_MAX) {
        proto_tree_add_item(stats_tree, hf_openflow_v4_meter_stats_meter_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(stats_tree, hf_openflow_v4_meter_stats_meter_id_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* uint16_t len; */
    stats_len = tvb_get_ntohs(tvb, offset);
    stats_end = offset - 4 + stats_len;
    proto_item_set_len(ti, stats_len);
    proto_tree_add_item(stats_tree, hf_openflow_v4_meter_stats_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint8_t pad[6]; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_meter_stats_pad, tvb, offset, 6, ENC_NA);
    offset+=6;

    /* uint32_t flow_count; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_meter_stats_flow_count, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* uint64_t packet_in_count; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_meter_stats_packet_in_count, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* uint64_t byte_in_count; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_meter_stats_byte_in_count, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset+=8;

    /* uint32_t duration_sec; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_meter_stats_duration_sec, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* uint32_t duration_nsec; */
    proto_tree_add_item(stats_tree, hf_openflow_v4_meter_stats_duration_nsec, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* struct ofp_meter_band_stats band_stats[0]; */
    while (offset < stats_end) {
        offset = dissect_openflow_meter_band_stats_v4(tvb, pinfo, stats_tree, offset, length);
    }

    return offset;
}


static int
dissect_openflow_meter_config_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    proto_item *ti;
    proto_tree *conf_tree, *flags_tree;
    guint16 config_len;
    gint32 config_end;

    conf_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_openflow_v4_meter_config, &ti, "Meter config");

    /* uint16_t len; */
    config_len = tvb_get_ntohs(tvb, offset);
    config_end = offset + config_len;
    proto_item_set_len(ti, config_len);
    proto_tree_add_item(conf_tree, hf_openflow_v4_meter_config_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint16_t flags; */
    ti = proto_tree_add_item(conf_tree, hf_openflow_v4_meter_config_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
    flags_tree = proto_item_add_subtree(ti, ett_openflow_v4_meter_config_flags);

    proto_tree_add_item(flags_tree, hf_openflow_v4_meter_config_flags_kbps, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_openflow_v4_meter_config_flags_pktps, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_openflow_v4_meter_config_flags_burst, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_openflow_v4_meter_config_flags_stats, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint32_t meter_id; */
    if (tvb_get_ntohl(tvb, offset) <= OFPM_MAX) {
        proto_tree_add_item(conf_tree, hf_openflow_v4_meter_config_meter_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(conf_tree, hf_openflow_v4_meter_config_meter_id_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* struct ofp_meter_band_header bands[0]; */
    while (offset < config_end) {
        offset = dissect_openflow_meter_band_v4(tvb, pinfo, conf_tree, offset, length);
    }

    return offset;
}


#define OFPMF_KBPS   1 << 0
#define OFPMF_PKTPS  1 << 1
#define OFPMF_BURST  1 << 2
#define OFPMF_STATS  1 << 3
static void
dissect_openflow_meter_features_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    proto_item *ti;
    proto_tree *bands_tree, *caps_tree;

    /* uint32_t max_meter; */
    proto_tree_add_item(tree, hf_openflow_v4_meter_features_max_meter, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* uint32_t band_types; */
    ti = proto_tree_add_item(tree, hf_openflow_v4_meter_features_band_types, tvb, offset, 4, ENC_BIG_ENDIAN);
    bands_tree = proto_item_add_subtree(ti, ett_openflow_v4_meter_features_band_types);

    proto_tree_add_item(bands_tree, hf_openflow_v4_meter_features_band_types_drop, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(bands_tree, hf_openflow_v4_meter_features_band_types_dscp_remark, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* uint32_t capabilities; */
    ti = proto_tree_add_item(tree, hf_openflow_v4_meter_features_capabilities, tvb, offset, 4, ENC_BIG_ENDIAN);
    caps_tree = proto_item_add_subtree(ti, ett_openflow_v4_meter_features_capabilities);

    proto_tree_add_item(caps_tree, hf_openflow_v4_meter_features_capabilities_kbps, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(caps_tree, hf_openflow_v4_meter_features_capabilities_pktps, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(caps_tree, hf_openflow_v4_meter_features_capabilities_burst, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(caps_tree, hf_openflow_v4_meter_features_capabilities_stats, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* uint8_t max_bands; */
    proto_tree_add_item(tree, hf_openflow_v4_meter_features_max_bands, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset+=1;

    /* uint8_t max_color; */
    proto_tree_add_item(tree, hf_openflow_v4_meter_features_max_color, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset+=1;

    /* uint8_t pad[2]; */
    proto_tree_add_item(tree, hf_openflow_v4_meter_features_pad, tvb, offset, 2, ENC_NA);
    /*offset+=2;*/
}


#define OFPMPF_REPLY_MORE  1 << 0
static void
dissect_openflow_multipart_reply_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length)
{
    proto_item *ti;
    proto_tree *flags_tree;
    guint16 type;

    /* uint16_t type; */
    type = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_openflow_v4_multipart_reply_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
                  val_to_str_const(type, openflow_v4_multipart_type_values, "Unknown type"));

    /* uint16_t flags; */
    ti = proto_tree_add_item(tree, hf_openflow_v4_multipart_reply_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
    flags_tree = proto_item_add_subtree(ti, ett_openflow_v4_multipart_reply_flags);

    proto_tree_add_item(flags_tree, hf_openflow_v4_multipart_reply_flags_more, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint8_t pad[4]; */
    proto_tree_add_item(tree, hf_openflow_v4_multipart_reply_pad, tvb, offset, 4, ENC_NA);
    offset+=4;

    switch(type){
    case OFPMP_DESC:
        dissect_openflow_switch_description_v4(tvb, pinfo, tree, offset, length);
        break;
    case OFPMP_FLOW:
        while (offset < length) {
            offset = dissect_openflow_flow_stats_v4(tvb, pinfo, tree, offset, length);
        }
        break;
    case OFPMP_AGGREGATE:
        dissect_openflow_aggregate_stats_v4(tvb, pinfo, tree, offset, length);
        break;
    case OFPMP_TABLE:
        while (offset < length) {
            offset = dissect_openflow_table_stats_v4(tvb, pinfo, tree, offset, length);
        }
        break;
    case OFPMP_PORT_STATS:
        while (offset < length) {
            offset = dissect_openflow_port_stats_v4(tvb, pinfo, tree, offset, length);
        }
        break;
    case OFPMP_QUEUE:
        while (offset < length) {
            offset = dissect_openflow_queue_stats_v4(tvb, pinfo, tree, offset, length);
        }
        break;
    case OFPMP_GROUP:
        while (offset < length) {
            offset = dissect_openflow_group_stats_v4(tvb, pinfo, tree, offset, length);
        }
        break;
    case OFPMP_GROUP_DESC:
        while (offset < length) {
            offset = dissect_openflow_group_desc_v4(tvb, pinfo, tree, offset, length);
        }
        break;
    case OFPMP_GROUP_FEATURES:
        dissect_openflow_group_features_v4(tvb, pinfo, tree, offset, length);
        break;
    case OFPMP_METER:
        while (offset < length) {
            offset = dissect_openflow_meter_stats_v4(tvb, pinfo, tree, offset, length);
        }
        break;
    case OFPMP_METER_CONFIG:
        while (offset < length) {
            offset = dissect_openflow_meter_config_v4(tvb, pinfo, tree, offset, length);
        }
        break;
    case OFPMP_METER_FEATURES:
        dissect_openflow_meter_features_v4(tvb, pinfo, tree, offset, length);
        break;
    case OFPMP_TABLE_FEATURES:
        while (offset < length) {
            offset = dissect_openflow_table_features_v4(tvb, pinfo, tree, offset, length);
        }
        break;
    case OFPMP_PORT_DESC:
        while (offset < length) {
            offset = dissect_openflow_port_v4(tvb, pinfo, tree, offset, length);
        }
        break;

    case OFPMP_EXPERIMENTER:
        /* uint32_t experimenter; */
        proto_tree_add_item(tree, hf_openflow_v4_multipart_reply_experimenter_experimenter, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;

        /* uint32_t exp_type; */
        proto_tree_add_item(tree, hf_openflow_v4_multipart_reply_experimenter_exp_type, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;

        /* uint32_t experimenter_data[0]; */
        proto_tree_add_expert_format(tree, pinfo, &ei_openflow_v4_multipart_reply_undecoded,
                                     tvb, offset, length - 16, "Experimenter multipart reply body.");

        break;
    default:
        proto_tree_add_expert_format(tree, pinfo, &ei_openflow_v4_multipart_reply_undecoded,
                                     tvb, offset, length - 8, "Unknown multipart reply body.");
        break;
    }
}



static void
dissect_openflow_queue_get_config_request_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    /* uint32_t port; */
    if (tvb_get_ntohl(tvb, offset) <= OFPP_MAX) {
        proto_tree_add_item(tree, hf_openflow_v4_queue_get_config_request_port, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(tree, hf_openflow_v4_queue_get_config_request_port_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* uint8_t pad[4]; */
    proto_tree_add_item(tree, hf_openflow_v4_queue_get_config_request_pad, tvb, offset, 4, ENC_NA);
    /*offset+=4;*/
}



#define OFPQ_MIN_RATE_MAX  1000
static const value_string openflow_v4_queue_prop_min_rate_reserved_values[] = {
    { 0xffff, "OFPQ_MIN_RATE_UNCFG" },
    { 0,        NULL }
};

#define OFPQ_MAX_RATE_MAX  1000
static const value_string openflow_v4_queue_prop_max_rate_reserved_values[] = {
    { 0xffff, "OFPQ_MAX_RATE_UNCFG" },
    { 0,        NULL }
};

#define OFPQT_MIN_RATE      1
#define OFPQT_MAX_RATE      2
#define OFPQT_EXPERIMENTER  0xffff
static const value_string openflow_v4_queue_prop_property_values[] = {
    { OFPQT_MIN_RATE,     "OFPQT_MIN_RATE" },
    { OFPQT_MAX_RATE,     "OFPQT_MAX_RATE" },
    { OFPQT_EXPERIMENTER, "OFPQT_EXPERIMENTER" },
    { 0,                  NULL },
};

static int
dissect_openflow_queue_prop_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    proto_item *ti;
    proto_tree *prop_tree;
    guint16 prop_type;
    guint16 prop_len;

    prop_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_openflow_v4_queue_prop, &ti, "Queue property");

    /* uint16_t property; */
    prop_type = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(prop_tree, hf_openflow_v4_queue_prop_property, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint16_t len; */
    prop_len = tvb_get_ntohs(tvb, offset);
    proto_item_set_len(ti, prop_len);
    proto_tree_add_item(prop_tree, hf_openflow_v4_queue_prop_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint8_t pad[4]; */
    proto_tree_add_item(prop_tree, hf_openflow_v4_queue_prop_pad, tvb, offset, 4, ENC_NA);
    offset+=4;

    switch (prop_type) {
    case OFPQT_MIN_RATE:
        /* uint16_t rate; */
        if (tvb_get_ntohs(tvb, offset) <= OFPQ_MIN_RATE_MAX) {
            proto_tree_add_item(prop_tree, hf_openflow_v4_queue_prop_min_rate_rate, tvb, offset, 2, ENC_BIG_ENDIAN);
        } else {
            proto_tree_add_item(prop_tree, hf_openflow_v4_queue_prop_min_rate_rate_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
        }
        offset+=2;

        /* uint8_t pad[6]; */
        proto_tree_add_item(prop_tree, hf_openflow_v4_queue_prop_min_rate_pad, tvb, offset, 6, ENC_NA);
        offset+=6;
        break;

    case OFPQT_MAX_RATE:
        /* uint16_t rate; */
        if (tvb_get_ntohs(tvb, offset) <= OFPQ_MAX_RATE_MAX) {
            proto_tree_add_item(prop_tree, hf_openflow_v4_queue_prop_max_rate_rate, tvb, offset, 2, ENC_BIG_ENDIAN);
        } else {
            proto_tree_add_item(prop_tree, hf_openflow_v4_queue_prop_max_rate_rate_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
        }
        offset+=2;

        /* uint8_t pad[6]; */
        proto_tree_add_item(prop_tree, hf_openflow_v4_queue_prop_max_rate_pad, tvb, offset, 6, ENC_NA);
        offset+=6;
        break;

    case OFPQT_EXPERIMENTER:
        /* uint32_t experimenter; */
        proto_tree_add_item(prop_tree, hf_openflow_v4_queue_prop_experimenter_experimenter, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;

        /* uint8_t pad[4]; */
        proto_tree_add_item(prop_tree, hf_openflow_v4_queue_prop_experimenter_pad, tvb, offset, 4, ENC_NA);
        offset+=4;

        /* uint8_t data[0]; */
        proto_tree_add_expert_format(prop_tree, pinfo, &ei_openflow_v4_queue_prop_undecoded,
                                     tvb, offset, prop_len - 16, "Experimenter queue property body.");
        if (prop_len > 16)
            offset+=prop_len-16;
        break;

    default:
        proto_tree_add_expert_format(prop_tree, pinfo, &ei_openflow_v4_queue_prop_undecoded,
                                     tvb, offset, prop_len - 8, "Unknown queue property body.");
        if (prop_len > 8)
            offset+=prop_len-8;
        break;
    }

    return offset;
}


#define OFPQ_ALL  0xffffffff
static const value_string openflow_v4_queue_id_reserved_values[] = {
    { OFPQ_ALL, "OFPQ_ALL" },
    { 0,        NULL }
};

static int
dissect_openflow_packet_queue_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    proto_item *ti;
    proto_tree *queue_tree;
    guint16 queue_len;
    guint16 queue_end;

    queue_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_openflow_v4_packet_queue, &ti, "Queue");

    /* uint32_t queue_id; */
    if (tvb_get_ntohl(tvb, offset) != OFPQ_ALL) {
        proto_tree_add_item(queue_tree, hf_openflow_v4_packet_queue_queue_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(queue_tree, hf_openflow_v4_packet_queue_queue_id_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* uint32_t port; */
    if (tvb_get_ntohl(tvb, offset) <= OFPP_MAX) {
        proto_tree_add_item(queue_tree, hf_openflow_v4_packet_queue_port, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(queue_tree, hf_openflow_v4_packet_queue_port_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* uint16_t len; */
    queue_len = tvb_get_ntohs(tvb, offset);
    queue_end = offset - 8 + queue_len;
    proto_item_set_len(ti, queue_len);
    proto_tree_add_item(queue_tree, hf_openflow_v4_packet_queue_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint8_t pad[6]; */
    proto_tree_add_item(queue_tree, hf_openflow_v4_packet_queue_pad, tvb, offset, 6, ENC_NA);
    offset+=6;

    /* struct ofp_queue_prop_header properties[0]; */
    while (offset < queue_end) {
        offset = dissect_openflow_queue_prop_v4(tvb, pinfo, queue_tree, offset, length);
    }

    return offset;
}

static void
dissect_openflow_queue_get_config_reply_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length)
{
    /* uint32_t port; */
    if (tvb_get_ntohl(tvb, offset) <= OFPP_MAX) {
        proto_tree_add_item(tree, hf_openflow_v4_queue_get_config_reply_port, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(tree, hf_openflow_v4_queue_get_config_reply_port_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* uint8_t pad[4]; */
    proto_tree_add_item(tree, hf_openflow_v4_queue_get_config_reply_pad, tvb, offset, 4, ENC_NA);
    offset+=4;

    /* struct ofp_packet_queue queues[0]; */
    while (offset < length) {
        offset = dissect_openflow_packet_queue_v4(tvb, pinfo, tree, offset, length);
    }
}

static const value_string openflow_v4_controller_role_values[] = {
    { 0, "OFPCR_ROLE_NOCHANGE" },
    { 1, "OFPCR_ROLE_EQUAL" },
    { 2, "OFPCR_ROLE_MASTER" },
    { 3, "OFPCR_ROLE_SLAVE" },
    { 0, NULL }
};

static void
dissect_openflow_role_request_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    /* uint32_t role; */
    proto_tree_add_item(tree, hf_openflow_v4_role_request_role, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* uint8_t pad[4]; */
    proto_tree_add_item(tree, hf_openflow_v4_role_request_pad, tvb, offset, 4, ENC_NA);
    offset+=4;

    /* uint64_t generation_id; */
    proto_tree_add_item(tree, hf_openflow_v4_role_request_generation_id, tvb, offset, 8, ENC_BIG_ENDIAN);
    /*offset+=8;*/
}


static void
dissect_openflow_role_reply_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    /* uint32_t role; */
    proto_tree_add_item(tree, hf_openflow_v4_role_reply_role, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* uint8_t pad[4]; */
    proto_tree_add_item(tree, hf_openflow_v4_role_reply_pad, tvb, offset, 4, ENC_NA);
    offset+=4;

    /* uint64_t generation_id; */
    proto_tree_add_item(tree, hf_openflow_v4_role_reply_generation_id, tvb, offset, 8, ENC_BIG_ENDIAN);
    /*offset+=8;*/
}


static void
dissect_openflow_async_config_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    proto_item *ti;
    proto_tree *pimm_tree, *psmm_tree, *frmm_tree;
    proto_tree *pims_tree, *psms_tree, *frms_tree;

    /* uint32_t packet_in_mask[2]; */
    ti = proto_tree_add_item(tree, hf_openflow_v4_async_config_packet_in_mask_master, tvb, offset, 4, ENC_BIG_ENDIAN);
    pimm_tree = proto_item_add_subtree(ti, ett_openflow_v4_async_config_packet_in_mask_master);

    proto_tree_add_item(pimm_tree, hf_openflow_v4_async_config_packet_in_mask_master_no_match, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(pimm_tree, hf_openflow_v4_async_config_packet_in_mask_master_action, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(pimm_tree, hf_openflow_v4_async_config_packet_in_mask_master_invalid_ttl, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    ti = proto_tree_add_item(tree, hf_openflow_v4_async_config_packet_in_mask_slave, tvb, offset, 4, ENC_BIG_ENDIAN);
    pims_tree = proto_item_add_subtree(ti, ett_openflow_v4_async_config_packet_in_mask_slave);

    proto_tree_add_item(pims_tree, hf_openflow_v4_async_config_packet_in_mask_slave_no_match, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(pims_tree, hf_openflow_v4_async_config_packet_in_mask_slave_action, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(pims_tree, hf_openflow_v4_async_config_packet_in_mask_slave_invalid_ttl, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* uint32_t port_status_mask[2]; */
    ti = proto_tree_add_item(tree, hf_openflow_v4_async_config_port_status_mask_master, tvb, offset, 4, ENC_BIG_ENDIAN);
    psmm_tree = proto_item_add_subtree(ti, ett_openflow_v4_async_config_port_status_mask_master);

    proto_tree_add_item(psmm_tree, hf_openflow_v4_async_config_port_status_mask_master_add, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(psmm_tree, hf_openflow_v4_async_config_port_status_mask_master_delete, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(psmm_tree, hf_openflow_v4_async_config_port_status_mask_master_modify, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    ti = proto_tree_add_item(tree, hf_openflow_v4_async_config_port_status_mask_slave, tvb, offset, 4, ENC_BIG_ENDIAN);
    psms_tree = proto_item_add_subtree(ti, ett_openflow_v4_async_config_port_status_mask_slave);

    proto_tree_add_item(psms_tree, hf_openflow_v4_async_config_port_status_mask_slave_add, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(psms_tree, hf_openflow_v4_async_config_port_status_mask_slave_delete, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(psms_tree, hf_openflow_v4_async_config_port_status_mask_slave_modify, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* uint32_t flow_removed_mask[2]; */
    ti = proto_tree_add_item(tree, hf_openflow_v4_async_config_flow_removed_mask_master, tvb, offset, 4, ENC_BIG_ENDIAN);
    frmm_tree = proto_item_add_subtree(ti, ett_openflow_v4_async_config_flow_removed_mask_master);

    proto_tree_add_item(frmm_tree, hf_openflow_v4_async_config_flow_removed_mask_master_idle_timeout, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(frmm_tree, hf_openflow_v4_async_config_flow_removed_mask_master_hard_timeout, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(frmm_tree, hf_openflow_v4_async_config_flow_removed_mask_master_delete, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(frmm_tree, hf_openflow_v4_async_config_flow_removed_mask_master_group_delete, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    ti = proto_tree_add_item(tree, hf_openflow_v4_async_config_flow_removed_mask_slave, tvb, offset, 4, ENC_BIG_ENDIAN);
    frms_tree = proto_item_add_subtree(ti, ett_openflow_v4_async_config_flow_removed_mask_slave);

    proto_tree_add_item(frms_tree, hf_openflow_v4_async_config_flow_removed_mask_slave_idle_timeout, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(frms_tree, hf_openflow_v4_async_config_flow_removed_mask_slave_hard_timeout, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(frms_tree, hf_openflow_v4_async_config_flow_removed_mask_slave_delete, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(frms_tree, hf_openflow_v4_async_config_flow_removed_mask_slave_group_delete, tvb, offset, 4, ENC_BIG_ENDIAN);
    /*offset+=4;*/
}



static const value_string openflow_v4_metermod_command_values[] = {
    { 0, "OFPMC_ADD" },
    { 1, "OFPMC_MODIFY" },
    { 2, "OFPMC_DELETE" },
    { 0, NULL }
};

static void
dissect_openflow_metermod_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    proto_item *ti;
    proto_tree *flags_tree;

    /* uint16_t command; */
    proto_tree_add_item(tree, hf_openflow_v4_metermod_command, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint16_t flags; */
    ti = proto_tree_add_item(tree, hf_openflow_v4_metermod_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
    flags_tree = proto_item_add_subtree(ti, ett_openflow_v4_metermod_flags);

    proto_tree_add_item(flags_tree, hf_openflow_v4_metermod_flags_kbps, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_openflow_v4_metermod_flags_pktps, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_openflow_v4_metermod_flags_burst, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_openflow_v4_metermod_flags_stats, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint32_t meter_id; */
    if (tvb_get_ntohl(tvb, offset) <= OFPM_MAX) {
        proto_tree_add_item(tree, hf_openflow_v4_metermod_meter_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(tree, hf_openflow_v4_metermod_meter_id_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;

    /* struct ofp_meter_band_header bands[0]; */
    while (offset < length) {
        offset = dissect_openflow_meter_band_v4(tvb, pinfo, tree, offset, length);
    }
}



static int
dissect_openflow_v4(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *openflow_tree;
    guint offset = 0;
    guint8 type;
    guint16 length;

    type   = tvb_get_guint8(tvb, 1);
    length = tvb_get_ntohs(tvb, 2);

    col_append_fstr(pinfo->cinfo, COL_INFO, "Type: %s",
                  val_to_str_ext_const(type, &openflow_v4_type_values_ext, "Unknown message type"));

    /* Create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_openflow_v4, tvb, 0, -1, ENC_NA);
    openflow_tree = proto_item_add_subtree(ti, ett_openflow_v4);

    offset = dissect_openflow_header_v4(tvb, pinfo, openflow_tree, offset, length);

    switch(type){
    case OFPT_HELLO:
        dissect_openflow_hello_v4(tvb, pinfo, openflow_tree, offset, length);
        break;

    case OFPT_ERROR:
        dissect_openflow_error_v4(tvb, pinfo, openflow_tree, offset, length);
        break;
    case OFPT_ECHO_REQUEST:
    case OFPT_ECHO_REPLY:
        dissect_openflow_echo_v4(tvb, pinfo, openflow_tree, offset, length);
        break;
    case OFPT_EXPERIMENTER:
        dissect_openflow_experimenter_v4(tvb, pinfo, openflow_tree, offset, length);
        break;
    case OFPT_FEATURES_REQUEST:
        /* message has no body */
        break;
    case OFPT_FEATURES_REPLY:
        dissect_openflow_switch_features_v4(tvb, pinfo, openflow_tree, offset, length);
        break;
    case OFPT_GET_CONFIG_REQUEST:
        /* mesage has no body */
        break;
    case OFPT_GET_CONFIG_REPLY:
    case OFPT_SET_CONFIG:
        dissect_openflow_switch_config_v4(tvb, pinfo, openflow_tree, offset, length);
        break;
    case OFPT_PACKET_IN:
        dissect_openflow_packet_in_v4(tvb, pinfo, openflow_tree, offset, length);
        break;
    case OFPT_FLOW_REMOVED:
        dissect_openflow_flow_removed_v4(tvb, pinfo, openflow_tree, offset, length);
        break;
    case OFPT_PORT_STATUS:
        dissect_openflow_port_status_v4(tvb, pinfo, openflow_tree, offset, length);
        break;
    case OFPT_PACKET_OUT:
        dissect_openflow_packet_out_v4(tvb, pinfo, openflow_tree, offset, length);
        break;
    case OFPT_FLOW_MOD:
        dissect_openflow_flowmod_v4(tvb, pinfo, openflow_tree, offset, length);
        break;
    case OFPT_GROUP_MOD:
        dissect_openflow_groupmod_v4(tvb, pinfo, openflow_tree, offset, length);
        break;
    case OFPT_PORT_MOD:
        dissect_openflow_portmod_v4(tvb, pinfo, openflow_tree, offset, length);
        break;
    case OFPT_TABLE_MOD:
        dissect_openflow_tablemod_v4(tvb, pinfo, openflow_tree, offset, length);
        break;
    case OFPT_MULTIPART_REQUEST:
        dissect_openflow_multipart_request_v4(tvb, pinfo, openflow_tree, offset, length);
        break;
    case OFPT_MULTIPART_REPLY:
        dissect_openflow_multipart_reply_v4(tvb, pinfo, openflow_tree, offset, length);
        break;
    case OFPT_BARRIER_REQUEST:
    case OFPT_BARRIER_REPLY:
        /* message has no body */
        break;
    case OFPT_QUEUE_GET_CONFIG_REQUEST:
        dissect_openflow_queue_get_config_request_v4(tvb, pinfo, openflow_tree, offset, length);
        break;
    case OFPT_QUEUE_GET_CONFIG_REPLY:
        dissect_openflow_queue_get_config_reply_v4(tvb, pinfo, openflow_tree, offset, length);
        break;
    case OFPT_ROLE_REQUEST:
        dissect_openflow_role_request_v4(tvb, pinfo, openflow_tree, offset, length);
        break;
    case OFPT_ROLE_REPLY:
        dissect_openflow_role_reply_v4(tvb, pinfo, openflow_tree, offset, length);
        break;
    case OFPT_GET_ASYNC_REQUEST:
        /* message has no body */
        break;
    case OFPT_GET_ASYNC_REPLY:
    case OFPT_SET_ASYNC:
        dissect_openflow_async_config_v4(tvb, pinfo, openflow_tree, offset, length);
        break;
    case OFPT_METER_MOD:
        dissect_openflow_metermod_v4(tvb, pinfo, openflow_tree, offset, length);
        break;

     default:
         if (length > 8) {
            proto_tree_add_expert_format(openflow_tree, pinfo, &ei_openflow_v4_message_undecoded,
                                     tvb, offset, length - 8, "Unknown message body.");
        }
        break;
    }

    return tvb_reported_length(tvb);
}

/*
 * Register the protocol with Wireshark.
 */
void
proto_register_openflow_v4(void)
{

    static hf_register_info hf[] = {
        { &hf_openflow_v4_version,
            { "Version", "openflow_v4.version",
               FT_UINT8, BASE_HEX, VALS(openflow_v4_version_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_type,
            { "Type", "openflow_v4.type",
               FT_UINT8, BASE_DEC | BASE_EXT_STRING, &openflow_v4_type_values_ext, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_xid,
            { "Transaction ID", "openflow_v4.xid",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_length,
            { "Length", "openflow_v4.length",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_class,
            { "Class", "openflow_v4.oxm.class",
               FT_UINT16, BASE_HEX, VALS(openflow_v4_oxm_class_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_field,
            { "Field", "openflow_v4.oxm.field",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_field_basic,
            { "Field", "openflow_v4.oxm.field",
               FT_UINT8, BASE_DEC | BASE_EXT_STRING, &openflow_v4_oxm_basic_field_values_ext, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_hm,
            { "Has mask", "openflow_v4.oxm.hm",
               FT_BOOLEAN, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_length,
            { "Length", "openflow_v4.oxm.length",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_experimenter_experimenter,
            { "Experimenter", "openflow_v4.oxm_experimenter.experimenter",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_experimenter_value,
            { "Experimenter Value", "openflow_v4.oxm_experimenter.value",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_value,
            { "Value", "openflow_v4.oxm.value",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_value_etheraddr,
            { "Value", "openflow_v4.oxm.value_etheraddr",
               FT_ETHER, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_value_ethertype,
            { "Value", "openflow_v4.oxm.value_ethertype",
               FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_value_vlan_present,
            { "OFPVID_PRESENT", "openflow_v4.oxm.value_vlan_present",
               FT_BOOLEAN, 16, NULL, OFPVID_PRESENT,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_value_vlan_vid,
            { "Value", "openflow_v4.oxm.value_vlan_vid",
               FT_UINT16, BASE_DEC, NULL, 0x0fff,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_value_ipv4addr,
            { "Value", "openflow_v4.oxm.value_ipv4addr",
               FT_IPv4, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_value_ipv6addr,
            { "Value", "openflow_v4.oxm.value_ipv6addr",
               FT_IPv6, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_value_ipproto,
            { "Value", "openflow_v4.oxm.value_ipproto",
               FT_UINT8, BASE_DEC|BASE_EXT_STRING, &ipproto_val_ext, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_value_uint16,
            { "Value", "openflow_v4.oxm.value_uint16",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_value_uint24,
            { "Value", "openflow_v4.oxm.value_uint24",
               FT_UINT24, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_value_uint32,
            { "Value", "openflow_v4.oxm.value_uint32",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_mask,
            { "Mask", "openflow_v4.oxm.mask",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_mask_etheraddr,
            { "Mask", "openflow_v4.oxm.ether_mask",
               FT_ETHER, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_mask_ipv4addr,
            { "Mask", "openflow_v4.oxm.ipv4_mask",
               FT_IPv4, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_oxm_mask_ipv6addr,
            { "Mask", "openflow_v4.oxm.ipv6_mask",
               FT_IPv6, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_match_type,
            { "Type", "openflow_v4.match.type",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_match_type_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_match_length,
            { "Length", "openflow_v4.match.length",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_match_pad,
            { "Pad", "openflow_v4.match.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_type,
            { "Type", "openflow_v4.action.type",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_action_type_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_length,
            { "Length", "openflow_v4.action.length",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_experimenter_experimenter,
            { "Experimenter", "openflow_v4.action_experimenter.experimenter",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_output_port,
            { "Port", "openflow_v4.action.output.port",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_output_port_reserved,
            { "Port", "openflow_v4.action.output.port",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_port_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_output_max_len,
            { "Max length", "openflow_v4.action.output.max_len",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_output_max_len_reserved,
            { "Max length", "openflow_v4.action.output.max_len",
               FT_UINT16, BASE_HEX, VALS(openflow_v4_controller_max_len_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_output_pad,
            { "Pad", "openflow_v4.action.output.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_copy_ttl_out_pad,
            { "Pad", "openflow_v4.action.copy_ttl_out.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_copy_ttl_in_pad,
            { "Pad", "openflow_v4.action.copy_ttl_in.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_set_mpls_ttl_ttl,
            { "TTL", "openflow_v4.action.set_mpls_ttl.ttl",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_set_mpls_ttl_pad,
            { "Pad", "openflow_v4.action.set_mpls_ttl.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_dec_mpls_ttl_pad,
            { "Pad", "openflow_v4.action.dec_mpls_ttl.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_push_vlan_ethertype,
            { "Ethertype", "openflow_v4.action.push_vlan.ethertype",
               FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_push_vlan_pad,
            { "Pad", "openflow_v4.action.push_vlan.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_pop_vlan_pad,
            { "Pad", "openflow_v4.action.pop_vlan.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_push_mpls_ethertype,
            { "Ethertype", "openflow_v4.action.push_mpls.ethertype",
               FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_push_mpls_pad,
            { "Pad", "openflow_v4.action.push_mpls.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_pop_mpls_ethertype,
            { "Ethertype", "openflow_v4.action.pop_mpls.ethertype",
               FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_pop_mpls_pad,
            { "Pad", "openflow_v4.action.pop_mpls.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_set_queue_queue_id,
            { "Queue ID", "openflow_v4.action.set_queue.queue_id",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_group_group_id,
            { "Group ID", "openflow_v4.action.group.group_id",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_group_group_id_reserved,
            { "Group ID", "openflow_v4.action.group.group_id",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_port_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_set_nw_ttl_ttl,
            { "TTL", "openflow_v4.action.set_nw_ttl.ttl",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_set_nw_ttl_pad,
            { "Pad", "openflow_v4.action.set_nw_ttl.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_dec_nw_ttl_pad,
            { "Pad", "openflow_v4.action.dec_nw_ttl.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_set_field_pad,
            { "Pad", "openflow_v4.action.set_field.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_push_pbb_ethertype,
            { "Ethertype", "openflow_v4.action.push_pbb.ethertype",
               FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_push_pbb_pad,
            { "Pad", "openflow_v4.action.push_pbb.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_action_pop_pbb_pad,
            { "Pad", "openflow_v4.action.pop_pbb.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_instruction_type,
            { "Type", "openflow_v4.instruction.type",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_instruction_type_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_instruction_length,
            { "Length", "openflow_v4.instruction.length",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_instruction_experimenter_experimenter,
            { "Experimenter", "openflow_v4.instruction_experimenter.experimenter",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_instruction_goto_table_table_id,
            { "Table ID", "openflow_v4.instruction.goto_table.table_id",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_instruction_goto_table_pad,
            { "Pad", "openflow_v4.instruction.goto_table.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_instruction_write_metadata_pad,
            { "Pad", "openflow_v4.instruction.write_metadata.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_instruction_write_metadata_value,
            { "Value", "openflow_v4.instruction.write_metadata.value",
               FT_UINT64, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_instruction_write_metadata_mask,
            { "Mask", "openflow_v4.instruction.write_metadata.mask",
               FT_UINT64, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_instruction_actions_pad,
            { "Pad", "openflow_v4.instruction.actions.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_instruction_meter_meter_id,
            { "Meter ID", "openflow_v4.instruction.meter.meter_id",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_instruction_meter_meter_id_reserved,
            { "Meter ID", "openflow_v4.instruction.meter.meter_id",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_meter_id_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_port_no,
            { "Port no", "openflow_v4.port.port_no",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_port_no_reserved,
            { "Port no", "openflow_v4.port.port_no",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_port_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_pad,
            { "Pad", "openflow_v4.port.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_hw_addr,
            { "Hw addr", "openflow_v4.port.hw_addr",
               FT_ETHER, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_pad2,
            { "Pad", "openflow_v4.port.pad2",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_name,
            { "Name", "openflow_v4.port.name",
               FT_STRING, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_config,
            { "Config", "openflow_v4.port.config",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_config_port_down,
            { "OFPPC_PORT_DOWN", "openflow_v4.port.config.port_down",
               FT_BOOLEAN, 32, NULL, OFPPC_PORT_DOWN,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_config_no_recv,
            { "OFPPC_NO_RECV", "openflow_v4.port.config.no_recv",
               FT_BOOLEAN, 32, NULL, OFPPC_NO_RECV,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_config_no_fwd,
            { "OFPPC_NO_FWD", "openflow_v4.port.config.no_fwd",
               FT_BOOLEAN, 32, NULL, OFPPC_NO_FWD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_config_no_packet_in,
            { "OFPPC_NO_PACKET_IN", "openflow_v4.port.config.no_packet_in",
               FT_BOOLEAN, 32, NULL, OFPPC_NO_PACKET_IN,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_state,
            { "State", "openflow_v4.port.sate",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_state_link_down,
            { "OFPPS_LINK_DOWN", "openflow_v4.port.state.link_down",
               FT_BOOLEAN, 32, NULL, OFPPS_LINK_DOWN,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_state_blocked,
            { "OFPPS_BLOCKED", "openflow_v4.port.state.blocked",
               FT_BOOLEAN, 32, NULL, OFPPS_BLOCKED,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_state_live,
            { "OFPPS_LIVE", "openflow_v4.port.state.live",
               FT_BOOLEAN, 32, NULL, OFPPS_LIVE,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_current,
            { "Current", "openflow_v4.port.current",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_current_10mb_hd,
            { "OFPPF_10MB_HD", "openflow_v4.port.current.10mb_hd",
               FT_BOOLEAN, 32, NULL, OFPPF_10MB_HD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_current_10mb_fd,
            { "OFPPF_10MB_FD", "openflow_v4.port.current.10mb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_10MB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_current_100mb_hd,
            { "OFPPF_100MB_HD", "openflow_v4.port.current.100mb_hd",
               FT_BOOLEAN, 32, NULL, OFPPF_100MB_HD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_current_100mb_fd,
            { "OFPPF_100MB_FD", "openflow_v4.port.current.100mb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_100MB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_current_1gb_hd,
            { "OFPPF_1GB_HD", "openflow_v4.port.current.1gb_hd",
               FT_BOOLEAN, 32, NULL, OFPPF_1GB_HD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_current_1gb_fd,
            { "OFPPF_1GB_FD", "openflow_v4.port.current.1gb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_1GB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_current_10gb_fd,
            { "OFPPF_10_GB_FD", "openflow_v4.port.current.10gb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_10GB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_current_40gb_fd,
            { "OFPPF_40GB_FD", "openflow_v4.port.current.40gb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_40GB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_current_100gb_fd,
            { "OFPPF_100_GB_FD", "openflow_v4.port.current.100_gb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_100GB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_current_1tb_fd,
            { "OFPPF_1TB_FD", "openflow_v4.port.current.1tb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_1TB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_current_other,
            { "OFPPF_OTHER", "openflow_v4.port.current.other",
               FT_BOOLEAN, 32, NULL, OFPPF_OTHER,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_current_copper,
            { "OFPPF_COPPER", "openflow_v4.port.current.copper",
               FT_BOOLEAN, 32, NULL, OFPPF_COPPER,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_current_fiber,
            { "OFPPF_FIBER", "openflow_v4.port.current.fiber",
               FT_BOOLEAN, 32, NULL, OFPPF_FIBER,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_current_autoneg,
            { "OFPPF_AUTONEG", "openflow_v4.port.current.autoneg",
               FT_BOOLEAN, 32, NULL, OFPPF_AUTONEG,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_current_pause,
            { "OFPPF_PAUSE", "openflow_v4.port.current.pause",
               FT_BOOLEAN, 32, NULL, OFPPF_PAUSE,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_current_pause_asym,
            { "OFPPF_PAUSE_ASYM", "openflow_v4.port.current.pause_asym",
               FT_BOOLEAN, 32, NULL, OFPPF_PAUSE_ASYM,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_advertised,
            { "Advertised", "openflow_v4.port.advertised",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_advertised_10mb_hd,
            { "OFPPF_10MB_HD", "openflow_v4.port.advertised.10mb_hd",
               FT_BOOLEAN, 32, NULL, OFPPF_10MB_HD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_advertised_10mb_fd,
            { "OFPPF_10MB_FD", "openflow_v4.port.advertised.10mb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_10MB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_advertised_100mb_hd,
            { "OFPPF_100MB_HD", "openflow_v4.port.advertised.100mb_hd",
               FT_BOOLEAN, 32, NULL, OFPPF_100MB_HD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_advertised_100mb_fd,
            { "OFPPF_100MB_FD", "openflow_v4.port.advertised.100mb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_100MB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_advertised_1gb_hd,
            { "OFPPF_1GB_HD", "openflow_v4.port.advertised.1gb_hd",
               FT_BOOLEAN, 32, NULL, OFPPF_1GB_HD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_advertised_1gb_fd,
            { "OFPPF_1GB_FD", "openflow_v4.port.advertised.1gb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_1GB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_advertised_10gb_fd,
            { "OFPPF_10_GB_FD", "openflow_v4.port.advertised.10gb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_10GB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_advertised_40gb_fd,
            { "OFPPF_40GB_FD", "openflow_v4.port.advertised.40gb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_40GB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_advertised_100gb_fd,
            { "OFPPF_100GB_FD", "openflow_v4.port.advertised.100gb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_100GB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_advertised_1tb_fd,
            { "OFPPF_1TB_FD", "openflow_v4.port.advertised.1tb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_1TB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_advertised_other,
            { "OFPPF_OTHER", "openflow_v4.port.advertised.other",
               FT_BOOLEAN, 32, NULL, OFPPF_OTHER,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_advertised_copper,
            { "OFPPF_COPPER", "openflow_v4.port.advertised.copper",
               FT_BOOLEAN, 32, NULL, OFPPF_COPPER,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_advertised_fiber,
            { "OFPPF_FIBER", "openflow_v4.port.advertised.fiber",
               FT_BOOLEAN, 32, NULL, OFPPF_FIBER,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_advertised_autoneg,
            { "OFPPF_AUTONEG", "openflow_v4.port.advertised.autoneg",
               FT_BOOLEAN, 32, NULL, OFPPF_AUTONEG,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_advertised_pause,
            { "OFPPF_PAUSE", "openflow_v4.port.advertised.pause",
               FT_BOOLEAN, 32, NULL, OFPPF_PAUSE,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_advertised_pause_asym,
            { "OFPPF_PAUSE_ASYM", "openflow_v4.port.advertised.pause_asym",
               FT_BOOLEAN, 32, NULL, OFPPF_PAUSE_ASYM,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_supported,
            { "Supported", "openflow_v4.port.supported",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_supported_10mb_hd,
            { "OFPPF_10MB_HD", "openflow_v4.port.supported.10mb_hd",
               FT_BOOLEAN, 32, NULL, OFPPF_10MB_HD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_supported_10mb_fd,
            { "OFPPF_10MB_FD", "openflow_v4.port.supported.10mb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_10MB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_supported_100mb_hd,
            { "OFPPF_100MB_HD", "openflow_v4.port.supported.100mb_hd",
               FT_BOOLEAN, 32, NULL, OFPPF_100MB_HD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_supported_100mb_fd,
            { "OFPPF_100MB_FD", "openflow_v4.port.supported.100mb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_100MB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_supported_1gb_hd,
            { "OFPPF_1GB_HD", "openflow_v4.port.supported.1gb_hd",
               FT_BOOLEAN, 32, NULL, OFPPF_1GB_HD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_supported_1gb_fd,
            { "OFPPF_1GB_FD", "openflow_v4.port.supported.1gb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_1GB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_supported_10gb_fd,
            { "OFPPF_10_GB_FD", "openflow_v4.port.supported.10gb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_10GB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_supported_40gb_fd,
            { "OFPPF_40GB_FD", "openflow_v4.port.supported.40gb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_40GB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_supported_100gb_fd,
            { "OFPPF_100GB_FD", "openflow_v4.port.supported.100gb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_100GB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_supported_1tb_fd,
            { "OFPPF_1TB_FD", "openflow_v4.port.supported.1tb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_1TB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_supported_other,
            { "OFPPF_OTHER", "openflow_v4.port.supported.other",
               FT_BOOLEAN, 32, NULL, OFPPF_OTHER,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_supported_copper,
            { "OFPPF_COPPER", "openflow_v4.port.supported.copper",
               FT_BOOLEAN, 32, NULL, OFPPF_COPPER,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_supported_fiber,
            { "OFPPF_FIBER", "openflow_v4.port.supported.fiber",
               FT_BOOLEAN, 32, NULL, OFPPF_FIBER,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_supported_autoneg,
            { "OFPPF_AUTONEG", "openflow_v4.port.supported.autoneg",
               FT_BOOLEAN, 32, NULL, OFPPF_AUTONEG,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_supported_pause,
            { "OFPPF_PAUSE", "openflow_v4.port.supported.pause",
               FT_BOOLEAN, 32, NULL, OFPPF_PAUSE,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_supported_pause_asym,
            { "OFPPF_PAUSE_ASYM", "openflow_v4.port.supported.pause_asym",
               FT_BOOLEAN, 32, NULL, OFPPF_PAUSE_ASYM,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_peer,
            { "Peer", "openflow_v4.port.peer",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_peer_10mb_hd,
            { "OFPPF_10MB_HD", "openflow_v4.port.peer.10mb_hd",
               FT_BOOLEAN, 32, NULL, OFPPF_10MB_HD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_peer_10mb_fd,
            { "OFPPF_10MB_FD", "openflow_v4.port.peer.10mb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_10MB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_peer_100mb_hd,
            { "OFPPF_100MB_HD", "openflow_v4.port.peer.100mb_hd",
               FT_BOOLEAN, 32, NULL, OFPPF_100MB_HD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_peer_100mb_fd,
            { "OFPPF_100MB_FD", "openflow_v4.port.peer.100mb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_100MB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_peer_1gb_hd,
            { "OFPPF_1GB_HD", "openflow_v4.port.peer.1gb_hd",
               FT_BOOLEAN, 32, NULL, OFPPF_1GB_HD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_peer_1gb_fd,
            { "OFPPF_1GB_FD", "openflow_v4.port.peer.1gb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_1GB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_peer_10gb_fd,
            { "OFPPF_10_GB_FD", "openflow_v4.port.peer.10gb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_10GB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_peer_40gb_fd,
            { "OFPPF_40GB_FD", "openflow_v4.port.peer.40gb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_40GB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_peer_100gb_fd,
            { "OFPPF_100GB_FD", "openflow_v4.port.peer.100gb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_100GB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_peer_1tb_fd,
            { "OFPPF_1TB_FD", "openflow_v4.port.peer.1tb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_1TB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_peer_other,
            { "OFPPF_OTHER", "openflow_v4.port.peer.other",
               FT_BOOLEAN, 32, NULL, OFPPF_OTHER,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_peer_copper,
            { "OFPPF_COPPER", "openflow_v4.port.peer.copper",
               FT_BOOLEAN, 32, NULL, OFPPF_COPPER,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_peer_fiber,
            { "OFPPF_FIBER", "openflow_v4.port.peer.fiber",
               FT_BOOLEAN, 32, NULL, OFPPF_FIBER,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_peer_autoneg,
            { "OFPPF_AUTONEG", "openflow_v4.port.peer.autoneg",
               FT_BOOLEAN, 32, NULL, OFPPF_AUTONEG,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_peer_pause,
            { "OFPPF_PAUSE", "openflow_v4.port.peer.pause",
               FT_BOOLEAN, 32, NULL, OFPPF_PAUSE,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_peer_pause_asym,
            { "OFPPF_PAUSE_ASYM", "openflow_v4.port.peer.pause_asym",
               FT_BOOLEAN, 32, NULL, OFPPF_PAUSE_ASYM,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_curr_speed,
            { "Curr speed", "openflow_v4.port.curr_speed",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_max_speed,
            { "Max speed", "openflow_v4.port.max_speed",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_band_type,
            { "Type", "openflow_v4.meter_band.type",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_meter_band_type_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_band_len,
            { "Length", "openflow_v4.meter_band.length",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_band_rate,
            { "Rate", "openflow_v4.meter_band.rate",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_band_burst_size,
            { "Burst size", "openflow_v4.meter_band.burst_size",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_band_drop_pad,
            { "Pad", "openflow_v4.meter_band.drop.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_band_dscp_remark_prec_level,
            { "Precedence level", "openflow_v4.meter_band.dscp_remark.prec_level",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_band_dscp_remark_pad,
            { "Pad", "openflow_v4.meter_band.dscp_remark.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_band_experimenter_experimenter,
            { "Experimenter", "openflow_v4.meter_band.experimenter.experimenter",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_hello_element_type,
            { "Type", "openflow_v4.hello_element.type",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_hello_element_type_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_hello_element_length,
            { "Length", "openflow_v4.hello_element.length",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_hello_element_version_bitmap,
            { "Bitmap", "openflow_v4.hello_element.version.bitmap",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_hello_element_pad,
            { "Pad", "openflow_v4.hello_element.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_type,
            { "Type", "openflow_v4.error.type",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_error_type_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_hello_failed_code,
            { "Code", "openflow_v4.error.code",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_error_hello_failed_code_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_bad_request_code,
            { "Code", "openflow_v4.error.code",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_error_bad_request_code_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_bad_action_code,
            { "Code", "openflow_v4.error.code",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_error_bad_action_code_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_bad_instruction_code,
            { "Code", "openflow_v4.error.code",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_error_bad_instruction_code_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_bad_match_code,
            { "Code", "openflow_v4.error.code",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_error_bad_match_code_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_flow_mod_failed_code,
            { "Code", "openflow_v4.error.code",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_error_flow_mod_failed_code_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_group_mod_failed_code,
            { "Code", "openflow_v4.error.code",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_error_group_mod_failed_code_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_port_mod_failed_code,
            { "Code", "openflow_v4.error.code",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_error_port_mod_failed_code_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_table_mod_failed_code,
            { "Code", "openflow_v4.error.code",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_error_table_mod_failed_code_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_queue_op_failed_code,
            { "Code", "openflow_v4.error.code",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_error_queue_op_failed_code_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_switch_config_failed_code,
            { "Code", "openflow_v4.error.code",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_error_switch_config_failed_code_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_role_request_failed_code,
            { "Code", "openflow_v4.error.code",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_error_role_request_failed_code_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_meter_mod_failed_code,
            { "Code", "openflow_v4.error.code",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_error_meter_mod_failed_code_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_table_features_failed_code,
            { "Code", "openflow_v4.error.code",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_error_table_features_failed_code_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_code,
            { "Code", "openflow_v4.error.code",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_data_text,
            { "Data", "openflow_v4.error.data",
               FT_STRING, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_echo_data,
            { "Data", "openflow_v4.echo.data",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_data_body,
            { "Body", "openflow_v4.error.data.body",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_error_experimenter,
            { "Experimenter", "openflow_v4.error.experimenter",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_experimenter_experimenter,
            { "Experimenter", "openflow_v4.experimenter.experimenter",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_experimenter_exp_type,
            { "Experimenter type", "openflow_v4.experimenter.exp_type",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_switch_features_datapath_id,
            { "datapath_id", "openflow_v4.switch_features.datapath_id",
               FT_UINT64, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_switch_features_n_buffers,
            { "n_buffers", "openflow_v4.switch_features.n_buffers",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_switch_features_n_tables,
            { "n_tables", "openflow_v4.switch_features.n_tables",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_switch_features_auxiliary_id,
            { "auxiliary_id", "openflow_v4.switch_features.auxiliary_id",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_switch_features_pad,
            { "Pad", "openflow_v4.switch_features.pad",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_switch_features_capabilities,
            { "capabilities", "openflow_v4.switch_features.capabilities",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_switch_features_capabilities_flow_stats,
            { "OFPC_FLOW_STATS", "openflow_v4.switch_features.capabilities.flow_stats",
               FT_BOOLEAN, 32, NULL, OFPC_FLOW_STATS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_switch_features_capabilities_table_stats,
            { "OFPC_TABLE_STATS", "openflow_v4.switch_features.capabilities.table_stats",
               FT_BOOLEAN, 32, NULL, OFPC_TABLE_STATS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_switch_features_capabilities_port_stats,
            { "OFPC_PORT_STATS", "openflow_v4.switch_features.capabilities.port_stats",
               FT_BOOLEAN, 32, NULL,  OFPC_PORT_STATS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_switch_features_capabilities_group_stats,
            { "OFPC_GROUP_STATS", "openflow_v4.switch_features.capabilities.group_stats",
               FT_BOOLEAN, 32, NULL, OFPC_GROUP_STATS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_switch_features_capabilities_ip_reasm,
            { "OFPC_IP_REASM", "openflow_v4.switch_features.capabilities.ip_reasm",
               FT_BOOLEAN, 32, NULL, OFPC_IP_REASM,
               NULL, HFILL }
        },
        { &hf_openflow_v4_switch_features_capabilities_queue_stats,
            { "OFPC_QUEUE_STATS", "openflow_v4.switch_features.capabilities.queue_stats",
               FT_BOOLEAN, 32, NULL, OFPC_QUEUE_STATS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_switch_features_capabilities_port_blocked,
            { "OFPC_PORT_BLOCKED", "openflow_v4.switch_features.capabilities.port_blocked",
               FT_BOOLEAN, 32, NULL, OFPC_PORT_BLOCKED,
               NULL, HFILL }
        },
        { &hf_openflow_v4_switch_features_reserved,
            { "Reserved", "openflow_v4.switch_features_reserved",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_switch_config_flags,
            { "Flags", "openflow_v4.switch_config.flags",
               FT_UINT16, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_switch_config_flags_fragments,
            { "IP Fragments", "openflow_v4.switch_config.flags.fragments",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_switch_config_fragments_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_switch_config_miss_send_len,
            { "Miss send length", "openflow_v4.switch_config.miss_send_len",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_switch_config_miss_send_len_reserved,
            { "Miss send length", "openflow_v4.switch_config.miss_send_len",
               FT_UINT16, BASE_HEX, VALS(openflow_v4_controller_max_len_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_packet_in_buffer_id,
            { "Buffer ID", "openflow_v4.packet_in.buffer_id",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
            },
        { &hf_openflow_v4_packet_in_buffer_id_reserved,
            { "Buffer ID", "openflow_v4.packet_in.buffer_id",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_buffer_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_packet_in_total_len,
            { "Total length", "openflow_v4.packet_in.total_len",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_packet_in_reason,
            { "Reason", "openflow_v4.packet_in.reason",
               FT_UINT8, BASE_DEC, VALS(openflow_v4_packet_in_reason_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_packet_in_table_id,
            { "Table ID", "openflow_v4.packet_in.table_id",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_packet_in_cookie,
            { "Cookie", "openflow_v4.packet_in.cookie",
               FT_UINT64, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_packet_in_pad,
            { "Pad", "openflow_v4.packet_in.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_removed_cookie,
            { "Cookie", "openflow_v4.flow_removed.cookie",
               FT_UINT64, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_removed_priority,
            { "Priority", "openflow_v4.flow_removed.priority",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_removed_reason,
            { "Reason", "openflow_v4.flow_removed.reason",
               FT_UINT8, BASE_DEC, VALS(openflow_v4_flow_removed_reason_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_removed_table_id,
            { "Table ID", "openflow_v4.flow_removed.table_id",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_removed_duration_sec,
            { "Duration sec", "openflow_v4.flow_removed.duration_sec",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_removed_duration_nsec,
            { "Duration nsec", "openflow_v4.flow_removed.duration_nsec",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_removed_idle_timeout,
            { "Idle timeout", "openflow_v4.flow_removed.idle_timeout",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_removed_hard_timeout,
            { "Hard timeout", "openflow_v4.flow_removed.hard_timeout",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_removed_packet_count,
            { "Packet count", "openflow_v4.flow_removed.packet_count",
               FT_UINT64, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_removed_byte_count,
            { "Byte count", "openflow_v4.flow_removed.byte_count",
               FT_UINT64, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_status_reason,
            { "Reason", "openflow_v4.port_status.reason",
               FT_UINT8, BASE_DEC, VALS(openflow_v4_port_status_reason_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_status_pad,
            { "Pad", "openflow_v4.port_status.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_packet_out_buffer_id,
            { "Buffer ID", "openflow_v4.packet_out.buffer_id",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
            },
        { &hf_openflow_v4_packet_out_buffer_id_reserved,
            { "Buffer ID", "openflow_v4.packet_out.buffer_id",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_buffer_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_packet_out_in_port,
            { "In port", "openflow_v4.packet_out.in_port",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_packet_out_in_port_reserved,
            { "In port", "openflow_v4.packet_out.in_port",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_port_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_packet_out_acts_len,
            { "Actions length", "openflow_v4.packet_out.acts_len",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_packet_out_pad,
            { "Pad", "openflow_v4.packet_out.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_cookie,
            { "Cookie", "openflow_v4.flowmod.cookie",
               FT_UINT64, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_cookie_mask,
            { "Cookie mask", "openflow_v4.flowmod.cookie_mask",
               FT_UINT64, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_table_id,
            { "Table ID", "openflow_v4.flowmod.table_id",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_table_id_reserved,
            { "Table ID", "openflow_v4.flowmod.table_id",
               FT_UINT8, BASE_DEC, VALS(openflow_v4_table_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_command,
            { "Command", "openflow_v4.flowmod.command",
               FT_UINT8, BASE_DEC, VALS(openflow_v4_flowmod_command_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_idle_timeout,
            { "Idle timeout", "openflow_v4.flowmod.idle_timeout",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_hard_timeout,
            { "Hard timeout", "openflow_v4.flowmod.hard_timeout",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_priority,
            { "Priority", "openflow_v4.flowmod.priority",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_buffer_id,
            { "Buffer ID", "openflow_v4.flowmod.buffer_id",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_buffer_id_reserved,
            { "Buffer ID", "openflow_v4.flowmod.buffer_id",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_buffer_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_out_port,
            { "Out port", "openflow_v4.flowmod.out_port",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_out_port_reserved,
            { "Out port", "openflow_v4.flowmod.out_port",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_port_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_out_group,
            { "Out group", "openflow_v4.flowmod.out_group",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_out_group_reserved,
            { "Out group", "openflow_v4.flowmod.out_group",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_group_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_flags,
            { "Flags", "openflow_v4.flowmod.flags",
               FT_UINT16, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_flags_send_flow_rem,
            { "Send flow removed", "openflow_v4.flowmod.flags.send_flow_rem",
               FT_BOOLEAN, 16, NULL, OFPFF_SEND_FLOW_REM,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_flags_check_overlap,
            { "Check overlap", "openflow_v4.flowmod.flags.check_overlap",
               FT_BOOLEAN, 16, NULL, OFPFF_CHECK_OVERLAP,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_flags_reset_counts,
            { "Reset counts", "openflow_v4.flowmod.flags.reset_counts",
               FT_BOOLEAN, 16, NULL, OFPFF_RESET_COUNTS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_flags_no_packet_counts,
            { "Don't count packets", "openflow_v4.flowmod.flags.no_packet_counts",
               FT_BOOLEAN, 16, NULL, OFPFF_NO_PKT_COUNTS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_flags_no_byte_counts,
            { "Don't count bytes", "openflow_v4.flowmod.flags.no_byte_counts",
               FT_BOOLEAN, 16, NULL, OFPFF_NO_BYT_COUNTS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flowmod_pad,
            { "Pad", "openflow_v4.flowmod.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_bucket_length,
            { "Length", "openflow_v4.bucket.length",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_bucket_weight,
            { "Weight", "openflow_v4.bucket.weight",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_bucket_watch_port,
            { "Watch port", "openflow_v4.bucket.watch_port",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_bucket_watch_port_reserved,
            { "Watch port", "openflow_v4.bucket.watch_port",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_port_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_bucket_watch_group,
            { "Watch group", "openflow_v4.bucket.watch_group",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_bucket_watch_group_reserved,
            { "Watch group", "openflow_v4.bucket.watch_group",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_group_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_bucket_pad,
            { "Pad", "openflow_v4.bucket.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_groupmod_command,
            { "Command", "openflow_v4.groupmod.command",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_groupmod_command_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_groupmod_type,
            { "Type", "openflow_v4.groupmod.type",
               FT_UINT8, BASE_DEC, VALS(openflow_v4_group_type_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_groupmod_pad,
            { "Pad", "openflow_v4.groupmod.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_groupmod_group_id,
            { "Group ID", "openflow_v4.groupmod.group_id",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_groupmod_group_id_reserved,
            { "Group ID", "openflow_v4.groupmod.group_id",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_group_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_portmod_port_no,
            { "Port no", "openflow_v4.portmod.port_no",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_portmod_port_no_reserved,
            { "Port no", "openflow_v4.portmod.port_no",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_port_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_portmod_pad,
            { "Pad", "openflow_v4.portmod.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_portmod_hw_addr,
            { "Hw addr", "openflow_v4.portmod.hw_addr",
               FT_ETHER, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_portmod_pad2,
            { "Pad", "openflow_v4.portmod.pad2",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_portmod_config,
            { "Config", "openflow_v4.portmod.config",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_portmod_config_port_down,
            { "OFPPC_PORT_DOWN", "openflow_v4.portmod.config.port_down",
               FT_BOOLEAN, 32, NULL, OFPPC_PORT_DOWN,
               NULL, HFILL }
        },
        { &hf_openflow_v4_portmod_config_no_recv,
            { "OFPPC_NO_RECV", "openflow_v4.portmod.config.no_recv",
               FT_BOOLEAN, 32, NULL, OFPPC_NO_RECV,
               NULL, HFILL }
        },
        { &hf_openflow_v4_portmod_config_no_fwd,
            { "OFPPC_NO_FWD", "openflow_v4.portmod.config.no_fwd",
               FT_BOOLEAN, 32, NULL, OFPPC_NO_FWD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_portmod_config_no_packet_in,
            { "OFPPC_NO_PACKET_IN", "openflow_v4.portmod.config.no_packet_in",
               FT_BOOLEAN, 32, NULL, OFPPC_NO_PACKET_IN,
               NULL, HFILL }
        },
        { &hf_openflow_v4_portmod_mask,
            { "Mask", "openflow_v4.portmod.mask",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_portmod_mask_port_down,
            { "OFPPC_PORT_DOWN", "openflow_v4.portmod.mask.port_down",
               FT_BOOLEAN, 32, NULL, OFPPC_PORT_DOWN,
               NULL, HFILL }
        },
        { &hf_openflow_v4_portmod_mask_no_recv,
            { "OFPPC_NO_RECV", "openflow_v4.portmod.mask.no_recv",
               FT_BOOLEAN, 32, NULL, OFPPC_NO_RECV,
               NULL, HFILL }
        },
        { &hf_openflow_v4_portmod_mask_no_fwd,
            { "OFPPC_NO_FWD", "openflow_v4.portmod.mask.no_fwd",
               FT_BOOLEAN, 32, NULL, OFPPC_NO_FWD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_portmod_mask_no_packet_in,
            { "OFPPC_NO_PACKET_IN", "openflow_v4.portmod.mask.no_packet_in",
               FT_BOOLEAN, 32, NULL, OFPPC_NO_PACKET_IN,
               NULL, HFILL }
        },
        { &hf_openflow_v4_portmod_advertise,
            { "Advertise", "openflow_v4.portmod.advertise",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_portmod_advertise_10mb_hd,
            { "OFPPF_10MB_HD", "openflow_v4.portmod.advertise.10mb_hd",
               FT_BOOLEAN, 32, NULL, OFPPF_10MB_HD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_portmod_advertise_10mb_fd,
            { "OFPPF_10MB_FD", "openflow_v4.portmod.advertise.10mb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_10MB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_portmod_advertise_100mb_hd,
            { "OFPPF_100MB_HD", "openflow_v4.portmod.advertise.100mb_hd",
               FT_BOOLEAN, 32, NULL, OFPPF_100MB_HD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_portmod_advertise_100mb_fd,
            { "OFPPF_100MB_FD", "openflow_v4.portmod.advertise.100mb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_100MB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_portmod_advertise_1gb_hd,
            { "OFPPF_1GB_HD", "openflow_v4.portmod.advertise.1gb_hd",
               FT_BOOLEAN, 32, NULL, OFPPF_1GB_HD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_portmod_advertise_1gb_fd,
            { "OFPPF_1GB_FD", "openflow_v4.portmod.advertise.1gb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_1GB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_portmod_advertise_10gb_fd,
            { "OFPPF_10_GB_FD", "openflow_v4.portmod.advertise.10gb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_10GB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_portmod_advertise_40gb_fd,
            { "OFPPF_40GB_FD", "openflow_v4.portmod.advertise.40gb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_40GB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_portmod_advertise_100gb_fd,
            { "OFPPF_100_GB_FD", "openflow_v4.portmod.advertise.100_gb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_100GB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_portmod_advertise_1tb_fd,
            { "OFPPF_1TB_FD", "openflow_v4.portmod.advertise.1tb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_1TB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_portmod_advertise_other,
            { "OFPPF_OTHER", "openflow_v4.portmod.advertise.other",
               FT_BOOLEAN, 32, NULL, OFPPF_OTHER,
               NULL, HFILL }
        },
        { &hf_openflow_v4_portmod_advertise_copper,
            { "OFPPF_COPPER", "openflow_v4.portmod.advertise.copper",
               FT_BOOLEAN, 32, NULL, OFPPF_COPPER,
               NULL, HFILL }
        },
        { &hf_openflow_v4_portmod_advertise_fiber,
            { "OFPPF_FIBER", "openflow_v4.portmod.advertise.fiber",
               FT_BOOLEAN, 32, NULL, OFPPF_FIBER,
               NULL, HFILL }
        },
        { &hf_openflow_v4_portmod_advertise_autoneg,
            { "OFPPF_AUTONEG", "openflow_v4.portmod.advertise.autoneg",
               FT_BOOLEAN, 32, NULL, OFPPF_AUTONEG,
               NULL, HFILL }
        },
        { &hf_openflow_v4_portmod_advertise_pause,
            { "OFPPF_PAUSE", "openflow_v4.portmod.advertise.pause",
               FT_BOOLEAN, 32, NULL, OFPPF_PAUSE,
               NULL, HFILL }
        },
        { &hf_openflow_v4_portmod_advertise_pause_asym,
            { "OFPPF_PAUSE_ASYM", "openflow_v4.portmod.advertise.pause_asym",
               FT_BOOLEAN, 32, NULL, OFPPF_PAUSE_ASYM,
               NULL, HFILL }
        },
        { &hf_openflow_v4_portmod_pad3,
            { "Pad", "openflow_v4.portmod.pad3",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_tablemod_table_id,
            { "Table ID", "openflow_v4.tablemod.table_id",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_tablemod_table_id_reserved,
            { "Table ID", "openflow_v4.tablemod.table_id",
               FT_UINT8, BASE_DEC, VALS(openflow_v4_table_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_tablemod_pad,
            { "Pad", "openflow_v4.tablemod.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_tablemod_config,
            { "Config", "openflow_v4.tablemod.config",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_stats_request_table_id,
            { "Table ID", "openflow_v4.flow_stats_request.table_id",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_stats_request_table_id_reserved,
            { "Table ID", "openflow_v4.flow_stats_request.table_id",
               FT_UINT8, BASE_DEC, VALS(openflow_v4_table_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_stats_request_pad,
            { "Pad", "openflow_v4.flow_stats_request.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_stats_request_out_port,
            { "Out port", "openflow_v4.flow_stats_request.out_port",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_stats_request_out_port_reserved,
            { "Out port", "openflow_v4.flow_stats_request.out_port",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_port_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_stats_request_out_group,
            { "Out group", "openflow_v4.flow_stats_request.out_group",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_stats_request_out_group_reserved,
            { "Out group", "openflow_v4.flow_stats_request.out_group",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_group_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_stats_request_pad2,
            { "Pad", "openflow_v4.flow_stats_request.pad2",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_stats_request_cookie,
            { "Cookie", "openflow_v4.flow_stats_request.cookie",
               FT_UINT64, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_stats_request_cookie_mask,
            { "Cookie mask", "openflow_v4.flow_stats_request.cookie_mask",
               FT_UINT64, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_aggregate_stats_request_table_id,
            { "Table ID", "openflow_v4.aggregate_stats_request.table_id",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_aggregate_stats_request_table_id_reserved,
            { "Table ID", "openflow_v4.aggregate_stats_request.table_id",
               FT_UINT8, BASE_DEC, VALS(openflow_v4_table_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_aggregate_stats_request_pad,
            { "Pad", "openflow_v4.aggregate_stats_request.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_aggregate_stats_request_out_port,
            { "Out port", "openflow_v4.aggregate_stats_request.out_port",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_aggregate_stats_request_out_port_reserved,
            { "Out port", "openflow_v4.aggregate_stats_request.out_port",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_port_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_aggregate_stats_request_out_group,
            { "Out group", "openflow_v4.aggregate_stats_request.out_group",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_aggregate_stats_request_out_group_reserved,
            { "Out group", "openflow_v4.aggregate_stats_request.out_group",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_group_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_aggregate_stats_request_pad2,
            { "Pad", "openflow_v4.aggregate_stats_request.pad2",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_aggregate_stats_request_cookie,
            { "Cookie", "openflow_v4.aggregate_stats_request.cookie",
               FT_UINT64, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_aggregate_stats_request_cookie_mask,
            { "Cookie mask", "openflow_v4.aggregate_stats_request.cookie_mask",
               FT_UINT64, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_table_feature_prop_type,
            { "Type", "openflow_v4.table_feature_prop.type",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_table_feature_prop_type_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_table_feature_prop_length,
            { "Length", "openflow_v4.table_feature_prop.length",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_table_feature_prop_next_tables_next_table_id,
            { "Next table ID", "openflow_v4.table_feature_prop.next_tables.next_table_id",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_table_feature_prop_experimenter_experimenter,
            { "Experimenter", "openflow_v4.table_feature_prop.experimenter.experimenter",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_table_feature_prop_experimenter_exp_type,
            { "Experimenter type", "openflow_v4.table_feature_prop.experimenter.exp_type",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_table_feature_prop_pad,
            { "Pad", "openflow_v4.table_feature_prop.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_table_features_length,
            { "Length", "openflow_v4.table_features.length",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_table_features_table_id,
            { "Table ID", "openflow_v4.table_features.table_id",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_table_features_pad,
            { "Pad", "openflow_v4.table_features.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_table_features_name,
            { "Name", "openflow_v4.table_features.name",
               FT_STRING, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_table_features_metadata_match,
            { "Metadata match", "openflow_v4.table_features.metadata_match",
               FT_UINT64, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_table_features_metadata_write,
            { "Metadata write", "openflow_v4.table_features.metadata_write",
               FT_UINT64, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_table_features_config,
            { "Config", "openflow_v4.table_features.config",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_table_features_max_entries,
            { "Max entries", "openflow_v4.table_features.max_entries",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_stats_request_port_no,
            { "Port number", "openflow_v4.port_stats_request.port_no",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_stats_request_port_no_reserved,
            { "Port number", "openflow_v4.port_stats_request.port_no",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_port_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_stats_request_pad,
            { "Pad", "openflow_v4.port_stats_request.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_queue_stats_request_port_no,
            { "Port number", "openflow_v4.queue_stats_request.port_no",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_queue_stats_request_port_no_reserved,
            { "Port number", "openflow_v4.queue_stats_request.port_no",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_port_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_queue_stats_request_queue_id,
            { "Queue ID", "openflow_v4.queue_stats_request.queue_id",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_queue_stats_request_queue_id_reserved,
            { "Queue ID", "openflow_v4.queue_stats_request.queue_id",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_queue_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_stats_request_group_id,
            { "Group ID", "openflow_v4.group_stats_request.group_id",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_stats_request_group_id_reserved,
            { "Group ID", "openflow_v4.group_stats_request.group_id",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_group_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_stats_request_pad,
            { "Pad", "openflow_v4.group_stats_request.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_stats_request_meter_id,
            { "Meter ID", "openflow_v4.meter_stats_request.meter_id",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_stats_request_meter_id_reserved,
            { "Meter ID", "openflow_v4.meter_stats_request.meter_id",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_meter_id_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_stats_request_pad,
            { "Pad", "openflow_v4.meter_stats_request.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_config_request_meter_id,
            { "Meter ID", "openflow_v4.meter_config_request.meter_id",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_config_request_meter_id_reserved,
            { "Meter ID", "openflow_v4.meter_config_request.meter_id",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_meter_id_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_config_request_pad,
            { "Pad", "openflow_v4.aggregate_config_request.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_multipart_request_type ,
            { "Type", "openflow_v4.multipart_request.type",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_multipart_type_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_multipart_request_flags,
            { "Flags", "openflow_v4.multipart_request.flags",
               FT_UINT16, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_multipart_request_flags_more,
            { "OFPMPF_REQ_MORE", "openflow_v4.multipart_request.flags.more",
               FT_UINT16, BASE_HEX, NULL, OFPMPF_REQ_MORE,
               NULL, HFILL }
        },
        { &hf_openflow_v4_multipart_request_pad,
            { "Pad", "openflow_v4.multipart_request.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_multipart_request_experimenter_experimenter,
            { "Experimenter", "openflow_v4.multipart_request.experimenter.experimenter",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_multipart_request_experimenter_exp_type,
            { "Experimenter type", "openflow_v4.multipart_request.experimenter.exp_type",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_switch_description_mfr_desc,
            { "Manufacturer desc.", "openflow_v4.switch_description.mfr_desc",
               FT_STRING, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_switch_description_hw_desc,
            { "Hardware desc.", "openflow_v4.switch_description.hw_desc",
               FT_STRING, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_switch_description_sw_desc,
            { "Software desc.", "openflow_v4.switch_description.sw_desc",
               FT_STRING, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_switch_description_serial_num,
            { "Serial no.", "openflow_v4.switch_description.serial_num",
               FT_STRING, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_switch_description_dp_desc,
            { "Datapath desc.", "openflow_v4.switch_description.dp_desc",
               FT_STRING, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_stats_length,
            { "Length", "openflow_v4.flow_stats.length",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_stats_table_id,
            { "Table ID", "openflow_v4.flow_stats.table_id",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_stats_pad,
            { "Pad", "openflow_v4.flow_stats.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_stats_duration_sec,
            { "Duration sec", "openflow_v4.flow_stats.duration_sec",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_stats_duration_nsec,
            { "Duration nsec", "openflow_v4.flow_stats.duration_nsec",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_stats_priority,
            { "Priority", "openflow_v4.flow_stats.priority",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_stats_idle_timeout,
            { "Idle timeout", "openflow_v4.flow_stats.idle_timeout",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_stats_hard_timeout,
            { "Hard timeout", "openflow_v4.flow_stats.hard_timeout",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_stats_flags,
            { "Flags", "openflow_v4.flow_stats.flags",
               FT_UINT16, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_stats_flags_send_flow_rem,
            { "Send flow removed", "openflow_v4.flow_stats.flags.send_flow_rem",
               FT_BOOLEAN, 16, NULL, OFPFF_SEND_FLOW_REM,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_stats_flags_check_overlap,
            { "Check overlap", "openflow_v4.flow_stats.flags.check_overlap",
               FT_BOOLEAN, 16, NULL, OFPFF_CHECK_OVERLAP,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_stats_flags_reset_counts,
            { "Reset counts", "openflow_v4.flow_stats.flags.reset_counts",
               FT_BOOLEAN, 16, NULL, OFPFF_RESET_COUNTS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_stats_flags_no_packet_counts,
            { "Don't count packets", "openflow_v4.flow_stats.flags.no_packet_counts",
               FT_BOOLEAN, 16, NULL, OFPFF_NO_PKT_COUNTS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_stats_flags_no_byte_counts,
            { "Don't count bytes", "openflow_v4.flow_stats.flags.no_byte_counts",
               FT_BOOLEAN, 16, NULL, OFPFF_NO_BYT_COUNTS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_stats_pad2,
            { "Pad", "openflow_v4.flow_stats.pad2",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_stats_cookie,
            { "Cookie", "openflow_v4.flow_stats.cookie",
               FT_UINT64, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_stats_packet_count,
            { "Packet count", "openflow_v4.flow_stats.packet_count",
               FT_UINT64, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_flow_stats_byte_count,
            { "Byte count", "openflow_v4.flow_stats.byte_count",
               FT_UINT64, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_aggregate_stats_packet_count,
            { "Packet count", "openflow_v4.aggregate_stats.packet_count",
               FT_UINT64, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_aggregate_stats_byte_count,
            { "Byte count", "openflow_v4.aggregate_stats.byte_count",
               FT_UINT64, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_aggregate_stats_flow_count,
            { "Flow count", "openflow_v4.aggregate_stats.flow_count",
               FT_UINT64, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_aggregate_stats_pad,
            { "Pad", "openflow_v4.aggregate_stats.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_table_stats_table_id,
            { "Table ID", "openflow_v4.table_stats.table_id",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_table_stats_table_id_reserved,
            { "Table ID", "openflow_v4.table_stats.table_id",
               FT_UINT8, BASE_DEC, VALS(openflow_v4_table_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_table_stats_pad,
            { "Pad", "openflow_v4.table_stats.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_table_stats_active_count,
            { "Active count", "openflow_v4.table_stats.active_count",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_table_stats_lookup_count,
            { "Lookup count", "openflow_v4.table_stats.lookup_count",
               FT_UINT64, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_table_stats_match_count,
            { "Match count", "openflow_v4.table_stats.match_count",
               FT_UINT64, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_stats_port_no,
            { "Port number", "openflow_v4.port_stats.port_no",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_stats_port_no_reserved,
            { "Port number", "openflow_v4.port_stats.port_no",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_port_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_stats_pad,
            { "Pad", "openflow_v4.port_stats.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_stats_rx_packets,
            { "Rx packets", "openflow_v4.port_stats.rx_packets",
               FT_UINT64, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_stats_tx_packets,
            { "Tx packets", "openflow_v4.port_stats.tx_packets",
               FT_UINT64, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_stats_rx_bytes,
            { "Rx bytes", "openflow_v4.port_stats.rx_bytes",
               FT_UINT64, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_stats_tx_bytes,
            { "Tx bytes", "openflow_v4.port_stats.tx_bytes",
               FT_UINT64, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_stats_rx_dropped,
            { "Rx dropped", "openflow_v4.port_stats.rx_dropped",
               FT_UINT64, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_stats_tx_dropped,
            { "Tx dropped", "openflow_v4.port_stats.tx_dropped",
               FT_UINT64, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_stats_rx_errors,
            { "Rx errors", "openflow_v4.port_stats.rx_errors",
               FT_UINT64, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_stats_tx_errors,
            { "Tx errors", "openflow_v4.port_stats.tx_errors",
               FT_UINT64, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_stats_rx_frame_error,
            { "Rx frame errors", "openflow_v4.port_stats.rx_frame_error",
               FT_UINT64, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_stats_rx_over_error,
            { "Rx overrun errors", "openflow_v4.port_stats.rx_over_error",
               FT_UINT64, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_stats_rx_crc_error,
            { "Rx CRC errors", "openflow_v4.port_stats.rx_crc_error",
               FT_UINT64, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_stats_collisions,
            { "Collisions", "openflow_v4.port_stats.collisions",
               FT_UINT64, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_stats_duration_sec,
            { "Duration sec", "openflow_v4.port_stats.duration_sec",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_stats_duration_nsec,
            { "Duration nsec", "openflow_v4.port_stats.duration_nsec",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_queue_stats_port_no,
            { "Port number", "openflow_v4.queue_stats.port_no",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_queue_stats_port_no_reserved,
            { "Port number", "openflow_v4.queue_stats.port_no",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_port_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_queue_stats_queue_id,
            { "Queue ID", "openflow_v4.queue_stats.queue_id",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_queue_stats_queue_id_reserved,
            { "Queue ID", "openflow_v4.queue_stats.queue_id",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_queue_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_queue_stats_tx_bytes,
            { "Tx bytes", "openflow_v4.queue_stats.tx_bytes",
               FT_UINT64, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_queue_stats_tx_packets,
            { "Tx packets", "openflow_v4.quee_stats.tx_packets",
               FT_UINT64, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_queue_stats_tx_errors,
            { "Tx errors", "openflow_v4.port_stats.tx_errors",
               FT_UINT64, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_queue_stats_duration_sec,
            { "Duration sec", "openflow_v4.queue_stats.duration_sec",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_queue_stats_duration_nsec,
            { "Duration nsec", "openflow_v4.queue_stats.duration_nsec",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_bucket_counter_packet_count,
            { "Packet count", "openflow_v4.bucket_counter.packet_count",
               FT_UINT64, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_bucket_counter_byte_count,
            { "Byte count", "openflow_v4.bucket_counter.byte_count",
               FT_UINT64, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_stats_length,
            { "Length", "openflow_v4.group_stats.length",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_stats_pad,
            { "Pad", "openflow_v4.group_stats.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_stats_group_id,
            { "Group ID", "openflow_v4.group_stats.group_id",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_stats_group_id_reserved,
            { "Group ID", "openflow_v4.group_stats.group_id",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_group_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_stats_ref_count,
            { "Ref. count", "openflow_v4.group_stats.ref_count",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_stats_pad2,
            { "Pad", "openflow_v4.group_stats.pad2",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_stats_packet_count,
            { "Packet count", "openflow_v4.group_stats.packet_count",
               FT_UINT64, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_stats_byte_count,
            { "Byte count", "openflow_v4.group_stats.byte_count",
               FT_UINT64, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_desc_length,
            { "Length", "openflow_v4.group_desc.length",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_desc_type,
            { "Type", "openflow_v4.group_desc.type",
               FT_UINT8, BASE_DEC, VALS(openflow_v4_group_type_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_desc_pad,
            { "Pad", "openflow_v4.group_desc.pad2",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_desc_group_id,
            { "Group ID", "openflow_v4.group_desc.group_id",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_desc_group_id_reserved,
            { "Group ID", "openflow_v4.group_desc.group_id",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_group_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_types,
            { "Types", "openflow_v4.group_features.types",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_types_all,
            { "OFPGT_ALL", "openflow_v4.group_features.types.all",
               FT_BOOLEAN, 32, NULL, 1 << OFPGT_ALL,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_types_select,
            { "OFPGT_SELECT", "openflow_v4.group_features.types.select",
               FT_BOOLEAN, 32, NULL, 1 << OFPGT_SELECT,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_types_indirect,
            { "OFPGT_INDIRECT", "openflow_v4.group_features.types.indirect",
               FT_BOOLEAN, 32, NULL, 1 << OFPGT_INDIRECT,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_types_ff,
            { "OFPGT_FF", "openflow_v4.group_features.types.ff",
               FT_BOOLEAN, 32, NULL, 1 << OFPGT_FF,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_capabilities,
            { "Capabilities", "openflow_v4.group_features.capabilities",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_capabilities_select_weight,
            { "OFPGFC_SELECT_WEIGHT", "openflow_v4.group_features.capabilities.select_weight",
               FT_BOOLEAN, 32, NULL, OFPGFC_SELECT_WEIGHT,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_capabilities_select_liveness,
            { "OFPGFC_SELECT_LIVENESS", "openflow_v4.group_features.capabilities.select_liveness",
               FT_BOOLEAN, 32, NULL, OFPGFC_SELECT_LIVENESS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_capabilities_chaining,
            { "OFPGFC_CHAINING", "openflow_v4.group_features.capabilities.chaining",
               FT_BOOLEAN, 32, NULL, OFPGFC_CHAINING,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_capabilities_chaining_checks,
            { "OFPGFC_CHAINING_CHECKS", "openflow_v4.group_features.capabilities.chaining_checks",
               FT_BOOLEAN, 32, NULL, OFPGFC_CHAINING_CHECKS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_max_groups_all,
            { "Max groups (all)", "openflow_v4.group_stats.max_groups.all",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_max_groups_select,
            { "Max groups (select)", "openflow_v4.group_stats.max_groups.select",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_max_groups_indirect,
            { "Max groups (indirect)", "openflow_v4.group_stats.max_groups.indirect",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_max_groups_ff,
            { "Max groups (ff)", "openflow_v4.group_stats.max_groups.ff",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_all,
            { "Actions (all)", "openflow_v4.group_features.actions.all",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_all_output,
            { "OFPAT_OUTPUT", "openflow_v4.group_features.actions.all.output",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_OUTPUT,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_all_copy_ttl_out,
            { "OFPAT_COPY_TTL_OUT", "openflow_v4.group_features.actions.all.copy_ttl_out",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_COPY_TTL_OUT,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_all_copy_ttl_in,
            { "OFPAT_COPY_TTL_IN", "openflow_v4.group_features.actions.all.copy_ttl_in",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_COPY_TTL_IN,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_all_set_mpls_ttl,
            { "OFPAT_SET_MPLS_TTL", "openflow_v4.group_features.actions.all.set_mpls_ttl",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_SET_MPLS_TTL,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_all_dec_mpls_ttl,
            { "OFPAT_DEC_MPLS_TTL", "openflow_v4.group_features.actions.all.dec_mpls_ttl",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_DEC_MPLS_TTL,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_all_push_vlan,
            { "OFPAT_PUSH_VLAN", "openflow_v4.group_features.actions.all.push_vlan",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_PUSH_VLAN,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_all_pop_vlan,
            { "OFPAT_POP_VLAN", "openflow_v4.group_features.actions.all.pop_vlan",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_POP_VLAN,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_all_push_mpls,
            { "OFPAT_PUSH_MPLS", "openflow_v4.group_features.actions.all.push_mpls",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_PUSH_MPLS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_all_pop_mpls,
            { "OFPAT_POP_MPLS", "openflow_v4.group_features.actions.all.pop_mpls",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_POP_MPLS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_all_set_queue,
            { "OFPAT_SET_QUEUE", "openflow_v4.group_features.actions.all.set_queue",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_SET_QUEUE,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_all_group,
            { "OFPAT_GROUP", "openflow_v4.group_features.actions.all.group",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_GROUP,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_all_set_nw_ttl,
            { "OFPAT_SET_NW_TTL", "openflow_v4.group_features.actions.all.set_nw_ttl",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_SET_NW_TTL,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_all_dec_nw_ttl,
            { "OFPAT_DEC_NW_TTL", "openflow_v4.group_features.actions.all.dec_nw_ttl",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_DEC_NW_TTL,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_all_set_field,
            { "OFPAT_SET_FIELD", "openflow_v4.group_features.actions.all.set_field",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_SET_FIELD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_all_push_pbb,
            { "OFPAT_PUSH_PBB", "openflow_v4.group_features.actions.all.push_pbb",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_PUSH_PBB,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_all_pop_pbb,
            { "OFPAT_POP_PBB", "openflow_v4.group_features.actions.all.pop_pbb",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_POP_PBB,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_select,
            { "Actions (select)", "openflow_v4.group_features.actions.select",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_select_output,
            { "OFPAT_OUTPUT", "openflow_v4.group_features.actions.select.output",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_OUTPUT,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_select_copy_ttl_out,
            { "OFPAT_COPY_TTL_OUT", "openflow_v4.group_features.actions.select.copy_ttl_out",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_COPY_TTL_OUT,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_select_copy_ttl_in,
            { "OFPAT_COPY_TTL_IN", "openflow_v4.group_features.actions.select.copy_ttl_in",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_COPY_TTL_IN,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_select_set_mpls_ttl,
            { "OFPAT_SET_MPLS_TTL", "openflow_v4.group_features.actions.select.set_mpls_ttl",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_SET_MPLS_TTL,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_select_dec_mpls_ttl,
            { "OFPAT_DEC_MPLS_TTL", "openflow_v4.group_features.actions.select.dec_mpls_ttl",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_DEC_MPLS_TTL,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_select_push_vlan,
            { "OFPAT_PUSH_VLAN", "openflow_v4.group_features.actions.select.push_vlan",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_PUSH_VLAN,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_select_pop_vlan,
            { "OFPAT_POP_VLAN", "openflow_v4.group_features.actions.select.pop_vlan",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_POP_VLAN,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_select_push_mpls,
            { "OFPAT_PUSH_MPLS", "openflow_v4.group_features.actions.select.push_mpls",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_PUSH_MPLS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_select_pop_mpls,
            { "OFPAT_POP_MPLS", "openflow_v4.group_features.actions.select.pop_mpls",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_POP_MPLS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_select_set_queue,
            { "OFPAT_SET_QUEUE", "openflow_v4.group_features.actions.select.set_queue",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_SET_QUEUE,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_select_group,
            { "OFPAT_GROUP", "openflow_v4.group_features.actions.select.group",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_GROUP,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_select_set_nw_ttl,
            { "OFPAT_SET_NW_TTL", "openflow_v4.group_features.actions.select.set_nw_ttl",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_SET_NW_TTL,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_select_dec_nw_ttl,
            { "OFPAT_DEC_NW_TTL", "openflow_v4.group_features.actions.select.dec_nw_ttl",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_DEC_NW_TTL,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_select_set_field,
            { "OFPAT_SET_FIELD", "openflow_v4.group_features.actions.select.set_field",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_SET_FIELD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_select_push_pbb,
            { "OFPAT_PUSH_PBB", "openflow_v4.group_features.actions.select.push_pbb",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_PUSH_PBB,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_select_pop_pbb,
            { "OFPAT_POP_PBB", "openflow_v4.group_features.actions.select.pop_pbb",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_POP_PBB,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_indirect,
            { "Actions (indirect)", "openflow_v4.group_features.actions.indirect",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_indirect_output,
            { "OFPAT_OUTPUT", "openflow_v4.group_features.actions.indirect.output",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_OUTPUT,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_indirect_copy_ttl_out,
            { "OFPAT_COPY_TTL_OUT", "openflow_v4.group_features.actions.indirect.copy_ttl_out",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_COPY_TTL_OUT,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_indirect_copy_ttl_in,
            { "OFPAT_COPY_TTL_IN", "openflow_v4.group_features.actions.indirect.copy_ttl_in",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_COPY_TTL_IN,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_indirect_set_mpls_ttl,
            { "OFPAT_SET_MPLS_TTL", "openflow_v4.group_features.actions.indirect.set_mpls_ttl",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_SET_MPLS_TTL,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_indirect_dec_mpls_ttl,
            { "OFPAT_DEC_MPLS_TTL", "openflow_v4.group_features.actions.indirect.dec_mpls_ttl",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_DEC_MPLS_TTL,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_indirect_push_vlan,
            { "OFPAT_PUSH_VLAN", "openflow_v4.group_features.actions.indirect.push_vlan",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_PUSH_VLAN,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_indirect_pop_vlan,
            { "OFPAT_POP_VLAN", "openflow_v4.group_features.actions.indirect.pop_vlan",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_POP_VLAN,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_indirect_push_mpls,
            { "OFPAT_PUSH_MPLS", "openflow_v4.group_features.actions.indirect.push_mpls",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_PUSH_MPLS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_indirect_pop_mpls,
            { "OFPAT_POP_MPLS", "openflow_v4.group_features.actions.indirect.pop_mpls",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_POP_MPLS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_indirect_set_queue,
            { "OFPAT_SET_QUEUE", "openflow_v4.group_features.actions.indirect.set_queue",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_SET_QUEUE,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_indirect_group,
            { "OFPAT_GROUP", "openflow_v4.group_features.actions.indirect.group",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_GROUP,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_indirect_set_nw_ttl,
            { "OFPAT_SET_NW_TTL", "openflow_v4.group_features.actions.indirect.set_nw_ttl",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_SET_NW_TTL,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_indirect_dec_nw_ttl,
            { "OFPAT_DEC_NW_TTL", "openflow_v4.group_features.actions.indirect.dec_nw_ttl",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_DEC_NW_TTL,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_indirect_set_field,
            { "OFPAT_SET_FIELD", "openflow_v4.group_features.actions.indirect.set_field",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_SET_FIELD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_indirect_push_pbb,
            { "OFPAT_PUSH_PBB", "openflow_v4.group_features.actions.indirect.push_pbb",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_PUSH_PBB,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_indirect_pop_pbb,
            { "OFPAT_POP_PBB", "openflow_v4.group_features.actions.indirect.pop_pbb",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_POP_PBB,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_ff,
            { "Actions (ff)", "openflow_v4.group_features.actions.ff",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_ff_output,
            { "OFPAT_OUTPUT", "openflow_v4.group_features.actions.ff.output",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_OUTPUT,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_ff_copy_ttl_out,
            { "OFPAT_COPY_TTL_OUT", "openflow_v4.group_features.actions.ff.copy_ttl_out",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_COPY_TTL_OUT,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_ff_copy_ttl_in,
            { "OFPAT_COPY_TTL_IN", "openflow_v4.group_features.actions.ff.copy_ttl_in",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_COPY_TTL_IN,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_ff_set_mpls_ttl,
            { "OFPAT_SET_MPLS_TTL", "openflow_v4.group_features.actions.ff.set_mpls_ttl",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_SET_MPLS_TTL,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_ff_dec_mpls_ttl,
            { "OFPAT_DEC_MPLS_TTL", "openflow_v4.group_features.actions.ff.dec_mpls_ttl",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_DEC_MPLS_TTL,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_ff_push_vlan,
            { "OFPAT_PUSH_VLAN", "openflow_v4.group_features.actions.ff.push_vlan",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_PUSH_VLAN,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_ff_pop_vlan,
            { "OFPAT_POP_VLAN", "openflow_v4.group_features.actions.ff.pop_vlan",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_POP_VLAN,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_ff_push_mpls,
            { "OFPAT_PUSH_MPLS", "openflow_v4.group_features.actions.ff.push_mpls",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_PUSH_MPLS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_ff_pop_mpls,
            { "OFPAT_POP_MPLS", "openflow_v4.group_features.actions.ff.pop_mpls",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_POP_MPLS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_ff_set_queue,
            { "OFPAT_SET_QUEUE", "openflow_v4.group_features.actions.ff.set_queue",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_SET_QUEUE,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_ff_group,
            { "OFPAT_GROUP", "openflow_v4.group_features.actions.ff.group",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_GROUP,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_ff_set_nw_ttl,
            { "OFPAT_SET_NW_TTL", "openflow_v4.group_features.actions.ff.set_nw_ttl",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_SET_NW_TTL,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_ff_dec_nw_ttl,
            { "OFPAT_DEC_NW_TTL", "openflow_v4.group_features.actions.ff.dec_nw_ttl",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_DEC_NW_TTL,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_ff_set_field,
            { "OFPAT_SET_FIELD", "openflow_v4.group_features.actions.ff.set_field",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_SET_FIELD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_ff_push_pbb,
            { "OFPAT_PUSH_PBB", "openflow_v4.group_features.actions.ff.push_pbb",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_PUSH_PBB,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_features_actions_ff_pop_pbb,
            { "OFPAT_POP_PBB", "openflow_v4.group_features.actions.ff.pop_pbb",
               FT_BOOLEAN, 32, NULL, 1 << OFPAT_POP_PBB,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_band_stats_packet_band_count,
            { "Packet count", "openflow_v4.meter_band_stats.packet_band_count",
               FT_UINT64, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_band_stats_byte_band_count,
            { "Byte count", "openflow_v4.meter_band_stats.byte_band_count",
               FT_UINT64, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_stats_meter_id,
            { "Meter ID", "openflow_v4.meter_stats.meter_id",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_stats_meter_id_reserved,
            { "Meter ID", "openflow_v4.meter_stats.meter_id",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_meter_id_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_stats_len,
            { "Length", "openflow_v4.meter_stats.length",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_stats_pad,
            { "Pad", "openflow_v4.meter_stats.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_stats_flow_count,
            { "Flow count", "openflow_v4.meter_stats.flow_count",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_stats_packet_in_count,
            { "Packet in count", "openflow_v4.meter_stats.packet_in_count",
               FT_UINT64, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_stats_byte_in_count,
            { "Byte in count", "openflow_v4.meter_stats.byte_in_count",
               FT_UINT64, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_stats_duration_sec,
            { "Duration sec", "openflow_v4.meter_stats.duration_sec",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_stats_duration_nsec,
            { "Duration nsec", "openflow_v4.meter_stats.duration_nsec",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_config_len,
            { "Length", "openflow_v4.meter_stats.len",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_config_flags,
            { "Flags", "openflow_v4.meter_config.flags",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_config_flags_kbps,
            { "OFPMF_KBPS", "openflow_v4.meter_config.flags.kbps",
               FT_BOOLEAN, 32, NULL, OFPMF_KBPS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_config_flags_pktps,
            { "OFPMF_PKTPS", "openflow_v4.meter_config.flags.ptkps",
               FT_BOOLEAN, 32, NULL, OFPMF_PKTPS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_config_flags_burst,
            { "OFPMF_BURST", "openflow_v4.meter_config.flags.burst",
               FT_BOOLEAN, 32, NULL, OFPMF_BURST,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_config_flags_stats,
            { "OFPMF_STATS", "openflow_v4.meter_config.flags.stats",
               FT_BOOLEAN, 32, NULL, OFPMF_STATS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_config_meter_id,
            { "Meter ID", "openflow_v4.meter_config.meter_id",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_config_meter_id_reserved,
            { "Meter ID", "openflow_v4.meter_config.meter_id",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_meter_id_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_features_max_meter,
            { "Max meters", "openflow_v4.meter_features.max_meter",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_features_band_types,
            { "Band types", "openflow_v4.features.band_types",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_features_band_types_drop,
            { "OFPMBT_DROP", "openflow_v4.meter_features.band_types.drop",
               FT_BOOLEAN, 32, NULL, 1 << OFPMBT_DROP,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_features_band_types_dscp_remark,
            { "OFPMBT_DSCP_REMARK", "openflow_v4.meter_features.band_types.dscp_remark",
               FT_BOOLEAN, 32, NULL, 1 << OFPMBT_DSCP_REMARK,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_features_capabilities,
            { "Capabilities", "openflow_v4.meter_features.capabilities",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_features_capabilities_kbps,
            { "OFPMF_KBPS", "openflow_v4.meter_features.capabilities.kbps",
               FT_BOOLEAN, 32, NULL, OFPMF_KBPS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_features_capabilities_pktps,
            { "OFPMF_PKTPS", "openflow_v4.meter_features.capabilities.ptkps",
               FT_BOOLEAN, 32, NULL, OFPMF_PKTPS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_features_capabilities_burst,
            { "OFPMF_BURST", "openflow_v4.meter_features.capabilities.burst",
               FT_BOOLEAN, 32, NULL, OFPMF_BURST,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_features_capabilities_stats,
            { "OFPMF_STATS", "openflow_v4.meter_features.capabilities.stats",
               FT_BOOLEAN, 32, NULL, OFPMF_STATS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_features_max_bands,
            { "Max bands", "openflow_v4.meter_features.max_bands",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_features_max_color,
            { "Max colors", "openflow_v4.meter_features.max_color",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_meter_features_pad,
            { "Pad", "openflow_v4.meter_features.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_multipart_reply_type ,
            { "Type", "openflow_v4.multipart_reply.type",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_multipart_type_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_multipart_reply_flags,
            { "Flags", "openflow_v4.multipart_reply.flags",
               FT_UINT16, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_multipart_reply_flags_more,
            { "OFPMPF_REPLY_MORE", "openflow_v4.multipart_reply.flags.more",
               FT_UINT16, BASE_HEX, NULL, OFPMPF_REPLY_MORE,
               NULL, HFILL }
        },
        { &hf_openflow_v4_multipart_reply_pad,
            { "Pad", "openflow_v4.multipart_reply.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_multipart_reply_experimenter_experimenter,
            { "Experimenter", "openflow_v4.multipart_reply.experimenter.experimenter",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_multipart_reply_experimenter_exp_type,
            { "Experimenter type", "openflow_v4.multipart_reply.experimenter.exp_type",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_queue_get_config_request_port,
            { "Port", "openflow_v4.queue_get_config_request.port",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_queue_get_config_request_port_reserved,
            { "Port", "openflow_v4.queue_get_config_request.port",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_port_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_queue_get_config_request_pad,
            { "Pad", "openflow_v4.queue_get_config_request.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_queue_prop_property,
            { "Property", "openflow_v4.queue_prop.property",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_queue_prop_property_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_queue_prop_len,
            { "Length", "openflow_v4.queue_prop.len",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_queue_prop_pad,
            { "Pad", "openflow_v4.queue_prop.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_queue_prop_min_rate_rate,
            { "Rate", "openflow_v4.queue_prop.min_rate.rate",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_queue_prop_min_rate_rate_reserved,
            { "Rate", "openflow_v4.queue_prop.min_rate.rate",
               FT_UINT16, BASE_HEX, VALS(openflow_v4_queue_prop_min_rate_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_queue_prop_min_rate_pad,
            { "Pad", "openflow_v4.queue_prop.min_rate.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_queue_prop_max_rate_rate,
            { "Rate", "openflow_v4.queue_prop.max_rate.rate",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_queue_prop_max_rate_rate_reserved,
            { "Rate", "openflow_v4.queue_prop.max_rate.rate",
               FT_UINT16, BASE_HEX, VALS(openflow_v4_queue_prop_max_rate_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_queue_prop_max_rate_pad,
            { "Pad", "openflow_v4.queue_prop.max_rate.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_queue_prop_experimenter_experimenter,
            { "Experimenter", "openflow_v4.queue_prop.experimenter.experimenter",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_queue_prop_experimenter_pad,
            { "Pad", "openflow_v4.queue_prop.experimenter.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_packet_queue_queue_id,
            { "Queue ID", "openflow_v4.packet_queue.queue_id",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_packet_queue_queue_id_reserved,
            { "Queue ID", "openflow_v4.packet_queue.queue_id",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_queue_id_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_packet_queue_port,
            { "Port", "openflow_v4.packet_queue.port",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_packet_queue_port_reserved,
            { "Port", "openflow_v4.packet_queue.port",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_port_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_packet_queue_len,
            { "Length", "openflow_v4.packet_queue.len",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_packet_queue_pad,
            { "Pad", "openflow_v4.packet_queue.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_queue_get_config_reply_port,
            { "Port", "openflow_v4.queue_get_config_reply.port",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_queue_get_config_reply_port_reserved,
            { "Port", "openflow_v4.queue_get_config_reply.port",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_port_reserved_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_queue_get_config_reply_pad,
            { "Pad", "openflow_v4.queue_get_config_reply.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_role_request_role,
            { "Role", "openflow_v4.role_request.role",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_controller_role_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_role_request_pad,
            { "Pad", "openflow_v4.role_request.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_role_request_generation_id,
            { "Generation ID", "openflow_v4.role_request.generation_id",
               FT_UINT64, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_role_reply_role,
            { "Role", "openflow_v4.role_reply.role",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_controller_role_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_role_reply_pad,
            { "Pad", "openflow_v4.role_reply.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_role_reply_generation_id,
            { "Generation ID", "openflow_v4.role_reply.generation_id",
               FT_UINT64, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_async_config_packet_in_mask_master,
            { "Packet_in mask (master)", "openflow_v4.async_config.packet_in_mask.master",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_async_config_packet_in_mask_master_no_match,
            { "OFPR_NO_MATCH", "openflow_v4.async_config.packet_in_mask.master.no_match",
               FT_BOOLEAN, 32, NULL, 1 << OFPR_NO_MATCH,
               NULL, HFILL }
        },
        { &hf_openflow_v4_async_config_packet_in_mask_master_action,
            { "OFPR_ACTION", "openflow_v4.async_config.packet_in_mask.master.action",
               FT_BOOLEAN, 32, NULL, 1 << OFPR_ACTION,
               NULL, HFILL }
        },
        { &hf_openflow_v4_async_config_packet_in_mask_master_invalid_ttl,
            { "OFPR_INVALID_TTL", "openflow_v4.async_config.packet_in_mask.master.invalid_ttl",
               FT_BOOLEAN, 32, NULL, 1 << OFPR_INVALID_TTL,
               NULL, HFILL }
        },
        { &hf_openflow_v4_async_config_packet_in_mask_slave,
            { "Packet_in mask (slave)", "openflow_v4.async_config.packet_in_mask.slave",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_async_config_packet_in_mask_slave_no_match,
            { "OFPR_NO_MATCH", "openflow_v4.async_config.packet_in_mask.slave.no_match",
               FT_BOOLEAN, 32, NULL, 1 << OFPR_NO_MATCH,
               NULL, HFILL }
        },
        { &hf_openflow_v4_async_config_packet_in_mask_slave_action,
            { "OFPR_ACTION", "openflow_v4.async_config.packet_in_mask.slave.action",
               FT_BOOLEAN, 32, NULL, 1 << OFPR_ACTION,
               NULL, HFILL }
        },
        { &hf_openflow_v4_async_config_packet_in_mask_slave_invalid_ttl,
            { "OFPR_INVALID_TTL", "openflow_v4.async_config.packet_in_mask.slave.invalid_ttl",
               FT_BOOLEAN, 32, NULL, 1 << OFPR_INVALID_TTL,
               NULL, HFILL }
        },
        { &hf_openflow_v4_async_config_port_status_mask_master,
            { "Port status mask (master)", "openflow_v4.async_config.port_status_mask.master",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_async_config_port_status_mask_master_add,
            { "OFPPR_ADD", "openflow_v4.async_config.port_status_mask.master.add",
               FT_BOOLEAN, 32, NULL, 1 << OFPPR_ADD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_async_config_port_status_mask_master_delete,
            { "OFPPR_DELETE", "openflow_v4.async_config.port_status_mask.master.delete",
               FT_BOOLEAN, 32, NULL, 1 << OFPPR_DELETE,
               NULL, HFILL }
        },
        { &hf_openflow_v4_async_config_port_status_mask_master_modify,
            { "OFPPR_MODIFY", "openflow_v4.async_config.port_status_mask.master.modify",
               FT_BOOLEAN, 32, NULL, 1 << OFPPR_MODIFY,
               NULL, HFILL }
        },
        { &hf_openflow_v4_async_config_port_status_mask_slave,
            { "Port status mask (slave)", "openflow_v4.async_config.port_status_mask.slave",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_async_config_port_status_mask_slave_add,
            { "OFPPR_ADD", "openflow_v4.async_config.port_status_mask.slave.add",
               FT_BOOLEAN, 32, NULL, 1 << OFPPR_ADD,
               NULL, HFILL }
        },
        { &hf_openflow_v4_async_config_port_status_mask_slave_delete,
            { "OFPPR_DELETE", "openflow_v4.async_config.port_status_mask.slave.delete",
               FT_BOOLEAN, 32, NULL, 1 << OFPPR_DELETE,
               NULL, HFILL }
        },
        { &hf_openflow_v4_async_config_port_status_mask_slave_modify,
            { "OFPPR_MODIFY", "openflow_v4.async_config.port_status_mask.slave.modify",
               FT_BOOLEAN, 32, NULL, 1 << OFPPR_MODIFY,
               NULL, HFILL }
        },
        { &hf_openflow_v4_async_config_flow_removed_mask_master,
            { "Flow removed mask (master)", "openflow_v4.async_config.flow_removed_mask.master",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_async_config_flow_removed_mask_master_idle_timeout,
            { "OFPRR_IDLE_TIMEOUT", "openflow_v4.async_config.flow_removed_mask.master.idle_timeout",
               FT_BOOLEAN, 32, NULL, 1 << OFPRR_IDLE_TIMEOUT,
               NULL, HFILL }
        },
        { &hf_openflow_v4_async_config_flow_removed_mask_master_hard_timeout,
            { "OFPRR_HARD_TIMEOUT", "openflow_v4.async_config.flow_removed_mask.master.hard_timeout",
               FT_BOOLEAN, 32, NULL, 1 << OFPRR_HARD_TIMEOUT,
               NULL, HFILL }
        },
        { &hf_openflow_v4_async_config_flow_removed_mask_master_delete,
            { "OFPRR_DELETE", "openflow_v4.async_config.flow_removed_mask.master.delete",
               FT_BOOLEAN, 32, NULL, 1 << OFPRR_DELETE,
               NULL, HFILL }
        },
        { &hf_openflow_v4_async_config_flow_removed_mask_master_group_delete,
            { "OFPRR_GROUP_DELETE", "openflow_v4.async_config.flow_removed_mask.master.group_delete",
               FT_BOOLEAN, 32, NULL, 1 << OFPRR_GROUP_DELETE,
               NULL, HFILL }
        },
        { &hf_openflow_v4_async_config_flow_removed_mask_slave,
            { "Flow removed mask (slave)", "openflow_v4.async_config.flow_removed_mask.slave",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_async_config_flow_removed_mask_slave_idle_timeout,
            { "OFPRR_IDLE_TIMEOUT", "openflow_v4.async_config.flow_removed_mask.slave.idle_timeout",
               FT_BOOLEAN, 32, NULL, 1 << OFPRR_IDLE_TIMEOUT,
               NULL, HFILL }
        },
        { &hf_openflow_v4_async_config_flow_removed_mask_slave_hard_timeout,
            { "OFPRR_HARD_TIMEOUT", "openflow_v4.async_config.flow_removed_mask.slave.hard_timeout",
               FT_BOOLEAN, 32, NULL, 1 << OFPRR_HARD_TIMEOUT,
               NULL, HFILL }
        },
        { &hf_openflow_v4_async_config_flow_removed_mask_slave_delete,
            { "OFPRR_DELETE", "openflow_v4.async_config.flow_removed_mask.slave.delete",
               FT_BOOLEAN, 32, NULL, 1 << OFPRR_DELETE,
               NULL, HFILL }
        },
        { &hf_openflow_v4_async_config_flow_removed_mask_slave_group_delete,
            { "OFPRR_GROUP_DELETE", "openflow_v4.async_config.flow_removed_mask.slave.group_delete",
               FT_BOOLEAN, 32, NULL, 1 << OFPRR_GROUP_DELETE,
               NULL, HFILL }
        },
        { &hf_openflow_v4_metermod_command,
            { "Command", "openflow_v4.metermod.command",
               FT_UINT8, BASE_DEC, VALS(openflow_v4_metermod_command_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_metermod_flags,
            { "Flags", "openflow_v4.metermod.flags",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_metermod_flags_kbps,
            { "OFPMF_KBPS", "openflow_v4.metermod.flags.kbps",
               FT_BOOLEAN, 32, NULL, OFPMF_KBPS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_metermod_flags_pktps,
            { "OFPMF_PKTPS", "openflow_v4.metermod.flags.ptkps",
               FT_BOOLEAN, 32, NULL, OFPMF_PKTPS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_metermod_flags_burst,
            { "OFPMF_BURST", "openflow_v4.metermod.flags.burst",
               FT_BOOLEAN, 32, NULL, OFPMF_BURST,
               NULL, HFILL }
        },
        { &hf_openflow_v4_metermod_flags_stats,
            { "OFPMF_STATS", "openflow_v4.metermod.flags.stats",
               FT_BOOLEAN, 32, NULL, OFPMF_STATS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_metermod_meter_id,
            { "Meter ID", "openflow_v4.metermod.meter_id",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_metermod_meter_id_reserved,
            { "Meter ID", "openflow_v4.metermod.meter_id",
               FT_UINT32, BASE_HEX, VALS(openflow_v4_meter_id_reserved_values), 0x0,
               NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_openflow_v4,
        &ett_openflow_v4_flowmod_flags,
        &ett_openflow_v4_bucket,
        &ett_openflow_v4_oxm,
        &ett_openflow_v4_match,
        &ett_openflow_v4_action,
        &ett_openflow_v4_instruction,
        &ett_openflow_v4_port,
        &ett_openflow_v4_port_config,
        &ett_openflow_v4_port_state,
        &ett_openflow_v4_port_current,
        &ett_openflow_v4_port_advertised,
        &ett_openflow_v4_port_supported,
        &ett_openflow_v4_port_peer,
        &ett_openflow_v4_meter_band,
        &ett_openflow_v4_hello_element,
        &ett_openflow_v4_error_data,
        &ett_openflow_v4_switch_features_capabilities,
        &ett_openflow_v4_switch_config_flags,
        &ett_openflow_v4_packet_in_data,
        &ett_openflow_v4_packet_out_data,
        &ett_openflow_v4_portmod_config,
        &ett_openflow_v4_portmod_mask,
        &ett_openflow_v4_portmod_advertise,
        &ett_openflow_v4_table_features,
        &ett_openflow_v4_table_feature_prop,
        &ett_openflow_v4_table_feature_prop_instruction_id,
        &ett_openflow_v4_table_feature_prop_action_id,
        &ett_openflow_v4_table_feature_prop_oxm_id,
        &ett_openflow_v4_multipart_request_flags,
        &ett_openflow_v4_flow_stats,
        &ett_openflow_v4_flow_stats_flags,
        &ett_openflow_v4_table_stats,
        &ett_openflow_v4_port_stats,
        &ett_openflow_v4_queue_stats,
        &ett_openflow_v4_bucket_counter,
        &ett_openflow_v4_group_stats,
        &ett_openflow_v4_group_desc,
        &ett_openflow_v4_group_features_types,
        &ett_openflow_v4_group_features_capabilities,
        &ett_openflow_v4_group_features_actions_all,
        &ett_openflow_v4_group_features_actions_select,
        &ett_openflow_v4_group_features_actions_indirect,
        &ett_openflow_v4_group_features_actions_ff,
        &ett_openflow_v4_meter_band_stats,
        &ett_openflow_v4_meter_stats,
        &ett_openflow_v4_meter_config,
        &ett_openflow_v4_meter_config_flags,
        &ett_openflow_v4_meter_features_band_types,
        &ett_openflow_v4_meter_features_capabilities,
        &ett_openflow_v4_multipart_reply_flags,
        &ett_openflow_v4_queue_prop,
        &ett_openflow_v4_packet_queue,
        &ett_openflow_v4_async_config_packet_in_mask_master,
        &ett_openflow_v4_async_config_packet_in_mask_slave,
        &ett_openflow_v4_async_config_port_status_mask_master,
        &ett_openflow_v4_async_config_port_status_mask_slave,
        &ett_openflow_v4_async_config_flow_removed_mask_master,
        &ett_openflow_v4_async_config_flow_removed_mask_slave,
        &ett_openflow_v4_metermod_flags
    };

    static ei_register_info ei[] = {
        { &ei_openflow_v4_oxm_undecoded,
            { "openflow_v4.oxm.undecoded", PI_UNDECODED, PI_NOTE,
              "Unknown OMX body.", EXPFILL }
        },
        { &ei_openflow_v4_match_undecoded,
            { "openflow_v4.match.undecoded", PI_UNDECODED, PI_NOTE,
              "Unknown match body.", EXPFILL }
        },
        { &ei_openflow_v4_action_undecoded,
            { "openflow_v4.action.undecoded", PI_UNDECODED, PI_NOTE,
              "Unknown action body.", EXPFILL }
        },
        { &ei_openflow_v4_instruction_undecoded,
            { "openflow_v4.instruction.undecoded", PI_UNDECODED, PI_NOTE,
              "Unknown instruction body.", EXPFILL }
        },
        { &ei_openflow_v4_meter_band_undecoded,
            { "openflow_v4.meter_band.undecoded", PI_UNDECODED, PI_NOTE,
              "Unknown meter band body.", EXPFILL }
        },
        { &ei_openflow_v4_hello_element_undecoded,
            { "openflow_v4.hello_element.undecoded", PI_UNDECODED, PI_NOTE,
              "Unknown hello element body.", EXPFILL }
        },
        { &ei_openflow_v4_error_undecoded,
            { "openflow_v4.error.undecoded", PI_UNDECODED, PI_NOTE,
              "Unknown error data.", EXPFILL }
        },
        { &ei_openflow_v4_experimenter_undecoded,
            { "openflow_v4.experimenter.undecoded", PI_UNDECODED, PI_NOTE,
              "Unknown experimenter body.", EXPFILL }
        },
        { &ei_openflow_v4_table_feature_prop_undecoded,
            { "openflow_v4.table_feature_prop.undecoded", PI_UNDECODED, PI_NOTE,
              "Unknown table feature property body.", EXPFILL }
        },
        { &ei_openflow_v4_multipart_request_undecoded,
            { "openflow_v4.multipart_request.undecoded", PI_UNDECODED, PI_NOTE,
              "Unknown multipart reqeuest body.", EXPFILL }
        },
        { &ei_openflow_v4_multipart_reply_undecoded,
            { "openflow_v4.multipart_reply.undecoded", PI_UNDECODED, PI_NOTE,
              "Unknown multipart reply body.", EXPFILL }
        },
        { &ei_openflow_v4_queue_prop_undecoded,
            { "openflow_v4.queue_prop.undecoded", PI_UNDECODED, PI_NOTE,
              "Unknown queue property body.", EXPFILL }
        },
        {&ei_openflow_v4_message_undecoded,
            { "openflow_v4.message.undecoded", PI_UNDECODED, PI_NOTE,
              "Unknown message body.", EXPFILL }
        }
    };

    expert_module_t *expert_openflow_v4;

    /* Register the protocol name and description */
    proto_openflow_v4 = proto_register_protocol("OpenFlow 1.3",
            "openflow_v4", "openflow_v4");

    register_dissector("openflow_v4", dissect_openflow_v4, proto_openflow_v4);

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_openflow_v4, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_openflow_v4 = expert_register_protocol(proto_openflow_v4);
    expert_register_field_array(expert_openflow_v4, ei, array_length(ei));
}

void
proto_reg_handoff_openflow_v4(void)
{
    eth_withoutfcs_handle = find_dissector_add_dependency("eth_withoutfcs", proto_openflow_v4);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
