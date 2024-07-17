/* packet-netmon.c
 * Routines for Network Monitor capture dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Network Event Tracing event taken from:
 *
 * https://docs.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/to_str.h>
#include <epan/expert.h>
#include <wiretap/wtap.h>
#include "packet-netmon.h"

void proto_register_netmon(void);
void proto_reg_handoff_netmon(void);

#define EVENT_HEADER_PROPERTY_XML               0x0001
#define EVENT_HEADER_PROPERTY_FORWARDED_XML     0x0002
#define EVENT_HEADER_PROPERTY_LEGACY_EVENTLOG   0x0004

static const value_string event_level_vals[] = {
	{ 0,	"Log Always"},
	{ 1,	"Critical"},
	{ 2,	"Error"},
	{ 3,	"Warning"},
	{ 4,	"Info"},
	{ 5,	"Verbose"},
	{ 6,	"Reserved"},
	{ 7,	"Reserved"},
	{ 8,	"Reserved"},
	{ 9,	"Reserved"},
	{ 10,	"Reserved"},
	{ 11,	"Reserved"},
	{ 12,	"Reserved"},
	{ 13,	"Reserved"},
	{ 14,	"Reserved"},
	{ 15,	"Reserved"},
	{ 0,	NULL }
};

static const value_string opcode_vals[] = {
	{ 0,	"Info"},
	{ 1,	"Start"},
	{ 2,	"Stop"},
	{ 3,	"DC Start"},
	{ 4,	"DC Stop"},
	{ 5,	"Extension"},
	{ 6,	"Reply"},
	{ 7,	"Resume"},
	{ 8,	"Suspend"},
	{ 9,	"Transfer"},
	{ 0,	NULL }
};

static const range_string filter_types[] = {
	{ 0,	0,	"Display Filter" },
	{ 1,	1,	"Capture Filter" },
	{ 2,	0xFFFFFFFF,	"Display Filter" },
	{ 0, 0, NULL }
};

static dissector_table_t provider_id_table;

/* Initialize the protocol and registered fields */
static int proto_netmon_header;
static int proto_netmon_event;
static int proto_netmon_filter;
static int proto_netmon_network_info;
static int proto_netmon_system_trace;
static int proto_netmon_system_config;
static int proto_netmon_process;

static int hf_netmon_header_title_comment;
static int hf_netmon_header_description_comment;

static int hf_netmon_event_size;
static int hf_netmon_event_header_type;
static int hf_netmon_event_flags;
static int hf_netmon_event_flags_extended_info;
static int hf_netmon_event_flags_private_session;
static int hf_netmon_event_flags_string_only;
static int hf_netmon_event_flags_trace_message;
static int hf_netmon_event_flags_no_cputime;
static int hf_netmon_event_flags_32bit_header;
static int hf_netmon_event_flags_64bit_header;
static int hf_netmon_event_flags_classic_header;
static int hf_netmon_event_event_property;
static int hf_netmon_event_event_property_xml;
static int hf_netmon_event_event_property_forwarded_xml;
static int hf_netmon_event_event_property_legacy_eventlog;
static int hf_netmon_event_thread_id;
static int hf_netmon_event_process_id;
static int hf_netmon_event_timestamp;
static int hf_netmon_event_provider_id;
static int hf_netmon_event_event_desc_id;
static int hf_netmon_event_event_desc_version;
static int hf_netmon_event_event_desc_channel;
static int hf_netmon_event_event_desc_level;
static int hf_netmon_event_event_desc_opcode;
static int hf_netmon_event_event_desc_task;
static int hf_netmon_event_event_desc_keyword;
static int hf_netmon_event_kernel_time;
static int hf_netmon_event_user_time;
static int hf_netmon_event_processor_time;
static int hf_netmon_event_activity_id;
static int hf_netmon_event_processor_number;
static int hf_netmon_event_alignment;
static int hf_netmon_event_logger_id;
static int hf_netmon_event_extended_data_count;
static int hf_netmon_event_user_data_length;
static int hf_netmon_event_reassembled;
static int hf_netmon_event_extended_data_reserved;
static int hf_netmon_event_extended_data_type;
static int hf_netmon_event_extended_data_linkage;
static int hf_netmon_event_extended_data_reserved2;
static int hf_netmon_event_extended_data_size;
static int hf_netmon_event_extended_data;
static int hf_netmon_event_user_data;

static int hf_netmon_filter_version;
static int hf_netmon_filter_type;
static int hf_netmon_filter_app_major_version;
static int hf_netmon_filter_app_minor_version;
static int hf_netmon_filter_app_name;
static int hf_netmon_filter_filter;

static int hf_netmon_network_info_version;
static int hf_netmon_network_info_adapter_count;
static int hf_netmon_network_info_computer_name;
static int hf_netmon_network_info_friendly_name;
static int hf_netmon_network_info_description;
static int hf_netmon_network_info_miniport_guid;
static int hf_netmon_network_info_media_type;
static int hf_netmon_network_info_mtu;
static int hf_netmon_network_info_link_speed;
static int hf_netmon_network_info_mac_address;
static int hf_netmon_network_info_ipv4_count;
static int hf_netmon_network_info_ipv6_count;
static int hf_netmon_network_info_gateway_count;
static int hf_netmon_network_info_dhcp_server_count;
static int hf_netmon_network_info_dns_ipv4_count;
static int hf_netmon_network_info_dns_ipv6_count;
static int hf_netmon_network_info_ipv4;
static int hf_netmon_network_info_subnet;
static int hf_netmon_network_info_ipv6;
static int hf_netmon_network_info_gateway;
static int hf_netmon_network_info_dhcp_server;
static int hf_netmon_network_info_dns_ipv4;
static int hf_netmon_network_info_dns_ipv6;

static int hf_netmon_system_trace_buffer_size;
static int hf_netmon_system_trace_version;
static int hf_netmon_system_trace_provider_version;
static int hf_netmon_system_trace_num_processors;
static int hf_netmon_system_trace_end_time;
static int hf_netmon_system_trace_timer_resolution;
static int hf_netmon_system_trace_max_file_size;
static int hf_netmon_system_trace_log_file_mode;
static int hf_netmon_system_trace_buffers_written;
static int hf_netmon_system_trace_start_buffers;
static int hf_netmon_system_trace_pointers_size;
static int hf_netmon_system_trace_events_lost;
static int hf_netmon_system_trace_cpu_speed;
static int hf_netmon_system_trace_logger_name;
static int hf_netmon_system_trace_log_file_name_ptr;
static int hf_netmon_system_trace_time_zone_info;
static int hf_netmon_system_trace_boot_time;
static int hf_netmon_system_trace_perf_freq;
static int hf_netmon_system_trace_start_time;
static int hf_netmon_system_trace_reserved_flags;
static int hf_netmon_system_trace_buffers_lost;
static int hf_netmon_system_trace_session_name;
static int hf_netmon_system_trace_log_file_name;
static int hf_netmon_system_trace_group_mask1;
static int hf_netmon_system_trace_group_mask2;
static int hf_netmon_system_trace_group_mask3;
static int hf_netmon_system_trace_group_mask4;
static int hf_netmon_system_trace_group_mask5;
static int hf_netmon_system_trace_group_mask6;
static int hf_netmon_system_trace_group_mask7;
static int hf_netmon_system_trace_group_mask8;
static int hf_netmon_system_trace_kernel_event_version;

static int hf_netmon_system_config_mhz;
static int hf_netmon_system_config_num_processors;
static int hf_netmon_system_config_mem_size;
static int hf_netmon_system_config_page_size;
static int hf_netmon_system_config_allocation_granularity;
static int hf_netmon_system_config_computer_name;
static int hf_netmon_system_config_domain_name;
static int hf_netmon_system_config_hyper_threading_flag;
static int hf_netmon_system_config_disk_number;
static int hf_netmon_system_config_bytes_per_sector;
static int hf_netmon_system_config_sectors_per_track;
static int hf_netmon_system_config_tracks_per_cylinder;
static int hf_netmon_system_config_cylinders;
static int hf_netmon_system_config_scsi_port;
static int hf_netmon_system_config_scsi_path;
static int hf_netmon_system_config_scsi_target;
static int hf_netmon_system_config_scsi_lun;
static int hf_netmon_system_config_manufacturer;
static int hf_netmon_system_config_partition_count;
static int hf_netmon_system_config_write_cache_enabled;
static int hf_netmon_system_config_pad;
static int hf_netmon_system_config_boot_drive_letter;
static int hf_netmon_system_config_spare;
static int hf_netmon_system_config_start_offset;
static int hf_netmon_system_config_partition_size;
static int hf_netmon_system_config_size;
static int hf_netmon_system_config_drive_type;
static int hf_netmon_system_config_drive_letter;
static int hf_netmon_system_config_partition_number;
static int hf_netmon_system_config_sectors_per_cluster;
static int hf_netmon_system_config_num_free_clusters;
static int hf_netmon_system_config_total_num_clusters;
static int hf_netmon_system_config_file_system;
static int hf_netmon_system_config_volume_ext;
static int hf_netmon_system_config_physical_addr;
static int hf_netmon_system_config_physical_addr_len;
static int hf_netmon_system_config_ipv4_index;
static int hf_netmon_system_config_ipv6_index;
static int hf_netmon_system_config_nic_description;
static int hf_netmon_system_config_ipaddresses;
static int hf_netmon_system_config_dns_server_addresses;
static int hf_netmon_system_config_memory_size;
static int hf_netmon_system_config_x_resolution;
static int hf_netmon_system_config_y_resolution;
static int hf_netmon_system_config_bits_per_pixel;
static int hf_netmon_system_config_vrefresh;
static int hf_netmon_system_config_chip_type;
static int hf_netmon_system_config_dac_type;
static int hf_netmon_system_config_adapter_string;
static int hf_netmon_system_config_bios_string;
static int hf_netmon_system_config_device_id;
static int hf_netmon_system_config_state_flags;
static int hf_netmon_system_config_process_id;
static int hf_netmon_system_config_service_state;
static int hf_netmon_system_config_sub_process_tag;
static int hf_netmon_system_config_service_name;
static int hf_netmon_system_config_display_name;
static int hf_netmon_system_config_process_name;
static int hf_netmon_system_config_s1;
static int hf_netmon_system_config_s2;
static int hf_netmon_system_config_s3;
static int hf_netmon_system_config_s4;
static int hf_netmon_system_config_s5;
static int hf_netmon_system_config_tcb_table_partitions;
static int hf_netmon_system_config_max_hash_table_size;
static int hf_netmon_system_config_max_user_port;
static int hf_netmon_system_config_tcp_timed_wait_delay;
static int hf_netmon_system_config_irq_affinity;
static int hf_netmon_system_config_irq_num;
static int hf_netmon_system_config_device_desc_len;
static int hf_netmon_system_config_device_desc;
static int hf_netmon_system_config_device_id_len;
static int hf_netmon_system_config_friendly_name_len;
static int hf_netmon_system_config_friendly_name;
static int hf_netmon_system_config_target_id;
static int hf_netmon_system_config_device_type;
static int hf_netmon_system_config_device_timing_mode;
static int hf_netmon_system_config_location_information_len;
static int hf_netmon_system_config_location_information;
static int hf_netmon_system_config_system_manufacturer;
static int hf_netmon_system_config_system_product_name;
static int hf_netmon_system_config_bios_date;
static int hf_netmon_system_config_bios_version;
static int hf_netmon_system_config_load_order_group;
static int hf_netmon_system_config_svc_host_group;
static int hf_netmon_system_config_irq_group;
static int hf_netmon_system_config_pdo_name;
static int hf_netmon_system_config_nic_name;
static int hf_netmon_system_config_index;
static int hf_netmon_system_config_physical_addr_str;
static int hf_netmon_system_config_ip_address;
static int hf_netmon_system_config_subnet_mask;
static int hf_netmon_system_config_dhcp_server;
static int hf_netmon_system_config_gateway;
static int hf_netmon_system_config_primary_wins_server;
static int hf_netmon_system_config_secondary_wins_server;
static int hf_netmon_system_config_dns_server1;
static int hf_netmon_system_config_dns_server2;
static int hf_netmon_system_config_dns_server3;
static int hf_netmon_system_config_dns_server4;
static int hf_netmon_system_config_data;



static int hf_netmon_process_unique_process_key;
static int hf_netmon_process_process_id;
static int hf_netmon_process_parent_id;
static int hf_netmon_process_session_id;
static int hf_netmon_process_exit_status;
static int hf_netmon_process_directory_table_base;
static int hf_netmon_process_unknown;
static int hf_netmon_process_user_sid_revision;
static int hf_netmon_process_user_sid_subauth_count;
static int hf_netmon_process_user_sid_id;
static int hf_netmon_process_user_sid_authority;
static int hf_netmon_process_image_file_name;
static int hf_netmon_process_command_line;
static int hf_netmon_process_page_directory_base;
static int hf_netmon_process_page_fault_count;
static int hf_netmon_process_handle_count;
static int hf_netmon_process_reserved;
static int hf_netmon_process_peak_virtual_size;
static int hf_netmon_process_peak_working_set_size;
static int hf_netmon_process_peak_page_file_usage;
static int hf_netmon_process_quota_peak_paged_pool_usage;
static int hf_netmon_process_quota_peak_non_paged_pool_usage;
static int hf_netmon_process_virtual_size;
static int hf_netmon_process_workingset_size;
static int hf_netmon_process_pagefile_usage;
static int hf_netmon_process_quota_paged_pool_usage;
static int hf_netmon_process_quota_non_paged_pool_usage;
static int hf_netmon_process_private_page_count;
static int hf_netmon_process_directory_table_base32;


static int ett_netmon_header;
static int ett_netmon_event;
static int ett_netmon_event_desc;
static int ett_netmon_event_flags;
static int ett_netmon_event_property;
static int ett_netmon_event_extended_data;
static int ett_netmon_filter;
static int ett_netmon_network_info;
static int ett_netmon_network_info_list;
static int ett_netmon_network_info_adapter;
static int ett_netmon_system_trace;
static int ett_netmon_event_buffer_context;
static int ett_netmon_process;
static int ett_netmon_sid;
static int ett_netmon_system_config;

static expert_field ei_netmon_process_user_sid;

static dissector_table_t wtap_encap_table;

void
netmon_etl_field(proto_tree *tree, tvbuff_t *tvb, int* offset, int hf, uint16_t flags)
{
	if (flags & EVENT_HEADER_FLAG_64_BIT_HEADER) {
		/* XXX - This seems to be how values are displayed in Network Monitor */
		uint64_t value = tvb_get_letoh64(tvb, *offset) & 0xFFFFFFFF;
		proto_tree_add_uint64(tree, hf, tvb, *offset, 8, value);
		(*offset) += 8;
	} else {
		proto_tree_add_item(tree, hf, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
		(*offset) += 4;
	}
}

void
netmon_sid_field(proto_tree *tree, tvbuff_t *tvb, int* offset, packet_info *pinfo,
				int hf_revision, int hf_subauthority_count, int hf_sid_id, int hf_sid_authority, expert_field* invalid_sid, bool conformant _U_)
{
	proto_item *ti, *sid_item;
	proto_tree *sid_tree;
	int start_offset = *offset;
	uint32_t i, revision, count;

	sid_tree = proto_tree_add_subtree(tree, tvb, *offset, 2, ett_netmon_sid, &sid_item, "SID");

	ti = proto_tree_add_item_ret_uint(sid_tree, hf_revision, tvb, *offset, 1, ENC_LITTLE_ENDIAN, &revision);
	(*offset) += 1;
	if (revision != 1)
	{
		expert_add_info(pinfo, ti, invalid_sid);
	}
	proto_tree_add_item_ret_uint(sid_tree, hf_subauthority_count, tvb, *offset, 1, ENC_LITTLE_ENDIAN, &count);
	(*offset) += 1;
	if (count > 15)
	{
		expert_add_info(pinfo, ti, invalid_sid);
	}

	proto_tree_add_item(sid_tree, hf_sid_id, tvb, *offset, 6, ENC_NA);
	(*offset) += 6;

	for (i = 0; i < count; i++)
	{
		proto_tree_add_item(sid_tree, hf_sid_authority, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
		(*offset) += 4;
	}

	proto_item_set_len(sid_item, (*offset)-start_offset);
}

/* Code to actually dissect the packets */
static int
dissect_netmon_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item *ti;
	proto_tree *header_tree;
	union wtap_pseudo_header temp_header;
	char *comment;

	ti = proto_tree_add_item(tree, proto_netmon_header, tvb, 0, 0, ENC_NA);
	header_tree = proto_item_add_subtree(ti, ett_netmon_header);

	if (pinfo->pseudo_header->netmon.title != NULL) {
		ti = proto_tree_add_string(header_tree, hf_netmon_header_title_comment, tvb, 0, 0, pinfo->pseudo_header->netmon.title);
		proto_item_set_generated(ti);
	}

	if (pinfo->pseudo_header->netmon.description != NULL) {
		/* Description comment is only ASCII.  However, it's
		 * RTF, not raw text.
		 */

		/* Ensure string termination */
		comment = wmem_strndup(pinfo->pool, pinfo->pseudo_header->netmon.description, pinfo->pseudo_header->netmon.descLength);

		ti = proto_tree_add_string(header_tree, hf_netmon_header_description_comment, tvb, 0, 0, comment);
		proto_item_set_generated(ti);
	}

	/* Save the pseudo header data to a temp variable before it's copied to
	 * real pseudo header
	 */
	switch (pinfo->pseudo_header->netmon.sub_encap)
	{
	case WTAP_ENCAP_ATM_PDUS:
		memcpy(&temp_header.atm, &pinfo->pseudo_header->netmon.subheader.atm, sizeof(temp_header.atm));
		memcpy(&pinfo->pseudo_header->atm, &temp_header.atm, sizeof(temp_header.atm));
		break;
	case WTAP_ENCAP_ETHERNET:
		memcpy(&temp_header.eth, &pinfo->pseudo_header->netmon.subheader.eth, sizeof(temp_header.eth));
		memcpy(&pinfo->pseudo_header->eth, &temp_header.eth, sizeof(temp_header.eth));
		break;
	case WTAP_ENCAP_IEEE_802_11_NETMON:
		memcpy(&temp_header.ieee_802_11, &pinfo->pseudo_header->netmon.subheader.ieee_802_11, sizeof(temp_header.ieee_802_11));
		memcpy(&pinfo->pseudo_header->ieee_802_11, &temp_header.ieee_802_11, sizeof(temp_header.ieee_802_11));
		break;
	}

	if (!dissector_try_uint_new(wtap_encap_table,
		pinfo->pseudo_header->netmon.sub_encap, tvb, pinfo, tree, true,
		(void *)pinfo->pseudo_header)) {
		call_data_dissector(tvb, pinfo, tree);
	}

	return tvb_captured_length(tvb);
}

static int
dissect_netmon_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item *ti, *extended_data_item;
	proto_tree *event_tree, *event_desc_tree, *extended_data_tree, *buffer_context_tree;
	int offset = 0, extended_data_count_offset;
	uint32_t i, thread_id, process_id, extended_data_count, extended_data_size, user_data_size;
	nstime_t timestamp;
	tvbuff_t *provider_id_tvb;
	guid_key provider_guid;
	struct netmon_provider_id_data provider_id_data;
	static int * const event_flags[] = {
		&hf_netmon_event_flags_extended_info,
		&hf_netmon_event_flags_private_session,
		&hf_netmon_event_flags_string_only,
		&hf_netmon_event_flags_trace_message,
		&hf_netmon_event_flags_no_cputime,
		&hf_netmon_event_flags_32bit_header,
		&hf_netmon_event_flags_64bit_header,
		&hf_netmon_event_flags_classic_header,
		NULL
	};
	static int * const event_property[] = {
		&hf_netmon_event_event_property_xml,
		&hf_netmon_event_event_property_forwarded_xml,
		&hf_netmon_event_event_property_legacy_eventlog,
		NULL
	};

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NetMon Event");
	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo, COL_INFO);

	memset(&provider_id_data, 0, sizeof(provider_id_data));

	ti = proto_tree_add_item(tree, proto_netmon_event, tvb, offset, -1, ENC_NA);
	event_tree = proto_item_add_subtree(ti, ett_netmon_event);

	proto_tree_add_item(event_tree, hf_netmon_event_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(event_tree, hf_netmon_event_header_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	provider_id_data.event_flags = tvb_get_letohs(tvb, offset);
	proto_tree_add_bitmask(event_tree, tvb, offset, hf_netmon_event_flags, ett_netmon_event_flags, event_flags, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_bitmask(event_tree, tvb, offset, hf_netmon_event_event_property, ett_netmon_event_property, event_property, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item_ret_uint(event_tree, hf_netmon_event_thread_id, tvb, offset, 4, ENC_LITTLE_ENDIAN, &thread_id);
	offset += 4;
	proto_tree_add_item_ret_uint(event_tree, hf_netmon_event_process_id, tvb, offset, 4, ENC_LITTLE_ENDIAN, &process_id);
	offset += 4;

	timestamp.secs = 0;
	timestamp.nsecs = 0;
	filetime_to_nstime(&timestamp, tvb_get_letoh64(tvb, offset));
	proto_tree_add_time(event_tree, hf_netmon_event_timestamp, tvb, offset, 8, &timestamp);
	offset += 8;

	proto_tree_add_item(event_tree, hf_netmon_event_provider_id, tvb, offset, 16, ENC_LITTLE_ENDIAN);
	/* Save the GUID to use in dissector table */
	tvb_memcpy(tvb, &provider_guid.guid, offset, 16);
	provider_guid.ver = 0; //version field not used
	offset += 16;

	col_add_fstr(pinfo->cinfo, COL_INFO, "Thread ID: %d, Process ID: %d, Provider ID: %s",
										thread_id, process_id, guid_to_str(pinfo->pool, &provider_guid.guid));

	event_desc_tree = proto_tree_add_subtree(event_tree, tvb, offset, 16, ett_netmon_event_desc, NULL, "Event Descriptor");
	proto_tree_add_item_ret_uint(event_desc_tree, hf_netmon_event_event_desc_id, tvb, offset, 2, ENC_LITTLE_ENDIAN, &provider_id_data.event_id);
	offset += 2;
	provider_id_data.event_version = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(event_desc_tree, hf_netmon_event_event_desc_version, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;
	proto_tree_add_item(event_desc_tree, hf_netmon_event_event_desc_channel, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;
	proto_tree_add_item(event_desc_tree, hf_netmon_event_event_desc_level, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;
	provider_id_data.opcode = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(event_desc_tree, hf_netmon_event_event_desc_opcode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;
	proto_tree_add_item(event_desc_tree, hf_netmon_event_event_desc_task, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item_ret_uint64(event_desc_tree, hf_netmon_event_event_desc_keyword, tvb, offset, 8, ENC_LITTLE_ENDIAN, &provider_id_data.keyword);
	offset += 8;

	if (provider_id_data.event_flags & (EVENT_HEADER_FLAG_PRIVATE_SESSION | EVENT_HEADER_FLAG_NO_CPUTIME))
	{
		/* Kernel and User time are a union with processor time */
		proto_tree_add_item(event_tree, hf_netmon_event_kernel_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(event_tree, hf_netmon_event_user_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
	}
	else
	{
		proto_tree_add_item(event_tree, hf_netmon_event_processor_time, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;
	}

	proto_tree_add_item(event_tree, hf_netmon_event_activity_id, tvb, offset, 16, ENC_LITTLE_ENDIAN);
	offset += 16;

	buffer_context_tree = proto_tree_add_subtree(event_tree, tvb, offset, 4, ett_netmon_event_buffer_context, NULL, "BufferContext");
	proto_tree_add_item(buffer_context_tree, hf_netmon_event_processor_number, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;
	proto_tree_add_item(buffer_context_tree, hf_netmon_event_alignment, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;
	proto_tree_add_item(buffer_context_tree, hf_netmon_event_logger_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item_ret_uint(event_tree, hf_netmon_event_extended_data_count, tvb, offset, 2, ENC_LITTLE_ENDIAN, &extended_data_count);
	offset += 2;
	proto_tree_add_item_ret_uint(event_tree, hf_netmon_event_user_data_length, tvb, offset, 2, ENC_LITTLE_ENDIAN, &user_data_size);
	offset += 2;
	proto_tree_add_item(event_tree, hf_netmon_event_reassembled, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	for (i = 1; i <= extended_data_count; i++)
	{
		extended_data_count_offset = offset;
		extended_data_tree = proto_tree_add_subtree_format(event_tree, tvb, offset, 4, ett_netmon_event_extended_data, &extended_data_item, "Extended Data Item #%d", i);
		proto_tree_add_item(extended_data_tree, hf_netmon_event_extended_data_reserved, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		proto_tree_add_item(extended_data_tree, hf_netmon_event_extended_data_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		proto_tree_add_item(extended_data_tree, hf_netmon_event_extended_data_linkage, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(extended_data_tree, hf_netmon_event_extended_data_reserved2, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		proto_tree_add_item_ret_uint(extended_data_tree, hf_netmon_event_extended_data_size, tvb, offset, 2, ENC_LITTLE_ENDIAN, &extended_data_size);
		offset += 2;
		proto_tree_add_item(extended_data_tree, hf_netmon_event_extended_data, tvb, offset, extended_data_size, ENC_NA);
		offset += extended_data_size;
		proto_item_set_len(extended_data_item, offset-extended_data_count_offset);
	}

	provider_id_tvb = tvb_new_subset_remaining(tvb, offset);
	if (!dissector_try_guid_new(provider_id_table, &provider_guid, provider_id_tvb, pinfo, tree, true, &provider_id_data))
	{
		proto_tree_add_item(event_tree, hf_netmon_event_user_data, tvb, offset, user_data_size, ENC_NA);
		offset += user_data_size;
	}
	proto_item_set_len(ti, offset);
	return tvb_captured_length(tvb);
}


static int
dissect_netmon_filter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item *ti;
	proto_tree *filter_tree;
	int offset = 0;
	unsigned length;
	const uint8_t* filter;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NetMon Filter");
	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_netmon_filter, tvb, offset, -1, ENC_NA);
	filter_tree = proto_item_add_subtree(ti, ett_netmon_filter);

	proto_tree_add_item(filter_tree, hf_netmon_filter_version, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(filter_tree, hf_netmon_filter_type, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(filter_tree, hf_netmon_filter_app_major_version, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(filter_tree, hf_netmon_filter_app_minor_version, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length = tvb_unicode_strsize(tvb, offset);
	proto_tree_add_item(filter_tree, hf_netmon_filter_app_name, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
	offset += length;
	length = tvb_unicode_strsize(tvb, offset);
	proto_tree_add_item_ret_string(filter_tree, hf_netmon_filter_filter, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16,
									pinfo->pool, &filter);
	col_add_fstr(pinfo->cinfo, COL_INFO, "Filter: %s", filter);

	return tvb_captured_length(tvb);
}


static int
dissect_netmon_network_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item *ti, *list_item, *adapter_item;
	proto_tree *network_info_tree, *list_tree, *adapter_tree;
	int offset = 0, list_start_offset, adapter_start_offset;
	unsigned adapter, adapter_count, length;
	uint64_t link_speed;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NetMon Network Info");
	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_netmon_network_info, tvb, offset, -1, ENC_NA);
	network_info_tree = proto_item_add_subtree(ti, ett_netmon_network_info);

	proto_tree_add_item(network_info_tree, hf_netmon_network_info_version, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item_ret_uint(network_info_tree, hf_netmon_network_info_adapter_count, tvb, offset, 2, ENC_BIG_ENDIAN, &adapter_count);
	offset += 2;
	col_add_fstr(pinfo->cinfo, COL_INFO, "Adapter count: %d", adapter_count);

	length = tvb_unicode_strsize(tvb, offset);
	proto_tree_add_item(network_info_tree, hf_netmon_network_info_computer_name, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
	offset += length;
	if (adapter_count > 0)
	{
		list_start_offset = offset;
		list_tree = proto_tree_add_subtree(network_info_tree, tvb, offset, 1, ett_netmon_network_info_list, &list_item, "NetworkInfo");
		for (adapter = 1; adapter <= adapter_count; adapter++)
		{
			uint32_t loop, ipv4_count, ipv6_count, gateway_count, dhcp_server_count, dns_ipv4_count, dns_ipv6_count;

			adapter_start_offset = offset;
			adapter_tree = proto_tree_add_subtree_format(list_tree, tvb, offset, 1, ett_netmon_network_info_adapter, &adapter_item, "Adapter #%d", adapter);

			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item(adapter_tree, hf_netmon_network_info_friendly_name, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += length;
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item(adapter_tree, hf_netmon_network_info_description, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += length;
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item(adapter_tree, hf_netmon_network_info_miniport_guid, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += length;
			proto_tree_add_item(adapter_tree, hf_netmon_network_info_media_type, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(adapter_tree, hf_netmon_network_info_mtu, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			link_speed = tvb_get_ntoh64(tvb, offset);
			if (link_speed == 0xFFFFFFFFFFFFFFFF)
			{
			    proto_tree_add_uint64_format_value(adapter_tree, hf_netmon_network_info_link_speed, tvb, offset, 8, link_speed, "(Unknown)");
			}
			else if (link_speed >= 1000 * 1000 * 1000)
			{
			    proto_tree_add_uint64_format_value(adapter_tree, hf_netmon_network_info_link_speed, tvb, offset, 8, link_speed, "%" PRIu64 " Gbps", link_speed/(1000*1000*1000));
			}
			else if (link_speed >= 1000 * 1000)
			{
			    proto_tree_add_uint64_format_value(adapter_tree, hf_netmon_network_info_link_speed, tvb, offset, 8, link_speed, "%" PRIu64 " Mbps", link_speed/(1000*1000));
			}
			else if (link_speed >= 1000)
			{
			    proto_tree_add_uint64_format_value(adapter_tree, hf_netmon_network_info_link_speed, tvb, offset, 8, link_speed, "%" PRIu64 " Kbps", link_speed/1000);
			}
			else
			{
			    proto_tree_add_uint64_format_value(adapter_tree, hf_netmon_network_info_link_speed, tvb, offset, 8, link_speed, "%" PRIu64 " bps", link_speed);
			}
			offset += 8;
			proto_tree_add_item(adapter_tree, hf_netmon_network_info_mac_address, tvb, offset, 6, ENC_NA);
			offset += 6;

			proto_tree_add_item_ret_uint(adapter_tree, hf_netmon_network_info_ipv4_count, tvb, offset, 2, ENC_BIG_ENDIAN, &ipv4_count);
			offset += 2;
			proto_tree_add_item_ret_uint(adapter_tree, hf_netmon_network_info_ipv6_count, tvb, offset, 2, ENC_BIG_ENDIAN, &ipv6_count);
			offset += 2;
			proto_tree_add_item_ret_uint(adapter_tree, hf_netmon_network_info_gateway_count, tvb, offset, 2, ENC_BIG_ENDIAN, &gateway_count);
			offset += 2;
			proto_tree_add_item_ret_uint(adapter_tree, hf_netmon_network_info_dhcp_server_count, tvb, offset, 2, ENC_BIG_ENDIAN, &dhcp_server_count);
			offset += 2;
			proto_tree_add_item_ret_uint(adapter_tree, hf_netmon_network_info_dns_ipv4_count, tvb, offset, 2, ENC_BIG_ENDIAN, &dns_ipv4_count);
			offset += 2;
			proto_tree_add_item_ret_uint(adapter_tree, hf_netmon_network_info_dns_ipv6_count, tvb, offset, 2, ENC_BIG_ENDIAN, &dns_ipv6_count);
			offset += 2;

			for (loop = 0; loop < ipv4_count; loop++)
			{
				proto_tree_add_item(adapter_tree, hf_netmon_network_info_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}
			for (loop = 0; loop < ipv4_count; loop++)
			{
				proto_tree_add_item(adapter_tree, hf_netmon_network_info_subnet, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}
			for (loop = 0; loop < ipv6_count; loop++)
			{
				proto_tree_add_item(adapter_tree, hf_netmon_network_info_ipv6, tvb, offset, 16, ENC_NA);
				offset += 16;
			}
			for (loop = 0; loop < gateway_count; loop++)
			{
				proto_tree_add_item(adapter_tree, hf_netmon_network_info_gateway, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}
			for (loop = 0; loop < dhcp_server_count; loop++)
			{
				proto_tree_add_item(adapter_tree, hf_netmon_network_info_dhcp_server, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}
			for (loop = 0; loop < dns_ipv4_count; loop++)
			{
				proto_tree_add_item(adapter_tree, hf_netmon_network_info_dns_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}
			for (loop = 0; loop < dns_ipv6_count; loop++)
			{
				proto_tree_add_item(adapter_tree, hf_netmon_network_info_dns_ipv6, tvb, offset, 16, ENC_NA);
				offset += 16;
			}

			proto_item_set_len(adapter_item, offset-adapter_start_offset);
		}

		proto_item_set_len(list_item, offset-list_start_offset);
	}

	return tvb_captured_length(tvb);
}

static int
dissect_netmon_system_trace(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item *ti;
	proto_tree *system_tree;
	int offset = 0;
	struct netmon_provider_id_data *provider_id_data = (struct netmon_provider_id_data*)data;
	unsigned length;
	nstime_t timestamp;
	uint64_t raw_timestamp;

	DISSECTOR_ASSERT(provider_id_data != NULL);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NetMon System Trace");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_netmon_system_trace, tvb, 0, -1, ENC_NA);
	system_tree = proto_item_add_subtree(ti, ett_netmon_system_trace);

	switch (provider_id_data->opcode)
	{
	case 0:
		proto_tree_add_item(system_tree, hf_netmon_system_trace_buffer_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(system_tree, hf_netmon_system_trace_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(system_tree, hf_netmon_system_trace_provider_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(system_tree, hf_netmon_system_trace_num_processors, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		raw_timestamp = tvb_get_letoh64(tvb, offset);
		if (raw_timestamp != 0)
		{
			timestamp.secs = 0;
			timestamp.nsecs = 0;
			filetime_to_nstime(&timestamp, raw_timestamp);
			proto_tree_add_time(system_tree, hf_netmon_system_trace_end_time, tvb, offset, 8, &timestamp);
		}
		else
		{
			proto_tree_add_time_format_value(system_tree, hf_netmon_system_trace_end_time, tvb, offset, 8, &timestamp, "(None)");
		}
		offset += 8;

		proto_tree_add_item(system_tree, hf_netmon_system_trace_timer_resolution, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(system_tree, hf_netmon_system_trace_max_file_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(system_tree, hf_netmon_system_trace_log_file_mode, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(system_tree, hf_netmon_system_trace_buffers_written, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(system_tree, hf_netmon_system_trace_start_buffers, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(system_tree, hf_netmon_system_trace_pointers_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(system_tree, hf_netmon_system_trace_events_lost, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(system_tree, hf_netmon_system_trace_cpu_speed, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		netmon_etl_field(system_tree, tvb, &offset, hf_netmon_system_trace_logger_name, provider_id_data->event_flags);
		netmon_etl_field(system_tree, tvb, &offset, hf_netmon_system_trace_log_file_name_ptr, provider_id_data->event_flags);
		proto_tree_add_item(system_tree, hf_netmon_system_trace_time_zone_info, tvb, offset, 176, ENC_NA);
		offset += 176;

		timestamp.secs = 0;
		timestamp.nsecs = 0;
		filetime_to_nstime(&timestamp, tvb_get_letoh64(tvb, offset));
		proto_tree_add_time(system_tree, hf_netmon_system_trace_boot_time, tvb, offset, 8, &timestamp);
		offset += 8;

		proto_tree_add_item(system_tree, hf_netmon_system_trace_perf_freq, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		timestamp.secs = 0;
		timestamp.nsecs = 0;
		filetime_to_nstime(&timestamp, tvb_get_letoh64(tvb, offset));
		proto_tree_add_time(system_tree, hf_netmon_system_trace_start_time, tvb, offset, 8, &timestamp);
		offset += 8;

		proto_tree_add_item(system_tree, hf_netmon_system_trace_reserved_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(system_tree, hf_netmon_system_trace_buffers_lost, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		length = tvb_unicode_strsize(tvb, offset);
		proto_tree_add_item(system_tree, hf_netmon_system_trace_session_name, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
		offset += length;
		length = tvb_unicode_strsize(tvb, offset);
		proto_tree_add_item(system_tree, hf_netmon_system_trace_log_file_name, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
		break;
	case 5:
	case 32:
		proto_tree_add_item(system_tree, hf_netmon_system_trace_group_mask1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(system_tree, hf_netmon_system_trace_group_mask2, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(system_tree, hf_netmon_system_trace_group_mask3, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(system_tree, hf_netmon_system_trace_group_mask4, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(system_tree, hf_netmon_system_trace_group_mask5, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(system_tree, hf_netmon_system_trace_group_mask6, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(system_tree, hf_netmon_system_trace_group_mask7, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(system_tree, hf_netmon_system_trace_group_mask8, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(system_tree, hf_netmon_system_trace_kernel_event_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		break;
	case 8: // EventTrace_RDComplete
		break;
	}

	return tvb_captured_length(tvb);
}

static int
dissect_netmon_system_config(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item *ti;
	proto_tree *system_tree;
	int offset = 0;
	struct netmon_provider_id_data *provider_id_data = (struct netmon_provider_id_data*)data;
	unsigned length;
	uint32_t field1, field2;
	const uint8_t *str_field1, *str_field2, *str_field3, *str_field4;

	DISSECTOR_ASSERT(provider_id_data != NULL);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NetMon System Config");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_netmon_system_config, tvb, 0, -1, ENC_NA);
	system_tree = proto_item_add_subtree(ti, ett_netmon_system_config);

	switch (provider_id_data->event_version)
	{
	// SystemConfig_V0
	case 0:
		switch (provider_id_data->opcode)
		{
		case 10:
			proto_tree_add_item_ret_uint(system_tree, hf_netmon_system_config_mhz, tvb, offset, 4, ENC_LITTLE_ENDIAN, &field1);
			offset += 4;
			proto_tree_add_item_ret_uint(system_tree, hf_netmon_system_config_num_processors, tvb, offset, 4, ENC_LITTLE_ENDIAN, &field2);
			offset += 4;
			col_add_fstr(pinfo->cinfo, COL_INFO, "Processors: %u, (%u MHz)", field2, field1);

			proto_tree_add_item(system_tree, hf_netmon_system_config_mem_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_page_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_allocation_granularity, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_computer_name, tvb, offset, 512, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += 512;
			proto_tree_add_item(system_tree, hf_netmon_system_config_domain_name, tvb, offset, 264, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += 264;
			netmon_etl_field(system_tree, tvb, &offset, hf_netmon_system_config_hyper_threading_flag, provider_id_data->event_flags);
			break;
		case 11:
			proto_tree_add_item(system_tree, hf_netmon_system_config_disk_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_bytes_per_sector, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_sectors_per_track, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_tracks_per_cylinder, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_cylinders, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			offset += 8;
			proto_tree_add_item(system_tree, hf_netmon_system_config_scsi_port, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_scsi_path, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_scsi_target, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_scsi_lun, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_manufacturer, tvb, offset, 512, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field1);
			offset += 512;
			proto_tree_add_item(system_tree, hf_netmon_system_config_partition_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_write_cache_enabled, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;
			proto_tree_add_item(system_tree, hf_netmon_system_config_pad, tvb, offset, 1, ENC_NA);
			offset += 1;
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_boot_drive_letter, tvb, offset, 6, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field2);
			offset += 6;
			proto_tree_add_item(system_tree, hf_netmon_system_config_spare, tvb, offset, 4, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += 4;

			col_add_fstr(pinfo->cinfo, COL_INFO, "Manufacturer: %s, BootDriveLetter: %s", str_field1, str_field2);
			break;
		case 12:
			proto_tree_add_item(system_tree, hf_netmon_system_config_start_offset, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			offset += 8;
			proto_tree_add_item(system_tree, hf_netmon_system_config_partition_size, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			offset += 8;
			proto_tree_add_item(system_tree, hf_netmon_system_config_disk_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_drive_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_drive_letter, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field1);
			offset += 8;
			proto_tree_add_item(system_tree, hf_netmon_system_config_pad, tvb, offset, 4, ENC_NA);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_partition_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_sectors_per_cluster, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_bytes_per_sector, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_pad, tvb, offset, 4, ENC_NA);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_num_free_clusters, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			offset += 8;
			proto_tree_add_item(system_tree, hf_netmon_system_config_total_num_clusters, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			offset += 8;
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_file_system, tvb, offset, 32, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field2);
			offset += 32;
			col_add_fstr(pinfo->cinfo, COL_INFO, "Drive: %s, FileSystem: %s", str_field1, str_field2);
			proto_tree_add_item(system_tree, hf_netmon_system_config_volume_ext, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			break;
		case 13:
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_nic_name, tvb, offset, 512, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field1);
			offset += 512;
			proto_tree_add_item(system_tree, hf_netmon_system_config_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_physical_addr_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_physical_addr_str, tvb, offset, 16, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += 16;
			proto_tree_add_item(system_tree, hf_netmon_system_config_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_ip_address, tvb, offset, 4, ENC_BIG_ENDIAN);
			col_add_fstr(pinfo->cinfo, COL_INFO, "NIC: %s, Address: %s", str_field1, tvb_ip_to_str(pinfo->pool, tvb, offset));
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_subnet_mask, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_dhcp_server, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_gateway, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_primary_wins_server, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_secondary_wins_server, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_dns_server1, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_dns_server2, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_dns_server3, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_dns_server4, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_data, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			break;
		case 14:
			proto_tree_add_item(system_tree, hf_netmon_system_config_memory_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_x_resolution, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_y_resolution, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_bits_per_pixel, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_vrefresh, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_chip_type, tvb, offset, 512, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field1);
			offset += 512;
			proto_tree_add_item(system_tree, hf_netmon_system_config_dac_type, tvb, offset, 512, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += 512;
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_adapter_string, tvb, offset, 512, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field2);
			offset += 512;
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_bios_string, tvb, offset, 512, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field3);
			offset += 512;
			col_add_fstr(pinfo->cinfo, COL_INFO, "Chip: %s, Adapter: %s, Bios: %s", str_field1, str_field2, str_field3);
			proto_tree_add_item(system_tree, hf_netmon_system_config_device_id, tvb, offset, 512, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += 512;
			proto_tree_add_item(system_tree, hf_netmon_system_config_state_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			break;
		case 15:
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_service_name, tvb, offset, 68, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field1);
			offset += 68;
			proto_tree_add_item(system_tree, hf_netmon_system_config_display_name, tvb, offset, 512, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += 512;
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_process_name, tvb, offset, 68, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field2);
			offset += 68;
			col_add_fstr(pinfo->cinfo, COL_INFO, "Service: %s, Process: %s", str_field1, str_field2);
			proto_tree_add_item_ret_uint(system_tree, hf_netmon_system_config_process_id, tvb, offset, 4, ENC_LITTLE_ENDIAN, &field1);
			offset += 4;
			break;
		case 16:
			proto_tree_add_item(system_tree, hf_netmon_system_config_s1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;
			proto_tree_add_item(system_tree, hf_netmon_system_config_s2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;
			proto_tree_add_item(system_tree, hf_netmon_system_config_s3, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;
			proto_tree_add_item(system_tree, hf_netmon_system_config_s4, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;
			proto_tree_add_item(system_tree, hf_netmon_system_config_s5, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;
			proto_tree_add_item(system_tree, hf_netmon_system_config_pad, tvb, offset, 3, ENC_NA);
			offset += 3;
			break;
		case 21:
			proto_tree_add_item(system_tree, hf_netmon_system_config_irq_affinity, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			offset += 8;
			proto_tree_add_item_ret_uint(system_tree, hf_netmon_system_config_irq_num, tvb, offset, 4, ENC_LITTLE_ENDIAN, &field1);
			offset += 4;
			col_add_fstr(pinfo->cinfo, COL_INFO, "IRQ: %u", field1);
			proto_tree_add_item(system_tree, hf_netmon_system_config_device_desc_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			/* XXX - can we trust size above? */
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item(system_tree, hf_netmon_system_config_device_desc, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += length;
			break;
		case 22:
			proto_tree_add_item(system_tree, hf_netmon_system_config_device_id_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_device_desc_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_friendly_name_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			/* XXX - can we trust sizes above? */
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_device_id, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field1);
			offset += length;
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item(system_tree, hf_netmon_system_config_device_desc, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += length;
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_friendly_name, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field2);
			offset += length;
			col_add_fstr(pinfo->cinfo, COL_INFO, "ID: %s, Name: %s", str_field1, str_field2);
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item(system_tree, hf_netmon_system_config_pdo_name, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += length;
			break;
		}
		break;
	// SystemConfig_V1
	case 1:
		switch (provider_id_data->opcode)
		{
		case 10:
			proto_tree_add_item_ret_uint(system_tree, hf_netmon_system_config_mhz, tvb, offset, 4, ENC_LITTLE_ENDIAN, &field1);
			offset += 4;
			proto_tree_add_item_ret_uint(system_tree, hf_netmon_system_config_num_processors, tvb, offset, 4, ENC_LITTLE_ENDIAN, &field2);
			offset += 4;
			col_add_fstr(pinfo->cinfo, COL_INFO, "Processors: %u, (%u MHz)", field2, field1);

			proto_tree_add_item(system_tree, hf_netmon_system_config_mem_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_page_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_allocation_granularity, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_computer_name, tvb, offset, 512, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += 512;
			proto_tree_add_item(system_tree, hf_netmon_system_config_domain_name, tvb, offset, 264, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += 264;
			netmon_etl_field(system_tree, tvb, &offset, hf_netmon_system_config_hyper_threading_flag, provider_id_data->event_flags);
			break;
		case 11:
			proto_tree_add_item(system_tree, hf_netmon_system_config_disk_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_bytes_per_sector, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_sectors_per_track, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_tracks_per_cylinder, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_cylinders, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			offset += 8;
			proto_tree_add_item(system_tree, hf_netmon_system_config_scsi_port, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_scsi_path, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_scsi_target, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_scsi_lun, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_manufacturer, tvb, offset, 512, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field1);
			offset += 512;
			proto_tree_add_item(system_tree, hf_netmon_system_config_partition_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_write_cache_enabled, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;
			proto_tree_add_item(system_tree, hf_netmon_system_config_pad, tvb, offset, 1, ENC_NA);
			offset += 1;
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_boot_drive_letter, tvb, offset, 6, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field2);
			offset += 6;
			proto_tree_add_item(system_tree, hf_netmon_system_config_spare, tvb, offset, 4, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += 4;

			col_add_fstr(pinfo->cinfo, COL_INFO, "Manufacturer: %s, BootDriveLetter: %s", str_field1, str_field2);
			break;
		case 12:
			proto_tree_add_item(system_tree, hf_netmon_system_config_start_offset, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			offset += 8;
			proto_tree_add_item(system_tree, hf_netmon_system_config_partition_size, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			offset += 8;
			proto_tree_add_item(system_tree, hf_netmon_system_config_disk_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_drive_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_drive_letter, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field1);
			offset += 8;
			proto_tree_add_item(system_tree, hf_netmon_system_config_pad, tvb, offset, 4, ENC_NA);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_partition_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_sectors_per_cluster, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_bytes_per_sector, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_pad, tvb, offset, 4, ENC_NA);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_num_free_clusters, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			offset += 8;
			proto_tree_add_item(system_tree, hf_netmon_system_config_total_num_clusters, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			offset += 8;
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_file_system, tvb, offset, 32, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field2);
			offset += 32;
			col_add_fstr(pinfo->cinfo, COL_INFO, "Drive: %s, FileSystem: %s", str_field1, str_field2);
			proto_tree_add_item(system_tree, hf_netmon_system_config_volume_ext, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			break;
		case 13:
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_nic_name, tvb, offset, 512, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field1);
			offset += 512;
			proto_tree_add_item(system_tree, hf_netmon_system_config_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_physical_addr_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_physical_addr_str, tvb, offset, 16, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += 16;
			proto_tree_add_item(system_tree, hf_netmon_system_config_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_ip_address, tvb, offset, 4, ENC_BIG_ENDIAN);
			col_add_fstr(pinfo->cinfo, COL_INFO, "NIC: %s, Address: %s", str_field1, tvb_ip_to_str(pinfo->pool, tvb, offset));
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_subnet_mask, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_dhcp_server, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_gateway, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_primary_wins_server, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_secondary_wins_server, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_dns_server1, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_dns_server2, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_dns_server3, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_dns_server4, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_data, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			break;
		case 14:
			proto_tree_add_item(system_tree, hf_netmon_system_config_memory_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_x_resolution, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_y_resolution, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_bits_per_pixel, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_vrefresh, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_chip_type, tvb, offset, 512, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field1);
			offset += 512;
			proto_tree_add_item(system_tree, hf_netmon_system_config_dac_type, tvb, offset, 512, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += 512;
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_adapter_string, tvb, offset, 512, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field2);
			offset += 512;
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_bios_string, tvb, offset, 512, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field3);
			offset += 512;
			col_add_fstr(pinfo->cinfo, COL_INFO, "Chip: %s, Adapter: %s, Bios: %s", str_field1, str_field2, str_field3);
			proto_tree_add_item(system_tree, hf_netmon_system_config_device_id, tvb, offset, 512, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += 512;
			proto_tree_add_item(system_tree, hf_netmon_system_config_state_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			break;
		case 15:
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_service_name, tvb, offset, 68, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field1);
			offset += 68;
			proto_tree_add_item(system_tree, hf_netmon_system_config_display_name, tvb, offset, 512, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += 512;
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_process_name, tvb, offset, 68, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field2);
			offset += 68;
			col_add_fstr(pinfo->cinfo, COL_INFO, "Service: %s, Process: %s", str_field1, str_field2);
			proto_tree_add_item_ret_uint(system_tree, hf_netmon_system_config_process_id, tvb, offset, 4, ENC_LITTLE_ENDIAN, &field1);
			offset += 4;
			break;
		case 16:
			proto_tree_add_item(system_tree, hf_netmon_system_config_s1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;
			proto_tree_add_item(system_tree, hf_netmon_system_config_s2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;
			proto_tree_add_item(system_tree, hf_netmon_system_config_s3, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;
			proto_tree_add_item(system_tree, hf_netmon_system_config_s4, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;
			proto_tree_add_item(system_tree, hf_netmon_system_config_s5, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;
			proto_tree_add_item(system_tree, hf_netmon_system_config_pad, tvb, offset, 3, ENC_NA);
			offset += 3;
			break;
		case 21:
			proto_tree_add_item(system_tree, hf_netmon_system_config_irq_affinity, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			offset += 8;
			proto_tree_add_item_ret_uint(system_tree, hf_netmon_system_config_irq_num, tvb, offset, 4, ENC_LITTLE_ENDIAN, &field1);
			offset += 4;
			col_add_fstr(pinfo->cinfo, COL_INFO, "IRQ: %u", field1);
			proto_tree_add_item(system_tree, hf_netmon_system_config_device_desc_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			/* XXX - can we trust size above? */
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item(system_tree, hf_netmon_system_config_device_desc, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += length;
			break;
		case 22:
			proto_tree_add_item(system_tree, hf_netmon_system_config_device_id_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_device_desc_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_friendly_name_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			/* XXX - can we trust sizes above? */
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_device_id, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field1);
			offset += length;
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item(system_tree, hf_netmon_system_config_device_desc, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += length;
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_friendly_name, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field2);
			offset += length;
			col_add_fstr(pinfo->cinfo, COL_INFO, "ID: %s, Name: %s", str_field1, str_field2);
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item(system_tree, hf_netmon_system_config_pdo_name, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += length;
			break;
		}
		break;
	// SystemConfig_V2
	case 2:
		switch (provider_id_data->opcode)
		{
		case 10:
			proto_tree_add_item_ret_uint(system_tree, hf_netmon_system_config_mhz, tvb, offset, 4, ENC_LITTLE_ENDIAN, &field1);
			offset += 4;
			proto_tree_add_item_ret_uint(system_tree, hf_netmon_system_config_num_processors, tvb, offset, 4, ENC_LITTLE_ENDIAN, &field2);
			offset += 4;
			col_add_fstr(pinfo->cinfo, COL_INFO, "Processors: %u, (%u MHz)", field2, field1);

			proto_tree_add_item(system_tree, hf_netmon_system_config_mem_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_page_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_allocation_granularity, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_computer_name, tvb, offset, 512, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += 512;
			proto_tree_add_item(system_tree, hf_netmon_system_config_domain_name, tvb, offset, 268, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += 268;
			netmon_etl_field(system_tree, tvb, &offset, hf_netmon_system_config_hyper_threading_flag, provider_id_data->event_flags);
			break;
		case 11:
			proto_tree_add_item(system_tree, hf_netmon_system_config_disk_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_bytes_per_sector, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_sectors_per_track, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_tracks_per_cylinder, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_cylinders, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			offset += 8;
			proto_tree_add_item(system_tree, hf_netmon_system_config_scsi_port, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_scsi_path, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_scsi_target, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_scsi_lun, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_manufacturer, tvb, offset, 512, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field1);
			offset += 512;
			proto_tree_add_item(system_tree, hf_netmon_system_config_partition_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_write_cache_enabled, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;
			proto_tree_add_item(system_tree, hf_netmon_system_config_pad, tvb, offset, 1, ENC_NA);
			offset += 1;
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_boot_drive_letter, tvb, offset, 6, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field2);
			offset += 6;
			proto_tree_add_item(system_tree, hf_netmon_system_config_spare, tvb, offset, 4, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += 4;

			col_add_fstr(pinfo->cinfo, COL_INFO, "Manufacturer: %s, BootDriveLetter: %s", str_field1, str_field2);
			break;
		case 12:
			proto_tree_add_item(system_tree, hf_netmon_system_config_start_offset, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			offset += 8;
			proto_tree_add_item(system_tree, hf_netmon_system_config_partition_size, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			offset += 8;
			proto_tree_add_item(system_tree, hf_netmon_system_config_disk_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_drive_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_drive_letter, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field1);
			offset += 8;
			proto_tree_add_item(system_tree, hf_netmon_system_config_pad, tvb, offset, 4, ENC_NA);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_partition_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_sectors_per_cluster, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_bytes_per_sector, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_pad, tvb, offset, 4, ENC_NA);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_num_free_clusters, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			offset += 8;
			proto_tree_add_item(system_tree, hf_netmon_system_config_total_num_clusters, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			offset += 8;
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_file_system, tvb, offset, 32, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field2);
			offset += 32;
			col_add_fstr(pinfo->cinfo, COL_INFO, "Drive: %s, FileSystem: %s", str_field1, str_field2);
			proto_tree_add_item(system_tree, hf_netmon_system_config_volume_ext, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_pad, tvb, offset, 4, ENC_NA);
			offset += 4;
			break;
		case 13:
			proto_tree_add_item(system_tree, hf_netmon_system_config_physical_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			offset += 8;
			proto_tree_add_item(system_tree, hf_netmon_system_config_physical_addr_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_ipv4_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_ipv6_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item(system_tree, hf_netmon_system_config_nic_description, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += length;
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_ipaddresses, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field1);
			offset += length;
			col_add_fstr(pinfo->cinfo, COL_INFO, "IP Addresses: %s", str_field1);
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item(system_tree, hf_netmon_system_config_dns_server_addresses, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += length;
			break;
		case 14:
			proto_tree_add_item(system_tree, hf_netmon_system_config_memory_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_x_resolution, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_y_resolution, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_bits_per_pixel, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_vrefresh, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_chip_type, tvb, offset, 512, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field1);
			offset += 512;
			proto_tree_add_item(system_tree, hf_netmon_system_config_dac_type, tvb, offset, 512, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += 512;
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_adapter_string, tvb, offset, 512, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field2);
			offset += 512;
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_bios_string, tvb, offset, 512, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field3);
			offset += 512;
			col_add_fstr(pinfo->cinfo, COL_INFO, "Chip: %s, Adapter: %s, Bios: %s", str_field1, str_field2, str_field3);
			proto_tree_add_item(system_tree, hf_netmon_system_config_device_id, tvb, offset, 512, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += 512;
			proto_tree_add_item(system_tree, hf_netmon_system_config_state_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			break;
		case 15:
			proto_tree_add_item(system_tree, hf_netmon_system_config_process_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_service_state, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_sub_process_tag, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_service_name, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field1);
			offset += length;
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item(system_tree, hf_netmon_system_config_display_name, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += length;
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_process_name, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field2);
			offset += length;
			col_add_fstr(pinfo->cinfo, COL_INFO, "Service: %s, Process: %s", str_field1, str_field2);
			break;
		case 16:
			proto_tree_add_item(system_tree, hf_netmon_system_config_s1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;
			proto_tree_add_item(system_tree, hf_netmon_system_config_s2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;
			proto_tree_add_item(system_tree, hf_netmon_system_config_s3, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;
			proto_tree_add_item(system_tree, hf_netmon_system_config_s4, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;
			proto_tree_add_item(system_tree, hf_netmon_system_config_s5, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;
			proto_tree_add_item(system_tree, hf_netmon_system_config_pad, tvb, offset, 3, ENC_NA);
			offset += 3;
			break;
		case 17:
			proto_tree_add_item(system_tree, hf_netmon_system_config_tcb_table_partitions, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_max_hash_table_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item_ret_uint(system_tree, hf_netmon_system_config_max_user_port, tvb, offset, 4, ENC_LITTLE_ENDIAN, &field1);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_tcp_timed_wait_delay, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			col_add_fstr(pinfo->cinfo, COL_INFO, "MaxUserPort: %u", field1);
			break;
		case 21:
			proto_tree_add_item(system_tree, hf_netmon_system_config_irq_affinity, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			offset += 8;
			proto_tree_add_item_ret_uint(system_tree, hf_netmon_system_config_irq_num, tvb, offset, 4, ENC_LITTLE_ENDIAN, &field1);
			offset += 4;
			col_add_fstr(pinfo->cinfo, COL_INFO, "IRQ: %u", field1);
			proto_tree_add_item(system_tree, hf_netmon_system_config_device_desc_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			/* XXX - can we trust size above? */
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item(system_tree, hf_netmon_system_config_device_desc, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += length;
			break;
		case 22:
			proto_tree_add_item(system_tree, hf_netmon_system_config_device_id_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_device_desc_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_friendly_name_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			/* XXX - can we trust sizes above? */
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_device_id, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field1);
			offset += length;
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item(system_tree, hf_netmon_system_config_device_desc, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += length;
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_friendly_name, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field2);
			offset += length;
			col_add_fstr(pinfo->cinfo, COL_INFO, "ID: %s, Name: %s", str_field1, str_field2);
			break;
		case 23:
			proto_tree_add_item(system_tree, hf_netmon_system_config_target_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_device_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_device_timing_mode, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_location_information_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_location_information, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field1);
			offset += length;
			col_add_fstr(pinfo->cinfo, COL_INFO, "Location: %s", str_field1);
			break;
		case 25:
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_system_manufacturer, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field1);
			offset += length;
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_system_product_name, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field2);
			offset += length;
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_bios_date, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field3);
			offset += length;
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_bios_version, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field4);
			offset += length;
			col_add_fstr(pinfo->cinfo, COL_INFO, "Manufacturer: %s, ProductName: %s, BiosDate: %s, BiosVersion: %s", str_field1, str_field2, str_field3, str_field4);
			break;
		}
		break;
	// SystemConfig_V3
	case 3:
		switch (provider_id_data->opcode)
		{
		case 15:
			proto_tree_add_item_ret_uint(system_tree, hf_netmon_system_config_process_id, tvb, offset, 4, ENC_LITTLE_ENDIAN, &field1);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_service_state, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_sub_process_tag, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_service_name, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field1);
			offset += length;
			col_add_fstr(pinfo->cinfo, COL_INFO, "Service: %s, (PID=%d)", str_field1, field1);
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item(system_tree, hf_netmon_system_config_display_name, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += length;
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item(system_tree, hf_netmon_system_config_process_name, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += length;
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item(system_tree, hf_netmon_system_config_load_order_group, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += length;
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item(system_tree, hf_netmon_system_config_svc_host_group, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += length;
			break;
		case 21:
			proto_tree_add_item(system_tree, hf_netmon_system_config_irq_affinity, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			offset += 8;
			proto_tree_add_item(system_tree, hf_netmon_system_config_irq_group, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
			proto_tree_add_item(system_tree, hf_netmon_system_config_pad, tvb, offset, 2, ENC_NA);
			offset += 2;
			proto_tree_add_item_ret_uint(system_tree, hf_netmon_system_config_irq_num, tvb, offset, 4, ENC_LITTLE_ENDIAN, &field1);
			offset += 4;
			col_add_fstr(pinfo->cinfo, COL_INFO, "IRQ: %u", field1);
			proto_tree_add_item(system_tree, hf_netmon_system_config_device_desc_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			/* XXX - can we trust size above? */
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item(system_tree, hf_netmon_system_config_device_desc, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += length;
			break;
		case 22:
			proto_tree_add_item(system_tree, hf_netmon_system_config_device_id_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_device_desc_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(system_tree, hf_netmon_system_config_friendly_name_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			/* XXX - can we trust sizes above? */
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_device_id, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field1);
			offset += length;
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item(system_tree, hf_netmon_system_config_device_desc, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += length;
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item_ret_string(system_tree, hf_netmon_system_config_friendly_name, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16, pinfo->pool, &str_field2);
			offset += length;
			col_add_fstr(pinfo->cinfo, COL_INFO, "ID: %s, Name: %s", str_field1, str_field2);
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item(system_tree, hf_netmon_system_config_pdo_name, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += length;
			break;
		}
		break;
	}

	return offset;
}

static int
dissect_netmon_process(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item *ti;
	proto_tree *process_tree;
	int offset = 0;
	struct netmon_provider_id_data *provider_id_data = (struct netmon_provider_id_data*)data;
	unsigned length;
	const uint8_t *filename;

	DISSECTOR_ASSERT(provider_id_data != NULL);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NetMon Process");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_netmon_process, tvb, 0, -1, ENC_NA);
	process_tree = proto_item_add_subtree(ti, ett_netmon_process);

	switch (provider_id_data->event_version)
	{
	case 0:
		switch (provider_id_data->opcode)
		{
		case 1:
		case 2:
		case 3:
		case 4:
			proto_tree_add_item(process_tree, hf_netmon_process_process_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(process_tree, hf_netmon_process_parent_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			netmon_sid_field(process_tree, tvb, &offset, pinfo, hf_netmon_process_user_sid_revision,
							hf_netmon_process_user_sid_subauth_count, hf_netmon_process_user_sid_id, hf_netmon_process_user_sid_authority,
							&ei_netmon_process_user_sid, false);
			length = tvb_strsize(tvb, offset);
			proto_tree_add_item_ret_string(process_tree, hf_netmon_process_image_file_name, tvb, offset, length, ENC_NA|ENC_ASCII,
							pinfo->pool, &filename);
			col_add_fstr(pinfo->cinfo, COL_INFO, "Filename: %s", filename);
			offset += length;
			break;

		}
		break;
	case 1:
		switch (provider_id_data->opcode)
		{
		case 1:
		case 2:
		case 3:
		case 4:
			netmon_etl_field(process_tree, tvb, &offset, hf_netmon_process_page_directory_base, provider_id_data->event_flags);
			proto_tree_add_item(process_tree, hf_netmon_process_process_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(process_tree, hf_netmon_process_parent_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(process_tree, hf_netmon_process_session_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(process_tree, hf_netmon_process_exit_status, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			netmon_sid_field(process_tree, tvb, &offset, pinfo, hf_netmon_process_user_sid_revision,
							hf_netmon_process_user_sid_subauth_count, hf_netmon_process_user_sid_id, hf_netmon_process_user_sid_authority,
							&ei_netmon_process_user_sid, false);
			length = tvb_strsize(tvb, offset);
			proto_tree_add_item_ret_string(process_tree, hf_netmon_process_image_file_name, tvb, offset, length, ENC_NA|ENC_ASCII,
							pinfo->pool, &filename);
			col_add_fstr(pinfo->cinfo, COL_INFO, "Filename: %s", filename);
			offset += length;
			break;
		}
		break;
	case 2:
		switch (provider_id_data->opcode)
		{
		case 1:
		case 2:
		case 3:
		case 4:
		case 39:
			netmon_etl_field(process_tree, tvb, &offset, hf_netmon_process_unique_process_key, provider_id_data->event_flags);
			proto_tree_add_item(process_tree, hf_netmon_process_process_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(process_tree, hf_netmon_process_parent_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(process_tree, hf_netmon_process_session_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(process_tree, hf_netmon_process_exit_status, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			if (provider_id_data->event_flags & EVENT_HEADER_FLAG_64_BIT_HEADER)
			{
				proto_tree_add_item(process_tree, hf_netmon_process_unknown, tvb, offset, 16, ENC_NA);
				offset += 16;
			}
			else
			{
				proto_tree_add_item(process_tree, hf_netmon_process_unknown, tvb, offset, 8, ENC_NA);
				offset += 8;
			}
			netmon_sid_field(process_tree, tvb, &offset, pinfo, hf_netmon_process_user_sid_revision,
							hf_netmon_process_user_sid_subauth_count, hf_netmon_process_user_sid_id, hf_netmon_process_user_sid_authority,
							&ei_netmon_process_user_sid, false);
			length = tvb_strsize(tvb, offset);
			proto_tree_add_item_ret_string(process_tree, hf_netmon_process_image_file_name, tvb, offset, length, ENC_NA|ENC_ASCII,
							pinfo->pool, &filename);
			col_add_fstr(pinfo->cinfo, COL_INFO, "Filename: %s", filename);
			offset += length;

			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item(process_tree, hf_netmon_process_command_line, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += length;
			break;

		case 32:
		case 33:
			proto_tree_add_item(process_tree, hf_netmon_process_process_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(process_tree, hf_netmon_process_page_fault_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(process_tree, hf_netmon_process_handle_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(process_tree, hf_netmon_process_reserved, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(process_tree, hf_netmon_process_peak_virtual_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(process_tree, hf_netmon_process_peak_working_set_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(process_tree, hf_netmon_process_peak_page_file_usage, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(process_tree, hf_netmon_process_quota_peak_paged_pool_usage, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(process_tree, hf_netmon_process_quota_peak_non_paged_pool_usage, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(process_tree, hf_netmon_process_virtual_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(process_tree, hf_netmon_process_workingset_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(process_tree, hf_netmon_process_pagefile_usage, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(process_tree, hf_netmon_process_quota_paged_pool_usage, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(process_tree, hf_netmon_process_quota_non_paged_pool_usage, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(process_tree, hf_netmon_process_private_page_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			break;
		case 35:
			proto_tree_add_item(process_tree, hf_netmon_process_process_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(process_tree, hf_netmon_process_directory_table_base32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			break;
		}
		break;
	case 3:
		switch (provider_id_data->opcode)
		{
		case 1:
		case 2:
		case 3:
		case 4:
		case 39:
			netmon_etl_field(process_tree, tvb, &offset, hf_netmon_process_unique_process_key, provider_id_data->event_flags);
			proto_tree_add_item(process_tree, hf_netmon_process_process_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(process_tree, hf_netmon_process_parent_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(process_tree, hf_netmon_process_session_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(process_tree, hf_netmon_process_exit_status, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			netmon_etl_field(process_tree, tvb, &offset, hf_netmon_process_directory_table_base, provider_id_data->event_flags);
			if (provider_id_data->event_flags & EVENT_HEADER_FLAG_64_BIT_HEADER)
			{
				proto_tree_add_item(process_tree, hf_netmon_process_unknown, tvb, offset, 16, ENC_NA);
				offset += 16;
			}
			else
			{
				proto_tree_add_item(process_tree, hf_netmon_process_unknown, tvb, offset, 8, ENC_NA);
				offset += 8;
			}
			netmon_sid_field(process_tree, tvb, &offset, pinfo, hf_netmon_process_user_sid_revision,
							hf_netmon_process_user_sid_subauth_count, hf_netmon_process_user_sid_id, hf_netmon_process_user_sid_authority,
							&ei_netmon_process_user_sid, false);
			length = tvb_strsize(tvb, offset);
			proto_tree_add_item_ret_string(process_tree, hf_netmon_process_image_file_name, tvb, offset, length, ENC_NA|ENC_ASCII,
							pinfo->pool, &filename);
			col_add_fstr(pinfo->cinfo, COL_INFO, "Filename: %s", filename);
			offset += length;

			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item(process_tree, hf_netmon_process_command_line, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += length;
			break;
		}
		break;
	}

	return tvb_captured_length(tvb);
}

void proto_register_netmon(void)
{
	static hf_register_info hf_header[] = {
		{ &hf_netmon_header_title_comment,
			{ "Comment title", "netmon_header.title_comment",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_header_description_comment,
			{ "Comment description", "netmon_header.description_comment",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
	};


	static hf_register_info hf_event[] = {
		{ &hf_netmon_event_size,
			{ "Size", "netmon_event.size",
			FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_event_header_type,
			{ "Header type", "netmon_event.header_type",
			FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_event_flags,
			{ "Flags", "netmon_event.flags",
			FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_event_flags_extended_info,
			{ "Extended Info", "netmon_event.flags.extended_info",
			FT_BOOLEAN, 16, TFS(&tfs_present_not_present), EVENT_HEADER_FLAG_EXTENDED_INFO, NULL, HFILL }
		},
		{ &hf_netmon_event_flags_private_session,
			{ "Private Sessions", "netmon_event.flags.private_session",
			FT_BOOLEAN, 16, TFS(&tfs_yes_no), EVENT_HEADER_FLAG_PRIVATE_SESSION, NULL, HFILL }
		},
		{ &hf_netmon_event_flags_string_only,
			{ "Null-terminated Unicode string", "netmon_event.flags.string_only",
			FT_BOOLEAN, 16, TFS(&tfs_yes_no), EVENT_HEADER_FLAG_STRING_ONLY, NULL, HFILL }
		},
		{ &hf_netmon_event_flags_trace_message,
			{ "TraceMessage logged", "netmon_event.flags.trace_message",
			FT_BOOLEAN, 16, TFS(&tfs_yes_no), EVENT_HEADER_FLAG_TRACE_MESSAGE, NULL, HFILL }
		},
		{ &hf_netmon_event_flags_no_cputime,
			{ "Use ProcessorTime", "netmon_event.flags.no_cputime",
			FT_BOOLEAN, 16, TFS(&tfs_yes_no), EVENT_HEADER_FLAG_NO_CPUTIME, NULL, HFILL }
		},
		{ &hf_netmon_event_flags_32bit_header,
			{ "Provider running on 32-bit computer", "netmon_event.flags.32bit_header",
			FT_BOOLEAN, 16, TFS(&tfs_yes_no), EVENT_HEADER_FLAG_32_BIT_HEADER, NULL, HFILL }
		},
		{ &hf_netmon_event_flags_64bit_header,
			{ "Provider running on 64-bit computer", "netmon_event.flags.64bit_header",
			FT_BOOLEAN, 16, TFS(&tfs_yes_no), EVENT_HEADER_FLAG_64_BIT_HEADER, NULL, HFILL }
		},
		{ &hf_netmon_event_flags_classic_header,
			{ "Use TraceEvent", "netmon_event.flags.classic_header",
			FT_BOOLEAN, 16, TFS(&tfs_yes_no), EVENT_HEADER_FLAG_CLASSIC_HEADER, NULL, HFILL }
		},
		{ &hf_netmon_event_event_property,
			{ "Event property", "netmon_event.event_property",
			FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_event_event_property_xml,
			{ "Need manifest", "netmon_event.event_property.xml",
			FT_BOOLEAN, 16, TFS(&tfs_yes_no), EVENT_HEADER_PROPERTY_XML, NULL, HFILL }
		},
		{ &hf_netmon_event_event_property_forwarded_xml,
			{ "Event data contains fully-rendered XML", "netmon_event.event_property.forwarded_xml",
			FT_BOOLEAN, 16, TFS(&tfs_yes_no), EVENT_HEADER_PROPERTY_FORWARDED_XML, NULL, HFILL }
		},
		{ &hf_netmon_event_event_property_legacy_eventlog,
			{ "Need WMI MOF class", "netmon_event.event_property.legacy_eventlog",
			FT_BOOLEAN, 16, TFS(&tfs_yes_no), EVENT_HEADER_PROPERTY_LEGACY_EVENTLOG, NULL, HFILL }
		},
		{ &hf_netmon_event_thread_id,
			{ "Thread ID", "netmon_event.thread_id",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_event_process_id,
			{ "Process ID", "netmon_event.process_id",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_event_timestamp,
			{ "Timestamp", "netmon_event.timestamp",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_event_provider_id,
			{ "Provider ID", "netmon_event.provider_id",
			FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_event_event_desc_id,
			{ "ID", "netmon_event.event_desc.id",
			FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_event_event_desc_version,
			{ "Version", "netmon_event.event_desc.version",
			FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_event_event_desc_channel,
			{ "Channel", "netmon_event.event_desc.channel",
			FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_event_event_desc_level,
			{ "Level", "netmon_event.event_desc.level",
			FT_UINT8, BASE_DEC, VALS(event_level_vals), 0x0, NULL, HFILL }
		},
		{ &hf_netmon_event_event_desc_opcode,
			{ "Opcode", "netmon_event.event_desc.opcode",
			FT_UINT8, BASE_HEX, VALS(opcode_vals), 0x0, NULL, HFILL }
		},
		{ &hf_netmon_event_event_desc_task,
			{ "Task", "netmon_event.event_desc.task",
			FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_event_event_desc_keyword,
			{ "Keyword", "netmon_event.event_desc.keyword",
			FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_event_kernel_time,
			{ "Kernel time", "netmon_event.kernel_time",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_event_user_time,
			{ "User time", "netmon_event.user_time",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_event_processor_time,
			{ "Processor time", "netmon_event.processor_time",
			FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_event_activity_id,
			{ "Activity ID", "netmon_event.activity_id",
			FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_event_processor_number,
			{ "Processor number", "netmon_event.processor_number",
			FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_event_alignment,
			{ "Alignment", "netmon_event.alignment",
			FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_event_logger_id,
			{ "Logger ID", "netmon_event.logger_id",
			FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_event_extended_data_count,
			{ "Extended data count", "netmon_event.extended_data_count",
			FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_event_user_data_length,
			{ "User data length", "netmon_event.user_data_length",
			FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_event_reassembled,
			{ "Reassembled", "netmon_event.reassembled",
			FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_event_extended_data_reserved,
			{ "Reserved", "netmon_event.extended_data.reserved",
			FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_event_extended_data_type,
			{ "Extended info type", "netmon_event.extended_data.type",
			FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_event_extended_data_linkage,
			{ "Additional extended data", "netmon_event.extended_data.linkage",
			FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0001, NULL, HFILL }
		},
		{ &hf_netmon_event_extended_data_reserved2,
			{ "Reserved", "netmon_event.extended_data.reserved2",
			FT_UINT16, BASE_HEX, NULL, 0xFFFE, NULL, HFILL }
		},
		{ &hf_netmon_event_extended_data_size,
			{ "Extended data size", "netmon_event.extended_data.size",
			FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_event_extended_data,
			{ "Extended data", "netmon_event.extended_data",
			FT_BYTES, BASE_NONE|BASE_ALLOW_ZERO, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_event_user_data,
			{ "User data", "netmon_event.user_data",
			FT_BYTES, BASE_NONE|BASE_ALLOW_ZERO, NULL, 0x0, NULL, HFILL }
		},
	};

	static hf_register_info hf_filter[] = {
		{ &hf_netmon_filter_version,
			{ "Version", "netmon_filter.version",
			FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_filter_type,
			{ "Filter type", "netmon_filter.type",
			FT_UINT32, BASE_DEC|BASE_RANGE_STRING, RVALS(filter_types), 0x0, NULL, HFILL }
		},
		{ &hf_netmon_filter_app_major_version,
			{ "App Major Version", "netmon_filter.app_major_version",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_filter_app_minor_version,
			{ "App Minor Version", "netmon_filter.app_minor_version",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_filter_app_name,
			{ "Application Name", "netmon_filter.app_name",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_filter_filter,
			{ "Filter", "netmon_filter.filter",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
	};

	static hf_register_info hf_network_info[] = {
		{ &hf_netmon_network_info_version,
			{ "Version", "netmon_network_info.version",
			FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_network_info_adapter_count,
			{ "Adapter count", "netmon_network_info.adapter_count",
			FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_network_info_computer_name,
			{ "Computer name", "netmon_network_info.computer_name",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_network_info_friendly_name,
			{ "Friendly name", "netmon_network_info.friendly_name",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_network_info_description,
			{ "Description", "netmon_network_info.description",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_network_info_miniport_guid,
			{ "Miniport GUID", "netmon_network_info.miniport_guid",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_network_info_media_type,
			{ "Media type", "netmon_network_info.media_type",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_network_info_mtu,
			{ "MTU", "netmon_network_info.mtu",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_network_info_link_speed,
			{ "Link speed", "netmon_network_info.link_speed",
			FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_network_info_mac_address,
			{ "MAC address", "netmon_network_info.mac_address",
			FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_network_info_ipv4_count,
			{ "IPv4 count", "netmon_network_info.ipv4_count",
			FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_network_info_ipv6_count,
			{ "IPv6 count", "netmon_network_info.ipv6_count",
			FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_network_info_gateway_count,
			{ "Gateway count", "netmon_network_info.gateway_count",
			FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_network_info_dhcp_server_count,
			{ "DHCP server count", "netmon_network_info.dhcp_server_count",
			FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_network_info_dns_ipv4_count,
			{ "DNS IPv4 count", "netmon_network_info.dns_ipv4_count",
			FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_network_info_dns_ipv6_count,
			{ "DNS IPv6 count", "netmon_network_info.dns_ipv6_count",
			FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_network_info_ipv4,
			{ "IPv4 address", "netmon_network_info.ipv4",
			FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_network_info_subnet,
			{ "Subnet mask", "netmon_network_info.subnet",
			FT_IPv4, BASE_NETMASK, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_network_info_ipv6,
			{ "IPv6 address", "netmon_network_info.ipv6",
			FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_network_info_gateway,
			{ "Gateway address", "netmon_network_info.gateway",
			FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_network_info_dhcp_server,
			{ "DHCP Server", "netmon_network_info.dhcp_server",
			FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_network_info_dns_ipv4,
			{ "DNS IPv4 address", "netmon_network_info.dns_ipv4",
			FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_network_info_dns_ipv6,
			{ "DNS IPv6 address", "netmon_network_info.dns_ipv6",
			FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
	};

	static hf_register_info hf_system_trace[] = {
		{ &hf_netmon_system_trace_buffer_size,
			{ "Buffer size", "netmon_system_trace.buffer_size",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_trace_version,
			{ "Version", "netmon_system_trace.version",
			FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_trace_provider_version,
			{ "Provider version", "netmon_system_trace.provider_version",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_trace_num_processors,
			{ "Number of processors", "netmon_system_trace.num_processors",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_trace_end_time,
			{ "End time", "netmon_system_trace.end_time",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_trace_timer_resolution,
			{ "Timer resolution", "netmon_system_trace.timer_resolution",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_trace_max_file_size,
			{ "Max file size", "netmon_system_trace.max_file_size",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_trace_log_file_mode,
			{ "Log file mode", "netmon_system_trace.log_file_mode",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_trace_buffers_written,
			{ "Buffers written", "netmon_system_trace.buffers_written",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_trace_start_buffers,
			{ "Start buffers", "netmon_system_trace.start_buffers",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_trace_pointers_size,
			{ "Pointers size", "netmon_system_trace.pointers_size",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_trace_events_lost,
			{ "Events lost", "netmon_system_trace.events_lost",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_trace_cpu_speed,
			{ "CPU speed", "netmon_system_trace.cpu_speed",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_trace_logger_name,
			{ "Logger name", "netmon_system_trace.logger_name",
			FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_trace_log_file_name_ptr,
			{ "Log file name", "netmon_system_trace.log_file_name_ptr",
			FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_trace_time_zone_info,
			{ "Time zone info", "netmon_system_trace.time_zone_info",
			FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_trace_boot_time,
			{ "Boot time", "netmon_system_trace.boot_time",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_trace_perf_freq,
			{ "Perf freq", "netmon_system_trace.pref_freq",
			FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_trace_start_time,
			{ "Start time", "netmon_system_trace.start_time",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_trace_reserved_flags,
			{ "Reserved Flags", "netmon_system_trace.reserved_flags",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_trace_buffers_lost,
			{ "Buffers lost", "netmon_system_trace.buffers_lost",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_trace_session_name,
			{ "Session name", "netmon_system_trace.session_name",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_trace_log_file_name,
			{ "Log file name", "netmon_system_trace.log_file_name",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_trace_group_mask1,
			{ "Group Mask1", "netmon_system_trace.group_mask1",
			FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_trace_group_mask2,
			{ "Group Mask2", "netmon_system_trace.group_mask2",
			FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_trace_group_mask3,
			{ "Group Mask3", "netmon_system_trace.group_mask3",
			FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_trace_group_mask4,
			{ "Group Mask4", "netmon_system_trace.group_mask4",
			FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_trace_group_mask5,
			{ "Group Mask5", "netmon_system_trace.group_mask5",
			FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_trace_group_mask6,
			{ "Group Mask6", "netmon_system_trace.group_mask6",
			FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_trace_group_mask7,
			{ "Group Mask7", "netmon_system_trace.group_mask7",
			FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_trace_group_mask8,
			{ "Group Mask8", "netmon_system_trace.group_mask8",
			FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_trace_kernel_event_version,
			{ "Kernel event version", "netmon_system_trace.kernel_event_version",
			FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
	};

	static hf_register_info hf_system_config[] = {
		{ &hf_netmon_system_config_mhz,
			{ "Mhz", "netmon_system_config.mhz",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_num_processors,
			{ "Number of processors", "netmon_system_config.num_processors",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_mem_size,
			{ "Memory size", "netmon_system_config.mem_size",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_page_size,
			{ "Page size", "netmon_system_config.page_size",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_allocation_granularity,
			{ "Allocation granularity", "netmon_system_config.allocation_granularity",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_computer_name,
			{ "Computer name", "netmon_system_config.computer_name",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_domain_name,
			{ "Domain name", "netmon_system_config.domain_name",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_hyper_threading_flag,
			{ "Hyper threading flag", "netmon_system_config.hyper_threading_flag",
			FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_disk_number,
			{ "Disk number", "netmon_system_config.disk_number",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_bytes_per_sector,
			{ "Bytes per sector", "netmon_system_config.bytes_per_sector",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_sectors_per_track,
			{ "Sectors per track", "netmon_system_config.sectors_per_track",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_tracks_per_cylinder,
			{ "Tracks per cylinder", "netmon_system_config.tracks_per_cylinder",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_cylinders,
			{ "Cylinders", "netmon_system_config.cylinders",
			FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_scsi_port,
			{ "SCSI port", "netmon_system_config.scsi_port",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_scsi_path,
			{ "SCSI path", "netmon_system_config.scsi_path",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_scsi_target,
			{ "SCSI target", "netmon_system_config.csi_target",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_scsi_lun,
			{ "SCSI lun", "netmon_system_config.scsi_lun",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_manufacturer,
			{ "Manufacturer", "netmon_system_config.manufacturer",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_partition_count,
			{ "Partition count", "netmon_system_config.partition_count",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_write_cache_enabled,
			{ "Write cache enabled", "netmon_system_config.write_cache_enabled",
			FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_pad,
			{ "Pad", "netmon_system_config.pad",
			FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_boot_drive_letter,
			{ "Boot drive letter", "netmon_system_config.boot_drive_letter",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_spare,
			{ "Spare", "netmon_system_config.spare",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_start_offset,
			{ "Start offset", "netmon_system_config.start_offset",
			FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_partition_size,
			{ "Partition size", "netmon_system_config.partition_size",
			FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_size,
			{ "Size", "netmon_system_config.size",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_drive_type,
			{ "Drive type", "netmon_system_config.drive_type",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_drive_letter,
			{ "Drive letter", "netmon_system_config.drive_letter",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_partition_number,
			{ "Partition number", "netmon_system_config.partition_number",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_sectors_per_cluster,
			{ "Sectors per cluster", "netmon_system_config.sectors_per_cluster",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_num_free_clusters,
			{ "Number of free clusters", "netmon_system_config.num_free_clusters",
			FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_total_num_clusters,
			{ "Total number of clusters", "netmon_system_config.total_num_clusters",
			FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_file_system,
			{ "File system", "netmon_system_config.file_system",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_volume_ext,
			{ "Volume ext", "netmon_system_config.volume_ext",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_physical_addr,
			{ "Physical address", "netmon_system_config.physical_addr",
			FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_physical_addr_len,
			{ "Physical address length", "netmon_system_config.physical_addr_len",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_ipv4_index,
			{ "IPv4 index", "netmon_system_config.ipv4_index",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_ipv6_index,
			{ "IPv6 index", "netmon_system_config.ipv6_index",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_nic_description,
			{ "File system", "netmon_system_config.file_system",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_ipaddresses,
			{ "IP addresses", "netmon_system_config.ipaddresses",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_dns_server_addresses,
			{ "DNS server addresses", "netmon_system_config.dns_server_addresses",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_memory_size,
			{ "Memory size", "netmon_system_config.memory_size",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_x_resolution,
			{ "X resolution", "netmon_system_config.x_resolution",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_y_resolution,
			{ "Y resolution", "netmon_system_config.y_resolution",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_bits_per_pixel,
			{ "Bits per pixel", "netmon_system_config.bits_per_pixel",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_vrefresh,
			{ "VRefresh", "netmon_system_config.vrefresh",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_chip_type,
			{ "Chip type", "netmon_system_config.chip_type",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_dac_type,
			{ "DAC type", "netmon_system_config.dac_type",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_adapter_string,
			{ "Adapter string", "netmon_system_config.adapter_string",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_bios_string,
			{ "BIOS string", "netmon_system_config.bios_string",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_device_id,
			{ "Device ID", "netmon_system_config.device_id",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_state_flags,
			{ "State flags", "netmon_system_config.state_flags",
			FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_process_id,
			{ "Process ID", "netmon_system_config.process_id",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_service_state,
			{ "Service state", "netmon_system_config.service_state",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_sub_process_tag,
			{ "Subprocess tag", "netmon_system_config.sub_process_tag",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_service_name,
			{ "Service name", "netmon_system_config.service_name",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_display_name,
			{ "Display name", "netmon_system_config.display_name",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_process_name,
			{ "Process name", "netmon_system_config.process_name",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_s1,
			{ "S1", "netmon_system_config.s1",
			FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_s2,
			{ "S2", "netmon_system_config.s2",
			FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_s3,
			{ "S3", "netmon_system_config.s3",
			FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_s4,
			{ "S4", "netmon_system_config.s4",
			FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_s5,
			{ "S5", "netmon_system_config.s5",
			FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_tcb_table_partitions,
			{ "Tcb table partitions", "netmon_system_config.tcb_table_partitions",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_max_hash_table_size,
			{ "Max hash table size", "netmon_system_config.max_hash_table_size",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_max_user_port,
			{ "Max user port", "netmon_system_config.max_user_port",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_tcp_timed_wait_delay,
			{ "TCP timed wait delay", "netmon_system_config.tcp_timed_wait_delay",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_irq_affinity,
			{ "IRQ affinity", "netmon_system_config.irq_affinity",
			FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_irq_num,
			{ "IRQ", "netmon_system_config.irq_num",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_device_desc_len,
			{ "Device description length", "netmon_system_config.device_desc_len",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_device_desc,
			{ "Device description", "netmon_system_config.device_desc",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_friendly_name,
			{ "Friendly name", "netmon_system_config.friendly_name",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_device_id_len,
			{ "Device ID length", "netmon_system_config.device_id_len",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_friendly_name_len,
			{ "Friendly name length", "netmon_system_config.friendly_name_len",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_target_id,
			{ "Target ID", "netmon_system_config.target_id",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_device_type,
			{ "Device type", "netmon_system_config.device_type",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_device_timing_mode,
			{ "Device timing mode", "netmon_system_config.device_timing_mode",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_location_information_len,
			{ "Location information length", "netmon_system_config.location_information_len",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_location_information,
			{ "Location information", "netmon_system_config.location_information",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_system_manufacturer,
			{ "System manufacturer", "netmon_system_config.system_manufacturer",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_system_product_name,
			{ "System product name", "netmon_system_config.system_product_name",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_bios_date,
			{ "BIOS date", "netmon_system_config.bios_date",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_bios_version,
			{ "BIOS version", "netmon_system_config.bios_version",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_load_order_group,
			{ "Load order group", "netmon_system_config.load_order_group",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_svc_host_group,
			{ "svchost group", "netmon_system_config.svc_host_group",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_irq_group,
			{ "IRQ group", "netmon_system_config.irq_group",
			FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_pdo_name,
			{ "PDO name", "netmon_system_config.pdo_name",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_nic_name,
			{ "NIC name", "netmon_system_config.nic_name",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_index,
			{ "Index", "netmon_system_config.index",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_physical_addr_str,
			{ "Physical address", "netmon_system_config.physical_addr_str",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_ip_address,
			{ "IP address", "netmon_system_config.ip_address",
			FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_subnet_mask,
			{ "Subnet mask", "netmon_system_config.subnet_mask",
			FT_IPv4, BASE_NETMASK, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_dhcp_server,
			{ "DHCP server", "netmon_system_config.dhcp_server",
			FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_gateway,
			{ "Gateway", "netmon_system_config.gateway",
			FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_primary_wins_server,
			{ "Primary WINS server", "netmon_system_config.primary_wins_server",
			FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_secondary_wins_server,
			{ "Secondary WINS server", "netmon_system_config.secondary_wins_server",
			FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_dns_server1,
			{ "DNS server1", "netmon_system_config.dns_server1",
			FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_dns_server2,
			{ "DNS server2", "netmon_system_config.dns_server2",
			FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_dns_server3,
			{ "DNS server3", "netmon_system_config.dns_server3",
			FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_dns_server4,
			{ "DNS server4", "netmon_system_config.dns_server4",
			FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_system_config_data,
			{ "Data", "netmon_system_config.data",
			FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
	};

	static hf_register_info hf_process[] = {
		{ &hf_netmon_process_unique_process_key,
			{ "Unique process key", "netmon_process.unique_process_key",
			FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_process_process_id,
			{ "Process ID", "netmon_process.process_id",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_process_parent_id,
			{ "Parent ID", "netmon_process.parent_id",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_process_session_id,
			{ "Session ID", "netmon_process.session_id",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_process_exit_status,
			{ "Exit status", "netmon_process.exit_status",
			FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_process_directory_table_base,
			{ "Directory table base", "netmon_process.directory_table_base",
			FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_process_unknown,
			{ "Unknown", "netmon_process.unknown",
			FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_process_user_sid_revision,
			{ "User SID Revision", "netmon_process.user_sid.revision",
			FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_process_user_sid_subauth_count,
			{ "User SID Subauth count", "netmon_process.user_sid.subauth_count",
			FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_process_user_sid_id,
			{ "User SID Identifier Authority", "netmon_process.user_sid.id",
			FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_process_user_sid_authority,
			{ "User SID Authority", "netmon_process.user_sid.authority",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_process_image_file_name,
			{ "Image file name", "netmon_process.image_file_name",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_process_command_line,
			{ "Commandline", "netmon_process.command_line",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_process_page_directory_base,
			{ "Page directory base", "netmon_process.page_directory_base",
			FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_process_page_fault_count,
			{ "Page fault count", "netmon_process.page_fault_count",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_process_handle_count,
			{ "Handle count", "netmon_process.handle_count",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_process_reserved,
			{ "Reserved", "netmon_process.reserved",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_process_peak_virtual_size,
			{ "Peak virtual size", "netmon_process.peak_virtual_size",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_process_peak_working_set_size,
			{ "Peak working set size", "netmon_process.peak_working_set_size",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_process_peak_page_file_usage,
			{ "Peak page file usage", "netmon_process.peak_page_file_usage",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_process_quota_peak_paged_pool_usage,
			{ "Quota peak paged pool usage", "netmon_process.quota_peak_paged_pool_usage",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_process_quota_peak_non_paged_pool_usage,
			{ "Quota peak non-paged pool usage", "netmon_process.quota_peak_non_paged_pool_usage",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_process_virtual_size,
			{ "Virtual size", "netmon_process.virtual_size",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_process_workingset_size,
			{ "Working set size", "netmon_process.workingset_size",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_process_pagefile_usage,
			{ "Pagefile usage", "netmon_process.pagefile_usage",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_process_quota_paged_pool_usage,
			{ "Quota paged pool usage", "netmon_process.quota_paged_pool_usage",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_process_quota_non_paged_pool_usage,
			{ "Quota nonpaged pool usage", "netmon_process.quota_non_paged_pool_usage",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_process_private_page_count,
			{ "Private page count", "netmon_process.private_page_count",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_process_directory_table_base32,
			{ "Directory table base", "netmon_process.directory_table_base32",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
	};

	static int *ett[] = {
		&ett_netmon_header,
		&ett_netmon_event,
		&ett_netmon_event_desc,
		&ett_netmon_event_flags,
		&ett_netmon_event_property,
		&ett_netmon_event_extended_data,
		&ett_netmon_filter,
		&ett_netmon_network_info,
		&ett_netmon_network_info_list,
		&ett_netmon_network_info_adapter,
		&ett_netmon_system_trace,
		&ett_netmon_event_buffer_context,
		&ett_netmon_process,
		&ett_netmon_sid,
		&ett_netmon_system_config,
	};

	static ei_register_info ei_process[] = {
		{ &ei_netmon_process_user_sid, { "netmon_process.process_user_sid.invalid", PI_MALFORMED, PI_WARN, "Invalid SID", EXPFILL }},
	};

	expert_module_t *expert_process;

	proto_netmon_header = proto_register_protocol ("Network Monitor Header", "NetMon Header", "netmon_header" );
	proto_netmon_event = proto_register_protocol ("Network Monitor Event", "NetMon Event", "netmon_event" );
	proto_netmon_filter = proto_register_protocol ("Network Monitor Filter", "NetMon Filter", "netmon_filter" );
	proto_netmon_network_info = proto_register_protocol ("Network Monitor Network Info", "NetMon Network Info", "netmon_network_info" );
	proto_netmon_system_trace = proto_register_protocol ("Network Monitor System Trace", "NetMon System Trace", "netmon_system_trace" );
	proto_netmon_system_config = proto_register_protocol ("Network Monitor System Config", "NetMon System Config", "netmon_system_config" );
	proto_netmon_process = proto_register_protocol ("Network Monitor Process", "NetMon Process", "netmon_process" );

	provider_id_table = register_dissector_table("netmon.provider_id", "NetMon Provider IDs", proto_netmon_event, FT_GUID, BASE_HEX);

	proto_register_field_array(proto_netmon_header, hf_header, array_length(hf_header));
	proto_register_field_array(proto_netmon_event, hf_event, array_length(hf_event));
	proto_register_field_array(proto_netmon_filter, hf_filter, array_length(hf_filter));
	proto_register_field_array(proto_netmon_network_info, hf_network_info, array_length(hf_network_info));
	proto_register_field_array(proto_netmon_system_trace, hf_system_trace, array_length(hf_system_trace));
	proto_register_field_array(proto_netmon_system_config, hf_system_config, array_length(hf_system_config));
	proto_register_field_array(proto_netmon_process, hf_process, array_length(hf_process));
	proto_register_subtree_array(ett, array_length(ett));

	expert_process = expert_register_protocol(proto_netmon_process);
	expert_register_field_array(expert_process, ei_process, array_length(ei_process));
}

void proto_reg_handoff_netmon(void)
{
	dissector_handle_t netmon_event_handle, netmon_filter_handle,
						netmon_network_info_handle, netmon_header_handle,
						system_trace_handle, system_config_handle, process_handle;

	static guid_key system_trace_guid = {{ 0x68fdd900, 0x4a3e, 0x11d1, { 0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3 }}, 0 };
	static guid_key system_config_guid = {{ 0x01853a65, 0x418f, 0x4f36, { 0xae, 0xfc, 0xdc, 0x0f, 0x1d, 0x2f, 0xd2, 0x35 }}, 0 };
	static guid_key process_guid = {{ 0x3d6fa8d0, 0xfe05, 0x11d0, { 0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c }}, 0 };

	netmon_event_handle = create_dissector_handle(dissect_netmon_event, proto_netmon_event);
	netmon_filter_handle = create_dissector_handle(dissect_netmon_filter, proto_netmon_filter);
	netmon_network_info_handle = create_dissector_handle(dissect_netmon_network_info, proto_netmon_network_info);
	netmon_header_handle = create_dissector_handle(dissect_netmon_header, proto_netmon_header);
	system_trace_handle = create_dissector_handle(dissect_netmon_system_trace, proto_netmon_system_trace);
	system_config_handle = create_dissector_handle(dissect_netmon_system_config, proto_netmon_system_config);
	process_handle = create_dissector_handle(dissect_netmon_process, proto_netmon_process);

	dissector_add_uint("wtap_encap", WTAP_ENCAP_NETMON_NET_NETEVENT, netmon_event_handle);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_NETMON_NET_FILTER, netmon_filter_handle);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_NETMON_NETWORK_INFO_EX, netmon_network_info_handle);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_NETMON_HEADER, netmon_header_handle);

	dissector_add_guid( "netmon.provider_id", &system_trace_guid, system_trace_handle);
	dissector_add_guid( "netmon.provider_id", &system_config_guid, system_config_handle);
	dissector_add_guid( "netmon.provider_id", &process_guid, process_handle);

	wtap_encap_table = find_dissector_table("wtap_encap");
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
