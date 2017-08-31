/* packet-netmon.c
 * Routines for Network Monitor capture dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 *
 * Network Event Tracing event taken from:
 *
 * http://msdn.microsoft.com/en-us/library/aa363759(VS.85).aspx
 */

#include "config.h"

#include <epan/packet.h>
#include <wiretap/wtap.h>

void proto_register_netmon(void);
void proto_reg_handoff_netmon(void);

#define EVENT_HEADER_FLAG_EXTENDED_INFO         0x0001
#define EVENT_HEADER_FLAG_PRIVATE_SESSION       0x0002
#define EVENT_HEADER_FLAG_STRING_ONLY           0x0004
#define EVENT_HEADER_FLAG_TRACE_MESSAGE         0x0008
#define EVENT_HEADER_FLAG_NO_CPUTIME            0x0010
#define EVENT_HEADER_FLAG_32_BIT_HEADER         0x0020
#define EVENT_HEADER_FLAG_64_BIT_HEADER         0x0040
#define EVENT_HEADER_FLAG_CLASSIC_HEADER        0x0100

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

static const range_string filter_types[] = {
	{ 0,	0,	"Display Filter" },
	{ 1,	1,	"Capture Filter" },
	{ 2,	0xFFFFFFFF,	"Display Filter" },
	{ 0, 0, NULL }
};

/* Initialize the protocol and registered fields */
static int proto_netmon_header = -1;
static int proto_netmon_event = -1;
static int proto_netmon_filter = -1;
static int proto_netmon_network_info = -1;

static int hf_netmon_header_title_comment = -1;
static int hf_netmon_header_description_comment = -1;

static int hf_netmon_event_size = -1;
static int hf_netmon_event_header_type = -1;
static int hf_netmon_event_flags = -1;
static int hf_netmon_event_flags_extended_info = -1;
static int hf_netmon_event_flags_private_session = -1;
static int hf_netmon_event_flags_string_only = -1;
static int hf_netmon_event_flags_trace_message = -1;
static int hf_netmon_event_flags_no_cputime = -1;
static int hf_netmon_event_flags_32bit_header = -1;
static int hf_netmon_event_flags_64bit_header = -1;
static int hf_netmon_event_flags_classic_header = -1;
static int hf_netmon_event_event_property = -1;
static int hf_netmon_event_event_property_xml = -1;
static int hf_netmon_event_event_property_forwarded_xml = -1;
static int hf_netmon_event_event_property_legacy_eventlog = -1;
static int hf_netmon_event_thread_id = -1;
static int hf_netmon_event_process_id = -1;
static int hf_netmon_event_timestamp = -1;
static int hf_netmon_event_provider_id = -1;
static int hf_netmon_event_event_desc_id = -1;
static int hf_netmon_event_event_desc_version = -1;
static int hf_netmon_event_event_desc_channel = -1;
static int hf_netmon_event_event_desc_level = -1;
static int hf_netmon_event_event_desc_opcode = -1;
static int hf_netmon_event_event_desc_task = -1;
static int hf_netmon_event_event_desc_keyword = -1;
static int hf_netmon_event_kernel_time = -1;
static int hf_netmon_event_user_time = -1;
static int hf_netmon_event_processor_time = -1;
static int hf_netmon_event_activity_id = -1;
static int hf_netmon_event_processor_number = -1;
static int hf_netmon_event_alignment = -1;
static int hf_netmon_event_logger_id = -1;
static int hf_netmon_event_extended_data_count = -1;
static int hf_netmon_event_user_data_length = -1;
static int hf_netmon_event_extended_data_reserved = -1;
static int hf_netmon_event_extended_data_type = -1;
static int hf_netmon_event_extended_data_linkage = -1;
static int hf_netmon_event_extended_data_reserved2 = -1;
static int hf_netmon_event_extended_data_size = -1;
static int hf_netmon_event_extended_data = -1;
static int hf_netmon_event_user_data = -1;

static int hf_netmon_filter_version = -1;
static int hf_netmon_filter_type = -1;
static int hf_netmon_filter_app_major_version = -1;
static int hf_netmon_filter_app_minor_version = -1;
static int hf_netmon_filter_app_name = -1;
static int hf_netmon_filter_filter = -1;

static int hf_netmon_network_info_version = -1;
static int hf_netmon_network_info_adapter_count = -1;
static int hf_netmon_network_info_computer_name = -1;
static int hf_netmon_network_info_friendly_name = -1;
static int hf_netmon_network_info_description = -1;
static int hf_netmon_network_info_miniport_guid = -1;
static int hf_netmon_network_info_media_type = -1;
static int hf_netmon_network_info_mtu = -1;
static int hf_netmon_network_info_link_speed = -1;
static int hf_netmon_network_info_mac_address = -1;
static int hf_netmon_network_info_ipv4_count = -1;
static int hf_netmon_network_info_ipv6_count = -1;
static int hf_netmon_network_info_gateway_count = -1;
static int hf_netmon_network_info_dhcp_server_count = -1;
static int hf_netmon_network_info_dns_ipv4_count = -1;
static int hf_netmon_network_info_dns_ipv6_count = -1;
static int hf_netmon_network_info_ipv4 = -1;
static int hf_netmon_network_info_subnet = -1;
static int hf_netmon_network_info_ipv6 = -1;
static int hf_netmon_network_info_gateway = -1;
static int hf_netmon_network_info_dhcp_server = -1;
static int hf_netmon_network_info_dns_ipv4 = -1;
static int hf_netmon_network_info_dns_ipv6 = -1;

/* Initialize the subtree pointers */
static gint ett_netmon_header = -1;
static gint ett_netmon_event = -1;
static gint ett_netmon_event_desc = -1;
static gint ett_netmon_event_flags = -1;
static gint ett_netmon_event_property = -1;
static gint ett_netmon_event_extended_data = -1;
static gint ett_netmon_filter = -1;
static gint ett_netmon_network_info = -1;
static gint ett_netmon_network_info_list = -1;
static gint ett_netmon_network_info_adapter = -1;

static dissector_table_t wtap_encap_table;

/* Code to actually dissect the packets */
static int
dissect_netmon_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item *ti;
	proto_tree *header_tree;
	union wtap_pseudo_header temp_header;
	gchar *comment;
	GIConv cd;

	ti = proto_tree_add_item(tree, proto_netmon_header, tvb, 0, 0, ENC_NA);
	header_tree = proto_item_add_subtree(ti, ett_netmon_header);

	if (pinfo->pseudo_header->netmon.title != NULL) {
		/* Title comment is UTF-16 */

		if ((cd = g_iconv_open("UTF-8", "UTF-16")) != (GIConv) -1)
		{
			comment = g_convert_with_iconv(pinfo->pseudo_header->netmon.title, pinfo->pseudo_header->netmon.titleLength, cd, NULL, NULL, NULL);
			g_iconv_close(cd);

			ti = proto_tree_add_string(header_tree, hf_netmon_header_title_comment, tvb, 0, 0, comment);
			PROTO_ITEM_SET_GENERATED(ti);
			g_free(comment);
		}

	}

	if (pinfo->pseudo_header->netmon.description != NULL) {
		/* Description comment is only ASCII */

		/* Ensure string termination */
		comment = wmem_strndup(wmem_packet_scope(), pinfo->pseudo_header->netmon.description, pinfo->pseudo_header->netmon.descLength);

		ti = proto_tree_add_string(header_tree, hf_netmon_header_description_comment, tvb, 0, 0, comment);
		PROTO_ITEM_SET_GENERATED(ti);
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
		pinfo->pseudo_header->netmon.sub_encap, tvb, pinfo, tree, TRUE,
		(void *)pinfo->pseudo_header)) {
		call_data_dissector(tvb, pinfo, tree);
	}

	return tvb_captured_length(tvb);
}

static int
dissect_netmon_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item *ti, *extended_data_item;
	proto_tree *event_tree, *event_desc_tree, *extended_data_tree;
	int offset = 0, extended_data_count_offset;
	guint32 i, thread_id, process_id, extended_data_count, extended_data_size, user_data_size;
	nstime_t timestamp;
	static const int * event_flags[] = {
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
	static const int * event_property[] = {
		&hf_netmon_event_event_property_xml,
		&hf_netmon_event_event_property_forwarded_xml,
		&hf_netmon_event_event_property_legacy_eventlog,
		NULL
	};

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NetMon Event");
	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_netmon_event, tvb, offset, -1, ENC_NA);
	event_tree = proto_item_add_subtree(ti, ett_netmon_event);

	proto_tree_add_item(event_tree, hf_netmon_event_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(event_tree, hf_netmon_event_header_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
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
	offset += 16;

	col_add_fstr(pinfo->cinfo, COL_INFO, "Thread ID: %d, Process ID: %d", thread_id, process_id);

	event_desc_tree = proto_tree_add_subtree(event_tree, tvb, offset, 16, ett_netmon_event_desc, NULL, "Event Descriptor");
	proto_tree_add_item(event_desc_tree, hf_netmon_event_event_desc_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(event_desc_tree, hf_netmon_event_event_desc_version, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;
	proto_tree_add_item(event_desc_tree, hf_netmon_event_event_desc_channel, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;
	proto_tree_add_item(event_desc_tree, hf_netmon_event_event_desc_level, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;
	proto_tree_add_item(event_desc_tree, hf_netmon_event_event_desc_opcode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;
	proto_tree_add_item(event_desc_tree, hf_netmon_event_event_desc_task, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(event_desc_tree, hf_netmon_event_event_desc_keyword, tvb, offset, 8, ENC_LITTLE_ENDIAN);
	offset += 8;

	proto_tree_add_item(event_tree, hf_netmon_event_processor_time, tvb, offset, 8, ENC_LITTLE_ENDIAN);
	/* Kernel and User time are a union with processor time */
	proto_tree_add_item(event_tree, hf_netmon_event_kernel_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;
	proto_tree_add_item(event_tree, hf_netmon_event_user_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(event_tree, hf_netmon_event_activity_id, tvb, offset, 16, ENC_LITTLE_ENDIAN);
	offset += 16;
	proto_tree_add_item(event_tree, hf_netmon_event_processor_number, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;
	proto_tree_add_item(event_tree, hf_netmon_event_alignment, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;
	proto_tree_add_item(event_tree, hf_netmon_event_logger_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item_ret_uint(event_tree, hf_netmon_event_extended_data_count, tvb, offset, 2, ENC_LITTLE_ENDIAN, &extended_data_count);
	offset += 2;
	proto_tree_add_item_ret_uint(event_tree, hf_netmon_event_user_data_length, tvb, offset, 2, ENC_LITTLE_ENDIAN, &user_data_size);
	offset += 2;

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

	proto_tree_add_item(event_tree, hf_netmon_event_user_data, tvb, offset, user_data_size, ENC_NA);

	return tvb_captured_length(tvb);
}


static int
dissect_netmon_filter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item *ti;
	proto_tree *filter_tree;
	int offset = 0;
	guint length;
	const guint8* filter;

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
									wmem_packet_scope(), &filter);
	col_add_fstr(pinfo->cinfo, COL_INFO, "Filter: %s", filter);

	return tvb_captured_length(tvb);
}


static int
dissect_netmon_network_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item *ti, *list_item, *adapter_item;
	proto_tree *network_info_tree, *list_tree, *adapter_tree;
	int offset = 0, list_start_offset, adapter_start_offset;
	guint adapter, adapter_count, length;
	guint64 link_speed;

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
			guint32 loop, ipv4_count, ipv6_count, gateway_count, dhcp_server_count, dns_ipv4_count, dns_ipv6_count;

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
			else if (link_speed >= 1000 * 1000 * 1024)
			{
			    proto_tree_add_uint64_format_value(adapter_tree, hf_netmon_network_info_link_speed, tvb, offset, 8, link_speed, "%" G_GINT64_MODIFIER "u Gbps", link_speed/(1000*1000*1000));
			}
			else if (link_speed >= 1000 * 1000)
			{
			    proto_tree_add_uint64_format_value(adapter_tree, hf_netmon_network_info_link_speed, tvb, offset, 8, link_speed, "%" G_GINT64_MODIFIER "u Mbps", link_speed/(1000*1000));
			}
			else if (link_speed >= 1000 * 1000)
			{
			    proto_tree_add_uint64_format_value(adapter_tree, hf_netmon_network_info_link_speed, tvb, offset, 8, link_speed, "%" G_GINT64_MODIFIER "u Kbps", link_speed/1000);
			}
			else
			{
			    proto_tree_add_uint64_format_value(adapter_tree, hf_netmon_network_info_link_speed, tvb, offset, 8, link_speed, "%" G_GINT64_MODIFIER "u bps", link_speed);
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
			FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_event_event_desc_version,
			{ "Version", "netmon_event.event_desc.version",
			FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_event_event_desc_channel,
			{ "Channel", "netmon_event.event_desc.channel",
			FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_event_event_desc_level,
			{ "Level", "netmon_event.event_desc.level",
			FT_UINT8, BASE_DEC, VALS(event_level_vals), 0x0, NULL, HFILL }
		},
		{ &hf_netmon_event_event_desc_opcode,
			{ "Opcode", "netmon_event.event_desc.opcode",
			FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
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
			FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_filter_filter,
			{ "Filter", "netmon_filter.filter",
			FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
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
			FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_network_info_friendly_name,
			{ "Friendly name", "netmon_network_info.friendly_name",
			FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_network_info_description,
			{ "Description", "netmon_network_info.description",
			FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_netmon_network_info_miniport_guid,
			{ "Miniport GUID", "netmon_network_info.miniport_guid",
			FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
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

	static gint *ett[] = {
		&ett_netmon_header,
		&ett_netmon_event,
		&ett_netmon_event_desc,
		&ett_netmon_event_flags,
		&ett_netmon_event_property,
		&ett_netmon_event_extended_data,
		&ett_netmon_filter,
		&ett_netmon_network_info,
		&ett_netmon_network_info_list,
		&ett_netmon_network_info_adapter
	};

	proto_netmon_header = proto_register_protocol ("Network Monitor Header", "NetMon Header", "netmon_header" );
	proto_netmon_event = proto_register_protocol ("Network Monitor Event", "NetMon Event", "netmon_event" );
	proto_netmon_filter = proto_register_protocol ("Network Monitor Filter", "NetMon Filter", "netmon_filter" );
	proto_netmon_network_info = proto_register_protocol ("Network Monitor Network Info", "NetMon Network Info", "netmon_network_info" );

	proto_register_field_array(proto_netmon_header, hf_header, array_length(hf_header));
	proto_register_field_array(proto_netmon_event, hf_event, array_length(hf_event));
	proto_register_field_array(proto_netmon_filter, hf_filter, array_length(hf_filter));
	proto_register_field_array(proto_netmon_network_info, hf_network_info, array_length(hf_network_info));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_netmon(void)
{
	dissector_handle_t netmon_event_handle, netmon_filter_handle,
						netmon_network_info_handle, netmon_header_handle;

	netmon_event_handle = create_dissector_handle(dissect_netmon_event, proto_netmon_event);
	netmon_filter_handle = create_dissector_handle(dissect_netmon_filter, proto_netmon_filter);
	netmon_network_info_handle = create_dissector_handle(dissect_netmon_network_info, proto_netmon_network_info);
	netmon_header_handle = create_dissector_handle(dissect_netmon_header, proto_netmon_header);

	dissector_add_uint("wtap_encap", WTAP_ENCAP_NETMON_NET_NETEVENT, netmon_event_handle);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_NETMON_NET_FILTER, netmon_filter_handle);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_NETMON_NETWORK_INFO_EX, netmon_network_info_handle);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_NETMON_HEADER, netmon_header_handle);

	wtap_encap_table = find_dissector_table("wtap_encap");
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
