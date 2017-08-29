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

/* Initialize the protocol and registered fields */
static int proto_netmon_event = -1;

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


/* Initialize the subtree pointers */
static gint ett_netmon_event = -1;
static gint ett_netmon_event_desc = -1;
static gint ett_netmon_event_flags = -1;
static gint ett_netmon_event_property = -1;
static gint ett_netmon_event_extended_data = -1;

/* Code to actually dissect the packets */
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

void proto_register_netmon(void)
{
	static hf_register_info hf[] = {
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

	static gint *ett[] = {
		&ett_netmon_event,
		&ett_netmon_event_desc,
		&ett_netmon_event_flags,
		&ett_netmon_event_property,
		&ett_netmon_event_extended_data
	};

	proto_netmon_event = proto_register_protocol ("Network Monitor Event", "NetMon Event", "netmon_event" );
	proto_register_field_array(proto_netmon_event, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_netmon(void)
{
	dissector_handle_t netmon_handle;

	netmon_handle = create_dissector_handle(dissect_netmon_event, proto_netmon_event);

	dissector_add_uint("wtap_encap", WTAP_ENCAP_NETMON_NET_NETEVENT, netmon_handle);
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
