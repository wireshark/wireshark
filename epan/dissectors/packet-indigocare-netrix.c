/* packet-indigocare-netrix.c
 * Dissector routines for the IndigoCare Netrix protocols
 * By Erik de Jong <erikdejong@gmail.com>
 * Copyright 2016 Erik de Jong
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <range.h>
#include <wiretap/wtap.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <wsutil/strtoi.h>

#define INDIGOCARE_NETRIX_SOH				0x01
#define INDIGOCARE_NETRIX_STX				0x02
#define INDIGOCARE_NETRIX_ETX				0x03
#define INDIGOCARE_NETRIX_EOT				0x04
#define INDIGOCARE_NETRIX_ACK				0x06
#define INDIGOCARE_NETRIX_US				0x1F
#define INDIGOCARE_NETRIX_RS				0x1E

#define INDIGOCARE_NETRIX_SYSTEMINFO			0x01
#define INDIGOCARE_NETRIX_GROUP				0x0A
#define INDIGOCARE_NETRIX_PROFILE			0x0F
#define INDIGOCARE_NETRIX_GET_CONVERSIONTABLE		0x23
#define INDIGOCARE_NETRIX_GET_CONVERSIONTABLE_BEGIN	0x88B8
#define INDIGOCARE_NETRIX_GET_CONVERSIONTABLE_END	0x8C9E
#define INDIGOCARE_NETRIX_GET_CONVERSIONTABLE_NONE	0x8C9F
#define INDIGOCARE_NETRIX_SEARCH_CONVERSIONTABLES	0x24
#define INDIGOCARE_NETRIX_SEARCH_CONVERSIONTABLES_BEGIN	0x8CA0
#define INDIGOCARE_NETRIX_SEARCH_CONVERSIONTABLES_END	0x9086
#define INDIGOCARE_NETRIX_SEARCH_CONVERSIONTABLES_NONE	0x9087
#define INDIGOCARE_NETRIX_BOSCH				0x69

#define INDIGOCARE_NETRIX_SYSTEMINFO_COMPUTERNAME	0x01
#define INDIGOCARE_NETRIX_SYSTEMINFO_IPADDRESS		0x02
#define INDIGOCARE_NETRIX_SYSTEMINFO_VERSION		0x03
#define INDIGOCARE_NETRIX_SYSTEMINFO_BEEP		0x04

#define INDIGOCARE_NETRIX_GROUP_GROUPNUMBER		0x01
#define INDIGOCARE_NETRIX_GROUP_TYPE			0x02
#define INDIGOCARE_NETRIX_GROUP_ADDITION		0x03
#define INDIGOCARE_NETRIX_GROUP_IDBOSCHLOC		0x04
#define INDIGOCARE_NETRIX_GROUP_NAME			0x05
#define INDIGOCARE_NETRIX_GROUP_ROOM			0x06
#define INDIGOCARE_NETRIX_GROUP_LOCATION		0x07

#define INDIGOCARE_NETRIX_PROFILE_PROFILENUMBER		0x01
#define INDIGOCARE_NETRIX_PROFILE_TYPE			0x02
#define INDIGOCARE_NETRIX_PROFILE_ADDITION		0x03
#define INDIGOCARE_NETRIX_PROFILE_IDBOSCHLOC		0x04
#define INDIGOCARE_NETRIX_PROFILE_NAME			0x05
#define INDIGOCARE_NETRIX_PROFILE_ROOM			0x06
#define INDIGOCARE_NETRIX_PROFILE_LOCATION		0x07

#define INDIGOCARE_NETRIX_GET_CONVERSIONTABLE_TABLE	0x01

#define INDIGOCARE_NETRIX_GET_CONVERSIONTABLE_KEY	0x01
#define INDIGOCARE_NETRIX_GET_CONVERSIONTABLE_VALUE	0x02

#define INDIGOCARE_NETRIX_SEARCH_CONVERSIONTABLES_KEY	0x01

#define INDIGOCARE_NETRIX_SEARCH_CONVERSIONTABLES_TABLE	0x01

void proto_reg_handoff_netrix(void);
void proto_register_netrix(void);

static expert_field ei_netrix_unexpected_header = EI_INIT;
static expert_field ei_netrix_unexpected_record = EI_INIT;

static int proto_netrix = -1;
static int hf_netrix_header_type = -1;
static int hf_netrix_header_systeminfo_type = -1;
static int hf_netrix_header_groupcall_type = -1;
static int hf_netrix_header_profilecall_type = -1;
static int hf_netrix_header_get_conversiontable_type = -1;
static int hf_netrix_header_get_conversiontable_none_type = -1;
static int hf_netrix_header_get_conversiontable_result_type = -1;
static int hf_netrix_header_search_conversiontables_type = -1;
static int hf_netrix_header_search_conversiontables_none_type = -1;
static int hf_netrix_header_boschcall_type = -1;

static int hf_netrix_ack_type = -1;

static int hf_netrix_systeminfo_computername_type = -1;
static int hf_netrix_systeminfo_ipaddress_type = -1;
static int hf_netrix_systeminfo_version_type = -1;
static int hf_netrix_systeminfo_beep_type = -1;

static int hf_netrix_groupcall_groupnumber_type = -1;
static int hf_netrix_groupcall_type_type = -1;
static int hf_netrix_groupcall_addition_type = -1;
static int hf_netrix_groupcall_idboschloc_type = -1;
static int hf_netrix_groupcall_name_type = -1;
static int hf_netrix_groupcall_room_type = -1;
static int hf_netrix_groupcall_location_type = -1;

static int hf_netrix_profilecall_groupnumber_type = -1;
static int hf_netrix_profilecall_type_type = -1;
static int hf_netrix_profilecall_addition_type = -1;
static int hf_netrix_profilecall_idboschloc_type = -1;
static int hf_netrix_profilecall_name_type = -1;
static int hf_netrix_profilecall_room_type = -1;
static int hf_netrix_profilecall_location_type = -1;

static int hf_netrix_get_conversiontable_table_type = -1;
static int hf_netrix_get_conversiontable_key_type = -1;
static int hf_netrix_get_conversiontable_value_type = -1;

static int hf_netrix_search_conversiontables_key_type = -1;
static int hf_netrix_search_conversiontables_table_type = -1;

static gint ett_netrix = -1;
static gint ett_netrix_systeminfo = -1;
static gint ett_netrix_groupcall = -1;
static gint ett_netrix_profilecall = -1;
static gint ett_netrix_get_conversiontable = -1;
static gint ett_netrix_get_conversiontable_result = -1;
static gint ett_netrix_search_conversiontables = -1;
static gint ett_netrix_search_conversiontables_result = -1;
static gint ett_netrix_boschcall = -1;
static gint ett_netrix_unknown = -1;

static const value_string netrix_headertypenames[] = {
	{ INDIGOCARE_NETRIX_SYSTEMINFO,				"System Info" },
	{ INDIGOCARE_NETRIX_GROUP,				"Group Call" },
	{ INDIGOCARE_NETRIX_PROFILE,				"Profile Call" },
	{ INDIGOCARE_NETRIX_GET_CONVERSIONTABLE,		"Get Conversiontable" },
	{ INDIGOCARE_NETRIX_GET_CONVERSIONTABLE_NONE,		"Get Conversiontable - No Results" },
	{ INDIGOCARE_NETRIX_SEARCH_CONVERSIONTABLES,		"Search Conversiontables" },
	{ INDIGOCARE_NETRIX_SEARCH_CONVERSIONTABLES_NONE,	"Search Conversiontables - No Results" },
	{ INDIGOCARE_NETRIX_BOSCH,				"Bosch Call" },
	{ 0, NULL }
};

static int
dissect_netrix(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	proto_item *ti;
	proto_item *header_item;
	proto_tree *netrix_tree;
	proto_tree *netrix_header_tree;
	gint32 current_offset = 0, header_offset, identifier_start, identifier_offset, data_start, data_offset, ett;
	gint32 header;
	gint32 record_identifier;
	gint32 group_number;
	gint32 profile_number;
	const char * record_data;

	/* Corner case: 'EssecProtocolWithAck' ACK */
	if (( tvb_get_guint8(tvb, 0) == INDIGOCARE_NETRIX_ACK ) && (tvb_reported_length(tvb) == 1)) {
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "Netrix");
		col_clear(pinfo->cinfo, COL_INFO);
		ti = proto_tree_add_item(tree, proto_netrix, tvb, 0, -1, ENC_NA);
		netrix_tree = proto_item_add_subtree(ti, ett_netrix);
		col_add_fstr(pinfo->cinfo, COL_INFO, "Ack");
		proto_tree_add_item(netrix_tree, hf_netrix_ack_type, tvb, 0, 1, ENC_NA);
		return 1;
	}

	/* Starts with SOH */
	if ( tvb_get_guint8(tvb, 0) != INDIGOCARE_NETRIX_SOH )
		return 0;
	/* Ends with ETX or EOT */
	if ((tvb_captured_length(tvb) == tvb_reported_length(tvb)) && (( tvb_get_guint8(tvb, tvb_reported_length(tvb) - 1) != INDIGOCARE_NETRIX_ETX ) && ( tvb_get_guint8(tvb, tvb_reported_length(tvb) - 1) != INDIGOCARE_NETRIX_EOT ))) {
		return 0;
	}
	/* It is a Netrix Communication Protocol packet */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Netrix");
	col_clear(pinfo->cinfo, COL_INFO);
	ti = proto_tree_add_item(tree, proto_netrix, tvb, 0, -1, ENC_NA);
	netrix_tree = proto_item_add_subtree(ti, ett_netrix);
	current_offset++;

	/* Read header */
	header_offset = tvb_find_guint8(tvb, current_offset, -1, INDIGOCARE_NETRIX_STX);
	if(!ws_strtoi32(tvb_get_string_enc(wmem_packet_scope(), tvb, current_offset, header_offset - current_offset, ENC_ASCII|ENC_NA), NULL, &header)) {
		/* Warn about invalid header? */
		return 0;
	}
	switch(header) {
		case INDIGOCARE_NETRIX_SYSTEMINFO:
			ett = ett_netrix_systeminfo;
			header_item = proto_tree_add_item(netrix_tree, hf_netrix_header_systeminfo_type, tvb, current_offset, header_offset - current_offset, ENC_NA);
			col_set_str(pinfo->cinfo, COL_INFO, "Systeminfo:");
		break;
		case INDIGOCARE_NETRIX_GROUP:
			ett = ett_netrix_groupcall;
			header_item = proto_tree_add_item(netrix_tree, hf_netrix_header_groupcall_type, tvb, current_offset, header_offset - current_offset, ENC_NA);
			col_set_str(pinfo->cinfo, COL_INFO, "Group Call:");
		break;
		case INDIGOCARE_NETRIX_PROFILE:
			ett = ett_netrix_profilecall;
			header_item = proto_tree_add_item(netrix_tree, hf_netrix_header_profilecall_type, tvb, current_offset, header_offset - current_offset, ENC_NA);
			col_set_str(pinfo->cinfo, COL_INFO, "Profile Call:");
		break;
		case INDIGOCARE_NETRIX_GET_CONVERSIONTABLE:
			ett = ett_netrix_get_conversiontable;
			header_item = proto_tree_add_item(netrix_tree, hf_netrix_header_get_conversiontable_type, tvb, current_offset, header_offset - current_offset, ENC_NA);
			col_set_str(pinfo->cinfo, COL_INFO, "Get Conversiontable:");
		break;
		case INDIGOCARE_NETRIX_GET_CONVERSIONTABLE_NONE:
			ett = ett_netrix_get_conversiontable_result;
			header_item = proto_tree_add_item(netrix_tree, hf_netrix_header_get_conversiontable_none_type, tvb, current_offset, header_offset - current_offset, ENC_NA);
			col_set_str(pinfo->cinfo, COL_INFO, "Get Conversiontable: No Results");
		break;
		case INDIGOCARE_NETRIX_SEARCH_CONVERSIONTABLES:
			ett = ett_netrix_search_conversiontables;
			header_item = proto_tree_add_item(netrix_tree, hf_netrix_header_search_conversiontables_type, tvb, current_offset, header_offset - current_offset, ENC_NA);
			col_set_str(pinfo->cinfo, COL_INFO, "Search Conversiontables:");
		break;
		case INDIGOCARE_NETRIX_SEARCH_CONVERSIONTABLES_NONE:
			ett = ett_netrix_search_conversiontables_result;
			header_item = proto_tree_add_item(netrix_tree, hf_netrix_header_search_conversiontables_none_type, tvb, current_offset, header_offset - current_offset, ENC_NA);
			col_set_str(pinfo->cinfo, COL_INFO, "Search Conversiontables: No Results");
		break;
		case INDIGOCARE_NETRIX_BOSCH:
			ett = ett_netrix_boschcall;
			header_item = proto_tree_add_item(netrix_tree, hf_netrix_header_boschcall_type, tvb, current_offset, header_offset - current_offset, ENC_NA);
			col_set_str(pinfo->cinfo, COL_INFO, "Bosch Call:");
		break;
		default:
			if ((header >= INDIGOCARE_NETRIX_GET_CONVERSIONTABLE_BEGIN) && (header <= INDIGOCARE_NETRIX_GET_CONVERSIONTABLE_END)) {
				ett = ett_netrix_get_conversiontable_result;
				header_item = proto_tree_add_item(netrix_tree, hf_netrix_header_get_conversiontable_result_type, tvb, current_offset, header_offset - current_offset, ENC_NA);
				col_add_fstr(pinfo->cinfo, COL_INFO, "Get Conversiontable result %d:", header - INDIGOCARE_NETRIX_GET_CONVERSIONTABLE_BEGIN);
			} else if ((header >= INDIGOCARE_NETRIX_SEARCH_CONVERSIONTABLES_BEGIN) && (header <= INDIGOCARE_NETRIX_SEARCH_CONVERSIONTABLES_END)) {
				ett = ett_netrix_search_conversiontables_result;
				header_item = proto_tree_add_item(netrix_tree, hf_netrix_header_get_conversiontable_result_type, tvb, current_offset, header_offset - current_offset, ENC_NA);
				col_add_fstr(pinfo->cinfo, COL_INFO, "Search Conversiontables result %d:", header - INDIGOCARE_NETRIX_SEARCH_CONVERSIONTABLES_BEGIN);
			} else {
				proto_tree_add_expert_format(netrix_tree, pinfo, &ei_netrix_unexpected_header, tvb, current_offset, header_offset -  current_offset, "Unexpected header %d", header);
				ett = ett_netrix_unknown;
				header_item = proto_tree_add_uint_format_value(netrix_tree, hf_netrix_header_type, tvb, current_offset, header_offset - current_offset, header, "%d", header);
				col_add_fstr(pinfo->cinfo, COL_INFO, "%s:", val_to_str(header, netrix_headertypenames, "Unknown (%d)"));
			}
		break;
	}
	netrix_header_tree = proto_item_add_subtree(header_item, ett);
	current_offset = header_offset + 1;

	/* Read records */
	while (tvb_get_guint8(tvb, current_offset) != INDIGOCARE_NETRIX_ETX) {
		identifier_start = current_offset;
		identifier_offset = tvb_find_guint8(tvb, current_offset, -1, INDIGOCARE_NETRIX_US);
		ws_strtoi32(tvb_get_string_enc(wmem_packet_scope(), tvb, current_offset, identifier_offset - current_offset, ENC_ASCII|ENC_NA), NULL, &record_identifier);
		current_offset = identifier_offset + 1;

		data_start = current_offset;
		data_offset = tvb_find_guint8(tvb, current_offset, -1, INDIGOCARE_NETRIX_RS);
		record_data = tvb_get_string_enc(wmem_packet_scope(), tvb, current_offset, data_offset - current_offset, ENC_ASCII|ENC_NA);

		current_offset = data_offset + 1;

		switch (header) {
			case INDIGOCARE_NETRIX_SYSTEMINFO:
				switch (record_identifier) {
					case INDIGOCARE_NETRIX_SYSTEMINFO_COMPUTERNAME:
						proto_tree_add_item(netrix_header_tree, hf_netrix_systeminfo_computername_type, tvb, data_start, data_offset - data_start, ENC_ASCII|ENC_NA);
						col_append_fstr(pinfo->cinfo, COL_INFO, " Computername=%s", record_data);
					break;
					case INDIGOCARE_NETRIX_SYSTEMINFO_IPADDRESS:
						proto_tree_add_item(netrix_header_tree, hf_netrix_systeminfo_ipaddress_type, tvb, data_start, data_offset - data_start, ENC_ASCII|ENC_NA);
						col_append_fstr(pinfo->cinfo, COL_INFO, " IP Address=%s", record_data);
					break;
					case INDIGOCARE_NETRIX_SYSTEMINFO_VERSION:
						proto_tree_add_item(netrix_header_tree, hf_netrix_systeminfo_version_type, tvb, data_start, data_offset - data_start, ENC_ASCII|ENC_NA);
						col_append_fstr(pinfo->cinfo, COL_INFO, " Systeminfo=%s", record_data);
					break;
					case INDIGOCARE_NETRIX_SYSTEMINFO_BEEP:
						proto_tree_add_item(netrix_header_tree, hf_netrix_systeminfo_beep_type, tvb, data_start, data_offset - data_start, ENC_ASCII|ENC_NA);
					break;
					default:
						proto_tree_add_expert_format(netrix_header_tree, pinfo, &ei_netrix_unexpected_record, tvb, identifier_start, data_offset - identifier_start, "Unexpected record %d with value %s", record_identifier, record_data);
					break;
				}
			break;
			case INDIGOCARE_NETRIX_GROUP:
				switch (record_identifier) {
					case INDIGOCARE_NETRIX_GROUP_GROUPNUMBER:
						ws_strtoi32(record_data, NULL, &group_number);
						proto_tree_add_uint_format_value(netrix_header_tree, hf_netrix_groupcall_groupnumber_type, tvb, identifier_start, data_offset - identifier_start, group_number, "%d", group_number);
						col_append_fstr(pinfo->cinfo, COL_INFO, " Groupnumber=%d", group_number);
					break;
					case INDIGOCARE_NETRIX_GROUP_TYPE:
						proto_tree_add_item(netrix_header_tree, hf_netrix_groupcall_type_type, tvb, data_start, data_offset - data_start, ENC_ASCII|ENC_NA);
						col_append_fstr(pinfo->cinfo, COL_INFO, " Type=%s", record_data);
					break;
					case INDIGOCARE_NETRIX_GROUP_ADDITION:
						proto_tree_add_item(netrix_header_tree, hf_netrix_groupcall_addition_type, tvb, data_start, data_offset - data_start, ENC_ASCII|ENC_NA);
					break;
					case INDIGOCARE_NETRIX_GROUP_IDBOSCHLOC:
						proto_tree_add_item(netrix_header_tree, hf_netrix_groupcall_idboschloc_type, tvb, data_start, data_offset - data_start, ENC_ASCII|ENC_NA);
					break;
					case INDIGOCARE_NETRIX_GROUP_NAME:
						proto_tree_add_item(netrix_header_tree, hf_netrix_groupcall_name_type, tvb, data_start, data_offset - data_start, ENC_ASCII|ENC_NA);
						col_append_fstr(pinfo->cinfo, COL_INFO, " Name=%s", record_data);
					break;
					case INDIGOCARE_NETRIX_GROUP_ROOM:
						proto_tree_add_item(netrix_header_tree, hf_netrix_groupcall_room_type, tvb, data_start, data_offset - data_start, ENC_ASCII|ENC_NA);
						col_append_fstr(pinfo->cinfo, COL_INFO, " Room=%s", record_data);
					break;
					case INDIGOCARE_NETRIX_GROUP_LOCATION:
						proto_tree_add_item(netrix_header_tree, hf_netrix_groupcall_location_type, tvb, data_start, data_offset - data_start, ENC_ASCII|ENC_NA);
						col_append_fstr(pinfo->cinfo, COL_INFO, " Location=%s", record_data);
					break;
					default:
						proto_tree_add_expert_format(netrix_header_tree, pinfo, &ei_netrix_unexpected_record, tvb, identifier_start, data_offset - identifier_start, "Unexpected record %d with value %s", record_identifier, record_data);
					break;
				}
			break;
			case INDIGOCARE_NETRIX_PROFILE:
				switch (record_identifier) {
					case INDIGOCARE_NETRIX_PROFILE_PROFILENUMBER:
						ws_strtoi32(record_data, NULL, &profile_number);
						proto_tree_add_uint_format_value(netrix_header_tree, hf_netrix_profilecall_groupnumber_type, tvb, identifier_start, data_offset - identifier_start, profile_number, "%d", profile_number);
						col_append_fstr(pinfo->cinfo, COL_INFO, " Profilenumber=%d", profile_number);
					break;
					case INDIGOCARE_NETRIX_PROFILE_TYPE:
						proto_tree_add_item(netrix_header_tree, hf_netrix_profilecall_type_type, tvb, data_start, data_offset - data_start, ENC_ASCII|ENC_NA);
						col_append_fstr(pinfo->cinfo, COL_INFO, " Type=%s", record_data);
					break;
					case INDIGOCARE_NETRIX_PROFILE_ADDITION:
						proto_tree_add_item(netrix_header_tree, hf_netrix_profilecall_addition_type, tvb, data_start, data_offset - data_start, ENC_ASCII|ENC_NA);
					break;
					case INDIGOCARE_NETRIX_PROFILE_IDBOSCHLOC:
						proto_tree_add_item(netrix_header_tree, hf_netrix_profilecall_idboschloc_type, tvb, data_start, data_offset - data_start, ENC_ASCII|ENC_NA);
					break;
					case INDIGOCARE_NETRIX_PROFILE_NAME:
						proto_tree_add_item(netrix_header_tree, hf_netrix_profilecall_name_type, tvb, data_start, data_offset - data_start, ENC_ASCII|ENC_NA);
						col_append_fstr(pinfo->cinfo, COL_INFO, " Name=%s", record_data);
					break;
					case INDIGOCARE_NETRIX_PROFILE_ROOM:
						proto_tree_add_item(netrix_header_tree, hf_netrix_profilecall_room_type, tvb, data_start, data_offset - data_start, ENC_ASCII|ENC_NA);
						col_append_fstr(pinfo->cinfo, COL_INFO, " Room=%s", record_data);
					break;
					case INDIGOCARE_NETRIX_PROFILE_LOCATION:
						proto_tree_add_item(netrix_header_tree, hf_netrix_profilecall_location_type, tvb, data_start, data_offset - data_start, ENC_ASCII|ENC_NA);
						col_append_fstr(pinfo->cinfo, COL_INFO, " Location=%s", record_data);
					break;
					default:
						proto_tree_add_expert_format(netrix_header_tree, pinfo, &ei_netrix_unexpected_record, tvb, identifier_start, data_offset - identifier_start, "Unexpected record %d with value %s", record_identifier, record_data);
					break;
				}
			break;
			case INDIGOCARE_NETRIX_GET_CONVERSIONTABLE:
				switch (record_identifier) {
					case INDIGOCARE_NETRIX_GET_CONVERSIONTABLE_TABLE:
						proto_tree_add_item(netrix_header_tree, hf_netrix_get_conversiontable_table_type, tvb, data_start, data_offset - data_start, ENC_ASCII|ENC_NA);
						col_append_fstr(pinfo->cinfo, COL_INFO, " Table=%s", record_data);
					break;
				}
			break;
			case INDIGOCARE_NETRIX_SEARCH_CONVERSIONTABLES:
				switch (record_identifier) {
					case INDIGOCARE_NETRIX_SEARCH_CONVERSIONTABLES_KEY:
						proto_tree_add_item(netrix_header_tree, hf_netrix_search_conversiontables_key_type, tvb, data_start, data_offset - data_start, ENC_ASCII|ENC_NA);
						col_append_fstr(pinfo->cinfo, COL_INFO, " Key=%s", record_data);
					break;
					default:
						proto_tree_add_expert_format(netrix_header_tree, pinfo, &ei_netrix_unexpected_record, tvb, identifier_start, data_offset - identifier_start, "Unexpected record %d with value %s", record_identifier, record_data);
					break;
				}
			break;
			default:
				if ((header >= INDIGOCARE_NETRIX_GET_CONVERSIONTABLE_BEGIN) && (header <= INDIGOCARE_NETRIX_GET_CONVERSIONTABLE_END)) {
					switch (record_identifier) {
						case INDIGOCARE_NETRIX_GET_CONVERSIONTABLE_KEY:
							proto_tree_add_item(netrix_header_tree, hf_netrix_get_conversiontable_key_type, tvb, data_start, data_offset - data_start, ENC_ASCII|ENC_NA);
							col_append_fstr(pinfo->cinfo, COL_INFO, " Key=%s", record_data);
						break;
						case INDIGOCARE_NETRIX_GET_CONVERSIONTABLE_VALUE:
							proto_tree_add_item(netrix_header_tree, hf_netrix_get_conversiontable_value_type, tvb, data_start, data_offset - data_start, ENC_ASCII|ENC_NA);
							col_append_fstr(pinfo->cinfo, COL_INFO, " Value=%s", record_data);
						break;
						default:
							proto_tree_add_expert_format(netrix_header_tree, pinfo, &ei_netrix_unexpected_record, tvb, identifier_start, data_offset - identifier_start, "Unexpected record %d with value %s", record_identifier, record_data);
						break;
					}
				} else if ((header >= INDIGOCARE_NETRIX_SEARCH_CONVERSIONTABLES_BEGIN) && (header <= INDIGOCARE_NETRIX_SEARCH_CONVERSIONTABLES_END)) {
					switch (record_identifier) {
						case INDIGOCARE_NETRIX_SEARCH_CONVERSIONTABLES_TABLE:
							proto_tree_add_item(netrix_header_tree, hf_netrix_search_conversiontables_table_type, tvb, data_start, data_offset - data_start, ENC_ASCII|ENC_NA);
							col_append_fstr(pinfo->cinfo, COL_INFO, " Table=%s", record_data);
						break;
						default:
							proto_tree_add_expert_format(netrix_header_tree, pinfo, &ei_netrix_unexpected_record, tvb, identifier_start, data_offset - identifier_start, "Unexpected record %d with value %s", record_identifier, record_data);
						break;
					}
				}
			break;
		}
	}
	return tvb_captured_length(tvb);
}

void
proto_reg_handoff_netrix(void)
{
	static dissector_handle_t netrix_handle;

	netrix_handle = create_dissector_handle(dissect_netrix, proto_netrix);
	dissector_add_for_decode_as("tcp.port", netrix_handle);
}

void
proto_register_netrix(void)
{
	static hf_register_info hf[] = {
	{ &hf_netrix_header_type,
		{ "Header Type", "netrix.header",
		FT_UINT32, BASE_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_netrix_header_systeminfo_type,
		{ "Ack", "netrix.systeminfo",
		FT_NONE, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_netrix_header_groupcall_type,
		{ "Group call", "netrix.groupcall",
		FT_NONE, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_netrix_header_profilecall_type,
		{ "Profile call", "netrix.profilecall",
		FT_NONE, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_netrix_header_get_conversiontable_type,
		{ "Get conversiontable", "netrix.getconversiontable",
		FT_NONE, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_netrix_header_get_conversiontable_none_type,
		{ "Get conversiontable: no results", "netrix.getconversiontable.noresult",
		FT_NONE, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_netrix_header_get_conversiontable_result_type,
		{ "Get conversiontable result", "netrix.getconversiontable.result",
		FT_NONE, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_netrix_header_search_conversiontables_type,
		{ "Search conversiontables", "netrix.searchconversiontables",
		FT_NONE, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_netrix_header_search_conversiontables_none_type,
		{ "Search converstiontables: no results", "netrix.searchconversiontables.noresult",
		FT_NONE, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_netrix_header_boschcall_type,
		{ "Bosch call", "netrix.boschcall",
		FT_NONE, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_netrix_ack_type,
		{ "Ack", "netrix.ack",
		FT_NONE, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_netrix_systeminfo_computername_type,
		{ "Computername", "netrix.systeminfo.computername",
		FT_STRING, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_netrix_systeminfo_ipaddress_type,
		{ "IP Address", "netrix.systeminfo.ipaddress",
		FT_STRING, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_netrix_systeminfo_version_type,
		{ "Version", "netrix.systeminfo.version",
		FT_STRING, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_netrix_systeminfo_beep_type,
		{ "Beep", "netrix.systeminfo.beep",
		FT_STRING, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_netrix_groupcall_groupnumber_type,
		{ "Groupnumber", "netrix.groupcall.groupnumber",
		FT_UINT32, BASE_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_netrix_groupcall_type_type,
		{ "MSG1 (Type)", "netrix.groupcall.type",
		FT_STRING, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_netrix_groupcall_addition_type,
		{ "MSG2 (Addition)", "netrix.groupcall.addition",
		FT_STRING, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_netrix_groupcall_idboschloc_type,
		{ "MSG3 (ID / Bosch Loc)", "netrix.groupcall.idboschloc",
		FT_STRING, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_netrix_groupcall_name_type,
		{ "MSG4 (Name)", "netrix.groupcall.name",
		FT_STRING, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_netrix_groupcall_room_type,
		{ "MSG5 (Room)", "netrix.groupcall.room",
		FT_STRING, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_netrix_groupcall_location_type,
		{ "MSG6 (Location)", "netrix.groupcall.location",
		FT_STRING, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_netrix_profilecall_groupnumber_type,
		{ "Profilenumber", "netrix.profilecall.profilenumber",
		FT_UINT32, BASE_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_netrix_profilecall_type_type,
		{ "MSG1 (Type)", "netrix.profilecall.type",
		FT_STRING, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_netrix_profilecall_addition_type,
		{ "MSG2 (Addition)", "netrix.profilecall.addition",
		FT_STRING, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_netrix_profilecall_idboschloc_type,
		{ "MSG3 (ID / Bosch Loc)", "netrix.profilecall.idboschloc",
		FT_STRING, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_netrix_profilecall_name_type,
		{ "MSG4 (Name)", "netrix.profilecall.name",
		FT_STRING, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_netrix_profilecall_room_type,
		{ "MSG5 (Room)", "netrix.profilecall.room",
		FT_STRING, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_netrix_profilecall_location_type,
		{ "MSG6 (Location)", "netrix.profilecall.location",
		FT_STRING, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_netrix_get_conversiontable_table_type,
		{ "Table", "netrix.getconversiontable.table",
		FT_STRING, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_netrix_get_conversiontable_key_type,
		{ "Key", "netrix.getconversiontable.key",
		FT_STRING, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_netrix_get_conversiontable_value_type,
		{ "Value", "netrix.getconversiontable.value",
		FT_STRING, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_netrix_search_conversiontables_key_type,
		{ "Key", "netrix.searchconversiontables.key",
		FT_STRING, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_netrix_search_conversiontables_table_type,
		{ "Table", "netrix.searchconversiontables.table",
		FT_STRING, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	}
	};

	static ei_register_info ei[] = {
		{ &ei_netrix_unexpected_header, { "netrix.unexpected.header", PI_MALFORMED, PI_WARN, "Unexpected header", EXPFILL }},
		{ &ei_netrix_unexpected_record, { "netrix.unexpected.record", PI_MALFORMED, PI_WARN, "Unexpected record", EXPFILL }}
	};

	expert_module_t* expert_netrix;

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_netrix,
		&ett_netrix_systeminfo,
		&ett_netrix_groupcall,
		&ett_netrix_profilecall,
		&ett_netrix_get_conversiontable,
		&ett_netrix_get_conversiontable_result,
		&ett_netrix_search_conversiontables,
		&ett_netrix_search_conversiontables_result,
		&ett_netrix_boschcall,
		&ett_netrix_unknown
	};

	proto_netrix = proto_register_protocol (
		"Netrix Communication Protocol",	/* name */
		"Netrix",				/* short name */
		"netrix"				/* abbrev */
	);

	proto_register_field_array(proto_netrix, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	expert_netrix = expert_register_protocol(proto_netrix);
	expert_register_field_array(expert_netrix, ei, array_length(ei));
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
