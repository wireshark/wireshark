/* packet-indigocare-icall.c
 * Dissector routines for the IndigoCare iCall protocol
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
#include <epan/packet.h>
#include <epan/expert.h>
#include <wsutil/strtoi.h>

#define INDIGOCARE_ICALL_SOH			0x01
#define INDIGOCARE_ICALL_STX			0x02
#define INDIGOCARE_ICALL_ETX			0x03
#define INDIGOCARE_ICALL_EOT			0x04
#define INDIGOCARE_ICALL_ACK			0x06
#define INDIGOCARE_ICALL_US			0x1F
#define INDIGOCARE_ICALL_RS			0x1E

#define INDIGOCARE_ICALL_CALL			0x0A

#define INDIGOCARE_ICALL_CALL_ROOM		0x01
#define INDIGOCARE_ICALL_CALL_TYPE		0x02
#define INDIGOCARE_ICALL_CALL_ADDITION		0x03
#define INDIGOCARE_ICALL_CALL_ID		0x04
#define INDIGOCARE_ICALL_CALL_TASK		0x05
#define INDIGOCARE_ICALL_CALL_LOCATION		0x06
#define INDIGOCARE_ICALL_CALL_NAME1		0x07
#define INDIGOCARE_ICALL_CALL_NAME2		0x08
#define INDIGOCARE_ICALL_CALL_TYPE_NUMERICAL	0x09
#define INDIGOCARE_ICALL_CALL_NURSE		0x0A

void proto_reg_handoff_icall(void);
void proto_register_icall(void);

static dissector_handle_t icall_handle;

static expert_field ei_icall_unexpected_header;
static expert_field ei_icall_unexpected_record;
static expert_field ei_icall_unexpected_end;

static int proto_icall;
static int hf_icall_header_type;

static int hf_icall_call_room_type;
static int hf_icall_call_type_type;
static int hf_icall_call_addition_type;
static int hf_icall_call_id_type;
static int hf_icall_call_task_type;
static int hf_icall_call_location_type;
static int hf_icall_call_name1_type;
static int hf_icall_call_name2_type;
static int hf_icall_call_numerical_type;
static int hf_icall_call_nurse_type;

static int hf_icall_padding_type;

static int ett_icall;
static int ett_icall_call;
static int ett_icall_unknown;

static const value_string icall_headertypenames[] = {
	{ INDIGOCARE_ICALL_CALL,		"Call Info" },
	{ 0, NULL }
};

static int
dissect_icall(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	proto_item *ti;
	proto_item *header_item;
	proto_tree *icall_tree;
	proto_tree *icall_header_tree;
	int32_t current_offset = 0, header_offset, identifier_start, identifier_offset, data_start, data_offset, ett;
	int32_t header;
	int32_t record_identifier;
	const uint8_t * record_data;

	/* Starts with SOH */
	if ( tvb_get_uint8(tvb, 0) != INDIGOCARE_ICALL_SOH )
		return 0;
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "iCall");
	col_clear(pinfo->cinfo,COL_INFO);
	ti = proto_tree_add_item(tree, proto_icall, tvb, 0, -1, ENC_NA);
	icall_tree = proto_item_add_subtree(ti, ett_icall);
	current_offset++;

	/* Read header */
	header_offset = tvb_find_guint8(tvb, current_offset, -1, INDIGOCARE_ICALL_STX);
	ws_strtoi32(tvb_get_string_enc(pinfo->pool, tvb, current_offset, header_offset - current_offset, ENC_ASCII|ENC_NA), NULL, &header);
	col_add_fstr(pinfo->cinfo, COL_INFO, "%s:", val_to_str(header, icall_headertypenames, "Unknown (%d)"));
	switch(header) {
		case INDIGOCARE_ICALL_CALL:
			ett = ett_icall_call;
		break;
		default:
			proto_tree_add_expert_format(icall_tree, pinfo, &ei_icall_unexpected_header, tvb, current_offset, header_offset -  current_offset, "Unexpected header %d", header);
			return 0;
		break;
	}
	header_item = proto_tree_add_uint_format(icall_tree, hf_icall_header_type, tvb, current_offset, header_offset - current_offset, header, "%s", val_to_str(header, icall_headertypenames, "Unknown (%d)"));
	icall_header_tree = proto_item_add_subtree(header_item, ett);
	current_offset = header_offset + 1;

	/* Read records */
	while (tvb_get_uint8(tvb, current_offset) != INDIGOCARE_ICALL_ETX) {
		identifier_start = current_offset;
		identifier_offset = tvb_find_guint8(tvb, current_offset, -1, INDIGOCARE_ICALL_US);
		ws_strtoi32(tvb_get_string_enc(pinfo->pool, tvb, current_offset, identifier_offset - current_offset, ENC_ASCII|ENC_NA), NULL, &record_identifier);
		current_offset = identifier_offset + 1;

		data_start = current_offset;
		data_offset = tvb_find_guint8(tvb, data_start, -1, INDIGOCARE_ICALL_RS);
		record_data = tvb_get_string_enc(pinfo->pool, tvb, current_offset, data_offset - data_start, ENC_ASCII|ENC_NA);

		current_offset = data_offset + 1;

		switch (header) {
			case INDIGOCARE_ICALL_CALL:
				switch (record_identifier) {
					case INDIGOCARE_ICALL_CALL_ROOM:
						proto_tree_add_item_ret_string(icall_header_tree, hf_icall_call_room_type, tvb, data_start, data_offset - data_start, ENC_ASCII|ENC_NA, pinfo->pool, &record_data);
						col_append_fstr(pinfo->cinfo, COL_INFO, " Room=%s", record_data);
					break;
					case INDIGOCARE_ICALL_CALL_TYPE:
						proto_tree_add_item_ret_string(icall_header_tree, hf_icall_call_type_type, tvb, data_start, data_offset - data_start, ENC_ASCII|ENC_NA, pinfo->pool, &record_data);
						col_append_fstr(pinfo->cinfo, COL_INFO, " Type=%s", record_data);
					break;
					case INDIGOCARE_ICALL_CALL_ADDITION:
						proto_tree_add_item(icall_header_tree, hf_icall_call_addition_type, tvb, data_start, data_offset - data_start, ENC_ASCII);
					break;
					case INDIGOCARE_ICALL_CALL_ID:
						proto_tree_add_item(icall_header_tree, hf_icall_call_id_type, tvb, data_start, data_offset - data_start, ENC_ASCII);
					break;
					case INDIGOCARE_ICALL_CALL_TASK:
						proto_tree_add_item(icall_header_tree, hf_icall_call_task_type, tvb, data_start, data_offset - data_start, ENC_ASCII);
					break;
					case INDIGOCARE_ICALL_CALL_LOCATION:
						proto_tree_add_item_ret_string(icall_header_tree, hf_icall_call_location_type, tvb, data_start, data_offset - data_start, ENC_ASCII|ENC_NA, pinfo->pool, &record_data);
						col_append_fstr(pinfo->cinfo, COL_INFO, " Location=%s", record_data);
					break;
					case INDIGOCARE_ICALL_CALL_NAME1:
						proto_tree_add_item_ret_string(icall_header_tree, hf_icall_call_name1_type, tvb, data_start, data_offset - data_start, ENC_ASCII|ENC_NA, pinfo->pool, &record_data);
						col_append_fstr(pinfo->cinfo, COL_INFO, " Name 1=%s", record_data);
					break;
					case INDIGOCARE_ICALL_CALL_NAME2:
						proto_tree_add_item_ret_string(icall_header_tree, hf_icall_call_name2_type, tvb, data_start, data_offset - data_start, ENC_ASCII|ENC_NA, pinfo->pool, &record_data);
						col_append_fstr(pinfo->cinfo, COL_INFO, " Name 2=%s", record_data);
					break;
					case INDIGOCARE_ICALL_CALL_TYPE_NUMERICAL:
						proto_tree_add_item(icall_header_tree, hf_icall_call_numerical_type, tvb, data_start, data_offset - data_start, ENC_ASCII);
					break;
					case INDIGOCARE_ICALL_CALL_NURSE:
						proto_tree_add_item(icall_header_tree, hf_icall_call_nurse_type, tvb, data_start, data_offset - data_start, ENC_ASCII);
					break;
					default:
						proto_tree_add_expert_format(icall_header_tree, pinfo, &ei_icall_unexpected_record, tvb, identifier_start, data_offset - identifier_start, "Unexpected record %d with value %s", record_identifier, record_data);
					break;
				}
			break;
		}
	}
	current_offset++;
	if (tvb_get_uint8(tvb, current_offset) != INDIGOCARE_ICALL_EOT) {
		/* Malformed packet terminator */
		proto_tree_add_expert(icall_header_tree, pinfo, &ei_icall_unexpected_end, tvb, current_offset, 1);
		return tvb_captured_length(tvb);
	}
	current_offset++;
	if (tvb_captured_length_remaining(tvb, current_offset)) {
		/* Padding */
		proto_tree_add_item(icall_header_tree, hf_icall_padding_type, tvb, current_offset, tvb_captured_length_remaining(tvb, current_offset), ENC_NA);
	}
	return tvb_captured_length(tvb);
}

void
proto_reg_handoff_icall(void)
{
	dissector_add_for_decode_as("udp.port", icall_handle);
	dissector_add_for_decode_as("tcp.port", icall_handle);
}

void
proto_register_icall(void)
{
	static hf_register_info hf[] = {
	{ &hf_icall_header_type,
		{ "Header Type", "icall.header",
		FT_UINT32, BASE_DEC,
		VALS(icall_headertypenames), 0x0,
		NULL, HFILL }
	},
	{ &hf_icall_call_room_type,
		{ "Room", "icall.call.room",
		FT_STRING, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_icall_call_type_type,
		{ "Type", "icall.call.type",
		FT_STRING, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_icall_call_addition_type,
		{ "Addition", "icall.call.addition",
		FT_STRING, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_icall_call_id_type,
		{ "ID", "icall.call.id",
		FT_STRING, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_icall_call_task_type,
		{ "Task", "icall.call.task",
		FT_STRING, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_icall_call_location_type,
		{ "Location", "icall.call.location",
		FT_STRING, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_icall_call_name1_type,
		{ "Name 1", "icall.call.name1",
		FT_STRING, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_icall_call_name2_type,
		{ "Name 2", "icall.call.name2",
		FT_STRING, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_icall_call_numerical_type,
		{ "Type Numerical", "icall.call.type_numerical",
		FT_STRING, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_icall_call_nurse_type,
		{ "Nurse", "icall.call.nurse",
		FT_STRING, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_icall_padding_type,
		{ "Padding", "icall.padding",
		FT_BYTES, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	}
	};

	static ei_register_info ei[] = {
		{ &ei_icall_unexpected_header, { "icall.unexpected.header", PI_MALFORMED, PI_WARN, "Unexpected header", EXPFILL }},
		{ &ei_icall_unexpected_record, { "icall.unexpected.record", PI_MALFORMED, PI_WARN, "Unexpected record", EXPFILL }},
		{ &ei_icall_unexpected_end, { "icall.unexpected.end", PI_MALFORMED, PI_WARN, "Unexpected end of packet", EXPFILL }}
	};

	expert_module_t* expert_icall;

	/* Setup protocol subtree array */
	static int *ett[] = {
		&ett_icall,
		&ett_icall_call,
		&ett_icall_unknown
	};

	proto_icall = proto_register_protocol (
		"iCall Communication Protocol",	/* name */
		"iCall",			/* short name */
		"icall"				/* abbrev */
	);

	proto_register_field_array(proto_icall, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	expert_icall = expert_register_protocol(proto_icall);
	expert_register_field_array(expert_icall, ei, array_length(ei));

	icall_handle = register_dissector("icall", dissect_icall, proto_icall);
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
