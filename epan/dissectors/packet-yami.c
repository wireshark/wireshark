/* packet-yami.c
 * Routines for YAMI dissection
 * Copyright 2010, Pawel Korbut
 * Copyright 2012, Jakub Zawadzki <darkjames-ws@darkjames.pl>
 *
 * Protocol documentation available at http://www.inspirel.com/yami4/book/B-2.html
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
#include <epan/to_str.h>
#include <wsutil/ws_roundup.h>
#include "packet-tcp.h"

void proto_reg_handoff_yami(void);
void proto_register_yami(void);

static bool yami_desegment = true;

static dissector_handle_t yami_handle;

#define YAMI_TYPE_BOOLEAN 1
#define YAMI_TYPE_INTEGER 2
#define YAMI_TYPE_LONGLONG 3
#define YAMI_TYPE_DOUBLE 4
#define YAMI_TYPE_STRING 5
#define YAMI_TYPE_BINARY 6
#define YAMI_TYPE_BOOLEAN_ARRAY 7
#define YAMI_TYPE_INTEGER_ARRAY 8
#define YAMI_TYPE_LONGLONG_ARRAY 9
#define YAMI_TYPE_DOUBLE_ARRAY 10
#define YAMI_TYPE_STRING_ARRAY 11
#define YAMI_TYPE_BINARY_ARRAY 12
#define YAMI_TYPE_NESTED 13

static const value_string yami_param_type_vals[] = {
	{ YAMI_TYPE_BOOLEAN,        "boolean" },
	{ YAMI_TYPE_INTEGER,        "integer" },
	{ YAMI_TYPE_LONGLONG,       "long long" },
	{ YAMI_TYPE_DOUBLE,         "double" },
	{ YAMI_TYPE_STRING,         "string" },
	{ YAMI_TYPE_BINARY,         "binary" },
	{ YAMI_TYPE_BOOLEAN_ARRAY,  "boolean array" },
	{ YAMI_TYPE_INTEGER_ARRAY,  "integer array" },
	{ YAMI_TYPE_LONGLONG_ARRAY, "long long array" },
	{ YAMI_TYPE_DOUBLE_ARRAY,   "double array" },
	{ YAMI_TYPE_STRING_ARRAY,   "string array" },
	{ YAMI_TYPE_BINARY_ARRAY,   "binary array" },
	{ YAMI_TYPE_NESTED,         "nested parameters" },
	{ 0, NULL }
};

static int proto_yami;

static int hf_yami_frame_number;
static int hf_yami_frame_payload_size;
static int hf_yami_items_count;
static int hf_yami_message_data;
static int hf_yami_message_hdr;
static int hf_yami_message_header_size;
static int hf_yami_message_id;
static int hf_yami_param;
static int hf_yami_param_name;
static int hf_yami_param_type;
static int hf_yami_param_value_bin;
static int hf_yami_param_value_bool;
static int hf_yami_param_value_double;
static int hf_yami_param_value_int;
static int hf_yami_param_value_long;
static int hf_yami_param_value_str;
static int hf_yami_params_count;

static int ett_yami;
static int ett_yami_msg_hdr;
static int ett_yami_msg_data;
static int ett_yami_param;

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_yami_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_item *par_ti)
{
	const int orig_offset = offset;

	proto_tree *yami_param;
	proto_item *ti;

	char *name;
	int name_offset;
	uint32_t name_len;

	uint32_t type;

	ti = proto_tree_add_item(tree, hf_yami_param, tvb, offset, 0, ENC_NA);
	yami_param = proto_item_add_subtree(ti, ett_yami_param);

	name_offset = offset;
	name_len = tvb_get_letohl(tvb, offset);
	offset += 4;

	name = tvb_get_string_enc(pinfo->pool, tvb, offset, name_len, ENC_ASCII | ENC_NA);
	proto_item_append_text(ti, ": %s", name);
	proto_item_append_text(par_ti, "%s, ", name);
	offset += WS_ROUNDUP_4(name_len);
	proto_tree_add_string(yami_param, hf_yami_param_name, tvb, name_offset, offset - name_offset, name);

	type = tvb_get_letohl(tvb, offset);
	proto_tree_add_item(yami_param, hf_yami_param_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	switch (type) {
		case YAMI_TYPE_BOOLEAN:
		{
			uint32_t val = tvb_get_letohl(tvb, offset);
			proto_item_append_text(ti, ", Type: boolean, Value: %s", val ? "True" : "False");
			proto_tree_add_item(yami_param, hf_yami_param_value_bool, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			break;
		}

		case YAMI_TYPE_INTEGER:
		{
			int32_t val = tvb_get_letohl(tvb, offset);
			proto_item_append_text(ti, ", Type: integer, Value: %d", val);
			proto_tree_add_item(yami_param, hf_yami_param_value_int, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			break;
		}

		case YAMI_TYPE_LONGLONG:
		{
			int64_t val = tvb_get_letoh64(tvb, offset);
			proto_item_append_text(ti, ", Type: long, Value: %" PRId64, val);
			proto_tree_add_item(yami_param, hf_yami_param_value_long, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			offset += 8;
			break;
		}

		case YAMI_TYPE_DOUBLE:
		{
			double val = tvb_get_letohieee_double(tvb, offset);
			proto_item_append_text(ti, ", Type: double, Value: %g", val);
			proto_tree_add_item(yami_param, hf_yami_param_value_double, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			offset += 8;
			break;
		}

		case YAMI_TYPE_STRING:
		{
			const int val_offset = offset;
			uint32_t val_len;
			char *val;

			val_len = tvb_get_letohl(tvb, offset);
			offset += 4;

			val = tvb_get_string_enc(pinfo->pool, tvb, offset, val_len, ENC_ASCII | ENC_NA);

			proto_item_append_text(ti, ", Type: string, Value: \"%s\"", val);
			offset += WS_ROUNDUP_4(val_len);
			proto_tree_add_string(yami_param, hf_yami_param_value_str, tvb, val_offset, offset - val_offset, val);
			break;
		}

		case YAMI_TYPE_BINARY:
		{
			const int val_offset = offset;
			uint32_t val_len;
			const uint8_t *val;
			char *repr;

			val_len = tvb_get_letohl(tvb, offset);
			offset += 4;

			val = tvb_get_ptr(tvb, offset, val_len);
			repr = bytes_to_str(pinfo->pool, val, val_len);

			proto_item_append_text(ti, ", Type: binary, Value: %s", repr);
			offset += WS_ROUNDUP_4(val_len);
			proto_tree_add_bytes_format_value(yami_param, hf_yami_param_value_bin, tvb, val_offset, offset - val_offset, val, "%s", repr);
			break;
		}

		case YAMI_TYPE_BOOLEAN_ARRAY:
		{
			uint32_t count;
			unsigned i;
			int j;

			count = tvb_get_letohl(tvb, offset);
			proto_tree_add_item(yami_param, hf_yami_items_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_item_append_text(ti, ", Type: boolean[], %u items: {", count);

			for (i = 0; i < count/32; i++) {
				uint32_t val = tvb_get_letohl(tvb, offset);

				for (j = 0; j < 32; j++) {
					int r = !!(val & (1U << j));

					proto_item_append_text(ti, "%s, ", r ? "T" : "F");
					proto_tree_add_boolean(yami_param, hf_yami_param_value_bool, tvb, offset+(j/8), 1, r);
				}
				offset += 4;
			}

			if (count % 32) {
				uint32_t val = tvb_get_letohl(tvb, offset);
				int tmp = count % 32;

				for (j = 0; j < tmp; j++) {
					int r = !!(val & (1 << j));

					proto_item_append_text(ti, "%s, ", r ? "T" : "F");
					proto_tree_add_boolean(yami_param, hf_yami_param_value_bool, tvb, offset+(j/8), 1, r);
				}
				offset += 4;
			}

			proto_item_append_text(ti, "}");
			break;
		}

		case YAMI_TYPE_INTEGER_ARRAY:
		{
			uint32_t count;
			unsigned i;

			count = tvb_get_letohl(tvb, offset);
			proto_tree_add_item(yami_param, hf_yami_items_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_item_append_text(ti, ", Type: integer[], %u items: {", count);
			for (i = 0; i < count; i++) {
				int32_t val = tvb_get_letohl(tvb, offset);

				proto_item_append_text(ti, "%d, ", val);
				proto_tree_add_item(yami_param, hf_yami_param_value_int, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;
			}
			proto_item_append_text(ti, "}");
			break;
		}

		case YAMI_TYPE_LONGLONG_ARRAY:
		{
			uint32_t count;
			unsigned i;

			count = tvb_get_letohl(tvb, offset);
			proto_tree_add_item(yami_param, hf_yami_items_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_item_append_text(ti, ", Type: long long[], %u items: {", count);

			for (i = 0; i < count; i++) {
				int64_t val = tvb_get_letoh64(tvb, offset);

				proto_item_append_text(ti, "%" PRId64 ", ", val);
				proto_tree_add_item(yami_param, hf_yami_param_value_long, tvb, offset, 8, ENC_LITTLE_ENDIAN);
				offset += 8;
			}
			proto_item_append_text(ti, "}");
			break;
		}

		case YAMI_TYPE_DOUBLE_ARRAY:
		{
			uint32_t count;
			unsigned i;

			count = tvb_get_letohl(tvb, offset);
			proto_tree_add_item(yami_param, hf_yami_items_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_item_append_text(ti, ", Type: double[], %u items: {", count);

			for (i = 0; i < count; i++) {
				double val = tvb_get_letohieee_double(tvb, offset);

				proto_item_append_text(ti, "%g, ", val);
				proto_tree_add_item(yami_param, hf_yami_param_value_double, tvb, offset, 8, ENC_LITTLE_ENDIAN);
				offset += 8;
			}
			proto_item_append_text(ti, "}");
			break;
		}

		case YAMI_TYPE_STRING_ARRAY:
		{
			uint32_t count;
			unsigned i;

			count = tvb_get_letohl(tvb, offset);
			proto_tree_add_item(yami_param, hf_yami_items_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_item_append_text(ti, ", Type: string[], %u items: {", count);

			for (i = 0; i < count; i++) {
				const int val_offset = offset;
				uint32_t val_len;
				char *val;

				val_len = tvb_get_letohl(tvb, offset);
				offset += 4;

				val = tvb_get_string_enc(pinfo->pool, tvb, offset, val_len, ENC_ASCII | ENC_NA);

				proto_item_append_text(ti, "\"%s\", ", val);
				proto_tree_add_string(yami_param, hf_yami_param_value_str, tvb, val_offset, offset - val_offset, val);
				offset += WS_ROUNDUP_4(val_len);
			}
			proto_item_append_text(ti, "}");
			break;
		}

		case YAMI_TYPE_BINARY_ARRAY:
		{
			uint32_t count;
			unsigned i;

			count = tvb_get_letohl(tvb, offset);
			proto_tree_add_item(yami_param, hf_yami_items_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_item_append_text(ti, ", Type: binary[], %u items: {", count);

			for (i = 0; i < count; i++) {
				const int val_offset = offset;
				uint32_t val_len;
				const uint8_t *val;
				char *repr;

				val_len = tvb_get_letohl(tvb, offset);
				offset += 4;

				val = tvb_get_ptr(tvb, offset, val_len);
				repr = bytes_to_str(pinfo->pool, val, val_len);

				proto_item_append_text(ti, "%s, ", repr);
				offset += WS_ROUNDUP_4(val_len);
				proto_tree_add_bytes_format_value(yami_param, hf_yami_param_value_bin, tvb, val_offset, offset - val_offset, val, "%s", repr);
			}
			proto_item_append_text(ti, "}");
			break;
		}

		case YAMI_TYPE_NESTED:
		{
			uint32_t count;
			unsigned i;

			count = tvb_get_letohl(tvb, offset);
			proto_tree_add_item(yami_param, hf_yami_params_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_item_append_text(ti, ", Type: nested, %u parameters: ", count);

			for (i = 0; i < count; i++) {
				increment_dissection_depth(pinfo);
				offset = dissect_yami_parameter(tvb, pinfo, yami_param, offset, ti);
				decrement_dissection_depth(pinfo);
				/* smth went wrong */
				if (offset == -1)
					return -1;
			}
			break;
		}

		default:
			proto_item_append_text(ti, ", Type: unknown (%d)!", type);
			return -1;
	}

	proto_item_set_len(ti, offset - orig_offset);
	return offset;
}

static int
dissect_yami_data(tvbuff_t *tvb, packet_info *pinfo, bool data, proto_tree *tree, int offset)
{
	const int orig_offset = offset;

	proto_tree *yami_data_tree;
	proto_item *ti;

	uint32_t count;
	unsigned i;

	ti = proto_tree_add_item(tree, (data) ? hf_yami_message_data : hf_yami_message_hdr, tvb, offset, 0, ENC_NA);
	yami_data_tree = proto_item_add_subtree(ti, (data) ? ett_yami_msg_data : ett_yami_msg_hdr);

	count = tvb_get_letohl(tvb, offset);
	proto_tree_add_item(yami_data_tree, hf_yami_params_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_item_append_text(ti, ", %u parameters: ", count);

	for (i = 0; i < count; i++) {
		offset = dissect_yami_parameter(tvb, pinfo, yami_data_tree, offset, ti);
		/* smth went wrong */
		if (offset == -1)
			return -1;
	}

	proto_item_set_len(ti, offset - orig_offset);

	return offset;
}

static int
dissect_yami_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree *yami_tree;
	proto_item *ti;

	int frame_number;
	int message_header_size;
	int frame_payload_size;
	int frame_size;
	int offset;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "YAMI");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_yami, tvb, 0, -1, ENC_NA);
	yami_tree = proto_item_add_subtree(ti, ett_yami);

	offset = 0;

	proto_tree_add_item(yami_tree, hf_yami_message_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	frame_number = tvb_get_letohl(tvb, offset);
	ti = proto_tree_add_item(yami_tree, hf_yami_frame_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	if(frame_number < 0)
		proto_item_append_text(ti, "%s", " (last frame)");
	offset += 4;

	message_header_size = tvb_get_letohl(tvb, offset);
	proto_tree_add_item(yami_tree, hf_yami_message_header_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	if (message_header_size < 4) {
		/* XXX, expert info */
	}
	offset += 4;

	frame_payload_size = tvb_get_letohl(tvb, offset);
	ti = proto_tree_add_item(yami_tree, hf_yami_frame_payload_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	frame_size = frame_payload_size + 16;
	proto_item_append_text(ti, ", (YAMI Frame Size: %d)", frame_size);
	offset += 4;

	if (frame_number == 1 || frame_number == -1) {
		if (message_header_size <= frame_payload_size) {
			const int orig_offset = offset;

			offset = dissect_yami_data(tvb, pinfo, false, yami_tree, offset);
			if (offset != orig_offset + message_header_size) {
				/* XXX, expert info */
				offset = orig_offset + message_header_size;
			}

			dissect_yami_data(tvb, pinfo, true, yami_tree, offset);
		}
	}

	return tvb_captured_length(tvb);
}

#define FRAME_HEADER_LEN 16

static unsigned
get_yami_message_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                     int offset, void *data _U_)
{
	uint32_t len = tvb_get_letohl(tvb, offset + 12);

	return len + FRAME_HEADER_LEN;
}

static int
dissect_yami(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	tcp_dissect_pdus(tvb, pinfo, tree, yami_desegment, FRAME_HEADER_LEN, get_yami_message_len, dissect_yami_pdu, data);
	return tvb_captured_length(tvb);
}

void
proto_register_yami(void)
{
	static hf_register_info hf[] = {
		{ &hf_yami_message_id,
			{ "Message ID", "yami.message_id",
			  FT_INT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_yami_frame_number,
			{ "Frame Number", "yami.frame_number",
			  FT_INT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_yami_message_header_size,
			{ "Message Header Size", "yami.message_header_size",
			  FT_INT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_yami_frame_payload_size,
			{ "Frame Payload Size", "yami.frame_payload_size",
			  FT_INT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_yami_message_hdr,
			{ "Header message", "yami.msg_hdr",
			  FT_NONE, BASE_NONE, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_yami_message_data,
			{ "Data message", "yami.msg_data",
			  FT_NONE, BASE_NONE, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_yami_param,
			{ "Parameter", "yami.param",
			  FT_NONE, BASE_NONE, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_yami_param_name,
			{ "Name", "yami.param.name",
			  FT_STRING, BASE_NONE, NULL, 0x00,
			  "Parameter name", HFILL }
		},
		{ &hf_yami_param_type,
			{ "Type", "yami.param.type",
			  FT_INT32, BASE_DEC, VALS(yami_param_type_vals), 0x00,
			  "Parameter type", HFILL }
		},
		{ &hf_yami_param_value_bool,
			{ "Value", "yami.param.value_bool",
			  FT_BOOLEAN, BASE_NONE, NULL, 0x00,
			  "Parameter value (bool)", HFILL }
		},
		{ &hf_yami_param_value_int,
			{ "Value", "yami.param.value_int",
			  FT_INT32, BASE_DEC, NULL, 0x00,
			  "Parameter value (int)", HFILL }
		},
		{ &hf_yami_param_value_long,
			{ "Value", "yami.param.value_long",
			  FT_INT64, BASE_DEC, NULL, 0x00,
			  "Parameter value (long)", HFILL }
		},
		{ &hf_yami_param_value_double,
			{ "Value", "yami.param.value_double",
			  FT_DOUBLE, BASE_NONE, NULL, 0x00,
			  "Parameter value (double)", HFILL }
		},
		{ &hf_yami_param_value_str,
			{ "Value", "yami.param.value_str",
			  FT_STRING, BASE_NONE, NULL, 0x00,
			  "Parameter value (string)", HFILL }
		},
		{ &hf_yami_param_value_bin,
			{ "Value", "yami.param.value_bin",
			  FT_BYTES, BASE_NONE, NULL, 0x00,
			  "Parameter value (binary)", HFILL }
		},
		{ &hf_yami_params_count,
			{ "Parameters count", "yami.params_count",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_yami_items_count,
			{ "Items count", "yami.items_count",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
	};

	static int *ett[] = {
		&ett_yami,
		&ett_yami_msg_hdr,
		&ett_yami_msg_data,
		&ett_yami_param
	};

	module_t *yami_module;

	proto_yami = proto_register_protocol("YAMI Protocol", "YAMI", "yami");

	proto_register_field_array(proto_yami, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	yami_module = prefs_register_protocol(proto_yami, NULL);
	prefs_register_bool_preference(yami_module, "desegment",
			"Reassemble YAMI messages spanning multiple TCP segments",
			"Whether the YAMI dissector should reassemble messages spanning multiple TCP segments."
			"To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
			&yami_desegment);

	yami_handle = register_dissector("yami", dissect_yami, proto_yami);
}

void
proto_reg_handoff_yami(void)
{
	dissector_add_for_decode_as_with_preference("tcp.port", yami_handle);
	dissector_add_for_decode_as_with_preference("udp.port", yami_handle);
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
