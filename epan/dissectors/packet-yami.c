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
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define NEW_PROTO_TREE_API

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/strutil.h>
#include <epan/to_str.h>
#include <epan/dissectors/packet-tcp.h>

void proto_reg_handoff_yami(void);
void proto_register_yami(void);

static gboolean yami_desegment = TRUE;
static guint global_yami_config_tcp_port = 0;
static guint global_yami_config_udp_port = 0;

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

static header_field_info *hfi_yami = NULL;

#define YAMI_HFI_INIT HFI_INIT(proto_yami)

/* Header */
static header_field_info hfi_yami_message_id YAMI_HFI_INIT =
	{ "Message ID", "yami.message_id", FT_INT32, BASE_DEC, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_yami_frame_number YAMI_HFI_INIT =
	{ "Frame Number", "yami.frame_number", FT_INT32, BASE_DEC, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_yami_message_header_size YAMI_HFI_INIT =
	{ "Message Header Size", "yami.message_header_size", FT_INT32, BASE_DEC, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_yami_frame_payload_size YAMI_HFI_INIT =
	{ "Frame Payload Size", "yami.frame_payload_size", FT_INT32, BASE_DEC, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_yami_message_hdr YAMI_HFI_INIT =
	{ "Header message", "yami.msg_hdr", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_yami_message_data YAMI_HFI_INIT =
	{ "Data message", "yami.msg_data", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL };

/* Parameter */
static header_field_info hfi_yami_param YAMI_HFI_INIT =
	{ "Parameter", "yami.param", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_yami_param_name YAMI_HFI_INIT =
	{ "Name", "yami.param.name", FT_STRING, BASE_NONE, NULL, 0x00, "Parameter name", HFILL };

static header_field_info hfi_yami_param_type YAMI_HFI_INIT =
	{ "Type", "yami.param.type", FT_INT32, BASE_DEC, VALS(yami_param_type_vals), 0x00, "Parameter type", HFILL };

static header_field_info hfi_yami_param_value_bool YAMI_HFI_INIT =
	{ "Value", "yami.param.value_bool", FT_BOOLEAN, BASE_NONE, NULL, 0x00, "Parameter value (bool)", HFILL };

static header_field_info hfi_yami_param_value_int YAMI_HFI_INIT =
	{ "Value", "yami.param.value_int", FT_INT32, BASE_DEC, NULL, 0x00, "Parameter value (int)", HFILL };

static header_field_info hfi_yami_param_value_long YAMI_HFI_INIT =
	{ "Value", "yami.param.value_long", FT_INT64, BASE_DEC, NULL, 0x00, "Parameter value (long)", HFILL };

static header_field_info hfi_yami_param_value_double YAMI_HFI_INIT =
	{ "Value", "yami.param.value_double", FT_DOUBLE, BASE_NONE, NULL, 0x00, "Parameter value (double)", HFILL };

static header_field_info hfi_yami_param_value_str YAMI_HFI_INIT =
	{ "Value", "yami.param.value_str", FT_STRING, BASE_NONE, NULL, 0x00, "Parameter value (string)", HFILL };

static header_field_info hfi_yami_param_value_bin YAMI_HFI_INIT =
	{ "Value", "yami.param.value_bin", FT_BYTES, BASE_NONE, NULL, 0x00, "Parameter value (binary)", HFILL };

static header_field_info hfi_yami_params_count YAMI_HFI_INIT =
	{ "Parameters count", "yami.params_count", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_yami_items_count YAMI_HFI_INIT =
	{ "Items count", "yami.items_count", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL };

static int ett_yami = -1;
static int ett_yami_msg_hdr = -1;
static int ett_yami_msg_data = -1;
static int ett_yami_param = -1;

static int
dissect_yami_parameter(tvbuff_t *tvb, proto_tree *tree, int offset, proto_item *par_ti)
{
	const int orig_offset = offset;

	proto_tree *yami_param;
	proto_item *ti;

	char *name;
	int name_offset;
	guint32 name_len;

	guint32 type;

	ti = proto_tree_add_item(tree, &hfi_yami_param, tvb, offset, 0, ENC_NA);
	yami_param = proto_item_add_subtree(ti, ett_yami_param);

	name_offset = offset;
	name_len = tvb_get_letohl(tvb, offset);
	offset += 4;

	name = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, name_len, ENC_ASCII | ENC_NA);
	proto_item_append_text(ti, ": %s", name);
	proto_item_append_text(par_ti, "%s, ", name);
	offset += (name_len + 3) & ~3;
	proto_tree_add_string(yami_param, &hfi_yami_param_name, tvb, name_offset, offset - name_offset, name);

	type = tvb_get_letohl(tvb, offset);
	proto_tree_add_item(yami_param, &hfi_yami_param_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	switch (type) {
		case YAMI_TYPE_BOOLEAN:
		{
			guint32 val = tvb_get_letohl(tvb, offset);
			proto_item_append_text(ti, ", Type: boolean, Value: %s", val ? "True" : "False");
			proto_tree_add_item(yami_param, &hfi_yami_param_value_bool, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			break;
		}

		case YAMI_TYPE_INTEGER:
		{
			gint32 val = tvb_get_letohl(tvb, offset);
			proto_item_append_text(ti, ", Type: integer, Value: %d", val);
			proto_tree_add_item(yami_param, &hfi_yami_param_value_int, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			break;
		}

		case YAMI_TYPE_LONGLONG:
		{
			gint64 val = tvb_get_letoh64(tvb, offset);
			proto_item_append_text(ti, ", Type: long, Value: %" G_GINT64_MODIFIER "d", val);
			proto_tree_add_item(yami_param, &hfi_yami_param_value_long, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			offset += 8;
			break;
		}

		case YAMI_TYPE_DOUBLE:
		{
			gdouble val = tvb_get_letohieee_double(tvb, offset);
			proto_item_append_text(ti, ", Type: double, Value: %g", val);
			proto_tree_add_item(yami_param, &hfi_yami_param_value_double, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			offset += 8;
			break;
		}

		case YAMI_TYPE_STRING:
		{
			const int val_offset = offset;
			guint32 val_len;
			char *val;

			val_len = tvb_get_letohl(tvb, offset);
			offset += 4;

			val = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, val_len, ENC_ASCII | ENC_NA);

			proto_item_append_text(ti, ", Type: string, Value: \"%s\"", val);
			offset += (val_len + 3) & ~3;
			proto_tree_add_string(yami_param, &hfi_yami_param_value_str, tvb, val_offset, offset - val_offset, val);
			break;
		}

		case YAMI_TYPE_BINARY:
		{
			const int val_offset = offset;
			guint32 val_len;
			const guint8 *val;
			char *repr;

			val_len = tvb_get_letohl(tvb, offset);
			offset += 4;

			val = tvb_get_ptr(tvb, offset, val_len);
			repr = bytes_to_ep_str(val, val_len);

			proto_item_append_text(ti, ", Type: binary, Value: %s", repr);
			offset += (val_len + 3) & ~3;
			proto_tree_add_bytes_format_value(yami_param, hfi_yami_param_value_bin.id, tvb, val_offset, offset - val_offset, val, "%s", repr);
			break;
		}

		case YAMI_TYPE_BOOLEAN_ARRAY:
		{
			guint32 count;
			guint i;
			int j;

			count = tvb_get_letohl(tvb, offset);
			proto_tree_add_item(yami_param, &hfi_yami_items_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_item_append_text(ti, ", Type: boolean[], %u items: {", count);

			for (i = 0; i < count/32; i++) {
				guint32 val = tvb_get_letohl(tvb, offset);

				for (j = 0; j < 32; j++) {
					int r = !!(val & (1 << j));

					proto_item_append_text(ti, "%s, ", r ? "T" : "F");
					proto_tree_add_boolean(yami_param, &hfi_yami_param_value_bool, tvb, offset+(j/8), 1, r);
				}
				offset += 4;
			}

			if (count % 32) {
				guint32 val = tvb_get_letohl(tvb, offset);
				int tmp = count % 32;

				for (j = 0; j < tmp; j++) {
					int r = !!(val & (1 << j));

					proto_item_append_text(ti, "%s, ", r ? "T" : "F");
					proto_tree_add_boolean(yami_param, &hfi_yami_param_value_bool, tvb, offset+(j/8), 1, r);
				}
				offset += 4;
			}

			proto_item_append_text(ti, "}");
			break;
		}

		case YAMI_TYPE_INTEGER_ARRAY:
		{
			guint32 count;
			guint i;

			count = tvb_get_letohl(tvb, offset);
			proto_tree_add_item(yami_param, &hfi_yami_items_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_item_append_text(ti, ", Type: integer[], %u items: {", count);
			for (i = 0; i < count; i++) {
				gint32 val = tvb_get_letohl(tvb, offset);

				proto_item_append_text(ti, "%d, ", val);
				proto_tree_add_item(yami_param, &hfi_yami_param_value_int, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;
			}
			proto_item_append_text(ti, "}");
			break;
		}

		case YAMI_TYPE_LONGLONG_ARRAY:
		{
			guint32 count;
			guint i;

			count = tvb_get_letohl(tvb, offset);
			proto_tree_add_item(yami_param, &hfi_yami_items_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_item_append_text(ti, ", Type: long long[], %u items: {", count);

			for (i = 0; i < count; i++) {
				gint64 val = tvb_get_letoh64(tvb, offset);

				proto_item_append_text(ti, "%" G_GINT64_MODIFIER "d, ", val);
				proto_tree_add_item(yami_param, &hfi_yami_param_value_long, tvb, offset, 8, ENC_LITTLE_ENDIAN);
				offset += 8;
			}
			proto_item_append_text(ti, "}");
			break;
		}

		case YAMI_TYPE_DOUBLE_ARRAY:
		{
			guint32 count;
			guint i;

			count = tvb_get_letohl(tvb, offset);
			proto_tree_add_item(yami_param, &hfi_yami_items_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_item_append_text(ti, ", Type: double[], %u items: {", count);

			for (i = 0; i < count; i++) {
				gdouble val = tvb_get_letohieee_double(tvb, offset);

				proto_item_append_text(ti, "%g, ", val);
				proto_tree_add_item(yami_param, &hfi_yami_param_value_double, tvb, offset, 8, ENC_LITTLE_ENDIAN);
				offset += 8;
			}
			proto_item_append_text(ti, "}");
			break;
		}

		case YAMI_TYPE_STRING_ARRAY:
		{
			guint32 count;
			guint i;

			count = tvb_get_letohl(tvb, offset);
			proto_tree_add_item(yami_param, &hfi_yami_items_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_item_append_text(ti, ", Type: string[], %u items: {", count);

			for (i = 0; i < count; i++) {
				const int val_offset = offset;
				guint32 val_len;
				char *val;

				val_len = tvb_get_letohl(tvb, offset);
				offset += 4;

				val = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, val_len, ENC_ASCII | ENC_NA);

				proto_item_append_text(ti, "\"%s\", ", val);
				proto_tree_add_string(yami_param, &hfi_yami_param_value_str, tvb, val_offset, offset - val_offset, val);
				offset += (val_len + 3) & ~3;
			}
			proto_item_append_text(ti, "}");
			break;
		}

		case YAMI_TYPE_BINARY_ARRAY:
		{
			guint32 count;
			guint i;

			count = tvb_get_letohl(tvb, offset);
			proto_tree_add_item(yami_param, &hfi_yami_items_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_item_append_text(ti, ", Type: binary[], %u items: {", count);

			for (i = 0; i < count; i++) {
				const int val_offset = offset;
				guint32 val_len;
				const guint8 *val;
				char *repr;

				val_len = tvb_get_letohl(tvb, offset);
				offset += 4;

				val = tvb_get_ptr(tvb, offset, val_len);
				repr = bytes_to_ep_str(val, val_len);

				proto_item_append_text(ti, "%s, ", repr);
				offset += (val_len + 3) & ~3;
				proto_tree_add_bytes_format_value(yami_param, hfi_yami_param_value_bin.id, tvb, val_offset, offset - val_offset, val, "%s", repr);
			}
			proto_item_append_text(ti, "}");
			break;
		}

		case YAMI_TYPE_NESTED:
		{
			guint32 count;
			guint i;

			count = tvb_get_letohl(tvb, offset);
			proto_tree_add_item(yami_param, &hfi_yami_params_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_item_append_text(ti, ", Type: nested, %u parameters: ", count);

			for (i = 0; i < count; i++) {
				offset = dissect_yami_parameter(tvb, yami_param, offset, ti);
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
dissect_yami_data(tvbuff_t *tvb, gboolean data, proto_tree *tree, int offset)
{
	const int orig_offset = offset;

	proto_tree *yami_data_tree;
	proto_item *ti;

	guint32 count;
	guint i;

	ti = proto_tree_add_item(tree, (data) ? &hfi_yami_message_data : &hfi_yami_message_hdr, tvb, offset, 0, ENC_NA);
	yami_data_tree = proto_item_add_subtree(ti, (data) ? ett_yami_msg_data : ett_yami_msg_hdr);

	count = tvb_get_letohl(tvb, offset);
	proto_tree_add_item(yami_data_tree, &hfi_yami_params_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_item_append_text(ti, ", %u parameters: ", count);

	for (i = 0; i < count; i++) {
		offset = dissect_yami_parameter(tvb, yami_data_tree, offset, ti);
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

	gint frame_number;
	gint message_header_size;
	gint frame_payload_size;
	gint frame_size;
	int offset;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "YAMI");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, hfi_yami, tvb, 0, -1, ENC_NA);
	yami_tree = proto_item_add_subtree(ti, ett_yami);

	offset = 0;

	proto_tree_add_item(yami_tree, &hfi_yami_message_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	frame_number = tvb_get_letohl(tvb, offset);
	ti = proto_tree_add_item(yami_tree, &hfi_yami_frame_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	if(frame_number < 0)
		proto_item_append_text(ti, "%s", " (last frame)");
	offset += 4;

	message_header_size = tvb_get_letohl(tvb, offset);
	proto_tree_add_item(yami_tree, &hfi_yami_message_header_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	if (message_header_size < 4) {
		/* XXX, expert info */
	}
	offset += 4;

	frame_payload_size = tvb_get_letohl(tvb, offset);
	ti = proto_tree_add_item(yami_tree, &hfi_yami_frame_payload_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	frame_size = frame_payload_size + 16;
	proto_item_append_text(ti, ", (YAMI Frame Size: %d)", frame_size);
	offset += 4;

	if (frame_number == 1 || frame_number == -1) {
		if (message_header_size <= frame_payload_size) {
			const int orig_offset = offset;

			offset = dissect_yami_data(tvb, FALSE, yami_tree, offset);
			if (offset != orig_offset + message_header_size) {
				/* XXX, expert info */
				offset = orig_offset + message_header_size;
			}

			dissect_yami_data(tvb, TRUE, yami_tree, offset);
		}
	}

	return tvb_length(tvb);
}

#define FRAME_HEADER_LEN 16

static guint
get_yami_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
	guint32 len = tvb_get_letohl(tvb, offset + 12);

	return len + FRAME_HEADER_LEN;
}

static int
dissect_yami(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	tcp_dissect_pdus(tvb, pinfo, tree, yami_desegment, FRAME_HEADER_LEN, get_yami_message_len, dissect_yami_pdu, data);
	return tvb_length(tvb);
}

void
proto_register_yami(void)
{
#ifndef HAVE_HFI_SECTION_INIT
	static header_field_info *hfi[] = {
	/* Header */
		&hfi_yami_message_id,
		&hfi_yami_frame_number,
		&hfi_yami_message_header_size,
		&hfi_yami_frame_payload_size,
		&hfi_yami_message_hdr,
		&hfi_yami_message_data,
	/* Parameter */
		&hfi_yami_param,
		&hfi_yami_param_name,
		&hfi_yami_param_type,
		&hfi_yami_param_value_bool,
		&hfi_yami_param_value_int,
		&hfi_yami_param_value_long,
		&hfi_yami_param_value_double,
		&hfi_yami_param_value_str,
		&hfi_yami_param_value_bin,
		&hfi_yami_params_count,
		&hfi_yami_items_count,
	};
#endif

	static gint *ett[] = {
		&ett_yami,
		&ett_yami_msg_hdr,
		&ett_yami_msg_data,
		&ett_yami_param
	};

	module_t *yami_module;

	int proto_yami;

	proto_yami = proto_register_protocol("YAMI Protocol", "YAMI", "yami");
	hfi_yami = proto_registrar_get_nth(proto_yami);

	proto_register_fields(proto_yami, hfi, array_length(hfi));
	proto_register_subtree_array(ett, array_length(ett));

	yami_module = prefs_register_protocol(proto_yami, proto_reg_handoff_yami);
	prefs_register_uint_preference(yami_module, "tcp.port", "YAMI TCP Port", "The TCP port on which YAMI messages will be read(3000)", 10, &global_yami_config_tcp_port);
	prefs_register_uint_preference(yami_module, "udp.port", "YAMI UDP Port", "The UDP port on which YAMI messages will be read(5000)", 10, &global_yami_config_udp_port);
	prefs_register_bool_preference(yami_module, "desegment",
			"Reassemble YAMI messages spanning multiple TCP segments",
			"Whether the YAMI dissector should reassemble messages spanning multiple TCP segments."
			"To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
			&yami_desegment);

	yami_handle = new_create_dissector_handle(dissect_yami, proto_yami);
}

void
proto_reg_handoff_yami(void)
{
	static int yami_prefs_initialized = FALSE;
	static guint yami_tcp_port, yami_udp_port;

	if(yami_prefs_initialized == FALSE){
		yami_prefs_initialized = TRUE;
		yami_tcp_port = global_yami_config_tcp_port;
		yami_udp_port = global_yami_config_udp_port;
	}else{
		dissector_delete_uint("tcp.port", yami_tcp_port, yami_handle);
		dissector_delete_uint("udp.port", yami_udp_port, yami_handle);
	}

	yami_tcp_port = global_yami_config_tcp_port;
	yami_udp_port = global_yami_config_udp_port;

	dissector_add_uint("tcp.port", yami_tcp_port, yami_handle);
	dissector_add_uint("udp.port", yami_udp_port, yami_handle);
}

