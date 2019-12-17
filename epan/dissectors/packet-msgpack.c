/* packet-msgpack.c
 *
 * Routines for MsgPack dissection
 * References:
 *   https://github.com/msgpack/msgpack/
 *
 * Copyright 2018, Dario Lombardo <lomato@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/to_str.h>

#include <math.h>

void proto_register_msgpack(void);
void proto_reg_handoff_msgpack(void);

dissector_handle_t msgpack_handle;

static int proto_msgpack = -1;

static int hf_msgpack_string = -1;
static int hf_msgpack_type = -1;
static int hf_msgpack_string_len = -1;
static int hf_msgpack_uint_8 = -1;
static int hf_msgpack_uint_16 = -1;
static int hf_msgpack_uint_32 = -1;
static int hf_msgpack_uint_64 = -1;
static int hf_msgpack_int_8 = -1;
static int hf_msgpack_int_16 = -1;
static int hf_msgpack_int_32 = -1;
static int hf_msgpack_int_64 = -1;
static int hf_msgpack_bool = -1;
static int hf_msgpack_float = -1;
static int hf_msgpack_ext_fixext = -1;
static int hf_msgpack_ext_type = -1;
static int hf_msgpack_ext_bytes = -1;

static gint ett_msgpack = -1;
static gint ett_msgpack_string = -1;
static gint ett_msgpack_array = -1;
static gint ett_msgpack_map = -1;
static gint ett_msgpack_map_elem = -1;
static gint ett_msgpack_ext = -1;

static expert_field ei_msgpack_unsupported = EI_INIT;

static const value_string msgpack_ext_fixtexts[] = {
	{ 0xd4, "fixext 1" },
	{ 0xd5, "fixext 2" },
	{ 0xd6, "fixext 4" },
	{ 0xd7, "fixext 8" },
	{ 0xd8, "fixext 16" },
	{ 0, NULL }
};

static void dissect_msgpack_object(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data, int* offset, char** value);

static void dissect_msgpack_integer(tvbuff_t* tvb, proto_tree* tree, guint8 type, void* data, int* offset, char** value)
{
	guint8 uint8;
	guint16 uint16;
	guint32 uint32;
	guint64 uint64;
	gint8 int8;
	gint16 int16;
	gint32 int32;
	gint64 int64;
	char* label;

	label = (data ? (char*)data : "MsgPack Integer");

	if (type >> 7 == 0) {
		proto_tree_add_uint_format(tree, hf_msgpack_uint_8, tvb, *offset, 1, type, "%s: %u", label, type);
		if (value)
			*value = wmem_strdup_printf(wmem_packet_scope(), "%u", type);
		*offset += 1;
		return;
	}

	if (type >> 5 == 7) {
		proto_tree_add_int_format(tree, hf_msgpack_int_8, tvb, *offset, 1, type, "%s: %u", label, type);
		if (value)
			*value = wmem_strdup_printf(wmem_packet_scope(), "%d", type);
		*offset += 1;
		return;
	}

	switch (type) {
		case 0xcc:
			uint8 = tvb_get_guint8(tvb, *offset + 1);
			proto_tree_add_uint_format(tree, hf_msgpack_uint_8, tvb, *offset, 2, uint8, "%s: %u", label, uint8);
			if (value)
				*value = wmem_strdup_printf(wmem_packet_scope(), "%u", uint8);
			*offset += 2;
			break;
		case 0xcd:
			uint16 = tvb_get_ntohs(tvb, *offset + 1);
			proto_tree_add_uint(tree, hf_msgpack_uint_16, tvb, *offset, 3, uint16);
			if (value)
				*value = wmem_strdup_printf(wmem_packet_scope(), "%u", uint16);
			*offset += 3;
			break;
		case 0xce:
			uint32 = tvb_get_ntohl(tvb, *offset + 1);
			proto_tree_add_uint(tree, hf_msgpack_uint_32, tvb, *offset, 5, uint32);
			if (value)
				*value = wmem_strdup_printf(wmem_packet_scope(), "%u", uint32);
			*offset += 5;
			break;
		case 0xcf:
			uint64 = tvb_get_ntoh64(tvb, *offset + 1);
			proto_tree_add_uint64(tree, hf_msgpack_uint_64, tvb, *offset, 9, uint64);
			if (value)
				*value = wmem_strdup_printf(wmem_packet_scope(), "%" G_GINT64_MODIFIER "u", uint64);
			*offset += 9;
			break;
		case 0xd0:
			int8 = tvb_get_gint8(tvb, *offset + 1);
			proto_tree_add_int(tree, hf_msgpack_int_8, tvb, *offset, 2, int8);
			if (value)
				*value = wmem_strdup_printf(wmem_packet_scope(), "%d", int8);
			*offset += 2;
			break;
		case 0xd1:
			int16 = tvb_get_ntohs(tvb, *offset + 1);
			proto_tree_add_int(tree, hf_msgpack_int_16, tvb, *offset, 3, int16);
			if (value)
				*value = wmem_strdup_printf(wmem_packet_scope(), "%d", int16);
			*offset += 3;
			break;
		case 0xd2:
			int32 = tvb_get_ntohl(tvb, *offset + 1);
			proto_tree_add_int(tree, hf_msgpack_int_32, tvb, *offset, 5, int32);
			if (value)
				*value = wmem_strdup_printf(wmem_packet_scope(), "%d", int32);
			*offset += 5;
			break;
		case 0xd3:
			int64 = tvb_get_ntoh64(tvb, *offset + 1);
			proto_tree_add_int64(tree, hf_msgpack_int_64, tvb, *offset, 9, int64);
			if (value)
				*value = wmem_strdup_printf(wmem_packet_scope(), "%" G_GINT64_MODIFIER "d", int64);
			*offset += 9;
			break;
		default:
			DISSECTOR_ASSERT_NOT_REACHED();
	}
}

static void dissect_msgpack_map(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, guint8 type, void* data, int* offset, char** value)
{
	proto_tree* subtree;
	proto_tree* map_subtree;
	proto_item* ti;
	guint8 len;
	char* label;
	guint i;

	len = type & 0x0F;

	label = wmem_strdup_printf(wmem_packet_scope(), "%s: %u element%s", data ? (char*)data : "MsgPack Map", len, len > 1 ? "s" : "");

	ti = proto_tree_add_string_format(tree, hf_msgpack_string, tvb, *offset, 1 + len, NULL, "%s", label);
	subtree = proto_item_add_subtree(ti, ett_msgpack_map);
	*offset += 1;
	for (i = 0; i < len; i++) {
		map_subtree = proto_tree_add_subtree(subtree, tvb, *offset, 0, ett_msgpack_map_elem, NULL, "");
		dissect_msgpack_object(tvb, pinfo, map_subtree, "Key", offset, value);
		if (value)
			proto_item_append_text(map_subtree, " %s:", *value);
		dissect_msgpack_object(tvb, pinfo, map_subtree, "Value", offset, value);
		if (value)
			proto_item_append_text(map_subtree, " %s", *value);
	}

	if (value)
		*value = label;
}

static void dissect_msgpack_array(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, guint8 type, void* data, int* offset, char** value)
{
	proto_tree* subtree;
	proto_item* ti;
	guint8 len;
	char* label;
	guint i;

	len = type & 0x0F;

	label = wmem_strdup_printf(wmem_packet_scope(), "%s %u element%s", data ? (char*)data : "MsgPack Array", len, len > 1 ? "s" : "");

	ti = proto_tree_add_string_format(tree, hf_msgpack_string, tvb, *offset, 1 + len, NULL, "%s", label);
	subtree = proto_item_add_subtree(ti, ett_msgpack_array);
	*offset += 1;
	for (i = 0; i < len; i++) {
		dissect_msgpack_object(tvb, pinfo, subtree, data, offset, value);
	}

	if (value)
		*value = label;
}

static void dissect_msgpack_string(tvbuff_t* tvb, proto_tree* tree, int type, void* data, int* offset, char** value)
{
	guint32 len = 0;
	guint32 lensize = 0;
	char* label;
	proto_item* ti;
	proto_tree* subtree;
	char* lvalue;

	if (type >> 5 == 0x5) {
		len = type & 0x1F;
		lensize = 0;
	}
	if (type == 0xd9) {
		len = tvb_get_guint8(tvb, *offset + 1);
		lensize = 1;
	}
	if (type == 0xda) {
		len = tvb_get_ntohs(tvb, *offset + 1);
		lensize = 2;
	}
	if (type == 0xdb) {
		len = tvb_get_ntohl(tvb, *offset + 1);
		lensize = 4;
	}

	lvalue = tvb_get_string_enc(wmem_packet_scope(), tvb, *offset + 1 + lensize, len, ENC_NA);
	label = (data ? (char*)data : "MsgPack String");

	ti = proto_tree_add_string_format(tree, hf_msgpack_string, tvb, *offset, 1 + lensize + len, lvalue, "%s: %s", label, lvalue);

	subtree = proto_item_add_subtree(ti, ett_msgpack_string);
	if (lensize == 0) {
		proto_tree_add_uint_format(subtree, hf_msgpack_type, tvb, *offset, 1, type, "Type: String");
		proto_tree_add_uint_format(subtree, hf_msgpack_string_len, tvb, *offset, 1, lensize, "Length: 1");
		proto_tree_add_item(subtree, hf_msgpack_string, tvb, *offset + 1 + lensize, len, ENC_ASCII|ENC_NA);
	} else {
		proto_tree_add_item(subtree, hf_msgpack_type, tvb, *offset, 1, ENC_NA);
		proto_tree_add_item(subtree, hf_msgpack_string_len, tvb, *offset + 1, lensize, ENC_BIG_ENDIAN);
		proto_tree_add_item(subtree, hf_msgpack_string, tvb, *offset + 1 + lensize, len, ENC_ASCII|ENC_NA);
	}
	*offset += 1 + lensize + len;

	if (value)
		*value = lvalue;
}

static void dissect_msgpack_float(tvbuff_t* tvb, proto_tree* tree, int type, void* data, int* offset, char** value)
{
	char* label;
	char* lvalue;

	label = (data ? (char*)data : "Float");

	*offset += 1;

	if (type == 0xca) {
		float f = tvb_get_ntohieee_float(tvb, *offset);
		lvalue = wmem_strdup_printf(wmem_packet_scope(), "%f", f);
		proto_tree_add_string_format(tree, hf_msgpack_float, tvb, *offset, 4, lvalue, "%s: %f", label, f);
		if (value)
			*value = lvalue;
		*offset += 4;
	} else {
		double d = tvb_get_ntohieee_double(tvb, *offset);
		lvalue = wmem_strdup_printf(wmem_packet_scope(), "%f", d);
		proto_tree_add_string_format(tree, hf_msgpack_float, tvb, *offset, 8, lvalue, "%s: %f", label, d);
		if (value)
			*value = lvalue;
		*offset += 8;
	}
}

static void dissect_msgpack_ext(tvbuff_t* tvb, proto_tree* tree, int type, void* data, int* offset, char** value)
{
	char* label;
	int bytes;
	const char* start;
	proto_tree* ext_tree;
	guint offset_start = *offset;

	label = (data ? (char*)data : "Ext");

	ext_tree = proto_tree_add_subtree(tree, tvb, *offset, 0, ett_msgpack_ext, NULL, label);

	proto_tree_add_item(ext_tree, hf_msgpack_ext_fixext, tvb, *offset, 1, ENC_NA);
	*offset += 1;

	if (type >= 0xd4 && type <= 0xd8) {
		proto_tree_add_item(ext_tree, hf_msgpack_ext_type, tvb, *offset, 1, ENC_NA);
		*offset += 1;
		bytes = 1 << (type - 0xd4);
		start = tvb_get_ptr(tvb, *offset, bytes);
		proto_tree_add_bytes(ext_tree, hf_msgpack_ext_bytes, tvb, *offset, bytes, start);
		if (value)
			*value = bytes_to_hexstr(*value, start, bytes);
		*offset += bytes;
	}

	proto_item_set_len(ext_tree, *offset - offset_start);
}

static void dissect_msgpack_object(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data, int* offset, char** value)
{
	guint8 type;

	type = tvb_get_guint8(tvb, *offset);

	// Nil
	if (type == 0xc0) {
		proto_tree_add_string_format(tree, hf_msgpack_string, tvb, *offset, 1, "nil", "nil");
		if (value)
			*value = "nil";
		*offset += 1;
		return;
	}

	// True/False
	if (type == 0xc2 || type == 0xc3) {
		proto_tree_add_boolean(tree, hf_msgpack_bool, tvb, *offset, 1, type - 0xc2);
		if (value)
			*value = (type - 0xc2 ? "True" : "False");
		*offset += 1;
		return;
	}

	// Integer
	if (type > 0xe0 || type < 0x7f || type == 0xd3) {
		dissect_msgpack_integer(tvb, tree, type, data, offset, value);
		return;
	}

	// Float
	if (type == 0xca || type == 0xcb) {
		dissect_msgpack_float(tvb, tree, type, data, offset, value);
		return;
	}

	// String
	if (type >> 5 == 0x5 || type == 0xd9 || type == 0xda || type == 0xdb) {
		dissect_msgpack_string(tvb, tree, type, data, offset, value);
		return;
	}

	// Array
	if (type >> 4 == 0x9) {
		dissect_msgpack_array(tvb, pinfo, tree, type, data, offset, value);
		return;
	}

	// Map
	if (type >> 4 == 0x8) {
		dissect_msgpack_map(tvb, pinfo, tree, type, data, offset, value);
		return;
	}

	// Ext
	if ((type >= 0xd4 && type <= 0xd8) || (type >= 0xc7 && type <= 0xc9)) {
		dissect_msgpack_ext(tvb, tree, type, data, offset, value);
		return;
	}

	if (*offset == 0) {
		expert_add_info_format(pinfo, tree, &ei_msgpack_unsupported, "Type 0x%x is unsupported", type);
	}
}

static int dissect_msgpack(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data)
{
	int offset = 0;
	dissect_msgpack_object(tvb, pinfo, tree, data, &offset, NULL);
	return offset;
}

void proto_register_msgpack(void)
{
	expert_module_t* expert_msgpack;

	static hf_register_info hf[] = {
		{ &hf_msgpack_string,
			{ "String", "msgpack.string", FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_msgpack_type,
			{ "Type", "msgpack.type", FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_msgpack_string_len,
			{ "Length", "msgpack.string.len", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_msgpack_uint_8,
			{ "Integer", "msgpack.integer", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_msgpack_uint_16,
			{ "Integer", "msgpack.integer", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_msgpack_uint_32,
			{ "Integer", "msgpack.integer", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_msgpack_uint_64,
			{ "Integer", "msgpack.integer", FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_msgpack_int_8,
			{ "Integer", "msgpack.integer", FT_INT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_msgpack_int_16,
			{ "Integer", "msgpack.integer", FT_INT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_msgpack_int_32,
			{ "Integer", "msgpack.integer", FT_INT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_msgpack_int_64,
			{ "Integer", "msgpack.integer", FT_INT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_msgpack_bool,
			{ "Boolean", "msgpack.boolean", FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_msgpack_float,
			{ "Float", "msgpack.float", FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_msgpack_ext_fixext,
			{ "Ext fix text", "msgpack.ext.fixtext", FT_UINT8, BASE_HEX, VALS(msgpack_ext_fixtexts), 0x00, NULL, HFILL }
		},
		{ &hf_msgpack_ext_type,
			{ "Ext type", "msgpack.ext.type", FT_INT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_msgpack_ext_bytes,
			{ "Ext", "msgpack.float", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
		}
	};

	static gint* ett[] = {
		&ett_msgpack,
		&ett_msgpack_string,
		&ett_msgpack_array,
		&ett_msgpack_map,
		&ett_msgpack_map_elem,
		&ett_msgpack_ext
	};

	static ei_register_info ei[] = {
		{ &ei_msgpack_unsupported, { "msgpack.unsupported", PI_UNDECODED, PI_WARN, "Unsupported type", EXPFILL }}
	};

	proto_msgpack = proto_register_protocol("Message Pack", "MsgPack", "msgpack");
	msgpack_handle = register_dissector("msgpack", dissect_msgpack, proto_msgpack);

	expert_msgpack = expert_register_protocol(proto_msgpack);
	expert_register_field_array(expert_msgpack, ei, array_length(ei));

	proto_register_field_array(proto_msgpack, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_msgpack(void)
{
	dissector_add_for_decode_as("udp.port", msgpack_handle);
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
