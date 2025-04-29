/* packet-msgpack.c
 *
 * Routines for MsgPack dissection
 * References:
 *   https://github.com/msgpack/msgpack/blob/master/spec.md
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

#include <wsutil/array.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/to_str.h>



void proto_register_msgpack(void);
void proto_reg_handoff_msgpack(void);

dissector_handle_t msgpack_handle;

static int proto_msgpack;

static int hf_msgpack_string;
static int hf_msgpack_bin;
static int hf_msgpack_type;
static int hf_msgpack_string_len;
static int hf_msgpack_bin_len;
static int hf_msgpack_uint_fix;
static int hf_msgpack_uint_8;
static int hf_msgpack_uint_16;
static int hf_msgpack_uint_32;
static int hf_msgpack_uint_64;
static int hf_msgpack_int_fix;
static int hf_msgpack_int_8;
static int hf_msgpack_int_16;
static int hf_msgpack_int_32;
static int hf_msgpack_int_64;
static int hf_msgpack_bool;
static int hf_msgpack_float;
static int hf_msgpack_double;
static int hf_msgpack_ext_type;
static int hf_msgpack_ext_len;
static int hf_msgpack_ext_bytes;

static int ett_msgpack;
static int ett_msgpack_num;
static int ett_msgpack_string;
static int ett_msgpack_bin;
static int ett_msgpack_array;
static int ett_msgpack_map;
static int ett_msgpack_map_elem;
static int ett_msgpack_ext;

static expert_field ei_msgpack_unsupported;

/* names and ranges from https://github.com/msgpack/msgpack/blob/master/spec.md#formats */
static const range_string msgpack_types[] = {
	{0x00, 0x7F, "positive fixint"},
	{0x80, 0x8F, "fixmap"},
	{0x90, 0x9F, "fixarray"},
	{0xA0, 0xBF, "fixstr"},
	{0xC0, 0xC0, "nil"},
	{0xC1, 0xC1, "(never used)"},
	{0xC2, 0xC2, "false"},
	{0xC3, 0xC3, "true"},
	{0xC4, 0xC4, "bin 8"},
	{0xC5, 0xC5, "bin 16"},
	{0xC6, 0xC6, "bin 32"},
	{0xC7, 0xC7, "ext 8"},
	{0xC8, 0xC8, "ext 16"},
	{0xC9, 0xC9, "ext 32"},
	{0xCA, 0xCA, "float 32"},
	{0xCB, 0xCB, "flost 64"},
	{0xCC, 0xCC, "uint 8"},
	{0xCD, 0xCD, "uint 16"},
	{0xCE, 0xCE, "uint 32"},
	{0xCF, 0xCF, "uint 64"},
	{0xD0, 0xD0, "int 8"},
	{0xD1, 0xD1, "int 16"},
	{0xD2, 0xD2, "int 32"},
	{0xD3, 0xD3, "int 64"},
	{0xD4, 0xD4, "fixext 1"},
	{0xD5, 0xD5, "fixext 2"},
	{0xD6, 0xD6, "fixext 4"},
	{0xD7, 0xD7, "fixext 8"},
	{0xD8, 0xD8, "fixext 16"},
	{0xD9, 0xD9, "str 8"},
	{0xDA, 0xDA, "str 16"},
	{0xDB, 0xDB, "str 32"},
	{0xDC, 0xDC, "array 16"},
	{0xDD, 0xDD, "array 32"},
	{0xDE, 0xDE, "map 16"},
	{0xDF, 0xDF, "map 32"},
	{0xE0, 0xFF, "negative fixint"},
	{0x00, 0x00, NULL}
};

static void dissect_msgpack_object(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data, int* offset, char** value);

static void dissect_msgpack_integer(tvbuff_t* tvb, packet_info *pinfo, proto_tree* tree, uint8_t type, void* data, int* offset, char** value)
{
	uint8_t uint8;
	uint16_t uint16;
	uint32_t uint32;
	uint64_t uint64;
	int8_t int8;
	int16_t int16;
	int32_t int32;
	int64_t int64;
	char* label;
	proto_tree* subtree;
	proto_item* ti;
	int t_offset = *offset;

	label = (data ? (char*)data : "MsgPack Integer");

	if (type >> 7 == 0) {
		ti = proto_tree_add_uint_format(tree, hf_msgpack_uint_fix, tvb, *offset, 1, type, "%s: %u", label, type);
		subtree = proto_item_add_subtree(ti, ett_msgpack_num);
		proto_tree_add_item(subtree, hf_msgpack_type, tvb, *offset, 1, ENC_NA);

		if (value)
			*value = wmem_strdup_printf(pinfo->pool, "%u", type);
		*offset += 1;
		return;
	}

	if (type >> 5 == 7) {
		int8_t stype = (int8_t)type;
		ti = proto_tree_add_int_format(tree, hf_msgpack_int_fix, tvb, *offset, 1, stype, "%s: %d", label, stype);
		subtree = proto_item_add_subtree(ti, ett_msgpack_num);
		proto_tree_add_item(subtree, hf_msgpack_type, tvb, *offset, 1, ENC_NA);

		if (value)
			*value = wmem_strdup_printf(pinfo->pool, "%d", stype);
		*offset += 1;
		return;
	}

	switch (type) {
		case 0xcc:
			uint8 = tvb_get_uint8(tvb, *offset + 1);
			ti = proto_tree_add_uint_format(tree, hf_msgpack_uint_8, tvb, *offset, 2, uint8, "%s: %u", label, uint8);
			if (value)
				*value = wmem_strdup_printf(pinfo->pool, "%u", uint8);
			*offset += 2;
			break;
		case 0xcd:
			uint16 = tvb_get_ntohs(tvb, *offset + 1);
			ti = proto_tree_add_uint_format(tree, hf_msgpack_uint_16, tvb, *offset, 3, uint16, "%s: %u", label, uint16);
			if (value)
				*value = wmem_strdup_printf(pinfo->pool, "%u", uint16);
			*offset += 3;
			break;
		case 0xce:
			uint32 = tvb_get_ntohl(tvb, *offset + 1);
			ti = proto_tree_add_uint_format(tree, hf_msgpack_uint_32, tvb, *offset, 5, uint32, "%s: %u", label, uint32);
			if (value)
				*value = wmem_strdup_printf(pinfo->pool, "%u", uint32);
			*offset += 5;
			break;
		case 0xcf:
			uint64 = tvb_get_ntoh64(tvb, *offset + 1);
			ti = proto_tree_add_uint64_format(tree, hf_msgpack_uint_64, tvb, *offset, 9, uint64, "%s: %" PRIu64, label, uint64);
			if (value)
				*value = wmem_strdup_printf(pinfo->pool, "%" PRIu64, uint64);
			*offset += 9;
			break;
		case 0xd0:
			int8 = tvb_get_int8(tvb, *offset + 1);
			ti = proto_tree_add_int_format(tree, hf_msgpack_int_8, tvb, *offset, 2, int8, "%s: %d", label, int8);
			if (value)
				*value = wmem_strdup_printf(pinfo->pool, "%d", int8);
			*offset += 2;
			break;
		case 0xd1:
			int16 = tvb_get_ntohs(tvb, *offset + 1);
			ti = proto_tree_add_int_format(tree, hf_msgpack_int_16, tvb, *offset, 3, int16, "%s: %d", label, int16);
			if (value)
				*value = wmem_strdup_printf(pinfo->pool, "%d", int16);
			*offset += 3;
			break;
		case 0xd2:
			int32 = tvb_get_ntohl(tvb, *offset + 1);
			ti = proto_tree_add_int_format(tree, hf_msgpack_int_32, tvb, *offset, 5, int32, "%s: %d", label, int32);
			if (value)
				*value = wmem_strdup_printf(pinfo->pool, "%d", int32);
			*offset += 5;
			break;
		case 0xd3:
			int64 = tvb_get_ntoh64(tvb, *offset + 1);
			ti = proto_tree_add_int64_format(tree, hf_msgpack_int_64, tvb, *offset, 9, int64, "%s: %" PRId64, label, int64);
			if (value)
				*value = wmem_strdup_printf(pinfo->pool, "%" PRId64, int64);
			*offset += 9;
			break;
	}
	subtree = proto_item_add_subtree(ti, ett_msgpack_num);
	proto_tree_add_item(subtree, hf_msgpack_type, tvb, t_offset, 1, ENC_NA);
}

// NOLINTNEXTLINE(misc-no-recursion)
static void dissect_msgpack_map(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, uint8_t type, void* data, int* offset, char** value)
{
	proto_tree* subtree;
	proto_tree* map_subtree;
	proto_item* ti;
	uint32_t len = 0;
	uint8_t lensize = 0;
	char* label;
	unsigned i;

	if (type >> 4 == 0x8) {
		len = type & 0x0F;
		lensize = 0;
	}
	else if (type == 0xde) {
		len = tvb_get_ntohs(tvb, *offset + 1);
		lensize = 2;
	}
	else if (type == 0xdf) {
		len = tvb_get_ntohl(tvb, *offset + 1);
		lensize = 4;
	}

	label = wmem_strdup_printf(pinfo->pool, "%s: %u element%s", data ? (char*)data : "MsgPack Map", len, len > 1 ? "s" : "");

	ti = proto_tree_add_string_format(tree, hf_msgpack_string, tvb, *offset, 1 + lensize, NULL, "%s", label);
	subtree = proto_item_add_subtree(ti, ett_msgpack_map);
	proto_tree_add_item(subtree, hf_msgpack_type, tvb, *offset, 1, ENC_NA);
	*offset += lensize + 1;
	for (i = 0; i < len; i++) {
		// We recurse here, but we'll run out of packet before we run out of stack.
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

// NOLINTNEXTLINE(misc-no-recursion)
static void dissect_msgpack_array(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, uint8_t type, void* data, int* offset, char** value)
{
	proto_tree* subtree;
	proto_item* ti;
	uint32_t len = 0;
	uint8_t lensize = 0;
	char* label;
	unsigned i;

	if (type >> 4 == 0x9) {
		len = type & 0x0F;
		lensize = 0;
	}
	else if (type == 0xdc) {
		len = tvb_get_ntohs(tvb, *offset + 1);
		lensize = 2;
	}
	else if (type == 0xdd) {
		len = tvb_get_ntohl(tvb, *offset + 1);
		lensize = 4;
	}

	label = wmem_strdup_printf(pinfo->pool, "%s %u element%s", data ? (char*)data : "MsgPack Array", len, len > 1 ? "s" : "");

	ti = proto_tree_add_string_format(tree, hf_msgpack_string, tvb, *offset, 1 + lensize, NULL, "%s", label);
	subtree = proto_item_add_subtree(ti, ett_msgpack_array);
	proto_tree_add_item(subtree, hf_msgpack_type, tvb, *offset, 1, ENC_NA);
	*offset += lensize + 1;
	for (i = 0; i < len; i++) {
		// We recurse here, but we'll run out of packet before we run out of stack.
		dissect_msgpack_object(tvb, pinfo, subtree, data, offset, value);
	}

	if (value)
		*value = label;
}

static void dissect_msgpack_string(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int type, void* data, int* offset, char** value)
{
	uint32_t len = 0;
	uint8_t lensize = 0;
	char* label;
	proto_item* ti;
	proto_tree* subtree;
	char* lvalue;

	if (type >> 5 == 0x5) {
		len = type & 0x1F;
		lensize = 0;
	}
	else if (type == 0xd9) {
		len = tvb_get_uint8(tvb, *offset + 1);
		lensize = 1;
	}
	else if (type == 0xda) {
		len = tvb_get_ntohs(tvb, *offset + 1);
		lensize = 2;
	}
	else if (type == 0xdb) {
		len = tvb_get_ntohl(tvb, *offset + 1);
		lensize = 4;
	}

	lvalue = (char*)tvb_get_string_enc(pinfo->pool, tvb, *offset + 1 + lensize, len, ENC_UTF_8);
	label = (data ? (char*)data : "MsgPack String");

	ti = proto_tree_add_string_format(tree, hf_msgpack_string, tvb, *offset, 1 + lensize + len, lvalue, "%s: %s", label, lvalue);
	subtree = proto_item_add_subtree(ti, ett_msgpack_string);
	proto_tree_add_item(subtree, hf_msgpack_type, tvb, *offset, 1, ENC_NA);

	if (lensize == 0) {
		proto_tree_add_uint(subtree, hf_msgpack_string_len, tvb, *offset, 1, len);
		*offset += 1;
	}
	else {
		*offset += 1;
		proto_tree_add_item(subtree, hf_msgpack_string_len, tvb, *offset, lensize, ENC_BIG_ENDIAN);
		*offset += lensize;
	}
	proto_tree_add_item(subtree, hf_msgpack_string, tvb, *offset, len, ENC_UTF_8);
	*offset += len;

	if (value)
		*value = lvalue;
}

static void dissect_msgpack_bin(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int type, void* data, int* offset, char** value)
{
	uint32_t len = 0;
	uint8_t lensize = 0;
	char* label;
	proto_item* ti;
	proto_tree* subtree;
	char* lvalue;

	switch (type) {
		case 0xc4:
			len = tvb_get_uint8(tvb, *offset + 1);
			lensize = 1;
			break;
		case 0xc5:
			len = tvb_get_ntohs(tvb, *offset + 1);
			lensize = 2;
			break;
		case 0xc6:
			len = tvb_get_ntohl(tvb, *offset + 1);
			lensize = 4;
			break;
	}

	lvalue = (char*)tvb_bytes_to_str(pinfo->pool, tvb, *offset + 1 + lensize, len);
	label = (data ? (char*)data : "MsgPack Bytes");

	ti = proto_tree_add_bytes_format(tree, hf_msgpack_bin, tvb, *offset, 1 + lensize + len, lvalue, "%s: %s", label, lvalue);
	subtree = proto_item_add_subtree(ti, ett_msgpack_bin);
	proto_tree_add_item(subtree, hf_msgpack_type, tvb, *offset, 1, ENC_NA);

	*offset += 1;
	proto_tree_add_item(subtree, hf_msgpack_bin_len, tvb, *offset, lensize, ENC_BIG_ENDIAN);
	*offset += lensize;

	proto_tree_add_item(subtree, hf_msgpack_bin, tvb, *offset, len, ENC_NA);
	*offset += len;

	if (value)
		*value = lvalue;
}

static void dissect_msgpack_float(tvbuff_t* tvb, packet_info *pinfo, proto_tree* tree, int type, void* data, int* offset, char** value)
{
	char* label;
	char* lvalue;
	proto_item* ti;
	proto_tree* subtree;
	int s_offset = *offset;

	*offset += 1;

	if (type == 0xca) {
		label = (data ? (char*)data : "MsgPack Float");
		float f = tvb_get_ntohieee_float(tvb, *offset);
		lvalue = wmem_strdup_printf(pinfo->pool, "%f", f);
		ti = proto_tree_add_float_format(tree, hf_msgpack_float, tvb, *offset, 4, f, "%s: %f", label, f);
		if (value)
			*value = lvalue;
		*offset += 4;
	} else {
		label = (data ? (char*)data : "MsgPack Double");
		double d = tvb_get_ntohieee_double(tvb, *offset);
		lvalue = wmem_strdup_printf(pinfo->pool, "%lf", d);
		ti = proto_tree_add_double_format(tree, hf_msgpack_double, tvb, *offset, 8, d, "%s: %lf", label, d);
		if (value)
			*value = lvalue;
		*offset += 8;
	}
	subtree = proto_item_add_subtree(ti, ett_msgpack_num);
	proto_tree_add_item(subtree, hf_msgpack_type, tvb, s_offset, 1, ENC_NA);
}

static void dissect_msgpack_ext(tvbuff_t* tvb, packet_info *pinfo, proto_tree* tree, int type, void* data, int* offset, char** value)
{
	char* label;
	uint32_t len = 0;
	uint8_t lensize = 0;
	proto_tree* subtree;
	unsigned offset_start = *offset;

	label = (data ? (char*)data : "Ext");

	subtree = proto_tree_add_subtree(tree, tvb, *offset, 0, ett_msgpack_ext, NULL, label);

	proto_tree_add_item(subtree, hf_msgpack_type, tvb, *offset, 1, ENC_NA);
	if (type >= 0xd4 && type <= 0xd8) {
		len = 1 << (type - 0xd4);
		proto_tree_add_uint(subtree, hf_msgpack_ext_len, tvb, *offset, 1, len);
	}
	else if (type == 0xc7) {
		len = tvb_get_uint8(tvb, *offset + 2);
		lensize = 1;
	}
	else if (type == 0xc8) {
		len = tvb_get_ntohs(tvb, *offset + 2);
		lensize = 2;
	}
	else if (type == 0xc9) {
		len = tvb_get_ntohl(tvb, *offset + 2);
		lensize = 4;
	}
	*offset += 1;

	proto_tree_add_item(subtree, hf_msgpack_ext_type, tvb, *offset, 1, ENC_NA);
	*offset += 1;

	if (lensize > 0) {
		proto_tree_add_item(subtree, hf_msgpack_ext_len, tvb, *offset, lensize, ENC_BIG_ENDIAN);
		*offset += lensize;
	}
	proto_tree_add_item(subtree, hf_msgpack_ext_bytes, tvb, *offset, len, ENC_NA);
	if (value) {
		*value = tvb_bytes_to_str(pinfo->pool, tvb, *offset, len);
	}
	*offset += len;

	proto_item_set_len(subtree, *offset - offset_start);
}

// NOLINTNEXTLINE(misc-no-recursion)
static void dissect_msgpack_object(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data, int* offset, char** value)
{
	uint8_t type;
	int s_offset = *offset;

	type = tvb_get_uint8(tvb, *offset);

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
			*value = (type - 0xc2) ? "True" : "False";
		*offset += 1;
		return;
	}

	// Integer
	if (type >= 0xe0 || type <= 0x7f || (type >= 0xcc && type <= 0xd3)) {
		dissect_msgpack_integer(tvb, pinfo, tree, type, data, offset, value);
		return;
	}

	// Float
	if (type == 0xca || type == 0xcb) {
		dissect_msgpack_float(tvb, pinfo, tree, type, data, offset, value);
		return;
	}

	// String
	if (type >> 5 == 0x5 || type == 0xd9 || type == 0xda || type == 0xdb) {
		dissect_msgpack_string(tvb, pinfo, tree, type, data, offset, value);
		return;
	}

	// Bin
	if (type == 0xc4 || type == 0xc5 || type == 0xc6) {
		dissect_msgpack_bin(tvb, pinfo, tree, type, data, offset, value);
		return;
	}

	// Array
	if (type >> 4 == 0x9 || type == 0xdc || type == 0xdd) {
		// We recurse here, but we'll run out of packet before we run out of stack.
		dissect_msgpack_array(tvb, pinfo, tree, type, data, offset, value);
		return;
	}

	// Map
	if (type >> 4 == 0x8 || type == 0xde || type == 0xdf) {
		// We recurse here, but we'll run out of packet before we run out of stack.
		dissect_msgpack_map(tvb, pinfo, tree, type, data, offset, value);
		return;
	}

	// Ext
	if ((type >= 0xd4 && type <= 0xd8) || (type >= 0xc7 && type <= 0xc9)) {
		dissect_msgpack_ext(tvb, pinfo, tree, type, data, offset, value);
		return;
	}

	if (*offset - s_offset == 0) {
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
			{ "Type", "msgpack.type", FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(msgpack_types), 0x00, NULL, HFILL }
		},
		{ &hf_msgpack_string_len,
			{ "Length", "msgpack.string.len", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_msgpack_bin,
			{ "Bytes", "msgpack.bin", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_msgpack_bin_len,
			{ "Length", "msgpack.bin.len", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_msgpack_uint_fix,
			{ "Integer", "msgpack.integer.fixint", FT_UINT8, BASE_DEC, NULL, 0x7F, NULL, HFILL }
		},
		{ &hf_msgpack_uint_8,
			{ "Integer", "msgpack.integer.u8", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_msgpack_uint_16,
			{ "Integer", "msgpack.integer.u16", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_msgpack_uint_32,
			{ "Integer", "msgpack.integer.u32", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_msgpack_uint_64,
			{ "Integer", "msgpack.integer.u64", FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_msgpack_int_fix,
			{ "Integer", "msgpack.integer.fixint", FT_INT8, BASE_DEC, NULL, 0x1F, NULL, HFILL }
		},
		{ &hf_msgpack_int_8,
			{ "Integer", "msgpack.integer.8", FT_INT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_msgpack_int_16,
			{ "Integer", "msgpack.integer.16", FT_INT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_msgpack_int_32,
			{ "Integer", "msgpack.integer.32", FT_INT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_msgpack_int_64,
			{ "Integer", "msgpack.integer.64", FT_INT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_msgpack_bool,
			{ "Boolean", "msgpack.boolean", FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_msgpack_float,
			{ "Float", "msgpack.float", FT_FLOAT, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_msgpack_double,
			{ "Double", "msgpack.double", FT_DOUBLE, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_msgpack_ext_type,
			{ "Ext type", "msgpack.ext.type", FT_INT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_msgpack_ext_len,
			{ "Length", "msgpack.ext.len", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_msgpack_ext_bytes,
			{ "Ext", "msgpack.ext", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
		}
	};

	static int* ett[] = {
		&ett_msgpack,
		&ett_msgpack_num,
		&ett_msgpack_string,
		&ett_msgpack_bin,
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
	// If this is ever streamed (transported over TCP) we need to add recursion checks
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
