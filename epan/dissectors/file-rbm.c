/* file-rbm.c
 *
 * Routines for Ruby Marshal Object
 *
 * Copyright 2018, Dario Lombardo (lomato@gmail.com)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Example for creating a Ruby marshal file:
 * o = <whatever ruby object>
 * f = File.open("marshal.dat", 'wb')
 * f.write(Marshal.dump(o))
 * f.close
*/

#include "config.h"

#include <epan/expert.h>
#include <epan/packet.h>

#include <file-rbm.h>
#include <wiretap/ruby_marshal.h>

static int proto_rbm;

static int hf_rbm_version;
static int hf_rbm_type;
static int hf_rbm_integer;
static int hf_rbm_length;
static int hf_rbm_string;
static int hf_rbm_link;
static int hf_rbm_double;
static int hf_rbm_struct;
static int hf_rbm_regex_param;

static int ett_rbm;
static int ett_array;
static int ett_array_obj;
static int ett_hash;
static int ett_hash_obj;
static int ett_variable;

static expert_field ei_rbm_invalid;
static expert_field ei_rbm_version_unsupported;

/* Marshal types */
static const value_string rbm_types[] = {
	{ '0', "nil" },
	{ 'T', "true" },
	{ 'F', "false" },
	{ 'i', "Integer" },
	{ ':', "Symbol" },
	{ '"', "String" },
	{ 'I', "Instance variable" },
	{ '[', "Array" },
	{ '{', "Hash" },
	{ 'f', "Double" },
	{ 'c', "Class" },
	{ 'm', "Module" },
	{ 'S', "Struct" },
	{ '/', "Regexp" },
	{ 'o', "Object" },
	{ 'C', "UserClass" },
	{ 'e', "Extended_object" },
	{ ';', "Symbol link" },
	{ '@', "Object link" },
	{ 'u', "DRb::DRbObject" },
	{ ',', "DRb address" },
	{0, NULL}
};

void proto_register_rbm(void);
void proto_reg_handoff_rbm(void);

static dissector_handle_t rbm_file_handle;

#define BETWEEN(v, b1, b2) (((v) >= (b1)) && ((v) <= (b2)))

static void dissect_rbm_object(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, unsigned* offset, char** type, char** value);

static void rbm_set_info(packet_info* pinfo, const char* str)
{
	const char* col_str = col_get_text(pinfo->cinfo, COL_INFO);
	if (!col_str || !strlen(col_str))
		col_append_fstr(pinfo->cinfo, COL_INFO, "Ruby Marshal Object: %s", str);
}

void get_rbm_integer(tvbuff_t* tvb, unsigned offset, int32_t* value, int* len)
{
	int8_t c;
	c = (tvb_get_int8(tvb, offset) ^ 128) - 128;
	if (c == 0) {
		*value = 0;
		*len = 1;
		return;
	}
	if (c >= 4) {
		*value = c - 5;
		*len = 1;
		return;
	}
	if (BETWEEN(c, 1, 3)) {
		int i;
		*value = 0;
		uint8_t byte;
		for (i = 0; i < c; i++) {
			byte = tvb_get_uint8(tvb, offset + 1 + i);
			*value |= (byte << (8 * i));
		}
		*len = (c + 1);
		return;
	}
	if (c < -6) {
		*value = c + 5;
		*len = 1;
		return;
	}
	if (BETWEEN(c, -5, -1)) {
		int i;
		*value = -1;
		uint8_t byte;
		int32_t a;
		int32_t b;
		for (i = 0; i < -c; i++) {
			byte = tvb_get_uint8(tvb, offset + 1 + i);
			a = ~(0xff << (8*i));
			b = byte << (8*i);
			*value = ((*value & a) | b);
		}
		*len = (-c + 1);
		return;
	}
}

static void dissect_rbm_integer(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, unsigned* offset, char** value_str)
{
	int32_t value = 0;
	int len = 0;
	rbm_set_info(pinfo, "integer");
	get_rbm_integer(tvb, *offset, &value, &len);
	proto_tree_add_int_format_value(tree, hf_rbm_integer, tvb, *offset, len, value, "%d", value);
	*offset += len;
	if (value_str)
		*value_str = wmem_strdup_printf(pinfo->pool, "%d", value);
}

static void dissect_rbm_basic(tvbuff_t* tvb _U_, packet_info* pinfo, proto_tree* tree _U_, unsigned* offset _U_, const uint8_t subtype,
	char** type, char** value_str)
{
	switch (subtype) {
		case '0':
			*type = "nil";
			break;
		case 'T':
			*type = "Boolean";
			*value_str = "true";
			break;
		case 'F':
			*type = "Boolean";
			*value_str = "false";
			break;
		default:
			DISSECTOR_ASSERT_NOT_REACHED();
	}
	rbm_set_info(pinfo, *type);
}

static void dissect_rbm_string_data_trailer(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, unsigned* offset, const char* label,
	const char* prefix, const char* trailer, char** value_str)
{
	int32_t value = 0;
	int len = 0;
	const char* s;

	rbm_set_info(pinfo, label);

	get_rbm_integer(tvb, *offset, &value, &len);
	proto_tree_add_int_format_value(tree, hf_rbm_length, tvb, *offset, len, value, "%d", value);
	*offset += len;
	s = (const char*)tvb_get_string_enc(pinfo->pool, tvb, *offset, value, ENC_NA);
	proto_tree_add_string_format_value(tree, hf_rbm_string, tvb, *offset, value, s, "%s%s%s", prefix, s, trailer);
	*offset += value;
	*value_str = wmem_strdup_printf(pinfo->pool, "%s%s%s", prefix, s, trailer);
}

static void dissect_rbm_string_data(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, unsigned* offset, const char* label,
	const char* prefix, char** value_str)
{
	dissect_rbm_string_data_trailer(tvb, pinfo, tree, offset, label, prefix, "", value_str);
}

// NOLINTNEXTLINE(misc-no-recursion)
static void dissect_rbm_array(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, unsigned* offset, char** value_str)
{
	int32_t value;
	int len;
	int32_t i;
	proto_tree* array_tree = NULL;
	proto_tree* array_obj_tree = NULL;
	int offset_start = *offset;

	rbm_set_info(pinfo, "Array");
	get_rbm_integer(tvb, *offset, &value, &len);
	proto_tree_add_int_format_value(tree, hf_rbm_length, tvb, *offset, len, value, "%d", value);
	array_tree = proto_tree_add_subtree(tree, tvb, *offset, 0, ett_array, NULL, "Array");
	*offset += len;

	for (i = 0; i < value; i++) {
		array_obj_tree = proto_tree_add_subtree(array_tree, tvb, *offset, 0, ett_array_obj, NULL, "Object");
		dissect_rbm_object(tvb, pinfo, array_obj_tree, offset, NULL, NULL);
	}
	proto_item_append_text(array_tree, " (%d)", value);
	proto_item_set_len(array_tree, *offset - offset_start);

	if (value_str)
		*value_str = wmem_strdup_printf(pinfo->pool, "%d", value);
}

// NOLINTNEXTLINE(misc-no-recursion)
static void dissect_rbm_hash(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, unsigned* offset, char** value_str)
{
	int32_t value;
	int len;
	int32_t i;
	proto_tree* hash_tree = NULL;
	proto_tree* hash_obj_tree = NULL;
	proto_tree* hash_key_tree = NULL;
	proto_tree* hash_value_tree = NULL;
	char* hkey = NULL;
	char* hval = NULL;
	int offset_start = *offset;

	rbm_set_info(pinfo, "Hash");
	get_rbm_integer(tvb, *offset, &value, &len);
	proto_tree_add_int_format_value(tree, hf_rbm_length, tvb, *offset, len, value, "%d", value);
	hash_tree = proto_tree_add_subtree(tree, tvb, *offset, 0, ett_hash, NULL, "Hash");
	*offset += len;

	for (i = 0; i < value; i++) {
		hash_obj_tree = proto_tree_add_subtree(hash_tree, tvb, *offset, 0, ett_hash_obj, NULL, "Entry");
		hash_key_tree = proto_tree_add_subtree(hash_obj_tree, tvb, *offset, 0, ett_hash_obj, NULL, "Key");
		dissect_rbm_object(tvb, pinfo, hash_key_tree, offset, NULL, &hkey);
		hash_value_tree = proto_tree_add_subtree(hash_obj_tree, tvb, *offset, 0, ett_hash_obj, NULL, "Value");
		dissect_rbm_object(tvb, pinfo, hash_value_tree, offset, NULL, &hval);
		proto_item_append_text(hash_obj_tree, " %s => %s", hkey, hval);
	}
	proto_item_append_text(hash_tree, " (%d)", value);
	proto_item_set_len(hash_tree, *offset - offset_start);

	if (value_str)
		*value_str = wmem_strdup_printf(pinfo->pool, "%d", value);
}

static void dissect_rbm_link(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, unsigned* offset, uint8_t subtype,
	char** type, char** value_str)
{
	int32_t value;
	int len;
	char* label;

	switch (subtype) {
		case ';':
			label = "Symbol";
			break;
		case '@':
			label = "Object";
			break;
		default:
			DISSECTOR_ASSERT_NOT_REACHED();
	}

	rbm_set_info(pinfo, wmem_strdup_printf(pinfo->pool, "%s Link", label));
	get_rbm_integer(tvb, *offset, &value, &len);
	proto_tree_add_int_format_value(tree, hf_rbm_link, tvb, *offset, len, value, "%d", value);
	*offset += len;
	if (type)
		*type = label;
	if (value_str)
		*value_str = wmem_strdup_printf(pinfo->pool, "%d", value);
}

static void dissect_rbm_double(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, unsigned* offset, char** value_str)
{
	int32_t value = 0;
	double valued;
	int len = 0;
	const char* s;

	rbm_set_info(pinfo, "Double");

	get_rbm_integer(tvb, *offset, &value, &len);
	proto_tree_add_int_format_value(tree, hf_rbm_length, tvb, *offset, len, value, "%d", value);
	*offset += len;
	s = (const char*)tvb_get_string_enc(pinfo->pool, tvb, *offset, value, ENC_NA);
	valued = g_ascii_strtod(s, NULL);
	proto_tree_add_double(tree, hf_rbm_double, tvb, *offset, value, valued);
	*offset += value;
	if (value_str)
		*value_str = wmem_strdup_printf(pinfo->pool, "%f", valued);
}

static void dissect_rbm_struct_data(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, unsigned* offset, char** value_str)
{
	int32_t value = 0;
	int len = 0;

	if (tvb_get_uint8(tvb, *offset) != ':')
		return;
	*offset += 1;

	rbm_set_info(pinfo, "Struct");
	get_rbm_integer(tvb, *offset, &value, &len);
	proto_tree_add_item(tree, hf_rbm_struct, tvb, *offset + 1, value, ENC_ASCII);
	*offset += 1 + value;
	if (value_str)
		*value_str = wmem_strdup_printf(pinfo->pool, "%d", value);
}

// NOLINTNEXTLINE(misc-no-recursion)
static void dissect_rbm_string(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, unsigned* offset, char** value)
{
	dissect_rbm_string_data(tvb, pinfo, tree, offset, "String", "", value);
	dissect_rbm_integer(tvb, pinfo, tree, offset, NULL);
	dissect_rbm_object(tvb, pinfo, tree, offset, NULL, NULL);
	dissect_rbm_object(tvb, pinfo, tree, offset, NULL, NULL);
}

// NOLINTNEXTLINE(misc-no-recursion)
static void dissect_rbm_regex(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, unsigned* offset, char** value)
{
	dissect_rbm_string_data_trailer(tvb, pinfo, tree, offset, "Regexp", "/", "/", value);
	proto_tree_add_item(tree, hf_rbm_regex_param, tvb, *offset, 1, ENC_NA);
	*offset += 1;
	dissect_rbm_integer(tvb, pinfo, tree, offset, NULL);
	dissect_rbm_object(tvb, pinfo, tree, offset, NULL, NULL);
	dissect_rbm_object(tvb, pinfo, tree, offset, NULL, NULL);
}

static void dissect_rbm_class(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, unsigned* offset, char** value_str)
{
	dissect_rbm_string_data(tvb, pinfo, tree, offset, "Class", "", value_str);
}

// NOLINTNEXTLINE(misc-no-recursion)
static void dissect_rbm_userclass(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, unsigned* offset, char** value)
{
	rbm_set_info(pinfo, "UserClass");
	dissect_rbm_object(tvb, pinfo, tree, offset, NULL, value);
}

static void dissect_rbm_symbol(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, unsigned* offset, char** value_str)
{
	dissect_rbm_string_data(tvb, pinfo, tree, offset, "Symbol", ":", value_str);
}

// NOLINTNEXTLINE(misc-no-recursion)
static void dissect_rbm_variable(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, unsigned* offset, char** value_str)
{
	int offset_start = *offset;
	proto_tree* variable_tree = proto_tree_add_subtree(tree, tvb, *offset, 0, ett_variable, NULL, "Variable");
	dissect_rbm_object(tvb, pinfo, variable_tree, offset, NULL, value_str);
	proto_item_set_len(variable_tree, *offset - offset_start);
}

static void dissect_rbm_module(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, unsigned* offset, char** value_str)
{
	dissect_rbm_string_data(tvb, pinfo, tree, offset, "Module", "", value_str);
}

// NOLINTNEXTLINE(misc-no-recursion)
static void dissect_rbm_struct(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, unsigned* offset, char** value)
{
	dissect_rbm_struct_data(tvb, pinfo, tree, offset, value);
	dissect_rbm_hash(tvb, pinfo, tree, offset, NULL);
}

// NOLINTNEXTLINE(misc-no-recursion)
static void dissect_rbm_drb(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, unsigned* offset)
{
	int offset_start = *offset;
	proto_tree* drb_tree = proto_tree_add_subtree(tree, tvb, *offset, 0, ett_variable, NULL, "Objects");
	dissect_rbm_object(tvb, pinfo, drb_tree, offset, NULL, NULL);
	dissect_rbm_object(tvb, pinfo, drb_tree, offset, NULL, NULL);
	proto_item_set_len(drb_tree, *offset - offset_start);
}

// NOLINTNEXTLINE(misc-no-recursion)
static void dissect_rbm_rubyobject(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, unsigned* offset)
{
	int offset_start = *offset;
	proto_tree* obj_tree = proto_tree_add_subtree(tree, tvb, *offset, 0, ett_variable, NULL, "Ruby Object");

	rbm_set_info(pinfo, "Ruby Object");

	dissect_rbm_object(tvb, pinfo, obj_tree, offset, NULL, NULL);
	dissect_rbm_hash(tvb, pinfo, obj_tree, offset, NULL);

	while (tvb_captured_length_remaining(tvb, *offset)) {
		dissect_rbm_object(tvb, pinfo, obj_tree, offset, NULL, NULL);
	}

	proto_item_set_len(obj_tree, *offset - offset_start);
}

// NOLINTNEXTLINE(misc-no-recursion)
static void dissect_rbm_extended(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, unsigned* offset)
{
	int offset_start = *offset;
	proto_tree* ext_tree = proto_tree_add_subtree(tree, tvb, *offset, 0, ett_variable, NULL, "Extended");

	rbm_set_info(pinfo, "Extended");
	dissect_rbm_object(tvb, pinfo, ext_tree, offset, NULL, NULL);
	proto_item_set_len(ext_tree, *offset - offset_start);
}

// NOLINTNEXTLINE(misc-no-recursion)
static void dissect_rbm_object(tvbuff_t* tvb, packet_info* pinfo, proto_tree* ptree, unsigned* offset, char** type, char** value)
{
	uint8_t subtype = tvb_get_uint8(tvb, *offset);
	proto_tree* tree;
	char* type_local = "Unknown";
	char* value_local = "Unknown";
	int offset_start = *offset;

	tree = proto_tree_add_subtree(ptree, tvb, *offset, 0, ett_variable, NULL, "");

	proto_tree_add_item(tree, hf_rbm_type, tvb, *offset, 1, ENC_NA);
	*offset += 1;

	increment_dissection_depth(pinfo);

	switch (subtype) {
		case '0':
		case 'T':
		case 'F':
			dissect_rbm_basic(tvb, pinfo, tree, offset, subtype, &type_local, &value_local);
			break;
		case 'i':
			type_local = "Integer";
			dissect_rbm_integer(tvb, pinfo, tree, offset, &value_local);
			break;
		case ':':
			type_local = "Symbol";
			dissect_rbm_symbol(tvb, pinfo, tree, offset, &value_local);
			break;
		case '"':
			type_local = "String";
			dissect_rbm_string(tvb, pinfo, tree, offset, &value_local);
			break;
		case 'I':
			type_local = "Instance Variable";
			dissect_rbm_variable(tvb, pinfo, tree, offset, &value_local);
			break;
		case '[':
			type_local = "Array";
			dissect_rbm_array(tvb, pinfo, tree, offset, &value_local);
			break;
		case '{':
			type_local = "Hash";
			dissect_rbm_hash(tvb, pinfo, tree, offset, &value_local);
			break;
		case ';':
		case '@':
			dissect_rbm_link(tvb, pinfo, tree, offset, subtype, &type_local, &value_local);
			break;
		case 'f':
			type_local = "Double";
			dissect_rbm_double(tvb, pinfo, tree, offset, &value_local);
			break;
		case 'c':
			type_local = "Class";
			dissect_rbm_class(tvb, pinfo, tree, offset, &value_local);
			break;
		case 'm':
			type_local = "Module";
			dissect_rbm_module(tvb, pinfo, tree, offset, &value_local);
			break;
		case 'S':
			type_local = "Struct";
			dissect_rbm_struct(tvb, pinfo, tree, offset, &value_local);
			break;
		case '/':
			type_local = "Regex";
			dissect_rbm_regex(tvb, pinfo, tree, offset, &value_local);
			break;
		case 'u':
			type_local = "DRb::DRbObject";
			dissect_rbm_drb(tvb, pinfo, tree, offset);
			break;
		case ',':
			dissect_rbm_inline(tvb, pinfo, tree, offset, &type_local, &value_local);
			break;
		case 'o':
			dissect_rbm_rubyobject(tvb, pinfo, tree, offset);
			type_local = "Ruby Object";
			break;
		case 'C':
			type_local = "UserClass";
			dissect_rbm_userclass(tvb, pinfo, tree, offset, &value_local);
			break;
		case 'e':
			type_local = "Extended Object";
			dissect_rbm_extended(tvb, pinfo, tree, offset);
			break;
		default:
			expert_add_info_format(pinfo, tree, &ei_rbm_invalid,
				"Object type 0x%x is invalid", subtype);
			*offset += tvb_reported_length_remaining(tvb, *offset);
	}

	proto_item_set_len(tree, *offset - offset_start);

	proto_item_append_text(tree, "Type: %s", type_local);
	if (value_local && strlen(value_local))
		proto_item_append_text(tree, ", Value: %s", value_local);

	if (type)
		*type = type_local;
	if (value)
		*value = value_local;

	decrement_dissection_depth(pinfo);
}

static bool dissect_rbm_header(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, unsigned* offset)
{
	uint8_t major;
	uint8_t minor;
	char* version;

	major = tvb_get_uint8(tvb, *offset);
	minor = tvb_get_uint8(tvb, *offset + 1);

	version = wmem_strdup_printf(pinfo->pool, "%u.%u", major, minor);
	proto_tree_add_string_format(tree, hf_rbm_version, tvb, *offset, 2, version, "Version: %s", version);
	*offset += 2;

	if (major != RUBY_MARSHAL_MAJOR || minor != RUBY_MARSHAL_MINOR) {
		expert_add_info_format(pinfo, tree, &ei_rbm_version_unsupported, "Version %u.%u is not supported (only %u.%u)",
			major, minor, RUBY_MARSHAL_MAJOR, RUBY_MARSHAL_MINOR);
		return false;
	}
	return true;
}

// NOLINTNEXTLINE(misc-no-recursion)
void dissect_rbm_inline(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, unsigned* offset, char** type, char** value)
{
	if (!dissect_rbm_header(tvb, pinfo, tree, offset))
		return;
	dissect_rbm_object(tvb, pinfo, tree, offset, type, value);
}

static int dissect_rbm(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
	unsigned offset = 0;
	proto_item* ti;
	proto_tree* rbm_tree;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Rbm");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_rbm, tvb, 0, -1, ENC_NA);
	rbm_tree = proto_item_add_subtree(ti, ett_rbm);

	dissect_rbm_inline(tvb, pinfo, rbm_tree, &offset, NULL, NULL);
	return offset;
}

void proto_register_rbm(void)
{
	expert_module_t* expert_rbm;

	static hf_register_info hf[] = {
		{ &hf_rbm_version,
			{ "Version", "rbm.version", FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_rbm_type,
			{ "Type", "rbm.type", FT_UINT8, BASE_HEX, VALS(rbm_types), 0x00, NULL, HFILL }
		},
		{ &hf_rbm_integer,
			{ "Integer", "rbm.int", FT_INT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_rbm_length,
			{ "Length", "rbm.length", FT_INT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_rbm_string,
			{ "Value", "rbm.string", FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_rbm_link,
			{ "Link to object", "rbm.link", FT_INT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_rbm_double,
			{ "Value", "rbm.double", FT_DOUBLE, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_rbm_struct,
			{ "Struct", "rbm.struct", FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_rbm_regex_param,
			{ "Regexp parameter", "rbm.regex.param", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
		}
	};

	static ei_register_info ei[] = {
		{ &ei_rbm_invalid, { "rbm.invalid", PI_UNDECODED, PI_WARN, "Invalid type", EXPFILL }},
		{ &ei_rbm_version_unsupported, { "rbm.version.unsupported", PI_UNDECODED, PI_WARN, "Unsupported version", EXPFILL }}
	};

	/* Setup protocol subtree array */
	static int* ett[] = {
		&ett_rbm,
		&ett_array,
		&ett_array_obj,
		&ett_hash,
		&ett_hash_obj,
		&ett_variable
	};

	proto_rbm = proto_register_protocol("Ruby Marshal Object", "Rbm", "rbm");

	expert_rbm = expert_register_protocol(proto_rbm);
	expert_register_field_array(expert_rbm, ei, array_length(ei));

	proto_register_field_array(proto_rbm, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	rbm_file_handle = register_dissector("rbm", dissect_rbm, proto_rbm);
}

void proto_reg_handoff_rbm(void)
{
	dissector_add_uint("wtap_encap", WTAP_ENCAP_RUBY_MARSHAL, rbm_file_handle);
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
