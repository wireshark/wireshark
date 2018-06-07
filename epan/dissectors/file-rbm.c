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
#include <epan/packet.h>
#include <epan/expert.h>
#include <file-rbm.h>
#include <wiretap/ruby_marshal.h>

static int proto_rbm = -1;

static int hf_rbm_version = -1;
static int hf_rbm_type = -1;
static int hf_rbm_integer = -1;
static int hf_rbm_length = -1;
static int hf_rbm_string = -1;
static int hf_rbm_symbolic_link = -1;
static int hf_rbm_double = -1;
static int hf_rbm_struct = -1;
static int hf_rbm_regex_param = -1;

static gint ett_rbm = -1;
static gint ett_array = -1;
static gint ett_array_obj = -1;
static gint ett_hash = -1;
static gint ett_hash_obj = -1;
static gint ett_variable = -1;

static expert_field ei_rbm_unsupported = EI_INIT;
static expert_field ei_rbm_invalid = EI_INIT;
static expert_field ei_rbm_version_unsupported = EI_INIT;

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
	{ 'C', "Userclass" },
	{ 'e', "Extended_object" },
	{ ';', "Symbol link" },
	{ '@', "Object link" },
	{ 'u', "DRb::DRbObject" },
	{ ',', "DRb address" },
	{0, NULL}
};

#define BETWEEN(v, b1, b2) (((v) >= (b1)) && ((v) <= (b2)))

static gchar* dissect_rbm_object(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, gint* offset);

void rbm_set_info(packet_info* pinfo, const gchar* str)
{
	const gchar* col_str = col_get_text(pinfo->cinfo, COL_INFO);
	if (!col_str || !strlen(col_str))
		col_append_fstr(pinfo->cinfo, COL_INFO, "Ruby Marshal Object: %s", str);
}

void get_rbm_integer(tvbuff_t* tvb, guint offset, gint32* value, guint* len)
{
	gint8 c;
	c = (tvb_get_gint8(tvb, offset) ^ 128) - 128;
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
		gint i;
		*value = 0;
		guint8 byte;
		for (i = 0; i < c; i++) {
			byte = tvb_get_guint8(tvb, offset + 1 + i);
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
		gint i;
		*value = -1;
		guint8 byte;
		gint32 a;
		gint32 b;
		for (i = 0; i < -c; i++) {
			byte = tvb_get_guint8(tvb, offset + 1 + i);
			a = ~(0xff << (8*i));
			b = byte << (8*i);
			*value = ((*value & a) | b);
		}
		*len = (-c + 1);
		return;
	}
}

static gchar* dissect_rbm_integer(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, guint* offset)
{
	gint32 value = 0;
	gint len = 0;
	rbm_set_info(pinfo, "integer");
	get_rbm_integer(tvb, *offset, &value, &len);
	proto_tree_add_int_format_value(tree, hf_rbm_integer, tvb, *offset, len, value, "%d", value);
	*offset += len;
	return wmem_strdup_printf(wmem_packet_scope(), "%d", value);
}

static gchar* dissect_rbm_basic(tvbuff_t* tvb _U_, packet_info* pinfo, proto_tree* tree _U_, guint* offset _U_, const guint8 subtype)
{
	gchar* label;
	switch (subtype) {
		case '0':
			label = wmem_strdup(wmem_packet_scope(), "nil");
			break;
		case 'T':
			label = wmem_strdup(wmem_packet_scope(), "true");
			break;
		case 'F':
			label = wmem_strdup(wmem_packet_scope(), "false");
			break;
		default:
			DISSECTOR_ASSERT_NOT_REACHED();
	}
	rbm_set_info(pinfo, label);
	return label;
}

static gchar* dissect_rbm_string_data_trailer(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, guint* offset, const guint8* label,
	const gchar* prefix, const gchar* trailer)
{
	gint32 value = 0;
	gint len = 0;
	guint8* s;

	rbm_set_info(pinfo, label);

	get_rbm_integer(tvb, *offset, &value, &len);
	proto_tree_add_int_format_value(tree, hf_rbm_length, tvb, *offset, len, value, "%d", value);
	*offset += len;
	s = tvb_get_string_enc(wmem_packet_scope(), tvb, *offset, value, ENC_NA);
	proto_tree_add_string_format_value(tree, hf_rbm_string, tvb, *offset, value, s, "%s%s%s", prefix, s, trailer);
	*offset += value;
	return wmem_strdup_printf(wmem_packet_scope(), "%s%s%s", prefix, s, trailer);
}

static gchar* dissect_rbm_string_data(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, guint* offset, const guint8* label, const gchar* prefix)
{
	return dissect_rbm_string_data_trailer(tvb, pinfo, tree, offset, label, prefix, "");
}

static gchar* dissect_rbm_array(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, gint* offset)
{
	gint32 value;
	guint len;
	gint32 i;
	proto_tree* array_tree = NULL;
	proto_tree* array_obj_tree = NULL;

	rbm_set_info(pinfo, "Array");
	get_rbm_integer(tvb, *offset, &value, &len);
	proto_tree_add_int_format_value(tree, hf_rbm_length, tvb, *offset, len, value, "%d", value);
	array_tree = proto_tree_add_subtree(tree, tvb, *offset, 0, ett_array, NULL, "Array");
	*offset += len;

	for (i = 0; i < value; i++) {
		array_obj_tree = proto_tree_add_subtree(array_tree, tvb, *offset, 0, ett_array_obj, NULL, "Object");
		dissect_rbm_object(tvb, pinfo, array_obj_tree, offset);
	}

	return "[]";
}

static gchar* dissect_rbm_hash(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, gint* offset)
{
	gint32 value;
	guint len;
	gint32 i;
	proto_tree* hash_tree = NULL;
	proto_tree* hash_obj_tree = NULL;
	proto_tree* hash_key_tree = NULL;
	proto_tree* hash_value_tree = NULL;

	rbm_set_info(pinfo, "Hash");
	get_rbm_integer(tvb, *offset, &value, &len);
	proto_tree_add_int_format_value(tree, hf_rbm_length, tvb, *offset, len, value, "%d", value);
	hash_tree = proto_tree_add_subtree(tree, tvb, *offset, 0, ett_hash, NULL, "Hash");
	*offset += len;

	for (i = 0; i < value; i++) {
		hash_obj_tree = proto_tree_add_subtree(hash_tree, tvb, *offset, 0, ett_hash_obj, NULL, "Object");
		hash_key_tree = proto_tree_add_subtree(hash_obj_tree, tvb, *offset, 0, ett_hash_obj, NULL, "Key");
		dissect_rbm_object(tvb, pinfo, hash_key_tree, offset);
		hash_value_tree = proto_tree_add_subtree(hash_obj_tree, tvb, *offset, 0, ett_hash_obj, NULL, "Value");
		dissect_rbm_object(tvb, pinfo, hash_value_tree, offset);
	}

	return "{}";
}

static gchar* dissect_rbm_symbol_link(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, gint* offset)
{
	gint32 value;
	guint len;
	rbm_set_info(pinfo, "Symbol Link");
	get_rbm_integer(tvb, *offset, &value, &len);
	proto_tree_add_int_format_value(tree, hf_rbm_symbolic_link, tvb, *offset, len, value, "%d", value);
	*offset += len;
	return "";
}

static gchar* dissect_rbm_double(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, gint* offset)
{
	gint32 value = 0;
	gdouble valued;
	gint len = 0;
	guint8* s;

	rbm_set_info(pinfo, "Double");

	get_rbm_integer(tvb, *offset, &value, &len);
	proto_tree_add_int_format_value(tree, hf_rbm_length, tvb, *offset, len, value, "%d", value);
	*offset += len;
	s = tvb_get_string_enc(wmem_packet_scope(), tvb, *offset, value, ENC_NA);
	valued = g_ascii_strtod(s, NULL);
	proto_tree_add_double(tree, hf_rbm_double, tvb, *offset, value, valued);
	*offset += value;
	return wmem_strdup_printf(wmem_packet_scope(), "%f", valued);
}

static gchar* dissect_rbm_struct_data(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, gint* offset)
{
	gint32 value = 0;
	gint len = 0;

	if (tvb_get_guint8(tvb, *offset) != ':')
		return "";
	*offset += 1;

	rbm_set_info(pinfo, "Struct");
	get_rbm_integer(tvb, *offset, &value, &len);
	proto_tree_add_item(tree, hf_rbm_struct, tvb, *offset + 1, value, ENC_ASCII|ENC_NA);
	*offset += 1 + value;
	return "";
}

static gchar* dissect_rbm_string(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, gint* offset)
{
	gchar* label;
	label = dissect_rbm_string_data(tvb, pinfo, tree, offset, "String", "");
	dissect_rbm_integer(tvb, pinfo, tree, offset);
	dissect_rbm_object(tvb, pinfo, tree, offset);
	dissect_rbm_object(tvb, pinfo, tree, offset);
	return label;
}

static gchar* dissect_rbm_regex(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, gint* offset)
{
	gchar* label;
	label = dissect_rbm_string_data_trailer(tvb, pinfo, tree, offset, "Regexp", "/", "/");
	proto_tree_add_item(tree, hf_rbm_regex_param, tvb, *offset, 1, ENC_NA);
	*offset += 1;
	dissect_rbm_integer(tvb, pinfo, tree, offset);
	dissect_rbm_object(tvb, pinfo, tree, offset);
	dissect_rbm_object(tvb, pinfo, tree, offset);
	return label;
}

static gchar* dissect_rbm_class(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, gint* offset)
{
	return dissect_rbm_string_data(tvb, pinfo, tree, offset, "Class", "");
}

static gchar* dissect_rbm_symbol(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, gint* offset)
{
	return dissect_rbm_string_data(tvb, pinfo, tree, offset, "Symbol", ":");
}

static gchar* dissect_rbm_variable(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, gint* offset)
{
	proto_tree* variable_tree = proto_tree_add_subtree(tree, tvb, *offset, 0, ett_variable, NULL, "Variable");
	return dissect_rbm_object(tvb, pinfo, variable_tree, offset);
}

static gchar* dissect_rbm_module(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, gint* offset)
{
	return dissect_rbm_string_data(tvb, pinfo, tree, offset, "Module", "");
}

static gchar* dissect_rbm_struct(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, gint* offset)
{
	dissect_rbm_struct_data(tvb, pinfo, tree, offset);
	dissect_rbm_hash(tvb, pinfo, tree, offset);
	return "";
}

static gchar* dissect_rbm_drb(tvbuff_t* tvb _U_, packet_info* pinfo _U_, proto_tree* tree _U_, gint* offset _U_)
{
	proto_tree* drb_tree = proto_tree_add_subtree(tree, tvb, *offset, 0, ett_variable, NULL, "Objects");
	dissect_rbm_object(tvb, pinfo, drb_tree, offset);
	dissect_rbm_object(tvb, pinfo, drb_tree, offset);
	return "";
}

static gchar* dissect_rbm_object(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, gint* offset)
{
	guint8 subtype = tvb_get_guint8(tvb, *offset);
	gchar* subtype_str = NULL;
	gchar* label = "TBD";

	proto_tree_add_item(tree, hf_rbm_type, tvb, *offset, 1, ENC_NA);
	*offset += 1;

	switch (subtype) {
		case '0':
		case 'T':
		case 'F':
			label = dissect_rbm_basic(tvb, pinfo, tree, offset, subtype);
			break;
		case 'i':
			label = dissect_rbm_integer(tvb, pinfo, tree, offset);
			break;
		case ':':
			label = dissect_rbm_symbol(tvb, pinfo, tree, offset);
			break;
		case '"':
			label = dissect_rbm_string(tvb, pinfo, tree, offset);
			break;
		case 'I':
			label = dissect_rbm_variable(tvb, pinfo, tree, offset);
			break;
		case '[':
			label = dissect_rbm_array(tvb, pinfo, tree, offset);
			break;
		case '{':
			label = dissect_rbm_hash(tvb, pinfo, tree, offset);
			break;
		case ';':
			label = dissect_rbm_symbol_link(tvb, pinfo, tree, offset);
			break;
		case 'f':
			label = dissect_rbm_double(tvb, pinfo, tree, offset);
			break;
		case 'c':
			label = dissect_rbm_class(tvb, pinfo, tree, offset);
			break;
		case 'm':
			label = dissect_rbm_module(tvb, pinfo, tree, offset);
			break;
		case 'S':
			label = dissect_rbm_struct(tvb, pinfo, tree, offset);
			break;
		case '/':
			label = dissect_rbm_regex(tvb, pinfo, tree, offset);
			break;
		case 'u':
			label = dissect_rbm_drb(tvb, pinfo, tree, offset);
			break;
		case ',':
			label = dissect_rbm_inline(tvb, pinfo, tree, offset);
			break;
		case 'o':
			subtype_str = "Object";
			break;
		case 'C':
			subtype_str = "User Class";
			break;
		case 'e':
			subtype_str = "Extended Object";
			break;
		case '@':
			subtype_str = "Object Link";
			break;
		default:
			expert_add_info_format(pinfo, tree, &ei_rbm_invalid,
				"Object type 0x%x is invalid", subtype);
	}

	if (subtype_str)
		expert_add_info_format(pinfo, tree, &ei_rbm_unsupported,
			"Object type 0x%x (%s) not supported yet", subtype, subtype_str);

	return label;
}

static gboolean dissect_rbm_header(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, gint* offset)
{
	guint8 major;
	guint8 minor;
	gchar* version;

	major = tvb_get_guint8(tvb, *offset);
	minor = tvb_get_guint8(tvb, *offset + 1);

	version = wmem_strdup_printf(wmem_packet_scope(), "%u.%u", major, minor);
	proto_tree_add_string_format(tree, hf_rbm_version, tvb, *offset, 2, version, "Version: %s", version);
	*offset += 2;

	if (major != RUBY_MARSHAL_MAJOR || minor != RUBY_MARSHAL_MINOR) {
		expert_add_info_format(pinfo, tree, &ei_rbm_version_unsupported, "Version %u.%u is not supported (only %u.%u)",
			major, minor, RUBY_MARSHAL_MAJOR, RUBY_MARSHAL_MINOR);
		return FALSE;
	}
	return TRUE;
}

gchar* dissect_rbm_inline(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, gint* offset)
{
	if (!dissect_rbm_header(tvb, pinfo, tree, offset))
		return "";
	return dissect_rbm_object(tvb, pinfo, tree, offset);
}

static int dissect_rbm(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
	gint offset = 0;
	proto_item* ti;
	proto_tree* rbm_tree;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Rbm");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_rbm, tvb, 0, -1, ENC_NA);
	rbm_tree = proto_item_add_subtree(ti, ett_rbm);

	dissect_rbm_inline(tvb, pinfo, rbm_tree, &offset);
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
		{ &hf_rbm_symbolic_link,
			{ "Symbol Link to object", "rbm.symbolic_link", FT_INT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
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
        { &ei_rbm_unsupported, { "rbm.unsupported", PI_UNDECODED, PI_WARN, "Unsupported type", EXPFILL }},
        { &ei_rbm_invalid, { "rbm.invalid", PI_UNDECODED, PI_WARN, "Invalid type", EXPFILL }},
        { &ei_rbm_version_unsupported, { "rbm.version.unsupported", PI_UNDECODED, PI_WARN, "Unsupported version", EXPFILL }}
    };

	/* Setup protocol subtree array */
	static gint* ett[] = {
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
}

void proto_reg_handoff_rbm(void)
{
	dissector_handle_t rbm_file_handle = create_dissector_handle(dissect_rbm, proto_rbm);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_RUBY_MARSHAL, rbm_file_handle);
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
