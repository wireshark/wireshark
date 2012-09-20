/* packet-dbus.c
 * Routines for D-Bus dissection
 * Copyright 2012, Jakub Zawadzki <darkjames-ws@darkjames.pl>
 *
 * $Id$
 *
 * Protocol specification available at http://dbus.freedesktop.org/doc/dbus-specification.html
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

#include "config.h"

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/expert.h>
#include <epan/dissectors/packet-tcp.h>

static gboolean dbus_desegment = TRUE;

static int hf_dbus_hdr = -1;
static int hf_dbus_hdr_endianess = -1;
static int hf_dbus_hdr_type = -1;
static int hf_dbus_hdr_flags = -1;
static int hf_dbus_hdr_version = -1;
static int hf_dbus_hdr_body_length = -1;
static int hf_dbus_hdr_serial = -1;
static int hf_dbus_hdr_fields_length = -1;
static int hf_dbus_hdr_field = -1;
static int hf_dbus_hdr_field_code = -1;

static int hf_dbus_value_bool = -1;
static int hf_dbus_value_int = -1;
static int hf_dbus_value_uint = -1;
static int hf_dbus_value_str = -1;
static int hf_dbus_value_double = -1;

static int hf_dbus_body = -1;
static int hf_dbus_type_signature = -1;

static int ett_dbus = -1;
static int ett_dbus_hdr = -1;
static int ett_dbus_body = -1;
static int ett_dbus_field = -1;

static int proto_dbus = -1;

#define DBUS_MESSAGE_TYPE_INVALID 0
#define DBUS_MESSAGE_TYPE_METHOD_CALL 1
#define DBUS_MESSAGE_TYPE_METHOD_RETURN 2
#define DBUS_MESSAGE_TYPE_ERROR 3
#define DBUS_MESSAGE_TYPE_SIGNAL 4

static const value_string message_type_vals[] = {
	{ DBUS_MESSAGE_TYPE_INVALID, "Invalid" },
	{ DBUS_MESSAGE_TYPE_METHOD_CALL, "Method call" },
	{ DBUS_MESSAGE_TYPE_METHOD_RETURN, "Method reply" },
	{ DBUS_MESSAGE_TYPE_ERROR, "Error reply" },
	{ DBUS_MESSAGE_TYPE_SIGNAL, "Signal emission" },
	{ 0, NULL }
};

#define DBUS_HEADER_FIELD_INVALID        0
#define DBUS_HEADER_FIELD_PATH           1
#define DBUS_HEADER_FIELD_INTERFACE      2
#define DBUS_HEADER_FIELD_MEMBER         3
#define DBUS_HEADER_FIELD_ERROR_NAME     4
#define DBUS_HEADER_FIELD_REPLY_SERIAL   5
#define DBUS_HEADER_FIELD_DESTINATION    6
#define DBUS_HEADER_FIELD_SENDER         7
#define DBUS_HEADER_FIELD_SIGNATURE      8
#define DBUS_HEADER_FIELD_UNIX_FDS       9

static const value_string field_code_vals[] = {
	{ DBUS_HEADER_FIELD_INVALID, "INVALID" },
	{ DBUS_HEADER_FIELD_PATH, "PATH" },
	{ DBUS_HEADER_FIELD_INTERFACE, "INTERFACE" },
	{ DBUS_HEADER_FIELD_MEMBER, "MEMBER" },
	{ DBUS_HEADER_FIELD_ERROR_NAME, "ERROR_NAME" },
	{ DBUS_HEADER_FIELD_REPLY_SERIAL, "REPLY_SERIAL" },
	{ DBUS_HEADER_FIELD_DESTINATION, "DESTINATION" },
	{ DBUS_HEADER_FIELD_SENDER, "SENDER" },
	{ DBUS_HEADER_FIELD_SIGNATURE, "SIGNATURE" },
	{ DBUS_HEADER_FIELD_UNIX_FDS, "UNIX_FDS" },
	{ 0, NULL }
};

typedef struct {
	packet_info *pinfo;

	guint16 (*get16)(tvbuff_t *, const gint);
	guint32 (*get32)(tvbuff_t *, const gint);
	gdouble (*getdouble)(tvbuff_t *, const gint);
	int enc;

	guint32 body_len;
	guint32 fields_len;
	char *body_sig;
} dbus_info_t;

typedef union {
	char *str;
	guint uint;

} dbus_val_t;

static gboolean
dbus_validate_object_path(const char *path)
{
	/* XXX check */
	if (*path != '/')
		return FALSE;

	do {
		path++;

		if (*path == '/')
			return FALSE;

		while ((*path >= 'A' && *path <= 'Z') || (*path >= 'a' && *path <= 'z') || (*path >= '0' && *path <= '9') || *path == '_')
			path++;

		if (*path == '\0')
			return TRUE;

	} while (*path == '/');

	return FALSE;
}

static gboolean
dbus_validate_signature(const char *sig _U_)
{
	/* XXX implement */
	return TRUE;
}

static int
dissect_dbus_sig(tvbuff_t *tvb, dbus_info_t *dinfo, proto_tree *tree, int offset, char sig, dbus_val_t *ret)
{
	const int org_offset = offset;
	proto_item *ti;

	switch (sig) {
		case 'y':	/* BYTE */
		{
			guint8 val;

			val = tvb_get_guint8(tvb, offset);
			offset += 1;

			proto_tree_add_uint_format(tree, hf_dbus_value_uint, tvb, org_offset, offset - org_offset, val, "BYTE: %u", val);
			ret->uint = val;
			return offset;
		}

		case 'b':	/* BOOLEAN */
		{
			guint32 val;

			val = dinfo->get32(tvb, offset);
			offset += 4;

			ti = proto_tree_add_boolean_format(tree, hf_dbus_value_bool, tvb, org_offset, offset - org_offset, val, "BOOLEAN: %s", val ? "True" : "False");
			if (val != 0 && val != 1) {
				expert_add_info_format(dinfo->pinfo, ti, PI_PROTOCOL, PI_WARN, "Invalid boolean value (must be 0 or 1 is: %u)", val);
				return -1;
			}
			ret->uint = val;
			return offset;
		}

		case 'n':	/* INT16 */
		{
			gint16 val;

			val = (gint16 )dinfo->get16(tvb, offset);
			offset += 2;

			proto_tree_add_uint_format(tree, hf_dbus_value_int, tvb, org_offset, offset - org_offset, val, "INT16: %d", val);
			/* XXX ret */
			return offset;
		}

		case 'q':	/* UINT16 */
		{
			guint16 val;

			val = dinfo->get16(tvb, offset);
			offset += 2;

			proto_tree_add_uint_format(tree, hf_dbus_value_uint, tvb, org_offset, offset - org_offset, val, "UINT16: %u", val);
			ret->uint = val;
			return offset;
		}

		case 'i':	/* INT32 */
		{
			gint32 val;

			val = (gint32) dinfo->get32(tvb, offset);
			offset += 4;

			proto_tree_add_int_format(tree, hf_dbus_value_int, tvb, org_offset, offset - org_offset, val, "INT32: %d", val);
			/* XXX ret */
			return offset;
		}

		case 'u':	/* UINT32 */
		{
			guint32 val;

			val = dinfo->get32(tvb, offset);
			offset += 4;

			proto_tree_add_uint_format(tree, hf_dbus_value_uint, tvb, org_offset, offset - org_offset, val, "UINT32: %u", val);
			ret->uint = val;
			return offset;
		}

		case 'x':	/* INT64 */
		case 't':	/* UINT64 */
			return -1;

		case 'd':	/* DOUBLE */
		{
			gdouble val;

			val = dinfo->getdouble(tvb, offset);
			offset += 8;

			proto_tree_add_double_format(tree, hf_dbus_value_double, tvb, org_offset, offset - org_offset, val, "DOUBLE: %." STRINGIFY(DBL_DIG) "g", val);
			/* XXX ret */
			return offset;
		}

		case 's':	/* STRING */
		case 'o':	/* OBJECT_PATH */
		{
			guint32 len;
			char *val;

			len = dinfo->get32(tvb, offset);
			offset += 4;

			val = tvb_get_ephemeral_string(tvb, offset, len);
			offset += (len + 1 /* NUL-byte */ + 3) & ~3;

			if (sig == 's') {
				ti = proto_tree_add_string_format(tree, hf_dbus_value_str, tvb, org_offset, offset - org_offset, val, "STRING: %s", val);
				if (!g_utf8_validate(val, -1, NULL)) {
					expert_add_info_format(dinfo->pinfo, ti, PI_PROTOCOL, PI_WARN, "Invalid string (not UTF-8)");
					return -1;
				}
			} else {
				ti = proto_tree_add_string_format(tree, hf_dbus_value_str, tvb, org_offset, offset - org_offset, val, "OBJECT_PATH: %s", val);
				if (!dbus_validate_object_path(val)) {
					expert_add_info_format(dinfo->pinfo, ti, PI_PROTOCOL, PI_WARN, "Invalid object_path");
					return -1;
				}
			}
			ret->str = val;
			return offset;
		}

		case 'g':	/* SIGNATURE */
		{
			guint8 len;
			char *val;

			len = tvb_get_guint8(tvb, offset);
			offset += 1;

			val = tvb_get_ephemeral_string(tvb, offset, len);
			offset += (len + 1);

			ti = proto_tree_add_string_format(tree, hf_dbus_value_str, tvb, org_offset, offset - org_offset, val, "SIGNATURE: %s", val);
			if (!dbus_validate_signature(val)) {
				expert_add_info_format(dinfo->pinfo, ti, PI_PROTOCOL, PI_WARN, "Invalid signature");
				return -1;
			}
			ret->str = val;
			return offset;
		}

		/* ... */
	}
	return -1;
}

static int
dissect_dbus_field_signature(tvbuff_t *tvb, dbus_info_t *dinfo, proto_tree *tree, int offset, int field_code)
{
	const int org_offset = offset;

	proto_item *ti;
	guint sig_len;
	char *sig;

	sig_len = tvb_get_guint8(tvb, offset);
	offset += 1;

	/* sig_len = tvb_strsize(tvb, offset); */

	sig = tvb_get_ephemeral_string(tvb, offset, sig_len);
	offset += (sig_len + 1);

	ti = proto_tree_add_string(tree, hf_dbus_type_signature, tvb, org_offset, offset - org_offset, sig);
	if (!dbus_validate_signature(sig)) {
		expert_add_info_format(dinfo->pinfo, ti, PI_PROTOCOL, PI_WARN, "Invalid signature");
		return -1;
	}

	switch (field_code) {
		case DBUS_HEADER_FIELD_REPLY_SERIAL:
			if (!strcmp(sig, "u")) {	/* UINT32 */
				dbus_val_t serial_val;

				offset = dissect_dbus_sig(tvb, dinfo, tree, offset, 'u', &serial_val);
				if (offset != -1)
					{ /* XXX link with sending frame (serial_val.uint) */ }
				return offset;
			}
			break;

		case DBUS_HEADER_FIELD_DESTINATION:
		case DBUS_HEADER_FIELD_SENDER:
			if (!strcmp(sig, "s")) {	/* STRING */
				dbus_val_t addr_val;

				offset = dissect_dbus_sig(tvb, dinfo, tree, offset, 's', &addr_val);
				if (offset != -1)
					SET_ADDRESS((field_code == DBUS_HEADER_FIELD_DESTINATION) ? &dinfo->pinfo->dst : &dinfo->pinfo->src,
					            AT_STRINGZ, (int)strlen(addr_val.str)+1, addr_val.str);
				return offset;
			}
			break;

		case DBUS_HEADER_FIELD_SIGNATURE:
			if (!strcmp(sig, "g")) {	/* SIGNATURE */
				dbus_val_t sig_val;

				offset = dissect_dbus_sig(tvb, dinfo, tree, offset, 'g', &sig_val);
				if (offset != -1)
					dinfo->body_sig = sig_val.str;
				return offset;
			}
			break;
	}

	while (*sig) {
		dbus_val_t val;

		offset = dissect_dbus_sig(tvb, dinfo, tree, offset, *sig, &val);
		if (offset == -1)
			return -1;
		sig++;
	}
	return offset;
}

static int
dissect_dbus_hdr_fields(tvbuff_t *tvb, dbus_info_t *dinfo, proto_tree *tree, int offset)
{
	int end_offset;

	end_offset = offset + dinfo->fields_len;

	while (offset < end_offset) {
		proto_tree *field_tree;
		proto_item *ti;

		guint8 field_code;

		ti = proto_tree_add_item(tree, hf_dbus_hdr_field, tvb, offset, 0, ENC_NA);
		field_tree = proto_item_add_subtree(ti, ett_dbus_field);

		field_code = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(field_tree, hf_dbus_hdr_field_code, tvb, offset, 1, dinfo->enc);
		proto_item_append_text(ti, ": %s", val_to_str(field_code, field_code_vals, "Unknown: %d"));
		offset += 1;

		offset = dissect_dbus_field_signature(tvb, dinfo, field_tree, offset, field_code);
		if (offset == -1)
			break;

		offset = (offset + 7) & ~7;	/* XXX ? */

		proto_item_set_end(ti, tvb, offset);
	}

	/* XXX, verify if all required fields are preset */

	if (offset >= end_offset) {
		/* XXX expert */
	}

	return end_offset;
}

static int
dissect_dbus_hdr(tvbuff_t *tvb, dbus_info_t *dinfo, proto_tree *tree, int offset)
{
	proto_tree *hdr_tree;
	proto_item *ti;

	guint8 type;

	ti = proto_tree_add_item(tree, hf_dbus_hdr, tvb, offset, 0, ENC_NA);
	hdr_tree = proto_item_add_subtree(ti, ett_dbus_hdr);

	proto_tree_add_item(hdr_tree, hf_dbus_hdr_endianess, tvb, offset, 1, ENC_ASCII | ENC_NA);
	offset += 1;

	type = tvb_get_guint8(tvb, offset);
	col_add_str(dinfo->pinfo->cinfo, COL_INFO, val_to_str_const(type, message_type_vals, ""));
	proto_tree_add_item(hdr_tree, hf_dbus_hdr_type, tvb, offset, 1, dinfo->enc);
	offset += 1;

	proto_tree_add_item(hdr_tree, hf_dbus_hdr_flags, tvb, offset, 1, dinfo->enc);
	offset += 1;

	proto_tree_add_item(hdr_tree, hf_dbus_hdr_version, tvb, offset, 1, dinfo->enc);
	offset += 1;

	dinfo->body_len = dinfo->get32(tvb, offset);
	proto_tree_add_item(hdr_tree, hf_dbus_hdr_body_length, tvb, offset, 4, dinfo->enc);
	offset += 4;

	proto_tree_add_item(hdr_tree, hf_dbus_hdr_serial, tvb, offset, 4, dinfo->enc);
	offset += 4;

	dinfo->fields_len = dinfo->get32(tvb, offset);
	proto_tree_add_item(hdr_tree, hf_dbus_hdr_fields_length, tvb, offset, 4, dinfo->enc);
	offset += 4;

	return offset;
}

static int
dissect_dbus_body(tvbuff_t *tvb, dbus_info_t *dinfo, proto_tree *tree, int offset)
{
	proto_tree *body_tree;
	proto_item *ti;

	if (dinfo->body_len && dinfo->body_sig[0]) {
		const char *sig = dinfo->body_sig;

		ti = proto_tree_add_item(tree, hf_dbus_body, tvb, offset, 0, ENC_NA);
		body_tree = proto_item_add_subtree(ti, ett_dbus_body);

		while (*sig) {
			dbus_val_t val;

			offset = dissect_dbus_sig(tvb, dinfo, body_tree, offset, *sig, &val);
			if (offset == -1)
				return -1;
			sig++;
		}

		proto_item_set_end(ti, tvb, offset);

	} else if (dinfo->body_len || dinfo->body_sig[0]) {
		/* XXX smth wrong */
	}
	return offset;
}

static int
dissect_dbus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_tree *dbus_tree = NULL;
	dbus_info_t dinfo;

	int offset;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "D-BUS");
	col_clear(pinfo->cinfo, COL_INFO);

	memset(&dinfo, 0, sizeof(dinfo));
	dinfo.pinfo = pinfo;
	switch (tvb_get_guint8(tvb, 0)) {
		case 'l':
			dinfo.enc   = ENC_LITTLE_ENDIAN;
			dinfo.get16 = tvb_get_letohs;
			dinfo.get32 = tvb_get_letohl;
			dinfo.getdouble = tvb_get_letohieee_double;
			break;
		case 'B':
			dinfo.enc   = ENC_BIG_ENDIAN;
			dinfo.get16 = tvb_get_ntohs;
			dinfo.get32 = tvb_get_ntohl;
			dinfo.getdouble = tvb_get_ntohieee_double;
			break;
		default:	/* same as BIG_ENDIAN */
			/* XXX we should probably return 0; */
			dinfo.enc   = ENC_NA;
			dinfo.get16 = tvb_get_ntohs;
			dinfo.get32 = tvb_get_ntohl;
			dinfo.getdouble = tvb_get_ntohieee_double;
	}

	if (tree) {
		proto_item *ti = proto_tree_add_item(tree, proto_dbus, tvb, 0, -1, ENC_NA);
		dbus_tree = proto_item_add_subtree(ti, ett_dbus);
	}

	offset = 0;
	offset = dissect_dbus_hdr(tvb, &dinfo, dbus_tree, offset);
	offset = dissect_dbus_hdr_fields(tvb, &dinfo, dbus_tree, offset);
	/* header aligned to 8B */
	offset = (offset + 7) & ~7;

	if (!dinfo.body_sig)
		dinfo.body_sig = "";

	offset = dissect_dbus_body(tvb, &dinfo, dbus_tree, offset);

	return offset;
}

#define DBUS_HEADER_LEN 16

static guint
get_dbus_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
	guint32 (*get_guint32)(tvbuff_t *, const gint);

	guint32 len_body, len_hdr;

	switch (tvb_get_guint8(tvb, offset)) {
		case 'l':
			get_guint32 = tvb_get_letohl;
			break;
		case 'B':
		default:
			get_guint32 = tvb_get_ntohl;
			break;
	}

	len_hdr = DBUS_HEADER_LEN + get_guint32(tvb, offset + 12);
	len_hdr = (len_hdr + 7) & ~7;
	len_body = get_guint32(tvb, offset + 4);

	return len_hdr + len_body;
}

static void
dissect_dbus_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_dbus(tvb, pinfo, tree, NULL);
}

static int
dissect_dbus_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	tcp_dissect_pdus(tvb, pinfo, tree, dbus_desegment, DBUS_HEADER_LEN, get_dbus_message_len, dissect_dbus_pdu);
	return tvb_length(tvb);
}

void
proto_register_dbus(void)
{
	/* XXX, FT_NONE -> FT_BYTES? */
	static hf_register_info hf[] = {
	/* Header */
		{ &hf_dbus_hdr,
			{ "Header", "dbus.header", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_dbus_hdr_endianess,
			{ "Endianess Flag", "dbus.endianess", FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_dbus_hdr_type,
			{ "Message Type", "dbus.type", FT_UINT8, BASE_DEC, VALS(message_type_vals), 0x00, NULL, HFILL }
		},
		{ &hf_dbus_hdr_flags,
			{ "Message Flags", "dbus.flags", FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_dbus_hdr_version,
			{ "Protocol Version", "dbus.version", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_dbus_hdr_body_length,
			{ "Message body Length", "dbus.length", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_dbus_hdr_serial,
			{ "Message Serial (cookie)", "dbus.serial", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_dbus_hdr_fields_length,
			{ "Header fields Length", "dbus.fields_length", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
	/* Header field */
		{ &hf_dbus_hdr_field,
			{ "Header Field", "dbus.field", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_dbus_hdr_field_code,
			{ "Field code", "dbus.field.code", FT_UINT8, BASE_DEC, VALS(field_code_vals), 0x00, NULL, HFILL }
		},

		{ &hf_dbus_type_signature,
			{ "Type signature", "dbus.type_signature", FT_STRINGZ, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},

		{ &hf_dbus_body,
			{ "Body", "dbus.body", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},

	/* Values */
		{ &hf_dbus_value_bool,
			{ "Value", "dbus.value.bool", FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_dbus_value_int,
			{ "Value", "dbus.value.int", FT_INT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_dbus_value_uint,
			{ "Value", "dbus.value.uint", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_dbus_value_str,
			{ "Value", "dbus.value.str", FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_dbus_value_double,
			{ "Value", "dbus.value.double", FT_DOUBLE, BASE_NONE, NULL, 0x00, NULL, HFILL }
		}
	};

	static gint *ett[] = {
		&ett_dbus,
		&ett_dbus_hdr,
		&ett_dbus_body,
		&ett_dbus_field
	};

	proto_dbus = proto_register_protocol("D-Bus", "D-BUS", "dbus");

	proto_register_field_array(proto_dbus, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dbus(void)
{
	dissector_handle_t dbus_handle = new_create_dissector_handle(dissect_dbus, proto_dbus);
	dissector_handle_t dbus_handle_tcp = new_create_dissector_handle(dissect_dbus_tcp, proto_dbus);

	dissector_add_uint("wtap_encap", WTAP_ENCAP_DBUS, dbus_handle);
	dissector_add_handle("tcp.port", dbus_handle_tcp);
}

