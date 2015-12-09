/* packet-dbus.c
 * Routines for D-Bus dissection
 * Copyright 2012, Jakub Zawadzki <darkjames-ws@darkjames.pl>
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

#define NEW_PROTO_TREE_API

#include "config.h"

#include <epan/packet.h>
#include <wiretap/wtap.h>
#include <epan/expert.h>
#include "packet-tcp.h"

void proto_register_dbus(void);
void proto_reg_handoff_dbus(void);

static gboolean dbus_desegment = TRUE;

static dissector_handle_t dbus_handle;
static dissector_handle_t dbus_handle_tcp;

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

static header_field_info *hfi_dbus = NULL;

#define DBUS_HFI_INIT HFI_INIT(proto_dbus)

/* XXX, FT_NONE -> FT_BYTES? */

/* Header */
static header_field_info hfi_dbus_hdr DBUS_HFI_INIT =
	{ "Header", "dbus.header", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_dbus_hdr_endianness DBUS_HFI_INIT =
	{ "Endianness Flag", "dbus.endianness", FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_dbus_hdr_type DBUS_HFI_INIT =
	{ "Message Type", "dbus.type", FT_UINT8, BASE_DEC, VALS(message_type_vals), 0x00, NULL, HFILL };

static header_field_info hfi_dbus_hdr_flags DBUS_HFI_INIT =
	{ "Message Flags", "dbus.flags", FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_dbus_hdr_version DBUS_HFI_INIT =
	{ "Protocol Version", "dbus.version", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_dbus_hdr_body_length DBUS_HFI_INIT =
	{ "Message body Length", "dbus.length", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_dbus_hdr_serial DBUS_HFI_INIT =
	{ "Message Serial (cookie)", "dbus.serial", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_dbus_hdr_fields_length DBUS_HFI_INIT =
	{ "Header fields Length", "dbus.fields_length", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL };

/* Header field */
static header_field_info hfi_dbus_hdr_field DBUS_HFI_INIT =
	{ "Header Field", "dbus.field", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_dbus_hdr_field_code DBUS_HFI_INIT =
	{ "Field code", "dbus.field.code", FT_UINT8, BASE_DEC, VALS(field_code_vals), 0x00, NULL, HFILL };

static header_field_info hfi_dbus_type_signature DBUS_HFI_INIT =
	{ "Type signature", "dbus.type_signature", FT_STRINGZ, BASE_NONE, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_dbus_body DBUS_HFI_INIT =
	{ "Body", "dbus.body", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL };

/* Values */
static header_field_info hfi_dbus_value_bool DBUS_HFI_INIT =
	{ "Value", "dbus.value.bool", FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_dbus_value_int DBUS_HFI_INIT =
	{ "Value", "dbus.value.int", FT_INT32, BASE_DEC, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_dbus_value_uint DBUS_HFI_INIT =
	{ "Value", "dbus.value.uint", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_dbus_value_str DBUS_HFI_INIT =
	{ "Value", "dbus.value.str", FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_dbus_value_double DBUS_HFI_INIT =
	{ "Value", "dbus.value.double", FT_DOUBLE, BASE_NONE, NULL, 0x00, NULL, HFILL };


static int ett_dbus = -1;
static int ett_dbus_hdr = -1;
static int ett_dbus_body = -1;
static int ett_dbus_field = -1;

static expert_field ei_dbus_value_bool_invalid = EI_INIT;
static expert_field ei_dbus_value_str_invalid = EI_INIT;
static expert_field ei_dbus_invalid_object_path = EI_INIT;
static expert_field ei_dbus_invalid_signature = EI_INIT;

typedef struct {
	packet_info *pinfo;

	guint16 (*get16)(tvbuff_t *, const gint);
	guint32 (*get32)(tvbuff_t *, const gint);
	gdouble (*getdouble)(tvbuff_t *, const gint);
	int enc;

	guint32 body_len;
	guint32 fields_len;
	const char *body_sig;
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
dbus_type_alignment(char sig)
{
	switch (sig) {
		case 'y':
		case 'g':
			return 1;
		case 'n':
		case 'q':
			return 2;
		case 'i':
		case 'u':
		case 'b':
		case 'o':
		case 'a':
		case 's':
			return 4;
		case 'x':
		case 't':
		case 'd':
			return 8;
		/* ... */
		default:
			return 1;
	}
}

static int
dissect_dbus_sig(tvbuff_t *tvb, dbus_info_t *dinfo, proto_tree *tree, int offset, char sig, dbus_val_t *ret)
{
	proto_item *ti;
	const int align = dbus_type_alignment(sig);
	const int org_offset = (offset + align - 1) / align * align;
	offset = org_offset;

	switch (sig) {
		case 'y':	/* BYTE */
		{
			guint8 val;

			val = tvb_get_guint8(tvb, offset);
			offset += 1;

			proto_tree_add_uint_format(tree, hfi_dbus_value_uint.id, tvb, org_offset, offset - org_offset, val, "BYTE: %u", val);
			ret->uint = val;
			return offset;
		}

		case 'b':	/* BOOLEAN */
		{
			guint32 val;

			val = dinfo->get32(tvb, offset);
			offset += 4;

			ti = proto_tree_add_boolean_format(tree, hfi_dbus_value_bool.id, tvb, org_offset, offset - org_offset, val, "BOOLEAN: %s", val ? "True" : "False");
			if (val != 0 && val != 1) {
				expert_add_info_format(dinfo->pinfo, ti, &ei_dbus_value_bool_invalid, "Invalid boolean value (must be 0 or 1 is: %u)", val);
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

			proto_tree_add_uint_format(tree, hfi_dbus_value_int.id, tvb, org_offset, offset - org_offset, val, "INT16: %d", val);
			/* XXX ret */
			return offset;
		}

		case 'q':	/* UINT16 */
		{
			guint16 val;

			val = dinfo->get16(tvb, offset);
			offset += 2;

			proto_tree_add_uint_format(tree, hfi_dbus_value_uint.id, tvb, org_offset, offset - org_offset, val, "UINT16: %u", val);
			ret->uint = val;
			return offset;
		}

		case 'i':	/* INT32 */
		{
			gint32 val;

			val = (gint32) dinfo->get32(tvb, offset);
			offset += 4;

			proto_tree_add_int_format(tree, hfi_dbus_value_int.id, tvb, org_offset, offset - org_offset, val, "INT32: %d", val);
			/* XXX ret */
			return offset;
		}

		case 'u':	/* UINT32 */
		{
			guint32 val;

			val = dinfo->get32(tvb, offset);
			offset += 4;

			proto_tree_add_uint_format(tree, hfi_dbus_value_uint.id, tvb, org_offset, offset - org_offset, val, "UINT32: %u", val);
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

			proto_tree_add_double_format(tree, hfi_dbus_value_double.id, tvb, org_offset, offset - org_offset, val, "DOUBLE: %." G_STRINGIFY(DBL_DIG) "g", val);
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

			val = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, len, ENC_ASCII);
			offset += (len + 1 /* NUL-byte */);

			if (sig == 's') {
				ti = proto_tree_add_string_format(tree, hfi_dbus_value_str.id, tvb, org_offset, offset - org_offset, val, "STRING: %s", val);
				if (!g_utf8_validate(val, -1, NULL)) {
					expert_add_info(dinfo->pinfo, ti, &ei_dbus_value_str_invalid);
					return -1;
				}
			} else {
				ti = proto_tree_add_string_format(tree, hfi_dbus_value_str.id, tvb, org_offset, offset - org_offset, val, "OBJECT_PATH: %s", val);
				if (!dbus_validate_object_path(val)) {
					expert_add_info(dinfo->pinfo, ti, &ei_dbus_invalid_object_path);
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

			val = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, len, ENC_ASCII);
			offset += (len + 1);

			ti = proto_tree_add_string_format(tree, hfi_dbus_value_str.id, tvb, org_offset, offset - org_offset, val, "SIGNATURE: %s", val);
			if (!dbus_validate_signature(val)) {
				expert_add_info(dinfo->pinfo, ti, &ei_dbus_invalid_signature);
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
dissect_dbus_field_signature(tvbuff_t *tvb, packet_info *pinfo, dbus_info_t *dinfo, proto_tree *tree, int offset, int field_code)
{
	const int org_offset = offset;

	proto_item *ti;
	guint sig_len;
	char *sig;

	sig_len = tvb_get_guint8(tvb, offset);
	offset += 1;

	/* sig_len = tvb_strsize(tvb, offset); */

	sig = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, sig_len, ENC_ASCII);
	offset += (sig_len + 1);

	ti = proto_tree_add_string(tree, &hfi_dbus_type_signature, tvb, org_offset, offset - org_offset, sig);
	if (!dbus_validate_signature(sig)) {
		expert_add_info(dinfo->pinfo, ti, &ei_dbus_invalid_signature);
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
					set_address((field_code == DBUS_HEADER_FIELD_DESTINATION) ? &dinfo->pinfo->dst : &dinfo->pinfo->src,
					            AT_STRINGZ, (int)strlen(addr_val.str)+1, wmem_strdup(pinfo->pool, addr_val.str));
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
dissect_dbus_hdr_fields(tvbuff_t *tvb, packet_info *pinfo, dbus_info_t *dinfo, proto_tree *tree, int offset)
{
	int end_offset;

	end_offset = offset + dinfo->fields_len;

	while (offset < end_offset) {
		proto_tree *field_tree;
		proto_item *ti;

		guint8 field_code;

		ti = proto_tree_add_item(tree, &hfi_dbus_hdr_field, tvb, offset, 0, ENC_NA);
		field_tree = proto_item_add_subtree(ti, ett_dbus_field);

		field_code = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(field_tree, &hfi_dbus_hdr_field_code, tvb, offset, 1, dinfo->enc);
		proto_item_append_text(ti, ": %s", val_to_str(field_code, field_code_vals, "Unknown: %d"));
		offset += 1;

		offset = dissect_dbus_field_signature(tvb, pinfo, dinfo, field_tree, offset, field_code);
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

	ti = proto_tree_add_item(tree, &hfi_dbus_hdr, tvb, offset, 0, ENC_NA);
	hdr_tree = proto_item_add_subtree(ti, ett_dbus_hdr);

	proto_tree_add_item(hdr_tree, &hfi_dbus_hdr_endianness, tvb, offset, 1, ENC_ASCII | ENC_NA);
	offset += 1;

	type = tvb_get_guint8(tvb, offset);
	col_set_str(dinfo->pinfo->cinfo, COL_INFO, val_to_str_const(type, message_type_vals, ""));
	proto_tree_add_item(hdr_tree, &hfi_dbus_hdr_type, tvb, offset, 1, dinfo->enc);
	offset += 1;

	proto_tree_add_item(hdr_tree, &hfi_dbus_hdr_flags, tvb, offset, 1, dinfo->enc);
	offset += 1;

	proto_tree_add_item(hdr_tree, &hfi_dbus_hdr_version, tvb, offset, 1, dinfo->enc);
	offset += 1;

	dinfo->body_len = dinfo->get32(tvb, offset);
	proto_tree_add_item(hdr_tree, &hfi_dbus_hdr_body_length, tvb, offset, 4, dinfo->enc);
	offset += 4;

	proto_tree_add_item(hdr_tree, &hfi_dbus_hdr_serial, tvb, offset, 4, dinfo->enc);
	offset += 4;

	dinfo->fields_len = dinfo->get32(tvb, offset);
	proto_tree_add_item(hdr_tree, &hfi_dbus_hdr_fields_length, tvb, offset, 4, dinfo->enc);
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

		ti = proto_tree_add_item(tree, &hfi_dbus_body, tvb, offset, 0, ENC_NA);
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
		proto_item *ti = proto_tree_add_item(tree, hfi_dbus, tvb, 0, -1, ENC_NA);
		dbus_tree = proto_item_add_subtree(ti, ett_dbus);
	}

	offset = 0;
	offset = dissect_dbus_hdr(tvb, &dinfo, dbus_tree, offset);
	offset = dissect_dbus_hdr_fields(tvb, pinfo, &dinfo, dbus_tree, offset);
	/* header aligned to 8B */
	offset = (offset + 7) & ~7;

	if (!dinfo.body_sig)
		dinfo.body_sig = "";

	offset = dissect_dbus_body(tvb, &dinfo, dbus_tree, offset);

	return offset;
}

#define DBUS_HEADER_LEN 16

static guint
get_dbus_message_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                     int offset, void *data _U_)
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

static int
dissect_dbus_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	return dissect_dbus(tvb, pinfo, tree, data);
}

static int
dissect_dbus_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	tcp_dissect_pdus(tvb, pinfo, tree, dbus_desegment, DBUS_HEADER_LEN, get_dbus_message_len, dissect_dbus_pdu, data);
	return tvb_reported_length(tvb);
}

void
proto_register_dbus(void)
{
#ifndef HAVE_HFI_SECTION_INIT
	static header_field_info *hfi[] = {
	/* Header */
		&hfi_dbus_hdr,
		&hfi_dbus_hdr_endianness,
		&hfi_dbus_hdr_type,
		&hfi_dbus_hdr_flags,
		&hfi_dbus_hdr_version,
		&hfi_dbus_hdr_body_length,
		&hfi_dbus_hdr_serial,
		&hfi_dbus_hdr_fields_length,
	/* Header field */
		&hfi_dbus_hdr_field,
		&hfi_dbus_hdr_field_code,
		&hfi_dbus_type_signature,
		&hfi_dbus_body,
	/* Values */
		&hfi_dbus_value_bool,
		&hfi_dbus_value_int,
		&hfi_dbus_value_uint,
		&hfi_dbus_value_str,
		&hfi_dbus_value_double,
	};
#endif

	static gint *ett[] = {
		&ett_dbus,
		&ett_dbus_hdr,
		&ett_dbus_body,
		&ett_dbus_field
	};

	static ei_register_info ei[] = {
		{ &ei_dbus_value_bool_invalid, { "dbus.value.bool.invalid", PI_PROTOCOL, PI_WARN, "Invalid boolean value", EXPFILL }},
		{ &ei_dbus_value_str_invalid, { "dbus.value.str.invalid", PI_PROTOCOL, PI_WARN, "Invalid string (not UTF-8)", EXPFILL }},
		{ &ei_dbus_invalid_object_path, { "dbus.invalid_object_path", PI_PROTOCOL, PI_WARN, "Invalid object_path", EXPFILL }},
		{ &ei_dbus_invalid_signature, { "dbus.invalid_signature", PI_PROTOCOL, PI_WARN, "Invalid signature", EXPFILL }},
	};

	expert_module_t *expert_dbus;

	int proto_dbus;

	proto_dbus = proto_register_protocol("D-Bus", "D-BUS", "dbus");
	hfi_dbus = proto_registrar_get_nth(proto_dbus);

	proto_register_fields(proto_dbus, hfi, array_length(hfi));
	proto_register_subtree_array(ett, array_length(ett));
	expert_dbus = expert_register_protocol(proto_dbus);
	expert_register_field_array(expert_dbus, ei, array_length(ei));

	dbus_handle = create_dissector_handle(dissect_dbus, proto_dbus);
	dbus_handle_tcp = create_dissector_handle(dissect_dbus_tcp, proto_dbus);
}

void
proto_reg_handoff_dbus(void)
{
	dissector_add_uint("wtap_encap", WTAP_ENCAP_DBUS, dbus_handle);
	dissector_add_for_decode_as("tcp.port", dbus_handle_tcp);
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
