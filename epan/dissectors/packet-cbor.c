/* packet-cbor.c
 * Routines for Concise Binary Object Representation (CBOR) (RFC 7049) dissection
 * References:
 *     RFC 7049: https://tools.ietf.org/html/rfc7049
 *     RFC 8742: https://tools.ietf.org/html/rfc8742
 *
 * Copyright 2015, Hauke Mehrtens <hauke@hauke-m.de>
 * Copyright 2022, Stig Bjorlykke <stig@bjorlykke.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <math.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <wsutil/str_util.h>

void proto_register_cbor(void);
void proto_reg_handoff_cbor(void);

static int proto_cbor				= -1;

static int hf_cbor_item_major_type		= -1;
static int hf_cbor_item_integer_size		= -1;
static int hf_cbor_item_length_size		= -1;
static int hf_cbor_item_length5			= -1;
static int hf_cbor_item_length			= -1;
static int hf_cbor_item_items5			= -1;
static int hf_cbor_item_items			= -1;
static int hf_cbor_item_pairs5			= -1;
static int hf_cbor_item_pairs			= -1;
static int hf_cbor_item_float_simple_type	= -1;
static int hf_cbor_item_unsigned_integer	= -1;
static int hf_cbor_item_negative_integer	= -1;
static int hf_cbor_item_text_string		= -1;
static int hf_cbor_item_byte_string		= -1;
static int hf_cbor_item_array			= -1;
static int hf_cbor_item_map			= -1;
static int hf_cbor_item_tag			= -1;
static int hf_cbor_item_float_simple		= -1;
static int hf_cbor_type_uint5			= -1;
static int hf_cbor_type_uint			= -1;
static int hf_cbor_type_nint			= -1;
static int hf_cbor_type_byte_string		= -1;
static int hf_cbor_type_byte_string_indef	= -1;
static int hf_cbor_type_text_string		= -1;
static int hf_cbor_type_text_string_indef	= -1;
static int hf_cbor_type_tag5			= -1;
static int hf_cbor_type_tag			= -1;
static int hf_cbor_type_simple_data5		= -1;
static int hf_cbor_type_simple_data8		= -1;
static int hf_cbor_type_float16			= -1;
static int hf_cbor_type_float32			= -1;
static int hf_cbor_type_float64			= -1;

static gint ett_cbor				= -1;
static gint ett_cbor_type			= -1;
static gint ett_cbor_unsigned_integer		= -1;
static gint ett_cbor_negative_integer		= -1;
static gint ett_cbor_byte_string		= -1;
static gint ett_cbor_byte_string_indef		= -1;
static gint ett_cbor_text_string		= -1;
static gint ett_cbor_text_string_indef		= -1;
static gint ett_cbor_array			= -1;
static gint ett_cbor_map			= -1;
static gint ett_cbor_tag			= -1;
static gint ett_cbor_float_simple		= -1;

static expert_field ei_cbor_invalid_minor_type  = EI_INIT;
static expert_field ei_cbor_invalid_element     = EI_INIT;
static expert_field ei_cbor_too_long_length     = EI_INIT;

static dissector_handle_t cbor_handle;
static dissector_handle_t cborseq_handle;

#define CBOR_TYPE_USIGNED_INT   0
#define CBOR_TYPE_NEGATIVE_INT  1
#define CBOR_TYPE_BYTE_STRING   2
#define CBOR_TYPE_TEXT_STRING   3
#define CBOR_TYPE_ARRAY		4
#define CBOR_TYPE_MAP		5
#define CBOR_TYPE_TAGGED	6
#define CBOR_TYPE_FLOAT		7

static const value_string major_type_vals[] = {
	{ 0, "Unsigned Integer" },
	{ 1, "Negative Integer" },
	{ 2, "Byte String" },
	{ 3, "Text String" },
	{ 4, "Array" },
	{ 5, "Map" },
	{ 6, "Tagged" },
	{ 7, "Floating-Point or Simple" },
	{ 0, NULL }
};

static const value_string integer_size_vals[] = {
	{ 24, "1 byte" },
	{ 25, "2 bytes" },
	{ 26, "4 bytes" },
	{ 27, "8 bytes" },
	{ 28, "Reserved for future additions" },
	{ 29, "Reserved for future additions" },
	{ 30, "Reserved for future additions" },
	{ 31, "No argument value is derived" },
	{ 0, NULL }
};

static const value_string length_size_vals[] = {
	{ 24, "1 byte" },
	{ 25, "2 bytes" },
	{ 26, "4 bytes" },
	{ 27, "8 bytes" },
	{ 28, "Reserved for future additions" },
	{ 29, "Reserved for future additions" },
	{ 30, "Reserved for future additions" },
	{ 31, "Indefinite Length" },
	{ 0, NULL }
};

static const value_string float_simple_type_vals[] = {
	{ 24, "Simple value" },
	{ 25, "IEEE 754 Half-Precision Float" },
	{ 26, "IEEE 754 Single-Precision Float" },
	{ 27, "IEEE 754 Double-Precision Float" },
	{ 28, "Reserved for future additions" },
	{ 29, "Reserved for future additions" },
	{ 30, "Reserved for future additions" },
	{ 31, "Break indefinite length" },
	{ 0, NULL }
};

/* see https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml#tags */
static const value_string tag32_vals[] = {
	{ 0, "Standard date/time string" },
	{ 1, "Epoch-based date/time" },
	{ 2, "Positive bignum" },
	{ 3, "Negative bignum" },
	{ 4, "Decimal fraction" },
	{ 5, "Bigfloat" },
	{ 21, "Expected conversion to base64url encoding" },
	{ 22, "Expected conversion to base64 encoding" },
	{ 23, "Expected conversion to base16 encoding" },
	{ 24, "Encoded CBOR data item" },
	{ 25, "reference the nth previously seen string" },
	{ 26, "Serialised Perl object with classname and constructor arguments" },
	{ 27, "Serialised language-independent object with type name and constructor arguments" },
	{ 28, "mark value as (potentially) shared" },
	{ 29, "reference nth marked value" },
	{ 30, "Rational number" },
	{ 32, "URI" },
	{ 33, "base64url" },
	{ 34, "base64" },
	{ 35, "Regular expression" },
	{ 36, "MIME message" },
	{ 37, "Binary UUID" },
	{ 38, "Language-tagged string" },
	{ 39, "Identifier" },
	{ 256, "mark value as having string references" },
	{ 257, "Binary MIME message" },
	{ 264, "Decimal fraction with arbitrary exponent" },
	{ 265, "Bigfloat with arbitrary exponent" },
	{ 22098, "hint that indicates an additional level of indirection" },
	{ 55799, "Self-describe CBOR" },
	{ 0, NULL },
};

static const val64_string tag64_vals[] = {
	{ 0, "Standard date/time string" },
	{ 1, "Epoch-based date/time" },
	{ 2, "Positive bignum" },
	{ 3, "Negative bignum" },
	{ 4, "Decimal fraction" },
	{ 5, "Bigfloat" },
	{ 21, "Expected conversion to base64url encoding" },
	{ 22, "Expected conversion to base64 encoding" },
	{ 23, "Expected conversion to base16 encoding" },
	{ 24, "Encoded CBOR data item" },
	{ 25, "reference the nth previously seen string" },
	{ 26, "Serialised Perl object with classname and constructor arguments" },
	{ 27, "Serialised language-independent object with type name and constructor arguments" },
	{ 28, "mark value as (potentially) shared" },
	{ 29, "reference nth marked value" },
	{ 30, "Rational number" },
	{ 32, "URI" },
	{ 33, "base64url" },
	{ 34, "base64" },
	{ 35, "Regular expression" },
	{ 36, "MIME message" },
	{ 37, "Binary UUID" },
	{ 38, "Language-tagged string" },
	{ 39, "Identifier" },
	{ 256, "mark value as having string references" },
	{ 257, "Binary MIME message" },
	{ 264, "Decimal fraction with arbitrary exponent" },
	{ 265, "Bigfloat with arbitrary exponent" },
	{ 22098, "hint that indicates an additional level of indirection" },
	{ 55799, "Self-describe CBOR" },
	{ 0, NULL },
};

static const value_string vals_simple_data[] = {
	{ 20, "False" },
	{ 21, "True" },
	{ 22, "Null" },
	{ 23, "Undefined" },
	{ 0, NULL },
};

static gboolean
dissect_cbor_main_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *cbor_tree, gint *offset);

static gboolean
dissect_cbor_float_simple_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *cbor_tree, gint *offset, guint8 type_minor);

static gboolean
dissect_cbor_unsigned_integer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *cbor_tree, gint *offset, guint8 type_minor)
{
	guint64 value = 0;
	proto_item *item;
	proto_tree *subtree;

	item = proto_tree_add_item(cbor_tree, hf_cbor_item_unsigned_integer, tvb, *offset, -1, ENC_NA);
	subtree = proto_item_add_subtree(item, ett_cbor_unsigned_integer);

	proto_tree_add_item(subtree, hf_cbor_item_major_type, tvb, *offset, 1, ENC_BIG_ENDIAN);
	if (type_minor <= 0x17) {
		proto_tree_add_item(subtree, hf_cbor_type_uint5, tvb, *offset, 1, ENC_BIG_ENDIAN);
		value = type_minor;
	} else {
		proto_tree_add_item(subtree, hf_cbor_item_integer_size, tvb, *offset, 1, ENC_BIG_ENDIAN);
	}
	*offset += 1;

	switch (type_minor) {
	case 0x18:
		proto_tree_add_item_ret_uint64(subtree, hf_cbor_type_uint, tvb, *offset, 1, ENC_BIG_ENDIAN, &value);
		*offset += 1;
		break;
	case 0x19:
		proto_tree_add_item_ret_uint64(subtree, hf_cbor_type_uint, tvb, *offset, 2, ENC_BIG_ENDIAN, &value);
		*offset += 2;
		break;
	case 0x1a:
		proto_tree_add_item_ret_uint64(subtree, hf_cbor_type_uint, tvb, *offset, 4, ENC_BIG_ENDIAN, &value);
		*offset += 4;
		break;
	case 0x1b:
		proto_tree_add_item_ret_uint64(subtree, hf_cbor_type_uint, tvb, *offset, 8, ENC_BIG_ENDIAN, &value);
		*offset += 8;
		break;
	default:
		if (type_minor > 0x17) {
			expert_add_info_format(pinfo, subtree, &ei_cbor_invalid_minor_type,
					"invalid minor type %i in unsigned integer", type_minor);
			return FALSE;
		}
		break;
	}

	proto_item_append_text(item, ": %" PRIu64, value);
	proto_item_set_end(item, tvb, *offset);

	return TRUE;
}

static gboolean
dissect_cbor_negative_integer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *cbor_tree, gint *offset, guint8 type_minor)
{
	gint64  value = 0;
	proto_item *item;
	proto_tree *subtree;

	item = proto_tree_add_item(cbor_tree, hf_cbor_item_negative_integer, tvb, *offset, -1, ENC_NA);
	subtree = proto_item_add_subtree(item, ett_cbor_negative_integer);

	proto_tree_add_item(subtree, hf_cbor_item_major_type, tvb, *offset, 1, ENC_BIG_ENDIAN);
	if (type_minor <= 0x17) {
		value = (gint64)-1 - type_minor;
		/* Keep correct bit representation with a modified value. */
		proto_tree_add_int64_bits_format_value(subtree, hf_cbor_type_nint, tvb, 3, 5, type_minor, ENC_BIG_ENDIAN, "%" PRId64, value);
	} else {
		proto_tree_add_item(subtree, hf_cbor_item_integer_size, tvb, *offset, 1, ENC_BIG_ENDIAN);
	}
	*offset += 1;

	switch (type_minor) {
	case 0x18:
		value = (gint64)-1 - tvb_get_guint8(tvb, *offset);
		proto_tree_add_int64(subtree, hf_cbor_type_nint, tvb, *offset, 1, value);
		*offset += 1;
		break;
	case 0x19:
		value = (gint64)-1 - tvb_get_ntohs(tvb, *offset);
		proto_tree_add_int64(subtree, hf_cbor_type_nint, tvb, *offset, 2, value);
		*offset += 2;
		break;
	case 0x1a:
		value = (gint64)-1 - tvb_get_ntohl(tvb, *offset);
		proto_tree_add_int64(subtree, hf_cbor_type_nint, tvb, *offset, 4, value);
		*offset += 4;
		break;
	case 0x1b:
		/* TODO: an overflow could happen here, for negative int < G_MININT64 */
		value = (gint64)-1 - tvb_get_ntoh64(tvb, *offset);
		if (value > -1) {
			expert_add_info_format(pinfo, subtree, &ei_cbor_too_long_length,
				"The value is too small, Wireshark can not display it correctly");
		}
		proto_tree_add_int64(subtree, hf_cbor_type_nint, tvb, *offset, 8, value);
		*offset += 8;
		break;
	default:
		if (type_minor > 0x17) {
			expert_add_info_format(pinfo, subtree, &ei_cbor_invalid_minor_type,
					"invalid minor type %i in negative integer", type_minor);
			return FALSE;
		}
		break;
	}

	proto_item_append_text(item, ": %" PRId64, value);
	proto_item_set_end(item, tvb, *offset);

	return TRUE;
}

static gboolean
dissect_cbor_byte_string(tvbuff_t *tvb, packet_info *pinfo, proto_tree *cbor_tree, gint *offset, guint8 type_minor)
{
	guint64  length;
	gint     eof_type;
	proto_tree *subtree;
	proto_item *item;

	item = proto_tree_add_item(cbor_tree, hf_cbor_item_byte_string, tvb, *offset, -1, ENC_NA);
	subtree = proto_item_add_subtree(item, ett_cbor_byte_string);

	proto_tree_add_item(subtree, hf_cbor_item_major_type, tvb, *offset, 1, ENC_BIG_ENDIAN);
	if (type_minor <= 0x17) {
		proto_tree_add_item(subtree, hf_cbor_item_length5, tvb, *offset, 1, ENC_BIG_ENDIAN);
		length = type_minor;
	} else {
		proto_tree_add_item(subtree, hf_cbor_item_length_size, tvb, *offset, 1, ENC_BIG_ENDIAN);
	}
	*offset += 1;

	switch (type_minor) {
	case 0x18:
		proto_tree_add_item_ret_uint64(subtree, hf_cbor_item_length, tvb, *offset, 1, ENC_BIG_ENDIAN, &length);
		*offset += 1;
		break;
	case 0x19:
		proto_tree_add_item_ret_uint64(subtree, hf_cbor_item_length, tvb, *offset, 2, ENC_BIG_ENDIAN, &length);
		*offset += 2;
		break;
	case 0x1a:
		proto_tree_add_item_ret_uint64(subtree, hf_cbor_item_length, tvb, *offset, 4, ENC_BIG_ENDIAN, &length);
		*offset += 4;
		break;
	case 0x1b:
		proto_tree_add_item_ret_uint64(subtree, hf_cbor_item_length, tvb, *offset, 8, ENC_BIG_ENDIAN, &length);
		*offset += 8;
		break;
	case 0x1f:
		proto_item_append_text(item, ": (indefinite length)");
		item = proto_tree_add_item(subtree, hf_cbor_type_byte_string_indef, tvb, *offset, 1, ENC_NA);
		subtree = proto_item_add_subtree(item, ett_cbor_byte_string_indef);
		while (1) {
			eof_type = tvb_get_guint8(tvb, *offset);
			if (eof_type == 0xff) {
				dissect_cbor_float_simple_data(tvb, pinfo, subtree, offset, 0x1f);
				proto_item_set_end(item, tvb, *offset);
				return TRUE;
			}

			if (((eof_type & 0xe0) >> 5) != CBOR_TYPE_BYTE_STRING) {
				expert_add_info_format(pinfo, subtree, &ei_cbor_invalid_element,
					"invalid element %i, expected byte string", (eof_type & 0xe0) >> 5);
				return FALSE;
			}

			if (!dissect_cbor_byte_string(tvb, pinfo, subtree, offset, eof_type & 0x1f)) {
				return FALSE;
			}
		}
		DISSECTOR_ASSERT_NOT_REACHED();
		return FALSE;
	default:
		if (type_minor > 0x17) {
			expert_add_info_format(pinfo, subtree, &ei_cbor_invalid_minor_type,
					"invalid minor type %i in byte string", type_minor);
			return FALSE;
		}
		break;
	}

	if (length > G_MAXINT32 || *offset + (gint)length < *offset) {
		expert_add_info_format(pinfo, subtree, &ei_cbor_too_long_length,
			"the length (%" PRIu64 ") of the byte string too long", length);
		return FALSE;
	}

	proto_tree_add_item(subtree, hf_cbor_type_byte_string, tvb, *offset, (gint)length, ENC_BIG_ENDIAN|ENC_NA);
	*offset += (gint)length;

	proto_item_append_text(item, ": (%" PRIu64 " byte%s)", length, plurality(length, "", "s"));
	proto_item_set_end(item, tvb, *offset);

	return TRUE;
}

static gboolean
dissect_cbor_text_string(tvbuff_t *tvb, packet_info *pinfo, proto_tree *cbor_tree, gint *offset, guint8 type_minor)
{
	const guint8 *value = NULL;
	guint64  length = 0;
	gint     eof_type;
	proto_tree *subtree;
	proto_item *item;

	item = proto_tree_add_item(cbor_tree, hf_cbor_item_text_string, tvb, *offset, -1, ENC_NA);
	subtree = proto_item_add_subtree(item, ett_cbor_text_string);

	proto_tree_add_item(subtree, hf_cbor_item_major_type, tvb, *offset, 1, ENC_BIG_ENDIAN);
	if (type_minor <= 0x17) {
		proto_tree_add_item(subtree, hf_cbor_item_length5, tvb, *offset, 1, ENC_BIG_ENDIAN);
		length = type_minor;
	} else {
		proto_tree_add_item(subtree, hf_cbor_item_length_size, tvb, *offset, 1, ENC_BIG_ENDIAN);
	}
	*offset += 1;

	switch (type_minor) {
	case 0x18:
		proto_tree_add_item_ret_uint64(subtree, hf_cbor_item_length, tvb, *offset, 1, ENC_BIG_ENDIAN, &length);
		*offset += 1;
		break;
	case 0x19:
		proto_tree_add_item_ret_uint64(subtree, hf_cbor_item_length, tvb, *offset, 2, ENC_BIG_ENDIAN, &length);
		*offset += 2;
		break;
	case 0x1a:
		proto_tree_add_item_ret_uint64(subtree, hf_cbor_item_length, tvb, *offset, 4, ENC_BIG_ENDIAN, &length);
		*offset += 4;
		break;
	case 0x1b:
		proto_tree_add_item_ret_uint64(subtree, hf_cbor_item_length, tvb, *offset, 8, ENC_BIG_ENDIAN, &length);
		*offset += 8;
		break;
	case 0x1f:
		proto_item_append_text(item, ": (indefinite length)");
		item = proto_tree_add_item(subtree, hf_cbor_type_text_string_indef, tvb, *offset, 1, ENC_NA);
		subtree = proto_item_add_subtree(item, ett_cbor_text_string_indef);
		while (1) {
			eof_type = tvb_get_guint8(tvb, *offset);
			if (eof_type == 0xff) {
				dissect_cbor_float_simple_data(tvb, pinfo, subtree, offset, 0x1f);
				proto_item_set_end(item, tvb, *offset);
				return TRUE;
			}

			if (((eof_type & 0xe0) >> 5) != CBOR_TYPE_TEXT_STRING) {
				expert_add_info_format(pinfo, subtree, &ei_cbor_invalid_element,
					"invalid element %i, expected text string", (eof_type & 0xe0) >> 5);
				return FALSE;
			}

			if (!dissect_cbor_text_string(tvb, pinfo, subtree, offset, eof_type & 0x1f)) {
				return FALSE;
			}
		}
		DISSECTOR_ASSERT_NOT_REACHED();
		return FALSE;
	default:
		if (type_minor > 0x17) {
			expert_add_info_format(pinfo, subtree, &ei_cbor_invalid_minor_type,
					"invalid minor type %i in text string", type_minor);
			return FALSE;
		}
		break;
	}

	if (length > G_MAXINT32 || *offset + (gint)length < *offset) {
		expert_add_info_format(pinfo, subtree, &ei_cbor_too_long_length,
			"the length (%" PRIu64 ") of the text string too long", length);
		return FALSE;
	}

	proto_tree_add_item_ret_string(subtree, hf_cbor_type_text_string, tvb, *offset, (gint)length, ENC_BIG_ENDIAN|ENC_UTF_8, pinfo->pool, &value);
	*offset += (gint)length;

	proto_item_append_text(item, ": %s", value);
	proto_item_set_end(item, tvb, *offset);

	return TRUE;
}

static gboolean
dissect_cbor_array(tvbuff_t *tvb, packet_info *pinfo, proto_tree *cbor_tree, gint *offset, guint8 type_minor)
{
	guint64  length = 0;
	proto_tree *subtree;
	proto_item *item;
	gboolean    indefinite = FALSE;

	item = proto_tree_add_item(cbor_tree, hf_cbor_item_array, tvb, *offset, -1, ENC_NA);
	subtree = proto_item_add_subtree(item, ett_cbor_array);

	proto_tree_add_item(subtree, hf_cbor_item_major_type, tvb, *offset, 1, ENC_BIG_ENDIAN);

	if (type_minor <= 0x17) {
		proto_tree_add_item(subtree, hf_cbor_item_items5, tvb, *offset, 1, ENC_BIG_ENDIAN);
		length = type_minor;
	} else {
		proto_tree_add_item(subtree, hf_cbor_item_length_size, tvb, *offset, 1, ENC_BIG_ENDIAN);
	}
	*offset += 1;

	switch (type_minor) {
	case 0x18:
		proto_tree_add_item_ret_uint64(subtree, hf_cbor_item_items, tvb, *offset, 1, ENC_BIG_ENDIAN, &length);
		*offset += 1;
		break;
	case 0x19:
		proto_tree_add_item_ret_uint64(subtree, hf_cbor_item_items, tvb, *offset, 2, ENC_BIG_ENDIAN, &length);
		*offset += 2;
		break;
	case 0x1a:
		proto_tree_add_item_ret_uint64(subtree, hf_cbor_item_items, tvb, *offset, 4, ENC_BIG_ENDIAN, &length);
		*offset += 4;
		break;
	case 0x1b:
		proto_tree_add_item_ret_uint64(subtree, hf_cbor_item_items, tvb, *offset, 8, ENC_BIG_ENDIAN, &length);
		*offset += 8;
		break;
	case 0x1f:
		length = INT_MAX;
		indefinite = TRUE;
		break;
	default:
		if (type_minor > 0x17) {
			expert_add_info_format(pinfo, subtree, &ei_cbor_invalid_minor_type,
					"invalid minor type %i in array", type_minor);
			return FALSE;
		}
		break;
	}

	for (guint64 i = 0; i < length; i++) {
		if (indefinite) {
			gint value = tvb_get_guint8(tvb, *offset);
			if (value == 0xff) {
				dissect_cbor_float_simple_data(tvb, pinfo, subtree, offset, 0x1f);
				break;
			}
		}

		if (!dissect_cbor_main_type(tvb, pinfo, subtree, offset)) {
			return FALSE;
		}
	}

	if (indefinite) {
		proto_item_append_text(item, ": (indefinite length)");
	} else {
		proto_item_append_text(item, ": (%" PRIu64 " item%s)", length, plurality(length, "", "s"));
	}
	proto_item_set_end(item, tvb, *offset);

	return TRUE;
}

static gboolean
dissect_cbor_map(tvbuff_t *tvb, packet_info *pinfo, proto_tree *cbor_tree, gint *offset, guint8 type_minor)
{
	guint64     length = 0;
	proto_tree *subtree;
	proto_item *item;
	gboolean    indefinite = FALSE;

	item = proto_tree_add_item(cbor_tree, hf_cbor_item_map, tvb, *offset, -1, ENC_NA);
	subtree = proto_item_add_subtree(item, ett_cbor_map);

	proto_tree_add_item(subtree, hf_cbor_item_major_type, tvb, *offset, 1, ENC_BIG_ENDIAN);

	if (type_minor <= 0x17) {
		proto_tree_add_item(subtree, hf_cbor_item_pairs5, tvb, *offset, 1, ENC_BIG_ENDIAN);
		length = type_minor;
	} else {
		proto_tree_add_item(subtree, hf_cbor_item_length_size, tvb, *offset, 1, ENC_BIG_ENDIAN);
	}
	*offset += 1;

	switch (type_minor) {
	case 0x18:
		proto_tree_add_item_ret_uint64(subtree, hf_cbor_item_pairs, tvb, *offset, 1, ENC_BIG_ENDIAN, &length);
		*offset += 1;
		break;
	case 0x19:
		proto_tree_add_item_ret_uint64(subtree, hf_cbor_item_pairs, tvb, *offset, 2, ENC_BIG_ENDIAN, &length);
		*offset += 2;
		break;
	case 0x1a:
		proto_tree_add_item_ret_uint64(subtree, hf_cbor_item_pairs, tvb, *offset, 4, ENC_BIG_ENDIAN, &length);
		*offset += 4;
		break;
	case 0x1b:
		proto_tree_add_item_ret_uint64(subtree, hf_cbor_item_pairs, tvb, *offset, 8, ENC_BIG_ENDIAN, &length);
		*offset += 8;
		break;
	case 0x1f:
		length = INT_MAX;
		indefinite = TRUE;
		break;
	default:
		if (type_minor > 0x17) {
			expert_add_info_format(pinfo, subtree, &ei_cbor_invalid_minor_type,
					"invalid minor type %i in map", type_minor);
			return FALSE;
		}
		break;
	}

	for (guint64 i = 0; i < length; i++) {
		if (indefinite) {
			gint value = tvb_get_guint8(tvb, *offset);
			if (value == 0xff) {
				dissect_cbor_float_simple_data(tvb, pinfo, subtree, offset, 0x1f);
				break;
			}
		}

		if (!dissect_cbor_main_type(tvb, pinfo, subtree, offset)) {
			return FALSE;
		}

		if (!dissect_cbor_main_type(tvb, pinfo, subtree, offset)) {
			return FALSE;
		}
	}

	if (indefinite) {
		proto_item_append_text(item, ": (indefinite length)");
	} else {
		proto_item_append_text(item, ": (%" PRIu64 " pair%s)", length, plurality(length, "", "s"));
	}
	proto_item_set_end(item, tvb, *offset);

	return TRUE;
}

static gboolean
dissect_cbor_tag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *cbor_tree, gint *offset, guint8 type_minor)
{
	guint64          tag = 0;
	proto_item      *item;
	proto_tree      *subtree;

	item = proto_tree_add_item(cbor_tree, hf_cbor_item_tag, tvb, *offset, -1, ENC_NA);
	subtree = proto_item_add_subtree(item, ett_cbor_tag);

	proto_tree_add_item(subtree, hf_cbor_item_major_type, tvb, *offset, 1, ENC_BIG_ENDIAN);

	if (type_minor <= 0x17) {
		proto_tree_add_item(subtree, hf_cbor_type_tag5, tvb, *offset, 1, ENC_BIG_ENDIAN);
		tag = type_minor;
	} else {
		proto_tree_add_item(subtree, hf_cbor_item_integer_size, tvb, *offset, 1, ENC_BIG_ENDIAN);
	}
	*offset += 1;

	switch (type_minor) {
	case 0x18:
		proto_tree_add_item_ret_uint64(subtree, hf_cbor_type_tag, tvb, *offset, 1, ENC_BIG_ENDIAN, &tag);
		*offset += 1;
		break;
	case 0x19:
		proto_tree_add_item_ret_uint64(subtree, hf_cbor_type_tag, tvb, *offset, 2, ENC_BIG_ENDIAN, &tag);
		*offset += 2;
		break;
	case 0x1a:
		proto_tree_add_item_ret_uint64(subtree, hf_cbor_type_tag, tvb, *offset, 4, ENC_BIG_ENDIAN, &tag);
		*offset += 4;
		break;
	case 0x1b:
		proto_tree_add_item_ret_uint64(subtree, hf_cbor_type_tag, tvb, *offset, 8, ENC_BIG_ENDIAN, &tag);
		*offset += 8;
		break;
	default:
		if (type_minor > 0x17) {
			expert_add_info_format(pinfo, subtree, &ei_cbor_invalid_minor_type,
					"invalid minor type %i in tag", type_minor);
			return FALSE;
		}
		break;
	}

	if (!dissect_cbor_main_type(tvb, pinfo, subtree, offset)) {
		return FALSE;
	}

	proto_item_append_text(item, ": %s (%" PRIu64 ")", val64_to_str(tag, tag64_vals, "Unknown"), tag);
	proto_item_set_end(item, tvb, *offset);

	return TRUE;
}

/* based on code from rfc7049 appendix-D */
static void
decode_half(tvbuff_t *tvb, proto_tree *tree, proto_item *item, gint *offset, int hfindex)
{
	gchar value[6];
	int half, exponent, mantissa;
	float val = 0;

	half = tvb_get_ntohs(tvb, *offset);
	exponent = (half >> 10) & 0x1f;
	mantissa = half & 0x3ff;

	if (exponent == 0) {
		val = ldexpf((float)mantissa, -24);
		if (half & 0x8000) {
			val = -val;
		}
		proto_tree_add_float(tree, hfindex, tvb, *offset, 2, val);
		proto_item_set_text(item, "Float: %." G_STRINGIFY(FLT_DIG) "g", val);
	} else if (exponent != 31) {
		val = ldexpf((float)(mantissa + 1024), exponent - 25);
		if (half & 0x8000) {
			val = -val;
		}
		proto_tree_add_float(tree, hfindex, tvb, *offset, 2, val);
		proto_item_set_text(item, "Float: %." G_STRINGIFY(FLT_DIG) "g", val);
	} else {
		snprintf(value, sizeof(value), "%s%s", half & 0x8000 ? "-" : "", mantissa == 0 ? "inf" : "nan");
		proto_tree_add_float_format_value(tree, hfindex, tvb, *offset, 2, 0, "%s", value);
		proto_item_set_text(item, "Float: %s", value);
	}
}

static gboolean
dissect_cbor_float_simple_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *cbor_tree, gint *offset, guint8 type_minor)
{
	guint32          simple;
	float            f_value;
	double           d_value;
	proto_item      *item;
	proto_tree      *subtree;

	item = proto_tree_add_item(cbor_tree, hf_cbor_item_float_simple, tvb, *offset, -1, ENC_NA);
	subtree = proto_item_add_subtree(item, ett_cbor_float_simple);

	proto_tree_add_item(subtree, hf_cbor_item_major_type, tvb, *offset, 1, ENC_BIG_ENDIAN);

	if (type_minor <= 0x17) {
		proto_tree_add_item_ret_uint(subtree, hf_cbor_type_simple_data5, tvb, *offset, 1, ENC_BIG_ENDIAN, &simple);
		proto_item_set_text(item, "Simple: %s (%u)", val_to_str(simple, vals_simple_data, "Unknown"), simple);
	} else {
		proto_tree_add_item(subtree, hf_cbor_item_float_simple_type, tvb, *offset, 1, ENC_BIG_ENDIAN);
	}
	*offset += 1;

	switch (type_minor) {
	case 0x18:
		proto_tree_add_item_ret_uint(subtree, hf_cbor_type_simple_data8, tvb, *offset, 1, ENC_BIG_ENDIAN, &simple);
		proto_item_set_text(item, "Simple: %s (%u)", val_to_str(simple, vals_simple_data, "Unknown"), simple);
		*offset += 1;
		break;
	case 0x19:
		decode_half(tvb, subtree, item, offset, hf_cbor_type_float16);
		*offset += 2;
		break;
	case 0x1a:
		f_value = tvb_get_ntohieee_float(tvb, *offset);
		proto_tree_add_item(subtree, hf_cbor_type_float32, tvb, *offset, 4, ENC_BIG_ENDIAN);
		proto_item_set_text(item, "Float: %." G_STRINGIFY(FLT_DIG) "g", f_value);
		*offset += 4;
		break;
	case 0x1b:
		d_value = tvb_get_ntohieee_double(tvb, *offset);
		proto_tree_add_item(subtree, hf_cbor_type_float64, tvb, *offset, 8, ENC_BIG_ENDIAN);
		proto_item_set_text(item, "Float: %." G_STRINGIFY(DBL_DIG) "g", d_value);
		*offset += 8;
		break;
	case 0x1f:
		proto_item_set_text(item, "Break indefinite length (%u)", type_minor);
		break;
	default:
		if (type_minor > 0x17) {
			expert_add_info_format(pinfo, subtree, &ei_cbor_invalid_minor_type,
					"invalid minor type %i in simple data and float", type_minor);
			return FALSE;
		}
		break;
	}

	proto_item_set_end(item, tvb, *offset);

	return TRUE;
}


static gboolean
dissect_cbor_main_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *cbor_tree, gint *offset)
{
	guint8      type;
	guint8      type_major;
	guint8      type_minor;

	type = tvb_get_guint8(tvb, *offset);

	type_major = (type & 0xe0) >> 5;
	type_minor = (type & 0x1f);

	switch (type_major) {
	case CBOR_TYPE_USIGNED_INT:
		return dissect_cbor_unsigned_integer(tvb, pinfo, cbor_tree, offset, type_minor);
	case CBOR_TYPE_NEGATIVE_INT:
		return dissect_cbor_negative_integer(tvb, pinfo, cbor_tree, offset, type_minor);
	case CBOR_TYPE_BYTE_STRING:
		return dissect_cbor_byte_string(tvb, pinfo, cbor_tree, offset, type_minor);
	case CBOR_TYPE_TEXT_STRING:
		return dissect_cbor_text_string(tvb, pinfo, cbor_tree, offset, type_minor);
	case CBOR_TYPE_ARRAY:
		return dissect_cbor_array(tvb, pinfo, cbor_tree, offset, type_minor);
	case CBOR_TYPE_MAP:
		return dissect_cbor_map(tvb, pinfo, cbor_tree, offset, type_minor);
	case CBOR_TYPE_TAGGED:
		return dissect_cbor_tag(tvb, pinfo, cbor_tree, offset, type_minor);
	case CBOR_TYPE_FLOAT:
		return dissect_cbor_float_simple_data(tvb, pinfo, cbor_tree, offset, type_minor);
	}

	DISSECTOR_ASSERT_NOT_REACHED();
	return FALSE;
}

static int
dissect_cbor(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
	gint        offset = 0;
	proto_item *cbor_root;
	proto_tree *cbor_tree;

	cbor_root = proto_tree_add_item(parent_tree, proto_cbor, tvb, offset, -1, ENC_NA);
	cbor_tree = proto_item_add_subtree(cbor_root, ett_cbor);
	dissect_cbor_main_type(tvb, pinfo, cbor_tree, &offset);

	proto_item_set_len(cbor_root, offset);
	return offset;
}

static int
dissect_cborseq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
	gint        offset = 0;
	proto_item *cbor_root;
	proto_tree *cbor_tree;

	cbor_root = proto_tree_add_item(parent_tree, proto_cbor, tvb, offset, -1, ENC_NA);
	proto_item_append_text(cbor_root, " Sequence");
	cbor_tree = proto_item_add_subtree(cbor_root, ett_cbor);
	while ((guint)offset < tvb_reported_length(tvb)) {
		if (!dissect_cbor_main_type(tvb, pinfo, cbor_tree, &offset)) {
			break;
		}
	}

	return offset;
}

void
proto_register_cbor(void)
{
	static hf_register_info hf[] = {
		{ &hf_cbor_item_major_type,
		  { "Major Type", "cbor.item.major_type",
		    FT_UINT8, BASE_DEC, VALS(major_type_vals), 0xe0,
		    NULL, HFILL }
		},
		{ &hf_cbor_item_integer_size,
		  { "Size", "cbor.item.size",
		    FT_UINT8, BASE_DEC, VALS(integer_size_vals), 0x1f,
		    NULL, HFILL }
		},
		{ &hf_cbor_item_length_size,
		  { "Size", "cbor.item.size",
		    FT_UINT8, BASE_DEC, VALS(length_size_vals), 0x1f,
		    NULL, HFILL }
		},
		{ &hf_cbor_item_length5,
		  { "Length", "cbor.item.length",
		    FT_UINT8, BASE_DEC, NULL, 0x1f,
		    NULL, HFILL }
		},
		{ &hf_cbor_item_length,
		  { "Length", "cbor.item.length",
		    FT_UINT64, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_cbor_item_items5,
		  { "Items", "cbor.item.items",
		    FT_UINT8, BASE_DEC, NULL, 0x1f,
		    NULL, HFILL }
		},
		{ &hf_cbor_item_items,
		  { "Items", "cbor.item.length",
		    FT_UINT64, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_cbor_item_pairs5,
		  { "Pairs", "cbor.item.pairs",
		    FT_UINT8, BASE_DEC, NULL, 0x1f,
		    NULL, HFILL }
		},
		{ &hf_cbor_item_pairs,
		  { "Pairs", "cbor.item.pairs",
		    FT_UINT64, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_cbor_item_float_simple_type,
		  { "Type", "cbor.item.float_simple_type",
		    FT_UINT8, BASE_DEC, VALS(float_simple_type_vals), 0x1f,
		    NULL, HFILL }
		},
		{ &hf_cbor_item_unsigned_integer,
		  { "Unsigned Integer", "cbor.item.unsigned_integer",
		    FT_NONE, BASE_NONE, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_cbor_item_negative_integer,
		  { "Negative Integer", "cbor.item.negative_integer",
		    FT_NONE, BASE_NONE, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_cbor_item_text_string,
		  { "Text String", "cbor.item.textstring",
		    FT_NONE, BASE_NONE, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_cbor_item_byte_string,
		  { "Byte String", "cbor.item.bytestring",
		    FT_NONE, BASE_NONE, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_cbor_item_array,
		  { "Array", "cbor.item.array",
		    FT_NONE, BASE_NONE, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_cbor_item_map,
		  { "Map", "cbor.item.map",
		    FT_NONE, BASE_NONE, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_cbor_item_tag,
		  { "Tag", "cbor.item.tag",
		    FT_NONE, BASE_NONE, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_cbor_item_float_simple,
		  { "Floating-point or Simple", "cbor.item.float_or_simple",
		    FT_NONE, BASE_NONE, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_cbor_type_uint5,
		  { "Unsigned Integer", "cbor.type.uint",
		    FT_UINT8, BASE_DEC, NULL, 0x1f,
		    NULL, HFILL }
		},
		{ &hf_cbor_type_uint,
		  { "Unsigned Integer", "cbor.type.uint",
		    FT_UINT64, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_cbor_type_nint,
		  { "Negative Integer", "cbor.type.nint",
		    FT_INT64, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_cbor_type_byte_string,
		  { "Byte String", "cbor.type.bytestring",
		    FT_BYTES, BASE_NONE, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_cbor_type_byte_string_indef,
		  { "Byte String (indefinite length)", "cbor.type.bytestring.indef",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_cbor_type_text_string,
		  { "Text String", "cbor.type.textstring",
		    FT_STRING, BASE_NONE, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_cbor_type_text_string_indef,
		  { "Text String (indefinite length)", "cbor.type.textstring.indef",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_cbor_type_tag5,
		  { "Tag", "cbor.type.tag",
		    FT_UINT8, BASE_DEC, VALS(tag32_vals), 0x1f,
		    NULL, HFILL }
		},
		{ &hf_cbor_type_tag,
		  { "Tag", "cbor.type.tag",
		    FT_UINT64, BASE_DEC|BASE_VAL64_STRING, VALS64(tag64_vals), 0x00,
		    NULL, HFILL }
		},
		{ &hf_cbor_type_simple_data5,
		  { "Simple data", "cbor.type.simple_data",
		    FT_UINT8, BASE_DEC, VALS(vals_simple_data), 0x1f,
		    NULL, HFILL }
		},
		{ &hf_cbor_type_simple_data8,
		  { "Simple data", "cbor.type.simple_data",
		    FT_UINT8, BASE_DEC, VALS(vals_simple_data), 0x00,
		    NULL, HFILL }
		},
		{ &hf_cbor_type_float16,
		  { "Float 16 Bit", "cbor.type.float16",
		    FT_FLOAT, BASE_NONE, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_cbor_type_float32,
		  { "Float 32 Bit", "cbor.type.float32",
		    FT_FLOAT, BASE_NONE, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_cbor_type_float64,
		  { "Float 64 Bit", "cbor.type.float64",
		    FT_DOUBLE, BASE_NONE, NULL, 0x00,
		    NULL, HFILL }
		},
	};

	static gint *ett[] = {
		&ett_cbor,
		&ett_cbor_type,
		&ett_cbor_unsigned_integer,
		&ett_cbor_negative_integer,
		&ett_cbor_byte_string,
		&ett_cbor_byte_string_indef,
		&ett_cbor_text_string,
		&ett_cbor_text_string_indef,
		&ett_cbor_array,
		&ett_cbor_map,
		&ett_cbor_tag,
		&ett_cbor_float_simple
	};

	static ei_register_info ei[] = {
		{ &ei_cbor_invalid_minor_type,
		  { "cbor.invalid_minor_type", PI_MALFORMED, PI_WARN, "Invalid minor type", EXPFILL }},
		{ &ei_cbor_invalid_element,
		  { "cbor.invalid_element", PI_MALFORMED, PI_WARN, "Invalid element", EXPFILL }},
		{ &ei_cbor_too_long_length,
		  { "cbor.too_long_length", PI_MALFORMED, PI_WARN, "Too long length", EXPFILL }},
	};

	expert_module_t *expert_cbor;

	proto_cbor = proto_register_protocol("Concise Binary Object Representation", "CBOR", "cbor");
	proto_register_field_array(proto_cbor, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_cbor = expert_register_protocol(proto_cbor);
	expert_register_field_array(expert_cbor, ei, array_length(ei));

	cbor_handle = register_dissector("cbor", dissect_cbor, proto_cbor);
	cborseq_handle = register_dissector("cborseq", dissect_cborseq, proto_cbor);
}

void
proto_reg_handoff_cbor(void)
{
	dissector_add_string("media_type", "application/cbor", cbor_handle); /* RFC 7049 */
	dissector_add_string("media_type", "application/senml+cbor", cbor_handle); /* RFC 8428 */
	dissector_add_string("media_type", "application/sensml+cbor", cbor_handle); /* RFC 8428 */
	dissector_add_string("media_type", "application/cbor-seq", cborseq_handle); /* RFC 8742 */
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
