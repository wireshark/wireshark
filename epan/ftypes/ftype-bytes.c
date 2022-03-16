/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <ftypes-int.h>
#include <string.h>
#include <epan/addr_resolv.h>
#include <epan/strutil.h>
#include <epan/oids.h>
#include <epan/osi-utils.h>
#include <epan/to_str.h>

static void
bytes_fvalue_new(fvalue_t *fv)
{
	fv->value.bytes = NULL;
}

static void
bytes_fvalue_free(fvalue_t *fv)
{
	if (fv->value.bytes) {
		g_byte_array_free(fv->value.bytes, TRUE);
		fv->value.bytes=NULL;
	}
}


static void
bytes_fvalue_set(fvalue_t *fv, GByteArray *value)
{
	/* Free up the old value, if we have one */
	bytes_fvalue_free(fv);

	fv->value.bytes = value;
}

static char *
oid_to_repr(wmem_allocator_t *scope, const fvalue_t *fv, ftrepr_t rtype _U_, int field_display _U_)
{
	return oid_encoded2string(scope, fv->value.bytes->data,fv->value.bytes->len);
}

static char *
rel_oid_to_repr(wmem_allocator_t *scope, const fvalue_t *fv, ftrepr_t rtype _U_, int field_display _U_)
{
	return rel_oid_encoded2string(scope, fv->value.bytes->data,fv->value.bytes->len);
}

static char *
system_id_to_repr(wmem_allocator_t *scope, const fvalue_t *fv, ftrepr_t rtype _U_, int field_display _U_)
{
	return print_system_id(scope, fv->value.bytes->data, fv->value.bytes->len);
}

static char *
bytes_to_repr(wmem_allocator_t *scope, const fvalue_t *fv, ftrepr_t rtype, int field_display)
{
	char separator;

	switch(FIELD_DISPLAY(field_display))
	{
	case SEP_DOT:
		separator = '.';
		break;
	case SEP_DASH:
		separator = '-';
		break;
	case SEP_SPACE:
	case SEP_COLON:
	case BASE_NONE:
	default:
		separator = ':';
		break;
	}

	if (fv->value.bytes->len) {
		return bytes_to_str_punct_maxlen(scope, fv->value.bytes->data, fv->value.bytes->len, separator, 0);
	}

	if (rtype == FTREPR_DFILTER) {
		/* An empty byte array in a display filter is represented as "" */
		return wmem_strdup(scope, "\"\"");
	}

	return wmem_strdup(scope, "");
}

static void
common_fvalue_set(fvalue_t *fv, const guint8* data, guint len)
{
	/* Free up the old value, if we have one */
	bytes_fvalue_free(fv);

	fv->value.bytes = g_byte_array_new();
	g_byte_array_append(fv->value.bytes, data, len);
}

static void
ax25_fvalue_set(fvalue_t *fv, const guint8 *value)
{
	common_fvalue_set(fv, value, FT_AX25_ADDR_LEN);
}

static void
vines_fvalue_set(fvalue_t *fv, const guint8 *value)
{
	common_fvalue_set(fv, value, FT_VINES_ADDR_LEN);
}

static void
ether_fvalue_set(fvalue_t *fv, const guint8 *value)
{
	common_fvalue_set(fv, value, FT_ETHER_LEN);
}

static void
fcwwn_fvalue_set(fvalue_t *fv, const guint8 *value)
{
	common_fvalue_set(fv, value, FT_FCWWN_LEN);
}

static void
oid_fvalue_set(fvalue_t *fv, GByteArray *value)
{
	/* Free up the old value, if we have one */
	bytes_fvalue_free(fv);

	fv->value.bytes = value;
}

static void
system_id_fvalue_set(fvalue_t *fv, GByteArray *value)
{
	/* Free up the old value, if we have one */
	bytes_fvalue_free(fv);

	fv->value.bytes = value;
}

static gpointer
value_get(fvalue_t *fv)
{
	return fv->value.bytes->data;
}

static gboolean
bytes_from_string(fvalue_t *fv, const char *s, gchar **err_msg _U_)
{
	GByteArray	*bytes;

	bytes = g_byte_array_new();

	g_byte_array_append(bytes, (const guint8 *)s, (guint)strlen(s));

	/* Free up the old value, if we have one */
	bytes_fvalue_free(fv);
	fv->value.bytes = bytes;

	return TRUE;
}

GByteArray *
byte_array_from_literal(const char *s, gchar **err_msg)
{
	GByteArray	*bytes;
	gboolean	res;

	/*
	 * Special case where the byte string is specified using a one byte
	 * hex literal. We can't allow this for byte strings that are longer
	 * than one byte, because then we'd have to know which endianness the
	 * byte string should be in.
	 */
	if (strlen(s) == 4 && s[0] == '0' && s[1] == 'x')
		s = s + 2;

	bytes = g_byte_array_new();

	res = hex_str_to_bytes(s, bytes, FALSE);

	if (!res) {
		if (err_msg != NULL)
			*err_msg = ws_strdup_printf("\"%s\" is not a valid byte string.", s);
		g_byte_array_free(bytes, TRUE);
		return NULL;
	}

	return bytes;
}

static gboolean
bytes_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value _U_, gchar **err_msg)
{
	GByteArray	*bytes;

	bytes = byte_array_from_literal(s, err_msg);
	if (bytes == NULL)
		return FALSE;

	/* Free up the old value, if we have one */
	bytes_fvalue_free(fv);

	fv->value.bytes = bytes;

	return TRUE;
}

GByteArray *
byte_array_from_charconst(unsigned long num, gchar **err_msg)
{
	if (num > UINT8_MAX) {
		if (err_msg) {
			*err_msg = ws_strdup_printf("%lu is too large for a byte value", num);
		}
		return NULL;
	}

	GByteArray *bytes = g_byte_array_new();
	uint8_t one_byte = (uint8_t)num;
	g_byte_array_append(bytes, &one_byte, 1);
	return bytes;
}

static gboolean
bytes_from_charconst(fvalue_t *fv, unsigned long num, gchar **err_msg)
{
	GByteArray	*bytes;

	bytes = byte_array_from_charconst(num, err_msg);
	if (bytes == NULL)
		return FALSE;

	/* Free up the old value, if we have one */
	bytes_fvalue_free(fv);

	fv->value.bytes = bytes;

	return TRUE;
}

static gboolean
ax25_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value, gchar **err_msg)
{
	/*
	 * Don't request an error message if bytes_from_literal fails;
	 * if it does, we'll report an error specific to this address
	 * type.
	 */
	if (bytes_from_literal(fv, s, TRUE, NULL)) {
		if (fv->value.bytes->len > FT_AX25_ADDR_LEN) {
			if (err_msg != NULL) {
				*err_msg = ws_strdup_printf("\"%s\" contains too many bytes to be a valid AX.25 address.",
				    s);
			}
			return FALSE;
		}
		else if (fv->value.bytes->len < FT_AX25_ADDR_LEN && !allow_partial_value) {
			if (err_msg != NULL) {
				*err_msg = ws_strdup_printf("\"%s\" contains too few bytes to be a valid AX.25 address.",
				    s);
			}
			return FALSE;
		}

		return TRUE;
	}

	/*
	 * XXX - what needs to be done here is something such as:
	 *
	 * Look for a "-" in the string.
	 *
	 * If we find it, make sure that there are 1-6 alphanumeric
	 * ASCII characters before it, and that there are 2 decimal
	 * digits after it, from 00 to 15; if we don't find it, make
	 * sure that there are 1-6 alphanumeric ASCII characters
	 * in the string.
	 *
	 * If so, make the first 6 octets of the address the ASCII
	 * characters, with lower-case letters mapped to upper-case
	 * letters, shifted left by 1 bit, padded to 6 octets with
	 * spaces, also shifted left by 1 bit, and, if we found a
	 * "-", convert what's after it to a number and make the 7th
	 * octet the number, shifted left by 1 bit, otherwise make the
	 * 7th octet zero.
	 *
	 * We should also change all the comparison functions for
	 * AX.25 addresses check the upper 7 bits of all but the last
	 * octet of the address, ignoring the "end of address" bit,
	 * and compare only the 4 bits above the low-order bit for
	 * the last octet, ignoring the "end of address" bit and
	 * various reserved bits and bits used for other purposes.
	 *
	 * See section 3.12 "Address-Field Encoding" of the AX.25
	 * spec and
	 *
	 *	http://www.itu.int/ITU-R/terrestrial/docs/fixedmobile/fxm-art19-sec3.pdf
	 */
	if (err_msg != NULL)
		*err_msg = ws_strdup_printf("\"%s\" is not a valid AX.25 address.", s);
	return FALSE;
}

static gboolean
vines_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value, gchar **err_msg)
{
	/*
	 * Don't request an error message if bytes_from_literal fails;
	 * if it does, we'll report an error specific to this address
	 * type.
	 */
	if (bytes_from_literal(fv, s, TRUE, NULL)) {
		if (fv->value.bytes->len > FT_VINES_ADDR_LEN) {
			if (err_msg != NULL) {
				*err_msg = ws_strdup_printf("\"%s\" contains too many bytes to be a valid Vines address.",
				    s);
			}
			return FALSE;
		}
		else if (fv->value.bytes->len < FT_VINES_ADDR_LEN && !allow_partial_value) {
			if (err_msg != NULL) {
				*err_msg = ws_strdup_printf("\"%s\" contains too few bytes to be a valid Vines address.",
				    s);
			}
			return FALSE;
		}

		return TRUE;
	}

	/* XXX - need better validation of Vines address */

	if (err_msg != NULL)
		*err_msg = ws_strdup_printf("\"%s\" is not a valid Vines address.", s);
	return FALSE;
}

static gboolean
ether_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value, gchar **err_msg)
{
	/*
	 * Don't request an error message if bytes_from_literal fails;
	 * if it does, we'll report an error specific to this address
	 * type.
	 */
	if (bytes_from_literal(fv, s, TRUE, NULL)) {
		if (fv->value.bytes->len > FT_ETHER_LEN) {
			if (err_msg != NULL) {
				*err_msg = ws_strdup_printf("\"%s\" contains too many bytes to be a valid Ethernet address.",
				    s);
			}
			return FALSE;
		}
		else if (fv->value.bytes->len < FT_ETHER_LEN && !allow_partial_value) {
			if (err_msg != NULL) {
				*err_msg = ws_strdup_printf("\"%s\" contains too few bytes to be a valid Ethernet address.",
				    s);
			}
			return FALSE;
		}

		return TRUE;
	}

	/* XXX - Try resolving as an Ethernet host name and parse that? */

	if (err_msg != NULL)
		*err_msg = ws_strdup_printf("\"%s\" is not a valid Ethernet address.", s);
	return FALSE;
}

static gboolean
oid_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value _U_, gchar **err_msg)
{
	GByteArray	*bytes;
	gboolean	res;


#if 0
	/*
	 * Don't log a message if this fails; we'll try looking it
	 * up as an OID if it does, and if that fails,
	 * we'll log a message.
	 */
	/* do not try it as '.' is handled as valid separator for hexbytes :( */
	if (bytes_from_literal(fv, s, TRUE, NULL)) {
		return TRUE;
	}
#endif

	bytes = g_byte_array_new();
	res = oid_str_to_bytes(s, bytes);
	if (!res) {
		if (err_msg != NULL)
			*err_msg = ws_strdup_printf("\"%s\" is not a valid OBJECT IDENTIFIER.", s);
		g_byte_array_free(bytes, TRUE);
		return FALSE;
	}

	/* Free up the old value, if we have one */
	bytes_fvalue_free(fv);
	fv->value.bytes = bytes;

	return TRUE;
}

static gboolean
rel_oid_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value _U_, gchar **err_msg)
{
	GByteArray	*bytes;
	gboolean	res;

	bytes = g_byte_array_new();
	res = rel_oid_str_to_bytes(s, bytes, FALSE);
	if (!res) {
		if (err_msg != NULL)
			*err_msg = ws_strdup_printf("\"%s\" is not a valid RELATIVE-OID.", s);
		g_byte_array_free(bytes, TRUE);
		return FALSE;
	}

	/* Free up the old value, if we have one */
	bytes_fvalue_free(fv);
	fv->value.bytes = bytes;

	return TRUE;
}

static gboolean
system_id_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value _U_, gchar **err_msg)
{
	/*
	 * Don't request an error message if bytes_from_literal fails;
	 * if it does, we'll report an error specific to this address
	 * type.
	 */
	if (bytes_from_literal(fv, s, TRUE, NULL)) {
		if (fv->value.bytes->len > MAX_SYSTEMID_LEN) {
			if (err_msg != NULL) {
				*err_msg = ws_strdup_printf("\"%s\" contains too many bytes to be a valid OSI System-ID.",
				    s);
			}
			return FALSE;
		}

		return TRUE;
	}

	/* XXX - need better validation of OSI System-ID address */

	if (err_msg != NULL)
		*err_msg = ws_strdup_printf("\"%s\" is not a valid OSI System-ID.", s);
	return FALSE;
}

static gboolean
fcwwn_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value _U_, gchar **err_msg)
{
	/*
	 * Don't request an error message if bytes_from_literal fails;
	 * if it does, we'll report an error specific to this address
	 * type.
	 */
	if (bytes_from_literal(fv, s, TRUE, NULL)) {
		if (fv->value.bytes->len > FT_FCWWN_LEN) {
			if (err_msg != NULL) {
				*err_msg = ws_strdup_printf("\"%s\" contains too many bytes to be a valid FCWWN.",
				    s);
			}
			return FALSE;
		}

		return TRUE;
	}

	/* XXX - need better validation of FCWWN address */

	if (err_msg != NULL)
		*err_msg = ws_strdup_printf("\"%s\" is not a valid FCWWN.", s);
	return FALSE;
}

static guint
len(fvalue_t *fv)
{
	return fv->value.bytes->len;
}

static void
slice(fvalue_t *fv, GByteArray *bytes, guint offset, guint length)
{
	guint8* data;

	data = fv->value.bytes->data + offset;

	g_byte_array_append(bytes, data, length);
}

static int
cmp_order(const fvalue_t *fv_a, const fvalue_t *fv_b)
{
	GByteArray	*a = fv_a->value.bytes;
	GByteArray	*b = fv_b->value.bytes;

	if (a->len != b->len)
		return a->len < b->len ? -1 : 1;

	return memcmp(a->data, b->data, a->len);
}

static gboolean
cmp_bitwise_and(const fvalue_t *fv_a, const fvalue_t *fv_b)
{
	GByteArray	*a = fv_a->value.bytes;
	GByteArray	*b = fv_b->value.bytes;
	guint i = 0;
	unsigned char *p_a, *p_b;

	if (b->len != a->len) {
		return FALSE;
	}
	p_a = a->data;
	p_b = b->data;
	while (i < b->len) {
		if (p_a[i] & p_b[i])
			return TRUE;
		else
			i++;
	}
	return FALSE;
}

static gboolean
cmp_contains(const fvalue_t *fv_a, const fvalue_t *fv_b)
{
	GByteArray	*a = fv_a->value.bytes;
	GByteArray	*b = fv_b->value.bytes;

	if (ws_memmem(a->data, a->len, b->data, b->len)) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}

static gboolean
cmp_matches(const fvalue_t *fv, const ws_regex_t *regex)
{
	GByteArray *a = fv->value.bytes;

	return ws_regex_matches_length(regex, a->data, a->len);
}

void
ftype_register_bytes(void)
{

	static ftype_t bytes_type = {
		FT_BYTES,			/* ftype */
		"FT_BYTES",			/* name */
		"Sequence of bytes",		/* pretty_name */
		0,				/* wire_size */
		bytes_fvalue_new,		/* new_value */
		bytes_fvalue_free,		/* free_value */
		bytes_from_literal,		/* val_from_literal */
		bytes_from_string,		/* val_from_string */
		bytes_from_charconst,		/* val_from_charconst */
		bytes_to_repr,			/* val_to_string_repr */

		{ .set_value_byte_array = bytes_fvalue_set },	/* union set_value */
		{ .get_value_ptr = value_get },			/* union get_value */

		cmp_order,
		cmp_bitwise_and,
		cmp_contains,
		cmp_matches,

		len,
		slice,
	};

	static ftype_t uint_bytes_type = {
		FT_UINT_BYTES,		/* ftype */
		"FT_UINT_BYTES",		/* name */
		"Sequence of bytes",		/* pretty_name */
		0,				/* wire_size */
		bytes_fvalue_new,		/* new_value */
		bytes_fvalue_free,		/* free_value */
		bytes_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		NULL,				/* val_from_charconst */
		bytes_to_repr,			/* val_to_string_repr */

		{ .set_value_byte_array = bytes_fvalue_set },	/* union set_value */
		{ .get_value_ptr = value_get },			/* union get_value */

		cmp_order,
		cmp_bitwise_and,
		cmp_contains,
		NULL,				/* cmp_matches */

		len,
		slice,
	};

	static ftype_t ax25_type = {
		FT_AX25,			/* ftype */
		"FT_AX25",			/* name */
		"AX.25 address",		/* pretty_name */
		FT_AX25_ADDR_LEN,		/* wire_size */
		bytes_fvalue_new,		/* new_value */
		bytes_fvalue_free,		/* free_value */
		ax25_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		NULL,				/* val_from_charconst */
		bytes_to_repr,			/* val_to_string_repr */

		{ .set_value_bytes = ax25_fvalue_set },	/* union set_value */
		{ .get_value_ptr = value_get },			/* union get_value */

		cmp_order,
		cmp_bitwise_and,
		cmp_contains,
		cmp_matches,

		len,
		slice,
	};

	static ftype_t vines_type = {
		FT_VINES,			/* ftype */
		"FT_VINES",			/* name */
		"VINES address",		/* pretty_name */
		FT_VINES_ADDR_LEN,		/* wire_size */
		bytes_fvalue_new,		/* new_value */
		bytes_fvalue_free,		/* free_value */
		vines_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		NULL,				/* val_from_charconst */
		bytes_to_repr,			/* val_to_string_repr */

		{ .set_value_bytes = vines_fvalue_set },	/* union set_value */
		{ .get_value_ptr = value_get },			/* union get_value */

		cmp_order,
		cmp_bitwise_and,
		cmp_contains,
		cmp_matches,

		len,
		slice,
	};

	static ftype_t ether_type = {
		FT_ETHER,			/* ftype */
		"FT_ETHER",			/* name */
		"Ethernet or other MAC address",/* pretty_name */
		FT_ETHER_LEN,			/* wire_size */
		bytes_fvalue_new,		/* new_value */
		bytes_fvalue_free,		/* free_value */
		ether_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		NULL,				/* val_from_charconst */
		bytes_to_repr,			/* val_to_string_repr */

		{ .set_value_bytes = ether_fvalue_set },	/* union set_value */
		{ .get_value_ptr = value_get },			/* union get_value */

		cmp_order,
		cmp_bitwise_and,
		cmp_contains,
		cmp_matches,

		len,
		slice,
	};

	static ftype_t oid_type = {
		FT_OID,			/* ftype */
		"FT_OID",			/* name */
		"ASN.1 object identifier",	/* pretty_name */
		0,			/* wire_size */
		bytes_fvalue_new,		/* new_value */
		bytes_fvalue_free,		/* free_value */
		oid_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		NULL,				/* val_from_charconst */
		oid_to_repr,			/* val_to_string_repr */

		{ .set_value_byte_array = oid_fvalue_set },	/* union set_value */
		{ .get_value_ptr = value_get },			/* union get_value */

		cmp_order,
		cmp_bitwise_and,
		cmp_contains,
		NULL,				/* cmp_matches */

		len,
		slice,
	};

	static ftype_t rel_oid_type = {
		FT_REL_OID,			/* ftype */
		"FT_REL_OID",			/* name */
		"ASN.1 relative object identifier",	/* pretty_name */
		0,			/* wire_size */
		bytes_fvalue_new,		/* new_value */
		bytes_fvalue_free,		/* free_value */
		rel_oid_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		NULL,				/* val_from_charconst */
		rel_oid_to_repr,		/* val_to_string_repr */

		{ .set_value_byte_array = oid_fvalue_set },	/* union set_value */
		{ .get_value_ptr = value_get },			/* union get_value */

		cmp_order,
		cmp_bitwise_and,
		cmp_contains,
		NULL,				/* cmp_matches */

		len,
		slice,
	};

	static ftype_t system_id_type = {
		FT_SYSTEM_ID,			/* ftype */
		"FT_SYSTEM_ID",			/* name */
		"OSI System-ID",		/* pretty_name */
		0,			/* wire_size */
		bytes_fvalue_new,		/* new_value */
		bytes_fvalue_free,		/* free_value */
		system_id_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		NULL,				/* val_from_charconst */
		system_id_to_repr,		/* val_to_string_repr */

		{ .set_value_byte_array = system_id_fvalue_set }, /* union set_value */
		{ .get_value_ptr = value_get },			/* union get_value */

		cmp_order,
		cmp_bitwise_and,
		cmp_contains,
		NULL,				/* cmp_matches */

		len,
		slice,
	};

	static ftype_t fcwwn_type = {
		FT_FCWWN,			/* ftype */
		"FT_FCWWN",			/* name */
		"Fibre Channel WWN",	/* pretty_name */
		FT_FCWWN_LEN,			/* wire_size */
		bytes_fvalue_new,		/* new_value */
		bytes_fvalue_free,		/* free_value */
		fcwwn_from_literal,		/* val_from_literal */
		NULL,				/* val_from_string */
		NULL,				/* val_from_charconst */
		bytes_to_repr,			/* val_to_string_repr */

		{ .set_value_bytes = fcwwn_fvalue_set },	/* union set_value */
		{ .get_value_ptr = value_get },			/* union get_value */

		cmp_order,
		cmp_bitwise_and,
		cmp_contains,
		cmp_matches,

		len,
		slice,
	};

	ftype_register(FT_BYTES, &bytes_type);
	ftype_register(FT_UINT_BYTES, &uint_bytes_type);
	ftype_register(FT_AX25, &ax25_type);
	ftype_register(FT_VINES, &vines_type);
	ftype_register(FT_ETHER, &ether_type);
	ftype_register(FT_OID, &oid_type);
	ftype_register(FT_REL_OID, &rel_oid_type);
	ftype_register(FT_SYSTEM_ID, &system_id_type);
	ftype_register(FT_FCWWN, &fcwwn_type);
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
