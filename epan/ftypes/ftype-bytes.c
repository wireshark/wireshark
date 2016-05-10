/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <ftypes-int.h>
#include <string.h>
#include <epan/addr_resolv.h>
#include <epan/strutil.h>
#include <epan/oids.h>
#include <epan/osi-utils.h>
#include <epan/to_str-int.h>

#define CMP_MATCHES cmp_matches

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

static int
bytes_repr_len(fvalue_t *fv, ftrepr_t rtype, int field_display _U_)
{
	if (fv->value.bytes->len == 0) {
		/* An empty array of bytes is represented as "" in a
		   display filter and as an empty string otherwise. */
		return (rtype == FTREPR_DFILTER) ? 2 : 0;
	} else {
		/* 3 bytes for each byte of the byte "NN<separator character>" minus 1 byte
		 * as there's no trailing "<separator character>". */
		return fv->value.bytes->len * 3 - 1;
	}
}

/*
 * OID_REPR_LEN:
 *
 * 5 for the first byte ([0-2].[0-39].)
 *
 * REL_OID_REPR_LEN:
 * for each extra byte if the sub-id is:
 *   1 byte it can be at most "127." (4 bytes we give it 4)
 *   2 bytes it can be at most "16383." (6 bytes we give it 8)
 *   3 bytes it can be at most "2097151." (8 bytes we give it 12)
 *   4 bytes it can be at most "268435456." (10 bytes we give it 16)
 *   5 bytes it can be at most "34359738368." (12 bytes we give it 20)
 *
 *  a 5 bytes encoded subid can already overflow the guint32 that holds a sub-id,
 *  making it a completely different issue!
 */
#define REL_OID_REPR_LEN(fv) (4 * ((fv)->value.bytes->len))
#define OID_REPR_LEN(fv) (1 + REL_OID_REPR_LEN(fv))

static int
oid_repr_len(fvalue_t *fv, ftrepr_t rtype _U_, int field_display _U_)
{
	return OID_REPR_LEN(fv);
}

static void
oid_to_repr(fvalue_t *fv, ftrepr_t rtype _U_, int field_display _U_, char *buf, unsigned int size _U_)
{
	char* oid_str = oid_encoded2string(NULL, fv->value.bytes->data,fv->value.bytes->len);
	/*
	 * XXX:
	 * I'm assuming that oid_repr_len is going to be called before to set buf's size.
	 * or else we might have a BO.
	 * I guess that is why this callback is not passed a length.
	 *    -- lego
	 */
	g_strlcpy(buf,oid_str,OID_REPR_LEN(fv));
	wmem_free(NULL, oid_str);
}

static int
rel_oid_repr_len(fvalue_t *fv, ftrepr_t rtype _U_, int field_display _U_)
{
	return REL_OID_REPR_LEN(fv);
}

static void
rel_oid_to_repr(fvalue_t *fv, ftrepr_t rtype _U_, int field_display _U_, char *buf, unsigned int size _U_)
{
	char* oid_str = rel_oid_encoded2string(NULL, fv->value.bytes->data,fv->value.bytes->len);
	/*
	 * XXX:
	 * I'm assuming that oid_repr_len is going to be called before to set buf's size.
	 * or else we might have a BO.
	 * I guess that is why this callback is not passed a length.
	 *    -- lego
	 */
	*buf++ = '.';
	g_strlcpy(buf,oid_str,REL_OID_REPR_LEN(fv));
	wmem_free(NULL, oid_str);
}

static void
system_id_to_repr(fvalue_t *fv, ftrepr_t rtype _U_, int field_display _U_, char *buf, unsigned int size)
{
	print_system_id_buf(fv->value.bytes->data,fv->value.bytes->len, buf, size);
}

static void
bytes_to_repr(fvalue_t *fv, ftrepr_t rtype, int field_display, char *buf, unsigned int size _U_)
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
		buf = bytes_to_hexstr_punct(buf, fv->value.bytes->data, fv->value.bytes->len, separator);
	}
	else {
		if (rtype == FTREPR_DFILTER) {
			/* An empty byte array in a display filter is represented as "" */
			*buf++ = '"';
			*buf++ = '"';
		}
	}
	*buf = '\0';
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

static gboolean
bytes_from_unparsed(fvalue_t *fv, const char *s, gboolean allow_partial_value _U_, gchar **err_msg)
{
	GByteArray	*bytes;
	gboolean	res;

	bytes = g_byte_array_new();

	res = hex_str_to_bytes(s, bytes, TRUE);

	if (!res) {
		if (err_msg != NULL)
			*err_msg = g_strdup_printf("\"%s\" is not a valid byte string.", s);
		g_byte_array_free(bytes, TRUE);
		return FALSE;
	}

	/* Free up the old value, if we have one */
	bytes_fvalue_free(fv);

	fv->value.bytes = bytes;

	return TRUE;
}

static gboolean
ax25_from_unparsed(fvalue_t *fv, const char *s, gboolean allow_partial_value, gchar **err_msg)
{
	/*
	 * Don't request an error message if bytes_from_unparsed fails;
	 * if it does, we'll report an error specific to this address
	 * type.
	 */
	if (bytes_from_unparsed(fv, s, TRUE, NULL)) {
		if (fv->value.bytes->len > FT_AX25_ADDR_LEN) {
			if (err_msg != NULL) {
				*err_msg = g_strdup_printf("\"%s\" contains too many bytes to be a valid AX.25 address.",
				    s);
			}
			return FALSE;
		}
		else if (fv->value.bytes->len < FT_AX25_ADDR_LEN && !allow_partial_value) {
			if (err_msg != NULL) {
				*err_msg = g_strdup_printf("\"%s\" contains too few bytes to be a valid AX.25 address.",
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
		*err_msg = g_strdup_printf("\"%s\" is not a valid AX.25 address.", s);
	return FALSE;
}

static gboolean
vines_from_unparsed(fvalue_t *fv, const char *s, gboolean allow_partial_value, gchar **err_msg)
{
	/*
	 * Don't request an error message if bytes_from_unparsed fails;
	 * if it does, we'll report an error specific to this address
	 * type.
	 */
	if (bytes_from_unparsed(fv, s, TRUE, NULL)) {
		if (fv->value.bytes->len > FT_VINES_ADDR_LEN) {
			if (err_msg != NULL) {
				*err_msg = g_strdup_printf("\"%s\" contains too many bytes to be a valid Vines address.",
				    s);
			}
			return FALSE;
		}
		else if (fv->value.bytes->len < FT_VINES_ADDR_LEN && !allow_partial_value) {
			if (err_msg != NULL) {
				*err_msg = g_strdup_printf("\"%s\" contains too few bytes to be a valid Vines address.",
				    s);
			}
			return FALSE;
		}

		return TRUE;
	}

	/* XXX - need better validation of Vines address */

	if (err_msg != NULL)
		*err_msg = g_strdup_printf("\"%s\" is not a valid Vines address.", s);
	return FALSE;
}

static gboolean
ether_from_unparsed(fvalue_t *fv, const char *s, gboolean allow_partial_value, gchar **err_msg)
{
	guint8	*mac;

	/*
	 * Don't request an error message if bytes_from_unparsed fails;
	 * if it does, we'll report an error specific to this address
	 * type.
	 */
	if (bytes_from_unparsed(fv, s, TRUE, NULL)) {
		if (fv->value.bytes->len > FT_ETHER_LEN) {
			if (err_msg != NULL) {
				*err_msg = g_strdup_printf("\"%s\" contains too many bytes to be a valid Ethernet address.",
				    s);
			}
			return FALSE;
		}
		else if (fv->value.bytes->len < FT_ETHER_LEN && !allow_partial_value) {
			if (err_msg != NULL) {
				*err_msg = g_strdup_printf("\"%s\" contains too few bytes to be a valid Ethernet address.",
				    s);
			}
			return FALSE;
		}

		return TRUE;
	}

	mac = get_ether_addr(s);
	if (!mac) {
		if (err_msg != NULL) {
			*err_msg = g_strdup_printf("\"%s\" is not a valid hostname or Ethernet address.",
			    s);
		}
		return FALSE;
	}

	ether_fvalue_set(fv, mac);
	return TRUE;
}

static gboolean
oid_from_unparsed(fvalue_t *fv, const char *s, gboolean allow_partial_value _U_, gchar **err_msg)
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
	if (bytes_from_unparsed(fv, s, TRUE, NULL)) {
		return TRUE;
	}
#endif

	bytes = g_byte_array_new();
	res = oid_str_to_bytes(s, bytes);
	if (!res) {
		if (err_msg != NULL)
			*err_msg = g_strdup_printf("\"%s\" is not a valid OBJECT IDENTIFIER.", s);
		g_byte_array_free(bytes, TRUE);
		return FALSE;
	}

	/* Free up the old value, if we have one */
	bytes_fvalue_free(fv);
	fv->value.bytes = bytes;

	return TRUE;
}

static gboolean
rel_oid_from_unparsed(fvalue_t *fv, const char *s, gboolean allow_partial_value _U_, gchar **err_msg)
{
	GByteArray	*bytes;
	gboolean	res;

	bytes = g_byte_array_new();
	res = rel_oid_str_to_bytes(s, bytes, FALSE);
	if (!res) {
		if (err_msg != NULL)
			*err_msg = g_strdup_printf("\"%s\" is not a valid RELATIVE-OID.", s);
		g_byte_array_free(bytes, TRUE);
		return FALSE;
	}

	/* Free up the old value, if we have one */
	bytes_fvalue_free(fv);
	fv->value.bytes = bytes;

	return TRUE;
}

static gboolean
system_id_from_unparsed(fvalue_t *fv, const char *s, gboolean allow_partial_value _U_, gchar **err_msg)
{
	/*
	 * Don't request an error message if bytes_from_unparsed fails;
	 * if it does, we'll report an error specific to this address
	 * type.
	 */
	if (bytes_from_unparsed(fv, s, TRUE, NULL)) {
		if (fv->value.bytes->len > MAX_SYSTEMID_LEN) {
			if (err_msg != NULL) {
				*err_msg = g_strdup_printf("\"%s\" contains too many bytes to be a valid OSI System-ID.",
				    s);
			}
			return FALSE;
		}

		return TRUE;
	}

	/* XXX - need better validation of OSI System-ID address */

	if (err_msg != NULL)
		*err_msg = g_strdup_printf("\"%s\" is not a valid OSI System-ID.", s);
	return FALSE;
}

static gboolean
fcwwn_from_unparsed(fvalue_t *fv, const char *s, gboolean allow_partial_value _U_, gchar **err_msg)
{
	/*
	 * Don't request an error message if bytes_from_unparsed fails;
	 * if it does, we'll report an error specific to this address
	 * type.
	 */
	if (bytes_from_unparsed(fv, s, TRUE, NULL)) {
		if (fv->value.bytes->len > FT_FCWWN_LEN) {
			if (err_msg != NULL) {
				*err_msg = g_strdup_printf("\"%s\" contains too many bytes to be a valid FCWWN.",
				    s);
			}
			return FALSE;
		}

		return TRUE;
	}

	/* XXX - need better validation of FCWWN address */

	if (err_msg != NULL)
		*err_msg = g_strdup_printf("\"%s\" is not a valid FCWWN.", s);
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


static gboolean
cmp_eq(const fvalue_t *fv_a, const fvalue_t *fv_b)
{
	GByteArray	*a = fv_a->value.bytes;
	GByteArray	*b = fv_b->value.bytes;

	if (a->len != b->len) {
		return FALSE;
	}

	return (memcmp(a->data, b->data, a->len) == 0);
}


static gboolean
cmp_ne(const fvalue_t *fv_a, const fvalue_t *fv_b)
{
	GByteArray	*a = fv_a->value.bytes;
	GByteArray	*b = fv_b->value.bytes;

	if (a->len != b->len) {
		return TRUE;
	}

	return (memcmp(a->data, b->data, a->len) != 0);
}


static gboolean
cmp_gt(const fvalue_t *fv_a, const fvalue_t *fv_b)
{
	GByteArray	*a = fv_a->value.bytes;
	GByteArray	*b = fv_b->value.bytes;

	if (a->len > b->len) {
		return TRUE;
	}

	if (a->len < b->len) {
		return FALSE;
	}

	return (memcmp(a->data, b->data, a->len) > 0);
}

static gboolean
cmp_ge(const fvalue_t *fv_a, const fvalue_t *fv_b)
{
	GByteArray	*a = fv_a->value.bytes;
	GByteArray	*b = fv_b->value.bytes;

	if (a->len > b->len) {
		return TRUE;
	}

	if (a->len < b->len) {
		return FALSE;
	}

	return (memcmp(a->data, b->data, a->len) >= 0);
}

static gboolean
cmp_lt(const fvalue_t *fv_a, const fvalue_t *fv_b)
{
	GByteArray	*a = fv_a->value.bytes;
	GByteArray	*b = fv_b->value.bytes;

	if (a->len < b->len) {
		return TRUE;
	}

	if (a->len > b->len) {
		return FALSE;
	}

	return (memcmp(a->data, b->data, a->len) < 0);
}

static gboolean
cmp_le(const fvalue_t *fv_a, const fvalue_t *fv_b)
{
	GByteArray	*a = fv_a->value.bytes;
	GByteArray	*b = fv_b->value.bytes;

	if (a->len < b->len) {
		return TRUE;
	}

	if (a->len > b->len) {
		return FALSE;
	}

	return (memcmp(a->data, b->data, a->len) <= 0);
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

	if (epan_memmem(a->data, a->len, b->data, b->len)) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}

static gboolean
cmp_matches(const fvalue_t *fv_a, const fvalue_t *fv_b)
{
	GByteArray *a = fv_a->value.bytes;
	GRegex *regex = fv_b->value.re;

	/* fv_b is always a FT_PCRE, otherwise the dfilter semcheck() would have
	 * warned us. For the same reason (and because we're using g_malloc()),
	 * fv_b->value.re is not NULL.
	 */
	if (strcmp(fv_b->ftype->name, "FT_PCRE") != 0) {
		return FALSE;
	}
	if (! regex) {
		return FALSE;
	}
	/*
	 * XXX - do we want G_REGEX_RAW or not?
	 *
	 * If we're matching against a string, we don't want it (and
	 * we want the string value encoded in UTF-8 - and, if it can't
	 * be converted to UTF-8, because it's in a character encoding
	 * that doesn't map every possible byte sequence to Unicode (and
	 * that includes strings that are supposed to be in UTF-8 but
	 * that contain invalid UTF-8 sequences!), treat the match as
	 * failing.
	 *
	 * If we're matching against binary data, and matching a binary
	 * pattern (e.g. "0xfa, 3 or more 0xff, and 0x37, in order"),
	 * we'd want G_REGEX_RAW. If we're matching a text pattern,
	 * it's not clear *what* the right thing to do is - if they're
	 * matching against a pattern containing non-ASCII characters,
	 * they might want it to match in whatever encoding the binary
	 * data is, but Wireshark might not have a clue what that
	 * encoding is.  In addition, it's not clear how to tell
	 * whether a pattern is "binary" or not, short of having
	 * a different (non-PCRE) syntax for binary patterns.
	 *
	 * So we don't use G_REGEX_RAW for now.
	 */
	return g_regex_match_full(
		regex,			/* Compiled PCRE */
		(char *)a->data,	/* The data to check for the pattern... */
		(int)a->len,		/* ... and its length */
		0,			/* Start offset within data */
		(GRegexMatchFlags)0,	/* GRegexMatchFlags */
		NULL,			/* We are not interested in the match information */
		NULL			/* We don't want error information */
		);
	/* NOTE - DO NOT g_free(data) */
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
		bytes_from_unparsed,		/* val_from_unparsed */
		bytes_from_string,		/* val_from_string */
		bytes_to_repr,			/* val_to_string_repr */
		bytes_repr_len,			/* len_string_repr */

		bytes_fvalue_set,		/* set_value_byte_array */
		NULL,				/* set_value_bytes */
		NULL,				/* set_value_guid */
		NULL,				/* set_value_time */
		NULL,				/* set_value_string */
		NULL,				/* set_value_protocol */
		NULL,				/* set_value_uinteger */
		NULL,				/* set_value_sinteger */
		NULL,				/* set_value_uinteger64 */
		NULL,				/* set_value_sinteger64 */
		NULL,				/* set_value_floating */

		value_get,			/* get_value */
		NULL,				/* get_value_uinteger */
		NULL,				/* get_value_sinteger */
		NULL,				/* get_value_uinteger64 */
		NULL,				/* get_value_sinteger64 */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		cmp_gt,
		cmp_ge,
		cmp_lt,
		cmp_le,
		cmp_bitwise_and,
		cmp_contains,
		CMP_MATCHES,

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
		bytes_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		bytes_to_repr,			/* val_to_string_repr */
		bytes_repr_len,			/* len_string_repr */

		bytes_fvalue_set,		/* set_value_byte_array */
		NULL,				/* set_value_bytes */
		NULL,				/* set_value_guid */
		NULL,				/* set_value_time */
		NULL,				/* set_value_string */
		NULL,				/* set_value_protocol */
		NULL,				/* set_value_uinteger */
		NULL,				/* set_value_sinteger */
		NULL,				/* set_value_uinteger64 */
		NULL,				/* set_value_sinteger64 */
		NULL,				/* set_value_floating */

		value_get,			/* get_value */
		NULL,				/* get_value_uinteger */
		NULL,				/* get_value_sinteger */
		NULL,				/* get_value_uinteger64 */
		NULL,				/* get_value_sinteger64 */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		cmp_gt,
		cmp_ge,
		cmp_lt,
		cmp_le,
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
		ax25_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		bytes_to_repr,			/* val_to_string_repr */
		bytes_repr_len,			/* len_string_repr */

		NULL,				/* set_value_byte_array */
		ax25_fvalue_set,		/* set_value_bytes */
		NULL,				/* set_value_guid */
		NULL,				/* set_value_time */
		NULL,				/* set_value_string */
		NULL,				/* set_value_protocol */
		NULL,				/* set_value_uinteger */
		NULL,				/* set_value_integer */
		NULL,				/* set_value_uinteger64 */
		NULL,				/* set_value_sinteger64 */
		NULL,				/* set_value_floating */

		value_get,			/* get_value */
		NULL,				/* set_value_uinteger */
		NULL,				/* get_value_integer */
		NULL,				/* get_value_uinteger64 */
		NULL,				/* get_value_sinteger64 */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		cmp_gt,
		cmp_ge,
		cmp_lt,
		cmp_le,
		cmp_bitwise_and,
		cmp_contains,
		CMP_MATCHES,

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
		vines_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		bytes_to_repr,			/* val_to_string_repr */
		bytes_repr_len,			/* len_string_repr */

		NULL,				/* set_value_byte_array */
		vines_fvalue_set,		/* set_value_bytes */
		NULL,				/* set_value_guid */
		NULL,				/* set_value_time */
		NULL,				/* set_value_string */
		NULL,				/* set_value_protocol */
		NULL,				/* set_value_uinteger */
		NULL,				/* set_value_integer */
		NULL,				/* set_value_uinteger64 */
		NULL,				/* set_value_sinteger64 */
		NULL,				/* set_value_floating */

		value_get,			/* get_value */
		NULL,				/* set_value_uinteger */
		NULL,				/* get_value_integer */
		NULL,				/* get_value_uinteger64 */
		NULL,				/* get_value_sinteger64 */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		cmp_gt,
		cmp_ge,
		cmp_lt,
		cmp_le,
		cmp_bitwise_and,
		cmp_contains,
		CMP_MATCHES,

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
		ether_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		bytes_to_repr,			/* val_to_string_repr */
		bytes_repr_len,			/* len_string_repr */

		NULL,				/* set_value_byte_array */
		ether_fvalue_set,		/* set_value_bytes */
		NULL,				/* set_value_guid */
		NULL,				/* set_value_time */
		NULL,				/* set_value_string */
		NULL,				/* set_value_protocol */
		NULL,				/* set_value_uinteger */
		NULL,				/* set_value_sinteger */
		NULL,				/* set_value_uinteger64 */
		NULL,				/* set_value_sinteger64 */
		NULL,				/* set_value_floating */

		value_get,			/* get_value */
		NULL,				/* get_value_uinteger */
		NULL,				/* get_value_sinteger */
		NULL,				/* get_value_uinteger64 */
		NULL,				/* get_value_sinteger64 */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		cmp_gt,
		cmp_ge,
		cmp_lt,
		cmp_le,
		cmp_bitwise_and,
		cmp_contains,
		CMP_MATCHES,

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
		oid_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		oid_to_repr,			/* val_to_string_repr */
		oid_repr_len,			/* len_string_repr */

		oid_fvalue_set,		/* set_value_byte_array */
		NULL,				/* set_value_bytes */
		NULL,				/* set_value_guid */
		NULL,				/* set_value_time */
		NULL,				/* set_value_string */
		NULL,				/* set_value_protocol */
		NULL,				/* set_value_uinteger */
		NULL,				/* set_value_sinteger */
		NULL,				/* set_value_uinteger64 */
		NULL,				/* set_value_sinteger64 */
		NULL,				/* set_value_floating */

		value_get,			/* get_value */
		NULL,				/* get_value_uinteger */
		NULL,				/* get_value_sinteger */
		NULL,				/* get_value_uinteger64 */
		NULL,				/* get_value_sinteger64 */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		cmp_gt,
		cmp_ge,
		cmp_lt,
		cmp_le,
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
		rel_oid_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		rel_oid_to_repr,		/* val_to_string_repr */
		rel_oid_repr_len,		/* len_string_repr */

		oid_fvalue_set,		/* set_value_byte_array (same as full oid) */
		NULL,				/* set_value_bytes */
		NULL,				/* set_value_guid */
		NULL,				/* set_value_time */
		NULL,				/* set_value_string */
		NULL,				/* set_value_protocol */
		NULL,				/* set_value_uinteger */
		NULL,				/* set_value_sinteger */
		NULL,				/* set_value_uinteger64 */
		NULL,				/* set_value_sinteger64 */
		NULL,				/* set_value_floating */

		value_get,			/* get_value */
		NULL,				/* get_value_uinteger */
		NULL,				/* get_value_sinteger */
		NULL,				/* get_value_uinteger64 */
		NULL,				/* get_value_sinteger64 */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		cmp_gt,
		cmp_ge,
		cmp_lt,
		cmp_le,
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
		system_id_from_unparsed,	/* val_from_unparsed */
		NULL,				/* val_from_string */
		system_id_to_repr,		/* val_to_string_repr */
		bytes_repr_len,			/* len_string_repr */

		system_id_fvalue_set,	/* set_value_byte_array */
		NULL,				/* set_value_bytes */
		NULL,				/* set_value_guid */
		NULL,				/* set_value_time */
		NULL,				/* set_value_string */
		NULL,				/* set_value_protocol */
		NULL,				/* set_value_uinteger */
		NULL,				/* set_value_sinteger */
		NULL,				/* set_value_uinteger64 */
		NULL,				/* set_value_sinteger64 */
		NULL,				/* set_value_floating */

		value_get,			/* get_value */
		NULL,				/* get_value_uinteger */
		NULL,				/* get_value_sinteger */
		NULL,				/* get_value_uinteger64 */
		NULL,				/* get_value_sinteger64 */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		cmp_gt,
		cmp_ge,
		cmp_lt,
		cmp_le,
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
		fcwwn_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		bytes_to_repr,			/* val_to_string_repr */
		bytes_repr_len,			/* len_string_repr */

		NULL,				/* set_value_byte_array */
		fcwwn_fvalue_set,		/* set_value_bytes */
		NULL,				/* set_value_guid */
		NULL,				/* set_value_time */
		NULL,				/* set_value_string */
		NULL,				/* set_value_protocol */
		NULL,				/* set_value_uinteger */
		NULL,				/* set_value_sinteger */
		NULL,				/* set_value_uinteger64 */
		NULL,				/* set_value_sinteger64 */
		NULL,				/* set_value_floating */

		value_get,			/* get_value */
		NULL,				/* get_value_uinteger */
		NULL,				/* get_value_sinteger */
		NULL,				/* get_value_uinteger64 */
		NULL,				/* get_value_sinteger64 */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		cmp_gt,
		cmp_ge,
		cmp_lt,
		cmp_le,
		cmp_bitwise_and,
		cmp_contains,
		CMP_MATCHES,

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
