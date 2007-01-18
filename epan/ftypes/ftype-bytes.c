/*
 * $Id$
 *
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ftypes-int.h>
#include <string.h>
#include <ctype.h>
#include <epan/addr_resolv.h>
#include <epan/strutil.h>

#ifdef HAVE_LIBPCRE
#include <pcre.h>
#define CMP_MATCHES cmp_matches
#else
#define CMP_MATCHES NULL
#endif

#define ETHER_LEN	6
#define IPv6_LEN	16

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
bytes_fvalue_set(fvalue_t *fv, gpointer value, gboolean already_copied)
{
	g_assert(already_copied);

	/* Free up the old value, if we have one */
	bytes_fvalue_free(fv);

	fv->value.bytes = value;
}

static int
bytes_repr_len(fvalue_t *fv, ftrepr_t rtype _U_)
{
	if (fv->value.bytes->len == 0) {
		/* Empty array of bytes, so the representation
		 * is an empty string. */
		return 0;
	} else {
		/* 3 bytes for each byte of the byte "NN:" minus 1 byte
		 * as there's no trailing ":". */
		return fv->value.bytes->len * 3 - 1;
	}
}

static int
oid_repr_len(fvalue_t *fv _U_, ftrepr_t rtype _U_)
{
	/* more exact computation will come later */
	return fv->value.bytes->len * 3 + 16;
}

static void
oid_to_repr(fvalue_t *fv, ftrepr_t rtype _U_, char *buf)
{
	oid_to_str_buf(fv->value.bytes->data, fv->value.bytes->len, buf, oid_repr_len(fv, rtype));
}

static void
bytes_to_repr(fvalue_t *fv, ftrepr_t rtype _U_, char *buf)
{
	guint8 *c;
	char *write_cursor;
	unsigned int i;

	c = fv->value.bytes->data;
	write_cursor = buf;

	for (i = 0; i < fv->value.bytes->len; i++) {
		if (i == 0) {
			sprintf(write_cursor, "%02x", *c++);
			write_cursor += 2;
		}
		else {
			sprintf(write_cursor, ":%02x", *c++);
			write_cursor += 3;
		}
	}
}

static void
common_fvalue_set(fvalue_t *fv, guint8* data, guint len)
{
	/* Free up the old value, if we have one */
	bytes_fvalue_free(fv);

	fv->value.bytes = g_byte_array_new();
	g_byte_array_append(fv->value.bytes, data, len);
}

static void
ether_fvalue_set(fvalue_t *fv, gpointer value, gboolean already_copied)
{
	g_assert(!already_copied);
	common_fvalue_set(fv, value, ETHER_LEN);
}

static void
ipv6_fvalue_set(fvalue_t *fv, gpointer value, gboolean already_copied)
{
	g_assert(!already_copied);
	common_fvalue_set(fv, value, IPv6_LEN);
}

static void
oid_fvalue_set(fvalue_t *fv, gpointer value, gboolean already_copied)
{
	g_assert(already_copied);

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
bytes_from_string(fvalue_t *fv, char *s, LogFunc logfunc _U_)
{
	GByteArray	*bytes;

	bytes = g_byte_array_new();

	g_byte_array_append(bytes, (guint8 *)s, strlen(s));

	/* Free up the old value, if we have one */
	bytes_fvalue_free(fv);
	fv->value.bytes = bytes;

	return TRUE;
}

static gboolean
bytes_from_unparsed(fvalue_t *fv, char *s, gboolean allow_partial_value _U_, LogFunc logfunc)
{
	GByteArray	*bytes;
	gboolean	res;

	bytes = g_byte_array_new();

	res = hex_str_to_bytes(s, bytes, TRUE);

	if (!res) {
		if (logfunc != NULL)
			logfunc("\"%s\" is not a valid byte string.", s);
		g_byte_array_free(bytes, TRUE);
		return FALSE;
	}

	/* Free up the old value, if we have one */
	bytes_fvalue_free(fv);

	fv->value.bytes = bytes;

	return TRUE;
}

static gboolean
ether_from_unparsed(fvalue_t *fv, char *s, gboolean allow_partial_value, LogFunc logfunc)
{
	guint8	*mac;

	/*
	 * Don't log a message if this fails; we'll try looking it
	 * up as an Ethernet host name if it does, and if that fails,
	 * we'll log a message.
	 */
	if (bytes_from_unparsed(fv, s, TRUE, NULL)) {
		if (fv->value.bytes->len > ETHER_LEN) {
			logfunc("\"%s\" contains too many bytes to be a valid Ethernet address.",
			    s);
			return FALSE;
		}
		else if (fv->value.bytes->len < ETHER_LEN && !allow_partial_value) {
			logfunc("\"%s\" contains too few bytes to be a valid Ethernet address.",
			    s);
			return FALSE;
		}

		return TRUE;
	}

	mac = get_ether_addr(s);
	if (!mac) {
		logfunc("\"%s\" is not a valid hostname or Ethernet address.",
		    s);
		return FALSE;
	}

	ether_fvalue_set(fv, mac, FALSE);
	return TRUE;
}

static gboolean
ipv6_from_unparsed(fvalue_t *fv, char *s, gboolean allow_partial_value _U_, LogFunc logfunc)
{
	guint8	buffer[16];

	if (!get_host_ipaddr6(s, (struct e_in6_addr*)buffer)) {
		logfunc("\"%s\" is not a valid hostname or IPv6 address.", s);
		return FALSE;
	}

	ipv6_fvalue_set(fv, buffer, FALSE);
	return TRUE;
}

static int
ipv6_repr_len(fvalue_t *fv _U_, ftrepr_t rtype _U_)
{
	/*
	 * 39 characters for "XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX".
	 */
	return 39;
}

static void
ipv6_to_repr(fvalue_t *fv, ftrepr_t rtype _U_, char *buf)
{
	ip6_to_str_buf((struct e_in6_addr *)fv->value.bytes->data, buf);
}

static gboolean
oid_from_unparsed(fvalue_t *fv, char *s, gboolean allow_partial_value _U_, LogFunc logfunc)
{
	GByteArray	*bytes;
	gboolean	res;


	/*
	 * Don't log a message if this fails; we'll try looking it
	 * up as an OID if it does, and if that fails,
	 * we'll log a message.
	 */
	/* do not try it as '.' is handled as valid separator for hexbytes :(
	if (bytes_from_unparsed(fv, s, TRUE, NULL)) {
		return TRUE;
	}
	*/

	bytes = g_byte_array_new();
	res = oid_str_to_bytes(s, bytes);
	if (!res) {
		if (logfunc != NULL)
			logfunc("\"%s\" is not a valid OBJECT IDENTIFIER.", s);
		g_byte_array_free(bytes, TRUE);
		return FALSE;
	}

	/* Free up the old value, if we have one */
	bytes_fvalue_free(fv);
	fv->value.bytes = bytes;

	return TRUE;
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
cmp_eq(fvalue_t *fv_a, fvalue_t *fv_b)
{
	GByteArray	*a = fv_a->value.bytes;
	GByteArray	*b = fv_b->value.bytes;

	if (a->len != b->len) {
		return FALSE;
	}

	return (memcmp(a->data, b->data, a->len) == 0);
}


static gboolean
cmp_ne(fvalue_t *fv_a, fvalue_t *fv_b)
{
	GByteArray	*a = fv_a->value.bytes;
	GByteArray	*b = fv_b->value.bytes;

	if (a->len != b->len) {
		return FALSE;
	}

	return (memcmp(a->data, b->data, a->len) != 0);
}


static gboolean
cmp_gt(fvalue_t *fv_a, fvalue_t *fv_b)
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
cmp_ge(fvalue_t *fv_a, fvalue_t *fv_b)
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
cmp_lt(fvalue_t *fv_a, fvalue_t *fv_b)
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
cmp_le(fvalue_t *fv_a, fvalue_t *fv_b)
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

static gboolean cmp_bytes_bitwise_and(fvalue_t *fv_a, fvalue_t *fv_b)
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
			i++;
		else
			return FALSE;
	}
	return TRUE;
}

static gboolean
cmp_contains(fvalue_t *fv_a, fvalue_t *fv_b)
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

#ifdef HAVE_LIBPCRE
static gboolean
cmp_matches(fvalue_t *fv_a, fvalue_t *fv_b)
{
	GString *a = fv_a->value.gstring;
	pcre_tuple_t *pcre = fv_b->value.re;
	int options = 0;
	int rc;

	/* fv_b is always a FT_PCRE, otherwise the dfilter semcheck() would have
	 * warned us. For the same reason (and because we're using g_malloc()),
	 * fv_b->value.re is not NULL.
	 */
	if (strcmp(fv_b->ftype->name, "FT_PCRE") != 0) {
		return FALSE;
	}
	if (! pcre) {
		return FALSE;
	}
	rc = pcre_exec(
		pcre->re,	/* Compiled PCRE */
		pcre->ex,	/* PCRE extra from pcre_study() */
		a->str,		/* The data to check for the pattern... */
		a->len,		/* ... and its length */
		0,			/* Start offset within data */
		options,	/* PCRE options */
		NULL,		/* We are not interested in the matched string */
		0			/* of the pattern; only in success or failure. */
		);
	/* NOTE - DO NOT g_free(data) */
	if (rc == 0) {
		return TRUE;
	}
	return FALSE;
}
#endif

void
ftype_register_bytes(void)
{

	static ftype_t bytes_type = {
		FT_BYTES,			/* ftype */
		"FT_BYTES",			/* name */
		"sequence of bytes",		/* pretty_name */
		0,				/* wire_size */
		bytes_fvalue_new,		/* new_value */
		bytes_fvalue_free,		/* free_value */
		bytes_from_unparsed,		/* val_from_unparsed */
		bytes_from_string,		/* val_from_string */
		bytes_to_repr,			/* val_to_string_repr */
		bytes_repr_len,			/* len_string_repr */

		bytes_fvalue_set,		/* set_value */
		NULL,				/* set_value_uinteger */
		NULL,				/* set_value_sinteger */
		NULL,				/* set_value_integer64 */
		NULL,				/* set_value_floating */

		value_get,			/* get_value */
		NULL,				/* get_value_uinteger */
		NULL,				/* get_value_sinteger */
		NULL,				/* get_value_integer64 */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		cmp_gt,
		cmp_ge,
		cmp_lt,
		cmp_le,
		cmp_bytes_bitwise_and,
		cmp_contains,
		CMP_MATCHES,

		len,
		slice,
	};

	static ftype_t uint_bytes_type = {
		FT_UINT_BYTES,		/* ftype */
		"FT_UINT_BYTES",		/* name */
		"sequence of bytes",		/* pretty_name */
		0,				/* wire_size */
		bytes_fvalue_new,		/* new_value */
		bytes_fvalue_free,		/* free_value */
		bytes_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		bytes_to_repr,			/* val_to_string_repr */
		bytes_repr_len,			/* len_string_repr */

		bytes_fvalue_set,		/* set_value */
		NULL,				/* set_value_uinteger */
		NULL,				/* set_value_sinteger */
		NULL,				/* set_value_integer64 */
		NULL,				/* set_value_floating */

		value_get,			/* get_value */
		NULL,				/* get_value_uinteger */
		NULL,				/* get_value_sinteger */
		NULL,				/* get_value_integer64 */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		cmp_gt,
		cmp_ge,
		cmp_lt,
		cmp_le,
		cmp_bytes_bitwise_and,
		cmp_contains,
		NULL,				/* cmp_matches */

		len,
		slice,
	};

	static ftype_t ether_type = {
		FT_ETHER,			/* ftype */
		"FT_ETHER",			/* name */
		"Ethernet or other MAC address",/* pretty_name */
		ETHER_LEN,			/* wire_size */
		bytes_fvalue_new,		/* new_value */
		bytes_fvalue_free,		/* free_value */
		ether_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		bytes_to_repr,			/* val_to_string_repr */
		bytes_repr_len,			/* len_string_repr */

		ether_fvalue_set,		/* set_value */
		NULL,				/* set_value_uinteger */
		NULL,				/* set_value_sinteger */
		NULL,				/* set_value_integer64 */
		NULL,				/* set_value_floating */

		value_get,			/* get_value */
		NULL,				/* get_value_uinteger */
		NULL,				/* get_value_sinteger */
		NULL,				/* get_value_integer64 */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		cmp_gt,
		cmp_ge,
		cmp_lt,
		cmp_le,
		cmp_bytes_bitwise_and,
		cmp_contains,
		CMP_MATCHES,

		len,
		slice,
	};

	static ftype_t ipv6_type = {
		FT_IPv6,			/* ftype */
		"FT_IPv6",			/* name */
		"IPv6 address",			/* pretty_name */
		IPv6_LEN,			/* wire_size */
		bytes_fvalue_new,		/* new_value */
		bytes_fvalue_free,		/* free_value */
		ipv6_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		ipv6_to_repr,			/* val_to_string_repr */
		ipv6_repr_len,			/* len_string_repr */

		ipv6_fvalue_set,		/* set_value */
		NULL,				/* set_value_uinteger */
		NULL,				/* set_value_sinteger */
		NULL,				/* set_value_integer64 */
		NULL,				/* set_value_floating */

		value_get,			/* get_value */
		NULL,				/* get_value_uinteger */
		NULL,				/* get_value_sinteger */
		NULL,				/* get_value_integer64 */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		cmp_gt,
		cmp_ge,
		cmp_lt,
		cmp_le,
		cmp_bytes_bitwise_and,
		cmp_contains,
		NULL,				/* cmp_matches */

		len,
		slice,
	};

	static ftype_t oid_type = {
		FT_OID,			/* ftype */
		"OID",			/* name */
		"OBJECT IDENTIFIER",			/* pretty_name */
		0,			/* wire_size */
		bytes_fvalue_new,		/* new_value */
		bytes_fvalue_free,		/* free_value */
		oid_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		oid_to_repr,			/* val_to_string_repr */
		oid_repr_len,			/* len_string_repr */

		oid_fvalue_set,		/* set_value */
		NULL,				/* set_value_uinteger */
		NULL,				/* set_value_sinteger */
		NULL,				/* set_value_integer64 */
		NULL,				/* set_value_floating */

		value_get,			/* get_value */
		NULL,				/* get_value_uinteger */
		NULL,				/* get_value_sinteger */
		NULL,				/* get_value_integer64 */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		cmp_gt,
		cmp_ge,
		cmp_lt,
		cmp_le,
		cmp_bytes_bitwise_and,
		cmp_contains,
		NULL,				/* cmp_matches */

		len,
		slice,
	};

	ftype_register(FT_BYTES, &bytes_type);
	ftype_register(FT_UINT_BYTES, &uint_bytes_type);
	ftype_register(FT_ETHER, &ether_type);
	ftype_register(FT_IPv6, &ipv6_type);
	ftype_register(FT_OID, &oid_type);
}
