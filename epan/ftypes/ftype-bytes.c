/*
 * $Id: ftype-bytes.c,v 1.16 2003/07/25 03:44:02 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
#include <epan/resolv.h>
#include <epan/int-64bit.h>

#define ETHER_LEN	6
#define IPv6_LEN	16
#define U64_LEN		8

static void
bytes_fvalue_new(fvalue_t *fv)
{
	fv->value.bytes = NULL;
}

void
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
	fv->value.bytes = value;
}

static int
bytes_repr_len(fvalue_t *fv, ftrepr_t rtype _U_)
{
	/* 3 bytes for each byte of the byte "NN:" minus 1 byte
	 * as there's no trailing ":". */
	return fv->value.bytes->len * 3 - 1;
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
u64_fvalue_set(fvalue_t *fv, gpointer value, gboolean already_copied)
{
	g_assert(!already_copied);
	common_fvalue_set(fv, value, U64_LEN);
}

static gpointer
value_get(fvalue_t *fv)
{
	return fv->value.bytes->data;
}

static gboolean
is_byte_sep(guint8 c)
{
	return (c == '-' || c == ':' || c == '.');
}

static gboolean
val_from_unparsed(fvalue_t *fv, char *s, LogFunc logfunc)
{
	GByteArray	*bytes;
	guint8		val;
	guchar		*p, *q, *punct;
	char		two_digits[3];
	char		one_digit[2];
	gboolean	fail = FALSE;

	bytes = g_byte_array_new();

	p = (guchar *)s;
	while (*p) {
		q = p+1;
		if (*q && isxdigit(*p) && isxdigit(*q)) {
			two_digits[0] = *p;
			two_digits[1] = *q;
			two_digits[2] = '\0';

			/*
			 * Two or more hex digits in a row.
			 * "strtoul()" will succeed, as it'll see at
			 * least one hex digit.
			 */
			val = (guint8) strtoul(two_digits, NULL, 16);
			g_byte_array_append(bytes, &val, 1);
			punct = q + 1;
			if (*punct) {
				/*
				 * Make sure the character after
				 * the second hex digit is a byte
				 * separator, i.e. that we don't have
				 * more than two hex digits, or a
				 * bogus character.
				 */
				if (is_byte_sep(*punct)) {
					p = punct + 1;
					continue;
				}
				else {
					fail = TRUE;
					break;
				}
			}
			else {
				p = punct;
				continue;
			}
		}
		else if (*q && isxdigit(*p) && is_byte_sep(*q)) {
			one_digit[0] = *p;
			one_digit[1] = '\0';

			/*
			 * Only one hex digit.
			 * "strtoul()" will succeed, as it'll see that
			 * hex digit.
			 */
			val = (guint8) strtoul(one_digit, NULL, 16);
			g_byte_array_append(bytes, &val, 1);
			p = q + 1;
			continue;
		}
		else if (!*q && isxdigit(*p)) {
			one_digit[0] = *p;
			one_digit[1] = '\0';

			/*
			 * Only one hex digit.
			 * "strtoul()" will succeed, as it'll see that
			 * hex digit.
			 */
			val = (guint8) strtoul(one_digit, NULL, 16);
			g_byte_array_append(bytes, &val, 1);
			p = q;
			continue;
		}
		else {
			fail = TRUE;
			break;
		}
	}

	if (fail) {
		if (logfunc != NULL)
			logfunc("\"%s\" is not a valid byte string.", s);
		g_byte_array_free(bytes, TRUE);
		return FALSE;
	}

	fv->value.bytes = bytes;


	return TRUE;
}

static gboolean
ether_from_unparsed(fvalue_t *fv, char *s, LogFunc logfunc)
{
	guint8	*mac;

	/*
	 * Don't log a message if this fails; we'll try looking it
	 * up as an Ethernet host name if it does, and if that fails,
	 * we'll log a message.
	 */
	if (val_from_unparsed(fv, s, NULL)) {
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
ipv6_from_unparsed(fvalue_t *fv, char *s, LogFunc logfunc)
{
	guint8	buffer[16];

	if (!get_host_ipaddr6(s, (struct e_in6_addr*)buffer)) {
		logfunc("\"%s\" is not a valid hostname or IPv6 address.", s);
		return FALSE;
	}

	ipv6_fvalue_set(fv, buffer, FALSE);
	return TRUE;
}

static gboolean
u64_from_unparsed(fvalue_t *fv, char *s, LogFunc logfunc)
{
	guint8	buffer[8];

	if (atou64(s, buffer) == NULL) {
		logfunc("\"%s\" is not a valid integer", s);
		return FALSE;
	}

	u64_fvalue_set(fv, buffer, FALSE);
	return TRUE;
}

static gboolean
i64_from_unparsed(fvalue_t *fv, char *s, LogFunc logfunc)
{
	guint8	buffer[8];

	if (atoi64(s, buffer) == NULL) {
		logfunc("\"%s\" is not a valid integer", s);
		return FALSE;
	}

	u64_fvalue_set(fv, buffer, FALSE);
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

static gboolean
cmp_gt_i64(fvalue_t *fv_a, fvalue_t *fv_b)
{
	GByteArray	*a = fv_a->value.bytes;
	GByteArray	*b = fv_b->value.bytes;

	if (a->len > b->len) {
		return TRUE;
	}

	if (a->len < b->len) {
		return FALSE;
	}

	if ((a->data[0] & 0x80) == 0) {
		/*
		 * "a" is positive.
		 */
		if (b->data[0] & 0x80) {
			/*
			 * "b" is negative, so a > b.
			 */
			return TRUE;
		}
	} else {
		/*
		 * "a" is negative.
		 */
		if ((b->data[0] & 0x80) == 0) {
			/*
			 * "b" is positive, so a < b.
			 */
			return FALSE;
		}
	}

	/*
	 * "a" and "b" have the same sign, so "memcmp()" should
	 * give the right answer.
	 */
	return (memcmp(a->data, b->data, a->len) > 0);
}

static gboolean
cmp_ge_i64(fvalue_t *fv_a, fvalue_t *fv_b)
{
	GByteArray	*a = fv_a->value.bytes;
	GByteArray	*b = fv_b->value.bytes;

	if (a->len > b->len) {
		return TRUE;
	}

	if (a->len < b->len) {
		return FALSE;
	}

	if ((a->data[0] & 0x80) == 0) {
		/*
		 * "a" is positive.
		 */
		if (b->data[0] & 0x80) {
			/*
			 * "b" is negative, so a > b.
			 */
			return TRUE;
		}
	} else {
		/*
		 * "a" is negative.
		 */
		if ((b->data[0] & 0x80) == 0) {
			/*
			 * "b" is positive, so a < b.
			 */
			return FALSE;
		}
	}

	/*
	 * "a" and "b" have the same sign, so "memcmp()" should
	 * give the right answer.
	 */
	return (memcmp(a->data, b->data, a->len) >= 0);
}

static gboolean
cmp_lt_i64(fvalue_t *fv_a, fvalue_t *fv_b)
{
	GByteArray	*a = fv_a->value.bytes;
	GByteArray	*b = fv_b->value.bytes;

	if (a->len < b->len) {
		return TRUE;
	}

	if (a->len > b->len) {
		return FALSE;
	}

	if (a->data[0] & 0x80) {
		/*
		 * "a" is negative.
		 */
		if ((b->data[0] & 0x80) == 0) {
			/*
			 * "b" is positive, so a < b.
			 */
			return TRUE;
		}
	} else {
		/*
		 * "a" is positive.
		 */
		if (b->data[0] & 0x80) {
			/*
			 * "b" is negative, so a > b.
			 */
			return FALSE;
		}
	}

	/*
	 * "a" and "b" have the same sign, so "memcmp()" should
	 * give the right answer.
	 */
	return (memcmp(a->data, b->data, a->len) < 0);
}

static gboolean
cmp_le_i64(fvalue_t *fv_a, fvalue_t *fv_b)
{
	GByteArray	*a = fv_a->value.bytes;
	GByteArray	*b = fv_b->value.bytes;

	if (a->len < b->len) {
		return TRUE;
	}

	if (a->len > b->len) {
		return FALSE;
	}

	if (a->data[0] & 0x80) {
		/*
		 * "a" is negative.
		 */
		if ((b->data[0] & 0x80) == 0) {
			/*
			 * "b" is positive, so a < b.
			 */
			return TRUE;
		}
	} else {
		/*
		 * "a" is positive.
		 */
		if (b->data[0] & 0x80) {
			/*
			 * "b" is negative, so a > b.
			 */
			return FALSE;
		}
	}

	/*
	 * "a" and "b" have the same sign, so "memcmp()" should
	 * give the right answer.
	 */
	return (memcmp(a->data, b->data, a->len) <= 0);
}

void
ftype_register_bytes(void)
{

	static ftype_t bytes_type = {
		"FT_BYTES",			/* name */
		"sequence of bytes",		/* pretty_name */
		0,				/* wire_size */
		bytes_fvalue_new,		/* new_value */
		bytes_fvalue_free,		/* free_value */
		val_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		bytes_to_repr,			/* val_to_string_repr */
		bytes_repr_len,			/* len_string_repr */

		bytes_fvalue_set,		/* set_value */
		NULL,				/* set_value_integer */
		NULL,				/* set_value_floating */

		value_get,			/* get_value */
		NULL,				/* get_value_integer */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		cmp_gt,
		cmp_ge,
		cmp_lt,
		cmp_le,

		len,
		slice,
	};

	static ftype_t uint_bytes_type = {
		"FT_UINT_BYTES",		/* name */
		"sequence of bytes",		/* pretty_name */
		0,				/* wire_size */
		bytes_fvalue_new,		/* new_value */
		bytes_fvalue_free,		/* free_value */
		val_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		bytes_to_repr,			/* val_to_string_repr */
		bytes_repr_len,			/* len_string_repr */

		bytes_fvalue_set,		/* set_value */
		NULL,				/* set_value_integer */
		NULL,				/* set_value_floating */

		value_get,			/* get_value */
		NULL,				/* get_value_integer */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		cmp_gt,
		cmp_ge,
		cmp_lt,
		cmp_le,

		len,
		slice,
	};

	static ftype_t ether_type = {
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
		NULL,				/* set_value_integer */
		NULL,				/* set_value_floating */

		value_get,			/* get_value */
		NULL,				/* get_value_integer */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		cmp_gt,
		cmp_ge,
		cmp_lt,
		cmp_le,

		len,
		slice,
	};

	static ftype_t ipv6_type = {
		"FT_IPv6",			/* name */
		"IPv6 address",			/* pretty_name */
		IPv6_LEN,			/* wire_size */
		bytes_fvalue_new,		/* new_value */
		bytes_fvalue_free,		/* free_value */
		ipv6_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		NULL,				/* val_to_string_repr */
		NULL,				/* len_string_repr */

		ipv6_fvalue_set,		/* set_value */
		NULL,				/* set_value_integer */
		NULL,				/* set_value_floating */

		value_get,			/* get_value */
		NULL,				/* get_value_integer */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		cmp_gt,
		cmp_ge,
		cmp_lt,
		cmp_le,

		len,
		slice,
	};

	static ftype_t u64_type = {
		"FT_UINT64",			/* name */
		"Unsigned 64-bit integer",	/* pretty_name */
		U64_LEN,			/* wire_size */
		bytes_fvalue_new,		/* new_value */
		bytes_fvalue_free,		/* free_value */
		u64_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		NULL,				/* val_to_string_repr */
		NULL,				/* len_string_repr */

		u64_fvalue_set,			/* set_value */
		NULL,				/* set_value_integer */
		NULL,				/* set_value_floating */

		value_get,			/* get_value */
		NULL,				/* get_value_integer */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		cmp_gt,
		cmp_ge,
		cmp_lt,
		cmp_le,

		len,
		slice,
	};

	static ftype_t i64_type = {
		"FT_INT64",			/* name */
		"Signed 64-bit integer",	/* pretty_name */
		U64_LEN,			/* wire_size */
		bytes_fvalue_new,		/* new_value */
		bytes_fvalue_free,		/* free_value */
		i64_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		NULL,				/* val_to_string_repr */
		NULL,				/* len_string_repr */

		u64_fvalue_set,			/* set_value */
		NULL,				/* set_value_integer */
		NULL,				/* set_value_floating */

		value_get,			/* get_value */
		NULL,				/* get_value_integer */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		cmp_gt_i64,
		cmp_ge_i64,
		cmp_lt_i64,
		cmp_le_i64,

		len,
		slice,
	};

	ftype_register(FT_BYTES, &bytes_type);
	ftype_register(FT_UINT_BYTES, &uint_bytes_type);
	ftype_register(FT_ETHER, &ether_type);
	ftype_register(FT_IPv6, &ipv6_type);
	ftype_register(FT_UINT64, &u64_type);
	ftype_register(FT_INT64, &i64_type);
}
