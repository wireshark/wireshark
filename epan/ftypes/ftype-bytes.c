/* 
 * $Id: ftype-bytes.c,v 1.7 2001/11/02 10:09:51 guy Exp $
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
#include "resolv.h"
#include "../../int-64bit.h"

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
val_from_string(fvalue_t *fv, char *s, LogFunc log)
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
		if (log != NULL)
			log("\"%s\" is not a valid byte string.", s);
		g_byte_array_free(bytes, TRUE);
		return FALSE;
	}

	fv->value.bytes = bytes;


	return TRUE;
}

static gboolean
ether_from_string(fvalue_t *fv, char *s, LogFunc log)
{
	guint8	*mac;

	/*
	 * Don't log a message if this fails; we'll try looking it
	 * up as an Ethernet host name if it does, and if that fails,
	 * we'll log a message.
	 */
	if (val_from_string(fv, s, NULL)) {
		return TRUE;
	}

	mac = get_ether_addr(s);
	if (!mac) {
		log("\"%s\" is not a valid hostname or Ethernet address.", s);
		return FALSE;
	}

	ether_fvalue_set(fv, mac, FALSE);
	return TRUE;
}

static gboolean
ipv6_from_string(fvalue_t *fv, char *s, LogFunc log)
{
	guint8	buffer[16];

	if (!get_host_ipaddr6(s, (struct e_in6_addr*)buffer)) {
		log("\"%s\" is not a valid hostname or IPv6 address.", s);
		return FALSE;
	}

	ipv6_fvalue_set(fv, buffer, FALSE);
	return TRUE;
}

static gboolean
u64_from_string(fvalue_t *fv, char *s, LogFunc log)
{
	guint8	buffer[8];

	if (atou64(s, buffer) == NULL) {
		log("\"%s\" is not a valid integer", s);
		return FALSE;
	}

	u64_fvalue_set(fv, buffer, FALSE);
	return TRUE;
}

static gboolean
i64_from_string(fvalue_t *fv, char *s, LogFunc log)
{
	guint8	buffer[8];

	if (atoi64(s, buffer) == NULL) {
		log("\"%s\" is not a valid integer", s);
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
		"FT_BYTES",
		"sequence of bytes",
		0,
		bytes_fvalue_new,
		bytes_fvalue_free,
		val_from_string,

		bytes_fvalue_set,
		NULL,
		NULL,

		value_get,
		NULL,
		NULL,

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
		"FT_ETHER",
		"Ethernet or other MAC address",
		ETHER_LEN,
		bytes_fvalue_new,
		bytes_fvalue_free,
		ether_from_string,

		ether_fvalue_set,
		NULL,
		NULL,

		value_get,
		NULL,
		NULL,

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
		"FT_IPv6",
		"IPv6 address",
		IPv6_LEN,
		bytes_fvalue_new,
		bytes_fvalue_free,
		ipv6_from_string,

		ipv6_fvalue_set,
		NULL,
		NULL,

		value_get,
		NULL,
		NULL,

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
		"FT_UINT64",
		"Unsigned 64-bit integer",
		U64_LEN,
		bytes_fvalue_new,
		bytes_fvalue_free,
		u64_from_string,

		u64_fvalue_set,
		NULL,
		NULL,

		value_get,
		NULL,
		NULL,

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
		"FT_INT64",
		"Signed 64-bit integer",
		U64_LEN,
		bytes_fvalue_new,
		bytes_fvalue_free,
		i64_from_string,

		u64_fvalue_set,
		NULL,
		NULL,

		value_get,
		NULL,
		NULL,

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
	ftype_register(FT_ETHER, &ether_type);
	ftype_register(FT_IPv6, &ipv6_type);
	ftype_register(FT_UINT64, &u64_type);
	ftype_register(FT_INT64, &i64_type);
}
