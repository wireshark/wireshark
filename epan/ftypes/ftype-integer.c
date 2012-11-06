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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <stdio.h>
#include <errno.h>
#include "ftypes-int.h"
#include <epan/addr_resolv.h>

static void
int_fvalue_new(fvalue_t *fv)
{
	fv->value.uinteger = 0;
}

static void
set_uinteger(fvalue_t *fv, guint32 value)
{
	fv->value.uinteger = value;
}

static void
set_sinteger(fvalue_t *fv, gint32 value)
{
	fv->value.sinteger = value;
}


static guint32
get_uinteger(fvalue_t *fv)
{
	return fv->value.uinteger;
}

static gint32
get_sinteger(fvalue_t *fv)
{
	return fv->value.sinteger;
}


static gboolean
uint_from_unparsed(fvalue_t *fv, char *s, gboolean allow_partial_value _U_, LogFunc logfunc,
		   guint32 max)
{
	unsigned long value;
	char    *endptr;

	if (strchr (s, '-') && strtol(s, NULL, 0) < 0) {
		/*
		 * Probably a negative integer, but will be
		 * "converted in the obvious manner" by strtoul().
		 */
		if (logfunc != NULL)
			logfunc("\"%s\" too small for this field, minimum 0.", s);
		return FALSE;
	}

	errno = 0;
	value = strtoul(s, &endptr, 0);

	if (errno == EINVAL || endptr == s || *endptr != '\0') {
		/* This isn't a valid number. */
		if (logfunc != NULL)
			logfunc("\"%s\" is not a valid number.", s);
		return FALSE;
	}
	if (errno == ERANGE) {
		if (logfunc != NULL) {
			if (value == ULONG_MAX) {
				logfunc("\"%s\" causes an integer overflow.",
				    s);
			}
			else {
				/*
				 * XXX - can "strtoul()" set errno to
				 * ERANGE without returning ULONG_MAX?
				 */
				logfunc("\"%s\" is not an integer.", s);
			}
		}
		return FALSE;
	}

	if (value > max) {
		if (logfunc != NULL)
			logfunc("\"%s\" too big for this field, maximum %u.", s, max);
		return FALSE;
	}

	fv->value.uinteger = (guint32)value;
	return TRUE;
}

static gboolean
uint32_from_unparsed(fvalue_t *fv, char *s, gboolean allow_partial_value, LogFunc logfunc)
{
	return uint_from_unparsed (fv, s, allow_partial_value, logfunc, G_MAXUINT32);
}

static gboolean
uint24_from_unparsed(fvalue_t *fv, char *s, gboolean allow_partial_value, LogFunc logfunc)
{
	return uint_from_unparsed (fv, s, allow_partial_value, logfunc, 0xFFFFFF);
}

static gboolean
uint16_from_unparsed(fvalue_t *fv, char *s, gboolean allow_partial_value, LogFunc logfunc)
{
	return uint_from_unparsed (fv, s, allow_partial_value, logfunc, G_MAXUINT16);
}

static gboolean
uint8_from_unparsed(fvalue_t *fv, char *s, gboolean allow_partial_value, LogFunc logfunc)
{
	return uint_from_unparsed (fv, s, allow_partial_value, logfunc, G_MAXUINT8);
}

static gboolean
sint_from_unparsed(fvalue_t *fv, char *s, gboolean allow_partial_value _U_, LogFunc logfunc,
		   gint32 max, gint32 min)
{
	long value;
	char *endptr;

	if (!strchr (s, '-') && strtoul(s, NULL, 0) > G_MAXINT32) {
		/*
		 * Probably a positive integer > G_MAXINT32, but will be
		 * "converted in the obvious manner" by strtol().
		 */
		if (logfunc != NULL)
			logfunc("\"%s\" causes an integer overflow.", s);
		return FALSE;
	}

	errno = 0;
	value = strtol(s, &endptr, 0);

	if (errno == EINVAL || endptr == s || *endptr != '\0') {
		/* This isn't a valid number. */
		if (logfunc != NULL)
			logfunc("\"%s\" is not a valid number.", s);
		return FALSE;
	}
	if (errno == ERANGE) {
		if (logfunc != NULL) {
			if (value == LONG_MAX) {
				logfunc("\"%s\" causes an integer overflow.", s);
			}
			else if (value == LONG_MIN) {
				logfunc("\"%s\" causes an integer underflow.", s);
			}
			else {
				/*
				 * XXX - can "strtol()" set errno to
				 * ERANGE without returning ULONG_MAX?
				 */
				logfunc("\"%s\" is not an integer.", s);
			}
		}
		return FALSE;
	}

	if (value > max) {
		if (logfunc != NULL)
			logfunc("\"%s\" too big for this field, maximum %d.",
				s, max);
		return FALSE;
	} else if (value < min) {
		if (logfunc != NULL)
			logfunc("\"%s\" too small for this field, minimum %d.",
				s, min);
		return FALSE;
	}

	fv->value.sinteger = (gint32)value;
	return TRUE;
}

static gboolean
sint32_from_unparsed(fvalue_t *fv, char *s, gboolean allow_partial_value, LogFunc logfunc)
{
	return sint_from_unparsed (fv, s, allow_partial_value, logfunc, G_MAXINT32, G_MININT32);
}

static gboolean
sint24_from_unparsed(fvalue_t *fv, char *s, gboolean allow_partial_value, LogFunc logfunc)
{
	return sint_from_unparsed (fv, s, allow_partial_value, logfunc, 0x7FFFFF, -0x800000);
}

static gboolean
sint16_from_unparsed(fvalue_t *fv, char *s, gboolean allow_partial_value, LogFunc logfunc)
{
	return sint_from_unparsed (fv, s, allow_partial_value, logfunc, G_MAXINT16, G_MININT16);
}

static gboolean
sint8_from_unparsed(fvalue_t *fv, char *s, gboolean allow_partial_value, LogFunc logfunc)
{
	return sint_from_unparsed (fv, s, allow_partial_value, logfunc, G_MAXINT8, G_MININT8);
}

static int
integer_repr_len(fvalue_t *fv _U_, ftrepr_t rtype _U_)
{
	return 11;	/* enough for 12^31-1, in decimal */
}

static void
integer_to_repr(fvalue_t *fv, ftrepr_t rtype _U_, char *buf)
{
	guint32 val;

	if (fv->value.sinteger < 0) {
		*buf++ = '-';
		val = -fv->value.sinteger;
	} else
		val = fv->value.sinteger;

	guint32_to_str_buf(val, buf, 11);
}

static int
uinteger_repr_len(fvalue_t *fv _U_, ftrepr_t rtype _U_)
{
	return 10;	/* enough for 2^32-1, in decimal */
}

static void
uinteger_to_repr(fvalue_t *fv, ftrepr_t rtype _U_, char *buf)
{
	guint32_to_str_buf(fv->value.uinteger, buf, 11);
}

static gboolean
ipxnet_from_unparsed(fvalue_t *fv, char *s, gboolean allow_partial_value _U_, LogFunc logfunc)
{
	guint32 	val;
	gboolean	known;

	/*
	 * Don't log a message if this fails; we'll try looking it
	 * up as an IPX network name if it does, and if that fails,
	 * we'll log a message.
	 */
	if (uint32_from_unparsed(fv, s, TRUE, NULL)) {
		return TRUE;
	}

	val = get_ipxnet_addr(s, &known);
	if (known) {
		fv->value.uinteger = val;
		return TRUE;
	}

	logfunc("\"%s\" is not a valid IPX network name or address.", s);
	return FALSE;
}

static int
ipxnet_repr_len(fvalue_t *fv _U_, ftrepr_t rtype _U_)
{
	return 2+8;	/* 0xXXXXXXXX */
}

static void
ipxnet_to_repr(fvalue_t *fv, ftrepr_t rtype _U_, char *buf)
{
	sprintf(buf, "0x%08x", fv->value.uinteger);
}

static gboolean
cmp_eq(const fvalue_t *a, const fvalue_t *b)
{
	return a->value.uinteger == b->value.uinteger;
}

static gboolean
cmp_ne(const fvalue_t *a, const fvalue_t *b)
{
	return a->value.uinteger != b->value.uinteger;
}

static gboolean
u_cmp_gt(const fvalue_t *a, const fvalue_t *b)
{
	return a->value.uinteger > b->value.uinteger;
}

static gboolean
u_cmp_ge(const fvalue_t *a, const fvalue_t *b)
{
	return a->value.uinteger >= b->value.uinteger;
}

static gboolean
u_cmp_lt(const fvalue_t *a, const fvalue_t *b)
{
	return a->value.uinteger < b->value.uinteger;
}

static gboolean
u_cmp_le(const fvalue_t *a, const fvalue_t *b)
{
	return a->value.uinteger <= b->value.uinteger;
}

static gboolean
s_cmp_gt(const fvalue_t *a, const fvalue_t *b)
{
	return a->value.sinteger > b->value.sinteger;
}

static gboolean
s_cmp_ge(const fvalue_t *a, const fvalue_t *b)
{
	return a->value.sinteger >= b->value.sinteger;
}

static gboolean
s_cmp_lt(const fvalue_t *a, const fvalue_t *b)
{
	return a->value.sinteger < b->value.sinteger;
}

static gboolean
s_cmp_le(const fvalue_t *a, const fvalue_t *b)
{
	return a->value.sinteger <= b->value.sinteger;
}

static gboolean
cmp_bitwise_and(const fvalue_t *a, const fvalue_t *b)
{
	return ((a->value.uinteger & b->value.uinteger) != 0);
}

static void
int64_fvalue_new(fvalue_t *fv)
{
	fv->value.integer64 = 0;
}

static void
set_integer64(fvalue_t *fv, guint64 value)
{
	fv->value.integer64 = value;
}

static guint64
get_integer64(fvalue_t *fv)
{
	return fv->value.integer64;
}

static gboolean
uint64_from_unparsed(fvalue_t *fv, char *s, gboolean allow_partial_value _U_, LogFunc logfunc)
{
	guint64 value;
	char    *endptr;

	if (strchr (s, '-') && g_ascii_strtoll(s, NULL, 0) < 0) {
		/*
		 * Probably a negative integer, but will be
		 * "converted in the obvious manner" by g_ascii_strtoull().
		 */
		if (logfunc != NULL)
			logfunc("\"%s\" causes an integer underflow.", s);
		return FALSE;
	}

	errno = 0;
	value = g_ascii_strtoull(s, &endptr, 0);

	if (errno == EINVAL || endptr == s || *endptr != '\0') {
		/* This isn't a valid number. */
		if (logfunc != NULL)
			logfunc("\"%s\" is not a valid number.", s);
		return FALSE;
	}
	if (errno == ERANGE) {
		if (logfunc != NULL) {
			if (value == G_MAXUINT64) {
				logfunc("\"%s\" causes an integer overflow.", s);
			}
			else {
				/*
				 * XXX - can "strtoul()" set errno to
				 * ERANGE without returning ULONG_MAX?
				 */
				logfunc("\"%s\" is not an integer.", s);
			}
		}
		return FALSE;
	}

	fv->value.integer64 = value;
	return TRUE;
}

static gboolean
sint64_from_unparsed(fvalue_t *fv, char *s, gboolean allow_partial_value _U_, LogFunc logfunc)
{
	gint64 value;
	char   *endptr;

	if (!strchr (s, '-') && g_ascii_strtoull(s, NULL, 0) > G_MAXINT64) {
		/*
		 * Probably a positive integer > G_MAXINT64, but will be
		 * "converted in the obvious manner" by g_ascii_strtoll().
		 */
		if (logfunc != NULL)
			logfunc("\"%s\" causes an integer overflow.", s);
		return FALSE;
	}

	errno = 0;
	value = g_ascii_strtoll(s, &endptr, 0);

	if (errno == EINVAL || endptr == s || *endptr != '\0') {
		/* This isn't a valid number. */
		if (logfunc != NULL)
			logfunc("\"%s\" is not a valid number.", s);
		return FALSE;
	}
	if (errno == ERANGE) {
		if (logfunc != NULL) {
			if (value == G_MAXINT64) {
				logfunc("\"%s\" causes an integer overflow.", s);
			}
			else if (value == G_MININT64) {
				logfunc("\"%s\" causes an integer underflow.", s);
			}
			else {
				/*
				 * XXX - can "strtol()" set errno to
				 * ERANGE without returning LONG_MAX?
				 */
				logfunc("\"%s\" is not an integer.", s);
			}
		}
		return FALSE;
	}

	fv->value.integer64 = (guint64)value;
	return TRUE;
}

static int
integer64_repr_len(fvalue_t *fv _U_, ftrepr_t rtype _U_)
{
	return 20;	/* enough for -2^63-1, in decimal */
}

static void
integer64_to_repr(fvalue_t *fv, ftrepr_t rtype _U_, char *buf)
{
	sprintf(buf, "%" G_GINT64_MODIFIER "d", fv->value.integer64);
}

static int
uinteger64_repr_len(fvalue_t *fv _U_, ftrepr_t rtype _U_)
{
	return 20;	/* enough for 2^64-1, in decimal */
}

static void
uinteger64_to_repr(fvalue_t *fv, ftrepr_t rtype _U_, char *buf)
{
	sprintf(buf, "%" G_GINT64_MODIFIER "u", fv->value.integer64);
}

static gboolean
cmp_eq64(const fvalue_t *a, const fvalue_t *b)
{
	return a->value.integer64 == b->value.integer64;
}

static gboolean
cmp_ne64(const fvalue_t *a, const fvalue_t *b)
{
	return a->value.integer64 != b->value.integer64;
}

static gboolean
u_cmp_gt64(const fvalue_t *a, const fvalue_t *b)
{
	return a->value.integer64 > b->value.integer64;
}

static gboolean
u_cmp_ge64(const fvalue_t *a, const fvalue_t *b)
{
	return a->value.integer64 >= b->value.integer64;
}

static gboolean
u_cmp_lt64(const fvalue_t *a, const fvalue_t *b)
{
	return a->value.integer64 < b->value.integer64;
}

static gboolean
u_cmp_le64(const fvalue_t *a, const fvalue_t *b)
{
	return a->value.integer64 <= b->value.integer64;
}

static gboolean
s_cmp_gt64(const fvalue_t *a, const fvalue_t *b)
{
	return (gint64)a->value.integer64 > (gint64)b->value.integer64;
}

static gboolean
s_cmp_ge64(const fvalue_t *a, const fvalue_t *b)
{
	return (gint64)a->value.integer64 >= (gint64)b->value.integer64;
}

static gboolean
s_cmp_lt64(const fvalue_t *a, const fvalue_t *b)
{
	return (gint64)a->value.integer64 < (gint64)b->value.integer64;
}

static gboolean
s_cmp_le64(const fvalue_t *a, const fvalue_t *b)
{
	return (gint64)a->value.integer64 <= (gint64)b->value.integer64;
}

static gboolean
cmp_bitwise_and64(const fvalue_t *a, const fvalue_t *b)
{
	return ((a->value.integer64 & b->value.integer64) != 0);
}

/* BOOLEAN-specific */

static void
boolean_fvalue_new(fvalue_t *fv)
{
	fv->value.uinteger = TRUE;
}

static int
boolean_repr_len(fvalue_t *fv _U_, ftrepr_t rtype _U_)
{
	return 1;
}

static void
boolean_to_repr(fvalue_t *fv, ftrepr_t rtype _U_, char *buf)
{
	*buf++ = (fv->value.uinteger) ? '1' : '0';
	*buf   = '\0';
}

/* Checks for equality with zero or non-zero */
static gboolean
bool_eq(const fvalue_t *a, const fvalue_t *b)
{
	if (a->value.uinteger) {
		if (b->value.uinteger) {
			return TRUE;
		}
		else {
			return FALSE;
		}
	}
	else {
		if (b->value.uinteger) {
			return FALSE;
		}
		else {
			return TRUE;
		}
	}
}

/* Checks for inequality with zero or non-zero */
static gboolean
bool_ne(const fvalue_t *a, const fvalue_t *b)
{
	return (!bool_eq(a,b));
}

/* EUI64-specific */
static gboolean
eui64_from_unparsed(fvalue_t *fv, char *s, gboolean allow_partial_value _U_, LogFunc logfunc)
{

	/*
	 * Don't log a message if this fails; we'll try looking it
	 * up as an EUI64 Address if it does, and if that fails,
	 * we'll log a message.
	 */
	if (uint64_from_unparsed(fv, s, TRUE, NULL)) {
		return TRUE;
	}

	logfunc("\"%s\" is not a valid EUI64 Address", s);
	return FALSE;
}

static int
eui64_repr_len(fvalue_t *fv _U_, ftrepr_t rtype _U_)
{
	return 8*3-1;	/* XX:XX:XX:XX:XX:XX:XX:XX */
}

static void
eui64_to_repr(fvalue_t *fv, ftrepr_t rtype _U_, char *buf)
{
  	guint8 *p_eui64 = (guint8 *)ep_alloc(8);

  	/* Copy and convert the address to network byte order. */
  	*(guint64 *)(void *)(p_eui64) = pntoh64(&(fv->value.integer64));

	g_snprintf(buf, EUI64_STR_LEN, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
	p_eui64[0], p_eui64[1], p_eui64[2], p_eui64[3],
	p_eui64[4], p_eui64[5], p_eui64[6], p_eui64[7] );
}

void
ftype_register_integers(void)
{

	static ftype_t uint8_type = {
		FT_UINT8,			/* ftype */
		"FT_UINT8",			/* name */
		"Unsigned integer, 1 byte",	/* pretty name */
		1,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* free_value */
		uint8_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		uinteger_to_repr,		/* val_to_string_repr */
		uinteger_repr_len,		/* len_string_repr */

		NULL,				/* set_value */
		set_uinteger,		/* set_value_uinteger */
		NULL,				/* set_value_sinteger */
		NULL,				/* set_value_integer64 */
		NULL,				/* set_value_floating */

		NULL,				/* get_value */
		get_uinteger,		/* get_value_uinteger */
		NULL,				/* get_value_sinteger */
		NULL,				/* get_value_integer64 */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		u_cmp_gt,
		u_cmp_ge,
		u_cmp_lt,
		u_cmp_le,
		cmp_bitwise_and,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,				/* len */
		NULL,				/* slice */
	};
	static ftype_t uint16_type = {
		FT_UINT16,			/* ftype */
		"FT_UINT16",			/* name */
		"Unsigned integer, 2 bytes",	/* pretty_name */
		2,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* free_value */
		uint16_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		uinteger_to_repr,		/* val_to_string_repr */
		uinteger_repr_len,		/* len_string_repr */

		NULL,				/* set_value */
		set_uinteger,		/* set_value_uinteger */
		NULL,				/* set_value_sinteger */
		NULL,				/* set_value_integer64 */
		NULL,				/* set_value_floating */

		NULL,				/* get_value */
		get_uinteger,			/* get_value_integer */
		NULL,				/* get_value_sinteger */
		NULL,				/* get_value_integer64 */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		u_cmp_gt,
		u_cmp_ge,
		u_cmp_lt,
		u_cmp_le,
		cmp_bitwise_and,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,				/* len */
		NULL,				/* slice */
	};
	static ftype_t uint24_type = {
		FT_UINT24,			/* ftype */
		"FT_UINT24",			/* name */
		"Unsigned integer, 3 bytes",	/* pretty_name */
		3,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* free_value */
		uint24_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		uinteger_to_repr,		/* val_to_string_repr */
		uinteger_repr_len,		/* len_string_repr */

		NULL,				/* set_value */
		set_uinteger,		/* set_value_integer */
		NULL,				/* set_value_sinteger */
		NULL,				/* set_value_integer64 */
		NULL,				/* set_value_floating */

		NULL,				/* get_value */
		get_uinteger,			/* get_value_integer */
		NULL,				/* get_value_sinteger */
		NULL,				/* get_value_integer64 */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		u_cmp_gt,
		u_cmp_ge,
		u_cmp_lt,
		u_cmp_le,
		cmp_bitwise_and,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,				/* len */
		NULL,				/* slice */
	};
	static ftype_t uint32_type = {
		FT_UINT32,			/* ftype */
		"FT_UINT32",			/* name */
		"Unsigned integer, 4 bytes",	/* pretty_name */
		4,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* free_value */
		uint32_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		uinteger_to_repr,		/* val_to_string_repr */
		uinteger_repr_len,		/* len_string_repr */

		NULL,				/* set_value */
		set_uinteger,		/* set_value_uinteger */
		NULL,				/* set_value_sinteger */
		NULL,				/* set_value_integer64 */
		NULL,				/* set_value_floating */

		NULL,				/* get_value */
		get_uinteger,		/* get_value_integer */
		NULL,				/* get_value_sinteger */
		NULL,				/* get_value_integer64 */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		u_cmp_gt,
		u_cmp_ge,
		u_cmp_lt,
		u_cmp_le,
		cmp_bitwise_and,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,				/* len */
		NULL,				/* slice */
	};
	static ftype_t uint64_type = {
		FT_UINT64,			/* ftype */
		"FT_UINT64",			/* name */
		"Unsigned integer, 8 bytes",	/* pretty_name */
		8,				/* wire_size */
		int64_fvalue_new,		/* new_value */
		NULL,				/* free_value */
		uint64_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		uinteger64_to_repr,		/* val_to_string_repr */
		uinteger64_repr_len,		/* len_string_repr */

		NULL,				/* set_value */
		NULL,				/* set_value_uinteger */
		NULL,				/* set_value_sinteger */
		set_integer64,		/* set_value_integer64 */
		NULL,				/* set_value_floating */

		NULL,				/* get_value */
		NULL,				/* get_value_uinteger */
		NULL,				/* get_value_sinteger */
		get_integer64,		/* get_value_integer64 */
		NULL,				/* get_value_floating */

		cmp_eq64,
		cmp_ne64,
		u_cmp_gt64,
		u_cmp_ge64,
		u_cmp_lt64,
		u_cmp_le64,
		cmp_bitwise_and64,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,
		NULL,
	};
	static ftype_t int8_type = {
		FT_INT8,			/* ftype */
		"FT_INT8",			/* name */
		"Signed integer, 1 byte",	/* pretty_name */
		1,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* free_value */
		sint8_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		integer_to_repr,		/* val_to_string_repr */
		integer_repr_len,		/* len_string_repr */

		NULL,				/* set_value */
		NULL,				/* set_value_uinteger */
		set_sinteger,		/* set_value_sinteger */
		NULL,				/* set_value_integer64 */
		NULL,				/* set_value_floating */

		NULL,				/* get_value */
		NULL,				/* get_value_uinteger */
		get_sinteger,			/* get_value_sinteger */
		NULL,				/* get_value_integer64 */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		s_cmp_gt,
		s_cmp_ge,
		s_cmp_lt,
		s_cmp_le,
		cmp_bitwise_and,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,				/* len */
		NULL,				/* slice */
	};
	static ftype_t int16_type = {
		FT_INT16,			/* ftype */
		"FT_INT16",			/* name */
		"Signed integer, 2 bytes",	/* pretty_name */
		2,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* free_value */
		sint16_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		integer_to_repr,		/* val_to_string_repr */
		integer_repr_len,		/* len_string_repr */

		NULL,				/* set_value */
		NULL,				/* set_value_uinteger */
		set_sinteger,		/* set_value_sinteger */
		NULL,				/* set_value_integer64 */
		NULL,				/* set_value_floating */

		NULL,				/* get_value */
		NULL,				/* get_value_uinteger */
		get_sinteger,		/* get_value_sinteger */
		NULL,				/* get_value_integer64 */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		s_cmp_gt,
		s_cmp_ge,
		s_cmp_lt,
		s_cmp_le,
		cmp_bitwise_and,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,				/* len */
		NULL,				/* slice */
	};
	static ftype_t int24_type = {
		FT_INT24,			/* ftype */
		"FT_INT24",			/* name */
		"Signed integer, 3 bytes",	/* pretty_name */
		3,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* free_value */
		sint24_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		integer_to_repr,		/* val_to_string_repr */
		integer_repr_len,		/* len_string_repr */

		NULL,				/* set_value */
		NULL,				/* set_value_uinteger */
		set_sinteger,		/* set_value_sinteger */
		NULL,				/* set_value_integer64 */
		NULL,				/* set_value_floating */

		NULL,				/* get_value */
		NULL,				/* get_value_uinteger */
		get_sinteger,			/* get_value_integer */
		NULL,				/* get_value_integer64 */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		s_cmp_gt,
		s_cmp_ge,
		s_cmp_lt,
		s_cmp_le,
		cmp_bitwise_and,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,				/* len */
		NULL,				/* slice */
	};
	static ftype_t int32_type = {
		FT_INT32,			/* ftype */
		"FT_INT32",			/* name */
		"Signed integer, 4 bytes",	/* pretty_name */
		4,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* free_value */
		sint32_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		integer_to_repr,		/* val_to_string_repr */
		integer_repr_len,		/* len_string_repr */

		NULL,				/* set_value */
		NULL,				/* set_value_uinteger */
		set_sinteger,		/* set_value_sinteger */
		NULL,				/* set_value_integer64 */
		NULL,				/* set_value_floating */

		NULL,				/* get_value */
		NULL,				/* get_value_uinteger */
		get_sinteger,		/* get_value_sinteger */
		NULL,				/* get_value_integer64 */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		s_cmp_gt,
		s_cmp_ge,
		s_cmp_lt,
		s_cmp_le,
		cmp_bitwise_and,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,				/* len */
		NULL,				/* slice */
	};
	static ftype_t int64_type = {
		FT_INT64,			/* ftype */
		"FT_INT64",			/* name */
		"Signed integer, 8 bytes",	/* pretty_name */
		8,				/* wire_size */
		int64_fvalue_new,		/* new_value */
		NULL,				/* free_value */
		sint64_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		integer64_to_repr,		/* val_to_string_repr */
		integer64_repr_len,		/* len_string_repr */

		NULL,				/* set_value */
		NULL,				/* set_value_uinteger */
		NULL,				/* set_value_sinteger */
		set_integer64,		/* set_value_integer64 */
		NULL,				/* set_value_floating */

		NULL,				/* get_value */
		NULL,				/* get_value_uinteger */
		NULL,				/* get_value_sinteger */
		get_integer64,		/* get_value_integer64 */
		NULL,				/* get_value_floating */

		cmp_eq64,
		cmp_ne64,
		s_cmp_gt64,
		s_cmp_ge64,
		s_cmp_lt64,
		s_cmp_le64,
		cmp_bitwise_and64,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,
		NULL,
	};
	static ftype_t boolean_type = {
		FT_BOOLEAN,			/* ftype */
		"FT_BOOLEAN",			/* name */
		"Boolean",			/* pretty_name */
		0,				/* wire_size */
		boolean_fvalue_new,		/* new_value */
		NULL,				/* free_value */
		uint32_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		boolean_to_repr,		/* val_to_string_repr */
		boolean_repr_len,		/* len_string_repr */

		NULL,				/* set_value */
		set_uinteger,		/* set_value_uinteger */
		NULL,				/* set_value_sinteger */
		NULL,				/* set_value_integer64 */
		NULL,				/* set_value_floating */

		NULL,				/* get_value */
		get_uinteger,		/* get_value_uinteger */
		NULL,				/* get_value_sinteger */
		NULL,				/* get_value_integer64 */
		NULL,				/* get_value_floating */

		bool_eq,			/* cmp_eq */
		bool_ne,			/* cmp_ne */
		NULL,				/* cmp_gt */
		NULL,				/* cmp_ge */
		NULL,				/* cmp_lt */
		NULL,				/* cmp_le */
		NULL,				/* cmp_bitwise_and */
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,				/* len */
		NULL,				/* slice */
	};

	static ftype_t ipxnet_type = {
		FT_IPXNET,			/* ftype */
		"FT_IPXNET",			/* name */
		"IPX network number",		/* pretty_name */
		4,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* free_value */
		ipxnet_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		ipxnet_to_repr,			/* val_to_string_repr */
		ipxnet_repr_len,		/* len_string_repr */

		NULL,				/* set_value */
		set_uinteger,		/* set_value_uinteger */
		NULL,				/* get_value_sinteger */
		NULL,				/* set_value_integer64 */
		NULL,				/* set_value_floating */

		NULL,				/* get_value */
		get_uinteger,		/* get_value_uinteger */
		NULL,				/* get_value_sinteger */
		NULL,				/* get_value_integer64 */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		u_cmp_gt,
		u_cmp_ge,
		u_cmp_lt,
		u_cmp_le,
		cmp_bitwise_and,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,				/* len */
		NULL,				/* slice */
	};

	static ftype_t framenum_type = {
		FT_FRAMENUM,			/* ftype */
		"FT_FRAMENUM",			/* name */
		"Frame number",			/* pretty_name */
		4,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* free_value */
		uint32_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		uinteger_to_repr,		/* val_to_string_repr */
		uinteger_repr_len,		/* len_string_repr */

		NULL,				/* set_value */
		set_uinteger,		/* set_value_uinteger */
		NULL,				/* set_value_sinteger */
		NULL,				/* set_value_integer64 */
		NULL,				/* set_value_floating */

		NULL,				/* get_value */
		get_uinteger,		/* get_value_uinteger */
		NULL,				/* get_value_sinteger */
		NULL,				/* get_value_integer64 */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		u_cmp_gt,
		u_cmp_ge,
		u_cmp_lt,
		u_cmp_le,
		NULL,				/* cmp_bitwise_and */
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,				/* len */
		NULL,				/* slice */
	};

	static ftype_t eui64_type = {
		FT_EUI64,			/* ftype */
		"FT_EUI64",			/* name */
		"EUI64 address",		/* pretty_name */
		FT_EUI64_LEN,			/* wire_size */
		int64_fvalue_new,		/* new_value */
		NULL,				/* free_value */
		eui64_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		eui64_to_repr,		/* val_to_string_repr */
		eui64_repr_len,		/* len_string_repr */

		NULL,				/* set_value */
		NULL,				/* set_value_uinteger */
		NULL,				/* set_value_sinteger */
		set_integer64,			/* set_value_integer64 */
		NULL,				/* set_value_floating */

		NULL,				/* get_value */
		NULL,				/* get_value_uinteger */
		NULL,				/* get_value_sinteger */
		get_integer64,			/* get_value_integer64 */
		NULL,				/* get_value_floating */

		cmp_eq64,
		cmp_ne64,
		u_cmp_gt64,
		u_cmp_ge64,
		u_cmp_lt64,
		u_cmp_le64,
		cmp_bitwise_and64,
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,
		NULL,
	};

	ftype_register(FT_UINT8, &uint8_type);
	ftype_register(FT_UINT16, &uint16_type);
	ftype_register(FT_UINT24, &uint24_type);
	ftype_register(FT_UINT32, &uint32_type);
	ftype_register(FT_UINT64, &uint64_type);
	ftype_register(FT_INT8, &int8_type);
	ftype_register(FT_INT16, &int16_type);
	ftype_register(FT_INT24, &int24_type);
	ftype_register(FT_INT32, &int32_type);
	ftype_register(FT_INT64, &int64_type);
	ftype_register(FT_BOOLEAN, &boolean_type);
	ftype_register(FT_IPXNET, &ipxnet_type);
	ftype_register(FT_FRAMENUM, &framenum_type);
	ftype_register(FT_EUI64, &eui64_type);
}
