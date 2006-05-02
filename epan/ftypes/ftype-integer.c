/*
 * $Id$
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

#include <stdlib.h>
#include <errno.h>
#include "ftypes-int.h"
#include <epan/addr_resolv.h>

#ifdef NEED_G_ASCII_STRTOULL_H
#include "g_ascii_strtoull.h"
#endif

/*
 * GLib 1.2[.x] doesn't define G_MAXUINT32 or G_MAXUINT64; if they're
 * not defined, we define them as the maximum 32-bit and 32-bit
 * unsigned numbers.
 */
#ifndef G_MAXUINT32
#define G_MAXUINT32	((guint32)0xFFFFFFFFU)
#endif
#ifndef G_MAXUINT64
#define G_MAXUINT64	((guint64)G_GINT64_CONSTANT(0xFFFFFFFFFFFFFFFFU))
#endif

static void
int_fvalue_new(fvalue_t *fv)
{
	fv->value.integer = 0;
}

static void
set_integer(fvalue_t *fv, guint32 value)
{
	fv->value.integer = value;
}

static guint32
get_integer(fvalue_t *fv)
{
	return fv->value.integer;
}

static gboolean
val_from_unparsed(fvalue_t *fv, char *s, gboolean allow_partial_value _U_, LogFunc logfunc)
{
	unsigned long value;
	char    *endptr;

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
	if (value > G_MAXUINT32) {
		/*
		 * Fits in an unsigned long, but not in a guint32
		 * (an unsigned long might be 64 bits).
		 */
		if (logfunc != NULL)
			logfunc("\"%s\" causes an integer overflow.", s);
		return FALSE;
	}

	fv->value.integer = value;
	return TRUE;
}

static int
integer_repr_len(fvalue_t *fv _U_, ftrepr_t rtype _U_)
{
	return 11;	/* enough for 12^31-1, in decimal */
}

static void
integer_to_repr(fvalue_t *fv, ftrepr_t rtype _U_, char *buf)
{
	sprintf(buf, "%d", fv->value.integer);
}

static int
uinteger_repr_len(fvalue_t *fv _U_, ftrepr_t rtype _U_)
{
	return 10;	/* enough for 2^32-1, in decimal */
}

static void
uinteger_to_repr(fvalue_t *fv, ftrepr_t rtype _U_, char *buf)
{
	sprintf(buf, "%u", fv->value.integer);
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
	if (val_from_unparsed(fv, s, TRUE, NULL)) {
		return TRUE;
	}

	val = get_ipxnet_addr(s, &known);
	if (known) {
		fv->value.integer = val;
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
	sprintf(buf, "0x%08x", fv->value.integer);
}

static gboolean
cmp_eq(fvalue_t *a, fvalue_t *b)
{
	return a->value.integer == b->value.integer;
}

static gboolean
cmp_ne(fvalue_t *a, fvalue_t *b)
{
	return a->value.integer != b->value.integer;
}

static gboolean
u_cmp_gt(fvalue_t *a, fvalue_t *b)
{
	return (int)a->value.integer > (int)b->value.integer;
}

static gboolean
u_cmp_ge(fvalue_t *a, fvalue_t *b)
{
	return (int)a->value.integer >= (int)b->value.integer;
}

static gboolean
u_cmp_lt(fvalue_t *a, fvalue_t *b)
{
	return (int)a->value.integer < (int)b->value.integer;
}

static gboolean
u_cmp_le(fvalue_t *a, fvalue_t *b)
{
	return (int)a->value.integer <= (int)b->value.integer;
}

static gboolean
s_cmp_gt(fvalue_t *a, fvalue_t *b)
{
	return a->value.integer > b->value.integer;
}

static gboolean
s_cmp_ge(fvalue_t *a, fvalue_t *b)
{
	return a->value.integer >= b->value.integer;
}

static gboolean
s_cmp_lt(fvalue_t *a, fvalue_t *b)
{
	return a->value.integer < b->value.integer;
}

static gboolean
s_cmp_le(fvalue_t *a, fvalue_t *b)
{
	return a->value.integer <= b->value.integer;
}

static gboolean
cmp_bitwise_and(fvalue_t *a, fvalue_t *b)
{
	return ((a->value.integer & b->value.integer) != 0);
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
val64_from_unparsed(fvalue_t *fv, char *s, gboolean allow_partial_value _U_, LogFunc logfunc)
{
	guint64 value;
	char    *endptr;

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
	if (value > G_MAXUINT64) {
		/*
		 * Fits in an unsigned long, but not in a guint64
		 * (unlikely, but not impossible).
		 */
		if (logfunc != NULL)
			logfunc("\"%s\" causes an integer overflow.", s);
		return FALSE;
	}

	fv->value.integer64 = value;
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
	sprintf(buf, "%" PRId64, fv->value.integer64);
}

static int
uinteger64_repr_len(fvalue_t *fv _U_, ftrepr_t rtype _U_)
{
	return 20;	/* enough for 2^64-1, in decimal */
}

static void
uinteger64_to_repr(fvalue_t *fv, ftrepr_t rtype _U_, char *buf)
{
	sprintf(buf, "%" PRIu64, fv->value.integer64);
}

static gboolean
cmp_eq64(fvalue_t *a, fvalue_t *b)
{
	return a->value.integer64 == b->value.integer64;
}

static gboolean
cmp_ne64(fvalue_t *a, fvalue_t *b)
{
	return a->value.integer64 != b->value.integer64;
}

static gboolean
u_cmp_gt64(fvalue_t *a, fvalue_t *b)
{
	return (gint64)a->value.integer64 > (gint64)b->value.integer64;
}

static gboolean
u_cmp_ge64(fvalue_t *a, fvalue_t *b)
{
	return (gint64)a->value.integer64 >= (gint64)b->value.integer64;
}

static gboolean
u_cmp_lt64(fvalue_t *a, fvalue_t *b)
{
	return (gint64)a->value.integer64 < (gint64)b->value.integer64;
}

static gboolean
u_cmp_le64(fvalue_t *a, fvalue_t *b)
{
	return (gint64)a->value.integer64 <= (gint64)b->value.integer64;
}

static gboolean
s_cmp_gt64(fvalue_t *a, fvalue_t *b)
{
	return a->value.integer64 > b->value.integer64;
}

static gboolean
s_cmp_ge64(fvalue_t *a, fvalue_t *b)
{
	return a->value.integer64 >= b->value.integer64;
}

static gboolean
s_cmp_lt64(fvalue_t *a, fvalue_t *b)
{
	return a->value.integer64 < b->value.integer64;
}

static gboolean
s_cmp_le64(fvalue_t *a, fvalue_t *b)
{
	return a->value.integer64 <= b->value.integer64;
}

static gboolean
cmp_bitwise_and64(fvalue_t *a, fvalue_t *b)
{
	return ((a->value.integer64 & b->value.integer64) != 0);
}

/* BOOLEAN-specific */

static void
boolean_fvalue_new(fvalue_t *fv)
{
	fv->value.integer = TRUE;
}

static int
boolean_repr_len(fvalue_t *fv _U_, ftrepr_t rtype _U_)
{
	return 1;
}

static void
boolean_to_repr(fvalue_t *fv, ftrepr_t rtype _U_, char *buf)
{
	sprintf(buf, "%s", fv->value.integer ? "1" : "0");
}

/* Checks for equality with zero or non-zero */
static gboolean
bool_eq(fvalue_t *a, fvalue_t *b)
{
	if (a->value.integer) {
		if (b->value.integer) {
			return TRUE;
		}
		else {
			return FALSE;
		}
	}
	else {
		if (b->value.integer) {
			return FALSE;
		}
		else {
			return TRUE;
		}
	}
}

/* Checks for inequality with zero or non-zero */
static gboolean
bool_ne(fvalue_t *a, fvalue_t *b)
{
	return (!bool_eq(a,b));
}



void
ftype_register_integers(void)
{

	static ftype_t uint8_type = {
		FT_UINT8,			/* ftype */
		"FT_UINT8",			/* name */
		"unsigned, 1 byte",		/* pretty name */
		1,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* free_value */
		val_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		uinteger_to_repr,		/* val_to_string_repr */
		uinteger_repr_len,		/* len_string_repr */

		NULL,				/* set_value */
		set_integer,			/* set_value_integer */
		NULL,				/* set_value_integer64 */
		NULL,				/* set_value_floating */

		NULL,				/* get_value */
		get_integer,			/* get_value_integer */
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
		"unsigned, 2 bytes",		/* pretty_name */
		2,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* free_value */
		val_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		uinteger_to_repr,		/* val_to_string_repr */
		uinteger_repr_len,		/* len_string_repr */

		NULL,				/* set_value */
		set_integer,			/* set_value_integer */
		NULL,				/* set_value_integer64 */
		NULL,				/* set_value_floating */

		NULL,				/* get_value */
		get_integer,			/* get_value_integer */
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
		"unsigned, 3 bytes",		/* pretty_name */
		3,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* free_value */
		val_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		uinteger_to_repr,		/* val_to_string_repr */
		uinteger_repr_len,		/* len_string_repr */

		NULL,				/* set_value */
		set_integer,			/* set_value_integer */
		NULL,				/* set_value_integer64 */
		NULL,				/* set_value_floating */

		NULL,				/* get_value */
		get_integer,			/* get_value_integer */
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
		"unsigned, 4 bytes",		/* pretty_name */
		4,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* free_value */
		val_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		uinteger_to_repr,		/* val_to_string_repr */
		uinteger_repr_len,		/* len_string_repr */

		NULL,				/* set_value */
		set_integer,			/* set_value_integer */
		NULL,				/* set_value_integer64 */
		NULL,				/* set_value_floating */

		NULL,				/* get_value */
		get_integer,			/* get_value_integer */
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
		"unsigned, 8 bytes",		/* pretty_name */
		8,				/* wire_size */
		int64_fvalue_new,		/* new_value */
		NULL,				/* free_value */
		val64_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		uinteger64_to_repr,		/* val_to_string_repr */
		uinteger64_repr_len,		/* len_string_repr */

		NULL,				/* set_value */
		NULL,				/* set_value_integer */
		set_integer64,			/* set_value_integer64 */
		NULL,				/* set_value_floating */

		NULL,				/* get_value */
		NULL,				/* get_value_integer */
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
	static ftype_t int8_type = {
		FT_INT8,			/* ftype */
		"FT_INT8",			/* name */
		"signed, 1 byte",		/* pretty_name */
		1,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* free_value */
		val_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		integer_to_repr,		/* val_to_string_repr */
		integer_repr_len,		/* len_string_repr */

		NULL,				/* set_value */
		set_integer,			/* set_value_integer */
		NULL,				/* set_value_integer64 */
		NULL,				/* set_value_floating */

		NULL,				/* get_value */
		get_integer,			/* get_value_integer */
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
		"signed, 2 bytes",		/* pretty_name */
		2,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* free_value */
		val_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		integer_to_repr,		/* val_to_string_repr */
		integer_repr_len,		/* len_string_repr */

		NULL,				/* set_value */
		set_integer,			/* set_value_integer */
		NULL,				/* set_value_integer64 */
		NULL,				/* set_value_floating */

		NULL,				/* get_value */
		get_integer,			/* get_value_integer */
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
		"signed, 3 bytes",		/* pretty_name */
		3,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* free_value */
		val_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		integer_to_repr,		/* val_to_string_repr */
		integer_repr_len,		/* len_string_repr */

		NULL,				/* set_value */
		set_integer,			/* set_value_integer */
		NULL,				/* set_value_integer64 */
		NULL,				/* set_value_floating */

		NULL,				/* get_value */
		get_integer,			/* get_value_integer */
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
		"signed, 4 bytes",		/* pretty_name */
		4,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* free_value */
		val_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		integer_to_repr,		/* val_to_string_repr */
		integer_repr_len,		/* len_string_repr */

		NULL,				/* set_value */
		set_integer,			/* set_value_integer */
		NULL,				/* set_value_integer64 */
		NULL,				/* set_value_floating */

		NULL,				/* get_value */
		get_integer,			/* get_value_integer */
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
		"signed, 8 bytes",		/* pretty_name */
		8,				/* wire_size */
		int64_fvalue_new,		/* new_value */
		NULL,				/* free_value */
		val64_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		integer64_to_repr,		/* val_to_string_repr */
		integer64_repr_len,		/* len_string_repr */

		NULL,				/* set_value */
		NULL,				/* set_value_integer */
		set_integer64,			/* set_value_integer64 */
		NULL,				/* set_value_floating */

		NULL,				/* get_value */
		NULL,				/* get_value_integer */
		get_integer64,			/* get_value_integer64 */
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
		val_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		boolean_to_repr,		/* val_to_string_repr */
		boolean_repr_len,		/* len_string_repr */

		NULL,				/* set_value */
		set_integer,			/* set_value_integer */
		NULL,				/* set_value_integer64 */
		NULL,				/* set_value_floating */

		NULL,				/* get_value */
		get_integer,			/* get_value_integer */
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
		set_integer,			/* set_value_integer */
		NULL,				/* set_value_integer64 */
		NULL,				/* set_value_floating */

		NULL,				/* get_value */
		get_integer,			/* get_value_integer */
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
		"frame number",			/* pretty_name */
		4,				/* wire_size */
		int_fvalue_new,			/* new_value */
		NULL,				/* free_value */
		val_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		uinteger_to_repr,		/* val_to_string_repr */
		uinteger_repr_len,		/* len_string_repr */

		NULL,				/* set_value */
		set_integer,			/* set_value_integer */
		NULL,				/* set_value_integer64 */
		NULL,				/* set_value_floating */

		NULL,				/* get_value */
		get_integer,			/* get_value_integer */
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
}
