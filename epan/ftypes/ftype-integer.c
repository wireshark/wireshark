/*
 * $Id: ftype-integer.c,v 1.3 2001/02/11 03:29:53 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 2001 Gerald Combs
 *
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


#ifdef NEED_SNPRINTF_H
#include "snprintf.h"
#endif

#include <stdlib.h>
#include <errno.h>
#include "ftypes-int.h"
#include "resolv.h"


static void
ftype_from_tvbuff(field_info *fi, tvbuff_t *tvb, int start, int length,
	gboolean little_endian)
{
	/* XXX */
	g_assert_not_reached();
}


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
val_from_string(fvalue_t *fv, char *s, LogFunc log)
{
	char    *endptr;

	fv->value.integer = strtoul(s, &endptr, 0);

	if (endptr == s || *endptr != '\0') {
		/* This isn't a valid number. */
		log("\"%s\" is not a valid number.", s);
		return FALSE;
	}
	if (errno == ERANGE) {
		if (fv->value.integer == ULONG_MAX) {
			log("\"%s\" causes an integer overflow.", s);
		}
		else {
			log("\"%s\" is not an integer.", s);
		}
		return FALSE;
	}

	return TRUE;
}

static gboolean
ipxnet_from_string(fvalue_t *fv, char *s, LogFunc log)
{
	guint32 	val;
	gboolean	known;

	if (val_from_string(fv, s, log)) {
		return TRUE;
	}

	val = get_ipxnet_addr(s, &known);
	if (known) {
		fv->value.integer = val;
		return TRUE;
	}

	return FALSE;
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

/* BOOLEAN-specific */

static void
boolean_fvalue_new(fvalue_t *fv)
{
	fv->value.integer = TRUE;
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
		"FT_UINT8",
		"unsigned, 1 byte",
		1,
		int_fvalue_new,
		NULL,
		ftype_from_tvbuff,
		val_from_string,

		NULL,
		set_integer,
		NULL,

		NULL,
		get_integer,
		NULL,

		cmp_eq,
		cmp_ne,
		u_cmp_gt,
		u_cmp_ge,
		u_cmp_lt,
		u_cmp_le,
	};
	static ftype_t uint16_type = {
		"FT_UINT16",
		"unsigned, 2 bytes",
		2,
		int_fvalue_new,
		NULL,
		ftype_from_tvbuff,
		val_from_string,

		NULL,
		set_integer,
		NULL,

		NULL,
		get_integer,
		NULL,

		cmp_eq,
		cmp_ne,
		u_cmp_gt,
		u_cmp_ge,
		u_cmp_lt,
		u_cmp_le,
	};
	static ftype_t uint24_type = {
		"FT_UINT24",
		"unsigned, 3 bytes",
		3,
		int_fvalue_new,
		NULL,
		ftype_from_tvbuff,
		val_from_string,

		NULL,
		set_integer,
		NULL,

		NULL,
		get_integer,
		NULL,

		cmp_eq,
		cmp_ne,
		u_cmp_gt,
		u_cmp_ge,
		u_cmp_lt,
		u_cmp_le,
	};
	static ftype_t uint32_type = {
		"FT_UINT32",
		"unsigned, 4 bytes",
		4,
		int_fvalue_new,
		NULL,
		ftype_from_tvbuff,
		val_from_string,

		NULL,
		set_integer,
		NULL,

		NULL,
		get_integer,
		NULL,

		cmp_eq,
		cmp_ne,
		u_cmp_gt,
		u_cmp_ge,
		u_cmp_lt,
		u_cmp_le,
	};
	static ftype_t int8_type = {
		"FT_INT8",
		"signed, 1 byte",
		1,
		int_fvalue_new,
		NULL,
		ftype_from_tvbuff,
		val_from_string,

		NULL,
		set_integer,
		NULL,

		NULL,
		get_integer,
		NULL,

		cmp_eq,
		cmp_ne,
		s_cmp_gt,
		s_cmp_ge,
		s_cmp_lt,
		s_cmp_le,
	};
	static ftype_t int16_type = {
		"FT_INT16",
		"signed, 2 bytes",
		2,
		int_fvalue_new,
		NULL,
		ftype_from_tvbuff,
		val_from_string,

		NULL,
		set_integer,
		NULL,

		NULL,
		get_integer,
		NULL,

		cmp_eq,
		cmp_ne,
		s_cmp_gt,
		s_cmp_ge,
		s_cmp_lt,
		s_cmp_le,
	};
	static ftype_t int24_type = {
		"FT_INT24",
		"signed, 3 bytes",
		3,
		int_fvalue_new,
		NULL,
		ftype_from_tvbuff,
		val_from_string,

		NULL,
		set_integer,
		NULL,

		NULL,
		get_integer,
		NULL,

		cmp_eq,
		cmp_ne,
		s_cmp_gt,
		s_cmp_ge,
		s_cmp_lt,
		s_cmp_le,
	};
	static ftype_t int32_type = {
		"FT_INT32",
		"signed, 4 bytes",
		4,
		int_fvalue_new,
		NULL,
		ftype_from_tvbuff,
		val_from_string,

		NULL,
		set_integer,
		NULL,

		NULL,
		get_integer,
		NULL,

		cmp_eq,
		cmp_ne,
		s_cmp_gt,
		s_cmp_ge,
		s_cmp_lt,
		s_cmp_le,
	};
	static ftype_t boolean_type = {
		"FT_BOOLEAN",
		"Boolean",
		0,
		boolean_fvalue_new,
		NULL,
		ftype_from_tvbuff,
		val_from_string,

		NULL,
		set_integer,
		NULL,

		NULL,
		get_integer,
		NULL,

		bool_eq,
		bool_ne,
		NULL,
		NULL,
		NULL,
		NULL,
	};

	static ftype_t ipxnet_type = {
		"FT_IPXNET",
		"IPX network number",
		4,
		int_fvalue_new,
		NULL,
		ftype_from_tvbuff,
		ipxnet_from_string,

		NULL,
		set_integer,
		NULL,

		NULL,
		get_integer,
		NULL,

		cmp_eq,
		cmp_ne,
		u_cmp_gt,
		u_cmp_ge,
		u_cmp_lt,
		u_cmp_le,
	};


	ftype_register(FT_UINT8, &uint8_type);
	ftype_register(FT_UINT16, &uint16_type);
	ftype_register(FT_UINT24, &uint24_type);
	ftype_register(FT_UINT32, &uint32_type);
	ftype_register(FT_INT8, &int8_type);
	ftype_register(FT_INT16, &int16_type);
	ftype_register(FT_INT24, &int24_type);
	ftype_register(FT_INT32, &int32_type);
	ftype_register(FT_BOOLEAN, &boolean_type);
	ftype_register(FT_IPXNET, &ipxnet_type);
}
