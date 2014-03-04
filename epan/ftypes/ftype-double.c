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

#include <stdio.h>
#include <ftypes-int.h>
#include <math.h>
#include <errno.h>
#include <float.h>

#include "strutil.h"

static void
double_fvalue_new(fvalue_t *fv)
{
	fv->value.floating = 0.0;
}

static void
double_fvalue_set_floating(fvalue_t *fv, gdouble value)
{
	fv->value.floating = value;
}

static double
value_get_floating(fvalue_t *fv)
{
	return fv->value.floating;
}

static gboolean
val_from_unparsed(fvalue_t *fv, const char *s, gboolean allow_partial_value _U_, LogFunc logfunc)
{
	char    *endptr = NULL;

	fv->value.floating = g_ascii_strtod(s, &endptr);

	if (endptr == s || *endptr != '\0') {
		/* This isn't a valid number. */
		logfunc("\"%s\" is not a valid number.", s);
		return FALSE;
	}
	if (errno == ERANGE) {
		if (fv->value.floating == 0) {
			logfunc("\"%s\" causes floating-point underflow.", s);
		}
		else if (fv->value.floating == HUGE_VAL) {
			logfunc("\"%s\" causes floating-point overflow.", s);
		}
		else {
			logfunc("\"%s\" is not a valid floating-point number.",
			    s);
		}
		return FALSE;
	}

	return TRUE;
}

static int
float_val_repr_len(fvalue_t *fv _U_, ftrepr_t rtype _U_)
{
	/*
	 * 1 character for a sign.
	 * 26 characters for a Really Big Number.
	 * XXX - is that platform-dependent?
	 * XXX - smaller for float than for double?
	 * XXX - can we compute it from FLT_DIG and the like?
	 */
	return 1 + 26;
}

static void
float_val_to_repr(fvalue_t *fv, ftrepr_t rtype _U_, char *buf)
{
	sprintf(buf, "%." G_STRINGIFY(FLT_DIG) "g", fv->value.floating);
}

static int
double_val_repr_len(fvalue_t *fv _U_, ftrepr_t rtype _U_)
{
	/*
	 * 1 character for a sign.
	 * 26 characters for a Really Big Number.
	 * XXX - is that platform-dependent?
	 * XXX - can we compute it from DBL_DIG and the like?
	 */
	return 1 + 26;
}

static void
double_val_to_repr(fvalue_t *fv, ftrepr_t rtype _U_, char *buf)
{
	sprintf(buf, "%." G_STRINGIFY(DBL_DIG) "g", fv->value.floating);
}

static gboolean
cmp_eq(const fvalue_t *a, const fvalue_t *b)
{
	return a->value.floating == b->value.floating;
}

static gboolean
cmp_ne(const fvalue_t *a, const fvalue_t *b)
{
	return a->value.floating != b->value.floating;
}

static gboolean
cmp_gt(const fvalue_t *a, const fvalue_t *b)
{
	return a->value.floating > b->value.floating;
}

static gboolean
cmp_ge(const fvalue_t *a, const fvalue_t *b)
{
	return a->value.floating >= b->value.floating;
}

static gboolean
cmp_lt(const fvalue_t *a, const fvalue_t *b)
{
	return a->value.floating < b->value.floating;
}

static gboolean
cmp_le(const fvalue_t *a, const fvalue_t *b)
{
	return a->value.floating <= b->value.floating;
}

void
ftype_register_double(void)
{

	static ftype_t float_type = {
		FT_FLOAT,			/* ftype */
		"FT_FLOAT",			/* name */
		"Floating point (single-precision)", /* pretty_name */
		0,				/* wire_size */
		double_fvalue_new,		/* new_value */
		NULL,				/* free_value */
		val_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		float_val_to_repr,		/* val_to_string_repr */
		float_val_repr_len,		/* len_string_repr */

		NULL,				/* set_value_byte_array */
		NULL,				/* set_value_bytes */
		NULL,				/* set_value_guid */
		NULL,				/* set_value_time */
		NULL,				/* set_value_string */
		NULL,				/* set_value_tvbuff */
		NULL,				/* set_value_uinteger */
		NULL,				/* set_value_snteger */
		NULL,				/* set_value_integer64 */
		double_fvalue_set_floating,	/* set_value_floating */

		NULL,				/* get_value */
		NULL,				/* get_value_uinteger */
		NULL,				/* get_value_sinteger */
		NULL,				/* get_value_integer64 */
		value_get_floating,		/* get_value_floating */

		cmp_eq,
		cmp_ne,
		cmp_gt,
		cmp_ge,
		cmp_lt,
		cmp_le,
		NULL,				/* cmp_bitwise_and */
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,
		NULL,
	};

	static ftype_t double_type = {
		FT_DOUBLE,			/* ftype */
		"FT_DOUBLE",			/* name */
		"Floating point (double-precision)", /* pretty_name */
		0,				/* wire_size */
		double_fvalue_new,		/* new_value */
		NULL,				/* free_value */
		val_from_unparsed,		/* val_from_unparsed */
		NULL,				/* val_from_string */
		double_val_to_repr,		/* val_to_string_repr */
		double_val_repr_len,		/* len_string_repr */

		NULL,				/* set_value_byte_array */
		NULL,				/* set_value_bytes */
		NULL,				/* set_value_guid */
		NULL,				/* set_value_time */
		NULL,				/* set_value_string */
		NULL,				/* set_value_tvbuff */
		NULL,				/* set_value_uinteger */
		NULL,				/* set_value_sinteger */
		NULL,				/* set_value_integer64 */
		double_fvalue_set_floating,	/* set_value_floating */

		NULL,				/* get_value */
		NULL,				/* get_value_uinteger */
		NULL,				/* get_value_snteger */
		NULL,				/* get_value_integer64 */
		value_get_floating,		/* get_value_floating */

		cmp_eq,
		cmp_ne,
		cmp_gt,
		cmp_ge,
		cmp_lt,
		cmp_le,
		NULL,				/* cmp_bitwise_and */
		NULL,				/* cmp_contains */
		NULL,				/* cmp_matches */

		NULL,
		NULL,
	};

	ftype_register(FT_FLOAT, &float_type);
	ftype_register(FT_DOUBLE, &double_type);
}
