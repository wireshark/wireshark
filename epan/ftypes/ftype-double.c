/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
val_from_unparsed(fvalue_t *fv, const char *s, gboolean allow_partial_value _U_, gchar **err_msg)
{
	char    *endptr = NULL;

	fv->value.floating = g_ascii_strtod(s, &endptr);

	if (endptr == s || *endptr != '\0') {
		/* This isn't a valid number. */
		if (err_msg != NULL)
			*err_msg = g_strdup_printf("\"%s\" is not a valid number.", s);
		return FALSE;
	}
	if (errno == ERANGE) {
		if (fv->value.floating == 0) {
			if (err_msg != NULL)
				*err_msg = g_strdup_printf("\"%s\" causes floating-point underflow.", s);
		}
		else if (fv->value.floating == HUGE_VAL) {
			if (err_msg != NULL)
				*err_msg = g_strdup_printf("\"%s\" causes floating-point overflow.", s);
		}
		else {
			if (err_msg != NULL)
				*err_msg = g_strdup_printf("\"%s\" is not a valid floating-point number.",
				    s);
		}
		return FALSE;
	}

	return TRUE;
}

static int
float_val_repr_len(fvalue_t *fv _U_, ftrepr_t rtype _U_, int field_display _U_)
{
	return G_ASCII_DTOSTR_BUF_SIZE;
}

static void
float_val_to_repr(fvalue_t *fv, ftrepr_t rtype _U_, int field_display _U_, char *buf, unsigned int size)
{
	g_ascii_formatd(buf, size, "%." G_STRINGIFY(FLT_DIG) "g", fv->value.floating);
}

static int
double_val_repr_len(fvalue_t *fv _U_, ftrepr_t rtype _U_, int field_display _U_)
{
	return G_ASCII_DTOSTR_BUF_SIZE;
}

static void
double_val_to_repr(fvalue_t *fv, ftrepr_t rtype _U_, int field_display _U_, char *buf, unsigned int size)
{
	g_ascii_formatd(buf, size, "%." G_STRINGIFY(DBL_DIG) "g", fv->value.floating);
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

		{ .set_value_floating = double_fvalue_set_floating },		/* union set_value */
		{ .get_value_floating = value_get_floating },	/* union get_value */

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

		{ .set_value_floating = double_fvalue_set_floating },		/* union set_value */
		{ .get_value_floating = value_get_floating },	/* union get_value */

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
