/*
 * $Id: ftypes.c,v 1.2 2001/02/01 20:31:21 gram Exp $
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

#include <ftypes-int.h>

/* Keep track of ftype_t's via their ftenum number */
static ftype_t* type_list[FT_NUM_TYPES];

/* Space for quickly allocating/de-allocating fvalue_t's */
static GMemChunk *gmc_fvalue = NULL;

/* These are the ftype registration functions that need to be called.
 * This list and the initialization function could be produced
 * via a script, like the dissector registration, but there's so few
 * that I don't mind doing it by hand for now. */
void ftype_register_bytes(void);
void ftype_register_double(void);
void ftype_register_integers(void);
void ftype_register_ipv4(void);
void ftype_register_none(void);
void ftype_register_string(void);
void ftype_register_time(void);
void ftype_register_tvbuff(void);

/* Initialize the ftype module. */
void
ftypes_initialize(void)
{
	ftype_register_bytes();
	ftype_register_double();
	ftype_register_integers();
	ftype_register_ipv4();
	ftype_register_none();
	ftype_register_string();
	ftype_register_time();
	ftype_register_tvbuff();

	if (gmc_fvalue)
		g_mem_chunk_destroy(gmc_fvalue);

	gmc_fvalue = g_mem_chunk_new("gmc_fvalue", sizeof(fvalue_t),
			200 * sizeof(fvalue_t), G_ALLOC_AND_FREE);
}

void
ftypes_cleanup(void)
{
	if (gmc_fvalue)
		g_mem_chunk_destroy(gmc_fvalue);
}



/* Each ftype_t is registered via this function */
void
ftype_register(enum ftenum ftype, ftype_t *ft)
{
	/* Check input */
	g_assert(ftype >= 0);
	g_assert(ftype < FT_NUM_TYPES);

	/* Don't re-register. */
	g_assert(type_list[ftype] == NULL);

	type_list[ftype] = ft;
}

/* Given an ftenum number, return an ftype_t* */
static ftype_t*
ftype_lookup(enum ftenum ftype)
{
	ftype_t* result;

	/* Check input */
	g_assert(ftype >= 0);
	g_assert(ftype < FT_NUM_TYPES);

	result = type_list[ftype];

	/* Check output. */
	g_assert(result != NULL);

	return result;
}


/* Returns a string representing the name of the type. Useful
 * for glossary production. */
const char*
ftype_name(enum ftenum ftype)
{
	ftype_t	*ft;

	ft = ftype_lookup(ftype);
	return ft->name;
}

const char*
ftype_pretty_name(enum ftenum ftype)
{
	ftype_t	*ft;

	ft = ftype_lookup(ftype);
	return ft->pretty_name;
}

int
ftype_length(enum ftenum ftype)
{
	ftype_t	*ft;

	ft = ftype_lookup(ftype);
	return ft->wire_size;
}

gboolean
ftype_can_slice(enum ftenum ftype)
{
	ftype_t	*ft;

	ft = ftype_lookup(ftype);
	return ft->slice ? TRUE : FALSE;
}

gboolean
ftype_can_eq(enum ftenum ftype)
{
	ftype_t	*ft;

	ft = ftype_lookup(ftype);
	return ft->cmp_eq ? TRUE : FALSE;
}

gboolean
ftype_can_ne(enum ftenum ftype)
{
	ftype_t	*ft;

	ft = ftype_lookup(ftype);
	return ft->cmp_ne ? TRUE : FALSE;
}

gboolean
ftype_can_gt(enum ftenum ftype)
{
	ftype_t	*ft;

	ft = ftype_lookup(ftype);
	return ft->cmp_gt ? TRUE : FALSE;
}

gboolean
ftype_can_ge(enum ftenum ftype)
{
	ftype_t	*ft;

	ft = ftype_lookup(ftype);
	return ft->cmp_ge ? TRUE : FALSE;
}

gboolean
ftype_can_lt(enum ftenum ftype)
{
	ftype_t	*ft;

	ft = ftype_lookup(ftype);
	return ft->cmp_lt ? TRUE : FALSE;
}

gboolean
ftype_can_le(enum ftenum ftype)
{
	ftype_t	*ft;

	ft = ftype_lookup(ftype);
	return ft->cmp_le ? TRUE : FALSE;
}

/* ---------------------------------------------------------- */

/* Allocate and initialize an fvalue_t, given an ftype */
fvalue_t*
fvalue_new(ftenum_t ftype)
{
	fvalue_t		*fv;
	ftype_t			*ft;
	FvalueNewFunc		new_value;

	fv = g_mem_chunk_alloc(gmc_fvalue);

	ft = ftype_lookup(ftype);
	fv->ftype = ft;

	new_value = ft->new_value;
	if (new_value) {
		new_value(fv);
	}

	return fv;
}

/* Free all memory used by an fvalue_t */
void
fvalue_free(fvalue_t *fv)
{
	FvalueFreeFunc	free_value;

	free_value = fv->ftype->free_value;
	if (free_value) {
		free_value(fv);
	}

	g_mem_chunk_free(gmc_fvalue, fv);
}



fvalue_t*
fvalue_from_string(ftenum_t ftype, char *s, LogFunc log)
{
	fvalue_t	*fv;

	fv = fvalue_new(ftype);
	if (fv->ftype->val_from_string) {
		if (fv->ftype->val_from_string(fv, s, log)) {
			return fv;
		}
	}
	else {
		log("\"%s\" cannot be converted to %s.",
				s, ftype_pretty_name(ftype));
	}
	fvalue_free(fv);
	return NULL;
}

const char*
fvalue_type_name(fvalue_t *fv)
{
	return fv->ftype->name;
}


guint
fvalue_length(fvalue_t *fv)
{
	if (fv->ftype->len)
		return fv->ftype->len(fv);
	else
		return fv->ftype->wire_size;
}

/* Returns a new FT_BYTES fvalue_t* if possible, otherwise NULL */
fvalue_t*
fvalue_slice(fvalue_t *fv, gint start, gint end)
{
	GByteArray	*bytes;
	guint		data_length, abs_end;
	guint		offset=0, length=0;
	fvalue_t	*new_fv;

	if (!fv->ftype->slice) {
		return NULL;
	}

	data_length = fvalue_length(fv);
	bytes = g_byte_array_new();

	/* Find absolute start position (offset) */
	if (start < 0) {
		start = data_length + start;
		if (start < 0) {
			offset = 0;
		}
		else {
			offset = start;
		}
	}
	else {
		offset = start;
	}

	/* Limit the offset value */
	if (offset > data_length) {
		offset = data_length;
	}

	/* Find absolute end position (abs_end) */
	if (end < 0) {
		end = data_length + end;
		if (end < 0) {
			abs_end = 0;
		}
		else {
			abs_end = end;
		}
	}
	else {
		abs_end = end;
	}

	/* Limit the abs_end value */
	if (abs_end > data_length) {
		abs_end = data_length;
	}

	/* Does end position occur *after* start position? */
	if (abs_end > offset) {
		length = abs_end - offset;
		fv->ftype->slice(fv, bytes, offset, length);
	}

	new_fv = fvalue_new(FT_BYTES);
	fvalue_set(new_fv, bytes, TRUE);
	return new_fv;
}


void
fvalue_set(fvalue_t *fv, gpointer value, gboolean already_copied)
{
	g_assert(fv->ftype->set_value);
	fv->ftype->set_value(fv, value, already_copied);
}

void
fvalue_set_integer(fvalue_t *fv, guint32 value)
{
	g_assert(fv->ftype->set_value_integer);
	fv->ftype->set_value_integer(fv, value);
}

void
fvalue_set_floating(fvalue_t *fv, gdouble value)
{
	g_assert(fv->ftype->set_value_floating);
	fv->ftype->set_value_floating(fv, value);
}


gpointer
fvalue_get(fvalue_t *fv)
{
	g_assert(fv->ftype->get_value);
	return fv->ftype->get_value(fv);
}

guint32
fvalue_get_integer(fvalue_t *fv)
{
	g_assert(fv->ftype->get_value_integer);
	return fv->ftype->get_value_integer(fv);
}

double
fvalue_get_floating(fvalue_t *fv)
{
	g_assert(fv->ftype->get_value_floating);
	return fv->ftype->get_value_floating(fv);
}

gboolean
fvalue_eq(fvalue_t *a, fvalue_t *b)
{
	/* XXX - check compatibility of a and b */
	g_assert(a->ftype->cmp_eq);
	return a->ftype->cmp_eq(a, b);
}

gboolean
fvalue_ne(fvalue_t *a, fvalue_t *b)
{
	/* XXX - check compatibility of a and b */
	g_assert(a->ftype->cmp_ne);
	return a->ftype->cmp_ne(a, b);
}

gboolean
fvalue_gt(fvalue_t *a, fvalue_t *b)
{
	/* XXX - check compatibility of a and b */
	g_assert(a->ftype->cmp_gt);
	return a->ftype->cmp_gt(a, b);
}

gboolean
fvalue_ge(fvalue_t *a, fvalue_t *b)
{
	/* XXX - check compatibility of a and b */
	g_assert(a->ftype->cmp_ge);
	return a->ftype->cmp_ge(a, b);
}

gboolean
fvalue_lt(fvalue_t *a, fvalue_t *b)
{
	/* XXX - check compatibility of a and b */
	g_assert(a->ftype->cmp_lt);
	return a->ftype->cmp_lt(a, b);
}

gboolean
fvalue_le(fvalue_t *a, fvalue_t *b)
{
	/* XXX - check compatibility of a and b */
	g_assert(a->ftype->cmp_le);
	return a->ftype->cmp_le(a, b);
}
