/*
 * $Id: ftypes.c,v 1.14 2003/11/25 19:25:31 guy Exp $
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
#include <glib.h>

/* Keep track of ftype_t's via their ftenum number */
static ftype_t* type_list[FT_NUM_TYPES];

/* Space for quickly allocating/de-allocating fvalue_t's */
fvalue_t *fvalue_free_list=NULL;

/* Chunk of fvalue_t values */
#define FVALUE_TS_PER_CHUNK	200
typedef struct _fvalue_chunk_t {
	struct _fvalue_chunk_t *next;
	fvalue_t fvalues[FVALUE_TS_PER_CHUNK];
} fvalue_chunk_t;

static fvalue_chunk_t *fvalue_chunk_list;

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
}

void
ftypes_cleanup(void)
{
	while (fvalue_chunk_list) {
		fvalue_chunk_t *tmpchunk;
		tmpchunk=fvalue_chunk_list->next;
		g_free(fvalue_chunk_list);
		fvalue_chunk_list=tmpchunk;
	}
	fvalue_free_list=NULL;
}



/* Each ftype_t is registered via this function */
void
ftype_register(enum ftenum ftype, ftype_t *ft)
{
	/* Check input */
	g_assert(ftype < FT_NUM_TYPES);

	/* Don't re-register. */
	g_assert(type_list[ftype] == NULL);

	type_list[ftype] = ft;
}

/* Given an ftenum number, return an ftype_t* */
#define FTYPE_LOOKUP(ftype, result)	\
	/* Check input */		\
	g_assert(ftype < FT_NUM_TYPES);	\
	result = type_list[ftype];



/* Returns a string representing the name of the type. Useful
 * for glossary production. */
const char*
ftype_name(enum ftenum ftype)
{
	ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->name;
}

const char*
ftype_pretty_name(enum ftenum ftype)
{
	ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->pretty_name;
}

int
ftype_length(enum ftenum ftype)
{
	ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->wire_size;
}

gboolean
ftype_can_slice(enum ftenum ftype)
{
	ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->slice ? TRUE : FALSE;
}

gboolean
ftype_can_eq(enum ftenum ftype)
{
	ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->cmp_eq ? TRUE : FALSE;
}

gboolean
ftype_can_ne(enum ftenum ftype)
{
	ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->cmp_ne ? TRUE : FALSE;
}

gboolean
ftype_can_gt(enum ftenum ftype)
{
	ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->cmp_gt ? TRUE : FALSE;
}

gboolean
ftype_can_ge(enum ftenum ftype)
{
	ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->cmp_ge ? TRUE : FALSE;
}

gboolean
ftype_can_lt(enum ftenum ftype)
{
	ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->cmp_lt ? TRUE : FALSE;
}

gboolean
ftype_can_le(enum ftenum ftype)
{
	ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->cmp_le ? TRUE : FALSE;
}

gboolean
ftype_can_contains(enum ftenum ftype)
{
	ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->cmp_contains ? TRUE : FALSE;
}

/* ---------------------------------------------------------- */

/* Allocate and initialize an fvalue_t, given an ftype */
fvalue_t*
fvalue_new(ftenum_t ftype)
{
	fvalue_t		*fv;
	ftype_t			*ft;
	FvalueNewFunc		new_value;

	if(!fvalue_free_list){
		int i;
		fvalue_chunk_t *chunk;
		chunk=g_malloc(sizeof(fvalue_chunk_t));
		chunk->next=fvalue_chunk_list;
		fvalue_chunk_list=chunk;
		for(i=0;i<FVALUE_TS_PER_CHUNK;i++){
			fvalue_t *tmpfv;
			tmpfv=&chunk->fvalues[i];
			tmpfv->ptr_u.next=fvalue_free_list;
			fvalue_free_list=tmpfv;
		}
	}
	fv=fvalue_free_list;
	fvalue_free_list=fv->ptr_u.next;

	FTYPE_LOOKUP(ftype, ft);
	fv->ptr_u.ftype = ft;

	new_value = ft->new_value;
	if (new_value) {
		new_value(fv);
	}

	return fv;
}

fvalue_t*
fvalue_from_unparsed(ftenum_t ftype, char *s, gboolean allow_partial_value, LogFunc logfunc)
{
	fvalue_t	*fv;

	fv = fvalue_new(ftype);
	if (fv->ptr_u.ftype->val_from_unparsed) {
		if (fv->ptr_u.ftype->val_from_unparsed(fv, s, allow_partial_value, logfunc)) {
			return fv;
		}
	}
	else {
		logfunc("\"%s\" cannot be converted to %s.",
				s, ftype_pretty_name(ftype));
	}
	FVALUE_FREE(fv);
	return NULL;
}

fvalue_t*
fvalue_from_string(ftenum_t ftype, char *s, LogFunc logfunc)
{
	fvalue_t	*fv;

	fv = fvalue_new(ftype);
	if (fv->ptr_u.ftype->val_from_string) {
		if (fv->ptr_u.ftype->val_from_string(fv, s, logfunc)) {
			return fv;
		}
	}
	else {
		logfunc("\"%s\" cannot be converted to %s.",
				s, ftype_pretty_name(ftype));
	}
	FVALUE_FREE(fv);
	return NULL;
}

const char*
fvalue_type_name(fvalue_t *fv)
{
	return fv->ptr_u.ftype->name;
}


guint
fvalue_length(fvalue_t *fv)
{
	if (fv->ptr_u.ftype->len)
		return fv->ptr_u.ftype->len(fv);
	else
		return fv->ptr_u.ftype->wire_size;
}

int
fvalue_string_repr_len(fvalue_t *fv, ftrepr_t rtype)
{
	g_assert(fv->ptr_u.ftype->len_string_repr);
	return fv->ptr_u.ftype->len_string_repr(fv, rtype);
}

char *
fvalue_to_string_repr(fvalue_t *fv, ftrepr_t rtype, char *buf)
{
	g_assert(fv->ptr_u.ftype->val_to_string_repr);
	if (!buf) {
		buf = g_malloc0(fvalue_string_repr_len(fv, rtype) + 1);
	}
	fv->ptr_u.ftype->val_to_string_repr(fv, rtype, buf);
	return buf;
}

typedef struct {
	fvalue_t	*fv;
	GByteArray	*bytes;
	gboolean	slice_failure;
} slice_data_t;

static void
slice_func(gpointer data, gpointer user_data)
{
	drange_node	*drnode = data;
	slice_data_t	*slice_data = user_data;
	gint		start_offset;
	gint		length = 0;
	gint		end_offset = 0;
	guint		field_length;
	fvalue_t	*fv;
	drange_node_end_t	ending;

	if (slice_data->slice_failure) {
		return;
	}

	start_offset = drange_node_get_start_offset(drnode);
	ending = drange_node_get_ending(drnode);

	fv = slice_data->fv;
	field_length = fvalue_length(fv);

	/* Check for negative start */
	if (start_offset < 0) {
		start_offset = field_length + start_offset;
	}

	/* Check the end type, and set both end_offset and length */
	if (ending == TO_THE_END) {
		end_offset = field_length;
		length = end_offset - start_offset;
	}
	else if (ending == LENGTH) {
		length = drange_node_get_length(drnode);
		if (length < 0) {
			end_offset = field_length + length;
			if (end_offset > start_offset) {
				length = end_offset - start_offset + 1;
			}
			else {
				slice_data->slice_failure = TRUE;
				return;
			}
		}
		else {
			end_offset = start_offset + length;
		}
	}
	else if (ending == OFFSET) {
		end_offset = drange_node_get_end_offset(drnode);
		if (end_offset < 0) {
			end_offset = field_length + end_offset;
			if (end_offset > start_offset) {
				length = end_offset - start_offset + 1;
			}
			else {
				slice_data->slice_failure = TRUE;
				return;
			}
		}
		else {
			length = end_offset - start_offset + 1;
		}
	}
	else {
		g_assert_not_reached();
	}

/*	g_debug("(NEW) start_offset=%d length=%d end_offset=%d",
			start_offset, length, end_offset); */

	if (start_offset > (int) field_length || end_offset > (int) field_length) {
		slice_data->slice_failure = TRUE;
		return;
	}

	fv->ptr_u.ftype->slice(fv, slice_data->bytes, start_offset, length);
}


/* Returns a new FT_BYTES fvalue_t* if possible, otherwise NULL */
fvalue_t*
fvalue_slice(fvalue_t *fv, drange *drange)
{
	slice_data_t	slice_data;
	fvalue_t	*new_fv;

	slice_data.fv = fv;
	slice_data.bytes = g_byte_array_new();
	slice_data.slice_failure = FALSE;

	/* XXX - We could make some optimizations here based on
	 * drange_has_total_length() and
	 * drange_get_max_offset().
	 */

	drange_foreach_drange_node(drange, slice_func, &slice_data);

	new_fv = fvalue_new(FT_BYTES);
	fvalue_set(new_fv, slice_data.bytes, TRUE);
	return new_fv;
}


void
fvalue_set(fvalue_t *fv, gpointer value, gboolean already_copied)
{
	g_assert(fv->ptr_u.ftype->set_value);
	fv->ptr_u.ftype->set_value(fv, value, already_copied);
}

void
fvalue_set_integer(fvalue_t *fv, guint32 value)
{
	g_assert(fv->ptr_u.ftype->set_value_integer);
	fv->ptr_u.ftype->set_value_integer(fv, value);
}

void
fvalue_set_floating(fvalue_t *fv, gdouble value)
{
	g_assert(fv->ptr_u.ftype->set_value_floating);
	fv->ptr_u.ftype->set_value_floating(fv, value);
}


gpointer
fvalue_get(fvalue_t *fv)
{
	g_assert(fv->ptr_u.ftype->get_value);
	return fv->ptr_u.ftype->get_value(fv);
}

guint32
fvalue_get_integer(fvalue_t *fv)
{
	g_assert(fv->ptr_u.ftype->get_value_integer);
	return fv->ptr_u.ftype->get_value_integer(fv);
}

double
fvalue_get_floating(fvalue_t *fv)
{
	g_assert(fv->ptr_u.ftype->get_value_floating);
	return fv->ptr_u.ftype->get_value_floating(fv);
}

gboolean
fvalue_eq(fvalue_t *a, fvalue_t *b)
{
	/* XXX - check compatibility of a and b */
	g_assert(a->ptr_u.ftype->cmp_eq);
	return a->ptr_u.ftype->cmp_eq(a, b);
}

gboolean
fvalue_ne(fvalue_t *a, fvalue_t *b)
{
	/* XXX - check compatibility of a and b */
	g_assert(a->ptr_u.ftype->cmp_ne);
	return a->ptr_u.ftype->cmp_ne(a, b);
}

gboolean
fvalue_gt(fvalue_t *a, fvalue_t *b)
{
	/* XXX - check compatibility of a and b */
	g_assert(a->ptr_u.ftype->cmp_gt);
	return a->ptr_u.ftype->cmp_gt(a, b);
}

gboolean
fvalue_ge(fvalue_t *a, fvalue_t *b)
{
	/* XXX - check compatibility of a and b */
	g_assert(a->ptr_u.ftype->cmp_ge);
	return a->ptr_u.ftype->cmp_ge(a, b);
}

gboolean
fvalue_lt(fvalue_t *a, fvalue_t *b)
{
	/* XXX - check compatibility of a and b */
	g_assert(a->ptr_u.ftype->cmp_lt);
	return a->ptr_u.ftype->cmp_lt(a, b);
}

gboolean
fvalue_le(fvalue_t *a, fvalue_t *b)
{
	/* XXX - check compatibility of a and b */
	g_assert(a->ptr_u.ftype->cmp_le);
	return a->ptr_u.ftype->cmp_le(a, b);
}

gboolean
fvalue_contains(fvalue_t *a, fvalue_t *b)
{
	/* XXX - check compatibility of a and b */
	g_assert(a->ptr_u.ftype->cmp_contains);
	return a->ptr_u.ftype->cmp_contains(a, b);
}
