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

#include <ftypes-int.h>
#include <glib.h>

#include "ftypes.h"

/* Keep track of ftype_t's via their ftenum number */
static ftype_t* type_list[FT_NUM_TYPES];

/* Initialize the ftype module. */
void
ftypes_initialize(void)
{
	ftype_register_bytes();
	ftype_register_double();
	ftype_register_integers();
	ftype_register_ipv4();
	ftype_register_ipv6();
	ftype_register_guid();
	ftype_register_none();
	ftype_register_string();
	ftype_register_time();
	ftype_register_tvbuff();
	ftype_register_pcre();
}

/* Each ftype_t is registered via this function */
void
ftype_register(enum ftenum ftype, ftype_t *ft)
{
	/* Check input */
	g_assert(ftype < FT_NUM_TYPES);
	g_assert(ftype == ft->ftype);

	/* Don't re-register. */
	g_assert(type_list[ftype] == NULL);

	type_list[ftype] = ft;
}

/* Given an ftenum number, return an ftype_t* */
#define FTYPE_LOOKUP(ftype, result)	\
	/* Check input */		\
	g_assert(ftype < FT_NUM_TYPES);	\
	result = type_list[ftype];



/* from README.dissector:
	Note that the formats used must all belong to the same list as defined below:
	- FT_INT8, FT_INT16, FT_INT24 and FT_INT32
	- FT_UINT8, FT_UINT16, FT_UINT24, FT_UINT32, FT_IPXNET and FT_FRAMENUM
	- FT_UINT64 and FT_EUI64
	- FT_STRING, FT_STRINGZ and FT_UINT_STRING
	- FT_FLOAT and FT_DOUBLE
	- FT_BYTES, FT_UINT_BYTES, FT_AX25, FT_ETHER, FT_VINES, FT_OID and FT_REL_OID
	- FT_ABSOLUTE_TIME and FT_RELATIVE_TIME
*/
static enum ftenum
same_ftype(const enum ftenum ftype)
{
	switch (ftype) {
		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
			return FT_INT32;

		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
			return FT_UINT32;

		case FT_STRING:
		case FT_STRINGZ:
		case FT_UINT_STRING:
			return FT_STRING;

		case FT_FLOAT:
		case FT_DOUBLE:
			return FT_DOUBLE;

		case FT_BYTES:
		case FT_UINT_BYTES:
			return FT_BYTES;

		case FT_OID:
		case FT_REL_OID:
			return FT_OID;

		/* XXX: the folowing are unqiue for now */
		case FT_INT64:
		case FT_UINT64:
		case FT_IPv4:
		case FT_IPv6:

		/* everything else is unique */
		default:
			return ftype;
	}
}

/* given two types, are they similar - for example can two
 * duplicate fields be registered of these two types. */
gboolean
ftype_similar_types(const enum ftenum ftype_a, const enum ftenum ftype_b)
{
	return (same_ftype(ftype_a) == same_ftype(ftype_b));
}

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
ftype_can_bitwise_and(enum ftenum ftype)
{
	ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->cmp_bitwise_and ? TRUE : FALSE;
}

gboolean
ftype_can_contains(enum ftenum ftype)
{
	ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->cmp_contains ? TRUE : FALSE;
}

gboolean
ftype_can_matches(enum ftenum ftype)
{
	ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->cmp_matches ? TRUE : FALSE;
}

/* ---------------------------------------------------------- */

/* Allocate and initialize an fvalue_t, given an ftype */
fvalue_t*
fvalue_new(ftenum_t ftype)
{
	fvalue_t		*fv;
	ftype_t			*ft;
	FvalueNewFunc		new_value;

	fv = g_slice_new(fvalue_t);

	FTYPE_LOOKUP(ftype, ft);
	fv->ftype = ft;

	new_value = ft->new_value;
	if (new_value) {
		new_value(fv);
	}

	return fv;
}

void
fvalue_init(fvalue_t *fv, ftenum_t ftype)
{
	ftype_t			*ft;
	FvalueNewFunc		new_value;

	FTYPE_LOOKUP(ftype, ft);
	fv->ftype = ft;

	new_value = ft->new_value;
	if (new_value) {
		new_value(fv);
	}
}

fvalue_t*
fvalue_from_unparsed(ftenum_t ftype, const char *s, gboolean allow_partial_value, LogFunc logfunc)
{
	fvalue_t	*fv;

	fv = fvalue_new(ftype);
	if (fv->ftype->val_from_unparsed) {
		if (fv->ftype->val_from_unparsed(fv, s, allow_partial_value, logfunc)) {
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
fvalue_from_string(ftenum_t ftype, const char *s, LogFunc logfunc)
{
	fvalue_t	*fv;

	fv = fvalue_new(ftype);
	if (fv->ftype->val_from_string) {
		if (fv->ftype->val_from_string(fv, s, logfunc)) {
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

ftenum_t
fvalue_type_ftenum(fvalue_t *fv)
{
	return fv->ftype->ftype;
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

int
fvalue_string_repr_len(fvalue_t *fv, ftrepr_t rtype)
{
	g_assert(fv->ftype->len_string_repr);
	return fv->ftype->len_string_repr(fv, rtype);
}

char *
fvalue_to_string_repr(fvalue_t *fv, ftrepr_t rtype, char *buf)
{
	if (fv->ftype->val_to_string_repr == NULL) {
		/* no value-to-string-representation function, so the value cannot be represented */
		return NULL;
	}
	if (!buf) {
		int len;
		if ((len = fvalue_string_repr_len(fv, rtype)) >= 0) {
			buf = (char *)g_malloc0(len + 1);
		} else {
			/* the value cannot be represented in the given representation type (rtype) */
			return NULL;
		}
	}
	fv->ftype->val_to_string_repr(fv, rtype, buf);
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
	drange_node	*drnode = (drange_node	*)data;
	slice_data_t	*slice_data = (slice_data_t *)user_data;
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
		if (start_offset < 0) {
			slice_data->slice_failure = TRUE;
			return;
		}
	}

	/* Check the end type and set the length */

	if (ending == DRANGE_NODE_END_T_TO_THE_END) {
		length = field_length - start_offset;
		if (length <= 0) {
			slice_data->slice_failure = TRUE;
			return;
		}
	}
	else if (ending == DRANGE_NODE_END_T_LENGTH) {
		length = drange_node_get_length(drnode);
		if (start_offset + length > (int) field_length) {
			slice_data->slice_failure = TRUE;
			return;
		}
	}
	else if (ending == DRANGE_NODE_END_T_OFFSET) {
		end_offset = drange_node_get_end_offset(drnode);
		if (end_offset < 0) {
			end_offset = field_length + end_offset;
			if (end_offset < start_offset) {
				slice_data->slice_failure = TRUE;
				return;
			}
		} else if (end_offset >= (int) field_length) {
			slice_data->slice_failure = TRUE;
			return;
		}
		length = end_offset - start_offset + 1;
	}
	else {
		g_assert_not_reached();
	}

	g_assert(start_offset >=0 && length > 0);
	fv->ftype->slice(fv, slice_data->bytes, start_offset, length);
}


/* Returns a new FT_BYTES fvalue_t* if possible, otherwise NULL */
fvalue_t*
fvalue_slice(fvalue_t *fv, drange_t *d_range)
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

	drange_foreach_drange_node(d_range, slice_func, &slice_data);

	new_fv = fvalue_new(FT_BYTES);
	fvalue_set_byte_array(new_fv, slice_data.bytes);
	return new_fv;
}


void
fvalue_set_byte_array(fvalue_t *fv, GByteArray *value)
{
	g_assert(fv->ftype->set_value_byte_array);
	fv->ftype->set_value_byte_array(fv, value);
}

void
fvalue_set_bytes(fvalue_t *fv, const guint8 *value)
{
	g_assert(fv->ftype->set_value_bytes);
	fv->ftype->set_value_bytes(fv, value);
}

void
fvalue_set_guid(fvalue_t *fv, const e_guid_t *value)
{
	g_assert(fv->ftype->set_value_guid);
	fv->ftype->set_value_guid(fv, value);
}

void
fvalue_set_time(fvalue_t *fv, const nstime_t *value)
{
	g_assert(fv->ftype->set_value_time);
	fv->ftype->set_value_time(fv, value);
}

void
fvalue_set_string(fvalue_t *fv, const gchar *value)
{
	g_assert(fv->ftype->set_value_string);
	fv->ftype->set_value_string(fv, value);
}

void
fvalue_set_tvbuff(fvalue_t *fv, tvbuff_t *value)
{
	g_assert(fv->ftype->set_value_tvbuff);
	fv->ftype->set_value_tvbuff(fv, value);
}

void
fvalue_set_uinteger(fvalue_t *fv, guint32 value)
{
	g_assert(fv->ftype->set_value_uinteger);
	fv->ftype->set_value_uinteger(fv, value);
}

void
fvalue_set_sinteger(fvalue_t *fv, gint32 value)
{
	g_assert(fv->ftype->set_value_sinteger);
	fv->ftype->set_value_sinteger(fv, value);
}


void
fvalue_set_integer64(fvalue_t *fv, guint64 value)
{
	g_assert(fv->ftype->set_value_integer64);
	fv->ftype->set_value_integer64(fv, value);
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
fvalue_get_uinteger(fvalue_t *fv)
{
	g_assert(fv->ftype->get_value_uinteger);
	return fv->ftype->get_value_uinteger(fv);
}

gint32
fvalue_get_sinteger(fvalue_t *fv)
{
	g_assert(fv->ftype->get_value_sinteger);
	return fv->ftype->get_value_sinteger(fv);
}


guint64
fvalue_get_integer64(fvalue_t *fv)
{
	g_assert(fv->ftype->get_value_integer64);
	return fv->ftype->get_value_integer64(fv);
}

double
fvalue_get_floating(fvalue_t *fv)
{
	g_assert(fv->ftype->get_value_floating);
	return fv->ftype->get_value_floating(fv);
}

gboolean
fvalue_eq(const fvalue_t *a, const fvalue_t *b)
{
	/* XXX - check compatibility of a and b */
	g_assert(a->ftype->cmp_eq);
	return a->ftype->cmp_eq(a, b);
}

gboolean
fvalue_ne(const fvalue_t *a, const fvalue_t *b)
{
	/* XXX - check compatibility of a and b */
	g_assert(a->ftype->cmp_ne);
	return a->ftype->cmp_ne(a, b);
}

gboolean
fvalue_gt(const fvalue_t *a, const fvalue_t *b)
{
	/* XXX - check compatibility of a and b */
	g_assert(a->ftype->cmp_gt);
	return a->ftype->cmp_gt(a, b);
}

gboolean
fvalue_ge(const fvalue_t *a, const fvalue_t *b)
{
	/* XXX - check compatibility of a and b */
	g_assert(a->ftype->cmp_ge);
	return a->ftype->cmp_ge(a, b);
}

gboolean
fvalue_lt(const fvalue_t *a, const fvalue_t *b)
{
	/* XXX - check compatibility of a and b */
	g_assert(a->ftype->cmp_lt);
	return a->ftype->cmp_lt(a, b);
}

gboolean
fvalue_le(const fvalue_t *a, const fvalue_t *b)
{
	/* XXX - check compatibility of a and b */
	g_assert(a->ftype->cmp_le);
	return a->ftype->cmp_le(a, b);
}

gboolean
fvalue_bitwise_and(const fvalue_t *a, const fvalue_t *b)
{
	/* XXX - check compatibility of a and b */
	g_assert(a->ftype->cmp_bitwise_and);
	return a->ftype->cmp_bitwise_and(a, b);
}

gboolean
fvalue_contains(const fvalue_t *a, const fvalue_t *b)
{
	/* XXX - check compatibility of a and b */
	g_assert(a->ftype->cmp_contains);
	return a->ftype->cmp_contains(a, b);
}

gboolean
fvalue_matches(const fvalue_t *a, const fvalue_t *b)
{
	/* XXX - check compatibility of a and b */
	g_assert(a->ftype->cmp_matches);
	return a->ftype->cmp_matches(a, b);
}
