/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "ftypes-int.h"

#include <wsutil/ws_assert.h>

/* Keep track of ftype_t's via their ftenum number */
ftype_t* type_list[FT_NUM_TYPES];

/* Initialize the ftype module. */
void
ftypes_initialize(void)
{
	ftype_register_bytes();
	ftype_register_double();
	ftype_register_ieee_11073_float();
	ftype_register_integers();
	ftype_register_ipv4();
	ftype_register_ipv6();
	ftype_register_guid();
	ftype_register_none();
	ftype_register_string();
	ftype_register_time();
	ftype_register_tvbuff();
}

void
ftypes_register_pseudofields(void)
{
	static int proto_ftypes;

	proto_ftypes = proto_register_protocol(
				"Wireshark Field/Fundamental Types",
				"Wireshark FTypes",
				"_ws.ftypes");

	ftype_register_pseudofields_bytes(proto_ftypes);
	ftype_register_pseudofields_double(proto_ftypes);
	ftype_register_pseudofields_ieee_11073_float(proto_ftypes);
	ftype_register_pseudofields_integer(proto_ftypes);
	ftype_register_pseudofields_ipv4(proto_ftypes);
	ftype_register_pseudofields_ipv6(proto_ftypes);
	ftype_register_pseudofields_guid(proto_ftypes);
	ftype_register_pseudofields_string(proto_ftypes);
	ftype_register_pseudofields_time(proto_ftypes);
	ftype_register_pseudofields_tvbuff(proto_ftypes);

	proto_set_cant_toggle(proto_ftypes);
}

/* Each ftype_t is registered via this function */
void
ftype_register(enum ftenum ftype, ftype_t *ft)
{
	/* Check input */
	ws_assert(ftype < FT_NUM_TYPES);
	ws_assert(ftype == ft->ftype);

	/* Don't re-register. */
	ws_assert(type_list[ftype] == NULL);

	type_list[ftype] = ft;
}


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

		case FT_INT40:
		case FT_INT48:
		case FT_INT56:
		case FT_INT64:
			return FT_INT64;

		case FT_UINT40:
		case FT_UINT48:
		case FT_UINT56:
		case FT_UINT64:
			return FT_UINT64;

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

		/* XXX: the folowing are unique for now */
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
	return ft->cmp_order != NULL;
}

gboolean
ftype_can_cmp(enum ftenum ftype)
{
	ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->cmp_order != NULL;
}

gboolean
ftype_can_bitwise_and(enum ftenum ftype)
{
	ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->bitwise_and ? TRUE : FALSE;
}

gboolean
ftype_can_unary_minus(enum ftenum ftype)
{
	ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->unary_minus != NULL;
}

gboolean
ftype_can_add(enum ftenum ftype)
{
	ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->add != NULL;
}

gboolean
ftype_can_subtract(enum ftenum ftype)
{
	ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->subtract != NULL;
}

gboolean
ftype_can_multiply(enum ftenum ftype)
{
	ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->multiply != NULL;
}

gboolean
ftype_can_divide(enum ftenum ftype)
{
	ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->divide != NULL;
}

gboolean
ftype_can_modulo(enum ftenum ftype)
{
	ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->modulo != NULL;
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

gboolean
ftype_can_is_zero(enum ftenum ftype)
{
	ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->is_zero ? TRUE : FALSE;
}

gboolean
ftype_can_is_negative(enum ftenum ftype)
{
	ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->is_negative ? TRUE : FALSE;
}

gboolean
ftype_can_val_to_sinteger(enum ftenum ftype)
{
	ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	/* We first convert to 64 bit and then check for overflow. */
	return ft->val_to_sinteger64 ? TRUE : FALSE;
}

gboolean
ftype_can_val_to_uinteger(enum ftenum ftype)
{
	ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	/* We first convert to 64 bit and then check for overflow. */
	return ft->val_to_uinteger64 ? TRUE : FALSE;
}

gboolean
ftype_can_val_to_sinteger64(enum ftenum ftype)
{
	ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->val_to_sinteger64 ? TRUE : FALSE;
}

gboolean
ftype_can_val_to_uinteger64(enum ftenum ftype)
{
	ftype_t	*ft;

	FTYPE_LOOKUP(ftype, ft);
	return ft->val_to_uinteger64 ? TRUE : FALSE;
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

fvalue_t*
fvalue_dup(const fvalue_t *fv_orig)
{
	fvalue_t		*fv_new;
	FvalueCopyFunc		copy_value;

	fv_new = g_slice_new(fvalue_t);
	fv_new->ftype = fv_orig->ftype;
	copy_value = fv_new->ftype->copy_value;
	if (copy_value != NULL) {
		/* deep copy */
		copy_value(fv_new, fv_orig);
	}
	else {
		/* shallow copy */
		memcpy(&fv_new->value, &fv_orig->value, sizeof(fv_orig->value));
	}

	return fv_new;
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

void
fvalue_cleanup(fvalue_t *fv)
{
	if (!fv->ftype->free_value)
		return;
	fv->ftype->free_value(fv);
}

void
fvalue_free(fvalue_t *fv)
{
	fvalue_cleanup(fv);
	g_slice_free(fvalue_t, fv);
}

fvalue_t*
fvalue_from_literal(ftenum_t ftype, const char *s, gboolean allow_partial_value, gchar **err_msg)
{
	fvalue_t	*fv;
	gboolean ok = FALSE;

	fv = fvalue_new(ftype);
	if (fv->ftype->val_from_literal) {
		ok = fv->ftype->val_from_literal(fv, s, allow_partial_value, err_msg);
		if (ok) {
			/* Success */
			if (err_msg != NULL)
				*err_msg = NULL;
			return fv;
		}
	}
	else {
		if (err_msg != NULL) {
			*err_msg = ws_strdup_printf("\"%s\" cannot be converted to %s.",
					s, ftype_pretty_name(ftype));
		}
	}
	fvalue_free(fv);
	return NULL;
}

fvalue_t*
fvalue_from_string(ftenum_t ftype, const char *str, size_t len, gchar **err_msg)
{
	fvalue_t	*fv;

	fv = fvalue_new(ftype);
	if (fv->ftype->val_from_string) {
		if (fv->ftype->val_from_string(fv, str, len, err_msg)) {
			/* Success */
			if (err_msg != NULL)
				*err_msg = NULL;
			return fv;
		}
	}
	else {
		if (err_msg != NULL) {
			*err_msg = ws_strdup_printf("%s cannot be converted from a string (\"%s\").",
					ftype_pretty_name(ftype), str);
		}
	}
	fvalue_free(fv);
	return NULL;
}

fvalue_t*
fvalue_from_charconst(ftenum_t ftype, unsigned long num, gchar **err_msg)
{
	fvalue_t	*fv;

	fv = fvalue_new(ftype);
	if (fv->ftype->val_from_charconst) {
		if (fv->ftype->val_from_charconst(fv, num, err_msg)) {
			/* Success */
			if (err_msg != NULL)
				*err_msg = NULL;
			return fv;
		}
	}
	else {
		if (err_msg != NULL) {
			if (num <= 0x7f && g_ascii_isprint(num)) {
				*err_msg = ws_strdup_printf("Character constant '%c' (0x%lx) cannot be converted to %s.",
						(int)num, num, ftype_pretty_name(ftype));
			}
			else {
				*err_msg = ws_strdup_printf("Character constant 0x%lx cannot be converted to %s.",
						num, ftype_pretty_name(ftype));
			}
		}
	}
	fvalue_free(fv);
	return NULL;
}

ftenum_t
fvalue_type_ftenum(fvalue_t *fv)
{
	return fv->ftype->ftype;
}

const char*
fvalue_type_name(const fvalue_t *fv)
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

char *
fvalue_to_string_repr(wmem_allocator_t *scope, const fvalue_t *fv, ftrepr_t rtype, int field_display)
{
	if (fv->ftype->val_to_string_repr == NULL) {
		/* no value-to-string-representation function, so the value cannot be represented */
		return NULL;
	}

	return fv->ftype->val_to_string_repr(scope, fv, rtype, field_display);
}

enum ft_result
fvalue_to_uinteger(const fvalue_t *fv, guint32 *repr)
{
	guint64 val;
	enum ft_result res = fv->ftype->val_to_uinteger64(fv, &val);
	if (res != FT_OK)
		return res;
	if (val > G_MAXUINT32)
		return FT_OVERFLOW;

	*repr = (guint32)val;
	return FT_OK;
}

enum ft_result
fvalue_to_sinteger(const fvalue_t *fv, gint32 *repr)
{
	gint64 val;
	enum ft_result res = fv->ftype->val_to_sinteger64(fv, &val);
	if (res != FT_OK)
		return res;
	if (val > G_MAXINT32)
		return FT_OVERFLOW;

	*repr = (gint32)val;
	return FT_OK;
}

enum ft_result
fvalue_to_uinteger64(const fvalue_t *fv, guint64 *repr)
{
	return fv->ftype->val_to_uinteger64(fv, repr);
}

enum ft_result
fvalue_to_sinteger64(const fvalue_t *fv, gint64 *repr)
{
	return fv->ftype->val_to_sinteger64(fv, repr);
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
		ws_assert_not_reached();
	}

	ws_assert(start_offset >=0 && length > 0);
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
	ws_assert(fv->ftype->ftype == FT_BYTES ||
			fv->ftype->ftype == FT_UINT_BYTES ||
			fv->ftype->ftype == FT_OID ||
			fv->ftype->ftype == FT_REL_OID ||
			fv->ftype->ftype == FT_SYSTEM_ID);
	ws_assert(fv->ftype->set_value.set_value_byte_array);
	fv->ftype->set_value.set_value_byte_array(fv, value);
}

void
fvalue_set_bytes(fvalue_t *fv, const guint8 *value)
{
	ws_assert(fv->ftype->ftype == FT_AX25 ||
			fv->ftype->ftype == FT_VINES ||
			fv->ftype->ftype == FT_ETHER ||
			fv->ftype->ftype == FT_FCWWN ||
			fv->ftype->ftype == FT_IPv6);
	ws_assert(fv->ftype->set_value.set_value_bytes);
	fv->ftype->set_value.set_value_bytes(fv, value);
}

void
fvalue_set_guid(fvalue_t *fv, const e_guid_t *value)
{
	ws_assert(fv->ftype->ftype == FT_GUID);
	ws_assert(fv->ftype->set_value.set_value_guid);
	fv->ftype->set_value.set_value_guid(fv, value);
}

void
fvalue_set_time(fvalue_t *fv, const nstime_t *value)
{
	ws_assert(IS_FT_TIME(fv->ftype->ftype));
	ws_assert(fv->ftype->set_value.set_value_time);
	fv->ftype->set_value.set_value_time(fv, value);
}

void
fvalue_set_string(fvalue_t *fv, const gchar *value)
{
	wmem_strbuf_t *buf = wmem_strbuf_new(NULL, value);
	fvalue_set_strbuf(fv, buf);
}

void
fvalue_set_strbuf(fvalue_t *fv, wmem_strbuf_t *value)
{
	if (value->allocator != NULL) {
		/* XXX Can this condition be relaxed? */
		ws_critical("Fvalue strbuf allocator must be NULL");
	}
	ws_assert(IS_FT_STRING(fv->ftype->ftype));
	ws_assert(fv->ftype->set_value.set_value_strbuf);
	fv->ftype->set_value.set_value_strbuf(fv, value);
}

void
fvalue_set_protocol(fvalue_t *fv, tvbuff_t *value, const gchar *name, int length)
{
	ws_assert(fv->ftype->ftype == FT_PROTOCOL);
	ws_assert(fv->ftype->set_value.set_value_protocol);
	fv->ftype->set_value.set_value_protocol(fv, value, name, length);
}

void
fvalue_set_uinteger(fvalue_t *fv, guint32 value)
{
	ws_assert(fv->ftype->ftype == FT_IEEE_11073_SFLOAT ||
			fv->ftype->ftype == FT_IEEE_11073_FLOAT ||
			fv->ftype->ftype == FT_CHAR ||
			fv->ftype->ftype == FT_UINT8 ||
			fv->ftype->ftype == FT_UINT16 ||
			fv->ftype->ftype == FT_UINT24 ||
			fv->ftype->ftype == FT_UINT32 ||
			fv->ftype->ftype == FT_IPXNET ||
			fv->ftype->ftype == FT_FRAMENUM ||
			fv->ftype->ftype == FT_IPv4);
	ws_assert(fv->ftype->set_value.set_value_uinteger);
	fv->ftype->set_value.set_value_uinteger(fv, value);
}

void
fvalue_set_sinteger(fvalue_t *fv, gint32 value)
{
	ws_assert(fv->ftype->ftype == FT_INT8 ||
			fv->ftype->ftype == FT_INT16 ||
			fv->ftype->ftype == FT_INT24 ||
			fv->ftype->ftype == FT_INT32);
	ws_assert(fv->ftype->set_value.set_value_sinteger);
	fv->ftype->set_value.set_value_sinteger(fv, value);
}

void
fvalue_set_uinteger64(fvalue_t *fv, guint64 value)
{
	ws_assert(fv->ftype->ftype == FT_UINT40 ||
			fv->ftype->ftype == FT_UINT48 ||
			fv->ftype->ftype == FT_UINT56 ||
			fv->ftype->ftype == FT_UINT64 ||
			fv->ftype->ftype == FT_BOOLEAN ||
			fv->ftype->ftype == FT_EUI64);
	ws_assert(fv->ftype->set_value.set_value_uinteger64);
	fv->ftype->set_value.set_value_uinteger64(fv, value);
}

void
fvalue_set_sinteger64(fvalue_t *fv, gint64 value)
{
	ws_assert(fv->ftype->ftype == FT_INT40 ||
			fv->ftype->ftype == FT_INT48 ||
			fv->ftype->ftype == FT_INT56 ||
			fv->ftype->ftype == FT_INT64);
	ws_assert(fv->ftype->set_value.set_value_sinteger64);
	fv->ftype->set_value.set_value_sinteger64(fv, value);
}

void
fvalue_set_floating(fvalue_t *fv, gdouble value)
{
	ws_assert(fv->ftype->ftype == FT_FLOAT ||
			fv->ftype->ftype == FT_DOUBLE);
	ws_assert(fv->ftype->set_value.set_value_floating);
	fv->ftype->set_value.set_value_floating(fv, value);
}

const guint8 *
fvalue_get_bytes(fvalue_t *fv)
{
	ws_assert(fv->ftype->ftype == FT_BYTES ||
			fv->ftype->ftype == FT_UINT_BYTES ||
			fv->ftype->ftype == FT_AX25 ||
			fv->ftype->ftype == FT_VINES ||
			fv->ftype->ftype == FT_ETHER ||
			fv->ftype->ftype == FT_OID ||
			fv->ftype->ftype == FT_REL_OID ||
			fv->ftype->ftype == FT_SYSTEM_ID ||
			fv->ftype->ftype == FT_FCWWN ||
			fv->ftype->ftype == FT_IPv6);
	ws_assert(fv->ftype->get_value.get_value_bytes);
	return fv->ftype->get_value.get_value_bytes(fv);
}

const e_guid_t *
fvalue_get_guid(fvalue_t *fv)
{
	ws_assert(fv->ftype->ftype == FT_GUID);
	ws_assert(fv->ftype->get_value.get_value_guid);
	return fv->ftype->get_value.get_value_guid(fv);
}

const nstime_t *
fvalue_get_time(fvalue_t *fv)
{
	ws_assert(IS_FT_TIME(fv->ftype->ftype));
	ws_assert(fv->ftype->get_value.get_value_time);
	return fv->ftype->get_value.get_value_time(fv);
}

const char *
fvalue_get_string(fvalue_t *fv)
{
	return wmem_strbuf_get_str(fvalue_get_strbuf(fv));
}

const wmem_strbuf_t *
fvalue_get_strbuf(fvalue_t *fv)
{
	ws_assert(IS_FT_STRING(fv->ftype->ftype));
	ws_assert(fv->ftype->get_value.get_value_strbuf);
	return fv->ftype->get_value.get_value_strbuf(fv);
}

tvbuff_t *
fvalue_get_protocol(fvalue_t *fv)
{
	ws_assert(fv->ftype->ftype == FT_PROTOCOL);
	ws_assert(fv->ftype->get_value.get_value_protocol);
	return fv->ftype->get_value.get_value_protocol(fv);
}

guint32
fvalue_get_uinteger(fvalue_t *fv)
{
	ws_assert(fv->ftype->ftype == FT_IEEE_11073_SFLOAT ||
			fv->ftype->ftype == FT_IEEE_11073_FLOAT ||
			fv->ftype->ftype == FT_CHAR ||
			fv->ftype->ftype == FT_UINT8 ||
			fv->ftype->ftype == FT_UINT16 ||
			fv->ftype->ftype == FT_UINT24 ||
			fv->ftype->ftype == FT_UINT32 ||
			fv->ftype->ftype == FT_IPXNET ||
			fv->ftype->ftype == FT_FRAMENUM ||
			fv->ftype->ftype == FT_IPv4);
	ws_assert(fv->ftype->get_value.get_value_uinteger);
	return fv->ftype->get_value.get_value_uinteger(fv);
}

gint32
fvalue_get_sinteger(fvalue_t *fv)
{
	ws_assert(fv->ftype->ftype == FT_INT8 ||
			fv->ftype->ftype == FT_INT16 ||
			fv->ftype->ftype == FT_INT24 ||
			fv->ftype->ftype == FT_INT32);
	ws_assert(fv->ftype->get_value.get_value_sinteger);
	return fv->ftype->get_value.get_value_sinteger(fv);
}

guint64
fvalue_get_uinteger64(fvalue_t *fv)
{
	ws_assert(fv->ftype->ftype == FT_UINT40 ||
			fv->ftype->ftype == FT_UINT48 ||
			fv->ftype->ftype == FT_UINT56 ||
			fv->ftype->ftype == FT_UINT64 ||
			fv->ftype->ftype == FT_BOOLEAN ||
			fv->ftype->ftype == FT_EUI64);
	ws_assert(fv->ftype->get_value.get_value_uinteger64);
	return fv->ftype->get_value.get_value_uinteger64(fv);
}

gint64
fvalue_get_sinteger64(fvalue_t *fv)
{
	ws_assert(fv->ftype->ftype == FT_INT40 ||
			fv->ftype->ftype == FT_INT48 ||
			fv->ftype->ftype == FT_INT56 ||
			fv->ftype->ftype == FT_INT64);
	ws_assert(fv->ftype->get_value.get_value_sinteger64);
	return fv->ftype->get_value.get_value_sinteger64(fv);
}

double
fvalue_get_floating(fvalue_t *fv)
{
	ws_assert(fv->ftype->ftype == FT_FLOAT ||
			fv->ftype->ftype == FT_DOUBLE);
	ws_assert(fv->ftype->get_value.get_value_floating);
	return fv->ftype->get_value.get_value_floating(fv);
}

ft_bool_t
fvalue_eq(const fvalue_t *a, const fvalue_t *b)
{
	int cmp;
	enum ft_result res;

	ws_assert(a->ftype->cmp_order);
	res = a->ftype->cmp_order(a, b, &cmp);
	if (res != FT_OK)
		return -res;
	return cmp == 0 ? FT_TRUE : FT_FALSE;
}

ft_bool_t
fvalue_ne(const fvalue_t *a, const fvalue_t *b)
{
	int cmp;
	enum ft_result res;

	ws_assert(a->ftype->cmp_order);
	res = a->ftype->cmp_order(a, b, &cmp);
	if (res != FT_OK)
		return -res;
	return cmp != 0 ? FT_TRUE : FT_FALSE;
}

ft_bool_t
fvalue_gt(const fvalue_t *a, const fvalue_t *b)
{
	int cmp;
	enum ft_result res;

	ws_assert(a->ftype->cmp_order);
	res = a->ftype->cmp_order(a, b, &cmp);
	if (res != FT_OK)
		return -res;
	return cmp > 0 ? FT_TRUE : FT_FALSE;
}

ft_bool_t
fvalue_ge(const fvalue_t *a, const fvalue_t *b)
{
	int cmp;
	enum ft_result res;

	ws_assert(a->ftype->cmp_order);
	res = a->ftype->cmp_order(a, b, &cmp);
	if (res != FT_OK)
		return -res;
	return cmp >= 0 ? FT_TRUE : FT_FALSE;
}

ft_bool_t
fvalue_lt(const fvalue_t *a, const fvalue_t *b)
{
	int cmp;
	enum ft_result res;

	ws_assert(a->ftype->cmp_order);
	res = a->ftype->cmp_order(a, b, &cmp);
	if (res != FT_OK)
		return -res;
	return cmp < 0 ? FT_TRUE : FT_FALSE;
}

ft_bool_t
fvalue_le(const fvalue_t *a, const fvalue_t *b)
{
	int cmp;
	enum ft_result res;

	ws_assert(a->ftype->cmp_order);
	res = a->ftype->cmp_order(a, b, &cmp);
	if (res != FT_OK)
		return -res;
	return cmp <= 0 ? FT_TRUE : FT_FALSE;
}

ft_bool_t
fvalue_contains(const fvalue_t *a, const fvalue_t *b)
{
	gboolean yes;
	enum ft_result res;

	ws_assert(a->ftype->cmp_contains);
	res = a->ftype->cmp_contains(a, b, &yes);
	if (res != FT_OK)
		return -res;
	return yes ? FT_TRUE : FT_FALSE;
}

ft_bool_t
fvalue_matches(const fvalue_t *a, const ws_regex_t *re)
{
	gboolean yes;
	enum ft_result res;

	ws_assert(a->ftype->cmp_matches);
	res = a->ftype->cmp_matches(a, re, &yes);
	if (res != FT_OK)
		return -res;
	return yes ? FT_TRUE : FT_FALSE;
}

gboolean
fvalue_is_zero(const fvalue_t *a)
{
	return a->ftype->is_zero(a);
}

gboolean
fvalue_is_negative(const fvalue_t *a)
{
	return a->ftype->is_negative(a);
}

static fvalue_t *
_fvalue_binop(FvalueBinaryOp op, const fvalue_t *a, const fvalue_t *b, char **err_msg)
{
	fvalue_t *result;

	result = fvalue_new(a->ftype->ftype);
	if (op(result, a, b, err_msg) != FT_OK) {
		fvalue_free(result);
		return NULL;
	}
	return result;
}

fvalue_t *
fvalue_bitwise_and(const fvalue_t *a, const fvalue_t *b, char **err_msg)
{
	/* XXX - check compatibility of a and b */
	ws_assert(a->ftype->bitwise_and);
	return _fvalue_binop(a->ftype->bitwise_and, a, b, err_msg);
}

fvalue_t *
fvalue_add(const fvalue_t *a, const fvalue_t *b, gchar **err_msg)
{
	/* XXX - check compatibility of a and b */
	ws_assert(a->ftype->add);
	return _fvalue_binop(a->ftype->add, a, b, err_msg);
}

fvalue_t *
fvalue_subtract(const fvalue_t *a, const fvalue_t *b, gchar **err_msg)
{
	/* XXX - check compatibility of a and b */
	ws_assert(a->ftype->subtract);
	return _fvalue_binop(a->ftype->subtract, a, b, err_msg);
}

fvalue_t *
fvalue_multiply(const fvalue_t *a, const fvalue_t *b, gchar **err_msg)
{
	/* XXX - check compatibility of a and b */
	ws_assert(a->ftype->multiply);
	return _fvalue_binop(a->ftype->multiply, a, b, err_msg);
}

fvalue_t *
fvalue_divide(const fvalue_t *a, const fvalue_t *b, gchar **err_msg)
{
	/* XXX - check compatibility of a and b */
	ws_assert(a->ftype->divide);
	return _fvalue_binop(a->ftype->divide, a, b, err_msg);
}

fvalue_t *
fvalue_modulo(const fvalue_t *a, const fvalue_t *b, gchar **err_msg)
{
	/* XXX - check compatibility of a and b */
	ws_assert(a->ftype->modulo);
	return _fvalue_binop(a->ftype->modulo, a, b, err_msg);
}

fvalue_t*
fvalue_unary_minus(const fvalue_t *fv, char **err_msg)
{
	fvalue_t *result;

	ws_assert(fv->ftype->unary_minus);

	result = fvalue_new(fv->ftype->ftype);
	if (fv->ftype->unary_minus(result, fv, err_msg) != FT_OK) {
		fvalue_free(result);
		return NULL;
	}
	return result;
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
