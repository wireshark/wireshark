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
#ifdef HAVE_PCRE2
#include <pcre2.h>
#endif

struct _fvalue_regex_t {
	void *code;
	char *pattern;
	char *repr_debug;
};

/* Keep track of ftype_t's via their ftenum number */
static ftype_t* type_list[FT_NUM_TYPES];

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

/* Given an ftenum number, return an ftype_t* */
#define FTYPE_LOOKUP(ftype, result)	\
	/* Check input */		\
	ws_assert(ftype < FT_NUM_TYPES);	\
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
fvalue_from_unparsed(ftenum_t ftype, const char *s, gboolean allow_partial_value, gchar **err_msg)
{
	fvalue_t	*fv;

	fv = fvalue_new(ftype);
	if (fv->ftype->val_from_unparsed) {
		if (fv->ftype->val_from_unparsed(fv, s, allow_partial_value, err_msg)) {
			/* Success */
			if (err_msg != NULL)
				*err_msg = NULL;
			return fv;
		}
	}
	else {
		if (err_msg != NULL) {
			*err_msg = g_strdup_printf("\"%s\" cannot be converted to %s.",
					s, ftype_pretty_name(ftype));
		}
	}
	fvalue_free(fv);
	return NULL;
}

fvalue_t*
fvalue_from_string(ftenum_t ftype, const char *s, gchar **err_msg)
{
	fvalue_t	*fv;

	fv = fvalue_new(ftype);
	if (fv->ftype->val_from_string) {
		if (fv->ftype->val_from_string(fv, s, err_msg)) {
			/* Success */
			if (err_msg != NULL)
				*err_msg = NULL;
			return fv;
		}
	}
	else {
		if (err_msg != NULL) {
			*err_msg = g_strdup_printf("\"%s\" cannot be converted to %s.",
					s, ftype_pretty_name(ftype));
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
	ws_assert(IS_FT_STRING(fv->ftype->ftype) ||
			fv->ftype->ftype == FT_UINT_STRING);
	ws_assert(fv->ftype->set_value.set_value_string);
	fv->ftype->set_value.set_value_string(fv, value);
}

void
fvalue_set_protocol(fvalue_t *fv, tvbuff_t *value, const gchar *name)
{
	ws_assert(fv->ftype->ftype == FT_PROTOCOL);
	ws_assert(fv->ftype->set_value.set_value_protocol);
	fv->ftype->set_value.set_value_protocol(fv, value, name);
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


gpointer
fvalue_get(fvalue_t *fv)
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
			fv->ftype->ftype == FT_GUID ||
			fv->ftype->ftype == FT_IPv6 ||
			fv->ftype->ftype == FT_PROTOCOL ||
			IS_FT_STRING(fv->ftype->ftype) ||
			fv->ftype->ftype == FT_UINT_STRING ||
			IS_FT_TIME(fv->ftype->ftype));
	ws_assert(fv->ftype->get_value.get_value_ptr);
	return fv->ftype->get_value.get_value_ptr(fv);
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

static inline int
_fvalue_cmp(const fvalue_t *a, const fvalue_t *b)
{
	/* XXX - check compatibility of a and b */
	ws_assert(a->ftype->cmp_order);
	return a->ftype->cmp_order(a, b);
}

gboolean
fvalue_eq(const fvalue_t *a, const fvalue_t *b)
{
	return _fvalue_cmp(a, b) == 0;
}

gboolean
fvalue_ne(const fvalue_t *a, const fvalue_t *b)
{
	return _fvalue_cmp(a, b) != 0;
}

gboolean
fvalue_gt(const fvalue_t *a, const fvalue_t *b)
{
	return _fvalue_cmp(a, b) > 0;
}

gboolean
fvalue_ge(const fvalue_t *a, const fvalue_t *b)
{
	return _fvalue_cmp(a, b) >= 0;
}

gboolean
fvalue_lt(const fvalue_t *a, const fvalue_t *b)
{
	return _fvalue_cmp(a, b) < 0;
}

gboolean
fvalue_le(const fvalue_t *a, const fvalue_t *b)
{
	return _fvalue_cmp(a, b) <= 0;
}

gboolean
fvalue_bitwise_and(const fvalue_t *a, const fvalue_t *b)
{
	/* XXX - check compatibility of a and b */
	ws_assert(a->ftype->cmp_bitwise_and);
	return a->ftype->cmp_bitwise_and(a, b);
}

gboolean
fvalue_contains(const fvalue_t *a, const fvalue_t *b)
{
	/* XXX - check compatibility of a and b */
	ws_assert(a->ftype->cmp_contains);
	return a->ftype->cmp_contains(a, b);
}

gboolean
fvalue_matches(const fvalue_t *a, const fvalue_regex_t *b)
{
	/* XXX - check compatibility of a and b */
	ws_assert(a->ftype->cmp_matches);
	return a->ftype->cmp_matches(a, b);
}

#ifdef HAVE_PCRE2
static pcre2_code *
_pcre2_compile(const char *patt, char **errmsg)
{
	pcre2_code *code;
	int errorcode;
	PCRE2_SIZE erroroffset;

	/* By default UTF-8 is off. */
	code = pcre2_compile_8((PCRE2_SPTR)patt,
				PCRE2_ZERO_TERMINATED,
				PCRE2_NEVER_UTF,
				&errorcode,
				&erroroffset,
				NULL);

	if (code == NULL) {
		*errmsg = g_malloc0(128);
		pcre2_get_error_message(errorcode, *errmsg, 128);
		return NULL;
	}

	return code;
}

static gboolean
_pcre2_matches(pcre2_code *code, const char *subj, gssize subj_size)
{
	PCRE2_SIZE length;
	pcre2_match_data *match_data;
	int rc;

	length = subj_size < 0 ? PCRE2_ZERO_TERMINATED : (PCRE2_SIZE)subj_size;
	match_data = pcre2_match_data_create_from_pattern(code, NULL);

	rc = pcre2_match(code, subj, length, 0, 0, match_data, NULL);
	pcre2_match_data_free(match_data);

	return rc < 0 ? FALSE : TRUE;
}
#endif /* HAVE_PCRE2 */

fvalue_regex_t *
fvalue_regex_compile(const char *patt, char **errmsg)
{
	void *code;

#ifdef HAVE_PCRE2
	code = _pcre2_compile(patt, errmsg);
#else
	(void)patt;
	code = NULL;
	*errmsg = g_strdup("Wireshark was compiled without PCRE2");
#endif
	if (code == NULL)
		return NULL;

	fvalue_regex_t *re = g_new(fvalue_regex_t, 1);
	re->code = code;
	re->pattern = g_strdup(patt);
	re->repr_debug = NULL;
	return re;
}

gboolean
fvalue_regex_matches(const fvalue_regex_t *regex, const char *subj, gssize subj_size)
{
#ifdef HAVE_PCRE2
	ws_assert(regex != NULL);
	return _pcre2_matches(regex->code, subj, subj_size);
#else
	ws_assert(regex == NULL);
	(void)subj;
	(void)subj_size;
	return FALSE;
#endif
}

void
fvalue_regex_free(fvalue_regex_t *regex)
{
#ifdef HAVE_PCRE2
	pcre2_code_free(regex->code);
#endif
	g_free(regex->pattern);
	g_free(regex->repr_debug);
	g_free(regex);
}

const char *
fvalue_regex_tostr(const fvalue_regex_t *regex, gboolean pretty)
{
	if (pretty)
		return regex->pattern;

	if (regex->repr_debug == NULL) {
#ifdef HAVE_PCRE2
		const char *kind = "PCRE2";
#else
		const char *kind = "not supported";
#endif
		((fvalue_regex_t *)regex)->repr_debug =
			g_strdup_printf("(%s)%s", kind, regex->pattern);
	}
	return regex->repr_debug;
}

const char *
fvalue_regex_pattern(const fvalue_regex_t *regex)
{
	return regex->pattern;
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
