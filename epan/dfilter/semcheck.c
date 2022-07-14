/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#define WS_LOG_DOMAIN LOG_DOMAIN_DFILTER

#include <string.h>

#include "dfilter-int.h"
#include "semcheck.h"
#include "syntax-tree.h"
#include "sttype-field.h"
#include "sttype-slice.h"
#include "sttype-op.h"
#include "sttype-set.h"
#include "sttype-function.h"
#include "sttype-pointer.h"

#include <epan/exceptions.h>
#include <epan/packet.h>

#include <wsutil/ws_assert.h>
#include <wsutil/wslog.h>

#include <ftypes/ftypes.h>


#define FAIL(dfw, node, ...) \
	do {								\
		ws_noisy("Semantic check failed here.");		\
		dfilter_fail_throw(dfw, stnode_location(node), __VA_ARGS__); \
	} while (0)

static void
semcheck(dfwork_t *dfw, stnode_t *st_node);

static fvalue_t *
mk_fvalue_from_val_string(dfwork_t *dfw, header_field_info *hfinfo, const char *s);

typedef gboolean (*FtypeCanFunc)(enum ftenum);

/* Compares to ftenum_t's and decides if they're
 * compatible or not (if they're the same basic type) */
static gboolean
compatible_ftypes(ftenum_t a, ftenum_t b)
{
	switch (a) {
		case FT_NONE:
		case FT_BOOLEAN:
		case FT_PROTOCOL:
		case FT_ABSOLUTE_TIME:
		case FT_RELATIVE_TIME:
		case FT_IEEE_11073_SFLOAT:
		case FT_IEEE_11073_FLOAT:
		case FT_IPv4:
		case FT_IPv6:
			return a == b;

		case FT_FLOAT:		/* XXX - should be able to compare with INT */
		case FT_DOUBLE:		/* XXX - should be able to compare with INT */
			switch (b) {
				case FT_FLOAT:
				case FT_DOUBLE:
					return TRUE;
				default:
					return FALSE;
			}

		case FT_ETHER:
		case FT_BYTES:
		case FT_UINT_BYTES:
		case FT_GUID:
		case FT_OID:
		case FT_AX25:
		case FT_VINES:
		case FT_FCWWN:
		case FT_REL_OID:
		case FT_SYSTEM_ID:

			return (b == FT_ETHER || b == FT_BYTES || b == FT_UINT_BYTES || b == FT_GUID || b == FT_OID || b == FT_AX25 || b == FT_VINES || b == FT_FCWWN || b == FT_REL_OID || b == FT_SYSTEM_ID);

		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
		case FT_CHAR:
		case FT_FRAMENUM:
		case FT_IPXNET:
			return ftype_can_val_to_uinteger(b);

		case FT_UINT40:
		case FT_UINT48:
		case FT_UINT56:
		case FT_UINT64:
		case FT_EUI64:
			return ftype_can_val_to_uinteger64(b);

		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
			return ftype_can_val_to_sinteger(b);

		case FT_INT40:
		case FT_INT48:
		case FT_INT56:
		case FT_INT64:
			return ftype_can_val_to_sinteger64(b);

		case FT_STRING:
		case FT_STRINGZ:
		case FT_UINT_STRING:
		case FT_STRINGZPAD:
		case FT_STRINGZTRUNC:
			switch (b) {
				case FT_STRING:
				case FT_STRINGZ:
				case FT_UINT_STRING:
				case FT_STRINGZPAD:
				case FT_STRINGZTRUNC:
					return TRUE;
				default:
					return FALSE;
			}

		case FT_NUM_TYPES:
			ws_assert_not_reached();
	}

	ws_assert_not_reached();
	return FALSE;
}

static gboolean
node_is_constant(stnode_t *node)
{
	switch (stnode_type_id(node)) {
		case STTYPE_CHARCONST:
		case STTYPE_STRING:
		case STTYPE_LITERAL:
			return TRUE;
		default:
			break;
	}
	return FALSE;
}

/* Gets an fvalue from a string, and sets the error message on failure. */
WS_RETNONNULL
fvalue_t*
dfilter_fvalue_from_literal(dfwork_t *dfw, ftenum_t ftype, stnode_t *st,
		gboolean allow_partial_value, header_field_info *hfinfo_value_string)
{
	fvalue_t *fv;
	const char *s = stnode_data(st);

	/* Don't set the error message if it's already set. */
	fv = fvalue_from_literal(ftype, s, allow_partial_value,
		dfw->error_message == NULL ? &dfw->error_message : NULL);
	if (fv == NULL && hfinfo_value_string) {
		/* check value_string */
		fv = mk_fvalue_from_val_string(dfw, hfinfo_value_string, s);
		/*
		 * Ignore previous errors if this can be mapped
		 * to an item from value_string.
		 */
		if (fv && dfw->error_message) {
			g_free(dfw->error_message);
			dfw->error_message = NULL;
		}
	}
	if (fv == NULL) {
		dfw_set_error_location(dfw, stnode_location(st));
		THROW(TypeError);
	}

	return fv;
}

/* Gets an fvalue from a string, and sets the error message on failure. */
WS_RETNONNULL
fvalue_t *
dfilter_fvalue_from_string(dfwork_t *dfw, ftenum_t ftype, stnode_t *st,
		header_field_info *hfinfo_value_string)
{
	fvalue_t *fv;
	const GString *gs = stnode_string(st);

	fv = fvalue_from_string(ftype, gs->str, gs->len,
	    dfw->error_message == NULL ? &dfw->error_message : NULL);
	if (fv == NULL && hfinfo_value_string) {
		fv = mk_fvalue_from_val_string(dfw, hfinfo_value_string, gs->str);
		/*
		 * Ignore previous errors if this can be mapped
		 * to an item from value_string.
		 */
		if (fv && dfw->error_message) {
			g_free(dfw->error_message);
			dfw->error_message = NULL;
		}
	}
	if (fv == NULL) {
		dfw_set_error_location(dfw, stnode_location(st));
		THROW(TypeError);
	}

	return fv;
}

/* Creates a FT_UINT32 fvalue with a given value. */
static fvalue_t*
mk_uint32_fvalue(guint32 val)
{
	fvalue_t *fv;

	fv = fvalue_new(FT_UINT32);
	fvalue_set_uinteger(fv, val);

	return fv;
}

/* Creates a FT_UINT64 fvalue with a given value. */
static fvalue_t*
mk_uint64_fvalue(guint64 val)
{
	fvalue_t *fv;

	fv = fvalue_new(FT_UINT64);
	fvalue_set_uinteger64(fv, val);

	return fv;
}

/* Try to make an fvalue from a string using a value_string or true_false_string.
 * This works only for ftypes that are integers. Returns the created fvalue_t*
 * or NULL if impossible. */
static fvalue_t*
mk_fvalue_from_val_string(dfwork_t *dfw, header_field_info *hfinfo, const char *s)
{
	static const true_false_string  default_tf = { "True", "False" };
	const true_false_string		*tf = &default_tf;

	/* Early return? */
	switch(hfinfo->type) {
		case FT_NONE:
		case FT_PROTOCOL:
		case FT_FLOAT:
		case FT_DOUBLE:
		case FT_IEEE_11073_SFLOAT:
		case FT_IEEE_11073_FLOAT:
		case FT_ABSOLUTE_TIME:
		case FT_RELATIVE_TIME:
		case FT_IPv4:
		case FT_IPv6:
		case FT_IPXNET:
		case FT_AX25:
		case FT_VINES:
		case FT_FCWWN:
		case FT_ETHER:
		case FT_BYTES:
		case FT_UINT_BYTES:
		case FT_STRING:
		case FT_STRINGZ:
		case FT_UINT_STRING:
		case FT_STRINGZPAD:
		case FT_STRINGZTRUNC:
		case FT_EUI64:
		case FT_GUID:
		case FT_OID:
		case FT_REL_OID:
		case FT_SYSTEM_ID:
		case FT_FRAMENUM: /* hfinfo->strings contains ft_framenum_type_t, not strings */
			return NULL;

		case FT_BOOLEAN:
		case FT_CHAR:
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
		case FT_UINT40:
		case FT_UINT48:
		case FT_UINT56:
		case FT_UINT64:
		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
		case FT_INT40:
		case FT_INT48:
		case FT_INT56:
		case FT_INT64:
			break;

		case FT_NUM_TYPES:
			ws_assert_not_reached();
	}

	/* TRUE/FALSE *always* exist for FT_BOOLEAN. */
	if (hfinfo->type == FT_BOOLEAN) {
		if (hfinfo->strings) {
			tf = (const true_false_string *)hfinfo->strings;
		}

		if (g_ascii_strcasecmp(s, tf->true_string) == 0) {
			return mk_uint64_fvalue(TRUE);
		}
		else if (g_ascii_strcasecmp(s, tf->false_string) == 0) {
			return mk_uint64_fvalue(FALSE);
		}
		else {
			/*
			 * Prefer this error message to whatever error message
			 * has already been set.
			 */
			g_free(dfw->error_message);
			dfw->error_message = NULL;
			dfilter_fail(dfw, NULL, "\"%s\" cannot be found among the possible values for %s.",
				s, hfinfo->abbrev);
			return NULL;
		}
	}

	/* Do val_strings exist? */
	if (!hfinfo->strings) {
		dfilter_fail(dfw, NULL, "%s cannot accept strings as values.",
				hfinfo->abbrev);
		return NULL;
	}

	/* Reset the error message, since *something* interesting will happen,
	 * and the error message will be more interesting than any error message
	 * I happen to have now. */
	g_free(dfw->error_message);
	dfw->error_message = NULL;

	if (hfinfo->display & BASE_RANGE_STRING) {
		dfilter_fail(dfw, NULL, "\"%s\" cannot accept [range] strings as values.",
				hfinfo->abbrev);
	}
	else if (hfinfo->display & BASE_VAL64_STRING) {
		const val64_string *vals = (const val64_string *)hfinfo->strings;

		while (vals->strptr != NULL) {
			if (g_ascii_strcasecmp(s, vals->strptr) == 0) {
				return mk_uint64_fvalue(vals->value);
			}
			vals++;
		}
		dfilter_fail(dfw, NULL, "\"%s\" cannot be found among the possible values for %s.",
				s, hfinfo->abbrev);
	}
	else if (hfinfo->display == BASE_CUSTOM) {
		/*  If a user wants to match against a custom string, we would
		 *  somehow have to have the integer value here to pass it in
		 *  to the custom-display function.  But we don't have an
		 *  integer, we have the string they're trying to match.
		 *  -><-
		 */
		dfilter_fail(dfw, NULL, "\"%s\" cannot accept [custom] strings as values.",
				hfinfo->abbrev);
	}
	else {
		const value_string *vals = (const value_string *)hfinfo->strings;
		if (hfinfo->display & BASE_EXT_STRING)
			vals = VALUE_STRING_EXT_VS_P((const value_string_ext *) vals);

		while (vals->strptr != NULL) {
			if (g_ascii_strcasecmp(s, vals->strptr) == 0) {
				return mk_uint32_fvalue(vals->value);
			}
			vals++;
		}
		dfilter_fail(dfw, NULL, "\"%s\" cannot be found among the possible values for %s.",
				s, hfinfo->abbrev);
	}
	return NULL;
}

static gboolean
is_bytes_type(enum ftenum type)
{
	switch(type) {
		case FT_AX25:
		case FT_VINES:
		case FT_FCWWN:
		case FT_ETHER:
		case FT_BYTES:
		case FT_UINT_BYTES:
		case FT_IPv6:
		case FT_GUID:
		case FT_OID:
		case FT_REL_OID:
		case FT_SYSTEM_ID:
			return TRUE;

		case FT_NONE:
		case FT_PROTOCOL:
		case FT_FLOAT:
		case FT_DOUBLE:
		case FT_IEEE_11073_SFLOAT:
		case FT_IEEE_11073_FLOAT:
		case FT_ABSOLUTE_TIME:
		case FT_RELATIVE_TIME:
		case FT_IPv4:
		case FT_IPXNET:
		case FT_STRING:
		case FT_STRINGZ:
		case FT_UINT_STRING:
		case FT_STRINGZPAD:
		case FT_STRINGZTRUNC:
		case FT_BOOLEAN:
		case FT_FRAMENUM:
		case FT_CHAR:
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
		case FT_UINT40:
		case FT_UINT48:
		case FT_UINT56:
		case FT_UINT64:
		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
		case FT_INT40:
		case FT_INT48:
		case FT_INT56:
		case FT_INT64:
		case FT_EUI64:
			return FALSE;

		case FT_NUM_TYPES:
			ws_assert_not_reached();
	}

	ws_assert_not_reached();
	return FALSE;
}

/* Check the semantics of an existence test. */
static void
check_exists(dfwork_t *dfw, stnode_t *st_arg1)
{
	LOG_NODE(st_arg1);

	switch (stnode_type_id(st_arg1)) {
		case STTYPE_FIELD:
			/* This is OK */
			break;
		case STTYPE_REFERENCE:
		case STTYPE_STRING:
		case STTYPE_LITERAL:
		case STTYPE_CHARCONST:
			FAIL(dfw, st_arg1, "%s is neither a field nor a protocol name.",
					stnode_todisplay(st_arg1));
			break;

		case STTYPE_FUNCTION:
			/* XXX - Maybe we should change functions so they can return fields,
			 * in which case the 'exist' should be fine. */
			FAIL(dfw, st_arg1, "You cannot test whether a function is present.");
			break;

		case STTYPE_SET:
		case STTYPE_UNINITIALIZED:
		case STTYPE_NUM_TYPES:
		case STTYPE_TEST:
		case STTYPE_FVALUE:
		case STTYPE_PCRE:
		case STTYPE_ARITHMETIC:
		case STTYPE_SLICE:
			ws_assert_not_reached();
	}
}

static void
check_slice_sanity(dfwork_t *dfw, stnode_t *st, ftenum_t lhs_ftype)
{
	stnode_t		*entity1;
	header_field_info	*hfinfo1;
	ftenum_t		ftype1;

	LOG_NODE(st);

	entity1 = sttype_slice_entity(st);
	ws_assert(entity1);

	if (stnode_type_id(entity1) == STTYPE_FIELD) {
		hfinfo1 = sttype_field_hfinfo(entity1);
		ftype1 = hfinfo1->type;

		if (!ftype_can_slice(ftype1)) {
			FAIL(dfw, entity1, "\"%s\" is a %s and cannot be sliced into a sequence of bytes.",
					hfinfo1->abbrev, ftype_pretty_name(ftype1));
		}
	} else if (stnode_type_id(entity1) == STTYPE_FUNCTION) {
		ftype1 = check_function(dfw, entity1, lhs_ftype);

		if (!ftype_can_slice(ftype1)) {
			FAIL(dfw, entity1, "Return value of function \"%s\" is a %s and cannot be converted into a sequence of bytes.",
					sttype_function_name(entity1), ftype_pretty_name(ftype1));
		}
	} else if (stnode_type_id(entity1) == STTYPE_SLICE) {
		/* Should this be rejected instead? */
		check_slice_sanity(dfw, entity1, lhs_ftype);
	} else {
		FAIL(dfw, entity1, "Range is not supported for entity %s",
					stnode_todisplay(entity1));
	}
}

#define IS_FIELD_ENTITY(ft) \
	((ft) == STTYPE_FIELD || \
		(ft) == STTYPE_REFERENCE)

static void
convert_to_bytes(stnode_t *arg)
{
	stnode_t      *entity1;
	drange_node   *rn;

	entity1 = stnode_dup(arg);
	rn = drange_node_new();
	drange_node_set_start_offset(rn, 0);
	drange_node_set_to_the_end(rn);

	stnode_replace(arg, STTYPE_SLICE, NULL);
	sttype_slice_set1(arg, entity1, rn);
}

ftenum_t
check_function(dfwork_t *dfw, stnode_t *st_node, ftenum_t lhs_ftype)
{
	df_func_def_t *funcdef;
	GSList        *params;
	guint          nparams;

	LOG_NODE(st_node);

	funcdef  = sttype_function_funcdef(st_node);
	params   = sttype_function_params(st_node);
	nparams  = g_slist_length(params);

	if (nparams < funcdef->min_nargs) {
		FAIL(dfw, st_node, "Function %s needs at least %u arguments.",
			funcdef->name, funcdef->min_nargs);
	} else if (funcdef->max_nargs > 0 && nparams > funcdef->max_nargs) {
		FAIL(dfw, st_node, "Function %s can only accept %u arguments.",
			funcdef->name, funcdef->max_nargs);
	}

	return funcdef->semcheck_param_function(dfw, funcdef->name, lhs_ftype, params,
					stnode_location(st_node));
}

WS_RETNONNULL
fvalue_t *
dfilter_fvalue_from_charconst(dfwork_t *dfw, ftenum_t ftype, stnode_t *st)
{
	fvalue_t *fvalue;
	unsigned long *nump = stnode_data(st);

	fvalue = fvalue_from_charconst(ftype, *nump,
			dfw->error_message == NULL ? &dfw->error_message : NULL);

	if (fvalue == NULL) {
		dfw_set_error_location(dfw, stnode_location(st));
		THROW(TypeError);
	}

	return fvalue;
}

/* If the LHS of a relation test is a FIELD, run some checks
 * and possibly some modifications of syntax tree nodes. */
static void
check_relation_LHS_FIELD(dfwork_t *dfw, stnode_op_t st_op,
		FtypeCanFunc can_func, gboolean allow_partial_value,
		stnode_t *st_node,
		stnode_t *st_arg1, stnode_t *st_arg2)
{
	sttype_id_t		type2;
	header_field_info	*hfinfo1;
	ftenum_t		ftype1, ftype2;
	fvalue_t		*fvalue;

	LOG_NODE(st_node);

	type2 = stnode_type_id(st_arg2);

	ws_assert(stnode_type_id(st_arg1) == STTYPE_FIELD ||
			stnode_type_id(st_arg1) == STTYPE_REFERENCE);
	hfinfo1 = sttype_field_hfinfo(st_arg1);
	ftype1 = hfinfo1->type;

	if (!can_func(ftype1)) {
		FAIL(dfw, st_arg1, "%s (type=%s) cannot participate in %s comparison.",
				hfinfo1->abbrev, ftype_pretty_name(ftype1),
				stnode_todisplay(st_node));
	}

	if (IS_FIELD_ENTITY(type2)) {
		ftype2 = sttype_field_ftenum(st_arg2);

		if (!compatible_ftypes(ftype1, ftype2)) {
			FAIL(dfw, st_arg2, "%s and %s are not of compatible types.",
					hfinfo1->abbrev, stnode_todisplay(st_arg2));
		}
		/* Do this check even though you'd think that if
		 * they're compatible, then can_func() would pass. */
		if (!can_func(ftype2)) {
			FAIL(dfw, st_arg2, "%s (type=%s) cannot participate in specified comparison.",
					stnode_todisplay(st_arg2), ftype_pretty_name(ftype2));
		}
	}
	else if (type2 == STTYPE_STRING || type2 == STTYPE_LITERAL) {
		/* Skip incompatible fields */
		while (hfinfo1->same_name_prev_id != -1 &&
				((type2 == STTYPE_STRING && ftype1 != FT_STRING && ftype1!= FT_STRINGZ) ||
				(type2 != STTYPE_STRING && (ftype1 == FT_STRING || ftype1== FT_STRINGZ)))) {
			hfinfo1 = proto_registrar_get_nth(hfinfo1->same_name_prev_id);
			ftype1 = hfinfo1->type;
		}

		if (type2 == STTYPE_STRING) {
			fvalue = dfilter_fvalue_from_string(dfw, ftype1, st_arg2, hfinfo1);
		}
		else {
			fvalue = dfilter_fvalue_from_literal(dfw, ftype1, st_arg2, allow_partial_value, hfinfo1);
		}
		stnode_replace(st_arg2, STTYPE_FVALUE, fvalue);
	}
	else if (type2 == STTYPE_CHARCONST) {
		fvalue = dfilter_fvalue_from_charconst(dfw, ftype1, st_arg2);
		stnode_replace(st_arg2, STTYPE_FVALUE, fvalue);
	}
	else if (type2 == STTYPE_SLICE) {
		check_slice_sanity(dfw, st_arg2, ftype1);
		if (!is_bytes_type(ftype1)) {
			if (!ftype_can_slice(ftype1)) {
				FAIL(dfw, st_arg1, "\"%s\" is a %s and cannot be converted into a sequence of bytes.",
						hfinfo1->abbrev,
						ftype_pretty_name(ftype1));
			}

			/* Convert entire field to bytes */
			convert_to_bytes(st_arg1);
		}
	}
	else if (type2 == STTYPE_FUNCTION) {
		ftype2 = check_function(dfw, st_arg2, ftype1);

		if (!compatible_ftypes(ftype1, ftype2)) {
			FAIL(dfw, st_arg2, "%s (type=%s) and return value of %s() (type=%s) are not of compatible types.",
					hfinfo1->abbrev, ftype_pretty_name(ftype1),
					sttype_function_name(st_arg2), ftype_pretty_name(ftype2));
		}

		if (!can_func(ftype2)) {
			FAIL(dfw, st_arg2, "return value of %s() (type=%s) cannot participate in specified comparison.",
					sttype_function_name(st_arg2), ftype_pretty_name(ftype2));
		}
	}
	else if (type2 == STTYPE_PCRE) {
		ws_assert(st_op == STNODE_OP_MATCHES);
	}
	else if (type2 == STTYPE_ARITHMETIC) {
		ftype2 = check_arithmetic_expr(dfw, st_arg2, ftype1);

		if (!compatible_ftypes(ftype1, ftype2)) {
			FAIL(dfw, st_arg2, "%s and %s are not of compatible types.",
					stnode_todisplay(st_arg1), stnode_todisplay(st_arg2));
		}

		if (!can_func(ftype2)) {
			FAIL(dfw, st_arg2, "%s (type=%s) cannot participate in specified comparison.",
					stnode_todisplay(st_arg2), ftype_pretty_name(ftype2));
		}
	}
	else {
		ws_assert_not_reached();
	}
}

static void
check_relation_LHS_SLICE(dfwork_t *dfw, stnode_op_t st_op,
		FtypeCanFunc can_func _U_,
		gboolean allow_partial_value,
		stnode_t *st_node _U_,
		stnode_t *st_arg1, stnode_t *st_arg2)
{
	sttype_id_t		type2;
	ftenum_t		ftype2;
	fvalue_t		*fvalue;

	LOG_NODE(st_node);

	check_slice_sanity(dfw, st_arg1, FT_NONE);

	type2 = stnode_type_id(st_arg2);

	if (IS_FIELD_ENTITY(type2)) {
		ftype2 = sttype_field_ftenum(st_arg2);

		if (!is_bytes_type(ftype2)) {
			if (!ftype_can_slice(ftype2)) {
				FAIL(dfw, st_arg2, "\"%s\" is a %s and cannot be converted into a sequence of bytes.",
						stnode_todisplay(st_arg2),
						ftype_pretty_name(ftype2));
			}

			/* Convert entire field to bytes */
			convert_to_bytes(st_arg2);
		}
	}
	else if (type2 == STTYPE_STRING) {
		fvalue = dfilter_fvalue_from_string(dfw, FT_BYTES, st_arg2, NULL);
		stnode_replace(st_arg2, STTYPE_FVALUE, fvalue);
	}
	else if (type2 == STTYPE_LITERAL) {
		fvalue = dfilter_fvalue_from_literal(dfw, FT_BYTES, st_arg2, allow_partial_value, NULL);
		stnode_replace(st_arg2, STTYPE_FVALUE, fvalue);
	}
	else if (type2 == STTYPE_CHARCONST) {
		fvalue = dfilter_fvalue_from_charconst(dfw, FT_BYTES, st_arg2);
		stnode_replace(st_arg2, STTYPE_FVALUE, fvalue);
	}
	else if (type2 == STTYPE_SLICE) {
		check_slice_sanity(dfw, st_arg2, FT_BYTES);
	}
	else if (type2 == STTYPE_FUNCTION) {
		ftype2 = check_function(dfw, st_arg2, FT_BYTES);

		if (!is_bytes_type(ftype2)) {
			if (!ftype_can_slice(ftype2)) {
				FAIL(dfw, st_arg2, "Return value of function \"%s\" is a %s and cannot be converted into a sequence of bytes.",
					sttype_function_name(st_arg2),
					ftype_pretty_name(ftype2));
			}

			/* Convert function result to bytes */
			convert_to_bytes(st_arg2);
		}
	}
	else if (type2 == STTYPE_PCRE) {
		ws_assert(st_op == STNODE_OP_MATCHES);
	}
	else if (type2 == STTYPE_ARITHMETIC) {
		ftype2 = check_arithmetic_expr(dfw, st_arg2, FT_BYTES);

		if (!compatible_ftypes(FT_BYTES, ftype2)) {
			FAIL(dfw, st_arg2, "%s and %s are not of compatible types.",
					stnode_todisplay(st_arg1), stnode_todisplay(st_arg2));
		}

		if (!can_func(ftype2)) {
			FAIL(dfw, st_arg2, "%s (type=%s) cannot participate in specified comparison.",
					stnode_todisplay(st_arg2), ftype_pretty_name(ftype2));
		}
	}
	else {
		ws_assert_not_reached();
	}
}

/* If the LHS of a relation test is a FUNCTION, run some checks
 * and possibly some modifications of syntax tree nodes. */
static void
check_relation_LHS_FUNCTION(dfwork_t *dfw, stnode_op_t st_op,
		FtypeCanFunc can_func, gboolean allow_partial_value,
		stnode_t *st_node,
		stnode_t *st_arg1, stnode_t *st_arg2)
{
	sttype_id_t		type2;
	ftenum_t		ftype1, ftype2;
	fvalue_t		*fvalue;

	LOG_NODE(st_node);

	ftype1 = check_function(dfw, st_arg1, FT_NONE);

	if (!can_func(ftype1)) {
		FAIL(dfw, st_arg1, "Function %s (type=%s) cannot participate in %s comparison.",
				sttype_function_name(st_arg1), ftype_pretty_name(ftype1),
				stnode_todisplay(st_node));
	}

	type2 = stnode_type_id(st_arg2);

	if (IS_FIELD_ENTITY(type2)) {
		ftype2 = sttype_field_ftenum(st_arg2);

		if (!compatible_ftypes(ftype1, ftype2)) {
			FAIL(dfw, st_arg2, "Function %s and %s are not of compatible types.",
					sttype_function_name(st_arg2), stnode_todisplay(st_arg2));
		}
		/* Do this check even though you'd think that if
		 * they're compatible, then can_func() would pass. */
		if (!can_func(ftype2)) {
			FAIL(dfw, st_arg2, "%s (type=%s) cannot participate in specified comparison.",
					stnode_todisplay(st_arg2), ftype_pretty_name(ftype2));
		}
	}
	else if (type2 == STTYPE_STRING) {
		fvalue = dfilter_fvalue_from_string(dfw, ftype1, st_arg2, NULL);
		stnode_replace(st_arg2, STTYPE_FVALUE, fvalue);
	}
	else if (type2 == STTYPE_LITERAL) {
		fvalue = dfilter_fvalue_from_literal(dfw, ftype1, st_arg2, allow_partial_value, NULL);
		stnode_replace(st_arg2, STTYPE_FVALUE, fvalue);
	}
	else if (type2 == STTYPE_CHARCONST) {
		fvalue = dfilter_fvalue_from_charconst(dfw, ftype1, st_arg2);
		stnode_replace(st_arg2, STTYPE_FVALUE, fvalue);
	}
	else if (type2 == STTYPE_SLICE) {
		check_slice_sanity(dfw, st_arg2, ftype1);
		if (!is_bytes_type(ftype1)) {
			if (!ftype_can_slice(ftype1)) {
				FAIL(dfw, st_arg1, "Function \"%s\" is a %s and cannot be converted into a sequence of bytes.",
						sttype_function_name(st_arg1),
						ftype_pretty_name(ftype1));
			}

			/* Convert function result to bytes */
			convert_to_bytes(st_arg1);
		}
	}
	else if (type2 == STTYPE_FUNCTION) {
		ftype2 = check_function(dfw, st_arg2, ftype1);

		if (!compatible_ftypes(ftype1, ftype2)) {
			FAIL(dfw, st_arg2, "Return values of function %s (type=%s) and function %s (type=%s) are not of compatible types.",
				     sttype_function_name(st_arg1), ftype_pretty_name(ftype1), sttype_function_name(st_arg1), ftype_pretty_name(ftype2));
		}

		/* Do this check even though you'd think that if
		 * they're compatible, then can_func() would pass. */
		if (!can_func(ftype2)) {
			FAIL(dfw, st_arg2, "Return value of %s (type=%s) cannot participate in specified comparison.",
				     sttype_function_name(st_arg2), ftype_pretty_name(ftype2));
		}
	}
	else if (type2 == STTYPE_PCRE) {
		ws_assert(st_op == STNODE_OP_MATCHES);
	}
	else if (type2 == STTYPE_ARITHMETIC) {
		ftype2 = check_arithmetic_expr(dfw, st_arg2, ftype1);

		if (!compatible_ftypes(ftype1, ftype2)) {
			FAIL(dfw, st_arg2, "%s and %s are not of compatible types.",
					stnode_todisplay(st_arg1), stnode_todisplay(st_arg2));
		}

		if (!can_func(ftype2)) {
			FAIL(dfw, st_arg2, "%s (type=%s) cannot participate in specified comparison.",
					stnode_todisplay(st_arg2), ftype_pretty_name(ftype2));
		}
	}
	else {
		ws_assert_not_reached();
	}
}

static void
check_relation_LHS_ARITHMETIC(dfwork_t *dfw, stnode_op_t st_op _U_,
		FtypeCanFunc can_func _U_, gboolean allow_partial_value,
		stnode_t *st_node, stnode_t *st_arg1, stnode_t *st_arg2)
{
	stnode_t		*entity;
	sttype_id_t		entity_type;

	LOG_NODE(st_node);

	check_arithmetic_expr(dfw, st_arg1, FT_NONE);

	sttype_oper_get(st_arg1, NULL, &entity, NULL);
	entity_type = stnode_type_id(entity);

	if (IS_FIELD_ENTITY(entity_type)) {
		check_relation_LHS_FIELD(dfw, st_op, can_func, allow_partial_value, st_node, entity, st_arg2);
	}
	else if (entity_type == STTYPE_FUNCTION) {
		check_relation_LHS_FUNCTION(dfw, st_op, can_func, allow_partial_value, st_node, entity, st_arg2);
	}
	else if (entity_type == STTYPE_SLICE) {
		check_relation_LHS_SLICE(dfw, st_op, can_func, allow_partial_value, st_node, entity, st_arg2);
	}
	else if (entity_type == STTYPE_ARITHMETIC) {
		check_relation_LHS_ARITHMETIC(dfw, st_op, can_func, allow_partial_value, st_node, entity, st_arg2);
	}
	else {
		ws_assert_not_reached();
	}
}

/* Check the semantics of any relational test. */
static void
check_relation(dfwork_t *dfw, stnode_op_t st_op,
		FtypeCanFunc can_func, gboolean allow_partial_value,
		stnode_t *st_node, stnode_t *st_arg1, stnode_t *st_arg2)
{
	LOG_NODE(st_node);

	switch (stnode_type_id(st_arg1)) {
		case STTYPE_FIELD:
		case STTYPE_REFERENCE:
			check_relation_LHS_FIELD(dfw, st_op, can_func,
					allow_partial_value, st_node, st_arg1, st_arg2);
			break;
		case STTYPE_SLICE:
			check_relation_LHS_SLICE(dfw, st_op, can_func,
					allow_partial_value, st_node, st_arg1, st_arg2);
			break;
		case STTYPE_FUNCTION:
			check_relation_LHS_FUNCTION(dfw, st_op, can_func,
					allow_partial_value, st_node, st_arg1, st_arg2);
			break;
		case STTYPE_ARITHMETIC:
			check_relation_LHS_ARITHMETIC(dfw, st_op, can_func,
					allow_partial_value, st_node, st_arg1, st_arg2);
			break;
		default:
			FAIL(dfw, st_arg1, "Left side of \"%s\" expression must be a field or function, not %s.",
					stnode_todisplay(st_node), stnode_todisplay(st_arg1));
	}
}

static void
check_relation_contains(dfwork_t *dfw, stnode_t *st_node,
		stnode_t *st_arg1, stnode_t *st_arg2)
{
	LOG_NODE(st_node);

	switch (stnode_type_id(st_arg1)) {
		case STTYPE_FIELD:
		case STTYPE_REFERENCE:
			check_relation_LHS_FIELD(dfw, STNODE_OP_CONTAINS, ftype_can_contains,
							TRUE, st_node, st_arg1, st_arg2);
			break;
		case STTYPE_FUNCTION:
			check_relation_LHS_FUNCTION(dfw, STNODE_OP_CONTAINS, ftype_can_contains,
							TRUE, st_node, st_arg1, st_arg2);
			break;
		case STTYPE_SLICE:
			check_relation_LHS_SLICE(dfw, STNODE_OP_CONTAINS, ftype_can_contains,
							TRUE, st_node, st_arg1, st_arg2);
			break;
		default:
			FAIL(dfw, st_arg1, "Left side of %s expression must be a field or function, not %s.",
					stnode_todisplay(st_node), stnode_todisplay(st_arg1));
	}
}


static void
check_relation_matches(dfwork_t *dfw, stnode_t *st_node,
		stnode_t *st_arg1, stnode_t *st_arg2)
{
	ws_regex_t *pcre;
	char *errmsg = NULL;
	GString *patt;

	LOG_NODE(st_node);

	if (stnode_type_id(st_arg2) != STTYPE_STRING) {
		FAIL(dfw, st_arg2, "Matches requires a double quoted string on the right side.");
	}

	patt = stnode_string(st_arg2);
	ws_debug("Compile regex pattern: %s", stnode_token(st_arg2));

	pcre = ws_regex_compile_ex(patt->str, patt->len, &errmsg, WS_REGEX_CASELESS|WS_REGEX_NEVER_UTF);
	if (errmsg) {
		dfilter_fail(dfw, NULL, "Regex compilation error: %s.", errmsg);
		g_free(errmsg);
		THROW(TypeError);
	}

	stnode_replace(st_arg2, STTYPE_PCRE, pcre);

	switch (stnode_type_id(st_arg1)) {
		case STTYPE_FIELD:
		case STTYPE_REFERENCE:
			check_relation_LHS_FIELD(dfw, STNODE_OP_MATCHES, ftype_can_matches,
							TRUE, st_node, st_arg1, st_arg2);
			break;
		case STTYPE_FUNCTION:
			check_relation_LHS_FUNCTION(dfw, STNODE_OP_MATCHES, ftype_can_matches,
							TRUE, st_node, st_arg1, st_arg2);
			break;
		case STTYPE_SLICE:
			check_relation_LHS_SLICE(dfw, STNODE_OP_MATCHES, ftype_can_matches,
							TRUE, st_node, st_arg1, st_arg2);
			break;
		default:
			FAIL(dfw, st_arg1, "Left side of %s expression must be a field or function, not %s.",
					stnode_todisplay(st_node), stnode_todisplay(st_arg1));
	}
}

static void
check_relation_in(dfwork_t *dfw, stnode_t *st_node _U_,
		stnode_t *st_arg1, stnode_t *st_arg2)
{
	GSList *nodelist;
	stnode_t *node_left, *node_right;

	LOG_NODE(st_node);

	if (stnode_type_id(st_arg1) != STTYPE_FIELD) {
		FAIL(dfw, st_arg1, "Only a field may be tested for membership in a set.");
	}
	/* Checked in the grammar parser. */
	ws_assert(stnode_type_id(st_arg2) == STTYPE_SET);

	/* Attempt to interpret one element of the set at a time. Each
	 * element is represented by two items in the list, the element
	 * value and NULL. Both will be replaced by a lower and upper
	 * value if the element is a range. */
	nodelist = stnode_data(st_arg2);
	while (nodelist) {
		node_left = nodelist->data;

		/* Don't let a range on the RHS affect the LHS field. */
		if (stnode_type_id(node_left) == STTYPE_SLICE) {
			FAIL(dfw, node_left, "A slice may not appear inside a set.");
			break;
		}

		nodelist = g_slist_next(nodelist);
		ws_assert(nodelist);
		node_right = nodelist->data;
		if (node_right) {
			check_relation_LHS_FIELD(dfw, STNODE_OP_GE, ftype_can_cmp,
					FALSE, st_node, st_arg1, node_left);
			check_relation_LHS_FIELD(dfw, STNODE_OP_LE, ftype_can_cmp,
					FALSE, st_node, st_arg1, node_right);
		} else {
			check_relation_LHS_FIELD(dfw, STNODE_OP_ANY_EQ, ftype_can_eq,
					FALSE, st_node, st_arg1, node_left);
		}
		nodelist = g_slist_next(nodelist);
	}
}

/* Check the semantics of any type of TEST */
static void
check_test(dfwork_t *dfw, stnode_t *st_node)
{
	stnode_op_t		st_op;
	stnode_t		*st_arg1, *st_arg2;

	LOG_NODE(st_node);

	sttype_oper_get(st_node, &st_op, &st_arg1, &st_arg2);

	switch (st_op) {
		case STNODE_OP_UNINITIALIZED:
			ws_assert_not_reached();
			break;

		case STNODE_OP_NOT:
			semcheck(dfw, st_arg1);
			break;

		case STNODE_OP_AND:
		case STNODE_OP_OR:
			semcheck(dfw, st_arg1);
			semcheck(dfw, st_arg2);
			break;

		case STNODE_OP_ALL_EQ:
		case STNODE_OP_ANY_EQ:
		case STNODE_OP_ALL_NE:
		case STNODE_OP_ANY_NE:
			check_relation(dfw, st_op, ftype_can_eq, FALSE, st_node, st_arg1, st_arg2);
			break;
		case STNODE_OP_GT:
		case STNODE_OP_GE:
		case STNODE_OP_LT:
		case STNODE_OP_LE:
			check_relation(dfw, st_op, ftype_can_cmp, FALSE, st_node, st_arg1, st_arg2);
			break;
		case STNODE_OP_CONTAINS:
			check_relation_contains(dfw, st_node, st_arg1, st_arg2);
			break;
		case STNODE_OP_MATCHES:
			check_relation_matches(dfw, st_node, st_arg1, st_arg2);
			break;
		case STNODE_OP_IN:
			check_relation_in(dfw, st_node, st_arg1, st_arg2);
			break;

		default:
			ws_assert_not_reached();
	}
}

static ftenum_t
check_arithmetic_entity(dfwork_t *dfw, stnode_t *st_arg, ftenum_t lhs_ftype)
{
	sttype_id_t		type;
	ftenum_t		ftype;

	LOG_NODE(st_arg);

	/* lhs_ftype variable determines the type for this entity. If LHS type
	 * is none we must have been passed an entity with a definite type
	 * (field, function, etc). */

	type = stnode_type_id(st_arg);

	if (type == STTYPE_LITERAL) {
		/* numeric constant */
		ws_assert(lhs_ftype != FT_NONE);
		fvalue_t *fvalue = dfilter_fvalue_from_literal(dfw, lhs_ftype, st_arg, FALSE, NULL);
		stnode_replace(st_arg, STTYPE_FVALUE, fvalue);
		ftype = fvalue_type_ftenum(fvalue);
	}
	else if (type == STTYPE_FIELD || type == STTYPE_REFERENCE) {
		header_field_info *hfinfo = sttype_field_hfinfo(st_arg);
		ftype = hfinfo->type;
	}
	else if (type == STTYPE_FUNCTION) {
		ftype = check_function(dfw, st_arg, lhs_ftype);
	}
	else if (type == STTYPE_SLICE) {
		check_slice_sanity(dfw, st_arg, lhs_ftype);

		ftype = FT_BYTES;
	}
	else if (type == STTYPE_FVALUE) {
		ftype = fvalue_type_ftenum(stnode_data(st_arg));
	}
	else {
		FAIL(dfw, st_arg, "%s is not a valid arithmetic operand.",
				stnode_todisplay(st_arg));
	}

	return ftype;
}

ftenum_t
check_arithmetic_expr(dfwork_t *dfw, stnode_t *st_node, ftenum_t lhs_ftype)
{
	stnode_op_t		st_op;
	stnode_t		*st_arg1, *st_arg2;
	ftenum_t		ftype1, ftype2;
	FtypeCanFunc 		can_func = NULL;

	LOG_NODE(st_node);

	if (stnode_type_id(st_node) != STTYPE_ARITHMETIC) {
		return check_arithmetic_entity(dfw, st_node, lhs_ftype);
	}

	sttype_oper_get(st_node, &st_op, &st_arg1, &st_arg2);

	/* On the LHS we require a field-like value as the first term. */
	if (lhs_ftype == FT_NONE && node_is_constant(st_arg1)) {
		FAIL(dfw, st_arg1, "Constant arithmetic expression on the LHS is invalid.");
	}

	if (st_op == STNODE_OP_UNARY_MINUS) {
		ftype1 = check_arithmetic_entity(dfw, st_arg1, lhs_ftype);
		if (stnode_type_id(st_arg1) == STTYPE_FVALUE) {
			/* Pre-compute constant unary minus result */
			char *err_msg;
			fvalue_t *new_fv = fvalue_unary_minus(stnode_data(st_arg1), &err_msg);
			if (new_fv == NULL) {
				dfilter_fail(dfw, stnode_location(st_arg1),
							"%s: %s", stnode_todisplay(st_arg1), err_msg);
				g_free(err_msg);
				THROW(TypeError);
			}
			/* Replaces unary operator with result */
			stnode_replace(st_node, STTYPE_FVALUE, new_fv);
		}
		return ftype1;
	}

	ftype1 = check_arithmetic_expr(dfw, st_arg1, lhs_ftype);
	ftype2 = check_arithmetic_expr(dfw, st_arg2, ftype1);

	switch (st_op) {
		case STNODE_OP_ADD:
			can_func = ftype_can_add;
			break;
		case STNODE_OP_SUBTRACT:
			can_func = ftype_can_subtract;
			break;
		case STNODE_OP_MULTIPLY:
			can_func = ftype_can_multiply;
			break;
		case STNODE_OP_DIVIDE:
			can_func = ftype_can_divide;
			break;
		case STNODE_OP_MODULO:
			can_func = ftype_can_modulo;
			break;
		case STNODE_OP_BITWISE_AND:
			can_func = ftype_can_bitwise_and;
			break;
		default:
			ws_assert_not_reached();
	}

	if (!can_func(ftype1)) {
		FAIL(dfw, st_arg1, "%s cannot %s.",
			ftype_name(ftype1), stnode_todisplay(st_node));
	}
	if (!can_func(ftype2)) {
		FAIL(dfw, st_arg2, "%s cannot %s.",
			ftype_name(ftype2), stnode_todisplay(st_node));
	}

	if (!compatible_ftypes(ftype1, ftype2)) {
		FAIL(dfw, st_arg2, "%s and %s are not type compatible.",
			stnode_todisplay(st_arg1), stnode_todisplay(st_arg2));
	}

	return ftype1;
}


/* Check the entire syntax tree. */
static void
semcheck(dfwork_t *dfw, stnode_t *st_node)
{
	LOG_NODE(st_node);

	switch (stnode_type_id(st_node)) {
		case STTYPE_TEST:
			check_test(dfw, st_node);
			break;
		case STTYPE_ARITHMETIC:
			check_arithmetic_expr(dfw, st_node, FT_NONE);
			break;
		case STTYPE_SLICE:
			check_slice_sanity(dfw, st_node, FT_NONE);
			break;
		default:
			check_exists(dfw, st_node);
	}
}


/* Check the syntax tree for semantic errors, and convert
 * some of the nodes into the form they need to be in order to
 * later generate the DFVM bytecode. */
gboolean
dfw_semcheck(dfwork_t *dfw)
{
	volatile gboolean ok_filter = TRUE;

	ws_noisy("Starting semantic check (dfw = %p)", dfw);

	/* Instead of having to check for errors at every stage of
	 * the semantic-checking, the semantic-checking code will
	 * throw an exception if a problem is found. */
	TRY {
		semcheck(dfw, dfw->st_root);
	}
	CATCH(TypeError) {
		ok_filter = FALSE;
	}
	ENDTRY;

	ws_noisy("Semantic check (dfw = %p) returns %s",
			dfw, ok_filter ? "TRUE" : "FALSE");

	return ok_filter;
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
