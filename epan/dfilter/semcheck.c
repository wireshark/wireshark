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
#include "sttype-number.h"

#include <epan/exceptions.h>
#include <epan/packet.h>

#include <wsutil/ws_assert.h>
#include <wsutil/wslog.h>

#include <ftypes/ftypes.h>

#define FAIL(dfw, node, ...) \
	do {								\
		ws_noisy("Semantic check failed here.");		\
		dfilter_fail_throw(dfw, DF_ERROR_GENERIC, stnode_location(node), __VA_ARGS__); \
	} while (0)

#define FAIL_HERE(dfw) \
	do {								\
		ws_noisy("Semantic check failed here.");		\
		THROW(TypeError);					\
	} while (0)

#define FAIL_MSG(dfw, node, msg) \
	do {								\
		ws_noisy("Semantic check failed here.");		\
		dfilter_fail(dfw, DF_ERROR_GENERIC, stnode_location(node), \
					"%s", msg);			\
		g_free(msg);						\
		THROW(TypeError);					\
	} while (0)

#define IS_FIELD_ENTITY(ft) \
	((ft) == STTYPE_FIELD || \
		(ft) == STTYPE_REFERENCE)

typedef bool (*FtypeCanFunc)(enum ftenum);

typedef void (*ArithmeticDoFunc)(dfwork_t *dfw, stnode_t *node, stnode_t *arg1, stnode_t *arg2);

static ftenum_t
find_logical_ftype(dfwork_t *dfw, stnode_t *st_node);

static void
check_relation(dfwork_t *dfw, stnode_op_t st_op,
		FtypeCanFunc can_func, bool allow_partial_value,
		stnode_t *st_node, stnode_t *st_arg1, stnode_t *st_arg2);

static void
semcheck(dfwork_t *dfw, stnode_t *st_node);

enum mk_result {
	MK_ERROR,
	MK_OK_BOOLEAN,
	MK_OK_NUMBER,
	MK_OK_STRING,
};

static enum mk_result
mk_fvalue_from_val_string(dfwork_t *dfw, header_field_info *hfinfo, const char *s, stnode_t *st);

static inline bool
op_is_equality(stnode_op_t op)
{
	switch (op) {
		case STNODE_OP_ALL_EQ:
		case STNODE_OP_ANY_EQ:
		case STNODE_OP_ALL_NE:
		case STNODE_OP_ANY_NE:
		case STNODE_OP_IN:
		case STNODE_OP_NOT_IN:
			return true;
		default:
			return false;
	}
}

/* Compares to ftenum_t's and decides if they're
 * compatible or not (if they're the same basic type) */
bool
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
					return true;
				default:
					return false;
			}

		case FT_ETHER:
		case FT_BYTES:
		case FT_UINT_BYTES:
		case FT_GUID:
		case FT_OID:
		case FT_VINES:
		case FT_FCWWN:
		case FT_REL_OID:
		case FT_SYSTEM_ID:

			return (b == FT_ETHER || b == FT_BYTES || b == FT_UINT_BYTES || b == FT_GUID || b == FT_OID || b == FT_VINES || b == FT_FCWWN || b == FT_REL_OID || b == FT_SYSTEM_ID);

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
		case FT_AX25:
			return FT_IS_STRING(b);

		case FT_NUM_TYPES:
		case FT_SCALAR:
			ASSERT_FTYPE_NOT_REACHED(a);
	}

	ws_assert_not_reached();
	return false;
}

void
resolve_unparsed(dfwork_t *dfw, stnode_t *st, bool strict)
{
	if (stnode_type_id(st) != STTYPE_UNPARSED)
		return;

	header_field_info *hfinfo = dfilter_resolve_unparsed(stnode_data(st), dfw->deprecated);
	if (hfinfo != NULL)
		stnode_replace(st, STTYPE_FIELD, hfinfo);
	else if (strict)
		FAIL(dfw, st, "\"%s\" is not a valid protocol or protocol field.", stnode_todisplay(st));
	else
		stnode_mutate(st, STTYPE_LITERAL);
}

/* Don't set the error message if it's already set. */
#define SET_ERROR(dfw, str) \
	do {						\
		if ((str) != NULL && (dfw)->error == NULL) {	\
			(dfw)->error = df_error_new(DF_ERROR_GENERIC, str, NULL); \
		}					\
		else {					\
			g_free(str);			\
		}					\
	} while (0)

/* Transforms a syntax node into a value and sets the error message on failure. */
bool
dfilter_fvalue_from_literal(dfwork_t *dfw, ftenum_t ftype, stnode_t *st,
		bool allow_partial_value, header_field_info *hfinfo_value_string)
{
	fvalue_t *fv;
	const char *s = stnode_data(st);
	char *error_message = NULL;
	enum mk_result res;

	fv = fvalue_from_literal(ftype, s, allow_partial_value, &error_message);
	if (fv != NULL) {
		g_free(error_message); // error_message is expected to be null
		stnode_replace(st, STTYPE_FVALUE, fv);
		return false;
	}
	SET_ERROR(dfw, error_message);

	if (hfinfo_value_string) {
		/* check value_string */
		res = mk_fvalue_from_val_string(dfw, hfinfo_value_string, s, st);
		/*
		 * Ignore previous errors if this can be mapped
		 * to an item from value_string.
		 */
		if (res != MK_ERROR) {
			df_error_free(&dfw->error);
			add_compile_warning(dfw, "Interpreting the symbol \u2039%s\u203A as a %s value string. "
					"Writing value strings without double quotes is deprecated. "
					"Please use \u2039\"%s\"\u203A instead",
					stnode_token(st), ftype_pretty_name(hfinfo_value_string->type), stnode_token(st));
			return res == MK_OK_STRING;
		}
	}

	// Failure
	dfw_set_error_location(dfw, stnode_location(st));
	FAIL_HERE(dfw);
	ws_assert_not_reached();
}

/* Transforms a syntax node into a value and sets the error message on failure. */
bool
dfilter_fvalue_from_string(dfwork_t *dfw, ftenum_t ftype, stnode_t *st,
		header_field_info *hfinfo_value_string)
{
	fvalue_t *fv;
	const GString *gs = stnode_string(st);
	char *error_message = NULL;
	enum mk_result res;

	fv = fvalue_from_string(ftype, gs->str, gs->len, &error_message);
	if (fv != NULL) {
		g_free(error_message); // error_message is expected to be null
		stnode_replace(st, STTYPE_FVALUE, fv);
		return false;
	}
	SET_ERROR(dfw, error_message);

	if (hfinfo_value_string) {
		res = mk_fvalue_from_val_string(dfw, hfinfo_value_string, gs->str, st);
		/*
		 * Ignore previous errors if this can be mapped
		 * to an item from value_string.
		 */
		if (res != MK_ERROR) {
			df_error_free(&dfw->error);
			return res == MK_OK_STRING;
		}
	}

	// Failure
	dfw_set_error_location(dfw, stnode_location(st));
	FAIL_HERE(dfw);
	ws_assert_not_reached();
}

void
dfilter_fvalue_from_charconst(dfwork_t *dfw, ftenum_t ftype, stnode_t *st)
{
	fvalue_t *fv;
	unsigned long *nump = stnode_data(st);
	char *error_message = NULL;

	fv = fvalue_from_charconst(ftype, *nump, &error_message);
	if (fv != NULL) {
		g_free(error_message); // error_message is expected to be null
		stnode_replace(st, STTYPE_FVALUE, fv);
		return;
	}
	SET_ERROR(dfw, error_message);

	// Failure
	dfw_set_error_location(dfw, stnode_location(st));
	FAIL_HERE(dfw);
	ws_assert_not_reached();
}

void
dfilter_fvalue_from_number(dfwork_t *dfw, ftenum_t ftype, stnode_t *st)
{
	fvalue_t *fv = NULL;
	const char *s = stnode_token(st);
	char *error_message = NULL;
	stnumber_t num_type;

	num_type = sttype_number_get_type(st);

	if (ftype == FT_SCALAR) {
		/* If a scalar was requested then transform the number
		 * syntax node to an fvalue according to its lexical
		 * type (integer or float). */
		switch (num_type) {
			case STNUM_INTEGER:
			case STNUM_UNSIGNED:
				ftype = FT_INT64;
				break;
			case STNUM_FLOAT:
				ftype = FT_DOUBLE;
				break;
			case STNUM_NONE:
				ws_assert_not_reached();
		}
	}

	switch (num_type) {
		case STNUM_INTEGER:
			fv = fvalue_from_sinteger64(ftype, s, sttype_number_get_integer(st), &error_message);
			break;

		case STNUM_UNSIGNED:
			fv = fvalue_from_uinteger64(ftype, s, sttype_number_get_unsigned(st), &error_message);
			break;

		case STNUM_FLOAT:
			fv = fvalue_from_floating(ftype, s, sttype_number_get_float(st), &error_message);
			break;

		case STNUM_NONE:
			ws_assert_not_reached();
	}

	if (fv != NULL) {
		g_free(error_message); // error_message is expected to be null
		stnode_replace(st, STTYPE_FVALUE, fv);
		return;
	}
	SET_ERROR(dfw, error_message);

	// Failure
	dfw_set_error_location(dfw, stnode_location(st));
	FAIL_HERE(dfw);
	ws_assert_not_reached();
}

/* Creates a FT_BOOLEAN fvalue with a given value. */
static fvalue_t*
mk_boolean_fvalue(bool val)
{
	fvalue_t *fv;

	fv = fvalue_new(FT_BOOLEAN);
	fvalue_set_uinteger64(fv, val);

	return fv;
}

/* Creates a FT_STRING fvalue with a given value. */
static fvalue_t*
mk_string_fvalue(const char *str)
{
	fvalue_t *fv = fvalue_new(FT_STRING);
	fvalue_set_string(fv, str);
	return fv;
}

/* Creates a FT_UINT64 fvalue with a given value. */
static fvalue_t*
mk_uint64_fvalue(uint64_t val)
{
	fvalue_t *fv = fvalue_new(FT_UINT64);
	fvalue_set_uinteger64(fv, val);
	return fv;
}

/* Try to make an fvalue from a string using a value_string or true_false_string.
 * This works only for ftypes that are integers. Returns the created fvalue_t*
 * or NULL if impossible.
 * If the mapping number<->string is unique convert the string to a number
 * by inverting the value string function.
 * Otherwise we compile it as a string and map the field value at runtime
 * to a string for the comparison. */
static enum mk_result
mk_fvalue_from_val_string(dfwork_t *dfw, header_field_info *hfinfo, const char *s, stnode_t *st)
{
	/* Early return? */
	switch(hfinfo->type) {
		case FT_NONE:
		case FT_PROTOCOL: /* hfinfo->strings contains the protocol_t */
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
			return MK_ERROR;

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
		case FT_SCALAR:
			ASSERT_FTYPE_NOT_REACHED(hfinfo->type);
	}

	/* Do val_strings exist? */
	if (!hfinfo->strings) {
		dfilter_fail(dfw, DF_ERROR_GENERIC, stnode_location(st), "%s cannot accept strings as values.",
				hfinfo->abbrev);
		return MK_ERROR;
	}

	/* Reset the error message, since *something* interesting will happen,
	 * and the error message will be more interesting than any error message
	 * I happen to have now. */
	df_error_free(&dfw->error);

	fvalue_t *fv;
	uint64_t val = 0, val_max = 0;
	size_t count = 0;

	if (hfinfo->type == FT_BOOLEAN) {
		const true_false_string	*tf = (const true_false_string *)hfinfo->strings;

		if (g_ascii_strcasecmp(s, tf->true_string) == 0) {
			fv = mk_boolean_fvalue(true);
			stnode_replace(st, STTYPE_FVALUE, fv);
			return MK_OK_BOOLEAN;
		}
		if (g_ascii_strcasecmp(s, tf->false_string) == 0) {
			fv = mk_boolean_fvalue(false);
			stnode_replace(st, STTYPE_FVALUE, fv);
			return MK_OK_BOOLEAN;
		}
		dfilter_fail(dfw, DF_ERROR_GENERIC, stnode_location(st), "\"%s\" cannot be found among the possible values for %s.",
								s, hfinfo->abbrev);
	}
	else if (hfinfo->display & BASE_RANGE_STRING) {
		const range_string *vals = (const range_string *)hfinfo->strings;

		while (vals->strptr != NULL && count <= 1) {
			if (g_ascii_strcasecmp(s, vals->strptr) == 0) {
				val = vals->value_min;
				val_max = vals->value_max;
				count++;
			}
			vals++;
		}
		if (count > 1) {
			// More than one match, use a string.
			fv = mk_string_fvalue(s);
			stnode_replace(st, STTYPE_FVALUE, fv);
			return MK_OK_STRING;
		}
		else if (count == 1) {
			// If the range has a single value use an integer.
			// Otherwise use a string.
			if (val == val_max) {
				fv = mk_uint64_fvalue(val);
				stnode_replace(st, STTYPE_FVALUE, fv);
				return MK_OK_NUMBER;
			}
			else {
				fv = mk_string_fvalue(s);
				stnode_replace(st, STTYPE_FVALUE, fv);
				return MK_OK_STRING;
			}
		}
		else {
			dfilter_fail(dfw, DF_ERROR_GENERIC, stnode_location(st), "\"%s\" cannot be found among the possible values for %s.",
					s, hfinfo->abbrev);
		}
	}
	else if (hfinfo->display & BASE_VAL64_STRING) {
		const val64_string *vals = (const val64_string *)hfinfo->strings;
		if (hfinfo->display & BASE_EXT_STRING)
			vals = VAL64_STRING_EXT_VS_P((const val64_string_ext *) vals);

		while (vals->strptr != NULL && count <= 1) {
			if (g_ascii_strcasecmp(s, vals->strptr) == 0) {
				val = vals->value;
				count++;
			}
			vals++;
		}
		if (count > 1) {
			// More than one match, use a string.
			fv = mk_string_fvalue(s);
			stnode_replace(st, STTYPE_FVALUE, fv);
			return MK_OK_STRING;
		}
		else if (count == 1) {
			// Only one match, convert string to number.
			fv = mk_uint64_fvalue(val);
			stnode_replace(st, STTYPE_FVALUE, fv);
			return MK_OK_NUMBER;
		}
		else {
			dfilter_fail(dfw, DF_ERROR_GENERIC, stnode_location(st), "\"%s\" cannot be found among the possible values for %s.",
					s, hfinfo->abbrev);
		}
	}
	else if (hfinfo->display == BASE_CUSTOM) {
		/*  We don't have a string catalog to compare to so just assume
		 * the provided string is a valid custom representation. */
		if (FT_IS_INTEGER(hfinfo->type)) {
			fv = mk_string_fvalue(s);
			stnode_replace(st, STTYPE_FVALUE, fv);
			return MK_OK_STRING;
		}
		dfilter_fail(dfw, DF_ERROR_GENERIC, stnode_location(st), "%s must be an integer.", hfinfo->abbrev);
	}
	else {
		const value_string *vals = (const value_string *)hfinfo->strings;
		if (hfinfo->display & BASE_EXT_STRING)
			vals = VALUE_STRING_EXT_VS_P((const value_string_ext *) vals);

		while (vals->strptr != NULL && count <= 1) {
			if (g_ascii_strcasecmp(s, vals->strptr) == 0) {
				val = vals->value;
				count++;
			}
			vals++;
		}
		if (count > 1) {
			// More than one match, use a string.
			fv = mk_string_fvalue(s);
			stnode_replace(st, STTYPE_FVALUE, fv);
			return MK_OK_STRING;
		}
		else if (count == 1) {
			// Only one match, convert string to number.
			fv = mk_uint64_fvalue(val);
			stnode_replace(st, STTYPE_FVALUE, fv);
			return MK_OK_NUMBER;
		}
		else {
			dfilter_fail(dfw, DF_ERROR_GENERIC, stnode_location(st), "\"%s\" cannot be found among the possible values for %s.",
					s, hfinfo->abbrev);
		}
	}
	return MK_ERROR;
}

static bool
is_bytes_type(enum ftenum type)
{
	switch(type) {
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
			return true;

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
		case FT_AX25:
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
			return false;

		case FT_NUM_TYPES:
		case FT_SCALAR:
			ASSERT_FTYPE_NOT_REACHED(type);
	}

	ws_assert_not_reached();
	return false;
}

static ftenum_t
get_slice_ftype(dfwork_t *dfw, stnode_t *st_node)
{
	stnode_t *entity1 = sttype_slice_entity(st_node);
	ws_assert(entity1);
	resolve_unparsed(dfw, entity1, true);
	ftenum_t ftype = get_logical_ftype(dfw, entity1);
	return FT_IS_STRING(ftype) ? FT_STRING : FT_BYTES;
}

static ftenum_t
get_function_ftype(dfwork_t *dfw, stnode_t *st_node)
{
	df_func_def_t *funcdef;
	GSList        *params;
	unsigned       nparams;

	funcdef  = sttype_function_funcdef(st_node);
	params   = sttype_function_params(st_node);
	nparams  = g_slist_length(params);

	if (funcdef->return_ftype != FT_NONE)
		return funcdef->return_ftype;
	if (nparams < 1)
		return FT_NONE;

	for (GSList *l = params; l != NULL; l = l->next) {
		resolve_unparsed(dfw, l->data, false);
		ftenum_t ftype = get_logical_ftype(dfw, l->data);
		if (ftype != FT_NONE) {
			return ftype;
		}
	}
	return FT_NONE;
}

ftenum_t
get_logical_ftype(dfwork_t *dfw, stnode_t *st_node)
{
	stnode_t *st_arg1, *st_arg2;
	ftenum_t ft;

	switch(stnode_type_id(st_node)) {
		case STTYPE_FIELD:
		case STTYPE_REFERENCE:
			return sttype_field_ftenum(st_node);

		case STTYPE_UNPARSED:
			resolve_unparsed(dfw, st_node, true);
			return sttype_field_ftenum(st_node);

		case STTYPE_STRING:
		case STTYPE_LITERAL:
		case STTYPE_CHARCONST:
		case STTYPE_NUMBER:
			return FT_NONE;

		case STTYPE_FUNCTION:
			return get_function_ftype(dfw, st_node);

		case STTYPE_ARITHMETIC:
		case STTYPE_TEST:
			sttype_oper_get(st_node, NULL, &st_arg1, &st_arg2);
			if (st_arg1 && (ft = get_logical_ftype(dfw, st_arg1)) != FT_NONE)
				return ft;
			if (st_arg2 && (ft = get_logical_ftype(dfw, st_arg2)) != FT_NONE)
				return ft;
			return FT_NONE;

		case STTYPE_SLICE:
			return get_slice_ftype(dfw, st_node);

		case STTYPE_SET:
		case STTYPE_UNINITIALIZED:
		case STTYPE_NUM_TYPES:
		case STTYPE_FVALUE:
		case STTYPE_PCRE:
			ASSERT_STTYPE_NOT_REACHED(stnode_type_id(st_node));
	}

	ws_assert_not_reached();
}

static ftenum_t
find_logical_ftype(dfwork_t *dfw, stnode_t *st_node)
{
	ftenum_t ftype = get_logical_ftype(dfw, st_node);
	if (ftype == FT_NONE) {
		FAIL(dfw, st_node, "Constant expression is invalid");
	}
	return ftype;
}

/* Check the semantics of an existence test. */
static void
check_exists(dfwork_t *dfw, stnode_t *st_arg1)
{

	resolve_unparsed(dfw, st_arg1, true);

	LOG_NODE(st_arg1);

	switch (stnode_type_id(st_arg1)) {
		case STTYPE_FIELD:
			dfw->field_count++;
			/* fall-through */
		case STTYPE_REFERENCE:
			/* This is OK */
			break;
		case STTYPE_STRING:
		case STTYPE_LITERAL:
		case STTYPE_CHARCONST:
		case STTYPE_NUMBER:
			FAIL(dfw, st_arg1, "%s is neither a field nor a protocol name.",
					stnode_todisplay(st_arg1));
			break;

		case STTYPE_UNPARSED:
		case STTYPE_FUNCTION:
		case STTYPE_SET:
		case STTYPE_UNINITIALIZED:
		case STTYPE_NUM_TYPES:
		case STTYPE_TEST:
		case STTYPE_FVALUE:
		case STTYPE_PCRE:
		case STTYPE_ARITHMETIC:
		case STTYPE_SLICE:
			ASSERT_STTYPE_NOT_REACHED(stnode_type_id(st_arg1));
	}
}

ftenum_t
check_slice(dfwork_t *dfw, stnode_t *st, ftenum_t logical_ftype)
{
	stnode_t		*entity1;
	header_field_info	*hfinfo1;
	sttype_id_t		sttype1;
	ftenum_t		ftype1 = FT_NONE;

	LOG_NODE(st);

	entity1 = sttype_slice_entity(st);
	ws_assert(entity1);
	resolve_unparsed(dfw, entity1, true);
	sttype1 = stnode_type_id(entity1);

	switch (sttype1) {
		case STTYPE_FIELD:
			dfw->field_count++;
			/* fall-through */
		case STTYPE_REFERENCE:
			hfinfo1 = sttype_field_hfinfo(entity1);
			ftype1 = sttype_field_ftenum(entity1);

			if (!ftype_can_slice(ftype1)) {
				FAIL(dfw, entity1, "\"%s\" is a %s and cannot be sliced into a sequence of bytes.",
						hfinfo1->abbrev, ftype_pretty_name(ftype1));
			}
			break;

		case STTYPE_FUNCTION:
			ftype1 = check_function(dfw, entity1, logical_ftype);

			if (!ftype_can_slice(ftype1)) {
				FAIL(dfw, entity1, "Return value of function \"%s\" is a %s and cannot be converted into a sequence of bytes.",
						sttype_function_name(entity1), ftype_pretty_name(ftype1));
			}
			break;

		case STTYPE_SLICE:
			ftype1 = check_slice(dfw, entity1, logical_ftype);
			break;

		case STTYPE_LITERAL:
		case STTYPE_STRING:
		case STTYPE_CHARCONST:
		case STTYPE_NUMBER:
			FAIL(dfw, entity1, "Range is not supported for entity %s",
						stnode_todisplay(entity1));

		case STTYPE_UNPARSED:
		case STTYPE_UNINITIALIZED:
		case STTYPE_NUM_TYPES:
		case STTYPE_PCRE:
		case STTYPE_FVALUE:
		case STTYPE_TEST:
		case STTYPE_ARITHMETIC:
		case STTYPE_SET:
			ASSERT_STTYPE_NOT_REACHED(sttype1);

	}

	return FT_IS_STRING(ftype1) ? FT_STRING : FT_BYTES;
}

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
check_function(dfwork_t *dfw, stnode_t *st_node, ftenum_t logical_ftype)
{
	df_func_def_t *funcdef;
	GSList        *params;
	unsigned       nparams;

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

	return funcdef->semcheck_param_function(dfw, funcdef->name, logical_ftype, params,
					stnode_location(st_node));
}

/* If the LHS of a relation test is a FIELD, run some checks
 * and possibly some modifications of syntax tree nodes. */
static void
check_relation_LHS_FIELD(dfwork_t *dfw, stnode_op_t st_op,
		FtypeCanFunc can_func, bool allow_partial_value,
		stnode_t *st_node,
		stnode_t *st_arg1, stnode_t *st_arg2)
{
	sttype_id_t		type2;
	header_field_info	*hfinfo1;
	ftenum_t		ftype1, ftype2;
	bool			mk_val_string = false;

	LOG_NODE(st_node);

	if (stnode_type_id(st_arg1) == STTYPE_FIELD)
		dfw->field_count++;

	hfinfo1 = sttype_field_hfinfo(st_arg1);
	ftype1 = sttype_field_ftenum(st_arg1);
	if (!can_func(ftype1)) {
		/* For "matches", implicitly convert to the value string, if
		 * there is one. (FT_FRAMENUM and FT_PROTOCOL have a pointer
		 * to something other than a value string in their ->strings
		 * member, though we can't get here for a FT_PROTOCOL because
		 * it supports "matches" on its bytes without conversion.)
		 */
		if (st_op == STNODE_OP_MATCHES && hfinfo1->strings != NULL && hfinfo1->type != FT_FRAMENUM && hfinfo1->type != FT_PROTOCOL) {
			sttype_field_set_value_string(st_arg1, true);
		}
		else {
			FAIL(dfw, st_arg1, "%s (type=%s) cannot participate in %s comparison.",
					hfinfo1->abbrev, ftype_pretty_name(ftype1),
					stnode_todisplay(st_node));
		}
	}

	ftype1 = sttype_field_ftenum(st_arg1);
	type2 = stnode_type_id(st_arg2);

	if (IS_FIELD_ENTITY(type2)) {
		ftype2 = sttype_field_ftenum(st_arg2);

		if (!compatible_ftypes(ftype1, ftype2)) {
			FAIL(dfw, st_arg2, "%s and %s are not of compatible types.",
					stnode_todisplay(st_arg1), stnode_todisplay(st_arg2));
		}
		/* Do this check even though you'd think that if
		 * they're compatible, then can_func() would pass. */
		if (!can_func(ftype2)) {
			FAIL(dfw, st_arg2, "%s (type=%s) cannot participate in specified comparison.",
					stnode_todisplay(st_arg2), ftype_pretty_name(ftype2));
		}
		if (type2 == STTYPE_FIELD) {
			dfw->field_count++;
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
			mk_val_string = dfilter_fvalue_from_string(dfw, ftype1, st_arg2, hfinfo1);
		}
		else {
			mk_val_string = dfilter_fvalue_from_literal(dfw, ftype1, st_arg2, allow_partial_value, hfinfo1);
		}
		if (mk_val_string) {
			sttype_field_set_value_string(st_arg1, true);
			// Value strings can only be ordered if they are numerical.
			// Don't try to order them lexicographically, that's not
			// what users expect.
			if (!op_is_equality(st_op)) {
				FAIL(dfw, st_arg2, "Cannot use order comparisons with \"%s\" "
					"because the value string cannot be uniquely converted to an integer.",
					stnode_todisplay(st_arg2));
			}
		}
	}
	else if (type2 == STTYPE_CHARCONST) {
		dfilter_fvalue_from_charconst(dfw, ftype1, st_arg2);
	}
	else if (type2 == STTYPE_NUMBER) {
		dfilter_fvalue_from_number(dfw, ftype1, st_arg2);
	}
	else if (type2 == STTYPE_SLICE) {
		ftype2 = check_slice(dfw, st_arg2, ftype1);

		if (!compatible_ftypes(ftype1, ftype2)) {
			FAIL(dfw, st_arg2, "%s and %s are not of compatible types.",
					stnode_todisplay(st_arg1), stnode_todisplay(st_arg2));
		}
		if (!can_func(ftype2)) {
			FAIL(dfw, st_arg2, "%s (type=%s) cannot participate in specified comparison.",
					stnode_todisplay(st_arg2), ftype_pretty_name(ftype2));
		}

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
		ftype2 = check_arithmetic(dfw, st_arg2, ftype1);

		if (!compatible_ftypes(ftype1, ftype2)) {
			FAIL(dfw, st_arg2, "%s and %s are not of compatible types.",
					stnode_todisplay(st_arg1), stnode_todisplay(st_arg2));
		}

		if (!can_func(ftype2)) {
			FAIL(dfw, st_arg2, "%s (type=%s) cannot participate in specified comparison.",
					stnode_todisplay(st_arg2), ftype_pretty_name(ftype2));
		}
	}
	else if (type2 == STTYPE_UNPARSED) {
		resolve_unparsed(dfw, st_arg2, true);
		ASSERT_STTYPE_NOT_REACHED(type2);
	}
	else {
		ASSERT_STTYPE_NOT_REACHED(type2);
	}
}

static void
check_relation_LHS_FVALUE(dfwork_t *dfw, stnode_op_t st_op,
		FtypeCanFunc can_func, bool allow_partial_value,
		stnode_t *st_node,
		stnode_t *st_arg1, stnode_t *st_arg2,
		ftenum_t logical_ftype)
{
	sttype_id_t		type1, type2;
	header_field_info	*hfinfo2 = NULL;
	ftenum_t		ftype2;
	bool			mk_val_string = false;

	LOG_NODE(st_node);

	type2 = stnode_type_id(st_arg2);

	if (IS_FIELD_ENTITY(type2)) {
		hfinfo2 = sttype_field_hfinfo(st_arg2);
		ftype2 = sttype_field_ftenum(st_arg2);

		if (!can_func(ftype2)) {
			FAIL(dfw, st_arg2, "%s (type=%s) cannot participate in specified comparison.",
					stnode_todisplay(st_arg2), ftype_pretty_name(ftype2));
		}
		if (type2 == STTYPE_FIELD) {
			dfw->field_count++;
		}
	}
	else if (type2 == STTYPE_STRING ||
				type2 == STTYPE_LITERAL ||
				type2 == STTYPE_CHARCONST ||
				type2 == STTYPE_NUMBER ||
				type2 == STTYPE_PCRE) {
		FAIL(dfw, st_node, "Constant expression is invalid.");
	}
	else if (type2 == STTYPE_SLICE) {
		ftype2 = check_slice(dfw, st_arg2, logical_ftype);

		if (!can_func(ftype2)) {
			FAIL(dfw, st_arg2, "%s (type=%s) cannot participate in specified comparison.",
					stnode_todisplay(st_arg2), ftype_pretty_name(ftype2));
		}
	}
	else if (type2 == STTYPE_FUNCTION) {
		ftype2 = check_function(dfw, st_arg2, logical_ftype);

		if (!can_func(ftype2)) {
			FAIL(dfw, st_arg2, "return value of %s() (type=%s) cannot participate in specified comparison.",
					sttype_function_name(st_arg2), ftype_pretty_name(ftype2));
		}
	}
	else if (type2 == STTYPE_ARITHMETIC) {
		ftype2 = check_arithmetic(dfw, st_arg2, logical_ftype);

		if (!can_func(ftype2)) {
			FAIL(dfw, st_arg2, "%s (type=%s) cannot participate in specified comparison.",
					stnode_todisplay(st_arg2), ftype_pretty_name(ftype2));
		}
	}
	else if (type2 == STTYPE_UNPARSED) {
		resolve_unparsed(dfw, st_arg2, true);
		ASSERT_STTYPE_NOT_REACHED(type2);
	}
	else {
		ASSERT_STTYPE_NOT_REACHED(type2);
	}

	type1 = stnode_type_id(st_arg1);
	if (type1 == STTYPE_STRING) {
		mk_val_string = dfilter_fvalue_from_string(dfw, ftype2, st_arg1, hfinfo2);
	}
	else if (type1 == STTYPE_LITERAL) {
		mk_val_string = dfilter_fvalue_from_literal(dfw, ftype2, st_arg1, allow_partial_value, hfinfo2);
	}
	else if (type1 == STTYPE_CHARCONST) {
		dfilter_fvalue_from_charconst(dfw, ftype2, st_arg1);
	}
	else if (type1 == STTYPE_NUMBER) {
		dfilter_fvalue_from_number(dfw, ftype2, st_arg1);
	}
	else {
		ASSERT_STTYPE_NOT_REACHED(type1);
	}
	if (mk_val_string) {
		sttype_field_set_value_string(st_arg2, true);
		// Value strings can only be ordered if they are numerical.
		// Don't try to order them lexicographically, that's not
		// what users expect.
		if (!op_is_equality(st_op)) {
			FAIL(dfw, st_arg1, "Cannot use order comparisons with \"%s\" "
				"because the value string cannot be uniquely converted to an integer.",
				stnode_todisplay(st_arg1));
		}
	}
}

static void
check_relation_LHS_SLICE(dfwork_t *dfw, stnode_op_t st_op _U_,
		FtypeCanFunc can_func _U_,
		bool allow_partial_value,
		stnode_t *st_node _U_,
		stnode_t *st_arg1, stnode_t *st_arg2,
		ftenum_t logical_ftype)
{
	sttype_id_t		type2;
	ftenum_t		ftype1, ftype2;

	LOG_NODE(st_node);

	ftype1 = check_slice(dfw, st_arg1, logical_ftype);
	if (!can_func(ftype1)) {
		FAIL(dfw, st_arg1, "%s cannot participate in %s comparison.",
				stnode_todisplay(st_arg1), stnode_todisplay(st_node));
	}

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
		if (type2 == STTYPE_FIELD) {
			dfw->field_count++;
		}
	}
	else if (type2 == STTYPE_STRING) {
		dfilter_fvalue_from_string(dfw, ftype1, st_arg2, NULL);
	}
	else if (type2 == STTYPE_LITERAL) {
		dfilter_fvalue_from_literal(dfw, ftype1, st_arg2, allow_partial_value, NULL);
	}
	else if (type2 == STTYPE_CHARCONST) {
		dfilter_fvalue_from_charconst(dfw, ftype1, st_arg2);
	}
	else if (type2 == STTYPE_NUMBER) {
		dfilter_fvalue_from_number(dfw, ftype1, st_arg2);
	}
	else if (type2 == STTYPE_SLICE) {
		ftype2 = check_slice(dfw, st_arg2, ftype1);

		if (!compatible_ftypes(ftype1, ftype2)) {
			FAIL(dfw, st_arg2, "%s and %s are not of compatible types.",
					stnode_todisplay(st_arg1), stnode_todisplay(st_arg2));
		}
		if (!can_func(ftype2)) {
			FAIL(dfw, st_arg2, "%s (type=%s) cannot participate in specified comparison.",
					stnode_todisplay(st_arg2), ftype_pretty_name(ftype2));
		}
	}
	else if (type2 == STTYPE_FUNCTION) {
		ftype2 = check_function(dfw, st_arg2, ftype1);

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
		ftype2 = check_arithmetic(dfw, st_arg2, ftype1);

		if (!compatible_ftypes(ftype1, ftype2)) {
			FAIL(dfw, st_arg2, "%s and %s are not of compatible types.",
					stnode_todisplay(st_arg1), stnode_todisplay(st_arg2));
		}

		if (!can_func(ftype2)) {
			FAIL(dfw, st_arg2, "%s (type=%s) cannot participate in specified comparison.",
					stnode_todisplay(st_arg2), ftype_pretty_name(ftype2));
		}
	}
	else if (type2 == STTYPE_UNPARSED) {
		resolve_unparsed(dfw, st_arg2, true);
		ASSERT_STTYPE_NOT_REACHED(type2);
	}
	else {
		ASSERT_STTYPE_NOT_REACHED(type2);
	}
}

/* If the LHS of a relation test is a FUNCTION, run some checks
 * and possibly some modifications of syntax tree nodes. */
static void
check_relation_LHS_FUNCTION(dfwork_t *dfw, stnode_op_t st_op _U_,
		FtypeCanFunc can_func, bool allow_partial_value,
		stnode_t *st_node, stnode_t *st_arg1, stnode_t *st_arg2,
		ftenum_t logical_ftype)
{
	sttype_id_t		type2;
	ftenum_t		ftype1, ftype2;

	LOG_NODE(st_node);

	ftype1 = check_function(dfw, st_arg1, logical_ftype);
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
		if (type2 == STTYPE_FIELD) {
			dfw->field_count++;
		}
	}
	else if (type2 == STTYPE_STRING) {
		dfilter_fvalue_from_string(dfw, ftype1, st_arg2, NULL);
	}
	else if (type2 == STTYPE_LITERAL) {
		dfilter_fvalue_from_literal(dfw, ftype1, st_arg2, allow_partial_value, NULL);
	}
	else if (type2 == STTYPE_CHARCONST) {
		dfilter_fvalue_from_charconst(dfw, ftype1, st_arg2);
	}
	else if (type2 == STTYPE_NUMBER) {
		dfilter_fvalue_from_number(dfw, ftype1, st_arg2);
	}
	else if (type2 == STTYPE_SLICE) {
		ftype2 = check_slice(dfw, st_arg2, ftype1);

		if (!compatible_ftypes(ftype1, ftype2)) {
			FAIL(dfw, st_arg2, "%s and %s are not of compatible types.",
					stnode_todisplay(st_arg1), stnode_todisplay(st_arg2));
		}
		if (!can_func(ftype2)) {
			FAIL(dfw, st_arg2, "%s (type=%s) cannot participate in specified comparison.",
					stnode_todisplay(st_arg2), ftype_pretty_name(ftype2));
		}

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
		ftype2 = check_arithmetic(dfw, st_arg2, ftype1);

		if (!compatible_ftypes(ftype1, ftype2)) {
			FAIL(dfw, st_arg2, "%s and %s are not of compatible types.",
					stnode_todisplay(st_arg1), stnode_todisplay(st_arg2));
		}

		if (!can_func(ftype2)) {
			FAIL(dfw, st_arg2, "%s (type=%s) cannot participate in specified comparison.",
					stnode_todisplay(st_arg2), ftype_pretty_name(ftype2));
		}
	}
	else if (type2 == STTYPE_UNPARSED) {
		resolve_unparsed(dfw, st_arg2, true);
		ASSERT_STTYPE_NOT_REACHED(type2);
	}
	else {
		ASSERT_STTYPE_NOT_REACHED(type2);
	}
}

static void
check_relation_LHS_ARITHMETIC(dfwork_t *dfw, stnode_op_t st_op _U_,
		FtypeCanFunc can_func, bool allow_partial_value,
		stnode_t *st_node, stnode_t *st_arg1, stnode_t *st_arg2,
		ftenum_t logical_ftype)
{
	sttype_id_t		type2;
	ftenum_t		ftype1, ftype2;

	LOG_NODE(st_node);

	ftype1 = check_arithmetic(dfw, st_arg1, logical_ftype);
	if (!can_func(ftype1)) {
		FAIL(dfw, st_arg1, "Result with type %s cannot participate in %s comparison.",
				ftype_pretty_name(ftype1),
				stnode_todisplay(st_node));
	}

	type2 = stnode_type_id(st_arg2);

	if (IS_FIELD_ENTITY(type2)) {
		ftype2 = sttype_field_ftenum(st_arg2);

		if (!compatible_ftypes(ftype1, ftype2)) {
			FAIL(dfw, st_arg2, "%s and %s are not of compatible types.",
					stnode_todisplay(st_arg1), stnode_todisplay(st_arg2));
		}
		if (!can_func(ftype2)) {
			FAIL(dfw, st_arg2, "%s (type=%s) cannot participate in specified comparison.",
					stnode_todisplay(st_arg2), ftype_pretty_name(ftype2));
		}
		if (type2 == STTYPE_FIELD) {
			dfw->field_count++;
		}
	}
	else if (type2 == STTYPE_STRING) {
		dfilter_fvalue_from_string(dfw, ftype1, st_arg2, NULL);
	}
	else if (type2 == STTYPE_LITERAL) {
		dfilter_fvalue_from_literal(dfw, ftype1, st_arg2, allow_partial_value, NULL);
	}
	else if (type2 == STTYPE_CHARCONST) {
		dfilter_fvalue_from_charconst(dfw, ftype1, st_arg2);
	}
	else if (type2 == STTYPE_NUMBER) {
		dfilter_fvalue_from_number(dfw, ftype1, st_arg2);
	}
	else if (type2 == STTYPE_SLICE) {
		ftype2 = check_slice(dfw, st_arg2, ftype1);

		if (!compatible_ftypes(ftype1, ftype2)) {
			FAIL(dfw, st_arg2, "%s and %s are not of compatible types.",
					stnode_todisplay(st_arg1), stnode_todisplay(st_arg2));
		}
		if (!can_func(ftype2)) {
			FAIL(dfw, st_arg2, "%s (type=%s) cannot participate in specified comparison.",
					stnode_todisplay(st_arg2), ftype_pretty_name(ftype2));
		}

		if (!is_bytes_type(ftype1)) {
			if (!ftype_can_slice(ftype1)) {
				FAIL(dfw, st_arg1, "Result is a %s and cannot be converted into a sequence of bytes.",
						ftype_pretty_name(ftype1));
			}

			/* Convert expression result to bytes */
			convert_to_bytes(st_arg1);
		}
	}
	else if (type2 == STTYPE_FUNCTION) {
		ftype2 = check_function(dfw, st_arg2, ftype1);

		if (!compatible_ftypes(ftype1, ftype2)) {
			FAIL(dfw, st_arg2, "Result (type=%s) and return value of %s() (type=%s) are not of compatible types.",
					ftype_pretty_name(ftype1),
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
		ftype2 = check_arithmetic(dfw, st_arg2, ftype1);

		if (!compatible_ftypes(ftype1, ftype2)) {
			FAIL(dfw, st_arg2, "%s and %s are not of compatible types.",
					stnode_todisplay(st_arg1), stnode_todisplay(st_arg2));
		}
		if (!can_func(ftype2)) {
			FAIL(dfw, st_arg2, "%s (type=%s) cannot participate in specified comparison.",
					stnode_todisplay(st_arg2), ftype_pretty_name(ftype2));
		}
	}
	else if (type2 == STTYPE_UNPARSED) {
		resolve_unparsed(dfw, st_arg2, true);
		ASSERT_STTYPE_NOT_REACHED(type2);
	}
	else {
		ASSERT_STTYPE_NOT_REACHED(type2);
	}
}

/* Check the semantics of any relational test. */
static void
check_relation(dfwork_t *dfw, stnode_op_t st_op,
		FtypeCanFunc can_func, bool allow_partial_value,
		stnode_t *st_node, stnode_t *st_arg1, stnode_t *st_arg2)
{
	resolve_unparsed(dfw, st_arg1, true);
	resolve_unparsed(dfw, st_arg2, false);

	LOG_NODE(st_node);

	switch (stnode_type_id(st_arg1)) {
		case STTYPE_FIELD:
		case STTYPE_REFERENCE:
		case STTYPE_UNPARSED:
			check_relation_LHS_FIELD(dfw, st_op, can_func,
					allow_partial_value, st_node, st_arg1, st_arg2);
			break;
		case STTYPE_SLICE:
			check_relation_LHS_SLICE(dfw, st_op, can_func,
					allow_partial_value, st_node, st_arg1, st_arg2, find_logical_ftype(dfw, st_node));
			break;
		case STTYPE_FUNCTION:
			check_relation_LHS_FUNCTION(dfw, st_op, can_func,
					allow_partial_value, st_node, st_arg1, st_arg2, find_logical_ftype(dfw, st_node));
			break;
		case STTYPE_ARITHMETIC:
			check_relation_LHS_ARITHMETIC(dfw, st_op, can_func,
					allow_partial_value, st_node, st_arg1, st_arg2, find_logical_ftype(dfw, st_node));
			break;
		case STTYPE_LITERAL:
		case STTYPE_STRING:
		case STTYPE_CHARCONST:
		case STTYPE_NUMBER:
			check_relation_LHS_FVALUE(dfw, st_op, can_func,
					allow_partial_value, st_node, st_arg1, st_arg2, find_logical_ftype(dfw, st_node));
			break;
		case STTYPE_UNINITIALIZED:
		case STTYPE_PCRE:
		case STTYPE_FVALUE:
		case STTYPE_TEST:
		case STTYPE_SET:
		case STTYPE_NUM_TYPES:
			ASSERT_STTYPE_NOT_REACHED(stnode_type_id(st_arg1));
	}
}

static void
check_warning_contains_RHS_FIELD(dfwork_t *dfw, stnode_t *st_node _U_,
		stnode_t *st_arg1 _U_, stnode_t *st_arg2)
{
	const char *token = stnode_token(st_arg2);
	header_field_info *hfinfo = sttype_field_hfinfo(st_arg2);
	fvalue_t *fvalue = fvalue_from_literal(FT_BYTES, token, true, NULL);
	if (fvalue != NULL) {
		char *repr = fvalue_to_string_repr(dfw->dfw_scope, fvalue, FTREPR_DFILTER, 0);
		add_compile_warning(dfw, "Interpreting \"%s\" as %s instead of %s. "
					"Consider writing \"%s\" or \".%s\" to remove this warning",
					token, hfinfo->name, ftype_pretty_name(FT_BYTES),
					repr, hfinfo->abbrev);
		fvalue_free(fvalue);
	}
}

static void
check_relation_contains(dfwork_t *dfw, stnode_t *st_node,
		stnode_t *st_arg1, stnode_t *st_arg2)
{
	resolve_unparsed(dfw, st_arg1, true);
	resolve_unparsed(dfw, st_arg2, false);

	LOG_NODE(st_node);

	if (stnode_type_id(st_arg2) == STTYPE_FIELD && stnode_get_flags(st_arg2, STFLAG_UNPARSED)) {
		check_warning_contains_RHS_FIELD(dfw, st_node, st_arg1, st_arg2);
	}

	switch (stnode_type_id(st_arg1)) {
		case STTYPE_FIELD:
		case STTYPE_REFERENCE:
		case STTYPE_UNPARSED:
			check_relation_LHS_FIELD(dfw, STNODE_OP_CONTAINS, ftype_can_contains,
							true, st_node, st_arg1, st_arg2);
			break;
		case STTYPE_FUNCTION:
			check_relation_LHS_FUNCTION(dfw, STNODE_OP_CONTAINS, ftype_can_contains,
							true, st_node, st_arg1, st_arg2, find_logical_ftype(dfw, st_node));
			break;
		case STTYPE_SLICE:
			check_relation_LHS_SLICE(dfw, STNODE_OP_CONTAINS, ftype_can_contains,
							true, st_node, st_arg1, st_arg2, find_logical_ftype(dfw, st_node));
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

	resolve_unparsed(dfw, st_arg1, true);

	LOG_NODE(st_node);

	if (stnode_type_id(st_arg2) != STTYPE_STRING) {
		FAIL(dfw, st_arg2, "Matches requires a double quoted string on the right side.");
	}

	patt = stnode_string(st_arg2);
	ws_debug("Compile regex pattern: %s", stnode_token(st_arg2));

	pcre = ws_regex_compile_ex(patt->str, patt->len, &errmsg, WS_REGEX_CASELESS|WS_REGEX_NEVER_UTF);
	if (errmsg) {
		dfilter_fail(dfw, DF_ERROR_GENERIC, stnode_location(st_arg2), "Regex compilation error: %s.", errmsg);
		g_free(errmsg);
		ws_noisy("Semantic check failed here with a regex syntax error");
		THROW(TypeError);
	}

	stnode_replace(st_arg2, STTYPE_PCRE, pcre);

	switch (stnode_type_id(st_arg1)) {
		case STTYPE_FIELD:
		case STTYPE_REFERENCE:
			check_relation_LHS_FIELD(dfw, STNODE_OP_MATCHES, ftype_can_matches,
							true, st_node, st_arg1, st_arg2);
			break;
		case STTYPE_FUNCTION:
			check_relation_LHS_FUNCTION(dfw, STNODE_OP_MATCHES, ftype_can_matches,
							true, st_node, st_arg1, st_arg2, find_logical_ftype(dfw, st_arg1));
			break;
		case STTYPE_SLICE:
			check_relation_LHS_SLICE(dfw, STNODE_OP_MATCHES, ftype_can_matches,
							true, st_node, st_arg1, st_arg2, find_logical_ftype(dfw, st_arg1));
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

	resolve_unparsed(dfw, st_arg1, true);
	resolve_unparsed(dfw, st_arg2, false);

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
					false, st_node, st_arg1, node_left);
			check_relation_LHS_FIELD(dfw, STNODE_OP_LE, ftype_can_cmp,
					false, st_node, st_arg1, node_right);
		} else {
			check_relation_LHS_FIELD(dfw, STNODE_OP_ANY_EQ, ftype_can_eq,
					false, st_node, st_arg1, node_left);
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
			check_relation(dfw, st_op, ftype_can_eq, false, st_node, st_arg1, st_arg2);
			break;
		case STNODE_OP_GT:
		case STNODE_OP_GE:
		case STNODE_OP_LT:
		case STNODE_OP_LE:
			check_relation(dfw, st_op, ftype_can_cmp, false, st_node, st_arg1, st_arg2);
			break;
		case STNODE_OP_CONTAINS:
			check_relation_contains(dfw, st_node, st_arg1, st_arg2);
			break;
		case STNODE_OP_MATCHES:
			check_relation_matches(dfw, st_node, st_arg1, st_arg2);
			break;
		case STNODE_OP_IN:
		case STNODE_OP_NOT_IN:
			check_relation_in(dfw, st_node, st_arg1, st_arg2);
			break;

		case STNODE_OP_UNINITIALIZED:
		case STNODE_OP_UNARY_MINUS:
		case STNODE_OP_BITWISE_AND:
		case STNODE_OP_ADD:
		case STNODE_OP_SUBTRACT:
		case STNODE_OP_MULTIPLY:
		case STNODE_OP_DIVIDE:
		case STNODE_OP_MODULO:
			ASSERT_STNODE_OP_NOT_REACHED(st_op);
	}
}

static void
check_nonzero(dfwork_t *dfw, stnode_t *st_node)
{
	ftenum_t ftype;

	LOG_NODE(st_node);

	switch (stnode_type_id(st_node)) {
		case STTYPE_ARITHMETIC:
			ftype = check_arithmetic(dfw, st_node, find_logical_ftype(dfw, st_node));
			break;
		case STTYPE_SLICE:
			ftype = check_slice(dfw, st_node, find_logical_ftype(dfw, st_node));
			break;
		case STTYPE_FUNCTION:
			ftype = check_function(dfw, st_node, find_logical_ftype(dfw, st_node));
			break;
		default:
			ASSERT_STTYPE_NOT_REACHED(stnode_type_id(st_node));
	}

	if (!ftype_can_is_zero(ftype)) {
		FAIL(dfw, st_node, "Type %s cannot be assigned a truth value.",
					ftype_pretty_name(ftype));
	}
}

static const char *
op_to_error_msg(stnode_op_t st_op)
{
	switch (st_op) {
		case STNODE_OP_UNARY_MINUS:
			return "cannot be negated";
		case STNODE_OP_ADD:
			return "cannot be added";
		case STNODE_OP_SUBTRACT:
			return "cannot be subtracted";
		case STNODE_OP_MULTIPLY:
			return "cannot be multiplied";
		case STNODE_OP_DIVIDE:
			return "cannot be divided";
		case STNODE_OP_MODULO:
			return "does not support modulo operation";
		case STNODE_OP_BITWISE_AND:
			return "does not support bitwise AND";
		default:
			return "cannot FIXME";
	}
}

static void
do_unary_minus(dfwork_t *dfw, stnode_t *st_node, stnode_t *st_arg1)
{
	char *err_msg;
	fvalue_t *new_fv = fvalue_unary_minus(stnode_data(st_arg1), &err_msg);
	if (new_fv == NULL)
		FAIL_MSG(dfw, st_node, err_msg);
	stnode_replace(st_node, STTYPE_FVALUE, new_fv);
}

static void
do_addition(dfwork_t *dfw, stnode_t *st_node, stnode_t *st_arg1, stnode_t *st_arg2)
{
	char *err_msg;
	fvalue_t *new_fv = fvalue_add(stnode_data(st_arg1), stnode_data(st_arg2), &err_msg);
	if (new_fv == NULL)
		FAIL_MSG(dfw, st_node, err_msg);
	stnode_replace(st_node, STTYPE_FVALUE, new_fv);
}

static void
do_subtraction(dfwork_t *dfw, stnode_t *st_node, stnode_t *st_arg1, stnode_t *st_arg2)
{
	char *err_msg;
	fvalue_t *new_fv = fvalue_subtract(stnode_data(st_arg1), stnode_data(st_arg2), &err_msg);
	if (new_fv == NULL)
		FAIL_MSG(dfw, st_node, err_msg);
	stnode_replace(st_node, STTYPE_FVALUE, new_fv);
}

static void
do_multiplication(dfwork_t *dfw, stnode_t *st_node, stnode_t *st_arg1, stnode_t *st_arg2)
{
	char *err_msg;
	fvalue_t *new_fv = fvalue_multiply(stnode_data(st_arg1), stnode_data(st_arg2), &err_msg);
	if (new_fv == NULL)
		FAIL_MSG(dfw, st_node, err_msg);
	stnode_replace(st_node, STTYPE_FVALUE, new_fv);
}

static void
do_division(dfwork_t *dfw, stnode_t *st_node, stnode_t *st_arg1, stnode_t *st_arg2)
{
	if (fvalue_is_zero(stnode_data(st_arg2)))
		FAIL(dfw, st_node, "Division by zero");

	char *err_msg;
	fvalue_t *new_fv = fvalue_divide(stnode_data(st_arg1), stnode_data(st_arg2), &err_msg);
	if (new_fv == NULL)
		FAIL_MSG(dfw, st_node, err_msg);
	stnode_replace(st_node, STTYPE_FVALUE, new_fv);
}

static void
do_modulo(dfwork_t *dfw, stnode_t *st_node, stnode_t *st_arg1, stnode_t *st_arg2)
{
	if (fvalue_is_zero(stnode_data(st_arg2)))
		FAIL(dfw, st_node, "Division by zero");

	char *err_msg;
	fvalue_t *new_fv = fvalue_modulo(stnode_data(st_arg1), stnode_data(st_arg2), &err_msg);
	if (new_fv == NULL)
		FAIL_MSG(dfw, st_node, err_msg);
	stnode_replace(st_node, STTYPE_FVALUE, new_fv);
}

static void
do_bitwise_and(dfwork_t *dfw, stnode_t *st_node, stnode_t *st_arg1, stnode_t *st_arg2)
{
	char *err_msg;
	fvalue_t *new_fv = fvalue_bitwise_and(stnode_data(st_arg1), stnode_data(st_arg2), &err_msg);
	if (new_fv == NULL)
		FAIL_MSG(dfw, st_node, err_msg);
	stnode_replace(st_node, STTYPE_FVALUE, new_fv);
}

static ftenum_t
check_arithmetic_LHS_NUMBER(dfwork_t *dfw, stnode_op_t st_op,
			stnode_t *st_node, stnode_t *st_arg1, stnode_t *st_arg2,
			ftenum_t logical_ftype)
{
	ftenum_t		ftype1, ftype2;
	FtypeCanFunc 		can_func = NULL;
	ArithmeticDoFunc	do_func = NULL;

	LOG_NODE(st_node);

	if (st_op == STNODE_OP_UNARY_MINUS) {
		ftype1 = check_arithmetic(dfw, st_arg1, logical_ftype);
		if (!ftype_can_unary_minus(ftype1)) {
			FAIL(dfw, st_arg1, "%s %s.",
				ftype_name(ftype1), op_to_error_msg(st_op));
		}
		if (dfw->flags & DF_OPTIMIZE && stnode_type_id(st_arg1) == STTYPE_FVALUE) {
			/* Pre-compute constant result */
			do_unary_minus(dfw, st_node, st_arg1);
		}
		return ftype1;
	}

	switch (st_op) {
		case STNODE_OP_ADD:
			can_func = ftype_can_add;
			do_func = do_addition;
			break;
		case STNODE_OP_SUBTRACT:
			can_func = ftype_can_subtract;
			do_func = do_subtraction;
			break;
		case STNODE_OP_MULTIPLY:
			can_func = ftype_can_multiply;
			do_func = do_multiplication;
			break;
		case STNODE_OP_DIVIDE:
			can_func = ftype_can_divide;
			do_func = do_division;
			break;
		case STNODE_OP_MODULO:
			can_func = ftype_can_modulo;
			do_func = do_modulo;
			break;
		case STNODE_OP_BITWISE_AND:
			can_func = ftype_can_bitwise_and;
			do_func = do_bitwise_and;
			break;
		default:
			ASSERT_STNODE_OP_NOT_REACHED(st_op);
	}

	ftype1 = check_arithmetic(dfw, st_arg1, logical_ftype);
	if (!can_func(ftype1)) {
		FAIL(dfw, st_arg1, "%s %s.",
			ftype_name(ftype1), op_to_error_msg(st_op));
	}

	ftype2 = check_arithmetic(dfw, st_arg2, ftype1);
	if (!can_func(ftype2)) {
		FAIL(dfw, st_arg2, "%s %s.",
			ftype_name(ftype2), op_to_error_msg(st_op));
	}

	if (!compatible_ftypes(ftype1, ftype2)) {
		FAIL(dfw, st_node, "%s and %s are not compatible.",
			ftype_name(ftype1), ftype_name(ftype2));
	}

	if (dfw->flags & DF_OPTIMIZE &&
				stnode_type_id(st_arg1) == STTYPE_FVALUE &&
				stnode_type_id(st_arg2) == STTYPE_FVALUE) {
		/* Pre-compute constant result */
		do_func(dfw, st_node, st_arg1, st_arg2);
	}

	return ftype1;
}

/*
 * Time arithmetic with scalar multiplication/division only.
 * An extra limitation is that multiplicative scalars must appear on the
 * RHS currently.
 */
static ftenum_t
check_arithmetic_LHS_TIME(dfwork_t *dfw, stnode_op_t st_op, stnode_t *st_node,
			stnode_t *st_arg1, stnode_t *st_arg2,
			ftenum_t logical_ftype)
{
	ftenum_t		ftype1, ftype2;
	ArithmeticDoFunc	do_func = NULL;

	sttype_oper_get(st_node, &st_op, &st_arg1, &st_arg2);

	LOG_NODE(st_node);

	if (st_op == STNODE_OP_UNARY_MINUS) {
		ftype1 = check_arithmetic(dfw, st_arg1, logical_ftype);
		if (dfw->flags & DF_OPTIMIZE && stnode_type_id(st_arg1) == STTYPE_FVALUE) {
			do_unary_minus(dfw, st_node, st_arg1);
		}
		return ftype1;
	}

	switch (st_op) {
		case STNODE_OP_ADD:
		case STNODE_OP_SUBTRACT:
			ftype1 = check_arithmetic(dfw, st_arg1, logical_ftype);
			if (!FT_IS_TIME(ftype1)) {
				FAIL(dfw, st_node, "Left hand side must be a time type, not %s.", ftype_pretty_name(ftype1));
			}
			ftype2 = check_arithmetic(dfw, st_arg2, logical_ftype);
			if (!FT_IS_TIME(ftype2)) {
				FAIL(dfw, st_node, "Right hand side must be a time type, not %s.", ftype_pretty_name(ftype2));
			}
			break;
		case STNODE_OP_MULTIPLY:
		case STNODE_OP_DIVIDE:
			ftype1 = check_arithmetic(dfw, st_arg1, logical_ftype);
			if (!FT_IS_TIME(ftype1)) {
				FAIL(dfw, st_node, "Left hand side must be a time type, not %s.", ftype_pretty_name(ftype1));
			}
			ftype2 = check_arithmetic(dfw, st_arg2, FT_SCALAR);
			if (!FT_IS_SCALAR(ftype2)) {
				FAIL(dfw, st_node, "Right hand side must be an integer ou float type, not %s.", ftype_pretty_name(ftype2));
			}
			break;
		default:
			FAIL(dfw, st_node, "\"%s\" is not a valid arithmetic operator for %s",
					stnode_todisplay(st_node), ftype_pretty_name(logical_ftype));
	}

	if (dfw->flags & DF_OPTIMIZE &&
				stnode_type_id(st_arg1) == STTYPE_FVALUE &&
				stnode_type_id(st_arg2) == STTYPE_FVALUE) {
		/* Pre-compute constant result */
		switch (st_op) {
			case STNODE_OP_ADD:
				do_func = do_addition;
				break;
			case STNODE_OP_SUBTRACT:
				do_func = do_subtraction;
				break;
			case STNODE_OP_MULTIPLY:
				do_func = do_multiplication;
				break;
			case STNODE_OP_DIVIDE:
				do_func = do_division;
				break;
			default:
				ASSERT_STNODE_OP_NOT_REACHED(st_op);
		}
		do_func(dfw, st_node, st_arg1, st_arg2);
	}

	return ftype1;
}

ftenum_t
check_arithmetic(dfwork_t *dfw, stnode_t *st_node, ftenum_t logical_ftype)
{
	sttype_id_t		type;
	stnode_op_t		st_op;
	stnode_t		*st_arg1, *st_arg2;
	ftenum_t		ftype = FT_NONE;

	LOG_NODE(st_node);

	resolve_unparsed(dfw, st_node, true);

	type = stnode_type_id(st_node);

	switch (type) {
		case STTYPE_LITERAL:
			dfilter_fvalue_from_literal(dfw, logical_ftype, st_node, false, NULL);
			ftype = sttype_pointer_ftenum(st_node);
			break;

		case STTYPE_STRING:
			dfilter_fvalue_from_string(dfw, logical_ftype, st_node, NULL);
			ftype = sttype_pointer_ftenum(st_node);
			break;

		case STTYPE_CHARCONST:
			dfilter_fvalue_from_charconst(dfw, logical_ftype, st_node);
			ftype = sttype_pointer_ftenum(st_node);
			break;

		case STTYPE_NUMBER:
			dfilter_fvalue_from_number(dfw, logical_ftype, st_node);
			ftype = sttype_pointer_ftenum(st_node);
			break;

		case STTYPE_FIELD:
			dfw->field_count++;
			/* fall-through */
		case STTYPE_REFERENCE:
			ftype = sttype_field_ftenum(st_node);
			break;

		case STTYPE_FUNCTION:
			ftype = check_function(dfw, st_node, logical_ftype);
			break;

		case STTYPE_SLICE:
			ftype = check_slice(dfw, st_node, logical_ftype);
			break;

		case STTYPE_FVALUE:
			ftype = sttype_pointer_ftenum(st_node);
			break;

		case STTYPE_ARITHMETIC:
			sttype_oper_get(st_node, &st_op, &st_arg1, &st_arg2);
			if (FT_IS_TIME(logical_ftype))
				ftype = check_arithmetic_LHS_TIME(dfw, st_op, st_node, st_arg1, st_arg2, logical_ftype);
			else
				ftype = check_arithmetic_LHS_NUMBER(dfw, st_op, st_node, st_arg1, st_arg2, logical_ftype);
			break;

		case STTYPE_SET:
		case STTYPE_PCRE:
		case STTYPE_UNPARSED:
		case STTYPE_UNINITIALIZED:
		case STTYPE_NUM_TYPES:
		case STTYPE_TEST:
			ASSERT_STTYPE_NOT_REACHED(type);
	}

	return ftype;
}


/* Check the entire syntax tree. */
static void
semcheck(dfwork_t *dfw, stnode_t *st_node)
{
	LOG_NODE(st_node);

	dfw->field_count = 0;

	switch (stnode_type_id(st_node)) {
		case STTYPE_TEST:
			check_test(dfw, st_node);
			break;
		case STTYPE_ARITHMETIC:
		case STTYPE_SLICE:
		case STTYPE_FUNCTION:
			check_nonzero(dfw, st_node);
			break;
		default:
			check_exists(dfw, st_node);
	}

	if (dfw->field_count == 0) {
		FAIL(dfw, st_node, "Constant expression is invalid.");
	}
}


/* Check the syntax tree for semantic errors, and convert
 * some of the nodes into the form they need to be in order to
 * later generate the DFVM bytecode. */
bool
dfw_semcheck(dfwork_t *dfw)
{
	volatile bool ok_filter = true;

	ws_debug("Starting semantic check (dfw = %p)", dfw);

	/* Instead of having to check for errors at every stage of
	 * the semantic-checking, the semantic-checking code will
	 * throw an exception if a problem is found. */
	TRY {
		semcheck(dfw, dfw->st_root);
	}
	CATCH(TypeError) {
		ok_filter = false;
	}
	ENDTRY;

	ws_debug("Semantic check (dfw = %p) returns %s",
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
