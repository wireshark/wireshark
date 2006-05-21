/*
 * $Id$
 *
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include "dfilter-int.h"
#include "semcheck.h"
#include "syntax-tree.h"
#include "sttype-range.h"
#include "sttype-test.h"
#include "sttype-function.h"

#include <epan/exceptions.h>
#include <epan/packet.h>

/* Enable debug logging by defining AM_CFLAGS
 * so that it contains "-DDEBUG_dfilter".
 * Usage: DebugLog(("Error: string=%s\n", str)); */
#ifdef DEBUG_dfilter
#define DebugLog(x) \
	printf("%s:%u: ", __FILE__, __LINE__); \
	printf x; \
	fflush(stdout)
#else
#define DebugLog(x) ;
#endif

static void
semcheck(stnode_t *st_node);

typedef gboolean (*FtypeCanFunc)(enum ftenum);

/* Compares to ftenum_t's and decides if they're
 * compatible or not (if they're the same basic type) */
static gboolean
compatible_ftypes(ftenum_t a, ftenum_t b)
{
	switch (a) {
		case FT_NONE:
		case FT_PROTOCOL:
		case FT_FLOAT:		/* XXX - should be able to compare with INT */
		case FT_DOUBLE:		/* XXX - should be able to compare with INT */
		case FT_ABSOLUTE_TIME:
		case FT_RELATIVE_TIME:
		case FT_IPv4:
		case FT_IPv6:
		case FT_IPXNET:
		case FT_INT64:		/* XXX - should be able to compare with INT */
		case FT_UINT64:		/* XXX - should be able to compare with INT */
			return a == b;

		case FT_ETHER:
		case FT_BYTES:
		case FT_UINT_BYTES:
		case FT_GUID:
		case FT_OID:
			return (b == FT_ETHER || b == FT_BYTES || b == FT_UINT_BYTES || b == FT_GUID || b == FT_OID);

		case FT_BOOLEAN:
		case FT_FRAMENUM:
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
			switch (b) {
				case FT_BOOLEAN:
				case FT_FRAMENUM:
				case FT_UINT8:
				case FT_UINT16:
				case FT_UINT24:
				case FT_UINT32:
				case FT_INT8:
				case FT_INT16:
				case FT_INT24:
				case FT_INT32:
					return TRUE;
				default:
					return FALSE;
			}

		case FT_STRING:
		case FT_STRINGZ:
		case FT_UINT_STRING:
			switch (b) {
				case FT_STRING:
				case FT_STRINGZ:
				case FT_UINT_STRING:
					return TRUE;
				default:
					return FALSE;
			}

		case FT_PCRE:
		case FT_NUM_TYPES:
			g_assert_not_reached();
	}

	g_assert_not_reached();
	return FALSE;
}

/* Creates a FT_UINT32 fvalue with a given value. */
static fvalue_t*
mk_uint32_fvalue(guint32 val)
{
	fvalue_t *fv;

	fv = fvalue_new(FT_UINT32);
	fvalue_set_integer(fv, val);

	return fv;
}

/* Try to make an fvalue from a string using a value_string or true_false_string.
 * This works only for ftypes that are integers. Returns the created fvalue_t*
 * or NULL if impossible. */
static fvalue_t*
mk_fvalue_from_val_string(header_field_info *hfinfo, char *s)
{
	static const true_false_string  default_tf = { "True", "False" };
	const true_false_string		*tf = &default_tf;
	const value_string		*vals;

	/* Early return? */
	switch(hfinfo->type) {
		case FT_NONE:
		case FT_PROTOCOL:
		case FT_FLOAT:
		case FT_DOUBLE:
		case FT_ABSOLUTE_TIME:
		case FT_RELATIVE_TIME:
		case FT_IPv4:
		case FT_IPv6:
		case FT_IPXNET:
		case FT_ETHER:
		case FT_BYTES:
		case FT_UINT_BYTES:
		case FT_STRING:
		case FT_STRINGZ:
		case FT_UINT_STRING:
		case FT_UINT64:
		case FT_INT64:
		case FT_PCRE:
		case FT_GUID:
		case FT_OID:
			return FALSE;

		case FT_BOOLEAN:
		case FT_FRAMENUM:
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
			break;

		case FT_NUM_TYPES:
			g_assert_not_reached();
	}

	/* Reset the dfilter error message, since *something* interesting
	 * will happen, and the error message will be more interesting than
	 * any error message I happen to have now. */
	dfilter_error_msg = NULL;

	/* TRUE/FALSE *always* exist for FT_BOOLEAN. */
	if (hfinfo->type == FT_BOOLEAN) {
		if (hfinfo->strings) {
			tf = hfinfo->strings;
		}

		if (strcasecmp(s, tf->true_string) == 0) {
			return mk_uint32_fvalue(TRUE);
		}
		else if (strcasecmp(s, tf->false_string) == 0) {
			return mk_uint32_fvalue(FALSE);
		}
		else {
			dfilter_fail("\"%s\" cannot be found among the possible values for %s.",
				s, hfinfo->abbrev);
			return NULL;
		}
	}

	/* Do val_strings exist? */
	if (!hfinfo->strings) {
		dfilter_fail("%s cannot accept strings as values.",
				hfinfo->abbrev);
		return FALSE;
	}

	vals = hfinfo->strings;
	while (vals->strptr != NULL) {
		if (strcasecmp(s, vals->strptr) == 0) {
			return mk_uint32_fvalue(vals->value);
		}
		vals++;
	}
	dfilter_fail("\"%s\" cannot be found among the possible values for %s.",
			s, hfinfo->abbrev);
	return FALSE;
}

static gboolean
is_bytes_type(enum ftenum type)
{
	switch(type) {
		case FT_ETHER:
		case FT_BYTES:
		case FT_UINT_BYTES:
		case FT_IPv6:
		case FT_GUID:
		case FT_OID:
			return TRUE;

		case FT_NONE:
		case FT_PROTOCOL:
		case FT_FLOAT:
		case FT_DOUBLE:
		case FT_ABSOLUTE_TIME:
		case FT_RELATIVE_TIME:
		case FT_IPv4:
		case FT_IPXNET:
		case FT_STRING:
		case FT_STRINGZ:
		case FT_UINT_STRING:
		case FT_BOOLEAN:
		case FT_FRAMENUM:
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
		case FT_UINT64:
		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
		case FT_INT64:
		case FT_PCRE:
			return FALSE;

		case FT_NUM_TYPES:
			g_assert_not_reached();
	}

	g_assert_not_reached();
	return FALSE;
}

/* Check the semantics of an existence test. */
static void
check_exists(stnode_t *st_arg1)
{
#ifdef DEBUG_dfilter
	static guint i = 0;
#endif

	DebugLog(("   4 check_exists() [%u]\n", i++));
	switch (stnode_type_id(st_arg1)) {
		case STTYPE_FIELD:
			/* This is OK */
			break;
		case STTYPE_STRING:
		case STTYPE_UNPARSED:
			dfilter_fail("\"%s\" is neither a field nor a protocol name.",
					stnode_data(st_arg1));
			THROW(TypeError);
			break;

		case STTYPE_RANGE:
			/*
			 * XXX - why not?  Shouldn't "eth[3:2]" mean
			 * "check whether the 'eth' field is present and
			 * has at least 2 bytes starting at an offset of
			 * 3"?
			 */
			dfilter_fail("You cannot test whether a range is present.");
			THROW(TypeError);
			break;

		case STTYPE_FUNCTION:
            /* XXX - Maybe we should change functions so they can return fields,
             * in which case the 'exist' should be fine. */
			dfilter_fail("You cannot test whether a function is present.");
			THROW(TypeError);
			break;

		case STTYPE_UNINITIALIZED:
		case STTYPE_TEST:
		case STTYPE_INTEGER:
		case STTYPE_FVALUE:
		case STTYPE_NUM_TYPES:
			g_assert_not_reached();
	}
}

struct check_drange_sanity_args {
	stnode_t		*st;
	gboolean		err;
};

/* Q: Where are sttype_range_drange() and sttype_range_hfinfo() defined?
 *
 * A: Those functions are defined by macros in epan/dfilter/sttype-range.h
 *
 *    The macro which creates them, STTYPE_ACCESSOR, is defined in
 *    epan/dfilter/syntax-tree.h.
 *
 * From http://www.ethereal.com/lists/ethereal-dev/200308/msg00070.html
 */

static void
check_drange_node_sanity(gpointer data, gpointer user_data)
{
	drange_node*		drnode = data;
	struct check_drange_sanity_args *args = user_data;
	gint			start_offset, end_offset, length;
	header_field_info	*hfinfo;

	switch (drange_node_get_ending(drnode)) {

	case LENGTH:
		length = drange_node_get_length(drnode);
		if (length <= 0) {
			if (!args->err) {
				args->err = TRUE;
				start_offset = drange_node_get_start_offset(drnode);
				hfinfo = sttype_range_hfinfo(args->st);
				dfilter_fail("Range %d:%d specified for \"%s\" isn't valid, "
					"as length %d isn't positive",
					start_offset, length,
					hfinfo->abbrev,
					length);
			}
		}
		break;

	case OFFSET:
		/*
		 * Make sure the start offset isn't beyond the end
		 * offset.  This applies to negative offsets too.
		 */

		/* XXX - [-ve - +ve] is probably pathological, but isn't
		 * disallowed.
		 * [+ve - -ve] is probably pathological too, and happens to be
		 * disallowed.
		 */
		start_offset = drange_node_get_start_offset(drnode);
		end_offset = drange_node_get_end_offset(drnode);
		if (start_offset > end_offset) {
			if (!args->err) {
				args->err = TRUE;
				hfinfo = sttype_range_hfinfo(args->st);
				dfilter_fail("Range %d-%d specified for \"%s\" isn't valid, "
					"as %d is greater than %d",
					start_offset, end_offset,
					hfinfo->abbrev,
					start_offset, end_offset);
			}
		}
		break;

	case TO_THE_END:
		break;

	case UNINITIALIZED:
	default:
		g_assert_not_reached();
	}
}

static void
check_drange_sanity(stnode_t *st)
{
	struct check_drange_sanity_args	args;

	args.st = st;
	args.err = FALSE;

	drange_foreach_drange_node(sttype_range_drange(st),
	    check_drange_node_sanity, &args);

	if (args.err) {
		THROW(TypeError);
	}
}

/* If the LHS of a relation test is a FIELD, run some checks
 * and possibly some modifications of syntax tree nodes. */
static void
check_relation_LHS_FIELD(const char *relation_string, FtypeCanFunc can_func,
		gboolean allow_partial_value,
		stnode_t *st_node, stnode_t *st_arg1, stnode_t *st_arg2)
{
	stnode_t		*new_st;
	sttype_id_t		type1, type2;
	header_field_info	*hfinfo1, *hfinfo2;
	ftenum_t		ftype1, ftype2;
	fvalue_t		*fvalue;
	char			*s;
	drange_node		*rn;

	type1 = stnode_type_id(st_arg1);
	type2 = stnode_type_id(st_arg2);

	hfinfo1 = stnode_data(st_arg1);
	ftype1 = hfinfo1->type;

	DebugLog(("    5 check_relation_LHS_FIELD(%s)\n", relation_string));

	if (!can_func(ftype1)) {
		dfilter_fail("%s (type=%s) cannot participate in '%s' comparison.",
				hfinfo1->abbrev, ftype_pretty_name(ftype1),
				relation_string);
		THROW(TypeError);
	}

	if (type2 == STTYPE_FIELD) {
		hfinfo2 = stnode_data(st_arg2);
		ftype2 = hfinfo2->type;

		if (!compatible_ftypes(ftype1, ftype2)) {
			dfilter_fail("%s and %s are not of compatible types.",
					hfinfo1->abbrev, hfinfo2->abbrev);
			THROW(TypeError);
		}
		/* Do this check even though you'd think that if
		 * they're compatible, then can_func() would pass. */
		if (!can_func(ftype2)) {
			dfilter_fail("%s (type=%s) cannot participate in specified comparison.",
					hfinfo2->abbrev, ftype_pretty_name(ftype2));
			THROW(TypeError);
		}
	}
	else if (type2 == STTYPE_STRING) {
		s = stnode_data(st_arg2);
		if (strcmp(relation_string, "matches") == 0) {
			/* Convert to a FT_PCRE */
			fvalue = fvalue_from_string(FT_PCRE, s, dfilter_fail);
		} else {
			fvalue = fvalue_from_string(ftype1, s, dfilter_fail);
			if (!fvalue) {
				/* check value_string */
				fvalue = mk_fvalue_from_val_string(hfinfo1, s);
			}
		}
		if (!fvalue) {
			THROW(TypeError);
		}

		new_st = stnode_new(STTYPE_FVALUE, fvalue);
		sttype_test_set2_args(st_node, st_arg1, new_st);
		stnode_free(st_arg2);
	}
	else if (type2 == STTYPE_UNPARSED) {
		s = stnode_data(st_arg2);
		if (strcmp(relation_string, "matches") == 0) {
			/* Convert to a FT_PCRE */
			fvalue = fvalue_from_unparsed(FT_PCRE, s, FALSE, dfilter_fail);
		} else {
			fvalue = fvalue_from_unparsed(ftype1, s, allow_partial_value, dfilter_fail);
			if (!fvalue) {
				/* check value_string */
				fvalue = mk_fvalue_from_val_string(hfinfo1, s);
			}
		}
		if (!fvalue) {
			THROW(TypeError);
		}

		new_st = stnode_new(STTYPE_FVALUE, fvalue);
		sttype_test_set2_args(st_node, st_arg1, new_st);
		stnode_free(st_arg2);
	}
	else if (type2 == STTYPE_RANGE) {
		check_drange_sanity(st_arg2);
		if (!is_bytes_type(ftype1)) {
			if (!ftype_can_slice(ftype1)) {
				dfilter_fail("\"%s\" is a %s and cannot be converted into a sequence of bytes.",
						hfinfo1->abbrev,
						ftype_pretty_name(ftype1));
				THROW(TypeError);
			}

			/* Convert entire field to bytes */
			new_st = stnode_new(STTYPE_RANGE, NULL);

			rn = drange_node_new();
			drange_node_set_start_offset(rn, 0);
			drange_node_set_to_the_end(rn);
			/* st_arg1 is freed in this step */
			sttype_range_set1(new_st, st_arg1, rn);

			sttype_test_set2_args(st_node, new_st, st_arg2);
		}
	}
	else {
		g_assert_not_reached();
	}
}

static void
check_relation_LHS_STRING(const char* relation_string,
		FtypeCanFunc can_func _U_, gboolean allow_partial_value _U_,
		stnode_t *st_node,
		stnode_t *st_arg1, stnode_t *st_arg2)
{
	stnode_t		*new_st;
	sttype_id_t		type1, type2;
	header_field_info	*hfinfo2;
	ftenum_t		ftype2;
	fvalue_t		*fvalue;
	char			*s;

	type1 = stnode_type_id(st_arg1);
	type2 = stnode_type_id(st_arg2);

	DebugLog(("    5 check_relation_LHS_STRING()\n"));

	if (type2 == STTYPE_FIELD) {
		hfinfo2 = stnode_data(st_arg2);
		ftype2 = hfinfo2->type;

		if (!can_func(ftype2)) {
			dfilter_fail("%s (type=%s) cannot participate in '%s' comparison.",
					hfinfo2->abbrev, ftype_pretty_name(ftype2),
					relation_string);
			THROW(TypeError);
		}

		s = stnode_data(st_arg1);
		fvalue = fvalue_from_string(ftype2, s, dfilter_fail);
		if (!fvalue) {
			/* check value_string */
			fvalue = mk_fvalue_from_val_string(hfinfo2, s);
			if (!fvalue) {
				THROW(TypeError);
			}
		}

		new_st = stnode_new(STTYPE_FVALUE, fvalue);
		sttype_test_set2_args(st_node, new_st, st_arg2);
		stnode_free(st_arg1);
	}
	else if (type2 == STTYPE_STRING || type2 == STTYPE_UNPARSED) {
		/* Well now that's silly... */
		dfilter_fail("Neither \"%s\" nor \"%s\" are field or protocol names.",
				stnode_data(st_arg1),
				stnode_data(st_arg2));
		THROW(TypeError);
	}
	else if (type2 == STTYPE_RANGE) {
		check_drange_sanity(st_arg2);
		s = stnode_data(st_arg1);
		fvalue = fvalue_from_string(FT_BYTES, s, dfilter_fail);
		if (!fvalue) {
			THROW(TypeError);
		}
		new_st = stnode_new(STTYPE_FVALUE, fvalue);
		sttype_test_set2_args(st_node, new_st, st_arg2);
		stnode_free(st_arg1);
	}
	else {
		g_assert_not_reached();
	}
}

static void
check_relation_LHS_UNPARSED(const char* relation_string,
		FtypeCanFunc can_func, gboolean allow_partial_value,
		stnode_t *st_node,
		stnode_t *st_arg1, stnode_t *st_arg2)
{
	stnode_t		*new_st;
	sttype_id_t		type1, type2;
	header_field_info	*hfinfo2;
	ftenum_t		ftype2;
	fvalue_t		*fvalue;
	char			*s;

	type1 = stnode_type_id(st_arg1);
	type2 = stnode_type_id(st_arg2);

	DebugLog(("    5 check_relation_LHS_UNPARSED()\n"));

	if (type2 == STTYPE_FIELD) {
		hfinfo2 = stnode_data(st_arg2);
		ftype2 = hfinfo2->type;

		if (!can_func(ftype2)) {
			dfilter_fail("%s (type=%s) cannot participate in '%s' comparison.",
					hfinfo2->abbrev, ftype_pretty_name(ftype2),
					relation_string);
			THROW(TypeError);
		}

		s = stnode_data(st_arg1);
		fvalue = fvalue_from_unparsed(ftype2, s, allow_partial_value, dfilter_fail);
		if (!fvalue) {
			/* check value_string */
			fvalue = mk_fvalue_from_val_string(hfinfo2, s);
			if (!fvalue) {
				THROW(TypeError);
			}
		}

		new_st = stnode_new(STTYPE_FVALUE, fvalue);
		sttype_test_set2_args(st_node, new_st, st_arg2);
		stnode_free(st_arg1);
	}
	else if (type2 == STTYPE_STRING || type2 == STTYPE_UNPARSED) {
		/* Well now that's silly... */
		dfilter_fail("Neither \"%s\" nor \"%s\" are field or protocol names.",
				stnode_data(st_arg1),
				stnode_data(st_arg2));
		THROW(TypeError);
	}
	else if (type2 == STTYPE_RANGE) {
		check_drange_sanity(st_arg2);
		s = stnode_data(st_arg1);
		fvalue = fvalue_from_unparsed(FT_BYTES, s, allow_partial_value, dfilter_fail);
		if (!fvalue) {
			THROW(TypeError);
		}
		new_st = stnode_new(STTYPE_FVALUE, fvalue);
		sttype_test_set2_args(st_node, new_st, st_arg2);
		stnode_free(st_arg1);
	}
	else {
		g_assert_not_reached();
	}
}

static void
check_relation_LHS_RANGE(const char *relation_string, FtypeCanFunc can_func _U_,
		gboolean allow_partial_value,
		stnode_t *st_node,
		stnode_t *st_arg1, stnode_t *st_arg2)
{
	stnode_t		*new_st;
	sttype_id_t		type1, type2;
	header_field_info	*hfinfo1, *hfinfo2;
	ftenum_t		ftype1, ftype2;
	fvalue_t		*fvalue;
	char			*s;
	drange_node		*rn;

	type1 = stnode_type_id(st_arg1);
	type2 = stnode_type_id(st_arg2);
	hfinfo1 = sttype_range_hfinfo(st_arg1);
	ftype1 = hfinfo1->type;

	DebugLog(("    5 check_relation_LHS_RANGE(%s)\n", relation_string));

	if (!ftype_can_slice(ftype1)) {
		dfilter_fail("\"%s\" is a %s and cannot be sliced into a sequence of bytes.",
				hfinfo1->abbrev, ftype_pretty_name(ftype1));
		THROW(TypeError);
	}

	check_drange_sanity(st_arg1);

	if (type2 == STTYPE_FIELD) {
		DebugLog(("    5 check_relation_LHS_RANGE(type2 = STTYPE_FIELD)\n"));
		hfinfo2 = stnode_data(st_arg2);
		ftype2 = hfinfo2->type;

		if (!is_bytes_type(ftype2)) {
			if (!ftype_can_slice(ftype2)) {
				dfilter_fail("\"%s\" is a %s and cannot be converted into a sequence of bytes.",
						hfinfo2->abbrev,
						ftype_pretty_name(ftype2));
				THROW(TypeError);
			}

			/* Convert entire field to bytes */
			new_st = stnode_new(STTYPE_RANGE, NULL);

			rn = drange_node_new();
			drange_node_set_start_offset(rn, 0);
			drange_node_set_to_the_end(rn);
			/* st_arg2 is freed in this step */
			sttype_range_set1(new_st, st_arg2, rn);

			sttype_test_set2_args(st_node, st_arg1, new_st);
		}
	}
	else if (type2 == STTYPE_STRING) {
		DebugLog(("    5 check_relation_LHS_RANGE(type2 = STTYPE_STRING)\n"));
		s = stnode_data(st_arg2);
		if (strcmp(relation_string, "matches") == 0) {
			/* Convert to a FT_PCRE */
			fvalue = fvalue_from_string(FT_PCRE, s, dfilter_fail);
		} else {
			fvalue = fvalue_from_string(FT_BYTES, s, dfilter_fail);
		}
		if (!fvalue) {
			DebugLog(("    5 check_relation_LHS_RANGE(type2 = STTYPE_STRING): Could not convert from string!\n"));
			THROW(TypeError);
		}
		new_st = stnode_new(STTYPE_FVALUE, fvalue);
		sttype_test_set2_args(st_node, st_arg1, new_st);
		stnode_free(st_arg2);
	}
	else if (type2 == STTYPE_UNPARSED) {
		DebugLog(("    5 check_relation_LHS_RANGE(type2 = STTYPE_UNPARSED)\n"));
		s = stnode_data(st_arg2);
		if (strcmp(relation_string, "matches") == 0) {
			/* Convert to a FT_PCRE */
			fvalue = fvalue_from_unparsed(FT_PCRE, s, FALSE, dfilter_fail);
		} else {
			fvalue = fvalue_from_unparsed(FT_BYTES, s, allow_partial_value, dfilter_fail);
		}
		if (!fvalue) {
			DebugLog(("    5 check_relation_LHS_RANGE(type2 = STTYPE_UNPARSED): Could not convert from string!\n"));
			THROW(TypeError);
		}
		new_st = stnode_new(STTYPE_FVALUE, fvalue);
		sttype_test_set2_args(st_node, st_arg1, new_st);
		stnode_free(st_arg2);
	}
	else if (type2 == STTYPE_RANGE) {
		DebugLog(("    5 check_relation_LHS_RANGE(type2 = STTYPE_RANGE)\n"));
		check_drange_sanity(st_arg2);
	}
	else {
		g_assert_not_reached();
	}
}

static stnode_t*
check_param_entity(stnode_t *st_node)
{
	sttype_id_t		e_type;
	stnode_t		*new_st;
	fvalue_t		*fvalue;
    char *s;

	e_type = stnode_type_id(st_node);
    /* If there's an unparsed string, change it to an FT_STRING */
    if (e_type == STTYPE_UNPARSED) {
		s = stnode_data(st_node);
        fvalue = fvalue_from_unparsed(FT_STRING, s, FALSE, dfilter_fail);
		if (!fvalue) {
			THROW(TypeError);
		}

		new_st = stnode_new(STTYPE_FVALUE, fvalue);
		stnode_free(st_node);
        return new_st;
    }

    return st_node;
}


/* If the LHS of a relation test is a FUNCTION, run some checks
 * and possibly some modifications of syntax tree nodes. */
static void
check_relation_LHS_FUNCTION(const char *relation_string, FtypeCanFunc can_func,
		gboolean allow_partial_value,
		stnode_t *st_node, stnode_t *st_arg1, stnode_t *st_arg2)
{
	stnode_t		*new_st;
	sttype_id_t		type2;
	header_field_info	*hfinfo2;
	ftenum_t		ftype1, ftype2;
	fvalue_t		*fvalue;
	char			*s;
    int             param_i;
	drange_node		*rn;
    df_func_def_t   *funcdef;
    guint             num_params;
    GSList          *params;

	type2 = stnode_type_id(st_arg2);

    funcdef = sttype_function_funcdef(st_arg1);
	ftype1 = funcdef->retval_ftype;

    params = sttype_function_params(st_arg1);
    num_params = g_slist_length(params);
    if (num_params < funcdef->min_nargs) {
        dfilter_fail("Function %s needs at least %u arguments.",
                funcdef->name, funcdef->min_nargs);
        THROW(TypeError);
    }
    else if (num_params > funcdef->max_nargs) {
        dfilter_fail("Function %s can only accept %u arguments.",
                funcdef->name, funcdef->max_nargs);
        THROW(TypeError);
    }

    param_i = 0;
    while (params) {
        params->data = check_param_entity(params->data);
        funcdef->semcheck_param_function(param_i, params->data);
        params = params->next;
    }

	DebugLog(("    5 check_relation_LHS_FUNCTION(%s)\n", relation_string));

	if (!can_func(ftype1)) {
		dfilter_fail("Function %s (type=%s) cannot participate in '%s' comparison.",
				funcdef->name, ftype_pretty_name(ftype1),
				relation_string);
		THROW(TypeError);
	}

	if (type2 == STTYPE_FIELD) {
		hfinfo2 = stnode_data(st_arg2);
		ftype2 = hfinfo2->type;

		if (!compatible_ftypes(ftype1, ftype2)) {
			dfilter_fail("Function %s and %s are not of compatible types.",
					funcdef->name, hfinfo2->abbrev);
			THROW(TypeError);
		}
		/* Do this check even though you'd think that if
		 * they're compatible, then can_func() would pass. */
		if (!can_func(ftype2)) {
			dfilter_fail("%s (type=%s) cannot participate in specified comparison.",
					hfinfo2->abbrev, ftype_pretty_name(ftype2));
			THROW(TypeError);
		}
	}
	else if (type2 == STTYPE_STRING) {
		s = stnode_data(st_arg2);
		if (strcmp(relation_string, "matches") == 0) {
			/* Convert to a FT_PCRE */
			fvalue = fvalue_from_string(FT_PCRE, s, dfilter_fail);
		} else {
			fvalue = fvalue_from_string(ftype1, s, dfilter_fail);
		}
		if (!fvalue) {
			THROW(TypeError);
		}

		new_st = stnode_new(STTYPE_FVALUE, fvalue);
		sttype_test_set2_args(st_node, st_arg1, new_st);
		stnode_free(st_arg2);
	}
	else if (type2 == STTYPE_UNPARSED) {
		s = stnode_data(st_arg2);
		if (strcmp(relation_string, "matches") == 0) {
			/* Convert to a FT_PCRE */
			fvalue = fvalue_from_unparsed(FT_PCRE, s, FALSE, dfilter_fail);
		} else {
			fvalue = fvalue_from_unparsed(ftype1, s, allow_partial_value, dfilter_fail);
		}
		if (!fvalue) {
			THROW(TypeError);
		}

		new_st = stnode_new(STTYPE_FVALUE, fvalue);
		sttype_test_set2_args(st_node, st_arg1, new_st);
		stnode_free(st_arg2);
	}
	else if (type2 == STTYPE_RANGE) {
		check_drange_sanity(st_arg2);
		if (!is_bytes_type(ftype1)) {
			if (!ftype_can_slice(ftype1)) {
				dfilter_fail("Function \"%s\" is a %s and cannot be converted into a sequence of bytes.",
						funcdef->name,
						ftype_pretty_name(ftype1));
				THROW(TypeError);
			}

			/* Convert entire field to bytes */
			new_st = stnode_new(STTYPE_RANGE, NULL);

			rn = drange_node_new();
			drange_node_set_start_offset(rn, 0);
			drange_node_set_to_the_end(rn);
			/* st_arg1 is freed in this step */
			sttype_range_set1(new_st, st_arg1, rn);

			sttype_test_set2_args(st_node, new_st, st_arg2);
		}
	}
	else {
		g_assert_not_reached();
	}
}


/* Check the semantics of any relational test. */
static void
check_relation(const char *relation_string, gboolean allow_partial_value,
		FtypeCanFunc can_func, stnode_t *st_node,
		stnode_t *st_arg1, stnode_t *st_arg2)
{
#ifdef DEBUG_dfilter
	static guint i = 0;
#endif
header_field_info   *hfinfo;

	DebugLog(("   4 check_relation(\"%s\") [%u]\n", relation_string, i++));

	/* Protocol can only be on LHS (for "contains" or "matches" operators).
	 * Check to see if protocol is on RHS.  This catches the case where the
	 * user has written "fc" on the RHS, probably intending a byte value
	 * rather than the fibre channel protocol.
	 */

	if (stnode_type_id(st_arg2) == STTYPE_FIELD) {
		hfinfo = stnode_data(st_arg2);
		if (hfinfo->type == FT_PROTOCOL)
			dfilter_fail("Protocol (\"%s\") cannot appear on right-hand side of comparison.", hfinfo->abbrev);
			THROW(TypeError);
	}

	switch (stnode_type_id(st_arg1)) {
		case STTYPE_FIELD:
			check_relation_LHS_FIELD(relation_string, can_func,
					allow_partial_value, st_node, st_arg1, st_arg2);
			break;
		case STTYPE_STRING:
			check_relation_LHS_STRING(relation_string, can_func,
					allow_partial_value, st_node, st_arg1, st_arg2);
			break;
		case STTYPE_RANGE:
			check_relation_LHS_RANGE(relation_string, can_func,
					allow_partial_value, st_node, st_arg1, st_arg2);
			break;
		case STTYPE_UNPARSED:
			check_relation_LHS_UNPARSED(relation_string, can_func,
					allow_partial_value, st_node, st_arg1, st_arg2);
			break;
		case STTYPE_FUNCTION:
			check_relation_LHS_FUNCTION(relation_string, can_func,
					allow_partial_value, st_node, st_arg1, st_arg2);
			break;

		case STTYPE_UNINITIALIZED:
		case STTYPE_TEST:
		case STTYPE_INTEGER:
		case STTYPE_FVALUE:
        default:
			g_assert_not_reached();
	}
}

/* Check the semantics of any type of TEST */
static void
check_test(stnode_t *st_node)
{
	test_op_t		st_op;
	stnode_t		*st_arg1, *st_arg2;
#ifdef DEBUG_dfilter
	static guint i = 0;
#endif

	DebugLog(("  3 check_test(stnode_t *st_node = %p) [%u]\n", st_node, i));

	sttype_test_get(st_node, &st_op, &st_arg1, &st_arg2);

	switch (st_op) {
		case TEST_OP_UNINITIALIZED:
			g_assert_not_reached();
			break;

		case TEST_OP_EXISTS:
			check_exists(st_arg1);
			break;

		case TEST_OP_NOT:
			semcheck(st_arg1);
			break;

		case TEST_OP_AND:
		case TEST_OP_OR:
			semcheck(st_arg1);
			semcheck(st_arg2);
			break;

		case TEST_OP_EQ:
			check_relation("==", FALSE, ftype_can_eq, st_node, st_arg1, st_arg2);
			break;
		case TEST_OP_NE:
			check_relation("!=", FALSE, ftype_can_ne, st_node, st_arg1, st_arg2);
			break;
		case TEST_OP_GT:
			check_relation(">", FALSE, ftype_can_gt, st_node, st_arg1, st_arg2);
			break;
		case TEST_OP_GE:
			check_relation(">=", FALSE, ftype_can_ge, st_node, st_arg1, st_arg2);
			break;
		case TEST_OP_LT:
			check_relation("<", FALSE, ftype_can_lt, st_node, st_arg1, st_arg2);
			break;
		case TEST_OP_LE:
			check_relation("<=", FALSE, ftype_can_le, st_node, st_arg1, st_arg2);
			break;
		case TEST_OP_BITWISE_AND:
			check_relation("&", FALSE, ftype_can_bitwise_and, st_node, st_arg1, st_arg2);
			break;
		case TEST_OP_CONTAINS:
			check_relation("contains", TRUE, ftype_can_contains, st_node, st_arg1, st_arg2);
			break;
		case TEST_OP_MATCHES:
#ifdef HAVE_LIBPCRE
			check_relation("matches", TRUE, ftype_can_matches, st_node, st_arg1, st_arg2);
#else
			dfilter_fail("This Ethereal version does not support the \"matches\" operation.");
			THROW(TypeError);
#endif
			break;

		default:
			g_assert_not_reached();
	}
	DebugLog(("  3 check_test(stnode_t *st_node = %p) [%u] - End\n", st_node, i++));
}


/* Check the entire syntax tree. */
static void
semcheck(stnode_t *st_node)
{
#ifdef DEBUG_dfilter
	static guint i = 0;
#endif
	DebugLog((" 2 semcheck(stnode_t *st_node = %p) [%u]\n", st_node, i++));
	/* The parser assures that the top-most syntax-tree
	 * node will be a TEST node, no matter what. So assert that. */
	switch (stnode_type_id(st_node)) {
		case STTYPE_TEST:
			check_test(st_node);
			break;
		default:
			g_assert_not_reached();
	}
}


/* Check the syntax tree for semantic errors, and convert
 * some of the nodes into the form they need to be in order to
 * later generate the DFVM bytecode. */
gboolean
dfw_semcheck(dfwork_t *dfw)
{
#ifdef DEBUG_dfilter
	static guint i = 0;
#endif
	
	DebugLog(("1 dfw_semcheck(dfwork_t *dfw = %p) [%u]\n", dfw, i));
	/* Instead of having to check for errors at every stage of
	 * the semantic-checking, the semantic-checking code will
	 * throw an exception if a problem is found. */
	TRY {
		semcheck(dfw->st_root);
	}
	CATCH(TypeError) {
		DebugLog(("1 dfw_semcheck(dfwork_t *dfw = %p) [%u] - Returns FALSE\n",
					dfw, i++));
		return FALSE;
	}
	ENDTRY;

	DebugLog(("1 dfw_semcheck(dfwork_t *dfw = %p) [%u] - Returns TRUE\n",
				dfw, i++));
	return TRUE;
}
