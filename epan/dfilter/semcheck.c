/*
 * $Id: semcheck.c,v 1.8 2002/01/21 07:37:37 guy Exp $
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

#include <string.h>

#include "dfilter-int.h"
#include "syntax-tree.h"
#include "sttype-range.h"
#include "sttype-test.h"

#include <epan/exceptions.h>
#include <epan/packet.h>

static void
semcheck(dfwork_t *dfw, stnode_t *st_node);

typedef gboolean (*FtypeCanFunc)(enum ftenum);

/* Compares to ftenum_t's and decides if they're
 * compatible or not (if they're the same basic type) */
static gboolean
compatible_ftypes(ftenum_t a, ftenum_t b)
{
	switch (a) {
		case FT_NONE:
		case FT_PROTOCOL:
		case FT_DOUBLE:
		case FT_ABSOLUTE_TIME:
		case FT_RELATIVE_TIME:
		case FT_IPv4:
		case FT_IPv6:
		case FT_IPXNET:
		case FT_INT64:
		case FT_UINT64:
			return a == b;

		case FT_ETHER:
		case FT_BYTES:
			return (b == FT_ETHER || b == FT_BYTES);

		case FT_BOOLEAN:
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
	static true_false_string        default_tf = { "True", "False" };
	true_false_string		*tf = &default_tf;
	value_string			*vals;

	/* Early return? */
	switch(hfinfo->type) {
		case FT_NONE:
		case FT_PROTOCOL:
		case FT_DOUBLE:
		case FT_ABSOLUTE_TIME:
		case FT_RELATIVE_TIME:
		case FT_IPv4:
		case FT_IPv6:
		case FT_IPXNET:
		case FT_ETHER:
		case FT_BYTES:
		case FT_STRING:
		case FT_STRINGZ:
		case FT_UINT_STRING:
		case FT_UINT64:
		case FT_INT64:
			return FALSE;

		case FT_BOOLEAN:
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
		case FT_IPv6:
			return TRUE;

		case FT_NONE:
		case FT_PROTOCOL:
		case FT_DOUBLE:
		case FT_ABSOLUTE_TIME:
		case FT_RELATIVE_TIME:
		case FT_IPv4:
		case FT_IPXNET:
		case FT_STRING:
		case FT_STRINGZ:
		case FT_UINT_STRING:
		case FT_BOOLEAN:
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
			return FALSE;
			
		case FT_NUM_TYPES:
			g_assert_not_reached();
	}

	g_assert_not_reached();
	return FALSE;
}

static void
check_relation_LHS_FIELD(dfwork_t *dfw, FtypeCanFunc can_func, stnode_t *st_node,
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

	hfinfo1 = stnode_data(st_arg1);
	ftype1 = hfinfo1->type;

	if (!can_func(ftype1)) {
		dfilter_fail("%s (type=%s) cannot participate in specified comparison.",
				hfinfo1->abbrev, ftype_pretty_name(ftype1));
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
		fvalue = fvalue_from_string(ftype1, s, dfilter_fail);
		if (!fvalue) {
			/* check value_string */
			fvalue = mk_fvalue_from_val_string(hfinfo1, s);
			if (!fvalue) {
				THROW(TypeError);
			}
		}

		new_st = stnode_new(STTYPE_FVALUE, fvalue);
		sttype_test_set2_args(st_node, st_arg1, new_st);
		stnode_free(st_arg2);
	}
	else if (type2 == STTYPE_RANGE) {
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
check_relation_LHS_STRING(dfwork_t *dfw, FtypeCanFunc can_func, stnode_t *st_node,
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
		
	if (type2 == STTYPE_FIELD) {
		hfinfo2 = stnode_data(st_arg2);
		ftype2 = hfinfo2->type;

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
	else if (type2 == STTYPE_STRING) {
		/* Well now that's silly... */
		dfilter_fail("Neither \"%s\" nor \"%s\" are field or protocol names.",
				stnode_data(st_arg1),
				stnode_data(st_arg2));
		THROW(TypeError);
	}
	else if (type2 == STTYPE_RANGE) {
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
check_relation_LHS_RANGE(dfwork_t *dfw, FtypeCanFunc can_func, stnode_t *st_node,
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

	if (!ftype_can_slice(ftype1)) {
		dfilter_fail("\"%s\" is a %s and cannot be sliced into a sequence of bytes.",
				hfinfo1->abbrev, ftype_pretty_name(ftype1));
		THROW(TypeError);
	}


	if (type2 == STTYPE_FIELD) {
		hfinfo2 = sttype_range_hfinfo(st_arg2);
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
		s = stnode_data(st_arg2);
		fvalue = fvalue_from_string(FT_BYTES, s, dfilter_fail);
		if (!fvalue) {
			THROW(TypeError);
		}
		new_st = stnode_new(STTYPE_FVALUE, fvalue);
		sttype_test_set2_args(st_node, st_arg1, new_st);
		stnode_free(st_arg2);
	}
	else if (type2 == STTYPE_RANGE) {
		/* XXX - check lengths of both ranges */
	}
	else {
		g_assert_not_reached();
	}
}


static void
check_relation(dfwork_t *dfw, FtypeCanFunc can_func, stnode_t *st_node,
		stnode_t *st_arg1, stnode_t *st_arg2)
{
	switch (stnode_type_id(st_arg1)) {
		case STTYPE_FIELD:
			check_relation_LHS_FIELD(dfw, can_func, st_node, st_arg1, st_arg2);
			break;
		case STTYPE_STRING:
			check_relation_LHS_STRING(dfw, can_func, st_node, st_arg1, st_arg2);
			break;
		case STTYPE_RANGE:
			check_relation_LHS_RANGE(dfw, can_func, st_node, st_arg1, st_arg2);
			break;

		case STTYPE_UNINITIALIZED:
		case STTYPE_TEST:
		case STTYPE_INTEGER:
		case STTYPE_FVALUE:
		case STTYPE_NUM_TYPES:
			g_assert_not_reached();
	}
}

static void
check_test(dfwork_t *dfw, stnode_t *st_node)
{
	test_op_t		st_op;
	stnode_t		*st_arg1, *st_arg2;

	sttype_test_get(st_node, &st_op, &st_arg1, &st_arg2);

	switch (st_op) {
		case TEST_OP_UNINITIALIZED:
			g_assert_not_reached();
			break;

		case TEST_OP_EXISTS:
			/* nothing */
			break;

		case TEST_OP_NOT:
			semcheck(dfw, st_arg1);
			break;

		case TEST_OP_AND:
		case TEST_OP_OR:
			semcheck(dfw, st_arg1);
			semcheck(dfw, st_arg2);
			break;

		case TEST_OP_EQ:
			check_relation(dfw, ftype_can_eq, st_node, st_arg1, st_arg2);
			break;
		case TEST_OP_NE:
			check_relation(dfw, ftype_can_ne, st_node, st_arg1, st_arg2);
			break;
		case TEST_OP_GT:
			check_relation(dfw, ftype_can_gt, st_node, st_arg1, st_arg2);
			break;
		case TEST_OP_GE:
			check_relation(dfw, ftype_can_ge, st_node, st_arg1, st_arg2);
			break;
		case TEST_OP_LT:
			check_relation(dfw, ftype_can_lt, st_node, st_arg1, st_arg2);
			break;
		case TEST_OP_LE:
			check_relation(dfw, ftype_can_le, st_node, st_arg1, st_arg2);
			break;
	}
}


static void
semcheck(dfwork_t *dfw, stnode_t *st_node)
{
	const char	*name;

	name = stnode_type_name(st_node);

	switch (stnode_type_id(st_node)) {
		case STTYPE_TEST:
			check_test(dfw, st_node);
			break;
		default:
			g_assert_not_reached();
	}
}


gboolean
dfw_semcheck(dfwork_t *dfw)
{
	TRY {
		semcheck(dfw, dfw->st_root);
	}
	CATCH(TypeError) {
		return FALSE;
	}
	ENDTRY;

	return TRUE;
}
