/*
 * $Id: gencode.c,v 1.5 2002/01/21 07:37:37 guy Exp $
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

#include "dfilter-int.h"
#include "dfvm.h"
#include "syntax-tree.h"
#include "sttype-range.h"
#include "sttype-test.h"
#include "ftypes/ftypes.h"
#include <epan/gdebug.h>

static void
gencode(dfwork_t *dfw, stnode_t *st_node);

static void
dfw_append_insn(dfwork_t *dfw, dfvm_insn_t *insn)
{
	insn->id = dfw->next_insn_id;
	dfw->next_insn_id++;
	g_ptr_array_add(dfw->insns, insn);
}

/* returns register number */
static int
dfw_append_read_tree(dfwork_t *dfw, int field_id)
{
	dfvm_insn_t	*insn;
	dfvm_value_t	*val1, *val2;
	int		reg = -1;

	/* Keep track of which registers
	 * were used for which field_id's so that we
	 * can re-use registers. */
	reg = GPOINTER_TO_UINT(
			g_hash_table_lookup(dfw->loaded_fields,
			GINT_TO_POINTER(field_id)));
	if (reg) {
		/* Reg's are stored in has as reg+1, so
		 * that the non-existence of a field_id in
		 * the hash, or 0, can be differentiated from
		 * a field_id being loaded into register #0. */
		reg--;
	}
	else {
		reg = dfw->next_register++;
		g_hash_table_insert(dfw->loaded_fields,
			GUINT_TO_POINTER(field_id),
			GUINT_TO_POINTER(reg + 1));

        /* Record the FIELD_ID in hash of interesting fields. */
        g_hash_table_insert(dfw->interesting_fields,
            GINT_TO_POINTER(field_id), GUINT_TO_POINTER(TRUE));
	}

	insn = dfvm_insn_new(READ_TREE);
	val1 = dfvm_value_new(FIELD_ID);
	val1->value.numeric = field_id;
	val2 = dfvm_value_new(REGISTER);
	val2->value.numeric = reg;

	insn->arg1 = val1;
	insn->arg2 = val2;
	dfw_append_insn(dfw, insn);

	return reg;
}

/* returns register number */
static int
dfw_append_put_fvalue(dfwork_t *dfw, fvalue_t *fv)
{
	dfvm_insn_t	*insn;
	dfvm_value_t	*val1, *val2;
	int		reg;

	insn = dfvm_insn_new(PUT_FVALUE);
	val1 = dfvm_value_new(FVALUE);
	val1->value.fvalue = fv;
	val2 = dfvm_value_new(REGISTER);
	reg = dfw->next_register++;
	val2->value.numeric = reg;
	insn->arg1 = val1;
	insn->arg2 = val2;
	dfw_append_insn(dfw, insn);

	return reg;
}

/* returns register number */
static int
dfw_append_mk_range(dfwork_t *dfw, stnode_t *node)
{
	int			hf_reg, reg;
	header_field_info	*hfinfo;
	dfvm_insn_t		*insn;
	dfvm_value_t		*val;

	hfinfo = sttype_range_hfinfo(node);
	hf_reg = dfw_append_read_tree(dfw, hfinfo->id);

	insn = dfvm_insn_new(MK_RANGE);

	val = dfvm_value_new(REGISTER);
	val->value.numeric = hf_reg;
	insn->arg1 = val;

	val = dfvm_value_new(REGISTER);
	reg =dfw->next_register++;
	val->value.numeric = reg;
	insn->arg2 = val;

	val = dfvm_value_new(DRANGE);
	val->value.drange = sttype_range_drange(node);
	insn->arg3 = val;

	sttype_range_remove_drange(node);

	dfw_append_insn(dfw, insn);

	return reg;
}


static void
gen_relation(dfwork_t *dfw, dfvm_opcode_t op, stnode_t *st_arg1, stnode_t *st_arg2)
{
	sttype_id_t	type1, type2;
	dfvm_insn_t	*insn;
	dfvm_value_t	*val1, *val2;
	dfvm_value_t	*jmp1 = NULL, *jmp2 = NULL;
	int		reg1 = -1, reg2 = -1;
	header_field_info	*hfinfo;

	type1 = stnode_type_id(st_arg1);
	type2 = stnode_type_id(st_arg2);

	if (type1 == STTYPE_FIELD) {
		hfinfo = stnode_data(st_arg1);
		reg1 = dfw_append_read_tree(dfw, hfinfo->id);

		insn = dfvm_insn_new(IF_FALSE_GOTO);
		jmp1 = dfvm_value_new(INSN_NUMBER);
		insn->arg1 = jmp1;
		dfw_append_insn(dfw, insn);
	}
	else if (type1 == STTYPE_FVALUE) {
		reg1 = dfw_append_put_fvalue(dfw, stnode_data(st_arg1));
	}
	else if (type1 == STTYPE_RANGE) {
		reg1 = dfw_append_mk_range(dfw, st_arg1);
	}
	else {
		g_assert_not_reached();
	}

	if (type2 == STTYPE_FIELD) {
		hfinfo = stnode_data(st_arg2);
		reg2 = dfw_append_read_tree(dfw, hfinfo->id);

		insn = dfvm_insn_new(IF_FALSE_GOTO);
		jmp2 = dfvm_value_new(INSN_NUMBER);
		insn->arg1 = jmp2;
		dfw_append_insn(dfw, insn);
	}
	else if (type2 == STTYPE_FVALUE) {
		reg2 = dfw_append_put_fvalue(dfw, stnode_data(st_arg2));
	}
	else {
		g_assert_not_reached();
	}

	insn = dfvm_insn_new(op);
	val1 = dfvm_value_new(REGISTER);
	val1->value.numeric = reg1;
	val2 = dfvm_value_new(REGISTER);
	val2->value.numeric = reg2;
	insn->arg1 = val1;
	insn->arg2 = val2;
	dfw_append_insn(dfw, insn);

	if (jmp1) {
		jmp1->value.numeric = dfw->next_insn_id;
	}

	if (jmp2) {
		jmp2->value.numeric = dfw->next_insn_id;
	}
}


static void
gen_test(dfwork_t *dfw, stnode_t *st_node)
{
	test_op_t	st_op;
	stnode_t	*st_arg1, *st_arg2;
	dfvm_value_t	*val1;
	dfvm_insn_t	*insn;

	header_field_info	*hfinfo;

	sttype_test_get(st_node, &st_op, &st_arg1, &st_arg2);

	switch (st_op) {
		case TEST_OP_UNINITIALIZED:
			g_assert_not_reached();
			break;

		case TEST_OP_EXISTS:
			val1 = dfvm_value_new(FIELD_ID);
			hfinfo = stnode_data(st_arg1);
			val1->value.numeric = hfinfo->id;
			insn = dfvm_insn_new(CHECK_EXISTS);
			insn->arg1 = val1;
			dfw_append_insn(dfw, insn);

            /* Record the FIELD_ID in hash of interesting fields. */
            g_hash_table_insert(dfw->interesting_fields,
                GINT_TO_POINTER(hfinfo->id), GUINT_TO_POINTER(TRUE));

			break;

		case TEST_OP_NOT:
			gencode(dfw, st_arg1);
			insn = dfvm_insn_new(NOT);
			dfw_append_insn(dfw, insn);
			break;

		case TEST_OP_AND:
			gencode(dfw, st_arg1);

			insn = dfvm_insn_new(IF_FALSE_GOTO);
			val1 = dfvm_value_new(INSN_NUMBER);
			insn->arg1 = val1;
			dfw_append_insn(dfw, insn);

			gencode(dfw, st_arg2);
			val1->value.numeric = dfw->next_insn_id;
			break;

		case TEST_OP_OR:
			gencode(dfw, st_arg1);

			insn = dfvm_insn_new(IF_TRUE_GOTO);
			val1 = dfvm_value_new(INSN_NUMBER);
			insn->arg1 = val1;
			dfw_append_insn(dfw, insn);

			gencode(dfw, st_arg2);
			val1->value.numeric = dfw->next_insn_id;
			break;

		case TEST_OP_EQ:
			gen_relation(dfw, ANY_EQ, st_arg1, st_arg2);
			break;

		case TEST_OP_NE:
			gen_relation(dfw, ANY_NE, st_arg1, st_arg2);
			break;

		case TEST_OP_GT:
			gen_relation(dfw, ANY_GT, st_arg1, st_arg2);
			break;

		case TEST_OP_GE:
			gen_relation(dfw, ANY_GE, st_arg1, st_arg2);
			break;

		case TEST_OP_LT:
			gen_relation(dfw, ANY_LT, st_arg1, st_arg2);
			break;

		case TEST_OP_LE:
			gen_relation(dfw, ANY_LE, st_arg1, st_arg2);
			break;
	}
}

static void
gencode(dfwork_t *dfw, stnode_t *st_node)
{
	const char	*name;

	name = stnode_type_name(st_node);

	switch (stnode_type_id(st_node)) {
		case STTYPE_TEST:
			gen_test(dfw, st_node);
			break;
		default:
			g_assert_not_reached();
	}
}


void
dfw_gencode(dfwork_t *dfw)
{
	dfw->insns = g_ptr_array_new();
	dfw->loaded_fields = g_hash_table_new(g_direct_hash, g_direct_equal);
	dfw->interesting_fields = g_hash_table_new(g_direct_hash, g_direct_equal);
	gencode(dfw, dfw->st_root);
	dfw_append_insn(dfw, dfvm_insn_new(RETURN));
}



typedef struct {
    int i;
    int *fields;
} hash_key_iterator;
 
static void
get_hash_key(gpointer key, gpointer value, gpointer user_data)
{
    int field_id = GPOINTER_TO_INT(key);
    hash_key_iterator *hki = user_data;

    hki->fields[hki->i] = field_id;
    hki->i++;
}

int*
dfw_interesting_fields(dfwork_t *dfw, int *caller_num_fields)
{
    int num_fields = g_hash_table_size(dfw->interesting_fields);

    hash_key_iterator hki;

    if (num_fields == 0) {
        *caller_num_fields = 0;
        return NULL;
    }

    hki.fields = g_new(int, num_fields);
    hki.i = 0;
        
    g_hash_table_foreach(dfw->interesting_fields, get_hash_key, &hki);
    *caller_num_fields = num_fields;
    return hki.fields;
}
