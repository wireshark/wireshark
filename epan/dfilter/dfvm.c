/*
 * $Id: dfvm.c,v 1.3 2001/02/27 19:23:28 gram Exp $
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

#include "dfvm.h"

dfvm_insn_t*
dfvm_insn_new(dfvm_opcode_t op)
{
	dfvm_insn_t	*insn;

	insn = g_new(dfvm_insn_t, 1);
	insn->op = op;
	insn->arg1 = NULL;
	insn->arg2 = NULL;
	insn->arg3 = NULL;
	return insn;
}

void
dfvm_insn_free(dfvm_insn_t *insn)
{
	if (insn->arg1) {
		dfvm_value_free(insn->arg1);
	}
	if (insn->arg2) {
		dfvm_value_free(insn->arg2);
	}
	if (insn->arg3) {
		dfvm_value_free(insn->arg3);
	}
	g_free(insn);
}



dfvm_value_t*
dfvm_value_new(dfvm_value_type_t type)
{
	dfvm_value_t	*v;

	v = g_new(dfvm_value_t, 1);
	v->type = type;
	return v;
}

void
dfvm_value_free(dfvm_value_t *v)
{
	switch (v->type) {
		case FVALUE:
			fvalue_free(v->value.fvalue);
			break;
		case DRANGE:
			drange_free(v->value.drange);
			break;
		default:
			/* nothing */
			;
	}
	g_free(v);
}


void
dfvm_dump(FILE *f, GPtrArray *insns)
{
	int		id, length;
	dfvm_insn_t	*insn;
	dfvm_value_t	*arg1;
	dfvm_value_t	*arg2;
	dfvm_value_t	*arg3;
	dfvm_value_t	*arg4;

	length = insns->len;

	for (id = 0; id < length; id++) {

		insn = g_ptr_array_index(insns, id);
		arg1 = insn->arg1;
		arg2 = insn->arg2;
		arg3 = insn->arg3;
		arg4 = insn->arg4;

		switch (insn->op) {
			case CHECK_EXISTS:
				fprintf(f, "%05d CHECK_EXISTS\t%s\n",
					id, proto_registrar_get_abbrev(arg1->value.numeric));
				break;

			case READ_TREE:
				fprintf(f, "%05d READ_TREE\t\t%s -> reg#%d\n",
					id, proto_registrar_get_abbrev(arg1->value.numeric),
					arg2->value.numeric);
				break;

			case PUT_FVALUE:
				fprintf(f, "%05d PUT_FVALUE\t<%s> -> reg#%d\n",
					id, fvalue_type_name(arg1->value.fvalue),
					arg2->value.numeric);
				break;

			case MK_RANGE:
				fprintf(f, "%05d MK_RANGE\t\treg#%d[?] -> reg#%d\n",
					id,
					arg1->value.numeric,
					arg2->value.numeric);
				break;

			case ANY_EQ:
				fprintf(f, "%05d ANY_EQ\t\treg#%d == reg#%d\n",
					id, arg1->value.numeric, arg2->value.numeric);
				break;

			case ANY_NE:
				fprintf(f, "%05d ANY_NE\t\treg#%d == reg#%d\n",
					id, arg1->value.numeric, arg2->value.numeric);
				break;

			case ANY_GT:
				fprintf(f, "%05d ANY_GT\t\treg#%d == reg#%d\n",
					id, arg1->value.numeric, arg2->value.numeric);
				break;

			case ANY_GE:
				fprintf(f, "%05d ANY_GE\t\treg#%d == reg#%d\n",
					id, arg1->value.numeric, arg2->value.numeric);
				break;

			case ANY_LT:
				fprintf(f, "%05d ANY_LT\t\treg#%d == reg#%d\n",
					id, arg1->value.numeric, arg2->value.numeric);
				break;

			case ANY_LE:
				fprintf(f, "%05d ANY_LE\t\treg#%d == reg#%d\n",
					id, arg1->value.numeric, arg2->value.numeric);
				break;

			case NOT:
				fprintf(f, "%05d NOT\n", id);
				break;

			case RETURN:
				fprintf(f, "%05d RETURN\n", id);
				break;

			case IF_TRUE_GOTO:
				fprintf(f, "%05d IF-TRUE-GOTO\t%d\n",
						id, arg1->value.numeric);
				break;

			case IF_FALSE_GOTO:
				fprintf(f, "%05d IF-FALSE-GOTO\t%d\n",
						id, arg1->value.numeric);
				break;

			default:
				g_assert_not_reached();
				break;
		}
	}
}

/* Reads a field from the proto_tree and loads the fvalues into a register,
 * if that field has not already been read. */
static gboolean
read_tree(dfilter_t *df, proto_tree *tree, int field_id, int reg)
{
	GPtrArray	*finfos;
	field_info	*finfo;
	int		i, len;
	GList		*fvalues = NULL;

	/* Already loaded in this run of the dfilter? */
	if (df->attempted_load[reg]) {
		if (df->registers[reg]) {
			return TRUE;
		}
		else {
			return FALSE;
		}
	}

	df->attempted_load[reg] = TRUE;

	finfos = proto_get_finfo_ptr_array(tree, field_id);
	if (!finfos) {
		return FALSE;
	}

	len = finfos->len;
	for (i = 0; i < len; i++) {
		finfo = g_ptr_array_index(finfos, i);
		fvalues = g_list_prepend(fvalues, finfo->value);
	}
	fvalues = g_list_reverse(fvalues);

	df->registers[reg] = fvalues;
	return TRUE;
}


static gboolean
put_fvalue(dfilter_t *df, fvalue_t *fv, int reg)
{
	df->registers[reg] = g_list_append(NULL, fv);
	return TRUE;
}

typedef gboolean (*FvalueCmpFunc)(fvalue_t*, fvalue_t*);

static gboolean
any_test(dfilter_t *df, FvalueCmpFunc cmp, int reg1, int reg2)
{
	GList	*list_a, *list_b;

	list_a = df->registers[reg1];

	while (list_a) {
		list_b = df->registers[reg2];
		while (list_b) {
			if (cmp(list_a->data, list_b->data)) {
				return TRUE;
			}
			list_b = g_list_next(list_b);
		}
		list_a = g_list_next(list_a);
	}
	return FALSE;
}


/* Free the list nodes w/o freeing the memory that each
 * list node points to. */
static void
free_register_overhead(dfilter_t* df)
{
	int i;

	for (i = 0; i < df->num_registers; i++) {
		if (df->registers[i]) {
			g_list_free(df->registers[i]);
		}
	}
}

/* Takes the list of fvalue_t's in a register, uses fvalue_slice()
 * to make a new list of fvalue_t's (which are ranges, or byte-slices),
 * and puts the new list into a new register. */
static void
mk_range(dfilter_t *df, int from_reg, int to_reg, drange *drange)
{
	GList		*from_list, *to_list;
	fvalue_t	*old_fv, *new_fv;

	to_list = NULL;
	from_list = df->registers[from_reg];

	while (from_list) {
		old_fv = from_list->data;
		new_fv = fvalue_slice(old_fv, drange);
		/* Assert here because semcheck.c should have
		 * already caught the cases in which a slice
		 * cannot be made. */
		g_assert(new_fv);
		to_list = g_list_append(to_list, new_fv);

		from_list = g_list_next(from_list);
	}

	df->registers[to_reg] = to_list;
}



gboolean
dfvm_apply(dfilter_t *df, tvbuff_t *tvb, proto_tree *tree)
{
	int		i, id, length;
	gboolean	accum = TRUE;
	dfvm_insn_t	*insn;
	dfvm_value_t	*arg1;
	dfvm_value_t	*arg2;
	dfvm_value_t	*arg3;

	g_assert(tvb);
	g_assert(tree);


	/* Clear registers */
	for (i = 0; i < df->num_registers; i++) {
		df->registers[i] = NULL;
		df->attempted_load[i] = FALSE;
	}

	length = df->insns->len;

	for (id = 0; id < length; id++) {

	  AGAIN:
		insn = g_ptr_array_index(df->insns, id);
		arg1 = insn->arg1;
		arg2 = insn->arg2;

		switch (insn->op) {
			case CHECK_EXISTS:
				accum = proto_check_for_protocol_or_field(tree,
						arg1->value.numeric);
				break;

			case READ_TREE:
				accum = read_tree(df, tree,
						arg1->value.numeric, arg2->value.numeric);
				break;

			case PUT_FVALUE:
				accum = put_fvalue(df,
						arg1->value.fvalue, arg2->value.numeric);
				break;

			case MK_RANGE:
				arg3 = insn->arg3;
				mk_range(df,
						arg1->value.numeric, arg2->value.numeric,
						arg3->value.drange);
				break;

			case ANY_EQ:
				accum = any_test(df, fvalue_eq,
						arg1->value.numeric, arg2->value.numeric);
				break;

			case ANY_NE:
				accum = any_test(df, fvalue_ne,
						arg1->value.numeric, arg2->value.numeric);
				break;

			case ANY_GT:
				accum = any_test(df, fvalue_gt,
						arg1->value.numeric, arg2->value.numeric);
				break;

			case ANY_GE:
				accum = any_test(df, fvalue_ge,
						arg1->value.numeric, arg2->value.numeric);
				break;

			case ANY_LT:
				accum = any_test(df, fvalue_lt,
						arg1->value.numeric, arg2->value.numeric);
				break;

			case ANY_LE:
				accum = any_test(df, fvalue_le,
						arg1->value.numeric, arg2->value.numeric);
				break;

			case NOT:
				accum = !accum;
				break;

			case RETURN:
				free_register_overhead(df);
				return accum;

			case IF_TRUE_GOTO:
				if (accum) {
					id = arg1->value.numeric;
					goto AGAIN;
				}
				break;

			case IF_FALSE_GOTO:
				if (!accum) {
					id = arg1->value.numeric;
					goto AGAIN;
				}
				break;


			default:
				g_assert_not_reached();
				break;
		}
	}

	g_assert_not_reached();
	return FALSE; /* to appease the compiler */
}
