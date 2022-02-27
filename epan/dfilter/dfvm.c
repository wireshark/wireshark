/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "dfvm.h"

#include <ftypes/ftypes.h>
#include <wsutil/ws_assert.h>

dfvm_insn_t*
dfvm_insn_new(dfvm_opcode_t op)
{
	dfvm_insn_t	*insn;

	insn = g_new(dfvm_insn_t, 1);
	insn->op = op;
	insn->arg1 = NULL;
	insn->arg2 = NULL;
	insn->arg3 = NULL;
	insn->arg4 = NULL;
	return insn;
}

static void
dfvm_value_free(dfvm_value_t *v)
{
	switch (v->type) {
		case FVALUE:
			fvalue_free(v->value.fvalue);
			break;
		case DRANGE:
			drange_free(v->value.drange);
			break;
		case PCRE:
			ws_regex_free(v->value.pcre);
			break;
		default:
			/* nothing */
			;
	}
	g_free(v);
}

dfvm_value_t*
dfvm_value_ref(dfvm_value_t *v)
{
	if (v == NULL)
		return NULL;
	v->ref_count++;
	return v;
}

void
dfvm_value_unref(dfvm_value_t *v)
{
	ws_assert(v);
	v->ref_count--;
	if (v->ref_count > 0)
		return;
	dfvm_value_free(v);
}

void
dfvm_insn_free(dfvm_insn_t *insn)
{
	if (insn->arg1) {
		dfvm_value_unref(insn->arg1);
	}
	if (insn->arg2) {
		dfvm_value_unref(insn->arg2);
	}
	if (insn->arg3) {
		dfvm_value_unref(insn->arg3);
	}
	if (insn->arg4) {
		dfvm_value_unref(insn->arg4);
	}
	g_free(insn);
}


dfvm_value_t*
dfvm_value_new(dfvm_value_type_t type)
{
	dfvm_value_t	*v;

	v = g_new(dfvm_value_t, 1);
	v->type = type;
	v->ref_count = 0;
	return v;
}

dfvm_value_t*
dfvm_value_new_fvalue(fvalue_t *fv)
{
	dfvm_value_t *v = dfvm_value_new(FVALUE);
	v->value.fvalue = fv;
	return v;
}

dfvm_value_t*
dfvm_value_new_hfinfo(header_field_info *hfinfo)
{
	dfvm_value_t *v = dfvm_value_new(HFINFO);
	v->value.hfinfo = hfinfo;
	return v;
}

dfvm_value_t*
dfvm_value_new_register(int reg)
{
	dfvm_value_t *v = dfvm_value_new(REGISTER);
	v->value.numeric = reg;
	return v;
}

dfvm_value_t*
dfvm_value_new_drange(drange_t *dr)
{
	dfvm_value_t *v = dfvm_value_new(DRANGE);
	v->value.drange = dr;
	return v;
}

dfvm_value_t*
dfvm_value_new_funcdef(df_func_def_t *funcdef)
{
	dfvm_value_t *v = dfvm_value_new(FUNCTION_DEF);
	v->value.funcdef = funcdef;
	return v;
}

dfvm_value_t*
dfvm_value_new_pcre(ws_regex_t *re)
{
	dfvm_value_t *v = dfvm_value_new(PCRE);
	v->value.pcre = re;
	return v;
}

char *
dfvm_value_tostr(dfvm_value_t *v)
{
	char *s, *aux;

	if (!v)
		return NULL;

	switch (v->type) {
		case HFINFO:
			s = ws_strdup(v->value.hfinfo->abbrev);
			break;
		case FVALUE:
			aux = fvalue_to_debug_repr(NULL, v->value.fvalue);
			s = ws_strdup_printf("%s <%s>",
				aux, fvalue_type_name(v->value.fvalue));
			g_free(aux);
			break;
		case DRANGE:
			s = drange_tostr(v->value.drange);
			break;
		case PCRE:
			s = ws_strdup(ws_regex_pattern(v->value.pcre));
			break;
		case REGISTER:
			s = ws_strdup_printf("reg#%u", v->value.numeric);
			break;
		case FUNCTION_DEF:
			s = ws_strdup(v->value.funcdef->name);
			break;
		default:
			s = ws_strdup("FIXME");
	}
	return s;
}

void
dfvm_dump(FILE *f, dfilter_t *df)
{
	int		id, length;
	dfvm_insn_t	*insn;
	dfvm_value_t	*arg1, *arg2, *arg3, *arg4;
	char 		*arg1_str, *arg2_str, *arg3_str, *arg4_str;

	fprintf(f, "Instructions:\n");

	length = df->insns->len;
	for (id = 0; id < length; id++) {

		insn = g_ptr_array_index(df->insns, id);
		arg1 = insn->arg1;
		arg2 = insn->arg2;
		arg3 = insn->arg3;
		arg4 = insn->arg4;
		arg1_str = dfvm_value_tostr(arg1);
		arg2_str = dfvm_value_tostr(arg2);
		arg3_str = dfvm_value_tostr(arg3);
		arg4_str = dfvm_value_tostr(arg4);

		switch (insn->op) {
			case CHECK_EXISTS:
				fprintf(f, "%05d CHECK_EXISTS\t%s\n",
					id, arg1_str);
				break;

			case READ_TREE:
				fprintf(f, "%05d READ_TREE\t\t%s -> %s\n",
					id, arg1_str, arg2_str);
				break;

			case CALL_FUNCTION:
				fprintf(f, "%05d CALL_FUNCTION\t%s(",
					id, arg1_str);
				if (arg3_str) {
					fprintf(f, "%s", arg3_str);
				}
				if (arg4_str) {
					fprintf(f, ", %s", arg4_str);
				}
				fprintf(f, ") -> %s\n", arg2_str);
				break;

			case MK_RANGE:
				arg3 = insn->arg3;
				fprintf(f, "%05d MK_RANGE\t\t%s[%s] -> %s\n",
					id, arg1_str, arg2_str, arg3_str);
				break;

			case ALL_EQ:
				fprintf(f, "%05d ALL_EQ\t\t%s === %s\n",
					id, arg1_str, arg2_str);
				break;

			case ANY_EQ:
				fprintf(f, "%05d ANY_EQ\t\t%s == %s\n",
					id, arg1_str, arg2_str);
				break;

			case ALL_NE:
				fprintf(f, "%05d ALL_NE\t\t%s != %s\n",
					id, arg1_str, arg2_str);
				break;

			case ANY_NE:
				fprintf(f, "%05d ANY_NE\t\t%s !== %s\n",
					id, arg1_str, arg2_str);
				break;

			case ANY_GT:
				fprintf(f, "%05d ANY_GT\t\t%s > %s\n",
					id, arg1_str, arg2_str);
				break;

			case ANY_GE:
				fprintf(f, "%05d ANY_GE\t\t%s >= %s\n",
					id, arg1_str, arg2_str);
				break;

			case ANY_LT:
				fprintf(f, "%05d ANY_LT\t\t%s < %s\n",
					id, arg1_str, arg2_str);
				break;

			case ANY_LE:
				fprintf(f, "%05d ANY_LE\t\t%s <= %s\n",
					id, arg1_str, arg2_str);
				break;

			case MK_BITWISE_AND:
				fprintf(f, "%05d MK_BITWISE_AND\t%s & %s -> %s\n",
					id, arg1_str, arg2_str, arg3_str);
				break;

			case ANY_ZERO:
				fprintf(f, "%05d ANY_ZERO\t\t%s\n",
					id, arg1_str);
				break;

			case ALL_ZERO:
				fprintf(f, "%05d ALL_ZERO\t\t%s\n",
					id, arg1_str);
				break;

			case ANY_CONTAINS:
				fprintf(f, "%05d ANY_CONTAINS\t%s contains %s\n",
					id, arg1_str, arg2_str);
				break;

			case ANY_MATCHES:
				fprintf(f, "%05d ANY_MATCHES\t%s matches %s\n",
					id, arg1_str, arg2_str);
				break;

			case ANY_IN_RANGE:
				fprintf(f, "%05d ANY_IN_RANGE\t%s in { %s .. %s }\n",
					id, arg1_str, arg2_str, arg3_str);
				break;

			case MK_MINUS:
				fprintf(f, "%05d MK_MINUS\t\t-%s -> %s\n",
					id, arg1_str, arg2_str);
				break;

			case NOT:
				fprintf(f, "%05d NOT\n", id);
				break;

			case RETURN:
				fprintf(f, "%05d RETURN\n", id);
				break;

			case IF_TRUE_GOTO:
				fprintf(f, "%05d IF_TRUE_GOTO\t%u\n",
						id, arg1->value.numeric);
				break;

			case IF_FALSE_GOTO:
				fprintf(f, "%05d IF_FALSE_GOTO\t%u\n",
						id, arg1->value.numeric);
				break;
		}

		g_free(arg1_str);
		g_free(arg2_str);
		g_free(arg3_str);
		g_free(arg4_str);
	}
}

/* Reads a field from the proto_tree and loads the fvalues into a register,
 * if that field has not already been read. */
static gboolean
read_tree(dfilter_t *df, proto_tree *tree,
				dfvm_value_t *arg1, dfvm_value_t *arg2)
{
	GPtrArray	*finfos;
	field_info	*finfo;
	int		i, len;
	GSList		*fvalues = NULL;
	gboolean	found_something = FALSE;

	header_field_info *hfinfo = arg1->value.hfinfo;
	int reg = arg2->value.numeric;

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

	while (hfinfo) {
		finfos = proto_get_finfo_ptr_array(tree, hfinfo->id);
		if ((finfos == NULL) || (g_ptr_array_len(finfos) == 0)) {
			hfinfo = hfinfo->same_name_next;
			continue;
		}
		else {
			found_something = TRUE;
		}

		len = finfos->len;
		for (i = 0; i < len; i++) {
			finfo = g_ptr_array_index(finfos, i);
			fvalues = g_slist_prepend(fvalues, &finfo->value);
		}

		hfinfo = hfinfo->same_name_next;
	}

	if (!found_something) {
		return FALSE;
	}

	df->registers[reg] = fvalues;
	// These values are referenced only, do not try to free it later.
	df->free_registers[reg] = NULL;
	return TRUE;
}

enum match_how {
	MATCH_ANY,
	MATCH_ALL
};

typedef gboolean (*DFVMCompareFunc)(const fvalue_t*, const fvalue_t*);
typedef gboolean (*DFVMTestFunc)(const fvalue_t*);

static gboolean
cmp_test(enum match_how how, DFVMCompareFunc match_func,
					GSList *arg1, GSList *arg2)
{
	GSList *list1, *list2;
	gboolean want_all = (how == MATCH_ALL);
	gboolean want_any = (how == MATCH_ANY);
	gboolean have_match;

	list1 = arg1;

	while (list1) {
		list2 = arg2;
		while (list2) {
			have_match = match_func(list1->data, list2->data);
			if (want_all && !have_match) {
				return FALSE;
			}
			else if (want_any && have_match) {
				return TRUE;
			}
			list2 = g_slist_next(list2);
		}
		list1 = g_slist_next(list1);
	}
	/* want_all || !want_any */
	return want_all;
}

static gboolean
cmp_test_unary(enum match_how how, DFVMTestFunc test_func, GSList *arg1)
{
	GSList *list1;
	gboolean want_all = (how == MATCH_ALL);
	gboolean want_any = (how == MATCH_ANY);
	gboolean have_match;

	list1 = arg1;

	while (list1) {
		have_match = test_func(list1->data);
		if (want_all && !have_match) {
			return FALSE;
		}
		else if (want_any && have_match) {
			return TRUE;
		}
		list1 = g_slist_next(list1);
	}
	/* want_all || !want_any */
	return want_all;
}

static gboolean
any_test_unary(dfilter_t *df, DFVMTestFunc func, dfvm_value_t *arg1)
{
	ws_assert(arg1->type == REGISTER);
	GSList *list1 = df->registers[arg1->value.numeric];
	return cmp_test_unary(MATCH_ANY, func, list1);
}

static gboolean
all_test_unary(dfilter_t *df, DFVMTestFunc func, dfvm_value_t *arg1)
{
	ws_assert(arg1->type == REGISTER);
	GSList *list1 = df->registers[arg1->value.numeric];
	return cmp_test_unary(MATCH_ALL, func, list1);
}

/* cmp(A) <=> cmp(a1) OR cmp(a2) OR cmp(a3) OR ... */
static gboolean
any_test(dfilter_t *df, DFVMCompareFunc cmp,
				dfvm_value_t *arg1, dfvm_value_t *arg2)
{
	ws_assert(arg1->type == REGISTER);
	GSList *list1 = df->registers[arg1->value.numeric];

	if (arg2->type == REGISTER) {
		return cmp_test(MATCH_ANY, cmp, list1, df->registers[arg2->value.numeric]);
	}
	if (arg2->type == FVALUE) {
		GSList list2;

		list2.data = arg2->value.fvalue;
		list2.next = NULL;
		return cmp_test(MATCH_ANY, cmp, list1, &list2);
	}
	ws_assert_not_reached();
}

/* cmp(A) <=> cmp(a1) AND cmp(a2) AND cmp(a3) AND ... */
static gboolean
all_test(dfilter_t *df, DFVMCompareFunc cmp,
				dfvm_value_t *arg1, dfvm_value_t *arg2)
{
	ws_assert(arg1->type == REGISTER);
	GSList *list1 = df->registers[arg1->value.numeric];

	if (arg2->type == REGISTER) {
		return cmp_test(MATCH_ALL, cmp, list1, df->registers[arg2->value.numeric]);
	}
	if (arg2->type == FVALUE) {
		GSList list2;

		list2.data = arg2->value.fvalue;
		list2.next = NULL;
		return cmp_test(MATCH_ALL, cmp, list1, &list2);
	}
	ws_assert_not_reached();
}

static gboolean
any_matches(dfilter_t *df, dfvm_value_t *arg1, dfvm_value_t *arg2)
{
	GSList *list1 = df->registers[arg1->value.numeric];
	ws_regex_t *re = arg2->value.pcre;

	while (list1) {
		if (fvalue_matches(list1->data, re)) {
			return TRUE;
		}
		list1 = g_slist_next(list1);
	}
	return FALSE;
}

static gboolean
any_in_range(dfilter_t *df, dfvm_value_t *arg1,
				dfvm_value_t *arg_low, dfvm_value_t *arg_high)
{
	GSList *list1 = df->registers[arg1->value.numeric];
	fvalue_t *low = arg_low->value.fvalue;
	fvalue_t *high = arg_high->value.fvalue;

	while (list1) {
		if (fvalue_ge(list1->data, low) &&
					fvalue_le(list1->data, high)) {
			return TRUE;
		}
		list1 = g_slist_next(list1);
	}
	return FALSE;
}

/* Clear registers that were populated during evaluation.
 * If we created the values, then these will be freed as well. */
static void
free_register_overhead(dfilter_t* df)
{
	guint i;

	for (i = 0; i < df->num_registers; i++) {
		df->attempted_load[i] = FALSE;
		if (df->registers[i]) {
			if (df->free_registers[i]) {
				for (GSList *l = df->registers[i]; l != NULL; l = l->next) {
					df->free_registers[i](l->data);
				}
				df->free_registers[i] = NULL;
			}
			g_slist_free(df->registers[i]);
			df->registers[i] = NULL;
		}
	}
}

/* Takes the list of fvalue_t's in a register, uses fvalue_slice()
 * to make a new list of fvalue_t's (which are ranges, or byte-slices),
 * and puts the new list into a new register. */
static void
mk_range(dfilter_t *df, dfvm_value_t *from_arg, dfvm_value_t *to_arg,
						dfvm_value_t *drange_arg)
{
	GSList		*from_list, *to_list;
	fvalue_t	*old_fv, *new_fv;

	to_list = NULL;
	from_list = df->registers[from_arg->value.numeric];
	drange_t *drange = drange_arg->value.drange;

	while (from_list) {
		old_fv = from_list->data;
		new_fv = fvalue_slice(old_fv, drange);
		/* Assert here because semcheck.c should have
		 * already caught the cases in which a slice
		 * cannot be made. */
		ws_assert(new_fv);
		to_list = g_slist_prepend(to_list, new_fv);

		from_list = g_slist_next(from_list);
	}

	df->registers[to_arg->value.numeric] = to_list;
	df->free_registers[to_arg->value.numeric] = (GDestroyNotify)fvalue_free;
}

static gboolean
call_function(dfilter_t *df, dfvm_value_t *arg1, dfvm_value_t *arg2,
				dfvm_value_t *arg3, dfvm_value_t *arg4)
{
	df_func_def_t *funcdef;
	GSList *param1 = NULL;
	GSList *param2 = NULL;
	GSList *retval = NULL;
	gboolean accum;

	funcdef = arg1->value.funcdef;
	if (arg3) {
		param1 = df->registers[arg3->value.numeric];
	}
	if (arg4) {
		param2 = df->registers[arg4->value.numeric];
	}
	accum = funcdef->function(param1, param2, &retval);

	df->registers[arg2->value.numeric] = retval;
	// functions create a new value, so own it.
	df->free_registers[arg2->value.numeric] = (GDestroyNotify)fvalue_free;
	return accum;
}

static void debug_op_error(fvalue_t *v1, fvalue_t *v2, const char *op, const char *msg)
{
	char *s1 = fvalue_to_debug_repr(NULL, v1);
	char *s2 = fvalue_to_debug_repr(NULL, v2);
	ws_noisy("Error: %s %s %s: %s", s1, op, s2, msg);
	g_free(s1);
	g_free(s2);
}


typedef fvalue_t* (*DFVMBitwiseFunc)(const fvalue_t*, const fvalue_t*, char **);

static void
mk_bitwise_internal(DFVMBitwiseFunc func,
			GSList *arg1, GSList *arg2, GSList **retval)
{
	GSList *list1, *list2;
	GSList *to_list = NULL;
	fvalue_t *val1, *val2;
	fvalue_t *result;
	char *err_msg = NULL;

	list1 = arg1;
	while (list1) {
		list2 = arg2;
		while (list2) {
			val1 = list1->data;
			val2 = list2->data;
			result = func(val1, val2, &err_msg);
			if (result == NULL) {
				debug_op_error(val1, val2, "&", err_msg);
				g_free(err_msg);
				err_msg = NULL;
			}
			else {
				to_list = g_slist_prepend(to_list, result);
			}
			list2 = g_slist_next(list2);
		}
		list1 = g_slist_next(list1);
	}
	*retval = to_list;
}

static void
mk_bitwise(dfilter_t *df, DFVMBitwiseFunc func,
		dfvm_value_t *arg1, dfvm_value_t *arg2, dfvm_value_t *to_arg)
{
	ws_assert(arg1->type == REGISTER);
	GSList *list1 = df->registers[arg1->value.numeric];
	GSList *result = NULL;

	if (arg2->type == REGISTER) {
		GSList *list2 = df->registers[arg2->value.numeric];

		mk_bitwise_internal(func, list1, list2, &result);
	}
	else if (arg2->type == FVALUE) {
		GSList list2;

		list2.data = arg2->value.fvalue;
		list2.next = NULL;
		mk_bitwise_internal(func, list1, &list2, &result);
	}
	else {
		ws_assert_not_reached();
	}
	df->registers[to_arg->value.numeric] = result;
	df->free_registers[to_arg->value.numeric] = (GDestroyNotify)fvalue_free;
}

static void
mk_minus_internal(GSList *arg1, GSList **retval)
{
	GSList *list1;
	GSList *to_list = NULL;
	fvalue_t *val1;
	fvalue_t *result;
	char *err_msg = NULL;

	list1 = arg1;
	while (list1) {
		val1 = list1->data;
		result = fvalue_unary_minus(val1, &err_msg);
		if (result == NULL) {
			ws_noisy("unary_minus: %s", err_msg);
			g_free(err_msg);
			err_msg = NULL;
		}
		else {
			to_list = g_slist_prepend(to_list, result);
		}
		list1 = g_slist_next(list1);
	}
	*retval = to_list;
}

static void
mk_minus(dfilter_t *df, dfvm_value_t *arg1, dfvm_value_t *to_arg)
{
	ws_assert(arg1->type == REGISTER);
	GSList *list1 = df->registers[arg1->value.numeric];
	GSList *result = NULL;

	mk_minus_internal(list1, &result);

	df->registers[to_arg->value.numeric] = result;
	df->free_registers[to_arg->value.numeric] = (GDestroyNotify)fvalue_free;
}

gboolean
dfvm_apply(dfilter_t *df, proto_tree *tree)
{
	int		id, length;
	gboolean	accum = TRUE;
	dfvm_insn_t	*insn;
	dfvm_value_t	*arg1;
	dfvm_value_t	*arg2;
	dfvm_value_t	*arg3 = NULL;
	dfvm_value_t	*arg4 = NULL;
	header_field_info	*hfinfo;

	ws_assert(tree);

	length = df->insns->len;

	for (id = 0; id < length; id++) {

	  AGAIN:
		insn = g_ptr_array_index(df->insns, id);
		arg1 = insn->arg1;
		arg2 = insn->arg2;
		arg3 = insn->arg3;
		arg4 = insn->arg4;

		switch (insn->op) {
			case CHECK_EXISTS:
				hfinfo = arg1->value.hfinfo;
				while(hfinfo) {
					accum = proto_check_for_protocol_or_field(tree,
							hfinfo->id);
					if (accum) {
						break;
					}
					else {
						hfinfo = hfinfo->same_name_next;
					}
				}
				break;

			case READ_TREE:
				accum = read_tree(df, tree, arg1, arg2);
				break;

			case CALL_FUNCTION:
				accum = call_function(df, arg1, arg2, arg3, arg4);
				break;

			case MK_RANGE:
				mk_range(df, arg1, arg2, arg3);
				break;

			case ALL_EQ:
				accum = all_test(df, fvalue_eq, arg1, arg2);
				break;

			case ANY_EQ:
				accum = any_test(df, fvalue_eq, arg1, arg2);
				break;

			case ALL_NE:
				accum = all_test(df, fvalue_ne, arg1, arg2);
				break;

			case ANY_NE:
				accum = any_test(df, fvalue_ne, arg1, arg2);
				break;

			case ANY_GT:
				accum = any_test(df, fvalue_gt, arg1, arg2);
				break;

			case ANY_GE:
				accum = any_test(df, fvalue_ge, arg1, arg2);
				break;

			case ANY_LT:
				accum = any_test(df, fvalue_lt, arg1, arg2);
				break;

			case ANY_LE:
				accum = any_test(df, fvalue_le, arg1, arg2);
				break;

			case MK_BITWISE_AND:
				mk_bitwise(df, fvalue_bitwise_and, arg1, arg2, arg3);
				break;

			case ANY_ZERO:
				accum = any_test_unary(df, fvalue_is_zero, arg1);
				break;

			case ALL_ZERO:
				accum = all_test_unary(df, fvalue_is_zero, arg1);
				break;

			case ANY_CONTAINS:
				accum = any_test(df, fvalue_contains, arg1, arg2);
				break;

			case ANY_MATCHES:
				accum = any_matches(df, arg1, arg2);
				break;

			case ANY_IN_RANGE:
				accum = any_in_range(df, arg1, arg2, arg3);
				break;

			case MK_MINUS:
				mk_minus(df, arg1, arg2);
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
		}
	}

	ws_assert_not_reached();
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
