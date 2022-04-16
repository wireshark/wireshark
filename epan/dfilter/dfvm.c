/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_DFILTER

#include "dfvm.h"

#include <ftypes/ftypes.h>
#include <wsutil/ws_assert.h>

static void
debug_register(GSList *reg, guint32 num);

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
			s = ws_strdup_printf("reg#%"G_GUINT32_FORMAT, v->value.numeric);
			break;
		case FUNCTION_DEF:
			s = ws_strdup(v->value.funcdef->name);
			break;
		case INTEGER:
			s = ws_strdup_printf("%"G_GUINT32_FORMAT, v->value.numeric);
			break;
		default:
			s = ws_strdup("FIXME");
	}
	return s;
}

char *
dfvm_dump_str(wmem_allocator_t *alloc, dfilter_t *df, gboolean print_references)
{
	int		id, length;
	dfvm_insn_t	*insn;
	dfvm_value_t	*arg1, *arg2, *arg3, *arg4;
	char 		*arg1_str, *arg2_str, *arg3_str, *arg4_str;
	wmem_strbuf_t	*buf;
	GHashTableIter	ref_iter;
	gpointer	key, value;
	char		*str;

	buf = wmem_strbuf_new(alloc, NULL);

	wmem_strbuf_append(buf, "Instructions:\n");

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
				wmem_strbuf_append_printf(buf, "%05d CHECK_EXISTS\t%s\n",
					id, arg1_str);
				break;

			case READ_TREE:
				wmem_strbuf_append_printf(buf, "%05d READ_TREE\t\t%s -> %s\n",
					id, arg1_str, arg2_str);
				break;

			case READ_REFERENCE:
				wmem_strbuf_append_printf(buf, "%05d READ_REFERENCE\t${%s} -> %s\n",
					id, arg1_str, arg2_str);
				break;

			case PUT_FVALUE:
				wmem_strbuf_append_printf(buf, "%05d PUT_FVALUE\t%s -> %s\n",
					id, arg1_str, arg2_str);
				break;

			case CALL_FUNCTION:
				wmem_strbuf_append_printf(buf, "%05d CALL_FUNCTION\t%s(",
					id, arg1_str);
				if (arg3_str) {
					wmem_strbuf_append_printf(buf, "%s", arg3_str);
				}
				for (guint32 i = 1; i <= arg4->value.numeric; i++) {
					wmem_strbuf_append_printf(buf, ", reg#%"G_GUINT32_FORMAT,
									arg3->value.numeric + i);
				}
				wmem_strbuf_append_printf(buf, ") -> %s\n", arg2_str);
				break;

			case MK_RANGE:
				wmem_strbuf_append_printf(buf, "%05d MK_RANGE\t\t%s[%s] -> %s\n",
					id, arg1_str, arg3_str, arg2_str);
				break;

			case ALL_EQ:
				wmem_strbuf_append_printf(buf, "%05d ALL_EQ\t\t%s === %s\n",
					id, arg1_str, arg2_str);
				break;

			case ANY_EQ:
				wmem_strbuf_append_printf(buf, "%05d ANY_EQ\t\t%s == %s\n",
					id, arg1_str, arg2_str);
				break;

			case ALL_NE:
				wmem_strbuf_append_printf(buf, "%05d ALL_NE\t\t%s != %s\n",
					id, arg1_str, arg2_str);
				break;

			case ANY_NE:
				wmem_strbuf_append_printf(buf, "%05d ANY_NE\t\t%s !== %s\n",
					id, arg1_str, arg2_str);
				break;

			case ANY_GT:
				wmem_strbuf_append_printf(buf, "%05d ANY_GT\t\t%s > %s\n",
					id, arg1_str, arg2_str);
				break;

			case ANY_GE:
				wmem_strbuf_append_printf(buf, "%05d ANY_GE\t\t%s >= %s\n",
					id, arg1_str, arg2_str);
				break;

			case ANY_LT:
				wmem_strbuf_append_printf(buf, "%05d ANY_LT\t\t%s < %s\n",
					id, arg1_str, arg2_str);
				break;

			case ANY_LE:
				wmem_strbuf_append_printf(buf, "%05d ANY_LE\t\t%s <= %s\n",
					id, arg1_str, arg2_str);
				break;

			case MK_BITWISE_AND:
				wmem_strbuf_append_printf(buf, "%05d MK_BITWISE_AND\t%s & %s -> %s\n",
					id, arg1_str, arg2_str, arg3_str);
				break;

			case ANY_ZERO:
				wmem_strbuf_append_printf(buf, "%05d ANY_ZERO\t\t%s\n",
					id, arg1_str);
				break;

			case ALL_ZERO:
				wmem_strbuf_append_printf(buf, "%05d ALL_ZERO\t\t%s\n",
					id, arg1_str);
				break;

			case DFVM_ADD:
				wmem_strbuf_append_printf(buf, "%05d ADD\t\t%s + %s -> %s\n",
					id, arg1_str, arg2_str, arg3_str);
				break;

			case DFVM_SUBTRACT:
				wmem_strbuf_append_printf(buf, "%05d SUBRACT\t\t%s - %s -> %s\n",
					id, arg1_str, arg2_str, arg3_str);
				break;

			case DFVM_MULTIPLY:
				wmem_strbuf_append_printf(buf, "%05d MULTIPLY\t\t%s * %s -> %s\n",
					id, arg1_str, arg2_str, arg3_str);
				break;

			case DFVM_DIVIDE:
				wmem_strbuf_append_printf(buf, "%05d DIVIDE\t\t%s / %s -> %s\n",
					id, arg1_str, arg2_str, arg3_str);
				break;

			case DFVM_MODULO:
				wmem_strbuf_append_printf(buf, "%05d MODULO\t\t%s %% %s -> %s\n",
					id, arg1_str, arg2_str, arg3_str);
				break;

			case ANY_CONTAINS:
				wmem_strbuf_append_printf(buf, "%05d ANY_CONTAINS\t%s contains %s\n",
					id, arg1_str, arg2_str);
				break;

			case ANY_MATCHES:
				wmem_strbuf_append_printf(buf, "%05d ANY_MATCHES\t%s matches %s\n",
					id, arg1_str, arg2_str);
				break;

			case ANY_IN_RANGE:
				wmem_strbuf_append_printf(buf, "%05d ANY_IN_RANGE\t%s in { %s .. %s }\n",
					id, arg1_str, arg2_str, arg3_str);
				break;

			case MK_MINUS:
				wmem_strbuf_append_printf(buf, "%05d MK_MINUS\t\t-%s -> %s\n",
					id, arg1_str, arg2_str);
				break;

			case NOT:
				wmem_strbuf_append_printf(buf, "%05d NOT\n", id);
				break;

			case RETURN:
				wmem_strbuf_append_printf(buf, "%05d RETURN\n", id);
				break;

			case IF_TRUE_GOTO:
				wmem_strbuf_append_printf(buf, "%05d IF_TRUE_GOTO\t%u\n",
						id, arg1->value.numeric);
				break;

			case IF_FALSE_GOTO:
				wmem_strbuf_append_printf(buf, "%05d IF_FALSE_GOTO\t%u\n",
						id, arg1->value.numeric);
				break;
		}

		g_free(arg1_str);
		g_free(arg2_str);
		g_free(arg3_str);
		g_free(arg4_str);
	}

	if (print_references && g_hash_table_size(df->references) > 0) {
		wmem_strbuf_append(buf, "\nReferences:\n");
		g_hash_table_iter_init(&ref_iter, df->references);
		while (g_hash_table_iter_next(&ref_iter, &key, &value)) {
			const char *abbrev = ((header_field_info *)key)->abbrev;
			GSList *fvalues = *(GSList **)value;

			wmem_strbuf_append_printf(buf, "${%s} = {", abbrev);

			if (fvalues != NULL) {
				str = fvalue_to_debug_repr(NULL, fvalues->data);
				wmem_strbuf_append_printf(buf, "%s <%s>", str, fvalue_type_name(fvalues->data));
				g_free(str);

				for (fvalues = fvalues->next; fvalues != NULL; fvalues = fvalues->next) {
					str = fvalue_to_debug_repr(NULL, fvalues->data);
					wmem_strbuf_append_printf(buf, ", %s <%s>", str, fvalue_type_name(fvalues->data));
					g_free(str);
				}
			}
			wmem_strbuf_append(buf, "}\n");
		}
	}

	return wmem_strbuf_finalize(buf);
}

void
dfvm_dump(FILE *f, dfilter_t *df)
{
	char *str = dfvm_dump_str(NULL, df, FALSE);
	fputs(str, f);
	wmem_free(NULL, str);
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

static gboolean
read_reference(dfilter_t *df, dfvm_value_t *arg1, dfvm_value_t *arg2)
{
	GSList		**fvalues_ptr;

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

	fvalues_ptr = g_hash_table_lookup(df->references, hfinfo);
	if (*fvalues_ptr == NULL) {
		df->registers[reg] = NULL;
		return FALSE;
	}

	/* Shallow copy */
	df->registers[reg] = g_slist_copy(*fvalues_ptr);
	/* These values are referenced only, do not try to free it later. */
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

/*
 * arg1: function def
 * arg2: return register
 * arg3: first input register
 * arg4: number of input registers after first
 */
static gboolean
call_function(dfilter_t *df, dfvm_value_t *arg1, dfvm_value_t *arg2,
				dfvm_value_t *arg3, dfvm_value_t *arg4)
{
	df_func_def_t *funcdef;
	GSList *retval = NULL;
	gboolean accum;
	guint32 reg_return, reg_first_arg, more_args_count;

	funcdef = arg1->value.funcdef;
	reg_return = arg2->value.numeric;
	reg_first_arg = arg3->value.numeric;
	more_args_count = arg4->value.numeric;

	accum = funcdef->function(&df->registers[reg_first_arg], 1 + more_args_count, &retval);

	/* Write return registers. */
	df->registers[reg_return] = retval;
	// functions create a new value, so own it.
	df->free_registers[reg_return] = (GDestroyNotify)fvalue_free;
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

/* Used for temporary debugging only, don't leave in production code (at
 * a minimum WS_DEBUG_HERE must be replaced by another log level). */
static void _U_
debug_register(GSList *reg, guint32 num)
{
	wmem_strbuf_t *buf;
	GSList *l;
	char *s;

	buf = wmem_strbuf_new(NULL, NULL);

	wmem_strbuf_append_printf(buf, "Reg#%"G_GUINT32_FORMAT" = { ", num);
	for (l = reg; l != NULL; l = l->next) {
		s = fvalue_to_debug_repr(NULL, l->data);
		wmem_strbuf_append(buf, s);
		g_free(s);
		wmem_strbuf_append_c(buf, ' ');
	}
	wmem_strbuf_append_c(buf, '}');
	WS_DEBUG_HERE("%s", wmem_strbuf_get_str(buf));
	wmem_strbuf_destroy(buf);
}


typedef fvalue_t* (*DFVMBinaryFunc)(const fvalue_t*, const fvalue_t*, char **);

static void
mk_binary_internal(DFVMBinaryFunc func,
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
mk_binary(dfilter_t *df, DFVMBinaryFunc func,
		dfvm_value_t *arg1, dfvm_value_t *arg2, dfvm_value_t *to_arg)
{
	GSList ls1, ls2;
	GSList *list1, *list2;
	GSList *result = NULL;

	if (arg1->type == REGISTER) {
		list1 = df->registers[arg1->value.numeric];
	}
	else if (arg1->type == FVALUE) {
		ls1.data = arg1->value.fvalue;
		ls1.next = NULL;
		list1 = &ls1;
	}
	else {
		ws_assert_not_reached();
	}

	if (arg2->type == REGISTER) {
		list2 = df->registers[arg2->value.numeric];
	}
	else if (arg2->type == FVALUE) {
		ls2.data = arg2->value.fvalue;
		ls2.next = NULL;
		list2 = &ls2;
	}
	else {
		ws_assert_not_reached();
	}

	mk_binary_internal(func, list1, list2, &result);
	//debug_register(result, to_arg->value.numeric);

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

static void
put_fvalue(dfilter_t *df, dfvm_value_t *arg1, dfvm_value_t *to_arg)
{
	fvalue_t *fv = arg1->value.fvalue;
	df->registers[to_arg->value.numeric] = g_slist_append(NULL, fv);

	/* Memory is owned by the dfvm_value_t. */
	df->free_registers[to_arg->value.numeric] = NULL;
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

			case READ_REFERENCE:
				accum = read_reference(df, arg1, arg2);
				break;

			case PUT_FVALUE:
				put_fvalue(df, arg1, arg2);
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
				mk_binary(df, fvalue_bitwise_and, arg1, arg2, arg3);
				break;

			case DFVM_ADD:
				mk_binary(df, fvalue_add, arg1, arg2, arg3);
				break;

			case DFVM_SUBTRACT:
				mk_binary(df, fvalue_subtract, arg1, arg2, arg3);
				break;

			case DFVM_MULTIPLY:
				mk_binary(df, fvalue_multiply, arg1, arg2, arg3);
				break;

			case DFVM_DIVIDE:
				mk_binary(df, fvalue_divide, arg1, arg2, arg3);
				break;

			case DFVM_MODULO:
				mk_binary(df, fvalue_modulo, arg1, arg2, arg3);
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
