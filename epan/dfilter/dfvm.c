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

const char *
dfvm_opcode_tostr(dfvm_opcode_t code)
{
	switch (code) {
		case DFVM_IF_TRUE_GOTO:		return "IF_TRUE_GOTO";
		case DFVM_IF_FALSE_GOTO:	return "IF_FALSE_GOTO";
		case DFVM_CHECK_EXISTS:		return "CHECK_EXISTS";
		case DFVM_CHECK_EXISTS_R:	return "CHECK_EXISTS_R";
		case DFVM_NOT:			return "NOT";
		case DFVM_RETURN:		return "RETURN";
		case DFVM_READ_TREE:		return "READ_TREE";
		case DFVM_READ_TREE_R:		return "READ_TREE_R";
		case DFVM_READ_REFERENCE:	return "READ_REFERENCE";
		case DFVM_READ_REFERENCE_R:	return "READ_REFERENCE_R";
		case DFVM_PUT_FVALUE:		return "PUT_FVALUE";
		case DFVM_ALL_EQ:		return "ALL_EQ";
		case DFVM_ANY_EQ:		return "ANY_EQ";
		case DFVM_ALL_NE:		return "ALL_NE";
		case DFVM_ANY_NE:		return "ANY_NE";
		case DFVM_ALL_GT:		return "ALL_GT";
		case DFVM_ANY_GT:		return "ANY_GT";
		case DFVM_ALL_GE:		return "ALL_GE";
		case DFVM_ANY_GE:		return "ANY_GE";
		case DFVM_ALL_LT:		return "ALL_LT";
		case DFVM_ANY_LT:		return "ANY_LT";
		case DFVM_ALL_LE:		return "ALL_LE";
		case DFVM_ANY_LE:		return "ANY_LE";
		case DFVM_ALL_CONTAINS:		return "ALL_CONTAINS";
		case DFVM_ANY_CONTAINS:		return "ANY_CONTAINS";
		case DFVM_ALL_MATCHES:		return "ALL_MATCHES";
		case DFVM_ANY_MATCHES:		return "ANY_MATCHES";
		case DFVM_ALL_IN_RANGE:		return "ALL_IN_RANGE";
		case DFVM_ANY_IN_RANGE:		return "ANY_IN_RANGE";
		case DFVM_SLICE:		return "SLICE";
		case DFVM_LENGTH:		return "LENGTH";
		case DFVM_BITWISE_AND:		return "BITWISE_AND";
		case DFVM_UNARY_MINUS:		return "UNARY_MINUS";
		case DFVM_ADD:			return "ADD";
		case DFVM_SUBTRACT:		return "SUBTRACT";
		case DFVM_MULTIPLY:		return "MULTIPLY";
		case DFVM_DIVIDE:		return "DIVIDE";
		case DFVM_MODULO:		return "MODULO";
		case DFVM_CALL_FUNCTION:	return "CALL_FUNCTION";
		case DFVM_STACK_PUSH:		return "STACK_PUSH";
		case DFVM_STACK_POP:		return "STACK_POP";
		case DFVM_NOT_ALL_ZERO:		return "NOT_ALL_ZERO";
	}
	return "(fix-opcode-string)";
}

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

dfvm_value_t*
dfvm_value_new_guint(guint num)
{
	dfvm_value_t *v = dfvm_value_new(INTEGER);
	v->value.numeric = num;
	return v;
}

static char *
dfvm_value_tostr(dfvm_value_t *v)
{
	char *s, *aux;

	if (!v)
		return NULL;

	switch (v->type) {
		case HFINFO:
			s = ws_strdup_printf("%s <%s>",
					v->value.hfinfo->abbrev,
					ftype_name(v->value.hfinfo->type));
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

static GSList *
dump_str_stack_push(GSList *stack, const char *str)
{
	return g_slist_prepend(stack, g_strdup(str));
}

static GSList *
dump_str_stack_pop(GSList *stack)
{
	if (!stack) {
		return NULL;
	}

	char *str;

	str = stack->data;
	stack = g_slist_delete_link(stack, stack);
	g_free(str);
	return stack;
}

char *
dfvm_dump_str(wmem_allocator_t *alloc, dfilter_t *df, gboolean print_references)
{
	int		id, length;
	dfvm_insn_t	*insn;
	dfvm_value_t	*arg1, *arg2, *arg3;
	char 		*arg1_str, *arg2_str, *arg3_str;
	const char	*opcode_str;
	wmem_strbuf_t	*buf;
	GHashTableIter	ref_iter;
	gpointer	key, value;
	char		*str;
	GSList		*stack_print = NULL, *l;
	guint		i;

	buf = wmem_strbuf_new(alloc, NULL);

	wmem_strbuf_append(buf, "Instructions:\n");

	length = df->insns->len;
	for (id = 0; id < length; id++) {

		insn = g_ptr_array_index(df->insns, id);
		arg1 = insn->arg1;
		arg2 = insn->arg2;
		arg3 = insn->arg3;
		arg1_str = dfvm_value_tostr(arg1);
		arg2_str = dfvm_value_tostr(arg2);
		arg3_str = dfvm_value_tostr(arg3);
		opcode_str = dfvm_opcode_tostr(insn->op);

		switch (insn->op) {
			case DFVM_CHECK_EXISTS:
			case DFVM_CHECK_EXISTS_R:
				wmem_strbuf_append_printf(buf, "%05d %s\t%s\n",
					id, opcode_str, arg1_str);
				break;

			case DFVM_READ_TREE:
			case DFVM_READ_TREE_R:
				wmem_strbuf_append_printf(buf, "%05d %s\t\t%s -> %s\n",
					id, opcode_str, arg1_str, arg2_str);
				break;

			case DFVM_READ_REFERENCE:
			case DFVM_READ_REFERENCE_R:
				wmem_strbuf_append_printf(buf, "%05d %s\t${%s} -> %s\n",
					id, opcode_str, arg1_str, arg2_str);
				break;

			case DFVM_PUT_FVALUE:
				wmem_strbuf_append_printf(buf, "%05d %s\t%s -> %s\n",
					id, opcode_str, arg1_str, arg2_str);
				break;

			case DFVM_CALL_FUNCTION:
				wmem_strbuf_append_printf(buf, "%05d %s\t%s(",
					id, opcode_str, arg1_str);
				for (l = stack_print, i = 0; i < arg3->value.numeric; i++, l = l->next) {
					if (l != stack_print) {
						wmem_strbuf_append(buf, ", ");
					}
					wmem_strbuf_append(buf, l->data);
				}
				wmem_strbuf_append_printf(buf, ") -> %s\n", arg2_str);
				break;

			case DFVM_STACK_PUSH:
				wmem_strbuf_append_printf(buf, "%05d %s\t%s\n",
					id, opcode_str, arg1_str);
				stack_print = dump_str_stack_push(stack_print, arg1_str);
				break;

			case DFVM_STACK_POP:
				wmem_strbuf_append_printf(buf, "%05d %s\t%s\n",
					id, opcode_str, arg1_str);
				for (i = 0; i < arg1->value.numeric; i ++) {
					stack_print = dump_str_stack_pop(stack_print);
				}
				break;

			case DFVM_SLICE:
				wmem_strbuf_append_printf(buf, "%05d %s\t\t%s[%s] -> %s\n",
					id, opcode_str, arg1_str, arg3_str, arg2_str);
				break;

			case DFVM_LENGTH:
				wmem_strbuf_append_printf(buf, "%05d %s\t\t%s -> %s\n",
					id, opcode_str, arg1_str, arg2_str);
				break;

			case DFVM_ALL_EQ:
				wmem_strbuf_append_printf(buf, "%05d %s\t\t%s === %s\n",
					id, opcode_str, arg1_str, arg2_str);
				break;

			case DFVM_ANY_EQ:
				wmem_strbuf_append_printf(buf, "%05d %s\t\t%s == %s\n",
					id, opcode_str, arg1_str, arg2_str);
				break;

			case DFVM_ALL_NE:
				wmem_strbuf_append_printf(buf, "%05d %s\t\t%s != %s\n",
					id, opcode_str, arg1_str, arg2_str);
				break;

			case DFVM_ANY_NE:
				wmem_strbuf_append_printf(buf, "%05d %s\t\t%s !== %s\n",
					id, opcode_str, arg1_str, arg2_str);
				break;

			case DFVM_ALL_GT:
			case DFVM_ANY_GT:
				wmem_strbuf_append_printf(buf, "%05d %s\t\t%s > %s\n",
					id, opcode_str, arg1_str, arg2_str);
				break;

			case DFVM_ALL_GE:
			case DFVM_ANY_GE:
				wmem_strbuf_append_printf(buf, "%05d %s\t\t%s >= %s\n",
					id, opcode_str, arg1_str, arg2_str);
				break;

			case DFVM_ALL_LT:
			case DFVM_ANY_LT:
				wmem_strbuf_append_printf(buf, "%05d %s\t\t%s < %s\n",
					id, opcode_str, arg1_str, arg2_str);
				break;

			case DFVM_ALL_LE:
			case DFVM_ANY_LE:
				wmem_strbuf_append_printf(buf, "%05d %s\t\t%s <= %s\n",
					id, opcode_str, arg1_str, arg2_str);
				break;

			case DFVM_NOT_ALL_ZERO:
				wmem_strbuf_append_printf(buf, "%05d %s\t%s\n",
					id, opcode_str, arg1_str);
				break;

			case DFVM_ALL_CONTAINS:
			case DFVM_ANY_CONTAINS:
				wmem_strbuf_append_printf(buf, "%05d %s\t%s contains %s\n",
					id, opcode_str, arg1_str, arg2_str);
				break;

			case DFVM_ALL_MATCHES:
			case DFVM_ANY_MATCHES:
				wmem_strbuf_append_printf(buf, "%05d %s\t%s matches %s\n",
					id, opcode_str, arg1_str, arg2_str);
				break;

			case DFVM_ALL_IN_RANGE:
			case DFVM_ANY_IN_RANGE:
				wmem_strbuf_append_printf(buf, "%05d %s\t%s in { %s .. %s }\n",
					id, opcode_str,
					arg1_str, arg2_str, arg3_str);
				break;

			case DFVM_BITWISE_AND:
				wmem_strbuf_append_printf(buf, "%05d %s\t%s & %s -> %s\n",
					id, opcode_str, arg1_str, arg2_str, arg3_str);
				break;

			case DFVM_UNARY_MINUS:
				wmem_strbuf_append_printf(buf, "%05d %s\t\t-%s -> %s\n",
					id, opcode_str, arg1_str, arg2_str);
				break;

			case DFVM_ADD:
				wmem_strbuf_append_printf(buf, "%05d %s\t\t%s + %s -> %s\n",
					id, opcode_str, arg1_str, arg2_str, arg3_str);
				break;

			case DFVM_SUBTRACT:
				wmem_strbuf_append_printf(buf, "%05d %s\t\t%s - %s -> %s\n",
					id, opcode_str, arg1_str, arg2_str, arg3_str);
				break;

			case DFVM_MULTIPLY:
				wmem_strbuf_append_printf(buf, "%05d %s\t\t%s * %s -> %s\n",
					id, opcode_str, arg1_str, arg2_str, arg3_str);
				break;

			case DFVM_DIVIDE:
				wmem_strbuf_append_printf(buf, "%05d %s\t\t%s / %s -> %s\n",
					id, opcode_str, arg1_str, arg2_str, arg3_str);
				break;

			case DFVM_MODULO:
				wmem_strbuf_append_printf(buf, "%05d %s\t\t%s %% %s -> %s\n",
					id, opcode_str, arg1_str, arg2_str, arg3_str);
				break;

			case DFVM_NOT:
				wmem_strbuf_append_printf(buf, "%05d NOT\n", id);
				break;

			case DFVM_RETURN:
				wmem_strbuf_append_printf(buf, "%05d RETURN\n", id);
				break;

			case DFVM_IF_TRUE_GOTO:
			case DFVM_IF_FALSE_GOTO:
				wmem_strbuf_append_printf(buf, "%05d %s\t%u\n",
						id, opcode_str, arg1->value.numeric);
				break;
		}

		g_free(arg1_str);
		g_free(arg2_str);
		g_free(arg3_str);
	}

	if (print_references && g_hash_table_size(df->references) > 0) {
		wmem_strbuf_append(buf, "\nReferences:\n");
		g_hash_table_iter_init(&ref_iter, df->references);
		while (g_hash_table_iter_next(&ref_iter, &key, &value)) {
			const char *abbrev = ((header_field_info *)key)->abbrev;
			GPtrArray *refs_array = value;
			df_reference_t *ref;

			wmem_strbuf_append_printf(buf, "${%s} = {", abbrev);
			for (i = 0; i < refs_array->len; i++) {
				if (i != 0) {
					wmem_strbuf_append(buf, ", ");
				}
				ref = refs_array->pdata[i];
				str = fvalue_to_debug_repr(NULL, ref->value);
				wmem_strbuf_append_printf(buf, "%s <%s>", str, fvalue_type_name(ref->value));
				g_free(str);
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

static int
compare_finfo_layer(gconstpointer _a, gconstpointer _b)
{
	const field_info *a = *(const field_info **)_a;
	const field_info *b = *(const field_info **)_b;
	return a->proto_layer_num - b->proto_layer_num;
}

static gboolean
drange_contains_layer(drange_t *dr, int num, int length)
{
	drange_node *rn;
	GSList *list = dr->range_list;
	int lower, upper;

	while (list) {
		rn = list->data;
		lower = rn->start_offset;
		if (lower < 0) {
			lower += length + 1;
		}
		if (rn->ending == DRANGE_NODE_END_T_LENGTH) {
			upper = lower + rn->length - 1;
		}
		else if (rn->ending == DRANGE_NODE_END_T_OFFSET) {
			upper = rn->end_offset;
		}
		else if (rn->ending == DRANGE_NODE_END_T_TO_THE_END) {
			upper = INT_MAX;
		}
		else {
			ws_assert_not_reached();
		}

		if (num >= lower && num <= upper) {  /* inclusive */
			return TRUE;
		}

		list = g_slist_next(list);
	}
	return FALSE;
}

static GSList *
filter_finfo_fvalues(GSList *fvalues, GPtrArray *finfos, drange_t *range)
{
	int length; /* maximum proto layer number. The numbers are sequential. */
	field_info *last_finfo, *finfo;
	int cookie = -1;
	gboolean cookie_matches = false;
	int layer;

	g_ptr_array_sort(finfos, compare_finfo_layer);
	last_finfo = finfos->pdata[finfos->len - 1];
	length = last_finfo->proto_layer_num;

	for (guint i = 0; i < finfos->len; i++) {
		finfo = finfos->pdata[i];
		layer = finfo->proto_layer_num;
		if (cookie == layer) {
			if (cookie_matches) {
				fvalues = g_slist_prepend(fvalues, &finfo->value);
			}
		}
		else {
			cookie = layer;
			cookie_matches = drange_contains_layer(range, layer, length);
			if (cookie_matches) {
				fvalues = g_slist_prepend(fvalues, &finfo->value);
			}
		}
	}
	return fvalues;
}

/* Reads a field from the proto_tree and loads the fvalues into a register,
 * if that field has not already been read. */
static gboolean
read_tree(dfilter_t *df, proto_tree *tree,
				dfvm_value_t *arg1, dfvm_value_t *arg2,
				dfvm_value_t *arg3)
{
	GPtrArray	*finfos;
	field_info	*finfo;
	int		i, len;
	GSList		*fvalues = NULL;
	drange_t	*range = NULL;

	header_field_info *hfinfo = arg1->value.hfinfo;
	int reg = arg2->value.numeric;

	if (arg3) {
		range = arg3->value.drange;
	}

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

		if (range) {
			fvalues = filter_finfo_fvalues(fvalues, finfos, range);
		}
		else {
			len = finfos->len;
			for (i = 0; i < len; i++) {
				finfo = g_ptr_array_index(finfos, i);
				fvalues = g_slist_prepend(fvalues, &finfo->value);
			}
		}

		hfinfo = hfinfo->same_name_next;
	}

	if (fvalues == NULL) {
		return FALSE;
	}

	df->registers[reg] = fvalues;
	// These values are referenced only, do not try to free it later.
	df->free_registers[reg] = NULL;
	return TRUE;
}

static GSList *
filter_refs_fvalues(GPtrArray *refs_array, drange_t *range)
{
	int length; /* maximum proto layer number. The numbers are sequential. */
	df_reference_t *last_ref = NULL;
	int cookie = -1;
	gboolean cookie_matches = false;
	GSList *fvalues = NULL;

	if (!refs_array || refs_array->len == 0) {
		return fvalues;
	}

	/* refs array is sorted. */
	last_ref = refs_array->pdata[refs_array->len - 1];
	length = last_ref->proto_layer_num;

	for (guint i = 0; i < refs_array->len; i++) {
		df_reference_t *ref = refs_array->pdata[i];
		int layer = ref->proto_layer_num;

		if (range == NULL) {
			fvalues = g_slist_prepend(fvalues, fvalue_dup(ref->value));
			continue;
		}

		if (cookie == layer) {
			if (cookie_matches) {
				fvalues = g_slist_prepend(fvalues, fvalue_dup(ref->value));
			}
		}
		else {
			cookie = layer;
			cookie_matches = drange_contains_layer(range, layer, length);
			if (cookie_matches) {
				fvalues = g_slist_prepend(fvalues, fvalue_dup(ref->value));
			}
		}
	}
	return fvalues;
}

static gboolean
read_reference(dfilter_t *df, dfvm_value_t *arg1, dfvm_value_t *arg2,
				dfvm_value_t *arg3)
{
	GPtrArray	*refs;
	drange_t	*range = NULL;

	header_field_info *hfinfo = arg1->value.hfinfo;
	int reg = arg2->value.numeric;

	if (arg3) {
		range = arg3->value.drange;
	}

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

	refs = g_hash_table_lookup(df->references, hfinfo);
	if (refs == NULL || refs->len == 0) {
		df->registers[reg] = NULL;
		return FALSE;
	}

	/* Shallow copy */
	df->registers[reg] = filter_refs_fvalues(refs, range);
	/* Creates new value so own it. */
	df->free_registers[reg] = (GDestroyNotify)fvalue_free;
	return TRUE;
}

enum match_how {
	MATCH_ANY,
	MATCH_ALL
};

typedef ft_bool_t (*DFVMCompareFunc)(const fvalue_t*, const fvalue_t*);
typedef ft_bool_t (*DFVMTestFunc)(const fvalue_t*);

static gboolean
cmp_test(enum match_how how, DFVMCompareFunc match_func,
					GSList *arg1, GSList *arg2)
{
	GSList *list1, *list2;
	gboolean want_all = (how == MATCH_ALL);
	gboolean want_any = (how == MATCH_ANY);
	ft_bool_t have_match;

	list1 = arg1;

	while (list1) {
		list2 = arg2;
		while (list2) {
			have_match = match_func(list1->data, list2->data);
			if (want_all && have_match == FT_FALSE) {
				return FALSE;
			}
			else if (want_any && have_match == FT_TRUE) {
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
	ft_bool_t have_match;

	list1 = arg1;

	while (list1) {
		have_match = test_func(list1->data);
		if (want_all && have_match == FT_FALSE) {
			return FALSE;
		}
		else if (want_any && have_match == FT_TRUE) {
			return TRUE;
		}
		list1 = g_slist_next(list1);
	}
	/* want_all || !want_any */
	return want_all;
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
		if (fvalue_matches(list1->data, re) == FT_TRUE) {
			return TRUE;
		}
		list1 = g_slist_next(list1);
	}
	return FALSE;
}

static gboolean
all_matches(dfilter_t *df, dfvm_value_t *arg1, dfvm_value_t *arg2)
{
	GSList *list1 = df->registers[arg1->value.numeric];
	ws_regex_t *re = arg2->value.pcre;

	while (list1) {
		if (fvalue_matches(list1->data, re) == FT_FALSE) {
			return FALSE;
		}
		list1 = g_slist_next(list1);
	}
	return TRUE;
}

static gboolean
any_in_range_internal(GSList *list1, fvalue_t *low, fvalue_t *high)
{
	while (list1) {
		if (fvalue_ge(list1->data, low) == FT_TRUE &&
				fvalue_le(list1->data, high) == FT_TRUE) {
			return TRUE;
		}
		list1 = g_slist_next(list1);
	}
	return FALSE;
}

static gboolean
all_in_range_internal(GSList *list1, fvalue_t *low, fvalue_t *high)
{
	while (list1) {
		if (fvalue_ge(list1->data, low) == FT_FALSE ||
				fvalue_le(list1->data, high) == FT_FALSE) {
			return FALSE;
		}
		list1 = g_slist_next(list1);
	}
	return TRUE;
}

static gboolean
match_in_range(dfilter_t *df, enum match_how how, dfvm_value_t *arg1,
				dfvm_value_t *arg_low, dfvm_value_t *arg_high)
{
	GSList *list1 = df->registers[arg1->value.numeric];
	GSList *_low, *_high;
	fvalue_t *low, *high;

	if (arg_low->type == REGISTER) {
		_low = df->registers[arg_low->value.numeric];
		ws_assert(g_slist_length(_low) == 1);
		low = _low->data;
	}
	else if (arg_low->type == FVALUE) {
		low = arg_low->value.fvalue;
	}
	else {
		ws_assert_not_reached();
	}
	if (arg_high->type == REGISTER) {
		_high = df->registers[arg_high->value.numeric];
		ws_assert(g_slist_length(_high) == 1);
		high = _high->data;
	}
	else if (arg_high->type == FVALUE) {
		high = arg_high->value.fvalue;
	}
	else {
		ws_assert_not_reached();
	}

	if (how == MATCH_ALL)
		return all_in_range_internal(list1, low, high);
	else if (how == MATCH_ANY)
		return any_in_range_internal(list1, low, high);
	else
		ws_assert_not_reached();
}

static gboolean
any_in_range(dfilter_t *df, dfvm_value_t *arg1,
				dfvm_value_t *arg_low, dfvm_value_t *arg_high)
{
	return match_in_range(df, MATCH_ANY, arg1, arg_low, arg_high);
}

static gboolean
all_in_range(dfilter_t *df, dfvm_value_t *arg1,
				dfvm_value_t *arg_low, dfvm_value_t *arg_high)
{
	return match_in_range(df, MATCH_ALL, arg1, arg_low, arg_high);
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
 * to make a new list of fvalue_t's (which are byte-slices),
 * and puts the new list into a new register. */
static void
mk_slice(dfilter_t *df, dfvm_value_t *from_arg, dfvm_value_t *to_arg,
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

static void
mk_length(dfilter_t *df, dfvm_value_t *from_arg, dfvm_value_t *to_arg)
{
	GSList		*from_list, *to_list;
	fvalue_t	*old_fv, *new_fv;

	to_list = NULL;
	from_list = df->registers[from_arg->value.numeric];

	while (from_list) {
		old_fv = from_list->data;
		new_fv = fvalue_new(FT_UINT32);
		fvalue_set_uinteger(new_fv, fvalue_length(old_fv));
		to_list = g_slist_prepend(to_list, new_fv);

		from_list = g_slist_next(from_list);
	}

	df->registers[to_arg->value.numeric] = to_list;
	df->free_registers[to_arg->value.numeric] = (GDestroyNotify)fvalue_free;
}

static gboolean
call_function(dfilter_t *df, dfvm_value_t *arg1, dfvm_value_t *arg2,
							dfvm_value_t *arg3)
{
	df_func_def_t *funcdef;
	GSList *retval = NULL;
	gboolean accum;
	guint32 reg_return, arg_count;

	funcdef = arg1->value.funcdef;
	reg_return = arg2->value.numeric;
	arg_count = arg3->value.numeric;

	accum = funcdef->function(df->function_stack, arg_count, &retval);

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
		wmem_strbuf_append_printf(buf, "%s <%s>", s, fvalue_type_name(l->data));
		g_free(s);
		if (l->next != NULL) {
			wmem_strbuf_append(buf, ", ");
		}
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

static void
stack_push(dfilter_t *df, dfvm_value_t *arg1)
{
	GSList *arg;

	if (arg1->type == FVALUE) {
		arg = g_slist_prepend(NULL, arg1->value.fvalue);
	}
	else if (arg1->type == REGISTER) {
		arg = g_slist_copy(df->registers[arg1->value.numeric]);
	}
	else {
		ws_assert_not_reached();
	}
	df->function_stack = g_slist_prepend(df->function_stack, arg);
}

static void
stack_pop(dfilter_t *df, dfvm_value_t *arg1)
{
	guint count;
	GSList *reg;

	count = arg1->value.numeric;

	for (guint i = 0; i < count; i++) {
		/* Free top of stack and register contained there. The register
		 * contentes are not owned by us. */
		reg = df->function_stack->data;
		/* Free the list but not the data it contains. */
		g_slist_free(reg);
		/* remove top of stack */
		df->function_stack = g_slist_delete_link(df->function_stack, df->function_stack);
	}
}

static gboolean
check_exists(proto_tree *tree, dfvm_value_t *arg1, dfvm_value_t *arg2)
{
	GPtrArray		*finfos;
	header_field_info	*hfinfo;
	drange_t		*range = NULL;
	gboolean		exists;
	GSList			*fvalues;

	hfinfo = arg1->value.hfinfo;
	if (arg2)
		range = arg2->value.drange;

	while (hfinfo) {
		finfos = proto_get_finfo_ptr_array(tree, hfinfo->id);
		if ((finfos == NULL) || (g_ptr_array_len(finfos) == 0)) {
			hfinfo = hfinfo->same_name_next;
			continue;
		}
		if (range == NULL) {
			return TRUE;
		}

		fvalues = filter_finfo_fvalues(NULL, finfos, range);
		exists = (fvalues != NULL);
		g_slist_free(fvalues);
		if (exists) {
			return TRUE;
		}

		hfinfo = hfinfo->same_name_next;
	}

	return FALSE;
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

	ws_assert(tree);

	length = df->insns->len;

	for (id = 0; id < length; id++) {

	  AGAIN:
		insn = g_ptr_array_index(df->insns, id);
		arg1 = insn->arg1;
		arg2 = insn->arg2;
		arg3 = insn->arg3;

		switch (insn->op) {
			case DFVM_CHECK_EXISTS:
				accum = check_exists(tree, arg1, NULL);
				break;

			case DFVM_CHECK_EXISTS_R:
				accum = check_exists(tree, arg1, arg2);
				break;

			case DFVM_READ_TREE:
				accum = read_tree(df, tree, arg1, arg2, NULL);
				break;

			case DFVM_READ_TREE_R:
				accum = read_tree(df, tree, arg1, arg2, arg3);
				break;

			case DFVM_READ_REFERENCE:
				accum = read_reference(df, arg1, arg2, NULL);
				break;

			case DFVM_READ_REFERENCE_R:
				accum = read_reference(df, arg1, arg2, arg3);
				break;

			case DFVM_PUT_FVALUE:
				put_fvalue(df, arg1, arg2);
				break;

			case DFVM_CALL_FUNCTION:
				accum = call_function(df, arg1, arg2, arg3);
				break;

			case DFVM_STACK_PUSH:
				stack_push(df, arg1);
				break;

			case DFVM_STACK_POP:
				stack_pop(df, arg1);
				break;

			case DFVM_SLICE:
				mk_slice(df, arg1, arg2, arg3);
				break;

			case DFVM_LENGTH:
				mk_length(df, arg1, arg2);
				break;

			case DFVM_ALL_EQ:
				accum = all_test(df, fvalue_eq, arg1, arg2);
				break;

			case DFVM_ANY_EQ:
				accum = any_test(df, fvalue_eq, arg1, arg2);
				break;

			case DFVM_ALL_NE:
				accum = all_test(df, fvalue_ne, arg1, arg2);
				break;

			case DFVM_ANY_NE:
				accum = any_test(df, fvalue_ne, arg1, arg2);
				break;

			case DFVM_ALL_GT:
				accum = all_test(df, fvalue_gt, arg1, arg2);
				break;

			case DFVM_ANY_GT:
				accum = any_test(df, fvalue_gt, arg1, arg2);
				break;

			case DFVM_ALL_GE:
				accum = all_test(df, fvalue_ge, arg1, arg2);
				break;

			case DFVM_ANY_GE:
				accum = any_test(df, fvalue_ge, arg1, arg2);
				break;

			case DFVM_ALL_LT:
				accum = all_test(df, fvalue_lt, arg1, arg2);
				break;

			case DFVM_ANY_LT:
				accum = any_test(df, fvalue_lt, arg1, arg2);
				break;

			case DFVM_ALL_LE:
				accum = all_test(df, fvalue_le, arg1, arg2);
				break;

			case DFVM_ANY_LE:
				accum = any_test(df, fvalue_le, arg1, arg2);
				break;

			case DFVM_BITWISE_AND:
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

			case DFVM_NOT_ALL_ZERO:
				accum = !all_test_unary(df, fvalue_is_zero, arg1);
				break;

			case DFVM_ALL_CONTAINS:
				accum = all_test(df, fvalue_contains, arg1, arg2);
				break;

			case DFVM_ANY_CONTAINS:
				accum = any_test(df, fvalue_contains, arg1, arg2);
				break;

			case DFVM_ALL_MATCHES:
				accum = all_matches(df, arg1, arg2);
				break;

			case DFVM_ANY_MATCHES:
				accum = any_matches(df, arg1, arg2);
				break;

			case DFVM_ALL_IN_RANGE:
				accum = all_in_range(df, arg1, arg2, arg3);
				break;

			case DFVM_ANY_IN_RANGE:
				accum = any_in_range(df, arg1, arg2, arg3);
				break;

			case DFVM_UNARY_MINUS:
				mk_minus(df, arg1, arg2);
				break;

			case DFVM_NOT:
				accum = !accum;
				break;

			case DFVM_RETURN:
				free_register_overhead(df);
				return accum;

			case DFVM_IF_TRUE_GOTO:
				if (accum) {
					id = arg1->value.numeric;
					goto AGAIN;
				}
				break;

			case DFVM_IF_FALSE_GOTO:
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
