/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "dfilter-int.h"
#include "gencode.h"
#include "dfvm.h"
#include "syntax-tree.h"
#include "sttype-range.h"
#include "sttype-test.h"
#include "sttype-set.h"
#include "sttype-function.h"
#include "ftypes/ftypes.h"
#include <wsutil/ws_assert.h>

static void
fixup_jumps(gpointer data, gpointer user_data);

static void
gencode(dfwork_t *dfw, stnode_t *st_node);

static dfvm_value_t *
gen_entity(dfwork_t *dfw, stnode_t *st_arg, GSList **jumps_ptr);

static void
dfw_append_insn(dfwork_t *dfw, dfvm_insn_t *insn)
{
	insn->id = dfw->next_insn_id;
	dfw->next_insn_id++;
	g_ptr_array_add(dfw->insns, insn);
}

/* returns register number */
static dfvm_value_t *
dfw_append_read_tree(dfwork_t *dfw, header_field_info *hfinfo, gboolean reuse_register)
{
	dfvm_insn_t	*insn;
	int		reg = -1;
	dfvm_value_t	*reg_val, *val1;
	gboolean	added_new_hfinfo = FALSE;
	void *loaded_key;

	/* Rewind to find the first field of this name. */
	while (hfinfo->same_name_prev_id != -1) {
		hfinfo = proto_registrar_get_nth(hfinfo->same_name_prev_id);
	}

	/* Keep track of which registers
	 * were used for which hfinfo's so that we
	 * can re-use registers. */
	loaded_key = g_hash_table_lookup(dfw->loaded_fields, hfinfo);
	if (loaded_key != NULL) {
		/* Already loaded at least once. */
		if (reuse_register) {
			/*
			 * Reg's are stored in has as reg+1, so
			 * that the non-existence of a hfinfo in
			 * the hash, or 0, can be differentiated from
			 * a hfinfo being loaded into register #0.
			 */
			reg = GPOINTER_TO_INT(loaded_key) - 1;
		}
		else {
			reg = dfw->next_register++;
		}
	}
	else {
		reg = dfw->next_register++;
		g_hash_table_insert(dfw->loaded_fields,
			hfinfo, GINT_TO_POINTER(reg + 1));

		added_new_hfinfo = TRUE;
	}

	insn = dfvm_insn_new(READ_TREE);
	val1 = dfvm_value_new_hfinfo(hfinfo);
	insn->arg1 = dfvm_value_ref(val1);
	reg_val = dfvm_value_new_register(reg);
	insn->arg2 = dfvm_value_ref(reg_val);
	dfw_append_insn(dfw, insn);

	if (added_new_hfinfo) {
		while (hfinfo) {
			/* Record the FIELD_ID in hash of interesting fields. */
			g_hash_table_insert(dfw->interesting_fields,
			    GINT_TO_POINTER(hfinfo->id),
			    GUINT_TO_POINTER(TRUE));
			hfinfo = hfinfo->same_name_next;
		}
	}

	return reg_val;
}

/* returns register number */
static dfvm_value_t *
dfw_append_read_reference(dfwork_t *dfw, header_field_info *hfinfo)
{
	dfvm_insn_t	*insn;
	dfvm_value_t	*reg_val, *val1;
	GSList		**fvalues_ptr;
	gboolean	added_new_hfinfo = FALSE;

	/* Rewind to find the first field of this name. */
	while (hfinfo->same_name_prev_id != -1) {
		hfinfo = proto_registrar_get_nth(hfinfo->same_name_prev_id);
	}

	/* Keep track of which registers
	 * were used for which hfinfo's so that we
	 * can re-use registers. */
	reg_val = g_hash_table_lookup(dfw->loaded_references, hfinfo);
	if (!reg_val) {
		reg_val = dfvm_value_new_register(dfw->next_register++);
		g_hash_table_insert(dfw->loaded_references, hfinfo, dfvm_value_ref(reg_val));
		added_new_hfinfo = TRUE;
	}

	insn = dfvm_insn_new(READ_REFERENCE);
	val1 = dfvm_value_new_hfinfo(hfinfo);
	insn->arg1 = dfvm_value_ref(val1);
	insn->arg2 = dfvm_value_ref(reg_val);
	dfw_append_insn(dfw, insn);

	fvalues_ptr = g_new(GSList *, 1);
	*fvalues_ptr = NULL;
	g_hash_table_insert(dfw->references, hfinfo, fvalues_ptr);

	if (added_new_hfinfo) {
		while (hfinfo) {
			/* Record the FIELD_ID in hash of interesting fields. */
			g_hash_table_insert(dfw->interesting_fields,
			    GINT_TO_POINTER(hfinfo->id),
			    GUINT_TO_POINTER(TRUE));
			hfinfo = hfinfo->same_name_next;
		}
	}

	return reg_val;
}

/* returns register number */
static dfvm_value_t *
dfw_append_mk_range(dfwork_t *dfw, stnode_t *node, GSList **jumps_ptr)
{
	stnode_t                *entity;
	dfvm_insn_t		*insn;
	dfvm_value_t		*reg_val, *val1, *val3;

	entity = sttype_range_entity(node);

	insn = dfvm_insn_new(MK_RANGE);
	val1 = gen_entity(dfw, entity, jumps_ptr);
	insn->arg1 = dfvm_value_ref(val1);
	reg_val = dfvm_value_new_register(dfw->next_register++);
	insn->arg2 = dfvm_value_ref(reg_val);
	val3 = dfvm_value_new_drange(sttype_range_drange(node));
	insn->arg3 = dfvm_value_ref(val3);
	sttype_range_remove_drange(node);
	dfw_append_insn(dfw, insn);

	return reg_val;
}

/* returns register number */
static dfvm_value_t *
dfw_append_put_fvalue(dfwork_t *dfw, fvalue_t *fv)
{
	dfvm_insn_t		*insn;
	dfvm_value_t		*reg_val, *val1;

	insn = dfvm_insn_new(PUT_FVALUE);
	val1 = dfvm_value_new_fvalue(fv);
	insn->arg1 = dfvm_value_ref(val1);
	reg_val = dfvm_value_new_register(dfw->next_register++);
	insn->arg2 = dfvm_value_ref(reg_val);
	dfw_append_insn(dfw, insn);

	return reg_val;
}

/* returns register number that the functions's result will be in. */
static dfvm_value_t *
dfw_append_function(dfwork_t *dfw, stnode_t *node, GSList **jumps_ptr)
{
	GSList *params;
	dfvm_value_t *jmp;
	dfvm_insn_t	*insn;
	dfvm_value_t	*reg_val, *val1, *val3, *val4, *val_arg;
	guint32		reg_first, more_args_count;
	stnode_t	*arg;

	/* Create the new DFVM instruction */
	insn = dfvm_insn_new(CALL_FUNCTION);
	val1 = dfvm_value_new_funcdef(sttype_function_funcdef(node));
	insn->arg1 = dfvm_value_ref(val1);
	reg_val = dfvm_value_new_register(dfw->next_register++);
	insn->arg2 = dfvm_value_ref(reg_val);

	/* Create input arguments */
	params = sttype_function_params(node);
	ws_assert(params);
	val3 = dfw_append_read_tree(dfw, stnode_steal_data(params->data), FALSE);
	insn->arg3 = dfvm_value_ref(val3);

	params = params->next;
	reg_first = val3->value.numeric;
	more_args_count = 0;
	while (params) {
		arg = params->data;
		switch (stnode_type_id(arg)) {
			case STTYPE_FVALUE:
				dfw_append_put_fvalue(dfw, stnode_steal_data(arg));
				break;
			case STTYPE_FIELD:
				/* We cannot reuse registers here because the function calling
				 * convention is to pass input arguments sequentially. */
				val_arg = dfw_append_read_tree(dfw, stnode_data(arg), FALSE);
				/* Assert the registers are numbered sequentially. */
				ws_assert(val_arg->value.numeric == reg_first + more_args_count + 1);
				break;
			default:
				ws_assert_not_reached();
		}
		more_args_count++;
		params = params->next;
	}
	val4 = dfvm_value_new(INTEGER);
	val4->value.numeric = more_args_count;
	insn->arg4 = dfvm_value_ref(val4);

	dfw_append_insn(dfw, insn);

	/* There is no jump if READ_TREE fails for a function parameter. It
	 * is up to the function to return TRUE/FALSE for any combination
	 * of (missing or not) arguments. */

	/* We need another instruction to jump to another exit
	 * place, if the call() of our function failed for some reaosn */
	insn = dfvm_insn_new(IF_FALSE_GOTO);
	jmp = dfvm_value_new(INSN_NUMBER);
	insn->arg1 = dfvm_value_ref(jmp);
	dfw_append_insn(dfw, insn);
	*jumps_ptr = g_slist_prepend(*jumps_ptr, jmp);

	return reg_val;
}

/**
 * Adds an instruction for a relation operator where the values are already
 * loaded in registers.
 */
static void
gen_relation_insn(dfwork_t *dfw, dfvm_opcode_t op,
			dfvm_value_t *arg1, dfvm_value_t *arg2,
			dfvm_value_t *arg3, dfvm_value_t *arg4)
{
	dfvm_insn_t	*insn;

	insn = dfvm_insn_new(op);
	insn->arg1 = dfvm_value_ref(arg1);
	insn->arg2 = dfvm_value_ref(arg2);
	insn->arg3 = dfvm_value_ref(arg3);
	insn->arg4 = dfvm_value_ref(arg4);
	dfw_append_insn(dfw, insn);
}

static void
gen_relation(dfwork_t *dfw, dfvm_opcode_t op, stnode_t *st_arg1, stnode_t *st_arg2)
{
	GSList		*jumps = NULL;
	dfvm_value_t	*val1, *val2;

	/* Create code for the LHS and RHS of the relation */
	val1 = gen_entity(dfw, st_arg1, &jumps);
	val2 = gen_entity(dfw, st_arg2, &jumps);

	/* Then combine them in a DFVM insruction */
	gen_relation_insn(dfw, op, val1, val2, NULL, NULL);

	/* If either of the relation arguments need an "exit" instruction
	 * to jump to (on failure), mark them */
	g_slist_foreach(jumps, fixup_jumps, dfw);
	g_slist_free(jumps);
	jumps = NULL;
}

static void
fixup_jumps(gpointer data, gpointer user_data)
{
	dfvm_value_t *jmp = (dfvm_value_t*)data;
	dfwork_t *dfw = (dfwork_t*)user_data;

	if (jmp) {
		jmp->value.numeric = dfw->next_insn_id;
	}
}

/* Generate the code for the in operator.  It behaves much like an OR-ed
 * series of == tests, but without the redundant existence checks. */
static void
gen_relation_in(dfwork_t *dfw, stnode_t *st_arg1, stnode_t *st_arg2)
{
	dfvm_insn_t	*insn;
	dfvm_value_t	*jmp;
	GSList		*jumps = NULL;
	GSList		*node_jumps = NULL;
	dfvm_value_t	*val1, *val2, *val3;
	stnode_t	*node1, *node2;
	GSList		*nodelist_head, *nodelist;

	/* Create code for the LHS of the relation */
	val1 = gen_entity(dfw, st_arg1, &jumps);

	/* Create code for the set on the RHS of the relation */
	nodelist_head = nodelist = stnode_steal_data(st_arg2);
	while (nodelist) {
		node1 = nodelist->data;
		nodelist = g_slist_next(nodelist);
		node2 = nodelist->data;
		nodelist = g_slist_next(nodelist);

		if (node2) {
			/* Range element: add lower/upper bound test. */
			val2 = gen_entity(dfw, node1, &node_jumps);
			val3 = gen_entity(dfw, node2, &node_jumps);

			/* Add test to see if the item is in range. */
			gen_relation_insn(dfw, ANY_IN_RANGE, val1, val2, val3, NULL);
		} else {
			/* Normal element: add equality test. */
			val2 = gen_entity(dfw, node1, &node_jumps);

			/* Add test to see if the item matches */
			gen_relation_insn(dfw, ANY_EQ, val1, val2, NULL, NULL);
		}

		/* Exit as soon as we find a match */
		if (nodelist) {
			insn = dfvm_insn_new(IF_TRUE_GOTO);
			jmp = dfvm_value_new(INSN_NUMBER);
			insn->arg1 = dfvm_value_ref(jmp);
			dfw_append_insn(dfw, insn);
			jumps = g_slist_prepend(jumps, jmp);
		}

		/* If an item is not present, just jump to the next item */
		g_slist_foreach(node_jumps, fixup_jumps, dfw);
		g_slist_free(node_jumps);
		node_jumps = NULL;
	}

	/* Jump here if the LHS entity was not present */
	/* Jump here if any of the items in the set matched */
	g_slist_foreach(jumps, fixup_jumps, dfw);
	g_slist_free(jumps);
	jumps = NULL;

	set_nodelist_free(nodelist_head);
}

static dfvm_value_t *
gen_arithmetic(dfwork_t *dfw, stnode_t *st_arg, GSList **jumps_ptr)
{
	stnode_t	*left, *right;
	test_op_t	st_op;
	dfvm_value_t	*reg_val, *val1, *val2 = NULL;
	dfvm_opcode_t	op;

	sttype_test_get(st_arg, &st_op, &left, &right);

	if (st_op == OP_UNARY_MINUS) {
		op = MK_MINUS;
	}
	else if (st_op == OP_ADD) {
		op = DFVM_ADD;
	}
	else if (st_op == OP_SUBTRACT) {
		op = DFVM_SUBTRACT;
	}
	else if (st_op == OP_MULTIPLY) {
		op = DFVM_MULTIPLY;
	}
	else if (st_op == OP_DIVIDE) {
		op = DFVM_DIVIDE;
	}
	else if (st_op == OP_MODULO) {
		op = DFVM_MODULO;
	}
	else if (st_op == OP_BITWISE_AND) {
		op = MK_BITWISE_AND;
	}
	else {
		ws_assert_not_reached();
	}

	val1 = gen_entity(dfw, left, jumps_ptr);
	if (right == NULL) {
		/* Generate unary DFVM instruction. */
		reg_val = dfvm_value_new_register(dfw->next_register++);
		gen_relation_insn(dfw, op, val1, reg_val, NULL, NULL);
		return reg_val;
	}

	val2 = gen_entity(dfw, right, jumps_ptr);
	reg_val = dfvm_value_new_register(dfw->next_register++);
	gen_relation_insn(dfw, op, val1, val2, reg_val, NULL);
	return reg_val;
}

/* Parse an entity, returning the reg that it gets put into.
 * p_jmp will be set if it has to be set by the calling code; it should
 * be set to the place to jump to, to return to the calling code,
 * if the load of a field from the proto_tree fails. */
static dfvm_value_t *
gen_entity(dfwork_t *dfw, stnode_t *st_arg, GSList **jumps_ptr)
{
	sttype_id_t       e_type;
	dfvm_insn_t       *insn;
	dfvm_value_t      *val, *jmp;
	header_field_info *hfinfo;
	e_type = stnode_type_id(st_arg);

	if (e_type == STTYPE_FIELD) {
		hfinfo = stnode_data(st_arg);
		val = dfw_append_read_tree(dfw, hfinfo, TRUE);

		insn = dfvm_insn_new(IF_FALSE_GOTO);
		jmp = dfvm_value_new(INSN_NUMBER);
		insn->arg1 = dfvm_value_ref(jmp);
		dfw_append_insn(dfw, insn);
		*jumps_ptr = g_slist_prepend(*jumps_ptr, jmp);
	}
	else if (e_type == STTYPE_REFERENCE) {
		hfinfo = stnode_data(st_arg);
		val = dfw_append_read_reference(dfw, hfinfo);

		insn = dfvm_insn_new(IF_FALSE_GOTO);
		jmp = dfvm_value_new(INSN_NUMBER);
		insn->arg1 = dfvm_value_ref(jmp);
		dfw_append_insn(dfw, insn);
		*jumps_ptr = g_slist_prepend(*jumps_ptr, jmp);
	}
	else if (e_type == STTYPE_FVALUE) {
		val = dfvm_value_new_fvalue(stnode_steal_data(st_arg));
	}
	else if (e_type == STTYPE_RANGE) {
		val = dfw_append_mk_range(dfw, st_arg, jumps_ptr);
	}
	else if (e_type == STTYPE_FUNCTION) {
		val = dfw_append_function(dfw, st_arg, jumps_ptr);
	}
	else if (e_type == STTYPE_PCRE) {
		val = dfvm_value_new_pcre(stnode_steal_data(st_arg));
	}
	else if (e_type == STTYPE_ARITHMETIC) {
		val = gen_arithmetic(dfw, st_arg, jumps_ptr);
	}
	else {
		/* printf("sttype_id is %u\n", (unsigned)e_type); */
		ws_assert_not_reached();
	}
	return val;
}

static void
gen_exists(dfwork_t *dfw, stnode_t *st_node)
{
	dfvm_insn_t *insn;
	header_field_info *hfinfo;

	hfinfo = stnode_data(st_node);

	/* Rewind to find the first field of this name. */
	while (hfinfo->same_name_prev_id != -1) {
		hfinfo = proto_registrar_get_nth(hfinfo->same_name_prev_id);
	}
	insn = dfvm_insn_new(CHECK_EXISTS);
	insn->arg1 = dfvm_value_new_hfinfo(hfinfo);
	dfw_append_insn(dfw, insn);

	/* Record the FIELD_ID in hash of interesting fields. */
	while (hfinfo) {
		g_hash_table_insert(dfw->interesting_fields,
			GINT_TO_POINTER(hfinfo->id),
			GUINT_TO_POINTER(TRUE));
		hfinfo = hfinfo->same_name_next;
	}
}

static void
gen_notzero(dfwork_t *dfw, stnode_t *st_node)
{
	dfvm_insn_t	*insn;
	dfvm_value_t	*val1;
	GSList		*jumps = NULL;

	val1 = gen_arithmetic(dfw, st_node, &jumps);
	insn = dfvm_insn_new(ALL_ZERO);
	insn->arg1 = dfvm_value_ref(val1);
	dfw_append_insn(dfw, insn);
	insn = dfvm_insn_new(NOT);
	dfw_append_insn(dfw, insn);
	g_slist_foreach(jumps, fixup_jumps, dfw);
	g_slist_free(jumps);
}

static void
gen_test(dfwork_t *dfw, stnode_t *st_node)
{
	test_op_t	st_op;
	stnode_t	*st_arg1, *st_arg2;
	dfvm_insn_t	*insn;
	dfvm_value_t	*jmp;


	sttype_test_get(st_node, &st_op, &st_arg1, &st_arg2);

	switch (st_op) {
		case TEST_OP_UNINITIALIZED:
			ws_assert_not_reached();
			break;

		case TEST_OP_NOT:
			gencode(dfw, st_arg1);
			insn = dfvm_insn_new(NOT);
			dfw_append_insn(dfw, insn);
			break;

		case TEST_OP_AND:
			gencode(dfw, st_arg1);

			insn = dfvm_insn_new(IF_FALSE_GOTO);
			jmp = dfvm_value_new(INSN_NUMBER);
			insn->arg1 = dfvm_value_ref(jmp);
			dfw_append_insn(dfw, insn);

			gencode(dfw, st_arg2);
			jmp->value.numeric = dfw->next_insn_id;
			break;

		case TEST_OP_OR:
			gencode(dfw, st_arg1);

			insn = dfvm_insn_new(IF_TRUE_GOTO);
			jmp = dfvm_value_new(INSN_NUMBER);
			insn->arg1 = dfvm_value_ref(jmp);
			dfw_append_insn(dfw, insn);

			gencode(dfw, st_arg2);
			jmp->value.numeric = dfw->next_insn_id;
			break;

		case TEST_OP_ALL_EQ:
			gen_relation(dfw, ALL_EQ, st_arg1, st_arg2);
			break;

		case TEST_OP_ANY_EQ:
			gen_relation(dfw, ANY_EQ, st_arg1, st_arg2);
			break;

		case TEST_OP_ALL_NE:
			gen_relation(dfw, ALL_NE, st_arg1, st_arg2);
			break;

		case TEST_OP_ANY_NE:
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

		case TEST_OP_CONTAINS:
			gen_relation(dfw, ANY_CONTAINS, st_arg1, st_arg2);
			break;

		case TEST_OP_MATCHES:
			gen_relation(dfw, ANY_MATCHES, st_arg1, st_arg2);
			break;

		case TEST_OP_IN:
			gen_relation_in(dfw, st_arg1, st_arg2);
			break;

		case OP_BITWISE_AND:
		case OP_UNARY_MINUS:
		case OP_ADD:
		case OP_SUBTRACT:
		case OP_MULTIPLY:
		case OP_DIVIDE:
		case OP_MODULO:
			ws_assert_not_reached();
			break;
	}
}

static void
gencode(dfwork_t *dfw, stnode_t *st_node)
{
	switch (stnode_type_id(st_node)) {
		case STTYPE_TEST:
			gen_test(dfw, st_node);
			break;
		case STTYPE_FIELD:
			gen_exists(dfw, st_node);
			break;
		case STTYPE_ARITHMETIC:
			gen_notzero(dfw, st_node);
			break;
		default:
			ws_assert_not_reached();
	}
}


static void
optimize(dfwork_t *dfw)
{
	int		id, id1, length;
	dfvm_insn_t	*insn, *insn1, *prev;
	dfvm_value_t	*arg1;

	length = dfw->insns->len;

	for (id = 0, prev = NULL; id < length; prev = insn, id++) {
		insn = (dfvm_insn_t	*)g_ptr_array_index(dfw->insns, id);
		arg1 = insn->arg1;
		if (insn->op == IF_TRUE_GOTO || insn->op == IF_FALSE_GOTO) {
			/* Try to optimize branch jumps */
			dfvm_opcode_t revert = (insn->op == IF_FALSE_GOTO) ? IF_TRUE_GOTO : IF_FALSE_GOTO;
			id1 = arg1->value.numeric;
			for (;;) {
				insn1 = (dfvm_insn_t*)g_ptr_array_index(dfw->insns, id1);
				if (insn1->op == revert) {
					/* Skip this one; it is always false and the branch is not taken */
					id1 = id1 +1;
					continue;
				}
				if (insn1->op == READ_TREE && prev && prev->op == READ_TREE &&
						prev->arg2->value.numeric == insn1->arg2->value.numeric) {
					/* Skip this one; hack if it's the same register it's the same field
					 * and it returns the same value */
					id1 = id1 +1;
					continue;
				}
				if (insn1->op == insn->op) {
					/* The branch jumps to the same branch instruction so
					 * coalesce the jumps */
					arg1 = insn1->arg1;
					id1 = arg1->value.numeric;
					continue;
				}
				/* Finished */
				arg1 = insn->arg1;
				arg1->value.numeric = id1;
				break;
			}
		}
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
	optimize(dfw);
}


typedef struct {
	int i;
	int *fields;
} hash_key_iterator;

static void
get_hash_key(gpointer key, gpointer value _U_, gpointer user_data)
{
	int field_id = GPOINTER_TO_INT(key);
	hash_key_iterator *hki = (hash_key_iterator *)user_data;

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
