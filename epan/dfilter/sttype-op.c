/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "syntax-tree.h"
#include "sttype-op.h"

typedef struct {
	uint32_t		magic;
	stnode_op_t	op;
	stmatch_t	how;
	stnode_t	*val1;
	stnode_t	*val2;
} oper_t;

#define OPER_MAGIC	0xab9009ba

static void *
oper_new(void *junk _U_)
{
	oper_t *oper;

	ws_assert(junk == NULL);

	oper = g_new(oper_t, 1);

	oper->magic = OPER_MAGIC;
	oper->op = STNODE_OP_UNINITIALIZED;
	oper->how = STNODE_MATCH_DEF;
	oper->val1 = NULL;
	oper->val2 = NULL;

	return oper;
}

static void *
oper_dup(const void *data)
{
	const oper_t *org = data;
	oper_t *oper;

	oper = oper_new(NULL);
	oper->op = org->op;
	oper->how = org->how;
	oper->val1 = stnode_dup(org->val1);
	oper->val2 = stnode_dup(org->val2);

	return oper;
}

static void
oper_free(void *value)
{
	oper_t *oper = value;
	ws_assert_magic(oper, OPER_MAGIC);

	if (oper->val1)
		stnode_free(oper->val1);
	if (oper->val2)
		stnode_free(oper->val2);

	g_free(oper);
}

static char *
oper_todisplay(const oper_t *oper)
{
	const char *s = "(notset)";

	switch(oper->op) {
		case STNODE_OP_NOT:
			s = "!";
			break;
		case STNODE_OP_AND:
			s = "&&";
			break;
		case STNODE_OP_OR:
			s = "||";
			break;
		case STNODE_OP_ALL_EQ:
			s = "===";
			break;
		case STNODE_OP_ANY_EQ:
			s = "==";
			break;
		case STNODE_OP_ALL_NE:
			s = "!=";
			break;
		case STNODE_OP_ANY_NE:
			s = "~=";
			break;
		case STNODE_OP_GT:
			s = ">";
			break;
		case STNODE_OP_GE:
			s = ">=";
			break;
		case STNODE_OP_LT:
			s = "<";
			break;
		case STNODE_OP_LE:
			s = "<=";
			break;
		case STNODE_OP_BITWISE_AND:
			s = "&";
			break;
		case STNODE_OP_ADD:
			s = "+";
			break;
		case STNODE_OP_UNARY_MINUS:
		case STNODE_OP_SUBTRACT:
			s = "-";
			break;
		case STNODE_OP_MULTIPLY:
			s = "*";
			break;
		case STNODE_OP_DIVIDE:
			s = "/";
			break;
		case STNODE_OP_MODULO:
			s = "%";
			break;
		case STNODE_OP_CONTAINS:
			s = "contains";
			break;
		case STNODE_OP_MATCHES:
			s = "matches";
			break;
		case STNODE_OP_IN:
			s = "in";
			break;
		case STNODE_OP_NOT_IN:
			s = "not in";
			break;
		case STNODE_OP_UNINITIALIZED:
			s = "(uninitialized)";
			break;
	}
	return g_strdup(s);
}

static char *
oper_todebug(const oper_t *oper)
{
	const char *s = stnode_op_name(oper->op);
	if (oper->how == STNODE_MATCH_ALL)
		return ws_strdup_printf("ALL %s", s);
	if (oper->how == STNODE_MATCH_ANY)
		return ws_strdup_printf("ANY %s", s);
	return ws_strdup(s);
}

static char *
oper_tostr(const void *value, bool pretty)
{
	const oper_t *oper = value;
	ws_assert_magic(oper, OPER_MAGIC);

	if (pretty)
		return oper_todisplay(oper);
	return oper_todebug(oper);
}

static int
num_operands(stnode_op_t op)
{
	switch(op) {
		case STNODE_OP_NOT:
		case STNODE_OP_UNARY_MINUS:
			return 1;
		case STNODE_OP_AND:
		case STNODE_OP_OR:
		case STNODE_OP_ALL_EQ:
		case STNODE_OP_ANY_EQ:
		case STNODE_OP_ALL_NE:
		case STNODE_OP_ANY_NE:
		case STNODE_OP_GT:
		case STNODE_OP_GE:
		case STNODE_OP_LT:
		case STNODE_OP_LE:
		case STNODE_OP_BITWISE_AND:
		case STNODE_OP_ADD:
		case STNODE_OP_SUBTRACT:
		case STNODE_OP_MULTIPLY:
		case STNODE_OP_DIVIDE:
		case STNODE_OP_MODULO:
		case STNODE_OP_CONTAINS:
		case STNODE_OP_MATCHES:
		case STNODE_OP_IN:
		case STNODE_OP_NOT_IN:
			return 2;
		case STNODE_OP_UNINITIALIZED:
			ASSERT_STNODE_OP_NOT_REACHED(op);
	}

	ws_assert_not_reached();
}


void
sttype_oper_set1(stnode_t *node, stnode_op_t op, stnode_t *val1)
{
	oper_t *oper = stnode_data(node);
	ws_assert_magic(oper, OPER_MAGIC);

	ws_assert(num_operands(op) == 1);
	oper->op = op;
	oper->val1 = val1;
	oper->val2 = NULL;
}

void
sttype_oper_set2(stnode_t *node, stnode_op_t op, stnode_t *val1, stnode_t *val2)
{
	oper_t *oper = stnode_data(node);
	ws_assert_magic(oper, OPER_MAGIC);

	ws_assert(num_operands(op) == 2);
	oper->op = op;
	oper->val1 = val1;
	oper->val2 = val2;
}

void
sttype_oper_set1_args(stnode_t *node, stnode_t *val1)
{
	oper_t	*oper;

	oper = (oper_t*)stnode_data(node);
	ws_assert_magic(oper, OPER_MAGIC);

	ws_assert(num_operands(oper->op) == 1);
	oper->val1 = val1;
	oper->val2 = NULL;
}

void
sttype_oper_set2_args(stnode_t *node, stnode_t *val1, stnode_t *val2)
{
	oper_t	*oper;

	oper = (oper_t*)stnode_data(node);
	ws_assert_magic(oper, OPER_MAGIC);

	ws_assert(num_operands(oper->op) == 2);
	oper->val1 = val1;
	oper->val2 = val2;
}

void
sttype_oper_set_op(stnode_t *node, stnode_op_t op)
{
	oper_t *oper = stnode_data(node);
	ws_assert_magic(oper, OPER_MAGIC);
	ws_assert(oper->op == STNODE_OP_UNINITIALIZED);
	oper->op = op;
}

stnode_op_t
sttype_oper_get_op(stnode_t *node)
{
	oper_t *oper = stnode_data(node);
	ws_assert_magic(oper, OPER_MAGIC);
	return oper->op;
}

void
sttype_oper_get(stnode_t *node, stnode_op_t *p_op, stnode_t **p_val1, stnode_t **p_val2)
{
	oper_t *oper = stnode_data(node);
	ws_assert_magic(oper, OPER_MAGIC);

	if (p_op)
		*p_op = oper->op;
	if (p_val1)
		*p_val1 = oper->val1;
	if (p_val2)
		*p_val2 = oper->val2;
}

void
sttype_test_set_match(stnode_t *node, stmatch_t how)
{
	oper_t *oper = stnode_data(node);
	ws_assert_magic(oper, OPER_MAGIC);
	oper->how = how;
}

stmatch_t
sttype_test_get_match(stnode_t *node)
{
	oper_t *oper = stnode_data(node);
	ws_assert_magic(oper, OPER_MAGIC);
	return oper->how;
}

void
sttype_register_opers(void)
{
	static sttype_t test_type = {
		STTYPE_TEST,
		oper_new,
		oper_free,
		oper_dup,
		oper_tostr
	};
	static sttype_t arithmetic_type = {
		STTYPE_ARITHMETIC,
		oper_new,
		oper_free,
		oper_dup,
		oper_tostr
	};

	sttype_register(&test_type);
	sttype_register(&arithmetic_type);
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
