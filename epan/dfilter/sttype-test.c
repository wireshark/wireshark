/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "syntax-tree.h"
#include "sttype-test.h"

typedef struct {
	guint32		magic;
	test_op_t	op;
	stnode_t	*val1;
	stnode_t	*val2;
} test_t;

#define TEST_MAGIC	0xab9009ba

static gpointer
test_new(gpointer junk)
{
	test_t		*test;

	g_assert(junk == NULL);

	test = g_new(test_t, 1);

	test->magic = TEST_MAGIC;
	test->op = TEST_OP_UNINITIALIZED;
	test->val1 = NULL;
	test->val2 = NULL;

	return (gpointer) test;
}

static gpointer
test_dup(gconstpointer data)
{
	const test_t *org = (const test_t *)data;
	test_t		 *test;

	test = (test_t *)test_new(NULL);
	test->op   = org->op;
	test->val1 = stnode_dup(org->val1);
	test->val2 = stnode_dup(org->val1);

	return (gpointer) test;
}

static void
test_free(gpointer value)
{
	test_t	*test = (test_t *)value;
	assert_magic(test, TEST_MAGIC);

	if (test->val1)
		stnode_free(test->val1);
	if (test->val2)
		stnode_free(test->val2);

	g_free(test);
}

static int
num_operands(test_op_t op)
{
	switch(op) {
		case TEST_OP_UNINITIALIZED:
			break;
		case TEST_OP_EXISTS:
		case TEST_OP_NOT:
			return 1;
		case TEST_OP_AND:
		case TEST_OP_OR:
		case TEST_OP_EQ:
		case TEST_OP_NE:
		case TEST_OP_GT:
		case TEST_OP_GE:
		case TEST_OP_LT:
		case TEST_OP_LE:
		case TEST_OP_BITWISE_AND:
		case TEST_OP_CONTAINS:
		case TEST_OP_MATCHES:
		case TEST_OP_IN:
			return 2;
	}
	g_assert_not_reached();
	return -1;
}


void
sttype_test_set1(stnode_t *node, test_op_t op, stnode_t *val1)
{
	test_t	*test;

	test = (test_t*)stnode_data(node);
	assert_magic(test, TEST_MAGIC);

	g_assert(num_operands(op) == 1);
	test->op = op;
	test->val1 = val1;
}

void
sttype_test_set2(stnode_t *node, test_op_t op, stnode_t *val1, stnode_t *val2)
{
	test_t	*test;

	test = (test_t*)stnode_data(node);
	assert_magic(test, TEST_MAGIC);

	g_assert(num_operands(op) == 2);
	test->op = op;
	test->val1 = val1;
	test->val2 = val2;
}

void
sttype_test_set2_args(stnode_t *node, stnode_t *val1, stnode_t *val2)
{
	test_t	*test;

	test = (test_t*)stnode_data(node);
	assert_magic(test, TEST_MAGIC);

	if (num_operands(test->op) == 1) {
		g_assert(val2 == NULL);
	}
	test->val1 = val1;
	test->val2 = val2;
}

void
sttype_test_get(stnode_t *node, test_op_t *p_op, stnode_t **p_val1, stnode_t **p_val2)
{
	test_t	*test;

	test = (test_t*)stnode_data(node);
	assert_magic(test, TEST_MAGIC);

	if (p_op)
		*p_op = test->op;
	if (p_val1)
		*p_val1 = test->val1;
	if (p_val2)
		*p_val2 = test->val2;
}

void
sttype_register_test(void)
{
	static sttype_t test_type = {
		STTYPE_TEST,
		"TEST",
		test_new,
		test_free,
		test_dup
	};

	sttype_register(&test_type);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
