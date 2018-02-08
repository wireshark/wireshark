/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef STTYPE_TEST_H
#define STTYPE_TEST_H

typedef enum {
	TEST_OP_UNINITIALIZED,
	TEST_OP_EXISTS,
	TEST_OP_NOT,
	TEST_OP_AND,
	TEST_OP_OR,
	TEST_OP_EQ,
	TEST_OP_NE,
	TEST_OP_GT,
	TEST_OP_GE,
	TEST_OP_LT,
	TEST_OP_LE,
	TEST_OP_BITWISE_AND,
	TEST_OP_CONTAINS,
	TEST_OP_MATCHES,
	TEST_OP_IN
} test_op_t;

void
sttype_test_set1(stnode_t *node, test_op_t op, stnode_t *val1);

void
sttype_test_set2(stnode_t *node, test_op_t op, stnode_t *val1, stnode_t *val2);

void
sttype_test_set2_args(stnode_t *node, stnode_t *val1, stnode_t *val2);

void
sttype_test_get(stnode_t *node, test_op_t *p_op, stnode_t **p_val1, stnode_t **p_val2);

#endif
