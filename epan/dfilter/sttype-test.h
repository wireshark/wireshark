/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef STTYPE_TEST_H
#define STTYPE_TEST_H

void
sttype_test_set1(stnode_t *node, test_op_t op, stnode_t *val1);

void
sttype_test_set2(stnode_t *node, test_op_t op, stnode_t *val1, stnode_t *val2);

void
sttype_test_set1_args(stnode_t *node, stnode_t *val1);

void
sttype_test_set2_args(stnode_t *node, stnode_t *val1, stnode_t *val2);

void
sttype_test_set_op(stnode_t *node, test_op_t op);

test_op_t
sttype_test_get_op(stnode_t *node);

void
sttype_test_get(stnode_t *node, test_op_t *p_op, stnode_t **p_val1, stnode_t **p_val2);

#endif
