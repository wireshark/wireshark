/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DFVM_H
#define DFVM_H

#include <epan/proto.h>
#include "dfilter-int.h"
#include "syntax-tree.h"
#include "drange.h"
#include "dfunctions.h"

typedef enum {
	EMPTY,
	FVALUE,
	HFINFO,
	INSN_NUMBER,
	REGISTER,
	INTEGER,
	DRANGE,
	FUNCTION_DEF
} dfvm_value_type_t;

typedef struct {
	dfvm_value_type_t	type;

	union {
		fvalue_t		*fvalue;
		guint32			numeric;
		drange_t		*drange;
		header_field_info	*hfinfo;
        df_func_def_t   *funcdef;
	} value;

} dfvm_value_t;


typedef enum {

	IF_TRUE_GOTO,
	IF_FALSE_GOTO,
	CHECK_EXISTS,
	NOT,
	RETURN,
	READ_TREE,
	PUT_FVALUE,
	ANY_EQ,
	ANY_NE,
	ANY_GT,
	ANY_GE,
	ANY_LT,
	ANY_LE,
	ANY_BITWISE_AND,
	ANY_CONTAINS,
	ANY_MATCHES,
	MK_RANGE,
	CALL_FUNCTION,
	ANY_IN_RANGE

} dfvm_opcode_t;

typedef struct {
	int		id;
	dfvm_opcode_t	op;
	dfvm_value_t	*arg1;
	dfvm_value_t	*arg2;
	dfvm_value_t	*arg3;
	dfvm_value_t	*arg4;
} dfvm_insn_t;

dfvm_insn_t*
dfvm_insn_new(dfvm_opcode_t op);

void
dfvm_insn_free(dfvm_insn_t *insn);

dfvm_value_t*
dfvm_value_new(dfvm_value_type_t type);

void
dfvm_dump(FILE *f, dfilter_t *df);

gboolean
dfvm_apply(dfilter_t *df, proto_tree *tree);

void
dfvm_init_const(dfilter_t *df);

#endif
