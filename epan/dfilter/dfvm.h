/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DFVM_H
#define DFVM_H

#include <wsutil/regex.h>
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
	FUNCTION_DEF,
	PCRE
} dfvm_value_type_t;

typedef struct {
	dfvm_value_type_t	type;

	union {
		fvalue_t		*fvalue;
		guint32			numeric;
		drange_t		*drange;
		header_field_info	*hfinfo;
		df_func_def_t		*funcdef;
		ws_regex_t		*pcre;
	} value;

	int ref_count;
} dfvm_value_t;


typedef enum {

	IF_TRUE_GOTO,
	IF_FALSE_GOTO,
	CHECK_EXISTS,
	CHECK_EXISTS_R,
	NOT,
	RETURN,
	READ_TREE,
	READ_TREE_R,
	READ_REFERENCE,
	READ_REFERENCE_R,
	PUT_FVALUE,
	ALL_EQ,
	ANY_EQ,
	ALL_NE,
	ANY_NE,
	ALL_GT,
	ANY_GT,
	ALL_GE,
	ANY_GE,
	ALL_LT,
	ANY_LT,
	ALL_LE,
	ANY_LE,
	ALL_ZERO,
	ANY_ZERO,
	ALL_CONTAINS,
	ANY_CONTAINS,
	ALL_MATCHES,
	ANY_MATCHES,
	MK_SLICE,
	MK_BITWISE_AND,
	MK_MINUS,
	DFVM_ADD,
	DFVM_SUBTRACT,
	DFVM_MULTIPLY,
	DFVM_DIVIDE,
	DFVM_MODULO,
	CALL_FUNCTION,
	STACK_PUSH,
	STACK_POP,
	ALL_IN_RANGE,
	ANY_IN_RANGE,
} dfvm_opcode_t;

const char *
dfvm_opcode_tostr(dfvm_opcode_t code);

typedef struct {
	int		id;
	dfvm_opcode_t	op;
	dfvm_value_t	*arg1;
	dfvm_value_t	*arg2;
	dfvm_value_t	*arg3;
} dfvm_insn_t;

dfvm_insn_t*
dfvm_insn_new(dfvm_opcode_t op);

void
dfvm_insn_free(dfvm_insn_t *insn);

dfvm_value_t*
dfvm_value_new(dfvm_value_type_t type);

dfvm_value_t*
dfvm_value_ref(dfvm_value_t *v);

void
dfvm_value_unref(dfvm_value_t *v);

dfvm_value_t*
dfvm_value_new_fvalue(fvalue_t *fv);

dfvm_value_t*
dfvm_value_new_hfinfo(header_field_info *hfinfo);

dfvm_value_t*
dfvm_value_new_register(int reg);

dfvm_value_t*
dfvm_value_new_drange(drange_t *dr);

dfvm_value_t*
dfvm_value_new_funcdef(df_func_def_t *funcdef);

dfvm_value_t*
dfvm_value_new_pcre(ws_regex_t *re);

dfvm_value_t*
dfvm_value_new_guint(guint num);

void
dfvm_dump(FILE *f, dfilter_t *df);

char *
dfvm_dump_str(wmem_allocator_t *alloc, dfilter_t *df, gboolean print_references);

gboolean
dfvm_apply(dfilter_t *df, proto_tree *tree);

#endif
