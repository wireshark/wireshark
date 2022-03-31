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
	NOT,
	RETURN,
	READ_TREE,
	READ_REFERENCE,
	ALL_EQ,
	ANY_EQ,
	ALL_NE,
	ANY_NE,
	ANY_GT,
	ANY_GE,
	ANY_LT,
	ANY_LE,
	ANY_ZERO,
	ALL_ZERO,
	ANY_CONTAINS,
	ANY_MATCHES,
	MK_RANGE,
	MK_BITWISE_AND,
	MK_MINUS,
	DFVM_ADD,
	DFVM_SUBTRACT,
	DFVM_MULTIPLY,
	DFVM_DIVIDE,
	DFVM_MODULO,
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

void
dfvm_dump(FILE *f, dfilter_t *df);

char *
dfvm_dump_str(wmem_allocator_t *alloc, dfilter_t *df, gboolean print_references);

gboolean
dfvm_apply(dfilter_t *df, proto_tree *tree);

#endif
