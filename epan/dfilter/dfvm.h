#ifndef DFVM_H
#define DFVM_H

#include <stdio.h>
#include "proto.h"
#include "dfilter-int.h"
#include "syntax-tree.h"

typedef enum {
	EMPTY,
	FVALUE,
	FIELD_ID,
	INSN_NUMBER,
	REGISTER,
	INTEGER
} dfvm_value_type_t;

typedef struct {
	dfvm_value_type_t	type;

	union {
		fvalue_t	*fvalue;
		guint32		numeric;
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
	MK_RANGE
	
} dfvm_opcode_t;

typedef struct {
	int		id;
	int		LHS;
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
dfvm_value_free(dfvm_value_t *v);

void
dfvm_dump(FILE *f, GPtrArray *insns);

gboolean
dfvm_apply(dfilter_t *df, tvbuff_t *tvb, proto_tree *tree);


#endif
