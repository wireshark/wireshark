/*
 * $Id: dfvm.h,v 1.3 2001/02/27 19:23:28 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef DFVM_H
#define DFVM_H

#include <stdio.h>
#include "proto.h"
#include "dfilter-int.h"
#include "syntax-tree.h"
#include "drange.h"

typedef enum {
	EMPTY,
	FVALUE,
	FIELD_ID,
	INSN_NUMBER,
	REGISTER,
	INTEGER,
	DRANGE
} dfvm_value_type_t;

typedef struct {
	dfvm_value_type_t	type;

	union {
		fvalue_t	*fvalue;
		guint32		numeric;
		drange		*drange;
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
