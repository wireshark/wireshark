/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DFILTER_INT_H
#define DFILTER_INT_H

#include "dfilter.h"
#include "syntax-tree.h"

#include <epan/proto.h>
#include <stdio.h>

/* Passed back to user */
struct epan_dfilter {
	GPtrArray	*insns;
	GPtrArray	*consts;
	guint		num_registers;
	guint		max_registers;
	GList		**registers;
	gboolean	*attempted_load;
	gboolean	*owns_memory;
	int		*interesting_fields;
	int		num_interesting_fields;
	GPtrArray	*deprecated;
};

typedef struct {
	/* Syntax Tree stuff */
	stnode_t	*st_root;
	gboolean	syntax_error;
	gchar		*error_message;
	GPtrArray	*insns;
	GPtrArray	*consts;
	GHashTable	*loaded_fields;
	GHashTable	*interesting_fields;
	int		next_insn_id;
	int		next_const_id;
	int		next_register;
	int		first_constant; /* first register used as a constant */
	GPtrArray	*deprecated;
} dfwork_t;

/*
 * State kept by the scanner.
 */
typedef struct {
	dfwork_t *dfw;
	GString* quoted_string;
	gboolean raw_string;
} df_scanner_state_t;

typedef struct {
	char *value;
	unsigned long number;
} df_lval_t;

static inline df_lval_t *
df_lval_new(void)
{
	return g_new0(df_lval_t, 1);
}

static inline char *
df_lval_value(df_lval_t *lval)
{
	if (!lval || !lval->value)
		return NULL;
	return lval->value;
}

static inline unsigned long
df_lval_number(df_lval_t *lval)
{
	return lval->number;
}

static inline void
df_lval_free(df_lval_t *lval, gboolean free_value)
{
	if (lval) {
		if (free_value) {
			g_free(lval->value);
		}
		g_free(lval);
	}
}

/* Constructor/Destructor prototypes for Lemon Parser */
void *DfilterAlloc(void* (*)(gsize));

void DfilterFree(void*, void (*)(void *));

void Dfilter(void*, int, df_lval_t*, dfwork_t*);

/* Return value for error in scanner. */
#define SCAN_FAILED	-1	/* not 0, as that means end-of-input */

void
dfilter_vfail(dfwork_t *dfw, const char *format, va_list args);

void
dfilter_fail(dfwork_t *dfw, const char *format, ...) G_GNUC_PRINTF(2, 3);

void
dfilter_fail_throw(dfwork_t *dfw, long code, const char *format, ...) G_GNUC_PRINTF(3, 4);

void
add_deprecated_token(dfwork_t *dfw, const char *token);

void
free_deprecated(GPtrArray *deprecated);

void
DfilterTrace(FILE *TraceFILE, char *zTracePrompt);

header_field_info *
dfilter_resolve_unparsed(dfwork_t *dfw, const char *name);

char *
dfilter_literal_normalized(const char *token);

const char *tokenstr(int token);

#endif
