/*
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
} dfwork_t;

/*
 * State kept by the scanner.
 */
typedef struct {
	dfwork_t *dfw;
	GString* quoted_string;
	gboolean in_set;	/* true if parsing set elements for the membership operator */
} df_scanner_state_t;

/* Constructor/Destructor prototypes for Lemon Parser */
void *DfilterAlloc(void* (*)(gsize));

void DfilterFree(void*, void (*)(void *));
void Dfilter(void*, int, stnode_t*, dfwork_t*);

/* Scanner's lval */
extern stnode_t *df_lval;

/* Return value for error in scanner. */
#define SCAN_FAILED	-1	/* not 0, as that means end-of-input */

/* Set dfw->error_message */
void
dfilter_fail(dfwork_t *dfw, const char *format, ...) G_GNUC_PRINTF(2, 3);

void
DfilterTrace(FILE *TraceFILE, char *zTracePrompt);

#endif
