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

typedef struct {
	const header_field_info *hfinfo;
	fvalue_t *value;
	int proto_layer_num;
} df_reference_t;

typedef struct {
	GPtrArray *array;
} df_cell_t;

typedef struct {
	GPtrArray *ptr;
	unsigned idx;
} df_cell_iter_t;

/* Passed back to user */
struct epan_dfilter {
	GPtrArray	*insns;
	unsigned	num_registers;
	df_cell_t	*registers;
	int		*interesting_fields;
	int		num_interesting_fields;
	GPtrArray	*deprecated;
	GSList		*warnings;
	char		*expanded_text;
	GHashTable	*references;
	GHashTable	*raw_references;
	char		*syntax_tree_str;
	/* Used to pass arguments to functions. List of Lists (list of registers). */
	GSList		*function_stack;
	GSList		*set_stack;
};

typedef struct {
	df_error_t *error;
	/* more fields. */
} dfstate_t;

/*
 * State for first stage of compilation (parsing).
 */
typedef struct {
	df_error_t	*error;		/* Must be first struct field. */
	unsigned	flags;
	stnode_t	*st_root;
	GPtrArray	*deprecated;
	stnode_t	*lval;
	GString		*quoted_string;
	bool		raw_string;
	df_loc_t	string_loc;
	df_loc_t	location;
} dfsyntax_t;

/*
 * State for second stage of compilation (semantic check and code generation).
 */
typedef struct {
	df_error_t	*error;		/* Must be first struct field. */
	unsigned	flags;
	stnode_t	*st_root;
	unsigned	field_count;
	GPtrArray	*insns;
	GHashTable	*loaded_fields;
	GHashTable	*loaded_raw_fields;
	GHashTable	*interesting_fields;
	int		next_insn_id;
	int		next_register;
	GPtrArray	*deprecated;
	GHashTable	*references; /* hfinfo -> pointer to array of references */
	GHashTable	*raw_references; /* hfinfo -> pointer to array of references */
	char		*expanded_text;
	wmem_allocator_t *dfw_scope; /* Because we use exceptions for error handling sometimes
	                                cleaning up memory allocations is inconvenient. Memory
					allocated from this pool will be freed when the dfwork_t
					context is destroyed. */
	GSList		*warnings;
} dfwork_t;

/* Constructor/Destructor prototypes for Lemon Parser */
void *DfilterAlloc(void *(*)(size_t));

void DfilterFree(void *, void (*)(void *));

void Dfilter(void *, int, stnode_t *, dfsyntax_t *);

/* Return value for error in scanner. */
#define SCAN_FAILED	-1	/* not 0, as that means end-of-input */

void
dfilter_vfail(void *state, int code, df_loc_t err_loc,
			const char *format, va_list args);

void
dfilter_fail(void *state, int code, df_loc_t err_loc,
			const char *format, ...) G_GNUC_PRINTF(4, 5);

WS_NORETURN
void
dfilter_fail_throw(void *state, int code, df_loc_t err_loc,
			const char *format, ...) G_GNUC_PRINTF(4, 5);

void
dfw_set_error_location(dfwork_t *dfw, df_loc_t err_loc);

void
add_deprecated_token(dfsyntax_t *dfs, const char *token);

void
add_compile_warning(dfwork_t *dfw, const char *format, ...);

void
free_deprecated(GPtrArray *deprecated);

void
DfilterTrace(FILE *TraceFILE, char *zTracePrompt);

header_field_info *
dfilter_resolve_unparsed(dfsyntax_t *dfs, const char *name);

WS_RETNONNULL fvalue_t*
dfilter_fvalue_from_literal(dfwork_t *dfw, ftenum_t ftype, stnode_t *st,
		bool allow_partial_value, header_field_info *hfinfo_value_string);

WS_RETNONNULL fvalue_t *
dfilter_fvalue_from_string(dfwork_t *dfw, ftenum_t ftype, stnode_t *st,
		header_field_info *hfinfo_value_string);

WS_RETNONNULL fvalue_t *
dfilter_fvalue_from_charconst(dfwork_t *dfw, ftenum_t ftype, stnode_t *st);

const char *tokenstr(int token);

df_reference_t *
reference_new(const field_info *finfo, bool raw);

void
reference_free(df_reference_t *ref);

void
df_cell_append(df_cell_t *rp, fvalue_t *fv);

GPtrArray *
df_cell_ref(df_cell_t *rp);

#define df_cell_ptr(rp) ((rp)->array)

size_t
df_cell_size(const df_cell_t *rp);

fvalue_t **
df_cell_array(const df_cell_t *rp);

bool
df_cell_is_empty(const df_cell_t *rp);

bool
df_cell_is_null(const df_cell_t *rp);

/* Pass true to free the array contents when the cell is cleared. */
void
df_cell_init(df_cell_t *rp, bool free_seg);

void
df_cell_clear(df_cell_t *rp);

/* Cell must not be cleared while iter is alive. */
void
df_cell_iter_init(df_cell_t *rp, df_cell_iter_t *iter);

fvalue_t *
df_cell_iter_next(df_cell_iter_t *iter);


#endif
