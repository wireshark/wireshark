/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_DFILTER

#include <stdio.h>
#include <string.h>

#include "dfilter-int.h"
#include "syntax-tree.h"
#include "gencode.h"
#include "semcheck.h"
#include "dfvm.h"
#include <epan/epan_dissect.h>
#include <epan/exceptions.h>
#include "dfilter.h"
#include "dfunctions.h"
#include "dfilter-macro.h"
#include "dfilter-plugin.h"
#include "scanner_lex.h"
#include <wsutil/wslog.h>
#include <wsutil/ws_assert.h>
#include "grammar.h"


#define DFILTER_TOKEN_ID_OFFSET	1

/* Holds the singular instance of our Lemon parser object */
static void*	ParserObj;

df_loc_t loc_empty = {-1, 0};

void
dfilter_vfail(void *state, int code, df_loc_t loc,
				const char *format, va_list args)
{
	df_error_t **ptr = &((dfstate_t *)state)->error;
	/* If we've already reported one error, don't overwite it */
	if (*ptr != NULL)
		return;

	*ptr = df_error_new_vprintf(code, &loc, format, args);
}

void
dfilter_fail(void *state, int code, df_loc_t loc,
				const char *format, ...)
{
	va_list	args;

	va_start(args, format);
	dfilter_vfail(state, code, loc, format, args);
	va_end(args);
}

void
dfilter_fail_throw(void *state, int code, df_loc_t loc, const char *format, ...)
{
	va_list	args;

	va_start(args, format);
	dfilter_vfail(state, code, loc, format, args);
	va_end(args);
	THROW(TypeError);
}

void
dfw_set_error_location(dfwork_t *dfw, df_loc_t loc)
{
	ws_assert(dfw->error);
	dfw->error->loc = loc;
}

header_field_info *
dfilter_resolve_unparsed(const char *name, GPtrArray *deprecated)
{
	header_field_info *hfinfo;

	hfinfo = proto_registrar_get_byname(name);
	if (hfinfo != NULL) {
		/* It's a field name */
		return hfinfo;
	}

	hfinfo = proto_registrar_get_byalias(name);
	if (hfinfo != NULL) {
		/* It's an aliased field name */
		if (deprecated)
			add_deprecated_token(deprecated, name);
		return hfinfo;
	}

	/* It's not a field. */
	return NULL;
}

/* Initialize the dfilter module */
void
dfilter_init(void)
{
	if (ParserObj) {
		ws_message("I expected ParserObj to be NULL\n");
		/* Free the Lemon Parser object */
		DfilterFree(ParserObj, g_free);
	}
	/* Allocate an instance of our Lemon-based parser */
	ParserObj = DfilterAlloc(g_malloc);

	/* Initialize the syntax-tree sub-sub-system */
	sttype_init();

	df_func_init();
	dfilter_macro_init();
	dfilter_plugins_init();
}

/* Clean-up the dfilter module */
void
dfilter_cleanup(void)
{
	dfilter_plugins_cleanup();
	dfilter_macro_cleanup();
	df_func_cleanup();

	/* Free the Lemon Parser object */
	if (ParserObj) {
		DfilterFree(ParserObj, g_free);
	}

	/* Clean up the syntax-tree sub-sub-system */
	sttype_cleanup();
}

static dfilter_t*
dfilter_new(GPtrArray *deprecated)
{
	dfilter_t	*df;

	df = g_new0(dfilter_t, 1);
	df->insns = NULL;
	df->function_stack = NULL;
	df->set_stack = NULL;
	df->warnings = NULL;
	if (deprecated)
		df->deprecated = g_ptr_array_ref(deprecated);
	return df;
}

/* Given a GPtrArray of instructions (dfvm_insn_t),
 * free them. */
static void
free_insns(GPtrArray *insns)
{
	unsigned int	i;
	dfvm_insn_t	*insn;

	for (i = 0; i < insns->len; i++) {
		insn = (dfvm_insn_t	*)g_ptr_array_index(insns, i);
		dfvm_insn_free(insn);
	}
	g_ptr_array_free(insns, true);
}

void
dfilter_free(dfilter_t *df)
{
	if (!df)
		return;

	if (df->insns) {
		free_insns(df->insns);
	}

	g_free(df->interesting_fields);

	g_hash_table_destroy(df->references);
	g_hash_table_destroy(df->raw_references);

	if (df->deprecated)
		g_ptr_array_unref(df->deprecated);

	if (df->function_stack != NULL) {
		ws_critical("Function stack list should be NULL");
		g_slist_free(df->function_stack);
	}

	if (df->set_stack != NULL) {
		ws_critical("Set stack list should be NULL");
		g_slist_free(df->set_stack);
	}

	if (df->warnings)
		g_slist_free_full(df->warnings, g_free);

	g_free(df->registers);
	g_free(df->expanded_text);
	g_free(df->syntax_tree_str);
	g_free(df);
}

static void free_refs_array(void *data)
{
	/* Array data must be freed. */
	(void)g_ptr_array_free(data, true);
}

static dfsyntax_t*
dfsyntax_new(unsigned flags)
{
	dfsyntax_t *dfs = g_new0(dfsyntax_t, 1);
	dfs->deprecated  = g_ptr_array_new_full(0, g_free);
	dfs->flags = flags;
	return dfs;
}

static void
dfsyntax_free(dfsyntax_t *dfs)
{
	if (dfs->error)
		df_error_free(&dfs->error);

	if (dfs->st_root)
		stnode_free(dfs->st_root);

	if (dfs->deprecated)
		g_ptr_array_unref(dfs->deprecated);

	if (dfs->lval)
		stnode_free(dfs->lval);

	if (dfs->quoted_string)
		g_string_free(dfs->quoted_string, TRUE);



	g_free(dfs);
}

static dfwork_t*
dfwork_new(const char *expanded_text, unsigned flags)
{
	dfwork_t *dfw = g_new0(dfwork_t, 1);
	dfw->expanded_text = g_strdup(expanded_text);
	dfw->flags = flags;

	dfw->references =
		g_hash_table_new_full(g_direct_hash, g_direct_equal,
				NULL, (GDestroyNotify)free_refs_array);

	dfw->raw_references =
		g_hash_table_new_full(g_direct_hash, g_direct_equal,
				NULL, (GDestroyNotify)free_refs_array);

	dfw->dfw_scope = wmem_allocator_new(WMEM_ALLOCATOR_SIMPLE);

	return dfw;
}

static void
dfwork_free(dfwork_t *dfw)
{
	if (dfw->st_root) {
		stnode_free(dfw->st_root);
	}

	if (dfw->loaded_fields) {
		g_hash_table_destroy(dfw->loaded_fields);
	}

	if (dfw->loaded_raw_fields) {
		g_hash_table_destroy(dfw->loaded_raw_fields);
	}

	if (dfw->interesting_fields) {
		g_hash_table_destroy(dfw->interesting_fields);
	}

	if (dfw->references) {
		g_hash_table_destroy(dfw->references);
	}

	if (dfw->raw_references) {
		g_hash_table_destroy(dfw->raw_references);
	}

	if (dfw->insns) {
		free_insns(dfw->insns);
	}

	if (dfw->deprecated)
		g_ptr_array_unref(dfw->deprecated);

	if (dfw->warnings)
		g_slist_free_full(dfw->warnings, g_free);

	g_free(dfw->expanded_text);

	if (dfw->error)
		df_error_free(&dfw->error);

	wmem_destroy_allocator(dfw->dfw_scope);

	/*
	 * We don't free the error message string; our caller will return
	 * it to its caller.
	 */
	g_free(dfw);
}

const char *tokenstr(int token)
{
	switch (token) {
		case TOKEN_TEST_AND:	return "TEST_AND";
		case TOKEN_TEST_OR: 	return "TEST_OR";
		case TOKEN_TEST_XOR: 	return "TEST_XOR";
		case TOKEN_TEST_ALL_EQ:	return "TEST_ALL_EQ";
		case TOKEN_TEST_ANY_EQ:	return "TEST_ANY_EQ";
		case TOKEN_TEST_ALL_NE:	return "TEST_ALL_NE";
		case TOKEN_TEST_ANY_NE:	return "TEST_ANY_NE";
		case TOKEN_TEST_LT:	return "TEST_LT";
		case TOKEN_TEST_LE:	return "TEST_LE";
		case TOKEN_TEST_GT:	return "TEST_GT";
		case TOKEN_TEST_GE:	return "TEST_GE";
		case TOKEN_TEST_CONTAINS: return "TEST_CONTAINS";
		case TOKEN_TEST_MATCHES: return "TEST_MATCHES";
		case TOKEN_BITWISE_AND: return "BITWISE_AND";
		case TOKEN_PLUS:	return "PLUS";
		case TOKEN_MINUS:	return "MINUS";
		case TOKEN_STAR:	return "STAR";
		case TOKEN_RSLASH:	return "RSLASH";
		case TOKEN_PERCENT:	return "PERCENT";
		case TOKEN_TEST_NOT:	return "TEST_NOT";
		case TOKEN_STRING:	return "STRING";
		case TOKEN_CHARCONST:	return "CHARCONST";
		case TOKEN_IDENTIFIER:	return "IDENTIFIER";
		case TOKEN_UNPARSED:	return "UNPARSED";
		case TOKEN_LITERAL:	return "LITERAL";
		case TOKEN_NUMBER:	return "NUMBER";
		case TOKEN_FIELD:	return "FIELD";
		case TOKEN_LBRACKET:	return "LBRACKET";
		case TOKEN_RBRACKET:	return "RBRACKET";
		case TOKEN_COMMA:	return "COMMA";
		case TOKEN_RANGE_NODE:	return "RANGE_NODE";
		case TOKEN_TEST_IN:	return "TEST_IN";
		case TOKEN_LBRACE:	return "LBRACE";
		case TOKEN_RBRACE:	return "RBRACE";
		case TOKEN_DOTDOT:	return "DOTDOT";
		case TOKEN_LPAREN:	return "LPAREN";
		case TOKEN_RPAREN:	return "RPAREN";
		case TOKEN_DOLLAR:	return "DOLLAR";
		case TOKEN_ATSIGN:	return "ATSIGN";
		case TOKEN_HASH:	return "HASH";
		case TOKEN_INDEX:	return "INDEX";
	}
	return "<unknown>";
}

void
add_deprecated_token(GPtrArray *deprecated, const char *token)
{
	for (unsigned i = 0; i < deprecated->len; i++) {
		const char *str = g_ptr_array_index(deprecated, i);
		if (g_ascii_strcasecmp(token, str) == 0) {
			/* It's already in our list */
			return;
		}
	}
	g_ptr_array_add(deprecated, g_strdup(token));
}

void
add_compile_warning(dfwork_t *dfw, const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	char *msg = ws_strdup_vprintf(format, ap);
	va_end(ap);
	dfw->warnings = g_slist_prepend(dfw->warnings, msg);
}

char *
dfilter_expand(const char *expr, df_error_t **err_ret)
{
	return dfilter_macro_apply(expr, err_ret);
}

static bool
dfwork_parse(const char *expanded_text, dfsyntax_t *dfs)
{
	yyscan_t	scanner;
	YY_BUFFER_STATE in_buffer;
	unsigned token_count = 0;
	int		token;

	if (df_yylex_init(&scanner) != 0) {
		dfs->error = df_error_new_printf(DF_ERROR_GENERIC, NULL, "Can't initialize scanner: %s", g_strerror(errno));
		return false;
	}

	in_buffer = df_yy_scan_string(expanded_text, scanner);
	df_yyset_extra(dfs, scanner);

#ifdef NDEBUG
	if (dfs->flags & DF_DEBUG_FLEX || dfs->flags & DF_DEBUG_LEMON) {
		ws_message("Compile Wireshark without NDEBUG to enable Flex and/or Lemon debug traces");
	}
#else
	/* Enable/disable debugging for Flex. */
	df_yyset_debug(dfs->flags & DF_DEBUG_FLEX, scanner);

	/* Enable/disable debugging for Lemon. */
	DfilterTrace(dfs->flags & DF_DEBUG_LEMON ? stderr : NULL, "lemon> ");
#endif

	while (1) {
		token = df_yylex(scanner);

		/* Check for scanner failure */
		if (token == SCAN_FAILED) {
			ws_noisy("Scanning failed");
			ws_assert(dfs->error != NULL);
			break;
		}

		/* Check for end-of-input */
		if (token == 0) {
			ws_noisy("Scanning finished");
			break;
		}

		ws_noisy("(%u) Token %d %s %s",
				++token_count, token, tokenstr(token),
				stnode_token(dfs->lval));

		/* Give the token to the parser */
		Dfilter(ParserObj, token, dfs->lval, dfs);
		/* The parser has freed the lval for us. */
		dfs->lval = NULL;

		if (dfs->error) {
			break;
		}

	} /* while (1) */

	/* Tell the parser that we have reached the end of input; that
	 * way, it'll reset its state for the next compile.  (We want
	 * to do that even if we got a syntax error, to make sure the
	 * parser state is cleaned up; we don't create a new parser
	 * object when we start a new parse, and don't destroy it when
	 * the parse finishes.) */
	Dfilter(ParserObj, 0, NULL, dfs);

	/* Free scanner state */
	df_yy_delete_buffer(in_buffer, scanner);
	df_yylex_destroy(scanner);

	return dfs->error == NULL;
}

static dfilter_t *
dfwork_build(dfwork_t *dfw)
{
	dfilter_t	*dfilter;
	char		*tree_str;

	log_syntax_tree(LOG_LEVEL_NOISY, dfw->st_root, "Syntax tree before semantic check", NULL);

	/* Check semantics and do necessary type conversion*/
	if (!dfw_semcheck(dfw))
		return NULL;

	/* Cache tree representation in tree_str. */
	tree_str = NULL;
	log_syntax_tree(LOG_LEVEL_NOISY, dfw->st_root, "Syntax tree after successful semantic check", &tree_str);

	if ((dfw->flags & DF_SAVE_TREE) && tree_str == NULL) {
		tree_str = dump_syntax_tree_str(dfw->st_root);
	}

	/* Create bytecode */
	dfw_gencode(dfw);

	/* Tuck away the bytecode in the dfilter_t */
	dfilter = dfilter_new(dfw->deprecated);
	dfilter->insns = dfw->insns;
	dfw->insns = NULL;
	dfilter->interesting_fields = dfw_interesting_fields(dfw,
		&dfilter->num_interesting_fields);
	dfilter->expanded_text = dfw->expanded_text;
	dfw->expanded_text = NULL;
	dfilter->references = dfw->references;
	dfw->references = NULL;
	dfilter->raw_references = dfw->raw_references;
	dfw->raw_references = NULL;
	dfilter->warnings = dfw->warnings;
	dfw->warnings = NULL;

	if (dfw->flags & DF_SAVE_TREE) {
		ws_assert(tree_str);
		dfilter->syntax_tree_str = tree_str;
		tree_str = NULL;
	}
	else {
		dfilter->syntax_tree_str = NULL;
		g_free(tree_str);
		tree_str = NULL;
	}

	/* Initialize run-time space */
	dfilter->num_registers = dfw->next_register;
	dfilter->registers = g_new0(df_cell_t, dfilter->num_registers);

	return dfilter;
}

static dfilter_t *
compile_filter(const char *expanded_text, unsigned flags, df_error_t **err_ptr)
{
	dfsyntax_t *dfs = NULL;
	dfwork_t *dfw = NULL;
	dfilter_t *dfcode = NULL;
	df_error_t *error = NULL;
	bool ok;

	dfs = dfsyntax_new(flags);

	ok = dfwork_parse(expanded_text, dfs);
	if (!ok) {
		error = dfs->error;
		dfs->error = NULL;
		goto FAILURE;
	}
	else if (dfs->st_root == NULL) {
		/* Is it an empty filter? If so set the dfcode to NULL and return success.
		 * This can happen if the user clears the display filter toolbar in the UI.
		 * In that case the compilation succeeds and the NULL dfcode clears the filter
		 * (show all frames). */
		dfsyntax_free(dfs);
		*err_ptr = NULL;
		return NULL;
	}

	dfw = dfwork_new(expanded_text, dfs->flags);
	dfw->st_root = dfs->st_root;
	dfs->st_root = NULL;
	dfw->deprecated = g_ptr_array_ref(dfs->deprecated);
	dfsyntax_free(dfs);
	dfs = NULL;

	dfcode = dfwork_build(dfw);
	if (dfcode == NULL) {
		error = dfw->error;
		dfw->error = NULL;
		goto FAILURE;
	}

	/* SUCCESS */
	dfwork_free(dfw);
	return dfcode;

FAILURE:
	if (error == NULL || error->msg == NULL) {
		/* We require an error message. */
		ws_critical("Unknown error compiling filter: %s", expanded_text);
		error = df_error_new_msg("Unknown error compiling filter");
	}

	ws_assert(err_ptr && error);
	*err_ptr = error;

	if (dfs)
		dfsyntax_free(dfs);
	if (dfw)
		dfwork_free(dfw);
	return NULL;
}

static inline bool
compile_failure(df_error_t *error, df_error_t **err_ptr)
{
	ws_assert(error);
	ws_debug("Error compiling filter: (%d) %s", error->code, error->msg);

	if (err_ptr)
		*err_ptr = error;
	else
		df_error_free(&error);

	return false;
}

bool
dfilter_compile_full(const char *text, dfilter_t **dfp,
			df_error_t **err_ptr, unsigned flags,
			const char *caller)
{
	char *expanded_text;
	dfilter_t *dfcode;
	df_error_t *error = NULL;

	ws_assert(dfp);
	*dfp = NULL;
	if (caller == NULL)
		caller = "(unknown)";

	if (text == NULL) {
		/* This is a bug. */
		ws_warning("Called from %s() with invalid NULL expression", caller);
		if (err_ptr) {
			*err_ptr = df_error_new_msg("BUG: NULL text argument is invalid");
		}
		return false;
	}

	ws_debug("Called from %s() with filter: %s", caller, text);

	if (flags & DF_EXPAND_MACROS) {
		expanded_text = dfilter_macro_apply(text, &error);
		if (expanded_text == NULL) {
			return compile_failure(error, err_ptr);
		}
		ws_noisy("Expanded text: %s", expanded_text);
	}
	else {
		expanded_text = g_strdup(text);
		ws_noisy("Verbatim text: %s", expanded_text);
	}

	dfcode = compile_filter(expanded_text, flags, &error);
	g_free(expanded_text);
	expanded_text = NULL;

	if(error != NULL) {
		return compile_failure(error, err_ptr);
	}

	*dfp = dfcode;
	ws_info("Compiled display filter: %s", text);
	return true;
}

struct stnode *dfilter_get_syntax_tree(const char *text)
{
	dfsyntax_t *dfs = NULL;
	dfwork_t *dfw = NULL;

	dfs = dfsyntax_new(DF_EXPAND_MACROS);

	char *expanded_text = dfilter_macro_apply(text, NULL);
	if (!expanded_text) {
		dfsyntax_free(dfs);
		return NULL;
	}

	bool ok = dfwork_parse(expanded_text, dfs);
	if (!ok || !dfs->st_root) {
		g_free(expanded_text);
		dfsyntax_free(dfs);
		return NULL;
	}

	dfw = dfwork_new(expanded_text, dfs->flags);
	dfw->st_root = dfs->st_root;
	dfs->st_root = NULL;
	g_free(expanded_text);
	dfsyntax_free(dfs);

	if (!dfw_semcheck(dfw)) {
		dfwork_free(dfw);
		return NULL;
	}

	stnode_t *st_root = dfw->st_root;
	dfw->st_root = NULL;
	dfwork_free(dfw);

	return st_root;
}

bool
dfilter_apply(dfilter_t *df, proto_tree *tree)
{
	return dfvm_apply(df, tree);
}

bool
dfilter_apply_edt(dfilter_t *df, epan_dissect_t* edt)
{
	return dfvm_apply(df, edt->tree);
}

bool
dfilter_apply_full(dfilter_t *df, proto_tree *tree, GPtrArray **fvals)
{
	return dfvm_apply_full(df, tree, fvals);
}

void
dfilter_prime_proto_tree(const dfilter_t *df, proto_tree *tree)
{
	int i;

	for (i = 0; i < df->num_interesting_fields; i++) {
		proto_tree_prime_with_hfid(tree, df->interesting_fields[i]);
	}
}

bool
dfilter_has_interesting_fields(const dfilter_t *df)
{
	return (df->num_interesting_fields > 0);
}

bool
dfilter_interested_in_field(const dfilter_t *df, int hfid)
{
	int i;

	for (i = 0; i < df->num_interesting_fields; i++) {
		if (df->interesting_fields[i] == hfid) {
			return true;
		}
	}
	return false;
}

bool
dfilter_interested_in_proto(const dfilter_t *df, int proto_id)
{
	int i;

	for (i = 0; i < df->num_interesting_fields; i++) {
		int df_hfid = df->interesting_fields[i];
		if (proto_registrar_is_protocol(df_hfid)) {
			/* XXX: Should we go up to the parent of a pino?
			 * We can tell if df_hfid is a PINO, but there's
			 * no function to return the parent proto ID yet.
			 */
			if (df_hfid == proto_id) {
				return true;
			}
		} else {
			if (proto_registrar_get_parent(df_hfid) == proto_id) {
				return true;
			}
		}
	}
	return false;
}

bool
dfilter_requires_columns(const dfilter_t *df)
{
	if (df == NULL) {
		return false;
	}

	/* XXX: Could cache this like packet_cache_proto_handles */
	static int proto_cols;
	if (proto_cols <= 0) {
		proto_cols = proto_get_id_by_filter_name("_ws.col");
	}
	ws_assert(proto_cols > 0);

	return dfilter_interested_in_proto(df, proto_cols);
}

GPtrArray *
dfilter_deprecated_tokens(dfilter_t *df) {
	if (df->deprecated && df->deprecated->len > 0) {
		return df->deprecated;
	}
	return NULL;
}

GSList *
dfilter_get_warnings(dfilter_t *df)
{
	return df->warnings;
}

void
dfilter_dump(FILE *fp, dfilter_t *df, uint16_t flags)
{
	dfvm_dump(fp, df, flags);
}

const char *
dfilter_text(dfilter_t *df)
{
	return df->expanded_text;
}

const char *
dfilter_syntax_tree(dfilter_t *df)
{
	return df->syntax_tree_str;
}

void
dfilter_log_full(const char *domain, enum ws_log_level level,
			const char *file, long line, const char *func,
			dfilter_t *df, const char *msg)
{
	if (!ws_log_msg_is_active(domain, level))
		return;

	if (df == NULL) {
		ws_log_write_always_full(domain, level, file, line, func,
				"%s: NULL display filter", msg ? msg : "?");
		return;
	}

	char *str = dfvm_dump_str(NULL, df, true);
	if (G_UNLIKELY(msg == NULL))
		ws_log_write_always_full(domain, level, file, line, func, "\nFilter:\n %s\n\n%s", dfilter_text(df), str);
	else
		ws_log_write_always_full(domain, level, file, line, func, "%s:\nFilter:\n %s\n\n%s", msg, dfilter_text(df), str);
	g_free(str);
}

static int
compare_ref_layer(const void *_a, const void *_b)
{
	const df_reference_t *a = *(const df_reference_t **)_a;
	const df_reference_t *b = *(const df_reference_t **)_b;
	return a->proto_layer_num - b->proto_layer_num;
}

static void
load_references(GHashTable *table, proto_tree *tree, bool raw)
{
	GHashTableIter iter;
	GPtrArray *finfos;
	field_info *finfo;
	header_field_info *hfinfo;
	GPtrArray *refs;

	if (g_hash_table_size(table) == 0) {
		/* Nothing to do. */
		return;
	}

	g_hash_table_iter_init(&iter, table);
	while (g_hash_table_iter_next(&iter, (void **)&hfinfo, (void **)&refs)) {
		/* If we have a previous array free the data */
		g_ptr_array_set_size(refs, 0);

		while (hfinfo) {
			finfos = proto_find_finfo(tree, hfinfo->id);
			if (finfos == NULL) {
				hfinfo = hfinfo->same_name_next;
				continue;
			}
			for (unsigned i = 0; i < finfos->len; i++) {
				finfo = g_ptr_array_index(finfos, i);
				g_ptr_array_add(refs, reference_new(finfo, raw));
			}
			g_ptr_array_free(finfos, true);
			hfinfo = hfinfo->same_name_next;
		}

		g_ptr_array_sort(refs, compare_ref_layer);
	}
}

void
dfilter_load_field_references(const dfilter_t *df, proto_tree *tree)
{
	load_references(df->references, tree, false);
	load_references(df->raw_references, tree, true);
}

void
dfilter_load_field_references_edt(const dfilter_t *df, epan_dissect_t *edt)
{
	dfilter_load_field_references(df, edt->tree);
}

df_reference_t *
reference_new(const field_info *finfo, bool raw)
{
	df_reference_t *ref = g_new(df_reference_t, 1);
	ref->hfinfo = finfo->hfinfo;
	if (raw) {
		ref->value = dfvm_get_raw_fvalue(finfo);
	}
	else {
		ref->value = fvalue_dup(finfo->value);
	}
	ref->proto_layer_num = finfo->proto_layer_num;
	return ref;
}

void
reference_free(df_reference_t *ref)
{
	fvalue_free(ref->value);
	g_free(ref);
}

df_error_t *
df_error_new(int code, char *msg, df_loc_t *loc)
{
	df_error_t *err = g_new(df_error_t, 1);
	err->code = code;
	err->msg = msg;
	if (loc) {
		err->loc.col_start = loc->col_start;
		err->loc.col_len = loc->col_len;
	}
	else {
		err->loc.col_start = -1;
		err->loc.col_len = 0;
	}
	return err;
}

df_error_t *
df_error_new_vprintf(int code, df_loc_t *loc, const char *fmt, va_list ap)
{
	df_error_t *err = g_new(df_error_t, 1);
	err->code = code;
	err->msg = ws_strdup_vprintf(fmt, ap);
	if (loc) {
		err->loc.col_start = loc->col_start;
		err->loc.col_len = loc->col_len;
	}
	else {
		err->loc.col_start = -1;
		err->loc.col_len = 0;
	}
	return err;
}

df_error_t *
df_error_new_printf(int code, df_loc_t *loc, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	df_error_t *err = df_error_new_vprintf(code, loc, fmt, ap);
	va_end(ap);
	return err;
}

void
df_error_free(df_error_t **ep)
{
	if (*ep == NULL)
		return;
	g_free((*ep)->msg);
	g_free(*ep);
	*ep = NULL;
}

void
df_cell_append(df_cell_t *rp, fvalue_t *fv)
{
	/* Assert cell has been initialized. */
	ws_assert(rp->array != NULL);
	g_ptr_array_add(rp->array, fv);
}

GPtrArray *
df_cell_ref(df_cell_t *rp)
{
	if (rp->array == NULL)
		return NULL;
	return g_ptr_array_ref(rp->array);
}

size_t
df_cell_size(const df_cell_t *rp)
{
	if (rp->array == NULL)
		return 0;
	return rp->array->len;
}

fvalue_t **
df_cell_array(const df_cell_t *rp)
{
	if (rp->array == NULL)
		return NULL;
	return (fvalue_t **)rp->array->pdata;
}

bool
df_cell_is_empty(const df_cell_t *rp)
{
	if (rp->array == NULL)
		return true;
	return rp->array->len == 0;
}

bool
df_cell_is_null(const df_cell_t *rp)
{
	return rp->array == NULL;
}

void
df_cell_init(df_cell_t *rp, bool free_seg)
{
	df_cell_clear(rp);
	if (free_seg)
		rp->array = g_ptr_array_new_with_free_func((GDestroyNotify)fvalue_free);
	else
		rp->array = g_ptr_array_new();
}

void
df_cell_clear(df_cell_t *rp)
{
	if (rp->array)
		g_ptr_array_unref(rp->array);
	rp->array = NULL;
}

void
df_cell_iter_init(df_cell_t *rp, df_cell_iter_t *iter)
{
	iter->ptr = rp->array;
	iter->idx = 0;
}

fvalue_t *
df_cell_iter_next(df_cell_iter_t *iter)
{
	if (iter->idx < iter->ptr->len) {
		return iter->ptr->pdata[iter->idx++];
	}
	return NULL;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
