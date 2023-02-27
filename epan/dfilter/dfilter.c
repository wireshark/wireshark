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
#include "dfilter-macro.h"
#include "scanner_lex.h"
#include <wsutil/wslog.h>
#include <wsutil/ws_assert.h>
#include "grammar.h"


#define DFILTER_TOKEN_ID_OFFSET	1

/* Scanner's lval */
extern stnode_t *df_lval;

/* Holds the singular instance of our Lemon parser object */
static void*	ParserObj = NULL;

/*
 * XXX - if we're using a version of Flex that supports reentrant lexical
 * analyzers, we should put this into the lexical analyzer's state.
 */
dfwork_t *global_dfw;

df_loc_t loc_empty = {-1, 0};

void
dfilter_vfail(dfwork_t *dfw, int code, df_loc_t loc,
				const char *format, va_list args)
{
	dfw->parse_failure = TRUE;

	/* If we've already reported one error, don't overwite it */
	if (dfw->error.code < 0 || dfw->error.msg != NULL)
		return;

	dfw->error.code = code;
	dfw->error.msg = ws_strdup_vprintf(format, args);
	dfw->error.loc = loc;
}

void
dfilter_fail(dfwork_t *dfw, int code, df_loc_t loc,
				const char *format, ...)
{
	va_list	args;

	va_start(args, format);
	dfilter_vfail(dfw, code, loc, format, args);
	va_end(args);
}

void
dfilter_fail_throw(dfwork_t *dfw, int code, df_loc_t loc, const char *format, ...)
{
	va_list	args;

	va_start(args, format);
	dfilter_vfail(dfw, code, loc, format, args);
	va_end(args);
	THROW(TypeError);
}

void
dfw_set_error_location(dfwork_t *dfw, df_loc_t loc)
{
	dfw->error.loc = loc;
}

header_field_info *
dfilter_resolve_unparsed(dfwork_t *dfw, const char *name)
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
		if (dfw)
			add_deprecated_token(dfw, name);
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

	dfilter_macro_init();
}

/* Clean-up the dfilter module */
void
dfilter_cleanup(void)
{
	dfilter_macro_cleanup();

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
	g_ptr_array_free(insns, TRUE);
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

	if (df->warnings)
		g_slist_free_full(df->warnings, g_free);

	g_free(df->registers);
	g_free(df->attempted_load);
	g_free(df->free_registers);
	g_free(df->expanded_text);
	g_free(df->syntax_tree_str);
	g_free(df);
}

static void free_refs_array(gpointer data)
{
	/* Array data must be freed. */
	(void)g_ptr_array_free(data, TRUE);
}


static dfwork_t*
dfwork_new(void)
{
	dfwork_t *dfw = g_new0(dfwork_t, 1);

	dfw_error_init(&dfw->error);
	dfw->warnings = NULL;

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
		case TOKEN_CONSTANT:	return "CONSTANT";
		case TOKEN_LITERAL:	return "LITERAL";
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
	}
	return "<unknown>";
}

void
add_deprecated_token(dfwork_t *dfw, const char *token)
{
	if (dfw->deprecated == NULL)
		dfw->deprecated  = g_ptr_array_new_full(0, g_free);

	GPtrArray *deprecated = dfw->deprecated;

	for (guint i = 0; i < deprecated->len; i++) {
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
dfilter_expand(const char *expr, char **err_ret)
{
	return dfilter_macro_apply(expr, err_ret);
}

gboolean
dfilter_compile_real(const gchar *text, dfilter_t **dfp,
			df_error_t **errpp, unsigned flags,
			const char *caller)
{
	int		token;
	dfilter_t	*dfilter;
	dfwork_t	*dfw;
	df_scanner_state_t state;
	yyscan_t	scanner;
	YY_BUFFER_STATE in_buffer;
	gboolean failure = FALSE;
	unsigned token_count = 0;
	char		*tree_str;

	ws_assert(dfp);
	*dfp = NULL;

	if (text == NULL) {
		ws_debug("%s() called from %s() with null filter",
			__func__, caller);
		/* XXX This BUG happens often. Some callers are ignoring these errors. */
		dfw_error_set_msg(errpp, "BUG: NULL text pointer passed to dfilter_compile");
		return FALSE;
	}
	else if (*text == '\0') {
		/* An empty filter is considered a valid input. */
		ws_debug("%s() called from %s() with empty filter",
			__func__, caller);
	}
	else {
		ws_debug("%s() called from %s(), compiling filter: %s",
			__func__, caller, text);
	}

	dfw = dfwork_new();
	dfw->apply_optimization = flags & DF_OPTIMIZE;

	if (flags & DF_EXPAND_MACROS) {
		dfw->expanded_text = dfilter_macro_apply(text, &dfw->error.msg);
		if (dfw->expanded_text == NULL) {
			goto FAILURE;
		}
		ws_noisy("Expanded text: %s", dfw->expanded_text);
	}
	else {
		dfw->expanded_text = g_strdup(text);
		ws_noisy("Verbatim text: %s", dfw->expanded_text);
	}

	if (df_yylex_init(&scanner) != 0) {
		dfw_error_set_msg(errpp, "Can't initialize scanner: %s", g_strerror(errno));
		goto FAILURE;
	}

	in_buffer = df_yy_scan_string(dfw->expanded_text, scanner);

	memset(&state, 0, sizeof(state));
	state.dfw = dfw;

	df_yyset_extra(&state, scanner);

#ifdef NDEBUG
	if (flags & DF_DEBUG_FLEX || flags & DF_DEBUG_LEMON) {
		ws_message("Compile Wireshark without NDEBUG to enable Flex and/or Lemon debug traces");
	}
#else
	/* Enable/disable debugging for Flex. */
	df_yyset_debug(flags & DF_DEBUG_FLEX, scanner);

	/* Enable/disable debugging for Lemon. */
	DfilterTrace(flags & DF_DEBUG_LEMON ? stderr : NULL, "lemon> ");
#endif

	while (1) {
		token = df_yylex(scanner);

		/* Check for scanner failure */
		if (token == SCAN_FAILED) {
			ws_noisy("Scanning failed");
			failure = TRUE;
			break;
		}

		/* Check for end-of-input */
		if (token == 0) {
			ws_noisy("Scanning finished");
			break;
		}

		ws_noisy("(%u) Token %d %s %s",
				++token_count, token, tokenstr(token),
				stnode_token(state.df_lval));

		/* Give the token to the parser */
		Dfilter(ParserObj, token, state.df_lval, dfw);
		/* The parser has freed the lval for us. */
		state.df_lval = NULL;

		if (dfw->parse_failure) {
			failure = TRUE;
			break;
		}

	} /* while (1) */

	/* If we created a df_lval_t but didn't use it, free it; the
	 * parser doesn't know about it and won't free it for us. */
	if (state.df_lval) {
		stnode_free(state.df_lval);
		state.df_lval = NULL;
	}

	/* Tell the parser that we have reached the end of input; that
	 * way, it'll reset its state for the next compile.  (We want
	 * to do that even if we got a syntax error, to make sure the
	 * parser state is cleaned up; we don't create a new parser
	 * object when we start a new parse, and don't destroy it when
	 * the parse finishes.) */
	Dfilter(ParserObj, 0, NULL, dfw);

	/* One last check for syntax error (after EOF) */
	if (dfw->parse_failure)
		failure = TRUE;

	/* Free scanner state */
	if (state.quoted_string != NULL)
		g_string_free(state.quoted_string, TRUE);
	df_yy_delete_buffer(in_buffer, scanner);
	df_yylex_destroy(scanner);

	if (failure)
		goto FAILURE;

	/* Success, but was it an empty filter? If so, discard
	 * it and set *dfp to NULL */
	if (dfw->st_root == NULL) {
		*dfp = NULL;
	}
	else {
		log_syntax_tree(LOG_LEVEL_NOISY, dfw->st_root, "Syntax tree before semantic check", NULL);

		/* Check semantics and do necessary type conversion*/
		if (!dfw_semcheck(dfw)) {
			goto FAILURE;
		}

		/* Cache tree representation in tree_str. */
		tree_str = NULL;
		log_syntax_tree(LOG_LEVEL_NOISY, dfw->st_root, "Syntax tree after successful semantic check", &tree_str);

		if ((flags & DF_SAVE_TREE) && tree_str == NULL) {
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

		if (flags & DF_SAVE_TREE) {
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
		dfilter->registers = g_new0(GSList *, dfilter->num_registers);
		dfilter->attempted_load = g_new0(gboolean, dfilter->num_registers);
		dfilter->free_registers = g_new0(GDestroyNotify, dfilter->num_registers);

		/* And give it to the user. */
		*dfp = dfilter;
	}
	/* SUCCESS */
	global_dfw = NULL;
	dfwork_free(dfw);
	if (*dfp != NULL)
		ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO, "Compiled display filter: %s", text);
	else
		ws_debug("Compiled empty filter (successfully).");
	return TRUE;

FAILURE:
	ws_assert(dfw);
	if (dfw->error.msg == NULL) {
		/* We require an error message. */
		ws_critical("Unknown error compiling filter: %s", text);
		dfw_error_set_msg(errpp, "Unknown error compiling filter: %s", text);
	}
	else {
		ws_debug("Compiling filter failed with error: %s.", dfw->error.msg);
		dfw_error_take(errpp, &dfw->error);
	}

	global_dfw = NULL;
	dfwork_free(dfw);
	*dfp = NULL;
	return FALSE;
}


gboolean
dfilter_apply(dfilter_t *df, proto_tree *tree)
{
	return dfvm_apply(df, tree);
}

gboolean
dfilter_apply_edt(dfilter_t *df, epan_dissect_t* edt)
{
	return dfvm_apply(df, edt->tree);
}


void
dfilter_prime_proto_tree(const dfilter_t *df, proto_tree *tree)
{
	int i;

	for (i = 0; i < df->num_interesting_fields; i++) {
		proto_tree_prime_with_hfid(tree, df->interesting_fields[i]);
	}
}

gboolean
dfilter_has_interesting_fields(const dfilter_t *df)
{
	return (df->num_interesting_fields > 0);
}

gboolean
dfilter_interested_in_field(const dfilter_t *df, int hfid)
{
	int i;

	for (i = 0; i < df->num_interesting_fields; i++) {
		if (df->interesting_fields[i] == hfid) {
			return TRUE;
		}
	}
	return FALSE;
}

gboolean
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
				return TRUE;
			}
		} else {
			if (proto_registrar_get_parent(df_hfid) == proto_id) {
				return TRUE;
			}
		}
	}
	return FALSE;
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

	char *str = dfvm_dump_str(NULL, df, TRUE);
	if (G_UNLIKELY(msg == NULL))
		ws_log_write_always_full(domain, level, file, line, func, "\nFilter:\n %s\n\n%s", dfilter_text(df), str);
	else
		ws_log_write_always_full(domain, level, file, line, func, "%s:\nFilter:\n %s\n\n%s", msg, dfilter_text(df), str);
	g_free(str);
}

static int
compare_ref_layer(gconstpointer _a, gconstpointer _b)
{
	const df_reference_t *a = *(const df_reference_t **)_a;
	const df_reference_t *b = *(const df_reference_t **)_b;
	return a->proto_layer_num - b->proto_layer_num;
}

static void
load_references(GHashTable *table, proto_tree *tree, gboolean raw)
{
	GHashTableIter iter;
	GPtrArray *finfos;
	field_info *finfo;
	header_field_info *hfinfo;
	GPtrArray *refs;
	int i, len;

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
			if ((finfos == NULL) || (g_ptr_array_len(finfos) == 0)) {
				hfinfo = hfinfo->same_name_next;
				continue;
			}

			len = finfos->len;
			for (i = 0; i < len; i++) {
				finfo = g_ptr_array_index(finfos, i);
				g_ptr_array_add(refs, reference_new(finfo, raw));
			}

			hfinfo = hfinfo->same_name_next;
		}

		g_ptr_array_sort(refs, compare_ref_layer);
	}
}

void
dfilter_load_field_references(const dfilter_t *df, proto_tree *tree)
{
	load_references(df->references, tree, FALSE);
	load_references(df->raw_references, tree, TRUE);
}

df_reference_t *
reference_new(const field_info *finfo, gboolean raw)
{
	df_reference_t *ref = g_new(df_reference_t, 1);
	ref->hfinfo = finfo->hfinfo;
	if (raw) {
		ref->value = dfvm_get_raw_fvalue(finfo);
	}
	else {
		ref->value = fvalue_dup(&finfo->value);
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

void
dfw_error_init(df_error_t *err) {
	err->code = 0;
	err->msg = NULL;
	err->loc.col_start = -1;
	err->loc.col_len = 0;
}

void
dfw_error_clear(df_error_t *err) {
	g_free(err->msg);
	dfw_error_init(err);
}

void
dfw_error_set_msg(df_error_t **errpp, const char *fmt, ...)
{
	if (errpp == NULL) {
		return;
	}
	va_list ap;

	df_error_t *errp = g_new(df_error_t, 1);
	errp->code = DF_ERROR_GENERIC;
	va_start(ap, fmt);
	errp->msg = ws_strdup_vprintf(fmt, ap);
	va_end(ap);
	errp->loc.col_start = -1;
	errp->loc.col_len = 0;
	*errpp = errp;
}

void
dfw_error_take(df_error_t **errpp, df_error_t *src)
{
	if (errpp == NULL) {
		g_free(src->msg);
		dfw_error_init(src);
		return;
	}
	df_error_t *errp = g_new(df_error_t, 1);
	errp->code = src->code;
	errp->msg = src->msg;
	errp->loc = src->loc;
	*errpp = errp;
	dfw_error_init(src);
}

void
dfilter_error_free(df_error_t *errp)
{
	if (errp == NULL)
		return;
	g_free(errp->msg);
	g_free(errp);
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
