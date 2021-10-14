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
#include "dfilter.h"
#include "dfilter-macro.h"
#include "scanner_lex.h"
#include <wsutil/wslog.h>
#include <wsutil/ws_assert.h>
#include "grammar.h"


#define DFILTER_TOKEN_ID_OFFSET	1

/* Holds the singular instance of our Lemon parser object */
static void*	ParserObj = NULL;

/*
 * XXX - if we're using a version of Flex that supports reentrant lexical
 * analyzers, we should put this into the lexical analyzer's state.
 */
dfwork_t *global_dfw;

void
dfilter_fail(dfwork_t *dfw, const char *format, ...)
{
	va_list	args;

	/* If we've already reported one error, don't overwite it */
	if (dfw->error_message != NULL)
		return;

	va_start(args, format);
	dfw->error_message = g_strdup_vprintf(format, args);
	va_end(args);
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

/* Enable parser tracing by defining AM_CFLAGS
 * so that it contains "-DDFTRACE".
 */
#ifdef DFTRACE
	/* Trace parser */
	DfilterTrace(stdout, "lemon> ");
#endif

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
	guint i;

	if (!df)
		return;

	if (df->insns) {
		free_insns(df->insns);
	}
	if (df->consts) {
		free_insns(df->consts);
	}

	g_free(df->interesting_fields);

	/* Clear registers with constant values (as set by dfvm_init_const).
	 * Other registers were cleared on RETURN by free_register_overhead. */
	for (i = df->num_registers; i < df->max_registers; i++) {
		g_list_free(df->registers[i]);
	}

	if (df->deprecated)
		g_ptr_array_unref(df->deprecated);

	g_free(df->registers);
	g_free(df->attempted_load);
	g_free(df->owns_memory);
	g_free(df);
}


static dfwork_t*
dfwork_new(void)
{
	dfwork_t	*dfw;

	dfw = g_new0(dfwork_t, 1);
	dfw->first_constant = -1;

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

	if (dfw->interesting_fields) {
		g_hash_table_destroy(dfw->interesting_fields);
	}

	if (dfw->insns) {
		free_insns(dfw->insns);
	}

	if (dfw->consts) {
		free_insns(dfw->consts);
	}

	if (dfw->deprecated)
		g_ptr_array_unref(dfw->deprecated);

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
		case TOKEN_TEST_EQ:	return "TEST_EQ";
		case TOKEN_TEST_NE:	return "TEST_NE";
		case TOKEN_TEST_LT:	return "TEST_LT";
		case TOKEN_TEST_LE:	return "TEST_LE";
		case TOKEN_TEST_GT:	return "TEST_GT";
		case TOKEN_TEST_GE:	return "TEST_GE";
		case TOKEN_TEST_CONTAINS: return "TEST_CONTAINS";
		case TOKEN_TEST_MATCHES: return "TEST_MATCHES";
		case TOKEN_TEST_BITWISE_AND: return "TEST_BITWISE_AND";
		case TOKEN_TEST_NOT:	return "TEST_NOT";
		case TOKEN_FIELD:	return "FIELD";
		case TOKEN_STRING:	return "STRING";
		case TOKEN_CHARCONST:	return "CHARCONST";
		case TOKEN_UNPARSED:	return "UNPARSED";
		case TOKEN_LBRACKET:	return "LBRACKET";
		case TOKEN_RBRACKET:	return "RBRACKET";
		case TOKEN_COMMA:	return "COMMA";
		case TOKEN_INTEGER:	return "INTEGER";
		case TOKEN_COLON:	return "COLON";
		case TOKEN_HYPHEN:	return "HYPHEN";
		case TOKEN_TEST_IN:	return "TEST_IN";
		case TOKEN_LBRACE:	return "LBRACE";
		case TOKEN_RBRACE:	return "RBRACE";
		case TOKEN_WHITESPACE:	return "WHITESPACE";
		case TOKEN_DOTDOT:	return "DOTDOT";
		case TOKEN_FUNCTION:	return "FUNCTION";
		case TOKEN_LPAREN:	return "LPAREN";
		case TOKEN_RPAREN:	return "RPAREN";
		default:		return "<unknown>";
	}
	ws_assert_not_reached();
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

gboolean
dfilter_compile(const gchar *text, dfilter_t **dfp, gchar **err_msg)
{
	gchar		*expanded_text;
	int		token;
	dfilter_t	*dfilter;
	dfwork_t	*dfw;
	df_scanner_state_t state;
	yyscan_t	scanner;
	YY_BUFFER_STATE in_buffer;
	gboolean failure = FALSE;

	ws_assert(dfp);

	if (!text) {
		*dfp = NULL;
		if (err_msg != NULL)
			*err_msg = g_strdup("BUG: NULL text pointer passed to dfilter_compile()");
		return FALSE;
	}

	if ( !( expanded_text = dfilter_macro_apply(text, err_msg) ) ) {
		*dfp = NULL;
		return FALSE;
	}

	if (df_lex_init(&scanner) != 0) {
		wmem_free(NULL, expanded_text);
		*dfp = NULL;
		if (err_msg != NULL)
			*err_msg = g_strdup_printf("Can't initialize scanner: %s",
			    g_strerror(errno));
		return FALSE;
	}

	in_buffer = df__scan_string(expanded_text, scanner);

	dfw = dfwork_new();

	state.dfw = dfw;
	state.quoted_string = NULL;
	state.in_set = FALSE;
	state.raw_string = FALSE;

	df_set_extra(&state, scanner);

	while (1) {
		df_lval = stnode_new(STTYPE_UNINITIALIZED, NULL, NULL);
		token = df_lex(scanner);

		/* Check for scanner failure */
		if (token == SCAN_FAILED) {
			failure = TRUE;
			break;
		}

		/* Check for end-of-input */
		if (token == 0) {
			break;
		}

		ws_debug("Token: %d %s", token, tokenstr(token));

		/* Give the token to the parser */
		Dfilter(ParserObj, token, df_lval, dfw);
		/* We've used the stnode_t, so we don't want to free it */
		df_lval = NULL;

		if (dfw->syntax_error) {
			failure = TRUE;
			break;
		}

	} /* while (1) */

	/* If we created an stnode_t but didn't use it, free it; the
	 * parser doesn't know about it and won't free it for us. */
	if (df_lval) {
		stnode_free(df_lval);
		df_lval = NULL;
	}

	/* Tell the parser that we have reached the end of input; that
	 * way, it'll reset its state for the next compile.  (We want
	 * to do that even if we got a syntax error, to make sure the
	 * parser state is cleaned up; we don't create a new parser
	 * object when we start a new parse, and don't destroy it when
	 * the parse finishes.) */
	Dfilter(ParserObj, 0, NULL, dfw);

	/* One last check for syntax error (after EOF) */
	if (dfw->syntax_error)
		failure = TRUE;

	/* Free scanner state */
	if (state.quoted_string != NULL)
		g_string_free(state.quoted_string, TRUE);
	df__delete_buffer(in_buffer, scanner);
	df_lex_destroy(scanner);

	if (failure)
		goto FAILURE;

	/* Success, but was it an empty filter? If so, discard
	 * it and set *dfp to NULL */
	if (dfw->st_root == NULL) {
		*dfp = NULL;
	}
	else {
		log_syntax_tree(LOG_LEVEL_NOISY, dfw->st_root, "Syntax tree before semantic check");

		/* Check semantics and do necessary type conversion*/
		if (!dfw_semcheck(dfw)) {
			goto FAILURE;
		}

		log_syntax_tree(LOG_LEVEL_NOISY, dfw->st_root, "Syntax tree after successful semantic check");

		/* Create bytecode */
		dfw_gencode(dfw);

		/* Tuck away the bytecode in the dfilter_t */
		dfilter = dfilter_new(dfw->deprecated);
		dfilter->insns = dfw->insns;
		dfilter->consts = dfw->consts;
		dfw->insns = NULL;
		dfw->consts = NULL;
		dfilter->interesting_fields = dfw_interesting_fields(dfw,
			&dfilter->num_interesting_fields);

		/* Initialize run-time space */
		dfilter->num_registers = dfw->first_constant;
		dfilter->max_registers = dfw->next_register;
		dfilter->registers = g_new0(GList*, dfilter->max_registers);
		dfilter->attempted_load = g_new0(gboolean, dfilter->max_registers);
		dfilter->owns_memory = g_new0(gboolean, dfilter->max_registers);

		/* Initialize constants */
		dfvm_init_const(dfilter);

		/* And give it to the user. */
		*dfp = dfilter;
	}
	/* SUCCESS */
	global_dfw = NULL;
	dfwork_free(dfw);
	wmem_free(NULL, expanded_text);
	return TRUE;

FAILURE:
	if (dfw) {
		if (err_msg != NULL)
			*err_msg = dfw->error_message;
		else
			g_free(dfw->error_message);
		global_dfw = NULL;
		dfwork_free(dfw);
	}
	if (err_msg != NULL) {
		/*
		 * Default error message.
		 *
		 * XXX - we should really make sure that this is never the
		 * case for any error.
		 */
		if (*err_msg == NULL)
			*err_msg = g_strdup_printf("Unable to parse filter string \"%s\".", expanded_text);
	}
	wmem_free(NULL, expanded_text);
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

GPtrArray *
dfilter_deprecated_tokens(dfilter_t *df) {
	if (df->deprecated && df->deprecated->len > 0) {
		return df->deprecated;
	}
	return NULL;
}

void
dfilter_dump(dfilter_t *df)
{
	guint i;
	const gchar *sep = "";

	dfvm_dump(stdout, df);

	if (df->deprecated && df->deprecated->len) {
		printf("\nDeprecated tokens: ");
		for (i = 0; i < df->deprecated->len; i++) {
			printf("%s\"%s\"", sep, (char *) g_ptr_array_index(df->deprecated, i));
			sep = ", ";
		}
		printf("\n");
	}
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
