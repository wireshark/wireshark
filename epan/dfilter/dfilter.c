/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

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
		g_message("I expected ParserObj to be NULL\n");
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
	/* Free the Lemon Parser object */
	if (ParserObj) {
		DfilterFree(ParserObj, g_free);
	}

	/* Clean up the syntax-tree sub-sub-system */
	sttype_cleanup();
}

static dfilter_t*
dfilter_new(void)
{
	dfilter_t	*df;

	df = g_new0(dfilter_t, 1);
	df->insns = NULL;
	df->deprecated = NULL;

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

	/* clear registers */
	for (i = 0; i < df->max_registers; i++) {
		if (df->registers[i]) {
			g_list_free(df->registers[i]);
		}
	}

	if (df->deprecated) {
		for (i = 0; i < df->deprecated->len; ++i) {
			gchar *depr = (gchar *)g_ptr_array_index(df->deprecated, i);
			g_free(depr);
		}
		g_ptr_array_free(df->deprecated, TRUE);
	}

	g_free(df->registers);
	g_free(df->attempted_load);
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

	/*
	 * We don't free the error message string; our caller will return
	 * it to its caller.
	 */
	g_free(dfw);
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
	const char	*depr_test;
	guint		i;
	/* XXX, GHashTable */
	GPtrArray	*deprecated;

	g_assert(dfp);

	if (!text) {
		*dfp = NULL;
		if (err_msg != NULL)
			*err_msg = g_strdup("BUG: NULL text pointer passed to dfilter_compile()");
		return FALSE;
	}

	if ( !( expanded_text = dfilter_macro_apply(text, err_msg) ) ) {
		return FALSE;
	}

	if (df_lex_init(&scanner) != 0) {
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

	df_set_extra(&state, scanner);

	deprecated = g_ptr_array_new();

	while (1) {
		df_lval = stnode_new(STTYPE_UNINITIALIZED, NULL);
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

		/* See if the node is deprecated */
		depr_test = stnode_deprecated(df_lval);

		if (depr_test) {
			for (i = 0; i < deprecated->len; i++) {
				if (g_ascii_strcasecmp(depr_test, (const gchar *)g_ptr_array_index(deprecated, i)) == 0) {
					/* It's already in our list */
					depr_test = NULL;
				}
			}
		}

		if (depr_test) {
			g_ptr_array_add(deprecated, g_strdup(depr_test));
		}

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
		for (i = 0; i < deprecated->len; ++i) {
			gchar* depr = (gchar*)g_ptr_array_index(deprecated,i);
			g_free(depr);
		}
		g_ptr_array_free(deprecated, TRUE);
	}
	else {

		/* Check semantics and do necessary type conversion*/
		if (!dfw_semcheck(dfw, deprecated)) {
			goto FAILURE;
		}

		/* Create bytecode */
		dfw_gencode(dfw);

		/* Tuck away the bytecode in the dfilter_t */
		dfilter = dfilter_new();
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

		/* Initialize constants */
		dfvm_init_const(dfilter);

		/* Add any deprecated items */
		dfilter->deprecated = deprecated;

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
	for (i = 0; i < deprecated->len; ++i) {
		gchar* depr = (gchar*)g_ptr_array_index(deprecated,i);
		g_free(depr);
	}
	g_ptr_array_free(deprecated, TRUE);
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
		proto_tree_prime_hfid(tree, df->interesting_fields[i]);
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
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
