/*
 * $Id$
 *
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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
#include <epan/report_err.h>

#define DFILTER_TOKEN_ID_OFFSET	1

/* Global error message space for dfilter_compile errors */
static gchar dfilter_error_msg_buf[1024];
const gchar *dfilter_error_msg;	/* NULL when no error resulted */

/* From scanner.c */
void df_scanner_text(const char *text);
void    df_scanner_cleanup(void);
int     df_lex(void);

/* Holds the singular instance of our Lemon parser object */
static void*	ParserObj = NULL;

void
dfilter_fail(const char *format, ...)
{
	va_list	args;

	/* If we've already reported one error, don't overwite it */
	if (dfilter_error_msg != NULL)
		return;

	va_start(args, format);

	g_vsnprintf(dfilter_error_msg_buf, sizeof(dfilter_error_msg_buf),
			format, args);
	dfilter_error_msg = dfilter_error_msg_buf;
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
		insn = g_ptr_array_index(insns, i);
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
			gchar *depr = g_ptr_array_index(df->deprecated, i);
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

	g_free(dfw);
}

gboolean
dfilter_compile(const gchar *text, dfilter_t **dfp)
{
	int		token;
	dfilter_t	*dfilter;
	dfwork_t	*dfw;
	gboolean failure = FALSE;
	const char	*depr_test;
	guint		i;
	GPtrArray	*deprecated;

	g_assert(dfp);

	if (!text) {
		*dfp = NULL;
		return FALSE;
	}

	dfilter_error_msg = NULL;

	if ( !( text = dfilter_macro_apply(text, &dfilter_error_msg) ) ) {
		return FALSE;
	}

	dfw = dfwork_new();

	df_scanner_text(text);

	deprecated = g_ptr_array_new();

	while (1) {
		df_lval = stnode_new(STTYPE_UNINITIALIZED, NULL);
		token = df_lex();

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
				if (g_ascii_strcasecmp(depr_test, g_ptr_array_index(deprecated, i)) == 0) {
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

	/* Reset flex */
	df_scanner_cleanup();

	if (failure)
		goto FAILURE;

	/* Success, but was it an empty filter? If so, discard
	 * it and set *dfp to NULL */
	if (dfw->st_root == NULL) {
		*dfp = NULL;
		for (i = 0; i < deprecated->len; ++i) {
			gchar* depr = g_ptr_array_index(deprecated,i);
			g_free(depr);
		}
		g_ptr_array_free(deprecated, TRUE);
	}
	else {

		/* Check semantics and do necessary type conversion*/
		if (!dfw_semcheck(dfw)) {
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
	dfwork_free(dfw);
	return TRUE;

FAILURE:
	if (dfw) {
		dfwork_free(dfw);
	}
	for (i = 0; i < deprecated->len; ++i) {
		gchar* depr = g_ptr_array_index(deprecated,i);
		g_free(depr);
	}
	g_ptr_array_free(deprecated, TRUE);
	dfilter_fail("Unable to parse filter string \"%s\".", text);
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
