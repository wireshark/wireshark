/*
 * $Id: dfilter.c,v 1.13 2002/10/16 16:32:59 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#ifdef NEED_SNPRINTF_H
#include "snprintf.h"
#endif

#include "dfilter-int.h"
#include "syntax-tree.h"
#include "gencode.h"
#include "semcheck.h"
#include "dfvm.h"
#include <epan/epan_dissect.h>

#define DFILTER_TOKEN_ID_OFFSET	1

/* Global error message space for dfilter_compile errors */
static gchar dfilter_error_msg_buf[1024];
gchar *dfilter_error_msg;	/* NULL when no error resulted */

/* In proto.c */
extern int hf_text_only;

/* From scanner.c */
void    df_scanner_text(const char *text);
void    df_scanner_file(FILE *fh);
void    df_scanner_cleanup(void);
int     df_lex(void);

/* Holds the singular instance of our Lemon parser object */
static void*	ParserObj = NULL;

void
dfilter_fail(char *format, ...)
{
	va_list	args;

	/* If we've already reported one error, don't overwite it */
	if (dfilter_error_msg != NULL)
		return;

	va_start(args, format);

	vsnprintf(dfilter_error_msg_buf, sizeof(dfilter_error_msg_buf),
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

	/* Initialize the syntax-tree sub-sub-system */
	sttype_init();
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

	df = g_new(dfilter_t, 1);
	df->insns = NULL;

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
}

void
dfilter_free(dfilter_t *df)
{
	if (df->insns) {
		free_insns(df->insns);
	}

	if (df->interesting_fields) {
		g_free(df->interesting_fields);
	}

	g_free(df->registers);
	g_free(df->attempted_load);
	g_free(df);
}


static dfwork_t*
dfwork_new(void)
{
	dfwork_t	*dfw;

	dfw = g_new(dfwork_t, 1);

	dfw->st_root = NULL;
	dfw->syntax_error = FALSE;
	dfw->insns = NULL;
	dfw->loaded_fields = NULL;
	dfw->interesting_fields = NULL;
	dfw->next_insn_id = 0;
	dfw->next_register = 0;

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


	g_free(dfw);
}


gboolean
dfilter_compile(gchar *text, dfilter_t **dfp)
{
	int		token;
	dfilter_t	*dfilter;
	dfwork_t	*dfw;

	dfilter_error_msg = NULL;

	dfw = dfwork_new();

	df_scanner_text(text);

	while (1) {
		df_lval = stnode_new(STTYPE_UNINITIALIZED, NULL);
		token = df_lex();

		/* Check for end-of-input */
		if (token == 0) {
			/* Tell the parser that we have reached the end of input */
			Dfilter(ParserObj, 0, NULL, dfw);

			/* Free the stnode_t that we just generated, since
			 * the parser doesn't know about it and won't free it
			 * for us. */
			stnode_free(df_lval);
			df_lval = NULL;
			break;
		}

		/* Give the token to the parser */
		Dfilter(ParserObj, token, df_lval, dfw);

		if (dfw->syntax_error) {
			break;
		}
	}

	/* One last check for syntax error (after EOF) */
	if (dfw->syntax_error) {
		goto FAILURE;
	}


	/* Success, but was it an empty filter? If so, discard
	 * it and set *dfp to NULL */
	if (dfw->st_root == NULL) {
		*dfp = NULL;
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
		dfw->insns = NULL;
		dfilter->interesting_fields = dfw_interesting_fields(dfw,
			&dfilter->num_interesting_fields);

		/* Initialize run-time space */
		dfilter->num_registers = dfw->next_register;
		dfilter->registers = g_new0(GList*, dfilter->num_registers);
		dfilter->attempted_load = g_new0(gboolean, dfilter->num_registers);

		/* And give it to the user. */
		*dfp = dfilter;
	}
	/* SUCCESS */
	dfwork_free(dfw);

	/* Reset flex */
	df_scanner_cleanup();

	return TRUE;

FAILURE:
	if (dfw) {
		dfwork_free(dfw);
	}
	dfilter_fail("Unable to parse filter string \"%s\".", text);
	*dfp = NULL;

	/* Reset flex */
	df_scanner_cleanup();
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


void
dfilter_dump(dfilter_t *df)
{
	dfvm_dump(stdout, df->insns);
}
