/*
 * $Id: dfilter.c,v 1.7 2002/01/21 07:37:37 guy Exp $
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


/* Balanced tree of abbreviations and IDs */
GTree *dfilter_tokens = NULL;

#define DFILTER_TOKEN_ID_OFFSET	1

/* Comparision function for tree insertion. A wrapper around strcmp() */
static int g_strcmp(gconstpointer a, gconstpointer b);

/* Global error message space for dfilter_compile errors */
gchar dfilter_error_msg_buf[1024];
gchar *dfilter_error_msg;	/* NULL when no error resulted */

/* In proto.c */
extern int hf_text_only;

/* From scanner.c */
void    df_scanner_text(const char *text);
void    df_scanner_file(FILE *fh);
void    df_scanner_cleanup(void);
int     df_lex(void);

/* Holds the singular instance of our Lemon parser object */
void*		ParserObj = NULL;

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
	int 			id, num_symbols;
	char 			*abbrev;
	header_field_info	*hfinfo, *same_name_hfinfo, *same_name_next_hfinfo;

	num_symbols = proto_registrar_n();

	if (dfilter_tokens) {
		/* XXX - needed? */
		g_message("I expected hf_ids to be NULL\n");
		g_tree_destroy(dfilter_tokens);

		/* Make sure the hfinfo->same_name links are broken */
		for (id = 0; id < num_symbols; id++) {
			hfinfo = proto_registrar_get_nth(id);
			hfinfo->same_name_next = NULL;
			hfinfo->same_name_prev = NULL;
		}
	}
	dfilter_tokens = g_tree_new(g_strcmp);

	/* Populate the abbrev/ID GTree (header-field symbol table) */

	
	for (id = 0; id < num_symbols; id++) {
		if (id == hf_text_only) {
			continue;
		}
		abbrev = proto_registrar_get_abbrev(id);
		hfinfo = proto_registrar_get_nth(id);

		g_assert(abbrev);		/* Not Null */
		g_assert(abbrev[0] != 0);	/* Not empty string */

		/* We allow multiple hfinfo's to be registered under the same
		 * abbreviation. This was done for X.25, as, depending
		 * on whether it's modulo-8 or modulo-128 operation,
		 * some bitfield fields may be in different bits of
		 * a byte, and we want to be able to refer to that field
		 * with one name regardless of whether the packets
		 * are modulo-8 or modulo-128 packets. */
		same_name_hfinfo = g_tree_lookup(dfilter_tokens, abbrev);
		if (same_name_hfinfo) {
			/* There's already a field with this name.
			 * Put it after that field in the list of
			 * fields with this name, then allow the code
			 * after this if{} block to replace the old
			 * hfinfo with the new hfinfo in the GTree. Thus,
			 * we end up with a linked-list of same-named hfinfo's,
			 * with the root of the list being the hfinfo in the GTree */
			same_name_next_hfinfo =
			    same_name_hfinfo->same_name_next;

			hfinfo->same_name_next = same_name_next_hfinfo;
			if (same_name_next_hfinfo)
				same_name_next_hfinfo->same_name_prev = hfinfo;

			same_name_hfinfo->same_name_next = hfinfo;
			hfinfo->same_name_prev = same_name_hfinfo;
		}
		g_tree_insert(dfilter_tokens, abbrev, hfinfo);
	}

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
	/* Free the abbrev/ID GTree */
	if (dfilter_tokens) {
		g_tree_destroy(dfilter_tokens);
		dfilter_tokens = NULL;
	}

	/* Free the Lemon Parser object */
	if (ParserObj) {
		DfilterFree(ParserObj, g_free);
	}

	/* Clean up the syntax-tree sub-sub-system */
	sttype_cleanup();
}



/* Lookup an abbreviation in our token tree, returing the ID #
 * If the abbreviation doesn't exit, returns -1 */
header_field_info*
dfilter_lookup_token(char *abbrev)
{
	g_assert(abbrev != NULL);
	return g_tree_lookup(dfilter_tokens, abbrev);
}

/* String comparison func for dfilter_token GTree */
static int
g_strcmp(gconstpointer a, gconstpointer b)
{
	return strcmp((const char*)a, (const char*)b);
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
dfilter_apply(dfilter_t *df, tvbuff_t *tvb, proto_tree *tree)
{
	return dfvm_apply(df, tvb, tree);
}

gboolean
dfilter_apply_edt(dfilter_t *df, epan_dissect_t* edt)
{
	return dfvm_apply(df, edt->tvb, edt->tree);
}


void
dfilter_foreach_interesting_field(dfilter_t *df, GFunc func,
        gpointer user_data)
{
    int i;

    for (i = 0; i < df->num_interesting_fields; i++) {
        func(GINT_TO_POINTER(df->interesting_fields[i]), user_data);
    }
}
                

void
dfilter_dump(dfilter_t *df)
{
	dfvm_dump(stdout, df->insns);
}
