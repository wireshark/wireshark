/* dfilter.c
 * Routines for display filters
 *
 * $Id: dfilter.c,v 1.19 1999/08/30 16:01:42 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifndef _STDIO_H
#include <stdio.h>
#endif

#ifndef _STRING_H
#include <string.h>
#endif

#ifdef NEED_SNPRINTF_H
# ifdef HAVE_STDARG_H
#  include <stdarg.h>
# else
#  include <varargs.h>
# endif
# include "snprintf.h"
#endif

#ifndef __G_LIB_H__
#include <glib.h>
#endif

#ifndef __PROTO_H__
#include "proto.h"
#endif

#ifndef __DFILTER_H__
#include "dfilter.h"
#endif

#ifndef __UTIL_H__
#include "util.h"
#endif

#include "dfilter-int.h"
#include "dfilter-grammar.h"

int dfilter_parse(void); /* yacc entry-point */

#define DFILTER_LEX_ABBREV_OFFSET	2000

/* Balanced tree of abbreviations and IDs */
GTree *dfilter_tokens = NULL;

/* Comparision function for tree insertion. A wrapper around strcmp() */
static int g_strcmp(gconstpointer a, gconstpointer b);

/* Silly global variables used to pass parameter to check_relation_bytes() */
int bytes_offset = 0;
int bytes_length = 0;

YYSTYPE yylval;

/* Global error message space for dfilter_compile errors */
gchar dfilter_error_msg_buf[1024];
gchar *dfilter_error_msg;	/* NULL when no error resulted */

static gboolean dfilter_apply_node(GNode *gnode, proto_tree *ptree, const guint8 *pd);
static gboolean check_relation(gint operand, GNode *a, GNode *b, proto_tree *ptree, const guint8 *pd);
static gboolean check_logical(gint operand, GNode *a, GNode *b, proto_tree *ptree, const guint8 *pd);
static GArray* get_values_from_ptree(dfilter_node *dnode, proto_tree *ptree, const guint8 *pd);
static GArray* get_values_from_dfilter(dfilter_node *dnode, GNode *gnode);
static gboolean check_existence_in_ptree(dfilter_node *dnode, proto_tree *ptree);
static void clear_byte_array(gpointer data, gpointer user_data);
static void unlink_gnode_children(gpointer gnode_ptr, gpointer user_data);
static void destroy_gnode(gpointer gnode_ptr, gpointer user_data);

/* this is not so pretty. I need my own g_array "function" (macro) to
 * retreive the pointer to the data stored in an array cell. I need this
 * for type ether.. GArray makes it easy for me to store 6 bytes inside an array
 * cell, but hard to retrieve it.
 */
#define g_array_index_ptr(a,s,i)      (((guint8*) (a)->data) + (i*s))

void
dfilter_init(void)
{
	int i, num_symbols, symbol;
	char *s;

	dfilter_tokens = g_tree_new(g_strcmp);

	/* Add the header field and protocol abbrevs to the symbol table */
	num_symbols = proto_registrar_n();
	for (i=0; i < num_symbols; i++) {
		s = proto_registrar_get_abbrev(i);
		if (s) {
			symbol = DFILTER_LEX_ABBREV_OFFSET + i;
			g_tree_insert(dfilter_tokens, s, GINT_TO_POINTER(symbol));
		}
	}
}

void
dfilter_cleanup(void)
{
	if (dfilter_tokens)
		g_tree_destroy(dfilter_tokens);
}

/* Compiles the textual representation of the display filter into a tree
 * of operations to perform. Can be called multiple times, compiling a new
 * display filter each time, without having to clear any memory used, since
 * dfilter_compile will take care of that automatically.
 * 
 * Returns 0 on success, non-zero on failure.
 * If a failure, dfilter_error_msg points to an appropriate error message.
 * This error message is a global string, so another invocation of
 * dfilter_compile will clear it. If the caller needs is stored, he
 * needs to g_strdup it himself.
 */
int
dfilter_compile(dfilter *df, gchar *dfilter_text)
{
	int retval;

	g_assert(dfilter_text != NULL);

	dfilter_clear_filter(df);
	df->dftext = g_strdup(dfilter_text);

	/* tell the scanner to use this string as input */
	dfilter_scanner_text(df->dftext);

	/* Assign global variable so dfilter_parse knows which dfilter we're
	 * talking about. Reset the global error message. We don't have to set
	 * gnode_slist since it will always be NULL by the time we get here.
	 */
	global_df = df;
	dfilter_error_msg = NULL;

	/* The magic happens right here. */
	retval = dfilter_parse();

	/* clean up lex */
	dfilter_scanner_cleanup();

	/* If a parse error occurred, fill in a generic error message
	 * if one was not created during parsing. */
	if (retval != 0) {
		if (dfilter_error_msg == NULL) {
			dfilter_error_msg = &dfilter_error_msg_buf[0];
			snprintf(dfilter_error_msg, sizeof(dfilter_error_msg_buf),
				"Unable to parse filter string \"%s\".",
				dfilter_text);
		}
	}

	/* Clear the list of allocated nodes */
	if (gnode_slist) {
		g_slist_free(gnode_slist);
		gnode_slist = NULL;
	}

	return retval;
}

/* clear the current filter, w/o clearing memchunk area which is where we'll
 * put new nodes in a future filter */
void
dfilter_clear_filter(dfilter *df)
{
	if (!df)
		return;

	if (df->dftext)
		g_free(df->dftext);

	if (df->dftree != NULL)
		g_node_destroy(df->dftree);

	/* clear the memory that the tree was using for nodes */
	if (df->node_memchunk)
		g_mem_chunk_reset(df->node_memchunk);

	/* clear the memory that the tree was using for byte arrays */
	if (df->list_of_byte_arrays) {
		g_slist_foreach(df->list_of_byte_arrays, clear_byte_array, NULL);
		g_slist_free(df->list_of_byte_arrays);
	}

	df->dftext = NULL;
	df->dftree = NULL;
	df->list_of_byte_arrays = NULL;
}

/* Allocates new dfilter, initializes values, and returns pointer to dfilter */
dfilter*
dfilter_new(void)
{
	dfilter *df;

	df = g_malloc(sizeof(dfilter));

	df->dftext = NULL;
	df->dftree = NULL;
	df->node_memchunk = g_mem_chunk_new("df->node_memchunk",
		sizeof(dfilter_node), 20 * sizeof(dfilter_node), G_ALLOC_ONLY);
	df->list_of_byte_arrays = NULL;

	return df;
}

/* Frees all memory used by dfilter, and frees dfilter itself */
void
dfilter_destroy(dfilter *df)
{
	if (!df)
		return;

	dfilter_clear_filter(df);

	/* Git rid of memchunk */
	if (df->node_memchunk)
		g_mem_chunk_destroy(df->node_memchunk);

	g_free(df);
}


static void
clear_byte_array(gpointer data, gpointer user_data)
{
	GByteArray *barray = data;
	if (barray)
		g_byte_array_free(barray, TRUE);
}

/* Called when the yacc grammar finds a parsing error */
void
dfilter_error(char *s)
{
	/* The only data we have to worry about freeing is the
	 * data used by any GNodes that were allocated during
	 * parsing. The data in those Gnodes will be cleared
	 * later via df->node_memchunk. Use gnode_slist to
	 * clear the GNodes, and set global_df to NULL just
	 * to be tidy.
	 */
	global_df = NULL;

	/* I don't want to call g_node_destroy on each GNode ptr,
	 * since that function frees any children. That could
	 * mess me up later in the list if I try to free a GNode
	 * that has already been freed. So, I'll unlink the
	 * children firs,t then call g_node_destroy on each GNode ptr.
	 */
	if (!gnode_slist)
		return;

	g_slist_foreach(gnode_slist, unlink_gnode_children, NULL);
	g_slist_foreach(gnode_slist, destroy_gnode, NULL);

	/* notice we don't clear gnode_slist itself. dfilter_compile()
	 * will take care of that.
	 */
}

static void
unlink_gnode_children(gpointer gnode_ptr, gpointer user_data)
{
	if (gnode_ptr)
		g_node_unlink((GNode*) gnode_ptr);
}

static void
destroy_gnode(gpointer gnode_ptr, gpointer user_data)
{
	if (gnode_ptr)
		g_node_destroy((GNode*) gnode_ptr);
}


/* lookup an abbreviation in our token tree, returing the ID #
 * If the abbreviation doesn't exit, returns 0 */
int dfilter_lookup_token(char *abbrev)
{
	int value;

	g_assert(abbrev != NULL);
	value =  GPOINTER_TO_INT(g_tree_lookup(dfilter_tokens, abbrev));

	if (value < DFILTER_LEX_ABBREV_OFFSET) {
		return 0;
	}
	return value - DFILTER_LEX_ABBREV_OFFSET;
}

static int
g_strcmp(gconstpointer a, gconstpointer b)
{
	return strcmp((const char*)a, (const char*)b);
}


gboolean
dfilter_apply(dfilter *dfcode, proto_tree *ptree, const guint8* pd)
{
	gboolean retval;
	retval = dfilter_apply_node(dfcode->dftree, ptree, pd);
	return retval;
}

static gboolean
dfilter_apply_node(GNode *gnode, proto_tree *ptree, const guint8* pd)
{
	GNode		*gnode_a, *gnode_b;
	dfilter_node	*dnode = (dfilter_node*) (gnode->data);

	/* We'll get 2 NULLs if we don't have children */
	gnode_a = g_node_nth_child(gnode, 0);
	gnode_b = g_node_nth_child(gnode, 1);

	switch(dnode->ntype) {
	case variable:
		/* We'll never see this case because if the parser finds the name of
		 * a variable, it will cause it to be an 'existence' operation.
		 */
		g_assert_not_reached();

	case logical:
		return check_logical(dnode->value.logical, gnode_a, gnode_b, ptree, pd);

	case relation:
		g_assert(gnode_a && gnode_b);
		return check_relation(dnode->value.relation, gnode_a, gnode_b, ptree, pd);

	case alternation:
		g_assert_not_reached();
		/* not coded yet */
	
	case numeric:
	case ipv4:
	case boolean:
	case ether:
	case string:
	case abs_time:
	case bytes:
	case ipxnet:
		/* the only time we'll see these at this point is if the display filter
		 * is really wacky. (like simply "192.168.1.1"). The parser as it stands
		 * now let these by. Just return TRUE */
		g_assert(!gnode_a && !gnode_b);
		return TRUE;

	case existence:	/* checking the existence of a protocol or hf*/
		g_assert(!gnode_a && !gnode_b);
		return check_existence_in_ptree(dnode, ptree);
	}

	g_assert_not_reached();
	return FALSE;
}

static gboolean
check_logical(gint operand, GNode *a, GNode *b, proto_tree *ptree, const guint8 *pd)
{
	gboolean val_a = dfilter_apply_node(a, ptree, pd);
	gboolean val_b;

	switch(operand) {
	case TOK_AND:
		return (val_a && dfilter_apply_node(b, ptree, pd));
	case TOK_OR:
		return (val_a || dfilter_apply_node(b, ptree, pd));
	case TOK_XOR:
		val_b = dfilter_apply_node(b, ptree, pd);
		return ( ( val_a || val_b ) && ! ( val_a && val_b ) );
	case TOK_NOT:
		return (!val_a);
	default:
		g_assert_not_reached();
	}	
	g_assert_not_reached();
	return FALSE;
}

/* this is inefficient. I get arrays for both a and b that represent all the values present. That is,
 * if a is bootp.option, e.g., i'll get an array showing all the bootp.option values in the protocol
 * tree. Then I'll get an array for b, which more than likely is a single int, and then I'll compare
 * them all. It makes my coding easier in the beginning, but I should change this to make it run
 * faster.
 */
static gboolean
check_relation(gint operand, GNode *a, GNode *b, proto_tree *ptree, const guint8* pd)
{
	dfilter_node	*node_a = (dfilter_node*) (a->data);
	dfilter_node	*node_b = (dfilter_node*) (b->data);
	GArray		*vals_a, *vals_b;
	gboolean	retval;


	bytes_length = MIN(node_a->length, node_b->length);
	bytes_offset = MIN(node_a->offset, node_b->offset);
	if (node_a->ntype == variable)
		vals_a = get_values_from_ptree(node_a, ptree, pd);
	else
		vals_a = get_values_from_dfilter(node_a, a);

	if (node_b->ntype == variable)
		vals_b = get_values_from_ptree(node_b, ptree, pd);
	else
		vals_b = get_values_from_dfilter(node_b, b);

	retval =  node_a->check_relation_func(operand, vals_a, vals_b);

	g_array_free(vals_a, FALSE);
	g_array_free(vals_b, FALSE);

	return retval;
}

static gboolean
check_existence_in_ptree(dfilter_node *dnode, proto_tree *ptree)
{
	int		target;

	target = dnode->value.variable;
	return proto_check_for_protocol_or_field(ptree, target);
}

static GArray*
get_values_from_ptree(dfilter_node *dnode, proto_tree *ptree, const guint8 *pd)
{
	GArray		*array;
	int		parent_protocol;
	proto_tree_search_info sinfo;

	g_assert(dnode->elem_size > 0);
	array = g_array_new(FALSE, FALSE, dnode->elem_size);

	sinfo.target = dnode->value.variable;
	sinfo.result.array = array;
	sinfo.packet_data = pd;
	sinfo.traverse_func = dnode->fill_array_func;

	/* Find the proto_tree subtree where we should start searching.*/
	if (proto_registrar_is_protocol(sinfo.target)) {
		proto_find_protocol_multi(ptree, sinfo.target,
				(GNodeTraverseFunc)proto_get_field_values, &sinfo);
	}
	else {
		parent_protocol = proto_registrar_get_parent(sinfo.target);
		if (parent_protocol >= 0) {
			proto_find_protocol_multi(ptree, parent_protocol,
					(GNodeTraverseFunc)proto_get_field_values, &sinfo);
		}
	}

	return array;
}

static GArray*
get_values_from_dfilter(dfilter_node *dnode, GNode *gnode)
{
	GArray		*array;

	g_assert(dnode->elem_size > 0);
	array = g_array_new(FALSE, FALSE, dnode->elem_size);

	g_node_traverse(gnode, G_IN_ORDER, G_TRAVERSE_ALL, -1, dnode->fill_array_func, array);
/*	dnode->fill_array_func(gnode, array);*/
	return array;
}

gboolean fill_array_numeric_variable(GNode *gnode, gpointer data)
{
	proto_tree_search_info	*sinfo = (proto_tree_search_info*)data;
	field_info		*fi = (field_info*) (gnode->data);

	if (fi->hfinfo->id == sinfo->target) {
		g_array_append_val(sinfo->result.array, fi->value.numeric);
	}

	return FALSE; /* FALSE = do not end traversal of GNode tree */
}

gboolean fill_array_ether_variable(GNode *gnode, gpointer data)
{
	proto_tree_search_info	*sinfo = (proto_tree_search_info*)data;
	field_info		*fi = (field_info*) (gnode->data);

	if (fi->hfinfo->id == sinfo->target) {
		g_array_append_val(sinfo->result.array, fi->value.ether);
	}

	return FALSE; /* FALSE = do not end traversal of GNode tree */
}

gboolean fill_array_bytes_variable(GNode *gnode, gpointer data)
{
	proto_tree_search_info	*sinfo = (proto_tree_search_info*)data;
	field_info		*fi = (field_info*) (gnode->data);
	GByteArray		*barray;

	if (fi->hfinfo->id == sinfo->target) {
		barray = g_byte_array_new();
		/*list_of_byte_arrays = g_slist_append(list_of_byte_arrays, barray);*/
		g_byte_array_append(barray, sinfo->packet_data + fi->start + bytes_offset, bytes_length);
		g_array_append_val(sinfo->result.array, barray);
	}

	return FALSE; /* FALSE = do not end traversal of GNode tree */
}

gboolean fill_array_numeric_value(GNode *gnode, gpointer data)
{
	GArray		*array = (GArray*)data;
	dfilter_node	*dnode = (dfilter_node*) (gnode->data);

	g_array_append_val(array, dnode->value.numeric);
	return FALSE; /* FALSE = do not end traversal of GNode tree */
}

gboolean fill_array_ether_value(GNode *gnode, gpointer data)
{
	GArray		*array = (GArray*)data;
	dfilter_node	*dnode = (dfilter_node*) (gnode->data);

	g_array_append_val(array, dnode->value.ether);

	return FALSE; /* FALSE = do not end traversal of GNode tree */
}

gboolean fill_array_bytes_value(GNode *gnode, gpointer data)
{
	GArray		*array = (GArray*)data;
	dfilter_node	*dnode = (dfilter_node*) (gnode->data);
	GByteArray	*barray = dnode->value.bytes;

	g_array_append_val(array, barray);

	return FALSE; /* FALSE = do not end traversal of GNode tree */
}

gboolean check_relation_numeric(gint operand, GArray *a, GArray *b)
{
	int	i, j, len_a, len_b;
	guint32	val_a;

	len_a = a->len;
	len_b = b->len;


	switch(operand) {
	case TOK_EQ:
		for(i = 0; i < len_a; i++) {
			val_a = g_array_index(a, guint32, i);
			for (j = 0; j < len_b; j++) {
				if (val_a == g_array_index(b, guint32, j))
					return TRUE;
			}
		}
		return FALSE;

	case TOK_NE:
		for(i = 0; i < len_a; i++) {
			val_a = g_array_index(a, guint32, i);
			for (j = 0; j < len_b; j++) {
				if (val_a != g_array_index(b, guint32, j))
					return TRUE;
			}
		}
		return FALSE;

	case TOK_GT:
		for(i = 0; i < len_a; i++) {
			val_a = g_array_index(a, guint32, i);
			for (j = 0; j < len_b; j++) {
				if (val_a > g_array_index(b, guint32, j))
					return TRUE;
			}
		}
		return FALSE;

	case TOK_GE:
		for(i = 0; i < len_a; i++) {
			val_a = g_array_index(a, guint32, i);
			for (j = 0; j < len_b; j++) {
				if (val_a >= g_array_index(b, guint32, j))
					return TRUE;
			}
		}
		return FALSE;

	case TOK_LT:
		for(i = 0; i < len_a; i++) {
			val_a = g_array_index(a, guint32, i);
			for (j = 0; j < len_b; j++) {
				if (val_a < g_array_index(b, guint32, j))
					return TRUE;
			}
		}
		return FALSE;

	case TOK_LE:
		for(i = 0; i < len_a; i++) {
			val_a = g_array_index(a, guint32, i);
			for (j = 0; j < len_b; j++) {
				if (val_a <= g_array_index(b, guint32, j))
					return TRUE;
			}
		}
		return FALSE;

	default:
		g_assert_not_reached();
	}

	g_assert_not_reached();
	return FALSE;
}


gboolean check_relation_ether(gint operand, GArray *a, GArray *b)
{
	int	i, j, len_a, len_b;
	guint8	*ptr_a, *ptr_b;

	len_a = a->len;
	len_b = b->len;


	switch(operand) {
	case TOK_EQ:
		for(i = 0; i < len_a; i++) {
			ptr_a = g_array_index_ptr(a, 6, i);
			for (j = 0; j < len_b; j++) {
				ptr_b = g_array_index_ptr(b, 6, j);
				if (memcmp(ptr_a, ptr_b, 6) == 0)
					return TRUE;
			}
		}
		return FALSE;

	case TOK_NE:
		for(i = 0; i < len_a; i++) {
			ptr_a = g_array_index_ptr(a, 6, i);
			for (j = 0; j < len_b; j++) {
				ptr_b = g_array_index_ptr(b, 6, j);
				if (memcmp(ptr_a, ptr_b, 6) != 0)
					return TRUE;
			}
		}
		return FALSE;
	}

	g_assert_not_reached();
	return FALSE;
}

gboolean check_relation_bytes(gint operand, GArray *a, GArray *b)
{
	int	i, j, len_a, len_b;
	GByteArray	*ptr_a,*ptr_b;

	len_a = a->len;
	len_b = b->len;


	switch(operand) {
	case TOK_EQ:
		for(i = 0; i < len_a; i++) {
			ptr_a = g_array_index(a, GByteArray*, i);
			for (j = 0; j < len_b; j++) {
				ptr_b = g_array_index(b, GByteArray*, j);
				if (memcmp(ptr_a->data, ptr_b->data, bytes_length) == 0)
					return TRUE;
			}
		}
		return FALSE;

	case TOK_NE:
		for(i = 0; i < len_a; i++) {
			ptr_a = g_array_index(a, GByteArray*, i);
			for (j = 0; j < len_b; j++) {
				ptr_b = g_array_index(b, GByteArray*, j);
				if (memcmp(ptr_a->data, ptr_b->data, bytes_length) != 0)
					return TRUE;
			}
		}
		return FALSE;

	case TOK_GT:
		for(i = 0; i < len_a; i++) {
			ptr_a = g_array_index(a, GByteArray*, i);
			for (j = 0; j < len_b; j++) {
				ptr_b = g_array_index(b, GByteArray*, j);
				if (memcmp(ptr_a->data, ptr_b->data, bytes_length) > 0)
					return TRUE;
			}
		}
		return FALSE;

	case TOK_LT:
		for(i = 0; i < len_a; i++) {
			ptr_a = g_array_index(a, GByteArray*, i);
			for (j = 0; j < len_b; j++) {
				ptr_b = g_array_index(b, GByteArray*, j);
				if (memcmp(ptr_a->data, ptr_b->data, bytes_length) < 0)
					return TRUE;
			}
		}
		return FALSE;
	}

	g_assert_not_reached();
	return FALSE;
}

