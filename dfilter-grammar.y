%{

/* dfilter-grammar.y
 * Parser for display filters
 *
 * $Id: dfilter-grammar.y,v 1.8 1999/08/12 21:16:31 guy Exp $
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

#define yylex dfilter_lex

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#ifndef __GLIB_H__
#include <glib.h>
#endif

#include <string.h> /* during testing */

#ifndef _STDLIB_H
#include <stdlib.h>
#endif

#ifndef __PROTO_H__
#include "proto.h"
#endif

#ifndef __PACKET_H__
#include "packet.h"
#endif

#ifndef __DFILTER_H__
#include "dfilter.h"
#endif

#include "dfilter-int.h"

#ifndef __RESOLV_H__
#include "resolv.h"
#endif

void dfilter_yacc_init(void);
static GNode* dfilter_mknode_join(GNode *n1, enum node_type ntype, int operand, GNode *n2);
static GNode* dfilter_mknode_unary(int operand, GNode *n2);
static GNode* dfilter_mknode_numeric_variable(gint id);
static GNode* dfilter_mknode_numeric_value(guint32 val);
static GNode* dfilter_mknode_ether_value(guint8*);
static GNode* dfilter_mknode_ether_variable(gint id);
static GNode* dfilter_mknode_ipxnet_value(guint32);
static GNode* dfilter_mknode_ipxnet_variable(gint id);
static GNode* dfilter_mknode_ipv4_value(char *host);
static GNode* dfilter_mknode_ipv4_variable(gint id);
static GNode* dfilter_mknode_existence(gint id);
static GNode* dfilter_mknode_bytes_value(GByteArray *barray);
static GNode* dfilter_mknode_bytes_variable(gint id, gint offset, guint length);
static GNode* dfilter_mknode_boolean_value(gint truth_value);
static GNode* dfilter_mknode_boolean_variable(gint id);

static guint32 string_to_value(char *s);

/* space for dfilter_nodes */
GMemChunk *gmc_dfilter_nodes = NULL;

/* this is how we pass display filter tree (dfcode) back to calling routine */
GNode *dfilter_tree = NULL;

/* list of byte arrays we allocate during parse. We can traverse this list
 * faster than the tree when we go back and free the byte arrays */
GSList *dfilter_list_byte_arrays = NULL;

%}

%union {
	gint		operand;	/* logical, relation, alternation */
	gint		variable;
	GNode*		node;
	gchar*		id;
	GByteArray*	bytes;
	guint8		ether[6];
	struct {
		gint	offset;
		guint	length;
	} byte_range;
}

%type <node>	statement expression relation
%type <node>	numeric_value numeric_variable
%type <node>	ether_value ether_variable
%type <node>	ipxnet_value ipxnet_variable
%type <node>	ipv4_value ipv4_variable
%type <node>	variable_name
%type <node>	bytes_value bytes_variable
%type <node>	boolean_value boolean_variable

%type <operand>	numeric_relation
%type <operand>	equality_relation
%type <operand>	bytes_relation

%type <variable>	any_variable_type

%token <variable>	T_FT_UINT8
%token <variable>	T_FT_UINT16
%token <variable>	T_FT_UINT32
%token <variable>	T_FT_ETHER
%token <variable>	T_FT_IPv4
%token <variable>	T_FT_NONE
%token <variable>	T_FT_BYTES
%token <variable>	T_FT_BOOLEAN
%token <variable>	T_FT_STRING
%token <variable>	T_FT_IPXNET

%token <id>	 	T_VAL_UNQUOTED_STRING
%token <ether>		T_VAL_ETHER
%token <bytes>		T_VAL_BYTES
%token <byte_range>	T_VAL_BYTE_RANGE

%token <operand>	TOK_AND TOK_OR TOK_NOT TOK_XOR
%token <operand>	TOK_EQ TOK_NE TOK_GT TOK_GE TOK_LT TOK_LE
%token <operand>	TOK_TRUE TOK_FALSE

%left TOK_AND
%left TOK_OR
%left TOK_XOR
%nonassoc TOK_NOT

%%

statement: expression
		{
			dfilter_tree = $1;
		}
	|	/* NULL */ { dfilter_tree = NULL; }
	;

expression:	'(' expression ')' { $$ = $2; }
	|	expression TOK_AND expression { $$ = dfilter_mknode_join($1, logical, $2, $3); }
	|	expression TOK_OR expression { $$ = dfilter_mknode_join($1, logical, $2, $3); }
	|	expression TOK_XOR expression { $$ = dfilter_mknode_join($1, logical, $2, $3); }
	|	TOK_NOT expression { $$ = dfilter_mknode_unary(TOK_NOT, $2); }
	|	relation { $$ = $1; }
	|	variable_name { $$ = $1; }
	;

relation:	numeric_variable numeric_relation numeric_value
		{
			$$ = dfilter_mknode_join($1, relation, $2, $3);
		}
	|	numeric_variable numeric_relation numeric_variable
		{
			$$ = dfilter_mknode_join($1, relation, $2, $3);
		}

	|	ether_variable equality_relation ether_value
		{
			$$ = dfilter_mknode_join($1, relation, $2, $3);
		}
	|	ether_variable equality_relation ether_variable
		{
			$$ = dfilter_mknode_join($1, relation, $2, $3);
		}

	|	ipxnet_variable equality_relation ipxnet_value
		{
			$$ = dfilter_mknode_join($1, relation, $2, $3);
		}
	|	ipxnet_variable equality_relation ipxnet_variable
		{
			$$ = dfilter_mknode_join($1, relation, $2, $3);
		}


	|	ipv4_variable numeric_relation ipv4_value
		{
			$$ = dfilter_mknode_join($1, relation, $2, $3);
		}
	|	ipv4_variable numeric_relation ipv4_variable
		{
			$$ = dfilter_mknode_join($1, relation, $2, $3);
		}

	|	bytes_variable bytes_relation bytes_value
		{
			$$ = dfilter_mknode_join($1, relation, $2, $3);
		}
	|	bytes_variable bytes_relation bytes_variable
		{
			$$ = dfilter_mknode_join($1, relation, $2, $3);
		}

	|	boolean_variable equality_relation boolean_value
		{
			$$ = dfilter_mknode_join($1, relation, $2, $3);
		}
	|	boolean_variable equality_relation boolean_variable
		{
			$$ = dfilter_mknode_join($1, relation, $2, $3);
		}

	;


numeric_value:	T_VAL_UNQUOTED_STRING
	{
		$$ = dfilter_mknode_numeric_value(string_to_value($1));
		g_free($1);
	 }
	;

ether_value:	T_VAL_ETHER
		{
			$$ = dfilter_mknode_ether_value($1);
		}
	;

ipxnet_value:	T_VAL_UNQUOTED_STRING
		{
			$$ = dfilter_mknode_ipxnet_value(string_to_value($1));
		}
	;

ipv4_value:	T_VAL_UNQUOTED_STRING
	{
		$$ = dfilter_mknode_ipv4_value($1);
		g_free($1);
	}
	;

bytes_value:	T_VAL_BYTES
	{								/* 2 - 5, or > 6 bytes */
		 $$ = dfilter_mknode_bytes_value($1);
	}

	|	T_VAL_UNQUOTED_STRING
	{								/* one or 4 bytes */
		GByteArray	*barray;

		/* the next function appends to dfilter_list_byte_arrays for me */
		barray = byte_str_to_guint8_array($1);
		$$ = dfilter_mknode_bytes_value(barray);
		g_free($1);
	}

	|	T_VAL_ETHER
	{								/* 6 bytes */
		GByteArray	*barray = g_byte_array_new();

		dfilter_list_byte_arrays = g_slist_append(dfilter_list_byte_arrays, barray);
		g_byte_array_append(barray, $1, 6);
		$$ = dfilter_mknode_bytes_value(barray);
	}
	;


boolean_value:	TOK_TRUE		{ $$ = dfilter_mknode_boolean_value($1); }
	|	TOK_FALSE		{ $$ = dfilter_mknode_boolean_value($1); }
	;


numeric_variable:	T_FT_UINT8	{ $$ = dfilter_mknode_numeric_variable($1); }
	|		T_FT_UINT16	{ $$ = dfilter_mknode_numeric_variable($1); }
	|		T_FT_UINT32	{ $$ = dfilter_mknode_numeric_variable($1); }
	;

ether_variable:		T_FT_ETHER	{ $$ = dfilter_mknode_ether_variable($1); }
	;

ipxnet_variable:	T_FT_IPXNET	{ $$ = dfilter_mknode_ipxnet_variable($1); }
	;

ipv4_variable:		T_FT_IPv4	{ $$ = dfilter_mknode_ipv4_variable($1); }
	;

variable_name:		any_variable_type	{ $$ = dfilter_mknode_existence($1); }
	;

bytes_variable:		any_variable_type T_VAL_BYTE_RANGE
		{
			$$ = dfilter_mknode_bytes_variable($1, $2.offset, $2.length);
		}
	;

boolean_variable:	T_FT_BOOLEAN	{ $$ = dfilter_mknode_boolean_variable($1); }
	;

any_variable_type:	T_FT_UINT8 { $$ = $1; }
	|		T_FT_UINT16 { $$ = $1; }
	|		T_FT_UINT32 { $$ = $1; }
	|		T_FT_ETHER { $$ = $1; }
	|		T_FT_IPv4 { $$ = $1; }
	|		T_FT_NONE { $$ = $1; }
	|		T_FT_BYTES { $$ = $1; }
	|		T_FT_BOOLEAN { $$ = $1; }
	|		T_FT_STRING { $$ = $1; }
	;

numeric_relation:	TOK_EQ { $$ = TOK_EQ; }
	|		TOK_NE { $$ = TOK_NE; }
	|		TOK_GT { $$ = TOK_GT; }
	|		TOK_GE { $$ = TOK_GE; }
	|		TOK_LT { $$ = TOK_LT; }
	|		TOK_LE { $$ = TOK_LE; }
	;

equality_relation:	TOK_EQ { $$ = TOK_EQ; }
	|		TOK_NE { $$ = TOK_NE; }
	;

bytes_relation:		TOK_EQ { $$ = TOK_EQ; }
	|		TOK_NE { $$ = TOK_NE; }
	|		TOK_GT { $$ = TOK_GT; }
	|		TOK_LT { $$ = TOK_LT; }
	;

%%

void
dfilter_yacc_init(void)
{
	if (gmc_dfilter_nodes)
		g_mem_chunk_destroy(gmc_dfilter_nodes);

	gmc_dfilter_nodes = g_mem_chunk_new("gmc_dfilter_nodes",
		sizeof(dfilter_node), 50 * sizeof(dfilter_node),
		G_ALLOC_ONLY);

	if (dfilter_list_byte_arrays) {
		/* clear the byte arrays */
		g_slist_free(dfilter_list_byte_arrays);
	}
		
}

void
dfilter_yacc_cleanup(void)
{
	if (gmc_dfilter_nodes)
		g_mem_chunk_destroy(gmc_dfilter_nodes);
}


static GNode*
dfilter_mknode_join(GNode *n1, enum node_type ntype, int operand, GNode *n2)
{
	dfilter_node	*node_root;
	GNode		*gnode_root;

	node_root = g_mem_chunk_alloc(gmc_dfilter_nodes);
	node_root->ntype = ntype;
	node_root->elem_size = 0;
	node_root->fill_array_func = NULL;
	node_root->check_relation_func = NULL;
	if (ntype == relation) {
		node_root->value.relation = operand;
	}
	else if (ntype == logical) {
		node_root->value.logical = operand;
	}
	else {
		g_assert_not_reached();
	}

	gnode_root = g_node_new(node_root);
	g_node_append(gnode_root, n1);
	g_node_append(gnode_root, n2);

	return gnode_root;
}

static GNode*
dfilter_mknode_unary(int operand, GNode *n2)
{
	dfilter_node	*node_root;
	GNode		*gnode_root;

	node_root = g_mem_chunk_alloc(gmc_dfilter_nodes);
	node_root->ntype = logical;
	node_root->value.logical = operand;
	node_root->elem_size = 0;
	node_root->fill_array_func = NULL;
	node_root->check_relation_func = NULL;

	gnode_root = g_node_new(node_root);
	g_node_append(gnode_root, n2);

	return gnode_root;
}


static GNode*
dfilter_mknode_numeric_variable(gint id)
{
	dfilter_node	*node;
	GNode		*gnode;

	node = g_mem_chunk_alloc(gmc_dfilter_nodes);
	node->ntype = variable;
	node->elem_size = sizeof(guint32);
	node->fill_array_func = fill_array_numeric_variable;
	node->check_relation_func = check_relation_numeric;
	node->value.variable = id;
	gnode = g_node_new(node);

	return gnode;
}

static GNode*
dfilter_mknode_ether_variable(gint id)
{
	dfilter_node	*node;
	GNode		*gnode;

	node = g_mem_chunk_alloc(gmc_dfilter_nodes);
	node->ntype = variable;
	node->elem_size = sizeof(guint8) * 6;
	node->fill_array_func = fill_array_ether_variable;
	node->check_relation_func = check_relation_ether;
	node->value.variable = id;
	gnode = g_node_new(node);

	return gnode;
}

static GNode*
dfilter_mknode_ipxnet_variable(gint id)
{
	dfilter_node	*node;
	GNode		*gnode;

	node = g_mem_chunk_alloc(gmc_dfilter_nodes);
	node->ntype = variable;
	node->elem_size = sizeof(guint8) * 4;
	node->fill_array_func = fill_array_numeric_variable; /* cheating ! */
	node->check_relation_func = check_relation_numeric; /* cheating ! */
	node->value.variable = id;
	gnode = g_node_new(node);

	return gnode;
}

static GNode*
dfilter_mknode_ipv4_variable(gint id)
{
	dfilter_node	*node;
	GNode		*gnode;

	node = g_mem_chunk_alloc(gmc_dfilter_nodes);
	node->ntype = variable;
	node->elem_size = sizeof(guint32);
	node->fill_array_func = fill_array_numeric_variable; /* cheating ! */
	node->check_relation_func = check_relation_numeric; /* cheating ! */
	node->value.variable = id;
	gnode = g_node_new(node);

	return gnode;
}

static GNode*
dfilter_mknode_bytes_variable(gint id, gint offset, guint length)
{
	dfilter_node	*node;
	GNode		*gnode;

	node = g_mem_chunk_alloc(gmc_dfilter_nodes);
	node->ntype = variable;
	node->elem_size = sizeof(GByteArray*);
	node->fill_array_func = fill_array_bytes_variable;
	node->check_relation_func = check_relation_bytes;
	node->value.variable = id;
	node->offset = offset;
	node->length = length;
	gnode = g_node_new(node);

	return gnode;
}

static GNode*
dfilter_mknode_boolean_variable(gint id)
{
	dfilter_node	*node;
	GNode		*gnode;

	node = g_mem_chunk_alloc(gmc_dfilter_nodes);
	node->ntype = variable;
	node->elem_size = sizeof(guint32);
	node->fill_array_func = fill_array_boolean_variable; /* cheating ! */
	node->check_relation_func = check_relation_boolean; /* cheating ! */
	node->value.variable = id;
	gnode = g_node_new(node);

	return gnode;
}

static GNode*
dfilter_mknode_numeric_value(guint32 val)
{
	dfilter_node	*node;
	GNode		*gnode;

	node = g_mem_chunk_alloc(gmc_dfilter_nodes);
	node->ntype = numeric;
	node->elem_size = sizeof(guint32);
	node->fill_array_func = fill_array_numeric_value;
	node->check_relation_func = check_relation_numeric;
	node->value.numeric = val;
	gnode = g_node_new(node);

	return gnode;
}

static GNode*
dfilter_mknode_ether_value(guint8 *ether_bytes)
{
	dfilter_node	*node;
	GNode		*gnode;

	node = g_mem_chunk_alloc(gmc_dfilter_nodes);
	node->ntype = ether;
	node->elem_size = sizeof(guint8) * 6;
	node->fill_array_func = fill_array_ether_value;
	node->check_relation_func = check_relation_ether;

	memcpy(&node->value.ether, ether_bytes, 6);

	gnode = g_node_new(node);
	return gnode;
}

static GNode*
dfilter_mknode_ipxnet_value(guint32 ipx_net_val)
{
	dfilter_node	*node;
	GNode		*gnode;

	node = g_mem_chunk_alloc(gmc_dfilter_nodes);
	node->ntype = ipxnet;
	node->elem_size = sizeof(guint8) * 4;
	node->fill_array_func = fill_array_numeric_value; /* cheating ! */
	node->check_relation_func = check_relation_numeric; /* cheating ! */
	node->value.numeric = ipx_net_val;
	gnode = g_node_new(node);

	return gnode;
}

static GNode*
dfilter_mknode_ipv4_value(char *host)
{
	dfilter_node	*node;
	GNode		*gnode;

	node = g_mem_chunk_alloc(gmc_dfilter_nodes);
	node->ntype = numeric;
	node->elem_size = sizeof(guint32);
	node->fill_array_func = fill_array_numeric_value; /* cheating ! */
	node->check_relation_func = check_relation_numeric; /* cheating ! */
	node->value.numeric = get_host_ipaddr(host);
	node->value.numeric = htonl(node->value.numeric);
	gnode = g_node_new(node);

	return gnode;
}

static GNode*
dfilter_mknode_bytes_value(GByteArray *barray)
{
	dfilter_node	*node;
	GNode		*gnode;

	node = g_mem_chunk_alloc(gmc_dfilter_nodes);
	node->ntype = bytes;
	node->elem_size = sizeof(GByteArray*);
	node->fill_array_func = fill_array_bytes_value;
	node->check_relation_func = check_relation_bytes;
	node->value.bytes = barray;
	node->offset = G_MAXINT;
	node->length = barray->len;
	gnode = g_node_new(node);

	return gnode;
}

static GNode*
dfilter_mknode_boolean_value(gint truth_value)
{
	dfilter_node	*node;
	GNode		*gnode;

	node = g_mem_chunk_alloc(gmc_dfilter_nodes);
	node->ntype = numeric;
	node->elem_size = sizeof(guint32);
	node->fill_array_func = fill_array_boolean_value;
	node->check_relation_func = check_relation_boolean;
	node->value.boolean = truth_value == TOK_TRUE ? TRUE : FALSE;
	gnode = g_node_new(node);

	return gnode;
}

static guint32
string_to_value(char *s)
{
	char	*endptr;
	guint32	val;

	val = strtoul(s, &endptr, 0);
	/* I should probably check errno here */

	return (guint32)val;
}
	
static GNode*
dfilter_mknode_existence(gint id)
{
	dfilter_node	*node;
	GNode		*gnode;

	node = g_mem_chunk_alloc(gmc_dfilter_nodes);
	node->ntype = existence;
	node->elem_size = sizeof(guint32);
	node->fill_array_func = NULL;
	node->check_relation_func = NULL;
	node->value.variable = id;
	gnode = g_node_new(node);

	return gnode;
}
