/* dfilter.h
 * Definitions for display filters
 *
 * $Id: dfilter.h,v 1.3 1999/07/13 02:52:48 gram Exp $
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

#ifndef __DFILTER_H__
#define __DFILTER_H__

void dfilter_init(void);
void dfilter_cleanup(void);
int dfilter_compile(char* dfilter_text, GNode** p_dfcode);
gboolean dfilter_apply(GNode *dfcode, proto_tree *ptree, const guint8* pd);

/* Here we provide interfaces to make our scanner act and look like lex */
int yylex(void);
void yyerror(char *s);
void dfilter_yyerror(char *fmt, ...);

/* functions that dfilter-grammar.y needs during parsing*/
gboolean check_relation_numeric(gint operand, GArray *a, GArray *b);
gboolean check_relation_ether(gint operand, GArray *a, GArray *b);
gboolean check_relation_bytes(gint operand, GArray *a, GArray *b);
gboolean check_relation_boolean(gint operand, GArray *a, GArray *b);

gboolean fill_array_numeric_value(GNode *gnode, gpointer data);
gboolean fill_array_numeric_variable(GNode *gnode, gpointer data);
gboolean fill_array_ether_value(GNode *gnode, gpointer data);
gboolean fill_array_ether_variable(GNode *gnode, gpointer data);
gboolean fill_array_bytes_value(GNode *gnode, gpointer data);
gboolean fill_array_bytes_variable(GNode *gnode, gpointer data);
gboolean fill_array_boolean_value(GNode *gnode, gpointer data);
gboolean fill_array_boolean_variable(GNode *gnode, gpointer data);

#ifdef WIN32
#define boolean truth_value
#endif

enum node_type {
	relation,	/* eq, ne, gt, ge, lt, le */
	logical,	/* and, or, not, xor */
	variable,	/* protocol or header field id */
	existence,	/* existence of a variable (protocol or hf) */
	alternation,	/* &, | */
	boolean,	/* true, false */
	numeric,	/* uint8, uint16, or uint32 value */
	abs_time,
	string,
	ether,
	ether_vendor,
	bytes,
	ipv4
};

typedef gboolean(*CheckRelationFunc) (gint operand, GArray *a, GArray *b);

/* This struct is the parse tree node created by this grammary and used
 * directly in the display filter routines to filter packets.
 */
typedef struct dfilter_node {
	enum node_type			ntype; /* from dfilter-grammar.h */
	int				elem_size; /* computed at dfilter parse time rather than
						when finding elements for each packet. Saves time
						in get_values_from_ptree() */
	CheckRelationFunc		check_relation_func;
	GNodeTraverseFunc		fill_array_func;

	/* copied from proto.h */
	union {
		gint		relation; /* if type == relation (eq, ne, gt, ge, lt, le) */
		gint		logical;  /* if type == logical (and, or, not, xor) */
		gint		variable; /* if type == variable (protocol or header field abbrev) */
		gint		alternation; /* if type == alternation (& or |) */

		gboolean	boolean;
		guint32		numeric;
		struct timeval	abs_time; /* the whole struct, not a pointer */
		gchar		*string;
		guint8		ether[6];
		GByteArray	*bytes;
	}				value;

	/* used for byte-ranges */
	int				offset;
	int				length;
} dfilter_node;



#endif /* ! __DFILTER_H__ */
