/* dfilter-int.h
 * Definitions for routines common to multiple modules in the display
 * filter code, but not used outside that code.
 *
 * $Id: dfilter-int.h,v 1.9 1999/10/11 17:04:32 deniel Exp $
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

#ifndef __DFILTER_INT_H__
#define __DFILTER_INT_H__

/* in dfilter-scanner.l */
GByteArray *byte_str_to_guint8_array(const char *s);
void dfilter_scanner_text(char*);
void dfilter_scanner_cleanup(void);

/* in dfilter-grammar.y */
extern dfilter *global_df;

/* Here we provide interfaces to make our scanner act and look like lex */
int dfilter_lex(void);
void dfilter_error(char *s);

/* Report an error during compilation of a filter; this is called by code
 * other than parser code, so all it does is record that an error occurred,
 * so that even if the filter is nominally syntactically valid, we still
 * fail.
 */
#if __GNUC__ == 2
void dfilter_fail(char *fmt, ...)
    __attribute__((format (printf, 1, 2)));
#else
void dfilter_fail(char *fmt, ...);
#endif

/* functions that dfilter-grammar.y needs during parsing*/
gboolean check_relation_numeric(gint operand, GArray *a, GArray *b);
gboolean check_relation_ether(gint operand, GArray *a, GArray *b);
gboolean check_relation_ipv6(gint operand, GArray *a, GArray *b);
gboolean check_relation_bytes(gint operand, GArray *a, GArray *b);

gboolean fill_array_numeric_value(GNode *gnode, gpointer data);
gboolean fill_array_numeric_variable(GNode *gnode, gpointer data);
gboolean fill_array_ether_value(GNode *gnode, gpointer data);
gboolean fill_array_ether_variable(GNode *gnode, gpointer data);
gboolean fill_array_ipv6_value(GNode *gnode, gpointer data);
gboolean fill_array_ipv6_variable(GNode *gnode, gpointer data);
gboolean fill_array_bytes_value(GNode *gnode, gpointer data);
gboolean fill_array_bytes_variable(GNode *gnode, gpointer data);

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
	bytes,
	ipv4,
	ipv6,
	ipxnet
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

		guint32		numeric;
		struct timeval	abs_time; /* the whole struct, not a pointer */
		gchar		*string;
		guint8		ether[6];
		guint8		ipv6[16];
		GByteArray	*bytes;
	}				value;

	/* used for byte-ranges */
	gint				offset;
	guint				length;
} dfilter_node;

/* lookup an abbreviation in our token hash, returing the ID # */
int dfilter_lookup_token(char *abbrev);

#endif /* ! __DFILTER_INT_H__ */
