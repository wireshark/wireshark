/* proto.h
 * Definitions for protocol display
 *
 * $Id: proto.h,v 1.16 1999/10/12 04:21:13 gram Exp $
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


#ifndef __PROTO_H__
#define __PROTO_H__

#ifdef HAVE_SYS_TIME_H
# ifndef _SYS_TIME_H
#  include <sys/time.h>
# endif
#endif

#ifdef HAVE_WINSOCK_H
# include <winsock.h>
#endif

/* needs glib.h */
typedef struct GNode proto_tree;
typedef struct GNode proto_item;
struct value_string;

#define ITEM_LABEL_LENGTH	240

/* In order to make a const value_string[] look like a value_string*, I
 * need this macro */
#define VALS(x)	(struct value_string*)(x)


/* field types */
enum ftenum {
	FT_NONE,	/* used for protocol labels (thus no field type) */
	FT_BOOLEAN,	/* TRUE and FALSE come from <glib.h> */
	FT_UINT8,
	FT_UINT16,
	FT_UINT32,
	FT_DOUBLE,
	FT_ABSOLUTE_TIME,
	FT_RELATIVE_TIME,
	FT_STRING,
	FT_ETHER,
	FT_BYTES,
	FT_IPv4,
	FT_IPv6,
	FT_IPXNET,
	FT_VALS_UINT8,
	FT_VALS_UINT16,
	FT_VALS_UINT24,
	FT_VALS_UINT32,
	FT_TEXT_ONLY,	/* non-filterable, used when converting ethereal
				from old-style proto_tree to new-style proto_tree */
	NUM_FIELD_TYPES /* last item number plus one */
};

/* information describing a header field */
typedef struct header_field_info {
	char				*name;
	char				*abbrev;
	enum ftenum			type;
	struct value_string		*vals;
	int				id; /* assigned by order of registration */
	int				parent; /* parent protocol */
} header_field_info;

/* Used when registering many fields at once */
typedef struct hf_register_info {
	int			*p_id;	/* pointer to int; written to by register() function */
	header_field_info	hfinfo;
} hf_register_info;

#ifdef WIN32
/* 'boolean' is a reserved word on win32 */
#define boolean truth_value
#endif

/* Info stored in each proto_item GNode */
typedef struct field_info {
	struct header_field_info	*hfinfo;
	gint				start;
	gint				length;
	gint				tree_type; /* ETT_* */
	char				*representation; /* for GUI tree */
	int				visible;
	union {
		guint32		numeric;
		struct timeval	time; /* the whole struct, not a pointer */
		gdouble		floating;
		gchar		*string;
		guint8		*bytes;
		guint8		ether[6];
		guint8		ipv6[16];
	}				value;
} field_info;


/* used when calling proto search functions */
typedef struct proto_tree_search_info {
	int			target;
	int			parent;
	const guint8		*packet_data;
	guint			packet_len;
	GNodeTraverseFunc	traverse_func;
	union {
		GArray			*array;
		GNode			*node;
	} 			result;
} proto_tree_search_info;

/* Sets up memory used by proto routines. Called at program startup */
void proto_init(void);

/* Frees memory used by proto routines. Called at program shutdown */
void proto_cleanup(void);

void proto_item_set_len(proto_item *ti, gint length);
proto_tree* proto_tree_create_root(void);
void proto_tree_free(proto_tree *tree);
proto_tree* proto_item_add_subtree(proto_item *ti, gint idx);

int
proto_register_field(char *name, char *abbrev, enum ftenum type, int parent,
	struct value_string* vals);

int
proto_register_protocol(char *name, char *abbrev);

void
proto_register_field_array(int parent, hf_register_info *hf, int num_records);

proto_item *
proto_tree_add_item(proto_tree *tree, int hfindex, gint start,
	gint length, ...);

proto_item *
proto_tree_add_item_hidden(proto_tree *tree, int hfindex, gint start,
	gint length, ...);

proto_item *
proto_tree_add_item_format(proto_tree *tree, int hfindex, gint start,
	gint length, ...);

proto_item *
proto_tree_add_text(proto_tree *tree, gint start, gint length, ...);

void
proto_item_fill_label(field_info *fi, gchar *label_str);

/* Returns number of items (protocols or header fields) registered. */
int proto_registrar_n(void);

/* Returns char* to abbrev for item # n (0-indexed) */
char* proto_registrar_get_abbrev(int n);

/* Returns enum ftenum for item # n */
int proto_registrar_get_ftype(int n);

/* Returns parent protocol for item # n.
 * Returns -1 if item _is_ a protocol */
int proto_registrar_get_parent(int n);

/* Is item #n a protocol? */
gboolean proto_registrar_is_protocol(int n);

/* Get length of registered field according to field type.
 * 0 means undeterminable at registration time.
 * -1 means unknown field */
gint proto_registrar_get_length(int n);

/* Checks for existence any protocol or field within a tree.
 * TRUE = found, FALSE = not found */
gboolean proto_check_for_protocol_or_field(proto_tree* tree, int id);

/* Search for a protocol subtree, which can occur more than once, and for each successful
 * find, call the calback function, passing sinfo as the second argument */
void proto_find_protocol_multi(proto_tree* tree, int target, GNodeTraverseFunc callback,
			proto_tree_search_info *sinfo);

/* Just a wrapper to call sinfo->traverse_func() for all nodes in the subtree, with the GNode
 * and sinfo as the two arguments to sinfo->traverse_func(). Useful when you have to process
 * all nodes in a subtree. */
gboolean proto_get_field_values(proto_tree* subtree, proto_tree_search_info *sinfo);

/* Dumps a glossary of the protocol and field registrations to STDOUT */
void proto_registrar_dump(void);

/* Is the parsing being done for a visible proto_tree or an invisible one?
 * By setting this correctly, the proto_tree creation is sped up by not
 * having to call vsnprintf and copy strings around.
 */
extern gboolean proto_tree_is_visible;

#endif /* proto.h */
