/* proto.h
 * Definitions for protocol display
 *
 * $Id: proto.h,v 1.25 2000/03/14 06:03:26 guy Exp $
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

#ifndef __IPV4_H__
#include "ipv4.h"
#endif

/* needs glib.h */
typedef struct GNode proto_tree;
typedef struct GNode proto_item;
struct value_string;

#define ITEM_LABEL_LENGTH	240

/* In order to make a const value_string[] look like a value_string*, I
 * need this macro */
#define VALS(x)	(struct value_string*)(x)

/* ... and similarly, */
#define TFS(x)	(struct true_false_string*)(x)

/* field types */
enum ftenum {
	FT_NONE,	/* used for protocol labels (thus no field type) */
	FT_BOOLEAN,	/* TRUE and FALSE come from <glib.h> */
	FT_UINT8,
	FT_UINT16,
	FT_UINT24,	/* really a UINT32, but displayed as 3 hex-digits if FD_HEX*/
	FT_UINT32,
	FT_INT8,
	FT_INT16,
	FT_INT24,
	FT_INT32,
	FT_DOUBLE,
	FT_ABSOLUTE_TIME,
	FT_RELATIVE_TIME,
	FT_STRING,
	FT_ETHER,
	FT_BYTES,
	FT_IPv4,
	FT_IPv6,
	FT_IPXNET,
	FT_TEXT_ONLY,	/* non-filterable, used when converting ethereal
				from old-style proto_tree to new-style proto_tree */
	NUM_FIELD_TYPES /* last item number plus one */
};

enum {
	BASE_NONE,
	BASE_DEC,
	BASE_HEX,
	BASE_OCT,
	BASE_BIN
};

/* information describing a header field */
typedef struct header_field_info {
	char				*name;
	char				*abbrev;
	enum ftenum			type;
	int				display;	/* for integers only, so far. Base */
	void				*strings;	/* val_string or true_false_string */
	guint32				bitmask;
	char				*blurb;		/* Brief description of field. */

	int				id;		/* assigned by registration function, not programmer */
	int				parent;		/* parent protocol */
	int				bitshift;	/* bits to shift */
} header_field_info;

/* Used when registering many fields at once */
typedef struct hf_register_info {
	int			*p_id;	/* pointer to int; written to by register() function */
	header_field_info	hfinfo;
} hf_register_info;


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
		ipv4_addr	ipv4;
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

/* Set text of proto_item after having already been created. */
#if __GNUC__ == 2
void proto_item_set_text(proto_item *ti, const char *format, ...)
	__attribute__((format (printf, 2, 3)));
#else
void proto_item_set_text(proto_item *ti, const char *format, ...);
#endif

/* Set length of proto_item after having already been created. */
void proto_item_set_len(proto_item *ti, gint length);

/* Creates new proto_tree root */
proto_tree* proto_tree_create_root(void);

/* Clear memory for entry proto_tree. Clears proto_tree struct also. */
void proto_tree_free(proto_tree *tree);

/* Create a subtree under an existing item; returns tree pointer */
proto_tree* proto_item_add_subtree(proto_item *ti, gint idx);

int
proto_register_field(char *name, char *abbrev, enum ftenum type, int parent,
	struct value_string* vals);

int
proto_register_protocol(char *name, char *abbrev);

void
proto_register_field_array(int parent, hf_register_info *hf, int num_records);

void
proto_register_subtree_array(gint **indices, int num_indices);

/* Add item's value to proto_tree, using label registered to that field */
proto_item *
proto_tree_add_item(proto_tree *tree, int hfindex, gint start,
	gint length, ...);

proto_item *
proto_tree_add_item_hidden(proto_tree *tree, int hfindex, gint start,
	gint length, ...);

#if __GNUC__ == 2
proto_item *
proto_tree_add_protocol_format(proto_tree *tree, int hfindex, gint start,
	gint length, const char *format, ...)
	__attribute__((format (printf, 5, 6)));
#else
proto_item *
proto_tree_add_protocol_format(proto_tree *tree, int hfindex, gint start,
	gint length, const char *format, ...);
#endif


#if __GNUC__ == 2
proto_item *
proto_tree_add_bytes_format(proto_tree *tree, int hfindex, gint start,
	gint length, const guint8* start_ptr, const char *format, ...)
	__attribute__((format (printf, 6, 7)));
#else
proto_item *
proto_tree_add_bytes_format(proto_tree *tree, int hfindex, gint start,
	gint length, const guint8* start_ptr, const char *format, ...);
#endif

#if __GNUC__ == 2
proto_item *
proto_tree_add_time_format(proto_tree *tree, int hfindex, gint start,
	gint length, struct timeval* value_ptr, const char *format, ...)
	__attribute__((format (printf, 6, 7)));
#else
proto_item *
proto_tree_add_time_format(proto_tree *tree, int hfindex, gint start,
	gint length, struct timeval* value_ptr, const char *format, ...);
#endif

#if __GNUC__ == 2
proto_item *
proto_tree_add_ipxnet_format(proto_tree *tree, int hfindex, gint start,
	gint length, guint32 value, const char *format, ...)
	__attribute__((format (printf, 6, 7)));
#else
proto_item *
proto_tree_add_ipxnet_format(proto_tree *tree, int hfindex, gint start,
	gint length, guint32 value, const char *format, ...);
#endif

#if __GNUC__ == 2
proto_item *
proto_tree_add_ipv4_format(proto_tree *tree, int hfindex, gint start,
	gint length, guint32 value, const char *format, ...)
	__attribute__((format (printf, 6, 7)));
#else
proto_item *
proto_tree_add_ipv4_format(proto_tree *tree, int hfindex, gint start,
	gint length, guint32 value, const char *format, ...);
#endif

#if __GNUC__ == 2
proto_item *
proto_tree_add_ipv6_format(proto_tree *tree, int hfindex, gint start,
	gint length, guint8* value_ptr, const char *format, ...)
	__attribute__((format (printf, 6, 7)));
#else
proto_item *
proto_tree_add_ipv6_format(proto_tree *tree, int hfindex, gint start,
	gint length, guint8* value_ptr, const char *format, ...);
#endif

#if __GNUC__ == 2
proto_item *
proto_tree_add_ether_format(proto_tree *tree, int hfindex, gint start,
	gint length, guint8* value, const char *format, ...)
	__attribute__((format (printf, 6, 7)));
#else
proto_item *
proto_tree_add_ether_format(proto_tree *tree, int hfindex, gint start,
	gint length, guint8* value, const char *format, ...);
#endif

#if __GNUC__ == 2
proto_item *
proto_tree_add_string_format(proto_tree *tree, int hfindex, gint start,
	gint length, const char* value, const char *format, ...)
	__attribute__((format (printf, 6, 7)));
#else
proto_item *
proto_tree_add_string_format(proto_tree *tree, int hfindex, gint start,
	gint length, const char* value, const char *format, ...);
#endif

#if __GNUC__ == 2
proto_item *
proto_tree_add_boolean_format(proto_tree *tree, int hfindex, gint start,
	gint length, guint32 value, const char *format, ...)
	__attribute__((format (printf, 6, 7)));
#else
proto_item *
proto_tree_add_boolean_format(proto_tree *tree, int hfindex, gint start,
	gint length, guint32 value, const char *format, ...);
#endif

#if __GNUC__ == 2
proto_item *
proto_tree_add_uint_format(proto_tree *tree, int hfindex, gint start,
	gint length, guint32 value, const char *format, ...)
	__attribute__((format (printf, 6, 7)));
#else
proto_item *
proto_tree_add_uint_format(proto_tree *tree, int hfindex, gint start,
	gint length, guint32 value, const char *format, ...);
#endif


#if __GNUC__ == 2
proto_item *
proto_tree_add_text(proto_tree *tree, gint start, gint length, const char *,
	...) __attribute__((format (printf, 4, 5)));
#else
proto_item *
proto_tree_add_text(proto_tree *tree, gint start, gint length, const char *,
	...);
#endif


proto_item *
proto_tree_add_notext(proto_tree *tree, gint start, gint length);


void
proto_item_fill_label(field_info *fi, gchar *label_str);

/* Returns number of items (protocols or header fields) registered. */
int proto_registrar_n(void);

/* Returns char* to name for item # n (0-indexed) */
char* proto_registrar_get_name(int n);

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

/* Points to the first element of an array of Booleans, indexed by
   a subtree item type; that array element is TRUE if subtrees of
   an item of that type are to be expanded.

   ETT_NONE is reserved for unregistered subtree types. */
#define	ETT_NONE	0
extern gboolean	     *tree_is_expanded;

/* Number of elements in that array. */
extern int           num_tree_types;

#endif /* proto.h */
