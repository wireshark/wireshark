/* proto.h
 * Definitions for protocol display
 *
 * $Id: proto.h,v 1.1 2000/09/27 04:54:52 gram Exp $
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
# include <sys/time.h>
#endif

#ifdef HAVE_STDARG_H
# include <stdarg.h>
#else
# include <varargs.h>
#endif

#ifdef HAVE_WINSOCK_H
# include <winsock.h>
#endif

#include "ipv4.h"
#include "tvbuff.h"

/* needs glib.h */
typedef GNode proto_tree;
typedef GNode proto_item;
struct value_string;

#define ITEM_LABEL_LENGTH	240

/* In order to make a const value_string[] look like a value_string*, I
 * need this macro */
#define VALS(x)	(struct value_string*)(x)

/* ... and similarly, */
#define TFS(x)	(struct true_false_string*)(x)

/* check protocol activation */
#define OLD_CHECK_DISPLAY_AS_DATA(index, pd, offset, fd, tree) {\
	if (!proto_is_protocol_enabled(index)) {		\
		old_dissect_data(pd, offset, fd, tree);		\
		return;						\
	}							\
  }

#define CHECK_DISPLAY_AS_DATA(index, tvb, pinfo, tree) {	\
	if (!proto_is_protocol_enabled(index)) {		\
		dissect_data(tvb, pinfo, tree);			\
		return;						\
	}							\
  }

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
	FT_STRINGZ,	/* for use with proto_tree_add_item() */
	FT_UINT_STRING,	/* for use with proto_tree_add_item() */
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


/* For use while converting dissectors to use tvbuff's */
#define NullTVB NULL

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

/* Get length of proto_item. Useful after using proto_tree_add_item()
 * to add a variable-length field (e.g., FT_NSTRING_UINT8) */
int proto_item_get_len(proto_item *ti);

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

/* Add an item to a proto_tree, using the text label registered to that item;
   the item is extracted from the tvbuff handed to it. */
proto_item *
proto_tree_add_item(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    gint start, gint length, gboolean little_endian);

proto_item *
proto_tree_add_item_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    gint start, gint length, gboolean little_endian);

/* Add a FT_NONE to a proto_tree */
#if __GNUC__ == 2
proto_item *
proto_tree_add_protocol_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, const char *format, ...)
	__attribute__((format (printf, 6, 7)));
#else
proto_item *
proto_tree_add_protocol_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, const char *format, ...);
#endif

/* Add a FT_BYTES to a proto_tree */
proto_item *
proto_tree_add_bytes(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, const guint8* start_ptr);

proto_item *
proto_tree_add_bytes_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, const guint8* start_ptr);

#if __GNUC__ == 2
proto_item *
proto_tree_add_bytes_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, const guint8* start_ptr, const char *format, ...)
	__attribute__((format (printf, 7, 8)));
#else
proto_item *
proto_tree_add_bytes_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, const guint8* start_ptr, const char *format, ...);
#endif

/* Add a FT_*TIME to a proto_tree */
proto_item *
proto_tree_add_time(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, struct timeval* value_ptr);

proto_item *
proto_tree_add_time_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, struct timeval* value_ptr);

#if __GNUC__ == 2
proto_item *
proto_tree_add_time_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, struct timeval* value_ptr, const char *format, ...)
	__attribute__((format (printf, 7, 8)));
#else
proto_item *
proto_tree_add_time_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, struct timeval* value_ptr, const char *format, ...);
#endif

/* Add a FT_IPXNET to a proto_tree */
proto_item *
proto_tree_add_ipxnet(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, guint32 value);

proto_item *
proto_tree_add_ipxnet_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, guint32 value);

#if __GNUC__ == 2
proto_item *
proto_tree_add_ipxnet_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, guint32 value, const char *format, ...)
	__attribute__((format (printf, 7, 8)));
#else
proto_item *
proto_tree_add_ipxnet_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, guint32 value, const char *format, ...);
#endif

/* Add a FT_IPv4 to a proto_tree */
proto_item *
proto_tree_add_ipv4(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, guint32 value);

proto_item *
proto_tree_add_ipv4_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, guint32 value);

#if __GNUC__ == 2
proto_item *
proto_tree_add_ipv4_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, guint32 value, const char *format, ...)
	__attribute__((format (printf, 7, 8)));
#else
proto_item *
proto_tree_add_ipv4_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, guint32 value, const char *format, ...);
#endif

/* Add a FT_IPv6 to a proto_tree */
proto_item *
proto_tree_add_ipv6(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, const guint8* value_ptr);

proto_item *
proto_tree_add_ipv6_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, const guint8* value_ptr);

#if __GNUC__ == 2
proto_item *
proto_tree_add_ipv6_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, const guint8* value_ptr, const char *format, ...)
	__attribute__((format (printf, 7, 8)));
#else
proto_item *
proto_tree_add_ipv6_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, const guint8* value_ptr, const char *format, ...);
#endif

/* Add a FT_ETHER to a proto_tree */
proto_item *
proto_tree_add_ether(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, const guint8* value);

proto_item *
proto_tree_add_ether_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, const guint8* value);

#if __GNUC__ == 2
proto_item *
proto_tree_add_ether_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, const guint8* value, const char *format, ...)
	__attribute__((format (printf, 7, 8)));
#else
proto_item *
proto_tree_add_ether_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, const guint8* value, const char *format, ...);
#endif

/* Add a FT_STRING to a proto_tree */
proto_item *
proto_tree_add_string(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, const char* value);

proto_item *
proto_tree_add_string_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, const char* value);

#if __GNUC__ == 2
proto_item *
proto_tree_add_string_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, const char* value, const char *format, ...)
	__attribute__((format (printf, 7, 8)));
#else
proto_item *
proto_tree_add_string_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, const char* value, const char *format, ...);
#endif

/* Add a FT_BOOLEAN to a proto_tree */
proto_item *
proto_tree_add_boolean(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, guint32 value);

proto_item *
proto_tree_add_boolean_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, guint32 value);

#if __GNUC__ == 2
proto_item *
proto_tree_add_boolean_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, guint32 value, const char *format, ...)
	__attribute__((format (printf, 7, 8)));
#else
proto_item *
proto_tree_add_boolean_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, guint32 value, const char *format, ...);
#endif

/* Add a FT_DOUBLE to a proto_tree */
proto_item *
proto_tree_add_double(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, double value);

proto_item *
proto_tree_add_double_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, double value);

#if __GNUC__ == 2
proto_item *
proto_tree_add_double_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, double value, const char *format, ...)
	__attribute__((format (printf, 7, 8)));
#else
proto_item *
proto_tree_add_double_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, double value, const char *format, ...);
#endif

/* Add any FT_UINT* to a proto_tree */
proto_item *
proto_tree_add_uint(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, guint32 value);

proto_item *
proto_tree_add_uint_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, guint32 value);

#if __GNUC__ == 2
proto_item *
proto_tree_add_uint_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, guint32 value, const char *format, ...)
	__attribute__((format (printf, 7, 8)));
#else
proto_item *
proto_tree_add_uint_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, guint32 value, const char *format, ...);
#endif

/* Add any FT_INT* to a proto_tree */
proto_item *
proto_tree_add_int(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, gint32 value);

proto_item *
proto_tree_add_int_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, gint32 value);

#if __GNUC__ == 2
proto_item *
proto_tree_add_int_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, gint32 value, const char *format, ...)
	__attribute__((format (printf, 7, 8)));
#else
proto_item *
proto_tree_add_int_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, gint32 value, const char *format, ...);
#endif


/* Add a text-only node to the proto_tree */
#if __GNUC__ == 2
proto_item *
proto_tree_add_text(proto_tree *tree, tvbuff_t *tvb, gint start, gint length, const char *,
	...) __attribute__((format (printf, 5, 6)));
#else
proto_item *
proto_tree_add_text(proto_tree *tree, tvbuff_t *tvb, gint start, gint length, const char *,
	...);
#endif

proto_item *
proto_tree_add_text_valist(proto_tree *tree, tvbuff_t *tvb, gint start,
	gint length, const char *format, va_list ap);

/* Add a node with no text */
proto_item *
proto_tree_add_notext(proto_tree *tree, tvbuff_t *tvb, gint start, gint length);


/* Useful for quick debugging. Also sends string to STDOUT, so don't
 * leave call to this function in production code. */
#if __GNUC__ == 2
proto_item *
proto_tree_add_debug_text(proto_tree *tree, const char *format, ...)
	__attribute__((format (printf, 2, 3)));
#else
proto_item *
proto_tree_add_debug_text(proto_tree *tree, const char *format, ...);
#endif

void
proto_item_fill_label(field_info *fi, gchar *label_str);

/* Returns number of items (protocols or header fields) registered. */
int proto_registrar_n(void);

/* Returns char* to name for item # n (0-indexed) */
char* proto_registrar_get_name(int n);

/* Returns char* to abbrev for item # n (0-indexed) */
char* proto_registrar_get_abbrev(int n);

/* get the header field information based upon a field or protocol id */
struct header_field_info* proto_registrar_get_nth(int hfindex);

/* Returns enum ftenum for item # n */
int proto_registrar_get_ftype(int n);

/* Returns parent protocol for item # n.
 * Returns -1 if item _is_ a protocol */
int proto_registrar_get_parent(int n);

/* Is item #n a protocol? */
gboolean proto_registrar_is_protocol(int n);

/* Is item #n decoding enabled ? */
gboolean proto_is_protocol_enabled(int n);

/* Enable / Disable protocol */
void proto_set_decoding(int n, gboolean enabled);

/* Get length of registered field according to field type.
 * 0 means undeterminable at registration time.
 * -1 means unknown field */
gint proto_registrar_get_length(int n);

/* Checks for existence any protocol or field within a tree.
 * "Protocols" are assumed to be a child of the [empty] root node.
 * TRUE = found, FALSE = not found */
gboolean proto_check_for_protocol_or_field(proto_tree* tree, int id);

/* Return GPtrArray* of field_info pointers for all hfindex that appear in
 * tree. Assume that a field will only appear under its registered parent's
 * subtree, and that the parent's subtree is a child of the
 * [empty] root node. */
GPtrArray* proto_get_finfo_ptr_array(proto_tree *tree, int hfindex);

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

/* glib doesn't have g_ptr_array_len of all things!*/
#ifndef g_ptr_array_len
#define g_ptr_array_len(a)      ((a)->len)
#endif

/* Returns a string representing the field type */
const char* proto_registrar_ftype_name(enum ftenum ftype);

#endif /* proto.h */
