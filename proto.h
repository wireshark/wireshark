/* proto.h
 * Definitions for protocol display
 *
 * $Id: proto.h,v 1.2 1999/07/07 23:54:12 guy Exp $
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
 #ifndef _SYS_TIME_H
  #include <sys/time.h>
 #endif
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
	FT_ABSOLUTE_TIME,
	FT_RELATIVE_TIME,
	FT_STRING,
	FT_ETHER,
	FT_ETHER_VENDOR,
	FT_BYTES,
	FT_IPv4,
	FT_IPv6,
	FT_IPXSERVER,
	FT_VALS_UINT8,
	FT_VALS_UINT16,
	FT_VALS_UINT24,
	FT_VALS_UINT32,
	FT_TEXT_ONLY,	/* non-filterable, used when converting ethereal
				from old-style proto_tree to new-style proto_tree */
	NUM_FIELD_TYPES /* last item number plus one */
};


typedef struct header_field_info {
	char				*name;
	char				*abbrev;
	enum ftenum			type;
	int				parent;
	struct value_string		*vals;
	int				id; /* assigned by order of registration */
/*	int				color;  for use by GUI code */
} header_field_info;

/*extern struct header_field_info hfinfo[];*/

/* Used when registering many fields at once */
typedef struct hf_register_info {
	char			*name;
	char			*abbrev;
	int			*p_id;	/* pointer to int; written to by register() function */
	enum ftenum		type;
	struct value_string	*vals;
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
		gboolean	boolean;
		guint32		numeric;
		struct timeval	abs_time; /* the whole struct, not a pointer */
		gchar		*string;
		guint8		ether[6];
	}				value;
} field_info;


typedef struct proto_tree_search_info {
	int		target_field;
	GArray		*result_array;
	const guint8	*packet_data;
} proto_tree_search_info;

void proto_init(void);
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
proto_register_field_array(int parent, const hf_register_info *hf, int num_records);

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

/* useful functions for external routines to get info about registered protos and fields */
int proto_registrar_n(void);
char* proto_registrar_get_abbrev(int n);
int proto_registrar_get_ftype(int n);
int proto_registrar_get_parent(int n);
gboolean proto_registrar_is_protocol(int n);
proto_item* proto_find_field(proto_tree* tree, int id);
proto_item* proto_find_protocol(proto_tree* tree, int protocol_id);
void proto_get_field_values(proto_tree* subtree, GNodeTraverseFunc fill_array_func,
	proto_tree_search_info *sinfo);

#endif /* proto.h */
