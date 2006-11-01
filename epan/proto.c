/* proto.c
 * Routines for protocol tree
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <glib.h>
#include <float.h>

#include "packet.h"
#include "ptvcursor.h"
#include "strutil.h"
#include "addr_resolv.h"
#include "oid_resolv.h"
#include "plugins.h"
#include "proto.h"
#include "epan_dissect.h"
#include "slab.h"
#include "tvbuff.h"
#include "emem.h"

struct ptvcursor {
	proto_tree	*tree;
	tvbuff_t	*tvb;
	gint		offset;
};

#define cVALS(x) (const value_string*)(x)

#if 1
#define TRY_TO_FAKE_THIS_ITEM(tree, hfindex) \
	/* If this item is not referenced we dont have to do much work	\
	   at all but we should still return a node so that		\
	   field items below this node ( think proto_item_add_subtree() )\
	   will still have somewhere to attach to			\
	   or else filtering will not work (they would be ignored since tree\
	   would be NULL).						\
	   DONT try to fake a node where PITEM_FINFO(pi) is NULL	\
	   since dissectors that want to do proto_item_set_len() ot	\
	   other operations that dereference this would crash.		\
	   We dont fake FT_PROTOCOL either since these are cheap and    \
	   some stuff (proto hier stat) assumes they always exist.	\
	*/								\
	if(!(PTREE_DATA(tree)->visible)){				\
		if(PITEM_FINFO(tree)){					\
			register header_field_info *hfinfo;		\
			PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);	\
			if((hfinfo->ref_count == 0)			\
			&& (hfinfo->type!=FT_PROTOCOL)){		\
				/* just return tree back to the caller */\
				return tree;				\
			}						\
		}							\
	}
#else
#define TRY_TO_FAKE_THIS_ITEM(tree, hfindex) ;
#endif

static gboolean
proto_tree_free_node(proto_node *node, gpointer data);

static void fill_label_boolean(field_info *fi, gchar *label_str);
static void fill_label_uint(field_info *fi, gchar *label_str);
static void fill_label_uint64(field_info *fi, gchar *label_str);
static void fill_label_enumerated_uint(field_info *fi, gchar *label_str);
static void fill_label_enumerated_bitfield(field_info *fi, gchar *label_str);
static void fill_label_numeric_bitfield(field_info *fi, gchar *label_str);
static void fill_label_int(field_info *fi, gchar *label_str);
static void fill_label_int64(field_info *fi, gchar *label_str);
static void fill_label_enumerated_int(field_info *fi, gchar *label_str);

int hfinfo_bitwidth(header_field_info *hfinfo);
static const char* hfinfo_uint_vals_format(header_field_info *hfinfo);
static const char* hfinfo_uint_format(header_field_info *hfinfo);
static const char* hfinfo_uint64_format(header_field_info *hfinfo);
static const char* hfinfo_int_vals_format(header_field_info *hfinfo);
static const char* hfinfo_int_format(header_field_info *hfinfo);
static const char* hfinfo_int64_format(header_field_info *hfinfo);

static proto_item*
proto_tree_add_node(proto_tree *tree, field_info *fi);

static header_field_info *
get_hfi_and_length(int hfindex, tvbuff_t *tvb, gint start, gint *length,
    gint *item_length);

static field_info *
new_field_info(proto_tree *tree, header_field_info *hfinfo, tvbuff_t *tvb,
    gint start, gint item_length);

static field_info *
alloc_field_info(proto_tree *tree, int hfindex, tvbuff_t *tvb,
        gint start, gint *length);

static proto_item *
proto_tree_add_pi(proto_tree *tree, int hfindex, tvbuff_t *tvb,
        gint start, gint *length, field_info **pfi);

static void
proto_tree_set_representation_value(proto_item *pi, const char *format, va_list ap);
static void
proto_tree_set_representation(proto_item *pi, const char *format, va_list ap);

static void
proto_tree_set_protocol_tvb(field_info *fi, tvbuff_t *tvb);
static void
proto_tree_set_bytes(field_info *fi, const guint8* start_ptr, gint length);
static void
proto_tree_set_bytes_tvb(field_info *fi, tvbuff_t *tvb, gint offset, gint length);
static void
proto_tree_set_time(field_info *fi, nstime_t *value_ptr);
static void
proto_tree_set_string(field_info *fi, const char* value, gboolean);
static void
proto_tree_set_string_tvb(field_info *fi, tvbuff_t *tvb, gint start, gint length);
static void
proto_tree_set_ether(field_info *fi, const guint8* value);
static void
proto_tree_set_ether_tvb(field_info *fi, tvbuff_t *tvb, gint start);
static void
proto_tree_set_ipxnet(field_info *fi, guint32 value);
static void
proto_tree_set_ipv4(field_info *fi, guint32 value);
static void
proto_tree_set_ipv6(field_info *fi, const guint8* value_ptr);
static void
proto_tree_set_ipv6_tvb(field_info *fi, tvbuff_t *tvb, gint start);
static void
proto_tree_set_guid(field_info *fi, const e_guid_t *value_ptr);
static void
proto_tree_set_guid_tvb(field_info *fi, tvbuff_t *tvb, gint start, gboolean little_endian);
static void
proto_tree_set_oid(field_info *fi, const guint8* value_ptr, gint length);
static void
proto_tree_set_oid_tvb(field_info *fi, tvbuff_t *tvb, gint start, gint length);
static void
proto_tree_set_boolean(field_info *fi, guint32 value);
static void
proto_tree_set_float(field_info *fi, float value);
static void
proto_tree_set_double(field_info *fi, double value);
static void
proto_tree_set_uint(field_info *fi, guint32 value);
static void
proto_tree_set_int(field_info *fi, gint32 value);
static void
proto_tree_set_uint64(field_info *fi, guint64 value);
static void
proto_tree_set_uint64_tvb(field_info *fi, tvbuff_t *tvb, gint start, gboolean little_endian);

static int proto_register_field_init(header_field_info *hfinfo, int parent);

/* Comparision function for tree insertion. A wrapper around strcmp() */
static int g_strcmp(gconstpointer a, gconstpointer b);

/* special-case header field used within proto.c */
int hf_text_only = -1;

/* Structure for information about a protocol */
struct _protocol {
	const char *name;		/* long description */
	const char *short_name;		/* short description */
	const char *filter_name;	/* name of this protocol in filters */
	int	proto_id;		/* field ID for this protocol */
	GList	*fields;		/* fields for this protocol */
	GList	*last_field;		/* pointer to end of list of fields */
	gboolean is_enabled;		/* TRUE if protocol is enabled */
	gboolean can_toggle;		/* TRUE if is_enabled can be changed */
};

/* List of all protocols */
static GList *protocols = NULL;

#define INITIAL_NUM_PROTOCOL_HFINFO     200


/* Contains information about protocols and header fields. Used when
 * dissectors register their data */
static GMemChunk *gmc_hfinfo = NULL;

/* Contains information about a field when a dissector calls
 * proto_tree_add_item.  */
SLAB_ITEM_TYPE_DEFINE(field_info)
static SLAB_FREE_LIST_DEFINE(field_info)
static field_info *field_info_tmp=NULL;
#define FIELD_INFO_NEW(fi)					\
	SLAB_ALLOC(fi, field_info)
#define FIELD_INFO_FREE(fi)					\
	SLAB_FREE(fi, field_info)



/* Contains the space for proto_nodes. */
SLAB_ITEM_TYPE_DEFINE(proto_node)
static SLAB_FREE_LIST_DEFINE(proto_node)
#define PROTO_NODE_NEW(node)				\
	SLAB_ALLOC(node, proto_node)			\
	node->first_child = NULL;			\
	node->last_child = NULL;			\
	node->next = NULL;

#define PROTO_NODE_FREE(node)				\
	SLAB_FREE(node, proto_node)



/* String space for protocol and field items for the GUI */
SLAB_ITEM_TYPE_DEFINE(item_label_t)
static SLAB_FREE_LIST_DEFINE(item_label_t)
#define ITEM_LABEL_NEW(il)				\
	SLAB_ALLOC(il, item_label_t)
#define ITEM_LABEL_FREE(il)				\
	SLAB_FREE(il, item_label_t)


#define PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo) \
	DISSECTOR_ASSERT((guint)hfindex < gpa_hfinfo.len); \
	hfinfo=gpa_hfinfo.hfi[hfindex];


/* List which stores protocols and fields that have been registered */
typedef struct _gpa_hfinfo_t {
	guint32 len;
	guint32 allocated_len;
	header_field_info **hfi;
} gpa_hfinfo_t;
gpa_hfinfo_t gpa_hfinfo;

/* Balanced tree of abbreviations and IDs */
static GTree *gpa_name_tree = NULL;

/* Points to the first element of an array of Booleans, indexed by
   a subtree item type; that array element is TRUE if subtrees of
   an item of that type are to be expanded. */
gboolean	*tree_is_expanded;

/* Number of elements in that array. */
int		num_tree_types;

/* Name hashtables for fast detection of duplicate names */
static GHashTable* proto_names = NULL;
static GHashTable* proto_short_names = NULL;
static GHashTable* proto_filter_names = NULL;

static gint
proto_compare_name(gconstpointer p1_arg, gconstpointer p2_arg)
{
	const protocol_t *p1 = p1_arg;
	const protocol_t *p2 = p2_arg;

	return g_strcasecmp(p1->short_name, p2->short_name);
}


/* initialize data structures and register protocols and fields */
void
proto_init(const char *plugin_dir
#ifndef HAVE_PLUGINS
				 _U_
#endif
	   ,
	   void (register_all_protocols)(void),
	   void (register_all_protocol_handoffs)(void))
{
	static hf_register_info hf[] = {
		{ &hf_text_only,
		{ "",	"", FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
	};


    proto_names = g_hash_table_new(g_int_hash, g_int_equal);
    proto_short_names = g_hash_table_new(g_int_hash, g_int_equal);
    proto_filter_names = g_hash_table_new(g_int_hash, g_int_equal);

	proto_cleanup();

	gmc_hfinfo = g_mem_chunk_new("gmc_hfinfo",
		sizeof(header_field_info),
        INITIAL_NUM_PROTOCOL_HFINFO * sizeof(header_field_info),
        G_ALLOC_ONLY);

	gpa_hfinfo.len=0;
	gpa_hfinfo.allocated_len=0;
	gpa_hfinfo.hfi=NULL;
	gpa_name_tree = g_tree_new(g_strcmp);

	/* Initialize the ftype subsystem */
	ftypes_initialize();

	/* Register one special-case FT_TEXT_ONLY field for use when
	   converting wireshark to new-style proto_tree. These fields
	   are merely strings on the GUI tree; they are not filterable */
	proto_register_field_array(-1, hf, array_length(hf));

	/* Have each built-in dissector register its protocols, fields,
	   dissector tables, and dissectors to be called through a
	   handle, and do whatever one-time initialization it needs to
	   do. */
	register_all_protocols();

#ifdef HAVE_PLUGINS
	/* Now scan for plugins and load all the ones we find, calling
	   their register routines to do the stuff described above. */
	init_plugins(plugin_dir);
#endif

	/* Now call the "handoff registration" routines of all built-in
	   dissectors; those routines register the dissector in other
	   dissectors' handoff tables, and fetch any dissector handles
	   they need. */
	register_all_protocol_handoffs();

#ifdef HAVE_PLUGINS
	/* Now do the same with plugins. */
	register_all_plugin_handoffs();
#endif

    /* sort the protocols by protocol name */
    protocols = g_list_sort(protocols, proto_compare_name);

	/* We've assigned all the subtree type values; allocate the array
	   for them, and zero it out. */
	tree_is_expanded = g_malloc(num_tree_types*sizeof (gboolean));
	memset(tree_is_expanded, 0, num_tree_types*sizeof (gboolean));
}

/* String comparison func for dfilter_token GTree */
static int
g_strcmp(gconstpointer a, gconstpointer b)
{
	return strcmp((const char*)a, (const char*)b);
}

void
proto_cleanup(void)
{
	/* Free the abbrev/ID GTree */
	if (gpa_name_tree) {
		g_tree_destroy(gpa_name_tree);
		gpa_name_tree = NULL;
	}

	if (gmc_hfinfo)
		g_mem_chunk_destroy(gmc_hfinfo);

	if(gpa_hfinfo.allocated_len){
		gpa_hfinfo.len=0;
		gpa_hfinfo.allocated_len=0;
		g_free(gpa_hfinfo.hfi);
		gpa_hfinfo.hfi=NULL;
	}
	if (tree_is_expanded != NULL)
		g_free(tree_is_expanded);

}

typedef gboolean (*proto_tree_traverse_func)(proto_node *, gpointer);

static gboolean
proto_tree_traverse_pre_order(proto_tree *tree, proto_tree_traverse_func func,
    gpointer data)
{
	proto_node *pnode = tree;
	proto_node *child;
	proto_node *current;

	if (func(pnode, data))
		return TRUE;

	child = pnode->first_child;
	while (child != NULL) {
		/*
		 * The routine we call might modify the child, e.g. by
		 * freeing it, so we get the child's successor before
		 * calling that routine.
		 */
		current = child;
		child = current->next;
		if (proto_tree_traverse_pre_order((proto_tree *)current, func,
		    data))
			return TRUE;
	}

	return FALSE;
}

static gboolean
proto_tree_traverse_in_order(proto_tree *tree, proto_tree_traverse_func func,
    gpointer data)
{
	proto_node *pnode = tree;
	proto_node *child;
	proto_node *current;

	child = pnode->first_child;
	if (child != NULL) {
		/*
		 * The routine we call might modify the child, e.g. by
		 * freeing it, so we get the child's successor before
		 * calling that routine.
		 */
		current = child;
		child = current->next;

		if (proto_tree_traverse_in_order((proto_tree *)current, func,
		    data))
			return TRUE;

		if (func(pnode, data))
			return TRUE;

		while (child != NULL) {
			/*
			 * The routine we call might modify the child, e.g. by
			 * freeing it, so we get the child's successor before
			 * calling that routine.
			 */
			current = child;
			child = current->next;
			if (proto_tree_traverse_in_order((proto_tree *)current,
			    func, data))
				return TRUE;
		}
	} else {
		if (func(pnode, data))
			return TRUE;
	}

	return FALSE;
}

void
proto_tree_children_foreach(proto_tree *tree, proto_tree_foreach_func func,
    gpointer data)
{
	proto_node *node = tree;
	proto_node *current;

	node = node->first_child;
	while (node != NULL) {
		current = node;
		node = current->next;
		func((proto_tree *)current, data);
	}
}

/* frees the resources that the dissection a proto_tree uses */
void
proto_tree_free(proto_tree *tree)
{
	proto_tree_traverse_in_order(tree, proto_tree_free_node, NULL);
}

static void
free_GPtrArray_value(gpointer key _U_, gpointer value, gpointer user_data _U_)
{
	GPtrArray   *ptrs = value;
	gint hfid = (gint)key;
	header_field_info *hfinfo;


	PROTO_REGISTRAR_GET_NTH(hfid, hfinfo);
	if(hfinfo->ref_count){
		/* when a field is referenced by a filter this also
		   affects the refcount for the parent protocol so we need
		   to adjust the refcount for the parent as well
		*/
		if( (hfinfo->parent != -1) && (hfinfo->ref_count) ){
			header_field_info *parent_hfinfo;
			PROTO_REGISTRAR_GET_NTH(hfinfo->parent, parent_hfinfo);
			parent_hfinfo->ref_count -= hfinfo->ref_count;
		}
		hfinfo->ref_count = 0;
	}

	g_ptr_array_free(ptrs, TRUE);
}

static void
free_node_tree_data(tree_data_t *tree_data)
{
        /* Free all the GPtrArray's in the interesting_hfids hash. */
        g_hash_table_foreach(tree_data->interesting_hfids,
            free_GPtrArray_value, NULL);

        /* And then destroy the hash. */
        g_hash_table_destroy(tree_data->interesting_hfids);

        /* And finally the tree_data_t itself. */
        g_free(tree_data);
}

#define FREE_NODE_FIELD_INFO(finfo)	\
	if(finfo->rep){			\
		ITEM_LABEL_FREE(finfo->rep);	\
	}				\
	FVALUE_CLEANUP(&finfo->value);	\
	FIELD_INFO_FREE(finfo);

static gboolean
proto_tree_free_node(proto_node *node, gpointer data _U_)
{
	field_info *finfo = PITEM_FINFO(node);

	if (finfo == NULL) {
		/* This is the root node. Destroy the per-tree data.
		 * There is no field_info to destroy. */
		free_node_tree_data(PTREE_DATA(node));
	}
	else {
		/* This is a child node. Don't free the per-tree data, but
		 * do free the field_info data. */
		FREE_NODE_FIELD_INFO(finfo);
	}

	/* Free the proto_node. */
	PROTO_NODE_FREE(node);

	return FALSE; /* FALSE = do not end traversal of protocol tree */
}

/* Is the parsing being done for a visible proto_tree or an invisible one?
 * By setting this correctly, the proto_tree creation is sped up by not
 * having to call g_vsnprintf and copy strings around.
 */
void
proto_tree_set_visible(proto_tree *tree, gboolean visible)
{
	PTREE_DATA(tree)->visible = visible;
}

/* Assume dissector set only its protocol fields.
   This function is called by dissectors and allowes to speed up filtering
   in wireshark, if this function returns FALSE it is safe to reset tree to NULL
   and thus skip calling most of the expensive proto_tree_add_...()
   functions.
   If the tree is visible we implicitely assume the field is referenced.
*/
gboolean
proto_field_is_referenced(proto_tree *tree, int proto_id)
{
	register header_field_info *hfinfo;


	if (!tree)
		return FALSE;

	if (PTREE_DATA(tree)->visible)
		return TRUE;

	PROTO_REGISTRAR_GET_NTH(proto_id, hfinfo);
	if (hfinfo->ref_count != 0)
		return TRUE;

	return FALSE;
}


/* Finds a record in the hf_info_records array by id. */
header_field_info*
proto_registrar_get_nth(guint hfindex)
{
	register header_field_info	*hfinfo;

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);
	return hfinfo;
}

/* Finds a record in the hf_info_records array by name.
 */
header_field_info*
proto_registrar_get_byname(const char *field_name)
{
	DISSECTOR_ASSERT(field_name != NULL);
	return g_tree_lookup(gpa_name_tree, field_name);
}

/* Allocates an initializes a ptvcursor_t with 3 variables:
 * 	proto_tree, tvbuff, and offset. */
ptvcursor_t*
ptvcursor_new(proto_tree *tree, tvbuff_t *tvb, gint offset)
{
	ptvcursor_t	*ptvc;

	ptvc = g_new(ptvcursor_t, 1);
	ptvc->tree	= tree;
	ptvc->tvb	= tvb;
	ptvc->offset	= offset;
	return ptvc;
}

/* Frees memory for ptvcursor_t, but nothing deeper than that. */
void
ptvcursor_free(ptvcursor_t *ptvc)
{
	g_free(ptvc);
}

/* Returns tvbuff. */
tvbuff_t*
ptvcursor_tvbuff(ptvcursor_t* ptvc)
{
	return ptvc->tvb;
}

/* Returns current offset. */
gint
ptvcursor_current_offset(ptvcursor_t* ptvc)
{
	return ptvc->offset;
}

proto_tree*
ptvcursor_tree(ptvcursor_t* ptvc)
{
	return ptvc->tree;
}

void
ptvcursor_set_tree(ptvcursor_t* ptvc, proto_tree *tree)
{
	ptvc->tree = tree;
}

/* Add a text-only node, leaving it to our caller to fill the text in */
static proto_item *
proto_tree_add_text_node(proto_tree *tree, tvbuff_t *tvb, gint start, gint length)
{
	proto_item	*pi;

	pi = proto_tree_add_pi(tree, hf_text_only, tvb, start, &length, NULL);
	if (pi == NULL)
		return(NULL);

	return pi;
}

/* Add a text-only node to the proto_tree */
proto_item *
proto_tree_add_text(proto_tree *tree, tvbuff_t *tvb, gint start, gint length,
	const char *format, ...)
{
	proto_item	*pi;
	va_list		ap;

	pi = proto_tree_add_text_node(tree, tvb, start, length);
	if (pi == NULL)
		return(NULL);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

/* Add a text-only node to the proto_tree (va_list version) */
proto_item *
proto_tree_add_text_valist(proto_tree *tree, tvbuff_t *tvb, gint start,
	gint length, const char *format, va_list ap)
{
	proto_item	*pi;

	pi = proto_tree_add_text_node(tree, tvb, start, length);
	if (pi == NULL)
		return(NULL);

	proto_tree_set_representation(pi, format, ap);

	return pi;
}

/* Add a text-only node for debugging purposes. The caller doesn't need
 * to worry about tvbuff, start, or length. Debug message gets sent to
 * STDOUT, too */
proto_item *
proto_tree_add_debug_text(proto_tree *tree, const char *format, ...)
{
	proto_item	*pi;
	va_list		ap;

	pi = proto_tree_add_text_node(tree, NULL, 0, 0);
	if (pi == NULL)
		return(NULL);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	vprintf(format, ap);
	va_end(ap);
	printf("\n");

	return pi;
}


static guint32
get_uint_value(tvbuff_t *tvb, gint offset, gint length, gboolean little_endian)
{
	guint32 value;

	switch (length) {

	case 1:
		value = tvb_get_guint8(tvb, offset);
		break;

	case 2:
		value = little_endian ? tvb_get_letohs(tvb, offset)
				      : tvb_get_ntohs(tvb, offset);
		break;

	case 3:
		value = little_endian ? tvb_get_letoh24(tvb, offset)
				      : tvb_get_ntoh24(tvb, offset);
		break;

	case 4:
		value = little_endian ? tvb_get_letohl(tvb, offset)
				      : tvb_get_ntohl(tvb, offset);
		break;

	default:
		THROW(ReportedBoundsError);
		value = 0;
		break;
	}
	return value;
}

static gint32
get_int_value(tvbuff_t *tvb, gint offset, gint length, gboolean little_endian)
{
	gint32 value;

	switch (length) {

	case 1:
		value = (gint8)tvb_get_guint8(tvb, offset);
		break;

	case 2:
		value = (gint16) (little_endian ? tvb_get_letohs(tvb, offset)
						: tvb_get_ntohs(tvb, offset));
		break;

	case 3:
		value = little_endian ? tvb_get_letoh24(tvb, offset)
				      : tvb_get_ntoh24(tvb, offset);
		if (value & 0x00800000) {
			/* Sign bit is set; sign-extend it. */
			value |= 0xFF000000;
		}
		break;

	case 4:
		value = little_endian ? tvb_get_letohl(tvb, offset)
				      : tvb_get_ntohl(tvb, offset);
		break;

	default:
		THROW(ReportedBoundsError);
		value = 0;
		break;
	}
	return value;
}

/* Add an item to a proto_tree, using the text label registered to that item;
   the item is extracted from the tvbuff handed to it. */
static proto_item *
proto_tree_new_item(field_info *new_fi, proto_tree *tree, int hfindex,
    tvbuff_t *tvb, gint start, gint length, gboolean little_endian)
{
	proto_item	*pi;
	guint32		value, n;
	float		floatval;
	double		doubleval;
	char		*string;
	GHashTable	*hash;
	GPtrArray	*ptrs;

	/* there is a possibility here that we might raise an exception
	 * and thus would lose track of the field_info.
	 * store it in a temp so that if we come here again we can reclaim
	 * the field_info without leaking memory.
	 */
	/* XXX this only keeps track of one field_info struct,
	   if we ever go multithreaded for calls to this function
	   we have to change this code to use per thread variable.
	*/
	if(field_info_tmp){
		/* oops, last one we got must have been lost due
		 * to an exception.
		 * good thing we saved it, now we can reverse the
		 * memory leak and reclaim it.
		 */
		SLAB_FREE(field_info_tmp, field_info);
	}
	/* we might throw an exception, keep track of this one
	 * across the "dangerous" section below.
	*/
	field_info_tmp=new_fi;

	switch(new_fi->hfinfo->type) {
		case FT_NONE:
			/* no value to set for FT_NONE */
			break;

		case FT_PROTOCOL:
			proto_tree_set_protocol_tvb(new_fi, tvb);
			break;

		case FT_BYTES:
			proto_tree_set_bytes_tvb(new_fi, tvb, start, length);
			break;

		case FT_UINT_BYTES:
			n = get_uint_value(tvb, start, length, little_endian);
			proto_tree_set_bytes_tvb(new_fi, tvb, start + length, n);

			/* Instead of calling proto_item_set_len(), since we don't yet
			 * have a proto_item, we set the field_info's length ourselves. */
			new_fi->length = n + length;
			break;

		case FT_BOOLEAN:
			proto_tree_set_boolean(new_fi,
			    get_uint_value(tvb, start, length, little_endian));
			break;

		/* XXX - make these just FT_UINT? */
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
			proto_tree_set_uint(new_fi,
			    get_uint_value(tvb, start, length, little_endian));
			break;

		case FT_INT64:
		case FT_UINT64:
			DISSECTOR_ASSERT(length == 8);
			proto_tree_set_uint64_tvb(new_fi, tvb, start, little_endian);
			break;

		/* XXX - make these just FT_INT? */
		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
			proto_tree_set_int(new_fi,
			    get_int_value(tvb, start, length, little_endian));
			break;

		case FT_IPv4:
			DISSECTOR_ASSERT(length == 4);
			value = tvb_get_ipv4(tvb, start);
			proto_tree_set_ipv4(new_fi, little_endian ? GUINT32_SWAP_LE_BE(value) : value);
			break;

		case FT_IPXNET:
			DISSECTOR_ASSERT(length == 4);
			proto_tree_set_ipxnet(new_fi,
			    get_uint_value(tvb, start, 4, FALSE));
			break;

		case FT_IPv6:
			DISSECTOR_ASSERT(length == 16);
			proto_tree_set_ipv6_tvb(new_fi, tvb, start);
			break;

		case FT_ETHER:
			DISSECTOR_ASSERT(length == 6);
			proto_tree_set_ether_tvb(new_fi, tvb, start);
			break;

		case FT_GUID:
			DISSECTOR_ASSERT(length == 16);
			proto_tree_set_guid_tvb(new_fi, tvb, start, little_endian);
			break;

		case FT_OID:
			proto_tree_set_oid_tvb(new_fi, tvb, start, length);
			break;

		case FT_FLOAT:
			DISSECTOR_ASSERT(length == 4);
			if (little_endian)
				floatval = tvb_get_letohieee_float(tvb, start);
			else
				floatval = tvb_get_ntohieee_float(tvb, start);
			proto_tree_set_float(new_fi, floatval);
			break;

		case FT_DOUBLE:
			DISSECTOR_ASSERT(length == 8);
			if (little_endian)
				doubleval = tvb_get_letohieee_double(tvb, start);
			else
				doubleval = tvb_get_ntohieee_double(tvb, start);
			proto_tree_set_double(new_fi, doubleval);
			break;

		case FT_STRING:
			/* This g_strdup'ed memory is freed in proto_tree_free_node() */
			proto_tree_set_string_tvb(new_fi, tvb, start, length);
			break;

		case FT_STRINGZ:
			DISSECTOR_ASSERT(length >= -1);
			/* Instead of calling proto_item_set_len(),
			 * since we don't yet have a proto_item, we
			 * set the field_info's length ourselves.
			 *
			 * XXX - our caller can't use that length to
			 * advance an offset unless they arrange that
			 * there always be a protocol tree into which
			 * we're putting this item.
			 */
			if (length == -1) {
				/* This can throw an exception */
				length = tvb_strsize(tvb, start);

				/* This g_malloc'ed memory is freed
				   in proto_tree_free_node() */
				string = g_malloc(length);

				tvb_memcpy(tvb, string, start, length);
			} else if (length == 0) {
				string = g_strdup("[Empty]");
			} else {
				/* In this case, length signifies
				 * the length of the string.
				 *
				 * This could either be a null-padded
				 * string, which doesn't necessarily
				 * have a '\0' at the end, or a
				 * null-terminated string, with a
				 * trailing '\0'.  (Yes, there are
				 * cases where you have a string
				 * that's both counted and null-
				 * terminated.)
				 *
				 * In the first case, we must
				 * allocate a buffer of length
				 * "length+1", to make room for
				 * a trailing '\0'.
				 *
				 * In the second case, we don't
				 * assume that there is a trailing
				 * '\0' there, as the packet might
				 * be malformed.  (XXX - should we
				 * throw an exception if there's no
				 * trailing '\0'?)  Therefore, we
				 * allocate a buffer of length
				 * "length+1", and put in a trailing
				 * '\0', just to be safe.
				 *
				 * (XXX - this would change if
				 * we made string values counted
				 * rather than null-terminated.)
				 */

				/* This g_malloc'ed memory is freed
				 * in proto_tree_free_node() */
				string = tvb_get_string(tvb, start,
					length);
			}
			new_fi->length = length;
			proto_tree_set_string(new_fi, string, TRUE);
			break;

		case FT_UINT_STRING:
			/* This g_strdup'ed memory is freed in proto_tree_free_node() */
			n = get_uint_value(tvb, start, length, little_endian);
			proto_tree_set_string_tvb(new_fi, tvb, start + length, n);

			/* Instead of calling proto_item_set_len(), since we
			 * don't yet have a proto_item, we set the
			 * field_info's length ourselves.
			 *
			 * XXX - our caller can't use that length to
			 * advance an offset unless they arrange that
			 * there always be a protocol tree into which
			 * we're putting this item.
			 */
			new_fi->length = n + length;
			break;

		default:
			g_error("new_fi->hfinfo->type %d (%s) not handled\n",
					new_fi->hfinfo->type,
					ftype_name(new_fi->hfinfo->type));
			DISSECTOR_ASSERT_NOT_REACHED();
			break;
	}

	/* Don't add new node to proto_tree until now so that any exceptions
	 * raised by a tvbuff access method doesn't leave junk in the proto_tree. */
	pi = proto_tree_add_node(tree, new_fi);

	/* we did not raise an exception so we dont have to remember this
	 * field_info struct any more.
	 */
	field_info_tmp=NULL;

	/* If the proto_tree wants to keep a record of this finfo
	 * for quick lookup, then record it. */
	if (new_fi->hfinfo->ref_count) {
		/*HERE*/
		hash = PTREE_DATA(tree)->interesting_hfids;
		ptrs = g_hash_table_lookup(hash, GINT_TO_POINTER(hfindex));
		if (ptrs) {
			g_ptr_array_add(ptrs, new_fi);
		}
	}

	return pi;
}

/* Gets data from tvbuff, adds it to proto_tree, increments offset,
   and returns proto_item* */
proto_item*
ptvcursor_add(ptvcursor_t *ptvc, int hfindex, gint length,
    gboolean little_endian)
{
	field_info		*new_fi;
	header_field_info	*hfinfo;
	gint			item_length;
	guint32			n;
	int			offset;

	offset = ptvc->offset;
	hfinfo = get_hfi_and_length(hfindex, ptvc->tvb, offset, &length,
	    &item_length);
	ptvc->offset += length;
	if (hfinfo->type == FT_UINT_BYTES || hfinfo->type == FT_UINT_STRING) {
		/*
		 * The length of the rest of the item is in the first N
		 * bytes of the item.
		 */
		n = get_uint_value(ptvc->tvb, offset, length, little_endian);
		ptvc->offset += n;
	}
	if (ptvc->tree == NULL)
		return NULL;

	TRY_TO_FAKE_THIS_ITEM(ptvc->tree, hfindex);

	new_fi = new_field_info(ptvc->tree, hfinfo, ptvc->tvb, offset,
	    item_length);
	if (new_fi == NULL)
		return NULL;

	return proto_tree_new_item(new_fi, ptvc->tree, hfindex, ptvc->tvb,
	    offset, length, little_endian);
}

/* Add an item to a proto_tree, using the text label registered to that item;
   the item is extracted from the tvbuff handed to it. */
proto_item *
proto_tree_add_item(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    gint start, gint length, gboolean little_endian)
{
	field_info	*new_fi;

	if (!tree)
		return(NULL);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex);

	new_fi = alloc_field_info(tree, hfindex, tvb, start, &length);

	if (new_fi == NULL)
		return(NULL);

	return proto_tree_new_item(new_fi, tree, hfindex, tvb, start,
	    length, little_endian);
}

proto_item *
proto_tree_add_item_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    gint start, gint length, gboolean little_endian)
{
	proto_item	*pi;

	pi = proto_tree_add_item(tree, hfindex, tvb, start, length, little_endian);
	if (pi == NULL)
		return(NULL);

	PROTO_ITEM_SET_HIDDEN(pi);

	return pi;
}


/* Add a FT_NONE to a proto_tree */
proto_item *
proto_tree_add_none_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		gint length, const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;
	header_field_info	*hfinfo;

	if (!tree)
		return (NULL);

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);
	DISSECTOR_ASSERT(hfinfo->type == FT_NONE);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, &length, NULL);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	/* no value to set for FT_NONE */
	return pi;
}

/* Gets data from tvbuff, adds it to proto_tree, *DOES NOT* increment
 * offset, and returns proto_item* */
proto_item*
ptvcursor_add_no_advance(ptvcursor_t* ptvc, int hf, gint length,
		gboolean endianness)
{
	proto_item	*item;

	item = proto_tree_add_item(ptvc->tree, hf, ptvc->tvb, ptvc->offset,
			length, endianness);

	return item;
}

/* Advance the ptvcursor's offset within its tvbuff without
 * adding anything to the proto_tree. */
void
ptvcursor_advance(ptvcursor_t* ptvc, gint length)
{
	ptvc->offset += length;
}


static void
proto_tree_set_protocol_tvb(field_info *fi, tvbuff_t *tvb)
{
	fvalue_set(&fi->value, tvb, TRUE);
}

/* Add a FT_PROTOCOL to a proto_tree */
proto_item *
proto_tree_add_protocol_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		gint length, const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;
	header_field_info	*hfinfo;
	field_info		*new_fi;

	if (!tree)
		return (NULL);

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);
	DISSECTOR_ASSERT(hfinfo->type == FT_PROTOCOL);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, &length, &new_fi);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	if (start == 0) {
		proto_tree_set_protocol_tvb(new_fi, tvb);
	}
	else {
		proto_tree_set_protocol_tvb(new_fi, NULL);
	}
	return pi;
}


/* Add a FT_BYTES to a proto_tree */
proto_item *
proto_tree_add_bytes(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		gint length, const guint8 *start_ptr)
{
	proto_item		*pi;
	field_info		*new_fi;
	header_field_info	*hfinfo;

	if (!tree)
		return (NULL);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex);

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);
	DISSECTOR_ASSERT(hfinfo->type == FT_BYTES);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, &length, &new_fi);
	proto_tree_set_bytes(new_fi, start_ptr, length);

	return pi;
}

proto_item *
proto_tree_add_bytes_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		gint length, const guint8 *start_ptr)
{
	proto_item		*pi;

	pi = proto_tree_add_bytes(tree, hfindex, tvb, start, length, start_ptr);
	if (pi == NULL)
		return (NULL);

	PROTO_ITEM_SET_HIDDEN(pi);

	return pi;
}

proto_item *
proto_tree_add_bytes_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
		gint start, gint length, const guint8 *start_ptr,
		const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_bytes(tree, hfindex, tvb, start, length, start_ptr);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation_value(pi, format, ap);
	va_end(ap);

	return pi;
}

proto_item *
proto_tree_add_bytes_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		gint length, const guint8 *start_ptr, const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_bytes(tree, hfindex, tvb, start, length, start_ptr);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

static void
proto_tree_set_bytes(field_info *fi, const guint8* start_ptr, gint length)
{
	GByteArray		*bytes;

	bytes = g_byte_array_new();
	if (length > 0) {
		g_byte_array_append(bytes, start_ptr, length);
	}
	fvalue_set(&fi->value, bytes, TRUE);
}


static void
proto_tree_set_bytes_tvb(field_info *fi, tvbuff_t *tvb, gint offset, gint length)
{
	proto_tree_set_bytes(fi, tvb_get_ptr(tvb, offset, length), length);
}

/* Add a FT_*TIME to a proto_tree */
proto_item *
proto_tree_add_time(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		nstime_t *value_ptr)
{
	proto_item		*pi;
	field_info		*new_fi;
	header_field_info	*hfinfo;

	if (!tree)
		return (NULL);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex);

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);
	DISSECTOR_ASSERT(hfinfo->type == FT_ABSOLUTE_TIME ||
				hfinfo->type == FT_RELATIVE_TIME);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, &length, &new_fi);
	proto_tree_set_time(new_fi, value_ptr);

	return pi;
}

proto_item *
proto_tree_add_time_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		nstime_t *value_ptr)
{
	proto_item		*pi;

	pi = proto_tree_add_time(tree, hfindex, tvb, start, length, value_ptr);
	if (pi == NULL)
		return (NULL);

	PROTO_ITEM_SET_HIDDEN(pi);

	return pi;
}

proto_item *
proto_tree_add_time_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
		gint start, gint length, nstime_t *value_ptr,
		const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_time(tree, hfindex, tvb, start, length, value_ptr);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation_value(pi, format, ap);
	va_end(ap);

	return pi;
}

proto_item *
proto_tree_add_time_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		nstime_t *value_ptr, const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_time(tree, hfindex, tvb, start, length, value_ptr);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

/* Set the FT_*TIME value */
static void
proto_tree_set_time(field_info *fi, nstime_t *value_ptr)
{
	DISSECTOR_ASSERT(value_ptr != NULL);
	fvalue_set(&fi->value, value_ptr, FALSE);
}

/* Add a FT_IPXNET to a proto_tree */
proto_item *
proto_tree_add_ipxnet(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		guint32 value)
{
	proto_item		*pi;
	field_info		*new_fi;
	header_field_info	*hfinfo;

	if (!tree)
		return (NULL);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex);

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);
	DISSECTOR_ASSERT(hfinfo->type == FT_IPXNET);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, &length, &new_fi);
	proto_tree_set_ipxnet(new_fi, value);

	return pi;
}

proto_item *
proto_tree_add_ipxnet_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		guint32 value)
{
	proto_item		*pi;

	pi = proto_tree_add_ipxnet(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	PROTO_ITEM_SET_HIDDEN(pi);

	return pi;
}

proto_item *
proto_tree_add_ipxnet_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
		gint start, gint length, guint32 value, const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_ipxnet(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation_value(pi, format, ap);
	va_end(ap);

	return pi;
}

proto_item *
proto_tree_add_ipxnet_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		guint32 value, const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_ipxnet(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

/* Set the FT_IPXNET value */
static void
proto_tree_set_ipxnet(field_info *fi, guint32 value)
{
	fvalue_set_integer(&fi->value, value);
}

/* Add a FT_IPv4 to a proto_tree */
proto_item *
proto_tree_add_ipv4(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		guint32 value)
{
	proto_item		*pi;
	field_info		*new_fi;
	header_field_info	*hfinfo;

	if (!tree)
		return (NULL);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex);

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);
	DISSECTOR_ASSERT(hfinfo->type == FT_IPv4);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, &length, &new_fi);
	proto_tree_set_ipv4(new_fi, value);

	return pi;
}

proto_item *
proto_tree_add_ipv4_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		guint32 value)
{
	proto_item		*pi;

	pi = proto_tree_add_ipv4(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	PROTO_ITEM_SET_HIDDEN(pi);

	return pi;
}

proto_item *
proto_tree_add_ipv4_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
		gint start, gint length, guint32 value, const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_ipv4(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation_value(pi, format, ap);
	va_end(ap);

	return pi;
}

proto_item *
proto_tree_add_ipv4_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		guint32 value, const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_ipv4(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

/* Set the FT_IPv4 value */
static void
proto_tree_set_ipv4(field_info *fi, guint32 value)
{
	fvalue_set_integer(&fi->value, value);
}

/* Add a FT_IPv6 to a proto_tree */
proto_item *
proto_tree_add_ipv6(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		const guint8* value_ptr)
{
	proto_item		*pi;
	field_info		*new_fi;
	header_field_info	*hfinfo;

	if (!tree)
		return (NULL);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex);

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);
	DISSECTOR_ASSERT(hfinfo->type == FT_IPv6);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, &length, &new_fi);
	proto_tree_set_ipv6(new_fi, value_ptr);

	return pi;
}

proto_item *
proto_tree_add_ipv6_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		const guint8* value_ptr)
{
	proto_item		*pi;

	pi = proto_tree_add_ipv6(tree, hfindex, tvb, start, length, value_ptr);
	if (pi == NULL)
		return (NULL);

	PROTO_ITEM_SET_HIDDEN(pi);

	return pi;
}

proto_item *
proto_tree_add_ipv6_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
		gint start, gint length, const guint8* value_ptr,
		const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_ipv6(tree, hfindex, tvb, start, length, value_ptr);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation_value(pi, format, ap);
	va_end(ap);

	return pi;
}

proto_item *
proto_tree_add_ipv6_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		const guint8* value_ptr, const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_ipv6(tree, hfindex, tvb, start, length, value_ptr);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

/* Set the FT_IPv6 value */
static void
proto_tree_set_ipv6(field_info *fi, const guint8* value_ptr)
{
	DISSECTOR_ASSERT(value_ptr != NULL);
	fvalue_set(&fi->value, (gpointer) value_ptr, FALSE);
}

static void
proto_tree_set_ipv6_tvb(field_info *fi, tvbuff_t *tvb, gint start)
{
	proto_tree_set_ipv6(fi, tvb_get_ptr(tvb, start, 16));
}

/* Add a FT_GUID to a proto_tree */
proto_item *
proto_tree_add_guid(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		const e_guid_t *value_ptr)
{
	proto_item		*pi;
	field_info		*new_fi;
	header_field_info	*hfinfo;

	if (!tree)
		return (NULL);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex);

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);
	DISSECTOR_ASSERT(hfinfo->type == FT_GUID);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, &length, &new_fi);
	proto_tree_set_guid(new_fi, value_ptr);

	return pi;
}

proto_item *
proto_tree_add_guid_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		const e_guid_t *value_ptr)
{
	proto_item		*pi;

	pi = proto_tree_add_guid(tree, hfindex, tvb, start, length, value_ptr);
	if (pi == NULL)
		return (NULL);

	PROTO_ITEM_SET_HIDDEN(pi);

	return pi;
}

proto_item *
proto_tree_add_guid_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
		gint start, gint length, const e_guid_t *value_ptr,
		const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_guid(tree, hfindex, tvb, start, length, value_ptr);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation_value(pi, format, ap);
	va_end(ap);

	return pi;
}

proto_item *
proto_tree_add_guid_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		const e_guid_t *value_ptr, const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_guid(tree, hfindex, tvb, start, length, value_ptr);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

/* Set the FT_GUID value */
static void
proto_tree_set_guid(field_info *fi, const e_guid_t *value_ptr)
{
	DISSECTOR_ASSERT(value_ptr != NULL);
	fvalue_set(&fi->value, (gpointer) value_ptr, FALSE);
}

static void
proto_tree_set_guid_tvb(field_info *fi, tvbuff_t *tvb, gint start, gboolean little_endian)
{
	e_guid_t guid;

	tvb_get_guid(tvb, start, &guid, little_endian);
	proto_tree_set_guid(fi, &guid);
}

/* Add a FT_OID to a proto_tree */
proto_item *
proto_tree_add_oid(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		const guint8* value_ptr)
{
	proto_item		*pi;
	field_info		*new_fi;
	header_field_info	*hfinfo;

	if (!tree)
		return (NULL);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex);

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);
	DISSECTOR_ASSERT(hfinfo->type == FT_OID);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, &length, &new_fi);
	proto_tree_set_oid(new_fi, value_ptr, length);

	return pi;
}

proto_item *
proto_tree_add_oid_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		const guint8* value_ptr)
{
	proto_item		*pi;

	pi = proto_tree_add_oid(tree, hfindex, tvb, start, length, value_ptr);
	if (pi == NULL)
		return (NULL);

	PROTO_ITEM_SET_HIDDEN(pi);

	return pi;
}

proto_item *
proto_tree_add_oid_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
		gint start, gint length, const guint8* value_ptr,
		const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_oid(tree, hfindex, tvb, start, length, value_ptr);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation_value(pi, format, ap);
	va_end(ap);

	return pi;
}

proto_item *
proto_tree_add_oid_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		const guint8* value_ptr, const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_oid(tree, hfindex, tvb, start, length, value_ptr);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

/* Set the FT_OID value */
static void
proto_tree_set_oid(field_info *fi, const guint8* value_ptr, gint length)
{
	GByteArray		*bytes;

	DISSECTOR_ASSERT(value_ptr != NULL);

	bytes = g_byte_array_new();
	if (length > 0) {
		g_byte_array_append(bytes, value_ptr, length);
	}
	fvalue_set(&fi->value, bytes, TRUE);
}

static void
proto_tree_set_oid_tvb(field_info *fi, tvbuff_t *tvb, gint start, gint length)
{
	proto_tree_set_oid(fi, tvb_get_ptr(tvb, start, length), length);
}

static void
proto_tree_set_uint64(field_info *fi, guint64 value)
{
	fvalue_set_integer64(&fi->value, value);
}

static void
proto_tree_set_uint64_tvb(field_info *fi, tvbuff_t *tvb, gint start, gboolean little_endian)
{
	guint64 value;

	value = little_endian ? tvb_get_letoh64(tvb, start)
			      : tvb_get_ntoh64(tvb, start);

	proto_tree_set_uint64(fi, value);
}

/* Add a FT_STRING or FT_STRINGZ to a proto_tree. Creates own copy of string,
 * and frees it when the proto_tree is destroyed. */
proto_item *
proto_tree_add_string(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		gint length, const char* value)
{
	proto_item		*pi;
	field_info		*new_fi;
	header_field_info	*hfinfo;

	if (!tree)
		return (NULL);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex);

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);
	DISSECTOR_ASSERT(hfinfo->type == FT_STRING || hfinfo->type == FT_STRINGZ);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, &length, &new_fi);
	DISSECTOR_ASSERT(length >= 0);
	proto_tree_set_string(new_fi, value, FALSE);

	return pi;
}

proto_item *
proto_tree_add_string_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		gint length, const char* value)
{
	proto_item		*pi;

	pi = proto_tree_add_string(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	PROTO_ITEM_SET_HIDDEN(pi);

	return pi;
}

proto_item *
proto_tree_add_string_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
		gint start, gint length, const char* value, const char *format,
		...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_string(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation_value(pi, format, ap);
	va_end(ap);

	return pi;
}

proto_item *
proto_tree_add_string_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		gint length, const char* value, const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_string(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

/* Appends string data to a FT_STRING or FT_STRINGZ, allowing progressive
 * field info update instead of only updating the representation as does
 * proto_item_append_text()
 */
/* NOTE: this function will break with the TRY_TO_FAKE_THIS_ITEM()
 * speed optimization.
 * Currently only WSP use this function so it is not that bad but try to
 * avoid using this one if possible.
 * IF you must use this function you MUST also disable the
 * TRY_TO_FAKE_THIS_ITEM() optimization for your dissector/function
 * using proto_item_append_string().
 * Do that by faking that the tree is visible by setting :
 *   PTREE_DATA(tree)->visible=1;  (see packet-wsp.c)
 * BEFORE you create the item you are later going to use
 * proto_item_append_string() on.
 */
void
proto_item_append_string(proto_item *pi, const char *str)
{
	field_info *fi;
	header_field_info *hfinfo;
	gchar *old_str, *new_str;

	if (!pi)
		return;
	if (!*str)
		return;

	fi = PITEM_FINFO(pi);
	hfinfo = fi->hfinfo;
	if (hfinfo->type == FT_PROTOCOL) {
		/* TRY_TO_FAKE_THIS_ITEM() speed optimization: silently skip */
		return;
	}
	DISSECTOR_ASSERT(hfinfo->type == FT_STRING || hfinfo->type == FT_STRINGZ);
	old_str = fvalue_get(&fi->value);
	new_str = g_strdup_printf("%s%s", old_str, str);
	fvalue_set(&fi->value, new_str, TRUE);
}

/* Set the FT_STRING value */
static void
proto_tree_set_string(field_info *fi, const char* value,
		gboolean already_allocated)
{
	if (value)
		fvalue_set(&fi->value, (gpointer) value, already_allocated);
	else
		fvalue_set(&fi->value, (gpointer) "[ Null ]", already_allocated);
}

static void
proto_tree_set_string_tvb(field_info *fi, tvbuff_t *tvb, gint start, gint length)
{
	gchar	*string;

	if (length == -1) {
		length = tvb_ensure_length_remaining(tvb, start);
	}

	/* This memory is freed in proto_tree_free_node() */
	string = tvb_get_string(tvb, start, length);
	proto_tree_set_string(fi, string, TRUE);
}

/* Add a FT_ETHER to a proto_tree */
proto_item *
proto_tree_add_ether(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		const guint8* value)
{
	proto_item		*pi;
	field_info		*new_fi;
	header_field_info	*hfinfo;

	if (!tree)
		return (NULL);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex);

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);
	DISSECTOR_ASSERT(hfinfo->type == FT_ETHER);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, &length, &new_fi);
	proto_tree_set_ether(new_fi, value);

	return pi;
}

proto_item *
proto_tree_add_ether_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		const guint8* value)
{
	proto_item		*pi;

	pi = proto_tree_add_ether(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	PROTO_ITEM_SET_HIDDEN(pi);

	return pi;
}

proto_item *
proto_tree_add_ether_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
		gint start, gint length, const guint8* value,
		const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_ether(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation_value(pi, format, ap);
	va_end(ap);

	return pi;
}

proto_item *
proto_tree_add_ether_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		const guint8* value, const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_ether(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

/* Set the FT_ETHER value */
static void
proto_tree_set_ether(field_info *fi, const guint8* value)
{
	fvalue_set(&fi->value, (gpointer) value, FALSE);
}

static void
proto_tree_set_ether_tvb(field_info *fi, tvbuff_t *tvb, gint start)
{
	proto_tree_set_ether(fi, tvb_get_ptr(tvb, start, 6));
}

/* Add a FT_BOOLEAN to a proto_tree */
proto_item *
proto_tree_add_boolean(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		guint32 value)
{
	proto_item		*pi;
	field_info		*new_fi;
	header_field_info	*hfinfo;

	if (!tree)
		return (NULL);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex);

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);
	DISSECTOR_ASSERT(hfinfo->type == FT_BOOLEAN);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, &length, &new_fi);
	proto_tree_set_boolean(new_fi, value);

	return pi;
}

proto_item *
proto_tree_add_boolean_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		guint32 value)
{
	proto_item		*pi;

	pi = proto_tree_add_boolean(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	PROTO_ITEM_SET_HIDDEN(pi);

	return pi;
}

proto_item *
proto_tree_add_boolean_format_value(proto_tree *tree, int hfindex,
		tvbuff_t *tvb, gint start, gint length, guint32 value,
		const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_boolean(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation_value(pi, format, ap);
	va_end(ap);

	return pi;
}

proto_item *
proto_tree_add_boolean_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		guint32 value, const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_boolean(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

/* Set the FT_BOOLEAN value */
static void
proto_tree_set_boolean(field_info *fi, guint32 value)
{
	proto_tree_set_uint(fi, value);
}

/* Add a FT_FLOAT to a proto_tree */
proto_item *
proto_tree_add_float(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		float value)
{
	proto_item		*pi;
	field_info		*new_fi;
	header_field_info	*hfinfo;

	if (!tree)
		return (NULL);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex);

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);
	DISSECTOR_ASSERT(hfinfo->type == FT_FLOAT);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, &length, &new_fi);
	proto_tree_set_float(new_fi, value);

	return pi;
}

proto_item *
proto_tree_add_float_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		float value)
{
	proto_item		*pi;

	pi = proto_tree_add_float(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	PROTO_ITEM_SET_HIDDEN(pi);

	return pi;
}

proto_item *
proto_tree_add_float_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
		gint start, gint length, float value, const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_float(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation_value(pi, format, ap);
	va_end(ap);

	return pi;
}

proto_item *
proto_tree_add_float_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		float value, const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_float(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

/* Set the FT_FLOAT value */
static void
proto_tree_set_float(field_info *fi, float value)
{
	fvalue_set_floating(&fi->value, value);
}

/* Add a FT_DOUBLE to a proto_tree */
proto_item *
proto_tree_add_double(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		double value)
{
	proto_item		*pi;
	field_info		*new_fi;
	header_field_info	*hfinfo;

	if (!tree)
		return (NULL);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex);

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);
	DISSECTOR_ASSERT(hfinfo->type == FT_DOUBLE);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, &length, &new_fi);
	proto_tree_set_double(new_fi, value);

	return pi;
}

proto_item *
proto_tree_add_double_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		double value)
{
	proto_item		*pi;

	pi = proto_tree_add_double(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	PROTO_ITEM_SET_HIDDEN(pi);

	return pi;
}

proto_item *
proto_tree_add_double_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
		gint start, gint length, double value, const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_double(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation_value(pi, format, ap);
	va_end(ap);

	return pi;
}

proto_item *
proto_tree_add_double_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		double value, const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_double(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

/* Set the FT_DOUBLE value */
static void
proto_tree_set_double(field_info *fi, double value)
{
	fvalue_set_floating(&fi->value, value);
}

/* Add FT_UINT{8,16,24,32} to a proto_tree */
proto_item *
proto_tree_add_uint(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		guint32 value)
{
	proto_item		*pi = NULL;
	field_info		*new_fi;
	header_field_info	*hfinfo;

	if (!tree)
		return (NULL);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex);

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);
	switch(hfinfo->type) {
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
		case FT_FRAMENUM:
			pi = proto_tree_add_pi(tree, hfindex, tvb, start, &length,
					&new_fi);
			proto_tree_set_uint(new_fi, value);
			break;

		default:
			DISSECTOR_ASSERT_NOT_REACHED();
	}

	return pi;
}

proto_item *
proto_tree_add_uint_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		guint32 value)
{
	proto_item		*pi;

	pi = proto_tree_add_uint(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	PROTO_ITEM_SET_HIDDEN(pi);

	return pi;
}

proto_item *
proto_tree_add_uint_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
		gint start, gint length, guint32 value, const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_uint(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation_value(pi, format, ap);
	va_end(ap);

	return pi;
}

proto_item *
proto_tree_add_uint_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		guint32 value, const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_uint(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

/* Set the FT_UINT{8,16,24,32} value */
static void
proto_tree_set_uint(field_info *fi, guint32 value)
{
	header_field_info	*hfinfo;
	guint32			integer;

	hfinfo = fi->hfinfo;
	integer = value;

	if (hfinfo->bitmask) {
		/* Mask out irrelevant portions */
		integer &= hfinfo->bitmask;

		/* Shift bits */
		if (hfinfo->bitshift > 0) {
			integer >>= hfinfo->bitshift;
		}
	}
	fvalue_set_integer(&fi->value, integer);
}

/* Add FT_UINT64 to a proto_tree */
proto_item *
proto_tree_add_uint64(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		guint64 value)
{
	proto_item		*pi = NULL;
	field_info		*new_fi;
	header_field_info	*hfinfo;

	if (!tree)
		return (NULL);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex);

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);
	DISSECTOR_ASSERT(hfinfo->type == FT_UINT64);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, &length, &new_fi);
	proto_tree_set_uint64(new_fi, value);

	return pi;
}

proto_item *
proto_tree_add_uint64_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
		gint start, gint length, guint64 value, const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_uint64(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation_value(pi, format, ap);
	va_end(ap);

	return pi;
}

proto_item *
proto_tree_add_uint64_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		guint64 value, const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_uint64(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

/* Add FT_INT{8,16,24,32} to a proto_tree */
proto_item *
proto_tree_add_int(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		gint32 value)
{
	proto_item		*pi = NULL;
	field_info		*new_fi;
	header_field_info	*hfinfo;

	if (!tree)
		return (NULL);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex);

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);
	switch(hfinfo->type) {
		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
			pi = proto_tree_add_pi(tree, hfindex, tvb, start, &length,
					&new_fi);
			proto_tree_set_int(new_fi, value);
			break;

		default:
			DISSECTOR_ASSERT_NOT_REACHED();
	}

	return pi;
}

proto_item *
proto_tree_add_int_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		gint32 value)
{
	proto_item		*pi;

	pi = proto_tree_add_int(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	PROTO_ITEM_SET_HIDDEN(pi);

	return pi;
}

proto_item *
proto_tree_add_int_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
		gint start, gint length, gint32 value, const char *format, ...)
{
	proto_item		*pi = NULL;
	va_list			ap;

	pi = proto_tree_add_int(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation_value(pi, format, ap);
	va_end(ap);

	return pi;
}

proto_item *
proto_tree_add_int_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		gint32 value, const char *format, ...)
{
	proto_item		*pi = NULL;
	va_list			ap;

	pi = proto_tree_add_int(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

/* Set the FT_INT{8,16,24,32} value */
static void
proto_tree_set_int(field_info *fi, gint32 value)
{
	header_field_info	*hfinfo;
	guint32			integer;

	hfinfo = fi->hfinfo;
	integer = (guint32) value;

	if (hfinfo->bitmask) {
		/* Mask out irrelevant portions */
		integer &= hfinfo->bitmask;

		/* Shift bits */
		if (hfinfo->bitshift > 0) {
			integer >>= hfinfo->bitshift;
		}
	}
	fvalue_set_integer(&fi->value, integer);
}

/* Add FT_INT64 to a proto_tree */
proto_item *
proto_tree_add_int64(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		gint64 value)
{
	proto_item		*pi = NULL;
	field_info		*new_fi;
	header_field_info	*hfinfo;

	if (!tree)
		return (NULL);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex);

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);
	DISSECTOR_ASSERT(hfinfo->type == FT_INT64);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, &length, &new_fi);
	proto_tree_set_uint64(new_fi, (guint64)value);

	return pi;
}

proto_item *
proto_tree_add_int64_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
		gint start, gint length, gint64 value, const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_int64(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation_value(pi, format, ap);
	va_end(ap);

	return pi;
}

proto_item *
proto_tree_add_int64_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		gint64 value, const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_int64(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

/* Throw an exception if we exceed this many tree items. */
/* XXX - This should probably be a preference */
#define MAX_TREE_ITEMS (1 * 1000 * 1000)
/* Add a field_info struct to the proto_tree, encapsulating it in a proto_node */
static proto_item *
proto_tree_add_node(proto_tree *tree, field_info *fi)
{
	proto_node *pnode, *tnode, *sibling;
	field_info *tfi;

	/*
	 * Make sure "tree" is ready to have subtrees under it, by
	 * checking whether it's been given an ett_ value.
	 *
	 * "tnode->finfo" may be null; that's the case for the root
	 * node of the protocol tree.  That node is not displayed,
	 * so it doesn't need an ett_ value to remember whether it
	 * was expanded.
	 */
	tnode = tree;
	tfi = tnode->finfo;
	if (tfi != NULL && (tfi->tree_type < 0 || tfi->tree_type >= num_tree_types)) {
		REPORT_DISSECTOR_BUG(ep_strdup_printf("\"%s\" - \"%s\" tfi->tree_type: %u invalid (%s:%u)",
			fi->hfinfo->name, fi->hfinfo->abbrev, tfi->tree_type, __FILE__, __LINE__));
		/* XXX - is it safe to continue here? */
	}

	DISSECTOR_ASSERT(tfi == NULL ||
	    (tfi->tree_type >= 0 && tfi->tree_type < num_tree_types));

	PTREE_DATA(tree)->count++;
	if (PTREE_DATA(tree)->count > MAX_TREE_ITEMS) {
		/* Let the exception handler add items to the tree */
		PTREE_DATA(tree)->count = 0;
		THROW_MESSAGE(DissectorError,
			ep_strdup_printf("More than %d items in the tree -- possible infinite loop", MAX_TREE_ITEMS));
	}

	PROTO_NODE_NEW(pnode);
	pnode->parent = tnode;
	pnode->finfo = fi;
	pnode->tree_data = PTREE_DATA(tree);

	if (tnode->last_child != NULL) {
		sibling = tnode->last_child;
		DISSECTOR_ASSERT(sibling->next == NULL);
		sibling->next = pnode;
	} else
		tnode->first_child = pnode;
	tnode->last_child = pnode;

	return (proto_item*)pnode;
}


/* Generic way to allocate field_info and add to proto_tree.
 * Sets *pfi to address of newly-allocated field_info struct, if pfi is
 * non-NULL. */
static proto_item *
proto_tree_add_pi(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint *length, field_info **pfi)
{
	proto_item	*pi;
	field_info	*fi;
	GHashTable	*hash;
	GPtrArray	*ptrs;

	if (!tree)
		return(NULL);

	fi = alloc_field_info(tree, hfindex, tvb, start, length);
	pi = proto_tree_add_node(tree, fi);

	/* If the proto_tree wants to keep a record of this finfo
	 * for quick lookup, then record it. */
	if (fi->hfinfo->ref_count) {
		/*HERE*/
		hash = PTREE_DATA(tree)->interesting_hfids;
		ptrs = g_hash_table_lookup(hash, GINT_TO_POINTER(hfindex));
		if (ptrs) {
			g_ptr_array_add(ptrs, fi);
		}
	}

	/* Does the caller want to know the fi pointer? */
	if (pfi) {
		*pfi = fi;
	}

	return pi;
}


static header_field_info *
get_hfi_and_length(int hfindex, tvbuff_t *tvb, gint start, gint *length,
    gint *item_length)
{
	header_field_info	*hfinfo;
	gint			length_remaining;

	/*
	 * We only allow a null tvbuff if the item has a zero length,
	 * i.e. if there's no data backing it.
	 */
	DISSECTOR_ASSERT(tvb != NULL || *length == 0);

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);

	/*
	 * XXX - in some protocols, there are 32-bit unsigned length
	 * fields, so lengths in protocol tree and tvbuff routines
	 * should really be unsigned.  We should have, for those
	 * field types for which "to the end of the tvbuff" makes sense,
	 * additional routines that take no length argument and
	 * add fields that run to the end of the tvbuff.
	 */
	if (*length == -1) {
		/*
		 * For FT_NONE, FT_PROTOCOL, FT_BYTES, and FT_STRING fields,
		 * a length of -1 means "set the length to what remains in
		 * the tvbuff".
		 *
		 * The assumption is either that
		 *
		 *	1) the length of the item can only be determined
		 *	   by dissection (typically true of items with
		 *	   subitems, which are probably FT_NONE or
		 *	   FT_PROTOCOL)
		 *
		 * or
		 *
		 *	2) if the tvbuff is "short" (either due to a short
		 *	   snapshot length or due to lack of reassembly of
		 *	   fragments/segments/whatever), we want to display
		 *	   what's available in the field (probably FT_BYTES
		 *	   or FT_STRING) and then throw an exception later
		 *
		 * or
		 *
		 *	3) the field is defined to be "what's left in the
		 *	   packet"
		 *
		 * so we set the length to what remains in the tvbuff so
		 * that, if we throw an exception while dissecting, it
		 * has what is probably the right value.
		 *
		 * For FT_STRINGZ, it means "the string is null-terminated,
		 * not null-padded; set the length to the actual length
		 * of the string", and if the tvbuff if short, we just
		 * throw an exception.
		 *
		 * It's not valid for any other type of field.
		 */
		switch (hfinfo->type) {

		case FT_PROTOCOL:
			/*
			 * We allow this to be zero-length - for
			 * example, an ONC RPC NULL procedure has
			 * neither arguments nor reply, so the
			 * payload for that protocol is empty.
			 *
			 * However, if the length is negative, the
			 * start offset is *past* the byte past the
			 * end of the tvbuff, so we throw an
			 * exception.
			 */
			*length = tvb_length_remaining(tvb, start);
			if (*length < 0) {
				/*
				 * Use "tvb_ensure_bytes_exist()"
				 * to force the appropriate exception
				 * to be thrown.
				 */
				tvb_ensure_bytes_exist(tvb, start, 0);
			}
			DISSECTOR_ASSERT(*length >= 0);
			break;

		case FT_NONE:
		case FT_BYTES:
		case FT_STRING:
			*length = tvb_ensure_length_remaining(tvb, start);
			DISSECTOR_ASSERT(*length >= 0);
			break;

		case FT_STRINGZ:
			/*
			 * Leave the length as -1, so our caller knows
			 * it was -1.
			 */
			break;

		default:
			DISSECTOR_ASSERT_NOT_REACHED();
		}
		*item_length = *length;
	} else {
		*item_length = *length;
		if (hfinfo->type == FT_PROTOCOL || hfinfo->type == FT_NONE) {
			/*
			 * These types are for interior nodes of the
			 * tree, and don't have data associated with
			 * them; if the length is negative (XXX - see
			 * above) or goes past the end of the tvbuff,
			 * cut it short at the end of the tvbuff.
			 * That way, if this field is selected in
			 * Wireshark, we don't highlight stuff past
			 * the end of the data.
			 */
			/* XXX - what to do, if we don't have a tvb? */
			if (tvb) {
				length_remaining = tvb_length_remaining(tvb, start);
				if (*item_length < 0 ||
				    (*item_length > 0 &&
				      (length_remaining < *item_length)))
					*item_length = length_remaining;
			}
		}
		if (*item_length < 0) {
			THROW(ReportedBoundsError);
		}
	}

	return hfinfo;
}

static field_info *
new_field_info(proto_tree *tree, header_field_info *hfinfo, tvbuff_t *tvb,
    gint start, gint item_length)
{
	field_info		*fi;

	FIELD_INFO_NEW(fi);

	fi->hfinfo = hfinfo;
	fi->start = start;
	fi->start+=(tvb)?TVB_RAW_OFFSET(tvb):0;
	fi->length = item_length;
	fi->tree_type = -1;
	fi->flags = 0;
	if (!PTREE_DATA(tree)->visible)
		FI_SET_FLAG(fi, FI_HIDDEN);
	fvalue_init(&fi->value, fi->hfinfo->type);
	fi->rep = NULL;

	/* add the data source tvbuff */
	fi->ds_tvb=tvb?TVB_GET_DS_TVB(tvb):NULL;

	return fi;
}

static field_info *
alloc_field_info(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
    gint *length)
{
	header_field_info	*hfinfo;
	gint			item_length;

	hfinfo = get_hfi_and_length(hfindex, tvb, start, length, &item_length);
	return new_field_info(tree, hfinfo, tvb, start, item_length);
}

/* If the protocol tree is to be visible, set the representation of a
   proto_tree entry with the name of the field for the item and with
   the value formatted with the supplied printf-style format and
   argument list. */
static void
proto_tree_set_representation_value(proto_item *pi, const char *format, va_list ap)
{
	int	ret;	/*tmp return value */
	int	replen;
	field_info *fi = PITEM_FINFO(pi);

	if (!PROTO_ITEM_IS_HIDDEN(pi)) {
		ITEM_LABEL_NEW(fi->rep);
		replen = 0;
		ret = g_snprintf(fi->rep->representation, ITEM_LABEL_LENGTH,
		    "%s: ", fi->hfinfo->name);
		if ((ret == -1) || (ret >= ITEM_LABEL_LENGTH)) {
			/* That's all we can put in the representation. */
			fi->rep->representation[ITEM_LABEL_LENGTH - 1] = '\0';
			return;
		}
		replen = ret;
		ret = g_vsnprintf(fi->rep->representation + replen,
		    ITEM_LABEL_LENGTH - replen, format, ap);
		if ((ret == -1) || (ret >= ITEM_LABEL_LENGTH - replen))
			fi->rep->representation[ITEM_LABEL_LENGTH - 1] = '\0';
	}
}

/* If the protocol tree is to be visible, set the representation of a
   proto_tree entry with the representation formatted with the supplied
   printf-style format and argument list. */
static void
proto_tree_set_representation(proto_item *pi, const char *format, va_list ap)
{
	int					ret;	/*tmp return value */
	field_info *fi = PITEM_FINFO(pi);

	if (!PROTO_ITEM_IS_HIDDEN(pi)) {
		ITEM_LABEL_NEW(fi->rep);
		ret = g_vsnprintf(fi->rep->representation, ITEM_LABEL_LENGTH, format, ap);
		if ((ret == -1) || (ret >= ITEM_LABEL_LENGTH))
			fi->rep->representation[ITEM_LABEL_LENGTH - 1] = '\0';
	}
}

/* Set text of proto_item after having already been created. */
void
proto_item_set_text(proto_item *pi, const char *format, ...)
{
	field_info *fi = NULL;
	va_list	ap;

	if (pi==NULL) {
		return;
	}

	fi = PITEM_FINFO(pi);

	if(fi->rep){
		ITEM_LABEL_FREE(fi->rep);
	}

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);
}

/* Append to text of proto_item after having already been created. */
void
proto_item_append_text(proto_item *pi, const char *format, ...)
{
	field_info *fi = NULL;
	size_t curlen;
	va_list	ap;
	int					ret;	/*tmp return value */

	if (pi==NULL) {
		return;
	}

	fi = PITEM_FINFO(pi);

	if (!PROTO_ITEM_IS_HIDDEN(pi)) {
		va_start(ap, format);

		/*
		 * If we don't already have a representation,
		 * generate the default representation.
		 */
		if (fi->rep == NULL) {
			ITEM_LABEL_NEW(fi->rep);
			proto_item_fill_label(fi, fi->rep->representation);
		}

		curlen = strlen(fi->rep->representation);
		if (ITEM_LABEL_LENGTH > curlen) {
			ret = g_vsnprintf(fi->rep->representation + curlen,
			    ITEM_LABEL_LENGTH - curlen, format, ap);
			if ((ret == -1) || (ret >= (int)(ITEM_LABEL_LENGTH - curlen)))
				fi->rep->representation[ITEM_LABEL_LENGTH - 1] = '\0';
		}
		va_end(ap);
	}
}

void
proto_item_set_len(proto_item *pi, gint length)
{
	field_info *fi;

	if (pi == NULL)
		return;
	fi = PITEM_FINFO(pi);
	DISSECTOR_ASSERT(length >= 0);
	fi->length = length;
}

/*
 * Sets the length of the item based on its start and on the specified
 * offset, which is the offset past the end of the item; as the start
 * in the item is relative to the beginning of the data source tvbuff,
 * we need to pass in a tvbuff - the end offset is relative to the beginning
 * of that tvbuff.
 */
void
proto_item_set_end(proto_item *pi, tvbuff_t *tvb, gint end)
{
	field_info *fi;

	if (pi == NULL)
		return;
	fi = PITEM_FINFO(pi);
	end += TVB_RAW_OFFSET(tvb);
	DISSECTOR_ASSERT(end >= fi->start);
	fi->length = end - fi->start;
}

int
proto_item_get_len(proto_item *pi)
{
	field_info *fi = PITEM_FINFO(pi);
	return fi->length;
}


/** clear flags according to the mask and set new flag values */
#define FI_REPLACE_FLAGS(fi, mask, flags_in) { \
	(fi->flags = (fi)->flags & ~(mask)); \
	(fi->flags = (fi)->flags | (flags_in)); \
}

gboolean
proto_item_set_expert_flags(proto_item *pi, int group, int severity)
{
	if(pi == NULL || pi->finfo == NULL)
		return FALSE;

	/* only change things if severity is worse or at least equal than before */
	if(severity >= FI_GET_FLAG(pi->finfo, PI_SEVERITY_MASK)) {
		FI_REPLACE_FLAGS(pi->finfo, PI_GROUP_MASK, group);
		FI_REPLACE_FLAGS(pi->finfo, PI_SEVERITY_MASK, severity);

		return TRUE;
	}

	return FALSE;
}



proto_tree*
proto_tree_create_root(void)
{
	proto_node  *pnode;

	/* Initialize the proto_node */
	PROTO_NODE_NEW(pnode);
	pnode->parent = NULL;
	pnode->finfo = NULL;
	pnode->tree_data = g_new(tree_data_t, 1);

	/* Initialize the tree_data_t */
	pnode->tree_data->interesting_hfids =
	    g_hash_table_new(g_direct_hash, g_direct_equal);

	/* Set the default to FALSE so it's easier to
	 * find errors; if we expect to see the protocol tree
	 * but for some reason the default 'visible' is not
	 * changed, then we'll find out very quickly. */
	pnode->tree_data->visible = FALSE;

	/* Keep track of the number of children */
	pnode->tree_data->count = 0;

	return (proto_tree*) pnode;
}


/* "prime" a proto_tree with a single hfid that a dfilter
 * is interested in. */
void
proto_tree_prime_hfid(proto_tree *tree, gint hfid)
{
	header_field_info *hfinfo;

	g_hash_table_insert(PTREE_DATA(tree)->interesting_hfids,
		GINT_TO_POINTER(hfid), g_ptr_array_new());

	PROTO_REGISTRAR_GET_NTH(hfid, hfinfo);
	/* this field is referenced by a filter so increase the refcount.
	   also increase the refcount for the parent, i.e the protocol.
	*/
	hfinfo->ref_count++;
	/* only increase the refcount if there is a parent.
	   if this is a protocol and not a field then parent will be -1
	   and there is no parent to add any refcounting for.
	*/
	if (hfinfo->parent != -1) {
		header_field_info *parent_hfinfo;
		PROTO_REGISTRAR_GET_NTH(hfinfo->parent, parent_hfinfo);
		parent_hfinfo->ref_count++;
	}
}

proto_tree*
proto_item_add_subtree(proto_item *pi,  gint idx) {
	field_info *fi;

	if (!pi)
		return(NULL);

	fi = PITEM_FINFO(pi);
	DISSECTOR_ASSERT(idx >= 0 && idx < num_tree_types);
	fi->tree_type = idx;

	return (proto_tree*) pi;
}

proto_tree*
proto_item_get_subtree(proto_item *pi) {
	field_info *fi;

	if (!pi)
		return(NULL);
	fi = PITEM_FINFO(pi);
	if ( (!fi) || (fi->tree_type == -1) )
		return(NULL);
	return (proto_tree*) pi;
}

proto_item*
proto_item_get_parent(proto_item *ti) {
	/* dont bother if tree is not visible */
	if( (!ti) || (!(PTREE_DATA(ti)->visible)) )
		return (NULL);
	return ti->parent;
}

proto_item*
proto_item_get_parent_nth(proto_item *ti, int gen) {
	/* dont bother if tree is not visible */
	if( (!ti) || (!(PTREE_DATA(ti)->visible)) )
		return (NULL);
	while (gen--) {
		ti = ti->parent;
		if (!ti)
			return (NULL);
	}
	return ti;
}


proto_item*
proto_tree_get_parent(proto_tree *tree) {
	/* dont bother if tree is not visible */
	if( (!tree) || (!(PTREE_DATA(tree)->visible)) )
		return (NULL);
	return (proto_item*) tree;
}

proto_tree*
proto_tree_get_root(proto_tree *tree) {
	/* dont bother if tree is not visible */
	if( (!tree) || (!(PTREE_DATA(tree)->visible)) )
		return (NULL);
	while (tree->parent) {
		tree = tree->parent;
	}
	return tree;
}

void
proto_tree_move_item(proto_tree *tree, proto_item *fixed_item, proto_item *item_to_move)
{
    proto_item *curr_item;


    /*** cut item_to_move out ***/

    /* is item_to_move the first? */
    if(tree->first_child == item_to_move) {
        /* simply change first child to next */
        tree->first_child = item_to_move->next;
    } else {
        /* find previous and change it's next */
        for(curr_item = tree->first_child; curr_item != NULL; curr_item = curr_item->next) {
            if(curr_item->next == item_to_move) {
                break;
            }
        }

        DISSECTOR_ASSERT(curr_item);

        curr_item->next = item_to_move->next;

        /* fix last_child if required */
        if(tree->last_child == item_to_move) {
            tree->last_child = curr_item;
        }
    }

    /*** insert to_move after fixed ***/
    item_to_move->next = fixed_item->next;
    fixed_item->next = item_to_move;
    if(tree->last_child == fixed_item) {
        tree->last_child = item_to_move;
    }
}


int
proto_register_protocol(const char *name, const char *short_name, const char *filter_name)
{
    protocol_t *protocol;
    header_field_info *hfinfo;
    int proto_id;
    char *existing_name;
    gint *key;
    guint i;
    guchar c;
    gboolean found_invalid;

    /*
     * Make sure there's not already a protocol with any of those
     * names.  Crash if there is, as that's an error in the code
     * or an inappropriate plugin.
     * This situation has to be fixed to not register more than one
     * protocol with the same name.
     *
     * This is done by reducing the number of strcmp (and alike) calls as much as possible,
     * as this significally slows down startup time.
     *
     * Drawback: As a hash value is used to reduce insert time,
     * this might lead to a hash collision.
     * However, as we have around 500+ protocols and we're using a 32 bit int this is very,
     * very unlikely.
     */

    key = g_malloc (sizeof(gint));
    *key = g_str_hash(name);
    existing_name = g_hash_table_lookup(proto_names, key);
    if (existing_name != NULL) {
        /* g_error will terminate the program */
        g_error("Duplicate protocol name \"%s\"!"
            " This might be caused by an inappropriate plugin or a development error.", name);
    }
    g_hash_table_insert(proto_names, key, (gpointer)name);

    key = g_malloc (sizeof(gint));
    *key = g_str_hash(short_name);
    existing_name = g_hash_table_lookup(proto_short_names, key);
    if (existing_name != NULL) {
        g_error("Duplicate protocol short_name \"%s\"!"
            " This might be caused by an inappropriate plugin or a development error.", short_name);
    }
    g_hash_table_insert(proto_short_names, key, (gpointer)short_name);

    found_invalid = FALSE;
    for (i = 0; i < strlen(filter_name); i++) {
        c = filter_name[i];
        if (!(islower(c) || isdigit(c) || c == '-' || c == '_' || c == '.')) {
            found_invalid = TRUE;
        }
    }
    if (found_invalid) {
        g_error("Protocol filter name \"%s\" has one or more invalid characters."
            " Allowed are lower characters, digits, '-', '_' and '.'."
            " This might be caused by an inappropriate plugin or a development error.", filter_name);
    }
    key = g_malloc (sizeof(gint));
    *key = g_str_hash(filter_name);
    existing_name = g_hash_table_lookup(proto_filter_names, key);
    if (existing_name != NULL) {
        g_error("Duplicate protocol filter_name \"%s\"!"
            " This might be caused by an inappropriate plugin or a development error.", filter_name);
    }
    g_hash_table_insert(proto_filter_names, key, (gpointer)filter_name);

    /* Add this protocol to the list of known protocols; the list
       is sorted by protocol short name. */
    protocol = g_malloc(sizeof (protocol_t));
    protocol->name = name;
    protocol->short_name = short_name;
    protocol->filter_name = filter_name;
    protocol->fields = NULL;
    protocol->is_enabled = TRUE; /* protocol is enabled by default */
    protocol->can_toggle = TRUE;
    /* list will be sorted later by name, when all protocols completed registering */
    protocols = g_list_append(protocols, protocol);

    /* Here we do allocate a new header_field_info struct */
    hfinfo = g_mem_chunk_alloc(gmc_hfinfo);
    hfinfo->name = name;
    hfinfo->abbrev = filter_name;
    hfinfo->type = FT_PROTOCOL;
    hfinfo->strings = protocol;
    hfinfo->bitmask = 0;
    hfinfo->bitshift = 0;
    hfinfo->ref_count = 0;
    hfinfo->blurb = NULL;
    hfinfo->parent = -1; /* this field differentiates protos and fields */

    proto_id = proto_register_field_init(hfinfo, hfinfo->parent);
    protocol->proto_id = proto_id;
    return proto_id;
}

/*
 * Routines to use to iterate over the protocols.
 * The argument passed to the iterator routines is an opaque cookie to
 * their callers; it's the GList pointer for the current element in
 * the list.
 * The ID of the protocol is returned, or -1 if there is no protocol.
 */
int
proto_get_first_protocol(void **cookie)
{
	protocol_t *protocol;

	if (protocols == NULL)
		return -1;
	*cookie = protocols;
	protocol = protocols->data;
	return protocol->proto_id;
}

int
proto_get_next_protocol(void **cookie)
{
	GList *list_item = *cookie;
	protocol_t *protocol;

	list_item = g_list_next(list_item);
	if (list_item == NULL)
		return -1;
	*cookie = list_item;
	protocol = list_item->data;
	return protocol->proto_id;
}

header_field_info *
proto_get_first_protocol_field(int proto_id, void **cookie)
{
	protocol_t *protocol = find_protocol_by_id(proto_id);
	hf_register_info *ptr;

	if ((protocol == NULL) || (protocol->fields == NULL))
		return NULL;

	*cookie = protocol->fields;
	ptr = protocol->fields->data;
	return &ptr->hfinfo;
}

header_field_info *
proto_get_next_protocol_field(void **cookie)
{
	GList *list_item = *cookie;
	hf_register_info *ptr;

	list_item = g_list_next(list_item);
	if (list_item == NULL)
		return NULL;

	*cookie = list_item;
	ptr = list_item->data;
	return &ptr->hfinfo;
}

protocol_t *
find_protocol_by_id(int proto_id)
{
	header_field_info *hfinfo;

	if(proto_id<0)
		return NULL;

	PROTO_REGISTRAR_GET_NTH(proto_id, hfinfo);
	DISSECTOR_ASSERT(hfinfo->type==FT_PROTOCOL);
	return (protocol_t *)hfinfo->strings;
}

static gint compare_filter_name(gconstpointer proto_arg,
				gconstpointer filter_name)
{
	const protocol_t *protocol = proto_arg;
	const gchar* f_name = filter_name;

	return (strcmp(protocol->filter_name, f_name));
}

int
proto_get_id(protocol_t *protocol)
{
	return protocol->proto_id;
}

int proto_get_id_by_filter_name(const gchar* filter_name)
{
	GList *list_entry;
	protocol_t *protocol;

	list_entry = g_list_find_custom(protocols, filter_name,
	    compare_filter_name);
	if (list_entry == NULL)
		return -1;
	protocol = list_entry->data;
	return protocol->proto_id;
}

const char *
proto_get_protocol_name(int proto_id)
{
	protocol_t *protocol;

	protocol = find_protocol_by_id(proto_id);
	return protocol->name;
}

const char *
proto_get_protocol_short_name(protocol_t *protocol)
{
	if (protocol == NULL)
		return "(none)";
	return protocol->short_name;
}

const char *
proto_get_protocol_filter_name(int proto_id)
{
	protocol_t *protocol;

	protocol = find_protocol_by_id(proto_id);
	return protocol->filter_name;
}

gboolean
proto_is_protocol_enabled(protocol_t *protocol)
{
	return protocol->is_enabled;
}

gboolean
proto_can_toggle_protocol(int proto_id)
{
	protocol_t *protocol;

	protocol = find_protocol_by_id(proto_id);
	return protocol->can_toggle;
}

void
proto_set_decoding(int proto_id, gboolean enabled)
{
	protocol_t *protocol;

	protocol = find_protocol_by_id(proto_id);
	DISSECTOR_ASSERT(protocol->can_toggle);
	protocol->is_enabled = enabled;
}

void
proto_set_cant_toggle(int proto_id)
{
	protocol_t *protocol;

	protocol = find_protocol_by_id(proto_id);
	protocol->can_toggle = FALSE;
}

/* for use with static arrays only, since we don't allocate our own copies
of the header_field_info struct contained within the hf_register_info struct */
void
proto_register_field_array(int parent, hf_register_info *hf, int num_records)
{
	int			field_id, i;
	hf_register_info	*ptr = hf;
	protocol_t		*proto;

	proto = find_protocol_by_id(parent);
	for (i = 0; i < num_records; i++, ptr++) {
		/*
		 * Make sure we haven't registered this yet.
		 * Most fields have variables associated with them
		 * that are initialized to -1; some have array elements,
		 * or possibly uninitialized variables, so we also allow
		 * 0 (which is unlikely to be the field ID we get back
		 * from "proto_register_field_init()").
		 */
		if (*ptr->p_id != -1 && *ptr->p_id != 0) {
			fprintf(stderr,
			    "Duplicate field detected in call to proto_register_field_array: %s is already registered\n",
			    ptr->hfinfo.abbrev);
			return;
		}

		if (proto != NULL) {
			if (proto->fields == NULL) {
				proto->fields = g_list_append(NULL, ptr);
				proto->last_field = proto->fields;
			} else {
				proto->last_field =
				    g_list_append(proto->last_field, ptr)->next;
			}
		}
		field_id = proto_register_field_init(&ptr->hfinfo, parent);
		*ptr->p_id = field_id;
	}
}

static int
proto_register_field_init(header_field_info *hfinfo, int parent)
{
	/* The field must have names */
	DISSECTOR_ASSERT(hfinfo->name);
	DISSECTOR_ASSERT(hfinfo->abbrev);

	/* These types of fields are allowed to have value_strings, true_false_strings or a protocol_t struct*/
	DISSECTOR_ASSERT((hfinfo->strings == NULL) || (
			(hfinfo->type == FT_UINT8) ||
			(hfinfo->type == FT_UINT16) ||
			(hfinfo->type == FT_UINT24) ||
			(hfinfo->type == FT_UINT32) ||
			(hfinfo->type == FT_INT8) ||
			(hfinfo->type == FT_INT16) ||
			(hfinfo->type == FT_INT24) ||
			(hfinfo->type == FT_INT32) ||
			(hfinfo->type == FT_BOOLEAN) ||
			(hfinfo->type == FT_PROTOCOL) ||
			(hfinfo->type == FT_FRAMENUM) ));

	switch (hfinfo->type) {

	case FT_UINT8:
	case FT_UINT16:
	case FT_UINT24:
	case FT_UINT32:
	case FT_INT8:
	case FT_INT16:
	case FT_INT24:
	case FT_INT32:
		/* Require integral types (other than frame number, which is
		   always displayed in decimal) to have a number base */
		DISSECTOR_ASSERT(hfinfo->display != BASE_NONE);
		break;

	case FT_FRAMENUM:
		/* Don't allow bitfields or value strings for frame numbers */
		DISSECTOR_ASSERT(hfinfo->bitmask == 0);
		DISSECTOR_ASSERT(hfinfo->strings == NULL);
		break;

	default:
		break;
	}
	/* if this is a bitfield, compute bitshift */
	if (hfinfo->bitmask) {
		while ((hfinfo->bitmask & (1 << hfinfo->bitshift)) == 0)
			hfinfo->bitshift++;
	}

	hfinfo->parent = parent;
	hfinfo->same_name_next = NULL;
	hfinfo->same_name_prev = NULL;

	/* if we always add and never delete, then id == len - 1 is correct */
	if(gpa_hfinfo.len>=gpa_hfinfo.allocated_len){
		if(!gpa_hfinfo.hfi){
			gpa_hfinfo.allocated_len=1000;
			gpa_hfinfo.hfi=g_malloc(sizeof(header_field_info *)*1000);
		} else {
			gpa_hfinfo.allocated_len+=1000;
			gpa_hfinfo.hfi=g_realloc(gpa_hfinfo.hfi, sizeof(header_field_info *)*gpa_hfinfo.allocated_len);
		}
	}
	gpa_hfinfo.hfi[gpa_hfinfo.len]=hfinfo;
	gpa_hfinfo.len++;
	hfinfo->id = gpa_hfinfo.len - 1;

	/* if we have real names, enter this field in the name tree */
	if ((hfinfo->name[0] != 0) && (hfinfo->abbrev[0] != 0 )) {

		header_field_info *same_name_hfinfo, *same_name_next_hfinfo;
		const char *p;
		guchar c;

		/* Check that the filter name (abbreviation) is legal;
		 * it must contain only alphanumerics, '-', "_", and ".". */
		for (p = hfinfo->abbrev; (c = *p) != '\0'; p++) {
			if (!(isalnum(c) || c == '-' || c == '_' || c == '.')) {
				fprintf(stderr, "OOPS: '%c' in '%s'\n", c, hfinfo->abbrev);
				DISSECTOR_ASSERT(isalnum(c) || c == '-' || c == '_' ||
			    		c == '.');
			}
		}
		/* We allow multiple hfinfo's to be registered under the same
		 * abbreviation. This was done for X.25, as, depending
		 * on whether it's modulo-8 or modulo-128 operation,
		 * some bitfield fields may be in different bits of
		 * a byte, and we want to be able to refer to that field
		 * with one name regardless of whether the packets
		 * are modulo-8 or modulo-128 packets. */
		same_name_hfinfo = g_tree_lookup(gpa_name_tree, hfinfo->abbrev);
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
		g_tree_insert(gpa_name_tree, (gpointer) (hfinfo->abbrev), hfinfo);
	}

	return hfinfo->id;
}

void
proto_register_subtree_array(gint *const *indices, int num_indices)
{
	int	i;
	gint	*const *ptr = indices;

	/*
	 * If we've already allocated the array of tree types, expand
	 * it; this lets plugins such as mate add tree types after
	 * the initial startup.  (If we haven't already allocated it,
	 * we don't allocate it; on the first pass, we just assign
	 * ett values and keep track of how many we've assigned, and
	 * when we're finished registering all dissectors we allocate
	 * the array, so that we do only one allocation rather than
	 * wasting CPU time and memory by growing the array for each
	 * dissector that registers ett values.)
	 */
	if (tree_is_expanded != NULL) {
		tree_is_expanded =
		    g_realloc(tree_is_expanded,
		        (num_tree_types+num_indices)*sizeof (gboolean));
		memset(tree_is_expanded + num_tree_types, 0,
		    num_indices*sizeof (gboolean));
	}

	/*
	 * Assign "num_indices" subtree numbers starting at "num_tree_types",
	 * returning the indices through the pointers in the array whose
	 * first element is pointed to by "indices", and update
	 * "num_tree_types" appropriately.
	 */
	for (i = 0; i < num_indices; i++, ptr++, num_tree_types++)
		**ptr = num_tree_types;
}

void
proto_item_fill_label(field_info *fi, gchar *label_str)
{
	header_field_info		*hfinfo = fi->hfinfo;

	guint8				*bytes;
	guint32				integer;
	ipv4_addr			*ipv4;
	e_guid_t			*guid;
	guint32				n_addr; /* network-order IPv4 address */
	const gchar			*name;
	int					ret;	/*tmp return value */

	switch(hfinfo->type) {
		case FT_NONE:
		case FT_PROTOCOL:
			ret = g_snprintf(label_str, ITEM_LABEL_LENGTH,
				"%s", hfinfo->name);
			if ((ret == -1) || (ret >= ITEM_LABEL_LENGTH))
				label_str[ITEM_LABEL_LENGTH - 1] = '\0';
			break;

		case FT_BOOLEAN:
			fill_label_boolean(fi, label_str);
			break;

		case FT_BYTES:
		case FT_UINT_BYTES:
			bytes = fvalue_get(&fi->value);
			if (bytes) {
				ret = g_snprintf(label_str, ITEM_LABEL_LENGTH,
					"%s: %s", hfinfo->name,
					 bytes_to_str(bytes, fvalue_length(&fi->value)));
				if ((ret == -1) || (ret >= ITEM_LABEL_LENGTH))
					label_str[ITEM_LABEL_LENGTH - 1] = '\0';
			}
			else {
				ret = g_snprintf(label_str, ITEM_LABEL_LENGTH,
					"%s: <MISSING>", hfinfo->name);
				if ((ret == -1) || (ret >= ITEM_LABEL_LENGTH))
					label_str[ITEM_LABEL_LENGTH - 1] = '\0';
			}
			break;

		/* Four types of integers to take care of:
		 * 	Bitfield, with val_string
		 * 	Bitfield, w/o val_string
		 * 	Non-bitfield, with val_string
		 * 	Non-bitfield, w/o val_string
		 */
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
		case FT_FRAMENUM:
			if (hfinfo->bitmask) {
				if (hfinfo->strings) {
					fill_label_enumerated_bitfield(fi, label_str);
				}
				else {
					fill_label_numeric_bitfield(fi, label_str);
				}
			}
			else {
				if (hfinfo->strings) {
					fill_label_enumerated_uint(fi, label_str);
				}
				else {
					fill_label_uint(fi, label_str);
				}
			}
			break;

		case FT_UINT64:
			fill_label_uint64(fi, label_str);
			break;

		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
			DISSECTOR_ASSERT(!hfinfo->bitmask);
			if (hfinfo->strings) {
				fill_label_enumerated_int(fi, label_str);
			}
			else {
				fill_label_int(fi, label_str);
			}
			break;

		case FT_INT64:
			fill_label_int64(fi, label_str);
			break;

		case FT_FLOAT:
			ret = g_snprintf(label_str, ITEM_LABEL_LENGTH,
				"%s: %." STRINGIFY(FLT_DIG) "f",
				hfinfo->name, fvalue_get_floating(&fi->value));
			if ((ret == -1) || (ret >= ITEM_LABEL_LENGTH))
				label_str[ITEM_LABEL_LENGTH - 1] = '\0';
			break;

		case FT_DOUBLE:
			ret = g_snprintf(label_str, ITEM_LABEL_LENGTH,
				"%s: %." STRINGIFY(DBL_DIG) "g",
				hfinfo->name, fvalue_get_floating(&fi->value));
			if ((ret == -1) || (ret >= ITEM_LABEL_LENGTH))
				label_str[ITEM_LABEL_LENGTH - 1] = '\0';
			break;

		case FT_ABSOLUTE_TIME:
			ret = g_snprintf(label_str, ITEM_LABEL_LENGTH,
				"%s: %s", hfinfo->name,
				abs_time_to_str(fvalue_get(&fi->value)));
			if ((ret == -1) || (ret >= ITEM_LABEL_LENGTH))
				label_str[ITEM_LABEL_LENGTH - 1] = '\0';
			break;

		case FT_RELATIVE_TIME:
			ret = g_snprintf(label_str, ITEM_LABEL_LENGTH,
				"%s: %s seconds", hfinfo->name,
				rel_time_to_secs_str(fvalue_get(&fi->value)));
			if ((ret == -1) || (ret >= ITEM_LABEL_LENGTH))
				label_str[ITEM_LABEL_LENGTH - 1] = '\0';
			break;

		case FT_IPXNET:
			integer = fvalue_get_integer(&fi->value);
			ret = g_snprintf(label_str, ITEM_LABEL_LENGTH,
				"%s: %s (0x%08X)", hfinfo->name,
				get_ipxnet_name(integer), integer);
			if ((ret == -1) || (ret >= ITEM_LABEL_LENGTH))
				label_str[ITEM_LABEL_LENGTH - 1] = '\0';
			break;

		case FT_ETHER:
			bytes = fvalue_get(&fi->value);
			ret = g_snprintf(label_str, ITEM_LABEL_LENGTH,
				"%s: %s (%s)", hfinfo->name,
				get_ether_name(bytes),
				ether_to_str(bytes));
			if ((ret == -1) || (ret >= ITEM_LABEL_LENGTH))
				label_str[ITEM_LABEL_LENGTH - 1] = '\0';
			break;

		case FT_IPv4:
			ipv4 = fvalue_get(&fi->value);
			n_addr = ipv4_get_net_order_addr(ipv4);
			ret = g_snprintf(label_str, ITEM_LABEL_LENGTH,
				"%s: %s (%s)", hfinfo->name,
				get_hostname(n_addr),
				ip_to_str((guint8*)&n_addr));
			if ((ret == -1) || (ret >= ITEM_LABEL_LENGTH))
				label_str[ITEM_LABEL_LENGTH - 1] = '\0';
			break;

		case FT_IPv6:
			bytes = fvalue_get(&fi->value);
			ret = g_snprintf(label_str, ITEM_LABEL_LENGTH,
				"%s: %s (%s)", hfinfo->name,
				get_hostname6((struct e_in6_addr *)bytes),
				ip6_to_str((struct e_in6_addr*)bytes));
			if ((ret == -1) || (ret >= ITEM_LABEL_LENGTH))
				label_str[ITEM_LABEL_LENGTH - 1] = '\0';
			break;

		case FT_GUID:
			guid = fvalue_get(&fi->value);
			ret = g_snprintf(label_str, ITEM_LABEL_LENGTH,
				"%s: %s", hfinfo->name,
				 guid_to_str(guid));
			if ((ret == -1) || (ret >= ITEM_LABEL_LENGTH))
				label_str[ITEM_LABEL_LENGTH - 1] = '\0';
			break;

		case FT_OID:
			bytes = fvalue_get(&fi->value);
			name = (oid_resolv_enabled()) ? get_oid_name(bytes, fvalue_length(&fi->value)) : NULL;
			if (name) {
				ret = g_snprintf(label_str, ITEM_LABEL_LENGTH,
					"%s: %s (%s)", hfinfo->name,
					 oid_to_str(bytes, fvalue_length(&fi->value)), name);
			} else {
				ret = g_snprintf(label_str, ITEM_LABEL_LENGTH,
					"%s: %s", hfinfo->name,
					 oid_to_str(bytes, fvalue_length(&fi->value)));
			}
			if ((ret == -1) || (ret >= ITEM_LABEL_LENGTH))
				label_str[ITEM_LABEL_LENGTH - 1] = '\0';
			break;

		case FT_STRING:
		case FT_STRINGZ:
		case FT_UINT_STRING:
			bytes = fvalue_get(&fi->value);
            if(strlen(bytes) > ITEM_LABEL_LENGTH) {
			    ret = g_snprintf(label_str, ITEM_LABEL_LENGTH,
				    "%s [truncated]: %s", hfinfo->name,
				    format_text(bytes, strlen(bytes)));
            } else {
			    ret = g_snprintf(label_str, ITEM_LABEL_LENGTH,
				    "%s: %s", hfinfo->name,
				    format_text(bytes, strlen(bytes)));
            }
			if ((ret == -1) || (ret >= ITEM_LABEL_LENGTH))
				label_str[ITEM_LABEL_LENGTH - 1] = '\0';
			break;

		default:
			g_error("hfinfo->type %d (%s) not handled\n",
					hfinfo->type,
					ftype_name(hfinfo->type));
			DISSECTOR_ASSERT_NOT_REACHED();
			break;
	}
}

static void
fill_label_boolean(field_info *fi, gchar *label_str)
{
	char	*p = label_str;
	int	bitfield_byte_length = 0, bitwidth;
	guint32	unshifted_value;
	guint32	value;
	int					ret;	/*tmp return value */

	header_field_info		*hfinfo = fi->hfinfo;
	static const true_false_string	default_tf = { "True", "False" };
	const true_false_string		*tfstring = &default_tf;

	if (hfinfo->strings) {
		tfstring = (const struct true_false_string*) hfinfo->strings;
	}

	value = fvalue_get_integer(&fi->value);
	if (hfinfo->bitmask) {
		/* Figure out the bit width */
		bitwidth = hfinfo_bitwidth(hfinfo);

		/* Un-shift bits */
		unshifted_value = value;
		if (hfinfo->bitshift > 0) {
			unshifted_value <<= hfinfo->bitshift;
		}

		/* Create the bitfield first */
		p = decode_bitfield_value(label_str, unshifted_value, hfinfo->bitmask, bitwidth);
		bitfield_byte_length = p - label_str;
	}

	/* Fill in the textual info */
	ret = g_snprintf(p, ITEM_LABEL_LENGTH - bitfield_byte_length,
		"%s: %s",  hfinfo->name,
		value ? tfstring->true_string : tfstring->false_string);
	if ((ret == -1) || (ret >= (ITEM_LABEL_LENGTH - bitfield_byte_length)))
		label_str[ITEM_LABEL_LENGTH - 1] = '\0';
}


/* Fills data for bitfield ints with val_strings */
static void
fill_label_enumerated_bitfield(field_info *fi, gchar *label_str)
{
	const char *format = NULL;
	char *p;
	int bitfield_byte_length, bitwidth;
	guint32 unshifted_value;
	guint32 value;
	int					ret;	/*tmp return value */

	header_field_info	*hfinfo = fi->hfinfo;

	/* Figure out the bit width */
	bitwidth = hfinfo_bitwidth(hfinfo);

	/* Pick the proper format string */
	format = hfinfo_uint_vals_format(hfinfo);

	/* Un-shift bits */
	unshifted_value = fvalue_get_integer(&fi->value);
	value = unshifted_value;
	if (hfinfo->bitshift > 0) {
		unshifted_value <<= hfinfo->bitshift;
	}

	/* Create the bitfield first */
	p = decode_bitfield_value(label_str, unshifted_value, hfinfo->bitmask, bitwidth);
	bitfield_byte_length = p - label_str;

	/* Fill in the textual info using stored (shifted) value */
	ret = g_snprintf(p, ITEM_LABEL_LENGTH - bitfield_byte_length,
			format,  hfinfo->name,
			val_to_str(value, cVALS(hfinfo->strings), "Unknown"), value);
	if ((ret == -1) || (ret >= (ITEM_LABEL_LENGTH - bitfield_byte_length)))
		label_str[ITEM_LABEL_LENGTH - 1] = '\0';
}

static void
fill_label_numeric_bitfield(field_info *fi, gchar *label_str)
{
	const char *format = NULL;
	char *p;
	int bitfield_byte_length, bitwidth;
	guint32 unshifted_value;
	guint32 value;
	int					ret;	/*tmp return value */

	header_field_info	*hfinfo = fi->hfinfo;

	/* Figure out the bit width */
	bitwidth = hfinfo_bitwidth(hfinfo);

	/* Pick the proper format string */
	format = hfinfo_uint_format(hfinfo);

	/* Un-shift bits */
	unshifted_value = fvalue_get_integer(&fi->value);
	value = unshifted_value;
	if (hfinfo->bitshift > 0) {
		unshifted_value <<= hfinfo->bitshift;
	}

	/* Create the bitfield using */
	p = decode_bitfield_value(label_str, unshifted_value, hfinfo->bitmask, bitwidth);
	bitfield_byte_length = p - label_str;

	/* Fill in the textual info using stored (shifted) value */
	if (IS_BASE_DUAL(hfinfo->display)) {
		ret = g_snprintf(p, ITEM_LABEL_LENGTH - bitfield_byte_length,
				format,  hfinfo->name, value, value);
	} else {
		ret = g_snprintf(p, ITEM_LABEL_LENGTH - bitfield_byte_length,
				format,  hfinfo->name, value);
	}
	if ((ret == -1) || (ret >= (ITEM_LABEL_LENGTH - bitfield_byte_length)))
		label_str[ITEM_LABEL_LENGTH - 1] = '\0';

}

static void
fill_label_enumerated_uint(field_info *fi, gchar *label_str)
{
	const char *format = NULL;
	header_field_info	*hfinfo = fi->hfinfo;
	guint32 value;
	int					ret;	/*tmp return value */

	/* Pick the proper format string */
	format = hfinfo_uint_vals_format(hfinfo);

	value = fvalue_get_integer(&fi->value);

	/* Fill in the textual info */
	ret = g_snprintf(label_str, ITEM_LABEL_LENGTH,
			format,  hfinfo->name,
			val_to_str(value, cVALS(hfinfo->strings), "Unknown"), value);
	if ((ret == -1) || (ret >= ITEM_LABEL_LENGTH))
		label_str[ITEM_LABEL_LENGTH - 1] = '\0';
}

static void
fill_label_uint(field_info *fi, gchar *label_str)
{
	const char *format = NULL;
	header_field_info	*hfinfo = fi->hfinfo;
	guint32 value;
	int					ret;	/*tmp return value */

	/* Pick the proper format string */
	format = hfinfo_uint_format(hfinfo);
	value = fvalue_get_integer(&fi->value);

	/* Fill in the textual info */
	if (IS_BASE_DUAL(hfinfo->display)) {
		ret = g_snprintf(label_str, ITEM_LABEL_LENGTH,
				format,  hfinfo->name, value, value);
	} else {
		ret = g_snprintf(label_str, ITEM_LABEL_LENGTH,
				format,  hfinfo->name, value);
	}
	if ((ret == -1) || (ret >= ITEM_LABEL_LENGTH))
		label_str[ITEM_LABEL_LENGTH - 1] = '\0';
}

static void
fill_label_uint64(field_info *fi, gchar *label_str)
{
	const char *format = NULL;
	header_field_info	*hfinfo = fi->hfinfo;
	guint64 value;
	int					ret;	/*tmp return value */

	/* Pick the proper format string */
	format = hfinfo_uint64_format(hfinfo);
	value = fvalue_get_integer64(&fi->value);

	/* Fill in the textual info */
	if (IS_BASE_DUAL(hfinfo->display)) {
		ret = g_snprintf(label_str, ITEM_LABEL_LENGTH,
				format,  hfinfo->name, value, value);
	} else {
		ret = g_snprintf(label_str, ITEM_LABEL_LENGTH,
				format,  hfinfo->name, value);
	}
	if ((ret == -1) || (ret >= ITEM_LABEL_LENGTH))
		label_str[ITEM_LABEL_LENGTH - 1] = '\0';
}

static void
fill_label_enumerated_int(field_info *fi, gchar *label_str)
{
	const char *format = NULL;
	header_field_info	*hfinfo = fi->hfinfo;
	guint32 value;
	int					ret;	/*tmp return value */

	/* Pick the proper format string */
	format = hfinfo_int_vals_format(hfinfo);
	value = fvalue_get_integer(&fi->value);

	/* Fill in the textual info */
	ret = g_snprintf(label_str, ITEM_LABEL_LENGTH,
			format,  hfinfo->name,
			val_to_str(value, cVALS(hfinfo->strings), "Unknown"), value);
	if ((ret == -1) || (ret >= ITEM_LABEL_LENGTH))
		label_str[ITEM_LABEL_LENGTH - 1] = '\0';
}

static void
fill_label_int(field_info *fi, gchar *label_str)
{
	const char *format = NULL;
	header_field_info	*hfinfo = fi->hfinfo;
	guint32 value;
	int					ret;	/*tmp return value */

	/* Pick the proper format string */
	format = hfinfo_int_format(hfinfo);
	value = fvalue_get_integer(&fi->value);

	/* Fill in the textual info */
	if (IS_BASE_DUAL(hfinfo->display)) {
		ret = g_snprintf(label_str, ITEM_LABEL_LENGTH,
				format,  hfinfo->name, value, value);
	} else {
		ret = g_snprintf(label_str, ITEM_LABEL_LENGTH,
				format,  hfinfo->name, value);
	}
	if ((ret == -1) || (ret >= ITEM_LABEL_LENGTH))
		label_str[ITEM_LABEL_LENGTH - 1] = '\0';
}

static void
fill_label_int64(field_info *fi, gchar *label_str)
{
	const char *format = NULL;
	header_field_info	*hfinfo = fi->hfinfo;
	guint64 value;
	int					ret;	/*tmp return value */

	/* Pick the proper format string */
	format = hfinfo_int64_format(hfinfo);
	value = fvalue_get_integer64(&fi->value);

	/* Fill in the textual info */
	if (IS_BASE_DUAL(hfinfo->display)) {
		ret = g_snprintf(label_str, ITEM_LABEL_LENGTH,
				format,  hfinfo->name, value, value);
	} else {
		ret = g_snprintf(label_str, ITEM_LABEL_LENGTH,
				format,  hfinfo->name, value);
	}
	if ((ret == -1) || (ret >= ITEM_LABEL_LENGTH))
		label_str[ITEM_LABEL_LENGTH - 1] = '\0';
}

int
hfinfo_bitwidth(header_field_info *hfinfo)
{
	int bitwidth = 0;

	if (!hfinfo->bitmask) {
		return 0;
	}

	switch(hfinfo->type) {
		case FT_UINT8:
		case FT_INT8:
			bitwidth = 8;
			break;
		case FT_UINT16:
		case FT_INT16:
			bitwidth = 16;
			break;
		case FT_UINT24:
		case FT_INT24:
			bitwidth = 24;
			break;
		case FT_UINT32:
		case FT_INT32:
			bitwidth = 32;
			break;
		case FT_BOOLEAN:
			bitwidth = hfinfo->display; /* hacky? :) */
			break;
		default:
			DISSECTOR_ASSERT_NOT_REACHED();
			;
	}
	return bitwidth;
}

static const char*
hfinfo_uint_vals_format(header_field_info *hfinfo)
{
	const char *format = NULL;

	switch(hfinfo->display) {
		case BASE_DEC:
		case BASE_DEC_HEX:
			format = "%s: %s (%u)";
			break;
		case BASE_OCT: /* I'm lazy */
			format = "%s: %s (%o)";
			break;
		case BASE_HEX:
		case BASE_HEX_DEC:
			switch(hfinfo->type) {
				case FT_UINT8:
					format = "%s: %s (0x%02x)";
					break;
				case FT_UINT16:
					format = "%s: %s (0x%04x)";
					break;
				case FT_UINT24:
					format = "%s: %s (0x%06x)";
					break;
				case FT_UINT32:
					format = "%s: %s (0x%08x)";
					break;
				default:
					DISSECTOR_ASSERT_NOT_REACHED();
					;
			}
			break;
		default:
			DISSECTOR_ASSERT_NOT_REACHED();
			;
	}
	return format;
}

static const char*
hfinfo_uint_format(header_field_info *hfinfo)
{
	const char *format = NULL;

	/* Pick the proper format string */
	if (hfinfo->type == FT_FRAMENUM) {
		/*
		 * Frame numbers are always displayed in decimal.
		 */
		format = "%s: %u";
	} else {
		switch(hfinfo->display) {
			case BASE_DEC:
				format = "%s: %u";
				break;
			case BASE_DEC_HEX:
				switch(hfinfo->type) {
					case FT_UINT8:
						format = "%s: %u (0x%02x)";
						break;
					case FT_UINT16:
						format = "%s: %u (0x%04x)";
						break;
					case FT_UINT24:
						format = "%s: %u (0x%06x)";
						break;
					case FT_UINT32:
						format = "%s: %u (0x%08x)";
						break;
					default:
						DISSECTOR_ASSERT_NOT_REACHED();
						;
				}
				break;
			case BASE_OCT: /* I'm lazy */
				format = "%s: %o";
				break;
			case BASE_HEX:
				switch(hfinfo->type) {
					case FT_UINT8:
						format = "%s: 0x%02x";
						break;
					case FT_UINT16:
						format = "%s: 0x%04x";
						break;
					case FT_UINT24:
						format = "%s: 0x%06x";
						break;
					case FT_UINT32:
						format = "%s: 0x%08x";
						break;
					default:
						DISSECTOR_ASSERT_NOT_REACHED();
						;
				}
				break;
			case BASE_HEX_DEC:
				switch(hfinfo->type) {
					case FT_UINT8:
						format = "%s: 0x%02x (%u)";
						break;
					case FT_UINT16:
						format = "%s: 0x%04x (%u)";
						break;
					case FT_UINT24:
						format = "%s: 0x%06x (%u)";
						break;
					case FT_UINT32:
						format = "%s: 0x%08x (%u)";
						break;
					default:
						DISSECTOR_ASSERT_NOT_REACHED();
						;
				}
				break;
			default:
				DISSECTOR_ASSERT_NOT_REACHED();
				;
		}
	}
	return format;
}

static const char*
hfinfo_int_vals_format(header_field_info *hfinfo)
{
	const char *format = NULL;

	switch(hfinfo->display) {
		case BASE_DEC:
		case BASE_DEC_HEX:
			format = "%s: %s (%d)";
			break;
		case BASE_OCT: /* I'm lazy */
			format = "%s: %s (%o)";
			break;
		case BASE_HEX:
		case BASE_HEX_DEC:
			switch(hfinfo->type) {
				case FT_INT8:
					format = "%s: %s (0x%02x)";
					break;
				case FT_INT16:
					format = "%s: %s (0x%04x)";
					break;
				case FT_INT24:
					format = "%s: %s (0x%06x)";
					break;
				case FT_INT32:
					format = "%s: %s (0x%08x)";
					break;
				default:
					DISSECTOR_ASSERT_NOT_REACHED();
					;
			}
			break;
		default:
			DISSECTOR_ASSERT_NOT_REACHED();
			;
	}
	return format;
}

static const char*
hfinfo_uint64_format(header_field_info *hfinfo)
{
	const char *format = NULL;

	/* Pick the proper format string */
	switch(hfinfo->display) {
		case BASE_DEC:
			format = "%s: %" PRIu64;
			break;
		case BASE_DEC_HEX:
			format = "%s: %" PRIu64 " (%" PRIx64 ")";
			break;
		case BASE_OCT: /* I'm lazy */
			format = "%s: %" PRIo64;
			break;
		case BASE_HEX:
			format = "%s: 0x%016" PRIx64;
			break;
		case BASE_HEX_DEC:
			format = "%s: 0x%016" PRIx64 " (%" PRIu64 ")";
			break;
		default:
			DISSECTOR_ASSERT_NOT_REACHED();
			;
	}
	return format;
}

static const char*
hfinfo_int_format(header_field_info *hfinfo)
{
	const char *format = NULL;

	/* Pick the proper format string */
	switch(hfinfo->display) {
		case BASE_DEC:
			format = "%s: %d";
			break;
		case BASE_DEC_HEX:
			switch(hfinfo->type) {
				case FT_INT8:
					format = "%s: %d (0x%02x)";
					break;
				case FT_INT16:
					format = "%s: %d (0x%04x)";
					break;
				case FT_INT24:
					format = "%s: %d (0x%06x)";
					break;
				case FT_INT32:
					format = "%s: %d (0x%08x)";
					break;
				default:
					DISSECTOR_ASSERT_NOT_REACHED();
					;
			}
		case BASE_OCT: /* I'm lazy */
			format = "%s: %o";
			break;
		case BASE_HEX:
			switch(hfinfo->type) {
				case FT_INT8:
					format = "%s: 0x%02x";
					break;
				case FT_INT16:
					format = "%s: 0x%04x";
					break;
				case FT_INT24:
					format = "%s: 0x%06x";
					break;
				case FT_INT32:
					format = "%s: 0x%08x";
					break;
				default:
					DISSECTOR_ASSERT_NOT_REACHED();
					;
			}
			break;
		case BASE_HEX_DEC:
			switch(hfinfo->type) {
				case FT_INT8:
					format = "%s: 0x%02x (%d)";
					break;
				case FT_INT16:
					format = "%s: 0x%04x (%d)";
					break;
				case FT_INT24:
					format = "%s: 0x%06x (%d)";
					break;
				case FT_INT32:
					format = "%s: 0x%08x (%d)";
					break;
				default:
					DISSECTOR_ASSERT_NOT_REACHED();
					;
			}
			break;
		default:
			DISSECTOR_ASSERT_NOT_REACHED();
			;
	}
	return format;
}

static const char*
hfinfo_int64_format(header_field_info *hfinfo)
{
	const char *format = NULL;

	/* Pick the proper format string */
	switch(hfinfo->display) {
		case BASE_DEC:
			format = "%s: %" PRId64;
			break;
		case BASE_DEC_HEX:
			format = "%s: %" PRId64 " (%" PRIx64 ")";
			break;
		case BASE_OCT: /* I'm lazy */
			format = "%s: %" PRIo64;
			break;
		case BASE_HEX:
			format = "%s: 0x%016" PRIx64;
			break;
		case BASE_HEX_DEC:
			format = "%s: 0x%016" PRIx64 " (%" PRId64 ")";
			break;
		default:
			DISSECTOR_ASSERT_NOT_REACHED();
			;
	}
	return format;
}



int
proto_registrar_n(void)
{
	return gpa_hfinfo.len;
}

const char*
proto_registrar_get_name(int n)
{
	header_field_info *hfinfo;

	PROTO_REGISTRAR_GET_NTH(n, hfinfo);
	return hfinfo->name;
}

const char*
proto_registrar_get_abbrev(int n)
{
	header_field_info *hfinfo;

	PROTO_REGISTRAR_GET_NTH(n, hfinfo);
	return hfinfo->abbrev;
}

int
proto_registrar_get_ftype(int n)
{
	header_field_info *hfinfo;

	PROTO_REGISTRAR_GET_NTH(n, hfinfo);
	return hfinfo->type;
}

int
proto_registrar_get_parent(int n)
{
	header_field_info *hfinfo;

	PROTO_REGISTRAR_GET_NTH(n, hfinfo);
	return hfinfo->parent;
}

gboolean
proto_registrar_is_protocol(int n)
{
	header_field_info *hfinfo;

	PROTO_REGISTRAR_GET_NTH(n, hfinfo);
	return (hfinfo->parent == -1 ? TRUE : FALSE);
}

/* Returns length of field in packet (not necessarily the length
 * in our internal representation, as in the case of IPv4).
 * 0 means undeterminable at time of registration
 * -1 means the field is not registered. */
gint
proto_registrar_get_length(int n)
{
	header_field_info *hfinfo;

	PROTO_REGISTRAR_GET_NTH(n, hfinfo);
	return ftype_length(hfinfo->type);
}



/* Looks for a protocol or a field in a proto_tree. Returns TRUE if
 * it exists anywhere, or FALSE if it exists nowhere. */
gboolean
proto_check_for_protocol_or_field(proto_tree* tree, int id)
{
	GPtrArray *ptrs = proto_get_finfo_ptr_array(tree, id);

	if (!ptrs) {
		return FALSE;
	}
	else if (g_ptr_array_len(ptrs) > 0) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}

/* Return GPtrArray* of field_info pointers for all hfindex that appear in tree.
 * This only works if the hfindex was "primed" before the dissection
 * took place, as we just pass back the already-created GPtrArray*.
 * The caller should *not* free the GPtrArray*; proto_tree_free_node()
 * handles that. */
GPtrArray*
proto_get_finfo_ptr_array(proto_tree *tree, int id)
{
	return g_hash_table_lookup(PTREE_DATA(tree)->interesting_hfids,
	    GINT_TO_POINTER(id));
}


/* Helper struct for proto_find_info() and  proto_all_finfos() */
typedef struct {
	GPtrArray	*array;
	int		id;
} ffdata_t;

/* Helper function for proto_find_info() */
static gboolean
find_finfo(proto_node *node, gpointer data)
{
	field_info *fi = PITEM_FINFO(node);
	if (fi && fi->hfinfo) {
		if (fi->hfinfo->id == ((ffdata_t*)data)->id) {
			g_ptr_array_add(((ffdata_t*)data)->array, fi);
		}
	}

	/* Don't stop traversing. */
	return FALSE;
}

/* Return GPtrArray* of field_info pointers for all hfindex that appear in a tree.
* This works on any proto_tree, primed or unprimed, but actually searches
* the tree, so it is slower than using proto_get_finfo_ptr_array on a primed tree.
* The caller does need to free the returned GPtrArray with
* g_ptr_array_free(<array>, FALSE).
*/
GPtrArray*
proto_find_finfo(proto_tree *tree, int id)
{
	ffdata_t	ffdata;

	ffdata.array = g_ptr_array_new();
	ffdata.id = id;

	proto_tree_traverse_pre_order(tree, find_finfo, &ffdata);

	return ffdata.array;
}

/* Helper function for proto_all_finfos() */
static gboolean
every_finfo(proto_node *node, gpointer data)
{
	field_info *fi = PITEM_FINFO(node);
	if (fi && fi->hfinfo) {
		g_ptr_array_add(((ffdata_t*)data)->array, fi);
	}

	/* Don't stop traversing. */
	return FALSE;
}

/* Return GPtrArray* of field_info pointers containing all hfindexes that appear in a tree. */
GPtrArray*
proto_all_finfos(proto_tree *tree)
{
	ffdata_t	ffdata;

	ffdata.array = g_ptr_array_new();
	ffdata.id = 0;

	proto_tree_traverse_pre_order(tree, every_finfo, &ffdata);

	return ffdata.array;
}


typedef struct {
	guint		offset;
	field_info	*finfo;
	tvbuff_t	*tvb;
} offset_search_t;

static gboolean
check_for_offset(proto_node *node, gpointer data)
{
	field_info          *fi = PITEM_FINFO(node);
	offset_search_t		*offsearch = data;

	/* !fi == the top most container node which holds nothing */
	if (fi && !PROTO_ITEM_IS_HIDDEN(node) && fi->ds_tvb && offsearch->tvb == fi->ds_tvb) {
		if (offsearch->offset >= (guint) fi->start &&
				offsearch->offset < (guint) (fi->start + fi->length)) {

			offsearch->finfo = fi;
			return FALSE; /* keep traversing */
		}
	}
	return FALSE; /* keep traversing */
}

/* Search a proto_tree backwards (from leaves to root) looking for the field
 * whose start/length occupies 'offset' */
/* XXX - I couldn't find an easy way to search backwards, so I search
 * forwards, w/o stopping. Therefore, the last finfo I find will the be
 * the one I want to return to the user. This algorithm is inefficient
 * and could be re-done, but I'd have to handle all the children and
 * siblings of each node myself. When I have more time I'll do that.
 * (yeah right) */
field_info*
proto_find_field_from_offset(proto_tree *tree, guint offset, tvbuff_t *tvb)
{
	offset_search_t		offsearch;

	offsearch.offset = offset;
	offsearch.finfo = NULL;
	offsearch.tvb = tvb;

	proto_tree_traverse_pre_order(tree, check_for_offset, &offsearch);

	return offsearch.finfo;
}

/* Dumps the protocols in the registration database to stdout.  An independent
 * program can take this output and format it into nice tables or HTML or
 * whatever.
 *
 * There is one record per line. The fields are tab-delimited.
 *
 * Field 1 = protocol name
 * Field 2 = protocol short name
 * Field 3 = protocol filter name
 */
void
proto_registrar_dump_protocols(void)
{
	protocol_t		*protocol;
	int			i;
	void			*cookie = NULL;

	for (i = proto_get_first_protocol(&cookie); i != -1;
	    i = proto_get_next_protocol(&cookie)) {
		protocol = find_protocol_by_id(i);
		printf("%s\t%s\t%s\n", protocol->name, protocol->short_name,
		    protocol->filter_name);
	}
}

/* Dumps the value_string and true/false strings for fields that have
 * them. There is one record per line. Fields are tab-delimited.
 * There are two types of records, Value String records and True/False
 * String records. The first field, 'V' or 'T', indicates the type
 * of record.
 *
 * Value Strings
 * -------------
 * Field 1 = 'V'
 * Field 2 = field abbreviation to which this value string corresponds
 * Field 3 = Integer value
 * Field 4 = String
 *
 * True/False Strings
 * ------------------
 * Field 1 = 'T'
 * Field 2 = field abbreviation to which this true/false string corresponds
 * Field 3 = True String
 * Field 4 = False String
 */
void
proto_registrar_dump_values(void)
{
	header_field_info	*hfinfo, *parent_hfinfo;
	int			i, len, vi;
	const value_string	*vals;
	const true_false_string	*tfs;

	len = gpa_hfinfo.len;
	for (i = 0; i < len ; i++) {
		PROTO_REGISTRAR_GET_NTH(i, hfinfo);

		 if (hfinfo->id == hf_text_only) {
			 continue;
		 }

		/* ignore protocols */
		if (proto_registrar_is_protocol(i)) {
			continue;
		}
		/* process header fields */
		else {
			/*
			 * If this field isn't at the head of the list of
			 * fields with this name, skip this field - all
			 * fields with the same name are really just versions
			 * of the same field stored in different bits, and
			 * should have the same type/radix/value list, and
			 * just differ in their bit masks.  (If a field isn't
			 * a bitfield, but can be, say, 1 or 2 bytes long,
			 * it can just be made FT_UINT16, meaning the
			 * *maximum* length is 2 bytes, and be used
			 * for all lengths.)
			 */
			if (hfinfo->same_name_prev != NULL)
				continue;

			PROTO_REGISTRAR_GET_NTH(hfinfo->parent, parent_hfinfo);

			vals = NULL;
			tfs = NULL;

			if (hfinfo->type == FT_UINT8 ||
				hfinfo->type == FT_UINT16 ||
				hfinfo->type == FT_UINT24 ||
				hfinfo->type == FT_UINT32 ||
				hfinfo->type == FT_UINT64 ||
				hfinfo->type == FT_INT8 ||
				hfinfo->type == FT_INT16 ||
				hfinfo->type == FT_INT24 ||
				hfinfo->type == FT_INT32 ||
				hfinfo->type == FT_INT64) {

				vals = hfinfo->strings;
			}
			else if (hfinfo->type == FT_BOOLEAN) {
				tfs = hfinfo->strings;
			}

			/* Print value strings? */
			if (vals) {
				vi = 0;
				while (vals[vi].strptr) {
					/* Print in the proper base */
					if (hfinfo->display == BASE_HEX) {
						printf("V\t%s\t0x%x\t%s\n",
								hfinfo->abbrev,
								vals[vi].value,
								vals[vi].strptr);
					}
					else {
						printf("V\t%s\t%u\t%s\n",
								hfinfo->abbrev,
								vals[vi].value,
								vals[vi].strptr);
					}
					vi++;
				}
			}

			/* Print true/false strings? */
			else if (tfs) {
				printf("T\t%s\t%s\t%s\n", hfinfo->abbrev,
						tfs->true_string, tfs->false_string);
			}
		}
	}
}

/* Dumps the contents of the registration database to stdout. An indepedent
 * program can take this output and format it into nice tables or HTML or
 * whatever.
 *
 * There is one record per line. Each record is either a protocol or a header
 * field, differentiated by the first field. The fields are tab-delimited.
 *
 * Protocols
 * ---------
 * Field 1 = 'P'
 * Field 2 = descriptive protocol name
 * Field 3 = protocol abbreviation
 *
 * Header Fields
 * -------------
 * (format 1)
 * Field 1 = 'F'
 * Field 2 = descriptive field name
 * Field 3 = field abbreviation
 * Field 4 = type ( textual representation of the the ftenum type )
 * Field 5 = parent protocol abbreviation
 * Field 6 = blurb describing field
 *
 * (format 2)
 * Field 1 = 'F'
 * Field 2 = descriptive field name
 * Field 3 = field abbreviation
 * Field 4 = type ( textual representation of the the ftenum type )
 * Field 5 = parent protocol abbreviation
 * Field 6 = blurb describing field
 * Field 7 = base for display (for integer types)
 * Field 8 = blurb describing field (yes, apparently we repeated this accidentally)
 *
 * (format 3)
 * Field 1 = 'F'
 * Field 2 = descriptive field name
 * Field 3 = field abbreviation
 * Field 4 = type ( textual representation of the the ftenum type )
 * Field 5 = parent protocol abbreviation
 * Field 6 = blurb describing field
 * Field 7 = base for display (for integer types)
 * Field 8 = bitmask
 */
void
proto_registrar_dump_fields(int format)
{
	header_field_info	*hfinfo, *parent_hfinfo;
	int			i, len;
	const char 		*enum_name;
	const char		*base_name;
	const char		*blurb;

	len = gpa_hfinfo.len;
	for (i = 0; i < len ; i++) {
		PROTO_REGISTRAR_GET_NTH(i, hfinfo);

		/*
		 * Skip the pseudo-field for "proto_tree_add_text()" since
		 * we don't want it in the list of filterable fields.
         */
        if (hfinfo->id == hf_text_only)
			continue;

		/* format for protocols */
		if (proto_registrar_is_protocol(i)) {
			printf("P\t%s\t%s\n", hfinfo->name, hfinfo->abbrev);
		}
		/* format for header fields */
		else {
			/*
			 * If this field isn't at the head of the list of
			 * fields with this name, skip this field - all
			 * fields with the same name are really just versions
			 * of the same field stored in different bits, and
			 * should have the same type/radix/value list, and
			 * just differ in their bit masks.  (If a field isn't
			 * a bitfield, but can be, say, 1 or 2 bytes long,
			 * it can just be made FT_UINT16, meaning the
			 * *maximum* length is 2 bytes, and be used
			 * for all lengths.)
			 */
			if (hfinfo->same_name_prev != NULL)
				continue;

			PROTO_REGISTRAR_GET_NTH(hfinfo->parent, parent_hfinfo);

			enum_name = ftype_name(hfinfo->type);
			base_name = "";

			if (format > 1) {
				if (hfinfo->type == FT_UINT8 ||
					hfinfo->type == FT_UINT16 ||
					hfinfo->type == FT_UINT24 ||
					hfinfo->type == FT_UINT32 ||
					hfinfo->type == FT_UINT64 ||
					hfinfo->type == FT_INT8 ||
					hfinfo->type == FT_INT16 ||
					hfinfo->type == FT_INT24 ||
					hfinfo->type == FT_INT32 ||
					hfinfo->type == FT_INT64) {


					switch(hfinfo->display) {
						case BASE_NONE:
							base_name = "BASE_NONE";
							break;
						case BASE_DEC:
							base_name = "BASE_DEC";
							break;
						case BASE_HEX:
							base_name = "BASE_HEX";
							break;
						case BASE_OCT:
							base_name = "BASE_OCT";
							break;
						case BASE_DEC_HEX:
							base_name = "BASE_DEC_HEX";
							break;
						case BASE_HEX_DEC:
							base_name = "BASE_HEX_DEC";
							break;
					}
				}
			}

			blurb = hfinfo->blurb;
			if (blurb == NULL)
				blurb = "";
			if (format == 1) {
				printf("F\t%s\t%s\t%s\t%s\t%s\n",
					hfinfo->name, hfinfo->abbrev, enum_name,
					parent_hfinfo->abbrev, blurb);
			}
			else if (format == 2) {
				printf("F\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					hfinfo->name, hfinfo->abbrev, enum_name,
					parent_hfinfo->abbrev, blurb,
					base_name, blurb);
			}
			else if (format == 3) {
				printf("F\t%s\t%s\t%s\t%s\t%s\t%s\t%u\n",
					hfinfo->name, hfinfo->abbrev, enum_name,
					parent_hfinfo->abbrev, blurb,
					base_name, hfinfo->bitmask);
			}
			else {
				g_assert_not_reached();
			}
		}
	}
}

static const char*
hfinfo_numeric_format(header_field_info *hfinfo)
{
	const char *format = NULL;

	/* Pick the proper format string */
	if (hfinfo->type == FT_FRAMENUM) {
		/*
		 * Frame numbers are always displayed in decimal.
		 */
		format = "%s == %u";
	} else {
		/* Pick the proper format string */
		switch(hfinfo->display) {
			case BASE_DEC:
			case BASE_DEC_HEX:
			case BASE_OCT: /* I'm lazy */
				switch(hfinfo->type) {
					case FT_UINT8:
					case FT_UINT16:
					case FT_UINT24:
					case FT_UINT32:
						format = "%s == %u";
						break;
					case FT_UINT64:
						format = "%s == %" PRIu64;
						break;
					case FT_INT8:
					case FT_INT16:
					case FT_INT24:
					case FT_INT32:
						format = "%s == %d";
						break;
					case FT_INT64:
						format = "%s == %" PRId64;
						break;
					default:
						DISSECTOR_ASSERT_NOT_REACHED();
						;
				}
				break;
			case BASE_HEX:
			case BASE_HEX_DEC:
				switch(hfinfo->type) {
					case FT_UINT8:
						format = "%s == 0x%02x";
						break;
					case FT_UINT16:
						format = "%s == 0x%04x";
						break;
					case FT_UINT24:
						format = "%s == 0x%06x";
						break;
					case FT_UINT32:
						format = "%s == 0x%08x";
						break;
					case FT_UINT64:
						format = "%s == 0x%016" PRIx64;
						break;
					default:
						DISSECTOR_ASSERT_NOT_REACHED();
						;
				}
				break;
			default:
				DISSECTOR_ASSERT_NOT_REACHED();
				;
		}
	}
	return format;
}

/*
 * Returns TRUE if we can do a "match selected" on the field, FALSE
 * otherwise.
 */
gboolean
proto_can_match_selected(field_info *finfo, epan_dissect_t *edt)
{
	header_field_info	*hfinfo;
	gint			length;

	hfinfo = finfo->hfinfo;
	DISSECTOR_ASSERT(hfinfo);

	switch(hfinfo->type) {

		case FT_BOOLEAN:
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
		case FT_FRAMENUM:
		case FT_UINT64:
		case FT_INT64:
		case FT_IPv4:
		case FT_IPXNET:
		case FT_IPv6:
		case FT_FLOAT:
		case FT_DOUBLE:
		case FT_ABSOLUTE_TIME:
		case FT_RELATIVE_TIME:
		case FT_STRING:
		case FT_STRINGZ:
		case FT_UINT_STRING:
		case FT_ETHER:
		case FT_BYTES:
		case FT_UINT_BYTES:
		case FT_PROTOCOL:
		case FT_GUID:
		case FT_OID:
			/*
			 * These all have values, so we can match.
			 */
			return TRUE;
		case FT_NONE:
			/*
			 * Doesn't have a value, but may still want to test
			 * for its presence in a trace
			 */
			return TRUE;
		default:
			/*
			 * This doesn't have a value, so we'd match
			 * on the raw bytes at this address.
			 *
			 * Should we be allowed to access to the raw bytes?
			 * If "edt" is NULL, the answer is "no".
			 */
			if (edt == NULL)
				return FALSE;

			/*
			 * Is this field part of the raw frame tvbuff?
			 * If not, we can't use "frame[N:M]" to match
			 * it.
			 *
			 * XXX - should this be frame-relative, or
			 * protocol-relative?
			 *
			 * XXX - does this fallback for non-registered
			 * fields even make sense?
			 */
			if (finfo->ds_tvb != edt->tvb)
				return FALSE;

			/*
			 * If the length is 0, there's nothing to match, so
			 * we can't match.  (Also check for negative values,
			 * just in case, as we'll cast it to an unsigned
			 * value later.)
			 */
			length = finfo->length;
			if (length <= 0)
				return FALSE;

			/*
			 * Don't go past the end of that tvbuff.
			 */
			if ((guint)length > tvb_length(finfo->ds_tvb))
				length = tvb_length(finfo->ds_tvb);
			if (length <= 0)
				return FALSE;
			return TRUE;
	}
}

/* This function returns a string allocated with packet lifetime scope.
 * You do not need to [g_]free() this string since it will be automatically
 * freed once the next packet is dissected.
 */
char*
proto_construct_dfilter_string(field_info *finfo, epan_dissect_t *edt)
{
	header_field_info	*hfinfo;
	int			abbrev_len;
	char			*buf, *ptr;
	int			buf_len;
	const char		*format;
	int			dfilter_len, i;
	gint			start, length, length_remaining;
	guint8			c;

	hfinfo = finfo->hfinfo;
	DISSECTOR_ASSERT(hfinfo);
	abbrev_len = strlen(hfinfo->abbrev);

	/*
	 * XXX - we can't use the "val_to_string_repr" and "string_repr_len"
	 * functions for FT_UINT and FT_INT types, as we choose the base in
	 * the string expression based on the display base of the field.
	 *
	 * Note that the base does matter, as this is also used for
	 * the protocolinfo tap.
	 *
	 * It might be nice to use them in "proto_item_fill_label()"
	 * as well, although, there, you'd have to deal with the base
	 * *and* with resolved values for addresses.
	 *
	 * Perhaps we need two different val_to_string routines, one
	 * to generate items for display filters and one to generate
	 * strings for display, and pass to both of them the
	 * "display" and "strings" values in the header_field_info
	 * structure for the field, so they can get the base and,
	 * if the field is Boolean or an enumerated integer type,
	 * the tables used to generate human-readable values.
	 */
	switch(hfinfo->type) {

		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
		case FT_FRAMENUM:
			/*
			 * 4 bytes for " == ".
			 * 11 bytes for:
			 *
			 *	a sign + up to 10 digits of 32-bit integer,
			 *	in decimal;
			 *
			 *	"0x" + 8 digits of 32-bit integer, in hex;
			 *
			 *	11 digits of 32-bit integer, in octal.
			 *	(No, we don't do octal, but this way,
			 *	we know that if we do, this will still
			 *	work.)
			 *
			 * 1 byte for the trailing '\0'.
			 */
			dfilter_len = abbrev_len + 4 + 11 + 1;
			buf = ep_alloc0(dfilter_len);
			format = hfinfo_numeric_format(hfinfo);
			g_snprintf(buf, dfilter_len, format, hfinfo->abbrev, fvalue_get_integer(&finfo->value));
			break;

		case FT_INT64:
		case FT_UINT64:
			/*
			 * 4 bytes for " == ".
			 * 22 bytes for:
			 *
			 *	a sign + up to 20 digits of 32-bit integer,
			 *	in decimal;
			 *
			 *	"0x" + 16 digits of 32-bit integer, in hex;
			 *
			 *	22 digits of 32-bit integer, in octal.
			 *	(No, we don't do octal, but this way,
			 *	we know that if we do, this will still
			 *	work.)
			 *
			 * 1 byte for the trailing '\0'.
			 */
			dfilter_len = abbrev_len + 4 + 22 + 1;
			buf = ep_alloc0(dfilter_len);
			format = hfinfo_numeric_format(hfinfo);
			g_snprintf(buf, dfilter_len, format, hfinfo->abbrev, fvalue_get_integer64(&finfo->value));
			break;

		/* These use the fvalue's "to_string_repr" method. */
		case FT_IPXNET:
		case FT_BOOLEAN:
		case FT_STRING:
		case FT_ETHER:
		case FT_BYTES:
		case FT_UINT_BYTES:
		case FT_UINT_STRING:
		case FT_FLOAT:
		case FT_DOUBLE:
		case FT_ABSOLUTE_TIME:
		case FT_RELATIVE_TIME:
		case FT_IPv4:
		case FT_IPv6:
		case FT_GUID:
		case FT_OID:
			/* Figure out the string length needed.
			 * 	The ft_repr length.
			 * 	4 bytes for " == ".
			 * 	1 byte for trailing NUL.
			 */
			dfilter_len = fvalue_string_repr_len(&finfo->value,
					FTREPR_DFILTER);
			dfilter_len += abbrev_len + 4 + 1;
			buf = ep_alloc0(dfilter_len);

			/* Create the string */
			g_snprintf(buf, dfilter_len, "%s == ", hfinfo->abbrev);
			fvalue_to_string_repr(&finfo->value,
					FTREPR_DFILTER,
					&buf[abbrev_len + 4]);
			break;

		case FT_PROTOCOL:
			buf = ep_strdup(finfo->hfinfo->abbrev);
			break;

		default:
			/*
			 * This doesn't have a value, so we'd match
			 * on the raw bytes at this address.
			 *
			 * Should we be allowed to access to the raw bytes?
			 * If "edt" is NULL, the answer is "no".
			 */
			if (edt == NULL)
				return NULL;

			/*
			 * Is this field part of the raw frame tvbuff?
			 * If not, we can't use "frame[N:M]" to match
			 * it.
			 *
			 * XXX - should this be frame-relative, or
			 * protocol-relative?
			 *
			 * XXX - does this fallback for non-registered
			 * fields even make sense?
			 */
			if (finfo->ds_tvb != edt->tvb)
				return NULL;	/* you lose */

			/*
			 * If the length is 0, just match the name of the field
			 * (Also check for negative values,
			 * just in case, as we'll cast it to an unsigned
			 * value later.)
			 */
			length = finfo->length;
			if (length == 0)
			{
				buf = ep_strdup(finfo->hfinfo->abbrev);
				break;
			}
			if (length < 0)
				return NULL;

			/*
			 * Don't go past the end of that tvbuff.
			 */
			length_remaining = tvb_length_remaining(finfo->ds_tvb, finfo->start);
			if (length > length_remaining)
				length = length_remaining;
			if (length <= 0)
				return NULL;

			start = finfo->start;
			buf_len = 32 + length * 3;
			buf = ep_alloc0(buf_len);
			ptr = buf;

			ptr += g_snprintf(ptr, buf_len-(ptr-buf), "frame[%d:%d] == ", finfo->start, length);
			for (i=0;i<length; i++) {
				c = tvb_get_guint8(finfo->ds_tvb, start);
				start++;
				if (i == 0 ) {
					ptr += g_snprintf(ptr, buf_len-(ptr-buf), "%02x", c);
				}
				else {
					ptr += g_snprintf(ptr, buf_len-(ptr-buf), ":%02x", c);
				}
			}
			break;
	}

	return buf;
}
