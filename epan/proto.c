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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
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
#include "oids.h"
#include "plugins.h"
#include "proto.h"
#include "epan_dissect.h"
#include "slab.h"
#include "tvbuff.h"
#include "emem.h"
#include "charsets.h"
#include "asm_utils.h"
#include "column-utils.h"
#include "to_str.h"

#include "wspython/wspy_register.h"

#define SUBTREE_ONCE_ALLOCATION_NUMBER 8
#define SUBTREE_MAX_LEVELS 256
/* Throw an exception if we exceed this many tree items. */
/* XXX - This should probably be a preference */
#define MAX_TREE_ITEMS (1 * 1000 * 1000)


typedef struct __subtree_lvl {
	gint        cursor_offset;
	proto_item *it;
	proto_tree *tree;
} subtree_lvl;

struct ptvcursor {
	subtree_lvl *pushed_tree;
	guint8	     pushed_tree_index;
	guint8	     pushed_tree_max;
	proto_tree  *tree;
	tvbuff_t    *tvb;
	gint	     offset;
};

/* Candidates for assembler */
static int
wrs_count_bitshift(const guint32 bitmask)
{
	int bitshift = 0;

	while ((bitmask & (1 << bitshift)) == 0)
		bitshift++;
	return bitshift;
}

#define cVALS(x) (const value_string*)(x)

/** See inlined comments.
 @param tree the tree to append this item to
 @param hfindex field index
 @param hfinfo header_field
 @return the header field matching 'hfinfo' */
#define TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo) \
	/* If this item is not referenced we dont have to do much work	\
	   at all but we should still return a node so that		\
	   field items below this node ( think proto_item_add_subtree() )\
	   will still have somewhere to attach to			\
	   or else filtering will not work (they would be ignored since tree\
	   would be NULL).						\
	   DONT try to fake a node where PTREE_FINFO(tree) is NULL	\
	   since dissectors that want to do proto_item_set_len() or	\
	   other operations that dereference this would crash.		\
	   We fake FT_PROTOCOL unless some clients have requested us	\
	   not to do so. \
	*/								\
	if (!tree)							\
		return NULL;						\
	PTREE_DATA(tree)->count++;					\
	if (PTREE_DATA(tree)->count > MAX_TREE_ITEMS) {			\
		if (getenv("WIRESHARK_ABORT_ON_DISSECTOR_BUG") != NULL) \
			abort();					\
		/* Let the exception handler add items to the tree */	\
		PTREE_DATA(tree)->count = 0;				\
		THROW_MESSAGE(DissectorError,				\
			ep_strdup_printf("More than %d items in the tree -- possible infinite loop", MAX_TREE_ITEMS)); \
	}								\
	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);			\
	if (!(PTREE_DATA(tree)->visible)) {				\
		if (PTREE_FINFO(tree)) {				\
			if ((hfinfo->ref_type != HF_REF_TYPE_DIRECT)	\
			    && (hfinfo->type != FT_PROTOCOL ||		\
				PTREE_DATA(tree)->fake_protocols)) {	\
				/* just return tree back to the caller */\
				return tree;				\
			}						\
		}							\
	}

/** See inlined comments.
 @param tree the tree to append this item to
 @param pi the created protocol item we're about to return */
#if 1
#define TRY_TO_FAKE_THIS_REPR(tree, pi) \
	DISSECTOR_ASSERT(tree); \
	if (!(PTREE_DATA(tree)->visible)) { \
		/* If the tree (GUI) isn't visible it's pointless for us to generate the protocol \
		 * items string representation */ \
		return pi; \
	}
#else
#define TRY_TO_FAKE_THIS_REPR(tree, pi)
#endif

static gboolean
proto_tree_free_node(proto_node *node, gpointer data);

static void fill_label_boolean(field_info *fi, gchar *label_str);
static void fill_label_uint(field_info *fi, gchar *label_str);
static void fill_label_uint64(field_info *fi, gchar *label_str);
static void fill_label_bitfield(field_info *fi, gchar *label_str);
static void fill_label_int(field_info *fi, gchar *label_str);
static void fill_label_int64(field_info *fi, gchar *label_str);

static const char* hfinfo_uint_vals_format(const header_field_info *hfinfo);
static const char* hfinfo_uint_format(const header_field_info *hfinfo);
static const char* hfinfo_uint_value_format(const header_field_info *hfinfo);
static const char* hfinfo_uint64_format(const header_field_info *hfinfo);
static const char* hfinfo_int_vals_format(const header_field_info *hfinfo);
static const char* hfinfo_int_format(const header_field_info *hfinfo);
static const char* hfinfo_int_value_format(const header_field_info *hfinfo);
static const char* hfinfo_int64_format(const header_field_info *hfinfo);
static const char* hfinfo_numeric_value_format(const header_field_info *hfinfo);

static proto_item *
proto_tree_add_node(proto_tree *tree, field_info *fi);

static header_field_info *
get_hfi_and_length(int hfindex, tvbuff_t *tvb, const gint start, gint *length,
		   gint *item_length);

static field_info *
new_field_info(proto_tree *tree, header_field_info *hfinfo, tvbuff_t *tvb,
	       const gint start, const gint item_length);

static field_info *
alloc_field_info(proto_tree *tree, int hfindex, tvbuff_t *tvb,
		 const gint start, gint *length);

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
proto_tree_set_string(field_info *fi, const char* value);
static void
proto_tree_set_string_tvb(field_info *fi, tvbuff_t *tvb, gint start, gint length, gint encoding);
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
proto_tree_set_ipv6_tvb(field_info *fi, tvbuff_t *tvb, gint start, gint length);
static void
proto_tree_set_guid(field_info *fi, const e_guid_t *value_ptr);
static void
proto_tree_set_guid_tvb(field_info *fi, tvbuff_t *tvb, gint start, const guint encoding);
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
proto_tree_set_uint64_tvb(field_info *fi, tvbuff_t *tvb, gint start, guint length, const guint encoding);
static void
proto_tree_set_eui64(field_info *fi, const guint64 value);
static void
proto_tree_set_eui64_tvb(field_info *fi, tvbuff_t *tvb, gint start, const guint encoding);
static gboolean
proto_item_add_bitmask_tree(proto_item *item, tvbuff_t *tvb, const int offset,
			    const int len, const gint ett, const gint **fields,
			    const guint encoding, const int flags,
			    gboolean first);

static int proto_register_field_init(header_field_info *hfinfo, const int parent);

/* special-case header field used within proto.c */
int hf_text_only = -1;

/* Structure for information about a protocol */
struct _protocol {
	const char *name;         /* long description */
	const char *short_name;   /* short description */
	const char *filter_name;  /* name of this protocol in filters */
	int         proto_id;     /* field ID for this protocol */
	GList      *fields;       /* fields for this protocol */
	GList      *last_field;   /* pointer to end of list of fields */
	gboolean    is_enabled;   /* TRUE if protocol is enabled */
	gboolean    can_toggle;   /* TRUE if is_enabled can be changed */
	gboolean    is_private;   /* TRUE is protocol is private */
};

/* List of all protocols */
static GList *protocols = NULL;

#define INITIAL_NUM_PROTOCOL_HFINFO	1500

/* Contains information about a field when a dissector calls
 * proto_tree_add_item.  */
static struct ws_memory_slab field_info_slab =
	WS_MEMORY_SLAB_INIT(field_info, 128);

static field_info *field_info_tmp = NULL;
#define FIELD_INFO_NEW(fi)					\
	fi = sl_alloc(&field_info_slab)
#define FIELD_INFO_FREE(fi)					\
	sl_free(&field_info_slab, fi)

/* Contains the space for proto_nodes. */
static struct ws_memory_slab proto_node_slab =
	WS_MEMORY_SLAB_INIT(proto_node, 128);

#define PROTO_NODE_NEW(node)				\
	node = sl_alloc(&proto_node_slab); \
	node->first_child = NULL;			\
	node->last_child = NULL;			\
	node->next = NULL;

#define PROTO_NODE_FREE(node)				\
	sl_free(&proto_node_slab, node)

/* String space for protocol and field items for the GUI */
static struct ws_memory_slab item_label_slab =
	WS_MEMORY_SLAB_INIT(item_label_t, 128);

#define ITEM_LABEL_NEW(il)				\
	il = sl_alloc(&item_label_slab);
#define ITEM_LABEL_FREE(il)				\
	sl_free(&item_label_slab, il);

#define PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo) \
	DISSECTOR_ASSERT((guint)hfindex < gpa_hfinfo.len); \
	hfinfo = gpa_hfinfo.hfi[hfindex];

/* List which stores protocols and fields that have been registered */
typedef struct _gpa_hfinfo_t {
	guint32             len;
	guint32             allocated_len;
	header_field_info **hfi;
} gpa_hfinfo_t;
gpa_hfinfo_t gpa_hfinfo;

/* Balanced tree of abbreviations and IDs */
static GTree *gpa_name_tree = NULL;
static header_field_info *same_name_hfinfo;

static void save_same_name_hfinfo(gpointer data)
{
	same_name_hfinfo = (header_field_info*)data;
}

/* Points to the first element of an array of Booleans, indexed by
   a subtree item type; that array element is TRUE if subtrees of
   an item of that type are to be expanded. */
gboolean	*tree_is_expanded;

/* Number of elements in that array. */
int		num_tree_types;

/* Name hashtables for fast detection of duplicate names */
static GHashTable* proto_names        = NULL;
static GHashTable* proto_short_names  = NULL;
static GHashTable* proto_filter_names = NULL;

static gint
proto_compare_name(gconstpointer p1_arg, gconstpointer p2_arg)
{
	const protocol_t *p1 = p1_arg;
	const protocol_t *p2 = p2_arg;

	return g_ascii_strcasecmp(p1->short_name, p2->short_name);
}


/* initialize data structures and register protocols and fields */
void
proto_init(void (register_all_protocols_func)(register_cb cb, gpointer client_data),
	   void (register_all_handoffs_func)(register_cb cb, gpointer client_data),
	   register_cb cb,
	   gpointer client_data)
{
	static hf_register_info hf[] = {
		{ &hf_text_only,
		{ "Text item",	"text", FT_NONE, BASE_NONE, NULL, 0x0,
		  NULL, HFILL }},
	};

	proto_cleanup();

	proto_names        = g_hash_table_new_full(g_int_hash, g_int_equal, g_free, NULL);
	proto_short_names  = g_hash_table_new(wrs_str_hash, g_str_equal);
	proto_filter_names = g_hash_table_new(wrs_str_hash, g_str_equal);

	gpa_hfinfo.len           = 0;
	gpa_hfinfo.allocated_len = 0;
	gpa_hfinfo.hfi           = NULL;
	gpa_name_tree            = g_tree_new_full(wrs_strcmp_with_data, NULL, NULL, save_same_name_hfinfo);

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
	register_all_protocols_func(cb, client_data);
#ifdef HAVE_PYTHON
	/* Now scan for python protocols */
	if (cb)
		(*cb)(RA_PYTHON_REGISTER, NULL, client_data);
	register_all_py_protocols_func();
#endif

#ifdef HAVE_PLUGINS
	/* Now scan for plugins and load all the ones we find, calling
	   their register routines to do the stuff described above. */
	if (cb)
		(*cb)(RA_PLUGIN_REGISTER, NULL, client_data);
	init_plugins();
	register_all_plugin_registrations();
#endif

	/* Now call the "handoff registration" routines of all built-in
	   dissectors; those routines register the dissector in other
	   dissectors' handoff tables, and fetch any dissector handles
	   they need. */
	register_all_handoffs_func(cb, client_data);

#ifdef HAVE_PYTHON
	/* Now do the same with python dissectors */
	if (cb)
		(*cb)(RA_PYTHON_HANDOFF, NULL, client_data);
	register_all_py_handoffs_func();
#endif

#ifdef HAVE_PLUGINS
	/* Now do the same with plugins. */
	if (cb)
		(*cb)(RA_PLUGIN_HANDOFF, NULL, client_data);
	register_all_plugin_handoffs();
#endif

	/* sort the protocols by protocol name */
	protocols = g_list_sort(protocols, proto_compare_name);

	/* We've assigned all the subtree type values; allocate the array
	   for them, and zero it out. */
	tree_is_expanded = g_new0(gboolean, num_tree_types);
}

void
proto_cleanup(void)
{
	/* Free the abbrev/ID GTree */
	if (gpa_name_tree) {
		g_tree_destroy(gpa_name_tree);
		gpa_name_tree = NULL;
	}

	while (protocols) {
		protocol_t        *protocol = protocols->data;
		header_field_info *hfinfo;
		PROTO_REGISTRAR_GET_NTH(protocol->proto_id, hfinfo);
		DISSECTOR_ASSERT(protocol->proto_id == hfinfo->id);

		g_slice_free(header_field_info, hfinfo);
		g_list_free(protocol->fields);
		protocols = g_list_remove(protocols, protocol);
		g_free(protocol);
	}

	if (proto_names) {
		g_hash_table_destroy(proto_names);
		proto_names = NULL;
	}

	if (proto_short_names) {
		g_hash_table_destroy(proto_short_names);
		proto_short_names = NULL;
	}

	if (proto_filter_names) {
		g_hash_table_destroy(proto_filter_names);
		proto_filter_names = NULL;
	}

	if (gpa_hfinfo.allocated_len) {
		gpa_hfinfo.len           = 0;
		gpa_hfinfo.allocated_len = 0;
		g_free(gpa_hfinfo.hfi);
		gpa_hfinfo.hfi           = NULL;
	}
	g_free(tree_is_expanded);
	tree_is_expanded = NULL;
}

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
		child   = current->next;
		if (proto_tree_traverse_pre_order((proto_tree *)current, func, data))
			return TRUE;
	}

	return FALSE;
}

gboolean
proto_tree_traverse_post_order(proto_tree *tree, proto_tree_traverse_func func,
			       gpointer data)
{
	proto_node *pnode = tree;
	proto_node *child;
	proto_node *current;

	child = pnode->first_child;
	while (child != NULL) {
		/*
		 * The routine we call might modify the child, e.g. by
		 * freeing it, so we get the child's successor before
		 * calling that routine.
		 */
		current = child;
		child   = current->next;
		if (proto_tree_traverse_post_order((proto_tree *)current, func, data))
			return TRUE;
	}
	if (func(pnode, data))
		return TRUE;

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
		node    = current->next;
		func((proto_tree *)current, data);
	}
}

/* frees the resources that the dissection a proto_tree uses */
void
proto_tree_free(proto_tree *tree)
{
	proto_tree_traverse_post_order(tree, proto_tree_free_node, NULL);
}

static void
free_GPtrArray_value(gpointer key, gpointer value, gpointer user_data _U_)
{
	GPtrArray         *ptrs = value;
	gint               hfid = (gint)(long)key;
	header_field_info *hfinfo;

	PROTO_REGISTRAR_GET_NTH(hfid, hfinfo);
	if (hfinfo->ref_type != HF_REF_TYPE_NONE) {
		/* when a field is referenced by a filter this also
		   affects the refcount for the parent protocol so we need
		   to adjust the refcount for the parent as well
		*/
		if (hfinfo->parent != -1) {
			header_field_info *parent_hfinfo;
			PROTO_REGISTRAR_GET_NTH(hfinfo->parent, parent_hfinfo);
			parent_hfinfo->ref_type = HF_REF_TYPE_NONE;
		}
		hfinfo->ref_type = HF_REF_TYPE_NONE;
	}

	g_ptr_array_free(ptrs, TRUE);
}

static void
free_node_tree_data(tree_data_t *tree_data)
{
	if (tree_data->interesting_hfids) {
		/* Free all the GPtrArray's in the interesting_hfids hash. */
		g_hash_table_foreach(tree_data->interesting_hfids,
			free_GPtrArray_value, NULL);

		/* And then destroy the hash. */
		g_hash_table_destroy(tree_data->interesting_hfids);
	}

	/* And finally the tree_data_t itself. */
	g_free(tree_data);
}

#define FREE_NODE_FIELD_INFO(finfo)	\
	if (finfo->rep) {			\
		ITEM_LABEL_FREE(finfo->rep);	\
	}				\
	FVALUE_CLEANUP(&finfo->value);	\
	FIELD_INFO_FREE(finfo);

static gboolean
proto_tree_free_node(proto_node *node, gpointer data _U_)
{
	field_info *finfo  = PNODE_FINFO(node);
#if 0
	proto_node *parent = node->parent;
#endif

	if (finfo == NULL) {
		/* This is the root node. Destroy the per-tree data.
		 * There is no field_info to destroy. */
		if (PTREE_DATA(node))
			free_node_tree_data(PTREE_DATA(node));
	}
	else {
		/* This is a child node. Don't free the per-tree data, but
		 * do free the field_info data. */
		FREE_NODE_FIELD_INFO(finfo);
	}

#if 0
	/* NOTE: This code is required when this function is used to free individual
	 * nodes only. Current use is for the destruction of complete trees, so the
	 * inconsistancies have no ill effect.
	 */
	/* Remove node from parent */
	if (parent) {
		proto_item *prev_item = NULL;
		if (parent->first_child == node) {
			parent->first_child = node->next;
		} else {
			/* find previous and change its next */
			for (prev_item = parent->first_child; prev_item; prev_item = prev_item->next) {
				if (prev_item->next == node) {
					break;
				}
			}
			DISSECTOR_ASSERT(prev_item);
			prev_item->next = node->next;
		}
		/* fix last_child if required */
		if (parent->last_child == node) {
			parent->last_child = prev_item;
		}
	}
	DISSECTOR_ASSERT(node->first_child == NULL && node->last_child == NULL);
#endif
	/* Free the proto_node. */
	PROTO_NODE_FREE(node);

	return FALSE; /* FALSE = do not end traversal of protocol tree */
}

/* Is the parsing being done for a visible proto_tree or an invisible one?
 * By setting this correctly, the proto_tree creation is sped up by not
 * having to call g_vsnprintf and copy strings around.
 */
gboolean
proto_tree_set_visible(proto_tree *tree, gboolean visible)
{
	gboolean old_visible = PTREE_DATA(tree)->visible;

	PTREE_DATA(tree)->visible = visible;

	return old_visible;
}

void
proto_tree_set_fake_protocols(proto_tree *tree, gboolean fake_protocols)
{
	PTREE_DATA(tree)->fake_protocols = fake_protocols;
}

/* Assume dissector set only its protocol fields.
   This function is called by dissectors and allows the speeding up of filtering
   in wireshark; if this function returns FALSE it is safe to reset tree to NULL
   and thus skip calling most of the expensive proto_tree_add_...()
   functions.
   If the tree is visible we implicitly assume the field is referenced.
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
	if (hfinfo->ref_type != HF_REF_TYPE_NONE)
		return TRUE;

	if (hfinfo->type == FT_PROTOCOL && !PTREE_DATA(tree)->fake_protocols)
		return TRUE;

	return FALSE;
}


/* Finds a record in the hf_info_records array by id. */
header_field_info *
proto_registrar_get_nth(guint hfindex)
{
	register header_field_info *hfinfo;

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);
	return hfinfo;
}


/*	Prefix initialization
 *	  this allows for a dissector to register a display filter name prefix
 *	  so that it can delay the initialization of the hf array as long as
 *	  possible.
 */

/* compute a hash for the part before the dot of a display filter */
static guint
prefix_hash (gconstpointer key) {
	/* end the string at the dot and compute its hash */
	gchar* copy = ep_strdup(key);
	gchar* c    = copy;

	for (; *c; c++) {
		if (*c == '.') {
			*c = 0;
			break;
		}
	}

	return g_str_hash(copy);
}

/* are both strings equal up to the end or the dot? */
static gboolean
prefix_equal (gconstpointer ap, gconstpointer bp) {
	const gchar* a = ap;
	const gchar* b = bp;

	do {
		gchar ac = *a++;
		gchar bc = *b++;

		if ( (ac == '.' || ac == '\0') &&   (bc == '.' || bc == '\0') ) return TRUE;

		if ( (ac == '.' || ac == '\0') && ! (bc == '.' || bc == '\0') ) return FALSE;
		if ( (bc == '.' || bc == '\0') && ! (ac == '.' || ac == '\0') ) return FALSE;

		if (ac != bc) return FALSE;
	} while (1);

	return FALSE;
}


/* indexed by prefix, contains initializers */
static GHashTable* prefixes = NULL;


/* Register a new prefix for "delayed" initialization of field arrays */
void
proto_register_prefix(const char *prefix, prefix_initializer_t pi ) {
	if (! prefixes ) {
		prefixes = g_hash_table_new(prefix_hash, prefix_equal);
	}

	g_hash_table_insert(prefixes, (gpointer)prefix, pi);
}

/* helper to call all prefix initializers */
static gboolean
initialize_prefix(gpointer k, gpointer v, gpointer u _U_) {
	((prefix_initializer_t)v)(k);
	return TRUE;
}

/** Initialize every remaining uninitialized prefix. */
void
proto_initialize_all_prefixes(void) {
	g_hash_table_foreach_remove(prefixes, initialize_prefix, NULL);
}

/* Finds a record in the hf_info_records array by name.
 * If it fails to find it in the already registered fields,
 * it tries to find and call an initializer in the prefixes
 * table and if so it looks again.
 */
header_field_info *
proto_registrar_get_byname(const char *field_name)
{
	header_field_info    *hfinfo;
	prefix_initializer_t  pi;

	if (!field_name)
		return NULL;

	hfinfo = g_tree_lookup(gpa_name_tree, field_name);

	if (hfinfo)
		return hfinfo;

	if (!prefixes)
		return NULL;

	if ((pi = g_hash_table_lookup(prefixes, field_name) ) != NULL) {
		pi(field_name);
		g_hash_table_remove(prefixes, field_name);
	} else {
		return NULL;
	}

	return g_tree_lookup(gpa_name_tree, field_name);
}


static void
ptvcursor_new_subtree_levels(ptvcursor_t *ptvc)
{
	subtree_lvl *pushed_tree;

	DISSECTOR_ASSERT(ptvc->pushed_tree_max <= SUBTREE_MAX_LEVELS-SUBTREE_ONCE_ALLOCATION_NUMBER);
	ptvc->pushed_tree_max += SUBTREE_ONCE_ALLOCATION_NUMBER;

	pushed_tree = ep_alloc(sizeof(subtree_lvl) * ptvc->pushed_tree_max);
	DISSECTOR_ASSERT(pushed_tree != NULL);
	if (ptvc->pushed_tree)
		memcpy(pushed_tree, ptvc->pushed_tree, ptvc->pushed_tree_max - SUBTREE_ONCE_ALLOCATION_NUMBER);
	ptvc->pushed_tree = pushed_tree;
}

static void
ptvcursor_free_subtree_levels(ptvcursor_t *ptvc)
{
	ptvc->pushed_tree       = NULL;
	ptvc->pushed_tree_max   = 0;
	DISSECTOR_ASSERT(ptvc->pushed_tree_index == 0);
	ptvc->pushed_tree_index = 0;
}

/* Allocates an initializes a ptvcursor_t with 3 variables:
 *	proto_tree, tvbuff, and offset. */
ptvcursor_t *
ptvcursor_new(proto_tree *tree, tvbuff_t *tvb, gint offset)
{
	ptvcursor_t *ptvc;

	ptvc                    = ep_alloc(sizeof(ptvcursor_t));
	ptvc->tree              = tree;
	ptvc->tvb               = tvb;
	ptvc->offset            = offset;
	ptvc->pushed_tree       = NULL;
	ptvc->pushed_tree_max   = 0;
	ptvc->pushed_tree_index = 0;
	return ptvc;
}


/* Frees memory for ptvcursor_t, but nothing deeper than that. */
void
ptvcursor_free(ptvcursor_t *ptvc)
{
	ptvcursor_free_subtree_levels(ptvc);
	/*g_free(ptvc);*/
}

/* Returns tvbuff. */
tvbuff_t *
ptvcursor_tvbuff(ptvcursor_t *ptvc)
{
	return ptvc->tvb;
}

/* Returns current offset. */
gint
ptvcursor_current_offset(ptvcursor_t *ptvc)
{
	return ptvc->offset;
}

proto_tree *
ptvcursor_tree(ptvcursor_t *ptvc)
{
	if (!ptvc)
		return NULL;

	return ptvc->tree;
}

void
ptvcursor_set_tree(ptvcursor_t *ptvc, proto_tree *tree)
{
	ptvc->tree = tree;
}

/* creates a subtree, sets it as the working tree and pushes the old working tree */
proto_tree *
ptvcursor_push_subtree(ptvcursor_t *ptvc, proto_item *it, gint ett_subtree)
{
	subtree_lvl *subtree;
	if (ptvc->pushed_tree_index >= ptvc->pushed_tree_max)
		ptvcursor_new_subtree_levels(ptvc);

	subtree = ptvc->pushed_tree + ptvc->pushed_tree_index;
	subtree->tree = ptvc->tree;
	subtree->it= NULL;
	ptvc->pushed_tree_index++;
	return ptvcursor_set_subtree(ptvc, it, ett_subtree);
}

/* pops a subtree */
void
ptvcursor_pop_subtree(ptvcursor_t *ptvc)
{
	subtree_lvl *subtree;

	if (ptvc->pushed_tree_index <= 0)
		return;

	ptvc->pushed_tree_index--;
	subtree = ptvc->pushed_tree + ptvc->pushed_tree_index;
	if (subtree->it != NULL)
		proto_item_set_len(subtree->it, ptvcursor_current_offset(ptvc) - subtree->cursor_offset);

	ptvc->tree = subtree->tree;
}

/* saves the current tvb offset and the item in the current subtree level */
static void
ptvcursor_subtree_set_item(ptvcursor_t *ptvc, proto_item *it)
{
	subtree_lvl *subtree;

	DISSECTOR_ASSERT(ptvc->pushed_tree_index > 0);

	subtree                = ptvc->pushed_tree + ptvc->pushed_tree_index - 1;
	subtree->it            = it;
	subtree->cursor_offset = ptvcursor_current_offset(ptvc);
}

/* Creates a subtree and adds it to the cursor as the working tree but does not
 * save the old working tree */
proto_tree *
ptvcursor_set_subtree(ptvcursor_t *ptvc, proto_item *it, gint ett_subtree)
{
	ptvc->tree = proto_item_add_subtree(it, ett_subtree);
	return ptvc->tree;
}

static proto_tree *
ptvcursor_add_subtree_item(ptvcursor_t *ptvc, proto_item *it, gint ett_subtree, gint length)
{
	ptvcursor_push_subtree(ptvc, it, ett_subtree);
	if (length == SUBTREE_UNDEFINED_LENGTH)
		ptvcursor_subtree_set_item(ptvc, it);
	return ptvcursor_tree(ptvc);
}

/* Add an item to the tree and create a subtree
 * If the length is unknown, length may be defined as SUBTREE_UNDEFINED_LENGTH.
 * In this case, when the subtree will be closed, the parent item length will
 * be equal to the advancement of the cursor since the creation of the subtree.
 */
proto_tree *
ptvcursor_add_with_subtree(ptvcursor_t *ptvc, int hfindex, gint length,
			   const guint encoding, gint ett_subtree)
{
	proto_item *it;

	it = ptvcursor_add_no_advance(ptvc, hfindex, length, encoding);
	return ptvcursor_add_subtree_item(ptvc, it, ett_subtree, length);
}

static proto_item *
proto_tree_add_text_node(proto_tree *tree, tvbuff_t *tvb, gint start, gint length);

/* Add a text node to the tree and create a subtree
 * If the length is unknown, length may be defined as SUBTREE_UNDEFINED_LENGTH.
 * In this case, when the subtree will be closed, the item length will be equal
 * to the advancement of the cursor since the creation of the subtree.
 */
proto_tree *
ptvcursor_add_text_with_subtree(ptvcursor_t *ptvc, gint length,
				gint ett_subtree, const char *format, ...)
{
	proto_item        *it;
	va_list            ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(ptvcursor_tree(ptvc), hf_text_only, hfinfo);

	it = proto_tree_add_text_node(ptvcursor_tree(ptvc), ptvcursor_tvbuff(ptvc),
				      ptvcursor_current_offset(ptvc), length);

	if (it == NULL)
		return NULL;

	va_start(ap, format);
	proto_tree_set_representation(it, format, ap);
	va_end(ap);

	return ptvcursor_add_subtree_item(ptvc, it, ett_subtree, length);
}

/* Add a text-only node, leaving it to our caller to fill the text in */
static proto_item *
proto_tree_add_text_node(proto_tree *tree, tvbuff_t *tvb, gint start, gint length)
{
	proto_item *pi;

	pi = proto_tree_add_pi(tree, hf_text_only, tvb, start, &length, NULL);
	if (pi == NULL)
		return NULL;

	return pi;
}

/* Add a text-only node to the proto_tree */
proto_item *
proto_tree_add_text(proto_tree *tree, tvbuff_t *tvb, gint start, gint length,
		    const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hf_text_only, hfinfo);

	pi = proto_tree_add_text_node(tree, tvb, start, length);
	if (pi == NULL)
		return NULL;

	TRY_TO_FAKE_THIS_REPR(tree, pi);

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
	proto_item        *pi;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hf_text_only, hfinfo);

	pi = proto_tree_add_text_node(tree, tvb, start, length);
	if (pi == NULL)
		return NULL;

	TRY_TO_FAKE_THIS_REPR(tree, pi);

	proto_tree_set_representation(pi, format, ap);

	return pi;
}

/* Add a text-only node for debugging purposes. The caller doesn't need
 * to worry about tvbuff, start, or length. Debug message gets sent to
 * STDOUT, too */
proto_item *
proto_tree_add_debug_text(proto_tree *tree, const char *format, ...)
{
	proto_item *pi;
	va_list	    ap;

	pi = proto_tree_add_text_node(tree, NULL, 0, 0);

	if (pi) {
		va_start(ap, format);
		proto_tree_set_representation(pi, format, ap);
		va_end(ap);
	}
	va_start(ap, format);
	vprintf(format, ap);
	va_end(ap);
	printf("\n");

	return pi;
}

/*
 * NOTE: to support code written when proto_tree_add_item() took a
 * gboolean as its last argument, with FALSE meaning "big-endian"
 * and TRUE meaning "little-endian", we treat any non-zero value of
 * "encoding" as meaning "little-endian".
 */
static guint32
get_uint_value(tvbuff_t *tvb, gint offset, gint length, const guint encoding)
{
	guint32 value;

	switch (length) {

	case 1:
		value = tvb_get_guint8(tvb, offset);
		break;

	case 2:
		value = encoding ? tvb_get_letohs(tvb, offset)
				 : tvb_get_ntohs(tvb, offset);
		break;

	case 3:
		value = encoding ? tvb_get_letoh24(tvb, offset)
				 : tvb_get_ntoh24(tvb, offset);
		break;

	case 4:
		value = encoding ? tvb_get_letohl(tvb, offset)
				 : tvb_get_ntohl(tvb, offset);
		break;

	default:
		DISSECTOR_ASSERT_NOT_REACHED();
		value = 0;
		break;
	}
	return value;
}

/*
 * NOTE: to support code written when proto_tree_add_item() took a
 * gboolean as its last argument, with FALSE meaning "big-endian"
 * and TRUE meaning "little-endian", we treat any non-zero value of
 * "encoding" as meaning "little-endian".
 */
static gint32
get_int_value(tvbuff_t *tvb, gint offset, gint length, const guint encoding)
{
	gint32 value;

	switch (length) {

	case 1:
		value = (gint8)tvb_get_guint8(tvb, offset);
		break;

	case 2:
		value = (gint16) (encoding ? tvb_get_letohs(tvb, offset)
					   : tvb_get_ntohs(tvb, offset));
		break;

	case 3:
		value = encoding ? tvb_get_letoh24(tvb, offset)
				 : tvb_get_ntoh24(tvb, offset);
		if (value & 0x00800000) {
			/* Sign bit is set; sign-extend it. */
			value |= 0xFF000000;
		}
		break;

	case 4:
		value = encoding ? tvb_get_letohl(tvb, offset)
				 : tvb_get_ntohl(tvb, offset);
		break;

	default:
		DISSECTOR_ASSERT_NOT_REACHED();
		value = 0;
		break;
	}
	return value;
}

static GPtrArray *
proto_lookup_or_create_interesting_hfids(proto_tree *tree,
					 header_field_info *hfinfo)
{
	GPtrArray *ptrs = NULL;

	DISSECTOR_ASSERT(tree);
	DISSECTOR_ASSERT(hfinfo);

	if (hfinfo->ref_type == HF_REF_TYPE_DIRECT) {
		if (PTREE_DATA(tree)->interesting_hfids == NULL) {
			/* Initialize the hash because we now know that it is needed */
			PTREE_DATA(tree)->interesting_hfids =
				g_hash_table_new(g_direct_hash, NULL /* g_direct_equal */);
		}

		ptrs = g_hash_table_lookup(PTREE_DATA(tree)->interesting_hfids,
					   GINT_TO_POINTER(hfinfo->id));
		if (!ptrs) {
			/* First element triggers the creation of pointer array */
			ptrs = g_ptr_array_new();
			g_hash_table_insert(PTREE_DATA(tree)->interesting_hfids,
					    GINT_TO_POINTER(hfinfo->id), ptrs);
		}
	}

	return ptrs;
}

/* Add an item to a proto_tree, using the text label registered to that item;
   the item is extracted from the tvbuff handed to it. */
static proto_item *
proto_tree_new_item(field_info *new_fi, proto_tree *tree,
		    tvbuff_t *tvb, gint start, gint length,
		    const guint encoding_arg)
{
	guint	    encoding = encoding_arg;
	proto_item *pi;
	guint32	    value, n;
	float	    floatval;
	double	    doubleval;
	const char *string;
	nstime_t    time_stamp;
	GPtrArray  *ptrs;

	/* there is a possibility here that we might raise an exception
	 * and thus would lose track of the field_info.
	 * store it in a temp so that if we come here again we can reclaim
	 * the field_info without leaking memory.
	 */
	/* XXX this only keeps track of one field_info struct,
	   if we ever go multithreaded for calls to this function
	   we have to change this code to use per thread variable.
	*/
	if (field_info_tmp) {
		/* oops, last one we got must have been lost due
		 * to an exception.
		 * good thing we saved it, now we can reverse the
		 * memory leak and reclaim it.
		 */
		FIELD_INFO_FREE(field_info_tmp);
	}
	/* we might throw an exception, keep track of this one
	 * across the "dangerous" section below.
	*/
	field_info_tmp = new_fi;

	switch (new_fi->hfinfo->type) {
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
			/*
			 * Map all non-zero values to little-endian for
			 * backwards compatibility.
			 */
			if (encoding)
				encoding = ENC_LITTLE_ENDIAN;
			n = get_uint_value(tvb, start, length, encoding);
			proto_tree_set_bytes_tvb(new_fi, tvb, start + length, n);

			/* Instead of calling proto_item_set_len(), since we don't yet
			 * have a proto_item, we set the field_info's length ourselves. */
			new_fi->length = n + length;
			break;

		case FT_BOOLEAN:
			/*
			 * Map all non-zero values to little-endian for
			 * backwards compatibility.
			 */
			if (encoding)
				encoding = ENC_LITTLE_ENDIAN;
			proto_tree_set_boolean(new_fi,
				get_uint_value(tvb, start, length, encoding));
			break;

		/* XXX - make these just FT_UINT? */
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
			/*
			 * Map all non-zero values to little-endian for
			 * backwards compatibility.
			 */
			if (encoding)
				encoding = ENC_LITTLE_ENDIAN;
			proto_tree_set_uint(new_fi,
				get_uint_value(tvb, start, length, encoding));
			break;

		case FT_INT64:
		case FT_UINT64:
			/*
			 * Map all non-zero values to little-endian for
			 * backwards compatibility.
			 */
			if (encoding)
				encoding = ENC_LITTLE_ENDIAN;
			DISSECTOR_ASSERT( length <= 8 && length >= 1);
			proto_tree_set_uint64_tvb(new_fi, tvb, start, length, encoding);
			break;

		/* XXX - make these just FT_INT? */
		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
			/*
			 * Map all non-zero values to little-endian for
			 * backwards compatibility.
			 */
			if (encoding)
				encoding = ENC_LITTLE_ENDIAN;
			proto_tree_set_int(new_fi,
				get_int_value(tvb, start, length, encoding));
			break;

		case FT_IPv4:
			/*
			 * Map all non-zero values to little-endian for
			 * backwards compatibility.
			 */
			if (encoding)
				encoding = ENC_LITTLE_ENDIAN;
			DISSECTOR_ASSERT(length == FT_IPv4_LEN);
			value = tvb_get_ipv4(tvb, start);
			/*
			 * NOTE: to support code written when
			 * proto_tree_add_item() took a gboolean as its
			 * last argument, with FALSE meaning "big-endian"
			 * and TRUE meaning "little-endian", we treat any
			 * non-zero value of "encoding" as meaning
			 * "little-endian".
			 */
			proto_tree_set_ipv4(new_fi, encoding ? GUINT32_SWAP_LE_BE(value) : value);
			break;

		case FT_IPXNET:
			DISSECTOR_ASSERT(length == FT_IPXNET_LEN);
			proto_tree_set_ipxnet(new_fi,
				get_uint_value(tvb, start, 4, FALSE));
			break;

		case FT_IPv6:
			DISSECTOR_ASSERT(length >= 0 && length <= FT_IPv6_LEN);
			proto_tree_set_ipv6_tvb(new_fi, tvb, start, length);
			break;

		case FT_ETHER:
			DISSECTOR_ASSERT(length == FT_ETHER_LEN);
			proto_tree_set_ether_tvb(new_fi, tvb, start);
			break;

		case FT_EUI64:
			/*
			 * Map all non-zero values to little-endian for
			 * backwards compatibility.
			 */
			if (encoding)
				encoding = ENC_LITTLE_ENDIAN;
			DISSECTOR_ASSERT(length == FT_EUI64_LEN);
			proto_tree_set_eui64_tvb(new_fi, tvb, start, encoding);
			break;
		case FT_GUID:
			/*
			 * Map all non-zero values to little-endian for
			 * backwards compatibility.
			 */
			if (encoding)
				encoding = ENC_LITTLE_ENDIAN;
			DISSECTOR_ASSERT(length == FT_GUID_LEN);
			proto_tree_set_guid_tvb(new_fi, tvb, start, encoding);
			break;

		case FT_OID:
			proto_tree_set_oid_tvb(new_fi, tvb, start, length);
			break;

		case FT_FLOAT:
			/*
			 * NOTE: to support code written when
			 * proto_tree_add_item() took a gboolean as its
			 * last argument, with FALSE meaning "big-endian"
			 * and TRUE meaning "little-endian", we treat any
			 * non-zero value of "encoding" as meaning
			 * "little-endian".
			 *
			 * At some point in the future, we might
			 * support non-IEEE-binary floating-point
			 * formats in the encoding as well
			 * (IEEE decimal, System/3x0, VAX).
			 */
			if (encoding)
				encoding = ENC_LITTLE_ENDIAN;
			DISSECTOR_ASSERT(length == 4);
			if (encoding)
				floatval = tvb_get_letohieee_float(tvb, start);
			else
				floatval = tvb_get_ntohieee_float(tvb, start);
			proto_tree_set_float(new_fi, floatval);
			break;

		case FT_DOUBLE:
			/*
			 * NOTE: to support code written when
			 * proto_tree_add_item() took a gboolean as its
			 * last argument, with FALSE meaning "big-endian"
			 * and TRUE meaning "little-endian", we treat any
			 * non-zero value of "encoding" as meaning
			 * "little-endian".
			 *
			 * At some point in the future, we might
			 * support non-IEEE-binary floating-point
			 * formats in the encoding as well
			 * (IEEE decimal, System/3x0, VAX).
			 */
			if (encoding == TRUE)
				encoding = ENC_LITTLE_ENDIAN;
			DISSECTOR_ASSERT(length == 8);
			if (encoding)
				doubleval = tvb_get_letohieee_double(tvb, start);
			else
				doubleval = tvb_get_ntohieee_double(tvb, start);
			proto_tree_set_double(new_fi, doubleval);
			break;

		case FT_STRING:
			proto_tree_set_string_tvb(new_fi, tvb, start, length,
			    encoding);
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
				string = tvb_get_stringz_enc(tvb, start, &length, encoding);
			} else if (length == 0) {
				string = "[Empty]";
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
				 * trailing '\0'?)	Therefore, we
				 * allocate a buffer of length
				 * "length+1", and put in a trailing
				 * '\0', just to be safe.
				 *
				 * (XXX - this would change if
				 * we made string values counted
				 * rather than null-terminated.)
				 */
				string = tvb_get_ephemeral_string_enc(tvb, start, length, encoding);
			}
			new_fi->length = length;
			proto_tree_set_string(new_fi, string);
			break;

		case FT_UINT_STRING:
			/*
			 * NOTE: to support code written when
			 * proto_tree_add_item() took a gboolean as its
			 * last argument, with FALSE meaning "big-endian"
			 * and TRUE meaning "little-endian", we any
			 * non-zero value of "encoding", except for
			 * ENC_EBCDIC|ENC_BIG_ENDIAN and
			 * ENC_EBCDIC|ENC_LITTLE_ENDIAN  as meaning
			 * "little-endian UTF-8".
			 *
			 * At some point in the future, we might
			 * support more character encodings in the
			 * encoding value as well.
			 */
			if (encoding != 0 &&
			    encoding != (ENC_EBCDIC|ENC_BIG_ENDIAN) &&
			    encoding != (ENC_EBCDIC|ENC_LITTLE_ENDIAN))
				encoding = ENC_UTF_8|ENC_LITTLE_ENDIAN;
			n = get_uint_value(tvb, start, length, encoding);
			proto_tree_set_string_tvb(new_fi, tvb, start + length, n,
			    encoding);

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

		case FT_ABSOLUTE_TIME:
			/*
			 * Absolute times can be in any of a number of
			 * formats, and they can be big-endian or
			 * little-endian.
			 *
			 * Historically FT_TIMEs were only timespecs;
			 * the only question was whether they were stored
			 * in big- or little-endian format.
			 *
			 * For backwards compatibility, we interpret an
			 * encoding of 1 as meaning "little-endian timespec",
			 * so that passing TRUE is interpreted as that.
			 */
			if (encoding == TRUE)
				encoding = ENC_TIME_TIMESPEC|ENC_LITTLE_ENDIAN;

			switch (encoding) {

			case ENC_TIME_TIMESPEC|ENC_BIG_ENDIAN:
				/*
				 * 4-byte UNIX epoch, possibly followed by
				 * 4-byte fractional time in nanoseconds,
				 * both big-endian.
				 */
				DISSECTOR_ASSERT(length == 8 || length == 4);
				time_stamp.secs  = tvb_get_ntohl(tvb, start);
				if (length == 8)
					time_stamp.nsecs = tvb_get_ntohl(tvb, start+4);
				else
					time_stamp.nsecs = 0;
				break;

			case ENC_TIME_TIMESPEC|ENC_LITTLE_ENDIAN:
				/*
				 * 4-byte UNIX epoch, possibly followed by
				 * 4-byte fractional time in nanoseconds,
				 * both little-endian.
				 */
				DISSECTOR_ASSERT(length == 8 || length == 4);
				time_stamp.secs  = tvb_get_letohl(tvb, start);
				if (length == 8)
					time_stamp.nsecs = tvb_get_letohl(tvb, start+4);
				else
					time_stamp.nsecs = 0;
				break;

			case ENC_TIME_NTP|ENC_BIG_ENDIAN:
				/*
				 * NTP time stamp, big-endian.
				 */
				DISSECTOR_ASSERT(length == 8 || length == 4);

/* XXX - where should this go? */
#define NTP_BASETIME 2208988800ul
				time_stamp.secs  = tvb_get_ntohl(tvb, start);
				if (time_stamp.secs)
					time_stamp.secs -= NTP_BASETIME;

				if (length == 8) {
					/*
					 * We're using nanoseconds here (and we will
					 * display nanoseconds), but NTP's timestamps
					 * have a precision in microseconds or greater.
					 * Round to 1 microsecond.
					 */
					time_stamp.nsecs = (int)(1000000*(tvb_get_ntohl(tvb, start+4)/4294967296.0));
					time_stamp.nsecs *= 1000;
				} else {
					time_stamp.nsecs = 0;
				}
				break;

			case ENC_TIME_NTP|ENC_LITTLE_ENDIAN:
				/*
				 * NTP time stamp, big-endian.
				 */
				DISSECTOR_ASSERT(length == 8 || length == 4);
				time_stamp.secs  = tvb_get_letohl(tvb, start);
				if (time_stamp.secs)
					time_stamp.secs -= NTP_BASETIME;

				if (length == 8) {
					/*
					 * We're using nanoseconds here (and we will
					 * display nanoseconds), but NTP's timestamps
					 * have a precision in microseconds or greater.
					 * Round to 1 microsecond.
					 */
					time_stamp.nsecs = (int)(1000000*(tvb_get_letohl(tvb, start+4)/4294967296.0));
					time_stamp.nsecs *= 1000;
				} else {
					time_stamp.nsecs = 0;
				}
				break;

			default:
				DISSECTOR_ASSERT_NOT_REACHED();
				time_stamp.secs = 0;
				time_stamp.nsecs = 0;
				break;
			}
			proto_tree_set_time(new_fi, &time_stamp);
			break;

		case FT_RELATIVE_TIME:
			/*
			 * Relative times can be in any of a number of
			 * formats, and they can be big-endian or
			 * little-endian.
			 *
			 * Historically FT_TIMEs were only timespecs;
			 * the only question was whether they were stored
			 * in big- or little-endian format.
			 *
			 * For backwards compatibility, we interpret an
			 * encoding of 1 as meaning "little-endian timespec",
			 * so that passing TRUE is interpreted as that.
			 */
			if (encoding == TRUE)
				encoding = ENC_TIME_TIMESPEC|ENC_LITTLE_ENDIAN;
			switch (encoding) {

			case ENC_TIME_TIMESPEC|ENC_BIG_ENDIAN:
				/*
				 * 4-byte UNIX epoch, possibly followed by
				 * 4-byte fractional time in nanoseconds,
				 * both big-endian.
				 */
				DISSECTOR_ASSERT(length == 8 || length == 4);
				time_stamp.secs  = tvb_get_ntohl(tvb, start);
				if (length == 8)
					time_stamp.nsecs = tvb_get_ntohl(tvb, start+4);
				else
					time_stamp.nsecs = 0;
				break;

			case ENC_TIME_TIMESPEC|ENC_LITTLE_ENDIAN:
				/*
				 * 4-byte UNIX epoch, possibly followed by
				 * 4-byte fractional time in nanoseconds,
				 * both little-endian.
				 */
				DISSECTOR_ASSERT(length == 8 || length == 4);
				time_stamp.secs  = tvb_get_letohl(tvb, start);
				if (length == 8)
					time_stamp.nsecs = tvb_get_letohl(tvb, start+4);
				else
					time_stamp.nsecs = 0;
				break;
			}
			proto_tree_set_time(new_fi, &time_stamp);
			break;

		default:
			g_error("new_fi->hfinfo->type %d (%s) not handled\n",
					new_fi->hfinfo->type,
					ftype_name(new_fi->hfinfo->type));
			DISSECTOR_ASSERT_NOT_REACHED();
			break;
	}
	FI_SET_FLAG(new_fi, (encoding & ENC_LITTLE_ENDIAN) ? FI_LITTLE_ENDIAN : FI_BIG_ENDIAN);

	/* Don't add new node to proto_tree until now so that any exceptions
	 * raised by a tvbuff access method doesn't leave junk in the proto_tree. */
	pi = proto_tree_add_node(tree, new_fi);

	/* we did not raise an exception so we dont have to remember this
	 * field_info struct any more.
	 */
	field_info_tmp = NULL;

	/* If the proto_tree wants to keep a record of this finfo
	 * for quick lookup, then record it. */
	ptrs = proto_lookup_or_create_interesting_hfids(tree, new_fi->hfinfo);
	if (ptrs)
		g_ptr_array_add(ptrs, new_fi);

	return pi;
}

/* Gets data from tvbuff, adds it to proto_tree, increments offset,
   and returns proto_item* */
proto_item *
ptvcursor_add(ptvcursor_t *ptvc, int hfindex, gint length,
	      const guint encoding)
{
	field_info	  *new_fi;
	header_field_info *hfinfo;
	gint		   item_length;
	guint32		   n;
	int		   offset;

	/* We can't fake it just yet. We have to advance the cursor
	TRY_TO_FAKE_THIS_ITEM(ptvc->tree, hfindex, hfinfo); */

	offset = ptvc->offset;
	hfinfo = get_hfi_and_length(hfindex, ptvc->tvb, offset, &length,
		&item_length);
	ptvc->offset += length;
	if (hfinfo->type == FT_UINT_BYTES || hfinfo->type == FT_UINT_STRING) {
		/*
		 * The length of the rest of the item is in the first N
		 * bytes of the item.
		 */
		n = get_uint_value(ptvc->tvb, offset, length, encoding);
		ptvc->offset += n;
	}

	/* Coast clear. Try and fake it */
	TRY_TO_FAKE_THIS_ITEM(ptvc->tree, hfindex, hfinfo);

	new_fi = new_field_info(ptvc->tree, hfinfo, ptvc->tvb, offset, item_length);
	if (new_fi == NULL)
		return NULL;

	return proto_tree_new_item(new_fi, ptvc->tree, ptvc->tvb,
		offset, length, encoding);
}

/* Add an item to a proto_tree, using the text label registered to that item;
   the item is extracted from the tvbuff handed to it. */
proto_item *
proto_tree_add_item(proto_tree *tree, const int hfindex, tvbuff_t *tvb,
		    const gint start, gint length, const guint encoding)
{
	field_info        *new_fi;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	new_fi = alloc_field_info(tree, hfindex, tvb, start, &length);

	if (new_fi == NULL)
		return NULL;

	return proto_tree_new_item(new_fi, tree, tvb, start,
		length, encoding);
}

/* Add a FT_NONE to a proto_tree */
proto_item *
proto_tree_add_none_format(proto_tree *tree, const int hfindex, tvbuff_t *tvb,
			   const gint start, gint length, const char *format,
			   ...)
{
	proto_item	  *pi;
	va_list		   ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT(hfinfo->type == FT_NONE);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, &length, NULL);

	TRY_TO_FAKE_THIS_REPR(tree, pi);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	/* no value to set for FT_NONE */
	return pi;
}

/* Gets data from tvbuff, adds it to proto_tree, *DOES NOT* increment
 * offset, and returns proto_item* */
proto_item *
ptvcursor_add_no_advance(ptvcursor_t* ptvc, int hf, gint length,
			 const guint encoding)
{
	proto_item *item;

	item = proto_tree_add_item(ptvc->tree, hf, ptvc->tvb, ptvc->offset,
				   length, encoding);

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
proto_tree_add_protocol_format(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			       gint start, gint length, const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;
	field_info	  *new_fi;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT(hfinfo->type == FT_PROTOCOL);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, &length, &new_fi);

	proto_tree_set_protocol_tvb(new_fi, (start == 0 ? tvb : tvb_new_subset(tvb, start, length, length)));

	TRY_TO_FAKE_THIS_REPR(tree, pi);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}


/* Add a FT_BYTES to a proto_tree */
proto_item *
proto_tree_add_bytes(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		     gint length, const guint8 *start_ptr)
{
	proto_item	  *pi;
	field_info	  *new_fi;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT(hfinfo->type == FT_BYTES);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, &length, &new_fi);
	proto_tree_set_bytes(new_fi, start_ptr, length);

	return pi;
}

proto_item *
proto_tree_add_bytes_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
				  gint start, gint length,
				  const guint8 *start_ptr,
				  const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	if (start_ptr)
		pi = proto_tree_add_bytes(tree, hfindex, tvb, start, length,
					  start_ptr);
	else
		pi = proto_tree_add_bytes(tree, hfindex, tvb, start, length,
					  tvb_get_ptr(tvb, start, length));

	if (pi == NULL)
		return NULL;

	TRY_TO_FAKE_THIS_REPR(tree, pi);

	va_start(ap, format);
	proto_tree_set_representation_value(pi, format, ap);
	va_end(ap);

	return pi;
}

proto_item *
proto_tree_add_bytes_format(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			    gint start, gint length, const guint8 *start_ptr,
			    const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	if (start_ptr)
		pi = proto_tree_add_bytes(tree, hfindex, tvb, start, length,
					  start_ptr);
	else
		pi = proto_tree_add_bytes(tree, hfindex, tvb, start, length,
					  tvb_get_ptr(tvb, start, length));

	if (pi == NULL)
		return NULL;

	TRY_TO_FAKE_THIS_REPR(tree, pi);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

static void
proto_tree_set_bytes(field_info *fi, const guint8* start_ptr, gint length)
{
	GByteArray *bytes;

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
proto_tree_add_time(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		    gint length, nstime_t *value_ptr)
{
	proto_item	  *pi;
	field_info	  *new_fi;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT(hfinfo->type == FT_ABSOLUTE_TIME ||
				hfinfo->type == FT_RELATIVE_TIME);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, &length, &new_fi);
	proto_tree_set_time(new_fi, value_ptr);

	return pi;
}

proto_item *
proto_tree_add_time_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
				 gint start, gint length, nstime_t *value_ptr,
				 const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	pi = proto_tree_add_time(tree, hfindex, tvb, start, length, value_ptr);
	if (pi == NULL)
		return NULL;

	TRY_TO_FAKE_THIS_REPR(tree, pi);

	va_start(ap, format);
	proto_tree_set_representation_value(pi, format, ap);
	va_end(ap);

	return pi;
}

proto_item *
proto_tree_add_time_format(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			   gint start, gint length, nstime_t *value_ptr,
			   const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	pi = proto_tree_add_time(tree, hfindex, tvb, start, length, value_ptr);
	if (pi == NULL)
		return NULL;

	TRY_TO_FAKE_THIS_REPR(tree, pi);

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
proto_tree_add_ipxnet(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		      gint length, guint32 value)
{
	proto_item	  *pi;
	field_info	  *new_fi;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT(hfinfo->type == FT_IPXNET);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, &length, &new_fi);
	proto_tree_set_ipxnet(new_fi, value);

	return pi;
}

proto_item *
proto_tree_add_ipxnet_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
				   gint start, gint length, guint32 value,
				   const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	pi = proto_tree_add_ipxnet(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return NULL;

	TRY_TO_FAKE_THIS_REPR(tree, pi);

	va_start(ap, format);
	proto_tree_set_representation_value(pi, format, ap);
	va_end(ap);

	return pi;
}

proto_item *
proto_tree_add_ipxnet_format(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			     gint start, gint length, guint32 value,
			     const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	pi = proto_tree_add_ipxnet(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return NULL;

	TRY_TO_FAKE_THIS_REPR(tree, pi);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

/* Set the FT_IPXNET value */
static void
proto_tree_set_ipxnet(field_info *fi, guint32 value)
{
	fvalue_set_uinteger(&fi->value, value);
}

/* Add a FT_IPv4 to a proto_tree */
proto_item *
proto_tree_add_ipv4(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		    gint length, guint32 value)
{
	proto_item	  *pi;
	field_info	  *new_fi;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT(hfinfo->type == FT_IPv4);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, &length, &new_fi);
	proto_tree_set_ipv4(new_fi, value);

	return pi;
}

proto_item *
proto_tree_add_ipv4_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
				 gint start, gint length, guint32 value,
				 const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	pi = proto_tree_add_ipv4(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return NULL;

	TRY_TO_FAKE_THIS_REPR(tree, pi);

	va_start(ap, format);
	proto_tree_set_representation_value(pi, format, ap);
	va_end(ap);

	return pi;
}

proto_item *
proto_tree_add_ipv4_format(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			   gint start, gint length, guint32 value,
			   const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	pi = proto_tree_add_ipv4(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return NULL;

	TRY_TO_FAKE_THIS_REPR(tree, pi);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

/* Set the FT_IPv4 value */
static void
proto_tree_set_ipv4(field_info *fi, guint32 value)
{
	fvalue_set_uinteger(&fi->value, value);
}

/* Add a FT_IPv6 to a proto_tree */
proto_item *
proto_tree_add_ipv6(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		    gint length, const guint8* value_ptr)
{
	proto_item	  *pi;
	field_info	  *new_fi;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT(hfinfo->type == FT_IPv6);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, &length, &new_fi);
	proto_tree_set_ipv6(new_fi, value_ptr);

	return pi;
}

proto_item *
proto_tree_add_ipv6_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
				 gint start, gint length,
				 const guint8* value_ptr,
				 const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	pi = proto_tree_add_ipv6(tree, hfindex, tvb, start, length, value_ptr);
	if (pi == NULL)
		return NULL;

	TRY_TO_FAKE_THIS_REPR(tree, pi);

	va_start(ap, format);
	proto_tree_set_representation_value(pi, format, ap);
	va_end(ap);

	return pi;
}

proto_item *
proto_tree_add_ipv6_format(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			   gint start, gint length, const guint8* value_ptr,
			   const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	pi = proto_tree_add_ipv6(tree, hfindex, tvb, start, length, value_ptr);
	if (pi == NULL)
		return NULL;

	TRY_TO_FAKE_THIS_REPR(tree, pi);

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
proto_tree_set_ipv6_tvb(field_info *fi, tvbuff_t *tvb, gint start, gint length)
{
	proto_tree_set_ipv6(fi, tvb_get_ptr(tvb, start, length));
}

/* Add a FT_GUID to a proto_tree */
proto_item *
proto_tree_add_guid(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		    gint length, const e_guid_t *value_ptr)
{
	proto_item	  *pi;
	field_info	  *new_fi;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT(hfinfo->type == FT_GUID);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, &length, &new_fi);
	proto_tree_set_guid(new_fi, value_ptr);

	return pi;
}

proto_item *
proto_tree_add_guid_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
				 gint start, gint length,
				 const e_guid_t *value_ptr,
				 const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	pi = proto_tree_add_guid(tree, hfindex, tvb, start, length, value_ptr);
	if (pi == NULL)
		return NULL;

	TRY_TO_FAKE_THIS_REPR(tree, pi);

	va_start(ap, format);
	proto_tree_set_representation_value(pi, format, ap);
	va_end(ap);

	return pi;
}

proto_item *
proto_tree_add_guid_format(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			   gint start, gint length, const e_guid_t *value_ptr,
			   const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	pi = proto_tree_add_guid(tree, hfindex, tvb, start, length, value_ptr);
	if (pi == NULL)
		return NULL;

	TRY_TO_FAKE_THIS_REPR(tree, pi);

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
proto_tree_set_guid_tvb(field_info *fi, tvbuff_t *tvb, gint start,
			const guint encoding)
{
	e_guid_t guid;

	tvb_get_guid(tvb, start, &guid, encoding);
	proto_tree_set_guid(fi, &guid);
}

/* Add a FT_OID to a proto_tree */
proto_item *
proto_tree_add_oid(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		   gint length, const guint8* value_ptr)
{
	proto_item	  *pi;
	field_info	  *new_fi;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT(hfinfo->type == FT_OID);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, &length, &new_fi);
	proto_tree_set_oid(new_fi, value_ptr, length);

	return pi;
}

proto_item *
proto_tree_add_oid_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
				gint start, gint length,
				const guint8* value_ptr,
				const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	pi = proto_tree_add_oid(tree, hfindex, tvb, start, length, value_ptr);
	if (pi == NULL)
		return NULL;

	TRY_TO_FAKE_THIS_REPR(tree, pi);

	va_start(ap, format);
	proto_tree_set_representation_value(pi, format, ap);
	va_end(ap);

	return pi;
}

proto_item *
proto_tree_add_oid_format(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			  gint start, gint length, const guint8* value_ptr,
			  const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	pi = proto_tree_add_oid(tree, hfindex, tvb, start, length, value_ptr);
	if (pi == NULL)
		return NULL;

	TRY_TO_FAKE_THIS_REPR(tree, pi);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

/* Set the FT_OID value */
static void
proto_tree_set_oid(field_info *fi, const guint8* value_ptr, gint length)
{
	GByteArray *bytes;

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

/*
 * NOTE: to support code written when proto_tree_add_item() took a
 * gboolean as its last argument, with FALSE meaning "big-endian"
 * and TRUE meaning "little-endian", we treat any non-zero value of
 * "encoding" as meaning "little-endian".
 */
static void
proto_tree_set_uint64_tvb(field_info *fi, tvbuff_t *tvb, gint start,
			  guint length, const guint encoding)
{
	guint64 value = 0;
	guint8* b = ep_tvb_memdup(tvb, start, length);

	if (encoding) {
		b += length;
		switch (length) {
			default: DISSECTOR_ASSERT_NOT_REACHED();
			case 8: value <<= 8; value += *--b;
			case 7: value <<= 8; value += *--b;
			case 6: value <<= 8; value += *--b;
			case 5: value <<= 8; value += *--b;
			case 4: value <<= 8; value += *--b;
			case 3: value <<= 8; value += *--b;
			case 2: value <<= 8; value += *--b;
			case 1: value <<= 8; value += *--b;
				break;
		}
	} else {
		switch (length) {
			default: DISSECTOR_ASSERT_NOT_REACHED();
			case 8: value <<= 8; value += *b++;
			case 7: value <<= 8; value += *b++;
			case 6: value <<= 8; value += *b++;
			case 5: value <<= 8; value += *b++;
			case 4: value <<= 8; value += *b++;
			case 3: value <<= 8; value += *b++;
			case 2: value <<= 8; value += *b++;
			case 1: value <<= 8; value += *b++;
				break;
		}
	}

	proto_tree_set_uint64(fi, value);
}

/* Add a FT_STRING or FT_STRINGZ to a proto_tree. Creates own copy of string,
 * and frees it when the proto_tree is destroyed. */
proto_item *
proto_tree_add_string(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		      gint length, const char* value)
{
	proto_item	  *pi;
	field_info	  *new_fi;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT(hfinfo->type == FT_STRING || hfinfo->type == FT_STRINGZ);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, &length, &new_fi);
	DISSECTOR_ASSERT(length >= 0);
	proto_tree_set_string(new_fi, value);

	return pi;
}

proto_item *
proto_tree_add_string_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
				   gint start, gint length, const char* value,
				   const char *format,
				   ...)
{
	proto_item	  *pi;
	va_list		   ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	pi = proto_tree_add_string(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return NULL;

	TRY_TO_FAKE_THIS_REPR(tree, pi);

	va_start(ap, format);
	proto_tree_set_representation_value(pi, format, ap);
	va_end(ap);

	return pi;
}

proto_item *
proto_tree_add_string_format(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			     gint start, gint length, const char* value,
			     const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	pi = proto_tree_add_string(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return NULL;

	TRY_TO_FAKE_THIS_REPR(tree, pi);

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
 * Do that by faking that the tree is visible by calling
 * proto_tree_set_visible(tree, TRUE) (see packet-wsp.c)
 * BEFORE you create the item you are later going to use
 * proto_item_append_string() on.
 */
void
proto_item_append_string(proto_item *pi, const char *str)
{
	field_info        *fi;
	header_field_info *hfinfo;
	gchar             *old_str, *new_str;

	if (!pi)
		return;
	if (!*str)
		return;

	fi = PITEM_FINFO(pi);
	DISSECTOR_ASSERT(fi && "proto_tree_set_visible(tree, TRUE) should have been called previously");

	hfinfo = fi->hfinfo;
	if (hfinfo->type == FT_PROTOCOL) {
		/* TRY_TO_FAKE_THIS_ITEM() speed optimization: silently skip */
		return;
	}
	DISSECTOR_ASSERT(hfinfo->type == FT_STRING || hfinfo->type == FT_STRINGZ);
	old_str = fvalue_get(&fi->value);
	new_str = ep_strdup_printf("%s%s", old_str, str);
	fvalue_set(&fi->value, new_str, FALSE);
}

/* Set the FT_STRING value */
static void
proto_tree_set_string(field_info *fi, const char* value)
{
	if (value) {
		fvalue_set(&fi->value, (gpointer) value, FALSE);
	} else {
		fvalue_set(&fi->value, (gpointer) "[ Null ]", FALSE);
	}
}

static void
proto_tree_set_string_tvb(field_info *fi, tvbuff_t *tvb, gint start, gint length, gint encoding)
{
	gchar	*string;

	if (length == -1) {
		length = tvb_ensure_length_remaining(tvb, start);
	}

	string = tvb_get_ephemeral_string_enc(tvb, start, length, encoding);
	proto_tree_set_string(fi, string);
}

/* Add a FT_ETHER to a proto_tree */
proto_item *
proto_tree_add_ether(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		     gint length, const guint8* value)
{
	proto_item	  *pi;
	field_info	  *new_fi;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT(hfinfo->type == FT_ETHER);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, &length, &new_fi);
	proto_tree_set_ether(new_fi, value);

	return pi;
}

proto_item *
proto_tree_add_ether_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
				  gint start, gint length, const guint8* value,
				  const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	pi = proto_tree_add_ether(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return NULL;

	TRY_TO_FAKE_THIS_REPR(tree, pi);

	va_start(ap, format);
	proto_tree_set_representation_value(pi, format, ap);
	va_end(ap);

	return pi;
}

proto_item *
proto_tree_add_ether_format(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			    gint start, gint length, const guint8* value,
			    const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	pi = proto_tree_add_ether(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return NULL;

	TRY_TO_FAKE_THIS_REPR(tree, pi);

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
	proto_tree_set_ether(fi, tvb_get_ptr(tvb, start, FT_ETHER_LEN));
}

/* Add a FT_BOOLEAN to a proto_tree */
proto_item *
proto_tree_add_boolean(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		       gint length, guint32 value)
{
	proto_item	  *pi;
	field_info	  *new_fi;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT(hfinfo->type == FT_BOOLEAN);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, &length, &new_fi);
	proto_tree_set_boolean(new_fi, value);

	return pi;
}

proto_item *
proto_tree_add_boolean_format_value(proto_tree *tree, int hfindex,
				    tvbuff_t *tvb, gint start, gint length,
				    guint32 value, const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	pi = proto_tree_add_boolean(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return NULL;

	TRY_TO_FAKE_THIS_REPR(tree, pi);

	va_start(ap, format);
	proto_tree_set_representation_value(pi, format, ap);
	va_end(ap);

	return pi;
}

proto_item *
proto_tree_add_boolean_format(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			      gint start, gint length, guint32 value,
			      const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	pi = proto_tree_add_boolean(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return NULL;

	TRY_TO_FAKE_THIS_REPR(tree, pi);

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
proto_tree_add_float(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		     gint length, float value)
{
	proto_item	  *pi;
	field_info	  *new_fi;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT(hfinfo->type == FT_FLOAT);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, &length, &new_fi);
	proto_tree_set_float(new_fi, value);

	return pi;
}

proto_item *
proto_tree_add_float_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
				  gint start, gint length, float value,
				  const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	pi = proto_tree_add_float(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return NULL;

	TRY_TO_FAKE_THIS_REPR(tree, pi);

	va_start(ap, format);
	proto_tree_set_representation_value(pi, format, ap);
	va_end(ap);

	return pi;
}

proto_item *
proto_tree_add_float_format(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			    gint start, gint length, float value,
			    const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	pi = proto_tree_add_float(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return NULL;

	TRY_TO_FAKE_THIS_REPR(tree, pi);

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
proto_tree_add_double(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		      gint length, double value)
{
	proto_item	  *pi;
	field_info	  *new_fi;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT(hfinfo->type == FT_DOUBLE);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, &length, &new_fi);
	proto_tree_set_double(new_fi, value);

	return pi;
}

proto_item *
proto_tree_add_double_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
				   gint start, gint length, double value,
				   const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	pi = proto_tree_add_double(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return NULL;

	TRY_TO_FAKE_THIS_REPR(tree, pi);

	va_start(ap, format);
	proto_tree_set_representation_value(pi, format, ap);
	va_end(ap);

	return pi;
}

proto_item *
proto_tree_add_double_format(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			     gint start, gint length, double value,
			     const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	pi = proto_tree_add_double(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return NULL;

	TRY_TO_FAKE_THIS_REPR(tree, pi);

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
proto_tree_add_uint(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		    gint length, guint32 value)
{
	proto_item	  *pi = NULL;
	field_info	  *new_fi;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	switch (hfinfo->type) {
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
proto_tree_add_uint_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
				 gint start, gint length, guint32 value,
				 const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	pi = proto_tree_add_uint(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return NULL;

	TRY_TO_FAKE_THIS_REPR(tree, pi);

	va_start(ap, format);
	proto_tree_set_representation_value(pi, format, ap);
	va_end(ap);

	return pi;
}

proto_item *
proto_tree_add_uint_format(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			   gint start, gint length, guint32 value,
			   const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	pi = proto_tree_add_uint(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return NULL;

	TRY_TO_FAKE_THIS_REPR(tree, pi);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

/* Set the FT_UINT{8,16,24,32} value */
static void
proto_tree_set_uint(field_info *fi, guint32 value)
{
	header_field_info *hfinfo;
	guint32		   integer;

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

	fvalue_set_uinteger(&fi->value, integer);
}

/* Add FT_UINT64 to a proto_tree */
proto_item *
proto_tree_add_uint64(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		      gint length, guint64 value)
{
	proto_item	  *pi = NULL;
	field_info	  *new_fi;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT(hfinfo->type == FT_UINT64);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, &length, &new_fi);
	proto_tree_set_uint64(new_fi, value);

	return pi;
}

proto_item *
proto_tree_add_uint64_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
				   gint start, gint length, guint64 value,
				   const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	pi = proto_tree_add_uint64(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return NULL;

	TRY_TO_FAKE_THIS_REPR(tree, pi);

	va_start(ap, format);
	proto_tree_set_representation_value(pi, format, ap);
	va_end(ap);

	return pi;
}

proto_item *
proto_tree_add_uint64_format(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			     gint start, gint length, guint64 value,
			     const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	pi = proto_tree_add_uint64(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return NULL;

	TRY_TO_FAKE_THIS_REPR(tree, pi);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

/* Add FT_INT{8,16,24,32} to a proto_tree */
proto_item *
proto_tree_add_int(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		   gint length, gint32 value)
{
	proto_item	  *pi = NULL;
	field_info	  *new_fi;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	switch (hfinfo->type) {
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
proto_tree_add_int_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
				gint start, gint length, gint32 value,
				const char *format, ...)
{
	proto_item	  *pi = NULL;
	va_list		   ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	pi = proto_tree_add_int(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return NULL;

	TRY_TO_FAKE_THIS_REPR(tree, pi);

	va_start(ap, format);
	proto_tree_set_representation_value(pi, format, ap);
	va_end(ap);

	return pi;
}

proto_item *
proto_tree_add_int_format(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			  gint start, gint length, gint32 value,
			  const char *format, ...)
{
	proto_item	  *pi = NULL;
	va_list		   ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	pi = proto_tree_add_int(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return NULL;

	TRY_TO_FAKE_THIS_REPR(tree, pi);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

/* Set the FT_INT{8,16,24,32} value */
static void
proto_tree_set_int(field_info *fi, gint32 value)
{
	header_field_info *hfinfo;
	guint32		   integer;

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

	fvalue_set_sinteger(&fi->value, integer);
}

/* Add FT_INT64 to a proto_tree */
proto_item *
proto_tree_add_int64(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		     gint length, gint64 value)
{
	proto_item	  *pi = NULL;
	field_info	  *new_fi;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT(hfinfo->type == FT_INT64);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, &length, &new_fi);
	proto_tree_set_uint64(new_fi, (guint64)value);

	return pi;
}

proto_item *
proto_tree_add_int64_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
				  gint start, gint length, gint64 value,
				  const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	pi = proto_tree_add_int64(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return NULL;

	TRY_TO_FAKE_THIS_REPR(tree, pi);

	va_start(ap, format);
	proto_tree_set_representation_value(pi, format, ap);
	va_end(ap);

	return pi;
}

proto_item *
proto_tree_add_int64_format(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			   gint start, gint length, gint64 value,
			   const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	pi = proto_tree_add_int64(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return NULL;

	TRY_TO_FAKE_THIS_REPR(tree, pi);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}
/* Add a FT_EUI64 to a proto_tree */
proto_item *
proto_tree_add_eui64(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		     gint length, const guint64 value)
{
	proto_item	  *pi;
	field_info	  *new_fi;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT(hfinfo->type == FT_EUI64);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, &length, &new_fi);
	proto_tree_set_eui64(new_fi, value);

	return pi;
}

proto_item *
proto_tree_add_eui64_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
				  gint start, gint length, const guint64 value,
				  const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	pi = proto_tree_add_eui64(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return NULL;

	TRY_TO_FAKE_THIS_REPR(tree, pi);

	va_start(ap, format);
	proto_tree_set_representation_value(pi, format, ap);
	va_end(ap);

	return pi;
}

proto_item *
proto_tree_add_eui64_format(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			    gint start, gint length, const guint64 value,
			    const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	pi = proto_tree_add_eui64(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return NULL;

	TRY_TO_FAKE_THIS_REPR(tree, pi);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

/* Set the FT_EUI64 value */
static void
proto_tree_set_eui64(field_info *fi, const guint64 value)
{
	fvalue_set_integer64(&fi->value, value);
}
static void
proto_tree_set_eui64_tvb(field_info *fi, tvbuff_t *tvb, gint start, const guint encoding)
{
	if (encoding)
	{
		proto_tree_set_eui64(fi, tvb_get_letoh64(tvb, start));
	} else {
		proto_tree_set_eui64(fi, tvb_get_ntoh64(tvb, start));
	}
}

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
	 * "PNODE_FINFO(tnode)" may be null; that's the case for the root
	 * node of the protocol tree.  That node is not displayed,
	 * so it doesn't need an ett_ value to remember whether it
	 * was expanded.
	 */
	tnode = tree;
	tfi = PNODE_FINFO(tnode);
	if (tfi != NULL && (tfi->tree_type < 0 || tfi->tree_type >= num_tree_types)) {
		REPORT_DISSECTOR_BUG(ep_strdup_printf("\"%s\" - \"%s\" tfi->tree_type: %u invalid (%s:%u)",
				     fi->hfinfo->name, fi->hfinfo->abbrev, tfi->tree_type, __FILE__, __LINE__));
		/* XXX - is it safe to continue here? */
	}

	DISSECTOR_ASSERT(tfi == NULL ||
		(tfi->tree_type >= 0 && tfi->tree_type < num_tree_types));

	PROTO_NODE_NEW(pnode);
	pnode->parent = tnode;
	PNODE_FINFO(pnode) = fi;
	pnode->tree_data = PTREE_DATA(tree);

	if (tnode->last_child != NULL) {
		sibling = tnode->last_child;
		DISSECTOR_ASSERT(sibling->next == NULL);
		sibling->next = pnode;
	} else
		tnode->first_child = pnode;
	tnode->last_child = pnode;

	return (proto_item *)pnode;
}


/* Generic way to allocate field_info and add to proto_tree.
 * Sets *pfi to address of newly-allocated field_info struct, if pfi is
 * non-NULL. */
static proto_item *
proto_tree_add_pi(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		  gint *length, field_info **pfi)
{
	proto_item *pi;
	field_info *fi;
	GPtrArray  *ptrs;

	if (!tree)
		return NULL;

	fi = alloc_field_info(tree, hfindex, tvb, start, length);
	pi = proto_tree_add_node(tree, fi);

	/* If the proto_tree wants to keep a record of this finfo
	 * for quick lookup, then record it. */
	ptrs = proto_lookup_or_create_interesting_hfids(tree, fi->hfinfo);
	if (ptrs)
		g_ptr_array_add(ptrs, fi);

	/* Does the caller want to know the fi pointer? */
	if (pfi) {
		*pfi = fi;
	}

	return pi;
}


static header_field_info *
get_hfi_and_length(int hfindex, tvbuff_t *tvb, const gint start, gint *length,
		   gint *item_length)
{
	header_field_info *hfinfo;
	gint		   length_remaining;

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
	       const gint start, const gint item_length)
{
	field_info *fi;

	FIELD_INFO_NEW(fi);

	fi->hfinfo     = hfinfo;
	fi->start      = start;
	fi->start     += (tvb)?tvb_raw_offset(tvb):0;
	fi->length     = item_length;
	fi->tree_type  = -1;
	fi->flags      = 0;
	if (!PTREE_DATA(tree)->visible)
		FI_SET_FLAG(fi, FI_HIDDEN);
	fvalue_init(&fi->value, fi->hfinfo->type);
	fi->rep        = NULL;

	/* add the data source tvbuff */
	fi->ds_tvb = tvb ? tvb_get_ds_tvb(tvb) : NULL;

	fi->appendix_start  = 0;
	fi->appendix_length = 0;

	return fi;
}

static field_info *
alloc_field_info(proto_tree *tree, int hfindex, tvbuff_t *tvb, const gint start,
		 gint *length)
{
	header_field_info *hfinfo;
	gint		   item_length;

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
	int                ret;	/*tmp return value */
	field_info        *fi = PITEM_FINFO(pi);
	header_field_info *hf;

	DISSECTOR_ASSERT(fi);

	hf = fi->hfinfo;

	if (!PROTO_ITEM_IS_HIDDEN(pi)) {
		ITEM_LABEL_NEW(fi->rep);
		if (hf->bitmask && (hf->type == FT_BOOLEAN || IS_FT_UINT(hf->type))) {
			char tmpbuf[64];
			guint32 val;

			val = fvalue_get_uinteger(&fi->value);
			if (hf->bitshift > 0) {
				val <<= hf->bitshift;
			}
			decode_bitfield_value(tmpbuf, val, hf->bitmask, hfinfo_bitwidth(hf));
			/* put in the hf name */
			ret = g_snprintf(fi->rep->representation, ITEM_LABEL_LENGTH,
					 "%s%s: ", tmpbuf, fi->hfinfo->name);
		} else {
			/* put in the hf name */
			ret = g_snprintf(fi->rep->representation, ITEM_LABEL_LENGTH,
					 "%s: ", fi->hfinfo->name);
		}

		/* If possible, Put in the value of the string */
		if (ret < ITEM_LABEL_LENGTH) {
			ret += g_vsnprintf(fi->rep->representation + ret,
					  ITEM_LABEL_LENGTH - ret, format, ap);
		}
		if (ret >= ITEM_LABEL_LENGTH) {
			/* Uh oh, we don't have enough room.  Tell the user
			 * that the field is truncated.
			 */
			char *oldrep;

			/*	Argh, we cannot reuse 'ap' here.  So make a copy
			 *	of what we formatted for (re)use below.
			 */
			oldrep = g_strdup(fi->rep->representation);

			g_snprintf(fi->rep->representation,
				   ITEM_LABEL_LENGTH,
				   "[truncated] %s",
				   oldrep);
			g_free(oldrep);
		}
	}
}

/* If the protocol tree is to be visible, set the representation of a
   proto_tree entry with the representation formatted with the supplied
   printf-style format and argument list. */
static void
proto_tree_set_representation(proto_item *pi, const char *format, va_list ap)
{
	int	    ret;	/*tmp return value */
	field_info *fi = PITEM_FINFO(pi);

	DISSECTOR_ASSERT(fi);

	if (!PROTO_ITEM_IS_HIDDEN(pi)) {
		ITEM_LABEL_NEW(fi->rep);
		ret = g_vsnprintf(fi->rep->representation, ITEM_LABEL_LENGTH,
				  format, ap);
		if (ret >= ITEM_LABEL_LENGTH) {
			/* Uh oh, we don't have enough room.  Tell the user
			 * that the field is truncated.
			 */
			char *oldrep;

			/*	Argh, we cannot reuse 'ap' here.  So make a copy
			 *	of what we formatted for (re)use below.
			 */
			oldrep = g_strdup(fi->rep->representation);

			g_snprintf(fi->rep->representation, ITEM_LABEL_LENGTH,
				   "[truncated] %s", oldrep);
			g_free(oldrep);
		}
	}
}

/* -------------------------- */
const gchar *
proto_custom_set(proto_tree* tree, const int field_id, gint occurrence,
		 gchar *result, gchar *expr, const int size)
{
	guint32            u_integer;
	gint32             integer;
	guint8            *bytes;
	ipv4_addr         *ipv4;
	struct e_in6_addr *ipv6;
	address            addr;
	guint32            n_addr; /* network-order IPv4 address */

	const true_false_string  *tfstring;

	int                 len, prev_len = 0, last, i, offset_r = 0, offset_e = 0;
	GPtrArray          *finfos;
	field_info         *finfo         = NULL;
	header_field_info*  hfinfo;
	const gchar        *abbrev        = NULL;

	g_assert(field_id >= 0);

	hfinfo = proto_registrar_get_nth((guint)field_id);

	/* do we need to rewind ? */
	if (!hfinfo)
		return "";

	if (occurrence < 0) {
		/* Search other direction */
		while (hfinfo->same_name_prev) {
			hfinfo = hfinfo->same_name_prev;
		}
	}

	while (hfinfo) {
		finfos = proto_get_finfo_ptr_array(tree, hfinfo->id);

		if (!finfos || !(len = g_ptr_array_len(finfos))) {
			if (occurrence < 0) {
				hfinfo = hfinfo->same_name_next;
			} else {
				hfinfo = hfinfo->same_name_prev;
			}
			continue;
		}

		/* Are there enough occurrences of the field? */
		if (((occurrence - prev_len) > len) || ((occurrence + prev_len) < -len)) {
			if (occurrence < 0) {
				hfinfo = hfinfo->same_name_next;
			} else {
				hfinfo = hfinfo->same_name_prev;
			}
			prev_len += len;
			continue;
		}

		/* Calculate single index or set outer bounderies */
		if (occurrence < 0) {
			i = occurrence + len + prev_len;
			last = i;
		} else if (occurrence > 0) {
			i = occurrence - 1 - prev_len;
			last = i;
		} else {
			i = 0;
			last = len - 1;
		}

		prev_len += len; /* Count handled occurrences */

		while (i <= last) {
			finfo = g_ptr_array_index(finfos, i);

			if (offset_r && (offset_r < (size - 2)))
				result[offset_r++] = ',';

			if (offset_e && (offset_e < (size - 2)))
				expr[offset_e++] = ',';

			switch (hfinfo->type) {

			case FT_NONE: /* Nothing to add */
				if (offset_r == 0) {
					result[0] = '\0';
				} else if (result[offset_r-1] == ',') {
					result[offset_r-1] = '\0';
				}
				break;

			case FT_PROTOCOL:
				/* prevent multiple "yes" entries by setting result directly */
				g_strlcpy(result, "Yes", size);
				break;

			case FT_UINT_BYTES:
			case FT_BYTES:
				bytes = fvalue_get(&finfo->value);
				offset_r += (int)g_strlcpy(result+offset_r,
							   bytes_to_str(bytes,
									fvalue_length(&finfo->value)),
							   size-offset_r);
				break;

			case FT_ABSOLUTE_TIME:
				offset_r += (int)g_strlcpy(result+offset_r,
							   abs_time_to_str(fvalue_get(&finfo->value),
									   hfinfo->display, TRUE),
							   size-offset_r);
				break;

			case FT_RELATIVE_TIME:
				offset_r += (int)g_strlcpy(result+offset_r,
							   rel_time_to_secs_str(fvalue_get(&finfo->value)),
							   size-offset_r);
				break;

			case FT_BOOLEAN:
				u_integer = fvalue_get_uinteger(&finfo->value);
				tfstring = (const true_false_string *)&tfs_true_false;
				if (hfinfo->strings) {
					tfstring = (const struct true_false_string*) hfinfo->strings;
				}
				offset_r += (int)g_strlcpy(result+offset_r,
							   u_integer ?
							     tfstring->true_string :
							     tfstring->false_string, size-offset_r);

				g_snprintf(expr+offset_e, size-offset_e, "%u",
					   fvalue_get_uinteger(&finfo->value) ? 1 : 0);
				offset_e = (int)strlen(expr);
				break;

			case FT_UINT8:
			case FT_UINT16:
			case FT_UINT24:
			case FT_UINT32:
			case FT_FRAMENUM:
				u_integer = fvalue_get_uinteger(&finfo->value);
				if (hfinfo->strings) {
					if (hfinfo->display & BASE_CUSTOM) {
						g_snprintf(result+offset_r, size-offset_r, "%u", u_integer);
					} else if (hfinfo->display & BASE_RANGE_STRING) {
						g_strlcpy(result+offset_r,
							  rval_to_str(u_integer, hfinfo->strings, "%u"),
							  size-offset_r);
					} else if (hfinfo->display & BASE_EXT_STRING) {
						g_strlcpy(result+offset_r,
							  val_to_str_ext(u_integer,
									 (value_string_ext *)(hfinfo->strings),
									 "%u"), size-offset_r);
					} else {
						g_strlcpy(result+offset_r,
							  val_to_str(u_integer, cVALS(hfinfo->strings), "%u"),
							  size-offset_r);
					}
				} else if (IS_BASE_DUAL(hfinfo->display)) {
					g_snprintf(result+offset_r, size-offset_r,
						   hfinfo_uint_value_format(hfinfo), u_integer, u_integer);
				} else {
					g_snprintf(result+offset_r, size-offset_r,
						   hfinfo_uint_value_format(hfinfo), u_integer);
				}

				if (hfinfo->strings && (hfinfo->display & BASE_DISPLAY_E_MASK) == BASE_NONE) {
					g_snprintf(expr+offset_e, size-offset_e,
						   "\"%s\"", result+offset_r);
				} else {
					g_snprintf(expr+offset_e, size-offset_e,
						   hfinfo_numeric_value_format(hfinfo),
						   fvalue_get_uinteger(&finfo->value));
				}

				offset_r = (int)strlen(result);
				offset_e = (int)strlen(expr);
				break;

			case FT_INT64:
				g_snprintf(result+offset_r, size-offset_r,
					   "%" G_GINT64_MODIFIER "d",
					   fvalue_get_integer64(&finfo->value));
				offset_r = (int)strlen(result);
				break;
			case FT_UINT64:
				g_snprintf(result+offset_r, size-offset_r,
					   "%" G_GINT64_MODIFIER "u",
					   fvalue_get_integer64(&finfo->value));
				offset_r = (int)strlen(result);
				break;
			case FT_EUI64:
				offset_r += (int)g_strlcpy(result+offset_r,
							   eui64_to_str(fvalue_get_integer64(&finfo->value)),
							   size-offset_r);
				break;
			/* XXX - make these just FT_INT? */
			case FT_INT8:
			case FT_INT16:
			case FT_INT24:
			case FT_INT32:
				integer = fvalue_get_sinteger(&finfo->value);
				if (hfinfo->strings) {
					if (hfinfo->display & BASE_CUSTOM) {
						g_snprintf(result+offset_r, size-offset_r, "%d", integer);
					} else if (hfinfo->display & BASE_RANGE_STRING) {
						g_strlcpy(result+offset_r,
							  rval_to_str(integer, hfinfo->strings, "%d"),
							  size-offset_r);
					} else if (hfinfo->display & BASE_EXT_STRING) {
						g_strlcpy(result+offset_r,
							  val_to_str_ext(integer,
									 (value_string_ext *)(hfinfo->strings),
									 "%d"),
							  size-offset_r);
					} else {
						g_strlcpy(result+offset_r,
							  val_to_str(integer, cVALS(hfinfo->strings), "%d"),
							  size-offset_r);
					}
				} else if (IS_BASE_DUAL(hfinfo->display)) {
					g_snprintf(result+offset_r, size-offset_r,
						   hfinfo_int_value_format(hfinfo), integer, integer);
				} else {
					g_snprintf(result+offset_r, size-offset_r,
						   hfinfo_int_value_format(hfinfo), integer);
				}

				if (hfinfo->strings && (hfinfo->display & BASE_DISPLAY_E_MASK) == BASE_NONE) {
					g_snprintf(expr+offset_e, size-offset_e, "\"%s\"", result+offset_r);
				} else {
					g_snprintf(expr+offset_e, size-offset_e,
						   hfinfo_numeric_value_format(hfinfo),
						   fvalue_get_sinteger(&finfo->value));
				}

				offset_r = (int)strlen(result);
				offset_e = (int)strlen(expr);
				break;

			case FT_IPv4:
				ipv4 = fvalue_get(&finfo->value);
				n_addr = ipv4_get_net_order_addr(ipv4);
				offset_r += (int)g_strlcpy(result+offset_r,
							   ip_to_str((guint8 *)&n_addr),
							   size-offset_r);
				break;

			case FT_IPv6:
				ipv6 = fvalue_get(&finfo->value);
				SET_ADDRESS (&addr, AT_IPv6, sizeof(struct e_in6_addr), ipv6);
				address_to_str_buf(&addr, result+offset_r, size-offset_r);
				offset_r = (int)strlen(result);
				break;

			case FT_ETHER:
				offset_r += (int)g_strlcpy(result+offset_r,
							   bytes_to_str_punct(fvalue_get(&finfo->value),
									      FT_ETHER_LEN, ':'),
							   size-offset_r);
				break;

			case FT_GUID:
				offset_r += (int)g_strlcpy(result+offset_r,
							   guid_to_str((e_guid_t *)fvalue_get(&finfo->value)),
							   size-offset_r);
				break;

			case FT_OID:
				bytes = fvalue_get(&finfo->value);
				offset_r += (int)g_strlcpy(result+offset_r,
							   oid_resolved_from_encoded(bytes,
										     fvalue_length(&finfo->value)),
							   size-offset_r);
				offset_e += (int)g_strlcpy(expr+offset_e,
							   oid_encoded2string(bytes, fvalue_length(&finfo->value)),
							   size-offset_e);
				break;

			case FT_FLOAT:
				g_snprintf(result+offset_r, size-offset_r,
					   "%." STRINGIFY(FLT_DIG) "g", fvalue_get_floating(&finfo->value));
				offset_r = (int)strlen(result);
				break;

			case FT_DOUBLE:
				g_snprintf(result+offset_r, size-offset_r,
					   "%." STRINGIFY(DBL_DIG) "g", fvalue_get_floating(&finfo->value));
				offset_r = (int)strlen(result);
				break;

			case FT_STRING:
			case FT_STRINGZ:
			case FT_UINT_STRING:
				bytes = fvalue_get(&finfo->value);
				offset_r += (int)g_strlcpy(result+offset_r,
							   format_text(bytes, strlen(bytes)),
							   size-offset_r);
				break;

			case FT_IPXNET: /*XXX really No column custom ?*/
			case FT_PCRE:
			default:
				g_error("hfinfo->type %d (%s) not handled\n",
						hfinfo->type,
						ftype_name(hfinfo->type));
				DISSECTOR_ASSERT_NOT_REACHED();
				break;
			}
			i++;
		}

		switch (hfinfo->type) {

		case FT_BOOLEAN:
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
		case FT_FRAMENUM:
		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
		case FT_OID:
			/* for these types, "expr" is filled in the loop above */
			break;

		default:
			/* for all others, just copy "result" to "expr" */
			g_strlcpy(expr, result, size);
			break;
		}

		if (!abbrev) {
			/* Store abbrev for return value */
			abbrev = hfinfo->abbrev;
		}

		if (occurrence == 0) {
			/* Fetch next hfinfo with same name (abbrev) */
			hfinfo = hfinfo->same_name_prev;
		} else {
			hfinfo = NULL;
		}
	}

	return abbrev ? abbrev : "";
}


/* Set text of proto_item after having already been created. */
void
proto_item_set_text(proto_item *pi, const char *format, ...)
{
	field_info *fi = NULL;
	va_list     ap;

	if (pi == NULL) {
		return;
	}

	fi = PITEM_FINFO(pi);
	if (fi == NULL)
		return;

	if (fi->rep) {
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
	size_t      curlen;
	va_list     ap;

	if (pi == NULL) {
		return;
	}

	fi = PITEM_FINFO(pi);
	if (fi == NULL) {
		return;
	}

	if (!PROTO_ITEM_IS_HIDDEN(pi)) {
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
			va_start(ap, format);
			g_vsnprintf(fi->rep->representation + curlen,
				ITEM_LABEL_LENGTH - (gulong) curlen, format, ap);
			va_end(ap);
		}
	}
}

/* Prepend to text of proto_item after having already been created. */
void
proto_item_prepend_text(proto_item *pi, const char *format, ...)
{
	field_info *fi = NULL;
	char        representation[ITEM_LABEL_LENGTH];
	va_list     ap;

	if (pi == NULL) {
		return;
	}

	fi = PITEM_FINFO(pi);
	if (fi == NULL) {
		return;
	}

	if (!PROTO_ITEM_IS_HIDDEN(pi)) {
		/*
		 * If we don't already have a representation,
		 * generate the default representation.
		 */
		if (fi->rep == NULL) {
			ITEM_LABEL_NEW(fi->rep);
			proto_item_fill_label(fi, fi->rep->representation);
		}

		g_strlcpy(representation, fi->rep->representation, ITEM_LABEL_LENGTH);
		va_start(ap, format);
		g_vsnprintf(fi->rep->representation,
			ITEM_LABEL_LENGTH, format, ap);
		va_end(ap);
		g_strlcat(fi->rep->representation, representation, ITEM_LABEL_LENGTH);
	}
}

void
proto_item_set_len(proto_item *pi, const gint length)
{
	field_info *fi;

	if (pi == NULL)
		return;

	fi = PITEM_FINFO(pi);
	if (fi == NULL)
		return;

	DISSECTOR_ASSERT(length >= 0);
	fi->length = length;

	/*
	 * You cannot just make the "len" field of a GByteArray
	 * larger, if there's no data to back that length;
	 * you can only make it smaller.
	 */
	if (fi->value.ftype->ftype == FT_BYTES && length <= (gint)fi->value.value.bytes->len)
		fi->value.value.bytes->len = length;
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
	if (fi == NULL)
		return;

	end += tvb_raw_offset(tvb);
	DISSECTOR_ASSERT(end >= fi->start);
	fi->length = end - fi->start;
}

int
proto_item_get_len(const proto_item *pi)
{
	field_info *fi = PITEM_FINFO(pi);
	return fi ? fi->length : -1;
}


/** clear flags according to the mask and set new flag values */
#define FI_REPLACE_FLAGS(fi, mask, flags_in) { \
	(fi->flags = (fi)->flags & ~(mask)); \
	(fi->flags = (fi)->flags | (flags_in)); \
}

gboolean
proto_item_set_expert_flags(proto_item *pi, const int group, const guint severity)
{
	if (pi == NULL || PITEM_FINFO(pi) == NULL)
		return FALSE;

	/* only change things if severity is worse or at least equal than before */
	if (severity >= FI_GET_FLAG(PITEM_FINFO(pi), PI_SEVERITY_MASK)) {
		FI_REPLACE_FLAGS(PITEM_FINFO(pi), PI_GROUP_MASK, group);
		FI_REPLACE_FLAGS(PITEM_FINFO(pi), PI_SEVERITY_MASK, severity);

		return TRUE;
	}

	return FALSE;
}

proto_tree *
proto_tree_create_root(void)
{
	proto_node *pnode;

	/* Initialize the proto_node */
	PROTO_NODE_NEW(pnode);
	pnode->parent = NULL;
	PNODE_FINFO(pnode) = NULL;
	pnode->tree_data = g_new(tree_data_t, 1);

	/* Don't initialize the tree_data_t. Wait until we know we need it */
	pnode->tree_data->interesting_hfids = NULL;

	/* Set the default to FALSE so it's easier to
	 * find errors; if we expect to see the protocol tree
	 * but for some reason the default 'visible' is not
	 * changed, then we'll find out very quickly. */
	pnode->tree_data->visible = FALSE;

	/* Make sure that we fake protocols (if possible) */
	pnode->tree_data->fake_protocols = TRUE;

	/* Keep track of the number of children */
	pnode->tree_data->count = 0;

	return (proto_tree *)pnode;
}


/* "prime" a proto_tree with a single hfid that a dfilter
 * is interested in. */
void
proto_tree_prime_hfid(proto_tree *tree _U_, const gint hfid)
{
	header_field_info *hfinfo;

	PROTO_REGISTRAR_GET_NTH(hfid, hfinfo);
	/* this field is referenced by a filter so increase the refcount.
	   also increase the refcount for the parent, i.e the protocol.
	*/
	hfinfo->ref_type = HF_REF_TYPE_DIRECT;
	/* only increase the refcount if there is a parent.
	   if this is a protocol and not a field then parent will be -1
	   and there is no parent to add any refcounting for.
	*/
	if (hfinfo->parent != -1) {
		header_field_info *parent_hfinfo;
		PROTO_REGISTRAR_GET_NTH(hfinfo->parent, parent_hfinfo);

		/* Mark parent as indirectly referenced unless it is already directly
		 * referenced, i.e. the user has specified the parent in a filter.
		 */
		if (parent_hfinfo->ref_type != HF_REF_TYPE_DIRECT)
			parent_hfinfo->ref_type = HF_REF_TYPE_INDIRECT;
	}
}

proto_tree *
proto_item_add_subtree(proto_item *pi,	const gint idx) {
	field_info *fi;

	if (!pi)
		return NULL;

	DISSECTOR_ASSERT(idx >= 0 && idx < num_tree_types);

	fi = PITEM_FINFO(pi);
	if (!fi)
		return (proto_tree *)pi;

	fi->tree_type = idx;

	return (proto_tree *)pi;
}

proto_tree *
proto_item_get_subtree(const proto_item *pi) {
	field_info *fi;

	if (!pi)
		return NULL;
	fi = PITEM_FINFO(pi);
	if ( (!fi) || (fi->tree_type == -1) )
		return NULL;
	return (proto_tree *)pi;
}

proto_item *
proto_item_get_parent(const proto_item *ti) {
	if (!ti)
		return NULL;
	return ti->parent;
}

proto_item *
proto_item_get_parent_nth(proto_item *ti, int gen) {
	if (!ti)
		return NULL;
	while (gen--) {
		ti = ti->parent;
		if (!ti)
			return NULL;
	}
	return ti;
}


proto_item *
proto_tree_get_parent(const proto_tree *tree) {
	if (!tree)
		return NULL;
	return (proto_item *)tree;
}

proto_tree *
proto_tree_get_root(proto_tree *tree) {
	if (!tree)
		return NULL;
	while (tree->parent) {
		tree = tree->parent;
	}
	return tree;
}

void
proto_tree_move_item(proto_tree *tree, proto_item *fixed_item,
		     proto_item *item_to_move)
{

	/* Revert part of: http://anonsvn.wireshark.org/viewvc?view=rev&revision=32443
	 * See https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5500
	 */
	/* This function doesn't generate any values. It only reorganizes the prococol tree
	 * so we can bail out immediately if it isn't visible. */
	if (!tree || !PTREE_DATA(tree)->visible)
		return;

	DISSECTOR_ASSERT(item_to_move->parent == tree);
	DISSECTOR_ASSERT(fixed_item->parent == tree);

	/*** cut item_to_move out ***/

	/* is item_to_move the first? */
	if (tree->first_child == item_to_move) {
		/* simply change first child to next */
		tree->first_child = item_to_move->next;

		DISSECTOR_ASSERT(tree->last_child != item_to_move);
	} else {
		proto_item *curr_item;
		/* find previous and change it's next */
		for(curr_item = tree->first_child; curr_item != NULL; curr_item = curr_item->next) {
			if (curr_item->next == item_to_move) {
				break;
			}
		}

		DISSECTOR_ASSERT(curr_item);

		curr_item->next = item_to_move->next;

		/* fix last_child if required */
		if (tree->last_child == item_to_move) {
			tree->last_child = curr_item;
		}
	}

	/*** insert to_move after fixed ***/
	item_to_move->next = fixed_item->next;
	fixed_item->next = item_to_move;
	if (tree->last_child == fixed_item) {
		tree->last_child = item_to_move;
	}
}

void
proto_tree_set_appendix(proto_tree *tree, tvbuff_t *tvb, gint start,
			const gint length)
{
	field_info *fi;

	if (tree == NULL)
		return;

	fi = PTREE_FINFO(tree);
	if (fi == NULL)
		return;

	start += tvb_raw_offset(tvb);
	DISSECTOR_ASSERT(start >= 0);
	DISSECTOR_ASSERT(length >= 0);

	fi->appendix_start = start;
	fi->appendix_length = length;
}

int
proto_register_protocol(const char *name, const char *short_name,
			const char *filter_name)
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
	 * This is done by reducing the number of strcmp (and alike) calls
	 * as much as possible, as this significally slows down startup time.
	 *
	 * Drawback: As a hash value is used to reduce insert time,
	 * this might lead to a hash collision.
	 * However, although we have somewhat over 1000 protocols, we're using
	 * a 32 bit int so this is very, very unlikely.
	 */

	key  = g_malloc (sizeof(gint));
	*key = wrs_str_hash(name);

	existing_name = g_hash_table_lookup(proto_names, key);
	if (existing_name != NULL) {
		/* g_error will terminate the program */
		g_error("Duplicate protocol name \"%s\"!"
			" This might be caused by an inappropriate plugin or a development error.", name);
	}
	g_hash_table_insert(proto_names, key, (gpointer)name);

	existing_name = g_hash_table_lookup(proto_short_names, (gpointer)short_name);
	if (existing_name != NULL) {
		g_error("Duplicate protocol short_name \"%s\"!"
			" This might be caused by an inappropriate plugin or a development error.", short_name);
	}
	g_hash_table_insert(proto_short_names, (gpointer)short_name, (gpointer)short_name);

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
	existing_name = g_hash_table_lookup(proto_filter_names, (gpointer)filter_name);
	if (existing_name != NULL) {
		g_error("Duplicate protocol filter_name \"%s\"!"
			" This might be caused by an inappropriate plugin or a development error.", filter_name);
	}
	g_hash_table_insert(proto_filter_names, (gpointer)filter_name, (gpointer)filter_name);

	/* Add this protocol to the list of known protocols; the list
	   is sorted by protocol short name. */
	protocol = g_new(protocol_t, 1);
	protocol->name = name;
	protocol->short_name = short_name;
	protocol->filter_name = filter_name;
	protocol->fields = NULL;
	protocol->is_enabled = TRUE; /* protocol is enabled by default */
	protocol->can_toggle = TRUE;
	protocol->is_private = FALSE;
	/* list will be sorted later by name, when all protocols completed registering */
	protocols = g_list_prepend(protocols, protocol);

	/* Here we do allocate a new header_field_info struct */
	hfinfo = g_slice_new(header_field_info);
	hfinfo->name = name;
	hfinfo->abbrev = filter_name;
	hfinfo->type = FT_PROTOCOL;
	hfinfo->display = BASE_NONE;
	hfinfo->strings = protocol;
	hfinfo->bitmask = 0;
	hfinfo->bitshift = 0;
	hfinfo->ref_type = HF_REF_TYPE_NONE;
	hfinfo->blurb = NULL;
	hfinfo->parent = -1; /* this field differentiates protos and fields */

	proto_id = proto_register_field_init(hfinfo, hfinfo->parent);
	protocol->proto_id = proto_id;
	return proto_id;
}

void
proto_mark_private(const int proto_id)
{
	protocol_t *protocol = find_protocol_by_id(proto_id);
	if (protocol)
		protocol->is_private = TRUE;
}

gboolean
proto_is_private(const int proto_id)
{
	protocol_t *protocol = find_protocol_by_id(proto_id);
	if (protocol)
		return protocol->is_private;
	else
		return FALSE;
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
	GList      *list_item = *cookie;
	protocol_t *protocol;

	list_item = g_list_next(list_item);
	if (list_item == NULL)
		return -1;
	*cookie = list_item;
	protocol = list_item->data;
	return protocol->proto_id;
}

header_field_info *
proto_get_first_protocol_field(const int proto_id, void **cookie)
{
	protocol_t       *protocol = find_protocol_by_id(proto_id);
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
	GList            *list_item = *cookie;
	hf_register_info *ptr;

	list_item = g_list_next(list_item);
	if (list_item == NULL)
		return NULL;

	*cookie = list_item;
	ptr = list_item->data;
	return &ptr->hfinfo;
}

protocol_t *
find_protocol_by_id(const int proto_id)
{
	header_field_info *hfinfo;

	if (proto_id < 0)
		return NULL;

	PROTO_REGISTRAR_GET_NTH(proto_id, hfinfo);
	DISSECTOR_ASSERT(hfinfo->type == FT_PROTOCOL);
	return (protocol_t *)hfinfo->strings;
}

static gint compare_filter_name(gconstpointer proto_arg,
				gconstpointer filter_name)
{
	const protocol_t *protocol = proto_arg;
	const gchar      *f_name   = filter_name;

	return (strcmp(protocol->filter_name, f_name));
}

int
proto_get_id(const protocol_t *protocol)
{
	return protocol->proto_id;
}

int proto_get_id_by_filter_name(const gchar* filter_name)
{
	GList      *list_entry;
	protocol_t *protocol;

	list_entry = g_list_find_custom(protocols, filter_name,
		compare_filter_name);

	if (list_entry == NULL)
		return -1;
	protocol = list_entry->data;
	return protocol->proto_id;
}

const char *
proto_get_protocol_name(const int proto_id)
{
	protocol_t *protocol;

	protocol = find_protocol_by_id(proto_id);

	if (protocol == NULL)
		return NULL;
	return protocol->name;
}

const char *
proto_get_protocol_short_name(const protocol_t *protocol)
{
	if (protocol == NULL)
		return "(none)";
	return protocol->short_name;
}

const char *
proto_get_protocol_long_name(const protocol_t *protocol)
{
	if (protocol == NULL)
		return "(none)";
	return protocol->name;
}

const char *
proto_get_protocol_filter_name(const int proto_id)
{
	protocol_t *protocol;

	protocol = find_protocol_by_id(proto_id);
	if (protocol == NULL)
		return "(none)";
	return protocol->filter_name;
}

gboolean
proto_is_protocol_enabled(const protocol_t *protocol)
{
	return protocol->is_enabled;
}

gboolean
proto_can_toggle_protocol(const int proto_id)
{
	protocol_t *protocol;

	protocol = find_protocol_by_id(proto_id);
	return protocol->can_toggle;
}

void
proto_set_decoding(const int proto_id, const gboolean enabled)
{
	protocol_t *protocol;

	protocol = find_protocol_by_id(proto_id);
	DISSECTOR_ASSERT(protocol->can_toggle);
	protocol->is_enabled = enabled;
}

void
proto_enable_all(void)
{
	protocol_t *protocol;
	GList      *list_item = protocols;

	if (protocols == NULL)
		return;

	while (list_item) {
		protocol = list_item->data;
		if (protocol->can_toggle)
			protocol->is_enabled = TRUE;
		list_item = g_list_next(list_item);
	}
}

void
proto_set_cant_toggle(const int proto_id)
{
	protocol_t *protocol;

	protocol = find_protocol_by_id(proto_id);
	protocol->can_toggle = FALSE;
}

/* for use with static arrays only, since we don't allocate our own copies
of the header_field_info struct contained within the hf_register_info struct */
void
proto_register_field_array(const int parent, hf_register_info *hf, const int num_records)
{
	int		  field_id, i;
	hf_register_info *ptr = hf;
	protocol_t	 *proto;

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

/* unregister already registered fields */
void
proto_unregister_field (const int parent, gint hf_id)
{
	hf_register_info *hf;
	protocol_t       *proto;
	GList            *field;

	if (hf_id == -1 || hf_id == 0)
		return;

	proto = find_protocol_by_id (parent);
	if (!proto || !proto->fields) {
		return;
	}

	for (field = g_list_first (proto->fields); field; field = g_list_next (field)) {
		hf = field->data;
		if (*hf->p_id == hf_id) {
			/* Found the hf_id in this protocol */
			g_tree_steal (gpa_name_tree, hf->hfinfo.abbrev);
			proto->fields = g_list_remove_link (proto->fields, field);
			proto->last_field = g_list_last (proto->fields);
			break;
		}
	}
}

/* chars allowed in field abbrev */
static
const guchar fld_abbrev_chars[256] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x00-0x0F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x10-0x1F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, /* 0x20-0x2F '-', '.'	   */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, /* 0x30-0x3F '0'-'9'	   */
	0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 0x40-0x4F 'A'-'O'	   */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, /* 0x50-0x5F 'P'-'Z', '_' */
	0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 0x60-0x6F 'a'-'o'	   */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, /* 0x70-0x7F 'p'-'z'	   */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x80-0x8F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x90-0x9F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0xA0-0xAF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0xB0-0xBF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0xC0-0xCF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0xD0-0xDF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0xE0-0xEF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0xF0-0xFF */
};

/* temporary function containing assert part for easier profiling */
static void
tmp_fld_check_assert(header_field_info *hfinfo) {
	static const value_string hf_types[] = {
		{ FT_NONE,	    "FT_NONE"	       },
		{ FT_PROTOCOL,	    "FT_PROTOCOL"      },
		{ FT_BOOLEAN,	    "FT_BOOLEAN"       },
		{ FT_UINT8,	    "FT_UINT8"	       },
		{ FT_UINT16,	    "FT_UINT16"	       },
		{ FT_UINT24,	    "FT_UINT24"	       },
		{ FT_UINT32,	    "FT_UINT32"	       },
		{ FT_UINT64,	    "FT_UINT64"	       },
		{ FT_INT8,	    "FT_INT8"	       },
		{ FT_INT16,	    "FT_INT16"	       },
		{ FT_INT24,	    "FT_INT24"	       },
		{ FT_INT32,	    "FT_INT32"	       },
		{ FT_INT64,	    "FT_INT64"	       },
		{ FT_EUI64,	    "FT_EUI64"	       },
		{ FT_FLOAT,	    "FT_FLOAT"	       },
		{ FT_DOUBLE,	    "FT_DOUBLE"	       },
		{ FT_ABSOLUTE_TIME, "FT_ABSOLUTE_TIME" },
		{ FT_RELATIVE_TIME, "FT_RELATIVE_TIME" },
		{ FT_STRING,	    "FT_STRING"	       },
		{ FT_STRINGZ,	    "FT_STRINGZ"       },
		{ FT_UINT_STRING,   "FT_UINT_STRING"   },
		{ FT_ETHER,	    "FT_ETHER"	       },
		{ FT_BYTES,	    "FT_BYTES"	       },
		{ FT_UINT_BYTES,    "FT_UINT_BYTES"    },
		{ FT_IPv4,	    "FT_IPv4"	       },
		{ FT_IPv6,	    "FT_IPv6"	       },
		{ FT_IPXNET,	    "FT_IPXNET"	       },
		{ FT_FRAMENUM,	    "FT_FRAMENUM"      },
		{ FT_PCRE,	    "FT_PCR"	       },
		{ FT_GUID,	    "FT_GUID"	       },
		{ FT_OID,	    "FT_OID"	       },
		{ 0,		NULL } };

	static const value_string hf_display[] = {
		{ BASE_NONE,                      "BASE_NONE"			   },
		{ BASE_DEC,			  "BASE_DEC"			   },
		{ BASE_HEX,			  "BASE_HEX"			   },
		{ BASE_OCT,			  "BASE_OCT"			   },
		{ BASE_DEC_HEX,                   "BASE_DEC_HEX"		   },
		{ BASE_HEX_DEC,                   "BASE_HEX_DEC"		   },
		{ BASE_CUSTOM,                    "BASE_CUSTOM"			   },
		{ BASE_NONE|BASE_RANGE_STRING,    "BASE_NONE|BASE_RANGE_STRING"	   },
		{ BASE_DEC|BASE_RANGE_STRING,     "BASE_DEC|BASE_RANGE_STRING"	   },
		{ BASE_HEX|BASE_RANGE_STRING,     "BASE_HEX|BASE_RANGE_STRING"	   },
		{ BASE_OCT|BASE_RANGE_STRING,     "BASE_OCT|BASE_RANGE_STRING"	   },
		{ BASE_DEC_HEX|BASE_RANGE_STRING, "BASE_DEC_HEX|BASE_RANGE_STRING" },
		{ BASE_HEX_DEC|BASE_RANGE_STRING, "BASE_HEX_DEC|BASE_RANGE_STRING" },
		{ BASE_CUSTOM|BASE_RANGE_STRING,  "BASE_CUSTOM|BASE_RANGE_STRING"  },
		{ ABSOLUTE_TIME_LOCAL,            "ABSOLUTE_TIME_LOCAL"		   },
		{ ABSOLUTE_TIME_UTC,              "ABSOLUTE_TIME_UTC"		   },
		{ ABSOLUTE_TIME_DOY_UTC,	  "ABSOLUTE_TIME_DOY_UTC"	   },
		{ 0,				NULL } };

	/* The field must have a name (with length > 0) */
	if (!hfinfo->name || !hfinfo->name[0]) {
		if (hfinfo->abbrev)
			/* Try to identify the field */
			g_error("Field (abbrev='%s') does not have a name\n",
				hfinfo->abbrev);
		else
			/* Hum, no luck */
			g_error("Field does not have a name (nor an abbreviation)\n");
	}

	/* fields with an empty string for an abbreviation aren't filterable */
	if (!hfinfo->abbrev || !hfinfo->abbrev[0])
		g_error("Field '%s' does not have an abbreviation\n", hfinfo->name);

	/*  These types of fields are allowed to have value_strings,
	 *  true_false_strings or a protocol_t struct
	 */
	if (hfinfo->strings != NULL && !(
		    (hfinfo->type == FT_UINT8)    ||
		    (hfinfo->type == FT_UINT16)   ||
		    (hfinfo->type == FT_UINT24)   ||
		    (hfinfo->type == FT_UINT32)   ||
		    (hfinfo->type == FT_INT8)     ||
		    (hfinfo->type == FT_INT16)    ||
		    (hfinfo->type == FT_INT24)    ||
		    (hfinfo->type == FT_INT32)    ||
		    (hfinfo->type == FT_BOOLEAN)  ||
		    (hfinfo->type == FT_PROTOCOL) ||
		    (hfinfo->type == FT_FRAMENUM) ))
		g_error("Field '%s' (%s) has a 'strings' value but is of type %s"
			" (which is not allowed to have strings)\n",
			hfinfo->name, hfinfo->abbrev,
			val_to_str(hfinfo->type, hf_types, "(Unknown: %d)"));

	/* TODO: This check may slow down startup, and output quite a few warnings.
	   It would be good to be able to enable this (and possibly other checks?)
	   in non-release builds.   */
#if 0
	/* Check for duplicate value_string values.
	   There are lots that have the same value *and* string, so for now only
	   report those that have same value but different string. */
	if (hfinfo->strings != NULL &&
	    !(hfinfo->display & BASE_EXT_STRING) &&
	    !(hfinfo->display & BASE_RANGE_STRING) &&
	    !(hfinfo->display & BASE_CUSTOM) &&
	    (
		    (hfinfo->type == FT_UINT8)  ||
		    (hfinfo->type == FT_UINT16) ||
		    (hfinfo->type == FT_UINT24) ||
		    (hfinfo->type == FT_UINT32) ||
		    (hfinfo->type == FT_INT8)   ||
		    (hfinfo->type == FT_INT16)  ||
		    (hfinfo->type == FT_INT24)  ||
		    (hfinfo->type == FT_INT32)  ||
		    (hfinfo->type == FT_FRAMENUM) )) {

		int n, m;
		value_string *start_values = (value_string*)hfinfo->strings;
		value_string *current = start_values;

		for (n=0; current; n++, current++) {
			/* Drop out if we reached the end. */
			if ((current->value == 0) && (current->strptr == NULL)) {
				break;
			}

			/* Check value against all previous */
			for (m=0; m < n; m++) {
				/* There are lots of duplicates with the same string,
				   so only report if different... */
				if ((start_values[m].value == current->value) &&
				    (strcmp(start_values[m].strptr, current->strptr) != 0)) {
					g_warning("Field '%s' (%s) has a conflicting entry in its"
                                                  " value_string: %u is at indices %u (%s) and %u (%s))\n",
						  hfinfo->name, hfinfo->abbrev,
						  current->value, m, start_values[m].strptr, n, current->strptr);
				}
			}
		}
	}
#endif


	switch (hfinfo->type) {

		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
		case FT_INT64:
			/*	Hexadecimal and octal are, in printf() and everywhere
			 *	else, unsigned so don't allow dissectors to register a
			 *	signed field to be displayed unsigned.  (Else how would
			 *	we display negative values?)
			 *
			 *	If you want to take out this check, be sure to fix
			 *	hfinfo_numeric_format() so that it does not assert out
			 *	when trying to construct a hexadecimal representation of
			 *	FT_INT*.
			 */
			if (hfinfo->display == BASE_HEX ||
			    hfinfo->display == BASE_OCT)
				g_error("Field '%s' (%s) is signed (%s) but is being displayed unsigned (%s)\n",
					hfinfo->name, hfinfo->abbrev,
					val_to_str(hfinfo->type, hf_types, "(Unknown: %d)"),
					val_to_str(hfinfo->display, hf_display, "(Bit count: %d)"));
			/* FALL THROUGH */
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
		case FT_UINT64:
			if (hfinfo->strings == NULL) {
				/*  Require integral types (other than frame number,
				 *  which is always displayed in decimal) to have a
				 *  number base */
				if (hfinfo->display == BASE_NONE)
					g_error("Field '%s' (%s) is an integral value (%s)"
                                                " without strings but is being displayed as BASE_NONE\n",
						hfinfo->name, hfinfo->abbrev,
						val_to_str(hfinfo->type, hf_types, "(Unknown: %d)"));
			}
			break;

		case FT_PROTOCOL:
		case FT_FRAMENUM:
			if (hfinfo->display != BASE_NONE)
				g_error("Field '%s' (%s) is an %s but is being displayed as %s instead of BASE_NONE\n",
					hfinfo->name, hfinfo->abbrev,
					val_to_str(hfinfo->type, hf_types, "(Unknown: %d)"),
					val_to_str(hfinfo->display, hf_display, "(Bit count: %d)"));
			if (hfinfo->bitmask != 0)
				g_error("Field '%s' (%s) is an %s but has a bitmask\n",
					hfinfo->name, hfinfo->abbrev,
					val_to_str(hfinfo->type, hf_types, "(Unknown: %d)"));
			break;

		case FT_BOOLEAN:
			break;

		case FT_ABSOLUTE_TIME:
			if (!(hfinfo->display == ABSOLUTE_TIME_LOCAL ||
			      hfinfo->display == ABSOLUTE_TIME_UTC   ||
			      hfinfo->display == ABSOLUTE_TIME_DOY_UTC))
				g_error("Field '%s' (%s) is a %s but is being displayed as %s instead of as a time\n",
					hfinfo->name, hfinfo->abbrev,
					val_to_str(hfinfo->type, hf_types, "(Unknown: %d)"),
					val_to_str(hfinfo->display, hf_display, "(Bit count: %d)"));
			if (hfinfo->bitmask != 0)
				g_error("Field '%s' (%s) is an %s but has a bitmask\n",
					hfinfo->name, hfinfo->abbrev,
					val_to_str(hfinfo->type, hf_types, "(Unknown: %d)"));
			break;

		default:
			if (hfinfo->display != BASE_NONE)
				g_error("Field '%s' (%s) is an %s but is being displayed as %s instead of BASE_NONE\n",
					hfinfo->name, hfinfo->abbrev,
					val_to_str(hfinfo->type, hf_types, "(Unknown: %d)"),
					val_to_str(hfinfo->display, hf_display, "(Bit count: %d)"));
			if (hfinfo->bitmask != 0)
				g_error("Field '%s' (%s) is an %s but has a bitmask\n",
					hfinfo->name, hfinfo->abbrev,
					val_to_str(hfinfo->type, hf_types, "(Unknown: %d)"));
			if (hfinfo->strings != NULL)
				g_error("Field '%s' (%s) is an %s but has a strings value\n",
					hfinfo->name, hfinfo->abbrev,
					val_to_str(hfinfo->type, hf_types, "(Unknown: %d)"));
			break;
	}
}

#define PROTO_PRE_ALLOC_HF_FIELDS_MEM 120000
static int
proto_register_field_init(header_field_info *hfinfo, const int parent)
{

	tmp_fld_check_assert(hfinfo);

	/* if this is a bitfield, compute bitshift */
	if (hfinfo->bitmask) {
		hfinfo->bitshift = wrs_count_bitshift(hfinfo->bitmask);
	}

	hfinfo->parent         = parent;
	hfinfo->same_name_next = NULL;
	hfinfo->same_name_prev = NULL;

	/* if we always add and never delete, then id == len - 1 is correct */
	if (gpa_hfinfo.len >= gpa_hfinfo.allocated_len) {
		if (!gpa_hfinfo.hfi) {
			gpa_hfinfo.allocated_len = PROTO_PRE_ALLOC_HF_FIELDS_MEM;
			gpa_hfinfo.hfi = g_malloc(sizeof(header_field_info *)*PROTO_PRE_ALLOC_HF_FIELDS_MEM);
		} else {
			gpa_hfinfo.allocated_len += 1000;
			gpa_hfinfo.hfi = g_realloc(gpa_hfinfo.hfi,
						   sizeof(header_field_info *)*gpa_hfinfo.allocated_len);
			/*g_warning("gpa_hfinfo.allocated_len %u", gpa_hfinfo.allocated_len);*/
		}
	}
	gpa_hfinfo.hfi[gpa_hfinfo.len] = hfinfo;
	gpa_hfinfo.len++;
	hfinfo->id = gpa_hfinfo.len - 1;

	/* if we have real names, enter this field in the name tree */
	if ((hfinfo->name[0] != 0) && (hfinfo->abbrev[0] != 0 )) {

		header_field_info *same_name_next_hfinfo;
		guchar c;

		/* Check that the filter name (abbreviation) is legal;
		 * it must contain only alphanumerics, '-', "_", and ".". */
		c = wrs_check_charset(fld_abbrev_chars, hfinfo->abbrev);
		if (c) {
			fprintf(stderr, "Invalid character '%c' in filter name '%s'\n", c, hfinfo->abbrev);
			DISSECTOR_ASSERT(!c);
		}

		/* We allow multiple hfinfo's to be registered under the same
		 * abbreviation. This was done for X.25, as, depending
		 * on whether it's modulo-8 or modulo-128 operation,
		 * some bitfield fields may be in different bits of
		 * a byte, and we want to be able to refer to that field
		 * with one name regardless of whether the packets
		 * are modulo-8 or modulo-128 packets. */

		same_name_hfinfo = NULL;

		g_tree_insert(gpa_name_tree, (gpointer) (hfinfo->abbrev), hfinfo);
		/* GLIB 2.x - if it is already present
		 * the previous hfinfo with the same name is saved
		 * to same_name_hfinfo by value destroy callback */
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
	}

	return hfinfo->id;
}

void
proto_register_subtree_array(gint *const *indices, const int num_indices)
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
				  (num_tree_types + num_indices)*sizeof (gboolean));
		memset(tree_is_expanded + num_tree_types, 0,
		       num_indices*sizeof (gboolean));
	}

	/*
	 * Assign "num_indices" subtree numbers starting at "num_tree_types",
	 * returning the indices through the pointers in the array whose
	 * first element is pointed to by "indices", and update
	 * "num_tree_types" appropriately.
	 */
	for (i = 0; i < num_indices; i++, ptr++, num_tree_types++) {
		if (**ptr != -1) {
			/* g_error will terminate the program */
			g_error("register_subtree_array: subtree item type (ett_...) not -1 !"
				" This is a development error:"
				" Either the subtree item type has already been assigned or"
				" was not initialized to -1.");
		}
		**ptr = num_tree_types;
	}
}

void
proto_item_fill_label(field_info *fi, gchar *label_str)
{
	header_field_info *hfinfo;
	guint8		  *bytes;
	guint32		   integer;
	guint64		   integer64;
	ipv4_addr	  *ipv4;
	e_guid_t	  *guid;
	guint32		   n_addr; /* network-order IPv4 address */
	const gchar	  *name;
	int		   ret;	   /*tmp return value */

	if (!fi) {
		if (label_str)
			label_str[0]= '\0';
		/* XXX: Check validity of hfinfo->type */
		return;
	}

	hfinfo = fi->hfinfo;

	switch (hfinfo->type) {
		case FT_NONE:
		case FT_PROTOCOL:
			g_strlcpy(label_str, hfinfo->name, ITEM_LABEL_LENGTH);
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
				if (ret >= ITEM_LABEL_LENGTH) {
					/* Uh oh, we don't have enough room.  Tell the
					 *	user that the field is truncated.
					 */
					g_snprintf(label_str, ITEM_LABEL_LENGTH,
						   "%s [truncated]: %s",
						   hfinfo->name,
						   bytes_to_str(bytes, fvalue_length(&fi->value)));
				}
			}
			else {
				g_snprintf(label_str, ITEM_LABEL_LENGTH, "%s: <MISSING>", hfinfo->name);
			}
			break;

		/* Four types of integers to take care of:
		 *	Bitfield, with val_string
		 *	Bitfield, w/o val_string
		 *	Non-bitfield, with val_string
		 *	Non-bitfield, w/o val_string
		 */
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
			if (hfinfo->bitmask) {
				fill_label_bitfield(fi, label_str);
			} else {
				fill_label_uint(fi, label_str);
			}
			break;

		case FT_FRAMENUM:
			fill_label_uint(fi, label_str);
			break;

		case FT_UINT64:
			fill_label_uint64(fi, label_str);
			break;

		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
			DISSECTOR_ASSERT(!hfinfo->bitmask);
			fill_label_int(fi, label_str);
			break;

		case FT_INT64:
			fill_label_int64(fi, label_str);
			break;

		case FT_FLOAT:
			g_snprintf(label_str, ITEM_LABEL_LENGTH,
				   "%s: %." STRINGIFY(FLT_DIG) "g",
				   hfinfo->name, fvalue_get_floating(&fi->value));
			break;

		case FT_DOUBLE:
			g_snprintf(label_str, ITEM_LABEL_LENGTH,
				   "%s: %." STRINGIFY(DBL_DIG) "g",
				   hfinfo->name, fvalue_get_floating(&fi->value));
			break;

		case FT_ABSOLUTE_TIME:
			g_snprintf(label_str, ITEM_LABEL_LENGTH,
				   "%s: %s", hfinfo->name,
				   abs_time_to_str(fvalue_get(&fi->value), hfinfo->display, TRUE));
			break;

		case FT_RELATIVE_TIME:
			g_snprintf(label_str, ITEM_LABEL_LENGTH,
				   "%s: %s seconds", hfinfo->name,
				   rel_time_to_secs_str(fvalue_get(&fi->value)));
			break;

		case FT_IPXNET:
			integer = fvalue_get_uinteger(&fi->value);
			g_snprintf(label_str, ITEM_LABEL_LENGTH,
				   "%s: %s (0x%08X)", hfinfo->name,
				   get_ipxnet_name(integer), integer);
			break;

		case FT_ETHER:
			bytes = fvalue_get(&fi->value);
			g_snprintf(label_str, ITEM_LABEL_LENGTH,
				   "%s: %s (%s)", hfinfo->name,
				   get_ether_name(bytes),
				   ether_to_str(bytes));
			break;

		case FT_IPv4:
			ipv4 = fvalue_get(&fi->value);
			n_addr = ipv4_get_net_order_addr(ipv4);
			g_snprintf(label_str, ITEM_LABEL_LENGTH,
				   "%s: %s (%s)", hfinfo->name,
				   get_hostname(n_addr),
				   ip_to_str((guint8*)&n_addr));
			break;

		case FT_IPv6:
			bytes = fvalue_get(&fi->value);
			g_snprintf(label_str, ITEM_LABEL_LENGTH,
				   "%s: %s (%s)", hfinfo->name,
				   get_hostname6((struct e_in6_addr *)bytes),
				   ip6_to_str((struct e_in6_addr*)bytes));
			break;

		case FT_GUID:
			guid = fvalue_get(&fi->value);
			g_snprintf(label_str, ITEM_LABEL_LENGTH,
				   "%s: %s", hfinfo->name,
				    guid_to_str(guid));
			break;

		case FT_OID:
			bytes = fvalue_get(&fi->value);
			name = oid_resolved_from_encoded(bytes, fvalue_length(&fi->value));
			if (name) {
				g_snprintf(label_str, ITEM_LABEL_LENGTH,
					"%s: %s (%s)", hfinfo->name,
					 oid_encoded2string(bytes, fvalue_length(&fi->value)), name);
			} else {
				g_snprintf(label_str, ITEM_LABEL_LENGTH,
					"%s: %s", hfinfo->name,
					 oid_encoded2string(bytes, fvalue_length(&fi->value)));
			}
			break;
		case FT_EUI64:
			integer64 = fvalue_get_integer64(&fi->value);
			g_snprintf(label_str, ITEM_LABEL_LENGTH,
				   "%s: %s (%s)", hfinfo->name,
				   get_eui64_name(integer64),
				   eui64_to_str(integer64));
			break;
		case FT_STRING:
		case FT_STRINGZ:
		case FT_UINT_STRING:
			bytes = fvalue_get(&fi->value);
			ret = g_snprintf(label_str, ITEM_LABEL_LENGTH,
					 "%s: %s", hfinfo->name,
					 format_text(bytes, strlen(bytes)));
			if (ret >= ITEM_LABEL_LENGTH) {
				/* Uh oh, we don't have enough room.  Tell the
				 *	user that the field is truncated.
				 */
				g_snprintf(label_str, ITEM_LABEL_LENGTH,
					   "%s [truncated]: %s", hfinfo->name,
					   format_text(bytes, strlen(bytes)));
			}
			break;

		default:
			g_error("hfinfo->type %d (%s) not handled\n",
				hfinfo->type, ftype_name(hfinfo->type));
			DISSECTOR_ASSERT_NOT_REACHED();
			break;
	}
}

static void
fill_label_boolean(field_info *fi, gchar *label_str)
{
	char	*p                    = label_str;
	int      bitfield_byte_length = 0, bitwidth;
	guint32  unshifted_value;
	guint32  value;

	header_field_info	*hfinfo   = fi->hfinfo;
	const true_false_string	*tfstring = (const true_false_string *)&tfs_true_false;

	if (hfinfo->strings) {
		tfstring = (const struct true_false_string*) hfinfo->strings;
	}

	value = fvalue_get_uinteger(&fi->value);
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
		bitfield_byte_length = (int) (p - label_str);
	}

	/* Fill in the textual info */
	g_snprintf(p, ITEM_LABEL_LENGTH - bitfield_byte_length,
		   "%s: %s",  hfinfo->name,
		   value ? tfstring->true_string : tfstring->false_string);
}

/* Fills data for bitfield ints with val_strings */
static void
fill_label_bitfield(field_info *fi, gchar *label_str)
{
	const char *format = NULL;
	char       *p;
	int         bitfield_byte_length, bitwidth;
	guint32     unshifted_value;
	guint32     value;

	header_field_info *hfinfo = fi->hfinfo;

	/* Figure out the bit width */
	bitwidth = hfinfo_bitwidth(hfinfo);

	/* Un-shift bits */
	unshifted_value = fvalue_get_uinteger(&fi->value);
	value = unshifted_value;
	if (hfinfo->bitshift > 0) {
		unshifted_value <<= hfinfo->bitshift;
	}

	/* Create the bitfield first */
	p = decode_bitfield_value(label_str, unshifted_value, hfinfo->bitmask, bitwidth);
	bitfield_byte_length = (int) (p - label_str);

	/* Fill in the textual info using stored (shifted) value */
	if (hfinfo->display == BASE_CUSTOM) {
		gchar tmp[ITEM_LABEL_LENGTH];
		custom_fmt_func_t fmtfunc = (custom_fmt_func_t)hfinfo->strings;

		DISSECTOR_ASSERT(fmtfunc);
		fmtfunc(tmp, value);
		g_snprintf(p, ITEM_LABEL_LENGTH - bitfield_byte_length,
			   "%s: %s", hfinfo->name, tmp);
	}
	else if (hfinfo->strings) {
		format = hfinfo_uint_vals_format(hfinfo);
		if (hfinfo->display & BASE_RANGE_STRING) {
			g_snprintf(p, ITEM_LABEL_LENGTH - bitfield_byte_length,
				   format,  hfinfo->name,
				   rval_to_str(value, hfinfo->strings, "Unknown"), value);
		} else if (hfinfo->display & BASE_EXT_STRING) {
			g_snprintf(p, ITEM_LABEL_LENGTH - bitfield_byte_length,
				 format,  hfinfo->name,
				 val_to_str_ext_const(value, (value_string_ext *) hfinfo->strings, "Unknown"), value);
		} else {
			g_snprintf(p, ITEM_LABEL_LENGTH - bitfield_byte_length,
				   format,  hfinfo->name,
				   val_to_str_const(value, cVALS(hfinfo->strings), "Unknown"), value);
		}
	}
	else {
		format = hfinfo_uint_format(hfinfo);
		if (IS_BASE_DUAL(hfinfo->display)) {
			g_snprintf(p, ITEM_LABEL_LENGTH - bitfield_byte_length,
				   format,  hfinfo->name, value, value);
		} else {
			g_snprintf(p, ITEM_LABEL_LENGTH - bitfield_byte_length,
				   format,  hfinfo->name, value);
		}
	}
}

static void
fill_label_uint(field_info *fi, gchar *label_str)
{
	const char        *format = NULL;
	header_field_info *hfinfo = fi->hfinfo;
	guint32            value;

	value = fvalue_get_uinteger(&fi->value);

	/* Fill in the textual info */
	if (hfinfo->display == BASE_CUSTOM) {
		gchar tmp[ITEM_LABEL_LENGTH];
		custom_fmt_func_t fmtfunc = (custom_fmt_func_t)hfinfo->strings;

		DISSECTOR_ASSERT(fmtfunc);
		fmtfunc(tmp, value);
		g_snprintf(label_str, ITEM_LABEL_LENGTH, "%s: %s", hfinfo->name, tmp);
	}
	else if (hfinfo->strings) {
		format = hfinfo_uint_vals_format(hfinfo);
		if (hfinfo->display & BASE_RANGE_STRING) {
			g_snprintf(label_str, ITEM_LABEL_LENGTH,
				   format,  hfinfo->name,
				   rval_to_str(value, hfinfo->strings, "Unknown"), value);
		} else if (hfinfo->display & BASE_EXT_STRING) {
			g_snprintf(label_str, ITEM_LABEL_LENGTH,
				 format,  hfinfo->name,
				 val_to_str_ext_const(value, (value_string_ext *) hfinfo->strings, "Unknown"), value);
		} else {
			g_snprintf(label_str, ITEM_LABEL_LENGTH,
				   format,  hfinfo->name,
				   val_to_str_const(value, cVALS(hfinfo->strings), "Unknown"), value);
		}
	}
	else {
		format = hfinfo_uint_format(hfinfo);
		if (IS_BASE_DUAL(hfinfo->display)) {
			g_snprintf(label_str, ITEM_LABEL_LENGTH,
				   format,  hfinfo->name, value, value);
		} else {
			g_snprintf(label_str, ITEM_LABEL_LENGTH,
				   format,  hfinfo->name, value);
		}
	}
}

static void
fill_label_uint64(field_info *fi, gchar *label_str)
{
	const char        *format = NULL;
	header_field_info *hfinfo = fi->hfinfo;
	guint64            value;

	/* Pick the proper format string */
	format = hfinfo_uint64_format(hfinfo);
	value  = fvalue_get_integer64(&fi->value);

	/* Fill in the textual info */
	if (IS_BASE_DUAL(hfinfo->display)) {
		g_snprintf(label_str, ITEM_LABEL_LENGTH,
			   format,  hfinfo->name, value, value);
	} else {
		g_snprintf(label_str, ITEM_LABEL_LENGTH,
			   format,  hfinfo->name, value);
	}
}

static void
fill_label_int(field_info *fi, gchar *label_str)
{
	const char        *format = NULL;
	header_field_info *hfinfo = fi->hfinfo;
	guint32            value;

	value = fvalue_get_sinteger(&fi->value);

	/* Fill in the textual info */
	if (hfinfo->display == BASE_CUSTOM) {
		gchar tmp[ITEM_LABEL_LENGTH];
		custom_fmt_func_t fmtfunc = (custom_fmt_func_t)hfinfo->strings;

		DISSECTOR_ASSERT(fmtfunc);
		fmtfunc(tmp, value);
		g_snprintf(label_str, ITEM_LABEL_LENGTH, "%s: %s", hfinfo->name, tmp);
	}
	else if (hfinfo->strings) {
		format = hfinfo_int_vals_format(hfinfo);
		if (hfinfo->display & BASE_RANGE_STRING) {
			g_snprintf(label_str, ITEM_LABEL_LENGTH,
				   format,  hfinfo->name,
				   rval_to_str(value, hfinfo->strings, "Unknown"), value);
		} else if (hfinfo->display & BASE_EXT_STRING) {
			g_snprintf(label_str, ITEM_LABEL_LENGTH,
				 format,  hfinfo->name,
				 val_to_str_ext_const(value, (value_string_ext *) hfinfo->strings, "Unknown"), value);
		} else {
			g_snprintf(label_str, ITEM_LABEL_LENGTH,
				   format,  hfinfo->name,
				   val_to_str_const(value, cVALS(hfinfo->strings), "Unknown"), value);
		}
	}
	else {
		format = hfinfo_int_format(hfinfo);
		if (IS_BASE_DUAL(hfinfo->display)) {
			g_snprintf(label_str, ITEM_LABEL_LENGTH,
				   format,  hfinfo->name, value, value);
		} else {
			g_snprintf(label_str, ITEM_LABEL_LENGTH,
				   format,  hfinfo->name, value);
		}
	}
}

static void
fill_label_int64(field_info *fi, gchar *label_str)
{
	const char        *format = NULL;
	header_field_info *hfinfo = fi->hfinfo;
	guint64            value;

	/* Pick the proper format string */
	format = hfinfo_int64_format(hfinfo);
	value  = fvalue_get_integer64(&fi->value);

	/* Fill in the textual info */
	if (IS_BASE_DUAL(hfinfo->display)) {
		g_snprintf(label_str, ITEM_LABEL_LENGTH,
			   format,  hfinfo->name, value, value);
	} else {
		g_snprintf(label_str, ITEM_LABEL_LENGTH,
			   format,  hfinfo->name, value);
	}
}

int
hfinfo_bitwidth(const header_field_info *hfinfo)
{
	int bitwidth = 0;

	if (!hfinfo->bitmask) {
		return 0;
	}

	switch (hfinfo->type) {
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

static const char *
hfinfo_uint_vals_format(const header_field_info *hfinfo)
{
	const char *format = NULL;

	/* Get the underlying BASE_ value */
	switch (hfinfo->display & BASE_DISPLAY_E_MASK) {
		case BASE_NONE:
			format = "%s: %s";
			break;
		case BASE_DEC:
		case BASE_DEC_HEX:
			format = "%s: %s (%u)";
			break;
		case BASE_OCT: /* I'm lazy */
			format = "%s: %s (%#o)";
			break;
		case BASE_HEX:
		case BASE_HEX_DEC:
			switch (hfinfo->type) {
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

static const char *
hfinfo_uint_format(const header_field_info *hfinfo)
{
	const char *format = NULL;

	/* Pick the proper format string */
	if (hfinfo->type == FT_FRAMENUM) {
		/*
		 * Frame numbers are always displayed in decimal.
		 */
		format = "%s: %u";
	} else {
		switch (hfinfo->display) {
			case BASE_DEC:
				format = "%s: %u";
				break;
			case BASE_DEC_HEX:
				switch (hfinfo->type) {
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
				format = "%s: %#o";
				break;
			case BASE_HEX:
				switch (hfinfo->type) {
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
				switch (hfinfo->type) {
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

static const char *
hfinfo_uint_value_format(const header_field_info *hfinfo)
{
	const char *format = NULL;

	/* Pick the proper format string */
	if (hfinfo->type == FT_FRAMENUM) {
		/*
		 * Frame numbers are always displayed in decimal.
		 */
		format = "%u";
	} else {
		switch (hfinfo->display) {
			case BASE_DEC:
				format = "%u";
				break;
			case BASE_DEC_HEX:
				switch (hfinfo->type) {
					case FT_UINT8:
						format = "%u (0x%02x)";
						break;
					case FT_UINT16:
						format = "%u (0x%04x)";
						break;
					case FT_UINT24:
						format = "%u (0x%06x)";
						break;
					case FT_UINT32:
						format = "%u (0x%08x)";
						break;
					default:
						DISSECTOR_ASSERT_NOT_REACHED();
						;
				}
				break;
			case BASE_OCT:
				format = "%#o";
				break;
			case BASE_HEX:
				switch (hfinfo->type) {
					case FT_UINT8:
						format = "0x%02x";
						break;
					case FT_UINT16:
						format = "0x%04x";
						break;
					case FT_UINT24:
						format = "0x%06x";
						break;
					case FT_UINT32:
						format = "0x%08x";
						break;
					default:
						DISSECTOR_ASSERT_NOT_REACHED();
						;
				}
				break;
			case BASE_HEX_DEC:
				switch (hfinfo->type) {
					case FT_UINT8:
						format = "0x%02x (%u)";
						break;
					case FT_UINT16:
						format = "0x%04x (%u)";
						break;
					case FT_UINT24:
						format = "0x%06x (%u)";
						break;
					case FT_UINT32:
						format = "0x%08x (%u)";
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

static const char *
hfinfo_int_vals_format(const header_field_info *hfinfo)
{
	const char *format = NULL;

	/* Get the underlying BASE_ value */
	switch (hfinfo->display & BASE_DISPLAY_E_MASK) {
		case BASE_NONE:
			format = "%s: %s";
			break;
		case BASE_DEC:
		case BASE_DEC_HEX:
			format = "%s: %s (%d)";
			break;
		case BASE_OCT: /* I'm lazy */
			format = "%s: %s (%#o)";
			break;
		case BASE_HEX:
		case BASE_HEX_DEC:
			switch (hfinfo->type) {
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

static const char *
hfinfo_uint64_format(const header_field_info *hfinfo)
{
	const char *format = NULL;

	/* Pick the proper format string */
	switch (hfinfo->display) {
		case BASE_DEC:
			format = "%s: %" G_GINT64_MODIFIER "u";
			break;
		case BASE_DEC_HEX:
			format = "%s: %" G_GINT64_MODIFIER "u (0x%016" G_GINT64_MODIFIER "x)";
			break;
		case BASE_OCT: /* I'm lazy */
			format = "%s: %#" G_GINT64_MODIFIER "o";
			break;
		case BASE_HEX:
			format = "%s: 0x%016" G_GINT64_MODIFIER "x";
			break;
		case BASE_HEX_DEC:
			format = "%s: 0x%016" G_GINT64_MODIFIER "x (%" G_GINT64_MODIFIER "u)";
			break;
		default:
			DISSECTOR_ASSERT_NOT_REACHED();
			;
	}
	return format;
}

static const char *
hfinfo_int_format(const header_field_info *hfinfo)
{
	const char *format = NULL;

	/* Pick the proper format string */
	switch (hfinfo->display) {
		case BASE_DEC:
			format = "%s: %d";
			break;
		case BASE_DEC_HEX:
			switch (hfinfo->type) {
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
			break;
		case BASE_OCT: /* I'm lazy */
			format = "%s: %#o";
			break;
		case BASE_HEX:
			switch (hfinfo->type) {
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
			switch (hfinfo->type) {
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

static const char *
hfinfo_int_value_format(const header_field_info *hfinfo)
{
	const char *format = NULL;

	/* Pick the proper format string */
	switch (hfinfo->display) {
		case BASE_DEC:
			format = "%d";
			break;
		case BASE_DEC_HEX:
			switch (hfinfo->type) {
				case FT_INT8:
					format = "%d (0x%02x)";
					break;
				case FT_INT16:
					format = "%d (0x%04x)";
					break;
				case FT_INT24:
					format = "%d (0x%06x)";
					break;
				case FT_INT32:
					format = "%d (0x%08x)";
					break;
				default:
					DISSECTOR_ASSERT_NOT_REACHED();
					;
			}
			break;
		case BASE_OCT:
			format = "%#o";
			break;
		case BASE_HEX:
			switch (hfinfo->type) {
				case FT_INT8:
					format = "0x%02x";
					break;
				case FT_INT16:
					format = "0x%04x";
					break;
				case FT_INT24:
					format = "0x%06x";
					break;
				case FT_INT32:
					format = "0x%08x";
					break;
				default:
					DISSECTOR_ASSERT_NOT_REACHED();
					;
			}
			break;
		case BASE_HEX_DEC:
			switch (hfinfo->type) {
				case FT_INT8:
					format = "0x%02x (%d)";
					break;
				case FT_INT16:
					format = "0x%04x (%d)";
					break;
				case FT_INT24:
					format = "0x%06x (%d)";
					break;
				case FT_INT32:
					format = "0x%08x (%d)";
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

static const char *
hfinfo_int64_format(const header_field_info *hfinfo)
{
	const char *format = NULL;

	/* Pick the proper format string */
	switch (hfinfo->display) {
		case BASE_DEC:
			format = "%s: %" G_GINT64_MODIFIER "d";
			break;
		case BASE_DEC_HEX:
			format = "%s: %" G_GINT64_MODIFIER "d (0x%016" G_GINT64_MODIFIER "x)";
			break;
		case BASE_OCT: /* I'm lazy */
			format = "%s: %#" G_GINT64_MODIFIER "o";
			break;
		case BASE_HEX:
			format = "%s: 0x%016" G_GINT64_MODIFIER "x";
			break;
		case BASE_HEX_DEC:
			format = "%s: 0x%016" G_GINT64_MODIFIER "x (%" G_GINT64_MODIFIER "d)";
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

const char *
proto_registrar_get_name(const int n)
{
	header_field_info *hfinfo;

	PROTO_REGISTRAR_GET_NTH(n, hfinfo);
	return hfinfo->name;
}

const char *
proto_registrar_get_abbrev(const int n)
{
	header_field_info *hfinfo;

	PROTO_REGISTRAR_GET_NTH(n, hfinfo);
	return hfinfo->abbrev;
}

int
proto_registrar_get_ftype(const int n)
{
	header_field_info *hfinfo;

	PROTO_REGISTRAR_GET_NTH(n, hfinfo);
	return hfinfo->type;
}

int
proto_registrar_get_parent(const int n)
{
	header_field_info *hfinfo;

	PROTO_REGISTRAR_GET_NTH(n, hfinfo);
	return hfinfo->parent;
}

gboolean
proto_registrar_is_protocol(const int n)
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
proto_registrar_get_length(const int n)
{
	header_field_info *hfinfo;

	PROTO_REGISTRAR_GET_NTH(n, hfinfo);
	return ftype_length(hfinfo->type);
}

/* Looks for a protocol or a field in a proto_tree. Returns TRUE if
 * it exists anywhere, or FALSE if it exists nowhere. */
gboolean
proto_check_for_protocol_or_field(const proto_tree* tree, const int id)
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
GPtrArray *
proto_get_finfo_ptr_array(const proto_tree *tree, const int id)
{
	if (!tree)
		return NULL;

	if (PTREE_DATA(tree)->interesting_hfids != NULL)
		return g_hash_table_lookup(PTREE_DATA(tree)->interesting_hfids,
					   GINT_TO_POINTER(id));
	else
		return NULL;
}

gboolean
proto_tracking_interesting_fields(const proto_tree *tree)
{
	if (!tree)
		return FALSE;

	return (PTREE_DATA(tree)->interesting_hfids != NULL);
}

/* Helper struct for proto_find_info() and	proto_all_finfos() */
typedef struct {
	GPtrArray *array;
	int	   id;
} ffdata_t;

/* Helper function for proto_find_info() */
static gboolean
find_finfo(proto_node *node, gpointer data)
{
	field_info *fi = PNODE_FINFO(node);
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
* g_ptr_array_free(<array>, TRUE).
*/
GPtrArray *
proto_find_finfo(proto_tree *tree, const int id)
{
	ffdata_t ffdata;

	ffdata.array = g_ptr_array_new();
	ffdata.id = id;

	proto_tree_traverse_pre_order(tree, find_finfo, &ffdata);

	return ffdata.array;
}

/* Helper function for proto_all_finfos() */
static gboolean
every_finfo(proto_node *node, gpointer data)
{
	field_info *fi = PNODE_FINFO(node);
	if (fi && fi->hfinfo) {
		g_ptr_array_add(((ffdata_t*)data)->array, fi);
	}

	/* Don't stop traversing. */
	return FALSE;
}

/* Return GPtrArray* of field_info pointers containing all hfindexes that appear in a tree. */
GPtrArray *
proto_all_finfos(proto_tree *tree)
{
	ffdata_t ffdata;

	ffdata.array = g_ptr_array_new();
	ffdata.id = 0;

	proto_tree_traverse_pre_order(tree, every_finfo, &ffdata);

	return ffdata.array;
}


typedef struct {
	guint	    offset;
	field_info *finfo;
	tvbuff_t   *tvb;
} offset_search_t;

static gboolean
check_for_offset(proto_node *node, const gpointer data)
{
	field_info	*fi        = PNODE_FINFO(node);
	offset_search_t	*offsearch = data;

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
field_info *
proto_find_field_from_offset(proto_tree *tree, guint offset, tvbuff_t *tvb)
{
	offset_search_t	offsearch;

	offsearch.offset = offset;
	offsearch.finfo  = NULL;
	offsearch.tvb    = tvb;

	proto_tree_traverse_pre_order(tree, check_for_offset, &offsearch);

	return offsearch.finfo;
}

/* Dumps the protocols in the registration database to stdout.	An independent
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
	protocol_t *protocol;
	int	    i;
	void	   *cookie = NULL;

	for (i = proto_get_first_protocol(&cookie); i != -1;
		i = proto_get_next_protocol(&cookie)) {
		protocol = find_protocol_by_id(i);
		printf("%s\t%s\t%s\n", protocol->name, protocol->short_name,
			protocol->filter_name);
	}
}

/* Dumps the value_strings, extended value string headers, range_strings
 * or true/false strings for fields that have them.
 * There is one record per line. Fields are tab-delimited.
 * There are four types of records: Value String, Extended Value String Header,
 * Range String and True/False String. The first field, 'V', 'E', 'R' or 'T', indicates
 * the type of record.
 *
 * Note that a record will be generated only if the value_string,... is referenced
 * in a registered hfinfo entry.
 *
 *
 * Value Strings
 * -------------
 * Field 1 = 'V'
 * Field 2 = Field abbreviation to which this value string corresponds
 * Field 3 = Integer value
 * Field 4 = String
 *
 * Extended Value String Headers
 * -----------------------------
 * Field 1 = 'E'
 * Field 2 = Field abbreviation to which this extended value string header corresponds
 * Field 3 = Extended Value String "Name"
 * Field 4 = Number of entries in the associated value_string array
 * Field 5 = Access Type: "Linear Search", "Binary Search", "Direct (indexed) Access"
 *
 * Range Strings
 * -------------
 * Field 1 = 'R'
 * Field 2 = Field abbreviation to which this range string corresponds
 * Field 3 = Integer value: lower bound
 * Field 4 = Integer value: upper bound
 * Field 5 = String
 *
 * True/False Strings
 * ------------------
 * Field 1 = 'T'
 * Field 2 = Field abbreviation to which this true/false string corresponds
 * Field 3 = True String
 * Field 4 = False String
 */
void
proto_registrar_dump_values(void)
{
	header_field_info	*hfinfo;
	int			i, len, vi;
	const value_string	*vals;
	const range_string	*range;
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
			 * just differ in their bit masks.	(If a field isn't
			 * a bitfield, but can be, say, 1 or 2 bytes long,
			 * it can just be made FT_UINT16, meaning the
			 * *maximum* length is 2 bytes, and be used
			 * for all lengths.)
			 */
			if (hfinfo->same_name_prev != NULL)
				continue;

			vals  = NULL;
			range = NULL;
			tfs   = NULL;

			if ((hfinfo->display & BASE_DISPLAY_E_MASK) != BASE_CUSTOM &&
				(hfinfo->type == FT_UINT8  ||
				 hfinfo->type == FT_UINT16 ||
				 hfinfo->type == FT_UINT24 ||
				 hfinfo->type == FT_UINT32 ||
				 hfinfo->type == FT_UINT64 ||
				 hfinfo->type == FT_INT8   ||
				 hfinfo->type == FT_INT16  ||
				 hfinfo->type == FT_INT24  ||
				 hfinfo->type == FT_INT32  ||
				 hfinfo->type == FT_INT64)) {

				if (hfinfo->display & BASE_EXT_STRING) {
					vals = VALUE_STRING_EXT_VS_P((value_string_ext *)hfinfo->strings);
				} else if ((hfinfo->display & BASE_RANGE_STRING) == 0) {
					vals = hfinfo->strings;
				} else {
					range = hfinfo->strings;
				}
			}
			else if (hfinfo->type == FT_BOOLEAN) {
				tfs = hfinfo->strings;
			}

			/* Print value strings? */
			if (vals) {
				if (hfinfo->display & BASE_EXT_STRING) {
					value_string_ext *vse_p = (value_string_ext *)hfinfo->strings;
					if (!value_string_ext_validate(vse_p)) {
						g_warning("Invalid value_string_ext ptr for: %s", hfinfo->abbrev);
						continue;
					}
					match_strval_ext(0, vse_p); /* "prime" the extended value_string */
					printf("E\t%s\t%d\t%s\t%s\n",
					       hfinfo->abbrev,
					       VALUE_STRING_EXT_VS_NUM_ENTRIES(vse_p),
					       VALUE_STRING_EXT_VS_NAME(vse_p),
					       value_string_ext_match_type_str(vse_p));
				}
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

			/* print range strings? */
			else if (range) {
				vi = 0;
				while (range[vi].strptr) {
					/* Print in the proper base */
					if ((hfinfo->display & BASE_DISPLAY_E_MASK) == BASE_HEX) {
						printf("R\t%s\t0x%x\t0x%x\t%s\n",
						       hfinfo->abbrev,
						       range[vi].value_min,
						       range[vi].value_max,
						       range[vi].strptr);
					}
					else {
						printf("R\t%s\t%u\t%u\t%s\n",
						       hfinfo->abbrev,
						       range[vi].value_min,
						       range[vi].value_max,
						       range[vi].strptr);
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

/* Dumps the contents of the registration database to stdout. An independent
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
 * Field 7 = base for display (for integer types); "parent bitfield width" for FT_BOOLEAN
 * Field 8 = blurb describing field (yes, apparently we repeated this accidentally)
 *
 * (format 3)
 * Field 1 = 'F'
 * Field 2 = descriptive field name
 * Field 3 = field abbreviation
 * Field 4 = type ( textual representation of the the ftenum type )
 * Field 5 = parent protocol abbreviation
 * Field 6 = blurb describing field
 * Field 7 = base for display (for integer types); "parent bitfield width" for FT_BOOLEAN
 * Field 8 = bitmask: format: hex: 0x....
 */
void
proto_registrar_dump_fields(const int format)
{
	header_field_info *hfinfo, *parent_hfinfo;
	int		   i, len;
	const char	  *enum_name;
	const char	  *base_name;
	const char	  *blurb;
	char		   width[5];

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
			 * just differ in their bit masks.	(If a field isn't
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
				if (hfinfo->type == FT_UINT8  ||
				    hfinfo->type == FT_UINT16 ||
				    hfinfo->type == FT_UINT24 ||
				    hfinfo->type == FT_UINT32 ||
				    hfinfo->type == FT_UINT64 ||
				    hfinfo->type == FT_INT8   ||
				    hfinfo->type == FT_INT16  ||
				    hfinfo->type == FT_INT24  ||
				    hfinfo->type == FT_INT32  ||
				    hfinfo->type == FT_INT64) {


					switch (hfinfo->display & BASE_DISPLAY_E_MASK) {
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
						case BASE_CUSTOM:
							base_name = "BASE_CUSTOM";
							break;
						default:
							base_name = "????";
							break;
					}
				} else if (hfinfo->type == FT_BOOLEAN) {
					/* For FT_BOOLEAN: 'display' can be "parent bitfield width" */
					g_snprintf(width, sizeof(width), "%d", hfinfo->display);
					base_name = width;
				}
			}

			blurb = hfinfo->blurb;
			if (blurb == NULL)
				blurb = "";
			else if (strlen(blurb) == 0)
				blurb = "\"\"";
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
				printf("F\t%s\t%s\t%s\t%s\t%s\t%s\t0x%x\n",
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

/* Dumps field types and descriptive names to stdout. An independent
 * program can take this output and format it into nice tables or HTML or
 * whatever.
 *
 * There is one record per line. The fields are tab-delimited.
 *
 * Field 1 = field type name, e.g. FT_UINT8
 * Field 2 = descriptive name, e.g. "Unsigned, 1 byte"
 */
void
proto_registrar_dump_ftypes(void)
{
	ftenum_t fte;

	for (fte = 0; fte < FT_NUM_TYPES; fte++) {
		printf("%s\t%s\n", ftype_name(fte), ftype_pretty_name(fte));
	}
}

static const char *
hfinfo_numeric_format(const header_field_info *hfinfo)
{
	const char *format = NULL;

	/* Pick the proper format string */
	if (hfinfo->type == FT_FRAMENUM) {
		/*
		 * Frame numbers are always displayed in decimal.
		 */
		format = "%s == %u";
	} else {
		/* Get the underlying BASE_ value */
		switch (hfinfo->display & BASE_DISPLAY_E_MASK) {
			case BASE_DEC:
			case BASE_DEC_HEX:
			case BASE_OCT: /* I'm lazy */
			case BASE_CUSTOM:
				switch (hfinfo->type) {
					case FT_UINT8:
					case FT_UINT16:
					case FT_UINT24:
					case FT_UINT32:
						format = "%s == %u";
						break;
					case FT_UINT64:
						format = "%s == %" G_GINT64_MODIFIER "u";
						break;
					case FT_INT8:
					case FT_INT16:
					case FT_INT24:
					case FT_INT32:
						format = "%s == %d";
						break;
					case FT_INT64:
						format = "%s == %" G_GINT64_MODIFIER "d";
						break;
					default:
						DISSECTOR_ASSERT_NOT_REACHED();
						;
				}
				break;
			case BASE_HEX:
			case BASE_HEX_DEC:
				switch (hfinfo->type) {
					case FT_UINT8:
					case FT_INT8:
						format = "%s == 0x%02x";
						break;
					case FT_UINT16:
					case FT_INT16:
						format = "%s == 0x%04x";
						break;
					case FT_UINT24:
					case FT_INT24:
						format = "%s == 0x%06x";
						break;
					case FT_UINT32:
					case FT_INT32:
						format = "%s == 0x%08x";
						break;
					case FT_UINT64:
					case FT_INT64:
						format = "%s == 0x%016" G_GINT64_MODIFIER "x";
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

static const char *
hfinfo_numeric_value_format(const header_field_info *hfinfo)
{
	const char *format = NULL;

	/* Pick the proper format string */
	if (hfinfo->type == FT_FRAMENUM) {
		/*
		 * Frame numbers are always displayed in decimal.
		 */
		format = "%u";
	} else {
		/* Get the underlying BASE_ value */
		switch (hfinfo->display & BASE_DISPLAY_E_MASK) {
			case BASE_NONE:
			case BASE_DEC:
			case BASE_DEC_HEX:
			case BASE_OCT: /* I'm lazy */
			case BASE_CUSTOM:
				switch (hfinfo->type) {
					case FT_UINT8:
					case FT_UINT16:
					case FT_UINT24:
					case FT_UINT32:
						format = "%u";
						break;
					case FT_UINT64:
						format = "%" G_GINT64_MODIFIER "u";
						break;
					case FT_INT8:
					case FT_INT16:
					case FT_INT24:
					case FT_INT32:
						format = "%d";
						break;
					case FT_INT64:
						format = "%" G_GINT64_MODIFIER "d";
						break;
					default:
						DISSECTOR_ASSERT_NOT_REACHED();
						;
				}
				break;
			case BASE_HEX:
			case BASE_HEX_DEC:
				switch (hfinfo->type) {
					case FT_UINT8:
					case FT_INT8:
						format = "0x%02x";
						break;
					case FT_UINT16:
					case FT_INT16:
						format = "0x%04x";
						break;
					case FT_UINT24:
					case FT_INT24:
						format = "0x%06x";
						break;
					case FT_UINT32:
					case FT_INT32:
						format = "0x%08x";
						break;
					case FT_UINT64:
					case FT_INT64:
						format = "0x%016" G_GINT64_MODIFIER "x";
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

/* This function indicates whether it's possible to construct a
 * "match selected" display filter string for the specified field,
 * returns an indication of whether it's possible, and, if it's
 * possible and "filter" is non-null, constructs the filter and
 * sets "*filter" to point to it.
 * You do not need to [g_]free() this string since it will be automatically
 * freed once the next packet is dissected.
 */
static gboolean
construct_match_selected_string(field_info *finfo, epan_dissect_t *edt,
				char **filter)
{
	header_field_info *hfinfo;
	int		   abbrev_len;
	char		  *ptr;
	int		   buf_len;
	const char	  *format;
	int		   dfilter_len, i;
	gint		   start, length, length_remaining;
	guint8		   c;
	gchar		   is_signed_num = FALSE;

	hfinfo     = finfo->hfinfo;
	DISSECTOR_ASSERT(hfinfo);
	abbrev_len = (int) strlen(hfinfo->abbrev);

	if (hfinfo->strings && (hfinfo->display & BASE_DISPLAY_E_MASK) == BASE_NONE) {
		const gchar *str = NULL;

		switch (hfinfo->type) {

		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
			if (hfinfo->display & BASE_RANGE_STRING) {
				str = match_strrval(fvalue_get_sinteger(&finfo->value), hfinfo->strings);
			} else if (hfinfo->display & BASE_EXT_STRING) {
				str = match_strval_ext(fvalue_get_sinteger(&finfo->value), hfinfo->strings);
			} else {
				str = match_strval(fvalue_get_sinteger(&finfo->value), hfinfo->strings);
			}
			break;

		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
			if (hfinfo->display & BASE_RANGE_STRING) {
				str = match_strrval(fvalue_get_uinteger(&finfo->value), hfinfo->strings);
			} else if (hfinfo->display & BASE_EXT_STRING) {
				str = match_strval_ext(fvalue_get_uinteger(&finfo->value), hfinfo->strings);
			} else {
				str = match_strval(fvalue_get_uinteger(&finfo->value), hfinfo->strings);
			}
			break;

		default:
			break;
		}

		if (str != NULL && filter != NULL) {
			*filter = ep_strdup_printf("%s == \"%s\"", hfinfo->abbrev, str);
			return TRUE;
		}
	}

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
	switch (hfinfo->type) {

		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
			is_signed_num = TRUE;
			/* FALLTHRU */
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
			if (filter != NULL) {
				format = hfinfo_numeric_format(hfinfo);
				if (is_signed_num) {
					*filter = ep_strdup_printf(format,
						   hfinfo->abbrev,
						   fvalue_get_sinteger(&finfo->value));
				} else {
					*filter = ep_strdup_printf(format,
						   hfinfo->abbrev,
							   fvalue_get_uinteger(&finfo->value));
				}
			}
			break;

		case FT_FRAMENUM:
			DISSECTOR_ASSERT(!is_signed_num);
			if (filter != NULL) {
				format = hfinfo_numeric_format(hfinfo);
				*filter = ep_strdup_printf(format,
					   hfinfo->abbrev,
						   fvalue_get_uinteger(&finfo->value));
			}
			break;

		case FT_INT64:
		case FT_UINT64:
			if (filter != NULL) {
				format = hfinfo_numeric_format(hfinfo);
				*filter = ep_strdup_printf(format,
					hfinfo->abbrev,
					fvalue_get_integer64(&finfo->value));
			}
			break;

		case FT_PROTOCOL:
			if (filter != NULL)
				*filter = ep_strdup(finfo->hfinfo->abbrev);
			break;

		case FT_NONE:
			/*
			 * If the length is 0, just match the name of the
			 * field.
			 *
			 * (Also check for negative values, just in case,
			 * as we'll cast it to an unsigned value later.)
			 */
			length = finfo->length;
			if (length == 0) {
				if (filter != NULL)
					*filter = ep_strdup(finfo->hfinfo->abbrev);
				break;
			}
			if (length < 0)
				return FALSE;

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
				return FALSE;	/* you lose */

			/*
			 * Don't go past the end of that tvbuff.
			 */
			length_remaining = tvb_length_remaining(finfo->ds_tvb, finfo->start);
			if (length > length_remaining)
				length = length_remaining;
			if (length <= 0)
				return FALSE;

			if (filter != NULL) {
				start = finfo->start;
				buf_len = 32 + length * 3;
				*filter = ep_alloc0(buf_len);
				ptr = *filter;

				ptr += g_snprintf(ptr, (gulong) (buf_len-(ptr-*filter)),
					"frame[%d:%d] == ", finfo->start, length);
				for (i=0; i<length; i++) {
					c = tvb_get_guint8(finfo->ds_tvb, start);
					start++;
					if (i == 0 ) {
						ptr += g_snprintf(ptr, (gulong) (buf_len-(ptr-*filter)), "%02x", c);
					}
					else {
						ptr += g_snprintf(ptr, (gulong) (buf_len-(ptr-*filter)), ":%02x", c);
					}
				}
			}
			break;

		case FT_PCRE:
			/* FT_PCRE never appears as a type for a registered field. It is
			 * only used internally. */
			DISSECTOR_ASSERT_NOT_REACHED();
			break;

		/* By default, use the fvalue's "to_string_repr" method. */
		default:
			/* Figure out the string length needed.
			 *	The ft_repr length.
			 *	4 bytes for " == ".
			 *	1 byte for trailing NUL.
			 */
			if (filter != NULL) {
				dfilter_len = fvalue_string_repr_len(&finfo->value,
						FTREPR_DFILTER);
				dfilter_len += abbrev_len + 4 + 1;
				*filter = ep_alloc0(dfilter_len);

				/* Create the string */
				g_snprintf(*filter, dfilter_len, "%s == ",
					hfinfo->abbrev);
				fvalue_to_string_repr(&finfo->value,
					FTREPR_DFILTER,
					&(*filter)[abbrev_len + 4]);
			}
			break;
	}

	return TRUE;
}

/*
 * Returns TRUE if we can do a "match selected" on the field, FALSE
 * otherwise.
 */
gboolean
proto_can_match_selected(field_info *finfo, epan_dissect_t *edt)
{
	return construct_match_selected_string(finfo, edt, NULL);
}

/* This function attempts to construct a "match selected" display filter
 * string for the specified field; if it can do so, it returns a pointer
 * to the string, otherwise it returns NULL.
 *
 * The string is allocated with packet lifetime scope.
 * You do not need to [g_]free() this string since it will be automatically
 * freed once the next packet is dissected.
 */
char *
proto_construct_match_selected_string(field_info *finfo, epan_dissect_t *edt)
{
	char *filter;

	if (!construct_match_selected_string(finfo, edt, &filter))
		return NULL;
	return filter;
}

/* This function is common code for both proto_tree_add_bitmask() and
 *	proto_tree_add_bitmask_text() functions.
 */

/* NOTE: to support code written when proto_tree_add_bitmask() and
 * proto_tree_add_bitmask_text took a
 * gboolean as its last argument, with FALSE meaning "big-endian"
 * and TRUE meaning "little-endian", we treat any non-zero value of
 * "encoding" as meaning "little-endian".
 */
static gboolean
proto_item_add_bitmask_tree(proto_item *item, tvbuff_t *tvb, const int offset,
			    const int len, const gint ett, const int **fields,
			    const guint encoding, const int flags,
			    gboolean first)
{
	guint32            value = 0;
	guint32            tmpval;
	proto_tree        *tree  = NULL;
	header_field_info *hf;
	const char        *fmt;

	switch (len) {
		case 1:
			value = tvb_get_guint8(tvb, offset);
			break;
		case 2:
			value = encoding ? tvb_get_letohs(tvb, offset) :
			tvb_get_ntohs(tvb, offset);
			break;
		case 3:
			value = encoding ? tvb_get_letoh24(tvb, offset) :
			tvb_get_ntoh24(tvb, offset);
			break;
		case 4:
			value = encoding ? tvb_get_letohl(tvb, offset) :
			tvb_get_ntohl(tvb, offset);
			break;
		default:
			g_assert_not_reached();
	}

	tree = proto_item_add_subtree(item, ett);
	while (*fields) {
		proto_tree_add_item(tree, **fields, tvb, offset, len, encoding);
		if (flags & BMT_NO_APPEND) {
			fields++;
			continue;
		}
		hf = proto_registrar_get_nth(**fields);
		DISSECTOR_ASSERT(hf->bitmask != 0);
		tmpval = (value & hf->bitmask) >> hf->bitshift;

		switch (hf->type) {
		case FT_INT8:
		case FT_UINT8:
		case FT_INT16:
		case FT_UINT16:
		case FT_INT24:
		case FT_UINT24:
		case FT_INT32:
		case FT_UINT32:
			DISSECTOR_ASSERT(len == ftype_length(hf->type));

			if (hf->display == BASE_CUSTOM) {
				gchar lbl[ITEM_LABEL_LENGTH];
				custom_fmt_func_t fmtfunc = (custom_fmt_func_t)hf->strings;

				DISSECTOR_ASSERT(fmtfunc);
				fmtfunc(lbl, tmpval);
				proto_item_append_text(item, "%s%s: %s", first ? "" : ", ",
						hf->name, lbl);
				first = FALSE;
			}
			else if (hf->strings) {
				if (hf->display & BASE_RANGE_STRING) {
					proto_item_append_text(item, "%s%s: %s", first ? "" : ", ",
							       hf->name, rval_to_str(tmpval, hf->strings, "Unknown"));
				} else if (hf->display & BASE_EXT_STRING) {
					proto_item_append_text(item, "%s%s: %s", first ? "" : ", ",
							       hf->name, val_to_str_ext_const(tmpval, (value_string_ext *) (hf->strings), "Unknown"));
				} else {
					proto_item_append_text(item, "%s%s: %s", first ? "" : ", ",
							       hf->name, val_to_str_const(tmpval, cVALS(hf->strings), "Unknown"));
				}
				first = FALSE;
			}
			else if (!(flags & BMT_NO_INT)) {
				if (!first) {
					proto_item_append_text(item, ", ");
				}

				fmt = IS_FT_INT(hf->type) ? hfinfo_int_format(hf) : hfinfo_uint_format(hf);
				if (IS_BASE_DUAL(hf->display)) {
					proto_item_append_text(item, fmt, hf->name, tmpval, tmpval);
				} else {
					proto_item_append_text(item, fmt, hf->name, tmpval);
				}
				first = FALSE;
			}

			break;
		case FT_BOOLEAN:
			DISSECTOR_ASSERT(len * 8 == hf->display);

			if (hf->strings && !(flags & BMT_NO_TFS)) {
				/* If we have true/false strings, emit full - otherwise messages
				   might look weird */
				const struct true_false_string *tfs =
					(const struct true_false_string *)hf->strings;

				if (tmpval) {
					proto_item_append_text(item, "%s%s: %s", first ? "" : ", ",
							hf->name, tfs->true_string);
					first = FALSE;
				} else if (!(flags & BMT_NO_FALSE)) {
					proto_item_append_text(item, "%s%s: %s", first ? "" : ", ",
							hf->name, tfs->false_string);
					first = FALSE;
				}
			} else if (hf->bitmask & value) {
				/* If the flag is set, show the name */
				proto_item_append_text(item, "%s%s", first ? "" : ", ", hf->name);
				first = FALSE;
			}
			break;
		default:
			g_assert_not_reached();
		}

		fields++;
	}

	return first;
}

/* This function will dissect a sequence of bytes that describe a
 * bitmask.
 * hf_hdr is a 8/16/24/32 bit integer that describes the bitmask to be dissected.
 * This field will form an expansion under which the individual fields of the
 * bitmask is dissected and displayed.
 * This field must be of the type FT_[U]INT{8|16|24|32}.
 *
 * fields is an array of pointers to int that lists all the fields of the
 * bitmask. These fields can be either of the type FT_BOOLEAN for flags
 * or another integer of the same type/size as hf_hdr with a mask specified.
 * This array is terminated by a NULL entry.
 *
 * FT_BOOLEAN bits that are set to 1 will have the name added to the expansion.
 * FT_integer fields that have a value_string attached will have the
 * matched string displayed on the expansion line.
 */
proto_item *
proto_tree_add_bitmask(proto_tree *parent_tree, tvbuff_t *tvb,
		       const guint offset, const int hf_hdr,
		       const gint ett, const int **fields,
		       const guint encoding)
{
	proto_item        *item = NULL;
	header_field_info *hf;
	int                len;

	hf = proto_registrar_get_nth(hf_hdr);
	DISSECTOR_ASSERT(IS_FT_INT(hf->type) || IS_FT_UINT(hf->type));
	len = ftype_length(hf->type);

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_hdr, tvb, offset, len, encoding);
		proto_item_add_bitmask_tree(item, tvb, offset, len, ett, fields, encoding,
					    BMT_NO_INT|BMT_NO_TFS, FALSE);
	}

	return item;
}

/* The same as proto_tree_add_bitmask(), but using an arbitrary text as a top-level item */
proto_item *
proto_tree_add_bitmask_text(proto_tree *parent_tree, tvbuff_t *tvb,
			    const guint offset, const guint len,
			    const char *name, const char *fallback,
			    const gint ett, const int **fields,
			    const guint encoding, const int flags)
{
	proto_item *item = NULL;

	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, len, "%s", name ? name : "");
		if (proto_item_add_bitmask_tree(item, tvb, offset, len, ett, fields, encoding,
					flags, TRUE) && fallback) {
			/* Still at first item - append 'fallback' text if any */
			proto_item_append_text(item, "%s", fallback);
		}
	}

	return item;
}

proto_item *
proto_tree_add_bits_item(proto_tree *tree, const int hf_index, tvbuff_t *tvb,
			 const gint bit_offset, const gint no_of_bits,
			 const guint encoding)
{
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hf_index, hfinfo);

	return proto_tree_add_bits_ret_val(tree, hf_index, tvb, bit_offset, no_of_bits, NULL, encoding);
}

/*
 * This function will dissect a sequence of bits that does not need to be byte aligned; the bits
 * set will be shown in the tree as ..10 10.. and the integer value returned if return_value is set.
 * Offset should be given in bits from the start of the tvb.
 */

static proto_item *
_proto_tree_add_bits_ret_val(proto_tree *tree, const int hf_index, tvbuff_t *tvb,
			    const gint bit_offset, const gint no_of_bits,
			    guint64 *return_value, const guint encoding)
{
	gint     offset;
	guint    length;
	guint8   tot_no_bits;
	char    *bf_str;
	char     lbl_str[ITEM_LABEL_LENGTH];
	guint64  value = 0;

	proto_item        *pi;
	header_field_info *hf_field;

	const true_false_string *tfstring;

	/* We can't fake it just yet. We have to fill in the 'return_value' parameter */
	PROTO_REGISTRAR_GET_NTH(hf_index, hf_field);

	if (hf_field->bitmask != 0) {
		REPORT_DISSECTOR_BUG(ep_strdup_printf("Incompatible use of proto_tree_add_bits_ret_val"
						      " with field '%s' (%s) with bitmask != 0",
						      hf_field->abbrev, hf_field->name));
	}

	DISSECTOR_ASSERT(bit_offset >= 0);
	DISSECTOR_ASSERT(no_of_bits >  0);

	/* Byte align offset */
	offset = bit_offset>>3;

	/*
	 * Calculate the number of octets used to hold the bits
	 */
	tot_no_bits = ((bit_offset&0x7) + no_of_bits);
	length = tot_no_bits>>3;
	/* If we are using part of the next octet, increase length by 1 */
	if (tot_no_bits & 0x07)
		length++;

	if (no_of_bits < 65) {
		value = tvb_get_bits64(tvb, bit_offset, no_of_bits, encoding);
	} else {
		DISSECTOR_ASSERT_NOT_REACHED();
		return NULL;
	}

	/* Sign extend for signed types */
	switch (hf_field->type) {
		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
		case FT_INT64:
			if (value & (G_GINT64_CONSTANT(1) << (no_of_bits-1)))
				value |= (G_GINT64_CONSTANT(-1) << no_of_bits);
			break;

		default:
			break;
	}

	if (return_value) {
		*return_value = value;
	}

	/* Coast clear. Try and fake it */
	TRY_TO_FAKE_THIS_ITEM(tree, hf_index, hf_field);

	bf_str = decode_bits_in_field(bit_offset, no_of_bits, value);

	switch (hf_field->type) {
	case FT_BOOLEAN:
		/* Boolean field */
		tfstring = (const true_false_string *) &tfs_true_false;
		if (hf_field->strings)
			tfstring = (const true_false_string *)hf_field->strings;
		return proto_tree_add_boolean_format(tree, hf_index, tvb, offset, length, (guint32)value,
			"%s = %s: %s",
			bf_str, hf_field->name,
			(guint32)value ? tfstring->true_string : tfstring->false_string);
		break;

	case FT_UINT8:
	case FT_UINT16:
	case FT_UINT24:
	case FT_UINT32:
		pi = proto_tree_add_uint(tree, hf_index, tvb, offset, length, (guint32)value);
		fill_label_uint(PITEM_FINFO(pi), lbl_str);
		break;

	case FT_INT8:
	case FT_INT16:
	case FT_INT24:
	case FT_INT32:
		pi = proto_tree_add_int(tree, hf_index, tvb, offset, length, (gint32)value);
		fill_label_int(PITEM_FINFO(pi), lbl_str);
		break;

	case FT_UINT64:
		pi = proto_tree_add_uint64(tree, hf_index, tvb, offset, length, value);
		fill_label_uint64(PITEM_FINFO(pi), lbl_str);
		break;

	case FT_INT64:
		pi = proto_tree_add_int64(tree, hf_index, tvb, offset, length, (gint64)value);
		fill_label_int64(PITEM_FINFO(pi), lbl_str);
		break;

	default:
		DISSECTOR_ASSERT_NOT_REACHED();
		return NULL;
		break;
	}

	proto_item_set_text(pi, "%s = %s", bf_str, lbl_str);
	return pi;
}

proto_item *
proto_tree_add_split_bits_item_ret_val(proto_tree *tree, const int hf_index, tvbuff_t *tvb,
				       const gint bit_offset, const crumb_spec_t *crumb_spec,
				       guint64 *return_value)
{
	proto_item *pi;
	gint        no_of_bits;
	gint        octet_offset;
	gint        mask_initial_bit_offset;
	gint        mask_greatest_bit_offset;
	guint       octet_length;
	guint8      i;
	char       *bf_str;
	char        lbl_str[ITEM_LABEL_LENGTH];
	guint64     value;
	guint64     composite_bitmask;
	guint64     composite_bitmap;

	header_field_info       *hf_field;
	const true_false_string *tfstring;

	/* We can't fake it just yet. We have to fill in the 'return_value' parameter */
	PROTO_REGISTRAR_GET_NTH(hf_index, hf_field);

	if (hf_field->bitmask != 0) {
		REPORT_DISSECTOR_BUG(ep_strdup_printf(
					     "Incompatible use of proto_tree_add_split_bits_item_ret_val"
					     " with field '%s' (%s) with bitmask != 0",
					     hf_field->abbrev, hf_field->name));
	}

	mask_initial_bit_offset = bit_offset % 8;

	no_of_bits = 0;
	value      = 0;
	i          = 0;
	mask_greatest_bit_offset = 0;
	composite_bitmask        = 0;
	composite_bitmap         = 0;

	while (crumb_spec[i].crumb_bit_length != 0) {
		guint64 crumb_mask, crumb_value;
		guint8	crumb_end_bit_offset;

		DISSECTOR_ASSERT(i < 64);
		crumb_value = tvb_get_bits64(tvb,
					     bit_offset + crumb_spec[i].crumb_bit_offset,
					     crumb_spec[i].crumb_bit_length,
					     ENC_BIG_ENDIAN);
		value      += crumb_value;
		no_of_bits += crumb_spec[i].crumb_bit_length;

		/* The bitmask is 64 bit, left-aligned, starting at the first bit of the
		   octet containing the initial offset.
		   If the mask is beyond 32 bits, then give up on bit map display.
		   This could be improved in future, probably showing a table
		   of 32 or 64 bits per row */
		if (mask_greatest_bit_offset < 32) {
			crumb_end_bit_offset = mask_initial_bit_offset
				+ crumb_spec[i].crumb_bit_offset
				+ crumb_spec[i].crumb_bit_length;
			crumb_mask = (1 << crumb_spec[i].crumb_bit_length) - 1;

			if (crumb_end_bit_offset > mask_greatest_bit_offset) {
				mask_greatest_bit_offset = crumb_end_bit_offset;
			}
			composite_bitmask |= (crumb_mask  << (64 - crumb_end_bit_offset));
			composite_bitmap  |= (crumb_value << (64 - crumb_end_bit_offset));
		}
		/* Shift left for the next segment */
		value <<= crumb_spec[++i].crumb_bit_length;
	}

	/* Sign extend for signed types */
	switch (hf_field->type) {
		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
		case FT_INT64:
			if (value & no_of_bits && (G_GINT64_CONSTANT(1) << (no_of_bits-1)))
				value |= (G_GINT64_CONSTANT(-1) << no_of_bits);
			break;
		default:
			break;
	}

	if (return_value) {
		*return_value = value;
	}

	/* Coast clear. Try and fake it */
	TRY_TO_FAKE_THIS_ITEM(tree, hf_index, hf_field);

	/* initialise the format string */
	bf_str    = ep_alloc(256);
	bf_str[0] = '\0';

	octet_offset = bit_offset >> 3;

	/* Round up mask length to nearest octet */
	octet_length = ((mask_greatest_bit_offset + 7) >> 3);
	mask_greatest_bit_offset = octet_length << 3;

	/* As noted above, we currently only produce a bitmap if the crumbs span less than 4 octets of the tvb.
	   It would be a useful enhancement to eliminate this restriction. */
	if (mask_greatest_bit_offset <= 32) {
		other_decode_bitfield_value(bf_str,
					    (guint32)(composite_bitmap  >> (64 - mask_greatest_bit_offset)),
					    (guint32)(composite_bitmask >> (64 - mask_greatest_bit_offset)),
					    mask_greatest_bit_offset);
	}

	switch (hf_field->type) {
	case FT_BOOLEAN: /* it is a bit odd to have a boolean encoded as split-bits, but possible, I suppose? */
		/* Boolean field */
		tfstring = (const true_false_string *) &tfs_true_false;
		if (hf_field->strings)
			tfstring = (const true_false_string *) hf_field->strings;
		return proto_tree_add_boolean_format(tree, hf_index,
						     tvb, octet_offset, octet_length, (guint32)value,
						     "%s = %s: %s",
						     bf_str, hf_field->name,
						     (guint32)value ? tfstring->true_string : tfstring->false_string);
		break;

	case FT_UINT8:
	case FT_UINT16:
	case FT_UINT24:
	case FT_UINT32:
		pi = proto_tree_add_uint(tree, hf_index, tvb, octet_offset, octet_length, (guint32)value);
		fill_label_uint(PITEM_FINFO(pi), lbl_str);
		break;

	case FT_INT8:
	case FT_INT16:
	case FT_INT24:
	case FT_INT32:
		pi = proto_tree_add_int(tree, hf_index, tvb, octet_offset, octet_length, (gint32)value);
		fill_label_int(PITEM_FINFO(pi), lbl_str);
		break;

	case FT_UINT64:
		pi = proto_tree_add_uint64(tree, hf_index, tvb, octet_offset, octet_length, value);
		fill_label_uint64(PITEM_FINFO(pi), lbl_str);
		break;

	case FT_INT64:
		pi = proto_tree_add_int64(tree, hf_index, tvb, octet_offset, octet_length, (gint64)value);
		fill_label_int64(PITEM_FINFO(pi), lbl_str);
		break;

	default:
		DISSECTOR_ASSERT_NOT_REACHED();
		return NULL;
		break;
	}
	proto_item_set_text(pi, "%s = %s", bf_str, lbl_str);
	return pi;
}

void
proto_tree_add_split_bits_crumb(proto_tree *tree, const int hf_index, tvbuff_t *tvb, const gint bit_offset,
				const crumb_spec_t *crumb_spec, guint16 crumb_index)
{
	header_field_info *hf_info;

	PROTO_REGISTRAR_GET_NTH(hf_index, hf_info);
	proto_tree_add_text(tree, tvb,
			    bit_offset >> 3,
			    ((bit_offset + crumb_spec[crumb_index].crumb_bit_length - 1) >> 3) - (bit_offset >> 3) + 1,
			    "%s crumb %d of %s (decoded above)",
			    decode_bits_in_field(bit_offset, crumb_spec[crumb_index].crumb_bit_length,
						 tvb_get_bits(tvb,
							      bit_offset,
							      crumb_spec[crumb_index].crumb_bit_length,
							      ENC_BIG_ENDIAN)),
			    crumb_index,
			    hf_info->name);
}

proto_item *
proto_tree_add_bits_ret_val(proto_tree *tree, const int hf_index, tvbuff_t *tvb,
			    const gint bit_offset, const gint no_of_bits,
			    guint64 *return_value, const guint encoding)
{
	proto_item *item;

	if ((item = _proto_tree_add_bits_ret_val(tree, hf_index, tvb,
						 bit_offset, no_of_bits,
						 return_value, encoding))) {
		FI_SET_FLAG(PNODE_FINFO(item), FI_BITS_OFFSET(bit_offset));
		FI_SET_FLAG(PNODE_FINFO(item), FI_BITS_SIZE(no_of_bits));
	}
	return item;
}

static proto_item *
_proto_tree_add_bits_format_value(proto_tree *tree, const int hf_index,
				 tvbuff_t *tvb, const gint bit_offset,
				 const gint no_of_bits, void *value_ptr,
				 gchar *value_str)
{
	gint     offset;
	guint    length;
	guint8   tot_no_bits;
	char    *str;
	guint64  value = 0;
	header_field_info *hf_field;

	/* We do not have to return a value, try to fake it as soon as possible */
	TRY_TO_FAKE_THIS_ITEM(tree, hf_index, hf_field);

	if (hf_field->bitmask != 0) {
		REPORT_DISSECTOR_BUG(ep_strdup_printf(
					     "Incompatible use of proto_tree_add_bits_format_value"
					     " with field '%s' (%s) with bitmask != 0",
					     hf_field->abbrev, hf_field->name));
	}

	DISSECTOR_ASSERT(bit_offset >= 0);
	DISSECTOR_ASSERT(no_of_bits > 0);

	/* Byte align offset */
	offset = bit_offset>>3;

	/*
	 * Calculate the number of octets used to hold the bits
	 */
	tot_no_bits = ((bit_offset&0x7) + no_of_bits);
	length      = tot_no_bits>>3;
	/* If we are using part of the next octet, increase length by 1 */
	if (tot_no_bits & 0x07)
		length++;

	if (no_of_bits < 65) {
		value = tvb_get_bits64(tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);
	} else {
		DISSECTOR_ASSERT_NOT_REACHED();
		return NULL;
	}

	str = decode_bits_in_field(bit_offset, no_of_bits, value);

	strcat(str, " = ");
	strcat(str, hf_field->name);

	/*
	 * This function does not receive an actual value but a dimensionless pointer to that value.
	 * For this reason, the type of the header field is examined in order to determine
	 * what kind of value we should read from this address.
	 * The caller of this function must make sure that for the specific header field type the address of
	 * a compatible value is provided.
	 */
	switch (hf_field->type) {
	case FT_BOOLEAN:
		return proto_tree_add_boolean_format(tree, hf_index, tvb, offset, length, *(guint32 *)value_ptr,
						     "%s: %s", str, value_str);
		break;

	case FT_UINT8:
	case FT_UINT16:
	case FT_UINT24:
	case FT_UINT32:
		return proto_tree_add_uint_format(tree, hf_index, tvb, offset, length, *(guint32 *)value_ptr,
						  "%s: %s", str, value_str);
		break;

	case FT_UINT64:
		return proto_tree_add_uint64_format(tree, hf_index, tvb, offset, length, *(guint64 *)value_ptr,
						    "%s: %s", str, value_str);
		break;

	case FT_INT8:
	case FT_INT16:
	case FT_INT24:
	case FT_INT32:
		return proto_tree_add_int_format(tree, hf_index, tvb, offset, length, *(gint32 *)value_ptr,
						 "%s: %s", str, value_str);
		break;

	case FT_INT64:
		return proto_tree_add_int64_format(tree, hf_index, tvb, offset, length, *(gint64 *)value_ptr,
						   "%s: %s", str, value_str);
		break;

	case FT_FLOAT:
		return proto_tree_add_float_format(tree, hf_index, tvb, offset, length, *(float *)value_ptr,
						   "%s: %s", str, value_str);
		break;

	default:
		DISSECTOR_ASSERT_NOT_REACHED();
		return NULL;
		break;
	}
}

proto_item *
proto_tree_add_bits_format_value(proto_tree *tree, const int hf_index,
				 tvbuff_t *tvb, const gint bit_offset,
				 const gint no_of_bits, void *value_ptr,
				 gchar *value_str)
{
	proto_item *item;

	if ((item = _proto_tree_add_bits_format_value(tree, hf_index,
						      tvb, bit_offset, no_of_bits,
						      value_ptr, value_str))) {
		FI_SET_FLAG(PNODE_FINFO(item), FI_BITS_OFFSET(bit_offset));
		FI_SET_FLAG(PNODE_FINFO(item), FI_BITS_SIZE(no_of_bits));
	}
	return item;
}

#define CREATE_VALUE_STRING(dst,format,ap) \
	va_start(ap, format); \
	dst = ep_strdup_vprintf(format, ap); \
	va_end(ap);

proto_item *
proto_tree_add_uint_bits_format_value(proto_tree *tree, const int hf_index,
				      tvbuff_t *tvb, const gint bit_offset,
				      const gint no_of_bits, guint32 value,
				      const char *format, ...)
{
	va_list ap;
	gchar  *dst;
	header_field_info *hf_field;

	TRY_TO_FAKE_THIS_ITEM(tree, hf_index, hf_field);

	switch (hf_field->type) {
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
			break;

		default:
			DISSECTOR_ASSERT_NOT_REACHED();
			return NULL;
			break;
	}

	CREATE_VALUE_STRING(dst, format, ap);

	return proto_tree_add_bits_format_value(tree, hf_index, tvb, bit_offset, no_of_bits, &value, dst);
}

proto_item *
proto_tree_add_float_bits_format_value(proto_tree *tree, const int hf_index,
				       tvbuff_t *tvb, const gint bit_offset,
				       const gint no_of_bits, float value,
				       const char *format, ...)
{
	va_list ap;
	gchar  *dst;
	header_field_info *hf_field;

	TRY_TO_FAKE_THIS_ITEM(tree, hf_index, hf_field);

	DISSECTOR_ASSERT(hf_field->type == FT_FLOAT);

	CREATE_VALUE_STRING(dst, format, ap);

	return proto_tree_add_bits_format_value(tree, hf_index, tvb, bit_offset, no_of_bits, &value, dst);
}

proto_item *
proto_tree_add_int_bits_format_value(proto_tree *tree, const int hf_index,
				     tvbuff_t *tvb, const gint bit_offset,
				     const gint no_of_bits, gint32 value,
				     const char *format, ...)
{
	va_list ap;
	gchar  *dst;
	header_field_info *hf_field;

	TRY_TO_FAKE_THIS_ITEM(tree, hf_index, hf_field);

	switch (hf_field->type) {
		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
			break;

		default:
			DISSECTOR_ASSERT_NOT_REACHED();
			return NULL;
			break;
	}

	CREATE_VALUE_STRING(dst, format, ap);

	return proto_tree_add_bits_format_value(tree, hf_index, tvb, bit_offset, no_of_bits, &value, dst);
}

proto_item *
proto_tree_add_boolean_bits_format_value(proto_tree *tree, const int hf_index,
					 tvbuff_t *tvb, const gint bit_offset,
					 const gint no_of_bits, guint32 value,
					 const char *format, ...)
{
	va_list ap;
	gchar  *dst;
	header_field_info *hf_field;

	TRY_TO_FAKE_THIS_ITEM(tree, hf_index, hf_field);

	DISSECTOR_ASSERT(hf_field->type == FT_BOOLEAN);

	CREATE_VALUE_STRING(dst, format, ap);

	return proto_tree_add_bits_format_value(tree, hf_index, tvb, bit_offset, no_of_bits, &value, dst);
}

guchar
proto_check_field_name(const gchar *field_name)
{
	return wrs_check_charset(fld_abbrev_chars, field_name);
}
