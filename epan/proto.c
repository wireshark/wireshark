/* proto.c
 * Routines for protocol tree
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

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <glib.h>
#include <float.h>
#include <errno.h>

#include <wsutil/bits_ctz.h>
#include <wsutil/bits_count_ones.h>
#include <wsutil/sign_ext.h>

#include <ftypes/ftypes-int.h>

#include "packet.h"
#include "exceptions.h"
#include "ptvcursor.h"
#include "strutil.h"
#include "addr_resolv.h"
#include "oids.h"
#include "proto.h"
#include "epan_dissect.h"
#include "tvbuff.h"
#include "emem.h"
#include "wmem/wmem.h"
#include "charsets.h"
#include "asm_utils.h"
#include "column-utils.h"
#include "to_str-int.h"
#include "to_str.h"
#include "osi-utils.h"
#include "expert.h"
#include "show_exception.h"

#include <wsutil/plugins.h>

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

#define cVALS(x) (const value_string*)(x)

/** See inlined comments.
 @param tree the tree to append this item to
 @param hfindex field index
 @param hfinfo header_field
 @param free_block a code block to call to free resources if this returns
 @return the header field matching 'hfinfo' */
#define TRY_TO_FAKE_THIS_ITEM_OR_FREE(tree, hfindex, hfinfo, free_block) \
	/* If this item is not referenced we dont have to do much work	\
	   at all but we should still return a node so that field items	\
	   below this node (think proto_item_add_subtree()) will still	\
	   have somewhere to attach to or else filtering will not work	\
	   (they would be ignored since tree would be NULL).		\
	   DONT try to fake a node where PTREE_FINFO(tree) is NULL	\
	   since dissectors that want to do proto_item_set_len() or	\
	   other operations that dereference this would crash.		\
	   We fake FT_PROTOCOL unless some clients have requested us	\
	   not to do so. \
	*/								\
	if (!tree) {							\
		free_block;						\
		return NULL;						\
	}								\
	PTREE_DATA(tree)->count++;					\
	if (PTREE_DATA(tree)->count > MAX_TREE_ITEMS) {			\
		free_block;						\
		if (getenv("WIRESHARK_ABORT_ON_TOO_MANY_ITEMS") != NULL) \
			g_error("More than %d items in the tree -- possible infinite loop", MAX_TREE_ITEMS); \
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
				free_block;				\
				/* just return tree back to the caller */\
				return tree;				\
			}						\
		}							\
	}

/** See inlined comments.
 @param tree the tree to append this item to
 @param hfindex field index
 @param hfinfo header_field
 @return the header field matching 'hfinfo' */
#define TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo) \
	TRY_TO_FAKE_THIS_ITEM_OR_FREE(tree, hfindex, hfinfo, ((void)0))


/** See inlined comments.
 @param pi the created protocol item we're about to return */
#define TRY_TO_FAKE_THIS_REPR(pi) \
	g_assert(pi);			\
	if (!(PTREE_DATA(pi)->visible)) { \
		/* If the tree (GUI) isn't visible it's pointless for us to generate the protocol \
		 * items string representation */ \
		return pi; \
	}

static const char *hf_try_val_to_str(guint32 value, const header_field_info *hfinfo);

static void label_mark_truncated(char *label_str, gsize name_pos);
#define LABEL_MARK_TRUNCATED_START(label_str) label_mark_truncated(label_str, 0)

static void fill_label_boolean(field_info *fi, gchar *label_str);
static void fill_label_bitfield(field_info *fi, gchar *label_str, gboolean is_signed);
static void fill_label_number(field_info *fi, gchar *label_str, gboolean is_signed);
static void fill_label_number64(field_info *fi, gchar *label_str, gboolean is_signed);

static const char *hfinfo_number_value_format_display(const header_field_info *hfinfo, int display, char buf[32], guint32 value);
static const char *hfinfo_number_vals_format(const header_field_info *hfinfo, char buf[32], guint32 value);
static const char *hfinfo_number_value_format(const header_field_info *hfinfo, char buf[32], guint32 value);
static const char *hfinfo_numeric_value_format(const header_field_info *hfinfo, char buf[32], guint32 value);

static const char* hfinfo_uint64_format(const header_field_info *hfinfo);
static const char* hfinfo_int64_format(const header_field_info *hfinfo);

static proto_item *
proto_tree_add_node(proto_tree *tree, field_info *fi);

static void
get_hfi_length(header_field_info *hfinfo, tvbuff_t *tvb, const gint start, gint *length,
		gint *item_length);

static field_info *
new_field_info(proto_tree *tree, header_field_info *hfinfo, tvbuff_t *tvb,
	       const gint start, const gint item_length);

static proto_item *
proto_tree_add_pi(proto_tree *tree, header_field_info *hfinfo, tvbuff_t *tvb,
		  gint start, gint *length);

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
proto_tree_set_bytes_gbytearray(field_info *fi, const GByteArray *value);
static void
proto_tree_set_time(field_info *fi, const nstime_t *value_ptr);
static void
proto_tree_set_string(field_info *fi, const char* value);
static void
proto_tree_set_string_tvb(field_info *fi, tvbuff_t *tvb, gint start, gint length, gint encoding);
static void
proto_tree_set_ax25(field_info *fi, const guint8* value);
static void
proto_tree_set_ax25_tvb(field_info *fi, tvbuff_t *tvb, gint start);
static void
proto_tree_set_vines(field_info *fi, const guint8* value);
static void
proto_tree_set_vines_tvb(field_info *fi, tvbuff_t *tvb, gint start);
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
proto_tree_set_system_id(field_info *fi, const guint8* value_ptr, gint length);
static void
proto_tree_set_system_id_tvb(field_info *fi, tvbuff_t *tvb, gint start, gint length);
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
proto_tree_set_int64_tvb(field_info *fi, tvbuff_t *tvb, gint start, guint length, const guint encoding);
static void
proto_tree_set_uint64(field_info *fi, guint64 value);
static void
proto_tree_set_uint64_tvb(field_info *fi, tvbuff_t *tvb, gint start, guint length, const guint encoding);
static void
proto_tree_set_eui64(field_info *fi, const guint64 value);
static void
proto_tree_set_eui64_tvb(field_info *fi, tvbuff_t *tvb, gint start, const guint encoding);

/* Handle type length mismatch (now filterable) expert info */
static int proto_type_length_mismatch = -1;
static expert_field ei_type_length_mismatch_error = EI_INIT;
static expert_field ei_type_length_mismatch_warn = EI_INIT;
static void register_type_length_mismatch(void);

/* Handle number string decoding errors with expert info */
static int proto_number_string_decoding_error = -1;
static expert_field ei_number_string_decoding_failed_error = EI_INIT;
static expert_field ei_number_string_decoding_erange_error = EI_INIT;
static void register_number_string_decoding_error(void);

static int proto_register_field_init(header_field_info *hfinfo, const int parent);

/* special-case header field used within proto.c */
static header_field_info hfi_text_only =
	{ "Text item",	"text", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
int hf_text_only = -1;

/* Structure for information about a protocol */
struct _protocol {
	const char *name;         /* long description */
	const char *short_name;   /* short description */
	const char *filter_name;  /* name of this protocol in filters */
	GPtrArray  *fields;       /* fields for this protocol */
	int         proto_id;     /* field ID for this protocol */
	gboolean    is_enabled;   /* TRUE if protocol is enabled */
	gboolean    can_toggle;   /* TRUE if is_enabled can be changed */
	gboolean    is_private;   /* TRUE is protocol is private */
};

/* List of all protocols */
static GList *protocols = NULL;

/* Contains information about a field when a dissector calls
 * proto_tree_add_item.  */
#define FIELD_INFO_NEW(pool, fi)  fi = wmem_new(pool, field_info)
#define FIELD_INFO_FREE(pool, fi) wmem_free(pool, fi)

/* Contains the space for proto_nodes. */
#define PROTO_NODE_INIT(node)			\
	node->first_child = NULL;		\
	node->last_child = NULL;		\
	node->next = NULL;

#define PROTO_NODE_FREE(pool, node)			\
	wmem_free(pool, node)

/* String space for protocol and field items for the GUI */
#define ITEM_LABEL_NEW(pool, il)			\
	il = wmem_new(pool, item_label_t);
#define ITEM_LABEL_FREE(pool, il)			\
	wmem_free(pool, il);

#define PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo)						\
	if((guint)hfindex >= gpa_hfinfo.len && getenv("WIRESHARK_ABORT_ON_DISSECTOR_BUG"))	\
		g_error("Unregistered hf! index=%d", hfindex);					\
	DISSECTOR_ASSERT_HINT((guint)hfindex < gpa_hfinfo.len, "Unregistered hf!");	\
	hfinfo = gpa_hfinfo.hfi[hfindex];

/* List which stores protocols and fields that have been registered */
typedef struct _gpa_hfinfo_t {
	guint32             len;
	guint32             allocated_len;
	header_field_info **hfi;
} gpa_hfinfo_t;

static gpa_hfinfo_t gpa_hfinfo;

/* Hash table of abbreviations and IDs */
static GHashTable *gpa_name_map = NULL;
static header_field_info *same_name_hfinfo;

static void save_same_name_hfinfo(gpointer data)
{
	same_name_hfinfo = (header_field_info*)data;
}

/* Points to the first element of an array of bits, indexed by
   a subtree item type; that array element is TRUE if subtrees of
   an item of that type are to be expanded. */
static guint32 *tree_is_expanded;

/* Number of elements in that array. */
int		num_tree_types;

/* Name hashtables for fast detection of duplicate names */
static GHashTable* proto_names        = NULL;
static GHashTable* proto_short_names  = NULL;
static GHashTable* proto_filter_names = NULL;

static gint
proto_compare_name(gconstpointer p1_arg, gconstpointer p2_arg)
{
	const protocol_t *p1 = (const protocol_t *)p1_arg;
	const protocol_t *p2 = (const protocol_t *)p2_arg;

	return g_ascii_strcasecmp(p1->short_name, p2->short_name);
}

#ifdef HAVE_PLUGINS
/*
 * List of dissector plugins.
 */
typedef struct {
	void (*register_protoinfo)(void);	/* routine to call to register protocol information */
	void (*reg_handoff)(void);		/* routine to call to register dissector handoff */
} dissector_plugin;

static GSList *dissector_plugins = NULL;

/*
 * Callback for each plugin found.
 */
static gboolean
check_for_dissector_plugin(GModule *handle)
{
	gpointer gp;
	void (*register_protoinfo)(void);
	void (*reg_handoff)(void);
	dissector_plugin *plugin;

	/*
	 * Do we have a register routine?
	 */
	if (g_module_symbol(handle, "plugin_register", &gp))
		register_protoinfo = (void (*)(void))gp;
	else
		register_protoinfo = NULL;

	/*
	 * Do we have a reg_handoff routine?
	 */
	if (g_module_symbol(handle, "plugin_reg_handoff", &gp))
		reg_handoff = (void (*)(void))gp;
	else
		reg_handoff = NULL;

	/*
	 * If we have neither, we're not a dissector plugin.
	 */
	if (register_protoinfo == NULL && reg_handoff == NULL)
		return FALSE;

	/*
	 * Add this one to the list of dissector plugins.
	 */
	plugin = (dissector_plugin *)g_malloc(sizeof (dissector_plugin));
	plugin->register_protoinfo = register_protoinfo;
	plugin->reg_handoff = reg_handoff;
	dissector_plugins = g_slist_append(dissector_plugins, plugin);
	return TRUE;
}

static void
register_dissector_plugin(gpointer data, gpointer user_data _U_)
{
	dissector_plugin *plugin = (dissector_plugin *)data;

	if (plugin->register_protoinfo)
		(plugin->register_protoinfo)();
}

static void
reg_handoff_dissector_plugin(gpointer data, gpointer user_data _U_)
{
	dissector_plugin *plugin = (dissector_plugin *)data;

	if (plugin->reg_handoff)
		(plugin->reg_handoff)();
}

/*
 * Register dissector plugin type.
 */
void
register_dissector_plugin_type(void)
{
	add_plugin_type("dissector", check_for_dissector_plugin);
}
#endif /* HAVE_PLUGINS */

/* initialize data structures and register protocols and fields */
void
proto_init(void (register_all_protocols_func)(register_cb cb, gpointer client_data),
	   void (register_all_handoffs_func)(register_cb cb, gpointer client_data),
	   register_cb cb,
	   gpointer client_data)
{
	proto_cleanup();

	proto_names        = g_hash_table_new_full(g_int_hash, g_int_equal, g_free, NULL);
	proto_short_names  = g_hash_table_new(wrs_str_hash, g_str_equal);
	proto_filter_names = g_hash_table_new(wrs_str_hash, g_str_equal);

	gpa_hfinfo.len           = 0;
	gpa_hfinfo.allocated_len = 0;
	gpa_hfinfo.hfi           = NULL;
	gpa_name_map             = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, save_same_name_hfinfo);

	/* Initialize the ftype subsystem */
	ftypes_initialize();

	/* Register one special-case FT_TEXT_ONLY field for use when
	   converting wireshark to new-style proto_tree. These fields
	   are merely strings on the GUI tree; they are not filterable */
	hf_text_only = proto_register_field_init(&hfi_text_only, -1);

	/* Register the pseudo-protocols used for exceptions. */
	register_show_exception();
	register_type_length_mismatch();
	register_number_string_decoding_error();

	/* Have each built-in dissector register its protocols, fields,
	   dissector tables, and dissectors to be called through a
	   handle, and do whatever one-time initialization it needs to
	   do. */
	register_all_protocols_func(cb, client_data);

#ifdef HAVE_PLUGINS
	/* Now call the registration routines for all disssector
	   plugins. */
	if (cb)
		(*cb)(RA_PLUGIN_REGISTER, NULL, client_data);
	g_slist_foreach(dissector_plugins, register_dissector_plugin, NULL);
#endif

	/* Now call the "handoff registration" routines of all built-in
	   dissectors; those routines register the dissector in other
	   dissectors' handoff tables, and fetch any dissector handles
	   they need. */
	register_all_handoffs_func(cb, client_data);

#ifdef HAVE_PLUGINS
	/* Now do the same with plugins. */
	if (cb)
		(*cb)(RA_PLUGIN_HANDOFF, NULL, client_data);
	g_slist_foreach(dissector_plugins, reg_handoff_dissector_plugin, NULL);
#endif

	/* sort the protocols by protocol name */
	protocols = g_list_sort(protocols, proto_compare_name);

	/* We've assigned all the subtree type values; allocate the array
	   for them, and zero it out. */
	tree_is_expanded = g_new0(guint32, (num_tree_types/32)+1);
}

void
proto_cleanup(void)
{
	/* Free the abbrev/ID GTree */
	if (gpa_name_map) {
		g_hash_table_destroy(gpa_name_map);
		gpa_name_map = NULL;
	}

	while (protocols) {
		protocol_t        *protocol = (protocol_t *)protocols->data;
		header_field_info *hfinfo;
		PROTO_REGISTRAR_GET_NTH(protocol->proto_id, hfinfo);
		DISSECTOR_ASSERT(protocol->proto_id == hfinfo->id);

		g_slice_free(header_field_info, hfinfo);
		g_ptr_array_free(protocol->fields, TRUE);
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

	if (!node)
		return;

	node = node->first_child;
	while (node != NULL) {
		current = node;
		node    = current->next;
		func((proto_tree *)current, data);
	}
}

static void
free_GPtrArray_value(gpointer key, gpointer value, gpointer user_data _U_)
{
	GPtrArray         *ptrs = (GPtrArray *)value;
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
proto_tree_free_node(proto_node *node, gpointer data _U_)
{
	field_info *finfo  = PNODE_FINFO(node);

	proto_tree_children_foreach(node, proto_tree_free_node, NULL);

	FVALUE_CLEANUP(&finfo->value);
}

void
proto_tree_reset(proto_tree *tree)
{
	tree_data_t *tree_data = PTREE_DATA(tree);

	proto_tree_children_foreach(tree, proto_tree_free_node, NULL);

	/* free tree data */
	if (tree_data->interesting_hfids) {
		/* Free all the GPtrArray's in the interesting_hfids hash. */
		g_hash_table_foreach(tree_data->interesting_hfids,
			free_GPtrArray_value, NULL);

		/* And then remove all values. */
		g_hash_table_remove_all(tree_data->interesting_hfids);
	}

	/* Reset track of the number of children */
	tree_data->count = 0;

	PROTO_NODE_INIT(tree);
}

/* frees the resources that the dissection a proto_tree uses */
void
proto_tree_free(proto_tree *tree)
{
	tree_data_t *tree_data = PTREE_DATA(tree);

	proto_tree_children_foreach(tree, proto_tree_free_node, NULL);

	/* free tree data */
	if (tree_data->interesting_hfids) {
		/* Free all the GPtrArray's in the interesting_hfids hash. */
		g_hash_table_foreach(tree_data->interesting_hfids,
			free_GPtrArray_value, NULL);

		/* And then destroy the hash. */
		g_hash_table_destroy(tree_data->interesting_hfids);
	}

	g_slice_free(tree_data_t, tree_data);

	g_slice_free(proto_tree, tree);
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


/* Finds a record in the hfinfo array by id. */
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
	gchar* copy = g_strdup((const gchar *)key);
	gchar* c    = copy;
	guint tmp;

	for (; *c; c++) {
		if (*c == '.') {
			*c = 0;
			break;
		}
	}

	tmp = g_str_hash(copy);
	g_free(copy);
	return tmp;
}

/* are both strings equal up to the end or the dot? */
static gboolean
prefix_equal (gconstpointer ap, gconstpointer bp) {
	const gchar* a = (const gchar *)ap;
	const gchar* b = (const gchar *)bp;

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
	((prefix_initializer_t)v)((const char *)k);
	return TRUE;
}

/** Initialize every remaining uninitialized prefix. */
void
proto_initialize_all_prefixes(void) {
	g_hash_table_foreach_remove(prefixes, initialize_prefix, NULL);
}

/* Finds a record in the hfinfo array by name.
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

	hfinfo = (header_field_info *)g_hash_table_lookup(gpa_name_map, field_name);

	if (hfinfo)
		return hfinfo;

	if (!prefixes)
		return NULL;

	if ((pi = (prefix_initializer_t)g_hash_table_lookup(prefixes, field_name) ) != NULL) {
		pi(field_name);
		g_hash_table_remove(prefixes, field_name);
	} else {
		return NULL;
	}

	return (header_field_info *)g_hash_table_lookup(gpa_name_map, field_name);
}

int
proto_registrar_get_id_byname(const char *field_name)
{
	header_field_info *hfinfo;

	hfinfo = proto_registrar_get_byname(field_name);

	if (!hfinfo)
		return -1;

	return hfinfo->id;
}


static void
ptvcursor_new_subtree_levels(ptvcursor_t *ptvc)
{
	subtree_lvl *pushed_tree;

	DISSECTOR_ASSERT(ptvc->pushed_tree_max <= SUBTREE_MAX_LEVELS-SUBTREE_ONCE_ALLOCATION_NUMBER);
	ptvc->pushed_tree_max += SUBTREE_ONCE_ALLOCATION_NUMBER;

	pushed_tree = (subtree_lvl *)ep_alloc(sizeof(subtree_lvl) * ptvc->pushed_tree_max);
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

	ptvc                    = (ptvcursor_t *)ep_alloc(sizeof(ptvcursor_t));
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
	proto_item        *pi;
	va_list            ap;
	header_field_info *hfinfo;
	proto_tree        *tree;

	tree = ptvcursor_tree(ptvc);

	TRY_TO_FAKE_THIS_ITEM(tree, hf_text_only, hfinfo);

	pi = proto_tree_add_text_node(tree, ptvcursor_tvbuff(ptvc),
				      ptvcursor_current_offset(ptvc), length);

	TRY_TO_FAKE_THIS_REPR(pi);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return ptvcursor_add_subtree_item(ptvc, pi, ett_subtree, length);
}

/* Add a text-only node, leaving it to our caller to fill the text in */
static proto_item *
proto_tree_add_text_node(proto_tree *tree, tvbuff_t *tvb, gint start, gint length)
{
	proto_item *pi;

	if (tree == NULL)
		return NULL;

	pi = proto_tree_add_pi(tree, &hfi_text_only, tvb, start, &length);

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

	TRY_TO_FAKE_THIS_REPR(pi);

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

	TRY_TO_FAKE_THIS_REPR(pi);

	proto_tree_set_representation(pi, format, ap);

	return pi;
}

/* Add a text-only node that creates a subtree underneath.
 * proto_tree_add_text + proto_item_add_subtree
 */
proto_tree *
proto_tree_add_subtree(proto_tree *tree, tvbuff_t *tvb, gint start, gint length, gint idx, proto_item **tree_item, const char *text)
{
	return proto_tree_add_subtree_format(tree, tvb, start, length, idx, tree_item, "%s", text);
}

/* Add a text-only node that creates a subtree underneath.
 * proto_tree_add_text + proto_item_add_subtree
 */
proto_tree *
proto_tree_add_subtree_format(proto_tree *tree, tvbuff_t *tvb, gint start, gint length, gint idx, proto_item **tree_item, const char *format, ...)
{
	proto_tree	*pt;
	proto_item	*pi;
	va_list		ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hf_text_only, hfinfo);

	pi = proto_tree_add_text_node(tree, tvb, start, length);

	TRY_TO_FAKE_THIS_REPR(pi);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	pt = proto_item_add_subtree(pi, idx);
	if (tree_item != NULL)
		*tree_item = pi;

	return pt;
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

proto_item *
proto_tree_add_format_text(proto_tree *tree, tvbuff_t *tvb, gint start, gint length)
{
	proto_item	  *pi;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hf_text_only, hfinfo);

	pi = proto_tree_add_text_node(tree, tvb, start, length);

	TRY_TO_FAKE_THIS_REPR(pi);

	proto_item_set_text(pi, "%s", tvb_format_text(tvb, start, length));

	return pi;
}

void proto_report_dissector_bug(const char *message)
{
	if (getenv("WIRESHARK_ABORT_ON_DISSECTOR_BUG") != NULL)
		abort();
	else
		THROW_MESSAGE(DissectorError, message);
}

/* We could probably get away with changing is_error to a minimum length value. */
static void
report_type_length_mismatch(proto_tree *tree, const gchar *descr, int length, gboolean is_error) {

	if (is_error) {
		expert_add_info_format(NULL, tree, &ei_type_length_mismatch_error, "Trying to fetch %s with length %d", descr, length);
	} else {
		expert_add_info_format(NULL, tree, &ei_type_length_mismatch_warn, "Trying to fetch %s with length %d", descr, length);
	}

	if (is_error) {
		THROW(ReportedBoundsError);
	}
}

static guint32
get_uint_value(proto_tree *tree, tvbuff_t *tvb, gint offset, gint length, const guint encoding)
{
	guint32 value;
	gboolean length_error;

	switch (length) {

	case 1:
		value = tvb_get_guint8(tvb, offset);
		break;

	case 2:
		value = (encoding & ENC_LITTLE_ENDIAN) ? tvb_get_letohs(tvb, offset)
						       : tvb_get_ntohs(tvb, offset);
		break;

	case 3:
		value = (encoding & ENC_LITTLE_ENDIAN) ? tvb_get_letoh24(tvb, offset)
						       : tvb_get_ntoh24(tvb, offset);
		break;

	case 4:
		value = (encoding & ENC_LITTLE_ENDIAN) ? tvb_get_letohl(tvb, offset)
						       : tvb_get_ntohl(tvb, offset);
		break;

	default:
		if (length < 1) {
			length_error = TRUE;
			value = 0;
		} else {
			length_error = FALSE;
			value = (encoding & ENC_LITTLE_ENDIAN) ? tvb_get_letohl(tvb, offset)
							       : tvb_get_ntohl(tvb, offset);
		}
		report_type_length_mismatch(tree, "an unsigned integer", length, length_error);
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
get_int_value(proto_tree *tree, tvbuff_t *tvb, gint offset, gint length, const guint encoding)
{
	gint32 value;
	gboolean length_error;

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
		if (length < 1) {
			length_error = TRUE;
			value = 0;
		} else {
			length_error = FALSE;
			value = encoding ? tvb_get_letohl(tvb, offset)
					 : tvb_get_ntohl(tvb, offset);
		}
		report_type_length_mismatch(tree, "a signed integer", length, length_error);
		break;
	}
	return value;
}

/* this can be called when there is no tree, so don't add that as a param */
static void
get_time_value(tvbuff_t *tvb, const gint start, const gint length, const guint encoding,
	       nstime_t *time_stamp, const gboolean is_relative)
{
	guint32     tmpsecs;
	guint64     todsecs;

	/* relative timestamps don't do TOD/NTP */
	if (is_relative &&
		(encoding != (ENC_TIME_TIMESPEC|ENC_BIG_ENDIAN)) &&
		(encoding != (ENC_TIME_TIMESPEC|ENC_LITTLE_ENDIAN)) )
	{
		/* XXX: I think this should call REPORT_DISSECTOR_BUG(), but
		   the existing code didn't do that, so I'm not either */
		return;
	}

	switch (encoding) {

		case ENC_TIME_TIMESPEC|ENC_BIG_ENDIAN:
			/*
			 * 4-byte UNIX epoch, possibly followed by
			 * 4-byte fractional time in nanoseconds,
			 * both big-endian.
			 */
			time_stamp->secs  = (time_t)tvb_get_ntohl(tvb, start);
			if (length == 8)
				time_stamp->nsecs = tvb_get_ntohl(tvb, start+4);
			else
				time_stamp->nsecs = 0;
			break;

		case ENC_TIME_TIMESPEC|ENC_LITTLE_ENDIAN:
			/*
			 * 4-byte UNIX epoch, possibly followed by
			 * 4-byte fractional time in nanoseconds,
			 * both little-endian.
			 */
			time_stamp->secs  = (time_t)tvb_get_letohl(tvb, start);
			if (length == 8)
				time_stamp->nsecs = tvb_get_letohl(tvb, start+4);
			else
				time_stamp->nsecs = 0;
			break;

		case ENC_TIME_TOD|ENC_BIG_ENDIAN:
			/*
			 * TOD time stamp, big-endian.
			 */
/* XXX - where should this go? */
#define TOD_BASETIME G_GUINT64_CONSTANT(2208988800)

			todsecs  = tvb_get_ntoh64(tvb, start) >> 12;
			time_stamp->secs = (time_t)((todsecs  / 1000000) - TOD_BASETIME);
			time_stamp->nsecs = (int)((todsecs  % 1000000) * 1000);
			break;

		case ENC_TIME_TOD|ENC_LITTLE_ENDIAN:
			/*
			 * TOD time stamp, big-endian.
			 */
			todsecs  = tvb_get_letoh64(tvb, start) >> 12 ;
			time_stamp->secs = (time_t)((todsecs  / 1000000) - TOD_BASETIME);
			time_stamp->nsecs = (int)((todsecs  % 1000000) * 1000);
			break;

		case ENC_TIME_NTP|ENC_BIG_ENDIAN:
			/*
			 * NTP time stamp, big-endian.
			 */

/* XXX - where should this go? */
#define NTP_BASETIME G_GUINT64_CONSTANT(2208988800)

			/* We need a temporary variable here so the unsigned math
			 * works correctly (for years > 2036 according to RFC 2030
			 * chapter 3).
			 */
			tmpsecs  = tvb_get_ntohl(tvb, start);
			if (tmpsecs)
				time_stamp->secs = (time_t)(tmpsecs - (guint32)NTP_BASETIME);
			else
				time_stamp->secs = tmpsecs; /* 0 */

			if (length == 8) {
				/*
				 * We're using nanoseconds here (and we will
				 * display nanoseconds), but NTP's timestamps
				 * have a precision in microseconds or greater.
				 * Round to 1 microsecond.
				 */
				time_stamp->nsecs = (int)(1000000*(tvb_get_ntohl(tvb, start+4)/4294967296.0));
				time_stamp->nsecs *= 1000;
			} else {
				time_stamp->nsecs = 0;
			}
			break;

		case ENC_TIME_NTP|ENC_LITTLE_ENDIAN:
			/*
			 * NTP time stamp, big-endian.
			 */
			tmpsecs  = tvb_get_letohl(tvb, start);
			if (tmpsecs)
				time_stamp->secs = (time_t)(tmpsecs - (guint32)NTP_BASETIME);
			else
				time_stamp->secs = tmpsecs; /* 0 */

			if (length == 8) {
				/*
				 * We're using nanoseconds here (and we will
				 * display nanoseconds), but NTP's timestamps
				 * have a precision in microseconds or greater.
				 * Round to 1 microsecond.
				 */
				time_stamp->nsecs = (int)(1000000*(tvb_get_letohl(tvb, start+4)/4294967296.0));
				time_stamp->nsecs *= 1000;
			} else {
				time_stamp->nsecs = 0;
			}
			break;

		default:
			DISSECTOR_ASSERT_NOT_REACHED();
			break;
	}
}

static void
tree_data_add_maybe_interesting_field(tree_data_t *tree_data, field_info *fi)
{
	const header_field_info *hfinfo = fi->hfinfo;

	if (hfinfo->ref_type == HF_REF_TYPE_DIRECT) {
		GPtrArray *ptrs = NULL;

		if (tree_data->interesting_hfids == NULL) {
			/* Initialize the hash because we now know that it is needed */
			tree_data->interesting_hfids =
				g_hash_table_new(g_direct_hash, NULL /* g_direct_equal */);
		} else if (g_hash_table_size(tree_data->interesting_hfids)) {
			ptrs = (GPtrArray *)g_hash_table_lookup(tree_data->interesting_hfids,
					   GINT_TO_POINTER(hfinfo->id));
		}

		if (!ptrs) {
			/* First element triggers the creation of pointer array */
			ptrs = g_ptr_array_new();
			g_hash_table_insert(tree_data->interesting_hfids,
					    GINT_TO_POINTER(hfinfo->id), ptrs);
		}

		g_ptr_array_add(ptrs, fi);
	}
}

/* Add an item to a proto_tree, using the text label registered to that item;
   the item is extracted from the tvbuff handed to it. */
static proto_item *
proto_tree_new_item(field_info *new_fi, proto_tree *tree,
		    tvbuff_t *tvb, gint start, gint length,
		    guint encoding)
{
	proto_item *pi;
	guint32	    value, n;
	float	    floatval;
	double	    doubleval;
	const char *string;
	nstime_t    time_stamp;
	gboolean    length_error;

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
			n = get_uint_value(tree, tvb, start, length, encoding);
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
				get_uint_value(tree, tvb, start, length, encoding));
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
				get_uint_value(tree, tvb, start, length, encoding));
			break;

		case FT_INT64:
		case FT_UINT64:
			/*
			 * Map all non-zero values to little-endian for
			 * backwards compatibility.
			 */
			if (encoding)
				encoding = ENC_LITTLE_ENDIAN;
			if (length < 1 || length > 8) {
				length_error = length < 1 ? TRUE : FALSE;
				report_type_length_mismatch(tree, "a 64-bit integer", length, length_error);
			}
			if (new_fi->hfinfo->type == FT_INT64)
			{
				proto_tree_set_int64_tvb(new_fi, tvb, start, length, encoding);
			}
			else
			{
				proto_tree_set_uint64_tvb(new_fi, tvb, start, length, encoding);
			}
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
				get_int_value(tree, tvb, start, length, encoding));
			break;

		case FT_IPv4:
			/*
			 * Map all non-zero values to little-endian for
			 * backwards compatibility.
			 */
			if (encoding)
				encoding = ENC_LITTLE_ENDIAN;
			if (length != FT_IPv4_LEN) {
				length_error = length < FT_IPv4_LEN ? TRUE : FALSE;
				report_type_length_mismatch(tree, "an IPv4 address", length, length_error);
			}
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
			if (length != FT_IPXNET_LEN) {
				length_error = length < FT_IPXNET_LEN ? TRUE : FALSE;
				report_type_length_mismatch(tree, "an IPXNET address", length, length_error);
			}
			proto_tree_set_ipxnet(new_fi,
				get_uint_value(tree, tvb, start, FT_IPXNET_LEN, ENC_BIG_ENDIAN));
			break;

		case FT_IPv6:
			if (length != FT_IPv6_LEN) {
				length_error = length < FT_IPv6_LEN ? TRUE : FALSE;
				report_type_length_mismatch(tree, "an IPv6 address", length, length_error);
			}
			proto_tree_set_ipv6_tvb(new_fi, tvb, start, length);
			break;

		case FT_AX25:
			if (length != 7) {
				length_error = length < 7 ? TRUE : FALSE;
				report_type_length_mismatch(tree, "an AX.25 address", length, length_error);
			}
			proto_tree_set_ax25_tvb(new_fi, tvb, start);
			break;

		case FT_VINES:
			if (length != VINES_ADDR_LEN) {
				length_error = length < VINES_ADDR_LEN ? TRUE : FALSE;
				report_type_length_mismatch(tree, "a Vines address", length, length_error);
			}
			proto_tree_set_vines_tvb(new_fi, tvb, start);
			break;

		case FT_ETHER:
			if (length != FT_ETHER_LEN) {
				length_error = length < FT_ETHER_LEN ? TRUE : FALSE;
				report_type_length_mismatch(tree, "a MAC address", length, length_error);
			}
			proto_tree_set_ether_tvb(new_fi, tvb, start);
			break;

		case FT_EUI64:
			/*
			 * Map all non-zero values to little-endian for
			 * backwards compatibility.
			 */
			if (encoding)
				encoding = ENC_LITTLE_ENDIAN;
			if (length != FT_EUI64_LEN) {
				length_error = length < FT_EUI64_LEN ? TRUE : FALSE;
				report_type_length_mismatch(tree, "an EUI-64 address", length, length_error);
			}
			proto_tree_set_eui64_tvb(new_fi, tvb, start, encoding);
			break;
		case FT_GUID:
			/*
			 * Map all non-zero values to little-endian for
			 * backwards compatibility.
			 */
			if (encoding)
				encoding = ENC_LITTLE_ENDIAN;
			if (length != FT_GUID_LEN) {
				length_error = length < FT_GUID_LEN ? TRUE : FALSE;
				report_type_length_mismatch(tree, "a GUID", length, length_error);
			}
			proto_tree_set_guid_tvb(new_fi, tvb, start, encoding);
			break;

		case FT_OID:
		case FT_REL_OID:
			proto_tree_set_oid_tvb(new_fi, tvb, start, length);
			break;

		case FT_SYSTEM_ID:
			proto_tree_set_system_id_tvb(new_fi, tvb, start, length);
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
			if (length != 4) {
				length_error = length < 4 ? TRUE : FALSE;
				report_type_length_mismatch(tree, "a single-precision floating point number", length, length_error);
			}
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
			if (length != 8) {
				length_error = length < 8 ? TRUE : FALSE;
				report_type_length_mismatch(tree, "a double-precision floating point number", length, length_error);
			}
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
			if (length < -1 ) {
				report_type_length_mismatch(tree, "a string", length, TRUE);
			}
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
				string = tvb_get_stringz_enc(wmem_packet_scope(), tvb, start, &length, encoding);
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
				string = tvb_get_string_enc(wmem_packet_scope(), tvb, start, length, encoding);
			}
			new_fi->length = length;
			proto_tree_set_string(new_fi, string);
			break;

		case FT_UINT_STRING:
			/*
			 * NOTE: to support code written when
			 * proto_tree_add_item() took a gboolean as its
			 * last argument, with FALSE meaning "big-endian"
			 * and TRUE meaning "little-endian", if the
			 * encoding value is TRUE, treat that as
			 * ASCII with a little-endian length.
			 *
			 * This won't work for code that passes
			 * arbitrary non-zero values; that code
			 * will need to be fixed.
			 */
			if (encoding == TRUE)
				encoding = ENC_ASCII|ENC_LITTLE_ENDIAN;
			n = get_uint_value(tree, tvb, start, length, encoding & ~ENC_CHARENCODING_MASK);
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

		case FT_STRINGZPAD:
			/*
			 * XXX - currently, string values are null-
			 * terminated, so a "zero-padded" string
			 * isn't special.  If we represent string
			 * values as something that includes a counted
			 * array of bytes, we'll need to strip
			 * trailing NULs.
			 */
			proto_tree_set_string_tvb(new_fi, tvb, start, length,
			    encoding);
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

			if (length != 8 && length != 4) {
				length_error = length < 4 ? TRUE : FALSE;
				report_type_length_mismatch(tree, "an absolute time value", length, length_error);
			}

			get_time_value(tvb, start, length, encoding, &time_stamp, FALSE);

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

			if (length != 8 && length != 4) {
				length_error = length < 4 ? TRUE : FALSE;
				report_type_length_mismatch(tree, "a relative time value", length, length_error);
			}

			get_time_value(tvb, start, length, encoding, &time_stamp, TRUE);

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
	/* XXX. wouldn't be better to add this item to tree, with some special flag (FI_EXCEPTION?)
	 *      to know which item caused exception? */
	pi = proto_tree_add_node(tree, new_fi);

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
	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);
	get_hfi_length(hfinfo, ptvc->tvb, offset, &length, &item_length);
	ptvc->offset += length;
	if (hfinfo->type == FT_UINT_BYTES || hfinfo->type == FT_UINT_STRING) {
		/*
		 * The length of the rest of the item is in the first N
		 * bytes of the item.
		 */
		n = get_uint_value(ptvc->tree, ptvc->tvb, offset, length, encoding);
		ptvc->offset += n;
	}

	/* Coast clear. Try and fake it */
	TRY_TO_FAKE_THIS_ITEM(ptvc->tree, hfindex, hfinfo);

	new_fi = new_field_info(ptvc->tree, hfinfo, ptvc->tvb, offset, item_length);

	return proto_tree_new_item(new_fi, ptvc->tree, ptvc->tvb,
		offset, length, encoding);
}

/*
 * Validates that field length bytes are available starting from
 * start (pos/neg). Throws an exception if they aren't.
 */
static void
test_length(header_field_info *hfinfo, tvbuff_t *tvb,
	    gint start, gint length)
{
	gint size = length;

	if (!tvb)
		return;

	if (hfinfo->type == FT_STRINGZ) {
		/* If we're fetching until the end of the TVB, only validate
		 * that the offset is within range.
		 */
		if (length == -1)
			size = 0;
	}

	tvb_ensure_bytes_exist(tvb, start, size);
}

/* Add an item to a proto_tree, using the text label registered to that item;
   the item is extracted from the tvbuff handed to it. */
proto_item *
proto_tree_add_item_new(proto_tree *tree, header_field_info *hfinfo, tvbuff_t *tvb,
		    const gint start, gint length, const guint encoding)
{
	field_info        *new_fi;
	gint		  item_length;

	DISSECTOR_ASSERT_HINT(hfinfo != NULL, "Not passed hfi!");

	get_hfi_length(hfinfo, tvb, start, &length, &item_length);
	test_length(hfinfo, tvb, start, item_length);

	TRY_TO_FAKE_THIS_ITEM(tree, hfinfo->id, hfinfo);

	new_fi = new_field_info(tree, hfinfo, tvb, start, item_length);

	if (new_fi == NULL)
		return NULL;

	return proto_tree_new_item(new_fi, tree, tvb, start, length, encoding);
}

proto_item *
proto_tree_add_item(proto_tree *tree, int hfindex, tvbuff_t *tvb,
		    const gint start, gint length, const guint encoding)
{
	register header_field_info *hfinfo;

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);
	return proto_tree_add_item_new(tree, hfinfo, tvb, start, length, encoding);
}

/* which FT_ types can use proto_tree_add_bytes_item() */
static inline gboolean
validate_proto_tree_add_bytes_ftype(const enum ftenum type)
{
	return (type == FT_BYTES      ||
		type == FT_UINT_BYTES ||
		type == FT_OID        ||
		type == FT_REL_OID    ||
		type == FT_SYSTEM_ID  );
}

/* Note: this does no validation that the byte array of an FT_OID or
   FT_REL_OID is actually valid; and neither does proto_tree_add_item(),
   so I think it's ok to continue not validating it?
 */
proto_item *
proto_tree_add_bytes_item(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			   const gint start, gint length, const guint encoding,
			   GByteArray *retval, gint *endoff, gint *err)
{
	field_info	  *new_fi;
	GByteArray	  *bytes = retval;
	GByteArray	  *created_bytes = NULL;
	gint		   saved_err = 0;
	guint32		   n = 0;
	header_field_info *hfinfo;
	gboolean	   generate = (bytes || tree) ? TRUE : FALSE;

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);

	DISSECTOR_ASSERT_HINT(hfinfo != NULL, "Not passed hfi!");

	DISSECTOR_ASSERT_HINT(validate_proto_tree_add_bytes_ftype(hfinfo->type),
		"Called proto_tree_add_bytes_item but not a bytes-based FT_XXX type");

	/* length has to be -1 or > 0 regardless of encoding */
	/* invalid FT_UINT_BYTES length is caught in get_uint_value() */
	if (length < -1 || length == 0) {
		REPORT_DISSECTOR_BUG(wmem_strdup_printf(wmem_packet_scope(),
		    "Invalid length %d passed to proto_tree_add_bytes_item for %s",
		    length, ftype_name(hfinfo->type)));
	}

	if (encoding & ENC_STR_NUM) {
		REPORT_DISSECTOR_BUG("Decoding number strings for byte arrays is not supported");
	}

	if (generate && (encoding & ENC_STR_HEX)) {
		if (hfinfo->type == FT_UINT_BYTES) {
			/* can't decode FT_UINT_BYTES from strings */
			REPORT_DISSECTOR_BUG("proto_tree_add_bytes_item called for "
			    "FT_UINT_BYTES type, but as ENC_STR_HEX");
		}

		if (!bytes) {
			/* caller doesn't care about return value, but we need it to
			   call tvb_get_string_bytes() and set the tree later */
			bytes = created_bytes = g_byte_array_new();
		}

		/* bytes might be NULL after this, but can't add expert error until later */
		bytes = tvb_get_string_bytes(tvb, start, length, encoding, bytes, endoff);

		/* grab the errno now before it gets overwritten */
		saved_err = errno;
	}
	else if (generate) {
		tvb_ensure_bytes_exist(tvb, start, length);

		if (!bytes) {
			/* caller doesn't care about return value, but we need it to
			   call tvb_get_string_bytes() and set the tree later */
			bytes = created_bytes = g_byte_array_new();
		}

		if (hfinfo->type == FT_UINT_BYTES) {
			n = length; /* n is now the "header" length */
			length = get_uint_value(tree, tvb, start, n, encoding);
			/* length is now the value's length; only store the value in the array */
			g_byte_array_append(bytes, tvb_get_ptr(tvb, start + n, length), length);
		}
		else if (length > 0) {
			g_byte_array_append(bytes, tvb_get_ptr(tvb, start, length), length);
		}

		if (endoff)
		    *endoff = start + n + length;
	}

	if (err) *err = saved_err;

	TRY_TO_FAKE_THIS_ITEM_OR_FREE(tree, hfinfo->id, hfinfo,
		{
		    if (created_bytes)
			g_byte_array_free(created_bytes, TRUE);
		    created_bytes = NULL;
		    bytes = NULL;
		} );

	/* n will be zero except when it's a FT_UINT_BYTES */
	new_fi = new_field_info(tree, hfinfo, tvb, start, n + length);

	if (new_fi == NULL)
		return NULL;

	if (encoding & ENC_STRING) {
		if (saved_err == ERANGE)
		    expert_add_info(NULL, tree, &ei_number_string_decoding_erange_error);
		else if (!bytes || saved_err != 0)
		    expert_add_info(NULL, tree, &ei_number_string_decoding_failed_error);

		if (bytes)
		    proto_tree_set_bytes_gbytearray(new_fi, bytes);

		if (created_bytes)
		    g_byte_array_free(created_bytes, TRUE);
	}
	else {
		/* n will be zero except when it's a FT_UINT_BYTES */
		proto_tree_set_bytes_tvb(new_fi, tvb, start + n, length);

		FI_SET_FLAG(new_fi,
			(encoding & ENC_LITTLE_ENDIAN) ? FI_LITTLE_ENDIAN : FI_BIG_ENDIAN);
	}

	return proto_tree_add_node(tree, new_fi);
}


proto_item *
proto_tree_add_time_item(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			   const gint start, gint length, const guint encoding,
			   nstime_t *retval, gint *endoff, gint *err)
{
	field_info	  *new_fi;
	nstime_t	   time_stamp;
	gint		   saved_err = 0;
	header_field_info *hfinfo;

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);

	DISSECTOR_ASSERT_HINT(hfinfo != NULL, "Not passed hfi!");

	DISSECTOR_ASSERT_HINT((hfinfo->type == FT_ABSOLUTE_TIME ||
		hfinfo->type == FT_RELATIVE_TIME),
		"Called proto_tree_add_time_item but not a FT_XXX_TIME");

	/* length has to be -1 or > 0 regardless of encoding */
	if (length < -1 || length == 0) {
		REPORT_DISSECTOR_BUG(wmem_strdup_printf(wmem_packet_scope(),
		    "Invalid length %d passed to proto_tree_add_time_item", length));
	}

	time_stamp.secs  = 0;
	time_stamp.nsecs = 0;

	if (encoding & ENC_STR_TIME_MASK) {
		tvb_get_string_time(tvb, start, length, encoding, &time_stamp, endoff);
		/* grab the errno now before it gets overwritten */
		saved_err = errno;
	}
	else {
		const gboolean is_relative = (hfinfo->type == FT_RELATIVE_TIME) ? TRUE : FALSE;

		if (length != 8 && length != 4) {
			const gboolean length_error = length < 4 ? TRUE : FALSE;
			if (is_relative)
			    report_type_length_mismatch(tree, "a relative time value", length, length_error);
			else
			    report_type_length_mismatch(tree, "an absolute time value", length, length_error);
		}

		tvb_ensure_bytes_exist(tvb, start, length);
		get_time_value(tvb, start, length, encoding, &time_stamp, is_relative);
		if (endoff) *endoff = length;
	}

	if (err) *err = saved_err;

	if (retval) {
		retval->secs  = time_stamp.secs;
		retval->nsecs = time_stamp.nsecs;
	}

	TRY_TO_FAKE_THIS_ITEM(tree, hfinfo->id, hfinfo);

	new_fi = new_field_info(tree, hfinfo, tvb, start, length);

	if (new_fi == NULL)
		return NULL;

	proto_tree_set_time(new_fi, &time_stamp);

	if (encoding & ENC_STRING) {
		if (saved_err == ERANGE)
		    expert_add_info(NULL, tree, &ei_number_string_decoding_erange_error);
		else if (saved_err == EDOM)
		    expert_add_info(NULL, tree, &ei_number_string_decoding_failed_error);
	}
	else {
		FI_SET_FLAG(new_fi,
			(encoding & ENC_LITTLE_ENDIAN) ? FI_LITTLE_ENDIAN : FI_BIG_ENDIAN);
	}

	return proto_tree_add_node(tree, new_fi);
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

	pi = proto_tree_add_pi(tree, hfinfo, tvb, start, &length);

	TRY_TO_FAKE_THIS_REPR(pi);

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
	fvalue_set_tvbuff(&fi->value, tvb);
}

/* Add a FT_PROTOCOL to a proto_tree */
proto_item *
proto_tree_add_protocol_format(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			       gint start, gint length, const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT(hfinfo->type == FT_PROTOCOL);

	pi = proto_tree_add_pi(tree, hfinfo, tvb, start, &length);

	proto_tree_set_protocol_tvb(PNODE_FINFO(pi), (start == 0 ? tvb : tvb_new_subset(tvb, start, length, length)));

	TRY_TO_FAKE_THIS_REPR(pi);

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
	header_field_info *hfinfo;
	gint		  item_length;

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);
	get_hfi_length(hfinfo, tvb, start, &length, &item_length);
	test_length(hfinfo, tvb, start, item_length);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT(hfinfo->type == FT_BYTES);

	pi = proto_tree_add_pi(tree, hfinfo, tvb, start, &length);
	proto_tree_set_bytes(PNODE_FINFO(pi), start_ptr, length);

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
	gint		  item_length;

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);
	get_hfi_length(hfinfo, tvb, start, &length, &item_length);
	test_length(hfinfo, tvb, start, item_length);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	if (start_ptr)
		pi = proto_tree_add_bytes(tree, hfindex, tvb, start, length,
					  start_ptr);
	else
		pi = proto_tree_add_bytes(tree, hfindex, tvb, start, length,
					  tvb_get_ptr(tvb, start, length));

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
	gint		  item_length;

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);
	get_hfi_length(hfinfo, tvb, start, &length, &item_length);
	test_length(hfinfo, tvb, start, item_length);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	if (start_ptr)
		pi = proto_tree_add_bytes(tree, hfindex, tvb, start, length,
					  start_ptr);
	else
		pi = proto_tree_add_bytes(tree, hfindex, tvb, start, length,
					  tvb_get_ptr(tvb, start, length));

	TRY_TO_FAKE_THIS_REPR(pi);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

static void
proto_tree_set_bytes(field_info *fi, const guint8* start_ptr, gint length)
{
	GByteArray *bytes;

	DISSECTOR_ASSERT(start_ptr != NULL || length == 0);

	bytes = g_byte_array_new();
	if (length > 0) {
		g_byte_array_append(bytes, start_ptr, length);
	}
	fvalue_set_byte_array(&fi->value, bytes);
}


static void
proto_tree_set_bytes_tvb(field_info *fi, tvbuff_t *tvb, gint offset, gint length)
{
	proto_tree_set_bytes(fi, tvb_get_ptr(tvb, offset, length), length);
}

static void
proto_tree_set_bytes_gbytearray(field_info *fi, const GByteArray *value)
{
	GByteArray *bytes;

	DISSECTOR_ASSERT(value != NULL);

	bytes = byte_array_dup(value);

	fvalue_set_byte_array(&fi->value, bytes);
}

/* Add a FT_*TIME to a proto_tree */
proto_item *
proto_tree_add_time(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		    gint length, const nstime_t *value_ptr)
{
	proto_item	  *pi;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT(hfinfo->type == FT_ABSOLUTE_TIME ||
			 hfinfo->type == FT_RELATIVE_TIME);

	pi = proto_tree_add_pi(tree, hfinfo, tvb, start, &length);
	proto_tree_set_time(PNODE_FINFO(pi), value_ptr);

	return pi;
}

proto_item *
proto_tree_add_time_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
				 gint start, gint length, nstime_t *value_ptr,
				 const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;

	pi = proto_tree_add_time(tree, hfindex, tvb, start, length, value_ptr);
	if (pi != tree) {
		va_start(ap, format);
		proto_tree_set_representation_value(pi, format, ap);
		va_end(ap);
	}

	return pi;
}

proto_item *
proto_tree_add_time_format(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			   gint start, gint length, nstime_t *value_ptr,
			   const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;

	pi = proto_tree_add_time(tree, hfindex, tvb, start, length, value_ptr);
	if (pi != tree) {
		TRY_TO_FAKE_THIS_REPR(pi);

		va_start(ap, format);
		proto_tree_set_representation(pi, format, ap);
		va_end(ap);
	}

	return pi;
}

/* Set the FT_*TIME value */
static void
proto_tree_set_time(field_info *fi, const nstime_t *value_ptr)
{
	DISSECTOR_ASSERT(value_ptr != NULL);

	fvalue_set_time(&fi->value, value_ptr);
}

/* Add a FT_IPXNET to a proto_tree */
proto_item *
proto_tree_add_ipxnet(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		      gint length, guint32 value)
{
	proto_item	  *pi;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT(hfinfo->type == FT_IPXNET);

	pi = proto_tree_add_pi(tree, hfinfo, tvb, start, &length);
	proto_tree_set_ipxnet(PNODE_FINFO(pi), value);

	return pi;
}

proto_item *
proto_tree_add_ipxnet_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
				   gint start, gint length, guint32 value,
				   const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;

	pi = proto_tree_add_ipxnet(tree, hfindex, tvb, start, length, value);
	if (pi != tree) {
		va_start(ap, format);
		proto_tree_set_representation_value(pi, format, ap);
		va_end(ap);
	}

	return pi;
}

proto_item *
proto_tree_add_ipxnet_format(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			     gint start, gint length, guint32 value,
			     const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;

	pi = proto_tree_add_ipxnet(tree, hfindex, tvb, start, length, value);
	if (pi != tree) {
		TRY_TO_FAKE_THIS_REPR(pi);

		va_start(ap, format);
		proto_tree_set_representation(pi, format, ap);
		va_end(ap);
	}

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
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT(hfinfo->type == FT_IPv4);

	pi = proto_tree_add_pi(tree, hfinfo, tvb, start, &length);
	proto_tree_set_ipv4(PNODE_FINFO(pi), value);

	return pi;
}

proto_item *
proto_tree_add_ipv4_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
				 gint start, gint length, guint32 value,
				 const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;

	pi = proto_tree_add_ipv4(tree, hfindex, tvb, start, length, value);
	if (pi != tree) {
		va_start(ap, format);
		proto_tree_set_representation_value(pi, format, ap);
		va_end(ap);
	}

	return pi;
}

proto_item *
proto_tree_add_ipv4_format(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			   gint start, gint length, guint32 value,
			   const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;

	pi = proto_tree_add_ipv4(tree, hfindex, tvb, start, length, value);
	if (pi != tree) {
		TRY_TO_FAKE_THIS_REPR(pi);

		va_start(ap, format);
		proto_tree_set_representation(pi, format, ap);
		va_end(ap);
	}

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
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT(hfinfo->type == FT_IPv6);

	pi = proto_tree_add_pi(tree, hfinfo, tvb, start, &length);
	proto_tree_set_ipv6(PNODE_FINFO(pi), value_ptr);

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

	pi = proto_tree_add_ipv6(tree, hfindex, tvb, start, length, value_ptr);
	if (pi != tree) {
		va_start(ap, format);
		proto_tree_set_representation_value(pi, format, ap);
		va_end(ap);
	}

	return pi;
}

proto_item *
proto_tree_add_ipv6_format(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			   gint start, gint length, const guint8* value_ptr,
			   const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;

	pi = proto_tree_add_ipv6(tree, hfindex, tvb, start, length, value_ptr);
	if (pi != tree) {
		TRY_TO_FAKE_THIS_REPR(pi);

		va_start(ap, format);
		proto_tree_set_representation(pi, format, ap);
		va_end(ap);
	}

	return pi;
}

/* Set the FT_IPv6 value */
static void
proto_tree_set_ipv6(field_info *fi, const guint8* value_ptr)
{
	DISSECTOR_ASSERT(value_ptr != NULL);
	fvalue_set_bytes(&fi->value, value_ptr);
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
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT(hfinfo->type == FT_GUID);

	pi = proto_tree_add_pi(tree, hfinfo, tvb, start, &length);
	proto_tree_set_guid(PNODE_FINFO(pi), value_ptr);

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

	pi = proto_tree_add_guid(tree, hfindex, tvb, start, length, value_ptr);
	if (pi != tree) {
		va_start(ap, format);
		proto_tree_set_representation_value(pi, format, ap);
		va_end(ap);
	}

	return pi;
}

proto_item *
proto_tree_add_guid_format(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			   gint start, gint length, const e_guid_t *value_ptr,
			   const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;

	pi = proto_tree_add_guid(tree, hfindex, tvb, start, length, value_ptr);
	if (pi != tree) {
		TRY_TO_FAKE_THIS_REPR(pi);

		va_start(ap, format);
		proto_tree_set_representation(pi, format, ap);
		va_end(ap);
	}

	return pi;
}

/* Set the FT_GUID value */
static void
proto_tree_set_guid(field_info *fi, const e_guid_t *value_ptr)
{
	DISSECTOR_ASSERT(value_ptr != NULL);
	fvalue_set_guid(&fi->value, value_ptr);
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
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT(hfinfo->type == FT_OID);

	pi = proto_tree_add_pi(tree, hfinfo, tvb, start, &length);
	proto_tree_set_oid(PNODE_FINFO(pi), value_ptr, length);

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

	pi = proto_tree_add_oid(tree, hfindex, tvb, start, length, value_ptr);
	if (pi != tree) {
		va_start(ap, format);
		proto_tree_set_representation_value(pi, format, ap);
		va_end(ap);
	}

	return pi;
}

proto_item *
proto_tree_add_oid_format(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			  gint start, gint length, const guint8* value_ptr,
			  const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;

	pi = proto_tree_add_oid(tree, hfindex, tvb, start, length, value_ptr);
	if (pi != tree) {
		TRY_TO_FAKE_THIS_REPR(pi);

		va_start(ap, format);
		proto_tree_set_representation(pi, format, ap);
		va_end(ap);
	}

	return pi;
}

/* Set the FT_OID value */
static void
proto_tree_set_oid(field_info *fi, const guint8* value_ptr, gint length)
{
	GByteArray *bytes;

	DISSECTOR_ASSERT(value_ptr != NULL || length == 0);

	bytes = g_byte_array_new();
	if (length > 0) {
		g_byte_array_append(bytes, value_ptr, length);
	}
	fvalue_set_byte_array(&fi->value, bytes);
}

static void
proto_tree_set_oid_tvb(field_info *fi, tvbuff_t *tvb, gint start, gint length)
{
	proto_tree_set_oid(fi, tvb_get_ptr(tvb, start, length), length);
}

/* Set the FT_SYSTEM_ID value */
static void
proto_tree_set_system_id(field_info *fi, const guint8* value_ptr, gint length)
{
	GByteArray *bytes;

	DISSECTOR_ASSERT(value_ptr != NULL || length == 0);

	bytes = g_byte_array_new();
	if (length > 0) {
		g_byte_array_append(bytes, value_ptr, length);
	}
	fvalue_set_byte_array(&fi->value, bytes);
}

static void
proto_tree_set_system_id_tvb(field_info *fi, tvbuff_t *tvb, gint start, gint length)
{
	proto_tree_set_system_id(fi, tvb_get_ptr(tvb, start, length), length);
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
	guint8* b = (guint8 *)tvb_memdup(wmem_packet_scope(), tvb, start, length);

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

static void
proto_tree_set_int64_tvb(field_info *fi, tvbuff_t *tvb, gint start,
			  guint length, const guint encoding)
{
	guint64 value = 0;
	guint8* b = (guint8 *)tvb_memdup(wmem_packet_scope(), tvb, start, length);

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

	switch(length)
	{
		case 7:
			value = ws_sign_ext64(value, 56);
			break;
		case 6:
			value = ws_sign_ext64(value, 48);
			break;
		case 5:
			value = ws_sign_ext64(value, 40);
			break;
		case 4:
			value = ws_sign_ext64(value, 32);
			break;
		case 3:
			value = ws_sign_ext64(value, 24);
			break;
		case 2:
			value = ws_sign_ext64(value, 16);
			break;
		case 1:
			value = ws_sign_ext64(value, 8);
			break;
	}

	proto_tree_set_uint64(fi, value);
}

/* Add a FT_STRING, FT_STRINGZ, or FT_STRINGZPAD to a proto_tree. Creates
 * own copy of string, and frees it when the proto_tree is destroyed. */
proto_item *
proto_tree_add_string(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		      gint length, const char* value)
{
	proto_item	  *pi;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT(hfinfo->type == FT_STRING || hfinfo->type == FT_STRINGZ || hfinfo->type == FT_STRINGZPAD);

	if (hfinfo->display == STR_UNICODE) {
		DISSECTOR_ASSERT(g_utf8_validate(value, -1, NULL));
	}

	pi = proto_tree_add_pi(tree, hfinfo, tvb, start, &length);
	DISSECTOR_ASSERT(length >= 0);
	proto_tree_set_string(PNODE_FINFO(pi), value);

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

	pi = proto_tree_add_string(tree, hfindex, tvb, start, length, value);
	if (pi != tree) {
		va_start(ap, format);
		proto_tree_set_representation_value(pi, format, ap);
		va_end(ap);
	}

	return pi;
}

proto_item *
proto_tree_add_string_format(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			     gint start, gint length, const char* value,
			     const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;

	pi = proto_tree_add_string(tree, hfindex, tvb, start, length, value);
	if (pi != tree) {
		TRY_TO_FAKE_THIS_REPR(pi);

		va_start(ap, format);
		proto_tree_set_representation(pi, format, ap);
		va_end(ap);
	}

	return pi;
}

/* Appends string data to a FT_STRING, FT_STRINGZ, or FT_STRINGZPAD,
 * allowing progressive field info update instead of only updating the
 * representation as does proto_item_append_text()
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
	const gchar       *old_str, *new_str;

	if (!pi)
		return;
	if (!*str)
		return;

	fi = PITEM_FINFO(pi);
	DISSECTOR_ASSERT_HINT(fi, "proto_tree_set_visible(tree, TRUE) should have been called previously");

	hfinfo = fi->hfinfo;
	if (hfinfo->type == FT_PROTOCOL) {
		/* TRY_TO_FAKE_THIS_ITEM() speed optimization: silently skip */
		return;
	}
	DISSECTOR_ASSERT(hfinfo->type == FT_STRING || hfinfo->type == FT_STRINGZ || hfinfo->type == FT_STRINGZPAD);
	old_str = (guint8 *)fvalue_get(&fi->value);
	if (old_str && old_str[0])
		new_str = ep_strconcat(old_str, str, NULL);
	else
		new_str = str;
	fvalue_set_string(&fi->value, new_str);
}

/* Set the FT_STRING value */
static void
proto_tree_set_string(field_info *fi, const char* value)
{
	if (value) {
		fvalue_set_string(&fi->value, value);
	} else {
		fvalue_set_string(&fi->value, "[ Null ]");
	}
}

static void
proto_tree_set_string_tvb(field_info *fi, tvbuff_t *tvb, gint start, gint length, gint encoding)
{
	gchar	*string;

	if (length == -1) {
		length = tvb_ensure_captured_length_remaining(tvb, start);
	}

	string = tvb_get_string_enc(wmem_packet_scope(), tvb, start, length, encoding);
	proto_tree_set_string(fi, string);
}


/* Add a FT_AX25 to a proto_tree */
proto_item *
proto_tree_add_ax25(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		const guint8* value)
{
	proto_item		*pi;
	header_field_info	*hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT(hfinfo->type == FT_AX25);

	pi = proto_tree_add_pi(tree, hfinfo, tvb, start, &length);
	proto_tree_set_ax25(PNODE_FINFO(pi), value);

	return pi;
}

/* Set the FT_AX25 value */
static void
proto_tree_set_ax25(field_info *fi, const guint8* value)
{
	fvalue_set_bytes(&fi->value, value);
}

static void
proto_tree_set_ax25_tvb(field_info *fi, tvbuff_t *tvb, gint start)
{
	proto_tree_set_ax25(fi, tvb_get_ptr(tvb, start, 7));
}

/* Set the FT_VINES value */
static void
proto_tree_set_vines(field_info *fi, const guint8* value)
{
	fvalue_set_bytes(&fi->value, value);
}

static void
proto_tree_set_vines_tvb(field_info *fi, tvbuff_t *tvb, gint start)
{
	proto_tree_set_vines(fi, tvb_get_ptr(tvb, start, FT_VINES_ADDR_LEN));
}

/* Add a FT_ETHER to a proto_tree */
proto_item *
proto_tree_add_ether(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		     gint length, const guint8* value)
{
	proto_item	  *pi;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT(hfinfo->type == FT_ETHER);

	pi = proto_tree_add_pi(tree, hfinfo, tvb, start, &length);
	proto_tree_set_ether(PNODE_FINFO(pi), value);

	return pi;
}

proto_item *
proto_tree_add_ether_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
				  gint start, gint length, const guint8* value,
				  const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;

	pi = proto_tree_add_ether(tree, hfindex, tvb, start, length, value);
	if (pi != tree) {
		va_start(ap, format);
		proto_tree_set_representation_value(pi, format, ap);
		va_end(ap);
	}

	return pi;
}

proto_item *
proto_tree_add_ether_format(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			    gint start, gint length, const guint8* value,
			    const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;

	pi = proto_tree_add_ether(tree, hfindex, tvb, start, length, value);
	if (pi != tree) {
		TRY_TO_FAKE_THIS_REPR(pi);

		va_start(ap, format);
		proto_tree_set_representation(pi, format, ap);
		va_end(ap);
	}

	return pi;
}

/* Set the FT_ETHER value */
static void
proto_tree_set_ether(field_info *fi, const guint8* value)
{
	fvalue_set_bytes(&fi->value, value);
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
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT(hfinfo->type == FT_BOOLEAN);

	pi = proto_tree_add_pi(tree, hfinfo, tvb, start, &length);
	proto_tree_set_boolean(PNODE_FINFO(pi), value);

	return pi;
}

proto_item *
proto_tree_add_boolean_format_value(proto_tree *tree, int hfindex,
				    tvbuff_t *tvb, gint start, gint length,
				    guint32 value, const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;

	pi = proto_tree_add_boolean(tree, hfindex, tvb, start, length, value);
	if (pi != tree) {
		va_start(ap, format);
		proto_tree_set_representation_value(pi, format, ap);
		va_end(ap);
	}

	return pi;
}

proto_item *
proto_tree_add_boolean_format(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			      gint start, gint length, guint32 value,
			      const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;

	pi = proto_tree_add_boolean(tree, hfindex, tvb, start, length, value);
	if (pi != tree) {
		TRY_TO_FAKE_THIS_REPR(pi);

		va_start(ap, format);
		proto_tree_set_representation(pi, format, ap);
		va_end(ap);
	}

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
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT(hfinfo->type == FT_FLOAT);

	pi = proto_tree_add_pi(tree, hfinfo, tvb, start, &length);
	proto_tree_set_float(PNODE_FINFO(pi), value);

	return pi;
}

proto_item *
proto_tree_add_float_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
				  gint start, gint length, float value,
				  const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;

	pi = proto_tree_add_float(tree, hfindex, tvb, start, length, value);
	if (pi != tree) {
		va_start(ap, format);
		proto_tree_set_representation_value(pi, format, ap);
		va_end(ap);
	}

	return pi;
}

proto_item *
proto_tree_add_float_format(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			    gint start, gint length, float value,
			    const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;

	pi = proto_tree_add_float(tree, hfindex, tvb, start, length, value);
	if (pi != tree) {
		TRY_TO_FAKE_THIS_REPR(pi);

		va_start(ap, format);
		proto_tree_set_representation(pi, format, ap);
		va_end(ap);
	}

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
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT(hfinfo->type == FT_DOUBLE);

	pi = proto_tree_add_pi(tree, hfinfo, tvb, start, &length);
	proto_tree_set_double(PNODE_FINFO(pi), value);

	return pi;
}

proto_item *
proto_tree_add_double_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
				   gint start, gint length, double value,
				   const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;

	pi = proto_tree_add_double(tree, hfindex, tvb, start, length, value);
	if (pi != tree) {
		va_start(ap, format);
		proto_tree_set_representation_value(pi, format, ap);
		va_end(ap);
	}

	return pi;
}

proto_item *
proto_tree_add_double_format(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			     gint start, gint length, double value,
			     const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;

	pi = proto_tree_add_double(tree, hfindex, tvb, start, length, value);
	if (pi != tree) {
		TRY_TO_FAKE_THIS_REPR(pi);

		va_start(ap, format);
		proto_tree_set_representation(pi, format, ap);
		va_end(ap);
	}

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
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	switch (hfinfo->type) {
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
		case FT_FRAMENUM:
			pi = proto_tree_add_pi(tree, hfinfo, tvb, start, &length);
			proto_tree_set_uint(PNODE_FINFO(pi), value);
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

	pi = proto_tree_add_uint(tree, hfindex, tvb, start, length, value);
	if (pi != tree) {
		va_start(ap, format);
		proto_tree_set_representation_value(pi, format, ap);
		va_end(ap);
	}

	return pi;
}

proto_item *
proto_tree_add_uint_format(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			   gint start, gint length, guint32 value,
			   const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;

	pi = proto_tree_add_uint(tree, hfindex, tvb, start, length, value);
	if (pi != tree) {
		TRY_TO_FAKE_THIS_REPR(pi);

		va_start(ap, format);
		proto_tree_set_representation(pi, format, ap);
		va_end(ap);
	}

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
		integer >>= hfinfo_bitshift(hfinfo);
	}

	fvalue_set_uinteger(&fi->value, integer);
}

/* Add FT_UINT64 to a proto_tree */
proto_item *
proto_tree_add_uint64(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		      gint length, guint64 value)
{
	proto_item	  *pi;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT(hfinfo->type == FT_UINT64);

	pi = proto_tree_add_pi(tree, hfinfo, tvb, start, &length);
	proto_tree_set_uint64(PNODE_FINFO(pi), value);

	return pi;
}

proto_item *
proto_tree_add_uint64_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
				   gint start, gint length, guint64 value,
				   const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;

	pi = proto_tree_add_uint64(tree, hfindex, tvb, start, length, value);
	if (pi != tree) {
		va_start(ap, format);
		proto_tree_set_representation_value(pi, format, ap);
		va_end(ap);
	}

	return pi;
}

proto_item *
proto_tree_add_uint64_format(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			     gint start, gint length, guint64 value,
			     const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;

	pi = proto_tree_add_uint64(tree, hfindex, tvb, start, length, value);
	if (pi != tree) {
		TRY_TO_FAKE_THIS_REPR(pi);

		va_start(ap, format);
		proto_tree_set_representation(pi, format, ap);
		va_end(ap);
	}

	return pi;
}

/* Add FT_INT{8,16,24,32} to a proto_tree */
proto_item *
proto_tree_add_int(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		   gint length, gint32 value)
{
	proto_item	  *pi = NULL;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	switch (hfinfo->type) {
		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
			pi = proto_tree_add_pi(tree, hfinfo, tvb, start, &length);
			proto_tree_set_int(PNODE_FINFO(pi), value);
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
	proto_item  *pi;
	va_list	     ap;

	pi = proto_tree_add_int(tree, hfindex, tvb, start, length, value);
	if (pi != tree) {
		va_start(ap, format);
		proto_tree_set_representation_value(pi, format, ap);
		va_end(ap);
	}

	return pi;
}

proto_item *
proto_tree_add_int_format(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			  gint start, gint length, gint32 value,
			  const char *format, ...)
{
	proto_item *pi;
	va_list     ap;

	pi = proto_tree_add_int(tree, hfindex, tvb, start, length, value);
	if (pi != tree) {
		TRY_TO_FAKE_THIS_REPR(pi);

		va_start(ap, format);
		proto_tree_set_representation(pi, format, ap);
		va_end(ap);
	}

	return pi;
}

/* Set the FT_INT{8,16,24,32} value */
static void
proto_tree_set_int(field_info *fi, gint32 value)
{
	header_field_info *hfinfo;
	guint32		   integer;
	gint		   no_of_bits;

	hfinfo = fi->hfinfo;
	integer = (guint32) value;

	if (hfinfo->bitmask) {
		/* Mask out irrelevant portions */
		integer &= hfinfo->bitmask;

		/* Shift bits */
		integer >>= hfinfo_bitshift(hfinfo);

		no_of_bits = ws_count_ones(hfinfo->bitmask);
		integer = ws_sign_ext32(integer, no_of_bits);
	}

	fvalue_set_sinteger(&fi->value, integer);
}

/* Add FT_INT64 to a proto_tree */
proto_item *
proto_tree_add_int64(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		     gint length, gint64 value)
{
	proto_item	  *pi;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT(hfinfo->type == FT_INT64);

	pi = proto_tree_add_pi(tree, hfinfo, tvb, start, &length);
	proto_tree_set_uint64(PNODE_FINFO(pi), (guint64)value);

	return pi;
}

proto_item *
proto_tree_add_int64_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
				  gint start, gint length, gint64 value,
				  const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;

	pi = proto_tree_add_int64(tree, hfindex, tvb, start, length, value);
	if (pi != tree) {
		va_start(ap, format);
		proto_tree_set_representation_value(pi, format, ap);
		va_end(ap);
	}

	return pi;
}

proto_item *
proto_tree_add_int64_format(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			   gint start, gint length, gint64 value,
			   const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;

	pi = proto_tree_add_int64(tree, hfindex, tvb, start, length, value);
	if (pi != tree) {
		TRY_TO_FAKE_THIS_REPR(pi);

		va_start(ap, format);
		proto_tree_set_representation(pi, format, ap);
		va_end(ap);
	}

	return pi;
}
/* Add a FT_EUI64 to a proto_tree */
proto_item *
proto_tree_add_eui64(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		     gint length, const guint64 value)
{
	proto_item	  *pi;
	header_field_info *hfinfo;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT(hfinfo->type == FT_EUI64);

	pi = proto_tree_add_pi(tree, hfinfo, tvb, start, &length);
	proto_tree_set_eui64(PNODE_FINFO(pi), value);

	return pi;
}

proto_item *
proto_tree_add_eui64_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
				  gint start, gint length, const guint64 value,
				  const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;

	pi = proto_tree_add_eui64(tree, hfindex, tvb, start, length, value);
	if (pi != tree) {
		va_start(ap, format);
		proto_tree_set_representation_value(pi, format, ap);
		va_end(ap);
	}

	return pi;
}

proto_item *
proto_tree_add_eui64_format(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			    gint start, gint length, const guint64 value,
			    const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;

	pi = proto_tree_add_eui64(tree, hfindex, tvb, start, length, value);
	if (pi != tree) {
		TRY_TO_FAKE_THIS_REPR(pi);

		va_start(ap, format);
		proto_tree_set_representation(pi, format, ap);
		va_end(ap);
	}

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

	pnode = wmem_new(PNODE_POOL(tree), proto_node);
	PROTO_NODE_INIT(pnode);
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

	tree_data_add_maybe_interesting_field(pnode->tree_data, fi);

	return (proto_item *)pnode;
}


/* Generic way to allocate field_info and add to proto_tree.
 * Sets *pfi to address of newly-allocated field_info struct */
static proto_item *
proto_tree_add_pi(proto_tree *tree, header_field_info *hfinfo, tvbuff_t *tvb, gint start,
		  gint *length)
{
	proto_item *pi;
	field_info *fi;
	gint		item_length;

	get_hfi_length(hfinfo, tvb, start, length, &item_length);
	fi = new_field_info(tree, hfinfo, tvb, start, item_length);
	pi = proto_tree_add_node(tree, fi);

	return pi;
}


static void
get_hfi_length(header_field_info *hfinfo, tvbuff_t *tvb, const gint start, gint *length,
		   gint *item_length)
{
	gint length_remaining;

	/*
	 * We only allow a null tvbuff if the item has a zero length,
	 * i.e. if there's no data backing it.
	 */
	DISSECTOR_ASSERT(tvb != NULL || *length == 0);

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
		 * For FT_NONE, FT_PROTOCOL, FT_BYTES, FT_STRING, and
		 * FT_STRINGZPAD fields, a length of -1 means "set the
		 * length to what remains in the tvbuff".
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
		case FT_NONE:
		case FT_BYTES:
		case FT_STRING:
		case FT_STRINGZPAD:
			/*
			 * We allow FT_PROTOCOLs to be zero-length -
			 * for example, an ONC RPC NULL procedure has
			 * neither arguments nor reply, so the
			 * payload for that protocol is empty.
			 *
			 * We also allow the others to be zero-length -
			 * because that's the way the code has been for a
			 * long, long time.
			 *
			 * However, we want to ensure that the start
			 * offset is not *past* the byte past the end
			 * of the tvbuff: we throw an exception in that
			 * case.
			 */
			*length = tvb_ensure_captured_length_remaining(tvb, start);
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
				length_remaining = tvb_captured_length_remaining(tvb, start);
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
}

static field_info *
new_field_info(proto_tree *tree, header_field_info *hfinfo, tvbuff_t *tvb,
	       const gint start, const gint item_length)
{
	field_info *fi;

	FIELD_INFO_NEW(PNODE_POOL(tree), fi);

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

/* If the protocol tree is to be visible, set the representation of a
   proto_tree entry with the name of the field for the item and with
   the value formatted with the supplied printf-style format and
   argument list. */
static void
proto_tree_set_representation_value(proto_item *pi, const char *format, va_list ap)
{
	g_assert(pi);

	/* If the tree (GUI) or item isn't visible it's pointless for us to generate the protocol
	 * items string representation */
	if (PTREE_DATA(pi)->visible && !PROTO_ITEM_IS_HIDDEN(pi)) {
		int               ret = 0;
		field_info        *fi = PITEM_FINFO(pi);
		header_field_info *hf;

		DISSECTOR_ASSERT(fi);

		hf = fi->hfinfo;

		ITEM_LABEL_NEW(PNODE_POOL(pi), fi->rep);
		if (hf->bitmask && (hf->type == FT_BOOLEAN || IS_FT_UINT(hf->type))) {
			guint32 val;
			char *p;

			val = fvalue_get_uinteger(&fi->value);
			val <<= hfinfo_bitshift(hf);

			p = decode_bitfield_value(fi->rep->representation, val, hf->bitmask, hfinfo_bitwidth(hf));
			ret = (int) (p - fi->rep->representation);
		}

		/* put in the hf name */
		ret += g_snprintf(fi->rep->representation + ret, ITEM_LABEL_LENGTH - ret, "%s: ", hf->name);

		/* If possible, Put in the value of the string */
		if (ret < ITEM_LABEL_LENGTH) {
			ret += g_vsnprintf(fi->rep->representation + ret,
					  ITEM_LABEL_LENGTH - ret, format, ap);
		}
		if (ret >= ITEM_LABEL_LENGTH) {
			/* Uh oh, we don't have enough room.  Tell the user
			 * that the field is truncated.
			 */
			LABEL_MARK_TRUNCATED_START(fi->rep->representation);
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
		ITEM_LABEL_NEW(PNODE_POOL(pi), fi->rep);
		ret = g_vsnprintf(fi->rep->representation, ITEM_LABEL_LENGTH,
				  format, ap);
		if (ret >= ITEM_LABEL_LENGTH) {
			/* Uh oh, we don't have enough room.  Tell the user
			 * that the field is truncated.
			 */
			LABEL_MARK_TRUNCATED_START(fi->rep->representation);
		}
	}
}

static const char *
hfinfo_format_text(const header_field_info *hfinfo, const guchar *string)
{
	switch (hfinfo->display) {
		case STR_ASCII:
			return format_text(string, strlen(string));
/*
		case STR_ASCII_WSP
			return format_text_wsp(string, strlen(string));
 */
		case STR_UNICODE:
			/* XXX, format_unicode_text() */
			return string;
	}

	return format_text(string, strlen(string));
}

static int
protoo_strlcpy(gchar *dest, const gchar *src, gsize dest_size)
{
	gsize res = g_strlcpy(dest, src, dest_size);

	if (res > dest_size)
		res = dest_size;
	return (int) res;
}

static header_field_info *
hfinfo_same_name_get_prev(const header_field_info *hfinfo)
{
	header_field_info *dup_hfinfo;

	if (hfinfo->same_name_prev_id == -1)
		return NULL;
	PROTO_REGISTRAR_GET_NTH(hfinfo->same_name_prev_id, dup_hfinfo);
	return dup_hfinfo;
}

/* -------------------------- */
const gchar *
proto_custom_set(proto_tree* tree, const int field_id, gint occurrence,
		 gchar *result, gchar *expr, const int size)
{
	guint32            number;
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

	const char *hf_str_val;
	char number_buf[32];
	const char *number_out;
	char *tmpbuf;

	g_assert(field_id >= 0);

	PROTO_REGISTRAR_GET_NTH((guint)field_id, hfinfo);

	/* do we need to rewind ? */
	if (!hfinfo)
		return "";

	if (occurrence < 0) {
		/* Search other direction */
		while (hfinfo->same_name_prev_id != -1) {
			PROTO_REGISTRAR_GET_NTH(hfinfo->same_name_prev_id, hfinfo);
		}
	}

	while (hfinfo) {
		finfos = proto_get_finfo_ptr_array(tree, hfinfo->id);

		if (!finfos || !(len = g_ptr_array_len(finfos))) {
			if (occurrence < 0) {
				hfinfo = hfinfo->same_name_next;
			} else {
				hfinfo = hfinfo_same_name_get_prev(hfinfo);
			}
			continue;
		}

		/* Are there enough occurrences of the field? */
		if (((occurrence - prev_len) > len) || ((occurrence + prev_len) < -len)) {
			if (occurrence < 0) {
				hfinfo = hfinfo->same_name_next;
			} else {
				hfinfo = hfinfo_same_name_get_prev(hfinfo);
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
			finfo = (field_info *)g_ptr_array_index(finfos, i);

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
				bytes = (guint8 *)fvalue_get(&finfo->value);
				offset_r += protoo_strlcpy(result+offset_r,
						bytes ?  bytes_to_ep_str(bytes, fvalue_length(&finfo->value)) : "<MISSING>",
						size-offset_r);
				break;

			case FT_ABSOLUTE_TIME:
				tmpbuf = abs_time_to_str(NULL, (const nstime_t *)fvalue_get(&finfo->value), (absolute_time_display_e)hfinfo->display, TRUE);
				offset_r += protoo_strlcpy(result+offset_r,
							   tmpbuf,
							   size-offset_r);
				wmem_free(NULL, tmpbuf);
				break;

			case FT_RELATIVE_TIME:
				tmpbuf = rel_time_to_secs_str(NULL, (const nstime_t *)fvalue_get(&finfo->value));
				offset_r += protoo_strlcpy(result+offset_r,
							   tmpbuf,
							   size-offset_r);
				wmem_free(NULL, tmpbuf);
				break;

			case FT_BOOLEAN:
				number = fvalue_get_uinteger(&finfo->value);
				tfstring = (const true_false_string *)&tfs_true_false;
				if (hfinfo->strings) {
					tfstring = (const struct true_false_string*) hfinfo->strings;
				}
				offset_r += protoo_strlcpy(result+offset_r,
							   number ?
							     tfstring->true_string :
							     tfstring->false_string, size-offset_r);

				offset_e += protoo_strlcpy(expr+offset_e,
							   number ? "1" : "0", size-offset_e);
				break;

			/* XXX - make these just FT_NUMBER? */
			case FT_INT8:
			case FT_INT16:
			case FT_INT24:
			case FT_INT32:
			case FT_UINT8:
			case FT_UINT16:
			case FT_UINT24:
			case FT_UINT32:
			case FT_FRAMENUM:
				hf_str_val = NULL;
				number = IS_FT_INT(hfinfo->type) ?
						(guint32) fvalue_get_sinteger(&finfo->value) :
						fvalue_get_uinteger(&finfo->value);

				if ((hfinfo->display & FIELD_DISPLAY_E_MASK) == BASE_CUSTOM) {
					gchar tmp[ITEM_LABEL_LENGTH];
					custom_fmt_func_t fmtfunc = (custom_fmt_func_t)hfinfo->strings;

					DISSECTOR_ASSERT(fmtfunc);
					fmtfunc(tmp, number);

					offset_r += protoo_strlcpy(result+offset_r, tmp, size-offset_r);

				} else if (hfinfo->strings) {
					number_out = hf_str_val = hf_try_val_to_str(number, hfinfo);

					if (!number_out)
						number_out = hfinfo_number_value_format_display(hfinfo, BASE_DEC, number_buf, number);

					offset_r += protoo_strlcpy(result+offset_r, number_out, size-offset_r);

				} else {
					number_out = hfinfo_number_value_format(hfinfo, number_buf, number);

					offset_r += protoo_strlcpy(result+offset_r, number_out, size-offset_r);
				}

				if (hf_str_val && (hfinfo->display & FIELD_DISPLAY_E_MASK) == BASE_NONE) {
					g_snprintf(expr+offset_e, size-offset_e, "\"%s\"", hf_str_val);
				} else {
					number_out = hfinfo_numeric_value_format(hfinfo, number_buf, number);

					g_strlcpy(expr+offset_e, number_out, size-offset_e);
				}

				offset_e = (int)strlen(expr);
				break;

			case FT_INT64:
				/* XXX: Should handle BASE_CUSTOM ? */
				g_snprintf(result+offset_r, size-offset_r,
					   "%" G_GINT64_MODIFIER "d",
					   fvalue_get_integer64(&finfo->value));
				offset_r = (int)strlen(result);
				break;
			case FT_UINT64:
				g_snprintf(result+offset_r, size-offset_r,
				/* XXX: Should handle BASE_CUSTOM ? */
					   "%" G_GINT64_MODIFIER "u",
					   fvalue_get_integer64(&finfo->value));
				offset_r = (int)strlen(result);
				break;
			case FT_EUI64:
				offset_r += protoo_strlcpy(result+offset_r,
							   eui64_to_str(fvalue_get_integer64(&finfo->value)),
							   size-offset_r);
				break;

			case FT_IPv4:
				ipv4 = (ipv4_addr *)fvalue_get(&finfo->value);
				n_addr = ipv4_get_net_order_addr(ipv4);
				offset_r += protoo_strlcpy(result+offset_r,
							   ip_to_str((guint8 *)&n_addr),
							   size-offset_r);
				break;

			case FT_IPv6:
				ipv6 = (struct e_in6_addr *)fvalue_get(&finfo->value);
				SET_ADDRESS (&addr, AT_IPv6, sizeof(struct e_in6_addr), ipv6);
				address_to_str_buf(&addr, result+offset_r, size-offset_r);
				offset_r = (int)strlen(result);
				break;

			case FT_ETHER:
				offset_r += protoo_strlcpy(result+offset_r,
							   bytes_to_ep_str_punct((const guint8 *)fvalue_get(&finfo->value),
									      FT_ETHER_LEN, ':'),
							   size-offset_r);
				break;

			case FT_GUID:
				offset_r += protoo_strlcpy(result+offset_r,
							   guid_to_ep_str((e_guid_t *)fvalue_get(&finfo->value)),
							   size-offset_r);
				break;

			case FT_REL_OID:
				bytes = (guint8 *)fvalue_get(&finfo->value);
				offset_r += protoo_strlcpy(result+offset_r,
							   rel_oid_resolved_from_encoded(bytes,
										     fvalue_length(&finfo->value)),
							   size-offset_r);
				offset_e += protoo_strlcpy(expr+offset_e,
							   rel_oid_encoded2string(bytes, fvalue_length(&finfo->value)),
							   size-offset_e);
				break;

			case FT_OID:
				bytes = (guint8 *)fvalue_get(&finfo->value);
				offset_r += protoo_strlcpy(result+offset_r,
							   oid_resolved_from_encoded(bytes,
										     fvalue_length(&finfo->value)),
							   size-offset_r);
				offset_e += protoo_strlcpy(expr+offset_e,
							   oid_encoded2string(bytes, fvalue_length(&finfo->value)),
							   size-offset_e);
				break;

			case FT_SYSTEM_ID:
				bytes = (guint8 *)fvalue_get(&finfo->value);
				offset_r += protoo_strlcpy(result+offset_r,
							   print_system_id(bytes, fvalue_length(&finfo->value)),
							   size-offset_r);
				offset_e += protoo_strlcpy(expr+offset_e,
							   print_system_id(bytes, fvalue_length(&finfo->value)),
							   size-offset_e);
				break;

			case FT_FLOAT:
				g_snprintf(result+offset_r, size-offset_r,
					   "%." G_STRINGIFY(FLT_DIG) "g", fvalue_get_floating(&finfo->value));
				offset_r = (int)strlen(result);
				break;

			case FT_DOUBLE:
				g_snprintf(result+offset_r, size-offset_r,
					   "%." G_STRINGIFY(DBL_DIG) "g", fvalue_get_floating(&finfo->value));
				offset_r = (int)strlen(result);
				break;

			case FT_STRING:
			case FT_STRINGZ:
			case FT_UINT_STRING:
			case FT_STRINGZPAD:
				bytes = (guint8 *)fvalue_get(&finfo->value);
				offset_r += protoo_strlcpy(result+offset_r,
							   hfinfo_format_text(hfinfo, bytes),
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
		case FT_REL_OID:
		case FT_SYSTEM_ID:
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
			hfinfo = hfinfo_same_name_get_prev(hfinfo);
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
		ITEM_LABEL_FREE(PNODE_POOL(pi), fi->rep);
		fi->rep = NULL;
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
			ITEM_LABEL_NEW(PNODE_POOL(pi), fi->rep);
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
			ITEM_LABEL_NEW(PNODE_POOL(pi), fi->rep);
			proto_item_fill_label(fi, representation);
		} else
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

proto_tree *
proto_tree_create_root(packet_info *pinfo)
{
	proto_node *pnode;

	/* Initialize the proto_node */
	pnode = g_slice_new(proto_tree);
	PROTO_NODE_INIT(pnode);
	pnode->parent = NULL;
	PNODE_FINFO(pnode) = NULL;
	pnode->tree_data = g_slice_new(tree_data_t);

	/* Make sure we can access pinfo everywhere */
	pnode->tree_data->pinfo = pinfo;

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
proto_item_get_subtree(proto_item *pi) {
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
proto_tree_get_parent(proto_tree *tree) {
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
	const protocol_t *existing_protocol = NULL;
	header_field_info *hfinfo;
	int proto_id;
	const char *existing_name;
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

	key  = (gint *)g_malloc (sizeof(gint));
	*key = wrs_str_hash(name);

	existing_name = (const char *)g_hash_table_lookup(proto_names, key);
	if (existing_name != NULL) {
		/* g_error will terminate the program */
		g_error("Duplicate protocol name \"%s\"!"
			" This might be caused by an inappropriate plugin or a development error.", name);
	}
	g_hash_table_insert(proto_names, key, (gpointer)name);

	existing_name = (const char *)g_hash_table_lookup(proto_short_names, (gpointer)short_name);
	if (existing_name != NULL) {
		g_error("Duplicate protocol short_name \"%s\"!"
			" This might be caused by an inappropriate plugin or a development error.", short_name);
	}
	g_hash_table_insert(proto_short_names, (gpointer)short_name, (gpointer)short_name);

	found_invalid = FALSE;
	for (i = 0; filter_name[i]; i++) {
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
	existing_protocol = (const protocol_t *)g_hash_table_lookup(proto_filter_names, (gpointer)filter_name);
	if (existing_protocol != NULL) {
		g_error("Duplicate protocol filter_name \"%s\"!"
			" This might be caused by an inappropriate plugin or a development error.", filter_name);
	}

	/* Add this protocol to the list of known protocols; the list
	   is sorted by protocol short name. */
	protocol = g_new(protocol_t, 1);
	protocol->name = name;
	protocol->short_name = short_name;
	protocol->filter_name = filter_name;
	protocol->fields = g_ptr_array_new();
	protocol->is_enabled = TRUE; /* protocol is enabled by default */
	protocol->can_toggle = TRUE;
	protocol->is_private = FALSE;
	/* list will be sorted later by name, when all protocols completed registering */
	protocols = g_list_prepend(protocols, protocol);
	g_hash_table_insert(proto_filter_names, (gpointer)filter_name, protocol);

	/* Here we allocate a new header_field_info struct */
	hfinfo = g_slice_new(header_field_info);
	hfinfo->name = name;
	hfinfo->abbrev = filter_name;
	hfinfo->type = FT_PROTOCOL;
	hfinfo->display = BASE_NONE;
	hfinfo->strings = protocol;
	hfinfo->bitmask = 0;
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
	protocol = (protocol_t *)protocols->data;
	return protocol->proto_id;
}

int
proto_get_data_protocol(void *cookie)
{
	GList *list_item = (GList *)cookie;

	protocol_t *protocol = (protocol_t *)list_item->data;
	return protocol->proto_id;
}

int
proto_get_next_protocol(void **cookie)
{
	GList      *list_item = (GList *)*cookie;
	protocol_t *protocol;

	list_item = g_list_next(list_item);
	if (list_item == NULL)
		return -1;
	*cookie = list_item;
	protocol = (protocol_t *)list_item->data;
	return protocol->proto_id;
}

header_field_info *
proto_get_first_protocol_field(const int proto_id, void **cookie)
{
	protocol_t *protocol = find_protocol_by_id(proto_id);

	if ((protocol == NULL) || (protocol->fields->len == 0))
		return NULL;

	*cookie = GINT_TO_POINTER(0);
	return (header_field_info *)g_ptr_array_index(protocol->fields, 0);
}

header_field_info *
proto_get_next_protocol_field(const int proto_id, void **cookie)
{
	protocol_t *protocol = find_protocol_by_id(proto_id);
	guint       i        = GPOINTER_TO_INT(*cookie);

	i++;

	if (i >= protocol->fields->len)
		return NULL;

	*cookie = GINT_TO_POINTER(i);
	return (header_field_info *)g_ptr_array_index(protocol->fields, i);
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

int
proto_get_id(const protocol_t *protocol)
{
	return protocol->proto_id;
}

int proto_get_id_by_filter_name(const gchar* filter_name)
{
	const protocol_t *protocol = NULL;

	if(!filter_name){
		fprintf(stderr, "No filter name present");
		DISSECTOR_ASSERT(filter_name);
	}

	protocol = (const protocol_t *)g_hash_table_lookup(proto_filter_names, (gpointer)filter_name);

	if (protocol == NULL)
		return -1;
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

void
proto_get_frame_protocols(const wmem_list_t *layers,
		gboolean *is_ip, gboolean *is_tcp, gboolean *is_udp, gboolean *is_sctp, gboolean *is_ssl) {
	wmem_list_frame_t *protos = wmem_list_head(layers);
	int	    proto_id;
	const char *proto_name;

	/* Walk the list of a available protocols in the packet and
	   find "major" ones. */
	/* It might make more sense to assemble and return a bitfield. */
	while (protos != NULL)
	{
		proto_id = GPOINTER_TO_INT(wmem_list_frame_data(protos));
		proto_name = proto_get_protocol_filter_name(proto_id);

		if (is_ip && ((!strcmp(proto_name, "ip")) ||
			      (!strcmp(proto_name, "ipv6")))) {
			*is_ip = TRUE;
		} else if (is_tcp && !strcmp(proto_name, "tcp")) {
			*is_tcp = TRUE;
		} else if (is_udp && !strcmp(proto_name, "udp")) {
			*is_udp = TRUE;
		} else if (is_sctp && !strcmp(proto_name, "sctp")) {
			*is_sctp = TRUE;
		} else if (is_ssl && !strcmp(proto_name, "ssl")) {
			*is_ssl = TRUE;
		}

		protos = wmem_list_frame_next(protos);
	}
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
		protocol = (protocol_t *)list_item->data;
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

static int
proto_register_field_common(protocol_t *proto, header_field_info *hfi, const int parent)
{
	if (proto != NULL) {
		g_ptr_array_add(proto->fields, hfi);
	}

	return proto_register_field_init(hfi, parent);
}

/* for use with static arrays only, since we don't allocate our own copies
of the header_field_info struct contained within the hf_register_info struct */
void
proto_register_field_array(const int parent, hf_register_info *hf, const int num_records)
{
	hf_register_info *ptr = hf;
	protocol_t	 *proto;
	int		  i;

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

		*ptr->p_id = proto_register_field_common(proto, &ptr->hfinfo, parent);
	}
}

void
proto_register_fields_section(const int parent, header_field_info *hfi, const int num_records)
{
	int		  i;
	protocol_t	 *proto;

	proto = find_protocol_by_id(parent);
	for (i = 0; i < num_records; i++) {
		/*
		 * Make sure we haven't registered this yet.
		 */
		if (hfi[i].id != -1) {
			fprintf(stderr,
				"Duplicate field detected in call to proto_register_fields: %s is already registered\n",
				hfi[i].abbrev);
			return;
		}

		proto_register_field_common(proto, &hfi[i], parent);
	}
}

void
proto_register_fields_manual(const int parent, header_field_info **hfi, const int num_records)
{
	int		  i;
	protocol_t	 *proto;

	proto = find_protocol_by_id(parent);
	for (i = 0; i < num_records; i++) {
		/*
		 * Make sure we haven't registered this yet.
		 */
		if (hfi[i]->id != -1) {
			fprintf(stderr,
				"Duplicate field detected in call to proto_register_fields: %s is already registered\n",
				hfi[i]->abbrev);
			return;
		}

		proto_register_field_common(proto, hfi[i], parent);
	}
}

/* unregister already registered fields */
void
proto_unregister_field (const int parent, gint hf_id)
{
	hf_register_info *hf;
	protocol_t       *proto;
	guint             i;

	if (hf_id == -1 || hf_id == 0)
		return;

	proto = find_protocol_by_id (parent);
	if (!proto || proto->fields->len == 0) {
		return;
	}

	for (i = 0; i < proto->fields->len; i++) {
		hf = (hf_register_info *)g_ptr_array_index(proto->fields, i);
		if (*hf->p_id == hf_id) {
			/* Found the hf_id in this protocol */
			g_hash_table_steal(gpa_name_map, hf->hfinfo.abbrev);
			g_ptr_array_remove_index_fast(proto->fields, i);
			return;
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

static const value_string hf_display[] = {
	{ BASE_NONE,			  "BASE_NONE"			   },
	{ BASE_DEC,			  "BASE_DEC"			   },
	{ BASE_HEX,			  "BASE_HEX"			   },
	{ BASE_OCT,			  "BASE_OCT"			   },
	{ BASE_DEC_HEX,			  "BASE_DEC_HEX"		   },
	{ BASE_HEX_DEC,			  "BASE_HEX_DEC"		   },
	{ BASE_CUSTOM,			  "BASE_CUSTOM"			   },
	{ BASE_NONE|BASE_RANGE_STRING,    "BASE_NONE|BASE_RANGE_STRING"	   },
	{ BASE_DEC|BASE_RANGE_STRING,     "BASE_DEC|BASE_RANGE_STRING"	   },
	{ BASE_HEX|BASE_RANGE_STRING,     "BASE_HEX|BASE_RANGE_STRING"	   },
	{ BASE_OCT|BASE_RANGE_STRING,     "BASE_OCT|BASE_RANGE_STRING"	   },
	{ BASE_DEC_HEX|BASE_RANGE_STRING, "BASE_DEC_HEX|BASE_RANGE_STRING" },
	{ BASE_HEX_DEC|BASE_RANGE_STRING, "BASE_HEX_DEC|BASE_RANGE_STRING" },
	{ BASE_CUSTOM|BASE_RANGE_STRING,  "BASE_CUSTOM|BASE_RANGE_STRING"  },
	{ BASE_NONE|BASE_VAL64_STRING,    "BASE_NONE|BASE_VAL64_STRING"	   },
	{ BASE_DEC|BASE_VAL64_STRING,     "BASE_DEC|BASE_VAL64_STRING"	   },
	{ BASE_HEX|BASE_VAL64_STRING,     "BASE_HEX|BASE_VAL64_STRING"	   },
	{ BASE_OCT|BASE_VAL64_STRING,     "BASE_OCT|BASE_VAL64_STRING"	   },
	{ BASE_DEC_HEX|BASE_VAL64_STRING, "BASE_DEC_HEX|BASE_VAL64_STRING" },
	{ BASE_HEX_DEC|BASE_VAL64_STRING, "BASE_HEX_DEC|BASE_VAL64_STRING" },
	{ BASE_CUSTOM|BASE_VAL64_STRING,  "BASE_CUSTOM|BASE_VAL64_STRING"  },
	/* { STR_ASCII,			  "STR_ASCII" }, */
	{ STR_UNICODE,			  "STR_UNICODE" },
	{ ABSOLUTE_TIME_LOCAL,		  "ABSOLUTE_TIME_LOCAL"		   },
	{ ABSOLUTE_TIME_UTC,		  "ABSOLUTE_TIME_UTC"		   },
	{ ABSOLUTE_TIME_DOY_UTC,	  "ABSOLUTE_TIME_DOY_UTC"	   },
	{ 0,				  NULL } };

/* temporary function containing assert part for easier profiling */
static void
tmp_fld_check_assert(header_field_info *hfinfo)
{

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
		    (hfinfo->type == FT_UINT64)   ||
		    (hfinfo->type == FT_INT8)     ||
		    (hfinfo->type == FT_INT16)    ||
		    (hfinfo->type == FT_INT24)    ||
		    (hfinfo->type == FT_INT32)    ||
		    (hfinfo->type == FT_INT64)    ||
		    (hfinfo->type == FT_BOOLEAN)  ||
		    (hfinfo->type == FT_PROTOCOL) ))
		g_error("Field '%s' (%s) has a 'strings' value but is of type %s"
			" (which is not allowed to have strings)\n",
			hfinfo->name, hfinfo->abbrev, ftype_name(hfinfo->type));

	/* TODO: This check may slow down startup, and output quite a few warnings.
	   It would be good to be able to enable this (and possibly other checks?)
	   in non-release builds.   */
#if 0
	/* Check for duplicate value_string values.
	   There are lots that have the same value *and* string, so for now only
	   report those that have same value but different string. */
	if ((hfinfo->strings != NULL) &&
	    !(hfinfo->display & BASE_RANGE_STRING) &&
	    !((hfinfo->display & FIELD_DISPLAY_E_MASK) == BASE_CUSTOM) &&
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
		const value_string *start_values;
		const value_string *current;

		if (hfinfo->display & BASE_EXT_STRING)
			start_values = VALUE_STRING_EXT_VS_P(((const value_string_ext*)hfinfo->strings));
		else
			start_values = (const value_string*)hfinfo->strings;
		current = start_values;

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
			 */
			switch (hfinfo->display & FIELD_DISPLAY_E_MASK) {
				case BASE_HEX:
				case BASE_OCT:
				case BASE_DEC_HEX:
				case BASE_HEX_DEC:
					g_error("Field '%s' (%s) is signed (%s) but is being displayed unsigned (%s)\n",
						hfinfo->name, hfinfo->abbrev,
						ftype_name(hfinfo->type),
						val_to_str(hfinfo->display, hf_display, "(Bit count: %d)"));
			}
			/* FALL THROUGH */
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
		case FT_UINT64:
			/*  Require integral types (other than frame number,
			 *  which is always displayed in decimal) to have a
			 *  number base.
			 *  If there is a strings value then this base is not
			 *  normally used except when constructing a display
			 *  filter for a value not found in the strings lookup.
			 */
			switch (hfinfo->display & FIELD_DISPLAY_E_MASK) {
				case BASE_DEC:
				case BASE_HEX:
				case BASE_OCT:
				case BASE_DEC_HEX:
				case BASE_HEX_DEC:
				case BASE_CUSTOM: /* hfinfo_numeric_value_format() treats this as decimal */
					break;
				default:
					g_error("Field '%s' (%s) is an integral value (%s)"
						" but is being displayed as %s\n",
						hfinfo->name, hfinfo->abbrev,
						ftype_name(hfinfo->type),
						val_to_str(hfinfo->display, hf_display, "(Unknown: 0x%x)"));
			}
			break;

		case FT_PROTOCOL:
		case FT_FRAMENUM:
			if (hfinfo->display != BASE_NONE)
				g_error("Field '%s' (%s) is an %s but is being displayed as %s instead of BASE_NONE\n",
					hfinfo->name, hfinfo->abbrev,
					ftype_name(hfinfo->type),
					val_to_str(hfinfo->display, hf_display, "(Bit count: %d)"));
			if (hfinfo->bitmask != 0)
				g_error("Field '%s' (%s) is an %s but has a bitmask\n",
					hfinfo->name, hfinfo->abbrev,
					ftype_name(hfinfo->type));
			break;

		case FT_BOOLEAN:
			break;

		case FT_ABSOLUTE_TIME:
			if (!(hfinfo->display == ABSOLUTE_TIME_LOCAL ||
			      hfinfo->display == ABSOLUTE_TIME_UTC   ||
			      hfinfo->display == ABSOLUTE_TIME_DOY_UTC))
				g_error("Field '%s' (%s) is a %s but is being displayed as %s instead of as a time\n",
					hfinfo->name, hfinfo->abbrev,
					ftype_name(hfinfo->type),
					val_to_str(hfinfo->display, hf_display, "(Bit count: %d)"));
			if (hfinfo->bitmask != 0)
				g_error("Field '%s' (%s) is an %s but has a bitmask\n",
					hfinfo->name, hfinfo->abbrev,
					ftype_name(hfinfo->type));
			break;

		case FT_STRING:
		case FT_STRINGZ:
		case FT_UINT_STRING:
		case FT_STRINGZPAD:
			switch (hfinfo->display) {
				case STR_ASCII:
				case STR_UNICODE:
					break;

				default:
					g_error("Field '%s' (%s) is an string value (%s)"
						" but is being displayed as %s\n",
						hfinfo->name, hfinfo->abbrev,
						ftype_name(hfinfo->type),
						val_to_str(hfinfo->display, hf_display, "(Unknown: 0x%x)"));
			}

			if (hfinfo->bitmask != 0)
				g_error("Field '%s' (%s) is an %s but has a bitmask\n",
					hfinfo->name, hfinfo->abbrev,
					ftype_name(hfinfo->type));
			if (hfinfo->strings != NULL)
				g_error("Field '%s' (%s) is an %s but has a strings value\n",
					hfinfo->name, hfinfo->abbrev,
					ftype_name(hfinfo->type));
			break;

		default:
			if (hfinfo->display != BASE_NONE)
				g_error("Field '%s' (%s) is an %s but is being displayed as %s instead of BASE_NONE\n",
					hfinfo->name, hfinfo->abbrev,
					ftype_name(hfinfo->type),
					val_to_str(hfinfo->display, hf_display, "(Bit count: %d)"));
			if (hfinfo->bitmask != 0)
				g_error("Field '%s' (%s) is an %s but has a bitmask\n",
					hfinfo->name, hfinfo->abbrev,
					ftype_name(hfinfo->type));
			if (hfinfo->strings != NULL)
				g_error("Field '%s' (%s) is an %s but has a strings value\n",
					hfinfo->name, hfinfo->abbrev,
					ftype_name(hfinfo->type));
			break;
	}
}

static void
register_type_length_mismatch(void)
{
	static ei_register_info ei[] = {
		{ &ei_type_length_mismatch_error, { "_ws.type_length.mismatch", PI_MALFORMED, PI_ERROR, "Trying to fetch X with length Y", EXPFILL }},
		{ &ei_type_length_mismatch_warn, { "_ws.type_length.mismatch", PI_MALFORMED, PI_WARN, "Trying to fetch X with length Y", EXPFILL }},
	};

	expert_module_t* expert_type_length_mismatch;

	proto_type_length_mismatch = proto_register_protocol("Type Length Mismatch", "Type length mismatch", "_ws.type_length");

	expert_type_length_mismatch = expert_register_protocol(proto_type_length_mismatch);
	expert_register_field_array(expert_type_length_mismatch, ei, array_length(ei));

	/* "Type Length Mismatch" isn't really a protocol, it's an error indication;
	   disabling them makes no sense. */
	proto_set_cant_toggle(proto_type_length_mismatch);
}

static void
register_number_string_decoding_error(void)
{
	static ei_register_info ei[] = {
		{ &ei_number_string_decoding_failed_error,
			{ "_ws.number_string.decoding_error.failed", PI_MALFORMED, PI_ERROR,
			  "Failed to decode number from string", EXPFILL
			}
		},
		{ &ei_number_string_decoding_erange_error,
			{ "_ws.number_string.decoding_error.erange", PI_MALFORMED, PI_ERROR,
			  "Decoded number from string is out of valid range", EXPFILL
			}
		},
	};

	expert_module_t* expert_number_string_decoding_error;

	proto_number_string_decoding_error =
		proto_register_protocol("Number-String Decoding Error",
					"Number-string decoding error",
					"_ws.number_string.decoding_error");

	expert_number_string_decoding_error =
		expert_register_protocol(proto_number_string_decoding_error);
	expert_register_field_array(expert_number_string_decoding_error, ei, array_length(ei));

	/* "Number-String Decoding Error" isn't really a protocol, it's an error indication;
	   disabling them makes no sense. */
	proto_set_cant_toggle(proto_number_string_decoding_error);
}

#define PROTO_PRE_ALLOC_HF_FIELDS_MEM (144000+PRE_ALLOC_EXPERT_FIELDS_MEM)
static int
proto_register_field_init(header_field_info *hfinfo, const int parent)
{

	tmp_fld_check_assert(hfinfo);

	hfinfo->parent         = parent;
	hfinfo->same_name_next = NULL;
	hfinfo->same_name_prev_id = -1;

	/* if we always add and never delete, then id == len - 1 is correct */
	if (gpa_hfinfo.len >= gpa_hfinfo.allocated_len) {
		if (!gpa_hfinfo.hfi) {
			gpa_hfinfo.allocated_len = PROTO_PRE_ALLOC_HF_FIELDS_MEM;
			gpa_hfinfo.hfi = (header_field_info **)g_malloc(sizeof(header_field_info *)*PROTO_PRE_ALLOC_HF_FIELDS_MEM);
		} else {
			gpa_hfinfo.allocated_len += 1000;
			gpa_hfinfo.hfi = (header_field_info **)g_realloc(gpa_hfinfo.hfi,
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

		g_hash_table_insert(gpa_name_map, (gpointer) (hfinfo->abbrev), hfinfo);
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
				same_name_next_hfinfo->same_name_prev_id = hfinfo->id;

			same_name_hfinfo->same_name_next = hfinfo;
			hfinfo->same_name_prev_id = same_name_hfinfo->id;
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
		tree_is_expanded = (guint32 *)g_realloc(tree_is_expanded, (1+((num_tree_types + num_indices)/32)) * sizeof(guint32));

		/* set new items to 0 */
		/* XXX, slow!!! optimize when needed (align 'i' to 32, and set rest of guint32 to 0) */
		for (i = num_tree_types; i < num_tree_types + num_indices; i++)
			tree_is_expanded[i >> 5] &= ~(1 << (i & 31));
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

static inline gsize
label_concat(char *label_str, gsize pos, const char *str)
{
	if (pos < ITEM_LABEL_LENGTH)
		pos += g_strlcpy(label_str + pos, str, ITEM_LABEL_LENGTH - pos);

	return pos;
}

static void
label_mark_truncated(char *label_str, gsize name_pos)
{
	static const char  trunc_str[] = " [truncated]";
	const size_t       trunc_len = sizeof(trunc_str)-1;
	gchar             *last_char;

	/* ..... field_name: dataaaaaaaaaaaaa
	 *                 |
	 *                 ^^^^^ name_pos
	 *
	 * ..... field_name [truncated]: dataaaaaaaaaaaaa
	 *
	 * name_pos==0 means that we have only data or only a field_name
	 */

	if (name_pos < ITEM_LABEL_LENGTH - trunc_len) {
		memmove(label_str + name_pos + trunc_len, label_str + name_pos, ITEM_LABEL_LENGTH - name_pos - trunc_len);
		memcpy(label_str + name_pos, trunc_str, trunc_len);

		/* in general, label_str is UTF-8
		   we can truncate it only at the beginning of a new character
		   we go backwards from the byte right after our buffer and
		    find the next starting byte of a UTF-8 character, this is
		    where we cut
		   there's no need to use g_utf8_find_prev_char(), the search
		    will always succeed since we copied trunc_str into the
		    buffer */
		last_char = g_utf8_prev_char(&label_str[ITEM_LABEL_LENGTH]);
		*last_char = '\0';

	} else if (name_pos < ITEM_LABEL_LENGTH)
		g_strlcpy(label_str + name_pos, trunc_str, ITEM_LABEL_LENGTH - name_pos);
}

static gsize
label_fill(char *label_str, gsize pos, const header_field_info *hfinfo, const char *text)
{
	gsize name_pos;

	/* "%s: %s", hfinfo->name, text */
	name_pos = pos = label_concat(label_str, pos, hfinfo->name);
	pos = label_concat(label_str, pos, ": ");
	pos = label_concat(label_str, pos, text ? text : "(null)");

	if (pos >= ITEM_LABEL_LENGTH) {
		/* Uh oh, we don't have enough room. Tell the user that the field is truncated. */
		label_mark_truncated(label_str, name_pos);
	}

	return pos;
}

static gsize
label_fill_descr(char *label_str, gsize pos, const header_field_info *hfinfo, const char *text, const char *descr)
{
	gsize name_pos;

	/* "%s: %s (%s)", hfinfo->name, text, descr */
	name_pos = pos = label_concat(label_str, pos, hfinfo->name);
	pos = label_concat(label_str, pos, ": ");
	pos = label_concat(label_str, pos, text ? text : "(null)");
	pos = label_concat(label_str, pos, " (");
	pos = label_concat(label_str, pos, descr ? descr : "(null)");
	pos = label_concat(label_str, pos, ")");

	if (pos >= ITEM_LABEL_LENGTH) {
		/* Uh oh, we don't have enough room. Tell the user that the field is truncated. */
		label_mark_truncated(label_str, name_pos);
	}

	return pos;
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
	address		   addr;
	char              *tmp;

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
			bytes = (guint8 *)fvalue_get(&fi->value);
			label_fill(label_str, 0, hfinfo,
					(bytes) ? bytes_to_ep_str(bytes, fvalue_length(&fi->value)) : "<MISSING>");
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
				fill_label_bitfield(fi, label_str, FALSE);
			} else {
				fill_label_number(fi, label_str, FALSE);
			}
			break;

		case FT_FRAMENUM:
			fill_label_number(fi, label_str, FALSE);
			break;

		case FT_UINT64:
			fill_label_number64(fi, label_str, FALSE);
			break;

		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
			if (hfinfo->bitmask) {
				fill_label_bitfield(fi, label_str, TRUE);
			} else {
				fill_label_number(fi, label_str, TRUE);
			}
			break;

		case FT_INT64:
			fill_label_number64(fi, label_str, TRUE);
			break;

		case FT_FLOAT:
			g_snprintf(label_str, ITEM_LABEL_LENGTH,
				   "%s: %." G_STRINGIFY(FLT_DIG) "g",
				   hfinfo->name, fvalue_get_floating(&fi->value));
			break;

		case FT_DOUBLE:
			g_snprintf(label_str, ITEM_LABEL_LENGTH,
				   "%s: %." G_STRINGIFY(DBL_DIG) "g",
				   hfinfo->name, fvalue_get_floating(&fi->value));
			break;

		case FT_ABSOLUTE_TIME:
			tmp = abs_time_to_str(NULL, (const nstime_t *)fvalue_get(&fi->value), (absolute_time_display_e)hfinfo->display, TRUE);
			label_fill(label_str, 0, hfinfo, tmp);
			wmem_free(NULL, tmp);
			break;

		case FT_RELATIVE_TIME:
			tmp = rel_time_to_secs_str(NULL, (const nstime_t *)fvalue_get(&fi->value));
			g_snprintf(label_str, ITEM_LABEL_LENGTH,
				   "%s: %s seconds", hfinfo->name, tmp);
			wmem_free(NULL, tmp);
			break;

		case FT_IPXNET:
			integer = fvalue_get_uinteger(&fi->value);
			g_snprintf(label_str, ITEM_LABEL_LENGTH,
				   "%s: %s (0x%08X)", hfinfo->name,
				   get_ipxnet_name(integer), integer);
			break;

		case FT_AX25:
			bytes = (guint8 *)fvalue_get(&fi->value);
			label_fill_descr(label_str, 0, hfinfo,
				   get_ax25_name(bytes),
				   ax25_to_str(bytes));
			break;

		case FT_VINES:
			addr.type = AT_VINES;
			addr.len  = VINES_ADDR_LEN;
			addr.data = (guint8 *)fvalue_get(&fi->value);

			g_snprintf(label_str, ITEM_LABEL_LENGTH,
				   "%s: %s", hfinfo->name,
				   ep_address_to_str( &addr ));
			break;

		case FT_ETHER:
			bytes = (guint8 *)fvalue_get(&fi->value);
			label_fill_descr(label_str, 0, hfinfo,
				   get_ether_name(bytes),
				   ether_to_str(bytes));
			break;

		case FT_IPv4:
			ipv4 = (ipv4_addr *)fvalue_get(&fi->value);
			n_addr = ipv4_get_net_order_addr(ipv4);
			label_fill_descr(label_str, 0, hfinfo,
				   get_hostname(n_addr),
				   ip_to_str((guint8*)&n_addr));
			break;

		case FT_IPv6:
			bytes = (guint8 *)fvalue_get(&fi->value);
			label_fill_descr(label_str, 0, hfinfo,
				   get_hostname6((struct e_in6_addr *)bytes),
				   ip6_to_str((struct e_in6_addr*)bytes));
			break;

		case FT_GUID:
			guid = (e_guid_t *)fvalue_get(&fi->value);
			label_fill(label_str, 0, hfinfo, guid_to_ep_str(guid));
			break;

		case FT_OID:
			bytes = (guint8 *)fvalue_get(&fi->value);
			name = oid_resolved_from_encoded(bytes, fvalue_length(&fi->value));
			if (name) {
				label_fill_descr(label_str, 0, hfinfo,
					 oid_encoded2string(bytes, fvalue_length(&fi->value)), name);
			} else {
				label_fill(label_str, 0, hfinfo,
					 oid_encoded2string(bytes, fvalue_length(&fi->value)));
			}
			break;

		case FT_REL_OID:
			bytes = (guint8 *)fvalue_get(&fi->value);
			name = rel_oid_resolved_from_encoded(bytes, fvalue_length(&fi->value));
			if (name) {
				label_fill_descr(label_str, 0, hfinfo,
					 rel_oid_encoded2string(bytes, fvalue_length(&fi->value)), name);
			} else {
				label_fill(label_str, 0, hfinfo,
					 rel_oid_encoded2string(bytes, fvalue_length(&fi->value)));
			}
			break;

		case FT_SYSTEM_ID:
			bytes = (guint8 *)fvalue_get(&fi->value);
			label_fill(label_str, 0, hfinfo, print_system_id(bytes, fvalue_length(&fi->value)));
			break;

		case FT_EUI64:
			integer64 = fvalue_get_integer64(&fi->value);
			label_fill_descr(label_str, 0, hfinfo,
				   ep_eui64_to_display(integer64),
				   eui64_to_str(integer64));
			break;
		case FT_STRING:
		case FT_STRINGZ:
		case FT_UINT_STRING:
		case FT_STRINGZPAD:
			bytes = (guint8 *)fvalue_get(&fi->value);
			label_fill(label_str, 0, hfinfo, hfinfo_format_text(hfinfo, bytes));
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
		unshifted_value <<= hfinfo_bitshift(hfinfo);

		/* Create the bitfield first */
		p = decode_bitfield_value(label_str, unshifted_value, hfinfo->bitmask, bitwidth);
		bitfield_byte_length = (int) (p - label_str);
	}

	/* Fill in the textual info */
	label_fill(label_str, bitfield_byte_length, hfinfo, value ? tfstring->true_string : tfstring->false_string);
}

static const char *
hf_try_val_to_str(guint32 value, const header_field_info *hfinfo)
{
	if (hfinfo->display & BASE_RANGE_STRING)
		return try_rval_to_str(value, (const range_string *) hfinfo->strings);

	if (hfinfo->display & BASE_EXT_STRING)
		return try_val_to_str_ext(value, (const value_string_ext *) hfinfo->strings);

	if (hfinfo->display & BASE_VAL64_STRING)
		return try_val64_to_str(value, (const val64_string *) hfinfo->strings);

	return try_val_to_str(value, (const value_string *) hfinfo->strings);
}

static const char *
hf_try_val64_to_str(guint64 value, const header_field_info *hfinfo)
{
	if (hfinfo->display & BASE_VAL64_STRING)
		return try_val64_to_str(value, (const val64_string *) hfinfo->strings);

	/* If this is reached somebody registered a 64-bit field with a 32-bit
	 * value-string, which isn't right. */
	DISSECTOR_ASSERT_NOT_REACHED();

	/* This is necessary to squelch MSVC errors; is there
	   any way to tell it that DISSECTOR_ASSERT_NOT_REACHED()
	   never returns? */
	return NULL;
}

static const char *
hf_try_val_to_str_const(guint32 value, const header_field_info *hfinfo, const char *unknown_str)
{
	const char *str = hf_try_val_to_str(value, hfinfo);

	return (str) ? str : unknown_str;
}

static const char *
hf_try_val64_to_str_const(guint64 value, const header_field_info *hfinfo, const char *unknown_str)
{
	const char *str = hf_try_val64_to_str(value, hfinfo);

	return (str) ? str : unknown_str;
}

/* Fills data for bitfield ints with val_strings */
static void
fill_label_bitfield(field_info *fi, gchar *label_str, gboolean is_signed)
{
	char       *p;
	int         bitfield_byte_length, bitwidth;
	guint32     unshifted_value;
	guint32     value;

	char        buf[32];
	const char *out;

	header_field_info *hfinfo = fi->hfinfo;

	/* Figure out the bit width */
	bitwidth = hfinfo_bitwidth(hfinfo);

	/* Un-shift bits */
	if (is_signed)
		unshifted_value = fvalue_get_sinteger(&fi->value);
	else
		unshifted_value = fvalue_get_uinteger(&fi->value);

	value = unshifted_value;
	if (hfinfo->bitmask) {
		unshifted_value <<= hfinfo_bitshift(hfinfo);
	}

	/* Create the bitfield first */
	p = decode_bitfield_value(label_str, unshifted_value, hfinfo->bitmask, bitwidth);
	bitfield_byte_length = (int) (p - label_str);

	/* Fill in the textual info using stored (shifted) value */
	if (hfinfo->display == BASE_CUSTOM) {
		gchar tmp[ITEM_LABEL_LENGTH];
		const custom_fmt_func_t fmtfunc = (const custom_fmt_func_t)hfinfo->strings;

		DISSECTOR_ASSERT(fmtfunc);
		fmtfunc(tmp, value);
		label_fill(label_str, bitfield_byte_length, hfinfo, tmp);
	}
	else if (hfinfo->strings) {
		const char *val_str = hf_try_val_to_str_const(value, hfinfo, "Unknown");

		out = hfinfo_number_vals_format(hfinfo, buf, value);
		if (out == NULL) /* BASE_NONE so don't put integer in descr */
			label_fill(label_str, bitfield_byte_length, hfinfo, val_str);
		else
			label_fill_descr(label_str, bitfield_byte_length, hfinfo, val_str, out);
	}
	else {
		out = hfinfo_number_value_format(hfinfo, buf, value);

		label_fill(label_str, bitfield_byte_length, hfinfo, out);
	}
}

static void
fill_label_number(field_info *fi, gchar *label_str, gboolean is_signed)
{
	header_field_info *hfinfo = fi->hfinfo;
	guint32            value;

	char               buf[32];
	const char        *out;

	if (is_signed)
		value = fvalue_get_sinteger(&fi->value);
	else
		value = fvalue_get_uinteger(&fi->value);

	/* Fill in the textual info */
	if (hfinfo->display == BASE_CUSTOM) {
		gchar tmp[ITEM_LABEL_LENGTH];
		const custom_fmt_func_t fmtfunc = (const custom_fmt_func_t)hfinfo->strings;

		DISSECTOR_ASSERT(fmtfunc);
		fmtfunc(tmp, value);
		label_fill(label_str, 0, hfinfo, tmp);
	}
	else if (hfinfo->strings) {
		const char *val_str = hf_try_val_to_str_const(value, hfinfo, "Unknown");

		out = hfinfo_number_vals_format(hfinfo, buf, value);
		if (out == NULL) /* BASE_NONE so don't put integer in descr */
			label_fill(label_str, 0, hfinfo, val_str);
		else
			label_fill_descr(label_str, 0, hfinfo, val_str, out);
	}
	else {
		out = hfinfo_number_value_format(hfinfo, buf, value);

		label_fill(label_str, 0, hfinfo, out);
	}
}

static void
fill_label_number64(field_info *fi, gchar *label_str, gboolean is_signed)
{
	const char        *format = NULL;
	header_field_info *hfinfo = fi->hfinfo;
	guint64            value;
	char               tmp[ITEM_LABEL_LENGTH+1];

	/* Pick the proper format string */
	if (is_signed)
		format = hfinfo_int64_format(hfinfo);
	else
		format = hfinfo_uint64_format(hfinfo);

	value = fvalue_get_integer64(&fi->value);

	/* Format the temporary string */
	if (IS_BASE_DUAL(hfinfo->display))
		g_snprintf(tmp, ITEM_LABEL_LENGTH, format, value, value);
	else
		g_snprintf(tmp, ITEM_LABEL_LENGTH, format, value);

	if (hfinfo->strings) {
		const char *val_str = hf_try_val64_to_str_const(value, hfinfo, "Unknown");

		if ((hfinfo->display & FIELD_DISPLAY_E_MASK) == BASE_NONE) {
			label_fill(label_str, 0, hfinfo, val_str);
		}
		else {
			label_fill_descr(label_str, 0, hfinfo, val_str, tmp);
		}
	}
	else {
		label_fill(label_str, 0, hfinfo, tmp);
	}
}

int
hfinfo_bitshift(const header_field_info *hfinfo)
{
	return ws_ctz(hfinfo->bitmask);
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

static int
_hfinfo_type_hex_octet(int type)
{
	switch (type) {
		case FT_INT8:
		case FT_UINT8:
			return 2;

		case FT_UINT16:
		case FT_INT16:
			return 4;

		case FT_UINT24:
		case FT_INT24:
			return 6;

		case FT_UINT32:
		case FT_INT32:
			return 8;

		default:
			DISSECTOR_ASSERT_NOT_REACHED();
			;
	}
	return -1;
}

static const char *
hfinfo_number_value_format_display(const header_field_info *hfinfo, int display, char buf[32], guint32 value)
{
	char *ptr = &buf[31];
	gboolean isint = IS_FT_INT(hfinfo->type);

	*ptr = '\0';
	/* Properly format value */
		switch (display) {
			case BASE_DEC:
				return isint ? int_to_str_back(ptr, (gint32) value) : uint_to_str_back(ptr, value);

			case BASE_DEC_HEX:
				*(--ptr) = ')';
				ptr = hex_to_str_back(ptr, _hfinfo_type_hex_octet(hfinfo->type), value);
				*(--ptr) = '(';
				*(--ptr) = ' ';
				ptr = isint ? int_to_str_back(ptr, (gint32) value) : uint_to_str_back(ptr, value);
				return ptr;

			case BASE_OCT:
				return oct_to_str_back(ptr, value);

			case BASE_HEX:
				return hex_to_str_back(ptr, _hfinfo_type_hex_octet(hfinfo->type), value);

			case BASE_HEX_DEC:
				*(--ptr) = ')';
				ptr = isint ? int_to_str_back(ptr, (gint32) value) : uint_to_str_back(ptr, value);
				*(--ptr) = '(';
				*(--ptr) = ' ';
				ptr = hex_to_str_back(ptr, _hfinfo_type_hex_octet(hfinfo->type), value);
				return ptr;

			default:
				DISSECTOR_ASSERT_NOT_REACHED();
				;
		}
	return ptr;
}

static const char *
hfinfo_number_value_format(const header_field_info *hfinfo, char buf[32], guint32 value)
{
	int display = hfinfo->display;

	if (hfinfo->type == FT_FRAMENUM) {
		/*
		 * Frame numbers are always displayed in decimal.
		 */
		display = BASE_DEC;
	}

	return hfinfo_number_value_format_display(hfinfo, display, buf, value);
}

static const char *
hfinfo_numeric_value_format(const header_field_info *hfinfo, char buf[32], guint32 value)
{
	/* Get the underlying BASE_ value */
	int display = hfinfo->display & FIELD_DISPLAY_E_MASK;

	if (hfinfo->type == FT_FRAMENUM) {
		/*
		 * Frame numbers are always displayed in decimal.
		 */
		display = BASE_DEC;
	}

	switch (display) {
		case BASE_NONE:
		/* case BASE_DEC: */
		case BASE_DEC_HEX:
		case BASE_OCT: /* XXX, why we're changing BASE_OCT to BASE_DEC? */
		case BASE_CUSTOM:
			display = BASE_DEC;
			break;

		/* case BASE_HEX: */
		case BASE_HEX_DEC:
			display = BASE_HEX;
			break;
	}

	return hfinfo_number_value_format_display(hfinfo, display, buf, value);
}

static const char *
hfinfo_number_vals_format(const header_field_info *hfinfo, char buf[32], guint32 value)
{
	/* Get the underlying BASE_ value */
	int display = hfinfo->display & FIELD_DISPLAY_E_MASK;

	if (display == BASE_NONE)
		return NULL;

	if (display == BASE_DEC_HEX)
		display = BASE_DEC;
	if (display == BASE_HEX_DEC)
		display = BASE_HEX;

	return hfinfo_number_value_format_display(hfinfo, display, buf, value);
}

static const char *
hfinfo_uint64_format(const header_field_info *hfinfo)
{
	const char *format = NULL;

	/* Pick the proper format string */
	switch (hfinfo->display & FIELD_DISPLAY_E_MASK) {
		case BASE_DEC:
			format = "%" G_GINT64_MODIFIER "u";
			break;
		case BASE_DEC_HEX:
			format = "%" G_GINT64_MODIFIER "u (0x%016" G_GINT64_MODIFIER "x)";
			break;
		case BASE_OCT: /* I'm lazy */
			format = "%#" G_GINT64_MODIFIER "o";
			break;
		case BASE_HEX:
			format = "0x%016" G_GINT64_MODIFIER "x";
			break;
		case BASE_HEX_DEC:
			format = "0x%016" G_GINT64_MODIFIER "x (%" G_GINT64_MODIFIER "u)";
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
	switch (hfinfo->display & FIELD_DISPLAY_E_MASK) {
		case BASE_DEC:
			format = "%" G_GINT64_MODIFIER "d";
			break;
		case BASE_DEC_HEX:
			format = "%" G_GINT64_MODIFIER "d (0x%016" G_GINT64_MODIFIER "x)";
			break;
		case BASE_OCT: /* I'm lazy */
			format = "%#" G_GINT64_MODIFIER "o";
			break;
		case BASE_HEX:
			format = "0x%016" G_GINT64_MODIFIER "x";
			break;
		case BASE_HEX_DEC:
			format = "0x%016" G_GINT64_MODIFIER "x (%" G_GINT64_MODIFIER "d)";
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

enum ftenum
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
		return (GPtrArray *)g_hash_table_lookup(PTREE_DATA(tree)->interesting_hfids,
					   GINT_TO_POINTER(id));
	else
		return NULL;
}

gboolean
proto_tracking_interesting_fields(const proto_tree *tree)
{
	GHashTable *interesting_hfids;

	if (!tree)
		return FALSE;

	interesting_hfids = PTREE_DATA(tree)->interesting_hfids;

	return (interesting_hfids != NULL) && g_hash_table_size(interesting_hfids);
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
	offset_search_t	*offsearch = (offset_search_t *)data;

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


	i = proto_get_first_protocol(&cookie);
	while (i != -1) {
		protocol = find_protocol_by_id(i);
		printf("%s\t%s\t%s\n", protocol->name, protocol->short_name,
			protocol->filter_name);
		i = proto_get_next_protocol(&cookie);
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
	const val64_string	*vals64;
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
			if (hfinfo->same_name_prev_id != -1)
				continue;

			vals   = NULL;
			vals64 = NULL;
			range  = NULL;
			tfs    = NULL;

			if (hfinfo->strings != NULL) {
				if ((hfinfo->display & FIELD_DISPLAY_E_MASK) != BASE_CUSTOM &&
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

					if (hfinfo->display & BASE_RANGE_STRING) {
						range = (const range_string *)hfinfo->strings;
					} else if (hfinfo->display & BASE_EXT_STRING) {
						vals = VALUE_STRING_EXT_VS_P((const value_string_ext *)hfinfo->strings);
					} else if (hfinfo->display & BASE_VAL64_STRING) {
						vals64 = (const val64_string *)hfinfo->strings;
					} else {
						vals = (const value_string *)hfinfo->strings;
					}
				}
				else if (hfinfo->type == FT_BOOLEAN) {
					tfs = (const struct true_false_string *)hfinfo->strings;
				}
			}

			/* Print value strings? */
			if (vals) {
				if (hfinfo->display & BASE_EXT_STRING) {
					const value_string_ext *vse_p = (const value_string_ext *)hfinfo->strings;
					if (!value_string_ext_validate(vse_p)) {
						g_warning("Invalid value_string_ext ptr for: %s", hfinfo->abbrev);
						continue;
					}
					try_val_to_str_ext(0, vse_p); /* "prime" the extended value_string */
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
			else if (vals64) {
				vi = 0;
				while (vals64[vi].strptr) {
					printf("V64\t%s\t%" G_GINT64_MODIFIER "u\t%s\n",
						hfinfo->abbrev,
						vals64[vi].value,
						vals64[vi].strptr);
					vi++;
				}
			}

			/* print range strings? */
			else if (range) {
				vi = 0;
				while (range[vi].strptr) {
					/* Print in the proper base */
					if ((hfinfo->display & FIELD_DISPLAY_E_MASK) == BASE_HEX) {
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
 * Field 1 = 'F'
 * Field 2 = descriptive field name
 * Field 3 = field abbreviation
 * Field 4 = type ( textual representation of the the ftenum type )
 * Field 5 = parent protocol abbreviation
 * Field 6 = base for display (for integer types); "parent bitfield width" for FT_BOOLEAN
 * Field 7 = bitmask: format: hex: 0x....
 * Field 8 = blurb describing field
 */
void
proto_registrar_dump_fields(void)
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
			if (hfinfo->same_name_prev_id != -1)
				continue;

			PROTO_REGISTRAR_GET_NTH(hfinfo->parent, parent_hfinfo);

			enum_name = ftype_name(hfinfo->type);
			base_name = "";

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

				switch (hfinfo->display & FIELD_DISPLAY_E_MASK) {
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

			blurb = hfinfo->blurb;
			if (blurb == NULL)
				blurb = "";
			else if (strlen(blurb) == 0)
				blurb = "\"\"";

			printf("F\t%s\t%s\t%s\t%s\t%s\t0x%x\t%s\n",
				hfinfo->name, hfinfo->abbrev, enum_name,
				parent_hfinfo->abbrev, base_name, hfinfo->bitmask, blurb);
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
	int fte;

	for (fte = 0; fte < FT_NUM_TYPES; fte++) {
		printf("%s\t%s\n", ftype_name((ftenum_t)fte), ftype_pretty_name((ftenum_t)fte));
	}
}

static const char *
hfinfo_numeric_format(const header_field_info *hfinfo)
{
	const char *format = NULL;

	/* Get the underlying BASE_ value */
	switch (hfinfo->display & FIELD_DISPLAY_E_MASK) {
		case BASE_DEC:
		case BASE_DEC_HEX:
		case BASE_OCT: /* I'm lazy */
		case BASE_CUSTOM:
			switch (hfinfo->type) {
				case FT_UINT64:
					format = "%s == %" G_GINT64_MODIFIER "u";
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
	int		   dfilter_len, i;
	gint		   start, length, length_remaining;
	guint8		   c;
	gchar		   is_signed_num = FALSE;

	if (!finfo)
		return FALSE;

	hfinfo     = finfo->hfinfo;
	DISSECTOR_ASSERT(hfinfo);
	abbrev_len = (int) strlen(hfinfo->abbrev);

	if (hfinfo->strings && (hfinfo->display & FIELD_DISPLAY_E_MASK) == BASE_NONE) {
		const gchar *str = NULL;

		switch (hfinfo->type) {

		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
			str = hf_try_val_to_str(fvalue_get_sinteger(&finfo->value), hfinfo);
			break;

		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
			str = hf_try_val_to_str(fvalue_get_uinteger(&finfo->value), hfinfo);
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
		case FT_FRAMENUM:
			if (filter != NULL) {
				guint32 number;

				char buf[32];
				const char *out;

				if (is_signed_num)
					number = fvalue_get_sinteger(&finfo->value);
				else
					number = fvalue_get_uinteger(&finfo->value);

				out = hfinfo_numeric_value_format(hfinfo, buf, number);

				*filter = ep_strdup_printf("%s == %s", hfinfo->abbrev, out);
			}
			break;

		case FT_INT64:
		case FT_UINT64:
			if (filter != NULL) {
				const char *format = hfinfo_numeric_format(hfinfo);

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
			length_remaining = tvb_captured_length_remaining(finfo->ds_tvb, finfo->start);
			if (length > length_remaining)
				length = length_remaining;
			if (length <= 0)
				return FALSE;

			if (filter != NULL) {
				start = finfo->start;
				buf_len = 32 + length * 3;
				*filter = (char *)ep_alloc0(buf_len);
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
				*filter = (char *)ep_alloc0(dfilter_len);

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
	guint32            available_bits = 0;
	guint32            tmpval;
	proto_tree        *tree  = NULL;
	header_field_info *hf;

	switch (len) {
		case 1:
			value = tvb_get_guint8(tvb, offset);
			available_bits = 0xFF;
			break;
		case 2:
			value = encoding ? tvb_get_letohs(tvb, offset) :
			tvb_get_ntohs(tvb, offset);
			available_bits = 0xFFFF;
			break;
		case 3:
			value = encoding ? tvb_get_letoh24(tvb, offset) :
			tvb_get_ntoh24(tvb, offset);
			available_bits = 0xFFFFFF;
			break;
		case 4:
			value = encoding ? tvb_get_letohl(tvb, offset) :
			tvb_get_ntohl(tvb, offset);
			available_bits = 0xFFFFFFFF;
			break;
		default:
			g_assert_not_reached();
	}

	tree = proto_item_add_subtree(item, ett);
	while (*fields) {
		guint32 present_bits;
		PROTO_REGISTRAR_GET_NTH(**fields,hf);
		DISSECTOR_ASSERT(hf->bitmask != 0);

		/* Skip fields that aren't fully present */
		present_bits = available_bits & hf->bitmask;
		if (present_bits != hf->bitmask) {
			fields++;
			continue;
		}

		proto_tree_add_item(tree, **fields, tvb, offset, len, encoding);
		if (flags & BMT_NO_APPEND) {
			fields++;
			continue;
		}
		tmpval = (value & hf->bitmask) >> hfinfo_bitshift(hf);

		switch (hf->type) {
		case FT_INT8:
		case FT_UINT8:
		case FT_INT16:
		case FT_UINT16:
		case FT_INT24:
		case FT_UINT24:
		case FT_INT32:
		case FT_UINT32:
			if (hf->display == BASE_CUSTOM) {
				gchar lbl[ITEM_LABEL_LENGTH];
				const custom_fmt_func_t fmtfunc = (const custom_fmt_func_t)hf->strings;

				DISSECTOR_ASSERT(fmtfunc);
				fmtfunc(lbl, tmpval);
				proto_item_append_text(item, "%s%s: %s", first ? "" : ", ",
						hf->name, lbl);
				first = FALSE;
			}
			else if (hf->strings) {
				proto_item_append_text(item, "%s%s: %s", first ? "" : ", ",
						       hf->name, hf_try_val_to_str_const(tmpval, hf, "Unknown"));
				first = FALSE;
			}
			else if (!(flags & BMT_NO_INT)) {
				char buf[32];
				const char *out;

				if (!first) {
					proto_item_append_text(item, ", ");
				}

				out = hfinfo_number_value_format(hf, buf, tmpval);
				proto_item_append_text(item, "%s: %s", hf->name, out);
				first = FALSE;
			}

			break;
		case FT_BOOLEAN:
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

	PROTO_REGISTRAR_GET_NTH(hf_hdr,hf);
	DISSECTOR_ASSERT(IS_FT_INT(hf->type) || IS_FT_UINT(hf->type));
	len = ftype_length(hf->type);

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_hdr, tvb, offset, len, encoding);
		proto_item_add_bitmask_tree(item, tvb, offset, len, ett, fields, encoding,
					    BMT_NO_INT|BMT_NO_TFS, FALSE);
	}

	return item;
}

/* The same as proto_tree_add_bitmask(), but using a caller-supplied length.
 * This is intended to support bitmask fields whose lengths can vary, perhaps
 * as the underlying standard evolves over time.
 * With this API there is the possibility of being called to display more or
 * less data than the dissector was coded to support.
 * In such cases, it is assumed that bitmasks are extended on the MSb end.
 * Thus when presented with "too much" or "too little" data, MSbits will be
 * ignored or MSfields sacrificed.
 *
 * Only fields for which all defined bits are available are displayed.
 */
proto_item *
proto_tree_add_bitmask_len(proto_tree *parent_tree, tvbuff_t *tvb,
		       const guint offset,  const guint len, const int hf_hdr,
		       const gint ett, const int **fields, struct expert_field* exp,
		       const guint encoding)
{
	proto_item        *item = NULL;
	header_field_info *hf;
	guint   decodable_len;
	guint   decodable_offset;
	guint32 decodable_value;

	PROTO_REGISTRAR_GET_NTH(hf_hdr, hf);
	DISSECTOR_ASSERT(IS_FT_INT(hf->type) || IS_FT_UINT(hf->type));

	decodable_offset = offset;
	decodable_len = MIN(len, (guint) ftype_length(hf->type));

	/* If we are ftype_length-limited,
	 * make sure we decode as many LSBs as possible.
	 */
	if (encoding == ENC_BIG_ENDIAN) {
		decodable_offset += (len - decodable_len);
	}

	if (parent_tree) {
		decodable_value = get_uint_value(parent_tree, tvb, decodable_offset,
						 decodable_len, encoding);

		/* The root item covers all the bytes even if we can't decode them all */
		item = proto_tree_add_uint(parent_tree, hf_hdr, tvb, offset, len,
					   decodable_value);
	}

	if (decodable_len < len) {
		/* Dissector likely requires updating for new protocol revision */
		expert_add_info_format(NULL, item, exp,
				       "Only least-significant %d of %d bytes decoded",
				       decodable_len, len);
	}

	if (item) {
		proto_item_add_bitmask_tree(item, tvb, decodable_offset, decodable_len,
					    ett, fields, encoding, BMT_NO_INT|BMT_NO_TFS, FALSE);
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
proto_tree_add_bits_item(proto_tree *tree, const int hfindex, tvbuff_t *tvb,
			 const guint bit_offset, const gint no_of_bits,
			 const guint encoding)
{
	header_field_info *hfinfo;
	gint		   octet_length;
	gint		   octet_offset;

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);

	octet_length = (no_of_bits + 7) >> 3;
	octet_offset = bit_offset >> 3;
	test_length(hfinfo, tvb, octet_offset, octet_length);

	/* Yes, we try to fake this item again in proto_tree_add_bits_ret_val()
	 * but only after doing a bunch more work (which we can, in the common
	 * case, shortcut here).
	 */
	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	return proto_tree_add_bits_ret_val(tree, hfindex, tvb, bit_offset, no_of_bits, NULL, encoding);
}

/*
 * This function will dissect a sequence of bits that does not need to be byte aligned; the bits
 * set will be shown in the tree as ..10 10.. and the integer value returned if return_value is set.
 * Offset should be given in bits from the start of the tvb.
 */

static proto_item *
_proto_tree_add_bits_ret_val(proto_tree *tree, const int hfindex, tvbuff_t *tvb,
			    const guint bit_offset, const gint no_of_bits,
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
	PROTO_REGISTRAR_GET_NTH(hfindex, hf_field);

	if (hf_field->bitmask != 0) {
		REPORT_DISSECTOR_BUG(ep_strdup_printf("Incompatible use of proto_tree_add_bits_ret_val"
						      " with field '%s' (%s) with bitmask != 0",
						      hf_field->abbrev, hf_field->name));
	}

	DISSECTOR_ASSERT(no_of_bits >  0);

	/* Byte align offset */
	offset = bit_offset>>3;

	/*
	 * Calculate the number of octets used to hold the bits
	 */
	tot_no_bits = ((bit_offset&0x7) + no_of_bits);
	length = (tot_no_bits + 7) >> 3;

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
			value = ws_sign_ext64(value, no_of_bits);
			break;

		default:
			break;
	}

	if (return_value) {
		*return_value = value;
	}

	/* Coast clear. Try and fake it */
	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hf_field);

	bf_str = decode_bits_in_field(bit_offset, no_of_bits, value);

	switch (hf_field->type) {
	case FT_BOOLEAN:
		/* Boolean field */
		tfstring = (const true_false_string *) &tfs_true_false;
		if (hf_field->strings)
			tfstring = (const true_false_string *)hf_field->strings;
		return proto_tree_add_boolean_format(tree, hfindex, tvb, offset, length, (guint32)value,
			"%s = %s: %s",
			bf_str, hf_field->name,
			(guint32)value ? tfstring->true_string : tfstring->false_string);
		break;

	case FT_UINT8:
	case FT_UINT16:
	case FT_UINT24:
	case FT_UINT32:
		pi = proto_tree_add_uint(tree, hfindex, tvb, offset, length, (guint32)value);
		fill_label_number(PITEM_FINFO(pi), lbl_str, FALSE);
		break;

	case FT_INT8:
	case FT_INT16:
	case FT_INT24:
	case FT_INT32:
		pi = proto_tree_add_int(tree, hfindex, tvb, offset, length, (gint32)value);
		fill_label_number(PITEM_FINFO(pi), lbl_str, TRUE);
		break;

	case FT_UINT64:
		pi = proto_tree_add_uint64(tree, hfindex, tvb, offset, length, value);
		fill_label_number64(PITEM_FINFO(pi), lbl_str, FALSE);
		break;

	case FT_INT64:
		pi = proto_tree_add_int64(tree, hfindex, tvb, offset, length, (gint64)value);
		fill_label_number64(PITEM_FINFO(pi), lbl_str, TRUE);
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
proto_tree_add_split_bits_item_ret_val(proto_tree *tree, const int hfindex, tvbuff_t *tvb,
				       const guint bit_offset, const crumb_spec_t *crumb_spec,
				       guint64 *return_value)
{
	proto_item *pi;
	gint        no_of_bits;
	gint        octet_offset;
	guint       mask_initial_bit_offset;
	guint       mask_greatest_bit_offset;
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
	PROTO_REGISTRAR_GET_NTH(hfindex, hf_field);

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
			crumb_mask = (G_GUINT64_CONSTANT(1) << crumb_spec[i].crumb_bit_length) - 1;

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
			value = ws_sign_ext64(value, no_of_bits);
			break;
		default:
			break;
	}

	if (return_value) {
		*return_value = value;
	}

	/* Coast clear. Try and fake it */
	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hf_field);

	/* initialise the format string */
	bf_str    = (char *)ep_alloc(256);
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
		return proto_tree_add_boolean_format(tree, hfindex,
						     tvb, octet_offset, octet_length, (guint32)value,
						     "%s = %s: %s",
						     bf_str, hf_field->name,
						     (guint32)value ? tfstring->true_string : tfstring->false_string);
		break;

	case FT_UINT8:
	case FT_UINT16:
	case FT_UINT24:
	case FT_UINT32:
		pi = proto_tree_add_uint(tree, hfindex, tvb, octet_offset, octet_length, (guint32)value);
		fill_label_number(PITEM_FINFO(pi), lbl_str, FALSE);
		break;

	case FT_INT8:
	case FT_INT16:
	case FT_INT24:
	case FT_INT32:
		pi = proto_tree_add_int(tree, hfindex, tvb, octet_offset, octet_length, (gint32)value);
		fill_label_number(PITEM_FINFO(pi), lbl_str, TRUE);
		break;

	case FT_UINT64:
		pi = proto_tree_add_uint64(tree, hfindex, tvb, octet_offset, octet_length, value);
		fill_label_number64(PITEM_FINFO(pi), lbl_str, FALSE);
		break;

	case FT_INT64:
		pi = proto_tree_add_int64(tree, hfindex, tvb, octet_offset, octet_length, (gint64)value);
		fill_label_number64(PITEM_FINFO(pi), lbl_str, TRUE);
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
proto_tree_add_split_bits_crumb(proto_tree *tree, const int hfindex, tvbuff_t *tvb, const guint bit_offset,
				const crumb_spec_t *crumb_spec, guint16 crumb_index)
{
	header_field_info *hfinfo;

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);
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
			    hfinfo->name);
}

proto_item *
proto_tree_add_bits_ret_val(proto_tree *tree, const int hfindex, tvbuff_t *tvb,
			    const guint bit_offset, const gint no_of_bits,
			    guint64 *return_value, const guint encoding)
{
	proto_item *item;

	if ((item = _proto_tree_add_bits_ret_val(tree, hfindex, tvb,
						 bit_offset, no_of_bits,
						 return_value, encoding))) {
		FI_SET_FLAG(PNODE_FINFO(item), FI_BITS_OFFSET(bit_offset));
		FI_SET_FLAG(PNODE_FINFO(item), FI_BITS_SIZE(no_of_bits));
	}
	return item;
}

static proto_item *
_proto_tree_add_bits_format_value(proto_tree *tree, const int hfindex,
				 tvbuff_t *tvb, const guint bit_offset,
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
	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hf_field);

	if (hf_field->bitmask != 0) {
		REPORT_DISSECTOR_BUG(ep_strdup_printf(
					     "Incompatible use of proto_tree_add_bits_format_value"
					     " with field '%s' (%s) with bitmask != 0",
					     hf_field->abbrev, hf_field->name));
	}

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

	g_strlcat(str, " = ", 256+64);
	g_strlcat(str, hf_field->name, 256+64);

	/*
	 * This function does not receive an actual value but a dimensionless pointer to that value.
	 * For this reason, the type of the header field is examined in order to determine
	 * what kind of value we should read from this address.
	 * The caller of this function must make sure that for the specific header field type the address of
	 * a compatible value is provided.
	 */
	switch (hf_field->type) {
	case FT_BOOLEAN:
		return proto_tree_add_boolean_format(tree, hfindex, tvb, offset, length, *(guint32 *)value_ptr,
						     "%s: %s", str, value_str);
		break;

	case FT_UINT8:
	case FT_UINT16:
	case FT_UINT24:
	case FT_UINT32:
		return proto_tree_add_uint_format(tree, hfindex, tvb, offset, length, *(guint32 *)value_ptr,
						  "%s: %s", str, value_str);
		break;

	case FT_UINT64:
		return proto_tree_add_uint64_format(tree, hfindex, tvb, offset, length, *(guint64 *)value_ptr,
						    "%s: %s", str, value_str);
		break;

	case FT_INT8:
	case FT_INT16:
	case FT_INT24:
	case FT_INT32:
		return proto_tree_add_int_format(tree, hfindex, tvb, offset, length, *(gint32 *)value_ptr,
						 "%s: %s", str, value_str);
		break;

	case FT_INT64:
		return proto_tree_add_int64_format(tree, hfindex, tvb, offset, length, *(gint64 *)value_ptr,
						   "%s: %s", str, value_str);
		break;

	case FT_FLOAT:
		return proto_tree_add_float_format(tree, hfindex, tvb, offset, length, *(float *)value_ptr,
						   "%s: %s", str, value_str);
		break;

	default:
		DISSECTOR_ASSERT_NOT_REACHED();
		return NULL;
		break;
	}
}

static proto_item *
proto_tree_add_bits_format_value(proto_tree *tree, const int hfindex,
				 tvbuff_t *tvb, const guint bit_offset,
				 const gint no_of_bits, void *value_ptr,
				 gchar *value_str)
{
	proto_item *item;

	if ((item = _proto_tree_add_bits_format_value(tree, hfindex,
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
proto_tree_add_uint_bits_format_value(proto_tree *tree, const int hfindex,
				      tvbuff_t *tvb, const guint bit_offset,
				      const gint no_of_bits, guint32 value,
				      const char *format, ...)
{
	va_list ap;
	gchar  *dst;
	header_field_info *hf_field;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hf_field);

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

	return proto_tree_add_bits_format_value(tree, hfindex, tvb, bit_offset, no_of_bits, &value, dst);
}

proto_item *
proto_tree_add_float_bits_format_value(proto_tree *tree, const int hfindex,
				       tvbuff_t *tvb, const guint bit_offset,
				       const gint no_of_bits, float value,
				       const char *format, ...)
{
	va_list ap;
	gchar  *dst;
	header_field_info *hf_field;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hf_field);

	DISSECTOR_ASSERT(hf_field->type == FT_FLOAT);

	CREATE_VALUE_STRING(dst, format, ap);

	return proto_tree_add_bits_format_value(tree, hfindex, tvb, bit_offset, no_of_bits, &value, dst);
}

proto_item *
proto_tree_add_int_bits_format_value(proto_tree *tree, const int hfindex,
				     tvbuff_t *tvb, const guint bit_offset,
				     const gint no_of_bits, gint32 value,
				     const char *format, ...)
{
	va_list ap;
	gchar  *dst;
	header_field_info *hf_field;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hf_field);

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

	return proto_tree_add_bits_format_value(tree, hfindex, tvb, bit_offset, no_of_bits, &value, dst);
}

proto_item *
proto_tree_add_boolean_bits_format_value(proto_tree *tree, const int hfindex,
					 tvbuff_t *tvb, const guint bit_offset,
					 const gint no_of_bits, guint32 value,
					 const char *format, ...)
{
	va_list ap;
	gchar  *dst;
	header_field_info *hf_field;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hf_field);

	DISSECTOR_ASSERT(hf_field->type == FT_BOOLEAN);

	CREATE_VALUE_STRING(dst, format, ap);

	return proto_tree_add_bits_format_value(tree, hfindex, tvb, bit_offset, no_of_bits, &value, dst);
}

proto_item *
proto_tree_add_ts_23_038_7bits_item(proto_tree *tree, const int hfindex, tvbuff_t *tvb,
	const guint bit_offset, const gint no_of_chars)
{
	proto_item	  *pi;
	header_field_info *hfinfo;
	gint		   byte_length;
	gint		   byte_offset;
	gchar		  *string;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT(hfinfo->type == FT_STRING);

	byte_length = (((no_of_chars + 1) * 7) + (bit_offset & 0x07)) >> 3;
	byte_offset = bit_offset >> 3;

	string = tvb_get_ts_23_038_7bits_string(wmem_packet_scope(), tvb, bit_offset, no_of_chars);

	if (hfinfo->display == STR_UNICODE) {
		DISSECTOR_ASSERT(g_utf8_validate(string, -1, NULL));
	}

	pi = proto_tree_add_pi(tree, hfinfo, tvb, byte_offset, &byte_length);
	DISSECTOR_ASSERT(byte_length >= 0);
	proto_tree_set_string(PNODE_FINFO(pi), string);

	return pi;
}

proto_item *
proto_tree_add_ascii_7bits_item(proto_tree *tree, const int hfindex, tvbuff_t *tvb,
	const guint bit_offset, const gint no_of_chars)
{
	proto_item	  *pi;
	header_field_info *hfinfo;
	gint		   byte_length;
	gint		   byte_offset;
	gchar		  *string;

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT(hfinfo->type == FT_STRING);

	byte_length = (((no_of_chars + 1) * 7) + (bit_offset & 0x07)) >> 3;
	byte_offset = bit_offset >> 3;

	string = tvb_get_ascii_7bits_string(wmem_packet_scope(), tvb, bit_offset, no_of_chars);

	if (hfinfo->display == STR_UNICODE) {
		DISSECTOR_ASSERT(g_utf8_validate(string, -1, NULL));
	}

	pi = proto_tree_add_pi(tree, hfinfo, tvb, byte_offset, &byte_length);
	DISSECTOR_ASSERT(byte_length >= 0);
	proto_tree_set_string(PNODE_FINFO(pi), string);

	return pi;
}

guchar
proto_check_field_name(const gchar *field_name)
{
	return wrs_check_charset(fld_abbrev_chars, field_name);
}

gboolean
tree_expanded(int tree_type)
{
	g_assert(tree_type >= 0 && tree_type < num_tree_types);
	return tree_is_expanded[tree_type >> 5] & (1 << (tree_type & 31));
}

void
tree_expanded_set(int tree_type, gboolean value)
{
	g_assert(tree_type >= 0 && tree_type < num_tree_types);

	if (value)
		tree_is_expanded[tree_type >> 5] |= (1 << (tree_type & 31));
	else
		tree_is_expanded[tree_type >> 5] &= ~(1 << (tree_type & 31));
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
