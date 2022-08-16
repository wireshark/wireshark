/* proto.c
 * Routines for protocol tree
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_EPAN

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <float.h>
#include <inttypes.h>
#include <errno.h>

#include <wsutil/bits_ctz.h>
#include <wsutil/bits_count_ones.h>
#include <wsutil/sign_ext.h>
#include <wsutil/utf8_entities.h>
#include <wsutil/json_dumper.h>
#include <wsutil/wslog.h>
#include <wsutil/ws_assert.h>

#include <ftypes/ftypes.h>

#include "packet.h"
#include "exceptions.h"
#include "ptvcursor.h"
#include "strutil.h"
#include "addr_resolv.h"
#include "address_types.h"
#include "oids.h"
#include "proto.h"
#include "epan_dissect.h"
#include "tvbuff.h"
#include <epan/wmem_scopes.h>
#include "charsets.h"
#include "column-utils.h"
#include "to_str.h"
#include "osi-utils.h"
#include "expert.h"
#include "show_exception.h"
#include "in_cksum.h"
#include "register-int.h"

#include <wsutil/crash_info.h>
#include <wsutil/epochs.h>

/* Ptvcursor limits */
#define SUBTREE_ONCE_ALLOCATION_NUMBER 8
#define SUBTREE_MAX_LEVELS 256

typedef struct __subtree_lvl {
	gint        cursor_offset;
	proto_item *it;
	proto_tree *tree;
} subtree_lvl;

struct ptvcursor {
	wmem_allocator_t *scope;
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
 @param free_block a code block to call to free resources if this returns
 @return NULL if 'tree' is null */
#define CHECK_FOR_NULL_TREE_AND_FREE(tree, free_block)			\
	if (!tree) {							\
		free_block;						\
		return NULL;						\
	}

/** See inlined comments.
 @param tree the tree to append this item to
 @param free_block a code block to call to free resources if this returns
 @return NULL if 'tree' is null */
#define CHECK_FOR_NULL_TREE(tree) \
	CHECK_FOR_NULL_TREE_AND_FREE(tree, ((void)0))

/** See inlined comments.
 @param length the length of this item
 @param cleanup_block a code block to call to free resources if this returns
 @return NULL if 'length' is lower -1 or equal 0 */
#define CHECK_FOR_ZERO_OR_MINUS_LENGTH_AND_CLEANUP(length, cleanup_block)	\
	if (length < -1 || length == 0 ) {				\
		cleanup_block;						\
		return NULL;						\
	}

/** See inlined comments.
 @param length the length of this item
 @return NULL if 'length' is lower -1 or equal 0 */
#define CHECK_FOR_ZERO_OR_MINUS_LENGTH(length) \
	CHECK_FOR_ZERO_OR_MINUS_LENGTH_AND_CLEANUP(length, ((void)0))

/** See inlined comments.
 @param tree the tree to append this item to
 @param hfindex field index
 @param hfinfo header_field
 @param free_block a code block to call to free resources if this returns
 @return the header field matching 'hfinfo' */
#define TRY_TO_FAKE_THIS_ITEM_OR_FREE(tree, hfindex, hfinfo, free_block) \
	/* If this item is not referenced we don't have to do much work	\
	   at all but we should still return a node so that field items	\
	   below this node (think proto_item_add_subtree()) will still	\
	   have somewhere to attach to or else filtering will not work	\
	   (they would be ignored since tree would be NULL).		\
	   DON'T try to fake a node where PTREE_FINFO(tree) is NULL	\
	   since dissectors that want to do proto_item_set_len() or	\
	   other operations that dereference this would crash.		\
	   We fake FT_PROTOCOL unless some clients have requested us	\
	   not to do so.						\
	*/								\
	PTREE_DATA(tree)->count++;					\
	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);			\
	if (PTREE_DATA(tree)->count > prefs.gui_max_tree_items) {			\
		free_block;						\
		if (wireshark_abort_on_too_many_items) \
			ws_error("Adding %s would put more than %d items in the tree -- possible infinite loop (max number of items can be increased in advanced preferences)", \
			    hfinfo->abbrev, prefs.gui_max_tree_items);	\
		/* Let the exception handler add items to the tree */	\
		PTREE_DATA(tree)->count = 0;				\
		THROW_MESSAGE(DissectorError,				\
			wmem_strdup_printf(PNODE_POOL(tree),		\
			    "Adding %s would put more than %d items in the tree -- possible infinite loop (max number of items can be increased in advanced preferences)", \
			    hfinfo->abbrev, prefs.gui_max_tree_items));	\
	}								\
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
#define TRY_TO_FAKE_THIS_REPR(pi)	\
	ws_assert(pi);			\
	if (!(PTREE_DATA(pi)->visible)) { \
		/* If the tree (GUI) isn't visible it's pointless for us to generate the protocol \
		 * items string representation */ \
		return pi; \
	}
/* Same as above but returning void */
#define TRY_TO_FAKE_THIS_REPR_VOID(pi)	\
	if (!pi)			\
		return;			\
	if (!(PTREE_DATA(pi)->visible)) { \
		/* If the tree (GUI) isn't visible it's pointless for us to generate the protocol \
		 * items string representation */ \
		return; \
	}
/* Similar to above, but allows a NULL tree */
#define TRY_TO_FAKE_THIS_REPR_NESTED(pi)	\
	if ((pi == NULL) || (!(PTREE_DATA(pi)->visible))) { \
		/* If the tree (GUI) isn't visible it's pointless for us to generate the protocol \
		 * items string representation */ \
		return pi; \
	}

#ifdef ENABLE_CHECK_FILTER
#define CHECK_HF_VALUE(type, spec, start_values) \
{ \
	const type *current; \
	int n, m; \
	current = start_values; \
	for (n=0; current; n++, current++) { \
		/* Drop out if we reached the end. */ \
		if ((current->value == 0) && (current->strptr == NULL)) { \
			break; \
		} \
		/* Check value against all previous */ \
		for (m=0; m < n; m++) { \
			/* There are lots of duplicates with the same string, \
			   so only report if different... */ \
			if ((start_values[m].value == current->value) && \
			    (strcmp(start_values[m].strptr, current->strptr) != 0)) { \
				ws_warning("Field '%s' (%s) has a conflicting entry in its" \
					  " value_string: %" spec " is at indices %u (%s) and %u (%s)", \
					  hfinfo->name, hfinfo->abbrev, \
					  current->value, m, start_values[m].strptr, n, current->strptr); \
			} \
		} \
	} \
}
#endif


static const char *hf_try_val_to_str(guint32 value, const header_field_info *hfinfo);
static const char *hf_try_val64_to_str(guint64 value, const header_field_info *hfinfo);
static int hfinfo_bitoffset(const header_field_info *hfinfo);
static int hfinfo_mask_bitwidth(const header_field_info *hfinfo);
static int hfinfo_container_bitwidth(const header_field_info *hfinfo);

static void label_mark_truncated(char *label_str, gsize name_pos);
#define LABEL_MARK_TRUNCATED_START(label_str) label_mark_truncated(label_str, 0)

static void fill_label_boolean(field_info *fi, gchar *label_str);
static void fill_label_bitfield_char(field_info *fi, gchar *label_str);
static void fill_label_bitfield(field_info *fi, gchar *label_str, gboolean is_signed);
static void fill_label_bitfield64(field_info *fi, gchar *label_str, gboolean is_signed);
static void fill_label_char(field_info *fi, gchar *label_str);
static void fill_label_number(field_info *fi, gchar *label_str, gboolean is_signed);
static void fill_label_number64(field_info *fi, gchar *label_str, gboolean is_signed);

static size_t fill_display_label_float(field_info *fi, gchar *label_str);
static void fill_label_float(field_info *fi, gchar *label_str);

static const char *hfinfo_char_value_format_display(int display, char buf[7], guint32 value);
static const char *hfinfo_number_value_format_display(const header_field_info *hfinfo, int display, char buf[32], guint32 value);
static const char *hfinfo_number_value_format_display64(const header_field_info *hfinfo, int display, char buf[48], guint64 value);
static const char *hfinfo_char_vals_format(const header_field_info *hfinfo, char buf[32], guint32 value);
static const char *hfinfo_number_vals_format(const header_field_info *hfinfo, char buf[32], guint32 value);
static const char *hfinfo_number_vals_format64(const header_field_info *hfinfo, char buf[48], guint64 value);
static const char *hfinfo_number_value_format(const header_field_info *hfinfo, char buf[32], guint32 value);
static const char *hfinfo_number_value_format64(const header_field_info *hfinfo, char buf[48], guint64 value);
static const char *hfinfo_char_value_format(const header_field_info *hfinfo, char buf[32], guint32 value);
static const char *hfinfo_numeric_value_format(const header_field_info *hfinfo, char buf[32], guint32 value);
static const char *hfinfo_numeric_value_format64(const header_field_info *hfinfo, char buf[48], guint64 value);

static void proto_cleanup_base(void);

static proto_item *
proto_tree_add_node(proto_tree *tree, field_info *fi);

static void
get_hfi_length(header_field_info *hfinfo, tvbuff_t *tvb, const gint start, gint *length,
		gint *item_length, const guint encoding);

static gint
get_full_length(header_field_info *hfinfo, tvbuff_t *tvb, const gint start,
		gint length, guint item_length, const gint encoding);

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
proto_tree_set_protocol_tvb(field_info *fi, tvbuff_t *tvb, const char* field_data, int length);
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
proto_tree_set_ipv4(field_info *fi, ws_in4_addr value);
static void
proto_tree_set_ipv6(field_info *fi, const guint8* value_ptr);
static void
proto_tree_set_ipv6_tvb(field_info *fi, tvbuff_t *tvb, gint start, gint length);
static void
proto_tree_set_fcwwn_tvb(field_info *fi, tvbuff_t *tvb, gint start, gint length);
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
proto_tree_set_boolean(field_info *fi, guint64 value);
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
proto_tree_set_int64(field_info *fi, gint64 value);
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
static void register_number_string_decodinws_error(void);

/* Handle string errors expert info */
static int proto_string_errors = -1;
static expert_field ei_string_trailing_characters = EI_INIT;
static void register_string_errors(void);

static int proto_register_field_init(header_field_info *hfinfo, const int parent);

/* special-case header field used within proto.c */
static header_field_info hfi_text_only =
	{ "Text item",	"text", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
int hf_text_only = -1;

/* Structure for information about a protocol */
struct _protocol {
	const char *name;               /* long description */
	const char *short_name;         /* short description */
	const char *filter_name;        /* name of this protocol in filters */
	GPtrArray  *fields;             /* fields for this protocol */
	int         proto_id;           /* field ID for this protocol */
	gboolean    is_enabled;         /* TRUE if protocol is enabled */
	gboolean    enabled_by_default; /* TRUE if protocol is enabled by default */
	gboolean    can_toggle;         /* TRUE if is_enabled can be changed */
	int         parent_proto_id;    /* Used to identify "pino"s (Protocol In Name Only).
                                       For dissectors that need a protocol name so they
                                       can be added to a dissector table, but use the
                                       parent_proto_id for things like enable/disable */
	GList      *heur_list;          /* Heuristic dissectors associated with this protocol */
};

/* List of all protocols */
static GList *protocols = NULL;

/* Structure stored for deregistered g_slice */
struct g_slice_data {
	gsize    block_size;
	gpointer mem_block;
};

/* Deregistered fields */
static GPtrArray *deregistered_fields = NULL;
static GPtrArray *deregistered_data = NULL;
static GPtrArray *deregistered_slice = NULL;

/* indexed by prefix, contains initializers */
static GHashTable* prefixes = NULL;

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
	if((guint)hfindex >= gpa_hfinfo.len && wireshark_abort_on_dissector_bug)	\
		ws_error("Unregistered hf! index=%d", hfindex);					\
	DISSECTOR_ASSERT_HINT((guint)hfindex < gpa_hfinfo.len, "Unregistered hf!");	\
	DISSECTOR_ASSERT_HINT(gpa_hfinfo.hfi[hfindex] != NULL, "Unregistered hf!");	\
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

/* Hash table protocol aliases. const char * -> const char * */
static GHashTable *gpa_protocol_aliases = NULL;

/*
 * We're called repeatedly with the same field name when sorting a column.
 * Cache our last gpa_name_map hit for faster lookups.
 */
static char *last_field_name = NULL;
static header_field_info *last_hfinfo;

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

static const char *reserved_filter_names[] = {
	/* Display filter keywords. */
	"eq",
	"ne",
	"all_eq",
	"any_eq",
	"all_ne",
	"any_ne",
	"gt",
	"ge",
	"lt",
	"le",
	"bitwise_and",
	"contains",
	"matches",
	"not",
	"and",
	"or",
	"in",
	"any",
	"all",
	NULL
};

static GHashTable *proto_reserved_filter_names = NULL;

static gint
proto_compare_name(gconstpointer p1_arg, gconstpointer p2_arg)
{
	const protocol_t *p1 = (const protocol_t *)p1_arg;
	const protocol_t *p2 = (const protocol_t *)p2_arg;

	return g_ascii_strcasecmp(p1->short_name, p2->short_name);
}

static GSList *dissector_plugins = NULL;

#ifdef HAVE_PLUGINS
void
proto_register_plugin(const proto_plugin *plug)
{
	dissector_plugins = g_slist_prepend(dissector_plugins, (proto_plugin *)plug);
}
#else /* HAVE_PLUGINS */
void
proto_register_plugin(const proto_plugin *plug _U_)
{
	ws_warning("proto_register_plugin: built without support for binary plugins");
}
#endif /* HAVE_PLUGINS */

static void
call_plugin_register_protoinfo(gpointer data, gpointer user_data _U_)
{
	proto_plugin *plug = (proto_plugin *)data;

	if (plug->register_protoinfo) {
		plug->register_protoinfo();
	}
}

static void
call_plugin_register_handoff(gpointer data, gpointer user_data _U_)
{
	proto_plugin *plug = (proto_plugin *)data;

	if (plug->register_handoff) {
		plug->register_handoff();
	}
}

/* initialize data structures and register protocols and fields */
void
proto_init(GSList *register_all_plugin_protocols_list,
	   GSList *register_all_plugin_handoffs_list,
	   register_cb cb,
	   gpointer client_data)
{
	proto_cleanup_base();

	proto_names        = g_hash_table_new(g_str_hash, g_str_equal);
	proto_short_names  = g_hash_table_new(g_str_hash, g_str_equal);
	proto_filter_names = g_hash_table_new(g_str_hash, g_str_equal);

	proto_reserved_filter_names = g_hash_table_new(g_str_hash, g_str_equal);
	for (const char **ptr = reserved_filter_names; *ptr != NULL; ptr++) {
		/* GHashTable has no key destructor so the cast is safe. */
		g_hash_table_add(proto_reserved_filter_names, *(char **)ptr);
	}

	gpa_hfinfo.len           = 0;
	gpa_hfinfo.allocated_len = 0;
	gpa_hfinfo.hfi           = NULL;
	gpa_name_map             = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, save_same_name_hfinfo);
	gpa_protocol_aliases     = g_hash_table_new(g_str_hash, g_str_equal);
	deregistered_fields      = g_ptr_array_new();
	deregistered_data        = g_ptr_array_new();
	deregistered_slice       = g_ptr_array_new();

	/* Initialize the ftype subsystem */
	ftypes_initialize();

	/* Initialize the addres type subsystem */
	address_types_initialize();

	/* Register one special-case FT_TEXT_ONLY field for use when
	   converting wireshark to new-style proto_tree. These fields
	   are merely strings on the GUI tree; they are not filterable */
	hf_text_only = proto_register_field_init(&hfi_text_only, -1);

	/* Register the pseudo-protocols used for exceptions. */
	register_show_exception();
	register_type_length_mismatch();
	register_number_string_decodinws_error();
	register_string_errors();

#ifndef WS_DISABLE_DEBUG
	ftypes_register_pseudofields();
#endif

	/* Have each built-in dissector register its protocols, fields,
	   dissector tables, and dissectors to be called through a
	   handle, and do whatever one-time initialization it needs to
	   do. */
	register_all_protocols(cb, client_data);

	/* Now call the registration routines for all epan plugins. */
	for (GSList *l = register_all_plugin_protocols_list; l != NULL; l = l->next) {
		((void (*)(register_cb, gpointer))l->data)(cb, client_data);
	}

	/* Now call the registration routines for all dissector plugins. */
	if (cb)
		(*cb)(RA_PLUGIN_REGISTER, NULL, client_data);
	g_slist_foreach(dissector_plugins, call_plugin_register_protoinfo, NULL);

	/* Now call the "handoff registration" routines of all built-in
	   dissectors; those routines register the dissector in other
	   dissectors' handoff tables, and fetch any dissector handles
	   they need. */
	register_all_protocol_handoffs(cb, client_data);

	/* Now do the same with epan plugins. */
	for (GSList *l = register_all_plugin_handoffs_list; l != NULL; l = l->next) {
		((void (*)(register_cb, gpointer))l->data)(cb, client_data);
	}

	/* Now do the same with dissector plugins. */
	if (cb)
		(*cb)(RA_PLUGIN_HANDOFF, NULL, client_data);
	g_slist_foreach(dissector_plugins, call_plugin_register_handoff, NULL);

	/* sort the protocols by protocol name */
	protocols = g_list_sort(protocols, proto_compare_name);

	/* We've assigned all the subtree type values; allocate the array
	   for them, and zero it out. */
	tree_is_expanded = g_new0(guint32, (num_tree_types/32)+1);
}

static void
proto_cleanup_base(void)
{
	protocol_t *protocol;
	header_field_info *hfinfo;

	/* Free the abbrev/ID hash table */
	if (gpa_name_map) {
		g_hash_table_destroy(gpa_name_map);
		gpa_name_map = NULL;
	}
	if (gpa_protocol_aliases) {
		g_hash_table_destroy(gpa_protocol_aliases);
		gpa_protocol_aliases = NULL;
	}
	g_free(last_field_name);
	last_field_name = NULL;

	while (protocols) {
		protocol = (protocol_t *)protocols->data;
		PROTO_REGISTRAR_GET_NTH(protocol->proto_id, hfinfo);
		DISSECTOR_ASSERT(protocol->proto_id == hfinfo->id);

		g_slice_free(header_field_info, hfinfo);
		if (protocol->parent_proto_id != -1) {
			// pino protocol
			DISSECTOR_ASSERT(protocol->fields == NULL); //helpers should not have any registered fields
			DISSECTOR_ASSERT(protocol->heur_list == NULL); //helpers should not have a heuristic list
		} else {
			if (protocol->fields) {
				g_ptr_array_free(protocol->fields, TRUE);
			}
			g_list_free(protocol->heur_list);
		}
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

	if (proto_reserved_filter_names) {
		g_hash_table_destroy(proto_reserved_filter_names);
		proto_reserved_filter_names = NULL;
	}

	if (gpa_hfinfo.allocated_len) {
		gpa_hfinfo.len           = 0;
		gpa_hfinfo.allocated_len = 0;
		g_free(gpa_hfinfo.hfi);
		gpa_hfinfo.hfi           = NULL;
	}

	if (deregistered_fields) {
		g_ptr_array_free(deregistered_fields, TRUE);
		deregistered_fields = NULL;
	}

	if (deregistered_data) {
		g_ptr_array_free(deregistered_data, TRUE);
		deregistered_data = NULL;
	}

	if (deregistered_slice) {
		g_ptr_array_free(deregistered_slice, TRUE);
		deregistered_slice = NULL;
	}

	g_free(tree_is_expanded);
	tree_is_expanded = NULL;

	if (prefixes)
		g_hash_table_destroy(prefixes);
}

void
proto_cleanup(void)
{
	proto_free_deregistered_fields();
	proto_cleanup_base();

	g_slist_free(dissector_plugins);
	dissector_plugins = NULL;
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
	gint               hfid = GPOINTER_TO_UINT(key);
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

	fvalue_cleanup(&finfo->value);
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
 * having to call vsnprintf and copy strings around.
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

/* Register a new prefix for "delayed" initialization of field arrays */
void
proto_register_prefix(const char *prefix, prefix_initializer_t pi ) {
	if (! prefixes ) {
		prefixes = g_hash_table_new(prefix_hash, prefix_equal);
	}

	g_hash_table_insert(prefixes, (gpointer)prefix, (gpointer)pi);
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

	if (g_strcmp0(field_name, last_field_name) == 0) {
		return last_hfinfo;
	}

	hfinfo = (header_field_info *)g_hash_table_lookup(gpa_name_map, field_name);

	if (hfinfo) {
		g_free(last_field_name);
		last_field_name = g_strdup(field_name);
		last_hfinfo = hfinfo;
		return hfinfo;
	}

	if (!prefixes)
		return NULL;

	if ((pi = (prefix_initializer_t)g_hash_table_lookup(prefixes, field_name) ) != NULL) {
		pi(field_name);
		g_hash_table_remove(prefixes, field_name);
	} else {
		return NULL;
	}

	hfinfo = (header_field_info *)g_hash_table_lookup(gpa_name_map, field_name);

	if (hfinfo) {
		g_free(last_field_name);
		last_field_name = g_strdup(field_name);
		last_hfinfo = hfinfo;
	}
	return hfinfo;
}

header_field_info*
proto_registrar_get_byalias(const char *alias_name)
{
	if (!alias_name) {
		return NULL;
	}

	/* Find our aliased protocol. */
	char *an_copy = g_strdup(alias_name);
	char *dot = strchr(an_copy, '.');
	if (dot) {
		*dot = '\0';
	}
	const char *proto_pfx = (const char *) g_hash_table_lookup(gpa_protocol_aliases, an_copy);
	if (!proto_pfx) {
		g_free(an_copy);
		return NULL;
	}

	/* Construct our aliased field and look it up. */
	GString *filter_name = g_string_new(proto_pfx);
	if (dot) {
		g_string_append_printf(filter_name, ".%s", dot+1);
	}
	header_field_info *hfinfo = proto_registrar_get_byname(filter_name->str);
	g_free(an_copy);
	g_string_free(filter_name, TRUE);

	return hfinfo;
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


static char *
hfinfo_format_text(wmem_allocator_t *scope, const header_field_info *hfinfo _U_,
    const guchar *string)
{
	return format_text_string(scope, string);
}

static char *
hfinfo_format_bytes(wmem_allocator_t *scope, const header_field_info *hfinfo,
    const guint8 *bytes, guint length)
{
	char *str = NULL;
	const guint8 *p;
	gboolean is_printable;

	if (bytes) {
		if (hfinfo->display & BASE_SHOW_UTF_8_PRINTABLE) {
			/*
			 * If all bytes are valid and printable UTF-8, show the
			 * bytes as a string - in quotes to indicate that it's
			 * a string.
			 */
			if (isprint_utf8_string(bytes, length)) {
				str = wmem_strdup_printf(scope, "\"%.*s\"",
				    (int)length, bytes);
				return str;
			}
		} else if (hfinfo->display & BASE_SHOW_ASCII_PRINTABLE) {
			/*
			 * Check whether all bytes are printable.
			 */
			is_printable = TRUE;
			for (p = bytes; p < bytes+length; p++) {
				if (!g_ascii_isprint(*p)) {
					/* Not printable. */
					is_printable = FALSE;
					break;
				}
			}

			/*
			 * If all bytes are printable ASCII, show the bytes
			 * as a string - in quotes to indicate that it's
			 * a string.
			 */
			if (is_printable) {
				str = wmem_strdup_printf(scope, "\"%.*s\"",
				    (int)length, bytes);
				return str;
			}
		}

		/*
		 * Either it's not printable ASCII, or we don't care whether
		 * it's printable ASCII; show it as hex bytes.
		 */
		switch (FIELD_DISPLAY(hfinfo->display)) {
		case SEP_DOT:
			str = bytes_to_str_punct(scope, bytes, length, '.');
			break;
		case SEP_DASH:
			str = bytes_to_str_punct(scope, bytes, length, '-');
			break;
		case SEP_COLON:
			str = bytes_to_str_punct(scope, bytes, length, ':');
			break;
		case SEP_SPACE:
			str = bytes_to_str_punct(scope, bytes, length, ' ');
			break;
		case BASE_NONE:
		default:
			if (prefs.display_byte_fields_with_spaces) {
				str = bytes_to_str_punct(scope, bytes, length, ' ');
			} else {
				str = bytes_to_str(scope, bytes, length);
			}
			break;
		}
	}
	else {
		if (hfinfo->display & BASE_ALLOW_ZERO) {
			str = wmem_strdup(scope, "<none>");
		} else {
			str = wmem_strdup(scope, "<MISSING>");
		}
	}
	return str;
}

static void
ptvcursor_new_subtree_levels(ptvcursor_t *ptvc)
{
	subtree_lvl *pushed_tree;

	DISSECTOR_ASSERT(ptvc->pushed_tree_max <= SUBTREE_MAX_LEVELS-SUBTREE_ONCE_ALLOCATION_NUMBER);
	ptvc->pushed_tree_max += SUBTREE_ONCE_ALLOCATION_NUMBER;

	pushed_tree = (subtree_lvl *)wmem_realloc(ptvc->scope, (void *)ptvc->pushed_tree, sizeof(subtree_lvl) * ptvc->pushed_tree_max);
	DISSECTOR_ASSERT(pushed_tree != NULL);
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
ptvcursor_new(wmem_allocator_t *scope, proto_tree *tree, tvbuff_t *tvb, gint offset)
{
	ptvcursor_t *ptvc;

	ptvc                    = wmem_new(scope, ptvcursor_t);
	ptvc->scope             = scope;
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

	CHECK_FOR_NULL_TREE(tree);

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

/* (INTERNAL USE ONLY) Add a text-only node to the proto_tree */
proto_item *
proto_tree_add_text_internal(proto_tree *tree, tvbuff_t *tvb, gint start, gint length,
		    const char *format, ...)
{
	proto_item	  *pi;
	va_list		   ap;
	header_field_info *hfinfo;

	if (length == -1) {
		length = tvb_captured_length(tvb) ? tvb_ensure_captured_length_remaining(tvb, start) : 0;
	} else {
		tvb_ensure_bytes_exist(tvb, start, length);
	}

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hf_text_only, hfinfo);

	pi = proto_tree_add_text_node(tree, tvb, start, length);

	TRY_TO_FAKE_THIS_REPR(pi);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

/* (INTERNAL USE ONLY) Add a text-only node to the proto_tree (va_list version) */
proto_item *
proto_tree_add_text_valist_internal(proto_tree *tree, tvbuff_t *tvb, gint start,
			   gint length, const char *format, va_list ap)
{
	proto_item        *pi;
	header_field_info *hfinfo;

	if (length == -1) {
		length = tvb_captured_length(tvb) ? tvb_ensure_captured_length_remaining(tvb, start) : 0;
	} else {
		tvb_ensure_bytes_exist(tvb, start, length);
	}

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hf_text_only, hfinfo);

	pi = proto_tree_add_text_node(tree, tvb, start, length);

	TRY_TO_FAKE_THIS_REPR(pi);

	proto_tree_set_representation(pi, format, ap);

	return pi;
}

/* Add a text-only node that creates a subtree underneath.
 */
proto_tree *
proto_tree_add_subtree(proto_tree *tree, tvbuff_t *tvb, gint start, gint length, gint idx, proto_item **tree_item, const char *text)
{
	return proto_tree_add_subtree_format(tree, tvb, start, length, idx, tree_item, "%s", text);
}

/* Add a text-only node that creates a subtree underneath.
 */
proto_tree *
proto_tree_add_subtree_format(proto_tree *tree, tvbuff_t *tvb, gint start, gint length, gint idx, proto_item **tree_item, const char *format, ...)
{
	proto_tree *pt;
	proto_item *pi;
	va_list	    ap;

	va_start(ap, format);
	pi = proto_tree_add_text_valist_internal(tree, tvb, start, length, format, ap);
	va_end(ap);

	if (tree_item != NULL)
		*tree_item = pi;

	pt = proto_item_add_subtree(pi, idx);

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

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hf_text_only, hfinfo);

	pi = proto_tree_add_text_node(tree, tvb, start, length);

	TRY_TO_FAKE_THIS_REPR(pi);

	proto_item_set_text(pi, "%s", tvb_format_text(tree->tree_data->pinfo->pool, tvb, start, length));

	return pi;
}

proto_item *
proto_tree_add_format_wsp_text(proto_tree *tree, tvbuff_t *tvb, gint start, gint length)
{
	proto_item	  *pi;
	header_field_info *hfinfo;
	gchar		  *str;

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hf_text_only, hfinfo);

	pi = proto_tree_add_text_node(tree, tvb, start, length);

	TRY_TO_FAKE_THIS_REPR(pi);

	str = tvb_format_text_wsp(NULL, tvb, start, length);
	proto_item_set_text(pi, "%s", str);
	wmem_free(NULL, str);

	return pi;
}

void proto_report_dissector_bug(const char *format, ...)
{
	va_list args;

	if (wireshark_abort_on_dissector_bug) {
		/*
		 * Try to have the error message show up in the crash
		 * information.
		 */
		va_start(args, format);
		ws_vadd_crash_info(format, args);
		va_end(args);

		/*
		 * Print the error message.
		 */
		va_start(args, format);
		vfprintf(stderr, format, args);
		va_end(args);
		putc('\n', stderr);

		/*
		 * And crash.
		 */
		abort();
	} else {
		va_start(args, format);
		VTHROW_FORMATTED(DissectorError, format, args);
		va_end(args);
	}
}

/* We could probably get away with changing is_error to a minimum length value. */
static void
report_type_length_mismatch(proto_tree *tree, const gchar *descr, int length, gboolean is_error)
{
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
		if (encoding & ENC_ZIGBEE) {
			if (value == 0xFF) { /* Invalid Zigbee length, set to 0 */
				value = 0;
			}
		}
		break;

	case 2:
		value = (encoding & ENC_LITTLE_ENDIAN) ? tvb_get_letohs(tvb, offset)
						       : tvb_get_ntohs(tvb, offset);
		if (encoding & ENC_ZIGBEE) {
			if (value == 0xFFFF) { /* Invalid Zigbee length, set to 0 */
				value = 0;
			}
		}
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

static inline guint64
get_uint64_value(proto_tree *tree, tvbuff_t *tvb, gint offset, guint length, const guint encoding)
{
	guint64 value;
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

	case 5:
		value = (encoding & ENC_LITTLE_ENDIAN) ? tvb_get_letoh40(tvb, offset)
						       : tvb_get_ntoh40(tvb, offset);
		break;

	case 6:
		value = (encoding & ENC_LITTLE_ENDIAN) ? tvb_get_letoh48(tvb, offset)
						       : tvb_get_ntoh48(tvb, offset);
		break;

	case 7:
		value = (encoding & ENC_LITTLE_ENDIAN) ? tvb_get_letoh56(tvb, offset)
						       : tvb_get_ntoh56(tvb, offset);
		break;

	case 8:
		value = (encoding & ENC_LITTLE_ENDIAN) ? tvb_get_letoh64(tvb, offset)
						       : tvb_get_ntoh64(tvb, offset);
		break;

	default:
		if (length < 1) {
			length_error = TRUE;
			value = 0;
		} else {
			length_error = FALSE;
			value = (encoding & ENC_LITTLE_ENDIAN) ? tvb_get_letoh64(tvb, offset)
							       : tvb_get_ntoh64(tvb, offset);
		}
		report_type_length_mismatch(tree, "an unsigned integer", length, length_error);
		break;
	}
	return value;
}

static gint32
get_int_value(proto_tree *tree, tvbuff_t *tvb, gint offset, gint length, const guint encoding)
{
	gint32 value;
	gboolean length_error;

	switch (length) {

	case 1:
		value = tvb_get_gint8(tvb, offset);
		break;

	case 2:
		value = encoding ? tvb_get_letohis(tvb, offset)
				 : tvb_get_ntohis(tvb, offset);
		break;

	case 3:
		value = encoding ? tvb_get_letohi24(tvb, offset)
				 : tvb_get_ntohi24(tvb, offset);
		break;

	case 4:
		value = encoding ? tvb_get_letohil(tvb, offset)
				 : tvb_get_ntohil(tvb, offset);
		break;

	default:
		if (length < 1) {
			length_error = TRUE;
			value = 0;
		} else {
			length_error = FALSE;
			value = encoding ? tvb_get_letohil(tvb, offset)
					 : tvb_get_ntohil(tvb, offset);
		}
		report_type_length_mismatch(tree, "a signed integer", length, length_error);
		break;
	}
	return value;
}

/* Note: this returns an unsigned int64, but with the appropriate bit(s) set to
 * be cast-able as a gint64. This is weird, but what the code has always done.
 */
static inline guint64
get_int64_value(proto_tree *tree, tvbuff_t *tvb, gint start, guint length, const guint encoding)
{
	guint64 value = get_uint64_value(tree, tvb, start, length, encoding);

	switch (length) {
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

	return value;
}

/* For FT_STRING */
static inline const guint8 *
get_string_value(wmem_allocator_t *scope, tvbuff_t *tvb, gint start,
    gint length, gint *ret_length, const guint encoding)
{
	if (length == -1) {
		length = tvb_ensure_captured_length_remaining(tvb, start);
	}
	*ret_length = length;
	return tvb_get_string_enc(scope, tvb, start, length, encoding);
}

/* For FT_STRINGZ */
static inline const guint8 *
get_stringz_value(wmem_allocator_t *scope, proto_tree *tree, tvbuff_t *tvb,
    gint start, gint length, gint *ret_length, const guint encoding)
{
	const guint8 *value;

	if (length < -1) {
		report_type_length_mismatch(tree, "a string", length, TRUE);
	}
	if (length == -1) {
		/* This can throw an exception */
		value = tvb_get_stringz_enc(scope, tvb, start, &length, encoding);
	} else {
		/* In this case, length signifies the length of the string.
		 *
		 * This could either be a null-padded string, which doesn't
		 * necessarily have a '\0' at the end, or a null-terminated
		 * string, with a trailing '\0'.  (Yes, there are cases
		 * where you have a string that's both counted and null-
		 * terminated.)
		 *
		 * In the first case, we must allocate a buffer of length
		 * "length+1", to make room for a trailing '\0'.
		 *
		 * In the second case, we don't assume that there is a
		 * trailing '\0' there, as the packet might be malformed.
		 * (XXX - should we throw an exception if there's no
		 * trailing '\0'?)  Therefore, we allocate a buffer of
		 * length "length+1", and put in a trailing '\0', just to
		 * be safe.
		 *
		 * (XXX - this would change if we made string values counted
		 * rather than null-terminated.)
		 */
		value = tvb_get_string_enc(scope, tvb, start, length, encoding);
	}
	*ret_length = length;
	return value;
}

/* For FT_UINT_STRING */
static inline const guint8 *
get_uint_string_value(wmem_allocator_t *scope, proto_tree *tree,
    tvbuff_t *tvb, gint start, gint length, gint *ret_length,
    const guint encoding)
{
	guint32 n;
	const guint8 *value;

	/* I believe it's ok if this is called with a NULL tree */
	n = get_uint_value(tree, tvb, start, length, encoding & ~ENC_CHARENCODING_MASK);
	value = tvb_get_string_enc(scope, tvb, start + length, n, encoding);
	length += n;
	*ret_length = length;
	return value;
}

/* For FT_STRINGZPAD */
static inline const guint8 *
get_stringzpad_value(wmem_allocator_t *scope, tvbuff_t *tvb, gint start,
    gint length, gint *ret_length, const guint encoding)
{
	/*
	 * XXX - currently, string values are null-
	 * terminated, so a "zero-padded" string
	 * isn't special.  If we represent string
	 * values as something that includes a counted
	 * array of bytes, we'll need to strip the
	 * trailing NULs.
	 */
	if (length == -1) {
		length = tvb_ensure_captured_length_remaining(tvb, start);
	}
	*ret_length = length;
	return tvb_get_string_enc(scope, tvb, start, length, encoding);
}

/* For FT_STRINGZTRUNC */
static inline const guint8 *
get_stringztrunc_value(wmem_allocator_t *scope, tvbuff_t *tvb, gint start,
    gint length, gint *ret_length, const guint encoding)
{
	/*
	 * XXX - currently, string values are null-
	 * terminated, so a "zero-truncated" string
	 * isn't special.  If we represent string
	 * values as something that includes a counted
	 * array of bytes, we'll need to strip everything
	 * starting with the terminating NUL.
	 */
	if (length == -1) {
		length = tvb_ensure_captured_length_remaining(tvb, start);
	}
	*ret_length = length;
	return tvb_get_string_enc(scope, tvb, start, length, encoding);
}

/*
 * Deltas between the epochs for various non-UN*X time stamp formats and
 * the January 1, 1970, 00:00:00 (proleptic?) UTC epoch for the UN*X time
 * stamp format.
 */

/*
 * NTP Era 0: the epoch is January 1, 1900, 00:00:00 (proleptic?) UTC.
 * XXX - if it's OK if this is unsigned, can we just use
 * EPOCH_DELTA_1900_01_01_00_00_00_UTC?
 */
#define NTP_TIMEDIFF1900TO1970SEC G_GINT64_CONSTANT(2208988800)

/*
 * NTP Era 1: the epoch is February 7, 2036, 06:28:16 UTC.
 */
#define NTP_TIMEDIFF1970TO2036SEC G_GINT64_CONSTANT(2085978496)

/* this can be called when there is no tree, so tree may be null */
static void
get_time_value(proto_tree *tree, tvbuff_t *tvb, const gint start,
	       const gint length, const guint encoding, nstime_t *time_stamp,
	       const gboolean is_relative)
{
	guint32     tmpsecs;
	guint64     tmp64secs;
	guint64     todusecs;

	switch (encoding) {

		case ENC_TIME_SECS_NSECS|ENC_BIG_ENDIAN:
			/*
			 * If the length is 16, 8-byte seconds, followed
			 * by 8-byte fractional time in nanoseconds,
			 * both big-endian.
			 *
			 * If the length is 12, 8-byte seconds, followed
			 * by 4-byte fractional time in nanoseconds,
			 * both big-endian.
			 *
			 * If the length is 8, 4-byte seconds, followed
			 * by 4-byte fractional time in nanoseconds,
			 * both big-endian.
			 *
			 * For absolute times, the seconds are seconds
			 * since the UN*X epoch.
			 */
			if (length == 16) {
				time_stamp->secs  = (time_t)tvb_get_ntoh64(tvb, start);
				time_stamp->nsecs = (guint32)tvb_get_ntoh64(tvb, start+8);
			} else if (length == 12) {
				time_stamp->secs  = (time_t)tvb_get_ntoh64(tvb, start);
				time_stamp->nsecs = tvb_get_ntohl(tvb, start+8);
			} else if (length == 8) {
				time_stamp->secs  = (time_t)tvb_get_ntohl(tvb, start);
				time_stamp->nsecs = tvb_get_ntohl(tvb, start+4);
			} else if (length == 4) {
				/*
				 * Backwards compatibility.
				 * ENC_TIME_SECS_NSECS is 0; using
				 * ENC_BIG_ENDIAN by itself with a 4-byte
				 * time-in-seconds value was done in the
				 * past.
				 */
				time_stamp->secs  = (time_t)tvb_get_ntohl(tvb, start);
				time_stamp->nsecs = 0;
			} else {
				time_stamp->secs  = 0;
				time_stamp->nsecs = 0;
				report_type_length_mismatch(tree, "a timespec", length, (length < 4));
			}
			break;

		case ENC_TIME_SECS_NSECS|ENC_LITTLE_ENDIAN:
			/*
			 * If the length is 16, 8-byte seconds, followed
			 * by 8-byte fractional time in nanoseconds,
			 * both little-endian.
			 *
			 * If the length is 12, 8-byte seconds, followed
			 * by 4-byte fractional time in nanoseconds,
			 * both little-endian.
			 *
			 * If the length is 8, 4-byte seconds, followed
			 * by 4-byte fractional time in nanoseconds,
			 * both little-endian.
			 *
			 * For absolute times, the seconds are seconds
			 * since the UN*X epoch.
			 */
			if (length == 16) {
				time_stamp->secs  = (time_t)tvb_get_letoh64(tvb, start);
				time_stamp->nsecs = (guint32)tvb_get_letoh64(tvb, start+8);
			} else if (length == 12) {
				time_stamp->secs  = (time_t)tvb_get_letoh64(tvb, start);
				time_stamp->nsecs = tvb_get_letohl(tvb, start+8);
			} else if (length == 8) {
				time_stamp->secs  = (time_t)tvb_get_letohl(tvb, start);
				time_stamp->nsecs = tvb_get_letohl(tvb, start+4);
			} else if (length == 4) {
				/*
				 * Backwards compatibility.
				 * ENC_TIME_SECS_NSECS is 0; using
				 * ENC_LITTLE_ENDIAN by itself with a 4-byte
				 * time-in-seconds value was done in the
				 * past.
				 */
				time_stamp->secs  = (time_t)tvb_get_letohl(tvb, start);
				time_stamp->nsecs = 0;
			} else {
				time_stamp->secs  = 0;
				time_stamp->nsecs = 0;
				report_type_length_mismatch(tree, "a timespec", length, (length < 4));
			}
			break;

		case ENC_TIME_NTP|ENC_BIG_ENDIAN:
			/*
			 * NTP time stamp, big-endian.
			 * Only supported for absolute times.
			 */
			DISSECTOR_ASSERT(!is_relative);

			/* We need a temporary variable here so the unsigned math
			 * works correctly (for years > 2036 according to RFC 2030
			 * chapter 3).
			 *
			 * If bit 0 is set, the UTC time is in the range 1968-2036 and
			 * UTC time is reckoned from 0h 0m 0s UTC on 1 January 1900.
			 * If bit 0 is not set, the time is in the range 2036-2104 and
			 * UTC time is reckoned from 6h 28m 16s UTC on 7 February 2036.
			 */
			tmpsecs  = tvb_get_ntohl(tvb, start);
			if ((tmpsecs & 0x80000000) != 0)
				time_stamp->secs = (time_t)((gint64)tmpsecs - NTP_TIMEDIFF1900TO1970SEC);
			else
				time_stamp->secs = (time_t)((gint64)tmpsecs + NTP_TIMEDIFF1970TO2036SEC);

			if (length == 8) {
				/*
				 * Convert 1/2^32s of a second to nanoseconds.
				 */
				time_stamp->nsecs = (int)(1000000000*(tvb_get_ntohl(tvb, start+4)/4294967296.0));
				if ((time_stamp->nsecs == 0) && (tmpsecs == 0)) {
					//This is "NULL" time
					time_stamp->secs = 0;
				}
			} else if (length == 4) {
				/*
				 * Backwards compatibility.
				 */
				if (tmpsecs == 0) {
					//This is "NULL" time
					time_stamp->secs = 0;
				}
				time_stamp->nsecs = 0;
			} else {
				time_stamp->secs  = 0;
				time_stamp->nsecs = 0;
				report_type_length_mismatch(tree, "an NTP time stamp", length, (length < 4));
			}
			break;

		case ENC_TIME_NTP|ENC_LITTLE_ENDIAN:
			/*
			 * NTP time stamp, little-endian.
			 * Only supported for absolute times.
			 */
			DISSECTOR_ASSERT(!is_relative);

			/* We need a temporary variable here so the unsigned math
			 * works correctly (for years > 2036 according to RFC 2030
			 * chapter 3).
			 *
			 * If bit 0 is set, the UTC time is in the range 1968-2036 and
			 * UTC time is reckoned from 0h 0m 0s UTC on 1 January 1900.
			 * If bit 0 is not set, the time is in the range 2036-2104 and
			 * UTC time is reckoned from 6h 28m 16s UTC on 7 February 2036.
			 */
			tmpsecs  = tvb_get_letohl(tvb, start);
			if ((tmpsecs & 0x80000000) != 0)
				time_stamp->secs = (time_t)((gint64)tmpsecs - NTP_TIMEDIFF1900TO1970SEC);
			else
				time_stamp->secs = (time_t)((gint64)tmpsecs + NTP_TIMEDIFF1970TO2036SEC);

			if (length == 8) {
				/*
				 * Convert 1/2^32s of a second to nanoseconds.
				 */
				time_stamp->nsecs = (int)(1000000000*(tvb_get_letohl(tvb, start+4)/4294967296.0));
				if ((time_stamp->nsecs == 0) && (tmpsecs == 0)) {
					//This is "NULL" time
					time_stamp->secs = 0;
				}
			} else if (length == 4) {
				/*
				 * Backwards compatibility.
				 */
				if (tmpsecs == 0) {
					//This is "NULL" time
					time_stamp->secs = 0;
				}
				time_stamp->nsecs = 0;
			} else {
				time_stamp->secs  = 0;
				time_stamp->nsecs = 0;
				report_type_length_mismatch(tree, "an NTP time stamp", length, (length < 4));
			}
			break;

		case ENC_TIME_TOD|ENC_BIG_ENDIAN:
			/*
			 * S/3x0 and z/Architecture TOD clock time stamp,
			 * big-endian.  The epoch is January 1, 1900,
			 * 00:00:00 (proleptic?) UTC.
			 *
			 * Only supported for absolute times.
			 */
			DISSECTOR_ASSERT(!is_relative);
			DISSECTOR_ASSERT(length == 8);

			if (length == 8) {
				todusecs  = tvb_get_ntoh64(tvb, start) >> 12;
				time_stamp->secs = (time_t)((todusecs  / 1000000) - EPOCH_DELTA_1900_01_01_00_00_00_UTC);
				time_stamp->nsecs = (int)((todusecs  % 1000000) * 1000);
			} else {
				time_stamp->secs  = 0;
				time_stamp->nsecs = 0;
				report_type_length_mismatch(tree, "a TOD clock time stamp", length, (length < 4));
			}
			break;

		case ENC_TIME_TOD|ENC_LITTLE_ENDIAN:
			/*
			 * S/3x0 and z/Architecture TOD clock time stamp,
			 * little-endian.  The epoch is January 1, 1900,
			 * 00:00:00 (proleptic?) UTC.
			 *
			 * Only supported for absolute times.
			 */
			DISSECTOR_ASSERT(!is_relative);

			if (length == 8) {
				todusecs  = tvb_get_letoh64(tvb, start) >> 12 ;
				time_stamp->secs = (time_t)((todusecs  / 1000000) - EPOCH_DELTA_1900_01_01_00_00_00_UTC);
				time_stamp->nsecs = (int)((todusecs  % 1000000) * 1000);
			} else {
				time_stamp->secs  = 0;
				time_stamp->nsecs = 0;
				report_type_length_mismatch(tree, "a TOD clock time stamp", length, (length < 4));
			}
			break;

		case ENC_TIME_RTPS|ENC_BIG_ENDIAN:
			/*
			 * Time stamp using the same seconds/fraction format
			 * as NTP, but with the origin of the time stamp being
			 * the UNIX epoch rather than the NTP epoch; big-
			 * endian.
			 *
			 * Only supported for absolute times.
			 */
			DISSECTOR_ASSERT(!is_relative);

			if (length == 8) {
				time_stamp->secs = (time_t)tvb_get_ntohl(tvb, start);
				/*
				 * Convert 1/2^32s of a second to nanoseconds.
				 */
				time_stamp->nsecs = (int)(1000000000*(tvb_get_ntohl(tvb, start+4)/4294967296.0));
			} else {
				time_stamp->secs  = 0;
				time_stamp->nsecs = 0;
				report_type_length_mismatch(tree, "an RTPS time stamp", length, (length < 4));
			}
			break;

		case ENC_TIME_RTPS|ENC_LITTLE_ENDIAN:
			/*
			 * Time stamp using the same seconds/fraction format
			 * as NTP, but with the origin of the time stamp being
			 * the UNIX epoch rather than the NTP epoch; little-
			 * endian.
			 *
			 * Only supported for absolute times.
			 */
			DISSECTOR_ASSERT(!is_relative);

			if (length == 8) {
				time_stamp->secs = (time_t)tvb_get_letohl(tvb, start);
				/*
				 * Convert 1/2^32s of a second to nanoseconds.
				 */
				time_stamp->nsecs = (int)(1000000000*(tvb_get_letohl(tvb, start+4)/4294967296.0));
			} else {
				time_stamp->secs  = 0;
				time_stamp->nsecs = 0;
				report_type_length_mismatch(tree, "an RTPS time stamp", length, (length < 4));
			}
			break;

		case ENC_TIME_MIP6 | ENC_BIG_ENDIAN:
			/*
			* MIP6 time stamp, big-endian.
			* A 64-bit unsigned integer field containing a timestamp.  The
			* value indicates the number of seconds since January 1, 1970,
			* 00:00 UTC, by using a fixed point format.  In this format, the
			* integer number of seconds is contained in the first 48 bits of
			* the field, and the remaining 16 bits indicate the number of
			* 1/65536 fractions of a second.

			* Only supported for absolute times.
			*/
			DISSECTOR_ASSERT(!is_relative);

			if (length == 8) {
				/* We need a temporary variable here so the casting and fractions
				* of a second work correctly.
				*/
				tmp64secs = tvb_get_ntoh48(tvb, start);
				tmpsecs = tvb_get_ntohs(tvb, start + 6);
				tmpsecs <<= 16;

				if ((tmp64secs == 0) && (tmpsecs == 0)) {
					//This is "NULL" time
					time_stamp->secs = 0;
					time_stamp->nsecs = 0;
				} else {
					time_stamp->secs = (time_t)tmp64secs;
					time_stamp->nsecs = (int)((tmpsecs / 4294967296.0) * 1000000000);
				}
			} else {
				time_stamp->secs = 0;
				time_stamp->nsecs = 0;
				report_type_length_mismatch(tree, "an NTP time stamp", length, (length != 8));
			}
			break;

		case ENC_TIME_SECS_USECS|ENC_BIG_ENDIAN:
			/*
			 * 4-byte seconds, followed by 4-byte fractional
			 * time in microseconds, both big-endian.
			 * For absolute times, the seconds are seconds
			 * since the UN*X epoch.
			 */
			if (length == 8) {
				time_stamp->secs  = (time_t)tvb_get_ntohl(tvb, start);
				time_stamp->nsecs = tvb_get_ntohl(tvb, start+4)*1000;
			} else {
				time_stamp->secs  = 0;
				time_stamp->nsecs = 0;
				report_type_length_mismatch(tree, "a timeval", length, (length < 4));
			}
			break;

		case ENC_TIME_SECS_USECS|ENC_LITTLE_ENDIAN:
			/*
			 * 4-byte seconds, followed by 4-byte fractional
			 * time in microseconds, both little-endian.
			 * For absolute times, the seconds are seconds
			 * since the UN*X epoch.
			 */
			if (length == 8) {
				time_stamp->secs  = (time_t)tvb_get_letohl(tvb, start);
				time_stamp->nsecs = tvb_get_letohl(tvb, start+4)*1000;
			} else {
				time_stamp->secs  = 0;
				time_stamp->nsecs = 0;
				report_type_length_mismatch(tree, "a timeval", length, (length < 4));
			}
			break;

		case ENC_TIME_SECS|ENC_BIG_ENDIAN:
		case ENC_TIME_SECS|ENC_LITTLE_ENDIAN:
			/*
			 * Seconds, 1 to 8 bytes.
			 * For absolute times, it's seconds since the
			 * UN*X epoch.
			 */
			if (length >= 1 && length <= 8) {
				time_stamp->secs  = (time_t)get_uint64_value(tree, tvb, start, length, encoding);
				time_stamp->nsecs = 0;
			} else {
				time_stamp->secs  = 0;
				time_stamp->nsecs = 0;
				report_type_length_mismatch(tree, "a time-in-seconds time stamp", length, (length < 4));
			}
			break;

		case ENC_TIME_MSECS|ENC_BIG_ENDIAN:
		case ENC_TIME_MSECS|ENC_LITTLE_ENDIAN:
			/*
			 * Milliseconds, 1 to 8 bytes.
			 * For absolute times, it's milliseconds since the
			 * UN*X epoch.
			 */
			if (length >= 1 && length <= 8) {
				guint64 msecs;

				msecs = get_uint64_value(tree, tvb, start, length, encoding);
				time_stamp->secs  = (time_t)(msecs / 1000);
				time_stamp->nsecs = (int)(msecs % 1000)*1000000;
			} else {
				time_stamp->secs  = 0;
				time_stamp->nsecs = 0;
				report_type_length_mismatch(tree, "a time-in-milliseconds time stamp", length, (length < 4));
			}
			break;

		case ENC_TIME_USECS|ENC_BIG_ENDIAN:
		case ENC_TIME_USECS|ENC_LITTLE_ENDIAN:
			/*
			* Microseconds, 1 to 8 bytes.
			* For absolute times, it's microseconds since the
			* UN*X epoch.
			*/
			if (length >= 1 && length <= 8) {
				guint64 usecs;

				usecs = get_uint64_value(tree, tvb, start, length, encoding);
				time_stamp->secs  = (time_t)(usecs / 1000000);
				time_stamp->nsecs = (int)(usecs % 1000000)*1000;
			} else {
				time_stamp->secs  = 0;
				time_stamp->nsecs = 0;
				report_type_length_mismatch(tree, "a time-in-microseconds time stamp", length, (length < 4));
			}
			break;

		case ENC_TIME_NSECS|ENC_BIG_ENDIAN:
		case ENC_TIME_NSECS|ENC_LITTLE_ENDIAN:
			/*
			 * nanoseconds, 1 to 8 bytes.
			 * For absolute times, it's nanoseconds since the
			 * UN*X epoch.
			 */

			if (length >= 1 && length <= 8) {
				guint64 nsecs;

				nsecs = get_uint64_value(tree, tvb, start, length, encoding);
				time_stamp->secs  = (time_t)(nsecs / 1000000000);
				time_stamp->nsecs = (int)(nsecs % 1000000000);
			} else {
				time_stamp->secs  = 0;
				time_stamp->nsecs = 0;
				report_type_length_mismatch(tree, "a time-in-nanoseconds time stamp", length, (length < 4));
			}
			break;

		case ENC_TIME_RFC_3971|ENC_BIG_ENDIAN:
			/*
			 * 1/64ths of a second since the UN*X epoch,
			 * big-endian.
			 *
			 * Only supported for absolute times.
			 */
			DISSECTOR_ASSERT(!is_relative);

			if (length == 8) {
				/*
				 * The upper 48 bits are seconds since the
				 * UN*X epoch.
				 */
				time_stamp->secs  = (time_t)tvb_get_ntoh48(tvb, start);
				/*
				 * The lower 16 bits are 1/2^16s of a second;
				 * convert them to nanoseconds.
				 *
				 * XXX - this may give the impression of higher
				 * precision than you actually get.
				 */
				time_stamp->nsecs = (int)(1000000000*(tvb_get_ntohs(tvb, start+6)/65536.0));
			} else {
				time_stamp->secs  = 0;
				time_stamp->nsecs = 0;
				report_type_length_mismatch(tree, "an RFC 3971-style time stamp", length, (length < 4));
			}
			break;

		case ENC_TIME_RFC_3971|ENC_LITTLE_ENDIAN:
			/*
			 * 1/64ths of a second since the UN*X epoch,
			 * little-endian.
			 *
			 * Only supported for absolute times.
			 */
			DISSECTOR_ASSERT(!is_relative);

			if (length == 8) {
				/*
				 * XXX - this is assuming that, if anybody
				 * were ever to use this format - RFC 3971
				 * doesn't, because that's an Internet
				 * protocol, and those use network byte
				 * order, i.e. big-endian - they'd treat it
				 * as a 64-bit count of 1/2^16s of a second,
				 * putting the upper 48 bits at the end.
				 *
				 * The lower 48 bits are seconds since the
				 * UN*X epoch.
				 */
				time_stamp->secs  = (time_t)tvb_get_letoh48(tvb, start+2);
				/*
				 * The upper 16 bits are 1/2^16s of a second;
				 * convert them to nanoseconds.
				 *
				 * XXX - this may give the impression of higher
				 * precision than you actually get.
				 */
				time_stamp->nsecs = (int)(1000000000*(tvb_get_letohs(tvb, start)/65536.0));
			} else {
				time_stamp->secs  = 0;
				time_stamp->nsecs = 0;
				report_type_length_mismatch(tree, "an RFC 3971-style time stamp", length, (length < 4));
			}
			break;

		case ENC_TIME_SECS_NTP|ENC_BIG_ENDIAN:
			/*
			 * NTP time stamp, with 1-second resolution (i.e.,
			 * seconds since the NTP epoch), big-endian.
			 * Only supported for absolute times.
			 */
			DISSECTOR_ASSERT(!is_relative);

			if (length == 4) {
				/*
				* We need a temporary variable here so the unsigned math
				* works correctly (for years > 2036 according to RFC 2030
				* chapter 3).
				*
				* If bit 0 is set, the UTC time is in the range 1968-2036 and
				* UTC time is reckoned from 0h 0m 0s UTC on 1 January 1900.
				* If bit 0 is not set, the time is in the range 2036-2104 and
				* UTC time is reckoned from 6h 28m 16s UTC on 7 February 2036.
				*/
				tmpsecs  = tvb_get_ntohl(tvb, start);
				if ((tmpsecs & 0x80000000) != 0)
					time_stamp->secs = (time_t)((gint64)tmpsecs - NTP_TIMEDIFF1900TO1970SEC);
				else
					time_stamp->secs = (time_t)((gint64)tmpsecs + NTP_TIMEDIFF1970TO2036SEC);
				time_stamp->nsecs = 0;
			} else {
				time_stamp->secs  = 0;
				time_stamp->nsecs = 0;
				report_type_length_mismatch(tree, "an NTP seconds-only time stamp", length, (length < 4));
			}
			break;

		case ENC_TIME_SECS_NTP|ENC_LITTLE_ENDIAN:
			/*
			 * NTP time stamp, with 1-second resolution (i.e.,
			 * seconds since the NTP epoch), little-endian.
			 * Only supported for absolute times.
			 */
			DISSECTOR_ASSERT(!is_relative);

			/*
			 * We need a temporary variable here so the unsigned math
			 * works correctly (for years > 2036 according to RFC 2030
			 * chapter 3).
			 *
			 * If bit 0 is set, the UTC time is in the range 1968-2036 and
			 * UTC time is reckoned from 0h 0m 0s UTC on 1 January 1900.
			 * If bit 0 is not set, the time is in the range 2036-2104 and
			 * UTC time is reckoned from 6h 28m 16s UTC on 7 February 2036.
			 */
			if (length == 4) {
				tmpsecs  = tvb_get_letohl(tvb, start);
				if ((tmpsecs & 0x80000000) != 0)
					time_stamp->secs = (time_t)((gint64)tmpsecs - NTP_TIMEDIFF1900TO1970SEC);
				else
					time_stamp->secs = (time_t)((gint64)tmpsecs + NTP_TIMEDIFF1970TO2036SEC);
				time_stamp->nsecs = 0;
			} else {
				time_stamp->secs  = 0;
				time_stamp->nsecs = 0;
				report_type_length_mismatch(tree, "an NTP seconds-only time stamp", length, (length < 4));
			}
			break;
		case ENC_TIME_MSEC_NTP | ENC_BIG_ENDIAN:
			/*
			* Milliseconds, 1 to 8 bytes.
			* For absolute times, it's milliseconds since the
			* NTP epoch.
			*/
			if (length >= 1 && length <= 8) {
				guint64 msecs;

				msecs = get_uint64_value(tree, tvb, start, length, encoding);
				tmpsecs = (guint32)(msecs / 1000);
				/*
				* If bit 0 is set, the UTC time is in the range 1968-2036 and
				* UTC time is reckoned from 0h 0m 0s UTC on 1 January 1900.
				* If bit 0 is not set, the time is in the range 2036-2104 and
				* UTC time is reckoned from 6h 28m 16s UTC on 7 February 2036.
				*/
				if ((tmpsecs & 0x80000000) != 0)
					time_stamp->secs = (time_t)((gint64)tmpsecs - NTP_TIMEDIFF1900TO1970SEC);
				else
					time_stamp->secs = (time_t)((gint64)tmpsecs + NTP_TIMEDIFF1970TO2036SEC);
				time_stamp->nsecs = (int)(msecs % 1000)*1000000;
			}
			else {
				time_stamp->secs  = 0;
				time_stamp->nsecs = 0;
				report_type_length_mismatch(tree, "a time-in-milliseconds NTP time stamp", length, (length < 4));
			}
			break;

		case ENC_TIME_CLASSIC_MAC_OS_SECS|ENC_BIG_ENDIAN:
			/*
			 * Classic Mac OS time stamps, big-endian.
			 * Only supported for absolute times.
			 */
			DISSECTOR_ASSERT(!is_relative);

			if (length == 8) {
				tmp64secs  = tvb_get_ntoh64(tvb, start);
				time_stamp->secs = (time_t)(gint64)(tmp64secs - EPOCH_DELTA_1904_01_01_00_00_00_UTC);
				time_stamp->nsecs = 0;
			} else if (length == 4) {
				tmpsecs  = tvb_get_ntohl(tvb, start);
				time_stamp->secs = (time_t)(gint32)(tmpsecs - EPOCH_DELTA_1904_01_01_00_00_00_UTC);
				time_stamp->nsecs = 0;
			} else {
				time_stamp->secs  = 0;
				time_stamp->nsecs = 0;
				report_type_length_mismatch(tree, "an MP4 time stamp", length, (length < 4));
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


/*
 * Validates that field length bytes are available starting from
 * start (pos/neg). Throws an exception if they aren't.
 */
static void
test_length(header_field_info *hfinfo, tvbuff_t *tvb,
	    gint start, gint length, const guint encoding)
{
	gint size = length;

	if (!tvb)
		return;

	if ((hfinfo->type == FT_STRINGZ) ||
	    ((encoding & ENC_VARINT_MASK) &&
	     (IS_FT_UINT(hfinfo->type) || IS_FT_INT(hfinfo->type)))) {
		/* If we're fetching until the end of the TVB, only validate
		 * that the offset is within range.
		 */
		if (length == -1)
			size = 0;
	}

	tvb_ensure_bytes_exist(tvb, start, size);
}

static void
detect_trailing_stray_characters(guint encoding, const char *string, gint length, proto_item *pi)
{
	gboolean found_stray_character = FALSE;

	if (!string)
		return;

	switch (encoding & ENC_CHARENCODING_MASK) {
		case ENC_ASCII:
		case ENC_UTF_8:
			for (gint i = (gint)strlen(string); i < length; i++) {
				if (string[i] != '\0') {
					found_stray_character = TRUE;
					break;
				}
			}
			break;

		default:
			break;
	}

	if (found_stray_character) {
		expert_add_info(NULL, pi, &ei_string_trailing_characters);
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
	guint64	    value64;
	ws_in4_addr ipv4_value;
	float	    floatval;
	double	    doubleval;
	const char *stringval = NULL;
	nstime_t    time_stamp;
	gboolean    length_error;

	switch (new_fi->hfinfo->type) {
		case FT_NONE:
			/* no value to set for FT_NONE */
			break;

		case FT_PROTOCOL:
			proto_tree_set_protocol_tvb(new_fi, tvb, new_fi->hfinfo->name, length);
			break;

		case FT_BYTES:
			proto_tree_set_bytes_tvb(new_fi, tvb, start, length);
			break;

		case FT_UINT_BYTES:
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
				get_uint64_value(tree, tvb, start, length, encoding));
			break;

		case FT_CHAR:
		/* XXX - make these just FT_UINT? */
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
			if (encoding & ENC_VARINT_MASK) {
				new_fi->length = tvb_get_varint(tvb, start, (length == -1) ? FT_VARINT_MAX_LEN : length, &value64, encoding);
				value = (guint32)value64;
				if (!(encoding & ENC_VARINT_QUIC)) {
					new_fi->flags |= FI_VARINT;
				}
			}
			else {
				/*
				 * Map all non-zero values to little-endian for
				 * backwards compatibility.
				 */
				if (encoding)
					encoding = ENC_LITTLE_ENDIAN;

				value = get_uint_value(tree, tvb, start, length, encoding);
			}
			proto_tree_set_uint(new_fi, value);
			break;

		case FT_UINT40:
		case FT_UINT48:
		case FT_UINT56:
		case FT_UINT64:
			if (encoding & ENC_VARINT_MASK) {
				new_fi->length = tvb_get_varint(tvb, start, (length == -1) ? FT_VARINT_MAX_LEN : length, &value64, encoding);
				if (!(encoding & ENC_VARINT_QUIC)) {
					new_fi->flags |= FI_VARINT;
				}
			}
			else {
				/*
				 * Map all other non-zero values to little-endian for
				 * backwards compatibility.
				 */
				if (encoding)
					encoding = ENC_LITTLE_ENDIAN;

				value64 = get_uint64_value(tree, tvb, start, length, encoding);
			}
			proto_tree_set_uint64(new_fi, value64);
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

		case FT_INT40:
		case FT_INT48:
		case FT_INT56:
		case FT_INT64:
			/*
			 * Map all non-zero values to little-endian for
			 * backwards compatibility.
			 */
			if (encoding)
				encoding = ENC_LITTLE_ENDIAN;
			proto_tree_set_int64(new_fi,
				get_int64_value(tree, tvb, start, length, encoding));
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
			ipv4_value = tvb_get_ipv4(tvb, start);
			/*
			 * NOTE: to support code written when
			 * proto_tree_add_item() took a gboolean as its
			 * last argument, with FALSE meaning "big-endian"
			 * and TRUE meaning "little-endian", we treat any
			 * non-zero value of "encoding" as meaning
			 * "little-endian".
			 */
			proto_tree_set_ipv4(new_fi, encoding ? GUINT32_SWAP_LE_BE(ipv4_value) : ipv4_value);
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

		case FT_FCWWN:
			if (length != FT_FCWWN_LEN) {
				length_error = length < FT_FCWWN_LEN ? TRUE : FALSE;
				report_type_length_mismatch(tree, "an FCWWN address", length, length_error);
			}
			proto_tree_set_fcwwn_tvb(new_fi, tvb, start, length);
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
			stringval = get_string_value(PNODE_POOL(tree),
			    tvb, start, length, &length, encoding);
			proto_tree_set_string(new_fi, stringval);

			/* Instead of calling proto_item_set_len(), since we
			 * don't yet have a proto_item, we set the
			 * field_info's length ourselves.
			 *
			 * XXX - our caller can't use that length to
			 * advance an offset unless they arrange that
			 * there always be a protocol tree into which
			 * we're putting this item.
			 */
			new_fi->length = length;
			break;

		case FT_STRINGZ:
			stringval = get_stringz_value(PNODE_POOL(tree),
			    tree, tvb, start, length, &length, encoding);
			proto_tree_set_string(new_fi, stringval);

			/* Instead of calling proto_item_set_len(),
			 * since we don't yet have a proto_item, we
			 * set the field_info's length ourselves.
			 *
			 * XXX - our caller can't use that length to
			 * advance an offset unless they arrange that
			 * there always be a protocol tree into which
			 * we're putting this item.
			 */
			new_fi->length = length;
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
			stringval = get_uint_string_value(PNODE_POOL(tree),
			    tree, tvb, start, length, &length, encoding);
			proto_tree_set_string(new_fi, stringval);

			/* Instead of calling proto_item_set_len(), since we
			 * don't yet have a proto_item, we set the
			 * field_info's length ourselves.
			 *
			 * XXX - our caller can't use that length to
			 * advance an offset unless they arrange that
			 * there always be a protocol tree into which
			 * we're putting this item.
			 */
			new_fi->length = length;
			break;

		case FT_STRINGZPAD:
			stringval = get_stringzpad_value(PNODE_POOL(tree),
			    tvb, start, length, &length, encoding);
			proto_tree_set_string(new_fi, stringval);

			/* Instead of calling proto_item_set_len(), since we
			 * don't yet have a proto_item, we set the
			 * field_info's length ourselves.
			 *
			 * XXX - our caller can't use that length to
			 * advance an offset unless they arrange that
			 * there always be a protocol tree into which
			 * we're putting this item.
			 */
			new_fi->length = length;
			break;

		case FT_STRINGZTRUNC:
			stringval = get_stringztrunc_value(PNODE_POOL(tree),
			    tvb, start, length, &length, encoding);
			proto_tree_set_string(new_fi, stringval);

			/* Instead of calling proto_item_set_len(), since we
			 * don't yet have a proto_item, we set the
			 * field_info's length ourselves.
			 *
			 * XXX - our caller can't use that length to
			 * advance an offset unless they arrange that
			 * there always be a protocol tree into which
			 * we're putting this item.
			 */
			new_fi->length = length;
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
				encoding = ENC_TIME_SECS_NSECS|ENC_LITTLE_ENDIAN;

			get_time_value(tree, tvb, start, length, encoding, &time_stamp, FALSE);

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
				encoding = ENC_TIME_SECS_NSECS|ENC_LITTLE_ENDIAN;

			get_time_value(tree, tvb, start, length, encoding, &time_stamp, TRUE);

			proto_tree_set_time(new_fi, &time_stamp);
			break;
		case FT_IEEE_11073_SFLOAT:
			if (encoding)
				encoding = ENC_LITTLE_ENDIAN;
			if (length != 2) {
				length_error = length < 2 ? TRUE : FALSE;
				report_type_length_mismatch(tree, "a IEEE 11073 SFLOAT", length, length_error);
			}

			fvalue_set_uinteger(&new_fi->value, tvb_get_guint16(tvb, start, encoding));

			break;
		case FT_IEEE_11073_FLOAT:
			if (encoding)
				encoding = ENC_LITTLE_ENDIAN;
			if (length != 4) {
				length_error = length < 4 ? TRUE : FALSE;
				report_type_length_mismatch(tree, "a IEEE 11073 FLOAT", length, length_error);
			}

			break;
		default:
			REPORT_DISSECTOR_BUG("field %s is of unknown type %d (%s)",
					     new_fi->hfinfo->abbrev,
					     new_fi->hfinfo->type,
					     ftype_name(new_fi->hfinfo->type));
			break;
	}
	FI_SET_FLAG(new_fi, (encoding & ENC_LITTLE_ENDIAN) ? FI_LITTLE_ENDIAN : FI_BIG_ENDIAN);

	/* Don't add new node to proto_tree until now so that any exceptions
	 * raised by a tvbuff access method doesn't leave junk in the proto_tree. */
	/* XXX. wouldn't be better to add this item to tree, with some special flag (FI_EXCEPTION?)
	 *      to know which item caused exception? */
	pi = proto_tree_add_node(tree, new_fi);

	switch (new_fi->hfinfo->type) {

	case FT_STRING:
		detect_trailing_stray_characters(encoding, stringval, length, pi);
		break;

	default:
		break;
	}

	return pi;
}

proto_item *
proto_tree_add_item_ret_int(proto_tree *tree, int hfindex, tvbuff_t *tvb,
                            const gint start, gint length,
                            const guint encoding, gint32 *retval)
{
	header_field_info *hfinfo;
	field_info	  *new_fi;
	gint32		   value;

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);

	switch (hfinfo->type) {
	case FT_INT8:
	case FT_INT16:
	case FT_INT24:
	case FT_INT32:
		break;
	case FT_INT64:
		REPORT_DISSECTOR_BUG("64-bit signed integer field %s used with proto_tree_add_item_ret_int()",
		    hfinfo->abbrev);
	default:
		REPORT_DISSECTOR_BUG("Non-signed-integer field %s used with proto_tree_add_item_ret_int()",
		    hfinfo->abbrev);
	}

	CHECK_FOR_ZERO_OR_MINUS_LENGTH_AND_CLEANUP(length,
		{
			if(retval)
			{
				*retval = 0;
			}
		} );

	if (encoding & ENC_STRING) {
		REPORT_DISSECTOR_BUG("wrong encoding");
	}
	/* I believe it's ok if this is called with a NULL tree */
	value = get_int_value(tree, tvb, start, length, encoding);

	if (retval) {
		gint no_of_bits;
		*retval = value;
		if (hfinfo->bitmask) {
			/* Mask out irrelevant portions */
			*retval &= (guint32)(hfinfo->bitmask);
			/* Shift bits */
			*retval >>= hfinfo_bitshift(hfinfo);
		}
		no_of_bits = ws_count_ones(hfinfo->bitmask);
		*retval = ws_sign_ext32(*retval, no_of_bits);
	}

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfinfo->id, hfinfo);

	new_fi = new_field_info(tree, hfinfo, tvb, start, length);

	proto_tree_set_int(new_fi, value);

	new_fi->flags |= (encoding & ENC_LITTLE_ENDIAN) ? FI_LITTLE_ENDIAN : FI_BIG_ENDIAN;

	return proto_tree_add_node(tree, new_fi);
}

proto_item *
proto_tree_add_item_ret_uint(proto_tree *tree, int hfindex, tvbuff_t *tvb,
                             const gint start, gint length,
                             const guint encoding, guint32 *retval)
{
	header_field_info *hfinfo;
	field_info	  *new_fi;
	guint32		   value;

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);

	switch (hfinfo->type) {
	case FT_CHAR:
	case FT_UINT8:
	case FT_UINT16:
	case FT_UINT24:
	case FT_UINT32:
		break;
	default:
		REPORT_DISSECTOR_BUG("field %s is not of type FT_CHAR, FT_UINT8, FT_UINT16, FT_UINT24, or FT_UINT32",
		    hfinfo->abbrev);
	}

	CHECK_FOR_ZERO_OR_MINUS_LENGTH_AND_CLEANUP(length,
		{
			if(retval)
			{
				*retval = 0;
			}
		} );

	if (encoding & ENC_STRING) {
		REPORT_DISSECTOR_BUG("wrong encoding");
	}
	/* I believe it's ok if this is called with a NULL tree */
	/* XXX - modify if we ever support EBCDIC FT_CHAR */
	if (encoding & ENC_VARINT_MASK) {
		guint64 temp64;
		tvb_get_varint(tvb, start, length, &temp64, encoding);
		value = (guint32)temp64;
	} else {
		value = get_uint_value(tree, tvb, start, length, encoding);
	}

	if (retval) {
		*retval = value;
		if (hfinfo->bitmask) {
			/* Mask out irrelevant portions */
			*retval &= (guint32)(hfinfo->bitmask);
			/* Shift bits */
			*retval >>= hfinfo_bitshift(hfinfo);
		}
	}

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfinfo->id, hfinfo);

	new_fi = new_field_info(tree, hfinfo, tvb, start, length);

	proto_tree_set_uint(new_fi, value);

	new_fi->flags |= (encoding & ENC_LITTLE_ENDIAN) ? FI_LITTLE_ENDIAN : FI_BIG_ENDIAN;
	if (encoding & (ENC_VARINT_PROTOBUF|ENC_VARINT_ZIGZAG)) {
		new_fi->flags |= FI_VARINT;
	}
	return proto_tree_add_node(tree, new_fi);
}

/* Gets data from tvbuff, adds it to proto_tree, increments offset,
 * and returns proto_item* and uint value retreived*/
proto_item *
ptvcursor_add_ret_uint(ptvcursor_t *ptvc, int hfindex, gint length,
	      const guint encoding, guint32 *retval)
{
	field_info	  *new_fi;
	header_field_info *hfinfo;
	gint		   item_length;
	int		   offset;
	guint32		   value;

	offset = ptvc->offset;
	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);

	switch (hfinfo->type) {
	case FT_CHAR:
	case FT_UINT8:
	case FT_UINT16:
	case FT_UINT24:
	case FT_UINT32:
		break;
	default:
		REPORT_DISSECTOR_BUG("field %s is not of type FT_CHAR, FT_UINT8, FT_UINT16, FT_UINT24, or FT_UINT32",
		    hfinfo->abbrev);
	}

	get_hfi_length(hfinfo, ptvc->tvb, offset, &length, &item_length, encoding);
	test_length(hfinfo, ptvc->tvb, offset, item_length, encoding);

	/* I believe it's ok if this is called with a NULL tree */
	/* XXX - modify if we ever support EBCDIC FT_CHAR */
	value = get_uint_value(ptvc->tree, ptvc->tvb, offset, item_length, encoding);

	if (retval) {
		*retval = value;
		if (hfinfo->bitmask) {
			/* Mask out irrelevant portions */
			*retval &= (guint32)(hfinfo->bitmask);
			/* Shift bits */
			*retval >>= hfinfo_bitshift(hfinfo);
		}
	}

	ptvc->offset += get_full_length(hfinfo, ptvc->tvb, offset, length,
	    item_length, encoding);

	CHECK_FOR_NULL_TREE(ptvc->tree);

	/* Coast clear. Try and fake it */
	TRY_TO_FAKE_THIS_ITEM(ptvc->tree, hfindex, hfinfo);

	new_fi = new_field_info(ptvc->tree, hfinfo, ptvc->tvb, offset, item_length);

	return proto_tree_new_item(new_fi, ptvc->tree, ptvc->tvb,
		offset, length, encoding);
}

/* Gets data from tvbuff, adds it to proto_tree, increments offset,
 * and returns proto_item* and int value retreived*/
proto_item *
ptvcursor_add_ret_int(ptvcursor_t *ptvc, int hfindex, gint length,
	      const guint encoding, gint32 *retval)
{
	field_info	  *new_fi;
	header_field_info *hfinfo;
	gint		   item_length;
	int		   offset;
	guint32		   value;

	offset = ptvc->offset;
	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);

	switch (hfinfo->type) {
	case FT_INT8:
	case FT_INT16:
	case FT_INT24:
	case FT_INT32:
		break;
	default:
		REPORT_DISSECTOR_BUG("field %s is not of type FT_INT8, FT_INT16, FT_INT24, or FT_INT32",
		    hfinfo->abbrev);
	}

	get_hfi_length(hfinfo, ptvc->tvb, offset, &length, &item_length, encoding);
	test_length(hfinfo, ptvc->tvb, offset, item_length, encoding);

	/* I believe it's ok if this is called with a NULL tree */
	/* XXX - modify if we ever support EBCDIC FT_CHAR */
	value = get_int_value(ptvc->tree, ptvc->tvb, offset, item_length, encoding);

	if (retval) {
		gint no_of_bits;
		*retval = value;
		if (hfinfo->bitmask) {
			/* Mask out irrelevant portions */
			*retval &= (guint32)(hfinfo->bitmask);
			/* Shift bits */
			*retval >>= hfinfo_bitshift(hfinfo);
		}
		no_of_bits = ws_count_ones(hfinfo->bitmask);
		*retval = ws_sign_ext32(*retval, no_of_bits);
	}

	ptvc->offset += get_full_length(hfinfo, ptvc->tvb, offset, length,
	    item_length, encoding);

	CHECK_FOR_NULL_TREE(ptvc->tree);

	/* Coast clear. Try and fake it */
	TRY_TO_FAKE_THIS_ITEM(ptvc->tree, hfindex, hfinfo);

	new_fi = new_field_info(ptvc->tree, hfinfo, ptvc->tvb, offset, item_length);

	return proto_tree_new_item(new_fi, ptvc->tree, ptvc->tvb,
		offset, length, encoding);
}

/* Gets data from tvbuff, adds it to proto_tree, increments offset,
 * and returns proto_item* and string value retreived */
proto_item*
ptvcursor_add_ret_string(ptvcursor_t* ptvc, int hf, gint length, const guint encoding, wmem_allocator_t *scope, const guint8 **retval)
{
	header_field_info *hfinfo;
	field_info		*new_fi;
	const guint8	*value;
	gint			item_length;
	int				offset;

	offset = ptvc->offset;

	PROTO_REGISTRAR_GET_NTH(hf, hfinfo);

	switch (hfinfo->type) {
	case FT_STRING:
		value = get_string_value(scope, ptvc->tvb, offset, length, &item_length, encoding);
		break;
	case FT_STRINGZ:
		value = get_stringz_value(scope, ptvc->tree, ptvc->tvb, offset, length, &item_length, encoding);
		break;
	case FT_UINT_STRING:
		value = get_uint_string_value(scope, ptvc->tree, ptvc->tvb, offset, length, &item_length, encoding);
		break;
	case FT_STRINGZPAD:
		value = get_stringzpad_value(scope, ptvc->tvb, offset, length, &item_length, encoding);
		break;
	case FT_STRINGZTRUNC:
		value = get_stringztrunc_value(scope, ptvc->tvb, offset, length, &item_length, encoding);
		break;
	default:
		REPORT_DISSECTOR_BUG("field %s is not of type FT_STRING, FT_STRINGZ, FT_UINT_STRING, FT_STRINGZPAD, or FT_STRINGZTRUNC",
		    hfinfo->abbrev);
	}

	if (retval)
		*retval = value;

	ptvc->offset += item_length;

	CHECK_FOR_NULL_TREE(ptvc->tree);

	TRY_TO_FAKE_THIS_ITEM(ptvc->tree, hfinfo->id, hfinfo);

	new_fi = new_field_info(ptvc->tree, hfinfo, ptvc->tvb, offset, item_length);

	return proto_tree_new_item(new_fi, ptvc->tree, ptvc->tvb,
		offset, length, encoding);
}

/* Gets data from tvbuff, adds it to proto_tree, increments offset,
 * and returns proto_item* and boolean value retreived */
proto_item*
ptvcursor_add_ret_boolean(ptvcursor_t* ptvc, int hfindex, gint length, const guint encoding, gboolean *retval)
{
	header_field_info *hfinfo;
	field_info		*new_fi;
	gint			item_length;
	int				offset;
	guint64			value, bitval;

	offset = ptvc->offset;
	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);

	if (hfinfo->type != FT_BOOLEAN) {
		REPORT_DISSECTOR_BUG("field %s is not of type FT_BOOLEAN",
		    hfinfo->abbrev);
	}

	CHECK_FOR_ZERO_OR_MINUS_LENGTH_AND_CLEANUP(length,
		{
			if(retval)
			{
				*retval = FALSE;
			}
		} );

	if (encoding & ENC_STRING) {
		REPORT_DISSECTOR_BUG("wrong encoding");
	}

	get_hfi_length(hfinfo, ptvc->tvb, offset, &length, &item_length, encoding);
	test_length(hfinfo, ptvc->tvb, offset, item_length, encoding);

	/* I believe it's ok if this is called with a NULL tree */
	value = get_uint64_value(ptvc->tree, ptvc->tvb, offset, length, encoding);

	if (retval) {
		bitval = value;
		if (hfinfo->bitmask) {
			/* Mask out irrelevant portions */
			bitval &= hfinfo->bitmask;
		}
		*retval = (bitval != 0);
	}

	ptvc->offset += get_full_length(hfinfo, ptvc->tvb, offset, length,
	    item_length, encoding);

	CHECK_FOR_NULL_TREE(ptvc->tree);

	TRY_TO_FAKE_THIS_ITEM(ptvc->tree, hfinfo->id, hfinfo);

	new_fi = new_field_info(ptvc->tree, hfinfo, ptvc->tvb, offset, item_length);

	return proto_tree_new_item(new_fi, ptvc->tree, ptvc->tvb,
		offset, length, encoding);
}

proto_item *
proto_tree_add_item_ret_uint64(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    const gint start, gint length, const guint encoding, guint64 *retval)
{
	header_field_info *hfinfo;
	field_info	  *new_fi;
	guint64		   value;

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);

	switch (hfinfo->type) {
	case FT_UINT40:
	case FT_UINT48:
	case FT_UINT56:
	case FT_UINT64:
		break;
	default:
		REPORT_DISSECTOR_BUG("field %s is not of type FT_UINT40, FT_UINT48, FT_UINT56, or FT_UINT64",
		    hfinfo->abbrev);
	}

	CHECK_FOR_ZERO_OR_MINUS_LENGTH_AND_CLEANUP(length,
		{
			if(retval)
			{
				*retval = 0;
			}
		} );

	if (encoding & ENC_STRING) {
		REPORT_DISSECTOR_BUG("wrong encoding");
	}
	/* I believe it's ok if this is called with a NULL tree */
	if (encoding & ENC_VARINT_MASK) {
		tvb_get_varint(tvb, start, length, &value, encoding);
	} else {
		value = get_uint64_value(tree, tvb, start, length, encoding);
	}

	if (retval) {
		*retval = value;
		if (hfinfo->bitmask) {
			/* Mask out irrelevant portions */
			*retval &= hfinfo->bitmask;
			/* Shift bits */
			*retval >>= hfinfo_bitshift(hfinfo);
		}
	}

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfinfo->id, hfinfo);

	new_fi = new_field_info(tree, hfinfo, tvb, start, length);

	proto_tree_set_uint64(new_fi, value);

	new_fi->flags |= (encoding & ENC_LITTLE_ENDIAN) ? FI_LITTLE_ENDIAN : FI_BIG_ENDIAN;
	if (encoding & (ENC_VARINT_PROTOBUF|ENC_VARINT_ZIGZAG)) {
		new_fi->flags |= FI_VARINT;
	}

	return proto_tree_add_node(tree, new_fi);
}

proto_item *
proto_tree_add_item_ret_int64(proto_tree *tree, int hfindex, tvbuff_t *tvb,
	const gint start, gint length, const guint encoding, gint64 *retval)
{
	header_field_info *hfinfo;
	field_info	  *new_fi;
	gint64		   value;

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);

	switch (hfinfo->type) {
	case FT_INT40:
	case FT_INT48:
	case FT_INT56:
	case FT_INT64:
		break;
	default:
		REPORT_DISSECTOR_BUG("field %s is not of type FT_INT40, FT_INT48, FT_INT56, or FT_INT64",
			hfinfo->abbrev);
	}

	CHECK_FOR_ZERO_OR_MINUS_LENGTH_AND_CLEANUP(length,
		{
			if(retval)
			{
				*retval = 0;
			}
		} );

	if (encoding & ENC_STRING) {
		REPORT_DISSECTOR_BUG("wrong encoding");
	}
	/* I believe it's ok if this is called with a NULL tree */
	if (encoding & ENC_VARINT_MASK) {
		tvb_get_varint(tvb, start, length, &value, encoding);
	}
	else {
		value = get_int64_value(tree, tvb, start, length, encoding);
	}

	if (retval) {
		*retval = value;
	}

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfinfo->id, hfinfo);

	new_fi = new_field_info(tree, hfinfo, tvb, start, length);

	proto_tree_set_int64(new_fi, value);

	new_fi->flags |= (encoding & ENC_LITTLE_ENDIAN) ? FI_LITTLE_ENDIAN : FI_BIG_ENDIAN;
	if (encoding & (ENC_VARINT_PROTOBUF | ENC_VARINT_ZIGZAG)) {
		new_fi->flags |= FI_VARINT;
	}

	return proto_tree_add_node(tree, new_fi);
}

proto_item *
proto_tree_add_item_ret_varint(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    const gint start, gint length, const guint encoding, guint64 *retval, gint *lenretval)
{
	header_field_info *hfinfo;
	field_info	*new_fi;
	guint64		value;

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);

	if ((!IS_FT_INT(hfinfo->type)) && (!IS_FT_UINT(hfinfo->type))) {
		REPORT_DISSECTOR_BUG("field %s is not of type FT_UINT or FT_INT",
		    hfinfo->abbrev);
	}

	/* length validation for native number encoding caught by get_uint64_value() */
	/* length has to be -1 or > 0 regardless of encoding */
	if (length == 0)
		REPORT_DISSECTOR_BUG("Invalid length %d passed to proto_tree_add_item_ret_varint",
			length);

	if (encoding & ENC_STRING) {
		REPORT_DISSECTOR_BUG("wrong encoding");
	}

	length = tvb_get_varint(tvb, start, (length == -1) ? FT_VARINT_MAX_LEN : length, &value, encoding);

	if (retval) {
		*retval = value;
		if (hfinfo->bitmask) {
			/* Mask out irrelevant portions */
			*retval &= hfinfo->bitmask;
			/* Shift bits */
			*retval >>= hfinfo_bitshift(hfinfo);
		}
	}

	if (lenretval) {
		*lenretval = length;
	}

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfinfo->id, hfinfo);

	new_fi = new_field_info(tree, hfinfo, tvb, start, length);

	proto_tree_set_uint64(new_fi, value);

	new_fi->flags |= (encoding & ENC_LITTLE_ENDIAN) ? FI_LITTLE_ENDIAN : FI_BIG_ENDIAN;
	if (encoding & (ENC_VARINT_PROTOBUF|ENC_VARINT_ZIGZAG)) {
		new_fi->flags |= FI_VARINT;
	}

	return proto_tree_add_node(tree, new_fi);

}

proto_item *
proto_tree_add_item_ret_boolean(proto_tree *tree, int hfindex, tvbuff_t *tvb,
                                const gint start, gint length,
                                const guint encoding, gboolean *retval)
{
	header_field_info *hfinfo;
	field_info	  *new_fi;
	guint64		   value, bitval;

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);

	if (hfinfo->type != FT_BOOLEAN) {
		REPORT_DISSECTOR_BUG("field %s is not of type FT_BOOLEAN",
		    hfinfo->abbrev);
	}

	CHECK_FOR_ZERO_OR_MINUS_LENGTH_AND_CLEANUP(length,
		{
			if(retval)
			{
				*retval = FALSE;
			}
		} );

	if (encoding & ENC_STRING) {
		REPORT_DISSECTOR_BUG("wrong encoding");
	}
	/* I believe it's ok if this is called with a NULL tree */
	value = get_uint64_value(tree, tvb, start, length, encoding);

	if (retval) {
		bitval = value;
		if (hfinfo->bitmask) {
			/* Mask out irrelevant portions */
			bitval &= hfinfo->bitmask;
		}
		*retval = (bitval != 0);
	}

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfinfo->id, hfinfo);

	new_fi = new_field_info(tree, hfinfo, tvb, start, length);

	proto_tree_set_boolean(new_fi, value);

	new_fi->flags |= (encoding & ENC_LITTLE_ENDIAN) ? FI_LITTLE_ENDIAN : FI_BIG_ENDIAN;

	return proto_tree_add_node(tree, new_fi);
}

proto_item *
proto_tree_add_item_ret_ipv4(proto_tree *tree, int hfindex, tvbuff_t *tvb,
                             const gint start, gint length,
                             const guint encoding, ws_in4_addr *retval)
{
	header_field_info *hfinfo;
	field_info	  *new_fi;
	ws_in4_addr	   value;

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);

	switch (hfinfo->type) {
	case FT_IPv4:
		break;
	default:
		REPORT_DISSECTOR_BUG("field %s is not of type FT_IPv4",
		    hfinfo->abbrev);
	}

	if (length != FT_IPv4_LEN)
		REPORT_DISSECTOR_BUG("Invalid length %d passed to proto_tree_add_item_ret_ipv4",
			length);

	if (encoding & (ENC_STRING | ENC_VARINT_MASK)) {
		REPORT_DISSECTOR_BUG("wrong encoding");
	}

	/*
	 * NOTE: to support code written when proto_tree_add_item() took
	 * a gboolean as its last argument, with FALSE meaning "big-endian"
	 * and TRUE meaning "little-endian", we treat any non-zero value
	 * of "encoding" as meaning "little-endian".
	 */
	value = tvb_get_ipv4(tvb, start);
	if (encoding)
		value = GUINT32_SWAP_LE_BE(value);

	if (retval) {
		*retval = value;
	}

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfinfo->id, hfinfo);

	new_fi = new_field_info(tree, hfinfo, tvb, start, length);

	proto_tree_set_ipv4(new_fi, value);

	new_fi->flags |= encoding ? FI_LITTLE_ENDIAN : FI_BIG_ENDIAN;
	return proto_tree_add_node(tree, new_fi);
}

proto_item *
proto_tree_add_item_ret_string_and_length(proto_tree *tree, int hfindex,
                                          tvbuff_t *tvb,
                                          const gint start, gint length,
                                          const guint encoding,
                                          wmem_allocator_t *scope,
                                          const guint8 **retval,
                                          gint *lenretval)
{
	proto_item *pi;
	header_field_info *hfinfo;
	field_info	  *new_fi;
	const guint8	  *value;

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);

	switch (hfinfo->type) {
	case FT_STRING:
		value = get_string_value(scope, tvb, start, length, lenretval, encoding);
		break;
	case FT_STRINGZ:
		value = get_stringz_value(scope, tree, tvb, start, length, lenretval, encoding);
		break;
	case FT_UINT_STRING:
		value = get_uint_string_value(scope, tree, tvb, start, length, lenretval, encoding);
		break;
	case FT_STRINGZPAD:
		value = get_stringzpad_value(scope, tvb, start, length, lenretval, encoding);
		break;
	case FT_STRINGZTRUNC:
		value = get_stringztrunc_value(scope, tvb, start, length, lenretval, encoding);
		break;
	default:
		REPORT_DISSECTOR_BUG("field %s is not of type FT_STRING, FT_STRINGZ, FT_UINT_STRING, FT_STRINGZPAD, or FT_STRINGZTRUNC",
		    hfinfo->abbrev);
	}

	if (retval)
		*retval = value;

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfinfo->id, hfinfo);

	new_fi = new_field_info(tree, hfinfo, tvb, start, *lenretval);

	proto_tree_set_string(new_fi, value);

	new_fi->flags |= (encoding & ENC_LITTLE_ENDIAN) ? FI_LITTLE_ENDIAN : FI_BIG_ENDIAN;

	pi = proto_tree_add_node(tree, new_fi);

	switch (hfinfo->type) {

	case FT_STRINGZ:
	case FT_STRINGZPAD:
	case FT_STRINGZTRUNC:
	case FT_UINT_STRING:
		break;

	case FT_STRING:
		detect_trailing_stray_characters(encoding, value, length, pi);
		break;

	default:
		ws_assert_not_reached();
	}

	return pi;
}

proto_item *
proto_tree_add_item_ret_string(proto_tree *tree, int hfindex, tvbuff_t *tvb,
                               const gint start, gint length,
                               const guint encoding, wmem_allocator_t *scope,
                               const guint8 **retval)
{
	return proto_tree_add_item_ret_string_and_length(tree, hfindex,
	    tvb, start, length, encoding, scope, retval, &length);
}

proto_item *
proto_tree_add_item_ret_display_string_and_length(proto_tree *tree, int hfindex,
                                                  tvbuff_t *tvb,
                                                  const gint start, gint length,
                                                  const guint encoding,
                                                  wmem_allocator_t *scope,
                                                  char **retval,
                                                  gint *lenretval)
{
	proto_item *pi;
	header_field_info *hfinfo;
	field_info	  *new_fi;
	const guint8	  *value;
	guint32		   n = 0;

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);

	switch (hfinfo->type) {
	case FT_STRING:
		value = get_string_value(scope, tvb, start, length, lenretval, encoding);
		*retval = hfinfo_format_text(scope, hfinfo, value);
		break;
	case FT_STRINGZ:
		value = get_stringz_value(scope, tree, tvb, start, length, lenretval, encoding);
		*retval = hfinfo_format_text(scope, hfinfo, value);
		break;
	case FT_UINT_STRING:
		value = get_uint_string_value(scope, tree, tvb, start, length, lenretval, encoding);
		*retval = hfinfo_format_text(scope, hfinfo, value);
		break;
	case FT_STRINGZPAD:
		value = get_stringzpad_value(scope, tvb, start, length, lenretval, encoding);
		*retval = hfinfo_format_text(scope, hfinfo, value);
		break;
	case FT_STRINGZTRUNC:
		value = get_stringztrunc_value(scope, tvb, start, length, lenretval, encoding);
		*retval = hfinfo_format_text(scope, hfinfo, value);
		break;
	case FT_BYTES:
		value = tvb_get_ptr(tvb, start, length);
		*retval = hfinfo_format_bytes(scope, hfinfo, value, length);
		*lenretval = length;
		break;
	case FT_UINT_BYTES:
		n = get_uint_value(tree, tvb, start, length, encoding);
		value = tvb_get_ptr(tvb, start + length, n);
		*retval = hfinfo_format_bytes(scope, hfinfo, value, n);
		*lenretval = length + n;
		break;
	default:
		REPORT_DISSECTOR_BUG("field %s is not of type FT_STRING, FT_STRINGZ, FT_UINT_STRING, FT_STRINGZPAD, FT_STRINGZTRUNC, FT_BYTES, or FT_UINT_BYTES",
		    hfinfo->abbrev);
	}

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfinfo->id, hfinfo);

	new_fi = new_field_info(tree, hfinfo, tvb, start, *lenretval);

	switch (hfinfo->type) {

	case FT_STRING:
	case FT_STRINGZ:
	case FT_UINT_STRING:
	case FT_STRINGZPAD:
	case FT_STRINGZTRUNC:
		proto_tree_set_string(new_fi, value);
		break;

	case FT_BYTES:
		proto_tree_set_bytes(new_fi, value, length);
		break;

	case FT_UINT_BYTES:
		proto_tree_set_bytes(new_fi, value, n);
		break;

	default:
		ws_assert_not_reached();
	}

	new_fi->flags |= (encoding & ENC_LITTLE_ENDIAN) ? FI_LITTLE_ENDIAN : FI_BIG_ENDIAN;

	pi = proto_tree_add_node(tree, new_fi);

	switch (hfinfo->type) {

	case FT_STRINGZ:
	case FT_STRINGZPAD:
	case FT_STRINGZTRUNC:
	case FT_UINT_STRING:
		break;

	case FT_STRING:
		detect_trailing_stray_characters(encoding, value, length, pi);
		break;

	case FT_BYTES:
	case FT_UINT_BYTES:
		break;

	default:
		ws_assert_not_reached();
	}

	return pi;
}

proto_item *
proto_tree_add_item_ret_display_string(proto_tree *tree, int hfindex,
                                       tvbuff_t *tvb,
                                       const gint start, gint length,
                                       const guint encoding,
                                       wmem_allocator_t *scope,
                                       char **retval)
{
	return proto_tree_add_item_ret_display_string_and_length(tree, hfindex,
	    tvb, start, length, encoding, scope, retval, &length);
}

proto_item *
proto_tree_add_item_ret_time_string(proto_tree *tree, int hfindex,
	tvbuff_t *tvb,
	const gint start, gint length, const guint encoding,
	wmem_allocator_t *scope, char **retval)
{
	header_field_info *hfinfo;
	field_info	  *new_fi;
	nstime_t    time_stamp;

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);

	switch (hfinfo->type) {
	case FT_ABSOLUTE_TIME:
		get_time_value(tree, tvb, start, length, encoding, &time_stamp, FALSE);
		*retval = abs_time_to_str(scope, &time_stamp, hfinfo->display, TRUE);
		break;
	case FT_RELATIVE_TIME:
		get_time_value(tree, tvb, start, length, encoding, &time_stamp, TRUE);
		*retval = rel_time_to_secs_str(scope, &time_stamp);
		break;
	default:
		REPORT_DISSECTOR_BUG("field %s is not of type FT_ABSOLUTE_TIME or FT_RELATIVE_TIME",
			hfinfo->abbrev);
	}

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfinfo->id, hfinfo);

	new_fi = new_field_info(tree, hfinfo, tvb, start, length);

	switch (hfinfo->type) {

	case FT_ABSOLUTE_TIME:
	case FT_RELATIVE_TIME:
		proto_tree_set_time(new_fi, &time_stamp);
		break;
	default:
		ws_assert_not_reached();
	}

	new_fi->flags |= (encoding & ENC_LITTLE_ENDIAN) ? FI_LITTLE_ENDIAN : FI_BIG_ENDIAN;

	return proto_tree_add_node(tree, new_fi);
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
	int		   offset;

	offset = ptvc->offset;
	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);
	get_hfi_length(hfinfo, ptvc->tvb, offset, &length, &item_length, encoding);
	test_length(hfinfo, ptvc->tvb, offset, item_length, encoding);

	ptvc->offset += get_full_length(hfinfo, ptvc->tvb, offset, length,
	    item_length, encoding);

	CHECK_FOR_NULL_TREE(ptvc->tree);

	/* Coast clear. Try and fake it */
	TRY_TO_FAKE_THIS_ITEM(ptvc->tree, hfindex, hfinfo);

	new_fi = new_field_info(ptvc->tree, hfinfo, ptvc->tvb, offset, item_length);

	return proto_tree_new_item(new_fi, ptvc->tree, ptvc->tvb,
		offset, length, encoding);
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

	get_hfi_length(hfinfo, tvb, start, &length, &item_length, encoding);
	test_length(hfinfo, tvb, start, item_length, encoding);

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfinfo->id, hfinfo);

	new_fi = new_field_info(tree, hfinfo, tvb, start, item_length);

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

/* Add an item to a proto_tree, using the text label registered to that item;
   the item is extracted from the tvbuff handed to it.

   Return the length of the item through the pointer. */
proto_item *
proto_tree_add_item_new_ret_length(proto_tree *tree, header_field_info *hfinfo,
				   tvbuff_t *tvb, const gint start,
				   gint length, const guint encoding,
				   gint *lenretval)
{
	field_info        *new_fi;
	gint		  item_length;
	proto_item	 *item;

	DISSECTOR_ASSERT_HINT(hfinfo != NULL, "Not passed hfi!");

	get_hfi_length(hfinfo, tvb, start, &length, &item_length, encoding);
	test_length(hfinfo, tvb, start, item_length, encoding);

	if (!tree) {
		/*
		 * We need to get the correct item length here.
		 * That's normally done by proto_tree_new_item(),
		 * but we won't be calling it.
		 */
		*lenretval = get_full_length(hfinfo, tvb, start, length,
		    item_length, encoding);
		return NULL;
	}

	TRY_TO_FAKE_THIS_ITEM_OR_FREE(tree, hfinfo->id, hfinfo, {
		/*
		 * Even if the tree item is not referenced (and thus faked),
		 * the caller must still be informed of the actual length.
		 */
		*lenretval = get_full_length(hfinfo, tvb, start, length,
		    item_length, encoding);
	});

	new_fi = new_field_info(tree, hfinfo, tvb, start, item_length);

	item = proto_tree_new_item(new_fi, tree, tvb, start, length, encoding);
	*lenretval = new_fi->length;
	return item;
}

proto_item *
proto_tree_add_item_ret_length(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			       const gint start, gint length,
			       const guint encoding, gint *lenretval)
{
	register header_field_info *hfinfo;

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);
	return proto_tree_add_item_new_ret_length(tree, hfinfo, tvb, start, length, encoding, lenretval);
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

	CHECK_FOR_ZERO_OR_MINUS_LENGTH(length);

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

	CHECK_FOR_NULL_TREE_AND_FREE(tree,
		{
		    if (created_bytes)
			g_byte_array_free(created_bytes, TRUE);
		    created_bytes = NULL;
		    bytes = NULL;
		} );

	TRY_TO_FAKE_THIS_ITEM_OR_FREE(tree, hfinfo->id, hfinfo,
		{
		    if (created_bytes)
			g_byte_array_free(created_bytes, TRUE);
		    created_bytes = NULL;
		    bytes = NULL;
		} );

	/* n will be zero except when it's a FT_UINT_BYTES */
	new_fi = new_field_info(tree, hfinfo, tvb, start, n + length);

	if (encoding & ENC_STRING) {
		if (saved_err == ERANGE)
		    expert_add_info(NULL, tree, &ei_number_string_decoding_erange_error);
		else if (!bytes || saved_err != 0)
		    expert_add_info(NULL, tree, &ei_number_string_decoding_failed_error);

		if (bytes)
		    proto_tree_set_bytes_gbytearray(new_fi, bytes);
		else
		    proto_tree_set_bytes(new_fi, NULL, 0);

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

	CHECK_FOR_ZERO_OR_MINUS_LENGTH_AND_CLEANUP(length,
		{
			if(retval)
			{
				nstime_set_zero(retval);
			}
		} );

	nstime_set_zero(&time_stamp);

	if (encoding & ENC_STR_TIME_MASK) {
		DISSECTOR_ASSERT_FIELD_TYPE(hfinfo, FT_ABSOLUTE_TIME);
		/* The only string format that could be a relative time is
		 * ENC_ISO_8601_TIME, and that is treated as an absolute time
		 * relative to "now" currently.
		 */
		tvb_get_string_time(tvb, start, length, encoding, &time_stamp, endoff);
		/* grab the errno now before it gets overwritten */
		saved_err = errno;
	}
	else {
		DISSECTOR_ASSERT_FIELD_TYPE_IS_TIME(hfinfo);
		const gboolean is_relative = (hfinfo->type == FT_RELATIVE_TIME) ? TRUE : FALSE;

		tvb_ensure_bytes_exist(tvb, start, length);
		get_time_value(tree, tvb, start, length, encoding, &time_stamp, is_relative);
		if (endoff) *endoff = length;
	}

	if (err) *err = saved_err;

	if (retval) {
		retval->secs  = time_stamp.secs;
		retval->nsecs = time_stamp.nsecs;
	}

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfinfo->id, hfinfo);

	new_fi = new_field_info(tree, hfinfo, tvb, start, length);

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

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT_FIELD_TYPE(hfinfo, FT_NONE);

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
proto_tree_set_protocol_tvb(field_info *fi, tvbuff_t *tvb, const char* field_data, int length)
{
	fvalue_set_protocol(&fi->value, tvb, field_data, length);
}

/* Add a FT_PROTOCOL to a proto_tree */
proto_item *
proto_tree_add_protocol_format(proto_tree *tree, int hfindex, tvbuff_t *tvb,
			       gint start, gint length, const char *format, ...)
{
	proto_item	  *pi;
	tvbuff_t	  *protocol_tvb;
	va_list		   ap;
	header_field_info *hfinfo;
	gchar* protocol_rep;

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT_FIELD_TYPE(hfinfo, FT_PROTOCOL);

	/*
	 * This can throw an exception, so do it before we allocate anything.
	 */
	protocol_tvb = (start == 0 ? tvb : tvb_new_subset_length(tvb, start, length));

	pi = proto_tree_add_pi(tree, hfinfo, tvb, start, &length);

	va_start(ap, format);
	protocol_rep = ws_strdup_vprintf(format, ap);
	proto_tree_set_protocol_tvb(PNODE_FINFO(pi), protocol_tvb, protocol_rep, length);
	g_free(protocol_rep);
	va_end(ap);

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
	get_hfi_length(hfinfo, tvb, start, &length, &item_length, ENC_NA);
	test_length(hfinfo, tvb, start, item_length, ENC_NA);

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT_FIELD_TYPE(hfinfo, FT_BYTES);

	pi = proto_tree_add_pi(tree, hfinfo, tvb, start, &length);
	proto_tree_set_bytes(PNODE_FINFO(pi), start_ptr, length);

	return pi;
}

/* Add a FT_BYTES to a proto_tree */
proto_item *
proto_tree_add_bytes_with_length(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
             gint tvbuff_length, const guint8 *start_ptr, gint ptr_length)
{
	proto_item    *pi;
	header_field_info *hfinfo;
	gint          item_length;

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);
	get_hfi_length(hfinfo, tvb, start, &tvbuff_length, &item_length, ENC_NA);
	test_length(hfinfo, tvb, start, item_length, ENC_NA);

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT_FIELD_TYPE(hfinfo, FT_BYTES);

	pi = proto_tree_add_pi(tree, hfinfo, tvb, start, &tvbuff_length);
	proto_tree_set_bytes(PNODE_FINFO(pi), start_ptr, ptr_length);

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

	if (start_ptr == NULL)
		start_ptr = tvb_get_ptr(tvb, start, length);

	pi = proto_tree_add_bytes(tree, hfindex, tvb, start, length, start_ptr);

	TRY_TO_FAKE_THIS_REPR_NESTED(pi);

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

	if (start_ptr == NULL)
		start_ptr = tvb_get_ptr(tvb, start, length);

	pi = proto_tree_add_bytes(tree, hfindex, tvb, start, length, start_ptr);

	TRY_TO_FAKE_THIS_REPR_NESTED(pi);

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

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT_FIELD_TYPE_IS_TIME(hfinfo);

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

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT_FIELD_TYPE(hfinfo, FT_IPXNET);

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
		    gint length, ws_in4_addr value)
{
	proto_item	  *pi;
	header_field_info *hfinfo;

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT_FIELD_TYPE(hfinfo, FT_IPv4);

	pi = proto_tree_add_pi(tree, hfinfo, tvb, start, &length);
	proto_tree_set_ipv4(PNODE_FINFO(pi), value);

	return pi;
}

proto_item *
proto_tree_add_ipv4_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
				 gint start, gint length, ws_in4_addr value,
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
			   gint start, gint length, ws_in4_addr value,
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
proto_tree_set_ipv4(field_info *fi, ws_in4_addr value)
{
	fvalue_set_uinteger(&fi->value, value);
}

/* Add a FT_IPv6 to a proto_tree */
proto_item *
proto_tree_add_ipv6(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		    gint length, const ws_in6_addr *value_ptr)
{
	proto_item	  *pi;
	header_field_info *hfinfo;

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT_FIELD_TYPE(hfinfo, FT_IPv6);

	pi = proto_tree_add_pi(tree, hfinfo, tvb, start, &length);
	proto_tree_set_ipv6(PNODE_FINFO(pi), value_ptr->bytes);

	return pi;
}

proto_item *
proto_tree_add_ipv6_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
				 gint start, gint length,
				 const ws_in6_addr *value_ptr,
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
			   gint start, gint length,
			   const ws_in6_addr *value_ptr,
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

/* Set the FT_FCWWN value */
static void
proto_tree_set_fcwwn(field_info *fi, const guint8* value_ptr)
{
	DISSECTOR_ASSERT(value_ptr != NULL);
	fvalue_set_bytes(&fi->value, value_ptr);
}

static void
proto_tree_set_fcwwn_tvb(field_info *fi, tvbuff_t *tvb, gint start, gint length)
{
	proto_tree_set_fcwwn(fi, tvb_get_ptr(tvb, start, length));
}

/* Add a FT_GUID to a proto_tree */
proto_item *
proto_tree_add_guid(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		    gint length, const e_guid_t *value_ptr)
{
	proto_item	  *pi;
	header_field_info *hfinfo;

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT_FIELD_TYPE(hfinfo, FT_GUID);

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

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT_FIELD_TYPE(hfinfo, FT_OID);

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

/* Add a FT_STRING, FT_STRINGZ, FT_STRINGZPAD, or FT_STRINGZTRUNC to a
 * proto_tree. Creates own copy of string, and frees it when the proto_tree
 * is destroyed. */
proto_item *
proto_tree_add_string(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		      gint length, const char* value)
{
	proto_item	  *pi;
	header_field_info *hfinfo;
	gint		  item_length;

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);
	get_hfi_length(hfinfo, tvb, start, &length, &item_length, ENC_NA);
	/*
	 * Special case - if the length is 0, skip the test, so that
	 * we can have an empty string right after the end of the
	 * packet.  (This handles URL-encoded forms where the last field
	 * has no value so the form ends right after the =.)
	 */
	if (item_length != 0)
		test_length(hfinfo, tvb, start, item_length, ENC_NA);

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT_FIELD_TYPE_IS_STRING(hfinfo);

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

/* Set the FT_STRING value */
static void
proto_tree_set_string(field_info *fi, const char* value)
{
	if (value) {
		fvalue_set_string(&fi->value, value);
	} else {
		/*
		 * XXX - why is a null value for a string field
		 * considered valid?
		 */
		fvalue_set_string(&fi->value, "[ Null ]");
	}
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

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT_FIELD_TYPE(hfinfo, FT_ETHER);

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

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT_FIELD_TYPE(hfinfo, FT_BOOLEAN);

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

static proto_item *
proto_tree_add_boolean64(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		         gint length, guint64 value)
{
	proto_item	  *pi;
	header_field_info *hfinfo;

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT_FIELD_TYPE(hfinfo, FT_BOOLEAN);

	pi = proto_tree_add_pi(tree, hfinfo, tvb, start, &length);
	proto_tree_set_boolean(PNODE_FINFO(pi), value);

	return pi;
}

/* Set the FT_BOOLEAN value */
static void
proto_tree_set_boolean(field_info *fi, guint64 value)
{
	proto_tree_set_uint64(fi, value);
}

/* Generate, into "buf", a string showing the bits of a bitfield.
   Return a pointer to the character after that string. */
static char *
other_decode_bitfield_value(char *buf, const guint64 val, const guint64 mask, const int width)
{
	int i = 0;
	guint64 bit;
	char *p;

	p = buf;

	/* This is a devel error. It is safer to stop here. */
	DISSECTOR_ASSERT(width >= 1);

	bit = G_GUINT64_CONSTANT(1) << (width - 1);
	for (;;) {
		if (mask & bit) {
			/* This bit is part of the field.  Show its value. */
			if (val & bit)
				*p++ = '1';
			else
				*p++ = '0';
		} else {
			/* This bit is not part of the field. */
			*p++ = '.';
		}
		bit >>= 1;
		i++;
		if (i >= width)
			break;
		if (i % 4 == 0)
			*p++ = ' ';
	}
	*p = '\0';
	return p;
}

static char *
decode_bitfield_value(char *buf, const guint64 val, const guint64 mask, const int width)
{
	char *p;

	p = other_decode_bitfield_value(buf, val, mask, width);
	p = g_stpcpy(p, " = ");

	return p;
}

static char *
other_decode_bitfield_varint_value(char *buf, guint64 val, guint64 mask, const int width)
{
	int i = 0;
	guint64 bit;
	char *p;

	p = buf;

	/* This is a devel error. It is safer to stop here. */
	DISSECTOR_ASSERT(width >= 1);

	bit = G_GUINT64_CONSTANT(1) << (width - 1);
	for (;;) {
		if (((8-(i % 8)) != 8) && /* MSB is never used for value. */
			(mask & bit)) {
			/* This bit is part of the field.  Show its value. */
			if (val & bit)
				*p++ = '1';
			else
				*p++ = '0';
		} else {
			/* This bit is not part of the field. */
			*p++ = '.';
		}
		bit >>= 1;
		i++;
		if (i >= width)
			break;
		if (i % 4 == 0)
			*p++ = ' ';
	}

	*p = '\0';
	return p;
}

static char *
decode_bitfield_varint_value(char *buf, const guint64 val, const guint64 mask, const int width)
{
	char *p;

	p = other_decode_bitfield_varint_value(buf, val, mask, width);
	p = g_stpcpy(p, " = ");

	return p;
}

/* Add a FT_FLOAT to a proto_tree */
proto_item *
proto_tree_add_float(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		     gint length, float value)
{
	proto_item	  *pi;
	header_field_info *hfinfo;

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT_FIELD_TYPE(hfinfo, FT_FLOAT);

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

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT_FIELD_TYPE(hfinfo, FT_DOUBLE);

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

/* Add FT_CHAR or FT_UINT{8,16,24,32} to a proto_tree */
proto_item *
proto_tree_add_uint(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		    gint length, guint32 value)
{
	proto_item	  *pi = NULL;
	header_field_info *hfinfo;

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	switch (hfinfo->type) {
		case FT_CHAR:
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
		case FT_FRAMENUM:
			pi = proto_tree_add_pi(tree, hfinfo, tvb, start, &length);
			proto_tree_set_uint(PNODE_FINFO(pi), value);
			break;

		default:
			REPORT_DISSECTOR_BUG("field %s is not of type FT_CHAR, FT_UINT8, FT_UINT16, FT_UINT24, FT_UINT32, or FT_FRAMENUM",
			    hfinfo->abbrev);
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
		integer &= (guint32)(hfinfo->bitmask);

		/* Shift bits */
		integer >>= hfinfo_bitshift(hfinfo);

		FI_SET_FLAG(fi, FI_BITS_OFFSET(hfinfo_bitoffset(hfinfo)));
		FI_SET_FLAG(fi, FI_BITS_SIZE(hfinfo_mask_bitwidth(hfinfo)));
	}

	fvalue_set_uinteger(&fi->value, integer);
}

/* Add FT_UINT{40,48,56,64} to a proto_tree */
proto_item *
proto_tree_add_uint64(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		      gint length, guint64 value)
{
	proto_item	  *pi = NULL;
	header_field_info *hfinfo;

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	switch (hfinfo->type) {
		case FT_UINT40:
		case FT_UINT48:
		case FT_UINT56:
		case FT_UINT64:
		case FT_FRAMENUM:
			pi = proto_tree_add_pi(tree, hfinfo, tvb, start, &length);
			proto_tree_set_uint64(PNODE_FINFO(pi), value);
			break;

		default:
			REPORT_DISSECTOR_BUG("field %s is not of type FT_UINT40, FT_UINT48, FT_UINT56, FT_UINT64, or FT_FRAMENUM",
			    hfinfo->abbrev);
	}

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

/* Set the FT_UINT{40,48,56,64} value */
static void
proto_tree_set_uint64(field_info *fi, guint64 value)
{
	header_field_info *hfinfo;
	guint64		   integer;

	hfinfo = fi->hfinfo;
	integer = value;

	if (hfinfo->bitmask) {
		/* Mask out irrelevant portions */
		integer &= hfinfo->bitmask;

		/* Shift bits */
		integer >>= hfinfo_bitshift(hfinfo);

		FI_SET_FLAG(fi, FI_BITS_OFFSET(hfinfo_bitoffset(hfinfo)));
		FI_SET_FLAG(fi, FI_BITS_SIZE(hfinfo_mask_bitwidth(hfinfo)));
	}

	fvalue_set_uinteger64(&fi->value, integer);
}

/* Add FT_INT{8,16,24,32} to a proto_tree */
proto_item *
proto_tree_add_int(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		   gint length, gint32 value)
{
	proto_item	  *pi = NULL;
	header_field_info *hfinfo;

	CHECK_FOR_NULL_TREE(tree);

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
			REPORT_DISSECTOR_BUG("field %s is not of type FT_INT8, FT_INT16, FT_INT24, or FT_INT32",
			    hfinfo->abbrev);
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
		integer &= (guint32)(hfinfo->bitmask);

		/* Shift bits */
		integer >>= hfinfo_bitshift(hfinfo);

		no_of_bits = ws_count_ones(hfinfo->bitmask);
		integer = ws_sign_ext32(integer, no_of_bits);

		FI_SET_FLAG(fi, FI_BITS_OFFSET(hfinfo_bitoffset(hfinfo)));
		FI_SET_FLAG(fi, FI_BITS_SIZE(hfinfo_mask_bitwidth(hfinfo)));
	}

	fvalue_set_sinteger(&fi->value, integer);
}

/* Add FT_INT{40,48,56,64} to a proto_tree */
proto_item *
proto_tree_add_int64(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		     gint length, gint64 value)
{
	proto_item	  *pi = NULL;
	header_field_info *hfinfo;

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	switch (hfinfo->type) {
		case FT_INT40:
		case FT_INT48:
		case FT_INT56:
		case FT_INT64:
			pi = proto_tree_add_pi(tree, hfinfo, tvb, start, &length);
			proto_tree_set_int64(PNODE_FINFO(pi), value);
			break;

		default:
			REPORT_DISSECTOR_BUG("field %s is not of type FT_INT40, FT_INT48, FT_INT56, or FT_INT64",
			    hfinfo->abbrev);
	}

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

/* Set the FT_INT{40,48,56,64} value */
static void
proto_tree_set_int64(field_info *fi, gint64 value)
{
	header_field_info *hfinfo;
	guint64		   integer;
	gint		   no_of_bits;

	hfinfo = fi->hfinfo;
	integer = value;

	if (hfinfo->bitmask) {
		/* Mask out irrelevant portions */
		integer &= hfinfo->bitmask;

		/* Shift bits */
		integer >>= hfinfo_bitshift(hfinfo);

		no_of_bits = ws_count_ones(hfinfo->bitmask);
		integer = ws_sign_ext64(integer, no_of_bits);

		FI_SET_FLAG(fi, FI_BITS_OFFSET(hfinfo_bitoffset(hfinfo)));
		FI_SET_FLAG(fi, FI_BITS_SIZE(hfinfo_mask_bitwidth(hfinfo)));
	}

	fvalue_set_sinteger64(&fi->value, integer);
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

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT_FIELD_TYPE(hfinfo, FT_EUI64);

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
	fvalue_set_uinteger64(&fi->value, value);
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
	guint depth = 1;

	/*
	 * Restrict our depth. proto_tree_traverse_pre_order and
	 * proto_tree_traverse_post_order (and possibly others) are recursive
	 * so we need to be mindful of our stack size.
	 */
	if (tree->first_child == NULL) {
		for (tnode = tree; tnode != NULL; tnode = tnode->parent) {
			depth++;
			if (G_UNLIKELY(depth > prefs.gui_max_tree_depth)) {
				THROW_MESSAGE(DissectorError, wmem_strdup_printf(PNODE_POOL(tree),
						     "Maximum tree depth %d exceeded for \"%s\" - \"%s\" (%s:%u) (Maximum depth can be increased in advanced preferences)",
						     prefs.gui_max_tree_depth,
						     fi->hfinfo->name, fi->hfinfo->abbrev, G_STRFUNC, __LINE__));
			}
		}
	}

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
		REPORT_DISSECTOR_BUG("\"%s\" - \"%s\" tfi->tree_type: %d invalid (%s:%u)",
				     fi->hfinfo->name, fi->hfinfo->abbrev, tfi->tree_type, __FILE__, __LINE__);
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

	get_hfi_length(hfinfo, tvb, start, length, &item_length, ENC_NA);
	fi = new_field_info(tree, hfinfo, tvb, start, item_length);
	pi = proto_tree_add_node(tree, fi);

	return pi;
}


static void
get_hfi_length(header_field_info *hfinfo, tvbuff_t *tvb, const gint start, gint *length,
		   gint *item_length, const guint encoding)
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
		 * For FT_NONE, FT_PROTOCOL, FT_BYTES, FT_STRING,
		 * FT_STRINGZPAD, and FT_STRINGZTRUNC fields, a length
		 * of -1 means "set the length to what remains in the
		 * tvbuff".
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
		 * For ENC_VARINT_PROTOBUF|ENC_VARINT_QUIC|ENC_VARIANT_ZIGZAG, it means "find the end of the string",
		 * and if the tvbuff if short, we just throw an exception.
		 *
		 * It's not valid for any other type of field.  For those
		 * fields, we treat -1 the same way we treat other
		 * negative values - we assume the length is a Really
		 * Big Positive Number, and throw a ReportedBoundsError
		 * exception, under the assumption that the Really Big
		 * Length would run past the end of the packet.
		 */
		if ((IS_FT_INT(hfinfo->type)) || (IS_FT_UINT(hfinfo->type))) {
			if (encoding & (ENC_VARINT_PROTOBUF|ENC_VARINT_ZIGZAG)) {
				/*
				 * Leave the length as -1, so our caller knows
				 * it was -1.
				 */
				*item_length = *length;
				return;
			} else if (encoding & ENC_VARINT_QUIC) {
				switch (tvb_get_guint8(tvb, start) >> 6)
				{
				case 0: /* 0b00 => 1 byte length (6 bits Usable) */
					*item_length = 1;
					break;
				case 1: /* 0b01 => 2 bytes length (14 bits Usable) */
					*item_length = 2;
					break;
				case 2: /* 0b10 => 4 bytes length (30 bits Usable) */
					*item_length = 4;
					break;
				case 3: /* 0b11 => 8 bytes length (62 bits Usable) */
					*item_length = 8;
					break;
				}
			}
		}

		switch (hfinfo->type) {

		case FT_PROTOCOL:
		case FT_NONE:
		case FT_BYTES:
		case FT_STRING:
		case FT_STRINGZPAD:
		case FT_STRINGZTRUNC:
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
			*length = tvb_captured_length(tvb) ? tvb_ensure_captured_length_remaining(tvb, start) : 0;
			DISSECTOR_ASSERT(*length >= 0);
			break;

		case FT_STRINGZ:
			/*
			 * Leave the length as -1, so our caller knows
			 * it was -1.
			 */
			break;

		default:
			THROW(ReportedBoundsError);
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

static gint
get_full_length(header_field_info *hfinfo, tvbuff_t *tvb, const gint start,
		gint length, guint item_length, const gint encoding)
{
	guint32 n;

	/*
	 * We need to get the correct item length here.
	 * That's normally done by proto_tree_new_item(),
	 * but we won't be calling it.
	 */
	switch (hfinfo->type) {

	case FT_NONE:
	case FT_PROTOCOL:
	case FT_BYTES:
		/*
		 * The length is the specified length.
		 */
		break;

	case FT_UINT_BYTES:
		n = get_uint_value(NULL, tvb, start, length, encoding);
		item_length += n;
		if ((int)item_length < length) {
			THROW(ReportedBoundsError);
		}
		break;

	/* XXX - make these just FT_UINT? */
	case FT_UINT8:
	case FT_UINT16:
	case FT_UINT24:
	case FT_UINT32:
	case FT_UINT40:
	case FT_UINT48:
	case FT_UINT56:
	case FT_UINT64:
	/* XXX - make these just FT_INT? */
	case FT_INT8:
	case FT_INT16:
	case FT_INT24:
	case FT_INT32:
	case FT_INT40:
	case FT_INT48:
	case FT_INT56:
	case FT_INT64:
		if (encoding & ENC_VARINT_MASK) {
			if (length < -1) {
				report_type_length_mismatch(NULL, "a FT_[U]INT", length, TRUE);
			}
			if (length == -1) {
				guint64 dummy;
				/* This can throw an exception */
				/* XXX - do this without fetching the varint? */
				length = tvb_get_varint(tvb, start, FT_VARINT_MAX_LEN, &dummy, encoding);
				if (length == 0) {
					THROW(ReportedBoundsError);
				}
			}
			item_length = length;
			break;
		}

		/*
		 * The length is the specified length.
		 */
		break;

	case FT_BOOLEAN:
	case FT_CHAR:
	case FT_IPv4:
	case FT_IPXNET:
	case FT_IPv6:
	case FT_FCWWN:
	case FT_AX25:
	case FT_VINES:
	case FT_ETHER:
	case FT_EUI64:
	case FT_GUID:
	case FT_OID:
	case FT_REL_OID:
	case FT_SYSTEM_ID:
	case FT_FLOAT:
	case FT_DOUBLE:
	case FT_STRING:
		/*
		 * The length is the specified length.
		 */
		break;

	case FT_STRINGZ:
		if (length < -1) {
			report_type_length_mismatch(NULL, "a string", length, TRUE);
		}
		if (length == -1) {
			/* This can throw an exception */
			/* XXX - do this without fetching the string? */
			wmem_free(NULL, tvb_get_stringz_enc(NULL, tvb, start, &length, encoding));
		}
		item_length = length;
		break;

	case FT_UINT_STRING:
		n = get_uint_value(NULL, tvb, start, length, encoding & ~ENC_CHARENCODING_MASK);
		item_length += n;
		if ((int)item_length < length) {
			THROW(ReportedBoundsError);
		}
		break;

	case FT_STRINGZPAD:
	case FT_STRINGZTRUNC:
	case FT_ABSOLUTE_TIME:
	case FT_RELATIVE_TIME:
	case FT_IEEE_11073_SFLOAT:
	case FT_IEEE_11073_FLOAT:
		/*
		 * The length is the specified length.
		 */
		break;

	default:
		REPORT_DISSECTOR_BUG("field %s has type %d (%s) not handled in gset_full_length()",
				     hfinfo->abbrev,
				     hfinfo->type,
				     ftype_name(hfinfo->type));
		break;
	}
	return item_length;
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

	fi->total_layer_num = tree->tree_data->pinfo->curr_layer_num;
	fi->proto_layer_num = tree->tree_data->pinfo->curr_proto_layer_num;

	return fi;
}

/* If the protocol tree is to be visible, set the representation of a
   proto_tree entry with the name of the field for the item and with
   the value formatted with the supplied printf-style format and
   argument list. */
static void
proto_tree_set_representation_value(proto_item *pi, const char *format, va_list ap)
{
	ws_assert(pi);

	/* If the tree (GUI) or item isn't visible it's pointless for us to generate the protocol
	 * items string representation */
	if (PTREE_DATA(pi)->visible && !proto_item_is_hidden(pi)) {
		int               ret = 0;
		field_info        *fi = PITEM_FINFO(pi);
		header_field_info *hf;

		DISSECTOR_ASSERT(fi);

		hf = fi->hfinfo;

		ITEM_LABEL_NEW(PNODE_POOL(pi), fi->rep);
		if (hf->bitmask && (hf->type == FT_BOOLEAN || IS_FT_UINT(hf->type))) {
			guint64 val;
			char *p;

			if (IS_FT_UINT32(hf->type))
				val = fvalue_get_uinteger(&fi->value);
			else
				val = fvalue_get_uinteger64(&fi->value);

			val <<= hfinfo_bitshift(hf);

			p = decode_bitfield_value(fi->rep->representation, val, hf->bitmask, hfinfo_container_bitwidth(hf));
			ret = (int) (p - fi->rep->representation);
		}

		/* put in the hf name */
		ret += snprintf(fi->rep->representation + ret, ITEM_LABEL_LENGTH - ret, "%s: ", hf->name);

		/* If possible, Put in the value of the string */
		if (ret < ITEM_LABEL_LENGTH) {
			ret += vsnprintf(fi->rep->representation + ret,
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

	if (!proto_item_is_hidden(pi)) {
		ITEM_LABEL_NEW(PNODE_POOL(pi), fi->rep);
		ret = vsnprintf(fi->rep->representation, ITEM_LABEL_LENGTH,
				  format, ap);
		if (ret >= ITEM_LABEL_LENGTH) {
			/* Uh oh, we don't have enough room.  Tell the user
			 * that the field is truncated.
			 */
			LABEL_MARK_TRUNCATED_START(fi->rep->representation);
		}
	}
}

static int
protoo_strlcpy(gchar *dest, const gchar *src, gsize dest_size)
{
	if (dest_size == 0) return 0;

	gsize res = g_strlcpy(dest, src, dest_size);

	/* At most dest_size - 1 characters will be copied
         * (unless dest_size is 0). */
	if (res >= dest_size)
		res = dest_size - 1;
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

static void
hfinfo_remove_from_gpa_name_map(const header_field_info *hfinfo)
{
	g_free(last_field_name);
	last_field_name = NULL;

	if (!hfinfo->same_name_next && hfinfo->same_name_prev_id == -1) {
		/* No hfinfo with the same name */
		g_hash_table_steal(gpa_name_map, hfinfo->abbrev);
		return;
	}

	if (hfinfo->same_name_next) {
		hfinfo->same_name_next->same_name_prev_id = hfinfo->same_name_prev_id;
	}

	if (hfinfo->same_name_prev_id != -1) {
		header_field_info *same_name_prev = hfinfo_same_name_get_prev(hfinfo);
		same_name_prev->same_name_next = hfinfo->same_name_next;
		if (!hfinfo->same_name_next) {
			/* It's always the latest added hfinfo which is stored in gpa_name_map */
			g_hash_table_insert(gpa_name_map, (gpointer) (same_name_prev->abbrev), same_name_prev);
		}
	}
}

int
proto_item_fill_display_label(field_info *finfo, gchar *display_label_str, const int label_str_size)
{
	header_field_info *hfinfo = finfo->hfinfo;
	int label_len = 0;
	char *tmp_str;
	const char *str;
	const guint8 *bytes;
	guint32 number;
	guint64 number64;
	const true_false_string  *tfstring;
	const char *hf_str_val;
	char number_buf[48];
	const char *number_out;
	address addr;
	ws_in4_addr ipv4;

	switch (hfinfo->type) {

		case FT_NONE:
		case FT_PROTOCOL:
			return protoo_strlcpy(display_label_str, UTF8_CHECK_MARK, label_str_size);

		case FT_UINT_BYTES:
		case FT_BYTES:
			tmp_str = hfinfo_format_bytes(NULL,
				hfinfo,
				fvalue_get_bytes(&finfo->value),
				fvalue_length(&finfo->value));
			label_len = protoo_strlcpy(display_label_str, tmp_str, label_str_size);
			wmem_free(NULL, tmp_str);
			break;

		case FT_ABSOLUTE_TIME:
			tmp_str = abs_time_to_str(NULL, fvalue_get_time(&finfo->value), hfinfo->display, TRUE);
			label_len = protoo_strlcpy(display_label_str, tmp_str, label_str_size);
			wmem_free(NULL, tmp_str);
			break;

		case FT_RELATIVE_TIME:
			tmp_str = rel_time_to_secs_str(NULL, fvalue_get_time(&finfo->value));
			label_len = protoo_strlcpy(display_label_str, tmp_str, label_str_size);
			wmem_free(NULL, tmp_str);
			break;

		case FT_BOOLEAN:
			number64 = fvalue_get_uinteger64(&finfo->value);
			tfstring = &tfs_true_false;
			if (hfinfo->strings) {
				tfstring = (const struct true_false_string*) hfinfo->strings;
			}
			label_len = protoo_strlcpy(display_label_str,
					tfs_get_string(!!number64, tfstring), label_str_size);
			break;

		case FT_CHAR:
			number = fvalue_get_uinteger(&finfo->value);

			if (FIELD_DISPLAY(hfinfo->display) == BASE_CUSTOM) {
				gchar tmp[ITEM_LABEL_LENGTH];
				custom_fmt_func_t fmtfunc = (custom_fmt_func_t)hfinfo->strings;

				DISSECTOR_ASSERT(fmtfunc);
				fmtfunc(tmp, number);

				label_len = protoo_strlcpy(display_label_str, tmp, label_str_size);

			} else if (hfinfo->strings) {
				number_out = hf_try_val_to_str(number, hfinfo);

				if (!number_out) {
					number_out = hfinfo_char_value_format_display(BASE_HEX, number_buf, number);
				}

				label_len = protoo_strlcpy(display_label_str, number_out, label_str_size);

			} else {
				number_out = hfinfo_char_value_format(hfinfo, number_buf, number);

				label_len = protoo_strlcpy(display_label_str, number_out, label_str_size);
			}

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

			if (FIELD_DISPLAY(hfinfo->display) == BASE_CUSTOM) {
				gchar tmp[ITEM_LABEL_LENGTH];
				custom_fmt_func_t fmtfunc = (custom_fmt_func_t)hfinfo->strings;

				DISSECTOR_ASSERT(fmtfunc);
				fmtfunc(tmp, number);

				label_len = protoo_strlcpy(display_label_str, tmp, label_str_size);

			} else if (hfinfo->strings && hfinfo->type != FT_FRAMENUM) {
				if (hfinfo->display & BASE_UNIT_STRING) {
					number_out = hfinfo_numeric_value_format(hfinfo, number_buf, number);
					label_len = protoo_strlcpy(display_label_str, number_out, label_str_size);
					hf_str_val = hf_try_val_to_str(number, hfinfo);
					label_len += protoo_strlcpy(display_label_str+label_len, hf_str_val, label_str_size-label_len);
				} else {
					number_out = hf_try_val_to_str(number, hfinfo);

					if (!number_out) {
						number_out = hfinfo_number_value_format_display(hfinfo, hfinfo->display, number_buf, number);
					}

					label_len = protoo_strlcpy(display_label_str, number_out, label_str_size);
				}
			} else {
				number_out = hfinfo_number_value_format(hfinfo, number_buf, number);

				label_len = protoo_strlcpy(display_label_str, number_out, label_str_size);
			}

			break;

		case FT_INT40:
		case FT_INT48:
		case FT_INT56:
		case FT_INT64:
		case FT_UINT40:
		case FT_UINT48:
		case FT_UINT56:
		case FT_UINT64:
			hf_str_val = NULL;
			number64 = IS_FT_INT(hfinfo->type) ?
				(guint64) fvalue_get_sinteger64(&finfo->value) :
				fvalue_get_uinteger64(&finfo->value);

			if (FIELD_DISPLAY(hfinfo->display) == BASE_CUSTOM) {
				gchar tmp[ITEM_LABEL_LENGTH];
				custom_fmt_func_64_t fmtfunc64 = (custom_fmt_func_64_t)hfinfo->strings;

				DISSECTOR_ASSERT(fmtfunc64);
				fmtfunc64(tmp, number64);

				label_len = protoo_strlcpy(display_label_str, tmp, label_str_size);
			} else if (hfinfo->strings) {
				if (hfinfo->display & BASE_UNIT_STRING) {
					number_out = hfinfo_numeric_value_format64(hfinfo, number_buf, number64);
					label_len = protoo_strlcpy(display_label_str, number_out, label_str_size);
					hf_str_val = hf_try_val64_to_str(number64, hfinfo);
					label_len += protoo_strlcpy(display_label_str+label_len, hf_str_val, label_str_size-label_len);
				} else {
					number_out = hf_try_val64_to_str(number64, hfinfo);

					if (!number_out)
						number_out = hfinfo_number_value_format_display64(hfinfo, hfinfo->display, number_buf, number64);

					label_len = protoo_strlcpy(display_label_str, number_out, label_str_size);
				}
			} else {
				number_out = hfinfo_number_value_format64(hfinfo, number_buf, number64);

				label_len = protoo_strlcpy(display_label_str, number_out, label_str_size);
			}

			break;

		case FT_EUI64:
			tmp_str = eui64_to_str(NULL, fvalue_get_uinteger64(&finfo->value));
			label_len = protoo_strlcpy(display_label_str, tmp_str, label_str_size);
			wmem_free(NULL, tmp_str);
			break;

		case FT_IPv4:
			ipv4 = fvalue_get_uinteger(&finfo->value);
			set_address (&addr, AT_IPv4, 4, &ipv4);
			address_to_str_buf(&addr, display_label_str, label_str_size);
			label_len = (int)strlen(display_label_str);
			break;

		case FT_IPv6:
			bytes = fvalue_get_bytes(&finfo->value);
			set_address (&addr, AT_IPv6, sizeof(ws_in6_addr), bytes);
			address_to_str_buf(&addr, display_label_str, label_str_size);
			label_len = (int)strlen(display_label_str);
			break;

		case FT_FCWWN:
			set_address (&addr, AT_FCWWN, FCWWN_ADDR_LEN, fvalue_get_bytes(&finfo->value));
			address_to_str_buf(&addr, display_label_str, label_str_size);
			label_len = (int)strlen(display_label_str);
			break;

		case FT_ETHER:
			set_address (&addr, AT_ETHER, FT_ETHER_LEN, fvalue_get_bytes(&finfo->value));
			address_to_str_buf(&addr, display_label_str, label_str_size);
			label_len = (int)strlen(display_label_str);
			break;

		case FT_GUID:
			tmp_str = guid_to_str(NULL, fvalue_get_guid(&finfo->value));
			label_len = protoo_strlcpy(display_label_str, tmp_str, label_str_size);
			wmem_free(NULL, tmp_str);
			break;

		case FT_REL_OID:
			bytes = fvalue_get_bytes(&finfo->value);
			tmp_str = rel_oid_resolved_from_encoded(NULL, bytes, fvalue_length(&finfo->value));
			label_len = protoo_strlcpy(display_label_str, tmp_str, label_str_size);
			wmem_free(NULL, tmp_str);
			break;

		case FT_OID:
			bytes = fvalue_get_bytes(&finfo->value);
			tmp_str = oid_resolved_from_encoded(NULL, bytes, fvalue_length(&finfo->value));
			label_len = protoo_strlcpy(display_label_str, tmp_str, label_str_size);
			wmem_free(NULL, tmp_str);
			break;

		case FT_SYSTEM_ID:
			bytes = fvalue_get_bytes(&finfo->value);
			tmp_str = print_system_id(NULL, bytes, fvalue_length(&finfo->value));
			label_len = protoo_strlcpy(display_label_str, tmp_str, label_str_size);
			wmem_free(NULL, tmp_str);
			break;

		case FT_FLOAT:
		case FT_DOUBLE:
			label_len = (int)fill_display_label_float(finfo, display_label_str);
			break;

		case FT_STRING:
		case FT_STRINGZ:
		case FT_UINT_STRING:
		case FT_STRINGZPAD:
		case FT_STRINGZTRUNC:
			str = fvalue_get_string(&finfo->value);
			tmp_str = hfinfo_format_text(NULL, hfinfo, str);
			label_len = protoo_strlcpy(display_label_str, tmp_str, label_str_size);
			wmem_free(NULL, tmp_str);
			break;

		default:
			/* First try ftype string representation */
			tmp_str = fvalue_to_string_repr(NULL, &finfo->value, FTREPR_DISPLAY, hfinfo->display);
			if (!tmp_str) {
				/* Default to show as bytes */
				bytes = fvalue_get_bytes(&finfo->value);
				tmp_str = bytes_to_str(NULL, bytes, fvalue_length(&finfo->value));
			}
			label_len = protoo_strlcpy(display_label_str, tmp_str, label_str_size);
			wmem_free(NULL, tmp_str);
			break;
	}
	return label_len;
}

/* -------------------------- */
const gchar *
proto_custom_set(proto_tree* tree, GSList *field_ids, gint occurrence,
		 gchar *result, gchar *expr, const int size)
{
	guint32             number;
	guint64             number64;
	const guint8       *bytes;

	int                 len, prev_len, last, i, offset_r = 0, offset_e = 0, prev_offset_r = 0, label_len;
	GPtrArray          *finfos;
	field_info         *finfo         = NULL;
	header_field_info*  hfinfo;
	const gchar        *abbrev        = NULL;

	const char *hf_str_val;
	char number_buf[48];
	const char *number_out;
	char *str;
	int *field_idx;
	int field_id;
	int ii = 0;

	ws_assert(field_ids != NULL);
	while ((field_idx = (int *) g_slist_nth_data(field_ids, ii++))) {
		field_id = *field_idx;
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

		prev_len = 0; /* Reset handled occurrences */

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

			/* Store the offset where all the occurrences of this
			 * field begin in the result.
			 */
			prev_offset_r = offset_r;
			if (offset_r && (offset_r < (size - 2))) {
				prev_offset_r++; /* skip the comma added below */
			}

			while (i <= last) {
				finfo = (field_info *)g_ptr_array_index(finfos, i);

				if (offset_r && (offset_r < (size - 2)))
					result[offset_r++] = ',';

				if (offset_e && (offset_e < (size - 2)))
					expr[offset_e++] = ',';

				switch (hfinfo->type) {

					case FT_NONE:
					case FT_PROTOCOL:
						/* Prevent multiple check marks */
						if (strstr(result, UTF8_CHECK_MARK ",") == NULL) {
							offset_r += proto_item_fill_display_label(finfo, result+offset_r, size-offset_r);
						} else {
							result[--offset_r] = '\0'; /* Remove the added trailing ',' again */
						}
						break;

					case FT_BOOLEAN:
						offset_r += proto_item_fill_display_label(finfo, result+offset_r, size-offset_r);

						number64 = fvalue_get_uinteger64(&finfo->value);
						offset_e += protoo_strlcpy(expr+offset_e,
								number64 ? "1" : "0", size-offset_e);
						break;

					case FT_CHAR:
						offset_r += proto_item_fill_display_label(finfo, result+offset_r, size-offset_r);

						number = fvalue_get_uinteger(&finfo->value);

						if (hfinfo->strings && FIELD_DISPLAY(hfinfo->display) == BASE_NONE) {
							hf_str_val = hf_try_val_to_str(number, hfinfo);
							snprintf(expr+offset_e, size-offset_e, "\"%s\"", hf_str_val);
						} else {
							number_out = hfinfo_char_value_format(hfinfo, number_buf, number);

							(void) g_strlcpy(expr+offset_e, number_out, size-offset_e);
						}

						offset_e = (int)strlen(expr);
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
						offset_r += proto_item_fill_display_label(finfo, result+offset_r, size-offset_r);

						hf_str_val = NULL;
						number = IS_FT_INT(hfinfo->type) ?
							(guint32) fvalue_get_sinteger(&finfo->value) :
							fvalue_get_uinteger(&finfo->value);

						if (hfinfo->strings && hfinfo->type != FT_FRAMENUM && FIELD_DISPLAY(hfinfo->display) != BASE_CUSTOM) {
							hf_str_val = hf_try_val_to_str(number, hfinfo);
						}

						if (hf_str_val && FIELD_DISPLAY(hfinfo->display) == BASE_NONE) {

							hf_str_val = hf_try_val_to_str(number, hfinfo);
							snprintf(expr+offset_e, size-offset_e, "\"%s\"", hf_str_val);
						} else {
							number_out = hfinfo_numeric_value_format(hfinfo, number_buf, number);

							(void) g_strlcpy(expr+offset_e, number_out, size-offset_e);
						}

						offset_e = (int)strlen(expr);
						break;

					case FT_INT40:
					case FT_INT48:
					case FT_INT56:
					case FT_INT64:
					case FT_UINT40:
					case FT_UINT48:
					case FT_UINT56:
					case FT_UINT64:
						offset_r += proto_item_fill_display_label(finfo, result+offset_r, size-offset_r);

						hf_str_val = NULL;
						number64 = IS_FT_INT(hfinfo->type) ?
							(guint64) fvalue_get_sinteger64(&finfo->value) :
							fvalue_get_uinteger64(&finfo->value);

						if (hfinfo->strings && hfinfo->type != FT_FRAMENUM && FIELD_DISPLAY(hfinfo->display) != BASE_CUSTOM) {
							hf_str_val = hf_try_val64_to_str(number64, hfinfo);
						}

						if (hf_str_val && FIELD_DISPLAY(hfinfo->display) == BASE_NONE) {
							snprintf(expr+offset_e, size-offset_e, "\"%s\"", hf_str_val);
						} else {
							number_out = hfinfo_numeric_value_format64(hfinfo, number_buf, number64);

							(void) g_strlcpy(expr+offset_e, number_out, size-offset_e);
						}

						offset_e = (int)strlen(expr);
						break;

					case FT_REL_OID:
						offset_r += proto_item_fill_display_label(finfo, result+offset_r, size-offset_r);

						bytes = fvalue_get_bytes(&finfo->value);
						str = rel_oid_encoded2string(NULL, bytes, fvalue_length(&finfo->value));
						offset_e += protoo_strlcpy(expr+offset_e, str, size-offset_e);
						wmem_free(NULL, str);
						break;

					case FT_OID:
						offset_r += proto_item_fill_display_label(finfo, result+offset_r, size-offset_r);

						bytes = fvalue_get_bytes(&finfo->value);
						str = oid_encoded2string(NULL, bytes, fvalue_length(&finfo->value));
						offset_e += protoo_strlcpy(expr+offset_e, str, size-offset_e);
						wmem_free(NULL, str);
						break;

					case FT_SYSTEM_ID:
						label_len = proto_item_fill_display_label(finfo, result+offset_r, size-offset_r);

						offset_e += protoo_strlcpy(expr+offset_e, result+offset_r, size-offset_e);

						offset_r += label_len;
						break;

					default:
						offset_r += proto_item_fill_display_label(finfo, result+offset_r, size-offset_r);
						break;
				}
				i++;
			}

			switch (hfinfo->type) {

				case FT_BOOLEAN:
				case FT_CHAR:
				case FT_UINT8:
				case FT_UINT16:
				case FT_UINT24:
				case FT_UINT32:
				case FT_UINT40:
				case FT_UINT48:
				case FT_UINT56:
				case FT_UINT64:
				case FT_FRAMENUM:
				case FT_INT8:
				case FT_INT16:
				case FT_INT24:
				case FT_INT32:
				case FT_INT40:
				case FT_INT48:
				case FT_INT56:
				case FT_INT64:
				case FT_OID:
				case FT_REL_OID:
				case FT_SYSTEM_ID:
					/* for these types, "expr" is filled in the loop above */
					break;

				default:
					/* for all others, just copy the latest "result" to "expr" */
					offset_e += protoo_strlcpy(expr+offset_e, result+prev_offset_r, size-offset_e);
					break;
			}

			/* XXX: Why is only the first abbreviation returned for a multifield
			 * custom column? */
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
	}

	return abbrev ? abbrev : "";
}


/* Set text of proto_item after having already been created. */
void
proto_item_set_text(proto_item *pi, const char *format, ...)
{
	field_info *fi = NULL;
	va_list     ap;

	TRY_TO_FAKE_THIS_REPR_VOID(pi);

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

	TRY_TO_FAKE_THIS_REPR_VOID(pi);

	fi = PITEM_FINFO(pi);
	if (fi == NULL) {
		return;
	}

	if (!proto_item_is_hidden(pi)) {
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
			vsnprintf(fi->rep->representation + curlen,
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

	TRY_TO_FAKE_THIS_REPR_VOID(pi);

	fi = PITEM_FINFO(pi);
	if (fi == NULL) {
		return;
	}

	if (!proto_item_is_hidden(pi)) {
		/*
		 * If we don't already have a representation,
		 * generate the default representation.
		 */
		if (fi->rep == NULL) {
			ITEM_LABEL_NEW(PNODE_POOL(pi), fi->rep);
			proto_item_fill_label(fi, representation);
		} else
			(void) g_strlcpy(representation, fi->rep->representation, ITEM_LABEL_LENGTH);

		va_start(ap, format);
		vsnprintf(fi->rep->representation,
			ITEM_LABEL_LENGTH, format, ap);
		va_end(ap);
		(void) g_strlcat(fi->rep->representation, representation, ITEM_LABEL_LENGTH);
	}
}

static void
finfo_set_len(field_info *fi, const gint length)
{
	gint length_remaining;

	DISSECTOR_ASSERT_HINT(length >= 0, fi->hfinfo->abbrev);
	length_remaining = tvb_captured_length_remaining(fi->ds_tvb, fi->start);
	if (length > length_remaining)
		fi->length = length_remaining;
	else
		fi->length = length;

	/* If we have an FT_PROTOCOL we need to set the length of the fvalue tvbuff as well. */
	if (fvalue_type_ftenum(&fi->value) == FT_PROTOCOL) {
		fvalue_set_protocol(&fi->value, NULL, NULL, fi->length);
	}

	/*
	 * You cannot just make the "len" field of a GByteArray
	 * larger, if there's no data to back that length;
	 * you can only make it smaller.
	 */
	if (fvalue_type_ftenum(&fi->value) == FT_BYTES && fi->length <= (gint)fi->value.value.bytes->len)
		fi->value.value.bytes->len = fi->length;
}

void
proto_item_set_len(proto_item *pi, const gint length)
{
	field_info *fi;

	/* XXX: We actually want to set the length of non visible proto_items
         * that are protocols, if we're not faking protocols, so that
         * ui/proto_hier_stats can work correctly. (#17877) But we don't
         * want to set the length of the protocol accidentally when intending
         * to set the length of a faked child. However, we can't tell whether
         * this is called by the original item or the child when faking items.
         */
	TRY_TO_FAKE_THIS_REPR_VOID(pi);

	fi = PITEM_FINFO(pi);
	if (fi == NULL)
		return;

	finfo_set_len(fi, length);
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
	gint length;

	TRY_TO_FAKE_THIS_REPR_VOID(pi);

	fi = PITEM_FINFO(pi);
	if (fi == NULL)
		return;

	end += tvb_raw_offset(tvb);
	DISSECTOR_ASSERT(end >= fi->start);
	length = end - fi->start;

	finfo_set_len(fi, length);
}

int
proto_item_get_len(const proto_item *pi)
{
	field_info *fi;

	if (!pi)
		return -1;
	fi = PITEM_FINFO(pi);
	return fi ? fi->length : -1;
}

void
proto_item_set_bits_offset_len(proto_item *ti, int bits_offset, int bits_len) {
	if (!ti) {
		return;
	}
	FI_SET_FLAG(PNODE_FINFO(ti), FI_BITS_OFFSET(bits_offset));
	FI_SET_FLAG(PNODE_FINFO(ti), FI_BITS_SIZE(bits_len));
}

char *
proto_item_get_display_repr(wmem_allocator_t *scope, proto_item *pi)
{
	field_info *fi;

	if (!pi)
		return "";
	fi = PITEM_FINFO(pi);
	DISSECTOR_ASSERT(fi->hfinfo != NULL);
	return fvalue_to_string_repr(scope, &fi->value, FTREPR_DISPLAY, fi->hfinfo->display);
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
proto_tree_prime_with_hfid(proto_tree *tree _U_, const gint hfid)
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
	/* XXX: If we're faking items, this will return the parent of the
	 * faked item, which may not be the logical parent expected.
	 * We have no way of knowing exactly which real item the fake
	 * item refers to here (the original item or one of its children
	 * using it as a fake), and thus whether the parent should be the
	 * faked item itself or the faked item's parent.
	 *
	 * In that case, there's a good chance we end up returning the
	 * root node of the protocol tree, which has "PNODE_FINFO()" null.
	 *
	 * If we later add items to _that_, they will not be faked even though
	 * they _should_ be, hurting performance (#8069). Also protocol
	 * hierarchy stats (which fakes everything but protocols) may
	 * behave oddly if unexpected items are added under the root node.
	 */
	if (!ti)
		return NULL;
	return ti->parent;
}

proto_item *
proto_item_get_parent_nth(proto_item *ti, int gen) {
	/* XXX: Same issue as above, even more so. */
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
proto_tree_get_parent_tree(proto_tree *tree) {
	/* XXX: Same issue as proto_item_get_parent */
	if (!tree)
		return NULL;

	/* we're the root tree, there's no parent
	   return ourselves so the caller has at least a tree to attach to */
	if (!tree->parent)
		return tree;

	return (proto_tree *)tree->parent;
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
		for (curr_item = tree->first_child; curr_item != NULL; curr_item = curr_item->next) {
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

static void
check_protocol_filter_name_or_fail(const char *filter_name)
{
	/* Require at least two characters. */
	if (filter_name[0] == '\0' || filter_name[1] == '\0') {
		REPORT_DISSECTOR_BUG("Protocol filter name \"%s\" cannot have length less than two.", filter_name);
	}

	if (proto_check_field_name(filter_name) != '\0') {
		REPORT_DISSECTOR_BUG("Protocol filter name \"%s\" has one or more invalid characters."
			" Allowed are letters, digits, '-', '_' and non-repeating '.'."
			" This might be caused by an inappropriate plugin or a development error.", filter_name);
	}

	/* Check that it doesn't match some very common numeric forms. */
	if (filter_name[0] == '0' &&
				(filter_name[1] == 'x' || filter_name[1] == 'X' ||
				filter_name[1] == 'b' || filter_name[1] == 'B')) {
		REPORT_DISSECTOR_BUG("Protocol filter name \"%s\" cannot start with \"%c%c\".",
						filter_name, filter_name[0], filter_name[1]);
	}

	/* Check that it doesn't have all decimal digits. */
	bool all_digits = true;
	for (const char *s = filter_name; *s != '\0'; s++) {
		if (!g_ascii_isdigit(*s)) {
			all_digits = false;
			break;
		}
	}
	if (all_digits) {
		REPORT_DISSECTOR_BUG("Protocol filter name \"%s\" cannot be composed of all decimal digits.",
						filter_name);
	}

	/* Check for reserved keywords. */
	if (g_hash_table_contains(proto_reserved_filter_names, filter_name)) {
		REPORT_DISSECTOR_BUG("Protocol filter name \"%s\" is invalid because it is a reserved keyword."
			" This might be caused by an inappropriate plugin or a development error.", filter_name);
	}
}

int
proto_register_protocol(const char *name, const char *short_name,
			const char *filter_name)
{
	protocol_t *protocol;
	header_field_info *hfinfo;

	/*
	 * Make sure there's not already a protocol with any of those
	 * names.  Crash if there is, as that's an error in the code
	 * or an inappropriate plugin.
	 * This situation has to be fixed to not register more than one
	 * protocol with the same name.
	 */

	if (g_hash_table_lookup(proto_names, name)) {
		/* ws_error will terminate the program */
		REPORT_DISSECTOR_BUG("Duplicate protocol name \"%s\"!"
			" This might be caused by an inappropriate plugin or a development error.", name);
	}

	if (g_hash_table_lookup(proto_short_names, short_name)) {
		REPORT_DISSECTOR_BUG("Duplicate protocol short_name \"%s\"!"
			" This might be caused by an inappropriate plugin or a development error.", short_name);
	}

	check_protocol_filter_name_or_fail(filter_name);

	if (g_hash_table_lookup(proto_filter_names, filter_name)) {
		REPORT_DISSECTOR_BUG("Duplicate protocol filter_name \"%s\"!"
			" This might be caused by an inappropriate plugin or a development error.", filter_name);
	}

	/*
	 * Add this protocol to the list of known protocols;
	 * the list is sorted by protocol short name.
	 */
	protocol = g_new(protocol_t, 1);
	protocol->name = name;
	protocol->short_name = short_name;
	protocol->filter_name = filter_name;
	protocol->fields = NULL; /* Delegate until actually needed */
	protocol->is_enabled = TRUE; /* protocol is enabled by default */
	protocol->enabled_by_default = TRUE; /* see previous comment */
	protocol->can_toggle = TRUE;
	protocol->parent_proto_id = -1;
	protocol->heur_list = NULL;

	/* List will be sorted later by name, when all protocols completed registering */
	protocols = g_list_prepend(protocols, protocol);
	g_hash_table_insert(proto_names, (gpointer)name, protocol);
	g_hash_table_insert(proto_filter_names, (gpointer)filter_name, protocol);
	g_hash_table_insert(proto_short_names, (gpointer)short_name, protocol);

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
	hfinfo->parent = -1; /* This field differentiates protos and fields */

	protocol->proto_id = proto_register_field_init(hfinfo, hfinfo->parent);
	return protocol->proto_id;
}

int
proto_register_protocol_in_name_only(const char *name, const char *short_name, const char *filter_name, int parent_proto, enum ftenum field_type)
{
	protocol_t *protocol;
	header_field_info *hfinfo;

	/*
	 * Helper protocols don't need the strict rules as a "regular" protocol
	 * Just register it in a list and make a hf_ field from it
	 */
	if ((field_type != FT_PROTOCOL) && (field_type != FT_BYTES)) {
		REPORT_DISSECTOR_BUG("Pino \"%s\" must be of type FT_PROTOCOL or FT_BYTES.", name);
	}

	if (parent_proto < 0) {
		REPORT_DISSECTOR_BUG("Must have a valid parent protocol for helper protocol \"%s\"!"
			" This might be caused by an inappropriate plugin or a development error.", name);
	}

	check_protocol_filter_name_or_fail(filter_name);

	/* Add this protocol to the list of helper protocols (just so it can be properly freed) */
	protocol = g_new(protocol_t, 1);
	protocol->name = name;
	protocol->short_name = short_name;
	protocol->filter_name = filter_name;
	protocol->fields = NULL; /* Delegate until actually needed */

	/* Enabling and toggling is really determined by parent protocol,
	   but provide default values here */
	protocol->is_enabled = TRUE;
	protocol->enabled_by_default = TRUE;
	protocol->can_toggle = TRUE;

	protocol->parent_proto_id = parent_proto;
	protocol->heur_list = NULL;

	/* List will be sorted later by name, when all protocols completed registering */
	protocols = g_list_prepend(protocols, protocol);

	/* Here we allocate a new header_field_info struct */
	hfinfo = g_slice_new(header_field_info);
	hfinfo->name = name;
	hfinfo->abbrev = filter_name;
	hfinfo->type = field_type;
	hfinfo->display = BASE_NONE;
	if (field_type == FT_BYTES) {
		hfinfo->display |= (BASE_NO_DISPLAY_VALUE|BASE_PROTOCOL_INFO);
	}
	hfinfo->strings = protocol;
	hfinfo->bitmask = 0;
	hfinfo->ref_type = HF_REF_TYPE_NONE;
	hfinfo->blurb = NULL;
	hfinfo->parent = -1; /* This field differentiates protos and fields */

	protocol->proto_id = proto_register_field_init(hfinfo, hfinfo->parent);
	return protocol->proto_id;
}

gboolean
proto_deregister_protocol(const char *short_name)
{
	protocol_t *protocol;
	header_field_info *hfinfo;
	int proto_id;
	guint i;

	proto_id = proto_get_id_by_short_name(short_name);
	protocol = find_protocol_by_id(proto_id);
	if (protocol == NULL)
		return FALSE;

	g_hash_table_remove(proto_names, protocol->name);
	g_hash_table_remove(proto_short_names, (gpointer)short_name);
	g_hash_table_remove(proto_filter_names, (gpointer)protocol->filter_name);

	if (protocol->fields) {
		for (i = 0; i < protocol->fields->len; i++) {
			hfinfo = (header_field_info *)g_ptr_array_index(protocol->fields, i);
			hfinfo_remove_from_gpa_name_map(hfinfo);
			expert_deregister_expertinfo(hfinfo->abbrev);
			g_ptr_array_add(deregistered_fields, gpa_hfinfo.hfi[hfinfo->id]);
		}
		g_ptr_array_free(protocol->fields, TRUE);
		protocol->fields = NULL;
	}

	g_list_free(protocol->heur_list);

	/* Remove this protocol from the list of known protocols */
	protocols = g_list_remove(protocols, protocol);

	g_ptr_array_add(deregistered_fields, gpa_hfinfo.hfi[proto_id]);
	g_hash_table_steal(gpa_name_map, protocol->filter_name);

	g_free(last_field_name);
	last_field_name = NULL;

	return TRUE;
}

void
proto_register_alias(const int proto_id, const char *alias_name)
{
	protocol_t *protocol;

	protocol = find_protocol_by_id(proto_id);
	if (alias_name && protocol) {
		g_hash_table_insert(gpa_protocol_aliases, (gpointer) alias_name, (gpointer)protocol->filter_name);
	}
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

	if ((protocol == NULL) || (protocol->fields == NULL) || (protocol->fields->len == 0))
		return NULL;

	*cookie = GUINT_TO_POINTER(0);
	return (header_field_info *)g_ptr_array_index(protocol->fields, 0);
}

header_field_info *
proto_get_next_protocol_field(const int proto_id, void **cookie)
{
	protocol_t *protocol = find_protocol_by_id(proto_id);
	guint       i        = GPOINTER_TO_UINT(*cookie);

	i++;

	if ((protocol->fields == NULL) || (i >= protocol->fields->len))
		return NULL;

	*cookie = GUINT_TO_POINTER(i);
	return (header_field_info *)g_ptr_array_index(protocol->fields, i);
}

protocol_t *
find_protocol_by_id(const int proto_id)
{
	header_field_info *hfinfo;

	if (proto_id < 0)
		return NULL;

	PROTO_REGISTRAR_GET_NTH(proto_id, hfinfo);
	if (hfinfo->type != FT_PROTOCOL) {
		DISSECTOR_ASSERT(hfinfo->display & BASE_PROTOCOL_INFO);
	}
	return (protocol_t *)hfinfo->strings;
}

int
proto_get_id(const protocol_t *protocol)
{
	return protocol->proto_id;
}

gboolean
proto_name_already_registered(const gchar *name)
{
	DISSECTOR_ASSERT_HINT(name, "No name present");

	if (g_hash_table_lookup(proto_names, name) != NULL)
		return TRUE;
	return FALSE;
}

int
proto_get_id_by_filter_name(const gchar *filter_name)
{
	const protocol_t *protocol = NULL;

	DISSECTOR_ASSERT_HINT(filter_name, "No filter name present");

	protocol = (const protocol_t *)g_hash_table_lookup(proto_filter_names, filter_name);

	if (protocol == NULL)
		return -1;
	return protocol->proto_id;
}

int
proto_get_id_by_short_name(const gchar *short_name)
{
	const protocol_t *protocol = NULL;

	DISSECTOR_ASSERT_HINT(short_name, "No short name present");

	protocol = (const protocol_t *)g_hash_table_lookup(proto_short_names, short_name);

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

void proto_add_heuristic_dissector(protocol_t *protocol, const char *short_name)
{
	heur_dtbl_entry_t* heuristic_dissector;

	if (protocol == NULL)
		return;

	heuristic_dissector = find_heur_dissector_by_unique_short_name(short_name);
	if (heuristic_dissector != NULL)
	{
		protocol->heur_list = g_list_prepend (protocol->heur_list, heuristic_dissector);
	}
}

void proto_heuristic_dissector_foreach(const protocol_t *protocol, GFunc func, gpointer user_data)
{
	if (protocol == NULL)
		return;

	g_list_foreach(protocol->heur_list, func, user_data);
}

void
proto_get_frame_protocols(const wmem_list_t *layers, gboolean *is_ip,
			  gboolean *is_tcp, gboolean *is_udp,
			  gboolean *is_sctp, gboolean *is_tls,
			  gboolean *is_rtp,
			  gboolean *is_lte_rlc)
{
	wmem_list_frame_t *protos = wmem_list_head(layers);
	int	    proto_id;
	const char *proto_name;

	/* Walk the list of a available protocols in the packet and
	   attempt to find "major" ones. */
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
		} else if (is_tls && !strcmp(proto_name, "tls")) {
			*is_tls = TRUE;
		} else if (is_rtp && !strcmp(proto_name, "rtp")) {
			*is_rtp = TRUE;
		} else if (is_lte_rlc && !strcmp(proto_name, "rlc-lte")) {
			*is_lte_rlc = TRUE;
		}

		protos = wmem_list_frame_next(protos);
	}
}

gboolean
proto_is_frame_protocol(const wmem_list_t *layers, const char* proto_name)
{
	wmem_list_frame_t *protos = wmem_list_head(layers);
	int	    proto_id;
	const char *name;

	/* Walk the list of a available protocols in the packet and
	   attempt to find the specified protocol. */
	while (protos != NULL)
	{
		proto_id = GPOINTER_TO_INT(wmem_list_frame_data(protos));
		name = proto_get_protocol_filter_name(proto_id);

		if (!strcmp(name, proto_name))
		{
			return TRUE;
		}

		protos = wmem_list_frame_next(protos);
	}

	return FALSE;
}

gchar *
proto_list_layers(const packet_info *pinfo)
{
	wmem_strbuf_t *buf;
	wmem_list_frame_t *layers = wmem_list_head(pinfo->layers);

	buf = wmem_strbuf_sized_new(pinfo->pool, 128, 0);

	/* Walk the list of layers in the packet and
	   return a string of all entries. */
	while (layers != NULL)
	{
		wmem_strbuf_append(buf, proto_get_protocol_filter_name(GPOINTER_TO_UINT(wmem_list_frame_data(layers))));

		layers = wmem_list_frame_next(layers);
		if (layers != NULL) {
			wmem_strbuf_append_c(buf, ':');
		}
	}

	return wmem_strbuf_finalize(buf);
}

gboolean
proto_is_pino(const protocol_t *protocol)
{
	return (protocol->parent_proto_id != -1);
}

gboolean
proto_is_protocol_enabled(const protocol_t *protocol)
{
	if (protocol == NULL)
		return FALSE;

	//parent protocol determines enable/disable for helper dissectors
	if (proto_is_pino(protocol))
		return proto_is_protocol_enabled(find_protocol_by_id(protocol->parent_proto_id));

	return protocol->is_enabled;
}

gboolean
proto_is_protocol_enabled_by_default(const protocol_t *protocol)
{
	//parent protocol determines enable/disable for helper dissectors
	if (proto_is_pino(protocol))
		return proto_is_protocol_enabled_by_default(find_protocol_by_id(protocol->parent_proto_id));

	return protocol->enabled_by_default;
}

gboolean
proto_can_toggle_protocol(const int proto_id)
{
	protocol_t *protocol;

	protocol = find_protocol_by_id(proto_id);
	//parent protocol determines toggling for helper dissectors
	if (proto_is_pino(protocol))
		return proto_can_toggle_protocol(protocol->parent_proto_id);

	return protocol->can_toggle;
}

void
proto_disable_by_default(const int proto_id)
{
	protocol_t *protocol;

	protocol = find_protocol_by_id(proto_id);
	DISSECTOR_ASSERT(protocol->can_toggle);
	DISSECTOR_ASSERT(proto_is_pino(protocol) == FALSE);
	protocol->is_enabled = FALSE;
	protocol->enabled_by_default = FALSE;
}

void
proto_set_decoding(const int proto_id, const gboolean enabled)
{
	protocol_t *protocol;

	protocol = find_protocol_by_id(proto_id);
	DISSECTOR_ASSERT(protocol->can_toggle);
	DISSECTOR_ASSERT(proto_is_pino(protocol) == FALSE);
	protocol->is_enabled = enabled;
}

void
proto_reenable_all(void)
{
	protocol_t *protocol;
	GList      *list_item = protocols;

	if (protocols == NULL)
		return;

	while (list_item) {
		protocol = (protocol_t *)list_item->data;
		if (protocol->can_toggle && protocol->enabled_by_default)
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

	if (proto->fields == NULL) {
		proto->fields = g_ptr_array_sized_new(num_records);
	}

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
			REPORT_DISSECTOR_BUG(
				"Duplicate field detected in call to proto_register_field_array: %s is already registered",
				ptr->hfinfo.abbrev);
			return;
		}

		*ptr->p_id = proto_register_field_common(proto, &ptr->hfinfo, parent);
	}
}

/* deregister already registered fields */
void
proto_deregister_field (const int parent, gint hf_id)
{
	header_field_info *hfi;
	protocol_t       *proto;
	guint             i;

	g_free(last_field_name);
	last_field_name = NULL;

	if (hf_id == -1 || hf_id == 0)
		return;

	proto = find_protocol_by_id (parent);
	if (!proto || proto->fields == NULL) {
		return;
	}

	for (i = 0; i < proto->fields->len; i++) {
		hfi = (header_field_info *)g_ptr_array_index(proto->fields, i);
		if (hfi->id == hf_id) {
			/* Found the hf_id in this protocol */
			g_hash_table_steal(gpa_name_map, hfi->abbrev);
			g_ptr_array_remove_index_fast(proto->fields, i);
			g_ptr_array_add(deregistered_fields, gpa_hfinfo.hfi[hf_id]);
			return;
		}
	}
}

void
proto_add_deregistered_data (void *data)
{
	g_ptr_array_add(deregistered_data, data);
}

void
proto_add_deregistered_slice (gsize block_size, gpointer mem_block)
{
	struct g_slice_data *slice_data = g_slice_new(struct g_slice_data);

	slice_data->block_size = block_size;
	slice_data->mem_block = mem_block;

	g_ptr_array_add(deregistered_slice, slice_data);
}

void proto_free_field_strings (ftenum_t field_type, unsigned int field_display, const void *field_strings)
{
	if (field_strings == NULL) {
		return;
	}

	switch (field_type) {
		case FT_FRAMENUM:
			/* This is just an integer represented as a pointer */
			break;
		case FT_PROTOCOL: {
			protocol_t *protocol = (protocol_t *)field_strings;
			g_free((gchar *)protocol->short_name);
			break;
		}
		case FT_BOOLEAN: {
			true_false_string *tf = (true_false_string *)field_strings;
			g_free((gchar *)tf->true_string);
			g_free((gchar *)tf->false_string);
			break;
		}
		case FT_UINT40:
		case FT_INT40:
		case FT_UINT48:
		case FT_INT48:
		case FT_UINT56:
		case FT_INT56:
		case FT_UINT64:
		case FT_INT64: {
			if (field_display & BASE_UNIT_STRING) {
				unit_name_string *unit = (unit_name_string *)field_strings;
				g_free((gchar *)unit->singular);
				g_free((gchar *)unit->plural);
			} else if (field_display & BASE_RANGE_STRING) {
				range_string *rs = (range_string *)field_strings;
				while (rs->strptr) {
					g_free((gchar *)rs->strptr);
					rs++;
				}
			} else if (field_display & BASE_EXT_STRING) {
				val64_string_ext *vse = (val64_string_ext *)field_strings;
				val64_string *vs = (val64_string *)vse->_vs_p;
				while (vs->strptr) {
					g_free((gchar *)vs->strptr);
					vs++;
				}
				val64_string_ext_free(vse);
				field_strings = NULL;
			} else if (field_display == BASE_CUSTOM) {
				/* this will be a pointer to a function, don't free that */
				field_strings = NULL;
			} else {
				val64_string *vs64 = (val64_string *)field_strings;
				while (vs64->strptr) {
					g_free((gchar *)vs64->strptr);
					vs64++;
				}
			}
			break;
		}
		case FT_CHAR:
		case FT_UINT8:
		case FT_INT8:
		case FT_UINT16:
		case FT_INT16:
		case FT_UINT24:
		case FT_INT24:
		case FT_UINT32:
		case FT_INT32:
		case FT_FLOAT:
		case FT_DOUBLE: {
			if (field_display & BASE_UNIT_STRING) {
				unit_name_string *unit = (unit_name_string *)field_strings;
				g_free((gchar *)unit->singular);
				g_free((gchar *)unit->plural);
			} else if (field_display & BASE_RANGE_STRING) {
				range_string *rs = (range_string *)field_strings;
				while (rs->strptr) {
					g_free((gchar *)rs->strptr);
					rs++;
				}
			} else if (field_display & BASE_EXT_STRING) {
				value_string_ext *vse = (value_string_ext *)field_strings;
				value_string *vs = (value_string *)vse->_vs_p;
				while (vs->strptr) {
					g_free((gchar *)vs->strptr);
					vs++;
				}
				value_string_ext_free(vse);
				field_strings = NULL;
			} else if (field_display == BASE_CUSTOM) {
				/* this will be a pointer to a function, don't free that */
				field_strings = NULL;
			} else {
				value_string *vs = (value_string *)field_strings;
				while (vs->strptr) {
					g_free((gchar *)vs->strptr);
					vs++;
				}
			}
			break;
		default:
			break;
		}
	}

	if (field_type != FT_FRAMENUM) {
		g_free((void *)field_strings);
	}
}

static void
free_deregistered_field (gpointer data, gpointer user_data _U_)
{
	header_field_info *hfi = (header_field_info *) data;
	gint hf_id = hfi->id;

	g_free((char *)hfi->name);
	g_free((char *)hfi->abbrev);
	g_free((char *)hfi->blurb);

	proto_free_field_strings(hfi->type, hfi->display, hfi->strings);

	if (hfi->parent == -1)
		g_slice_free(header_field_info, hfi);

	gpa_hfinfo.hfi[hf_id] = NULL; /* Invalidate this hf_id / proto_id */
}

static void
free_deregistered_data (gpointer data, gpointer user_data _U_)
{
	g_free (data);
}

static void
free_deregistered_slice (gpointer data, gpointer user_data _U_)
{
	struct g_slice_data *slice_data = (struct g_slice_data *)data;

	g_slice_free1(slice_data->block_size, slice_data->mem_block);
	g_slice_free(struct g_slice_data, slice_data);
}

/* free deregistered fields and data */
void
proto_free_deregistered_fields (void)
{
	expert_free_deregistered_expertinfos();

	g_ptr_array_foreach(deregistered_fields, free_deregistered_field, NULL);
	g_ptr_array_free(deregistered_fields, TRUE);
	deregistered_fields = g_ptr_array_new();

	g_ptr_array_foreach(deregistered_data, free_deregistered_data, NULL);
	g_ptr_array_free(deregistered_data, TRUE);
	deregistered_data = g_ptr_array_new();

	g_ptr_array_foreach(deregistered_slice, free_deregistered_slice, NULL);
	g_ptr_array_free(deregistered_slice, TRUE);
	deregistered_slice = g_ptr_array_new();
}

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
	{ ABSOLUTE_TIME_LOCAL,		  "ABSOLUTE_TIME_LOCAL"		   },
	{ ABSOLUTE_TIME_UTC,		  "ABSOLUTE_TIME_UTC"		   },
	{ ABSOLUTE_TIME_DOY_UTC,	  "ABSOLUTE_TIME_DOY_UTC"	   },
	{ BASE_PT_UDP,			  "BASE_PT_UDP"			   },
	{ BASE_PT_TCP,			  "BASE_PT_TCP"			   },
	{ BASE_PT_DCCP,			  "BASE_PT_DCCP"		   },
	{ BASE_PT_SCTP,			  "BASE_PT_SCTP"		   },
	{ BASE_OUI,			  "BASE_OUI"			   },
	{ 0,				  NULL } };

const char* proto_field_display_to_string(int field_display)
{
	return val_to_str_const(field_display, hf_display, "Unknown");
}

static inline port_type
display_to_port_type(field_display_e e)
{
	switch (e) {
	case BASE_PT_UDP:
		return PT_UDP;
	case BASE_PT_TCP:
		return PT_TCP;
	case BASE_PT_DCCP:
		return PT_DCCP;
	case BASE_PT_SCTP:
		return PT_SCTP;
	default:
		break;
	}
	return PT_NONE;
}

/* temporary function containing assert part for easier profiling */
static void
tmp_fld_check_assert(header_field_info *hfinfo)
{
	gchar* tmp_str;

	/* The field must have a name (with length > 0) */
	if (!hfinfo->name || !hfinfo->name[0]) {
		if (hfinfo->abbrev)
			/* Try to identify the field */
			REPORT_DISSECTOR_BUG("Field (abbrev='%s') does not have a name",
				hfinfo->abbrev);
		else
			/* Hum, no luck */
			REPORT_DISSECTOR_BUG("Field does not have a name (nor an abbreviation)");
	}

	/* fields with an empty string for an abbreviation aren't filterable */
	if (!hfinfo->abbrev || !hfinfo->abbrev[0])
		REPORT_DISSECTOR_BUG("Field '%s' does not have an abbreviation", hfinfo->name);

	/*  These types of fields are allowed to have value_strings,
	 *  true_false_strings or a protocol_t struct
	 */
	if (hfinfo->strings != NULL && FIELD_DISPLAY(hfinfo->display) != BASE_CUSTOM) {
		switch (hfinfo->type) {

		/*
		 * These types are allowed to support display value_strings,
		 * value64_strings, the extended versions of the previous
		 * two, range strings, or unit strings.
		 */
		case FT_CHAR:
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
		case FT_UINT40:
		case FT_UINT48:
		case FT_UINT56:
		case FT_UINT64:
		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
		case FT_INT40:
		case FT_INT48:
		case FT_INT56:
		case FT_INT64:
		case FT_BOOLEAN:
		case FT_PROTOCOL:
			break;

		/*
		 * This is allowed to have a value of type
		 * enum ft_framenum_type to indicate what relationship
		 * the frame in question has to the frame in which
		 * the field is put.
		 */
		case FT_FRAMENUM:
			break;

		/*
		 * These types are allowed to support only unit strings.
		 */
		case FT_FLOAT:
		case FT_DOUBLE:
			if (!(hfinfo->display & BASE_UNIT_STRING)) {
				REPORT_DISSECTOR_BUG("Field '%s' (%s) has a non-unit-strings 'strings' value but is of type %s"
					" (which is only allowed to have unit strings)",
					hfinfo->name, hfinfo->abbrev, ftype_name(hfinfo->type));
			}
			break;

		/*
		 * This type is only allowed to support a string if it's
		 * a protocol (for pinos).
		 */
		case FT_BYTES:
			if (!(hfinfo->display & BASE_PROTOCOL_INFO)) {
				REPORT_DISSECTOR_BUG("Field '%s' (%s) has a non-protocol-info 'strings' value but is of type %s"
					" (which is only allowed to have protocol-info strings)",
					hfinfo->name, hfinfo->abbrev, ftype_name(hfinfo->type));
			}
			break;

		default:
			REPORT_DISSECTOR_BUG("Field '%s' (%s) has a 'strings' value but is of type %s"
				" (which is not allowed to have strings)",
				hfinfo->name, hfinfo->abbrev, ftype_name(hfinfo->type));
		}
	}

	/* TODO: This check may slow down startup, and output quite a few warnings.
	   It would be good to be able to enable this (and possibly other checks?)
	   in non-release builds.   */
#ifdef ENABLE_CHECK_FILTER
	/* Check for duplicate value_string values.
	   There are lots that have the same value *and* string, so for now only
	   report those that have same value but different string. */
	if ((hfinfo->strings != NULL) &&
	    !(hfinfo->display & BASE_RANGE_STRING) &&
	    !(hfinfo->display & BASE_UNIT_STRING) &&
	    !((hfinfo->display & FIELD_DISPLAY_E_MASK) == BASE_CUSTOM) &&
	    (
		    (hfinfo->type == FT_CHAR)  ||
		    (hfinfo->type == FT_UINT8)  ||
		    (hfinfo->type == FT_UINT16) ||
		    (hfinfo->type == FT_UINT24) ||
		    (hfinfo->type == FT_UINT32) ||
		    (hfinfo->type == FT_INT8)   ||
		    (hfinfo->type == FT_INT16)  ||
		    (hfinfo->type == FT_INT24)  ||
		    (hfinfo->type == FT_INT32)  )) {

		if (hfinfo->display & BASE_EXT_STRING) {
			if (hfinfo->display & BASE_VAL64_STRING) {
				const val64_string *start_values = VAL64_STRING_EXT_VS_P((const val64_string_ext*)hfinfo->strings);
				CHECK_HF_VALUE(val64_string, PRIu64, start_values);
			} else {
				const value_string *start_values = VALUE_STRING_EXT_VS_P((const value_string_ext*)hfinfo->strings);
				CHECK_HF_VALUE(value_string, "u", start_values);
			}
		} else {
			const value_string *start_values = (const value_string*)hfinfo->strings;
			CHECK_HF_VALUE(value_string, "u", start_values);
		}
	}

	if (hfinfo->type == FT_BOOLEAN) {
		const true_false_string *tfs = (const true_false_string*)hfinfo->strings;
		if (tfs) {
			if (strcmp(tfs->false_string, tfs->true_string) == 0) {
				ws_warning("Field '%s' (%s) has identical true and false strings (\"%s\", \"%s\")",
						   hfinfo->name, hfinfo->abbrev,
						   tfs->false_string, tfs->true_string);
			}
		}
	}

	if (hfinfo->display & BASE_RANGE_STRING) {
		const range_string *rs = (const range_string*)(hfinfo->strings);
		if (rs) {
			const range_string *this_it = rs;

			do {
				if (this_it->value_max < this_it->value_min) {
					ws_warning("value_range_string error:  %s (%s) entry for \"%s\" - max(%"PRIu64" 0x%"PRIx64") is less than min(%"PRIu64" 0x%"PRIx64")",
							  hfinfo->name, hfinfo->abbrev,
							  this_it->strptr,
							  this_it->value_max, this_it->value_max,
							  this_it->value_min, this_it->value_min);
					++this_it;
					continue;
				}

				for (const range_string *prev_it=rs; prev_it < this_it; ++prev_it) {
					/* Not OK if this one is completely hidden by an earlier one! */
					if ((prev_it->value_min <= this_it->value_min) && (prev_it->value_max >= this_it->value_max)) {
						ws_warning("value_range_string error:  %s (%s) hidden by earlier entry "
								  "(prev=\"%s\":  %"PRIu64" 0x%"PRIx64" -> %"PRIu64" 0x%"PRIx64")  (this=\"%s\":  %"PRIu64" 0x%"PRIx64" -> %"PRIu64" 0x%"PRIx64")",
								  hfinfo->name, hfinfo->abbrev,
								  prev_it->strptr, prev_it->value_min, prev_it->value_min,
								  prev_it->value_max, prev_it->value_max,
								  this_it->strptr, this_it->value_min, this_it->value_min,
								  this_it->value_max, this_it->value_max);
					}
				}
				++this_it;
			} while (this_it->strptr);
		}
	}
#endif

	switch (hfinfo->type) {

		case FT_CHAR:
			/*  Require the char type to have BASE_HEX, BASE_OCT,
			 *  BASE_CUSTOM, or BASE_NONE as its base.
			 *
			 *  If the display value is BASE_NONE and there is a
			 *  strings conversion then the dissector writer is
			 *  telling us that the field's numerical value is
			 *  meaningless; we'll avoid showing the value to the
			 *  user.
			 */
			switch (FIELD_DISPLAY(hfinfo->display)) {
				case BASE_HEX:
				case BASE_OCT:
				case BASE_CUSTOM: /* hfinfo_numeric_value_format() treats this as decimal */
					break;
				case BASE_NONE:
					if (hfinfo->strings == NULL)
						REPORT_DISSECTOR_BUG("Field '%s' (%s) is an integral value (%s)"
							" but is being displayed as BASE_NONE but"
							" without a strings conversion",
							hfinfo->name, hfinfo->abbrev,
							ftype_name(hfinfo->type));
					break;
				default:
					tmp_str = val_to_str_wmem(NULL, hfinfo->display, hf_display, "(Unknown: 0x%x)");
					REPORT_DISSECTOR_BUG("Field '%s' (%s) is a character value (%s)"
						" but is being displayed as %s",
						hfinfo->name, hfinfo->abbrev,
						ftype_name(hfinfo->type), tmp_str);
					wmem_free(NULL, tmp_str);
			}
			if (hfinfo->display & BASE_UNIT_STRING) {
				REPORT_DISSECTOR_BUG("Field '%s' (%s) is a character value (%s) but has a unit string",
					hfinfo->name, hfinfo->abbrev,
					ftype_name(hfinfo->type));
			}
			break;
		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
		case FT_INT40:
		case FT_INT48:
		case FT_INT56:
		case FT_INT64:
			/*	Hexadecimal and octal are, in printf() and everywhere
			 *	else, unsigned so don't allow dissectors to register a
			 *	signed field to be displayed unsigned.  (Else how would
			 *	we display negative values?)
			 */
			switch (FIELD_DISPLAY(hfinfo->display)) {
				case BASE_HEX:
				case BASE_OCT:
				case BASE_DEC_HEX:
				case BASE_HEX_DEC:
					tmp_str = val_to_str_wmem(NULL, hfinfo->display, hf_display, "(Bit count: %d)");
					REPORT_DISSECTOR_BUG("Field '%s' (%s) is signed (%s) but is being displayed unsigned (%s)",
						hfinfo->name, hfinfo->abbrev,
						ftype_name(hfinfo->type), tmp_str);
					wmem_free(NULL, tmp_str);
			}
			/* FALL THROUGH */
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
		case FT_UINT40:
		case FT_UINT48:
		case FT_UINT56:
		case FT_UINT64:
			if (IS_BASE_PORT(hfinfo->display)) {
				tmp_str = val_to_str_wmem(NULL, hfinfo->display, hf_display, "(Unknown: 0x%x)");
				if (hfinfo->type != FT_UINT16) {
					REPORT_DISSECTOR_BUG("Field '%s' (%s) has 'display' value %s but it can only be used with FT_UINT16, not %s",
						hfinfo->name, hfinfo->abbrev,
						tmp_str, ftype_name(hfinfo->type));
				}
				if (hfinfo->strings != NULL) {
					REPORT_DISSECTOR_BUG("Field '%s' (%s) is an %s (%s) but has a strings value",
						hfinfo->name, hfinfo->abbrev,
						ftype_name(hfinfo->type), tmp_str);
				}
				if (hfinfo->bitmask != 0) {
					REPORT_DISSECTOR_BUG("Field '%s' (%s) is an %s (%s) but has a bitmask",
						hfinfo->name, hfinfo->abbrev,
						ftype_name(hfinfo->type), tmp_str);
				}
				wmem_free(NULL, tmp_str);
				break;
			}

			if (hfinfo->display == BASE_OUI) {
				tmp_str = val_to_str_wmem(NULL, hfinfo->display, hf_display, "(Unknown: 0x%x)");
				if (hfinfo->type != FT_UINT24) {
					REPORT_DISSECTOR_BUG("Field '%s' (%s) has 'display' value %s but it can only be used with FT_UINT24, not %s",
						hfinfo->name, hfinfo->abbrev,
						tmp_str, ftype_name(hfinfo->type));
				}
				if (hfinfo->strings != NULL) {
					REPORT_DISSECTOR_BUG("Field '%s' (%s) is an %s (%s) but has a strings value",
						hfinfo->name, hfinfo->abbrev,
						ftype_name(hfinfo->type), tmp_str);
				}
				if (hfinfo->bitmask != 0) {
					REPORT_DISSECTOR_BUG("Field '%s' (%s) is an %s (%s) but has a bitmask",
						hfinfo->name, hfinfo->abbrev,
						ftype_name(hfinfo->type), tmp_str);
				}
				wmem_free(NULL, tmp_str);
				break;
			}

			/*  Require integral types (other than frame number,
			 *  which is always displayed in decimal) to have a
			 *  number base.
			 *
			 *  If the display value is BASE_NONE and there is a
			 *  strings conversion then the dissector writer is
			 *  telling us that the field's numerical value is
			 *  meaningless; we'll avoid showing the value to the
			 *  user.
			 */
			switch (FIELD_DISPLAY(hfinfo->display)) {
				case BASE_DEC:
				case BASE_HEX:
				case BASE_OCT:
				case BASE_DEC_HEX:
				case BASE_HEX_DEC:
				case BASE_CUSTOM: /* hfinfo_numeric_value_format() treats this as decimal */
					break;
				case BASE_NONE:
					if (hfinfo->strings == NULL) {
						REPORT_DISSECTOR_BUG("Field '%s' (%s) is an integral value (%s)"
							" but is being displayed as BASE_NONE but"
							" without a strings conversion",
							hfinfo->name, hfinfo->abbrev,
							ftype_name(hfinfo->type));
					}
					if (hfinfo->display & BASE_SPECIAL_VALS) {
						REPORT_DISSECTOR_BUG("Field '%s' (%s) is an integral value (%s)"
							" that is being displayed as BASE_NONE but"
							" with BASE_SPECIAL_VALS",
							hfinfo->name, hfinfo->abbrev,
							ftype_name(hfinfo->type));
					}
					break;

				default:
					tmp_str = val_to_str_wmem(NULL, hfinfo->display, hf_display, "(Unknown: 0x%x)");
					REPORT_DISSECTOR_BUG("Field '%s' (%s) is an integral value (%s)"
						" but is being displayed as %s",
						hfinfo->name, hfinfo->abbrev,
						ftype_name(hfinfo->type), tmp_str);
					wmem_free(NULL, tmp_str);
			}
			break;
		case FT_BYTES:
		case FT_UINT_BYTES:
			/*  Require bytes to have a "display type" that could
			 *  add a character between displayed bytes.
			 */
			switch (FIELD_DISPLAY(hfinfo->display)) {
				case BASE_NONE:
				case SEP_DOT:
				case SEP_DASH:
				case SEP_COLON:
				case SEP_SPACE:
					break;
				default:
					tmp_str = val_to_str_wmem(NULL, hfinfo->display, hf_display, "(Bit count: %d)");
					REPORT_DISSECTOR_BUG("Field '%s' (%s) is an byte array but is being displayed as %s instead of BASE_NONE, SEP_DOT, SEP_DASH, SEP_COLON, or SEP_SPACE",
						hfinfo->name, hfinfo->abbrev, tmp_str);
					wmem_free(NULL, tmp_str);
			}
			if (hfinfo->bitmask != 0)
				REPORT_DISSECTOR_BUG("Field '%s' (%s) is an %s but has a bitmask",
					hfinfo->name, hfinfo->abbrev,
					ftype_name(hfinfo->type));
			//allowed to support string if its a protocol (for pinos)
			if ((hfinfo->strings != NULL) && (!(hfinfo->display & BASE_PROTOCOL_INFO)))
				REPORT_DISSECTOR_BUG("Field '%s' (%s) is an %s but has a strings value",
					hfinfo->name, hfinfo->abbrev,
					ftype_name(hfinfo->type));
			break;

		case FT_PROTOCOL:
		case FT_FRAMENUM:
			if (hfinfo->display != BASE_NONE) {
				tmp_str = val_to_str_wmem(NULL, hfinfo->display, hf_display, "(Bit count: %d)");
				REPORT_DISSECTOR_BUG("Field '%s' (%s) is an %s but is being displayed as %s instead of BASE_NONE",
					hfinfo->name, hfinfo->abbrev,
					ftype_name(hfinfo->type), tmp_str);
				wmem_free(NULL, tmp_str);
			}
			if (hfinfo->bitmask != 0)
				REPORT_DISSECTOR_BUG("Field '%s' (%s) is an %s but has a bitmask",
					hfinfo->name, hfinfo->abbrev,
					ftype_name(hfinfo->type));
			break;

		case FT_BOOLEAN:
			break;

		case FT_ABSOLUTE_TIME:
			if (!(hfinfo->display == ABSOLUTE_TIME_LOCAL ||
			      hfinfo->display == ABSOLUTE_TIME_UTC   ||
			      hfinfo->display == ABSOLUTE_TIME_NTP_UTC   ||
			      hfinfo->display == ABSOLUTE_TIME_DOY_UTC)) {
				tmp_str = val_to_str_wmem(NULL, hfinfo->display, hf_display, "(Bit count: %d)");
				REPORT_DISSECTOR_BUG("Field '%s' (%s) is a %s but is being displayed as %s instead of as a time",
					hfinfo->name, hfinfo->abbrev, ftype_name(hfinfo->type), tmp_str);
				wmem_free(NULL, tmp_str);
			}
			if (hfinfo->bitmask != 0)
				REPORT_DISSECTOR_BUG("Field '%s' (%s) is an %s but has a bitmask",
					hfinfo->name, hfinfo->abbrev,
					ftype_name(hfinfo->type));
			break;

		case FT_STRING:
		case FT_STRINGZ:
		case FT_UINT_STRING:
		case FT_STRINGZPAD:
		case FT_STRINGZTRUNC:
			switch (hfinfo->display) {
				case BASE_NONE:
					break;

				default:
					tmp_str = val_to_str_wmem(NULL, hfinfo->display, hf_display, "(Unknown: 0x%x)");
					REPORT_DISSECTOR_BUG("Field '%s' (%s) is an string value (%s)"
						" but is being displayed as %s",
						hfinfo->name, hfinfo->abbrev,
						ftype_name(hfinfo->type), tmp_str);
					wmem_free(NULL, tmp_str);
			}

			if (hfinfo->bitmask != 0)
				REPORT_DISSECTOR_BUG("Field '%s' (%s) is an %s but has a bitmask",
					hfinfo->name, hfinfo->abbrev,
					ftype_name(hfinfo->type));
			if (hfinfo->strings != NULL)
				REPORT_DISSECTOR_BUG("Field '%s' (%s) is an %s but has a strings value",
					hfinfo->name, hfinfo->abbrev,
					ftype_name(hfinfo->type));
			break;

		case FT_IPv4:
			switch (hfinfo->display) {
				case BASE_NONE:
				case BASE_NETMASK:
					break;

				default:
					tmp_str = val_to_str_wmem(NULL, hfinfo->display, hf_display, "(Unknown: 0x%x)");
					REPORT_DISSECTOR_BUG("Field '%s' (%s) is an IPv4 value (%s)"
						" but is being displayed as %s",
						hfinfo->name, hfinfo->abbrev,
						ftype_name(hfinfo->type), tmp_str);
					wmem_free(NULL, tmp_str);
					break;
			}
			break;
		case FT_FLOAT:
		case FT_DOUBLE:
			switch (FIELD_DISPLAY(hfinfo->display)) {
				case BASE_NONE:
				case BASE_DEC:
				case BASE_HEX:
				case BASE_EXP:
				case BASE_CUSTOM:
					break;
				default:
					tmp_str = val_to_str_wmem(NULL, hfinfo->display, hf_display, "(Unknown: 0x%x)");
					REPORT_DISSECTOR_BUG("Field '%s' (%s) is a float value (%s)"
						" but is being displayed as %s",
						hfinfo->name, hfinfo->abbrev,
						ftype_name(hfinfo->type), tmp_str);
					wmem_free(NULL, tmp_str);
			}
			if (hfinfo->bitmask != 0)
				REPORT_DISSECTOR_BUG("Field '%s' (%s) is an %s but has a bitmask",
					hfinfo->name, hfinfo->abbrev,
					ftype_name(hfinfo->type));
			if (FIELD_DISPLAY(hfinfo->display) != BASE_CUSTOM && (hfinfo->strings != NULL) && !(hfinfo->display & BASE_UNIT_STRING))
				REPORT_DISSECTOR_BUG("Field '%s' (%s) is an %s but has a strings value",
					hfinfo->name, hfinfo->abbrev,
					ftype_name(hfinfo->type));
			break;
		default:
			if (hfinfo->display != BASE_NONE) {
				tmp_str = val_to_str_wmem(NULL, hfinfo->display, hf_display, "(Bit count: %d)");
				REPORT_DISSECTOR_BUG("Field '%s' (%s) is an %s but is being displayed as %s instead of BASE_NONE",
					hfinfo->name, hfinfo->abbrev,
					ftype_name(hfinfo->type),
					tmp_str);
				wmem_free(NULL, tmp_str);
			}
			if (hfinfo->bitmask != 0)
				REPORT_DISSECTOR_BUG("Field '%s' (%s) is an %s but has a bitmask",
					hfinfo->name, hfinfo->abbrev,
					ftype_name(hfinfo->type));
			if (hfinfo->strings != NULL)
				REPORT_DISSECTOR_BUG("Field '%s' (%s) is an %s but has a strings value",
					hfinfo->name, hfinfo->abbrev,
					ftype_name(hfinfo->type));
			break;
	}
}

#ifdef ENABLE_CHECK_FILTER
static enum ftenum
_ftype_common(enum ftenum type)
{
	switch (type) {
		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
			return FT_INT32;

		case FT_CHAR:
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
		case FT_IPXNET:
		case FT_FRAMENUM:
			return FT_UINT32;

		case FT_UINT64:
		case FT_EUI64:
			return FT_UINT64;

		case FT_STRING:
		case FT_STRINGZ:
		case FT_UINT_STRING:
			return FT_STRING;

		case FT_FLOAT:
		case FT_DOUBLE:
			return FT_DOUBLE;

		case FT_BYTES:
		case FT_UINT_BYTES:
		case FT_ETHER:
		case FT_OID:
			return FT_BYTES;

		case FT_ABSOLUTE_TIME:
		case FT_RELATIVE_TIME:
			return FT_ABSOLUTE_TIME;

		default:
			return type;
	}
}
#endif

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
register_number_string_decodinws_error(void)
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

static void
register_string_errors(void)
{
	static ei_register_info ei[] = {
		{ &ei_string_trailing_characters,
			{ "_ws.string.trailing_stray_characters", PI_UNDECODED, PI_WARN, "Trailing stray characters", EXPFILL }
		},
	};

	expert_module_t* expert_string_errors;

	proto_string_errors = proto_register_protocol("String Errors", "String errors", "_ws.string");

	expert_string_errors = expert_register_protocol(proto_string_errors);
	expert_register_field_array(expert_string_errors, ei, array_length(ei));

	/* "String Errors" isn't really a protocol, it's an error indication;
	   disabling them makes no sense. */
	proto_set_cant_toggle(proto_string_errors);
}

#define PROTO_PRE_ALLOC_HF_FIELDS_MEM (270000+PRE_ALLOC_EXPERT_FIELDS_MEM)
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
			/*ws_warning("gpa_hfinfo.allocated_len %u", gpa_hfinfo.allocated_len);*/
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
		c = proto_check_field_name(hfinfo->abbrev);
		if (c) {
			if (c == '.') {
				REPORT_DISSECTOR_BUG("Invalid leading, duplicated or trailing '.' found in filter name '%s'", hfinfo->abbrev);
			} else if (g_ascii_isprint(c)) {
				REPORT_DISSECTOR_BUG("Invalid character '%c' in filter name '%s'", c, hfinfo->abbrev);
			} else {
				REPORT_DISSECTOR_BUG("Invalid byte \\%03o in filter name '%s'", c, hfinfo->abbrev);
			}
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
			 * Put the current field *before* that field
			 * in the list of fields with this name, Thus,
			 * we end up with an effectively
			 * doubly-linked-list of same-named hfinfo's,
			 * with the head of the list (stored in the
			 * hash) being the last seen hfinfo.
			 */
			same_name_next_hfinfo =
				same_name_hfinfo->same_name_next;

			hfinfo->same_name_next = same_name_next_hfinfo;
			if (same_name_next_hfinfo)
				same_name_next_hfinfo->same_name_prev_id = hfinfo->id;

			same_name_hfinfo->same_name_next = hfinfo;
			hfinfo->same_name_prev_id = same_name_hfinfo->id;
#ifdef ENABLE_CHECK_FILTER
			while (same_name_hfinfo) {
				if (_ftype_common(hfinfo->type) != _ftype_common(same_name_hfinfo->type))
					ws_warning("'%s' exists multiple times with incompatible types: %s and %s", hfinfo->abbrev, ftype_name(hfinfo->type), ftype_name(same_name_hfinfo->type));
				same_name_hfinfo = same_name_hfinfo->same_name_next;
			}
#endif
		}
	}

	return hfinfo->id;
}

void
proto_register_subtree_array(gint * const *indices, const int num_indices)
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
			tree_is_expanded[i >> 5] &= ~(1U << (i & 31));
	}

	/*
	 * Assign "num_indices" subtree numbers starting at "num_tree_types",
	 * returning the indices through the pointers in the array whose
	 * first element is pointed to by "indices", and update
	 * "num_tree_types" appropriately.
	 */
	for (i = 0; i < num_indices; i++, ptr++, num_tree_types++) {
		if (**ptr != -1) {
			REPORT_DISSECTOR_BUG("register_subtree_array: subtree item type (ett_...) not -1 !"
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
		last_char = g_utf8_prev_char(&label_str[ITEM_LABEL_LENGTH - 1]);
		*last_char = '\0';

	} else if (name_pos < ITEM_LABEL_LENGTH)
		(void) g_strlcpy(label_str + name_pos, trunc_str, ITEM_LABEL_LENGTH - name_pos);
}

static gsize
label_fill(char *label_str, gsize pos, const header_field_info *hfinfo, const char *text)
{
	gsize name_pos;

	/* "%s: %s", hfinfo->name, text */
	name_pos = pos = label_concat(label_str, pos, hfinfo->name);
	if (!(hfinfo->display & BASE_NO_DISPLAY_VALUE)) {
		pos = label_concat(label_str, pos, ": ");
		pos = label_concat(label_str, pos, text ? text : "(null)");
	}

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
	if (!(hfinfo->display & BASE_NO_DISPLAY_VALUE)) {
		pos = label_concat(label_str, pos, ": ");
		if (hfinfo->display & BASE_UNIT_STRING) {
			pos = label_concat(label_str, pos, descr ? descr : "(null)");
			pos = label_concat(label_str, pos, text ? text : "(null)");
		} else {
			pos = label_concat(label_str, pos, text ? text : "(null)");
			pos = label_concat(label_str, pos, " (");
			pos = label_concat(label_str, pos, descr ? descr : "(null)");
			pos = label_concat(label_str, pos, ")");
		}
	}

	if (pos >= ITEM_LABEL_LENGTH) {
		/* Uh oh, we don't have enough room. Tell the user that the field is truncated. */
		label_mark_truncated(label_str, name_pos);
	}

	return pos;
}

void
proto_item_fill_label(field_info *fi, gchar *label_str)
{
	header_field_info  *hfinfo;
	const char	   *str;
	const guint8	   *bytes;
	guint32		    integer;
	guint64		    integer64;
	ws_in4_addr         ipv4;
	const e_guid_t	   *guid;
	gchar		   *name;
	address		    addr;
	char		   *addr_str;
	char		   *tmp;

	if (!label_str) {
		ws_warning("NULL label_str passed to proto_item_fill_label.");
		return;
	}

	label_str[0]= '\0';

	if (!fi) {
		return;
	}

	hfinfo = fi->hfinfo;

	switch (hfinfo->type) {
		case FT_NONE:
		case FT_PROTOCOL:
			(void) g_strlcpy(label_str, hfinfo->name, ITEM_LABEL_LENGTH);
			break;

		case FT_BOOLEAN:
			fill_label_boolean(fi, label_str);
			break;

		case FT_BYTES:
		case FT_UINT_BYTES:
			tmp = hfinfo_format_bytes(NULL, hfinfo,
			    fvalue_get_bytes(&fi->value),
			    fvalue_length(&fi->value));
			label_fill(label_str, 0, hfinfo, tmp);
			wmem_free(NULL, tmp);
			break;

		case FT_CHAR:
			if (hfinfo->bitmask) {
				fill_label_bitfield_char(fi, label_str);
			} else {
				fill_label_char(fi, label_str);
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
				fill_label_bitfield(fi, label_str, FALSE);
			} else {
				fill_label_number(fi, label_str, FALSE);
			}
			break;

		case FT_FRAMENUM:
			fill_label_number(fi, label_str, FALSE);
			break;

		case FT_UINT40:
		case FT_UINT48:
		case FT_UINT56:
		case FT_UINT64:
			if (hfinfo->bitmask) {
				fill_label_bitfield64(fi, label_str, FALSE);
			} else {
				fill_label_number64(fi, label_str, FALSE);
			}
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

		case FT_INT40:
		case FT_INT48:
		case FT_INT56:
		case FT_INT64:
			if (hfinfo->bitmask) {
				fill_label_bitfield64(fi, label_str, TRUE);
			} else {
				fill_label_number64(fi, label_str, TRUE);
			}
			break;

		case FT_FLOAT:
		case FT_DOUBLE:
			fill_label_float(fi, label_str);
			break;

		case FT_ABSOLUTE_TIME:
			tmp = abs_time_to_str(NULL, fvalue_get_time(&fi->value), hfinfo->display, TRUE);
			label_fill(label_str, 0, hfinfo, tmp);
			wmem_free(NULL, tmp);
			break;

		case FT_RELATIVE_TIME:
			tmp = rel_time_to_secs_str(NULL, fvalue_get_time(&fi->value));
			snprintf(label_str, ITEM_LABEL_LENGTH,
				   "%s: %s seconds", hfinfo->name, tmp);
			wmem_free(NULL, tmp);
			break;

		case FT_IPXNET:
			integer = fvalue_get_uinteger(&fi->value);
			tmp = get_ipxnet_name(NULL, integer);
			snprintf(label_str, ITEM_LABEL_LENGTH,
				   "%s: %s (0x%08X)", hfinfo->name,
				   tmp, integer);
			wmem_free(NULL, tmp);
			break;

		case FT_AX25:
			addr.type = AT_AX25;
			addr.len  = AX25_ADDR_LEN;
			addr.data = fvalue_get_bytes(&fi->value);

			addr_str = (char*)address_to_str(NULL, &addr);
			snprintf(label_str, ITEM_LABEL_LENGTH,
				   "%s: %s", hfinfo->name, addr_str);
			wmem_free(NULL, addr_str);
			break;

		case FT_VINES:
			addr.type = AT_VINES;
			addr.len  = VINES_ADDR_LEN;
			addr.data = fvalue_get_bytes(&fi->value);

			addr_str = (char*)address_to_str(NULL, &addr);
			snprintf(label_str, ITEM_LABEL_LENGTH,
				   "%s: %s", hfinfo->name, addr_str);
			wmem_free(NULL, addr_str);
			break;

		case FT_ETHER:
			bytes = fvalue_get_bytes(&fi->value);

			addr.type = AT_ETHER;
			addr.len  = 6;
			addr.data = bytes;

			addr_str = (char*)address_with_resolution_to_str(NULL, &addr);
			snprintf(label_str, ITEM_LABEL_LENGTH,
				   "%s: %s", hfinfo->name, addr_str);
			wmem_free(NULL, addr_str);
			break;

		case FT_IPv4:
			ipv4 = fvalue_get_uinteger(&fi->value);

			addr.type = AT_IPv4;
			addr.len  = 4;
			addr.data = &ipv4;

			if (hfinfo->display == BASE_NETMASK) {
				addr_str = (char*)address_to_str(NULL, &addr);
			} else {
				addr_str = (char*)address_with_resolution_to_str(NULL, &addr);
			}
			snprintf(label_str, ITEM_LABEL_LENGTH,
				   "%s: %s", hfinfo->name, addr_str);
			wmem_free(NULL, addr_str);
			break;

		case FT_IPv6:
			bytes = fvalue_get_bytes(&fi->value);

			addr.type = AT_IPv6;
			addr.len  = 16;
			addr.data = bytes;

			addr_str = (char*)address_with_resolution_to_str(NULL, &addr);
			snprintf(label_str, ITEM_LABEL_LENGTH,
				   "%s: %s", hfinfo->name, addr_str);
			wmem_free(NULL, addr_str);
			break;

		case FT_FCWWN:
			addr.type = AT_FCWWN;
			addr.len  = FCWWN_ADDR_LEN;
			addr.data = fvalue_get_bytes(&fi->value);

			addr_str = (char*)address_with_resolution_to_str(NULL, &addr);
			snprintf(label_str, ITEM_LABEL_LENGTH,
				   "%s: %s", hfinfo->name, addr_str);
			wmem_free(NULL, addr_str);
			break;

		case FT_GUID:
			guid = fvalue_get_guid(&fi->value);
			tmp = guid_to_str(NULL, guid);
			label_fill(label_str, 0, hfinfo, tmp);
			wmem_free(NULL, tmp);
			break;

		case FT_OID:
			bytes = fvalue_get_bytes(&fi->value);
			name = oid_resolved_from_encoded(NULL, bytes, fvalue_length(&fi->value));
			tmp = oid_encoded2string(NULL, bytes, fvalue_length(&fi->value));
			if (name) {
				label_fill_descr(label_str, 0, hfinfo, tmp, name);
				wmem_free(NULL, name);
			} else {
				label_fill(label_str, 0, hfinfo, tmp);
			}
			wmem_free(NULL, tmp);
			break;

		case FT_REL_OID:
			bytes = fvalue_get_bytes(&fi->value);
			name = rel_oid_resolved_from_encoded(NULL, bytes, fvalue_length(&fi->value));
			tmp = rel_oid_encoded2string(NULL, bytes, fvalue_length(&fi->value));
			if (name) {
				label_fill_descr(label_str, 0, hfinfo, tmp, name);
				wmem_free(NULL, name);
			} else {
				label_fill(label_str, 0, hfinfo, tmp);
			}
			wmem_free(NULL, tmp);
			break;

		case FT_SYSTEM_ID:
			bytes = fvalue_get_bytes(&fi->value);
			tmp = print_system_id(NULL, bytes, fvalue_length(&fi->value));
			label_fill(label_str, 0, hfinfo, tmp);
			wmem_free(NULL, tmp);
			break;

		case FT_EUI64:
			integer64 = fvalue_get_uinteger64(&fi->value);
			addr_str = eui64_to_str(NULL, integer64);
			tmp = (char*)eui64_to_display(NULL, integer64);
			label_fill_descr(label_str, 0, hfinfo, tmp, addr_str);
			wmem_free(NULL, tmp);
			wmem_free(NULL, addr_str);
			break;
		case FT_STRING:
		case FT_STRINGZ:
		case FT_UINT_STRING:
		case FT_STRINGZPAD:
		case FT_STRINGZTRUNC:
			str = fvalue_get_string(&fi->value);
			tmp = hfinfo_format_text(NULL, hfinfo, str);
			label_fill(label_str, 0, hfinfo, tmp);
			wmem_free(NULL, tmp);
			break;

		case FT_IEEE_11073_SFLOAT:
		case FT_IEEE_11073_FLOAT:
			tmp = fvalue_to_string_repr(NULL, &fi->value, FTREPR_DISPLAY, hfinfo->display);
			snprintf(label_str, ITEM_LABEL_LENGTH,
						"%s: %s",
						hfinfo->name, tmp);
			wmem_free(NULL, tmp);
			break;

		default:
			REPORT_DISSECTOR_BUG("field %s has type %d (%s) not handled in proto_item_fill_label()",
					     hfinfo->abbrev,
					     hfinfo->type,
					     ftype_name(hfinfo->type));
			break;
	}
}

static void
fill_label_boolean(field_info *fi, gchar *label_str)
{
	char	*p                    = label_str;
	int      bitfield_byte_length = 0, bitwidth;
	guint64  unshifted_value;
	guint64  value;

	header_field_info	*hfinfo   = fi->hfinfo;
	const true_false_string	*tfstring = &tfs_true_false;

	if (hfinfo->strings) {
		tfstring = (const struct true_false_string*) hfinfo->strings;
	}

	value = fvalue_get_uinteger64(&fi->value);
	if (hfinfo->bitmask) {
		/* Figure out the bit width */
		bitwidth = hfinfo_container_bitwidth(hfinfo);

		/* Un-shift bits */
		unshifted_value = value;
		unshifted_value <<= hfinfo_bitshift(hfinfo);

		/* Create the bitfield first */
		p = decode_bitfield_value(label_str, unshifted_value, hfinfo->bitmask, bitwidth);
		bitfield_byte_length = (int) (p - label_str);
	}

	/* Fill in the textual info */
	label_fill(label_str, bitfield_byte_length, hfinfo, tfs_get_string(!!value, tfstring));
}

static const char *
hf_try_val_to_str(guint32 value, const header_field_info *hfinfo)
{
	if (hfinfo->display & BASE_RANGE_STRING)
		return try_rval_to_str(value, (const range_string *) hfinfo->strings);

	if (hfinfo->display & BASE_EXT_STRING) {
		if (hfinfo->display & BASE_VAL64_STRING)
			return try_val64_to_str_ext(value, (val64_string_ext *) hfinfo->strings);
		else
			return try_val_to_str_ext(value, (value_string_ext *) hfinfo->strings);
	}

	if (hfinfo->display & BASE_VAL64_STRING)
		return try_val64_to_str(value, (const val64_string *) hfinfo->strings);

	if (hfinfo->display & BASE_UNIT_STRING)
		return unit_name_string_get_value(value, (const struct unit_name_string*) hfinfo->strings);

	return try_val_to_str(value, (const value_string *) hfinfo->strings);
}

static const char *
hf_try_val64_to_str(guint64 value, const header_field_info *hfinfo)
{
	if (hfinfo->display & BASE_VAL64_STRING) {
		if (hfinfo->display & BASE_EXT_STRING)
			return try_val64_to_str_ext(value, (val64_string_ext *) hfinfo->strings);
		else
			return try_val64_to_str(value, (const val64_string *) hfinfo->strings);
	}

	if (hfinfo->display & BASE_RANGE_STRING)
		return try_rval64_to_str(value, (const range_string *) hfinfo->strings);

	if (hfinfo->display & BASE_UNIT_STRING)
		return unit_name_string_get_value64(value, (const struct unit_name_string*) hfinfo->strings);

	/* If this is reached somebody registered a 64-bit field with a 32-bit
	 * value-string, which isn't right. */
	REPORT_DISSECTOR_BUG("field %s is a 64-bit field with a 32-bit value_string",
	    hfinfo->abbrev);

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

/* Fills data for bitfield chars with val_strings */
static void
fill_label_bitfield_char(field_info *fi, gchar *label_str)
{
	char       *p;
	int         bitfield_byte_length, bitwidth;
	guint32     unshifted_value;
	guint32     value;

	char        buf[32];
	const char *out;

	header_field_info *hfinfo = fi->hfinfo;

	/* Figure out the bit width */
	bitwidth = hfinfo_container_bitwidth(hfinfo);

	/* Un-shift bits */
	value = fvalue_get_uinteger(&fi->value);

	unshifted_value = value;
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

		out = hfinfo_char_vals_format(hfinfo, buf, value);
		if (out == NULL) /* BASE_NONE so don't put integer in descr */
			label_fill(label_str, bitfield_byte_length, hfinfo, val_str);
		else
			label_fill_descr(label_str, bitfield_byte_length, hfinfo, val_str, out);
	}
	else {
		out = hfinfo_char_value_format(hfinfo, buf, value);

		label_fill(label_str, bitfield_byte_length, hfinfo, out);
	}
}

/* Fills data for bitfield ints with val_strings */
static void
fill_label_bitfield(field_info *fi, gchar *label_str, gboolean is_signed)
{
	char       *p;
	int         bitfield_byte_length, bitwidth;
	guint32     value, unshifted_value;
	char        buf[32];
	const char *out;

	header_field_info *hfinfo = fi->hfinfo;

	/* Figure out the bit width */
	if (fi->flags & FI_VARINT)
		bitwidth = fi->length*8;
	else
		bitwidth = hfinfo_container_bitwidth(hfinfo);

	/* Un-shift bits */
	if (is_signed)
		value = fvalue_get_sinteger(&fi->value);
	else
		value = fvalue_get_uinteger(&fi->value);

	unshifted_value = value;
	if (hfinfo->bitmask) {
		unshifted_value <<= hfinfo_bitshift(hfinfo);
	}

	/* Create the bitfield first */
	if (fi->flags & FI_VARINT)
		p = decode_bitfield_varint_value(label_str, unshifted_value, hfinfo->bitmask, bitwidth);
	else
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
		const char *val_str = hf_try_val_to_str(value, hfinfo);

		out = hfinfo_number_vals_format(hfinfo, buf, value);
		if (hfinfo->display & BASE_SPECIAL_VALS) {
			/*
			 * Unique values only display value_string string
			 * if there is a match. Otherwise it's just a number
			 */
			if (val_str) {
				label_fill_descr(label_str, bitfield_byte_length, hfinfo, val_str, out);
			} else {
				label_fill(label_str, bitfield_byte_length, hfinfo, out);
			}
		} else {
			if (val_str == NULL)
				val_str = "Unknown";

			if (out == NULL) /* BASE_NONE so don't put integer in descr */
				label_fill(label_str, bitfield_byte_length, hfinfo, val_str);
			else
				label_fill_descr(label_str, bitfield_byte_length, hfinfo, val_str, out);
		}
	}
	else {
		out = hfinfo_number_value_format(hfinfo, buf, value);

		label_fill(label_str, bitfield_byte_length, hfinfo, out);
	}
}

static void
fill_label_bitfield64(field_info *fi, gchar *label_str, gboolean is_signed)
{
	char       *p;
	int         bitfield_byte_length, bitwidth;
	guint64     value, unshifted_value;
	char        buf[48];
	const char *out;

	header_field_info *hfinfo = fi->hfinfo;

	/* Figure out the bit width */
	if (fi->flags & FI_VARINT)
		bitwidth = fi->length*8;
	else
		bitwidth = hfinfo_container_bitwidth(hfinfo);

	/* Un-shift bits */
	if (is_signed)
		value = fvalue_get_sinteger64(&fi->value);
	else
		value = fvalue_get_uinteger64(&fi->value);

	unshifted_value = value;
	if (hfinfo->bitmask) {
		unshifted_value <<= hfinfo_bitshift(hfinfo);
	}

	/* Create the bitfield first */
	if (fi->flags & FI_VARINT)
		p = decode_bitfield_varint_value(label_str, unshifted_value, hfinfo->bitmask, bitwidth);
	else
		p = decode_bitfield_value(label_str, unshifted_value, hfinfo->bitmask, bitwidth);
	bitfield_byte_length = (int) (p - label_str);

	/* Fill in the textual info using stored (shifted) value */
	if (hfinfo->display == BASE_CUSTOM) {
		gchar tmp[ITEM_LABEL_LENGTH];
		const custom_fmt_func_64_t fmtfunc64 = (const custom_fmt_func_64_t)hfinfo->strings;

		DISSECTOR_ASSERT(fmtfunc64);
		fmtfunc64(tmp, value);
		label_fill(label_str, bitfield_byte_length, hfinfo, tmp);
	}
	else if (hfinfo->strings) {
		const char *val_str = hf_try_val64_to_str(value, hfinfo);

		out = hfinfo_number_vals_format64(hfinfo, buf, value);
		if (hfinfo->display & BASE_SPECIAL_VALS) {
			/*
			 * Unique values only display value_string string
			 * if there is a match. Otherwise it's just a number
			 */
			if (val_str) {
				label_fill_descr(label_str, bitfield_byte_length, hfinfo, val_str, out);
			} else {
				label_fill(label_str, bitfield_byte_length, hfinfo, out);
			}
		} else {
			if (val_str == NULL)
				val_str = "Unknown";

			if (out == NULL) /* BASE_NONE so don't put integer in descr */
				label_fill(label_str, bitfield_byte_length, hfinfo, val_str);
			else
				label_fill_descr(label_str, bitfield_byte_length, hfinfo, val_str, out);
		}
	}
	else {
		out = hfinfo_number_value_format64(hfinfo, buf, value);

		label_fill(label_str, bitfield_byte_length, hfinfo, out);
	}
}

static void
fill_label_char(field_info *fi, gchar *label_str)
{
	header_field_info *hfinfo = fi->hfinfo;
	guint32            value;

	char               buf[32];
	const char        *out;

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

		out = hfinfo_char_vals_format(hfinfo, buf, value);
		label_fill_descr(label_str, 0, hfinfo, val_str, out);
	}
	else {
		out = hfinfo_char_value_format(hfinfo, buf, value);

		label_fill(label_str, 0, hfinfo, out);
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
	else if (hfinfo->strings && hfinfo->type != FT_FRAMENUM) {
		/*
		 * It makes no sense to have a value-string table for a
		 * frame-number field - they're just integers giving
		 * the ordinal frame number.
		 */
		const char *val_str = hf_try_val_to_str(value, hfinfo);

		out = hfinfo_number_vals_format(hfinfo, buf, value);
		if (hfinfo->display & BASE_SPECIAL_VALS) {
			/*
			 * Unique values only display value_string string
			 * if there is a match. Otherwise it's just a number
			 */
			if (val_str) {
				label_fill_descr(label_str, 0, hfinfo, val_str, out);
			} else {
				label_fill(label_str, 0, hfinfo, out);
			}
		} else {
			if (val_str == NULL)
				val_str = "Unknown";

			if (out == NULL) /* BASE_NONE so don't put integer in descr */
				label_fill(label_str, 0, hfinfo, val_str);
			else
				label_fill_descr(label_str, 0, hfinfo, val_str, out);
		}
	}
	else if (IS_BASE_PORT(hfinfo->display)) {
		gchar tmp[ITEM_LABEL_LENGTH];

		port_with_resolution_to_str_buf(tmp, sizeof(tmp),
			display_to_port_type((field_display_e)hfinfo->display), value);
		label_fill(label_str, 0, hfinfo, tmp);
	}
	else {
		out = hfinfo_number_value_format(hfinfo, buf, value);

		label_fill(label_str, 0, hfinfo, out);
	}
}

static void
fill_label_number64(field_info *fi, gchar *label_str, gboolean is_signed)
{
	header_field_info *hfinfo = fi->hfinfo;
	guint64            value;

	char               buf[48];
	const char        *out;

	if (is_signed)
		value = fvalue_get_sinteger64(&fi->value);
	else
		value = fvalue_get_uinteger64(&fi->value);

	/* Fill in the textual info */
	if (hfinfo->display == BASE_CUSTOM) {
		gchar tmp[ITEM_LABEL_LENGTH];
		const custom_fmt_func_64_t fmtfunc64 = (const custom_fmt_func_64_t)hfinfo->strings;

		DISSECTOR_ASSERT(fmtfunc64);
		fmtfunc64(tmp, value);
		label_fill(label_str, 0, hfinfo, tmp);
	}
	else if (hfinfo->strings) {
		const char *val_str = hf_try_val64_to_str(value, hfinfo);

		out = hfinfo_number_vals_format64(hfinfo, buf, value);
		if (hfinfo->display & BASE_SPECIAL_VALS) {
			/*
			 * Unique values only display value_string string
			 * if there is a match. Otherwise it's just a number
			 */
			if (val_str) {
				label_fill_descr(label_str, 0, hfinfo, val_str, out);
			} else {
				label_fill(label_str, 0, hfinfo, out);
			}
		} else {
			if (val_str == NULL)
				val_str = "Unknown";

			if (out == NULL) /* BASE_NONE so don't put integer in descr */
				label_fill(label_str, 0, hfinfo, val_str);
			else
				label_fill_descr(label_str, 0, hfinfo, val_str, out);
		}
	}
	else {
		out = hfinfo_number_value_format64(hfinfo, buf, value);

		label_fill(label_str, 0, hfinfo, out);
	}
}

static size_t
fill_display_label_float(field_info *fi, gchar *label_str)
{
	int display;
	int digits;
	int n;
	double value;

	display = FIELD_DISPLAY(fi->hfinfo->display);
	value = fvalue_get_floating(&fi->value);

	if (display == BASE_CUSTOM) {
		const custom_fmt_func_double_t fmtfunc = (const custom_fmt_func_double_t)fi->hfinfo->strings;
		DISSECTOR_ASSERT(fmtfunc);
		fmtfunc(label_str, value);
		return strlen(label_str);
	}

	switch (display) {
		case BASE_NONE:
			if (fi->hfinfo->type == FT_FLOAT)
				digits = FLT_DIG;
			else
				digits = DBL_DIG;

			n = snprintf(label_str, ITEM_LABEL_LENGTH, "%.*g", digits, value);
			break;
		case BASE_DEC:
			n = snprintf(label_str, ITEM_LABEL_LENGTH, "%f", value);
			break;
		case BASE_HEX:
			n = snprintf(label_str, ITEM_LABEL_LENGTH, "%a", value);
			break;
		case BASE_EXP:
			n = snprintf(label_str, ITEM_LABEL_LENGTH, "%e", value);
			break;
		default:
			ws_assert_not_reached();
	}
	if (n < 0) {
		return 0; /* error */
	}
	if (n > ITEM_LABEL_LENGTH) {
		ws_warning("label length too small");
		return strlen(label_str);
	}

	return n;
}

void
fill_label_float(field_info *fi, gchar *label_str)
{
	gchar tmp[ITEM_LABEL_LENGTH];

	fill_display_label_float(fi, tmp);
	label_fill(label_str, 0, fi->hfinfo, tmp);
}

int
hfinfo_bitshift(const header_field_info *hfinfo)
{
	return ws_ctz(hfinfo->bitmask);
}


static int
hfinfo_bitoffset(const header_field_info *hfinfo)
{
	if (!hfinfo->bitmask) {
		return 0;
	}

	/* ilog2 = first set bit, counting 0 as the last bit; we want 0
	 * as the first bit */
	return hfinfo_container_bitwidth(hfinfo) - 1 - ws_ilog2(hfinfo->bitmask);
}

static int
hfinfo_mask_bitwidth(const header_field_info *hfinfo)
{
	if (!hfinfo->bitmask) {
		return 0;
	}

	/* ilog2 = first set bit, ctz = last set bit */
	return ws_ilog2(hfinfo->bitmask) - ws_ctz(hfinfo->bitmask) + 1;
}

static int
hfinfo_type_bitwidth(enum ftenum type)
{
	int bitwidth = 0;

	switch (type) {
		case FT_CHAR:
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
		case FT_UINT40:
		case FT_INT40:
			bitwidth = 40;
			break;
		case FT_UINT48:
		case FT_INT48:
			bitwidth = 48;
			break;
		case FT_UINT56:
		case FT_INT56:
			bitwidth = 56;
			break;
		case FT_UINT64:
		case FT_INT64:
			bitwidth = 64;
			break;
		default:
			DISSECTOR_ASSERT_NOT_REACHED();
			;
	}
	return bitwidth;
}


static int
hfinfo_container_bitwidth(const header_field_info *hfinfo)
{
	if (!hfinfo->bitmask) {
		return 0;
	}

	if (hfinfo->type == FT_BOOLEAN) {
		return hfinfo->display; /* hacky? :) */
	}

	return hfinfo_type_bitwidth(hfinfo->type);
}

static int
hfinfo_hex_digits(const header_field_info *hfinfo)
{
	int bitwidth;

	/* If we have a bitmask, hfinfo->type is the width of the container, so not
	 * appropriate to determine the number of hex digits for the field.
	 * So instead, we compute it from the bitmask.
	 */
	if (hfinfo->bitmask != 0) {
		bitwidth = hfinfo_mask_bitwidth(hfinfo);
	} else {
		bitwidth = hfinfo_type_bitwidth(hfinfo->type);
	}

	/* Divide by 4, rounding up, to get number of hex digits. */
	return (bitwidth + 3) / 4;
}

static const char *
hfinfo_char_value_format_display(int display, char buf[7], guint32 value)
{
	char *ptr = &buf[6];
	static const gchar hex_digits[16] =
	{ '0', '1', '2', '3', '4', '5', '6', '7',
	  '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

	*ptr = '\0';
	*(--ptr) = '\'';
	/* Properly format value */
	if (g_ascii_isprint(value)) {
		/*
		 * Printable, so just show the character, and, if it needs
		 * to be escaped, escape it.
		 */
		*(--ptr) = value;
		if (value == '\\' || value == '\'')
			*(--ptr) = '\\';
	} else {
		/*
		 * Non-printable; show it as an escape sequence.
		 */
		switch (value) {

		case '\0':
			/*
			 * Show a NUL with only one digit.
			 */
			*(--ptr) = '0';
			break;

		case '\a':
			*(--ptr) = 'a';
			break;

		case '\b':
			*(--ptr) = 'b';
			break;

		case '\f':
			*(--ptr) = 'f';
			break;

		case '\n':
			*(--ptr) = 'n';
			break;

		case '\r':
			*(--ptr) = 'r';
			break;

		case '\t':
			*(--ptr) = 't';
			break;

		case '\v':
			*(--ptr) = 'v';
			break;

		default:
			switch (FIELD_DISPLAY(display)) {

			case BASE_OCT:
				*(--ptr) = (value & 0x7) + '0';
				value >>= 3;
				*(--ptr) = (value & 0x7) + '0';
				value >>= 3;
				*(--ptr) = (value & 0x7) + '0';
				break;

			case BASE_HEX:
				*(--ptr) = hex_digits[value & 0x0F];
				value >>= 4;
				*(--ptr) = hex_digits[value & 0x0F];
				*(--ptr) = 'x';
				break;

			default:
				REPORT_DISSECTOR_BUG("Invalid base: %d", FIELD_DISPLAY(display));
			}
		}
		*(--ptr) = '\\';
	}
	*(--ptr) = '\'';
	return ptr;
}

static const char *
hfinfo_number_value_format_display(const header_field_info *hfinfo, int display, char buf[32], guint32 value)
{
	char *ptr = &buf[31];
	gboolean isint = IS_FT_INT(hfinfo->type);

	*ptr = '\0';
	/* Properly format value */
	switch (FIELD_DISPLAY(display)) {
		case BASE_DEC:
			return isint ? int_to_str_back(ptr, (gint32) value) : uint_to_str_back(ptr, value);

		case BASE_DEC_HEX:
			*(--ptr) = ')';
			ptr = hex_to_str_back_len(ptr, value, hfinfo_hex_digits(hfinfo));
			*(--ptr) = '(';
			*(--ptr) = ' ';
			ptr = isint ? int_to_str_back(ptr, (gint32) value) : uint_to_str_back(ptr, value);
			return ptr;

		case BASE_OCT:
			return oct_to_str_back(ptr, value);

		case BASE_HEX:
			return hex_to_str_back_len(ptr, value, hfinfo_hex_digits(hfinfo));

		case BASE_HEX_DEC:
			*(--ptr) = ')';
			ptr = isint ? int_to_str_back(ptr, (gint32) value) : uint_to_str_back(ptr, value);
			*(--ptr) = '(';
			*(--ptr) = ' ';
			ptr = hex_to_str_back_len(ptr, value, hfinfo_hex_digits(hfinfo));
			return ptr;

		case BASE_PT_UDP:
		case BASE_PT_TCP:
		case BASE_PT_DCCP:
		case BASE_PT_SCTP:
			port_with_resolution_to_str_buf(buf, 32,
					display_to_port_type((field_display_e)display), value);
			return buf;
		case BASE_OUI:
			{
			guint8 p_oui[3];
			const gchar *manuf_name;

			p_oui[0] = value >> 16 & 0xFF;
			p_oui[1] = value >> 8 & 0xFF;
			p_oui[2] = value & 0xFF;

			/* Attempt an OUI lookup. */
			manuf_name = uint_get_manuf_name_if_known(value);
			if (manuf_name == NULL) {
				/* Could not find an OUI. */
				snprintf(buf, 32, "%02x:%02x:%02x", p_oui[0], p_oui[1], p_oui[2]);
			}
			else {
				/* Found an address string. */
				snprintf(buf, 32, "%02x:%02x:%02x (%s)", p_oui[0], p_oui[1], p_oui[2], manuf_name);
			}
			return buf;
			}

		default:
			REPORT_DISSECTOR_BUG("Invalid base: %d", FIELD_DISPLAY(display));
	}
	return ptr;
}

static const char *
hfinfo_number_value_format_display64(const header_field_info *hfinfo, int display, char buf[48], guint64 value)
{
	char *ptr = &buf[47];
	gboolean isint = IS_FT_INT(hfinfo->type);

	*ptr = '\0';
	/* Properly format value */
	switch (FIELD_DISPLAY(display)) {
		case BASE_DEC:
			return isint ? int64_to_str_back(ptr, (gint64) value) : uint64_to_str_back(ptr, value);

		case BASE_DEC_HEX:
			*(--ptr) = ')';
			ptr = hex64_to_str_back_len(ptr, value, hfinfo_hex_digits(hfinfo));
			*(--ptr) = '(';
			*(--ptr) = ' ';
			ptr = isint ? int64_to_str_back(ptr, (gint64) value) : uint64_to_str_back(ptr, value);
			return ptr;

		case BASE_OCT:
			return oct64_to_str_back(ptr, value);

		case BASE_HEX:
			return hex64_to_str_back_len(ptr, value, hfinfo_hex_digits(hfinfo));

		case BASE_HEX_DEC:
			*(--ptr) = ')';
			ptr = isint ? int64_to_str_back(ptr, (gint64) value) : uint64_to_str_back(ptr, value);
			*(--ptr) = '(';
			*(--ptr) = ' ';
			ptr = hex64_to_str_back_len(ptr, value, hfinfo_hex_digits(hfinfo));
			return ptr;

		default:
			REPORT_DISSECTOR_BUG("Invalid base: %d", FIELD_DISPLAY(display));
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
hfinfo_number_value_format64(const header_field_info *hfinfo, char buf[48], guint64 value)
{
	int display = hfinfo->display;

	if (hfinfo->type == FT_FRAMENUM) {
		/*
		 * Frame numbers are always displayed in decimal.
		 */
		display = BASE_DEC;
	}

	return hfinfo_number_value_format_display64(hfinfo, display, buf, value);
}

static const char *
hfinfo_char_value_format(const header_field_info *hfinfo, char buf[32], guint32 value)
{
	/* Get the underlying BASE_ value */
	int display = FIELD_DISPLAY(hfinfo->display);

	return hfinfo_char_value_format_display(display, buf, value);
}

static const char *
hfinfo_numeric_value_format(const header_field_info *hfinfo, char buf[32], guint32 value)
{
	/* Get the underlying BASE_ value */
	int display = FIELD_DISPLAY(hfinfo->display);

	if (hfinfo->type == FT_FRAMENUM) {
		/*
		 * Frame numbers are always displayed in decimal.
		 */
		display = BASE_DEC;
	}

	if (IS_BASE_PORT(display)) {
		display = BASE_DEC;
	} else if (display == BASE_OUI) {
		display = BASE_HEX;
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
hfinfo_numeric_value_format64(const header_field_info *hfinfo, char buf[48], guint64 value)
{
	/* Get the underlying BASE_ value */
	int display = FIELD_DISPLAY(hfinfo->display);

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

	return hfinfo_number_value_format_display64(hfinfo, display, buf, value);
}

static const char *
hfinfo_char_vals_format(const header_field_info *hfinfo, char buf[32], guint32 value)
{
	/* Get the underlying BASE_ value */
	int display = FIELD_DISPLAY(hfinfo->display);

	return hfinfo_char_value_format_display(display, buf, value);
}

static const char *
hfinfo_number_vals_format(const header_field_info *hfinfo, char buf[32], guint32 value)
{
	/* Get the underlying BASE_ value */
	int display = FIELD_DISPLAY(hfinfo->display);

	if (display == BASE_NONE)
		return NULL;

	if (display == BASE_DEC_HEX)
		display = BASE_DEC;
	if (display == BASE_HEX_DEC)
		display = BASE_HEX;

	return hfinfo_number_value_format_display(hfinfo, display, buf, value);
}

static const char *
hfinfo_number_vals_format64(const header_field_info *hfinfo, char buf[48], guint64 value)
{
	/* Get the underlying BASE_ value */
	int display = FIELD_DISPLAY(hfinfo->display);

	if (display == BASE_NONE)
		return NULL;

	if (display == BASE_DEC_HEX)
		display = BASE_DEC;
	if (display == BASE_HEX_DEC)
		display = BASE_HEX;

	return hfinfo_number_value_format_display64(hfinfo, display, buf, value);
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
	return (((hfinfo->id != hf_text_only) && (hfinfo->parent == -1)) ? TRUE : FALSE);
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

	if (g_ptr_array_len(ptrs) > 0) {
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

/* Helper function for proto_find_first_info() */
static gboolean
find_first_finfo(proto_node *node, gpointer data)
{
	field_info *fi = PNODE_FINFO(node);
	if (fi && fi->hfinfo) {
		if (fi->hfinfo->id == ((ffdata_t*)data)->id) {
			g_ptr_array_add(((ffdata_t*)data)->array, fi);

			/* Stop traversing. */
			return TRUE;
		}
	}

	/* Continue traversing. */
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

/* Return GPtrArray* of first field_info pointers for the searched hfindex that appear in a tree.
* This works on any proto_tree, primed or unprimed, but actually searches
* the tree, so it is slower than using proto_get_finfo_ptr_array on a primed tree.
* The caller does need to free the returned GPtrArray with
* g_ptr_array_free(<array>, TRUE).
*/
GPtrArray *
proto_find_first_finfo(proto_tree *tree, const int id)
{
	ffdata_t ffdata;

	ffdata.array = g_ptr_array_new();
	ffdata.id = id;

	proto_tree_traverse_pre_order(tree, find_first_finfo, &ffdata);

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

	/* Pre allocate enough space to hold all fields in most cases */
	ffdata.array = g_ptr_array_sized_new(512);
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
check_for_offset(proto_node *node, gpointer data)
{
	field_info	*fi        = PNODE_FINFO(node);
	offset_search_t	*offsearch = (offset_search_t *)data;

	/* !fi == the top most container node which holds nothing */
	if (fi && !proto_item_is_hidden(node) && !proto_item_is_generated(node) && fi->ds_tvb && offsearch->tvb == fi->ds_tvb) {
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

typedef struct {
	gint length;
	gchar *buf;
} decoded_data_t;

static gboolean
check_for_undecoded(proto_node *node, gpointer data)
{
	field_info *fi = PNODE_FINFO(node);
	decoded_data_t* decoded = (decoded_data_t*)data;
	gint i;
	guint byte;
	guint bit;

	if (fi && fi->hfinfo->type != FT_PROTOCOL) {
		for (i = fi->start; i < fi->start + fi->length && i < decoded->length; i++) {
			byte = i / 8;
			bit = i % 8;
			decoded->buf[byte] |= (1 << bit);
		}
	}

	return FALSE;
}

gchar*
proto_find_undecoded_data(proto_tree *tree, guint length)
{
	decoded_data_t decoded;
	decoded.length = length;
	decoded.buf = (gchar*)wmem_alloc0(PNODE_POOL(tree), length / 8 + 1);

	proto_tree_traverse_pre_order(tree, check_for_undecoded, &decoded);
	return decoded.buf;
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
	const unit_name_string	*units;

	len = gpa_hfinfo.len;
	for (i = 0; i < len ; i++) {
		if (gpa_hfinfo.hfi[i] == NULL)
			continue; /* This is a deregistered protocol or field */

		PROTO_REGISTRAR_GET_NTH(i, hfinfo);

		if (hfinfo->id == hf_text_only) {
			continue;
		}

		/* ignore protocols */
		if (proto_registrar_is_protocol(i)) {
			continue;
		}
		/* process header fields */
#if 0 /* XXX: We apparently allow fields with the same name but with differing "strings" content */
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
#endif
		vals   = NULL;
		vals64 = NULL;
		range  = NULL;
		tfs    = NULL;
		units  = NULL;

		if (hfinfo->strings != NULL) {
			if (FIELD_DISPLAY(hfinfo->display) != BASE_CUSTOM &&
			    (hfinfo->type == FT_CHAR  ||
			     hfinfo->type == FT_UINT8  ||
			     hfinfo->type == FT_UINT16 ||
			     hfinfo->type == FT_UINT24 ||
			     hfinfo->type == FT_UINT32 ||
			     hfinfo->type == FT_UINT40 ||
			     hfinfo->type == FT_UINT48 ||
			     hfinfo->type == FT_UINT56 ||
			     hfinfo->type == FT_UINT64 ||
			     hfinfo->type == FT_INT8   ||
			     hfinfo->type == FT_INT16  ||
			     hfinfo->type == FT_INT24  ||
			     hfinfo->type == FT_INT32  ||
			     hfinfo->type == FT_INT40  ||
			     hfinfo->type == FT_INT48  ||
			     hfinfo->type == FT_INT56  ||
			     hfinfo->type == FT_INT64  ||
			     hfinfo->type == FT_FLOAT  ||
			     hfinfo->type == FT_DOUBLE)) {

				if (hfinfo->display & BASE_RANGE_STRING) {
					range = (const range_string *)hfinfo->strings;
				} else if (hfinfo->display & BASE_EXT_STRING) {
					if (hfinfo->display & BASE_VAL64_STRING) {
						vals64 = VAL64_STRING_EXT_VS_P((const val64_string_ext *)hfinfo->strings);
					} else {
						vals = VALUE_STRING_EXT_VS_P((const value_string_ext *)hfinfo->strings);
					}
				} else if (hfinfo->display & BASE_VAL64_STRING) {
					vals64 = (const val64_string *)hfinfo->strings;
				} else if (hfinfo->display & BASE_UNIT_STRING) {
					units = (const unit_name_string *)hfinfo->strings;
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
				if (hfinfo->display & BASE_VAL64_STRING) {
					val64_string_ext *vse_p = (val64_string_ext *)hfinfo->strings;
					if (!val64_string_ext_validate(vse_p)) {
						ws_warning("Invalid val64_string_ext ptr for: %s", hfinfo->abbrev);
						continue;
					}
					try_val64_to_str_ext(0, vse_p); /* "prime" the extended val64_string */
					printf("E\t%s\t%u\t%s\t%s\n",
					       hfinfo->abbrev,
					       VAL64_STRING_EXT_VS_NUM_ENTRIES(vse_p),
					       VAL64_STRING_EXT_VS_NAME(vse_p),
					       val64_string_ext_match_type_str(vse_p));
				} else {
					value_string_ext *vse_p = (value_string_ext *)hfinfo->strings;
					if (!value_string_ext_validate(vse_p)) {
						ws_warning("Invalid value_string_ext ptr for: %s", hfinfo->abbrev);
						continue;
					}
					try_val_to_str_ext(0, vse_p); /* "prime" the extended value_string */
					printf("E\t%s\t%u\t%s\t%s\n",
					       hfinfo->abbrev,
					       VALUE_STRING_EXT_VS_NUM_ENTRIES(vse_p),
					       VALUE_STRING_EXT_VS_NAME(vse_p),
					       value_string_ext_match_type_str(vse_p));
				}
			}
			vi = 0;
			while (vals[vi].strptr) {
				/* Print in the proper base */
				if (hfinfo->type == FT_CHAR) {
					if (g_ascii_isprint(vals[vi].value)) {
						printf("V\t%s\t'%c'\t%s\n",
						       hfinfo->abbrev,
						       vals[vi].value,
						       vals[vi].strptr);
					} else {
						if (hfinfo->display == BASE_HEX) {
							printf("V\t%s\t'\\x%02x'\t%s\n",
							       hfinfo->abbrev,
							       vals[vi].value,
							       vals[vi].strptr);
						}
						else {
							printf("V\t%s\t'\\%03o'\t%s\n",
							       hfinfo->abbrev,
							       vals[vi].value,
							       vals[vi].strptr);
						}
					}
				} else {
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
				}
				vi++;
			}
		}
		else if (vals64) {
			vi = 0;
			while (vals64[vi].strptr) {
				printf("V64\t%s\t%" PRIu64 "\t%s\n",
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
				if (FIELD_DISPLAY(hfinfo->display) == BASE_HEX) {
					printf("R\t%s\t0x%"PRIx64"\t0x%"PRIx64"\t%s\n",
					       hfinfo->abbrev,
					       range[vi].value_min,
					       range[vi].value_max,
					       range[vi].strptr);
				}
				else {
					printf("R\t%s\t%"PRIu64"\t%"PRIu64"\t%s\n",
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
		/* Print unit strings? */
		else if (units) {
			printf("U\t%s\t%s\t%s\n", hfinfo->abbrev,
			       units->singular, units->plural ? units->plural : "(no plural)");
		}
	}
}

/* Prints the number of registered fields.
 * Useful for determining an appropriate value for
 * PROTO_PRE_ALLOC_HF_FIELDS_MEM.
 *
 * Returns FALSE if PROTO_PRE_ALLOC_HF_FIELDS_MEM is larger than or equal to
 * the number of fields, TRUE otherwise.
 */
gboolean
proto_registrar_dump_fieldcount(void)
{
	guint32			i;
	header_field_info	*hfinfo;
	guint32			deregistered_count = 0;
	guint32			same_name_count = 0;
	guint32			protocol_count = 0;

	for (i = 0; i < gpa_hfinfo.len; i++) {
		if (gpa_hfinfo.hfi[i] == NULL) {
			deregistered_count++;
			continue; /* This is a deregistered protocol or header field */
		}

		PROTO_REGISTRAR_GET_NTH(i, hfinfo);

		if (proto_registrar_is_protocol(i))
			protocol_count++;

		if (hfinfo->same_name_prev_id != -1)
			same_name_count++;
	}

	printf("There are %u header fields registered, of which:\n"
		"\t%u are deregistered\n"
		"\t%u are protocols\n"
		"\t%u have the same name as another field\n\n",
		gpa_hfinfo.len, deregistered_count, protocol_count,
		same_name_count);

	printf("%d fields were pre-allocated.\n%s", PROTO_PRE_ALLOC_HF_FIELDS_MEM,
		(gpa_hfinfo.allocated_len > PROTO_PRE_ALLOC_HF_FIELDS_MEM) ?
		    "* * Please increase PROTO_PRE_ALLOC_HF_FIELDS_MEM (in epan/proto.c)! * *\n\n" :
		    "\n");

	printf("The header field table consumes %u KiB of memory.\n",
		(unsigned int)(gpa_hfinfo.allocated_len * sizeof(header_field_info *) / 1024));
	printf("The fields themselves consume %u KiB of memory.\n",
		(unsigned int)(gpa_hfinfo.len * sizeof(header_field_info) / 1024));

	return (gpa_hfinfo.allocated_len > PROTO_PRE_ALLOC_HF_FIELDS_MEM);
}

static void
elastic_add_base_mapping(json_dumper *dumper)
{
	json_dumper_set_member_name(dumper, "settings");
	json_dumper_begin_object(dumper);
	json_dumper_set_member_name(dumper, "index.mapping.total_fields.limit");
	json_dumper_value_anyf(dumper, "%d", 1000000);
	json_dumper_end_object(dumper);
}

static gchar*
ws_type_to_elastic(guint type _U_)
{
	switch(type) {
		case FT_UINT16:
		case FT_INT16:
		case FT_INT32:
		case FT_UINT24:
		case FT_INT24:
			return "integer";
		case FT_INT8:
		case FT_UINT8:
			return "short";
		case FT_FRAMENUM:
		case FT_UINT32:
		case FT_UINT40:
		case FT_UINT48:
		case FT_UINT56:
		case FT_UINT64: // Actually it's not handled by 'long' elastic type.
		case FT_INT48:
		case FT_INT64:
			return "long";
		case FT_FLOAT:
		case FT_DOUBLE:
			return "float";
		case FT_IPv6:
		case FT_IPv4:
			return "ip";
		case FT_ABSOLUTE_TIME:
		case FT_RELATIVE_TIME:
			return "date";
		case FT_BYTES:
		case FT_UINT_BYTES:
			return "byte";
		case FT_BOOLEAN:
			return "boolean";
		default:
			return NULL;
	}
}

static gchar*
dot_to_underscore(gchar* str)
{
	unsigned i;
	for (i = 0; i < strlen(str); i++) {
		if (str[i] == '.')
			str[i] = '_';
	}
	return str;
}

/* Dumps a mapping file for ElasticSearch
 */
void
proto_registrar_dump_elastic(const gchar* filter)
{
	header_field_info *hfinfo;
	header_field_info *parent_hfinfo;
	guint i;
	gboolean open_object = TRUE;
	const char* prev_proto = NULL;
	gchar* str;
	gchar** protos = NULL;
	gchar* proto;
	gboolean found;
	guint j;
	gchar* type;
	gchar* prev_item = NULL;

	/* We have filtering protocols. Extract them. */
	if (filter) {
		protos = g_strsplit(filter, ",", -1);
	}

	/*
	 * To help tracking down the json tree, objects have been appended with a comment:
	 * n.label -> where n is the indentation level and label the name of the object
	 */

	json_dumper dumper = {
		.output_file = stdout,
		.flags = JSON_DUMPER_FLAGS_PRETTY_PRINT,
	};
	json_dumper_begin_object(&dumper); // 1.root
	elastic_add_base_mapping(&dumper);

	json_dumper_set_member_name(&dumper, "mappings");
	json_dumper_begin_object(&dumper); // 2.mappings
	json_dumper_set_member_name(&dumper, "dynamic");
	json_dumper_value_anyf(&dumper, "false");

	json_dumper_set_member_name(&dumper, "properties");
	json_dumper_begin_object(&dumper); // 3.properties
	json_dumper_set_member_name(&dumper, "timestamp");
	json_dumper_begin_object(&dumper); // 4.timestamp
	json_dumper_set_member_name(&dumper, "type");
	json_dumper_value_string(&dumper, "date");
	json_dumper_end_object(&dumper); // 4.timestamp

	json_dumper_set_member_name(&dumper, "layers");
	json_dumper_begin_object(&dumper); // 4.layers
	json_dumper_set_member_name(&dumper, "properties");
	json_dumper_begin_object(&dumper); // 5.properties

	for (i = 0; i < gpa_hfinfo.len; i++) {
		if (gpa_hfinfo.hfi[i] == NULL)
			continue; /* This is a deregistered protocol or header field */

		PROTO_REGISTRAR_GET_NTH(i, hfinfo);

		/*
		 * Skip the pseudo-field for "proto_tree_add_text()" since
		 * we don't want it in the list of filterable protocols.
		 */
		if (hfinfo->id == hf_text_only)
			continue;

		if (!proto_registrar_is_protocol(i)) {
			PROTO_REGISTRAR_GET_NTH(hfinfo->parent, parent_hfinfo);

			/*
			 * Skip the field if filter protocols have been set and this one's
			 * parent is not listed.
			 */
			if (protos) {
				found = FALSE;
				j = 0;
				proto = protos[0];
				while(proto) {
					if (!g_strcmp0(proto, parent_hfinfo->abbrev)) {
						found = TRUE;
						break;
					}
					j++;
					proto = protos[j];
				}
				if (!found)
					continue;
			}

			if (prev_proto && g_strcmp0(parent_hfinfo->abbrev, prev_proto)) {
				json_dumper_end_object(&dumper); // 7.properties
				json_dumper_end_object(&dumper); // 8.parent_hfinfo->abbrev
				open_object = TRUE;
			}

			prev_proto = parent_hfinfo->abbrev;

			if (open_object) {
				json_dumper_set_member_name(&dumper, parent_hfinfo->abbrev);
				json_dumper_begin_object(&dumper); // 6.parent_hfinfo->abbrev
				json_dumper_set_member_name(&dumper, "properties");
				json_dumper_begin_object(&dumper); // 7.properties
				open_object = FALSE;
			}
			/* Skip the fields that would map into string. This is the default in elasticsearch. */
			type = ws_type_to_elastic(hfinfo->type);
			if (type) {
				str = ws_strdup_printf("%s_%s", prev_proto, hfinfo->abbrev);
				dot_to_underscore(str);
				if (g_strcmp0(prev_item, str)) {
					json_dumper_set_member_name(&dumper, str);
					json_dumper_begin_object(&dumper); // 8.hfinfo->abbrev
					json_dumper_set_member_name(&dumper, "type");
					json_dumper_value_string(&dumper, type);
					json_dumper_end_object(&dumper); // 8.hfinfo->abbrev
				}
				g_free(prev_item);
				prev_item = str;
			}
		}
	}
	g_free(prev_item);

	if (prev_proto) {
		json_dumper_end_object(&dumper); // 7.properties
		json_dumper_end_object(&dumper); // 6.parent_hfinfo->abbrev
	}

	json_dumper_end_object(&dumper); // 5.properties
	json_dumper_end_object(&dumper); // 4.layers
	json_dumper_end_object(&dumper); // 3.properties
	json_dumper_end_object(&dumper); // 2.mappings
	json_dumper_end_object(&dumper); // 1.root
	gboolean ret = json_dumper_finish(&dumper);
	DISSECTOR_ASSERT(ret);

	g_strfreev(protos);
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
 * Field 4 = type ( textual representation of the ftenum type )
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
		if (gpa_hfinfo.hfi[i] == NULL)
			continue; /* This is a deregistered protocol or header field */

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

			if (hfinfo->type == FT_CHAR  ||
			    hfinfo->type == FT_UINT8  ||
			    hfinfo->type == FT_UINT16 ||
			    hfinfo->type == FT_UINT24 ||
			    hfinfo->type == FT_UINT32 ||
			    hfinfo->type == FT_UINT40 ||
			    hfinfo->type == FT_UINT48 ||
			    hfinfo->type == FT_UINT56 ||
			    hfinfo->type == FT_UINT64 ||
			    hfinfo->type == FT_INT8   ||
			    hfinfo->type == FT_INT16  ||
			    hfinfo->type == FT_INT24  ||
			    hfinfo->type == FT_INT32  ||
			    hfinfo->type == FT_INT40 ||
			    hfinfo->type == FT_INT48 ||
			    hfinfo->type == FT_INT56 ||
			    hfinfo->type == FT_INT64) {

				switch (FIELD_DISPLAY(hfinfo->display)) {
					case BASE_NONE:
					case BASE_DEC:
					case BASE_HEX:
					case BASE_OCT:
					case BASE_DEC_HEX:
					case BASE_HEX_DEC:
					case BASE_CUSTOM:
					case BASE_PT_UDP:
					case BASE_PT_TCP:
					case BASE_PT_DCCP:
					case BASE_PT_SCTP:
					case BASE_OUI:
						base_name = val_to_str_const(FIELD_DISPLAY(hfinfo->display), hf_display, "????");
						break;
					default:
						base_name = "????";
						break;
				}
			} else if (hfinfo->type == FT_BOOLEAN) {
				/* For FT_BOOLEAN: 'display' can be "parent bitfield width" */
				snprintf(width, sizeof(width), "%d", hfinfo->display);
				base_name = width;
			}

			blurb = hfinfo->blurb;
			if (blurb == NULL)
				blurb = "";
			else if (strlen(blurb) == 0)
				blurb = "\"\"";

			printf("F\t%s\t%s\t%s\t%s\t%s\t0x%" PRIx64 "\t%s\n",
				hfinfo->name, hfinfo->abbrev, enum_name,
				parent_hfinfo->abbrev, base_name,
				hfinfo->bitmask, blurb);
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
	char		  *ptr;
	int		   buf_len;
	int		   i;
	gint		   start, length, length_remaining;
	guint8		   c;
	gchar		   is_signed_num = FALSE;

	if (!finfo)
		return FALSE;

	hfinfo     = finfo->hfinfo;
	DISSECTOR_ASSERT(hfinfo);

	if (hfinfo->strings && FIELD_DISPLAY(hfinfo->display) == BASE_NONE) {
		const gchar *str = NULL;

		switch (hfinfo->type) {

		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
			str = hf_try_val_to_str(fvalue_get_sinteger(&finfo->value), hfinfo);
			break;

		case FT_CHAR:
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
			*filter = wmem_strdup_printf(NULL, "%s == \"%s\"", hfinfo->abbrev, str);
			return TRUE;
		}
	}

	/*
	 * XXX - we can't use the "val_to_string_repr" function
	 * for FT_UINT and FT_INT types, as we choose the base in
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

		case FT_CHAR:
			if (filter != NULL) {
				guint32 number;

				char buf [48];
				const char *out;

				number = fvalue_get_uinteger(&finfo->value);

				out = hfinfo_char_value_format(hfinfo, buf, number);

				*filter = wmem_strdup_printf(NULL, "%s == %s", hfinfo->abbrev, out);
			}
			break;

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

				*filter = wmem_strdup_printf(NULL, "%s == %s", hfinfo->abbrev, out);
			}
			break;

		case FT_INT40:
		case FT_INT48:
		case FT_INT56:
		case FT_INT64:
			is_signed_num = TRUE;
			/* FALLTHRU */
		case FT_UINT40:
		case FT_UINT48:
		case FT_UINT56:
		case FT_UINT64:
			if (filter != NULL) {
				guint64 number;

				char buf [48];
				const char *out;

				if (is_signed_num)
					number = fvalue_get_sinteger64(&finfo->value);
				else
					number = fvalue_get_uinteger64(&finfo->value);

				out = hfinfo_numeric_value_format64(hfinfo, buf, number);

				*filter = wmem_strdup_printf(NULL, "%s == %s", hfinfo->abbrev, out);
			}
			break;

		case FT_PROTOCOL:
			if (filter != NULL)
				*filter = wmem_strdup(NULL, finfo->hfinfo->abbrev);
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
					*filter = wmem_strdup(NULL, finfo->hfinfo->abbrev);
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
				*filter = (char *)wmem_alloc0(NULL, buf_len);
				ptr = *filter;

				ptr += snprintf(ptr, (gulong) (buf_len-(ptr-*filter)),
					"frame[%d:%d] == ", finfo->start, length);
				for (i=0; i<length; i++) {
					c = tvb_get_guint8(finfo->ds_tvb, start);
					start++;
					if (i == 0 ) {
						ptr += snprintf(ptr, (gulong) (buf_len-(ptr-*filter)), "%02x", c);
					}
					else {
						ptr += snprintf(ptr, (gulong) (buf_len-(ptr-*filter)), ":%02x", c);
					}
				}
			}
			break;

		/* By default, use the fvalue's "to_string_repr" method. */
		default:
			if (filter != NULL) {
				char *str = fvalue_to_string_repr(NULL, &finfo->value, FTREPR_DFILTER, finfo->hfinfo->display);
				*filter = wmem_strdup_printf(NULL, "%s == %s", hfinfo->abbrev, str);
				wmem_free(NULL, str);
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
 * The string is wmem allocated and must be freed with "wmem_free(NULL, ...)".
 */
char *
proto_construct_match_selected_string(field_info *finfo, epan_dissect_t *edt)
{
	char *filter = NULL;

	if (!construct_match_selected_string(finfo, edt, &filter))
	{
		wmem_free(NULL, filter);
		return NULL;
	}
	return filter;
}

/* This function is common code for all proto_tree_add_bitmask... functions.
 */

static gboolean
proto_item_add_bitmask_tree(proto_item *item, tvbuff_t *tvb, const int offset,
			    const int len, const gint ett, int * const *fields,
			    const int flags, gboolean first,
			    gboolean use_parent_tree,
			    proto_tree* tree, guint64 value)
{
	guint64            available_bits = G_MAXUINT64;
	guint64            bitmask = 0;
	guint64            tmpval;
	header_field_info *hf;
	guint32            integer32;
	gint               bit_offset;
	gint               no_of_bits;

	if (!*fields)
		REPORT_DISSECTOR_BUG("Illegal call of proto_item_add_bitmask_tree without fields");

	if (len < 0 || len > 8)
		REPORT_DISSECTOR_BUG("Invalid len: %d", len);
	/**
	 * packet-frame.c uses len=0 since the value is taken from the packet
	 * metadata, not the packet bytes. In that case, assume that all bits
	 * in the provided value are valid.
	 */
	if (len > 0) {
		available_bits >>= (8 - (guint)len)*8;
	}

	if (use_parent_tree == FALSE)
		tree = proto_item_add_subtree(item, ett);

	while (*fields) {
		guint64 present_bits;
		PROTO_REGISTRAR_GET_NTH(**fields,hf);
		DISSECTOR_ASSERT_HINT(hf->bitmask != 0, hf->abbrev);

		bitmask |= hf->bitmask;

		/* Skip fields that aren't fully present */
		present_bits = available_bits & hf->bitmask;
		if (present_bits != hf->bitmask) {
			fields++;
			continue;
		}

		switch (hf->type) {
		case FT_CHAR:
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
			proto_tree_add_uint(tree, **fields, tvb, offset, len, (guint32)value);
			break;

		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
			proto_tree_add_int(tree, **fields, tvb, offset, len, (gint32)value);
			break;

		case FT_UINT40:
		case FT_UINT48:
		case FT_UINT56:
		case FT_UINT64:
			proto_tree_add_uint64(tree, **fields, tvb, offset, len, value);
			break;

		case FT_INT40:
		case FT_INT48:
		case FT_INT56:
		case FT_INT64:
			proto_tree_add_int64(tree, **fields, tvb, offset, len, (gint64)value);
			break;

		case FT_BOOLEAN:
			proto_tree_add_boolean64(tree, **fields, tvb, offset, len, value);
			break;

		default:
			REPORT_DISSECTOR_BUG("field %s has type %d (%s) not handled in proto_item_add_bitmask_tree()",
					     hf->abbrev,
					     hf->type,
					     ftype_name(hf->type));
			break;
		}
		if (flags & BMT_NO_APPEND) {
			fields++;
			continue;
		}
		tmpval = (value & hf->bitmask) >> hfinfo_bitshift(hf);

		/* XXX: README.developer and the comments have always defined
		 * BMT_NO_INT as "only boolean flags are added to the title /
		 * don't add non-boolean (integral) fields", but the
		 * implementation has always added BASE_CUSTOM and fields with
		 * value_strings, though not fields with unit_strings.
		 * Possibly this is because some dissectors use a FT_UINT8
		 * with a value_string for fields that should be a FT_BOOLEAN.
		 */
		switch (hf->type) {
		case FT_CHAR:
			if (hf->display == BASE_CUSTOM) {
				gchar lbl[ITEM_LABEL_LENGTH];
				const custom_fmt_func_t fmtfunc = (const custom_fmt_func_t)hf->strings;

				DISSECTOR_ASSERT(fmtfunc);
				fmtfunc(lbl, (guint32) tmpval);
				proto_item_append_text(item, "%s%s: %s", first ? "" : ", ",
						hf->name, lbl);
				first = FALSE;
			}
			else if (hf->strings) {
				proto_item_append_text(item, "%s%s: %s", first ? "" : ", ",
						       hf->name, hf_try_val_to_str_const((guint32) tmpval, hf, "Unknown"));
				first = FALSE;
			}
			else if (!(flags & BMT_NO_INT)) {
				char buf[32];
				const char *out;

				if (!first) {
					proto_item_append_text(item, ", ");
				}

				out = hfinfo_char_value_format(hf, buf, (guint32) tmpval);
				proto_item_append_text(item, "%s: %s", hf->name, out);
				first = FALSE;
			}

			break;

		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
			if (hf->display == BASE_CUSTOM) {
				gchar lbl[ITEM_LABEL_LENGTH];
				const custom_fmt_func_t fmtfunc = (const custom_fmt_func_t)hf->strings;

				DISSECTOR_ASSERT(fmtfunc);
				fmtfunc(lbl, (guint32) tmpval);
				proto_item_append_text(item, "%s%s: %s", first ? "" : ", ",
						hf->name, lbl);
				first = FALSE;
			}
			else if ((hf->strings) &&(!(hf->display & (BASE_UNIT_STRING|BASE_SPECIAL_VALS)))) {
				proto_item_append_text(item, "%s%s: %s", first ? "" : ", ",
										hf->name, hf_try_val_to_str_const((guint32) tmpval, hf, "Unknown"));
				first = FALSE;
			}
			else if (!(flags & BMT_NO_INT)) {
				char buf[32];
				const char *out = NULL;

				if (!first) {
					proto_item_append_text(item, ", ");
				}

				if (hf->strings && hf->display & BASE_SPECIAL_VALS) {
					out = hf_try_val_to_str((guint32) tmpval, hf);
				}
				if (out == NULL) {
					out = hfinfo_number_value_format(hf, buf, (guint32) tmpval);
				}
				proto_item_append_text(item, "%s: %s", hf->name, out);
				if (hf->strings && hf->display & BASE_UNIT_STRING) {
					proto_item_append_text(item, "%s", unit_name_string_get_value((guint32) tmpval, (const unit_name_string*)hf->strings));
				}
				first = FALSE;
			}

			break;

		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
			integer32 = (guint32) tmpval;
			if (hf->bitmask) {
				no_of_bits = ws_count_ones(hf->bitmask);
				integer32 = ws_sign_ext32(integer32, no_of_bits);
			}
			if (hf->display == BASE_CUSTOM) {
				gchar lbl[ITEM_LABEL_LENGTH];
				const custom_fmt_func_t fmtfunc = (const custom_fmt_func_t)hf->strings;

				DISSECTOR_ASSERT(fmtfunc);
				fmtfunc(lbl, (gint32) integer32);
				proto_item_append_text(item, "%s%s: %s", first ? "" : ", ",
						hf->name, lbl);
				first = FALSE;
			}
			else if ((hf->strings) &&(!(hf->display & (BASE_UNIT_STRING|BASE_SPECIAL_VALS)))) {
				proto_item_append_text(item, "%s%s: %s", first ? "" : ", ",
						hf->name, hf_try_val_to_str_const((gint32) integer32, hf, "Unknown"));
				first = FALSE;
			}
			else if (!(flags & BMT_NO_INT)) {
				char buf[32];
				const char *out = NULL;

				if (!first) {
					proto_item_append_text(item, ", ");
				}

				if (hf->strings && hf->display & BASE_SPECIAL_VALS) {
					out = hf_try_val_to_str((gint32) integer32, hf);
				}
				if (out == NULL) {
					out = hfinfo_number_value_format(hf, buf, (gint32) integer32);
				}
				proto_item_append_text(item, "%s: %s", hf->name, out);
				if (hf->display & BASE_UNIT_STRING) {
					proto_item_append_text(item, "%s", unit_name_string_get_value((guint32) tmpval, (const unit_name_string*)hf->strings));
				}
				first = FALSE;
			}

			break;

		case FT_UINT40:
		case FT_UINT48:
		case FT_UINT56:
		case FT_UINT64:
			if (hf->display == BASE_CUSTOM) {
				gchar lbl[ITEM_LABEL_LENGTH];
				const custom_fmt_func_64_t fmtfunc = (const custom_fmt_func_64_t)hf->strings;

				DISSECTOR_ASSERT(fmtfunc);
				fmtfunc(lbl, tmpval);
				proto_item_append_text(item, "%s%s: %s", first ? "" : ", ",
						hf->name, lbl);
				first = FALSE;
			}
			else if ((hf->strings) &&(!(hf->display & (BASE_UNIT_STRING|BASE_SPECIAL_VALS)))) {
				proto_item_append_text(item, "%s%s: %s", first ? "" : ", ",
						hf->name, hf_try_val64_to_str_const(tmpval, hf, "Unknown"));
				first = FALSE;
			}
			else if (!(flags & BMT_NO_INT)) {
				char buf[48];
				const char *out = NULL;

				if (!first) {
					proto_item_append_text(item, ", ");
				}

				if (hf->strings && hf->display & BASE_SPECIAL_VALS) {
					out = hf_try_val64_to_str(tmpval, hf);
				}
				if (out == NULL) {
					out = hfinfo_number_value_format64(hf, buf, tmpval);
				}
				proto_item_append_text(item, "%s: %s", hf->name, out);
				if (hf->strings && hf->display & BASE_UNIT_STRING) {
					proto_item_append_text(item, "%s", unit_name_string_get_value64(tmpval, (const unit_name_string*)hf->strings));
				}
				first = FALSE;
			}

			break;

		case FT_INT40:
		case FT_INT48:
		case FT_INT56:
		case FT_INT64:
			if (hf->bitmask) {
				no_of_bits = ws_count_ones(hf->bitmask);
				tmpval = ws_sign_ext64(tmpval, no_of_bits);
			}
			if (hf->display == BASE_CUSTOM) {
				gchar lbl[ITEM_LABEL_LENGTH];
				const custom_fmt_func_64_t fmtfunc = (const custom_fmt_func_64_t)hf->strings;

				DISSECTOR_ASSERT(fmtfunc);
				fmtfunc(lbl, (gint64) tmpval);
				proto_item_append_text(item, "%s%s: %s", first ? "" : ", ",
						hf->name, lbl);
				first = FALSE;
			}
			else if ((hf->strings) &&(!(hf->display & (BASE_UNIT_STRING|BASE_SPECIAL_VALS)))) {
				proto_item_append_text(item, "%s%s: %s", first ? "" : ", ",
						hf->name, hf_try_val64_to_str_const((gint64) tmpval, hf, "Unknown"));
				first = FALSE;
			}
			else if (!(flags & BMT_NO_INT)) {
				char buf[48];
				const char *out = NULL;

				if (!first) {
					proto_item_append_text(item, ", ");
				}

				if (hf->strings && hf->display & BASE_SPECIAL_VALS) {
					out = hf_try_val64_to_str((gint64) tmpval, hf);
				}
				if (out == NULL) {
					out = hfinfo_number_value_format64(hf, buf, (gint64) tmpval);
				}
				proto_item_append_text(item, "%s: %s", hf->name, out);
				if (hf->strings && hf->display & BASE_UNIT_STRING) {
					proto_item_append_text(item, "%s", unit_name_string_get_value64(tmpval, (const unit_name_string*)hf->strings));
				}
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
			REPORT_DISSECTOR_BUG("field %s has type %d (%s) not handled in proto_item_add_bitmask_tree()",
					     hf->abbrev,
					     hf->type,
					     ftype_name(hf->type));
			break;
		}

		fields++;
	}

	/* XXX: We don't pass the hfi into this function. Perhaps we should,
	 * but then again most dissectors don't set the bitmask field for
	 * the higher level bitmask hfi, so calculate the bitmask from the
	 * fields present. */
	if (item) {
		bit_offset = len*8 - 1 - ws_ilog2(bitmask);
		no_of_bits = ws_ilog2(bitmask) - ws_ctz(bitmask) + 1;
		FI_SET_FLAG(PNODE_FINFO(item), FI_BITS_OFFSET(bit_offset));
		FI_SET_FLAG(PNODE_FINFO(item), FI_BITS_SIZE(no_of_bits));
	}
	return first;
}

/* This function will dissect a sequence of bytes that describe a
 * bitmask and supply the value of that sequence through a pointer.
 * hf_hdr is a 8/16/24/32/40/48/56/64 bit integer that describes the bitmask
 * to be dissected.
 * This field will form an expansion under which the individual fields of the
 * bitmask is dissected and displayed.
 * This field must be of the type FT_[U]INT{8|16|24|32|40|48|56|64}.
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
proto_tree_add_bitmask_ret_uint64(proto_tree *parent_tree, tvbuff_t *tvb,
		       const guint offset, const int hf_hdr,
		       const gint ett, int * const *fields,
		       const guint encoding, guint64 *retval)
{
	return proto_tree_add_bitmask_with_flags_ret_uint64(parent_tree, tvb, offset, hf_hdr, ett, fields, encoding, BMT_NO_INT|BMT_NO_TFS, retval);
}

/* This function will dissect a sequence of bytes that describe a
 * bitmask.
 * hf_hdr is a 8/16/24/32/40/48/56/64 bit integer that describes the bitmask
 * to be dissected.
 * This field will form an expansion under which the individual fields of the
 * bitmask is dissected and displayed.
 * This field must be of the type FT_[U]INT{8|16|24|32|40|48|56|64}.
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
		       const gint ett, int * const *fields,
		       const guint encoding)
{
	return proto_tree_add_bitmask_with_flags(parent_tree, tvb, offset, hf_hdr, ett, fields, encoding, BMT_NO_INT|BMT_NO_TFS);
}

/* The same as proto_tree_add_bitmask_ret_uint64(), but uses user-supplied flags to determine
 * what data is appended to the header.
 */
proto_item *
proto_tree_add_bitmask_with_flags_ret_uint64(proto_tree *parent_tree, tvbuff_t *tvb, const guint offset,
		const int hf_hdr, const gint ett, int * const *fields, const guint encoding, const int flags,
		guint64 *retval)
{
	proto_item        *item = NULL;
	header_field_info *hf;
	int                len;
	guint64            value;

	PROTO_REGISTRAR_GET_NTH(hf_hdr,hf);
	DISSECTOR_ASSERT_FIELD_TYPE_IS_INTEGRAL(hf);
	len = ftype_length(hf->type);
	value = get_uint64_value(parent_tree, tvb, offset, len, encoding);

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_hdr, tvb, offset, len, encoding);
		proto_item_add_bitmask_tree(item, tvb, offset, len, ett, fields,
		    flags, FALSE, FALSE, NULL, value);
	}

	*retval = value;
	if (hf->bitmask) {
		/* Mask out irrelevant portions */
		*retval &= hf->bitmask;
		/* Shift bits */
		*retval >>= hfinfo_bitshift(hf);
	}

	return item;
}

/* The same as proto_tree_add_bitmask_ret_uint64(), but uses user-supplied flags to determine
 * what data is appended to the header.
 */
proto_item *
proto_tree_add_bitmask_with_flags(proto_tree *parent_tree, tvbuff_t *tvb, const guint offset,
		const int hf_hdr, const gint ett, int * const *fields, const guint encoding, const int flags)
{
	proto_item        *item = NULL;
	header_field_info *hf;
	int                len;
	guint64            value;

	PROTO_REGISTRAR_GET_NTH(hf_hdr,hf);
	DISSECTOR_ASSERT_FIELD_TYPE_IS_INTEGRAL(hf);

	if (parent_tree) {
		len = ftype_length(hf->type);
		item = proto_tree_add_item(parent_tree, hf_hdr, tvb, offset, len, encoding);
		value = get_uint64_value(parent_tree, tvb, offset, len, encoding);
		proto_item_add_bitmask_tree(item, tvb, offset, len, ett, fields,
		    flags, FALSE, FALSE, NULL, value);
	}

	return item;
}

/* Similar to proto_tree_add_bitmask(), but with a passed in value (presumably because it
   can't be retrieved directly from tvb) */
proto_item *
proto_tree_add_bitmask_value(proto_tree *parent_tree, tvbuff_t *tvb, const guint offset,
		const int hf_hdr, const gint ett, int * const *fields, const guint64 value)
{
	return proto_tree_add_bitmask_value_with_flags(parent_tree, tvb, offset,
						hf_hdr, ett, fields, value, BMT_NO_INT|BMT_NO_TFS);
}

/* Similar to proto_tree_add_bitmask_value(), but with control of flag values */
WS_DLL_PUBLIC proto_item *
proto_tree_add_bitmask_value_with_flags(proto_tree *parent_tree, tvbuff_t *tvb, const guint offset,
		const int hf_hdr, const gint ett, int * const *fields, const guint64 value, const int flags)
{
	proto_item        *item = NULL;
	header_field_info *hf;
	int                len;

	PROTO_REGISTRAR_GET_NTH(hf_hdr,hf);
	DISSECTOR_ASSERT_FIELD_TYPE_IS_INTEGRAL(hf);
	/* the proto_tree_add_uint/_uint64() calls below
	   will fail if tvb==NULL and len!=0 */
	len = tvb ? ftype_length(hf->type) : 0;

	if (parent_tree) {
		if (len <= 4)
			item = proto_tree_add_uint(parent_tree, hf_hdr, tvb, offset, len, (guint32)value);
		else
			item = proto_tree_add_uint64(parent_tree, hf_hdr, tvb, offset, len, value);

		proto_item_add_bitmask_tree(item, tvb, offset, len, ett, fields,
		    flags, FALSE, FALSE, NULL, value);
	}

	return item;
}

/* Similar to proto_tree_add_bitmask(), but with no "header" item to group all of the fields */
void
proto_tree_add_bitmask_list(proto_tree *tree, tvbuff_t *tvb, const guint offset,
								const int len, int * const *fields, const guint encoding)
{
	guint64 value;

	if (tree) {
		value = get_uint64_value(tree, tvb, offset, len, encoding);
		proto_item_add_bitmask_tree(NULL, tvb, offset, len, -1, fields,
		    BMT_NO_APPEND, FALSE, TRUE, tree, value);
	}
}

WS_DLL_PUBLIC void
proto_tree_add_bitmask_list_ret_uint64(proto_tree *tree, tvbuff_t *tvb, const guint offset,
					const int len, int * const *fields, const guint encoding, guint64 *retval)
{
	guint64 value;

	value = get_uint64_value(tree, tvb, offset, len, encoding);
	if (tree) {
		proto_item_add_bitmask_tree(NULL, tvb, offset, len, -1, fields,
		    BMT_NO_APPEND, FALSE, TRUE, tree, value);
	}
	if (retval) {
		*retval = value;
	}
}

WS_DLL_PUBLIC void
proto_tree_add_bitmask_list_value(proto_tree *tree, tvbuff_t *tvb, const guint offset,
								const int len, int * const *fields, const guint64 value)
{
	if (tree) {
		proto_item_add_bitmask_tree(NULL, tvb, offset, len, -1, fields,
		    BMT_NO_APPEND, FALSE, TRUE, tree, value);
	}
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
		       const gint ett, int * const *fields, struct expert_field* exp,
		       const guint encoding)
{
	proto_item        *item = NULL;
	header_field_info *hf;
	guint   decodable_len;
	guint   decodable_offset;
	guint32 decodable_value;
	guint64 value;

	PROTO_REGISTRAR_GET_NTH(hf_hdr, hf);
	DISSECTOR_ASSERT_FIELD_TYPE_IS_INTEGRAL(hf);

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
		value = get_uint64_value(parent_tree, tvb, decodable_offset, decodable_len, encoding);
		proto_item_add_bitmask_tree(item, tvb, decodable_offset, decodable_len,
		    ett, fields, BMT_NO_INT|BMT_NO_TFS, FALSE, FALSE, NULL, value);
	}

	return item;
}

/* The same as proto_tree_add_bitmask(), but using an arbitrary text as a top-level item */
proto_item *
proto_tree_add_bitmask_text(proto_tree *parent_tree, tvbuff_t *tvb,
			    const guint offset, const guint len,
			    const char *name, const char *fallback,
			    const gint ett, int * const *fields,
			    const guint encoding, const int flags)
{
	proto_item *item = NULL;
	guint64     value;

	if (parent_tree) {
		item = proto_tree_add_text_internal(parent_tree, tvb, offset, len, "%s", name ? name : "");
		value = get_uint64_value(parent_tree, tvb, offset, len, encoding);
		if (proto_item_add_bitmask_tree(item, tvb, offset, len, ett, fields,
		    flags, TRUE, FALSE, NULL, value) && fallback) {
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
	test_length(hfinfo, tvb, octet_offset, octet_length, encoding);

	/* Yes, we try to fake this item again in proto_tree_add_bits_ret_val()
	 * but only after doing a bunch more work (which we can, in the common
	 * case, shortcut here).
	 */
	CHECK_FOR_NULL_TREE(tree);
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
	guint8  *bytes = NULL;
	size_t bytes_length = 0;

	proto_item        *pi;
	header_field_info *hf_field;

	const true_false_string *tfstring;

	/* We can't fake it just yet. We have to fill in the 'return_value' parameter */
	PROTO_REGISTRAR_GET_NTH(hfindex, hf_field);

	if (hf_field->bitmask != 0) {
		REPORT_DISSECTOR_BUG("Incompatible use of proto_tree_add_bits_ret_val"
				     " with field '%s' (%s) with bitmask != 0",
				     hf_field->abbrev, hf_field->name);
	}

	if (no_of_bits == 0) {
		REPORT_DISSECTOR_BUG("field %s passed to proto_tree_add_bits_ret_val() has a bit width of 0",
				     hf_field->abbrev);
	}

	/* Byte align offset */
	offset = bit_offset>>3;

	/*
	 * Calculate the number of octets used to hold the bits
	 */
	tot_no_bits = ((bit_offset&0x7) + no_of_bits);
	length = (tot_no_bits + 7) >> 3;

	if (no_of_bits < 65) {
		value = tvb_get_bits64(tvb, bit_offset, no_of_bits, encoding);
	} else if (hf_field->type != FT_BYTES) {
		REPORT_DISSECTOR_BUG("field %s passed to proto_tree_add_bits_ret_val() has a bit width of %u > 65",
				     hf_field->abbrev, no_of_bits);
		return NULL;
	}

	/* Sign extend for signed types */
	switch (hf_field->type) {
		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
		case FT_INT40:
		case FT_INT48:
		case FT_INT56:
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
	CHECK_FOR_NULL_TREE(tree);
	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hf_field);

	bf_str = decode_bits_in_field(PNODE_POOL(tree), bit_offset, no_of_bits, value, encoding);

	switch (hf_field->type) {
	case FT_BOOLEAN:
		/* Boolean field */
		tfstring = &tfs_true_false;
		if (hf_field->strings)
			tfstring = (const true_false_string *)hf_field->strings;
		return proto_tree_add_boolean_format(tree, hfindex, tvb, offset, length, (guint32)value,
			"%s = %s: %s",
			bf_str, hf_field->name, tfs_get_string(!!value, tfstring));
		break;

	case FT_CHAR:
		pi = proto_tree_add_uint(tree, hfindex, tvb, offset, length, (guint32)value);
		fill_label_char(PITEM_FINFO(pi), lbl_str);
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

	case FT_UINT40:
	case FT_UINT48:
	case FT_UINT56:
	case FT_UINT64:
		pi = proto_tree_add_uint64(tree, hfindex, tvb, offset, length, value);
		fill_label_number64(PITEM_FINFO(pi), lbl_str, FALSE);
		break;

	case FT_INT40:
	case FT_INT48:
	case FT_INT56:
	case FT_INT64:
		pi = proto_tree_add_int64(tree, hfindex, tvb, offset, length, (gint64)value);
		fill_label_number64(PITEM_FINFO(pi), lbl_str, TRUE);
		break;

	case FT_BYTES:
		bytes = tvb_get_bits_array(PNODE_POOL(tree), tvb, bit_offset, no_of_bits, &bytes_length, encoding);
		pi = proto_tree_add_bytes_with_length(tree, hfindex, tvb, offset, length, bytes, (gint) bytes_length);
		proto_item_fill_label(PITEM_FINFO(pi), lbl_str);
		proto_item_set_text(pi, "%s", lbl_str);
		return pi;
		break;

	default:
		REPORT_DISSECTOR_BUG("field %s has type %d (%s) not handled in proto_tree_add_bits_ret_val()",
				     hf_field->abbrev,
				     hf_field->type,
				     ftype_name(hf_field->type));
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
	char        bf_str[256];
	char        lbl_str[ITEM_LABEL_LENGTH];
	guint64     value;
	guint64     composite_bitmask;
	guint64     composite_bitmap;

	header_field_info       *hf_field;
	const true_false_string *tfstring;

	/* We can't fake it just yet. We have to fill in the 'return_value' parameter */
	PROTO_REGISTRAR_GET_NTH(hfindex, hf_field);

	if (hf_field->bitmask != 0) {
		REPORT_DISSECTOR_BUG("Incompatible use of proto_tree_add_split_bits_item_ret_val"
				     " with field '%s' (%s) with bitmask != 0",
				     hf_field->abbrev, hf_field->name);
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

		crumb_value = tvb_get_bits64(tvb,
					     bit_offset + crumb_spec[i].crumb_bit_offset,
					     crumb_spec[i].crumb_bit_length,
					     ENC_BIG_ENDIAN);
		value      += crumb_value;
		no_of_bits += crumb_spec[i].crumb_bit_length;
		DISSECTOR_ASSERT_HINT(no_of_bits <= 64, "a value larger than 64 bits cannot be represented");

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
			/* Currently the bitmap of the crumbs are only shown if
			 * smaller than 32 bits. Do not bother calculating the
			 * mask if it is larger than that. */
			if (crumb_end_bit_offset <= 32) {
				composite_bitmask |= (crumb_mask  << (64 - crumb_end_bit_offset));
				composite_bitmap  |= (crumb_value << (64 - crumb_end_bit_offset));
			}
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
		case FT_INT40:
		case FT_INT48:
		case FT_INT56:
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
	CHECK_FOR_NULL_TREE(tree);
	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hf_field);

	/* initialise the format string */
	bf_str[0] = '\0';

	octet_offset = bit_offset >> 3;

	/* Round up mask length to nearest octet */
	octet_length = ((mask_greatest_bit_offset + 7) >> 3);
	mask_greatest_bit_offset = octet_length << 3;

	/* As noted above, we currently only produce a bitmap if the crumbs span less than 4 octets of the tvb.
	   It would be a useful enhancement to eliminate this restriction. */
	if (mask_greatest_bit_offset > 0 && mask_greatest_bit_offset <= 32) {
		other_decode_bitfield_value(bf_str,
					    (guint32)(composite_bitmap  >> (64 - mask_greatest_bit_offset)),
					    (guint32)(composite_bitmask >> (64 - mask_greatest_bit_offset)),
					    mask_greatest_bit_offset);
	} else {
		/* If the bitmask is too large, try to describe its contents. */
		snprintf(bf_str, sizeof(bf_str), "%d bits", no_of_bits);
	}

	switch (hf_field->type) {
	case FT_BOOLEAN: /* it is a bit odd to have a boolean encoded as split-bits, but possible, I suppose? */
		/* Boolean field */
		tfstring = &tfs_true_false;
		if (hf_field->strings)
			tfstring = (const true_false_string *) hf_field->strings;
		return proto_tree_add_boolean_format(tree, hfindex,
						     tvb, octet_offset, octet_length, (guint32)value,
						     "%s = %s: %s",
						     bf_str, hf_field->name, tfs_get_string(!!value, tfstring));
		break;

	case FT_CHAR:
		pi = proto_tree_add_uint(tree, hfindex, tvb, octet_offset, octet_length, (guint32)value);
		fill_label_char(PITEM_FINFO(pi), lbl_str);
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

	case FT_UINT40:
	case FT_UINT48:
	case FT_UINT56:
	case FT_UINT64:
		pi = proto_tree_add_uint64(tree, hfindex, tvb, octet_offset, octet_length, value);
		fill_label_number64(PITEM_FINFO(pi), lbl_str, FALSE);
		break;

	case FT_INT40:
	case FT_INT48:
	case FT_INT56:
	case FT_INT64:
		pi = proto_tree_add_int64(tree, hfindex, tvb, octet_offset, octet_length, (gint64)value);
		fill_label_number64(PITEM_FINFO(pi), lbl_str, TRUE);
		break;

	default:
		REPORT_DISSECTOR_BUG("field %s has type %d (%s) not handled in proto_tree_add_split_bits_item_ret_val()",
				     hf_field->abbrev,
				     hf_field->type,
				     ftype_name(hf_field->type));
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
	gint start = bit_offset >> 3;
	gint length = ((bit_offset + crumb_spec[crumb_index].crumb_bit_length - 1) >> 3) - (bit_offset >> 3) + 1;

	/* We have to duplicate this length check from proto_tree_add_text_internal in order to check for a null tree
	 * so that we can use the tree's memory scope in calculating the string */
	if (length == -1) {
		tvb_captured_length(tvb) ? tvb_ensure_captured_length_remaining(tvb, start) : 0;
	} else {
		tvb_ensure_bytes_exist(tvb, start, length);
	}
	if (!tree) return;

	PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo);
	proto_tree_add_text_internal(tree, tvb, start, length,
			    "%s crumb %d of %s (decoded above)",
			    decode_bits_in_field(PNODE_POOL(tree), bit_offset, crumb_spec[crumb_index].crumb_bit_length,
						 tvb_get_bits(tvb,
							      bit_offset,
							      crumb_spec[crumb_index].crumb_bit_length,
							      ENC_BIG_ENDIAN),
						 ENC_BIG_ENDIAN),
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
				 const guint encoding, gchar *value_str)
{
	gint     offset;
	guint    length;
	guint8   tot_no_bits;
	char    *str;
	guint64  value = 0;
	header_field_info *hf_field;

	/* We do not have to return a value, try to fake it as soon as possible */
	CHECK_FOR_NULL_TREE(tree);
	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hf_field);

	if (hf_field->bitmask != 0) {
		REPORT_DISSECTOR_BUG("Incompatible use of proto_tree_add_bits_format_value"
				     " with field '%s' (%s) with bitmask != 0",
				     hf_field->abbrev, hf_field->name);
	}

	if (no_of_bits == 0) {
		REPORT_DISSECTOR_BUG("field %s passed to proto_tree_add_bits_format_value() has a bit width of 0",
				     hf_field->abbrev);
	}

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
		value = tvb_get_bits64(tvb, bit_offset, no_of_bits, encoding);
	} else {
		REPORT_DISSECTOR_BUG("field %s passed to proto_tree_add_bits_format_value() has a bit width of %u > 65",
				     hf_field->abbrev, no_of_bits);
		return NULL;
	}

	str = decode_bits_in_field(PNODE_POOL(tree), bit_offset, no_of_bits, value, encoding);

	(void) g_strlcat(str, " = ", 256+64);
	(void) g_strlcat(str, hf_field->name, 256+64);

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

	case FT_CHAR:
	case FT_UINT8:
	case FT_UINT16:
	case FT_UINT24:
	case FT_UINT32:
		return proto_tree_add_uint_format(tree, hfindex, tvb, offset, length, *(guint32 *)value_ptr,
						  "%s: %s", str, value_str);
		break;

	case FT_UINT40:
	case FT_UINT48:
	case FT_UINT56:
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

	case FT_INT40:
	case FT_INT48:
	case FT_INT56:
	case FT_INT64:
		return proto_tree_add_int64_format(tree, hfindex, tvb, offset, length, *(gint64 *)value_ptr,
						   "%s: %s", str, value_str);
		break;

	case FT_FLOAT:
		return proto_tree_add_float_format(tree, hfindex, tvb, offset, length, *(float *)value_ptr,
						   "%s: %s", str, value_str);
		break;

	default:
		REPORT_DISSECTOR_BUG("field %s has type %d (%s) not handled in proto_tree_add_bits_format_value()",
				     hf_field->abbrev,
				     hf_field->type,
				     ftype_name(hf_field->type));
		return NULL;
		break;
	}
}

static proto_item *
proto_tree_add_bits_format_value(proto_tree *tree, const int hfindex,
				 tvbuff_t *tvb, const guint bit_offset,
				 const gint no_of_bits, void *value_ptr,
				 const guint encoding, gchar *value_str)
{
	proto_item *item;

	if ((item = _proto_tree_add_bits_format_value(tree, hfindex,
						      tvb, bit_offset, no_of_bits,
						      value_ptr, encoding, value_str))) {
		FI_SET_FLAG(PNODE_FINFO(item), FI_BITS_OFFSET(bit_offset));
		FI_SET_FLAG(PNODE_FINFO(item), FI_BITS_SIZE(no_of_bits));
	}
	return item;
}

#define CREATE_VALUE_STRING(tree,dst,format,ap) \
	va_start(ap, format); \
	dst = wmem_strdup_vprintf(PNODE_POOL(tree), format, ap); \
	va_end(ap);

proto_item *
proto_tree_add_uint_bits_format_value(proto_tree *tree, const int hfindex,
				      tvbuff_t *tvb, const guint bit_offset,
				      const gint no_of_bits, guint32 value,
				      const guint encoding,
				      const char *format, ...)
{
	va_list ap;
	gchar  *dst;
	header_field_info *hf_field;

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hf_field);

	switch (hf_field->type) {
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
			break;

		default:
			REPORT_DISSECTOR_BUG("field %s is not of type FT_UINT8, FT_UINT16, FT_UINT24, or FT_UINT32",
			    hf_field->abbrev);
			return NULL;
			break;
	}

	CREATE_VALUE_STRING(tree, dst, format, ap);

	return proto_tree_add_bits_format_value(tree, hfindex, tvb, bit_offset, no_of_bits, &value, encoding, dst);
}

proto_item *
proto_tree_add_uint64_bits_format_value(proto_tree *tree, const int hfindex,
				      tvbuff_t *tvb, const guint bit_offset,
				      const gint no_of_bits, guint64 value,
				      const guint encoding,
				      const char *format, ...)
{
	va_list ap;
	gchar  *dst;
	header_field_info *hf_field;

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hf_field);

	switch (hf_field->type) {
		case FT_UINT40:
		case FT_UINT48:
		case FT_UINT56:
		case FT_UINT64:
			break;

		default:
			REPORT_DISSECTOR_BUG("field %s is not of type FT_UINT40, FT_UINT48, FT_UINT56, or FT_UINT64",
			    hf_field->abbrev);
			return NULL;
			break;
	}

	CREATE_VALUE_STRING(tree, dst, format, ap);

	return proto_tree_add_bits_format_value(tree, hfindex, tvb, bit_offset, no_of_bits, &value, encoding, dst);
}

proto_item *
proto_tree_add_float_bits_format_value(proto_tree *tree, const int hfindex,
				       tvbuff_t *tvb, const guint bit_offset,
				       const gint no_of_bits, float value,
				       const guint encoding,
				       const char *format, ...)
{
	va_list ap;
	gchar  *dst;
	header_field_info *hf_field;

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hf_field);

	DISSECTOR_ASSERT_FIELD_TYPE(hf_field, FT_FLOAT);

	CREATE_VALUE_STRING(tree, dst, format, ap);

	return proto_tree_add_bits_format_value(tree, hfindex, tvb, bit_offset, no_of_bits, &value, encoding, dst);
}

proto_item *
proto_tree_add_int_bits_format_value(proto_tree *tree, const int hfindex,
				     tvbuff_t *tvb, const guint bit_offset,
				     const gint no_of_bits, gint32 value,
	                             const guint encoding,
				     const char *format, ...)
{
	va_list ap;
	gchar  *dst;
	header_field_info *hf_field;

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hf_field);

	switch (hf_field->type) {
		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
			break;

		default:
			REPORT_DISSECTOR_BUG("field %s is not of type FT_INT8, FT_INT16, FT_INT24, or FT_INT32",
			    hf_field->abbrev);
			return NULL;
			break;
	}

	CREATE_VALUE_STRING(tree, dst, format, ap);

	return proto_tree_add_bits_format_value(tree, hfindex, tvb, bit_offset, no_of_bits, &value, encoding, dst);
}

proto_item *
proto_tree_add_int64_bits_format_value(proto_tree *tree, const int hfindex,
				     tvbuff_t *tvb, const guint bit_offset,
				     const gint no_of_bits, gint64 value,
				     const guint encoding,
				     const char *format, ...)
{
	va_list ap;
	gchar  *dst;
	header_field_info *hf_field;

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hf_field);

	switch (hf_field->type) {
		case FT_INT40:
		case FT_INT48:
		case FT_INT56:
		case FT_INT64:
			break;

		default:
			REPORT_DISSECTOR_BUG("field %s is not of type FT_INT40, FT_INT48, FT_INT56, or FT_INT64",
			    hf_field->abbrev);
			return NULL;
			break;
	}

	CREATE_VALUE_STRING(tree, dst, format, ap);

	return proto_tree_add_bits_format_value(tree, hfindex, tvb, bit_offset, no_of_bits, &value, encoding, dst);
}

proto_item *
proto_tree_add_boolean_bits_format_value(proto_tree *tree, const int hfindex,
					 tvbuff_t *tvb, const guint bit_offset,
					 const gint no_of_bits, guint32 value,
				         const guint encoding,
					 const char *format, ...)
{
	va_list ap;
	gchar  *dst;
	header_field_info *hf_field;

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hf_field);

	DISSECTOR_ASSERT_FIELD_TYPE(hf_field, FT_BOOLEAN);

	CREATE_VALUE_STRING(tree, dst, format, ap);

	return proto_tree_add_bits_format_value(tree, hfindex, tvb, bit_offset, no_of_bits, &value, encoding, dst);
}

proto_item *
proto_tree_add_boolean_bits_format_value64(proto_tree *tree, const int hfindex,
					 tvbuff_t *tvb, const guint bit_offset,
					 const gint no_of_bits, guint64 value,
				         const guint encoding,
					 const char *format, ...)
{
	va_list ap;
	gchar  *dst;
	header_field_info *hf_field;

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hf_field);

	DISSECTOR_ASSERT_FIELD_TYPE(hf_field, FT_BOOLEAN);

	CREATE_VALUE_STRING(tree, dst, format, ap);

	return proto_tree_add_bits_format_value(tree, hfindex, tvb, bit_offset, no_of_bits, &value, encoding, dst);
}

proto_item *
proto_tree_add_ts_23_038_7bits_packed_item(proto_tree *tree, const int hfindex, tvbuff_t *tvb,
	const guint bit_offset, const gint no_of_chars)
{
	proto_item	  *pi;
	header_field_info *hfinfo;
	gint		   byte_length;
	gint		   byte_offset;
	gchar		  *string;

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT_FIELD_TYPE(hfinfo, FT_STRING);

	byte_length = (((no_of_chars + 1) * 7) + (bit_offset & 0x07)) >> 3;
	byte_offset = bit_offset >> 3;

	string = tvb_get_ts_23_038_7bits_string_packed(PNODE_POOL(tree), tvb, bit_offset, no_of_chars);

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

	CHECK_FOR_NULL_TREE(tree);

	TRY_TO_FAKE_THIS_ITEM(tree, hfindex, hfinfo);

	DISSECTOR_ASSERT_FIELD_TYPE(hfinfo, FT_STRING);

	byte_length = (((no_of_chars + 1) * 7) + (bit_offset & 0x07)) >> 3;
	byte_offset = bit_offset >> 3;

	string = tvb_get_ascii_7bits_string(PNODE_POOL(tree), tvb, bit_offset, no_of_chars);

	pi = proto_tree_add_pi(tree, hfinfo, tvb, byte_offset, &byte_length);
	DISSECTOR_ASSERT(byte_length >= 0);
	proto_tree_set_string(PNODE_FINFO(pi), string);

	return pi;
}

const value_string proto_checksum_vals[] = {
	{ PROTO_CHECKSUM_E_BAD,        "Bad"  },
	{ PROTO_CHECKSUM_E_GOOD,       "Good" },
	{ PROTO_CHECKSUM_E_UNVERIFIED, "Unverified" },
	{ PROTO_CHECKSUM_E_NOT_PRESENT, "Not present" },
	{ PROTO_CHECKSUM_E_ILLEGAL,    "Illegal" },

	{ 0,        NULL }
};

proto_item *
proto_tree_add_checksum(proto_tree *tree, tvbuff_t *tvb, const guint offset,
		const int hf_checksum, const int hf_checksum_status, struct expert_field* bad_checksum_expert,
		packet_info *pinfo, guint32 computed_checksum, const guint encoding, const guint flags)
{
	header_field_info *hfinfo;
	guint32 checksum;
	guint32 len;
	proto_item* ti = NULL;
	proto_item* ti2;
	gboolean incorrect_checksum = TRUE;

	PROTO_REGISTRAR_GET_NTH(hf_checksum, hfinfo);

	switch (hfinfo->type) {
	case FT_UINT8:
		len = 1;
		break;
	case FT_UINT16:
		len = 2;
		break;
	case FT_UINT24:
		len = 3;
		break;
	case FT_UINT32:
		len = 4;
		break;
	default:
		REPORT_DISSECTOR_BUG("field %s is not of type FT_UINT8, FT_UINT16, FT_UINT24, or FT_UINT32",
		    hfinfo->abbrev);
	}

	if (flags & PROTO_CHECKSUM_NOT_PRESENT) {
		ti = proto_tree_add_uint_format_value(tree, hf_checksum, tvb, offset, len, 0, "[missing]");
		proto_item_set_generated(ti);
		if (hf_checksum_status != -1) {
			ti2 = proto_tree_add_uint(tree, hf_checksum_status, tvb, offset, len, PROTO_CHECKSUM_E_NOT_PRESENT);
			proto_item_set_generated(ti2);
		}
		return ti;
	}

	if (flags & PROTO_CHECKSUM_GENERATED) {
		ti = proto_tree_add_uint(tree, hf_checksum, tvb, offset, len, computed_checksum);
		proto_item_set_generated(ti);
	} else {
		ti = proto_tree_add_item_ret_uint(tree, hf_checksum, tvb, offset, len, encoding, &checksum);
		if (flags & PROTO_CHECKSUM_VERIFY) {
			if (flags & (PROTO_CHECKSUM_IN_CKSUM|PROTO_CHECKSUM_ZERO)) {
				if (computed_checksum == 0) {
					proto_item_append_text(ti, " [correct]");
					if (hf_checksum_status != -1) {
						ti2 = proto_tree_add_uint(tree, hf_checksum_status, tvb, offset, 0, PROTO_CHECKSUM_E_GOOD);
						proto_item_set_generated(ti2);
					}
					incorrect_checksum = FALSE;
				} else if (flags & PROTO_CHECKSUM_IN_CKSUM) {
					computed_checksum = in_cksum_shouldbe(checksum, computed_checksum);
				}
			} else {
				if (checksum == computed_checksum) {
					proto_item_append_text(ti, " [correct]");
					if (hf_checksum_status != -1) {
						ti2 = proto_tree_add_uint(tree, hf_checksum_status, tvb, offset, 0, PROTO_CHECKSUM_E_GOOD);
						proto_item_set_generated(ti2);
					}
					incorrect_checksum = FALSE;
				}
			}

			if (incorrect_checksum) {
				if (hf_checksum_status != -1) {
					ti2 = proto_tree_add_uint(tree, hf_checksum_status, tvb, offset, 0, PROTO_CHECKSUM_E_BAD);
					proto_item_set_generated(ti2);
				}
				if (flags & PROTO_CHECKSUM_ZERO) {
					proto_item_append_text(ti, " [incorrect]");
					if (bad_checksum_expert != NULL)
						expert_add_info_format(pinfo, ti, bad_checksum_expert, "%s", expert_get_summary(bad_checksum_expert));
				} else {
					proto_item_append_text(ti, " incorrect, should be 0x%0*x", len*2, computed_checksum);
					if (bad_checksum_expert != NULL)
						expert_add_info_format(pinfo, ti, bad_checksum_expert, "%s [should be 0x%0*x]", expert_get_summary(bad_checksum_expert), len * 2, computed_checksum);
				}
			}
		} else {
			if (hf_checksum_status != -1) {
				proto_item_append_text(ti, " [unverified]");
				ti2 = proto_tree_add_uint(tree, hf_checksum_status, tvb, offset, 0, PROTO_CHECKSUM_E_UNVERIFIED);
				proto_item_set_generated(ti2);
			}
		}
	}

	return ti;
}

guchar
proto_check_field_name(const gchar *field_name)
{
	return module_check_valid_name(field_name, FALSE);
}

guchar
proto_check_field_name_lower(const gchar *field_name)
{
	return module_check_valid_name(field_name, TRUE);
}

gboolean
tree_expanded(int tree_type)
{
	if (tree_type == -1) {
		return FALSE;
	}
	ws_assert(tree_type >= 0 && tree_type < num_tree_types);
	return tree_is_expanded[tree_type >> 5] & (1U << (tree_type & 31));
}

void
tree_expanded_set(int tree_type, gboolean value)
{
	ws_assert(tree_type >= 0 && tree_type < num_tree_types);

	if (value)
		tree_is_expanded[tree_type >> 5] |= (1U << (tree_type & 31));
	else
		tree_is_expanded[tree_type >> 5] &= ~(1U << (tree_type & 31));
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
