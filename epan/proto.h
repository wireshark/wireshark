/* proto.h
 * Definitions for protocol display
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


/*! @file proto.h
    The protocol tree related functions.<BR>
    A protocol tree will hold all necessary data to display the whole dissected packet.
    Creating a protocol tree is done in a two stage process:
    A static part at program startup, and a dynamic part when the dissection with the real packet data is done.<BR>
    The "static" information is provided by creating a hf_register_info hf[] array, and register it using the
    proto_register_field_array() function. This is usually done at dissector registering.<BR>
    The "dynamic" information is added to the protocol tree by calling one of the proto_tree_add_...() functions,
    e.g. proto_tree_add_bytes().
*/

#ifndef __PROTO_H__
#define __PROTO_H__

#ifdef HAVE_STDARG_H
# include <stdarg.h>
#else
# include <varargs.h>
#endif

#include <glib.h>

#include "ipv4.h"
#include "nstime.h"
#include "time_fmt.h"
#include "tvbuff.h"
#include "ftypes/ftypes.h"
#include "register.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** The header-field index for the special text pseudo-field. Exported by libwireshark.dll */
WS_VAR_IMPORT int hf_text_only;

/** the maximum length of a protocol field string representation */
#define ITEM_LABEL_LENGTH	240

struct _value_string;

/** Make a const value_string[] look like a _value_string pointer, used to set header_field_info.strings */
#define VALS(x)	(const struct _value_string*)(x)

/** Make a const true_false_string[] look like a _true_false_string pointer, used to set header_field_info.strings */
#define TFS(x)	(const struct true_false_string*)(x)

typedef void (*custom_fmt_func_t)(gchar *, guint32);

/** Make a const range_string[] look like a _range_string pointer, used to set
 * header_field_info.strings */
#define RVALS(x) (const struct _range_string*)(x)

struct _protocol;

/** Structure for information about a protocol */
typedef struct _protocol protocol_t;

/** check protocol activation
 * @todo this macro looks like a hack */
#define CHECK_DISPLAY_AS_X(x_handle,index, tvb, pinfo, tree) {	\
	if (!proto_is_protocol_enabled(find_protocol_by_id(index))) {	\
		call_dissector(x_handle,tvb, pinfo, tree);		\
		return;							\
	}								\
  }

/** Macro used for reporting errors in dissectors; it throws a
 * DissectorError exception, with the string passed as an argument
 * as the message for the exception, so that it can show up in
 * the Info column and the protocol tree.
 *
 * If that string is dynamically allocated, it should be allocated with
 * ep_alloc(); using ep_strdup_printf() would work.
 *
 * If the WIRESHARK_ABORT_ON_DISSECTOR_BUG environment variable is set,
 * it will call abort(), instead, to make it easier to get a stack trace.
 *
 * @param message string to use as the message
 */
#define REPORT_DISSECTOR_BUG(message)  \
  ((getenv("WIRESHARK_ABORT_ON_DISSECTOR_BUG") != NULL) ? \
    abort() : \
    THROW_MESSAGE(DissectorError, message))

/** Macro used to provide a hint to static analysis tools.
 * (Currently only Visual C++.)
 */
#if _MSC_VER >= 1400
/* XXX - Is there a way to say "quit checking at this point"? */
#define __DISSECTOR_ASSERT_STATIC_ANALYSIS_HINT(expression) \
  ; __analysis_assume(expression);
#else
#define __DISSECTOR_ASSERT_STATIC_ANALYSIS_HINT(expression)
#endif

/** Macro used for assertions in dissectors; it doesn't abort, it just
 * throws a DissectorError exception, with the assertion failure
 * message as a parameter, so that it can show up in the protocol tree.
 *
 * NOTE: this should only be used to detect bugs in the dissector (e.g., logic
 * conditions that shouldn't happen).  It should NOT be used for showing
 * that a packet is malformed.  For that, use expert_infos instead.
 *
 * @param expression expression to test in the assertion
 */

#define DISSECTOR_ASSERT(expression)  \
  ((void) ((expression) ? (void)0 : \
   __DISSECTOR_ASSERT (expression, __FILE__, __LINE__))) \
   __DISSECTOR_ASSERT_STATIC_ANALYSIS_HINT(expression)

#if 0
/* win32: using a debug breakpoint (int 3) can be very handy while debugging,
 * as the assert handling of GTK/GLib is currently not very helpful */
#define DISSECTOR_ASSERT(expression)  \
{ if(!(expression)) _asm { int 3}; }
#endif

/** Same as DISSECTOR_ASSERT(), but will throw DissectorError exception
 * unconditionally, much like GLIB's g_assert_not_reached works.
 *
 * NOTE: this should only be used to detect bugs in the dissector (e.g., logic
 * conditions that shouldn't happen).  It should NOT be used for showing
 * that a packet is malformed.  For that, use expert_infos instead.
 *
 */
#define DISSECTOR_ASSERT_NOT_REACHED()  \
  (REPORT_DISSECTOR_BUG( \
    ep_strdup_printf("%s:%u: failed assertion \"DISSECTOR_ASSERT_NOT_REACHED\"", \
     __FILE__, __LINE__)))

#define __DISSECTOR_ASSERT_STRINGIFY(s)	# s

#define __DISSECTOR_ASSERT(expression, file, lineno)  \
  (REPORT_DISSECTOR_BUG( \
    ep_strdup_printf("%s:%u: failed assertion \"%s\"", \
     file, lineno, __DISSECTOR_ASSERT_STRINGIFY(expression))))

/*
 * The encoding of a field of a particular type may involve more
 * than just whether it's big-endian or little-endian and its size.
 *
 * For integral values, that's it, as 99.9999999999999% of the machines
 * out there are 2's complement binary machines with 8-bit bytes,
 * so the protocols out there expect that and, for example, any Unisys
 * 2200 series machines out there just have to translate between 2's
 * complement and 1's complement (and nobody's put any IBM 709x's on
 * any networks lately :-)).
 *
 * However:
 *
 *	for floating-point numbers, in addition to IEEE decimal
 *	floating-point, there's also IBM System/3x0 and PDP-11/VAX
 *	floating-point - most protocols use IEEE binary, but DCE RPC
 *	can use other formats if that's what the sending host uses;
 *
 *	for character strings, there are various character encodings
 *	(various ISO 646 sets, ISO 8859/x, various other national
 *	standards, various DOS and Windows encodings, various Mac
 *	encodings, UTF-8, UTF-16, other extensions to ASCII, EBCDIC,
 *	etc.);
 *
 *	for absolute times, there's UNIX time_t, UNIX time_t followed
 *	by 32-bit microseconds, UNIX time_t followed by 32-bit
 *	nanoseconds, DOS date/time, Windows FILETIME, NTP time, etc..
 *
 * We might also, in the future, want to allow a field specifier to
 * indicate the encoding of the field, or at least its default
 * encoding, as most fields in most protocols always use the
 * same encoding (although that's not true of all fields, so we
 * still need to be able to specify that at run time).
 *
 * So, for now, we define ENC_BIG_ENDIAN and ENC_LITTLE_ENDIAN as
 * bit flags, to be combined, in the future, with other information
 * to specify the encoding in the last argument to
 * proto_tree_add_item(), and possibly to specify in a field
 * definition (e.g., ORed in with the type value).
 *
 * Currently, proto_tree_add_item() treats its last argument as a
 * Boolean - if it's zero, the field is big-endian, and if it's non-zero,
 * the field is little-endian - and other code in epan/proto.c does
 * the same.  We therefore define ENC_BIG_ENDIAN as 0x00000000 and
 * ENC_LITTLE_ENDIAN as 0x80000000 - we're using the high-order bit
 * so that we could put a field type and/or a value such as a character
 * encoding in the lower bits.
 *
 * For protocols (FT_PROTOCOL), aggregate items with subtrees (FT_NONE),
 * opaque byte-array fields (FT_BYTES), and other fields where there
 * is no choice of encoding (either because it's "just a bucket
 * of bytes" or because the encoding is completely fixed), we
 * have ENC_NA (for "Not Applicable").
 */
#define ENC_BIG_ENDIAN		0x00000000
#define ENC_LITTLE_ENDIAN	0x80000000

/*
 * Historically FT_TIMEs were only timespecs; the only question was whether
 * they were stored in big- or little-endian format.
 *
 * For backwards compatibility, we interpret an encoding of 1 as meaning
 * "little-endian timespec", so that passing TRUE is interpreted as that.
 */
#define ENC_TIME_TIMESPEC	0
#define ENC_TIME_NTP		2

#define ENC_NA			0x00000000

/* Values for header_field_info.display */

/* For integral types, the display format is a base_display_e value
 * possibly ORed with BASE_RANGE_STRING. */

/** BASE_DISPLAY_E_MASK selects the base_display_e value.  Its current
 * value means that we may have at most 16 base_display_e values. */
#define BASE_DISPLAY_E_MASK 0x0F

typedef enum {
	BASE_NONE,	/**< none */
	BASE_DEC,	/**< decimal */
	BASE_HEX,	/**< hexadecimal */
	BASE_OCT,	/**< octal */
	BASE_DEC_HEX,	/**< decimal (hexadecimal) */
	BASE_HEX_DEC,	/**< hexadecimal (decimal) */
	BASE_CUSTOM	/**< call custom routine (in ->strings) to format */
} base_display_e;

/* Following constants have to be ORed with a base_display_e when dissector
 * want to use specials MACROs (for the moment, only RVALS) for a
 * header_field_info */
#define BASE_RANGE_STRING 0x10
#define BASE_EXT_STRING 0x20

/** BASE_ values that cause the field value to be displayed twice */
#define IS_BASE_DUAL(b) ((b)==BASE_DEC_HEX||(b)==BASE_HEX_DEC)

/* For FT_ABSOLUTE_TIME, the display format is an absolute_time_display_e
 * as per time_fmt.h. */

typedef enum {
    HF_REF_TYPE_NONE,       /**< Field is not referenced */
    HF_REF_TYPE_INDIRECT,   /**< Field is indirectly referenced (only applicable for FT_PROTOCOL) via. its child */
    HF_REF_TYPE_DIRECT      /**< Field is directly referenced */
} hf_ref_type;

/** information describing a header field */
typedef struct _header_field_info header_field_info;

/** information describing a header field */
struct _header_field_info {
	/* ---------- set by dissector --------- */
	const char		*name;           /**< full name of this field */
	const char		*abbrev;         /**< abbreviated name of this field */
	enum ftenum		 type;           /**< field type, one of FT_ (from ftypes.h) */
	int				 display;        /**< one of BASE_, or field bit-width if FT_BOOLEAN and non-zero bitmask */
	const void		*strings;        /**< value_string, range_string or true_false_string,
				                      typically converted by VALS(), RVALS() or TFS().
				                      If this is an FT_PROTOCOL then it points to the
				                      associated protocol_t structure */
	guint32			 bitmask;        /**< bitmask of interesting bits */
	const char		*blurb;          /**< Brief description of field */

	/* ------- set by proto routines (prefilled by HFILL macro, see below) ------ */
	int					 id;             /**< Field ID */
	int					 parent;         /**< parent protocol tree */
	hf_ref_type			 ref_type;       /**< is this field referenced by a filter */
	int					 bitshift;       /**< bits to shift */
	header_field_info	*same_name_next; /**< Link to next hfinfo with same abbrev */
	header_field_info	*same_name_prev; /**< Link to previous hfinfo with same abbrev */
};

/**
 * HFILL initializes all the "set by proto routines" fields in a
 * _header_field_info. If new fields are added or removed, it should
 * be changed as necessary.
 */
#define HFILL 0, 0, HF_REF_TYPE_NONE, 0, NULL, NULL

/** Used when registering many fields at once, using proto_register_field_array() */
typedef struct hf_register_info {
	int						*p_id;		 /**< written to by register() function */
	header_field_info		hfinfo;      /**< the field info to be registered */
} hf_register_info;




/** string representation, if one of the proto_tree_add_..._format() functions used */
typedef struct _item_label_t {
	char representation[ITEM_LABEL_LENGTH];
} item_label_t;


/** Contains the field information for the proto_item. */
typedef struct field_info {
	header_field_info	*hfinfo;          /**< pointer to registered field information */
	gint				 start;           /**< current start of data in field_info.ds_tvb */
	gint				 length;          /**< current data length of item in field_info.ds_tvb */
	gint				 appendix_start;  /**< start of appendix data */
	gint				 appendix_length; /**< length of appendix data */
	gint				 tree_type;       /**< one of ETT_ or -1 */
	item_label_t		*rep;             /**< string for GUI tree */
	guint32				 flags;           /**< bitfield like FI_GENERATED, ... */
	tvbuff_t			*ds_tvb;          /**< data source tvbuff */
	fvalue_t			 value;
} field_info;


/*
 * Flag fields.  Do not assign values greater than 0x00000080 unless you
 * shuffle the expert information upward; see below.
 */

/** The protocol field should not be shown in the tree (it's used for filtering only),
 * used in field_info.flags. */
/** HIDING PROTOCOL FIELDS IS DEPRECATED, IT'S CONSIDERED TO BE BAD GUI DESIGN!
   A user cannot tell by looking at the packet detail that the field exists
   and that they can filter on its value. */
#define FI_HIDDEN		0x00000001
/** The protocol field should be displayed as "generated by Wireshark",
 * used in field_info.flags. */
#define FI_GENERATED		0x00000002
/** The protocol field is actually a URL */
#define FI_URL                  0x00000004

/** The protocol field value is in little endian */
#define FI_LITTLE_ENDIAN        0x00000008
/** The protocol field value is in big endian */
#define FI_BIG_ENDIAN           0x00000010
/** Field value start from nth bit (values from 0x20 - 0x100) */
#define FI_BITS_OFFSET(n)        ((n & 7) << 5)
/** Field value takes n bits (values from 0x100 - 0x4000) */
/* if 0, it means that field takes fi->length * 8 */
#define FI_BITS_SIZE(n)         ((n & 63) << 8)

/** convenience macro to get field_info.flags */
#define FI_GET_FLAG(fi, flag) ((fi) ? (fi->flags & flag) : 0)
/** convenience macro to set field_info.flags */
#define FI_SET_FLAG(fi, flag) \
    do { \
      if (fi) \
        (fi)->flags = (fi)->flags | (flag); \
    } while(0)

#define FI_GET_BITS_OFFSET(fi) (FI_GET_FLAG(fi, FI_BITS_OFFSET(7)) >> 5)
#define FI_GET_BITS_SIZE(fi)   (FI_GET_FLAG(fi, FI_BITS_SIZE(63)) >> 8)

/** One of these exists for the entire protocol tree. Each proto_node
 * in the protocol tree points to the same copy. */
typedef struct {
    GHashTable  *interesting_hfids;
    gboolean    visible;
    gboolean    fake_protocols;
    gint        count;
} tree_data_t;

/** Each proto_tree, proto_item is one of these. */
typedef struct _proto_node {
	struct _proto_node *first_child;
	struct _proto_node *last_child;
	struct _proto_node *next;
	struct _proto_node *parent;
	field_info  *finfo;
	tree_data_t *tree_data;
} proto_node;

/** A protocol tree element. */
typedef proto_node proto_tree;
/** A protocol item element. */
typedef proto_node proto_item;

/*
 * Expert information.
 * This is in the flags field; we allocate this from the top down,
 * so as not to collide with FI_ flags, which are allocated from
 * the bottom up.
 */

/* expert severities */
#define PI_SEVERITY_MASK	0x00F00000	/**< mask usually for internal use only! */
/** Usual workflow, e.g. TCP connection establishing */
#define PI_CHAT			0x00200000
/** Notable messages, e.g. an application returned an "usual" error code like HTTP 404 */
#define PI_NOTE			0x00400000
/** Warning, e.g. application returned an "unusual" error code */
#define PI_WARN			0x00600000
/** Serious problems, e.g. [Malformed Packet] */
#define PI_ERROR		0x00800000

/* expert "event groups" */
#define PI_GROUP_MASK		0xFF000000	/**< mask usually for internal use only! */
/** The protocol field has a bad checksum, usually PI_WARN */

#define PI_CHECKSUM		0x01000000
/** The protocol field indicates a sequence problem (e.g. TCP window is zero) */
#define PI_SEQUENCE		0x02000000
/** The protocol field indicates a bad application response code (e.g. HTTP 404), usually PI_NOTE */
#define PI_RESPONSE_CODE	0x03000000
/** The protocol field indicates an application request (e.g. File Handle == xxxx), usually PI_CHAT */
#define PI_REQUEST_CODE		0x04000000
/** The data is undecoded, the protocol dissection is incomplete here, usually PI_WARN */
#define PI_UNDECODED		0x05000000
/** The protocol field indicates a reassemble (e.g. DCE/RPC defragmentation), usually PI_CHAT (or PI_ERROR) */
#define PI_REASSEMBLE		0x06000000
/** The packet data is malformed, the dissector has "given up", usually PI_ERROR */
#define PI_MALFORMED		0x07000000
/** A generic debugging message (shouldn't remain in production code!), usually PI_ERROR */
#define PI_DEBUG		0x08000000
/** The protocol field violates a protocol specification, usually PI_WARN */
#define PI_PROTOCOL             0x09000000
/* The protocol field indicates a security probem (e.g. unsecure implementation) */
#define PI_SECURITY		0x0a000000

/* add more, see http://wiki.wireshark.org/Development/ExpertInfo */


/** is this protocol field hidden from the protocol tree display (used for filtering only)? */
/* HIDING PROTOCOL FIELDS IS DEPRECATED, IT'S CONSIDERED TO BE BAD GUI DESIGN! */
#define PROTO_ITEM_IS_HIDDEN(proto_item)        \
	((proto_item) ? FI_GET_FLAG(PITEM_FINFO(proto_item), FI_HIDDEN) : 0)
/** mark this protocol field to be hidden from the protocol tree display (used for filtering only) */
/* HIDING PROTOCOL FIELDS IS DEPRECATED, IT'S CONSIDERED TO BE BAD GUI DESIGN! */
#define PROTO_ITEM_SET_HIDDEN(proto_item)       \
  do { \
    if (proto_item) \
      FI_SET_FLAG(PITEM_FINFO(proto_item), FI_HIDDEN); \
	} while(0)
/** is this protocol field generated by Wireshark (and not read from the packet data)? */
#define PROTO_ITEM_IS_GENERATED(proto_item)	\
	((proto_item) ? FI_GET_FLAG(PITEM_FINFO(proto_item), FI_GENERATED) : 0)
/** mark this protocol field as generated by Wireshark (and not read from the packet data) */
#define PROTO_ITEM_SET_GENERATED(proto_item)	\
    do { \
      if (proto_item) \
        FI_SET_FLAG(PITEM_FINFO(proto_item), FI_GENERATED); \
    } while(0)
/** is this protocol field actually a URL? */
#define PROTO_ITEM_IS_URL(proto_item)	\
	((proto_item) ? FI_GET_FLAG(PITEM_FINFO(proto_item), FI_URL) : 0)
/** mark this protocol field as a URL */
#define PROTO_ITEM_SET_URL(proto_item)	\
    do { \
      if (proto_item) \
        FI_SET_FLAG(PITEM_FINFO(proto_item), FI_URL); \
    } while(0)

typedef void (*proto_tree_foreach_func)(proto_node *, gpointer);
typedef gboolean (*proto_tree_traverse_func)(proto_node *, gpointer);

extern gboolean proto_tree_traverse_post_order(proto_tree *tree,
    proto_tree_traverse_func func, gpointer data);

extern void proto_tree_children_foreach(proto_tree *tree,
    proto_tree_foreach_func func, gpointer data);

/** Retrieve the field_info from a proto_node */
#define PNODE_FINFO(proto_node)  ((proto_node)->finfo)

/** Retrieve the field_info from a proto_item */
#define PITEM_FINFO(proto_item)  PNODE_FINFO(proto_item)

/** Retrieve the field_info from a proto_tree */
#define PTREE_FINFO(proto_tree)  PNODE_FINFO(proto_tree)

/** Retrieve the tree_data_t from a proto_tree */
#define PTREE_DATA(proto_tree)   ((proto_tree)->tree_data)

/** Sets up memory used by proto routines. Called at program startup */
extern void proto_init(void (register_all_protocols_func)(register_cb cb, gpointer client_data),
		       void (register_all_handoffs_func)(register_cb cb, gpointer client_data),
		       register_cb cb, void *client_data);


/** Frees memory used by proto routines. Called at program shutdown */
extern void proto_cleanup(void);

/** This function takes a tree and a protocol id as parameter and
    will return TRUE/FALSE for whether the protocol or any of the filterable
    fields in the protocol is referenced by any fitlers.
    If this function returns FALSE then it is safe to skip any
    proto_tree_add_...() calls and just treat the call as if the
    dissector was called with tree==NULL.
    If you reset the tree to NULL by this dissector returning FALSE,
    you will still need to call any subdissector with the original value of
    tree or filtering will break.

    The purpose of this is to optimize wireshark for speed and make it
    faster for when filters are being used.
*/
extern gboolean proto_field_is_referenced(proto_tree *tree, int proto_id);

/* XXX where should this go? */
#ifdef __GNUC__
#define WARN_IF_UNUSED __attribute__ ((warn_unused_result))
#else
#define WARN_IF_UNUSED
#endif

/** Create a subtree under an existing item.
 @param ti the parent item of the new subtree
 @param idx one of the ett_ array elements registered with proto_register_subtree_array()
 @return the new subtree */
extern proto_tree* proto_item_add_subtree(proto_item *ti, const gint idx) WARN_IF_UNUSED;

/** Get an existing subtree under an item.
 @param ti the parent item of the subtree
 @return the subtree or NULL */
extern proto_tree* proto_item_get_subtree(const proto_item *ti);

/** Get the parent of a subtree item.
 @param ti the child item in the subtree
 @return parent item or NULL */
extern proto_item* proto_item_get_parent(const proto_item *ti);

/** Get Nth generation parent item.
 @param ti the child item in the subtree
 @param gen the generation to get (using 1 here is the same as using proto_item_get_parent())
 @return parent item */
extern proto_item* proto_item_get_parent_nth(proto_item *ti, int gen);

/** Replace text of item after it already has been created.
 @param ti the item to set the text
 @param format printf like format string
 @param ... printf like parameters */
extern void proto_item_set_text(proto_item *ti, const char *format, ...)
	G_GNUC_PRINTF(2,3);

/** Append to text of item after it has already been created.
 @param ti the item to append the text to
 @param format printf like format string
 @param ... printf like parameters */
extern void proto_item_append_text(proto_item *ti, const char *format, ...)
	G_GNUC_PRINTF(2,3);

/** Prepend to text of item after it has already been created.
 @param ti the item to prepend the text to
 @param format printf like format string
 @param ... printf like parameters */
extern void proto_item_prepend_text(proto_item *ti, const char *format, ...)
	G_GNUC_PRINTF(2,3);

/** Set proto_item's length inside tvb, after it has already been created.
 @param ti the item to set the length
 @param length the new length ot the item */
extern void proto_item_set_len(proto_item *ti, const gint length);

/**
 * Sets the length of the item based on its start and on the specified
 * offset, which is the offset past the end of the item; as the start
 * in the item is relative to the beginning of the data source tvbuff,
 * we need to pass in a tvbuff.
 @param ti the item to set the length
 @param tvb end is relative to this tvbuff
 @param end this end offset is relative to the beginning of tvb
 @todo make usage clearer, I don't understand it!
 */
extern void proto_item_set_end(proto_item *ti, tvbuff_t *tvb, gint end);

/** Get length of a proto_item. Useful after using proto_tree_add_item()
 * to add a variable-length field (e.g., FT_NSTRING_UINT8).
 @param ti the item to get the length from
 @return the current length */
extern int proto_item_get_len(const proto_item *ti);

/**
 * Sets an expert info to the proto_item.
 @param ti the item to set the expert info
 @param group the group of this info (e.g. PI_CHECKSUM)
 @param severity of this info (e.g. PI_ERROR)
 @return TRUE if value was written
 */
extern gboolean proto_item_set_expert_flags(proto_item *ti, const int group, const guint severity);




/** Creates a new proto_tree root.
 @return the new tree root */
extern proto_tree* proto_tree_create_root(void);

/** Clear memory for entry proto_tree. Clears proto_tree struct also.
 @param tree the tree to free */
extern void proto_tree_free(proto_tree *tree);

/** Set the tree visible or invisible.
 Is the parsing being done for a visible proto_tree or an invisible one?
 By setting this correctly, the proto_tree creation is sped up by not
 having to call g_vsnprintf and copy strings around.
 @param tree the tree to be set
 @param visible ... or not
 @return the old value */
extern gboolean
proto_tree_set_visible(proto_tree *tree, gboolean visible);

/** Indicate whether we should fake protocols during dissection (default = TRUE)
 @param tree the tree to be set
 @param fake_protocols TRUE if we should fake protocols */
extern void
proto_tree_set_fake_protocols(proto_tree *tree, gboolean fake_protocols);

/** Mark a field/protocol ID as "interesting".
 @param tree the tree to be set
 @param hfid the interesting field id
 @todo what *does* interesting mean? */
extern void
proto_tree_prime_hfid(proto_tree *tree, const int hfid);

/** Get a parent item of a subtree.
 @param tree the tree to get the parent from
 @return parent item */
extern proto_item* proto_tree_get_parent(const proto_tree *tree);

/** Get the root tree from any subtree.
 @param tree the tree to get the root from
 @return root tree */
extern proto_tree* proto_tree_get_root(proto_tree *tree);

/** Move an existing item behind another existing item.
 @param tree the tree to which both items belong
 @param fixed_item the item which keeps it's position
 @param item_to_move the item which will be moved */
extern void proto_tree_move_item(proto_tree *tree, proto_item *fixed_item, proto_item *item_to_move);


/** Set start and length of an appendix for a proto_tree.
  @param tree the tree to set the appendix start and length
  @param tvb the tv buffer of the current data
  @param start the start offset of the appendix
  @param length the length of the appendix */
extern void proto_tree_set_appendix(proto_tree *tree, tvbuff_t *tvb, gint start, const gint length);


/** Add an item to a proto_tree, using the text label registered to that item.
   The item is extracted from the tvbuff handed to it.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param encoding data encoding
 @return the newly created item */
extern proto_item *
proto_tree_add_item(proto_tree *tree, const int hfindex, tvbuff_t *tvb,
    const gint start, gint length, const guint encoding);

/** Add a text-only node to a proto_tree.
 @param tree the tree to append this item to
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_text(proto_tree *tree, tvbuff_t *tvb, gint start, gint length, const char *format,
	...) G_GNUC_PRINTF(5,6);

/** Add a text-only node to a proto_tree using a variable argument list.
 @param tree the tree to append this item to
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param format printf like format string
 @param ap variable argument list
 @return the newly created item */
extern proto_item *
proto_tree_add_text_valist(proto_tree *tree, tvbuff_t *tvb, gint start,
	gint length, const char *format, va_list ap);


/** Add a FT_NONE field to a proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_none_format(proto_tree *tree, const int hfindex, tvbuff_t *tvb, const gint start,
	gint length, const char *format, ...) G_GNUC_PRINTF(6,7);

/** Add a FT_PROTOCOL to a proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_protocol_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, const char *format, ...) G_GNUC_PRINTF(6,7);




/** Add a FT_BYTES to a proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param start_ptr pointer to the data to display
 @return the newly created item */
extern proto_item *
proto_tree_add_bytes(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, const guint8* start_ptr);

/** Add a formatted FT_BYTES to a proto_tree, with the format generating
    the string for the value and with the field name being included
    automatically.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param start_ptr pointer to the data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_bytes_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
	gint start, gint length, const guint8* start_ptr, const char *format,
	...) G_GNUC_PRINTF(7,8);

/** Add a formatted FT_BYTES to a proto_tree, with the format generating
    the entire string for the entry, including any field name.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param start_ptr pointer to the data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_bytes_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, const guint8* start_ptr, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Add a FT_ABSOLUTE_TIME or FT_RELATIVE_TIME to a proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value_ptr pointer to the data to display
 @return the newly created item */
extern proto_item *
proto_tree_add_time(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, nstime_t* value_ptr);

/** Add a formatted FT_ABSOLUTE_TIME or FT_RELATIVE_TIME to a proto_tree, with
    the format generating the string for the value and with the field name
    being included automatically.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value_ptr pointer to the data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_time_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
	gint start, gint length, nstime_t* value_ptr, const char *format, ...)
	G_GNUC_PRINTF(7,8);

/** Add a formatted FT_ABSOLUTE_TIME or FT_RELATIVE_TIME to a proto_tree, with
    the format generating the entire string for the entry, including any field
    name.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value_ptr pointer to the data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_time_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, nstime_t* value_ptr, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Add a FT_IPXNET to a proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @return the newly created item */
extern proto_item *
proto_tree_add_ipxnet(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, guint32 value);

/** Add a formatted FT_IPXNET to a proto_tree, with the format generating
    the string for the value and with the field name being included
    automatically.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_ipxnet_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
	gint start, gint length, guint32 value, const char *format, ...)
	G_GNUC_PRINTF(7,8);

/** Add a formatted FT_IPXNET to a proto_tree, with the format generating
    the entire string for the entry, including any field name.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_ipxnet_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, guint32 value, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Add a FT_IPv4 to a proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @return the newly created item */
extern proto_item *
proto_tree_add_ipv4(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, guint32 value);

/** Add a formatted FT_IPv4 to a proto_tree, with the format generating
    the string for the value and with the field name being included
    automatically.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_ipv4_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
	gint start, gint length, guint32 value, const char *format, ...)
	G_GNUC_PRINTF(7,8);

/** Add a formatted FT_IPv4 to a proto_tree, with the format generating
    the entire string for the entry, including any field name.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_ipv4_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, guint32 value, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Add a FT_IPv6 to a proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value_ptr data to display
 @return the newly created item */
extern proto_item *
proto_tree_add_ipv6(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, const guint8* value_ptr);

/** Add a formatted FT_IPv6 to a proto_tree, with the format generating
    the string for the value and with the field name being included
    automatically.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value_ptr data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_ipv6_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
	gint start, gint length, const guint8* value_ptr, const char *format,
	...) G_GNUC_PRINTF(7,8);

/** Add a formatted FT_IPv6 to a proto_tree, with the format generating
    the entire string for the entry, including any field name.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value_ptr data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_ipv6_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, const guint8* value_ptr, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Add a FT_ETHER to a proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @return the newly created item */
extern proto_item *
proto_tree_add_ether(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, const guint8* value);

/** Add a formatted FT_ETHER to a proto_tree, with the format generating
    the string for the value and with the field name being included
    automatically.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_ether_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
	gint start, gint length, const guint8* value, const char *format, ...)
	G_GNUC_PRINTF(7,8);

/** Add a formatted FT_ETHER to a proto_tree, with the format generating
    the entire string for the entry, including any field name.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_ether_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, const guint8* value, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Add a FT_GUID to a proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value_ptr data to display
 @return the newly created item */
extern proto_item *
proto_tree_add_guid(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, const e_guid_t *value_ptr);

/** Add a formatted FT_GUID to a proto_tree, with the format generating
    the string for the value and with the field name being included
    automatically.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value_ptr data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_guid_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
	gint start, gint length, const e_guid_t *value_ptr, const char *format,
	...) G_GNUC_PRINTF(7,8);

/** Add a formatted FT_GUID to a proto_tree, with the format generating
    the entire string for the entry, including any field name.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value_ptr data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_guid_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, const e_guid_t *value_ptr, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Add a FT_OID to a proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value_ptr data to display
 @return the newly created item */
extern proto_item *
proto_tree_add_oid(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, const guint8* value_ptr);

/** Add a formatted FT_OID to a proto_tree, with the format generating
    the string for the value and with the field name being included
    automatically.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value_ptr data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_oid_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
	gint start, gint length, const guint8* value_ptr, const char *format,
	...) G_GNUC_PRINTF(7,8);

/** Add a formatted FT_OID to a proto_tree, with the format generating
    the entire string for the entry, including any field name.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value_ptr data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_oid_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, const guint8* value_ptr, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Add a FT_STRING to a proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @return the newly created item */
extern proto_item *
proto_tree_add_string(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, const char* value);

/** Add a formatted FT_STRING to a proto_tree, with the format generating
    the string for the value and with the field name being included
    automatically.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_string_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
	gint start, gint length, const char* value, const char *format, ...)
	G_GNUC_PRINTF(7,8);

/** Add a formatted FT_STRING to a proto_tree, with the format generating
    the entire string for the entry, including any field name.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_string_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, const char* value, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Add a FT_BOOLEAN to a proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @return the newly created item */
extern proto_item *
proto_tree_add_boolean(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, guint32 value);

/** Add a formatted FT_BOOLEAN to a proto_tree, with the format generating
    the string for the value and with the field name being included
    automatically.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_boolean_format_value(proto_tree *tree, int hfindex,
	tvbuff_t *tvb, gint start, gint length, guint32 value,
	const char *format, ...) G_GNUC_PRINTF(7,8);

/** Add a formatted FT_BOOLEAN to a proto_tree, with the format generating
    the entire string for the entry, including any field name.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_boolean_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, guint32 value, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Add a FT_FLOAT to a proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @return the newly created item */
extern proto_item *
proto_tree_add_float(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, float value);

/** Add a formatted FT_FLOAT to a proto_tree, with the format generating
    the string for the value and with the field name being included
    automatically.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_float_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
	gint start, gint length, float value, const char *format, ...)
	G_GNUC_PRINTF(7,8);

/** Add a formatted FT_FLOAT to a proto_tree, with the format generating
    the entire string for the entry, including any field name.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_float_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, float value, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Add a FT_DOUBLE to a proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @return the newly created item */
extern proto_item *
proto_tree_add_double(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, double value);

/** Add a formatted FT_DOUBLE to a proto_tree, with the format generating
    the string for the value and with the field name being included
    automatically.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_double_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
	gint start, gint length, double value, const char *format, ...)
	G_GNUC_PRINTF(7,8);

/** Add a formatted FT_DOUBLE to a proto_tree, with the format generating
    the entire string for the entry, including any field name.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_double_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, double value, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Add one of FT_UINT8, FT_UINT16, FT_UINT24 or FT_UINT32 to a proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @return the newly created item */
extern proto_item *
proto_tree_add_uint(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, guint32 value);

/** Add a formatted FT_UINT8, FT_UINT16, FT_UINT24 or FT_UINT32 to a proto_tree,
    with the format generating the string for the value and with the field
    name being included automatically.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_uint_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
	gint start, gint length, guint32 value, const char *format, ...)
	G_GNUC_PRINTF(7,8);

/** Add a formatted FT_UINT8, FT_UINT16, FT_UINT24 or FT_UINT32 to a proto_tree,
    with the format generating the entire string for the entry, including any
    field name.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_uint_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, guint32 value, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Add an FT_UINT64 to a proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @return the newly created item */
extern proto_item *
proto_tree_add_uint64(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, guint64 value);

/** Add a formatted FT_UINT64 to a proto_tree, with the format generating
    the string for the value and with the field name being included
    automatically.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_uint64_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
	gint start, gint length, guint64 value, const char *format, ...)
	G_GNUC_PRINTF(7,8);

/** Add a formatted FT_UINT64 to a proto_tree, with the format generating
    the entire string for the entry, including any field name.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_uint64_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, guint64 value, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Add one of FT_INT8, FT_INT16, FT_INT24 or FT_INT32 to a proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @return the newly created item */
extern proto_item *
proto_tree_add_int(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, gint32 value);

/** Add a formatted FT_INT8, FT_INT16, FT_INT24 or FT_INT32 to a proto_tree,
    with the format generating the string for the value and with the field
    name being included automatically.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_int_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
	gint start, gint length, gint32 value, const char *format, ...)
	G_GNUC_PRINTF(7,8);

/** Add a formatted FT_INT8, FT_INT16, FT_INT24 or FT_INT32 to a proto_tree,
    with the format generating the entire string for the entry, including
    any field name.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_int_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, gint32 value, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Add an FT_INT64 to a proto_tree.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @return the newly created item */
extern proto_item *
proto_tree_add_int64(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, gint64 value);

/** Add a formatted FT_INT64 to a proto_tree, with the format generating
    the string for the value and with the field name being included
    automatically.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_int64_format_value(proto_tree *tree, int hfindex, tvbuff_t *tvb,
	gint start, gint length, gint64 value, const char *format, ...)
	G_GNUC_PRINTF(7,8);

/** Add a formatted FT_INT64 to a proto_tree, with the format generating
    the entire string for the entry, including any field name.
 @param tree the tree to append this item to
 @param hfindex field index
 @param tvb the tv buffer of the current data
 @param start start of data in tvb
 @param length length of data in tvb
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_int64_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
	gint length, gint64 value, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Useful for quick debugging. Also sends string to STDOUT, so don't
    leave call to this function in production code.
 @param tree the tree to append the text to
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_debug_text(proto_tree *tree, const char *format,
	...) G_GNUC_PRINTF(2,3);



/** Append a string to a protocol item.<br>
    NOTE: this function will break with the TRY_TO_FAKE_THIS_ITEM()
    speed optimization.
    Currently only WSP use this function so it is not that bad but try to
    avoid using this one if possible.
    IF you must use this function you MUST also disable the
    TRY_TO_FAKE_THIS_ITEM() optimization for your dissector/function
    using proto_item_append_string().
    Do that by faking that the tree is visible by calling
    proto_tree_set_visible(tree, TRUE) (see packet-wsp.c)
    BEFORE you create the item you are later going to use
    proto_item_append_string() on.
 @param pi the item to append the string to
 @param str the string to append */
extern void
proto_item_append_string(proto_item *pi, const char *str);



/** Fill given label_str with string representation of field
 @param fi the item to get the info from
 @param label_str the string to fill
 @todo think about changing the parameter profile */
extern void
proto_item_fill_label(field_info *fi, gchar *label_str);


/** Register a new protocol.
 @param name the full name of the new protocol
 @param short_name abbreviated name of the new protocol
 @param filter_name protocol name used for a display filter string
 @return the new protocol handle */
extern int
proto_register_protocol(const char *name, const char *short_name, const char *filter_name);

/** Mark protocol as private
 @param proto_id the handle of the protocol */
extern void
proto_mark_private(const int proto_id);

/** Return if protocol is private
 @param proto_id the handle of the protocol
 @return TRUE if it is a private protocol, FALSE is not. */
extern gboolean
proto_is_private(const int proto_id);

/** This is the type of function can be registered to get called whenever
    a given field was not found but a its prefix is matched
	it can be used to procrastinate the hf array registration
   @param match  what's being matched */
typedef void (*prefix_initializer_t)(const char* match);

/** Register a new prefix for delayed initialization of field arrays
@param prefix the prefix for the new protocol
@param initializer function that will initialize the field array for the given prefix */
extern void
proto_register_prefix(const char *prefix,  prefix_initializer_t initializer);

/** Initialize every remaining uninitialized prefix. */
extern void proto_initialize_all_prefixes(void);

/** Register a header_field array.
 @param parent the protocol handle from proto_register_protocol()
 @param hf the hf_register_info array
 @param num_records the number of records in hf */
extern void
proto_register_field_array(const int parent, hf_register_info *hf, const int num_records);

/** Register a protocol subtree (ett) array.
 @param indices array of ett indices
 @param num_indices the number of records in indices */
extern void
proto_register_subtree_array(gint *const *indices, const int num_indices);

/** Returns number of items (protocols or header fields) registered.
 @return the number of items */
extern int proto_registrar_n(void);

/** Get name of registered header_field number n.
 @param n item # n (0-indexed)
 @return the name of this registered item */
extern const char* proto_registrar_get_name(const int n);

/** Get abbreviation of registered header_field number n.
 @param n item # n (0-indexed)
 @return the abbreviation of this registered item */
extern const char* proto_registrar_get_abbrev(const int n);

/** Get the header_field information based upon a field or protocol id.
 @param hfindex item # n (0-indexed)
 @return the registered item */
extern header_field_info* proto_registrar_get_nth(guint hfindex);

/** Get the header_field information based upon a field name.
 @param field_name the field name to search for
 @return the registered item */
extern header_field_info* proto_registrar_get_byname(const char *field_name);

/** Get enum ftenum FT_ of registered header_field number n.
 @param n item # n (0-indexed)
 @return the registered item */
extern int proto_registrar_get_ftype(const int n);

/** Get parent protocol of registered header_field number n.
 @param n item # n (0-indexed)
 @return -1 if item _is_ a protocol */
extern int proto_registrar_get_parent(const int n);

/** Is item # n a protocol?
 @param n item # n (0-indexed)
 @return TRUE if it's a protocol, FALSE if it's not */
extern gboolean proto_registrar_is_protocol(const int n);

/** Get length of registered field according to field type.
 @param n item # n (0-indexed)
 @return 0 means undeterminable at registration time, -1 means unknown field */
extern gint proto_registrar_get_length(const int n);


/** Routines to use to iterate over the protocols and their fields;
 * they return the item number of the protocol in question or the
 * appropriate hfinfo pointer, and keep state in "*cookie". */
extern int proto_get_first_protocol(void **cookie);
extern int proto_get_next_protocol(void **cookie);
extern header_field_info *proto_get_first_protocol_field(const int proto_id, void **cookle);
extern header_field_info *proto_get_next_protocol_field(void **cookle);

/** Given a protocol's filter_name.
 @param filter_name the filter name to search for
 @return proto_id */
extern int proto_get_id_by_filter_name(const gchar* filter_name);

/** Can item # n decoding be disabled?
 @param proto_id protocol id (0-indexed)
 @return TRUE if it's a protocol, FALSE if it's not */
extern gboolean proto_can_toggle_protocol(const int proto_id);

/** Get the "protocol_t" structure for the given protocol's item number.
 @param proto_id protocol id (0-indexed) */
extern protocol_t *find_protocol_by_id(const int proto_id);

/** Get the protocol's name for the given protocol's item number.
 @param proto_id protocol id (0-indexed)
 @return its name */
extern const char *proto_get_protocol_name(const int proto_id);

/** Get the protocol's item number, for the given protocol's "protocol_t".
 @return its proto_id */
extern int proto_get_id(const protocol_t *protocol);

/** Get the protocol's short name, for the given protocol's "protocol_t".
 @return its short name. */
extern const char *proto_get_protocol_short_name(const protocol_t *protocol);

/** Get the protocol's long name, for the given protocol's "protocol_t".
 @return its long name. */
extern const char *proto_get_protocol_long_name(const protocol_t *protocol);

/** Is protocol's decoding enabled ?
 @param protocol
 @return TRUE if decoding is enabled, FALSE if not */
extern gboolean proto_is_protocol_enabled(const protocol_t *protocol);

/** Get a protocol's filter name by it's item number.
 @param proto_id protocol id (0-indexed)
 @return its filter name. */
extern const char *proto_get_protocol_filter_name(const int proto_id);

/** Enable / Disable protocol of the given item number.
 @param proto_id protocol id (0-indexed)
 @param enabled enable / disable the protocol */
extern void proto_set_decoding(const int proto_id, const gboolean enabled);

/** Enable all protocols */
extern void proto_enable_all(void);

/** Disable disabling/enabling of protocol of the given item number.
 @param proto_id protocol id (0-indexed) */
extern void proto_set_cant_toggle(const int proto_id);

/** Checks for existence any protocol or field within a tree.
 @param tree "Protocols" are assumed to be a child of the [empty] root node.
 @param id hfindex of protocol or field
 @return TRUE = found, FALSE = not found
 @todo add explanation of id parameter */
extern gboolean proto_check_for_protocol_or_field(const proto_tree* tree, const int id);

/** Return GPtrArray* of field_info pointers for all hfindex that appear in
    tree. Only works with primed trees, and is fast.
 @param tree tree of interest
 @param hfindex primed hfindex
 @return GPtrArry pointer */
extern GPtrArray* proto_get_finfo_ptr_array(const proto_tree *tree, const int hfindex);

/** Return whether we're tracking any interesting fields.
    Only works with primed trees, and is fast.
 @param tree tree of interest
 @return TRUE if we're tracking interesting fields */
extern gboolean proto_tracking_interesting_fields(const proto_tree *tree);

/** Return GPtrArray* of field_info pointers for all hfindex that appear in
    tree. Works with any tree, primed or unprimed, and is slower than
    proto_get_finfo_ptr_array because it has to search through the tree.
 @param tree tree of interest
 @param hfindex index of field info of interest
 @return GPtrArry pointer */
extern GPtrArray* proto_find_finfo(proto_tree *tree, const int hfindex);

/** Return GPtrArray* of field_info pointers containg all hfindexes that appear
    in tree.
 @param tree tree of interest
 @return GPtrArry pointer */
extern GPtrArray* proto_all_finfos(proto_tree *tree);

/** Dumps a glossary of the protocol registrations to STDOUT */
extern void proto_registrar_dump_protocols(void);

/** Dumps a glossary of the field value strings or true/false strings to STDOUT */
extern void proto_registrar_dump_values(void);

/** Dumps a glossary of the protocol and field registrations to STDOUT.
 * Format 1 is the original format. Format 2 includes the base (for integers)
 * and the blurb. */
extern void proto_registrar_dump_fields(const int format);



/** Points to the first element of an array of Booleans, indexed by
   a subtree item type. That array element is TRUE if subtrees of
   an item of that type are to be expanded. With MSVC and a
   libwireshark.dll, we need a special declaration. */
WS_VAR_IMPORT gboolean	     *tree_is_expanded;

/** Number of elements in the tree_is_expanded array. With MSVC and a
 * libwireshark.dll, we need a special declaration. */
WS_VAR_IMPORT int           num_tree_types;

/** glib doesn't have g_ptr_array_len of all things!*/
#ifndef g_ptr_array_len
#define g_ptr_array_len(a)      ((a)?(a)->len:0)
#endif

/** Get number of bits of a header_field.
 @param hfinfo header_field
 @return the bitwidth */
extern int
hfinfo_bitwidth(const header_field_info *hfinfo);




#include "epan.h"

/** Can we do a "match selected" on this field.
 @param finfo field_info
 @param edt epan dissecting
 @return TRUE if we can do a "match selected" on the field, FALSE otherwise. */
extern gboolean
proto_can_match_selected(field_info *finfo, epan_dissect_t *edt);

/** Construct a "match selected" display filter string.
 @param finfo field_info
 @param edt epan dissecting
 @return the display filter string */
extern char*
proto_construct_match_selected_string(field_info *finfo, epan_dissect_t *edt);

/** Find field from offset in tvb.
 @param tree tree of interest
 @param offset offset in the tvb
 @param tvb the tv buffer
 @return the corresponding field_info */
extern field_info*
proto_find_field_from_offset(proto_tree *tree, guint offset, tvbuff_t *tvb);

/** This function will dissect a sequence of bytes that describe a bitmask.
 @param tree the tree to append this item to
 @param tvb the tv buffer of the current data
 @param offset start of data in tvb
 @param hf_hdr an 8/16/24/32 bit integer that describes the bitmask to be dissected.
        This field will form an expansion under which the individual fields of the
        bitmask is dissected and displayed.
        This field must be of the type FT_[U]INT{8|16|24|32}.
 @param ett subtree index
 @param fields an array of pointers to int that lists all the fields of the
        bitmask. These fields can be either of the type FT_BOOLEAN for flags
        or another integer of the same type/size as hf_hdr with a mask specified.
        This array is terminated by a NULL entry.
        FT_BOOLEAN bits that are set to 1 will have the name added to the expansion.
        FT_integer fields that have a value_string attached will have the
        matched string displayed on the expansion line.
 @param little_endian big or little endian byte representation
 @return the newly created item */
extern proto_item *
proto_tree_add_bitmask(proto_tree *tree, tvbuff_t *tvb, const guint offset,
		const int hf_hdr, const gint ett, const int **fields, const gboolean little_endian);

/** Add a text with a subtree of bitfields.
 @param tree the tree to append this item to
 @param tvb the tv buffer of the current data
 @param offset start of data in tvb
 @param len length of the field name
 @param name field name (NULL if bitfield contents should be used)
 @param fallback field name if none of bitfields were usable
 @param ett subtree index
 @param fields NULL-terminated array of bitfield indexes
 @param little_endian big or little endian byte representation
 @param little_endian big or little endian byte representation
 @param flags
 @return the newly created item */
extern proto_item *
proto_tree_add_bitmask_text(proto_tree *tree, tvbuff_t *tvb, const guint offset, const guint len,
		const char *name, const char *fallback,
		const gint ett, const int **fields, const gboolean little_endian, const int flags);

#define BMT_NO_APPEND	0x01	/**< Don't change the title at all */
#define BMT_NO_INT	0x02	/**< Don't add integral (non-boolean) fields to title */
#define BMT_NO_FALSE	0x04	/**< Don't add booleans unless they're TRUE */
#define BMT_NO_TFS	0x08	/**< Don't use true_false_string while formatting booleans */

/** Add bits to a proto_tree, using the text label registered to that item.
   The item is extracted from the tvbuff handed to it.
 @param tree the tree to append this item to
 @param hf_index field index. Fields for use with this function should have bitmask==0.
 @param tvb the tv buffer of the current data
 @param bit_offset start of data in tvb expressed in bits
 @param no_of_bits length of data in tvb expressed in bits
 @param little_endian big or little endian byte representation
 @return the newly created item */
extern proto_item *
proto_tree_add_bits_item(proto_tree *tree, const int hf_index, tvbuff_t *tvb, const gint bit_offset, const gint no_of_bits, const gboolean little_endian);

/** Add bits to a proto_tree, using the text label registered to that item.
   The item is extracted from the tvbuff handed to it.
 @param tree the tree to append this item to
 @param hf_index field index. Fields for use with this function should have bitmask==0.
 @param tvb the tv buffer of the current data
 @param bit_offset start of data in tvb expressed in bits
 @param no_of_bits length of data in tvb expressed in bits
 @param return_value if a pointer is passed here the value is returned.
 @param little_endian big or little endian byte representation
 @return the newly created item */
extern proto_item *
proto_tree_add_bits_ret_val(proto_tree *tree, const int hf_index, tvbuff_t *tvb, const gint bit_offset, const gint no_of_bits, guint64 *return_value, const gboolean little_endian);

/** Add bits for a FT_UINT8, FT_UINT16, FT_UINT24 or FT_UINT32
    header field to a proto_tree, with the format generating the
    string for the value and with the field name being included automatically.
 @param tree the tree to append this item to
 @param hf_index field index
 @param tvb the tv buffer of the current data
 @param bit_offset start of data in tvb expressed in bits
 @param no_of_bits length of data in tvb expressed in bit
 @param value data to display
 @param format printf like format string
 @return the newly created item */
extern proto_item *
proto_tree_add_uint_bits_format_value(proto_tree *tree, const int hf_index, tvbuff_t *tvb, const gint bit_offset, const gint no_of_bits,
	guint32 value, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Add bits for a FT_BOOLEAN header field to a proto_tree, with
    the format generating the string for the value and with the field
    name being included automatically.
 @param tree the tree to append this item to
 @param hf_index field index
 @param tvb the tv buffer of the current data
 @param bit_offset start of data in tvb expressed in bits
 @param no_of_bits length of data in tvb expressed in bit
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_boolean_bits_format_value(proto_tree *tree, const int hf_index, tvbuff_t *tvb, const gint bit_offset, const gint no_of_bits,
	guint32 value, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Add bits for a FT_INT8, FT_INT16, FT_INT24 or FT_INT32
    header field to a proto_tree, with the format generating the
    string for the value and with the field name being included automatically.
 @param tree the tree to append this item to
 @param hf_index field index
 @param tvb the tv buffer of the current data
 @param bit_offset start of data in tvb expressed in bits
 @param no_of_bits length of data in tvb expressed in bit
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_int_bits_format_value(proto_tree *tree, const int hf_index, tvbuff_t *tvb, const gint bit_offset, const gint no_of_bits,
	gint32 value, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Add bits for a FT_FLOAT header field to a proto_tree, with
    the format generating the string for the value and with the field
    name being included automatically.
 @param tree the tree to append this item to
 @param hf_index field index
 @param tvb the tv buffer of the current data
 @param bit_offset start of data in tvb expressed in bits
 @param no_of_bits length of data in tvb expressed in bit
 @param value data to display
 @param format printf like format string
 @param ... printf like parameters
 @return the newly created item */
extern proto_item *
proto_tree_add_float_bits_format_value(proto_tree *tree, const int hf_index, tvbuff_t *tvb, const gint bit_offset, const gint no_of_bits,
	float value, const char *format, ...) G_GNUC_PRINTF(7,8);

/** Check if given string is a valid field name
 @param field_name the field name to check
 @return 0 if valid, else first illegal character */
extern guchar
proto_check_field_name(const gchar *field_name);


/** Check if given string is a valid field name
 @param tree the tree to append this item to
 @param field_id the field id used for custom column
 @param occurrence the occurrence of the field used for custom column
 @param result the buffer to fill with the field string
 @param expr the filter expression
 @param size the size of the string buffer */
const gchar *
proto_custom_set(proto_tree* tree, const int field_id,
                             gint occurrence,
                             gchar *result,
                             gchar *expr, const int size );

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* proto.h */
