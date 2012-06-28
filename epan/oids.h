/* oids.h
 * Object IDentifier Support
 *
 * $Id$
 *
 * (c) 2007, Luis E. Garcia Ontanon <luis@ontanon.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __OIDS_H__
#define __OIDS_H__

#include <epan/ftypes/ftypes.h>
/**
 *@file
 */
#define BER_TAG_ANY -1

struct _oid_bit_t {
	guint offset;
	int hfid;
};

typedef struct _oid_bits_info_t {
	guint num;
	gint ett;
	struct _oid_bit_t* data;
} oid_bits_info_t;

typedef enum _oid_key_type_t {
	OID_KEY_TYPE_WRONG,
	OID_KEY_TYPE_INTEGER,
	OID_KEY_TYPE_OID,
	OID_KEY_TYPE_STRING,
	OID_KEY_TYPE_BYTES,
	OID_KEY_TYPE_NSAP,
	OID_KEY_TYPE_IPADDR,
	OID_KEY_TYPE_IMPLIED_OID,
	OID_KEY_TYPE_IMPLIED_STRING,
	OID_KEY_TYPE_IMPLIED_BYTES,
	OID_KEY_TYPE_ETHER
} oid_key_type_t;

typedef struct _oid_value_type_t {
	enum ftenum ft_type;
	int display;
	gint8 ber_class;
	gint32 ber_tag;
	int min_len;
	int max_len;
	oid_key_type_t keytype;
	int keysize;
} oid_value_type_t;

typedef enum _oid_kind_t {
	OID_KIND_UNKNOWN = 0,
	OID_KIND_NODE,
	OID_KIND_SCALAR,
	OID_KIND_TABLE,
	OID_KIND_ROW,
	OID_KIND_COLUMN,
	OID_KIND_NOTIFICATION,
	OID_KIND_GROUP,
	OID_KIND_COMPLIANCE,
	OID_KIND_CAPABILITIES
} oid_kind_t;

typedef struct _oid_key_t {
	char* name;
	guint32 num_subids;
	oid_key_type_t key_type;
	int hfid;
	enum ftenum ft_type;
	int display;
	struct _oid_key_t* next;
} oid_key_t;

typedef struct _oid_info_t {
	guint32 subid;
	char* name;
	oid_kind_t kind;
	void* children; /**< an emem_tree_t* */
	const oid_value_type_t* value_type;
	int value_hfid;
	oid_key_t* key;
	oid_bits_info_t* bits;
	struct _oid_info_t* parent;
} oid_info_t;

/** init funcion called from epan.h */
extern void oids_init(void);

/** init funcion called from epan.h */
extern void oids_cleanup(void);

/*
 * The objects returned by all these functions are all allocated with a
 * packet lifetime and does not have have to be freed.
 * However, take into account that when the packet dissection
 * completes, these buffers will be automatically reclaimed/freed.
 * If you need the buffer to remain for a longer scope than packet lifetime
 * you must copy the content to an se_alloc() buffer.
 */

/*
 * These functions convert through the various formats:
 * string: is  like "0.1.3.4.5.30" (not resolved)
 * encoded: is BER encoded (as per X.690 section 8.19)
 * subids: is an array of guint32s
 */

/* return length of encoded buffer */
guint oid_subid2encoded(guint len, guint32* subids, guint8** encoded_p);
guint oid_string2encoded(const gchar *oid_str, guint8** encoded_p);

/* return length of subid array */
guint oid_encoded2subid(const guint8 *oid, gint len, guint32** subids_p);
guint oid_string2subid(const gchar *oid_str, guint32** subids_p);

extern const gchar* oid_encoded2string(const guint8* encoded, guint len);
extern const gchar* oid_subid2string(guint32 *subids, guint len);

/* these return a formated string as human readable as posible */
extern const gchar *oid_resolved(guint len, guint32 *subids);
extern const gchar *oid_resolved_from_encoded(const guint8 *oid, gint len);
extern const gchar *oid_resolved_from_string(const gchar *oid_str);

/* these yield two formated strings one resolved and one numeric */
extern void oid_both(guint oid_len, guint32 *subids, char** resolved_p, char** numeric_p);
extern void oid_both_from_encoded(const guint8 *oid, gint oid_len, char** resolved_p, char** numeric_p);
extern void oid_both_from_string(const gchar *oid_str, char** resolved_p, char** numeric_p);

/*
 * These return the info for the best match.
 *  *matched_p will be set to the number of nodes used by the returned oid
 *  *left_p will be set to the number of remaining unresolved subids
 */
extern oid_info_t* oid_get(guint oid_len, guint32 *subids, guint* matched_p, guint* left_p);
extern oid_info_t* oid_get_from_encoded(const guint8 *oid, gint oid_len, guint32 **subids, guint* matched, guint* left);
extern oid_info_t* oid_get_from_string(const gchar *oid_str, guint32 **subids, guint* matched, guint* left);

/* these are used to add oids to the collection */
extern void oid_add(const char* name, guint oid_len, guint32 *subids);
extern void oid_add_from_encoded(const char* name, const guint8 *oid, gint oid_len);
extern void oid_add_from_string(const char* name, const gchar *oid_str);

/**
 * Fetch the default MIB/PIB path
 *
 * @return A string containing the default MIB/PIB path.  It must be
 * g_free()d by the caller.
 */
extern gchar *oid_get_default_mib_path(void);

/* macros for legacy oid functions */
#define oid_resolv_cleanup() ((void)0)
#define subid_t guint32



#ifdef DEBUG_OIDS
extern char* oid_test_a2b(guint32 num_subids, guint32* subids);
extern void add_oid_debug_subtree(oid_info_t* oid_info, proto_tree *tree);
#else
#define add_oid_debug_subtree(a,b) ((void)0)
#endif

#endif
