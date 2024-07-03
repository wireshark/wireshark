/* oids.h
 * Object IDentifier Support
 *
 * (c) 2007, Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __OIDS_H__
#define __OIDS_H__

#include <epan/ftypes/ftypes.h>
#include <epan/prefs.h>
#include <epan/wmem_scopes.h>
#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 *@file
 */
#define BER_TAG_ANY -1

struct _oid_bit_t {
    unsigned offset;
    int hfid;
};

typedef struct _oid_bits_info_t {
    unsigned num;
    int ett;
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
    OID_KEY_TYPE_ETHER,
    OID_KEY_TYPE_DATE_AND_TIME
} oid_key_type_t;

typedef struct _oid_value_type_t {
    enum ftenum ft_type;
    int display;
    int8_t ber_class;
    int32_t ber_tag;
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
    uint32_t num_subids;
    oid_key_type_t key_type;
    int hfid;
    enum ftenum ft_type;
    int display;
    struct _oid_key_t* next;
} oid_key_t;

typedef struct _oid_info_t {
    uint32_t subid;
    char* name;
    oid_kind_t kind;
    wmem_tree_t* children;
    const oid_value_type_t* value_type;
    int value_hfid;
    oid_key_t* key;
    oid_bits_info_t* bits;
    struct _oid_info_t* parent;
} oid_info_t;

/** init function called from prefs.c */
WS_DLL_PUBLIC void oids_init(void);
extern void oid_pref_init(module_t *nameres);

/** init function called from epan.h */
WS_DLL_PUBLIC void oids_cleanup(void);

/*
 * The objects returned by all these functions are all allocated with a
 * packet lifetime and do not have to be freed.
 * However, take into account that when the packet dissection
 * completes, these buffers will be automatically reclaimed/freed.
 * If you need the buffer to remain for a longer scope than packet lifetime
 * you must copy the content to an wmem_file_scope() buffer.
 */

/*
 * These functions convert through the various formats:
 * string: is  like "0.1.3.4.5.30" (not resolved)
 * encoded: is BER encoded (as per X.690 section 8.19)
 * subids: is an array of guint32s
 */

/* return length of encoded buffer */
WS_DLL_PUBLIC
unsigned oid_subid2encoded(wmem_allocator_t *scope, unsigned len, uint32_t* subids, uint8_t** encoded_p);
WS_DLL_PUBLIC
unsigned oid_string2encoded(wmem_allocator_t *scope, const char *oid_str, uint8_t** encoded_p);

/* return length of subid array */
WS_DLL_PUBLIC
unsigned oid_encoded2subid(wmem_allocator_t *scope, const uint8_t *oid, int len, uint32_t** subids_p);
WS_DLL_PUBLIC
unsigned oid_encoded2subid_sub(wmem_allocator_t *scope, const uint8_t *oid_bytes, int oid_len, uint32_t** subids_pi,
                bool is_first);
WS_DLL_PUBLIC
unsigned oid_string2subid(wmem_allocator_t *scope, const char *oid_str, uint32_t** subids_p);

WS_DLL_PUBLIC char* oid_encoded2string(wmem_allocator_t *scope, const uint8_t* encoded, unsigned len);
WS_DLL_PUBLIC char* rel_oid_encoded2string(wmem_allocator_t *scope, const uint8_t* encoded, unsigned len);
WS_DLL_PUBLIC char* oid_subid2string(wmem_allocator_t *scope, uint32_t *subids, unsigned len);
WS_DLL_PUBLIC char* rel_oid_subid2string(wmem_allocator_t *scope, uint32_t *subids, unsigned len, bool is_absolute);

/* these return a formated string as human readable as possible */
WS_DLL_PUBLIC char *oid_resolved(wmem_allocator_t *scope, unsigned len, uint32_t *subids);
WS_DLL_PUBLIC char *oid_resolved_from_encoded(wmem_allocator_t *scope, const uint8_t *oid, int len);
WS_DLL_PUBLIC char *rel_oid_resolved_from_encoded(wmem_allocator_t *scope, const uint8_t *oid, int len);
WS_DLL_PUBLIC char *oid_resolved_from_string(wmem_allocator_t *scope, const char *oid_str);

/* these yield two formated strings one resolved and one numeric */
WS_DLL_PUBLIC void oid_both(wmem_allocator_t *scope, unsigned oid_len, uint32_t *subids, char** resolved_p, char** numeric_p);
WS_DLL_PUBLIC void oid_both_from_encoded(wmem_allocator_t *scope, const uint8_t *oid, int oid_len, char** resolved_p, char** numeric_p);
WS_DLL_PUBLIC void oid_both_from_string(wmem_allocator_t *scope, const char *oid_str, char** resolved_p, char** numeric_p);

/*
 * These return the info for the best match.
 *  *matched_p will be set to the number of nodes used by the returned oid
 *  *left_p will be set to the number of remaining unresolved subids
 */
WS_DLL_PUBLIC oid_info_t* oid_get(unsigned oid_len, uint32_t *subids, unsigned* matched_p, unsigned* left_p);
WS_DLL_PUBLIC oid_info_t* oid_get_from_encoded(wmem_allocator_t *scope, const uint8_t *oid, int oid_len, uint32_t **subids, unsigned* matched, unsigned* left);
WS_DLL_PUBLIC oid_info_t* oid_get_from_string(wmem_allocator_t *scope, const char *oid_str, uint32_t **subids, unsigned* matched, unsigned* left);

/* these are used to add oids to the collection */
WS_DLL_PUBLIC void oid_add(const char* name, unsigned oid_len, uint32_t *subids);
WS_DLL_PUBLIC void oid_add_from_encoded(const char* name, const uint8_t *oid, int oid_len);
WS_DLL_PUBLIC void oid_add_from_string(const char* name, const char *oid_str);

/**
 * Fetch the default MIB/PIB path
 *
 * @return A string containing the default MIB/PIB path.  It must be
 * g_free()d by the caller.
 */
WS_DLL_PUBLIC char *oid_get_default_mib_path(void);

/* macros for legacy oid functions */
#define subid_t uint32_t



#ifdef DEBUG_OIDS
extern char* oid_test_a2b(uint32_t num_subids, uint32_t* subids);
extern void add_oid_debug_subtree(oid_info_t* oid_info, proto_tree *tree);
#else
#define add_oid_debug_subtree(a,b) ((void)0)
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif  /* __OIDS_H__ */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
