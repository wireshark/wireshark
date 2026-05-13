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
#pragma once
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
/**
 * @brief Initialize OID resolution and register related preferences.
 *
 * @param app_env_var_prefix The prefix for environment variables related to OID resolution.
 */
WS_DLL_PUBLIC void oids_init(const char* app_env_var_prefix);

/**
 * @brief Initialize OID-related preferences.
 *
 * @param nameres The module structure for name resolution.
 */
extern void oid_pref_init(module_t *nameres);

/** init function called from epan.h */
/**
 * @brief Clean up OID-related resources.
 */
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
 * subids: is an array of uint32_t
 */

/**
 * @brief Return length of encoded buffer.
 *
 * @param scope     The memory allocator scope.
 * @param len       The number of sub-identifiers in subids.
 * @param subids    The array of sub-identifiers to encode.
 * @param encoded_p Output pointer to the encoded buffer.
 * @return Length of the encoded buffer.
 */
WS_DLL_PUBLIC
unsigned oid_subid2encoded(wmem_allocator_t *scope, unsigned len, uint32_t* subids, uint8_t** encoded_p);

/**
 * @brief Return length of encoded buffer.
 *
 * @param scope     The memory allocator scope.
 * @param oid_str   The OID string to encode.
 * @param encoded_p Output pointer to the encoded buffer.
 * @return Length of the encoded buffer.
 */
WS_DLL_PUBLIC
unsigned oid_string2encoded(wmem_allocator_t *scope, const char *oid_str, uint8_t** encoded_p);

/**
 * @brief Return the number of sub-identifiers in a decoded OID.
 *
 * @param scope    The memory allocator scope.
 * @param oid      The encoded OID buffer.
 * @param len      The length of the encoded buffer.
 * @param subids_p Output pointer to the array of sub-identifiers.
 * @return The number of sub-identifiers in the decoded OID.
 */
WS_DLL_PUBLIC
unsigned oid_encoded2subid(wmem_allocator_t *scope, const uint8_t *oid, int len, uint32_t** subids_p);

/**
 * @brief Return the number of sub-identifiers in a decoded OID, with support
 * for partial (sub-) OID decoding.
 *
 * @param scope     The memory allocator scope.
 * @param oid_bytes The encoded OID buffer.
 * @param oid_len   The length of the encoded buffer.
 * @param subids_pi Output pointer to the array of sub-identifiers.
 * @param is_first  Whether this is the first component of the OID.
 * @return The number of sub-identifiers in the decoded OID.
 */
WS_DLL_PUBLIC
unsigned oid_encoded2subid_sub(wmem_allocator_t *scope, const uint8_t *oid_bytes, int oid_len, uint32_t** subids_pi,
                bool is_first);

/**
 * @brief Return the number of sub-identifiers in a decoded OID string.
 *
 * @param scope    The memory allocator scope.
 * @param oid_str  The OID string to decode.
 * @param subids_p Output pointer to the array of sub-identifiers.
 * @return The number of sub-identifiers in the decoded OID.
 */
WS_DLL_PUBLIC
unsigned oid_string2subid(wmem_allocator_t *scope, const char *oid_str, uint32_t** subids_p);

/**
 * @brief Return the string representation of an encoded OID.
 *
 * @param scope   The memory allocator scope.
 * @param encoded The encoded OID buffer.
 * @param len     The length of the encoded buffer.
 * @return The string representation of the OID.
 */
WS_DLL_PUBLIC char* oid_encoded2string(wmem_allocator_t *scope, const uint8_t* encoded, unsigned len);

/**
 * @brief Return the string representation of an encoded relative OID.
 *
 * @param scope   The memory allocator scope.
 * @param encoded The encoded relative OID buffer.
 * @param len     The length of the encoded buffer.
 * @return The string representation of the relative OID.
 */
WS_DLL_PUBLIC char* rel_oid_encoded2string(wmem_allocator_t *scope, const uint8_t* encoded, unsigned len);

/**
 * @brief Convert a sequence of OID sub-identifiers to a human-readable string.
 *
 * @param scope Memory allocator for the returned string.
 * @param subids Array of OID sub-identifiers.
 * @param len Number of sub-identifiers in the array.
 * @return A formatted string representing the OID, or NULL on failure.
 */
WS_DLL_PUBLIC char* oid_subid2string(wmem_allocator_t *scope, uint32_t *subids, unsigned len);

/**
 * @brief Convert a sequence of OID subidentifiers to a human-readable string.
 *
 * @param scope Memory allocator for the returned string.
 * @param subids Array of OID subidentifiers.
 * @param len Number of subidentifiers in the array.
 * @param is_absolute Flag indicating if the OID is absolute (starts with a dot).
 * @return A formatted string representing the OID, or "*** Empty OID ***" if input is invalid.
 */
WS_DLL_PUBLIC char* rel_oid_subid2string(wmem_allocator_t *scope, uint32_t *subids, unsigned len, bool is_absolute);

/* these return a formated string as human readable as possible */
/**
 * @brief Resolve an OID to its human-readable name.
 *
 * @param scope Memory allocator for the returned string.
 * @param len Length of the OID sub-identifier array.
 * @param subids Array of OID sub-identifiers.
 * @return Human-readable name of the OID, or NULL if not found.
 */
WS_DLL_PUBLIC char *oid_resolved(wmem_allocator_t *scope, unsigned len, uint32_t *subids);

/**
 * @brief Resolve an OID from its encoded form.
 *
 * @param scope Memory allocator for allocated memory.
 * @param oid Encoded OID data.
 * @param len Length of the encoded OID data.
 * @return Resolved OID as a string, or NULL if resolution fails.
 */
WS_DLL_PUBLIC char *oid_resolved_from_encoded(wmem_allocator_t *scope, const uint8_t *oid, int len);

/**
 * @brief Resolve an OID from its encoded form.
 *
 * @param scope Memory allocator for allocated memory.
 * @param oid Encoded OID data.
 * @param len Length of the encoded OID data.
 * @return Resolved OID as a string, or NULL if resolution fails.
 */
WS_DLL_PUBLIC char *rel_oid_resolved_from_encoded(wmem_allocator_t *scope, const uint8_t *oid, int len);

/**
 * @brief Resolves an OID string to its resolved form.
 *
 * @param scope Memory allocator scope for allocating memory.
 * @param oid_str The OID string to resolve.
 * @return The resolved OID as a string, or NULL if resolution fails.
 */
WS_DLL_PUBLIC char *oid_resolved_from_string(wmem_allocator_t *scope, const char *oid_str);

/* these yield two formated strings one resolved and one numeric */

/**
 * @brief Resolve and convert an OID to both resolved and numeric representations.
 *
 * @param scope Memory allocator for allocating memory.
 * @param oid_len Length of the OID subids array.
 * @param subids Array of OID subidentifiers.
 * @param resolved_p Pointer to store the resolved OID string.
 * @param numeric_p Pointer to store the numeric OID representation.
 */
WS_DLL_PUBLIC void oid_both(wmem_allocator_t *scope, unsigned oid_len, uint32_t *subids, char** resolved_p, char** numeric_p);

/**
 * @brief Resolve and convert an OID from its encoded form to both resolved and numeric representations.
 *
 * @param scope Memory allocator for allocating memory.
 * @param oid Encoded OID data.
 * @param oid_len Length of the encoded OID data.
 * @param resolved_p Pointer to store the resolved OID string.
 * @param numeric_p Pointer to store the numeric OID representation.
 */
WS_DLL_PUBLIC void oid_both_from_encoded(wmem_allocator_t *scope, const uint8_t *oid, int oid_len, char** resolved_p, char** numeric_p);

/**
 * @brief Resolve and convert an OID from its string representation to both resolved and numeric forms.
 *
 * @param scope Memory allocator for allocating memory.
 * @param oid_str The OID string to resolve and convert.
 * @param resolved_p Pointer to store the resolved OID string.
 * @param numeric_p Pointer to store the numeric OID representation.
 */
WS_DLL_PUBLIC void oid_both_from_string(wmem_allocator_t *scope, const char *oid_str, char** resolved_p, char** numeric_p);

/*
 * These return the info for the best match.
 *  *matched_p will be set to the number of nodes used by the returned oid
 *  *left_p will be set to the number of remaining unresolved subids
 */

/**
 * @brief Retrieves an OID information structure from its encoded form.
 *
 * @param oid_len Length of the encoded OID data.
 * @param subids Pointer to store the decoded sub-identifiers.
 * @param matched_p Pointer to store the number of nodes used by the returned OID.
 * @param left_p Pointer to store the number of remaining unresolved sub-identifiers.
 * @return oid_info_t* Pointer to the retrieved OID information structure or the root OID if no match is found.
 */
WS_DLL_PUBLIC oid_info_t* oid_get(unsigned oid_len, uint32_t *subids, unsigned* matched_p, unsigned* left_p);

/**
 * @brief Retrieves an OID information structure from its encoded form.
 *
 * @param scope Memory allocator scope for allocating the returned object.
 * @param oid Encoded OID data.
 * @param oid_len Length of the encoded OID data.
 * @param subids Pointer to store the decoded sub-identifiers.
 * @param matched Pointer to store the number of matched sub-identifiers.
 * @param left Pointer to store the number of remaining sub-identifiers.
 * @return Pointer to the retrieved OID information structure, or NULL if not found.
 */
WS_DLL_PUBLIC oid_info_t* oid_get_from_encoded(wmem_allocator_t *scope, const uint8_t *oid, int oid_len, uint32_t **subids, unsigned* matched, unsigned* left);

/**
 * @brief Retrieves an OID information structure from a string representation.
 *
 * @param scope Memory allocator scope for the returned oid_info_t structure.
 * @param oid_str String representation of the OID to retrieve.
 * @param subids Pointer to store the resulting sub-identifier array.
 * @param matched Pointer to store the number of matched sub-identifiers.
 * @param left Pointer to store the number of remaining sub-identifiers.
 * @return Pointer to the retrieved oid_info_t structure, or NULL if not found.
 */
WS_DLL_PUBLIC oid_info_t* oid_get_from_string(wmem_allocator_t *scope, const char *oid_str, uint32_t **subids, unsigned* matched, unsigned* left);

/* these are used to add oids to the collection */
/**
 * @brief Add an OID to the OID database.
 *
 * @param name    The name to associate with the OID.
 * @param oid_len The number of sub-identifiers in @p subids.
 * @param subids  The array of sub-identifiers.
 */
WS_DLL_PUBLIC void oid_add(const char* name, unsigned oid_len, uint32_t *subids);

/**
 * @brief Add an OID to the OID database from an encoded buffer.
 *
 * @param name    The name to associate with the OID.
 * @param oid     The encoded OID buffer.
 * @param oid_len The length of the encoded buffer.
 */
WS_DLL_PUBLIC void oid_add_from_encoded(const char* name, const uint8_t *oid, int oid_len);

/**
 * @brief Add an OID to the OID database from a string.
 *
 * @param name    The name to associate with the OID.
 * @param oid_str The OID string.
 */
WS_DLL_PUBLIC void oid_add_from_string(const char* name, const char *oid_str);

/**
 * @brief Fetch the default MIB/PIB path
 *
 * @param app_env_var_prefix The prefix for environment variables related to OID resolution.
 * @return A string containing the default MIB/PIB path.  It must be
 * g_free()d by the caller.
 */
WS_DLL_PUBLIC char *oid_get_default_mib_path(const char* app_env_var_prefix);

/* macros for legacy oid functions */
#define subid_t uint32_t



#ifdef DEBUG_OIDS
/**
 * @brief Test function to convert an array of sub-identifiers to an encoded
 * buffer and back, returning the result as a string.
 *
 * @param num_subids The number of sub-identifiers in @p subids.
 * @param subids     The array of sub-identifiers.
 * @return The string representation of the round-tripped OID.
 */
extern char* oid_test_a2b(uint32_t num_subids, uint32_t* subids);

/**
 * @brief Add a debug subtree for an OID info node to a protocol tree.
 *
 * @param oid_info The OID info node to debug.
 * @param tree     The protocol tree to add the subtree to.
 */
extern void add_oid_debug_subtree(oid_info_t* oid_info, proto_tree *tree);
#else
#define add_oid_debug_subtree(a,b) ((void)0)
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

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
