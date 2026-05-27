/** @file
 * Definitions for packet disassembly structures and routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include <wsutil/array.h>
#include "proto.h"
#include "range.h"
#include "tvbuff.h"
#include "epan.h"
#include "frame_data.h"
#include "packet_info.h"
#include "column-utils.h"
#include "guid-utils.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct wtap_block;
typedef struct wtap_block* wtap_block_t;


/** @defgroup packet General Packet Dissection
 *
 * @{
 */

#define hi_nibble(b) (((b) & 0xf0) >> 4)
#define lo_nibble(b) ((b) & 0x0f)

/* Check whether the "len" bytes of data starting at "offset" is
 * entirely inside the captured data for this packet. */
#define	BYTES_ARE_IN_FRAME(offset, captured_len, len) \
	((unsigned)(offset) + (unsigned)(len) > (unsigned)(offset) && \
	 (unsigned)(offset) + (unsigned)(len) <= (unsigned)(captured_len))

/* 0 is case sensitive for backwards compatibility with tables that
 * used false or BASE_NONE for case sensitive, which was the default.
 */
#define STRING_CASE_SENSITIVE 0
#define STRING_CASE_INSENSITIVE 1

/**
 * @brief Initialize the packet dissection engine.
 */
extern void packet_init(void);

/**
 * @brief Cache protocol handles for fast lookup during dissection.
 */
extern void packet_cache_proto_handles(void);

/**
 * @brief Sort the dissector handles in all dissector tables.
 */
extern void packet_all_tables_sort_handles(void);

/**
 * @brief Clean up the packet dissection engine.
 */
extern void packet_cleanup(void);

/* Handle for dissectors you call directly or register with "dissector_add_uint()".
   This handle is opaque outside of "packet.c". */
struct dissector_handle;
typedef struct dissector_handle *dissector_handle_t;

/* Hash table for matching unsigned integers, or strings, and dissectors;
   this is opaque outside of "packet.c". */
struct dissector_table;
typedef struct dissector_table *dissector_table_t;

/*
 * Dissector that returns:
 *
 *	The amount of data in the protocol's PDU, if it was able to
 *	dissect all the data;
 *
 *	0, if the tvbuff doesn't contain a PDU for that protocol;
 *
 *	The negative of the amount of additional data needed, if
 *	we need more data (e.g., from subsequent TCP segments) to
 *	dissect the entire PDU.
 */
typedef int (*dissector_t)(tvbuff_t *, packet_info *, proto_tree *, void *);

/* Same as dissector_t with an extra parameter for callback pointer */
typedef int (*dissector_cb_t)(tvbuff_t *, packet_info *, proto_tree *, void *, void *);

/** Type of a heuristic dissector, used in heur_dissector_add().
 *
 * @param tvb the tvbuff with the (remaining) packet data
 * @param pinfo the packet info of this packet (additional info)
 * @param tree the protocol tree to be build or NULL
 * @return true if the packet was recognized by the sub-dissector (stop dissection here)
 */
typedef bool (*heur_dissector_t)(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, void *);

/**
 * @brief Controls whether a heuristic dissector is active.
 */
typedef enum {
    HEURISTIC_DISABLE, /**< Heuristic dissector is disabled and will not be invoked */
    HEURISTIC_ENABLE   /**< Heuristic dissector is enabled and may be invoked for matching traffic */
} heuristic_enable_e;

typedef void (*DATFunc) (const char *table_name, ftenum_t selector_type,
    void *key, void *value, void *user_data);
typedef void (*DATFunc_handle) (const char *table_name, void *value,
    void *user_data);
typedef void (*DATFunc_table) (const char *table_name, const char *ui_name,
    void *user_data);

/* Opaque structure - provides type checking but no access to components */
typedef struct dtbl_entry dtbl_entry_t;

/**
 * @brief Return the currently active dissector handle for a dissector table entry.
 *
 * @param dtbl_entry The dissector table entry to query.
 * @return The currently active dissector handle for the entry.
 */
WS_DLL_PUBLIC dissector_handle_t dtbl_entry_get_handle(dtbl_entry_t *dtbl_entry);

/**
 * @brief Return the initial (registered) dissector handle for a dissector table entry.
 *
 * @param entry The dissector table entry to query.
 * @return The original registered dissector handle for the entry, or NULL
 *         if no initial handle was recorded.
 */
WS_DLL_PUBLIC dissector_handle_t dtbl_entry_get_initial_handle(dtbl_entry_t *entry);

/** Iterate over dissectors in a table with non-default "decode as" settings.
 *
 * Walk one dissector table calling a user supplied function only on
 * any entry that has been changed from its original state.
 *
 * @param[in] table_name The name of the dissector table, e.g. "ip.proto".
 * @param[in] func The function to call for each dissector.
 * @param[in] user_data User data to pass to the function.
 */
void dissector_table_foreach_changed (const char *table_name, DATFunc func,
    void *user_data);

/** Iterate over dissectors in a table.
 *
 * Walk one dissector table's hash table calling a user supplied function
 * on each entry.
 *
 * @param[in] table_name The name of the dissector table, e.g. "ip.proto".
 * @param[in] func The function to call for each dissector.
 * @param[in] user_data User data to pass to the function.
 */
WS_DLL_PUBLIC void dissector_table_foreach (const char *table_name, DATFunc func,
    void *user_data);

/** Iterate over dissectors with non-default "decode as" settings.
 *
 * Walk all dissector tables calling a user supplied function only on
 * any "decode as" entry that has been changed from its original state.
 *
 * @param[in] func The function to call for each dissector.
 * @param[in] user_data User data to pass to the function.
 */
WS_DLL_PUBLIC void dissector_all_tables_foreach_changed (DATFunc func,
    void *user_data);

/** Iterate over dissectors in a table by handle.
 *
 * Walk one dissector table's list of handles calling a user supplied
 * function on each entry.
 *
 * @param[in] table_name The name of the dissector table, e.g. "ip.proto".
 * @param[in] func The function to call for each dissector.
 * @param[in] user_data User data to pass to the function.
 */
WS_DLL_PUBLIC void dissector_table_foreach_handle(const char *table_name, DATFunc_handle func,
    void *user_data);

/** Iterate over all dissector tables.
 *
 * Walk the set of dissector tables calling a user supplied function on each
 * table.
 * @param[in] func The function to call for each table.
 * @param[in] user_data User data to pass to the function.
 * @param[in] compare_key_func Function used to sort the set of tables before
 * calling the function.  No sorting is done if NULL. */
WS_DLL_PUBLIC void dissector_all_tables_foreach_table (DATFunc_table func,
    void *user_data, GCompareFunc compare_key_func);

/**
 * @brief a protocol uses the function to register a sub-dissector table
 *
 * 'param' is the display base for integer tables, STRING_CASE_SENSITIVE
 * or STRING_CASE_INSENSITIVE for string tables, and ignored for other
 * table types.
 *
 * @param name the name of the dissector table, e.g. "ip.proto"
 * @param ui_name the name of the dissector table to show in the UI, e.g. "IP Protocols"
 * @param proto the protocol ID of the protocol that registers this table, or -1 if the table is not associated with a protocol
 * @param type the type of the selector for this dissector table, e.g. FT_UINT8 for "ip.proto"
 * @param param the parameter for this dissector table, e.g. BASE_HEX for "ip.proto"
 * @return the dissector table created for this name
 */
WS_DLL_PUBLIC dissector_table_t register_dissector_table(const char *name,
    const char *ui_name, const int proto, const ftenum_t type, const int param);

/**
 * @brief Similar to register_dissector_table, but with a "custom" hash function
 * to store subdissectors.
 * @param name the name of the dissector table, e.g. "ip.proto"
 * @param ui_name the name of the dissector table to show in the UI, e.g. "IP Protocols"
 * @param proto the protocol ID of the protocol that registers this table, or -1 if the table is not associated with a protocol
 * @param hash_func the hash function for the custom hash table
 * @param key_equal_func the function to compare keys in the hash table
 * @return the dissector table created for this name
 */
WS_DLL_PUBLIC dissector_table_t register_custom_dissector_table(const char *name,
    const char *ui_name, const int proto, GHashFunc hash_func, GEqualFunc key_equal_func,
    GDestroyNotify key_destroy_func);

/** Register a dissector table alias.
 * This is for dissectors whose original name has changed, e.g. SSL to TLS.
 * @param dissector_table dissector table returned by register_dissector_table.
 * @param alias_name alias for the dissector table name.
 */
WS_DLL_PUBLIC void register_dissector_table_alias(dissector_table_t dissector_table,
    const char *alias_name);

/**
 * @brief Deregister the dissector table by table name.
 * @param name The name of the dissector table to deregister.
 */
void deregister_dissector_table(const char *name);

/** @brief Find a dissector table by its internal name.
 *  @param name The internal name of the dissector table.
 *  @return The dissector table handle, or NULL if not found. */
WS_DLL_PUBLIC dissector_table_t find_dissector_table(const char *name);

/** @brief Return the UI display name for a dissector table.
 *  @param name The internal name of the dissector table.
 *  @return The UI name string for the table. */
WS_DLL_PUBLIC const char *get_dissector_table_ui_name(const char *name);

/** @brief Return the field type of the selector for a dissector table.
 *  @param name The internal name of the dissector table.
 *  @return The @c ftenum_t selector field type for the table. */
WS_DLL_PUBLIC ftenum_t get_dissector_table_selector_type(const char *name);

/** @brief Return the parameter value associated with a dissector table.
 *  @param name The internal name of the dissector table.
 *  @return The integer parameter for the table. */
WS_DLL_PUBLIC int get_dissector_table_param(const char *name);

/**
 * @brief Print information about all registered dissector tables to
 * standard output.
 *
 * Prints table metadata only; individual table entries are not shown.
 */
WS_DLL_PUBLIC void dissector_dump_dissector_tables(void);

/** @brief Add a uint-keyed entry to a dissector table.
 *  @param name    The internal name of the dissector table.
 *  @param pattern The uint selector value to register.
 *  @param handle  The dissector handle to associate with @p pattern. */
WS_DLL_PUBLIC void dissector_add_uint(const char *name, const uint32_t pattern,
    dissector_handle_t handle);

/** @brief Add a uint-keyed entry to a dissector table and automatically
 *  register a corresponding user preference.
 *  @param name    The internal name of the dissector table.
 *  @param pattern The uint selector value to register.
 *  @param handle  The dissector handle to associate with @p pattern. */
WS_DLL_PUBLIC void dissector_add_uint_with_preference(const char *name, const uint32_t pattern,
    dissector_handle_t handle);

/** @brief Add a range of uint-keyed entries to a dissector table.
 *  @param abbrev The internal name of the dissector table.
 *  @param range  The range of uint selector values to register.
 *  @param handle The dissector handle to associate with each value in @p range. */
WS_DLL_PUBLIC void dissector_add_uint_range(const char *abbrev, range_t *range,
    dissector_handle_t handle);

/** @brief Add a range of uint-keyed entries to a dissector table and
 *  automatically register a corresponding user preference.
 *  @param abbrev    The internal name of the dissector table.
 *  @param range_str The default range string for the registered preference.
 *  @param handle    The dissector handle to associate with the range. */
WS_DLL_PUBLIC void dissector_add_uint_range_with_preference(const char *abbrev, const char* range_str,
    dissector_handle_t handle);

/** @brief Remove the entry for a specific uint value from a dissector table.
 *  @param name    The internal name of the dissector table.
 *  @param pattern The uint selector value to remove.
 *  @param handle  The dissector handle to remove. */
WS_DLL_PUBLIC void dissector_delete_uint(const char *name, const uint32_t pattern,
    dissector_handle_t handle);

/** @brief Remove a range of uint-keyed entries from a dissector table.
 *  @param abbrev The internal name of the dissector table.
 *  @param range  The range of uint selector values to remove.
 *  @param handle The dissector handle to remove. */
WS_DLL_PUBLIC void dissector_delete_uint_range(const char *abbrev, range_t *range,
    dissector_handle_t handle);

/**
 * @brief Remove all entries for a given dissector handle from a table.
 * @param name   The internal name of the dissector table.
 * @param handle The dissector handle whose entries should be removed.
 */
WS_DLL_PUBLIC void dissector_delete_all(const char *name, dissector_handle_t handle);

/** @brief Override the dissector for a uint value in a dissector table.
 *  @param abbrev  The internal name of the dissector table.
 *  @param pattern The uint selector value to override.
 *  @param handle  The new dissector handle to use for @p pattern. */
WS_DLL_PUBLIC void dissector_change_uint(const char *abbrev, const uint32_t pattern,
    dissector_handle_t handle);

/** @brief Reset a uint dissector table entry to its initial registered value.
 *  @param name    The internal name of the dissector table.
 *  @param pattern The uint selector value to reset. */
WS_DLL_PUBLIC void dissector_reset_uint(const char *name, const uint32_t pattern);

/**
 * @brief Return whether a uint dissector table entry has been overridden.
 *
 * Returns true if the entry for @p uint_val has been changed from its
 * registered default (e.g. via Decode As or a preference registered with
 * dissector_add_uint_with_preference()), false otherwise.
 *
 * @param sub_dissectors The dissector table to query.
 * @param uint_val       The uint selector value to check.
 * @return true if the entry has been changed, false otherwise.
 */
WS_DLL_PUBLIC bool dissector_is_uint_changed(dissector_table_t const sub_dissectors, const uint32_t uint_val);

/**
 * @brief Try to dissect using a uint-keyed dissector table entry.
 *
 * Looks up @p uint_val in @p sub_dissectors and, if found, calls the
 * matching dissector with the supplied arguments.
 *
 * @param sub_dissectors The dissector table to search.
 * @param uint_val       The uint selector value to look up.
 * @param tvb            The packet buffer.
 * @param pinfo          The packet info.
 * @param tree           The protocol tree.
 * @return The number of bytes consumed by the dissector, or 0 if no
 *         matching entry was found. */
WS_DLL_PUBLIC int dissector_try_uint(dissector_table_t sub_dissectors,
    const uint32_t uint_val, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/**
 * @brief Try to dissect using a uint-keyed dissector table entry, with
 * additional options and caller data.
 *
 * Looks up @p uint_val in @p sub_dissectors and, if found, calls the
 * matching dissector with the supplied arguments.
 *
 * @param sub_dissectors  The dissector table to search.
 * @param uint_val        The uint selector value to look up.
 * @param tvb             The packet buffer.
 * @param pinfo           The packet info.
 * @param tree            The protocol tree.
 * @param add_proto_name  Whether to add the protocol name to the tree.
 * @param data            Caller-supplied data passed to the dissector.
 * @return The number of bytes consumed by the dissector, or 0 if no
 *         matching entry was found. */
WS_DLL_PUBLIC int dissector_try_uint_with_data(dissector_table_t sub_dissectors,
    const uint32_t uint_val, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const bool add_proto_name, void *data);

/**
 * @brief Try to dissect using a uint-keyed dissector table entry, with additional options and caller data.
 * @param sub_dissectors  The dissector table to search.
 * @param uint_val        The uint selector value to look up.
 * @param tvb             The packet buffer.
 * @param pinfo           The packet info.
 * @param tree            The protocol tree.
 * @param add_proto_name  Whether to add the protocol name to the tree.
 * @param data            Caller-supplied data passed to the dissector.
 * @return The number of bytes consumed by the dissector, or 0 if no
 *         matching entry was found.
*/
WS_DEPRECATED_X("Use dissector_try_uint_with_data instead")
static inline int dissector_try_uint_new(dissector_table_t sub_dissectors,
	const uint32_t uint_val, tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, const bool add_proto_name, void* data) \
{	return dissector_try_uint_with_data(sub_dissectors, uint_val, tvb, pinfo, tree, add_proto_name, data); }

/** Look for a given value in a given uint dissector table and, if found,
 * return the current dissector handle for that value.
 *
 * @param[in] sub_dissectors Dissector table to search.
 * @param[in] uint_val Value to match, e.g. the port number for the TCP dissector.
 * @return The matching dissector handle on success, NULL if no match is found.
 */
WS_DLL_PUBLIC dissector_handle_t dissector_get_uint_handle(
    dissector_table_t const sub_dissectors, const uint32_t uint_val);

/** Look for a given value in a given uint dissector table and, if found,
 * return the default dissector handle for that value.
 *
 * @param[in] name Dissector table name.
 * @param[in] uint_val Value to match, e.g. the port number for the TCP dissector.
 * @return The matching dissector handle on success, NULL if no match is found.
 */
WS_DLL_PUBLIC dissector_handle_t dissector_get_default_uint_handle(
    const char *name, const uint32_t uint_val);

/**
 * @brief Add a string-keyed entry to a dissector table.
 * @param name    The internal name of the dissector table.
 * @param pattern The string selector value to register.
 * @param handle  The dissector handle to associate with @p pattern.
 */
WS_DLL_PUBLIC void dissector_add_string(const char *name, const char *pattern,
    dissector_handle_t handle);

/** @brief Remove the entry for a specific string value from a dissector table.
 *  @param name    The internal name of the dissector table.
 *  @param pattern The string selector value to remove.
 *  @param handle  The dissector handle to remove. */
WS_DLL_PUBLIC void dissector_delete_string(const char *name, const char *pattern,
    dissector_handle_t handle);

/** @brief Override the dissector for a string value in a dissector table.
 *  @param name    The internal name of the dissector table.
 *  @param pattern The string selector value to override.
 *  @param handle  The new dissector handle to use for @p pattern. */
WS_DLL_PUBLIC void dissector_change_string(const char *name, const char *pattern,
    dissector_handle_t handle);

/** @brief Reset a string dissector table entry to its initial registered value.
 *  @param name    The internal name of the dissector table.
 *  @param pattern The string selector value to reset. */
WS_DLL_PUBLIC void dissector_reset_string(const char *name, const char *pattern);

/**
 * @brief Return whether a string dissector table entry has been overridden.
 *
 * Returns true if the entry for @p string has been changed from its
 * registered default (e.g. via Decode As), false otherwise.
 *
 * @param subdissectors The dissector table to query.
 * @param string        The string selector value to check.
 * @return true if the entry has been changed, false otherwise.
 */
WS_DLL_PUBLIC bool dissector_is_string_changed(dissector_table_t const subdissectors, const char *string);

/**
 * @brief Look for a given string in a given dissector table and, if found, call
 * the dissector with the arguments supplied, and return the number of
 * bytes consumed, otherwise return 0.
 * @param sub_dissectors The dissector table to search.
 * @param string The string to look for.
 * @param tvb The TVBuffer containing the data to dissect.
 * @param pinfo Packet information for the current packet.
 * @param tree The protocol tree to add nodes to.
 * @param add_proto_name Whether to add the protocol name to each node.
 * @param data Pointer to additional data to pass to the dissector.
 * @return The number of bytes consumed by the dissector, or 0 if not found.
 */
WS_DLL_PUBLIC int dissector_try_string_with_data(dissector_table_t sub_dissectors,
	const char* string, tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, const bool add_proto_name, void* data);

/**
 * @brief Look for a given string in a given dissector table and, if found, call
 * the dissector with the arguments supplied, and return the number of
 * bytes consumed, otherwise return 0.
 * @param sub_dissectors The dissector table to search.
 * @param string The string to look for.
 * @param tvb The TVBuffer containing the data to dissect.
 * @param pinfo Packet information for the current packet.
 * @param tree The protocol tree to add nodes to.
 * @param data Pointer to additional data to pass to the dissector.
 * @return The number of bytes consumed by the dissector, or 0 if not found.
 */
WS_DEPRECATED_X("Use dissector_try_string_with_data instead")
static inline int
dissector_try_string(dissector_table_t sub_dissectors, const char* string,\
	tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data) \
	{ return dissector_try_string_with_data(sub_dissectors, string, tvb, pinfo, tree, true, data); }

/**
 * @brief Look for a given string in a given dissector table and, if found, call
 * the dissector with the arguments supplied, and return the number of
 * bytes consumed, otherwise return 0.
 * @param sub_dissectors The dissector table to search.
 * @param string The string to look for.
 * @param tvb The TVBuffer containing the data to dissect.
 * @param pinfo Packet information for the current packet.
 * @param tree The protocol tree to add nodes to.
 * @param add_proto_name Whether to add the protocol name to each node.
 * @param data Pointer to additional data to pass to the dissector.
 * @return The number of bytes consumed by the dissector, or 0 if not found.
 */
WS_DEPRECATED_X("Use dissector_try_string_with_data instead")
static inline int
dissector_try_string_new(dissector_table_t sub_dissectors, const char* string, \
	tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, const bool add_proto_name, void* data) \
{ return dissector_try_string_with_data(sub_dissectors, string, tvb, pinfo, tree, add_proto_name, data); }


/** Look for a given value in a given string dissector table and, if found,
 * return the current dissector handle for that value.
 *
 * @param[in] sub_dissectors Dissector table to search.
 * @param[in] string Value to match, e.g. the OID for the BER dissector.
 * @return The matching dissector handle on success, NULL if no match is found.
 */
WS_DLL_PUBLIC dissector_handle_t dissector_get_string_handle(
    dissector_table_t sub_dissectors, const char *string);

/** Look for a given value in a given string dissector table and, if found,
 * return the default dissector handle for that value.
 *
 * @param[in] name Dissector table name.
 * @param[in] string Value to match, e.g. the OID for the BER dissector.
 * @return The matching dissector handle on success, NULL if no match is found.
 */
WS_DLL_PUBLIC dissector_handle_t dissector_get_default_string_handle(
    const char *name, const char *string);

/**
 * @brief Add an entry to a "custom" dissector table.
 * @param name The name of the dissector table.
 * @param pattern The pattern to match.
 * @param handle The dissector handle to associate with the pattern.
 */
WS_DLL_PUBLIC void dissector_add_custom_table_handle(const char *name, void *pattern,
    dissector_handle_t handle);

/** Look for a given key in a given "custom" dissector table and, if found,
 * return the current dissector handle for that key.
 *
 * @param[in] sub_dissectors Dissector table to search.
 * @param[in] key Value to match, e.g. RPC key for its subdissectors
 * @return The matching dissector handle on success, NULL if no match is found.
 */
WS_DLL_PUBLIC dissector_handle_t dissector_get_custom_table_handle(
    dissector_table_t sub_dissectors, void *key);
/* Key for GUID dissector tables.  This is based off of DCE/RPC needs
   so some dissector tables may not need the ver portion of the hash
 */
typedef struct _guid_key {
    e_guid_t guid;
    uint16_t ver;
} guid_key;

/**
 * @brief Add an entry to a guid dissector table.
 * @param name The name of the dissector table.
 * @param guid_val The GUID value to add.
 * @param handle The dissector handle to associate with the GUID.
 */
WS_DLL_PUBLIC void dissector_add_guid(const char *name, guid_key* guid_val,
    dissector_handle_t handle);

/**
 * @brief Look for a given value in a given guid dissector table and, if found,
 * call the dissector with the arguments supplied, and return true,
 * otherwise return false.
 *
 * @param sub_dissectors The dissector table to search.
 * @param guid_val The GUID value to look for.
 * @param tvb The TVBuffer containing the data to dissect.
 * @param pinfo Packet information for the current packet.
 * @param tree The protocol tree to add nodes to.
 * @param add_proto_name Whether to add the protocol name to each node.
 * @param data Pointer to additional data to pass to the dissector.
 * @return The number of bytes consumed by the dissector, or 0 if no
 *         matching entry was found.
 */
WS_DLL_PUBLIC int dissector_try_guid_with_data(dissector_table_t sub_dissectors,
    guid_key* guid_val, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const bool add_proto_name, void *data);

/**
 * @brief Delete a GUID from a dissector table.
 * @param name The name of the dissector table.
 * @param guid_val The GUID value to delete.
 * @param handle The dissector handle to associate with the GUID.
 */
WS_DLL_PUBLIC void dissector_delete_guid(const char *name, guid_key* guid_val,
    dissector_handle_t handle);

/** Look for a given value in a given guid dissector table and, if found,
 * return the current dissector handle for that value.
 *
 * @param[in] sub_dissectors Dissector table to search.
 * @param[in] guid_val Value to match, e.g. the GUID number for the GUID dissector.
 * @return The matching dissector handle on success, NULL if no match is found.
 */
WS_DLL_PUBLIC dissector_handle_t dissector_get_guid_handle(
    dissector_table_t const sub_dissectors, guid_key* guid_val);

/**
 * @brief Invoke the currently assigned payload dissector for a dissector table.
 *
 * Uses whichever dissector has been assigned as the payload dissector for
 * @p sub_dissectors (e.g. via Decode As or a default assignment) and, if one
 * is assigned, calls it with the supplied arguments. Unlike
 * dissector_try_uint_with_data(), this does not look up by a key value —
 * it directly invokes the table's designated payload dissector.
 *
 * @param sub_dissectors  The dissector table whose payload dissector to invoke.
 * @param tvb             The packet buffer to dissect.
 * @param pinfo           The packet info for the current packet.
 * @param tree            The protocol tree to populate.
 * @param add_proto_name  Whether to add the protocol name to the protocol tree.
 * @param data            Caller-supplied data passed through to the dissector.
 * @return The number of bytes consumed by the dissector, or 0 if no payload
 *         dissector is assigned.
 */
WS_DLL_PUBLIC int dissector_try_payload_with_data(dissector_table_t sub_dissectors,
    tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const bool add_proto_name, void *data);

/**
 * @brief Invoke the currently assigned payload dissector for a dissector table.
 *
 * @param sub_dissectors  The dissector table whose payload dissector to invoke.
 * @param tvb             The packet buffer to dissect.
 * @param pinfo           The packet info for the current packet.
 * @param tree            The protocol tree to populate.
 * @param add_proto_name  Whether to add the protocol name to the protocol tree.
 * @param data            Caller-supplied data passed through to the dissector.
 * @return The number of bytes consumed by the dissector, or 0 if no payload
 *         dissector is assigned.
 */
WS_DEPRECATED_X("Use dissector_try_payload_with_data instead")
static inline int dissector_try_payload_new(dissector_table_t sub_dissectors,
	tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, const bool add_proto_name, void* data){ \
	return dissector_try_payload_with_data(sub_dissectors, tvb, pinfo, tree, add_proto_name, data); \
}

/**
 * @brief Use the currently assigned payload dissector for the dissector table and,
 * if any, call the dissector with the arguments supplied, and return the
 * number of bytes consumed, otherwise return 0.
 *
 * @param sub_dissectors The dissector table whose payload dissector to invoke.
 * @param tvb The TVBuffer containing the data to dissect.
 * @param pinfo Packet information for the current packet.
 * @param tree The protocol tree to add nodes to.
 * @return The number of bytes consumed by the dissector, or 0 if no payload
 *         dissector is assigned.
 */
WS_DEPRECATED_X("Use dissector_try_payload_with_data instead")
static inline int dissector_try_payload(dissector_table_t sub_dissectors,
	tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree) {
	\
	return dissector_try_payload_with_data(sub_dissectors, tvb, pinfo, tree, true, NULL); \
}

/** @brief Override the payload dissector for an FT_NONE dissector table.
 *  @param abbrev The internal name of the payload dissector table.
 *  @param handle The new dissector handle to assign as the payload dissector. */
WS_DLL_PUBLIC void dissector_change_payload(const char *abbrev, dissector_handle_t handle);

/** @brief Reset an FT_NONE payload dissector table to its initial registered value.
 *  @param name The internal name of the payload dissector table. */
WS_DLL_PUBLIC void dissector_reset_payload(const char *name);

/** @brief Return the currently active dissector handle for a payload dissector table.
 *
 *  Returns the handle of whichever dissector was selected for the given
 *  FT_NONE table, typically via Decode As.
 *
 *  @param dissector_table The payload (FT_NONE) dissector table to query.
 *  @return The currently active dissector handle, or NULL if none is set. */
WS_DLL_PUBLIC dissector_handle_t dissector_get_payload_handle(
        dissector_table_t const dissector_table);

/** @brief Register a dissector handle as a candidate for Decode As on a table.
 *
 *  Adds @p handle to the list of dissectors that the user may select when
 *  using Decode As or the @c -d command-line option, without binding it to
 *  a specific key value.
 *
 *  @param name   The internal name of the dissector table.
 *  @param handle The dissector handle to make available for Decode As. */
WS_DLL_PUBLIC void dissector_add_for_decode_as(const char *name,
    dissector_handle_t handle);

/** @brief Same as dissector_add_for_decode_as(), but also registers a
 *  user preference for the dissector table value.
 *  @param name   The internal name of the dissector table.
 *  @param handle The dissector handle to make available for Decode As. */
WS_DLL_PUBLIC void dissector_add_for_decode_as_with_preference(const char *name,
    dissector_handle_t handle);

/** @brief Return the list of all dissector handles registered with a table.
 *  @param dissector_table The dissector table to query.
 *  @return A @c GSList of @c dissector_handle_t entries registered with the table. */
WS_DLL_PUBLIC GSList *dissector_table_get_dissector_handles(dissector_table_t dissector_table);

/** @brief Look up a dissector handle in a table by its description string.
 *  @param dissector_table The dissector table to search.
 *  @param description     The human-readable description of the target dissector.
 *  @return The matching dissector handle, or NULL if not found. */
WS_DLL_PUBLIC dissector_handle_t dissector_table_get_dissector_handle(dissector_table_t dissector_table, const char* description);

/**
 * @brief Return the selector field type of a dissector table.
 *  @param dissector_table The dissector table to query.
 *  @return The @c ftenum_t field type used as the selector for this table.
 */
WS_DLL_PUBLIC ftenum_t dissector_table_get_type(dissector_table_t dissector_table);

/**
 * @brief Mark a dissector table as supporting Decode As.
 *
 * @note Prefer calling register_decode_as() instead of this function
 * directly. This function is public only for legacy reasons.
 *
 * @param dissector_table The dissector table to mark.
 */
WS_DLL_PUBLIC void dissector_table_allow_decode_as(dissector_table_t dissector_table);

/**
 * @brief Return whether a dissector table supports Decode As.
 *  @param dissector_table The dissector table to query.
 *  @return true if the table allows Decode As, false otherwise.
 */
WS_DLL_PUBLIC bool dissector_table_supports_decode_as(dissector_table_t dissector_table);

/* List of "heuristic" dissectors (which get handed a packet, look at it,
   and either recognize it as being for their protocol, dissect it, and
   return true, or don't recognize it and return false) to be called
   by another dissector.

   This is opaque outside of "packet.c". */
struct heur_dissector_list;
typedef struct heur_dissector_list *heur_dissector_list_t;


typedef struct heur_dtbl_entry {
	heur_dissector_t dissector;
	protocol_t *protocol; /* this entry's protocol */
	char *list_name;     /* the list name this entry is in the list of */
	const char *display_name;     /* the string used to present heuristic to user */
	char *short_name;     /* string used for "internal" use to uniquely identify heuristic */
	bool enabled;
	bool enabled_by_default;
} heur_dtbl_entry_t;

/** A protocol uses this function to register a heuristic sub-dissector list.
 *  Call this in the parent dissectors proto_register function.
 *
 * @param name a unique short name for the list
 * @param ui_name the name used in the user interface
 * @param proto the value obtained when registering the protocol
 */
WS_DLL_PUBLIC heur_dissector_list_t register_heur_dissector_list_with_description(const char *name, const char *ui_name, const int proto);

/** Get description of heuristic sub-dissector list.
 *
 * @param list the dissector list
 */
WS_DLL_PUBLIC const char *heur_dissector_list_get_description(heur_dissector_list_t list);

/** A protocol uses this function to register a heuristic sub-dissector list.
 *  Call this in the parent dissectors proto_register function.
 *
 * @param name the name of this protocol
 * @param proto the value obtained when registering the protocol
 */
WS_DLL_PUBLIC heur_dissector_list_t register_heur_dissector_list(const char *name, const int proto);

/** Deregister a heuristic dissector list by unique short name. */
void deregister_heur_dissector_list(const char *name);

typedef void (*DATFunc_heur) (const char *table_name,
    struct heur_dtbl_entry *entry, void *user_data);
typedef void (*DATFunc_heur_table) (const char *table_name,
    struct heur_dissector_list *table, void *user_data);

/** Iterate over heuristic dissectors in a table.
 *
 * Walk one heuristic dissector table's list calling a user supplied function
 * on each entry.
 *
 * @param[in] table_name The name of the dissector table, e.g. "tcp".
 * @param[in] func The function to call for each dissector.
 * @param[in] user_data User data to pass to the function.
 */
WS_DLL_PUBLIC void heur_dissector_table_foreach(const char *table_name,
    DATFunc_heur func, void *user_data);

/** Iterate over all heuristic dissector tables.
 *
 * Walk the set of heuristic dissector tables calling a user supplied function
 * on each table.
 * @param[in] func The function to call for each table.
 * @param[in] user_data User data to pass to the function.
 * @param[in] compare_key_func Function used to sort the set of tables before
 * calling the function.  No sorting is done if NULL. */
WS_DLL_PUBLIC void dissector_all_heur_tables_foreach_table (DATFunc_heur_table func,
    void *user_data, GCompareFunc compare_key_func);

/**
 * @brief Check if a heuristic dissector list of the given name exists.
 * @param name The name of the heuristic dissector list to check for.
 * @return true if a heur_dissector list of that name exists to be registered into, false otherwise.
 */
WS_DLL_PUBLIC bool has_heur_dissector_list(const char *name);

/** Try all the dissectors in a given heuristic dissector list. This is done,
 *  until we find one that recognizes the protocol.
 *  Call this while the parent dissector running.
 *
 * @param sub_dissectors the sub-dissector list
 * @param tvb the tvbuff with the (remaining) packet data
 * @param pinfo the packet info of this packet (additional info)
 * @param tree the protocol tree to be build or NULL
 * @param hdtbl_entry returns the last tried dissectors hdtbl_entry.
 * @param data parameter to pass to subdissector
 * @return true if the packet was recognized by the sub-dissector (stop dissection here)
 */
WS_DLL_PUBLIC bool dissector_try_heuristic(heur_dissector_list_t sub_dissectors,
    tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, heur_dtbl_entry_t **hdtbl_entry, void *data);

/** Find a heuristic dissector table by table name.
 *
 * @param name name of the dissector table
 * @return pointer to the table on success, NULL if no such table exists
 */
WS_DLL_PUBLIC heur_dissector_list_t find_heur_dissector_list(const char *name);

/** Find a heuristic dissector by the unique short protocol name provided during registration.
 *
 * @param short_name short name of the protocol to look at
 * @return pointer to the heuristic dissector entry, NULL if not such dissector exists
 */
WS_DLL_PUBLIC heur_dtbl_entry_t* find_heur_dissector_by_unique_short_name(const char *short_name);

/** Add a sub-dissector to a heuristic dissector list.
 *  Call this in the proto_handoff function of the sub-dissector.
 *
 * @param name the name of the heuristic dissector table into which to register the dissector, e.g. "tcp"
 * @param dissector the sub-dissector to be registered
 * @param display_name the string used to present heuristic to user, e.g. "HTTP over TCP"
 * @param internal_name the string used for "internal" use to identify heuristic, e.g. "http_tcp"
 * @param proto the protocol id of the sub-dissector
 * @param enable initially enabled or not
 */
WS_DLL_PUBLIC void heur_dissector_add(const char *name, heur_dissector_t dissector,
    const char *display_name, const char *internal_name, const int proto, heuristic_enable_e enable);

/** Remove a sub-dissector from a heuristic dissector list.
 *  Call this in the prefs_reinit function of the sub-dissector.
 *
 * @param name the name of the "parent" protocol, e.g. "tcp"
 * @param dissector the sub-dissector to be unregistered
 * @param proto the protocol id of the sub-dissector
 */
WS_DLL_PUBLIC void heur_dissector_delete(const char *name, heur_dissector_t dissector, const int proto);

/**
 * @brief Register a new dissector with the global dissector registry.
 *
 * @param name      Short, unique machine-friendly name for this dissector
 *                  (e.g. @c "http").
 * @param dissector The dissector function to call.
 * @param proto     Protocol index returned by @c proto_register_protocol().
 * @return The newly created and registered @c dissector_handle_t.
 */
WS_DLL_PUBLIC dissector_handle_t register_dissector(const char *name,
    dissector_t dissector, const int proto);

/**
 * @brief Register a new dissector with a custom user-visible description.
 *
 * @param name        Short, unique machine-friendly name for this dissector.
 * @param description Human-readable description shown in the UI.
 * @param dissector   The dissector function to call.
 * @param proto       Protocol index returned by @c proto_register_protocol().
 * @return The newly created and registered @c dissector_handle_t.
 */
WS_DLL_PUBLIC dissector_handle_t register_dissector_with_description(const char *name,
    const char *description, dissector_t dissector, const int proto);

/**
 * @brief Register a new dissector that carries an opaque callback pointer.
 *
 * @param name      Short, unique machine-friendly name for this dissector.
 * @param dissector The callback-style dissector function to call.
 * @param proto     Protocol index returned by @c proto_register_protocol().
 * @param cb_data   Opaque pointer passed through to @p dissector on each
 *                  invocation.
 * @return The newly created and registered @c dissector_handle_t.
 */
WS_DLL_PUBLIC dissector_handle_t register_dissector_with_data(const char *name,
    dissector_cb_t dissector, const int proto, void *cb_data);

/**
 * @brief Deregister a previously registered dissector.
 * @param name The name passed to register_dissector() at registration time.
 */
void deregister_dissector(const char *name);

/**
 * @brief Return the long (full) protocol name for a dissector handle.
 *
 * @param handle A valid dissector handle.
 * @return The long protocol name string (e.g. @c "Hypertext Transfer Protocol"),
 *         or NULL if @p handle is invalid.
 */
WS_DLL_PUBLIC const char *dissector_handle_get_protocol_long_name(
    const dissector_handle_t handle);

/**
 * @brief Return the short protocol name for a dissector handle.
 *
 * @param handle A valid dissector handle.
 * @return The short protocol name string (e.g. @c "HTTP"), or NULL if
 *         @p handle is invalid.
 */
WS_DLL_PUBLIC const char *dissector_handle_get_protocol_short_name(
    const dissector_handle_t handle);

/**
 * @brief Return the short protocol name for a dissector handle.
 *
 * For backwards source and binary compatibility.
 *
 * @param handle A valid dissector handle.
 * @return The short protocol name string, or NULL if @p handle is invalid.
 */
G_DEPRECATED_FOR(dissector_handle_get_protocol_short_name)
WS_DLL_PUBLIC const char *dissector_handle_get_short_name(
    const dissector_handle_t handle);


/**
 * @brief Return the user-visible description for a dissector handle.
 *
 * @param handle A valid dissector handle.
 * @return The description string, or NULL if @p handle is invalid.
 */
WS_DLL_PUBLIC const char *dissector_handle_get_description(
    const dissector_handle_t handle);

/**
 * @brief Return the protocol index for a dissector handle.
 *
 * @param handle A valid dissector handle.
 * @return The @c proto index (as returned by @c proto_register_protocol())
 *         for the protocol associated with @p handle, or -1 if invalid.
 */
WS_DLL_PUBLIC int dissector_handle_get_protocol_index(
    const dissector_handle_t handle);

/**
 * @brief Return a GList of all registered dissector name strings.
 * @return A newly allocated @c GList of registered dissector name strings.
 */
WS_DLL_PUBLIC GList *get_dissector_names(void);

/**
 * @brief Find a registered dissector by name.
 *
 * @param name The short name used at register_dissector() time.
 * @return The @c dissector_handle_t for @p name, or NULL if no dissector
 *         with that name is registered.
 */
WS_DLL_PUBLIC dissector_handle_t find_dissector(const char *name);

/**
 * @brief Find a registered dissector by name and record a protocol dependency.
 *
 * @param name         The short name of the dissector to find.
 * @param parent_proto The protocol index of the calling dissector's protocol.
 * @return The @c dissector_handle_t for @p name, or NULL if not found.
 */
WS_DLL_PUBLIC dissector_handle_t find_dissector_add_dependency(const char *name,
    const int parent_proto);

/**
 * @brief Return the registered name of a dissector from its handle.
 *
 * @param handle A valid dissector handle.
 * @return The name string passed to register_dissector() or
 *         create_dissector_handle_with_name(), or NULL for anonymous handles.
 */
WS_DLL_PUBLIC const char *dissector_handle_get_dissector_name(
    const dissector_handle_t handle);

/**
 * @brief Return the preferences suffix string for a dissector handle.
 *
 * @param handle A valid dissector handle.
 * @return The preference key suffix string, or NULL if none is set.
 */
WS_DLL_PUBLIC const char *dissector_handle_get_pref_suffix(
    const dissector_handle_t handle);

/**
 * @brief Create an anonymous, unregistered dissector handle.
 *
 * Unregistered means that
 * other dissectors can't find the dissector through this API. The typical use
 * case is dissectors added to dissector tables that shouldn't be called by other
 * dissectors, perhaps if some data structure must be passed to the dissector.
 *
 * @param dissector The dissector the handle will call
 * @param proto The value obtained when registering the protocol
 *
 * @note The protocol short name will be used as the user-visible description.
 */
WS_DLL_PUBLIC dissector_handle_t create_dissector_handle(dissector_t dissector,
    const int proto);

/**
 * @brief Create a named, unregistered dissector handle.
 *
 * Create an named, unregistered dissector handle.
 * A non-NULL name is needed for dissector_add_for_decode_add_with_preference().
 *
 * @note The protocol short name will be used as the user-visible description.
 *
 * @param dissector The dissector the handle will call
 * @param proto The value obtained when registering the protocol
 * @param name a short, machine-friendly name for the dissector. Does not have
 * to be globally unique, but should be unique for any table the handle will be
 * registered to. Can be NULL, which creates an anonymous dissector.
 *
 * @return A newly created, unregistered @c dissector_handle_t.
 */
WS_DLL_PUBLIC dissector_handle_t create_dissector_handle_with_name(
    dissector_t dissector, const int proto, const char *name);

/** Create an named, unregistered handle dissector handle with a description.
 * A non-NULL name is needed for dissector_add_for_decode_add_with_preference().
 * The description is used to allow a user to distinguish dissectors for the
 * same protocol, e.g. when registered to the same table.
 *
 * @param dissector The dissector the handle will call
 * @param proto The value obtained when registering the protocol
 * @param name a short, machine-friendly name for the dissector. Does not have
 * to be globally unique, but should be unique for any table the handle will be
 * registered to. Can be NULL, which creates an anonymous dissector.
 * @param description Freeform text designed to be shown to a user. Must be
 * unique for any table the dissector is registered in. Can be NULL, in which
 * case the protocol short name is used as the user-visible description.
 */
WS_DLL_PUBLIC dissector_handle_t create_dissector_handle_with_name_and_description(dissector_t dissector,
    const int proto, const char* name, const char* description);

/**
 * @brief Create an anonymous, unregistered callback-style dissector handle.
 *
 * Like create_dissector_handle(), but uses the @c dissector_cb_t calling
 * convention so that @p cb_data is forwarded to the dissector on every
 * invocation. The handle is not added to the global registry.
 *
 * @param dissector The callback-style dissector function the handle will invoke.
 * @param proto     Protocol index returned by @c proto_register_protocol().
 * @param cb_data   Opaque pointer passed through to @p dissector on each call.
 * @return A newly created, unregistered @c dissector_handle_t.
 */
WS_DLL_PUBLIC dissector_handle_t create_dissector_handle_with_data(
    dissector_cb_t dissector, const int proto, void *cb_data);

/**
 * @brief Dump all registered dissectors to the standard output
 */
WS_DLL_PUBLIC void dissector_dump_dissectors(void);

/**
 * @brief Call a dissector through a handle and if no dissector was found
 * pass it over to the "data" dissector instead.
 *
 *   @param handle The dissector to call.
 *   @param  tvb The buffer to dissect.
 *   @param  pinfo Packet Info.
 *   @param  tree The protocol tree.
 *   @param  data parameter to pass to dissector
 *   @return  If the protocol for that handle isn't enabled call the data
 *   dissector. Otherwise, if the handle refers to a new-style
 *   dissector, call the dissector and return its return value, otherwise call
 *   it and return the length of the tvbuff pointed to by the argument.
 */
WS_DLL_PUBLIC int call_dissector_with_data(dissector_handle_t handle, tvbuff_t *tvb,
    packet_info *pinfo, proto_tree *tree, void *data);

/**
 * @brief Call a dissector through its handle, falling back to the data dissector.
 *
 * @param handle The handle of the dissector to invoke.
 * @param tvb    The buffer containing the payload to dissect.
 * @param pinfo  Packet metadata and column information.
 * @param tree   The protocol tree node under which the child dissector should
 *               add its items.
 * @return The number of bytes consumed by the dissector, or the number
 *         consumed by the data dissector fallback if the primary dissector
 *         declined. A return value equal to @c tvb_captured_length(tvb)
 *         indicates the entire buffer was consumed.
 */
WS_DLL_PUBLIC int call_dissector(dissector_handle_t handle, tvbuff_t *tvb,
    packet_info *pinfo, proto_tree *tree);

/**
 * @brief Call a data dissector.
 *
 * @param  tvb The buffer to dissect.
 * @param  pinfo Packet Info.
 * @param  tree The protocol tree.
 * @return 0 if the data dissector did not consume any bytes, otherwise the number of bytes consumed.
 */
WS_DLL_PUBLIC int call_data_dissector(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/** Call a dissector through a handle but if no dissector was found
 * just return 0 and do not call the "data" dissector instead.
 *
 *   @param handle The dissector to call.
 *   @param  tvb The buffer to dissect.
 *   @param  pinfo Packet Info.
 *   @param  tree The protocol tree.
 *   @param  data parameter to pass to dissector
 *   @return  If the protocol for that handle isn't enabled, return 0 without
 *   calling the dissector. Otherwise, if the handle refers to a new-style
 *   dissector, call the dissector and return its return value, otherwise call
 *   it and return the length of the tvbuff pointed to by the argument.
 */
WS_DLL_PUBLIC int call_dissector_only(dissector_handle_t handle, tvbuff_t *tvb,
    packet_info *pinfo, proto_tree *tree, void *data);

/**
 *   @param heur_dtbl_entry The heur_dtbl_entry of the dissector to call.
 *   @param  tvb The buffer to dissect.
 *   @param  pinfo Packet Info.
 *   @param  tree The protocol tree.
 *   @param  data parameter to pass to dissector
 */
WS_DLL_PUBLIC void call_heur_dissector_direct(heur_dtbl_entry_t *heur_dtbl_entry, tvbuff_t *tvb,
    packet_info *pinfo, proto_tree *tree, void *data);

/* This is opaque outside of "packet.c". */
struct depend_dissector_list;
typedef struct depend_dissector_list *depend_dissector_list_t;

/** Register a protocol dependency
 * This is done automatically when registering with a dissector or
 * heuristic table.  This is for "manual" registration when a dissector
 * ends up calling another through call_dissector (or similar) so
 * dependencies can be determined
 *
 *   @param parent "Parent" protocol short name
 *   @param dependent "Dependent" protocol short name
 *   @return  return true if dependency was successfully registered
 */
WS_DLL_PUBLIC bool register_depend_dissector(const char* parent, const char* dependent);

/** Unregister a protocol dependency
 * This is done automatically when removing from a dissector or
 * heuristic table.  This is for "manual" deregistration for things
 * like Lua.
 *
 *   @param parent "Parent" protocol short name
 *   @param dependent "Dependent" protocol short name
 *   @return  return true if dependency was successfully unregistered
 */
WS_DLL_PUBLIC bool deregister_depend_dissector(const char* parent, const char* dependent);

/** Find the list of protocol dependencies
 *
 *   @param name Protocol short name to search for
 *   @return  return list of dependent was successfully registered
 */
WS_DLL_PUBLIC depend_dissector_list_t find_depend_dissector_list(const char* name);

/**
 * @brief Given a tvbuff, and a length from a packet header, adjust the length
 * of the tvbuff to reflect the specified length.
 *
 * @param tvb The tvbuff to adjust.
 * @param specified_len The length to set for the tvbuff.
 */
WS_DLL_PUBLIC void set_actual_length(tvbuff_t *tvb, const unsigned specified_len);

/**
 * Allow protocols to register "init" routines, which are called before
 * we make a pass through a capture file and dissect all its packets
 * (e.g., when we read in a new capture file, or run a "filter packets"
 * or "colorize packets" pass over the current capture file or when the
 * preferences are changed).
 */
WS_DLL_PUBLIC void register_init_routine(void (*func)(void));

/**
 * Allows protocols to register "cleanup" routines, which are called
 * after closing a capture file (or when preferences are changed, in
 * that case these routines are called before the init routines are
 * executed). It can be used to release resources that are allocated in
 * an "init" routine.
 */
WS_DLL_PUBLIC void register_cleanup_routine(void (*func)(void));

/**
 * Allows protocols to register "shutdown" routines, which are called
 * once, just before program exit
 */
WS_DLL_PUBLIC void register_shutdown_routine(void (*func)(void));

/**
 * @brief Initialize all data structures used for dissection.
 * @param app_env_var_prefix The prefix for environment variables that control dissection.
 */
void init_dissection(const char* app_env_var_prefix);

/** @brief Free data structures allocated for dissection. */
void cleanup_dissection(void);

/** @brief Allow protocols to register a "cleanup" routine to be
 * run after the initial sequential run through the packets.
 * Note that the file can still be open after this; this is not
 * the final cleanup. */
WS_DLL_PUBLIC void register_postseq_cleanup_routine(void (*func)(void));

/**@brief Call all the registered "postseq_cleanup" routines. */
WS_DLL_PUBLIC void postseq_cleanup_all_protocols(void);

/**
 * Allow dissectors to register a "final_registration" routine
 * that is run like the proto_register_XXX() routine, but the end
 * end of the epan_init() function; that is, *after* all other
 * subsystems (such as dfilters) have finished initializing. This is
 * useful for dissector registration routines which need to compile
 * display filters. dfilters can't initialize itself until all protocols
 * have registered themselves.
 */
WS_DLL_PUBLIC void
register_final_registration_routine(void (*func)(void));

/**
 * @brief Call all the registered "final_registration" routines.
 */
extern void
final_registration_all_protocols(void);

// XXX Should we move frame_data.encoding here?
/**
 * @brief MIME media type descriptor for a packet data source buffer.
 */
typedef enum {
    DS_MEDIA_TYPE_APPLICATION_OCTET_STREAM, /**< Raw binary data (application/octet-stream) */
    DS_MEDIA_TYPE_APPLICATION_JSON,         /**< JSON-encoded data (application/json) */
} data_source_media_type_e;

struct data_source;

/**
 * Add a new data source to the list of data sources for a frame, given
 * the tvbuff for the data source and its name. The media type will be
 * set to DS_MEDIA_TYPE_APPLICATION_OCTET_STREAM.
 * @param pinfo Packet info.
 * @param tvb The tvbuff to associate with the data source.
 * @param name A display-friendly name of the data source.
 * @return An opaque pointer to the data source.
 */
WS_DLL_PUBLIC struct data_source* add_new_data_source(packet_info *pinfo, tvbuff_t *tvb,
    const char *name);

/**
 * Set the name for the data source.
 * @param pinfo pinfo from whose pool to allocate a copy of the data source
 * @param src The data source.
 * @param name new name for the data source
 */
WS_DLL_PUBLIC void set_data_source_name(packet_info *pinfo, struct data_source *src, const char *name);

/**
 * Set the media type for the data source. This will be used as a hint
 * to display the source's tvbuff.
 * @param src The data source.
 * @param media_type A valid media type.
 */
WS_DLL_PUBLIC void set_data_source_media_type(struct data_source *src, data_source_media_type_e media_type);

/**
 * @brief Remove the most recently added data source from a packet.
 *
 * Removes the last-added data source, if it turns out it wasn't needed.
 *
 * @param pinfo The packet info structure whose last data source should
 *              be removed.
 */
WS_DLL_PUBLIC void remove_last_data_source(packet_info *pinfo);

/**
 * @brief Return the display name of a data source.
 *
 * @param src The data source whose name should be returned.
 * @return A newly allocated string of the form @c "Name (N bytes)".
 */
WS_DLL_PUBLIC const char *get_data_source_name(const struct data_source *src);

/**
 * @brief Return the description of a data source.
 *
 * @param src The data source whose description should be returned.
 * @return The description string. The pointer is valid for the lifetime
 *         of the packet dissection pool; do not free it.
 */
WS_DLL_PUBLIC char *get_data_source_description(const struct data_source *src);

/**
 * @brief Return the tvbuff associated with a data source.
 *
 * @param src The data source whose tvb should be returned.
 * @return The @c tvbuff_t associated with @p src. The pointer is valid
 *         for the lifetime of the packet dissection; do not free it
 *         directly.
 */
WS_DLL_PUBLIC tvbuff_t *get_data_source_tvb(const struct data_source *src);
/**
 * Find and return data source with the given name.
 * @param pinfo packet_info for the packet whose data sources are to be searched
 * @param name name of the data source
 * @return the data source or NULL if not found
 */
WS_DLL_PUBLIC struct data_source *get_data_source_by_name(const packet_info *pinfo, const char *name);

/**
 * Find and return data source with the given tvb.
 * @param pinfo packet_info for the packet whose data sources are to be searched
 * @param tvb tvb of the data source
 * @return the data source or NULL if not found
 */
WS_DLL_PUBLIC struct data_source *get_data_source_by_tvb(const packet_info *pinfo, const tvbuff_t *tvb);

/**
 * Get a data source's media type.
 * @param src The data source.
 * @return A media type.
 */
WS_DLL_PUBLIC data_source_media_type_e get_data_source_media_type(const struct data_source *src);

/**
 * @brief Free up a frame's list of data sources.
 * @param pinfo The packet info structure whose data sources should be freed.
 */
extern void free_data_sources(packet_info *pinfo);

/**
 * @brief Mark another frame as depended upon by the current frame.
 *
 * This information is used to ensure that when the current frame is exported
 * or saved that the depended upon frames necessary for correct dissection are
 * also exported (along with the frames that those depend upon, in infinite
 * descent.) The fragment handling functions in reassemble.c mark any frame
 * used to reassemble the current frame as depended upon; dissectors can also
 * mark frames themselves.
 *
 * In Wireshark, the "Include depended upon packets" checkbox in the Export
 * Specified Packets dialog (enabled by default) controls whether depended
 * upon frames of selected frames are also exported. TShark also saves
 * any depended upon frames when saving filtered packets to a file.
 *
 * @param fd The frame data for the current frame.
 * @param frame_num The frame number of the frame to mark as depended upon.
 */
WS_DLL_PUBLIC void mark_frame_as_depended_upon(frame_data *fd, uint32_t frame_num);

/* Structure passed to the frame dissector */
typedef struct frame_data_s
{
    int file_type_subtype;
    /*
     * This might be the block from the packet's wtap_rec or it might
     * be a modified copy of that, as, for example, the comments
     * might have been edited but not yet saved to the file.
     */
    wtap_block_t pkt_block;         /**< NULL if not available */
    struct epan_dissect *color_edt; /** Used strictly for "coloring rules" */

} frame_data_t;

/* Structure passed to the file dissector */
typedef struct file_data_s
{
    wtap_block_t pkt_block;         /**< NULL if not available */
    struct epan_dissect *color_edt; /** Used strictly for "coloring rules" */

} file_data_t;

/**
 * @brief Dissectors should never modify the record data.
 * @param edt The epan_dissect_t for the current dissection.
 * @param file_type_subtype The file type subtype of the current frame.
 * @param rec The record for the current frame.
 * @param fd The frame data for the current frame.
 * @param cinfo The column info for the current frame.
 */
extern void dissect_record(struct epan_dissect *edt, int file_type_subtype,
    wtap_rec *rec, frame_data *fd, column_info *cinfo);

/**
 * @brief Dissectors should never modify the file data.
 * @param edt The epan_dissect_t for the current dissection.
 * @param rec The record for the current frame.
 * @param fd The frame data for the current frame.
 * @param cinfo The column info for the current frame.
 */
extern void dissect_file(struct epan_dissect *edt,
    wtap_rec *rec, frame_data *fd, column_info *cinfo);

/* Structure passed to the ethertype dissector */
typedef struct ethertype_data_s
{
    uint16_t etype;
    int payload_offset;
    proto_tree *fh_tree;
    int trailer_id;
    int fcs_len;
} ethertype_data_t;

/**
 * @brief Dump layer/selector/dissector records in a fashion similar to the
 * proto_registrar_dump_* routines.
 */
WS_DLL_PUBLIC void dissector_dump_decodes(void);

/**
 * @brief For each heuristic dissector table, dump list of dissectors (filter_names) for that table
 */
WS_DLL_PUBLIC void dissector_dump_heur_decodes(void);

/*
 * postdissectors are to be called by packet-frame.c after every other
 * dissector has been called.
 */

/**
 * @brief Register a postdissector; the argument is the dissector handle for it.
 * @param handle The dissector handle for the postdissector to register.
 */
WS_DLL_PUBLIC void register_postdissector(dissector_handle_t handle);

/**
 * Specify a set of hfids that the postdissector will need on the first pass.
 * This ensures that the fields will not be faked, and can be retrieved with
 * proto_get_finfo_ptr_array.
 *
 * @note There is no way to guarantee that fields added by other postdissectors
 * will be available. (Issue #19804) This is for postdissectors that examine
 * fields added by other dissectors on the first linear pass, and then store
 * their own results in persistent memory for retrieval and adding in later
 * passes. Postdissectors that need field values on later passes should call
 * something else, like epan_set_always_visible() (which slows dissection.)
 *
 * @param handle The dissector handle used to register the postdissector.
 * @param wanted_hfids An array of hfids (type int), which should be NULL to
 * clear the list. This function will take ownership of the array.
 */
WS_DLL_PUBLIC void set_postdissector_wanted_hfids(dissector_handle_t handle,
    GArray *wanted_hfids);

/**
 * @brief Deregister a postdissector.  Not for use in (post)dissectors or
 * applications; only to be used by libwireshark itself.
 * @param handle The dissector handle for the postdissector to deregister.
 */
void deregister_postdissector(dissector_handle_t handle);

/**
 * @brief Return whether any postdissectors are registered.
 *
 * Checks if at least one postdissector has been registered with the
 * dissection engine.
 *
 * @note Internal to libwireshark. Not for use by dissectors or applications.
 *
 * @return true if at least one postdissector is registered, false otherwise.
 */
extern bool have_postdissector(void);

/**
 * @brief Invoke all registered postdissectors on the current frame.
 *
 * Iterates over every registered postdissector and calls each one with
 * the supplied packet buffer, packet info, and protocol tree. Postdissectors
 * run after all regular dissectors have completed for a given frame.
 *
 * @note Internal to libwireshark. Not for use by dissectors or applications.
 *
 * @param tvb   The packet buffer for the current frame.
 * @param pinfo The packet info for the current frame.
 * @param tree  The fully populated protocol tree for the current frame.
 */
extern void call_all_postdissectors(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/**
 * @brief Return whether any postdissector has requested specific hfids.
 *
 * Returns true if at least one registered postdissector has declared
 * interest in one or more header field IDs (hfids), meaning the dissection
 * engine must prime those fields before calling postdissectors.
 *
 * @return true if any postdissector wants at least one hfid, false otherwise.
 */
WS_DLL_PUBLIC bool postdissectors_want_hfids(void);

/**
 * @brief Prime an epan_dissect_t with all hfids requested by postdissectors.
 *
 * Registers all header field IDs declared by postdissectors into @p edt so
 * that those fields are extracted and available during the first-pass
 * dissection of an unvisited frame. libwireshark calls this automatically
 * before dissecting any frame that has not yet been visited; it should not
 * be called manually by dissectors or applications.
 *
 * @note Internal to libwireshark. Not for use by dissectors or applications.
 *
 * @param edt The epan_dissect_t to prime with postdissector-requested hfids.
 */
extern void
prime_epan_dissect_with_postdissector_wanted_hfids(epan_dissect_t *edt);

/** Increment the dissection depth.
 * This should be used to limit recursion outside the tree depth checks in
 * call_dissector and dissector_try_heuristic.
 * @param pinfo Packet Info.
 */
WS_DLL_PUBLIC void increment_dissection_depth(packet_info *pinfo);

/** Increment the dissection depth by a value.
 * This should be used to limit recursion outside the tree depth checks in
 * call_dissector and dissector_try_heuristic.
 * @param pinfo Packet Info.
 * @param n The value by which to increment the depth
 */
WS_DLL_PUBLIC void increment_dissection_depth_by_n(packet_info *pinfo, unsigned n);

/**
 * @brief Decrement the dissection depth.
 * @param pinfo Packet Info.
 */
WS_DLL_PUBLIC void decrement_dissection_depth(packet_info *pinfo);

/**
 * @brief Decrement the dissection depth by a value.
 * @param pinfo Packet Info.
 * @param n The value by which to decrement the depth
 */
WS_DLL_PUBLIC void decrement_dissection_depth_by_n(packet_info *pinfo, unsigned n);

/** @} */

#ifdef __cplusplus
}
#endif /* __cplusplus */
