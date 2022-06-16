/** @file
 * Definitions for packet disassembly structures and routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_H__
#define __PACKET_H__
#include <wireshark.h>

#include <wiretap/wtap_opttypes.h>
#include "proto.h"
#include "tvbuff.h"
#include "epan.h"
#include "value_string.h"
#include "frame_data.h"
#include "packet_info.h"
#include "column-utils.h"
#include "guid-utils.h"
#include "tfs.h"
#include "unit_strings.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct epan_range;

/** @defgroup packet General Packet Dissection
 *
 * @{
 */

#define hi_nibble(b) (((b) & 0xf0) >> 4)
#define lo_nibble(b) ((b) & 0x0f)

/* Useful when you have an array whose size you can tell at compile-time */
#define array_length(x)	(sizeof x / sizeof x[0])

/* Check whether the "len" bytes of data starting at "offset" is
 * entirely inside the captured data for this packet. */
#define	BYTES_ARE_IN_FRAME(offset, captured_len, len) \
	((guint)(offset) + (guint)(len) > (guint)(offset) && \
	 (guint)(offset) + (guint)(len) <= (guint)(captured_len))

extern void packet_init(void);
extern void packet_cache_proto_handles(void);
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
 * @return TRUE if the packet was recognized by the sub-dissector (stop dissection here)
 */
typedef gboolean (*heur_dissector_t)(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, void *);

typedef enum {
    HEURISTIC_DISABLE,
    HEURISTIC_ENABLE
} heuristic_enable_e;

typedef void (*DATFunc) (const gchar *table_name, ftenum_t selector_type,
    gpointer key, gpointer value, gpointer user_data);
typedef void (*DATFunc_handle) (const gchar *table_name, gpointer value,
    gpointer user_data);
typedef void (*DATFunc_table) (const gchar *table_name, const gchar *ui_name,
    gpointer user_data);

/* Opaque structure - provides type checking but no access to components */
typedef struct dtbl_entry dtbl_entry_t;

WS_DLL_PUBLIC dissector_handle_t dtbl_entry_get_handle (dtbl_entry_t *dtbl_entry);
WS_DLL_PUBLIC dissector_handle_t dtbl_entry_get_initial_handle (dtbl_entry_t * entry);

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
    gpointer user_data);

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
    gpointer user_data);

/** Iterate over dissectors with non-default "decode as" settings.
 *
 * Walk all dissector tables calling a user supplied function only on
 * any "decode as" entry that has been changed from its original state.
 *
 * @param[in] func The function to call for each dissector.
 * @param[in] user_data User data to pass to the function.
 */
WS_DLL_PUBLIC void dissector_all_tables_foreach_changed (DATFunc func,
    gpointer user_data);

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
    gpointer user_data);

/** Iterate over all dissector tables.
 *
 * Walk the set of dissector tables calling a user supplied function on each
 * table.
 * @param[in] func The function to call for each table.
 * @param[in] user_data User data to pass to the function.
 * @param[in] compare_key_func Function used to sort the set of tables before
 * calling the function.  No sorting is done if NULL. */
WS_DLL_PUBLIC void dissector_all_tables_foreach_table (DATFunc_table func,
    gpointer user_data, GCompareFunc compare_key_func);

/* a protocol uses the function to register a sub-dissector table
 *
 * 'param' is the display base for integer tables, and TRUE/FALSE for
 * string tables (true indicating case-insensitive, false indicating
 * case-sensitive)
 */
WS_DLL_PUBLIC dissector_table_t register_dissector_table(const char *name,
    const char *ui_name, const int proto, const ftenum_t type, const int param);

/*
 * Similar to register_dissector_table, but with a "custom" hash function
 * to store subdissectors.
 */
WS_DLL_PUBLIC dissector_table_t register_custom_dissector_table(const char *name,
    const char *ui_name, const int proto, GHashFunc hash_func, GEqualFunc key_equal_func);

/** Register a dissector table alias.
 * This is for dissectors whose original name has changed, e.g. SSL to TLS.
 * @param dissector_table dissector table returned by register_dissector_table.
 * @param alias_name alias for the dissector table name.
 */
WS_DLL_PUBLIC void register_dissector_table_alias(dissector_table_t dissector_table,
    const char *alias_name);

/** Deregister the dissector table by table name. */
void deregister_dissector_table(const char *name);

/* Find a dissector table by table name. */
WS_DLL_PUBLIC dissector_table_t find_dissector_table(const char *name);

/* Get the UI name for a sub-dissector table, given its internal name */
WS_DLL_PUBLIC const char *get_dissector_table_ui_name(const char *name);

/* Get the field type for values of the selector for a dissector table,
   given the table's internal name */
WS_DLL_PUBLIC ftenum_t get_dissector_table_selector_type(const char *name);

/* Get the param set for the sub-dissector table,
   given the table's internal name */
WS_DLL_PUBLIC int get_dissector_table_param(const char *name);

/* Dump all dissector tables to the standard output (not the entries,
   just the information about the tables) */
WS_DLL_PUBLIC void dissector_dump_dissector_tables(void);

/* Add an entry to a uint dissector table. */
WS_DLL_PUBLIC void dissector_add_uint(const char *name, const guint32 pattern,
    dissector_handle_t handle);

/* Add an entry to a uint dissector table with "preference" automatically added. */
WS_DLL_PUBLIC void dissector_add_uint_with_preference(const char *name, const guint32 pattern,
    dissector_handle_t handle);

/* Add an range of entries to a uint dissector table. */
WS_DLL_PUBLIC void dissector_add_uint_range(const char *abbrev, struct epan_range *range,
    dissector_handle_t handle);

/* Add an range of entries to a uint dissector table with "preference" automatically added. */
WS_DLL_PUBLIC void dissector_add_uint_range_with_preference(const char *abbrev, const char* range_str,
    dissector_handle_t handle);

/* Delete the entry for a dissector in a uint dissector table
   with a particular pattern. */
WS_DLL_PUBLIC void dissector_delete_uint(const char *name, const guint32 pattern,
    dissector_handle_t handle);

/* Delete an range of entries from a uint dissector table. */
WS_DLL_PUBLIC void dissector_delete_uint_range(const char *abbrev, struct epan_range *range,
    dissector_handle_t handle);

/* Delete all entries from a dissector table. */
WS_DLL_PUBLIC void dissector_delete_all(const char *name, dissector_handle_t handle);

/* Change the entry for a dissector in a uint dissector table
   with a particular pattern to use a new dissector handle. */
WS_DLL_PUBLIC void dissector_change_uint(const char *abbrev, const guint32 pattern,
    dissector_handle_t handle);

/* Reset an entry in a uint dissector table to its initial value. */
WS_DLL_PUBLIC void dissector_reset_uint(const char *name, const guint32 pattern);

/* Return TRUE if an entry in a uint dissector table is found and has been
 * changed (i.e. dissector_change_uint() has been called, such as from
 * Decode As, prefs registered via dissector_add_uint_[range_]with_preference),
 * etc.), otherwise return FALSE.
 */
WS_DLL_PUBLIC gboolean dissector_is_uint_changed(dissector_table_t const sub_dissectors, const guint32 uint_val);

/* Look for a given value in a given uint dissector table and, if found,
   call the dissector with the arguments supplied, and return the number
   of bytes consumed, otherwise return 0. */
WS_DLL_PUBLIC int dissector_try_uint(dissector_table_t sub_dissectors,
    const guint32 uint_val, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Look for a given value in a given uint dissector table and, if found,
   call the dissector with the arguments supplied, and return the number
   of bytes consumed, otherwise return 0. */
WS_DLL_PUBLIC int dissector_try_uint_new(dissector_table_t sub_dissectors,
    const guint32 uint_val, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const gboolean add_proto_name, void *data);

/** Look for a given value in a given uint dissector table and, if found,
 * return the current dissector handle for that value.
 *
 * @param[in] sub_dissectors Dissector table to search.
 * @param[in] uint_val Value to match, e.g. the port number for the TCP dissector.
 * @return The matching dissector handle on success, NULL if no match is found.
 */
WS_DLL_PUBLIC dissector_handle_t dissector_get_uint_handle(
    dissector_table_t const sub_dissectors, const guint32 uint_val);

/** Look for a given value in a given uint dissector table and, if found,
 * return the default dissector handle for that value.
 *
 * @param[in] name Dissector table name.
 * @param[in] uint_val Value to match, e.g. the port number for the TCP dissector.
 * @return The matching dissector handle on success, NULL if no match is found.
 */
WS_DLL_PUBLIC dissector_handle_t dissector_get_default_uint_handle(
    const char *name, const guint32 uint_val);

/* Add an entry to a string dissector table. */
WS_DLL_PUBLIC void dissector_add_string(const char *name, const gchar *pattern,
    dissector_handle_t handle);

/* Delete the entry for a dissector in a string dissector table
   with a particular pattern. */
WS_DLL_PUBLIC void dissector_delete_string(const char *name, const gchar *pattern,
	dissector_handle_t handle);

/* Change the entry for a dissector in a string dissector table
   with a particular pattern to use a new dissector handle. */
WS_DLL_PUBLIC void dissector_change_string(const char *name, const gchar *pattern,
    dissector_handle_t handle);

/* Reset an entry in a string sub-dissector table to its initial value. */
WS_DLL_PUBLIC void dissector_reset_string(const char *name, const gchar *pattern);

/* Return TRUE if an entry in a string dissector table is found and has been
 * changed (i.e. dissector_change_string() has been called, such as from
 * Decode As), otherwise return FALSE.
 */
WS_DLL_PUBLIC gboolean dissector_is_string_changed(dissector_table_t const subdissectors, const gchar *string);

/* Look for a given string in a given dissector table and, if found, call
   the dissector with the arguments supplied, and return the number of
   bytes consumed, otherwise return 0. */
WS_DLL_PUBLIC int dissector_try_string(dissector_table_t sub_dissectors,
    const gchar *string, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);

/* Look for a given string in a given dissector table and, if found, call
   the dissector with the arguments supplied, and return the number of
   bytes consumed, otherwise return 0. */
WS_DLL_PUBLIC int dissector_try_string_new(dissector_table_t sub_dissectors,
    const gchar *string, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const gboolean add_proto_name,void *data);

/** Look for a given value in a given string dissector table and, if found,
 * return the current dissector handle for that value.
 *
 * @param[in] sub_dissectors Dissector table to search.
 * @param[in] string Value to match, e.g. the OID for the BER dissector.
 * @return The matching dissector handle on success, NULL if no match is found.
 */
WS_DLL_PUBLIC dissector_handle_t dissector_get_string_handle(
    dissector_table_t sub_dissectors, const gchar *string);

/** Look for a given value in a given string dissector table and, if found,
 * return the default dissector handle for that value.
 *
 * @param[in] name Dissector table name.
 * @param[in] string Value to match, e.g. the OID for the BER dissector.
 * @return The matching dissector handle on success, NULL if no match is found.
 */
WS_DLL_PUBLIC dissector_handle_t dissector_get_default_string_handle(
    const char *name, const gchar *string);

/* Add an entry to a "custom" dissector table. */
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
    guint16 ver;
} guid_key;

/* Add an entry to a guid dissector table. */
WS_DLL_PUBLIC void dissector_add_guid(const char *name, guid_key* guid_val,
    dissector_handle_t handle);

/* Look for a given value in a given guid dissector table and, if found,
   call the dissector with the arguments supplied, and return TRUE,
   otherwise return FALSE. */
WS_DLL_PUBLIC int dissector_try_guid(dissector_table_t sub_dissectors,
    guid_key* guid_val, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Look for a given value in a given guid dissector table and, if found,
   call the dissector with the arguments supplied, and return TRUE,
   otherwise return FALSE. */
WS_DLL_PUBLIC int dissector_try_guid_new(dissector_table_t sub_dissectors,
    guid_key* guid_val, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const gboolean add_proto_name, void *data);

/** Look for a given value in a given guid dissector table and, if found,
 * return the current dissector handle for that value.
 *
 * @param[in] sub_dissectors Dissector table to search.
 * @param[in] guid_val Value to match, e.g. the GUID number for the GUID dissector.
 * @return The matching dissector handle on success, NULL if no match is found.
 */
WS_DLL_PUBLIC dissector_handle_t dissector_get_guid_handle(
    dissector_table_t const sub_dissectors, guid_key* guid_val);

/* Use the currently assigned payload dissector for the dissector table and,
   if any, call the dissector with the arguments supplied, and return the
   number of bytes consumed, otherwise return 0. */
WS_DLL_PUBLIC int dissector_try_payload(dissector_table_t sub_dissectors,
    tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Use the currently assigned payload dissector for the dissector table and,
   if any, call the dissector with the arguments supplied, and return the
   number of bytes consumed, otherwise return 0. */
WS_DLL_PUBLIC int dissector_try_payload_new(dissector_table_t sub_dissectors,
    tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const gboolean add_proto_name, void *data);

/* Change the entry for a dissector in a payload (FT_NONE) dissector table
   with a particular pattern to use a new dissector handle. */
WS_DLL_PUBLIC void dissector_change_payload(const char *abbrev, dissector_handle_t handle);

/* Reset payload (FT_NONE) dissector table to its initial value. */
WS_DLL_PUBLIC void dissector_reset_payload(const char *name);

/* Given a payload dissector table (type FT_NONE), return the handle of
   the dissector that is currently active, i.e. that was selected via
   Decode As. */
WS_DLL_PUBLIC dissector_handle_t dissector_get_payload_handle(
        dissector_table_t const dissector_table);

/* Add a handle to the list of handles that *could* be used with this
   table.  That list is used by the "Decode As"/"-d" code in the UI. */
WS_DLL_PUBLIC void dissector_add_for_decode_as(const char *name,
    dissector_handle_t handle);

/* Same as dissector_add_for_decode_as, but adds preference for dissector table value */
WS_DLL_PUBLIC void dissector_add_for_decode_as_with_preference(const char *name,
    dissector_handle_t handle);

/** Get the list of handles for a dissector table
 */
WS_DLL_PUBLIC GSList *dissector_table_get_dissector_handles(dissector_table_t dissector_table);

/** Get a handle to dissector out of a dissector table
 */
WS_DLL_PUBLIC dissector_handle_t dissector_table_get_dissector_handle(dissector_table_t dissector_table, const gchar* short_name);

/** Get a dissector table's type
 */
WS_DLL_PUBLIC ftenum_t dissector_table_get_type(dissector_table_t dissector_table);

/** Mark a dissector table as allowing "Decode As"
 */
WS_DLL_PUBLIC void dissector_table_allow_decode_as(dissector_table_t dissector_table);

/** Returns TRUE if dissector table allows "Decode As"
 */
WS_DLL_PUBLIC gboolean dissector_table_supports_decode_as(dissector_table_t dissector_table);

/* List of "heuristic" dissectors (which get handed a packet, look at it,
   and either recognize it as being for their protocol, dissect it, and
   return TRUE, or don't recognize it and return FALSE) to be called
   by another dissector.

   This is opaque outside of "packet.c". */
struct heur_dissector_list;
typedef struct heur_dissector_list *heur_dissector_list_t;


typedef struct heur_dtbl_entry {
	heur_dissector_t dissector;
	protocol_t *protocol; /* this entry's protocol */
	gchar *list_name;     /* the list name this entry is in the list of */
	const gchar *display_name;     /* the string used to present heuristic to user */
	gchar *short_name;     /* string used for "internal" use to uniquely identify heuristic */
	gboolean enabled;
} heur_dtbl_entry_t;

/** A protocol uses this function to register a heuristic sub-dissector list.
 *  Call this in the parent dissectors proto_register function.
 *
 * @param name the name of this protocol
 * @param proto the value obtained when regestering the protocol
 */
WS_DLL_PUBLIC heur_dissector_list_t register_heur_dissector_list(const char *name, const int proto);

typedef void (*DATFunc_heur) (const gchar *table_name,
    struct heur_dtbl_entry *entry, gpointer user_data);
typedef void (*DATFunc_heur_table) (const char *table_name,
    struct heur_dissector_list *table, gpointer user_data);

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
    DATFunc_heur func, gpointer user_data);

/** Iterate over all heuristic dissector tables.
 *
 * Walk the set of heuristic dissector tables calling a user supplied function
 * on each table.
 * @param[in] func The function to call for each table.
 * @param[in] user_data User data to pass to the function.
 * @param[in] compare_key_func Function used to sort the set of tables before
 * calling the function.  No sorting is done if NULL. */
WS_DLL_PUBLIC void dissector_all_heur_tables_foreach_table (DATFunc_heur_table func,
    gpointer user_data, GCompareFunc compare_key_func);

/* true if a heur_dissector list of that anme exists to be registered into */
WS_DLL_PUBLIC gboolean has_heur_dissector_list(const gchar *name);

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
 * @return TRUE if the packet was recognized by the sub-dissector (stop dissection here)
 */
WS_DLL_PUBLIC gboolean dissector_try_heuristic(heur_dissector_list_t sub_dissectors,
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

/** Register a new dissector. */
WS_DLL_PUBLIC dissector_handle_t register_dissector(const char *name, dissector_t dissector, const int proto);

/** Register a new dissector with a callback pointer. */
WS_DLL_PUBLIC dissector_handle_t register_dissector_with_data(const char *name, dissector_cb_t dissector, const int proto, void *cb_data);

/** Deregister a dissector. */
void deregister_dissector(const char *name);

/** Get the long name of the protocol for a dissector handle. */
extern const char *dissector_handle_get_long_name(const dissector_handle_t handle);

/** Get the short name of the protocol for a dissector handle. */
WS_DLL_PUBLIC const char *dissector_handle_get_short_name(const dissector_handle_t handle);

/** Get the index of the protocol for a dissector handle. */
WS_DLL_PUBLIC int dissector_handle_get_protocol_index(const dissector_handle_t handle);

/** Get a GList of all registered dissector names. */
WS_DLL_PUBLIC GList* get_dissector_names(void);

/** Find a dissector by name. */
WS_DLL_PUBLIC dissector_handle_t find_dissector(const char *name);

/** Find a dissector by name and add parent protocol as a depedency*/
WS_DLL_PUBLIC dissector_handle_t find_dissector_add_dependency(const char *name, const int parent_proto);

/** Get a dissector name from handle. */
WS_DLL_PUBLIC const char *dissector_handle_get_dissector_name(const dissector_handle_t handle);

/** Create an anonymous handle for a dissector. */
WS_DLL_PUBLIC dissector_handle_t create_dissector_handle(dissector_t dissector,
    const int proto);
WS_DLL_PUBLIC dissector_handle_t create_dissector_handle_with_name(dissector_t dissector,
    const int proto, const char* name);

/** Call a dissector through a handle and if no dissector was found
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
WS_DLL_PUBLIC int call_dissector(dissector_handle_t handle, tvbuff_t *tvb,
    packet_info *pinfo, proto_tree *tree);

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
 *   @return  return TRUE if dependency was successfully registered
 */
WS_DLL_PUBLIC gboolean register_depend_dissector(const char* parent, const char* dependent);

/** Unregister a protocol dependency
 * This is done automatically when removing from a dissector or
 * heuristic table.  This is for "manual" deregistration for things
 * like Lua
 *
 *   @param parent "Parent" protocol short name
 *   @param dependent "Dependent" protocol short name
 *   @return  return TRUE if dependency was successfully unregistered
 */
WS_DLL_PUBLIC gboolean deregister_depend_dissector(const char* parent, const char* dependent);

/** Find the list of protocol dependencies
 *
 *   @param name Protocol short name to search for
 *   @return  return list of dependent was successfully registered
 */
WS_DLL_PUBLIC depend_dissector_list_t find_depend_dissector_list(const char* name);


/* Do all one-time initialization. */
extern void dissect_init(void);

extern void dissect_cleanup(void);

/*
 * Given a tvbuff, and a length from a packet header, adjust the length
 * of the tvbuff to reflect the specified length.
 */
WS_DLL_PUBLIC void set_actual_length(tvbuff_t *tvb, const guint specified_len);

/**
 * Allow protocols to register "init" routines, which are called before
 * we make a pass through a capture file and dissect all its packets
 * (e.g., when we read in a new capture file, or run a "filter packets"
 * or "colorize packets" pass over the current capture file or when the
 * preferences are changed).
 */
WS_DLL_PUBLIC void register_init_routine(void (*func)(void));

/**
 * Allows protocols to register "cleanup" routines which are called
 * after closing a capture file (or when preferences are changed, in
 * that case these routines are called before the init routines are
 * executed). It can be used to release resources that are allocated in
 * register_init_routine.
 */
WS_DLL_PUBLIC void register_cleanup_routine(void (*func)(void));

/*
 * Register a shutdown routine to call once just before program exit
 */
WS_DLL_PUBLIC void register_shutdown_routine(void (*func)(void));

/* Initialize all data structures used for dissection. */
void init_dissection(void);

/* Free data structures allocated for dissection. */
void cleanup_dissection(void);

/* Allow protocols to register a "cleanup" routine to be
 * run after the initial sequential run through the packets.
 * Note that the file can still be open after this; this is not
 * the final cleanup. */
WS_DLL_PUBLIC void register_postseq_cleanup_routine(void (*func)(void));

/* Call all the registered "postseq_cleanup" routines. */
WS_DLL_PUBLIC void postseq_cleanup_all_protocols(void);

/* Allow dissectors to register a "final_registration" routine
 * that is run like the proto_register_XXX() routine, but the end
 * end of the epan_init() function; that is, *after* all other
 * subsystems, liked dfilters, have finished initializing. This is
 * useful for dissector registration routines which need to compile
 * display filters. dfilters can't initialize itself until all protocols
 * have registereed themselvs. */
WS_DLL_PUBLIC void
register_final_registration_routine(void (*func)(void));

/* Call all the registered "final_registration" routines. */
extern void
final_registration_all_protocols(void);

/*
 * Add a new data source to the list of data sources for a frame, given
 * the tvbuff for the data source and its name.
 */
WS_DLL_PUBLIC void add_new_data_source(packet_info *pinfo, tvbuff_t *tvb,
    const char *name);
/* Removes the last-added data source, if it turns out it wasn't needed */
WS_DLL_PUBLIC void remove_last_data_source(packet_info *pinfo);

/*
 * Return the data source name, tvb.
 */
struct data_source;
WS_DLL_PUBLIC char *get_data_source_name(const struct data_source *src);
WS_DLL_PUBLIC tvbuff_t *get_data_source_tvb(const struct data_source *src);
WS_DLL_PUBLIC tvbuff_t *get_data_source_tvb_by_name(packet_info *pinfo, const char *name);

/*
 * Free up a frame's list of data sources.
 */
extern void free_data_sources(packet_info *pinfo);

/* Mark another frame as depended upon by the current frame.
 *
 * This information is used to ensure that the dependend-upon frame is saved
 * if the user does a File->Save-As of only the Displayed packets and the
 * current frame passed the display filter.
 */
WS_DLL_PUBLIC void mark_frame_as_depended_upon(packet_info *pinfo, guint32 frame_num);

/* Structure passed to the frame dissector */
typedef struct frame_data_s
{
    int file_type_subtype;
    wtap_block_t pkt_block;         /**< NULL if not available */
    struct epan_dissect *color_edt; /** Used strictly for "coloring rules" */

} frame_data_t;

/* Structure passed to the file dissector */
typedef struct file_data_s
{
    wtap_block_t pkt_block;         /**< NULL if not available */
    struct epan_dissect *color_edt; /** Used strictly for "coloring rules" */

} file_data_t;

/*
 * Dissectors should never modify the record data.
 */
extern void dissect_record(struct epan_dissect *edt, int file_type_subtype,
    wtap_rec *rec, tvbuff_t *tvb, frame_data *fd, column_info *cinfo);

/*
 * Dissectors should never modify the packet data.
 */
extern void dissect_file(struct epan_dissect *edt,
    wtap_rec *rec, tvbuff_t *tvb, frame_data *fd, column_info *cinfo);

/* Structure passed to the ethertype dissector */
typedef struct ethertype_data_s
{
    guint16 etype;
    int payload_offset;
    proto_tree *fh_tree;
    int trailer_id;
    int fcs_len;
} ethertype_data_t;

/*
 * Dump layer/selector/dissector records in a fashion similar to the
 * proto_registrar_dump_* routines.
 */
WS_DLL_PUBLIC void dissector_dump_decodes(void);

/*
 * For each heuristic dissector table, dump list of dissectors (filter_names) for that table
 */
WS_DLL_PUBLIC void dissector_dump_heur_decodes(void);

/*
 * postdissectors are to be called by packet-frame.c after every other
 * dissector has been called.
 */

/*
 * Register a postdissector; the argument is the dissector handle for it.
 */
WS_DLL_PUBLIC void register_postdissector(dissector_handle_t handle);

/*
 * Specify a set of hfids that the postdissector will need.
 * The GArray is an array of hfids (type int) and should be NULL to clear the
 * list. This function will take ownership of the memory.
 */
WS_DLL_PUBLIC void set_postdissector_wanted_hfids(dissector_handle_t handle,
    GArray *wanted_hfids);

/*
 * Deregister a postdissector.  Not for use in (post)dissectors or
 * applications; only to be used by libwireshark itself.
 */
void deregister_postdissector(dissector_handle_t handle);

/*
 * Return TRUE if we have at least one postdissector, FALSE if not.
 * Not for use in (post)dissectors or applications; only to be used
 * by libwireshark itself.
 */
extern gboolean have_postdissector(void);

/*
 * Call all postdissectors, handing them the supplied arguments.
 * Not for use in (post)dissectors or applications; only to be used
 * by libwireshark itself.
 */
extern void call_all_postdissectors(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/*
 * Return TRUE if at least one postdissector needs at least one hfid,
 * FALSE otherwise.
 */
WS_DLL_PUBLIC gboolean postdissectors_want_hfids(void);

/*
 * Prime an epan_dissect_t with all the hfids wanted by postdissectors.
 */
WS_DLL_PUBLIC void
prime_epan_dissect_with_postdissector_wanted_hfids(epan_dissect_t *edt);

/** @} */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* packet.h */
