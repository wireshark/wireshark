/* decode_as.h
 * Routines for dissector Decode As handlers
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __DECODE_AS_H__
#define __DECODE_AS_H__

#include "ws_symbol_export.h"

#include "ftypes/ftypes.h"
#include "packet_info.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file
 */

#define MAX_DECODE_AS_PROMPT_LEN    200
#define DECODE_AS_ENTRY "decode_as_entry"
#define DECODE_AS_NONE "(none)"

/*
 * Filename of the "decode as" entry preferences
 */
#define DECODE_AS_ENTRIES_FILE_NAME "decode_as_entries"


/** callback function definition: return formatted label string */
typedef void (*build_label_func)(packet_info *pinfo, gchar* result);

/** callback function definition: return value used to pass to dissector table */
typedef gpointer (*build_valid_func)(packet_info *pinfo);

typedef void (*decode_as_add_to_list_func)(const gchar *table_name, const gchar *proto_name, gpointer value, gpointer user_data);
typedef void (*decode_as_populate_list_func)(const gchar *table_name, decode_as_add_to_list_func add_to_list, gpointer ui_element);
typedef void (*decode_as_free_func)(gpointer value);

/** callback function definition: Clear value from dissector table */
typedef gboolean (*decode_as_reset_func)(const gchar *name, gconstpointer pattern);
/** callback function definition: Apply value to dissector table */
typedef gboolean (*decode_as_change_func)(const gchar *name, gconstpointer pattern, gconstpointer handle, const gchar *list_name);

/**
Contains all of the function pointers (typically just 1) that
provide the text explaining the name and use of the value field that will
be passed to the dissector table to change the dissection output.
*/
typedef struct decode_as_value_s {
    build_label_func label_func;            /**< function pointer to the function used to create the label*/
    guint num_values;                       /**< Number of values */
    build_valid_func* build_values;         /**< Function used to build the value to go into the table. Retreive from current frame */
} decode_as_value_t;

/**
Pulls everything together including the dissector (protocol) name, the
"layer type" of the dissector, the dissector table name, the function pointer
values as well as handlers for populating, applying and reseting the changes
to the dissector table through Decode As GUI functionality. For dissector
tables that are an integer or string type, the provided "default" handling
functions should suffice.

*/
typedef struct decode_as_s {
    const char *name;                               /**< Protocol name */
    const gchar *table_name;                        /**< Disector table name */
    guint num_items;                                /**< Number of index in the decode_as_value_t struct */
    guint default_index_value;                      /**< Which display function to use first, set to zero if only one function*/
    decode_as_value_t* values;                      /**< The array of function pointers, see decode_as_value_t */
    const char* pre_value_str;                      /**< String to prepend the value, NULL if none */
    const char* post_value_str;                     /**< String to append the value, NULL if none */
    decode_as_populate_list_func populate_list;     /**< function pointer to the function used to populate the list, NULL if none */
    decode_as_reset_func reset_value;               /**< function pointer to the function used resetting the value, NULL if none */
    decode_as_change_func change_value;             /**< function pointer to the function used resetting the value, NULL if none */
    decode_as_free_func free_func;                  /**< function pointer to the function used freeing the entry, NULL if none */

} decode_as_t;

/** register a "Decode As".  A copy of the decode_as_t will be maintained by the decode_as module */
WS_DLL_PUBLIC void register_decode_as(decode_as_t* reg);

/* Forward declaration to prevent requiring packet.h */
struct dissector_table;

/** Register a "Decode As" entry for the special case where there is no
 *  indication for the next protocol (such as port number etc.).
 *  For now, this will use a uint32 dissector table internally and
 *  assign all registered protocols to 0. The framework to do this can
 *  be kept internal to epan.
 *
 * @param proto The protocol ID to create the dissector table.
 * @param table_name The table name in which this dissector is found.
 * @param ui_name UI name for created dissector table.
 * @param label_func Pointer to optional function to generate prompt text
 *  for dissector.  If NULL, "Next level protocol as" is used.
 *
 * @return Created dissector table with Decode As support
*/
WS_DLL_PUBLIC struct dissector_table* register_decode_as_next_proto(int proto, const gchar *table_name, const gchar *ui_name, build_label_func label_func);

/* Walk though the dissector table and provide dissector_handle_t for each item in the table */
WS_DLL_PUBLIC void decode_as_default_populate_list(const gchar *table_name, decode_as_add_to_list_func add_to_list, gpointer ui_element);
/* Clear a FT_UINT32 value from dissector table list */
WS_DLL_PUBLIC gboolean decode_as_default_reset(const gchar *name, gconstpointer pattern);
/* Add a FT_UINT32 value to dissector table list */
WS_DLL_PUBLIC gboolean decode_as_default_change(const gchar *name, gconstpointer pattern, gconstpointer handle, const gchar *list_name);

/** List of registered decode_as_t structs.
 * For UI code only. Should not be directly accessed by dissectors.
 */
WS_DLL_PUBLIC GList *decode_as_list;

/* Some useful utilities for Decode As */

/** Reset the "decode as" entries and reload ones of the current profile.
 * This is called by epan_load_settings(); programs should call that
 * rather than individually calling the routines it calls.
 */
extern void load_decode_as_entries(void);

/** Write out the "decode as" entries of the current profile.
 */
WS_DLL_PUBLIC int save_decode_as_entries(gchar** err);

/** Clear all "decode as" settings.
 */
WS_DLL_PUBLIC void decode_clear_all(void);

/** Frees memory used by "decode as" routines. Called at program shutdown.
 */
WS_DLL_PUBLIC void decode_cleanup(void);

/** This routine creates one entry in the list of protocol dissector
 * that need to be reset. It is called by the g_hash_table_foreach
 * routine once for each changed entry in a dissector table.
 * Unfortunately it cannot delete the entry immediately as this screws
 * up the foreach function, so it builds a list of dissectors to be
 * reset once the foreach routine finishes.
 *
 * @param table_name The table name in which this dissector is found.
 *
 * @param selector_type The type of the selector in that dissector table
 *
 * @param key A pointer to the key for this entry in the dissector
 * hash table.  This is generally the numeric selector of the
 * protocol, i.e. the ethernet type code, IP port number, TCP port
 * number, etc.
 *
 * @param value A pointer to the value for this entry in the dissector
 * hash table.  This is an opaque pointer that can only be handed back
 * to routine in the file packet.c - but it's unused.
 *
 * @param user_data Unused.
 */
WS_DLL_PUBLIC void decode_build_reset_list (const gchar *table_name, ftenum_t selector_type,
                         gpointer key, gpointer value,
                         gpointer user_data);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* decode_as.h */
