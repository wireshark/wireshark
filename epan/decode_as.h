/* decode_as.h
 * Routines for dissector Decode As handlers
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
typedef gboolean (*decode_as_reset_func)(const char *name, const gpointer pattern);
/** callback function definition: Apply value to dissector table */
typedef gboolean (*decode_as_change_func)(const char *name, const gpointer pattern, gpointer handle, gchar* list_name);

typedef struct decode_as_value_s {
    build_label_func label_func;
    guint num_values;
    build_valid_func* build_values;
} decode_as_value_t;

typedef struct decode_as_s {
    const char *name;
    const gchar *title;
    const gchar *table_name;
    guint num_items;
    guint default_index_value;
    decode_as_value_t* values;
    const char* pre_value_str;
    const char* post_value_str;
    decode_as_populate_list_func populate_list;
    decode_as_reset_func reset_value;
    decode_as_change_func change_value;
    decode_as_free_func free_func;

} decode_as_t;

/** register a "Decode As".  A copy of the decode_as_t will be maintained by the decode_as module */
WS_DLL_PUBLIC void register_decode_as(decode_as_t* reg);

/* Walk though the dissector table and provide dissector_handle_t for each item in the table */
WS_DLL_PUBLIC void decode_as_default_populate_list(const gchar *table_name, decode_as_add_to_list_func add_to_list, gpointer ui_element);
/* Clear a FT_UINT32 value from dissector table list */
WS_DLL_PUBLIC gboolean decode_as_default_reset(const char *name, const gpointer pattern);
/* Add a FT_UINT32 value to dissector table list */
WS_DLL_PUBLIC gboolean decode_as_default_change(const char *name, const gpointer pattern, gpointer handle, gchar* list_name);

/** List of registered decode_as_t structs.
 * For UI code only. Should not be directly accessed by dissectors.
 */
WS_DLL_PUBLIC GList *decode_as_list;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* decode_as.h */
