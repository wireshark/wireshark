/* decode_as.c
 * Routines for dissector Decode As handlers
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#include "decode_as.h"
#include "packet.h"
#include "prefs.h"
#include "prefs-int.h"

#include "epan/dissectors/packet-dcerpc.h"

#include "wsutil/filesystem.h"
#include "wsutil/file_util.h"

GList *decode_as_list = NULL;

/*
 * A list of dissectors that need to be reset.
 */
GSList *dissector_reset_list = NULL;


void register_decode_as(decode_as_t* reg)
{
    /* Ensure valid functions */
    DISSECTOR_ASSERT(reg->populate_list);
    DISSECTOR_ASSERT(reg->reset_value);
    DISSECTOR_ASSERT(reg->change_value);

    decode_as_list = g_list_append(decode_as_list, reg);
}


struct decode_as_default_populate
{
    decode_as_add_to_list_func add_to_list;
    gpointer ui_element;
};

static void
decode_proto_add_to_list (const gchar *table_name, gpointer value, gpointer user_data)
{
    struct decode_as_default_populate* populate = (struct decode_as_default_populate*)user_data;
    const gchar     *proto_name;
    gint       i;
    dissector_handle_t handle;


    handle = (dissector_handle_t)value;
    proto_name = dissector_handle_get_short_name(handle);

    i = dissector_handle_get_protocol_index(handle);
    if (i >= 0 && !proto_is_protocol_enabled(find_protocol_by_id(i)))
        return;

    populate->add_to_list(table_name, proto_name, value, populate->ui_element);
}

void decode_as_default_populate_list(const gchar *table_name, decode_as_add_to_list_func add_to_list, gpointer ui_element)
{
    struct decode_as_default_populate populate;

    populate.add_to_list = add_to_list;
    populate.ui_element = ui_element;

    dissector_table_foreach_handle(table_name, decode_proto_add_to_list, &populate);
}


gboolean decode_as_default_reset(const char *name, const gpointer pattern)
{
    dissector_reset_uint(name, GPOINTER_TO_UINT(pattern));
    return TRUE;
}

gboolean decode_as_default_change(const char *name, const gpointer pattern, gpointer handle, gchar* list_name _U_)
{
    dissector_handle_t* dissector = (dissector_handle_t*)handle;
    if (dissector != NULL)
        dissector_change_uint(name, GPOINTER_TO_UINT(pattern), *dissector);
    return TRUE;
}

/* UI-related functions */

/*
 * Data structure used as user data when iterating dissector handles
 */
struct lookup_entry {
  gchar*             dissector_short_name;
  dissector_handle_t handle;
};

/*
 * Data structure for tracking which dissector need to be reset.  This
 * structure is necessary as a hash table entry cannot be removed
 * while a g_hash_table_foreach walk is in progress.
 */
struct dissector_delete_item {
    /* The name of the dissector table */
    const gchar *ddi_table_name;
    /* The type of the selector in that dissector table */
    ftenum_t ddi_selector_type;
    /* The selector in the dissector table */
    union {
        guint   sel_uint;
        char    *sel_string;
    } ddi_selector;
};

typedef struct lookup_entry lookup_entry_t;

/*
 * A callback function to changed a dissector_handle if matched
 * This is used when iterating a dissector table
 */
static void
change_dissector_if_matched(gpointer item, gpointer user_data)
{
  dissector_handle_t handle = (dissector_handle_t)item;
  lookup_entry_t * lookup = (lookup_entry_t *)user_data;
  if (strcmp(lookup->dissector_short_name, dissector_handle_get_short_name(handle)) == 0) {
    lookup->handle = handle;
  }
}

/*
 * A callback function to parse each "decode as" entry in the file and apply the change
 */
static prefs_set_pref_e
read_set_decode_as_entries(gchar *key, const gchar *value,
			   void *user_data _U_,
			   gboolean return_range_errors _U_)
{
  gchar *values[4] = {NULL, NULL, NULL, NULL};
  gchar delimiter[4] = {',', ',', ',','\0'};
  gchar *pch;
  guint i, j;
  dissector_table_t sub_dissectors;
  prefs_set_pref_e retval = PREFS_SET_OK;

  if (strcmp(key, DECODE_AS_ENTRY) == 0) {
    /* Parse csv into table, selector, initial, current */
    for (i = 0; i < 4; i++) {
      pch = strchr(value, delimiter[i]);
      if (pch == NULL) {
	for (j = 0; j < i; j++) {
	  g_free(values[j]);
	}
	return PREFS_SET_SYNTAX_ERR;
      }
      values[i] = g_strndup(value, pch - value);
      value = pch + 1;
    }
    sub_dissectors = find_dissector_table(values[0]);
    if (sub_dissectors != NULL) {
      lookup_entry_t lookup;
      lookup.dissector_short_name = values[3];
      lookup.handle = NULL;
      g_slist_foreach(dissector_table_get_dissector_handles(sub_dissectors),
                      change_dissector_if_matched, &lookup);
      if (lookup.handle != NULL) {
	dissector_change_uint(values[0], atoi(values[1]), lookup.handle);
	decode_build_reset_list(g_strdup(values[0]), dissector_table_get_type(sub_dissectors),
                                g_strdup(values[1]), NULL, NULL);
      }
    } else {
      retval = PREFS_SET_SYNTAX_ERR;
    }

  } else {
    retval = PREFS_SET_NO_SUCH_PREF;
  }

  for (i = 0; i < 4; i++) {
    g_free(values[i]);
  }
  return retval;
}

void load_decode_as_entries(void)
{
  char   *daf_path;
  FILE   *daf;

  if (dissector_reset_list) {
    decode_clear_all();
  }

  daf_path = get_persconffile_path(DECODE_AS_ENTRIES_FILE_NAME, TRUE);
  if ((daf = ws_fopen(daf_path, "r")) != NULL) {
    read_prefs_file(daf_path, daf, read_set_decode_as_entries, NULL);
    fclose(daf);
  }
  g_free(daf_path);
}

/*
 * A typedef for the data structure to track the original dissector
 * used for any given port on any given protocol.
 */
typedef struct dissector_delete_item dissector_delete_item_t;

void
decode_build_reset_list (const gchar *table_name, ftenum_t selector_type,
                         gpointer key, gpointer value _U_,
                         gpointer user_data _U_)
{
    dissector_delete_item_t *item;

    item = g_new(dissector_delete_item_t,1);
    item->ddi_table_name = table_name;
    item->ddi_selector_type = selector_type;
    switch (selector_type) {

    case FT_UINT8:
    case FT_UINT16:
    case FT_UINT24:
    case FT_UINT32:
        item->ddi_selector.sel_uint = GPOINTER_TO_UINT(key);
        break;

    case FT_STRING:
    case FT_STRINGZ:
        item->ddi_selector.sel_string = (char *)key;
        break;

    default:
        g_assert_not_reached();
    }
    dissector_reset_list = g_slist_prepend(dissector_reset_list, item);
}

/* clear all settings */
void
decode_clear_all(void)
{
    dissector_delete_item_t *item;
    GSList *tmp;

    dissector_all_tables_foreach_changed(decode_build_reset_list, NULL);

    for (tmp = dissector_reset_list; tmp; tmp = g_slist_next(tmp)) {
        item = (dissector_delete_item_t *)tmp->data;
        switch (item->ddi_selector_type) {

        case FT_UINT8:
        case FT_UINT16:
        case FT_UINT24:
        case FT_UINT32:
            dissector_reset_uint(item->ddi_table_name,
                                 item->ddi_selector.sel_uint);
            break;

        case FT_STRING:
        case FT_STRINGZ:
            dissector_reset_string(item->ddi_table_name,
                                   item->ddi_selector.sel_string);
            break;

        default:
            g_assert_not_reached();
        }
        g_free(item);
    }
    g_slist_free(dissector_reset_list);
    dissector_reset_list = NULL;

    decode_dcerpc_reset_all();
}
