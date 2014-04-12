/* decode_as_utils.c
 *
 * Routines to modify dissector tables on the fly.
 *
 * By David Hampton <dhampton@mac.com>
 * Copyright 2001 David Hampton
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

#include <stdlib.h>

#include <stdio.h>
#include <errno.h>

#include "epan/decode_as.h"
#include "epan/packet.h"
#include "epan/prefs.h"
#include "epan/prefs-int.h"

#include "epan/dissectors/packet-dcerpc.h"

#include "ui/decode_as_utils.h"
#include "ui/simple_dialog.h"

#include "wsutil/file_util.h"
#include "wsutil/filesystem.h"

#include "version_info.h"

/*
 * A list of dissectors that need to be reset.
 */
static GSList *dissector_reset_list = NULL;

/*
 * Data structure used as user data when iterating dissector handles
 */
typedef struct lookup_entry {
    gchar*             dissector_short_name;
    dissector_handle_t handle;
} lookup_entry_t;

/*
 * Data structure for tracking which dissector need to be reset.  This
 * structure is necessary as a hash table entry cannot be removed
 * while a g_hash_table_foreach walk is in progress.
 */
typedef struct dissector_delete_item {
    /* The name of the dissector table */
    const gchar *ddi_table_name;
    /* The type of the selector in that dissector table */
    ftenum_t ddi_selector_type;
    /* The selector in the dissector table */
    union {
        guint   sel_uint;
        char    *sel_string;
    } ddi_selector;
} dissector_delete_item_t;

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
    gboolean is_valid = FALSE;

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
            ftenum_t selector_type;

            lookup.dissector_short_name = values[3];
            lookup.handle = NULL;
            selector_type = dissector_table_get_type(sub_dissectors);

            g_slist_foreach(dissector_table_get_dissector_handles(sub_dissectors),
                    change_dissector_if_matched, &lookup);
            if (lookup.handle != NULL || g_ascii_strcasecmp(values[3], DECODE_AS_NONE) == 0) {
                is_valid = TRUE;
            }

            if (is_valid) {
                if (IS_FT_STRING(selector_type)) {
                    dissector_change_string(values[0], values[1], lookup.handle);
                } else {
                    dissector_change_uint(values[0], atoi(values[1]), lookup.handle);
                }
                decode_build_reset_list(g_strdup(values[0]), selector_type,
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

void
load_decode_as_entries(void)
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
    case FT_UINT_STRING:
    case FT_STRINGZPAD:
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
        case FT_UINT_STRING:
        case FT_STRINGZPAD:
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

/* XXX - We might want to switch this to a UAT */
FILE *
decode_as_open(void) {
    char *pf_dir_path;
    char *daf_path;
    FILE *da_file;

    if (create_persconffile_dir(&pf_dir_path) == -1) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                "Can't create directory\n\"%s\"\nfor recent file: %s.", pf_dir_path,
                g_strerror(errno));
        g_free(pf_dir_path);
        return NULL;
    }

    daf_path = get_persconffile_path(DECODE_AS_ENTRIES_FILE_NAME, TRUE);
    if ((da_file = ws_fopen(daf_path, "w")) == NULL) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
            "Can't open decode_as_entries file\n\"%s\": %s.", daf_path,
            g_strerror(errno));
        g_free(daf_path);
        return NULL;
    }

    fputs("# \"Decode As\" entries file for Wireshark " VERSION ".\n"
        "#\n"
        "# This file is regenerated each time \"Decode As\" preferences\n"
        "# are saved within Wireshark. Making manual changes should be safe,"
        "# however.\n", da_file);

    return da_file;
}

/* XXX We might want to have separate int and string routines. */
void
decode_as_write_entry(FILE *da_file, const char *table_name, const char *selector, const char *default_proto, const char *current_proto) {
    fprintf (da_file,
             DECODE_AS_ENTRY ": %s,%s,%s,%s\n",
             table_name, selector, default_proto, current_proto);
}


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

