/* tap-exportobject.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include <wsutil/file_util.h>
#include <ui/cmdarg_err.h>

#include <epan/packet_info.h>
#include <epan/packet.h>
#include <epan/export_object.h>
#include <ui/export_object_ui.h>
#include "tap-exportobject.h"

typedef struct _export_object_list_gui_t {
    GSList *entries;
    register_eo_t* eo;
} export_object_list_gui_t;

static GHashTable* eo_opts = NULL;

static gboolean
list_exportobject_protocol(const void *key, void *value _U_, void *userdata _U_)
{
    fprintf(stderr, "     %s\n", (const gchar*)key);
    return FALSE;
}

void eo_list_object_types(void)
{
    eo_iterate_tables(list_exportobject_protocol, NULL);
}

gboolean eo_tap_opt_add(const char *option_string)
{
    gchar** splitted;

    if (!eo_opts)
        eo_opts = g_hash_table_new(g_str_hash,g_str_equal);

    splitted = g_strsplit(option_string, ",", 2);

    if ((splitted[0] == NULL) || (splitted[1] == NULL) || (get_eo_by_name(splitted[0]) == NULL))
    {
        fprintf(stderr, "tshark: \"--export-objects\" are specified as: <protocol>,<destdir>\n");
        fprintf(stderr, "tshark: The available export object types for the \"--export-objects\" option are:\n");
        eo_list_object_types();
    }
    else
    {
        gchar* dir = (gchar*)g_hash_table_lookup(eo_opts, splitted[0]);

        /* Since we're saving all objects from a protocol,
            it can only be listed once */
        if (dir == NULL) {
            g_hash_table_insert(eo_opts, splitted[0], splitted[1]);

            g_free(splitted);
            return TRUE;
        }
        else
        {
            cmdarg_err("\"--export-objects\" already specified protocol '%s'", splitted[0]);
        }
    }

    g_strfreev(splitted);
    return FALSE;
}

static void
object_list_add_entry(void *gui_data, export_object_entry_t *entry)
{
    export_object_list_gui_t *object_list = (export_object_list_gui_t*)gui_data;

    object_list->entries = g_slist_append(object_list->entries, entry);
}

static export_object_entry_t*
object_list_get_entry(void *gui_data, int row) {
    export_object_list_gui_t *object_list = (export_object_list_gui_t*)gui_data;

    return (export_object_entry_t *)g_slist_nth_data(object_list->entries, row);
}

/* This is just for writing Exported Objects to a file */
static void
eo_draw(void *tapdata)
{
    export_object_list_t *tap_object = (export_object_list_t *)tapdata;
    export_object_list_gui_t *object_list = (export_object_list_gui_t*)tap_object->gui_data;
    GSList *slist = object_list->entries;
    export_object_entry_t *entry;
    gchar* save_in_path = (gchar*)g_hash_table_lookup(eo_opts, proto_get_protocol_filter_name(get_eo_proto_id(object_list->eo)));
    GString *safe_filename = NULL;
    gchar *save_as_fullpath = NULL;
    guint count = 0;

    if (!g_file_test(save_in_path, G_FILE_TEST_IS_DIR)) {
        /* If the destination directory (or its parents) do not exist, create them. */
        if (g_mkdir_with_parents(save_in_path, 0755) == -1) {
            fprintf(stderr, "Failed to create export objects output directory \"%s\": %s\n",
                    save_in_path, g_strerror(errno));
            return;
        }
    }

    while (slist) {
        entry = (export_object_entry_t *)slist->data;
        do {
            g_free(save_as_fullpath);
            if (entry->filename) {
                safe_filename = eo_massage_str(entry->filename,
                    EXPORT_OBJECT_MAXFILELEN, count);
            } else {
                char generic_name[EXPORT_OBJECT_MAXFILELEN+1];
                const char *ext;
                ext = eo_ct2ext(entry->content_type);
                g_snprintf(generic_name, sizeof(generic_name),
                    "object%u%s%s", entry->pkt_num, ext ? "." : "", ext ? ext : "");
                safe_filename = eo_massage_str(generic_name,
                    EXPORT_OBJECT_MAXFILELEN, count);
            }
            save_as_fullpath = g_build_filename(save_in_path, safe_filename->str, NULL);
            g_string_free(safe_filename, TRUE);
        } while (g_file_test(save_as_fullpath, G_FILE_TEST_EXISTS) && ++count < prefs.gui_max_export_objects);
        count = 0;
        eo_save_entry(save_as_fullpath, entry);
        g_free(save_as_fullpath);
        save_as_fullpath = NULL;
        slist = slist->next;
    }
}

static void
exportobject_handler(gpointer key, gpointer value _U_, gpointer user_data _U_)
{
    GString *error_msg;
    export_object_list_t *tap_data;
    export_object_list_gui_t *object_list;
    register_eo_t* eo;

    eo = get_eo_by_name((const char*)key);
    if (eo == NULL)
    {
        cmdarg_err("\"--export-objects\" INTERNAL ERROR '%s' protocol not found", (const char*)key);
        return;
    }

    tap_data = g_new0(export_object_list_t,1);
    object_list = g_new0(export_object_list_gui_t,1);

    tap_data->add_entry = object_list_add_entry;
    tap_data->get_entry = object_list_get_entry;
    tap_data->gui_data = (void*)object_list;

    object_list->eo = eo;

    /* Data will be gathered via a tap callback */
    error_msg = register_tap_listener(get_eo_tap_listener_name(eo), tap_data, NULL, 0,
                      NULL, get_eo_packet_func(eo), eo_draw, NULL);

    if (error_msg) {
        cmdarg_err("Can't register %s tap: %s", (const char*)key, error_msg->str);
        g_string_free(error_msg, TRUE);
        g_free(tap_data);
        g_free(object_list);
        return;
    }
}

void start_exportobjects(void)
{
    if (eo_opts != NULL)
        g_hash_table_foreach(eo_opts, exportobject_handler, NULL);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
