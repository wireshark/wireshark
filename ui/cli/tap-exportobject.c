/* tap-exportobject.c
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include <wsutil/file_util.h>

#include <epan/packet_info.h>
#include <epan/packet.h>
#include <epan/export_object.h>
#include <ui/export_object_ui.h>
#include "tap-exportobject.h"

/* XXX - This is effectively a copy of eo_save_entry with the "GUI alerts"
 * removed to accomodate tshark
 */
static gboolean
local_eo_save_entry(const gchar *save_as_filename, export_object_entry_t *entry)
{
    int to_fd;
    gint64 bytes_left;
    int bytes_to_write;
    ssize_t bytes_written;
    guint8 *ptr;

    to_fd = ws_open(save_as_filename, O_WRONLY | O_CREAT | O_EXCL | O_BINARY, 0644);
    if(to_fd == -1) { /* An error occurred */
        return FALSE;
    }

    /*
     * The third argument to _write() on Windows is an unsigned int,
     * so, on Windows, that's the size of the third argument to
     * ws_write().
     *
     * The third argument to write() on UN*X is a size_t, although
     * the return value is an ssize_t, so one probably shouldn't
     * write more than the max value of an ssize_t.
     *
     * In either case, there's no guarantee that a gint64 such as
     * payload_len can be passed to ws_write(), so we write in
     * chunks of, at most 2^31 bytes.
     */
    ptr = entry->payload_data;
    bytes_left = entry->payload_len;
    while (bytes_left != 0) {
        if (bytes_left > 0x40000000)
            bytes_to_write = 0x40000000;
        else
            bytes_to_write = (int)bytes_left;
        bytes_written = ws_write(to_fd, ptr, bytes_to_write);
        if(bytes_written <= 0) {
            ws_close(to_fd);
            return FALSE;
        }
        bytes_left -= bytes_written;
        ptr += bytes_written;
    }
    if (ws_close(to_fd) < 0) {
        return FALSE;
    }

    return TRUE;
}

typedef struct _export_object_list_gui_t {
    GSList *entries;
    register_eo_t* eo;
} export_object_list_gui_t;

static GHashTable* eo_opts = NULL;

static gboolean
list_exportobject_protocol(const void *key, void *value _U_, void *userdata _U_)
{
    fprintf(stderr, "     %s\n", (gchar*)key);
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
            fprintf(stderr, "tshark: \"--export-objects\" already specified protocol '%s'\n", splitted[0]);
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
    gboolean all_saved = TRUE;
    gchar* save_in_path = (gchar*)g_hash_table_lookup(eo_opts, proto_get_protocol_filter_name(get_eo_proto_id(object_list->eo)));
    GString *safe_filename = NULL;
    gchar *save_as_fullpath = NULL;
    int count = 0;

    if (!g_file_test(save_in_path, G_FILE_TEST_IS_DIR)) {
        /* If the destination directory (or its parents) do not exist, create them. */
        if (g_mkdir_with_parents(save_in_path, 0755) == -1) {
            fprintf(stderr, "Failed to create export objects output directory \"%s\": %s\n",
                    save_in_path, g_strerror(errno));
            return;
        }
    }

    if ((strlen(save_in_path) < EXPORT_OBJECT_MAXFILELEN)) {
        while (slist) {
            entry = (export_object_entry_t *)slist->data;
            do {
                g_free(save_as_fullpath);
                if (entry->filename) {
                    safe_filename = eo_massage_str(entry->filename,
                        EXPORT_OBJECT_MAXFILELEN - strlen(save_in_path), count);
                } else {
                    char generic_name[EXPORT_OBJECT_MAXFILELEN+1];
                    const char *ext;
                    ext = eo_ct2ext(entry->content_type);
                    g_snprintf(generic_name, sizeof(generic_name),
                        "object%u%s%s", entry->pkt_num, ext ? "." : "", ext ? ext : "");
                    safe_filename = eo_massage_str(generic_name,
                        EXPORT_OBJECT_MAXFILELEN - strlen(save_in_path), count);
                }
                save_as_fullpath = g_build_filename(save_in_path, safe_filename->str, NULL);
                g_string_free(safe_filename, TRUE);
            } while (g_file_test(save_as_fullpath, G_FILE_TEST_EXISTS) && ++count < 1000);
            count = 0;
            if (!local_eo_save_entry(save_as_fullpath, entry))
                all_saved = FALSE;
            g_free(save_as_fullpath);
            save_as_fullpath = NULL;
            slist = slist->next;
        }
    }
    else
    {
        all_saved = FALSE;
    }

    if (!all_saved)
        fprintf(stderr, "Export objects (%s): Some files could not be saved.\n",
                    proto_get_protocol_filter_name(get_eo_proto_id(object_list->eo)));
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
        fprintf(stderr, "tshark: \"--export-objects\" INTERNAL ERROR '%s' protocol not found\n", (const char*)key);
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
                      NULL, get_eo_packet_func(eo), eo_draw);

    if (error_msg) {
        fprintf(stderr, "tshark: Can't register %s tap: %s\n", (const char*)key, error_msg->str);
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
