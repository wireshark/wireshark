/* plugins.c
 * plugin routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <time.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <glib.h>
#include <gmodule.h>

#include <wsutil/filesystem.h>
#include <wsutil/privileges.h>
#include <wsutil/file_util.h>
#include <wsutil/report_message.h>

#include <wsutil/plugins.h>
#include <wsutil/ws_printf.h> /* ws_debug_printf */

typedef struct _plugin {
    GModule        *handle;       /* handle returned by g_module_open */
    gchar          *name;         /* plugin name */
    const gchar    *version;      /* plugin version */
    const gchar    *type_name;    /* user-facing name (what it does). Should these be capitalized? */
} plugin;

#define TYPE_DIR_EPAN       "epan"
#define TYPE_DIR_WIRETAP    "wiretap"
#define TYPE_DIR_CODECS     "codecs"

#define TYPE_NAME_DISSECTOR "dissector"
#define TYPE_NAME_FILE_TYPE "file type"
#define TYPE_NAME_CODEC     "codec"


static GSList *plugins_module_list = NULL;


static inline const char *
type_to_dir(plugin_type_e type)
{
    switch (type) {
    case WS_PLUGIN_EPAN:
        return TYPE_DIR_EPAN;
    case WS_PLUGIN_WIRETAP:
        return TYPE_DIR_WIRETAP;
    case WS_PLUGIN_CODEC:
        return TYPE_DIR_CODECS;
    default:
        g_error("Unknown plugin type: %u. Aborting.", (unsigned) type);
        break;
    }
    g_assert_not_reached();
}

static inline const char *
type_to_name(plugin_type_e type)
{
    switch (type) {
    case WS_PLUGIN_EPAN:
        return TYPE_NAME_DISSECTOR;
    case WS_PLUGIN_WIRETAP:
        return TYPE_NAME_FILE_TYPE;
    case WS_PLUGIN_CODEC:
        return TYPE_NAME_CODEC;
    default:
        g_error("Unknown plugin type: %u. Aborting.", (unsigned) type);
        break;
    }
    g_assert_not_reached();
}

static void
free_plugin(gpointer data)
{
    plugin *p = (plugin *)data;
    g_module_close(p->handle);
    g_free(p->name);
    g_free(p);
}

static gint
compare_plugins(gconstpointer a, gconstpointer b)
{
    return g_strcmp0((*(plugin *const *)a)->name, (*(plugin *const *)b)->name);
}

static gboolean
pass_plugin_version_compatibility(GModule *handle, const char *name)
{
    gpointer symb;
    int major, minor;

    if(!g_module_symbol(handle, "plugin_want_major", &symb)) {
        report_failure("The plugin '%s' has no \"plugin_want_major\" symbol", name);
        return FALSE;
    }
    major = *(int *)symb;

    if(!g_module_symbol(handle, "plugin_want_minor", &symb)) {
        report_failure("The plugin '%s' has no \"plugin_want_minor\" symbol", name);
        return FALSE;
    }
    minor = *(int *)symb;

    if (major != VERSION_MAJOR || minor != VERSION_MINOR) {
        report_failure("The plugin '%s' was compiled for Wireshark version %d.%d",
                            name, major, minor);
        return FALSE;
    }

    return TRUE;
}

static void
scan_plugins_dir(GHashTable *plugins_module, const char *dirpath, plugin_type_e type, gboolean append_type)
{
    GDir          *dir;
    const char    *name;            /* current file name */
    gchar         *plugin_folder;
    gchar         *plugin_file;     /* current file full path */
    GModule       *handle;          /* handle returned by g_module_open */
    gpointer       symbol;
    const char    *plug_version;
    plugin        *new_plug;

    if (append_type)
        plugin_folder = g_build_filename(dirpath, type_to_dir(type), (gchar *)NULL);
    else
        plugin_folder = g_strdup(dirpath);

    dir = g_dir_open(plugin_folder, 0, NULL);
    if (dir == NULL) {
        g_free(plugin_folder);
        return;
    }

    while ((name = g_dir_read_name(dir)) != NULL) {
        /* Skip anything but files with G_MODULE_SUFFIX. */
        if (!g_str_has_suffix(name, "." G_MODULE_SUFFIX))
            continue;

        /*
         * Check if the same name is already registered.
         */
        if (g_hash_table_lookup(plugins_module, name)) {
            /* Yes, it is. */
            report_warning("The plugin '%s' was found "
                                "in multiple directories", name);
            continue;
        }

        plugin_file = g_build_filename(plugin_folder, name, (gchar *)NULL);
        handle = g_module_open(plugin_file, G_MODULE_BIND_LOCAL);
        g_free(plugin_file);
        if (handle == NULL) {
            /* g_module_error() provides file path. */
            report_failure("Couldn't load plugin '%s': %s", name,
                            g_module_error());
            continue;
        }

        if (!g_module_symbol(handle, "plugin_version", &symbol))
        {
            report_failure("The plugin '%s' has no \"plugin_version\" symbol", name);
            g_module_close(handle);
            continue;
        }
        plug_version = (const char *)symbol;

        if (!pass_plugin_version_compatibility(handle, name)) {
            g_module_close(handle);
            continue;
        }

        /* Search for the entry point for the plugin registration function */
        if (!g_module_symbol(handle, "plugin_register", &symbol)) {
            report_failure("The plugin '%s' has no \"plugin_register\" symbol", name);
            g_module_close(handle);
            continue;
        }

DIAG_OFF_PEDANTIC
        /* Found it, call the plugin registration function. */
        ((plugin_register_func)symbol)();
DIAG_ON_PEDANTIC

        new_plug = (plugin *)g_malloc(sizeof(plugin));
        new_plug->handle = handle;
        new_plug->name = g_strdup(name);
        new_plug->version = plug_version;
        new_plug->type_name = type_to_name(type);

        /* Add it to the list of plugins. */
        g_hash_table_replace(plugins_module, new_plug->name, new_plug);
    }
    ws_dir_close(dir);
    g_free(plugin_folder);
}

/*
 * Scan for plugins.
 */
plugins_t *
plugins_init(plugin_type_e type)
{
    if (!g_module_supported())
        return NULL; /* nothing to do */

    GHashTable *plugins_module = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, free_plugin);

    /*
     * Scan the global plugin directory.
     */
    scan_plugins_dir(plugins_module, get_plugins_dir_with_version(), type, TRUE);

    /*
     * If the program wasn't started with special privileges,
     * scan the users plugin directory.  (Even if we relinquish
     * them, plugins aren't safe unless we've *permanently*
     * relinquished them, and we can't do that in Wireshark as,
     * if we need privileges to start capturing, we'd need to
     * reclaim them before each time we start capturing.)
     */
    if (!started_with_special_privs()) {
        scan_plugins_dir(plugins_module, get_plugins_pers_dir_with_version(), type, TRUE);
    }

    plugins_module_list = g_slist_prepend(plugins_module_list, plugins_module);

    return plugins_module;
}

WS_DLL_PUBLIC void
plugins_get_descriptions(plugin_description_callback callback, void *callback_data)
{
    GPtrArray *plugins_array = g_ptr_array_new();
    GHashTableIter iter;
    gpointer value;

    for (GSList *l = plugins_module_list; l != NULL; l = l->next) {
        g_hash_table_iter_init (&iter, (GHashTable *)l->data);
        while (g_hash_table_iter_next (&iter, NULL, &value)) {
            g_ptr_array_add(plugins_array, value);
        }
    }

    g_ptr_array_sort(plugins_array, compare_plugins);

    for (guint i = 0; i < plugins_array->len; i++) {
        plugin *plug = (plugin *)plugins_array->pdata[i];
        callback(plug->name, plug->version, plug->type_name, g_module_name(plug->handle), callback_data);
    }

    g_ptr_array_free(plugins_array, TRUE);
}

static void
print_plugin_description(const char *name, const char *version,
                         const char *description, const char *filename,
                         void *user_data _U_)
{
    ws_debug_printf("%-16s\t%s\t%s\t%s\n", name, version, description, filename);
}

void
plugins_dump_all(void)
{
    plugins_get_descriptions(print_plugin_description, NULL);
}

int
plugins_get_count(void)
{
    guint count = 0;

    for (GSList *l = plugins_module_list; l != NULL; l = l->next) {
        count += g_hash_table_size((GHashTable *)l->data);
    }
    return count;
}

void
plugins_cleanup(plugins_t *plugins)
{
    if (!plugins)
        return;

    plugins_module_list = g_slist_remove(plugins_module_list, plugins);
    g_hash_table_destroy((GHashTable *)plugins);
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
