/* plugins.c
 * plugin routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include "config.h"

#ifdef HAVE_PLUGINS

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
    const gchar    *type;         /* type of plugin */
} plugin;

/* array of plugins */
static GPtrArray *plugins_array = NULL;
/* map of names to plugin */
static GHashTable *plugins_table = NULL;

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
    return g_strcmp0((*(const plugin **)a)->name, (*(const plugin **)b)->name);
}

static void
plugins_scan_dir(GPtrArray **plugins_ptr, const char *dirpath, const char *type_name, gboolean build_dir)
{
    GDir          *dir;
    const char    *name;            /* current file name */
    gchar         *path;            /* current file full path */
    GModule       *handle;          /* handle returned by g_module_open */
    gpointer       symbol;
    const char    *plug_version, *plug_release;
    plugin        *new_plug;
    gchar         *dot;

    dir = g_dir_open(dirpath, 0, NULL);
    if (dir == NULL)
        return;

    while ((name = g_dir_read_name(dir)) != NULL) {
        /* Skip anything but files with G_MODULE_SUFFIX. */
        dot = strrchr(name, '.');
        if (dot == NULL || strcmp(dot+1, G_MODULE_SUFFIX) != 0)
            continue;

#if WIN32
        if (strncmp(name, "nordic_ble.dll", 14) == 0) {
            /*
             * Skip the Nordic BLE Sniffer dll on WIN32 because
             * the dissector has been added as internal.
             */
            continue;
        }
#endif

        /*
         * Check if the same name is already registered.
         */
        if (g_hash_table_lookup(plugins_table, name)) {
            /* Yes, it is. */
            if (!build_dir) {
                report_warning("The plugin '%s' was found "
                                "in multiple directories", name);
            }
            continue;
        }

        path = g_build_filename(dirpath, name, (gchar *)NULL);
        handle = g_module_open(path, G_MODULE_BIND_LOCAL);
        g_free(path);
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

        if (!g_module_symbol(handle, "plugin_release", &symbol))
        {
            report_failure("The plugin '%s' has no \"plugin_release\" symbol", name);
            g_module_close(handle);
            continue;
        }
        plug_release = (const char *)symbol;
        if (strcmp(plug_release, VERSION_RELEASE) != 0) {
            report_failure("The plugin '%s' was compiled for Wireshark version %s", name, plug_release);
            g_module_close(handle);
            continue;
        }

        /* Search for the entry point for the plugin type */
        if (!g_module_symbol(handle, "plugin_register", &symbol)) {
            report_failure("The plugin '%s' has no \"plugin_register\" symbol", name);
            g_module_close(handle);
            continue;
        }

DIAG_OFF(pedantic)
        /* Found it, call the plugin registration function. */
        ((plugin_register_func)symbol)();
DIAG_ON(pedantic)

        new_plug = (plugin *)g_malloc(sizeof(plugin));
        new_plug->handle = handle;
        new_plug->name = g_strdup(name);
        new_plug->version = plug_version;
        if (build_dir)
            new_plug->type = "[build]";
        else
            new_plug->type = type_name;

        /* Add it to the list of plugins. */
        if (*plugins_ptr == NULL)
            *plugins_ptr = g_ptr_array_new_with_free_func(free_plugin);
        g_ptr_array_add(*plugins_ptr, new_plug);
        g_ptr_array_add(plugins_array, new_plug);
        g_hash_table_insert(plugins_table, new_plug->name, new_plug);
    }
    ws_dir_close(dir);
}

/*
 * Scan the buildir for plugins.
 */
static void
scan_plugins_build_dir(GPtrArray **plugins_ptr, const char *type_name)
{
    const char *plugin_dir;
    const char *name;
    char *plugin_dir_path;
    WS_DIR *dir;                /* scanned directory */
    WS_DIRENT *file;            /* current file */

    plugin_dir = get_plugins_dir();
    if ((dir = ws_dir_open(plugin_dir, 0, NULL)) == NULL)
        return;

    plugins_scan_dir(plugins_ptr, plugin_dir, type_name, TRUE);
    while ((file = ws_dir_read_name(dir)) != NULL)
    {
        name = ws_dir_get_name(file);
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
            continue;        /* skip "." and ".." */
        /*
         * Get the full path of a ".libs" subdirectory of that
         * directory.
         */
        plugin_dir_path = g_build_filename(plugin_dir, name, ".libs", (gchar *)NULL);
        if (test_for_directory(plugin_dir_path) != EISDIR) {
            /*
             * Either it doesn't refer to a directory or it
             * refers to something that doesn't exist.
             *
             * Assume that means that the plugins are in
             * the subdirectory of the plugin directory, not
             * a ".libs" subdirectory of that subdirectory.
             */
            g_free(plugin_dir_path);
            plugin_dir_path = g_build_filename(plugin_dir, name, (gchar *)NULL);
        }
        plugins_scan_dir(plugins_ptr, plugin_dir_path, type_name, TRUE);
        g_free(plugin_dir_path);
    }
    ws_dir_close(dir);
}

/*
 * Scan for plugins.
 */
plugins_t *
plugins_init(const char *type_name)
{
    if (!g_module_supported())
        return NULL; /* nothing to do */

    gchar *dirpath;
    GPtrArray *plugins = NULL;

    if (plugins_table == NULL)
        plugins_table = g_hash_table_new(g_str_hash, g_str_equal);
    if (plugins_array == NULL)
        plugins_array = g_ptr_array_new();

    /*
     * Scan the global plugin directory.
     * If we're running from a build directory, scan the "plugins"
     * subdirectory, as that's where plugins are located in an
     * out-of-tree build. If we find subdirectories scan those since
     * they will contain plugins in the case of an in-tree build.
     */
    if (running_in_build_directory())
    {
        scan_plugins_build_dir(&plugins, type_name);
    }
    else
    {
        dirpath = g_build_filename(get_plugins_dir_with_version(), type_name, (gchar *)NULL);
        plugins_scan_dir(&plugins, dirpath, type_name, FALSE);
        g_free(dirpath);
    }

    /*
     * If the program wasn't started with special privileges,
     * scan the users plugin directory.  (Even if we relinquish
     * them, plugins aren't safe unless we've *permanently*
     * relinquished them, and we can't do that in Wireshark as,
     * if we need privileges to start capturing, we'd need to
     * reclaim them before each time we start capturing.)
     */
    if (!started_with_special_privs())
    {
        dirpath = g_build_filename(get_plugins_pers_dir_with_version(), type_name, (gchar *)NULL);
        plugins_scan_dir(&plugins, dirpath, type_name, FALSE);
        g_free(dirpath);
    }

    g_ptr_array_sort(plugins_array, compare_plugins);

    return plugins;
}

WS_DLL_PUBLIC void
plugins_get_descriptions(plugin_description_callback callback, void *callback_data)
{
    if (!plugins_array)
        return;

    for (guint i = 0; i < plugins_array->len; i++) {
        plugin *plug = (plugin *)plugins_array->pdata[i];
        callback(plug->name, plug->version, plug->type, g_module_name(plug->handle), callback_data);
    }
}

static void
print_plugin_description(const char *name, const char *version,
                         const char *description, const char *filename,
                         void *user_data _U_)
{
    ws_debug_printf("%s\t%s\t%s\t%s\n", name, version, description, filename);
}

void
plugins_dump_all(void)
{
    plugins_get_descriptions(print_plugin_description, NULL);
}

int
plugins_get_count(void)
{
    if (plugins_table)
        return g_hash_table_size(plugins_table);
    return 0;
}

void
plugins_cleanup(plugins_t *plugins)
{
    if (plugins)
        g_ptr_array_free((GPtrArray *)plugins, TRUE);

    /*
     * This module uses global bookkeeping data structures and per-library
     * objects sharing data. To avoid having to walk the plugins GPtrArray
     * and delete each plugin from the global data structures we purge them
     * once the first plugin cleanup function is called. This means that after
     * calling ONE OF POSSIBLY MANY plugin cleanup function NO OTHER plugin
     * APIs can be used except plugins_cleanup. If it ever becomes an issue
     * it will be easy to change, for a small performance penalty.
     */
    if (plugins_table) {
        g_hash_table_destroy(plugins_table);
        plugins_table = NULL;
    }
    if (plugins_array) {
        g_ptr_array_free(plugins_array, FALSE);
        plugins_array = NULL;
    }
}

#endif /* HAVE_PLUGINS */

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
