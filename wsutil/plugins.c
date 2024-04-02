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
#define WS_LOG_DOMAIN LOG_DOMAIN_PLUGINS
#include "plugins.h"

#include <time.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <gmodule.h>

#include <wsutil/filesystem.h>
#include <wsutil/privileges.h>
#include <wsutil/file_util.h>
#include <wsutil/report_message.h>
#include <wsutil/wslog.h>

typedef struct _plugin {
    GModule        *handle;       /* handle returned by g_module_open */
    char           *name;         /* plugin name */
    struct ws_module *module;
    plugin_scope_e  scope;
} plugin;

#define TYPE_DIR_EPAN       "epan"
#define TYPE_DIR_WIRETAP    "wiretap"
#define TYPE_DIR_CODECS     "codecs"

static GSList *plugins_module_list;


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
        ws_error("Unknown plugin type: %u. Aborting.", (unsigned) type);
        break;
    }
    ws_assert_not_reached();
}

static inline const char *
type_to_name(plugin_type_e type)
{
    switch (type) {
    case WS_PLUGIN_EPAN:
        return "epan";
    case WS_PLUGIN_WIRETAP:
        return "wiretap";
    case WS_PLUGIN_CODEC:
        return "codec";
    default:
        return "unknown";
    }
    ws_assert_not_reached();
}

static inline const char *
flags_to_str(uint32_t flags)
{
    /* XXX: Allow joining multiple types? Our plugins only implement a
     * single type but out in the wild this may not be true. */
    if (flags & WS_PLUGIN_DESC_DISSECTOR)
        return "dissector";
    else if (flags & WS_PLUGIN_DESC_FILE_TYPE)
        return "file type";
    else if (flags & WS_PLUGIN_DESC_CODEC)
        return "codec";
    else if (flags & WS_PLUGIN_DESC_EPAN)
        return "epan";
    else if (flags & WS_PLUGIN_DESC_TAP_LISTENER)
        return "tap listener";
    else if (flags & WS_PLUGIN_DESC_DFUNCTION)
        return "dfunction";
    else
        return "unknown";
}

static void
free_plugin(void * data)
{
    plugin *p = (plugin *)data;
    g_module_close(p->handle);
    g_free(p->name);
    g_free(p);
}

static int
compare_plugins(gconstpointer a, gconstpointer b)
{
    return g_strcmp0((*(plugin *const *)a)->name, (*(plugin *const *)b)->name);
}

static bool
pass_plugin_compatibility(const char *name, plugin_type_e type,
                            int abi_version, int min_api_level)
{
    if (abi_version != plugins_abi_version(type)) {
        report_failure("The plugin '%s' has incompatible ABI, have version %d, expected %d",
                            name, abi_version, plugins_abi_version(type));
        return false;
    }

    /* Check if the minimum requested API level is supported by this version
        * of Wireshark (only used with codec plugins). */
    if (min_api_level > 0 && min_api_level > plugins_api_max_level(type)) {
        report_failure("The plugin '%s' requires API level %d, have %d",
                            name, min_api_level, plugins_api_max_level(type));
        return false;
    }

    return true;
}

static void
scan_plugins_dir(GHashTable *plugins_module, const char *dirpath,
                        plugin_type_e type, plugin_scope_e scope)
{
    GDir          *dir;
    const char    *name;            /* current file name */
    char          *plugin_folder;
    char          *plugin_file;     /* current file full path */
    char          *plugin_ext;      /* plugin file extension */
    GModule       *handle;          /* handle returned by g_module_open */
    void          *symbol;
    plugin        *new_plug;
    plugin_type_e have_type;
    int            abi_version;
    int            min_api_level;
    struct ws_module *module;
    char          *s;

    plugin_folder = g_build_filename(dirpath, type_to_dir(type), (char *)NULL);

    dir = g_dir_open(plugin_folder, 0, NULL);
    if (dir == NULL) {
        g_free(plugin_folder);
        return;
    }

    plugin_ext = plugins_file_suffix(type);

    ws_debug("Scanning plugins folder \"%s\" for *%s", plugin_folder, plugin_ext);

    while ((name = g_dir_read_name(dir)) != NULL) {
        /* Skip anything but files with .dll or .so. */
        if (!g_str_has_suffix(name, plugin_ext))
            continue;

        plugin_file = g_build_filename(plugin_folder, name, (char *)NULL);

        /*
         * Check if the same name is already registered.
         */
        if (g_hash_table_lookup(plugins_module, name)) {
            /* Yes, it is. In that case ignore it without
             * requiring user intervention. There are situations
             * where this is a legitimate case, like the user overwriting
             * the system plugin with their own updated version. They may not have
             * permissions to replace the system plugin. We still log a
             * message to the console in case this catches someone by surprise,
             * and while it is not ideal to have duplicate plugins (at a minimum
             * it is inneficient), it doesn't raise to the level of warning,
             * i.e something that requires corrective action. */
            ws_message("The plugin name '%s' is already registered, ignoring the "
                       "file \"%s\"", name, plugin_file);
            g_free(plugin_file);
            continue;
        }

        handle = g_module_open(plugin_file, G_MODULE_BIND_LOCAL);
        if (handle == NULL) {
            /* g_module_error() provides file path. */
            report_failure("Couldn't load plugin '%s': %s", name,
                            g_module_error());
            g_free(plugin_file);
            continue;
        }

        /* Search for the entry point for the plugin registration function */
        if (!g_module_symbol(handle, "wireshark_load_module", &symbol)) {
            report_failure("The plugin '%s' has no \"wireshark_load_module\" symbol", name);
            g_module_close(handle);
            g_free(plugin_file);
            continue;
        }

DIAG_OFF_PEDANTIC
        /* Found it, load module. */
        have_type = ((ws_load_module_func)symbol)(&abi_version, &min_api_level, &module);
DIAG_ON_PEDANTIC

        if (have_type != type) {
            // Should not happen. Our filesystem hierarchy uses plugin type.
            report_failure("The plugin '%s' has invalid type, expected %s, have %s",
                                name, type_to_name(type), type_to_name(have_type));
            g_module_close(handle);
            g_free(plugin_file);
            continue;
        }

        if (!pass_plugin_compatibility(name, type, abi_version, min_api_level)) {
            g_module_close(handle);
            g_free(plugin_file);
            continue;
        }

        /* Call the plugin registration function. */
        module->register_cb();

        new_plug = g_new(plugin, 1);
        new_plug->handle = handle;
        new_plug->name = g_strdup(name);
        new_plug->module = module;
        new_plug->scope = scope;

        // Strip version from plugin display name
        s = strrchr(new_plug->name, '.');
        if (s != NULL && g_ascii_isdigit(*(s+1)))
            *s = '\0';

        /* Add it to the list of plugins. */
        g_hash_table_replace(plugins_module, g_strdup(name), new_plug);
        ws_info("Registered plugin: %s (%s)", new_plug->name, plugin_file);
        ws_debug("plugin '%s' meta data: version = %s, flags = 0x%"PRIu32", spdx = %s, blurb = %s",
                    name, module->version, module->flags, module->spdx_id, module->blurb);
        g_free(plugin_file);
    }
    ws_dir_close(dir);
    wmem_free(NULL, plugin_ext);
    g_free(plugin_folder);
}

/*
 * Scan for plugins.
 */
plugins_t *
plugins_init(plugin_type_e type)
{
    if (!plugins_supported())
        return NULL; /* nothing to do */

    GHashTable *plugins_module = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, free_plugin);

    /* Scan the users plugins directory first, giving it priority over the
     * global plugins folder. Only scan it if we weren't started with special
     * privileges.  (Even if we relinquish
     * them, plugins aren't safe unless we've *permanently*
     * relinquished them, and we can't do that in Wireshark as,
     * if we need privileges to start capturing, we'd need to
     * reclaim them before each time we start capturing.)
     */
    const char *user_dir = get_plugins_pers_dir();
    if (!started_with_special_privs()) {
        scan_plugins_dir(plugins_module, user_dir, type, WS_PLUGIN_SCOPE_USER);
    }
    else {
        ws_info("Skipping the personal plugin folder because we were "
                   "started with special privileges");
    }

    /*
     * Scan the global plugin directory. Make sure we don't scan the same directory
     * twice (under some unusual install configurations).
     */
    const char *global_dir = get_plugins_dir();
    if (strcmp(global_dir, user_dir) != 0) {
        scan_plugins_dir(plugins_module, global_dir, type, WS_PLUGIN_SCOPE_GLOBAL);
    }
    else {
        ws_warning("Skipping the global plugin folder because it is the same path as the personal folder");
    }

    plugins_module_list = g_slist_prepend(plugins_module_list, plugins_module);

    return plugins_module;
}

WS_DLL_PUBLIC void
plugins_get_descriptions(plugin_description_callback callback, void *callback_data)
{
    GPtrArray *plugins_array = g_ptr_array_new();
    GHashTableIter iter;
    void * value;

    for (GSList *l = plugins_module_list; l != NULL; l = l->next) {
        g_hash_table_iter_init (&iter, (GHashTable *)l->data);
        while (g_hash_table_iter_next (&iter, NULL, &value)) {
            g_ptr_array_add(plugins_array, value);
        }
    }

    g_ptr_array_sort(plugins_array, compare_plugins);

    for (unsigned i = 0; i < plugins_array->len; i++) {
        plugin *plug = (plugin *)plugins_array->pdata[i];
        callback(plug->name, plug->module->version, plug->module->flags, plug->module->spdx_id,
                    plug->module->blurb, plug->module->home_url,
                    g_module_name(plug->handle), plug->scope,
                    callback_data);
    }

    g_ptr_array_free(plugins_array, true);
}

void
plugins_print_description(const char *name, const char *version,
                         uint32_t flags, const char *spdx_id _U_,
                         const char *blurb _U_, const char *home_url _U_,
                         const char *filename, plugin_scope_e scope _U_,
                         void *user_data _U_)
{
    printf("%-16s\t%s\t%s\t%s\n", name, version, flags_to_str(flags), filename);
}

void
plugins_dump_all(void)
{
    plugins_get_descriptions(plugins_print_description, NULL);
}

int
plugins_get_count(void)
{
    unsigned count = 0;

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

bool
plugins_supported(void)
{
#ifndef HAVE_PLUGINS
    return false;
#else
    return g_module_supported();
#endif
}

plugin_type_e
plugins_check_file(const char *from_filename)
{
    char          *name;
    GModule       *handle;
    void          *symbol;
    plugin_type_e  have_type;
    int            abi_version;
    int            min_api_level;

    handle = g_module_open(from_filename, G_MODULE_BIND_LAZY);
    if (handle == NULL) {
        /* g_module_error() provides file path. */
        report_failure("Couldn't load file: %s", g_module_error());
        return WS_PLUGIN_NONE;
    }

    /* Search for the entry point for the plugin registration function */
    if (!g_module_symbol(handle, "wireshark_load_module", &symbol)) {
        report_failure("The file '%s' has no \"wireshark_load_module\" symbol", from_filename);
        return WS_PLUGIN_NONE;
    }

DIAG_OFF_PEDANTIC
    /* Load module. */
    have_type = ((ws_load_module_func)symbol)(&abi_version, &min_api_level, NULL);
DIAG_ON_PEDANTIC

    name = g_path_get_basename(from_filename);

    if (!pass_plugin_compatibility(name, have_type, abi_version, min_api_level)) {
        g_module_close(handle);
        g_free(name);
        return WS_PLUGIN_NONE;
    }

    g_module_close(handle);
    g_free(name);
    return have_type;
}

char *
plugins_pers_type_folder(plugin_type_e type)
{
    return g_build_filename(get_plugins_pers_dir(),
                type_to_dir(type), (const char *)NULL);
}

char *
plugins_file_suffix(plugin_type_e type)
{
    return ws_strdup_printf("%s.%d", WS_PLUGIN_MODULE_SUFFIX, plugins_abi_version(type));
}

int
plugins_api_max_level(plugin_type_e type)
{
    /*
     * The API level is only defined for codecs because it is a small
     * and easy to define API.
     * Maybe we could do the same for wiretap (file type) plugins?
     * For the various epan plugin types it seems pointless and futile.
     */
    switch (type) {
        case WS_PLUGIN_CODEC:   return WIRESHARK_API_MAX_LEVEL_CODEC;
        default: return 0;
    }
    ws_assert_not_reached();

}

int
plugins_abi_version(plugin_type_e type)
{
    switch (type) {
        case WS_PLUGIN_EPAN:    return WIRESHARK_ABI_VERSION_EPAN;
        case WS_PLUGIN_WIRETAP: return WIRESHARK_ABI_VERSION_WIRETAP;
        case WS_PLUGIN_CODEC:   return WIRESHARK_ABI_VERSION_CODEC;
        default: return -1;
    }
    ws_assert_not_reached();
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
