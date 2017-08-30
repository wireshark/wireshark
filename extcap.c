/* extcap.c
 *
 * Routines for extcap external capture
 * Copyright 2013, Mike Ryan <mikeryan@lacklustre.net>
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

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#include <time.h>
#else
/* Include for unlink */
#include <unistd.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#include <glib.h>
#include <log.h>

#include <epan/prefs.h>

#include "ui/iface_toolbar.h"

#include <wsutil/glib-compat.h>
#include <wsutil/file_util.h>
#include <wsutil/filesystem.h>
#include <wsutil/tempfile.h>

#include "capture_opts.h"

#include "extcap.h"
#include "extcap_parser.h"
#include "extcap_spawn.h"

#ifdef _WIN32
static HANDLE pipe_h = INVALID_HANDLE_VALUE;
#endif

static void extcap_child_watch_cb(GPid pid, gint status, gpointer user_data);

/* internal container, for all the extcap executables that have been found.
 * Will be resetted if extcap_clear_interfaces() is being explicitly called
 * and is being used for printing information about all extcap interfaces found,
 * as well as storing all sub-interfaces
 */
static GHashTable * _loaded_interfaces = NULL;

/* Internal container, which maps each ifname to the tool providing it, for faster
 * lookup. The key and string value are owned by this table.
 */
static GHashTable * _tool_for_ifname = NULL;

/* internal container, for all the extcap executables that have been found
 * and that provides a toolbar with controls to be added to a Interface Toolbar
 */
static GHashTable *_toolbars = NULL;

/* internal container, to map preference names to pointers that hold preference
 * values. These ensure that preferences can survive extcap if garbage
 * collection, and does not lead to dangling pointers in the prefs subsystem.
 */
static GHashTable *extcap_prefs_dynamic_vals = NULL;

typedef struct _extcap_callback_info_t
{
    const gchar * extcap;
    const gchar * ifname;
    gchar * output;
    void * data;
    gchar ** err_str;
} extcap_callback_info_t;

/* Callback definition for extcap_foreach */
typedef gboolean(*extcap_cb_t)(extcap_callback_info_t info_structure);

static void extcap_load_interface_list(void);

GHashTable *
extcap_loaded_interfaces(void)
{
    if ( !_loaded_interfaces || g_hash_table_size(_loaded_interfaces) == 0 )
        extcap_load_interface_list();

    return _loaded_interfaces;
}

void
extcap_clear_interfaces(void)
{
    if ( _loaded_interfaces )
        g_hash_table_destroy(_loaded_interfaces);
    _loaded_interfaces = NULL;

    if ( _tool_for_ifname )
        g_hash_table_destroy(_tool_for_ifname);
    _tool_for_ifname = NULL;
}

guint extcap_count(void)
{
    const char *dirname = get_extcap_dir();
    GDir *dir;
    guint count;

    count = 0;

    if ((dir = g_dir_open(dirname, 0, NULL)) != NULL)
    {
        GString *extcap_path = NULL;
        const gchar *file;

        extcap_path = g_string_new("");
        while ((file = g_dir_read_name(dir)) != NULL)
        {
            /* full path to extcap binary */
            g_string_printf(extcap_path, "%s" G_DIR_SEPARATOR_S "%s", dirname, file);
            /* treat anything executable as an extcap binary */
            if (g_file_test(extcap_path->str, G_FILE_TEST_IS_REGULAR) &&
                g_file_test(extcap_path->str, G_FILE_TEST_IS_EXECUTABLE))
            {
                count++;
            }
        }

        g_dir_close(dir);
        g_string_free(extcap_path, TRUE);
    }
    return count;
}

static gboolean
extcap_if_exists(const gchar *ifname)
{
    if (!ifname || !_tool_for_ifname)
    {
        return FALSE;
    }

    if (g_hash_table_lookup(_tool_for_ifname, ifname))
    {
        return TRUE;
    }

    return FALSE;
}

static extcap_interface *
extcap_find_interface_for_ifname(const gchar *ifname)
{
    extcap_interface * result = NULL;

    if ( !ifname || ! _tool_for_ifname || ! _loaded_interfaces )
        return result;

    gchar * extcap_util = (gchar *)g_hash_table_lookup(_tool_for_ifname, ifname);
    if ( ! extcap_util )
        return result;

    extcap_info * element = (extcap_info *)g_hash_table_lookup(_loaded_interfaces, extcap_util);
    if ( ! element )
        return result;

    GList * walker = element->interfaces;
    while ( walker && walker->data && ! result )
    {
        extcap_interface * interface = (extcap_interface *)walker->data;
        if ( g_strcmp0(interface->call, ifname) == 0 )
        {
            result = interface;
            break;
        }

        walker = g_list_next ( walker );
    }

    return result;
}

static void
extcap_free_toolbar_value(iface_toolbar_value *value)
{
    if (!value)
    {
        return;
    }

    g_free(value->value);
    g_free(value->display);
    g_free(value);
}

static void
extcap_free_toolbar_control(iface_toolbar_control *control)
{
    if (!control)
    {
        return;
    }

    g_free(control->display);
    g_free(control->validation);
    g_free(control->tooltip);
    if (control->ctrl_type == INTERFACE_TYPE_STRING) {
        g_free(control->default_value.string);
    }
    g_list_foreach(control->values, (GFunc)extcap_free_toolbar_value, NULL);
    g_list_free(control->values);
    g_free(control);
}

static void
extcap_free_toolbar(gpointer data)
{
    if (!data)
    {
        return;
    }

    iface_toolbar *toolbar = (iface_toolbar *)data;

    g_free(toolbar->menu_title);
    g_free(toolbar->help);
    g_list_free_full(toolbar->ifnames, g_free);
    g_list_foreach(toolbar->controls, (GFunc)extcap_free_toolbar_control, NULL);
    g_list_free(toolbar->controls);
    g_free(toolbar);
}

static gboolean
extcap_if_exists_for_extcap(const gchar *ifname, const gchar *extcap)
{
    extcap_interface *entry = extcap_find_interface_for_ifname(ifname);

    if (entry && strcmp(entry->extcap_path, extcap) == 0)
    {
        return TRUE;
    }

    return FALSE;
}

static gchar *
extcap_if_executable(const gchar *ifname)
{
    extcap_interface *interface = extcap_find_interface_for_ifname(ifname);
    return interface != NULL ? interface->extcap_path : NULL;
}

static void
extcap_iface_toolbar_add(const gchar *extcap, iface_toolbar *toolbar_entry)
{
    char *toolname;

    if (!extcap || !toolbar_entry)
    {
        return;
    }

    toolname = g_path_get_basename(extcap);

    if (!g_hash_table_lookup(_toolbars, toolname))
    {
        g_hash_table_insert(_toolbars, g_strdup(toolname), toolbar_entry);
    }

    g_free(toolname);
}

/* Note: args does not need to be NULL-terminated. */
static gboolean extcap_foreach(gint argc, gchar **args,
                                      extcap_cb_t cb, extcap_callback_info_t cb_info)
{
    GDir *dir;
    gboolean keep_going;
    const char *dirname = get_extcap_dir();

    keep_going = TRUE;

    if ((dir = g_dir_open(dirname, 0, NULL)) != NULL)
    {
        GString *extcap_path = NULL;
        const gchar *file;

        extcap_path = g_string_new("");
        while (keep_going && (file = g_dir_read_name(dir)) != NULL)
        {
            gchar *command_output = NULL;

            /* full path to extcap binary */
            g_string_printf(extcap_path, "%s" G_DIR_SEPARATOR_S "%s", dirname, file);
            /* treat anything executable as an extcap binary */
            if (g_file_test(extcap_path->str, G_FILE_TEST_IS_REGULAR) &&
                g_file_test(extcap_path->str, G_FILE_TEST_IS_EXECUTABLE))
            {
                if (extcap_if_exists(cb_info.ifname) && !extcap_if_exists_for_extcap(cb_info.ifname, extcap_path->str))
                {
                    continue;
                }

                if (extcap_spawn_sync((gchar *) dirname, extcap_path->str, argc, args, &command_output))
                {
                    cb_info.output = command_output;
                    cb_info.extcap = extcap_path->str;

                    keep_going = cb(cb_info);
                }

                g_free(command_output);
            }
        }

        g_dir_close(dir);
        g_string_free(extcap_path, TRUE);
    }

    return keep_going;
}

static void extcap_free_dlt(gpointer d, gpointer user_data _U_)
{
    if (d == NULL)
    {
        return;
    }

    g_free(((extcap_dlt *)d)->name);
    g_free(((extcap_dlt *)d)->display);
    g_free(d);
}

static void extcap_free_dlts(GList *dlts)
{
    g_list_foreach(dlts, extcap_free_dlt, NULL);
    g_list_free(dlts);
}

static gboolean cb_dlt(extcap_callback_info_t cb_info)
{
    GList *dlts = NULL, *temp = NULL;

    if_capabilities_t *caps;
    GList *linktype_list = NULL;
    data_link_info_t *data_link_info;
    extcap_dlt *dlt_item;

    dlts = extcap_parse_dlts(cb_info.output);
    temp = dlts;

    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "Extcap pipe %s ", cb_info.extcap);

    /*
     * Allocate the interface capabilities structure.
     */
    caps = (if_capabilities_t *) g_malloc(sizeof * caps);
    caps->can_set_rfmon = FALSE;

    while (dlts)
    {
        dlt_item = (extcap_dlt *)dlts->data;
        if (dlt_item)
        {
            g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG,
                  "  DLT %d name=\"%s\" display=\"%s\" ", dlt_item->number,
                  dlt_item->name, dlt_item->display);

            data_link_info = g_new(data_link_info_t, 1);
            data_link_info->dlt = dlt_item->number;
            data_link_info->name = g_strdup(dlt_item->name);
            data_link_info->description = g_strdup(dlt_item->display);
            linktype_list = g_list_append(linktype_list, data_link_info);
        }

        dlts = g_list_next(dlts);
    }

    /* Check to see if we built a list */
    if (linktype_list != NULL && cb_info.data != NULL)
    {
        caps->data_link_types = linktype_list;
        *(if_capabilities_t **) cb_info.data = caps;
    }
    else
    {
        if (cb_info.err_str)
        {
            g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "  returned no DLTs");
            *(cb_info.err_str) = g_strdup("Extcap returned no DLTs");
        }
        g_free(caps);
    }

    extcap_free_dlts(temp);

    return FALSE;
}

if_capabilities_t *
extcap_get_if_dlts(const gchar *ifname, char **err_str)
{
    gchar *argv[3];
    gint i;
    if_capabilities_t *caps = NULL;

    if (err_str != NULL)
    {
        *err_str = NULL;
    }

    if (extcap_if_exists(ifname))
    {
        argv[0] = g_strdup(EXTCAP_ARGUMENT_LIST_DLTS);
        argv[1] = g_strdup(EXTCAP_ARGUMENT_INTERFACE);
        argv[2] = g_strdup(ifname);

        extcap_callback_info_t cb_info;
        cb_info.data = &caps;
        cb_info.err_str = err_str;
        cb_info.ifname = ifname;

        extcap_foreach(3, argv, cb_dlt, cb_info);

        for (i = 0; i < 3; ++i)
        {
            g_free(argv[i]);
        }
    }

    return caps;
}

static void extcap_free_interface(gpointer i)
{

    extcap_interface *interface = (extcap_interface *)i;

    if (i == NULL)
    {
        return;
    }

    g_free(interface->call);
    g_free(interface->display);
    g_free(interface->version);
    g_free(interface->help);
    g_free(interface->extcap_path);
    g_free(interface);
}

static void extcap_free_interfaces(GList *interfaces)
{
    if (interfaces == NULL)
    {
        return;
    }

    g_list_foreach(interfaces, (GFunc)extcap_free_interface, NULL);
    g_list_free(interfaces);
}

static gint
if_info_compare(gconstpointer a, gconstpointer b)
{
    gint comp = 0;
    const if_info_t *if_a = (const if_info_t *)a;
    const if_info_t *if_b = (const if_info_t *)b;

    if ((comp = g_strcmp0(if_a->name, if_b->name)) == 0)
    {
        return g_strcmp0(if_a->friendly_name, if_b->friendly_name);
    }

    return comp;
}

gchar *
extcap_get_help_for_ifname(const char *ifname)
{
    extcap_interface *interface = extcap_find_interface_for_ifname(ifname);
    return interface != NULL ? interface->help : NULL;
}

GList *
append_extcap_interface_list(GList *list, char **err_str _U_)
{
    GList *interface_list = NULL;
    extcap_interface *data = NULL;
    GList *ifutilkeys_head = NULL, *ifutilkeys = NULL;

    /* Update the extcap interfaces and get a list of their if_infos */
    if ( !_loaded_interfaces || g_hash_table_size(_loaded_interfaces) == 0 )
        extcap_load_interface_list();

    ifutilkeys_head = g_hash_table_get_keys(_loaded_interfaces);
    ifutilkeys = ifutilkeys_head;
    while ( ifutilkeys && ifutilkeys->data )
    {
        extcap_info * extinfo =
                (extcap_info *) g_hash_table_lookup(_loaded_interfaces, (gchar *)ifutilkeys->data);
        GList * walker = extinfo->interfaces;
        while ( walker && walker->data )
        {
            interface_list = g_list_append(interface_list, walker->data);
            walker = g_list_next(walker);
        }

        ifutilkeys = g_list_next(ifutilkeys);
    }
    g_list_free(ifutilkeys_head);

    /* Sort that list */
    interface_list = g_list_sort(interface_list, if_info_compare);

    /* Append the interfaces in that list to the list we're handed. */
    while (interface_list != NULL)
    {
        GList *entry = g_list_first(interface_list);
        data = (extcap_interface *)entry->data;
        interface_list = g_list_delete_link(interface_list, entry);

        if_info_t * if_info = g_new0(if_info_t, 1);
        if_info->name = g_strdup(data->call);
        if_info->friendly_name = g_strdup(data->display);

        if_info->type = IF_EXTCAP;

        if_info->extcap = g_strdup(data->extcap_path);

        list = g_list_append(list, if_info);
    }

    return list;
}

static void
extcap_register_preferences_callback(gpointer key, gpointer value _U_, gpointer user_data _U_)
{
    GList *arguments;

    arguments = extcap_get_if_configuration((gchar *)key);
    /* Memory for prefs are external to an interface, they are part of
     * extcap core, so the parsed arguments can be freed. */
    extcap_free_if_configuration(arguments, TRUE);
}

void extcap_register_preferences(void)
{
    module_t *dev_module = prefs_find_module("extcap");

    if (!dev_module)
    {
        return;
    }

    if ( !_loaded_interfaces || g_hash_table_size(_loaded_interfaces) == 0 )
        extcap_load_interface_list();


    g_hash_table_foreach(_tool_for_ifname, extcap_register_preferences_callback, NULL);
}

/**
 * Releases the dynamic preference value pointers. Must not be called before
 * prefs_cleanup since these pointers could still be in use.
 */
void extcap_cleanup(void)
{
    if (extcap_prefs_dynamic_vals)
        g_hash_table_destroy(extcap_prefs_dynamic_vals);

    if (_loaded_interfaces)
        g_hash_table_destroy(_loaded_interfaces);

    if (_tool_for_ifname)
        g_hash_table_destroy(_tool_for_ifname);
}

/**
 * Obtains a pointer which can store a value for the given preference name.
 * The preference name that can be passed to the prefs API is stored into
 * 'prefs_name'.
 *
 * Extcap interfaces (and their preferences) are dynamic, they can be created
 * and destroyed at will. Thus their data structures are insufficient to pass to
 * the preferences APIs which require pointers which are valid until the
 * preferences are removed (at exit).
 */
static gchar **extcap_prefs_dynamic_valptr(const char *name, char **pref_name)
{
    gchar **valp;
    if (!extcap_prefs_dynamic_vals)
    {
        /* Initialize table only as needed, most preferences are not dynamic */
        extcap_prefs_dynamic_vals = g_hash_table_new_full(g_str_hash, g_str_equal,
                                    g_free, g_free);
    }
    if (!g_hash_table_lookup_extended(extcap_prefs_dynamic_vals, name,
                                      (gpointer *)pref_name, (gpointer *)&valp))
    {
        /* New dynamic pref, allocate, initialize and store. */
        valp = g_new0(gchar *, 1);
        *pref_name = g_strdup(name);
        g_hash_table_insert(extcap_prefs_dynamic_vals, *pref_name, valp);
    }
    return valp;
}

void extcap_free_if_configuration(GList *list, gboolean free_args)
{
    GList *elem, *sl;

    for (elem = g_list_first(list); elem; elem = elem->next)
    {
        if (elem->data != NULL)
        {
            sl = g_list_first((GList *)elem->data);
            if (free_args)
            {
                extcap_free_arg_list(sl);
            }
            else
            {
                g_list_free(sl);
            }
        }
    }
    g_list_free(list);
}

struct preference *
extcap_pref_for_argument(const gchar *ifname, struct _extcap_arg *arg)
{
    struct preference *pref = NULL;

    GRegex *regex_name = g_regex_new("[-]+", (GRegexCompileFlags) 0, (GRegexMatchFlags) 0, NULL);
    GRegex *regex_ifname = g_regex_new("(?![a-zA-Z1-9_]).", (GRegexCompileFlags) 0, (GRegexMatchFlags) 0, NULL);
    if (regex_name && regex_ifname)
    {
        if (prefs_find_module("extcap"))
        {
            gchar *pref_name = g_regex_replace(regex_name, arg->call, strlen(arg->call), 0, "", (GRegexMatchFlags) 0, NULL);
            gchar *ifname_underscore = g_regex_replace(regex_ifname, ifname, strlen(ifname), 0, "_", (GRegexMatchFlags) 0, NULL);
            gchar *ifname_lowercase = g_ascii_strdown(ifname_underscore, -1);
            gchar *pref_ifname = g_strconcat(ifname_lowercase, ".", pref_name, NULL);

            pref = prefs_find_preference(prefs_find_module("extcap"), pref_ifname);

            g_free(pref_name);
            g_free(ifname_underscore);
            g_free(ifname_lowercase);
            g_free(pref_ifname);
        }
    }
    if (regex_name)
    {
        g_regex_unref(regex_name);
    }
    if (regex_ifname)
    {
        g_regex_unref(regex_ifname);
    }

    return pref;
}

static gboolean cb_preference(extcap_callback_info_t cb_info)
{
    GList *arguments = NULL;
    GList **il = (GList **) cb_info.data;
    module_t *dev_module = NULL;

    arguments = extcap_parse_args(cb_info.output);

    dev_module = prefs_find_module("extcap");

    if (dev_module)
    {
        GList *walker = arguments;

        GRegex *regex_name = g_regex_new("[-]+", (GRegexCompileFlags) 0, (GRegexMatchFlags) 0, NULL);
        GRegex *regex_ifname = g_regex_new("(?![a-zA-Z1-9_]).", (GRegexCompileFlags) 0, (GRegexMatchFlags) 0, NULL);
        if (regex_name && regex_ifname)
        {
            while (walker != NULL)
            {
                extcap_arg *arg = (extcap_arg *)walker->data;
                arg->device_name = g_strdup(cb_info.ifname);

                if (arg->save)
                {
                    struct preference *pref = NULL;

                    gchar *pref_name = g_regex_replace(regex_name, arg->call, strlen(arg->call), 0, "", (GRegexMatchFlags) 0, NULL);
                    gchar *ifname_underscore = g_regex_replace(regex_ifname, cb_info.ifname, strlen(cb_info.ifname), 0, "_", (GRegexMatchFlags) 0, NULL);
                    gchar *ifname_lowercase = g_ascii_strdown(ifname_underscore, -1);
                    gchar *pref_ifname = g_strconcat(ifname_lowercase, ".", pref_name, NULL);

                    if ((pref = prefs_find_preference(dev_module, pref_ifname)) == NULL)
                    {
                        char *pref_name_for_prefs;
                        char *pref_title = wmem_strdup(wmem_epan_scope(), arg->display);

                        arg->pref_valptr = extcap_prefs_dynamic_valptr(pref_ifname, &pref_name_for_prefs);
                        /* Set an initial value if any (the string will be copied at registration) */
                        if (arg->default_complex)
                        {
                            *arg->pref_valptr = arg->default_complex->_val;
                        }

                        prefs_register_string_preference(dev_module, pref_name_for_prefs,
                                                         pref_title, pref_title, (const char **)arg->pref_valptr);
                    }
                    else
                    {
                        /* Been here before, restore stored value */
                        if (arg->pref_valptr == NULL)
                        {
                            arg->pref_valptr = (gchar**)g_hash_table_lookup(extcap_prefs_dynamic_vals, pref_ifname);
                        }
                    }

                    g_free(pref_name);
                    g_free(ifname_underscore);
                    g_free(ifname_lowercase);
                    g_free(pref_ifname);
                }

                walker = g_list_next(walker);
            }
        }
        if (regex_name)
        {
            g_regex_unref(regex_name);
        }
        if (regex_ifname)
        {
            g_regex_unref(regex_ifname);
        }
    }

    *il = g_list_append(*il, arguments);

    /* By returning false, extcap_foreach will break on first found */
    return TRUE;
}

GList *
extcap_get_if_configuration(const char *ifname)
{
    gchar *argv[3];
    GList *ret = NULL;
    gchar **err_str = NULL;
    int i;

    if (extcap_if_exists(ifname))
    {
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "Extcap path %s",
              get_extcap_dir());

        argv[0] = g_strdup(EXTCAP_ARGUMENT_CONFIG);
        argv[1] = g_strdup(EXTCAP_ARGUMENT_INTERFACE);
        argv[2] = g_strdup(ifname);

        extcap_callback_info_t cb_info;
        cb_info.data = &ret;
        cb_info.err_str = err_str;
        cb_info.ifname = ifname;

        extcap_foreach(3, argv, cb_preference, cb_info);

        for (i = 0; i < 3; i++)
        {
            g_free(argv[i]);
        }
    }

    return ret;
}

/**
 * If is_required is FALSE: returns TRUE if the extcap interface has
 * configurable options.
 * If is_required is TRUE: returns TRUE when the extcap interface has
 * configurable options that required modification. (For example, when an
 * argument is required but empty.)
 */
gboolean
extcap_has_configuration(const char *ifname, gboolean is_required)
{
    GList *arguments = 0;
    GList *walker = 0, * item = 0;

    gboolean found = FALSE;

    arguments = extcap_get_if_configuration((const char *)(ifname));
    walker = g_list_first(arguments);

    while (walker != NULL && !found)
    {
        item = g_list_first((GList *)(walker->data));
        while (item != NULL && !found)
        {
            if ((extcap_arg *)(item->data) != NULL)
            {
                extcap_arg *arg = (extcap_arg *)(item->data);
                /* Should required options be present, or any kind of options */
                if (!is_required)
                {
                    found = TRUE;
                }
                else if (arg->is_required)
                {
                    const gchar *stored = NULL;
                    const gchar *defval = NULL;

                    if (arg->pref_valptr != NULL)
                    {
                        stored = *arg->pref_valptr;
                    }

                    if (arg->default_complex != NULL && arg->default_complex->_val != NULL)
                    {
                        defval = arg->default_complex->_val;
                    }

                    if (arg->is_required)
                    {
                        /* If stored and defval is identical and the argument is required,
                         * configuration is needed */
                        if (defval && stored && g_strcmp0(stored, defval) == 0)
                        {
                            found = TRUE;
                        }
                        else if (!defval && (!stored || !*stored))
                        {
                            found = TRUE;
                        }
                    }

                    if (arg->arg_type == EXTCAP_ARG_FILESELECT)
                    {
                        if (arg->fileexists && !(file_exists(defval) || file_exists(stored)))
                        {
                            found = TRUE;
                        }
                    }
                }
            }

            item = item->next;
        }
        walker = walker->next;
    }
    extcap_free_if_configuration(arguments, TRUE);

    return found;
}

static gboolean cb_verify_filter(extcap_callback_info_t cb_info)
{
    extcap_filter_status *status = (extcap_filter_status *)cb_info.data;
    size_t output_size, i;

    output_size = strlen(cb_info.output);
    if (output_size == 0) {
        *status = EXTCAP_FILTER_VALID;
    } else {
        *status = EXTCAP_FILTER_INVALID;
        for (i = 0; i < output_size; i++) {
            if (cb_info.output[i] == '\n' || cb_info.output[i] == '\r') {
                cb_info.output[i] = '\0';
                break;
            }
        }
        *cb_info.err_str = g_strdup(cb_info.output);
    }

    return TRUE;
}

extcap_filter_status
extcap_verify_capture_filter(const char *ifname, const char *filter, gchar **err_str)
{
    gchar *argv[4];
    extcap_filter_status status = EXTCAP_FILTER_UNKNOWN;

    if (extcap_if_exists(ifname))
    {
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "Extcap path %s",
              get_extcap_dir());

        argv[0] = EXTCAP_ARGUMENT_CAPTURE_FILTER;
        argv[1] = (gchar*)filter;
        argv[2] = EXTCAP_ARGUMENT_INTERFACE;
        argv[3] = (gchar*)ifname;

        extcap_callback_info_t cb_info;
        cb_info.data = &status;
        cb_info.err_str = err_str;
        cb_info.ifname = ifname;

        extcap_foreach(4, argv, cb_verify_filter, cb_info);
    }

    return status;
}

gboolean
extcap_has_toolbar(const char *ifname)
{
    if (!iface_toolbar_use())
    {
        return FALSE;
    }

    GList *toolbar_list = g_hash_table_get_values (_toolbars);
    for (GList *walker = toolbar_list; walker; walker = walker->next)
    {
        iface_toolbar *toolbar = (iface_toolbar *) walker->data;
        if (g_list_find_custom(toolbar->ifnames, ifname, (GCompareFunc) strcmp))
        {
            return TRUE;
        }
    }

    return FALSE;
}

/* taken from capchild/capture_sync.c */
static gboolean pipe_data_available(int pipe_fd)
{
#ifdef _WIN32 /* PeekNamedPipe */
    HANDLE hPipe = (HANDLE) _get_osfhandle(pipe_fd);
    DWORD bytes_avail;

    if (hPipe == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    if (! PeekNamedPipe(hPipe, NULL, 0, NULL, &bytes_avail, NULL))
    {
        return FALSE;
    }

    if (bytes_avail > 0)
    {
        return TRUE;
    }
    return FALSE;
#else /* select */
    fd_set rfds;
    struct timeval timeout;

    FD_ZERO(&rfds);
    FD_SET(pipe_fd, &rfds);
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;

    if (select(pipe_fd + 1, &rfds, NULL, NULL, &timeout) > 0)
    {
        return TRUE;
    }

    return FALSE;
#endif
}

void extcap_if_cleanup(capture_options *capture_opts, gchar **errormsg)
{
    interface_options interface_opts;
    extcap_userdata *userdata;
    guint icnt = 0;
    gboolean overwrite_exitcode;
    gchar *buffer;
#define STDERR_BUFFER_SIZE 1024

    for (icnt = 0; icnt < capture_opts->ifaces->len; icnt++)
    {
        interface_opts = g_array_index(capture_opts->ifaces, interface_options,
                                       icnt);

        /* skip native interfaces */
        if (interface_opts.if_type != IF_EXTCAP)
        {
            continue;
        }

        overwrite_exitcode = FALSE;

        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG,
              "Extcap [%s] - Cleaning up fifo: %s; PID: %d", interface_opts.name,
              interface_opts.extcap_fifo, interface_opts.extcap_pid);
#ifdef _WIN32
        if (interface_opts.extcap_pipe_h != INVALID_HANDLE_VALUE)
        {
            g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG,
                  "Extcap [%s] - Closing pipe", interface_opts.name);
            FlushFileBuffers(interface_opts.extcap_pipe_h);
            DisconnectNamedPipe(interface_opts.extcap_pipe_h);
            CloseHandle(interface_opts.extcap_pipe_h);
            interface_opts.extcap_pipe_h = INVALID_HANDLE_VALUE;
        }
        if (interface_opts.extcap_control_in_h != INVALID_HANDLE_VALUE)
        {
            g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG,
                  "Extcap [%s] - Closing control_in pipe", interface_opts.name);
            FlushFileBuffers(interface_opts.extcap_control_in_h);
            DisconnectNamedPipe(interface_opts.extcap_control_in_h);
            CloseHandle(interface_opts.extcap_control_in_h);
            interface_opts.extcap_control_in_h = INVALID_HANDLE_VALUE;
        }
        if (interface_opts.extcap_control_out_h != INVALID_HANDLE_VALUE)
        {
            g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG,
                  "Extcap [%s] - Closing control_out pipe", interface_opts.name);
            FlushFileBuffers(interface_opts.extcap_control_out_h);
            DisconnectNamedPipe(interface_opts.extcap_control_out_h);
            CloseHandle(interface_opts.extcap_control_out_h);
            interface_opts.extcap_control_out_h = INVALID_HANDLE_VALUE;
        }
#else
        if (interface_opts.extcap_fifo != NULL && file_exists(interface_opts.extcap_fifo))
        {
            /* the fifo will not be freed here, but with the other capture_opts in capture_sync */
            ws_unlink(interface_opts.extcap_fifo);
            interface_opts.extcap_fifo = NULL;
        }
        if (interface_opts.extcap_control_in && file_exists(interface_opts.extcap_control_in))
        {
            ws_unlink(interface_opts.extcap_control_in);
            interface_opts.extcap_control_in = NULL;
        }
        if (interface_opts.extcap_control_out && file_exists(interface_opts.extcap_control_out))
        {
            ws_unlink(interface_opts.extcap_control_out);
            interface_opts.extcap_control_out = NULL;
        }
#endif
        /* Maybe the client closed and removed fifo, but ws should check if
         * pid should be closed */
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG,
              "Extcap [%s] - Closing spawned PID: %d", interface_opts.name,
              interface_opts.extcap_pid);

        userdata = (extcap_userdata *) interface_opts.extcap_userdata;
        if (userdata)
        {
            if (userdata->extcap_stderr_rd > 0 && pipe_data_available(userdata->extcap_stderr_rd))
            {
                buffer = (gchar *)g_malloc0(sizeof(gchar) * STDERR_BUFFER_SIZE + 1);
#ifdef _WIN32
                win32_readfrompipe((HANDLE)_get_osfhandle(userdata->extcap_stderr_rd), STDERR_BUFFER_SIZE, buffer);
#else
                if (read(userdata->extcap_stderr_rd, buffer, sizeof(gchar) * STDERR_BUFFER_SIZE) <= 0)
                {
                    buffer[0] = '\0';
                }
#endif
                if (strlen(buffer) > 0)
                {
                    userdata->extcap_stderr = g_strdup_printf("%s", buffer);
                    userdata->exitcode = 1;
                }
                g_free(buffer);
            }

#ifndef _WIN32
            /* Final child watch may not have been called */
            if (interface_opts.extcap_child_watch != 0)
            {
                extcap_child_watch_cb(userdata->pid, 0, capture_opts);
                /* it will have changed in extcap_child_watch_cb */
                interface_opts = g_array_index(capture_opts->ifaces, interface_options,
                                               icnt);
            }
#endif

            if (userdata->extcap_stderr != NULL)
            {
                overwrite_exitcode = TRUE;
            }

            if (overwrite_exitcode || userdata->exitcode != 0)
            {
                if (userdata->extcap_stderr != 0)
                {
                    if (*errormsg == NULL)
                    {
                        *errormsg = g_strdup_printf("Error by extcap pipe: %s", userdata->extcap_stderr);
                    }
                    else
                    {
                        gchar *temp = g_strconcat(*errormsg, "\nError by extcap pipe: " , userdata->extcap_stderr, NULL);
                        g_free(*errormsg);
                        *errormsg = temp;
                    }
                    g_free(userdata->extcap_stderr);
                }

                userdata->extcap_stderr = NULL;
                userdata->exitcode = 0;
            }
        }

        if (interface_opts.extcap_child_watch > 0)
        {
            g_source_remove(interface_opts.extcap_child_watch);
            interface_opts.extcap_child_watch = 0;
        }

        if (interface_opts.extcap_pid != INVALID_EXTCAP_PID)
        {
#ifdef _WIN32
            TerminateProcess(interface_opts.extcap_pid, 0);
#endif
            g_spawn_close_pid(interface_opts.extcap_pid);
            interface_opts.extcap_pid = INVALID_EXTCAP_PID;

            g_free(interface_opts.extcap_userdata);
            interface_opts.extcap_userdata = NULL;
        }

        /* Make sure modified interface_opts is saved in capture_opts. */
        capture_opts->ifaces = g_array_remove_index(capture_opts->ifaces, icnt);
        g_array_insert_val(capture_opts->ifaces, icnt, interface_opts);
    }
}

static gboolean
extcap_add_arg_and_remove_cb(gpointer key, gpointer value, gpointer data)
{
    GPtrArray *args = (GPtrArray *)data;

    if (key != NULL)
    {
        g_ptr_array_add(args, g_strdup((const gchar *)key));

        if (value != NULL)
        {
            g_ptr_array_add(args, g_strdup((const gchar *)value));
        }

        return TRUE;
    }

    return FALSE;
}

void extcap_child_watch_cb(GPid pid, gint status, gpointer user_data)
{
    guint i;
    interface_options interface_opts;
    extcap_userdata *userdata = NULL;
    capture_options *capture_opts = (capture_options *)(user_data);

    if (capture_opts == NULL || capture_opts->ifaces == NULL || capture_opts->ifaces->len == 0)
    {
        return;
    }

    /* Close handle to child process. */
    g_spawn_close_pid(pid);

    /* Update extcap_pid in interface options structure. */
    for (i = 0; i < capture_opts->ifaces->len; i++)
    {
        interface_opts = g_array_index(capture_opts->ifaces, interface_options, i);
        if (interface_opts.extcap_pid == pid)
        {
            userdata = (extcap_userdata *)interface_opts.extcap_userdata;
            if (userdata != NULL)
            {
                interface_opts.extcap_pid = INVALID_EXTCAP_PID;
                userdata->exitcode = 0;
#ifndef _WIN32
                if (WIFEXITED(status))
                {
                    if (WEXITSTATUS(status) != 0)
                    {
                        userdata->exitcode = WEXITSTATUS(status);
                    }
                }
                else
                {
                    userdata->exitcode = G_SPAWN_ERROR_FAILED;
                }
#else
                if (status != 0)
                {
                    userdata->exitcode = status;
                }
#endif
                if (status == 0 && userdata->extcap_stderr != NULL)
                {
                    userdata->exitcode = 1;
                }
            }
            g_source_remove(interface_opts.extcap_child_watch);
            interface_opts.extcap_child_watch = 0;

            capture_opts->ifaces = g_array_remove_index(capture_opts->ifaces, i);
            g_array_insert_val(capture_opts->ifaces, i, interface_opts);
            break;
        }
    }
}

static
GPtrArray *extcap_prepare_arguments(interface_options interface_opts)
{
    GPtrArray *result = NULL;

    if (interface_opts.if_type == IF_EXTCAP)
    {
        result = g_ptr_array_new();

#define add_arg(X) g_ptr_array_add(result, g_strdup(X))

        add_arg(interface_opts.extcap);
        add_arg(EXTCAP_ARGUMENT_RUN_CAPTURE);
        add_arg(EXTCAP_ARGUMENT_INTERFACE);
        add_arg(interface_opts.name);
        if (interface_opts.cfilter && strlen(interface_opts.cfilter) > 0)
        {
            add_arg(EXTCAP_ARGUMENT_CAPTURE_FILTER);
            add_arg(interface_opts.cfilter);
        }
        add_arg(EXTCAP_ARGUMENT_RUN_PIPE);
        add_arg(interface_opts.extcap_fifo);
        if (interface_opts.extcap_control_in)
        {
            add_arg(EXTCAP_ARGUMENT_CONTROL_OUT);
            add_arg(interface_opts.extcap_control_in);
        }
        if (interface_opts.extcap_control_out)
        {
            add_arg(EXTCAP_ARGUMENT_CONTROL_IN);
            add_arg(interface_opts.extcap_control_out);
        }
        if (interface_opts.extcap_args == NULL || g_hash_table_size(interface_opts.extcap_args) == 0)
        {
            /* User did not perform interface configuration.
             *
             * Check if there are any boolean flags that are set by default
             * and hence their argument should be added.
             */
            GList *arglist;
            GList *elem;

            arglist = extcap_get_if_configuration(interface_opts.name);
            for (elem = g_list_first(arglist); elem; elem = elem->next)
            {
                GList *arg_list;
                extcap_arg *arg_iter;

                if (elem->data == NULL)
                {
                    continue;
                }

                arg_list = g_list_first((GList *)elem->data);
                while (arg_list != NULL)
                {
                    const gchar *stored = NULL, * defval = NULL;
                    /* In case of boolflags only first element in arg_list is relevant. */
                    arg_iter = (extcap_arg *)(arg_list->data);
                    if (arg_iter->pref_valptr != NULL && strlen(*arg_iter->pref_valptr) > 0)
                    {
                        stored = *arg_iter->pref_valptr;
                    }

                    if (arg_iter->default_complex != NULL && arg_iter->default_complex->_val != NULL)
                    {
                        defval = arg_iter->default_complex->_val;
                    }

                    /* Different data in storage then set for default */
                    if (g_strcmp0(stored, defval) != 0)
                    {
                        if (arg_iter->arg_type == EXTCAP_ARG_BOOLFLAG)
                        {
                            if (g_strcmp0(stored, "true") == 0)
                            {
                                add_arg(arg_iter->call);
                            }
                        }
                        else
                        {
                            add_arg(arg_iter->call);
                            add_arg(stored);
                        }
                    }
                    else if (arg_iter->arg_type == EXTCAP_ARG_BOOLFLAG)
                    {
                        if (extcap_complex_get_bool(arg_iter->default_complex))
                        {
                            add_arg(arg_iter->call);
                        }
                    }

                    arg_list = arg_list->next;
                }
            }

            extcap_free_if_configuration(arglist, TRUE);
        }
        else
        {
            g_hash_table_foreach_remove(interface_opts.extcap_args, extcap_add_arg_and_remove_cb, result);
        }
        add_arg(NULL);
#undef add_arg

    }

    return result;
}

/* call mkfifo for each extcap,
 * returns FALSE if there's an error creating a FIFO */
gboolean
extcap_init_interfaces(capture_options *capture_opts)
{
    guint i;
    interface_options interface_opts;
    extcap_userdata *userdata;

    for (i = 0; i < capture_opts->ifaces->len; i++)
    {
        GPtrArray *args = NULL;
        GPid pid = INVALID_EXTCAP_PID;

        interface_opts = g_array_index(capture_opts->ifaces, interface_options, i);

        /* skip native interfaces */
        if (interface_opts.if_type != IF_EXTCAP)
        {
            continue;
        }

        /* create control pipes if having toolbar */
        if (extcap_has_toolbar(interface_opts.name))
        {
            extcap_create_pipe(interface_opts.name, &interface_opts.extcap_control_in,
                               EXTCAP_CONTROL_IN_PREFIX, FALSE);
#ifdef _WIN32
            interface_opts.extcap_control_in_h = pipe_h;
#endif
            extcap_create_pipe(interface_opts.name, &interface_opts.extcap_control_out,
                               EXTCAP_CONTROL_OUT_PREFIX, FALSE);
#ifdef _WIN32
            interface_opts.extcap_control_out_h = pipe_h;
#endif
        }

        /* create pipe for fifo */
        if (!extcap_create_pipe(interface_opts.name, &interface_opts.extcap_fifo,
                                EXTCAP_PIPE_PREFIX, TRUE))
        {
            return FALSE;
        }
#ifdef _WIN32
        interface_opts.extcap_pipe_h = pipe_h;
#endif

        /* Create extcap call */
        args = extcap_prepare_arguments(interface_opts);

        userdata = g_new0(extcap_userdata, 1);

        pid = extcap_spawn_async(userdata, args);

        g_ptr_array_foreach(args, (GFunc)g_free, NULL);
        g_ptr_array_free(args, TRUE);

        if (pid == INVALID_EXTCAP_PID)
        {
            g_free(userdata);
            continue;
        }

        interface_opts.extcap_pid = pid;

        interface_opts.extcap_child_watch =
            g_child_watch_add(pid, extcap_child_watch_cb, (gpointer)capture_opts);

#ifdef _WIN32
        /* On Windows, wait for extcap to connect to named pipe.
         * Some extcaps will present UAC screen to user.
         * 30 second timeout should be reasonable timeout for extcap to
         * connect to named pipe (including user interaction).
         * Wait on multiple object in case of extcap termination
         * without opening pipe.
         *
         * Minimum supported version of Windows: XP / Server 2003.
         */
        if (pid != INVALID_EXTCAP_PID)
        {
            HANDLE pipe_handles[3];
            int num_pipe_handles = 1;
            pipe_handles[0] = interface_opts.extcap_pipe_h;

            if (extcap_has_toolbar(interface_opts.name))
            {
                pipe_handles[1] = interface_opts.extcap_control_in_h;
                pipe_handles[2] = interface_opts.extcap_control_out_h;
                num_pipe_handles += 2;
             }

            extcap_wait_for_pipe(pipe_handles, num_pipe_handles, pid);
        }
#endif

        interface_opts.extcap_userdata = (gpointer) userdata;

        capture_opts->ifaces = g_array_remove_index(capture_opts->ifaces, i);
        g_array_insert_val(capture_opts->ifaces, i, interface_opts);
    }

    return TRUE;
}

gboolean extcap_create_pipe(const gchar *ifname, gchar **fifo, const gchar *pipe_prefix, gboolean byte_mode _U_)
{
#ifdef _WIN32
    gchar timestr[ 14 + 1 ];
    time_t current_time;
    gchar *pipename = NULL;
    SECURITY_ATTRIBUTES security;

    /* create pipename */
    current_time = time(NULL);
    /*
     * XXX - we trust Windows not to return a time before the Epoch here,
     * so we won't get a null pointer back from localtime().
     */
    strftime(timestr, sizeof(timestr), "%Y%m%d%H%M%S", localtime(&current_time));
    pipename = g_strconcat("\\\\.\\pipe\\", pipe_prefix, "_", ifname, "_", timestr, NULL);

    /* Security struct to enable Inheritable HANDLE */
    memset(&security, 0, sizeof(SECURITY_ATTRIBUTES));
    security.nLength = sizeof(SECURITY_ATTRIBUTES);
    security.bInheritHandle = TRUE;
    security.lpSecurityDescriptor = NULL;

    /* create a namedPipe */
    pipe_h = CreateNamedPipe(
                 utf_8to16(pipename),
                 PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                 byte_mode ? PIPE_TYPE_BYTE : PIPE_TYPE_MESSAGE | byte_mode ? PIPE_READMODE_BYTE : PIPE_READMODE_MESSAGE | PIPE_WAIT,
                 1, 65536, 65536,
                 300,
                 &security);

    if (pipe_h == INVALID_HANDLE_VALUE)
    {
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "\nError creating pipe => (%d)", GetLastError());
        g_free (pipename);
        return FALSE;
    }
    else
    {
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "\nWireshark Created pipe =>(%s)", pipename);
        *fifo = g_strdup(pipename);
    }
#else
    gchar *temp_name = NULL;
    int fd = 0;

    gchar *pfx = g_strconcat(pipe_prefix, "_", ifname, NULL);
    if ((fd = create_tempfile(&temp_name, pfx, NULL)) < 0)
    {
        g_free(pfx);
        return FALSE;
    }
    g_free(pfx);

    ws_close(fd);

    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG,
          "Extcap - Creating fifo: %s", temp_name);

    if (file_exists(temp_name))
    {
        ws_unlink(temp_name);
    }

    if (mkfifo(temp_name, 0600) == 0)
    {
        *fifo = g_strdup(temp_name);
    }
#endif

    return TRUE;
}

/************* EXTCAP LOAD INTERFACE LIST ***************
 *
 * The following code handles loading and reloading the interface list. It is explicitly
 * kept separate from the rest
 */


static void
extcap_free_interface_info(gpointer data)
{
    extcap_info *info = (extcap_info *)data;

    g_free(info->basename);
    g_free(info->full_path);
    g_free(info->version);
    g_free(info->help);

    extcap_free_interfaces(info->interfaces);

    g_free(info);
}

static extcap_info *
extcap_ensure_interface(const gchar * toolname, gboolean create_if_nonexist)
{
    extcap_info * element = 0;

    if ( ! toolname )
        return element;

    if ( ! _loaded_interfaces )
        _loaded_interfaces = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, extcap_free_interface);

    element = (extcap_info *) g_hash_table_lookup(_loaded_interfaces, toolname );
    if ( ! element && create_if_nonexist )
    {
        g_hash_table_insert(_loaded_interfaces, g_strdup(toolname), g_new0(extcap_info, 1));
        element = (extcap_info *) g_hash_table_lookup(_loaded_interfaces, toolname );
    }

    return element;
}

extcap_info *
extcap_get_tool_by_ifname(const gchar *ifname)
{
    if ( ifname && _tool_for_ifname )
    {
        gchar * toolname = (gchar *)g_hash_table_lookup(_tool_for_ifname, ifname);
        if ( toolname )
            return extcap_ensure_interface(toolname, FALSE);
    }

    return NULL;
}

extcap_info *
extcap_get_tool_info(const gchar * toolname)
{
    return extcap_ensure_interface(toolname, FALSE);
}

static void remove_extcap_entry(gpointer entry, gpointer data _U_)
{
    extcap_interface *int_iter = (extcap_interface*)entry;

    if (int_iter->if_type == EXTCAP_SENTENCE_EXTCAP)
        extcap_free_interface(entry);
}

static gboolean cb_load_interfaces(extcap_callback_info_t cb_info)
{
    GList * interfaces = NULL, * control_items = NULL, * walker = NULL;
    extcap_interface * int_iter = NULL;
    extcap_info * element = NULL;
    iface_toolbar * toolbar_entry = NULL;
    gchar * toolname = g_path_get_basename(cb_info.extcap);

    GList * interface_keys = g_hash_table_get_keys(_loaded_interfaces);

    /* Load interfaces from utility */
    interfaces = extcap_parse_interfaces(cb_info.output, &control_items);

    if (control_items)
    {
        toolbar_entry = g_new0(iface_toolbar, 1);
        toolbar_entry->controls = control_items;
    }

    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "Loading interface list for %s ", cb_info.extcap);

    /* Seems, that there where no interfaces to be loaded */
    if ( ! interfaces || g_list_length(interfaces) == 0 )
    {
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "Cannot load interfaces for %s", cb_info.extcap );
        /* Some utilities, androiddump for example, may actually don't present any interfaces, even
         * if the utility itself is present. In such a case, we return here, but do not return
         * FALSE, or otherwise further loading of other utilities will be stopped */
        g_list_free(interface_keys);
        g_free(toolname);
        return TRUE;
    }

    /* Load or create the storage element for the tool */
    element = extcap_ensure_interface(toolname, TRUE);
    if ( element == NULL )
    {
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_ERROR, "Cannot store interface %s, maybe duplicate?", cb_info.extcap );
        g_list_foreach(interfaces, remove_extcap_entry, NULL);
        g_list_free(interfaces);
        g_list_free(interface_keys);
        g_free(toolname);
        return FALSE;
    }

    walker = interfaces;
    gchar* help = NULL;
    while (walker != NULL)
    {
        int_iter = (extcap_interface *)walker->data;

        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "Interface found %s\n", int_iter->call);

        /* Help is not necessarily stored with the interface, but rather with the version string.
         * As the version string allways comes in front of the interfaces, this ensures, that it get's
         * properly stored with the interface */
        if (int_iter->if_type == EXTCAP_SENTENCE_EXTCAP)
        {
            g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "  Extcap [%s] ", int_iter->call);
            /* Only initialize values if none are set. Need to check only one element here */
            if ( ! element->version )
            {
                element->version = g_strdup(int_iter->version);
                element->basename = g_strdup(toolname);
                element->full_path = g_strdup(cb_info.extcap);
                element->help = g_strdup(int_iter->help);
            }

            help = int_iter->help;
            if (toolbar_entry)
            {
                toolbar_entry->menu_title = g_strdup(int_iter->display);
                toolbar_entry->help = g_strdup(int_iter->help);
            }

            walker = g_list_next(walker);
            continue;
        }

        /* Only interface definitions will be parsed here. help is already set by the extcap element,
         * which makes it necessary to have version in the list before the interfaces. This is normally
         * the case by design, but could be changed by separating the information in extcap-base. */
        if ( int_iter->if_type == EXTCAP_SENTENCE_INTERFACE )
        {
            if ( g_list_find(interface_keys, int_iter->call) )
            {
                g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_WARNING, "Extcap interface \"%s\" is already provided by \"%s\" ",
                      int_iter->call, (gchar *)extcap_if_executable(int_iter->call));
                walker = g_list_next(walker);
                continue;
            }

            g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "  Interface [%s] \"%s\" ",
                  int_iter->call, int_iter->display);

            int_iter->extcap_path = g_strdup(cb_info.extcap);

            /* Only set the help, if it exists and no parsed help information is present */
            if ( ! int_iter->help && help )
                int_iter->help = g_strdup(help);

            element->interfaces = g_list_append(element->interfaces, int_iter);
            g_hash_table_insert(_tool_for_ifname, g_strdup(int_iter->call), g_strdup(toolname));

            if (toolbar_entry)
            {
                if (!toolbar_entry->menu_title)
                {
                    toolbar_entry->menu_title = g_strdup(int_iter->display);
                }
                toolbar_entry->ifnames = g_list_append(toolbar_entry->ifnames, g_strdup(int_iter->call));
            }
        }

        walker = g_list_next(walker);
    }

    if (toolbar_entry && toolbar_entry->menu_title)
    {
        iface_toolbar_add(toolbar_entry);
        extcap_iface_toolbar_add(cb_info.extcap, toolbar_entry);
    }

    g_list_foreach(interfaces, remove_extcap_entry, NULL);
    g_list_free(interfaces);
    g_list_free(interface_keys);
    g_free(toolname);
    return TRUE;
}


/* Handles loading of the interfaces.
 *
 * A list of interfaces can be obtained by calling \ref extcap_loaded_interfaces
 */
static void
extcap_load_interface_list(void)
{
    gchar *argv;
    gchar *error;

    if (_toolbars)
    {
        // Remove existing interface toolbars here instead of in extcap_clear_interfaces()
        // to avoid flicker in shown toolbars when refreshing interfaces.
        GList *toolbar_list = g_hash_table_get_values (_toolbars);
        for (GList *walker = toolbar_list; walker; walker = walker->next)
        {
            iface_toolbar *toolbar = (iface_toolbar *) walker->data;
            iface_toolbar_remove(toolbar->menu_title);
        }
        g_hash_table_remove_all(_toolbars);
    } else {
        _toolbars = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, extcap_free_toolbar);
    }

    if (_loaded_interfaces == NULL)
    {
        _loaded_interfaces = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, extcap_free_interface_info);
        /* Cleanup lookup table */
        if ( _tool_for_ifname )
        {
            g_hash_table_remove_all(_tool_for_ifname);
            _tool_for_ifname = 0;
        } else {
            _tool_for_ifname = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
        }

        argv = g_strdup(EXTCAP_ARGUMENT_LIST_INTERFACES);

        extcap_callback_info_t cb_info;
        cb_info.data = NULL;
        cb_info.ifname = NULL;
        cb_info.err_str = &error;

        extcap_foreach(1, &argv, cb_load_interfaces, cb_info);

        g_free(argv);
    }
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
