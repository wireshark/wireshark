/* extcap.c
 *
 * Routines for extcap external capture
 * Copyright 2013, Mike Ryan <mikeryan@lacklustre.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>
#define WS_LOG_DOMAIN LOG_DOMAIN_EXTCAP

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

#include <sys/types.h>
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#include <glib.h>

#include <epan/prefs.h>

#include "ui/iface_toolbar.h"

#include <wsutil/file_util.h>
#include <wsutil/filesystem.h>
#include <wsutil/ws_pipe.h>
#include <wsutil/tempfile.h>
#include <wsutil/wslog.h>
#include <wsutil/ws_assert.h>

#include "capture/capture_session.h"
#include "capture_opts.h"

#include "extcap.h"
#include "extcap_parser.h"

#include "ui/version_info.h"

/* Number of seconds to wait for extcap process to exit after cleanup.
 * If extcap does not exit before the timeout, it is forcefully terminated.
 */
#ifdef _WIN32
/* Extcap interface does not specify SIGTERM replacement on Windows yet */
#define EXTCAP_CLEANUP_TIMEOUT 0
#else
#define EXTCAP_CLEANUP_TIMEOUT 30
#endif

/* internal container, for all the extcap executables that have been found.
 * Will be reset if extcap_clear_interfaces() is being explicitly called
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
static GHashTable *_extcap_prefs_dynamic_vals = NULL;

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

/** GThreadPool does not support pushing new work from a thread while waiting
 * for the thread pool to finish. This data structure tracks ongoing work.
 * See https://gitlab.gnome.org/GNOME/glib/issues/1598 */
typedef struct thread_pool {
    GThreadPool    *pool;
    gint            count;  /**< Number of tasks that have not finished. */
    GCond           cond;
    GMutex          data_mutex;
} thread_pool_t;

/**
 * Callback definition for extcap_run_all, invoked with a thread pool (to
 * schedule new tasks), an opaque data parameter, and the output from last task
 * (or NULL if it failed). The output must be freed by the callback function.
 * The implementation MUST be thread-safe.
 */
typedef void (*extcap_run_cb_t)(thread_pool_t *pool, void *data, char *output);

typedef struct extcap_run_task {
    const char     *extcap_path;
    char          **argv;       /**< NULL-terminated arguments list, freed when the task is completed. */
    extcap_run_cb_t output_cb;
    void           *data;       /** Parameter to be passed to output_cb. */
} extcap_run_task_t;

typedef struct extcap_iface_info {
    char *ifname;                       /**< Interface name. */
    char *output;                       /**< Output of --extcap-config. */
} extcap_iface_info_t;

typedef struct extcap_run_extcaps_info {
    char    *extcap_path;               /**< Extcap program path, MUST be the first member.  */
    char    *output;                    /**< Output of --extcap-interfaces. */
    guint   num_interfaces;             /**< Number of discovered interfaces. */
    extcap_iface_info_t *iface_infos;   /**< Per-interface information. */
} extcap_run_extcaps_info_t;


static void extcap_load_interface_list(void);

/* Used for lazily loading our interfaces. */
static void extcap_ensure_all_interfaces_loaded(void) {
    if ( !_loaded_interfaces || g_hash_table_size(_loaded_interfaces) == 0 )
        extcap_load_interface_list();
}

static gboolean
thread_pool_push(thread_pool_t *pool, gpointer data, GError **error)
{
    g_mutex_lock(&pool->data_mutex);
    ++pool->count;
    g_mutex_unlock(&pool->data_mutex);
    return g_thread_pool_push(pool->pool, data, error);
}

static void
thread_pool_wait(thread_pool_t *pool)
{
    g_mutex_lock(&pool->data_mutex);
    while (pool->count != 0) {
        g_cond_wait(&pool->cond, &pool->data_mutex);
    }
    g_mutex_unlock(&pool->data_mutex);
}

static GHashTable *
extcap_loaded_interfaces(void)
{
    if (prefs.capture_no_extcap)
        return NULL;

    extcap_ensure_all_interfaces_loaded();

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

static gint
compare_tools(gconstpointer a, gconstpointer b)
{
    return g_strcmp0((*(extcap_info *const *)a)->basename, (*(extcap_info *const *)b)->basename);
}

void
extcap_get_descriptions(plugin_description_callback callback, void *callback_data)
{
    extcap_ensure_all_interfaces_loaded();

    GHashTable * tools = extcap_loaded_interfaces();
    GPtrArray *tools_array = g_ptr_array_new();

    if (tools && g_hash_table_size(tools) > 0) {
        GList * keys = g_hash_table_get_keys(tools);
        GList * walker = g_list_first(keys);
        while (walker && walker->data) {
            extcap_info * tool = (extcap_info *)g_hash_table_lookup(tools, walker->data);
            if (tool) {
                g_ptr_array_add(tools_array, tool);
            }
            walker = g_list_next(walker);
        }
        g_list_free(keys);
    }

    g_ptr_array_sort(tools_array, compare_tools);

    for (guint i = 0; i < tools_array->len; i++) {
        extcap_info *tool = (extcap_info *)tools_array->pdata[i];
        callback(tool->basename, tool->version, "extcap", tool->full_path, callback_data);
    }

    g_ptr_array_free(tools_array, TRUE);
}

static void
print_extcap_description(const char *basename, const char *version,
                        const char *description, const char *filename,
                        void *user_data _U_)
{
    printf("%-16s\t%s\t%s\t%s\n", basename, version, description, filename);
}

void
extcap_dump_all(void)
{
    extcap_get_descriptions(print_extcap_description, NULL);
}

static GSList *
extcap_get_extcap_paths_from_dir(GSList * list, const char * dirname)
{
    GDir * dir;
    const char * file;

    GSList * paths = list;

    if ((dir = g_dir_open(dirname, 0, NULL)) != NULL) {
        while ((file = g_dir_read_name(dir)) != NULL) {
            /* full path to extcap binary */
            gchar *extcap_path = ws_strdup_printf("%s" G_DIR_SEPARATOR_S "%s", dirname, file);
            /* treat anything executable as an extcap binary */
            if (g_file_test(extcap_path, G_FILE_TEST_IS_REGULAR) &&
                g_file_test(extcap_path, G_FILE_TEST_IS_EXECUTABLE)) {
                paths = g_slist_append(paths, extcap_path);
            } else {
                g_free(extcap_path);
            }

        }
        g_dir_close(dir);
    }

    return paths;
}

/**
 * Obtains a list of extcap program paths. Use g_slist_free_full(paths, g_free)
 * to destroy the list.
 */
static GSList *
extcap_get_extcap_paths(void)
{
    GSList *paths = NULL;

    char *persconffile_path = get_persconffile_path("extcap", FALSE);
    paths = extcap_get_extcap_paths_from_dir(paths, persconffile_path);
    g_free(persconffile_path);

    paths = extcap_get_extcap_paths_from_dir(paths, get_extcap_dir());

    return paths;
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
    g_list_free_full(toolbar->controls, (GDestroyNotify)extcap_free_toolbar_control);
    g_free(toolbar);
}

static gchar *
extcap_if_executable(const gchar *ifname)
{
    extcap_interface *interface = extcap_find_interface_for_ifname(ifname);
    return interface != NULL ? interface->extcap_path : NULL;
}

static gboolean
extcap_iface_toolbar_add(const gchar *extcap, iface_toolbar *toolbar_entry)
{
    char *toolname;
    gboolean ret = FALSE;

    if (!extcap || !toolbar_entry)
    {
        return ret;
    }

    toolname = g_path_get_basename(extcap);

    if (!g_hash_table_lookup(_toolbars, toolname))
    {
        g_hash_table_insert(_toolbars, g_strdup(toolname), toolbar_entry);
        ret = TRUE;
    }

    g_free(toolname);
    return ret;
}

static gchar **
extcap_convert_arguments_to_array(GList * arguments)
{
    gchar ** result = NULL;
    if ( arguments )
    {
        GList * walker = g_list_first(arguments);
        int cnt = 0;

        result = (gchar **) g_malloc0(sizeof(gchar *) * (g_list_length(arguments)));

        while(walker)
        {
            result[cnt] = g_strdup((const gchar *)walker->data);
            walker = g_list_next(walker);
            cnt++;
        }
    }
    return result;
}

static void extcap_free_array(gchar ** args, int argc)
{
    int cnt = 0;

    for ( cnt = 0; cnt < argc; cnt++ )
        g_free(args[cnt]);
    g_free(args);
}

static void
extcap_free_extcaps_info_array(extcap_run_extcaps_info_t *infos, guint count)
{
    for (guint i = 0; i < count; i++) {
        g_free(infos[i].extcap_path);
        g_free(infos[i].output);
        for (guint j = 0; j < infos[i].num_interfaces; j++) {
            extcap_iface_info_t *iface_info = &infos[i].iface_infos[j];
            g_free(iface_info->ifname);
            g_free(iface_info->output);
        }
        g_free(infos[i].iface_infos);
    }
    g_free(infos);
}

static void
extcap_run_one(const extcap_interface *interface, GList *arguments, extcap_cb_t cb, void *user_data, char **err_str)
{
    const char *dirname = get_extcap_dir();
    gchar **args = extcap_convert_arguments_to_array(arguments);
    int cnt = g_list_length(arguments);
    gchar *command_output;
    if (ws_pipe_spawn_sync(dirname, interface->extcap_path, cnt, args, &command_output)) {
        extcap_callback_info_t cb_info = {
            .ifname = interface->call,
            .extcap = interface->extcap_path,
            .output = command_output,
            .data = user_data,
            .err_str = err_str,
        };
        cb(cb_info);
        g_free(command_output);
    }
    extcap_free_array(args, cnt);
}

/** Thread callback to run an extcap program and pass its output. */
static void
extcap_thread_callback(gpointer data, gpointer user_data)
{
    extcap_run_task_t *task = (extcap_run_task_t *)data;
    thread_pool_t *pool = (thread_pool_t *)user_data;
    const char *dirname = get_extcap_dir();

    char *command_output;
    if (ws_pipe_spawn_sync(dirname, task->extcap_path, g_strv_length(task->argv), task->argv, &command_output)) {
        task->output_cb(pool, task->data, command_output);
    } else {
        task->output_cb(pool, task->data, NULL);
    }
    g_strfreev(task->argv);
    g_free(task);

    // Notify when all tasks are completed and no new subtasks were created.
    g_mutex_lock(&pool->data_mutex);
    if (--pool->count == 0) {
        g_cond_signal(&pool->cond);
    }
    g_mutex_unlock(&pool->data_mutex);
}

/*
 * Run all extcap programs with the given arguments list, invoke the callback to
 * do some processing and return the results.
 *
 * @param [IN] argv NULL-terminated arguments list.
 * @param [IN] output_cb Thread callback function that receives the output.
 * @param [IN] data_size Size of the per-program information that will be returned.
 * @param [OUT] count Size of the returned array.
 * @return Array of information or NULL if there are none. The first member of
 * each element (char *extcap_path) must be freed.
 */
static gpointer
extcap_run_all(const char *argv[], extcap_run_cb_t output_cb, gsize data_size, guint *count)
{
    /* Need enough space for at least 'extcap_path'. */
    ws_assert(data_size >= sizeof(char *));

    GSList *paths = extcap_get_extcap_paths();
    int i = 0;
    int max_threads = (int)g_get_num_processors();

    if (!paths) {
        *count = 0;
        return NULL;
    }

    guint64 start_time = g_get_monotonic_time();
    guint paths_count = g_slist_length(paths);
    /* GSList is not thread-safe, so pre-allocate an array instead. */
    gpointer infos = g_malloc0_n(paths_count, data_size);

    thread_pool_t pool;
    pool.pool = g_thread_pool_new(extcap_thread_callback, &pool, max_threads, FALSE, NULL);
    pool.count = 0;
    g_cond_init(&pool.cond);
    g_mutex_init(&pool.data_mutex);

    for (GSList *path = paths; path; path = g_slist_next(path), i++) {
        extcap_run_task_t *task = g_new0(extcap_run_task_t, 1);

        task->extcap_path = (char *)path->data;
        task->argv = g_strdupv((char **)argv);
        task->output_cb = output_cb;
        task->data = ((char *)infos) + (i * data_size);
        *((char **)task->data) = (char *)path->data;

        thread_pool_push(&pool, task, NULL);
    }
    g_slist_free(paths);    /* Note: the contents are transferred to 'infos'. */

    /* Wait for all (sub)tasks to complete. */
    thread_pool_wait(&pool);

    g_mutex_clear(&pool.data_mutex);
    g_cond_clear(&pool.cond);
    g_thread_pool_free(pool.pool, FALSE, TRUE);

    ws_debug("extcap: completed discovery of %d tools in %.3fms",
            paths_count, (g_get_monotonic_time() - start_time) / 1000.0);
    *count = paths_count;
    return infos;
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

    ws_debug("Extcap pipe %s ", cb_info.extcap);

    /*
     * Allocate the interface capabilities structure.
     */
    caps = (if_capabilities_t *) g_malloc(sizeof * caps);
    caps->can_set_rfmon = FALSE;
    caps->timestamp_types = NULL;

    while (dlts)
    {
        dlt_item = (extcap_dlt *)dlts->data;
        if (dlt_item)
        {
            ws_debug("  DLT %d name=\"%s\" display=\"%s\" ", dlt_item->number,
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
            ws_debug("  returned no DLTs");
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
    GList * arguments = NULL;
    if_capabilities_t *caps = NULL;

    if (err_str != NULL)
    {
        *err_str = NULL;
    }

    /* Update the extcap interfaces and get a list of their if_infos */
    extcap_ensure_all_interfaces_loaded();

    extcap_interface *interface = extcap_find_interface_for_ifname(ifname);
    if (interface)
    {
        arguments = g_list_append(arguments, g_strdup(EXTCAP_ARGUMENT_LIST_DLTS));
        arguments = g_list_append(arguments, g_strdup(EXTCAP_ARGUMENT_INTERFACE));
        arguments = g_list_append(arguments, g_strdup(ifname));

        extcap_run_one(interface, arguments, cb_dlt, &caps, err_str);

        g_list_free_full(arguments, g_free);
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

    g_list_free_full(interfaces, extcap_free_interface);
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
    extcap_ensure_all_interfaces_loaded();

    extcap_interface *interface = extcap_find_interface_for_ifname(ifname);
    return interface != NULL ? interface->help : NULL;
}

GList *
append_extcap_interface_list(GList *list, char **err_str _U_)
{
    GList *interface_list = NULL;
    extcap_interface *data = NULL;
    GList *ifutilkeys_head = NULL, *ifutilkeys = NULL;

    if (prefs.capture_no_extcap)
        return list;

    /* Update the extcap interfaces and get a list of their if_infos */
    extcap_ensure_all_interfaces_loaded();

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

void extcap_register_preferences(void)
{
    if (prefs.capture_no_extcap)
        return;

    module_t *dev_module = prefs_find_module("extcap");

    if (!dev_module)
    {
        return;
    }

    // Will load information about extcaps and their supported config.
    extcap_ensure_all_interfaces_loaded();
}

/**
 * Releases the dynamic preference value pointers. Must not be called before
 * prefs_cleanup since these pointers could still be in use.
 */
void extcap_cleanup(void)
{
    if (_extcap_prefs_dynamic_vals)
        g_hash_table_destroy(_extcap_prefs_dynamic_vals);

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
    if (!_extcap_prefs_dynamic_vals)
    {
        /* Initialize table only as needed, most preferences are not dynamic */
        _extcap_prefs_dynamic_vals = g_hash_table_new_full(g_str_hash, g_str_equal,
                                    g_free, g_free);
    }
    if (!g_hash_table_lookup_extended(_extcap_prefs_dynamic_vals, name,
                                      (gpointer *)pref_name, (gpointer *)&valp))
    {
        /* New dynamic pref, allocate, initialize and store. */
        valp = g_new0(gchar *, 1);
        *pref_name = g_strdup(name);
        g_hash_table_insert(_extcap_prefs_dynamic_vals, *pref_name, valp);
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

    extcap_ensure_all_interfaces_loaded();

    GRegex *regex_name = g_regex_new("[-]+", G_REGEX_RAW, (GRegexMatchFlags) 0, NULL);
    GRegex *regex_ifname = g_regex_new("(?![a-zA-Z0-9_]).", G_REGEX_RAW, (GRegexMatchFlags) 0, NULL);
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

        GRegex *regex_name = g_regex_new("[-]+", G_REGEX_RAW, (GRegexMatchFlags) 0, NULL);
        GRegex *regex_ifname = g_regex_new("(?![a-zA-Z0-9_]).", G_REGEX_RAW, (GRegexMatchFlags) 0, NULL);
        if (regex_name && regex_ifname)
        {
            while (walker != NULL)
            {
                extcap_arg *arg = (extcap_arg *)walker->data;
                arg->device_name = g_strdup(cb_info.ifname);

                if (arg->save)
                {
                    gchar *pref_name = g_regex_replace(regex_name, arg->call, strlen(arg->call), 0, "", (GRegexMatchFlags) 0, NULL);
                    gchar *ifname_underscore = g_regex_replace(regex_ifname, cb_info.ifname, strlen(cb_info.ifname), 0, "_", (GRegexMatchFlags) 0, NULL);
                    gchar *ifname_lowercase = g_ascii_strdown(ifname_underscore, -1);
                    gchar *pref_ifname = g_strconcat(ifname_lowercase, ".", pref_name, NULL);

                    if (prefs_find_preference(dev_module, pref_ifname) == NULL)
                    {
                        char *pref_name_for_prefs;
                        char *pref_title = wmem_strdup(wmem_epan_scope(), arg->display);

                        arg->pref_valptr = extcap_prefs_dynamic_valptr(pref_ifname, &pref_name_for_prefs);
                        /* Set an initial value if any (the string will be copied at registration) */
                        if (arg->default_complex)
                        {
                            *arg->pref_valptr = arg->default_complex->_val;
                        }

                        if (arg->arg_type == EXTCAP_ARG_PASSWORD)
                        {
                            prefs_register_password_preference(dev_module, pref_name_for_prefs,
                                                         pref_title, pref_title, (const char **)arg->pref_valptr);
                        } else {
                            prefs_register_string_preference(dev_module, pref_name_for_prefs,
                                                         pref_title, pref_title, (const char **)arg->pref_valptr);
                        }
                    }
                    else
                    {
                        /* Been here before, restore stored value */
                        if (arg->pref_valptr == NULL)
                        {
                            arg->pref_valptr = (gchar**)g_hash_table_lookup(_extcap_prefs_dynamic_vals, pref_ifname);
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
    GList * arguments = NULL;
    GList *ret = NULL;

    extcap_ensure_all_interfaces_loaded();

    extcap_interface *interface = extcap_find_interface_for_ifname(ifname);
    if (interface)
    {
        ws_debug("Extcap path %s", get_extcap_dir());

        arguments = g_list_append(arguments, g_strdup(EXTCAP_ARGUMENT_CONFIG));
        arguments = g_list_append(arguments, g_strdup(EXTCAP_ARGUMENT_INTERFACE));
        arguments = g_list_append(arguments, g_strdup(ifname));

        extcap_run_one(interface, arguments, cb_preference, &ret, NULL);

        g_list_free_full(arguments, g_free);
    }

    return ret;
}

static gboolean cb_reload_preference(extcap_callback_info_t cb_info)
{
    GList *arguments = NULL, * walker = NULL;
    GList **il = (GList **) cb_info.data;

    arguments = extcap_parse_values(cb_info.output);

    walker = g_list_first(arguments);
    while (walker != NULL)
    {
        extcap_value * val = (extcap_value *)walker->data;
        *il = g_list_append(*il, val);
        walker = g_list_next(walker);
    }
    g_list_free(arguments);

    /* By returning false, extcap_foreach will break on first found */
    return FALSE;
}

GList *
extcap_get_if_configuration_values(const char * ifname, const char * argname, GHashTable *arguments)
{
    GList * args = NULL;
    GList *ret = NULL;

    extcap_ensure_all_interfaces_loaded();

    extcap_interface *interface = extcap_find_interface_for_ifname(ifname);
    if (interface)
    {
        ws_debug("Extcap path %s", get_extcap_dir());

        args = g_list_append(args, g_strdup(EXTCAP_ARGUMENT_CONFIG));
        args = g_list_append(args, g_strdup(EXTCAP_ARGUMENT_INTERFACE));
        args = g_list_append(args, g_strdup(ifname));
        args = g_list_append(args, g_strdup(EXTCAP_ARGUMENT_RELOAD_OPTION));
        args = g_list_append(args, g_strdup(argname));

        if ( arguments )
        {
            GList * keys = g_hash_table_get_keys(arguments);
            GList * walker = g_list_first(keys);
            while ( walker )
            {
                const gchar * key_data = (const gchar *)walker->data;
                args = g_list_append(args, g_strdup(key_data));
                args = g_list_append(args, g_strdup((const gchar *)g_hash_table_lookup(arguments, key_data)));
                walker = g_list_next(walker);
            }
            g_list_free(keys);
        }

        extcap_run_one(interface, args, cb_reload_preference, &ret, NULL);

        g_list_free_full(args, g_free);
    }

    return ret;
}

gboolean
extcap_has_configuration(const char *ifname, gboolean is_required)
{
    GList *arguments = 0;
    GList *walker = 0, * item = 0;
    gboolean found = FALSE;

    extcap_ensure_all_interfaces_loaded();

    arguments = extcap_get_if_configuration(ifname);
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
    GList * arguments = NULL;
    extcap_filter_status status = EXTCAP_FILTER_UNKNOWN;

    extcap_ensure_all_interfaces_loaded();

    extcap_interface *interface = extcap_find_interface_for_ifname(ifname);
    if (interface)
    {
        ws_debug("Extcap path %s", get_extcap_dir());

        arguments = g_list_append(arguments, g_strdup(EXTCAP_ARGUMENT_CAPTURE_FILTER));
        arguments = g_list_append(arguments, g_strdup(filter));
        arguments = g_list_append(arguments, g_strdup(EXTCAP_ARGUMENT_INTERFACE));
        arguments = g_list_append(arguments, g_strdup(ifname));

        extcap_run_one(interface, arguments, cb_verify_filter, &status, err_str);
        g_list_free_full(arguments, g_free);
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

    extcap_ensure_all_interfaces_loaded();

    GList *toolbar_list = g_hash_table_get_values (_toolbars);
    for (GList *walker = toolbar_list; walker; walker = walker->next)
    {
        iface_toolbar *toolbar = (iface_toolbar *) walker->data;
        if (g_list_find_custom(toolbar->ifnames, ifname, (GCompareFunc) g_strcmp0))
        {
            g_list_free(toolbar_list);
            return TRUE;
        }
    }

    g_list_free(toolbar_list);
    return FALSE;
}

#ifdef HAVE_LIBPCAP
static gboolean extcap_terminate_cb(gpointer user_data)
{
    capture_session *cap_session = (capture_session *)user_data;
    capture_options *capture_opts = cap_session->capture_opts;
    interface_options *interface_opts;
    guint icnt;
    gboolean all_finished = TRUE;

    for (icnt = 0; icnt < capture_opts->ifaces->len; icnt++)
    {
        interface_opts = &g_array_index(capture_opts->ifaces, interface_options,
                                       icnt);

        /* skip native interfaces */
        if (interface_opts->if_type != IF_EXTCAP)
        {
            continue;
        }

        if (interface_opts->extcap_pid != WS_INVALID_PID)
        {
#ifdef _WIN32
            TerminateProcess(interface_opts->extcap_pid, 0);
#else
            kill(interface_opts->extcap_pid, SIGKILL);
#endif
            all_finished = FALSE;
        }

        /* Do not care about stdout/stderr anymore */
        if (interface_opts->extcap_stdout_watch > 0)
        {
            g_source_remove(interface_opts->extcap_stdout_watch);
            interface_opts->extcap_stdout_watch = 0;
        }

        if (interface_opts->extcap_stderr_watch > 0)
        {
            g_source_remove(interface_opts->extcap_stderr_watch);
            interface_opts->extcap_stderr_watch = 0;
        }
    }

    capture_opts->wait_for_extcap_cbs = TRUE;
    capture_opts->extcap_terminate_id = 0;
    if (all_finished)
    {
        capture_process_finished(cap_session);
    }

    return G_SOURCE_REMOVE;
}

void extcap_request_stop(capture_session *cap_session)
{
    capture_options *capture_opts = cap_session->capture_opts;
    interface_options *interface_opts;
    guint icnt = 0;

    if (capture_opts->extcap_terminate_id > 0)
    {
        /* Already requested, do not extend timeout */
        return;
    }

    if (capture_opts->wait_for_extcap_cbs)
    {
        /* Terminate callback was called, waiting for child callbacks */
        return;
    }

    if (extcap_session_stop(cap_session))
    {
        /* Nothing left to do, all extcaps have fully finished */
        return;
    }

    for (icnt = 0; icnt < capture_opts->ifaces->len; icnt++)
    {
        interface_opts = &g_array_index(capture_opts->ifaces, interface_options,
                                       icnt);

        /* skip native interfaces */
        if (interface_opts->if_type != IF_EXTCAP)
        {
            continue;
        }

        ws_debug("Extcap [%s] - Requesting stop PID: %d", interface_opts->name,
              interface_opts->extcap_pid);

#ifndef _WIN32
        if (interface_opts->extcap_pid != WS_INVALID_PID)
        {
            kill(interface_opts->extcap_pid, SIGTERM);
        }
#endif
    }

    capture_opts->extcap_terminate_id =
        g_timeout_add_seconds(EXTCAP_CLEANUP_TIMEOUT, extcap_terminate_cb, cap_session);
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

gboolean extcap_session_stop(capture_session *cap_session)
{
    capture_options *capture_opts = cap_session->capture_opts;
    interface_options *interface_opts;
    guint i;

    for (i = 0; i < capture_opts->ifaces->len; i++)
    {
        interface_opts = &g_array_index(capture_opts->ifaces, interface_options, i);
        if (interface_opts->if_type != IF_EXTCAP)
        {
            continue;
        }

        if ((interface_opts->extcap_pid != WS_INVALID_PID) ||
            (interface_opts->extcap_stdout_watch > 0) ||
            (interface_opts->extcap_stderr_watch > 0))
        {
            /* Capture session is not finished, wait for remaining watches */
            return FALSE;
        }

        g_free(interface_opts->extcap_pipedata);
        interface_opts->extcap_pipedata = NULL;

#ifdef _WIN32
        if (interface_opts->extcap_pipe_h != INVALID_HANDLE_VALUE)
        {
            ws_debug("Extcap [%s] - Closing pipe", interface_opts->name);
            FlushFileBuffers(interface_opts->extcap_pipe_h);
            DisconnectNamedPipe(interface_opts->extcap_pipe_h);
            CloseHandle(interface_opts->extcap_pipe_h);
            interface_opts->extcap_pipe_h = INVALID_HANDLE_VALUE;
        }
        if (interface_opts->extcap_control_in_h != INVALID_HANDLE_VALUE)
        {
            ws_debug("Extcap [%s] - Closing control_in pipe", interface_opts->name);
            FlushFileBuffers(interface_opts->extcap_control_in_h);
            DisconnectNamedPipe(interface_opts->extcap_control_in_h);
            CloseHandle(interface_opts->extcap_control_in_h);
            interface_opts->extcap_control_in_h = INVALID_HANDLE_VALUE;
        }
        if (interface_opts->extcap_control_out_h != INVALID_HANDLE_VALUE)
        {
            ws_debug("Extcap [%s] - Closing control_out pipe", interface_opts->name);
            FlushFileBuffers(interface_opts->extcap_control_out_h);
            DisconnectNamedPipe(interface_opts->extcap_control_out_h);
            CloseHandle(interface_opts->extcap_control_out_h);
            interface_opts->extcap_control_out_h = INVALID_HANDLE_VALUE;
        }
#else
        if (interface_opts->extcap_fifo != NULL && file_exists(interface_opts->extcap_fifo))
        {
            /* the fifo will not be freed here, but with the other capture_opts in capture_sync */
            ws_unlink(interface_opts->extcap_fifo);
            interface_opts->extcap_fifo = NULL;
        }
        if (interface_opts->extcap_control_in && file_exists(interface_opts->extcap_control_in))
        {
            ws_unlink(interface_opts->extcap_control_in);
            interface_opts->extcap_control_in = NULL;
        }
        if (interface_opts->extcap_control_out && file_exists(interface_opts->extcap_control_out))
        {
            ws_unlink(interface_opts->extcap_control_out);
            interface_opts->extcap_control_out = NULL;
        }
#endif
    }

    /* All child processes finished */
    capture_opts->wait_for_extcap_cbs = FALSE;
    if (capture_opts->extcap_terminate_id > 0)
    {
        g_source_remove(capture_opts->extcap_terminate_id);
        capture_opts->extcap_terminate_id = 0;
    }

    /* Nothing left to do, do not prevent capture session stop */
    return TRUE;
}

static void
extcap_watch_removed(capture_session *cap_session, interface_options *interface_opts)
{
    if ((interface_opts->extcap_pid == WS_INVALID_PID) &&
        (interface_opts->extcap_stdout_watch == 0) &&
        (interface_opts->extcap_stderr_watch == 0))
    {
        /* Close session if this was the last remaining process */
        capture_process_finished(cap_session);
    }
}

static interface_options *
extcap_find_channel_interface(capture_session *cap_session, GIOChannel *source)
{
    capture_options *capture_opts = cap_session->capture_opts;
    interface_options *interface_opts;
    guint i;

    for (i = 0; i < capture_opts->ifaces->len; i++)
    {
        ws_pipe_t *pipedata;
        interface_opts = &g_array_index(capture_opts->ifaces, interface_options, i);
        pipedata = (ws_pipe_t *)interface_opts->extcap_pipedata;
        if (pipedata &&
            ((pipedata->stdout_io == source) || (pipedata->stderr_io == source)))
        {
            return interface_opts;
        }
    }

    ws_assert_not_reached();
}

static gboolean
extcap_stdout_cb(GIOChannel *source, GIOCondition condition _U_, gpointer data)
{
    capture_session *cap_session = (capture_session *)data;
    interface_options *interface_opts = extcap_find_channel_interface(cap_session, source);
    char buf[128];
    gsize bytes_read = 0;
    GIOStatus status = G_IO_STATUS_EOF;

    /* Discard data to prevent child process hanging on stdout write */
    if (condition & G_IO_IN)
    {
        status = g_io_channel_read_chars(source, buf, sizeof(buf), &bytes_read, NULL);
    }

    if ((bytes_read == 0) || (status != G_IO_STATUS_NORMAL))
    {
        interface_opts->extcap_stdout_watch = 0;
        extcap_watch_removed(cap_session, interface_opts);
        return G_SOURCE_REMOVE;
    }
    return G_SOURCE_CONTINUE;
}

static gboolean
extcap_stderr_cb(GIOChannel *source, GIOCondition condition, gpointer data)
{
    capture_session *cap_session = (capture_session *)data;
    interface_options *interface_opts = extcap_find_channel_interface(cap_session, source);
    char buf[128];
    gsize bytes_read = 0;
    GIOStatus status = G_IO_STATUS_EOF;

    if (condition & G_IO_IN)
    {
        status = g_io_channel_read_chars(source, buf, sizeof(buf), &bytes_read, NULL);
    }

#define STDERR_BUFFER_SIZE 1024
    if (bytes_read > 0)
    {
        if (interface_opts->extcap_stderr == NULL)
        {
            interface_opts->extcap_stderr = g_string_new_len(buf, bytes_read);
        }
        else
        {
            gssize remaining = STDERR_BUFFER_SIZE - interface_opts->extcap_stderr->len;
            if (remaining > 0)
            {
                gssize bytes = bytes_read;
                bytes = MIN(bytes, remaining);
                g_string_append_len(interface_opts->extcap_stderr, buf, bytes);
            }
        }
    }

    if ((bytes_read == 0) || (status != G_IO_STATUS_NORMAL))
    {
        interface_opts->extcap_stderr_watch = 0;
        extcap_watch_removed(cap_session, interface_opts);
        return G_SOURCE_REMOVE;
    }
    return G_SOURCE_CONTINUE;
}

static void extcap_child_watch_cb(GPid pid, gint status _U_, gpointer user_data)
{
    guint i;
    interface_options *interface_opts;
    capture_session *cap_session = (capture_session *)(user_data);
    capture_options *capture_opts = cap_session->capture_opts;

    /* Close handle to child process. */
    g_spawn_close_pid(pid);

    /* Update extcap_pid in interface options structure. */
    for (i = 0; i < capture_opts->ifaces->len; i++)
    {
        interface_opts = &g_array_index(capture_opts->ifaces, interface_options, i);
        if (interface_opts->extcap_pid == pid)
        {
            ws_debug("Extcap [%s] - Closing spawned PID: %d", interface_opts->name,
                     interface_opts->extcap_pid);
            interface_opts->extcap_pid = WS_INVALID_PID;
            extcap_watch_removed(cap_session, interface_opts);
            break;
        }
    }
}

static
GPtrArray *extcap_prepare_arguments(interface_options *interface_opts)
{
    GPtrArray *result = NULL;

    if (interface_opts->if_type == IF_EXTCAP)
    {
        result = g_ptr_array_new();

#define add_arg(X) g_ptr_array_add(result, g_strdup(X))

        add_arg(interface_opts->extcap);
        add_arg(EXTCAP_ARGUMENT_RUN_CAPTURE);
        add_arg(EXTCAP_ARGUMENT_INTERFACE);
        add_arg(interface_opts->name);
        if (interface_opts->cfilter && strlen(interface_opts->cfilter) > 0)
        {
            add_arg(EXTCAP_ARGUMENT_CAPTURE_FILTER);
            add_arg(interface_opts->cfilter);
        }
        add_arg(EXTCAP_ARGUMENT_RUN_PIPE);
        add_arg(interface_opts->extcap_fifo);
        if (interface_opts->extcap_control_in)
        {
            add_arg(EXTCAP_ARGUMENT_CONTROL_OUT);
            add_arg(interface_opts->extcap_control_in);
        }
        if (interface_opts->extcap_control_out)
        {
            add_arg(EXTCAP_ARGUMENT_CONTROL_IN);
            add_arg(interface_opts->extcap_control_out);
        }
        if (interface_opts->extcap_args == NULL || g_hash_table_size(interface_opts->extcap_args) == 0)
        {
            /* User did not perform interface configuration.
             *
             * Check if there are any boolean flags that are set by default
             * and hence their argument should be added.
             */
            GList *arglist;
            GList *elem;

            arglist = extcap_get_if_configuration(interface_opts->name);
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
                    const gchar *stored = NULL;
                    /* In case of boolflags only first element in arg_list is relevant. */
                    arg_iter = (extcap_arg *)(arg_list->data);
                    if (arg_iter->pref_valptr != NULL)
                    {
                        stored = *arg_iter->pref_valptr;
                    }

                    if (arg_iter->arg_type == EXTCAP_ARG_BOOLFLAG)
                    {
                        if (!stored && extcap_complex_get_bool(arg_iter->default_complex))
                        {
                            add_arg(arg_iter->call);
                        }
                        else if (g_strcmp0(stored, "true") == 0)
                        {
                            add_arg(arg_iter->call);
                        }
                    }
                    else
                    {
                        if (stored && strlen(stored) > 0) {
                            add_arg(arg_iter->call);
                            add_arg(stored);
                        }
                    }

                    arg_list = arg_list->next;
                }
            }

            extcap_free_if_configuration(arglist, TRUE);
        }
        else
        {
            g_hash_table_foreach_remove(interface_opts->extcap_args, extcap_add_arg_and_remove_cb, result);
        }
        add_arg(NULL);
#undef add_arg

    }

    return result;
}

static void ptr_array_free(gpointer data, gpointer user_data _U_)
{
    g_free(data);
}

#ifdef _WIN32
static gboolean extcap_create_pipe(const gchar *ifname, gchar **fifo, HANDLE *handle_out, const gchar *pipe_prefix)
{
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
    *handle_out = CreateNamedPipe(
                 utf_8to16(pipename),
                 PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                 PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                 1, 65536, 65536,
                 300,
                 &security);

    if (*handle_out == INVALID_HANDLE_VALUE)
    {
        ws_debug("Error creating pipe => (%d)", GetLastError());
        g_free (pipename);
        return FALSE;
    }
    else
    {
        ws_debug("Wireshark Created pipe =>(%s) handle (%" PRIuPTR ")", pipename, *handle_out);
        *fifo = g_strdup(pipename);
    }

    return TRUE;
}
#else
static gboolean extcap_create_pipe(const gchar *ifname, gchar **fifo, const gchar *temp_dir, const gchar *pipe_prefix)
{
    gchar *temp_name = NULL;
    int fd = 0;

    gchar *pfx = g_strconcat(pipe_prefix, "_", ifname, NULL);
    if ((fd = create_tempfile(temp_dir, &temp_name, pfx, NULL, NULL)) < 0)
    {
        g_free(pfx);
        return FALSE;
    }
    g_free(pfx);

    ws_close(fd);

    ws_debug("Extcap - Creating fifo: %s", temp_name);

    if (file_exists(temp_name))
    {
        ws_unlink(temp_name);
    }

    if (mkfifo(temp_name, 0600) == 0)
    {
        *fifo = temp_name;
    }
    else
    {
        g_free(temp_name);
    }
    return TRUE;
}
#endif

/* call mkfifo for each extcap,
 * returns FALSE if there's an error creating a FIFO */
gboolean
extcap_init_interfaces(capture_session *cap_session)
{
    capture_options *capture_opts = cap_session->capture_opts;
    guint i;
    interface_options *interface_opts;
    ws_pipe_t *pipedata;

    extcap_ensure_all_interfaces_loaded();

    for (i = 0; i < capture_opts->ifaces->len; i++)
    {
        GPtrArray *args = NULL;
        GPid pid = WS_INVALID_PID;

        interface_opts = &g_array_index(capture_opts->ifaces, interface_options, i);

        /* skip native interfaces */
        if (interface_opts->if_type != IF_EXTCAP)
        {
            continue;
        }

        /* create control pipes if having toolbar */
        if (extcap_has_toolbar(interface_opts->name))
        {
            extcap_create_pipe(interface_opts->name, &interface_opts->extcap_control_in,
#ifdef _WIN32
                               &interface_opts->extcap_control_in_h,
#else
                               capture_opts->temp_dir,
#endif
                               EXTCAP_CONTROL_IN_PREFIX);
            extcap_create_pipe(interface_opts->name, &interface_opts->extcap_control_out,
#ifdef _WIN32
                               &interface_opts->extcap_control_out_h,
#else
                               capture_opts->temp_dir,
#endif
                               EXTCAP_CONTROL_OUT_PREFIX);
        }

        /* create pipe for fifo */
        if (!extcap_create_pipe(interface_opts->name, &interface_opts->extcap_fifo,
#ifdef _WIN32
                                &interface_opts->extcap_pipe_h,
#else
                               capture_opts->temp_dir,
#endif
                                EXTCAP_PIPE_PREFIX))
        {
            return FALSE;
        }


        /* Create extcap call */
        args = extcap_prepare_arguments(interface_opts);

        pipedata = g_new0(ws_pipe_t, 1);

        pid = ws_pipe_spawn_async(pipedata, args);

        g_ptr_array_foreach(args, ptr_array_free, NULL);
        g_ptr_array_free(args, TRUE);

        if (pid == WS_INVALID_PID)
        {
            g_free(pipedata);
            continue;
        }

        g_io_channel_unref(pipedata->stdin_io);
        pipedata->stdin_io = NULL;
        interface_opts->extcap_pid = pid;

        g_child_watch_add_full(G_PRIORITY_HIGH, pid, extcap_child_watch_cb,
                               (gpointer)cap_session, NULL);
        interface_opts->extcap_stdout_watch =
            g_io_add_watch(pipedata->stdout_io, G_IO_IN | G_IO_HUP,
                           extcap_stdout_cb, (gpointer)cap_session);
        interface_opts->extcap_stderr_watch =
            g_io_add_watch(pipedata->stderr_io, G_IO_IN | G_IO_HUP,
                           extcap_stderr_cb, (gpointer)cap_session);

        /* Pipedata pointers are only used to match GIOChannel to interface.
         * GIOChannel watch holds the only remaining reference.
         */
        g_io_channel_unref(pipedata->stdout_io);
        g_io_channel_unref(pipedata->stderr_io);

#ifdef _WIN32
        /* On Windows, wait for extcap to connect to named pipe.
         * Some extcaps will present UAC screen to user.
         * 30 second timeout should be reasonable timeout for extcap to
         * connect to named pipe (including user interaction).
         * Wait on multiple object in case of extcap termination
         * without opening pipe.
         */
        if (pid != WS_INVALID_PID)
        {
            HANDLE pipe_handles[3];
            int num_pipe_handles = 1;
            pipe_handles[0] = interface_opts->extcap_pipe_h;

            if (extcap_has_toolbar(interface_opts->name))
            {
                pipe_handles[1] = interface_opts->extcap_control_in_h;
                pipe_handles[2] = interface_opts->extcap_control_out_h;
                num_pipe_handles += 2;
             }

            ws_pipe_wait_for_pipe(pipe_handles, num_pipe_handles, pid);
        }
#endif

        interface_opts->extcap_pipedata = (gpointer) pipedata;
    }

    return TRUE;
}
#endif /* HAVE_LIBPCAP */

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

    if ( prefs.capture_no_extcap )
        return NULL;

    if ( ! toolname )
        return element;

    if ( ! _loaded_interfaces )
        _loaded_interfaces = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, extcap_free_interface);

    element = (extcap_info *) g_hash_table_lookup(_loaded_interfaces, toolname );
    if ( element )
        return NULL;

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
    extcap_ensure_all_interfaces_loaded();

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
    extcap_ensure_all_interfaces_loaded();

    return extcap_ensure_interface(toolname, FALSE);
}

static void remove_extcap_entry(gpointer entry, gpointer data _U_)
{
    extcap_interface *int_iter = (extcap_interface*)entry;

    if (int_iter->if_type == EXTCAP_SENTENCE_EXTCAP)
        extcap_free_interface(entry);
}

static void
process_new_extcap(const char *extcap, char *output)
{
    GList * interfaces = NULL, * control_items = NULL, * walker = NULL;
    extcap_interface * int_iter = NULL;
    extcap_info * element = NULL;
    iface_toolbar * toolbar_entry = NULL;
    gchar * toolname = g_path_get_basename(extcap);

    GList * interface_keys = g_hash_table_get_keys(_loaded_interfaces);

    /* Load interfaces from utility */
    interfaces = extcap_parse_interfaces(output, &control_items);

    ws_debug("Loading interface list for %s ", extcap);

    /* Seems, that there where no interfaces to be loaded */
    if ( ! interfaces || g_list_length(interfaces) == 0 )
    {
        ws_debug("Cannot load interfaces for %s", extcap );
        g_list_free(interface_keys);
        g_free(toolname);
        return;
    }

    /* Load or create the storage element for the tool */
    element = extcap_ensure_interface(toolname, TRUE);
    if ( element == NULL )
    {
        ws_warning("Cannot store interface %s, already loaded as personal plugin", extcap );
        g_list_foreach(interfaces, remove_extcap_entry, NULL);
        g_list_free(interfaces);
        g_list_free(interface_keys);
        g_free(toolname);
        return;
    }

    if (control_items)
    {
        toolbar_entry = g_new0(iface_toolbar, 1);
        toolbar_entry->controls = control_items;
    }

    walker = interfaces;
    gchar* help = NULL;
    while (walker != NULL)
    {
        int_iter = (extcap_interface *)walker->data;

        if (int_iter->call != NULL)
            ws_debug("Interface found %s\n", int_iter->call);

        /* Help is not necessarily stored with the interface, but rather with the version string.
         * As the version string allways comes in front of the interfaces, this ensures, that it get's
         * properly stored with the interface */
        if (int_iter->if_type == EXTCAP_SENTENCE_EXTCAP)
        {
            if (int_iter->call != NULL)
                ws_debug("  Extcap [%s] ", int_iter->call);

            /* Only initialize values if none are set. Need to check only one element here */
            if ( ! element->version )
            {
                element->version = g_strdup(int_iter->version);
                element->basename = g_strdup(toolname);
                element->full_path = g_strdup(extcap);
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
                ws_warning("Extcap interface \"%s\" is already provided by \"%s\" ",
                      int_iter->call, extcap_if_executable(int_iter->call));
                walker = g_list_next(walker);
                continue;
            }

            if ((int_iter->call != NULL) && (int_iter->display))
                ws_debug("  Interface [%s] \"%s\" ", int_iter->call, int_iter->display);

            int_iter->extcap_path = g_strdup(extcap);

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
        if (extcap_iface_toolbar_add(extcap, toolbar_entry))
        {
            toolbar_entry = NULL;
        }
    }

    extcap_free_toolbar(toolbar_entry);
    g_list_foreach(interfaces, remove_extcap_entry, NULL);
    g_list_free(interfaces);
    g_list_free(interface_keys);
    g_free(toolname);
}


/** Thread callback to save the output of a --extcap-config call. */
static void
extcap_process_config_cb(thread_pool_t *pool _U_, void *data, char *output)
{
    extcap_iface_info_t *iface_info = (extcap_iface_info_t *)data;
    iface_info->output = output;
}

/**
 * Thread callback to process discovered interfaces, scheduling more tasks to
 * retrieve the configuration for each interface. Called once for every extcap
 * program.
 */
static void
extcap_process_interfaces_cb(thread_pool_t *pool, void *data, char *output)
{
    extcap_run_extcaps_info_t *info = (extcap_run_extcaps_info_t *)data;
    guint i = 0;
    guint num_interfaces = 0;

    if (!output) {
        // No interfaces available, nothing to do.
        return;
    }

    // Save output for process_new_extcap.
    info->output = output;

    // Are there any interfaces to query information from?
    GList *interfaces = extcap_parse_interfaces(output, NULL);
    for (GList *iface = interfaces; iface; iface = g_list_next(iface)) {
        extcap_interface *intf = (extcap_interface *)iface->data;
        if (intf->if_type == EXTCAP_SENTENCE_INTERFACE) {
            ++num_interfaces;
        }
    }
    if (num_interfaces == 0) {
        // nothing to do.
        g_list_free_full(interfaces, extcap_free_interface);
        return;
    }

    /* GSList is not thread-safe, so pre-allocate an array instead. */
    info->iface_infos = g_new0(extcap_iface_info_t, num_interfaces);
    info->num_interfaces = num_interfaces;

    // Schedule new commands to retrieve the configuration.
    for (GList *iface = interfaces; iface; iface = g_list_next(iface)) {
        extcap_interface *intf = (extcap_interface *)iface->data;
        if (intf->if_type != EXTCAP_SENTENCE_INTERFACE) {
            continue;
        }

        const char *argv[] = {
            EXTCAP_ARGUMENT_CONFIG,
            EXTCAP_ARGUMENT_INTERFACE,
            intf->call,
            NULL
        };
        extcap_run_task_t *task = g_new0(extcap_run_task_t, 1);
        extcap_iface_info_t *iface_info = &info->iface_infos[i++];

        task->extcap_path = info->extcap_path;
        task->argv = g_strdupv((char **)argv);
        task->output_cb = extcap_process_config_cb;
        task->data = iface_info;
        iface_info->ifname = g_strdup(intf->call);

        thread_pool_push(pool, task, NULL);
    }
    g_list_free_full(interfaces, extcap_free_interface);
}

/**
 * Thread callback to check whether the new-style --list-interfaces call with an
 * explicit function succeeded. If not, schedule a call without the new version
 * argument.
 */
static void
extcap_list_interfaces_cb(thread_pool_t *pool, void *data, char *output)
{
    extcap_run_extcaps_info_t *info = (extcap_run_extcaps_info_t *)data;

    if (!output) {
        /* No output available, schedule a fallback query. */
        const char *argv[] = {
            EXTCAP_ARGUMENT_LIST_INTERFACES,
            NULL
        };
        extcap_run_task_t *task = g_new0(extcap_run_task_t, 1);

        task->extcap_path = info->extcap_path;
        task->argv = g_strdupv((char **)argv);
        task->output_cb = extcap_process_interfaces_cb;
        task->data = info;

        thread_pool_push(pool, task, NULL);
    } else {
        extcap_process_interfaces_cb(pool, info, output);
    }
}


/* Handles loading of the interfaces. */
static void
extcap_load_interface_list(void)
{
    if (prefs.capture_no_extcap)
        return;

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
        g_list_free(toolbar_list);
        g_hash_table_remove_all(_toolbars);
    } else {
        _toolbars = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, extcap_free_toolbar);
    }

    if (_loaded_interfaces == NULL)
    {
        int major = 0;
        int minor = 0;
        guint count = 0;
        extcap_run_extcaps_info_t *infos;
        GList *unused_arguments = NULL;

        _loaded_interfaces = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, extcap_free_interface_info);
        /* Cleanup lookup table */
        if ( _tool_for_ifname )
        {
            g_hash_table_remove_all(_tool_for_ifname);
            _tool_for_ifname = 0;
        } else {
            _tool_for_ifname = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
        }

        get_ws_version_number(&major, &minor, NULL);
        char *arg_version = ws_strdup_printf("%s=%d.%d", EXTCAP_ARGUMENT_VERSION, major, minor);
        const char *argv[] = {
            EXTCAP_ARGUMENT_LIST_INTERFACES,
            arg_version,
            NULL
        };
        infos = (extcap_run_extcaps_info_t *)extcap_run_all(argv,
                extcap_list_interfaces_cb, sizeof(extcap_run_extcaps_info_t),
                &count);
        for (guint i = 0; i < count; i++) {
            if (!infos[i].output) {
                continue;
            }

            // Save new extcap and each discovered interface.
            process_new_extcap(infos[i].extcap_path, infos[i].output);
            for (guint j = 0; j < infos[i].num_interfaces; j++) {
                extcap_iface_info_t *iface_info = &infos[i].iface_infos[j];

                if (!iface_info->output) {
                    continue;
                }

                extcap_callback_info_t cb_info = {
                    .ifname = iface_info->ifname,
                    .output = iface_info->output,
                    .data = &unused_arguments,
                };
                cb_preference(cb_info);
            }
        }
        /* XXX rework cb_preference such that this unused list can be removed. */
        extcap_free_if_configuration(unused_arguments, TRUE);
        extcap_free_extcaps_info_array(infos, count);
        g_free(arg_version);
    }
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
