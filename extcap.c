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
#include <epan/prefs-int.h>

#include <wsutil/file_util.h>
#include <wsutil/filesystem.h>
#include <wsutil/tempfile.h>

#include "capture_opts.h"

#include "extcap.h"
#include "extcap_parser.h"
#include "extcap_spawn.h"

#ifdef _WIN32
static HANDLE pipe_h = NULL;
#endif

static void extcap_child_watch_cb(GPid pid, gint status, gpointer user_data);

/* internal container, for all the extcap interfaces that have been found.
 * will be resetted by every call to extcap_interface_list() and is being
 * used in extcap_get_if_* as well as extcap_init_interfaces to ensure,
 * that only extcap interfaces are being given to underlying extcap programs
 */
static GHashTable *ifaces = NULL;

/* internal container, for all the extcap executables that have been found.
 * will be resetted by every call to extcap_interface_list() and is being
 * used for printing information about all extcap interfaces found
 */
static GHashTable *tools = NULL;

/* internal container, to map preference names to pointers that hold preference
 * values. These ensure that preferences can survive extcap if garbage
 * collection, and does not lead to dangling pointers in the prefs subsystem.
 */
static GHashTable *extcap_prefs_dynamic_vals = NULL;

/* Callback definition for extcap_foreach */
typedef gboolean (*extcap_cb_t)(const gchar *extcap, const gchar *ifname, gchar *output, void *data,
        gchar **err_str);

/* #define ARG_DEBUG */
#if ARG_DEBUG
static void extcap_debug_arguments ( extcap_arg *arg_iter );
#endif

static gboolean
extcap_if_exists(const gchar *ifname)
{
    if ( !ifname || !ifaces )
        return FALSE;

    if ( g_hash_table_lookup(ifaces, ifname) )
        return TRUE;

    return FALSE;
}

static gboolean
extcap_if_exists_for_extcap(const gchar *ifname, const gchar *extcap)
{
    gchar *entry = (gchar *)g_hash_table_lookup(ifaces, ifname);

    if ( entry && strcmp(entry, extcap) == 0 )
        return TRUE;

    return FALSE;
}

static gchar *
extcap_if_executable(const gchar *ifname)
{
    return (gchar *)g_hash_table_lookup(ifaces, ifname);
}

static void
extcap_if_add(const gchar *ifname, const gchar *extcap)
{
    if ( !g_hash_table_lookup(ifaces, ifname) )
        g_hash_table_insert(ifaces, g_strdup(ifname), g_strdup(extcap));
}

static void
extcap_free_info (gpointer data) {
    extcap_info * info = (extcap_info *)data;

    g_free (info->basename);
    g_free (info->full_path);
    g_free (info->version);
    g_free (info);
}

static void
extcap_tool_add(const gchar *extcap, const extcap_interface *interface)
{
    char *toolname;

    if ( !extcap || !interface )
        return;

    toolname = g_path_get_basename(extcap);

    if ( !g_hash_table_lookup(tools, toolname) ) {
        extcap_info * store = (extcap_info *)g_new0(extcap_info, 1);
        store->version = g_strdup(interface->version);
        store->full_path = g_strdup(extcap);
        store->basename = g_strdup(toolname);

        g_hash_table_insert(tools, g_strdup(toolname), store);
    }

    g_free(toolname);
}

/* Note: args does not need to be NULL-terminated. */
static void extcap_foreach(gint argc, gchar **args, extcap_cb_t cb,
        void *cb_data, char **err_str, const char * ifname _U_) {
    const char *dirname = get_extcap_dir();
    GDir *dir;
    const gchar *file;
    gboolean keep_going;

    keep_going = TRUE;

    if ((dir = g_dir_open(dirname, 0, NULL)) != NULL) {
        GString *extcap_path = NULL;

        extcap_path = g_string_new("");
        while (keep_going && (file = g_dir_read_name(dir)) != NULL ) {
            gchar *command_output = NULL;

            /* full path to extcap binary */
#ifdef _WIN32
            g_string_printf(extcap_path, "%s\\%s", dirname, file);
#else
            g_string_printf(extcap_path, "%s/%s", dirname, file);
#endif
            if ( extcap_if_exists(ifname) && !extcap_if_exists_for_extcap(ifname, extcap_path->str ) )
                continue;

            if ( extcap_spawn_sync ( (gchar *) dirname, extcap_path->str, argc, args, &command_output ) )
                keep_going = cb(extcap_path->str, ifname, command_output, cb_data, err_str);

            g_free(command_output);
        }

        g_dir_close(dir);
        g_string_free(extcap_path, TRUE);
    }

}

static gboolean dlt_cb(const gchar *extcap _U_, const gchar *ifname _U_, gchar *output, void *data,
        char **err_str) {
    extcap_token_sentence *tokens;
    extcap_dlt *dlts, *dlt_iter, *next;
    if_capabilities_t *caps;
    GList *linktype_list = NULL;
    data_link_info_t *data_link_info;

    tokens = extcap_tokenize_sentences(output);
    extcap_parse_dlts(tokens, &dlts);

    extcap_free_tokenized_sentence_list(tokens);

    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "Extcap pipe %s ", extcap);

    /*
     * Allocate the interface capabilities structure.
     */
    caps = (if_capabilities_t *) g_malloc(sizeof *caps);
    caps->can_set_rfmon = FALSE;

    dlt_iter = dlts;
    while (dlt_iter != NULL ) {
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG,
                "  DLT %d name=\"%s\" display=\"%s\" ", dlt_iter->number,
                dlt_iter->name, dlt_iter->display);

        data_link_info = g_new(data_link_info_t, 1);
        data_link_info->dlt = dlt_iter->number;
        data_link_info->name = g_strdup(dlt_iter->name);
        data_link_info->description = g_strdup(dlt_iter->display);
        linktype_list = g_list_append(linktype_list, data_link_info);
        dlt_iter = dlt_iter->next_dlt;
    }

    /* Check to see if we built a list */
    if (linktype_list != NULL && data != NULL) {
        caps->data_link_types = linktype_list;
        *(if_capabilities_t **) data = caps;
    } else {
        if (err_str) {
            g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "  returned no DLTs");
            *err_str = g_strdup("Extcap returned no DLTs");
        }
        g_free(caps);
    }

    dlt_iter = dlts;
    while (dlt_iter != NULL ) {
        next = dlt_iter->next_dlt;
        extcap_free_dlt(dlt_iter);
        dlt_iter = next;
    }

    return FALSE;
}

if_capabilities_t *
extcap_get_if_dlts(const gchar *ifname, char **err_str) {
    gchar *argv[3];
    gint i;
    if_capabilities_t *caps = NULL;

    if (err_str != NULL)
        *err_str = NULL;

    if ( extcap_if_exists(ifname) )
    {
        argv[0] = g_strdup(EXTCAP_ARGUMENT_LIST_DLTS);
        argv[1] = g_strdup(EXTCAP_ARGUMENT_INTERFACE);
        argv[2] = g_strdup(ifname);

        extcap_foreach(3, argv, dlt_cb, &caps, err_str, ifname);

        for (i = 0; i < 3; ++i)
            g_free(argv[i]);
    }

    return caps;
}

static gboolean interfaces_cb(const gchar *extcap, const gchar *ifname _U_, gchar *output, void *data,
        char **err_str _U_) {
    GList **il = (GList **) data;
    extcap_token_sentence *tokens;
    extcap_interface *interfaces, *int_iter; /*, *next; */
    if_info_t *if_info;

    tokens = extcap_tokenize_sentences(output);
    extcap_parse_interfaces(tokens, &interfaces);

    extcap_free_tokenized_sentence_list(tokens);

    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "Extcap pipe %s ", extcap);

    int_iter = interfaces;
    while (int_iter != NULL ) {
        if ( int_iter->if_type == EXTCAP_SENTENCE_INTERFACE && extcap_if_exists(int_iter->call) )
        {
            g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_WARNING, "Extcap interface \"%s\" is already provided by \"%s\" ",
                    int_iter->call, (gchar *)extcap_if_executable(int_iter->call) );
            int_iter = int_iter->next_interface;
            continue;
        }

        if ( int_iter->if_type == EXTCAP_SENTENCE_INTERFACE )
            g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "  Interface [%s] \"%s\" ",
                    int_iter->call, int_iter->display);
        else if ( int_iter->if_type == EXTCAP_SENTENCE_EXTCAP )
            g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "  Extcap [%s] ", int_iter->call);

        if ( int_iter->if_type == EXTCAP_SENTENCE_INTERFACE ) {
            if (il != NULL) {
                if_info = g_new0(if_info_t, 1);
                if_info->name = g_strdup(int_iter->call);
                if_info->friendly_name = g_strdup(int_iter->display);

                if_info->type = IF_EXTCAP;

                if_info->extcap = g_strdup(extcap);
                *il = g_list_append(*il, if_info);
            }

            extcap_if_add(int_iter->call, extcap);
        }

        /* Call for interfaces and tools alike. Multiple calls (because a tool has multiple
         * interfaces) are handled internally */
        extcap_tool_add(extcap, int_iter);

        int_iter = int_iter->next_interface;
    }
    extcap_free_interface(interfaces);

    return TRUE;
}

static gint
if_info_compare(gconstpointer a, gconstpointer b)
{
    gint comp = 0;
    const if_info_t * if_a = (const if_info_t *)a;
    const if_info_t * if_b = (const if_info_t *)b;

    if ( (comp = g_strcmp0(if_a->name, if_b->name)) == 0 )
        return g_strcmp0(if_a->friendly_name, if_b->friendly_name);

    return comp;
}

static void
extcap_reload_interface_list(GList **retp, char **err_str) {
    gchar *argv;

    if (err_str != NULL)
        *err_str = NULL;

    /* ifaces is used as cache, do not destroy its contents when
     * returning or no extcap interfaces can be queried for options */
    if (ifaces == NULL)
        ifaces = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    else
        g_hash_table_remove_all(ifaces);

    if (tools == NULL)
        tools = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, extcap_free_info);
    else
        g_hash_table_remove_all(tools);

    argv = g_strdup(EXTCAP_ARGUMENT_LIST_INTERFACES);

    extcap_foreach(1, &argv, interfaces_cb, retp, err_str, NULL);

    g_free(argv);
}

GHashTable *
extcap_tools_list(void) {
    if ( tools == NULL || g_hash_table_size(tools) == 0 )
        extcap_reload_interface_list(NULL, NULL);

    return tools;
}

GList *
append_extcap_interface_list(GList *list, char **err_str) {
    GList *ret = NULL;
    GList *entry;
    void *data;

    /* Update the extcap interfaces and get a list of their if_infos */
    extcap_reload_interface_list(&ret, err_str);

    /* Sort that list */
    ret = g_list_sort(ret, if_info_compare);

    /* Append the interfaces in that list to the list we're handed. */
    while (ret != NULL) {
        entry = g_list_first(ret);
        data = entry->data;
        ret = g_list_delete_link(ret, entry);
        list = g_list_append(list, data);
    }
    return list;
}

static void extcap_free_arg_elem(gpointer data, gpointer user_data _U_) {
    extcap_free_arg((extcap_arg *) data);
    g_free(data);
}

void extcap_register_preferences(void)
{
    GList * interfaces = NULL;

    module_t * dev_module = prefs_find_module("extcap");

    if ( !dev_module )
        return;

    if ( ! ifaces || g_hash_table_size(ifaces) == 0 )
        extcap_reload_interface_list(NULL, NULL);

    interfaces = g_hash_table_get_keys(ifaces);

    while ( interfaces ) {
        extcap_get_if_configuration((gchar *)interfaces->data);

        interfaces = g_list_next(interfaces);
    }
}

/**
 * Releases the dynamic preference value pointers. Must not be called before
 * prefs_cleanup since these pointers could still be in use.
 */
void extcap_cleanup(void)
{
    if (extcap_prefs_dynamic_vals) {
        g_hash_table_destroy(extcap_prefs_dynamic_vals);
    }
}

void extcap_pref_store(extcap_arg * arg, const char * newval)
{
    if (arg && arg->pref_valptr != NULL)
    {
        g_free(*arg->pref_valptr);
        *arg->pref_valptr = g_strdup(newval);
    }

}

/**
 * Obtains a pointer which can store a value for the given preference name.
 *
 * Extcap interfaces (and their preferences) are dynamic, they can be created
 * and destroyed at will. Thus their data structures are insufficient to pass to
 * the preferences APIs which require pointers which are valid until the
 * preferences are removed (at exit).
 */
static gchar ** extcap_prefs_dynamic_valptr(const char *name)
{
    gchar **valp;
    if (!extcap_prefs_dynamic_vals) {
        /* Initialize table only as needed, most preferences are not dynamic */
        extcap_prefs_dynamic_vals = g_hash_table_new_full(g_str_hash, g_str_equal,
                g_free, g_free);
    }
    valp = (gchar **)g_hash_table_lookup(extcap_prefs_dynamic_vals, name);
    if (!valp) {
        /* New dynamic pref, allocate, initialize and store. */
        valp = g_new0(gchar *, 1);
        g_hash_table_insert(extcap_prefs_dynamic_vals, g_strdup(name), valp);
    }
    return valp;
}

static void extcap_free_if_configuration(GList *list)
{
    GList *elem, *sl;

    for (elem = g_list_first(list); elem; elem = elem->next)
    {
        if (elem->data != NULL) {
            /* g_list_free_full() only exists since 2.28. */
            sl = g_list_first((GList *)elem->data);
            g_list_foreach(sl, (GFunc)extcap_free_arg_elem, NULL);
            g_list_free(sl);
        }
    }
    g_list_free(list);
}

struct preference *
extcap_pref_for_argument(const gchar *ifname, struct _extcap_arg * arg) {
    struct preference * pref = NULL;

    GRegex * regex_name = g_regex_new ("[-]+", (GRegexCompileFlags) 0, (GRegexMatchFlags) 0, NULL );
    GRegex * regex_ifname = g_regex_new ("(?![a-zA-Z1-9_]).", (GRegexCompileFlags) 0, (GRegexMatchFlags) 0, NULL );
    if (regex_name && regex_ifname) {
        if ( prefs_find_module("extcap") ) {
            gchar * pref_name = g_regex_replace(regex_name, arg->call, strlen(arg->call), 0, "", (GRegexMatchFlags) 0, NULL );
            gchar * ifname_underscore = g_regex_replace(regex_ifname, ifname, strlen(ifname), 0, "_", (GRegexMatchFlags) 0, NULL );
            gchar * ifname_lowercase = g_ascii_strdown(ifname_underscore, -1);
            gchar * pref_ifname = g_strconcat(ifname_lowercase, ".", pref_name, NULL);

            pref = prefs_find_preference(prefs_find_module("extcap"), pref_ifname);

            g_free(pref_name);
            g_free(ifname_underscore);
            g_free(ifname_lowercase);
            g_free(pref_ifname);
        }
    }
    if (regex_name) {
        g_regex_unref(regex_name);
    }
    if (regex_ifname) {
        g_regex_unref(regex_ifname);
    }

    return pref;
}

static gboolean search_cb(const gchar *extcap _U_, const gchar *ifname _U_, gchar *output, void *data,
        char **err_str _U_) {
    extcap_token_sentence *tokens = NULL;
    GList *arguments = NULL;
    GList **il = (GList **) data;
    module_t * dev_module = NULL;

    tokens = extcap_tokenize_sentences(output);
    arguments = extcap_parse_args(tokens);

    extcap_free_tokenized_sentence_list(tokens);

#if ARG_DEBUG
    extcap_debug_arguments ( arguments );
#endif

    dev_module = prefs_find_module("extcap");

    if ( dev_module ) {
        GList * walker = arguments;

        GRegex * regex_name = g_regex_new ("[-]+", (GRegexCompileFlags) 0, (GRegexMatchFlags) 0, NULL );
        GRegex * regex_ifname = g_regex_new ("(?![a-zA-Z1-9_]).", (GRegexCompileFlags) 0, (GRegexMatchFlags) 0, NULL );
        if (regex_name && regex_ifname) {
            while ( walker != NULL ) {
                extcap_arg * arg = (extcap_arg *)walker->data;
                arg->device_name = g_strdup(ifname);

                if ( arg->save ) {
                    struct preference * pref = NULL;

                    gchar * pref_name = g_regex_replace(regex_name, arg->call, strlen(arg->call), 0, "", (GRegexMatchFlags) 0, NULL );
                    gchar * ifname_underscore = g_regex_replace(regex_ifname, ifname, strlen(ifname), 0, "_", (GRegexMatchFlags) 0, NULL );
                    gchar * ifname_lowercase = g_ascii_strdown(ifname_underscore, -1);
                    gchar * pref_ifname = g_strconcat(ifname_lowercase, ".", pref_name, NULL);

                    if ( ( pref = prefs_find_preference(dev_module, pref_ifname) ) == NULL ) {
                        arg->pref_valptr = extcap_prefs_dynamic_valptr(pref_ifname);
                        /* Set an initial value if any (the string will be copied at registration) */
                        if (arg->default_complex) {
                            *arg->pref_valptr = arg->default_complex->_val;
                        }

                        prefs_register_string_preference(dev_module, g_strdup(pref_ifname),
                                arg->display, arg->display, (const char **)arg->pref_valptr);
                    } else {
                        /* Been here before, restore stored value */
                        if (! arg->pref_valptr && pref->varp.string && strlen(*pref->varp.string))
                        {
                            arg->pref_valptr = pref->varp.string;
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
        if (regex_name) {
            g_regex_unref(regex_name);
        }
        if (regex_ifname) {
            g_regex_unref(regex_ifname);
        }
    }

    *il = g_list_append(*il, arguments);

    /* By returning false, extcap_foreach will break on first found */
    return TRUE;
}

GList *
extcap_get_if_configuration(const char * ifname) {
    gchar *argv[3];
    GList *ret = NULL;
    gchar **err_str = NULL;
    int i;

    if ( extcap_if_exists(ifname) )
    {
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "Extcap path %s",
                get_extcap_dir());

        argv[0] = g_strdup(EXTCAP_ARGUMENT_CONFIG);
        argv[1] = g_strdup(EXTCAP_ARGUMENT_INTERFACE);
        argv[2] = g_strdup(ifname);

        extcap_foreach(3, argv, search_cb, &ret, err_str, ifname);

        for (i = 0; i < 3; i++)
            g_free(argv[i]);
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
extcap_has_configuration(const char * ifname, gboolean is_required) {
    GList * arguments = 0;
    GList * walker = 0, * item = 0;

    gboolean found = FALSE;

    arguments = extcap_get_if_configuration((const char *)( ifname ) );
    walker = g_list_first(arguments);

    while ( walker != NULL && ! found ) {
        item = g_list_first((GList *)(walker->data));
        while ( item != NULL && ! found ) {
            if ( (extcap_arg *)(item->data) != NULL ) {
                extcap_arg * arg = (extcap_arg *)(item->data);
                /* Should required options be present, or any kind of options */
                if ( ! is_required )
                    found = TRUE;
                else if ( arg->is_required ) {
                    const gchar * stored = NULL;
                    const gchar * defval = NULL;

                    if (arg->pref_valptr != NULL)
                        stored = *arg->pref_valptr;

                    if ( arg->default_complex != NULL && arg->default_complex->_val != NULL )
                        defval = arg->default_complex->_val;

                    if ( arg->is_required ) {
                        /* If stored and defval is identical and the argument is required,
                         * configuration is needed */
                        if ( defval && stored && g_strcmp0(stored, defval) == 0 )
                            found = TRUE;
                        else if ( ! defval && (!stored || !*stored) )
                            found = TRUE;
                    }

                    if ( arg->arg_type == EXTCAP_ARG_FILESELECT ) {
                        if ( arg->fileexists && ! ( file_exists(defval) || file_exists(stored) ) )
                            found = TRUE;
                    }
                }
            }

            item = item->next;
        }
        walker = walker->next;
    }
    extcap_free_if_configuration(arguments);

    return found;
}

/* taken from capchild/capture_sync.c */
static gboolean pipe_data_available(int pipe_fd) {
#ifdef _WIN32 /* PeekNamedPipe */
    HANDLE hPipe = (HANDLE) _get_osfhandle(pipe_fd);
    DWORD bytes_avail;

    if (hPipe == INVALID_HANDLE_VALUE)
        return FALSE;

    if (! PeekNamedPipe(hPipe, NULL, 0, NULL, &bytes_avail, NULL))
        return FALSE;

    if (bytes_avail > 0)
        return TRUE;
    return FALSE;
#else /* select */
    fd_set rfds;
    struct timeval timeout;

    FD_ZERO(&rfds);
    FD_SET(pipe_fd, &rfds);
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;

    if (select(pipe_fd+1, &rfds, NULL, NULL, &timeout) > 0)
        return TRUE;

    return FALSE;
#endif
}

void extcap_if_cleanup(capture_options * capture_opts, gchar ** errormsg) {
    interface_options interface_opts;
    extcap_userdata * userdata;
    guint icnt = 0;
    gboolean overwrite_exitcode;
    gchar * buffer;
#define STDERR_BUFFER_SIZE 1024

    for (icnt = 0; icnt < capture_opts->ifaces->len; icnt++) {
        interface_opts = g_array_index(capture_opts->ifaces, interface_options,
                icnt);

        /* skip native interfaces */
        if (interface_opts.if_type != IF_EXTCAP)
            continue;

        overwrite_exitcode = FALSE;

        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG,
                "Extcap [%s] - Cleaning up fifo: %s; PID: %d", interface_opts.name,
                interface_opts.extcap_fifo, interface_opts.extcap_pid);
#ifdef _WIN32
        if (pipe_h)
        {
            g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG,
                "Extcap [%s] - Closing pipe", interface_opts.name);
            FlushFileBuffers(pipe_h);
            DisconnectNamedPipe(pipe_h);
            CloseHandle(pipe_h);
        }
#else
        if (interface_opts.extcap_fifo != NULL && file_exists(interface_opts.extcap_fifo))
        {
            /* the fifo will not be freed here, but with the other capture_opts in capture_sync */
            ws_unlink(interface_opts.extcap_fifo);
            interface_opts.extcap_fifo = NULL;
        }
#endif
        /* Maybe the client closed and removed fifo, but ws should check if
         * pid should be closed */
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG,
                "Extcap [%s] - Closing spawned PID: %d", interface_opts.name,
                interface_opts.extcap_pid);

        userdata = (extcap_userdata *) interface_opts.extcap_userdata;
        if ( userdata )
        {
            if (userdata->extcap_stderr_rd > 0 && pipe_data_available(userdata->extcap_stderr_rd) )
            {
                buffer = (gchar * )g_malloc0(sizeof(gchar) * STDERR_BUFFER_SIZE + 1);
#ifdef _WIN32
                win32_readfrompipe((HANDLE)_get_osfhandle(userdata->extcap_stderr_rd), STDERR_BUFFER_SIZE, buffer);
#else
                if (read(userdata->extcap_stderr_rd, buffer, sizeof(gchar) * STDERR_BUFFER_SIZE) <= 0 )
                    buffer[0] = '\0';
#endif
                if ( strlen ( buffer) > 0 )
                {
                    userdata->extcap_stderr = g_strdup_printf("%s", buffer);
                    userdata->exitcode = 1;
                }
                g_free(buffer);
            }

#ifndef _WIN32
            /* Final child watch may not have been called */
            if ( interface_opts.extcap_child_watch != 0 )
            {
                extcap_child_watch_cb(userdata->pid, 0, capture_opts);
                /* it will have changed in extcap_child_watch_cb */
                interface_opts = g_array_index(capture_opts->ifaces, interface_options,
                                icnt);
            }
#endif

            if ( userdata->extcap_stderr != NULL )
                overwrite_exitcode = TRUE;

            if ( overwrite_exitcode || userdata->exitcode != 0 )
            {
                if ( userdata->extcap_stderr != 0 )
                {
                    if ( *errormsg == NULL )
                        *errormsg = g_strdup_printf("Error by extcap pipe: %s", userdata->extcap_stderr);
                    else
                    {
                        gchar * temp = g_strconcat ( *errormsg, "\nError by extcap pipe: " ,userdata->extcap_stderr, NULL );
                        g_free(*errormsg);
                        *errormsg = temp;
                    }
                    g_free (userdata->extcap_stderr );
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
extcap_add_arg_and_remove_cb(gpointer key, gpointer value, gpointer data) {
    GPtrArray *args = (GPtrArray *)data;

    if ( key != NULL )
    {
        g_ptr_array_add(args, g_strdup((const gchar*)key));

        if ( value != NULL )
            g_ptr_array_add(args, g_strdup((const gchar*)value));

        return TRUE;
    }

    return FALSE;
}

void extcap_child_watch_cb(GPid pid, gint status, gpointer user_data)
{
    guint i;
    interface_options interface_opts;
    extcap_userdata * userdata = NULL;
    capture_options * capture_opts = (capture_options *)(user_data);

    if ( capture_opts == NULL || capture_opts->ifaces == NULL || capture_opts->ifaces->len == 0 )
        return;

    /* Close handle to child process. */
    g_spawn_close_pid(pid);

    /* Update extcap_pid in interface options structure. */
    for (i = 0; i < capture_opts->ifaces->len; i++)
    {
        interface_opts = g_array_index(capture_opts->ifaces, interface_options, i);
        if (interface_opts.extcap_pid == pid)
        {
            userdata = (extcap_userdata *)interface_opts.extcap_userdata;
            if ( userdata != NULL )
            {
                interface_opts.extcap_pid = INVALID_EXTCAP_PID;
                userdata->exitcode = 0;
#ifndef _WIN32
                if ( WIFEXITED(status) )
                {
                    if ( WEXITSTATUS(status) != 0 )
                        userdata->exitcode = WEXITSTATUS(status);
                }
                else
                    userdata->exitcode = G_SPAWN_ERROR_FAILED;
#else
                if (status != 0)
                    userdata->exitcode = status;
#endif
                if ( status == 0 && userdata->extcap_stderr != NULL )
                    userdata->exitcode = 1;
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
GPtrArray * extcap_prepare_arguments(interface_options interface_opts)
{
    GPtrArray *result = NULL;
#if ARG_DEBUG
    gchar **tmp;
    int tmp_i;
#endif

    if (interface_opts.if_type == IF_EXTCAP )
    {
        result = g_ptr_array_new();

#define add_arg(X) g_ptr_array_add(result, g_strdup(X))

        add_arg(interface_opts.extcap);
        add_arg(EXTCAP_ARGUMENT_RUN_CAPTURE);
        add_arg(EXTCAP_ARGUMENT_INTERFACE);
        add_arg(interface_opts.name);
        if (interface_opts.cfilter && strlen(interface_opts.cfilter) > 0) {
            add_arg(EXTCAP_ARGUMENT_CAPTURE_FILTER);
            add_arg(interface_opts.cfilter);
        }
        add_arg(EXTCAP_ARGUMENT_RUN_PIPE);
        add_arg(interface_opts.extcap_fifo);
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
                GList * arg_list;
                extcap_arg *arg_iter;

                if (elem->data == NULL)
                {
                    continue;
                }

                arg_list = g_list_first((GList *)elem->data);
                while (arg_list != NULL) {
                    const gchar * stored = NULL, * defval = NULL;
                    /* In case of boolflags only first element in arg_list is relevant. */
                    arg_iter = (extcap_arg*) (arg_list->data);
                    if (arg_iter->pref_valptr != NULL)
                        stored = *arg_iter->pref_valptr;

                    if ( arg_iter->default_complex != NULL && arg_iter->default_complex->_val != NULL )
                        defval = arg_iter->default_complex->_val;

                    /* Different data in storage then set for default */
                    if ( g_strcmp0(stored, defval) != 0 ) {
                        if ( arg_iter->arg_type == EXTCAP_ARG_BOOLFLAG ) {
                            if ( g_strcmp0(stored, "true") == 0 )
                                add_arg(arg_iter->call);
                        } else {
                            add_arg(arg_iter->call);
                            add_arg(stored);
                        }
                    } else if  (arg_iter->arg_type == EXTCAP_ARG_BOOLFLAG) {
                        if (extcap_complex_get_bool(arg_iter->default_complex))
                            add_arg(arg_iter->call);
                    }

                    arg_list = arg_list->next;
                }
            }

            extcap_free_if_configuration(arglist);
        }
        else
        {
            g_hash_table_foreach_remove(interface_opts.extcap_args, extcap_add_arg_and_remove_cb, result);
        }
        add_arg(NULL);
#undef add_arg

#if ARG_DEBUG
        /* Dump commandline parameters sent to extcap. */
        for (tmp = (gchar **)result->pdata, tmp_i = 0; *tmp && **tmp; ++tmp_i, ++tmp)
        {
            g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "argv[%d]: %s", tmp_i, *tmp);
        }
#endif

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
    extcap_userdata * userdata;

    for (i = 0; i < capture_opts->ifaces->len; i++)
    {
        GPtrArray *args = NULL;
        GPid pid = INVALID_EXTCAP_PID;

        interface_opts = g_array_index(capture_opts->ifaces, interface_options, i);

        /* skip native interfaces */
        if (interface_opts.if_type != IF_EXTCAP )
            continue;

        /* create pipe for fifo */
        if ( ! extcap_create_pipe ( &interface_opts.extcap_fifo ) )
            return FALSE;

        /* Create extcap call */
        args = extcap_prepare_arguments(interface_opts);

        userdata = g_new0(extcap_userdata, 1);

        pid = extcap_spawn_async(userdata, args );

        g_ptr_array_foreach(args, (GFunc)g_free, NULL);
        g_ptr_array_free(args, TRUE);

        if ( pid == INVALID_EXTCAP_PID )
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
            extcap_wait_for_pipe(pipe_h, pid);
        }

#endif

        interface_opts.extcap_userdata = (gpointer) userdata;

        capture_opts->ifaces = g_array_remove_index(capture_opts->ifaces, i);
        g_array_insert_val(capture_opts->ifaces, i, interface_opts);
    }

    return TRUE;
}

#ifdef _WIN32
/* called by capture_sync to get the CreatNamedPipe handle*/
HANDLE
extcap_get_win32_handle()
{
    return pipe_h;
}
#endif

gboolean extcap_create_pipe(char ** fifo)
{
#ifdef _WIN32
    gchar timestr[ 14+1 ];
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
    pipename = g_strconcat ( "\\\\.\\pipe\\", EXTCAP_PIPE_PREFIX, "_", timestr, NULL );

    /* Security struct to enable Inheritable HANDLE */
    memset(&security, 0, sizeof(SECURITY_ATTRIBUTES));
    security.nLength = sizeof(SECURITY_ATTRIBUTES);
    security.bInheritHandle = TRUE;
    security.lpSecurityDescriptor = NULL;

    /* create a namedPipe*/
    pipe_h = CreateNamedPipe(
                utf_8to16(pipename),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_MESSAGE| PIPE_READMODE_MESSAGE | PIPE_WAIT,
                5, 65536, 65536,
                300,
                &security);

    if (pipe_h == INVALID_HANDLE_VALUE)
    {
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG,"\nError creating pipe => (%d)", GetLastError());
        return FALSE;
    }
    else
    {
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG,"\nWireshark Created pipe =>(%s)",pipename);
        *fifo = g_strdup(pipename);
    }
#else
    gchar *temp_name = NULL;
    int fd = 0;

    if ((fd = create_tempfile(&temp_name, EXTCAP_PIPE_PREFIX, NULL)) < 0 )
        return FALSE;

    ws_close(fd);

    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG,
            "Extcap - Creating fifo: %s", temp_name);

    if ( file_exists(temp_name) )
        ws_unlink(temp_name);

    if (mkfifo(temp_name, 0600) == 0)
        *fifo = g_strdup(temp_name);
#endif

    return TRUE;
}

#if ARG_DEBUG
void extcap_debug_arguments ( extcap_arg *arg_iter )
{
    extcap_value *v = NULL;
    GList *walker = NULL;

    printf("debug - parser dump\n");
    while (arg_iter != NULL) {
        printf("ARG %d call=%s display=\"%s\" type=", arg_iter->arg_num, arg_iter->call, arg_iter->display);

        switch (arg_iter->arg_type) {
            case EXTCAP_ARG_INTEGER:
            printf("int\n");
            break;
            case EXTCAP_ARG_UNSIGNED:
            printf("unsigned\n");
            break;
            case EXTCAP_ARG_LONG:
            printf("long\n");
            break;
            case EXTCAP_ARG_DOUBLE:
            printf("double\n");
            break;
            case EXTCAP_ARG_BOOLEAN:
            printf("boolean\n");
            break;
            case EXTCAP_ARG_MENU:
            printf("menu\n");
            break;
            case EXTCAP_ARG_RADIO:
            printf("radio\n");
            break;
            case EXTCAP_ARG_SELECTOR:
            printf("selctor\n");
            break;
            case EXTCAP_ARG_STRING:
            printf ( "string\n" );
            break;
            case EXTCAP_ARG_PASSWORD:
            printf ( "PASSWORD\n" );
            break;
            case EXTCAP_ARG_MULTICHECK:
            printf ( "unknown\n" );
            break;
            case EXTCAP_ARG_UNKNOWN:
            printf ( "unknown\n" );
            break;
        }

        if (arg_iter->range_start != NULL && arg_iter->range_end != NULL) {
            printf("\tRange: ");
            extcap_printf_complex(arg_iter->range_start);
            printf(" - ");
            extcap_printf_complex(arg_iter->range_end);
            printf("\n");
        }

        for ( walker = g_list_first ( arg_iter->value_list ); walker; walker = walker->next )
        {
            v = (extcap_value *)walker->data;
            if (v->is_default)
            printf("*");
            printf("\tcall=\"%p\" display=\"%p\"\n", v->call, v->display);
            printf("\tcall=\"%s\" display=\"%s\"\n", v->call, v->display);
        }

        arg_iter = arg_iter->next_arg;
    }
}
#endif

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
