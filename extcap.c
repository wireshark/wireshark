/* extcap.h
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

#include <glib.h>
#include <log.h>

#include <wsutil/file_util.h>
#include <wsutil/filesystem.h>
#include <wsutil/tempfile.h>

#include "capture_opts.h"

#ifdef HAVE_EXTCAP

#include "extcap.h"
#include "extcap_parser.h"

#ifdef _WIN32
static HANDLE pipe_h = NULL;
#endif

/* internal container, for all the extcap interfaces that have been found.
 * will be resetted by every call to extcap_interface_list() and is being
 * used in extcap_get_if_* as well as extcaps_init_initerfaces to ensure,
 * that only extcap interfaces are being given to underlying extcap programs
 */
static GHashTable *ifaces = NULL;

/* Callback definition for extcap_foreach */
typedef gboolean (*extcap_cb_t)(const gchar *extcap, gchar *output, void *data,
        gchar **err_str);

/* #define ARG_DEBUG */
#if ARG_DEBUG
static void extcap_debug_arguments ( extcap_arg *arg_iter );
#endif

static gboolean
extcap_if_exists(const char *ifname)
{
    if ( ifname != NULL )
    {
        if ( ifaces != NULL )
        {
            if ( g_hash_table_size(ifaces) > 0 )
            {
                if ( g_hash_table_lookup(ifaces, (const gchar *)ifname) != NULL )
                {
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

static gboolean
extcap_if_exists_for_extcap(const char *ifname, const char *extcap)
{
    gchar * entry = NULL;

    if ( extcap_if_exists(ifname) )
    {
        if ( ( entry = (gchar *)g_hash_table_lookup(ifaces, (const gchar *)ifname) ) != NULL )
        {
            if ( strcmp(entry, extcap) == 0 )
                return TRUE;
        }
    }

    return FALSE;
}

static gchar *
extcap_if_executable(const char *ifname)
{
    if ( extcap_if_exists(ifname) )
        return (gchar *)g_hash_table_lookup(ifaces, (const gchar *)ifname);

    return (gchar *)NULL;
}

static void
extcap_if_cleanup(void)
{
    if ( ifaces == NULL )
        ifaces = g_hash_table_new(g_str_hash, g_str_equal);

    g_hash_table_remove_all(ifaces);
}

static void
extcap_if_add(gchar *ifname, gchar *extcap)
{
    if ( g_hash_table_lookup(ifaces, ifname) == NULL )
        g_hash_table_insert(ifaces, ifname, extcap);
}

static void extcap_foreach(gint argc, gchar **args, extcap_cb_t cb,
        void *cb_data, char **err_str, const char * ifname _U_) {
    const char *dirname = get_extcap_dir();
    GDir *dir;
    const gchar *file;
    gboolean keep_going;
    gchar **argv;
#ifdef _WIN32
    gchar **dll_search_envp;
    gchar *progfile_dir;
#endif

    keep_going = TRUE;

    argv = (gchar **) g_malloc0(sizeof(gchar *) * (argc + 2));

#ifdef _WIN32
    /*
     * Make sure executables can find dependent DLLs and that they're *our*
     * DLLs: https://msdn.microsoft.com/en-us/library/windows/desktop/ms682586.aspx
     * Alternatively we could create a simple wrapper exe similar to Create
     * Hidden Process (http://www.commandline.co.uk/chp/).
     */
    dll_search_envp = g_get_environ();
    progfile_dir = g_strdup_printf("%s;%s", get_progfile_dir(), g_environ_getenv(dll_search_envp, "Path"));
    dll_search_envp = g_environ_setenv(dll_search_envp, "Path", progfile_dir, TRUE);
    g_free(progfile_dir);
#endif

    if ((dir = g_dir_open(dirname, 0, NULL)) != NULL) {
#ifdef _WIN32
        dirname = g_strescape(dirname,NULL);
#endif
        while (keep_going && (file = g_dir_read_name(dir)) != NULL ) {
            GString *extcap_string = NULL;
            gchar *extcap = NULL;
            gchar *command_output = NULL;
            gboolean status = FALSE;
            gint i;
            gint exit_status = 0;
            GError *error = NULL;
            gchar **envp = NULL;

            /* full path to extcap binary */
            extcap_string = g_string_new("");
#ifdef _WIN32
            g_string_printf(extcap_string, "%s\\\\%s",dirname,file);
            extcap = g_string_free(extcap_string, FALSE);
            envp = dll_search_envp;
#else
            g_string_printf(extcap_string, "%s/%s", dirname, file);
            extcap = g_string_free(extcap_string, FALSE);
#endif
            if ( extcap_if_exists(ifname) && !extcap_if_exists_for_extcap(ifname, extcap ) )
                continue;

            argv[0] = extcap;
            for (i = 0; i < argc; ++i)
                argv[i+1] = args[i];
            argv[argc+1] = NULL;

            status = g_spawn_sync(dirname, argv, envp,
                (GSpawnFlags) 0, NULL, NULL,
                    &command_output, NULL, &exit_status, &error);

            if (status && exit_status == 0)
            keep_going = cb(extcap, command_output, cb_data, err_str);

            g_free(extcap);
            g_free(command_output);
        }

        g_dir_close(dir);
    }

#ifdef _WIN32
    g_strfreev(dll_search_envp);
#endif
    g_free(argv);
}

static gboolean dlt_cb(const gchar *extcap _U_, gchar *output, void *data,
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

    if (ifname != NULL && err_str != NULL)
        *err_str = NULL;

    if ( extcap_if_exists(ifname) )
    {
        argv[0] = g_strdup(EXTCAP_ARGUMENT_LIST_DLTS);
        argv[1] = g_strdup(EXTCAP_ARGUMENT_INTERFACE);
        argv[2] = g_strdup(ifname);

        if (err_str)
            *err_str = NULL;
        extcap_foreach(3, argv, dlt_cb, &caps, err_str, ifname);

        for (i = 0; i < 3; ++i)
            g_free(argv[i]);
    }

    return caps;
}

static gboolean interfaces_cb(const gchar *extcap, gchar *output, void *data,
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
        if ( extcap_if_exists(int_iter->call) )
        {
            g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_WARNING, "Extcap interface \"%s\" is already provided by \"%s\" ",
                    int_iter->call, (gchar *)extcap_if_executable(int_iter->call) );
            int_iter = int_iter->next_interface;
            continue;
        }

        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "  Interface [%s] \"%s\" ",
                int_iter->call, int_iter->display);

        if_info = g_new0(if_info_t, 1);
        if_info->name = g_strdup(int_iter->call);
        if_info->friendly_name = g_strdup(int_iter->display);

        if_info->type = IF_EXTCAP;

        if_info->extcap = g_strdup(extcap);
        *il = g_list_append(*il, if_info);

        extcap_if_add(g_strdup(int_iter->call), g_strdup(extcap) );
        int_iter = int_iter->next_interface;
    }

    return TRUE;
}

GList *
extcap_interface_list(char **err_str) {
    gchar *argv;
    /* gint i; */
    GList *ret = NULL;

    if (err_str != NULL)
    *err_str = NULL;

    extcap_if_cleanup();

    argv = g_strdup(EXTCAP_ARGUMENT_LIST_INTERFACES);

    if (err_str)
    *err_str = NULL;
    extcap_foreach(1, &argv, interfaces_cb, &ret, err_str, NULL);

    g_free(argv);

    return ret;
}

static void g_free_1(gpointer data, gpointer user_data _U_)
{
    g_free(data);
}

static void extcap_free_if_configuration(GList *list)
{
    GList *elem;

    for (elem = g_list_first(list); elem; elem = elem->next)
    {
        GList *arg_list;
        if (elem->data == NULL)
        {
            continue;
        }

        arg_list = g_list_first((GList *)elem->data);
        g_list_foreach(arg_list, g_free_1, NULL);
        g_list_free(arg_list);
    }
    g_list_free(list);
}

static gboolean search_cb(const gchar *extcap _U_, gchar *output, void *data,
        char **err_str _U_) {
    extcap_token_sentence *tokens = NULL;
    GList *arguments = NULL;
    GList **il = (GList **) data;

    tokens = extcap_tokenize_sentences(output);
    arguments = extcap_parse_args(tokens);

    extcap_free_tokenized_sentence_list(tokens);

#if ARG_DEBUG
    extcap_debug_arguments ( arguments );
#endif

    *il = g_list_append(*il, arguments);

    /* By returning false, extcap_foreach will break on first found */
    return TRUE;
}

GList *
extcap_get_if_configuration(const char * ifname) {
    gchar *argv[4];
    GList *ret = NULL;
    gchar **err_str = NULL;

    if ( extcap_if_exists(ifname) )
    {
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "Extcap path %s",
                get_extcap_dir());

        argv[0] = g_strdup(EXTCAP_ARGUMENT_CONFIG);
        argv[1] = g_strdup(EXTCAP_ARGUMENT_INTERFACE);
        argv[2] = g_strdup(ifname);
        argv[3] = NULL;

        extcap_foreach(4, argv, search_cb, &ret, err_str, ifname);
    }

    return ret;
}

gboolean
extcap_has_configuration(const char * ifname) {
    GList * arguments = 0;
    GList * walker = 0, * item = 0;

    gboolean found = FALSE;

    arguments = extcap_get_if_configuration((const char *)( ifname ) );
    walker = g_list_first(arguments);

    while ( walker != NULL && ! found )
    {
        item = g_list_first((GList *)(walker->data));
        while ( item != NULL && ! found )
        {
            if ( (extcap_arg *)(item->data) != NULL )
                found = TRUE;

            item = item->next;
        }
        walker = walker->next;
    }

    return found;
}

void extcap_cleanup(capture_options * capture_opts) {
    interface_options interface_opts;
    guint icnt = 0;

    for (icnt = 0; icnt < capture_opts->ifaces->len; icnt++) {
        interface_opts = g_array_index(capture_opts->ifaces, interface_options,
                icnt);

        /* skip native interfaces */
        if (interface_opts.if_type != IF_EXTCAP)
        continue;

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
        }

        /* Make sure modified interface_opts is saved in capture_opts. */
        capture_opts->ifaces = g_array_remove_index(capture_opts->ifaces, icnt);
        g_array_insert_val(capture_opts->ifaces, icnt, interface_opts);
    }
}

static void
extcap_arg_cb(gpointer key, gpointer value, gpointer data) {
    GPtrArray *args = (GPtrArray *)data;

    if ( key != NULL )
    {
        g_ptr_array_add(args, g_strdup((const gchar*)key));

        if ( value != NULL )
            g_ptr_array_add(args, g_strdup((const gchar*)value));
    }
}

static void extcap_child_watch_cb(GPid pid, gint status _U_, gpointer user_data)
{
    guint i;
    interface_options interface_opts;
    capture_options *capture_opts = (capture_options *)user_data;

    /* Close handle to child process. */
    g_spawn_close_pid(pid);

    /* Update extcap_pid in interface options structure. */
    for (i = 0; i < capture_opts->ifaces->len; i++)
    {
        interface_opts = g_array_index(capture_opts->ifaces, interface_options, i);
        if (interface_opts.extcap_pid == pid)
        {
            interface_opts.extcap_pid = INVALID_EXTCAP_PID;
            interface_opts.extcap_child_watch = 0;
            capture_opts->ifaces = g_array_remove_index(capture_opts->ifaces, i);
            g_array_insert_val(capture_opts->ifaces, i, interface_opts);
            break;
        }
    }
}

/* call mkfifo for each extcap,
 * returns FALSE if there's an error creating a FIFO */
gboolean
extcaps_init_initerfaces(capture_options *capture_opts)
{
    guint i;
    interface_options interface_opts;

    for (i = 0; i < capture_opts->ifaces->len; i++)
    {
        GPtrArray *args = NULL;
        GPid pid = INVALID_EXTCAP_PID;
        gchar **tmp;
        int tmp_i;

        interface_opts = g_array_index(capture_opts->ifaces, interface_options, i);

        /* skip native interfaces */
        if (interface_opts.if_type != IF_EXTCAP )
            continue;

        /* create pipe for fifo */
        if ( ! extcap_create_pipe ( &interface_opts.extcap_fifo ) )
            return FALSE;

        /* Create extcap call */
        args = g_ptr_array_new();
#define add_arg(X) g_ptr_array_add(args, g_strdup(X))

        add_arg(interface_opts.extcap);
        add_arg(EXTCAP_ARGUMENT_RUN_CAPTURE);
        add_arg(EXTCAP_ARGUMENT_INTERFACE);
        add_arg(interface_opts.name);
        add_arg(EXTCAP_ARGUMENT_RUN_PIPE);
        add_arg(interface_opts.extcap_fifo);
        if (interface_opts.extcap_args == NULL)
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
                while (arg_list != NULL)
                {
                    /* In case of boolflags only first element in arg_list is relevant. */
                    arg_iter = (extcap_arg*) (arg_list->data);

                    if  (arg_iter->arg_type == EXTCAP_ARG_BOOLFLAG)
                    {
                        if (arg_iter->default_complex != NULL
                            && extcap_complex_get_bool(arg_iter->default_complex))
                        {
                            add_arg(arg_iter->call);
                        }
                    }

                    arg_list = arg_list->next;
                }
            }

            extcap_free_if_configuration(arglist);
        }
        else
        {
            g_hash_table_foreach(interface_opts.extcap_args, extcap_arg_cb, args);
        }
        add_arg(NULL);
#undef add_arg

        /* Dump commandline parameters sent to extcap. */
        for (tmp = (gchar **)args->pdata, tmp_i = 0; *tmp && **tmp; ++tmp_i, ++tmp)
        {
            g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "argv[%d]: %s", tmp_i, *tmp);
        }

        /* Wireshark for windows crashes here sometimes *
         * Access violation reading location 0x...      */
        g_spawn_async(NULL, (gchar **)args->pdata, NULL,
                    (GSpawnFlags) G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL,
                    &pid,NULL);

        g_ptr_array_foreach(args, (GFunc)g_free, NULL);
        g_ptr_array_free(args, TRUE);
        interface_opts.extcap_pid = pid;
        interface_opts.extcap_child_watch =
            g_child_watch_add(pid, extcap_child_watch_cb, (gpointer)capture_opts);
        capture_opts->ifaces = g_array_remove_index(capture_opts->ifaces, i);
        g_array_insert_val(capture_opts->ifaces, i, interface_opts);

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
            DWORD dw;
            HANDLE handles[2];
            OVERLAPPED ov;
            ov.Pointer = 0;
            ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

            ConnectNamedPipe(pipe_h, &ov);
            handles[0] = ov.hEvent;
            handles[1] = pid;

            if (GetLastError() == ERROR_PIPE_CONNECTED)
            {
                g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "extcap connected to pipe");
            }
            else
            {
                dw = WaitForMultipleObjects(2, handles, FALSE, 30000);
                if (dw == WAIT_OBJECT_0)
                {
                    /* ConnectNamedPipe finished. */
                    DWORD code;

                    code = GetLastError();
                    if (code == ERROR_IO_PENDING)
                    {
                        DWORD dummy;
                        if (!GetOverlappedResult(ov.hEvent, &ov, &dummy, TRUE))
                        {
                            code = GetLastError();
                        }
                        else
                        {
                            code = ERROR_SUCCESS;
                        }
                    }

                    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "ConnectNamedPipe code: %d", code);
                }
                else if (dw == (WAIT_OBJECT_0 + 1))
                {
                    /* extcap process terminated. */
                    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "extcap terminated without connecting to pipe!");
                }
                else if (dw == WAIT_TIMEOUT)
                {
                    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "extcap didn't connect to pipe within 30 seconds!");
                }
                else
                {
                    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "WaitForMultipleObjects returned 0x%08X. Error %d", dw, GetLastError());
                }
            }

            CloseHandle(ov.hEvent);
        }
#endif
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

    if ( ( fd = create_tempfile ( &temp_name, EXTCAP_PIPE_PREFIX ) ) == 0 )
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
            if (v->is_default == TRUE)
            printf("*");
            printf("\tcall=\"%p\" display=\"%p\"\n", v->call, v->display);
            printf("\tcall=\"%s\" display=\"%s\"\n", v->call, v->display);
        }

        arg_iter = arg_iter->next_arg;
    }
}
#endif
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
