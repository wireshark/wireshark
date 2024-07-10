/* capture_sync.c
 * Synchronisation between Wireshark capture parent and child instances
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_CAPTURE

#include <wireshark.h>

#ifdef HAVE_LIBPCAP

#include <glib.h>
#include <stdio.h>
#include <stdlib.h>

#include <signal.h>

#include <ws_exit_codes.h>

#include <wsutil/strtoi.h>
#include <wsutil/ws_assert.h>

#ifdef _WIN32
#include <wsutil/unicode-utils.h>
#include <wsutil/win32-utils.h>
#include <wsutil/ws_pipe.h>
#else
#include <glib-unix.h>
#endif

#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif

#include "capture/capture-pcap-util.h"

#ifndef _WIN32
/*
 * Define various POSIX macros (and, in the case of WCOREDUMP, non-POSIX
 * macros) on UNIX systems that don't have them.
 */
#ifndef WIFEXITED
# define WIFEXITED(status)      (((status) & 0177) == 0)
#endif
#ifndef WIFSTOPPED
# define WIFSTOPPED(status)     (((status) & 0177) == 0177)
#endif
#ifndef WIFSIGNALED
# define WIFSIGNALED(status)    (!WIFSTOPPED(status) && !WIFEXITED(status))
#endif
#ifndef WEXITSTATUS
# define WEXITSTATUS(status)    ((status) >> 8)
#endif
#ifndef WTERMSIG
# define WTERMSIG(status)       ((status) & 0177)
#endif
#ifndef WCOREDUMP
# define WCOREDUMP(status)      ((status) & 0200)
#endif
#ifndef WSTOPSIG
# define WSTOPSIG(status)       ((status) >> 8)
#endif
#endif /* _WIN32 */

#include <epan/packet.h>
#include <epan/prefs.h>

#include "file.h"

#include "ui/capture.h"
#include <capture/capture_sync.h>

#include "sync_pipe.h"

#ifdef _WIN32
#include "capture/capture-wpcap.h"
#endif

#include "ui/ws_ui_util.h"

#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>
#include <wsutil/report_message.h>
#include "extcap.h"

#ifdef _WIN32
#include <process.h>    /* For spawning child process */
#endif

#include <wsutil/ws_pipe.h>

#ifdef _WIN32
static int create_dummy_signal_pipe(char **msg);
static HANDLE dummy_signal_pipe; /* Dummy named pipe which lets the child check for a dropped connection */
static char *dummy_control_id;
#else
static const char *sync_pipe_signame(int);
#endif

/* We use this pipe buffer size for both the sync message pipe and the
 * data pipe. Ensure that it's large enough for the indicator and header
 * plus maximum message size.
 */
#define PIPE_BUF_SIZE (SP_MAX_MSG_LEN+4)

static gboolean sync_pipe_input_cb(GIOChannel *pipe_io, capture_session *cap_session);
static int sync_pipe_wait_for_child(ws_process_id fork_child, char **msgp);
static void pipe_convert_header(const unsigned char *header, int header_len, char *indicator, int *block_len);
static ssize_t pipe_read_block(GIOChannel *pipe_io, char *indicator, int len, char *msg,
                           char **err_msg);

static void (*fetch_dumpcap_pid)(ws_process_id);

void
capture_session_init(capture_session *cap_session, capture_file *cf,
                     new_file_fn new_file, new_packets_fn new_packets,
                     drops_fn drops, error_fn error,
                     cfilter_error_fn cfilter_error, closed_fn closed)
{
    cap_session->cf                              = cf;
    cap_session->fork_child                      = WS_INVALID_PID;   /* invalid process handle */
    cap_session->pipe_input_id                   = 0;
#ifdef _WIN32
    cap_session->signal_pipe_write_fd            = -1;
#endif
    cap_session->state                           = CAPTURE_STOPPED;
#ifndef _WIN32
    cap_session->owner                           = getuid();
    cap_session->group                           = getgid();
#endif
    cap_session->count                           = 0;
    cap_session->count_pending                   = 0;
    cap_session->session_will_restart            = false;

    cap_session->new_file                        = new_file;
    cap_session->new_packets                     = new_packets;
    cap_session->drops                           = drops;
    cap_session->error                           = error;
    cap_session->cfilter_error                   = cfilter_error;
    cap_session->closed                          = closed;
    cap_session->frame_cksum                     = NULL;
}

void capture_process_finished(capture_session *cap_session)
{
    capture_options *capture_opts = cap_session->capture_opts;
    interface_options *interface_opts;
    GString *message;
    unsigned i;

    if (!extcap_session_stop(cap_session)) {
        /* At least one extcap process did not fully finish yet, wait for it */
        return;
    }

    if (cap_session->fork_child != WS_INVALID_PID) {
        if (capture_opts->stop_after_extcaps) {
            /* User has requested capture stop and all extcaps are gone now */
            capture_opts->stop_after_extcaps = false;
            sync_pipe_stop(cap_session);
        }
        /* Wait for child process to end, session is not closed yet */
        return;
    }

    /* Construct message and close session */
    message = g_string_new(capture_opts->closed_msg);
    for (i = 0; i < capture_opts->ifaces->len; i++) {
        interface_opts = &g_array_index(capture_opts->ifaces, interface_options, i);
        if (interface_opts->if_type != IF_EXTCAP) {
            continue;
        }

        if ((interface_opts->extcap_stderr != NULL) &&
            (interface_opts->extcap_stderr->len > 0)) {
            if (message->len > 0) {
                g_string_append(message, "\n");
            }
            g_string_append(message, "Error from extcap pipe: ");
            g_string_append(message, interface_opts->extcap_stderr->str);
        }
    }

    cap_session->closed(cap_session, message->str);
    g_string_free(message, TRUE);
    g_free(capture_opts->closed_msg);
    capture_opts->closed_msg = NULL;
    capture_opts->stop_after_extcaps = false;
}

/* Append an arg (realloc) to an argc/argv array */
/* (add a string pointer to a NULL-terminated array of string pointers) */
/* XXX: For glib >= 2.68 we could use a GStrvBuilder.
 */
static char **
sync_pipe_add_arg(char **args, int *argc, const char *arg)
{
    /* Grow the array; "*argc" currently contains the number of string
       pointers, *not* counting the NULL pointer at the end, so we have
       to add 2 in order to get the new size of the array, including the
       new pointer and the terminating NULL pointer. */
    args = (char **)g_realloc( (void *) args, (*argc + 2) * sizeof (char *));

    /* Stuff the pointer into the penultimate element of the array, which
       is the one at the index specified by "*argc". */
    args[*argc] = g_strdup(arg);
    /* Now bump the count. */
    (*argc)++;

    /* We overwrite the NULL pointer; put it back right after the
       element we added. */
    args[*argc] = NULL;

    return args;
}

/* Take a buffer from an SP_LOG_MSG from dumpcap and send it to our
 * current logger. Keep this in sync with the format used in
 * dumpcap_log_writer. (We might want to do more proper serialization
 * of more than just the log level.)
 */
static void
sync_pipe_handle_log_msg(const char *buffer) {
    const char *log_msg = NULL;
    const char* end;
    uint32_t level = 0;

    if (ws_strtou32(buffer, &end, &level) && end[0] == ':') {
        log_msg = end + 1;
    }
    ws_log(LOG_DOMAIN_CAPCHILD, level, "%s", log_msg);
}

/* Initialize an argument list and add dumpcap to it. */
static char **
init_pipe_args(int *argc) {
    char *exename;
    char **argv;

    /* Find the absolute path of the dumpcap executable. */
    exename = get_executable_path("dumpcap");
    if (exename == NULL) {
        return NULL;
    }

    /* Allocate the string pointer array with enough space for the
       terminating NULL pointer. */
    *argc = 0;
    argv = (char **)g_malloc(sizeof (char *));
    *argv = NULL;

    /* Make that the first argument in the argument list (argv[0]). */
    argv = sync_pipe_add_arg(argv, argc, exename);

    /* Tell dumpcap to log at the lowest level its domain (Capchild) is
     * set to log in the main program. (It might be in the special noisy
     * or debug filter, so we can't just check the overall level.)
     */
    for (enum ws_log_level level = LOG_LEVEL_NOISY; level != _LOG_LEVEL_LAST; level++) {
        if (ws_log_msg_is_active(LOG_DOMAIN_CAPCHILD, level)) {
            argv = sync_pipe_add_arg(argv, argc, "--log-level");
            argv = sync_pipe_add_arg(argv, argc, ws_log_level_to_string(level));
            break;
        }
    }

    /* sync_pipe_add_arg strdupes exename, so we should free our copy */
    g_free(exename);

    return argv;
}

static gboolean
pipe_io_cb(GIOChannel *pipe_io, GIOCondition condition _U_, void * user_data)
{
    capture_session *cap_session = (capture_session *)user_data;
    if (!sync_pipe_input_cb(pipe_io, cap_session)) {
        cap_session->pipe_input_id = 0;
        return G_SOURCE_REMOVE;
    }
    return G_SOURCE_CONTINUE;
}

/*
 * Open two pipes to dumpcap with the supplied arguments, one for its
 * standard output and one for its standard error.
 *
 * On success, *msg is unchanged and 0 is returned; data_read_fd,
 * message_read_fd, and fork_child point to the standard output pipe's
 * file descriptor, the standard error pipe's file descriptor, and
 * the child's PID/handle, respectively.
 *
 * On failure, *msg points to an error message for the failure, and -1 is
 * returned, in which case *msg must be freed with g_free().
 */
#define ARGV_NUMBER_LEN 24
static int
#ifdef _WIN32
sync_pipe_open_command(char **argv, int *data_read_fd,
                       GIOChannel **message_read_io, int *signal_write_fd,
                       ws_process_id *fork_child, GArray *ifaces,
                       char **msg, void(*update_cb)(void))
#else
sync_pipe_open_command(char **argv, int *data_read_fd,
                       GIOChannel **message_read_io, int *signal_write_fd _U_,
                       ws_process_id *fork_child, GArray *ifaces _U_,
                       char **msg, void(*update_cb)(void))
#endif
{
    enum PIPES { PIPE_READ, PIPE_WRITE };   /* Constants 0 and 1 for PIPE_READ and PIPE_WRITE */
    int message_read_fd = -1;
    char sync_id[ARGV_NUMBER_LEN];
#ifdef _WIN32
    HANDLE sync_pipe[2];                    /* pipe used to send messages from child to parent */
    HANDLE data_pipe[2];                    /* pipe used to send data from child to parent */
    int signal_pipe_write_fd = -1;
    HANDLE signal_pipe;                     /* named pipe used to send messages from parent to child (currently only stop) */
    char control_id[ARGV_NUMBER_LEN];
    char *signal_pipe_name;
    size_t i_handles = 0;
    HANDLE *handles;
    GString *args = g_string_sized_new(200);
    char *quoted_arg;
    SECURITY_ATTRIBUTES sa;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    int i;
    unsigned j;
    interface_options *interface_opts;
#else
    int sync_pipe[2];                       /* pipe used to send messages from child to parent */
    int data_pipe[2];                       /* pipe used to send data from child to parent */
#endif
    *fork_child = WS_INVALID_PID;
    if (data_read_fd != NULL) {
        *data_read_fd = -1;
    }
    *message_read_io = NULL;
    ws_debug("sync_pipe_open_command");

    if (!msg) {
        /* We can't return anything */
        g_strfreev(argv);
#ifdef _WIN32
        g_string_free(args, TRUE);
#endif
        return -1;
    }

#ifdef _WIN32
    /* init SECURITY_ATTRIBUTES */
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = false;
    sa.lpSecurityDescriptor = NULL;

    /* Create a pipe for the child process to send us messages */
    /* (increase this value if you have trouble while fast capture file switches) */
    if (! CreatePipe(&sync_pipe[PIPE_READ], &sync_pipe[PIPE_WRITE], &sa, PIPE_BUF_SIZE)) {
        /* Couldn't create the message pipe between parent and child. */
        *msg = ws_strdup_printf("Couldn't create sync pipe: %s",
                               win32strerror(GetLastError()));
        g_strfreev(argv);
        return -1;
    }

    /*
     * Associate a C run-time file handle with the Windows HANDLE for the
     * read side of the message pipe.
     *
     * (See http://www.flounder.com/handles.htm for information on various
     * types of file handle in C/C++ on Windows.)
     */
    message_read_fd = _open_osfhandle( (intptr_t) sync_pipe[PIPE_READ], _O_BINARY);
    if (message_read_fd == -1) {
        *msg = ws_strdup_printf("Couldn't get C file handle for message read pipe: %s", g_strerror(errno));
        g_strfreev(argv);
        CloseHandle(sync_pipe[PIPE_READ]);
        CloseHandle(sync_pipe[PIPE_WRITE]);
        return -1;
    }

    if (data_read_fd != NULL) {
        /* Create a pipe for the child process to send us data */
        /* (increase this value if you have trouble while fast capture file switches) */
        if (! CreatePipe(&data_pipe[PIPE_READ], &data_pipe[PIPE_WRITE], &sa, PIPE_BUF_SIZE)) {
            /* Couldn't create the message pipe between parent and child. */
            *msg = ws_strdup_printf("Couldn't create data pipe: %s",
                                   win32strerror(GetLastError()));
            g_strfreev(argv);
            ws_close(message_read_fd);    /* Should close sync_pipe[PIPE_READ] */
            CloseHandle(sync_pipe[PIPE_WRITE]);
            return -1;
        }

        /*
         * Associate a C run-time file handle with the Windows HANDLE for the
         * read side of the data pipe.
         *
         * (See http://www.flounder.com/handles.htm for information on various
         * types of file handle in C/C++ on Windows.)
         */
        *data_read_fd = _open_osfhandle( (intptr_t) data_pipe[PIPE_READ], _O_BINARY);
        if (*data_read_fd == -1) {
            *msg = ws_strdup_printf("Couldn't get C file handle for data read pipe: %s", g_strerror(errno));
            g_strfreev(argv);
            CloseHandle(data_pipe[PIPE_READ]);
            CloseHandle(data_pipe[PIPE_WRITE]);
            ws_close(message_read_fd);    /* Should close sync_pipe[PIPE_READ] */
            CloseHandle(sync_pipe[PIPE_WRITE]);
            return -1;
        }
    }

    if (signal_write_fd != NULL) {
        /* Create the signal pipe */
        snprintf(control_id, ARGV_NUMBER_LEN, "%ld", GetCurrentProcessId());
        signal_pipe_name = ws_strdup_printf(SIGNAL_PIPE_FORMAT, control_id);
        signal_pipe = CreateNamedPipe(utf_8to16(signal_pipe_name),
                                      PIPE_ACCESS_OUTBOUND, PIPE_TYPE_BYTE, 1, 65535, 65535, 0, NULL);
        g_free(signal_pipe_name);

        if (signal_pipe == INVALID_HANDLE_VALUE) {
            /* Couldn't create the signal pipe between parent and child. */
            *msg = ws_strdup_printf("Couldn't create signal pipe: %s",
                           win32strerror(GetLastError()));
            g_strfreev(argv);
            ws_close(message_read_fd);    /* Should close sync_pipe[PIPE_READ] */
            CloseHandle(sync_pipe[PIPE_WRITE]);
            return -1;
        }

        /*
         * Associate a C run-time file handle with the Windows HANDLE for the
         * read side of the message pipe.
         *
         * (See http://www.flounder.com/handles.htm for information on various
         * types of file handle in C/C++ on Windows.)
         */
        signal_pipe_write_fd = _open_osfhandle( (intptr_t) signal_pipe, _O_BINARY);
        if (signal_pipe_write_fd == -1) {
            /* Couldn't create the pipe between parent and child. */
            *msg = ws_strdup_printf("Couldn't get C file handle for sync pipe: %s", g_strerror(errno));
            g_strfreev(argv);
            ws_close(message_read_fd);    /* Should close sync_pipe[PIPE_READ] */
            CloseHandle(sync_pipe[PIPE_WRITE]);
            CloseHandle(signal_pipe);
            return -1;
        }
    }

    /* init STARTUPINFO & PROCESS_INFORMATION */
    memset(&si, 0, sizeof(si));
    si.cb           = sizeof(si);
    memset(&pi, 0, sizeof(pi));
#ifdef DEBUG_CHILD
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow  = SW_SHOW;
#else
    si.dwFlags = STARTF_USESTDHANDLES|STARTF_USESHOWWINDOW;
    si.wShowWindow  = SW_HIDE;  /* this hides the console window */

    if (data_read_fd == NULL) {
        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    } else {
        si.hStdInput = NULL; /* handle for named pipe*/
        si.hStdOutput = data_pipe[PIPE_WRITE];
    }
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);

    /* On Windows, "[a]n inherited handle refers to the same object in the child
     * process as it does in the parent process. It also has the same value."
     * https://learn.microsoft.com/en-us/windows/win32/procthread/inheritance
     * When converted to a file descriptor (via _open_osfhandle), the fd
     * value is not necessarily the same in the two processes, but the handle
     * value can be shared.
     * A HANDLE is a void* though "64-bit versions of Windows use 32-bit handles
     * for interoperability... only the lower 32 bits are significant, so it is
     * safe to truncate the handle... or sign-extend the handle"
     * https://learn.microsoft.com/en-us/windows/win32/winprog64/interprocess-communication
     * So it should be fine to call PtrToLong instead of casting to intptr_t.
     * https://learn.microsoft.com/en-us/windows/win32/WinProg64/rules-for-using-pointers
     */
    int argc = g_strv_length(argv);
    argv = sync_pipe_add_arg(argv, &argc, "-Z");
    snprintf(sync_id, ARGV_NUMBER_LEN, "%ld", PtrToLong(sync_pipe[PIPE_WRITE]));
    argv = sync_pipe_add_arg(argv, &argc, sync_id);
#endif

    if (ifaces) {
        for (j = 0; j < ifaces->len; j++) {
            interface_opts = &g_array_index(ifaces, interface_options, j);
            if (interface_opts->extcap_fifo != NULL) {
                i_handles++;
            }
        }
    }
    handles = g_new(HANDLE, 3 + i_handles);
    i_handles = 0;
    if (si.hStdInput) {
        handles[i_handles++] = si.hStdInput;
    }
    if (si.hStdOutput && (si.hStdOutput != si.hStdInput)) {
        handles[i_handles++] = si.hStdOutput;
    }
    handles[i_handles++] = sync_pipe[PIPE_WRITE];
    if (ifaces) {
        for (j = 0; j < ifaces->len; j++) {
            interface_opts = &g_array_index(ifaces, interface_options, j);
            if (interface_opts->extcap_fifo != NULL) {
                handles[i_handles++] = interface_opts->extcap_pipe_h;
            }
        }
    }

    /* convert args array into a single string */
    /* XXX - could change sync_pipe_add_arg() instead */
    /* there is a drawback here: the length is internally limited to 1024 bytes */
    for(i=0; argv[i] != 0; i++) {
        if(i != 0) g_string_append_c(args, ' ');    /* don't prepend a space before the path!!! */
        quoted_arg = protect_arg(argv[i]);
        g_string_append(args, quoted_arg);
        g_free(quoted_arg);
    }

    /* call dumpcap */
    if(!win32_create_process(argv[0], args->str, NULL, NULL, i_handles, handles,
                             CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        *msg = ws_strdup_printf("Couldn't run %s in child process: %s",
                               args->str, win32strerror(GetLastError()));
        if (data_read_fd) {
            ws_close(*data_read_fd);       /* Should close data_pipe[PIPE_READ] */
            CloseHandle(data_pipe[PIPE_WRITE]);
        } else {
            ws_close(signal_pipe_write_fd);
        }
        ws_close(message_read_fd);    /* Should close sync_pipe[PIPE_READ] */
        CloseHandle(sync_pipe[PIPE_WRITE]);
        g_strfreev(argv);
        g_string_free(args, TRUE);
        g_free(handles);
        return -1;
    }
    *fork_child = pi.hProcess;
    /* We may need to store this and close it later */
    CloseHandle(pi.hThread);
    g_strfreev(argv);
    g_string_free(args, TRUE);
    g_free(handles);

    if (signal_write_fd != NULL) {
        *signal_write_fd = signal_pipe_write_fd;
    }
#else /* _WIN32 */
    /* Create a pipe for the child process to send us messages */
    if (pipe(sync_pipe) < 0) {
        /* Couldn't create the message pipe between parent and child. */
        *msg = ws_strdup_printf("Couldn't create sync pipe: %s", g_strerror(errno));
        g_strfreev(argv);
        return -1;
    }

    if (data_read_fd != NULL) {
        /* Create a pipe for the child process to send us data */
        if (pipe(data_pipe) < 0) {
            /* Couldn't create the data pipe between parent and child. */
            *msg = ws_strdup_printf("Couldn't create data pipe: %s", g_strerror(errno));
            g_strfreev(argv);
            ws_close(sync_pipe[PIPE_READ]);
            ws_close(sync_pipe[PIPE_WRITE]);
            return -1;
        }
    }

    if ((*fork_child = fork()) == 0) {
        /*
         * Child process - run dumpcap with the right arguments to make
         * it just capture with the specified capture parameters
         */
        if (data_read_fd != NULL) {
            dup2(data_pipe[PIPE_WRITE], 1);
            ws_close(data_pipe[PIPE_READ]);
            ws_close(data_pipe[PIPE_WRITE]);
        }
        ws_close(sync_pipe[PIPE_READ]);
        /* dumpcap should be running in capture child mode (hidden feature) */
#ifndef DEBUG_CHILD
        int argc = g_strv_length(argv);
        argv = sync_pipe_add_arg(argv, &argc, "-Z");
        snprintf(sync_id, ARGV_NUMBER_LEN, "%d", sync_pipe[PIPE_WRITE]);
        argv = sync_pipe_add_arg(argv, &argc, sync_id);
#endif
        execv(argv[0], argv);
        sync_pipe_write_int_msg(sync_pipe[PIPE_WRITE], SP_EXEC_FAILED, errno);

        /* Exit with "_exit()", so that we don't close the connection
           to the X server (and cause stuff buffered up by our parent but
           not yet sent to be sent, as that stuff should only be sent by
           our parent).  We've sent an error message to the parent, so
           we exit with an exit status of 1 (any exit status other than
           0 or 1 will cause an additional message to report that exit
           status, over and above the error message we sent to the parent). */
        _exit(1);
    }

    g_strfreev(argv);

    if (fetch_dumpcap_pid && *fork_child > 0)
        fetch_dumpcap_pid(*fork_child);

    if (data_read_fd != NULL) {
        *data_read_fd = data_pipe[PIPE_READ];
    }
    message_read_fd = sync_pipe[PIPE_READ];

#endif

    /* Parent process - read messages from the child process over the
       sync pipe. */

    /* Close the write sides of the pipes, so that only the child has them
       open, and thus they completely close, and thus return to us
       an EOF indication, if the child closes them (either deliberately
       or by exiting abnormally). */
#ifdef _WIN32
    if (data_read_fd != NULL) {
        CloseHandle(data_pipe[PIPE_WRITE]);
    }
    CloseHandle(sync_pipe[PIPE_WRITE]);
#else
    if (data_read_fd != NULL) {
        ws_close(data_pipe[PIPE_WRITE]);
    }
    ws_close(sync_pipe[PIPE_WRITE]);
#endif

    if (*fork_child == WS_INVALID_PID) {
        /* We couldn't even create the child process. */
        *msg = ws_strdup_printf("Couldn't create child process: %s", g_strerror(errno));
        if (data_read_fd != NULL) {
            ws_close(*data_read_fd);
        }
#ifdef _WIN32
        if (signal_write_fd != NULL) {
            ws_close(signal_pipe_write_fd);
        }
#endif
        ws_close(message_read_fd);
        return -1;
    }

#ifdef _WIN32
    *message_read_io = g_io_channel_win32_new_fd(message_read_fd);
#else
    *message_read_io = g_io_channel_unix_new(message_read_fd);
#endif
    g_io_channel_set_encoding(*message_read_io, NULL, NULL);
    g_io_channel_set_buffered(*message_read_io, false);
    g_io_channel_set_close_on_unref(*message_read_io, true);

    /* we might wait for a moment till child is ready, so update screen now */
    if (update_cb) update_cb();
    return 0;
}

/* a new capture run: start a new dumpcap task and hand over parameters through command line */
bool
sync_pipe_start(capture_options *capture_opts, GPtrArray *capture_comments,
                capture_session *cap_session, info_data_t* cap_data,
                void (*update_cb)(void))
{
#ifdef _WIN32
    size_t i_handles = 0;
    char control_id[ARGV_NUMBER_LEN];
#endif
    GIOChannel *sync_pipe_read_io;
    int argc;
    char **argv;
    int i;
    unsigned j;
    interface_options *interface_opts;

    if (capture_opts->ifaces->len > 1)
        capture_opts->use_pcapng = true;
    ws_debug("sync_pipe_start");
    capture_opts_log(LOG_DOMAIN_CAPTURE, LOG_LEVEL_DEBUG, capture_opts);

    cap_session->fork_child = WS_INVALID_PID;
    cap_session->capture_opts = capture_opts;

    if (!extcap_init_interfaces(cap_session)) {
        report_failure("Unable to init extcaps. (tmp fifo already exists?)");
        return false;
    }

    argv = init_pipe_args(&argc);
    if (!argv) {
        /* We don't know where to find dumpcap. */
        report_failure("We don't know where to find dumpcap.");
        return false;
    }

    if (capture_opts->ifaces->len > 1)
        argv = sync_pipe_add_arg(argv, &argc, "-t");

    argv = sync_pipe_add_arg(argv, &argc, "-F");
    if (capture_opts->use_pcapng)
        argv = sync_pipe_add_arg(argv, &argc, "pcapng");
    else
        argv = sync_pipe_add_arg(argv, &argc, "pcap");

    if (capture_comments != NULL) {
        for (j = 0; j < capture_comments->len; j++) {
            argv = sync_pipe_add_arg(argv, &argc, "--capture-comment");
            argv = sync_pipe_add_arg(argv, &argc, (char*)g_ptr_array_index(capture_comments, j));
        }
    }

    if (capture_opts->temp_dir) {
            argv = sync_pipe_add_arg(argv, &argc, "--temp-dir");
            argv = sync_pipe_add_arg(argv, &argc, capture_opts->temp_dir);
    }

    if (capture_opts->multi_files_on) {
        if (capture_opts->has_autostop_filesize) {
            char sfilesize[ARGV_NUMBER_LEN];
            argv = sync_pipe_add_arg(argv, &argc, "-b");
            snprintf(sfilesize, ARGV_NUMBER_LEN, "filesize:%u",capture_opts->autostop_filesize);
            argv = sync_pipe_add_arg(argv, &argc, sfilesize);
        }

        if (capture_opts->has_file_duration) {
            char sfile_duration[ARGV_NUMBER_LEN];
            argv = sync_pipe_add_arg(argv, &argc, "-b");
            snprintf(sfile_duration, ARGV_NUMBER_LEN, "duration:%f",capture_opts->file_duration);
            argv = sync_pipe_add_arg(argv, &argc, sfile_duration);
        }

        if (capture_opts->has_file_interval) {
            char sfile_interval[ARGV_NUMBER_LEN];
            argv = sync_pipe_add_arg(argv, &argc, "-b");
            snprintf(sfile_interval, ARGV_NUMBER_LEN, "interval:%d",capture_opts->file_interval);
            argv = sync_pipe_add_arg(argv, &argc, sfile_interval);
        }

        if (capture_opts->has_file_packets) {
            char sfile_packets[ARGV_NUMBER_LEN];
            argv = sync_pipe_add_arg(argv, &argc, "-b");
            snprintf(sfile_packets, ARGV_NUMBER_LEN, "packets:%d",capture_opts->file_packets);
            argv = sync_pipe_add_arg(argv, &argc, sfile_packets);
        }

        if (capture_opts->has_ring_num_files) {
            char sring_num_files[ARGV_NUMBER_LEN];
            argv = sync_pipe_add_arg(argv, &argc, "-b");
            snprintf(sring_num_files, ARGV_NUMBER_LEN, "files:%d",capture_opts->ring_num_files);
            argv = sync_pipe_add_arg(argv, &argc, sring_num_files);
        }

        if (capture_opts->print_file_names) {
            char *print_name = g_strdup_printf("printname:%s", capture_opts->print_name_to);
            argv = sync_pipe_add_arg(argv, &argc, "-b");
            argv = sync_pipe_add_arg(argv, &argc, print_name);
            g_free(print_name);
        }

        if (capture_opts->has_nametimenum) {
            char nametimenum[ARGV_NUMBER_LEN];
            argv = sync_pipe_add_arg(argv, &argc, "-b");
            snprintf(nametimenum, ARGV_NUMBER_LEN, "nametimenum:2");
            argv = sync_pipe_add_arg(argv, &argc, nametimenum);
        }

        if (capture_opts->has_autostop_files) {
            char sautostop_files[ARGV_NUMBER_LEN];
            argv = sync_pipe_add_arg(argv, &argc, "-a");
            snprintf(sautostop_files, ARGV_NUMBER_LEN, "files:%d",capture_opts->autostop_files);
            argv = sync_pipe_add_arg(argv, &argc, sautostop_files);
        }
    } else {
        if (capture_opts->has_autostop_filesize) {
            char sautostop_filesize[ARGV_NUMBER_LEN];
            argv = sync_pipe_add_arg(argv, &argc, "-a");
            snprintf(sautostop_filesize, ARGV_NUMBER_LEN, "filesize:%u",capture_opts->autostop_filesize);
            argv = sync_pipe_add_arg(argv, &argc, sautostop_filesize);
        }
    }

    if (capture_opts->has_autostop_packets) {
        char scount[ARGV_NUMBER_LEN];
        argv = sync_pipe_add_arg(argv, &argc, "-c");
        snprintf(scount, ARGV_NUMBER_LEN, "%d",capture_opts->autostop_packets);
        argv = sync_pipe_add_arg(argv, &argc, scount);
    }

    if (capture_opts->has_autostop_duration) {
        char sautostop_duration[ARGV_NUMBER_LEN];
        argv = sync_pipe_add_arg(argv, &argc, "-a");
        snprintf(sautostop_duration, ARGV_NUMBER_LEN, "duration:%f",capture_opts->autostop_duration);
        argv = sync_pipe_add_arg(argv, &argc, sautostop_duration);
    }

    if (capture_opts->has_autostop_written_packets) {
        char scount[ARGV_NUMBER_LEN];
        argv = sync_pipe_add_arg(argv, &argc, "-a");
        snprintf(scount, ARGV_NUMBER_LEN, "packets:%d",capture_opts->autostop_written_packets);
        argv = sync_pipe_add_arg(argv, &argc, scount);
    }

    if (capture_opts->group_read_access) {
        argv = sync_pipe_add_arg(argv, &argc, "-g");
    }

    if (capture_opts->update_interval != DEFAULT_UPDATE_INTERVAL) {
        char scount[ARGV_NUMBER_LEN];
        argv = sync_pipe_add_arg(argv, &argc, "--update-interval");
        snprintf(scount, ARGV_NUMBER_LEN, "%d", capture_opts->update_interval);
        argv = sync_pipe_add_arg(argv, &argc, scount);
    }

    for (j = 0; j < capture_opts->ifaces->len; j++) {
        interface_opts = &g_array_index(capture_opts->ifaces, interface_options, j);

        argv = sync_pipe_add_arg(argv, &argc, "-i");
        if (interface_opts->extcap_fifo != NULL)
        {
#ifdef _WIN32
            char *pipe = ws_strdup_printf("%s%" PRIuMAX, EXTCAP_PIPE_PREFIX, (uintmax_t)interface_opts->extcap_pipe_h);
            argv = sync_pipe_add_arg(argv, &argc, pipe);
            g_free(pipe);
            i_handles++;
#else
            argv = sync_pipe_add_arg(argv, &argc, interface_opts->extcap_fifo);
#endif
            /* Add a name for the interface, to put into an IDB. */
            argv = sync_pipe_add_arg(argv, &argc, "--ifname");
            argv = sync_pipe_add_arg(argv, &argc, interface_opts->name);
        }
        else
            argv = sync_pipe_add_arg(argv, &argc, interface_opts->name);

        if (interface_opts->descr != NULL)
        {
            /* Add a description for the interface to put into an IDB and
             * use for the temporary filename. */
            argv = sync_pipe_add_arg(argv, &argc, "--ifdescr");
            argv = sync_pipe_add_arg(argv, &argc, interface_opts->descr);
        }

        if (interface_opts->cfilter != NULL && strlen(interface_opts->cfilter) != 0) {
            argv = sync_pipe_add_arg(argv, &argc, "-f");
            argv = sync_pipe_add_arg(argv, &argc, interface_opts->cfilter);
        }
        if (interface_opts->has_snaplen) {
            char ssnap[ARGV_NUMBER_LEN];
            argv = sync_pipe_add_arg(argv, &argc, "-s");
            snprintf(ssnap, ARGV_NUMBER_LEN, "%d", interface_opts->snaplen);
            argv = sync_pipe_add_arg(argv, &argc, ssnap);
        }

        if (interface_opts->linktype != -1) {
            const char *linktype = linktype_val_to_name(interface_opts->linktype);
            if ( linktype != NULL )
            {
                argv = sync_pipe_add_arg(argv, &argc, "-y");
                argv = sync_pipe_add_arg(argv, &argc, linktype);
            }
        }

        if (!interface_opts->promisc_mode) {
            argv = sync_pipe_add_arg(argv, &argc, "-p");
        }

#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
        if (interface_opts->buffer_size != DEFAULT_CAPTURE_BUFFER_SIZE) {
            char buffer_size[ARGV_NUMBER_LEN];
            argv = sync_pipe_add_arg(argv, &argc, "-B");
            if(interface_opts->buffer_size == 0x00)
                interface_opts->buffer_size = DEFAULT_CAPTURE_BUFFER_SIZE;
            snprintf(buffer_size, ARGV_NUMBER_LEN, "%d", interface_opts->buffer_size);
            argv = sync_pipe_add_arg(argv, &argc, buffer_size);
        }
#endif

#ifdef HAVE_PCAP_CREATE
        if (interface_opts->monitor_mode) {
            argv = sync_pipe_add_arg(argv, &argc, "-I");
        }
#endif

#ifdef HAVE_PCAP_REMOTE
        if (interface_opts->datatx_udp)
            argv = sync_pipe_add_arg(argv, &argc, "-u");

        if (!interface_opts->nocap_rpcap)
            argv = sync_pipe_add_arg(argv, &argc, "-r");

        if (interface_opts->auth_type == CAPTURE_AUTH_PWD) {
            char sauth[256];
            argv = sync_pipe_add_arg(argv, &argc, "-A");
            snprintf(sauth, sizeof(sauth), "%s:%s",
                       interface_opts->auth_username,
                       interface_opts->auth_password);
            argv = sync_pipe_add_arg(argv, &argc, sauth);
        }
#endif

#ifdef HAVE_PCAP_SETSAMPLING
        if (interface_opts->sampling_method != CAPTURE_SAMP_NONE) {
            char ssampling[ARGV_NUMBER_LEN];
            argv = sync_pipe_add_arg(argv, &argc, "-m");
            snprintf(ssampling, ARGV_NUMBER_LEN, "%s:%d",
                       interface_opts->sampling_method == CAPTURE_SAMP_BY_COUNT ? "count" :
                       interface_opts->sampling_method == CAPTURE_SAMP_BY_TIMER ? "timer" :
                       "undef",
                       interface_opts->sampling_param);
            argv = sync_pipe_add_arg(argv, &argc, ssampling);
        }
#endif
        if (interface_opts->timestamp_type) {
            argv = sync_pipe_add_arg(argv, &argc, "--time-stamp-type");
            argv = sync_pipe_add_arg(argv, &argc, interface_opts->timestamp_type);
        }
    }

#ifndef DEBUG_CHILD
#ifdef _WIN32
    /* pass process id to dumpcap for named signal pipe */
    argv = sync_pipe_add_arg(argv, &argc, "--signal-pipe");
    snprintf(control_id, ARGV_NUMBER_LEN, "%ld", GetCurrentProcessId());
    argv = sync_pipe_add_arg(argv, &argc, control_id);
#endif
#endif

    if (capture_opts->save_file) {
        argv = sync_pipe_add_arg(argv, &argc, "-w");
        argv = sync_pipe_add_arg(argv, &argc, capture_opts->save_file);
    }
    for (i = 0; i < argc; i++) {
        ws_debug("argv[%d]: %s", i, argv[i]);
    }
    if (capture_opts->compress_type) {
        argv = sync_pipe_add_arg(argv, &argc, "--compress-type");
        argv = sync_pipe_add_arg(argv, &argc, capture_opts->compress_type);
    }

    int ret;
    char* msg;
#ifdef _WIN32
    ret = sync_pipe_open_command(argv, NULL, &sync_pipe_read_io, &cap_session->signal_pipe_write_fd,
                                 &cap_session->fork_child, capture_opts->ifaces, &msg, update_cb);
#else
    ret = sync_pipe_open_command(argv, NULL, &sync_pipe_read_io, NULL,
                                 &cap_session->fork_child, NULL, &msg, update_cb);
#endif

    if (ret == -1) {
        report_failure("%s", msg);
        g_free(msg);
        return false;
    }

    /* Parent process - read messages from the child process over the
       sync pipe. */

    cap_session->fork_child_status = 0;
    cap_session->cap_data_info = cap_data;

    /* We were able to set up to read the capture file;
       arrange that our callback be called whenever it's possible
       to read from the sync pipe, so that it's called when
       the child process wants to tell us something. */

    /* we have a running capture, now wait for the real capture filename */
    if (cap_session->pipe_input_id) {
        g_source_remove(cap_session->pipe_input_id);
        cap_session->pipe_input_id = 0;
    }
    cap_session->pipe_input_id = g_io_add_watch(sync_pipe_read_io, G_IO_IN | G_IO_HUP, pipe_io_cb, cap_session);
    /* Pipe will be closed when watch is removed */
    g_io_channel_unref(sync_pipe_read_io);

    return true;
}

/*
 * Close the pipes we're using to read from dumpcap, and wait for it
 * to exit.  On success, *msgp is unchanged, and the exit status of
 * dumpcap is returned.  On failure (which includes "dumpcap exited
 * due to being killed by a signal or an exception"), *msgp points
 * to an error message for the failure, and -1 is returned.  In the
 * latter case, *msgp must be freed with g_free().
 */
static int
sync_pipe_close_command(int *data_read_fd, GIOChannel *message_read_io,
	ws_process_id *fork_child, char **msgp)
{
    ws_close(*data_read_fd);
    if (message_read_io != NULL)
        g_io_channel_unref(message_read_io);

#ifdef _WIN32
    /* XXX - Should we signal the child somehow? */
    sync_pipe_kill(*fork_child);
#endif

    return sync_pipe_wait_for_child(*fork_child, msgp);
}

/*
 * Run dumpcap with the supplied arguments.
 *
 * On success, *data points to a buffer containing the dumpcap output,
 * *primary_msg and *secondary_message are NULL, and 0 is returned; *data
 * must be freed with g_free().
 *
 * On failure, *data is NULL, *primary_msg points to an error message,
 * *secondary_msg either points to an additional error message or is
 * NULL, and -1 is returned; *primary_msg, and *secondary_msg if not NULL,
 * must be freed with g_free().
 */
static int
sync_pipe_run_command_actual(char **argv, char **data, char **primary_msg,
                      char **secondary_msg,  void(*update_cb)(void))
{
    char *msg;
    int data_pipe_read_fd, ret;
    GIOChannel *sync_pipe_read_io;
    ws_process_id fork_child;
    char *wait_msg;
    char *buffer = g_malloc(PIPE_BUF_SIZE + 1);
    ssize_t nread;
    char indicator;
    int32_t exec_errno = 0;
    int  primary_msg_len;
    char *primary_msg_text;
    int  secondary_msg_len;
    char *secondary_msg_text;
    char *combined_msg;
    GString *data_buf = NULL;
    ssize_t count;

    ret = sync_pipe_open_command(argv, &data_pipe_read_fd, &sync_pipe_read_io, NULL,
                                 &fork_child, NULL, &msg, update_cb);
    if (ret == -1) {
        *primary_msg = msg;
        *secondary_msg = NULL;
        *data = NULL;
        g_free(buffer);
        return -1;
    }

    /*
     * We were able to set up to read dumpcap's output.  Do so.
     *
     * First, wait for an SP_ERROR_MSG message or SP_SUCCESS message.
     */
    do {
        nread = pipe_read_block(sync_pipe_read_io, &indicator, SP_MAX_MSG_LEN,
                                buffer, primary_msg);
        if(nread <= 0) {
            /* We got a read error from the sync pipe, or we got no data at
               all from the sync pipe, so we're not going to be getting any
               data or error message from the child process.  Pick up its
               exit status, and complain.

               We don't have to worry about killing the child, if the sync pipe
               returned an error. Usually this error is caused as the child killed
               itself while going down. Even in the rare cases that this isn't the
               case, the child will get an error when writing to the broken pipe
               the next time, cleaning itself up then. */
            g_io_channel_unref(sync_pipe_read_io);
            ret = sync_pipe_wait_for_child(fork_child, &wait_msg);
            if(nread == 0) {
                /* We got an EOF from the sync pipe.  That means that it exited
                   before giving us any data to read.  If ret is -1, we report
                   that as a bad exit (e.g., exiting due to a signal); otherwise,
                   we report it as a premature exit. */
                if (ret == -1)
                    *primary_msg = wait_msg;
                else
                    *primary_msg = g_strdup("Child dumpcap closed sync pipe prematurely");
            } else {
                /* We got an error from the sync pipe.  If ret is -1, report
                   both the sync pipe I/O error and the wait error. */
                if (ret == -1) {
                    combined_msg = ws_strdup_printf("%s\n\n%s", *primary_msg, wait_msg);
                    g_free(*primary_msg);
                    g_free(wait_msg);
                    *primary_msg = combined_msg;
                }
            }
            *secondary_msg = NULL;
            *data = NULL;
            g_free(buffer);

            return -1;
        }

        /* we got a valid message block from the child, process it */
        switch(indicator) {

        case SP_EXEC_FAILED:
            /*
             * Exec of dumpcap failed.  Get the errno for the failure.
             */
            if (!ws_strtoi32(buffer, NULL, &exec_errno)) {
                ws_warning("Invalid errno: %s", buffer);
            }

            /*
             * Pick up the child status.
             */
            ret = sync_pipe_close_command(&data_pipe_read_fd, sync_pipe_read_io,
                                          &fork_child, &msg);
            if (ret == -1) {
                /*
                 * Child process failed unexpectedly, or wait failed; msg is the
                 * error message.
                 */
                *primary_msg = msg;
                *secondary_msg = NULL;
            } else {
                /*
                 * Child process failed, but returned the expected exit status.
                 * Return the messages it gave us, and indicate failure.
                 */
                *primary_msg = ws_strdup_printf("Couldn't run dumpcap in child process: %s",
                                                g_strerror(exec_errno));
                *secondary_msg = NULL;
                ret = -1;
            }
            *data = NULL;
            break;

        case SP_ERROR_MSG:
            /*
             * Error from dumpcap; there will be a primary message and a
             * secondary message.
             */

            /* convert primary message */
            pipe_convert_header((unsigned char*)buffer, 4, &indicator, &primary_msg_len);
            primary_msg_text = buffer+4;
            /* convert secondary message */
            pipe_convert_header((unsigned char*)primary_msg_text + primary_msg_len, 4, &indicator,
                                &secondary_msg_len);
            secondary_msg_text = primary_msg_text + primary_msg_len + 4;
            /* the capture child will close the sync_pipe, nothing to do */

            /*
             * Pick up the child status.
             */
            ret = sync_pipe_close_command(&data_pipe_read_fd, sync_pipe_read_io,
                                          &fork_child, &msg);
            if (ret == -1) {
                /*
                 * Child process failed unexpectedly, or wait failed; msg is the
                 * error message.
                 */
                *primary_msg = msg;
                *secondary_msg = NULL;
            } else {
                /*
                 * Child process failed, but returned the expected exit status.
                 * Return the messages it gave us, and indicate failure.
                 */
                *primary_msg = g_strdup(primary_msg_text);
                *secondary_msg = g_strdup(secondary_msg_text);
                ret = -1;
            }
            *data = NULL;
            break;

        case SP_LOG_MSG:
            /*
             * Log from dumpcap; pass to our log
             */
            sync_pipe_handle_log_msg(buffer);
            break;

        case SP_SUCCESS:
            /* read the output from the command */
            data_buf = g_string_new("");
            while ((count = ws_read(data_pipe_read_fd, buffer, PIPE_BUF_SIZE)) > 0) {
                buffer[count] = '\0';
                g_string_append(data_buf, buffer);
            }

            /*
             * Pick up the child status.
             */
            ret = sync_pipe_close_command(&data_pipe_read_fd, sync_pipe_read_io,
                                          &fork_child, &msg);
            if (ret == -1) {
                /*
                 * Child process failed unexpectedly, or wait failed; msg is the
                 * error message.
                 */
                *primary_msg = msg;
                *secondary_msg = NULL;
                g_string_free(data_buf, TRUE);
                *data = NULL;
            } else {
                /*
                 * Child process succeeded.
                 */
                *primary_msg = NULL;
                *secondary_msg = NULL;
                *data = g_string_free(data_buf, FALSE);
            }
            break;

        default:
            /*
             * Pick up the child status.
             */
            ret = sync_pipe_close_command(&data_pipe_read_fd, sync_pipe_read_io,
                                          &fork_child, &msg);
            if (ret == -1) {
                /*
                 * Child process failed unexpectedly, or wait failed; msg is the
                 * error message.
                 */
                *primary_msg = msg;
                *secondary_msg = NULL;
            } else {
                /*
                 * Child process returned an unknown status.
                 */
                *primary_msg = ws_strdup_printf("dumpcap process gave an unexpected message type: 0x%02x",
                                               indicator);
                *secondary_msg = NULL;
                ret = -1;
            }
            *data = NULL;
            break;
        }
    } while (indicator != SP_SUCCESS && ret != -1);

    g_free(buffer);
    return ret;
}

/* centralised logging and timing for sync_pipe_run_command_actual(),
* redirects to sync_pipe_run_command_actual()
*/
static int
sync_pipe_run_command(char **argv, char **data, char **primary_msg,
                      char **secondary_msg, void (*update_cb)(void))
{
    int ret, i;
    int64_t start_time;
    double elapsed;
    int logging_enabled;

    /* check if logging is actually enabled, otherwise don't expend the CPU generating logging */
    logging_enabled = ws_log_msg_is_active(WS_LOG_DOMAIN, LOG_LEVEL_INFO);
    if (logging_enabled) {
        start_time = g_get_monotonic_time();
        ws_debug("sync_pipe_run_command() starts");
        for (i=0; argv[i] != 0; i++) {
            ws_noisy("  argv[%d]: %s", i, argv[i]);
        }
    }
    /* do the actual sync pipe run command */
    ret = sync_pipe_run_command_actual(argv, data, primary_msg, secondary_msg, update_cb);

    if (logging_enabled) {
        elapsed = (g_get_monotonic_time() - start_time) / 1e6;

        ws_debug("sync_pipe_run_command() ends, taking %.3fs, result=%d", elapsed, ret);

    }
    return ret;
}


int
sync_interface_set_80211_chan(const char *iface, const char *freq, const char *type,
                              const char *center_freq1, const char *center_freq2,
                              char **data, char **primary_msg,
                              char **secondary_msg, void (*update_cb)(void))
{
    int argc, ret;
    char **argv;
    char *opt;

    argv = init_pipe_args(&argc);

    if (!argv) {
        *primary_msg = g_strdup("We don't know where to find dumpcap.");
        *secondary_msg = NULL;
        *data = NULL;
        return -1;
    }

    argv = sync_pipe_add_arg(argv, &argc, "-i");
    argv = sync_pipe_add_arg(argv, &argc, iface);

    if (center_freq2)
        opt = ws_strdup_printf("%s,%s,%s,%s", freq, type, center_freq1, center_freq2);
    else if (center_freq1)
        opt = ws_strdup_printf("%s,%s,%s", freq, type, center_freq1);
    else if (type)
        opt = ws_strdup_printf("%s,%s", freq, type);
    else
        opt = g_strdup(freq);

    if (!opt) {
        *primary_msg = g_strdup("Out of mem.");
        *secondary_msg = NULL;
        *data = NULL;
        return -1;
    }

    argv = sync_pipe_add_arg(argv, &argc, "-k");
    argv = sync_pipe_add_arg(argv, &argc, opt);

    ret = sync_pipe_run_command(argv, data, primary_msg, secondary_msg, update_cb);
    g_free(opt);
    return ret;
}

/*
 * Get the list of interfaces using dumpcap.
 *
 * On success, *data points to a buffer containing the dumpcap output,
 * *primary_msg and *secondary_msg are NULL, and 0 is returned.  *data
 * must be freed with g_free().
 *
 * On failure, *data is NULL, *primary_msg points to an error message,
 * *secondary_msg either points to an additional error message or is
 * NULL, and -1 is returned; *primary_msg, and *secondary_msg if not NULL,
 * must be freed with g_free().
 */
int
sync_interface_list_open(char **data, char **primary_msg,
                         char **secondary_msg, void (*update_cb)(void))
{
    int argc;
    char **argv;
    int ret;

    ws_debug("sync_interface_list_open");

    argv = init_pipe_args(&argc);

    if (!argv) {
        *primary_msg = g_strdup("We don't know where to find dumpcap..");
        *secondary_msg = NULL;
        *data = NULL;
        return -1;
    }

    /* Ask for the interface list */
    argv = sync_pipe_add_arg(argv, &argc, "-D");

    ret = sync_pipe_run_command(argv, data, primary_msg, secondary_msg, update_cb);
    return ret;
}

/*
 * Get the capabilities of an interface using dumpcap.
 *
 * On success, *data points to a buffer containing the dumpcap output,
 * *primary_msg and *secondary_msg are NULL, and 0 is returned.  *data
 * must be freed with g_free().
 *
 * On failure, *data is NULL, *primary_msg points to an error message,
 * *secondary_msg either points to an additional error message or is
 * NULL, and -1 is returned; *primary_msg, and *secondary_msg if not NULL,
 * must be freed with g_free().
 */
int
sync_if_capabilities_open(const char *ifname, bool monitor_mode, const char* auth,
                          char **data, char **primary_msg,
                          char **secondary_msg, void (*update_cb)(void))
{
    int argc;
    char **argv;
    int ret;

    ws_debug("sync_if_capabilities_open");

    argv = init_pipe_args(&argc);

    if (!argv) {
        *primary_msg = g_strdup("We don't know where to find dumpcap.");
        *secondary_msg = NULL;
        *data = NULL;
        return -1;
    }

    /* Ask for the interface capabilities */
    argv = sync_pipe_add_arg(argv, &argc, "-i");
    argv = sync_pipe_add_arg(argv, &argc, ifname);
    argv = sync_pipe_add_arg(argv, &argc, "-L");
    argv = sync_pipe_add_arg(argv, &argc, "--list-time-stamp-types");
    if (monitor_mode)
        argv = sync_pipe_add_arg(argv, &argc, "-I");
    if (auth) {
        argv = sync_pipe_add_arg(argv, &argc, "-A");
        argv = sync_pipe_add_arg(argv, &argc, auth);
    }

    ret = sync_pipe_run_command(argv, data, primary_msg, secondary_msg, update_cb);
    return ret;
}

int
sync_if_list_capabilities_open(GList *if_queries,
                          char **data, char **primary_msg,
                          char **secondary_msg, void (*update_cb)(void))
{
    int argc;
    char **argv;
    int ret;
    if_cap_query_t *if_cap_query;

    ws_debug("sync_if_list_capabilities_open");

    argv = init_pipe_args(&argc);

    if (!argv) {
        *primary_msg = g_strdup("We don't know where to find dumpcap.");
        *secondary_msg = NULL;
        *data = NULL;
        return -1;
    }

    for (GList *li = if_queries; li != NULL; li = g_list_next(li)) {
        if_cap_query = (if_cap_query_t*)li->data;
        /* Ask for the interface capabilities */
        argv = sync_pipe_add_arg(argv, &argc, "-i");
        argv = sync_pipe_add_arg(argv, &argc, if_cap_query->name);
        if (if_cap_query->monitor_mode)
            argv = sync_pipe_add_arg(argv, &argc, "-I");
        if (if_cap_query->auth_username && if_cap_query->auth_password) {
            char sauth[256];
            argv = sync_pipe_add_arg(argv, &argc, "-A");
            snprintf(sauth, sizeof(sauth), "%s:%s",
                       if_cap_query->auth_username,
                       if_cap_query->auth_password);
            argv = sync_pipe_add_arg(argv, &argc, sauth);
        }
    }
    argv = sync_pipe_add_arg(argv, &argc, "-L");
    argv = sync_pipe_add_arg(argv, &argc, "--list-time-stamp-types");

    ret = sync_pipe_run_command(argv, data, primary_msg, secondary_msg, update_cb);
    return ret;
}

/*
 * Start getting interface statistics using dumpcap.  On success, read_fd
 * contains the file descriptor for the pipe's stdout, *msg is unchanged,
 * and zero is returned.  On failure, *msg will point to an error message
 * that must be g_free()d, and -1 will be returned.
 * If data is not NULL, then it will also be set to point to a JSON
 * serialization of the list of local interfaces and their capabilities.
 */
int
sync_interface_stats_open(int *data_read_fd, ws_process_id *fork_child, char **data, char **msg, void (*update_cb)(void))
{
    int argc;
    char **argv;
    int ret;
    GIOChannel *message_read_io;
    char *wait_msg;
    char *buffer = g_malloc(PIPE_BUF_SIZE + 1);
    ssize_t nread;
    char indicator;
    int32_t exec_errno = 0;
    int  primary_msg_len;
    char *primary_msg_text;
    int  secondary_msg_len;
    /*char *secondary_msg_text;*/
    char *combined_msg;

    ws_debug("sync_interface_stats_open");

    argv = init_pipe_args(&argc);

    if (!argv) {
        *msg = g_strdup("We don't know where to find dumpcap.");
        g_free(buffer);
        return -1;
    }

    /* Ask for the interface statistics */
    argv = sync_pipe_add_arg(argv, &argc, "-S");

    /* If requested, ask for the interface list and capabilities. */
    if (data) {
        argv = sync_pipe_add_arg(argv, &argc, "-D");
        argv = sync_pipe_add_arg(argv, &argc, "-L");
    }

#ifndef DEBUG_CHILD
#ifdef _WIN32
    argv = sync_pipe_add_arg(argv, &argc, "--signal-pipe");
    ret = create_dummy_signal_pipe(msg);
    if (ret == -1) {
        g_free(buffer);
        return -1;
    }
    argv = sync_pipe_add_arg(argv, &argc, dummy_control_id);
#endif
#endif
    ret = sync_pipe_open_command(argv, data_read_fd, &message_read_io, NULL,
                                 fork_child, NULL, msg, update_cb);
    if (ret == -1) {
        g_free(buffer);
        return -1;
    }

    /*
     * We were able to set up to read dumpcap's output.  Do so.
     *
     * First, wait for an SP_ERROR_MSG message or SP_SUCCESS message.
     */
    do {
        nread = pipe_read_block(message_read_io, &indicator, SP_MAX_MSG_LEN,
                                buffer, msg);
        if(nread <= 0) {
            /* We got a read error from the sync pipe, or we got no data at
               all from the sync pipe, so we're not going to be getting any
               data or error message from the child process.  Pick up its
               exit status, and complain.

               We don't have to worry about killing the child, if the sync pipe
               returned an error. Usually this error is caused as the child killed
               itself while going down. Even in the rare cases that this isn't the
               case, the child will get an error when writing to the broken pipe
               the next time, cleaning itself up then. */
            g_io_channel_unref(message_read_io);
            ws_close(*data_read_fd);
            ret = sync_pipe_wait_for_child(*fork_child, &wait_msg);
            if(nread == 0) {
                /* We got an EOF from the sync pipe.  That means that it exited
                   before giving us any data to read.  If ret is -1, we report
                   that as a bad exit (e.g., exiting due to a signal); otherwise,
                   we report it as a premature exit. */
                if (ret == -1)
                    *msg = wait_msg;
                else
                    *msg = g_strdup("Child dumpcap closed sync pipe prematurely");
            } else {
                /* We got an error from the sync pipe.  If ret is -1, report
                   both the sync pipe I/O error and the wait error. */
                if (ret == -1) {
                    combined_msg = ws_strdup_printf("%s\n\n%s", *msg, wait_msg);
                    g_free(*msg);
                    g_free(wait_msg);
                    *msg = combined_msg;
                }
            }
            g_free(buffer);
            return -1;
        }

        /* we got a valid message block from the child, process it */
        switch(indicator) {

        case SP_EXEC_FAILED:
            /*
             * Exec of dumpcap failed.  Get the errno for the failure.
             */
            if (!ws_strtoi32(buffer, NULL, &exec_errno)) {
                ws_warning("Invalid errno: %s", buffer);
            }
            *msg = ws_strdup_printf("Couldn't run dumpcap in child process: %s",
                                    g_strerror(exec_errno));

            /*
             * Pick up the child status.
             */
            char *close_msg = NULL;
            sync_pipe_close_command(data_read_fd, message_read_io,
                                    fork_child, &close_msg);
            /*
             * Ignore the error from sync_pipe_close_command, presumably the one
             * returned by the child is more pertinent to what went wrong.
             */
            g_free(close_msg);
            ret = -1;
            break;

        case SP_ERROR_MSG:
            /*
             * Error from dumpcap; there will be a primary message and a
             * secondary message.
             */

            /* convert primary message */
            pipe_convert_header((unsigned char*)buffer, 4, &indicator, &primary_msg_len);
            primary_msg_text = buffer+4;
            /* convert secondary message */
            pipe_convert_header((unsigned char*)primary_msg_text + primary_msg_len, 4, &indicator,
                                &secondary_msg_len);
            /*secondary_msg_text = primary_msg_text + primary_msg_len + 4;*/
            /* the capture child will close the sync_pipe, nothing to do */

            /*
             * Pick up the child status.
             */
            ret = sync_pipe_close_command(data_read_fd, message_read_io,
                                          fork_child, msg);
            if (ret == -1) {
                /*
                 * Child process failed unexpectedly, or wait failed; msg is the
                 * error message.
                 */
            } else if (ret == WS_EXIT_NO_INTERFACES) {
                /*
                    * No interfaces were found.  If that's not the
                    * result of an error when fetching the local
                    * interfaces, let the user know.
                    */
                *msg = g_strdup(primary_msg_text);
            } else {
                /*
                 * Child process failed, but returned the expected exit status.
                 * Return the messages it gave us, and indicate failure.
                 */
                *msg = g_strdup(primary_msg_text);
                ret = -1;
            }
            g_free(buffer);
            return ret;

        case SP_LOG_MSG:
            /*
             * Log from dumpcap; pass to our log
             */
            sync_pipe_handle_log_msg(buffer);
            break;

        case SP_IFACE_LIST:
            /*
             * Dumpcap giving us the interface list
             */

            /* convert primary message */
            if (data) {
                *data = g_strdup(buffer);
            }
            break;

        case SP_SUCCESS:
            /* Close the message pipe. */
            g_io_channel_unref(message_read_io);
            break;

        default:
            /*
             * Pick up the child status.
             */
            ret = sync_pipe_close_command(data_read_fd, message_read_io,
                                          fork_child, msg);
            if (ret == -1) {
                /*
                 * Child process failed unexpectedly, or wait failed; msg is the
                 * error message.
                 */
            } else {
                /*
                 * Child process returned an unknown status.
                 */
                *msg = ws_strdup_printf("dumpcap process gave an unexpected message type: 0x%02x",
                                       indicator);
                ret = -1;
            }
            break;
        }
    } while (indicator != SP_SUCCESS && ret != -1);

    g_free(buffer);
    return ret;
}

/* Close down the stats process */
int
sync_interface_stats_close(int *read_fd, ws_process_id *fork_child, char **msg)
{
#ifdef _WIN32
    CloseHandle(dummy_signal_pipe);
    dummy_signal_pipe = NULL;
#else
    /*
     * Don't bother waiting for the child. sync_pipe_close_command
     * does this for us on Windows.
     */
    sync_pipe_kill(*fork_child);
#endif
    return sync_pipe_close_command(read_fd, NULL, fork_child, msg);
}

/* read a number of bytes from a pipe */
/* (blocks until enough bytes read or an error occurs) */
static ssize_t
pipe_read_bytes(GIOChannel *pipe_io, char *bytes, size_t required, char **msg)
{
    GError *err = NULL;
    size_t newly;
    size_t offset = 0;

    while(required) {
        g_io_channel_read_chars(pipe_io, &bytes[offset], required, &newly, &err);
        if (err != NULL) {
            ws_debug("read from pipe %p: error(%u): %s", pipe_io, err->code, err->message);
            *msg = ws_strdup_printf("Error reading from sync pipe: %s", err->message);
            g_clear_error(&err);
            return -1;
        }
        if (newly == 0) {
            /* EOF */
            ws_debug("read from pipe %p: EOF (capture closed?)", pipe_io);
            *msg = 0;
            return offset;
        }

        required -= newly;
        offset += newly;
    }

    *msg = NULL;
    return offset;
}

/*
 * Read a line from a pipe; similar to fgets, but doesn't block.
 *
 * XXX - just stops reading if there's nothing to be read right now;
 * that could conceivably mean that you don't get a complete line.
 */
int
sync_pipe_gets_nonblock(int pipe_fd, char *bytes, int max) {
    ssize_t newly;
    int offset = -1;

    while(offset < max - 1) {
        offset++;
        if (! ws_pipe_data_available(pipe_fd))
            break;
        newly = ws_read(pipe_fd, &bytes[offset], 1);
        if (newly == 0) {
            /* EOF - not necessarily an error */
            break;
        } else if (newly == -1) {
            /* error */
            ws_debug("read from pipe %d: error(%u): %s", pipe_fd, errno, g_strerror(errno));
            return -1;
        } else if (bytes[offset] == '\n') {
            break;
        }
    }

    if (offset >= 0)
        bytes[offset] = '\0';

    return offset;
}


/* convert header values (indicator and 3-byte length) */
static void
pipe_convert_header(const unsigned char *header, int header_len _U_, char *indicator, int *block_len) {

    ws_assert(header_len == 4);

    /* convert header values */
    *indicator = header[0];
    *block_len = (header[1]&0xFF)<<16 | (header[2]&0xFF)<<8 | (header[3]&0xFF);
}

/* read a message from the sending pipe in the standard format
   (1-byte message indicator, 3-byte message length (excluding length
   and indicator field), and the rest is the message) */
static ssize_t
pipe_read_block(GIOChannel *pipe_io, char *indicator, int len, char *msg,
                char **err_msg)
{
    int required;
    ssize_t newly;
    char header[4];

    /* read header (indicator and 3-byte length) */
    newly = pipe_read_bytes(pipe_io, header, 4, err_msg);
    if(newly != 4) {
        if (newly == 0) {
            /*
             * Immediate EOF; if the capture child exits normally, this
             * is an "I'm done" indication, so don't report it as an
             * error.
             */
            ws_debug("read %p got an EOF", pipe_io);
            return 0;
        }
        ws_debug("read %p failed to read header: %lu", pipe_io, (long)newly);
        if (newly != -1) {
            /*
             * Short read, but not an immediate EOF.
             */
            *err_msg = ws_strdup_printf("Premature EOF reading from sync pipe: got only %ld bytes",
                                       (long)newly);
        }
        return -1;
    }

    /* convert header values */
    pipe_convert_header((unsigned char*)header, 4, indicator, &required);

    /* only indicator with no value? */
    if(required == 0) {
        ws_debug("read %p indicator: %c empty value", pipe_io, *indicator);
        return 4;
    }

    /* does the data fit into the given buffer? */
    if(required > len) {
        size_t bytes_read;
        GError *err = NULL;
        ws_debug("read %p length error, required %d > len %d, header: 0x%02x 0x%02x 0x%02x 0x%02x",
              pipe_io, required, len,
              header[0], header[1], header[2], header[3]);

        /* we have a problem here, try to read some more bytes from the pipe to debug where the problem really is */
        g_io_channel_read_chars(pipe_io, msg, len, &bytes_read, &err);
        if (err != NULL) { /* error */
            ws_debug("read from pipe %p: error(%u): %s", pipe_io, err->code, err->message);
            g_clear_error(&err);
        }
        *err_msg = ws_strdup_printf("Message %c from dumpcap with length %d > buffer size %d! Partial message: %s",
                                    *indicator, required, len, msg);
        return -1;
    }
    len = required;

    /* read the actual block data */
    newly = pipe_read_bytes(pipe_io, msg, required, err_msg);
    if(newly != required) {
        if (newly != -1) {
            *err_msg = ws_strdup_printf("Unknown message from dumpcap reading data, try to show it as a string: %s",
                                       msg);
        }
        return -1;
    }

    /* XXX If message is "2part", the msg probably won't be sent to debug log correctly */
    ws_debug("read %p ok indicator: %c len: %u msg: %s", pipe_io, *indicator, len, msg);
    *err_msg = NULL;
    return newly + 4;
}


/* There's stuff to read from the sync pipe, meaning the child has sent
   us a message, or the sync pipe has closed, meaning the child has
   closed it (perhaps because it exited). */
static gboolean
sync_pipe_input_cb(GIOChannel *pipe_io, capture_session *cap_session)
{
    int  ret;
    char *buffer = g_malloc(SP_MAX_MSG_LEN + 1);
    ssize_t nread;
    char indicator;
    int32_t exec_errno = 0;
    int  primary_len;
    char *primary_msg;
    int  secondary_len;
    char *secondary_msg;
    char *wait_msg, *combined_msg;
    uint32_t npackets = 0;

    nread = pipe_read_block(pipe_io, &indicator, SP_MAX_MSG_LEN, buffer,
                            &primary_msg);
    if(nread <= 0) {
        /* We got a read error, or a bad message, or an EOF, from the sync pipe.

           If we got a read error or a bad message, nread is -1 and
           primary_msg is set to point to an error message.  We don't
           have to worry about killing the child; usually this error
           is caused as the child killed  itself while going down.
           Even in the rare cases that this isn't the case, the child
           will get an error when writing to the broken pipe the next time,
           cleaning itself up then.

           If we got an EOF, nread is 0 and primary_msg isn't set.  This
           is an indication that the capture is finished. */
        ret = sync_pipe_wait_for_child(cap_session->fork_child, &wait_msg);
        if(nread == 0) {
            /* We got an EOF from the sync pipe.  That means that the capture
               child exited, and not in the middle of a message; we treat
               that as an indication that it's done, and only report an
               error if ret is -1, in which case wait_msg is the error
               message. */
            if (ret == -1)
                primary_msg = wait_msg;
        } else {
            /* We got an error from the sync pipe.  If ret is -1, report
               both the sync pipe I/O error and the wait error. */
            if (ret == -1) {
                combined_msg = ws_strdup_printf("%s\n\n%s", primary_msg, wait_msg);
                g_free(primary_msg);
                g_free(wait_msg);
                primary_msg = combined_msg;
            }
        }

        /* No more child process. */
        cap_session->fork_child = WS_INVALID_PID;
        cap_session->fork_child_status = ret;

#ifdef _WIN32
        ws_close(cap_session->signal_pipe_write_fd);
#endif
        cap_session->capture_opts->closed_msg = primary_msg;
        if (extcap_session_stop(cap_session)) {
            capture_process_finished(cap_session);
        } else {
            extcap_request_stop(cap_session);
        }
        g_free(buffer);
        return false;
    }

    /* we got a valid message block from the child, process it */
    switch(indicator) {
    case SP_FILE:
        if(!cap_session->new_file(cap_session, buffer)) {
            ws_debug("file failed, closing capture");

            /* We weren't able to open the new capture file; user has been
               alerted. The sync pipe will close after we return false. */

            /* The child has sent us a filename which we couldn't open.

               This could mean that the child is creating and deleting files
               (ring buffer mode) faster than we can handle it.

               That should only be the case for very fast file switches;
               We can't do much more than telling the child to stop.
               (This is the "emergency brake" if the user e.g. wants to
               switch files every second).

               This can also happen if the user specified "-", meaning
               "standard output", as the capture file. */
            sync_pipe_stop(cap_session);
            cap_session->closed(cap_session, NULL);
            g_free(buffer);
            return false;
        }
        break;
    case SP_PACKET_COUNT:
        if (!ws_strtou32(buffer, NULL, &npackets)) {
            ws_warning("Invalid packets number: %s", buffer);
        }
        ws_debug("new packets %u", npackets);
        cap_session->count += npackets;
        cap_session->new_packets(cap_session, npackets);
        break;
    case SP_EXEC_FAILED:
        /*
         * Exec of dumpcap failed.  Get the errno for the failure.
         */
        if (!ws_strtoi32(buffer, NULL, &exec_errno)) {
            ws_warning("Invalid errno: %s", buffer);
        }
        primary_msg = ws_strdup_printf("Couldn't run dumpcap in child process: %s",
                                       g_strerror(exec_errno));
        cap_session->error(cap_session, primary_msg, NULL);
        /* the capture child will close the sync_pipe, nothing to do for now */
        /* (an error message doesn't mean we have to stop capturing) */
        break;
    case SP_ERROR_MSG:
        /* convert primary message */
        pipe_convert_header((unsigned char*)buffer, 4, &indicator, &primary_len);
        primary_msg = buffer+4;
        /* convert secondary message */
        pipe_convert_header((unsigned char*)primary_msg + primary_len, 4, &indicator, &secondary_len);
        secondary_msg = primary_msg + primary_len + 4;
        /* message output */
        cap_session->error(cap_session, primary_msg, secondary_msg);
        /* the capture child will close the sync_pipe, nothing to do for now */
        /* (an error message doesn't mean we have to stop capturing) */
        break;
    case SP_LOG_MSG:
        /*
         * Log from dumpcap; pass to our log
         */
        sync_pipe_handle_log_msg(buffer);
        break;
    case SP_BAD_FILTER: {
        const char *message=NULL;
        uint32_t indx = 0;
        const char* end;

        if (ws_strtou32(buffer, &end, &indx) && end[0] == ':') {
            message = end + 1;
        }

        cap_session->cfilter_error(cap_session, indx, message);
        /* the capture child will close the sync_pipe, nothing to do for now */
        break;
        }
    case SP_DROPS: {
        const char *name = NULL;
        const char* end;
        uint32_t num = 0;

        if (ws_strtou32(buffer, &end, &num) && end[0] == ':') {
            name = end + 1;
        }

        cap_session->drops(cap_session, num, name);
        break;
        }
    default:
        if (g_ascii_isprint(indicator))
            ws_warning("Unknown indicator '%c'", indicator);
        else
            ws_warning("Unknown indicator '\\x%02x", indicator);
        break;
    }

    g_free(buffer);
    return true;
}



/*
 * dumpcap is exiting; wait for it to exit.  On success, *msgp is
 * unchanged, and the exit status of dumpcap is returned.  On
 * failure (which includes "dumpcap exited due to being killed by
 * a signal or an exception"), *msgp points to an error message
 * for the failure, and -1 is returned.  In the latter case, *msgp
 * must be freed with g_free().
 */
static int
sync_pipe_wait_for_child(ws_process_id fork_child, char **msgp)
{
    int fork_child_status;
#ifndef _WIN32
    int retry_waitpid = 3;
#endif
    int ret = -1;
    int64_t start_time;
    double elapsed;

    start_time = g_get_monotonic_time();

    ws_debug("wait till child closed");
    ws_assert(fork_child != WS_INVALID_PID);

    *msgp = NULL; /* assume no error */
#ifdef _WIN32
    if (_cwait(&fork_child_status, (intptr_t) fork_child, _WAIT_CHILD) == -1) {
        *msgp = ws_strdup_printf("Error from cwait(): %s", g_strerror(errno));
        ret = -1;
    } else {
        /*
         * The child exited; return its exit status.  Do not treat this as
         * an error.
         */
        ret = fork_child_status;
        if ((fork_child_status & 0xC0000000) == ERROR_SEVERITY_ERROR) {
            /* Probably an exception code */
            *msgp = ws_strdup_printf("Child dumpcap process died: %s",
                                    win32strexception(fork_child_status));
            ret = -1;
        }
    }
#else
    while (--retry_waitpid >= 0) {
        if (waitpid(fork_child, &fork_child_status, 0) != -1) {
            /* waitpid() succeeded */
            if (WIFEXITED(fork_child_status)) {
                /*
                 * The child exited; return its exit status.  Do not treat this as
                 * an error.
                 */
                ret = WEXITSTATUS(fork_child_status);
            } else if (WIFSTOPPED(fork_child_status)) {
                /* It stopped, rather than exiting.  "Should not happen." */
                *msgp = ws_strdup_printf("Child dumpcap process stopped: %s",
                                        sync_pipe_signame(WSTOPSIG(fork_child_status)));
                ret = -1;
            } else if (WIFSIGNALED(fork_child_status)) {
                /* It died with a signal. */
                *msgp = ws_strdup_printf("Child dumpcap process died: %s%s",
                                        sync_pipe_signame(WTERMSIG(fork_child_status)),
                                        WCOREDUMP(fork_child_status) ? " - core dumped" : "");
                ret = -1;
            } else {
                /* What?  It had to either have exited, or stopped, or died with
                   a signal; what happened here? */
                *msgp = ws_strdup_printf("Bad status from waitpid(): %#o",
                                        fork_child_status);
                ret = -1;
            }
        } else {
            /* waitpid() failed */
            if (errno == EINTR) {
                /*
                 * Signal interrupted waitpid().
                 *
                 * If it's SIGALRM, we just want to keep waiting, in case
                 * there's some timer using it (e.g., in a GUI toolkit).
                 *
                 * If you ^C TShark (or Wireshark), that should deliver
                 * SIGINT to dumpcap as well.  dumpcap catches SIGINT,
                 * and should clean up and exit, so we should eventually
                 * see that and clean up and terminate.
                 *
                 * If we're sent a SIGTERM, we should (and do) catch it,
                 * and TShark, at least, calls sync_pipe_stop(). which
                 * kills dumpcap, so we should eventually see that and
                 * clean up and terminate.
                 */
                ws_warning("waitpid returned EINTR. retrying.");
                continue;
            } else if (errno == ECHILD) {
                /*
                 * The process identified by fork_child either doesn't
                 * exist any more or isn't our child process (anymore?).
                 *
                 * echld might have already reaped the child.
                 */
               ret = fetch_dumpcap_pid ? 0 : -1;
            } else {
                /* Unknown error. */
                *msgp = ws_strdup_printf("Error from waitpid(): %s", g_strerror(errno));
                ret = -1;
            }
        }
        break;
    }
#endif

    elapsed = (g_get_monotonic_time() - start_time) / 1e6;
    ws_debug("capture child closed after %.3fs", elapsed);
    return ret;
}


#ifndef _WIN32
/* convert signal to corresponding name */
static const char *
sync_pipe_signame(int sig)
{
    const char *sigmsg;
    static char sigmsg_buf[6+1+3+1];

    switch (sig) {

    case SIGHUP:
        sigmsg = "Hangup";
        break;

    case SIGINT:
        sigmsg = "Interrupted";
        break;

    case SIGQUIT:
        sigmsg = "Quit";
        break;

    case SIGILL:
        sigmsg = "Illegal instruction";
        break;

    case SIGTRAP:
        sigmsg = "Trace trap";
        break;

    case SIGABRT:
        sigmsg = "Abort";
        break;

    case SIGFPE:
        sigmsg = "Arithmetic exception";
        break;

    case SIGKILL:
        sigmsg = "Killed";
        break;

    case SIGBUS:
        sigmsg = "Bus error";
        break;

    case SIGSEGV:
        sigmsg = "Segmentation violation";
        break;

        /* http://metalab.unc.edu/pub/Linux/docs/HOWTO/GCC-HOWTO
           Linux is POSIX compliant.  These are not POSIX-defined signals ---
           ISO/IEC 9945-1:1990 (IEEE Std 1003.1-1990), paragraph B.3.3.1.1 sez:

           ``The signals SIGBUS, SIGEMT, SIGIOT, SIGTRAP, and SIGSYS
           were omitted from POSIX.1 because their behavior is
           implementation dependent and could not be adequately catego-
           rized.  Conforming implementations may deliver these sig-
           nals, but must document the circumstances under which they
           are delivered and note any restrictions concerning their
           delivery.''

           So we only check for SIGSYS on those systems that happen to
           implement them (a system can be POSIX-compliant and implement
           them, it's just that POSIX doesn't *require* a POSIX-compliant
           system to implement them).
        */

#ifdef SIGSYS
    case SIGSYS:
        sigmsg = "Bad system call";
        break;
#endif

    case SIGPIPE:
        sigmsg = "Broken pipe";
        break;

    case SIGALRM:
        sigmsg = "Alarm clock";
        break;

    case SIGTERM:
        sigmsg = "Terminated";
        break;

    default:
        /* Returning a static buffer is ok in the context we use it here */
        snprintf(sigmsg_buf, sizeof sigmsg_buf, "Signal %d", sig);
        sigmsg = sigmsg_buf;
        break;
    }
    return sigmsg;
}
#endif


#ifdef _WIN32

static int create_dummy_signal_pipe(char **msg) {
    char *dummy_signal_pipe_name;

    if (dummy_signal_pipe != NULL) return 0;

    if (!dummy_control_id) {
        dummy_control_id = ws_strdup_printf("%ld.dummy", GetCurrentProcessId());
    }

    /* Create the signal pipe */
    dummy_signal_pipe_name = ws_strdup_printf(SIGNAL_PIPE_FORMAT, dummy_control_id);
    dummy_signal_pipe = CreateNamedPipe(utf_8to16(dummy_signal_pipe_name),
                                  PIPE_ACCESS_OUTBOUND, PIPE_TYPE_BYTE, 1, 65535, 65535, 0, NULL);
    g_free(dummy_signal_pipe_name);
    if (dummy_signal_pipe == INVALID_HANDLE_VALUE) {
        *msg = ws_strdup_printf("Couldn't create signal pipe: %s",
            win32strerror(GetLastError()));
        return -1;
    }
    return 0;
}

/* tell the child through the signal pipe that we want to quit the capture */
static void
signal_pipe_capquit_to_child(capture_session *cap_session)
{
    const char quit_msg[] = "QUIT";
    int ret;

    ws_debug("signal_pipe_capquit_to_child");

    /* it doesn't matter *what* we send here, the first byte will stop the capture */
    /* simply sending a "QUIT" string */
    /*sync_pipe_write_string_msg(cap_session->signal_pipe_write_fd, SP_QUIT, quit_msg);*/
    ret = ws_write(cap_session->signal_pipe_write_fd, quit_msg, sizeof quit_msg);
    if(ret == -1) {
        ws_warning("%d header: error %s", cap_session->signal_pipe_write_fd, win32strerror(GetLastError()));
    }
}
#endif


/* user wants to stop the capture run */
void
sync_pipe_stop(capture_session *cap_session)
{
    if (cap_session->fork_child != WS_INVALID_PID) {
#ifndef _WIN32
        /* send the SIGINT signal to close the capture child gracefully. */
        int sts = kill(cap_session->fork_child, SIGINT);
        if (sts != 0) {
            ws_warning("Sending SIGINT to child failed: %s\n", g_strerror(errno));
        }
#else
#define STOP_SLEEP_TIME 500 /* ms */
        DWORD status;

        /* First, use the special signal pipe to try to close the capture child
         * gracefully.
         */
        signal_pipe_capquit_to_child(cap_session);

        /* Next, wait for the process to exit on its own */
        status = WaitForSingleObject((HANDLE) cap_session->fork_child, STOP_SLEEP_TIME);

        /* Force the issue. */
        if (status != WAIT_OBJECT_0) {
            ws_warning("sync_pipe_stop: forcing child to exit");
            sync_pipe_kill(cap_session->fork_child);
        }
#endif
    }
}


/* Wireshark has to exit, force the capture child to close */
void
sync_pipe_kill(ws_process_id fork_child)
{
    if (fork_child != WS_INVALID_PID) {
#ifndef _WIN32
        int sts = kill(fork_child, SIGTERM);    /* SIGTERM so it can clean up if necessary */
        if (sts != 0) {
            ws_warning("Sending SIGTERM to child failed: %s\n", g_strerror(errno));
        }
#else
        /* Remark: This is not the preferred method of closing a process!
         * the clean way would be getting the process id of the child process,
         * then getting window handle hWnd of that process (using EnumChildWindows),
         * and then do a SendMessage(hWnd, WM_CLOSE, 0, 0)
         *
         * Unfortunately, I don't know how to get the process id from the
         * handle.  OpenProcess will get an handle (not a window handle)
         * from the process ID; it will not get a window handle from the
         * process ID.  (How could it?  A process can have more than one
         * window.  For that matter, a process might have *no* windows,
         * as a process running dumpcap, the normal child process program,
         * probably does.)
         *
         * Hint: GenerateConsoleCtrlEvent() will only work if both processes are
         * running in the same console; that's not necessarily the case for
         * us, as we might not be running in a console.
         * And this also will require to have the process id.
         */
        TerminateProcess((HANDLE) (fork_child), 0);

#endif
    }
}

void capture_sync_set_fetch_dumpcap_pid_cb(void(*cb)(ws_process_id pid)) {
    fetch_dumpcap_pid = cb;
}

#endif /* HAVE_LIBPCAP */
