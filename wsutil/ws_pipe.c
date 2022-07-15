/* ws_pipe.c
 *
 * Routines for handling pipes.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>
#define WS_LOG_DOMAIN LOG_DOMAIN_CAPTURE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#include <fcntl.h> /* for _O_BINARY */
#include <wsutil/win32-utils.h>
#else
#include <unistd.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#endif

#include <glib.h>

#ifdef __linux__
#define HAS_G_SPAWN_LINUX_THREAD_SAFETY_BUG
#include <fcntl.h>
#include <sys/syscall.h>        /* for syscall and SYS_getdents64 */
#include <wsutil/file_util.h>   /* for ws_open -> open to pacify checkAPIs.pl */
#endif

#include "wsutil/filesystem.h"
#include "wsutil/ws_pipe.h"
#include "wsutil/wslog.h"

#ifdef HAS_G_SPAWN_LINUX_THREAD_SAFETY_BUG
struct linux_dirent64 {
    guint64        d_ino;    /* 64-bit inode number */
    guint64        d_off;    /* 64-bit offset to next structure */
    unsigned short d_reclen; /* Size of this dirent */
    unsigned char  d_type;   /* File type */
    char           d_name[]; /* Filename (null-terminated) */
};

/* Async-signal-safe string to integer conversion. */
static gint
filename_to_fd(const char *p)
{
    char c;
    int fd = 0;
    const int cutoff = G_MAXINT / 10;
    const int cutlim = G_MAXINT % 10;

    if (*p == '\0')
        return -1;

    while ((c = *p++) != '\0') {
        if (!g_ascii_isdigit(c))
            return -1;
        c -= '0';

        /* Check for overflow. */
        if (fd > cutoff || (fd == cutoff && c > cutlim))
            return -1;

        fd = fd * 10 + c;
    }

    return fd;
}

static void
close_non_standard_fds_linux(gpointer user_data _U_)
{
    /*
     * GLib 2.14.2 and newer (up to at least GLib 2.58.1) on Linux with multiple
     * threads can deadlock in the child process due to use of opendir (which
     * is not async-signal-safe). To avoid this, disable the broken code path
     * and manually close file descriptors using async-signal-safe code only.
     * Use CLOEXEC to allow reporting of execve errors to the parent via a pipe.
     * https://gitlab.gnome.org/GNOME/glib/issues/1014
     * https://gitlab.gnome.org/GNOME/glib/merge_requests/490
     */
    int dir_fd = ws_open("/proc/self/fd", O_RDONLY | O_DIRECTORY);
    if (dir_fd >= 0) {
        char buf[4096];
        int nread, fd;
        struct linux_dirent64 *de;

        while ((nread = (int) syscall(SYS_getdents64, dir_fd, buf, sizeof(buf))) > 0) {
            for (int pos = 0; pos < nread; pos += de->d_reclen) {
                de = (struct linux_dirent64 *)(buf + pos);
                fd = filename_to_fd(de->d_name);
                if (fd > STDERR_FILENO && fd != dir_fd) {
                    /* Close all other (valid) file descriptors above stderr. */
                    fcntl(fd, F_SETFD, FD_CLOEXEC);
                }
            }
        }

        close(dir_fd);
    } else {
        /* Slow fallback in case /proc is not mounted */
        for (int fd = STDERR_FILENO + 1; fd < getdtablesize(); fd++) {
            fcntl(fd, F_SETFD, FD_CLOEXEC);
        }
    }
}
#endif

#ifdef _WIN32
static ULONG pipe_serial_number;

/* Alternative for CreatePipe() where read handle is opened with FILE_FLAG_OVERLAPPED */
static gboolean
ws_pipe_create_overlapped_read(HANDLE *read_pipe_handle, HANDLE *write_pipe_handle,
                               SECURITY_ATTRIBUTES *sa, DWORD suggested_buffer_size)
{
    HANDLE read_pipe, write_pipe;
    guchar *name = ws_strdup_printf("\\\\.\\Pipe\\WiresharkWsPipe.%08x.%08x",
                                   GetCurrentProcessId(),
                                   InterlockedIncrement(&pipe_serial_number));
    gunichar2 *wname = g_utf8_to_utf16(name, -1, NULL, NULL, NULL);

    g_free(name);

    read_pipe = CreateNamedPipe(wname, PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
                                PIPE_TYPE_BYTE | PIPE_WAIT, 1,
                                suggested_buffer_size, suggested_buffer_size,
                                0, sa);
    if (INVALID_HANDLE_VALUE == read_pipe)
    {
        g_free(wname);
        return FALSE;
    }

    write_pipe = CreateFile(wname, GENERIC_WRITE, 0, sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == write_pipe)
    {
        DWORD error = GetLastError();
        CloseHandle(read_pipe);
        SetLastError(error);
        g_free(wname);
        return FALSE;
    }

    *read_pipe_handle = read_pipe;
    *write_pipe_handle = write_pipe;
    g_free(wname);
    return(TRUE);
}
#endif

/**
 * Helper to convert a command and argument list to an NULL-terminated 'argv'
 * array, suitable for g_spawn_sync and friends. Free with g_strfreev.
 */
static gchar **
convert_to_argv(const char *command, int args_count, char *const *args)
{
    gchar **argv = g_new(gchar *, args_count + 2);
    // The caller does not seem to modify this, but g_spawn_sync uses 'gchar **'
    // as opposed to 'const gchar **', so just to be sure clone it.
    argv[0] = g_strdup(command);
    for (int i = 0; i < args_count; i++) {
        // Empty arguments may indicate a bug in Wireshark. Extcap for example
        // omits arguments when their string value is empty. On Windows, empty
        // arguments would silently be ignored because protect_arg returns an
        // empty string, therefore we print a warning here.
        if (!*args[i]) {
            ws_warning("Empty argument %d in arguments list", i);
        }
        argv[1 + i] = g_strdup(args[i]);
    }
    argv[args_count + 1] = NULL;
    return argv;
}

/**
 * Convert a non-empty NULL-terminated array of command and arguments to a
 * string for displaying purposes. On Windows, the returned string is properly
 * escaped and can be executed directly.
 */
static gchar *
convert_to_command_line(gchar **argv)
{
    GString *command_line = g_string_sized_new(200);
#ifdef _WIN32
    // The first argument must always be quoted even if it does not contain
    // special characters or else CreateProcess might consider arguments as part
    // of the executable.
    gchar *quoted_arg = protect_arg(argv[0]);
    if (quoted_arg[0] != '"') {
        g_string_append_c(command_line, '"');
        g_string_append(command_line, quoted_arg);
        g_string_append_c(command_line, '"');
    } else {
        g_string_append(command_line, quoted_arg);
    }
    g_free(quoted_arg);

    for (int i = 1; argv[i]; i++) {
        quoted_arg = protect_arg(argv[i]);
        g_string_append_c(command_line, ' ');
        g_string_append(command_line, quoted_arg);
        g_free(quoted_arg);
    }
#else
    for (int i = 0; argv[i]; i++) {
        gchar *quoted_arg = g_shell_quote(argv[i]);
        if (i != 0) {
            g_string_append_c(command_line, ' ');
        }
        g_string_append(command_line, quoted_arg);
        g_free(quoted_arg);
    }
#endif
    return g_string_free(command_line, FALSE);
}

gboolean ws_pipe_spawn_sync(const gchar *working_directory, const gchar *command, gint argc, gchar **args, gchar **command_output)
{
    gboolean status = FALSE;
    gboolean result = FALSE;
    gchar *local_output = NULL;
#ifdef _WIN32

#define BUFFER_SIZE 16384

    STARTUPINFO info;
    PROCESS_INFORMATION processInfo;

    SECURITY_ATTRIBUTES sa;
    HANDLE child_stdout_rd = NULL;
    HANDLE child_stdout_wr = NULL;
    HANDLE child_stderr_rd = NULL;
    HANDLE child_stderr_wr = NULL;

    OVERLAPPED stdout_overlapped;
    OVERLAPPED stderr_overlapped;
#else
    gint exit_status = 0;
#endif

    gchar **argv = convert_to_argv(command, argc, args);
    gchar *command_line = convert_to_command_line(argv);

    ws_debug("command line: %s", command_line);

    guint64 start_time = g_get_monotonic_time();

#ifdef _WIN32
    /* Setup overlapped structures. Create Manual Reset events, initially not signalled */
    memset(&stdout_overlapped, 0, sizeof(OVERLAPPED));
    memset(&stderr_overlapped, 0, sizeof(OVERLAPPED));
    stdout_overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!stdout_overlapped.hEvent)
    {
        g_free(command_line);
        g_strfreev(argv);
        ws_debug("Could not create stdout overlapped event");
        return FALSE;
    }
    stderr_overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!stderr_overlapped.hEvent)
    {
        CloseHandle(stdout_overlapped.hEvent);
        g_free(command_line);
        g_strfreev(argv);
        ws_debug("Could not create stderr overlapped event");
        return FALSE;
    }

    memset(&sa, 0, sizeof(SECURITY_ATTRIBUTES));
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    if (!ws_pipe_create_overlapped_read(&child_stdout_rd, &child_stdout_wr, &sa, 0))
    {
        CloseHandle(stdout_overlapped.hEvent);
        CloseHandle(stderr_overlapped.hEvent);
        g_free(command_line);
        g_strfreev(argv);
        ws_debug("Could not create stdout handle");
        return FALSE;
    }

    if (!ws_pipe_create_overlapped_read(&child_stderr_rd, &child_stderr_wr, &sa, 0))
    {
        CloseHandle(stdout_overlapped.hEvent);
        CloseHandle(stderr_overlapped.hEvent);
        CloseHandle(child_stdout_rd);
        CloseHandle(child_stdout_wr);
        g_free(command_line);
        g_strfreev(argv);
        ws_debug("Could not create stderr handle");
        return FALSE;
    }

    memset(&processInfo, 0, sizeof(PROCESS_INFORMATION));
    memset(&info, 0, sizeof(STARTUPINFO));

    info.cb = sizeof(STARTUPINFO);
    info.hStdError = child_stderr_wr;
    info.hStdOutput = child_stdout_wr;
    info.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    info.wShowWindow = SW_HIDE;

    if (win32_create_process(NULL, command_line, NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, working_directory, &info, &processInfo))
    {
        gchar* stdout_buffer = (gchar*)g_malloc(BUFFER_SIZE);
        gchar* stderr_buffer = (gchar*)g_malloc(BUFFER_SIZE);
        DWORD dw;
        DWORD bytes_read;
        GString *output_string = g_string_new(NULL);
        gboolean process_finished = FALSE;
        gboolean pending_stdout = TRUE;
        gboolean pending_stderr = TRUE;

        /* Start asynchronous reads from child process stdout and stderr */
        if (!ReadFile(child_stdout_rd, stdout_buffer, BUFFER_SIZE, NULL, &stdout_overlapped))
        {
            if (GetLastError() != ERROR_IO_PENDING)
            {
                ws_debug("ReadFile on child stdout pipe failed. Error %d", GetLastError());
                pending_stdout = FALSE;
            }
        }

        if (!ReadFile(child_stderr_rd, stderr_buffer, BUFFER_SIZE, NULL, &stderr_overlapped))
        {
            if (GetLastError() != ERROR_IO_PENDING)
            {
                ws_debug("ReadFile on child stderr pipe failed. Error %d", GetLastError());
                pending_stderr = FALSE;
            }
        }

        for (;;)
        {
            HANDLE handles[3];
            DWORD n_handles = 0;
            if (!process_finished)
            {
                handles[n_handles++] = processInfo.hProcess;
            }
            if (pending_stdout)
            {
                handles[n_handles++] = stdout_overlapped.hEvent;
            }
            if (pending_stderr)
            {
                handles[n_handles++] = stderr_overlapped.hEvent;
            }

            if (!n_handles)
            {
                /* No more things to wait */
                break;
            }

            dw = WaitForMultipleObjects(n_handles, handles, FALSE, INFINITE);
            if (dw < (WAIT_OBJECT_0 + n_handles))
            {
                int i = dw - WAIT_OBJECT_0;
                if (handles[i] == processInfo.hProcess)
                {
                    /* Process finished but there might still be unread data in the pipe.
                     * Close the write pipes, so ReadFile does not wait indefinitely.
                     */
                    CloseHandle(child_stdout_wr);
                    CloseHandle(child_stderr_wr);
                    process_finished = TRUE;
                }
                else if (handles[i] == stdout_overlapped.hEvent)
                {
                    bytes_read = 0;
                    if (!GetOverlappedResult(child_stdout_rd, &stdout_overlapped, &bytes_read, TRUE))
                    {
                        if (GetLastError() == ERROR_BROKEN_PIPE)
                        {
                            pending_stdout = FALSE;
                            continue;
                        }
                        ws_debug("GetOverlappedResult on stdout failed. Error %d", GetLastError());
                    }
                    if (process_finished && (bytes_read == 0))
                    {
                        /* We have drained the pipe and there isn't any process that holds active write handle to the pipe. */
                        pending_stdout = FALSE;
                        continue;
                    }
                    g_string_append_len(output_string, stdout_buffer, bytes_read);
                    if (!ReadFile(child_stdout_rd, stdout_buffer, BUFFER_SIZE, NULL, &stdout_overlapped))
                    {
                        if (GetLastError() != ERROR_IO_PENDING)
                        {
                            ws_debug("ReadFile on child stdout pipe failed. Error %d", GetLastError());
                            pending_stdout = FALSE;
                        }
                    }
                }
                else if (handles[i] == stderr_overlapped.hEvent)
                {
                    /* Discard the stderr data just like non-windows version of this function does. */
                    bytes_read = 0;
                    if (!GetOverlappedResult(child_stderr_rd, &stderr_overlapped, &bytes_read, TRUE))
                    {
                        if (GetLastError() == ERROR_BROKEN_PIPE)
                        {
                            pending_stderr = FALSE;
                            continue;
                        }
                        ws_debug("GetOverlappedResult on stderr failed. Error %d", GetLastError());
                    }
                    if (process_finished && (bytes_read == 0))
                    {
                        pending_stderr = FALSE;
                        continue;
                    }
                    if (!ReadFile(child_stderr_rd, stderr_buffer, BUFFER_SIZE, NULL, &stderr_overlapped))
                    {
                        if (GetLastError() != ERROR_IO_PENDING)
                        {
                            ws_debug("ReadFile on child stderr pipe failed. Error %d", GetLastError());
                            pending_stderr = FALSE;
                        }
                    }
                }
            }
            else
            {
                ws_debug("WaitForMultipleObjects returned 0x%08X. Error %d", dw, GetLastError());
            }
        }

        g_free(stdout_buffer);
        g_free(stderr_buffer);

        status = GetExitCodeProcess(processInfo.hProcess, &dw);
        if (status && dw != 0)
        {
            status = FALSE;
        }

        local_output = g_string_free(output_string, FALSE);

        CloseHandle(child_stdout_rd);
        CloseHandle(child_stderr_rd);

        CloseHandle(processInfo.hProcess);
        CloseHandle(processInfo.hThread);
    }
    else
    {
        status = FALSE;

        CloseHandle(child_stdout_rd);
        CloseHandle(child_stdout_wr);
        CloseHandle(child_stderr_rd);
        CloseHandle(child_stderr_wr);
    }

    CloseHandle(stdout_overlapped.hEvent);
    CloseHandle(stderr_overlapped.hEvent);
#else

    GSpawnFlags flags = (GSpawnFlags)0;
    GSpawnChildSetupFunc child_setup = NULL;
#ifdef HAS_G_SPAWN_LINUX_THREAD_SAFETY_BUG
    flags = (GSpawnFlags)(flags | G_SPAWN_LEAVE_DESCRIPTORS_OPEN);
    child_setup = close_non_standard_fds_linux;
#endif
    status = g_spawn_sync(working_directory, argv, NULL,
                          flags, child_setup, NULL, &local_output, NULL, &exit_status, NULL);

    if (status && exit_status != 0)
        status = FALSE;
#endif

    ws_debug("%s finished in %.3fms", argv[0], (g_get_monotonic_time() - start_time) / 1000.0);

    if (status)
    {
        if (local_output != NULL) {
            ws_noisy("spawn output: %s", local_output);
            if (command_output != NULL)
                *command_output = g_strdup(local_output);
        }
        result = TRUE;
    }

    g_free(local_output);
    g_free(command_line);
    g_strfreev(argv);

    return result;
}

void ws_pipe_init(ws_pipe_t *ws_pipe)
{
    if (!ws_pipe) return;
    memset(ws_pipe, 0, sizeof(ws_pipe_t));
    ws_pipe->pid = WS_INVALID_PID;
}

GPid ws_pipe_spawn_async(ws_pipe_t *ws_pipe, GPtrArray *args)
{
    GPid pid = WS_INVALID_PID;
#ifdef _WIN32
    STARTUPINFO info;
    PROCESS_INFORMATION processInfo;

    SECURITY_ATTRIBUTES sa;
    HANDLE child_stdin_rd = NULL;
    HANDLE child_stdin_wr = NULL;
    HANDLE child_stdout_rd = NULL;
    HANDLE child_stdout_wr = NULL;
    HANDLE child_stderr_rd = NULL;
    HANDLE child_stderr_wr = NULL;
#endif

    // XXX harmonize handling of command arguments for the sync/async functions
    // and make them const? This array ends with a trailing NULL by the way.
    gchar **args_array = (gchar **)args->pdata;
    gchar **argv = convert_to_argv(args_array[0], args->len - 2, args_array + 1);
    gchar *command_line = convert_to_command_line(argv);

    ws_debug("command line: %s", command_line);

#ifdef _WIN32
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&child_stdin_rd, &child_stdin_wr, &sa, 0))
    {
        g_free(command_line);
        g_strfreev(argv);
        ws_debug("Could not create stdin handle");
        return WS_INVALID_PID;
    }

    if (!CreatePipe(&child_stdout_rd, &child_stdout_wr, &sa, 0))
    {
        CloseHandle(child_stdin_rd);
        CloseHandle(child_stdin_wr);
        g_free(command_line);
        g_strfreev(argv);
        ws_debug("Could not create stdout handle");
        return WS_INVALID_PID;
    }

    if (!CreatePipe(&child_stderr_rd, &child_stderr_wr, &sa, 0))
    {
        CloseHandle(child_stdin_rd);
        CloseHandle(child_stdin_wr);
        CloseHandle(child_stdout_rd);
        CloseHandle(child_stdout_wr);
        g_free(command_line);
        g_strfreev(argv);
        ws_debug("Could not create stderr handle");
        return WS_INVALID_PID;
    }

    memset(&processInfo, 0, sizeof(PROCESS_INFORMATION));
    memset(&info, 0, sizeof(STARTUPINFO));

    info.cb = sizeof(STARTUPINFO);
    info.hStdInput = child_stdin_rd;
    info.hStdError = child_stderr_wr;
    info.hStdOutput = child_stdout_wr;
    info.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    info.wShowWindow = SW_HIDE;

    if (win32_create_process(NULL, command_line, NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL, &info, &processInfo))
    {
        ws_pipe->stdin_fd = _open_osfhandle((intptr_t)(child_stdin_wr), _O_BINARY);
        ws_pipe->stdout_fd = _open_osfhandle((intptr_t)(child_stdout_rd), _O_BINARY);
        ws_pipe->stderr_fd = _open_osfhandle((intptr_t)(child_stderr_rd), _O_BINARY);
        ws_pipe->threadId = processInfo.hThread;
        pid = processInfo.hProcess;
    }
    else
    {
        CloseHandle(child_stdin_wr);
        CloseHandle(child_stdout_rd);
        CloseHandle(child_stderr_rd);
    }

    /* We no longer need other (child) end of pipes. The child process holds
     * its own handles that will be closed on process exit. However, we have
     * to close *our* handles as otherwise read() on stdout_fd and stderr_fd
     * will block indefinitely after the process exits.
     */
    CloseHandle(child_stdin_rd);
    CloseHandle(child_stdout_wr);
    CloseHandle(child_stderr_wr);
#else

    GError *error = NULL;
    GSpawnFlags flags = G_SPAWN_DO_NOT_REAP_CHILD;
    GSpawnChildSetupFunc child_setup = NULL;
#ifdef HAS_G_SPAWN_LINUX_THREAD_SAFETY_BUG
    flags = (GSpawnFlags)(flags | G_SPAWN_LEAVE_DESCRIPTORS_OPEN);
    child_setup = close_non_standard_fds_linux;
#endif
    gboolean spawned = g_spawn_async_with_pipes(NULL, argv, NULL,
                             flags, child_setup, NULL,
                             &pid, &ws_pipe->stdin_fd, &ws_pipe->stdout_fd, &ws_pipe->stderr_fd, &error);
    if (!spawned) {
        ws_debug("Error creating async pipe: %s", error->message);
        g_free(error->message);
    }
#endif

    g_free(command_line);
    g_strfreev(argv);

    ws_pipe->pid = pid;

    return pid;
}

void ws_pipe_close(ws_pipe_t * ws_pipe)
{
    if (ws_pipe->pid != WS_INVALID_PID) {
#ifdef _WIN32
        TerminateProcess(ws_pipe->pid, 0);
#endif
        g_spawn_close_pid(ws_pipe->pid);
        ws_pipe->pid = WS_INVALID_PID;
    }
}

#ifdef _WIN32

typedef struct
{
    HANDLE pipeHandle;
    OVERLAPPED ol;
    BOOL pendingIO;
} PIPEINTS;

gboolean
ws_pipe_wait_for_pipe(HANDLE * pipe_handles, int num_pipe_handles, HANDLE pid)
{
    PIPEINTS pipeinsts[3];
    HANDLE handles[4];
    gboolean result = TRUE;

    SecureZeroMemory(pipeinsts, sizeof(pipeinsts));

    if (num_pipe_handles == 0 || num_pipe_handles > 3)
    {
        ws_debug("Invalid number of pipes given as argument.");
        return FALSE;
    }

    for (int i = 0; i < num_pipe_handles; ++i)
    {
        pipeinsts[i].ol.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (!pipeinsts[i].ol.hEvent)
        {
            ws_debug("Could not create overlapped event");
            for (int j = 0; j < i; j++)
            {
                CloseHandle(pipeinsts[j].ol.hEvent);
            }
            return FALSE;
        }
    }

    for (int i = 0; i < num_pipe_handles; ++i)
    {
        pipeinsts[i].pipeHandle = pipe_handles[i];
        pipeinsts[i].ol.Pointer = 0;
        pipeinsts[i].pendingIO = FALSE;
        if (!ConnectNamedPipe(pipeinsts[i].pipeHandle, &pipeinsts[i].ol))
        {
            DWORD error = GetLastError();
            switch (error)
            {
            case ERROR_IO_PENDING:
                pipeinsts[i].pendingIO = TRUE;
                break;

            case ERROR_PIPE_CONNECTED:
                SetEvent(pipeinsts[i].ol.hEvent);
                break;

            default:
                ws_debug("ConnectNamedPipe failed with %d\n.", error);
                result = FALSE;
            }
        }
    }

    while (result)
    {
        DWORD dw;
        int num_handles = 0;
        for (int i = 0; i < num_pipe_handles; ++i)
        {
            if (pipeinsts[i].pendingIO)
            {
                handles[num_handles] = pipeinsts[i].ol.hEvent;
                num_handles++;
            }
        }
        if (num_handles == 0)
        {
            /* All pipes have been successfully connected */
            break;
        }
        /* Wait for process in case it exits before the pipes have connected */
        handles[num_handles] = pid;
        num_handles++;

        dw = WaitForMultipleObjects(num_handles, handles, FALSE, 30000);
        int handle_idx = dw - WAIT_OBJECT_0;
        if (dw == WAIT_TIMEOUT)
        {
            ws_debug("extcap didn't connect to pipe within 30 seconds.");
            result = FALSE;
            break;
        }
        // If index points to our handles array
        else if (handle_idx >= 0 && handle_idx < num_handles)
        {
            if (handles[handle_idx] == pid)
            {
                ws_debug("extcap terminated without connecting to pipe.");
                result = FALSE;
            }
            for (int i = 0; i < num_pipe_handles; ++i)
            {
                if (handles[handle_idx] == pipeinsts[i].ol.hEvent)
                {
                    DWORD cbRet;
                    BOOL success = GetOverlappedResult(
                        pipeinsts[i].pipeHandle, // handle to pipe
                        &pipeinsts[i].ol,        // OVERLAPPED structure
                        &cbRet,                    // bytes transferred
                        TRUE);                     // wait
                    if (!success)
                    {
                        ws_debug("Error %d \n.", GetLastError());
                        result = FALSE;
                    }
                    pipeinsts[i].pendingIO = FALSE;
                }
            }
        }
        else
        {
            ws_debug("WaitForMultipleObjects returned 0x%08X. Error %d", dw, GetLastError());
            result = FALSE;
        }
    }

    for (int i = 0; i < num_pipe_handles; ++i)
    {
        if (pipeinsts[i].pendingIO)
        {
            CancelIoEx(pipeinsts[i].pipeHandle, &pipeinsts[i].ol);
            WaitForSingleObject(pipeinsts[i].ol.hEvent, INFINITE);
        }
        CloseHandle(pipeinsts[i].ol.hEvent);
    }

    return result;
}
#endif

gboolean
ws_pipe_data_available(int pipe_fd)
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

gboolean
ws_read_string_from_pipe(ws_pipe_handle read_pipe, gchar *buffer,
                         size_t buffer_size)
{
    size_t total_bytes_read;
    size_t buffer_bytes_remaining;
#ifdef _WIN32
    DWORD bytes_to_read;
    DWORD bytes_read;
    DWORD bytes_avail;
#else
    size_t bytes_to_read;
    ssize_t bytes_read;
#endif
    int ret = FALSE;

    if (buffer_size == 0)
    {
        /* XXX - provide an error string */
        return FALSE;
    }

    total_bytes_read = 0;
    for (;;)
    {
        /* Leave room for the terminating NUL. */
        buffer_bytes_remaining = buffer_size - total_bytes_read - 1;
        if (buffer_bytes_remaining == 0)
        {
            /* The string won't fit in the buffer. */
            ws_debug("Buffer too small (%zd).", buffer_size);
            break;
        }

#ifdef _WIN32
        /*
         * XXX - is there some reason why we do this before reading?
         *
         * If we're not trying to do UN*X-style non-blocking I/O,
         * where we don't block if there isn't data available to
         * read right now, I'm not sure why we do this.
         *
         * If we *are* trying to do UN*X-style non-blocking I/O,
         * 1) we're presumably in an event loop waiting for,
         * among other things, input to be available on the
         * pipe, in which case we should be doing "overlapped"
         * I/O and 2) we need to accumulate data until we have
         * a complete string, rather than just saying "OK, here's
         * the string".)
         */
        if (!PeekNamedPipe(read_pipe, NULL, 0, NULL, &bytes_avail, NULL))
        {
            break;
        }
        if (bytes_avail == 0)
        {
            ret = TRUE;
            break;
        }

        /*
         * Truncate this to whatever fits in a DWORD.
         */
        if (buffer_bytes_remaining > 0x7fffffff)
        {
            bytes_to_read = 0x7fffffff;
        }
        else
        {
            bytes_to_read = (DWORD)buffer_bytes_remaining;
        }
        if (!ReadFile(read_pipe, &buffer[total_bytes_read], bytes_to_read,
            &bytes_read, NULL))
        {
            /* XXX - provide an error string */
            break;
        }
#else
        /*
         * Check if data is available before doing a blocking I/O read.
         *
         * XXX - this means that if part of the string, but not all of
         * the string, has been written to the pipe, this will just
         * return, as the string, the part that's been written as of
         * this point.
         *
         * Pipes, on UN*X, are like TCP connections - there are *no*
         * message boundaries, they're just byte streams.  Either 1)
         * precisely *one* string can be sent on this pipe, and the
         * sending side must be closed after the string is written to
         * the pipe, so that an EOF indicates the end of the string
         * or 2) the strings must either be preceded by a length indication
         * or must be terminated with an end-of-string indication (such
         * as a '\0'), so that we can determine when one string ends and
         * another string begins.
         */
        if (!ws_pipe_data_available(read_pipe)) {
            ret = TRUE;
            break;
        }

        bytes_to_read = buffer_bytes_remaining;
        bytes_read = read(read_pipe, &buffer[total_bytes_read], bytes_to_read);
        if (bytes_read == -1)
        {
            /* XXX - provide an error string */
            break;
        }
#endif
        if (bytes_read == 0)
        {
            ret = TRUE;
            break;
        }

        total_bytes_read += bytes_read;
    }

    buffer[total_bytes_read] = '\0';
    return ret;
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
