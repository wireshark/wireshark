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
#include "wsutil/ws_pipe.h"

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

#if !GLIB_CHECK_VERSION(2, 58, 2)
#ifdef __linux__
#define HAS_G_SPAWN_LINUX_THREAD_SAFETY_BUG
#include <fcntl.h>
#include <sys/syscall.h>        /* for syscall and SYS_getdents64 */
#include <wsutil/file_util.h>   /* for ws_open -> open to pacify checkAPIs.pl */
#endif
#endif

#include "wsutil/filesystem.h"
#include "wsutil/wslog.h"

#ifdef HAS_G_SPAWN_LINUX_THREAD_SAFETY_BUG
struct linux_dirent64 {
    uint64_t       d_ino;    /* 64-bit inode number */
    uint64_t       d_off;    /* 64-bit offset to next structure */
    unsigned short d_reclen; /* Size of this dirent */
    unsigned char  d_type;   /* File type */
    char           d_name[]; /* Filename (null-terminated) */
};

/* Async-signal-safe string to integer conversion. */
static int
filename_to_fd(const char *p)
{
    char c;
    int fd = 0;
    const int cutoff = INT_MAX / 10;
    const int cutlim = INT_MAX % 10;

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
close_non_standard_fds_linux(void * user_data _U_)
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
static bool
ws_pipe_create_overlapped_read(HANDLE *read_pipe_handle, HANDLE *write_pipe_handle,
                               SECURITY_ATTRIBUTES *sa, DWORD suggested_buffer_size)
{
    HANDLE read_pipe, write_pipe;
    unsigned char *name = ws_strdup_printf("\\\\.\\Pipe\\WiresharkWsPipe.%08lx.%08lx",
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
        return false;
    }

    write_pipe = CreateFile(wname, GENERIC_WRITE, 0, sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == write_pipe)
    {
        DWORD error = GetLastError();
        CloseHandle(read_pipe);
        SetLastError(error);
        g_free(wname);
        return false;
    }

    *read_pipe_handle = read_pipe;
    *write_pipe_handle = write_pipe;
    g_free(wname);
    return true;
}
#endif

/**
 * Helper to convert a command and argument list to an NULL-terminated 'argv'
 * array, suitable for g_spawn_sync and friends. Free with g_strfreev.
 */
static char **
convert_to_argv(const char *command, int args_count, char *const *args)
{
    char **argv = g_new(char *, args_count + 2);
    // The caller does not seem to modify this, but g_spawn_sync uses 'char **'
    // as opposed to 'const char **', so just to be sure clone it.
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
static char *
convert_to_command_line(char **argv)
{
    GString *command_line = g_string_sized_new(200);
#ifdef _WIN32
    // The first argument must always be quoted even if it does not contain
    // special characters or else CreateProcess might consider arguments as part
    // of the executable.
    char *quoted_arg = protect_arg(argv[0]);
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
        char *quoted_arg = g_shell_quote(argv[i]);
        if (i != 0) {
            g_string_append_c(command_line, ' ');
        }
        g_string_append(command_line, quoted_arg);
        g_free(quoted_arg);
    }
#endif
    return g_string_free(command_line, FALSE);
}

bool ws_pipe_spawn_sync(const char *working_directory, const char *command, int argc, char **args, char **command_output)
{
    bool status = false;
    bool result = false;
    char *local_output = NULL;
#ifdef _WIN32

#define BUFFER_SIZE 16384

    STARTUPINFO info;
    PROCESS_INFORMATION processInfo;

    SECURITY_ATTRIBUTES sa;
    HANDLE child_stdout_rd = NULL;
    HANDLE child_stdout_wr = NULL;
    HANDLE child_stderr_rd = NULL;
    HANDLE child_stderr_wr = NULL;
    HANDLE inherit_handles[2];

    OVERLAPPED stdout_overlapped;
    OVERLAPPED stderr_overlapped;
#else
    int exit_status = 0;
#endif

    char **argv = convert_to_argv(command, argc, args);
    char *command_line = convert_to_command_line(argv);

    ws_debug("command line: %s", command_line);

    uint64_t start_time = g_get_monotonic_time();

#ifdef _WIN32
    /* Setup overlapped structures. Create Manual Reset events, initially not signalled */
    memset(&stdout_overlapped, 0, sizeof(OVERLAPPED));
    memset(&stderr_overlapped, 0, sizeof(OVERLAPPED));
    stdout_overlapped.hEvent = CreateEvent(NULL, true, false, NULL);
    if (!stdout_overlapped.hEvent)
    {
        g_free(command_line);
        g_strfreev(argv);
        ws_debug("Could not create stdout overlapped event");
        return false;
    }
    stderr_overlapped.hEvent = CreateEvent(NULL, true, false, NULL);
    if (!stderr_overlapped.hEvent)
    {
        CloseHandle(stdout_overlapped.hEvent);
        g_free(command_line);
        g_strfreev(argv);
        ws_debug("Could not create stderr overlapped event");
        return false;
    }

    memset(&sa, 0, sizeof(SECURITY_ATTRIBUTES));
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = false;
    sa.lpSecurityDescriptor = NULL;

    if (!ws_pipe_create_overlapped_read(&child_stdout_rd, &child_stdout_wr, &sa, 0))
    {
        CloseHandle(stdout_overlapped.hEvent);
        CloseHandle(stderr_overlapped.hEvent);
        g_free(command_line);
        g_strfreev(argv);
        ws_debug("Could not create stdout handle");
        return false;
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
        return false;
    }

    inherit_handles[0] = child_stderr_wr;
    inherit_handles[1] = child_stdout_wr;

    memset(&processInfo, 0, sizeof(PROCESS_INFORMATION));
    memset(&info, 0, sizeof(STARTUPINFO));

    info.cb = sizeof(STARTUPINFO);
    info.hStdError = child_stderr_wr;
    info.hStdOutput = child_stdout_wr;
    info.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    info.wShowWindow = SW_HIDE;

    if (win32_create_process(NULL, command_line, NULL, NULL, G_N_ELEMENTS(inherit_handles), inherit_handles,
                             CREATE_NEW_CONSOLE, NULL, working_directory, &info, &processInfo))
    {
        char* stdout_buffer = (char*)g_malloc(BUFFER_SIZE);
        char* stderr_buffer = (char*)g_malloc(BUFFER_SIZE);
        DWORD dw;
        DWORD bytes_read;
        GString *output_string = g_string_new(NULL);
        bool process_finished = false;
        bool pending_stdout = true;
        bool pending_stderr = true;

        /* Start asynchronous reads from child process stdout and stderr */
        if (!ReadFile(child_stdout_rd, stdout_buffer, BUFFER_SIZE, NULL, &stdout_overlapped))
        {
            if (GetLastError() != ERROR_IO_PENDING)
            {
                ws_debug("ReadFile on child stdout pipe failed. Error %ld", GetLastError());
                pending_stdout = false;
            }
        }

        if (!ReadFile(child_stderr_rd, stderr_buffer, BUFFER_SIZE, NULL, &stderr_overlapped))
        {
            if (GetLastError() != ERROR_IO_PENDING)
            {
                ws_debug("ReadFile on child stderr pipe failed. Error %ld", GetLastError());
                pending_stderr = false;
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

            dw = WaitForMultipleObjects(n_handles, handles, false, INFINITE);
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
                    process_finished = true;
                }
                else if (handles[i] == stdout_overlapped.hEvent)
                {
                    bytes_read = 0;
                    if (!GetOverlappedResult(child_stdout_rd, &stdout_overlapped, &bytes_read, true))
                    {
                        if (GetLastError() == ERROR_BROKEN_PIPE)
                        {
                            pending_stdout = false;
                            continue;
                        }
                        ws_debug("GetOverlappedResult on stdout failed. Error %ld", GetLastError());
                    }
                    if (process_finished && (bytes_read == 0))
                    {
                        /* We have drained the pipe and there isn't any process that holds active write handle to the pipe. */
                        pending_stdout = false;
                        continue;
                    }
                    g_string_append_len(output_string, stdout_buffer, bytes_read);
                    if (!ReadFile(child_stdout_rd, stdout_buffer, BUFFER_SIZE, NULL, &stdout_overlapped))
                    {
                        if (GetLastError() != ERROR_IO_PENDING)
                        {
                            ws_debug("ReadFile on child stdout pipe failed. Error %ld", GetLastError());
                            pending_stdout = false;
                        }
                    }
                }
                else if (handles[i] == stderr_overlapped.hEvent)
                {
                    /* Discard the stderr data just like non-windows version of this function does. */
                    bytes_read = 0;
                    if (!GetOverlappedResult(child_stderr_rd, &stderr_overlapped, &bytes_read, true))
                    {
                        if (GetLastError() == ERROR_BROKEN_PIPE)
                        {
                            pending_stderr = false;
                            continue;
                        }
                        ws_debug("GetOverlappedResult on stderr failed. Error %ld", GetLastError());
                    }
                    if (process_finished && (bytes_read == 0))
                    {
                        pending_stderr = false;
                        continue;
                    }
                    if (!ReadFile(child_stderr_rd, stderr_buffer, BUFFER_SIZE, NULL, &stderr_overlapped))
                    {
                        if (GetLastError() != ERROR_IO_PENDING)
                        {
                            ws_debug("ReadFile on child stderr pipe failed. Error %ld", GetLastError());
                            pending_stderr = false;
                        }
                    }
                }
            }
            else
            {
                ws_debug("WaitForMultipleObjects returned 0x%08lX. Error %ld", dw, GetLastError());
            }
        }

        g_free(stdout_buffer);
        g_free(stderr_buffer);

        status = GetExitCodeProcess(processInfo.hProcess, &dw);
        if (status && dw != 0)
        {
            status = false;
        }

        local_output = g_string_free(output_string, FALSE);

        CloseHandle(child_stdout_rd);
        CloseHandle(child_stderr_rd);

        CloseHandle(processInfo.hProcess);
        CloseHandle(processInfo.hThread);
    }
    else
    {
        status = false;

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
        status = false;
#endif

    ws_debug("%s finished in %.3fms", argv[0], (g_get_monotonic_time() - start_time) / 1000.0);

    if (status)
    {
        if (local_output != NULL) {
            ws_noisy("spawn output: %s", local_output);
            if (command_output != NULL)
                *command_output = g_strdup(local_output);
        }
        result = true;
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
    int stdin_fd, stdout_fd, stderr_fd;
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
    HANDLE inherit_handles[3];
#endif

    // XXX harmonize handling of command arguments for the sync/async functions
    // and make them const? This array ends with a trailing NULL by the way.
    char **args_array = (char **)args->pdata;
    char **argv = convert_to_argv(args_array[0], args->len - 2, args_array + 1);
    char *command_line = convert_to_command_line(argv);

    ws_debug("command line: %s", command_line);

#ifdef _WIN32
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = false;
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

    inherit_handles[0] = child_stdin_rd;
    inherit_handles[1] = child_stderr_wr;
    inherit_handles[2] = child_stdout_wr;

    memset(&processInfo, 0, sizeof(PROCESS_INFORMATION));
    memset(&info, 0, sizeof(STARTUPINFO));

    info.cb = sizeof(STARTUPINFO);
    info.hStdInput = child_stdin_rd;
    info.hStdError = child_stderr_wr;
    info.hStdOutput = child_stdout_wr;
    info.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    info.wShowWindow = SW_HIDE;

    if (win32_create_process(NULL, command_line, NULL, NULL, G_N_ELEMENTS(inherit_handles), inherit_handles,
                             CREATE_NEW_CONSOLE, NULL, NULL, &info, &processInfo))
    {
        stdin_fd = _open_osfhandle((intptr_t)(child_stdin_wr), _O_BINARY);
        stdout_fd = _open_osfhandle((intptr_t)(child_stdout_rd), _O_BINARY);
        stderr_fd = _open_osfhandle((intptr_t)(child_stderr_rd), _O_BINARY);
        pid = processInfo.hProcess;
        CloseHandle(processInfo.hThread);
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
    bool spawned = g_spawn_async_with_pipes(NULL, argv, NULL,
                             flags, child_setup, NULL,
                             &pid, &stdin_fd, &stdout_fd, &stderr_fd, &error);
    if (!spawned) {
        ws_debug("Error creating async pipe: %s", error->message);
        g_free(error->message);
    }
#endif

    g_free(command_line);
    g_strfreev(argv);

    ws_pipe->pid = pid;

    if (pid != WS_INVALID_PID) {
#ifdef _WIN32
        ws_pipe->stdin_io = g_io_channel_win32_new_fd(stdin_fd);
        ws_pipe->stdout_io = g_io_channel_win32_new_fd(stdout_fd);
        ws_pipe->stderr_io = g_io_channel_win32_new_fd(stderr_fd);
#else
        ws_pipe->stdin_io = g_io_channel_unix_new(stdin_fd);
        ws_pipe->stdout_io = g_io_channel_unix_new(stdout_fd);
        ws_pipe->stderr_io = g_io_channel_unix_new(stderr_fd);
#endif
        g_io_channel_set_encoding(ws_pipe->stdin_io, NULL, NULL);
        g_io_channel_set_encoding(ws_pipe->stdout_io, NULL, NULL);
        g_io_channel_set_encoding(ws_pipe->stderr_io, NULL, NULL);
        g_io_channel_set_buffered(ws_pipe->stdin_io, false);
        g_io_channel_set_buffered(ws_pipe->stdout_io, false);
        g_io_channel_set_buffered(ws_pipe->stderr_io, false);
        g_io_channel_set_close_on_unref(ws_pipe->stdin_io, true);
        g_io_channel_set_close_on_unref(ws_pipe->stdout_io, true);
        g_io_channel_set_close_on_unref(ws_pipe->stderr_io, true);
    }

    return pid;
}

#ifdef _WIN32

typedef struct
{
    HANDLE pipeHandle;
    OVERLAPPED ol;
    BOOL pendingIO;
} PIPEINTS;

bool
ws_pipe_wait_for_pipe(HANDLE * pipe_handles, int num_pipe_handles, HANDLE pid)
{
    PIPEINTS pipeinsts[3];
    HANDLE handles[4];
    bool result = true;

    SecureZeroMemory(pipeinsts, sizeof(pipeinsts));

    if (num_pipe_handles == 0 || num_pipe_handles > 3)
    {
        ws_debug("Invalid number of pipes given as argument.");
        return false;
    }

    for (int i = 0; i < num_pipe_handles; ++i)
    {
        pipeinsts[i].ol.hEvent = CreateEvent(NULL, true, false, NULL);
        if (!pipeinsts[i].ol.hEvent)
        {
            ws_debug("Could not create overlapped event");
            for (int j = 0; j < i; j++)
            {
                CloseHandle(pipeinsts[j].ol.hEvent);
            }
            return false;
        }
    }

    for (int i = 0; i < num_pipe_handles; ++i)
    {
        pipeinsts[i].pipeHandle = pipe_handles[i];
        pipeinsts[i].ol.Pointer = 0;
        pipeinsts[i].pendingIO = false;
        if (!ConnectNamedPipe(pipeinsts[i].pipeHandle, &pipeinsts[i].ol))
        {
            DWORD error = GetLastError();
            switch (error)
            {
            case ERROR_IO_PENDING:
                pipeinsts[i].pendingIO = true;
                break;

            case ERROR_PIPE_CONNECTED:
                SetEvent(pipeinsts[i].ol.hEvent);
                break;

            default:
                ws_debug("ConnectNamedPipe failed with %ld\n.", error);
                result = false;
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

        dw = WaitForMultipleObjects(num_handles, handles, false, 30000);
        int handle_idx = dw - WAIT_OBJECT_0;
        if (dw == WAIT_TIMEOUT)
        {
            ws_debug("extcap didn't connect to pipe within 30 seconds.");
            result = false;
            break;
        }
        // If index points to our handles array
        else if (handle_idx >= 0 && handle_idx < num_handles)
        {
            if (handles[handle_idx] == pid)
            {
                ws_debug("extcap terminated without connecting to pipe.");
                result = false;
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
                        true);                     // wait
                    if (!success)
                    {
                        ws_debug("Error %ld \n.", GetLastError());
                        result = false;
                    }
                    pipeinsts[i].pendingIO = false;
                }
            }
        }
        else
        {
            ws_debug("WaitForMultipleObjects returned 0x%08lX. Error %ld", dw, GetLastError());
            result = false;
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

bool
ws_pipe_data_available(int pipe_fd)
{
#ifdef _WIN32 /* PeekNamedPipe */
    HANDLE hPipe = (HANDLE) _get_osfhandle(pipe_fd);
    DWORD bytes_avail;

    if (hPipe == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    if (! PeekNamedPipe(hPipe, NULL, 0, NULL, &bytes_avail, NULL))
    {
        return false;
    }

    if (bytes_avail > 0)
    {
        return true;
    }
    return false;
#else /* select */
    fd_set rfds;
    struct timeval timeout;

    FD_ZERO(&rfds);
    FD_SET(pipe_fd, &rfds);
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;

    if (select(pipe_fd + 1, &rfds, NULL, NULL, &timeout) > 0)
    {
        return true;
    }

    return false;
#endif
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
