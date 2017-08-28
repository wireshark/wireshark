/* extcap_spawn.c
 *
 * Routines to spawn extcap external capture programs
 * Copyright 2016, Roland Knall <rknall@gmail.com>
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
#include <glib.h>
#include <string.h>

#include <wsutil/file_util.h>
#include <wsutil/filesystem.h>
#ifdef _WIN32
#include <wsutil/win32-utils.h>
#endif

#include <log.h>

#include "extcap.h"
#include "extcap_spawn.h"

#ifdef _WIN32

void win32_readfrompipe(HANDLE read_pipe, gint32 max_buffer, gchar *buffer)
{
    gboolean bSuccess = FALSE;
    gint32 bytes_written = 0;
    gint32 max_bytes = 0;

    DWORD dwRead;
    DWORD bytes_avail = 0;

    for (;;)
    {
        if (!PeekNamedPipe(read_pipe, NULL, 0, NULL, &bytes_avail, NULL)) break;
        if (bytes_avail <= 0) break;

        max_bytes = max_buffer - bytes_written - 1;

        bSuccess = ReadFile(read_pipe, &buffer[bytes_written], max_bytes, &dwRead, NULL);
        if (!bSuccess || dwRead == 0) break;

        bytes_written += dwRead;
        if ((bytes_written + 1) >= max_buffer) break;
    }

    buffer[bytes_written] = '\0';
}
#endif

gboolean extcap_spawn_sync(gchar *dirname, gchar *command, gint argc, gchar **args, gchar **command_output)
{
    gboolean status = FALSE;
    gboolean result = FALSE;
    gchar **argv = NULL;
    gint cnt = 0;
    gchar *local_output = NULL;
#ifdef _WIN32

#define BUFFER_SIZE 4096
    gchar buffer[BUFFER_SIZE];

    GString *winargs = g_string_sized_new(200);
    gchar *quoted_arg;
    gunichar2 *wcommandline;

    STARTUPINFO info;
    PROCESS_INFORMATION processInfo;

    SECURITY_ATTRIBUTES sa;
    HANDLE child_stdout_rd = NULL;
    HANDLE child_stdout_wr = NULL;
    HANDLE child_stderr_rd = NULL;
    HANDLE child_stderr_wr = NULL;

    const gchar *oldpath = g_getenv("PATH");
    gchar *newpath = NULL;
#else
    gint exit_status = 0;
#endif

    argv = (gchar **) g_malloc0(sizeof(gchar *) * (argc + 2));

#ifdef _WIN32
    newpath = g_strdup_printf("%s;%s", g_strescape(get_progfile_dir(), NULL), oldpath);
    g_setenv("PATH", newpath, TRUE);

    argv[0] = g_strescape(command, NULL);
#else
    argv[0] = g_strdup(command);
#endif

    for (cnt = 0; cnt < argc; cnt++)
        argv[cnt + 1] = args[cnt];
    argv[argc + 1] = NULL;

#ifdef _WIN32

    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&child_stdout_rd, &child_stdout_wr, &sa, 0))
    {
        g_free(argv[0]);
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "Could not create stdout handle");
        return FALSE;
    }

    if (!CreatePipe(&child_stderr_rd, &child_stderr_wr, &sa, 0))
    {
        CloseHandle(child_stdout_rd);
        CloseHandle(child_stdout_wr);
        g_free(argv[0]);
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "Could not create stderr handle");
        return FALSE;
    }

    /* convert args array into a single string */
    /* XXX - could change sync_pipe_add_arg() instead */
    /* there is a drawback here: the length is internally limited to 1024 bytes */
    for (cnt = 0; argv[cnt] != 0; cnt++) {
        if (cnt != 0) g_string_append_c(winargs, ' ');    /* don't prepend a space before the path!!! */
        quoted_arg = protect_arg(argv[cnt]);
        g_string_append(winargs, quoted_arg);
        g_free(quoted_arg);
    }

    wcommandline = g_utf8_to_utf16(winargs->str, (glong)winargs->len, NULL, NULL, NULL);

    memset(&processInfo, 0, sizeof(PROCESS_INFORMATION));
    memset(&info, 0, sizeof(STARTUPINFO));

    info.cb = sizeof(STARTUPINFO);
    info.hStdError = child_stderr_wr;
    info.hStdOutput = child_stdout_wr;
    info.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    info.wShowWindow = SW_HIDE;

    if (CreateProcess(NULL, wcommandline, NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL, &info, &processInfo))
    {
        WaitForSingleObject(processInfo.hProcess, INFINITE);
        win32_readfrompipe(child_stdout_rd, BUFFER_SIZE, buffer);
        local_output = g_strdup_printf("%s", buffer);

        CloseHandle(child_stdout_rd);
        CloseHandle(child_stdout_wr);
        CloseHandle(child_stderr_rd);
        CloseHandle(child_stderr_wr);

        CloseHandle(processInfo.hProcess);
        CloseHandle(processInfo.hThread);
        status = TRUE;
    }
    else
        status = FALSE;

    g_setenv("PATH", oldpath, TRUE);
#else

    status = g_spawn_sync(dirname, argv, NULL,
                          (GSpawnFlags) 0, NULL, NULL, &local_output, NULL, &exit_status, NULL);

    if (status && exit_status != 0)
        status = FALSE;
#endif

    if (status)
    {
        if (command_output != NULL && local_output != NULL)
            *command_output = g_strdup(local_output);

        result = TRUE;
    }

    g_free(local_output);
    g_free(argv[0]);
    g_free(argv);

    return result;
}

GPid extcap_spawn_async(extcap_userdata *userdata, GPtrArray *args)
{
    GPid pid = INVALID_EXTCAP_PID;

#ifdef _WIN32
    gint cnt = 0;
    gchar **tmp = NULL;

    GString *winargs = g_string_sized_new(200);
    gchar *quoted_arg;
    gunichar2 *wcommandline;

    STARTUPINFO info;
    PROCESS_INFORMATION processInfo;

    SECURITY_ATTRIBUTES sa;
    HANDLE child_stdout_rd = NULL;
    HANDLE child_stdout_wr = NULL;
    HANDLE child_stderr_rd = NULL;
    HANDLE child_stderr_wr = NULL;

    const gchar *oldpath = g_getenv("PATH");
    gchar *newpath = NULL;

    newpath = g_strdup_printf("%s;%s", g_strescape(get_progfile_dir(), NULL), oldpath);
    g_setenv("PATH", newpath, TRUE);

    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&child_stdout_rd, &child_stdout_wr, &sa, 0))
    {
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "Could not create stdout handle");
        return FALSE;
    }

    if (!CreatePipe(&child_stderr_rd, &child_stderr_wr, &sa, 0))
    {
        CloseHandle(child_stdout_rd);
        CloseHandle(child_stdout_wr);
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "Could not create stderr handle");
        return FALSE;
    }

    /* convert args array into a single string */
    /* XXX - could change sync_pipe_add_arg() instead */
    /* there is a drawback here: the length is internally limited to 1024 bytes */
    for (tmp = (gchar **)args->pdata, cnt = 0; *tmp && **tmp; ++cnt, ++tmp) {
        if (cnt != 0) g_string_append_c(winargs, ' ');    /* don't prepend a space before the path!!! */
        quoted_arg = protect_arg(*tmp);
        g_string_append(winargs, quoted_arg);
        g_free(quoted_arg);
    }

    wcommandline = g_utf8_to_utf16(winargs->str, (glong)winargs->len, NULL, NULL, NULL);

    memset(&processInfo, 0, sizeof(PROCESS_INFORMATION));
    memset(&info, 0, sizeof(STARTUPINFO));

    info.cb = sizeof(STARTUPINFO);
    info.hStdError = child_stderr_wr;
    info.hStdOutput = child_stdout_wr;
    info.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    info.wShowWindow = SW_HIDE;

    if (CreateProcess(NULL, wcommandline, NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL, &info, &processInfo))
    {
        userdata->extcap_stderr_rd = _open_osfhandle((intptr_t)(child_stderr_rd), _O_BINARY);
        userdata->extcap_stdout_rd = _open_osfhandle((intptr_t)(child_stdout_rd), _O_BINARY);
        userdata->threadId = processInfo.hThread;
        pid = processInfo.hProcess;
    }

    g_setenv("PATH", oldpath, TRUE);
#else
    g_spawn_async_with_pipes(NULL, (gchar **)args->pdata, NULL,
                             (GSpawnFlags) G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL,
                             &pid, NULL, &userdata->extcap_stdout_rd, &userdata->extcap_stderr_rd, NULL);
#endif

    userdata->pid = pid;

    return pid;
}

#ifdef _WIN32

typedef struct
{
    HANDLE pipeHandle;
    OVERLAPPED ol;
    BOOL pendingIO;
} PIPEINTS;

gboolean
extcap_wait_for_pipe(HANDLE * pipe_handles, int num_pipe_handles, HANDLE pid)
{
    PIPEINTS pipeinsts[3];
    DWORD dw, cbRet;
    HANDLE handles[4];
    int error_code;
    int num_waiting_to_connect = 0;
    int num_handles = num_pipe_handles + 1; // PID handle is also added to list of handles.

    if (num_pipe_handles == 0 || num_pipe_handles > 3)
    {
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "Invalid number of pipes given as argument.");
        return FALSE;
    }

    for (int i = 0; i < num_pipe_handles; ++i)
    {
        pipeinsts[i].pipeHandle = pipe_handles[i];
        pipeinsts[i].ol.Pointer = 0;
        pipeinsts[i].ol.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
        pipeinsts[i].pendingIO = FALSE;
        handles[i] = pipeinsts[i].ol.hEvent;
        BOOL connected = ConnectNamedPipe(pipeinsts[i].pipeHandle, &pipeinsts[i].ol);
        if (connected)
        {
            error_code = GetLastError();
            g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "ConnectNamedPipe failed with %d \n.", error_code);
            return FALSE;
        }

        switch (GetLastError())
        {
        case ERROR_IO_PENDING:
            num_waiting_to_connect++;
            pipeinsts[i].pendingIO = TRUE;
            break;

        case ERROR_PIPE_CONNECTED:
            if (SetEvent(pipeinsts[i].ol.hEvent))
            {
                break;
            } // Fallthrough if this fails.

        default:
            error_code = GetLastError();
            g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "ConnectNamedPipe failed with %d \n.", error_code);
            return FALSE;
        }
    }

    // Store pid of extcap process so it can be monitored in case it fails before the pipes has connceted.
    handles[num_pipe_handles] = pid;

    while(num_waiting_to_connect > 0)
    {
        dw = WaitForMultipleObjects(num_handles, handles, FALSE, 30000);
        int idx = dw - WAIT_OBJECT_0;
        if (dw == WAIT_TIMEOUT)
        {
            g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "extcap didn't connect to pipe within 30 seconds.");
            return FALSE;
        }
        // If index points to our handles array
        else if (idx >= 0 && idx < num_handles)
        {
            if (idx < num_pipe_handles)  // Index of pipe handle
            {
                if (pipeinsts[idx].pendingIO)
                {
                    BOOL success = GetOverlappedResult(
                        pipeinsts[idx].pipeHandle, // handle to pipe
                        &pipeinsts[idx].ol,        // OVERLAPPED structure
                        &cbRet,                    // bytes transferred
                        FALSE);                    // do not wait

                    if (!success)
                    {
                        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "Error %d \n.", GetLastError());
                        return FALSE;
                    }
                    else
                    {
                        pipeinsts[idx].pendingIO = FALSE;
                        CloseHandle(pipeinsts[idx].ol.hEvent);
                        num_waiting_to_connect--;
                    }
                }
            }
            else // Index of PID
            {
                // Fail since index of 'pid' indicates that the pid of the extcap process has terminated.
                g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "extcap terminated without connecting to pipe.");
                return FALSE;
            }
        }
        else
        {
            g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "WaitForMultipleObjects returned 0x%08X. Error %d", dw, GetLastError());
            return FALSE;
        }
    }

    return TRUE;
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
