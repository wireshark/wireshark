/* ws_pipe.h
 *
 * Routines for handling pipes.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WS_PIPE_H__
#define __WS_PIPE_H__

// ws_symbol_export and WS_INVALID_PID
#include "wsutil/processes.h"

#include <glib.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#define ws_pipe_handle			HANDLE
#define ws_get_pipe_handle(pipe_fd)	((HANDLE)_get_osfhandle(pipe_fd))
#else
#define ws_pipe_handle			int
#define ws_get_pipe_handle(pipe_fd)	(pipe_fd)
#endif

typedef struct _ws_pipe_t {
    GPid pid;
    gchar *stderr_msg;
    gint exitcode;
    gint stdin_fd;
    gint stdout_fd;
    gint stderr_fd;
#ifdef _WIN32
    HANDLE threadId;
#endif
} ws_pipe_t;

/**
 * @brief Run a process using g_spawn_sync on UNIX and Linux, and
 *        CreateProcess on Windows. Wait for it to finish.
 * @param [IN] working_directory Initial working directory.
 * @param [IN] command Command to run.
 * @param [IN] argc Number of arguments for the command, not including the command itself.
 * @param [IN] args Arguments for the command, not including the command itself.
 * The last element must be NULL.
 * @param [OUT] command_output If not NULL, receives a copy of the command output. Must be g_freed.
 * @return TRUE on success or FALSE on failure.
 */
WS_DLL_PUBLIC gboolean ws_pipe_spawn_sync(const gchar * working_directory, const gchar * command, gint argc, gchar ** args, gchar ** command_output);

/**
 * @brief Initialize a ws_pipe_t struct. Sets .pid to WS_INVALID_PID and all other members to 0 or NULL.
 * @param ws_pipe [IN] The pipe to initialize.
 */
WS_DLL_PUBLIC void ws_pipe_init(ws_pipe_t *ws_pipe);

/**
 * @brief Checks whether a pipe is valid (for reading or writing).
 */
static inline gboolean ws_pipe_valid(ws_pipe_t *ws_pipe)
{
    return ws_pipe && ws_pipe->pid && ws_pipe->pid != WS_INVALID_PID;
}

/**
 * @brief Start a process using g_spawn_sync on UNIX and Linux, and CreateProcess on Windows.
 * @param ws_pipe The process PID, stdio descriptors, etc.
 * @param args The command to run along with its arguments.
 * @return A valid PID on success, otherwise WS_INVALID_PID.
 */
WS_DLL_PUBLIC GPid ws_pipe_spawn_async (ws_pipe_t * ws_pipe, GPtrArray * args );

/**
 * @brief Stop a process started with ws_pipe_spawn_async
 * @param ws_pipe The process PID, stdio descriptors, etc.
 */
WS_DLL_PUBLIC void ws_pipe_close(ws_pipe_t * ws_pipe);

#ifdef _WIN32
/**
 * @brief Wait for a set of handles using WaitForMultipleObjects. Windows only.
 * @param pipe_handles An array of handles
 * @param num_pipe_handles The size of the array.
 * @param pid Child process PID.
 * @return TRUE on success or FALSE on failure.
 */
WS_DLL_PUBLIC gboolean ws_pipe_wait_for_pipe(HANDLE * pipe_handles, int num_pipe_handles, HANDLE pid);
#endif

/**
 * @brief Check to see if a file descriptor has data available.
 * @param pipe_fd File descriptor, usually ws_pipe_t .stdout_fd or .stderr_fd.
 * @return TRUE if data is available or FALSE otherwise.
 */
WS_DLL_PUBLIC gboolean ws_pipe_data_available(int pipe_fd);

/**
 * @brief Read up to buffer_size - 1 bytes from a pipe and append '\0' to the buffer.
 * @param read_pipe File descriptor, usually ws_pipe_t .stdout_fd or .stderr_fd.
 * @param buffer String buffer.
 * @param buffer_size String buffer size.
 * @return TRUE if zero or more bytes were read without error, FALSE otherwise.
 */
WS_DLL_PUBLIC gboolean ws_read_string_from_pipe(ws_pipe_handle read_pipe,
    gchar *buffer, size_t buffer_size);

#endif /* __WS_PIPE_H__ */

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
