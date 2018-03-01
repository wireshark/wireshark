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

#include "ws_symbol_export.h"

#include <glib.h>

#ifdef _WIN32
#define INVALID_EXTCAP_PID INVALID_HANDLE_VALUE
#else
#define INVALID_EXTCAP_PID (GPid)-1
#endif

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

WS_DLL_PUBLIC gboolean ws_pipe_spawn_sync ( gchar * dirname, gchar * command, gint argc, gchar ** argv, gchar ** command_output );

WS_DLL_PUBLIC GPid ws_pipe_spawn_async (ws_pipe_t * ws_pipe, GPtrArray * args );

#ifdef _WIN32
WS_DLL_PUBLIC gboolean ws_pipe_wait_for_pipe(HANDLE * pipe_handles, int num_pipe_handles, HANDLE pid);
#endif

WS_DLL_PUBLIC gboolean ws_pipe_data_available(int pipe_fd);

WS_DLL_PUBLIC gboolean ws_read_string_from_pipe(ws_pipe_handle read_pipe,
    gchar *buffer, size_t buffer_size);

#endif /* __WS_PIPE_H__ */

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
