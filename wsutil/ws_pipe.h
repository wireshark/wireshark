/* ws_pipe.h
 *
 * Routines for handling pipes.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef __WS_PIPE_H__
#define __WS_PIPE_H__

#include "ws_symbol_export.h"

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
