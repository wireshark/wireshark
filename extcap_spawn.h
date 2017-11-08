/* extcap_spawn.h
 * Helper routines for executing extcap utilities
 *
 * Copyright 2016, Roland Knall <rknall@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef __EXTCAP_SPAWN_H__
#define __EXTCAP_SPAWN_H__

#include <config.h>

#include <glib.h>

#include <extcap.h>

typedef struct _extcap_userdata {
    GPid pid;
    gchar * extcap_stderr;
    gint exitcode;
    gint extcap_stderr_rd;
    gint extcap_stdout_rd;
#ifdef _WIN32
    HANDLE threadId;
#endif
} extcap_userdata;

gboolean extcap_spawn_sync ( gchar * dirname, gchar * command, gint argc, gchar ** argv, gchar ** command_output );

GPid extcap_spawn_async ( extcap_userdata * userdata, GPtrArray * args );

#ifdef _WIN32
gboolean extcap_wait_for_pipe(HANDLE * pipe_handles, int num_pipe_handles, HANDLE pid);
void win32_readfrompipe(HANDLE read_pipe, gint32 max_buffer, gchar * buffer);
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
