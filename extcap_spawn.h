/* extcap_spawn.h
 * Helper routines for executing extcap utilities
 *
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
gboolean extcap_wait_for_pipe(HANDLE pipe_h, HANDLE pid);
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
