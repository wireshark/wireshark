/* processes.h
 * Process utility definitions
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

#ifndef _WSUTIL_PROCESSES_H_
#define _WSUTIL_PROCESSES_H_

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef _WIN32
/*
 * On Windows, a process ID is a HANDLE.
 * Include <windows.h> to make sure HANDLE is defined.
 */
#include <windows.h>

typedef HANDLE ws_process_id;

#define WS_INVALID_PID    INVALID_HANDLE_VALUE
#else
/*
 * On UN*X, a process ID is a pid_t.
 * Include <sys/types.h> to make sure pid_t is defined.
 */
#include <sys/types.h>

typedef pid_t ws_process_id;

#define WS_INVALID_PID    -1
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _WSUTIL_PROCESSES_H_ */
