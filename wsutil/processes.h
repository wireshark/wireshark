/* processes.h
 * Process utility definitions
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
