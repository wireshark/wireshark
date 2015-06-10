/* process.h
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

#ifndef _WSUTIL_PROCESS_H_
#define _WSUTIL_PROCESS_H_

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef _WIN32
typedef HANDLE ws_process_id; /* on Windows, a process ID is a HANDLE */
#else
typedef pid_t ws_process_id;  /* on UN\*X, a process ID is a pid_t */
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _WSUTIL_PROCESS_H_ */
