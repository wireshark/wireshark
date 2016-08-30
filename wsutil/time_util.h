/* time_util.h
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

#ifndef __TIME_UTIL_H__
#define __TIME_UTIL_H__

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <time.h>

WS_DLL_PUBLIC
time_t mktime_utc(struct tm *tm);

/** Fetch the process CPU time.
 *
 * Fetch the current process user and system CPU times, convert them to
 * seconds, and store them in the provided parameters.
 *
 * @param user_time Seconds spent in user mode.
 * @param sys_time Seconds spent in system (kernel) mode.
 */
WS_DLL_PUBLIC
void get_resource_usage(double *user_time, double *sys_time);

/** Print the process CPU time followed by a log message.
 *
 * Print the current process user and system CPU times along with the times
 * elapsed since the times were last reset.
 *
 * @param reset_delta Reset the delta times. This will typically be TRUE when
 * logging the first measurement and FALSE thereafter.
 * @param format Printf-style format string. Passed to g_string_vprintf.
 * @param ... Parameters for the format string.
 */
WS_DLL_PUBLIC
void log_resource_usage(gboolean reset_delta, const char *format, ...);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TIME_UTIL_H__ */
