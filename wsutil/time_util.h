/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __TIME_UTIL_H__
#define __TIME_UTIL_H__

#include <wireshark.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** Converts a broken down date representation, relative to UTC,
 * to a timestamp
 */
WS_DLL_PUBLIC
time_t mktime_utc(struct tm *tm);

/** Validate the values in a time_t.
 * Currently checks tm_year, tm_mon, tm_mday, tm_hour, tm_min, and tm_sec;
 * disregards tm_wday, tm_yday, and tm_isdst.
 *
 * @param tm The struct tm to validate.
 */
WS_DLL_PUBLIC
bool tm_is_valid(struct tm *tm);

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
 * @param reset_delta Reset the delta times. This will typically be true when
 * logging the first measurement and false thereafter.
 * @param format Printf-style format string. Passed to g_string_vprintf.
 * @param ... Parameters for the format string.
 */
WS_DLL_PUBLIC
void log_resource_usage(bool reset_delta, const char *format, ...);

/**
 * Fetch the number of microseconds since midnight (0 hour), January 1, 1970.
 */
WS_DLL_PUBLIC
uint64_t create_timestamp(void);

WS_DLL_PUBLIC
void ws_tzset(void);

WS_DLL_PUBLIC
struct timespec *ws_clock_get_realtime(struct timespec *ts);

WS_DLL_PUBLIC
struct tm *ws_localtime_r(const time_t *timep, struct tm *result);

WS_DLL_PUBLIC
struct tm *ws_gmtime_r(const time_t *timep, struct tm *result);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TIME_UTIL_H__ */
