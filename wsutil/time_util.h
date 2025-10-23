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

/**
 * @brief Converts a UTC-based broken-down time to a timestamp.
 *
 * Converts a `struct tm` representing a UTC time into a `time_t` value.
 * This is similar to `mktime()` but assumes the input is in UTC rather than local time.
 *
 * @param tm Pointer to a `struct tm` representing UTC time.
 * @return The corresponding `time_t` value.
 */
WS_DLL_PUBLIC
time_t mktime_utc(struct tm *tm);

/**
 * @brief Validates the fields of a broken-down time structure.
 *
 * Checks whether the values in a `struct tm` are within valid ranges.
 * Only `tm_year`, `tm_mon`, `tm_mday`, `tm_hour`, `tm_min`, and `tm_sec` are validated.
 * Fields `tm_wday`, `tm_yday`, and `tm_isdst` are ignored.
 *
 * @param tm Pointer to the `struct tm` to validate.
 * @return true if the structure contains valid values, false otherwise.
 */
WS_DLL_PUBLIC
bool tm_is_valid(struct tm *tm);

/**
 * @brief Retrieves the current process CPU usage.
 *
 * Fetches the amount of time the process has spent in user and system (kernel) mode,
 * and stores the values in seconds.
 *
 * @param user_time Pointer to receive user-mode CPU time in seconds.
 * @param sys_time Pointer to receive system-mode CPU time in seconds.
 */
WS_DLL_PUBLIC
void get_resource_usage(double *user_time, double *sys_time);

/**
 * @brief Logs the process CPU usage along with a formatted message.
 *
 * Prints the current user and system CPU times, and optionally resets the delta
 * used for tracking elapsed time between measurements.
 *
 * @param reset_delta If true, resets the delta timer after logging.
 * @param format Printf-style format string for the log message.
 * @param ... Arguments for the format string.
 */
WS_DLL_PUBLIC
void log_resource_usage(bool reset_delta, const char *format, ...);

/**
 * @brief Fetches the number of microseconds since the Unix epoch.
 *
 * Returns the current time as a 64-bit unsigned integer representing
 * microseconds since midnight (00:00:00), January 1, 1970 (UTC).
 *
 * @return The current timestamp in microseconds since the epoch.
 */
WS_DLL_PUBLIC
uint64_t create_timestamp(void);

/**
 * @brief Initializes or updates timezone settings.
 *
 * Calls the system-specific timezone setup routine (e.g., tzset()) to ensure
 * local time conversions reflect the current environment.
 */
WS_DLL_PUBLIC
void ws_tzset(void);

/**
 * @brief Retrieves the current real-time clock value.
 *
 * Fills the provided `timespec` structure with the current time from the system clock.
 *
 * @param ts Pointer to a `struct timespec` to receive the current time.
 * @return Pointer to the same `ts` structure, or NULL on failure.
 */
WS_DLL_PUBLIC
struct timespec *ws_clock_get_realtime(struct timespec *ts);

/**
 * @brief Converts a time value to local time.
 *
 * Thread-safe version of `localtime()`. Converts a `time_t` value to a `struct tm`
 * representing local time. The result is stored in the caller-provided buffer.
 *
 * @param timep Pointer to the time value to convert.
 * @param result Pointer to a `struct tm` to receive the result.
 * @return Pointer to `result`, or NULL on failure.
 */
WS_DLL_PUBLIC
struct tm *ws_localtime_r(const time_t *timep, struct tm *result);

/**
 * @brief Converts a time value to UTC (GMT).
 *
 * Thread-safe version of `gmtime()`. Converts a `time_t` value to a `struct tm`
 * representing UTC time. The result is stored in the caller-provided buffer.
 *
 * @param timep Pointer to the time value to convert.
 * @param result Pointer to a `struct tm` to receive the result.
 * @return Pointer to `result`, or NULL on failure.
 */
WS_DLL_PUBLIC
struct tm *ws_gmtime_r(const time_t *timep, struct tm *result);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TIME_UTIL_H__ */
