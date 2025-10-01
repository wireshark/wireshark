/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WS_STRPTIME_H__
#define __WS_STRPTIME_H__

#include <wireshark.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @struct ws_timezone
 * @brief Portable representation of timezone offset and name.
 *
 * Provides a wrapper for the `tm_gmtoff` and `tm_zone` fields found in some
 * platform-specific implementations of `struct tm`. This struct is used to
 * pass timezone information on systems where these fields are not available
 * in the standard `struct tm`.
 *
 * @var tm_gmtoff  Offset from UTC in seconds.
 * @var tm_zone    Timezone abbreviation (e.g., "EST", "UTC").
 */
struct ws_timezone {
    long tm_gmtoff;
    const char *tm_zone;
};


/**
 * @brief Parse a date/time string using NetBSD's strptime() with the "C" locale.
 *
 * This function is a modified version of NetBSD's `strptime()`, adapted to
 * always use the "C" locale for consistent parsing behavior across platforms.
 * It converts the input string `buf` into broken-down time components stored
 * in `tm`, according to the format string `format`. If available, timezone
 * information is stored in the optional `zonep` structure.
 *
 * @param buf      Input string containing the date/time representation.
 * @param format   Format string specifying the expected structure of `buf`.
 * @param tm       Output structure to receive parsed time components.
 * @param zonep    Optional output for timezone offset and name (may be NULL).
 * @return         Pointer to the first character not processed, or NULL on failure.
 */
WS_DLL_PUBLIC
char *
ws_strptime(const char *buf, const char *format, struct tm *tm,
						struct ws_timezone *zonep);

/**
 * @brief Portable wrapper around the system's strptime().
 *
 * Provides a compatibility layer for parsing date/time strings using the system's
 * native `strptime()` implementation. This wrapper ensures consistent behavior across
 * platforms that support `strptime()`, without enforcing locale or timezone extensions.
 *
 * @param buf      Input string containing the date/time representation.
 * @param format   Format string specifying the expected structure of `buf`.
 * @param tm       Output structure to receive parsed time components.
 * @return         Pointer to the first character not processed, or NULL on failure.
 */
WS_DLL_PUBLIC
char *
ws_strptime_p(const char *buf, const char *format, struct tm *tm);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WS_STRPTIME_H__ */
