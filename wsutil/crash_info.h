/** @file
 * Routines to try to provide more useful information in crash dumps.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2006 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __CRASH_INFO_H__
#define __CRASH_INFO_H__

#include <wireshark.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Append formatted crash diagnostic information using a va_list.
 *
 * Adds a formatted message to the crash info log using a variable argument list.
 * This function is typically used internally when forwarding variadic arguments.
 *
 * @param fmt Format string (printf-style).
 * @param ap  va_list containing the arguments for the format string.
 */
WS_DLL_PUBLIC void ws_vadd_crash_info(const char *fmt, va_list ap);

/**
 * @brief Append formatted crash diagnostic information.
 *
 * Adds a formatted message to the crash info log. This is used to record
 * contextual information during a crash or fatal error, aiding in post-mortem
 * debugging and diagnostics.
 *
 * @param fmt Format string (printf-style).
 * @param ... Arguments corresponding to the format string.
 */
WS_DLL_PUBLIC void ws_add_crash_info(const char *fmt, ...)
    G_GNUC_PRINTF(1,2);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __CRASH_INFO_H__ */
