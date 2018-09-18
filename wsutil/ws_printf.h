/*
 * Wrappers for printf like functions.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2007 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WS_PRINTF_H__
#define __WS_PRINTF_H__

/*
 * GLib's string utility routines are slow on windows, likely due to calling
 * g_printf_string_upper_bound. Using ws_snprintf and ws_vsnprintf in hot
 * code paths can speed up program execution. Otherwise you're probably safe
 * sticking with g_snprintf and g_vsnprintf.
 */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef _WIN32
#include <strsafe.h>

/* The UCRT versions of snprintf and vsnprintf conform to C99 */

static __inline void
ws_vsnprintf(char *buffer, size_t size_of_buffer, const char *format, va_list argptr)
{
    vsnprintf(buffer, size_of_buffer, format, argptr);
}

#else /* _WIN32 */

#include <glib.h>

/*
 * Use g_vsnprintf. On Linux and macOS these should be a thin wrapper around
 * vsprintf.
 */

static inline void
ws_vsnprintf(char *buffer, size_t size_of_buffer, const char *format, va_list argptr)
{
    g_vsnprintf(buffer, (gulong) size_of_buffer, format, argptr);
}

#endif /* _WIN32 */

#ifdef _WIN32
static __inline void
#else
static inline void
#endif
ws_snprintf(char *buffer, size_t size_of_buffer, const char * format, ...) {
    va_list argptr;

    va_start(argptr, format);
    ws_vsnprintf(buffer, size_of_buffer, format, argptr);
    va_end(argptr);
}

/* This is intended to fool checkAPIs.pl for places that have "debugging"
(using printf) usually wrapped in an #ifdef, but checkAPIs.pl isn't smart
enough to figure that out.
Dissectors should still try to use proto_tree_add_debug_text when the
debugging context has a protocol tree.
*/
#define ws_debug_printf     printf

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WS_PRINTF_H__ */
