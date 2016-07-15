/*
 * Wrappers for printf like functions.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2007 Gerald Combs
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

#if _MSC_VER < 1900
#include <stdarg.h>

/*
 * vsnprintf_s's return value isn't compatible with C99 vsnprintf. We don't
 * return anything in order to avoid confusion.
 */

static __inline void
ws_vsnprintf(char *buffer, size_t size_of_buffer, const char *format, va_list argptr) {
    /* We could alternatively use StringCchVPrintfA */
    vsnprintf_s(buffer, size_of_buffer, _TRUNCATE, format, argptr);
}

#else /* _MSC_VER uses UCRT */

/* The UCRT versions of snprintf and vsnprintf conform to C99 */

static __inline void
ws_vsnprintf(char *buffer, size_t size_of_buffer, const char *format, va_list argptr)
{
    vsnprintf(buffer, size_of_buffer, format, argptr);
}

#endif /* _MSC_VER */

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

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WS_PRINTF_H__ */
