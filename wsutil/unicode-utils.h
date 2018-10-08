/* unicode-utils.h
 * Unicode utility definitions
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2006 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __UNICODEUTIL_H__
#define __UNICODEUTIL_H__

#include "ws_symbol_export.h"

#include <glib.h>

/**
 * @file
 * Unicode convenience routines.
 */

#ifdef	__cplusplus
extern "C" {
#endif

WS_DLL_PUBLIC
int ws_utf8_char_len(guint8 ch);

#ifdef _WIN32

#include <windows.h>
#include <tchar.h>
#include <wchar.h>

/** Given a UTF-8 string, convert it to UTF-16.  This is meant to be used
 * to convert between GTK+ 2.x (UTF-8) to Windows (UTF-16).
 *
 * @param utf8str The string to convert.  May be NULL.
 * @return The string converted to UTF-16.  If utf8str is NULL, returns
 * NULL.  The return value should NOT be freed by the caller.
 */
WS_DLL_PUBLIC
const wchar_t * utf_8to16(const char *utf8str);

/** Create a UTF-16 string (in place) according to the format string.
 *
 * @param utf16buf The buffer to return the UTF-16 string in.
 * @param utf16buf_len The size of the 'utf16buf' parameter
 * @param fmt A standard g_printf() format string
 */
WS_DLL_PUBLIC
void utf_8to16_snprintf(TCHAR *utf16buf, gint utf16buf_len, const gchar* fmt,
	...) G_GNUC_PRINTF(3, 4);

/** Given a UTF-16 string, convert it to UTF-8.  This is meant to be used
 * to convert between GTK+ 2.x (UTF-8) to Windows (UTF-16).
 *
 * @param utf16str The string to convert.  May be NULL.
 * @return The string converted to UTF-8.  If utf16str is NULL, returns
 * NULL.  The return value should NOT be freed by the caller.
 */
WS_DLL_PUBLIC
gchar * utf_16to8(const wchar_t *utf16str);

/** Convert the supplied program argument list from UTF-16 to UTF-8
 * return a pointer to the array of UTF-8 arguments. This is intended
 * to be used to normalize command line arguments at program startup.
 *
 * @param argc The number of arguments.
 * @param argv The argument values (vector).
 */
WS_DLL_PUBLIC
char ** arg_list_utf_16to8(int argc, wchar_t *wc_argv[]);

#endif /* _WIN32 */

/*
 * defines for helping with UTF-16 surrogate pairs
 */

#define IS_LEAD_SURROGATE(uchar2) \
	((uchar2) >= 0xd800 && (uchar2) < 0xdc00)
#define IS_TRAIL_SURROGATE(uchar2) \
	((uchar2) >= 0xdc00 && (uchar2) < 0xe000)
#define SURROGATE_VALUE(lead, trail) \
	(((((lead) - 0xd800) << 10) | ((trail) - 0xdc00)) + 0x10000)

#ifdef	__cplusplus
}
#endif

#endif /* __UNICODEUTIL_H__ */
