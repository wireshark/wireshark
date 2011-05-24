/* unicode-utils.h
 * Unicode utility definitions
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2006 Gerald Combs
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __UNICODEUTIL_H__
#define __UNICODEUTIL_H__

#ifdef _WIN32

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <windows.h>
#include <tchar.h>
#include <wchar.h>

/**
 * @file Unicode convenience routines.
 */

/** Given a UTF-8 string, convert it to UTF-16.  This is meant to be used
 * to convert between GTK+ 2.x (UTF-8) to Windows (UTF-16).
 *
 * @param utf8str The string to convert.  May be NULL.
 * @return The string converted to UTF-16.  If utf8str is NULL, returns
 * NULL.  The return value should NOT be freed by the caller.
 */
wchar_t * utf_8to16(const char *utf8str);

/** Create a UTF-16 string (in place) according to the format string.
 *
 * @param utf16buf The buffer to return the UTF-16 string in.
 * @param utf16buf_len The size of the 'utf16buf' parameter
 * @param fmt A standard g_printf() format string
 */
void utf_8to16_snprintf(TCHAR *utf16buf, gint utf16buf_len, const gchar* fmt, ...);

/** Given a UTF-16 string, convert it to UTF-8.  This is meant to be used
 * to convert between GTK+ 2.x (UTF-8) to Windows (UTF-16).
 *
 * @param utf16str The string to convert.  May be NULL.
 * @return The string converted to UTF-8.  If utf16str is NULL, returns
 * NULL.  The return value should NOT be freed by the caller.
 */
gchar * utf_16to8(const wchar_t *utf16str);

/** Convert the program argument list from UTF-16 to UTF-8 and
 * store it in the supplied array. This is intended to be used
 * to normalize command line arguments at program startup.
 *
 * @param argc The number of arguments. You should simply pass the
 * first argument from main().
 * @param argv The argument values (vector). You should simply pass
 * the second argument from main().
 */
void arg_list_utf_16to8(int argc, char *argv[]);


#endif /* _WIN32 */

#endif /* __UNICODEUTIL_H__ */
