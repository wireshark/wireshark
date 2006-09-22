/* unicode-utils.c
 * Unicode utility routines
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

#ifdef _WIN32

#include <glib.h>
#include "unicode-utils.h"

#include <windows.h>
#include <tchar.h>
#include <wchar.h>

/** @file
 * Unicode utilities (internal interface)
 *
 * We define UNICODE and _UNICODE under Windows.  This means that
 * Windows SDK routines expect UTF-16 strings, in contrast to newer
 * versions of Glib and GTK+ which expect UTF-8.  This module provides
 * convenience routines for converting between UTF-8 and UTF-16.
 */

#define INITIAL_UTFBUF_SIZE 128

/*
 * XXX - Should we use g_utf8_to_utf16() and g_utf16_to_utf8()
 * instead?  The goal of the functions below was to provide simple
 * wrappers for UTF-8 <-> UTF-16 conversion without making the
 * caller worry about freeing up memory afterward.
 */

/* Convert from UTF-8 to UTF-16. */
wchar_t * utf_8to16(const char *utf8str) {
  static wchar_t *utf16buf[3];
  static int utf16buf_len[3];
  static int idx;

  if (utf8str == NULL)
    return NULL;

  idx = (idx + 1) % 3;

  /*
   * Allocate the buffer if it's not already allocated.
   */
  if (utf16buf[idx] == NULL) {
    utf16buf_len[idx] = INITIAL_UTFBUF_SIZE;
    utf16buf[idx] = g_malloc(utf16buf_len[idx] * sizeof(wchar_t));
  }

  while (MultiByteToWideChar(CP_UTF8, 0, utf8str,
      -1, NULL, 0) >= utf16buf_len[idx]) {
    /*
     * Double the buffer's size if it's not big enough.
     * The size of the buffer starts at 128, so doubling its size
     * adds at least another 128 bytes, which is more than enough
     * for one more character plus a terminating '\0'.
     */
    utf16buf_len[idx] *= 2;
    utf16buf[idx] = g_realloc(utf16buf[idx], utf16buf_len[idx] * sizeof(wchar_t));
  }

  if (MultiByteToWideChar(CP_UTF8, 0, utf8str,
      -1, utf16buf[idx], utf16buf_len[idx]) == 0)
    return NULL;

  return utf16buf[idx];
}

/* Convert from UTF-16 to UTF-8. */
gchar * utf_16to8(const wchar_t *utf16str) {
  static gchar *utf8buf[3];
  static int utf8buf_len[3];
  static int idx;

  if (utf16str == NULL)
    return NULL;

  idx = (idx + 1) % 3;

  /*
   * Allocate the buffer if it's not already allocated.
   */
  if (utf8buf[idx] == NULL) {
    utf8buf_len[idx] = INITIAL_UTFBUF_SIZE;
    utf8buf[idx] = g_malloc(utf8buf_len[idx]);
  }

  while (WideCharToMultiByte(CP_UTF8, 0, utf16str, -1,
      NULL, 0, NULL, NULL) >= utf8buf_len[idx]) {
    /*
     * Double the buffer's size if it's not big enough.
     * The size of the buffer starts at 128, so doubling its size
     * adds at least another 128 bytes, which is more than enough
     * for one more character plus a terminating '\0'.
     */
    utf8buf_len[idx] *= 2;
    utf8buf[idx] = g_realloc(utf8buf[idx], utf8buf_len[idx]);
  }

  if (WideCharToMultiByte(CP_UTF8, 0, utf16str, -1,
      utf8buf[idx], utf8buf_len[idx], NULL, NULL) == 0)
    return NULL;

  return utf8buf[idx];
}

#endif
