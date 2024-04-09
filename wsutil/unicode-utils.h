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

#include <wireshark.h>

#ifdef _WIN32
#include <windows.h>
#include <tchar.h>
#include <wchar.h>
#endif

/**
 * @file
 * Unicode convenience routines.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef WS_DEBUG_UTF_8
#define DEBUG_UTF_8_ENABLED true
#else
#define DEBUG_UTF_8_ENABLED false
#endif

#define _CHECK_UTF_8(level, str, len) \
    do {                                                                \
        const char *__uni_endptr;                                       \
        if (DEBUG_UTF_8_ENABLED && (str) != NULL &&                     \
                        !g_utf8_validate(str, len, &__uni_endptr)) {    \
            ws_log_utf8(str, len, __uni_endptr);                        \
        }                                                               \
    } while (0)

#define WS_UTF_8_CHECK(str, len) \
    _CHECK_UTF_8(LOG_LEVEL_DEBUG, str, len)

#define WS_UTF_8_DEBUG_HERE(str, len) \
    _CHECK_UTF_8(LOG_LEVEL_ECHO, str, len)

WSUTIL_EXPORT
const int ws_utf8_seqlen[256];

/** Given the first byte in an UTF-8 encoded code point,
 * return the length of the multibyte sequence, or *ZERO*
 * if the byte is invalid as the first byte in a multibyte
 * sequence.
 */
#define ws_utf8_char_len(ch)  (ws_utf8_seqlen[(ch)])

/*
 * Given a wmem scope, a pointer, and a length, treat the string of bytes
 * referred to by the pointer and length as a UTF-8 string, and return a
 * pointer to a UTF-8 string, allocated using the wmem scope, with all
 * ill-formed sequences replaced with the Unicode REPLACEMENT CHARACTER
 * according to the recommended "best practices" given in the Unicode
 * Standard and specified by W3C/WHATWG.
 */
WS_DLL_PUBLIC uint8_t *
ws_utf8_make_valid(wmem_allocator_t *scope, const uint8_t *ptr, ssize_t length);

/*
 * Same as ws_utf8_make_valid() but returns a wmem_strbuf_t.
 */
WS_DLL_PUBLIC wmem_strbuf_t *
ws_utf8_make_valid_strbuf(wmem_allocator_t *scope, const uint8_t *ptr, ssize_t length);

#ifdef _WIN32

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
 * @param fmt A standard printf() format string
 */
WS_DLL_PUBLIC
void utf_8to16_snprintf(TCHAR *utf16buf, int utf16buf_len, const char* fmt, ...)
G_GNUC_PRINTF(3, 4);

/** Given a UTF-16 string, convert it to UTF-8.  This is meant to be used
 * to convert between GTK+ 2.x (UTF-8) to Windows (UTF-16).
 *
 * @param utf16str The string to convert.  May be NULL.
 * @return The string converted to UTF-8.  If utf16str is NULL, returns
 * NULL.  The return value should NOT be freed by the caller.
 */
WS_DLL_PUBLIC
char * utf_16to8(const wchar_t *utf16str);

/** Convert the supplied program argument list from UTF-16 to UTF-8
 * return a pointer to the array of UTF-8 arguments. This is intended
 * to be used to normalize command line arguments at program startup.
 *
 * @param argc The number of arguments.
 * @param argv The argument values (vector).
 */
WS_DLL_PUBLIC
char **arg_list_utf_16to8(int argc, wchar_t *wc_argv[]);

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
