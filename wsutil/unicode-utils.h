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

/**
 * @brief Returns the length of a UTF-8 multibyte sequence from its first byte.
 *
 * Determines the expected number of bytes in a UTF-8 encoded code point
 * based on the leading byte. Returns 0 if the byte is invalid as a UTF-8 starter.
 *
 * @param ch The first byte of a UTF-8 sequence.
 * @return Length of the UTF-8 sequence (1–4), or 0 if invalid.
 */
#define ws_utf8_char_len(ch)  (ws_utf8_seqlen[(ch)])

/**
 * @brief Validates and sanitizes a UTF-8 byte sequence.
 *
 * Processes a raw byte string of length `length`, replacing any ill-formed
 * UTF-8 sequences with the Unicode REPLACEMENT CHARACTER (U+FFFD).
 * The result is allocated using the provided `wmem` scope.
 *
 * @param scope Memory allocator scope for the returned string.
 * @param ptr Pointer to the input byte sequence.
 * @param length Length of the input sequence.
 * @return Pointer to a valid UTF-8 string, allocated via `scope`.
 */
WS_DLL_PUBLIC uint8_t *
ws_utf8_make_valid(wmem_allocator_t *scope, const uint8_t *ptr, ssize_t length);

/**
 * @brief Validates a UTF-8 byte sequence and returns a string buffer.
 *
 * Similar to `ws_utf8_make_valid()`, but returns a `wmem_strbuf_t` object
 * for easier manipulation and appending. Ill-formed sequences are replaced
 * with the Unicode REPLACEMENT CHARACTER.
 *
 * @param scope Memory allocator scope for the returned buffer.
 * @param ptr Pointer to the input byte sequence.
 * @param length Length of the input sequence.
 * @return Pointer to a valid UTF-8 string buffer.
 */
WS_DLL_PUBLIC wmem_strbuf_t *
ws_utf8_make_valid_strbuf(wmem_allocator_t *scope, const uint8_t *ptr, ssize_t length);

#ifdef _WIN32

/**
 * @brief Given a UTF-8 string, convert it to UTF-16.  This is meant to be used
 * to convert between GTK+ 2.x (UTF-8) to Windows (UTF-16).
 *
 * @param utf8str The string to convert.  May be NULL.
 * @return The string converted to UTF-16.  If utf8str is NULL, returns
 * NULL.  The return value should NOT be freed by the caller.
 */
WS_DLL_PUBLIC
const wchar_t * utf_8to16(const char *utf8str);

/**
 * @brief Create a UTF-16 string (in place) according to the format string.
 *
 * @param utf16buf The buffer to return the UTF-16 string in.
 * @param utf16buf_len The size of the 'utf16buf' parameter
 * @param fmt A standard printf() format string
 */
WS_DLL_PUBLIC
void utf_8to16_snprintf(TCHAR *utf16buf, int utf16buf_len, const char* fmt, ...)
G_GNUC_PRINTF(3, 4);

/**
 * @brief Given a UTF-16 string, convert it to UTF-8.  This is meant to be used
 * to convert between GTK+ 2.x (UTF-8) to Windows (UTF-16).
 *
 * @param utf16str The string to convert.  May be NULL.
 * @return The string converted to UTF-8.  If utf16str is NULL, returns
 * NULL.  The return value should NOT be freed by the caller.
 */
WS_DLL_PUBLIC
char * utf_16to8(const wchar_t *utf16str);

/**
 * @brief Converts a UTF-16 argument list to UTF-8.
 *
 * Converts a program's command-line arguments from UTF-16 (typically used on Windows)
 * to UTF-8 encoding. This is useful for normalizing input at startup to ensure consistent
 * string handling across platforms and libraries.
 *
 * The returned array is allocated using standard memory allocation routines and must be
 * freed by the caller. Each string in the array is individually allocated.
 *
 * @param argc The number of arguments.
 * @param wc_argv Array of UTF-16 encoded argument strings.
 * @return Pointer to an array of UTF-8 encoded strings, or NULL on failure.
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
