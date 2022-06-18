/** @file
 * String utility definitions
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __STR_UTIL_H__
#define __STR_UTIL_H__

#include <wireshark.h>
#include <wsutil/wmem/wmem.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

WS_DLL_PUBLIC
gchar *
wmem_strconcat(wmem_allocator_t *allocator, const gchar *first, ...)
G_GNUC_MALLOC G_GNUC_NULL_TERMINATED;

WS_DLL_PUBLIC
gchar *
wmem_strjoin(wmem_allocator_t *allocator,
             const gchar *separator, const gchar *first, ...)
G_GNUC_MALLOC G_GNUC_NULL_TERMINATED;

WS_DLL_PUBLIC
gchar *
wmem_strjoinv(wmem_allocator_t *allocator,
              const gchar *separator, gchar **str_array)
G_GNUC_MALLOC;

/**
 * Splits a string into a maximum of max_tokens pieces, using the given
 * delimiter. If max_tokens is reached, the remainder of string is appended
 * to the last token. Successive tokens are not folded and will instead result
 * in an empty string as element.
 *
 * If src or delimiter are NULL, or if delimiter is empty, this will return
 * NULL.
 *
 * Do not use with a NULL allocator, use g_strsplit instead.
 */
WS_DLL_PUBLIC
gchar **
wmem_strsplit(wmem_allocator_t *allocator, const gchar *src,
        const gchar *delimiter, int max_tokens);

/**
 * wmem_ascii_strdown:
 * Based on g_ascii_strdown
 * @param allocator  An enumeration of the different types of available allocators.
 * @param str a string.
 * @param len length of str in bytes, or -1 if str is nul-terminated.
 *
 * Converts all upper case ASCII letters to lower case ASCII letters.
 *
 * Return value: a newly-allocated string, with all the upper case
 *               characters in str converted to lower case, with
 *               semantics that exactly match g_ascii_tolower(). (Note
 *               that this is unlike the old g_strdown(), which modified
 *               the string in place.)
 **/
WS_DLL_PUBLIC
gchar*
wmem_ascii_strdown(wmem_allocator_t *allocator, const gchar *str, gssize len);

/** Convert all upper-case ASCII letters to their ASCII lower-case
 *  equivalents, in place, with a simple non-locale-dependent
 *  ASCII mapping (A-Z -> a-z).
 *  All other characters are left unchanged, as the mapping to
 *  lower case may be locale-dependent.
 *
 *  The string is assumed to be in a character encoding, such as
 *  an ISO 8859 or other EUC encoding, or UTF-8, in which all
 *  bytes in the range 0x00 through 0x7F are ASCII characters and
 *  non-ASCII characters are constructed from one or more bytes in
 *  the range 0x80 through 0xFF.
 *
 * @param str The string to be lower-cased.
 * @return    ptr to the string
 */
WS_DLL_PUBLIC
gchar *ascii_strdown_inplace(gchar *str);

/** Convert all lower-case ASCII letters to their ASCII upper-case
 *  equivalents, in place, with a simple non-locale-dependent
 *  ASCII mapping (a-z -> A-Z).
 *  All other characters are left unchanged, as the mapping to
 *  lower case may be locale-dependent.
 *
 *  The string is assumed to be in a character encoding, such as
 *  an ISO 8859 or other EUC encoding, or UTF-8, in which all
 *  bytes in the range 0x00 through 0x7F are ASCII characters and
 *  non-ASCII characters are constructed from one or more bytes in
 *  the range 0x80 through 0xFF.
 *
 * @param str The string to be upper-cased.
 * @return    ptr to the string
 */
WS_DLL_PUBLIC
gchar *ascii_strup_inplace(gchar *str);

/** Check if an entire string consists of printable characters
 *
 * @param str    The string to be checked
 * @return       TRUE if the entire string is printable, otherwise FALSE
 */
WS_DLL_PUBLIC
gboolean isprint_string(const gchar *str);

/** Given a not-necessarily-null-terminated string, expected to be in
 *  UTF-8 but possibly containing invalid sequences (as it may have come
 *  from packet data), and the length of the string, deterimine if the
 *  string is valid UTF-8 consisting entirely of printable characters.
 *
 *  This means that it:
 *
 *   does not contain an illegal UTF-8 sequence (including overlong encodings,
 *   the sequences reserved for UTF-16 surrogate halves, and the values for
 *   code points above U+10FFFF that are no longer in Unicode)
 *
 *   does not contain a non-printable Unicode character such as control
 *   characters (including internal NULL bytes)
 *
 *   does not end in a partial sequence that could begin a valid character;
 *
 *   does not start with a partial sequence that could end a valid character;
 *
 * and thus guarantees that the result of format_text() would be the same as
 * that of wmem_strndup() with the same parameters.
 *
 * @param str    The string to be checked
 * @param length The number of bytes to validate
 * @return       TRUE if the entire string is valid and printable UTF-8,
 *               otherwise FALSE
 */
WS_DLL_PUBLIC
gboolean isprint_utf8_string(const gchar *str, const guint length);

/** Check if an entire string consists of digits
 *
 * @param str    The string to be checked
 * @return       TRUE if the entire string is digits, otherwise FALSE
 */
WS_DLL_PUBLIC
gboolean isdigit_string(const guchar *str);

/** Finds the first occurrence of string 'needle' in string 'haystack'.
 *  The matching is done in a case insensitive manner.
 *
 * @param haystack The string possibly containing the substring
 * @param needle The substring to be searched
 * @return A pointer into 'haystack' where 'needle' is first found.
 *   Otherwise it returns NULL.
 */
WS_DLL_PUBLIC
const char *ws_strcasestr(const char *haystack, const char *needle);

WS_DLL_PUBLIC
char *ws_escape_string(wmem_allocator_t *alloc, const char *string, bool add_quotes);

WS_DLL_PUBLIC
char *ws_escape_string_len(wmem_allocator_t *alloc, const char *string, ssize_t len, bool add_quotes);

/* Replace null bytes with "\0". */
WS_DLL_PUBLIC
char *ws_escape_null(wmem_allocator_t *alloc, const char *string, size_t len, bool add_quotes);

WS_DLL_PUBLIC
int ws_xton(char ch);

typedef enum {
    FORMAT_SIZE_UNIT_NONE,          /**< No unit will be appended. You must supply your own. */
    FORMAT_SIZE_UNIT_BYTES,         /**< "bytes" for un-prefixed sizes, "B" otherwise. */
    FORMAT_SIZE_UNIT_BITS,          /**< "bits" for un-prefixed sizes, "b" otherwise. */
    FORMAT_SIZE_UNIT_BITS_S,        /**< "bits/s" for un-prefixed sizes, "bps" otherwise. */
    FORMAT_SIZE_UNIT_BYTES_S,       /**< "bytes/s" for un-prefixed sizes, "Bps" otherwise. */
    FORMAT_SIZE_UNIT_PACKETS,       /**< "packets" */
    FORMAT_SIZE_UNIT_PACKETS_S,     /**< "packets/s" */
} format_size_units_e;

#define FORMAT_SIZE_PREFIX_SI   (1 << 0)    /**< SI (power of 1000) prefixes will be used. */
#define FORMAT_SIZE_PREFIX_IEC  (1 << 1)    /**< IEC (power of 1024) prefixes will be used. */

/** Given a size, return its value in a human-readable format
 *
 * Prefixes up to "T/Ti" (tera, tebi) are currently supported.
 *
 * @param size The size value
 * @param flags Flags to control the output (unit of measurement,
 * SI vs IEC, etc). Unit and prefix flags may be ORed together.
 * @return A newly-allocated string representing the value.
 */
WS_DLL_PUBLIC
char *format_size_wmem(wmem_allocator_t *allocator, int64_t size,
                        format_size_units_e unit, uint16_t flags);

#define format_size(size, unit, flags) \
    format_size_wmem(NULL, size, unit, flags)

WS_DLL_PUBLIC
gchar printable_char_or_period(gchar c);

WS_DLL_PUBLIC WS_RETNONNULL
const char *ws_strerrorname_r(int errnum, char *buf, size_t buf_size);

WS_DLL_PUBLIC
char *ws_strdup_underline(wmem_allocator_t *allocator, long offset, size_t len);

/* To pass one of two strings, singular or plural */
#define plurality(d,s,p) ((d) == 1 ? (s) : (p))

#define true_or_false(val) ((val) ? "TRUE" : "FALSE")

#define string_or_null(val) ((val) ? (val) : "[NULL]")

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __STR_UTIL_H__ */
