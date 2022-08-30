/* strutil.h
 * String utility definitions
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __STRUTIL_H__
#define __STRUTIL_H__

#include "ws_symbol_export.h"

#include <epan/wmem_scopes.h>
#include <wsutil/str_util.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file
 * String handling and conversion utilities.
 */

/** Given a pointer into a data buffer, and to the end of the buffer,
 *  find the end of the (putative) line at that position in the data
 *  buffer.
 *
 * @param data A pointer to the beginning of the data
 * @param dataend A pointer to the end of the data
 * @param eol A pointer that will receive the EOL location
 * @return A pointer to the EOL character(s) in "*eol".
 */
const guchar *find_line_end(const guchar *data, const guchar *dataend,
    const guchar **eol);

/** Get the length of the next token in a line, and the beginning of the
 *  next token after that (if any).
 * @param linep A pointer to the beginning of the line
 * @param lineend A pointer to the end of the line
 * @param next_token Receives the location of the next token
 * @return 0 if there is no next token.
 */
WS_DLL_PUBLIC
int        get_token_len(const guchar *linep, const guchar *lineend,
    const guchar **next_token);

/** Given a wmem scope, a not-necessarily-null-terminated string,
 *  expected to be in UTF-8 but possibly containing invalid sequences
 *  (as it may have come from packet data), and the length of the string,
 *  generate a valid UTF-8 string from it, allocated in the specified
 *  wmem scope, that:
 *
 *   shows printable Unicode characters as themselves;
 *
 *   shows non-printable ASCII characters as C-style escapes (octal
 *   if not one of the standard ones such as LF -> '\n');
 *
 *   shows non-printable Unicode-but-not-ASCII characters as
 *   their universal character names;
 *
 *   shows illegal UTF-8 sequences as a sequence of bytes represented
 *   as C-style hex escapes;
 *
 *  and return a pointer to it.
 *
 * @param allocator The wmem scope
 * @param string A pointer to the input string
 * @param len The length of the input string
 * @return A pointer to the formatted string
 *
 * @see tvb_format_text()
 */
WS_DLL_PUBLIC
gchar*     format_text(wmem_allocator_t* allocator, const guchar *string, size_t len);

/** Given a wmem scope and a null-terminated string, expected to be in
 *  UTF-8 but possibly containing invalid sequences (as it may have come
 *  from packet data), and the length of the string, generate a valid
 *  UTF-8 string from it, allocated in the specified wmem scope, that:
 *
 *   shows printable Unicode characters as themselves;
 *
 *   shows non-printable ASCII characters as C-style escapes (octal
 *   if not one of the standard ones such as LF -> '\n');
 *
 *   shows non-printable Unicode-but-not-ASCII characters as
 *   their universal character names;
 *
 *   shows illegal UTF-8 sequences as a sequence of bytes represented
 *   as C-style hex escapes;
 *
 *  and return a pointer to it.
 *
 * @param allocator The wmem scope
 * @param string A pointer to the input string
 * @return A pointer to the formatted string
 *
 * @see tvb_format_text()
 */
WS_DLL_PUBLIC
gchar*     format_text_string(wmem_allocator_t* allocator, const guchar *string);

/**
 * Given a string, generate a string from it that shows non-printable
 * characters as C-style escapes except a whitespace character
 * (space, tab, carriage return, new line, vertical tab, or formfeed)
 * which will be replaced by a space, and return a pointer to it.
 *
 * @param allocator The wmem scope
 * @param line A pointer to the input string
 * @param len The length of the input string
 * @return A pointer to the formatted string
 *
 */
WS_DLL_PUBLIC
gchar*     format_text_wsp(wmem_allocator_t* allocator, const guchar *line, size_t len);

/**
 * Given a string, generate a string from it that shows non-printable
 * characters as the chr parameter passed, except a whitespace character
 * (space, tab, carriage return, new line, vertical tab, or formfeed)
 * which will be replaced by a space, and return a pointer to it.
 *
 * @param allocator The wmem scope
 * @param string A pointer to the input string
 * @param len The length of the input string
 * @param chr The character to use to replace non-printable characters
 * @return A pointer to the formatted string
 *
 */
WS_DLL_PUBLIC
char *format_text_chr(wmem_allocator_t *allocator,
                        const char *string, size_t len, char chr);


/** Turn a string of hex digits with optional separators (defined by
 *  is_byte_sep() into a byte array.
 *
 * @param hex_str The string of hex digits.
 * @param bytes The GByteArray that will receive the bytes.  This
 *        must be initialized by the caller.
 * @param force_separators If set to TRUE, separators MUST exist between
 *        bytes.
 * @return True if the string was converted successfully
 */
WS_DLL_PUBLIC
gboolean   hex_str_to_bytes(const char *hex_str, GByteArray *bytes,
    gboolean force_separators);

/* Turn a string of hex digits with optional separators (defined by encoding)
 * into a byte array. Unlike hex_str_to_bytes(), this will read as many hex-char
 * pairs as possible and not error if it hits a non-hex-char; instead it just ends
 * there. (i.e., like strtol()/atoi()/etc.) But it must see two hex chars at the
 * beginning or it will return FALSE.
 *
 * @param hex_str The string of hex digits.
 * @param bytes The GByteArray that will receive the bytes.  This
 *        must be initialized by the caller.
 * @param endptr if not NULL, is set to the char after the last hex character consumed.
 * @param encoding set to one or more bitwise-or'ed ENC_SEP_* (see proto.h)
 * @param fail_if_partial If set to TRUE, then the conversion fails if the whole
 *    hex_str is not consumed.
 * @return FALSE only if no bytes were generated; or if fail_if_partial is TRUE
 *    and the entire hex_str was not consumed.
 *
 * If no ENC_SEP_* is set, then no separators are allowed. If multiple ENC_SEP_* are
 * bit-or'ed, any of them can be a separator, but once the separator is seen then
 * only its same type is accepted for the rest of the string. (i.e., it won't convert
 * a "01:23-4567" even if ENC_SEP_COLON|ENC_SEP_DASH|ENC_SEP_NONE is passed in)
 *
 * This is done this way because it's likely a malformed scenario if they're mixed,
 * and this routine is used by dissectors via tvb_get_string_XXX routines.
 */
WS_DLL_PUBLIC
gboolean hex_str_to_bytes_encoding(const char *hex_str, GByteArray *bytes, const char **endptr,
                                   const guint encoding, const gboolean fail_if_partial);

/** Turn an RFC 3986 percent-encoded array of characters, not necessarily
 * null-terminated, into a byte array.
 *
 * @param uri_str The string of hex digits.
 * @param bytes The GByteArray that will receive the bytes.  This
 *        must be initialized by the caller.
 * @return True if the string was converted successfully
 */
WS_DLL_PUBLIC
gboolean   uri_to_bytes(const char *uri_str, GByteArray *bytes, size_t len);

/** Turn an RFC 3986 percent-encoded string into a byte array.
 *
 * @param uri_str The string of hex digits.
 * @param bytes The GByteArray that will receive the bytes.  This
 *        must be initialized by the caller.
 * @param len The length of the input string
 * @return True if the string was converted successfully
 */
WS_DLL_PUBLIC
gboolean   uri_str_to_bytes(const char *uri_str, GByteArray *bytes);

/** Turn a OID string representation (dot notation) into a byte array.
 *
 * @param oid_str The OID string (dot notaion).
 * @param bytes The GByteArray that will receive the bytes.  This
 *        must be initialized by the caller.
 * @param is_absolute True if this is an absolute OID; false for relative OID.
 * @return True if the string was converted successfully
 */
WS_DLL_PUBLIC
gboolean   rel_oid_str_to_bytes(const char *oid_str, GByteArray *bytes, gboolean is_absolute);

/** Turn a OID string representation (dot notation) into a byte array.
 *
 * @param oid_str The OID string (dot notaion).
 * @param bytes The GByteArray that will receive the bytes.  This
 *        must be initialized by the caller.
 * @return True if the string was converted successfully
 */
WS_DLL_PUBLIC
gboolean   oid_str_to_bytes(const char *oid_str, GByteArray *bytes);

/**
 * Create a copy of a GByteArray
 *
 * @param ba The byte array to be copied.
 * @return If ba exists, a freshly allocated copy.  NULL otherwise.
 *
 * @todo - Should this be in strutil.c?
 */
WS_DLL_PUBLIC
GByteArray *byte_array_dup(const GByteArray *ba);

/**
 * Compare the contents of two GByteArrays
 *
 * @param ba1 A byte array
 * @param ba2 A byte array
 * @return If both arrays are non-NULL and their lengths are equal and
 *         their contents are equal, returns TRUE.  Otherwise, returns
 *         FALSE.
 *
 * @todo - Should this be in strutil.c?
 */
WS_DLL_PUBLIC
gboolean byte_array_equal(GByteArray *ba1, GByteArray *ba2);


/** Return a XML escaped representation of the unescaped string.
 *  The returned string must be freed when no longer in use.
 *
 * @param unescaped The unescaped string
 * @return An XML-escaped representation of the input string
 */
WS_DLL_PUBLIC
gchar*     xml_escape(const gchar *unescaped);

/** Scan a string to make sure it's valid hex.
 *
 * @param string The string to validate
 * @param nbytes The length of the return buffer
 * @return A pointer to a buffer containing the converted raw bytes.  This
 *         buffer must be g_free()d by the caller.
 */
WS_DLL_PUBLIC
guint8 * convert_string_to_hex(const char *string, size_t *nbytes);

/** Prep a string for case-sensitive vs case-insensitive searching.
 *
 * @param string The search string
 * @param case_insensitive TRUE if case-insensitive, FALSE if not
 * @return A direct copy of the string if it's a case-sensitive search and
 * an uppercased version if not.  In either case the string must be g_free()d
 * by the caller.
 */
WS_DLL_PUBLIC
char * convert_string_case(const char *string, gboolean case_insensitive);

WS_DLL_PUBLIC
void IA5_7BIT_decode(unsigned char * dest, const unsigned char* src, int len);

/*
 * Check name is valid. This covers names for display filter fields, dissector
 * tables, preference modules, etc. Lower case is preferred.
 */
WS_DLL_LOCAL guchar
module_check_valid_name(const char *name, gboolean lower_only);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __STRUTIL_H__ */
