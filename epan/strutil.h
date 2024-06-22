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
const unsigned char *find_line_end(const unsigned char *data, const unsigned char *dataend,
    const unsigned char **eol);

/** Get the length of the next token in a line, and the beginning of the
 *  next token after that (if any).
 * @param linep A pointer to the beginning of the line
 * @param lineend A pointer to the end of the line
 * @param next_token Receives the location of the next token
 * @return 0 if there is no next token.
 */
WS_DLL_PUBLIC
int        get_token_len(const unsigned char *linep, const unsigned char *lineend,
    const unsigned char **next_token);

/** Turn a string of hex digits with optional separators (defined by
 *  is_byte_sep() into a byte array.
 *
 * @param hex_str The string of hex digits.
 * @param bytes The GByteArray that will receive the bytes.  This
 *        must be initialized by the caller.
 * @param force_separators If set to true, separators MUST exist between
 *        bytes.
 * @return True if the string was converted successfully
 */
WS_DLL_PUBLIC
bool       hex_str_to_bytes(const char *hex_str, GByteArray *bytes,
    bool force_separators);

/* Turn a string of hex digits with optional separators (defined by encoding)
 * into a byte array. Unlike hex_str_to_bytes(), this will read as many hex-char
 * pairs as possible and not error if it hits a non-hex-char; instead it just ends
 * there. (i.e., like strtol()/atoi()/etc.) But it must see two hex chars at the
 * beginning or it will return false.
 *
 * @param hex_str The string of hex digits.
 * @param bytes The GByteArray that will receive the bytes.  This
 *        must be initialized by the caller.
 * @param endptr if not NULL, is set to the char after the last hex character consumed.
 * @param encoding set to one or more bitwise-or'ed ENC_SEP_* (see proto.h)
 * @param fail_if_partial If set to true, then the conversion fails if the whole
 *    hex_str is not consumed.
 * @return false only if no bytes were generated; or if fail_if_partial is true
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
bool hex_str_to_bytes_encoding(const char *hex_str, GByteArray *bytes, const char **endptr,
                                   const unsigned encoding, const bool fail_if_partial);

/** Turn an RFC 3986 percent-encoded array of characters, not necessarily
 * null-terminated, into a byte array.
 *
 * @param uri_str The string of hex digits.
 * @param bytes The GByteArray that will receive the bytes.  This
 *        must be initialized by the caller.
 * @return True if the string was converted successfully
 */
WS_DLL_PUBLIC
bool       uri_to_bytes(const char *uri_str, GByteArray *bytes, size_t len);

/** Turn an RFC 3986 percent-encoded string into a byte array.
 *
 * @param uri_str The string of hex digits.
 * @param bytes The GByteArray that will receive the bytes.  This
 *        must be initialized by the caller.
 * @return True if the string was converted successfully
 */
WS_DLL_PUBLIC
bool       uri_str_to_bytes(const char *uri_str, GByteArray *bytes);

/** Turn a OID string representation (dot notation) into a byte array.
 *
 * @param oid_str The OID string (dot notaion).
 * @param bytes The GByteArray that will receive the bytes.  This
 *        must be initialized by the caller.
 * @param is_absolute True if this is an absolute OID; false for relative OID.
 * @return True if the string was converted successfully
 */
WS_DLL_PUBLIC
bool       rel_oid_str_to_bytes(const char *oid_str, GByteArray *bytes, bool is_absolute);

/** Turn a OID string representation (dot notation) into a byte array.
 *
 * @param oid_str The OID string (dot notaion).
 * @param bytes The GByteArray that will receive the bytes.  This
 *        must be initialized by the caller.
 * @return True if the string was converted successfully
 */
WS_DLL_PUBLIC
bool       oid_str_to_bytes(const char *oid_str, GByteArray *bytes);

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
 *         their contents are equal, returns true.  Otherwise, returns
 *         false.
 *
 * @todo - Should this be in strutil.c?
 */
WS_DLL_PUBLIC
bool byte_array_equal(GByteArray *ba1, GByteArray *ba2);


/** Return a XML escaped representation of the unescaped string.
 *  The returned string must be freed when no longer in use.
 *
 * @param unescaped The unescaped string
 * @return An XML-escaped representation of the input string
 */
WS_DLL_PUBLIC
char*     xml_escape(const char *unescaped);

/** Scan a string to make sure it's valid hex.
 *
 * @param string The string to validate
 * @param nbytes The length of the return buffer
 * @return A pointer to a buffer containing the converted raw bytes.  This
 *         buffer must be g_free()d by the caller.
 */
WS_DLL_PUBLIC
uint8_t * convert_string_to_hex(const char *string, size_t *nbytes);

/** Prep a string for case-sensitive vs case-insensitive searching.
 *
 * @param string The search string
 * @param case_insensitive true if case-insensitive, false if not
 * @return A direct copy of the string if it's a case-sensitive search and
 * an uppercased version if not.  In either case the string must be g_free()d
 * by the caller.
 */
WS_DLL_PUBLIC
char * convert_string_case(const char *string, bool case_insensitive);

WS_DLL_PUBLIC
void IA5_7BIT_decode(unsigned char * dest, const unsigned char* src, int len);

#define FORMAT_LABEL_REPLACE_SPACE      (0x1 << 0)

WS_DLL_PUBLIC
size_t ws_label_strcpy(char *label_str, size_t bufsize, size_t pos, const uint8_t *str, int flags);

WS_DLL_PUBLIC
size_t ws_label_strcat(char *label_str, size_t bufsize, const uint8_t *str, int flags);

/*
 * Check name is valid. This covers names for display filter fields, dissector
 * tables, preference modules, etc. Lower case is preferred.
 */
WS_DLL_LOCAL unsigned char
module_check_valid_name(const char *name, bool lower_only);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __STRUTIL_H__ */
