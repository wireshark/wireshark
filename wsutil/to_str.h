/** @file
 *
 * Definitions for utilities to convert various other types to strings.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WSUTIL_TO_STR_H__
#define __WSUTIL_TO_STR_H__

#include <wireshark.h>

#include <wsutil/wmem/wmem.h>
#include <wsutil/inet_addr.h>
#include <wsutil/nstime.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * guint8_to_hex()
 *
 * Output uint8_t hex representation to 'out', and return pointer after last character (out + 2).
 * It will always output full representation (padded with 0).
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least 2 bytes in the buffer.
 */
WS_DLL_PUBLIC char *guint8_to_hex(char *out, uint8_t val);

/**
 * word_to_hex()
 *
 * Output uint16_t hex representation to 'out', and return pointer after last character (out + 4).
 * It will always output full representation (padded with 0).
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least 4 bytes in the buffer.
 */
WS_DLL_PUBLIC char *word_to_hex(char *out, uint16_t word);

/**
 * word_to_hex_punct()
 *
 * Output uint16_t hex representation to 'out', and return pointer after last character.
 * Each byte will be separated with punct character (cannot be NUL).
 * It will always output full representation (padded with 0).
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least 5 bytes in the buffer.
 */
WS_DLL_PUBLIC char *word_to_hex_punct(char *out, uint16_t word, char punct);

/**
 * word_to_hex_npad()
 *
 * Output uint16_t hex representation to 'out', and return pointer after last character.
 * Value is not padded.
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least 4 bytes in the buffer.
 */
WS_DLL_PUBLIC char *word_to_hex_npad(char *out, uint16_t word);

/**
 * dword_to_hex()
 *
 * Output uint32_t hex representation to 'out', and return pointer after last character.
 * It will always output full representation (padded with 0).
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least 8 bytes in the buffer.
 */
WS_DLL_PUBLIC char *dword_to_hex(char *out, uint32_t dword);

/**
 * dword_to_hex_punct()
 *
 * Output uint32_t hex representation to 'out', and return pointer after last character.
 * Each byte will be separated with punct character (cannot be NUL).
 * It will always output full representation (padded with 0).
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least 11 bytes in the buffer.
 */
WS_DLL_PUBLIC char *dword_to_hex_punct(char *out, uint32_t dword, char punct);

/**
 * qword_to_hex()
 *
 * Output uint64_t hex representation to 'out', and return pointer after last character.
 * It will always output full representation (padded with 0).
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least 16 bytes in the buffer.
 */
WS_DLL_PUBLIC char *qword_to_hex(char *out, uint64_t qword);

/**
 * qword_to_hex_punct()
 *
 * Output uint64_t hex representation to 'out', and return pointer after last character.
 * Each byte will be separated with punct character (cannot be NUL).
 * It will always output full representation (padded with 0).
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least 22 bytes in the buffer.
 */
WS_DLL_PUBLIC char *qword_to_hex_punct(char *out, uint64_t qword, char punct);

/**
 * bytes_to_hexstr()
 *
 * Output hex representation of uint8_t array, and return pointer after last character.
 * It will always output full representation (padded with 0).
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least len * 2 bytes in the buffer.
 */
WS_DLL_PUBLIC char *bytes_to_hexstr(char *out, const uint8_t *ad, size_t len);

/**
 * bytes_to_hexstr_punct()
 *
 * Output hex representation of uint8_t array, and return pointer after last character.
 * Each byte will be separated with punct character (cannot be NUL).
 * It will always output full representation (padded with 0).
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least len * 3 - 1 bytes in the buffer.
 */
WS_DLL_PUBLIC char *bytes_to_hexstr_punct(char *out, const uint8_t *ad, size_t len, char punct);

/** Turn an array of bytes into a string showing the bytes in hex,
 *  separated by a punctuation character.
 *
 * @param scope memory allocation scheme used
 * @param buf A pointer to the byte array
 * @param buf_size The length of the byte array
 * @param punct The punctuation character
 * @param max_bytes_len Maximum number of bytes to represent, zero for no limit.
 * @return A pointer to the formatted string
 */
WS_DLL_PUBLIC char *bytes_to_str_punct_maxlen(wmem_allocator_t *scope,
                                const uint8_t *buf, size_t buf_size,
                                char punct, size_t max_bytes_len);

#define bytes_to_str_punct(scope, buf, buf_size, punct) \
    bytes_to_str_punct_maxlen(scope, buf, buf_size, punct, 24)

/** Turn an array of bytes into a string showing the bytes in hex.
 *
 * @param scope memory allocation scheme used
 * @param buf A pointer to the byte array
 * @param buf_size The length of the byte array
 * @param max_bytes_len Maximum number of bytes to represent, zero for no limit.
 * @return A pointer to the formatted string
 */
WS_DLL_PUBLIC char *bytes_to_str_maxlen(wmem_allocator_t *scope,
                                const uint8_t *buf, size_t buf_size,
                                size_t max_bytes_len);

#define bytes_to_str(scope, buf, buf_size) \
    bytes_to_str_maxlen(scope, buf, buf_size, 36)

/**
 * oct_to_str_back()
 *
 * Output uint32_t octal representation backward (last character will be written on ptr - 1),
 * and return pointer to first character.
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least 12 bytes in the buffer.
 */
WS_DLL_PUBLIC char *oct_to_str_back(char *ptr, uint32_t value);

/**
 * oct64_to_str_back()
 *
 * Output uint64_t octal representation backward (last character will be written on ptr - 1),
 * and return pointer to first character.
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least 12 bytes in the buffer.
 */
WS_DLL_PUBLIC char *oct64_to_str_back(char *ptr, uint64_t value);

/**
 * hex_to_str_back()
 *
 * Output uint32_t hex representation backward (last character will be written on ptr - 1),
 * and return pointer to first character.
 * This routine will output for sure (can output more) 'len' decimal characters (number padded with '0').
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least 2 + MAX(8, len) bytes in the buffer.
 */
WS_DLL_PUBLIC char *hex_to_str_back_len(char *ptr, uint32_t value, int len);

/**
 * hex64_to_str_back()
 *
 * Output uint64_t hex representation backward (last character will be written on ptr - 1),
 * and return pointer to first character.
 * This routine will output for sure (can output more) 'len' decimal characters (number padded with '0').
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least 2 + MAX(16, len) bytes in the buffer.
 */
WS_DLL_PUBLIC char *hex64_to_str_back_len(char *ptr, uint64_t value, int len);

/**
 * uint_to_str_back()
 *
 * Output uint32_t decimal representation backward (last character will be written on ptr - 1),
 * and return pointer to first character.
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least 10 bytes in the buffer.
 */
WS_DLL_PUBLIC char *uint_to_str_back(char *ptr, uint32_t value);

/**
 * uint64_str_back()
 *
 * Output uint64_t decimal representation backward (last character will be written on ptr - 1),
 * and return pointer to first character.
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least 20 bytes in the buffer.
 */
WS_DLL_PUBLIC char *uint64_to_str_back(char *ptr, uint64_t value);

/**
 * uint_to_str_back_len()
 *
 * Output uint32_t decimal representation backward (last character will be written on ptr - 1),
 * and return pointer to first character.
 * This routine will output for sure (can output more) 'len' decimal characters (number padded with '0').
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least MAX(10, len) bytes in the buffer.
 */
WS_DLL_PUBLIC char *uint_to_str_back_len(char *ptr, uint32_t value, int len);

/**
 * uint64_to_str_back_len()
 *
 * Output uint64_t decimal representation backward (last character will be written on ptr - 1),
 * and return pointer to first character.
 * This routine will output for sure (can output more) 'len' decimal characters (number padded with '0').
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least MAX(20, len) bytes in the buffer.
 */
WS_DLL_PUBLIC char *uint64_to_str_back_len(char *ptr, uint64_t value, int len);

/**
 * int_to_str_back()
 *
 * Output int32_t decimal representation backward (last character will be written on ptr - 1),
 * and return pointer to first character.
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least 11 bytes in the buffer.
 */
WS_DLL_PUBLIC char *int_to_str_back(char *ptr, int32_t value);

/**
 * int64_to_str_back()
 *
 * Output int64_t decimal representation backward (last character will be written on ptr - 1),
 * and return pointer to first character.
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least 21 bytes in the buffer.
 */
WS_DLL_PUBLIC char *int64_to_str_back(char *ptr, int64_t value);

WS_DLL_PUBLIC void guint32_to_str_buf(uint32_t u, char *buf, size_t buf_len);

WS_DLL_PUBLIC void guint64_to_str_buf(uint64_t u, char *buf, size_t buf_len);

WS_DEPRECATED_X("Use ip_num_to_str_buf() or ip_addr_to_str() instead")
WS_DLL_PUBLIC void ip_to_str_buf(const uint8_t *ad, char *buf, const int buf_len);

WS_DEPRECATED_X("Use ip_num_to_str() or ip_addr_to_str() instead")
WS_DLL_PUBLIC char *ip_to_str(wmem_allocator_t *scope, const uint8_t *ad);

/* Host byte order */
WS_DLL_PUBLIC void ip_num_to_str_buf(uint32_t ad, char *buf, const int buf_len);

/* Host byte order */
WS_DLL_PUBLIC char *ip_num_to_str(wmem_allocator_t *scope, uint32_t ad);

WS_DLL_PUBLIC void ip_addr_to_str_buf(const ws_in4_addr *ad, char *buf, const int buf_len);

WS_DLL_PUBLIC char *ip_addr_to_str(wmem_allocator_t *scope, const ws_in4_addr *ad);

WS_DLL_PUBLIC void ip6_to_str_buf(const ws_in6_addr *ad, char *buf, size_t buf_size);

WS_DLL_PUBLIC char *ip6_to_str(wmem_allocator_t *scope, const ws_in6_addr *ad);

WS_DLL_PUBLIC char *ipxnet_to_str_punct(wmem_allocator_t *scope, const uint32_t ad, const char punct);

WS_DLL_PUBLIC char *eui64_to_str(wmem_allocator_t *scope, const uint64_t ad);

WS_DLL_PUBLIC int format_fractional_part_nsecs(char *, size_t, uint32_t, const char *, int);

WS_DLL_PUBLIC void display_epoch_time(char *, size_t, const nstime_t *, int);

WS_DLL_PUBLIC void display_signed_time(char *, size_t, const nstime_t *, int);

WS_DLL_PUBLIC void format_nstime_as_iso8601(char *, size_t, const nstime_t *, char *, bool, int);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TO_STR_H__  */
