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
 * uint8_to_hex()
 *
 * Output uint8_t hex representation to 'out', and return pointer after last character (out + 2).
 * It will always output full representation (padded with 0).
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least 2 bytes in the buffer.
 */
WS_DLL_PUBLIC char *uint8_to_hex(char *out, uint8_t val);

WS_DEPRECATED_X("Use uint8_to_hex instead")
static inline char *guint8_to_hex(char *out, uint8_t val) { return uint8_to_hex(out, val); }

/**
 * @brief Converts a 16-bit word to a fixed-width hexadecimal string.
 *
 * Writes the hexadecimal representation of a `uint16_t` value to the provided buffer.
 * The output is always 4 characters long, zero-padded if necessary (e.g., `0x000A` → `"000A"`).
 * The result is not NUL-terminated, and the caller must ensure the buffer has at least 4 bytes.
 *
 * @param out Pointer to the destination buffer (must have space for at least 4 characters).
 * @param word The 16-bit value to convert.
 * @return Pointer to the position immediately after the last written character (`out + 4`).
 */
WS_DLL_PUBLIC char *word_to_hex(char *out, uint16_t word);

/**
 * @brief Converts a 16-bit word to a hexadecimal string with byte-level punctuation.
 *
 * Writes the hexadecimal representation of a `uint16_t` value to the provided buffer,
 * inserting the specified punctuation character between the high and low bytes.
 * The output is always 5 characters long (e.g., `"12:34"` for `0x1234` with `':'`).
 * The result is not NUL-terminated, and the caller must ensure the buffer has at least 5 bytes.
 *
 * @param out Pointer to the destination buffer (must have space for at least 5 characters).
 * @param word The 16-bit value to convert.
 * @param punct The punctuation character to insert between bytes (must not be NUL).
 * @return Pointer to the position immediately after the last written character (`out + 5`).
 */
WS_DLL_PUBLIC char *word_to_hex_punct(char *out, uint16_t word, char punct);

/**
 * @brief Converts a 16-bit word to a hexadecimal string without padding.
 *
 * Writes the hexadecimal representation of a `uint16_t` value to the provided buffer.
 * The output is not zero-padded and is not NUL-terminated.
 * The caller must ensure the buffer has at least 4 bytes.
 *
 * @param out Pointer to the destination buffer.
 * @param word The 16-bit value to convert.
 * @return Pointer to the position immediately after the last written character.
 */
WS_DLL_PUBLIC char *word_to_hex_npad(char *out, uint16_t word);

/**
 * @brief Converts a 32-bit word to a fixed-width hexadecimal string.
 *
 * Writes the zero-padded 8-character hexadecimal representation of a `uint32_t` value
 * to the provided buffer. The result is not NUL-terminated.
 * The caller must ensure the buffer has at least 8 bytes.
 *
 * @param out Pointer to the destination buffer.
 * @param dword The 32-bit value to convert.
 * @return Pointer to the position immediately after the last written character.
 */
WS_DLL_PUBLIC char *dword_to_hex(char *out, uint32_t dword);

/**
 * @brief Converts a 32-bit word to a hexadecimal string with punctuation.
 *
 * Writes the hexadecimal representation of a `uint32_t` value to the buffer,
 * inserting the specified punctuation character between each byte.
 * The output is always 11 characters long and not NUL-terminated.
 * The caller must ensure the buffer has at least 11 bytes.
 *
 * @param out Pointer to the destination buffer.
 * @param dword The 32-bit value to convert.
 * @param punct The punctuation character to insert (must not be NUL).
 * @return Pointer to the position immediately after the last written character.
 */
WS_DLL_PUBLIC char *dword_to_hex_punct(char *out, uint32_t dword, char punct);

/**
 * @brief Converts a 64-bit word to a fixed-width hexadecimal string.
 *
 * Writes the zero-padded 16-character hexadecimal representation of a `uint64_t` value
 * to the provided buffer. The result is not NUL-terminated.
 * The caller must ensure the buffer has at least 16 bytes.
 *
 * @param out Pointer to the destination buffer.
 * @param qword The 64-bit value to convert.
 * @return Pointer to the position immediately after the last written character.
 */
WS_DLL_PUBLIC char *qword_to_hex(char *out, uint64_t qword);

/**
 * @brief Converts a 64-bit word to a hexadecimal string with punctuation.
 *
 * Writes the hexadecimal representation of a `uint64_t` value to the buffer,
 * inserting the specified punctuation character between each byte.
 * The output is always 22 characters long and not NUL-terminated.
 * The caller must ensure the buffer has at least 22 bytes.
 *
 * @param out Pointer to the destination buffer.
 * @param qword The 64-bit value to convert.
 * @param punct The punctuation character to insert (must not be NUL).
 * @return Pointer to the position immediately after the last written character.
 */
WS_DLL_PUBLIC char *qword_to_hex_punct(char *out, uint64_t qword, char punct);

/**
 * @brief Converts a byte array to a hexadecimal string.
 *
 * Writes the hexadecimal representation of a byte array to the provided buffer.
 * Each byte is represented by two hex characters. The result is not NUL-terminated.
 * The caller must ensure the buffer has at least `len * 2` bytes.
 *
 * @param out Pointer to the destination buffer.
 * @param ad Pointer to the byte array.
 * @param len Number of bytes in the array.
 * @return Pointer to the position immediately after the last written character.
 */
WS_DLL_PUBLIC char *bytes_to_hexstr(char *out, const uint8_t *ad, size_t len);

/**
 * @brief Converts a byte array to a hexadecimal string with punctuation.
 *
 * Writes the hexadecimal representation of a byte array to the provided buffer,
 * inserting the specified punctuation character between each byte.
 * Each byte is represented by two hex digits, and the output is not NUL-terminated.
 * The caller must ensure the buffer has at least `(len * 3) - 1` bytes.
 *
 * Example: For input `{0xAB, 0xCD, 0xEF}` and `punct = ':'`, the output will be `"AB:CD:EF"`.
 *
 * @param out Pointer to the destination buffer.
 * @param ad Pointer to the byte array to convert.
 * @param len Number of bytes in the array.
 * @param punct The punctuation character to insert between bytes (must not be NUL).
 * @return Pointer to the position immediately after the last written character.
 */
WS_DLL_PUBLIC char *bytes_to_hexstr_punct(char *out, const uint8_t *ad, size_t len, char punct);

/**
 * @brief Turn an array of bytes into a string showing the bytes in hex,
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

/**
 * @brief Turn an array of bytes into a string showing the bytes in hex.
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
 * @brief Converts a 32-bit unsigned integer to octal string in reverse.
 *
 * Writes the octal representation of `value` backward into the buffer,
 * ending at `ptr - 1`, and returns a pointer to the first character written.
 * The result is not NUL-terminated.
 *
 * @param ptr Pointer to the end of the buffer (last character will be written at `ptr - 1`).
 * @param value The 32-bit unsigned integer to convert.
 * @return Pointer to the first character of the written octal string.
 */
WS_DLL_PUBLIC char *oct_to_str_back(char *ptr, uint32_t value);

/**
 * @brief Converts a 64-bit unsigned integer to octal string in reverse.
 *
 * Writes the octal representation of `value` backward into the buffer,
 * ending at `ptr - 1`, and returns a pointer to the first character written.
 * The result is not NUL-terminated.
 *
 * @param ptr Pointer to the end of the buffer (last character will be written at `ptr - 1`).
 * @param value The 64-bit unsigned integer to convert.
 * @return Pointer to the first character of the written octal string.
 */
WS_DLL_PUBLIC char *oct64_to_str_back(char *ptr, uint64_t value);

/**
 * @brief Converts a 32-bit unsigned integer to hex string in reverse with fixed length.
 *
 * Writes the hexadecimal representation of `value` backward into the buffer,
 * ending at `ptr - 1`, and returns a pointer to the first character written.
 * The output is zero-padded to at least `len` characters.
 * The result is not NUL-terminated.
 *
 * @param ptr Pointer to the end of the buffer.
 * @param value The 32-bit unsigned integer to convert.
 * @param len Minimum number of hex digits to output.
 * @return Pointer to the first character of the written hex string.
 */
WS_DLL_PUBLIC char *hex_to_str_back_len(char *ptr, uint32_t value, int len);

/**
 * @brief Converts a 64-bit unsigned integer to hex string in reverse with fixed length.
 *
 * Writes the hexadecimal representation of `value` backward into the buffer,
 * ending at `ptr - 1`, and returns a pointer to the first character written.
 * The output is zero-padded to at least `len` characters.
 * The result is not NUL-terminated.
 *
 * @param ptr Pointer to the end of the buffer.
 * @param value The 64-bit unsigned integer to convert.
 * @param len Minimum number of hex digits to output.
 * @return Pointer to the first character of the written hex string.
 */
WS_DLL_PUBLIC char *hex64_to_str_back_len(char *ptr, uint64_t value, int len);

/**
 * @brief Converts a 32-bit unsigned integer to decimal string in reverse.
 *
 * Writes the decimal representation of `value` backward into the buffer,
 * ending at `ptr - 1`, and returns a pointer to the first character written.
 * The result is not NUL-terminated.
 *
 * @param ptr Pointer to the end of the buffer.
 * @param value The 32-bit unsigned integer to convert.
 * @return Pointer to the first character of the written decimal string.
 */
WS_DLL_PUBLIC char *uint_to_str_back(char *ptr, uint32_t value);

/**
 * @brief Converts a 64-bit unsigned integer to a decimal string in reverse.
 *
 * Writes the decimal representation of `value` backward into the buffer,
 * ending at `ptr - 1`, and returns a pointer to the first character written.
 * The result is not NUL-terminated.
 *
 * @param ptr Pointer to the end of the buffer.
 * @param value The 64-bit unsigned integer to convert.
 * @return Pointer to the first character of the written decimal string.
 */
WS_DLL_PUBLIC char *uint64_to_str_back(char *ptr, uint64_t value);

/**
 * @brief Converts a 32-bit unsigned integer to a zero-padded decimal string in reverse.
 *
 * Writes the decimal representation of `value` backward into the buffer,
 * ending at `ptr - 1`, and returns a pointer to the first character written.
 * The output is padded with zeros to ensure at least `len` digits.
 * The result is not NUL-terminated.
 *
 * @param ptr Pointer to the end of the buffer.
 * @param value The 32-bit unsigned integer to convert.
 * @param len Minimum number of decimal digits to output.
 * @return Pointer to the first character of the written decimal string.
 */
WS_DLL_PUBLIC char *uint_to_str_back_len(char *ptr, uint32_t value, int len);

/**
 * @brief Converts a 64-bit unsigned integer to a zero-padded decimal string in reverse.
 *
 * Writes the decimal representation of `value` backward into the buffer,
 * ending at `ptr - 1`, and returns a pointer to the first character written.
 * The output is padded with zeros to ensure at least `len` digits.
 * The result is not NUL-terminated.
 *
 * @param ptr Pointer to the end of the buffer.
 * @param value The 64-bit unsigned integer to convert.
 * @param len Minimum number of decimal digits to output.
 * @return Pointer to the first character of the written decimal string.
 */
WS_DLL_PUBLIC char *uint64_to_str_back_len(char *ptr, uint64_t value, int len);

/**
 * @brief Converts a 32-bit signed integer to a decimal string in reverse.
 *
 * Writes the decimal representation of `value` backward into the buffer,
 * ending at `ptr - 1`, and returns a pointer to the first character written.
 * Handles negative values by prepending a minus sign.
 * The result is not NUL-terminated.
 *
 * @param ptr Pointer to the end of the buffer.
 * @param value The 32-bit signed integer to convert.
 * @return Pointer to the first character of the written decimal string.
 */
WS_DLL_PUBLIC char *int_to_str_back(char *ptr, int32_t value);

/**
 * @brief Converts a 64-bit signed integer to a decimal string in reverse.
 *
 * Writes the decimal representation of `value` backward into the buffer,
 * ending at `ptr - 1`, and returns a pointer to the first character written.
 * Handles negative values by prepending a minus sign.
 * The result is not NUL-terminated.
 *
 * @param ptr Pointer to the end of the buffer.
 * @param value The 64-bit signed integer to convert.
 * @return Pointer to the first character of the written decimal string.
 */
WS_DLL_PUBLIC char *int64_to_str_back(char *ptr, int64_t value);

/**
 * @brief Converts a 32-bit unsigned integer to a decimal string.
 *
 * Writes the decimal representation of `u` into the provided buffer.
 * The output is NUL-terminated and truncated if it exceeds `buf_len - 1` characters.
 *
 * @param u The 32-bit unsigned integer to convert.
 * @param buf Pointer to the destination buffer.
 * @param buf_len Size of the destination buffer, including space for the NUL terminator.
 */
WS_DLL_PUBLIC void uint32_to_str_buf(uint32_t u, char *buf, size_t buf_len);

WS_DEPRECATED_X("Use uint32_to_str_buf instead")
static inline void guint32_to_str_buf(uint32_t u, char *buf, size_t buf_len) { uint32_to_str_buf(u, buf, buf_len); }

/**
 * @brief Converts a 64-bit unsigned integer to a decimal string.
 *
 * Writes the decimal representation of `u` into the provided buffer.
 * The output is NUL-terminated and truncated if it exceeds `buf_len - 1` characters.
 * This function ensures safe formatting within the given buffer size.
 *
 * @param u The 64-bit unsigned integer to convert.
 * @param buf Pointer to the destination buffer.
 * @param buf_len Size of the destination buffer, including space for the NUL terminator.
 */
WS_DLL_PUBLIC void uint64_to_str_buf(uint64_t u, char *buf, size_t buf_len);

WS_DEPRECATED_X("Use uint64_to_str_buf instead")
static inline void guint64_to_str_buf(uint64_t u, char *buf, size_t buf_len) { uint64_to_str_buf(u, buf, buf_len); }

WS_DEPRECATED_X("Use ip_num_to_str_buf() or ip_addr_to_str() instead")
WS_DLL_PUBLIC void ip_to_str_buf(const uint8_t *ad, char *buf, const int buf_len);

WS_DEPRECATED_X("Use ip_num_to_str() or ip_addr_to_str() instead")
WS_DLL_PUBLIC char *ip_to_str(wmem_allocator_t *scope, const uint8_t *ad);

/**
 * @brief Converts a 32-bit IPv4 address to string format.
 *
 * Converts an IPv4 address in host byte order to dotted-decimal notation
 * and writes it to the provided buffer.
 *
 * @param ad IPv4 address in host byte order.
 * @param buf Destination buffer for the string.
 * @param buf_len Size of the destination buffer.
 */
WS_DLL_PUBLIC void ip_num_to_str_buf(uint32_t ad, char *buf, const int buf_len);

/**
 * @brief Converts a 32-bit IPv4 address to a string using memory scope.
 *
 * Converts an IPv4 address in host byte order to dotted-decimal notation
 * and allocates the result using the provided memory scope.
 *
 * @param scope Memory allocator scope.
 * @param ad IPv4 address in host byte order.
 * @return Pointer to the allocated string.
 */
WS_DLL_PUBLIC char *ip_num_to_str(wmem_allocator_t *scope, uint32_t ad);

/**
 * @brief Converts a ws_in4_addr structure to string format.
 *
 * Writes the dotted-decimal representation of the IPv4 address to the buffer.
 *
 * @param ad Pointer to the IPv4 address structure.
 * @param buf Destination buffer for the string.
 * @param buf_len Size of the destination buffer.
 */
WS_DLL_PUBLIC void ip_addr_to_str_buf(const ws_in4_addr *ad, char *buf, const int buf_len);

/**
 * @brief Converts a ws_in4_addr structure to a string using memory scope.
 *
 * Allocates and returns the dotted-decimal representation of the IPv4 address.
 *
 * @param scope Memory allocator scope.
 * @param ad Pointer to the IPv4 address structure.
 * @return Pointer to the allocated string.
 */
WS_DLL_PUBLIC char *ip_addr_to_str(wmem_allocator_t *scope, const ws_in4_addr *ad);

/**
 * @brief Converts a ws_in6_addr structure to string format.
 *
 * Writes the colon-separated hexadecimal representation of the IPv6 address to the buffer.
 *
 * @param ad Pointer to the IPv6 address structure.
 * @param buf Destination buffer for the string.
 * @param buf_size Size of the destination buffer.
 */
WS_DLL_PUBLIC void ip6_to_str_buf(const ws_in6_addr *ad, char *buf, size_t buf_size);

/**
 * @brief Converts a ws_in6_addr structure to a string using memory scope.
 *
 * Allocates and returns the colon-separated hexadecimal representation of the IPv6 address.
 *
 * @param scope Memory allocator scope.
 * @param ad Pointer to the IPv6 address structure.
 * @return Pointer to the allocated string.
 */
WS_DLL_PUBLIC char *ip6_to_str(wmem_allocator_t *scope, const ws_in6_addr *ad);

/**
 * @brief Converts an IPX network address to a string with punctuation.
 *
 * Formats the 32-bit IPX network address using the specified punctuation character
 * between bytes and allocates the result using the provided memory scope.
 *
 * @param scope Memory allocator scope.
 * @param ad IPX network address.
 * @param punct Punctuation character to insert between bytes.
 * @return Pointer to the allocated string.
 */
WS_DLL_PUBLIC char *ipxnet_to_str_punct(wmem_allocator_t *scope, const uint32_t ad, const char punct);

/**
 * @brief Converts a 64-bit EUI-64 address to string format.
 *
 * Formats the EUI-64 address as a colon-separated hexadecimal string and allocates
 * the result using the provided memory scope.
 *
 * @param scope Memory allocator scope.
 * @param ad EUI-64 address.
 * @return Pointer to the allocated string.
 */
WS_DLL_PUBLIC char *eui64_to_str(wmem_allocator_t *scope, const uint64_t ad);

/**
 * @brief Formats the fractional part of a timestamp in nanoseconds.
 *
 * Converts the nanosecond portion of a timestamp to a string with optional formatting.
 *
 * @param buf Destination buffer.
 * @param buflen Length of the buffer.
 * @param nsecs Nanoseconds to format.
 * @param decimal_point String to use as the decimal point.
 * @param precision Number of digits to include.
 * @return Number of characters written to the buffer.
 */
WS_DLL_PUBLIC int format_fractional_part_nsecs(char *buf, size_t buflen, uint32_t nsecs, const char *decimal_point, int precision);

/**
 * @brief Formats an epoch time value for display.
 *
 * Converts an `nstime_t` value to a human-readable string representing the epoch time.
 *
 * @param buf Destination buffer.
 * @param buflen Size of the buffer.
 * @param ns Pointer to the time value.
 * @param precision Number of fractional digits to include.
 */
WS_DLL_PUBLIC void display_epoch_time(char *buf, size_t buflen, const nstime_t *ns, int precision);

/**
 * @brief Formats a signed time value for display.
 *
 * Converts an `nstime_t` value to a human-readable string, preserving sign and precision.
 *
 * @param buf Destination buffer.
 * @param buf_size Size of the buffer.
 * @param nstime Pointer to the time value.
 * @param precision Number of fractional digits to include.
 */
WS_DLL_PUBLIC void display_signed_time(char *buf, size_t buf_size, const nstime_t *nstime, int precision);

/**
 * @brief Formats an `nstime_t` value as an ISO 8601 timestamp.
 *
 * Converts the time value to a string in ISO 8601 format, optionally including fractional seconds.
 *
 * @param buf Destination buffer.
 * @param buf_size Size of the buffer.
 * @param nstime Pointer to the time value.
 * @param frac_buf Optional buffer for fractional part.
 * @param include_tz Whether to include timezone information.
 * @param precision Number of fractional digits to include.
 */
WS_DLL_PUBLIC void format_nstime_as_iso8601(char *buf, size_t buf_size, const nstime_t *nstime, char *frac_buf, bool include_tz, int precision);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TO_STR_H__  */
