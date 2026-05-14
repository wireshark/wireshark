/** @file
 * Utilities to convert strings to integers
 *
 * Copyright 2016, Dario Lombardo
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _WS_STRTOI_H
#define _WS_STRTOI_H

#include <stdbool.h>
#include <inttypes.h>

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * \brief Convert a decimal string to a signed/unsigned int, with error checks.
 * \param str The string to convert
 * \param endptr A pointer that will store a pointer to the first invalid
 * character in str, allowing a number to be parsed even if there is trailing
 * whitespace. If NULL, then the string is assumed to contain only valid
 * characters (or it will error out).
 * \param cint The converted integer
 * \return true if the conversion succeeds, false otherwise.
 * On error, errno is set to EINVAL for unrecognized input and ERANGE
 * if the resulting number does not fit in the type.
 */
WS_DLL_PUBLIC bool ws_strtoi64(const char* str, const char** endptr, int64_t* cint);

/**
 * @brief Convert a string to an integer of specified size.
 *
 * Converts a string to an integer of the specified size and stores the result in the provided variable.
 *
 * @param str The input string to convert.
 * @param endptr A pointer to a character that will be set to point to the first character after the converted number.
 * @param cint A pointer to the variable where the converted integer will be stored.
 * @return true if the conversion was successful, false otherwise.
 */
WS_DLL_PUBLIC bool ws_strtoi32(const char* str, const char** endptr, int32_t* cint);

/**
 * @brief Convert a string to a 16-bit integer.
 *
 * Converts the initial portion of the string pointed to by str to an int value.
 *
 * @param str The string to be converted.
 * @param endptr A pointer to a char pointer that will receive the address of the first character not part of the conversion.
 * @param cint Pointer to the location where the result should be stored.
 * @return true if successful, false otherwise.
 */
WS_DLL_PUBLIC bool ws_strtoi16(const char* str, const char** endptr, int16_t* cint);

/**
 * @brief Convert a string to an 8-bit integer.
 *
 * Converts the initial portion of the string pointed to by str to an int value.
 *
 * @param str The string to be converted.
 * @param endptr A pointer to a char pointer that will receive the address of the first character not part of the conversion.
 * @param cint Pointer to the location where the result should be stored.
 * @return true if successful, false otherwise.
 */
WS_DLL_PUBLIC bool ws_strtoi8 (const char* str, const char** endptr, int8_t* cint);

/**
 * @brief Convert a string to an integer.
 *
 * Converts the initial part of the string pointed to by 'str' to an int.
 *
 * @param str The string to be converted.
 * @param endptr A pointer to a char pointer that will receive the address of the first character not converted.
 * @param cint A pointer to an int where the result will be stored.
 * @return true if successful, false otherwise.
 */
WS_DLL_PUBLIC bool ws_strtoi (const char* str, const char** endptr, int* cint);

/**
 * @brief Convert a decimal string to a 64-bit unsigned int, with error checks.
 * @param str The string to convert
 * @param endptr A pointer to a char pointer that will receive the address of the first character not converted.
 * @param cint A pointer to a uint64_t where the result will be stored.
 * @return true if conversion is successful, false otherwise
 */
WS_DLL_PUBLIC bool ws_strtou64(const char* str, const char** endptr, uint64_t* cint);

/**
 * @brief Convert a decimal string to a 32-bit unsigned int, with error checks.
 * @param str The string to convert
 * @param endptr A pointer to a char pointer that will receive the address of the first character not converted.
 * @param cint A pointer to a uint32_t where the result will be stored.
 * @return true if conversion is successful, false otherwise
 */
WS_DLL_PUBLIC bool ws_strtou32(const char* str, const char** endptr, uint32_t* cint);

/**
 * @brief Convert a decimal string to an unsigned int, with error checks.
 * @param str The string to convert
 * @param endptr A pointer to a char pointer that will receive the address of the first character not converted.
 * @return true if the conversion was successful, false otherwise.
 */
WS_DLL_PUBLIC bool ws_strtou16(const char* str, const char** endptr, uint16_t* cint);

/**
 * @brief Convert a decimal string to an unsigned int, with error checks.
 *
 * @param str The string to convert
 * @param endptr A pointer that will store a pointer to the first invalid character in str,
 *               allowing a number to be parsed even if there is trailing whitespace. If NULL,
 *               then the string is assumed to contain only valid characters.
 * @return true on success, false otherwise
 */
WS_DLL_PUBLIC bool ws_strtou8 (const char* str, const char** endptr, uint8_t*  cint);

/**
 * @brief Convert a decimal string to an unsigned int, with error checks.
 * @param str The string to convert
 * @param endptr A pointer that will store a pointer to the first invalid character in str,
 * allowing a number to be parsed even if there is trailing whitespace. If NULL, then the string
 * is assumed to contain only valid characters (or it will error out).
 * @return true on success, false on failure.
 */
WS_DLL_PUBLIC bool ws_strtou (const char* str, const char** endptr, unsigned*  cint);

/**
 * @brief Convert a hexdecimal string to an unsigned int, with error checks.
 * @param str The hexdecimal string to convert
 * @param endptr A pointer that will store a pointer to the first invalid
 * character in str, allowing a number to be parsed even if there is trailing
 * whitespace. If NULL, then the string is assumed to contain only valid
 * characters (or it will error out).
 * @param cint The converted integer
 * @return true if the conversion succeeds, false otherwise.
 * On error, errno is set to EINVAL for unrecognized input and ERANGE
 * if the resulting number does not fit in the type.
 */
WS_DLL_PUBLIC bool ws_hexstrtou64(const char* str, const char** endptr, uint64_t* cint);

/**
 * @brief Convert a hexadecimal string to an 32-bit unsigned int, with error checks.
 *
 * @param str The hexadecimal string to convert.
 * @param endptr A pointer that will store a pointer to the first invalid character encountered during conversion.
 * @return true If the conversion was successful.
 * @return false If the conversion failed.
 */
WS_DLL_PUBLIC bool ws_hexstrtou32(const char* str, const char** endptr, uint32_t* cint);

/**
 * @brief Convert a hexadecimal string to an 16-bit unsigned int, with error checks.
 *
 * @param str The hexadecimal string to convert.
 * @param endptr A pointer that will store a pointer to the first invalid character encountered during conversion.
 * @return true If the conversion was successful.
 * @return false If the conversion failed.
 */
WS_DLL_PUBLIC bool ws_hexstrtou16(const char* str, const char** endptr, uint16_t* cint);

/**
 * @brief Convert a hexadecimal string in the specified base to an 8-bit unsigned int, with error checks.
 *
 * @param str The hexadecimal string to convert.
 * @param endptr A pointer that will store a pointer to the first invalid character encountered during conversion.
 * @return true If the conversion was successful.
 * @return false If the conversion failed.
 */
WS_DLL_PUBLIC bool ws_hexstrtou8 (const char* str, const char** endptr, uint8_t*  cint);

/**
 * @brief Convert a hexadecimal string to an unsigned int, with error checks.
 * @param str The hexadecimal string to convert.
 * @param endptr A pointer that will store a pointer to the first invalid character in str,
 * allowing a number to be parsed even if there is trailing whitespace. If NULL, then the
 * string is assumed to contain only valid characters.
 * @return true if the conversion was successful, false otherwise.
 */
WS_DLL_PUBLIC bool ws_hexstrtou (const char* str, const char** endptr, unsigned*  cint);

/**
 * @brief Convert a string in the specified base to a 64-bit unsigned int, with
 * error checks.
 * @param str The string to convert
 * @param endptr A pointer that will store a pointer to the first invalid
 * character in str, allowing a number to be parsed even if there is trailing
 * whitespace. If NULL, then the string is assumed to contain only valid
 * characters (or it will error out).
 * @param cint The converted integer
 * @param base The base for the integer; 0 means "if it begins with 0x,
 * it's hex, otherwise if it begins with 0, it's octal, otherwise it's
 * decimal".
 * @return true if the conversion succeeds, false otherwise.
 * On error, errno is set to EINVAL for unrecognized input and ERANGE
 * if the resulting number does not fit in the type.
 */
WS_DLL_PUBLIC bool ws_basestrtou64(const char* str, const char** endptr, uint64_t* cint, int base);

/**
 * @brief Convert a string in the specified base to a 32-bit unsigned int, with
 * error checks.
 * @param str The string to convert
 * @param endptr A pointer that will store a pointer to the first invalid
 * character in str, allowing a number to be parsed even if there is trailing
 * whitespace. If NULL, then the string is assumed to contain only valid
 * characters (or it will error out).
 * @param cint The converted integer
 * @param base The base for the integer; 0 means "if it begins with 0x,
 * it's hex, otherwise if it begins with 0, it's octal, otherwise it's
 * decimal".
 * @return true if the conversion succeeds, false otherwise.
 * On error, errno is set to EINVAL for unrecognized input and ERANGE
 * if the resulting number does not fit in the type.
 */
WS_DLL_PUBLIC bool ws_basestrtou32(const char* str, const char** endptr, uint32_t* cint, int base);

/**
 * @brief Convert a string in the specified base to a 16-bit unsigned int, with
 * error checks.
 * @param str The string to convert
 * @param endptr A pointer that will store a pointer to the first invalid
 * character in str, allowing a number to be parsed even if there is trailing
 * whitespace. If NULL, then the string is assumed to contain only valid
 * characters (or it will error out).
 * @param cint The converted integer
 * @param base The base for the integer; 0 means "if it begins with 0x,
 * it's hex, otherwise if it begins with 0, it's octal, otherwise it's
 * decimal".
 * @return true if the conversion succeeds, false otherwise.
 * On error, errno is set to EINVAL for unrecognized input and ERANGE
 * if the resulting number does not fit in the type.
 */
WS_DLL_PUBLIC bool ws_basestrtou16(const char* str, const char** endptr, uint16_t* cint, int base);

/**
 * @brief Convert a string in the specified base to an 8-bit unsigned int, with
 * error checks.
 * @param str The string to convert
 * @param endptr A pointer that will store a pointer to the first invalid
 * character in str, allowing a number to be parsed even if there is trailing
 * whitespace. If NULL, then the string is assumed to contain only valid
 * characters (or it will error out).
 * @param cint The converted integer
 * @param base The base for the integer; 0 means "if it begins with 0x,
 * it's hex, otherwise if it begins with 0, it's octal, otherwise it's
 * decimal".
 * @return true if the conversion succeeds, false otherwise.
 * On error, errno is set to EINVAL for unrecognized input and ERANGE
 * if the resulting number does not fit in the type.
 */
WS_DLL_PUBLIC bool ws_basestrtou8 (const char* str, const char** endptr, uint8_t*  cint, int base);

/**
 * @brief Convert a string in the specified base to an unsigned int, with
 * error checks.
 * @param str The string to convert
 * @param endptr A pointer that will store a pointer to the first invalid
 * character in str, allowing a number to be parsed even if there is trailing
 * whitespace. If NULL, then the string is assumed to contain only valid
 * characters (or it will error out).
 * @param cint The converted integer
 * @param base The base for the integer; 0 means "if it begins with 0x,
 * it's hex, otherwise if it begins with 0, it's octal, otherwise it's
 * decimal".
 * @return true if the conversion succeeds, false otherwise.
 * On error, errno is set to EINVAL for unrecognized input and ERANGE
 * if the resulting number does not fit in the type.
 */
WS_DLL_PUBLIC bool ws_basestrtou (const char* str, const char** endptr, unsigned*  cint, int base);

/**
 * @brief Convert a counted string (not necessarily null terminated, of the
 * given length) in the specified base to an unsigned 64-bit integer, with
 * error checks.
 *
 * @param buf The string buffer to convert
 * @param len The length of the string
 * @param endptr A pointer that will store a pointer to the first invalid
 * character in str, allowing a number to be parsed even if there is trailing
 * whitespace. If NULL, then the string is assumed to contain only valid
 * characters (or it will error out).
 * @param cint The converted integer
 * @param base The base for the integer; 0 means "if it begins with 0x,
 * it's hex, otherwise if it begins with 0, it's octal, otherwise it's
 * decimal".
 * @return true if the conversion succeeds, false otherwise.
 * On error, errno is set to EINVAL for unrecognized input and ERANGE
 * if the resulting number does not fit in the type.
 *
 * @note This is useful when a string representation of an integer is not
 * null-terminated and also cannot be modified to insert a NULL (e.g.,
 * a const uint8_t* from packet data), avoiding having to copy the string.
 * This does not allow a sign, neither '+' nor '-', prefixing the string,
 * unlike strtoull and g_ascii_strtoull. (The latter allow a negative sign
 * and cast to unsigned in the normal way.)
 */
WS_DLL_PUBLIC bool ws_basebuftou64(const uint8_t* buf, size_t len, const uint8_t** endptr, uint64_t* cint, int base);

/**
 * @brief Convert a counted decimal string (not necessarily null terminated,
 * of the given length) to an unsigned 64-bit integer, with error checks.
 *
 * @param buf The string buffer to convert
 * @param len The length of the string
 * @param endptr A pointer that will store a pointer to the first invalid
 * character in str, allowing a number to be parsed even if there is trailing
 * whitespace. If NULL, then the string is assumed to contain only valid
 * characters (or it will error out).
 * @param cint The converted integer
 * @return true if the conversion succeeds, false otherwise.
 * On error, errno is set to EINVAL for unrecognized input and ERANGE
 * if the resulting number does not fit in the type.
 *
 * @note This does not allow a sign, neither '+' nor '-', prefixing the string,
 * unlike strtoull and g_ascii_strtoull. (The latter allow a negative sign
 * and cast to unsigned in the normal way.)
 */
WS_DLL_PUBLIC bool ws_buftou64(const uint8_t* buf, size_t len, const uint8_t** endptr, uint64_t* cint);

/**
 * @brief Convert a counted hexadecimal string (not necessarily null terminated,
 * of the given length) to an unsigned 64-bit integer, with error checks.
 *
 * @param buf The string buffer to convert
 * @param len The length of the string
 * @param endptr A pointer that will store a pointer to the first invalid
 * character in str, allowing a number to be parsed even if there is trailing
 * whitespace. If NULL, then the string is assumed to contain only valid
 * characters (or it will error out).
 * @param cint The converted integer
 * @return true if the conversion succeeds, false otherwise.
 * On error, errno is set to EINVAL for unrecognized input and ERANGE
 * if the resulting number does not fit in the type.
 *
 * @note This does not allow a sign, neither '+' nor '-', prefixing the string,
 * unlike strtoull and g_ascii_strtoull. (The latter allow a negative sign
 * and cast to unsigned in the normal way.)
 */
WS_DLL_PUBLIC bool ws_hexbuftou64(const uint8_t* buf, size_t len, const uint8_t** endptr, uint64_t* cint);

/**
 * @brief Parse a uint32_t from a byte buffer using a specified numeric base.
 *
 * Reads up to @p len bytes from @p buf, interpreting them as an unsigned
 * integer in the given @p base. On success, stores the result in @p cint
 * and sets @p endptr to one past the last consumed byte.
 *
 * @param buf     Pointer to the input byte buffer.
 * @param len     Number of bytes available in @p buf.
 * @param endptr  Set to one past the last byte consumed; NULL to ignore.
 * @param cint    Receives the parsed uint32_t value on success.
 * @param base    Numeric base to use for parsing (e.g. 10, 16).
 * @return true on success, false if no valid digits were found, the
 *         buffer was exhausted, or the value overflows uint32_t.
 */
WS_DLL_PUBLIC bool ws_basebuftou32(const uint8_t* buf, size_t len, const uint8_t** endptr, uint32_t* cint, int base);


/**
 * @brief Parse a uint32_t from a byte buffer in base 10.
 *
 * Convenience wrapper around ws_basebuftou32() using base 10.
 *
 * @param buf    Pointer to the input byte buffer.
 * @param len    Number of bytes available in @p buf.
 * @param endptr Set to one past the last byte consumed; NULL to ignore.
 * @param cint   Receives the parsed uint32_t value on success.
 * @return true on success, false on parse error or overflow.
 */
WS_DLL_PUBLIC bool ws_buftou32(const uint8_t* buf, size_t len, const uint8_t** endptr, uint32_t* cint);

/**
 * @brief Parse a uint32_t from a byte buffer in base 16 (hexadecimal).
 *
 * Convenience wrapper around ws_basebuftou32() using base 16.
 *
 * @param buf    Pointer to the input byte buffer.
 * @param len    Number of bytes available in @p buf.
 * @param endptr Set to one past the last byte consumed; NULL to ignore.
 * @param cint   Receives the parsed uint32_t value on success.
 * @return true on success, false on parse error or overflow.
 */
WS_DLL_PUBLIC bool ws_hexbuftou32(const uint8_t* buf, size_t len, const uint8_t** endptr, uint32_t* cint);

/**
 * @brief Parse a uint16_t from a byte buffer using a specified numeric base.
 *
 * @param buf    Pointer to the input byte buffer.
 * @param len    Number of bytes available in @p buf.
 * @param endptr Set to one past the last byte consumed; NULL to ignore.
 * @param cint   Receives the parsed uint16_t value on success.
 * @param base   Numeric base to use for parsing (e.g. 10, 16).
 * @return true on success, false on parse error or overflow.
 */
WS_DLL_PUBLIC bool ws_basebuftou16(const uint8_t* buf, size_t len, const uint8_t** endptr, uint16_t* cint, int base);

/**
 * @brief Parse a uint16_t from a byte buffer in base 10.
 *
 * Convenience wrapper around ws_basebuftou16() using base 10.
 *
 * @param buf    Pointer to the input byte buffer.
 * @param len    Number of bytes available in @p buf.
 * @param endptr Set to one past the last byte consumed; NULL to ignore.
 * @param cint   Receives the parsed uint16_t value on success.
 * @return true on success, false on parse error or overflow.
 */
WS_DLL_PUBLIC bool ws_buftou16(const uint8_t* buf, size_t len, const uint8_t** endptr, uint16_t* cint);

/**
 * @brief Parse a uint16_t from a byte buffer in base 16 (hexadecimal).
 *
 * Convenience wrapper around ws_basebuftou16() using base 16.
 *
 * @param buf    Pointer to the input byte buffer.
 * @param len    Number of bytes available in @p buf.
 * @param endptr Set to one past the last byte consumed; NULL to ignore.
 * @param cint   Receives the parsed uint16_t value on success.
 * @return true on success, false on parse error or overflow.
 */
WS_DLL_PUBLIC bool ws_hexbuftou16(const uint8_t* buf, size_t len, const uint8_t** endptr, uint16_t* cint);

/**
 * @brief Parse a uint8_t from a byte buffer using a specified numeric base.
 *
 * @param buf    Pointer to the input byte buffer.
 * @param len    Number of bytes available in @p buf.
 * @param endptr Set to one past the last byte consumed; NULL to ignore.
 * @param cint   Receives the parsed uint8_t value on success.
 * @param base   Numeric base to use for parsing (e.g. 10, 16).
 * @return true on success, false on parse error or overflow.
 */
WS_DLL_PUBLIC bool ws_basebuftou8(const uint8_t* buf, size_t len, const uint8_t** endptr, uint8_t* cint, int base);

/**
 * @brief Parse a uint8_t from a byte buffer in base 10.
 *
 * Convenience wrapper around ws_basebuftou8() using base 10.
 *
 * @param buf    Pointer to the input byte buffer.
 * @param len    Number of bytes available in @p buf.
 * @param endptr Set to one past the last byte consumed; NULL to ignore.
 * @param cint   Receives the parsed uint8_t value on success.
 * @return true on success, false on parse error or overflow.
 */
WS_DLL_PUBLIC bool ws_buftou8(const uint8_t* buf, size_t len, const uint8_t** endptr, uint8_t* cint);

/**
 * @brief Parse a uint8_t from a byte buffer in base 16 (hexadecimal).
 *
 * Convenience wrapper around ws_basebuftou8() using base 16.
 *
 * @param buf    Pointer to the input byte buffer.
 * @param len    Number of bytes available in @p buf.
 * @param endptr Set to one past the last byte consumed; NULL to ignore.
 * @param cint   Receives the parsed uint8_t value on success.
 * @return true on success, false on parse error or overflow.
 */
WS_DLL_PUBLIC bool ws_hexbuftou8(const uint8_t* buf, size_t len, const uint8_t** endptr, uint8_t* cint);

/**
 * @brief Convert a counted string (not necessarily null terminated, of the
 * given length) in the specified base to a signed 64-bit integer, with
 * error checks.
 *
 * @param buf The string buffer to convert
 * @param len The length of the string
 * @param endptr A pointer that will store a pointer to the first invalid
 * character in str, allowing a number to be parsed even if there is trailing
 * whitespace. If NULL, then the string is assumed to contain only valid
 * characters (or it will error out).
 * @param cint The converted integer
 * @param base The base for the integer; 0 means "if it begins with 0x,
 * it's hex, otherwise if it begins with 0, it's octal, otherwise it's
 * decimal".
 * @return true if the conversion succeeds, false otherwise.
 * On error, errno is set to EINVAL for unrecognized input and ERANGE
 * if the resulting number does not fit in the type.
 *
 * @note This is useful when a string representation of an integer is not
 * null-terminated and also cannot be modified to insert a NULL (e.g.,
 * a const uint8_t* from packet data), avoiding having to copy the string.
 * This allows a sign, either '+' or '-', to prefix the string.
 */
WS_DLL_PUBLIC bool ws_basebuftoi64(const uint8_t* buf, size_t len, const uint8_t** endptr, int64_t* cint, int base);

/**
 * @brief Convert a counted decimal string (not necessarily null terminated,
 * of the given length) to a signed 64-bit integer, with error checks.
 *
 * @param buf The string buffer to convert
 * @param len The length of the string
 * @param endptr A pointer that will store a pointer to the first invalid
 * character in str, allowing a number to be parsed even if there is trailing
 * whitespace. If NULL, then the string is assumed to contain only valid
 * characters (or it will error out).
 * @param cint The converted integer
 * @return true if the conversion succeeds, false otherwise.
 * On error, errno is set to EINVAL for unrecognized input and ERANGE
 * if the resulting number does not fit in the type.
 *
 * @note This is useful when a string representation of an integer is not
 * null-terminated and also cannot be modified to insert a NULL (e.g.,
 * a const uint8_t* from packet data), avoiding having to copy the string.
 * This allows a sign, either '+' or '-', to prefix the string.
 */
WS_DLL_PUBLIC bool ws_buftoi64(const uint8_t* buf, size_t len, const uint8_t** endptr, int64_t* cint);

/**
 * @brief Convert a counted hexadecimal string (not necessarily null terminated,
 * of the given length) to a signed 64-bit integer, with error checks.
 *
 * @param buf The string buffer to convert
 * @param len The length of the string
 * @param endptr A pointer that will store a pointer to the first invalid
 * character in str, allowing a number to be parsed even if there is trailing
 * whitespace. If NULL, then the string is assumed to contain only valid
 * characters (or it will error out).
 * @param cint The converted integer
 * @return true if the conversion succeeds, false otherwise.
 * On error, errno is set to EINVAL for unrecognized input and ERANGE
 * if the resulting number does not fit in the type.
 *
 * @note This is useful when a string representation of an integer is not
 * null-terminated and also cannot be modified to insert a NULL (e.g.,
 * a const uint8_t* from packet data), avoiding having to copy the string.
 * This allows a sign, either '+' or '-', to prefix the string.
 */
WS_DLL_PUBLIC bool ws_hexbuftoi64(const uint8_t* buf, size_t len, const uint8_t** endptr, int64_t* cint);

/**
 * @brief Parse an int32_t from a byte buffer using a specified numeric base.
 *
 * @param buf    Pointer to the input byte buffer.
 * @param len    Number of bytes available in @p buf.
 * @param endptr Set to one past the last byte consumed; NULL to ignore.
 * @param cint   Receives the parsed int32_t value on success.
 * @param base   Numeric base to use for parsing (e.g. 10, 16).
 * @return true on success, false if no valid digits were found, the
 *         buffer was exhausted, or the value overflows int32_t.
 */
WS_DLL_PUBLIC bool ws_basebuftoi32(const uint8_t* buf, size_t len, const uint8_t** endptr, int32_t* cint, int base);

/**
 * @brief Parse an int32_t from a byte buffer in base 10.
 *
 * @param buf    Pointer to the input byte buffer.
 * @param len    Number of bytes available in @p buf.
 * @param endptr Set to one past the last byte consumed; NULL to ignore.
 * @param cint   Receives the parsed int32_t value on success.
 * @return true on success, false on parse error or overflow.
 */
WS_DLL_PUBLIC bool ws_buftoi32(const uint8_t* buf, size_t len, const uint8_t** endptr, int32_t* cint);

/**
 * @brief Parse an int32_t from a byte buffer in base 16 (hexadecimal).
 *
 * @param buf    Pointer to the input byte buffer.
 * @param len    Number of bytes available in @p buf.
 * @param endptr Set to one past the last byte consumed; NULL to ignore.
 * @param cint   Receives the parsed int32_t value on success.
 * @return true on success, false on parse error or overflow.
 */
WS_DLL_PUBLIC bool ws_hexbuftoi32(const uint8_t* buf, size_t len, const uint8_t** endptr, int32_t* cint);

/**
 * @brief Parse an int16_t from a byte buffer using a specified numeric base.
 *
 * @param buf    Pointer to the input byte buffer.
 * @param len    Number of bytes available in @p buf.
 * @param endptr Set to one past the last byte consumed; NULL to ignore.
 * @param cint   Receives the parsed int16_t value on success.
 * @param base   Numeric base to use for parsing (e.g. 10, 16).
 * @return true on success, false on parse error or overflow.
 */
WS_DLL_PUBLIC bool ws_basebuftoi16(const uint8_t* buf, size_t len, const uint8_t** endptr, int16_t* cint, int base);

/**
 * @brief Parse an int16_t from a byte buffer in base 10.
 *
 * @param buf    Pointer to the input byte buffer.
 * @param len    Number of bytes available in @p buf.
 * @param endptr Set to one past the last byte consumed; NULL to ignore.
 * @param cint   Receives the parsed int16_t value on success.
 * @return true on success, false on parse error or overflow.
 */
WS_DLL_PUBLIC bool ws_buftoi16(const uint8_t* buf, size_t len, const uint8_t** endptr, int16_t* cint);

/**
 * @brief Parse an int16_t from a byte buffer in base 16 (hexadecimal).
 *
 * @param buf    Pointer to the input byte buffer.
 * @param len    Number of bytes available in @p buf.
 * @param endptr Set to one past the last byte consumed; NULL to ignore.
 * @param cint   Receives the parsed int16_t value on success.
 * @return true on success, false on parse error or overflow.
 */
WS_DLL_PUBLIC bool ws_hexbuftoi16(const uint8_t* buf, size_t len, const uint8_t** endptr, int16_t* cint);

/**
 * @brief Parse an int8_t from a byte buffer using a specified numeric base.
 *
 * @param buf    Pointer to the input byte buffer.
 * @param len    Number of bytes available in @p buf.
 * @param endptr Set to one past the last byte consumed; NULL to ignore.
 * @param cint   Receives the parsed int8_t value on success.
 * @param base   Numeric base to use for parsing (e.g. 10, 16).
 * @return true on success, false on parse error or overflow.
 */
WS_DLL_PUBLIC bool ws_basebuftoi8(const uint8_t* buf, size_t len, const uint8_t** endptr, int8_t* cint, int base);

/**
 * @brief Parse an int8_t from a byte buffer in base 10.
 *
 * @param buf    Pointer to the input byte buffer.
 * @param len    Number of bytes available in @p buf.
 * @param endptr Set to one past the last byte consumed; NULL to ignore.
 * @param cint   Receives the parsed int8_t value on success.
 * @return true on success, false on parse error or overflow.
 */
WS_DLL_PUBLIC bool ws_buftoi8(const uint8_t* buf, size_t len, const uint8_t** endptr, int8_t* cint);

/**
 * @brief Parse an int8_t from a byte buffer in base 16 (hexadecimal).
 *
 * @param buf    Pointer to the input byte buffer.
 * @param len    Number of bytes available in @p buf.
 * @param endptr Set to one past the last byte consumed; NULL to ignore.
 * @param cint   Receives the parsed int8_t value on success.
 * @return true on success, false on parse error or overflow.
 */
WS_DLL_PUBLIC bool ws_hexbuftoi8(const uint8_t* buf, size_t len, const uint8_t** endptr, int8_t* cint);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 noexpandtab:
 * :indentSize=4:tabSize=8:noTabs=false:
 */
