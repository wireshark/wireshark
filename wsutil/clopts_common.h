/** @file
 *
 * Handle command-line arguments common to various programs
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __CLOPTS_COMMON_H__
#define __CLOPTS_COMMON_H__

#include <wireshark.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Long options.
 * For long options with no corresponding short options, we define values
 * outside the range of ASCII graphic characters, make that the last
 * component of the entry for the long option, and have a case for that
 * option in the switch statement.
 */
// Base value for capture related long options
#define LONGOPT_BASE_CAPTURE        1000
// Base value for dissector related long options
#define LONGOPT_BASE_DISSECTOR      2000
// Base value for application specific long options
#define LONGOPT_BASE_APPLICATION    3000
// Base value for GUI specific long options
#define LONGOPT_BASE_GUI            4000
// Base value for logging related long options
#define LONGOPT_BASE_WSLOG          5000

#define LONGOPT_READ_CAPTURE_COMMON \
    {"read-file", ws_required_argument, NULL, 'r' }, \

#define OPTSTRING_READ_CAPTURE_COMMON \
    "r:"

/**
 * @brief Parses a string as a natural (non-negative) 32-bit integer.
 *
 * Attempts to convert the input string to an `int32_t` value ≥ 0.
 * If successful, stores the result in `number` and returns true.
 *
 * @param string The input string to parse.
 * @param name Contextual name used for error reporting.
 * @param number Pointer to receive the parsed value.
 * @return true if parsing succeeds and value is ≥ 0, false otherwise.
 */
WS_DLL_PUBLIC bool
get_natural_int(const char *string, const char *name, int32_t* number);

/**
 * @brief Parses a string as a strictly positive 32-bit integer.
 *
 * Attempts to convert the input string to an `int32_t` value > 0.
 * If successful, stores the result in `number` and returns true.
 *
 * @param string The input string to parse.
 * @param name Contextual name used for error reporting.
 * @param number Pointer to receive the parsed value.
 * @return true if parsing succeeds and value is > 0, false otherwise.
 */
WS_DLL_PUBLIC bool
get_positive_int(const char *string, const char *name, int32_t* number);

/**
 * @brief Parses a string as a natural (non-negative) 64-bit integer.
 *
 * Attempts to convert the input string to an `int64_t` value ≥ 0.
 * If successful, stores the result in `number` and returns true.
 *
 * @param string The input string to parse.
 * @param name Contextual name used for error reporting.
 * @param number Pointer to receive the parsed value.
 * @return true if parsing succeeds and value is ≥ 0, false otherwise.
 */
WS_DLL_PUBLIC bool
get_natural_int64(const char* string, const char* name, int64_t* number);

/**
 * @brief Parses a string as a strictly positive 64-bit integer.
 *
 * Attempts to convert the input string to an `int64_t` value > 0.
 * If successful, stores the result in `number` and returns true.
 *
 * @param string The input string to parse.
 * @param name Contextual name used for error reporting.
 * @param number Pointer to receive the parsed value.
 * @return true if parsing succeeds and value is > 0, false otherwise.
 */
WS_DLL_PUBLIC bool
get_positive_int64(const char* string, const char* name, int64_t* number);

/**
 * @brief Parses a string as an unsigned 32-bit integer.
 *
 * Attempts to convert the input string to a `uint32_t` value.
 * If successful, stores the result in `number` and returns true.
 *
 * @param string The input string to parse.
 * @param name Contextual name used for error reporting.
 * @param number Pointer to receive the parsed value.
 * @return true if parsing succeeds, false otherwise.
 */
WS_DLL_PUBLIC bool
get_uint32(const char *string, const char *name, uint32_t* number);

WS_DEPRECATED_X("Use get_uint32 instead")
static inline uint32_t
get_guint32(const char *string, const char *name) {
    uint32_t number = 0;
    get_uint32(string, name, &number);
    return number;
}

/**
 * @brief Parses a string as a non-zero unsigned 32-bit integer.
 *
 * Attempts to convert the input string to a `uint32_t` value.
 * If successful and the value is not zero, stores the result in `number` and returns true.
 * Returns false if the string is invalid or the parsed value is zero.
 *
 * @param string The input string to parse.
 * @param name Contextual name used for error reporting.
 * @param number Pointer to receive the parsed value.
 * @return true if parsing succeeds and value is > 0, false otherwise.
 */
WS_DLL_PUBLIC bool
get_nonzero_uint32(const char *string, const char *name, uint32_t* number);

WS_DEPRECATED_X("Use get_nonzero_uint32 instead")
static inline uint32_t
get_nonzero_guint32(const char *string, const char *name) {
    uint32_t number = 0;
    get_nonzero_uint32(string, name, &number);
    return number;
}

/**
 * @brief Parses a string as an unsigned 64-bit integer.
 *
 * Attempts to convert the input string to a `uint64_t` value.
 * If successful, stores the result in `number` and returns true.
 *
 * @param string The input string to parse.
 * @param name Contextual name used for error reporting.
 * @param number Pointer to receive the parsed value.
 * @return true if parsing succeeds, false otherwise.
 */
WS_DLL_PUBLIC bool
get_uint64(const char *string, const char *name, uint64_t* number);

/**
 * @brief Parses a string as a non-zero unsigned 64-bit integer.
 *
 * Attempts to convert the input string to a `uint64_t` value.
 * If successful and the value is not zero, stores the result in `number` and returns true.
 *
 * @param string The input string to parse.
 * @param name Contextual name used for error reporting.
 * @param number Pointer to receive the parsed value.
 * @return true if parsing succeeds and value is > 0, false otherwise.
 */
WS_DLL_PUBLIC bool
get_nonzero_uint64(const char *string, const char *name, uint64_t* number);

/**
 * @brief Parses a string as a strictly positive double-precision floating-point number.
 *
 * Attempts to convert the input string to a `double` value.
 * If successful and the value is greater than zero, stores the result in `number` and returns true.
 *
 * @param string The input string to parse.
 * @param name Contextual name used for error reporting.
 * @param number Pointer to receive the parsed value.
 * @return true if parsing succeeds and value is > 0.0, false otherwise.
 */
WS_DLL_PUBLIC bool
get_positive_double(const char *string, const char *name, double* number);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __CLOPTS_COMMON_H__ */
