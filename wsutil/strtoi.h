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
WS_DLL_PUBLIC bool ws_strtoi32(const char* str, const char** endptr, int32_t* cint);
WS_DLL_PUBLIC bool ws_strtoi16(const char* str, const char** endptr, int16_t* cint);
WS_DLL_PUBLIC bool ws_strtoi8 (const char* str, const char** endptr, int8_t*  cint);
WS_DLL_PUBLIC bool ws_strtoi (const char* str, const char** endptr, int*  cint);

WS_DLL_PUBLIC bool ws_strtou64(const char* str, const char** endptr, uint64_t* cint);
WS_DLL_PUBLIC bool ws_strtou32(const char* str, const char** endptr, uint32_t* cint);
WS_DLL_PUBLIC bool ws_strtou16(const char* str, const char** endptr, uint16_t* cint);
WS_DLL_PUBLIC bool ws_strtou8 (const char* str, const char** endptr, uint8_t*  cint);
WS_DLL_PUBLIC bool ws_strtou (const char* str, const char** endptr, unsigned*  cint);

/*
 * \brief Convert a hexadecimal string to an unsigned int, with error checks.
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

WS_DLL_PUBLIC bool ws_hexstrtou64(const char* str, const char** endptr, uint64_t* cint);
WS_DLL_PUBLIC bool ws_hexstrtou32(const char* str, const char** endptr, uint32_t* cint);
WS_DLL_PUBLIC bool ws_hexstrtou16(const char* str, const char** endptr, uint16_t* cint);
WS_DLL_PUBLIC bool ws_hexstrtou8 (const char* str, const char** endptr, uint8_t*  cint);
WS_DLL_PUBLIC bool ws_hexstrtou (const char* str, const char** endptr, unsigned*  cint);

/*
 * \brief Convert a string in the specified base to an unsigned int, with
 * error checks.
 * \param str The string to convert
 * \param endptr A pointer that will store a pointer to the first invalid
 * character in str, allowing a number to be parsed even if there is trailing
 * whitespace. If NULL, then the string is assumed to contain only valid
 * characters (or it will error out).
 * \param cint The converted integer
 * \param base The base for the integer; 0 means "if it begins with 0x,
 * it's hex, otherwise if it begins with 0, it's octal, otherwise it's
 * decimal".
 * \return true if the conversion succeeds, false otherwise.
 * On error, errno is set to EINVAL for unrecognized input and ERANGE
 * if the resulting number does not fit in the type.
 */

WS_DLL_PUBLIC bool ws_basestrtou64(const char* str, const char** endptr, uint64_t* cint, int base);
WS_DLL_PUBLIC bool ws_basestrtou32(const char* str, const char** endptr, uint32_t* cint, int base);
WS_DLL_PUBLIC bool ws_basestrtou16(const char* str, const char** endptr, uint16_t* cint, int base);
WS_DLL_PUBLIC bool ws_basestrtou8 (const char* str, const char** endptr, uint8_t*  cint, int base);
WS_DLL_PUBLIC bool ws_basestrtou (const char* str, const char** endptr, unsigned*  cint, int base);

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
