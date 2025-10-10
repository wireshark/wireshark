/** @file
 * Definitions for the Wireshark Memory Manager String Utilities
 * Copyright 2012, Evan Huus <eapache@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WMEM_STRUTL_H__
#define __WMEM_STRUTL_H__

#include <stdarg.h>

#include "wmem_core.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @addtogroup wmem
 *  @{
 *    @defgroup wmem-strutl String Utilities
 *
 *    A collection of utility function for operating on C strings with wmem.
 *
 *    @{
 */

/**
 * @brief Duplicate a string using the specified memory allocator.
 *
 * Allocates memory for a copy of the null-terminated string `src` using the given
 * `allocator`, and returns a pointer to the newly allocated string.
 *
 * @param allocator Pointer to the memory allocator to use.
 * @param src Null-terminated string to duplicate.
 * @return Pointer to the duplicated string, or NULL on failure.
 *
 * @note The returned memory is allocated and should be freed appropriately if not managed automatically.
 */
WS_DLL_PUBLIC
char *
wmem_strdup(wmem_allocator_t *allocator, const char *src)
G_GNUC_MALLOC;

#define ws_strdup(src) wmem_strdup(NULL, src)

/**
 * @brief Duplicate a string up to a specified length using the given memory allocator.
 *
 * Allocates memory for a copy of the first `len` characters of the null-terminated string `src`
 * using the specified `allocator`. The resulting string is null-terminated.
 *
 * @param allocator Pointer to the memory allocator to use.
 * @param src Null-terminated source string to duplicate.
 * @param len Maximum number of characters to copy from the source string.
 * @return Pointer to the newly allocated string, or NULL on failure.
 *
 * @note The returned memory is allocated and should be freed appropriately if not managed automatically.
 */
WS_DLL_PUBLIC
char *
wmem_strndup(wmem_allocator_t *allocator, const char *src, const size_t len)
G_GNUC_MALLOC;

#define ws_strndup(src, len) wmem_strndup(NULL, src, len)

/**
 * @brief Allocate and format a string using the specified memory allocator.
 *
 * Formats a string using printf-style formatting and allocates memory for it
 * using the given allocator. The resulting string is null-terminated.
 *
 * @param allocator Pointer to the memory allocator to use.
 * @param fmt Format string (as used in printf).
 * @param ... Additional arguments to format into the string.
 * @return Pointer to the newly allocated formatted string, or NULL on failure.
 *
 * @note The returned memory is allocated and should be freed appropriately if not managed automatically.
 */
WS_DLL_PUBLIC
char *
wmem_strdup_printf(wmem_allocator_t *allocator, const char *fmt, ...)
G_GNUC_MALLOC G_GNUC_PRINTF(2, 3);

#define ws_strdup_printf(...) wmem_strdup_printf(NULL, __VA_ARGS__)

/**
 * @brief Allocate and format a string using a va_list and the specified memory allocator.
 *
 * Formats a string using a printf-style format string and a va_list of arguments,
 * allocating memory for the resulting string using the given allocator.
 *
 * @param allocator Pointer to the memory allocator to use.
 * @param fmt Format string (as used in printf).
 * @param ap va_list containing the arguments to format into the string.
 * @return Pointer to the newly allocated formatted string, or NULL on failure.
 *
 * @note The returned memory is allocated and should be freed appropriately if not managed automatically.
 */
WS_DLL_PUBLIC
char *
wmem_strdup_vprintf(wmem_allocator_t *allocator, const char *fmt, va_list ap)
G_GNUC_MALLOC;

#define ws_strdup_vprintf(fmt, ap) wmem_strdup_vprintf(NULL, fmt, ap)

/**
 * @brief Return the first occurrence of needle in haystack.
 *
 * @param haystack The data to search
 * @param haystack_len The length of the search data
 * @param needle The string to look for
 * @param needle_len The length of the search string
 * @return A pointer to the first occurrence of "needle" in
 *         "haystack".  If "needle" isn't found or is NULL, NULL is returned.
 *         If "needle_len" is 0, a pointer to "haystack" is returned.
 */
WS_DLL_PUBLIC
const uint8_t *ws_memmem(const void *haystack, size_t haystack_len,
                        const void *needle, size_t needle_len);

/**   @}
 *  @} */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WMEM_STRUTL_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
