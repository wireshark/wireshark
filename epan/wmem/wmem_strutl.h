/* wmem_strutl.h
 * Definitions for the Wireshark Memory Manager String Utilities
 * Copyright 2012, Evan Huus <eapache@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __WMEM_STRUTL_H__
#define __WMEM_STRUTL_H__

#include <string.h>

#include <glib.h>

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

WS_DLL_PUBLIC
gchar *
wmem_strdup(wmem_allocator_t *allocator, const gchar *src)
G_GNUC_MALLOC;

WS_DLL_PUBLIC
gchar *
wmem_strndup(wmem_allocator_t *allocator, const gchar *src, const size_t len)
G_GNUC_MALLOC;

WS_DLL_PUBLIC
gchar *
wmem_strdup_printf(wmem_allocator_t *allocator, const gchar *fmt, ...)
G_GNUC_MALLOC G_GNUC_PRINTF(2, 3);

WS_DLL_PUBLIC
gchar *
wmem_strdup_vprintf(wmem_allocator_t *allocator, const gchar *fmt, va_list ap)
G_GNUC_MALLOC;

WS_DLL_PUBLIC
gchar *
wmem_strconcat(wmem_allocator_t *allocator, const gchar *first, ...)
G_GNUC_MALLOC G_GNUC_NULL_TERMINATED;

/**
 * Splits a string into a maximum of max_tokens pieces, using the given
 * delimiter. If max_tokens is reached, the remainder of string is appended
 * to the last token. Consecutive delimiters are treated as a single delimiter.
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
/**   @}
 *  @} */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WMEM_STRUTL_H__ */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
