/** @file
 * Definitions for the Wireshark Memory Manager Misc Utilities
 * Copyright 2013, Evan Huus <eapache@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WMEM_MISCUTL_H__
#define __WMEM_MISCUTL_H__

#include <string.h>
#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @addtogroup wmem
 *  @{
 *    @defgroup wmem-strutl String Utilities
 *
 *    A collection of misc. utility functions for wmem.
 *
 *    @{
 */

/**
 * @brief Copies a block of memory.
 *
 * @param allocator The allocator object to use to allocate memory to copy into.
 * @param source The pointer to the memory block to copy.
 * @param size The amount of memory to copy.
 * @return The location of the memory copy or NULL if size is 0.
 */
WS_DLL_PUBLIC
void *
wmem_memdup(wmem_allocator_t *allocator, const void *source, const size_t size)
G_GNUC_ALLOC_SIZE(3);

/**
 * @brief Generic GCompareFunc to compare two signed integers.
 *
 * Casts both `a` and `b` to `const gint*` and returns the result of their comparison.
 * This function is suitable for use with sorting or searching routines that accept
 * a `GCompareFunc`.
 *
 * @param a Pointer to the first signed integer.
 * @param b Pointer to the second signed integer.
 * @return Negative if *a < *b, zero if *a == *b, positive if *a > *b.
 */
WS_DLL_PUBLIC
int
wmem_compare_int(const void *a, const void *b);

/**
 * @brief Generic GCompareFunc to compare two unsigned integers.
 *
 * Casts both `a` and `b` to `const guint*` and returns the result of their comparison.
 * This function is suitable for use with sorting or searching routines that accept
 * a `GCompareFunc`.
 *
 * @param a Pointer to the first unsigned integer.
 * @param b Pointer to the second unsigned integer.
 * @return Negative if *a < *b, zero if *a == *b, positive if *a > *b.
 */
WS_DLL_PUBLIC
int
wmem_compare_uint(const void *a, const void *b);

/**   @}
 *  @} */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WMEM_MISCUTL_H__ */

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
