/* fifo_string_cache.h
 * A string cache, possibly with a bounded size, using FIFO order to control
 * the size.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include <stdbool.h>

#include <glib.h>

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * A string cache with FIFO eviction. The cache tracks insertion order so
 * that the oldest entry can be removed when max_entries is exceeded.
 */
typedef struct {
    GHashTable          *set;           /**< Hash table for O(1) lookup. */
    GSList              *head;          /**< Head of the FIFO queue (oldest entry). */
    GSList              *tail;          /**< Tail of the FIFO queue (newest entry). */
    unsigned            max_entries;    /**< Maximum number of entries, or 0 for unlimited. */
} fifo_string_cache_t;

// These functions are marked with WS_DLL_PUBLIC so they can be unit-tested

/**
 * @brief Initialize a FIFO string cache.
 *
 * Initialize an object. If string_free_func is given, then the
 * fifo_string_cache owns the string data, and will call this string_free_func
 * during fifo_string_cache_free().
 * If string_free_func is NULL, then the caller owns the string data, and it is
 * the caller that is responsible for freeing the data.

 * @param fcache Pointer to the FIFO string cache structure.
 * @param max_entries Maximum number of entries in the cache.
 * @param string_free_func Function to free strings when they are no longer needed, or NULL if the cache does not own the strings.
 */
WS_DLL_PUBLIC void
fifo_string_cache_init(fifo_string_cache_t *fcache, unsigned max_entries, GDestroyNotify string_free_func);

/**
 * @brief Free all memory owned by the FIFO string cache.
 *
 * Free all memory owned by the fifo_string_cache. Whether or not the
 * fifo_string_cache owns the actual strings depends on whether a
 * string_free_func was passed in during fifo_string_cache_init().
 *
 * @param fcache The FIFO string cache.
 */
WS_DLL_PUBLIC void
fifo_string_cache_free(fifo_string_cache_t *fcache);

/**
 * @brief Checks if a string is contained in the FIFO string cache.
 *
 * @param fcache Pointer to the FIFO string cache.
 * @param entry The string to check for.
 * @return true if the string is already in the cache, false otherwise.
 */
WS_DLL_PUBLIC bool
fifo_string_cache_contains(fifo_string_cache_t *fcache, const char *entry);

/**
 * @brief Inserts a string into the FIFO string cache.
 *
 * Insert a string. The return value indicates whether the string was already
 * in the cache before this function was called. If the string was newly
 * inserted, and max_entries is > 0, and inserting the string would have caused
 * max_entries to be exceeded, the oldest inserted key is removed (FIFO order).
 *
 * @param fcache The FIFO string cache.
 * @param entry  The string to insert.
 * @return Whether the string was already in the cache.
 */
WS_DLL_PUBLIC bool
fifo_string_cache_insert(fifo_string_cache_t *fcache, const char *entry);

#ifdef __cplusplus
}
#endif /* __cplusplus */
