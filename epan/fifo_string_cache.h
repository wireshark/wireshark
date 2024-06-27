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
#ifndef __FIFO_STRING_CACHE_H__
#define __FIFO_STRING_CACHE_H__

#include <stdbool.h>

#include <glib.h>

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct {
    GHashTable          *set;
    GSList              *head;
    GSList              *tail;
    unsigned            max_entries;
} fifo_string_cache_t;

// These functions are marked with WS_DLL_PUBLIC so they can be unit-tested

// Initialize an object. If string_free_func is given, then the
// fifo_string_cache owns the string data, and will call this string_free_func
// during fifo_string_cache_free().
// If string_free_func is NULL, then the caller owns the string data, and it is
// the caller that is responsible for freeing the data.
WS_DLL_PUBLIC void
fifo_string_cache_init(fifo_string_cache_t *fcache, unsigned max_entries, GDestroyNotify string_free_func);

// Free all memory owned by the fifo_string_cache. Whether or not the
// fifoe_string_cache owns the actual strings depends on whether a
// string_free_func was passed in during fifo_string_cache_init().
WS_DLL_PUBLIC void
fifo_string_cache_free(fifo_string_cache_t *fcache);

// Does the cache contain a specific string?
WS_DLL_PUBLIC bool
fifo_string_cache_contains(fifo_string_cache_t *fcache, const char *entry);

// Insert a string. The return value indicates whether the string was already
// in the cache before this function was called. If the string was newly
// inserted, and max_entries is > 0, and inserting the string would have caused
// max_entries to be exceeded, the oldest inserted key is removed (FIFO order).
WS_DLL_PUBLIC bool
fifo_string_cache_insert(fifo_string_cache_t *fcache, const char *entry);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __FIFO_STRING_CACHE_H__ */
