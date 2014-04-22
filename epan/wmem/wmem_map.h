/* wmem_map.h
 * Definitions for the Wireshark Memory Manager Hash Map
 * Copyright 2014, Evan Huus <eapache@gmail.com>
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

#ifndef __WMEM_MAP_H__
#define __WMEM_MAP_H__

#include <glib.h>

#include "wmem_core.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @addtogroup wmem
 *  @{
 *    @defgroup wmem-map Hash Map
 *
 *    A hash map implementation on top of wmem. Provides insertion, deletion and
 *    lookup in expected amortized constant time. Uses universal hashing to map
 *    keys into buckets, and provides a generic strong hash function that makes
 *    it secure against algorithmic complexity attacks, and suitable for use
 *    even with untrusted data.
 *
 *    @{
 */

struct _wmem_map_t;
typedef struct _wmem_map_t wmem_map_t;

/** Creates a map with the given allocator scope. When the scope is emptied,
 * the map is fully destroyed. Items stored in it will not be freed unless they
 * were allocated from the same scope. For details on the GHashFunc and
 * GEqualFunc parameters, see the glib documentation at:
 * https://developer.gnome.org/glib/unstable/glib-Hash-Tables.html
 *
 * If the keys are coming from untrusted data, do *not* use glib's default hash
 * functions for strings, int64s or doubles. Wmem provides stronger equivalents
 * below. Feel free to use the g_direct_hash, g_int_hash, and any of the
 * g_*_equal functions though, as they should be safe.
 *
 * @param allocator The allocator scope with which to create the map.
 * @param hash_func The hash function used to place inserted keys.
 * @param eql_func  The equality function used to compare inserted keys.
 * @return The newly-allocated map.
 */
WS_DLL_PUBLIC
wmem_map_t *
wmem_map_new(wmem_allocator_t *allocator,
        GHashFunc hash_func, GEqualFunc eql_func)
G_GNUC_MALLOC;

/** Inserts a value into the map.
 *
 * @param map The map to insert into.
 * @param key The key to insert by.
 * @param value The value to insert.
 * @return The previous value stored at this key if any, or NULL.
 */
WS_DLL_PUBLIC
void *
wmem_map_insert(wmem_map_t *map, const void *key, void *value);

/** Lookup a value in the map.
 *
 * @param map The map to search in.
 * @param key The key to lookup.
 * @return The value stored at the key if any, or NULL.
 */
WS_DLL_PUBLIC
void *
wmem_map_lookup(wmem_map_t *map, const void *key);

/** Remove a value from the map. If no value is stored at that key, nothing
 * happens.
 *
 * @param map The map to remove from.
 * @param key The key of the value to remove.
 * @return The (removed) value stored at the key if any, or NULL.
 */
WS_DLL_PUBLIC
void *
wmem_map_remove(wmem_map_t *map, const void *key);


/** Compute a strong hash value for an arbitrary sequence of bytes. Use of this
 * hash value should be secure against algorithmic complexity attacks, even for
 * short keys. The computation uses a random seed which is generated on wmem
 * initialization, so the same key will hash to different values on different
 * runs of the application.
 *
 * @param buf The buffer of bytes (does not have to be aligned).
 * @param len The length of buf to use for the hash computation.
 * @return The hash value.
 */
WS_DLL_PUBLIC
guint32
wmem_strong_hash(const guint8 *buf, const size_t len);

/** An implementation of GHashFunc using wmem_strong_hash. Prefer this over
 * g_str_hash when the data comes from an untrusted source.
 */
WS_DLL_PUBLIC
guint
wmem_str_hash(gconstpointer key);

/** An implementation of GHashFunc using wmem_strong_hash. Prefer this over
 * g_int64_hash when the data comes from an untrusted source.
 */
WS_DLL_PUBLIC
guint
wmem_int64_hash(gconstpointer key);

/** An implementation of GHashFunc using wmem_strong_hash. Prefer this over
 * g_double_hash when the data comes from an untrusted source.
 */
WS_DLL_PUBLIC
guint
wmem_double_hash(gconstpointer key);

/**   @}
 *  @} */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WMEM_MAP_H__ */

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
