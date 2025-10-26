/** @file
 *
 * Definitions for the Wireshark Memory Manager Hash Multimap
 * Copyright 2021, John Thacker <johnthacker@gmail.com>
 * Copyright 2014, Evan Huus <eapache@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WMEM_MULTIMAP_H__
#define __WMEM_MULTIMAP_H__

#include <glib.h>

#include "wmem_core.h"
#include "wmem_list.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @addtogroup wmem
 *  @{
 *    @defgroup wmem-multimap Hash Multimap
 *
 *    A hash multimap implementation on top of wmem_map and wmem_tree, storing
 *    multiple values at each hash key in a tree indexed by a 32 bit integer.
 *
 *    The primary use case is a protocol with an ID used as the hash lookup
 *    key that can be reused in a capture, and the frame number used as the
 *    tree key. We often want to find the most recent frame that had a certain
 *    ID, e.g. for request/response matching, and wmem_multimap_lookup32_le()
 *    serves that purpose.
 *
 *    Since the tree implementation is a self-balancing red-black tree, lookup
 *    time is still O(log(n)) even though elements with equivalent hash keys
 *    are usually added in increasing order of frame number.
 *
 *    NOTE: The multimap does not yet support inserting items without
 *    specifying the tree key, because the total capacity of individual trees
 *    (including deleted nodes) is not tracked.
 *
 *    @{
 */

/**
 * @typedef wmem_multimap_t
 * @brief Opaque type representing a hash multimap in the wmem system.
 *
 * `wmem_multimap_t` stores multiple values per hash key using a red-black tree
 * indexed by 32-bit integers. It is optimized for use cases like request/response
 * matching, where the same protocol ID may appear multiple times in a capture,
 * and frame numbers are used to distinguish and order entries.
 *
 * Use functions such as `wmem_multimap_insert32()` and `wmem_multimap_lookup32_le()`
 * to interact with this structure.
 */
typedef struct _wmem_multimap_t wmem_multimap_t;

/**
 * @brief Creates a multimap with the given allocator scope.
 *
 * When the scope is emptied,
 * the map is fully destroyed. Items stored in it will not be freed unless they
 * were allocated from the same scope.
 *
 * @param allocator The allocator scope with which to create the map.
 * @param hash_func The hash function used to place inserted keys.
 * @param eql_func  The equality function used to compare inserted keys.
 * @return The newly-allocated map.
 */
WS_DLL_PUBLIC
wmem_multimap_t *
wmem_multimap_new(wmem_allocator_t *allocator,
        GHashFunc hash_func, GEqualFunc eql_func)
G_GNUC_MALLOC;

/**
 * @brief Creates a multimap with two allocator scopes.
 *
 * The base structure lives in the
 * metadata scope, and the map data lives in the data scope. Every time free_all
 * occurs in the data scope the map is transparently emptied without affecting
 * the location of the base / metadata structure.
 *
 * WARNING: None of the map (even the part in the metadata scope) can be used
 * after the data scope has been *destroyed*.
 *
 * The primary use for this function is to create maps that reset for each new
 * capture file that is loaded. This can be done by specifying wmem_epan_scope()
 * as the metadata scope and wmem_file_scope() as the data scope.
 *
 * @param metadata_scope Pointer to the allocator used for the base structure.
 * @param data_scope Pointer to the allocator used for the map's key-value data.
 * @param hash_func The hash function used to place inserted keys.
 * @param eql_func The equality function used to compare inserted keys.
 * @return The newly-allocated map.
 */
WS_DLL_PUBLIC
wmem_multimap_t *
wmem_multimap_new_autoreset(wmem_allocator_t *metadata_scope, wmem_allocator_t *data_scope,
        GHashFunc hash_func, GEqualFunc eql_func)
G_GNUC_MALLOC;

/**
 * @brief Retrieves a list of the keys inside the multimap
 *
 * @param list_allocator The allocator scope for the returned list.
 * @param map The multimap to extract keys from
 * @return list of keys in the multimap
 */
WS_DLL_PUBLIC
wmem_list_t*
wmem_multimap_get_keys(wmem_allocator_t *list_allocator, const wmem_multimap_t *map);

/**
 * @brief Return the total number of elements in the multimap.
 *
 * @param map The multimap to use
 * @return the number of elements
*/
WS_DLL_PUBLIC
unsigned
wmem_multimap_size(const wmem_multimap_t *map);

/**
 * @brief Returns the number of values in the multimap with a certain hash key.
 *
 * Note: This is the number of current elements, so this can only be used to
 * safely generate unique tree keys prior to insertion if no values have been
 * removed, due to how the tree implementation works.
 *
 * @param map The multimap to search in.
 * @param key The primary key to lookup in the map.
 * @return The number of values in the tree stored at map key, or zero if no
 * tree exists at that key.
 */
WS_DLL_PUBLIC
unsigned
wmem_multimap_count(const wmem_multimap_t *map, const void *key);

/**
 * @brief Insert a value in the multimap.
 *
 * Note: as with wmem_tree, if there is already a node with the same pair
 * of keys, then the existing value will simply be overwritten. This is not
 * a problem if the value is wmem allocated, but if it is manually managed,
 * then you must ensure that the pair is unique or do a lookup before inserting.
 *
 * @param map The multimap to insert into.
 * @param key The key to insert by in the map.
 * @param frame_num The key to insert by in the tree.
 * @param value The value to insert.
 * @return true if there was already a tree mapped at key, in which case the
 * caller may safely free key. (This is not necessary if key is allocated with
 * a wmem pool.)
 */
WS_DLL_PUBLIC
bool
wmem_multimap_insert32(wmem_multimap_t *map, const void *key, uint32_t frame_num, void *value);

/**
 * @brief Lookup a value in the multimap combination with an exact match.
 *
 * @param map The multimap to search in.
 * @param key The primary key to lookup in the map.
 * @param frame_num The secondary key to lookup in the tree.
 * @return The value stored at the keys if any, or NULL.
 */
WS_DLL_PUBLIC
void *
wmem_multimap_lookup32(const wmem_multimap_t *map, const void *key, const uint32_t frame_num);

/**
 * @brief Lookup a value in the multimap with an exact match for the map key
 * and the largest value less than or equal to the tree key.
 *
 * This is
 * useful for request/response matching where IDs can be reused.
 *
 * @param map The multimap to search in.
 * @param key The primary key to lookup in the map.
 * @param frame_num The secondary key to lookup in the tree.
 * @return The value stored at the primary key in the map and with the largest
 * key in the tree that is less than or equal to the second key if any, or NULL.
 */
WS_DLL_PUBLIC
void *
wmem_multimap_lookup32_le(const wmem_multimap_t *map, const void *key, const uint32_t frame_num);

/**
 * @brief Remove a value from the multimap.
 *
 * If no value is stored at that key pair,
 * nothing happens. As with wmem_tree, this is not really a remove, but the
 * value is set to NULL so that wmem_multimap_lookup32 not will find it.
 *
 * @param map The multimap to remove from.
 * @param key The map key of the value to remove.
 * @param frame_num The tree key of the value to remove.
 * @return The (removed) value stored at the key if any, or NULL.
 */
WS_DLL_PUBLIC
void *
wmem_multimap_remove32(wmem_multimap_t *map, const void *key, const uint32_t frame_num);

/**   @}
 *  @} */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WMEM_MULTIMAP_H__ */

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
