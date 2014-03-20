/* wmem_splay.h
 * Definitions for the Wireshark Memory Manager Splay Tree
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

#ifndef __WMEM_SPLAY_H__
#define __WMEM_SPLAY_H__

#include "wmem_core.h"
#include "wmem_tree.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @addtogroup wmem
 *  @{
 *    @defgroup wmem-splay Splay Tree
 *
 *    Binary trees are a well-known and popular device in computer science to
 *    handle storage of objects based on a search key or identity. The
 *    particular binary tree style implemented here is the splay tree, which
 *    has a large number of nice properties. It guarantees O(log(n)) amortized
 *    time per operation, and O(1) per operation for certain special access
 *    patterns. See https://en.wikipedia.org/wiki/Splay_tree
 *
 *    The version implemented here is known as "independent semi-splaying",
 *    which is a variant with the same properties but slightly better practical
 *    performance.
 *
 *    @{
 */

struct _wmem_splay_t;
typedef struct _wmem_splay_t wmem_splay_t;

/* like strcmp: 0 means a==b,
 * >0 means a>b
 * <0 means a<b
 */
typedef int (*wmem_compare_func)(const void *a, const void *b);

/** Creates a tree with the given allocator scope. When the scope is emptied,
 * the tree is fully destroyed. The given comparison function is used to compare
 * keys; it must provide a coherent ordering on the key-space for the tree to
 * work sensibly. It is permitted to pass NULL for the comparison function, in
 * which case the key pointer values will be compared directly (cast to
 * integers). */
WS_DLL_PUBLIC
wmem_splay_t *
wmem_splay_new(wmem_allocator_t *allocator, wmem_compare_func cmp)
G_GNUC_MALLOC;

/** Creates a tree with two allocator scopes. The base structure lives in the
 * master scope, however the data lives in the slave scope. Every time free_all
 * occurs in the slave scope the tree is transparently emptied without affecting
 * the location of the master structure.
 *
 * WARNING: None of the tree (even the part in the master scope) can be used
 * after the slave scope has been *destroyed*.
 *
 * The primary use for this function is to create trees that reset for each new
 * capture file that is loaded. This can be done by specifying wmem_epan_scope()
 * as the master and wmem_file_scope() as the slave.
 */
WS_DLL_PUBLIC
wmem_splay_t *
wmem_splay_new_autoreset(wmem_allocator_t *master, wmem_allocator_t *slave,
        wmem_compare_func cmp)
G_GNUC_MALLOC;

/** Returns true if the tree is empty (has no nodes). */
WS_DLL_PUBLIC
gboolean
wmem_splay_is_empty(const wmem_splay_t *tree);

/** Look up a node in the tree indexed by the given key. If no node is found
 * the function will return NULL.
 */
WS_DLL_PUBLIC
void *
wmem_splay_lookup(wmem_splay_t *tree, const void *key);

/** Look up a node in the tree indexed by the given key. Returns the node that
 * has the largest key that is less than or equal to the search key, or NULL if
 * no such node exists.
 */
WS_DLL_PUBLIC
void *
wmem_splay_lookup_le(wmem_splay_t *tree, const void *key);

/** Insert a node indexed by the given key.
 *
 * Value is a pointer to the structure you want to be able to retrieve by
 * searching for the same key later.
 *
 * NOTE: If you insert a node to a key that already exists in the tree this
 * function will simply overwrite the old value. If the structures you are
 * storing are allocated in a wmem pool this is not a problem as they will still
 * be freed with the pool. If you are managing them manually however, you must
 * either ensure each key is unique, or do a lookup before each insert.
 */
WS_DLL_PUBLIC
void
wmem_splay_insert(wmem_splay_t *tree, void *key, void *value);

/** Traverse the tree and call callback(value, userdata) for each value found.
 * Returns TRUE if the traversal was ended prematurely by the callback.
 */
WS_DLL_PUBLIC
gboolean
wmem_splay_foreach(wmem_splay_t* tree, wmem_foreach_func callback,
        void *user_data);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WMEM_SPLAY_H__ */

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
