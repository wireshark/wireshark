/* wmem_tree.h
 * Definitions for the Wireshark Memory Manager Red-Black Tree
 * Based on the red-black tree implementation in epan/emem.*
 * Copyright 2013, Evan Huus <eapache@gmail.com>
 *
 * $Id$
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

#ifndef __WMEM_TREE_H__
#define __WMEM_TREE_H__

#include "wmem_core.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @addtogroup wmem
 *  @{
 *    @defgroup wmem-tree Red-Black Tree
 *
 *    A red-black tree implementation on top of wmem.
 *
 *    @{
 */

struct _wmem_tree_t;
typedef struct _wmem_tree_t wmem_tree_t;

/** Creates a tree with the given allocator scope */
WS_DLL_PUBLIC
wmem_tree_t *
wmem_tree_new(wmem_allocator_t *allocator)
G_GNUC_MALLOC;

/** Creates a tree with two allocator scopes. The base structure lives in the
 * master scope, however the data lives in the slave scope. Every time free_all
 * occurs in the slave scope the tree is transparently emptied without affecting
 * the location of the master structure.
 *
 * WARNING: None of the tree (even the part in the master scope) can be used
 * after the slave scope has been destroyed.
 */
WS_DLL_PUBLIC
wmem_tree_t *
wmem_tree_new_autoreset(wmem_allocator_t *master, wmem_allocator_t *slave)
G_GNUC_MALLOC;

/** Returns true if the tree is empty (has no nodes). */
WS_DLL_PUBLIC
gboolean
wmem_tree_is_empty(wmem_tree_t *tree);

/** Insert a node indexed by a guint32 key value. */
WS_DLL_PUBLIC
void
wmem_tree_insert32(wmem_tree_t *tree, guint32 key, void *data);

/** Look up a node in the tree indexed by a guint32 integer value */
WS_DLL_PUBLIC
void *
wmem_tree_lookup32(wmem_tree_t *tree, guint32 key);

/** Look up a node in the tree indexed by a guint32 integer value.
 * Returns the node that has the largest key that is less than or equal
 * to the search key, or NULL if no such key exists.
 */
WS_DLL_PUBLIC
void *
wmem_tree_lookup32_le(wmem_tree_t *tree, guint32 key);

/** case insensitive strings as keys */
#define WMEM_TREE_STRING_NOCASE			0x00000001
/** Insert a new value under a string key */
WS_DLL_PUBLIC
void
wmem_tree_insert_string(wmem_tree_t *tree, const gchar* key, void *data,
        guint32 flags);

/** Lookup the value under a string key */
WS_DLL_PUBLIC
void *
wmem_tree_lookup_string(wmem_tree_t* tree, const gchar* key, guint32 flags);

typedef struct _wmem_tree_key_t {
    guint32 length;    /**< length in guint32 words */
    guint32 *key;
} wmem_tree_key_t;

/** Insert a node indexed by a sequence of guint32 key values.
 *
 * Note: all the "key" members of the "key" argument MUST be aligned on
 * 32-bit boundaries; otherwise, this code will crash on platforms such
 * as SPARC that require aligned pointers.
 *
 * If you use ...32_array() calls you MUST make sure that every single node
 * you add to a specific tree always has a key of exactly the same number of
 * keylen words or things will most likely crash. Or at least that every single
 * item that sits behind the same top level node always have exactly the same
 * number of words.
 *
 * One way to guarantee this is the way that NFS does this for the
 * nfs_name_snoop_known tree which holds filehandles for both v2 and v3.
 * v2 filehandles are always 32 bytes (8 words) while v3 filehandles can have
 * any length (though 32 bytes are most common).
 * The NFS dissector handles this by providing a guint32 containing the length
 * as the very first item in this vector :
 *
 *			wmem_tree_key_t fhkey[3];
 *
 *			fhlen=nns->fh_length;
 *			fhkey[0].length=1;
 *			fhkey[0].key=&fhlen;
 *			fhkey[1].length=fhlen/4;
 *			fhkey[1].key=nns->fh;
 *			fhkey[2].length=0;
 */
WS_DLL_PUBLIC
void
wmem_tree_insert32_array(wmem_tree_t *tree, wmem_tree_key_t *key, void *data);

/** Look up a node in the tree indexed by a sequence of guint32 integer values.
 */
WS_DLL_PUBLIC
void *
wmem_tree_lookup32_array(wmem_tree_t *tree, wmem_tree_key_t *key);

/** Look up a node in the tree indexed by a multi-part tree value.
 * The function will return the node that has the largest key that is
 * equal to or smaller than the search key, or NULL if no such key was
 * found.
 * Note:  The key returned will be "less" in key order.  The usefullness
 * of the returned node must be verified prior to use.
 */
WS_DLL_PUBLIC
void *
wmem_tree_lookup32_array_le(wmem_tree_t *tree, wmem_tree_key_t *key);

/** traverse a tree. if the callback returns TRUE the traversal will end */
typedef gboolean (*wmem_foreach_func)(void *value, void *userdata);

WS_DLL_PUBLIC
gboolean
wmem_tree_foreach(wmem_tree_t* tree, wmem_foreach_func callback,
        void *user_data);

void
wmem_print_tree(wmem_tree_t *tree);

/**   @}
 *  @} */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WMEM_TREE_H__ */

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
