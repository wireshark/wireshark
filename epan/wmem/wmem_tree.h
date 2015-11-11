/* wmem_tree.h
 * Definitions for the Wireshark Memory Manager Red-Black Tree
 * Based on the red-black tree implementation in epan/emem.*
 * Copyright 2013, Evan Huus <eapache@gmail.com>
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
 *    @defgroup wmem-tree Red/Black Tree
 *
 *    Binary trees are a well-known and popular device in computer science to
 *    handle storage of objects based on a search key or identity. The
 *    particular binary tree style implemented here is the red/black tree, which
 *    has the nice property of being self-balancing. This guarantees O(log(n))
 *    time for lookups, compared to linked lists that are O(n). This means
 *    red/black trees scale very well when many objects are being stored.
 *
 *    @{
 */

struct _wmem_tree_t;
typedef struct _wmem_tree_t wmem_tree_t;

/** Creates a tree with the given allocator scope. When the scope is emptied,
 * the tree is fully destroyed. */
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
 * after the slave scope has been *destroyed*.
 *
 * The primary use for this function is to create trees that reset for each new
 * capture file that is loaded. This can be done by specifying wmem_epan_scope()
 * as the master and wmem_file_scope() as the slave.
 */
WS_DLL_PUBLIC
wmem_tree_t *
wmem_tree_new_autoreset(wmem_allocator_t *master, wmem_allocator_t *slave)
G_GNUC_MALLOC;

/** Returns true if the tree is empty (has no nodes). */
WS_DLL_PUBLIC
gboolean
wmem_tree_is_empty(wmem_tree_t *tree);

/** Insert a node indexed by a guint32 key value.
 *
 * Data is a pointer to the structure you want to be able to retrieve by
 * searching for the same key later.
 *
 * NOTE: If you insert a node to a key that already exists in the tree this
 * function will simply overwrite the old value. If the structures you are
 * storing are allocated in a wmem pool this is not a problem as they will still
 * be freed with the pool. If you are managing them manually however, you must
 * either ensure the key is unique, or do a lookup before each insert.
 */
WS_DLL_PUBLIC
void
wmem_tree_insert32(wmem_tree_t *tree, guint32 key, void *data);

/** Look up a node in the tree indexed by a guint32 integer value. If no node is
 * found the function will return NULL.
 */
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
#define WMEM_TREE_STRING_NOCASE                 0x00000001
/** Insert a new value under a string key. Like wmem_tree_insert32 but where the
 * key is a null-terminated string instead of a guint32. You may pass
 * WMEM_TREE_STRING_NOCASE to the flags argument in order to make it store the
 * key in a case-insensitive way.  (Note that "case-insensitive" refers
 * only to the ASCII letters A-Z and a-z; it is locale-independent.
 * Do not expect it to honor the rules of your language; for example, "I"
 * will always be mapped to "i". */
WS_DLL_PUBLIC
void
wmem_tree_insert_string(wmem_tree_t *tree, const gchar* key, void *data,
        guint32 flags);

/** Lookup the value under a string key, like wmem_tree_lookup32 but where the
 * keye is a null-terminated string instead of a guint32. See
 * wmem_tree_insert_string for an explanation of flags. */
WS_DLL_PUBLIC
void *
wmem_tree_lookup_string(wmem_tree_t* tree, const gchar* key, guint32 flags);

/** Remove the value under a string key.  This is not really a remove, but the
 * value is set to NULL so that wmem_tree_lookup_string not will find it.
 * See wmem_tree_insert_string for an explanation of flags. */
WS_DLL_PUBLIC
void *
wmem_tree_remove_string(wmem_tree_t* tree, const gchar* key, guint32 flags);

typedef struct _wmem_tree_key_t {
    guint32 length;    /**< length in guint32 words */
    guint32 *key;
} wmem_tree_key_t;

/** Insert a node indexed by a sequence of guint32 key values.
 *
 * Takes as key an array of guint32 vectors of type wmem_tree_key_t. It will
 * iterate through each key to search further down the tree until it reaches an
 * element where length==0, indicating the end of the array. You MUST terminate
 * the key array by {0, NULL} or this will crash.
 *
 * NOTE: length indicates the number of guint32 values in the vector, not the
 * number of bytes.
 *
 * NOTE: all the "key" members of the "key" argument MUST be aligned on
 * 32-bit boundaries; otherwise, this code will crash on platforms such
 * as SPARC that require aligned pointers.
 *
 * If you use ...32_array() calls you MUST make sure that every single node
 * you add to a specific tree always has a key of exactly the same number of
 * keylen words or it will crash. Or at least that every single item that sits
 * behind the same top level node always has exactly the same number of words.
 *
 * One way to guarantee this is the way that NFS does this for the
 * nfs_name_snoop_known tree which holds filehandles for both v2 and v3.
 * v2 filehandles are always 32 bytes (8 words) while v3 filehandles can have
 * any length (though 32 bytes are most common).
 * The NFS dissector handles this by providing a guint32 containing the length
 * as the very first item in this vector :
 *
 *                      wmem_tree_key_t fhkey[3];
 *
 *                      fhlen=nns->fh_length;
 *                      fhkey[0].length=1;
 *                      fhkey[0].key=&fhlen;
 *                      fhkey[1].length=fhlen/4;
 *                      fhkey[1].key=nns->fh;
 *                      fhkey[2].length=0;
 */
WS_DLL_PUBLIC
void
wmem_tree_insert32_array(wmem_tree_t *tree, wmem_tree_key_t *key, void *data);

/** Look up a node in the tree indexed by a sequence of guint32 integer values.
 * See wmem_tree_insert32_array for details on the key.
 */
WS_DLL_PUBLIC
void *
wmem_tree_lookup32_array(wmem_tree_t *tree, wmem_tree_key_t *key);

/** Look up a node in the tree indexed by a multi-part tree value.
 * The function will return the node that has the largest key that is
 * equal to or smaller than the search key, or NULL if no such key was
 * found.
 *
 * NOTE:  The key returned will be "less" in key order.  The usefulness
 * of the returned node must be verified prior to use.
 *
 * See wmem_tree_insert32_array for details on the key.
 */
WS_DLL_PUBLIC
void *
wmem_tree_lookup32_array_le(wmem_tree_t *tree, wmem_tree_key_t *key);

/** Function type for processing one node of a tree during a traversal. Value is
 * the value of the node, userdata is whatever was passed to the traversal
 * function. If the function returns TRUE the traversal will end prematurely.
 */
typedef gboolean (*wmem_foreach_func)(const void *key, void *value, void *userdata);


/** Function type to print key/data of nodes in wmem_print_tree_verbose */
typedef void (*wmem_printer_func)(const void *data);


/** Traverse the tree and call callback(value, userdata) for each value found.
 * Returns TRUE if the traversal was ended prematurely by the callback.
 */
WS_DLL_PUBLIC
gboolean
wmem_tree_foreach(wmem_tree_t* tree, wmem_foreach_func callback,
        void *user_data);


/* Accepts callbacks to print the key and/or data (both printers can be null) */
void
wmem_print_tree(wmem_tree_t *tree, wmem_printer_func key_printer, wmem_printer_func data_printer);

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
