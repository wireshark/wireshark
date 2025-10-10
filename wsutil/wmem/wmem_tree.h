/** @file
 * Definitions for the Wireshark Memory Manager Red-Black Tree
 * Based on the red-black tree implementation in epan/emem.*
 * Copyright 2013, Evan Huus <eapache@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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

/**
 * @brief Creates a tree with the given allocator scope. When the scope is emptied,
 * the tree is fully destroyed.
 *
 * @param allocator Allocator used for the tree.
 * @return A pointer to the newly created tree.
 */
WS_DLL_PUBLIC
wmem_tree_t *
wmem_tree_new(wmem_allocator_t *allocator);

/**
 * @brief Creates a tree with two allocator scopes.
 *
 * The base structure lives in the
 * metadata scope, and the tree data lives in the data scope. Every time free_all
 * occurs in the data scope the tree is transparently emptied without affecting
 * the location of the base / metadata structure.
 *
 * WARNING: None of the tree (even the part in the metadata scope) can be used
 * after the data scope has been *destroyed*.
 *
 * The primary use for this function is to create trees that reset for each new
 * capture file that is loaded. This can be done by specifying wmem_epan_scope()
 * as the metadata scope and wmem_file_scope() as the data scope.
 *
 * @param metadata_scope Allocator for the base structure and metadata.
 * @param data_scope Allocator for the tree data that resets on free_all.
 * @return A pointer to the newly created tree.
 */
WS_DLL_PUBLIC
wmem_tree_t *
wmem_tree_new_autoreset(wmem_allocator_t *metadata_scope, wmem_allocator_t *data_scope);

/**
 * @brief Cleanup memory used by tree.
 *
 * Intended for trees allocated with a NULL scope.
 *
 * @param tree Pointer to the tree to be destroyed.
 * @param free_keys If true, frees memory associated with keys.
 * @param free_values If true, frees memory associated with values.
 */
WS_DLL_PUBLIC
void
wmem_tree_destroy(wmem_tree_t *tree, bool free_keys, bool free_values);

/**
 * @brief Returns true if the tree is empty (has no nodes).
 *
 * @param tree Pointer to the tree to check.
 * @return True if the tree has no nodes, false otherwise.
 */
WS_DLL_PUBLIC
bool
wmem_tree_is_empty(const wmem_tree_t *tree);

/**
 * @brief Returns number of nodes in tree.
 *
 * @param tree Pointer to the tree whose nodes are to be counted.
 * @return The total number of nodes in the tree.
 */
WS_DLL_PUBLIC
unsigned
wmem_tree_count(const wmem_tree_t* tree);

/**
 * @brief Insert a node indexed by a uint32_t key value.
 *
 * Data is a pointer to the structure you want to be able to retrieve by
 * searching for the same key later.
 *
 * NOTE: If you insert a node to a key that already exists in the tree this
 * function will simply overwrite the old value. If the structures you are
 * storing are allocated in a wmem pool this is not a problem as they will still
 * be freed with the pool. If you are managing them manually however, you must
 * either ensure the key is unique, or do a lookup before each insert.
 *
 * @param tree Pointer to the tree where the node will be inserted.
 * @param key The uint32_t key used to index the node.
 * @param data Pointer to the data to associate with the key.
 */
WS_DLL_PUBLIC
void
wmem_tree_insert32(wmem_tree_t *tree, uint32_t key, void *data);

/**
 * @brief Look up a node in the tree indexed by a uint32_t integer value.
 *
 * @param tree Pointer to the tree to search.
 * @param key The uint32_t key to look up.
 * @return True if a node with the given key exists, false otherwise.
 */
WS_DLL_PUBLIC
bool
wmem_tree_contains32(const wmem_tree_t *tree, uint32_t key);

/**
 * @brief Look up a node in the tree indexed by a uint32_t integer value.
 *
 * If no node is found, the function will return NULL.
 *
 * @param tree Pointer to the tree to search.
 * @param key The uint32_t key to look up.
 * @return Pointer to the data associated with the key, or NULL if not found.
 */
WS_DLL_PUBLIC
void *
wmem_tree_lookup32(const wmem_tree_t *tree, uint32_t key);

/**
 * @brief Look up a node in the tree indexed by a uint32_t integer value.
 *
 * Returns the node that has the largest key that is less than or equal
 * to the search key, or NULL if no such key exists.
 *
 * @param tree Pointer to the tree to search.
 * @param key The uint32_t key used as the upper bound for the lookup.
 * @return Pointer to the data associated with the closest matching key, or NULL if none found.
 */
WS_DLL_PUBLIC
void *
wmem_tree_lookup32_le(const wmem_tree_t *tree, uint32_t key);

/**
 * @brief Look up a node in the tree indexed by a uint32_t integer value.
 *
 * Returns the node that has the largest key that is less than or equal
 * to the search key, or NULL if no such key exists. Also returns the
 * greatest lower bound key if it exists.
 *
 * @param tree Pointer to the tree to search.
 * @param key The uint32_t key used as the upper bound for the lookup.
 * @param orig_key Pointer to store the greatest lower bound key, if found.
 * @return Pointer to the data associated with the closest matching key, or NULL if none found.
 */
WS_DLL_PUBLIC
void *
wmem_tree_lookup32_le_full(const wmem_tree_t *tree, uint32_t key, uint32_t *orig_key);

/**
 * @brief Look up a node in the tree indexed by a uint32_t integer value.
 *
 * Returns the node that has the smallest key that is greater than or equal
 * to the search key, or NULL if no such key exists.
 *
 * @param tree Pointer to the tree to search.
 * @param key The uint32_t key used as the lower bound for the lookup.
 * @return Pointer to the data associated with the closest matching key, or NULL if none found.
 */
WS_DLL_PUBLIC
void *
wmem_tree_lookup32_ge(const wmem_tree_t *tree, uint32_t key);

/**
 * @brief Look up a node in the tree indexed by a uint32_t integer value.
 *
 * Returns the node that has the smallest key that is greater than or equal
 * to the search key, or NULL if no such key exists. Also returns the
 * least upper bound key if it exists.
 *
 * @param tree Pointer to the tree to search.
 * @param key The uint32_t key used as the upper bound for the lookup.
 * @param orig_key Pointer to store the greatest lower bound key, if found.
 * @return Pointer to the data associated with the closest matching key, or NULL if none found.
 */
WS_DLL_PUBLIC
void *
wmem_tree_lookup32_ge_full(const wmem_tree_t *tree, uint32_t key, uint32_t *orig_key);

/**
 * @brief Remove a node in the tree indexed by a uint32_t integer value.
 *
 * This is a real removal operation. The function returns the value stored at the given key.
 * If the tree memory is managed manually (i.e., with a NULL allocator), it is the caller's
 * responsibility to free the returned value.
 *
 * @param tree Pointer to the tree from which the node will be removed.
 * @param key The uint32_t key identifying the node to remove.
 * @return Pointer to the data that was stored at the key, or NULL if no such key exists.
 */
WS_DLL_PUBLIC
void *
wmem_tree_remove32(wmem_tree_t *tree, uint32_t key);

/** case insensitive strings as keys */
#define WMEM_TREE_STRING_NOCASE                 0x00000001

/**
 * @brief Insert a new value under a string key.
 *
 * Like wmem_tree_insert32 but where the key is a null-terminated string instead of a uint32_t.
 * You may pass WMEM_TREE_STRING_NOCASE to the flags argument in order to make it store the
 * key in a case-insensitive way. (Note that "case-insensitive" refers only to the ASCII letters
 * A-Z and a-z; it is locale-independent. Do not expect it to honor the rules of your language;
 * for example, "I" will always be mapped to "i".)
 *
 * @param tree Pointer to the tree where the node will be inserted.
 * @param key Null-terminated string key used to index the node.
 * @param data Pointer to the data to associate with the key.
 * @param flags Flags to control insertion behavior (e.g., case-insensitive key handling).
 */
WS_DLL_PUBLIC
void
wmem_tree_insert_string(wmem_tree_t *tree, const char* key, void *data,
        uint32_t flags);

/**
 * @brief Lookup the value under a string key.
 *
 * Similar to wmem_tree_lookup32 but uses a null-terminated string as the key.
 * See wmem_tree_insert_string for an explanation of flags.
 *
 * @param tree Pointer to the tree to search.
 * @param key Null-terminated string key to look up.
 * @param flags Flags to control lookup behavior (e.g., case-insensitive matching).
 * @return Pointer to the data associated with the key, or NULL if not found.
 */
WS_DLL_PUBLIC
void *
wmem_tree_lookup_string(const wmem_tree_t* tree, const char* key, uint32_t flags);

/**
 * @brief Remove the value under a string key.
 *
 * This is not a true removal; instead, the value is set to NULL so that
 * wmem_tree_lookup_string will no longer find it.
 * See wmem_tree_insert_string for an explanation of flags.
 *
 * @param tree Pointer to the tree from which the value will be removed.
 * @param key Null-terminated string key identifying the value to remove.
 * @param flags Flags to control removal behavior (e.g., case-insensitive matching).
 * @return Pointer to the data that was previously associated with the key, or NULL if not found.
 */
WS_DLL_PUBLIC
void *
wmem_tree_remove_string(wmem_tree_t* tree, const char* key, uint32_t flags);

typedef struct _wmem_tree_key_t {
    uint32_t length;    /**< length in uint32_t words */
    uint32_t *key;      /**< Pointer to the key data. */
} wmem_tree_key_t;

/**
 * @brief Insert a node indexed by a sequence of uint32_t key values.
 *
 * Takes as key an array of uint32_t vectors of type wmem_tree_key_t. It will
 * iterate through each key to search further down the tree until it reaches an
 * element where length==0, indicating the end of the array. You MUST terminate
 * the key array by {0, NULL} or this will crash.
 *
 * NOTE: length indicates the number of uint32_t values in the vector, not the
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
 * The NFS dissector handles this by providing a uint32_t containing the length
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
 *
 * @param tree Pointer to the tree where the node will be inserted.
 * @param key Array of wmem_tree_key_t structures representing the key sequence.
 * @param data Pointer to the data to associate with the key.
 */
WS_DLL_PUBLIC
void
wmem_tree_insert32_array(wmem_tree_t *tree, wmem_tree_key_t *key, void *data);

/**
 * @brief Look up a node in the tree indexed by a sequence of uint32_t integer values.
 *
 * See wmem_tree_insert32_array for details on the key format and usage.
 *
 * @param tree Pointer to the tree to search.
 * @param key Array of wmem_tree_key_t structures representing the key sequence.
 * @return Pointer to the data associated with the key, or NULL if not found.
 */
WS_DLL_PUBLIC
void *
wmem_tree_lookup32_array(const wmem_tree_t *tree, wmem_tree_key_t *key);

/**
 * @brief Look up a node in the tree indexed by a multi-part tree value.
 *
 * The function returns the node that has the largest key that is equal to or
 * smaller than the search key, or NULL if no such key was found.
 *
 * NOTE: The key returned will be "less" in key order. The usefulness of the
 * returned node must be verified prior to use.
 *
 * See wmem_tree_insert32_array for details on the key.
 *
 * @param tree Pointer to the tree to search.
 * @param key Array of wmem_tree_key_t structures representing the key sequence.
 * @return Pointer to the data associated with the closest matching key, or NULL if none found.
 */
WS_DLL_PUBLIC
void *
wmem_tree_lookup32_array_le(const wmem_tree_t *tree, wmem_tree_key_t *key);

/**
 * @brief Function type for processing one node of a tree during a traversal.
 *
 * This function is called for each node during a tree traversal. If the function
 * returns true, the traversal will end prematurely.
 *
 * @param key Pointer to the key of the current node.
 * @param value Pointer to the value of the current node.
 * @param userdata Pointer to user-defined data passed to the traversal function.
 * @return True to stop traversal early, false to continue.
 */
typedef bool (*wmem_foreach_func)(const void *key, void *value, void *userdata);


/**
 * @brief Function type to print key/data of nodes in wmem_print_tree_verbose.
 *
 * @param data Pointer to the data to be printed.
 */
typedef void (*wmem_printer_func)(const void *data);


/**
 * @brief Inorder traversal (left/parent/right) of the tree.
 *
 * Calls the provided callback function for each value found during traversal.
 * Traversal stops early if the callback returns true.
 *
 * @param tree Pointer to the tree to traverse.
 * @param callback Function to call for each node's value.
 * @param user_data Pointer to user-defined data passed to the callback.
 * @return True if traversal was ended prematurely by the callback, false otherwise.
 */
WS_DLL_PUBLIC
bool
wmem_tree_foreach(const wmem_tree_t* tree, wmem_foreach_func callback,
        void *user_data);


/**
 * @brief Print the contents of a tree using optional key and data printer callbacks.
 *
 * Accepts callbacks to print the key and/or data of each node. Either or both printer
 * functions may be NULL, in which case the corresponding output will be skipped.
 *
 * @param tree Pointer to the tree to print.
 * @param key_printer Callback function to print the key of each node (may be NULL).
 * @param data_printer Callback function to print the data of each node (may be NULL).
 */
WS_DLL_PUBLIC
void
wmem_print_tree(const wmem_tree_t *tree, wmem_printer_func key_printer, wmem_printer_func data_printer);

/**   @}
 *  @} */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WMEM_TREE_H__ */

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
