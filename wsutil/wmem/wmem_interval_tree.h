/** @file
 * Definitions for the Wireshark Memory Manager Red-Black Tree
 * Based on the red-black tree implementation in epan/emem.*
 * Copyright 2015, Matthieu coudron <matthieu.coudron@lip6.fr>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef __WMEM_INTERVAL_TREE_H__
#define __WMEM_INTERVAL_TREE_H__

#include "wmem_core.h"
#include "wmem_tree.h"
#include "wmem_list.h"


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @addtogroup wmem
 *  @{
 *    @defgroup wmem-interval-tree Interval Tree
 *
 * http://www.geeksforgeeks.org/interval-tree/
 * The idea is to augment a self-balancing Binary Search Tree (BST) like Red Black Tree, AVL Tree, etc ...
 * to maintain a set of intervals so that all operations can be done in O(Logn) time.
 *    @{
 * Following wikipedia's convention this is an augmented tree rather than an interval tree
 * http://www.wikiwand.com/en/Interval_tree
 */

struct _wmem_tree_t;

/**
 * @typedef wmem_itree_t
 * @brief Alias for a wmem interval tree.
 *
 * `wmem_itree_t` is an alias for `wmem_tree_t`, used when the tree stores
 * interval-based keys (e.g., ranges or spans). It supports efficient lookup
 * and insertion of overlapping intervals, commonly used in range-based indexing.
 */
typedef struct _wmem_tree_t wmem_itree_t;

/**
 * @brief Represents a numeric range used in wmem's internal range tree.
 *
 * This structure defines a half-open interval [low, high] and is used as a node
 * in a binary range tree. It supports efficient range queries and overlap detection.
 */
struct _wmem_range_t {
    uint64_t low;       /**< Lower bound of the range; used as the tree key. */
    uint64_t high;      /**< Upper bound of the range . */
    uint64_t max_edge;  /**< Maximum high value among all descendant nodes in the subtree. */
};


/**
 * @brief Create a new interval tree using the specified memory allocator.
 *
 * Allocates and initializes a new `wmem_itree_t` structure for managing intervals.
 * The tree is created using the provided `wmem_allocator_t`, which controls memory
 * allocation and cleanup.
 *
 * @param allocator Pointer to the memory allocator to use for tree allocation.
 * @return Pointer to the newly created interval tree.
 */
WS_DLL_PUBLIC
wmem_itree_t *
wmem_itree_new(wmem_allocator_t *allocator)
G_GNUC_MALLOC;


/**
 * @brief Check whether an interval tree is empty.
 *
 * Returns true if the tree is empty (has no nodes).
 *
 * @param tree Pointer to the interval tree to check.
 * @return `true` if the tree has no nodes, `false` otherwise.
 */
WS_DLL_PUBLIC
bool
wmem_itree_is_empty(wmem_itree_t *tree);


/**
 * @brief Insert an interval into the interval tree.
 *
 * Inserts a range defined by `[low, high]` into the given `wmem_itree_t` in O(log(n)) time.
 * The interval is indexed by its `low` value, and associated with the provided `data` pointer.
 * If an interval with the same `low` value already exists, it will be overwritten.
 *
 * @param tree Pointer to the interval tree.
 * @param low Lower bound of the interval (inclusive).
 * @param high Upper bound of the interval (inclusive).
 * @param data Pointer to user-defined data associated with the interval.
 */
WS_DLL_PUBLIC
void
wmem_itree_insert(wmem_itree_t *tree, const uint64_t low, const uint64_t high, void *data);


/**
 * @brief Find all intervals overlapping a given range in an interval tree.
 *
 * Searches the specified `wmem_itree_t` for all intervals that overlap with the range
 * `[low, high]`, and stores the results in a newly allocated `wmem_list_t` using the
 * provided `allocator`. The list is always created, even if no matching intervals are found.
 *
 * @param tree Pointer to the interval tree to search.
 * @param allocator Memory allocator used to allocate the result list.
 * @param low Lower bound of the search range (inclusive).
 * @param high Upper bound of the search range (inclusive).
 * @return A pointer to a `wmem_list_t` containing all overlapping intervals.
 */
WS_DLL_PUBLIC
wmem_list_t *
wmem_itree_find_intervals(wmem_itree_t *tree, wmem_allocator_t *allocator, uint64_t low, uint64_t high);


/**
 * @brief Print all intervals stored in the interval tree.
 *
 * Traverses the given `wmem_itree_t` and prints each stored interval range.
 * This is typically used for debugging or inspection purposes to visualize
 * the contents of the tree.
 *
 * @param tree Pointer to the interval tree to print.
 */
void
wmem_print_itree(wmem_itree_t *tree);

/**   @}
 *  @} */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WMEM_INTERVAL_TREE_H__ */

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
