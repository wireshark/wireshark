/** @file
 *
 * Definitions for the Wireshark Memory Manager Red-Black Tree
 * Copyright 2013, Evan Huus <eapache@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WMEM_TREE_INT_H__
#define __WMEM_TREE_INT_H__

#include "wmem_tree.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Enumeration of node colors used in red-black trees.
 *
 * Red-black trees use node coloring to maintain balance during insertions and deletions.
 * This enum defines the two possible colors for tree nodes.
 */
typedef enum _wmem_node_color_t {
    WMEM_NODE_COLOR_RED,   /**< Node is colored red. */
    WMEM_NODE_COLOR_BLACK  /**< Node is colored black. */
} wmem_node_color_t;


/**
 * @brief Internal node structure for a wmem balanced tree.
 *
 * This structure represents a node in a red-black tree used by the wmem subsystem
 * for efficient key-based storage and retrieval. It supports hierarchical organization,
 * subtree tracking, and logical removal.
 */
struct _wmem_tree_node_t {
    struct _wmem_tree_node_t *parent; /**< Pointer to the parent node. */
    struct _wmem_tree_node_t *left;   /**< Pointer to the left child node. */
    struct _wmem_tree_node_t *right;  /**< Pointer to the right child node. */

    const void *key;  /**< Pointer to the key associated with this node. */
    void *data;       /**< Pointer to the value or payload stored in this node. */

    wmem_node_color_t color; /**< Node color for red-black balancing (e.g., red or black). */
    bool is_subtree;         /**< True if this node represents a subtree root. */
    bool is_removed;         /**< True if this node has been logically removed. */
};

/**
 * @typedef wmem_tree_node_t
 * @brief Opaque type representing a node in a red-black tree.
 *
 * `wmem_tree_node_t` is used internally by the wmem tree implementation to store
 * key-value pairs and maintain tree structure and balance.
 */
typedef struct _wmem_tree_node_t wmem_tree_node_t;

/**
 * @typedef wmem_itree_node_t
 * @brief Opaque type representing a node in an interval tree.
 *
 * `wmem_itree_node_t` extends `wmem_tree_node_t` to support range-based indexing,
 * typically used in multimap structures for request/response matching by frame number.
 */
typedef struct _wmem_itree_node_t wmem_itree_node_t;


/**
 * @brief Internal representation of a wmem balanced tree.
 *
 * This structure manages a red-black tree used for efficient key-based storage
 * and retrieval within the wmem memory management system. It supports scoped
 * allocation, metadata separation, and optional post-rotation callbacks for
 * advanced tree manipulation.
 */
struct _wmem_tree_t {
    wmem_allocator_t *metadata_allocator; /**< Allocator for tree metadata (e.g., nodes, keys). */
    wmem_allocator_t *data_allocator;     /**< Allocator for stored data values. */
    wmem_tree_node_t *root;               /**< Root node of the red-black tree. */

    unsigned metadata_scope_cb_id;        /**< Callback ID for metadata scope lifecycle management. */
    unsigned data_scope_cb_id;            /**< Callback ID for data scope lifecycle management. */

    void (*post_rotation_cb)(wmem_tree_node_t *); /**< Optional callback invoked after tree rotations. */
};

/**
 * @typedef compare_func
 * @brief Function pointer type for comparing two values.
 *
 * Used to define custom comparison logic for sorting, searching, or ordering
 * operations. The function should return:
 * - A negative value if `a` is less than `b`
 * - Zero if `a` is equal to `b`
 * - A positive value if `a` is greater than `b`
 *
 * @param a Pointer to the first value.
 * @param b Pointer to the second value.
 * @return Integer indicating the relative order of `a` and `b`.
 */
typedef int (*compare_func)(const void *a, const void *b);

/**
 * @brief Insert a key-value pair into a wmem red-black tree and return the new node.
 *
 * Inserts a new node into the specified `wmem_tree_t` using the provided `key` and `data`.
 * If a custom comparison function `cmp` is provided, it overrides the default key comparison.
 * The tree remains balanced after insertion, ensuring O(log n) performance.
 *
 * @param tree Pointer to the red-black tree to insert into.
 * @param key Pointer to the key used for ordering within the tree.
 * @param data Pointer to the value associated with the key.
 * @param cmp Optional comparison function for custom key ordering. If NULL, default ordering is used.
 * @return Pointer to the newly inserted `wmem_tree_node_t`, or NULL on failure.
 */
wmem_tree_node_t *
wmem_tree_insert_node(wmem_tree_t *tree, const void *key, void *data, compare_func cmp);

/**
 * @typedef wmem_range_t
 * @brief Opaque type representing a 32-bit interval range.
 *
 * `wmem_range_t` is used to represent a closed or half-open interval over
 * 32-bit integers, typically for indexing within interval trees.
 */
typedef struct _wmem_range_t wmem_range_t;

/**
 * @brief Check whether two 32-bit ranges overlap.
 *
 * Compares two `wmem_range_t` intervals and returns true if they intersect.
 * This is commonly used in interval tree lookups to identify overlapping ranges.
 *
 * @param r1 Pointer to the first range.
 * @param r2 Pointer to the second range.
 * @return true if the ranges overlap, false otherwise.
 */
bool
wmem_itree_range_overlap(const wmem_range_t *r1, const wmem_range_t *r2);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WMEM_TREE__INTERNALS_H__ */

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
