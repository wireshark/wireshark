/* wmem_interval_tree.h
 * Definitions for the Wireshark Memory Manager Red-Black Tree
 * Based on the red-black tree implementation in epan/emem.*
 * Copyright 2015, Matthieu coudron <matthieu.coudron@lip6.fr>
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
 * Following wikipedia's convention this is an augmented tree rather then an interval tree
 * http://www.wikiwand.com/en/Interval_tree
 */

struct _wmem_tree_t;
typedef struct _wmem_tree_t wmem_itree_t;

struct _wmem_range_t {
    guint64 low;        /* low is used as the key in the binary tree */
    guint64 high;       /* Max value of the range */
    guint64 max_edge;   /* max value among subtrees */
};

WS_DLL_PUBLIC
wmem_itree_t *
wmem_itree_new(wmem_allocator_t *allocator)
G_GNUC_MALLOC;


/** Returns true if the tree is empty (has no nodes). */
WS_DLL_PUBLIC
gboolean
wmem_itree_is_empty(wmem_itree_t *tree);


/** Inserts a range low-high indexed by "low" in O(log(n)).
 * As in wmem_tree, if a key "low" already exists, it will be overwritten with the new data
 *
 */
WS_DLL_PUBLIC
void
wmem_itree_insert(wmem_itree_t *tree, const guint64 low, const guint64 high, void *data);


/*
 * Save results in a wmem_list with the scope passed as a parameter.
 * wmem_list_t is always allocated even if there is no result
 */
WS_DLL_PUBLIC
wmem_list_t *
wmem_itree_find_intervals(wmem_itree_t *tree, wmem_allocator_t *allocator, guint64 low, guint64 high);


/**
 * Print ranges along the tree
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
