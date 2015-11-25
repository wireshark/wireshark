/* wmem_interval_tree.c
 * Implements an augmented interval tree
 * Based on the red-black tree implementation in epan/wmem.*
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

#include "config.h"

#include <string.h>
#include <stdio.h>
#include <glib.h>

#include "wmem_core.h"
#include "wmem_tree-int.h"
#include "wmem_strutl.h"
#include "wmem_interval_tree.h"
#include "wmem_user_cb.h"



static void
print_range(const void *value)
{
    wmem_range_t *range = (wmem_range_t *)value;
    if(!value) {
        return;
    }
    printf("Range: low=%" G_GUINT64_FORMAT " high=%" G_GUINT64_FORMAT " max_edge=%" G_GUINT64_FORMAT "\n", range->low, range->high, range->max_edge);
}

/**
 * In an augmented interval tree, each node saves the maximum edge of its child subtrees
 * This function compares the children max_edge with the current max_edge
 * and propagates any change to the parent nodes.
 */
static void
update_max_edge(wmem_tree_node_t *node)
{
    wmem_range_t *range;
    wmem_range_t *range_l;
    wmem_range_t *range_r;
    guint64 maxEdge  = 0;

    if(!node) {
        return ;
    }

    range = (wmem_range_t *)node->key;

    range_l = (node->left) ? (wmem_range_t *) (node->left->key) : NULL;
    range_r = (node->right) ? (wmem_range_t *) (node->right->key) : NULL;

    maxEdge = range->max_edge;

    if(range_r) {
        maxEdge = MAX(maxEdge, range_r->max_edge) ;
    }
    if(range_l) {
        maxEdge = MAX(maxEdge, range_l->max_edge) ;
    }

    /* a change was made, update the parent nodes */
    if(range->max_edge != maxEdge) {
        range->max_edge = maxEdge;
        update_max_edge(node->parent);
    }
}

gboolean
wmem_itree_range_overlap(const wmem_range_t *r1, const wmem_range_t *r2)
{
    return (r1->low <= r2->high && r2->low <= r1->high);
}

wmem_itree_t *
wmem_itree_new(wmem_allocator_t *allocator)
{
    wmem_itree_t *tree      = wmem_tree_new(allocator);
    tree->post_rotation_cb  = &update_max_edge;
    return tree;
}

gboolean
wmem_itree_is_empty(wmem_itree_t *tree)
{
    return wmem_tree_is_empty(tree);
}

static int
wmem_tree_compare_ranges(const wmem_range_t *ra, const wmem_range_t *rb)
{
    if( ra->low == rb->low) {
        return 0;
    }
    else if(ra->low < rb->low) {
        return -1;
    }
    else {
        return 1;
    }
}


void
wmem_itree_insert(wmem_itree_t *tree, const guint64 low, const guint64 high, void *data)
{
    wmem_tree_node_t *node;
    wmem_range_t *range = (wmem_range_t *)wmem_new(tree->allocator, wmem_range_t);

    g_assert(low <= high);
    range->low = low;
    range->high = high;
    range->max_edge = high;

    node = wmem_tree_insert(tree, range, data, (compare_func)wmem_tree_compare_ranges);

    /* Even If no rotations, still a need to update max_edge */
    update_max_edge(node);
}


static void
wmem_itree_find_intervals_in_subtree(wmem_tree_node_t *node, wmem_range_t requested, wmem_list_t *results)
{
    const wmem_range_t* current;

    if(!node) {
        return;
    }
    current = (wmem_range_t*)node->key;

    /* there is no child that can possibly match */
    if(requested.low > current->max_edge) {
        return;
    }

    if(wmem_itree_range_overlap(current, &requested)) {
        wmem_list_prepend(results, node->data);
    }

    wmem_itree_find_intervals_in_subtree(node->left, requested, results);
    wmem_itree_find_intervals_in_subtree(node->right, requested, results);
}

wmem_list_t *
wmem_itree_find_intervals(wmem_itree_t *tree, wmem_allocator_t *allocator, guint64 low, guint64 high)
{
    wmem_list_t *results = NULL;
    wmem_range_t requested = { low, high, 0 };
    results = wmem_list_new(allocator);

    wmem_itree_find_intervals_in_subtree(tree->root, requested, results);
    return results;
}


void
wmem_print_itree(wmem_tree_t *tree)
{
    wmem_print_tree(tree, &print_range, NULL);
}

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
