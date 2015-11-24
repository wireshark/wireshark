/* wmem_tree_internals.h
 * Definitions for the Wireshark Memory Manager Red-Black Tree
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

#ifndef __WMEM_TREE_INT_H__
#define __WMEM_TREE_INT_H__

#include <epan/wmem/wmem_tree.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum _wmem_node_color_t {
    WMEM_NODE_COLOR_RED,
    WMEM_NODE_COLOR_BLACK
} wmem_node_color_t;


struct _wmem_tree_node_t {
    struct _wmem_tree_node_t *parent;
    struct _wmem_tree_node_t *left;
    struct _wmem_tree_node_t *right;

    const void *key;
    void *data;

    wmem_node_color_t color;
    gboolean          is_subtree;
    gboolean          is_removed;


};

typedef struct _wmem_tree_node_t wmem_tree_node_t;


typedef struct _wmem_itree_node_t wmem_itree_node_t;

struct _wmem_tree_t {
    wmem_allocator_t *master;
    wmem_allocator_t *allocator;
    wmem_tree_node_t *root;
    guint             master_cb_id;
    guint             slave_cb_id;

    void (*post_rotation_cb)(wmem_tree_node_t *);
};

typedef int (*compare_func)(const void *a, const void *b);

wmem_tree_node_t *
wmem_tree_insert(wmem_tree_t *tree, const void *key, void *data, compare_func cmp);

typedef struct _wmem_range_t wmem_range_t;

gboolean
wmem_itree_range_overlap(const wmem_range_t *r1, const wmem_range_t *r2);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WMEM_TREE__INTERNALS_H__ */

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
