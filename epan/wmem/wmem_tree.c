/* wmem_tree.c
 * Wireshark Memory Manager Red-Black Tree
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

#include "config.h"

#include <string.h>
#include <stdio.h>
#include <glib.h>

#include "wmem_core.h"
#include "wmem_strutl.h"
#include "wmem_tree.h"
#include "wmem_tree-int.h"
#include "wmem_user_cb.h"




static wmem_tree_node_t *
node_uncle(wmem_tree_node_t *node)
{
    wmem_tree_node_t *parent, *grandparent;

    parent = node->parent;
    if (parent == NULL) {
        return NULL;
    }

    grandparent = parent->parent;
    if (grandparent == NULL) {
        return NULL;
    }

    if (parent == grandparent->left) {
        return grandparent->right;
    }
    else {
        return grandparent->left;
    }
}

static void rb_insert_case1(wmem_tree_t *tree, wmem_tree_node_t *node);
static void rb_insert_case2(wmem_tree_t *tree, wmem_tree_node_t *node);

static void
rotate_left(wmem_tree_t *tree, wmem_tree_node_t *node)
{
    if (node->parent) {
        if (node->parent->left == node) {
            node->parent->left = node->right;
        }
        else {
            node->parent->right = node->right;
        }
    }
    else {
        tree->root = node->right;
    }

    node->right->parent = node->parent;
    node->parent        = node->right;
    node->right         = node->right->left;
    if (node->right) {
        node->right->parent = node;
    }
    node->parent->left = node;

    if (tree->post_rotation_cb) {
        tree->post_rotation_cb (node);
    }
}

static void
rotate_right(wmem_tree_t *tree, wmem_tree_node_t *node)
{
    if (node->parent) {
        if (node->parent->left == node) {
            node->parent->left = node->left;
        }
        else {
            node->parent->right = node->left;
        }
    }
    else {
        tree->root = node->left;
    }

    node->left->parent = node->parent;
    node->parent       = node->left;
    node->left         = node->left->right;
    if (node->left) {
        node->left->parent = node;
    }
    node->parent->right = node;


    if (tree->post_rotation_cb) {
        tree->post_rotation_cb (node);
    }
}

static void
rb_insert_case5(wmem_tree_t *tree, wmem_tree_node_t *node)
{
    wmem_tree_node_t *parent, *grandparent;

    parent      = node->parent;
    grandparent = parent->parent;

    parent->color      = WMEM_NODE_COLOR_BLACK;
    grandparent->color = WMEM_NODE_COLOR_RED;

    if (node == parent->left && parent == grandparent->left) {
        rotate_right(tree, grandparent);
    }
    else {
        rotate_left(tree, grandparent);
    }
}

static void
rb_insert_case4(wmem_tree_t *tree, wmem_tree_node_t *node)
{
    wmem_tree_node_t *parent, *grandparent;

    parent      = node->parent;
    grandparent = parent->parent;
    if (!grandparent) {
        return;
    }

    if (node == parent->right && parent == grandparent->left) {
        rotate_left(tree, parent);
        node = node->left;
    }
    else if (node == parent->left && parent == grandparent->right) {
        rotate_right(tree, parent);
        node = node->right;
    }

    rb_insert_case5(tree, node);
}

static void
rb_insert_case3(wmem_tree_t *tree, wmem_tree_node_t *node)
{
    wmem_tree_node_t *parent, *grandparent, *uncle;

    uncle = node_uncle(node);

    if (uncle && uncle->color == WMEM_NODE_COLOR_RED) {
        parent      = node->parent;
        grandparent = parent->parent;

        parent->color      = WMEM_NODE_COLOR_BLACK;
        uncle->color       = WMEM_NODE_COLOR_BLACK;
        grandparent->color = WMEM_NODE_COLOR_RED;

        rb_insert_case1(tree, grandparent);
    }
    else {
        rb_insert_case4(tree, node);
    }
}

static void
rb_insert_case2(wmem_tree_t *tree, wmem_tree_node_t *node)
{
    /* parent is always non-NULL here */
    if (node->parent->color == WMEM_NODE_COLOR_RED) {
        rb_insert_case3(tree, node);
    }
}

static void
rb_insert_case1(wmem_tree_t *tree, wmem_tree_node_t *node)
{
    wmem_tree_node_t *parent = node->parent;

    if (parent == NULL) {
        node->color = WMEM_NODE_COLOR_BLACK;
    }
    else {
        rb_insert_case2(tree, node);
    }
}

wmem_tree_t *
wmem_tree_new(wmem_allocator_t *allocator)
{
    wmem_tree_t *tree;

    tree = wmem_new(allocator, wmem_tree_t);
    tree->master    = allocator;
    tree->allocator = allocator;
    tree->root      = NULL;
    tree->post_rotation_cb = NULL;
    return tree;
}

static gboolean
wmem_tree_reset_cb(wmem_allocator_t *allocator _U_, wmem_cb_event_t event,
        void *user_data)
{
    wmem_tree_t *tree = (wmem_tree_t *)user_data;

    tree->root = NULL;

    if (event == WMEM_CB_DESTROY_EVENT) {
        wmem_unregister_callback(tree->master, tree->master_cb_id);
        wmem_free(tree->master, tree);
    }

    return TRUE;
}

static gboolean
wmem_tree_destroy_cb(wmem_allocator_t *allocator _U_, wmem_cb_event_t event _U_,
        void *user_data)
{
    wmem_tree_t *tree = (wmem_tree_t *)user_data;

    wmem_unregister_callback(tree->allocator, tree->slave_cb_id);

    return FALSE;
}

wmem_tree_t *
wmem_tree_new_autoreset(wmem_allocator_t *master, wmem_allocator_t *slave)
{
    wmem_tree_t *tree;

    tree = wmem_new(master, wmem_tree_t);
    tree->master    = master;
    tree->allocator = slave;
    tree->root      = NULL;
    tree->post_rotation_cb      = NULL;

    tree->master_cb_id = wmem_register_callback(master, wmem_tree_destroy_cb,
            tree);
    tree->slave_cb_id  = wmem_register_callback(slave, wmem_tree_reset_cb,
            tree);

    return tree;
}

gboolean
wmem_tree_is_empty(wmem_tree_t *tree)
{
    return tree->root == NULL;
}

static wmem_tree_node_t *
create_node(wmem_allocator_t *allocator, wmem_tree_node_t *parent, const void *key,
        void *data, wmem_node_color_t color, gboolean is_subtree)
{
    wmem_tree_node_t *node;

    node = wmem_new(allocator, wmem_tree_node_t);

    node->left   = NULL;
    node->right  = NULL;
    node->parent = parent;

    node->key  = key;
    node->data = data;

    node->color      = color;
    node->is_subtree = is_subtree;
    node->is_removed = FALSE;

    return node;
}

#define CREATE_DATA(TRANSFORM, DATA) ((TRANSFORM) ? (TRANSFORM)(DATA) : (DATA))


/**
 * return inserted node
 */
static wmem_tree_node_t *
lookup_or_insert32_node(wmem_tree_t *tree, guint32 key,
        void*(*func)(void*), void* data, gboolean is_subtree, gboolean replace)
{
    wmem_tree_node_t *node     = tree->root;
    wmem_tree_node_t *new_node = NULL;

    /* is this the first node ?*/
    if (!node) {
        new_node = create_node(tree->allocator, NULL, GUINT_TO_POINTER(key),
                CREATE_DATA(func, data), WMEM_NODE_COLOR_BLACK, is_subtree);
        tree->root = new_node;
        return new_node;
    }

    /* it was not the new root so walk the tree until we find where to
     * insert this new leaf.
     */
    while (!new_node) {
        /* this node already exists, so just return the data pointer*/
        if (key == GPOINTER_TO_UINT(node->key)) {
            if (replace) {
                node->data = CREATE_DATA(func, data);
            }
            return node;
        }
        else if (key < GPOINTER_TO_UINT(node->key)) {
            if (node->left) {
                node = node->left;
            }
            else {
                /* new node to the left */
                new_node = create_node(tree->allocator, node, GUINT_TO_POINTER(key),
                        CREATE_DATA(func, data), WMEM_NODE_COLOR_RED,
                        is_subtree);
                node->left = new_node;
            }
        }
        else if (key > GPOINTER_TO_UINT(node->key)) {
            if (node->right) {
                node = node->right;
            }
            else {
                /* new node to the right */
                new_node = create_node(tree->allocator, node, GUINT_TO_POINTER(key),
                        CREATE_DATA(func, data), WMEM_NODE_COLOR_RED,
                        is_subtree);
                node->right = new_node;
            }
        }
    }

    /* node will now point to the newly created node */
    rb_insert_case1(tree, new_node);

    return new_node;
}


static void *
lookup_or_insert32(wmem_tree_t *tree, guint32 key,
        void*(*func)(void*), void* data, gboolean is_subtree, gboolean replace)
{
    wmem_tree_node_t *node = lookup_or_insert32_node(tree, key, func, data, is_subtree, replace);
    return node->data;
}

static void *
wmem_tree_lookup(wmem_tree_t *tree, const void *key, compare_func cmp)
{
    wmem_tree_node_t *node;

    if (tree == NULL || key == NULL) {
        return NULL;
    }

    node = tree->root;

    while (node) {
        int result = cmp(key, node->key);
        if (result == 0) {
            return node->data;
        }
        else if (result < 0) {
            node = node->left;
        }
        else if (result > 0) {
            node = node->right;
        }
    }

    return NULL;
}

wmem_tree_node_t *
wmem_tree_insert(wmem_tree_t *tree, const void *key, void *data, compare_func cmp)
{
    wmem_tree_node_t *node = tree->root;
    wmem_tree_node_t *new_node = NULL;

    /* is this the first node ?*/
    if (!node) {
        tree->root = create_node(tree->allocator, node, key,
                data, WMEM_NODE_COLOR_BLACK, FALSE);
        return tree->root;
    }

    /* it was not the new root so walk the tree until we find where to
     * insert this new leaf.
     */
    while (!new_node) {
        int result = cmp(key, node->key);
        if (result == 0) {
            node->data = data;
            node->is_removed = data ? FALSE : TRUE;
            return node;
        }
        else if (result < 0) {
            if (node->left) {
                node = node->left;
            }
            else {
                new_node = create_node(tree->allocator, node, key,
                        data, WMEM_NODE_COLOR_RED, FALSE);
                node->left = new_node;
            }
        }
        else if (result > 0) {
            if (node->right) {
                node = node->right;
            }
            else {
                /* new node to the right */
                new_node = create_node(tree->allocator, node, key,
                        data, WMEM_NODE_COLOR_RED, FALSE);
                node->right = new_node;
            }
        }
    }

    /* node will now point to the newly created node */
    rb_insert_case1(tree, new_node);

    return new_node;
}

void
wmem_tree_insert32(wmem_tree_t *tree, guint32 key, void *data)
{
    lookup_or_insert32(tree, key, NULL, data, FALSE, TRUE);
}

void *
wmem_tree_lookup32(wmem_tree_t *tree, guint32 key)
{
    wmem_tree_node_t *node = tree->root;

    while (node) {
        if (key == GPOINTER_TO_UINT(node->key)) {
            return node->data;
        }
        else if (key < GPOINTER_TO_UINT(node->key)) {
            node = node->left;
        }
        else if (key > GPOINTER_TO_UINT(node->key)) {
            node = node->right;
        }
    }

    return NULL;
}

void *
wmem_tree_lookup32_le(wmem_tree_t *tree, guint32 key)
{
    wmem_tree_node_t *node = tree->root;

    while (node) {
        if (key == GPOINTER_TO_UINT(node->key)) {
            return node->data;
        }
        else if (key < GPOINTER_TO_UINT(node->key)) {
            if (node->left == NULL) {
                break;
            }
            node = node->left;
        }
        else if (key > GPOINTER_TO_UINT(node->key)) {
            if (node->right == NULL) {
                break;
            }
            node = node->right;
        }
    }

    if (!node) {
        return NULL;
    }

    /* If we are still at the root of the tree this means that this node
     * is either smaller than the search key and then we return this
     * node or else there is no smaller key available and then
     * we return NULL.
     */
    if (node->parent == NULL) {
        if (key > GPOINTER_TO_UINT(node->key)) {
            return node->data;
        } else {
            return NULL;
        }
    }

    if (GPOINTER_TO_UINT(node->key) <= key) {
        /* if our key is <= the search key, we have the right node */
        return node->data;
    }
    else if (node == node->parent->left) {
        /* our key is bigger than the search key and we're a left child,
         * we have to check if any of our ancestors are smaller. */
        while (node) {
            if (key > GPOINTER_TO_UINT(node->key)) {
                return node->data;
            }
            node=node->parent;
        }
        return NULL;
    }
    else {
        /* our key is bigger than the search key and we're a right child,
         * our parent is the one we want */
        return node->parent->data;
    }
}

void
wmem_tree_insert_string(wmem_tree_t* tree, const gchar* k, void* v, guint32 flags)
{
    char *key;
    compare_func cmp;

    key = wmem_strdup(tree->allocator, k);

    if (flags & WMEM_TREE_STRING_NOCASE) {
        cmp = (compare_func)g_ascii_strcasecmp;
    } else {
        cmp = (compare_func)strcmp;
    }

    wmem_tree_insert(tree, key, v, cmp);
}

void *
wmem_tree_lookup_string(wmem_tree_t* tree, const gchar* k, guint32 flags)
{
    compare_func cmp;

    if (flags & WMEM_TREE_STRING_NOCASE) {
        cmp = (compare_func)g_ascii_strcasecmp;
    } else {
        cmp = (compare_func)strcmp;
    }

    return wmem_tree_lookup(tree, k, cmp);
}

void *
wmem_tree_remove_string(wmem_tree_t* tree, const gchar* k, guint32 flags)
{
    void *ret = wmem_tree_lookup_string(tree, k, flags);
    if (ret) {
        /* Not really a remove, but set data to NULL to mark node with is_removed */
        wmem_tree_insert_string(tree, k, NULL, flags);
    }
    return ret;
}

static void *
create_sub_tree(void* d)
{
    return wmem_tree_new(((wmem_tree_t *)d)->allocator);
}

void
wmem_tree_insert32_array(wmem_tree_t *tree, wmem_tree_key_t *key, void *data)
{
    wmem_tree_t *insert_tree = NULL;
    wmem_tree_key_t *cur_key;
    guint32 i, insert_key32 = 0;

    for (cur_key = key; cur_key->length > 0; cur_key++) {
        for (i = 0; i < cur_key->length; i++) {
            /* Insert using the previous key32 */
            if (!insert_tree) {
                insert_tree = tree;
            } else {
                insert_tree = (wmem_tree_t *)lookup_or_insert32(insert_tree,
                        insert_key32, create_sub_tree, tree, TRUE, FALSE);
            }
            insert_key32 = cur_key->key[i];
        }
    }

    g_assert(insert_tree);

    wmem_tree_insert32(insert_tree, insert_key32, data);
}

static void *
wmem_tree_lookup32_array_helper(wmem_tree_t *tree, wmem_tree_key_t *key,
        void*(*helper)(wmem_tree_t*, guint32))
{
    wmem_tree_t *lookup_tree = NULL;
    wmem_tree_key_t *cur_key;
    guint32 i, lookup_key32 = 0;

    if (!tree || !key) {
        return NULL;
    }

    for (cur_key = key; cur_key->length > 0; cur_key++) {
        for (i = 0; i < cur_key->length; i++) {
            /* Lookup using the previous key32 */
            if (!lookup_tree) {
                lookup_tree = tree;
            }
            else {
                lookup_tree =
                    (wmem_tree_t *)(*helper)(lookup_tree, lookup_key32);
                if (!lookup_tree) {
                    return NULL;
                }
            }
            lookup_key32 = cur_key->key[i];
        }
    }

    /* Assert if we didn't get any valid keys */
    g_assert(lookup_tree);

    return (*helper)(lookup_tree, lookup_key32);
}

void *
wmem_tree_lookup32_array(wmem_tree_t *tree, wmem_tree_key_t *key)
{
    return wmem_tree_lookup32_array_helper(tree, key, wmem_tree_lookup32);
}

void *
wmem_tree_lookup32_array_le(wmem_tree_t *tree, wmem_tree_key_t *key)
{
    return wmem_tree_lookup32_array_helper(tree, key, wmem_tree_lookup32_le);
}

static gboolean
wmem_tree_foreach_nodes(wmem_tree_node_t* node, wmem_foreach_func callback,
        void *user_data)
{
    gboolean stop_traverse = FALSE;

    if (!node) {
        return FALSE;
    }

    if (node->left) {
        if (wmem_tree_foreach_nodes(node->left, callback, user_data)) {
            return TRUE;
        }
    }

    if (node->is_subtree) {
        stop_traverse = wmem_tree_foreach((wmem_tree_t *)node->data,
                callback, user_data);
    } else if (!node->is_removed) {
        /* No callback for "removed" nodes */
        stop_traverse = callback(node->key, node->data, user_data);
    }

    if (stop_traverse) {
        return TRUE;
    }

    if(node->right) {
        if (wmem_tree_foreach_nodes(node->right, callback, user_data)) {
            return TRUE;
        }
    }

    return FALSE;
}

gboolean
wmem_tree_foreach(wmem_tree_t* tree, wmem_foreach_func callback,
        void *user_data)
{
    if(!tree->root)
        return FALSE;

    return wmem_tree_foreach_nodes(tree->root, callback, user_data);
}

static void wmem_print_subtree(wmem_tree_t *tree, guint32 level, wmem_printer_func key_printer, wmem_printer_func data_printer);

static void
wmem_print_indent(guint32 level) {
    guint32 i;
    for (i=0; i<level; i++) {
        printf("    ");
    }
}

static void
wmem_tree_print_nodes(const char *prefix, wmem_tree_node_t *node, guint32 level,
    wmem_printer_func key_printer, wmem_printer_func data_printer)
{
    if (!node)
        return;

    wmem_print_indent(level);

    printf("%sNODE:%p parent:%p left:%p right:%p colour:%s key:%p %s:%p\n",
            prefix,
            (void *)node, (void *)node->parent,
            (void *)node->left, (void *)node->right,
            node->color?"Black":"Red", node->key,
            node->is_subtree?"tree":"data", node->data);
    if(key_printer) {
        wmem_print_indent(level);
        key_printer(node->key);
        printf("\n");
    }
    if(data_printer) {
        wmem_print_indent(level);
        data_printer(node->data);
        printf("\n");
    }

    if (node->left)
        wmem_tree_print_nodes("L-", node->left, level+1, key_printer, data_printer);
    if (node->right)
        wmem_tree_print_nodes("R-", node->right, level+1, key_printer, data_printer);

    if (node->is_subtree)
        wmem_print_subtree((wmem_tree_t *)node->data, level+1, key_printer, data_printer);
}


static void
wmem_print_subtree(wmem_tree_t *tree, guint32 level, wmem_printer_func key_printer, wmem_printer_func data_printer)
{
    if (!tree)
        return;

    wmem_print_indent(level);

    printf("WMEM tree:%p root:%p\n", (void *)tree, (void *)tree->root);
    if (tree->root) {
        wmem_tree_print_nodes("Root-", tree->root, level, key_printer, data_printer);
    }
}

void
wmem_print_tree(wmem_tree_t *tree, wmem_printer_func key_printer, wmem_printer_func data_printer)
{
    wmem_print_subtree(tree, 0, key_printer, data_printer);
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
