/* wmem_splay.c
 * Wireshark Memory Manager Splay Tree
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

/* Splay trees provide (sort of) balanced binary search trees that bubble
 * recently accessed keys to the top, and as such have a number of very nice
 * properties: https://en.wikipedia.org/wiki/Splay_tree
 *
 * This implementation is of a variant known as "independent semi-splaying",
 * as described in the 2008 paper by Brinkmann, Degraer and De Loof:
 * http://onlinelibrary.wiley.com/doi/10.1002/spe.886/abstract
 * Unfortunately I have not found a link to a public copy of this paper...
 *
 * Independent semi-splaying is a variant on Sleator and Tarjan's original splay
 * tree structure with better practical performance. It should do about as well
 * as a red-black tree for random insertions and accesses, but somewhat better
 * for patterned accesses (such as accessing each key in order, or accessing
 * certain keys very frequently).
 *
 * I took the opportunity of writing new code to make a few other changes
 * relative to the old red-black tree implementation:
 *  - Instead of requiring complex keys to be split into guint32 chunks and
 *    doing this weird radix-like trick with sub-trees, I let the keys be
 *    arbitrary pointers and allowed the user to specify an arbitrary comparison
 *    function. If the function is NULL then the pointers are compared directly
 *    for the simple integer-key case.
 *  - Splay trees do not need to store a red-black colour flag for each node.
 *    It is also much easier to do without the parent pointer in each node. And
 *    due to the simpler system for complex keys, I was able to remove the
 *    "is_subtree" boolean. As such, splay nodes are 12 bytes smaller on 32-bit
 *    platforms, and 16 bytes smaller on a 64-bit platform.
 */

#include "config.h"

#include <glib.h>

#include "wmem_core.h"
#include "wmem_splay.h"
#include "wmem_user_cb.h"

struct _wmem_splay_node_t {
    void *key, *value;
    struct _wmem_splay_node_t *left, *right;
};

typedef struct _wmem_splay_node_t wmem_splay_node_t;

struct _wmem_splay_t {
    wmem_allocator_t  *master;
    wmem_allocator_t  *allocator;
    guint              master_cb_id;
    guint              slave_cb_id;

    wmem_compare_func  cmp;

    wmem_splay_node_t *root;
};

static gboolean
wmem_splay_reset_cb(wmem_allocator_t *allocator _U_, wmem_cb_event_t event,
        void *user_data)
{
    wmem_splay_t *tree = (wmem_splay_t *)user_data;

    tree->root = NULL;

    if (event == WMEM_CB_DESTROY_EVENT) {
        wmem_unregister_callback(tree->master, tree->master_cb_id);
        wmem_free(tree->master, tree);
    }

    return TRUE;
}

static gboolean
wmem_splay_destroy_cb(wmem_allocator_t *allocator _U_, wmem_cb_event_t event _U_,
        void *user_data)
{
    wmem_splay_t *tree = (wmem_splay_t *)user_data;

    wmem_unregister_callback(tree->allocator, tree->slave_cb_id);

    return FALSE;
}

wmem_splay_t *
wmem_splay_new(wmem_allocator_t *allocator, wmem_compare_func cmp)
{
    wmem_splay_t *tree;

    tree = wmem_new(allocator, wmem_splay_t);
    tree->master    = allocator;
    tree->allocator = allocator;
    tree->root      = NULL;
    tree->cmp       = cmp;

    return tree;
}

wmem_splay_t *
wmem_splay_new_autoreset(wmem_allocator_t *master, wmem_allocator_t *slave,
        wmem_compare_func cmp)
{
    wmem_splay_t *tree;

    tree = wmem_new(master, wmem_splay_t);
    tree->master    = master;
    tree->allocator = slave;
    tree->root      = NULL;
    tree->cmp       = cmp;

    tree->master_cb_id = wmem_register_callback(master, wmem_splay_destroy_cb,
            tree);
    tree->slave_cb_id  = wmem_register_callback(slave, wmem_splay_reset_cb,
            tree);

    return tree;
}

gboolean
wmem_splay_is_empty(const wmem_splay_t *tree)
{
    return tree->root == NULL;
}

#define COMPARE(a, b)                        \
    (tree->cmp == NULL ?                     \
     GPOINTER_TO_INT(a)-GPOINTER_TO_INT(b) : \
     tree->cmp(a, b))

static void
wmem_splay_pred_succ(wmem_splay_t *tree, const void *key,
        wmem_splay_node_t **pred, wmem_splay_node_t **succ)
{
    wmem_splay_node_t *cur = tree->root;
    int cmp;

    if (pred != NULL) {
        *pred = NULL;
    }
    if (succ != NULL) {
        *succ = NULL;
    }

    while (cur != NULL) {
        cmp = COMPARE(key, cur->key);
        if (cmp == 0) {
            return;
        }
        else if (cmp < 0) {
            if (succ != NULL) {
                *succ = cur;
            }
            cur = cur->left;
        }
        else {
            if (pred != NULL) {
                *pred = cur;
            }
            cur = cur->right;
        }
    }
}

#define TRAVERSE(CUR, NXT, KEY)        \
do {                                   \
    if ((*CUR) == NULL) {              \
        return (CUR);                  \
    }                                  \
    cmp = COMPARE((KEY), (*CUR)->key); \
    if (cmp == 0) {                    \
        return (CUR);                  \
    }                                  \
    else if (cmp < 0) {                \
        (NXT) = &((*CUR)->left);       \
    }                                  \
    else {                             \
        (NXT) = &((*CUR)->right);      \
    }                                  \
} while (0)

#define ZIGZIG(CHILD, KEY)             \
do {                                   \
    tmp = *p;                          \
    *p = tmp->CHILD;                   \
    tmp->CHILD = *gp;                  \
    *gp = tmp;                         \
    cmp = COMPARE((KEY), (*cur)->key); \
    if (cmp == 0) {                    \
        return cur;                    \
    }                                  \
    else if (cmp < 0) {                \
        gp = &((*cur)->left);          \
    }                                  \
    else {                             \
        gp = &((*cur)->right);         \
    }                                  \
} while (0)

#define ZIGZAG(LEFT, RIGHT, KEY)    \
do {                                \
    tmp = *cur;                     \
    *cur = tmp->LEFT;               \
    tmp->LEFT = *p;                 \
    *p = tmp->RIGHT;                \
    tmp->RIGHT = *gp;               \
    *gp = tmp;                      \
    cmp = COMPARE((KEY), tmp->key); \
    if (cmp == 0) {                 \
        return gp;                  \
    }                               \
    else if (cmp < 0) {             \
        gp = &(tmp->left->right);   \
    }                               \
    else {                          \
        gp = &(tmp->right->left);   \
    }                               \
} while (0)

static wmem_splay_node_t **
wmem_splay_splay(wmem_splay_t *tree, const void *key)
{
    wmem_splay_node_t **gp, **p, **cur, *tmp;
    int cmp;

    gp = &(tree->root);

    while (TRUE) {
        TRAVERSE(gp, p,   key);
        TRAVERSE(p,  cur, key);

        if ((*cur) == NULL) {
            return cur;
        }

        if (p == &((*gp)->left)) {
            if (cur == &((*p)->left)) {
                ZIGZIG(right, key);
            }
            else {
                ZIGZAG(left, right, key);
            }
        }
        else {
            if (cur == &((*p)->right)) {
                ZIGZIG(left, key);
            }
            else {
                ZIGZAG(right, left, key);
            }
        }
    }
}

void *
wmem_splay_lookup(wmem_splay_t *tree, const void *key)
{
    wmem_splay_node_t **target;
    target = wmem_splay_splay(tree, key);

    if ((*target) == NULL) {
        return NULL;
    }

    return (*target)->value;
}

void *
wmem_splay_lookup_le(wmem_splay_t *tree, const void *key)
{
    wmem_splay_node_t *target;
    target = *(wmem_splay_splay(tree, key));

    if (target == NULL) {
        wmem_splay_pred_succ(tree, key, &target, NULL);
    }

    if (target == NULL) {
        return NULL;
    }

    return target->value;
}

void
wmem_splay_insert(wmem_splay_t *tree, void *key, void *value)
{
    wmem_splay_node_t **target;
    target = wmem_splay_splay(tree, key);

    if ((*target) == NULL) {
        *target = wmem_new(tree->allocator, wmem_splay_node_t);
        (*target)->key   = key;
        (*target)->value = value;
        (*target)->left  = NULL;
        (*target)->right = NULL;
    }
    else {
        (*target)->value = value;
    }
}

static gboolean
wmem_splay_foreach_node(wmem_splay_node_t* node, wmem_foreach_func callback,
        void *user_data)
{
    if (!node) {
        return FALSE;
    }

    if (node->left) {
        if (wmem_splay_foreach_node(node->left, callback, user_data)) {
            return TRUE;
        }
    }

    if (callback(node->value, user_data)) {
        return TRUE;
    }

    if(node->right) {
        if (wmem_splay_foreach_node(node->right, callback, user_data)) {
            return TRUE;
        }
    }

    return FALSE;
}

gboolean
wmem_splay_foreach(wmem_splay_t* tree, wmem_foreach_func callback,
        void *user_data)
{
    return wmem_splay_foreach_node(tree->root, callback, user_data);
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
