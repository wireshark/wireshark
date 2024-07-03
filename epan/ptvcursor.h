/** @file
 *
 * Proto Tree TVBuff cursor
 * Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2000 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PTVCURSOR_H__
#define __PTVCURSOR_H__

#include <glib.h>
#include <epan/packet.h>
#include "ws_symbol_export.h"

#define SUBTREE_UNDEFINED_LENGTH -1

typedef struct ptvcursor ptvcursor_t;

/* Allocates an initializes a ptvcursor_t with 3 variables:
 * proto_tree, tvbuff, and offset. */
WS_DLL_PUBLIC
ptvcursor_t*
ptvcursor_new(wmem_allocator_t *scope, proto_tree* tree, tvbuff_t* tvb, int offset);

/* Gets data from tvbuff, adds it to proto_tree, increments offset,
 * and returns proto_item* */
WS_DLL_PUBLIC
proto_item*
ptvcursor_add(ptvcursor_t* ptvc, int hf, int length, const unsigned encoding);

/* Gets data from tvbuff, adds it to proto_tree, increments offset,
 * and returns proto_item* and uint value retrieved*/
WS_DLL_PUBLIC
proto_item*
ptvcursor_add_ret_uint(ptvcursor_t* ptvc, int hf, int length, const unsigned encoding, uint32_t *retval);

/* Gets data from tvbuff, adds it to proto_tree, increments offset,
 * and returns proto_item* and int value retrieved */
WS_DLL_PUBLIC
proto_item*
ptvcursor_add_ret_int(ptvcursor_t* ptvc, int hf, int length, const unsigned encoding, int32_t *retval);

/* Gets data from tvbuff, adds it to proto_tree, increments offset,
 * and returns proto_item* and string value retrieved */
WS_DLL_PUBLIC
proto_item*
ptvcursor_add_ret_string(ptvcursor_t* ptvc, int hf, int length, const unsigned encoding, wmem_allocator_t *scope, const uint8_t **retval);

/* Gets data from tvbuff, adds it to proto_tree, increments offset,
 * and returns proto_item* and boolean value retrieved */
WS_DLL_PUBLIC
proto_item*
ptvcursor_add_ret_boolean(ptvcursor_t* ptvc, int hf, int length, const unsigned encoding, bool *retval);

/* Gets data from tvbuff, adds it to proto_tree, *DOES NOT* increment
 * offset, and returns proto_item* */
WS_DLL_PUBLIC
proto_item*
ptvcursor_add_no_advance(ptvcursor_t* ptvc, int hf, int length, const unsigned encoding);

/* Advance the ptvcursor's offset within its tvbuff without
 * adding anything to the proto_tree. */
WS_DLL_PUBLIC
void
ptvcursor_advance(ptvcursor_t* ptvc, int length);

/* Frees memory for ptvcursor_t, but nothing deeper than that. */
WS_DLL_PUBLIC
void
ptvcursor_free(ptvcursor_t* ptvc);

/* Returns tvbuff. */
WS_DLL_PUBLIC
tvbuff_t*
ptvcursor_tvbuff(ptvcursor_t* ptvc);

/* Returns current offset. */
WS_DLL_PUBLIC
int
ptvcursor_current_offset(ptvcursor_t* ptvc);

/* Returns the proto_tree* */
WS_DLL_PUBLIC
proto_tree*
ptvcursor_tree(ptvcursor_t* ptvc);

/* Sets a new proto_tree* for the ptvcursor_t */
WS_DLL_PUBLIC
void
ptvcursor_set_tree(ptvcursor_t* ptvc, proto_tree* tree);

/* push a subtree in the tree stack of the cursor */
WS_DLL_PUBLIC
proto_tree*
ptvcursor_push_subtree(ptvcursor_t* ptvc, proto_item* it, int ett_subtree);

/* pop a subtree in the tree stack of the cursor */
WS_DLL_PUBLIC
void
ptvcursor_pop_subtree(ptvcursor_t* ptvc);

/* Add an item to the tree and create a subtree
 * If the length is unknown, length may be defined as SUBTREE_UNDEFINED_LENGTH.
 * In this case, when the subtree will be closed, the parent item length will
 * be equal to the advancement of the cursor since the creation of the subtree.
 */
WS_DLL_PUBLIC
proto_tree*
ptvcursor_add_with_subtree(ptvcursor_t* ptvc, int hfindex, int length,
    const unsigned encoding, int ett_subtree);

/* Add a text node to the tree and create a subtree
 * If the length is unknown, length may be defined as SUBTREE_UNDEFINED_LENGTH.
 * In this case, when the subtree will be closed, the item length will be equal
 * to the advancement of the cursor since the creation of the subtree.
 */
WS_DLL_PUBLIC
proto_tree*
ptvcursor_add_text_with_subtree(ptvcursor_t* ptvc, int length,
    int ett_subtree, const char* format, ...)
    G_GNUC_PRINTF(4, 5);

/* Creates a subtree and adds it to the cursor as the working tree but does not
 * save the old working tree */
WS_DLL_PUBLIC
proto_tree*
ptvcursor_set_subtree(ptvcursor_t* ptvc, proto_item* it, int ett_subtree);

#endif /* __PTVCURSOR_H__ */
