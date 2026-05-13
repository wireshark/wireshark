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
#pragma once
#include <epan/packet.h>
#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SUBTREE_UNDEFINED_LENGTH -1

typedef struct ptvcursor ptvcursor_t;

/**
 * @brief Creates a new protocol tree cursor.
 *
 * Allocates and initializes a ptvcursor_t with the given proto_tree, tvbuff, and offset.
 *
 * @param scope Memory allocation scope for the cursor.
 * @param tree Protocol tree to which data will be added.
 * @param tvb Buffer containing the data to be dissected.
 * @param offset Initial offset within the buffer.
 * @return Pointer to the newly created ptvcursor_t.
 */
WS_DLL_PUBLIC
ptvcursor_t*
ptvcursor_new(wmem_allocator_t *scope, proto_tree* tree, tvbuff_t* tvb, unsigned offset);

/**
 * @brief Adds data from tvbuff to proto_tree and increments offset.
 *
 * Gets data from tvbuff, adds it to proto_tree, increments offset,
 * and returns proto_item*
 *
 * @param ptvc Pointer to ptvcursor_t structure.
 * @param hf Index of header field to use for adding data.
 * @param length Length of data to add.
 * @param encoding Encoding of the data.
 * @return proto_item* Pointer to the newly added proto_item.
 */
WS_DLL_PUBLIC
proto_item*
ptvcursor_add(ptvcursor_t* ptvc, int hf, int length, const unsigned encoding);

/**
 * @brief Adds a uint32_t value to the protocol tree and returns it.
 *
 * Gets data from tvbuff, adds it to proto_tree, increments offset,
 * and returns proto_item* and uint value retrieved
 *
 * @param ptvc Pointer to the protocol tree cursor.
 * @param hf Field ID for the new item.
 * @param length Length of the data to be added.
 * @param encoding Encoding type for the data.
 * @param retval Pointer to store the retrieved uint32_t value.
 * @return proto_item* Pointer to the newly created protocol item.
 */
WS_DLL_PUBLIC
proto_item*
ptvcursor_add_ret_uint(ptvcursor_t* ptvc, int hf, unsigned length, const unsigned encoding, uint32_t *retval);

/**
 * @brief Adds an integer value to the protocol tree and returns it.
 *
 * Gets data from tvbuff, adds it to proto_tree, increments offset,
 * and returns proto_item* and int value retrieved
 *
 * @param ptvc Pointer to the protocol tree cursor.
 * @param hf The field index for the new item.
 * @param length The length of the data to be added.
 * @param encoding The encoding type for the data.
 * @param retval Pointer to store the retrieved integer value.
 * @return proto_item* Pointer to the newly created protocol item.
 */
WS_DLL_PUBLIC
proto_item*
ptvcursor_add_ret_int(ptvcursor_t* ptvc, int hf, unsigned length, const unsigned encoding, int32_t *retval);

/**
 * @brief Adds a string to the protocol tree and returns the proto_item* and the retrieved string value.
 *
 * Gets data from tvbuff, adds it to proto_tree, increments offset,
 * and returns proto_item* and string value retrieved
 *
 * @param ptvc Pointer to the protocol tree cursor.
 * @param hf The field ID for the new item.
 * @param length The length of the data to be added.
 * @param encoding The encoding type of the data.
 * @param scope The memory allocator scope for the returned string.
 * @param retval Pointer to store the retrieved string value.
 * @return proto_item* Pointer to the newly created protocol tree item.
 */
WS_DLL_PUBLIC
proto_item*
ptvcursor_add_ret_string(ptvcursor_t* ptvc, int hf, int length, const unsigned encoding, wmem_allocator_t *scope, const uint8_t **retval);

/**
 * @brief Adds a boolean value to the protocol tree and returns it.
 *
 * Gets data from tvbuff, adds it to proto_tree, increments offset,
 * and returns proto_item* and boolean value retrieved
 *
 * @param ptvc Pointer to the protocol tree cursor.
 * @param hf The header field index for the item.
 * @param length The length of the data to be added.
 * @param encoding The encoding type of the data.
 * @param retval Pointer to store the retrieved boolean value.
 * @return proto_item* Pointer to the newly created protocol item.
 */
WS_DLL_PUBLIC
proto_item*
ptvcursor_add_ret_boolean(ptvcursor_t* ptvc, int hf, unsigned length, const unsigned encoding, bool *retval);

/**
 * @brief Adds a new item to the protocol tree without advancing the cursor.
 *
 * Gets data from tvbuff, adds it to proto_tree, *DOES NOT* increment
 * offset, and returns proto_item
 *
 * @param ptvc Pointer to the protocol tree cursor.
 * @param hf Field identifier for the new item.
 * @param length Length of the data to be added.
 * @param encoding Encoding type for the data.
 */
WS_DLL_PUBLIC
proto_item*
ptvcursor_add_no_advance(ptvcursor_t* ptvc, int hf, int length, const unsigned encoding);

/**
 * @brief Advances the ptvcursor's offset within its tvbuff without
 * adding anything to the proto_tree.
 *
 * @param ptvc Pointer to the protocol tree cursor.
 * @param length The amount to advance the offset.
 */
WS_DLL_PUBLIC
void
ptvcursor_advance(ptvcursor_t* ptvc, unsigned length);

/**
 * @brief Frees a ptvcursor_t structure.
 *
 * Frees memory for ptvcursor_t, but nothing deeper than that.
 *
 * @param ptvc Pointer to the ptvcursor_t structure to be freed.
 */
WS_DLL_PUBLIC
void
ptvcursor_free(ptvcursor_t* ptvc);

/**
 * @brief Retrieves the tvbuff associated with the protocol tree cursor.
 *
 * @param ptvc Pointer to the protocol tree cursor.
 * @return Pointer to the tvbuff associated with the cursor.
 */
WS_DLL_PUBLIC
tvbuff_t*
ptvcursor_tvbuff(ptvcursor_t* ptvc);

/**
 * @brief Returns the current offset in the protocol tree cursor.
 *
 * @param ptvc Pointer to the protocol tree cursor.
 * @return The current offset as a size_t value.
 */
WS_DLL_PUBLIC
unsigned
ptvcursor_current_offset(ptvcursor_t* ptvc);

/**
 * @brief Returns the current proto_tree associated with the ptvcursor.
 *
 * @param ptvc Pointer to the ptvcursor_t structure.
 * @return The current proto_tree*.
 */
WS_DLL_PUBLIC
proto_tree*
ptvcursor_tree(ptvcursor_t* ptvc);

/**
 * @brief Sets a new proto_tree* for the ptvcursor_t.
 *
 * @param ptvc Pointer to the ptvcursor_t structure.
 * @param tree Pointer to the proto_tree to be set.
 */
WS_DLL_PUBLIC
void
ptvcursor_set_tree(ptvcursor_t* ptvc, proto_tree* tree);

/**
 * @brief Pushes a subtree onto the tree stack of the cursor.
 *
 * @param ptvc Pointer to the protocol tree cursor.
 * @param it Protocol item for the subtree.
 * @param ett_subtree Expert Tree ID for the subtree.
 */
WS_DLL_PUBLIC
proto_tree*
ptvcursor_push_subtree(ptvcursor_t* ptvc, proto_item* it, int ett_subtree);

/**
 * @brief Pops a subtree from the protocol tree cursor.
 *
 * This function removes the most recently added subtree from the protocol tree cursor,
 * effectively closing it and returning to the parent context.
 *
 * @param ptvc Pointer to the protocol tree cursor.
 */
WS_DLL_PUBLIC
void
ptvcursor_pop_subtree(ptvcursor_t* ptvc);

/**
 * @brief Adds text with a subtree to the cursor.
 *
 * Add an item to the tree and create a subtree
 * If the length is unknown, length may be defined as SUBTREE_UNDEFINED_LENGTH.
 * In this case, when the subtree will be closed, the parent item length will
 * be equal to the advancement of the cursor since the creation of the subtree.
 *
 * @param ptvc Pointer to the protocol tree cursor.
 * @param hfindex The field index of the text node.
 * @param length The length of the text node. Use SUBTREE_UNDEFINED_LENGTH if unknown.
 * @param encoding The encoding of the text node.
 * @param ett_subtree The subtree ID for the new subtree.
 * @return A pointer to the created subtree.
 */
WS_DLL_PUBLIC
proto_tree*
ptvcursor_add_with_subtree(ptvcursor_t* ptvc, int hfindex, int length,
    const unsigned encoding, int ett_subtree);

/**
 * @brief Adds text with a subtree to the cursor.
 *
 * Add a text node to the tree and create a subtree
 * If the length is unknown, length may be defined as SUBTREE_UNDEFINED_LENGTH.
 * In this case, when the subtree will be closed, the item length will be equal
 * to the advancement of the cursor since the creation of the subtree.
 *
 * @param ptvc Pointer to the protocol tree cursor.
 * @param length Length of the text, or SUBTREE_UNDEFINED_LENGTH if unknown.
 * @param ett_subtree The ETT (Expert Tree Tag) for the subtree.
 * @param format Format string for the text.
 * @return proto_tree* Pointer to the created subtree.
 */
WS_DLL_PUBLIC
proto_tree*
ptvcursor_add_text_with_subtree(ptvcursor_t* ptvc, int length,
    int ett_subtree, const char* format, ...)
    G_GNUC_PRINTF(4, 5);

/**
 * @brief Sets a new subtree for the protocol tree cursor.
 *
 * Creates a subtree and adds it to the cursor as the working tree but does not
 * save the old working tree
 *
 * @param ptvc Pointer to the protocol tree cursor.
 * @param it Protocol item representing the subtree.
 * @param ett_subtree Expert Tree ID for the subtree.
 */
WS_DLL_PUBLIC
proto_tree*
ptvcursor_set_subtree(ptvcursor_t* ptvc, proto_item* it, int ett_subtree);

#ifdef __cplusplus
}
#endif
