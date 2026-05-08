/** @file
 * Definitions for "next tvb" list
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
/* The buffers returned by these functions are all allocated with a
 * packet lifetime or are static buffers and does not have to be freed.
 * However, take into account that when the packet dissection
 * completes, these buffers will be automatically reclaimed/freed.
 * If you need the buffer to remain for a longer scope than packet lifetime
 * you must copy the content to an wmem_file_scope() buffer.
 */
#pragma once
#include "ws_symbol_export.h"
#include <epan/packet.h>

typedef enum {
  NTVB_HANDLE,
  NTVB_UINT,
  NTVB_STRING
} next_tvb_call_e;

/* For old code that hasn't yet been changed. */
#define NTVB_PORT	NTVB_UINT

typedef struct next_tvb_item {
  struct next_tvb_item *next;
  struct next_tvb_item *previous;
  next_tvb_call_e type;
  dissector_handle_t handle;
  dissector_table_t table;
  uint32_t uint_val;
  const char *string;
  tvbuff_t *tvb;
  proto_tree *tree;
} next_tvb_item_t;

typedef struct {
  next_tvb_item_t *first;
  next_tvb_item_t *last;
  wmem_allocator_t *pool;
  int count;
} next_tvb_list_t;

/**
 * @brief Create a new list for managing TVB items.
 *
 * @param pool Memory allocator to use for allocating the list.
 * @return Pointer to the newly created next_tvb_list_t structure.
 */
WS_DLL_PUBLIC next_tvb_list_t* next_tvb_list_new(wmem_allocator_t *pool);

/**
 * @brief Adds a dissector handle to the list.
 *
 * @param list The next_tvb_list_t structure where the item will be added.
 * @param tvb The tvbuff_t structure associated with the item.
 * @param tree The proto_tree structure associated with the item.
 * @param handle The dissector_handle_t to be added.
 */

WS_DLL_PUBLIC void next_tvb_add_handle(next_tvb_list_t *list, tvbuff_t *tvb, proto_tree *tree, dissector_handle_t handle);

/**
 * @brief Adds a uint value to the list.
 *
 * @param list The next_tvb_list_t structure where the item will be added.
 * @param tvb The tvbuff_t structure associated with the item.
 * @param tree The proto_tree structure associated with the item.
 * @param table The dissector_table_t to be used.
 * @param uint_val The uint32_t value to be added.
 */
WS_DLL_PUBLIC void next_tvb_add_uint(next_tvb_list_t *list, tvbuff_t *tvb, proto_tree *tree, dissector_table_t table, uint32_t uint_val);

 /**
 * @brief Adds a string to the list.
 *
 * @param list The next_tvb_list_t structure where the item will be added.
 * @param tvb The tvbuff_t structure associated with the item.
 * @param tree The proto_tree structure associated with the item.
 * @param table The dissector_table_t to be used.
 * @param string The const char* string to be added.
 */
WS_DLL_PUBLIC void next_tvb_add_string(next_tvb_list_t *list, tvbuff_t *tvb, proto_tree *tree, dissector_table_t table, const char *string);

/**
 * @brief Calls the dissector for each item in the list.
 *
 * @param list The next_tvb_list_t structure containing the items.
 * @param pinfo The packet_info structure for the current packet.
 * @param tree The proto_tree structure associated with the item.
 * @param handle The dissector_handle_t to be called.
 * @param data_handle The dissector_handle_t for the data dissector.
 */
WS_DLL_PUBLIC void next_tvb_call(next_tvb_list_t *list, packet_info *pinfo, proto_tree *tree, dissector_handle_t handle, dissector_handle_t data_handle);
