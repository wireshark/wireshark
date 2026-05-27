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

/**
 * @brief Discriminator indicating how a queued subdissector is to be invoked.
 */
typedef enum {
    NTVB_HANDLE, /**< Invoke a subdissector directly via a dissector_handle_t */
    NTVB_UINT,   /**< Look up and invoke a subdissector from a table using an unsigned integer key */
    NTVB_STRING  /**< Look up and invoke a subdissector from a table using a string key */
} next_tvb_call_e;

/** @brief Backward-compatibility alias; use NTVB_UINT for port-based table lookups. */
#define NTVB_PORT NTVB_UINT

/**
 * @brief A single queued subdissector call, forming a node in a next_tvb_list_t.
 */
typedef struct next_tvb_item {
    struct next_tvb_item *next;     /**< Pointer to the next item in the list, or NULL if last */
    struct next_tvb_item *previous; /**< Pointer to the previous item in the list, or NULL if first */
    next_tvb_call_e       type;     /**< Dispatch type controlling which union field and lookup method to use */
    dissector_handle_t    handle;   /**< Direct dissector handle; valid when type == NTVB_HANDLE */
    dissector_table_t     table;    /**< Dissector table for key-based lookup; valid when type == NTVB_UINT or NTVB_STRING */
    uint32_t              uint_val; /**< Unsigned integer lookup key (e.g., port number); valid when type == NTVB_UINT */
    const char           *string;   /**< String lookup key; valid when type == NTVB_STRING */
    tvbuff_t             *tvb;      /**< Buffer slice to pass to the subdissector */
    proto_tree           *tree;     /**< Protocol tree node under which the subdissector should add its items */
} next_tvb_item_t;

/**
 * @brief A doubly-linked list of queued subdissector calls with a shared memory pool.
 */
typedef struct {
    next_tvb_item_t  *first; /**< Pointer to the first item in the list, or NULL if empty */
    next_tvb_item_t  *last;  /**< Pointer to the last item in the list, or NULL if empty */
    wmem_allocator_t *pool;  /**< Memory allocator used for all items in this list */
    int               count; /**< Number of items currently in the list */
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
