/** @file
 *
 * Definitions for the Wireshark Memory Manager Queue
 * Copyright 2013, Evan Huus <eapache@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WMEM_QUEUE_H__
#define __WMEM_QUEUE_H__

#include <string.h>
#include <glib.h>

#include "wmem_core.h"
#include "wmem_list.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @addtogroup wmem
 *  @{
 *    @defgroup wmem-queue Queue
 *
 *    A queue implementation on top of wmem.
 *
 *    @{
 */

/**
 * @typedef wmem_queue_t
 * @brief A queue abstraction implemented as a wrapper over wmem_list_t.
 *
 * The wmem queue provides FIFO (first-in, first-out) semantics using the underlying
 * doubly-linked list structure (`wmem_list_t`). All queue operations are built on top
 * of list and stack functions for simplicity and consistency.
 */
typedef wmem_list_t wmem_queue_t;

/**
 * @def wmem_queue_count(X)
 * @brief Get the number of elements in a wmem queue.
 *
 * Returns the number of frames currently stored in the queue.
 * This macro maps directly to `wmem_list_count(X)`.
 *
 * @param X Pointer to a `wmem_queue_t`.
 * @return Number of elements in the queue.
 */
#define wmem_queue_count(X) wmem_list_count(X)


/**
 * @def wmem_queue_peek(QUEUE)
 * @brief Peek at the front element of a wmem queue without removing it.
 *
 * Returns the data pointer stored in the front frame of the queue.
 * This macro maps directly to `wmem_stack_peek(QUEUE)`.
 *
 * @param QUEUE Pointer to the `wmem_queue_t` to inspect.
 * @return Pointer to the data at the front of the queue, or `NULL` if empty.
 */
#define wmem_queue_peek(QUEUE) wmem_stack_peek(QUEUE)


/**
 * @def wmem_queue_pop(QUEUE)
 * @brief Remove and return the front element of a wmem queue.
 *
 * Removes the front frame from the queue and returns its data pointer.
 * This macro maps directly to `wmem_stack_pop(QUEUE)`.
 *
 * @param QUEUE Pointer to the `wmem_queue_t` to modify.
 * @return Pointer to the data that was at the front, or `NULL` if empty.
 */
#define wmem_queue_pop(QUEUE) wmem_stack_pop(QUEUE)


/**
 * @def wmem_queue_push(QUEUE, DATA)
 * @brief Add a data element to the end of a wmem queue.
 *
 * Appends the specified `DATA` pointer to the tail of the queue.
 * This macro maps directly to `wmem_list_append((QUEUE), (DATA))`.
 *
 * @param QUEUE Pointer to the `wmem_queue_t` to modify.
 * @param DATA Pointer to the data to enqueue.
 */
#define wmem_queue_push(QUEUE, DATA) wmem_list_append((QUEUE), (DATA))


/**
 * @def wmem_queue_new(ALLOCATOR)
 * @brief Create a new wmem queue using the specified memory allocator.
 *
 * Allocates and initializes a new `wmem_queue_t`, implemented as a wrapper over `wmem_list_t`.
 * This macro maps directly to `wmem_list_new(ALLOCATOR)`.
 *
 * @param ALLOCATOR Pointer to a `wmem_allocator_t` used for memory management.
 * @return Pointer to the newly created `wmem_queue_t`.
 */
#define wmem_queue_new(ALLOCATOR) wmem_list_new(ALLOCATOR)

/**
 * @def wmem_destroy_queue(QUEUE)
 * @brief Destroy a wmem queue and release its internal resources.
 *
 * Frees all internal memory associated with the given `wmem_queue_t`, including its frames.
 * This macro maps directly to `wmem_destroy_list(QUEUE)`.
 *
 * @note This does not free the data stored in the queue frames.
 *
 * @param QUEUE Pointer to the queue to destroy.
 */
#define wmem_destroy_queue(QUEUE) wmem_destroy_list(QUEUE)

/**   @}
 *  @} */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WMEM_QUEUE_H__ */

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
