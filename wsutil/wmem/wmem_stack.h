/** @file
 * Definitions for the Wireshark Memory Manager Stack
 * Copyright 2012, Evan Huus <eapache@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WMEM_STACK_H__
#define __WMEM_STACK_H__

#include <string.h>
#include <glib.h>

#include "wmem_core.h"
#include "wmem_list.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @addtogroup wmem
 *  @{
 *    @defgroup wmem-stack Stack
 *
 *    A stack implementation on top of wmem.
 *
 *    @{
 */

/**
 * @typedef wmem_stack_t
 * @brief A stack abstraction implemented as a wrapper over wmem_list_t.
 *
 * The wmem stack provides LIFO (last-in, first-out) semantics using the underlying
 * doubly-linked list structure (`wmem_list_t`). All stack operations are built on top
 * of list functions for simplicity and consistency.
 */
typedef wmem_list_t wmem_stack_t;


/**
 * @def wmem_stack_count(X)
 * @brief Get the number of elements in a wmem stack.
 *
 * Returns the number of frames (elements) currently stored in the stack.
 * This macro maps directly to `wmem_list_count(X)`.
 *
 * @param X Pointer to a `wmem_stack_t`.
 * @return Number of elements in the stack.
 */
#define wmem_stack_count(X) wmem_list_count(X)

/**
 * @brief Peek at the top element of a wmem stack without removing it.
 *
 * Returns the data pointer stored in the top frame of the given `wmem_stack_t`.
 * If the stack is empty, the function returns `NULL`.
 *
 * @param stack Pointer to the stack to inspect.
 * @return Pointer to the data at the top of the stack, or `NULL` if the stack is empty.
 */
WS_DLL_PUBLIC
void *
wmem_stack_peek(const wmem_stack_t *stack);

/**
 * @brief Pop the top element from a wmem stack.
 *
 * Removes and returns the data pointer stored in the top frame of the given `wmem_stack_t`.
 * If the stack is empty, the function returns `NULL`.
 *
 * @param stack Pointer to the stack to modify.
 * @return Pointer to the data that was at the top of the stack, or `NULL` if the stack was empty.
 */
WS_DLL_PUBLIC
void *
wmem_stack_pop(wmem_stack_t *stack);

/**
 * @def wmem_stack_push(STACK, DATA)
 * @brief Push a data element onto the top of a wmem stack.
 *
 * Inserts the specified `DATA` pointer at the top of the given `wmem_stack_t`.
 * This macro maps directly to `wmem_list_prepend()`, maintaining LIFO semantics.
 *
 * @param STACK Pointer to the `wmem_stack_t` to modify.
 * @param DATA Pointer to the data to push onto the stack.
 */
#define wmem_stack_push(STACK, DATA) wmem_list_prepend((STACK), (DATA))

/**
 * @def wmem_stack_new(ALLOCATOR)
 * @brief Create a new wmem stack using the specified memory allocator.
 *
 * Allocates and initializes a new `wmem_stack_t`, which is implemented as a wrapper over `wmem_list_t`.
 * This macro maps directly to `wmem_list_new(ALLOCATOR)`.
 *
 * @param ALLOCATOR Pointer to a `wmem_allocator_t` used for memory management.
 * @return Pointer to the newly created `wmem_stack_t`.
 */
#define wmem_stack_new(ALLOCATOR) wmem_list_new(ALLOCATOR)

/**
 * @def wmem_destroy_stack(STACK)
 * @brief Destroy a wmem stack and release its internal resources.
 *
 * Frees all internal memory associated with the given `wmem_stack_t`, including its frames.
 * This macro maps directly to `wmem_destroy_list(STACK)`.
 *
 * @param STACK Pointer to the stack to destroy.
 *
 * @note This does not free the data stored in the stack frames.
 */
#define wmem_destroy_stack(STACK) wmem_destroy_list(STACK)

/**   @}
 *  @} */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WMEM_STACK_H__ */

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
