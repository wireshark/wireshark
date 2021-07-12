/* wmem_stack.h
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

/* Wmem stack is implemented as a simple wrapper over Wmem list */
typedef wmem_list_t wmem_stack_t;

#define wmem_stack_count(X) wmem_list_count(X)

WS_DLL_PUBLIC
void *
wmem_stack_peek(const wmem_stack_t *stack);

WS_DLL_PUBLIC
void *
wmem_stack_pop(wmem_stack_t *stack);

#define wmem_stack_push(STACK, DATA) wmem_list_prepend((STACK), (DATA))

#define wmem_stack_new(ALLOCATOR) wmem_list_new(ALLOCATOR)

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
