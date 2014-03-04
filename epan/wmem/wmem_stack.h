/* wmem_stack.h
 * Definitions for the Wireshark Memory Manager Stack
 * Copyright 2012, Evan Huus <eapache@gmail.com>
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
