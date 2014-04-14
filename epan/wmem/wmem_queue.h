/* wmem_queue.h
 * Definitions for the Wireshark Memory Manager Queue
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

/* Wmem queue is implemented as a dumb wrapper over Wmem list and stack */
typedef wmem_list_t wmem_queue_t;

#define wmem_queue_count(X) wmem_list_count(X)

#define wmem_queue_peek(QUEUE) wmem_stack_peek(QUEUE)

#define wmem_queue_pop(QUEUE) wmem_stack_pop(QUEUE)

#define wmem_queue_push(QUEUE, DATA) wmem_list_append((QUEUE), (DATA))

#define wmem_queue_new(ALLOCATOR) wmem_list_new(ALLOCATOR)

#define wmem_destroy_queue(QUEUE) wmem_destroy_list(QUEUE)

/**   @}
 *  @} */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WMEM_QUEUE_H__ */

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
