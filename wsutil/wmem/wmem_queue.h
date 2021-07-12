/* wmem_queue.h
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
