/* wmem_user_cb.c
 * Wireshark Memory Manager User Callbacks
 * Copyright 2012, Evan Huus <eapache@gmail.com>
 *
 * $Id$
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

#include "wmem_core.h"
#include "wmem_allocator.h"

#include "wmem_user_cb.h"
#include "wmem_user_cb_int.h"

typedef struct _wmem_user_cb_container_t {
    wmem_user_cb_t                    cb;
    void                             *user_data;
    struct _wmem_user_cb_container_t *next;
    gboolean                          recurring;
} wmem_user_cb_container_t;

void
wmem_call_cleanup_callbacks(wmem_allocator_t *allocator, gboolean final)
{
    wmem_user_cb_container_t **prev, *cur;

    prev = &(allocator->callbacks);
    cur  = allocator->callbacks;

    while (cur) {

        /* call it */
        cur->cb(allocator, final, cur->user_data);

        /* if it was a one-time callback, or this is being triggered by
         * the final destruction of the allocator, remove the callback */
        if (! cur->recurring || final) {
            *prev = cur->next;
            g_slice_free(wmem_user_cb_container_t, cur);
            cur = *prev;
        }
        else {
            prev = &(cur->next);
            cur  = cur->next;
        }
    }
}

void
wmem_register_cleanup_callback(wmem_allocator_t *allocator, gboolean recurring,
        wmem_user_cb_t callback, void *user_data)
{
    wmem_user_cb_container_t *container;

    container = g_slice_new(wmem_user_cb_container_t);

    container->cb        = callback;
    container->user_data = user_data;
    container->recurring = recurring;
    container->next      = allocator->callbacks;

    allocator->callbacks = container;
}

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
