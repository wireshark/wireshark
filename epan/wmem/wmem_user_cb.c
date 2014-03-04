/* wmem_user_cb.c
 * Wireshark Memory Manager User Callbacks
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

#include "wmem_core.h"
#include "wmem_allocator.h"

#include "wmem_user_cb.h"
#include "wmem_user_cb_int.h"

typedef struct _wmem_user_cb_container_t {
    wmem_user_cb_t                    cb;
    void                             *user_data;
    struct _wmem_user_cb_container_t *next;
    guint                             id;
} wmem_user_cb_container_t;

void
wmem_call_callbacks(wmem_allocator_t *allocator, wmem_cb_event_t event)
{
    wmem_user_cb_container_t **prev, *cur;
    gboolean again;

    prev = &(allocator->callbacks);
    cur  = allocator->callbacks;

    while (cur) {

        /* call it */
        again = cur->cb(allocator, event, cur->user_data);

        /* if the callback requested deregistration, or this is being triggered
         * by the final destruction of the allocator, remove the callback */
        if (! again || event == WMEM_CB_DESTROY_EVENT) {
            *prev = cur->next;
            wmem_free(NULL, cur);
            cur = *prev;
        }
        else {
            prev = &(cur->next);
            cur  = cur->next;
        }
    }
}

guint
wmem_register_callback(wmem_allocator_t *allocator,
        wmem_user_cb_t callback, void *user_data)
{
    wmem_user_cb_container_t *container;
    static guint next_id = 0;

    container = wmem_new(NULL, wmem_user_cb_container_t);

    container->cb        = callback;
    container->user_data = user_data;
    container->next      = allocator->callbacks;
    container->id        = next_id++;

    allocator->callbacks = container;

    return container->id;
}

void
wmem_unregister_callback(wmem_allocator_t *allocator, guint id)
{
    wmem_user_cb_container_t **prev, *cur;

    prev = &(allocator->callbacks);
    cur  = allocator->callbacks;

    while (cur) {

        if (cur->id == id) {
            *prev = cur->next;
            wmem_free(NULL, cur);
            return;
        }

        prev = &(cur->next);
        cur  = cur->next;
    }
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
