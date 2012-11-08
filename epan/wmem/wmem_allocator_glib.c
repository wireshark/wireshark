/* wmem_allocator_glib.c
 * Wireshark Memory Manager GLib-Based Allocator
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

#include <string.h>

#include <glib.h>

#include "wmem_core.h"
#include "wmem_allocator.h"

/* In this trivial allocator, we just store a GSList of g_malloc()ed
 * blocks in the private_data pointer. */
typedef struct _wmem_glib_allocator_t {
    GSList *block_list;
} wmem_glib_allocator_t;

static void *
wmem_glib_alloc(void *private_data, const size_t size)
{
    void *buf;
    wmem_glib_allocator_t *allocator = (wmem_glib_allocator_t*) private_data;
    
    buf = g_malloc(size);

    allocator->block_list = g_slist_prepend(allocator->block_list, buf);

    return buf;
}

static void
wmem_glib_free_all(void *private_data)
{
    wmem_glib_allocator_t *allocator = (wmem_glib_allocator_t*) private_data;
    GSList                *tmp;

    /* We can't use g_slist_free_full() as it was only introduced in GLIB 2.28
     * while we support way back to 2.14. So loop through and manually free
     * each block, then call g_slist_free(). */
    tmp = allocator->block_list;
    while (tmp) {
        g_free(tmp->data);
        tmp = tmp->next;
    }
    g_slist_free(allocator->block_list);

    allocator->block_list = NULL;
}

static void
wmem_destroy_glib_allocator(wmem_allocator_t *allocator)
{
    g_free(allocator->private_data);
    g_free(allocator);
}

wmem_allocator_t *
wmem_create_glib_allocator(void)
{
    wmem_allocator_t      *allocator;
    wmem_glib_allocator_t *glib_allocator;

    allocator      = g_new(wmem_allocator_t, 1);
    glib_allocator = g_new(wmem_glib_allocator_t, 1);

    allocator->alloc        = &wmem_glib_alloc;
    allocator->free_all     = &wmem_glib_free_all;
    allocator->destroy      = &wmem_destroy_glib_allocator;
    allocator->private_data = (void*) glib_allocator;

    glib_allocator->block_list = NULL;

    return allocator;
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
