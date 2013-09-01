/* wmem_allocator_simple.c
 * Wireshark Memory Manager Simple Allocator
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

#include "config.h"

#include <string.h>

#include <glib.h>

#include "wmem_core.h"
#include "wmem_allocator.h"

/* In this trivial allocator, we just store a GHashTable of malloc()ed
 * blocks in the private_data pointer. We could just set the private_data
 * pointer directly to the GHashTable, but we use a separate structure here
 * to demonstrate the pattern that most other allocators should follow. */
typedef struct _wmem_simple_allocator_t {
    GHashTable *block_table;
} wmem_simple_allocator_t;

static void *
wmem_simple_alloc(void *private_data, const size_t size)
{
    void *buf;
    wmem_simple_allocator_t *allocator;

    allocator = (wmem_simple_allocator_t*) private_data;

    buf = wmem_alloc(NULL, size);

    g_hash_table_insert(allocator->block_table, buf, buf);

    return buf;
}

static void
wmem_simple_do_free(gpointer ptr)
{
    wmem_free(NULL, ptr);
}

static void
wmem_simple_free(void *private_data, void *ptr)
{
    gboolean                 removed;
    wmem_simple_allocator_t *allocator;

    allocator = (wmem_simple_allocator_t*) private_data;

    /* remove() takes care of calling wmem_free() for us since we set up the
     * hash table with g_hash_table_new_full() */
    removed = g_hash_table_remove(allocator->block_table, ptr);

    g_assert(removed);
}

static void *
wmem_simple_realloc(void *private_data, void *ptr, const size_t size)
{ void *newptr;
    wmem_simple_allocator_t *allocator;

    allocator = (wmem_simple_allocator_t*) private_data;

    newptr = wmem_realloc(NULL, ptr, size);

    if (ptr != newptr) {
        /* Realloc actually moved the memory block, so we need to replace the
         * value in our hash table. Calling g_hash_table_remove() would trigger
         * a wmem_free() which is incorrect since realloc already reclaimed the old
         * block, so use g_hash_table_steal() instead. */
        g_hash_table_steal(allocator->block_table, ptr);
        g_hash_table_insert(allocator->block_table, newptr, newptr);
    }

    return newptr;
}

static void
wmem_simple_free_all(void *private_data)
{
    wmem_simple_allocator_t *allocator;

    allocator = (wmem_simple_allocator_t*) private_data;

    /* remove_all() takes care of calling wmem_free() for us since we set up the
     * hash table with g_hash_table_new_full() */
    g_hash_table_remove_all(allocator->block_table);
}

static void
wmem_simple_gc(void *private_data _U_)
{
    /* In this simple allocator, there is nothing to garbage-collect */
}

static void
wmem_simple_allocator_cleanup(void *private_data)
{
    wmem_simple_allocator_t *allocator;

    allocator = (wmem_simple_allocator_t*) private_data;

    g_hash_table_destroy(allocator->block_table);
    wmem_free(NULL, allocator);
}

void
wmem_simple_allocator_init(wmem_allocator_t *allocator)
{
    wmem_simple_allocator_t *simple_allocator;

    simple_allocator = wmem_new(NULL, wmem_simple_allocator_t);

    allocator->alloc   = &wmem_simple_alloc;
    allocator->realloc = &wmem_simple_realloc;
    allocator->free    = &wmem_simple_free;

    allocator->free_all = &wmem_simple_free_all;
    allocator->gc       = &wmem_simple_gc;
    allocator->cleanup  = &wmem_simple_allocator_cleanup;

    allocator->private_data = (void*) simple_allocator;

    simple_allocator->block_table = g_hash_table_new_full(
            &g_direct_hash, &g_direct_equal, NULL, &wmem_simple_do_free);
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
