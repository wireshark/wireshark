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

#include <string.h>

#include <glib.h>

#include "config.h"

#include "wmem_core.h"
#include "wmem_allocator.h"

/* In this trivial allocator, we just store a GHashTable of g_malloc()ed
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
    
    buf = g_malloc(size);

    g_hash_table_insert(allocator->block_table, buf, buf);

    return buf;
}

static void *
wmem_simple_realloc(void *private_data, void *ptr, const size_t size)
{
    void *newptr;
    wmem_simple_allocator_t *allocator;

    allocator = (wmem_simple_allocator_t*) private_data;
    
    newptr = g_realloc(ptr, size);

    if (ptr != newptr) {
        /* realloc actually moved the memory block. We have to steal()
         * instead of remove() because realloc has already reclaimed the old
         * block, and remove()ing it would call g_free() which we don't want. */
        g_hash_table_steal(allocator->block_table, ptr);
        /* realloc is allowed to return NULL if the requested size is 0, in
         * which case we don't want to add back to the hash table */
        if (newptr) {
            g_hash_table_insert(allocator->block_table, newptr, newptr);
        }
    }

    return newptr;
}

static void
wmem_simple_free(void *private_data, void *ptr)
{
    wmem_simple_allocator_t *allocator;

    allocator = (wmem_simple_allocator_t*) private_data;

    /* remove() takes care of calling g_free() for us since we set up the hash
     * table with g_hash_table_new_full() */
    g_hash_table_remove(allocator->block_table, ptr);
}

static void
wmem_simple_free_all(void *private_data)
{
    wmem_simple_allocator_t *allocator;
    
    allocator = (wmem_simple_allocator_t*) private_data;

    /* remove_all() takes care of calling g_free() for us since we set up the
     * hash table with g_hash_table_new_full() */
    g_hash_table_remove_all(allocator->block_table);
}

static void
wmem_simple_gc(void *private_data _U_)
{
    /* In this simple allocator, there is nothing to garbage-collect */
}

static void
wmem_simple_allocator_destroy(wmem_allocator_t *allocator)
{
    wmem_simple_allocator_t *private_allocator;
    
    private_allocator = (wmem_simple_allocator_t*) allocator->private_data;

    g_hash_table_destroy(private_allocator->block_table);
    g_free(private_allocator);
    g_free(allocator);
}

wmem_allocator_t *
wmem_simple_allocator_new(void)
{
    wmem_allocator_t        *allocator;
    wmem_simple_allocator_t *simple_allocator;

    allocator        = g_new(wmem_allocator_t, 1);
    simple_allocator = g_new(wmem_simple_allocator_t, 1);

    allocator->private_data = (void*) simple_allocator;

    allocator->alloc   = &wmem_simple_alloc;
    allocator->realloc = &wmem_simple_realloc;
    allocator->free    = &wmem_simple_free;

    allocator->free_all = &wmem_simple_free_all;
    allocator->gc       = &wmem_simple_gc;
    allocator->destroy  = &wmem_simple_allocator_destroy;

    simple_allocator->block_table = g_hash_table_new_full(
            &g_direct_hash, &g_direct_equal, NULL, &g_free);

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
