/* wmem_allocator_block.c
 * Wireshark Memory Manager Large-Block Allocator
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

/* When required, allocate more memory from the OS in this size chunks (8 MB) */
#define WMEM_BLOCK_SIZE (8 * 1024 * 1024)

typedef struct _wmem_block_allocator_t {
    GSList *free_list;
    GSList *full_list;
} wmem_block_allocator_t;

typedef struct _wmem_block__t {
    void  *base;
    size_t offset;
    size_t remaining;
} wmem_block_t;

static wmem_block_t *
wmem_block_alloc_block(void)
{
    wmem_block_t *block;

    block = g_new(wmem_block_t, 1);

    block->base      = g_malloc(WMEM_BLOCK_SIZE);
    block->offset    = 0;
    block->remaining = WMEM_BLOCK_SIZE;

    return block;
}

static void
wmem_block_free_block(wmem_block_t *block)
{
    g_free(block->base);
    g_free(block);
}

static void *
wmem_block_alloc(void *private_data, const size_t size)
{
    guint8                  align;
    void                   *buf;
    wmem_block_t           *block;
    wmem_block_allocator_t *allocator = (wmem_block_allocator_t*) private_data;

    /* We can't allocate more memory than is in a single block
     * (which is an awful lot) */
    g_assert(size < WMEM_BLOCK_SIZE);

    if (allocator->free_list == NULL) {
        allocator->free_list = g_slist_prepend(allocator->free_list,
                                               wmem_block_alloc_block());
    }

    block = (wmem_block_t *) allocator->free_list->data;

    if (size > block->remaining) {
        /* If the block doesn't have room for this allocation, remove it
         * from the free list and add it to the full list, then allocate
         * another block on the free list if necessary. */
        allocator->free_list = g_slist_remove(allocator->free_list,
                                              block);

        allocator->full_list = g_slist_prepend(allocator->full_list,
                                               block);

        if (allocator->free_list == NULL) {
            allocator->free_list = g_slist_prepend(allocator->free_list,
                                                   wmem_block_alloc_block());
        }

        block = (wmem_block_t *) allocator->free_list->data;
    }

    /* 'block' is now guaranteed to have room for the amount of memory
     * that's been requested */

    /* we cast base to type guint8 so that our pointer arithmatic is in bytes */
    buf = ((guint8*) block->base) + block->offset;
    block->offset    += size;
    block->remaining -= size;

    /* Make sure that our next allocation is 8-byte aligned. This wastes a
     * little space on 32-bit systems, but greatly simplifies the logic. */
    align = block->offset & 0x07;
    if (align) {

        align = 0x08 - align;

        if (align > block->remaining) {
            /* The cast is to avoid a moronic MSVC warning about loss of data,
             * even though the if statement clearly guarantees that it will
             * fit */
            align = (guint8)(block->remaining);
        }

        block->offset    += align;
        block->remaining -= align;
    }

    return buf;
}

static void
wmem_block_free_all(void *private_data)
{
    GSList                *tmp;
    wmem_block_allocator_t *allocator = (wmem_block_allocator_t*) private_data;

    /* Don't actually free the blocks, just move everything back to the
     * free-list */
    tmp = allocator->full_list;
    while (tmp) {
        allocator->free_list = g_slist_prepend(allocator->free_list,
                                               tmp->data);
        tmp = tmp->next;
    }
    g_slist_free(allocator->full_list);
    allocator->full_list = NULL;
}

static void
wmem_destroy_block_allocator(wmem_allocator_t *allocator)
{
    GSList                 *tmp;
    wmem_block_allocator_t *real_allocator;

    real_allocator = (wmem_block_allocator_t*) allocator->private_data;

    tmp = real_allocator->free_list;
    while (tmp) {
        wmem_block_free_block((wmem_block_t *)tmp->data);
        tmp = tmp->next;
    }

    /* The API guarantees that free_all will be called before destroy, so
     * we don't have to worry about full_list because free_all will empty it
     * into free_list for us */
    g_slist_free(real_allocator->free_list);

    g_free(real_allocator);
    g_free(allocator);
}

wmem_allocator_t *
wmem_create_block_allocator(void)
{
    wmem_allocator_t       *allocator;
    wmem_block_allocator_t *block_allocator;

    allocator       = g_new(wmem_allocator_t, 1);
    block_allocator = g_new(wmem_block_allocator_t, 1);

    allocator->alloc        = &wmem_block_alloc;
    allocator->free_all     = &wmem_block_free_all;
    allocator->destroy      = &wmem_destroy_block_allocator;
    allocator->private_data = (void*) block_allocator;

    block_allocator->free_list = NULL;
    block_allocator->full_list = NULL;

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
