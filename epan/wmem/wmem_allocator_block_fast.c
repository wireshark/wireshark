/* wmem_allocator_block.c
 * Wireshark Memory Manager Fast Large-Block Allocator
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

#include <stdio.h>
#include <string.h>

#include <glib.h>

#include "wmem_core.h"
#include "wmem_allocator.h"
#include "wmem_allocator_block_fast.h"

/* https://mail.gnome.org/archives/gtk-devel-list/2004-December/msg00091.html
 * The 2*sizeof(size_t) alignment here is borrowed from GNU libc, so it should
 * be good most everywhere. It is more conservative than is needed on some
 * 64-bit platforms, but ia64 does require a 16-byte alignment. The SIMD
 * extensions for x86 and ppc32 would want a larger alignment than this, but
 * we don't need to do better than malloc.
 */
#define WMEM_ALIGN_AMOUNT (2 * sizeof (gsize))
#define WMEM_ALIGN_SIZE(SIZE) ((~(WMEM_ALIGN_AMOUNT-1)) & \
        ((SIZE) + (WMEM_ALIGN_AMOUNT-1)))

#define WMEM_CHUNK_TO_DATA(CHUNK) ((void*)((guint8*)(CHUNK) + WMEM_CHUNK_HEADER_SIZE))
#define WMEM_DATA_TO_CHUNK(DATA) ((wmem_block_fast_chunk_t*)((guint8*)(DATA) - WMEM_CHUNK_HEADER_SIZE))

#define WMEM_BLOCK_MAX_ALLOC_SIZE (WMEM_BLOCK_SIZE - (WMEM_BLOCK_HEADER_SIZE + WMEM_CHUNK_HEADER_SIZE))

/* When required, allocate more memory from the OS in chunks of this size.
 * 2MB is a pretty arbitrary value - it's big enough that it should last a while
 * and small enough that a mostly-unused one doesn't waste *too* much. It's
 * also a nice power of two, of course. */
#define WMEM_BLOCK_SIZE (2 * 1024 * 1024)

/* The header for an entire OS-level 'block' of memory */
typedef struct _wmem_block_fast_hdr {
    struct _wmem_block_fast_hdr *prev, *next;

    gint32 pos;
} wmem_block_fast_hdr_t;
#define WMEM_BLOCK_HEADER_SIZE WMEM_ALIGN_SIZE(sizeof(wmem_block_fast_hdr_t))

typedef struct {
    guint32 len;
} wmem_block_fast_chunk_t;
#define WMEM_CHUNK_HEADER_SIZE WMEM_ALIGN_SIZE(sizeof(wmem_block_fast_chunk_t))

typedef struct {
    wmem_block_fast_hdr_t *block_list;
} wmem_block_fast_allocator_t;

/* Add a block to the allocator's embedded doubly-linked list of OS-level blocks
 * that it owns. */
static inline void
wmem_block_fast_add_to_block_list(wmem_block_fast_allocator_t *allocator,
                             wmem_block_fast_hdr_t *block)
{
    block->prev = NULL;
    block->next = allocator->block_list;
    if (block->next)
        block->next->prev = block;
    allocator->block_list = block;
}

/* Creates a new block, and initializes it. */
static void
wmem_block_fast_new_block(wmem_block_fast_allocator_t *allocator)
{
    wmem_block_fast_hdr_t *block;

    /* allocate the new block and add it to the block list */
    block = (wmem_block_fast_hdr_t *)wmem_alloc(NULL, WMEM_BLOCK_SIZE);
    wmem_block_fast_add_to_block_list(allocator, block);

    /* initialize it */
    block->pos = WMEM_BLOCK_HEADER_SIZE;
}

/* API */

static void *
wmem_block_fast_alloc(void *private_data, const size_t size)
{
    wmem_block_fast_allocator_t *allocator = (wmem_block_fast_allocator_t*) private_data;
    wmem_block_fast_chunk_t     *chunk;
    gint32 real_size;

    g_assert(size <= WMEM_BLOCK_MAX_ALLOC_SIZE);

    real_size = (gint32)(WMEM_ALIGN_SIZE(size) + WMEM_CHUNK_HEADER_SIZE);

    /* Allocate a new block if necessary. */
    if (!allocator->block_list ||
            (WMEM_BLOCK_SIZE - allocator->block_list->pos) < real_size) {
        wmem_block_fast_new_block(allocator);
    }

    chunk = (wmem_block_fast_chunk_t *) ((guint8 *) allocator->block_list + allocator->block_list->pos);
    /* safe to cast, size smaller than WMEM_BLOCK_MAX_ALLOC_SIZE */
    chunk->len = (guint32) size;

    allocator->block_list->pos += real_size;

    /* and return the user's pointer */
    return WMEM_CHUNK_TO_DATA(chunk);
}

static void
wmem_block_fast_free(void *private_data _U_, void *ptr _U_)
{
   /* free is NOP */
}

static void *
wmem_block_fast_realloc(void *private_data, void *ptr, const size_t size)
{
    wmem_block_fast_chunk_t *chunk;

    chunk = WMEM_DATA_TO_CHUNK(ptr);

    /* grow */
    if (chunk->len < size) {
        void *newptr;

        /* need to alloc and copy; free is no-op, so don't call it */
        newptr = wmem_block_fast_alloc(private_data, size);
        memcpy(newptr, ptr, chunk->len);

        return newptr;
    }

    /* shrink or same space - great we can do nothing */
    return ptr;
}

static void
wmem_block_fast_free_all(void *private_data)
{
    wmem_block_fast_allocator_t *allocator = (wmem_block_fast_allocator_t*) private_data;
    wmem_block_fast_hdr_t       *cur;

    /* iterate through the blocks, reinitializing each one */
    cur = allocator->block_list;

    while (cur) {
         cur->pos = WMEM_BLOCK_HEADER_SIZE;
         cur = cur->next;
    }
}

static void
wmem_block_fast_gc(void *private_data)
{
    wmem_block_fast_allocator_t *allocator = (wmem_block_fast_allocator_t*) private_data;
    wmem_block_fast_hdr_t   *cur, *next;

    /* Walk through the blocks, adding used blocks to the new list and
     * completely destroying unused blocks. */
    cur = allocator->block_list;
    allocator->block_list = NULL;

    while (cur) {
        next  = cur->next;

        if (cur->pos == WMEM_BLOCK_HEADER_SIZE)
        {
            /* unused block -> really free */
            wmem_free(NULL, cur);
        }
        else
        {
            /* part of this block is used, so add it to the new block list */
            wmem_block_fast_add_to_block_list(allocator, cur);
        }

        cur = next;
    }
}

static void
wmem_block_fast_allocator_cleanup(void *private_data)
{
    /* wmem guarantees that free_all() is called directly before this, so
     * calling gc will return all our blocks to the OS automatically */
    wmem_block_fast_gc(private_data);

    /* then just free the allocator structs */
    wmem_free(NULL, private_data);
}

void
wmem_block_fast_allocator_init(wmem_allocator_t *allocator)
{
    wmem_block_fast_allocator_t *block_allocator;

    block_allocator = wmem_new(NULL, wmem_block_fast_allocator_t);

    allocator->alloc   = &wmem_block_fast_alloc;
    allocator->realloc = &wmem_block_fast_realloc;
    allocator->free    = &wmem_block_fast_free;

    allocator->free_all = &wmem_block_fast_free_all;
    allocator->gc       = &wmem_block_fast_gc;
    allocator->cleanup  = &wmem_block_fast_allocator_cleanup;

    allocator->private_data = (void*) block_allocator;

    block_allocator->block_list = NULL;
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
