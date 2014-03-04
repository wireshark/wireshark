/* wmem_allocator_block.c
 * Wireshark Memory Manager Large-Block Allocator (version 3)
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

#include <stdio.h>
#include <string.h>

#include <glib.h>

#include "wmem_core.h"
#include "wmem_allocator.h"
#include "wmem_allocator_block.h"

/* This has turned into a very interesting excercise in algorithms and data
 * structures.
 *
 * HISTORY
 *
 * Version 1 of this allocator was embedded in the original emem framework. It
 * didn't have to handle realloc or free, so it was very simple: it just grabbed
 * a block from the OS and served allocations sequentially out of that until it
 * ran out, then allocated a new block. The old block was never revisited, so
 * it generally had a bit of wasted space at the end, but the waste was
 * small enough that it was simply ignored. This allocator provided very fast
 * constant-time allocation for any request that didn't require a new block from
 * the OS, and that cost could be amortized away.
 *
 * Version 2 of this allocator was prompted by the need to support realloc and
 * free in wmem. The original version simply didn't save enough metadata to do
 * this, so I added a layer on top to make it possible. The primary principle
 * was the same (allocate sequentially out of big blocks) with a bit of extra
 * magic. Allocations were still fast constant-time, and frees were as well.
 * Large parts of that design are still present in this one, but for more
 * details see older versions of this file from git or svn.
 *
 * Version 3 of this allocator was written to address some issues that
 * eventually showed up with version 2 under real-world usage. Specifically,
 * version 2 dealt very poorly with memory fragmentation, almost never reusing
 * freed blocks and choosing to just keep allocating from the master block
 * instead. This led to particularly poor behaviour under the tick-tock loads
 * (alloc/free/alloc/free or alloc/alloc/free/alloc/alloc/free/ or ...) that
 * showed up in a couple of different protocol dissectors (TCP, Kafka).
 *
 * BLOCKS AND CHUNKS
 *
 * As in previous versions, allocations typically happen sequentially out of
 * large OS-level blocks. Each block has a short embedded header used to
 * maintain a doubly-linked list of all blocks (used or not) currently owned by
 * the allocator. Each block is divided into chunks, which represent allocations
 * and free sections (a block is initialized with one large, free, chunk). Each
 * chunk is prefixed with a wmem_block_chunk_t structure, which is a short
 * metadata header (8 bytes, regardless of 32 or 64-bit architecture unless
 * alignment requires it to be padded) that contains the length of the chunk,
 * the length of the previous chunk, a flag marking the chunk as free or used,
 * and a flag marking the last chunk in a block. This serves to implement an
 * inline sequential doubly-linked list of all the chunks in each block. A block
 * with three chunks might look something like this:
 *
 *          0                    _________________________
 *          ^      ___________  /        ______________   \       __________
 * ||---||--|-----/-----------||--------/--------------||--\-----/----------||
 * ||hdr|| prv | len |  body  || prv | len |   body    || prv | len | body  ||
 * ||---||--------------------||--/--------------------||-------------------||
 *        \______________________/
 *
 *
 * When allocating, a free chunk is found (more on that later) and split into
 * two chunks: the first of the requested size and the second containing any
 * remaining free. The first is marked used and returned to the caller.
 *
 * When freeing, the chunk in question is marked as free. Its neighbouring
 * chunks are then checked; if either of them are free, the consecutive free
 * chunks are merged into a single larger free chunk. Induction can show that
 * applying this operation consistently prevents us ever having consecutive
 * free chunks.
 *
 * Free chunks (because they are not being used for anything else) each store an
 * additional pair of pointers (see the wmem_block_free_t structure) that form
 * the backbone of the data structures used to track free chunks.
 *
 * MASTER AND RECYCLER
 *
 * The extra pair of pointers in free chunks are used to build two doubly-linked
 * lists: the master and the recycler. The recycler is circular, the master is
 * a stack.
 *
 * The master stack is only populated by chunks from new OS-level blocks,
 * so every chunk in this list is guaranteed to be able to serve any allocation
 * request (the allocator will not serve requests larger than its block size).
 * The chunk at the head of the master list shrinks as it serves requests. When
 * it is too small to serve the current request, it is popped and inserted into
 * the recycler. If the master list is empty, a new OS-level block is allocated,
 * and its chunk is pushed onto the master stack.
 *
 * The recycler is populated by 'leftovers' from the master, as well as any
 * chunks that were returned to the allocator via a call to free(). Although the
 * recycler is circular, we will refer to the element referenced from the
 * allocator as the 'head' of the list for convenience. The primary operation on
 * the recycler is called cycling it. In this operation, the head is compared
 * with its clockwise neighbour. If the neighbour is as large or larger, it
 * becomes the head (the list rotates counter-clockwise). If the neighbour is
 * smaller, then it is removed from its location and inserted as the counter-
 * clockwise neighbour of the head (the list still rotates counter-clockwise,
 * but the head element is held fixed while the rest of the list spins). This
 * operation has the following properties:
 *  - fast constant time
 *  - once the largest chunk is at the head, it remains at the head
 *  - more iterations increases the probability that the largest chunk will be
 *    the head (for a list with n items, n iterations guarantees that the
 *    largest chunk will be the head).
 *
 * ALLOCATING
 *
 * When an allocation request is received, the allocator first attempts to
 * satisfy it with the chunk at the head of the recycler. If that does not
 * succeed, the request is satisfied by the master list instead. Regardless of
 * which chunk satisfied the request, the recycler is always cycled.
 */

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

/* When required, allocate more memory from the OS in chunks of this size.
 * 8MB is a pretty arbitrary value - it's big enough that it should last a while
 * and small enough that a mostly-unused one doesn't waste *too* much. It's
 * also a nice power of two, of course. */
#define WMEM_BLOCK_SIZE (8 * 1024 * 1024)

/* The header for an entire OS-level 'block' of memory */
typedef struct _wmem_block_hdr_t {
    struct _wmem_block_hdr_t *prev, *next;
} wmem_block_hdr_t;

/* The header for a single 'chunk' of memory as returned from alloc/realloc.
 * The 'jumbo' flag indicates an allocation larger than a normal-sized block
 * would be capable of serving. If this is set, it is the only chunk in the
 * block and the other chunk header fields are irrelevant.
 */
typedef struct _wmem_block_chunk_t {
    guint32 prev;

    /* flags */
    guint32 last:1;
    guint32 used:1;
    guint32 jumbo:1;

    guint32 len:29;
} wmem_block_chunk_t;

/* Handy macros for navigating the chunks in a block as if they were a
 * doubly-linked list. */
#define WMEM_CHUNK_PREV(CHUNK) ((CHUNK)->prev \
        ? ((wmem_block_chunk_t*)(((guint8*)(CHUNK)) - (CHUNK)->prev)) \
        : NULL)

#define WMEM_CHUNK_NEXT(CHUNK) ((CHUNK)->last \
        ? NULL \
        : ((wmem_block_chunk_t*)(((guint8*)(CHUNK)) + (CHUNK)->len)))

#define WMEM_CHUNK_HEADER_SIZE WMEM_ALIGN_SIZE(sizeof(wmem_block_chunk_t))

#define WMEM_BLOCK_MAX_ALLOC_SIZE (WMEM_BLOCK_SIZE - \
        (WMEM_BLOCK_HEADER_SIZE + WMEM_CHUNK_HEADER_SIZE))

/* other handy chunk macros */
#define WMEM_CHUNK_TO_DATA(CHUNK) ((void*)((guint8*)(CHUNK) + WMEM_CHUNK_HEADER_SIZE))
#define WMEM_DATA_TO_CHUNK(DATA) ((wmem_block_chunk_t*)((guint8*)(DATA) - WMEM_CHUNK_HEADER_SIZE))
#define WMEM_CHUNK_DATA_LEN(CHUNK) ((CHUNK)->len - WMEM_CHUNK_HEADER_SIZE)

/* some handy block macros */
#define WMEM_BLOCK_HEADER_SIZE WMEM_ALIGN_SIZE(sizeof(wmem_block_hdr_t))
#define WMEM_BLOCK_TO_CHUNK(BLOCK) ((wmem_block_chunk_t*)((guint8*)(BLOCK) + WMEM_BLOCK_HEADER_SIZE))
#define WMEM_CHUNK_TO_BLOCK(CHUNK) ((wmem_block_hdr_t*)((guint8*)(CHUNK) - WMEM_BLOCK_HEADER_SIZE))

/* This is what the 'data' section of a chunk contains if it is free. */
typedef struct _wmem_block_free_t {
    wmem_block_chunk_t *prev, *next;
} wmem_block_free_t;

/* Handy macro for accessing the free-header of a chunk */
#define WMEM_GET_FREE(CHUNK) ((wmem_block_free_t*)WMEM_CHUNK_TO_DATA(CHUNK))

typedef struct _wmem_block_allocator_t {
    wmem_block_hdr_t   *block_list;
    wmem_block_chunk_t *master_head;
    wmem_block_chunk_t *recycler_head;
} wmem_block_allocator_t;

/* DEBUG AND TEST */
static int
wmem_block_verify_block(wmem_block_hdr_t *block)
{
    int                 total_free_space = 0;
    guint32             total_len;
    wmem_block_chunk_t *chunk;

    chunk     = WMEM_BLOCK_TO_CHUNK(block);
    total_len = WMEM_BLOCK_HEADER_SIZE;

    if (chunk->jumbo) {
        /* We can tell nothing else about jumbo chunks except that they are
         * always used. */
        return 0;
    }

    g_assert(chunk->prev == 0);

    do {
        total_len += chunk->len;

        g_assert(chunk->len >= WMEM_CHUNK_HEADER_SIZE);
        g_assert(!chunk->jumbo);

        if (WMEM_CHUNK_NEXT(chunk)) {
            g_assert(chunk->len == WMEM_CHUNK_NEXT(chunk)->prev);
        }

        if (!chunk->used &&
                WMEM_CHUNK_DATA_LEN(chunk) >= sizeof(wmem_block_free_t)) {

            total_free_space += chunk->len;

            if (!chunk->last) {
                g_assert(WMEM_GET_FREE(chunk)->next);
                g_assert(WMEM_GET_FREE(chunk)->prev);
            }
        }

        chunk = WMEM_CHUNK_NEXT(chunk);
    } while (chunk);

    g_assert(total_len == WMEM_BLOCK_SIZE);

    return total_free_space;
}

static int
wmem_block_verify_master_list(wmem_block_allocator_t *allocator)
{
    wmem_block_chunk_t *cur;
    wmem_block_free_t  *cur_free;
    int                 free_space = 0;

    cur = allocator->master_head;
    if (!cur) {
        return 0;
    }

    g_assert(WMEM_GET_FREE(cur)->prev == NULL);

    while (cur) {
        free_space += cur->len;

        cur_free = WMEM_GET_FREE(cur);

        g_assert(! cur->used);

        if (cur_free->next) {
            g_assert(WMEM_GET_FREE(cur_free->next)->prev == cur);
        }

        if (cur != allocator->master_head) {
            g_assert(cur->len == WMEM_BLOCK_SIZE);
        }

        cur = cur_free->next;
    }

    return free_space;
}

static int
wmem_block_verify_recycler(wmem_block_allocator_t *allocator)
{
    wmem_block_chunk_t *cur;
    wmem_block_free_t  *cur_free;
    int                 free_space = 0;

    cur = allocator->recycler_head;
    if (!cur) {
        return 0;
    }

    do {
        free_space += cur->len;

        cur_free = WMEM_GET_FREE(cur);

        g_assert(! cur->used);

        g_assert(cur_free->prev);
        g_assert(cur_free->next);

        g_assert(WMEM_GET_FREE(cur_free->prev)->next == cur);
        g_assert(WMEM_GET_FREE(cur_free->next)->prev == cur);

        cur = cur_free->next;
    } while (cur != allocator->recycler_head);

    return free_space;
}

void
wmem_block_verify(wmem_allocator_t *allocator)
{
    wmem_block_hdr_t       *cur;
    wmem_block_allocator_t *private_allocator;
    int                     master_free, recycler_free, chunk_free = 0;

    /* Normally it would be bad for an allocator helper function to depend
     * on receiving the right type of allocator, but this is for testing only
     * and is not part of any real API. */
    g_assert(allocator->type == WMEM_ALLOCATOR_BLOCK);

    private_allocator = (wmem_block_allocator_t*) allocator->private_data;

    if (private_allocator->block_list == NULL) {
        g_assert(! private_allocator->master_head);
        g_assert(! private_allocator->recycler_head);
        return;
    }

    master_free   = wmem_block_verify_master_list(private_allocator);
    recycler_free = wmem_block_verify_recycler(private_allocator);

    cur = private_allocator->block_list;
    g_assert(cur->prev == NULL);
    while (cur) {
        if (cur->next) {
            g_assert(cur->next->prev == cur);
        }
        chunk_free += wmem_block_verify_block(cur);
        cur = cur->next;
    }

    g_assert(chunk_free == master_free + recycler_free);
}

/* MASTER/RECYCLER HELPERS */

/* Cycles the recycler. See the design notes at the top of this file for more
 * details. */
static void
wmem_block_cycle_recycler(wmem_block_allocator_t *allocator)
{
    wmem_block_chunk_t *chunk;
    wmem_block_free_t  *free_chunk;

    chunk = allocator->recycler_head;

    if (chunk == NULL) {
        return;
    }

    free_chunk = WMEM_GET_FREE(chunk);

    if (free_chunk->next->len < chunk->len) {
        /* Hold the current head fixed during rotation. */
        WMEM_GET_FREE(free_chunk->next)->prev = free_chunk->prev;
        WMEM_GET_FREE(free_chunk->prev)->next = free_chunk->next;

        free_chunk->prev = free_chunk->next;
        free_chunk->next = WMEM_GET_FREE(free_chunk->next)->next;

        WMEM_GET_FREE(free_chunk->next)->prev = chunk;
        WMEM_GET_FREE(free_chunk->prev)->next = chunk;
    }
    else {
        /* Just rotate everything. */
        allocator->recycler_head = free_chunk->next;
    }
}

/* Adds a chunk from the recycler. */
static void
wmem_block_add_to_recycler(wmem_block_allocator_t *allocator,
                           wmem_block_chunk_t *chunk)
{
    wmem_block_free_t *free_chunk;

    if (WMEM_CHUNK_DATA_LEN(chunk) < sizeof(wmem_block_free_t)) {
        return;
    }

    free_chunk = WMEM_GET_FREE(chunk);

    if (! allocator->recycler_head) {
        /* First one */
        free_chunk->next         = chunk;
        free_chunk->prev         = chunk;
        allocator->recycler_head = chunk;
    }
    else {
        free_chunk->next = allocator->recycler_head;
        free_chunk->prev = WMEM_GET_FREE(allocator->recycler_head)->prev;

        WMEM_GET_FREE(free_chunk->next)->prev = chunk;
        WMEM_GET_FREE(free_chunk->prev)->next = chunk;

        if (chunk->len > allocator->recycler_head->len) {
            allocator->recycler_head = chunk;
        }
    }
}

/* Removes a chunk from the recycler. */
static void
wmem_block_remove_from_recycler(wmem_block_allocator_t *allocator,
                                wmem_block_chunk_t *chunk)
{
    wmem_block_free_t *free_chunk;

    free_chunk = WMEM_GET_FREE(chunk);

    if (free_chunk->prev == chunk && free_chunk->next == chunk) {
        /* Only one item in recycler, just empty it. */
        allocator->recycler_head = NULL;
    }
    else {
        /* Two or more items, usual doubly-linked-list removal. It's circular
         * so we don't need to worry about null-checking anything, which is
         * nice. */
        WMEM_GET_FREE(free_chunk->prev)->next = free_chunk->next;
        WMEM_GET_FREE(free_chunk->next)->prev = free_chunk->prev;
        if (allocator->recycler_head == chunk) {
            allocator->recycler_head = free_chunk->next;
        }
    }
}

/* Pushes a chunk onto the master stack. */
static void
wmem_block_push_master(wmem_block_allocator_t *allocator,
                       wmem_block_chunk_t *chunk)
{
    wmem_block_free_t *free_chunk;

    free_chunk = WMEM_GET_FREE(chunk);
    free_chunk->prev = NULL;
    free_chunk->next = allocator->master_head;
    if (free_chunk->next) {
        WMEM_GET_FREE(free_chunk->next)->prev = chunk;
    }
    allocator->master_head = chunk;
}

/* Removes the top chunk from the master stack. */
static void
wmem_block_pop_master(wmem_block_allocator_t *allocator)
{
    wmem_block_chunk_t *chunk;
    wmem_block_free_t  *free_chunk;

    chunk = allocator->master_head;

    free_chunk = WMEM_GET_FREE(chunk);

    allocator->master_head = free_chunk->next;
    if (free_chunk->next) {
        WMEM_GET_FREE(free_chunk->next)->prev = NULL;
    }
}

/* CHUNK HELPERS */

/* Takes a free chunk and checks the chunks to its immediate right and left in
 * the block. If they are also free, the contigous free chunks are merged into
 * a single free chunk. The resulting chunk ends up in either the master list or
 * the recycler, depending on where the merged chunks were originally.
 */
static void
wmem_block_merge_free(wmem_block_allocator_t *allocator,
                      wmem_block_chunk_t *chunk)
{
    wmem_block_chunk_t *tmp;
    wmem_block_chunk_t *left_free  = NULL;
    wmem_block_chunk_t *right_free = NULL;

    /* Check the chunk to our right. If it is free, merge it into our current
     * chunk. If it is big enough to hold a free-header, save it for later (we
     * need to know about the left chunk before we decide what goes where). */
    tmp = WMEM_CHUNK_NEXT(chunk);
    if (tmp && !tmp->used) {
        if (WMEM_CHUNK_DATA_LEN(tmp) >= sizeof(wmem_block_free_t)) {
            right_free = tmp;
        }
        chunk->len += tmp->len;
        chunk->last = tmp->last;
    }

    /* Check the chunk to our left. If it is free, merge our current chunk into
     * it (thus chunk = tmp). As before, save it if it has enough space to
     * hold a free-header. */
    tmp = WMEM_CHUNK_PREV(chunk);
    if (tmp && !tmp->used) {
        if (WMEM_CHUNK_DATA_LEN(tmp) >= sizeof(wmem_block_free_t)) {
            left_free = tmp;
        }
        tmp->len += chunk->len;
        tmp->last = chunk->last;
        chunk = tmp;
    }

    /* The length of our chunk may have changed. If we have a chunk following,
     * update its 'prev' count. */
    if (!chunk->last) {
        WMEM_CHUNK_NEXT(chunk)->prev = chunk->len;
    }

    /* Now that the chunk headers are merged and consistent, we need to figure
     * out what goes where in which free list. */
    if (right_free && right_free == allocator->master_head) {
        /* If we merged right, and that chunk was the head of the master list,
         * then we leave the resulting chunk at the head of the master list. */
        wmem_block_free_t *moved;
        if (left_free) {
            wmem_block_remove_from_recycler(allocator, left_free);
        }
        moved = WMEM_GET_FREE(chunk);
        moved->prev = NULL;
        moved->next = WMEM_GET_FREE(right_free)->next;
        allocator->master_head = chunk;
        if (moved->next) {
            WMEM_GET_FREE(moved->next)->prev = chunk;
        }
    }
    else {
        /* Otherwise, we remove the right-merged chunk (if there was one) from
         * the recycler. Then, if we merged left we have nothing to do, since
         * that recycler entry is still valid. If not, we add the chunk. */
        if (right_free) {
            wmem_block_remove_from_recycler(allocator, right_free);
        }
        if (!left_free) {
            wmem_block_add_to_recycler(allocator, chunk);
        }
    }
}

/* Takes an unused chunk and a size, and splits it into two chunks if possible.
 * The first chunk (at the same address as the input chunk) is guaranteed to
 * hold at least `size` bytes of data, and to not be in either the master or
 * recycler lists.
 *
 * The second chunk gets whatever data is left over. It is marked unused and
 * replaces the input chunk in whichever list it originally inhabited. */
static void
wmem_block_split_free_chunk(wmem_block_allocator_t *allocator,
                            wmem_block_chunk_t *chunk,
                            const size_t size)
{
    wmem_block_chunk_t *extra;
    wmem_block_free_t  *old_blk, *new_blk;
    size_t aligned_size, available;
    gboolean last;

    aligned_size = WMEM_ALIGN_SIZE(size) + WMEM_CHUNK_HEADER_SIZE;

    if (WMEM_CHUNK_DATA_LEN(chunk) < aligned_size + sizeof(wmem_block_free_t)) {
        /* If the available space is not enought to store all of
         * (hdr + requested size + alignment padding + hdr + free-header) then
         * just remove the current chunk from the free list and return, since we
         * can't usefully split it. */
        if (chunk == allocator->master_head) {
            wmem_block_pop_master(allocator);
        }
        else {
            wmem_block_remove_from_recycler(allocator, chunk);
        }
        return;
    }

    /* preserve a few values from chunk that we'll need to manipulate */
    last      = chunk->last;
    available = chunk->len - aligned_size;

    /* set new values for chunk */
    chunk->len  = (guint32) aligned_size;
    chunk->last = FALSE;

    /* with chunk's values set, we can use the standard macro to calculate
     * the location and size of the new free chunk */
    extra = WMEM_CHUNK_NEXT(chunk);

    /* Now we move the free chunk's address without changing its location
     * in whichever list it is in.
     *
     * Note that the new chunk header 'extra' may overlap the old free header,
     * so we have to copy the free header before we write anything to extra.
     */
    old_blk = WMEM_GET_FREE(chunk);
    new_blk = WMEM_GET_FREE(extra);

    if (allocator->master_head == chunk) {
        new_blk->prev = old_blk->prev;
        new_blk->next = old_blk->next;

        if (old_blk->next) {
            WMEM_GET_FREE(old_blk->next)->prev = extra;
        }

        allocator->master_head = extra;
    }
    else {
        if (old_blk->prev == chunk) {
            new_blk->prev = extra;
            new_blk->next = extra;
        }
        else {
            new_blk->prev = old_blk->prev;
            new_blk->next = old_blk->next;

            WMEM_GET_FREE(old_blk->prev)->next = extra;
            WMEM_GET_FREE(old_blk->next)->prev = extra;
        }

        if (allocator->recycler_head == chunk) {
            allocator->recycler_head = extra;
        }
    }

    /* Now that we've copied over the free-list stuff (which may have overlapped
     * with our new chunk header) we can safely write our new chunk header. */
    extra->len   = (guint32) available;
    extra->last  = last;
    extra->prev  = chunk->len;
    extra->used  = FALSE;
    extra->jumbo = FALSE;

    /* Correctly update the following chunk's back-pointer */
    if (!last) {
        WMEM_CHUNK_NEXT(extra)->prev = extra->len;
    }
}

/* Takes a used chunk and a size, and splits it into two chunks if possible.
 * The first chunk can hold at least `size` bytes of data, while the second gets
 * whatever's left over. The second is marked as unused and is added to the
 * recycler. */
static void
wmem_block_split_used_chunk(wmem_block_allocator_t *allocator,
                            wmem_block_chunk_t *chunk,
                            const size_t size)
{
    wmem_block_chunk_t *extra;
    size_t aligned_size, available;
    gboolean last;

    aligned_size = WMEM_ALIGN_SIZE(size) + WMEM_CHUNK_HEADER_SIZE;

    if (aligned_size > WMEM_CHUNK_DATA_LEN(chunk)) {
        /* in this case we don't have enough space to really split it, so
         * it's basically a no-op */
        return;
    }
    /* otherwise, we have room to split it, though the remaining free chunk
     * may still not be usefully large */

    /* preserve a few values from chunk that we'll need to manipulate */
    last      = chunk->last;
    available = chunk->len - aligned_size;

    /* set new values for chunk */
    chunk->len  = (guint32) aligned_size;
    chunk->last = FALSE;

    /* with chunk's values set, we can use the standard macro to calculate
     * the location and size of the new free chunk */
    extra = WMEM_CHUNK_NEXT(chunk);

    /* set the new values for the chunk */
    extra->len   = (guint32) available;
    extra->last  = last;
    extra->prev  = chunk->len;
    extra->used  = FALSE;
    extra->jumbo = FALSE;

    /* Correctly update the following chunk's back-pointer */
    if (!last) {
        WMEM_CHUNK_NEXT(extra)->prev = extra->len;
    }

    /* Merge it to its right if possible (it can't be merged left, obviously).
     * This also adds it to the recycler. */
    wmem_block_merge_free(allocator, extra);
}

/* BLOCK HELPERS */

/* Add a block to the allocator's embedded doubly-linked list of OS-level blocks
 * that it owns. */
static void
wmem_block_add_to_block_list(wmem_block_allocator_t *allocator,
                             wmem_block_hdr_t *block)
{
    block->prev = NULL;
    block->next = allocator->block_list;
    if (block->next) {
        block->next->prev = block;
    }
    allocator->block_list = block;
}

/* Remove a block from the allocator's embedded doubly-linked list of OS-level
 * blocks that it owns. */
static void
wmem_block_remove_from_block_list(wmem_block_allocator_t *allocator,
                                  wmem_block_hdr_t *block)
{
    if (block->prev) {
        block->prev->next = block->next;
    }
    else {
        allocator->block_list = block->next;
    }

    if (block->next) {
        block->next->prev = block->prev;
    }
}

/* Initializes a single unused chunk at the beginning of the block, and
 * adds that chunk to the free list. */
static void
wmem_block_init_block(wmem_block_allocator_t *allocator,
                      wmem_block_hdr_t *block)
{
    wmem_block_chunk_t *chunk;

    /* a new block contains one chunk, right at the beginning */
    chunk = WMEM_BLOCK_TO_CHUNK(block);

    chunk->used  = FALSE;
    chunk->jumbo = FALSE;
    chunk->last  = TRUE;
    chunk->prev  = 0;
    chunk->len   = WMEM_BLOCK_SIZE - WMEM_BLOCK_HEADER_SIZE;

    /* now push that chunk onto the master list */
    wmem_block_push_master(allocator, chunk);
}

/* Creates a new block, and initializes it. */
static void
wmem_block_new_block(wmem_block_allocator_t *allocator)
{
    wmem_block_hdr_t *block;

    /* allocate the new block and add it to the block list */
    block = (wmem_block_hdr_t *)wmem_alloc(NULL, WMEM_BLOCK_SIZE);
    wmem_block_add_to_block_list(allocator, block);

    /* initialize it */
    wmem_block_init_block(allocator, block);
}

/* JUMBO ALLOCATIONS */

/* Allocates special 'jumbo' blocks for sizes that won't fit normally. */
static void *
wmem_block_alloc_jumbo(wmem_block_allocator_t *allocator, const size_t size)
{
    wmem_block_hdr_t   *block;
    wmem_block_chunk_t *chunk;

    /* allocate a new block of exactly the right size */
    block = (wmem_block_hdr_t *) wmem_alloc(NULL, size
            + WMEM_BLOCK_HEADER_SIZE
            + WMEM_CHUNK_HEADER_SIZE);

    /* add it to the block list */
    wmem_block_add_to_block_list(allocator, block);

    /* the new block contains a single jumbo chunk */
    chunk = WMEM_BLOCK_TO_CHUNK(block);
    chunk->last  = TRUE;
    chunk->used  = TRUE;
    chunk->jumbo = TRUE;
    chunk->len   = 0;
    chunk->prev  = 0;

    /* and return the data pointer */
    return WMEM_CHUNK_TO_DATA(chunk);
}

/* Frees special 'jumbo' blocks of sizes that won't fit normally. */
static void
wmem_block_free_jumbo(wmem_block_allocator_t *allocator,
                      wmem_block_chunk_t *chunk)
{
    wmem_block_hdr_t *block;

    block = WMEM_CHUNK_TO_BLOCK(chunk);

    wmem_block_remove_from_block_list(allocator, block);

    wmem_free(NULL, block);
}

/* Reallocs special 'jumbo' blocks of sizes that won't fit normally. */
static void *
wmem_block_realloc_jumbo(wmem_block_allocator_t *allocator,
                         wmem_block_chunk_t *chunk,
                         const size_t size)
{
    wmem_block_hdr_t *block;

    block = WMEM_CHUNK_TO_BLOCK(chunk);

    block = (wmem_block_hdr_t *) wmem_realloc(NULL, block, size
            + WMEM_BLOCK_HEADER_SIZE
            + WMEM_CHUNK_HEADER_SIZE);

    if (block->next) {
        block->next->prev = block;
    }

    if (block->prev) {
        block->prev->next = block;
    }
    else {
        allocator->block_list = block;
    }

    return WMEM_CHUNK_TO_DATA(WMEM_BLOCK_TO_CHUNK(block));
}

/* API */

static void *
wmem_block_alloc(void *private_data, const size_t size)
{
    wmem_block_allocator_t *allocator = (wmem_block_allocator_t*) private_data;
    wmem_block_chunk_t     *chunk;

    if (size > WMEM_BLOCK_MAX_ALLOC_SIZE) {
        return wmem_block_alloc_jumbo(allocator, size);
    }

    if (allocator->recycler_head &&
            WMEM_CHUNK_DATA_LEN(allocator->recycler_head) >= size) {

        /* If we can serve it from the recycler, do so. */
        chunk = allocator->recycler_head;
    }
    else {
        if (allocator->master_head &&
                WMEM_CHUNK_DATA_LEN(allocator->master_head) < size) {

            /* Recycle the head of the master list if necessary. */
            chunk = allocator->master_head;
            wmem_block_pop_master(allocator);
            wmem_block_add_to_recycler(allocator, chunk);
        }

        if (!allocator->master_head) {
            /* Allocate a new block if necessary. */
            wmem_block_new_block(allocator);
        }

        chunk = allocator->master_head;
    }

    /* Split our chunk into two to preserve any trailing free space */
    wmem_block_split_free_chunk(allocator, chunk, size);

    /* Now cycle the recycler */
    wmem_block_cycle_recycler(allocator);

    /* mark it as used */
    chunk->used = TRUE;

    /* and return the user's pointer */
    return WMEM_CHUNK_TO_DATA(chunk);
}

static void
wmem_block_free(void *private_data, void *ptr)
{
    wmem_block_allocator_t *allocator = (wmem_block_allocator_t*) private_data;
    wmem_block_chunk_t     *chunk;

    chunk = WMEM_DATA_TO_CHUNK(ptr);

    if (chunk->jumbo) {
        wmem_block_free_jumbo(allocator, chunk);
        return;
    }

    /* mark it as unused */
    chunk->used = FALSE;

    /* merge it with any other free chunks adjacent to it, so that contiguous
     * free space doesn't get fragmented */
    wmem_block_merge_free(allocator, chunk);

    /* Now cycle the recycler */
    wmem_block_cycle_recycler(allocator);
}

static void *
wmem_block_realloc(void *private_data, void *ptr, const size_t size)
{
    wmem_block_allocator_t *allocator = (wmem_block_allocator_t*) private_data;
    wmem_block_chunk_t     *chunk;

    chunk = WMEM_DATA_TO_CHUNK(ptr);

    if (chunk->jumbo) {
        return wmem_block_realloc_jumbo(allocator, chunk, size);
    }

    if (size > WMEM_CHUNK_DATA_LEN(chunk)) {
        /* grow */
        wmem_block_chunk_t *tmp;

        tmp = WMEM_CHUNK_NEXT(chunk);

        if (tmp && (!tmp->used) &&
            (size < WMEM_CHUNK_DATA_LEN(chunk) + tmp->len)) {
            /* the next chunk is free and has enough extra, so just grab
             * from that */
            size_t split_size;

            /* we ask for the next chunk to be split, but we don't end up
             * using the split chunk header (it just gets merged into this one),
             * so we want the split to be of (size - curdatalen - header_size).
             * However, this can underflow by header_size, so we do a quick
             * check here and floor the value to 0. */
            split_size = size - WMEM_CHUNK_DATA_LEN(chunk);

            if (split_size < WMEM_CHUNK_HEADER_SIZE) {
                split_size = 0;
            }
            else {
                split_size -= WMEM_CHUNK_HEADER_SIZE;
            }

            wmem_block_split_free_chunk(allocator, tmp, split_size);

            /* Now do a 'quickie' merge between the current block and the left-
             * hand side of the split. Simply calling wmem_block_merge_free
             * might confuse things, since we may temporarily have two blocks
             * to our right that are both free (and it isn't guaranteed to
             * handle that case). Update our 'next' count and last flag, and
             * our (new) successor's 'prev' count */
            chunk->len += tmp->len;
            chunk->last = tmp->last;
            tmp = WMEM_CHUNK_NEXT(chunk);
            if (tmp) {
                tmp->prev = chunk->len;
            }

            /* Now cycle the recycler */
            wmem_block_cycle_recycler(allocator);

            /* And return the same old pointer */
            return ptr;
        }
        else {
            /* no room to grow, need to alloc, copy, free */
            void *newptr;

            newptr = wmem_block_alloc(private_data, size);
            memcpy(newptr, ptr, WMEM_CHUNK_DATA_LEN(chunk));
            wmem_block_free(private_data, ptr);

            /* No need to cycle the recycler, alloc and free both did that
             * already */

            return newptr;
        }
    }
    else if (size < WMEM_CHUNK_DATA_LEN(chunk)) {
        /* shrink */
        wmem_block_split_used_chunk(allocator, chunk, size);

        /* Now cycle the recycler */
        wmem_block_cycle_recycler(allocator);

        return ptr;
    }

    /* no-op */
    return ptr;
}

static void
wmem_block_free_all(void *private_data)
{
    wmem_block_allocator_t *allocator = (wmem_block_allocator_t*) private_data;
    wmem_block_hdr_t       *cur;
    wmem_block_chunk_t     *chunk;

    /* the existing free lists are entirely irrelevant */
    allocator->master_head   = NULL;
    allocator->recycler_head = NULL;

    /* iterate through the blocks, reinitializing each one */
    cur = allocator->block_list;

    while (cur) {
        chunk = WMEM_BLOCK_TO_CHUNK(cur);
        if (chunk->jumbo) {
            wmem_block_remove_from_block_list(allocator, cur);
            cur = cur->next;
            wmem_free(NULL, WMEM_CHUNK_TO_BLOCK(chunk));
        }
        else {
            wmem_block_init_block(allocator, cur);
            cur = cur->next;
        }
    }
}

static void
wmem_block_gc(void *private_data)
{
    wmem_block_allocator_t *allocator = (wmem_block_allocator_t*) private_data;
    wmem_block_hdr_t   *cur, *next;
    wmem_block_chunk_t *chunk;
    wmem_block_free_t  *free_chunk;

    /* Walk through the blocks, adding used blocks to the new list and
     * completely destroying unused blocks. */
    cur = allocator->block_list;
    allocator->block_list = NULL;

    while (cur) {
        chunk = WMEM_BLOCK_TO_CHUNK(cur);
        next  = cur->next;

        if (!chunk->jumbo && !chunk->used && chunk->last) {
            /* If the first chunk is also the last, and is unused, then
             * the block as a whole is entirely unused, so return it to
             * the OS and remove it from whatever lists it is in. */
            free_chunk = WMEM_GET_FREE(chunk);
            if (free_chunk->next) {
                WMEM_GET_FREE(free_chunk->next)->prev = free_chunk->prev;
            }
            if (free_chunk->prev) {
                WMEM_GET_FREE(free_chunk->prev)->next = free_chunk->next;
            }
            if (allocator->recycler_head == chunk) {
                if (free_chunk->next == chunk) {
                    allocator->recycler_head = NULL;
                }
                else {
                    allocator->recycler_head = free_chunk->next;
                }
            }
            else if (allocator->master_head == chunk) {
                allocator->master_head = free_chunk->next;
            }
            wmem_free(NULL, cur);
        }
        else {
            /* part of this block is used, so add it to the new block list */
            wmem_block_add_to_block_list(allocator, cur);
        }

        cur = next;
    }
}

static void
wmem_block_allocator_cleanup(void *private_data)
{
    /* wmem guarantees that free_all() is called directly before this, so
     * calling gc will return all our blocks to the OS automatically */
    wmem_block_gc(private_data);

    /* then just free the allocator structs */
    wmem_free(NULL, private_data);
}

void
wmem_block_allocator_init(wmem_allocator_t *allocator)
{
    wmem_block_allocator_t *block_allocator;

    block_allocator = wmem_new(NULL, wmem_block_allocator_t);

    allocator->alloc   = &wmem_block_alloc;
    allocator->realloc = &wmem_block_realloc;
    allocator->free    = &wmem_block_free;

    allocator->free_all = &wmem_block_free_all;
    allocator->gc       = &wmem_block_gc;
    allocator->cleanup  = &wmem_block_allocator_cleanup;

    allocator->private_data = (void*) block_allocator;

    block_allocator->block_list    = NULL;
    block_allocator->master_head   = NULL;
    block_allocator->recycler_head = NULL;
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
