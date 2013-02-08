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

/* AUTHOR'S NOTE:
 *
 * This turned into one of the most interesting excercises in algorithms I've
 * ever worked on. It's 'bad' in that there is no algorithmic limit on the
 * amount of memory it can waste (at least not as a function of the calls to
 * alloc/realloc/free) but in practical terms it's still a major step up from
 * the old block allocator because that one didn't implement realloc or free.
 *
 * Historically, the emem/wmem block allocator simply grabbed big blocks from
 * the OS and served allocations sequentially out of the block until it ran out
 * of space (potentially wasting a bit at the end), then allocated a new block.
 * The only metadata was a linked list of the blocks themselves, so realloc and
 * free were impossible. The benefit, of course, was constant-time allocation
 * cost for any size that didn't require a new block from the OS (and given
 * Wireshark's allocation patterns, that cost could be amortized away anyways).
 *
 * In order to implement realloc and free, I made the following structural
 * changes:
 * - Each allocation is preceeded by an 8-byte metadata header (constant size
 *   regardless of 32 or 64-bit architecture). See the wmem_block_chunk_t
 *   structure.
 * - In addition to the singly-linked list of OS blocks, a doubly-linked list of
 *   free chunks is maintained. The chunks themselves are in the OS-level blocks
 *   (each block can have 1 or more chunks) and have their prev/next pointers
 *   embedded, so the only additional storage cost is two pointers: one to the
 *   head of this list and one to the priority divider of the list (explained
 *   in more detail later). See the wmem_block_free_t structure.
 * 
 * Alloc is implemented very similarly to before. The first chunk in the free
 * list is checked. If it has enough space, it is used (potentially splitting
 * the chunk in two - the allocated part and the remaining free space). If it
 * doesn't have enough room, it is removed from the free list and the next chunk
 * is tried. If it doesn't have enough room it is left where it is and a new OS-
 * level block is allocated, inserted at the beginning of the free list, and
 * used. This is still fast constant-time except in the case where a new OS-
 * level block is needed.
 *
 * Free is implemented very simply. The chunk in question is flagged as free,
 * and the chunks before and after it in the block are checked. If either of
 * them are free then the chunks are merged (induction shows that this constant-
 * time operation prevents us from ever having multiple contiguous but unmerged
 * free chunks). If the resulting free chunk is usefully large, it is inserted
 * into the free list (either before or after the priority divider, depending
 * on exactly how large - this permits us to limit the amount of memory we can
 * be forced to waste to a reasonable amount still without costing more than
 * constant time).
 *
 * Realloc is also fairly straight-forward. If the request is to shrink, a new
 * free chunk is created at the appropriate point, merged with the chunk on its
 * right if possible, and added to the free list if usefully large. If the
 * request is to grow, then the additional space is taken from the chunk to the
 * right if it is free and sufficiently large. Otherwise a new chunk is
 * allocated with regular alloc, the memory is memcopied, and the old chunk is
 * freed with the regular free.
 *
 * Hopefully all of this still makes sense when someone else comes back to it
 * in a year's time.
 *
 * -- Evan Huus
 * February, 2013
 */

/* https://mail.gnome.org/archives/gtk-devel-list/2004-December/msg00091.html
 * The 2*sizeof(size_t) alignment here is borrowed from GNU libc, so it should
 * be good most everywhere. It is more conservative than is needed on some
 * 64-bit platforms, but ia64 does require a 16-byte alignment. The SIMD
 * extensions for x86 and ppc32 would want a larger alignment than this, but
 * we don't need to do better than malloc.
 */
#define WMEM_ALIGN_AMOUNT (2 * sizeof (gsize))
#define WMEM_ALIGN_SIZE(SIZE) ((SIZE) + WMEM_ALIGN_AMOUNT - \
        ((SIZE) & (WMEM_ALIGN_AMOUNT - 1)));

/* When required, allocate more memory from the OS in chunks of this size.
 * 8MB is a pretty arbitrary value - it's big enough that it should last a while
 * and small enough that a mostly-unused one doesn't waste too much. It's also a
 * nice power of two, of course. */
#define WMEM_BLOCK_SIZE (8 * 1024 * 1024)

/* Two arbitrary values. The first is the minimum size to bother reclaiming;
 * below this value it's likely that the chunk isn't big enough to satisfy
 * many requests, and we're better off 'wasting' it for now. The second is
 * the minimum size to say "this is huge, we want it now" and prioritize
 * using it over the smaller chunks.
 *
 * TODO: Do some profiling of calls in to emem/wmem in the common case and
 * pick better values here.
 */
#define WMEM_RECLAIM_LEN 256
#define WMEM_RECLAIM_PRIORITY_LEN 8*WMEM_RECLAIM_LEN

/* The header for a single 'chunk' of memory as returned from alloc/realloc. */
typedef struct _wmem_block_chunk_t {
    guint32 used:1;
    guint32 prev:31;

    guint32 last:1;
    guint32 len:31;
} wmem_block_chunk_t;

/* Handy macros for navigating the chunks in a block as if they were a
 * doubly-linked list. */
#define WMEM_CHUNK_PREV(CHUNK) ((CHUNK)->prev \
        ? ((wmem_block_chunk_t*)(((guint8*)(CHUNK)) - (CHUNK)->prev)) \
        : NULL)

#define WMEM_CHUNK_NEXT(CHUNK) ((CHUNK)->last \
        ? NULL \
        : ((wmem_block_chunk_t*)(((guint8*)(CHUNK)) + (CHUNK)->len)))

/* other handy chunk macros */
#define WMEM_CHUNK_DATA(CHUNK) ((void*)((CHUNK) + 1))
#define WMEM_CHUNK_DATA_LEN(CHUNK) ((CHUNK)->len - sizeof(wmem_block_chunk_t))
#define WMEM_DATA_TO_CHUNK(DATA) (((wmem_block_chunk_t*)(DATA)) - 1)

/* This is what the 'data' section of a chunk contains if it is free (hasn't
 * been returned from a call to alloc/realloc). We point directly to the
 * chunk headers rather than the 'free' header which is a bit odd but makes
 * most operations simpler in practice (I think). */
typedef struct _wmem_block_free_t {
    /* we need this to be able to tell if this block is in the free list at all
     * or not, since it may not be depending on its size */
    gboolean           in_free_list;

    /* the regular doubly-linked-list bits */
    wmem_block_chunk_t *prev, *next;
} wmem_block_free_t;

/* Handy macro for accessing the free-header of a chunk */
#define WMEM_GET_FREE(CHUNK) ((wmem_block_free_t*)WMEM_CHUNK_DATA(CHUNK))

typedef struct _wmem_block_allocator_t {
    GSList             *block_list;
    wmem_block_chunk_t *free_list_head;
    wmem_block_chunk_t *free_insert_point;
} wmem_block_allocator_t;

/* HELPERS */

/* Removes a chunk from the free list. If the chunk is too small to
 * store the necessary pointers, or if it is flagged as not being in the
 * list, then calling this function is safe (a no-op). */
static void
wmem_block_remove_from_free_list(wmem_block_allocator_t *allocator,
                                 wmem_block_chunk_t *chunk)
{
    wmem_block_free_t  *freeChunk;

    g_assert(!chunk->used);

    if (WMEM_CHUNK_DATA_LEN(chunk) < sizeof(wmem_block_free_t)) {
        /* it's not even big enough to store the free-chunk structure, so it
         * can't have been added to the list in the first place */
        return;
    }

    freeChunk = WMEM_GET_FREE(chunk);

    if (! freeChunk->in_free_list) {
        /* it was never added to the free list in the first place */
        return;
    }

    if (freeChunk->prev) {
        WMEM_GET_FREE(freeChunk->prev)->next = freeChunk->next;
    }
    else {
        allocator->free_list_head = freeChunk->next;
    }

    if (freeChunk->next) {
        WMEM_GET_FREE(freeChunk->next)->prev = freeChunk->prev;
    }

    if (allocator->free_insert_point == chunk) {
        allocator->free_insert_point = freeChunk->prev;
    }

    freeChunk->in_free_list = FALSE;
}

/* Adds an unused chunk to the free list after the chunk pointed to by
 * insertPoint. If insertPoint is NULL, the chunk is added to the head of the
 * list. Does not update the allocator's insert-point, the caller is expected
 * to do that if necessary. */
static void
wmem_block_add_to_free_list_after(wmem_block_allocator_t *allocator,
                                  wmem_block_chunk_t *chunk,
                                  wmem_block_chunk_t *insertPoint)
{
    wmem_block_free_t  *freeChunk;

    g_assert(!chunk->used);
    g_assert(WMEM_CHUNK_DATA_LEN(chunk) >= sizeof(wmem_block_free_t));

    freeChunk = WMEM_GET_FREE(chunk);

    g_assert(! freeChunk->in_free_list);

    if (insertPoint == NULL) {
        /* insert at the very beginning */
        freeChunk->next = allocator->free_list_head;
        freeChunk->prev = NULL;
        allocator->free_list_head = chunk;
    }
    else {
        /* insert after insertPoint */
        freeChunk->next = WMEM_GET_FREE(insertPoint)->next;
        freeChunk->prev = insertPoint;

        WMEM_GET_FREE(insertPoint)->next     = chunk;
        WMEM_GET_FREE(freeChunk->next)->prev = chunk;
    }

    freeChunk->in_free_list = TRUE;
}

/* Adds an unused chunk to the free list at the default location. This is
 * after the insert barrier if it is smaller than WMEM_RECLAIM_PRIORITY_LEN,
 * or before the insert barrier if it is bigger than that. If it is smaller
 * than WMEM_RECLAIM_LEN, it is not added at all. */
static void
wmem_block_add_to_free_list(wmem_block_allocator_t *allocator,
                            wmem_block_chunk_t *chunk)
{
    g_assert(!chunk->used);

    if (chunk->len < WMEM_RECLAIM_LEN) {
        /* it's not big enough to claim */
        if (WMEM_CHUNK_DATA_LEN(chunk) >= sizeof(wmem_block_free_t)) {
            /* it's still big enough to store the struct, so set the flag
             * so we know in future it wasn't added */
            WMEM_GET_FREE(chunk)->in_free_list = FALSE;
        }
        return;
    }

    wmem_block_add_to_free_list_after(allocator, chunk,
            allocator->free_insert_point);

    /* if it's a priority chunk, move the insert divider to after it */
    if (chunk->len > WMEM_RECLAIM_PRIORITY_LEN) {
        allocator->free_insert_point = chunk;
    }

}

/* Takes a free chunk and checks the chunks to its immediate left and right in
 * the block. If they are also free, the contigous free chunks are merged into
 * a single free chunk. The merged-in chunks are removed from the free list if
 * they were in it, and the address of the final merged free chunk is returned.
 */
static wmem_block_chunk_t *
wmem_block_merge_free(wmem_block_allocator_t *allocator,
                      wmem_block_chunk_t *chunk)
{
    wmem_block_chunk_t *tmp;

    g_assert(!chunk->used);

    /* check the chunk to our right */
    tmp = WMEM_CHUNK_NEXT(chunk);

    if (tmp && !tmp->used) {
        /* Remove it from the free list since we're merging it, then add its
         * length to our length since the two free chunks are now one.
         * Our 'chunk' pointer is still the master header. */
        wmem_block_remove_from_free_list(allocator, tmp);
        chunk->len += tmp->len;
    }

    /* check the chunk to our left */
    tmp = WMEM_CHUNK_PREV(chunk);

    if (tmp && !tmp->used) {
        /* Remove it from the free list. We do this for consistency across
         * cases - an optimization later might be to not do this if we're
         * just going to insert it again right away. */
        wmem_block_remove_from_free_list(allocator, tmp);

        /* Add our length to its length since the two free chunks
         * are now one. */
        tmp->len += chunk->len;

        /* The chunk pointer passed in is no longer valid, it's been merged to
         * its left, so return the chunk to our left */
        return tmp;
    }

    /* Otherwise return the chunk as passed in */
    return chunk;
}

/* Takes an unused chunk and a size, and splits it into two chunks if possible.
 * The first chunk can hold at least `size` bytes of data, while the second gets
 * whatever's left over. The second is marked as unused and is left in the same
 * place in the free list that the original chunk was. The original chunk is
 * removed from the free list - the caller is responsible for dealing with it
 * however they see fit. */
static void
wmem_block_split_free_chunk(wmem_block_allocator_t *allocator,
                            wmem_block_chunk_t *chunk,
                            const size_t size)
{
    wmem_block_chunk_t *extra;
    size_t aligned_size, available;
    gboolean last;

    g_assert(!chunk->used);
    g_assert(WMEM_CHUNK_DATA_LEN(chunk) >= size);

    aligned_size = WMEM_ALIGN_SIZE(size);

    if (aligned_size + sizeof(wmem_block_chunk_t) >
            WMEM_CHUNK_DATA_LEN(chunk)) {
        /* In this case we don't have enough space to really split it, so we
         * don't. Just remove it from the free list and return. */
        wmem_block_remove_from_free_list(allocator, chunk);
        return;
    }
    /* otherwise, we have room to split it, though the remaining free chunk
     * may still not be usefully large */

    /* preserve a few values from chunk that we'll need to manipulate */
    last      = chunk->last;
    available = chunk->len;

    /* set new values for chunk */
    chunk->len  = (guint32) (aligned_size + sizeof(wmem_block_chunk_t));
    chunk->last = FALSE;

    /* with chunk's values set, we can use the standard macro to calculate
     * the location and size of the new free chunk */
    extra = WMEM_CHUNK_NEXT(chunk);
    available -= (aligned_size + sizeof(wmem_block_chunk_t));

    if (available > sizeof(wmem_block_chunk_t) + sizeof(wmem_block_free_t)) {
        /* If the new block has room for the free header (in which case the old
         * bigger one must have as well) then we move the free chunk's address
         * without changing its location in the free list so that for large
         * chunks we serve from them consecutively like the old allocator.
         *
         * XXX: Note that we have not yet written to the new chunk header - it
         * may overlap the old free header, so we have to do all of our reads
         * here first!
         */
        if (! WMEM_GET_FREE(chunk)->in_free_list) {
            /* it wasn't in the free list, so just do that */
            WMEM_GET_FREE(extra)->in_free_list = FALSE;
        }
        else {
            /* it was in the free list, so copy over its prev and next pointers,
             * then update anything that may have pointed to it to point to the
             * new address instead */
            wmem_block_chunk_t *prev, *next;
            wmem_block_free_t  *old, *new;

            old = WMEM_GET_FREE(chunk);
            new = WMEM_GET_FREE(extra);

            prev = old->prev;
            next = old->next;

            new->in_free_list = TRUE;
            new->prev = prev;
            new->next = next;

            if (prev) WMEM_GET_FREE(prev)->next = extra;
            if (next) WMEM_GET_FREE(next)->prev = extra;

            if (allocator->free_list_head == chunk)
                allocator->free_list_head = extra;

            if (allocator->free_insert_point == chunk)
                allocator->free_insert_point = extra;
        }
    }

    /* Now that we've copied over the free-list stuff (which may have overlapped
     * with our new chunk header) we can safely write our new chunk header. */
    extra->len  = (guint32) available;
    extra->last = last;
    extra->prev = (guint32) (aligned_size + sizeof(wmem_block_chunk_t));
    extra->used = FALSE;
}

/* Takes a used chunk and a size, and splits it into two chunks if possible.
 * The first chunk can hold at least `size` bytes of data, while the second gets
 * whatever's left over. The second is marked as unused and is added to the free
 * list. */
static void
wmem_block_split_used_chunk(wmem_block_allocator_t *allocator,
                            wmem_block_chunk_t *chunk,
                            const size_t size)
{
    wmem_block_chunk_t *extra;
    size_t aligned_size, available;
    gboolean last;

    g_assert(chunk->used);
    g_assert(WMEM_CHUNK_DATA_LEN(chunk) >= size);

    aligned_size = WMEM_ALIGN_SIZE(size);

    if (aligned_size + sizeof(wmem_block_chunk_t) >
            WMEM_CHUNK_DATA_LEN(chunk)) {
        /* in this case we don't have enough space to really split it, so
         * it's basically a no-op */
        return;
    }
    /* otherwise, we have room to split it, though the remaining free chunk
     * may still not be usefully large */

    /* preserve a few values from chunk that we'll need to manipulate */
    last      = chunk->last;
    available = chunk->len;

    /* set new values for chunk */
    chunk->len  = (guint32) (aligned_size + sizeof(wmem_block_chunk_t));
    chunk->last = FALSE;

    /* with chunk's values set, we can use the standard macro to calculate
     * the location and size of the new free chunk */
    extra = WMEM_CHUNK_NEXT(chunk);
    available -= (aligned_size + sizeof(wmem_block_chunk_t));

    /* set the new values for the chunk */
    extra->len  = (guint32) available;
    extra->last = last;
    extra->prev = (guint32) (aligned_size + sizeof(wmem_block_chunk_t));
    extra->used = FALSE;

    /* add it to the free list */
    wmem_block_add_to_free_list(allocator, extra);
}

/* Initializes a single unused chunk at the beginning of the block, and
 * adds that chunk to the free list. */
static void
wmem_block_init_block(wmem_block_allocator_t *allocator, void *block)
{
    wmem_block_chunk_t *chunk;

    /* a new block contains one chunk, right at the beginning */
    chunk = (wmem_block_chunk_t*) block;
    chunk->used = FALSE;
    chunk->last = TRUE;
    chunk->prev = 0;
    chunk->len = WMEM_BLOCK_SIZE;
    WMEM_GET_FREE(chunk)->in_free_list = FALSE;

    /* since the chunk is free and a brand new block, it gets added right to the
     * head of the free list */
    wmem_block_add_to_free_list_after(allocator, chunk, NULL);

    /* if the insert point was the head of the list as well, move
     * it after since this chunk is definitely a priority */
    if (allocator->free_insert_point == NULL) {
        allocator->free_insert_point = chunk;
    }
}

/* Creates a new block, and initializes it. */
static void
wmem_block_new_block(wmem_block_allocator_t *allocator)
{
    void *block;

    /* allocate the new block and add it to the block list */
    block = g_malloc(WMEM_BLOCK_SIZE);
    allocator->block_list = g_slist_prepend(allocator->block_list, block);

    /* initialize it */
    wmem_block_init_block(allocator, block);
}

/* API */
static void *
wmem_block_alloc(void *private_data, const size_t size)
{
    wmem_block_allocator_t *allocator = (wmem_block_allocator_t*) private_data;
    wmem_block_chunk_t     *chunk;

    /* We can't allocate more than will fit in a block (less our header),
     * which is an aweful lot. */
    g_assert(size < WMEM_BLOCK_SIZE - sizeof(wmem_block_chunk_t));

    if (allocator->free_list_head == NULL) {
        /* No free chunks at all, grab a new block */
        wmem_block_new_block(allocator);
    }
    else if (WMEM_CHUNK_DATA_LEN(allocator->free_list_head) < size) {
        /* First free chunk isn't big enough. Try the next one. */
        chunk = allocator->free_list_head;
        wmem_block_remove_from_free_list(allocator, chunk);
        if (allocator->free_list_head == NULL ||
                WMEM_CHUNK_DATA_LEN(allocator->free_list_head) < size) {
            /* Next one isn't big enough (or there is no next one) so grab
             * a new block */
            wmem_block_new_block(allocator);
        }
        /* Add the old block back (it may still deserve to be listed, just
         * deprioritized). This is a no-op if it is not large enough. */
        wmem_block_add_to_free_list(allocator, chunk);
    }

    chunk = allocator->free_list_head;

    /* if we still don't have the space at this point, something is wrong */
    g_assert(size <= WMEM_CHUNK_DATA_LEN(chunk));

    /* Split our chunk into two to preserve any trailing free space */
    wmem_block_split_free_chunk(allocator, chunk, size);

    /* if our split reduced our size too much, something went wrong */
    g_assert(size <= WMEM_CHUNK_DATA_LEN(chunk));

    /* mark it as used */
    chunk->used = TRUE;

    /* and return the user's pointer */
    return WMEM_CHUNK_DATA(chunk);
}

static void
wmem_block_free(void *private_data, void *ptr)
{
    wmem_block_allocator_t *allocator = (wmem_block_allocator_t*) private_data;
    wmem_block_chunk_t     *chunk;

    chunk = WMEM_DATA_TO_CHUNK(ptr);

    g_assert(chunk->used);

    /* mark it as unused */
    chunk->used = FALSE;

    /* merge it with any other free chunks adjacent to it, so that contiguous
     * free space doesn't get fragmented */
    wmem_block_merge_free(allocator, chunk);

    /* Add it to the free list. If it isn't big enough, this is a no-op */
    wmem_block_add_to_free_list(allocator, chunk);
}

static void *
wmem_block_realloc(void *private_data, void *ptr, const size_t size)
{
    wmem_block_allocator_t *allocator = (wmem_block_allocator_t*) private_data;
    wmem_block_chunk_t     *chunk;

    chunk = WMEM_DATA_TO_CHUNK(ptr);

    g_assert(chunk->used);

    if (size > WMEM_CHUNK_DATA_LEN(chunk)) {
        /* grow */
        if (WMEM_CHUNK_NEXT(chunk) &&
            (!WMEM_CHUNK_NEXT(chunk)->used) &&
            (size < WMEM_CHUNK_DATA_LEN(chunk) + WMEM_CHUNK_NEXT(chunk)->len)) {
            /* the next chunk is free and has enough extra, so just grab
             * from that */
            wmem_block_split_free_chunk(allocator, chunk,
                    (size - WMEM_CHUNK_DATA_LEN(chunk)
                     - sizeof(wmem_block_chunk_t)));
            return ptr;
        }
        else {
            /* no room to grow, need to alloc, copy, free */
            void *newptr;

            newptr = wmem_block_alloc(private_data, size);
            memcpy(newptr, ptr, WMEM_CHUNK_DATA_LEN(chunk));
            wmem_block_free(private_data, ptr);

            return newptr;
        }
    }
    else if (size < WMEM_CHUNK_DATA_LEN(chunk)) {
        /* shrink */
        wmem_block_split_used_chunk(allocator, chunk, size);

        return ptr;
    }

    /* no-op */
    return ptr;
}

static void
wmem_block_free_all(void *private_data)
{
    wmem_block_allocator_t *allocator = (wmem_block_allocator_t*) private_data;
    GSList *tmp;

    /* the existing free list is entirely irrelevant */
    allocator->free_list_head = NULL;
    allocator->free_insert_point = NULL;

    /* iterate through the blocks, reinitializing each one */
    tmp = allocator->block_list;

    while (tmp) {
        wmem_block_init_block(allocator, tmp->data);
        tmp = tmp->next;
    }
}

static void
wmem_block_gc(void *private_data)
{
    wmem_block_allocator_t *allocator = (wmem_block_allocator_t*) private_data;
    GSList *tmp, *new_block_list = NULL;
    wmem_block_chunk_t *chunk;

    /* Walk through the blocks, adding used blocks to a new list and
     * completely destroying unused blocks. The newly built list is the new
     * block list. */
    tmp = allocator->block_list;

    while (tmp) {
        chunk = (wmem_block_chunk_t *) tmp->data;

        if (!chunk->used && chunk->last) {
            /* if the first chunk is also the last, and is unused, then
             * the block as a whole is entirely unused, so return it to the
             * OS */
            g_free(chunk);
        }
        else {
            /* part of this block is used, so add it to the new block list */
            new_block_list = g_slist_prepend(new_block_list, chunk);
        }

        tmp = tmp->next;
    }

    /* free the data structure for the old list */
    g_slist_free(allocator->block_list);
    /* and store the new list */
    allocator->block_list = new_block_list;
}

static void
wmem_block_allocator_destroy(wmem_allocator_t *allocator)
{
    wmem_block_allocator_t *real_allocator;

    real_allocator = (wmem_block_allocator_t*) allocator->private_data;

    /* wmem guarantees that free_all() is called directly before this, so
     * calling gc will return all our blocks to the OS automatically */
    wmem_block_gc(real_allocator);

    /* then just free the allocator structs */
    g_free(real_allocator);
    g_free(allocator);
}

wmem_allocator_t *
wmem_block_allocator_new(void)
{
    wmem_allocator_t       *allocator;
    wmem_block_allocator_t *block_allocator;

    allocator       = g_new(wmem_allocator_t, 1);
    block_allocator = g_new(wmem_block_allocator_t, 1);

    allocator->private_data = (void*) block_allocator;

    allocator->alloc   = &wmem_block_alloc;
    allocator->realloc = &wmem_block_realloc;
    allocator->free    = &wmem_block_free;

    allocator->free_all = &wmem_block_free_all;
    allocator->gc       = &wmem_block_gc;
    allocator->destroy  = &wmem_block_allocator_destroy;

    block_allocator->block_list        = NULL;
    block_allocator->free_list_head    = NULL;
    block_allocator->free_insert_point = NULL;

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
