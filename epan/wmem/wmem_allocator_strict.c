/* wmem_allocator_strict.c
 * Wireshark Memory Manager Strict Allocator
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

#include "config.h"

#include <string.h>

#include <glib.h>

#include "wmem_core.h"
#include "wmem_allocator.h"
#include "wmem_allocator_strict.h"

/* In this allocator, we do everything we can to catch invalid memory accesses.
 * This includes using canaries (what Valgrind calls redzones) and
 * filling allocated and freed memory with garbage. Valgrind is still the
 * better tool on the platforms where it is available - use it instead if
 * possible.
 */

#define WMEM_CANARY_SIZE  8 /* in bytes */
#define WMEM_CANARY_VALUE 0x9E

#define WMEM_PREFILL  0xA1
#define WMEM_POSTFILL 0x1A

typedef struct _wmem_strict_allocator_block_t {
    struct _wmem_strict_allocator_block_t *prev, *next;

    /* Just the length of real_data, not counting the canaries */
    gsize data_len;
} wmem_strict_allocator_block_t;

#define WMEM_DATA_TO_BLOCK(DATA) ((wmem_strict_allocator_block_t*)((guint8*)(DATA) - WMEM_CANARY_SIZE - sizeof(wmem_strict_allocator_block_t)))
#define WMEM_BLOCK_TO_DATA(BLOCK) ((void*)((guint8*)(BLOCK) + WMEM_CANARY_SIZE + sizeof(wmem_strict_allocator_block_t)))
#define WMEM_BLOCK_TO_PRE_CANARY(BLOCK) ((guint8*)(BLOCK) + sizeof(wmem_strict_allocator_block_t))
#define WMEM_BLOCK_TO_POST_CANARY(BLOCK) ((guint8*)(BLOCK) + WMEM_CANARY_SIZE + sizeof(wmem_strict_allocator_block_t) + (BLOCK)->data_len)
#define WMEM_FULL_SIZE(SIZE) ((SIZE) + sizeof(wmem_strict_allocator_block_t) + (2*WMEM_CANARY_SIZE))

typedef struct _wmem_strict_allocator_t {
    wmem_strict_allocator_block_t *blocks;
} wmem_strict_allocator_t;

/*
 * some internal helper functions
 */
static inline void
wmem_strict_block_check_canaries(wmem_strict_allocator_block_t *block)
{
    guint i;
    guint8 *canary;

    canary = WMEM_BLOCK_TO_PRE_CANARY(block);
    for (i=0; i<WMEM_CANARY_SIZE; i++) g_assert(canary[i] == WMEM_CANARY_VALUE);

    canary = WMEM_BLOCK_TO_POST_CANARY(block);
    for (i=0; i<WMEM_CANARY_SIZE; i++) g_assert(canary[i] == WMEM_CANARY_VALUE);
}

/*
 * public API functions
 */
static void *
wmem_strict_alloc(void *private_data, const size_t size)
{
    wmem_strict_allocator_t       *allocator;
    wmem_strict_allocator_block_t *block;
    guint   i;
    guint8 *canary;

    allocator = (wmem_strict_allocator_t*) private_data;

    block = (wmem_strict_allocator_block_t *)wmem_alloc(NULL, WMEM_FULL_SIZE(size));
    block->data_len = size;

    memset(WMEM_BLOCK_TO_DATA(block), WMEM_PREFILL, block->data_len);

    canary = WMEM_BLOCK_TO_PRE_CANARY(block);
    for (i=0; i<WMEM_CANARY_SIZE; i++) canary[i] = WMEM_CANARY_VALUE;

    canary = WMEM_BLOCK_TO_POST_CANARY(block);
    for (i=0; i<WMEM_CANARY_SIZE; i++) canary[i] = WMEM_CANARY_VALUE;

    if (allocator->blocks) {
        allocator->blocks->prev = block;
    }
    block->next = allocator->blocks;
    block->prev = NULL;
    allocator->blocks = block;

    return WMEM_BLOCK_TO_DATA(block);
}

static void
wmem_strict_free(void *private_data, void *ptr)
{
    wmem_strict_allocator_t       *allocator;
    wmem_strict_allocator_block_t *block;

    allocator = (wmem_strict_allocator_t*) private_data;

    block = WMEM_DATA_TO_BLOCK(ptr);

    wmem_strict_block_check_canaries(block);

    if (block->next) {
        block->next->prev = block->prev;
    }

    if (block->prev) {
        block->prev->next = block->next;
    }
    else {
        allocator->blocks = block->next;
    }

    memset(block, WMEM_POSTFILL, WMEM_FULL_SIZE(block->data_len));

    wmem_free(NULL, block);
}

static void *
wmem_strict_realloc(void *private_data, void *ptr, const size_t size)
{
    wmem_strict_allocator_block_t *block;
    void                          *new_ptr;

    block = WMEM_DATA_TO_BLOCK(ptr);

    /* create a new block */
    new_ptr = wmem_strict_alloc(private_data, size);

    /* copy from the old block to the new */
    if (block->data_len > size) {
        memcpy(new_ptr, ptr, size);
    }
    else {
        memcpy(new_ptr, ptr, block->data_len);
    }

    /* free the old block */
    wmem_strict_free(private_data, ptr);

    return new_ptr;
}

void
wmem_strict_check_canaries(wmem_allocator_t *allocator)
{
    wmem_strict_allocator_t *private_allocator;
    wmem_strict_allocator_block_t *block;

    if (allocator->type != WMEM_ALLOCATOR_STRICT) {
        return;
    }

    private_allocator = (wmem_strict_allocator_t*) allocator->private_data;

    block = private_allocator->blocks;
    while (block) {
        wmem_strict_block_check_canaries(block);
        block = block->next;
    }
}

static void
wmem_strict_free_all(void *private_data)
{
    wmem_strict_allocator_t       *allocator;

    allocator = (wmem_strict_allocator_t*) private_data;

    while (allocator->blocks) {
        wmem_strict_free(private_data, WMEM_BLOCK_TO_DATA(allocator->blocks));
    }
}

static void
wmem_strict_gc(void *private_data _U_)
{
    /* We don't really have anything to garbage-collect, but it might be worth
     * checking our canaries at this point? */
}

static void
wmem_strict_allocator_cleanup(void *private_data)
{
    wmem_free(NULL, private_data);
}

void
wmem_strict_allocator_init(wmem_allocator_t *allocator)
{
    wmem_strict_allocator_t *strict_allocator;

    strict_allocator = wmem_new(NULL, wmem_strict_allocator_t);

    allocator->alloc   = &wmem_strict_alloc;
    allocator->realloc = &wmem_strict_realloc;
    allocator->free    = &wmem_strict_free;

    allocator->free_all = &wmem_strict_free_all;
    allocator->gc       = &wmem_strict_gc;
    allocator->cleanup  = &wmem_strict_allocator_cleanup;

    allocator->private_data = (void*) strict_allocator;

    strict_allocator->blocks = NULL;
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
