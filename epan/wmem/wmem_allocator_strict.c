/* wmem_allocator_strict.c
 * Wireshark Memory Manager Strict Allocator
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

/* In this allocator, we do everything we can to catch invalid memory accesses.
 * This includes using canaries (what Valgrind calls redzones) and
 * filling allocated and freed memory with garbage. Valgrind is still the
 * better tool on the platforms where it is available - use it instead if
 * possible.
 */

#define WMEM_CANARY_SIZE  16
#define WMEM_CANARY_VALUE 0x8E

#define WMEM_PREFILL  0xA1
#define WMEM_POSTFILL 0x1A

typedef struct _wmem_strict_allocator_block_t {
    /* Simple manual singly-linked list of allocations */
    struct _wmem_strict_allocator_block_t *next;

    /* Just the length of real_data, not counting the canaries */
    gsize   data_len;

    guint8 *leading_canary;
    guint8 *real_data;
    guint8 *trailing_canary;
} wmem_strict_allocator_block_t;

typedef struct _wmem_strict_allocator_t {
    wmem_strict_allocator_block_t *block_list;
} wmem_strict_allocator_t;

static void *
wmem_strict_alloc(void *private_data, const size_t size)
{
    wmem_strict_allocator_t       *allocator;
    wmem_strict_allocator_block_t *block;
    
    allocator = (wmem_strict_allocator_t*) private_data;

    block = g_new(wmem_strict_allocator_block_t, 1);

    block->data_len        = size;
    block->leading_canary  = g_malloc(block->data_len + (2 * WMEM_CANARY_SIZE));
    block->real_data       = block->leading_canary + WMEM_CANARY_SIZE;
    block->trailing_canary = block->real_data + block->data_len;
    block->next            = allocator->block_list;
    allocator->block_list  = block;

    memset(block->leading_canary,  WMEM_CANARY_VALUE, WMEM_CANARY_SIZE);
    memset(block->real_data,       WMEM_PREFILL,      block->data_len);
    memset(block->trailing_canary, WMEM_CANARY_VALUE, WMEM_CANARY_SIZE);
    
    return block->real_data;
}

static void
wmem_strict_real_check_canaries(wmem_strict_allocator_t *allocator)
{
    guint i;
    wmem_strict_allocator_block_t *block;

    block = allocator->block_list;

    while (block) {
        for (i=0; i<WMEM_CANARY_SIZE; i++) {
            g_assert(block->leading_canary[i]  == WMEM_CANARY_VALUE);
            g_assert(block->trailing_canary[i] == WMEM_CANARY_VALUE);
        }
        block = block->next;
    }
}

void
wmem_strict_check_canaries(wmem_allocator_t *allocator)
{
    /* XXX: Should this be a g_assert() instead? This is more of a general API
     * issue - should allocator-specific functions be safe to call with an
     * allocator of the wrong type or not? And how should they interact with the
     * WIRESHARK_DEBUG_WMEM_OVERRIDE environment variable? */
    if (allocator->type != WMEM_ALLOCATOR_STRICT) {
        return;
    }

    wmem_strict_real_check_canaries(allocator->private_data);
}

static void
wmem_strict_free_all(void *private_data)
{
    wmem_strict_allocator_t       *allocator;
    wmem_strict_allocator_block_t *block, *tmp;

    allocator = (wmem_strict_allocator_t*) private_data;

    wmem_strict_real_check_canaries(allocator);

    block = allocator->block_list;

    while (block) {
        memset(block->real_data, WMEM_POSTFILL, block->data_len);

        g_free(block->leading_canary);

        tmp = block;
        block = block->next;
        g_free(tmp);
    }

    allocator->block_list = NULL;
}

static void
wmem_strict_allocator_destroy(wmem_allocator_t *allocator)
{
    g_free(allocator->private_data);
    g_free(allocator);
}

wmem_allocator_t *
wmem_strict_allocator_new(void)
{
    wmem_allocator_t        *allocator;
    wmem_strict_allocator_t *strict_allocator;

    allocator        = g_new(wmem_allocator_t, 1);
    strict_allocator = g_new(wmem_strict_allocator_t, 1);

    allocator->alloc        = &wmem_strict_alloc;
    allocator->free_all     = &wmem_strict_free_all;
    allocator->destroy      = &wmem_strict_allocator_destroy;
    allocator->private_data = (void*) strict_allocator;

    /* TODO */
    allocator->realloc = NULL;
    allocator->free    = NULL;
    allocator->gc      = NULL;

    strict_allocator->block_list = NULL;

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
