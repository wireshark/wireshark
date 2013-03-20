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

#include "config.h"

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
    /* Just the length of real_data, not counting the canaries */
    gsize   data_len;

    guint8 *leading_canary;
    guint8 *real_data;
    guint8 *trailing_canary;
} wmem_strict_allocator_block_t;

typedef struct _wmem_strict_allocator_t {
    GHashTable *block_table;
} wmem_strict_allocator_t;

/*
 * some internal helper functions
 */
static void
wmem_strict_block_check_canaries(wmem_strict_allocator_block_t *block)
{
    guint i;

    for (i=0; i<WMEM_CANARY_SIZE; i++) {
        g_assert(block->leading_canary[i]  == WMEM_CANARY_VALUE);
        g_assert(block->trailing_canary[i] == WMEM_CANARY_VALUE);
    }
}

/* wrapper for use with g_hash_table_foreach() */
static void
wmem_strict_ghash_check_canaries(gpointer key _U_, gpointer value,
        gpointer user_data _U_)
{
    wmem_strict_block_check_canaries((wmem_strict_allocator_block_t *)value);
}

static void
wmem_strict_block_free(wmem_strict_allocator_block_t *block)
{
    memset(block->real_data, WMEM_POSTFILL, block->data_len);

    g_free(block->leading_canary);
    g_slice_free(wmem_strict_allocator_block_t, block);
}

/* wrapper for use with g_hash_table_new_full() */
static void
wmem_strict_ghash_block_free(gpointer data)
{
    wmem_strict_block_free((wmem_strict_allocator_block_t *)data);
}

static wmem_strict_allocator_block_t *
wmem_strict_block_new(const size_t size)
{
    wmem_strict_allocator_block_t *block;
    
    block = g_slice_new(wmem_strict_allocator_block_t);

    block->data_len        = size;
    block->leading_canary  = (guint8 *)g_malloc(block->data_len + (2 * WMEM_CANARY_SIZE));
    block->real_data       = block->leading_canary + WMEM_CANARY_SIZE;
    block->trailing_canary = block->real_data + block->data_len;

    memset(block->leading_canary,  WMEM_CANARY_VALUE, WMEM_CANARY_SIZE);
    memset(block->real_data,       WMEM_PREFILL,      block->data_len);
    memset(block->trailing_canary, WMEM_CANARY_VALUE, WMEM_CANARY_SIZE);

    return block;
}

/*
 * public API functions
 */
static void *
wmem_strict_alloc(void *private_data, const size_t size)
{
    wmem_strict_allocator_t       *allocator;
    wmem_strict_allocator_block_t *block;
    
    allocator = (wmem_strict_allocator_t*) private_data;

    block = wmem_strict_block_new(size);

    /* we store a pointer to our header, keyed by a pointer to the actual
     * block we return to the user */
    g_hash_table_insert(allocator->block_table, block->real_data, block);
    
    return block->real_data;
}

static void
wmem_strict_free(void *private_data, void *ptr)
{
    wmem_strict_allocator_t       *allocator;
    wmem_strict_allocator_block_t *block;
    
    allocator = (wmem_strict_allocator_t*) private_data;

    block = (wmem_strict_allocator_block_t *)g_hash_table_lookup(allocator->block_table, ptr);

    g_assert(block);

    wmem_strict_block_check_canaries(block);

    g_hash_table_remove(allocator->block_table, ptr);
}

static void *
wmem_strict_realloc(void *private_data, void *ptr, const size_t size)
{
    gsize                          copy_len;
    wmem_strict_allocator_t       *allocator;
    wmem_strict_allocator_block_t *block, *newblock;
    
    allocator = (wmem_strict_allocator_t*) private_data;

    /* retrieve and check the old block */
    block = (wmem_strict_allocator_block_t *)g_hash_table_lookup(allocator->block_table, ptr);
    g_assert(block);
    wmem_strict_block_check_canaries(block);
    
    /* create a new block */
    newblock = wmem_strict_block_new(size);

    /* copy from the old block to the new */
    if (block->data_len > newblock->data_len) {
        copy_len = newblock->data_len;
    }
    else {
        copy_len = block->data_len;
    }

    memcpy(newblock->real_data, block->real_data, copy_len);

    /* update the hash table */
    g_hash_table_remove(allocator->block_table, ptr);
    g_hash_table_insert(allocator->block_table, newblock->real_data, newblock);
    
    return newblock->real_data;
}

void
wmem_strict_check_canaries(wmem_allocator_t *allocator)
{
    wmem_strict_allocator_t *private_allocator;

    if (allocator->type != WMEM_ALLOCATOR_STRICT) {
        return;
    }
    
    private_allocator = (wmem_strict_allocator_t*) allocator->private_data;

    g_hash_table_foreach(private_allocator->block_table,
            &wmem_strict_ghash_check_canaries, NULL);
}

static void
wmem_strict_free_all(void *private_data)
{
    wmem_strict_allocator_t       *allocator;

    allocator = (wmem_strict_allocator_t*) private_data;

    g_hash_table_foreach(allocator->block_table,
            &wmem_strict_ghash_check_canaries, NULL);

    g_hash_table_remove_all(allocator->block_table);
}

static void
wmem_strict_gc(void *private_data _U_)
{
    /* We don't really have anything to garbage-collect, but it might be worth
     * checking our canaries at this point? */
}

static void
wmem_strict_allocator_destroy(wmem_allocator_t *allocator)
{
    wmem_strict_allocator_t *private_allocator;
    
    private_allocator = (wmem_strict_allocator_t*) allocator->private_data;

    g_hash_table_destroy(private_allocator->block_table);
    g_slice_free(wmem_strict_allocator_t, private_allocator);
    g_slice_free(wmem_allocator_t, allocator);
}

wmem_allocator_t *
wmem_strict_allocator_new(void)
{
    wmem_allocator_t        *allocator;
    wmem_strict_allocator_t *strict_allocator;

    allocator        = g_slice_new(wmem_allocator_t);
    strict_allocator = g_slice_new(wmem_strict_allocator_t);

    allocator->alloc   = &wmem_strict_alloc;
    allocator->realloc = &wmem_strict_realloc;
    allocator->free    = &wmem_strict_free;

    allocator->free_all = &wmem_strict_free_all;
    allocator->gc       = &wmem_strict_gc;
    allocator->destroy  = &wmem_strict_allocator_destroy;

    allocator->private_data = (void*) strict_allocator;

    strict_allocator->block_table = g_hash_table_new_full(
            &g_direct_hash, &g_direct_equal,
            NULL, &wmem_strict_ghash_block_free);

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
