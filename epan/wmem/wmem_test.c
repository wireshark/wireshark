/* wmem_test.c
 * Wireshark Memory Manager Tests
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

#include <glib.h>
#include "wmem.h"
#include "wmem_allocator.h"
#include "wmem_allocator_block.h"
#include "wmem_allocator_simple.h"
#include "wmem_allocator_strict.h"
#include "config.h"

#define MAX_SIMULTANEOUS_ALLOCS 1024
#define MAX_ALLOC_SIZE (1024*64)

typedef void (*wmem_verify_func)(wmem_allocator_t *allocator);

/* A local copy of wmem_allocator_new that ignores the
 * WIRESHARK_DEBUG_WMEM_OVERRIDE variable so that test functions are
 * guaranteed to actually get the allocator type they asked for */
static wmem_allocator_t *
wmem_allocator_force_new(const wmem_allocator_type_t type)
{
    wmem_allocator_t      *allocator;

    switch (type) {
        case WMEM_ALLOCATOR_SIMPLE:
            allocator = wmem_simple_allocator_new();
            break;
        case WMEM_ALLOCATOR_BLOCK:
            allocator = wmem_block_allocator_new();
            break;
        case WMEM_ALLOCATOR_STRICT:
            allocator = wmem_strict_allocator_new();
            break;
        default:
            g_assert_not_reached();
            /* This is necessary to squelch MSVC errors; is there
	       any way to tell it that g_assert_not_reached()
	       never returns? */
            return NULL;
    };

    allocator->type = type;

    return allocator;
}

static void
wmem_test_allocator(wmem_allocator_type_t type, wmem_verify_func verify)
{
    int i;
    char *ptrs[MAX_SIMULTANEOUS_ALLOCS];
    wmem_allocator_t *allocator;

    allocator = wmem_allocator_force_new(type);

    if (verify) (*verify)(allocator);
    
    /* start with some fairly simple deterministic tests */

    /* we use wmem_alloc0 in part because it tests slightly more code, but
     * primarily so that if the allocator doesn't give us enough memory or
     * gives us memory that includes its own metadata, we write to it and
     * things go wrong, causing the tests to fail */
    for (i=0; i<MAX_SIMULTANEOUS_ALLOCS; i++) {
        ptrs[i] = (char *)wmem_alloc0(allocator, 8);
    }
    for (i=0; i<MAX_SIMULTANEOUS_ALLOCS; i++) {
        wmem_free(allocator, ptrs[i]);
    }

    if (verify) (*verify)(allocator);
    wmem_free_all(allocator);
    wmem_gc(allocator);
    if (verify) (*verify)(allocator);

    for (i=0; i<MAX_SIMULTANEOUS_ALLOCS; i++) {
        ptrs[i] = (char *)wmem_alloc0(allocator, 64);
    }
    for (i=0; i<MAX_SIMULTANEOUS_ALLOCS; i++) {
        wmem_free(allocator, ptrs[i]);
    }

    if (verify) (*verify)(allocator);
    wmem_free_all(allocator);
    wmem_gc(allocator);
    if (verify) (*verify)(allocator);

    for (i=0; i<MAX_SIMULTANEOUS_ALLOCS; i++) {
        ptrs[i] = (char *)wmem_alloc0(allocator, 512);
    }
    for (i=MAX_SIMULTANEOUS_ALLOCS-1; i>=0; i--) {
        /* no wmem_realloc0 so just use memset manually */
        ptrs[i] = (char *)wmem_realloc(allocator, ptrs[i], MAX_ALLOC_SIZE);
        memset(ptrs[i], 0, MAX_ALLOC_SIZE);
    }
    for (i=0; i<MAX_SIMULTANEOUS_ALLOCS; i++) {
        wmem_free(allocator, ptrs[i]);
    }

    if (verify) (*verify)(allocator);
    wmem_free_all(allocator);
    wmem_gc(allocator);
    if (verify) (*verify)(allocator);

    /* now do some random fuzz-like tests */

    /* reset our ptr array */
    for (i=0; i<MAX_SIMULTANEOUS_ALLOCS; i++) {
        ptrs[i] = NULL;
    }

    /* Run ~64,000 iterations */
    for (i=0; i<1024*64; i++) {
        gint ptrs_index;
        gint new_size;
        
        /* returns value 0 <= x < MAX_SIMULTANEOUS_ALLOCS which is a valid
         * index into ptrs */
        ptrs_index = g_test_rand_int_range(0, MAX_SIMULTANEOUS_ALLOCS);

        if (ptrs[ptrs_index] == NULL) {
            /* if that index is unused, allocate some random amount of memory
             * between 0 and MAX_ALLOC_SIZE */
            new_size = g_test_rand_int_range(0, MAX_ALLOC_SIZE);

            ptrs[ptrs_index] = (char *) wmem_alloc0(allocator, new_size);
        }
        else if (g_test_rand_bit()) {
            /* the index is used, and our random bit has determined we will be
             * reallocating instead of freeing. Do so to some random size
             * between 0 and MAX_ALLOC_SIZE, then manually zero the
             * new memory */
            new_size = g_test_rand_int_range(0, MAX_ALLOC_SIZE);

            ptrs[ptrs_index] = (char *) wmem_realloc(allocator,
                    ptrs[ptrs_index], new_size);

            memset(ptrs[ptrs_index], 0, new_size);
        }
        else {
            /* the index is used, and our random bit has determined we will be
             * freeing instead of reallocating. Do so and NULL the pointer for
             * the next iteration. */
            wmem_free(allocator, ptrs[ptrs_index]);
            ptrs[ptrs_index] = NULL;
        }
        if (verify) (*verify)(allocator);
    }

    wmem_destroy_allocator(allocator);
}

static void
wmem_test_allocator_block(void)
{
    wmem_test_allocator(WMEM_ALLOCATOR_BLOCK, &wmem_block_verify);
}

static void
wmem_test_allocator_simple(void)
{
    wmem_test_allocator(WMEM_ALLOCATOR_SIMPLE, NULL);
}

static void
wmem_test_allocator_strict(void)
{
    wmem_test_allocator(WMEM_ALLOCATOR_STRICT, &wmem_strict_check_canaries);
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/wmem/allocator/block",  wmem_test_allocator_block);
    g_test_add_func("/wmem/allocator/simple", wmem_test_allocator_simple);
    g_test_add_func("/wmem/allocator/strict", wmem_test_allocator_strict);

    return g_test_run();
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
