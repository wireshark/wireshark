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

#include <stdio.h>
#include <glib.h>
#include "wmem.h"
#include "wmem_allocator.h"
#include "wmem_allocator_block.h"
#include "wmem_allocator_simple.h"
#include "wmem_allocator_strict.h"
#include "config.h"

/* Glibs's testing functions were mostly introduced in 2.16 but Wireshark as
 * a whole supports older Glibs, so if we don't have a new enough Glib then stub
 * the test suite.
 */
#if !GLIB_CHECK_VERSION(2,16,0)
int
main()
{
    return 0;
}
#else

#define MAX_SIMULTANEOUS_ALLOCS 1024
#define MAX_ALLOC_SIZE (1024*64)
#define LIST_ITERS 10000

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
wmem_time_allocator(wmem_allocator_type_t type)
{
    int i, j;
    wmem_allocator_t *allocator;

    allocator = wmem_allocator_force_new(type);

    for (j=0; j<128; j++) {
        for (i=0; i<MAX_SIMULTANEOUS_ALLOCS; i++) {
            wmem_alloc(allocator, 8);
        }
        wmem_free_all(allocator);

        for (i=0; i<MAX_SIMULTANEOUS_ALLOCS; i++) {
            wmem_alloc(allocator, 256);
        }
        wmem_free_all(allocator);

        for (i=0; i<MAX_SIMULTANEOUS_ALLOCS; i++) {
            wmem_alloc(allocator, 1024);
        }
    }

    wmem_destroy_allocator(allocator);
}

static void
wmem_time_allocators(void)
{
    double simple_time, block_time;

    g_test_timer_start();
    wmem_time_allocator(WMEM_ALLOCATOR_SIMPLE);
    simple_time = g_test_timer_elapsed();

    g_test_timer_start();
    wmem_time_allocator(WMEM_ALLOCATOR_BLOCK);
    block_time = g_test_timer_elapsed();

    printf("(simple: %lf; block: %lf) ", simple_time, block_time);
    g_assert(simple_time > block_time);
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

static void
wmem_test_strutls(void)
{
    wmem_allocator_t   *allocator;
    const char         *orig_str;
    char               *new_str;

    allocator = wmem_allocator_force_new(WMEM_ALLOCATOR_STRICT);

    orig_str = "TEST1";
    new_str  = wmem_strdup(allocator, orig_str);
    g_assert_cmpstr(new_str, ==, orig_str);
    new_str[0] = 'X';
    g_assert_cmpstr(new_str, >, orig_str);
    wmem_strict_check_canaries(allocator);

    orig_str = "TEST123456789";
    new_str  = wmem_strndup(allocator, orig_str, 6);
    g_assert_cmpstr(new_str, ==, "TEST12");
    g_assert_cmpstr(new_str, <, orig_str);
    new_str[0] = 'X';
    g_assert_cmpstr(new_str, >, orig_str);
    wmem_strict_check_canaries(allocator);

    new_str = wmem_strdup_printf(allocator, "abc %s %% %d", "boo", 23);
    g_assert_cmpstr(new_str, ==, "abc boo % 23");
    wmem_strict_check_canaries(allocator);

    wmem_destroy_allocator(allocator);
}

static void
wmem_test_slist(void)
{
    wmem_allocator_t   *allocator;
    wmem_slist_t       *slist;
    wmem_slist_frame_t *frame;
    unsigned int        i;

    allocator = wmem_allocator_force_new(WMEM_ALLOCATOR_STRICT);

    slist = wmem_slist_new(allocator);
    g_assert(slist);
    g_assert(wmem_slist_count(slist) == 0);

    frame = wmem_slist_front(slist);
    g_assert(frame == NULL);

    for (i=0; i<LIST_ITERS; i++) {
        wmem_slist_prepend(slist, GINT_TO_POINTER(i));
        g_assert(wmem_slist_count(slist) == i+1);

        frame = wmem_slist_front(slist);
        g_assert(frame);
        g_assert(wmem_slist_frame_data(frame) == GINT_TO_POINTER(i));
    }

    i = LIST_ITERS - 1;
    frame = wmem_slist_front(slist);
    while (frame) {
        g_assert(wmem_slist_frame_data(frame) == GINT_TO_POINTER(i));
        i--;
        frame = wmem_slist_frame_next(frame);
    }

    i = LIST_ITERS - 2;
    while (wmem_slist_count(slist) > 1) {
        wmem_slist_remove(slist, GINT_TO_POINTER(i));
        i--;
    }
    wmem_slist_remove(slist, GINT_TO_POINTER(LIST_ITERS - 1));
    g_assert(wmem_slist_count(slist) == 0);
    g_assert(wmem_slist_front(slist) == NULL);

    wmem_destroy_allocator(allocator);
}

static void
wmem_test_strbuf(void)
{
    wmem_allocator_t   *allocator;
    wmem_strbuf_t      *strbuf;
    int                 i;

    allocator = wmem_allocator_force_new(WMEM_ALLOCATOR_STRICT);

    strbuf = wmem_strbuf_new(allocator, "TEST");
    g_assert(strbuf);
    g_assert_cmpstr(wmem_strbuf_get_str(strbuf), ==, "TEST");
    g_assert(wmem_strbuf_get_len(strbuf) == 4);

    wmem_strbuf_append(strbuf, "FUZZ");
    g_assert_cmpstr(wmem_strbuf_get_str(strbuf), ==, "TESTFUZZ");
    g_assert(wmem_strbuf_get_len(strbuf) == 8);

    wmem_strbuf_append_printf(strbuf, "%d%s", 3, "a");
    g_assert_cmpstr(wmem_strbuf_get_str(strbuf), ==, "TESTFUZZ3a");
    g_assert(wmem_strbuf_get_len(strbuf) == 10);

    strbuf = wmem_strbuf_sized_new(allocator, 10, 10);
    g_assert(strbuf);
    g_assert_cmpstr(wmem_strbuf_get_str(strbuf), ==, "");
    g_assert(wmem_strbuf_get_len(strbuf) == 0);

    wmem_strbuf_append(strbuf, "FUZZ");
    g_assert_cmpstr(wmem_strbuf_get_str(strbuf), ==, "FUZZ");
    g_assert(wmem_strbuf_get_len(strbuf) == 4);

    wmem_strbuf_append_printf(strbuf, "%d%s", 3, "abcdefghijklmnop");
    g_assert_cmpstr(wmem_strbuf_get_str(strbuf), ==, "FUZZ3abcd");
    g_assert(wmem_strbuf_get_len(strbuf) == 9);

    wmem_free_all(allocator);

    strbuf = wmem_strbuf_new(allocator, "TEST");
    for (i=0; i<1024; i++) {
        if (g_test_rand_bit()) {
            wmem_strbuf_append(strbuf, "ABC");
        }
        else {
            wmem_strbuf_append_printf(strbuf, "%d%d", 3, 777);
        }
        wmem_strict_check_canaries(allocator);
    }
    g_assert(strlen(wmem_strbuf_get_str(strbuf)) ==
             wmem_strbuf_get_len(strbuf));

    wmem_destroy_allocator(allocator);
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/wmem/allocator/block",  wmem_test_allocator_block);
    g_test_add_func("/wmem/allocator/simple", wmem_test_allocator_simple);
    g_test_add_func("/wmem/allocator/strict", wmem_test_allocator_strict);
    g_test_add_func("/wmem/allocator/times",  wmem_time_allocators);

    g_test_add_func("/wmem/utils/strings", wmem_test_strutls);

    g_test_add_func("/wmem/datastruct/slist",  wmem_test_slist);
    g_test_add_func("/wmem/datastruct/strbuf", wmem_test_strbuf);

    return g_test_run();
}

#endif /* !GLIB_CHECK_VERSION(2,16,0) */

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
