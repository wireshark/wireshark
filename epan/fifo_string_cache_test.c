/* fifo_string_cache_test.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#undef G_DISABLE_ASSERT

#include <stdio.h>
#include <string.h>
#include <glib.h>

#include "fifo_string_cache.h"


// Simple test of insertion and checking its true/false values
static void
test_fifo_string_cache_01(void)
{
    fifo_string_cache_t fcache;
    bool has;

    fifo_string_cache_init(&fcache, 10, NULL);

    has = fifo_string_cache_insert(&fcache, "alpha");
    g_assert_false(has);

    has = fifo_string_cache_insert(&fcache, "alpha");
    g_assert_true(has);

    has = fifo_string_cache_insert(&fcache, "beta");
    g_assert_false(has);

    has = fifo_string_cache_insert(&fcache, "beta");
    g_assert_true(has);

    has = fifo_string_cache_insert(&fcache, "alpha");
    g_assert_true(has);

    fifo_string_cache_free(&fcache);
}

// Is the max_entries honored?
static void
test_fifo_string_cache_02(void)
{
    fifo_string_cache_t fcache;
    bool has;
    fifo_string_cache_init(&fcache, 4, NULL);

    // Insert 4 items
    has = fifo_string_cache_insert(&fcache, "alpha");
    g_assert_false(has);
    has = fifo_string_cache_insert(&fcache, "beta");
    g_assert_false(has);
    has = fifo_string_cache_insert(&fcache, "gamma");
    g_assert_false(has);
    has = fifo_string_cache_insert(&fcache, "delta");
    g_assert_false(has);

    // They should all be there
    has = fifo_string_cache_contains(&fcache, "alpha");
    g_assert_true(has);
    has = fifo_string_cache_contains(&fcache, "beta");
    g_assert_true(has);
    has = fifo_string_cache_contains(&fcache, "gamma");
    g_assert_true(has);
    has = fifo_string_cache_contains(&fcache, "delta");
    g_assert_true(has);

    // Add a 5th item
    has = fifo_string_cache_insert(&fcache, "epsilon");
    g_assert_false(has);

    // The first one should no longer be there
    has = fifo_string_cache_contains(&fcache, "alpha");
    g_assert_false(has); // false
    has = fifo_string_cache_contains(&fcache, "beta");
    g_assert_true(has);
    has = fifo_string_cache_contains(&fcache, "gamma");
    g_assert_true(has);
    has = fifo_string_cache_contains(&fcache, "delta");
    g_assert_true(has);
    has = fifo_string_cache_contains(&fcache, "epsilon");
    g_assert_true(has);

    // Add a 6th item
    has = fifo_string_cache_insert(&fcache, "zeta");
    g_assert_false(has);

    // The first two should no longer be there
    has = fifo_string_cache_contains(&fcache, "alpha");
    g_assert_false(has); // false
    has = fifo_string_cache_contains(&fcache, "beta");
    g_assert_false(has); // false
    has = fifo_string_cache_contains(&fcache, "gamma");
    g_assert_true(has);
    has = fifo_string_cache_contains(&fcache, "delta");
    g_assert_true(has);
    has = fifo_string_cache_contains(&fcache, "epsilon");
    g_assert_true(has);
    has = fifo_string_cache_contains(&fcache, "zeta");
    g_assert_true(has);

    fifo_string_cache_free(&fcache);
}

// Check a max_entries == 1, to ensure we don't have any mistakes
// at that end of the range
static void
test_fifo_string_cache_03(void)
{
    fifo_string_cache_t fcache;
    bool has;
    fifo_string_cache_init(&fcache, 1, NULL);

    // Insert
    has = fifo_string_cache_insert(&fcache, "alpha");
    g_assert_false(has);

    // Check
    has = fifo_string_cache_contains(&fcache, "alpha");
    g_assert_true(has);

    // Insert
    has = fifo_string_cache_insert(&fcache, "beta");
    g_assert_false(has);

    // Check
    has = fifo_string_cache_contains(&fcache, "alpha");
    g_assert_false(has);
    has = fifo_string_cache_contains(&fcache, "beta");
    g_assert_true(has);

    // Insert
    has = fifo_string_cache_insert(&fcache, "gamma");
    g_assert_false(has);

    // Check
    has = fifo_string_cache_contains(&fcache, "alpha");
    g_assert_false(has);
    has = fifo_string_cache_contains(&fcache, "beta");
    g_assert_false(has);
    has = fifo_string_cache_contains(&fcache, "gamma");
    g_assert_true(has);

    fifo_string_cache_free(&fcache);
}

// Test an unbounded maximum (max_entries == 0)
static void
test_fifo_string_cache_04(void)
{
    fifo_string_cache_t fcache;
    bool has;
    fifo_string_cache_init(&fcache, 0, g_free);

    // Insert; we call g_strdup because in this test, the cache owns the string
    has = fifo_string_cache_insert(&fcache, g_strdup("alpha"));
    g_assert_false(has);

    // Check
    has = fifo_string_cache_contains(&fcache, "alpha");
    g_assert_true(has);

    // Insert; we call g_strdup because in this test, the cache owns the string
    has = fifo_string_cache_insert(&fcache, g_strdup("beta"));
    g_assert_false(has);

    // Check
    has = fifo_string_cache_contains(&fcache, "alpha");
    g_assert_true(has);
    has = fifo_string_cache_contains(&fcache, "beta");
    g_assert_true(has);

    // Insert many
    int i;
    char *s;
    for (i = 0; i < 1000 ; i++) {
        s = g_strdup_printf("%d", i);
        has = fifo_string_cache_insert(&fcache, s);
        g_assert_false(has);
    }

    // Check everything
    has = fifo_string_cache_contains(&fcache, "alpha");
    g_assert_true(has);
    has = fifo_string_cache_contains(&fcache, "beta");
    g_assert_true(has);
    for (i = 0; i < 1000 ; i++) {
        s = g_strdup_printf("%d", i);
        has = fifo_string_cache_contains(&fcache, s);
        g_assert_true(has);
    }
    fifo_string_cache_free(&fcache);
}

int
main(int argc, char **argv)
{
    int result;

    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/fifo_string_cache/01",    test_fifo_string_cache_01);
    g_test_add_func("/fifo_string_cache/02",    test_fifo_string_cache_02);
    g_test_add_func("/fifo_string_cache/03",    test_fifo_string_cache_03);
    g_test_add_func("/fifo_string_cache/04",    test_fifo_string_cache_04);

    result = g_test_run();

    return result;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
