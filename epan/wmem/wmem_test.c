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
#include "config.h"

typedef struct _wmem_test_fixture_t {
    wmem_allocator_t *allocator;
} wmem_test_fixture_t;

static void
wmem_test_block_allocator_setup(wmem_test_fixture_t *fixture,
        const void *extra _U_)
{
    /* we call the functions direct to ensure our type doesn't get overridden */
    fixture->allocator = wmem_block_allocator_new();
    fixture->allocator->type = WMEM_ALLOCATOR_BLOCK;
}

static void
wmem_test_teardown(wmem_test_fixture_t *fixture, const void *extra _U_)
{
    wmem_destroy_allocator(fixture->allocator);
}

static void
wmem_test_block_allocator(wmem_test_fixture_t *fixture, const void *extra _U_)
{
    char *ptrs[1024];
    int i;

    wmem_block_verify(fixture->allocator);

    for (i=0; i<1024; i++) ptrs[i] = wmem_alloc(fixture->allocator, 8);
    for (i=0; i<1024; i++) wmem_free(fixture->allocator, ptrs[i]);

    wmem_block_verify(fixture->allocator);

    for (i=0; i<1024; i++) ptrs[i] = wmem_alloc(fixture->allocator, 64);
    for (i=0; i<1024; i++) wmem_free(fixture->allocator, ptrs[i]);

    wmem_block_verify(fixture->allocator);

    for (i=0; i<1024; i++) ptrs[i] = wmem_alloc(fixture->allocator, 512);
    for (i=0; i<1024; i++) wmem_free(fixture->allocator, ptrs[i]);

    wmem_block_verify(fixture->allocator);
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add("/wmem/block-allocator", wmem_test_fixture_t, NULL,
            wmem_test_block_allocator_setup,
            wmem_test_block_allocator,
            wmem_test_teardown);

    /* return g_test_run(); */
    return 0;
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
