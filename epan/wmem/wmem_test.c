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

static void
wmem_test_block_allocator(void)
{
    int i;
    char *ptrs[1024];
    wmem_allocator_t *allocator;

    /* we set up our allocator directly to ensure our type doesn't get
     * overridden */
    allocator = wmem_block_allocator_new();
    allocator->type = WMEM_ALLOCATOR_BLOCK;

    wmem_block_verify(allocator);

    for (i=0; i<1024; i++) ptrs[i] = wmem_alloc(allocator, 8);
    for (i=0; i<1024; i++) wmem_free(allocator, ptrs[i]);

    wmem_block_verify(allocator);

    for (i=0; i<1024; i++) ptrs[i] = wmem_alloc(allocator, 64);
    for (i=0; i<1024; i++) wmem_free(allocator, ptrs[i]);

    wmem_block_verify(allocator);

    for (i=0; i<1024; i++)  ptrs[i] = wmem_alloc(allocator, 512);
    for (i=1023; i>=0; i--) ptrs[i] = wmem_realloc(allocator, ptrs[i], 16*1024);
    for (i=0; i<1024; i++)  wmem_free(allocator, ptrs[i]);

    wmem_block_verify(allocator);

    wmem_destroy_allocator(allocator);
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/wmem/block-allocator", wmem_test_block_allocator);

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
