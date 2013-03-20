/* wmem_core.c
 * Wireshark Memory Manager Core
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

#include <stdlib.h>
#include <string.h>
#include <glib.h>

#include "wmem_core.h"
#include "wmem_scopes.h"
#include "wmem_allocator.h"
#include "wmem_allocator_simple.h"
#include "wmem_allocator_block.h"
#include "wmem_allocator_strict.h"

void *
wmem_alloc(wmem_allocator_t *allocator, const size_t size)
{
    if (allocator == NULL) {
        return g_malloc(size);
    }

    if (size == 0) {
        return NULL;
    }

    return allocator->alloc(allocator->private_data, size);
}

void *
wmem_alloc0(wmem_allocator_t *allocator, const size_t size)
{
    void *buf;

    if (size == 0) {
        return NULL;
    }
    
    buf = wmem_alloc(allocator, size);

    memset(buf, 0, size);

    return buf;
}

void
wmem_free(wmem_allocator_t *allocator, void *ptr)
{
    if (allocator == NULL) {
        g_free(ptr);
        return;
    }

    if (ptr == NULL) {
        return;
    }

    allocator->free(allocator->private_data, ptr);
}

void *
wmem_realloc(wmem_allocator_t *allocator, void *ptr, const size_t size)
{
    if (allocator == NULL) {
        return g_realloc(ptr, size);
    }

    if (ptr == NULL) {
        return wmem_alloc(allocator, size);
    }

    if (size == 0) {
        wmem_free(allocator, ptr);
        return NULL;
    }

    return allocator->realloc(allocator->private_data, ptr, size);
}

void
wmem_free_all(wmem_allocator_t *allocator)
{
    allocator->free_all(allocator->private_data);
}

void
wmem_gc(wmem_allocator_t *allocator)
{
    allocator->gc(allocator->private_data);
}

void
wmem_destroy_allocator(wmem_allocator_t *allocator)
{
    wmem_free_all(allocator);
    allocator->destroy(allocator);
}

wmem_allocator_t *
wmem_allocator_new(const wmem_allocator_type_t type)
{
    const char            *override;
    wmem_allocator_t      *allocator;
    wmem_allocator_type_t  real_type;

    /* Our valgrind script uses this environment variable to override the
     * usual allocator choice so that everything goes through system-level
     * allocations that it understands and can track. Otherwise it will get
     * confused by the block allocator etc. */
    override = getenv("WIRESHARK_DEBUG_WMEM_OVERRIDE");

    if (override == NULL) {
        real_type = type;
    }
    else if (strncmp(override, "simple", strlen("simple")) == 0) {
        real_type = WMEM_ALLOCATOR_SIMPLE;
    }
    else if (strncmp(override, "block", strlen("block")) == 0) {
        real_type = WMEM_ALLOCATOR_BLOCK;
    }
    else if (strncmp(override, "strict", strlen("strict")) == 0) {
        real_type = WMEM_ALLOCATOR_STRICT;
    }
    else {
        g_warning("Unrecognized wmem override");
        real_type = type;
    }

    switch (real_type) {
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

    allocator->type = real_type;

    return allocator;
}

void
wmem_init(void)
{
    wmem_init_scopes();
}

void
wmem_cleanup(void)
{
    wmem_cleanup_scopes();
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
