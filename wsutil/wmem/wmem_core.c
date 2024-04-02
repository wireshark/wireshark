/* wmem_core.c
 * Wireshark Memory Manager Core
 * Copyright 2012, Evan Huus <eapache@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdlib.h>
#include <string.h>
#include <glib.h>

#include "wmem-int.h"
#include "wmem_core.h"
#include "wmem_map_int.h"
#include "wmem_user_cb_int.h"
#include "wmem_allocator.h"
#include "wmem_allocator_simple.h"
#include "wmem_allocator_block.h"
#include "wmem_allocator_block_fast.h"
#include "wmem_allocator_strict.h"

/* Set according to the WIRESHARK_DEBUG_WMEM_OVERRIDE environment variable in
 * wmem_init. Should not be set again. */
static bool do_override;
static wmem_allocator_type_t override_type;

void *
wmem_alloc(wmem_allocator_t *allocator, const size_t size)
{
    if (allocator == NULL) {
        return g_malloc(size);
    }

    ws_assert(allocator->in_scope);

    if (size == 0) {
        return NULL;
    }

    return allocator->walloc(allocator->private_data, size);
}

void *
wmem_alloc0(wmem_allocator_t *allocator, const size_t size)
{
    void *buf;

    buf = wmem_alloc(allocator, size);

    if (buf) {
        memset(buf, 0, size);
    }

    return buf;
}

void
wmem_free(wmem_allocator_t *allocator, void *ptr)
{
    if (allocator == NULL) {
        g_free(ptr);
        return;
    }

    ws_assert(allocator->in_scope);

    if (ptr == NULL) {
        return;
    }

    allocator->wfree(allocator->private_data, ptr);
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

    ws_assert(allocator->in_scope);

    return allocator->wrealloc(allocator->private_data, ptr, size);
}

static void
wmem_free_all_real(wmem_allocator_t *allocator, bool final)
{
    wmem_call_callbacks(allocator,
            final ? WMEM_CB_DESTROY_EVENT : WMEM_CB_FREE_EVENT);
    allocator->free_all(allocator->private_data);
}

void
wmem_free_all(wmem_allocator_t *allocator)
{
    wmem_free_all_real(allocator, false);
}

void
wmem_gc(wmem_allocator_t *allocator)
{
    allocator->gc(allocator->private_data);
}

void
wmem_destroy_allocator(wmem_allocator_t *allocator)
{

    wmem_free_all_real(allocator, true);
    allocator->cleanup(allocator->private_data);
    wmem_free(NULL, allocator);
}

wmem_allocator_t *
wmem_allocator_new(const wmem_allocator_type_t type)
{
    wmem_allocator_t      *allocator;
    wmem_allocator_type_t  real_type;

    if (do_override) {
        real_type = override_type;
    }
    else {
        real_type = type;
    }

    allocator = wmem_new(NULL, wmem_allocator_t);
    allocator->type      = real_type;
    allocator->callbacks = NULL;
    allocator->in_scope  = true;

    switch (real_type) {
        case WMEM_ALLOCATOR_SIMPLE:
            wmem_simple_allocator_init(allocator);
            break;
        case WMEM_ALLOCATOR_BLOCK:
            wmem_block_allocator_init(allocator);
            break;
        case WMEM_ALLOCATOR_BLOCK_FAST:
            wmem_block_fast_allocator_init(allocator);
            break;
        case WMEM_ALLOCATOR_STRICT:
            wmem_strict_allocator_init(allocator);
            break;
        default:
            g_assert_not_reached();
            break;
    };

    return allocator;
}

void
wmem_init(void)
{
    const char *override_env;

    /* Our valgrind script uses this environment variable to override the
     * usual allocator choice so that everything goes through system-level
     * allocations that it understands and can track. Otherwise it will get
     * confused by the block allocator etc. */
    override_env = getenv("WIRESHARK_DEBUG_WMEM_OVERRIDE");

    if (override_env == NULL) {
        do_override = false;
    }
    else {
        do_override = true;
        if (strncmp(override_env, "simple", strlen("simple")) == 0) {
            override_type = WMEM_ALLOCATOR_SIMPLE;
        }
        else if (strncmp(override_env, "block", strlen("block")) == 0) {
            override_type = WMEM_ALLOCATOR_BLOCK;
        }
        else if (strncmp(override_env, "strict", strlen("strict")) == 0) {
            override_type = WMEM_ALLOCATOR_STRICT;
        }
        else if (strncmp(override_env, "block_fast", strlen("block_fast")) == 0) {
            override_type = WMEM_ALLOCATOR_BLOCK_FAST;
        }
        else {
            g_warning("Unrecognized wmem override");
            do_override = false;
        }
    }

    wmem_init_hashing();
}

void
wmem_cleanup(void)
{
}

void
wmem_enter_scope(wmem_allocator_t *allocator)
{
    allocator->in_scope = true;
}

void
wmem_leave_scope(wmem_allocator_t *allocator)
{
    wmem_free_all(allocator);
    allocator->in_scope = false;
}

bool
wmem_in_scope(wmem_allocator_t *allocator)
{
    return allocator->in_scope;
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
