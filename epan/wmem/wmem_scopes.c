/* wmem_scopes.c
 * Wireshark Memory Manager Scopes
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

#include <glib.h>

#include "wmem_core.h"
#include "wmem_scopes.h"
#include "wmem_allocator.h"

/* One of the supposed benefits of wmem over the old emem was going to be that
 * the scoping of the various memory pools would be obvious, since they would
 * no longer be global. Instead, the pools would be managed as variables scoped
 * by the compiler, so functions outside of that scope wouldn't have access to
 * the pools and wouldn't be able to allocate memory in a scope to which they
 * didn't belong.
 *
 * That idea fell apart rather quickly :P
 *
 * The principle still stands, and most pools should be managed in that way.
 * The three in this file are *exceptions*. They are the three scopes that emem
 * provided as globals. Converting all of the code that used them to pass an
 * extra parameter (or three) around would have been a nightmare of epic
 * proportions, so we provide these three as globals still.
 *
 * We do, however, use some extra booleans and a mountain of assertions to try
 * and catch anybody accessing the pools out of the correct scope. It's not
 * perfect, but it should stop most of the bad behaviour that emem permitted.
 */

/* TODO: Make these thread-local */
static wmem_allocator_t *packet_scope = NULL;
static wmem_allocator_t *file_scope   = NULL;
static wmem_allocator_t *epan_scope   = NULL;

/* Packet Scope */

wmem_allocator_t *
wmem_packet_scope(void)
{
    g_assert(packet_scope);

    return packet_scope;
}

void
wmem_enter_packet_scope(void)
{
    g_assert(packet_scope);
    g_assert(file_scope->in_scope);
    g_assert(!packet_scope->in_scope);

    packet_scope->in_scope = TRUE;
}

void
wmem_leave_packet_scope(void)
{
    g_assert(packet_scope);
    g_assert(packet_scope->in_scope);

    wmem_free_all(packet_scope);
    packet_scope->in_scope = FALSE;
}

/* File Scope */

wmem_allocator_t *
wmem_file_scope(void)
{
    g_assert(file_scope);

    return file_scope;
}

void
wmem_enter_file_scope(void)
{
    g_assert(file_scope);
    g_assert(!file_scope->in_scope);

    file_scope->in_scope = TRUE;
}

void
wmem_leave_file_scope(void)
{
    g_assert(file_scope);
    g_assert(file_scope->in_scope);
    g_assert(!packet_scope->in_scope);

    wmem_free_all(file_scope);
    file_scope->in_scope = FALSE;

    /* this seems like a good time to do garbage collection */
    wmem_gc(file_scope);
    wmem_gc(packet_scope);
}

/* Epan Scope */

wmem_allocator_t *
wmem_epan_scope(void)
{
    g_assert(epan_scope);

    return epan_scope;
}

/* Scope Management */

void
wmem_init_scopes(void)
{
    g_assert(packet_scope == NULL);
    g_assert(file_scope   == NULL);
    g_assert(epan_scope   == NULL);

    packet_scope = wmem_allocator_new(WMEM_ALLOCATOR_BLOCK_FAST);
    file_scope   = wmem_allocator_new(WMEM_ALLOCATOR_BLOCK);
    epan_scope   = wmem_allocator_new(WMEM_ALLOCATOR_SIMPLE);

    /* Scopes are initialized to TRUE by default on creation */
    packet_scope->in_scope = FALSE;
    file_scope->in_scope   = FALSE;
}

void
wmem_cleanup_scopes(void)
{
    g_assert(packet_scope);
    g_assert(file_scope);
    g_assert(epan_scope);

    g_assert(packet_scope->in_scope == FALSE);
    g_assert(file_scope->in_scope   == FALSE);

    wmem_destroy_allocator(packet_scope);
    wmem_destroy_allocator(file_scope);
    wmem_destroy_allocator(epan_scope);

    packet_scope = NULL;
    file_scope   = NULL;
    epan_scope   = NULL;
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
