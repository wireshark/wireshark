/* wmem_stack.c
 * Wireshark Memory Manager Stack
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
#include "wmem_slab.h"
#include "wmem_stack.h"

typedef struct _wmem_stack_frame_t {
    struct _wmem_stack_frame_t *next;
    void *data;
} wmem_stack_frame_t;

struct _wmem_stack_t {
    guint count;
    wmem_stack_frame_t *top;
    wmem_slab_t *slab;
};

guint
wmem_stack_count(const wmem_stack_t *stack)
{
    return stack->count;
}

void *
wmem_stack_peek(const wmem_stack_t *stack)
{
    g_assert(stack->top != NULL);
    g_assert(stack->count > 0);

    return stack->top->data;
}

void *
wmem_stack_pop(wmem_stack_t *stack)
{
    wmem_stack_frame_t *top;
    void *data;

    g_assert(stack->top != NULL);
    g_assert(stack->count > 0);

    top = stack->top;
    stack->top = top->next;
    stack->count--;
    data = top->data;
    wmem_slab_free(stack->slab, top);

    return data;
}

void
wmem_stack_push(wmem_stack_t *stack, void *data)
{
    wmem_stack_frame_t *new;

    new = (wmem_stack_frame_t *) wmem_slab_alloc(stack->slab);

    new->data = data;
    new->next = stack->top;
    stack->top = new;
    stack->count++;
}

wmem_stack_t *
wmem_create_stack(wmem_allocator_t *allocator)
{
    wmem_stack_t *stack;

    stack = (wmem_stack_t *) wmem_alloc(allocator, sizeof(wmem_stack_t));

    stack->count = 0;
    stack->top   = NULL;
    stack->slab  = wmem_create_slab(allocator, sizeof(wmem_stack_frame_t));

    return stack;
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
