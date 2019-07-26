/* wmem_stack.c
 * Wireshark Memory Manager Stack
 * Copyright 2012, Evan Huus <eapache@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <string.h>
#include <glib.h>

#include "wmem_core.h"
#include "wmem_stack.h"
#include "wmem_list.h"

/* Wmem stack is implemented as a simple wrapper over Wmem list */

void *
wmem_stack_peek(const wmem_stack_t *stack)
{
    wmem_list_frame_t *frame;

    frame = wmem_list_head(stack);

    g_assert(frame);

    return wmem_list_frame_data(frame);
}

void *
wmem_stack_pop(wmem_stack_t *stack)
{
    void *data;

    data = wmem_stack_peek(stack);

    wmem_list_remove(stack, data);

    return data;
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
