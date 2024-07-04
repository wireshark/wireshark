/* wmem_miscutl.c
 * Wireshark Memory Manager Misc Utilities
 * Copyright 2013, Evan Huus <eapache@gmail.com>
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
#include "wmem_miscutl.h"

void *
wmem_memdup(wmem_allocator_t *allocator, const void *source, const size_t size)
{
    void *dest;

    if (!size)
        return NULL;

    dest = wmem_alloc(allocator, size);
    memcpy(dest, source, size);

    return dest;
}

int
wmem_compare_int(const void *a, const void *b)
{
    return GPOINTER_TO_INT(a) - GPOINTER_TO_INT(b);
}

int
wmem_compare_uint(const void *a, const void *b)
{
    return GPOINTER_TO_UINT(a) > GPOINTER_TO_UINT(b) ? 1 : (GPOINTER_TO_UINT(a) < GPOINTER_TO_UINT(b) ? -1 : 0);
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
