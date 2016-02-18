/* wmem_array.c
 * Wireshark Memory Manager Array
 * Copyright 2013, Evan Huus <eapache@gmail.com>
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

#include "config.h"

#include <string.h>
#include <stdlib.h>
#include <glib.h>

#include "wmem_core.h"
#include "wmem_array.h"

/* Holds a wmem-allocated array.
 *  elem_len is the size of each element
 *  elem_count is the number of used elements
 *  alloc_count is the length (in elems) of the raw buffer pointed to by buf,
 *      regardless of how many elems are used (the contents)
 */
struct _wmem_array_t {
    wmem_allocator_t *allocator;

    guint8 *buf;

    gsize elem_size;

    guint elem_count;
    guint alloc_count;

    gboolean null_terminated;
};

wmem_array_t *
wmem_array_sized_new(wmem_allocator_t *allocator, gsize elem_size,
                     guint alloc_count)
{
    wmem_array_t *array;

    array = wmem_new(allocator, wmem_array_t);

    array->allocator   = allocator;
    array->elem_size   = elem_size;
    array->elem_count  = 0;
    array->alloc_count = alloc_count ? alloc_count : 1;
    array->null_terminated = FALSE;

    array->buf = (guint8 *)wmem_alloc(array->allocator,
            array->elem_size * array->alloc_count);

    return array;
}

wmem_array_t *
wmem_array_new(wmem_allocator_t *allocator, const gsize elem_size)
{
    wmem_array_t *array;

    array = wmem_array_sized_new(allocator, elem_size, 1);

    return array;
}

static void
wmem_array_grow(wmem_array_t *array, const guint to_add)
{
    guint new_alloc_count, new_count;

    new_alloc_count = array->alloc_count;
    new_count = array->elem_count + to_add;

    while (new_alloc_count < new_count) {
        new_alloc_count *= 2;
    }

    if (new_alloc_count == array->alloc_count) {
        return;
    }

    array->buf = (guint8 *)wmem_realloc(array->allocator, array->buf,
            new_alloc_count * array->elem_size);

    array->alloc_count = new_alloc_count;
}

static void
wmem_array_write_null_terminator(wmem_array_t *array)
{
    if (array->null_terminated) {
        wmem_array_grow(array, 1);
        memset(&array->buf[array->elem_count * array->elem_size], 0x0, array->elem_size);
    }
}

void
wmem_array_set_null_terminator(wmem_array_t *array)
{
    array->null_terminated = TRUE;
    wmem_array_write_null_terminator(array);
}

void
wmem_array_bzero(wmem_array_t *array)
{
    memset(array->buf, 0x0, array->elem_size * array->elem_count);
}

void
wmem_array_append(wmem_array_t *array, const void *in, guint count)
{
    wmem_array_grow(array, count);

    memcpy(&array->buf[array->elem_count * array->elem_size], in,
            count * array->elem_size);

    array->elem_count += count;

    wmem_array_write_null_terminator(array);
}

void *
wmem_array_index(wmem_array_t *array, guint array_index)
{
    g_assert(array_index < array->elem_count);
    return &array->buf[array_index * array->elem_size];
}

void
wmem_array_sort(wmem_array_t *array, int (*compar)(const void*,const void*))
{
    qsort(array->buf, array->elem_count, array->elem_size, compar);
}

void *
wmem_array_get_raw(wmem_array_t *array)
{
    return array->buf;
}

guint
wmem_array_get_count(wmem_array_t *array)
{
    return array->elem_count;
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
