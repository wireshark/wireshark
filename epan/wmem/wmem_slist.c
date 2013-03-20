/* wmem_slist.c
 * Wireshark Memory Manager Singly-Linked List
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
#include "wmem_slist.h"

struct _wmem_slist_frame_t {
    struct _wmem_slist_frame_t *next;
    void *data;
};

struct _wmem_slist_t {
    guint count;
    wmem_slist_frame_t *front;
    wmem_allocator_t   *allocator;
};

guint
wmem_slist_count(const wmem_slist_t *slist)
{
    return slist->count;
}

wmem_slist_frame_t *
wmem_slist_front(const wmem_slist_t *slist)
{
    return slist->front;
}

wmem_slist_frame_t *
wmem_slist_frame_next(const wmem_slist_frame_t *frame)
{
    return frame->next;
}

void *
wmem_slist_frame_data(const wmem_slist_frame_t *frame)
{
    return frame->data;
}

static wmem_slist_frame_t **
wmem_slist_find(wmem_slist_t *slist, void *data)
{
    wmem_slist_frame_t **cur;

    cur = &(slist->front);

    while (*cur && (*cur)->data != data) {
        cur = &((*cur)->next);
    }

    return cur;
}

void
wmem_slist_remove(wmem_slist_t *slist, void *data)
{
    wmem_slist_frame_t *frame;
    wmem_slist_frame_t **link;

    link = wmem_slist_find(slist, data);
    frame = *link;

    if (frame == NULL) {
        return;
    }

    *link = frame->next;
    slist->count--;
    wmem_free(slist->allocator, frame);
}

void
wmem_slist_prepend(wmem_slist_t *slist, void *data)
{
    wmem_slist_frame_t *new_frame;

    new_frame = wmem_new(slist->allocator, wmem_slist_frame_t);

    new_frame->data = data;
    new_frame->next = slist->front;

    slist->front = new_frame;
    slist->count++;
}

wmem_slist_t *
wmem_slist_new(wmem_allocator_t *allocator)
{
    wmem_slist_t *slist;

    slist = (wmem_slist_t *) wmem_alloc(allocator, sizeof(wmem_slist_t));

    slist->count     = 0;
    slist->front     = NULL;
    slist->allocator = allocator;

    return slist;
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
