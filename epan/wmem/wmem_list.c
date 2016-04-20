/* wmem_list.c
 * Wireshark Memory Manager Doubly-Linked List
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

#include <string.h>
#include <glib.h>

#include "wmem_core.h"
#include "wmem_list.h"

struct _wmem_list_frame_t {
    struct _wmem_list_frame_t *next, *prev;
    void *data;
};

struct _wmem_list_t {
    guint count;
    wmem_list_frame_t  *head, *tail;
    wmem_allocator_t   *allocator;
};

guint
wmem_list_count(const wmem_list_t *list)
{
    return list->count;
}

wmem_list_frame_t *
wmem_list_head(const wmem_list_t *list)
{
    return list->head;
}

wmem_list_frame_t *
wmem_list_tail(const wmem_list_t *list)
{
    return list->tail;
}

wmem_list_frame_t *
wmem_list_frame_next(const wmem_list_frame_t *frame)
{
    return frame->next;
}

wmem_list_frame_t *
wmem_list_frame_prev(const wmem_list_frame_t *frame)
{
    return frame->prev;
}

void *
wmem_list_frame_data(const wmem_list_frame_t *frame)
{
    return frame->data;
}

void
wmem_list_remove(wmem_list_t *list, void *data)
{
    wmem_list_frame_t *frame;

    frame = list->head;

    while (frame && frame->data != data) {
        frame = frame->next;
    }

    if (frame == NULL) {
        return;
    }

    wmem_list_remove_frame(list, frame);
}

void
wmem_list_remove_frame(wmem_list_t *list, wmem_list_frame_t *frame)
{
    if (frame->prev) {
        frame->prev->next = frame->next;
    }
    else {
        list->head = frame->next;
    }

    if (frame->next) {
        frame->next->prev = frame->prev;
    }
    else {
        list->tail = frame->prev;
    }

    list->count--;
    wmem_free(list->allocator, frame);
}

wmem_list_frame_t *
wmem_list_find(wmem_list_t *list, const void *data)
{
    wmem_list_frame_t *cur;

    for (cur = list->head; cur; cur = cur->next) {
        if(cur->data == data)
            return cur;
    }

    return NULL;
}

void
wmem_list_prepend(wmem_list_t *list, void *data)
{
    wmem_list_frame_t *new_frame;

    new_frame = wmem_new(list->allocator, wmem_list_frame_t);

    new_frame->data = data;
    new_frame->next = list->head;
    new_frame->prev = NULL;

    if (list->head) {
        list->head->prev = new_frame;
    }
    else {
        list->tail = new_frame;
    }

    list->head = new_frame;
    list->count++;
}

void
wmem_list_append(wmem_list_t *list, void *data)
{
    wmem_list_frame_t *new_frame;

    new_frame = wmem_new(list->allocator, wmem_list_frame_t);
    new_frame->data = data;
    new_frame->next = NULL;
    new_frame->prev = list->tail;

    if (list->tail) {
        list->tail->next = new_frame;
    }
    else {
        list->head = new_frame;
    }

    list->tail = new_frame;
    list->count++;
}

wmem_list_t *
wmem_list_new(wmem_allocator_t *allocator)
{
    wmem_list_t *list;

    list =  wmem_new(allocator, wmem_list_t);

    list->count     = 0;
    list->head      = NULL;
    list->tail      = NULL;
    list->allocator = allocator;

    return list;
}

void
wmem_destroy_list(wmem_list_t *list)
{
    wmem_list_frame_t *cur, *next;

    cur = list->head;

    while (cur) {
        next = cur->next;
        wmem_free(list->allocator, cur);
        cur = next;
    }

    wmem_free(list->allocator, list);
}

void
wmem_list_foreach(wmem_list_t *list, GFunc foreach_func, gpointer user_data)
{
    wmem_list_frame_t *cur;

    cur = list->head;

    while (cur) {
        foreach_func(cur->data, user_data);
        cur = cur->next;
    }
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
