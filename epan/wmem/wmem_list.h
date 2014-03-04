/* wmem_list.h
 * Definitions for the Wireshark Memory Manager Doubly-Linked List
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

#ifndef __WMEM_LIST_H__
#define __WMEM_LIST_H__

#include <string.h>
#include <glib.h>

#include "wmem_core.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @addtogroup wmem
 *  @{
 *    @defgroup wmem-list Doubly-Linked List
 *
 *    A doubly-linked list implementation on top of wmem.
 *
 *    @{
 */

struct _wmem_list_t;
struct _wmem_list_frame_t;

typedef struct _wmem_list_t       wmem_list_t;
typedef struct _wmem_list_frame_t wmem_list_frame_t;

WS_DLL_PUBLIC
guint
wmem_list_count(const wmem_list_t *list);

WS_DLL_PUBLIC
wmem_list_frame_t *
wmem_list_head(const wmem_list_t *list);

WS_DLL_PUBLIC
wmem_list_frame_t *
wmem_list_tail(const wmem_list_t *list);

WS_DLL_PUBLIC
wmem_list_frame_t *
wmem_list_frame_next(const wmem_list_frame_t *frame);

WS_DLL_PUBLIC
wmem_list_frame_t *
wmem_list_frame_prev(const wmem_list_frame_t *frame);

WS_DLL_PUBLIC
void *
wmem_list_frame_data(const wmem_list_frame_t *frame);

WS_DLL_PUBLIC
void
wmem_list_remove(wmem_list_t *list, void *data);

WS_DLL_PUBLIC
void
wmem_list_remove_frame(wmem_list_t *list, wmem_list_frame_t *frame);

WS_DLL_PUBLIC
void
wmem_list_prepend(wmem_list_t *list, void *data);

WS_DLL_PUBLIC
void
wmem_list_append(wmem_list_t *list, void *data);

WS_DLL_PUBLIC
wmem_list_t *
wmem_list_new(wmem_allocator_t *allocator)
G_GNUC_MALLOC;

WS_DLL_PUBLIC
void
wmem_destroy_list(wmem_list_t *list);

/**   @}
 *  @} */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WMEM_LIST_H__ */

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
