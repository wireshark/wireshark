/* wmem_allocator.h
 * Definitions for the Wireshark Memory Manager Allocator
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

#ifndef __WMEM_ALLOCATOR_H__
#define __WMEM_ALLOCATOR_H__

#include <glib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

enum _wmem_allocator_type_t;
struct _wmem_user_cb_container_t;

/* See section "4. Internal Design" of doc/README.wmem for details
 * on this structure */
struct _wmem_allocator_t {
    /* Consumer functions */
    void *(*alloc)(void *private_data, const size_t size);
    void  (*free)(void *private_data, void *ptr);
    void *(*realloc)(void *private_data, void *ptr, const size_t size);

    /* Producer/Manager functions */
    void  (*free_all)(void *private_data);
    void  (*gc)(void *private_data);
    void  (*cleanup)(void *private_data);

    /* Callback List */
    struct _wmem_user_cb_container_t *callbacks;

    /* Implementation details */
    void                        *private_data;
    enum _wmem_allocator_type_t  type;
    gboolean                     in_scope;
};

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WMEM_ALLOCATOR_H__ */

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
