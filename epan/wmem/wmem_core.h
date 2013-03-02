/* wmem_core.h
 * Definitions for the Wireshark Memory Manager Core
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

#ifndef __WMEM_CORE_H__
#define __WMEM_CORE_H__

#include <string.h>
#include <ws_symbol_export.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum _wmem_allocator_type_t {
    WMEM_ALLOCATOR_SIMPLE,
    WMEM_ALLOCATOR_BLOCK,
    WMEM_ALLOCATOR_STRICT
} wmem_allocator_type_t;

struct _wmem_allocator_t;

typedef struct _wmem_allocator_t wmem_allocator_t;

WS_DLL_PUBLIC
void *
wmem_alloc(wmem_allocator_t *allocator, const size_t size);
#define wmem_new(allocator, type) \
    ((type*)wmem_alloc((allocator), sizeof(type)))

WS_DLL_PUBLIC
void *
wmem_alloc0(wmem_allocator_t *allocator, const size_t size);
#define wmem_new0(allocator, type) \
    ((type*)wmem_alloc0((allocator), sizeof(type)))

WS_DLL_PUBLIC
void
wmem_free(wmem_allocator_t *allocator, void *ptr);

WS_DLL_PUBLIC
void *
wmem_realloc(wmem_allocator_t *allocator, void *ptr, const size_t size);

WS_DLL_PUBLIC
void
wmem_free_all(wmem_allocator_t *allocator);

WS_DLL_PUBLIC
void
wmem_gc(wmem_allocator_t *allocator);

WS_DLL_PUBLIC
void
wmem_destroy_allocator(wmem_allocator_t *allocator);

WS_DLL_PUBLIC
wmem_allocator_t *
wmem_allocator_new(const wmem_allocator_type_t type);

WS_DLL_LOCAL
void
wmem_init(void);

WS_DLL_LOCAL
void
wmem_cleanup(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WMEM_CORE_H__ */

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
