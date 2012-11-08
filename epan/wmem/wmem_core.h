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

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct _wmem_allocator_t;

typedef struct _wmem_allocator_t wmem_allocator_t;

void *
wmem_alloc(wmem_allocator_t *allocator, const size_t size);

void *
wmem_alloc0(wmem_allocator_t *allocator, const size_t size);

void
wmem_free_all(wmem_allocator_t *allocator);

void
wmem_destroy_allocator(wmem_allocator_t *allocator);

void
wmem_init(void);

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
