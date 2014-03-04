/* wmem_scopes.h
 * Definitions for the Wireshark Memory Manager Scopes
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

#ifndef __WMEM_SCOPES_H__
#define __WMEM_SCOPES_H__

#include "wmem_core.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Epan Scope */

WS_DLL_PUBLIC
wmem_allocator_t *
wmem_epan_scope(void);

/* Packet Scope */

WS_DLL_PUBLIC
wmem_allocator_t *
wmem_packet_scope(void);

WS_DLL_LOCAL
void
wmem_enter_packet_scope(void);

WS_DLL_LOCAL
void
wmem_leave_packet_scope(void);

/* File Scope */

WS_DLL_PUBLIC
wmem_allocator_t *
wmem_file_scope(void);

WS_DLL_LOCAL
void
wmem_enter_file_scope(void);

WS_DLL_LOCAL
void
wmem_leave_file_scope(void);

/* Scope Management */

WS_DLL_LOCAL
void
wmem_init_scopes(void);

WS_DLL_LOCAL
void
wmem_cleanup_scopes(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WMEM_SCOPES_H__ */

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
