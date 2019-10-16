/* wmem_scopes.h
 * Definitions for the Wireshark Memory Manager Scopes
 * Copyright 2012, Evan Huus <eapache@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
