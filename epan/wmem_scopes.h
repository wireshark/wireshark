/** @file
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

#include <wsutil/wmem/wmem.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Fetch the current epan scope.
 *
 * Allocated memory is freed when wmem_leave_epan_scope() is called, which is normally at program exit.
 */
WS_DLL_PUBLIC
wmem_allocator_t *
wmem_epan_scope(void);

/**
 * @brief Fetch the current packet scope.
 *
 * Allocated memory is freed when wmem_leave_packet_scope() is called, which is normally at the end of packet dissection.
 */
WS_DLL_PUBLIC
wmem_allocator_t *
wmem_packet_scope(void);

WS_DLL_LOCAL
void
wmem_enter_packet_scope(void);

WS_DLL_LOCAL
void
wmem_leave_packet_scope(void);

/**
 * @brief Fetch the current file scope.
 *
 * Allocated memory is freed when wmem_leave_file_scope() is called, which is normally when a capture file is closed.
 */
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

WS_DLL_PUBLIC
void
wmem_init_scopes(void);

WS_DLL_PUBLIC
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
