/* proto_data.h
 * Definitions for protocol-specific data
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PROTO_DATA_H__
#define __PROTO_DATA_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "ws_symbol_export.h"

/* Allocator should be either pinfo->pool or wmem_file_scope() */
WS_DLL_PUBLIC void p_add_proto_data(wmem_allocator_t *scope, struct _packet_info* pinfo, int proto, guint32 key, void *proto_data);
WS_DLL_PUBLIC void *p_get_proto_data(wmem_allocator_t *scope, struct _packet_info* pinfo, int proto, guint32 key);
WS_DLL_PUBLIC void p_remove_proto_data(wmem_allocator_t *scope, struct _packet_info* pinfo, int proto, guint32 key);
gchar *p_get_proto_name_and_key(wmem_allocator_t *scope, struct _packet_info* pinfo, guint pfd_index);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif  /* __PROTO_DATA__ */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
