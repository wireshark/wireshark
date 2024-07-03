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

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file
 * Dissected packet data and metadata.
 */

/** @defgroup packetinfo Packet Data and Metadata
 *
 * @{
 */

/* Allocator should be either pinfo->pool or wmem_file_scope() */

/**
 * Add data associated with a protocol.
 *
 * This can be used to persist file-scoped data between packets or share
 * packet-scoped data between dissectors without having to use global
 * variables.
 *
 * Each call adds a new entry to the protocol data list.
 *
 * @param scope The memory scope, either pinfo->pool or wmem_file_scope().
 * @param pinfo This dissection's packet info.
 * @param proto The protocol ID.
 * @param key A unique key for the data.
 * @param proto_data The data to add.
 */
WS_DLL_PUBLIC void p_add_proto_data(wmem_allocator_t *scope, struct _packet_info* pinfo, int proto, uint32_t key, void *proto_data);

/**
 * Set data associated with a protocol.
 *
 * This can be used to persist file-scoped data between packets or share
 * packet-scoped data between dissectors without having to use global
 * variables.
 *
 * If the protocol data list contains a matching entry it will be updated,
 * otherwise a new entry will be created.
 *
 * @param scope The memory scope, either pinfo->pool or wmem_file_scope().
 * @param pinfo This dissection's packet info.
 * @param proto The protocol ID.
 * @param key A unique key for the data.
 * @param proto_data The data to add.
 */
WS_DLL_PUBLIC void p_set_proto_data(wmem_allocator_t *scope, struct _packet_info* pinfo, int proto, uint32_t key, void *proto_data);

/**
 * Fetch data associated with a protocol.
 *
 * @param scope The memory scope, typically pinfo->pool or wmem_file_scope().
 * @param pinfo This dissection's packet info.
 * @param proto The protocol ID.
 * @param key A unique key for the data.
 * @return The data set using p_set_proto_data or most recently added
 * using p_add_proto_data if the scope, protocol ID, and key match,
 * otherwise NULL.
 */
WS_DLL_PUBLIC void *p_get_proto_data(wmem_allocator_t *scope, struct _packet_info* pinfo, int proto, uint32_t key);

/**
 * Remove data associated with a protocol.
 *
 * @param scope The memory scope, typically pinfo->pool or wmem_file_scope().
 * @param pinfo This dissection's packet info.
 * @param proto The protocol ID.
 * @param key A unique key for the data.
 */
WS_DLL_PUBLIC void p_remove_proto_data(wmem_allocator_t *scope, struct _packet_info* pinfo, int proto, uint32_t key);

char *p_get_proto_name_and_key(wmem_allocator_t *scope, struct _packet_info* pinfo, unsigned pfd_index);

/**
 * Initialize or update a per-protocol and per-packet check for recursion, nesting, cycling, etc.
 *
 * @param pinfo Packet info for this packet.
 * @param proto The current protocol.
 * @param depth The depth to set.
 */
WS_DLL_PUBLIC void p_set_proto_depth(struct _packet_info* pinfo, int proto, unsigned depth);

/**
 * Fetch the current per-protocol and per-packet recursion, nesting, or cycling depth.
 * @param pinfo Packet info for this packet.
 * @param proto The current protocol.
 * @return The current depth.
 */
WS_DLL_PUBLIC unsigned p_get_proto_depth(struct _packet_info* pinfo, int proto);

/** @} */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif  /* __PROTO_DATA__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
