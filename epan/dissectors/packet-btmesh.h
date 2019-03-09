/* packet-btmesh.h
 * Structures for determining the dissection context for Bluetooth mesh.
 *
 * Copyright 2019, Piotr Winiarczyk <wino45@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef __PACKET_BTMESH_H__
#define __PACKET_BTMESH_H__

#include <epan/packet.h>

#define MESH_NONCE_TYPE_NETWORK 0x00
#define MESH_NONCE_TYPE_PROXY   0x03

typedef enum {
    E_BTMESH_TR_UNKNOWN = 0,
    E_BTMESH_TR_ADV,
    E_BTMESH_TR_PB_ADV,
    E_BTMESH_TR_PROXY
} btle_mesh_tr_t;

typedef enum {
    E_BTMESH_PROXY_SIDE_UNKNOWN = 0,
    E_BTMESH_PROXY_SIDE_SERVER,
    E_BTMESH_PROXY_SIDE_CLIENT,
    E_BTMESH_PROXY_SIDE_LAST
} btle_mesh_proxy_side_t;

typedef struct {
    btle_mesh_tr_t transport;
    gboolean fragmented;
    guint segment_index;
} btle_mesh_transport_ctx_t;

typedef struct {
    guint32 interface_id;
    guint32 adapter_id;
    guint16 chandle;
    guint16 bt_uuid;
    guint32 access_address;
    btle_mesh_proxy_side_t proxy_side;
} btle_mesh_proxy_ctx_t;

tvbuff_t *btmesh_network_find_key_and_decrypt(tvbuff_t *tvb, packet_info *pinfo, guint8 **decrypted_data, int *enc_data_len, guint8 nonce_type);

#endif /* __PACKET_BTMESH_H__ */

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
