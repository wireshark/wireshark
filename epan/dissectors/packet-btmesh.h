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

#define BTMESH_NONCE_TYPE_NETWORK     0x00
#define BTMESH_NONCE_TYPE_APPLICATION 0x01
#define BTMESH_NONCE_TYPE_DEVICE      0x02
#define BTMESH_NONCE_TYPE_PROXY       0x03

#define BTMESH_ADDRESS_UNASSIGNED     0x00
#define BTMESH_ADDRESS_UNICAST        0x01
#define BTMESH_ADDRESS_VIRTUAL        0x02
#define BTMESH_ADDRESS_GROUP          0x03

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

typedef struct {
    /* Network Layer */
    guint32 src;
    guint32 seq;
    guint8 seq_src_buf[5];
    guint8 ivindex_buf[4];
    guint8 net_nonce_type;
    guint32 net_key_iv_index_hash;

    /* Transport layer */
    guint32 dst;
    guint8 dst_buf[2];
    gint32 label_uuid_idx;
    guint32 seg; /* Segmentation */
    guint8 aid;
    guint8 app_nonce_type;
    guint32 seqzero;
    int transmic_size;
} network_decryption_ctx_t;

tvbuff_t *btmesh_network_find_key_and_decrypt(tvbuff_t *tvb, packet_info *pinfo, guint8 **decrypted_data, int *enc_data_len, network_decryption_ctx_t *dec_ctx);

#endif /* __PACKET_BTMESH_H__ */

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
