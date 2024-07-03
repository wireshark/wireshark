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
    bool fragmented;
    unsigned segment_index;
} btle_mesh_transport_ctx_t;

typedef struct {
    uint32_t interface_id;
    uint32_t adapter_id;
    uint16_t chandle;
    uint16_t bt_uuid;
    uint32_t access_address;
    btle_mesh_proxy_side_t proxy_side;
} btle_mesh_proxy_ctx_t;

typedef struct {
    /* Network Layer */
    uint32_t src;
    uint32_t seq;
    uint8_t seq_src_buf[5];
    uint8_t ivindex_buf[4];
    uint8_t net_nonce_type;
    uint32_t net_key_iv_index_hash;

    /* Transport layer */
    uint32_t dst;
    uint8_t dst_buf[2];
    int32_t label_uuid_idx;
    uint32_t seg; /* Segmentation */
    uint8_t aid;
    uint8_t app_nonce_type;
    uint32_t seqzero;
    int transmic_size;
} network_decryption_ctx_t;

tvbuff_t *btmesh_network_find_key_and_decrypt(tvbuff_t *tvb, packet_info *pinfo, uint8_t **decrypted_data, int *enc_data_len, network_decryption_ctx_t *dec_ctx);

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
