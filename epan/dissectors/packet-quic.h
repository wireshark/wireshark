/* packet-quic.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_QUIC_H__
#define __PACKET_QUIC_H__

#include "ws_symbol_export.h"

#include <glibconfig.h>
#include <wsutil/wsgcrypt.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


/**
 * Metadata for a STREAM frame.
 * https://tools.ietf.org/html/draft-ietf-quic-transport-23#section-19.8
 */
typedef struct _quic_stream_info {
    uint64_t    stream_id;      /**< 62-bit Stream ID. */
    uint64_t    stream_offset;  /**< 62-bit stream offset. */
    uint32_t    offset;         /**< Offset within the stream (different for reassembled data). */
    uint32_t    inorder_offset; /**< Offset of the inorder data. */
    struct quic_info_data *quic_info;    /**< Opaque data structure to find the QUIC session. */
    bool        from_server;
} quic_stream_info;

/*
 * Although the QUIC SCID/DCID length field can store at most 255, v1 limits the
 * CID length to 20.
 */
#define QUIC_MAX_CID_LENGTH  20

typedef struct quic_cid {
    uint8_t     len;
    uint8_t     cid[QUIC_MAX_CID_LENGTH];
    uint8_t     reset_token[16];
    bool        reset_token_set;
    uint64_t    seq_num;
    uint64_t    path_id;
} quic_cid_t;

/**
 * Obtain Stream Type from a Stream ID.
 * https://tools.ietf.org/html/draft-ietf-quic-transport-23#section-2.1
 */
#define QUIC_STREAM_TYPE(stream_id) ((stream_id) & 3U)
#define QUIC_STREAM_CLIENT_BIDI 0
#define QUIC_STREAM_SERVER_BIDI 1
#define QUIC_STREAM_CLIENT_UNI  2
#define QUIC_STREAM_SERVER_UNI  3

/** QUIC Multipath versions; pre draft-07 uses sequence number
 * instead of path ID.
 */
#define QUIC_MP_NO_PATH_ID 1
#define QUIC_MP_PATH_ID 2

/** Set/Get protocol-specific data for the QUIC STREAM. */

void    quic_stream_add_proto_data(struct _packet_info *pinfo, quic_stream_info *stream_info, void *proto_data);
void   *quic_stream_get_proto_data(struct _packet_info *pinfo, quic_stream_info *stream_info);

/** Returns the number of items for quic.connection.number. */
WS_DLL_PUBLIC uint32_t get_quic_connections_count(void);

typedef struct gquic_info_data {
    uint8_t version;
    bool version_valid;
    bool encoding;
    uint16_t server_port;
} gquic_info_data_t;

int
dissect_gquic_frame_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *gquic_tree, unsigned offset, uint8_t len_pkn, gquic_info_data_t *gquic_info);
uint32_t
dissect_gquic_tags(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ft_tree, unsigned offset);

void
quic_add_connection(packet_info *pinfo, quic_cid_t *cid);
void
quic_add_loss_bits(packet_info *pinfo, uint64_t value);
void
quic_add_stateless_reset_token(packet_info *pinfo, tvbuff_t *tvb, int offset, const quic_cid_t *cid);
void
quic_add_multipath(packet_info *pinfo, unsigned version);
void
quic_add_grease_quic_bit(packet_info *pinfo);
void
quic_proto_tree_add_version(tvbuff_t *tvb, proto_tree *tree, int hfindex, unsigned offset);

/**
 * Retrieves the QUIC Stream ID which is smaller than or equal to the provided
 * ID. If available, sub_stream_id_out will be set and true is returned.
 */
WS_DLL_PUBLIC bool
quic_get_stream_id_le(unsigned streamid, unsigned sub_stream_id, unsigned *sub_stream_id_out);

/**
 * Retrieves the QUIC Stream ID which is greater than or equal to the provided
 * ID. If available, sub_stream_id_out will be set and true is returned.
 */
WS_DLL_PUBLIC bool
quic_get_stream_id_ge(unsigned streamid, unsigned sub_stream_id, unsigned *sub_stream_id_out);


/**
 * Retrieves the initial client DCID from the packet info, if available
 */
WS_DLL_PUBLIC bool
quic_conn_data_get_conn_client_dcid_initial(struct _packet_info *pinfo, quic_cid_t *dcid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif  /* __PACKET_QUIC_H__ */
