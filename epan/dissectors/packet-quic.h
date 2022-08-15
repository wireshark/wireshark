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

#include <wsutil/wsgcrypt.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * Metadata for a STREAM frame.
 * https://tools.ietf.org/html/draft-ietf-quic-transport-23#section-19.8
 */
typedef struct _quic_stream_info {
    guint64     stream_id;      /**< 62-bit Stream ID. */
    guint64     stream_offset;  /**< 62-bit stream offset. */
    guint32     offset;         /**< Offset within the stream (different for reassembled data). */
    struct quic_info_data *quic_info;    /**< Opaque data structure to find the QUIC session. */
    gboolean    from_server;
} quic_stream_info;

/*
 * Although the QUIC SCID/DCID length field can store at most 255, v1 limits the
 * CID length to 20.
 */
#define QUIC_MAX_CID_LENGTH  20

typedef struct quic_cid {
    guint8      len;
    guint8      cid[QUIC_MAX_CID_LENGTH];
    guint8      reset_token[16];
    gboolean    reset_token_set;
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

/** Set/Get protocol-specific data for the QUIC STREAM. */

void    quic_stream_add_proto_data(struct _packet_info *pinfo, quic_stream_info *stream_info, void *proto_data);
void   *quic_stream_get_proto_data(struct _packet_info *pinfo, quic_stream_info *stream_info);

/** Returns the number of items for quic.connection.number. */
WS_DLL_PUBLIC guint32 get_quic_connections_count(void);

typedef struct gquic_info_data {
    guint8 version;
    gboolean version_valid;
    gboolean encoding;
    guint16 server_port;
} gquic_info_data_t;

int
dissect_gquic_frame_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *gquic_tree, guint offset, guint8 len_pkn, gquic_info_data_t *gquic_info);
guint32
dissect_gquic_tags(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ft_tree, guint offset);

void
quic_add_connection(packet_info *pinfo, const quic_cid_t *cid);
void
quic_add_loss_bits(packet_info *pinfo, guint64 value);
void
quic_add_stateless_reset_token(packet_info *pinfo, tvbuff_t *tvb, gint offset, const quic_cid_t *cid);
void
quic_proto_tree_add_version(tvbuff_t *tvb, proto_tree *tree, int hfindex, guint offset);

/**
 * Retrieves the QUIC Stream ID which is smaller than or equal to the provided
 * ID. If available, sub_stream_id_out will be set and TRUE is returned.
 */
WS_DLL_PUBLIC gboolean
quic_get_stream_id_le(guint streamid, guint sub_stream_id, guint *sub_stream_id_out);

/**
 * Retrieves the QUIC Stream ID which is greater than or equal to the provided
 * ID. If available, sub_stream_id_out will be set and TRUE is returned.
 */
WS_DLL_PUBLIC gboolean
quic_get_stream_id_ge(guint streamid, guint sub_stream_id, guint *sub_stream_id_out);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif  /* __PACKET_QUIC_H__ */
