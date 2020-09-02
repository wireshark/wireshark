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

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "ws_symbol_export.h"

#include <wsutil/wsgcrypt.h>	/* needed to define HAVE_LIBGCRYPT_AEAD */

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

#ifdef HAVE_LIBGCRYPT_AEAD
void    quic_stream_add_proto_data(struct _packet_info *pinfo, quic_stream_info *stream_info, void *proto_data);
void   *quic_stream_get_proto_data(struct _packet_info *pinfo, quic_stream_info *stream_info);
#endif /* HAVE_LIBGCRYPT_AEAD */

/** Returns the number of items for quic.connection.number. */
WS_DLL_PUBLIC guint32 get_quic_connections_count(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif  /* __PACKET_QUIC_H__ */
