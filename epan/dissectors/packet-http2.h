/* packet-http2.h
 * Routines for HTTP/2 dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef __PACKET_HTTP2_H__
#define __PACKET_HTTP2_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* http2 standard headers */
#define HTTP2_HEADER_CONTENT_ENCODING "content-encoding"
#define HTTP2_HEADER_STATUS ":status"
#define HTTP2_HEADER_STATUS_PARTIAL_CONTENT "206"
#define HTTP2_HEADER_METHOD ":method"
#define HTTP2_HEADER_METHOD_CONNECT "CONNECT"
#define HTTP2_HEADER_TRANSFER_ENCODING "transfer-encoding"
#define HTTP2_HEADER_PATH ":path"
#define HTTP2_HEADER_AUTHORITY ":authority"
#define HTTP2_HEADER_SCHEME ":scheme"
#define HTTP2_HEADER_CONTENT_TYPE "content-type"
#define HTTP2_HEADER_UNKNOWN "<unknown>"
/* http2 for grpc */
#define HTTP2_HEADER_GRPC_ENCODING "grpc-encoding"

int dissect_http2_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_ );

/** Get header value from current or the other direction stream.
 * Return the value of a header if it appear in previous HEADERS or PROMISE frames in
 * current or the other direction stream. Subdissector may invoke this function to get http2
 * header value.
 * @param pinfo  packet info pointer. Http2 dissector passes it to subdissector
 *               when dissecting http2.data.data.
 * @param name   the name of header.
 * @param the_other_direction  false means from current direction stream, true from the other.
 * @return  NULL if header was not found. Or header value. Note: the value is allocated
 *          by pinfo->pool.
 * @note The returned field value is decoded from US-ASCII and characters outside
 * that range, i.e. obs-text, are replaced with UTF-8 REPLACEMENT CHARACTERS.
 * Dissectors may need to perform additional decoding (e.g., percent decoding or
 * the more robust decoding per RFC 8187.)
 * @warning Don't call this if HTTP but not HTTP/2 is present in the packet
 * (e.g. test with proto_is_frame_protocol() first). This ultimately calls
 * get_http2_session, creating a HTTP/2 session on the current conversation,
 * which can confuse the HTTP dissector. (This should be fixed.)
 */
const char* http2_get_header_value(packet_info *pinfo, const char* name, bool the_other_direction);

/**
 * Get the HTTP/2 Stream ID for the current PDU (typically the DATA frame).
 * Only valid when called from a HTTP/2 subdissector.
 * Returns 0 if no HTTP/2 session was found.
 */
uint32_t http2_get_stream_id(packet_info *pinfo);

/**
 * Retrieves the HTTP/2 Stream ID which is smaller than or equal to the provided
 * ID. If available, sub_stream_id_out will be set and true is returned.
 */
WS_DLL_PUBLIC bool
http2_get_stream_id_le(unsigned streamid, unsigned sub_stream_id, unsigned *sub_stream_id_out);

/**
 * Retrieves the HTTP/2 Stream ID which is greater than or equal to the provided
 * ID. If available, sub_stream_id_out will be set and true is returned.
 */
WS_DLL_PUBLIC bool
http2_get_stream_id_ge(unsigned streamid, unsigned sub_stream_id, unsigned *sub_stream_id_out);

WS_DLL_PUBLIC void
dissect_http2_settings_ext(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* http2_tree, unsigned offset);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif

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
