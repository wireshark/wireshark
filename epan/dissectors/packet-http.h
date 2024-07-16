/* packet-http.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_HTTP_H__
#define __PACKET_HTTP_H__

#include <epan/packet.h>
#include "ws_symbol_export.h"

WS_DLL_PUBLIC const value_string vals_http_status_code[];

WS_DLL_PUBLIC
void http_tcp_dissector_add(uint32_t port, dissector_handle_t handle);
WS_DLL_PUBLIC
void http_tcp_dissector_delete(uint32_t port);
WS_DLL_PUBLIC
void http_tcp_port_add(uint32_t port);

WS_DLL_PUBLIC
void http_add_path_components_to_tree(tvbuff_t* tvb, packet_info* pinfo _U_, proto_item* item, int offset, int length);

/* Used for HTTP statistics */
typedef struct _http_info_value_t {
	uint32_t framenum;
	char	*request_method;
	unsigned	 response_code;
	char    *http_host;
	const char    *request_uri;
	const char    *referer_uri;
	const char    *full_uri;
	const char    *location_base_uri;
	const char    *location_target;
} http_info_value_t;

#define HTTP_PROTO_DATA_REQRES	0
#define HTTP_PROTO_DATA_INFO	1

/** information about a request and response on a HTTP conversation. */
typedef struct _http_req_res_t {
	/** the running number on the conversation */
	uint32_t number;
	/** frame number of the request */
	uint32_t req_framenum;
	/** frame number of the corresponding response */
	uint32_t res_framenum;
	/** timestamp of the request */
	nstime_t req_ts;
	unsigned response_code;
	char    *request_method;
	char    *http_host;
	char    *request_uri;
	char    *full_uri;
	bool req_has_range;
	bool resp_has_range;

	/** private data used by http dissector */
	void* private_data;
} http_req_res_t;

/** Conversation data of a HTTP connection. */
typedef struct _http_conv_t {

        /* Used to speed up desegmenting of chunked Transfer-Encoding. */
	wmem_map_t *chunk_offsets_fwd;
	wmem_map_t *chunk_offsets_rev;

	/* Fields related to proxied/tunneled/Upgraded connections. */
	uint32_t	 startframe;	/* First frame of proxied connection */
	int    	 startoffset;	/* Offset within the frame where the new protocol begins. */
	dissector_handle_t next_handle;	/* New protocol */

	char    *websocket_protocol;	/* Negotiated WebSocket protocol */
	char    *websocket_extensions;	/* Negotiated WebSocket extensions */
	/* Server address and port, known after first server response */
	uint16_t server_port;
	address server_addr;
	/** the tail node of req_res */
	http_req_res_t *req_res_tail;
	/** Information from the last request or response can
	 * be found in the tail node. It is only sensible to look
	 * at on the first (sequential) pass, or after startframe /
	 * startoffset on connections that have proxied/tunneled/Upgraded.
	 */

	/* true means current message is chunked streaming, and not ended yet.
	 * This is only meaningful during the first scan.
	 */
	bool message_ended;

	/* Used for req/res matching */
	GSList *req_list;
        wmem_map_t *matches_table;

} http_conv_t;

/* Used for HTTP Export Object feature */
typedef struct _http_eo_t {
	char    *hostname;
	char    *filename;
	char    *content_type;
	tvbuff_t *payload;
} http_eo_t;

#endif /* __PACKET_HTTP_H__ */
