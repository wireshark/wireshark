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
void http_tcp_dissector_add(guint32 port, dissector_handle_t handle);
WS_DLL_PUBLIC
void http_tcp_dissector_delete(guint32 port);
WS_DLL_PUBLIC
void http_tcp_port_add(guint32 port);

WS_DLL_PUBLIC
void http_add_path_components_to_tree(tvbuff_t* tvb, packet_info* pinfo _U_, proto_item* item, int offset, int length);

/* Used for HTTP statistics */
typedef struct _http_info_value_t {
	guint32 framenum;
	gchar	*request_method;
	guint	 response_code;
	gchar   *http_host;
	const gchar   *request_uri;
	const gchar   *referer_uri;
	const gchar   *full_uri;
	const gchar   *location_base_uri;
	const gchar   *location_target;
} http_info_value_t;


/** information about a request and response on a HTTP conversation. */
typedef struct _http_req_res_t {
	/** the running number on the conversation */
	guint32 number;
	/** frame number of the request */
	guint32 req_framenum;
	/** frame number of the corresponding response */
	guint32 res_framenum;
	/** timestamp of the request */
	nstime_t req_ts;
	guint    response_code;
	gchar   *request_method;
	gchar   *http_host;
	gchar   *request_uri;
	gchar   *full_uri;
	/** pointer to the next element in the linked list, NULL for the tail node */
	struct _http_req_res_t *next;
	/** pointer to the previous element in the linked list, NULL for the head node */
	struct _http_req_res_t *prev;
	/** private data used by http dissector */
	void* private_data;
} http_req_res_t;

/** Conversation data of a HTTP connection. */
typedef struct _http_conv_t {
	guint32  req_res_num;	/**< The number of requests in the conversation. */

        /* Used to speed up desegmenting of chunked Transfer-Encoding. */
	wmem_map_t *chunk_offsets_fwd;
	wmem_map_t *chunk_offsets_rev;

	/* Fields related to proxied/tunneled/Upgraded connections. */
	guint32	 startframe;	/* First frame of proxied connection */
	int    	 startoffset;	/* Offset within the frame where the new protocol begins. */
	dissector_handle_t next_handle;	/* New protocol */

	gchar   *websocket_protocol;	/* Negotiated WebSocket protocol */
	gchar   *websocket_extensions;	/* Negotiated WebSocket extensions */
	/* Server address and port, known after first server response */
	guint16 server_port;
	address server_addr;
	/** the tail node of req_res */
	http_req_res_t *req_res_tail;
	/** Information from the last request or response can
	 * be found in the tail node. It is only sensible to look
	 * at on the first (sequential) pass, or after startframe /
	 * startoffset on connections that have proxied/tunneled/Upgraded.
	 */

	/* TRUE means current message is chunked streaming, and not ended yet.
	 * This is only meaningful during the first scan.
	 */
	gboolean message_ended;

} http_conv_t;

/* Used for HTTP Export Object feature */
typedef struct _http_eo_t {
	gchar   *hostname;
	gchar   *filename;
	gchar   *content_type;
	tvbuff_t *payload;
} http_eo_t;

#endif /* __PACKET_HTTP_H__ */
