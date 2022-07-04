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
	/** pointer to the next element in the linked list, NULL for the tail node */
	struct _http_req_res_t *next;
	/** pointer to the previous element in the linked list, NULL for the head node */
	struct _http_req_res_t *prev;
} http_req_res_t;

/** Conversation data of a HTTP connection. */
typedef struct _http_conv_t {
	guint    response_code;
	guint32  req_res_num;	/**< The number of requests in the conversation. */
	gchar   *http_host;
	gchar   *request_method;
	gchar   *request_uri;
	gchar   *full_uri;

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
} http_conv_t;

typedef enum _http_type {
	HTTP_REQUEST,
	HTTP_RESPONSE,
	HTTP_NOTIFICATION,
	HTTP_OTHERS,
	SIP_DATA            /* If the content is from the SIP dissector*/
} http_type_t;

/** Passed to dissectors called by the HTTP dissector. */
typedef struct _http_message_info_t {
	http_type_t type;       /**< Message type; may be HTTP_OTHERS if not called by HTTP */
	const char *media_str;  /**< Content-Type parameters */
	const char *content_id; /**< Content-ID parameter */
	void *data;             /**< The http_type is used to indicate the data transported */
} http_message_info_t;

#endif /* __PACKET_HTTP_H__ */
