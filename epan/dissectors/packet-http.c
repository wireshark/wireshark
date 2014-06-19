/* packet-http.c
 * Routines for HTTP packet disassembly
 * RFC 1945 (HTTP/1.0)
 * RFC 2616 (HTTP/1.1)
 *
 * Guy Harris <guy@alum.mit.edu>
 *
 * Copyright 2004, Jerry Talkington <jtalkington@users.sourceforge.net>
 * Copyright 2002, Tim Potter <tpot@samba.org>
 * Copyright 1999, Andrew Tridgell <tridge@samba.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <glib.h>
#include <epan/conversation.h>
#include <epan/packet.h>
#include <epan/strutil.h>
#include <wsutil/base64.h>
#include <epan/stats_tree.h>
#include <epan/to_str.h>

#include <epan/req_resp_hdrs.h>
#include "packet-http.h"
#include "packet-tcp.h"
#include "packet-ssl.h"
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/uat.h>
#include <epan/wmem/wmem.h>

typedef enum _http_type {
	HTTP_REQUEST,
	HTTP_RESPONSE,
	HTTP_NOTIFICATION,
	HTTP_OTHERS
} http_type_t;

#include <epan/tap.h>

void proto_register_http(void);
void proto_reg_handoff_http(void);
void proto_register_message_http(void);
void proto_reg_handoff_message_http(void);

static int http_tap = -1;
static int http_eo_tap = -1;

static int proto_http = -1;
static int hf_http_notification = -1;
static int hf_http_response = -1;
static int hf_http_request = -1;
static int hf_http_response_line = -1;
static int hf_http_request_line = -1;
static int hf_http_basic = -1;
static int hf_http_request_method = -1;
static int hf_http_request_uri = -1;
static int hf_http_request_full_uri = -1;
static int hf_http_version = -1;
static int hf_http_response_code = -1;
static int hf_http_response_phrase = -1;
static int hf_http_authorization = -1;
static int hf_http_proxy_authenticate = -1;
static int hf_http_proxy_authorization = -1;
static int hf_http_proxy_connect_host = -1;
static int hf_http_proxy_connect_port = -1;
static int hf_http_www_authenticate = -1;
static int hf_http_content_type = -1;
static int hf_http_content_length_header = -1;
static int hf_http_content_length = -1;
static int hf_http_content_encoding = -1;
static int hf_http_transfer_encoding = -1;
static int hf_http_upgrade = -1;
static int hf_http_user_agent = -1;
static int hf_http_host = -1;
static int hf_http_connection = -1;
static int hf_http_cookie = -1;
static int hf_http_cookie_pair = -1;
static int hf_http_accept = -1;
static int hf_http_referer = -1;
static int hf_http_accept_language = -1;
static int hf_http_accept_encoding = -1;
static int hf_http_date = -1;
static int hf_http_cache_control = -1;
static int hf_http_server = -1;
static int hf_http_location = -1;
static int hf_http_sec_websocket_accept = -1;
static int hf_http_sec_websocket_extensions = -1;
static int hf_http_sec_websocket_key = -1;
static int hf_http_sec_websocket_protocol = -1;
static int hf_http_sec_websocket_version = -1;
static int hf_http_set_cookie = -1;
static int hf_http_last_modified = -1;
static int hf_http_x_forwarded_for = -1;
static int hf_http_request_in = -1;
static int hf_http_response_in = -1;
static int hf_http_next_request_in = -1;
static int hf_http_next_response_in = -1;
static int hf_http_prev_request_in = -1;
static int hf_http_prev_response_in = -1;
static int hf_http_time = -1;

static gint ett_http = -1;
static gint ett_http_ntlmssp = -1;
static gint ett_http_kerberos = -1;
static gint ett_http_request = -1;
static gint ett_http_chunked_response = -1;
static gint ett_http_chunk_data = -1;
static gint ett_http_encoded_entity = -1;
static gint ett_http_header_item = -1;

static expert_field ei_http_chat = EI_INIT;
static expert_field ei_http_chunked_and_length = EI_INIT;
static expert_field ei_http_subdissector_failed = EI_INIT;

static dissector_handle_t http_handle;

static dissector_handle_t data_handle;
static dissector_handle_t media_handle;
static dissector_handle_t websocket_handle;
static dissector_handle_t http2_handle;

/* Stuff for generation/handling of fields for custom HTTP headers */
typedef struct _header_field_t {
	gchar* header_name;
	gchar* header_desc;
} header_field_t;

static header_field_t* header_fields = NULL;
static guint num_header_fields = 0;

static GHashTable* header_fields_hash = NULL;

static void
header_fields_update_cb(void *r, const char **err)
{
	header_field_t *rec = (header_field_t *)r;
	char c;

	if (rec->header_name == NULL) {
		*err = g_strdup("Header name can't be empty");
		return;
	}

	g_strstrip(rec->header_name);
	if (rec->header_name[0] == 0) {
		*err = g_strdup("Header name can't be empty");
		return;
	}

	/* Check for invalid characters (to avoid asserting out when
	 * registering the field).
	 */
	c = proto_check_field_name(rec->header_name);
	if (c) {
		*err = g_strdup_printf("Header name can't contain '%c'", c);
		return;
	}

	*err = NULL;
}

static void *
header_fields_copy_cb(void* n, const void* o, size_t siz _U_)
{
	header_field_t* new_rec = (header_field_t*)n;
	const header_field_t* old_rec = (const header_field_t*)o;

	if (old_rec->header_name) {
		new_rec->header_name = g_strdup(old_rec->header_name);
	} else {
		new_rec->header_name = NULL;
	}

	if (old_rec->header_desc) {
		new_rec->header_desc = g_strdup(old_rec->header_desc);
	} else {
		new_rec->header_desc = NULL;
	}

	return new_rec;
}

static void
header_fields_free_cb(void*r)
{
	header_field_t* rec = (header_field_t*)r;

	if (rec->header_name)
		g_free(rec->header_name);
	if (rec->header_desc)
		g_free(rec->header_desc);
}

UAT_CSTRING_CB_DEF(header_fields, header_name, header_field_t)
UAT_CSTRING_CB_DEF(header_fields, header_desc, header_field_t)

/*
 * desegmentation of HTTP headers
 * (when we are over TCP or another protocol providing the desegmentation API)
 */
static gboolean http_desegment_headers = TRUE;

/*
 * desegmentation of HTTP bodies
 * (when we are over TCP or another protocol providing the desegmentation API)
 * TODO let the user filter on content-type the bodies he wants desegmented
 */
static gboolean http_desegment_body = TRUE;

/*
 * De-chunking of content-encoding: chunk entity bodies.
 */
static gboolean http_dechunk_body = TRUE;

/*
 * Decompression of zlib encoded entities.
 */
#ifdef HAVE_LIBZ
static gboolean http_decompress_body = TRUE;
#else
static gboolean http_decompress_body = FALSE;
#endif

/* Simple Service Discovery Protocol
 * SSDP is implemented atop HTTP (yes, it really *does* run over UDP).
 * SSDP is the discovery protocol of Universal Plug and Play
 * UPnP   http://www.upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.1.pdf
 */
#define TCP_PORT_SSDP			1900
#define UDP_PORT_SSDP			1900

/*
 * tcp and ssl ports
 *
 * 2710 is the XBT BitTorrent tracker
 */

#define TCP_DEFAULT_RANGE "80,3128,3132,5985,8080,8088,11371,1900,2869,2710"
#define SSL_DEFAULT_RANGE "443"

#define UPGRADE_WEBSOCKET 1
#define UPGRADE_HTTP2 2

static range_t *global_http_tcp_range = NULL;
static range_t *global_http_ssl_range = NULL;

static range_t *http_tcp_range = NULL;
static range_t *http_ssl_range = NULL;

typedef void (*ReqRespDissector)(tvbuff_t*, proto_tree*, int, const guchar*,
				 const guchar*, http_conv_t *);

/*
 * Structure holding information from headers needed by main
 * HTTP dissector code.
 */
typedef struct {
	char	*content_type;
	char	*content_type_parameters;
	gboolean have_content_length;
	gint64	content_length;
	char	*content_encoding;
	char	*transfer_encoding;
	guint8  upgrade;
} headers_t;

static int is_http_request_or_reply(const gchar *data, int linelen,
				    http_type_t *type, ReqRespDissector
				    *reqresp_dissector, http_conv_t *conv_data);
static int chunked_encoding_dissector(tvbuff_t **tvb_ptr, packet_info *pinfo,
				      proto_tree *tree, int offset);
static void process_header(tvbuff_t *tvb, int offset, int next_offset,
			   const guchar *line, int linelen, int colon_offset,
			   packet_info *pinfo, proto_tree *tree,
			   headers_t *eh_ptr, http_conv_t *conv_data,
			   int http_type);
static gint find_header_hf_value(tvbuff_t *tvb, int offset, guint header_len);
static gboolean check_auth_ntlmssp(proto_item *hdr_item, tvbuff_t *tvb,
				   packet_info *pinfo, gchar *value);
static gboolean check_auth_basic(proto_item *hdr_item, tvbuff_t *tvb,
				 gchar *value);
static gboolean check_auth_kerberos(proto_item *hdr_item, tvbuff_t *tvb,
				   packet_info *pinfo, const gchar *value);

static dissector_table_t port_subdissector_table;
static dissector_table_t media_type_subdissector_table;
static heur_dissector_list_t heur_subdissector_list;

static dissector_handle_t ntlmssp_handle;
static dissector_handle_t gssapi_handle;

/* --- HTTP Status Codes */
/* Note: The reference for uncommented entries is RFC 2616 */
static const value_string vals_status_code[] = {
	{ 100, "Continue" },
	{ 101, "Switching Protocols" },
	{ 102, "Processing" },                     /* RFC 2518 */
	{ 199, "Informational - Others" },

	{ 200, "OK"},
	{ 201, "Created"},
	{ 202, "Accepted"},
	{ 203, "Non-authoritative Information"},
	{ 204, "No Content"},
	{ 205, "Reset Content"},
	{ 206, "Partial Content"},
	{ 207, "Multi-Status"},                    /* RFC 4918 */
	{ 226, "IM Used"},                         /* RFC 3229 */
	{ 299, "Success - Others"},

	{ 300, "Multiple Choices"},
	{ 301, "Moved Permanently"},
	{ 302, "Found"},
	{ 303, "See Other"},
	{ 304, "Not Modified"},
	{ 305, "Use Proxy"},
	{ 307, "Temporary Redirect"},
	{ 399, "Redirection - Others"},

	{ 400, "Bad Request"},
	{ 401, "Unauthorized"},
	{ 402, "Payment Required"},
	{ 403, "Forbidden"},
	{ 404, "Not Found"},
	{ 405, "Method Not Allowed"},
	{ 406, "Not Acceptable"},
	{ 407, "Proxy Authentication Required"},
	{ 408, "Request Time-out"},
	{ 409, "Conflict"},
	{ 410, "Gone"},
	{ 411, "Length Required"},
	{ 412, "Precondition Failed"},
	{ 413, "Request Entity Too Large"},
	{ 414, "Request-URI Too Long"},
	{ 415, "Unsupported Media Type"},
	{ 416, "Requested Range Not Satisfiable"},
	{ 417, "Expectation Failed"},
	{ 418, "I'm a teapot"},                    /* RFC 2324 */
	{ 422, "Unprocessable Entity"},            /* RFC 4918 */
	{ 423, "Locked"},                          /* RFC 4918 */
	{ 424, "Failed Dependency"},               /* RFC 4918 */
	{ 426, "Upgrade Required"},                /* RFC 2817 */
	{ 428, "Precondition Required"},           /* RFC 6585 */
	{ 429, "Too Many Requests"},               /* RFC 6585 */
	{ 431, "Request Header Fields Too Large"}, /* RFC 6585 */
	{ 499, "Client Error - Others"},

	{ 500, "Internal Server Error"},
	{ 501, "Not Implemented"},
	{ 502, "Bad Gateway"},
	{ 503, "Service Unavailable"},
	{ 504, "Gateway Time-out"},
	{ 505, "HTTP Version not supported"},
	{ 507, "Insufficient Storage"},            /* RFC 4918 */
	{ 511, "Network Authentication Required"}, /* RFC 6585 */
	{ 599, "Server Error - Others"},

	{ 0, 	NULL}
};

static const gchar* st_str_reqs = "HTTP Requests by Server";
static const gchar* st_str_reqs_by_srv_addr = "HTTP Requests by Server Address";
static const gchar* st_str_reqs_by_http_host = "HTTP Requests by HTTP Host";
static const gchar* st_str_resps_by_srv_addr = "HTTP Responses by Server Address";

static int st_node_reqs = -1;
static int st_node_reqs_by_srv_addr = -1;
static int st_node_reqs_by_http_host = -1;
static int st_node_resps_by_srv_addr = -1;

/* HTTP/Load Distribution stats init function */
static void
http_reqs_stats_tree_init(stats_tree* st)
{
	st_node_reqs = stats_tree_create_node(st, st_str_reqs, 0, TRUE);
	st_node_reqs_by_srv_addr = stats_tree_create_node(st, st_str_reqs_by_srv_addr, st_node_reqs, TRUE);
	st_node_reqs_by_http_host = stats_tree_create_node(st, st_str_reqs_by_http_host, st_node_reqs, TRUE);
	st_node_resps_by_srv_addr = stats_tree_create_node(st, st_str_resps_by_srv_addr, 0, TRUE);
}

/* HTTP/Load Distribution stats packet function */
static int
http_reqs_stats_tree_packet(stats_tree* st, packet_info* pinfo, epan_dissect_t* edt _U_, const void* p)
{
	const http_info_value_t* v = (const http_info_value_t*)p;
	int reqs_by_this_host;
	int reqs_by_this_addr;
	int resps_by_this_addr;
	int i = v->response_code;
	gchar *ip_str;


	if (v->request_method) {
		ip_str = address_to_str(NULL, &pinfo->dst);

		tick_stat_node(st, st_str_reqs, 0, FALSE);
		tick_stat_node(st, st_str_reqs_by_srv_addr, st_node_reqs, TRUE);
		tick_stat_node(st, st_str_reqs_by_http_host, st_node_reqs, TRUE);
		reqs_by_this_addr = tick_stat_node(st, ip_str, st_node_reqs_by_srv_addr, TRUE);

		if (v->http_host) {
			reqs_by_this_host = tick_stat_node(st, v->http_host, st_node_reqs_by_http_host, TRUE);
			tick_stat_node(st, ip_str, reqs_by_this_host, FALSE);

			tick_stat_node(st, v->http_host, reqs_by_this_addr, FALSE);
		}

		wmem_free(NULL, ip_str);

		return 1;

	} else if (i != 0) {
		ip_str = address_to_str(NULL, &pinfo->src);

		tick_stat_node(st, st_str_resps_by_srv_addr, 0, FALSE);
		resps_by_this_addr = tick_stat_node(st, ip_str, st_node_resps_by_srv_addr, TRUE);

		if ( (i>100)&&(i<400) ) {
			tick_stat_node(st, "OK", resps_by_this_addr, FALSE);
		} else {
			tick_stat_node(st, "KO", resps_by_this_addr, FALSE);
		}

		wmem_free(NULL, ip_str);

		return 1;
	}

	return 0;
}


static int st_node_requests_by_host = -1;
static const gchar *st_str_requests_by_host = "HTTP Requests by HTTP Host";

/* HTTP/Requests stats init function */
static void
http_req_stats_tree_init(stats_tree* st)
{
	st_node_requests_by_host = stats_tree_create_node(st, st_str_requests_by_host, 0, TRUE);
}

/* HTTP/Requests stats packet function */
static int
http_req_stats_tree_packet(stats_tree* st, packet_info* pinfo _U_, epan_dissect_t* edt _U_, const void* p)
{
	const http_info_value_t* v = (const http_info_value_t*)p;
	int reqs_by_this_host;

	if (v->request_method) {
		tick_stat_node(st, st_str_requests_by_host, 0, FALSE);

		if (v->http_host) {
			reqs_by_this_host = tick_stat_node(st, v->http_host, st_node_requests_by_host, TRUE);

			if (v->request_uri) {
				tick_stat_node(st, v->request_uri, reqs_by_this_host, TRUE);
			}
		}

		return 1;
	}

	return 0;
}

static const gchar *st_str_packets = "Total HTTP Packets";
static const gchar *st_str_requests = "HTTP Request Packets";
static const gchar *st_str_responses = "HTTP Response Packets";
static const gchar *st_str_resp_broken = "???: broken";
static const gchar *st_str_resp_100 = "1xx: Informational";
static const gchar *st_str_resp_200 = "2xx: Success";
static const gchar *st_str_resp_300 = "3xx: Redirection";
static const gchar *st_str_resp_400 = "4xx: Client Error";
static const gchar *st_str_resp_500 = "5xx: Server Error";
static const gchar *st_str_other = "Other HTTP Packets";

static int st_node_packets = -1;
static int st_node_requests = -1;
static int st_node_responses = -1;
static int st_node_resp_broken = -1;
static int st_node_resp_100 = -1;
static int st_node_resp_200 = -1;
static int st_node_resp_300 = -1;
static int st_node_resp_400 = -1;
static int st_node_resp_500 = -1;
static int st_node_other = -1;


/* HTTP/Packet Counter stats init function */
static void
http_stats_tree_init(stats_tree* st)
{
	st_node_packets = stats_tree_create_node(st, st_str_packets, 0, TRUE);
	st_node_requests = stats_tree_create_pivot(st, st_str_requests, st_node_packets);
	st_node_responses = stats_tree_create_node(st, st_str_responses, st_node_packets, TRUE);
	st_node_resp_broken = stats_tree_create_node(st, st_str_resp_broken, st_node_responses, TRUE);
	st_node_resp_100    = stats_tree_create_node(st, st_str_resp_100,    st_node_responses, TRUE);
	st_node_resp_200    = stats_tree_create_node(st, st_str_resp_200,    st_node_responses, TRUE);
	st_node_resp_300    = stats_tree_create_node(st, st_str_resp_300,    st_node_responses, TRUE);
	st_node_resp_400    = stats_tree_create_node(st, st_str_resp_400,    st_node_responses, TRUE);
	st_node_resp_500    = stats_tree_create_node(st, st_str_resp_500,    st_node_responses, TRUE);
	st_node_other = stats_tree_create_node(st, st_str_other, st_node_packets,FALSE);
}

/* HTTP/Packet Counter stats packet function */
static int
http_stats_tree_packet(stats_tree* st, packet_info* pinfo _U_, epan_dissect_t* edt _U_, const void* p)
{
	const http_info_value_t* v = (const http_info_value_t*)p;
	guint i = v->response_code;
	int resp_grp;
	const gchar *resp_str;
	gchar str[64];

	tick_stat_node(st, st_str_packets, 0, FALSE);

	if (i) {
		tick_stat_node(st, st_str_responses, st_node_packets, FALSE);

		if ( (i<100)||(i>=600) ) {
			resp_grp = st_node_resp_broken;
			resp_str = st_str_resp_broken;
		} else if (i<200) {
			resp_grp = st_node_resp_100;
			resp_str = st_str_resp_100;
		} else if (i<300) {
			resp_grp = st_node_resp_200;
			resp_str = st_str_resp_200;
		} else if (i<400) {
			resp_grp = st_node_resp_300;
			resp_str = st_str_resp_300;
		} else if (i<500) {
			resp_grp = st_node_resp_400;
			resp_str = st_str_resp_400;
		} else {
			resp_grp = st_node_resp_500;
			resp_str = st_str_resp_500;
		}

		tick_stat_node(st, resp_str, st_node_responses, FALSE);

		g_snprintf(str, sizeof(str), "%u %s", i,
			   val_to_str(i, vals_status_code, "Unknown (%d)"));
		tick_stat_node(st, str, resp_grp, FALSE);
	} else if (v->request_method) {
		stats_tree_tick_pivot(st,st_node_requests,v->request_method);
	} else {
		tick_stat_node(st, st_str_other, st_node_packets, FALSE);
	}

	return 1;
}


static void
dissect_http_ntlmssp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		     const char *line)
{
	tvbuff_t *ntlmssp_tvb;

	ntlmssp_tvb = base64_to_tvb(tvb, line);
	add_new_data_source(pinfo, ntlmssp_tvb, "NTLMSSP / GSSAPI Data");
	if (tvb_strneql(ntlmssp_tvb, 0, "NTLMSSP", 7) == 0)
		call_dissector(ntlmssp_handle, ntlmssp_tvb, pinfo, tree);
	else
		call_dissector(gssapi_handle, ntlmssp_tvb, pinfo, tree);
}

static void
dissect_http_kerberos(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		     const char *line)
{
	tvbuff_t *kerberos_tvb;

	kerberos_tvb = base64_to_tvb(tvb, line + 9); /* skip 'Kerberos ' which is 9 chars */
	add_new_data_source(pinfo, kerberos_tvb, "Kerberos Data");
	call_dissector(gssapi_handle, kerberos_tvb, pinfo, tree);

}


static http_conv_t *
get_http_conversation_data(packet_info *pinfo)
{
	conversation_t  *conversation;
	http_conv_t	*conv_data;

	conversation = find_or_create_conversation(pinfo);

	/* Retrieve information from conversation
	 * or add it if it isn't there yet
	 */
	conv_data = (http_conv_t *)conversation_get_proto_data(conversation, proto_http);
	if(!conv_data) {
		/* Setup the conversation structure itself */
		conv_data = (http_conv_t *)wmem_alloc0(wmem_file_scope(), sizeof(http_conv_t));

		conversation_add_proto_data(conversation, proto_http,
					    conv_data);
	}

	return conv_data;
}

/**
 * create a new http_req_res_t and add it to the conversation.
 * @return the new allocated object which is already added to the linked list
 */
static http_req_res_t* push_req_res(http_conv_t *conv_data)
{
	http_req_res_t *req_res = (http_req_res_t *)wmem_alloc0(wmem_file_scope(), sizeof(http_req_res_t));
	nstime_set_unset(&(req_res->req_ts));
	req_res->number = ++conv_data->req_res_num;

	if (! conv_data->req_res_tail) {
		conv_data->req_res_tail = req_res;
	} else {
		req_res->prev = conv_data->req_res_tail;
		conv_data->req_res_tail->next = req_res;
		conv_data->req_res_tail = req_res;
	}

	return req_res;
}

/**
 * push a request frame number and its time stamp to the conversation data.
 */
static void push_req(http_conv_t *conv_data, packet_info *pinfo)
{
	/* a request will always create a new http_req_res_t object */
	http_req_res_t *req_res = push_req_res(conv_data);

	req_res->req_framenum = pinfo->fd->num;
	req_res->req_ts = pinfo->fd->abs_ts;

	p_add_proto_data(wmem_file_scope(), pinfo, proto_http, 0, req_res);
}

/**
 * push a response frame number to the conversation data.
 */
static void push_res(http_conv_t *conv_data, packet_info *pinfo)
{
	/* a response will create a new http_req_res_t object: if no
	   object exists, or if one exists for another response. In
	   both cases the corresponding request was not
	   detected/included in the conversation. In all other cases
	   the http_req_res_t object created by the request is
	   used. */
	http_req_res_t *req_res = conv_data->req_res_tail;
	if (!req_res || req_res->res_framenum > 0) {
		req_res = push_req_res(conv_data);
	}
	req_res->res_framenum = pinfo->fd->num;
	p_add_proto_data(wmem_file_scope(), pinfo, proto_http, 0, req_res);
}

/*
 * TODO: remove this ugly global variable.
 * XXX: do we really want to have to pass this from one function to another?
 */
static http_info_value_t	*stat_info;

static int
dissect_http_message(tvbuff_t *tvb, int offset, packet_info *pinfo,
		     proto_tree *tree, http_conv_t *conv_data)
{
	const char	*proto_tag;
	proto_tree	*http_tree = NULL;
	proto_item	*ti = NULL;
	proto_item	*hidden_item;
	const guchar	*line, *firstline;
	gint		next_offset;
	const guchar	*linep, *lineend;
	int		orig_offset;
	int		first_linelen, linelen;
	gboolean	is_request_or_reply;
	gboolean	saw_req_resp_or_header;
	guchar		c;
	http_type_t     http_type;
	proto_item	*hdr_item = NULL;
	ReqRespDissector reqresp_dissector;
	proto_tree	*req_tree;
	int		colon_offset;
	headers_t	headers;
	int		datalen;
	int		reported_datalen = -1;
	dissector_handle_t handle;
	gboolean	dissected = FALSE;
	gboolean	first_loop = TRUE;
	/*guint		i;*/
	/*http_info_value_t *si;*/
	http_eo_t       *eo_info;
	heur_dtbl_entry_t *hdtbl_entry;

	/*
	 * If this should be a request or response, do this quick check to see if
	 * it begins with a string...
	 * Otherwise, looking for the end of line in a binary file can take a long time
	 * and this probably isn't HTTP
	 */
	if ((tvb_reported_length_remaining(tvb, offset) < 1) || !g_ascii_isprint(tvb_get_guint8(tvb, offset))) {
		return -1;
	}

	/*
	 * Is this a request or response?
	 *
	 * Note that "tvb_find_line_end()" will return a value that
	 * is not longer than what's in the buffer, so the
	 * "tvb_get_ptr()" call won't throw an exception.
	 */
	first_linelen = tvb_find_line_end(tvb, offset,
	    tvb_ensure_length_remaining(tvb, offset), &next_offset,
	    TRUE);

	if (first_linelen == -1) {
		/* No complete line was found in this segment, do
		 * desegmentation if we're told to.
		 */
		if (!req_resp_hdrs_do_reassembly(tvb, offset, pinfo,
		    http_desegment_headers, http_desegment_body)) {
			/*
			 * More data needed for desegmentation.
			 */
			return -1;
		}
	}

	/*
	 * Is the first line a request or response?
	 *
	 * Note that "tvb_find_line_end()" will return a value that
	 * is not longer than what's in the buffer, so the
	 * "tvb_get_ptr()" call won't throw an exception.
	 */
	firstline = tvb_get_ptr(tvb, offset, first_linelen);
	http_type = HTTP_OTHERS;	/* type not known yet */
	is_request_or_reply = is_http_request_or_reply((const gchar *)firstline,
	    first_linelen, &http_type, NULL, conv_data);
	if (is_request_or_reply) {
		/*
		 * Yes, it's a request or response.
		 * Do header desegmentation if we've been told to,
		 * and do body desegmentation if we've been told to and
		 * we find a Content-Length header.
		 */
		if (!req_resp_hdrs_do_reassembly(tvb, offset, pinfo,
		    http_desegment_headers, http_desegment_body)) {
			/*
			 * More data needed for desegmentation.
			 */
			return -1;
		}
	}

	stat_info = wmem_new(wmem_packet_scope(), http_info_value_t);
	stat_info->framenum = pinfo->fd->num;
	stat_info->response_code = 0;
	stat_info->request_method = NULL;
	stat_info->request_uri = NULL;
	stat_info->http_host = NULL;

	switch (pinfo->match_uint) {

	case TCP_PORT_SSDP:	/* TCP_PORT_SSDP = UDP_PORT_SSDP */
		proto_tag = "SSDP";
		break;

	default:
		proto_tag = "HTTP";
		break;
	}

	orig_offset = offset;

	/*
	 * Process the packet data, a line at a time.
	 */
	http_type = HTTP_OTHERS;	/* type not known yet */
	headers.content_type = NULL;	/* content type not known yet */
	headers.content_type_parameters = NULL;	/* content type parameters too */
	headers.have_content_length = FALSE;	/* content length not known yet */
	headers.content_length = 0;		/* content length set to 0 (avoid a gcc warning) */
	headers.content_encoding = NULL; /* content encoding not known yet */
	headers.transfer_encoding = NULL; /* transfer encoding not known yet */
	headers.upgrade = 0; /* assume we're not upgrading */
	saw_req_resp_or_header = FALSE;	/* haven't seen anything yet */
	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		/*
		 * Find the end of the line.
		 * XXX - what if we don't find it because the packet
		 * is cut short by a snapshot length or the header is
		 * split across TCP segments?  How much dissection should
		 * we do on it?
		 */
		linelen = tvb_find_line_end(tvb, offset,
		    tvb_ensure_length_remaining(tvb, offset), &next_offset,
		    FALSE);
		if (linelen < 0)
			return -1;

		/*
		 * Get a buffer that refers to the line.
		 *
		 * Note that "tvb_find_line_end()" will return a value that
		 * is not longer than what's in the buffer, so the
		 * "tvb_get_ptr()" call won't throw an exception.
		 */
		line = tvb_get_ptr(tvb, offset, linelen);
		lineend = line + linelen;
		colon_offset = -1;

		/*
		 * OK, does it look like an HTTP request or response?
		 */
		reqresp_dissector = NULL;
		is_request_or_reply =
		    is_http_request_or_reply((const gchar *)line,
		    linelen, &http_type, &reqresp_dissector, conv_data);
		if (is_request_or_reply)
			goto is_http;

		/*
		 * No.  Does it look like a blank line (as would appear
		 * at the end of an HTTP request)?
		 */
		if (linelen == 0)
			goto is_http;	/* Yes. */

		/*
		 * No.  Does it look like a header?
		 */
		linep = line;
		colon_offset = offset;
		while (linep < lineend) {
			c = *linep++;

			/*
			 * This must be a CHAR to be part of a token; that
			 * means it must be ASCII.
			 */
			if (!isascii(c))
				break;	/* not ASCII, thus not a CHAR */

			/*
			 * This mustn't be a CTL to be part of a token.
			 *
			 * XXX - what about leading LWS on continuation
			 * lines of a header?
			 */
			if (iscntrl(c))
				break;	/* CTL, not part of a header */

			/*
			 * This mustn't be a SEP to be part of a token;
			 * a ':' ends the token, everything else is an
			 * indication that this isn't a header.
			 */
			switch (c) {

			case '(':
			case ')':
			case '<':
			case '>':
			case '@':
			case ',':
			case ';':
			case '\\':
			case '"':
			case '/':
			case '[':
			case ']':
			case '?':
			case '=':
			case '{':
			case '}':
			case ' ':
				/*
				 * It's a separator, so it's not part of a
				 * token, so it's not a field name for the
				 * beginning of a header.
				 *
				 * (We don't have to check for HT; that's
				 * already been ruled out by "iscntrl()".)
				 */
				goto not_http;

			case ':':
				/*
				 * This ends the token; we consider this
				 * to be a header.
				 */
				goto is_http;

			default:
				colon_offset++;
				break;
			}
		}

		/*
		 * We haven't seen the colon, but everything else looks
		 * OK for a header line.
		 *
		 * If we've already seen an HTTP request or response
		 * line, or a header line, and we're at the end of
		 * the tvbuff, we assume this is an incomplete header
		 * line.  (We quit this loop after seeing a blank line,
		 * so if we've seen a request or response line, or a
		 * header line, this is probably more of the request
		 * or response we're presumably seeing.  There is some
		 * risk of false positives, but the same applies for
		 * full request or response lines or header lines,
		 * although that's less likely.)
		 *
		 * We throw an exception in that case, by checking for
		 * the existence of the next byte after the last one
		 * in the line.  If it exists, "tvb_ensure_bytes_exist()"
		 * throws no exception, and we fall through to the
		 * "not HTTP" case.  If it doesn't exist,
		 * "tvb_ensure_bytes_exist()" will throw the appropriate
		 * exception.
		 */
		if (saw_req_resp_or_header)
			tvb_ensure_bytes_exist(tvb, offset, linelen + 1);

	not_http:
		/*
		 * We don't consider this part of an HTTP request or
		 * reply, so we don't display it.
		 * (Yeah, that means we don't display, say, a text/http
		 * page, but you can get that from the data pane.)
		 */
		break;

	is_http:
		if (first_loop) {
			col_set_str(pinfo->cinfo, COL_PROTOCOL, proto_tag);

			/*
			 * Put the first line from the buffer into the summary
			 * if it's an HTTP request or reply (but leave out the
			 * line terminator).
			 * Otherwise, just call it a continuation.
			 */
			if (is_request_or_reply)
				col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", format_text(firstline, first_linelen));
			else
				col_set_str(pinfo->cinfo, COL_INFO, "Continuation");

			first_loop = FALSE;
		}

		if ((tree) && (http_tree == NULL)) {
			ti = proto_tree_add_item(tree, proto_http, tvb, orig_offset, -1, ENC_NA);
			http_tree = proto_item_add_subtree(ti, ett_http);
		}

		/*
		 * Process this line.
		 */

		if (linelen == 0) {
			/*
			 * This is a blank line, which means that
			 * whatever follows it isn't part of this
			 * request or reply.
			 */
			proto_tree_add_format_text(http_tree, tvb, offset, next_offset - offset);
			offset = next_offset;
			break;
		}

		/*
		 * Not a blank line - either a request, a reply, or a header
		 * line.
		 */
		saw_req_resp_or_header = TRUE;
		if (is_request_or_reply) {
		    	char *text = tvb_format_text(tvb, offset, next_offset - offset);
			if (tree) {
				hdr_item = proto_tree_add_text(http_tree, tvb,
				    offset, next_offset - offset, "%s", text);
			}
			expert_add_info_format(pinfo, hdr_item, &ei_http_chat, "%s", text);
			if (reqresp_dissector) {
				if (tree)
					req_tree = proto_item_add_subtree(hdr_item, ett_http_request);
				else
					req_tree = NULL;

				reqresp_dissector(tvb, req_tree, offset, line,
						  lineend, conv_data);
			}
		} else {
			/*
			 * Header.
			 */
			process_header(tvb, offset, next_offset, line, linelen,
			    colon_offset, pinfo, http_tree, &headers, conv_data,
			    http_type);
		}
		offset = next_offset;
	}

	if (tree && stat_info->http_host && stat_info->request_uri) {
		proto_item *e_ti;
		gboolean    is_ssl = FALSE;
		gchar      *uri;

		proto_get_frame_protocols(pinfo->layers, NULL, NULL, NULL, NULL, &is_ssl);
		uri = wmem_strdup_printf(wmem_packet_scope(), "%s://%s%s",
			    is_ssl ? "https" : "http",
			    g_strstrip(wmem_strdup(wmem_packet_scope(), stat_info->http_host)), stat_info->request_uri);

		e_ti = proto_tree_add_string(http_tree,
					     hf_http_request_full_uri, tvb, 0,
					     0, uri);

		PROTO_ITEM_SET_URL(e_ti);
		PROTO_ITEM_SET_GENERATED(e_ti);
	}

	if (!PINFO_FD_VISITED(pinfo)) {
		if (http_type == HTTP_REQUEST) {
			push_req(conv_data, pinfo);
		} else if (http_type == HTTP_RESPONSE) {
			push_res(conv_data, pinfo);
		}
	}

	if (tree) {
		proto_item *pi;
		http_req_res_t *curr = (http_req_res_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_http, 0);
		http_req_res_t *prev = curr ? curr->prev : NULL;
		http_req_res_t *next = curr ? curr->next : NULL;

		switch (http_type) {

		case HTTP_NOTIFICATION:
			hidden_item = proto_tree_add_boolean(http_tree,
					    hf_http_notification, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			break;

		case HTTP_RESPONSE:
			hidden_item = proto_tree_add_boolean(http_tree,
					    hf_http_response, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			if (curr) {
				nstime_t delta;

				pi = proto_tree_add_text(http_tree, tvb, 0, 0, "HTTP response %u/%u", curr->number, conv_data->req_res_num);
				PROTO_ITEM_SET_GENERATED(pi);

				if (! nstime_is_unset(&(curr->req_ts))) {
					nstime_delta(&delta, &pinfo->fd->abs_ts, &(curr->req_ts));
					pi = proto_tree_add_time(http_tree, hf_http_time, tvb, 0, 0, &delta);
					PROTO_ITEM_SET_GENERATED(pi);
				}
			}
			if (prev && prev->req_framenum) {
				pi = proto_tree_add_uint(http_tree, hf_http_prev_request_in, tvb, 0, 0, prev->req_framenum);
				PROTO_ITEM_SET_GENERATED(pi);
			}
			if (prev && prev->res_framenum) {
				pi = proto_tree_add_uint(http_tree, hf_http_prev_response_in, tvb, 0, 0, prev->res_framenum);
				PROTO_ITEM_SET_GENERATED(pi);
			}
			if (curr && curr->req_framenum) {
				pi = proto_tree_add_uint(http_tree, hf_http_request_in, tvb, 0, 0, curr->req_framenum);
				PROTO_ITEM_SET_GENERATED(pi);
			}
			if (next && next->req_framenum) {
				pi = proto_tree_add_uint(http_tree, hf_http_next_request_in, tvb, 0, 0, next->req_framenum);
				PROTO_ITEM_SET_GENERATED(pi);
			}
			if (next && next->res_framenum) {
				pi = proto_tree_add_uint(http_tree, hf_http_next_response_in, tvb, 0, 0, next->res_framenum);
				PROTO_ITEM_SET_GENERATED(pi);
			}

			break;

		case HTTP_REQUEST:
			hidden_item = proto_tree_add_boolean(http_tree,
					    hf_http_request, tvb, 0, 0, 1);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			if (curr) {
				pi = proto_tree_add_text(http_tree, tvb, 0, 0, "HTTP request %u/%u", curr->number, conv_data->req_res_num);
				PROTO_ITEM_SET_GENERATED(pi);
			}
			if (prev && prev->req_framenum) {
				pi = proto_tree_add_uint(http_tree, hf_http_prev_request_in, tvb, 0, 0, prev->req_framenum);
				PROTO_ITEM_SET_GENERATED(pi);
			}
			if (curr && curr->res_framenum) {
				pi = proto_tree_add_uint(http_tree, hf_http_response_in, tvb, 0, 0, curr->res_framenum);
				PROTO_ITEM_SET_GENERATED(pi);
			}
			if (next && next->req_framenum) {
				pi = proto_tree_add_uint(http_tree, hf_http_next_request_in, tvb, 0, 0, next->req_framenum);
				PROTO_ITEM_SET_GENERATED(pi);
			}

			break;

		case HTTP_OTHERS:
		default:
			break;
		}
	}

	reported_datalen = tvb_reported_length_remaining(tvb, offset);
	datalen = tvb_length_remaining(tvb, offset);

	/*
	 * If a content length was supplied, the amount of data to be
	 * processed as HTTP payload is the minimum of the content
	 * length and the amount of data remaining in the frame.
	 *
	 * If a message is received with both a Transfer-Encoding
	 * header field and a Content-Length header field, the latter
	 * MUST be ignored.
	 *
	 * If no content length was supplied (or if a bad content length
	 * was supplied), the amount of data to be processed is the amount
	 * of data remaining in the frame.
	 *
	 * If there was no Content-Length entity header, we should
	 * accumulate all data until the end of the connection.
	 * That'd require that the TCP dissector call subdissectors
	 * for all frames with FIN, even if they contain no data,
	 * which would require subdissectors to deal intelligently
	 * with empty segments.
	 *
	 * According to RFC 2616, however, 1xx responses, 204 responses,
	 * and 304 responses MUST NOT include a message body; if no
	 * content length is specified for them, we don't attempt to
	 * dissect the body.
	 *
	 * XXX - it says the same about responses to HEAD requests;
	 * unless there's a way to determine from the response
	 * whether it's a response to a HEAD request, we have to
	 * keep information about the request and associate that with
	 * the response in order to handle that.
	 */
	if (headers.have_content_length &&
	    headers.content_length != -1 &&
	    headers.transfer_encoding == NULL) {
		if (datalen > headers.content_length)
			datalen = (int)headers.content_length;

		/*
		 * XXX - limit the reported length in the tvbuff we'll
		 * hand to a subdissector to be no greater than the
		 * content length.
		 *
		 * We really need both unreassembled and "how long it'd
		 * be if it were reassembled" lengths for tvbuffs, so
		 * that we throw the appropriate exceptions for
		 * "not enough data captured" (running past the length),
		 * "packet needed reassembly" (within the length but
		 * running past the unreassembled length), and
		 * "packet is malformed" (running past the reassembled
		 * length).
		 */
		if (reported_datalen > headers.content_length)
			reported_datalen = (int)headers.content_length;
	} else {
		switch (http_type) {

		case HTTP_REQUEST:
			/*
			 * Requests have no content if there's no
			 * Content-Length header and no Transfer-Encoding
			 * header.
			 */
			if (headers.transfer_encoding == NULL)
				datalen = 0;
			else
				reported_datalen = -1;
			break;

		case HTTP_RESPONSE:
			if ((stat_info->response_code/100) == 1 ||
			    stat_info->response_code == 204 ||
			    stat_info->response_code == 304)
				datalen = 0;	/* no content! */
			else {
				/*
				 * XXX - responses to HEAD requests,
				 * and possibly other responses,
				 * "MUST NOT" include a
				 * message-body.
				 */
				reported_datalen = -1;
			}
			break;

		default:
			/*
			 * XXX - what about HTTP_NOTIFICATION?
			 */
			reported_datalen = -1;
			break;
		}
	}

	if (datalen > 0) {
		/*
		 * There's stuff left over; process it.
		 */
		tvbuff_t *next_tvb;
		void *save_private_data = NULL;
		gboolean private_data_changed = FALSE;
		gint chunks_decoded = 0;

		/*
		 * Create a tvbuff for the payload.
		 *
		 * The amount of data to be processed that's
		 * available in the tvbuff is "datalen", which
		 * is the minimum of the amount of data left in
		 * the tvbuff and any specified content length.
		 *
		 * The amount of data to be processed that's in
		 * this frame, regardless of whether it was
		 * captured or not, is "reported_datalen",
		 * which, if no content length was specified,
		 * is -1, i.e. "to the end of the frame.
		 */
		next_tvb = tvb_new_subset(tvb, offset, datalen,
		    reported_datalen);

		/*
		 * Handle *transfer* encodings other than "identity".
		 */
		if (headers.transfer_encoding != NULL &&
		    g_ascii_strcasecmp(headers.transfer_encoding, "identity") != 0) {
			if (http_dechunk_body &&
			    (g_ascii_strncasecmp(headers.transfer_encoding, "chunked", 7)
			    == 0)) {

				chunks_decoded = chunked_encoding_dissector(
				    &next_tvb, pinfo, http_tree, 0);

				if (chunks_decoded <= 0) {
					/*
					 * The chunks weren't reassembled,
					 * or there was a single zero
					 * length chunk.
					 */
					goto body_dissected;
				} else {
					/*
					 * Add a new data source for the
					 * de-chunked data.
					 */
#if 0 /* Handled in chunked_encoding_dissector() */
					tvb_set_child_real_data_tvbuff(tvb,
						next_tvb);
#endif
					add_new_data_source(pinfo, next_tvb,
						"De-chunked entity body");
				}
			} else {
				/*
				 * We currently can't handle, for example,
				 * "gzip", "compress", or "deflate" as
				 * *transfer* encodings; just handle them
				 * as data for now.
				 */
				call_dissector(data_handle, next_tvb, pinfo,
				    http_tree);
				goto body_dissected;
			}
		}
		/*
		 * At this point, any chunked *transfer* coding has been removed
		 * (the entity body has been dechunked) so it can be presented
		 * for the following operation (*content* encoding), or it has
		 * been been handed off to the data dissector.
		 *
		 * Handle *content* encodings other than "identity" (which
		 * shouldn't appear in a Content-Encoding header, but
		 * we handle it in any case).
		 */
		if (headers.content_encoding != NULL &&
		    g_ascii_strcasecmp(headers.content_encoding, "identity") != 0) {
			/*
			 * We currently can't handle, for example, "compress";
			 * just handle them as data for now.
			 *
			 * After July 7, 2004 the LZW patent expires, so support
			 * might be added then.  However, I don't think that
			 * anybody ever really implemented "compress", due to
			 * the aforementioned patent.
			 */
			tvbuff_t *uncomp_tvb = NULL;
			proto_item *e_ti = NULL;
			proto_tree *e_tree = NULL;

			if (http_decompress_body &&
			    (g_ascii_strcasecmp(headers.content_encoding, "gzip") == 0 ||
			     g_ascii_strcasecmp(headers.content_encoding, "deflate") == 0 ||
			     g_ascii_strcasecmp(headers.content_encoding, "x-gzip") == 0 ||
			     g_ascii_strcasecmp(headers.content_encoding, "x-deflate") == 0))
			{
				uncomp_tvb = tvb_child_uncompress(tvb, next_tvb, 0,
				    tvb_length(next_tvb));
			}

			/*
			 * Add the encoded entity to the protocol tree
			 */
			e_ti = proto_tree_add_text(http_tree, next_tvb,
					0, tvb_length(next_tvb),
					"Content-encoded entity body (%s): %u bytes",
					headers.content_encoding,
					tvb_length(next_tvb));
			e_tree = proto_item_add_subtree(e_ti,
					ett_http_encoded_entity);

			if (uncomp_tvb != NULL) {
				/*
				 * Decompression worked
				 */

				/* XXX - Don't free this, since it's possible
				 * that the data was only partially
				 * decompressed, such as when desegmentation
				 * isn't enabled.
				 *
				tvb_free(next_tvb);
				*/
				proto_item_append_text(e_ti, " -> %u bytes", tvb_length(uncomp_tvb));
				next_tvb = uncomp_tvb;
				add_new_data_source(pinfo, next_tvb,
				    "Uncompressed entity body");
			} else {
				proto_item_append_text(e_ti, " [Error: Decompression failed]");
				call_dissector(data_handle, next_tvb, pinfo,
				    e_tree);

				goto body_dissected;
			}
		}
		/*
		 * Note that a new data source is added for the entity body
		 * only if it was content-encoded and/or transfer-encoded.
		 */

		/* Save values for the Export Object GUI feature if we have
		 * an active listener to process it (which happens when
		 * the export object window is open). */
		if(have_tap_listener(http_eo_tap)) {
			eo_info = wmem_new(wmem_packet_scope(), http_eo_t);

			eo_info->hostname = conv_data->http_host;
			eo_info->filename = conv_data->request_uri;
			eo_info->content_type = headers.content_type;
			eo_info->payload_len = tvb_length(next_tvb);
			eo_info->payload_data = tvb_get_ptr(next_tvb, 0, eo_info->payload_len);

			tap_queue_packet(http_eo_tap, pinfo, eo_info);
		}

		/*
		 * Do subdissector checks.
		 *
		 * First, if we have a Content-Type value, check whether
		 * there's a subdissector for that media type.
		 */
		handle = NULL;
		if (headers.content_type != NULL) {
			/*
			 * We didn't find any subdissector that
			 * registered for the port, and we have a
			 * Content-Type value.  Is there any subdissector
			 * for that content type?
			 */
			save_private_data = pinfo->private_data;
			private_data_changed = TRUE;

			if (headers.content_type_parameters)
				pinfo->private_data = wmem_strdup(wmem_packet_scope(), headers.content_type_parameters);
			else
				pinfo->private_data = NULL;
			/*
			 * Calling the string handle for the media type
			 * dissector table will set pinfo->match_string
			 * to headers.content_type for us.
			 */
			pinfo->match_string = headers.content_type;
			handle = dissector_get_string_handle(
			    media_type_subdissector_table,
			    headers.content_type);
			if (handle == NULL &&
			    strncmp(headers.content_type, "multipart/", sizeof("multipart/")-1) == 0) {
				/* Try to decode the unknown multipart subtype anyway */
				handle = dissector_get_string_handle(
				    media_type_subdissector_table,
				    "multipart/");
			}
		}

		/*
		 * Now, if we didn't find such a subdissector, check
		 * whether some subdissector asked that they be called
		 * if HTTP traffic was on some particular port.  This
		 * handles protocols that use HTTP syntax but don't have
		 * a media type and instead use a specified port.
		 */
		if (handle == NULL) {
			handle = dissector_get_uint_handle(port_subdissector_table,
			    pinfo->match_uint);
		}

		if (handle != NULL) {
			/*
			 * We have a subdissector - call it.
			 */
			dissected = call_dissector_only(handle, next_tvb, pinfo, tree, NULL);
			if (!dissected)
				expert_add_info(pinfo, http_tree, &ei_http_subdissector_failed);
		}

		if (!dissected) {
			/*
			 * We don't have a subdissector or we have one and it did not
			 * dissect the payload - try the heuristic subdissectors.
			 */
			dissected = dissector_try_heuristic(heur_subdissector_list,
							    next_tvb, pinfo, tree, &hdtbl_entry, NULL);
		}

		if (dissected) {
			/*
			 * The subdissector dissected the body.
			 * Fix up the top-level item so that it doesn't
			 * include the stuff for that protocol.
			 */
			if (ti != NULL)
				proto_item_set_len(ti, offset);
		} else {
			if (headers.content_type != NULL) {
				/*
				 * Calling the default media handle if there is a content-type that
				 * wasn't handled above.
				 */
				call_dissector(media_handle, next_tvb, pinfo, tree);
			} else {
				/* Call the default data dissector */
				call_dissector(data_handle, next_tvb, pinfo, http_tree);
			}
		}

	body_dissected:
		/*
		 * Do *not* attempt at freeing the private data;
		 * it may be in use by subdissectors.
		 */
		if (private_data_changed) /*restore even NULL value*/
			pinfo->private_data = save_private_data;
		/*
		 * We've processed "datalen" bytes worth of data
		 * (which may be no data at all); advance the
		 * offset past whatever data we've processed.
		 */
		offset += datalen;
	}

	if (http_type == HTTP_RESPONSE && pinfo->desegment_offset<=0 && pinfo->desegment_len<=0) {
		conv_data->upgrade = headers.upgrade;
		conv_data->startframe = pinfo->fd->num + 1;
		SE_COPY_ADDRESS(&conv_data->server_addr, &pinfo->src);
		conv_data->server_port = pinfo->srcport;
	}

	tap_queue_packet(http_tap, pinfo, stat_info);

	return offset - orig_offset;
}

/* This can be used to dissect an HTTP request until such time
 * that a more complete dissector is written for that HTTP request.
 * This simple dissector only puts the request method, URI, and
 * protocol version into a sub-tree.
 */
static void
basic_request_dissector(tvbuff_t *tvb, proto_tree *tree, int offset,
			const guchar *line, const guchar *lineend,
			http_conv_t *conv_data)
{
	const guchar *next_token;
	const gchar *request_uri;
	int tokenlen;

	/* The first token is the method. */
	tokenlen = get_token_len(line, lineend, &next_token);
	if (tokenlen == 0)
		return;
	proto_tree_add_item(tree, hf_http_request_method, tvb, offset, tokenlen,
			    ENC_ASCII|ENC_NA);
	if ((next_token - line) > 2 && next_token[-1] == ' ' && next_token[-2] == ' ') {
	  /* Two spaces in a now indicates empty URI, so roll back one here */
	  next_token--;
	}
	offset += (int) (next_token - line);
	line = next_token;

	/* The next token is the URI. */
	tokenlen = get_token_len(line, lineend, &next_token);

	/* Save the request URI for various later uses */
	request_uri = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, tokenlen, ENC_ASCII);
	stat_info->request_uri = wmem_strdup(wmem_packet_scope(), request_uri);
	conv_data->request_uri = wmem_strdup(wmem_file_scope(), request_uri);

	proto_tree_add_string(tree, hf_http_request_uri, tvb, offset, tokenlen,
			      request_uri);
	offset += (int) (next_token - line);
	line = next_token;

	/* Everything to the end of the line is the version. */
	tokenlen = (int) (lineend - line);
	proto_tree_add_item(tree, hf_http_version, tvb, offset, tokenlen,
	    ENC_ASCII|ENC_NA);
}

static void
basic_response_dissector(tvbuff_t *tvb, proto_tree *tree, int offset,
			 const guchar *line, const guchar *lineend,
			 http_conv_t *conv_data _U_)
{
	const guchar *next_token;
	int tokenlen;
	gchar response_code_chars[4];

	/*
	 * The first token is the HTTP Version.
	 */
	tokenlen = get_token_len(line, lineend, &next_token);
	if (tokenlen == 0)
		return;
	proto_tree_add_item(tree, hf_http_version, tvb, offset, tokenlen,
			    ENC_ASCII|ENC_NA);
	/* Advance to the start of the next token. */
	offset += (int) (next_token - line);
	line = next_token;

	/*
	 * The second token is the Status Code.
	 */
	tokenlen = get_token_len(line, lineend, &next_token);
	if (tokenlen < 3)
		return;

	/* The Status Code characters must be copied into a null-terminated
	 * buffer for strtoul() to parse them into an unsigned integer value.
	 */
	memcpy(response_code_chars, line, 3);
	response_code_chars[3] = '\0';

	stat_info->response_code = conv_data->response_code =
		(guint)strtoul(response_code_chars, NULL, 10);

	proto_tree_add_uint(tree, hf_http_response_code, tvb, offset, 3,
			    stat_info->response_code);

	/* Advance to the start of the next token. */
	offset += (int) (next_token - line);
	line = next_token;

	/*
	 * The remaining tokens in the line comprise the Reason Phrase.
	 */
	tokenlen = (int) (lineend - line);
	if (tokenlen < 1)
		return;
	proto_tree_add_item(tree, hf_http_response_phrase, tvb, offset,
				tokenlen, ENC_ASCII|ENC_NA);

}

#if 0 /* XXX: Replaced by code creating the "Dechunked" tvb  O(N) rather tan O(N^2) */
/*
 * Dissect the http data chunks and add them to the tree.
 */
static int
chunked_encoding_dissector(tvbuff_t **tvb_ptr, packet_info *pinfo,
			   proto_tree *tree, int offset)
{
	guint8 *chunk_string = NULL;
	guint32 chunk_size = 0;
	gint chunk_offset = 0;
	guint32 datalen = 0;
	gint linelen = 0;
	gint chunks_decoded = 0;
	tvbuff_t *tvb = NULL;
	tvbuff_t *new_tvb = NULL;
	gint chunked_data_size = 0;
	proto_tree *subtree = NULL;
	proto_item *ti = NULL;

	if (tvb_ptr == NULL || *tvb_ptr == NULL) {
		return 0;
	}

	tvb = *tvb_ptr;

	datalen = tvb_reported_length_remaining(tvb, offset);

	if (tree) {
		ti = proto_tree_add_text(tree, tvb, offset, datalen,
					 "HTTP chunked response");
		subtree = proto_item_add_subtree(ti, ett_http_chunked_response);
	}


	while (datalen > 0) {
		proto_item *chunk_ti = NULL;
		proto_tree *chunk_subtree = NULL;
		tvbuff_t *data_tvb = NULL; /*  */
		gchar *c = NULL;
		guint8 *raw_data;
		gint raw_len = 0;

		linelen = tvb_find_line_end(tvb, offset, -1, &chunk_offset, TRUE);

		if (linelen <= 0) {
			/* Can't get the chunk size line */
			break;
		}

		chunk_string = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, linelen, ENC_ASCII);

		if (chunk_string == NULL) {
			/* Can't get the chunk size line */
			break;
		}

		c = (gchar*) chunk_string;

		/*
		 * We don't care about the extensions.
		 */
		if ((c = strchr(c, ';'))) {
			*c = '\0';
		}

		chunk_size = (guint32)strtol((gchar*)chunk_string, NULL, 16);

		if (chunk_size > datalen) {
			/*
			 * The chunk size is more than what's in the tvbuff,
			 * so either the user hasn't enabled decoding, or all
			 * of the segments weren't captured.
			 */
			chunk_size = datalen;
		}
#if 0
		  else if (new_tvb == NULL) {
			new_tvb = tvb_new_composite();
		}



		if (new_tvb != NULL && chunk_size != 0) {
			tvbuff_t *chunk_tvb = NULL;

			chunk_tvb = tvb_new_subset(tvb, chunk_offset,
			    chunk_size, datalen);

			tvb_composite_append(new_tvb, chunk_tvb);

		}
#endif

		chunked_data_size += chunk_size;

		raw_data = g_malloc(chunked_data_size);
		raw_len = 0;

		if (new_tvb != NULL) {
			raw_len = tvb_length_remaining(new_tvb, 0);
			tvb_memcpy(new_tvb, raw_data, 0, raw_len);

			tvb_free(new_tvb);
		}

		tvb_memcpy(tvb, (guint8 *)(raw_data + raw_len),
			    chunk_offset, chunk_size);

		/* Don't create a new tvb if we have a single chunk with
		 * a size of zero (meaning it is the end of the chunks). */
		if(chunked_data_size > 0) {
			new_tvb = tvb_new_real_data(raw_data,
			      chunked_data_size, chunked_data_size);
			tvb_set_free_cb(new_tvb, g_free);
		}


		if (subtree) {
			if(chunk_size == 0) {
				chunk_ti = proto_tree_add_text(subtree, tvb,
					    offset,
					    chunk_offset - offset + chunk_size + 2,
					    "End of chunked encoding");
			} else {
				chunk_ti = proto_tree_add_text(subtree, tvb,
					    offset,
					    chunk_offset - offset + chunk_size + 2,
					    "Data chunk (%u octets)", chunk_size);
			}

			chunk_subtree = proto_item_add_subtree(chunk_ti,
			    ett_http_chunk_data);

			proto_tree_add_text(chunk_subtree, tvb, offset,
			    chunk_offset - offset, "Chunk size: %u octets",
			    chunk_size);

			data_tvb = tvb_new_subset_length(tvb, chunk_offset, chunk_size);


			/*
			 * XXX - just use "proto_tree_add_text()"?
			 * This means that, in TShark, you get
			 * the entire chunk dumped out in hex,
			 * in addition to whatever dissection is
			 * done on the reassembled data.
			 */
			call_dissector(data_handle, data_tvb, pinfo,
				    chunk_subtree);

			proto_tree_add_text(chunk_subtree, tvb, chunk_offset +
			    chunk_size, 2, "Chunk boundary");
		}

		chunks_decoded++;
		offset = chunk_offset + chunk_size + 2;
		datalen = tvb_reported_length_remaining(tvb, offset);
	}

	if (new_tvb != NULL) {

		/* Placeholder for the day that composite tvbuffer's will work.
		tvb_composite_finalize(new_tvb);
		/ * tvb_set_reported_length(new_tvb, chunked_data_size); * /
		*/

		/*
		 * XXX - Don't free this, since the tvbuffer that was passed
		 * may be used if the data spans multiple frames and reassembly
		 * isn't enabled.
		 *
		tvb_free(*tvb_ptr);
		 */
		*tvb_ptr = new_tvb;

	} else {
		/*
		 * We didn't create a new tvb, so don't allow sub dissectors
		 * try to decode the non-existent entity body.
		 */
		chunks_decoded = -1;
	}

	return chunks_decoded;

}
#else
/*
 * Dissect the http data chunks and add them to the tree.
 */
static int
chunked_encoding_dissector(tvbuff_t **tvb_ptr, packet_info *pinfo,
			   proto_tree *tree, int offset)
{
	tvbuff_t	*tvb;
	guint32		 datalen;
	guint32		 orig_datalen;
	gint		 chunks_decoded;
	gint		 chunked_data_size;
	proto_tree	*subtree;
	guint8		*raw_data;
	gint		 raw_len;

	if ((tvb_ptr == NULL) || (*tvb_ptr == NULL)) {
		return 0;
	}

	tvb = *tvb_ptr;

	datalen = tvb_reported_length_remaining(tvb, offset);

	subtree = NULL;
	if (tree) {
		proto_item *ti;
		ti = proto_tree_add_text(tree, tvb, offset, datalen,
					 "HTTP chunked response");
		subtree = proto_item_add_subtree(ti, ett_http_chunked_response);
	}

	/* Dechunk the "chunked response" to a new memory buffer */
	orig_datalen      = datalen;
	raw_data	      = (guint8 *)wmem_alloc(pinfo->pool, datalen);
	raw_len		      = 0;
	chunks_decoded	  = 0;
	chunked_data_size = 0;

	while (datalen > 0) {
		tvbuff_t *data_tvb;
		guint32	  chunk_size;
		gint	  chunk_offset;
		guint8	 *chunk_string;
		gint	  linelen;
		gchar	 *c;

		linelen = tvb_find_line_end(tvb, offset, -1, &chunk_offset, TRUE);

		if (linelen <= 0) {
			/* Can't get the chunk size line */
			break;
		}

		chunk_string = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, linelen, ENC_ASCII);

		if (chunk_string == NULL) {
			/* Can't get the chunk size line */
			break;
		}

		c = (gchar*)chunk_string;

		/*
		 * We don't care about the extensions.
		 */
		if ((c = strchr(c, ';'))) {
			*c = '\0';
		}

		chunk_size = (guint32)strtol((gchar*)chunk_string, NULL, 16);

		if (chunk_size > datalen) {
			/*
			 * The chunk size is more than what's in the tvbuff,
			 * so either the user hasn't enabled decoding, or all
			 * of the segments weren't captured.
			 */
			chunk_size = datalen;
		}

		chunked_data_size += chunk_size;

		DISSECTOR_ASSERT((raw_len+chunk_size) <= orig_datalen);
		tvb_memcpy(tvb, (guint8 *)(raw_data + raw_len), chunk_offset, chunk_size);
		raw_len += chunk_size;

		if (subtree) {
			proto_item *chunk_ti;
			proto_tree *chunk_subtree;

			if(chunk_size == 0) {
				chunk_ti = proto_tree_add_text(subtree, tvb,
					    offset,
					    chunk_offset - offset + chunk_size + 2,
					    "End of chunked encoding");
			} else {
				chunk_ti = proto_tree_add_text(subtree, tvb,
					    offset,
					    chunk_offset - offset + chunk_size + 2,
					    "Data chunk (%u octets)", chunk_size);
			}

			chunk_subtree = proto_item_add_subtree(chunk_ti,
			    ett_http_chunk_data);

			proto_tree_add_text(chunk_subtree, tvb, offset,
			    chunk_offset - offset, "Chunk size: %u octets",
			    chunk_size);

			data_tvb = tvb_new_subset(tvb, chunk_offset, chunk_size, datalen);

			/*
			 * XXX - just use "proto_tree_add_text()"?
			 * This means that, in TShark, you get
			 * the entire chunk dumped out in hex,
			 * in addition to whatever dissection is
			 * done on the reassembled data.
			 */
			call_dissector(data_handle, data_tvb, pinfo,
				    chunk_subtree);

			proto_tree_add_text(chunk_subtree, tvb, chunk_offset +
			    chunk_size, 2, "Chunk boundary");
		}

		chunks_decoded++;
		offset  = chunk_offset + 2 + chunk_size;  /* beginning of next chunk */
		datalen = tvb_reported_length_remaining(tvb, offset);
	}

	if (chunked_data_size > 0) {
		tvbuff_t *new_tvb;
		new_tvb = tvb_new_child_real_data(tvb, raw_data, chunked_data_size, chunked_data_size);
		*tvb_ptr = new_tvb;
	} else {
		/*
		 * There was no actual chunk data, so don't allow sub dissectors
		 * try to decode the non-existent entity body.
		 */
		chunks_decoded = -1;
	}

	return chunks_decoded;
}
#endif

/* Call a subdissector to handle HTTP CONNECT's traffic */
static void
http_payload_subdissector(tvbuff_t *tvb, proto_tree *tree,
			  packet_info *pinfo, http_conv_t *conv_data, void* data)
{
	guint32 *ptr = NULL;
	guint32 uri_port, saved_port, srcport, destport;
	gchar **strings; /* An array for splitting the request URI into hostname and port */
	proto_item *item;
	proto_tree *proxy_tree;
	conversation_t *conv;
	gboolean from_server = pinfo->srcport == conv_data->server_port &&
		addresses_equal(&conv_data->server_addr, &pinfo->src);

	/* Grab the destination port number from the request URI to find the right subdissector */
	strings = g_strsplit(conv_data->request_uri, ":", 2);

	if(strings[0] != NULL && strings[1] != NULL) {
		/*
		 * The string was successfully split in two
		 * Create a proxy-connect subtree
		 */
		if(tree) {
			item = proto_tree_add_item(tree, proto_http, tvb, 0, -1, ENC_NA);
			proxy_tree = proto_item_add_subtree(item, ett_http);

			item = proto_tree_add_string(proxy_tree, hf_http_proxy_connect_host,
						     tvb, 0, 0, strings[0]);
			PROTO_ITEM_SET_GENERATED(item);

			item = proto_tree_add_uint(proxy_tree, hf_http_proxy_connect_port,
						   tvb, 0, 0, (guint32)strtol(strings[1], NULL, 10) );
			PROTO_ITEM_SET_GENERATED(item);
		}

		uri_port = (int)strtol(strings[1], NULL, 10); /* Convert string to a base-10 integer */

		if (!from_server) {
			srcport = pinfo->srcport;
			destport = uri_port;
		} else {
			srcport = uri_port;
			destport = pinfo->destport;
		}

		conv = find_conversation(PINFO_FD_NUM(pinfo), &pinfo->src, &pinfo->dst, PT_TCP, srcport, destport, 0);

		/* We may get stuck in a recursion loop if we let process_tcp_payload() call us.
		 * So, if the port in the URI is one we're registered for or we have set up a
		 * conversation (e.g., one we detected heuristically or via Decode-As) call the data
		 * dissector directly.
		 */
		if (value_is_in_range(http_tcp_range, uri_port) || (conv && conv->dissector_handle == http_handle)) {
			call_dissector(data_handle, tvb, pinfo, tree);
		} else {
			/* set pinfo->{src/dst port} and call the TCP sub-dissector lookup */
			if (!from_server)
				ptr = &pinfo->destport;
			else
				ptr = &pinfo->srcport;

			/* Increase pinfo->can_desegment because we are traversing
			 * http and want to preserve desegmentation functionality for
			 * the proxied protocol
			 */
			if( pinfo->can_desegment>0 )
				pinfo->can_desegment++;

			saved_port = *ptr;
			*ptr = uri_port;
			decode_tcp_ports(tvb, 0, pinfo, tree,
				pinfo->srcport, pinfo->destport, NULL,
				(struct tcpinfo *)data);
			*ptr = saved_port;
		}
	}
	g_strfreev(strings); /* Free the result of g_strsplit() above */
}



/*
 * XXX - this won't handle HTTP 0.9 replies, but they're all data
 * anyway.
 */
static int
is_http_request_or_reply(const gchar *data, int linelen, http_type_t *type,
			 ReqRespDissector *reqresp_dissector,
			 http_conv_t *conv_data)
{
	int isHttpRequestOrReply = FALSE;

	/*
	 * From RFC 2774 - An HTTP Extension Framework
	 *
	 * Support the command prefix that identifies the presence of
	 * a "mandatory" header.
	 */
	if (linelen >= 2 && strncmp(data, "M-", 2) == 0) {
		data += 2;
		linelen -= 2;
	}

	/*
	 * From draft-cohen-gena-client-01.txt, available from the uPnP forum:
	 *	NOTIFY, SUBSCRIBE, UNSUBSCRIBE
	 *
	 * From draft-ietf-dasl-protocol-00.txt, a now vanished Microsoft draft:
	 *	SEARCH
	 */
	if (linelen >= 5 && strncmp(data, "HTTP/", 5) == 0) {
		*type = HTTP_RESPONSE;
		isHttpRequestOrReply = TRUE;	/* response */
		if (reqresp_dissector)
			*reqresp_dissector = basic_response_dissector;
	} else {
		const guchar * ptr = (const guchar *)data;
		int		 indx = 0;

		/* Look for the space following the Method */
		while (indx < linelen) {
			if (*ptr == ' ')
				break;
			else {
				ptr++;
				indx++;
			}
		}

		/* Check the methods that have same length */
		switch (indx) {

		case 3:
			if (strncmp(data, "GET", indx) == 0 ||
			    strncmp(data, "PUT", indx) == 0) {
				*type = HTTP_REQUEST;
				isHttpRequestOrReply = TRUE;
			}
			else if (strncmp(data, "ICY", indx) == 0) {
				*type = HTTP_RESPONSE;
				isHttpRequestOrReply = TRUE;
			}
			break;

		case 4:
			if (strncmp(data, "COPY", indx) == 0 ||
			    strncmp(data, "HEAD", indx) == 0 ||
			    strncmp(data, "LOCK", indx) == 0 ||
			    strncmp(data, "MOVE", indx) == 0 ||
			    strncmp(data, "POLL", indx) == 0 ||
			    strncmp(data, "POST", indx) == 0) {
				*type = HTTP_REQUEST;
				isHttpRequestOrReply = TRUE;
			}
			break;

		case 5:
			if (strncmp(data, "BCOPY", indx) == 0 ||
				strncmp(data, "BMOVE", indx) == 0 ||
				strncmp(data, "MKCOL", indx) == 0 ||
				strncmp(data, "TRACE", indx) == 0 ||
				strncmp(data, "LABEL", indx) == 0 ||  /* RFC 3253 8.2 */
				strncmp(data, "MERGE", indx) == 0) {  /* RFC 3253 11.2 */
				*type = HTTP_REQUEST;
				isHttpRequestOrReply = TRUE;
			}
			break;

		case 6:
			if (strncmp(data, "DELETE", indx) == 0 ||
				strncmp(data, "SEARCH", indx) == 0 ||
				strncmp(data, "UNLOCK", indx) == 0 ||
				strncmp(data, "REPORT", indx) == 0 ||  /* RFC 3253 3.6 */
				strncmp(data, "UPDATE", indx) == 0) {  /* RFC 3253 7.1 */
				*type = HTTP_REQUEST;
				isHttpRequestOrReply = TRUE;
			}
			else if (strncmp(data, "NOTIFY", indx) == 0) {
				*type = HTTP_NOTIFICATION;
				isHttpRequestOrReply = TRUE;
			}
			break;

		case 7:
			if (strncmp(data, "BDELETE", indx) == 0 ||
			    strncmp(data, "CONNECT", indx) == 0 ||
			    strncmp(data, "OPTIONS", indx) == 0 ||
			    strncmp(data, "CHECKIN", indx) == 0) {  /* RFC 3253 4.4, 9.4 */
				*type = HTTP_REQUEST;
				isHttpRequestOrReply = TRUE;
			}
			break;

		case 8:
			if (strncmp(data, "PROPFIND", indx) == 0 ||
			    strncmp(data, "CHECKOUT", indx) == 0 || /* RFC 3253 4.3, 9.3 */
			    strncmp(data, "CCM_POST", indx) == 0) {
				*type = HTTP_REQUEST;
				isHttpRequestOrReply = TRUE;
			}
			break;

		case 9:
			if (strncmp(data, "SUBSCRIBE", indx) == 0) {
				*type = HTTP_NOTIFICATION;
				isHttpRequestOrReply = TRUE;
			} else if (strncmp(data, "PROPPATCH", indx) == 0 ||
			    strncmp(data, "BPROPFIND", indx) == 0) {
				*type = HTTP_REQUEST;
				isHttpRequestOrReply = TRUE;
			}
			break;

		case 10:
			if (strncmp(data, "BPROPPATCH", indx) == 0 ||
				strncmp(data, "UNCHECKOUT", indx) == 0 ||  /* RFC 3253 4.5 */
				strncmp(data, "MKACTIVITY", indx) == 0) {  /* RFC 3253 13.5 */
				*type = HTTP_REQUEST;
				isHttpRequestOrReply = TRUE;
			}
			break;

		case 11:
			if (strncmp(data, "MKWORKSPACE", indx) == 0 || /* RFC 3253 6.3 */
			    strncmp(data, "RPC_CONNECT", indx) == 0 || /* [MS-RPCH] 2.1.1.1.1 */
			    strncmp(data, "RPC_IN_DATA", indx) == 0) { /* [MS-RPCH] 2.1.2.1.1 */
				*type = HTTP_REQUEST;
				isHttpRequestOrReply = TRUE;
			} else if (strncmp(data, "UNSUBSCRIBE", indx) == 0) {
				*type = HTTP_NOTIFICATION;
				isHttpRequestOrReply = TRUE;
			}
			break;

		case 12:
			if (strncmp(data, "RPC_OUT_DATA", indx) == 0) { /* [MS-RPCH] 2.1.2.1.2 */
				*type = HTTP_REQUEST;
				isHttpRequestOrReply = TRUE;
			}
			break;

		case 15:
			if (strncmp(data, "VERSION-CONTROL", indx) == 0) {  /* RFC 3253 3.5 */
				*type = HTTP_REQUEST;
				isHttpRequestOrReply = TRUE;
			}
			break;

		case 16:
			if (strncmp(data, "BASELINE-CONTROL", indx) == 0) {  /* RFC 3253 12.6 */
				*type = HTTP_REQUEST;
				isHttpRequestOrReply = TRUE;
			}
			break;

		default:
			break;
		}

		if (isHttpRequestOrReply && reqresp_dissector) {
			*reqresp_dissector = basic_request_dissector;

			stat_info->request_method = wmem_strndup(wmem_packet_scope(), data, indx);
			conv_data->request_method = wmem_strndup(wmem_file_scope(), data, indx);
		}



	}

	return isHttpRequestOrReply;
}

/*
 * Process headers.
 */
typedef struct {
	const char	*name;
	gint		*hf;
	int		special;
} header_info;

#define HDR_NO_SPECIAL		0
#define HDR_AUTHORIZATION	1
#define HDR_AUTHENTICATE	2
#define HDR_CONTENT_TYPE	3
#define HDR_CONTENT_LENGTH	4
#define HDR_CONTENT_ENCODING	5
#define HDR_TRANSFER_ENCODING	6
#define HDR_HOST		7
#define HDR_UPGRADE		8
#define HDR_COOKIE		9

static const header_info headers[] = {
	{ "Authorization", &hf_http_authorization, HDR_AUTHORIZATION },
	{ "Proxy-Authorization", &hf_http_proxy_authorization, HDR_AUTHORIZATION },
	{ "Proxy-Authenticate", &hf_http_proxy_authenticate, HDR_AUTHENTICATE },
	{ "WWW-Authenticate", &hf_http_www_authenticate, HDR_AUTHENTICATE },
	{ "Content-Type", &hf_http_content_type, HDR_CONTENT_TYPE },
	{ "Content-Length", &hf_http_content_length_header, HDR_CONTENT_LENGTH },
	{ "Content-Encoding", &hf_http_content_encoding, HDR_CONTENT_ENCODING },
	{ "Transfer-Encoding", &hf_http_transfer_encoding, HDR_TRANSFER_ENCODING },
	{ "Upgrade", &hf_http_upgrade, HDR_UPGRADE },
	{ "User-Agent",	&hf_http_user_agent, HDR_NO_SPECIAL },
	{ "Host", &hf_http_host, HDR_HOST },
	{ "Connection", &hf_http_connection, HDR_NO_SPECIAL },
	{ "Cookie", &hf_http_cookie, HDR_COOKIE },
	{ "Accept", &hf_http_accept, HDR_NO_SPECIAL },
	{ "Referer", &hf_http_referer, HDR_NO_SPECIAL },
	{ "Accept-Language", &hf_http_accept_language, HDR_NO_SPECIAL },
	{ "Accept-Encoding", &hf_http_accept_encoding, HDR_NO_SPECIAL },
	{ "Date", &hf_http_date, HDR_NO_SPECIAL },
	{ "Cache-Control", &hf_http_cache_control, HDR_NO_SPECIAL },
	{ "Server", &hf_http_server, HDR_NO_SPECIAL },
	{ "Location", &hf_http_location, HDR_NO_SPECIAL },
	{ "Sec-WebSocket-Accept", &hf_http_sec_websocket_accept, HDR_NO_SPECIAL },
	{ "Sec-WebSocket-Extensions", &hf_http_sec_websocket_extensions, HDR_NO_SPECIAL },
	{ "Sec-WebSocket-Key", &hf_http_sec_websocket_key, HDR_NO_SPECIAL },
	{ "Sec-WebSocket-Protocol", &hf_http_sec_websocket_protocol, HDR_NO_SPECIAL },
	{ "Sec-WebSocket-Version", &hf_http_sec_websocket_version, HDR_NO_SPECIAL },
	{ "Set-Cookie", &hf_http_set_cookie, HDR_NO_SPECIAL },
	{ "Last-Modified", &hf_http_last_modified, HDR_NO_SPECIAL },
	{ "X-Forwarded-For", &hf_http_x_forwarded_for, HDR_NO_SPECIAL },
};

/*
 *
 */
static gint*
get_hf_for_header(char* header_name)
{
	gint* hf_id = NULL;

	if (header_fields_hash) {
		hf_id = (gint*) g_hash_table_lookup(header_fields_hash, header_name);
	} else {
		hf_id = NULL;
	}

	return hf_id;
}

/*
 *
 */
static void
header_fields_initialize_cb(void)
{
	static hf_register_info* hf;
	gint* hf_id;
	guint i;
	gchar* header_name;

	if (header_fields_hash && hf) {
		guint hf_size = g_hash_table_size (header_fields_hash);
		/* Unregister all fields */
		for (i = 0; i < hf_size; i++) {
			proto_unregister_field (proto_http, *(hf[i].p_id));

			g_free (hf[i].p_id);
			g_free ((char *) hf[i].hfinfo.name);
			g_free ((char *) hf[i].hfinfo.abbrev);
			g_free ((char *) hf[i].hfinfo.blurb);
		}
		g_hash_table_destroy (header_fields_hash);
		g_free (hf);
		header_fields_hash = NULL;
	}

	if (num_header_fields) {
		header_fields_hash = g_hash_table_new(g_str_hash, g_str_equal);
		hf = g_new0(hf_register_info, num_header_fields);

		for (i = 0; i < num_header_fields; i++) {
			hf_id = g_new(gint,1);
			*hf_id = -1;
			header_name = g_strdup(header_fields[i].header_name);

			hf[i].p_id = hf_id;
			hf[i].hfinfo.name = header_name;
			hf[i].hfinfo.abbrev = g_strdup_printf("http.header.%s", header_name);
			hf[i].hfinfo.type = FT_STRING;
			hf[i].hfinfo.display = BASE_NONE;
			hf[i].hfinfo.strings = NULL;
			hf[i].hfinfo.blurb = g_strdup(header_fields[i].header_desc);
			hf[i].hfinfo.same_name_prev_id = -1;
			hf[i].hfinfo.same_name_next = NULL;

			g_hash_table_insert(header_fields_hash, header_name, hf_id);
		}

		proto_register_field_array(proto_http, hf, num_header_fields);
	}
}

static void
process_header(tvbuff_t *tvb, int offset, int next_offset,
	       const guchar *line, int linelen, int colon_offset,
	       packet_info *pinfo, proto_tree *tree, headers_t *eh_ptr,
	       http_conv_t *conv_data, int http_type)
{
	int len;
	int line_end_offset;
	int header_len;
	gint hf_index;
	guchar c;
	int value_offset;
	int value_len;
	char *value;
	char *header_name;
	char *p;
	guchar *up;
	proto_item *hdr_item, *it;
	int i;
	int* hf_id;

	len = next_offset - offset;
	line_end_offset = offset + linelen;
	header_len = colon_offset - offset;
	header_name = wmem_strndup(wmem_file_scope(), &line[0], header_len);
	hf_index = find_header_hf_value(tvb, offset, header_len);

	/*
	 * Skip whitespace after the colon.
	 */
	value_offset = colon_offset + 1;
	while (value_offset < line_end_offset
			&& ((c = line[value_offset - offset]) == ' ' || c == '\t'))
		value_offset++;

	/*
	 * Fetch the value.
	 *
	 * XXX - the line may well have a NUL in it.  Wireshark should
	 * really treat strings extracted from packets as counted
	 * strings, so that NUL isn't any different from any other
	 * character.  For now, we just allocate a buffer that's
	 * value_len+1 bytes long, copy value_len bytes, and stick
	 * in a NUL terminator, so that the buffer for value actually
	 * has value_len bytes in it.
	 */
	value_len = line_end_offset - value_offset;
	value = (char *)wmem_alloc(wmem_packet_scope(), value_len+1);
	memcpy(value, &line[value_offset - offset], value_len);
	value[value_len] = '\0';

	if (hf_index == -1) {
		/*
		 * Not a header we know anything about.
		 * Check if a HF generated from UAT information exists.
		 */
		hf_id = get_hf_for_header(header_name);

		if (tree) {
			if (!hf_id) {
				if (http_type == HTTP_REQUEST ||
					http_type == HTTP_RESPONSE) {
					it = proto_tree_add_item(tree,
						http_type == HTTP_RESPONSE ?
						hf_http_response_line :
						hf_http_request_line,
						tvb, offset, len,
						ENC_NA|ENC_ASCII);
					proto_item_set_text(it, "%s",
							format_text(line, len));
				} else {
					proto_tree_add_text(tree, tvb, offset,
						len, "%s", format_text(line, len));
				}

			} else {
				proto_tree_add_string_format(tree,
					*hf_id, tvb, offset, len,
					value, "%s", format_text(line, len));
				if (http_type == HTTP_REQUEST ||
					http_type == HTTP_RESPONSE) {
					it = proto_tree_add_item(tree,
						http_type == HTTP_RESPONSE ?
						hf_http_response_line :
						hf_http_request_line,
						tvb, offset, len,
						ENC_NA|ENC_ASCII);
					proto_item_set_text(it, "%s",
							format_text(line, len));
					PROTO_ITEM_SET_HIDDEN(it);
				}
			}
		}
	} else {
		/*
		 * Add it to the protocol tree as a particular field,
		 * but display the line as is.
		 */
		if (tree) {
			header_field_info *hfinfo;
			guint32 tmp;

			hfinfo = proto_registrar_get_nth(*headers[hf_index].hf);
			switch(hfinfo->type){
			case FT_UINT8:
			case FT_UINT16:
			case FT_UINT24:
			case FT_UINT32:
			case FT_INT8:
			case FT_INT16:
			case FT_INT24:
			case FT_INT32:
				tmp=(guint32)strtol(value, NULL, 10);
				hdr_item = proto_tree_add_uint(tree, *headers[hf_index].hf, tvb, offset, len, tmp);
				if (http_type == HTTP_REQUEST ||
					http_type == HTTP_RESPONSE) {
					it = proto_tree_add_item(tree,
						http_type == HTTP_RESPONSE ?
						hf_http_response_line :
						hf_http_request_line,
						tvb, offset, len,
						ENC_NA|ENC_ASCII);
					proto_item_set_text(it, "%d", tmp);
					PROTO_ITEM_SET_HIDDEN(it);
				}
				break;
			default:
				hdr_item = proto_tree_add_string_format(tree,
				    *headers[hf_index].hf, tvb, offset, len,
				    value, "%s", format_text(line, len));
				if (http_type == HTTP_REQUEST ||
					http_type == HTTP_RESPONSE) {
					it = proto_tree_add_item(tree,
						http_type == HTTP_RESPONSE ?
						hf_http_response_line :
						hf_http_request_line,
						tvb, offset, len,
						ENC_NA|ENC_ASCII);
					proto_item_set_text(it, "%s",
							format_text(line, len));
					PROTO_ITEM_SET_HIDDEN(it);
				}
			}
		} else
			hdr_item = NULL;

		/*
		 * Do any special processing that particular headers
		 * require.
		 */
		switch (headers[hf_index].special) {

		case HDR_AUTHORIZATION:
			if (check_auth_ntlmssp(hdr_item, tvb, pinfo, value))
				break;	/* dissected NTLMSSP */
			if (check_auth_basic(hdr_item, tvb, value))
				break; /* dissected basic auth */
			check_auth_kerberos(hdr_item, tvb, pinfo, value);
			break;

		case HDR_AUTHENTICATE:
			if (check_auth_ntlmssp(hdr_item, tvb, pinfo, value))
				break; /* dissected NTLMSSP */
			check_auth_kerberos(hdr_item, tvb, pinfo, value);
			break;

		case HDR_CONTENT_TYPE:
			eh_ptr->content_type = (gchar*) wmem_memdup(wmem_packet_scope(), (guint8*)value,value_len + 1);

			for (i = 0; i < value_len; i++) {
				c = value[i];
				if (c == ';' || g_ascii_isspace(c)) {
					/*
					 * End of subtype - either
					 * white space or a ";"
					 * separating the subtype from
					 * a parameter.
					 */
					break;
				}

				/*
				 * Map the character to lower case;
				 * content types are case-insensitive.
				 */
				eh_ptr->content_type[i] = g_ascii_tolower(eh_ptr->content_type[i]);
			}
			eh_ptr->content_type[i] = '\0';
			/*
			 * Now find the start of the optional parameters;
			 * skip the optional white space and the semicolon
			 * if this has not been done before.
			 */
			i++;
			while (i < value_len) {
				c = eh_ptr->content_type[i];
				if (c == ';' || g_ascii_isspace(c))
					/* Skip till start of parameters */
					i++;
				else
					break;
			}
			if (i < value_len)
				eh_ptr->content_type_parameters = eh_ptr->content_type + i;
			else
				eh_ptr->content_type_parameters = NULL;
			break;

		case HDR_CONTENT_LENGTH:
			errno = 0;
			eh_ptr->content_length = g_ascii_strtoll(value, &p, 10);
			up = (guchar *)p;
			if (eh_ptr->content_length < 0 ||
			    p == value ||
			    errno == ERANGE ||
			    (*up != '\0' && !isspace(*up))) {
				/*
				 * Content length not valid; pretend
				 * we don't have it.
				 */
				eh_ptr->have_content_length = FALSE;
			} else {
				proto_tree *header_tree;
				proto_item *tree_item;
				/*
				 * We do have a valid content length.
				 */
				eh_ptr->have_content_length = TRUE;
				header_tree = proto_item_add_subtree(hdr_item, ett_http_header_item);
				tree_item = proto_tree_add_uint64(header_tree, hf_http_content_length,
					tvb, offset, len, eh_ptr->content_length);
				PROTO_ITEM_SET_GENERATED(tree_item);
				if (eh_ptr->transfer_encoding != NULL &&
						g_ascii_strncasecmp(eh_ptr->transfer_encoding, "chunked", 7) == 0) {
					expert_add_info(pinfo, hdr_item, &ei_http_chunked_and_length);
				}
			}
			break;

		case HDR_CONTENT_ENCODING:
			eh_ptr->content_encoding = wmem_strndup(wmem_packet_scope(), value, value_len);
			break;

		case HDR_TRANSFER_ENCODING:
			eh_ptr->transfer_encoding = wmem_strndup(wmem_packet_scope(), value, value_len);
			if (eh_ptr->have_content_length &&
					g_ascii_strncasecmp(eh_ptr->transfer_encoding, "chunked", 7) == 0) {
				expert_add_info(pinfo, hdr_item, &ei_http_chunked_and_length);
			}
			break;

		case HDR_HOST:
			stat_info->http_host = wmem_strndup(wmem_packet_scope(), value, value_len);
			conv_data->http_host = wmem_strndup(wmem_file_scope(), value, value_len);
			break;

		case HDR_UPGRADE:
			if (g_ascii_strncasecmp(value, "WebSocket", value_len) == 0){
				eh_ptr->upgrade = UPGRADE_WEBSOCKET;
			}
			/* Check if upgrade is HTTP 2.0 (Start with h2...) */
			if ( (g_str_has_prefix(value, "h2")) == 1){
				eh_ptr->upgrade = UPGRADE_HTTP2;
			}
			break;

		case HDR_COOKIE:
			if (hdr_item) {
				proto_tree *cookie_tree;
				char *part, *part_end;
				int part_len;

				cookie_tree = proto_item_add_subtree(hdr_item, ett_http_header_item);
				for (i = 0; i < value_len; ) {
					/* skip whitespace and ';' (terminates at '\0' or earlier) */
					c = value[i];
					while (c == ';' || g_ascii_isspace(c))
						c = value[++i];

					if (i >= value_len)
						break;

					/* find "cookie=foo " in "cookie=foo ; bar" */
					part = value + i;
					part_end = (char *)memchr(part, ';', value_len - i);
					if (part_end)
						part_len =(int)(part_end - part);
					else
						part_len = value_len - i;

					/* finally add cookie to tree */
					proto_tree_add_item(cookie_tree, hf_http_cookie_pair,
						tvb, value_offset + i, part_len, ENC_NA|ENC_ASCII);
					i += part_len;
				}
			}
			break;

		}
	}
}

/* Returns index of header tag in headers */
static gint
find_header_hf_value(tvbuff_t *tvb, int offset, guint header_len)
{
	guint i;

	for (i = 0; i < array_length(headers); i++) {
		if (header_len == strlen(headers[i].name) &&
			tvb_strncaseeql(tvb, offset,
				    headers[i].name, header_len) == 0)
			return i;
	}

	return -1;
}

/*
 * Dissect Microsoft's abomination called NTLMSSP over HTTP.
 */
static gboolean
check_auth_ntlmssp(proto_item *hdr_item, tvbuff_t *tvb, packet_info *pinfo, gchar *value)
{
	static const char *ntlm_headers[] = {
		"NTLM ",
		"Negotiate ",
		NULL
	};
	const char **header;
	size_t hdrlen;
	proto_tree *hdr_tree;

	/*
	 * Check for NTLM credentials and challenge; those can
	 * occur with WWW-Authenticate.
	 */
	for (header = &ntlm_headers[0]; *header != NULL; header++) {
		hdrlen = strlen(*header);
		if (strncmp(value, *header, hdrlen) == 0) {
			if (hdr_item != NULL) {
				hdr_tree = proto_item_add_subtree(hdr_item,
				    ett_http_ntlmssp);
			} else
				hdr_tree = NULL;
			value += hdrlen;
			dissect_http_ntlmssp(tvb, pinfo, hdr_tree, value);
			return TRUE;
		}
	}
	return FALSE;
}

/*
 * Dissect HTTP Basic authorization.
 */
static gboolean
check_auth_basic(proto_item *hdr_item, tvbuff_t *tvb, gchar *value)
{
	static const char *basic_headers[] = {
		"Basic ",
		NULL
	};
	const char **header;
	size_t hdrlen;
	proto_tree *hdr_tree;

	for (header = &basic_headers[0]; *header != NULL; header++) {
		hdrlen = strlen(*header);
		if (strncmp(value, *header, hdrlen) == 0) {
			if (hdr_item != NULL) {
				hdr_tree = proto_item_add_subtree(hdr_item,
				    ett_http_ntlmssp);
			} else
				hdr_tree = NULL;
			value += hdrlen;

			ws_base64_decode_inplace(value);
			proto_tree_add_string(hdr_tree, hf_http_basic, tvb,
			    0, 0, value);

			return TRUE;
		}
	}
	return FALSE;
}

static gboolean
check_auth_kerberos(proto_item *hdr_item, tvbuff_t *tvb, packet_info *pinfo, const gchar *value)
{
	proto_tree *hdr_tree;

	if (strncmp(value, "Kerberos ", 9) == 0) {
		if (hdr_item != NULL) {
			hdr_tree = proto_item_add_subtree(hdr_item, ett_http_kerberos);
		} else
			hdr_tree = NULL;

		dissect_http_kerberos(tvb, pinfo, hdr_tree, value);
		return TRUE;
	}
	return FALSE;
}

static int
dissect_http(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	http_conv_t	*conv_data;
	int		offset = 0;
	int		len;

	/*
	 * Check if this is proxied connection and if so, hand of dissection to the
	 * payload-dissector.
	 * Response code 200 means "OK" and strncmp() == 0 means the strings match exactly */
	conv_data = get_http_conversation_data(pinfo);
	if(pinfo->fd->num >= conv_data->startframe &&
	   conv_data->response_code == 200 &&
	   conv_data->request_method &&
	   strncmp(conv_data->request_method, "CONNECT", 7) == 0 &&
	   conv_data->request_uri) {
		if(conv_data->startframe == 0 && !pinfo->fd->flags.visited)
			conv_data->startframe = pinfo->fd->num;
		http_payload_subdissector(tvb, tree, pinfo, conv_data, data);
	} else {
		while (tvb_reported_length_remaining(tvb, offset) > 0) {
			if (conv_data->upgrade == UPGRADE_WEBSOCKET && pinfo->fd->num >= conv_data->startframe) {
				call_dissector_only(websocket_handle, tvb_new_subset_remaining(tvb, offset), pinfo, tree, NULL);
				break;
			}
			if (conv_data->upgrade == UPGRADE_HTTP2 && pinfo->fd->num >= conv_data->startframe) {
				call_dissector_only(http2_handle, tvb_new_subset_remaining(tvb, offset), pinfo, tree, NULL);
				break;
			}
			len = dissect_http_message(tvb, offset, pinfo, tree, conv_data);
			if (len == -1)
				break;
			offset += len;

			/*
			 * OK, we've set the Protocol and Info columns for the
			 * first HTTP message; set a fence so that subsequent
			 * HTTP messages don't overwrite the Info column.
			 */
			col_set_fence(pinfo->cinfo, COL_INFO);
		}
	}

	return tvb_length(tvb);
}

static gboolean
dissect_http_heur_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	gint offset = 0, next_offset, linelen;
	conversation_t  *conversation;


	/* Check if we have a line terminated by CRLF
	 * Return the length of the line (not counting the line terminator at
	 * the end), or, if we don't find a line terminator:
	 *
	 *	if "deseg" is true, return -1;
	 */
	linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, TRUE);
	if((linelen == -1)||(linelen == 8)){
		return FALSE;
	}

	/* Check if the line start or ends with the HTTP token */
	if((tvb_strncaseeql(tvb, linelen-8, "HTTP/1.1", 8) == 0)||(tvb_strncaseeql(tvb, 0, "HTTP/1.1", 8) == 0)){
		conversation = find_or_create_conversation(pinfo);
		conversation_set_dissector(conversation,http_handle);
		dissect_http(tvb, pinfo, tree, data);
		return TRUE;
	}

	return FALSE;
}

static void
dissect_http_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	http_conv_t	*conv_data;

	conv_data = get_http_conversation_data(pinfo);
	dissect_http_message(tvb, 0, pinfo, tree, conv_data);
}


static void
range_delete_http_ssl_callback(guint32 port) {
	ssl_dissector_delete(port, "http", TRUE);
}

static void
range_add_http_ssl_callback(guint32 port) {
	ssl_dissector_add(port, "http", TRUE);
}

static void reinit_http(void) {
	dissector_delete_uint_range("tcp.port", http_tcp_range, http_handle);
	g_free(http_tcp_range);
	http_tcp_range = range_copy(global_http_tcp_range);
	dissector_add_uint_range("tcp.port", http_tcp_range, http_handle);

	range_foreach(http_ssl_range, range_delete_http_ssl_callback);
	g_free(http_ssl_range);
	http_ssl_range = range_copy(global_http_ssl_range);
	range_foreach(http_ssl_range, range_add_http_ssl_callback);
}

void
proto_register_http(void)
{
	static hf_register_info hf[] = {
	    { &hf_http_notification,
	      { "Notification",		"http.notification",
		FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		"TRUE if HTTP notification", HFILL }},
	    { &hf_http_response,
	      { "Response",		"http.response",
		FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		"TRUE if HTTP response", HFILL }},
	    { &hf_http_request,
	      { "Request",		"http.request",
		FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		"TRUE if HTTP request", HFILL }},
	    { &hf_http_basic,
	      { "Credentials",		"http.authbasic",
		FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	    { &hf_http_response_line,
	      { "Response line",	"http.response.line",
		FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	    { &hf_http_request_line,
	      { "Request line",		"http.request.line",
		FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	    { &hf_http_request_method,
	      { "Request Method",	"http.request.method",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Request Method", HFILL }},
	    { &hf_http_request_uri,
	      { "Request URI",	"http.request.uri",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Request-URI", HFILL }},
	    { &hf_http_version,
	      { "Request Version",	"http.request.version",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Request HTTP-Version", HFILL }},
	    { &hf_http_request_full_uri,
	      { "Full request URI",	"http.request.full_uri",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"The full requested URI (including host name)", HFILL }},
	    { &hf_http_response_code,
	      { "Status Code",	"http.response.code",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		"HTTP Response Status Code", HFILL }},
		{ &hf_http_response_phrase,
		  { "Response Phrase", "http.response.phrase",
	    FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Response Reason Phrase", HFILL }},
	    { &hf_http_authorization,
	      { "Authorization",	"http.authorization",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Authorization header", HFILL }},
	    { &hf_http_proxy_authenticate,
	      { "Proxy-Authenticate",	"http.proxy_authenticate",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Proxy-Authenticate header", HFILL }},
	    { &hf_http_proxy_authorization,
	      { "Proxy-Authorization",	"http.proxy_authorization",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Proxy-Authorization header", HFILL }},
	    { &hf_http_proxy_connect_host,
	      { "Proxy-Connect-Hostname", "http.proxy_connect_host",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Proxy Connect Hostname", HFILL }},
	    { &hf_http_proxy_connect_port,
	      { "Proxy-Connect-Port",	"http.proxy_connect_port",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		"HTTP Proxy Connect Port", HFILL }},
	    { &hf_http_www_authenticate,
	      { "WWW-Authenticate",	"http.www_authenticate",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP WWW-Authenticate header", HFILL }},
	    { &hf_http_content_type,
	      { "Content-Type",	"http.content_type",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Content-Type header", HFILL }},
	    { &hf_http_content_length_header,
	      { "Content-Length",	"http.content_length_header",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Content-Length header", HFILL }},
	    { &hf_http_content_length,
	      { "Content length",	"http.content_length",
		FT_UINT64, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},
	    { &hf_http_content_encoding,
	      { "Content-Encoding",	"http.content_encoding",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Content-Encoding header", HFILL }},
	    { &hf_http_transfer_encoding,
	      { "Transfer-Encoding",	"http.transfer_encoding",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Transfer-Encoding header", HFILL }},
	    { &hf_http_upgrade,
	      { "Upgrade",	"http.upgrade",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Upgrade header", HFILL }},
	    { &hf_http_user_agent,
	      { "User-Agent",	"http.user_agent",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP User-Agent header", HFILL }},
	    { &hf_http_host,
	      { "Host",	"http.host",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Host", HFILL }},
	    { &hf_http_connection,
	      { "Connection",	"http.connection",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Connection", HFILL }},
	    { &hf_http_cookie,
	      { "Cookie",	"http.cookie",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Cookie", HFILL }},
	    { &hf_http_cookie_pair,
	      { "Cookie pair",	"http.cookie_pair",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"A name/value HTTP cookie pair", HFILL }},
	    { &hf_http_accept,
	      { "Accept",	"http.accept",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Accept", HFILL }},
	    { &hf_http_referer,
	      { "Referer",	"http.referer",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Referer", HFILL }},
	    { &hf_http_accept_language,
	      { "Accept-Language",	"http.accept_language",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Accept Language", HFILL }},
	    { &hf_http_accept_encoding,
	      { "Accept Encoding",	"http.accept_encoding",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Accept Encoding", HFILL }},
	    { &hf_http_date,
	      { "Date",	"http.date",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Date", HFILL }},
	    { &hf_http_cache_control,
	      { "Cache-Control",	"http.cache_control",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Cache Control", HFILL }},
	    { &hf_http_server,
	      { "Server",	"http.server",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Server", HFILL }},
	    { &hf_http_location,
	      { "Location",	"http.location",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Location", HFILL }},
	    { &hf_http_sec_websocket_accept,
	      { "Sec-WebSocket-Accept",	"http.sec_websocket_accept",
		FT_STRING, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},
	    { &hf_http_sec_websocket_extensions,
	      { "Sec-WebSocket-Extensions",	"http.sec_websocket_extensions",
		FT_STRING, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},
	    { &hf_http_sec_websocket_key,
	      { "Sec-WebSocket-Key",	"http.sec_websocket_key",
		FT_STRING, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},
	    { &hf_http_sec_websocket_protocol,
	      { "Sec-WebSocket-Protocol",	"http.sec_websocket_protocol",
		FT_STRING, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},
	    { &hf_http_sec_websocket_version,
	      { "Sec-WebSocket-Version",	"http.sec_websocket_version",
		FT_STRING, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},
	    { &hf_http_set_cookie,
	      { "Set-Cookie",	"http.set_cookie",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Set Cookie", HFILL }},
	    { &hf_http_last_modified,
	      { "Last-Modified",	"http.last_modified",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Last Modified", HFILL }},
	    { &hf_http_x_forwarded_for,
	      { "X-Forwarded-For",	"http.x_forwarded_for",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP X-Forwarded-For", HFILL }},
	    { &hf_http_request_in,
	      { "Request in frame", "http.request_in",
		FT_FRAMENUM, BASE_NONE, NULL, 0,
		"This packet is a response to the packet with this number", HFILL }},
	    { &hf_http_response_in,
	      { "Response in frame","http.response_in",
		FT_FRAMENUM, BASE_NONE, NULL, 0,
		"This packet will be responded in the packet with this number", HFILL }},
	    { &hf_http_next_request_in,
	      { "Next request in frame", "http.next_request_in",
		FT_FRAMENUM, BASE_NONE, NULL, 0,
		"The next HTTP request starts in packet number", HFILL }},
	    { &hf_http_next_response_in,
	      { "Next response in frame","http.next_response_in",
		FT_FRAMENUM, BASE_NONE, NULL, 0,
		"The next HTTP response starts in packet number", HFILL }},
	    { &hf_http_prev_request_in,
	      { "Prev request in frame", "http.prev_request_in",
		FT_FRAMENUM, BASE_NONE, NULL, 0,
		"The previous HTTP request starts in packet number", HFILL }},
	    { &hf_http_prev_response_in,
	      { "Prev response in frame","http.prev_response_in",
		FT_FRAMENUM, BASE_NONE, NULL, 0,
		"The previous HTTP response starts in packet number", HFILL }},
	    { &hf_http_time,
	      { "Time since request", "http.time",
		FT_RELATIVE_TIME, BASE_NONE, NULL, 0,
		"Time since the request was send", HFILL }},
	};
	static gint *ett[] = {
		&ett_http,
		&ett_http_ntlmssp,
		&ett_http_kerberos,
		&ett_http_request,
		&ett_http_chunked_response,
		&ett_http_chunk_data,
		&ett_http_encoded_entity,
		&ett_http_header_item
	};

	static ei_register_info ei[] = {
		{ &ei_http_chat, { "http.chat", PI_SEQUENCE, PI_CHAT, "Formatted text", EXPFILL }},
		{ &ei_http_chunked_and_length, { "http.chunkd_and_length", PI_MALFORMED, PI_WARN, "It is incorrect to specify a content-length header and chunked encoding together.", EXPFILL }},
		{ &ei_http_subdissector_failed, { "http.subdissector_failed", PI_MALFORMED, PI_NOTE, "HTTP body subdissector failed, trying heuristic subdissector", EXPFILL }},
	};

	/* UAT for header fields */
	static uat_field_t custom_header_uat_fields[] = {
		UAT_FLD_CSTRING(header_fields, header_name, "Header name", "HTTP header name"),
		UAT_FLD_CSTRING(header_fields, header_desc, "Field desc", "Description of the value contained in the header"),
		UAT_END_FIELDS
	};

	module_t *http_module;
	expert_module_t* expert_http;
	uat_t* headers_uat;

	proto_http = proto_register_protocol("Hypertext Transfer Protocol",
	    "HTTP", "http");
	proto_register_field_array(proto_http, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_http = expert_register_protocol(proto_http);
	expert_register_field_array(expert_http, ei, array_length(ei));

	http_handle = new_register_dissector("http", dissect_http, proto_http);

	http_module = prefs_register_protocol(proto_http, reinit_http);
	prefs_register_bool_preference(http_module, "desegment_headers",
	    "Reassemble HTTP headers spanning multiple TCP segments",
	    "Whether the HTTP dissector should reassemble headers "
	    "of a request spanning multiple TCP segments. "
		"To use this option, you must also enable "
	"\"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
	    &http_desegment_headers);
	prefs_register_bool_preference(http_module, "desegment_body",
	    "Reassemble HTTP bodies spanning multiple TCP segments",
	    "Whether the HTTP dissector should use the "
	    "\"Content-length:\" value, if present, to reassemble "
	    "the body of a request spanning multiple TCP segments, "
	    "and reassemble chunked data spanning multiple TCP segments. "
		"To use this option, you must also enable "
	"\"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
	    &http_desegment_body);
	prefs_register_bool_preference(http_module, "dechunk_body",
	    "Reassemble chunked transfer-coded bodies",
	    "Whether to reassemble bodies of entities that are transferred "
	    "using the \"Transfer-Encoding: chunked\" method",
	    &http_dechunk_body);
#ifdef HAVE_LIBZ
	prefs_register_bool_preference(http_module, "decompress_body",
	    "Uncompress entity bodies",
	    "Whether to uncompress entity bodies that are compressed "
	    "using \"Content-Encoding: \"",
	    &http_decompress_body);
#endif
	prefs_register_obsolete_preference(http_module, "tcp_alternate_port");

	range_convert_str(&global_http_tcp_range, TCP_DEFAULT_RANGE, 65535);
	http_tcp_range = range_empty();
	prefs_register_range_preference(http_module, "tcp.port", "TCP Ports",
					"TCP Ports range",
					&global_http_tcp_range, 65535);

	range_convert_str(&global_http_ssl_range, SSL_DEFAULT_RANGE, 65535);
	http_ssl_range = range_empty();
	prefs_register_range_preference(http_module, "ssl.port", "SSL/TLS Ports",
					"SSL/TLS Ports range",
					&global_http_ssl_range, 65535);
	/* UAT */
	headers_uat = uat_new("Custom HTTP headers fields Table",
			      sizeof(header_field_t),
			      "custom_http_header_fields",
			      TRUE,
			      &header_fields,
			      &num_header_fields,
			      /* specifies named fields, so affects dissection
			         and the set of named fields */
			      UAT_AFFECTS_DISSECTION|UAT_AFFECTS_FIELDS,
			      NULL,
			      header_fields_copy_cb,
			      header_fields_update_cb,
			      header_fields_free_cb,
			      header_fields_initialize_cb,
			      custom_header_uat_fields
	);

	prefs_register_uat_preference(http_module, "custom_http_header_fields", "Custom HTTP headers fields",
	    "A table to define custom HTTP header for which fields can be setup and used for filtering/data extraction etc.",
	   headers_uat);

	/*
	 * Dissectors shouldn't register themselves in this table;
	 * instead, they should call "http_dissector_add()", and
	 * we'll register the port number they specify as a port
	 * for HTTP, and register them in our subdissector table.
	 *
	 * This only works for protocols such as IPP that run over
	 * HTTP on a specific non-HTTP port.
	 */
	port_subdissector_table = register_dissector_table("http.port",
	    "TCP port for protocols using HTTP", FT_UINT16, BASE_DEC);

	/*
	 * Dissectors can register themselves in this table.
	 * It's just "media_type", not "http.content_type", because
	 * it's an Internet media type, usable by other protocols as well.
	 */
	media_type_subdissector_table =
	    register_dissector_table("media_type",
		"Internet media type", FT_STRING, BASE_NONE);

	/*
	 * Heuristic dissectors SHOULD register themselves in
	 * this table using the standard heur_dissector_add()
	 * function.
	 */
	register_heur_dissector_list("http", &heur_subdissector_list);

	/*
	 * Register for tapping
	 */
	http_tap = register_tap("http"); /* HTTP statistics tap */
	http_eo_tap = register_tap("http_eo"); /* HTTP Export Object tap */
}

/*
 * Called by dissectors for protocols that run atop HTTP/TCP.
 */
void
http_dissector_add(guint32 port, dissector_handle_t handle)
{
	/*
	 * Register ourselves as the handler for that port number
	 * over TCP.
	 */
	dissector_add_uint("tcp.port", port, http_handle);

	/*
	 * And register them in *our* table for that port.
	 */
	dissector_add_uint("http.port", port, handle);
}

void
http_port_add(guint32 port)
{
	/*
	 * Register ourselves as the handler for that port number
	 * over TCP.  We rely on our caller having registered
	 * themselves for the appropriate media type.
	 */
	dissector_add_uint("tcp.port", port, http_handle);
}

void
proto_reg_handoff_http(void)
{
	dissector_handle_t http_udp_handle;

	data_handle = find_dissector("data");
	media_handle = find_dissector("media");
	websocket_handle = find_dissector("websocket");
	http2_handle = find_dissector("http2");
	/*
	 * XXX - is there anything to dissect in the body of an SSDP
	 * request or reply?  I.e., should there be an SSDP dissector?
	 */
	http_udp_handle = create_dissector_handle(dissect_http_udp, proto_http);
	dissector_add_uint("udp.port", UDP_PORT_SSDP, http_udp_handle);

	ntlmssp_handle = find_dissector("ntlmssp");
	gssapi_handle = find_dissector("gssapi");

	stats_tree_register("http", "http",     "HTTP/Packet Counter",   0, http_stats_tree_packet,      http_stats_tree_init, NULL );
	stats_tree_register("http", "http_req", "HTTP/Requests",         0, http_req_stats_tree_packet,  http_req_stats_tree_init, NULL );
	stats_tree_register("http", "http_srv", "HTTP/Load Distribution",0, http_reqs_stats_tree_packet, http_reqs_stats_tree_init, NULL );

}

/*
 * Content-Type: message/http
 */

static gint proto_message_http = -1;
static gint ett_message_http = -1;

static void
dissect_message_http(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*subtree;
	proto_item	*ti;
	gint		offset = 0, next_offset;
	gint		len;

	col_append_str(pinfo->cinfo, COL_INFO, " (message/http)");
	if (tree) {
		ti = proto_tree_add_item(tree, proto_message_http,
				tvb, 0, -1, ENC_NA);
		subtree = proto_item_add_subtree(ti, ett_message_http);
		while (tvb_reported_length_remaining(tvb, offset) > 0) {
			len = tvb_find_line_end(tvb, offset,
					tvb_ensure_length_remaining(tvb, offset),
					&next_offset, FALSE);
			if (len == -1)
				break;
			proto_tree_add_text(subtree, tvb, offset, next_offset - offset,
					"%s", tvb_format_text(tvb, offset, len));
			offset = next_offset;
		}
	}
}

void
proto_register_message_http(void)
{
	static gint *ett[] = {
		&ett_message_http,
	};

	proto_message_http = proto_register_protocol(
			"Media Type: message/http",
			"message/http",
			"message-http"
	);
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_message_http(void)
{
	dissector_handle_t message_http_handle;

	message_http_handle = create_dissector_handle(dissect_message_http,
			proto_message_http);

	dissector_add_string("media_type", "message/http", message_http_handle);

	heur_dissector_add("tcp", dissect_http_heur_tcp, proto_http);


	reinit_http();
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
