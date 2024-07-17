/* packet-http.c
 * Routines for HTTP packet disassembly
 * RFC 1945 (HTTP/1.0)
 * RFC 2616 (HTTP/1.1)
 *
 * Guy Harris <guy@alum.mit.edu>
 *
 * Copyright 2017, Eugene Adell <eugene.adell@gmail.com>
 * Copyright 2004, Jerry Talkington <jtalkington@users.sourceforge.net>
 * Copyright 2002, Tim Potter <tpot@samba.org>
 * Copyright 1999, Andrew Tridgell <tridge@samba.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <errno.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/follow.h>
#include <epan/addr_resolv.h>
#include <epan/uat.h>
#include <epan/charsets.h>
#include <epan/strutil.h>
#include <epan/stats_tree.h>
#include <epan/to_str.h>
#include <epan/req_resp_hdrs.h>
#include <epan/proto_data.h>
#include <epan/export_object.h>
#include <epan/exceptions.h>
#include <epan/show_exception.h>
#include <glib.h>
#include "packet-http.h"
#include "packet-http2.h"
#include "packet-tcp.h"
#include "packet-tls.h"
#include "packet-acdr.h"
#include "packet-media-type.h"

#include <ui/tap-credentials.h>

void proto_register_http(void);
void proto_reg_handoff_http(void);
void proto_register_message_http(void);
void proto_reg_handoff_message_http(void);

static int http_tap;
static int http_eo_tap;
static int http_follow_tap;
static int credentials_tap;

static int proto_http;
static int proto_http2;
static int proto_ssdp;
static int hf_http_notification;
static int hf_http_response;
static int hf_http_request;
static int hf_http_response_line;
static int hf_http_request_line;
static int hf_http_basic;
static int hf_http_citrix;
static int hf_http_citrix_user;
static int hf_http_citrix_domain;
static int hf_http_citrix_passwd;
static int hf_http_citrix_session;
static int hf_http_request_method;
static int hf_http_request_uri;
static int hf_http_request_full_uri;
static int hf_http_request_path;
static int hf_http_request_path_segment;
static int hf_http_request_query;
static int hf_http_request_query_parameter;
static int hf_http_request_version;
static int hf_http_response_version;
static int hf_http_response_code;
static int hf_http_response_code_desc;
static int hf_http_response_phrase;
static int hf_http_authorization;
static int hf_http_proxy_authenticate;
static int hf_http_proxy_authorization;
static int hf_http_proxy_connect_host;
static int hf_http_proxy_connect_port;
static int hf_http_www_authenticate;
static int hf_http_content_type;
static int hf_http_content_length_header;
static int hf_http_content_length;
static int hf_http_content_encoding;
static int hf_http_transfer_encoding;
static int hf_http_upgrade;
static int hf_http_user_agent;
static int hf_http_host;
static int hf_http_range;
static int hf_http_content_range;
static int hf_http_connection;
static int hf_http_cookie;
static int hf_http_cookie_pair;
static int hf_http_accept;
static int hf_http_referer;
static int hf_http_accept_language;
static int hf_http_accept_encoding;
static int hf_http_date;
static int hf_http_cache_control;
static int hf_http_server;
static int hf_http_location;
static int hf_http_sec_websocket_accept;
static int hf_http_sec_websocket_extensions;
static int hf_http_sec_websocket_key;
static int hf_http_sec_websocket_protocol;
static int hf_http_sec_websocket_version;
static int hf_http_set_cookie;
static int hf_http_last_modified;
static int hf_http_x_forwarded_for;
static int hf_http_http2_settings;
static int hf_http_request_in;
static int hf_http_response_in;
/*static int hf_http_next_request_in;
static int hf_http_next_response_in;
static int hf_http_prev_request_in;
static int hf_http_prev_response_in; */
static int hf_http_time;
static int hf_http_chunk_size;
static int hf_http_chunk_data;
static int hf_http_chunk_boundary;
static int hf_http_chunked_trailer_part;
static int hf_http_file_data;
static int hf_http_unknown_header;
static int hf_http_http2_settings_uri;

static int ett_http;
static int ett_http_ntlmssp;
static int ett_http_kerberos;
static int ett_http_request;
static int ett_http_request_uri;
static int ett_http_request_path;
static int ett_http_request_query;
static int ett_http_chunked_response;
static int ett_http_chunk_data;
static int ett_http_encoded_entity;
static int ett_http_header_item;
static int ett_http_http2_settings_item;

static expert_field ei_http_te_and_length;
static expert_field ei_http_te_unknown;
static expert_field ei_http_subdissector_failed;
static expert_field ei_http_tls_port;
static expert_field ei_http_leading_crlf;
static expert_field ei_http_excess_data;
static expert_field ei_http_bad_header_name;
static expert_field ei_http_decompression_failed;
static expert_field ei_http_decompression_disabled;

static dissector_handle_t http_handle;
static dissector_handle_t http_tcp_handle;
static dissector_handle_t http_tls_handle;
static dissector_handle_t http_sctp_handle;

static dissector_handle_t media_handle;
static dissector_handle_t http2_handle;
static dissector_handle_t sstp_handle;
static dissector_handle_t ntlmssp_handle;
static dissector_handle_t gssapi_handle;

/* RFC 3986 Ch 2.2 Reserved characters*/
/* patterns used for tvb_ws_mempbrk_pattern_guint8 */
static ws_mempbrk_pattern pbrk_gen_delims;
static ws_mempbrk_pattern pbrk_sub_delims;

/* reassembly table for streaming chunk mode */
static reassembly_table http_streaming_reassembly_table;

REASSEMBLE_ITEMS_DEFINE(http_body, "HTTP Chunked Body");

/* HTTP chunk virtual frame number (similar to HTTP2 frame num) */
#define get_http_chunk_frame_num  get_virtual_frame_num64

/* Stuff for generation/handling of fields for custom HTTP headers */
typedef struct _header_field_t {
	char* header_name;
	char* header_desc;
} header_field_t;

static header_field_t* header_fields;
static unsigned num_header_fields;

static GHashTable* header_fields_hash;
static hf_register_info* dynamic_hf;
static unsigned dynamic_hf_size;

static bool
header_fields_update_cb(void *r, char **err)
{
	header_field_t *rec = (header_field_t *)r;
	char c;

	if (rec->header_name == NULL) {
		*err = g_strdup("Header name can't be empty");
		return false;
	}

	g_strstrip(rec->header_name);
	if (rec->header_name[0] == 0) {
		*err = g_strdup("Header name can't be empty");
		return false;
	}

	/* Check for invalid characters (to avoid asserting out when
	 * registering the field).
	 */
	c = proto_check_field_name(rec->header_name);
	if (c) {
		*err = ws_strdup_printf("Header name can't contain '%c'", c);
		return false;
	}

	*err = NULL;
	return true;
}

static void *
header_fields_copy_cb(void* n, const void* o, size_t siz _U_)
{
	header_field_t* new_rec = (header_field_t*)n;
	const header_field_t* old_rec = (const header_field_t*)o;

	new_rec->header_name = g_strdup(old_rec->header_name);
	new_rec->header_desc = g_strdup(old_rec->header_desc);

	return new_rec;
}

static void
header_fields_free_cb(void*r)
{
	header_field_t* rec = (header_field_t*)r;

	g_free(rec->header_name);
	g_free(rec->header_desc);
}

UAT_CSTRING_CB_DEF(header_fields, header_name, header_field_t)
UAT_CSTRING_CB_DEF(header_fields, header_desc, header_field_t)

/*
 * desegmentation of HTTP headers
 * (when we are over TCP or another protocol providing the desegmentation API)
 */
static bool http_desegment_headers = true;

/*
 * desegmentation of HTTP bodies
 * (when we are over TCP or another protocol providing the desegmentation API)
 * TODO let the user filter on content-type the bodies he wants desegmented
 */
static bool http_desegment_body = true;

/*
 * De-chunking of content-encoding: chunk entity bodies.
 */
static bool http_dechunk_body = true;

/*
 * Decompression of zlib or brotli encoded entities.
 */
#if defined(HAVE_ZLIB)|| defined(HAVE_ZLIBNG) || defined(HAVE_BROTLI)
static bool http_decompress_body = true;
#endif

/*
 * Extra checks for valid ASCII data in HTTP headers.
 */
static bool http_check_ascii_headers = false;

/* Simple Service Discovery Protocol
 * SSDP is implemented atop HTTP (yes, it really *does* run over UDP).
 * SSDP is the discovery protocol of Universal Plug and Play
 * UPnP   http://www.upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.1.pdf
 */
#define TCP_PORT_SSDP			1900
#define UDP_PORT_SSDP			1900

/*
 * TCP and TLS ports
 *
 * 2710 is the XBT BitTorrent tracker
 */

#define TCP_DEFAULT_RANGE "80,3128,3132,5985,8080,8088,11371,1900,2869,2710"
#define SCTP_DEFAULT_RANGE "80"
#define TLS_DEFAULT_RANGE "443"

static range_t *global_http_tls_range;

static range_t *http_tcp_range;
static range_t *http_sctp_range;
static range_t *http_tls_range;

typedef void (*ReqRespDissector)(packet_info*, tvbuff_t*, proto_tree*, int, const unsigned char*,
				 const unsigned char*, http_conv_t *, http_req_res_t *);

/**
 * Transfer codings from
 * https://www.iana.org/assignments/http-parameters/http-parameters.xhtml#transfer-coding
 * Note: chunked encoding is handled separately.
 */
typedef enum _http_transfer_coding {
	HTTP_TE_NONE,           /* Dummy value for header which is not set */
	/* HTTP_TE_CHUNKED, */
	HTTP_TE_COMPRESS,
	HTTP_TE_DEFLATE,
	HTTP_TE_GZIP,
	HTTP_TE_IDENTITY,
	HTTP_TE_UNKNOWN,    /* Header was set, but no valid name was found */
} http_transfer_coding;

/*
 * Structure holding information from headers needed by main
 * HTTP dissector code.
 */
typedef struct {
	char	*content_type;
	char	*content_type_parameters;
	bool have_content_length;
	int64_t  content_length;
	char     *content_encoding;
	bool transfer_encoding_chunked;
	http_transfer_coding transfer_encoding;
	char    *upgrade;
} headers_t;

/* request or response streaming reassembly data */
typedef struct {
	/* reassembly information only for request or response with chunked and streaming data */
	streaming_reassembly_info_t* streaming_reassembly_info;
	/* subdissector handler for request or response with chunked and streaming data */
	dissector_handle_t streaming_handle;
	/* message being passed to subdissector if the request or response has chunked and streaming data */
	media_content_info_t* content_info;
	headers_t* main_headers;
} http_streaming_reassembly_data_t;

/* http request or response private data */
typedef struct {
	/* direction of request message */
	int req_fwd_flow;
	/* request or response streaming reassembly data */
	http_streaming_reassembly_data_t* req_streaming_reassembly_data;
	http_streaming_reassembly_data_t* res_streaming_reassembly_data;
} http_req_res_private_data_t;

 typedef struct _request_trans_t {
	uint64_t first_range_num;
	uint32_t req_frame;
	nstime_t abs_time;
	char *request_uri;
} request_trans_t;

 typedef struct _match_trans_t {
	uint32_t req_frame;
	uint32_t resp_frame;
	nstime_t delta_time;
	char *request_uri;
	char *http_host;
} match_trans_t;

static int parse_http_status_code(const unsigned char *line, const unsigned char *lineend);
static int is_http_request_or_reply(packet_info *pinfo, const char *data, int linelen,
				    media_container_type_t *type, ReqRespDissector
				    *reqresp_dissector, http_conv_t *conv_data);
static unsigned chunked_encoding_dissector(tvbuff_t **tvb_ptr, packet_info *pinfo,
					proto_tree *tree, int offset);
static bool valid_header_name(const unsigned char *line, int header_len);
static bool process_header(tvbuff_t *tvb, int offset, int next_offset,
			   const unsigned char *line, int linelen, int colon_offset,
			   packet_info *pinfo, proto_tree *tree,
			   headers_t *eh_ptr, http_conv_t *conv_data,
			   media_container_type_t http_type, wmem_map_t *header_value_map, bool streaming_chunk_mode);
static int find_header_hf_value(tvbuff_t *tvb, int offset, unsigned header_len);
static bool check_auth_ntlmssp(proto_item *hdr_item, tvbuff_t *tvb,
				   packet_info *pinfo, char *value);
static bool check_auth_basic(proto_item *hdr_item, tvbuff_t *tvb,
				 packet_info *pinfo, char *value);
static bool check_auth_digest(proto_item* hdr_item, tvbuff_t* tvb, packet_info* pinfo _U_, char* value, int offset, int len);
static bool check_auth_citrixbasic(proto_item *hdr_item, tvbuff_t *tvb, packet_info *pinfo,
				 char *value, int offset);
static bool check_auth_kerberos(proto_item *hdr_item, tvbuff_t *tvb,
				   packet_info *pinfo, const char *value);

static dissector_table_t port_subdissector_table;
static dissector_table_t media_type_subdissector_table;
static dissector_table_t streaming_content_type_dissector_table;
static dissector_table_t upgrade_subdissector_table;
static heur_dissector_list_t heur_subdissector_list;

static tap_packet_status
http_eo_packet(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_, const void *data, tap_flags_t flags _U_)
{
	export_object_list_t *object_list = (export_object_list_t *)tapdata;
	const http_eo_t *eo_info = (const http_eo_t *)data;
	export_object_entry_t *entry;

	if(eo_info) { /* We have data waiting for us */
		/* These values will be freed when the Export Object window
		 * is closed. */
		entry = g_new(export_object_entry_t, 1);

		entry->pkt_num = pinfo->num;
		/* XXX: Should this remove the port, if any? It's only
	         * for display, so probably not. */
		entry->hostname = g_strdup(eo_info->hostname);
		entry->content_type = g_strdup(eo_info->content_type);
		/* XXX: Should this remove the query portion, if any, from
	         * the path? (Or should that be done in the dissector?) */
		entry->filename = eo_info->filename ? g_path_get_basename(eo_info->filename) : NULL;
		entry->payload_len = tvb_captured_length(eo_info->payload);
		entry->payload_data = (uint8_t *)tvb_memdup(NULL, eo_info->payload, 0, entry->payload_len);

		object_list->add_entry(object_list->gui_data, entry);

		return TAP_PACKET_REDRAW; /* State changed - window should be redrawn */
	} else {
		return TAP_PACKET_DONT_REDRAW; /* State unchanged - no window updates needed */
	}
}

/* --- HTTP Status Codes */
/* Note: The reference for uncommented entries is RFC 2616 */
const value_string vals_http_status_code[] = {
	{ 100, "Continue" },
	{ 101, "Switching Protocols" },
	{ 102, "Processing" },                     /* RFC 2518 */
	{ 103, "Early Hints" },                    /* RFC-ietf-httpbis-early-hints-05 */
	{ 199, "Informational - Others" },

	{ 200, "OK"},
	{ 201, "Created"},
	{ 202, "Accepted"},
	{ 203, "Non-authoritative Information"},
	{ 204, "No Content"},
	{ 205, "Reset Content"},
	{ 206, "Partial Content"},
	{ 207, "Multi-Status"},                    /* RFC 4918 */
	{ 208, "Already Reported"},                /* RFC 5842 */
	{ 226, "IM Used"},                         /* RFC 3229 */
	{ 299, "Success - Others"},

	{ 300, "Multiple Choices"},
	{ 301, "Moved Permanently"},
	{ 302, "Found"},
	{ 303, "See Other"},
	{ 304, "Not Modified"},
	{ 305, "Use Proxy"},
	{ 307, "Temporary Redirect"},
	{ 308, "Permanent Redirect"},              /* RFC 7538 */
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
	{ 421, "Misdirected Request"},             /* RFC 7540 */
	{ 422, "Unprocessable Entity"},            /* RFC 4918 */
	{ 423, "Locked"},                          /* RFC 4918 */
	{ 424, "Failed Dependency"},               /* RFC 4918 */
	{ 425, "Too Early"},                       /* RFC 8470 */
	{ 426, "Upgrade Required"},                /* RFC 2817 */
	{ 428, "Precondition Required"},           /* RFC 6585 */
	{ 429, "Too Many Requests"},               /* RFC 6585 */
	{ 431, "Request Header Fields Too Large"}, /* RFC 6585 */
	{ 451, "Unavailable For Legal Reasons"},   /* RFC 7725 */
	{ 499, "Client Error - Others"},

	{ 500, "Internal Server Error"},
	{ 501, "Not Implemented"},
	{ 502, "Bad Gateway"},
	{ 503, "Service Unavailable"},
	{ 504, "Gateway Time-out"},
	{ 505, "HTTP Version not supported"},
	{ 506, "Variant Also Negotiates"},         /* RFC 2295 */
	{ 507, "Insufficient Storage"},            /* RFC 4918 */
	{ 508, "Loop Detected"},                   /* RFC 5842 */
	{ 510, "Not Extended"},                    /* RFC 2774 */
	{ 511, "Network Authentication Required"}, /* RFC 6585 */
	{ 599, "Server Error - Others"},

	{ 0, 	NULL}
};

static const char* st_str_reqs = "HTTP Requests by Server";
static const char* st_str_reqs_by_srv_addr = "HTTP Requests by Server Address";
static const char* st_str_reqs_by_http_host = "HTTP Requests by HTTP Host";
static const char* st_str_resps_by_srv_addr = "HTTP Responses by Server Address";

static int st_node_reqs = -1;
static int st_node_reqs_by_srv_addr = -1;
static int st_node_reqs_by_http_host = -1;
static int st_node_resps_by_srv_addr = -1;

/* Parse HTTP path sub components RFC3986 Ch 3.3, 3.4 */
void
http_add_path_components_to_tree(tvbuff_t* tvb, packet_info* pinfo _U_, proto_item* item, int offset, int length)
{
	proto_item* ti;
	proto_tree* uri_tree;
	int end_offset, end_path_offset, query_offset, path_len, query_len, parameter_offset;
	end_offset = offset + length;
	/* The Content-Location (and Referer) headers in HTTP 1.1, and the
	 * :path header in HTTP/2 can be an absolute-URI or a partial-URI;
	 * i.e. that they can include a path and a query, but not a fragment.
	 * RFC 7230 2.7 Uniform Request Identifiers, RFC 7231 Appendices C and D,
	 * RFC 7540 8.1.2.3. Request Pseudo-Header Fields
	 * Look for a ? to mark a query.
	 */
	query_offset = tvb_find_guint8(tvb, offset, length, '?');
	end_path_offset = (query_offset == -1) ? end_offset : query_offset;
	parameter_offset = tvb_ws_mempbrk_pattern_guint8(tvb, offset + 1, end_path_offset - offset - 1, &pbrk_sub_delims, NULL);
	if (query_offset == -1 && parameter_offset == -1) {
		/* Nothing interesting, no need to split. */
		return;
	}
	uri_tree = proto_item_add_subtree(item, ett_http_request_uri);
	path_len = end_path_offset - offset;
	proto_tree_add_item(uri_tree, hf_http_request_path, tvb, offset, path_len, ENC_ASCII);
	parameter_offset = tvb_ws_mempbrk_pattern_guint8(tvb, offset + 1, end_path_offset - offset - 1, &pbrk_sub_delims, NULL);
	if (parameter_offset != -1) {
		proto_tree* path_tree = proto_item_add_subtree(item, ett_http_request_path);
		while (offset < end_path_offset) {
			parameter_offset = tvb_ws_mempbrk_pattern_guint8(tvb, offset + 1, end_path_offset - offset - 1, &pbrk_sub_delims, NULL);
			if (parameter_offset == -1) {
				parameter_offset = end_path_offset;
			}
			proto_tree_add_item(path_tree, hf_http_request_path_segment, tvb, offset, parameter_offset - offset, ENC_ASCII);
			offset = parameter_offset + 1;
		}
	}
	if (query_offset == -1) {
		return;
	}
	/* Skip past the delimiter. */
	query_offset++;
	query_len = end_offset - query_offset;
	offset = query_offset;
	ti = proto_tree_add_item(uri_tree, hf_http_request_query, tvb, query_offset, query_len, ENC_ASCII);
	proto_tree *query_tree = proto_item_add_subtree(ti, ett_http_request_query);
	while (offset < end_offset) {
		parameter_offset = tvb_ws_mempbrk_pattern_guint8(tvb, offset + 1, end_offset - offset - 1, &pbrk_sub_delims, NULL);
		if (parameter_offset == -1) {
			parameter_offset = end_offset;
		}
		proto_tree_add_item(query_tree, hf_http_request_query_parameter, tvb, offset, parameter_offset - offset, ENC_ASCII);
		offset = parameter_offset + 1;
	}
}

/* HTTP/Load Distribution stats init function */
static void
http_reqs_stats_tree_init(stats_tree* st)
{
	st_node_reqs = stats_tree_create_node(st, st_str_reqs, 0, STAT_DT_INT, true);
	st_node_reqs_by_srv_addr = stats_tree_create_node(st, st_str_reqs_by_srv_addr, st_node_reqs, STAT_DT_INT, true);
	st_node_reqs_by_http_host = stats_tree_create_node(st, st_str_reqs_by_http_host, st_node_reqs, STAT_DT_INT, true);
	st_node_resps_by_srv_addr = stats_tree_create_node(st, st_str_resps_by_srv_addr, 0, STAT_DT_INT, true);
}

/* HTTP/Load Distribution stats packet function */
static tap_packet_status
http_reqs_stats_tree_packet(stats_tree* st, packet_info* pinfo, epan_dissect_t* edt _U_, const void* p, tap_flags_t flags _U_)
{
	const http_info_value_t* v = (const http_info_value_t*)p;
	int reqs_by_this_host;
	int reqs_by_this_addr;
	int resps_by_this_addr;
	int i = v->response_code;
	char *ip_str;


	if (v->request_method) {
		ip_str = address_to_str(NULL, &pinfo->dst);

		tick_stat_node(st, st_str_reqs, 0, false);
		tick_stat_node(st, st_str_reqs_by_srv_addr, st_node_reqs, true);
		tick_stat_node(st, st_str_reqs_by_http_host, st_node_reqs, true);
		reqs_by_this_addr = tick_stat_node(st, ip_str, st_node_reqs_by_srv_addr, true);

		if (v->http_host) {
			reqs_by_this_host = tick_stat_node(st, v->http_host, st_node_reqs_by_http_host, true);
			tick_stat_node(st, ip_str, reqs_by_this_host, false);

			tick_stat_node(st, v->http_host, reqs_by_this_addr, false);
		}

		wmem_free(NULL, ip_str);

		return TAP_PACKET_REDRAW;

	} else if (i != 0) {
		ip_str = address_to_str(NULL, &pinfo->src);

		tick_stat_node(st, st_str_resps_by_srv_addr, 0, false);
		resps_by_this_addr = tick_stat_node(st, ip_str, st_node_resps_by_srv_addr, true);

		if ( (i>=100)&&(i<400) ) {
			tick_stat_node(st, "OK", resps_by_this_addr, false);
		} else {
			tick_stat_node(st, "Error", resps_by_this_addr, false);
		}

		wmem_free(NULL, ip_str);

		return TAP_PACKET_REDRAW;
	}

	return TAP_PACKET_DONT_REDRAW;
}


static int st_node_requests_by_host = -1;
static const char *st_str_requests_by_host = "HTTP Requests by HTTP Host";

/* HTTP/Requests stats init function */
static void
http_req_stats_tree_init(stats_tree* st)
{
	st_node_requests_by_host = stats_tree_create_node(st, st_str_requests_by_host, 0, STAT_DT_INT, true);
}

/* HTTP/Requests stats packet function */
static tap_packet_status
http_req_stats_tree_packet(stats_tree* st, packet_info* pinfo _U_, epan_dissect_t* edt _U_, const void* p, tap_flags_t flags _U_)
{
	const http_info_value_t* v = (const http_info_value_t*)p;
	int reqs_by_this_host;

	if (v->request_method) {
		tick_stat_node(st, st_str_requests_by_host, 0, false);

		if (v->http_host) {
			reqs_by_this_host = tick_stat_node(st, v->http_host, st_node_requests_by_host, true);

			if (v->request_uri) {
				tick_stat_node(st, v->request_uri, reqs_by_this_host, true);
			}
		}

		return TAP_PACKET_REDRAW;
	}

	return TAP_PACKET_DONT_REDRAW;
}

static const char *st_str_packets = "Total HTTP Packets";
static const char *st_str_requests = "HTTP Request Packets";
static const char *st_str_responses = "HTTP Response Packets";
static const char *st_str_resp_broken = "???: broken";
static const char *st_str_resp_100 = "1xx: Informational";
static const char *st_str_resp_200 = "2xx: Success";
static const char *st_str_resp_300 = "3xx: Redirection";
static const char *st_str_resp_400 = "4xx: Client Error";
static const char *st_str_resp_500 = "5xx: Server Error";
static const char *st_str_other = "Other HTTP Packets";

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
	st_node_packets = stats_tree_create_node(st, st_str_packets, 0, STAT_DT_INT, true);
	st_node_requests = stats_tree_create_pivot(st, st_str_requests, st_node_packets);
	st_node_responses = stats_tree_create_node(st, st_str_responses, st_node_packets, STAT_DT_INT, true);
	st_node_resp_broken = stats_tree_create_node(st, st_str_resp_broken, st_node_responses, STAT_DT_INT, true);
	st_node_resp_100    = stats_tree_create_node(st, st_str_resp_100,    st_node_responses, STAT_DT_INT, true);
	st_node_resp_200    = stats_tree_create_node(st, st_str_resp_200,    st_node_responses, STAT_DT_INT, true);
	st_node_resp_300    = stats_tree_create_node(st, st_str_resp_300,    st_node_responses, STAT_DT_INT, true);
	st_node_resp_400    = stats_tree_create_node(st, st_str_resp_400,    st_node_responses, STAT_DT_INT, true);
	st_node_resp_500    = stats_tree_create_node(st, st_str_resp_500,    st_node_responses, STAT_DT_INT, true);
	st_node_other = stats_tree_create_node(st, st_str_other, st_node_packets, STAT_DT_INT, false);
}

/* HTTP/Packet Counter stats packet function */
static tap_packet_status
http_stats_tree_packet(stats_tree* st, packet_info* pinfo _U_, epan_dissect_t* edt _U_, const void* p, tap_flags_t flags _U_)
{
	const http_info_value_t* v = (const http_info_value_t*)p;
	unsigned i = v->response_code;
	int resp_grp;
	const char *resp_str;
	char str[64];

	tick_stat_node(st, st_str_packets, 0, false);

	if (i) {
		tick_stat_node(st, st_str_responses, st_node_packets, false);

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

		tick_stat_node(st, resp_str, st_node_responses, false);

		snprintf(str, sizeof(str), "%u %s", i,
			   val_to_str(i, vals_http_status_code, "Unknown (%d)"));
		tick_stat_node(st, str, resp_grp, false);
	} else if (v->request_method) {
		stats_tree_tick_pivot(st,st_node_requests,v->request_method);
	} else {
		tick_stat_node(st, st_str_other, st_node_packets, false);
	}

	return TAP_PACKET_REDRAW;
}

/*
Generates a referer tree - a best-effort representation of which web request led to which.

Some challenges:
A user can be forwarded to a single sites from multiple sources. For example,
google.com -> foo.com and bing.com -> foo.com. A URI alone is not unique.

Additionally, if a user has a subsequent request to foo.com -> bar.com, the
full chain could either be:
	google.com -> foo.com -> bar.com, or
	bing.com   -> foo.com -> bar.com,

This indicates that a URI and its referer are not unique. Only a URI and its
full referer chain are unique. However, HTTP requests only contain the URI
and the immediate referer. This means that any attempt at generating a
referer tree is inherently going to be a best-effort approach.

This code assumes that the referer in a request is from the most-recent request
to that referer.

* To maintain readability of the statistics, whenever a site is visited, all
prior referers are 'ticked' as well, so that one can easily see the breakdown.
*/

/* Root node for all referer statistics */
static int st_node_requests_by_referer = -1;
/* Referer statistics root node's text */
static const char *st_str_request_sequences = "HTTP Request Sequences";

/* Mapping of URIs to the most-recently seen node id */
static wmem_map_t* refstats_uri_to_node_id_hash;
/* Mapping of node ids to the node's URI ('name' value) */
static wmem_map_t* refstats_node_id_to_uri_hash;
/* Mapping of node ids to the parent node id */
static wmem_map_t* refstats_node_id_to_parent_node_id_hash;


/* HTTP/Request Sequences stats init function */
static void
http_seq_stats_tree_init(stats_tree* st)
{
	int root_node_id = 0;
	void *root_node_id_p = GINT_TO_POINTER(root_node_id);
	void *node_id_p = NULL;
	char *uri = NULL;

	refstats_node_id_to_parent_node_id_hash = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
	refstats_node_id_to_uri_hash = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
	refstats_uri_to_node_id_hash = wmem_map_new(wmem_file_scope(), wmem_str_hash, g_str_equal);

	/* Add the root node and its mappings */
	st_node_requests_by_referer = stats_tree_create_node(st, st_str_request_sequences, root_node_id, STAT_DT_INT, true);
	node_id_p = GINT_TO_POINTER(st_node_requests_by_referer);
	uri = wmem_strdup(wmem_file_scope(), st_str_request_sequences);

	wmem_map_insert(refstats_uri_to_node_id_hash, uri, node_id_p);
	wmem_map_insert(refstats_node_id_to_uri_hash, node_id_p, uri);
	wmem_map_insert(refstats_node_id_to_parent_node_id_hash, node_id_p, root_node_id_p);
}

static int
http_seq_stats_tick_referer(stats_tree* st, const char* arg_referer_uri)
{
	int root_node_id = st_node_requests_by_referer;
	void *root_node_id_p = GINT_TO_POINTER(st_node_requests_by_referer);
	int referer_node_id;
	void *referer_node_id_p;
	int referer_parent_node_id;
	void *referer_parent_node_id_p;
	char *referer_uri;

	/* Tick the referer's URI */
	/* Does the node exist? */
	if (!wmem_map_lookup_extended(refstats_uri_to_node_id_hash, arg_referer_uri, NULL, &referer_node_id_p)) {
		/* The node for the referer didn't already exist, create the mappings */
		referer_node_id = tick_stat_node(st, arg_referer_uri, root_node_id, true);
		referer_node_id_p = GINT_TO_POINTER(referer_node_id);
		referer_parent_node_id_p = root_node_id_p;

		referer_uri = wmem_strdup(wmem_file_scope(), arg_referer_uri);
		wmem_map_insert(refstats_uri_to_node_id_hash, referer_uri, referer_node_id_p);
		wmem_map_insert(refstats_node_id_to_uri_hash, referer_node_id_p, referer_uri);
		wmem_map_insert(refstats_node_id_to_parent_node_id_hash, referer_node_id_p, referer_parent_node_id_p);
	} else {
		/* The node for the referer already exists, tick it */
		referer_parent_node_id_p = wmem_map_lookup(refstats_node_id_to_parent_node_id_hash, referer_node_id_p);
		referer_parent_node_id = GPOINTER_TO_INT(referer_parent_node_id_p);
		referer_node_id = tick_stat_node(st, arg_referer_uri, referer_parent_node_id, true);
	}
	return referer_node_id;
}

static void
http_seq_stats_tick_request(stats_tree* st, const char* arg_full_uri, int referer_node_id)
{
	void *referer_node_id_p = GINT_TO_POINTER(referer_node_id);
	int node_id;
	void *node_id_p;
	char *uri;

	node_id = tick_stat_node(st, arg_full_uri, referer_node_id, true);
	node_id_p = GINT_TO_POINTER(node_id);

	/* Update the mappings. Even if the URI was already seen, the URI->node mapping may need to be updated */

	/* Is this a new node? */
	uri = (char *) wmem_map_lookup(refstats_node_id_to_uri_hash, node_id_p);
	if (!uri) {
		/* node not found, add mappings for the node and uri */
		uri = wmem_strdup(wmem_file_scope(), arg_full_uri);

		wmem_map_insert(refstats_uri_to_node_id_hash, uri, node_id_p);
		wmem_map_insert(refstats_node_id_to_uri_hash, node_id_p, uri);
		wmem_map_insert(refstats_node_id_to_parent_node_id_hash, node_id_p, referer_node_id_p);
	} else {
		/* We've seen the node id before. Update the URI mapping refer to this node id*/
		wmem_map_insert(refstats_uri_to_node_id_hash, uri, node_id_p);
	}
}

static char*
determine_http_location_target(wmem_allocator_t *scope, const char *base_url, const char * location_url)
{
	/* Resolving a base URI + relative URI to an absolute URI ("Relative Resolution")
	is complicated. Because of that, we take shortcuts that may result in
	inaccurate results, but is also significantly simpler.
	It would be best to use an external library to do this for us.
	For reference, the RFC is located at https://tools.ietf.org/html/rfc3986#section-5.4

	Returns NULL if the resolution fails
	*/
	char *final_target;

	/* base_url must be an absolute URL.*/
	if (strstr(base_url, "://") == NULL){
		return NULL;
	}

	/* Empty Location */
	if (location_url[0] == '\0') {
		final_target = wmem_strdup(scope, base_url);
		return final_target;
	}
	/* Protocol Relative */
	else if (g_str_has_prefix(location_url, "//") ) {
		char *base_scheme = g_uri_parse_scheme(base_url);
		if (base_scheme == NULL) {
			return NULL;
		}
		final_target = wmem_strdup_printf(scope, "%s:%s", base_scheme, location_url);
		g_free(base_scheme);
		return final_target;
	}
	/* Absolute URL*/
	else if (strstr(location_url, "://") != NULL) {
		final_target = wmem_strdup(scope, location_url);
		return final_target;
	}
	/* Relative */
	else {
		char *start_fragment = strstr(base_url, "#");
		char *start_query = NULL;
		char *base_url_no_fragment = NULL;
		char *base_url_no_query = NULL;

		/* Strip off the fragment (which should never be present)*/
		if (start_fragment == NULL) {
			base_url_no_fragment = wmem_strdup(scope, base_url);
		}
		else {
			base_url_no_fragment = wmem_strndup(scope, base_url, start_fragment - base_url);
		}

		/* Strip off the query (Queries are stripped from all relative URIs) */
		start_query = strstr(base_url_no_fragment, "?");
		if (start_query == NULL) {
			base_url_no_query = wmem_strdup(scope, base_url_no_fragment);
		}
		else {
			base_url_no_query = wmem_strndup(scope, base_url_no_fragment, start_query - base_url_no_fragment);
		}

		/* A leading question mark (?) means to replace the old query with the new*/
		if (g_str_has_prefix(location_url, "?")) {
			final_target = wmem_strdup_printf(scope, "%s%s", base_url_no_query, location_url);
			return final_target;
		}
		/* A leading slash means to put the location after the netloc */
		else if (g_str_has_prefix(location_url, "/")) {
			/* We have already tested strstr(base_url) above */
			char *scheme_end;
			char *netloc_end;
			int netloc_length;

			scheme_end = strstr(base_url_no_query, "://") + 3;
			/* The following code was the only way to stop VS dereferencing errors. */
			if (!(*scheme_end)) {
				return NULL;
			}
			netloc_end = strstr(scheme_end, "/");
			if (!(*netloc_end)) {
				return NULL;
			}
			netloc_length = (int) (netloc_end - base_url_no_query);
			final_target = wmem_strdup_printf(scope, "%.*s%s", netloc_length, base_url_no_query, location_url);
			return final_target;
		}
		/* Otherwise, it replaces the last element in the URI */
		else {
			char *scheme_end = strstr(base_url_no_query, "://") + 3;
			char *end_of_path = g_strrstr(scheme_end, "/");

			if (end_of_path != NULL) {
				int base_through_path = (int) (end_of_path - base_url_no_query);
				final_target = wmem_strdup_printf(scope, "%.*s/%s", base_through_path, base_url_no_query, location_url);
			}
			else {
				final_target = wmem_strdup_printf(scope, "%s/%s", base_url_no_query, location_url);
			}

			return final_target;
		}
	}
	return NULL;
}

/* HTTP/Request Sequences stats packet function */
static tap_packet_status
http_seq_stats_tree_packet(stats_tree* st, packet_info* pinfo, epan_dissect_t* edt _U_, const void* p, tap_flags_t flags _U_)
{
	const http_info_value_t* v = (const http_info_value_t*)p;

	/* Track HTTP Redirects */
	if (v->location_target && v->location_base_uri) {
		int referer_node_id;
		int parent_node_id;
		void *parent_node_id_p;
		void *current_node_id_p;
		char *uri = NULL;

		char *absolute_target = determine_http_location_target(pinfo->pool, v->location_base_uri, v->location_target);
		/* absolute_target is NULL if the resolution fails */
		if (absolute_target != NULL) {
			/* We assume the user makes the request to the absolute_target */
			/* Tick the base URI */
			referer_node_id = http_seq_stats_tick_referer(st, v->location_base_uri);

			/* Tick the location header's resolved URI */
			http_seq_stats_tick_request(st, absolute_target, referer_node_id);

			/* Tick all stats nodes above the location */
			current_node_id_p = GINT_TO_POINTER(referer_node_id);
			while (wmem_map_lookup_extended(refstats_node_id_to_parent_node_id_hash, current_node_id_p, NULL, &parent_node_id_p)) {
				parent_node_id = GPOINTER_TO_INT(parent_node_id_p);
				uri = (char *) wmem_map_lookup(refstats_node_id_to_uri_hash, current_node_id_p);
				tick_stat_node(st, uri, parent_node_id, true);
				current_node_id_p = parent_node_id_p;
			}
		}
	}

	/* Track HTTP Requests/Referers */
	if (v->request_method && v->referer_uri && v->full_uri) {
		int referer_node_id;
		int parent_node_id;
		void *parent_node_id_p;
		void *current_node_id_p;
		char *uri = NULL;
		/* Tick the referer's URI */
		referer_node_id = http_seq_stats_tick_referer(st, v->referer_uri);

		/* Tick the request's URI */
		http_seq_stats_tick_request(st, v->full_uri, referer_node_id);

		/* Tick all stats nodes above the referer */
		current_node_id_p = GINT_TO_POINTER(referer_node_id);
		while (wmem_map_lookup_extended(refstats_node_id_to_parent_node_id_hash, current_node_id_p, NULL, &parent_node_id_p)) {
			parent_node_id = GPOINTER_TO_INT(parent_node_id_p);
			uri = (char *) wmem_map_lookup(refstats_node_id_to_uri_hash, current_node_id_p);
			tick_stat_node(st, uri, parent_node_id, true);
			current_node_id_p = parent_node_id_p;
		}
	}
	return TAP_PACKET_DONT_REDRAW;
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
get_http_conversation_data(packet_info *pinfo, conversation_t **conversation)
{
	http_conv_t	*conv_data;

	*conversation = find_or_create_conversation(pinfo);

	/* Retrieve information from conversation
	 * or add it if it isn't there yet
	 */
	conv_data = (http_conv_t *)conversation_get_proto_data(*conversation, proto_http);
	if(!conv_data) {
		/* Setup the conversation structure itself */
		conv_data = wmem_new0(wmem_file_scope(), http_conv_t);
		conv_data->chunk_offsets_fwd = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
		conv_data->chunk_offsets_rev = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
		conv_data->req_list = NULL;
		conv_data->matches_table = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);

		conversation_add_proto_data(*conversation, proto_http,
					    conv_data);
	}

	return conv_data;
}

/**
 * create a new http_req_res_t and add it to the conversation.
 * @return the new allocated object which is already added to the linked list
 */
static http_req_res_t*
push_req_res(http_conv_t *conv_data)
{
	http_req_res_t *req_res = wmem_new0(wmem_file_scope(), http_req_res_t);

	nstime_set_unset(&(req_res->req_ts));
	conv_data->req_res_tail = req_res;
	req_res->private_data = wmem_new0(wmem_file_scope(), http_req_res_private_data_t);

	return req_res;
}

/**
 * push a request frame number and its time stamp to the conversation data.
 */
static http_req_res_t*
push_req(http_conv_t *conv_data, packet_info *pinfo)
{
	/* a request will always create a new http_req_res_t object */
	http_req_res_t *req_res = push_req_res(conv_data);

	req_res->req_framenum = pinfo->num;
	req_res->req_ts = pinfo->abs_ts;

	/* XXX: Using the same proto key for the frame doesn't work well
         * with HTTP 1.1 pipelining, or other situations where more
         * than one request can appear in a frame.
         */
	p_add_proto_data(wmem_file_scope(), pinfo, proto_http, HTTP_PROTO_DATA_REQRES, req_res);

	return req_res;
}

/**
 * push a response frame number to the conversation data.
 */
static http_req_res_t*
push_res(http_conv_t *conv_data, packet_info *pinfo)
{
	/* a response will create a new http_req_res_t object: if no
	   object exists, or if the most recent one is already for
	   a different response. (Exception: If the previous response
	   code was in the Informational 1xx category, then it was
	   an interim response, and this response could be for the same
	   request.) In both cases the corresponding request was not
	   detected/included in the conversation. In all other cases
	   the http_req_res_t object created by the request is
	   used. */
	/* XXX: This finds the only most recent request and doesn't support
         * HTTP 1.1 pipelining. This limitation has been addressed for
	 * HTTP GETS if Range Requests are supported.
         */
	http_req_res_t *req_res = conv_data->req_res_tail;
	if (!req_res || (req_res->res_framenum > 0 && req_res->response_code >= 200)) {
		req_res = push_req_res(conv_data);
	}
	req_res->res_framenum = pinfo->num;
	/* XXX: Using the same proto key for the frame doesn't work well
         * with HTTP 1.1 pipelining, or other situations where more
         * than one request can appear in a frame and multiple outstanding
	 * GET requests. The latter has been addressed with matches_table."
         */
	p_add_proto_data(wmem_file_scope(), pinfo, proto_http, HTTP_PROTO_DATA_REQRES, req_res);

	return req_res;
}

static int
dissect_http_message(tvbuff_t *tvb, int offset, packet_info *pinfo,
		     proto_tree *tree, http_conv_t *conv_data,
		     const char* proto_tag, int proto, bool end_of_stream,
		     const uint32_t* const seq)
{
	proto_tree	*http_tree = NULL;
	proto_item	*ti = NULL;
	proto_item	*hidden_item;
	const unsigned char	*line, *firstline;
	int		next_offset;
	const unsigned char	*linep, *lineend;
	int		orig_offset = offset;
	int		first_linelen, linelen;
	bool	is_request_or_reply, is_tls = false;
	bool	saw_req_resp_or_header;
	media_container_type_t     http_type;
	proto_item	*hdr_item = NULL;
	ReqRespDissector reqresp_dissector;
	proto_tree	*req_tree;
	int		colon_offset;
	headers_t	*headers = NULL;
	int		datalen;
	int		reported_datalen = -1;
	dissector_handle_t handle = NULL;
	bool	dissected = false;
	bool	first_loop = true;
	bool	have_seen_http = false;
	/*unsigned		i;*/
	/*http_info_value_t *si;*/
	http_eo_t       *eo_info;
	heur_dtbl_entry_t *hdtbl_entry;
	int reported_length;
	uint16_t word;
	bool	leading_crlf = false;
	bool	excess_data = false;
	media_content_info_t* content_info = NULL;
	wmem_map_t* header_value_map = NULL;
	int 		chunk_offset = 0;
	wmem_map_t	*chunk_map = NULL;
	/*
	 * For supporting dissecting chunked data in streaming reassembly mode.
	 *
	 * If a HTTP request or response is chunked encoding (the transfer-encoding
	 * header is 'chunked') and its content-type matching a subdissector in
	 * "streaming_content_type" dissector table, then we switch to dissect in
	 * streaming chunk mode. In streaming chunk mode, we dissect the data as soon
	 * as possible, unlike normal mode, we don't start reassembling until the end
	 * of the request or response message or at the end of the TCP stream. In
	 * streaming chunk mode, the first reassembled PDU contains HTTP headers
	 * and at least one completed chunk of this request or response message. And
	 * subsequent PDUs consist of one or more chunks:
	 *
	 * -----             +-- Reassembled Streaming Content PDU(s) --+-- Reassembled Streaming Content PDU(s) --+--- Reassembled ...
	 * HLProtos          |              1*high-proto-pdu            |             1*high-proto-pdu             |   1*high-proto-pdu
	 * -----             +-------------------------------------+----+--------------------------------+---------+-------------------
	 *                   |           de-chunked-data           |            de-chunked-data          |        de-chunked-data
	 * HTTP    +-------- First Reassembled HTTP PDU -----------+--- Second Reassembled HTTP PDU -----+- Third PDU -+  +- Fourth ---
	 *         |            headers and 1*chunk                |               1*chunk               |   1*chunk   |  | 1*chunk ...
	 * -----   +--------- TCP segment ---------+  +-----------TCP segment -----------+  +---- TCP segment ---------+  +------------
	 * TCP     | headers | *chunk | part-chunk |  | part-chunk | *chunk | part-chunk |  | part-chunk |   1*chunk   |  | 1*chunk ...
	 * -----   +---------+--------+------------+  +------------+--------+------------+  +------------+-------------+  +------------
	 *
	 * Notation:
	 * - headers             HTTP headers of a request or response message.
	 * - part-chunk          The front or rear part of a HTTP chunk.
	 * - *chunk              Zero or more completed HTTP chunks of a HTTP message.
	 * - 1*chunk             One or more completed HTTP chunks of a HTTP message.
	 * - de-chunked-data     De-chunked HTTP body data based on one or more completed chunks.
	 * - 1*high-proto-pdu    One or more high level protocol (on top of HTTP) PDUs.
	 * - HLProtos            High Level Protocols like GRPC-Web.
	 *
	 * The headers and content_info of the req_res are allocated in file scope that
	 * helps to provide information for dissecting subsequent PDUs which only
	 * contains chunks without headers.
	 */
	bool streaming_chunk_mode = false;
	bool begin_with_chunk = false;
	http_streaming_reassembly_data_t* streaming_reassembly_data = NULL;

	http_req_res_t  *curr = (http_req_res_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_http, HTTP_PROTO_DATA_REQRES);
	http_info_value_t *stat_info = NULL;
	http_req_res_private_data_t* prv_data = curr ? (http_req_res_private_data_t*)curr->private_data : NULL;
	http_req_res_private_data_t* tail_prv_data = NULL;

	/* Determine the direction as in the TCP dissector, but don't call
	 * get_tcp_conversation_data because we don't want to create a new
	 * TCP stream if it doesn't exist (e.g., SSDP over UDP.)
         */
	int direction = cmp_address(&pinfo->src, &pinfo->dst);
	/* if the addresses are equal, match the ports instead */
	if (direction == 0) {
		direction = (pinfo->srcport > pinfo->destport) ? 1 : -1;
	}
	if (direction >= 0) {
		chunk_map = conv_data->chunk_offsets_fwd;
	} else {
		chunk_map = conv_data->chunk_offsets_rev;
	}

	if (seq && chunk_map) {
		chunk_offset = GPOINTER_TO_INT(wmem_map_lookup(chunk_map, GUINT_TO_POINTER(*seq)));
		/* Returns 0 when there is no entry in the map, as we want. */
	}

	reported_length = tvb_reported_length_remaining(tvb, offset);
	if (reported_length < 1) {
		return -1;
	}

	/* RFC 2616
	 *   In the interest of robustness, servers SHOULD ignore any empty
	 *   line(s) received where a Request-Line is expected. In other words, if
	 *   the server is reading the protocol stream at the beginning of a
	 *   message and receives a CRLF first, it should ignore the CRLF.
	 */
	if (reported_length > 3) {
		word = tvb_get_ntohs(tvb,offset);
		if (word == 0x0d0a) {
			leading_crlf = true;
			offset += 2;
		}
	}

	/*
	 * If we previously dissected an HTTP request in this conversation then
	 * we should be pretty sure that whatever we got in this TVB is
	 * actually HTTP (even if what we have here is part of a file being
	 * transferred over HTTP).
	 */
	if (conv_data->req_res_tail)
		have_seen_http = true;

	/*
	 * If this is binary data then there's no point in doing all the string
	 * operations below: they'll just be slow on this data.
	 */
	if (!g_ascii_isprint(tvb_get_uint8(tvb, offset))) {
		/*
		 * But, if we've seen some real HTTP then we're sure this is
		 * an HTTP conversation, and this is binary file data.
		 * Mark it as such.
		 */
		if (have_seen_http) {
			tvbuff_t *next_tvb;
			int data_len;

			col_set_str(pinfo->cinfo, COL_PROTOCOL, proto_tag);
			col_set_str(pinfo->cinfo, COL_INFO, "Continuation");
			ti = proto_tree_add_item(tree, proto, tvb, offset, -1, ENC_NA);
			http_tree = proto_item_add_subtree(ti, ett_http);

			next_tvb = tvb_new_subset_remaining(tvb, orig_offset);
			/* If orig_offset > 0, this isn't the first message
			 * dissected in this TCP segment, which means we had
			 * a Content-Length, but more data after that body.
			 */
			if (orig_offset > 0) {
				proto_tree_add_expert(http_tree, pinfo, &ei_http_excess_data, next_tvb, 0, tvb_captured_length(next_tvb));
			}
			/* Send it to Follow HTTP Stream and mark as file data */
			if(have_tap_listener(http_follow_tap)) {
				tap_queue_packet(http_follow_tap, pinfo, next_tvb);
			}
			data_len = tvb_captured_length(next_tvb);
			proto_tree_add_bytes_format_value(http_tree, hf_http_file_data,
				next_tvb, 0, data_len, NULL, "%u byte%s", data_len, plurality(data_len, "", "s"));
			call_data_dissector(next_tvb, pinfo, http_tree);
		}
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
	    tvb_ensure_captured_length_remaining(tvb, offset), &next_offset,
	    true);

	if (first_linelen == -1) {
		/* No complete line was found in this segment, do
		 * desegmentation if we're told to.
		 */
		if (!req_resp_hdrs_do_reassembly(tvb, offset, pinfo,
		    http_desegment_headers, http_desegment_body, false, &chunk_offset,
			streaming_content_type_dissector_table, &handle)) {
			/*
			 * More data needed for desegmentation.
			 */
			return -1;
		}
	}

	if (!PINFO_FD_VISITED(pinfo) && conv_data->req_res_tail && conv_data->req_res_tail->private_data) {
		tail_prv_data = (http_req_res_private_data_t*) conv_data->req_res_tail->private_data;
	}

	/* Check whether the first line is the beginning of a chunk. If it is the beginning
	 * of a chunk, the headers and at least one chunk of HTTP request or response should
	 * be dissected in the previous packets, and now we are processing subsequent chunks.
	 */
	if (http_desegment_body && http_dechunk_body) {
		begin_with_chunk = starts_with_chunk_size(tvb, offset, pinfo);

		if (begin_with_chunk &&
			((prv_data && (      /* This packet has been parsed */
				/* and now we are in a HTTP request chunk stream */
				(prv_data->req_fwd_flow == direction && prv_data->req_streaming_reassembly_data) ||
				/* and now we are in a HTTP response chunk stream */
				(prv_data->req_fwd_flow != direction && prv_data->res_streaming_reassembly_data)))
			||
			(tail_prv_data && ( /* This packet has not been parsed and headers info in conv_data->req_res_tail */
				/* and now we are in a HTTP request chunk stream */
				(tail_prv_data->req_fwd_flow == direction && tail_prv_data->req_streaming_reassembly_data) ||
				/* and now we are in a HTTP response chunk stream */
				(tail_prv_data->req_fwd_flow != direction && tail_prv_data->res_streaming_reassembly_data)))))
		{
			streaming_chunk_mode = true;
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
	http_type = MEDIA_CONTAINER_HTTP_OTHERS;	/* type not known yet */
	is_request_or_reply = is_http_request_or_reply(pinfo, (const char *)firstline,
	    first_linelen, &http_type, NULL, conv_data);
	if (is_request_or_reply || streaming_chunk_mode) {
		bool try_desegment_body;

		if (streaming_chunk_mode && begin_with_chunk) {
			col_add_str(pinfo->cinfo, COL_INFO, "Chunk Stream ");
		} else {
			/*
			 * Yes, it's a request or response.
			 * Put the first line from the buffer into the summary
			 * (but leave out the line terminator).
			 */
			col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", format_text(pinfo->pool, firstline, first_linelen));
		}

		/*
		 * Do header desegmentation if we've been told to,
		 * and do body desegmentation if we've been told to and
		 * we find a Content-Length header in requests.
		 *
		 * The following cases (from RFC 7230, Section 3.3) never have a
		 * response body, so do not attempt to desegment the body for:
		 * * Responses to HEAD requests.
		 * * 2xx responses to CONNECT requests.
		 * * 1xx, 204 No Content, 304 Not Modified responses.
		 *
		 * Additionally if we are at the end of stream, no more segments
		 * will be added so disable body segmentation too in that case.
		 */
		try_desegment_body = (http_desegment_body && !end_of_stream);
		if (try_desegment_body && http_type == MEDIA_CONTAINER_HTTP_RESPONSE && !streaming_chunk_mode) {
			/*
			 * The response_code is not yet set, so extract
			 * the response code from the current line.
			 */
			int response_code = parse_http_status_code(firstline, firstline + first_linelen);
			/*
			 * On a second pass, we should have already associated
			 * the response with the request. On a first sequential
			 * pass, we haven't done so yet (as we don't know if we
			 * need more data), so get the request method from the
			 * most recent request, if it exists.
			 */
			char* request_method = NULL;
			if (curr) {
				request_method = curr->request_method;
			} else if (!PINFO_FD_VISITED(pinfo) && conv_data->req_res_tail) {
				request_method = conv_data->req_res_tail->request_method;
			}
			if ((g_strcmp0(request_method, "HEAD") == 0 ||
				(response_code / 100 == 2 &&
					(g_strcmp0(request_method, "CONNECT") == 0 ||
					 g_strcmp0(request_method, "SSTP_DUPLEX_POST") == 0)) ||
				response_code / 100 == 1 ||
				response_code == 204 ||
				response_code == 304)) {
				/* No response body is present. */
				try_desegment_body = false;
			}
		}
		if (!req_resp_hdrs_do_reassembly(tvb, offset, pinfo,
		    http_desegment_headers, try_desegment_body, http_type == MEDIA_CONTAINER_HTTP_RESPONSE, &chunk_offset,
			streaming_content_type_dissector_table, &handle)) {
			/*
			 * More data needed for desegmentation.
			 */
			if (seq && chunk_map && chunk_offset) {
				wmem_map_insert(chunk_map, GUINT_TO_POINTER(*seq), GINT_TO_POINTER(chunk_offset));
			}
			return -1;
		}

		if (handle && http_desegment_body && http_dechunk_body) {
			/* This handle is set because there is a header 'Transfer-Encoding: chunked', and
			 * a streaming mode reassembly supported subdissector is found according to the
			 * header of Content-Type.
			 */
			streaming_chunk_mode = true;
		}
	} else if (have_seen_http) {
		/*
		 * If we know this is HTTP then call it continuation.
		 */
		/* If orig_offset > 0, this isn't the first message dissected
		 * in this segment, which means we had a Content-Length, but
		 * more data after the body. If this isn't a request or reply,
		 * that's bogus, and probably means the Content-Length was
		 * wrong.
		 */
		if (orig_offset > 0) {
			excess_data = true;
		}
		col_set_str(pinfo->cinfo, COL_INFO, "Continuation");
	}

	if (is_request_or_reply || have_seen_http || streaming_chunk_mode) {
		/*
		 * Now set COL_PROTOCOL and create the http tree for the
		 * cases where we set COL_INFO above.
		 */
		col_set_str(pinfo->cinfo, COL_PROTOCOL, proto_tag);
		ti = proto_tree_add_item(tree, proto, tvb, offset, -1, ENC_NA);
		http_tree = proto_item_add_subtree(ti, ett_http);

		if (leading_crlf) {
			proto_tree_add_expert(http_tree, pinfo, &ei_http_leading_crlf, tvb, offset-2, 2);
		}
		if (excess_data) {
			proto_tree_add_expert(http_tree, pinfo, &ei_http_excess_data, tvb, offset, tvb_captured_length_remaining(tvb, offset));
		}
	}

	is_tls = proto_is_frame_protocol(pinfo->layers, "tls");

	if (!PINFO_FD_VISITED(pinfo) && begin_with_chunk
		&& streaming_chunk_mode && conv_data->req_res_tail) {
		/* point this packet beginning with a chunk to req_res info created in previous packet. */
		curr = conv_data->req_res_tail;
		prv_data = (http_req_res_private_data_t*)curr->private_data;
		p_set_proto_data(wmem_file_scope(), pinfo, proto_http, HTTP_PROTO_DATA_REQRES, curr);
	}

	if (prv_data) {
		if (prv_data->req_fwd_flow == direction && prv_data->req_streaming_reassembly_data) {
			/* in request flow */
			streaming_reassembly_data = prv_data->req_streaming_reassembly_data;
		} else if (prv_data->req_fwd_flow != direction && prv_data->res_streaming_reassembly_data) {
			/* in response flow */
			streaming_reassembly_data = prv_data->res_streaming_reassembly_data;
		}

		if (streaming_reassembly_data) {
			streaming_chunk_mode = true;
			headers = streaming_reassembly_data->main_headers;
			handle = streaming_reassembly_data->streaming_handle;
			content_info = streaming_reassembly_data->content_info;
			header_value_map = (wmem_map_t*) content_info->data;
		}
	}

	if (streaming_chunk_mode && begin_with_chunk) {
		datalen = reported_length;
		goto dissecting_body;
	}

	stat_info = wmem_new(pinfo->pool, http_info_value_t);
	stat_info->framenum = pinfo->num;
	stat_info->response_code = 0;
	stat_info->request_method = NULL;
	stat_info->request_uri = NULL;
	stat_info->referer_uri = NULL;
	stat_info->http_host = NULL;
	stat_info->full_uri = NULL;
	stat_info->location_target = NULL;
	stat_info->location_base_uri = NULL;
	p_set_proto_data(pinfo->pool, pinfo, proto_http, HTTP_PROTO_DATA_INFO, (void *)stat_info);

	/*
	 * Process the packet data, a line at a time.
	 */
	http_type = MEDIA_CONTAINER_HTTP_OTHERS;	/* type not known yet */
	if (headers == NULL) {
		DISSECTOR_ASSERT_HINT(!PINFO_FD_VISITED(pinfo) || (PINFO_FD_VISITED(pinfo) && !streaming_chunk_mode),
			"The headers variable should not be NULL if it is in streaming mode during a non first scan.");
		DISSECTOR_ASSERT_HINT(header_value_map == NULL, "The header_value_map variable should be NULL while headers is NULL.");

		headers = wmem_new0((streaming_chunk_mode ? wmem_file_scope() : pinfo->pool), headers_t);
		header_value_map = wmem_map_new((streaming_chunk_mode ? wmem_file_scope() : pinfo->pool), g_str_hash, g_str_equal);
	}

	saw_req_resp_or_header = false;	/* haven't seen anything yet */
	while (tvb_offset_exists(tvb, offset)) {
		/*
		 * Find the end of the line.
		 * XXX - what if we don't find it because the packet
		 * is cut short by a snapshot length or the header is
		 * split across TCP segments?  How much dissection should
		 * we do on it?
		 */
		linelen = tvb_find_line_end(tvb, offset,
		    tvb_ensure_captured_length_remaining(tvb, offset), &next_offset,
		    false);
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
		    is_http_request_or_reply(pinfo, (const char *)line,
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
		colon_offset = offset;

		linep = (const unsigned char *)memchr(line, ':', linelen);
		if (linep) {
			/*
			 * Colon found, assume it is a header if we've seen a
			 * valid line before. Check a little more if not.
			 */
			if (saw_req_resp_or_header || valid_header_name(line, (int)(linep - line))) {
				colon_offset += (int)(linep - line);
				if (http_check_ascii_headers) {
					int i;
					for (i = 0; i < linelen; i++) {
						if (line[i] & 0x80) {
							/*
							 * Non-ASCII! Return -2 for invalid
							 * HTTP, distinct from -1 for possible
							 * reassembly required.
							 */
							return -2;
						}
					}
				}
				goto is_http;
			}
		}

		/*
		 * We haven't seen the colon yet.
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

		/*
		 * We don't consider this part of an HTTP request or
		 * reply, so we don't display it.
		 * (Yeah, that means we don't display, say, a text/http
		 * page, but you can get that from the data pane.)
		 */
		break;

	is_http:
		if ((tree) && (http_tree == NULL)) {
			ti = proto_tree_add_item(tree, proto, tvb, orig_offset, -1, ENC_NA);
			http_tree = proto_item_add_subtree(ti, ett_http);
			if (leading_crlf) {
				proto_tree_add_expert(http_tree, pinfo, &ei_http_leading_crlf, tvb, orig_offset-2, 2);
			}
		}

		if (first_loop && !is_tls && pinfo->ptype == PT_TCP &&
				(pinfo->srcport == 443 || pinfo->destport == 443)) {
			expert_add_info(pinfo, ti, &ei_http_tls_port);
		}

		first_loop = false;

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
		saw_req_resp_or_header = true;
		if (is_request_or_reply) {
			char *text = tvb_format_text(pinfo->pool, tvb, offset, next_offset - offset);

			req_tree = proto_tree_add_subtree(http_tree, tvb,
				    offset, next_offset - offset, ett_http_request, &hdr_item, text);

			if (!PINFO_FD_VISITED(pinfo)) {
				if (http_type == MEDIA_CONTAINER_HTTP_REQUEST) {
					curr = push_req(conv_data, pinfo);
					curr->request_method = wmem_strdup(wmem_file_scope(), stat_info->request_method);
					prv_data = curr->private_data;
					prv_data->req_fwd_flow = direction;
				} else if (http_type == MEDIA_CONTAINER_HTTP_RESPONSE) {
					curr = push_res(conv_data, pinfo);
					prv_data = curr->private_data;
					prv_data->req_fwd_flow = -direction;
				}
			}
			if (reqresp_dissector) {
				reqresp_dissector(pinfo, tvb, req_tree, offset, line,
						  lineend, conv_data, curr);
			}
		} else {
			/*
			 * Header.
			 */
			bool good_header = process_header(tvb, offset, next_offset, line, linelen,
			    colon_offset, pinfo, http_tree, headers, conv_data,
			    http_type, header_value_map, streaming_chunk_mode);
			if (http_check_ascii_headers && !good_header) {
				/*
				 * Line is not a good HTTP header.
				 * Return -2 to mark as invalid HTTP;
				 * this is distinct from returning -1 when
				 * it may be HTTP but in need of reassembly.
				 */
				return -2;
			}
		}
		offset = next_offset;
	}
	if (stat_info->http_host && stat_info->request_uri) {
		char       *uri;

		if ((g_ascii_strncasecmp(stat_info->request_uri, "http://", 7) == 0) ||
		    (g_ascii_strncasecmp(stat_info->request_uri, "https://", 8) == 0) ||
		    (g_ascii_strncasecmp(stat_info->request_method, "CONNECT", 7) == 0)) {
			uri = wmem_strdup(pinfo->pool, stat_info->request_uri);
		}
		else {
			uri = wmem_strdup_printf(pinfo->pool, "%s://%s%s",
				    is_tls ? "https" : "http",
				    g_strstrip(wmem_strdup(pinfo->pool, stat_info->http_host)), stat_info->request_uri);
		}
		stat_info->full_uri = wmem_strdup(pinfo->pool, uri);
		if (!PINFO_FD_VISITED(pinfo) && curr) {
		        curr->full_uri = wmem_strdup(wmem_file_scope(), uri);
		}
	}
	else {
		/* If the request has a range, this is, or potentially is, asynchronous I/O thus
		* full_uri must be reinitialized because it is set to that of the last request. */
		if (curr && curr->req_has_range)
			curr->full_uri = NULL;
	}
	if (tree) {
		proto_item *pi;

		switch (http_type) {

		case MEDIA_CONTAINER_HTTP_NOTIFICATION:
			hidden_item = proto_tree_add_boolean(http_tree,
					    hf_http_notification, tvb, 0, 0, 1);
			proto_item_set_hidden(hidden_item);
			break;

		case MEDIA_CONTAINER_HTTP_RESPONSE:
			hidden_item = proto_tree_add_boolean(http_tree,
					    hf_http_response, tvb, 0, 0, 1);
			proto_item_set_hidden(hidden_item);

			match_trans_t *match_trans = NULL;

			if (curr && curr->response_code == 206 && curr->resp_has_range) {
				/* The conv_data->matches_table is only used for GET requests with ranges and
				*  response_codes of 206 (Partial Content). (Note: only GETs use ranges.)
				*/
				match_trans = (match_trans_t *)wmem_map_lookup(conv_data->matches_table,
								GUINT_TO_POINTER(pinfo->num));
				if (match_trans) {
					pi = proto_tree_add_uint(http_tree, hf_http_request_in, tvb, 0, 0,
									match_trans->req_frame);
					proto_item_set_generated(pi);

					pi = proto_tree_add_time(http_tree, hf_http_time, tvb, 0, 0,
									&match_trans->delta_time);
					proto_item_set_generated(pi);

					pi = proto_tree_add_string(http_tree, hf_http_request_uri, tvb, 0, 0,
									match_trans->request_uri);
					proto_item_set_generated(pi);
					{
					char *uri;
					uri = wmem_strdup_printf(pinfo->pool, "%s://%s%s",
						    is_tls ? "https" : "http",
					g_strstrip(wmem_strdup(pinfo->pool, match_trans->http_host)), match_trans->request_uri);

					pi = proto_tree_add_string(http_tree, hf_http_request_full_uri, tvb, 0, 0,
									uri);
					proto_item_set_url(pi);
					proto_item_set_generated(pi);
					}
				}
			}

			/* If responses don't have a range, the I/O is synchronous in which case a request is
			*  matched with the following response. If a request or response is missing from the
			*  capture file, correct matching resumes at the next request. */
			if(!match_trans
			&& curr
			&& !curr->resp_has_range
			&& curr->req_framenum) {
				pi = proto_tree_add_uint(http_tree, hf_http_request_in, tvb, 0, 0, curr->req_framenum);
				proto_item_set_generated(pi);

				if (! nstime_is_unset(&(curr->req_ts))) {
					nstime_t delta;

					nstime_delta(&delta, &pinfo->abs_ts, &(curr->req_ts));
					pi = proto_tree_add_time(http_tree, hf_http_time, tvb, 0, 0, &delta);
					proto_item_set_generated(pi);
				}
				if (curr->request_uri) {
					pi = proto_tree_add_string(http_tree, hf_http_request_uri, tvb, 0, 0,
									curr->request_uri);
					proto_item_set_generated(pi);
				}
				if (curr->full_uri) {
					pi = proto_tree_add_string(http_tree, hf_http_request_full_uri, tvb, 0, 0,
									curr->full_uri);
					proto_item_set_url(pi);
					proto_item_set_generated(pi);
				}
			}
			break;
		case MEDIA_CONTAINER_HTTP_REQUEST:
			{
			int size = wmem_map_size(conv_data->matches_table);

			hidden_item = proto_tree_add_boolean(http_tree,	hf_http_request, tvb, 0, 0, 1);
			proto_item_set_hidden(hidden_item);

			match_trans = NULL;
			if (curr) {
				if (size > 0 && curr->req_has_range) {
					match_trans = (match_trans_t *)wmem_map_lookup(conv_data->matches_table,
										GUINT_TO_POINTER(pinfo->num));
					if (match_trans) {
						pi = proto_tree_add_uint(http_tree, hf_http_response_in,
										tvb, 0, 0, match_trans->resp_frame);
						proto_item_set_generated(pi);
					}
				}
				else {
					if(!match_trans
					&& !curr->resp_has_range
					&& curr->res_framenum) {
						pi = proto_tree_add_uint(http_tree, hf_http_response_in, tvb, 0, 0, curr->res_framenum);
						proto_item_set_generated(pi);

					}
				}

				if (curr->full_uri) {
					pi = proto_tree_add_string(http_tree, hf_http_request_full_uri, tvb, 0, 0,
									curr->full_uri);
					proto_item_set_url(pi);
					proto_item_set_generated(pi);
				}
				else if (stat_info->full_uri){
					pi = proto_tree_add_string(http_tree, hf_http_request_full_uri, tvb, 0, 0,
									stat_info->full_uri);
					proto_item_set_url(pi);
					proto_item_set_generated(pi);
				}
			}
			}
			break;

		case MEDIA_CONTAINER_HTTP_OTHERS:
		default:
			break;
		}
	}

	/* Give the follow tap what we've currently dissected */
	if(have_tap_listener(http_follow_tap)) {
		tap_queue_packet(http_follow_tap, pinfo, tvb_new_subset_length(tvb, orig_offset, offset-orig_offset));
	}

	reported_datalen = tvb_reported_length_remaining(tvb, offset);
	datalen = tvb_captured_length_remaining(tvb, offset);

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
	if (headers->have_content_length &&
	    headers->transfer_encoding == HTTP_TE_NONE) {
		if (datalen > headers->content_length)
			datalen = (int)headers->content_length;

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
		if (reported_datalen > headers->content_length)
			reported_datalen = (int)headers->content_length;
	} else {
		switch (http_type) {

		case MEDIA_CONTAINER_HTTP_REQUEST:
			/*
			 * Requests have no content if there's no
			 * Content-Length header and no Transfer-Encoding
			 * header.
			 */
			if (headers->transfer_encoding == HTTP_TE_NONE)
				datalen = 0;
			else
				reported_datalen = -1;
			break;

		case MEDIA_CONTAINER_HTTP_RESPONSE:
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
			 * XXX - what about MEDIA_CONTAINER_HTTP_NOTIFICATION?
			 */
			reported_datalen = -1;
			break;
		}
	}

	if (!PINFO_FD_VISITED(pinfo) && streaming_chunk_mode && streaming_reassembly_data == NULL) {
		DISSECTOR_ASSERT(!begin_with_chunk && handle && http_dechunk_body && http_desegment_body
			&& headers && headers->content_type && header_value_map);

		content_info = wmem_new0(wmem_file_scope(), media_content_info_t);
		content_info->media_str = headers->content_type_parameters;
		content_info->type = http_type;
		content_info->data = header_value_map;

		streaming_reassembly_data = wmem_new0(wmem_file_scope(), http_streaming_reassembly_data_t);
		streaming_reassembly_data->streaming_handle = handle;
		streaming_reassembly_data->streaming_reassembly_info = streaming_reassembly_info_new();
		streaming_reassembly_data->content_info = content_info;
		streaming_reassembly_data->main_headers = headers;

		if (prv_data->req_fwd_flow == direction) {
			prv_data->req_streaming_reassembly_data = streaming_reassembly_data;
		} else {
			prv_data->res_streaming_reassembly_data = streaming_reassembly_data;
		}
	}

	if (content_info == NULL) {
		content_info = wmem_new0(pinfo->pool, media_content_info_t);
		content_info->media_str = headers->content_type_parameters;
		content_info->type = http_type;
		content_info->data = header_value_map;
	}

dissecting_body:

	if (datalen > 0) {
		/*
		 * There's stuff left over; process it.
		 */
		tvbuff_t *next_tvb;
		unsigned chunked_datalen = 0;
		int data_len;

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
		next_tvb = tvb_new_subset_length_caplen(tvb, offset, datalen,
		    reported_datalen);

		/*
		 * Handle *transfer* encodings.
		 */
		if (headers && headers->transfer_encoding_chunked) {
			if (!http_dechunk_body) {
				/* Chunking disabled, cannot dissect further. */
				/* XXX: Should this be sent to the follow tap? */
				call_data_dissector(next_tvb, pinfo, http_tree);
				goto body_dissected;
			}

			chunked_datalen = chunked_encoding_dissector(
			    &next_tvb, pinfo, http_tree, 0);

			if (chunked_datalen == 0) {
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
				/* chunked-body might be smaller than
				 * datalen. */
				datalen = chunked_datalen;
			}
		}
		/* Handle other transfer codings after de-chunking. */
		switch (headers->transfer_encoding) {
		case HTTP_TE_COMPRESS:
		case HTTP_TE_DEFLATE:
		case HTTP_TE_GZIP:
			/*
			 * We currently can't handle, for example, "gzip",
			 * "compress", or "deflate" as *transfer* encodings;
			 * just handle them as data for now.
			 * XXX: Should this be sent to the follow tap?
			 */
			call_data_dissector(next_tvb, pinfo, http_tree);
			goto body_dissected;
		default:
			/* Nothing to do for "identity" or when header is
			 * missing or invalid. */
			break;
		}
		/*
		 * At this point, any chunked *transfer* coding has been removed
		 * (the entity body has been dechunked) so it can be presented
		 * for the following operation (*content* encoding), or it has
		 * been handed off to the data dissector.
		 *
		 * Handle *content* encodings other than "identity" (which
		 * shouldn't appear in a Content-Encoding header, but
		 * we handle it in any case).
		 */
		if (headers->content_encoding != NULL &&
		    g_ascii_strcasecmp(headers->content_encoding, "identity") != 0) {
			/*
			 * We currently don't handle, for example, "compress";
			 * just handle them as data for now.
			 *
			 * After July 7, 2004 the LZW patent expired, so
			 * support could be added.  However, I don't think
			 * that anybody ever really implemented "compress",
			 * due to the aforementioned patent.
			 */
			tvbuff_t *uncomp_tvb = NULL;
			proto_item *e_ti = NULL;
			proto_tree *e_tree = NULL;

#if defined(HAVE_ZLIB) || defined(HAVE_ZLIBNG)
			if (http_decompress_body &&
			    (g_ascii_strcasecmp(headers->content_encoding, "gzip") == 0 ||
			     g_ascii_strcasecmp(headers->content_encoding, "deflate") == 0 ||
			     g_ascii_strcasecmp(headers->content_encoding, "x-gzip") == 0 ||
			     g_ascii_strcasecmp(headers->content_encoding, "x-deflate") == 0))
			{
				uncomp_tvb = tvb_child_uncompress_zlib(tvb, next_tvb, 0,
				    tvb_captured_length(next_tvb));
			}
#endif

#ifdef HAVE_BROTLI
			if (http_decompress_body &&
			    g_ascii_strcasecmp(headers->content_encoding, "br") == 0)
			{
				uncomp_tvb = tvb_child_uncompress_brotli(tvb, next_tvb, 0,
				    tvb_captured_length(next_tvb));
			}
#endif

#ifdef HAVE_SNAPPY
			if (http_decompress_body &&
			    g_ascii_strcasecmp(headers->content_encoding, "snappy") == 0)
			{
				uncomp_tvb = tvb_child_uncompress_snappy(tvb, next_tvb, 0,
				    tvb_captured_length(next_tvb));
			}
#endif

			/*
			 * Add the encoded entity to the protocol tree
			 */
			e_tree = proto_tree_add_subtree_format(http_tree, next_tvb,
					0, tvb_captured_length(next_tvb), ett_http_encoded_entity, &e_ti,
					"Content-encoded entity body (%s): %u bytes",
					headers->content_encoding,
					tvb_captured_length(next_tvb));

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
				proto_item_append_text(e_ti, " -> %u bytes", tvb_captured_length(uncomp_tvb));
				next_tvb = uncomp_tvb;
				add_new_data_source(pinfo, next_tvb,
				    "Uncompressed entity body");
			} else {
#if defined(HAVE_ZLIB) || defined(HAVE_ZLIBNG) || defined(HAVE_BROTLI)
				if (http_decompress_body) {
					expert_add_info(pinfo, e_ti, &ei_http_decompression_failed);
				}
				else {
					expert_add_info(pinfo, e_ti, &ei_http_decompression_disabled);
				}
#endif
				/* XXX: Should this be sent to the follow tap? */
				call_data_dissector(next_tvb, pinfo, e_tree);

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
		/* XXX: Do we really want to send it to Export Object if we didn't
		 * get the headers, so that this is just a fragment of Continuation
		 * Data and not a complete object?
		 */
		if(have_tap_listener(http_eo_tap)) {
			eo_info = wmem_new0(pinfo->pool, http_eo_t);

			if (curr) {
				eo_info->hostname = curr->http_host;
				eo_info->filename = curr->request_uri;
			}
			eo_info->content_type = headers->content_type;
			eo_info->payload = next_tvb;

			tap_queue_packet(http_eo_tap, pinfo, eo_info);
		}

		/* Send it to Follow HTTP Stream and mark as file data */
		if(have_tap_listener(http_follow_tap)) {
			tap_queue_packet(http_follow_tap, pinfo, next_tvb);
		}
		data_len = tvb_captured_length(next_tvb);
		proto_tree_add_bytes_format_value(http_tree, hf_http_file_data,
			next_tvb, 0, data_len, NULL, "%u byte%s", data_len, plurality(data_len, "", "s"));

		if (tvb_captured_length(next_tvb) == 0)
			goto body_dissected;

		/*
		 * Do subdissector checks.
		 *
		 * First, if we have a Content-Type value, check whether
		 * there's a subdissector for that media type.
		 */
		if (headers->content_type != NULL && handle == NULL) {
			/*
			 * We didn't find any subdissector that
			 * registered for the port, and we have a
			 * Content-Type value.  Is there any subdissector
			 * for that content type?
			 */

			/*
			 * Calling the string handle for the media type
			 * dissector table will set pinfo->match_string
			 * to headers->content_type for us.
			 */
			pinfo->match_string = headers->content_type;
			handle = dissector_get_string_handle(
			    media_type_subdissector_table,
			    headers->content_type);
			if (handle == NULL &&
			    strncmp(headers->content_type, "multipart/", sizeof("multipart/")-1) == 0) {
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
			/* If the HTTP dissector was called heuristically
			 * (or the HTTP dissector was called from the TLS
			 * dissector, which was called heuristically), then
			 * match_uint doesn't get set (or is likely set to
			 * 6 for IP_PROTO_TCP.) Some protocols (e.g., IPP)
			 * use the same specified port for both HTTP and
			 * HTTP over TLS, and one will be a heuristic match.
			 * In those cases, look at the src or dest port.
			 */
			if (pinfo->match_uint == pinfo->srcport || pinfo->match_uint == pinfo->destport) {
				handle = dissector_get_uint_handle(port_subdissector_table,
				    pinfo->match_uint);
			} else if (http_type == MEDIA_CONTAINER_HTTP_REQUEST) {
				handle = dissector_get_uint_handle(port_subdissector_table,
				    pinfo->destport);
			} else if (http_type == MEDIA_CONTAINER_HTTP_RESPONSE) {
				handle = dissector_get_uint_handle(port_subdissector_table,
				    pinfo->srcport);
			}
		}

		if (handle != NULL) {
			/*
			 * We have a subdissector - call it.
			 */
			if (streaming_chunk_mode) {
				pinfo->match_string = headers->content_type;
				/* reassemble and call subdissector */
				dissected = (bool)reassemble_streaming_data_and_call_subdissector(next_tvb, pinfo, 0,
					tvb_reported_length_remaining(next_tvb, 0), http_tree, proto_tree_get_parent_tree(tree),
					http_streaming_reassembly_table, streaming_reassembly_data->streaming_reassembly_info,
					get_http_chunk_frame_num(tvb, pinfo, offset), handle,
					proto_tree_get_parent_tree(tree), content_info,
					"HTTP", &http_body_fragment_items, hf_http_body_segment);
			} else {
				dissected = (bool)call_dissector_only(handle, next_tvb, pinfo, tree, content_info);
			}
			if (!dissected)
				expert_add_info(pinfo, http_tree, &ei_http_subdissector_failed);
		}

		if (!dissected) {
			/*
			 * We don't have a subdissector or we have one and it did not
			 * dissect the payload - try the heuristic subdissectors.
			 */
			dissected = dissector_try_heuristic(heur_subdissector_list,
							    next_tvb, pinfo, tree, &hdtbl_entry, content_info);
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
			if (headers->content_type != NULL) {
				/*
				 * Calling the default media handle if there is a content-type that
				 * wasn't handled above.
				 */
				call_dissector_with_data(media_handle, next_tvb, pinfo, tree, content_info);
			} else {
				/* Call the default data dissector */
				call_data_dissector(next_tvb, pinfo, http_tree);
			}
		}

	body_dissected:
		/*
		 * We've processed "datalen" bytes worth of data
		 * (which may be no data at all); advance the
		 * offset past whatever data we've processed.
		 */
		offset += datalen;
	}

	/* Detect protocol changes after receiving full response headers. */
	if (http_type == MEDIA_CONTAINER_HTTP_RESPONSE && curr && pinfo->desegment_offset <= 0 && pinfo->desegment_len <= 0) {
		dissector_handle_t next_handle = NULL;
		bool server_acked = false;

		/*
		 * SSTP uses a special request method (instead of the Upgrade
		 * header) and expects a 200 response to set up the session.
		 */
		if (g_strcmp0(curr->request_method, "SSTP_DUPLEX_POST") == 0 && curr->response_code == 200) {
			next_handle = sstp_handle;
			server_acked = true;
		}

		/*
		 * An HTTP/1.1 upgrade only proceeds if the server responds
		 * with 101 Switching Protocols. See RFC 7230 Section 6.7.
		 */
		if (headers->upgrade && curr->response_code == 101) {
			next_handle = dissector_get_string_handle(upgrade_subdissector_table, headers->upgrade);
			if (!next_handle) {
				char *slash_pos = strchr(headers->upgrade, '/');
				if (slash_pos) {
					/* Try again without version suffix. */
					next_handle = dissector_get_string_handle(upgrade_subdissector_table,
							wmem_strndup(pinfo->pool, headers->upgrade, slash_pos - headers->upgrade));
				}
			}
			server_acked = true;
		}

		if (server_acked && !PINFO_FD_VISITED(pinfo)) {
			conv_data->startframe = pinfo->num;
			conv_data->startoffset = offset;
			conv_data->next_handle = next_handle;
			copy_address_wmem(wmem_file_scope(), &conv_data->server_addr, &pinfo->src);
			conv_data->server_port = pinfo->srcport;
		}
	}

	if (stat_info)
		tap_queue_packet(http_tap, pinfo, stat_info);

	return offset - orig_offset;
}

/* This can be used to dissect an HTTP request until such time
 * that a more complete dissector is written for that HTTP request.
 * This simple dissector only puts the request method, URI, and
 * protocol version into a sub-tree.
 */
static void
basic_request_dissector(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tree,
			int offset, const unsigned char *line, const unsigned char *lineend,
			http_conv_t *conv_data _U_, http_req_res_t *curr)
{
	const unsigned char *next_token;
	const char *request_uri;
	int tokenlen;
	proto_item* ti;
	http_info_value_t *stat_info = p_get_proto_data(pinfo->pool, pinfo, proto_http, HTTP_PROTO_DATA_INFO);

	/* The first token is the method. */
	tokenlen = get_token_len(line, lineend, &next_token);
	if (tokenlen == 0)
		return;
	proto_tree_add_item(tree, hf_http_request_method, tvb, offset, tokenlen,
			    ENC_ASCII);
	if ((next_token - line) > 2 && next_token[-1] == ' ' && next_token[-2] == ' ') {
	  /* Two spaces in a now indicates empty URI, so roll back one here */
	  next_token--;
	}
	offset += (int) (next_token - line);
	line = next_token;

	/* The next token is the URI. */
	tokenlen = get_token_len(line, lineend, &next_token);

	/* Save the request URI for various later uses */
	request_uri = tvb_get_string_enc(pinfo->pool, tvb, offset, tokenlen, ENC_ASCII);

	if (request_uri == NULL && curr)
	       request_uri = curr->request_uri;

	stat_info->request_uri = wmem_strdup(pinfo->pool, request_uri);
	if (!PINFO_FD_VISITED(pinfo) && curr) {
		curr->request_uri = wmem_strdup(wmem_file_scope(), request_uri);
	}
	ti = proto_tree_add_string(tree, hf_http_request_uri, tvb, offset, tokenlen, request_uri);
	http_add_path_components_to_tree(tvb, pinfo, ti, offset, tokenlen);
	offset += (int) (next_token - line);
	line = next_token;

	/* Everything to the end of the line is the version. */
	tokenlen = (int) (lineend - line);
	proto_tree_add_item(tree, hf_http_request_version, tvb, offset, tokenlen,
	    ENC_ASCII);
}

static int
parse_http_status_code(const unsigned char *line, const unsigned char *lineend)
{
	const unsigned char *next_token;
	int tokenlen;
	char response_code_chars[4];
	int32_t status_code = 0;

	/*
	 * The first token is the HTTP Version.
	 */
	tokenlen = get_token_len(line, lineend, &next_token);
	if (tokenlen == 0)
		return 0;
	line = next_token;

	/*
	 * The second token is the Status Code.
	 */
	tokenlen = get_token_len(line, lineend, &next_token);
	if (tokenlen != 3)
		return 0;

	memcpy(response_code_chars, line, 3);
	response_code_chars[3] = '\0';
	if (!ws_strtoi32(response_code_chars, NULL, &status_code))
		return 0;

	return status_code;
}

static void
basic_response_dissector(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tree,
			int offset, const unsigned char *line, const unsigned char *lineend,
			 http_conv_t *conv_data _U_, http_req_res_t *curr)
{
	const unsigned char *next_token;
	int tokenlen;
	char response_code_chars[4];
	proto_item *r_ti;
	http_info_value_t *stat_info = p_get_proto_data(pinfo->pool, pinfo, proto_http, HTTP_PROTO_DATA_INFO);

	/*
	 * The first token is the HTTP Version.
	 */
	tokenlen = get_token_len(line, lineend, &next_token);
	if (tokenlen == 0)
		return;
	proto_tree_add_item(tree, hf_http_response_version, tvb, offset, tokenlen,
			    ENC_ASCII);
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

	stat_info->response_code =
		(unsigned)strtoul(response_code_chars, NULL, 10);
	if (curr) {
		curr->response_code = stat_info->response_code;
	}

	proto_tree_add_uint(tree, hf_http_response_code, tvb, offset, 3,
			    stat_info->response_code);

	r_ti = proto_tree_add_string(tree, hf_http_response_code_desc,
		tvb, offset, 3, val_to_str(stat_info->response_code,
		vals_http_status_code, "Unknown (%d)"));

	proto_item_set_generated(r_ti);

	/* Advance to the start of the next token. */
	offset += (int) (next_token - line);
	line = next_token;

	/*
	 * The remaining tokens in the line comprise the Reason Phrase.
	 */
	tokenlen = (int) (lineend - line);
	if (tokenlen >= 1) {
		proto_tree_add_item(tree, hf_http_response_phrase, tvb, offset,
				tokenlen, ENC_ASCII);
	}
}

/*
 * Dissect the http data chunks and add them to the tree.
 */
static unsigned
chunked_encoding_dissector(tvbuff_t **tvb_ptr, packet_info *pinfo,
			   proto_tree *tree, int offset)
{
	tvbuff_t	*tvb;
	uint32_t		 datalen;
	uint32_t		 orig_datalen;
	int		 chunked_data_size;
	proto_tree	*subtree;
	proto_item	*pi_chunked = NULL;
	uint8_t		*raw_data;
	int		 raw_len;
	int          chunk_counter = 0;
	int          last_chunk_id = -1;

	if ((tvb_ptr == NULL) || (*tvb_ptr == NULL)) {
		return 0;
	}

	tvb = *tvb_ptr;

	datalen = tvb_reported_length_remaining(tvb, offset);

	subtree = proto_tree_add_subtree(tree, tvb, offset, datalen,
					 ett_http_chunked_response, &pi_chunked,
					 "HTTP chunked response");

	/* Dechunk the "chunked response" to a new memory buffer */
	/* XXX: Composite tvbuffers do work now, so we should probably
         * use that to avoid the memcpys unless necessary.
         */
	orig_datalen      = datalen;
	raw_data	      = (uint8_t *)wmem_alloc(pinfo->pool, datalen);
	raw_len		      = 0;
	chunked_data_size = 0;

	while (datalen > 0) {
		uint32_t	  chunk_size;
		int	  chunk_offset;
		uint8_t	 *chunk_string;
		int	  linelen;
		char	 *c;

		linelen = tvb_find_line_end(tvb, offset, -1, &chunk_offset, true);

		if (linelen <= 0) {
			/* Can't get the chunk size line */
			break;
		}

		chunk_string = tvb_get_string_enc(pinfo->pool, tvb, offset, linelen, ENC_ASCII);

		if (chunk_string == NULL) {
			/* Can't get the chunk size line */
			break;
		}

		c = (char*)chunk_string;

		/*
		 * We don't care about the extensions.
		 */
		if ((c = strchr(c, ';'))) {
			*c = '\0';
		}

		chunk_size = (uint32_t)strtol((char*)chunk_string, NULL, 16);

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
		tvb_memcpy(tvb, (uint8_t *)(raw_data + raw_len), chunk_offset, chunk_size);
		raw_len += chunk_size;

		++chunk_counter;

		if (subtree) {
			proto_tree *chunk_subtree;
			proto_item *chunk_size_item;

			if(chunk_size == 0) {
				chunk_subtree = proto_tree_add_subtree(subtree, tvb,
					    offset,
					    chunk_offset - offset + chunk_size + 2,
					    ett_http_chunk_data, NULL,
					    "End of chunked encoding");
				last_chunk_id = chunk_counter - 1;
			} else {
				chunk_subtree = proto_tree_add_subtree_format(subtree, tvb,
					    offset,
					    chunk_offset - offset + chunk_size + 2,
					    ett_http_chunk_data, NULL,
					    "Data chunk (%u octets)", chunk_size);
			}

			chunk_size_item = proto_tree_add_uint(chunk_subtree, hf_http_chunk_size, tvb, offset,
			    1, chunk_size);
			proto_item_set_len(chunk_size_item, chunk_offset - offset);

			/* last-chunk does not have chunk-data CRLF. */
			if (chunk_size > 0) {
				/*
				 * Adding the chunk as FT_BYTES means that, in
				 * TShark, you get the entire chunk dumped
				 * out in hex, in addition to whatever
				 * dissection is done on the reassembled data.
				 */
				proto_tree_add_item(chunk_subtree, hf_http_chunk_data, tvb, chunk_offset, chunk_size, ENC_NA);
				proto_tree_add_item(chunk_subtree, hf_http_chunk_boundary, tvb,
									chunk_offset + chunk_size, 2, ENC_NA);
			}
		}

		offset  = chunk_offset + chunk_size;  /* beginning of next chunk */
		if (chunk_size > 0) offset += 2; /* CRLF of chunk */
		datalen = tvb_reported_length_remaining(tvb, offset);

		/* This is the last chunk */
		if (chunk_size == 0) {
			/* Check for: trailer-part CRLF.
			 * trailer-part   = *( header-field CRLF ) */
			int trailer_offset = offset, trailer_len;
			int header_field_len;
			/* Skip all header-fields. */
			do {
				trailer_len = trailer_offset - offset;
				header_field_len = tvb_find_line_end(tvb,
					trailer_offset,
					datalen - trailer_len,
					&trailer_offset, true);
			} while (header_field_len > 0);
			if (trailer_len > 0) {
				proto_tree_add_item(subtree,
					hf_http_chunked_trailer_part,
					tvb, offset, trailer_len, ENC_ASCII);
				offset += trailer_len;
				datalen -= trailer_len;
			}

			/* last CRLF of chunked-body is found. */
			if (header_field_len == 0) {
				proto_tree_add_format_text(subtree, tvb, offset,
					trailer_offset - offset);
				datalen -= trailer_offset - offset;
			}
			break;
		}
	}

	/* datalen is the remaining bytes that are available for consumption. If
	 * smaller than orig_datalen, then bytes were consumed. */
	if (datalen < orig_datalen) {
		tvbuff_t *new_tvb;
		proto_item_set_len(pi_chunked, orig_datalen - datalen);
		new_tvb = tvb_new_child_real_data(tvb, raw_data, chunked_data_size, chunked_data_size);
		*tvb_ptr = new_tvb;
	}

	if (chunk_counter > 0) {
		proto_item* ti_http = proto_tree_get_parent(tree);
		proto_item_append_text(ti_http, ", has %d chunk%s%s",
			chunk_counter, plurality(chunk_counter, "", "s"),
			(last_chunk_id < 0 ? "" : " (including last chunk)"));

		if (last_chunk_id == 0) {
			/* only append text to column while starting with last chunk */
			col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "[Last Chunk]");
		}
	}

	/* Size of chunked-body or 0 if none was found. */
	return orig_datalen - datalen;
}

static bool
conversation_dissector_is_http(conversation_t *conv, uint32_t frame_num)
{
	dissector_handle_t conv_handle;

	if (conv == NULL)
		return false;
	conv_handle = conversation_get_dissector(conv, frame_num);
	return conv_handle == http_handle ||
	       conv_handle == http_tcp_handle ||
	       conv_handle == http_sctp_handle;
}

/* Call a subdissector to handle HTTP CONNECT's traffic */
static void
http_payload_subdissector(tvbuff_t *tvb, proto_tree *tree,
			  packet_info *pinfo, http_conv_t *conv_data, void* data)
{
	uint32_t *ptr = NULL;
	uint32_t uri_port, saved_port, srcport, destport;
	char **strings; /* An array for splitting the request URI into hostname and port */
	proto_item *item;
	proto_tree *proxy_tree;
	conversation_t *conv;
	bool from_server = pinfo->srcport == conv_data->server_port &&
		addresses_equal(&conv_data->server_addr, &pinfo->src);

	/* Grab the destination port number from the request URI to find the right subdissector */
	strings = wmem_strsplit(pinfo->pool, conv_data->req_res_tail->request_uri, ":", 2);

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
			proto_item_set_generated(item);

			item = proto_tree_add_uint(proxy_tree, hf_http_proxy_connect_port,
						   tvb, 0, 0, (uint32_t)strtol(strings[1], NULL, 10) );
			proto_item_set_generated(item);
		}

		uri_port = (int)strtol(strings[1], NULL, 10); /* Convert string to a base-10 integer */

		if (!from_server) {
			srcport = pinfo->srcport;
			destport = uri_port;
		} else {
			srcport = uri_port;
			destport = pinfo->destport;
		}

		conv = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst, CONVERSATION_TCP, srcport, destport, 0);

		/* We may get stuck in a recursion loop if we let process_tcp_payload() call us.
		 * So, if the port in the URI is one we're registered for or we have set up a
		 * conversation (e.g., one we detected heuristically or via Decode-As) call the data
		 * dissector directly.
		 */
		if (value_is_in_range(http_tcp_range, uri_port) ||
		    conversation_dissector_is_http(conv, pinfo->num)) {
			call_data_dissector(tvb, pinfo, tree);
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
}



/*
 * XXX - this won't handle HTTP 0.9 replies, but they're all data
 * anyway.
 */
static int
is_http_request_or_reply(packet_info *pinfo, const char *data, int linelen, media_container_type_t *type,
			 ReqRespDissector *reqresp_dissector,
			 http_conv_t *conv_data _U_)
{
	http_info_value_t *stat_info = p_get_proto_data(pinfo->pool, pinfo, proto_http, HTTP_PROTO_DATA_INFO);
	int isHttpRequestOrReply = false;

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
	if ((linelen >= 5 && strncmp(data, "HTTP/", 5) == 0) ||
		(linelen >= 3 && strncmp(data, "ICY", 3) == 0)) {
		*type = MEDIA_CONTAINER_HTTP_RESPONSE;
		isHttpRequestOrReply = true;	/* response */
		if (reqresp_dissector)
			*reqresp_dissector = basic_response_dissector;
	} else {
		const unsigned char * ptr = (const unsigned char *)data;
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
				*type = MEDIA_CONTAINER_HTTP_REQUEST;
				isHttpRequestOrReply = true;
			}
			break;

		case 4:
			if (strncmp(data, "COPY", indx) == 0 ||
			    strncmp(data, "HEAD", indx) == 0 ||
			    strncmp(data, "LOCK", indx) == 0 ||
			    strncmp(data, "MOVE", indx) == 0 ||
			    strncmp(data, "POLL", indx) == 0 ||
			    strncmp(data, "POST", indx) == 0) {
				*type = MEDIA_CONTAINER_HTTP_REQUEST;
				isHttpRequestOrReply = true;
			}
			break;

		case 5:
			if (strncmp(data, "BCOPY", indx) == 0 ||
				strncmp(data, "BMOVE", indx) == 0 ||
				strncmp(data, "MKCOL", indx) == 0 ||
				strncmp(data, "TRACE", indx) == 0 ||
				strncmp(data, "PATCH", indx) == 0 ||  /* RFC 5789 */
				strncmp(data, "LABEL", indx) == 0 ||  /* RFC 3253 8.2 */
				strncmp(data, "MERGE", indx) == 0) {  /* RFC 3253 11.2 */
				*type = MEDIA_CONTAINER_HTTP_REQUEST;
				isHttpRequestOrReply = true;
			}
			break;

		case 6:
			if (strncmp(data, "DELETE", indx) == 0 ||
				strncmp(data, "SEARCH", indx) == 0 ||
				strncmp(data, "UNLOCK", indx) == 0 ||
				strncmp(data, "REPORT", indx) == 0 ||  /* RFC 3253 3.6 */
				strncmp(data, "UPDATE", indx) == 0) {  /* RFC 3253 7.1 */
				*type = MEDIA_CONTAINER_HTTP_REQUEST;
				isHttpRequestOrReply = true;
			}
			else if (strncmp(data, "NOTIFY", indx) == 0) {
				*type = MEDIA_CONTAINER_HTTP_NOTIFICATION;
				isHttpRequestOrReply = true;
			}
			break;

		case 7:
			if (strncmp(data, "BDELETE", indx) == 0 ||
			    strncmp(data, "CONNECT", indx) == 0 ||
			    strncmp(data, "OPTIONS", indx) == 0 ||
			    strncmp(data, "CHECKIN", indx) == 0) {  /* RFC 3253 4.4, 9.4 */
				*type = MEDIA_CONTAINER_HTTP_REQUEST;
				isHttpRequestOrReply = true;
			}
			break;

		case 8:
			if (strncmp(data, "PROPFIND", indx) == 0 ||
			    strncmp(data, "CHECKOUT", indx) == 0 || /* RFC 3253 4.3, 9.3 */
			    strncmp(data, "CCM_POST", indx) == 0) {
				*type = MEDIA_CONTAINER_HTTP_REQUEST;
				isHttpRequestOrReply = true;
			}
			break;

		case 9:
			if (strncmp(data, "SUBSCRIBE", indx) == 0) {
				*type = MEDIA_CONTAINER_HTTP_NOTIFICATION;
				isHttpRequestOrReply = true;
			} else if (strncmp(data, "PROPPATCH", indx) == 0 ||
			    strncmp(data, "BPROPFIND", indx) == 0) {
				*type = MEDIA_CONTAINER_HTTP_REQUEST;
				isHttpRequestOrReply = true;
			}
			break;

		case 10:
			if (strncmp(data, "BPROPPATCH", indx) == 0 ||
				strncmp(data, "UNCHECKOUT", indx) == 0 ||  /* RFC 3253 4.5 */
				strncmp(data, "MKACTIVITY", indx) == 0) {  /* RFC 3253 13.5 */
				*type = MEDIA_CONTAINER_HTTP_REQUEST;
				isHttpRequestOrReply = true;
			}
			break;

		case 11:
			if (strncmp(data, "MKWORKSPACE", indx) == 0 || /* RFC 3253 6.3 */
			    strncmp(data, "RPC_CONNECT", indx) == 0 || /* [MS-RPCH] 2.1.1.1.1 */
			    strncmp(data, "RPC_IN_DATA", indx) == 0) { /* [MS-RPCH] 2.1.2.1.1 */
				*type = MEDIA_CONTAINER_HTTP_REQUEST;
				isHttpRequestOrReply = true;
			} else if (strncmp(data, "UNSUBSCRIBE", indx) == 0) {
				*type = MEDIA_CONTAINER_HTTP_NOTIFICATION;
				isHttpRequestOrReply = true;
			}
			break;

		case 12:
			if (strncmp(data, "RPC_OUT_DATA", indx) == 0) { /* [MS-RPCH] 2.1.2.1.2 */
				*type = MEDIA_CONTAINER_HTTP_REQUEST;
				isHttpRequestOrReply = true;
			}
			break;

		case 15:
			if (strncmp(data, "VERSION-CONTROL", indx) == 0) {  /* RFC 3253 3.5 */
				*type = MEDIA_CONTAINER_HTTP_REQUEST;
				isHttpRequestOrReply = true;
			}
			break;

		case 16:
			if (strncmp(data, "BASELINE-CONTROL", indx) == 0) {  /* RFC 3253 12.6 */
				*type = MEDIA_CONTAINER_HTTP_REQUEST;
				isHttpRequestOrReply = true;
			} else if (strncmp(data, "SSTP_DUPLEX_POST", indx) == 0) {  /* MS SSTP */
				*type = MEDIA_CONTAINER_HTTP_REQUEST;
				isHttpRequestOrReply = true;
			}
			break;

		default:
			break;
		}

		if (isHttpRequestOrReply && reqresp_dissector) {
			*reqresp_dissector = basic_request_dissector;

			stat_info->request_method = wmem_strndup(pinfo->pool, data, indx);
		}



	}

	return isHttpRequestOrReply;
}

/*
 * Process headers.
 */
typedef struct {
	const char	*name;
	int		*hf;
	int		special;
} header_info;

#define HDR_NO_SPECIAL			0
#define HDR_AUTHORIZATION		1
#define HDR_AUTHENTICATE		2
#define HDR_CONTENT_TYPE		3
#define HDR_CONTENT_LENGTH		4
#define HDR_CONTENT_ENCODING		5
#define HDR_TRANSFER_ENCODING		6
#define HDR_HOST			7
#define HDR_UPGRADE			8
#define HDR_COOKIE			9
#define HDR_WEBSOCKET_PROTOCOL		10
#define HDR_WEBSOCKET_EXTENSIONS	11
#define HDR_REFERER			12
#define HDR_LOCATION			13
#define HDR_HTTP2_SETTINGS		14
#define HDR_RANGE           		15
#define HDR_CONTENT_RANGE		16

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
	{ "Range", &hf_http_range, HDR_RANGE },
	{ "Content-Range", &hf_http_content_range, HDR_CONTENT_RANGE },
	{ "Connection", &hf_http_connection, HDR_NO_SPECIAL },
	{ "Cookie", &hf_http_cookie, HDR_COOKIE },
	{ "Accept", &hf_http_accept, HDR_NO_SPECIAL },
	{ "Referer", &hf_http_referer, HDR_REFERER },
	{ "Accept-Language", &hf_http_accept_language, HDR_NO_SPECIAL },
	{ "Accept-Encoding", &hf_http_accept_encoding, HDR_NO_SPECIAL },
	{ "Date", &hf_http_date, HDR_NO_SPECIAL },
	{ "Cache-Control", &hf_http_cache_control, HDR_NO_SPECIAL },
	{ "Server", &hf_http_server, HDR_NO_SPECIAL },
	{ "Location", &hf_http_location, HDR_LOCATION },
	{ "Sec-WebSocket-Accept", &hf_http_sec_websocket_accept, HDR_NO_SPECIAL },
	{ "Sec-WebSocket-Extensions", &hf_http_sec_websocket_extensions, HDR_WEBSOCKET_EXTENSIONS },
	{ "Sec-WebSocket-Key", &hf_http_sec_websocket_key, HDR_NO_SPECIAL },
	{ "Sec-WebSocket-Protocol", &hf_http_sec_websocket_protocol, HDR_WEBSOCKET_PROTOCOL },
	{ "Sec-WebSocket-Version", &hf_http_sec_websocket_version, HDR_NO_SPECIAL },
	{ "Set-Cookie", &hf_http_set_cookie, HDR_NO_SPECIAL },
	{ "Last-Modified", &hf_http_last_modified, HDR_NO_SPECIAL },
	{ "X-Forwarded-For", &hf_http_x_forwarded_for, HDR_NO_SPECIAL },
	{ "HTTP2-Settings", &hf_http_http2_settings, HDR_HTTP2_SETTINGS },
};

/*
 * Look up a header name (assume lower-case header_name).
 */
static int*
get_hf_for_header(char* header_name)
{
	int* hf_id = NULL;

	if (header_fields_hash) {
		hf_id = (int*) g_hash_table_lookup(header_fields_hash, header_name);
	} else {
		hf_id = NULL;
	}

	return hf_id;
}

/*
 *
 */
static void
deregister_header_fields(void)
{
	if (dynamic_hf) {
		/* Deregister all fields */
		for (unsigned i = 0; i < dynamic_hf_size; i++) {
			proto_deregister_field (proto_http, *(dynamic_hf[i].p_id));
			g_free (dynamic_hf[i].p_id);
		}

		proto_add_deregistered_data (dynamic_hf);
		dynamic_hf = NULL;
		dynamic_hf_size = 0;
	}

	if (header_fields_hash) {
		g_hash_table_destroy (header_fields_hash);
		header_fields_hash = NULL;
	}
}

static void
header_fields_post_update_cb(void)
{
	int* hf_id;
	char* header_name;
	char* header_name_key;

	deregister_header_fields();

	if (num_header_fields) {
		header_fields_hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
		dynamic_hf = g_new0(hf_register_info, num_header_fields);
		dynamic_hf_size = num_header_fields;

		for (unsigned i = 0; i < dynamic_hf_size; i++) {
			hf_id = g_new(int,1);
			*hf_id = -1;
			header_name = g_strdup(header_fields[i].header_name);
			header_name_key = g_ascii_strdown(header_name, -1);

			dynamic_hf[i].p_id = hf_id;
			dynamic_hf[i].hfinfo.name = header_name;
			dynamic_hf[i].hfinfo.abbrev = ws_strdup_printf("http.header.%s", header_name);
			dynamic_hf[i].hfinfo.type = FT_STRING;
			dynamic_hf[i].hfinfo.display = BASE_NONE;
			dynamic_hf[i].hfinfo.strings = NULL;
			dynamic_hf[i].hfinfo.bitmask = 0;
			dynamic_hf[i].hfinfo.blurb = g_strdup(header_fields[i].header_desc);
			HFILL_INIT(dynamic_hf[i]);

			g_hash_table_insert(header_fields_hash, header_name_key, hf_id);
		}

		proto_register_field_array(proto_http, dynamic_hf, dynamic_hf_size);
	}
}

static void
header_fields_reset_cb(void)
{
	deregister_header_fields();
}

/**
 * Parses the transfer-coding, returning true if everything was fully understood
 * or false when unknown names were encountered.
 */
static bool
http_parse_transfer_coding(const char *value, headers_t *eh_ptr)
{
	bool is_fully_parsed = true;

	/* Mark header as set, but with unknown encoding. */
	eh_ptr->transfer_encoding = HTTP_TE_UNKNOWN;

	while (*value) {
		/* skip OWS (SP / HTAB) and commas; stop at the end. */
		while (*value == ' ' || *value == '\t' || *value == ',')
			value++;
		if (!*value)
			break;

		if (g_str_has_prefix(value, "chunked")) {
			eh_ptr->transfer_encoding_chunked = true;
			value += sizeof("chunked") - 1;
			continue;
		}

		/* For now assume that chunked can only combined with exactly
		 * one other (compression) encoding. Anything else is
		 * unsupported. */
		if (eh_ptr->transfer_encoding != HTTP_TE_UNKNOWN) {
			/* No more transfer codings are expected. */
			is_fully_parsed = false;
			break;
		}

		if (g_str_has_prefix(value, "compress")) {
			eh_ptr->transfer_encoding = HTTP_TE_COMPRESS;
			value += sizeof("compress") - 1;
		} else if (g_str_has_prefix(value, "deflate")) {
			eh_ptr->transfer_encoding = HTTP_TE_DEFLATE;
			value += sizeof("deflate") - 1;
		} else if (g_str_has_prefix(value, "gzip")) {
			eh_ptr->transfer_encoding = HTTP_TE_GZIP;
			value += sizeof("gzip") - 1;
		} else if (g_str_has_prefix(value, "identity")) {
			eh_ptr->transfer_encoding = HTTP_TE_IDENTITY;
			value += sizeof("identity") - 1;
		} else if (g_str_has_prefix(value, "x-compress")) {
			eh_ptr->transfer_encoding = HTTP_TE_COMPRESS;
			value += sizeof("x-compress") - 1;
		} else if (g_str_has_prefix(value, "x-gzip")) {
			eh_ptr->transfer_encoding = HTTP_TE_GZIP;
			value += sizeof("x-gzip") - 1;
		} else {
			/* Unknown transfer encoding, skip until next comma.
			 * Stop when no more names are found. */
			is_fully_parsed = false;
			value = strchr(value, ',');
			if (!value)
				break;
		}
	}

	return is_fully_parsed;
}

static bool
is_token_char(char c)
{
	/* tchar according to https://tools.ietf.org/html/rfc7230#section-3.2.6 */
	return strchr("!#$%&\\:*+-.^_`|~", c) || g_ascii_isalnum(c);
}

static bool
valid_header_name(const unsigned char *line, int header_len)
{

	/*
	 * Validate the header name. This allows no space between the field name
	 * and colon (RFC 7230, Section. 3.2.4).
	 */
	if (header_len == 0) {
		return false;
	}
	for (int i = 0; i < header_len; i++) {
		/*
		 * NUL is not a valid character; treat it specially
		 * due to C's notion that strings are NUL-terminated.
		 */
		if (line[i] == '\0') {
			return false;
		}
		if (!is_token_char(line[i])) {
			return false;
		}
	}
	return true;
}

static bool
process_header(tvbuff_t *tvb, int offset, int next_offset,
	       const unsigned char *line, int linelen, int colon_offset,
	       packet_info *pinfo, proto_tree *tree, headers_t *eh_ptr,
	       http_conv_t *conv_data, media_container_type_t http_type, wmem_map_t *header_value_map,
	       bool streaming_chunk_mode)
{
	int len;
	int line_end_offset;
	int header_len;
	int hf_index;
	unsigned char c;
	int value_offset;
	int value_len, value_bytes_len;
	uint8_t *value_bytes;
	char *value;
	char *header_name;
	char *p;
	unsigned char *up;
	proto_item *hdr_item, *it;
	int f;
	int* hf_id;
	tap_credential_t* auth;
	http_req_res_t  *curr_req_res = (http_req_res_t *)p_get_proto_data(wmem_file_scope(), pinfo,
			proto_http, HTTP_PROTO_DATA_REQRES);
	http_info_value_t *stat_info = p_get_proto_data(pinfo->pool, pinfo, proto_http, HTTP_PROTO_DATA_INFO);
	wmem_allocator_t *scope = (!PINFO_FD_VISITED(pinfo) && streaming_chunk_mode) ? wmem_file_scope() :
		                      ((PINFO_FD_VISITED(pinfo) && streaming_chunk_mode) ? NULL : pinfo->pool);

	len = next_offset - offset;
	line_end_offset = offset + linelen;
	header_len = colon_offset - offset;

	/**
	 * Not a valid header name? Just add a line plus expert info.
	 */
	if (!valid_header_name(line, header_len)) {
		if (http_check_ascii_headers) {
			/* If we're offering the chance for other dissectors to parse,
			 * we shouldn't add any tree items ourselves.
			 */
			return false;
		}
		if (http_type == MEDIA_CONTAINER_HTTP_REQUEST) {
			hf_index = hf_http_request_line;
		} else if (http_type == MEDIA_CONTAINER_HTTP_RESPONSE) {
			hf_index = hf_http_response_line;
		} else {
			hf_index = hf_http_unknown_header;
		}
		it = proto_tree_add_item(tree, hf_index, tvb, offset, len, ENC_NA|ENC_ASCII);
		proto_item_set_text(it, "%s", format_text(pinfo->pool, line, len));
		expert_add_info(pinfo, it, &ei_http_bad_header_name);
		return false;
	}

	/*
	 * Make a null-terminated, all-lower-case version of the header
	 * name.
	 */
	header_name = wmem_ascii_strdown(pinfo->pool, &line[0], header_len);

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
	 * XXX - RFC 9110 5.5 "Specification for newly defined fields
	 * SHOULD limit their values to visible US-ASCII octets (VCHAR),
	 * SP, and HTAB. A recipient SHOULD treat other allowed octets in
	 * field content (i.e., obs-text [%x80-FF]) as opaque data...
	 * Field values containing CR, LF, or NUL characters are invalid
	 * and dangerous." (Up to RFC 7230, an obsolete "line-folding"
	 * mechanism that included CRLF was allowed.)
	 *
	 * So NUL is not allowed, and we should have one or more
	 * expert infos if the field value has anything other than
	 * ASCII printable + TAB. (Possibly different severities
	 * depending on whether it contains obsolete characters
	 * like \x80-\xFF vs characters never allowed like NUL.)
	 * All known field types respect this (using Base64, etc.)
	 * Unknown field types (possibly including those registered
	 * through the UAT) should be treated like FT_BYTES with
	 * BASE_SHOW_ASCII_PRINTABLE instead of FT_STRING, but it's
	 * more difficult to do that with the custom formatting
	 * that uses the header name.
	 *
	 * Instead, for now for display purposes we will treat strings
	 * as ASCII and pass the raw value to subdissectors via the
	 * header_value_map. For the latter, we allocate a buffer that's
	 * value_bytes_len+1 bytes long, copy value_bytes_len bytes, and
	 * stick in a NUL terminator, so that the buffer for value actually
	 * has value_bytes_len bytes in it.
	 */
	value_bytes_len = line_end_offset - value_offset;
	value_bytes = (char *)wmem_alloc((scope ? scope : pinfo->pool), value_bytes_len+1);
	memcpy(value_bytes, &line[value_offset - offset], value_bytes_len);
	value_bytes[value_bytes_len] = '\0';
	value = tvb_get_string_enc(pinfo->pool, tvb, value_offset, value_bytes_len, ENC_ASCII);
	/* The length of the value might change after UTF-8 sanitization */
	value_len = (int)strlen(value);

	if (scope == pinfo->pool) {
		wmem_map_insert(header_value_map, header_name, value_bytes);
	} else if (scope) { /* (!PINFO_FD_VISITED(pinfo) && streaming_chunk_mode) */
		wmem_map_insert(header_value_map, wmem_strdup(scope, header_name), value_bytes);
	} /* else skip while (PINFO_FD_VISITED(pinfo) && streaming_chunk_mode) */

	if (hf_index == -1) {
		/*
		 * Not a header we know anything about.
		 * Check if a HF generated from UAT information exists.
		 */
		hf_id = get_hf_for_header(header_name);

		if (tree) {
			if (!hf_id) {
				if (http_type == MEDIA_CONTAINER_HTTP_REQUEST ||
					http_type == MEDIA_CONTAINER_HTTP_RESPONSE) {
					it = proto_tree_add_item(tree,
						http_type == MEDIA_CONTAINER_HTTP_RESPONSE ?
						hf_http_response_line :
						hf_http_request_line,
						tvb, offset, len,
						ENC_NA|ENC_ASCII);
					proto_item_set_text(it, "%s",
							format_text(pinfo->pool, line, len));
				} else {
					char* str = format_text(pinfo->pool, line, len);
					proto_tree_add_string_format(tree, hf_http_unknown_header, tvb, offset,
						len, str, "%s", str);
				}

			} else {
				proto_tree_add_string_format(tree,
					*hf_id, tvb, offset, len, value,
					"%s", format_text(pinfo->pool, line, len));
				if (http_type == MEDIA_CONTAINER_HTTP_REQUEST ||
					http_type == MEDIA_CONTAINER_HTTP_RESPONSE) {
					it = proto_tree_add_item(tree,
						http_type == MEDIA_CONTAINER_HTTP_RESPONSE ?
						hf_http_response_line :
						hf_http_request_line,
						tvb, offset, len,
						ENC_NA|ENC_ASCII);
					proto_item_set_text(it, "%s",
							format_text(pinfo->pool, line, len));
					proto_item_set_hidden(it);
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
			uint32_t tmp;

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
				tmp=(uint32_t)strtol(value, NULL, 10);
				hdr_item = proto_tree_add_uint(tree, *headers[hf_index].hf, tvb, offset, len, tmp);
				if (http_type == MEDIA_CONTAINER_HTTP_REQUEST ||
					http_type == MEDIA_CONTAINER_HTTP_RESPONSE) {
					it = proto_tree_add_item(tree,
						http_type == MEDIA_CONTAINER_HTTP_RESPONSE ?
						hf_http_response_line :
						hf_http_request_line,
						tvb, offset, len,
						ENC_NA|ENC_ASCII);
					proto_item_set_text(it, "%d", tmp);
					proto_item_set_hidden(it);
				}
				break;
			default:
				hdr_item = proto_tree_add_string_format(tree,
				    *headers[hf_index].hf, tvb, offset, len,
				    value,
				    "%s", format_text(pinfo->pool, line, len));
				if (http_type == MEDIA_CONTAINER_HTTP_REQUEST ||
					http_type == MEDIA_CONTAINER_HTTP_RESPONSE) {
					it = proto_tree_add_item(tree,
						http_type == MEDIA_CONTAINER_HTTP_RESPONSE ?
						hf_http_response_line :
						hf_http_request_line,
						tvb, offset, len,
						ENC_NA|ENC_ASCII);
					proto_item_set_text(it, "%s",
							format_text(pinfo->pool, line, len));
					proto_item_set_hidden(it);
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
			if (check_auth_basic(hdr_item, tvb, pinfo, value))
				break; /* dissected basic auth */
			if (check_auth_citrixbasic(hdr_item, tvb, pinfo, value, offset))
				break; /* dissected citrix basic auth */
			if (check_auth_kerberos(hdr_item, tvb, pinfo, value))
				break;
			if (check_auth_digest(hdr_item, tvb, pinfo, value, offset, value_len))
				break;/* dissected digest basic auth */
			auth = wmem_new0(pinfo->pool, tap_credential_t);
			auth->num = pinfo->num;
			auth->password_hf_id = *headers[hf_index].hf;
			auth->proto = "HTTP header auth";
			auth->username = wmem_strdup(pinfo->pool, TAP_CREDENTIALS_PLACEHOLDER);
			tap_queue_packet(credentials_tap, pinfo, auth);
			break;

		case HDR_AUTHENTICATE:
			if (check_auth_ntlmssp(hdr_item, tvb, pinfo, value))
				break; /* dissected NTLMSSP */
			check_auth_kerberos(hdr_item, tvb, pinfo, value);
			break;

		case HDR_CONTENT_TYPE:
			if (scope == NULL) { /* identical to (PINFO_FD_VISITED(pinfo) && streaming_chunk_mode) */
				break; /* eh_ptr->content_type[_parameters] must have been set during first scan */
			}
			eh_ptr->content_type = wmem_strdup(scope, value);

			for (f = 0; f < value_len; f++) {
				c = value[f];
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
				eh_ptr->content_type[f] = g_ascii_tolower(eh_ptr->content_type[f]);
			}
			eh_ptr->content_type[f] = '\0';
			/*
			 * Now find the start of the optional parameters;
			 * skip the optional white space and the semicolon
			 * if this has not been done before.
			 */
			f++;
			while (f < value_len) {
				c = eh_ptr->content_type[f];
				if (c == ';' || g_ascii_isspace(c))
					/* Skip till start of parameters */
					f++;
				else
					break;
			}
			if (f < value_len)
				eh_ptr->content_type_parameters = eh_ptr->content_type + f;
			else
				eh_ptr->content_type_parameters = NULL;
			break;

		case HDR_CONTENT_LENGTH:
			DISSECTOR_ASSERT_HINT(!streaming_chunk_mode, "In streaming chunk mode, there will never be content-length header.");
			errno = 0;
			eh_ptr->content_length = g_ascii_strtoll(value, &p, 10);
			up = (unsigned char *)p;
			if (eh_ptr->content_length < 0 ||
			    p == value ||
			    errno == ERANGE ||
			    (*up != '\0' && !g_ascii_isspace(*up))) {
				/*
				 * Content length not valid; pretend
				 * we don't have it.
				 */
				eh_ptr->have_content_length = false;
			} else {
				proto_tree *header_tree;
				proto_item *tree_item;
				/*
				 * We do have a valid content length.
				 */
				eh_ptr->have_content_length = true;
				header_tree = proto_item_add_subtree(hdr_item, ett_http_header_item);
				tree_item = proto_tree_add_uint64(header_tree, hf_http_content_length,
					tvb, offset, len, eh_ptr->content_length);
				proto_item_set_generated(tree_item);
				if (eh_ptr->transfer_encoding != HTTP_TE_NONE) {
					expert_add_info(pinfo, hdr_item, &ei_http_te_and_length);
				}
			}
			break;

		case HDR_CONTENT_ENCODING:
			if (scope == NULL) { /* identical to (PINFO_FD_VISITED(pinfo) && streaming_chunk_mode) */
				break; /* eh_ptr->content_encoding must have been set during first scan */
			}
			eh_ptr->content_encoding = wmem_strndup(scope, value, value_len);
			break;

		case HDR_TRANSFER_ENCODING:
			if (eh_ptr->have_content_length) {
				expert_add_info(pinfo, hdr_item, &ei_http_te_and_length);
			}
			if (!http_parse_transfer_coding(value, eh_ptr)) {
				expert_add_info(pinfo, hdr_item, &ei_http_te_unknown);
			}
			break;

		case HDR_HOST:
			stat_info->http_host = wmem_strndup(pinfo->pool, value, value_len);
			if (!PINFO_FD_VISITED(pinfo) && curr_req_res) {
				curr_req_res->http_host = wmem_strndup(wmem_file_scope(), value, value_len);
			}
			break;

		case HDR_UPGRADE:
			if (scope == NULL) { /* identical to (PINFO_FD_VISITED(pinfo) && streaming_chunk_mode) */
				break;
			}
			eh_ptr->upgrade = wmem_ascii_strdown(scope, value, value_len);
			break;

		case HDR_COOKIE:
			if (hdr_item) {
				proto_tree *cookie_tree;
				char *part, *part_end;
				int part_len;

				cookie_tree = proto_item_add_subtree(hdr_item, ett_http_header_item);
				for (f = 0; f < value_len; ) {
					/* skip whitespace and ';' (terminates at '\0' or earlier) */
					c = value[f];
					while (c == ';' || g_ascii_isspace(c))
						c = value[++f];

					if (f >= value_len)
						break;

					/* find "cookie=foo " in "cookie=foo ; bar" */
					part = value + f;
					part_end = (char *)memchr(part, ';', value_len - f);
					if (part_end)
						part_len =(int)(part_end - part);
					else
						part_len = value_len - f;

					/* finally add cookie to tree */
					proto_tree_add_item(cookie_tree, hf_http_cookie_pair,
						tvb, value_offset + f, part_len, ENC_NA|ENC_ASCII);
					f += part_len;
				}
			}
			break;

		case HDR_WEBSOCKET_PROTOCOL:
			if (http_type == MEDIA_CONTAINER_HTTP_RESPONSE) {
				conv_data->websocket_protocol = wmem_strndup(wmem_file_scope(), value, value_len);
			}
			break;

		case HDR_WEBSOCKET_EXTENSIONS:
			if (http_type == MEDIA_CONTAINER_HTTP_RESPONSE) {
				conv_data->websocket_extensions = wmem_strndup(wmem_file_scope(), value, value_len);
			}
			break;

		case HDR_REFERER:
			stat_info->referer_uri = wmem_strndup(pinfo->pool, value, value_len);
			break;

		case HDR_LOCATION:
			if (curr_req_res && curr_req_res->request_uri){
				stat_info->location_target = wmem_strndup(pinfo->pool, value, value_len);
				stat_info->location_base_uri = wmem_strdup(pinfo->pool, curr_req_res->full_uri);
			}
			break;
		case HDR_HTTP2_SETTINGS:
		{
			proto_tree* settings_tree = proto_item_add_subtree(hdr_item, ett_http_http2_settings_item);
			tvbuff_t* new_tvb = base64uri_tvb_to_new_tvb(tvb, value_offset, value_bytes_len);
			add_new_data_source(pinfo, new_tvb, "Base64uri decoded");
			TRY{
				dissect_http2_settings_ext(new_tvb, pinfo, settings_tree, 0);
			} CATCH_ALL{
				show_exception(tvb, pinfo, settings_tree, EXCEPT_CODE, GET_MESSAGE);
			}
			ENDTRY;

			break;
		}
		case HDR_RANGE:
			{
			/* THIS IS A GET REQUEST
			 *  Note: GET is the only method that employs ranges.
			 *  (Unless the data has errors or is noncompliant.)
			 */
			if (curr_req_res && !pinfo->fd->visited) {
			 /*
			 *  Unlike protocols such as NFS and SMB, the HTTP protocol (RFC 9110) does not
			 *  provide an identifier with which to match requests and responses. Instead,
			 *  matching is solely based upon the order in which responses are received.
			 *  HTTP I/O is 'asynchronously ordered' such that, for example, the first of four
			 *  GET responses are matched with the first outstanding request, the next
			 *  response with the second oldest outstanding request and so on (FIFO).
			 *  The previous method instead matched responses with the last of several
			 *  async requests rather than the first (LIFO), and did not handle requests
			 *  with no responses such as the case where one or more HTTP packets were
			 *  not captured. Whenever there were multiple outstanding requests, the SRT
			 *  (RTT) stats were incorrect, in some cases massively so.
			 *
			 *  While RFC 9110 expressly prohibits matching via byte ranges because, among
			 *  other things, the server may return fewer bytes than requested,
			 *  the first number of the range does not change. Unlike HTTP implementations,
			 *  Wireshark has the problem of requests/responses missing from the capture
			 *  file. In such cases resumption of correct matching was virtually impossible.
			 *  In addition, all matching was incorrect from that point on.
			 *
			 *  The method of matching used herein is able to recover from packet loss,
			 *  any number of missing frames, and duplicate range requests. The
			 *  method used is explained within the comments.
			 */
			/* https://www.rfc-editor.org/rfc/rfc9110.html#name-range-requests
			 * Note that RFC 9110 16.5 defines a registry for
			 * range units, but only bytes are registered.
			 * ABNF:
			 * Range = ranges-specifier
			 * ranges-specifier = range-unit "=" range-set
			 * range-set        = 1#range-spec
			 * range-spec       = int-range / suffix-range / other-range
			 * 1# is an ABNF extension defined in RFC 9110 5.6.1
			 * which covers comma separated list with optional
			 * white space:
			 * 1#element => element *( OWS "," OWS element )
			 * We don't care about other-range, but will try to
			 * handle int-range and suffix-range.
			 * This ignores any entries past the first in a list,
			 * though responses to such would be multipart.
			 * As mentioned above, this breaks down if the
			 * response does not include all requested ranges
			 * fully in one response.
			 */
			const char *pos = strchr(value, '=');
			if (pos == NULL) {
				break;
			}
			pos++;
			uint64_t first_range_num = 0;
			/* Get the first range number */
			ws_strtou64(pos, &pos, &first_range_num);
			/* If the first number of the range is missing or '0',
			 * use the second number in the range instead if we can.
			 * XXX - Unlike strtoul, we can check the return value
			 * of ws_strtou64() to distinguish between "converted
			 * successfully as 0" and "failed conversion."
			 * Note that strtoul allows an unsigned integer to
			 * begin with a negative sign and applies unsigned
			 * integer wraparound rules.
			 * ws_strtouXX rejects an initial hyphen-minus, which
			 * is good, as we want to properly handle:
			 * 	suffix-range = "-" suffix-length
			 */
			if (first_range_num == 0 && *pos == '-') {
				pos++;
				/* Pass in an end pointer to convert
				 * a list of ranges, the first of which is
				 * a suffix-range.
				 */
				ws_strtou64(pos, &pos, &first_range_num);
			}
			/* req_list is used for req/resp matching and the deletion (and freeing) of matching
			*  requests and any orphans that preceed them. A GSList is used instead of a wmem map
			*  because there are rarely more than 10 requests in the list."
			*/
			if (first_range_num > 0) {
				request_trans_t* req_trans = wmem_new(wmem_file_scope(), request_trans_t);
				req_trans->first_range_num = first_range_num;
				req_trans->req_frame = pinfo->num;
				req_trans->abs_time = pinfo->fd->abs_ts;
				req_trans->request_uri = curr_req_res->request_uri;

				/* XXX - This leaks if matching responses aren't
				 * found (the data does not, but the list node
				 * does.) A wmem_list would prevent that.
				 */
				conv_data->req_list = g_slist_append(conv_data->req_list, GUINT_TO_POINTER(req_trans));
				curr_req_res->req_has_range = true;
			}
			}

			break;
			}
		case HDR_CONTENT_RANGE:
			/*
			 * THIS IS A GET RESPONSE
			 * GET is the only method that employs ranges.
			 * XXX - Except that RFC 9110 14.4 & 14.5 note that by
			 * private agreement it can be included in a request
			 * to request a partial PUT.
			 * ABNF:
			 * Content-Range     = range-unit SP ( range-resp / unsatisfied-range )
			 * range-resp        = incl-range "/" ( complete-length / "*" )
			 * We do not attempt to handle unsatisfied-range.
			 * Note that only one range can be included; multiple
			 * ranges are transmitted with the media type of
			 * "multipart/byteranges" and each body part contains
			 * its own Content-Type and Content-Range fields.
			 * The multipart dissector does not handle this nor
			 * access the request list.
			 */
			if (curr_req_res && !pinfo->fd->visited) {
				request_trans_t *req_trans;
				match_trans_t *match_trans = NULL;
				nstime_t  ns;
				GSList *iter = NULL;

				/* Note SP instead of '=' in ABNF. */
				const char *pos = strchr(value, ' ');
				if (pos == NULL) {
					break;
				}
				pos++;
				uint64_t first_crange_num = 0;
				/* Get the first content range number */
				ws_strtou64(pos, &pos, &first_crange_num);

				if (first_crange_num == 0 && *pos == '-') {
					pos++;
					ws_strtou64(pos, &pos, &first_crange_num);
				}

				/* Get the position of the matching request if any in the reqs_table.
				* This is used to remove and free the matching request, and the unmatched
				* requests (orphans) that preceed it.
				* XXX - There is *NO* guarantee that there is
				* a perfectly matching request, see 15.3.7:
				* "However, a server might want to send only a
				* subset of the data requested for reasons of
				* its own... A client MUST inspect a 206
				* response's Content-Type and Content-Range
				* field(s) to determine what parts are enclosed
				* and whether additional requests are needed."
				* Also 15.3.7.2 Multiple Parts, noting that
				* the response may be sent in a Content-Type
				* multipart/byteranges, also "When multiple
				* ranges are requested, a server MAY coalesce
				* any of the ranges that overlap, or that are
				* separated by a gap that is smaller than the
				* overhead of sending multiple parts, regardless
				* of the order in which the corresponding range-
				* spec appeared in the received Range header
				* field." and 15.3.7.3 Combining Parts.
				* However, as mentioned above, the LIFO method
				* had issues with that as well. Truly proper
				* handling of such edge cases is more difficult.
				*/
				req_trans = NULL;
				if (conv_data->req_list && conv_data->req_list->data) {
					for (iter = conv_data->req_list; iter; iter = iter->next) {
						if (((request_trans_t*)iter->data)->first_range_num == first_crange_num) {
							req_trans = iter->data;
							break;
						}
					}
				}

				if (first_crange_num != 0 && req_trans) {
					match_trans = wmem_new(wmem_file_scope(), match_trans_t);
					match_trans->req_frame = req_trans->req_frame;
					match_trans->resp_frame = pinfo->num;
					nstime_delta(&ns, &pinfo->fd->abs_ts, &req_trans->abs_time);
					match_trans->delta_time = ns;
					match_trans->request_uri = req_trans->request_uri;
					match_trans->http_host = curr_req_res->http_host;

					wmem_map_insert(conv_data->matches_table,
						GUINT_TO_POINTER(match_trans->req_frame), (void *)match_trans);
					wmem_map_insert(conv_data->matches_table,
						GUINT_TO_POINTER(match_trans->resp_frame), (void *)match_trans);

					/* Remove and free all of the list entries up to and including the
					*  matching one from req_list. */
					if (conv_data->req_list) {
						GSList *top_of_list = NULL;

						top_of_list = conv_data->req_list;
						while (top_of_list && top_of_list->data != req_trans) {

						    top_of_list = g_slist_delete_link(top_of_list, top_of_list);
						}
						if (top_of_list && top_of_list->data == req_trans) {

						    top_of_list = g_slist_delete_link(top_of_list, top_of_list);
						}
						conv_data->req_list = top_of_list;
					}
				}
			}
			if (curr_req_res)
				curr_req_res->resp_has_range = true;
			break;
		}
	}
	return true;
}

/* Returns index of header tag in headers */
static int
find_header_hf_value(tvbuff_t *tvb, int offset, unsigned header_len)
{
	unsigned i;

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
static bool
check_auth_ntlmssp(proto_item *hdr_item, tvbuff_t *tvb, packet_info *pinfo, char *value)
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
			return true;
		}
	}
	return false;
}

static tap_credential_t*
basic_auth_credentials(wmem_allocator_t *scope, const char* str)
{
	char **tokens = g_strsplit(str, ":", -1);

	if (!tokens || !tokens[0] || !tokens[1]) {
		g_strfreev(tokens);
		return NULL;
	}

	tap_credential_t* auth = wmem_new0(scope, tap_credential_t);

	auth->username = wmem_strdup(scope, tokens[0]);
	auth->proto = "HTTP basic auth";

	g_strfreev(tokens);

	return auth;
}

/*
 * Dissect HTTP Basic authorization.
 */
static bool
check_auth_basic(proto_item *hdr_item, tvbuff_t *tvb, packet_info *pinfo, char *value)
{
	static const char *basic_headers[] = {
		"Basic ",
		NULL
	};
	const char **header;
	size_t hdrlen;
	const uint8_t *decoded_value;
	proto_tree *hdr_tree;
	tvbuff_t *auth_tvb;

	for (header = &basic_headers[0]; *header != NULL; header++) {
		hdrlen = strlen(*header);
		if (strncmp(value, *header, hdrlen) == 0) {
			if (hdr_item != NULL) {
				hdr_tree = proto_item_add_subtree(hdr_item,
				    ett_http_ntlmssp);
			} else
				hdr_tree = NULL;
			value += hdrlen;

			auth_tvb = base64_to_tvb(tvb, value);
			add_new_data_source(pinfo, auth_tvb, "Basic Credentials");
			/* RFC 7617 says that the character encoding is only
			 * known to be UTF-8 if the 'charset' parameter was
			 * used. Otherwise, after Base64 decoding it could be
			 * any character encoding.
			 * XXX: Perhaps the field should be a FT_BYTES with
			 * BASE_SHOW_UTF_8_PRINTABLE?
			 */
			proto_tree_add_item_ret_string(hdr_tree, hf_http_basic, auth_tvb, 0, tvb_reported_length(auth_tvb), ENC_UTF_8, pinfo->pool, &decoded_value);
			tap_credential_t* auth = basic_auth_credentials(pinfo->pool, decoded_value);
			if (auth) {
				auth->num = auth->username_num = pinfo->num;
				auth->password_hf_id = hf_http_basic;
				tap_queue_packet(credentials_tap, pinfo, auth);
			}

			return true;
		}
	}
	return false;
}

/*
 * Dissect HTTP Digest authorization.
 */
static bool
check_auth_digest(proto_item* hdr_item, tvbuff_t* tvb, packet_info* pinfo _U_, char* value, int offset, int len)
{
	proto_tree* hdr_tree;
	int queried_offset;

	if (strncmp(value, "Digest", 6) == 0) {
		if (hdr_item != NULL) {
			hdr_tree = proto_item_add_subtree(hdr_item, ett_http_ntlmssp);
		} else {
			hdr_tree = NULL;
		}
		offset += 21;
		len -= 21;
		while (len > 0) {
			/* Find comma/end of line */
			queried_offset = tvb_find_guint8(tvb, offset, len, ',');
			if (queried_offset > 0) {
				proto_tree_add_format_text(hdr_tree, tvb, offset, queried_offset - offset);
				len -= (queried_offset - offset);
				offset = queried_offset + 1;
			} else {
				len = 0;
			}
		}
		return true;
	} else {
		return false;
	}
}
/*
 * Dissect HTTP CitrixAGBasic authorization.
 */
static bool
check_auth_citrixbasic(proto_item *hdr_item, tvbuff_t *tvb, packet_info *pinfo, char *value, int offset)
{
	static const char *basic_headers[] = {
		"CitrixAGBasic ",
		NULL
	};
	const char **header;
	size_t hdrlen;
	proto_tree *hdr_tree;
	char *ch_ptr;
	int data_len;
	tvbuff_t *data_tvb;
	proto_item *hidden_item;
	proto_item *pi;
	const uint8_t *user = NULL, *passwd = NULL;

	for (header = &basic_headers[0]; *header != NULL; header++) {
		hdrlen = strlen(*header);
		if (strncmp(value, *header, hdrlen) == 0) {
			if (hdr_item != NULL) {
				hdr_tree = proto_item_add_subtree(hdr_item,
				    ett_http_ntlmssp);
			} else
				hdr_tree = NULL;
			value += hdrlen;
			offset += (int)hdrlen + 15;
			hidden_item = proto_tree_add_boolean(hdr_tree,
					    hf_http_citrix, tvb, 0, 0, 1);
			proto_item_set_hidden(hidden_item);

			if(strncmp(value, "username=\"", 10) == 0) {
				value += 10;
				offset += 10;
				ch_ptr = strchr(value, '"');
				if ( ch_ptr != NULL ) {
					data_len = (int)(ch_ptr - value);
					if (data_len) {
						data_tvb = base64_tvb_to_new_tvb(tvb, offset, data_len);
						add_new_data_source(pinfo, data_tvb, "Username");
						/* XXX: We don't know for certain the string encoding here. */
						pi = proto_tree_add_item_ret_string(hdr_tree, hf_http_citrix_user, data_tvb, 0, tvb_reported_length(data_tvb), ENC_UTF_8, pinfo->pool, &user);
					} else {
						pi = proto_tree_add_string(hdr_tree, hf_http_citrix_user, tvb, offset, 0, "");
					}
					proto_item_set_generated(pi);
					value += data_len + 1;
					offset += data_len + 1;
				}
			}
			if(strncmp(value, "; domain=\"", 10) == 0) {
				value += 10;
				offset += 10;
				ch_ptr = strchr(value, '"');
				if ( ch_ptr != NULL ) {
					data_len = (int)(ch_ptr - value);
					if (data_len) {
						data_tvb = base64_tvb_to_new_tvb(tvb, offset, data_len);
						add_new_data_source(pinfo, data_tvb, "Domain");
						pi = proto_tree_add_item(hdr_tree, hf_http_citrix_domain, data_tvb, 0, tvb_reported_length(data_tvb), ENC_UTF_8);
					} else {
						pi = proto_tree_add_string(hdr_tree, hf_http_citrix_domain, tvb, offset, 0, "");
					}
					proto_item_set_generated(pi);
					value += data_len + 1;
					offset += data_len + 1;
				}
			}
			if(strncmp(value, "; password=\"", 12) == 0) {
				value += 12;
				offset += 12;
				ch_ptr = strchr(value, '"');
				if ( ch_ptr != NULL ) {
					data_len = (int)(ch_ptr - value);
					if (data_len) {
						data_tvb = base64_tvb_to_new_tvb(tvb, offset, data_len);
						add_new_data_source(pinfo, data_tvb, "Password");
						pi = proto_tree_add_item_ret_string(hdr_tree, hf_http_citrix_passwd, data_tvb, 0, tvb_reported_length(data_tvb), ENC_UTF_8, pinfo->pool, &passwd);
					} else {
						pi = proto_tree_add_string(hdr_tree, hf_http_citrix_passwd, tvb, offset, 0, "");
					}
					proto_item_set_generated(pi);
					value += data_len + 1;
					offset += data_len + 1;
				}
			}
			if(strncmp(value, "; AGESessionId=\"", 16) == 0) {
				value += 16;
				offset += 16;
				ch_ptr = strchr(value, '"');
				if ( ch_ptr != NULL ) {
					data_len = (int)(ch_ptr - value);
					if (data_len) {
						data_tvb = base64_tvb_to_new_tvb(tvb, offset, data_len);
						add_new_data_source(pinfo, data_tvb, "Session ID");
						pi = proto_tree_add_item(hdr_tree, hf_http_citrix_session, data_tvb, 0, tvb_reported_length(data_tvb), ENC_UTF_8);
					} else {
						pi = proto_tree_add_string(hdr_tree, hf_http_citrix_session, tvb,
						    offset, 0, "");
					}
					proto_item_set_generated(pi);
				}
			}
			if (user != NULL && passwd != NULL) {

				tap_credential_t* auth = wmem_new0(pinfo->pool, tap_credential_t);

				auth->username = wmem_strdup(pinfo->pool, user);
				auth->proto = "HTTP CitrixAGBasic auth";
				auth->num = auth->username_num = pinfo->num;
				auth->password_hf_id = hf_http_citrix_passwd;
				tap_queue_packet(credentials_tap, pinfo, auth);
			}
			return true;
		}
	}
	return false;
}

static bool
check_auth_kerberos(proto_item *hdr_item, tvbuff_t *tvb, packet_info *pinfo, const char *value)
{
	proto_tree *hdr_tree;

	if (strncmp(value, "Kerberos ", 9) == 0) {
		if (hdr_item != NULL) {
			hdr_tree = proto_item_add_subtree(hdr_item, ett_http_kerberos);
		} else
			hdr_tree = NULL;

		dissect_http_kerberos(tvb, pinfo, hdr_tree, value);
		return true;
	}
	return false;
}

static int
dissect_http_on_stream(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    http_conv_t *conv_data, bool end_of_stream, const uint32_t *seq)
{
	int		offset = 0;
	int		len = 0;

	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		/* Switch protocol if the data starts after response headers. */
		if (conv_data->startframe &&
				(pinfo->num > conv_data->startframe ||
				(pinfo->num == conv_data->startframe && offset >= conv_data->startoffset))) {
			/* Increase pinfo->can_desegment because we are traversing
			 * http and want to preserve desegmentation functionality for
			 * the proxied protocol
			 */
			if (pinfo->can_desegment > 0)
				pinfo->can_desegment++;
			if (conv_data->next_handle) {
				call_dissector_only(conv_data->next_handle, tvb_new_subset_remaining(tvb, offset), pinfo, tree, NULL);
			} else {
				call_data_dissector(tvb_new_subset_remaining(tvb, offset), pinfo, tree);
			}
			/*
			 * If a subdissector requests reassembly, be sure not to
			 * include the preceding HTTP headers.
			 */
			if (pinfo->desegment_len) {
				pinfo->desegment_offset += offset;
			}
			break;
		}
		len = dissect_http_message(tvb, offset, pinfo, tree, conv_data, "HTTP", proto_http, end_of_stream, seq);
		if (len < 0)
			break;
		offset += len;

		/*
		 * OK, we've set the Protocol and Info columns for the
		 * first HTTP message; set a fence so that subsequent
		 * HTTP messages don't overwrite the Info column.
		 */
		col_set_fence(pinfo->cinfo, COL_INFO);
	}
	/* dissect_http_message() returns -2 if message is not valid HTTP */
	return (len == -2)
		? 0
		: (int)tvb_captured_length(tvb);
}

static int
dissect_http_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	struct tcpinfo *tcpinfo = (struct tcpinfo *)data;
	conversation_t *conversation;
	http_conv_t *conv_data;
	bool end_of_stream;

	conv_data = get_http_conversation_data(pinfo, &conversation);

	/* Call HTTP2 dissector directly when detected via heuristics, but not
	 * when it was upgraded (the conversation started with HTTP). */
	if (conversation_get_proto_data(conversation, proto_http2) &&
	    !conv_data->startframe) {
		if (pinfo->can_desegment > 0)
			pinfo->can_desegment++;
		return call_dissector_only(http2_handle, tvb, pinfo, tree, data);
	}

	/*
	 * Check if this is proxied connection and if so, hand of dissection to the
	 * payload-dissector.
	 * Response code 200 means "OK" and strncmp() == 0 means the strings match exactly */
	http_req_res_t *curr_req_res = conv_data->req_res_tail;
	if(pinfo->num >= conv_data->startframe &&
	   curr_req_res &&
	   curr_req_res->response_code == 200 &&
	   curr_req_res->request_method &&
	   strncmp(curr_req_res->request_method, "CONNECT", 7) == 0 &&
	   curr_req_res->request_uri) {
		if (conv_data->startframe == 0 && !PINFO_FD_VISITED(pinfo)) {
			conv_data->startframe = pinfo->num;
			conv_data->startoffset = 0;
			copy_address_wmem(wmem_file_scope(), &conv_data->server_addr, &pinfo->dst);
			conv_data->server_port = pinfo->destport;
		}
		http_payload_subdissector(tvb, tree, pinfo, conv_data, data);

		return tvb_captured_length(tvb);
	}

	/* XXX - how to detect end-of-stream without tcpinfo */
	end_of_stream = (tcpinfo && IS_TH_FIN(tcpinfo->flags));
	return dissect_http_on_stream(tvb, pinfo, tree, conv_data, end_of_stream, tcpinfo ? &tcpinfo->seq : NULL);
}

static bool
dissect_http_heur_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	int offset = 0, next_offset, linelen;
	conversation_t  *conversation;


	/* Check if we have a line terminated by CRLF
	 * Return the length of the line (not counting the line terminator at
	 * the end), or, if we don't find a line terminator:
	 *
	 *	if "deseg" is true, return -1;
	 */
	linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, true);
	if((linelen == -1)||(linelen == 8)){
		return false;
	}

	/* Check if the line start or ends with the HTTP token */
	if((tvb_strncaseeql(tvb, linelen-8, "HTTP/1.", 7) == 0)||(tvb_strncaseeql(tvb, 0, "HTTP/1.", 7) == 0)){
		conversation = find_or_create_conversation(pinfo);
		conversation_set_dissector_from_frame_number(conversation, pinfo->num, http_tcp_handle);
		dissect_http_tcp(tvb, pinfo, tree, data);
		return true;
	}

	return false;
}

static int
dissect_http_tls(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	conversation_t *conversation;
	http_conv_t *conv_data;
	bool end_of_stream;

	conv_data = get_http_conversation_data(pinfo, &conversation);

	struct tlsinfo *tlsinfo = (struct tlsinfo *)data;
	end_of_stream = (tlsinfo && tlsinfo->end_of_stream);
	return dissect_http_on_stream(tvb, pinfo, tree, conv_data, end_of_stream, tlsinfo ? &tlsinfo->seq : NULL);
}

static bool
dissect_http_heur_tls(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	int offset = 0, next_offset, linelen;
	conversation_t  *conversation;
	http_conv_t	*conv_data;

	conversation = find_or_create_conversation(pinfo);
	conv_data = (http_conv_t *)conversation_get_proto_data(conversation, proto_http);
	/* A http conversation was previously started, assume it is still active */
	if (conv_data) {
		dissect_http_tls(tvb, pinfo, tree, data);
		return true;
	}

	/* Check if we have a line terminated by CRLF
	 * Return the length of the line (not counting the line terminator at
	 * the end), or, if we don't find a line terminator:
	 *
	 *	if "deseg" is true, return -1;
	 */
	linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, true);
	if((linelen == -1)||(linelen == 8)){
		return false;
	}

	/* Check if the line start or ends with the HTTP token */
	if((tvb_strncaseeql(tvb, linelen-8, "HTTP/1.", 7) != 0) && (tvb_strncaseeql(tvb, 0, "HTTP/1.", 7) != 0)) {
	        /* we couldn't find the Magic Hello HTTP/1.X. */
		return false;
	}

	dissect_http_tls(tvb, pinfo, tree, data);
	return true;
}

static int
dissect_http_sctp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	conversation_t *conversation;
	http_conv_t *conv_data;

	conv_data = get_http_conversation_data(pinfo, &conversation);

	/*
	 * XXX - we need to provide an end-of-stream indication.
	 */
	return dissect_http_on_stream(tvb, pinfo, tree, conv_data, false, NULL);
}

static int
dissect_http(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	conversation_t *conversation;
	http_conv_t *conv_data;

	conv_data = get_http_conversation_data(pinfo, &conversation);

	/*
	 * XXX - what should be done about reassembly, pipelining, etc.
	 * here?
	 */
	return dissect_http_on_stream(tvb, pinfo, tree, conv_data, false, NULL);
}

static int
dissect_ssdp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	conversation_t  *conversation;
	http_conv_t	*conv_data;

	conv_data = get_http_conversation_data(pinfo, &conversation);
	dissect_http_message(tvb, 0, pinfo, tree, conv_data, "SSDP", proto_ssdp, false, NULL);
	return tvb_captured_length(tvb);
}

static void
range_delete_http_tls_callback(uint32_t port, void *ptr _U_) {
	ssl_dissector_delete(port, http_tls_handle);
}

static void
range_add_http_tls_callback(uint32_t port, void *ptr _U_) {
	ssl_dissector_add(port, http_tls_handle);
}

static void reinit_http(void) {
	http_tcp_range = prefs_get_range_value("http", "tcp.port");

	http_sctp_range = prefs_get_range_value("http", "sctp.port");

	range_foreach(http_tls_range, range_delete_http_tls_callback, NULL);
	wmem_free(wmem_epan_scope(), http_tls_range);
	http_tls_range = range_copy(wmem_epan_scope(), global_http_tls_range);
	range_foreach(http_tls_range, range_add_http_tls_callback, NULL);
}

void
proto_register_http(void)
{
	static hf_register_info hf[] = {
	    { &hf_http_notification,
	      { "Notification", "http.notification",
		FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		"true if HTTP notification", HFILL }},
	    { &hf_http_response,
	      { "Response", "http.response",
		FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		"true if HTTP response", HFILL }},
	    { &hf_http_request,
	      { "Request", "http.request",
		FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		"true if HTTP request", HFILL }},
	    { &hf_http_basic,
	      { "Credentials", "http.authbasic",
		FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	    { &hf_http_citrix,
	      { "Citrix AG Auth", "http.authcitrix",
		FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		"true if CitrixAGBasic Auth", HFILL }},
	    { &hf_http_citrix_user,
	      { "Citrix AG Username", "http.authcitrix.user",
		FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	    { &hf_http_citrix_domain,
	      { "Citrix AG Domain", "http.authcitrix.domain",
		FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	    { &hf_http_citrix_passwd,
	      { "Citrix AG Password", "http.authcitrix.password",
		FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	    { &hf_http_citrix_session,
	      { "Citrix AG Session ID", "http.authcitrix.session",
		FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	    { &hf_http_response_line,
	      { "Response line", "http.response.line",
		FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	    { &hf_http_request_line,
	      { "Request line", "http.request.line",
		FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	    { &hf_http_request_method,
	      { "Request Method", "http.request.method",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Request Method", HFILL }},
	    { &hf_http_request_uri,
	      { "Request URI", "http.request.uri",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Request-URI", HFILL }},
	    { &hf_http_request_path,
	      { "Request URI Path", "http.request.uri.path",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Request-URI Path", HFILL }},
	    { &hf_http_request_path_segment,
	      { "Request URI Path Segment", "http.request.uri.path.segment",
		FT_STRING, BASE_NONE, NULL, 0,
		NULL, HFILL } },
	    { &hf_http_request_query,
	      { "Request URI Query", "http.request.uri.query",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Request-URI Query", HFILL }},
	    { &hf_http_request_query_parameter,
	      { "Request URI Query Parameter", "http.request.uri.query.parameter",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Request-URI Query Parameter", HFILL }},
	    { &hf_http_request_version,
	      { "Request Version", "http.request.version",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Request HTTP-Version", HFILL }},
	    { &hf_http_response_version,
	      { "Response Version", "http.response.version",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Response HTTP-Version", HFILL }},
	    { &hf_http_request_full_uri,
	      { "Full request URI", "http.request.full_uri",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"The full requested URI (including host name)", HFILL }},
	    { &hf_http_response_code,
	      { "Status Code", "http.response.code",
		FT_UINT24, BASE_DEC, NULL, 0x0,
		"HTTP Response Status Code", HFILL }},
	    { &hf_http_response_code_desc,
	      { "Status Code Description", "http.response.code.desc",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Response Status Code Description", HFILL }},
	    { &hf_http_response_phrase,
	      { "Response Phrase", "http.response.phrase",
	        FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Response Reason Phrase", HFILL }},
	    { &hf_http_authorization,
	      { "Authorization", "http.authorization",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Authorization header", HFILL }},
	    { &hf_http_proxy_authenticate,
	      { "Proxy-Authenticate", "http.proxy_authenticate",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Proxy-Authenticate header", HFILL }},
	    { &hf_http_proxy_authorization,
	      { "Proxy-Authorization", "http.proxy_authorization",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Proxy-Authorization header", HFILL }},
	    { &hf_http_proxy_connect_host,
	      { "Proxy-Connect-Hostname", "http.proxy_connect_host",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Proxy Connect Hostname", HFILL }},
	    { &hf_http_proxy_connect_port,
	      { "Proxy-Connect-Port", "http.proxy_connect_port",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		"HTTP Proxy Connect Port", HFILL }},
	    { &hf_http_www_authenticate,
	      { "WWW-Authenticate", "http.www_authenticate",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP WWW-Authenticate header", HFILL }},
	    { &hf_http_content_type,
	      { "Content-Type", "http.content_type",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Content-Type header", HFILL }},
	    { &hf_http_content_length_header,
	      { "Content-Length", "http.content_length_header",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Content-Length header", HFILL }},
	    { &hf_http_content_length,
	      { "Content length", "http.content_length",
		FT_UINT64, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},
	    { &hf_http_content_encoding,
	      { "Content-Encoding", "http.content_encoding",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Content-Encoding header", HFILL }},
	    { &hf_http_transfer_encoding,
	      { "Transfer-Encoding", "http.transfer_encoding",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Transfer-Encoding header", HFILL }},
	    { &hf_http_upgrade,
	      { "Upgrade", "http.upgrade",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Upgrade header", HFILL }},
	    { &hf_http_user_agent,
	      { "User-Agent", "http.user_agent",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP User-Agent header", HFILL }},
	    { &hf_http_host,
	      { "Host", "http.host",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Host", HFILL }},
	    { &hf_http_range,
	      { "Range", "http.range",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Range", HFILL }},
	    { &hf_http_content_range,
	      { "Content-Range", "http.content_range",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Content-Range", HFILL }},
	    { &hf_http_connection,
	      { "Connection", "http.connection",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Connection", HFILL }},
	    { &hf_http_cookie,
	      { "Cookie", "http.cookie",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Cookie", HFILL }},
	    { &hf_http_cookie_pair,
	      { "Cookie pair", "http.cookie_pair",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"A name/value HTTP cookie pair", HFILL }},
	    { &hf_http_accept,
	      { "Accept", "http.accept",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Accept", HFILL }},
	    { &hf_http_referer,
	      { "Referer", "http.referer",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Referer", HFILL }},
	    { &hf_http_accept_language,
	      { "Accept-Language", "http.accept_language",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Accept Language", HFILL }},
	    { &hf_http_accept_encoding,
	      { "Accept Encoding", "http.accept_encoding",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Accept Encoding", HFILL }},
	    { &hf_http_date,
	      { "Date", "http.date",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Date", HFILL }},
	    { &hf_http_cache_control,
	      { "Cache-Control", "http.cache_control",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Cache Control", HFILL }},
	    { &hf_http_server,
	      { "Server", "http.server",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Server", HFILL }},
	    { &hf_http_location,
	      { "Location", "http.location",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Location", HFILL }},
	    { &hf_http_sec_websocket_accept,
	      { "Sec-WebSocket-Accept", "http.sec_websocket_accept",
		FT_STRING, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},
	    { &hf_http_sec_websocket_extensions,
	      { "Sec-WebSocket-Extensions", "http.sec_websocket_extensions",
		FT_STRING, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},
	    { &hf_http_sec_websocket_key,
	      { "Sec-WebSocket-Key", "http.sec_websocket_key",
		FT_STRING, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},
	    { &hf_http_sec_websocket_protocol,
	      { "Sec-WebSocket-Protocol", "http.sec_websocket_protocol",
		FT_STRING, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},
	    { &hf_http_sec_websocket_version,
	      { "Sec-WebSocket-Version", "http.sec_websocket_version",
		FT_STRING, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},
	    { &hf_http_set_cookie,
	      { "Set-Cookie", "http.set_cookie",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Set Cookie", HFILL }},
	    { &hf_http_last_modified,
	      { "Last-Modified", "http.last_modified",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Last Modified", HFILL }},
	    { &hf_http_x_forwarded_for,
	      { "X-Forwarded-For", "http.x_forwarded_for",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP X-Forwarded-For", HFILL }},
	    { &hf_http_http2_settings,
	      { "HTTP2-Settings", "http.http2_settings",
		FT_STRING, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},
	    { &hf_http_request_in,
	      { "Request in frame", "http.request_in",
		FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0,
		"This packet is a response to the packet with this number", HFILL }},
	    { &hf_http_response_in,
	      { "Response in frame", "http.response_in",
		FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0,
		"This packet will be responded in the packet with this number", HFILL }},
	    { &hf_http_time,
	      { "Time since request", "http.time",
		FT_RELATIVE_TIME, BASE_NONE, NULL, 0,
		"Time since the request was sent", HFILL }},
	    { &hf_http_chunked_trailer_part,
	      { "trailer-part", "http.chunked_trailer_part",
		FT_STRING, BASE_NONE, NULL, 0,
		"Optional trailer in a chunked body", HFILL }},
	    { &hf_http_chunk_boundary,
	      { "Chunk boundary", "http.chunk_boundary",
		FT_BYTES, BASE_NONE, NULL, 0,
		NULL, HFILL }},
	    { &hf_http_chunk_size,
	      { "Chunk size", "http.chunk_size",
		FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0,
		NULL, HFILL }},
	    { &hf_http_chunk_data,
	      { "Chunk data", "http.chunk_data",
		FT_BYTES, BASE_NONE, NULL, 0,
		NULL, HFILL }},
	    { &hf_http_file_data,
	      { "File Data", "http.file_data",
		FT_BYTES, BASE_NONE, NULL, 0,
		NULL, HFILL }},
	    { &hf_http_unknown_header,
	      { "Unknown header", "http.unknown_header",
		FT_STRING, BASE_NONE, NULL, 0,
		NULL, HFILL }},
	    { &hf_http_http2_settings_uri,
	      { "HTTP2 Settings URI", "http.http2_settings_uri",
		FT_BYTES, BASE_NONE, NULL, 0,
		NULL, HFILL }},

		/* Body fragments */
	    REASSEMBLE_INIT_HF_ITEMS(http_body, "HTTP Chunked Body", "http.body"),
	};
	static int *ett[] = {
		&ett_http,
		&ett_http_ntlmssp,
		&ett_http_kerberos,
		&ett_http_request,
		&ett_http_request_uri,
		&ett_http_request_path,
		&ett_http_request_query,
		&ett_http_chunked_response,
		&ett_http_chunk_data,
		&ett_http_encoded_entity,
		&ett_http_header_item,
		&ett_http_http2_settings_item,
		REASSEMBLE_INIT_ETT_ITEMS(http_body),
	};

	static ei_register_info ei[] = {
		{ &ei_http_te_and_length, { "http.te_and_length", PI_MALFORMED, PI_WARN, "The Content-Length and Transfer-Encoding header must not be set together", EXPFILL }},
		{ &ei_http_te_unknown, { "http.te_unknown", PI_UNDECODED, PI_WARN, "Unknown transfer coding name in Transfer-Encoding header", EXPFILL }},
		{ &ei_http_subdissector_failed, { "http.subdissector_failed", PI_MALFORMED, PI_NOTE, "HTTP body subdissector failed, trying heuristic subdissector", EXPFILL }},
		{ &ei_http_tls_port, { "http.tls_port", PI_SECURITY, PI_WARN, "Unencrypted HTTP protocol detected over encrypted port, could indicate a dangerous misconfiguration.", EXPFILL }},
		{ &ei_http_excess_data, { "http.excess_data", PI_PROTOCOL, PI_WARN, "Excess data after a body (not a new request/response), previous Content-Length bogus?", EXPFILL }},
		{ &ei_http_leading_crlf, { "http.leading_crlf", PI_MALFORMED, PI_ERROR, "Leading CRLF previous message in the stream may have extra CRLF", EXPFILL }},
		{ &ei_http_bad_header_name, { "http.bad_header_name", PI_PROTOCOL, PI_WARN, "Illegal characters found in header name", EXPFILL }},
		{ &ei_http_decompression_failed, { "http.decompression_failed", PI_UNDECODED, PI_WARN, "Decompression failed", EXPFILL }},
		{ &ei_http_decompression_disabled, { "http.decompression_disabled", PI_UNDECODED, PI_CHAT, "Decompression disabled", EXPFILL }}

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

	proto_http = proto_register_protocol("Hypertext Transfer Protocol", "HTTP", "http");
	proto_ssdp = proto_register_protocol("Simple Service Discovery Protocol", "SSDP", "ssdp");

	proto_register_field_array(proto_http, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_http = expert_register_protocol(proto_http);
	expert_register_field_array(expert_http, ei, array_length(ei));

	http_handle = register_dissector("http", dissect_http, proto_http);
	http_tcp_handle = register_dissector("http-over-tcp", dissect_http_tcp, proto_http);
	http_tls_handle = register_dissector("http-over-tls", dissect_http_tls, proto_http); /* RFC 2818 */
	http_sctp_handle = register_dissector("http-over-sctp", dissect_http_sctp, proto_http);

	reassembly_table_register(&http_streaming_reassembly_table, &addresses_ports_reassembly_table_functions);

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
#if defined(HAVE_ZLIB) || defined(HAVE_ZLIBNG) || defined(HAVE_BROTLI)
	prefs_register_bool_preference(http_module, "decompress_body",
	    "Uncompress entity bodies",
	    "Whether to uncompress entity bodies that are compressed "
	    "using \"Content-Encoding: \"",
	    &http_decompress_body);
#endif
	prefs_register_bool_preference(http_module, "check_ascii_headers",
	    "Reject non-ASCII headers as invalid HTTP",
	    "Whether to treat non-ASCII in headers as non-HTTP data "
	    "and allow other dissectors to process it",
	    &http_check_ascii_headers);
	prefs_register_obsolete_preference(http_module, "tcp_alternate_port");

	range_convert_str(wmem_epan_scope(), &global_http_tls_range, TLS_DEFAULT_RANGE, 65535);
	prefs_register_range_preference(http_module, "tls.port", "SSL/TLS Ports",
					"SSL/TLS Ports range",
					&global_http_tls_range, 65535);
	prefs_register_obsolete_preference(http_module, "ssl.port");
	/* UAT */
	headers_uat = uat_new("Custom HTTP Header Fields",
			      sizeof(header_field_t),
			      "custom_http_header_fields",
			      true,
			      &header_fields,
			      &num_header_fields,
			      /* specifies named fields, so affects dissection
			         and the set of named fields */
			      UAT_AFFECTS_DISSECTION|UAT_AFFECTS_FIELDS,
			      NULL,
			      header_fields_copy_cb,
			      header_fields_update_cb,
			      header_fields_free_cb,
			      header_fields_post_update_cb,
			      header_fields_reset_cb,
			      custom_header_uat_fields
	);

	prefs_register_uat_preference(http_module, "custom_http_header_fields", "Custom HTTP header fields",
	    "A table to define custom HTTP header for which fields can be setup and used for filtering/data extraction etc.",
	   headers_uat);

	/*
	 * Dissectors shouldn't register themselves in this table;
	 * instead, they should call "http_tcp_dissector_add()", and
	 * we'll register the port number they specify as a port
	 * for HTTP, and register them in our subdissector table.
	 *
	 * This only works for protocols such as IPP that run over
	 * HTTP on a specific non-HTTP port.
	 */
	port_subdissector_table = register_dissector_table("http.port",
	    "TCP port for protocols using HTTP", proto_http, FT_UINT16, BASE_DEC);

	/*
	 * Maps the lowercase Upgrade header value.
	 * https://tools.ietf.org/html/rfc7230#section-8.6
	 */
	upgrade_subdissector_table = register_dissector_table("http.upgrade", "HTTP Upgrade", proto_http, FT_STRING, STRING_CASE_SENSITIVE);

	/*
	 * Heuristic dissectors SHOULD register themselves in
	 * this table using the standard heur_dissector_add()
	 * function.
	 */
	heur_subdissector_list = register_heur_dissector_list_with_description("http", "HTTP payload fallback", proto_http);

	/*
	 * Register for tapping
	 */
	http_tap = register_tap("http"); /* HTTP statistics tap */
	http_follow_tap = register_tap("http_follow"); /* HTTP Follow tap */
	credentials_tap = register_tap("credentials"); /* credentials tap */

	register_follow_stream(proto_http, "http_follow", tcp_follow_conv_filter, tcp_follow_index_filter, tcp_follow_address_filter,
							tcp_port_to_display, follow_tvb_tap_listener,
							get_tcp_stream_count, NULL);
	http_eo_tap = register_export_object(proto_http, http_eo_packet, NULL);

	/* compile patterns, excluding "/" */
	ws_mempbrk_compile(&pbrk_gen_delims, ":?#[]@");
	/* exclude "=", separating key and value should be done separately */
	ws_mempbrk_compile(&pbrk_sub_delims, "!$&'()*+,;");

}

/*
 * Called by dissectors for protocols that run atop HTTP/TCP.
 */
void
http_tcp_dissector_add(uint32_t port, dissector_handle_t handle)
{
	/*
	 * Register ourselves as the handler for that port number
	 * over TCP.  "Auto-preference" not needed
	 */
	dissector_add_uint("tcp.port", port, http_tcp_handle);

	/*
	 * And register them in *our* table for that port.
	 */
	dissector_add_uint("http.port", port, handle);
}

WS_DLL_PUBLIC
void http_tcp_dissector_delete(uint32_t port)
{
	/*
	 * Unregister ourselves as the handler for that port number
	 * over TCP.  "Auto-preference" not needed
	 */
	dissector_delete_uint("tcp.port", port, NULL);

	/*
	 * And unregister them in *our* table for that port.
	 */
	dissector_delete_uint("http.port", port, NULL);
}

void
http_tcp_port_add(uint32_t port)
{
	/*
	 * Register ourselves as the handler for that port number
	 * over TCP.  We rely on our caller having registered
	 * themselves for the appropriate media type.
	 * No "auto-preference" used.
	 */
	dissector_add_uint("tcp.port", port, http_tcp_handle);
}

void
proto_reg_handoff_http(void)
{
	dissector_handle_t ssdp_handle;

	media_handle = find_dissector_add_dependency("media", proto_http);
	http2_handle = find_dissector("http2");
	/*
	 * XXX - is there anything to dissect in the body of an SSDP
	 * request or reply?  I.e., should there be an SSDP dissector?
	 */
	ssdp_handle = create_dissector_handle(dissect_ssdp, proto_ssdp);
	dissector_add_uint_with_preference("udp.port", UDP_PORT_SSDP, ssdp_handle);

	/*
	 * TLS Application-Layer Protocol Negotiation (ALPN) protocol ID.
	 */
	dissector_add_string("tls.alpn", "http/1.1", http_tls_handle);

	ntlmssp_handle = find_dissector_add_dependency("ntlmssp", proto_http);
	gssapi_handle = find_dissector_add_dependency("gssapi", proto_http);
	sstp_handle = find_dissector_add_dependency("sstp", proto_http);

	stats_tree_cfg *st_config;
	st_config = stats_tree_register("http", "http",     "HTTP" STATS_TREE_MENU_SEPARATOR "Packet Counter",   0, http_stats_tree_packet,      http_stats_tree_init, NULL );
	stats_tree_set_first_column_name(st_config, "Packet Type");
	st_config = stats_tree_register("http", "http_req", "HTTP" STATS_TREE_MENU_SEPARATOR "Requests",         0, http_req_stats_tree_packet,  http_req_stats_tree_init, NULL );
	stats_tree_set_first_column_name(st_config, "Request Type");
	st_config = stats_tree_register("http", "http_srv", "HTTP" STATS_TREE_MENU_SEPARATOR "Load Distribution",0, http_reqs_stats_tree_packet, http_reqs_stats_tree_init, NULL );
	stats_tree_set_first_column_name(st_config, "Packet Type");
	st_config = stats_tree_register("http", "http_seq", "HTTP" STATS_TREE_MENU_SEPARATOR "Request Sequences",0, http_seq_stats_tree_packet,  http_seq_stats_tree_init, NULL );
	stats_tree_set_first_column_name(st_config, "Sequence Type");

	dissector_add_uint("acdr.tls_application_port", 443, http_handle);
	dissector_add_uint("acdr.tls_application", TLS_APP_HTTP, http_handle);
	dissector_add_uint("acdr.tls_application", TLS_APP_TR069, http_handle);
	dissector_add_uint("ippusb", 0, http_tcp_handle);
}

/*
 * Content-Type: message/http
 */

static int proto_message_http;
static int ett_message_http;

static int
dissect_message_http(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree	*subtree;
	proto_item	*ti;
	int		offset = 0, next_offset;
	int		len;

	col_append_str(pinfo->cinfo, COL_INFO, " (message/http)");
	if (tree) {
		ti = proto_tree_add_item(tree, proto_message_http,
				tvb, 0, -1, ENC_NA);
		subtree = proto_item_add_subtree(ti, ett_message_http);
		while (tvb_offset_exists(tvb, offset)) {
			len = tvb_find_line_end(tvb, offset,
					tvb_ensure_captured_length_remaining(tvb, offset),
					&next_offset, false);
			if (len == -1)
				break;
			proto_tree_add_format_text(subtree, tvb, offset, len);
			offset = next_offset;
		}
	}
	return tvb_captured_length(tvb);
}

void
proto_register_message_http(void)
{
	static int *ett[] = {
		&ett_message_http,
	};

	proto_message_http = proto_register_protocol("Media Type: message/http", "message/http", "message-http");
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_message_http(void)
{
	dissector_handle_t message_http_handle;

	message_http_handle = create_dissector_handle(dissect_message_http,
			proto_message_http);

	dissector_add_string("media_type", "message/http", message_http_handle);

	heur_dissector_add("tcp", dissect_http_heur_tcp, "HTTP over TCP", "http_tcp", proto_http, HEURISTIC_ENABLE);
	heur_dissector_add("tls", dissect_http_heur_tls, "HTTP over TLS", "http_tls", proto_http, HEURISTIC_ENABLE);

	proto_http2 = proto_get_id_by_filter_name("http2");

	dissector_add_uint_range_with_preference("tcp.port", TCP_DEFAULT_RANGE, http_tcp_handle);
	dissector_add_uint_range_with_preference("sctp.port", SCTP_DEFAULT_RANGE, http_sctp_handle);

	/*
	 * Get the content type and Internet media type table
	 */
	media_type_subdissector_table = find_dissector_table("media_type");

	streaming_content_type_dissector_table = find_dissector_table("streaming_content_type");

	reinit_http();
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
