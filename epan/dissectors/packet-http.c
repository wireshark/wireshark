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
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <ctype.h>

#include <glib.h>
#include <epan/conversation.h>
#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/base64.h>
#include <epan/emem.h>
#include <epan/stats_tree.h>

#include <epan/req_resp_hdrs.h>
#include "packet-http.h"
#include "packet-tcp.h"
#include <epan/prefs.h>
#include <epan/expert.h>

typedef enum _http_type {
	HTTP_REQUEST,
	HTTP_RESPONSE,
	HTTP_NOTIFICATION,
	HTTP_OTHERS
} http_type_t;

#include <epan/tap.h>

static int http_tap = -1;

static int proto_http = -1;
static int hf_http_notification = -1;
static int hf_http_response = -1;
static int hf_http_request = -1;
static int hf_http_basic = -1;
static int hf_http_request_method = -1;
static int hf_http_request_uri = -1;
static int hf_http_version = -1;
static int hf_http_response_code = -1;
static int hf_http_authorization = -1;
static int hf_http_proxy_authenticate = -1;
static int hf_http_proxy_authorization = -1;
static int hf_http_www_authenticate = -1;
static int hf_http_content_type = -1;
static int hf_http_content_length = -1;
static int hf_http_content_encoding = -1;
static int hf_http_transfer_encoding = -1;
static int hf_http_user_agent = -1;
static int hf_http_host = -1;
static int hf_http_connection = -1;
static int hf_http_cookie = -1;
static int hf_http_accept = -1;
static int hf_http_referer = -1;
static int hf_http_accept_language = -1;
static int hf_http_accept_encoding = -1;
static int hf_http_date = -1;
static int hf_http_cache_control = -1;
static int hf_http_server = -1;
static int hf_http_location = -1;
static int hf_http_set_cookie = -1;
static int hf_http_last_modified = -1;
static int hf_http_x_forwarded_for = -1;

static gint ett_http = -1;
static gint ett_http_ntlmssp = -1;
static gint ett_http_request = -1;
static gint ett_http_chunked_response = -1;
static gint ett_http_chunk_data = -1;
static gint ett_http_encoded_entity = -1;

static dissector_handle_t data_handle;
static dissector_handle_t media_handle;
static dissector_handle_t http_handle;

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


#define TCP_PORT_HTTP			80
#define TCP_PORT_PROXY_HTTP		3128
#define TCP_PORT_PROXY_ADMIN_HTTP	3132
#define TCP_ALT_PORT_HTTP		8080
#define TCP_RADAN_HTTP			8088
#define TCP_PORT_HKP			11371
#define TCP_PORT_DAAP			3689

#define HTTP_PORTS (TCP_PORT_HTTP || TCP_PORT_PROXY_HTTP || TCP_PORT_PROXY_ADMIN_HTTP || TCP_ALT_PORT_HTTP || TCP_RADAN_HTTP || \
		    TCP_PORT_HKP || TCP_PORT_DAAP)

/*
 * SSDP is implemented atop HTTP (yes, it really *does* run over UDP).
 */
#define TCP_PORT_SSDP			1900
#define UDP_PORT_SSDP			1900

/*
 * tcp alternate port
 */
static guint http_alternate_tcp_port = 0;
static guint alternate_tcp_port = 0;

/*
 * Protocols implemented atop HTTP.
 */
typedef enum {
	PROTO_HTTP,		/* just HTTP */
	PROTO_SSDP,		/* Simple Service Discovery Protocol */
	PROTO_DAAP		/* Digital Audio Access Protocol */
} http_proto_t;

typedef void (*ReqRespDissector)(tvbuff_t*, proto_tree*, int, const guchar*,
    const guchar*);

/*
 * Structure holding information from headers needed by main
 * HTTP dissector code.
 */
typedef struct {
	char	*content_type;
	char	*content_type_parameters;
	gboolean have_content_length;
	long	content_length;	/* XXX - make it 64-bit? */
	char	*content_encoding;
	char	*transfer_encoding;
} headers_t;

static int is_http_request_or_reply(const gchar *data, int linelen,
    http_type_t *type, ReqRespDissector *reqresp_dissector);
static int chunked_encoding_dissector(tvbuff_t **tvb_ptr, packet_info *pinfo,
		proto_tree *tree, int offset);
static void http_payload_subdissector(tvbuff_t *next_tvb, proto_tree *tree, proto_tree *sub_tree, packet_info *pinfo);
static void process_header(tvbuff_t *tvb, int offset, int next_offset,
    const guchar *line, int linelen, int colon_offset, packet_info *pinfo,
    proto_tree *tree, headers_t *eh_ptr);
static gint find_header_hf_value(tvbuff_t *tvb, int offset, guint header_len);
static gboolean check_auth_ntlmssp(proto_item *hdr_item, tvbuff_t *tvb,
    packet_info *pinfo, gchar *value);
static gboolean check_auth_basic(proto_item *hdr_item, tvbuff_t *tvb,
    gchar *value);

static dissector_table_t port_subdissector_table;
static dissector_table_t media_type_subdissector_table;
static heur_dissector_list_t heur_subdissector_list;

static dissector_handle_t ntlmssp_handle=NULL;
static dissector_handle_t gssapi_handle=NULL;

static const value_string vals_status_code[] = {
	{ 100, "Continue" },
	{ 101, "Switching Protocols" },
	{ 102, "Processing" },
	{ 199, "Informational - Others" },

	{ 200, "OK"},
	{ 201, "Created"},
	{ 202, "Accepted"},
	{ 203, "Non-authoritative Information"},
	{ 204, "No Content"},
	{ 205, "Reset Content"},
	{ 206, "Partial Content"},
	{ 207, "Multi-Status"},
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
	{ 422, "Unprocessable Entity"},
	{ 423, "Locked"},
	{ 424, "Failed Dependency"},
	{ 499, "Client Error - Others"},

	{ 500, "Internal Server Error"},
	{ 501, "Not Implemented"},
	{ 502, "Bad Gateway"},
	{ 503, "Service Unavailable"},
	{ 504, "Gateway Time-out"},
	{ 505, "HTTP Version not supported"},
	{ 507, "Insufficient Storage"},
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

static void http_reqs_stats_tree_init(stats_tree* st) {
	st_node_reqs = stats_tree_create_node(st, st_str_reqs, 0, TRUE);
	st_node_reqs_by_srv_addr = stats_tree_create_node(st, st_str_reqs_by_srv_addr, st_node_reqs, TRUE);
	st_node_reqs_by_http_host = stats_tree_create_node(st, st_str_reqs_by_http_host, st_node_reqs, TRUE);
	st_node_resps_by_srv_addr = stats_tree_create_node(st, st_str_resps_by_srv_addr, 0, TRUE);
}

static int http_reqs_stats_tree_packet(stats_tree* st, packet_info* pinfo, epan_dissect_t* edt _U_, const void* p) {
	const http_info_value_t* v = p;
	int reqs_by_this_host;
	int reqs_by_this_addr;
	int resps_by_this_addr;
	int i = v->response_code;
	static gchar ip_str[256];


	if (v->request_method) {
		g_snprintf(ip_str,sizeof(ip_str),"%s",address_to_str(&pinfo->dst));

		tick_stat_node(st, st_str_reqs, 0, FALSE);
		tick_stat_node(st, st_str_reqs_by_srv_addr, st_node_reqs, TRUE);
		tick_stat_node(st, st_str_reqs_by_http_host, st_node_reqs, TRUE);
		reqs_by_this_addr = tick_stat_node(st, ip_str, st_node_reqs_by_srv_addr, TRUE);

		if (v->http_host) {
			reqs_by_this_host = tick_stat_node(st, v->http_host, st_node_reqs_by_http_host, TRUE);
			tick_stat_node(st, ip_str, reqs_by_this_host, FALSE);

			tick_stat_node(st, v->http_host, reqs_by_this_addr, FALSE);
		}

		return 1;

	} else if (i != 0) {
		g_snprintf(ip_str,sizeof(ip_str),"%s",address_to_str(&pinfo->src));

		tick_stat_node(st, st_str_resps_by_srv_addr, 0, FALSE);
		resps_by_this_addr = tick_stat_node(st, ip_str, st_node_resps_by_srv_addr, TRUE);

		if ( (i>100)&&(i<400) ) {
			tick_stat_node(st, "OK", resps_by_this_addr, FALSE);
		} else {
			tick_stat_node(st, "KO", resps_by_this_addr, FALSE);
		}

		return 1;
	}

	return 0;
}


static int st_node_requests_by_host = -1;
static const guint8* st_str_requests_by_host = "HTTP Requests by HTTP Host";

static void http_req_stats_tree_init(stats_tree* st) {
	st_node_requests_by_host = stats_tree_create_node(st, st_str_requests_by_host, 0, TRUE);
}

static int http_req_stats_tree_packet(stats_tree* st, packet_info* pinfo _U_, epan_dissect_t* edt _U_, const void* p) {
	const http_info_value_t* v = p;
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

static const guint8* st_str_packets = "Total HTTP Packets";
static const guint8* st_str_requests = "HTTP Request Packets";
static const guint8* st_str_responses = "HTTP Response Packets";
static const guint8* st_str_resp_broken = "???: broken";
static const guint8* st_str_resp_100 = "1xx: Informational";
static const guint8* st_str_resp_200 = "2xx: Success";
static const guint8* st_str_resp_300 = "3xx: Redirection";
static const guint8* st_str_resp_400 = "4xx: Client Error";
static const guint8* st_str_resp_500 = "5xx: Server Error";
static const guint8* st_str_other = "Other HTTP Packets";

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


static void http_stats_tree_init(stats_tree* st) {
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

static int http_stats_tree_packet(stats_tree* st, packet_info* pinfo _U_, epan_dissect_t* edt _U_, const void* p) {
	const http_info_value_t* v = p;
	guint i = v->response_code;
	int resp_grp;
	const guint8* resp_str;
	static gchar str[64];

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

		g_snprintf(str, sizeof(str),"%u %s",i,match_strval(i,vals_status_code));
		tick_stat_node(st, str, resp_grp, FALSE);
	} else if (v->request_method) {
		stats_tree_tick_pivot(st,st_node_requests,v->request_method);
	} else {
		tick_stat_node(st, st_str_other, st_node_packets, FALSE);
	}

	return 1;
}

/* Return a tvb that contains the binary representation of a base64
   string */

static tvbuff_t *
base64_to_tvb(const char *base64)
{
	tvbuff_t *tvb;
	char *data = g_strdup(base64);
	size_t len;

	len = epan_base64_decode(data);
	tvb = tvb_new_real_data((const guint8 *)data, len, len);

	tvb_set_free_cb(tvb, g_free);

	return tvb;
}

static void
dissect_http_ntlmssp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    const char *line)
{
	tvbuff_t *ntlmssp_tvb;

	ntlmssp_tvb = base64_to_tvb(line);
	tvb_set_child_real_data_tvbuff(tvb, ntlmssp_tvb);
	add_new_data_source(pinfo, ntlmssp_tvb, "NTLMSSP / GSSAPI Data");
	if (tvb_strneql(ntlmssp_tvb, 0, "NTLMSSP", 7) == 0)
		call_dissector(ntlmssp_handle, ntlmssp_tvb, pinfo, tree);
	else
		call_dissector(gssapi_handle, ntlmssp_tvb, pinfo, tree);
}

/*
 * TODO: remove this ugly global variable.
 * XXX: do we really want to have to pass this from one function to another?
 */
static http_info_value_t	*stat_info;

static int
dissect_http_message(tvbuff_t *tvb, int offset, packet_info *pinfo,
    proto_tree *tree)
{
	http_proto_t	proto;
	const char	*proto_tag;
	proto_tree	*http_tree = NULL;
	proto_item	*ti = NULL;
	const guchar	*line;
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
	gboolean	dissected;
	/*guint		i;*/
	/*http_info_value_t *si;*/
	conversation_t  *conversation;

	/*
	 * Is this a request or response?
	 *
	 * Note that "tvb_find_line_end()" will return a value that
	 * is not longer than what's in the buffer, so the
	 * "tvb_get_ptr()" call won't throw an exception.
	 */
	first_linelen = tvb_find_line_end(tvb, offset,
	    tvb_ensure_length_remaining(tvb, offset), &next_offset,
	    FALSE);
	/*
	 * Is the first line a request or response?
	 */
	line = tvb_get_ptr(tvb, offset, first_linelen);
	http_type = HTTP_OTHERS;	/* type not known yet */
	is_request_or_reply = is_http_request_or_reply((const gchar *)line,
	    first_linelen, &http_type, NULL);
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

	conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);

	if(!conversation) {  /* Conversation does not exist yet - create it */
		conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
	}

	/* Retrieve information from conversation
	 * or add it if it isn't there yet
	 */
	stat_info = conversation_get_proto_data(conversation, proto_http);
	if(!stat_info) {
		stat_info = se_alloc(sizeof(http_info_value_t));
		stat_info->response_code = 0;
		stat_info->request_method = NULL;
		stat_info->request_uri = NULL;
		stat_info->http_host = NULL;

		conversation_add_proto_data(conversation, proto_http, stat_info);
	}

	switch (pinfo->match_port) {

	case TCP_PORT_SSDP:	/* TCP_PORT_SSDP = UDP_PORT_SSDP */
		proto = PROTO_SSDP;
		proto_tag = "SSDP";
		break;

	case TCP_PORT_DAAP:
		proto = PROTO_DAAP;
		proto_tag = "DAAP";
		break;

	default:
		proto = PROTO_HTTP;
		proto_tag = "HTTP";
		break;
	}

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, proto_tag);
	if (check_col(pinfo->cinfo, COL_INFO)) {
		/*
		 * Put the first line from the buffer into the summary
		 * if it's an HTTP request or reply (but leave out the
		 * line terminator).
		 * Otherwise, just call it a continuation.
		 *
		 * Note that "tvb_find_line_end()" will return a value that
		 * is not longer than what's in the buffer, so the
		 * "tvb_get_ptr()" call won't throw an exception.
		 */
		line = tvb_get_ptr(tvb, offset, first_linelen);
		if (is_request_or_reply)
			col_add_str(pinfo->cinfo, COL_INFO,
			    format_text(line, first_linelen));
		else
			col_set_str(pinfo->cinfo, COL_INFO, "Continuation or non-HTTP traffic");
	}

	orig_offset = offset;
	if (tree) {
		ti = proto_tree_add_item(tree, proto_http, tvb, offset, -1,
		    FALSE);
		http_tree = proto_item_add_subtree(ti, ett_http);
	}

	/*
	 * Process the packet data, a line at a time.
	 */
	http_type = HTTP_OTHERS;	/* type not known yet */
	headers.content_type = NULL;	/* content type not known yet */
	headers.content_type_parameters = NULL;	/* content type parameters too */
	headers.have_content_length = FALSE;	/* content length not known yet */
	headers.content_encoding = NULL; /* content encoding not known yet */
	headers.transfer_encoding = NULL; /* transfer encoding not known yet */
	saw_req_resp_or_header = FALSE;	/* haven't seen anything yet */
	while (tvb_reported_length_remaining(tvb, offset) != 0) {
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
		    linelen, &http_type, &reqresp_dissector);
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
		/*
		 * Process this line.
		 */
		if (linelen == 0) {
			/*
			 * This is a blank line, which means that
			 * whatever follows it isn't part of this
			 * request or reply.
			 */
			proto_tree_add_text(http_tree, tvb, offset,
			    next_offset - offset, "%s",
			    tvb_format_text(tvb, offset, next_offset - offset));
			offset = next_offset;
			break;
		}

		/*
		 * Not a blank line - either a request, a reply, or a header
		 * line.
		 */
		saw_req_resp_or_header = TRUE;
		if (is_request_or_reply) {
			if (tree) {
				hdr_item = proto_tree_add_text(http_tree, tvb,
				    offset, next_offset - offset, "%s",
				    tvb_format_text(tvb, offset,
				      next_offset - offset));
			}
			expert_add_info_format(pinfo, hdr_item, PI_SEQUENCE, PI_CHAT,
				"%s",
				tvb_format_text(tvb, offset, next_offset - offset));
			if (reqresp_dissector) {
				if (tree) req_tree = proto_item_add_subtree(hdr_item, ett_http_request);
				else req_tree = NULL;

				reqresp_dissector(tvb, req_tree, offset, line, lineend);
			}
		} else {
			/*
			 * Header.
			 */
			process_header(tvb, offset, next_offset, line, linelen,
			    colon_offset, pinfo, http_tree, &headers);
		}
		offset = next_offset;
	}

	if (tree) {
		switch (http_type) {

		case HTTP_NOTIFICATION:
			proto_tree_add_boolean_hidden(http_tree,
			    hf_http_notification, tvb, 0, 0, 1);
			break;

		case HTTP_RESPONSE:
			proto_tree_add_boolean_hidden(http_tree,
			    hf_http_response, tvb, 0, 0, 1);
			break;

		case HTTP_REQUEST:
			proto_tree_add_boolean_hidden(http_tree,
			    hf_http_request, tvb, 0, 0, 1);
			break;

		case HTTP_OTHERS:
		default:
			break;
		}
	}

	/*
	 * If a content length was supplied, the amount of data to be
	 * processed as HTTP payload is the minimum of the content
	 * length and the amount of data remaining in the frame.
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
	 * Acccording to RFC 2616, however, 1xx responses, 204 responses,
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
	datalen = tvb_length_remaining(tvb, offset);
	if (headers.have_content_length && headers.content_length != -1) {
		if (datalen > headers.content_length)
			datalen = headers.content_length;

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
		reported_datalen = tvb_reported_length_remaining(tvb, offset);
		if (reported_datalen > headers.content_length)
			reported_datalen = headers.content_length;
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
		 * BEWARE - next_tvb is a subset of another tvb,
		 * so we MUST NOT attempt tvb_free(next_tvb);
		 */

		/*
		 * Handle *transfer* encodings other than "identity".
		 */
		if (headers.transfer_encoding != NULL &&
		    strcasecmp(headers.transfer_encoding, "identity") != 0) {
			if (http_dechunk_body &&
			    (strncasecmp(headers.transfer_encoding, "chunked", 7)
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
					tvb_set_child_real_data_tvbuff(tvb,
						next_tvb);
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
		    strcasecmp(headers.content_encoding, "identity") != 0) {
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
			    (strcasecmp(headers.content_encoding, "gzip") == 0 ||
			    strcasecmp(headers.content_encoding, "deflate")
			    == 0)) {

				uncomp_tvb = tvb_uncompress(next_tvb, 0,
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
				tvb_set_child_real_data_tvbuff(tvb, next_tvb);
				add_new_data_source(pinfo, next_tvb,
				    "Uncompressed entity body");
			} else {
				if (chunks_decoded > 1) {
					tvb_set_child_real_data_tvbuff(tvb,
					    next_tvb);
					add_new_data_source(pinfo, next_tvb,
					    "Compressed entity body");
				}
				call_dissector(data_handle, next_tvb, pinfo,
				    e_tree);

				goto body_dissected;
			}
		}
		/*
		 * Note that a new data source is added for the entity body
		 * only if it was content-encoded and/or transfer-encoded.
		 */

		/*
		 * Do subdissector checks.
		 *
		 * First, check whether some subdissector asked that they
		 * be called if something was on some particular port.
		 */
		handle = dissector_get_port_handle(port_subdissector_table,
		    pinfo->match_port);
		if (handle == NULL && headers.content_type != NULL) {
			/*
			 * We didn't find any subdissector that
			 * registered for the port, and we have a
			 * Content-Type value.  Is there any subdissector
			 * for that content type?
			 */
			save_private_data = pinfo->private_data;

			if (headers.content_type_parameters)
				pinfo->private_data = ep_strdup(headers.content_type_parameters);
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
		}
		if (handle != NULL) {
			/*
			 * We have a subdissector - call it.
			 */
			dissected = call_dissector(handle, next_tvb, pinfo,
			    tree);
		} else {
			/*
			 * We don't have a subdissector - try the heuristic
			 * subdissectors.
			 */
			dissected = dissector_try_heuristic(
			    heur_subdissector_list, next_tvb, pinfo, tree);
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
				/* Call the subdissector (defaults to data), otherwise. */
				http_payload_subdissector(next_tvb, tree, http_tree, pinfo);
			}
		}

	body_dissected:
		/*
		 * Do *not* attempt at freeing the private data;
		 * it may be in use by subdissectors.
		 */
		if (save_private_data)
			pinfo->private_data = save_private_data;
		/*
		 * We've processed "datalen" bytes worth of data
		 * (which may be no data at all); advance the
		 * offset past whatever data we've processed.
		 */
		offset += datalen;
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
    const guchar *line, const guchar *lineend)
{
	const guchar *next_token;
	int tokenlen;

	/* The first token is the method. */
	tokenlen = get_token_len(line, lineend, &next_token);
	if (tokenlen == 0)
		return;
	proto_tree_add_item(tree, hf_http_request_method, tvb, offset, tokenlen,
	    FALSE);
	offset += next_token - line;
	line = next_token;

	/* The next token is the URI. */
	tokenlen = get_token_len(line, lineend, &next_token);
	if (tokenlen == 0)
		return;
	stat_info->request_uri = se_strdup((gchar*) tvb_get_ephemeral_string(tvb, offset, tokenlen));
	proto_tree_add_string(tree, hf_http_request_uri, tvb, offset, tokenlen,
	    stat_info->request_uri);
	offset += next_token - line;
	line = next_token;

	/* Everything to the end of the line is the version. */
	tokenlen = lineend - line;
	if (tokenlen == 0)
		return;
	proto_tree_add_item(tree, hf_http_version, tvb, offset, tokenlen,
	    FALSE);
}

static void
basic_response_dissector(tvbuff_t *tvb, proto_tree *tree, int offset,
    const guchar *line, const guchar *lineend)
{
	const guchar *next_token;
	int tokenlen;
	gchar response_chars[4];

	/* The first token is the version. */
	tokenlen = get_token_len(line, lineend, &next_token);
	if (tokenlen == 0)
		return;
	proto_tree_add_item(tree, hf_http_version, tvb, offset, tokenlen,
	    FALSE);
	offset += next_token - line;
	line = next_token;

	/* The next token is the status code. */
	tokenlen = get_token_len(line, lineend, &next_token);
	if (tokenlen < 3)
		return;
	memcpy(response_chars, line, 3);
	response_chars[3] = '\0';

	stat_info->response_code = strtoul(response_chars,NULL,10);

	proto_tree_add_uint(tree, hf_http_response_code, tvb, offset, 3,
	    stat_info->response_code);
}

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


	while (datalen != 0) {
		proto_item *chunk_ti = NULL;
		proto_tree *chunk_subtree = NULL;
		tvbuff_t *data_tvb = NULL;
		gchar *c = NULL;
		guint8 *raw_data;
		gint raw_len = 0;

		linelen = tvb_find_line_end(tvb, offset, -1, &chunk_offset, TRUE);

		if (linelen <= 0) {
			/* Can't get the chunk size line */
			break;
		}

		chunk_string = tvb_get_ephemeral_string(tvb, offset, linelen);

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

		if ( ( chunk_size = strtol((gchar*)chunk_string, NULL, 16) ) == 0 ) {
			break;
		}


		if (chunk_size > datalen) {
			/*
			 * The chunk size is more than what's in the tvbuff,
			 * so either the user hasn't enabled decoding, or all
			 * of the segments weren't captured.
			 */
			chunk_size = datalen;
		}
		/*
		 * chunk_size is guaranteed to be >0 from here on
		 */
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

		new_tvb = tvb_new_real_data(raw_data,
			    chunked_data_size, chunked_data_size);
		tvb_set_free_cb(new_tvb, g_free);


		if (subtree) {
			chunk_ti = proto_tree_add_text(subtree, tvb,
				    offset,
				    chunk_offset - offset + chunk_size + 2,
				    "Data chunk (%u octets)", chunk_size);

			chunk_subtree = proto_item_add_subtree(chunk_ti,
			    ett_http_chunk_data);

			proto_tree_add_text(chunk_subtree, tvb, offset,
			    chunk_offset - offset, "Chunk size: %u octets",
			    chunk_size);

			data_tvb = tvb_new_subset(tvb, chunk_offset, chunk_size,
			    datalen);


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
		 * try to decode the non-existant entity body.
		 */
		chunks_decoded = -1;
	}

	return chunks_decoded;

}

static void
http_payload_subdissector(tvbuff_t *next_tvb, proto_tree *tree, proto_tree *sub_tree, packet_info *pinfo)
{
	/* tree = the main protocol tree that the subdissector would be listed in
	 * sub_tree = the http protocol tree
	 */
 	guint32 *ptr;
	struct tcpinfo *tcpinfo = pinfo->private_data;
	struct tcp_analysis *tcpd=NULL;
	gchar **strings; /* An array for splitting the request URI into hostname and port */

	/* Response code 200 means "OK" and strncmp() == 0 means the strings match exactly */
	if(stat_info->request_uri && stat_info->response_code == 200 &&
	   stat_info->request_method && strncmp(stat_info->request_method, "CONNECT", 7) == 0) {

		/* Call a subdissector to handle HTTP CONNECT's traffic */
		tcpd=get_tcp_conversation_data(pinfo);

		/* Grab the destination port number from the request URI to find the right subdissector */
		strings = g_strsplit(stat_info->request_uri, ":", 2);

		if(strings[0] != NULL && strings[1] != NULL) { /* The string was successfuly split in two */
			proto_tree_add_text(sub_tree, next_tvb, 0, 0, "Proxy connect hostname: %s", strings[0]);
			proto_tree_add_text(sub_tree, next_tvb, 0, 0, "Proxy connect port: %s", strings[1]);

			/* Replaces the pinfo->destport or srcport with the port the http connect was done to */
			/* pinfo->srcport and destport are guint32 variables (epan/packet_info.h) */
			if (pinfo->destport  == HTTP_PORTS)
				ptr = &pinfo->destport;
			else
				ptr = &pinfo->srcport;

			*ptr = (int)strtol(strings[1], NULL, 10); /* Convert string to a base-10 integer */

			dissect_tcp_payload(next_tvb, pinfo, 0, tcpinfo->seq, /* 0 = offset */
					    tcpinfo->nxtseq, pinfo->srcport, pinfo->destport,
					    tree, tree, tcpd);
		}

		g_strfreev(strings); /* Free the result of g_strsplit() above */

	} else {
		/* Call the default data dissector */
		   call_dissector(data_handle, next_tvb, pinfo, sub_tree);
	}
}



/*
 * XXX - this won't handle HTTP 0.9 replies, but they're all data
 * anyway.
 */
static int
is_http_request_or_reply(const gchar *data, int linelen, http_type_t *type,
		ReqRespDissector *reqresp_dissector)
{
	int isHttpRequestOrReply = FALSE;
	int prefix_len = 0;

	/*
	 * From RFC 2774 - An HTTP Extension Framework
	 *
	 * Support the command prefix that identifies the presence of
	 * a "mandatory" header.
	 */
	if (linelen >= 2 && strncmp(data, "M-", 2) == 0) {
		data += 2;
		linelen -= 2;
		prefix_len = 2;
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
		int		 index = 0;

		/* Look for the space following the Method */
		while (index < linelen) {
			if (*ptr == ' ')
				break;
			else {
				ptr++;
				index++;
			}
		}

		/* Check the methods that have same length */
		switch (index) {

		case 3:
			if (strncmp(data, "GET", index) == 0 ||
			    strncmp(data, "PUT", index) == 0) {
				*type = HTTP_REQUEST;
				isHttpRequestOrReply = TRUE;
			}
			else if (strncmp(data, "ICY", index) == 0) {
				*type = HTTP_RESPONSE;
				isHttpRequestOrReply = TRUE;
			}
			break;

		case 4:
			if (strncmp(data, "COPY", index) == 0 ||
			    strncmp(data, "HEAD", index) == 0 ||
			    strncmp(data, "LOCK", index) == 0 ||
			    strncmp(data, "MOVE", index) == 0 ||
			    strncmp(data, "POLL", index) == 0 ||
			    strncmp(data, "POST", index) == 0) {
				*type = HTTP_REQUEST;
				isHttpRequestOrReply = TRUE;
			}
			break;

		case 5:
			if (strncmp(data, "BCOPY", index) == 0 ||
				strncmp(data, "BMOVE", index) == 0 ||
				strncmp(data, "MKCOL", index) == 0 ||
				strncmp(data, "TRACE", index) == 0 ||
				strncmp(data, "LABEL", index) == 0 ||  /* RFC 3253 8.2 */
				strncmp(data, "MERGE", index) == 0) {  /* RFC 3253 11.2 */
				*type = HTTP_REQUEST;
				isHttpRequestOrReply = TRUE;
			}
			break;

		case 6:
			if (strncmp(data, "DELETE", index) == 0 ||
				strncmp(data, "SEARCH", index) == 0 ||
				strncmp(data, "UNLOCK", index) == 0 ||
				strncmp(data, "REPORT", index) == 0 ||  /* RFC 3253 3.6 */
				strncmp(data, "UPDATE", index) == 0) {  /* RFC 3253 7.1 */
				*type = HTTP_REQUEST;
				isHttpRequestOrReply = TRUE;
			}
			else if (strncmp(data, "NOTIFY", index) == 0) {
				*type = HTTP_NOTIFICATION;
				isHttpRequestOrReply = TRUE;
			}
			break;

		case 7:
			if (strncmp(data, "BDELETE", index) == 0 ||
			    strncmp(data, "CONNECT", index) == 0 ||
			    strncmp(data, "OPTIONS", index) == 0 ||
			    strncmp(data, "CHECKIN", index) == 0) {  /* RFC 3253 4.4, 9.4 */
				*type = HTTP_REQUEST;
				isHttpRequestOrReply = TRUE;
			}
			break;

		case 8:
			if (strncmp(data, "PROPFIND", index) == 0 ||
			    strncmp(data, "CHECKOUT", index) == 0 || /* RFC 3253 4.3, 9.3 */
			    strncmp(data, "CCM_POST", index) == 0) {
				*type = HTTP_REQUEST;
				isHttpRequestOrReply = TRUE;
			}
			break;

		case 9:
			if (strncmp(data, "SUBSCRIBE", index) == 0) {
				*type = HTTP_NOTIFICATION;
				isHttpRequestOrReply = TRUE;
			} else if (strncmp(data, "PROPPATCH", index) == 0 ||
			    strncmp(data, "BPROPFIND", index) == 0) {
				*type = HTTP_REQUEST;
				isHttpRequestOrReply = TRUE;
			}
			break;

		case 10:
			if (strncmp(data, "BPROPPATCH", index) == 0 ||
				strncmp(data, "UNCHECKOUT", index) == 0 ||  /* RFC 3253 4.5 */
				strncmp(data, "MKACTIVITY", index) == 0) {  /* RFC 3253 13.5 */
				*type = HTTP_REQUEST;
				isHttpRequestOrReply = TRUE;
			}
			break;

		case 11:
			if (strncmp(data, "MKWORKSPACE", index) == 0) {  /* RFC 3253 6.3 */
				*type = HTTP_REQUEST;
				isHttpRequestOrReply = TRUE;
			} else if (strncmp(data, "UNSUBSCRIBE", index) == 0) {
				*type = HTTP_NOTIFICATION;
				isHttpRequestOrReply = TRUE;
			} else if (strncmp(data, "RPC_CONNECT", index) == 0) {
				*type = HTTP_REQUEST;
				isHttpRequestOrReply = TRUE;
			}
			break;

		case 15:
			if (strncmp(data, "VERSION-CONTROL", index) == 0) {  /* RFC 3253 3.5 */
				*type = HTTP_REQUEST;
				isHttpRequestOrReply = TRUE;
			}
			break;

		case 16:
			if (strncmp(data, "BASELINE-CONTROL", index) == 0) {  /* RFC 3253 12.6 */
				*type = HTTP_REQUEST;
				isHttpRequestOrReply = TRUE;
			}
			break;

		default:
			break;
		}

		if (isHttpRequestOrReply && reqresp_dissector) {
			*reqresp_dissector = basic_request_dissector;
			if (!stat_info->request_method)
				stat_info->request_method = se_strndup(data, index+1);
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
#define HDR_HOST  7

static const header_info headers[] = {
	{ "Authorization", &hf_http_authorization, HDR_AUTHORIZATION },
	{ "Proxy-Authorization", &hf_http_proxy_authorization, HDR_AUTHORIZATION },
	{ "Proxy-Authenticate", &hf_http_proxy_authenticate, HDR_AUTHENTICATE },
	{ "WWW-Authenticate", &hf_http_www_authenticate, HDR_AUTHENTICATE },
	{ "Content-Type", &hf_http_content_type, HDR_CONTENT_TYPE },
	{ "Content-Length", &hf_http_content_length, HDR_CONTENT_LENGTH },
	{ "Content-Encoding", &hf_http_content_encoding, HDR_CONTENT_ENCODING },
	{ "Transfer-Encoding", &hf_http_transfer_encoding, HDR_TRANSFER_ENCODING },
	{ "User-Agent",	&hf_http_user_agent, HDR_NO_SPECIAL },
	{ "Host", &hf_http_host, HDR_HOST },
	{ "Connection", &hf_http_connection, HDR_NO_SPECIAL },
	{ "Cookie", &hf_http_cookie, HDR_NO_SPECIAL },
	{ "Accept", &hf_http_accept, HDR_NO_SPECIAL },
	{ "Referer", &hf_http_referer, HDR_NO_SPECIAL },
	{ "Accept-Language", &hf_http_accept_language, HDR_NO_SPECIAL },
	{ "Accept-Encoding", &hf_http_accept_encoding, HDR_NO_SPECIAL },
	{ "Date", &hf_http_date, HDR_NO_SPECIAL },
	{ "Cache-Control", &hf_http_cache_control, HDR_NO_SPECIAL },
	{ "Server", &hf_http_server, HDR_NO_SPECIAL },
	{ "Location", &hf_http_location, HDR_NO_SPECIAL },
	{ "Set-Cookie", &hf_http_set_cookie, HDR_NO_SPECIAL },
	{ "Last-Modified", &hf_http_last_modified, HDR_NO_SPECIAL },
	{ "X-Forwarded-For", &hf_http_x_forwarded_for, HDR_NO_SPECIAL },
};

static void
process_header(tvbuff_t *tvb, int offset, int next_offset,
    const guchar *line, int linelen, int colon_offset,
    packet_info *pinfo, proto_tree *tree, headers_t *eh_ptr)
{
	int len;
	int line_end_offset;
	int header_len;
	gint hf_index;
	guchar c;
	int value_offset;
	int value_len;
	char *value;
	char *p;
	guchar *up;
	proto_item *hdr_item;
	int i;

	len = next_offset - offset;
	line_end_offset = offset + linelen;
	header_len = colon_offset - offset;
	hf_index = find_header_hf_value(tvb, offset, header_len);

	if (hf_index == -1) {
		/*
		 * Not a header we know anything about.  Just put it into
		 * the tree as text.
		 */
		if (tree) {
			proto_tree_add_text(tree, tvb, offset, len,
			    "%s", format_text(line, len));
		}
	} else {
		/*
		 * Skip whitespace after the colon.
		 */
		value_offset = colon_offset + 1;
		while (value_offset < line_end_offset
		    && ((c = line[value_offset - offset]) == ' ' || c == '\t'))
			value_offset++;

		/*
		 * Fetch the value.
		 */
		value_len = line_end_offset - value_offset;
		value = ep_strndup(&line[value_offset - offset], value_len);

		/*
		 * Add it to the protocol tree as a particular field,
		 * but display the line as is.
		 */
		if (tree) {
			hdr_item = proto_tree_add_string_format(tree,
			    *headers[hf_index].hf, tvb, offset, len,
			    value, "%s", format_text(line, len));
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
			check_auth_basic(hdr_item, tvb, value);
			break;

		case HDR_AUTHENTICATE:
			check_auth_ntlmssp(hdr_item, tvb, pinfo, value);
			break;

		case HDR_CONTENT_TYPE:
			eh_ptr->content_type = (gchar*) ep_memdup((guint8*)value,value_len + 1);

			for (i = 0; i < value_len; i++) {
				c = value[i];
				if (c == ';' || isspace(c)) {
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
				eh_ptr->content_type[i] = tolower(eh_ptr->content_type[i]);
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
				if (c == ';' || isspace(c))
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
			eh_ptr->content_length = strtol(value, &p, 10);
			up = (guchar *)p;
			if (eh_ptr->content_length < 0 || p == value ||
			    (*up != '\0' && !isspace(*up))) {
				/*
				 * Content length not valid; pretend
				 * we don't have it.
				 */
				eh_ptr->have_content_length = FALSE;
			} else {
				/*
				 * We do have a valid content length.
				 */
				eh_ptr->have_content_length = TRUE;
			}
			break;

		case HDR_CONTENT_ENCODING:
			eh_ptr->content_encoding = ep_strndup(value, value_len);
			break;

		case HDR_TRANSFER_ENCODING:
			eh_ptr->transfer_encoding = ep_strndup(value, value_len);
			break;

		case HDR_HOST:
			stat_info->http_host = se_strndup(value, value_len);
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
check_auth_ntlmssp(proto_item *hdr_item, tvbuff_t *tvb, packet_info *pinfo,
    gchar *value)
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
	size_t len;

	for (header = &basic_headers[0]; *header != NULL; header++) {
		hdrlen = strlen(*header);
		if (strncmp(value, *header, hdrlen) == 0) {
			if (hdr_item != NULL) {
				hdr_tree = proto_item_add_subtree(hdr_item,
				    ett_http_ntlmssp);
			} else
				hdr_tree = NULL;
			value += hdrlen;

			len = epan_base64_decode(value);
			value[len] = '\0';
			proto_tree_add_string(hdr_tree, hf_http_basic, tvb,
			    0, 0, value);

			return TRUE;
		}
	}
	return FALSE;
}

static void
dissect_http(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int		offset = 0;
	int		len;

	while (tvb_reported_length_remaining(tvb, offset) != 0) {
		len = dissect_http_message(tvb, offset, pinfo, tree);
		if (len == -1)
			break;
		offset += len;

		/*
		 * OK, we've set the Protocol and Info columns for the
		 * first HTTP message; make the columns non-writable,
		 * so that we don't change it for subsequent HTTP messages.
		 */
		col_set_writable(pinfo->cinfo, FALSE);
	}
}

static void
dissect_http_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_http_message(tvb, 0, pinfo, tree);
}

static void reinit_http(void) {
	if ( http_alternate_tcp_port != alternate_tcp_port ) {

		if (alternate_tcp_port)
			dissector_delete("tcp.port", alternate_tcp_port, http_handle );

		if (http_alternate_tcp_port)
			dissector_add("tcp.port", http_alternate_tcp_port, http_handle);

		alternate_tcp_port = http_alternate_tcp_port;
	}
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
		FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
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
	    { &hf_http_response_code,
	      { "Response Code",	"http.response.code",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		"HTTP Response Code", HFILL }},
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
	    { &hf_http_www_authenticate,
	      { "WWW-Authenticate",	"http.www_authenticate",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP WWW-Authenticate header", HFILL }},
	    { &hf_http_content_type,
	      { "Content-Type",	"http.content_type",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Content-Type header", HFILL }},
	    { &hf_http_content_length,
	      { "Content-Length",	"http.content_length",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Content-Length header", HFILL }},
	    { &hf_http_content_encoding,
	      { "Content-Encoding",	"http.content_encoding",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Content-Encoding header", HFILL }},
	    { &hf_http_transfer_encoding,
	      { "Transfer-Encoding",	"http.transfer_encoding",
		FT_STRING, BASE_NONE, NULL, 0x0,
		"HTTP Transfer-Encoding header", HFILL }},
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
	};
	static gint *ett[] = {
		&ett_http,
		&ett_http_ntlmssp,
		&ett_http_request,
		&ett_http_chunked_response,
		&ett_http_chunk_data,
		&ett_http_encoded_entity,
	};
	module_t *http_module;

	proto_http = proto_register_protocol("Hypertext Transfer Protocol",
	    "HTTP", "http");
	proto_register_field_array(proto_http, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_dissector("http", dissect_http, proto_http);
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
	    "Whether to reassemble bodies of entities that are transfered "
	    "using the \"Transfer-Encoding: chunked\" method",
	    &http_dechunk_body);
#ifdef HAVE_LIBZ
	prefs_register_bool_preference(http_module, "decompress_body",
	    "Uncompress entity bodies",
	    "Whether to uncompress entity bodies that are compressed "
	    "using \"Content-Encoding: \"",
	    &http_decompress_body);
#endif
	prefs_register_uint_preference(http_module, "tcp_alternate_port",
								   "Alternate TCP port",
								   "Decode packets on this TCP port as HTTP",
								   10,&http_alternate_tcp_port);

	http_handle = create_dissector_handle(dissect_http, proto_http);

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
	http_tap = register_tap("http");
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
	dissector_add("tcp.port", port, http_handle);

	/*
	 * And register them in *our* table for that port.
	 */
	dissector_add("http.port", port, handle);
}

void
proto_reg_handoff_http(void)
{
	dissector_handle_t http_udp_handle;

	data_handle = find_dissector("data");
	media_handle = find_dissector("media");

	dissector_add("tcp.port", TCP_PORT_HTTP, http_handle);
	dissector_add("tcp.port", TCP_PORT_PROXY_HTTP, http_handle);
	dissector_add("tcp.port", TCP_ALT_PORT_HTTP, http_handle);
	dissector_add("tcp.port", TCP_RADAN_HTTP, http_handle);
	dissector_add("tcp.port", TCP_PORT_PROXY_ADMIN_HTTP, http_handle);
	dissector_add("tcp.port", TCP_PORT_HKP, http_handle);

	/*
	 * XXX - is there anything to dissect in the body of an SSDP
	 * request or reply?  I.e., should there be an SSDP dissector?
	 */
	dissector_add("tcp.port", TCP_PORT_SSDP, http_handle);
	http_udp_handle = create_dissector_handle(dissect_http_udp, proto_http);
	dissector_add("udp.port", UDP_PORT_SSDP, http_udp_handle);

	ntlmssp_handle = find_dissector("ntlmssp");
	gssapi_handle = find_dissector("gssapi");

	stats_tree_register("http","http","HTTP/Packet Counter", http_stats_tree_packet, http_stats_tree_init, NULL );
	stats_tree_register("http","http_req","HTTP/Requests", http_req_stats_tree_packet, http_req_stats_tree_init, NULL );
	stats_tree_register("http","http_srv","HTTP/Load Distribution",http_reqs_stats_tree_packet,http_reqs_stats_tree_init, NULL );

}

/*
 * Content-Type: message/http
 */

static gint proto_message_http = -1;
static gint ett_message_http = -1;
static dissector_handle_t message_http_handle;

static void
dissect_message_http(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*subtree;
	proto_item	*ti;
	gint		offset = 0, next_offset;
	gint		len;

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_str(pinfo->cinfo, COL_INFO, " (message/http)");
	if (tree) {
		ti = proto_tree_add_item(tree, proto_message_http,
				tvb, 0, -1, FALSE);
		subtree = proto_item_add_subtree(ti, ett_message_http);
		while (tvb_reported_length_remaining(tvb, offset) != 0) {
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
	message_http_handle = create_dissector_handle(dissect_message_http,
			proto_message_http);

	dissector_add_string("media_type", "message/http", message_http_handle);
}
