/* packet-http.c
 * Routines for HTTP packet disassembly
 *
 * Guy Harris <guy@alum.mit.edu>
 *
 * Copyright 2002, Tim Potter <tpot@samba.org>
 * Copyright 1999, Andrew Tridgell <tridge@samba.org>
 *
 * $Id: packet-http.c,v 1.93 2004/01/19 23:57:11 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
#include <epan/packet.h>
#include <epan/strutil.h>

#include "util.h"
#include "req_resp_hdrs.h"
#include "packet-http.h"
#include "prefs.h"

typedef enum _http_type {
	HTTP_REQUEST,
	HTTP_RESPONSE,
	HTTP_NOTIFICATION,
	HTTP_OTHERS
} http_type_t;

#include "tap.h"

static int http_tap = -1;

static int proto_http = -1;
static int hf_http_notification = -1;
static int hf_http_response = -1;
static int hf_http_request = -1;
static int hf_http_basic = -1;
static int hf_http_request_method = -1;
static int hf_http_response_code = -1;
static int hf_http_authorization = -1;
static int hf_http_proxy_authenticate = -1;
static int hf_http_proxy_authorization = -1;
static int hf_http_www_authenticate = -1;
static int hf_http_content_type = -1;
static int hf_http_content_length = -1;

static gint ett_http = -1;
static gint ett_http_ntlmssp = -1;
static gint ett_http_request = -1;

static dissector_handle_t data_handle;
static dissector_handle_t http_handle;

/*
 * desegmentation of HTTP headers
 * (when we are over TCP or another protocol providing the desegmentation API)
 */
static gboolean http_desegment_headers = FALSE;

/*
 * desegmentation of HTTP bodies
 * (when we are over TCP or another protocol providing the desegmentation API)
 * TODO let the user filter on content-type the bodies he wants desegmented
 */
static gboolean http_desegment_body = FALSE;

#define TCP_PORT_HTTP			80
#define TCP_PORT_PROXY_HTTP		3128
#define TCP_PORT_PROXY_ADMIN_HTTP	3132
#define TCP_ALT_PORT_HTTP		8080

/*
 * SSDP is implemented atop HTTP (yes, it really *does* run over UDP).
 */
#define TCP_PORT_SSDP			1900
#define UDP_PORT_SSDP			1900

/*
 * Protocols implemented atop HTTP.
 */
typedef enum {
	PROTO_HTTP,		/* just HTTP */
	PROTO_SSDP		/* Simple Service Discovery Protocol */
} http_proto_t;

typedef void (*RequestDissector)(tvbuff_t*, proto_tree*, int);

/*
 * Structure holding information from headers needed by main
 * HTTP dissector code.
 */
typedef struct {
	char	*content_type;
	char	*content_type_parameters;
	long	content_length;	/* XXX - make it 64-bit? */
} headers_t;

static int is_http_request_or_reply(const gchar *data, int linelen, http_type_t *type,
		RequestDissector *req_dissector, int *req_strlen);
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


/* Return a tvb that contains the binary representation of a base64
   string */

static tvbuff_t *
base64_to_tvb(const char *base64)
{
	tvbuff_t *tvb;
	char *data = g_strdup(base64);
	size_t len;

	len = base64_decode(data);
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
	add_new_data_source(pinfo, ntlmssp_tvb, "NTLMSSP Data");

	call_dissector(ntlmssp_handle, ntlmssp_tvb, pinfo, tree);
}

static void
cleanup_headers(void *arg)
{
	headers_t *headers = arg;

	g_free(headers->content_type);
	/*
	 * The content_type_parameters field actually points into the
	 * content_type headers, so don't attempt at freeing it twice.
	 */
}

/*
 * TODO: remove this ugly global variable.
 *
 * XXX - we leak "http_info_value_t" structures.
 * XXX - this gets overwritten if there's more than one HTTP request or
 * reply in the tvbuff.
 */
static http_info_value_t	*stat_info;

static int
dissect_http_message(tvbuff_t *tvb, int offset, packet_info *pinfo,
    proto_tree *tree)
{
	http_proto_t	proto;
	char		*proto_tag;
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
	proto_item	*hdr_item;
	RequestDissector req_dissector;
	int		req_strlen;
	proto_tree	*req_tree;
	int		colon_offset;
	headers_t	headers;
	int		datalen;
	int		reported_datalen;
	dissector_handle_t handle;
	gboolean	dissected;

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
			first_linelen, &http_type, NULL, NULL);
	if (is_request_or_reply) {
		/*
		 * Yes, it's a request or response.
		 * Do header desegmentation if we've been told to,
		 * and do body desegmentation if we've been told to and
		 * we find a Content-Length header.
		 */
		if (!req_resp_hdrs_do_reassembly(tvb, pinfo,
		    http_desegment_headers, http_desegment_body)) {
			/*
			 * More data needed for desegmentation.
			 */
			return -1;
		}
	}

	stat_info = g_malloc(sizeof(http_info_value_t));
	stat_info->response_code = 0;
	stat_info->request_method = NULL;

	switch (pinfo->match_port) {

	case TCP_PORT_SSDP:	/* TCP_PORT_SSDP = UDP_PORT_SSDP */
		proto = PROTO_SSDP;
		proto_tag = "SSDP";
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
			col_set_str(pinfo->cinfo, COL_INFO, "Continuation");
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
	headers.content_length = -1;	/* content length not known yet */
	saw_req_resp_or_header = FALSE;	/* haven't seen anything yet */
	CLEANUP_PUSH(cleanup_headers, &headers);
	while (tvb_reported_length_remaining(tvb, offset) != 0) {
		/*
		 * Find the end of the line.
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
		req_dissector = NULL;
		is_request_or_reply = is_http_request_or_reply((const gchar *)line,
				linelen, &http_type, &req_dissector, &req_strlen);
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
			 * This mustn't be a CTL to be part of a token;
			 * that means it must be printable.
			 *
			 * XXX - what about leading LWS on continuation
			 * lines of a header?
			 */
			if (!isprint(c))
				break;	/* not printable, not a header */

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
				 * already been ruled out by "isprint()".)
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
				if (req_dissector) {
					req_tree = proto_item_add_subtree(
					    hdr_item, ett_http_request);
					req_dissector(tvb, req_tree,
					    req_strlen);
				}
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
	if (headers.content_length != -1) {
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
		if ((stat_info->response_code/100) == 1 ||
		    stat_info->response_code == 204 ||
		    stat_info->response_code == 304)
			datalen = 0;	/* no content! */
		else
			reported_datalen = -1;
	}

	if (datalen > 0) {
		/*
		 * There's stuff left over; process it.
		 */
		tvbuff_t *next_tvb;
		void *save_private_data = NULL;

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
				pinfo->private_data = g_strdup(headers.content_type_parameters);
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
			call_dissector(data_handle, next_tvb, pinfo,
			    http_tree);
		}

		/*
		 * Do *not* attempt at freeing the private data;
		 * it may be in use by subdissectors
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

	/*
	 * Clean up any header stuff, by calling and popping the cleanup
	 * handler.
	 */
	CLEANUP_CALL_AND_POP;

	tap_queue_packet(http_tap, pinfo, stat_info);

	return offset - orig_offset;
}

/* This can be used to dissect an HTTP request until such time
 * that a more complete dissector is written for that HTTP request.
 * This simple dissectory only puts http.request_method into a sub-tree.
 */
static void
basic_request_dissector(tvbuff_t *tvb, proto_tree *tree, int req_strlen)
{
	proto_tree_add_item(tree, hf_http_request_method, tvb, 0, req_strlen, FALSE);
}

static void
basic_response_dissector(tvbuff_t *tvb, proto_tree *tree, int req_strlen _U_)
{
	const guchar *data;
	int minor, major, status_code;

	data = tvb_get_ptr(tvb, 5, 12);
	if (sscanf((const gchar *)data, "%d.%d %d", &minor, &major, &status_code) == 3) {
		proto_tree_add_uint(tree, hf_http_response_code, tvb, 9, 3, status_code);
		stat_info->response_code = status_code;
	}
}

/*
 * XXX - this won't handle HTTP 0.9 replies, but they're all data
 * anyway.
 */
static int
is_http_request_or_reply(const gchar *data, int linelen, http_type_t *type,
		RequestDissector *req_dissector, int *req_strlen)
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
		if (req_dissector) {
			*req_dissector = basic_response_dissector;
			*req_strlen = linelen - 5;
		}
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
				strncmp(data, "TRACE", index) == 0) {
				*type = HTTP_REQUEST;
				isHttpRequestOrReply = TRUE;
			}
			break;

		case 6:
			if (strncmp(data, "DELETE", index) == 0 ||
				strncmp(data, "SEARCH", index) == 0 ||
				strncmp(data, "UNLOCK", index) == 0) {
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
			    strncmp(data, "OPTIONS", index) == 0) {
				*type = HTTP_REQUEST;
				isHttpRequestOrReply = TRUE;
			}
			break;

		case 8:
			if (strncmp(data, "PROPFIND", index) == 0) {
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
			if (strncmp(data, "BPROPPATCH", index) == 0) {
				*type = HTTP_REQUEST;
				isHttpRequestOrReply = TRUE;
			}
			break;

		case 11:
			if (strncmp(data, "UNSUBSCRIBE", index) == 0) {
				*type = HTTP_NOTIFICATION;
				isHttpRequestOrReply = TRUE;
			}
			break;

		default:
			break;
		}

		if (isHttpRequestOrReply && req_dissector) {
			*req_dissector = basic_request_dissector;
			*req_strlen = index + prefix_len;
		}
		if (isHttpRequestOrReply && req_dissector) {
			if (!stat_info->request_method)
				stat_info->request_method = g_malloc( index+1 );
				strncpy( stat_info->request_method, data, index);
				stat_info->request_method[index] = '\0';
		}
	}

	return isHttpRequestOrReply;
}

/*
 * Process headers.
 */
typedef struct {
	char	*name;
	gint	*hf;
	int	special;
} header_info;

#define HDR_NO_SPECIAL		0
#define HDR_AUTHORIZATION	1
#define HDR_AUTHENTICATE	2
#define HDR_CONTENT_TYPE	3
#define HDR_CONTENT_LENGTH	4

static const header_info headers[] = {
	{ "Authorization", &hf_http_authorization, HDR_AUTHORIZATION },
	{ "Proxy-Authorization", &hf_http_proxy_authorization, HDR_AUTHORIZATION },
	{ "Proxy-Authenticate", &hf_http_proxy_authenticate, HDR_AUTHENTICATE },
	{ "WWW-Authenticate", &hf_http_www_authenticate, HDR_AUTHENTICATE },
	{ "Content-Type", &hf_http_content_type, HDR_CONTENT_TYPE },
	{ "Content-Length", &hf_http_content_length, HDR_CONTENT_LENGTH },
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
		value = g_malloc(value_len + 1);
		memcpy(value, &line[value_offset - offset], value_len);
		value[value_len] = '\0';
		CLEANUP_PUSH(g_free, value);

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
			if (eh_ptr->content_type != NULL)
				g_free(eh_ptr->content_type);
			eh_ptr->content_type = g_malloc(value_len + 1);
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
				eh_ptr->content_type[i] = tolower(c);
			}
			eh_ptr->content_type[i] = '\0';
			/*
			 * Now find the start of the optional parameters;
			 * skip the optional white space and the semicolon
			 * if this has not been done before.
			 */
			i++;
			while (i < value_len) {
				c = value[i];
				if (c == ';' || isspace(c))
					/* Skip till start of parameters */
					i++;
				else
					break;
			}
			if (i < value_len)
				eh_ptr->content_type_parameters = value + i;
			else
				eh_ptr->content_type_parameters = NULL;
			break;

		case HDR_CONTENT_LENGTH:
			eh_ptr->content_length = strtol(value, &p, 10);
			up = (guchar *)p;
			if (eh_ptr->content_length < 0 || p == value ||
			    (*up != '\0' && !isspace(*up)))
				eh_ptr->content_length = -1;	/* not valid */
			break;
		}

		/*
		 * Free the value, by calling and popping the cleanup
		 * handler for it.
		 */
		CLEANUP_CALL_AND_POP;
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
						(const guint8 *)headers[i].name, header_len) == 0)
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

			len = base64_decode(value);
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
	};
	static gint *ett[] = {
		&ett_http,
		&ett_http_ntlmssp,
		&ett_http_request,
	};
	module_t *http_module;

	proto_http = proto_register_protocol("Hypertext Transfer Protocol",
	    "HTTP", "http");
	proto_register_field_array(proto_http, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	http_module = prefs_register_protocol(proto_http, NULL);
	prefs_register_bool_preference(http_module, "desegment_headers",
	    "Desegment all HTTP headers spanning multiple TCP segments",
	    "Whether the HTTP dissector should desegment all headers "
	    "of a request spanning multiple TCP segments",
	    &http_desegment_headers);
	prefs_register_bool_preference(http_module, "desegment_body",
	    "Trust the \"Content-length:\" header and desegment HTTP "
	    "bodies\nspanning multiple TCP segments",
	    "Whether the HTTP dissector should use the "
	    "\"Content-length:\" value to desegment the body "
	    "of a request spanning multiple TCP segments",
	    &http_desegment_body);

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

	dissector_add("tcp.port", TCP_PORT_HTTP, http_handle);
	dissector_add("tcp.port", TCP_ALT_PORT_HTTP, http_handle);
	dissector_add("tcp.port", TCP_PORT_PROXY_HTTP, http_handle);
	dissector_add("tcp.port", TCP_PORT_PROXY_ADMIN_HTTP, http_handle);

	/*
	 * XXX - is there anything to dissect in the body of an SSDP
	 * request or reply?  I.e., should there be an SSDP dissector?
	 */
	dissector_add("tcp.port", TCP_PORT_SSDP, http_handle);
	http_udp_handle = create_dissector_handle(dissect_http_udp, proto_http);
	dissector_add("udp.port", UDP_PORT_SSDP, http_udp_handle);

	ntlmssp_handle = find_dissector("ntlmssp");
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
	message_http_handle = create_dissector_handle(dissect_message_http,
			proto_message_http);
}

void
proto_reg_handoff_message_http(void)
{
	message_http_handle = create_dissector_handle(dissect_message_http,
			proto_message_http);

	dissector_add_string("media_type", "message/http", message_http_handle);
}
