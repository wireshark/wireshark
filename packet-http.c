/* packet-http.c
 * Routines for HTTP packet disassembly
 *
 * Guy Harris <guy@alum.mit.edu>
 *
 * $Id: packet-http.c,v 1.45 2002/01/21 07:36:35 guy Exp $
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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <string.h>
#include <ctype.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/strutil.h>

#include "packet-http.h"

typedef enum _http_type {
	HTTP_REQUEST,
	HTTP_RESPONSE,
	HTTP_NOTIFICATION,
	HTTP_OTHERS
} http_type_t;

static int proto_http = -1;
static int hf_http_notification = -1;
static int hf_http_response = -1;
static int hf_http_request = -1;

static gint ett_http = -1;

static dissector_handle_t data_handle;
static dissector_handle_t http_handle;

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

static int is_http_request_or_reply(const u_char *data, int linelen, http_type_t *type);

static dissector_table_t subdissector_table;
static heur_dissector_list_t heur_subdissector_list;

static void
dissect_http(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	http_proto_t	proto;
	char		*proto_tag;
	proto_tree	*http_tree = NULL;
	proto_item	*ti = NULL;
	gint		offset = 0;
	const u_char	*line;
	gint		next_offset;
	const u_char	*linep, *lineend;
	int		linelen;
	u_char		c;
	http_type_t     http_type;
	int		datalen;

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
		linelen = tvb_find_line_end(tvb, offset, -1, &next_offset);
		line = tvb_get_ptr(tvb, offset, linelen);
		http_type = HTTP_OTHERS;	/* type not known yet */
		if (is_http_request_or_reply(line, linelen, &http_type))
			col_add_str(pinfo->cinfo, COL_INFO,
			    format_text(line, linelen));
		else
			col_set_str(pinfo->cinfo, COL_INFO, "Continuation");
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_http, tvb, offset,
		    tvb_length_remaining(tvb, offset), FALSE);
		http_tree = proto_item_add_subtree(ti, ett_http);
	}

	/*
	 * Process the packet data, a line at a time.
	 */
	http_type = HTTP_OTHERS;	/* type not known yet */
	while (tvb_offset_exists(tvb, offset)) {
		/*
		 * Find the end of the line.
		 */
		linelen = tvb_find_line_end(tvb, offset, -1, &next_offset);

		/*
		 * Get a buffer that refers to the line.
		 */
		line = tvb_get_ptr(tvb, offset, linelen);
		lineend = line + linelen;

		/*
		 * OK, does it look like an HTTP request or response?
		 */
		if (is_http_request_or_reply(line, linelen, &http_type))
			goto is_http;

		/*
		 * No.  Does it look like a blank line (as would appear
		 * at the end of an HTTP request)?
		 */
		if (linelen == 0)
			goto is_http;

		/*
		 * No.  Does it look like a MIME header?
		 */
		linep = line;
		while (linep < lineend) {
			c = *linep++;
			if (!isprint(c))
				break;	/* not printable, not a MIME header */
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
				/*
				 * It's a tspecial, so it's not part of a
				 * token, so it's not a field name for the
				 * beginning of a MIME header.
				 */
				goto not_http;

			case ':':
				/*
				 * This ends the token; we consider this
				 * to be a MIME header.
				 */
				goto is_http;
			}
		}

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
		 * Put this line.
		 */
		if (tree) {
			proto_tree_add_text(http_tree, tvb, offset,
			    next_offset - offset, "%s",
			    tvb_format_text(tvb, offset, next_offset - offset));
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

	datalen = tvb_length_remaining(tvb, offset);
	if (datalen > 0) {
		tvbuff_t *next_tvb = tvb_new_subset(tvb, offset, -1, -1);

		/*
		 * OK, has some subdissector asked that they be called
		 * if something was on some particular port?
		 */
		if (dissector_try_port(subdissector_table, pinfo->match_port,
		    next_tvb, pinfo, tree)) {
			/*
			 * Yes.  Fix up the top-level item so that it
			 * doesn't include the stuff for that protocol.
			 */
			if (ti != NULL)
				proto_item_set_len(ti, offset);
		} else if(dissector_try_heuristic(heur_subdissector_list,
						  next_tvb,pinfo,tree)){
			/*
			 * Yes.  Fix up the top-level item so that it
			 * doesn't include the stuff for that protocol.
			 */
			if (ti != NULL)
				proto_item_set_len(ti, offset);
		} else
			call_dissector(data_handle,tvb_new_subset(tvb, offset,-1,tvb_reported_length_remaining(tvb,offset)), pinfo, http_tree);
	}
}

/*
 * XXX - this won't handle HTTP 0.9 replies, but they're all data
 * anyway.
 */
static int
is_http_request_or_reply(const u_char *data, int linelen, http_type_t *type)
{
	/*
	 * From RFC 2774 - An HTTP Extension Framework
	 *
	 * Support the command prefix that identifies the presence of
	 * a "mandatory" header.
	 */
	if (strncmp(data, "M-", 2) == 0) {
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
	if (linelen >= 4) {
		if (strncmp(data, "GET ", 4) == 0 ||
		    strncmp(data, "PUT ", 4) == 0) {
			if (*type == HTTP_OTHERS)
				*type = HTTP_REQUEST;
			return TRUE;
		}
	}
	if (linelen >= 5) {
		if (strncmp(data, "HEAD ", 5) == 0 ||
		    strncmp(data, "POST ", 5) == 0) {
			if (*type == HTTP_OTHERS)
				*type = HTTP_REQUEST;
			return TRUE;
		}
		if (strncmp(data, "HTTP/", 5) == 0) {
			if (*type == HTTP_OTHERS)
				*type = HTTP_RESPONSE;
			return TRUE;	/* response */
		}
	}
	if (linelen >= 6) {
		if (strncmp(data, "TRACE ", 6) == 0) {
			if (*type == HTTP_OTHERS)
				*type = HTTP_REQUEST;
			return TRUE;
		}
	}
	if (linelen >= 7) {
		if (strncmp(data, "DELETE ", 7) == 0) {
			if (*type == HTTP_OTHERS)
				*type = HTTP_REQUEST;
			return TRUE;
		}
		if (strncmp(data, "NOTIFY ", 7) == 0 ||
		    strncmp(data, "SEARCH ", 7) == 0) {
			if (*type == HTTP_OTHERS)
				*type = HTTP_NOTIFICATION;
			return TRUE;
		}
	}
	if (linelen >= 8) {
		if (strncmp(data, "OPTIONS ", 8) == 0 ||
		    strncmp(data, "CONNECT ", 8) == 0) {
			if (*type == HTTP_OTHERS)
				*type = HTTP_REQUEST;
			return TRUE;
		}
	}
	if (linelen >= 10) {
		if (strncmp(data, "SUBSCRIBE ", 10) == 0) {
			if (*type == HTTP_OTHERS)
				*type = HTTP_NOTIFICATION;
			return TRUE;
		}
	}
	if (linelen >= 12) {
		if (strncmp(data, "UNSUBSCRIBE ", 10) == 0) {
			if (*type == HTTP_OTHERS)
				*type = HTTP_NOTIFICATION;
			return TRUE;
		}
	}
	return FALSE;
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
	};
	static gint *ett[] = {
		&ett_http,
	};

	proto_http = proto_register_protocol("Hypertext Transfer Protocol",
	    "HTTP", "http");
	proto_register_field_array(proto_http, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("http", dissect_http, proto_http);
	http_handle = find_dissector("http");

	/*
	 * Dissectors shouldn't register themselves in this table;
	 * instead, they should call "http_dissector_add()", and
	 * we'll register the port number they specify as a port
	 * for HTTP, and register them in our subdissector table.
	 *
	 * This only works for protocols such as IPP that run over
	 * HTTP on a specific non-HTTP port.
	 */
	subdissector_table = register_dissector_table("http.port",
	    "TCP port for protocols using HTTP", FT_UINT16, BASE_DEC);

	/* 
	 * Heuristic dissectors SHOULD register themselves in 
	 * this table using the standard heur_dissector_add() 
	 * function.
	 */

	register_heur_dissector_list("http",&heur_subdissector_list);
	
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
	dissector_add("udp.port", UDP_PORT_SSDP, http_handle);
}
