/* packet-http.c
 * Routines for HTTP packet disassembly
 *
 * Guy Harris <guy@alum.mit.edu>
 *
 * $Id: packet-http.c,v 1.29 2000/11/19 08:53:57 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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
 *
 *
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
#include "packet.h"
#include "strutil.h"

typedef enum _http_type {
	HTTP_REQUEST,
	HTTP_RESPONSE,
	HTTP_OTHERS
} http_type_t;

static int proto_http = -1;
static int hf_http_response = -1;
static int hf_http_request = -1;

static gint ett_http = -1;

#define TCP_PORT_HTTP			80
#define TCP_PORT_PROXY_HTTP		3128
#define TCP_PORT_PROXY_ADMIN_HTTP	3132
#define TCP_ALT_PORT_HTTP		8080

static int is_http_request_or_reply(const u_char *data, int linelen, http_type_t *type);

static dissector_handle_t ipp_handle;

void
dissect_http(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gboolean	is_ipp = (pinfo->srcport == 631 || pinfo->destport == 631);
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

	CHECK_DISPLAY_AS_DATA(proto_http, tvb, pinfo, tree);

	pinfo->current_proto = "HTTP";

	if (check_col(pinfo->fd, COL_PROTOCOL))
		col_set_str(pinfo->fd, COL_PROTOCOL, is_ipp ? "IPP" : "HTTP");
	if (check_col(pinfo->fd, COL_INFO)) {
		/*
		 * Put the first line from the buffer into the summary
		 * if it's an HTTP request or reply (but leave out the
		 * line terminator).
		 * Otherwise, just call it a continuation.
		 */
		linelen = tvb_find_line_end(tvb, offset, -1, &next_offset);
		line = tvb_get_ptr(tvb, offset, linelen);
		if (is_http_request_or_reply(line, linelen, &http_type))
			col_add_str(pinfo->fd, COL_INFO,
			    format_text(line, linelen));
		else
			col_set_str(pinfo->fd, COL_INFO, "Continuation");
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_http, tvb, offset,
		    tvb_length_remaining(tvb, offset), FALSE);
		http_tree = proto_item_add_subtree(ti, ett_http);

		/*
		 * Process the packet data, a line at a time.
		 */
		while (tvb_offset_exists(tvb, offset)) {
			/*
			 * Find the end of the line.
			 */
			linelen = tvb_find_line_end(tvb, offset, -1,
			    &next_offset);

			/*
			 * Get a buffer that refers to the line.
			 */
			line = tvb_get_ptr(tvb, offset, linelen);
			lineend = line + linelen;

			/*
			 * OK, does it look like an HTTP request or
			 * response?
			 */
			if (is_http_request_or_reply(line, linelen, &http_type))
				goto is_http;

			/*
			 * No.  Does it look like a blank line (as would
			 * appear at the end of an HTTP request)?
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
					 * It's a tspecial, so it's not
					 * part of a token, so it's not
					 * a field name for the beginning
					 * of a MIME header.
					 */
					goto not_http;

				case ':':
					/*
					 * This ends the token; we consider
					 * this to be a MIME header.
					 */
					goto is_http;
				}
			}

		not_http:
			/*
			 * We don't consider this part of an HTTP request or
			 * reply, so we don't display it.
			 * (Yeah, that means we don't display, say, a
			 * text/http page, but you can get that from the
			 * data pane.)
			 */
			break;

		is_http:
			/*
			 * Put this line.
			 */
			proto_tree_add_text(http_tree, tvb, offset,
			    next_offset - offset, "%s",
			    tvb_format_text(tvb, offset, next_offset - offset));
			offset = next_offset;
		}

		switch (http_type) {

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
		if (is_ipp) {
			tvbuff_t *new_tvb = tvb_new_subset(tvb, offset, -1, -1);

			/*
			 * Fix up the top-level item so that it doesn't
			 * include the IPP stuff.
			 */
			if (ti != NULL)
				proto_item_set_len(ti, offset);

			call_dissector(ipp_handle, new_tvb, pinfo, tree);
		} else
			dissect_data(tvb, offset, pinfo, http_tree);
	}
}

/*
 * XXX - this won't handle HTTP 0.9 replies, but they're all data
 * anyway.
 */
static int
is_http_request_or_reply(const u_char *data, int linelen, http_type_t *type)
{
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
	}
	if (linelen >= 8) {
		if (strncmp(data, "OPTIONS ", 8) == 0 ||
		    strncmp(data, "CONNECT ", 8) == 0) {
			if (*type == HTTP_OTHERS)
				*type = HTTP_REQUEST;
			return TRUE;
		}
	}
	return FALSE;
}

void
proto_register_http(void)
{
	static hf_register_info hf[] = {
	    { &hf_http_response,
	      { "Response",		"http.response",  
		FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		"TRUE if HTTP response" }},
	    { &hf_http_request,
	      { "Request",		"http.request",
		FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		"TRUE if HTTP request" }},
	};
	static gint *ett[] = {
		&ett_http,
	};

	proto_http = proto_register_protocol("Hypertext Transfer Protocol",
	    "http");
	proto_register_field_array(proto_http, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_http(void)
{
	dissector_add("tcp.port", TCP_PORT_HTTP, dissect_http);
	dissector_add("tcp.port", TCP_ALT_PORT_HTTP, dissect_http);
	dissector_add("tcp.port", TCP_PORT_PROXY_HTTP, dissect_http);
	dissector_add("tcp.port", TCP_PORT_PROXY_ADMIN_HTTP, dissect_http);

	/*
	 * Get a handle for the IPP dissector.
	 */
	ipp_handle = find_dissector("ipp");
}
