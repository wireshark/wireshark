/* packet-rtsp.c
 * Routines for RTSP packet disassembly
 *
 * Jason Lango <jal@netapp.com>
 * Liberally copied from packet-http.c, by Guy Harris <guy@netapp.com>
 *
 * $Id: packet-rtsp.c,v 1.5 2000/01/13 03:07:26 guy Exp $
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

#include "config.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <string.h>
#include <ctype.h>

#include <glib.h>
#include "packet.h"

static int proto_rtsp = -1;
static gint ett_rtsp = -1;

static int hf_rtsp_method = -1;
static int hf_rtsp_url = -1;
static int hf_rtsp_status = -1;

static int process_rtsp_request_or_reply(const u_char *data, int offset,
	int linelen, proto_tree *tree);

static int
is_content_sdp(const u_char *line, int linelen)
{
	const char	*hdr = "Content-Type:";
	size_t		hdrlen = strlen(hdr);
	const char	*type = "application/sdp";
	size_t		typelen = strlen(type);

	if (linelen < hdrlen || strncasecmp(hdr, line, hdrlen))
		return 0;

	line += hdrlen;
	linelen -= hdrlen;
	while (linelen > 0 && (*line == ' ' || *line == '\t')) {
		line++;
		linelen--;
	}

	if (linelen < typelen || strncasecmp(type, line, typelen))
		return 0;

	line += typelen;
	linelen -= typelen;
	if (linelen > 0 && !isspace(*line))
		return 0;

	return 1;
}

void dissect_rtsp(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree)
{
	proto_tree	*rtsp_tree;
	proto_item	*ti;
	const u_char	*data, *dataend;
	const u_char	*linep, *lineend, *eol;
	int		linelen;
	u_char		c;
	int		is_sdp = 0;
	int		end_offset;

	data = &pd[offset];
	dataend = data + END_OF_FRAME;
	end_offset = offset + END_OF_FRAME;

	rtsp_tree = NULL;
	if (tree) {
		ti = proto_tree_add_item(tree, proto_rtsp, offset, 
			END_OF_FRAME, NULL);
		rtsp_tree = proto_item_add_subtree(ti, ett_rtsp);
	}

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "RTSP");
	if (check_col(fd, COL_INFO)) {
		/*
		 * Put the first line from the buffer into the summary
		 * if it's an RTSP request or reply. Otherwise, just call 
		 * it a continuation.
		 */
		lineend = find_line_end(data, dataend, &eol);
		linelen = lineend - data;
		if (process_rtsp_request_or_reply(data, offset, linelen,
				rtsp_tree))
			col_add_str(fd, COL_INFO, format_text(data, linelen));
		else
			col_add_str(fd, COL_INFO, "Continuation");
	}

	if (!rtsp_tree)
		return;

	if (offset >= end_offset)
		goto bad_len;
	while (data < dataend) {
		/*
		 * Find the end of the line.
		 */
		lineend = find_line_end(data, dataend, &eol);
		linelen = lineend - data;

		/*
		 * OK, does it look like an RTSP request or
		 * response?
		 */
		if (process_rtsp_request_or_reply(data, offset, linelen,
				rtsp_tree))
			goto is_rtsp;

		/*
		 * No.  Does it look like a blank line (as would
		 * appear at the end of an RTSP request)?
		 */
		if (linelen == 1) {
			if (*data == '\n')
				goto is_rtsp;
		}
		if (linelen == 2) {
			if (strncmp(data, "\r\n", 2) == 0 ||
			    strncmp(data, "\n\r", 2) == 0)
				goto is_rtsp;
		}

		/*
		 * No.  Does it look like a MIME header?
		 */
		linep = data;
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
				goto not_rtsp;

			case ':':
				/*
				 * This ends the token; we consider
				 * this to be a MIME header.
				 */
				if (is_content_sdp(data, linelen))
					is_sdp = 1;
				goto is_rtsp;
			}
		}

	not_rtsp:
		/*
		 * We don't consider this part of an RTSP request or
		 * reply, so we don't display it.
		 */
		break;

	is_rtsp:
		/*
		 * Put this line.
		 */
		proto_tree_add_text(rtsp_tree, offset, linelen, "%s",
			format_text(data, linelen));
		offset += linelen;
		data = lineend;
	}

	if (is_sdp) {
		dissect_sdp(pd, offset, fd, tree);
		if (check_col(fd, COL_PROTOCOL))
			col_add_str(fd, COL_PROTOCOL, "RTSP/SDP");
	}
	else if (data < dataend) {
		proto_tree_add_text(rtsp_tree, offset, END_OF_FRAME,
		    "Data (%d bytes)", END_OF_FRAME);
	}
	return;

bad_len:
	proto_tree_add_text(rtsp_tree, end_offset, 0,
		"Unexpected end of packet");
}

const char *rtsp_methods[] = {
	"DESCRIBE", "ANNOUNCE", "GET_PARAMETER", "OPTIONS",
	"PAUSE", "PLAY", "RECORD", "REDIRECT", "SETUP",
	"SET_PARAMETER", "TEARDOWN"
};
const int rtsp_nmethods = sizeof(rtsp_methods) / sizeof(*rtsp_methods);

static int
process_rtsp_request_or_reply(const u_char *data, int offset, int linelen,
	proto_tree *tree)
{
	int		ii;
	const u_char	*lineend = data + linelen;

	/* Reply */
	if (linelen >= 5 && !strncasecmp("RTSP/", data, 5)) {
		if (tree) {
			/* status code */
			const u_char *status = data;
			const u_char *status_start;
			unsigned int status_i = 0;
			while (status < lineend && !isspace(*status))
				status++;
			while (status < lineend && isspace(*status))
				status++;
			status_start = status;
			while (status < lineend && isdigit(*status))
				status_i = status_i * 10 + *status++ - '0';
			proto_tree_add_item_hidden(tree, hf_rtsp_status,
				offset + (status_start - data),
				status - status_start, status_i);
		}
		return TRUE;
	}

	/* Request Methods */
	for (ii = 0; ii < rtsp_nmethods; ii++) {
		size_t len = strlen(rtsp_methods[ii]);
		if (linelen >= len && !strncasecmp(rtsp_methods[ii], data, len))
			break;
	}
	if (ii == rtsp_nmethods)
		return FALSE;

	if (tree) {
		const u_char *url;
		const u_char *url_start;
		u_char *tmp_url;

		/* method name */
		proto_tree_add_item_hidden(tree, hf_rtsp_method, offset,
			strlen(rtsp_methods[ii]), rtsp_methods[ii]);

		/* URL */
		url = data;
		while (url < lineend && !isspace(*url))
			url++;
		while (url < lineend && isspace(*url))
			url++;
		url_start = url;
		while (url < lineend && !isspace(*url))
			url++;
		tmp_url = g_malloc(url - url_start + 1);
		memcpy(tmp_url, url_start, url - url_start);
		tmp_url[url - url_start] = 0;
		proto_tree_add_item_hidden(tree, hf_rtsp_url,
			offset + (url_start - data), url - url_start, tmp_url);
		g_free(tmp_url);
	}
	return TRUE;
}

void
proto_register_rtsp(void)
{
	static gint *ett[] = {
		&ett_rtsp,
	};
	static hf_register_info hf[] = {
	{ &hf_rtsp_method,
	{ "Method", "rtsp.method", FT_STRING, BASE_NONE, NULL, 0 }},
	{ &hf_rtsp_url,
	{ "URL", "rtsp.url", FT_STRING, BASE_NONE, NULL, 0 }},
	{ &hf_rtsp_status,
	{ "Status", "rtsp.status", FT_UINT32, BASE_DEC, NULL, 0 }},
	};

        proto_rtsp = proto_register_protocol("Real Time Streaming Protocol",
		"rtsp");
	proto_register_field_array(proto_rtsp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}
