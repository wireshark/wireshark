/* packet-rtsp.c
 * Routines for RTSP packet disassembly (RFC 2326)
 *
 * Jason Lango <jal@netapp.com>
 * Liberally copied from packet-http.c, by Guy Harris <guy@alum.mit.edu>
 *
 * $Id: packet-rtsp.c,v 1.24 2000/11/12 21:23:53 guy Exp $
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
#include "packet-sdp.h"
#include "packet-rtp.h"
#include "packet-rtcp.h"
#include "conversation.h"
#include "strutil.h"

static int proto_rtsp = -1;
static gint ett_rtsp = -1;

static int hf_rtsp_method = -1;
static int hf_rtsp_url = -1;
static int hf_rtsp_status = -1;

#define TCP_PORT_RTSP			554

static void process_rtsp_request(tvbuff_t *tvb, int offset, const u_char *data,
	int linelen, proto_tree *tree);

static void process_rtsp_reply(tvbuff_t *tvb, int offset, const u_char *data,
	int linelen, proto_tree *tree);

typedef enum {
	RTSP_REQUEST,
	RTSP_REPLY,
	NOT_RTSP
} rtsp_type_t;

static const char *rtsp_methods[] = {
	"DESCRIBE", "ANNOUNCE", "GET_PARAMETER", "OPTIONS",
	"PAUSE", "PLAY", "RECORD", "REDIRECT", "SETUP",
	"SET_PARAMETER", "TEARDOWN"
};

#define RTSP_NMETHODS	(sizeof rtsp_methods / sizeof rtsp_methods[0])

static rtsp_type_t
is_rtsp_request_or_reply(const u_char *line, int linelen)
{
	int		ii;

	/* Is this an RTSP reply? */
	if (linelen >= 5 && strncasecmp("RTSP/", line, 5) == 0) {
		/*
		 * Yes.
		 */
		return RTSP_REPLY;
	}

	/*
	 * Is this an RTSP request?
	 * Check whether the line begins with one of the RTSP request
	 * methods.
	 */
	for (ii = 0; ii < RTSP_NMETHODS; ii++) {
		size_t len = strlen(rtsp_methods[ii]);
		if (linelen >= len &&
		    strncasecmp(rtsp_methods[ii], line, len) == 0)
			return RTSP_REQUEST;
	}
	return NOT_RTSP;
}

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

static const char rtsp_transport[] = "Transport:";
static const char rtsp_sps[] = "server_port=";
static const char rtsp_cps[] = "client_port=";
static const char rtsp_rtp[] = "rtp/avp";

static void
rtsp_create_conversation(const u_char *trans_begin, const u_char *trans_end)
{
	conversation_t	*conv;
	u_char		tbuf[256];
	u_char		*tmp;
	int		c_data_port, c_mon_port;
	int		s_data_port, s_mon_port;

	strncpy(tbuf, trans_begin, trans_end - trans_begin);
	tbuf[sizeof(tbuf)-1] = 0;

	tmp = tbuf + strlen(rtsp_transport);
	while (*tmp && isspace(*tmp))
		tmp++;
	if (strncasecmp(tmp, rtsp_rtp, strlen(rtsp_rtp)) != 0)
		return;

	c_data_port = c_mon_port = 0;
	s_data_port = s_mon_port = 0;
	if ((tmp = strstr(tbuf, rtsp_sps))) {
		tmp += strlen(rtsp_sps);
		if (sscanf(tmp, "%u-%u", &s_data_port, &s_mon_port) < 1)
			g_warning("rtsp: failed to parse server_port");
	}
	if ((tmp = strstr(tbuf, rtsp_cps))) {
		tmp += strlen(rtsp_cps);
		if (sscanf(tmp, "%u-%u", &c_data_port, &c_mon_port) < 1)
			g_warning("rtsp: failed to parse client_port");
	}
	if (!c_data_port || !s_data_port)
		return;

	conv = conversation_new(&pi.src, &pi.dst, PT_UDP, s_data_port,
		c_data_port, 0, 0);
	conversation_set_dissector(conv, dissect_rtp);

	if (!c_mon_port || !s_mon_port)
		return;

	conv = conversation_new(&pi.src, &pi.dst, PT_UDP, s_mon_port,
		c_mon_port, 0, 0);
	conversation_set_dissector(conv, dissect_rtcp);
}

static void
dissect_rtsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*rtsp_tree;
	proto_item	*ti = NULL;
	gint		offset = 0;
	const u_char	*line;
	gint		next_offset;
	const u_char	*linep, *lineend;
	int		linelen;
	u_char		c;
	int		is_sdp = FALSE;
	int		datalen;

	CHECK_DISPLAY_AS_DATA(proto_rtsp, tvb, pinfo, tree);

	pinfo->current_proto = "RTSP";

	rtsp_tree = NULL;
	if (tree) {
		ti = proto_tree_add_item(tree, proto_rtsp, tvb, offset,
			tvb_length_remaining(tvb, offset), FALSE);
		rtsp_tree = proto_item_add_subtree(ti, ett_rtsp);
	}

	if (check_col(pinfo->fd, COL_PROTOCOL))
		col_add_str(pinfo->fd, COL_PROTOCOL, "RTSP");
	if (check_col(pinfo->fd, COL_INFO)) {
		/*
		 * Put the first line from the buffer into the summary
		 * if it's an RTSP request or reply (but leave out the
		 * line terminator).
		 * Otherwise, just call it a continuation.
		 */
		linelen = tvb_find_line_end(tvb, offset, -1, &next_offset);
		line = tvb_get_ptr(tvb, offset, linelen);
		switch (is_rtsp_request_or_reply(line, linelen)) {

		case RTSP_REQUEST:
		case RTSP_REPLY:
			col_add_str(pinfo->fd, COL_INFO,
			    format_text(line, linelen));
			break;

		default:
			col_add_str(pinfo->fd, COL_INFO, "Continuation");
			break;
		}
	}

	/*
	 * Process the packet data, a line at a time.
	 */
	while (tvb_length_remaining(tvb, offset)) {
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
		 * OK, does it look like an RTSP request or
		 * response?
		 */
		switch (is_rtsp_request_or_reply(line, linelen)) {

		case RTSP_REQUEST:
			if (rtsp_tree != NULL)
				process_rtsp_request(tvb, offset, line, linelen,
				    rtsp_tree);
			goto is_rtsp;

		case RTSP_REPLY:
			if (rtsp_tree != NULL)
				process_rtsp_reply(tvb, offset, line, linelen,
				    rtsp_tree);
			goto is_rtsp;

		case NOT_RTSP:
			break;
		}

		/*
		 * No.  Does it look like a blank line (as would
		 * appear at the end of an RTSP request)?
		 */
		if (linelen == 0)
			goto is_rtsp;	/* Yes. */

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
				goto not_rtsp;

			case ':':
				/*
				 * This ends the token; we consider
				 * this to be a MIME header.
				 */
				if (is_content_sdp(line, linelen))
					is_sdp = TRUE;
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
		if (rtsp_tree) {
			proto_tree_add_text(rtsp_tree, tvb, offset,
			    next_offset - offset, "%s",
			    tvb_format_text(tvb, offset, next_offset - offset));
		}
		if (linelen > strlen(rtsp_transport) &&
			strncasecmp(line, rtsp_transport,
				strlen(rtsp_transport)) == 0)
			rtsp_create_conversation(line, line + linelen);
		offset = next_offset;
	}

	datalen = tvb_length_remaining(tvb, offset);
	if (is_sdp) {
		if (datalen > 0) {
			tvbuff_t *new_tvb;

			/*
			 * Fix up the top-level item so that it doesn't
			 * include the SDP stuff.
			 */
			if (ti != NULL)
				proto_item_set_len(ti, offset);

			/*
			 * Now creat a tvbuff for the SDP stuff and
			 * dissect it.
			 */
			new_tvb = tvb_new_subset(tvb, offset, -1, -1);
			dissect_sdp(new_tvb, pinfo, tree);
		}
	} else {
		if (datalen > 0) {
			proto_tree_add_text(rtsp_tree, tvb, offset, datalen,
			    "Data (%d bytes)", datalen);
		}
	}
}

static void
process_rtsp_request(tvbuff_t *tvb, int offset, const u_char *data,
	int linelen, proto_tree *tree)
{
	const u_char	*lineend = data + linelen;
	int		ii;
	const u_char	*url;
	const u_char	*url_start;
	u_char		*tmp_url;

	/* Request Methods */
	for (ii = 0; ii < RTSP_NMETHODS; ii++) {
		size_t len = strlen(rtsp_methods[ii]);
		if (linelen >= len && !strncasecmp(rtsp_methods[ii], data, len))
			break;
	}
	if (ii == RTSP_NMETHODS) {
		/*
		 * We got here because "is_rtsp_request_or_reply()" returned
		 * RTSP_REQUEST, so we know one of the request methods
		 * matched, so we "can't get here".
		 */
		g_assert_not_reached();
	}

	/* Method name */
	proto_tree_add_string_hidden(tree, hf_rtsp_method, tvb, offset,
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
	proto_tree_add_string_hidden(tree, hf_rtsp_url, tvb,
		offset + (url_start - data), url - url_start, tmp_url);
	g_free(tmp_url);
}

static void
process_rtsp_reply(tvbuff_t *tvb, int offset, const u_char *data,
	int linelen, proto_tree *tree)
{
	const u_char	*lineend = data + linelen;
	const u_char	*status = data;
	const u_char	*status_start;
	unsigned int	status_i;

	/* status code */
	while (status < lineend && !isspace(*status))
		status++;
	while (status < lineend && isspace(*status))
		status++;
	status_start = status;
	status_i = 0;
	while (status < lineend && isdigit(*status))
		status_i = status_i * 10 + *status++ - '0';
	proto_tree_add_uint_hidden(tree, hf_rtsp_status, tvb,
		offset + (status_start - data),
		status - status_start, status_i);
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

void
proto_reg_handoff_rtsp(void)
{
	dissector_add("tcp.port", TCP_PORT_RTSP, dissect_rtsp);
}
