/* packet-rtsp.c
 * Routines for RTSP packet disassembly (RFC 2326)
 *
 * Jason Lango <jal@netapp.com>
 * Liberally copied from packet-http.c, by Guy Harris <guy@alum.mit.edu>
 *
 * $Id: packet-rtsp.c,v 1.41 2001/09/03 10:33:06 guy Exp $
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

#include "config.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include <glib.h>
#include "packet.h"
#include "packet-rtp.h"
#include "packet-rtcp.h"
#include "conversation.h"
#include "strutil.h"

static int proto_rtsp = -1;
static gint ett_rtsp = -1;

static gint ett_rtspframe = -1;

static int hf_rtsp_method = -1;
static int hf_rtsp_url = -1;
static int hf_rtsp_status = -1;

#define TCP_PORT_RTSP			554

/*
 * Takes an array of bytes, assumed to contain a null-terminated
 * string, as an argument, and returns the length of the string -
 * i.e., the size of the array, minus 1 for the null terminator.
 */
#define STRLEN_CONST(str)	(sizeof (str) - 1)

#define RTSP_FRAMEHDR	('$')

static int
dissect_rtspinterleaved(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree)
{
	proto_tree	*rtspframe_tree;
	proto_item	*ti;
	int		orig_offset;
	guint8		rf_start;	/* always RTSP_FRAMEHDR */
	guint8		rf_chan;        /* interleaved channel id */
	guint16		rf_len;         /* packet length */
	gint		framelen;
	tvbuff_t	*next_tvb;

	orig_offset = offset;
	rf_start = tvb_get_guint8(tvb, offset);
	rf_chan = tvb_get_guint8(tvb, offset+1);
	rf_len = tvb_get_ntohs(tvb, offset+2);

	if (check_col(pinfo->fd, COL_INFO))
		col_add_fstr(pinfo->fd, COL_INFO, 
			"Interleaved channel 0x%02x, %u bytes",
			rf_chan, rf_len);

	if (tree == NULL) {
		/*
		 * We're not building a full protocol tree; all we care
		 * about is setting the column info.
		 */
		return -1;
	}

	ti = proto_tree_add_protocol_format(tree, proto_rtsp, tvb, offset, 4,
		"RTSP Interleaved Frame, Channel: 0x%02x, %u bytes",
		rf_chan, rf_len);
	rtspframe_tree = proto_item_add_subtree(ti, ett_rtspframe);

	proto_tree_add_text(rtspframe_tree, tvb, offset, 1,
		"Magic: 0x%02x",
		rf_start);
	offset += 1;

	proto_tree_add_text(rtspframe_tree, tvb, offset, 1,
		"Channel: 0x%02x",
		rf_chan);
	offset += 1;

	proto_tree_add_text(rtspframe_tree, tvb, offset, 2,
		"Length: %u bytes",
		rf_len);
	offset += 2;

	/*
	 * We set the actual length of the tvbuff for the interleaved
	 * stuff to the minimum of what's left in the tvbuff and the
	 * length in the header.
	 *
	 * XXX - what if there's nothing left in the tvbuff?
	 * We'd want a BoundsError exception to be thrown, so
	 * that a Short Frame would be reported.
	 */
	framelen = tvb_length_remaining(tvb, offset);
	if (framelen > rf_len)
		framelen = rf_len;
	next_tvb = tvb_new_subset(tvb, offset, framelen, rf_len);
	dissect_data(next_tvb, 0, pinfo, tree);
	offset += rf_len;

	return offset - orig_offset;
}

static void process_rtsp_request(tvbuff_t *tvb, int offset, const u_char *data,
	size_t linelen, proto_tree *tree);

static void process_rtsp_reply(tvbuff_t *tvb, int offset, const u_char *data,
	size_t linelen, proto_tree *tree);

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

static dissector_handle_t sdp_handle;

static rtsp_type_t
is_rtsp_request_or_reply(const u_char *line, size_t linelen)
{
	unsigned	ii;

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

static const char rtsp_content_type[] = "Content-Type:";

static int
is_content_sdp(const u_char *line, size_t linelen)
{
	static const char type[] = "application/sdp";
	size_t		typelen = STRLEN_CONST(type);

	line += STRLEN_CONST(rtsp_content_type);
	linelen -= STRLEN_CONST(rtsp_content_type);
	while (linelen > 0 && (*line == ' ' || *line == '\t')) {
		line++;
		linelen--;
	}

	if (linelen < typelen || strncasecmp(type, line, typelen))
		return FALSE;

	line += typelen;
	linelen -= typelen;
	if (linelen > 0 && !isspace(*line))
		return FALSE;

	return TRUE;
}

static const char rtsp_transport[] = "Transport:";
static const char rtsp_sps[] = "server_port=";
static const char rtsp_cps[] = "client_port=";
static const char rtsp_rtp[] = "rtp/avp";

static void
rtsp_create_conversation(packet_info *pinfo, const u_char *line_begin,
	size_t line_len)
{
	conversation_t	*conv;
	u_char		buf[256];
	u_char		*tmp;
	int		c_data_port, c_mon_port;
	int		s_data_port, s_mon_port;
	address		null_addr;

	if (line_len > sizeof(buf) - 1) {
		/*
		 * Don't overflow the buffer.
		 */
		line_len = sizeof(buf) - 1;
	}
	memcpy(buf, line_begin, line_len);
	buf[line_len] = '\0';

	tmp = buf + STRLEN_CONST(rtsp_transport);
	while (*tmp && isspace(*tmp))
		tmp++;
	if (strncasecmp(tmp, rtsp_rtp, strlen(rtsp_rtp)) != 0)
		return;	/* we don't know this transport */

	c_data_port = c_mon_port = 0;
	s_data_port = s_mon_port = 0;
	if ((tmp = strstr(buf, rtsp_sps))) {
		tmp += strlen(rtsp_sps);
		if (sscanf(tmp, "%u-%u", &s_data_port, &s_mon_port) < 1)
			g_warning("rtsp: failed to parse server_port");
	}
	if ((tmp = strstr(buf, rtsp_cps))) {
		tmp += strlen(rtsp_cps);
		if (sscanf(tmp, "%u-%u", &c_data_port, &c_mon_port) < 1)
			g_warning("rtsp: failed to parse client_port");
	}
	if (!c_data_port)
		return;

	/*
	 * We only want to match on the destination address, not the
	 * source address, because the server might send back a packet
	 * from an address other than the address to which its client
	 * sent the packet, so we construct a conversation with no
	 * second address.
	 */
	SET_ADDRESS(&null_addr, pinfo->src.type, 0, NULL);

	conv = conversation_new(&pinfo->dst, &null_addr, PT_UDP, c_data_port,
		s_data_port, NO_ADDR2 | (!s_data_port ? NO_PORT2 : 0));
	conversation_set_dissector(conv, dissect_rtp);

	if (!c_mon_port)
		return;

	conv = conversation_new(&pinfo->dst, &null_addr, PT_UDP, c_mon_port,
		s_mon_port, NO_ADDR2 | (!s_mon_port ? NO_PORT2 : 0));
	conversation_set_dissector(conv, dissect_rtcp);
}

static const char rtsp_content_length[] = "Content-Length:";

static int
rtsp_get_content_length(const u_char *line_begin, size_t line_len)
{
	u_char		buf[256];
	u_char		*tmp;
	long		content_length;
	char		*p;
	u_char		*up;

	if (line_len > sizeof(buf) - 1) {
		/*
		 * Don't overflow the buffer.
		 */
		line_len = sizeof(buf) - 1;
	}
	memcpy(buf, line_begin, line_len);
	buf[line_len] = '\0';

	tmp = buf + STRLEN_CONST(rtsp_content_length);
	while (*tmp && isspace(*tmp))
		tmp++;
	content_length = strtol(tmp, &p, 10);
	up = p;
	if (up == tmp || (*up != '\0' && !isspace(*up)))
		return -1;	/* not a valid number */
	return content_length;
}

static int
dissect_rtspmessage(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree)
{
	proto_tree	*rtsp_tree;
	proto_item	*ti = NULL;
	const u_char	*line;
	gint		next_offset;
	const u_char	*linep, *lineend;
	int		orig_offset;
	size_t		linelen;
	u_char		c;
	gboolean	is_mime_header;
	int		is_sdp = FALSE;
	int		datalen;
	int		content_length;
	int		reported_datalen;

	orig_offset = offset;
	rtsp_tree = NULL;
	if (tree) {
		ti = proto_tree_add_item(tree, proto_rtsp, tvb, offset,
			tvb_length_remaining(tvb, offset), FALSE);
		rtsp_tree = proto_item_add_subtree(ti, ett_rtsp);
	}

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
			col_set_str(pinfo->fd, COL_INFO, "Continuation");
			break;
		}
	}

	/*
	 * We haven't yet seen a Content-Length header.
	 */
	content_length = -1;

	/*
	 * Process the packet data, a line at a time.
	 */
	while (tvb_offset_exists(tvb, offset)) {
		/*
		 * We haven't yet concluded that this is a MIME header.
		 */
		is_mime_header = FALSE;

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
				is_mime_header = TRUE;
				goto is_rtsp;

			case ' ':
			case '\t':
				/*
				 * LWS (RFC-2616, 4.2); continue the previous
				 * header.
				 */
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
		if (is_mime_header) {
			/*
			 * Process some MIME headers specially.
			 */
#define MIME_HDR_MATCHES(header) \
	(linelen > STRLEN_CONST(header) && \
	 strncasecmp(line, (header), STRLEN_CONST(header)) == 0)

			if (MIME_HDR_MATCHES(rtsp_transport)) {
				/*
				 * Based on the port numbers specified
				 * in the Transport: header, set up
				 * a conversation that will be dissected
				 * with the appropriate dissector.
				 */
				rtsp_create_conversation(pinfo, line, linelen);
			} else if (MIME_HDR_MATCHES(rtsp_content_type)) {
				/*
				 * If the Content-Type: header says this
				 * is SDP, dissect the payload as SDP.
				 */
				if (is_content_sdp(line, linelen))
					is_sdp = TRUE;
			} else if (MIME_HDR_MATCHES(rtsp_content_length)) {
				/*
				 * Only the amount specified by the
				 * Content-Length: header should be treated
				 * as payload.
				 */
				content_length = rtsp_get_content_length(line,
				    linelen);
			}
		}
		offset = next_offset;
	}

	/*
	 * If a content length was supplied, the amount of data to be
	 * processed as RTSP payload is the minimum of the content
	 * length and the amount of data remaining in the frame.
	 *
	 * If no content length was supplied, the amount of data to be
	 * processed is the amount of data remaining in the frame.
	 */
	datalen = tvb_length_remaining(tvb, offset);
	if (content_length != -1) {
		if (datalen > content_length)
			datalen = content_length;

		/*
		 * XXX - for now, if the content length is greater
		 * than the amount of data left in this frame (not
		 * the amount of *captured* data left in the frame
		 * minus the current offset, but the amount of *actual*
		 * data that was reported to be in the frame minus
		 * the current offset), limit it to the amount
		 * of data left in this frame.
		 *
		 * If we ever handle data that crosses frame
		 * boundaries, we'll need to remember the actual
		 * content length.
		 */
		reported_datalen = tvb_reported_length_remaining(tvb, offset);
		if (content_length > reported_datalen)
			content_length = reported_datalen;
	}

	if (datalen > 0) {
		/*
		 * There's stuff left over; process it.
		 */
		if (is_sdp) {
			tvbuff_t *new_tvb;

			/*
			 * Fix up the top-level item so that it doesn't
			 * include the SDP stuff.
			 */
			if (ti != NULL)
				proto_item_set_len(ti, offset);

			/*
			 * Now create a tvbuff for the SDP stuff and
			 * dissect it.
			 *
			 * The amount of data to be processed that's
			 * available in the tvbuff is "datalen", which
			 * is the minimum of the amount of data left in
			 * the tvbuff and any specified content length.
			 *
			 * The amount of data to be processed that's in
			 * this frame, regardless of whether it was
			 * captured or not, is "content_length",
			 * which, if no content length was specified,
			 * is -1, i.e. "to the end of the frame.
			 */
			new_tvb = tvb_new_subset(tvb, offset, datalen,
			    content_length);
			call_dissector(sdp_handle, new_tvb, pinfo, tree);
		} else {
			if (tvb_get_guint8(tvb, offset) == RTSP_FRAMEHDR) {
				/*
				 * This is interleaved stuff; don't
				 * treat it as raw data - set "datalen"
				 * to 0, so we won't skip the offset
				 * past it, which will cause our
				 * caller to process that stuff itself.
				 */
				datalen = 0;
			} else {
				proto_tree_add_text(rtsp_tree, tvb, offset,
				    datalen, "Data (%d bytes)", datalen);
			}
		}

		/*
		 * We've processed "datalen" bytes worth of data
		 * (which may be no data at all); advance the
		 * offset past whatever data we've processed, so they
		 * don't process it.
		 */
		offset += datalen;
	}
	return offset - orig_offset;
}

static void
process_rtsp_request(tvbuff_t *tvb, int offset, const u_char *data,
	size_t linelen, proto_tree *tree)
{
	const u_char	*lineend = data + linelen;
	unsigned	ii;
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
	size_t linelen, proto_tree *tree)
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

static void
dissect_rtsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int		offset = 0;
	int		len;

	if (check_col(pinfo->fd, COL_PROTOCOL))
		col_set_str(pinfo->fd, COL_PROTOCOL, "RTSP");
	if (check_col(pinfo->fd, COL_INFO))
		col_clear(pinfo->fd, COL_INFO);

	while (tvb_offset_exists(tvb, offset)) {
		len = (tvb_get_guint8(tvb, offset) == RTSP_FRAMEHDR)
			? dissect_rtspinterleaved(tvb, offset, pinfo, tree)
			: dissect_rtspmessage(tvb, offset, pinfo, tree);
		if (len == -1)
			break;
		offset += len;

		/*
		 * OK, we've set the Protocol and Info columns for the
		 * first RTSP message; make the columns non-writable,
		 * so that we don't change it for subsequent RTSP messages.
		 */
		col_set_writable(pinfo->fd, FALSE);
	}
}

void
proto_register_rtsp(void)
{
	static gint *ett[] = {
		&ett_rtspframe,
		&ett_rtsp,
	};
	static hf_register_info hf[] = {
	{ &hf_rtsp_method,
	{ "Method", "rtsp.method", FT_STRING, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_rtsp_url,
	{ "URL", "rtsp.url", FT_STRING, BASE_NONE, NULL, 0, "", HFILL }},
	{ &hf_rtsp_status,
	{ "Status", "rtsp.status", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
	};

        proto_rtsp = proto_register_protocol("Real Time Streaming Protocol",
		"RTSP", "rtsp");
	proto_register_field_array(proto_rtsp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_rtsp(void)
{
	dissector_add("tcp.port", TCP_PORT_RTSP, dissect_rtsp, proto_rtsp);

	/*
	 * Get a handle for the SDP dissector.
	 */
	sdp_handle = find_dissector("sdp");
}
