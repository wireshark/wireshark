/* packet-rtsp.c
 * Routines for RTSP packet disassembly
 *
 * Jason Lango <jal@netapp.com>
 * Liberally copied from packet-http.c, by Guy Harris <guy@netapp.com>
 *
 * $Id: packet-rtsp.c,v 1.4 1999/11/16 11:42:53 guy Exp $
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

static int is_rtsp_request_or_reply(const u_char *data, int linelen);

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

	data = &pd[offset];
	dataend = data + END_OF_FRAME;

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "RTSP");
	if (check_col(fd, COL_INFO)) {
		/*
		 * Put the first line from the buffer into the summary,
		 * if it's an RTSP request or reply.
		 * Otherwise, just call it a continuation.
		 */
		lineend = find_line_end(data, dataend, &eol);
		linelen = lineend - data;
		if (is_rtsp_request_or_reply(data, linelen))
			col_add_str(fd, COL_INFO, format_text(data, linelen));
		else
			col_add_str(fd, COL_INFO, "Continuation");
	}

	rtsp_tree = NULL;

	if (tree) {
		ti = proto_tree_add_item(tree, proto_rtsp, offset, END_OF_FRAME, NULL);
		rtsp_tree = proto_item_add_subtree(ti, ett_rtsp);
	}

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
		if (is_rtsp_request_or_reply(data, linelen))
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
		if (rtsp_tree) {
			proto_tree_add_text(rtsp_tree, offset, linelen, "%s",
			    format_text(data, linelen));
		}
		offset += linelen;
		data = lineend;
	}

	if (is_sdp) {
		dissect_sdp(pd, offset, fd, tree);
		if (check_col(fd, COL_PROTOCOL))
			col_add_str(fd, COL_PROTOCOL, "RTSP/SDP");
	}
	else if (rtsp_tree && data < dataend) {
		proto_tree_add_text(rtsp_tree, offset, END_OF_FRAME,
		    "Data (%d bytes)", END_OF_FRAME);
	}
}

const char *rtsp_methods[] = {
	"DESCRIBE", "ANNOUNCE", "GET_PARAMETER", "OPTIONS",
	"PAUSE", "PLAY", "RECORD", "REDIRECT", "SETUP",
	"SET_PARAMETER", "TEARDOWN"
};
const int rtsp_nmethods = sizeof(rtsp_methods) / sizeof(*rtsp_methods);

static int
is_rtsp_request_or_reply(const u_char *data, int linelen)
{
	int		ii;
	size_t		len;

	/* Reply */
	if (linelen >= 5 && !strncasecmp("RTSP/", data, 5))
		return TRUE;

	/* Request Methods */
	for (ii = 0; ii < rtsp_nmethods; ii++) {
		len = strlen(rtsp_methods[ii]);
		if (linelen >= len && !strncasecmp(rtsp_methods[ii], data, len))
			return TRUE;
	}

	return FALSE;
}

void
proto_register_rtsp(void)
{
/*        static hf_register_info hf[] = {
                { &variable,
                { "Name",           "rtsp.abbreviation", TYPE, VALS_POINTER }},
        };*/
	static gint *ett[] = {
		&ett_rtsp,
	};

        proto_rtsp = proto_register_protocol("Real Time Streaming Protocol", "rtsp");
 /*       proto_register_field_array(proto_rtsp, hf, array_length(hf));*/
	proto_register_subtree_array(ett, array_length(ett));
}
