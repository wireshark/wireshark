/* packet-http.c
 * Routines for HTTP packet disassembly
 *
 * Guy Harris <guy@netapp.com>
 *
 * $Id: packet-http.c,v 1.8 1999/09/12 18:46:57 guy Exp $
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

static int proto_http = -1;

static int is_http_request_or_reply(const u_char *data, int linelen);

void dissect_http(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	proto_tree	*http_tree;
	proto_item	*ti;
	const u_char	*data, *dataend;
	const u_char	*linep, *lineend, *eol;
	int		linelen;
	u_char		c;

	data = &pd[offset];
	dataend = data + END_OF_FRAME;

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "HTTP");
	if (check_col(fd, COL_INFO)) {
		/*
		 * Put the first line from the buffer into the summary,
		 * if it's an HTTP request or reply.
		 * Otherwise, just call it a continuation.
		 */
		lineend = find_line_end(data, dataend, &eol);
		linelen = lineend - data;
		if (is_http_request_or_reply(data, linelen))
			col_add_str(fd, COL_INFO, format_text(data, linelen));
		else
			col_add_str(fd, COL_INFO, "Continuation");
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_http, offset, END_OF_FRAME, NULL);
		http_tree = proto_item_add_subtree(ti, ETT_HTTP);

		while (data < dataend) {
			/*
			 * Find the end of the line.
			 */
			lineend = find_line_end(data, dataend, &eol);
			linelen = lineend - data;

			/*
			 * OK, does it look like an HTTP request or
			 * response?
			 */
			if (is_http_request_or_reply(data, linelen))
				goto is_http;

			/*
			 * No.  Does it look like a blank line (as would
			 * appear at the end of an HTTP request)?
			 */
			if (linelen == 1) {
				if (*data == '\n')
					goto is_http;
			}
			if (linelen == 2) {
				if (strncmp(data, "\r\n", 2) == 0 ||
				    strncmp(data, "\n\r", 2) == 0)
					goto is_http;
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
			proto_tree_add_text(http_tree, offset, linelen, "%s",
			    format_text(data, linelen));
			offset += linelen;
			data = lineend;
		}

		if (data < dataend)
			dissect_data(&pd[offset], offset, fd, http_tree);
	}
}

/*
 * XXX - this won't handle HTTP 0.9 replies, but they're all data
 * anyway.
 */
static int
is_http_request_or_reply(const u_char *data, int linelen)
{
	if (linelen >= 3) {
		if (strncasecmp(data, "GET", 3) == 0 ||
		    strncasecmp(data, "PUT", 3) == 0)
			return TRUE;
	}
	if (linelen >= 4) {
		if (strncasecmp(data, "HEAD", 4) == 0 ||
		    strncasecmp(data, "POST", 4) == 0)
			return TRUE;
	}
	if (linelen >= 5) {
		if (strncasecmp(data, "TRACE", 5) == 0)
			return TRUE;
		if (strncasecmp(data, "HTTP/", 5) == 0)
			return TRUE;	/* response */
	}
	if (linelen >= 6) {
		if (strncasecmp(data, "DELETE", 6) == 0)
			return TRUE;
	}
	if (linelen >= 7) {
		if (strncasecmp(data, "OPTIONS", 7) == 0)
			return TRUE;
	}
	return FALSE;
}

void
proto_register_http(void)
{
/*        static hf_register_info hf[] = {
                { &variable,
                { "Name",           "http.abbreviation", TYPE, VALS_POINTER }},
        };*/

        proto_http = proto_register_protocol("Hypertext Transfer Protocol", "http");
 /*       proto_register_field_array(proto_http, hf, array_length(hf));*/
}
