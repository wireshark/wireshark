/* req_resp_hdrs.c
 * Routines handling protocols with a request/response line, headers,
 * a blank line, and an optional body.
 *
 * $Id: req_resp_hdrs.c,v 1.3 2003/12/29 22:33:18 guy Exp $
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

#include <glib.h>
#include <epan/packet.h>
#include <epan/strutil.h>

#include "req_resp_hdrs.h"

/*
 * Optionally do reassembly of the request/response line, headers, and body.
 */
gboolean
req_resp_hdrs_do_reassembly(tvbuff_t *tvb, packet_info *pinfo,
    gboolean desegment_headers, gboolean desegment_body)
{
	gint		offset = 0;
	gint		next_offset;
	gint		next_offset_sav;
	gint		length_remaining, reported_length_remaining;
	int		linelen;
	long int	content_length;
	gboolean	content_length_found = FALSE;

	/*
	 * Do header desegmentation if we've been told to.
	 *
	 * RFC 2616 defines HTTP messages as being either of the
	 * Request or the Response type
	 * (HTTP-message = Request | Response).
	 * Request and Response are defined as:
	 *     Request = Request-Line
	 *         *(( general-header
	 *         | request-header
	 *         | entity-header ) CRLF)
	 *         CRLF
	 *         [ message-body ]
	 *     Response = Status-Line
	 *         *(( general-header
	 *         | response-header
	 *         | entity-header ) CRLF)
	 *         CRLF
	 *         [ message-body ]
	 * that's why we can always assume two consecutive line
	 * endings (we allow CR, LF, or CRLF, as some clients
	 * or servers might not use a full CRLF) to mark the end
	 * of the headers.  The worst thing that would happen
	 * otherwise would be the packet not being desegmented
	 * or being interpreted as only headers.
	 *
	 * RFC 2326 says RTSP works the same way; RFC 3261 says SIP
	 * works the same way.
	 */

	/*
	 * If header desegmentation is activated, check that all
	 * headers are in this tvbuff (search for an empty line
	 * marking end of headers) or request one more byte (we
	 * don't know how many bytes we'll need, so we just ask
	 * for one).
	 */
	if (desegment_headers && pinfo->can_desegment) {
		next_offset = offset;
		for (;;) {
			next_offset_sav = next_offset;

			length_remaining = tvb_length_remaining(tvb,
			    next_offset);
			reported_length_remaining =
			    tvb_reported_length_remaining(tvb, next_offset);

			/*
			 * Request one more byte if there're no
			 * bytes left in the reported data (if there're
			 * bytes left in the reported data, but not in
			 * the available data, requesting more bytes
			 * won't help, as those bytes weren't captured).
			 */
			if (reported_length_remaining < 1) {
				pinfo->desegment_offset = offset;
				pinfo->desegment_len = 1;
				return FALSE;
			}

			/*
			 * Request one more byte if we cannot find a
			 * header (i.e. a line end).
			 */
			linelen = tvb_find_line_end(tvb, next_offset,
			    -1, &next_offset, TRUE);
			if (linelen == -1 &&
			    length_remaining >= reported_length_remaining) {
				/*
				 * Not enough data; ask for one more
				 * byte.
				 */
				pinfo->desegment_offset = offset;
				pinfo->desegment_len = 1;
				return FALSE;
			} else if (linelen == 0) {
				/*
				 * We found the end of the headers.
				 */
				break;
			}

			/*
			 * Is this a Content-Length header?
			 * If not, it either means that we are in
			 * a different header line, or that we are
			 * at the end of the headers, or that there
			 * isn't enough data; the two latter cases
			 * have already been handled above.
			 */
			if (desegment_body) {
				/*
				 * Check if we've found Content-Length.
				 */
				if (tvb_strncaseeql(tvb, next_offset_sav,
				    "Content-Length:", 15) == 0) {
					if (sscanf(
					    tvb_get_string(tvb,
					        next_offset_sav + 15,
					        linelen - 15),
					    "%li", &content_length)
					    == 1)
						content_length_found = TRUE;
				}
			}
		}
	}

	/*
	 * The above loop ends when we reached the end of the headers, so
	 * there should be content_length byte after the 4 terminating bytes
	 * and next_offset points to after the end of the headers.
	 */
	if (desegment_body && content_length_found) {
		/* next_offset has been set because content-length was found */
		if (!tvb_bytes_exist(tvb, next_offset, content_length)) {
			length_remaining = tvb_length_remaining(tvb,
			    next_offset);
			reported_length_remaining =
			    tvb_reported_length_remaining(tvb, next_offset);
			if (length_remaining < reported_length_remaining) {
				/*
				 * It's a waste of time asking for more
				 * data, because that data wasn't captured.
				 */
				return TRUE;
			}
			if (length_remaining == -1)
				length_remaining = 0;
			pinfo->desegment_offset = offset;
			pinfo->desegment_len =
			    content_length - length_remaining;
			return FALSE;
		}
	}

	/*
	 * No further desegmentation needed.
	 */
	return TRUE;
}
