/* req_resp_hdrs.c
 * Routines handling protocols with a request/response line, headers,
 * a blank line, and an optional body.
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

#include <glib.h>
#include <epan/packet.h>
#include <epan/strutil.h>
#include <string.h>

#include <epan/req_resp_hdrs.h>

/*
 * Optionally do reassembly of the request/response line, headers, and body.
 */
gboolean
req_resp_hdrs_do_reassembly(tvbuff_t *tvb, int offset, packet_info *pinfo,
    gboolean desegment_headers, gboolean desegment_body)
{
	gint		next_offset;
	gint		next_offset_sav;
	gint		length_remaining, reported_length_remaining;
	int		linelen;
	gchar		*header_val;
	long int	content_length;
	gboolean	content_length_found = FALSE;
	gboolean	content_type_found = FALSE;
	gboolean	chunked_encoding = FALSE;

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
				pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
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
				pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
				return FALSE;
			} else if (linelen == 0) {
				/*
				 * We found the end of the headers.
				 */
				break;
			}

			/*
			 * Is this a Content-Length or Transfer-Encoding
			 * header?  If not, it either means that we are in
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
					header_val = tvb_get_string(tvb,
					    next_offset_sav + 15,
					    linelen - 15);
					if (sscanf(header_val,
					    "%li", &content_length)
					    == 1)
						content_length_found = TRUE;
					g_free(header_val);
				} else if (tvb_strncaseeql(tvb, next_offset_sav,
				    "Content-Type:", 13) == 0) {
					content_type_found = TRUE;
				} else if (tvb_strncaseeql(tvb,
					    next_offset_sav,
					    "Transfer-Encoding:", 18) == 0) {
					/*
					 * Find out if this Transfer-Encoding is
					 * chunked.  It should be, since there
					 * really aren't any other types, but
					 * RFC 2616 allows for them.
					 */
					gchar *p;
					gint len;

					header_val = tvb_get_string(tvb,
					    next_offset_sav + 18, linelen - 18);
					p = header_val;
					len = strlen(header_val);
					/* Skip white space */
					while (p < header_val + len &&
					    (*p == ' ' || *p == '\t'))
						p++;
					if (p <= header_val + len) {
						if (strncasecmp(p, "chunked", 7)
						    == 0) {
							/*
							 * Don't bother looking
							 * for extensions;
							 * since we don't
							 * understand them,
							 * they should be
							 * ignored.
							 */
							chunked_encoding = TRUE;
						}
					}
					g_free(header_val);
				}
			}
		}
	}

	/*
	 * The above loop ends when we reached the end of the headers, so
	 * there should be content_length bytes after the 4 terminating bytes
	 * and next_offset points to after the end of the headers.
	 */
	if (desegment_body) {
		if (content_length_found) {
			/* next_offset has been set to the end of the headers */
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
		} else if (chunked_encoding) {
			/*
			 * This data is chunked, so we need to keep pulling
			 * data until we reach the end of the stream, or a
			 * zero sized chunk.
			 *
			 * XXX
			 * This doesn't bother with trailing headers; I don't
			 * think they are really used, and we'd have to use
			 * is_http_request_or_reply() to determine if it was
			 * a trailing header, or the start of a new response.
			 */
			gboolean done_chunking = FALSE;

			while (!done_chunking) {
				gint chunk_size = 0;
				gint chunk_offset = 0;
				gchar *chunk_string = NULL;
				gchar *c = NULL;

				length_remaining = tvb_length_remaining(tvb,
				    next_offset);
				reported_length_remaining =
				    tvb_reported_length_remaining(tvb,
				    next_offset);

				if (reported_length_remaining < 1) {
					pinfo->desegment_offset = offset;
					pinfo->desegment_len = 1;
					return FALSE;
				}

				linelen = tvb_find_line_end(tvb, next_offset,
						-1, &chunk_offset, TRUE);

				if (linelen == -1 &&
				    length_remaining >=
				    reported_length_remaining) {
					 pinfo->desegment_offset = offset;
					 pinfo->desegment_len = 2;
					 return FALSE;
				}
				
				/* We have a line with the chunk size in it.*/
				chunk_string = tvb_get_string(tvb, next_offset,
				    linelen);
				c = chunk_string;

				/*
				 * We don't care about the extensions.
				 */
				if ((c = strchr(c, ';'))) {
					*c = '\0';
				}

				if ((sscanf(chunk_string, "%x",
				    &chunk_size) < 0) || chunk_size < 0) {
					/* We couldn't get the chunk size,
					 * so stop trying.
					 */
					g_free(chunk_string);
					return TRUE;
				}
				g_free(chunk_string);

				if (chunk_size == 0) {
					/*
					 * This is the last chunk.  Let's pull in the
					 * trailing CRLF.
					 */
					linelen = tvb_find_line_end(tvb,
					    chunk_offset, -1, &chunk_offset, TRUE);
						
					if (linelen == -1 &&
					    length_remaining >=
					    reported_length_remaining) {
						pinfo->desegment_offset = offset;
						pinfo->desegment_len = 1;
						return FALSE;
					}

					pinfo->desegment_offset = chunk_offset;
					pinfo->desegment_len = 0;
					done_chunking = TRUE;
				} else {
					/* 
					 * Skip to the next chunk if we
					 * already have it 
					 */
					if (reported_length_remaining >
					        chunk_size) {
						
						next_offset = chunk_offset 
						    + chunk_size + 2;
					} else {
						/* 
						 * Fetch this chunk, plus the
						 * trailing CRLF.
						 */ 
						pinfo->desegment_offset = offset;
						pinfo->desegment_len =
						    chunk_size + 1 -
						    reported_length_remaining;
						return FALSE;
					}
				}

			}
		} else if (content_type_found && pinfo->can_desegment) {
			/* We found a content-type but no content-length.
			 * This is probably a HTTP header for a session with
			 * only one HTTP PDU and where the content spans
			 * until the end of the tcp session.
			 * Set up tcp reassembly until the end of this session.
			 */
			length_remaining = tvb_length_remaining(tvb, next_offset);
			reported_length_remaining = tvb_reported_length_remaining(tvb, next_offset);
			if (length_remaining < reported_length_remaining) {
				/*
				 * It's a waste of time asking for more
				 * data, because that data wasn't captured.
				 */
				return TRUE;
			}

			pinfo->desegment_offset = offset;
			pinfo->desegment_len = DESEGMENT_UNTIL_FIN;

			return FALSE;
		}

	}

	/*
	 * No further desegmentation needed.
	 */
	return TRUE;
}
