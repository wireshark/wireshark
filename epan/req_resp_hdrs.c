/* req_resp_hdrs.c
 * Routines handling protocols with a request/response line, headers,
 * a blank line, and an optional body.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>
#include <stdio.h>
#include <string.h>

#include <epan/packet.h>
#include <epan/strutil.h>
#include <wsutil/strtoi.h>

#include <epan/req_resp_hdrs.h>

/*
 * Optionally do reassembly of the request/response line, headers, and body.
 */
bool
req_resp_hdrs_do_reassembly(tvbuff_t *tvb, const int offset, packet_info *pinfo,
    const bool desegment_headers, const bool desegment_body,
    bool desegment_until_fin, int *last_chunk_offset,
	dissector_table_t streaming_subdissector_table, dissector_handle_t *streaming_chunk_handle)
{
	int		next_offset = offset;
	int		next_offset_sav;
	int		length_remaining, reported_length_remaining;
	int		linelen;
	char		*header_val;
	int		content_length;
	bool	content_length_found = false;
	bool	content_type_found = false;
	bool	chunked_encoding = false;
	char		*line;
	char		*content_type = NULL;
	dissector_handle_t streaming_handle = NULL;
	bool streaming_chunk_mode = false;

	DISSECTOR_ASSERT_HINT((streaming_subdissector_table && streaming_chunk_handle)
		|| (streaming_subdissector_table == NULL && streaming_chunk_handle == NULL),
		"The streaming_subdissector_table and streaming_chunk_handle arguments must "
		"be both given or both NULL.");

	/* Check whether the first line is the beginning of a chunk.
	 * If it is the beginning of a chunk, we assume we are working
	 * in streaming chunk mode. The headers of HTTP request or response
	 * and at least one chunk should have been dissected in the previous
	 * packets and now we are processing subsequent chunks.
	 */
	if (desegment_body && streaming_subdissector_table
		&& starts_with_chunk_size(tvb, offset, pinfo)) {
		streaming_chunk_mode = true;
	}

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
	 *
	 * If tvb starts with chunk size, then we just ignore headers parsing.
	 */
	if (!streaming_chunk_mode
		&& desegment_headers && pinfo->can_desegment) {
		for (;;) {
			next_offset_sav = next_offset;

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
				return false;
			}

			length_remaining = tvb_captured_length_remaining(tvb,
			    next_offset);

			/*
			 * Request one more byte if we cannot find a
			 * header (i.e. a line end).
			 */
			linelen = tvb_find_line_end(tvb, next_offset,
			    length_remaining, &next_offset, true);
			if (linelen == -1 &&
			    length_remaining >= reported_length_remaining) {
				/*
				 * Not enough data; ask for one more
				 * byte.
				 */
				pinfo->desegment_offset = offset;
				pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
				return false;
			}

                        if (linelen == 0) {
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
				/* Optimization to avoid fetching the whole (potentially very long)
				 * line and doing expensive string comparisons if the first
				 * character doesn't match. Shaves about 20% off the load time of
				 * one of my sample files that's HTTP-alike. */
				unsigned char first_byte = tvb_get_guint8(tvb, next_offset_sav);
				if (! (first_byte == 'c' || first_byte == 'C' ||
				       first_byte == 't' || first_byte == 'T')) {
					continue;
				}

				/*
				 * Check if we've found Content-Length.
				 */
				line = tvb_get_string_enc(pinfo->pool, tvb, next_offset_sav, linelen, ENC_UTF_8|ENC_NA);
				if (g_ascii_strncasecmp(line, "Content-Length:", 15) == 0) {
					/* SSTP sets 2^64 as length, but does not really have such a
					 * large payload. Since the current tvb APIs are limited to
					 * 2^31-1 bytes, ignore large values we cannot handle. */
					header_val = g_strstrip(line + 15);
					if (ws_strtoi32(header_val, NULL, &content_length) && content_length >= 0)
						content_length_found = true;
				} else if (g_ascii_strncasecmp(line, "Content-Type:", 13) == 0) {
					content_type_found = true;
					content_type = line+13;
					while (*content_type == ' ') {
						content_type++;
					}
					g_strchomp(content_type);
					if (streaming_subdissector_table) {
						streaming_handle = dissector_get_string_handle(streaming_subdissector_table, content_type);
					}
				} else if (g_ascii_strncasecmp( line, "Transfer-Encoding:", 18) == 0) {
					/*
					 * Find out if this Transfer-Encoding is
					 * chunked.  It should be, since the
					 * other types aren't really used, but
					 * RFC 7230 defines some.
					 * (RFC 3261 says "chunked" MUST NOT be
					 * used for SIP, and RFCs 2326 and 7826
					 * say the same for RTSP, but handle it
					 * anyway.)
					 */
					char *p;
					unsigned len;

					header_val = line+18;
					p = header_val;
					len = (unsigned) strlen(header_val);
					/* Skip white space */
					while (p < header_val + len &&
					    (*p == ' ' || *p == '\t'))
						p++;
					if (p <= header_val + len) {
						if (g_ascii_strncasecmp(p, "chunked", 7)
						    == 0) {
							/*
							 * Don't bother looking
							 * for extensions;
							 * since we don't
							 * understand them,
							 * they should be
							 * ignored.
							 */
							chunked_encoding = true;
						}
					}
				}
			}
		}
	}

	if (streaming_chunk_mode) {
		/* the tvb starts with chunk size without HTTP headers */
		chunked_encoding = true;
	} else if (desegment_body && chunked_encoding && streaming_handle && streaming_chunk_handle) {
		streaming_chunk_mode = true;
		*streaming_chunk_handle = streaming_handle;
	}

	/*
	 * The above loop ends when we reached the end of the headers, so
	 * there should be content_length bytes after the 4 terminating bytes
	 * and next_offset points to after the end of the headers.
	 *
	 * XXX: If desegment_headers is false but desegment_body is true,
	 * then for HTTP Responses we will always set to DESEGMENT_UNTIL_FIN,
	 * which is probably not what we want.
	 */
	if (desegment_body) {
		if (chunked_encoding) {
			/*
			 * This data is chunked, so we need to keep pulling
			 * data until we reach the end of the stream, or a
			 * zero sized chunk.
			 *
			 * But if streaming_chunk_mode is true,
			 * we will just pull one more chunk if the end of
			 * this tvb is in middle of a chunk. Because we want
			 * to dissect chunks with subdissector as soon as
			 * possible.
			 *
			 * XXX
			 * This doesn't bother with trailing headers; I don't
			 * think they are really used, and we'd have to use
			 * is_http_request_or_reply() to determine if it was
			 * a trailing header, or the start of a new response.
			 */
			bool done_chunking = false;
			if (last_chunk_offset != NULL && *last_chunk_offset) {
				next_offset = offset + *last_chunk_offset;
			}

			while (!done_chunking) {
				unsigned chunk_size = 0;
				int   chunk_offset = 0;
				char *chunk_string = NULL;
				char *c = NULL;

				reported_length_remaining =
				    tvb_reported_length_remaining(tvb,
				    next_offset);

				if (reported_length_remaining == 0 && streaming_chunk_mode) {
					return true;
				}

				if (reported_length_remaining < 1) {
					pinfo->desegment_offset = offset;
					pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
					return false;
				}

				length_remaining = tvb_captured_length_remaining(tvb,
				    next_offset);

				linelen = tvb_find_line_end(tvb, next_offset,
						length_remaining, &chunk_offset, true);

				if (linelen == -1 &&
				    length_remaining >=
				    reported_length_remaining) {
					 pinfo->desegment_offset = offset;
					 pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
					 return false;
				}

				/* We have a line with the chunk size in it.*/

				/* Save off the offset so we can skip this work next time.
				 * Use a relative offset, because we might call this
				 * with a different offset with a reassembled tvb.
				 */
				if (last_chunk_offset != NULL) {
					*last_chunk_offset = next_offset - offset;
				}

				chunk_string = tvb_get_string_enc(pinfo->pool, tvb, next_offset,
				    linelen, ENC_ASCII);
				c = chunk_string;

				/*
				 * We don't care about the extensions (including optional
				 * BWS, see RFC 9112 7.1.1)
				 */
				if ((c = strpbrk(c, "; \t"))) {
					*c = '\0';
				}

				if (!ws_hexstrtou32(chunk_string, NULL, &chunk_size)) {
					/* We couldn't get the chunk size,
					 * so stop trying.
					 */
					return true;
				}
				if (chunk_size > 1U<<31) {
					/* Chunk size is unreasonable. */
					/* XXX What /is/ reasonable? */
					return true;
				}

				if (chunk_size == 0) {
					/*
					 * This is the last chunk.  Let's pull in the
					 * trailing CRLF.
					 */
					linelen = tvb_find_line_end(tvb,
					    chunk_offset, length_remaining, &chunk_offset, true);

					if (linelen == -1 &&
					    length_remaining >=
					    reported_length_remaining) {
						pinfo->desegment_offset = offset;
						pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
						return false;
					}

					pinfo->desegment_offset = chunk_offset;
					pinfo->desegment_len = 0;
					done_chunking = true;
				} else {
					/*
					 * Skip to the next chunk if we
					 * already have it
					 */
					if (reported_length_remaining >
					        (int) chunk_size) {

						next_offset = chunk_offset
						    + chunk_size + 2;
					} else {
						/*
						 * Fetch this chunk, plus the
						 * trailing CRLF.
						 */
						if (streaming_chunk_mode) {
							int size_remaining = chunk_size + linelen + 4 - reported_length_remaining;
							if (size_remaining == 0) {
								return true;
							} else {
								pinfo->desegment_offset = offset;
								pinfo->desegment_len = size_remaining;
								return false;
							}
						} else {
							pinfo->desegment_offset = offset;
							pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
							return false;
						}
					}
				}

			}
		} else if (content_length_found) {
			if (content_length >= 128*1024) { /* MS-RPCH stipulate that the content-length must be between 128K and 2G */
				char *tmp;
				if (content_type_found &&
				strncmp(content_type, "application/rpc", 15) == 0) {
					/* It looks like a RPC_IN_DATA request or a RPC_OUT_DATA response
					 * in which the content-length is meaningless
					 */
					return true;
				}
				/* Following sizeof will return the length of the string + \0 we need to not count it*/
				tmp = tvb_get_string_enc(pinfo->pool, tvb, 0, sizeof("RPC_OUT_DATA") - 1, ENC_ASCII);
				if ((strncmp(tmp, "RPC_IN_DATA", sizeof("RPC_IN_DATA") - 1) == 0) ||
				    (strncmp(tmp, "RPC_OUT_DATA", sizeof("RPC_OUT_DATA") - 1) == 0)) {
					return true;
				}
			}
			/* next_offset has been set to the end of the headers */
			if (!tvb_bytes_exist(tvb, next_offset, content_length)) {
				length_remaining = tvb_captured_length_remaining(tvb,
				    next_offset);
				reported_length_remaining =
				    tvb_reported_length_remaining(tvb, next_offset);
				if (length_remaining < reported_length_remaining) {
					/*
					 * It's a waste of time asking for more
					 * data, because that data wasn't captured.
					 */
					return true;
				}
				if (length_remaining == -1)
					length_remaining = 0;
				pinfo->desegment_offset = offset;
				pinfo->desegment_len =
				    content_length - length_remaining;
				return false;
			}
		} else if (desegment_until_fin && pinfo->can_desegment) {
			/*
			 * No Content-Length nor Transfer-Encoding headers are
			 * found. For HTTP requests, there is definitely no
			 * body (case 6 of RFC 7230, Section 3.3.3.). For HTTP
			 * responses, the message body length runs until the end
			 * of the connection (case 7).
			 *
			 * Protocols like RTSP treat absence of Content-Length
			 * as 0, so do not request more segments either.
			 */
			length_remaining = tvb_captured_length_remaining(tvb, next_offset);
			reported_length_remaining = tvb_reported_length_remaining(tvb, next_offset);
			if (length_remaining < reported_length_remaining) {
				/*
				 * It's a waste of time asking for more
				 * data, because that data wasn't captured.
				 */
				return true;
			}

			pinfo->desegment_offset = offset;
			pinfo->desegment_len = DESEGMENT_UNTIL_FIN;

			return false;
		}

	}

	/*
	 * No further desegmentation needed.
	 */
	return true;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
