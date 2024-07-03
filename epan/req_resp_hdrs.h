/** @file
 * Declarations of routines handling protocols with a request/response line,
 * headers, a blank line, and an optional body.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __REQ_RESP_HDRS_H__
#define __REQ_RESP_HDRS_H__

#include "ws_symbol_export.h"
#include "wsutil/strtoi.h"

/**
 * Optionally do reassembly of the request/response line, headers, and body.
 *
 *  @param tvb  The buffer.
 *  @param offset   The offset in the buffer to begin inspection.
 *  @param pinfo    Packet info from the parent protocol.
 *  @param desegment_headers    Do desegmentation on headers.
 *  @param desegment_body   Do desegmentation on body.
 *  @param desegment_until_fin  When desegment_body is enabled and no
 *  Content-Length header is found, assume that all data following the headers
 *  are part of the body.
 *  @param[in,out] last_chunk_offset  For the chunked Transfer-Encoding,
 *  the offset (relative to the initial tvb offset) of the last chunk size
 *  found.  The result can be fed back into a future call in order to skip
 *  to a later chunk and reduce processing from O(N^2) to O(N).  Use 0 for
 *  the initial call.  Only set when chunked TE is found.  May be NULL.
 *  @param streaming_subdissector_table   For searching a streaming reassembly
 *  mode supported subdissector on it by the content-type header value.
 *  @param[out] streaming_chunk_handle   Only set when this is the beginning of
 *  a chunk stream. (There is 'Transfer-Encoding: chunked' header and a
 *  streaming reassembly mode supported subdissector is found according to
 *  Content-Type header)
 *  @return true if desegmentation is complete otherwise false
 */
WS_DLL_PUBLIC bool
req_resp_hdrs_do_reassembly(tvbuff_t *tvb, const  int offset, packet_info *pinfo,
    const bool desegment_headers, const bool desegment_body,
    bool desegment_until_fin, int *last_chunk_offset,
	dissector_table_t streaming_subdissector_table, dissector_handle_t *streaming_chunk_handle);

/** Check whether the first line is the beginning of a chunk. */
static inline bool
starts_with_chunk_size(tvbuff_t* tvb, const int offset, packet_info* pinfo)
{
	unsigned chunk_size = 0;
	int linelen = tvb_find_line_end(tvb, offset, tvb_reported_length_remaining(tvb, offset), NULL, true);

	if (linelen < 0)
		return false;

	char* chunk_string = tvb_get_string_enc(pinfo->pool, tvb, offset, linelen, ENC_ASCII);
	char* c = chunk_string;

	/* ignore extensions, including optional BWS ("bad whitespace")
         * in the grammar for historical reasons, see RFC 9112 7.1.1.
         */
	if ((c = strpbrk(c, "; \t"))) {
		*c = '\0';
	}

        if (!ws_hexstrtou32(chunk_string, NULL, &chunk_size)) {
		return false; /* can not get chunk size*/
	} else if (chunk_size > (1U << 31)) {
		return false; /* chunk size is unreasonable */
	}
	return true;
}

#endif
