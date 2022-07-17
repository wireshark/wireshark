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
 *  @return TRUE if desegmentation is complete otherwise FALSE
 */
WS_DLL_PUBLIC gboolean
req_resp_hdrs_do_reassembly(tvbuff_t *tvb, const  int offset, packet_info *pinfo,
    const gboolean desegment_headers, const gboolean desegment_body,
    gboolean desegment_until_fin, int *last_chunk_offset);

#endif
