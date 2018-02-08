/* req_resp_hdrs.h
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
 *  @param desegment_body   Do desegmenation on body.
 *  @return TRUE if desegmentation is complete otherwise FALSE
 */
WS_DLL_PUBLIC gboolean
req_resp_hdrs_do_reassembly(tvbuff_t *tvb, const  int offset, packet_info *pinfo,
    const gboolean desegment_headers, const gboolean desegment_body);

#endif
