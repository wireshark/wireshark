/* packet-http3.h
 * Routines for HTTP/3 dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * Get the HTTP/3 Stream ID for the current HTTP/3 frame
 *
 * @param pinfo A packet_info struct
 * @return A pointer to pinfo->pool scoped data with the most recent HTTP/3
 * stream ID for the frame indicated by the packet_info struct. NULL if no
 * HTTP/3 frame has been dissected.
 *
 * @note The HTTP/3 Stream ID is identical to the QUIC Stream ID, but this
 * is NULL if the HTTP/3 dissector was not called. Zero is a valid and common
 * stream ID; since the space is 62-bit we could return a scalar uint64_t and
 * use some #defined large value (e.g., UINT64_MAX) to mean failure.
 */
uint64_t* http3_get_stream_id(packet_info *pinfo);

#ifdef __cplusplus
}
#endif /* __cplusplus */
