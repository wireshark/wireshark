/* packet-tpkt.h
 *
 * Routines for TPKT dissection
 *
 * Copyright 2000, Philips Electronics N.V.
 * Andreas Sikkema <andreas.sikkema@philips.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "ws_symbol_export.h"

/*
 * Check whether this could be a TPKT-encapsulated PDU.
 * Returns -1 if it's not, and the PDU length from the TPKT header
 * if it is.
 *
 * "min_len" is the minimum length of the PDU; the length field in the
 * TPKT header must be at least "4+min_len" in order for this to be a
 * valid TPKT PDU for the protocol in question.
 */
WS_DLL_PUBLIC int is_tpkt(tvbuff_t *tvb, int min_len);

/*
 * Dissect TPKT-encapsulated data in a TCP stream.
 */
WS_DLL_PUBLIC void dissect_tpkt_encap(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, gboolean desegment,
    dissector_handle_t subdissector_handle);

/*
 * Check whether this could be a ASCII TPKT-encapsulated PDU.
 * Returns -1 if it's not, and the PDU length from the TPKT header
 * if it is.
 *
 * "min_len" is the minimum length of the PDU; the length field in the
 * TPKT header must be at least "8+min_len" in order for this to be a
 * valid TPKT PDU for the protocol in question.
 */
extern guint16 is_asciitpkt(tvbuff_t *tvb);

/*
 * Dissect ASCII TPKT-encapsulated data in a TCP stream.
 */
extern void dissect_asciitpkt(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, dissector_handle_t subdissector_handle);
