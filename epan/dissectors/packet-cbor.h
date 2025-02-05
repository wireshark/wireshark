/* packet-cbor.h
 *
 * Routines for Concise Binary Object Representation (CBOR) (STD 94)
 * References:
 *     RFC 8949: https://tools.ietf.org/html/rfc8949
 *     RFC 8742: https://tools.ietf.org/html/rfc8742
 *
 * Copyright 2025, Brian Sipos <brian.sipos@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_CBOR_H
#define PACKET_CBOR_H

#include <epan/packet_info.h>
#include <epan/proto.h>
#include <epan/tvbuff.h>

/**
 * A dissector function which checks whether the entire data is composed of
 * one or more CBOR items (a "CBOR sequence").
 * This meets the signature of ::heur_dissector_t to allow it to be used
 * by other protocols directly as a heuristic.
 *
 * @param[in] tvb the tvbuff with the (remaining) packet data
 * @param pinfo the packet info of this packet (additional info)
 * @param tree the protocol tree to be build or NULL
 * @param[in] data Unused user data pointer
 * @return true if the entire TVB contains cbor item(s) and nothing more
 */
bool cbor_heuristic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);

#endif /* PACKET_CBOR_H */
