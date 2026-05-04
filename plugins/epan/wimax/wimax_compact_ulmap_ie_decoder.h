/* wimax_compact_ulmap_ie_decoder.h
 * WiMax HARQ Map Message decoder
 *
 * Copyright (c) 2007 by Intel Corporation.
 *
 * Author: Lu Pan <lu.pan@intel.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _WIMAX_COMPACT_ULMAP_IE_DECODER_H_
#define _WIMAX_COMPACT_ULMAP_IE_DECODER_H_

/**
 * @brief Decodes WiMax Compact UL-MAP Information Elements.
 *
 * @param tree Protocol tree to add decoded information to.
 * @param pinfo Packet information structure.
 * @param tvb Buffer containing the packet data.
 * @param offset Offset within the buffer where decoding should start.
 * @param nibble_offset Nibble offset for decoding.
 * @return unsigned Length of the decoded information.
 */
extern unsigned wimax_compact_ulmap_ie_decoder(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, unsigned offset, unsigned nibble_offset);

#endif /* _WIMAX_COMPACT_ULMAP_IE_DECODER_H_ */
