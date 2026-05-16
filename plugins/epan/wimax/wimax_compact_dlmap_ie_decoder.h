/* wimax_compact_dlmap_ie_decoder.h
 * Declarations of routines exported by WiMax HARQ Map Message decoder
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

#ifndef _WIMAX_COMPACT_DLMAP_IE_DECODER_H_
#define _WIMAX_COMPACT_DLMAP_IE_DECODER_H_

extern unsigned harq_mode;
extern unsigned cid_type;
extern unsigned band_amc_subchannel_type;
extern unsigned num_of_broadcast_symbols;
extern unsigned num_of_dl_band_amc_symbols;
extern unsigned num_of_ul_band_amc_symbols;

/**
 * @brief Decodes WiMax Compact DL-MAP Information Elements.
 *
 * @param tree Protocol tree to add decoded information to.
 * @param pinfo Packet information structure.
 * @param tvb Buffer containing the packet data.
 * @param offset Current offset within the buffer.
 * @param nibble_offset Nibble offset for decoding.
 * @return unsigned Length of the decoded information.
 */
extern unsigned wimax_compact_dlmap_ie_decoder(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, unsigned offset, unsigned nibble_offset);

#endif /* _WIMAX_COMPACT_DLMAP_IE_DECODER_H_ */
