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

extern guint wimax_compact_ulmap_ie_decoder(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, guint offset, guint nibble_offset);

#endif /* _WIMAX_COMPACT_ULMAP_IE_DECODER_H_ */
