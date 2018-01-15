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

#ifndef _WIMAX_COMPACT_DLMAP_IE_DECODER_H_
#define _WIMAX_COMPACT_DLMAP_IE_DECODER_H_

extern guint wimax_compact_dlmap_ie_decoder(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, guint offset, guint nibble_offset);

#endif /* _WIMAX_COMPACT_DLMAP_IE_DECODER_H_ */
