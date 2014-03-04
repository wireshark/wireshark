/* packet-h264.h
 * Routines for H.264 dissection
 * Copyright 2007, Anders Broman <anders.broman[at]ericsson.com>
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
 *
 * References:
 * http://www.ietf.org/rfc/rfc3984.txt?number=3984
 */
#ifndef __PACKET_H264_H__
#define __PACKET_H264_H__

void dissect_h264_profile(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
void dissect_h264_nal_unit(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

#endif /* __PACKET_H264_H__ */
