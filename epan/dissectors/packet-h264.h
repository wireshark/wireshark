/* packet-h264.h
 * Routines for H.264 dissection
 * Copyright 2007, Anders Broman <anders.broman[at]ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * References:
 * http://www.ietf.org/rfc/rfc3984.txt?number=3984
 */
#ifndef __PACKET_H264_H__
#define __PACKET_H264_H__

void dissect_h264_profile(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
void dissect_h264_nal_unit(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

#endif /* __PACKET_H264_H__ */
