/* packet-h265.h
* Routines for H.265 dissection
* Copyright 2018, Asaf Kave <kave.asaf[at]gmail.com>
* Based on the H.264 dissector, thanks!
*
* Wireshark - Network traffic analyzer
* By Gerald Combs <gerald@wireshark.org>
* Copyright 1998 Gerald Combs
*
* SPDX-License-Identifier: GPL-2.0-or-later
*
* References:
* https://tools.ietf.org/html/rfc7798
* http://www.itu.int/rec/T-REC-H.265/en
*/

#ifndef __PACKET_H265_H__
#define __PACKET_H265_H__

void dissect_h265_format_specific_parameter(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo);

#endif /* __PACKET_H265_H__ */
