/* packet-isl.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_ISL_H__
#define __PACKET_ISL_H__

void dissect_isl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    int fcs_len);

#endif
