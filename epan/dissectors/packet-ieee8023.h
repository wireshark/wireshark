/* packet-ieee8023.h
 * Declaration of routine for dissecting 802.3 (as opposed to D/I/X Ethernet)
 * packets.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_IEEE8023_H__
#define __PACKET_IEEE8023_H__

void dissect_802_3(volatile int length, bool is_802_2, tvbuff_t *tvb,
    int offset_after_length, packet_info *pinfo, proto_tree *tree,
    proto_tree *fh_tree, int length_id, int trailer_id, expert_field* ei_len, int fcs_len);

#endif
