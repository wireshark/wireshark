/* packet-eth.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_ETH_H__
#define __PACKET_ETH_H__

typedef struct _eth_hdr {
	address dst;
	address src;
	guint16 type;
} eth_hdr;

void add_ethernet_trailer(packet_info *pinfo, proto_tree *tree, proto_tree *fh_tree,
			  int trailer_id, tvbuff_t *tvb, tvbuff_t *trailer_tvb,
			  int fcs_len);

#endif
