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

#include <epan/conversation.h>

typedef struct _eth_hdr {
	address dst;
	address src;
	uint16_t type;
	uint32_t stream;  /* track conversations */
} eth_hdr;

/* conversations related struct */
struct eth_analysis {

    /* Initial frame starting this conversation
     */
    uint32_t initial_frame;

    uint32_t stream;
};


void add_ethernet_trailer(packet_info *pinfo, proto_tree *tree, proto_tree *fh_tree,
			  int trailer_id, tvbuff_t *tvb, tvbuff_t *trailer_tvb,
			  int fcs_len, int payload_offset);

WS_DLL_PUBLIC struct eth_analysis *get_eth_conversation_data(conversation_t *conv,
                                  packet_info *pinfo);

#endif
