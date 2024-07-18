/* packet-rdpudp.h
 * RDP UDP dissection
 * Author: David Fort
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_RDPUDP_H__
#define __PACKET_RDPUDP_H__

#include <glib.h>
#include <epan/packet.h>

extern int proto_rdpudp;

typedef struct {
	uint64_t current_base;
	uint16_t last_received;
} rdpudp_seq_context_t;

typedef struct _rdpudp_conv_info_t {
	uint32_t start_v2_at;
	bool is_lossy;

	address server_addr;
	uint16_t server_port;
	wmem_tree_t* server_chunks;
	rdpudp_seq_context_t server_data_seq;
	rdpudp_seq_context_t server_channel_seq;
	wmem_tree_t* client_chunks;
	rdpudp_seq_context_t client_data_seq;
	rdpudp_seq_context_t client_channel_seq;
} rdpudp_conv_info_t;

bool rdp_isServerAddressTarget(packet_info *pinfo);
bool rdpudp_is_reliable_transport(packet_info *pinfo);

#endif /* __PACKET_RDPUDP_H_ */
