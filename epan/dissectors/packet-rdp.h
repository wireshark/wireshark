/* packet-rdp.h
 * RDP dissection
 * Author: David Fort
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_RDP_H__
#define __PACKET_RDP_H__

#include <epan/packet.h>

extern int proto_rdp;

#define RDP_MAX_CHANNELS 31

typedef enum {
	RDP_CHANNEL_UNKNOWN,
	RDP_CHANNEL_DRDYNVC,
	RDP_CHANNEL_CLIPBOARD,
	RDP_CHANNEL_SOUND,
	RDP_CHANNEL_DISK,
	RDP_CHANNEL_RAIL,
	RDP_CHANNEL_CONCTRL,
} rdp_known_channel_t;


typedef struct {
	wmem_array_t *currentPayload;
	uint32_t packetLen;
	uint32_t pendingLen;
	uint32_t startFrame;
	wmem_array_t *chunks;
} rdp_channel_packet_context_t;

typedef struct {
	uint32_t startFrame;
	uint32_t endFrame;
	tvbuff_t* tvb;
	bool reassembled;
} rdp_channel_pdu_chunk_t;

typedef struct _rdp_channel_def {
    uint32_t value;
    const char *strptr;
    rdp_known_channel_t channelType;

    rdp_channel_packet_context_t current_sc;
    rdp_channel_packet_context_t current_cs;
    wmem_multimap_t *chunks_sc;
    wmem_multimap_t *chunks_cs;
} rdp_channel_def_t;

typedef struct _rdp_server_address {
	address addr;
	uint16_t port;
} rdp_server_address_t;



typedef struct _rdp_conv_info_t {
  uint32_t staticChannelId;
  uint32_t messageChannelId;
  uint32_t encryptionMethod;
  uint32_t encryptionLevel;
  uint32_t licenseAgreed;
  rdp_server_address_t serverAddr;
  uint8_t maxChannels;
  bool isRdstls;
  rdp_channel_def_t staticChannels[RDP_MAX_CHANNELS+1];
} rdp_conv_info_t;

unsigned dissect_rdp_bandwidth_req(tvbuff_t *tvb, unsigned offset, packet_info *pinfo, proto_tree *tree, bool from_server);
void rdp_transport_set_udp_conversation(const packet_info *pinfo, bool reliable, uint32_t reqId,
		uint8_t *cookie, conversation_t *conv);
conversation_t *rdp_find_tcp_conversation_from_udp(conversation_t *udp);

conversation_t *rdp_find_main_conversation(const packet_info *pinfo);


#endif /* __PACKET_RDP_H__ */
