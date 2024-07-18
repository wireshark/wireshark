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

#include <glib.h>
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
} rdp_known_channel_t;

typedef struct _rdp_channel_def {
    uint32_t     value;
    const char *strptr;
    rdp_known_channel_t channelType;
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

int dissect_rdp_bandwidth_req(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, bool from_server);
void rdp_transport_set_udp_conversation(const address *serverAddr, uint16_t serverPort, bool reliable, uint32_t reqId,
		uint8_t *cookie, conversation_t *conv);
conversation_t *rdp_find_tcp_conversation_from_udp(conversation_t *udp);

#endif /* __PACKET_RDP_H__ */
