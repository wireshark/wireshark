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
} rdp_known_channel_t;

typedef struct _rdp_channel_def {
    guint32      value;
    const gchar *strptr;
    rdp_known_channel_t channelType;
} rdp_channel_def_t;

typedef struct _rdp_server_address {
	address addr;
	guint16 port;
} rdp_server_address_t;

typedef struct _rdp_conv_info_t {
  guint32 staticChannelId;
  guint32 messageChannelId;
  guint32 encryptionMethod;
  guint32 encryptionLevel;
  guint32 licenseAgreed;
  rdp_server_address_t serverAddr;
  guint8  maxChannels;
  rdp_channel_def_t staticChannels[RDP_MAX_CHANNELS+1];
} rdp_conv_info_t;


#endif /* __PACKET_RDP_H__ */
