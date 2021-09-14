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

typedef struct _rdpudp_conv_info_t {
	guint32 start_v2_at;
	gboolean is_lossy;

	address server_addr;
	guint16 server_port;
} rdpudp_conv_info_t;

gboolean rdp_isServerAddressTarget(packet_info *pinfo);
gboolean rdpudp_is_reliable_transport(packet_info *pinfo);

#endif /* __PACKET_RDPUDP_H_ */
