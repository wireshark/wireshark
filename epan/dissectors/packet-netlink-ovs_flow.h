/* packet-netlink-ovs_flow.h
 * Public entry points for reusing the ovs_flow key/action/tunnel-key
 * dissectors from other dissectors (e.g. ovs_packet upcalls).
 *
 * Copyright 2026, Red Hat Inc.
 * By Timothy Redaelli <tredaelli@redhat.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_NETLINK_OVS_FLOW_H__
#define __PACKET_NETLINK_OVS_FLOW_H__

#include "packet-netlink.h"

/*
 * Dissect an OVS_FLOW_ATTR_KEY / OVS_FLOW_ATTR_MASK attribute payload.
 * pinfo is required so that string fields can be allocated from the
 * per-packet memory pool.
 */
int ovs_flow_dissect_key(tvbuff_t *tvb, packet_info *pinfo,
	struct packet_netlink_data *nl_data, proto_tree *tree,
	int offset, int len);

/*
 * Dissect an OVS_FLOW_ATTR_ACTIONS attribute payload.
 */
int ovs_flow_dissect_actions(tvbuff_t *tvb, packet_info *pinfo,
	struct packet_netlink_data *nl_data, proto_tree *tree,
	int offset, int len);

/*
 * Dissect a tunnel-key attribute payload (OVS_TUNNEL_KEY_ATTR_* stream),
 * used for OVS_PACKET_ATTR_EGRESS_TUN_KEY.
 */
int ovs_flow_dissect_tunnel_key(tvbuff_t *tvb, packet_info *pinfo,
	struct packet_netlink_data *nl_data, proto_tree *tree,
	int offset, int len);

#endif /* __PACKET_NETLINK_OVS_FLOW_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
