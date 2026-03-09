/* packet-netlink-ovs_flow.c
 * Routines for Open vSwitch flow netlink protocol dissection
 * Copyright 2026, Red Hat Inc.
 * By Timothy Redaelli <tredaelli@redhat.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* ovs_flow manages Open vSwitch flow entries via Generic Netlink
 *
 * Relevant Linux kernel header file:
 * include/uapi/linux/openvswitch.h
 */

#include "config.h"

#include <epan/packet.h>

#include "packet-netlink.h"

void proto_register_netlink_ovs_flow(void);
void proto_reg_handoff_netlink_ovs_flow(void);

/* from <include/uapi/linux/openvswitch.h> prefixed with WS_ */
enum ws_ovs_flow_cmd {
	WS_OVS_FLOW_CMD_UNSPEC,
	WS_OVS_FLOW_CMD_NEW,
	WS_OVS_FLOW_CMD_DEL,
	WS_OVS_FLOW_CMD_GET,
	WS_OVS_FLOW_CMD_SET,
};

enum ws_ovs_flow_attr {
	WS_OVS_FLOW_ATTR_UNSPEC,
	WS_OVS_FLOW_ATTR_KEY,
	WS_OVS_FLOW_ATTR_ACTIONS,
	WS_OVS_FLOW_ATTR_STATS,
	WS_OVS_FLOW_ATTR_TCP_FLAGS,
	WS_OVS_FLOW_ATTR_USED,
	WS_OVS_FLOW_ATTR_CLEAR,
	WS_OVS_FLOW_ATTR_MASK,
	WS_OVS_FLOW_ATTR_PROBE,
	WS_OVS_FLOW_ATTR_UFID,
	WS_OVS_FLOW_ATTR_UFID_FLAGS,
	WS_OVS_FLOW_ATTR_PAD,
};


enum ws_ovs_key_attr {
	WS_OVS_KEY_ATTR_UNSPEC,
	WS_OVS_KEY_ATTR_ENCAP,
	WS_OVS_KEY_ATTR_PRIORITY,
	WS_OVS_KEY_ATTR_IN_PORT,
	WS_OVS_KEY_ATTR_ETHERNET,
	WS_OVS_KEY_ATTR_VLAN,
	WS_OVS_KEY_ATTR_ETHERTYPE,
	WS_OVS_KEY_ATTR_IPV4,
	WS_OVS_KEY_ATTR_IPV6,
	WS_OVS_KEY_ATTR_TCP,
	WS_OVS_KEY_ATTR_UDP,
	WS_OVS_KEY_ATTR_ICMP,
	WS_OVS_KEY_ATTR_ICMPV6,
	WS_OVS_KEY_ATTR_ARP,
	WS_OVS_KEY_ATTR_ND,
	WS_OVS_KEY_ATTR_SKB_MARK,
	WS_OVS_KEY_ATTR_TUNNEL,
	WS_OVS_KEY_ATTR_SCTP,
	WS_OVS_KEY_ATTR_TCP_FLAGS,
	WS_OVS_KEY_ATTR_DP_HASH,
	WS_OVS_KEY_ATTR_RECIRC_ID,
	WS_OVS_KEY_ATTR_MPLS,
	WS_OVS_KEY_ATTR_CT_STATE,
	WS_OVS_KEY_ATTR_CT_ZONE,
	WS_OVS_KEY_ATTR_CT_MARK,
	WS_OVS_KEY_ATTR_CT_LABELS,
	WS_OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4,
	WS_OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6,
	WS_OVS_KEY_ATTR_NSH,
	WS_OVS_KEY_ATTR_PACKET_TYPE,
	WS_OVS_KEY_ATTR_ND_EXTENSIONS,
	WS_OVS_KEY_ATTR_TUNNEL_INFO,
	WS_OVS_KEY_ATTR_IPV6_EXTHDRS,
};


enum ws_ovs_tunnel_key_attr {
	WS_OVS_TUNNEL_KEY_ATTR_ID,
	WS_OVS_TUNNEL_KEY_ATTR_IPV4_SRC,
	WS_OVS_TUNNEL_KEY_ATTR_IPV4_DST,
	WS_OVS_TUNNEL_KEY_ATTR_TOS,
	WS_OVS_TUNNEL_KEY_ATTR_TTL,
	WS_OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT,
	WS_OVS_TUNNEL_KEY_ATTR_CSUM,
	WS_OVS_TUNNEL_KEY_ATTR_OAM,
	WS_OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS,
	WS_OVS_TUNNEL_KEY_ATTR_TP_SRC,
	WS_OVS_TUNNEL_KEY_ATTR_TP_DST,
	WS_OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS,
	WS_OVS_TUNNEL_KEY_ATTR_IPV6_SRC,
	WS_OVS_TUNNEL_KEY_ATTR_IPV6_DST,
	WS_OVS_TUNNEL_KEY_ATTR_PAD,
	WS_OVS_TUNNEL_KEY_ATTR_ERSPAN_OPTS,
	WS_OVS_TUNNEL_KEY_ATTR_IPV4_INFO_BRIDGE,
};

enum ws_ovs_frag_type {
	WS_OVS_FRAG_TYPE_NONE,
	WS_OVS_FRAG_TYPE_FIRST,
	WS_OVS_FRAG_TYPE_LATER,
};

enum ws_ovs_action_attr {
	WS_OVS_ACTION_ATTR_UNSPEC,
	WS_OVS_ACTION_ATTR_OUTPUT,
	WS_OVS_ACTION_ATTR_USERSPACE,
	WS_OVS_ACTION_ATTR_SET,
	WS_OVS_ACTION_ATTR_PUSH_VLAN,
	WS_OVS_ACTION_ATTR_POP_VLAN,
	WS_OVS_ACTION_ATTR_SAMPLE,
	WS_OVS_ACTION_ATTR_RECIRC,
	WS_OVS_ACTION_ATTR_HASH,
	WS_OVS_ACTION_ATTR_PUSH_MPLS,
	WS_OVS_ACTION_ATTR_POP_MPLS,
	WS_OVS_ACTION_ATTR_SET_MASKED,
	WS_OVS_ACTION_ATTR_CT,
	WS_OVS_ACTION_ATTR_TRUNC,
	WS_OVS_ACTION_ATTR_PUSH_ETH,
	WS_OVS_ACTION_ATTR_POP_ETH,
	WS_OVS_ACTION_ATTR_CT_CLEAR,
	WS_OVS_ACTION_ATTR_PUSH_NSH,
	WS_OVS_ACTION_ATTR_POP_NSH,
	WS_OVS_ACTION_ATTR_METER,
	WS_OVS_ACTION_ATTR_CLONE,
	WS_OVS_ACTION_ATTR_CHECK_PKT_LEN,
	WS_OVS_ACTION_ATTR_ADD_MPLS,
	WS_OVS_ACTION_ATTR_DEC_TTL,
	WS_OVS_ACTION_ATTR_DROP,
	WS_OVS_ACTION_ATTR_PSAMPLE,
};

enum ws_ovs_userspace_attr {
	WS_OVS_USERSPACE_ATTR_UNSPEC,
	WS_OVS_USERSPACE_ATTR_PID,
	WS_OVS_USERSPACE_ATTR_USERDATA,
	WS_OVS_USERSPACE_ATTR_EGRESS_TUN_PORT,
	WS_OVS_USERSPACE_ATTR_ACTIONS,
};

enum ws_ovs_sample_attr {
	WS_OVS_SAMPLE_ATTR_UNSPEC,
	WS_OVS_SAMPLE_ATTR_PROBABILITY,
	WS_OVS_SAMPLE_ATTR_ACTIONS,
};

enum ws_ovs_ct_attr {
	WS_OVS_CT_ATTR_UNSPEC,
	WS_OVS_CT_ATTR_COMMIT,
	WS_OVS_CT_ATTR_ZONE,
	WS_OVS_CT_ATTR_MARK,
	WS_OVS_CT_ATTR_LABELS,
	WS_OVS_CT_ATTR_HELPER,
	WS_OVS_CT_ATTR_NAT,
	WS_OVS_CT_ATTR_FORCE_COMMIT,
	WS_OVS_CT_ATTR_EVENTMASK,
	WS_OVS_CT_ATTR_TIMEOUT,
};

enum ws_ovs_nat_attr {
	WS_OVS_NAT_ATTR_UNSPEC,
	WS_OVS_NAT_ATTR_SRC,
	WS_OVS_NAT_ATTR_DST,
	WS_OVS_NAT_ATTR_IP_MIN,
	WS_OVS_NAT_ATTR_IP_MAX,
	WS_OVS_NAT_ATTR_PROTO_MIN,
	WS_OVS_NAT_ATTR_PROTO_MAX,
	WS_OVS_NAT_ATTR_PERSISTENT,
	WS_OVS_NAT_ATTR_PROTO_HASH,
	WS_OVS_NAT_ATTR_PROTO_RANDOM,
};

static const value_string ws_ovs_flow_commands_vals[] = {
	{ WS_OVS_FLOW_CMD_UNSPEC,	"OVS_FLOW_CMD_UNSPEC" },
	{ WS_OVS_FLOW_CMD_NEW,		"OVS_FLOW_CMD_NEW" },
	{ WS_OVS_FLOW_CMD_DEL,		"OVS_FLOW_CMD_DEL" },
	{ WS_OVS_FLOW_CMD_GET,		"OVS_FLOW_CMD_GET" },
	{ WS_OVS_FLOW_CMD_SET,		"OVS_FLOW_CMD_SET" },
	{ 0, NULL }
};

static const value_string ws_ovs_flow_attr_vals[] = {
	{ WS_OVS_FLOW_ATTR_UNSPEC,	"OVS_FLOW_ATTR_UNSPEC" },
	{ WS_OVS_FLOW_ATTR_KEY,	"OVS_FLOW_ATTR_KEY" },
	{ WS_OVS_FLOW_ATTR_ACTIONS,	"OVS_FLOW_ATTR_ACTIONS" },
	{ WS_OVS_FLOW_ATTR_STATS,	"OVS_FLOW_ATTR_STATS" },
	{ WS_OVS_FLOW_ATTR_TCP_FLAGS,	"OVS_FLOW_ATTR_TCP_FLAGS" },
	{ WS_OVS_FLOW_ATTR_USED,	"OVS_FLOW_ATTR_USED" },
	{ WS_OVS_FLOW_ATTR_CLEAR,	"OVS_FLOW_ATTR_CLEAR" },
	{ WS_OVS_FLOW_ATTR_MASK,	"OVS_FLOW_ATTR_MASK" },
	{ WS_OVS_FLOW_ATTR_PROBE,	"OVS_FLOW_ATTR_PROBE" },
	{ WS_OVS_FLOW_ATTR_UFID,	"OVS_FLOW_ATTR_UFID" },
	{ WS_OVS_FLOW_ATTR_UFID_FLAGS,	"OVS_FLOW_ATTR_UFID_FLAGS" },
	{ WS_OVS_FLOW_ATTR_PAD,	"OVS_FLOW_ATTR_PAD" },
	{ 0, NULL }
};

static const value_string ws_ovs_key_attr_vals[] = {
	{ WS_OVS_KEY_ATTR_UNSPEC,		"OVS_KEY_ATTR_UNSPEC" },
	{ WS_OVS_KEY_ATTR_ENCAP,		"OVS_KEY_ATTR_ENCAP" },
	{ WS_OVS_KEY_ATTR_PRIORITY,		"OVS_KEY_ATTR_PRIORITY" },
	{ WS_OVS_KEY_ATTR_IN_PORT,		"OVS_KEY_ATTR_IN_PORT" },
	{ WS_OVS_KEY_ATTR_ETHERNET,		"OVS_KEY_ATTR_ETHERNET" },
	{ WS_OVS_KEY_ATTR_VLAN,		"OVS_KEY_ATTR_VLAN" },
	{ WS_OVS_KEY_ATTR_ETHERTYPE,		"OVS_KEY_ATTR_ETHERTYPE" },
	{ WS_OVS_KEY_ATTR_IPV4,		"OVS_KEY_ATTR_IPV4" },
	{ WS_OVS_KEY_ATTR_IPV6,		"OVS_KEY_ATTR_IPV6" },
	{ WS_OVS_KEY_ATTR_TCP,			"OVS_KEY_ATTR_TCP" },
	{ WS_OVS_KEY_ATTR_UDP,			"OVS_KEY_ATTR_UDP" },
	{ WS_OVS_KEY_ATTR_ICMP,		"OVS_KEY_ATTR_ICMP" },
	{ WS_OVS_KEY_ATTR_ICMPV6,		"OVS_KEY_ATTR_ICMPV6" },
	{ WS_OVS_KEY_ATTR_ARP,			"OVS_KEY_ATTR_ARP" },
	{ WS_OVS_KEY_ATTR_ND,			"OVS_KEY_ATTR_ND" },
	{ WS_OVS_KEY_ATTR_SKB_MARK,		"OVS_KEY_ATTR_SKB_MARK" },
	{ WS_OVS_KEY_ATTR_TUNNEL,		"OVS_KEY_ATTR_TUNNEL" },
	{ WS_OVS_KEY_ATTR_SCTP,		"OVS_KEY_ATTR_SCTP" },
	{ WS_OVS_KEY_ATTR_TCP_FLAGS,		"OVS_KEY_ATTR_TCP_FLAGS" },
	{ WS_OVS_KEY_ATTR_DP_HASH,		"OVS_KEY_ATTR_DP_HASH" },
	{ WS_OVS_KEY_ATTR_RECIRC_ID,		"OVS_KEY_ATTR_RECIRC_ID" },
	{ WS_OVS_KEY_ATTR_MPLS,		"OVS_KEY_ATTR_MPLS" },
	{ WS_OVS_KEY_ATTR_CT_STATE,		"OVS_KEY_ATTR_CT_STATE" },
	{ WS_OVS_KEY_ATTR_CT_ZONE,		"OVS_KEY_ATTR_CT_ZONE" },
	{ WS_OVS_KEY_ATTR_CT_MARK,		"OVS_KEY_ATTR_CT_MARK" },
	{ WS_OVS_KEY_ATTR_CT_LABELS,		"OVS_KEY_ATTR_CT_LABELS" },
	{ WS_OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4,	"OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4" },
	{ WS_OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6,	"OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6" },
	{ WS_OVS_KEY_ATTR_NSH,			"OVS_KEY_ATTR_NSH" },
	{ WS_OVS_KEY_ATTR_PACKET_TYPE,		"OVS_KEY_ATTR_PACKET_TYPE" },
	{ WS_OVS_KEY_ATTR_ND_EXTENSIONS,	"OVS_KEY_ATTR_ND_EXTENSIONS" },
	{ WS_OVS_KEY_ATTR_TUNNEL_INFO,		"OVS_KEY_ATTR_TUNNEL_INFO" },
	{ WS_OVS_KEY_ATTR_IPV6_EXTHDRS,	"OVS_KEY_ATTR_IPV6_EXTHDRS" },
	{ 0, NULL }
};

static const value_string ws_ovs_tunnel_key_attr_vals[] = {
	{ WS_OVS_TUNNEL_KEY_ATTR_ID,			"OVS_TUNNEL_KEY_ATTR_ID" },
	{ WS_OVS_TUNNEL_KEY_ATTR_IPV4_SRC,		"OVS_TUNNEL_KEY_ATTR_IPV4_SRC" },
	{ WS_OVS_TUNNEL_KEY_ATTR_IPV4_DST,		"OVS_TUNNEL_KEY_ATTR_IPV4_DST" },
	{ WS_OVS_TUNNEL_KEY_ATTR_TOS,			"OVS_TUNNEL_KEY_ATTR_TOS" },
	{ WS_OVS_TUNNEL_KEY_ATTR_TTL,			"OVS_TUNNEL_KEY_ATTR_TTL" },
	{ WS_OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT,	"OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT" },
	{ WS_OVS_TUNNEL_KEY_ATTR_CSUM,			"OVS_TUNNEL_KEY_ATTR_CSUM" },
	{ WS_OVS_TUNNEL_KEY_ATTR_OAM,			"OVS_TUNNEL_KEY_ATTR_OAM" },
	{ WS_OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS,		"OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS" },
	{ WS_OVS_TUNNEL_KEY_ATTR_TP_SRC,		"OVS_TUNNEL_KEY_ATTR_TP_SRC" },
	{ WS_OVS_TUNNEL_KEY_ATTR_TP_DST,		"OVS_TUNNEL_KEY_ATTR_TP_DST" },
	{ WS_OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS,		"OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS" },
	{ WS_OVS_TUNNEL_KEY_ATTR_IPV6_SRC,		"OVS_TUNNEL_KEY_ATTR_IPV6_SRC" },
	{ WS_OVS_TUNNEL_KEY_ATTR_IPV6_DST,		"OVS_TUNNEL_KEY_ATTR_IPV6_DST" },
	{ WS_OVS_TUNNEL_KEY_ATTR_PAD,			"OVS_TUNNEL_KEY_ATTR_PAD" },
	{ WS_OVS_TUNNEL_KEY_ATTR_ERSPAN_OPTS,		"OVS_TUNNEL_KEY_ATTR_ERSPAN_OPTS" },
	{ WS_OVS_TUNNEL_KEY_ATTR_IPV4_INFO_BRIDGE,	"OVS_TUNNEL_KEY_ATTR_IPV4_INFO_BRIDGE" },
	{ 0, NULL }
};

static const value_string ws_ovs_frag_type_vals[] = {
	{ WS_OVS_FRAG_TYPE_NONE,	"OVS_FRAG_TYPE_NONE" },
	{ WS_OVS_FRAG_TYPE_FIRST,	"OVS_FRAG_TYPE_FIRST" },
	{ WS_OVS_FRAG_TYPE_LATER,	"OVS_FRAG_TYPE_LATER" },
	{ 0, NULL }
};

static const value_string ws_ovs_action_attr_vals[] = {
	{ WS_OVS_ACTION_ATTR_UNSPEC,		"OVS_ACTION_ATTR_UNSPEC" },
	{ WS_OVS_ACTION_ATTR_OUTPUT,		"OVS_ACTION_ATTR_OUTPUT" },
	{ WS_OVS_ACTION_ATTR_USERSPACE,	"OVS_ACTION_ATTR_USERSPACE" },
	{ WS_OVS_ACTION_ATTR_SET,		"OVS_ACTION_ATTR_SET" },
	{ WS_OVS_ACTION_ATTR_PUSH_VLAN,	"OVS_ACTION_ATTR_PUSH_VLAN" },
	{ WS_OVS_ACTION_ATTR_POP_VLAN,		"OVS_ACTION_ATTR_POP_VLAN" },
	{ WS_OVS_ACTION_ATTR_SAMPLE,		"OVS_ACTION_ATTR_SAMPLE" },
	{ WS_OVS_ACTION_ATTR_RECIRC,		"OVS_ACTION_ATTR_RECIRC" },
	{ WS_OVS_ACTION_ATTR_HASH,		"OVS_ACTION_ATTR_HASH" },
	{ WS_OVS_ACTION_ATTR_PUSH_MPLS,	"OVS_ACTION_ATTR_PUSH_MPLS" },
	{ WS_OVS_ACTION_ATTR_POP_MPLS,		"OVS_ACTION_ATTR_POP_MPLS" },
	{ WS_OVS_ACTION_ATTR_SET_MASKED,	"OVS_ACTION_ATTR_SET_MASKED" },
	{ WS_OVS_ACTION_ATTR_CT,		"OVS_ACTION_ATTR_CT" },
	{ WS_OVS_ACTION_ATTR_TRUNC,		"OVS_ACTION_ATTR_TRUNC" },
	{ WS_OVS_ACTION_ATTR_PUSH_ETH,		"OVS_ACTION_ATTR_PUSH_ETH" },
	{ WS_OVS_ACTION_ATTR_POP_ETH,		"OVS_ACTION_ATTR_POP_ETH" },
	{ WS_OVS_ACTION_ATTR_CT_CLEAR,		"OVS_ACTION_ATTR_CT_CLEAR" },
	{ WS_OVS_ACTION_ATTR_PUSH_NSH,		"OVS_ACTION_ATTR_PUSH_NSH" },
	{ WS_OVS_ACTION_ATTR_POP_NSH,		"OVS_ACTION_ATTR_POP_NSH" },
	{ WS_OVS_ACTION_ATTR_METER,		"OVS_ACTION_ATTR_METER" },
	{ WS_OVS_ACTION_ATTR_CLONE,		"OVS_ACTION_ATTR_CLONE" },
	{ WS_OVS_ACTION_ATTR_CHECK_PKT_LEN,	"OVS_ACTION_ATTR_CHECK_PKT_LEN" },
	{ WS_OVS_ACTION_ATTR_ADD_MPLS,		"OVS_ACTION_ATTR_ADD_MPLS" },
	{ WS_OVS_ACTION_ATTR_DEC_TTL,		"OVS_ACTION_ATTR_DEC_TTL" },
	{ WS_OVS_ACTION_ATTR_DROP,		"OVS_ACTION_ATTR_DROP" },
	{ WS_OVS_ACTION_ATTR_PSAMPLE,		"OVS_ACTION_ATTR_PSAMPLE" },
	{ 0, NULL }
};

static const value_string ws_ovs_userspace_attr_vals[] = {
	{ WS_OVS_USERSPACE_ATTR_UNSPEC,		"OVS_USERSPACE_ATTR_UNSPEC" },
	{ WS_OVS_USERSPACE_ATTR_PID,			"OVS_USERSPACE_ATTR_PID" },
	{ WS_OVS_USERSPACE_ATTR_USERDATA,		"OVS_USERSPACE_ATTR_USERDATA" },
	{ WS_OVS_USERSPACE_ATTR_EGRESS_TUN_PORT,	"OVS_USERSPACE_ATTR_EGRESS_TUN_PORT" },
	{ WS_OVS_USERSPACE_ATTR_ACTIONS,		"OVS_USERSPACE_ATTR_ACTIONS" },
	{ 0, NULL }
};

static const value_string ws_ovs_sample_attr_vals[] = {
	{ WS_OVS_SAMPLE_ATTR_UNSPEC,		"OVS_SAMPLE_ATTR_UNSPEC" },
	{ WS_OVS_SAMPLE_ATTR_PROBABILITY,	"OVS_SAMPLE_ATTR_PROBABILITY" },
	{ WS_OVS_SAMPLE_ATTR_ACTIONS,		"OVS_SAMPLE_ATTR_ACTIONS" },
	{ 0, NULL }
};

static const value_string ws_ovs_ct_attr_vals[] = {
	{ WS_OVS_CT_ATTR_UNSPEC,	"OVS_CT_ATTR_UNSPEC" },
	{ WS_OVS_CT_ATTR_COMMIT,	"OVS_CT_ATTR_COMMIT" },
	{ WS_OVS_CT_ATTR_ZONE,		"OVS_CT_ATTR_ZONE" },
	{ WS_OVS_CT_ATTR_MARK,		"OVS_CT_ATTR_MARK" },
	{ WS_OVS_CT_ATTR_LABELS,	"OVS_CT_ATTR_LABELS" },
	{ WS_OVS_CT_ATTR_HELPER,	"OVS_CT_ATTR_HELPER" },
	{ WS_OVS_CT_ATTR_NAT,		"OVS_CT_ATTR_NAT" },
	{ WS_OVS_CT_ATTR_FORCE_COMMIT,	"OVS_CT_ATTR_FORCE_COMMIT" },
	{ WS_OVS_CT_ATTR_EVENTMASK,	"OVS_CT_ATTR_EVENTMASK" },
	{ WS_OVS_CT_ATTR_TIMEOUT,	"OVS_CT_ATTR_TIMEOUT" },
	{ 0, NULL }
};

static const value_string ws_ovs_nat_attr_vals[] = {
	{ WS_OVS_NAT_ATTR_UNSPEC,	"OVS_NAT_ATTR_UNSPEC" },
	{ WS_OVS_NAT_ATTR_SRC,		"OVS_NAT_ATTR_SRC" },
	{ WS_OVS_NAT_ATTR_DST,		"OVS_NAT_ATTR_DST" },
	{ WS_OVS_NAT_ATTR_IP_MIN,	"OVS_NAT_ATTR_IP_MIN" },
	{ WS_OVS_NAT_ATTR_IP_MAX,	"OVS_NAT_ATTR_IP_MAX" },
	{ WS_OVS_NAT_ATTR_PROTO_MIN,	"OVS_NAT_ATTR_PROTO_MIN" },
	{ WS_OVS_NAT_ATTR_PROTO_MAX,	"OVS_NAT_ATTR_PROTO_MAX" },
	{ WS_OVS_NAT_ATTR_PERSISTENT,	"OVS_NAT_ATTR_PERSISTENT" },
	{ WS_OVS_NAT_ATTR_PROTO_HASH,	"OVS_NAT_ATTR_PROTO_HASH" },
	{ WS_OVS_NAT_ATTR_PROTO_RANDOM,"OVS_NAT_ATTR_PROTO_RANDOM" },
	{ 0, NULL }
};

struct netlink_ovs_flow_info {
	packet_info *pinfo;
};

static dissector_handle_t netlink_ovs_flow_handle;

static int proto_netlink_ovs_flow;

/* Header fields */
static int hf_ovs_flow_commands;
static int hf_ovs_flow_dp_ifindex;
static int hf_ovs_flow_attr;
static int hf_ovs_flow_key_attr;
static int hf_ovs_flow_action_attr;
static int hf_ovs_flow_tunnel_key_attr;
static int hf_ovs_flow_userspace_attr;
static int hf_ovs_flow_sample_attr;
static int hf_ovs_flow_ct_attr;
static int hf_ovs_flow_nat_attr;

/* Flow attribute fields */
static int hf_ovs_flow_stats_n_packets;
static int hf_ovs_flow_stats_n_bytes;
static int hf_ovs_flow_tcp_flags;
static int hf_ovs_flow_used;
static int hf_ovs_flow_ufid;
static int hf_ovs_flow_ufid_flags;

/* Key fields */
static int hf_ovs_flow_key_priority;
static int hf_ovs_flow_key_in_port;
static int hf_ovs_flow_key_eth_src;
static int hf_ovs_flow_key_eth_dst;
static int hf_ovs_flow_key_vlan_tci;
static int hf_ovs_flow_key_ethertype;
static int hf_ovs_flow_key_ipv4_src;
static int hf_ovs_flow_key_ipv4_dst;
static int hf_ovs_flow_key_ipv4_proto;
static int hf_ovs_flow_key_ipv4_tos;
static int hf_ovs_flow_key_ipv4_ttl;
static int hf_ovs_flow_key_ipv4_frag;
static int hf_ovs_flow_key_ipv6_src;
static int hf_ovs_flow_key_ipv6_dst;
static int hf_ovs_flow_key_ipv6_label;
static int hf_ovs_flow_key_ipv6_proto;
static int hf_ovs_flow_key_ipv6_tclass;
static int hf_ovs_flow_key_ipv6_hlimit;
static int hf_ovs_flow_key_ipv6_frag;
static int hf_ovs_flow_key_tcp_src;
static int hf_ovs_flow_key_tcp_dst;
static int hf_ovs_flow_key_udp_src;
static int hf_ovs_flow_key_udp_dst;
static int hf_ovs_flow_key_sctp_src;
static int hf_ovs_flow_key_sctp_dst;
static int hf_ovs_flow_key_icmp_type;
static int hf_ovs_flow_key_icmp_code;
static int hf_ovs_flow_key_icmpv6_type;
static int hf_ovs_flow_key_icmpv6_code;
static int hf_ovs_flow_key_arp_sip;
static int hf_ovs_flow_key_arp_tip;
static int hf_ovs_flow_key_arp_op;
static int hf_ovs_flow_key_arp_sha;
static int hf_ovs_flow_key_arp_tha;
static int hf_ovs_flow_key_nd_target;
static int hf_ovs_flow_key_nd_sll;
static int hf_ovs_flow_key_nd_tll;
static int hf_ovs_flow_key_skb_mark;
static int hf_ovs_flow_key_tcp_flags_value;
static int hf_ovs_flow_key_dp_hash;
static int hf_ovs_flow_key_recirc_id;
static int hf_ovs_flow_key_mpls_lse;
static int hf_ovs_flow_key_ct_state;
static int hf_ovs_flow_key_ct_zone;
static int hf_ovs_flow_key_ct_mark;
static int hf_ovs_flow_key_ct_labels;
static int hf_ovs_flow_key_packet_type;
static int hf_ovs_flow_key_ipv6_exthdrs;

/* Tunnel key fields */
static int hf_ovs_flow_tunnel_id;
static int hf_ovs_flow_tunnel_ipv4_src;
static int hf_ovs_flow_tunnel_ipv4_dst;
static int hf_ovs_flow_tunnel_tos;
static int hf_ovs_flow_tunnel_ttl;
static int hf_ovs_flow_tunnel_tp_src;
static int hf_ovs_flow_tunnel_tp_dst;
static int hf_ovs_flow_tunnel_geneve_opts;
static int hf_ovs_flow_tunnel_erspan_opts;
static int hf_ovs_flow_tunnel_ipv6_src;
static int hf_ovs_flow_tunnel_ipv6_dst;

/* Action fields */
static int hf_ovs_flow_action_output;
static int hf_ovs_flow_action_recirc;
static int hf_ovs_flow_action_hash_alg;
static int hf_ovs_flow_action_hash_basis;
static int hf_ovs_flow_action_push_vlan_tpid;
static int hf_ovs_flow_action_push_vlan_tci;
static int hf_ovs_flow_action_push_mpls_lse;
static int hf_ovs_flow_action_push_mpls_etype;
static int hf_ovs_flow_action_pop_mpls_etype;
static int hf_ovs_flow_action_trunc_max_len;
static int hf_ovs_flow_action_push_eth_src;
static int hf_ovs_flow_action_push_eth_dst;
static int hf_ovs_flow_action_meter;
static int hf_ovs_flow_action_drop;

/* Userspace action fields */
static int hf_ovs_flow_userspace_pid;
static int hf_ovs_flow_userspace_userdata;
static int hf_ovs_flow_userspace_egress_tun_port;

/* Sample action fields */
static int hf_ovs_flow_sample_probability;

/* CT action fields */
static int hf_ovs_flow_ct_zone;
static int hf_ovs_flow_ct_mark;
static int hf_ovs_flow_ct_labels;
static int hf_ovs_flow_ct_helper;
static int hf_ovs_flow_ct_eventmask;
static int hf_ovs_flow_ct_timeout;

/* NAT action fields */
static int hf_ovs_flow_nat_ip_min;
static int hf_ovs_flow_nat_ip_max;
static int hf_ovs_flow_nat_proto_min;
static int hf_ovs_flow_nat_proto_max;

/* Subtrees */
static int ett_ovs_flow;
static int ett_ovs_flow_attrs;
static int ett_ovs_flow_key_attrs;
static int ett_ovs_flow_action_attrs;
static int ett_ovs_flow_tunnel_key_attrs;
static int ett_ovs_flow_key_ethernet;
static int ett_ovs_flow_key_ipv4;
static int ett_ovs_flow_key_ipv6;
static int ett_ovs_flow_key_tcp;
static int ett_ovs_flow_key_udp;
static int ett_ovs_flow_key_sctp;
static int ett_ovs_flow_key_icmp;
static int ett_ovs_flow_key_icmpv6;
static int ett_ovs_flow_key_arp;
static int ett_ovs_flow_key_nd;
static int ett_ovs_flow_stats;
static int ett_ovs_flow_action_hash;
static int ett_ovs_flow_action_push_vlan;
static int ett_ovs_flow_action_push_mpls;
static int ett_ovs_flow_action_push_eth;
static int ett_ovs_flow_userspace_attrs;
static int ett_ovs_flow_sample_attrs;
static int ett_ovs_flow_ct_attrs;
static int ett_ovs_flow_nat_attrs;
static int ett_ovs_flow_ct_tuple;

/* Forward declarations */
static int dissect_ovs_flow_action_attrs(tvbuff_t *tvb, void *data,
	struct packet_netlink_data *nl_data, proto_tree *tree,
	int nla_type, int offset, int len);

static int
dissect_ovs_flow_tunnel_key_attrs(tvbuff_t *tvb, void *data _U_,
	struct packet_netlink_data *nl_data _U_, proto_tree *tree,
	int nla_type, int offset, int len)
{
	enum ws_ovs_tunnel_key_attr type =
		(enum ws_ovs_tunnel_key_attr) nla_type;

	switch (type) {
	case WS_OVS_TUNNEL_KEY_ATTR_ID:
		proto_tree_add_item(tree, hf_ovs_flow_tunnel_id, tvb,
			offset, 8, ENC_BIG_ENDIAN);
		return 1;
	case WS_OVS_TUNNEL_KEY_ATTR_IPV4_SRC:
		proto_tree_add_item(tree, hf_ovs_flow_tunnel_ipv4_src, tvb,
			offset, 4, ENC_BIG_ENDIAN);
		return 1;
	case WS_OVS_TUNNEL_KEY_ATTR_IPV4_DST:
		proto_tree_add_item(tree, hf_ovs_flow_tunnel_ipv4_dst, tvb,
			offset, 4, ENC_BIG_ENDIAN);
		return 1;
	case WS_OVS_TUNNEL_KEY_ATTR_TOS:
		proto_tree_add_item(tree, hf_ovs_flow_tunnel_tos, tvb,
			offset, 1, ENC_NA);
		return 1;
	case WS_OVS_TUNNEL_KEY_ATTR_TTL:
		proto_tree_add_item(tree, hf_ovs_flow_tunnel_ttl, tvb,
			offset, 1, ENC_NA);
		return 1;
	case WS_OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT:
	case WS_OVS_TUNNEL_KEY_ATTR_CSUM:
	case WS_OVS_TUNNEL_KEY_ATTR_OAM:
	case WS_OVS_TUNNEL_KEY_ATTR_IPV4_INFO_BRIDGE:
		/* Flag attributes, no payload */
		return 1;
	case WS_OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS:
		proto_tree_add_item(tree, hf_ovs_flow_tunnel_geneve_opts,
			tvb, offset, len, ENC_NA);
		return 1;
	case WS_OVS_TUNNEL_KEY_ATTR_TP_SRC:
		proto_tree_add_item(tree, hf_ovs_flow_tunnel_tp_src, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		return 1;
	case WS_OVS_TUNNEL_KEY_ATTR_TP_DST:
		proto_tree_add_item(tree, hf_ovs_flow_tunnel_tp_dst, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		return 1;
	case WS_OVS_TUNNEL_KEY_ATTR_IPV6_SRC:
		proto_tree_add_item(tree, hf_ovs_flow_tunnel_ipv6_src, tvb,
			offset, 16, ENC_NA);
		return 1;
	case WS_OVS_TUNNEL_KEY_ATTR_IPV6_DST:
		proto_tree_add_item(tree, hf_ovs_flow_tunnel_ipv6_dst, tvb,
			offset, 16, ENC_NA);
		return 1;
	case WS_OVS_TUNNEL_KEY_ATTR_ERSPAN_OPTS:
		proto_tree_add_item(tree, hf_ovs_flow_tunnel_erspan_opts,
			tvb, offset, len, ENC_NA);
		return 1;
	default:
		return 0;
	}
}

static int
dissect_ovs_flow_key_attrs(tvbuff_t *tvb, void *data,
	struct packet_netlink_data *nl_data, proto_tree *tree,
	int nla_type, int offset, int len)
{
	enum ws_ovs_key_attr type = (enum ws_ovs_key_attr) nla_type;
	proto_item *pi;
	proto_tree *ptree;

	switch (type) {
	case WS_OVS_KEY_ATTR_ENCAP:
		return dissect_netlink_attributes(tvb,
			hf_ovs_flow_key_attr, ett_ovs_flow_key_attrs,
			data, nl_data, tree, offset, len,
			dissect_ovs_flow_key_attrs);

	case WS_OVS_KEY_ATTR_PRIORITY:
		proto_tree_add_item(tree, hf_ovs_flow_key_priority, tvb,
			offset, 4, nl_data->encoding);
		return 1;

	case WS_OVS_KEY_ATTR_IN_PORT:
		proto_tree_add_item(tree, hf_ovs_flow_key_in_port, tvb,
			offset, 4, nl_data->encoding);
		return 1;

	case WS_OVS_KEY_ATTR_ETHERNET:
		/* struct ovs_key_ethernet: eth_src(6) + eth_dst(6) = 12 */
		if (len == 12) {
			ptree = proto_tree_add_subtree(tree, tvb, offset, len,
				ett_ovs_flow_key_ethernet, &pi, "Ethernet");
			proto_tree_add_item(ptree, hf_ovs_flow_key_eth_src,
				tvb, offset, 6, ENC_NA);
			proto_tree_add_item(ptree, hf_ovs_flow_key_eth_dst,
				tvb, offset + 6, 6, ENC_NA);
		}
		return 1;

	case WS_OVS_KEY_ATTR_VLAN:
		proto_tree_add_item(tree, hf_ovs_flow_key_vlan_tci, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		return 1;

	case WS_OVS_KEY_ATTR_ETHERTYPE:
		proto_tree_add_item(tree, hf_ovs_flow_key_ethertype, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		return 1;

	case WS_OVS_KEY_ATTR_IPV4:
		/* struct ovs_key_ipv4: src(4)+dst(4)+proto(1)+tos(1)+
		 * ttl(1)+frag(1) = 12 */
		if (len == 12) {
			int off = offset;
			ptree = proto_tree_add_subtree(tree, tvb, offset, len,
				ett_ovs_flow_key_ipv4, &pi, "IPv4");
			proto_tree_add_item(ptree, hf_ovs_flow_key_ipv4_src,
				tvb, off, 4, ENC_BIG_ENDIAN);
			off += 4;
			proto_tree_add_item(ptree, hf_ovs_flow_key_ipv4_dst,
				tvb, off, 4, ENC_BIG_ENDIAN);
			off += 4;
			proto_tree_add_item(ptree, hf_ovs_flow_key_ipv4_proto,
				tvb, off, 1, ENC_NA);
			off += 1;
			proto_tree_add_item(ptree, hf_ovs_flow_key_ipv4_tos,
				tvb, off, 1, ENC_NA);
			off += 1;
			proto_tree_add_item(ptree, hf_ovs_flow_key_ipv4_ttl,
				tvb, off, 1, ENC_NA);
			off += 1;
			proto_tree_add_item(ptree, hf_ovs_flow_key_ipv4_frag,
				tvb, off, 1, ENC_NA);
		}
		return 1;

	case WS_OVS_KEY_ATTR_IPV6:
		/* struct ovs_key_ipv6: src(16)+dst(16)+label(4)+proto(1)+
		 * tclass(1)+hlimit(1)+frag(1) = 40 */
		if (len == 40) {
			int off = offset;
			ptree = proto_tree_add_subtree(tree, tvb, offset, len,
				ett_ovs_flow_key_ipv6, &pi, "IPv6");
			proto_tree_add_item(ptree, hf_ovs_flow_key_ipv6_src,
				tvb, off, 16, ENC_NA);
			off += 16;
			proto_tree_add_item(ptree, hf_ovs_flow_key_ipv6_dst,
				tvb, off, 16, ENC_NA);
			off += 16;
			proto_tree_add_item(ptree, hf_ovs_flow_key_ipv6_label,
				tvb, off, 4, ENC_BIG_ENDIAN);
			off += 4;
			proto_tree_add_item(ptree, hf_ovs_flow_key_ipv6_proto,
				tvb, off, 1, ENC_NA);
			off += 1;
			proto_tree_add_item(ptree, hf_ovs_flow_key_ipv6_tclass,
				tvb, off, 1, ENC_NA);
			off += 1;
			proto_tree_add_item(ptree, hf_ovs_flow_key_ipv6_hlimit,
				tvb, off, 1, ENC_NA);
			off += 1;
			proto_tree_add_item(ptree, hf_ovs_flow_key_ipv6_frag,
				tvb, off, 1, ENC_NA);
		}
		return 1;

	case WS_OVS_KEY_ATTR_TCP:
		if (len == 4) {
			ptree = proto_tree_add_subtree(tree, tvb, offset, len,
				ett_ovs_flow_key_tcp, &pi, "TCP");
			proto_tree_add_item(ptree, hf_ovs_flow_key_tcp_src,
				tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(ptree, hf_ovs_flow_key_tcp_dst,
				tvb, offset + 2, 2, ENC_BIG_ENDIAN);
		}
		return 1;

	case WS_OVS_KEY_ATTR_UDP:
		if (len == 4) {
			ptree = proto_tree_add_subtree(tree, tvb, offset, len,
				ett_ovs_flow_key_udp, &pi, "UDP");
			proto_tree_add_item(ptree, hf_ovs_flow_key_udp_src,
				tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(ptree, hf_ovs_flow_key_udp_dst,
				tvb, offset + 2, 2, ENC_BIG_ENDIAN);
		}
		return 1;

	case WS_OVS_KEY_ATTR_ICMP:
		if (len == 2) {
			ptree = proto_tree_add_subtree(tree, tvb, offset, len,
				ett_ovs_flow_key_icmp, &pi, "ICMP");
			proto_tree_add_item(ptree, hf_ovs_flow_key_icmp_type,
				tvb, offset, 1, ENC_NA);
			proto_tree_add_item(ptree, hf_ovs_flow_key_icmp_code,
				tvb, offset + 1, 1, ENC_NA);
		}
		return 1;

	case WS_OVS_KEY_ATTR_ICMPV6:
		if (len == 2) {
			ptree = proto_tree_add_subtree(tree, tvb, offset, len,
				ett_ovs_flow_key_icmpv6, &pi, "ICMPv6");
			proto_tree_add_item(ptree, hf_ovs_flow_key_icmpv6_type,
				tvb, offset, 1, ENC_NA);
			proto_tree_add_item(ptree, hf_ovs_flow_key_icmpv6_code,
				tvb, offset + 1, 1, ENC_NA);
		}
		return 1;

	case WS_OVS_KEY_ATTR_ARP:
		/* struct ovs_key_arp: sip(4)+tip(4)+op(2)+sha(6)+tha(6)=22 */
		if (len >= 22) {
			int off = offset;
			ptree = proto_tree_add_subtree(tree, tvb, offset, len,
				ett_ovs_flow_key_arp, &pi, "ARP");
			proto_tree_add_item(ptree, hf_ovs_flow_key_arp_sip,
				tvb, off, 4, ENC_BIG_ENDIAN);
			off += 4;
			proto_tree_add_item(ptree, hf_ovs_flow_key_arp_tip,
				tvb, off, 4, ENC_BIG_ENDIAN);
			off += 4;
			proto_tree_add_item(ptree, hf_ovs_flow_key_arp_op,
				tvb, off, 2, ENC_BIG_ENDIAN);
			off += 2;
			proto_tree_add_item(ptree, hf_ovs_flow_key_arp_sha,
				tvb, off, 6, ENC_NA);
			off += 6;
			proto_tree_add_item(ptree, hf_ovs_flow_key_arp_tha,
				tvb, off, 6, ENC_NA);
		}
		return 1;

	case WS_OVS_KEY_ATTR_ND:
		/* struct ovs_key_nd: target(16)+sll(6)+tll(6)=28 */
		if (len >= 28) {
			int off = offset;
			ptree = proto_tree_add_subtree(tree, tvb, offset, len,
				ett_ovs_flow_key_nd, &pi, "Neighbor Discovery");
			proto_tree_add_item(ptree, hf_ovs_flow_key_nd_target,
				tvb, off, 16, ENC_NA);
			off += 16;
			proto_tree_add_item(ptree, hf_ovs_flow_key_nd_sll,
				tvb, off, 6, ENC_NA);
			off += 6;
			proto_tree_add_item(ptree, hf_ovs_flow_key_nd_tll,
				tvb, off, 6, ENC_NA);
		}
		return 1;

	case WS_OVS_KEY_ATTR_SKB_MARK:
		proto_tree_add_item(tree, hf_ovs_flow_key_skb_mark, tvb,
			offset, 4, nl_data->encoding);
		return 1;

	case WS_OVS_KEY_ATTR_TUNNEL:
		return dissect_netlink_attributes(tvb,
			hf_ovs_flow_tunnel_key_attr,
			ett_ovs_flow_tunnel_key_attrs, data, nl_data,
			tree, offset, len,
			dissect_ovs_flow_tunnel_key_attrs);

	case WS_OVS_KEY_ATTR_SCTP:
		if (len == 4) {
			ptree = proto_tree_add_subtree(tree, tvb, offset, len,
				ett_ovs_flow_key_sctp, &pi, "SCTP");
			proto_tree_add_item(ptree, hf_ovs_flow_key_sctp_src,
				tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(ptree, hf_ovs_flow_key_sctp_dst,
				tvb, offset + 2, 2, ENC_BIG_ENDIAN);
		}
		return 1;

	case WS_OVS_KEY_ATTR_TCP_FLAGS:
		proto_tree_add_item(tree, hf_ovs_flow_key_tcp_flags_value,
			tvb, offset, 2, ENC_BIG_ENDIAN);
		return 1;

	case WS_OVS_KEY_ATTR_DP_HASH:
		proto_tree_add_item(tree, hf_ovs_flow_key_dp_hash, tvb,
			offset, 4, nl_data->encoding);
		return 1;

	case WS_OVS_KEY_ATTR_RECIRC_ID:
		proto_tree_add_item(tree, hf_ovs_flow_key_recirc_id, tvb,
			offset, 4, nl_data->encoding);
		return 1;

	case WS_OVS_KEY_ATTR_MPLS:
		{
			int i;
			for (i = 0; i + 4 <= len; i += 4) {
				proto_tree_add_item(tree,
					hf_ovs_flow_key_mpls_lse, tvb,
					offset + i, 4, ENC_BIG_ENDIAN);
			}
		}
		return 1;

	case WS_OVS_KEY_ATTR_CT_STATE:
		proto_tree_add_item(tree, hf_ovs_flow_key_ct_state, tvb,
			offset, 4, nl_data->encoding);
		return 1;

	case WS_OVS_KEY_ATTR_CT_ZONE:
		proto_tree_add_item(tree, hf_ovs_flow_key_ct_zone, tvb,
			offset, 2, nl_data->encoding);
		return 1;

	case WS_OVS_KEY_ATTR_CT_MARK:
		proto_tree_add_item(tree, hf_ovs_flow_key_ct_mark, tvb,
			offset, 4, nl_data->encoding);
		return 1;

	case WS_OVS_KEY_ATTR_CT_LABELS:
		proto_tree_add_item(tree, hf_ovs_flow_key_ct_labels, tvb,
			offset, len, ENC_NA);
		return 1;

	case WS_OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4:
		/* struct ovs_key_ct_tuple_ipv4: src(4)+dst(4)+
		 * sport(2)+dport(2)+proto(1) = 13 */
		if (len >= 13) {
			int off = offset;
			ptree = proto_tree_add_subtree(tree, tvb, offset, len,
				ett_ovs_flow_ct_tuple, &pi, "CT Original Tuple IPv4");
			proto_tree_add_item(ptree, hf_ovs_flow_key_ipv4_src,
				tvb, off, 4, ENC_BIG_ENDIAN);
			off += 4;
			proto_tree_add_item(ptree, hf_ovs_flow_key_ipv4_dst,
				tvb, off, 4, ENC_BIG_ENDIAN);
			off += 4;
			proto_tree_add_item(ptree, hf_ovs_flow_key_tcp_src,
				tvb, off, 2, ENC_BIG_ENDIAN);
			off += 2;
			proto_tree_add_item(ptree, hf_ovs_flow_key_tcp_dst,
				tvb, off, 2, ENC_BIG_ENDIAN);
			off += 2;
			proto_tree_add_item(ptree, hf_ovs_flow_key_ipv4_proto,
				tvb, off, 1, ENC_NA);
		}
		return 1;

	case WS_OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6:
		/* struct ovs_key_ct_tuple_ipv6: src(16)+dst(16)+
		 * sport(2)+dport(2)+proto(1) = 37 */
		if (len >= 37) {
			int off = offset;
			ptree = proto_tree_add_subtree(tree, tvb, offset, len,
				ett_ovs_flow_ct_tuple, &pi, "CT Original Tuple IPv6");
			proto_tree_add_item(ptree, hf_ovs_flow_key_ipv6_src,
				tvb, off, 16, ENC_NA);
			off += 16;
			proto_tree_add_item(ptree, hf_ovs_flow_key_ipv6_dst,
				tvb, off, 16, ENC_NA);
			off += 16;
			proto_tree_add_item(ptree, hf_ovs_flow_key_tcp_src,
				tvb, off, 2, ENC_BIG_ENDIAN);
			off += 2;
			proto_tree_add_item(ptree, hf_ovs_flow_key_tcp_dst,
				tvb, off, 2, ENC_BIG_ENDIAN);
			off += 2;
			proto_tree_add_item(ptree, hf_ovs_flow_key_ipv6_proto,
				tvb, off, 1, ENC_NA);
		}
		return 1;

	case WS_OVS_KEY_ATTR_PACKET_TYPE:
		proto_tree_add_item(tree, hf_ovs_flow_key_packet_type, tvb,
			offset, 4, ENC_BIG_ENDIAN);
		return 1;

	case WS_OVS_KEY_ATTR_IPV6_EXTHDRS:
		proto_tree_add_item(tree, hf_ovs_flow_key_ipv6_exthdrs, tvb,
			offset, 2, nl_data->encoding);
		return 1;

	default:
		return 0;
	}
}

static int
dissect_ovs_flow_nat_attrs(tvbuff_t *tvb, void *data _U_,
	struct packet_netlink_data *nl_data _U_, proto_tree *tree,
	int nla_type, int offset, int len)
{
	enum ws_ovs_nat_attr type = (enum ws_ovs_nat_attr) nla_type;

	switch (type) {
	case WS_OVS_NAT_ATTR_SRC:
	case WS_OVS_NAT_ATTR_DST:
	case WS_OVS_NAT_ATTR_PERSISTENT:
	case WS_OVS_NAT_ATTR_PROTO_HASH:
	case WS_OVS_NAT_ATTR_PROTO_RANDOM:
		/* Flag attributes */
		return 1;
	case WS_OVS_NAT_ATTR_IP_MIN:
		proto_tree_add_item(tree, hf_ovs_flow_nat_ip_min, tvb,
			offset, len, ENC_NA);
		return 1;
	case WS_OVS_NAT_ATTR_IP_MAX:
		proto_tree_add_item(tree, hf_ovs_flow_nat_ip_max, tvb,
			offset, len, ENC_NA);
		return 1;
	case WS_OVS_NAT_ATTR_PROTO_MIN:
		proto_tree_add_item(tree, hf_ovs_flow_nat_proto_min, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		return 1;
	case WS_OVS_NAT_ATTR_PROTO_MAX:
		proto_tree_add_item(tree, hf_ovs_flow_nat_proto_max, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		return 1;
	default:
		return 0;
	}
}

static int
dissect_ovs_flow_ct_action_attrs(tvbuff_t *tvb, void *data,
	struct packet_netlink_data *nl_data, proto_tree *tree,
	int nla_type, int offset, int len)
{
	enum ws_ovs_ct_attr type = (enum ws_ovs_ct_attr) nla_type;
	const uint8_t *str;

	switch (type) {
	case WS_OVS_CT_ATTR_COMMIT:
	case WS_OVS_CT_ATTR_FORCE_COMMIT:
		/* Flag attributes */
		return 1;
	case WS_OVS_CT_ATTR_ZONE:
		proto_tree_add_item(tree, hf_ovs_flow_ct_zone, tvb,
			offset, 2, nl_data->encoding);
		return 1;
	case WS_OVS_CT_ATTR_MARK:
		proto_tree_add_item(tree, hf_ovs_flow_ct_mark, tvb,
			offset, len, ENC_NA);
		return 1;
	case WS_OVS_CT_ATTR_LABELS:
		proto_tree_add_item(tree, hf_ovs_flow_ct_labels, tvb,
			offset, len, ENC_NA);
		return 1;
	case WS_OVS_CT_ATTR_HELPER:
		{
			struct netlink_ovs_flow_info *info =
				(struct netlink_ovs_flow_info *) data;
			DISSECTOR_ASSERT(info);
			proto_tree_add_item_ret_string(tree,
				hf_ovs_flow_ct_helper, tvb, offset, len,
				ENC_ASCII | ENC_NA,
				info->pinfo->pool, &str);
			proto_item_append_text(tree, ": %s", str);
		}
		return 1;
	case WS_OVS_CT_ATTR_NAT:
		return dissect_netlink_attributes(tvb,
			hf_ovs_flow_nat_attr, ett_ovs_flow_nat_attrs,
			data, nl_data, tree, offset, len,
			dissect_ovs_flow_nat_attrs);
	case WS_OVS_CT_ATTR_EVENTMASK:
		proto_tree_add_item(tree, hf_ovs_flow_ct_eventmask, tvb,
			offset, 4, nl_data->encoding);
		return 1;
	case WS_OVS_CT_ATTR_TIMEOUT:
		{
			struct netlink_ovs_flow_info *info =
				(struct netlink_ovs_flow_info *) data;
			DISSECTOR_ASSERT(info);
			proto_tree_add_item_ret_string(tree,
				hf_ovs_flow_ct_timeout, tvb, offset, len,
				ENC_ASCII | ENC_NA,
				info->pinfo->pool, &str);
			proto_item_append_text(tree, ": %s", str);
		}
		return 1;
	default:
		return 0;
	}
}

static int
dissect_ovs_flow_userspace_attrs(tvbuff_t *tvb, void *data _U_,
	struct packet_netlink_data *nl_data, proto_tree *tree,
	int nla_type, int offset, int len)
{
	enum ws_ovs_userspace_attr type =
		(enum ws_ovs_userspace_attr) nla_type;

	switch (type) {
	case WS_OVS_USERSPACE_ATTR_PID:
		proto_tree_add_item(tree, hf_ovs_flow_userspace_pid, tvb,
			offset, 4, nl_data->encoding);
		return 1;
	case WS_OVS_USERSPACE_ATTR_USERDATA:
		proto_tree_add_item(tree, hf_ovs_flow_userspace_userdata,
			tvb, offset, len, ENC_NA);
		return 1;
	case WS_OVS_USERSPACE_ATTR_EGRESS_TUN_PORT:
		proto_tree_add_item(tree,
			hf_ovs_flow_userspace_egress_tun_port,
			tvb, offset, 4, nl_data->encoding);
		return 1;
	case WS_OVS_USERSPACE_ATTR_ACTIONS:
		/* Flag attribute */
		return 1;
	default:
		return 0;
	}
}

static int
dissect_ovs_flow_sample_attrs(tvbuff_t *tvb, void *data,
	struct packet_netlink_data *nl_data, proto_tree *tree,
	int nla_type, int offset, int len)
{
	enum ws_ovs_sample_attr type = (enum ws_ovs_sample_attr) nla_type;

	switch (type) {
	case WS_OVS_SAMPLE_ATTR_PROBABILITY:
		proto_tree_add_item(tree, hf_ovs_flow_sample_probability,
			tvb, offset, 4, nl_data->encoding);
		return 1;
	case WS_OVS_SAMPLE_ATTR_ACTIONS:
		return dissect_netlink_attributes(tvb,
			hf_ovs_flow_action_attr, ett_ovs_flow_action_attrs,
			data, nl_data, tree, offset, len,
			dissect_ovs_flow_action_attrs);
	default:
		return 0;
	}
}

static int
dissect_ovs_flow_action_attrs(tvbuff_t *tvb, void *data,
	struct packet_netlink_data *nl_data, proto_tree *tree,
	int nla_type, int offset, int len)
{
	enum ws_ovs_action_attr type = (enum ws_ovs_action_attr) nla_type;
	uint32_t value;
	proto_item *pi;
	proto_tree *ptree;

	switch (type) {
	case WS_OVS_ACTION_ATTR_OUTPUT:
		proto_tree_add_item_ret_uint(tree, hf_ovs_flow_action_output,
			tvb, offset, 4, nl_data->encoding, &value);
		proto_item_append_text(tree, ": %u", value);
		return 1;

	case WS_OVS_ACTION_ATTR_USERSPACE:
		return dissect_netlink_attributes(tvb,
			hf_ovs_flow_userspace_attr,
			ett_ovs_flow_userspace_attrs, data, nl_data,
			tree, offset, len,
			dissect_ovs_flow_userspace_attrs);

	case WS_OVS_ACTION_ATTR_SET:
	case WS_OVS_ACTION_ATTR_SET_MASKED:
		return dissect_netlink_attributes(tvb,
			hf_ovs_flow_key_attr, ett_ovs_flow_key_attrs,
			data, nl_data, tree, offset, len,
			dissect_ovs_flow_key_attrs);

	case WS_OVS_ACTION_ATTR_PUSH_VLAN:
		/* struct ovs_action_push_vlan: tpid(2)+tci(2)=4 */
		if (len == 4) {
			ptree = proto_tree_add_subtree(tree, tvb, offset, len,
				ett_ovs_flow_action_push_vlan, &pi, "Push VLAN");
			proto_tree_add_item(ptree,
				hf_ovs_flow_action_push_vlan_tpid,
				tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(ptree,
				hf_ovs_flow_action_push_vlan_tci,
				tvb, offset + 2, 2, ENC_BIG_ENDIAN);
		}
		return 1;

	case WS_OVS_ACTION_ATTR_POP_VLAN:
	case WS_OVS_ACTION_ATTR_POP_ETH:
	case WS_OVS_ACTION_ATTR_CT_CLEAR:
	case WS_OVS_ACTION_ATTR_POP_NSH:
		/* No payload */
		return 1;

	case WS_OVS_ACTION_ATTR_SAMPLE:
		return dissect_netlink_attributes(tvb,
			hf_ovs_flow_sample_attr,
			ett_ovs_flow_sample_attrs, data, nl_data,
			tree, offset, len,
			dissect_ovs_flow_sample_attrs);

	case WS_OVS_ACTION_ATTR_RECIRC:
		proto_tree_add_item_ret_uint(tree,
			hf_ovs_flow_action_recirc, tvb, offset, 4,
			nl_data->encoding, &value);
		proto_item_append_text(tree, ": %u", value);
		return 1;

	case WS_OVS_ACTION_ATTR_HASH:
		/* struct ovs_action_hash: alg(4)+basis(4)=8 */
		if (len == 8) {
			ptree = proto_tree_add_subtree(tree, tvb, offset, len,
				ett_ovs_flow_action_hash, &pi, "Hash");
			proto_tree_add_item(ptree,
				hf_ovs_flow_action_hash_alg,
				tvb, offset, 4, nl_data->encoding);
			proto_tree_add_item(ptree,
				hf_ovs_flow_action_hash_basis,
				tvb, offset + 4, 4, nl_data->encoding);
		}
		return 1;

	case WS_OVS_ACTION_ATTR_PUSH_MPLS:
		/* struct ovs_action_push_mpls: lse(4)+etype(2)=6 */
		if (len >= 6) {
			ptree = proto_tree_add_subtree(tree, tvb, offset, len,
				ett_ovs_flow_action_push_mpls, &pi, "Push MPLS");
			proto_tree_add_item(ptree,
				hf_ovs_flow_action_push_mpls_lse,
				tvb, offset, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(ptree,
				hf_ovs_flow_action_push_mpls_etype,
				tvb, offset + 4, 2, ENC_BIG_ENDIAN);
		}
		return 1;

	case WS_OVS_ACTION_ATTR_POP_MPLS:
		proto_tree_add_item(tree,
			hf_ovs_flow_action_pop_mpls_etype, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		return 1;

	case WS_OVS_ACTION_ATTR_CT:
		return dissect_netlink_attributes(tvb,
			hf_ovs_flow_ct_attr, ett_ovs_flow_ct_attrs,
			data, nl_data, tree, offset, len,
			dissect_ovs_flow_ct_action_attrs);

	case WS_OVS_ACTION_ATTR_TRUNC:
		proto_tree_add_item_ret_uint(tree,
			hf_ovs_flow_action_trunc_max_len, tvb,
			offset, 4, nl_data->encoding, &value);
		proto_item_append_text(tree, ": %u", value);
		return 1;

	case WS_OVS_ACTION_ATTR_PUSH_ETH:
		/* struct ovs_action_push_eth contains ovs_key_ethernet */
		if (len == 12) {
			ptree = proto_tree_add_subtree(tree, tvb, offset, len,
				ett_ovs_flow_action_push_eth, &pi, "Push Ethernet");
			proto_tree_add_item(ptree,
				hf_ovs_flow_action_push_eth_src,
				tvb, offset, 6, ENC_NA);
			proto_tree_add_item(ptree,
				hf_ovs_flow_action_push_eth_dst,
				tvb, offset + 6, 6, ENC_NA);
		}
		return 1;

	case WS_OVS_ACTION_ATTR_METER:
		proto_tree_add_item_ret_uint(tree,
			hf_ovs_flow_action_meter, tvb, offset, 4,
			nl_data->encoding, &value);
		proto_item_append_text(tree, ": %u", value);
		return 1;

	case WS_OVS_ACTION_ATTR_CLONE:
		/* Nested actions */
		return dissect_netlink_attributes(tvb,
			hf_ovs_flow_action_attr, ett_ovs_flow_action_attrs,
			data, nl_data, tree, offset, len,
			dissect_ovs_flow_action_attrs);

	case WS_OVS_ACTION_ATTR_DROP:
		proto_tree_add_item_ret_uint(tree,
			hf_ovs_flow_action_drop, tvb, offset, 4,
			nl_data->encoding, &value);
		proto_item_append_text(tree, ": %u", value);
		return 1;

	default:
		return 0;
	}
}

static int
dissect_ovs_flow_attrs(tvbuff_t *tvb, void *data,
	struct packet_netlink_data *nl_data, proto_tree *tree,
	int nla_type, int offset, int len)
{
	enum ws_ovs_flow_attr type = (enum ws_ovs_flow_attr) nla_type;
	proto_item *pi;
	proto_tree *ptree;

	switch (type) {
	case WS_OVS_FLOW_ATTR_KEY:
	case WS_OVS_FLOW_ATTR_MASK:
		return dissect_netlink_attributes(tvb,
			hf_ovs_flow_key_attr, ett_ovs_flow_key_attrs,
			data, nl_data, tree, offset, len,
			dissect_ovs_flow_key_attrs);

	case WS_OVS_FLOW_ATTR_ACTIONS:
		return dissect_netlink_attributes(tvb,
			hf_ovs_flow_action_attr, ett_ovs_flow_action_attrs,
			data, nl_data, tree, offset, len,
			dissect_ovs_flow_action_attrs);

	case WS_OVS_FLOW_ATTR_STATS:
		/* struct ovs_flow_stats: n_packets(u64)+n_bytes(u64) = 16 */
		if (len == 16) {
			ptree = proto_tree_add_subtree(tree, tvb, offset,
				len, ett_ovs_flow_stats, &pi, "Flow Statistics");
			proto_tree_add_item(ptree,
				hf_ovs_flow_stats_n_packets, tvb,
				offset, 8, nl_data->encoding);
			proto_tree_add_item(ptree,
				hf_ovs_flow_stats_n_bytes, tvb,
				offset + 8, 8, nl_data->encoding);
			return 1;
		}
		return 0;

	case WS_OVS_FLOW_ATTR_TCP_FLAGS:
		proto_tree_add_item(tree, hf_ovs_flow_tcp_flags, tvb,
			offset, 1, ENC_NA);
		return 1;

	case WS_OVS_FLOW_ATTR_USED:
		proto_tree_add_item(tree, hf_ovs_flow_used, tvb,
			offset, 8, nl_data->encoding);
		return 1;

	case WS_OVS_FLOW_ATTR_CLEAR:
	case WS_OVS_FLOW_ATTR_PROBE:
		/* Flag attributes */
		return 1;

	case WS_OVS_FLOW_ATTR_UFID:
		proto_tree_add_item(tree, hf_ovs_flow_ufid, tvb,
			offset, len, ENC_NA);
		return 1;

	case WS_OVS_FLOW_ATTR_UFID_FLAGS:
		proto_tree_add_item(tree, hf_ovs_flow_ufid_flags, tvb,
			offset, 4, nl_data->encoding);
		return 1;

	default:
		return 0;
	}
}

static int
dissect_netlink_ovs_flow(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, void *data)
{
	genl_info_t *genl_info = (genl_info_t *) data;
	proto_tree *nlmsg_tree;
	proto_item *pi;
	int offset;

	DISSECTOR_ASSERT(genl_info);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ovs_flow");
	col_clear(pinfo->cinfo, COL_INFO);

	offset = dissect_genl_header(tvb, genl_info, genl_info->nl_data,
		hf_ovs_flow_commands);

	if (tvb_reported_length_remaining(tvb, offset) < 4)
		return offset;

	pi = proto_tree_add_item(tree, proto_netlink_ovs_flow, tvb, offset,
		-1, ENC_NA);
	nlmsg_tree = proto_item_add_subtree(pi, ett_ovs_flow);

	proto_tree_add_item(nlmsg_tree, hf_ovs_flow_dp_ifindex, tvb, offset,
		4, genl_info->nl_data->encoding);
	offset += 4;

	if (!tvb_reported_length_remaining(tvb, offset))
		return offset;

	{
		struct netlink_ovs_flow_info info;
		info.pinfo = pinfo;
		dissect_netlink_attributes_to_end(tvb, hf_ovs_flow_attr,
			ett_ovs_flow_attrs, &info, genl_info->nl_data,
			nlmsg_tree, offset, dissect_ovs_flow_attrs);
	}

	return offset;
}

/* ------------------------------------------------------------------ */
/* Public wrappers -- used by ovs_packet to decode upcall payloads    */
/* ------------------------------------------------------------------ */

int
ovs_flow_dissect_key(tvbuff_t *tvb, packet_info *pinfo,
	struct packet_netlink_data *nl_data, proto_tree *tree,
	int offset, int len)
{
	struct netlink_ovs_flow_info info = { .pinfo = pinfo };
	return dissect_netlink_attributes(tvb,
		hf_ovs_flow_key_attr, ett_ovs_flow_key_attrs,
		&info, nl_data, tree, offset, len,
		dissect_ovs_flow_key_attrs);
}

int
ovs_flow_dissect_actions(tvbuff_t *tvb, packet_info *pinfo,
	struct packet_netlink_data *nl_data, proto_tree *tree,
	int offset, int len)
{
	struct netlink_ovs_flow_info info = { .pinfo = pinfo };
	return dissect_netlink_attributes(tvb,
		hf_ovs_flow_action_attr, ett_ovs_flow_action_attrs,
		&info, nl_data, tree, offset, len,
		dissect_ovs_flow_action_attrs);
}

int
ovs_flow_dissect_tunnel_key(tvbuff_t *tvb, packet_info *pinfo,
	struct packet_netlink_data *nl_data, proto_tree *tree,
	int offset, int len)
{
	struct netlink_ovs_flow_info info = { .pinfo = pinfo };
	return dissect_netlink_attributes(tvb,
		hf_ovs_flow_tunnel_key_attr, ett_ovs_flow_tunnel_key_attrs,
		&info, nl_data, tree, offset, len,
		dissect_ovs_flow_tunnel_key_attrs);
}

void
proto_register_netlink_ovs_flow(void)
{
	static hf_register_info hf[] = {
		{ &hf_ovs_flow_commands,
			{ "Command", "ovs_flow.cmd",
			  FT_UINT8, BASE_DEC,
			  VALS(ws_ovs_flow_commands_vals), 0x00,
			  NULL, HFILL }
		},
		{ &hf_ovs_flow_dp_ifindex,
			{ "Datapath ifindex", "ovs_flow.dp_ifindex",
			  FT_INT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_attr,
			{ "Attribute type", "ovs_flow.attr_type",
			  FT_UINT16, BASE_DEC,
			  VALS(ws_ovs_flow_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_ovs_flow_key_attr,
			{ "Key attribute type", "ovs_flow.key.attr_type",
			  FT_UINT16, BASE_DEC,
			  VALS(ws_ovs_key_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_ovs_flow_action_attr,
			{ "Action attribute type",
			  "ovs_flow.action.attr_type",
			  FT_UINT16, BASE_DEC,
			  VALS(ws_ovs_action_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_ovs_flow_tunnel_key_attr,
			{ "Tunnel key attribute type",
			  "ovs_flow.tunnel_key.attr_type",
			  FT_UINT16, BASE_DEC,
			  VALS(ws_ovs_tunnel_key_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_ovs_flow_userspace_attr,
			{ "Userspace attribute type",
			  "ovs_flow.userspace.attr_type",
			  FT_UINT16, BASE_DEC,
			  VALS(ws_ovs_userspace_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_ovs_flow_sample_attr,
			{ "Sample attribute type",
			  "ovs_flow.sample.attr_type",
			  FT_UINT16, BASE_DEC,
			  VALS(ws_ovs_sample_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_ovs_flow_ct_attr,
			{ "CT attribute type", "ovs_flow.ct.attr_type",
			  FT_UINT16, BASE_DEC,
			  VALS(ws_ovs_ct_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_ovs_flow_nat_attr,
			{ "NAT attribute type", "ovs_flow.nat.attr_type",
			  FT_UINT16, BASE_DEC,
			  VALS(ws_ovs_nat_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		/* Flow attribute fields */
		{ &hf_ovs_flow_stats_n_packets,
			{ "Packets", "ovs_flow.stats.n_packets",
			  FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_stats_n_bytes,
			{ "Bytes", "ovs_flow.stats.n_bytes",
			  FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_tcp_flags,
			{ "TCP flags", "ovs_flow.tcp_flags",
			  FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_used,
			{ "Last used (ms)", "ovs_flow.used",
			  FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_ufid,
			{ "Unique flow ID", "ovs_flow.ufid",
			  FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_ufid_flags,
			{ "UFID flags", "ovs_flow.ufid_flags",
			  FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		/* Key fields */
		{ &hf_ovs_flow_key_priority,
			{ "Priority", "ovs_flow.key.priority",
			  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_in_port,
			{ "Input port", "ovs_flow.key.in_port",
			  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_eth_src,
			{ "Ethernet source", "ovs_flow.key.eth_src",
			  FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_eth_dst,
			{ "Ethernet destination", "ovs_flow.key.eth_dst",
			  FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_vlan_tci,
			{ "VLAN TCI", "ovs_flow.key.vlan_tci",
			  FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_ethertype,
			{ "Ethertype", "ovs_flow.key.ethertype",
			  FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_ipv4_src,
			{ "IPv4 source", "ovs_flow.key.ipv4_src",
			  FT_IPv4, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_ipv4_dst,
			{ "IPv4 destination", "ovs_flow.key.ipv4_dst",
			  FT_IPv4, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_ipv4_proto,
			{ "IP protocol", "ovs_flow.key.ipv4_proto",
			  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_ipv4_tos,
			{ "IP ToS", "ovs_flow.key.ipv4_tos",
			  FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_ipv4_ttl,
			{ "IP TTL", "ovs_flow.key.ipv4_ttl",
			  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_ipv4_frag,
			{ "IP fragment type", "ovs_flow.key.ipv4_frag",
			  FT_UINT8, BASE_DEC,
			  VALS(ws_ovs_frag_type_vals), 0x00,
			  NULL, HFILL }
		},
		{ &hf_ovs_flow_key_ipv6_src,
			{ "IPv6 source", "ovs_flow.key.ipv6_src",
			  FT_IPv6, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_ipv6_dst,
			{ "IPv6 destination", "ovs_flow.key.ipv6_dst",
			  FT_IPv6, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_ipv6_label,
			{ "IPv6 flow label", "ovs_flow.key.ipv6_label",
			  FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_ipv6_proto,
			{ "IPv6 next header", "ovs_flow.key.ipv6_proto",
			  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_ipv6_tclass,
			{ "IPv6 traffic class", "ovs_flow.key.ipv6_tclass",
			  FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_ipv6_hlimit,
			{ "IPv6 hop limit", "ovs_flow.key.ipv6_hlimit",
			  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_ipv6_frag,
			{ "IPv6 fragment type", "ovs_flow.key.ipv6_frag",
			  FT_UINT8, BASE_DEC,
			  VALS(ws_ovs_frag_type_vals), 0x00,
			  NULL, HFILL }
		},
		{ &hf_ovs_flow_key_tcp_src,
			{ "TCP source port", "ovs_flow.key.tcp_src",
			  FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_tcp_dst,
			{ "TCP destination port", "ovs_flow.key.tcp_dst",
			  FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_udp_src,
			{ "UDP source port", "ovs_flow.key.udp_src",
			  FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_udp_dst,
			{ "UDP destination port", "ovs_flow.key.udp_dst",
			  FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_sctp_src,
			{ "SCTP source port", "ovs_flow.key.sctp_src",
			  FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_sctp_dst,
			{ "SCTP destination port", "ovs_flow.key.sctp_dst",
			  FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_icmp_type,
			{ "ICMP type", "ovs_flow.key.icmp_type",
			  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_icmp_code,
			{ "ICMP code", "ovs_flow.key.icmp_code",
			  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_icmpv6_type,
			{ "ICMPv6 type", "ovs_flow.key.icmpv6_type",
			  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_icmpv6_code,
			{ "ICMPv6 code", "ovs_flow.key.icmpv6_code",
			  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_arp_sip,
			{ "ARP source IP", "ovs_flow.key.arp_sip",
			  FT_IPv4, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_arp_tip,
			{ "ARP target IP", "ovs_flow.key.arp_tip",
			  FT_IPv4, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_arp_op,
			{ "ARP opcode", "ovs_flow.key.arp_op",
			  FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_arp_sha,
			{ "ARP source hardware address",
			  "ovs_flow.key.arp_sha",
			  FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_arp_tha,
			{ "ARP target hardware address",
			  "ovs_flow.key.arp_tha",
			  FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_nd_target,
			{ "ND target", "ovs_flow.key.nd_target",
			  FT_IPv6, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_nd_sll,
			{ "ND source link-layer address",
			  "ovs_flow.key.nd_sll",
			  FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_nd_tll,
			{ "ND target link-layer address",
			  "ovs_flow.key.nd_tll",
			  FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_skb_mark,
			{ "SKB mark", "ovs_flow.key.skb_mark",
			  FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_tcp_flags_value,
			{ "TCP flags", "ovs_flow.key.tcp_flags",
			  FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_dp_hash,
			{ "Datapath hash", "ovs_flow.key.dp_hash",
			  FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_recirc_id,
			{ "Recirculation ID", "ovs_flow.key.recirc_id",
			  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_mpls_lse,
			{ "MPLS label stack entry",
			  "ovs_flow.key.mpls_lse",
			  FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_ct_state,
			{ "CT state", "ovs_flow.key.ct_state",
			  FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_ct_zone,
			{ "CT zone", "ovs_flow.key.ct_zone",
			  FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_ct_mark,
			{ "CT mark", "ovs_flow.key.ct_mark",
			  FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_ct_labels,
			{ "CT labels", "ovs_flow.key.ct_labels",
			  FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_packet_type,
			{ "Packet type", "ovs_flow.key.packet_type",
			  FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_key_ipv6_exthdrs,
			{ "IPv6 extension headers",
			  "ovs_flow.key.ipv6_exthdrs",
			  FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		/* Tunnel key fields */
		{ &hf_ovs_flow_tunnel_id,
			{ "Tunnel ID", "ovs_flow.tunnel.id",
			  FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_tunnel_ipv4_src,
			{ "Tunnel IPv4 source", "ovs_flow.tunnel.ipv4_src",
			  FT_IPv4, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_tunnel_ipv4_dst,
			{ "Tunnel IPv4 destination",
			  "ovs_flow.tunnel.ipv4_dst",
			  FT_IPv4, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_tunnel_tos,
			{ "Tunnel ToS", "ovs_flow.tunnel.tos",
			  FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_tunnel_ttl,
			{ "Tunnel TTL", "ovs_flow.tunnel.ttl",
			  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_tunnel_tp_src,
			{ "Tunnel transport source port",
			  "ovs_flow.tunnel.tp_src",
			  FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_tunnel_tp_dst,
			{ "Tunnel transport destination port",
			  "ovs_flow.tunnel.tp_dst",
			  FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_tunnel_geneve_opts,
			{ "Geneve options", "ovs_flow.tunnel.geneve_opts",
			  FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_tunnel_erspan_opts,
			{ "ERSPAN options", "ovs_flow.tunnel.erspan_opts",
			  FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_tunnel_ipv6_src,
			{ "Tunnel IPv6 source", "ovs_flow.tunnel.ipv6_src",
			  FT_IPv6, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_tunnel_ipv6_dst,
			{ "Tunnel IPv6 destination",
			  "ovs_flow.tunnel.ipv6_dst",
			  FT_IPv6, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		/* Action fields */
		{ &hf_ovs_flow_action_output,
			{ "Output port", "ovs_flow.action.output",
			  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_action_recirc,
			{ "Recirculation ID", "ovs_flow.action.recirc",
			  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_action_hash_alg,
			{ "Hash algorithm", "ovs_flow.action.hash_alg",
			  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_action_hash_basis,
			{ "Hash basis", "ovs_flow.action.hash_basis",
			  FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_action_push_vlan_tpid,
			{ "VLAN TPID", "ovs_flow.action.push_vlan.tpid",
			  FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_action_push_vlan_tci,
			{ "VLAN TCI", "ovs_flow.action.push_vlan.tci",
			  FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_action_push_mpls_lse,
			{ "MPLS label stack entry",
			  "ovs_flow.action.push_mpls.lse",
			  FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_action_push_mpls_etype,
			{ "MPLS ethertype",
			  "ovs_flow.action.push_mpls.ethertype",
			  FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_action_pop_mpls_etype,
			{ "MPLS ethertype",
			  "ovs_flow.action.pop_mpls.ethertype",
			  FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_action_trunc_max_len,
			{ "Truncation max length",
			  "ovs_flow.action.trunc.max_len",
			  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_action_push_eth_src,
			{ "Ethernet source",
			  "ovs_flow.action.push_eth.src",
			  FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_action_push_eth_dst,
			{ "Ethernet destination",
			  "ovs_flow.action.push_eth.dst",
			  FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_action_meter,
			{ "Meter ID", "ovs_flow.action.meter",
			  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_action_drop,
			{ "Drop error code", "ovs_flow.action.drop",
			  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		/* Userspace action fields */
		{ &hf_ovs_flow_userspace_pid,
			{ "Userspace PID", "ovs_flow.userspace.pid",
			  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_userspace_userdata,
			{ "Userspace data", "ovs_flow.userspace.userdata",
			  FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_userspace_egress_tun_port,
			{ "Egress tunnel port",
			  "ovs_flow.userspace.egress_tun_port",
			  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		/* Sample action fields */
		{ &hf_ovs_flow_sample_probability,
			{ "Sample probability",
			  "ovs_flow.sample.probability",
			  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		/* CT action fields */
		{ &hf_ovs_flow_ct_zone,
			{ "CT zone", "ovs_flow.ct.zone",
			  FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_ct_mark,
			{ "CT mark", "ovs_flow.ct.mark",
			  FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_ct_labels,
			{ "CT labels", "ovs_flow.ct.labels",
			  FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_ct_helper,
			{ "CT helper", "ovs_flow.ct.helper",
			  FT_STRINGZ, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_ct_eventmask,
			{ "CT event mask", "ovs_flow.ct.eventmask",
			  FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_ct_timeout,
			{ "CT timeout", "ovs_flow.ct.timeout",
			  FT_STRINGZ, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		/* NAT action fields */
		{ &hf_ovs_flow_nat_ip_min,
			{ "NAT IP min", "ovs_flow.nat.ip_min",
			  FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_nat_ip_max,
			{ "NAT IP max", "ovs_flow.nat.ip_max",
			  FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_nat_proto_min,
			{ "NAT port min", "ovs_flow.nat.proto_min",
			  FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_flow_nat_proto_max,
			{ "NAT port max", "ovs_flow.nat.proto_max",
			  FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
	};

	static int *ett[] = {
		&ett_ovs_flow,
		&ett_ovs_flow_attrs,
		&ett_ovs_flow_key_attrs,
		&ett_ovs_flow_action_attrs,
		&ett_ovs_flow_tunnel_key_attrs,
		&ett_ovs_flow_key_ethernet,
		&ett_ovs_flow_key_ipv4,
		&ett_ovs_flow_key_ipv6,
		&ett_ovs_flow_key_tcp,
		&ett_ovs_flow_key_udp,
		&ett_ovs_flow_key_sctp,
		&ett_ovs_flow_key_icmp,
		&ett_ovs_flow_key_icmpv6,
		&ett_ovs_flow_key_arp,
		&ett_ovs_flow_key_nd,
		&ett_ovs_flow_stats,
		&ett_ovs_flow_action_hash,
		&ett_ovs_flow_action_push_vlan,
		&ett_ovs_flow_action_push_mpls,
		&ett_ovs_flow_action_push_eth,
		&ett_ovs_flow_userspace_attrs,
		&ett_ovs_flow_sample_attrs,
		&ett_ovs_flow_ct_attrs,
		&ett_ovs_flow_nat_attrs,
		&ett_ovs_flow_ct_tuple,
	};

	proto_netlink_ovs_flow = proto_register_protocol(
		"Linux ovs_flow (Open vSwitch Flow) protocol",
		"ovs_flow", "ovs_flow");
	proto_register_field_array(proto_netlink_ovs_flow, hf,
		array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	netlink_ovs_flow_handle = register_dissector("ovs_flow",
		dissect_netlink_ovs_flow, proto_netlink_ovs_flow);
}

void
proto_reg_handoff_netlink_ovs_flow(void)
{
	dissector_add_string("genl.family", "ovs_flow",
		netlink_ovs_flow_handle);
}

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
