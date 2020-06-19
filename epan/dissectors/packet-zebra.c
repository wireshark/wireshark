/* packet-zebra.c
 * Routines for zebra packet disassembly
 *
 * Jochen Friedrich <jochen@scram.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * The Zebra Protocol is the protocol used between the Zebra routing daemon and other
 * protocol daemons (ones for BGP, OSPF, etc.) within the Zebra and Quagga open-source
 * routing suites. Zebra itself (https://www.gnu.org/software/zebra) is discontinued,
 * and its successor is Quagga (http://www.nongnu.org/quagga).
 *
 * Both Zebra and Quagga use a "Zebra Protocol", but starting with Quagga v0.99 the
 * Zebra Protocol has changed, with a different header format and more commands/types.
 * Quagga 0.99.0 was version 1, and 0.99.20 or so changed it to version 2.
 *
 * See http://www.nongnu.org/quagga/docs/docs-info.html#Zebra-Protocol for some details.
 *
 * Quagga 0.99.24 changed to Zebra Protocol version 3.
 * FRRouting version 2 and 3 use Zebra Protocol version 4
 * FRRouting version 4 and 5 use Zebra Protocol version 5
 * FRRouting version 4 and 5 have incompatible commands partialy.
 * This file use commands of FRRRouting version 5.
 * FRRouting version 6 and 7 use Zebra Protocol version 6
 * FRRouting version 6 and 7 have incompatible commands partialy.
 * This file use commands of FRRRouting version 7.
 */

#include "config.h"


#include <epan/packet.h>

/*  Function declarations */
void proto_reg_handoff_zebra(void);
void proto_register_zebra(void);

static int proto_zebra = -1;
static int hf_zebra_len = -1;
static int hf_zebra_command = -1;
static int hf_zebra_request = -1;
static int hf_zebra_interface = -1;
static int hf_zebra_index = -1;
static int hf_zebra_indexnum = -1;
static int hf_zebra_type_v0 = -1;
static int hf_zebra_type_v1 = -1;
static int hf_zebra_intflags = -1;
static int hf_zebra_rtflags = -1;
static int hf_zebra_distance = -1;
static int hf_zebra_metric = -1;
static int hf_zebra_mtu = -1;
static int hf_zebra_mtu6 = -1;
static int hf_zebra_bandwidth = -1;
static int hf_zebra_family = -1;
static int hf_zebra_flags = -1;
static int hf_zebra_message = -1;
static int hf_zebra_route_safi = -1;
static int hf_zebra_msg_nexthop = -1;
static int hf_zebra_msg_index = -1;
static int hf_zebra_msg_distance = -1;
static int hf_zebra_msg_metric = -1;
static int hf_zebra_nexthopnum = -1;
static int hf_zebra_nexthop4 = -1;
static int hf_zebra_nexthop6 = -1;
static int hf_zebra_dest4 = -1;
static int hf_zebra_dest6 = -1;
static int hf_zebra_prefixlen = -1;
static int hf_zebra_prefix4 = -1;
static int hf_zebra_prefix6 = -1;
static int hf_zebra_version = -1;
static int hf_zebra_marker = -1;
static int hf_zebra_intstatus = -1;
static int hf_zebra_routeridaddress = -1;
static int hf_zebra_routeridmask = -1;
static int hf_zebra_mac = -1;
static int hf_zebra_redist_default = -1;
static int hf_zebra_vrfid = -1;
static int hf_zebra_routeridfamily = -1;
static int hf_zebra_nexthoptype = -1;
static int hf_zebra_msg_mtu = -1;
static int hf_zebra_msg_tag = -1;
static int hf_zebra_tag = -1;
static int hf_zebra_maclen = -1;
static int hf_zebra_haslinkparam = -1;
/* FRRouting, Zebra API v4, v5 and v6 */
static int hf_zebra_command_v4 = -1;
static int hf_zebra_command_v5 = -1;
static int hf_zebra_command_v6 = -1;
static int hf_zebra_type_v4 = -1;
static int hf_zebra_type_v5 = -1;
static int hf_zebra_ptmenable = -1;
static int hf_zebra_ptmstatus = -1;
static int hf_zebra_instance = -1;
static int hf_zebra_rtflags_u32 = -1;
static int hf_zebra_speed = -1;
static int hf_zebra_lltype = -1;
static int hf_zebra_message4 = -1;
static int hf_zebra_message5 = -1;
static int hf_zebra_route_safi_u8 = -1;
static int hf_zebra_rmac = -1;
static int hf_zebra_msg4_tag = -1;
static int hf_zebra_msg4_mtu = -1;
static int hf_zebra_msg4_srcpfx = -1;
static int hf_zebra_msg5_distance = -1;
static int hf_zebra_msg5_metric = -1;
static int hf_zebra_msg5_tag = -1;
static int hf_zebra_msg5_mtu = -1;
static int hf_zebra_msg5_srcpfx = -1;
static int hf_zebra_msg_label = -1;
static int hf_zebra_msg_tableid = -1;
static int hf_zebra_nexthopnum_u16 = -1;
static int hf_zebra_nexthoptype_frr = -1;
static int hf_zebra_bhtype = -1;
static int hf_zebra_srcprefixlen = -1;
static int hf_zebra_srcprefix4 = -1;
static int hf_zebra_srcprefix6 = -1;
static int hf_zebra_tableid = -1;
static int hf_zebra_afi = -1;
static int hf_zebra_pid = -1;
static int hf_zebra_vrf_table_id = -1;
static int hf_zebra_vrf_netns_name = -1;
static int hf_zebra_vrf_name = -1;
static int hf_zebra_proto = -1;
static int hf_zebra_label_chunk_keep = -1;
static int hf_zebra_label_chunk_size = -1;
static int hf_zebra_label_chunk_start = -1;
static int hf_zebra_label_chunk_end = -1;
static int hf_zebra_mpls_enabled = -1;
static int hf_zebra_multipath_num = -1;
static int hf_zebra_labelnum = -1;
static int hf_zebra_label = -1;
static int hf_zebra_receive_notify = -1;

static gint ett_zebra = -1;
static gint ett_zebra_request = -1;
static gint ett_message = -1;

#define TCP_PORT_ZEBRA			2600 /* Not IANA registered */

/* Zebra message types. */
#define ZEBRA_INTERFACE_ADD                1
#define ZEBRA_INTERFACE_DELETE             2
#define ZEBRA_INTERFACE_ADDRESS_ADD        3
#define ZEBRA_INTERFACE_ADDRESS_DELETE     4
#define ZEBRA_INTERFACE_UP                 5
#define ZEBRA_INTERFACE_DOWN               6
#define ZEBRA_IPV4_ROUTE_ADD               7
#define ZEBRA_IPV4_ROUTE_DELETE            8
#define ZEBRA_IPV6_ROUTE_ADD               9
#define ZEBRA_IPV6_ROUTE_DELETE           10
#define ZEBRA_REDISTRIBUTE_ADD            11
#define ZEBRA_REDISTRIBUTE_DELETE         12
#define ZEBRA_REDISTRIBUTE_DEFAULT_ADD    13
#define ZEBRA_REDISTRIBUTE_DEFAULT_DELETE 14
#define ZEBRA_IPV4_NEXTHOP_LOOKUP         15
#define ZEBRA_IPV6_NEXTHOP_LOOKUP         16
#define ZEBRA_IPV4_IMPORT_LOOKUP          17
#define ZEBRA_IPV6_IMPORT_LOOKUP          18
#define ZEBRA_INTERFACE_RENAME            19
#define ZEBRA_ROUTER_ID_ADD               20
#define ZEBRA_ROUTER_ID_DELETE            21
#define ZEBRA_ROUTER_ID_UPDATE            22
#define ZEBRA_HELLO                       23
#define ZEBRA_IPV4_NEXTHOP_LOOKUP_MRIB    24
#define ZEBRA_VRF_UNREGISTER              25
#define ZEBRA_INTERFACE_LINK_PARAMS       26
#define ZEBRA_NEXTHOP_REGISTER            27
#define ZEBRA_NEXTHOP_UNREGISTER          28
#define ZEBRA_NEXTHOP_UPDATE              29
#define ZEBRA_MESSAGE_MAX                 30


static const value_string messages[] = {
	{ ZEBRA_INTERFACE_ADD,			"Add Interface" },
	{ ZEBRA_INTERFACE_DELETE,		"Delete Interface" },
	{ ZEBRA_INTERFACE_ADDRESS_ADD,		"Add Interface Address" },
	{ ZEBRA_INTERFACE_ADDRESS_DELETE,	"Delete Interface Address" },
	{ ZEBRA_INTERFACE_UP,			"Interface Up" },
	{ ZEBRA_INTERFACE_DOWN,			"Interface Down" },
	{ ZEBRA_IPV4_ROUTE_ADD,			"Add IPv4 Route" },
	{ ZEBRA_IPV4_ROUTE_DELETE,		"Delete IPv4 Route" },
	{ ZEBRA_IPV6_ROUTE_ADD,			"Add IPv6 Route" },
	{ ZEBRA_IPV6_ROUTE_DELETE,		"Delete IPv6 Route" },
	{ ZEBRA_REDISTRIBUTE_ADD,		"Add Redistribute" },
	{ ZEBRA_REDISTRIBUTE_DELETE,		"Delete Redistribute" },
	{ ZEBRA_REDISTRIBUTE_DEFAULT_ADD,	"Add Default Redistribute" },
	{ ZEBRA_REDISTRIBUTE_DEFAULT_DELETE,	"Delete Default Redistribute" },
	{ ZEBRA_IPV4_NEXTHOP_LOOKUP,		"IPv4 Nexthop Lookup" },
	{ ZEBRA_IPV6_NEXTHOP_LOOKUP,		"IPv6 Nexthop Lookup" },
	{ ZEBRA_IPV4_IMPORT_LOOKUP,		"IPv4 Import Lookup" },
	{ ZEBRA_IPV6_IMPORT_LOOKUP,		"IPv6 Import Lookup" },
	{ ZEBRA_INTERFACE_RENAME,		"Rename Interface" },
	{ ZEBRA_ROUTER_ID_ADD,			"Router ID Add" },
	{ ZEBRA_ROUTER_ID_DELETE,		"Router ID Delete" },
	{ ZEBRA_ROUTER_ID_UPDATE,		"Router ID Update" },
	{ ZEBRA_HELLO,				"Hello" },
	{ ZEBRA_IPV4_NEXTHOP_LOOKUP_MRIB,	"IPv4 Nexthop Lookup Multicast RIB" },
	{ ZEBRA_VRF_UNREGISTER,			"VRF Unregister" },
	{ ZEBRA_INTERFACE_LINK_PARAMS,		"Interface Link Paameters" },
	{ ZEBRA_NEXTHOP_REGISTER,		"Nexthop Register" },
	{ ZEBRA_NEXTHOP_UNREGISTER,		"Nexthop Unregister" },
	{ ZEBRA_NEXTHOP_UPDATE,			"Nexthop Update" },
	{ 0,					NULL },
};

/* FRRouting ZAPI v4 message types. */
enum {
	FRR_ZAPI4_INTERFACE_ADD,
	FRR_ZAPI4_INTERFACE_DELETE,
	FRR_ZAPI4_INTERFACE_ADDRESS_ADD,
	FRR_ZAPI4_INTERFACE_ADDRESS_DELETE,
	FRR_ZAPI4_INTERFACE_UP,
	FRR_ZAPI4_INTERFACE_DOWN,
	FRR_ZAPI4_IPV4_ROUTE_ADD,
	FRR_ZAPI4_IPV4_ROUTE_DELETE,
	FRR_ZAPI4_IPV6_ROUTE_ADD,
	FRR_ZAPI4_IPV6_ROUTE_DELETE,
	FRR_ZAPI4_REDISTRIBUTE_ADD,
	FRR_ZAPI4_REDISTRIBUTE_DELETE,
	FRR_ZAPI4_REDISTRIBUTE_DEFAULT_ADD,
	FRR_ZAPI4_REDISTRIBUTE_DEFAULT_DELETE,
	FRR_ZAPI4_ROUTER_ID_ADD,
	FRR_ZAPI4_ROUTER_ID_DELETE,
	FRR_ZAPI4_ROUTER_ID_UPDATE,
	FRR_ZAPI4_HELLO,
	FRR_ZAPI4_NEXTHOP_REGISTER,
	FRR_ZAPI4_NEXTHOP_UNREGISTER,
	FRR_ZAPI4_NEXTHOP_UPDATE,
	FRR_ZAPI4_INTERFACE_NBR_ADDRESS_ADD,
	FRR_ZAPI4_INTERFACE_NBR_ADDRESS_DELETE,
	FRR_ZAPI4_INTERFACE_BFD_DEST_UPDATE,
	FRR_ZAPI4_IMPORT_ROUTE_REGISTER,
	FRR_ZAPI4_IMPORT_ROUTE_UNREGISTER,
	FRR_ZAPI4_IMPORT_CHECK_UPDATE,
	FRR_ZAPI4_IPV4_ROUTE_IPV6_NEXTHOP_ADD,
	FRR_ZAPI4_BFD_DEST_REGISTER,
	FRR_ZAPI4_BFD_DEST_DEREGISTER,
	FRR_ZAPI4_BFD_DEST_UPDATE,
	FRR_ZAPI4_BFD_DEST_REPLAY,
	FRR_ZAPI4_REDISTRIBUTE_IPV4_ADD,
	FRR_ZAPI4_REDISTRIBUTE_IPV4_DEL,
	FRR_ZAPI4_REDISTRIBUTE_IPV6_ADD,
	FRR_ZAPI4_REDISTRIBUTE_IPV6_DEL,
	FRR_ZAPI4_VRF_UNREGISTER,
	FRR_ZAPI4_VRF_ADD,
	FRR_ZAPI4_VRF_DELETE,
	FRR_ZAPI4_INTERFACE_VRF_UPDATE,
	FRR_ZAPI4_BFD_CLIENT_REGISTER,
	FRR_ZAPI4_INTERFACE_ENABLE_RADV,
	FRR_ZAPI4_INTERFACE_DISABLE_RADV,
	FRR_ZAPI4_IPV4_NEXTHOP_LOOKUP_MRIB,
	FRR_ZAPI4_INTERFACE_LINK_PARAMS,
	FRR_ZAPI4_MPLS_LABELS_ADD,
	FRR_ZAPI4_MPLS_LABELS_DELETE,
	FRR_ZAPI4_IPV4_NEXTHOP_ADD,
	FRR_ZAPI4_IPV4_NEXTHOP_DELETE,
	FRR_ZAPI4_IPV6_NEXTHOP_ADD,
	FRR_ZAPI4_IPV6_NEXTHOP_DELETE,
	FRR_ZAPI4_IPMR_ROUTE_STATS,
	FRR_ZAPI4_LABEL_MANAGER_CONNECT,
	FRR_ZAPI4_GET_LABEL_CHUNK,
	FRR_ZAPI4_RELEASE_LABEL_CHUNK,
	FRR_ZAPI4_PW_ADD,
	FRR_ZAPI4_PW_DELETE,
	FRR_ZAPI4_PW_SET,
	FRR_ZAPI4_PW_UNSET,
	FRR_ZAPI4_PW_STATUS_UPDATE,
};

static const value_string frr_zapi4_messages[] = {
	{ FRR_ZAPI4_INTERFACE_ADD,		"Add Interface" },
	{ FRR_ZAPI4_INTERFACE_DELETE,		"Delete Interface" },
	{ FRR_ZAPI4_INTERFACE_ADDRESS_ADD,	"Add Interface Address" },
	{ FRR_ZAPI4_INTERFACE_ADDRESS_DELETE,	"Delete Interface Address" },
	{ FRR_ZAPI4_INTERFACE_UP,		"Interface Up" },
	{ FRR_ZAPI4_INTERFACE_DOWN,		"Interface Down" },
	{ FRR_ZAPI4_IPV4_ROUTE_ADD,		"Add IPv4 Route" },
	{ FRR_ZAPI4_IPV4_ROUTE_DELETE,		"Delete IPv4 Route" },
	{ FRR_ZAPI4_IPV6_ROUTE_ADD,		"Add IPv6 Route" },
	{ FRR_ZAPI4_IPV6_ROUTE_DELETE,		"Delete IPv6 Route" },
	{ FRR_ZAPI4_REDISTRIBUTE_ADD,		"Add Redistribute" },
	{ FRR_ZAPI4_REDISTRIBUTE_DELETE,	"Delete Redistribute" },
	{ FRR_ZAPI4_REDISTRIBUTE_DEFAULT_ADD,	"Add Default Redistribute" },
	{ FRR_ZAPI4_REDISTRIBUTE_DEFAULT_DELETE,"Delete Default Redistribute" },
	{ FRR_ZAPI4_ROUTER_ID_ADD,		"Router ID Add" },
	{ FRR_ZAPI4_ROUTER_ID_DELETE,		"Router ID Delete" },
	{ FRR_ZAPI4_ROUTER_ID_UPDATE,		"Router ID Update" },
	{ FRR_ZAPI4_HELLO,			"Hello" },
	{ FRR_ZAPI4_NEXTHOP_REGISTER,		"Nexthop Register" },
	{ FRR_ZAPI4_NEXTHOP_UNREGISTER,		"Nexthop Unregister" },
	{ FRR_ZAPI4_NEXTHOP_UPDATE,		"Nexthop Update" },
	{ FRR_ZAPI4_INTERFACE_NBR_ADDRESS_ADD,	"Interface Neighbor Address Add" },
	{ FRR_ZAPI4_INTERFACE_NBR_ADDRESS_DELETE, "Interface Neighbor Address Delete" },
	{ FRR_ZAPI4_INTERFACE_BFD_DEST_UPDATE,	"Interface BFD Destination Update" },
	{ FRR_ZAPI4_IMPORT_ROUTE_REGISTER,	"Import Route Register" },
	{ FRR_ZAPI4_IMPORT_ROUTE_UNREGISTER,	"Import Route Unregister" },
	{ FRR_ZAPI4_IMPORT_CHECK_UPDATE,	"Import Check Update" },
	{ FRR_ZAPI4_IPV4_ROUTE_IPV6_NEXTHOP_ADD,"Add IPv6 nexthop for IPv4 Route" },
	{ FRR_ZAPI4_BFD_DEST_REGISTER,		"BFD Destination Register" },
	{ FRR_ZAPI4_BFD_DEST_DEREGISTER,	"BFD Destination Deregister" },
	{ FRR_ZAPI4_BFD_DEST_UPDATE,		"BFD Destination Update" },
	{ FRR_ZAPI4_BFD_DEST_REPLAY,		"BFD Destination Replay" },
	{ FRR_ZAPI4_REDISTRIBUTE_IPV4_ADD,	"Add Redistribute IPv4 Route" },
	{ FRR_ZAPI4_REDISTRIBUTE_IPV4_DEL,	"Delete Redistribute IPv4 Route" },
	{ FRR_ZAPI4_REDISTRIBUTE_IPV6_ADD,	"Add Redistribute IPv6 Route" },
	{ FRR_ZAPI4_REDISTRIBUTE_IPV6_DEL,	"Delete Redistribute IPv6 Route" },
	{ FRR_ZAPI4_VRF_UNREGISTER,		"VRF Unregister" },
	{ FRR_ZAPI4_VRF_ADD,			"VRF Add" },
	{ FRR_ZAPI4_VRF_DELETE,			"VRF Delete" },
	{ FRR_ZAPI4_INTERFACE_VRF_UPDATE,	"Interface VRF Update" },
	{ FRR_ZAPI4_BFD_CLIENT_REGISTER,	"BFD Client Register" },
	{ FRR_ZAPI4_INTERFACE_ENABLE_RADV,	"Interface Enable Rouer Advertisement" },
	{ FRR_ZAPI4_INTERFACE_DISABLE_RADV,	"Interface Disable Rouer Advertisement" },
	{ FRR_ZAPI4_IPV4_NEXTHOP_LOOKUP_MRIB,	"IPv4 Nexthop Lookup Multicast RIB" },
	{ FRR_ZAPI4_INTERFACE_LINK_PARAMS,	"Interface Link Paameters" },
	{ FRR_ZAPI4_MPLS_LABELS_ADD,		"MPLS Labels Add" },
	{ FRR_ZAPI4_MPLS_LABELS_DELETE,		"MPLS Labels Delete" },
	{ FRR_ZAPI4_IPV4_NEXTHOP_ADD,		"Add IPv4 Nexthop" },
	{ FRR_ZAPI4_IPV4_NEXTHOP_DELETE,	"Delete IPv4 Nexthop" },
	{ FRR_ZAPI4_IPV6_NEXTHOP_ADD,		"Add IPv6 Nexthop" },
	{ FRR_ZAPI4_IPV6_NEXTHOP_DELETE,	"Delete IPv6 Nexthop" },
	{ FRR_ZAPI4_IPMR_ROUTE_STATS,		"IPMR Route Statics" },
	{ FRR_ZAPI4_LABEL_MANAGER_CONNECT,	"Label Manager Connect" },
	{ FRR_ZAPI4_GET_LABEL_CHUNK,		"Get Label Chunk" },
	{ FRR_ZAPI4_RELEASE_LABEL_CHUNK,	"Release Label Chunk" },
	{ FRR_ZAPI4_PW_ADD,			"PseudoWire Add" },
	{ FRR_ZAPI4_PW_DELETE,			"PseudoWire Delete" },
	{ FRR_ZAPI4_PW_SET,			"PseudoWire Set" },
	{ FRR_ZAPI4_PW_UNSET,			"PseudoWire Unset" },
	{ FRR_ZAPI4_PW_STATUS_UPDATE,		"PseudoWire Status Update" },
	{ 0,					NULL },
};

enum {
	FRR_ZAPI5_INTERFACE_ADD,
	FRR_ZAPI5_INTERFACE_DELETE,
	FRR_ZAPI5_INTERFACE_ADDRESS_ADD,
	FRR_ZAPI5_INTERFACE_ADDRESS_DELETE,
	FRR_ZAPI5_INTERFACE_UP,
	FRR_ZAPI5_INTERFACE_DOWN,
	FRR_ZAPI5_INTERFACE_SET_MASTER,
	FRR_ZAPI5_ROUTE_ADD,
	FRR_ZAPI5_ROUTE_DELETE,
	FRR_ZAPI5_ROUTE_NOTIFY_OWNER,
	FRR_ZAPI5_IPV4_ROUTE_ADD,
	FRR_ZAPI5_IPV4_ROUTE_DELETE,
	FRR_ZAPI5_IPV6_ROUTE_ADD,
	FRR_ZAPI5_IPV6_ROUTE_DELETE,
	FRR_ZAPI5_REDISTRIBUTE_ADD,
	FRR_ZAPI5_REDISTRIBUTE_DELETE,
	FRR_ZAPI5_REDISTRIBUTE_DEFAULT_ADD,
	FRR_ZAPI5_REDISTRIBUTE_DEFAULT_DELETE,
	FRR_ZAPI5_ROUTER_ID_ADD,
	FRR_ZAPI5_ROUTER_ID_DELETE,
	FRR_ZAPI5_ROUTER_ID_UPDATE,
	FRR_ZAPI5_HELLO,
	FRR_ZAPI5_CAPABILITIES,
	FRR_ZAPI5_NEXTHOP_REGISTER,
	FRR_ZAPI5_NEXTHOP_UNREGISTER,
	FRR_ZAPI5_NEXTHOP_UPDATE,
	FRR_ZAPI5_INTERFACE_NBR_ADDRESS_ADD,
	FRR_ZAPI5_INTERFACE_NBR_ADDRESS_DELETE,
	FRR_ZAPI5_INTERFACE_BFD_DEST_UPDATE,
	FRR_ZAPI5_IMPORT_ROUTE_REGISTER,
	FRR_ZAPI5_IMPORT_ROUTE_UNREGISTER,
	FRR_ZAPI5_IMPORT_CHECK_UPDATE,
	FRR_ZAPI5_IPV4_ROUTE_IPV6_NEXTHOP_ADD,
	FRR_ZAPI5_BFD_DEST_REGISTER,
	FRR_ZAPI5_BFD_DEST_DEREGISTER,
	FRR_ZAPI5_BFD_DEST_UPDATE,
	FRR_ZAPI5_BFD_DEST_REPLAY,
	FRR_ZAPI5_REDISTRIBUTE_ROUTE_ADD,
	FRR_ZAPI5_REDISTRIBUTE_ROUTE_DEL,
	FRR_ZAPI5_VRF_UNREGISTER,
	FRR_ZAPI5_VRF_ADD,
	FRR_ZAPI5_VRF_DELETE,
	FRR_ZAPI5_VRF_LABEL,
	FRR_ZAPI5_INTERFACE_VRF_UPDATE,
	FRR_ZAPI5_BFD_CLIENT_REGISTER,
	FRR_ZAPI5_INTERFACE_ENABLE_RADV,
	FRR_ZAPI5_INTERFACE_DISABLE_RADV,
	FRR_ZAPI5_IPV4_NEXTHOP_LOOKUP_MRIB,
	FRR_ZAPI5_INTERFACE_LINK_PARAMS,
	FRR_ZAPI5_MPLS_LABELS_ADD,
	FRR_ZAPI5_MPLS_LABELS_DELETE,
	FRR_ZAPI5_IPMR_ROUTE_STATS,
	FRR_ZAPI5_LABEL_MANAGER_CONNECT,
	FRR_ZAPI5_LABEL_MANAGER_CONNECT_ASYNC,
	FRR_ZAPI5_GET_LABEL_CHUNK,
	FRR_ZAPI5_RELEASE_LABEL_CHUNK,
	FRR_ZAPI5_FEC_REGISTER,
	FRR_ZAPI5_FEC_UNREGISTER,
	FRR_ZAPI5_FEC_UPDATE,
	FRR_ZAPI5_ADVERTISE_DEFAULT_GW,
	FRR_ZAPI5_ADVERTISE_SUBNET,
	FRR_ZAPI5_ADVERTISE_ALL_VNI,
	FRR_ZAPI5_VNI_ADD,
	FRR_ZAPI5_VNI_DEL,
	FRR_ZAPI5_L3VNI_ADD,
	FRR_ZAPI5_L3VNI_DEL,
	FRR_ZAPI5_REMOTE_VTEP_ADD,
	FRR_ZAPI5_REMOTE_VTEP_DEL,
	FRR_ZAPI5_MACIP_ADD,
	FRR_ZAPI5_MACIP_DEL,
	FRR_ZAPI5_IP_PREFIX_ROUTE_ADD,
	FRR_ZAPI5_IP_PREFIX_ROUTE_DEL,
	FRR_ZAPI5_REMOTE_MACIP_ADD,
	FRR_ZAPI5_REMOTE_MACIP_DEL,
	FRR_ZAPI5_PW_ADD,
	FRR_ZAPI5_PW_DELETE,
	FRR_ZAPI5_PW_SET,
	FRR_ZAPI5_PW_UNSET,
	FRR_ZAPI5_PW_STATUS_UPDATE,
	FRR_ZAPI5_RULE_ADD,
	FRR_ZAPI5_RULE_DELETE,
	FRR_ZAPI5_RULE_NOTIFY_OWNER,
	FRR_ZAPI5_TABLE_MANAGER_CONNECT,
	FRR_ZAPI5_GET_TABLE_CHUNK,
	FRR_ZAPI5_RELEASE_TABLE_CHUNK,
	FRR_ZAPI5_IPSET_CREATE,
	FRR_ZAPI5_IPSET_DESTROY,
	FRR_ZAPI5_IPSET_ENTRY_ADD,
	FRR_ZAPI5_IPSET_ENTRY_DELETE,
	FRR_ZAPI5_IPSET_NOTIFY_OWNER,
	FRR_ZAPI5_IPSET_ENTRY_NOTIFY_OWNER,
	FRR_ZAPI5_IPTABLE_ADD,
	FRR_ZAPI5_IPTABLE_DELETE,
	FRR_ZAPI5_IPTABLE_NOTIFY_OWNER,
};

static const value_string frr_zapi5_messages[] = {
	{ FRR_ZAPI5_INTERFACE_ADD,		"Add Interface" },
	{ FRR_ZAPI5_INTERFACE_DELETE,		"Delete Interface" },
	{ FRR_ZAPI5_INTERFACE_ADDRESS_ADD,	"Add Interface Address" },
	{ FRR_ZAPI5_INTERFACE_ADDRESS_DELETE,	"Delete Interface Address" },
	{ FRR_ZAPI5_INTERFACE_UP,		"Interface Up" },
	{ FRR_ZAPI5_INTERFACE_DOWN,		"Interface Down" },
	{ FRR_ZAPI5_ROUTE_ADD,			"Add Route" },
	{ FRR_ZAPI5_ROUTE_DELETE,		"Delete Route" },
	{ FRR_ZAPI5_IPV4_ROUTE_ADD,		"Add IPv4 Route" },
	{ FRR_ZAPI5_IPV4_ROUTE_DELETE,		"Delete IPv4 Route" },
	{ FRR_ZAPI5_IPV6_ROUTE_ADD,		"Add IPv6 Route" },
	{ FRR_ZAPI5_IPV6_ROUTE_DELETE,		"Delete IPv6 Route" },
	{ FRR_ZAPI5_REDISTRIBUTE_ADD,		"Add Redistribute" },
	{ FRR_ZAPI5_REDISTRIBUTE_DELETE,	"Delete Redistribute" },
	{ FRR_ZAPI5_REDISTRIBUTE_DEFAULT_ADD,	"Add Default Redistribute" },
	{ FRR_ZAPI5_REDISTRIBUTE_DEFAULT_DELETE,"Delete Default Redistribute" },
	{ FRR_ZAPI5_ROUTER_ID_ADD,		"Router ID Add" },
	{ FRR_ZAPI5_ROUTER_ID_DELETE,		"Router ID Delete" },
	{ FRR_ZAPI5_ROUTER_ID_UPDATE,		"Router ID Update" },
	{ FRR_ZAPI5_HELLO,			"Hello" },
	{ FRR_ZAPI5_CAPABILITIES,		"Capabilities" },
	{ FRR_ZAPI5_NEXTHOP_REGISTER,		"Nexthop Register" },
	{ FRR_ZAPI5_NEXTHOP_UNREGISTER,		"Nexthop Unregister" },
	{ FRR_ZAPI5_NEXTHOP_UPDATE,		"Nexthop Update" },
	{ FRR_ZAPI5_INTERFACE_NBR_ADDRESS_ADD,	"Interface Neighbor Address Add" },
	{ FRR_ZAPI5_INTERFACE_NBR_ADDRESS_DELETE, "Interface Neighbor Address Delete" },
	{ FRR_ZAPI5_INTERFACE_BFD_DEST_UPDATE,	"Interface BFD Destination Update" },
	{ FRR_ZAPI5_IMPORT_ROUTE_REGISTER,	"Import Route Register" },
	{ FRR_ZAPI5_IMPORT_ROUTE_UNREGISTER,	"Import Route Unregister" },
	{ FRR_ZAPI5_IMPORT_CHECK_UPDATE,	"Import Check Update" },
	{ FRR_ZAPI5_IPV4_ROUTE_IPV6_NEXTHOP_ADD,"Add IPv6 nexthop for IPv4 Route" },
	{ FRR_ZAPI5_BFD_DEST_REGISTER,		"BFD Destination Register" },
	{ FRR_ZAPI5_BFD_DEST_DEREGISTER,	"BFD Destination Deregister" },
	{ FRR_ZAPI5_BFD_DEST_UPDATE,		"BFD Destination Update" },
	{ FRR_ZAPI5_BFD_DEST_REPLAY,		"BFD Destination Replay" },
	{ FRR_ZAPI5_REDISTRIBUTE_ROUTE_ADD,	"Add Redistribute Route" },
	{ FRR_ZAPI5_REDISTRIBUTE_ROUTE_DEL,	"Delete Redistribute Route" },
	{ FRR_ZAPI5_VRF_UNREGISTER,		"VRF Unregister" },
	{ FRR_ZAPI5_VRF_ADD,			"VRF Add" },
	{ FRR_ZAPI5_VRF_DELETE,			"VRF Delete" },
	{ FRR_ZAPI5_VRF_LABEL,			"VRF Label" },
	{ FRR_ZAPI5_INTERFACE_VRF_UPDATE,	"Interface VRF Update" },
	{ FRR_ZAPI5_BFD_CLIENT_REGISTER,	"BFD Client Register" },
	{ FRR_ZAPI5_INTERFACE_ENABLE_RADV,	"Interface Enable Rouer Advertisement" },
	{ FRR_ZAPI5_INTERFACE_DISABLE_RADV,	"Interface Disable Rouer Advertisement" },
	{ FRR_ZAPI5_IPV4_NEXTHOP_LOOKUP_MRIB,	"IPv4 Nexthop Lookup Multicast RIB" },
	{ FRR_ZAPI5_INTERFACE_LINK_PARAMS,	"Interface Link Paameters" },
	{ FRR_ZAPI5_MPLS_LABELS_ADD,		"MPLS Labels Add" },
	{ FRR_ZAPI5_MPLS_LABELS_DELETE,		"MPLS Labels Delete" },
	{ FRR_ZAPI5_IPMR_ROUTE_STATS,		"IPMR Route Statics" },
	{ FRR_ZAPI5_LABEL_MANAGER_CONNECT,	"Label Manager Connect" },
	{ FRR_ZAPI5_LABEL_MANAGER_CONNECT_ASYNC,"Label Manager Connect Asynchronous" },
	{ FRR_ZAPI5_GET_LABEL_CHUNK,		"Get Label Chunk" },
	{ FRR_ZAPI5_RELEASE_LABEL_CHUNK,	"Release Label Chunk" },
	{ FRR_ZAPI5_FEC_REGISTER,		"FEC Register" },
	{ FRR_ZAPI5_FEC_UNREGISTER,		"FEC Unregister" },
	{ FRR_ZAPI5_FEC_UPDATE,			"FEC Update" },
	{ FRR_ZAPI5_ADVERTISE_DEFAULT_GW,	"Advertise Deffault Gateway" },
	{ FRR_ZAPI5_ADVERTISE_SUBNET,		"Advertise Subnet" },
	{ FRR_ZAPI5_ADVERTISE_ALL_VNI,		"Advertise all VNI" },
	{ FRR_ZAPI5_VNI_ADD,			"VNI Add" },
	{ FRR_ZAPI5_VNI_DEL,			"VNI Delete" },
	{ FRR_ZAPI5_L3VNI_ADD,			"L3VNI Add" },
	{ FRR_ZAPI5_L3VNI_DEL,			"L3VNI Delete" },
	{ FRR_ZAPI5_REMOTE_VTEP_ADD,		"Remote VTEP Add" },
	{ FRR_ZAPI5_REMOTE_VTEP_DEL,		"Remote VTEP Delete" },
	{ FRR_ZAPI5_MACIP_ADD,			"MAC/IP Add" },
	{ FRR_ZAPI5_MACIP_DEL,			"MAC/IP Dleate" },
	{ FRR_ZAPI5_IP_PREFIX_ROUTE_ADD,	"IP Prefix Route Add" },
	{ FRR_ZAPI5_IP_PREFIX_ROUTE_DEL,	"IP Prefix Route Delete" },
	{ FRR_ZAPI5_REMOTE_MACIP_ADD,		"Remote MAC/IP Add" },
	{ FRR_ZAPI5_REMOTE_MACIP_DEL,		"Remote MAC/IP Delete" },
	{ FRR_ZAPI5_PW_ADD,			"PseudoWire Add" },
	{ FRR_ZAPI5_PW_DELETE,			"PseudoWire Delete" },
	{ FRR_ZAPI5_PW_SET,			"PseudoWire Set" },
	{ FRR_ZAPI5_PW_UNSET,			"PseudoWire Unset" },
	{ FRR_ZAPI5_PW_STATUS_UPDATE,		"PseudoWire Status Update" },
	{ FRR_ZAPI5_RULE_ADD,			"Rule Add" },
	{ FRR_ZAPI5_RULE_DELETE,		"Rule Delete" },
	{ FRR_ZAPI5_RULE_NOTIFY_OWNER,		"Rule Notify Owner" },
	{ FRR_ZAPI5_TABLE_MANAGER_CONNECT,	"Table Manager Connect" },
	{ FRR_ZAPI5_GET_TABLE_CHUNK,		"Get Table Chunk" },
	{ FRR_ZAPI5_RELEASE_TABLE_CHUNK,	"Release Table Chunk" },
	{ FRR_ZAPI5_IPSET_CREATE,		"IPSet Create" },
	{ FRR_ZAPI5_IPSET_DESTROY,		"IPSet Destroy" },
	{ FRR_ZAPI5_IPSET_ENTRY_ADD,		"IPSet Entry Add" },
	{ FRR_ZAPI5_IPSET_ENTRY_DELETE,		"IPSet Entry Delete" },
	{ FRR_ZAPI5_IPSET_NOTIFY_OWNER,		"IPSet Notify Oner" },
	{ FRR_ZAPI5_IPSET_ENTRY_NOTIFY_OWNER,	"IPSet Entry Notify Owner" },
	{ FRR_ZAPI5_IPTABLE_ADD,		"IPTable Add" },
	{ FRR_ZAPI5_IPTABLE_DELETE,		"IPTable Delete" },
	{ FRR_ZAPI5_IPTABLE_NOTIFY_OWNER,	"IPTable Notify Owner" },
	{ 0,					NULL },
};

enum {
	FRR_ZAPI6_INTERFACE_ADD,
	FRR_ZAPI6_INTERFACE_DELETE,
	FRR_ZAPI6_INTERFACE_ADDRESS_ADD,
	FRR_ZAPI6_INTERFACE_ADDRESS_DELETE,
	FRR_ZAPI6_INTERFACE_UP,
	FRR_ZAPI6_INTERFACE_DOWN,
	FRR_ZAPI6_INTERFACE_SET_MASTER,
	FRR_ZAPI6_ROUTE_ADD,
	FRR_ZAPI6_ROUTE_DELETE,
	FRR_ZAPI6_ROUTE_NOTIFY_OWNER,
	FRR_ZAPI6_REDISTRIBUTE_ADD,
	FRR_ZAPI6_REDISTRIBUTE_DELETE,
	FRR_ZAPI6_REDISTRIBUTE_DEFAULT_ADD,
	FRR_ZAPI6_REDISTRIBUTE_DEFAULT_DELETE,
	FRR_ZAPI6_ROUTER_ID_ADD,
	FRR_ZAPI6_ROUTER_ID_DELETE,
	FRR_ZAPI6_ROUTER_ID_UPDATE,
	FRR_ZAPI6_HELLO,
	FRR_ZAPI6_CAPABILITIES,
	FRR_ZAPI6_NEXTHOP_REGISTER,
	FRR_ZAPI6_NEXTHOP_UNREGISTER,
	FRR_ZAPI6_NEXTHOP_UPDATE,
	FRR_ZAPI6_INTERFACE_NBR_ADDRESS_ADD,
	FRR_ZAPI6_INTERFACE_NBR_ADDRESS_DELETE,
	FRR_ZAPI6_INTERFACE_BFD_DEST_UPDATE,
	FRR_ZAPI6_IMPORT_ROUTE_REGISTER,
	FRR_ZAPI6_IMPORT_ROUTE_UNREGISTER,
	FRR_ZAPI6_IMPORT_CHECK_UPDATE,
	//FRR_ZAPI6_IPV4_ROUTE_IPV6_NEXTHOP_ADD,
	FRR_ZAPI6_BFD_DEST_REGISTER,
	FRR_ZAPI6_BFD_DEST_DEREGISTER,
	FRR_ZAPI6_BFD_DEST_UPDATE,
	FRR_ZAPI6_BFD_DEST_REPLAY,
	FRR_ZAPI6_REDISTRIBUTE_ROUTE_ADD,
	FRR_ZAPI6_REDISTRIBUTE_ROUTE_DEL,
	FRR_ZAPI6_VRF_UNREGISTER,
	FRR_ZAPI6_VRF_ADD,
	FRR_ZAPI6_VRF_DELETE,
	FRR_ZAPI6_VRF_LABEL,
	FRR_ZAPI6_INTERFACE_VRF_UPDATE,
	FRR_ZAPI6_BFD_CLIENT_REGISTER,
	FRR_ZAPI6_BFD_CLIENT_DEREGISTER,
	FRR_ZAPI6_INTERFACE_ENABLE_RADV,
	FRR_ZAPI6_INTERFACE_DISABLE_RADV,
	FRR_ZAPI6_IPV4_NEXTHOP_LOOKUP_MRIB,
	FRR_ZAPI6_INTERFACE_LINK_PARAMS,
	FRR_ZAPI6_MPLS_LABELS_ADD,
	FRR_ZAPI6_MPLS_LABELS_DELETE,
	FRR_ZAPI6_IPMR_ROUTE_STATS,
	FRR_ZAPI6_LABEL_MANAGER_CONNECT,
	FRR_ZAPI6_LABEL_MANAGER_CONNECT_ASYNC,
	FRR_ZAPI6_GET_LABEL_CHUNK,
	FRR_ZAPI6_RELEASE_LABEL_CHUNK,
	FRR_ZAPI6_FEC_REGISTER,
	FRR_ZAPI6_FEC_UNREGISTER,
	FRR_ZAPI6_FEC_UPDATE,
	FRR_ZAPI6_ADVERTISE_DEFAULT_GW,
	FRR_ZAPI6_ADVERTISE_SUBNET,
	FRR_ZAPI6_ADVERTISE_ALL_VNI,
	FRR_ZAPI6_LOCAL_ES_ADD,
	FRR_ZAPI6_LOCAL_ES_DEL,
	FRR_ZAPI6_VNI_ADD,
	FRR_ZAPI6_VNI_DEL,
	FRR_ZAPI6_L3VNI_ADD,
	FRR_ZAPI6_L3VNI_DEL,
	FRR_ZAPI6_REMOTE_VTEP_ADD,
	FRR_ZAPI6_REMOTE_VTEP_DEL,
	FRR_ZAPI6_MACIP_ADD,
	FRR_ZAPI6_MACIP_DEL,
	FRR_ZAPI6_IP_PREFIX_ROUTE_ADD,
	FRR_ZAPI6_IP_PREFIX_ROUTE_DEL,
	FRR_ZAPI6_REMOTE_MACIP_ADD,
	FRR_ZAPI6_REMOTE_MACIP_DEL,
	FRR_ZAPI6_DUPLICATE_ADDR_DETECTION,
	FRR_ZAPI6_PW_ADD,
	FRR_ZAPI6_PW_DELETE,
	FRR_ZAPI6_PW_SET,
	FRR_ZAPI6_PW_UNSET,
	FRR_ZAPI6_PW_STATUS_UPDATE,
	FRR_ZAPI6_RULE_ADD,
	FRR_ZAPI6_RULE_DELETE,
	FRR_ZAPI6_RULE_NOTIFY_OWNER,
	FRR_ZAPI6_TABLE_MANAGER_CONNECT,
	FRR_ZAPI6_GET_TABLE_CHUNK,
	FRR_ZAPI6_RELEASE_TABLE_CHUNK,
	FRR_ZAPI6_IPSET_CREATE,
	FRR_ZAPI6_IPSET_DESTROY,
	FRR_ZAPI6_IPSET_ENTRY_ADD,
	FRR_ZAPI6_IPSET_ENTRY_DELETE,
	FRR_ZAPI6_IPSET_NOTIFY_OWNER,
	FRR_ZAPI6_IPSET_ENTRY_NOTIFY_OWNER,
	FRR_ZAPI6_IPTABLE_ADD,
	FRR_ZAPI6_IPTABLE_DELETE,
	FRR_ZAPI6_IPTABLE_NOTIFY_OWNER,
	FRR_ZAPI6_VXLAN_FLOOD_CONTROL,
};

static const value_string frr_zapi6_messages[] = {
	{ FRR_ZAPI6_INTERFACE_ADD,		"Add Interface" },
	{ FRR_ZAPI6_INTERFACE_DELETE,		"Delete Interface" },
	{ FRR_ZAPI6_INTERFACE_ADDRESS_ADD,	"Add Interface Address" },
	{ FRR_ZAPI6_INTERFACE_ADDRESS_DELETE,	"Delete Interface Address" },
	{ FRR_ZAPI6_INTERFACE_UP,		"Interface Up" },
	{ FRR_ZAPI6_INTERFACE_DOWN,		"Interface Down" },
	{ FRR_ZAPI6_ROUTE_ADD,			"Add Route" },
	{ FRR_ZAPI6_ROUTE_DELETE,		"Delete Route" },
	{ FRR_ZAPI6_REDISTRIBUTE_ADD,		"Add Redistribute" },
	{ FRR_ZAPI6_REDISTRIBUTE_DELETE,	"Delete Redistribute" },
	{ FRR_ZAPI6_REDISTRIBUTE_DEFAULT_ADD,	"Add Default Redistribute" },
	{ FRR_ZAPI6_REDISTRIBUTE_DEFAULT_DELETE,"Delete Default Redistribute" },
	{ FRR_ZAPI6_ROUTER_ID_ADD,		"Router ID Add" },
	{ FRR_ZAPI6_ROUTER_ID_DELETE,		"Router ID Delete" },
	{ FRR_ZAPI6_ROUTER_ID_UPDATE,		"Router ID Update" },
	{ FRR_ZAPI6_HELLO,			"Hello" },
	{ FRR_ZAPI6_CAPABILITIES,		"Capabilities" },
	{ FRR_ZAPI6_NEXTHOP_REGISTER,		"Nexthop Register" },
	{ FRR_ZAPI6_NEXTHOP_UNREGISTER,		"Nexthop Unregister" },
	{ FRR_ZAPI6_NEXTHOP_UPDATE,		"Nexthop Update" },
	{ FRR_ZAPI6_INTERFACE_NBR_ADDRESS_ADD,	"Interface Neighbor Address Add" },
	{ FRR_ZAPI6_INTERFACE_NBR_ADDRESS_DELETE, "Interface Neighbor Address Delete" },
	{ FRR_ZAPI6_INTERFACE_BFD_DEST_UPDATE,	"Interface BFD Destination Update" },
	{ FRR_ZAPI6_IMPORT_ROUTE_REGISTER,	"Import Route Register" },
	{ FRR_ZAPI6_IMPORT_ROUTE_UNREGISTER,	"Import Route Unregister" },
	{ FRR_ZAPI6_IMPORT_CHECK_UPDATE,	"Import Check Update" },
	//{ FRR_ZAPI6_IPV4_ROUTE_IPV6_NEXTHOP_ADD,"Add IPv6 nexthop for IPv4 Route" },
	{ FRR_ZAPI6_BFD_DEST_REGISTER,		"BFD Destination Register" },
	{ FRR_ZAPI6_BFD_DEST_DEREGISTER,	"BFD Destination Deregister" },
	{ FRR_ZAPI6_BFD_DEST_UPDATE,		"BFD Destination Update" },
	{ FRR_ZAPI6_BFD_DEST_REPLAY,		"BFD Destination Replay" },
	{ FRR_ZAPI6_REDISTRIBUTE_ROUTE_ADD,	"Add Redistribute Route" },
	{ FRR_ZAPI6_REDISTRIBUTE_ROUTE_DEL,	"Delete Redistribute Route" },
	{ FRR_ZAPI6_VRF_UNREGISTER,		"VRF Unregister" },
	{ FRR_ZAPI6_VRF_ADD,			"VRF Add" },
	{ FRR_ZAPI6_VRF_DELETE,			"VRF Delete" },
	{ FRR_ZAPI6_VRF_LABEL,			"VRF Label" },
	{ FRR_ZAPI6_INTERFACE_VRF_UPDATE,	"Interface VRF Update" },
	{ FRR_ZAPI6_BFD_CLIENT_REGISTER,	"BFD Client Register" },
	{ FRR_ZAPI6_BFD_CLIENT_DEREGISTER,	"BFD Client Deregister" },
	{ FRR_ZAPI6_INTERFACE_ENABLE_RADV,	"Interface Enable Rouer Advertisement" },
	{ FRR_ZAPI6_INTERFACE_DISABLE_RADV,	"Interface Disable Rouer Advertisement" },
	{ FRR_ZAPI6_IPV4_NEXTHOP_LOOKUP_MRIB,	"IPv4 Nexthop Lookup Multicast RIB" },
	{ FRR_ZAPI6_INTERFACE_LINK_PARAMS,	"Interface Link Paameters" },
	{ FRR_ZAPI6_MPLS_LABELS_ADD,		"MPLS Labels Add" },
	{ FRR_ZAPI6_MPLS_LABELS_DELETE,		"MPLS Labels Delete" },
	{ FRR_ZAPI6_IPMR_ROUTE_STATS,		"IPMR Route Statics" },
	{ FRR_ZAPI6_LABEL_MANAGER_CONNECT,	"Label Manager Connect" },
	{ FRR_ZAPI6_LABEL_MANAGER_CONNECT_ASYNC,"Label Manager Connect Asynchronous" },
	{ FRR_ZAPI6_GET_LABEL_CHUNK,		"Get Label Chunk" },
	{ FRR_ZAPI6_RELEASE_LABEL_CHUNK,	"Release Label Chunk" },
	{ FRR_ZAPI6_FEC_REGISTER,		"FEC Register" },
	{ FRR_ZAPI6_FEC_UNREGISTER,		"FEC Unregister" },
	{ FRR_ZAPI6_FEC_UPDATE,			"FEC Update" },
	{ FRR_ZAPI6_ADVERTISE_DEFAULT_GW,	"Advertise Deffault Gateway" },
	{ FRR_ZAPI6_ADVERTISE_SUBNET,		"Advertise Subnet" },
	{ FRR_ZAPI6_ADVERTISE_ALL_VNI,		"Advertise all VNI" },
	{ FRR_ZAPI6_LOCAL_ES_ADD,		"Local Ethernet Segment Add" },
	{ FRR_ZAPI6_LOCAL_ES_DEL,		"Local Ethernet Segment Delete" },
	{ FRR_ZAPI6_VNI_ADD,			"VNI Add" },
	{ FRR_ZAPI6_VNI_DEL,			"VNI Delete" },
	{ FRR_ZAPI6_L3VNI_ADD,			"L3VNI Add" },
	{ FRR_ZAPI6_L3VNI_DEL,			"L3VNI Delete" },
	{ FRR_ZAPI6_REMOTE_VTEP_ADD,		"Remote VTEP Add" },
	{ FRR_ZAPI6_REMOTE_VTEP_DEL,		"Remote VTEP Delete" },
	{ FRR_ZAPI6_MACIP_ADD,			"MAC/IP Add" },
	{ FRR_ZAPI6_MACIP_DEL,			"MAC/IP Dleate" },
	{ FRR_ZAPI6_IP_PREFIX_ROUTE_ADD,	"IP Prefix Route Add" },
	{ FRR_ZAPI6_IP_PREFIX_ROUTE_DEL,	"IP Prefix Route Delete" },
	{ FRR_ZAPI6_REMOTE_MACIP_ADD,		"Remote MAC/IP Add" },
	{ FRR_ZAPI6_REMOTE_MACIP_DEL,		"Remote MAC/IP Delete" },
	{ FRR_ZAPI6_DUPLICATE_ADDR_DETECTION,   "Duplicate Address Detection" },
	{ FRR_ZAPI6_PW_ADD,			"PseudoWire Add" },
	{ FRR_ZAPI6_PW_DELETE,			"PseudoWire Delete" },
	{ FRR_ZAPI6_PW_SET,			"PseudoWire Set" },
	{ FRR_ZAPI6_PW_UNSET,			"PseudoWire Unset" },
	{ FRR_ZAPI6_PW_STATUS_UPDATE,		"PseudoWire Status Update" },
	{ FRR_ZAPI6_RULE_ADD,			"Rule Add" },
	{ FRR_ZAPI6_RULE_DELETE,		"Rule Delete" },
	{ FRR_ZAPI6_RULE_NOTIFY_OWNER,		"Rule Notify Owner" },
	{ FRR_ZAPI6_TABLE_MANAGER_CONNECT,	"Table Manager Connect" },
	{ FRR_ZAPI6_GET_TABLE_CHUNK,		"Get Table Chunk" },
	{ FRR_ZAPI6_RELEASE_TABLE_CHUNK,	"Release Table Chunk" },
	{ FRR_ZAPI6_IPSET_CREATE,		"IPSet Create" },
	{ FRR_ZAPI6_IPSET_DESTROY,		"IPSet Destroy" },
	{ FRR_ZAPI6_IPSET_ENTRY_ADD,		"IPSet Entry Add" },
	{ FRR_ZAPI6_IPSET_ENTRY_DELETE,		"IPSet Entry Delete" },
	{ FRR_ZAPI6_IPSET_NOTIFY_OWNER,		"IPSet Notify Oner" },
	{ FRR_ZAPI6_IPSET_ENTRY_NOTIFY_OWNER,	"IPSet Entry Notify Owner" },
	{ FRR_ZAPI6_IPTABLE_ADD,		"IPTable Add" },
	{ FRR_ZAPI6_IPTABLE_DELETE,		"IPTable Delete" },
	{ FRR_ZAPI6_IPTABLE_NOTIFY_OWNER,	"IPTable Notify Owner" },
	{ FRR_ZAPI6_VXLAN_FLOOD_CONTROL,	"VXLAN Flood Control" },
	{ 0,					NULL },
};

/* Zebra route's types. */
#define ZEBRA_ROUTE_SYSTEM               0
#define ZEBRA_ROUTE_KERNEL               1
#define ZEBRA_ROUTE_CONNECT              2
#define ZEBRA_ROUTE_STATIC               3
#define ZEBRA_ROUTE_RIP                  4
#define ZEBRA_ROUTE_RIPNG                5
#define ZEBRA_ROUTE_OSPF                 6
#define ZEBRA_ROUTE_OSPF6                7
#define ZEBRA_ROUTE_BGP                  8

static const value_string routes_v0[] = {
	{ ZEBRA_ROUTE_SYSTEM,			"System Route" },
	{ ZEBRA_ROUTE_KERNEL,			"Kernel Route" },
	{ ZEBRA_ROUTE_CONNECT,			"Connected Route" },
	{ ZEBRA_ROUTE_STATIC,			"Static Route" },
	{ ZEBRA_ROUTE_RIP,			"RIP Route" },
	{ ZEBRA_ROUTE_RIPNG,			"RIPnG Route" },
	{ ZEBRA_ROUTE_OSPF,			"OSPF Route" },
	{ ZEBRA_ROUTE_OSPF6,			"OSPF6 Route" },
	{ ZEBRA_ROUTE_BGP,			"BGP Route" },
	{ 0,					NULL },
};

/*
 * In Quagga, ISIS is type 8 and BGP is type 9, but Zebra didn't have ISIS...
 * so for Zebra BGP is type 8. So we dup the value_string table for quagga.
 */
#define QUAGGA_ROUTE_ISIS                 8
#define QUAGGA_ROUTE_BGP                  9
#define QUAGGA_ROUTE_HSLS                 10
#define QUAGGA_ROUTE_OLSR                 11
#define QUAGGA_ROUTE_BABEL                12

static const value_string routes_v1[] = {
	{ ZEBRA_ROUTE_SYSTEM,			"System Route" },
	{ ZEBRA_ROUTE_KERNEL,			"Kernel Route" },
	{ ZEBRA_ROUTE_CONNECT,			"Connected Route" },
	{ ZEBRA_ROUTE_STATIC,			"Static Route" },
	{ ZEBRA_ROUTE_RIP,			"RIP Route" },
	{ ZEBRA_ROUTE_RIPNG,			"RIPnG Route" },
	{ ZEBRA_ROUTE_OSPF,			"OSPF Route" },
	{ ZEBRA_ROUTE_OSPF6,			"OSPF6 Route" },
	{ QUAGGA_ROUTE_ISIS,			"ISIS Route" },
	{ QUAGGA_ROUTE_BGP,			"BGP Route" },
	{ QUAGGA_ROUTE_HSLS,			"HSLS Route" },
	{ QUAGGA_ROUTE_OLSR,			"OLSR Route" },
	{ QUAGGA_ROUTE_BABEL,			"BABEL Route" },
	{ 0,					NULL },
};

#define FRR_ZAPI4_ROUTE_PIM               10
#define FRR_ZAPI4_ROUTE_NHRP              11
#define FRR_ZAPI4_ROUTE_HSLS              12
#define FRR_ZAPI4_ROUTE_OLSR              13
#define FRR_ZAPI4_ROUTE_TABLE             14
#define FRR_ZAPI4_ROUTE_LDP               15
#define FRR_ZAPI4_ROUTE_VNC               16
#define FRR_ZAPI4_ROUTE_VNC_DIRECT        17
#define FRR_ZAPI4_ROUTE_VNC_DIRECT_RH     18
#define FRR_ZAPI4_ROUTE_BGP_DIRECT        19
#define FRR_ZAPI4_ROUTE_BGP_DIRECT_EXT    20

static const value_string routes_v4[] = {
	{ ZEBRA_ROUTE_SYSTEM,			"System Route" },
	{ ZEBRA_ROUTE_KERNEL,			"Kernel Route" },
	{ ZEBRA_ROUTE_CONNECT,			"Connected Route" },
	{ ZEBRA_ROUTE_STATIC,			"Static Route" },
	{ ZEBRA_ROUTE_RIP,			"RIP Route" },
	{ ZEBRA_ROUTE_RIPNG,			"RIPnG Route" },
	{ ZEBRA_ROUTE_OSPF,			"OSPF Route" },
	{ ZEBRA_ROUTE_OSPF6,			"OSPF6 Route" },
	{ QUAGGA_ROUTE_ISIS,			"ISIS Route" },
	{ QUAGGA_ROUTE_BGP,			"BGP Route" },
	{ FRR_ZAPI4_ROUTE_PIM,			"PIM Route" },
	{ FRR_ZAPI4_ROUTE_NHRP,			"NHRP Route" },
	{ FRR_ZAPI4_ROUTE_HSLS,			"HSLS Route" },
	{ FRR_ZAPI4_ROUTE_OLSR,			"OLSR Route" },
	{ FRR_ZAPI4_ROUTE_TABLE,		"Table Route" },
	{ FRR_ZAPI4_ROUTE_LDP,			"LDP Route" },
	{ FRR_ZAPI4_ROUTE_VNC,			"VNC Route" },
	{ FRR_ZAPI4_ROUTE_VNC_DIRECT,		"VNC Direct Route" },
	{ FRR_ZAPI4_ROUTE_VNC_DIRECT_RH,	"VNC RN Route" },
	{ FRR_ZAPI4_ROUTE_BGP_DIRECT,		"BGP Direct Route" },
	{ FRR_ZAPI4_ROUTE_BGP_DIRECT_EXT,	"BGP Direct to NVE groups Route" },
	{ 0,					NULL},
};

#define FRR_ZAPI5_ROUTE_EIGRP             11
#define FRR_ZAPI5_ROUTE_NHRP              12
#define FRR_ZAPI5_ROUTE_HSLS              13
#define FRR_ZAPI5_ROUTE_OLSR              14
#define FRR_ZAPI5_ROUTE_TABLE             15
#define FRR_ZAPI5_ROUTE_LDP               16
#define FRR_ZAPI5_ROUTE_VNC               17
#define FRR_ZAPI5_ROUTE_VNC_DIRECT        18
#define FRR_ZAPI5_ROUTE_VNC_DIRECT_RH     19
#define FRR_ZAPI5_ROUTE_BGP_DIRECT        20
#define FRR_ZAPI5_ROUTE_BGP_DIRECT_EXT    21
#define FRR_ZAPI5_ROUTE_BABEL             22
#define FRR_ZAPI5_ROUTE_SHARP             23
#define FRR_ZAPI5_ROUTE_PBR               24
#define FRR_ZAPI6_ROUTE_BFD               25
#define FRR_ZAPI6_ROUTE_OPENFABRIC        26

static const value_string routes_v5[] = {
	{ ZEBRA_ROUTE_SYSTEM,			"System Route" },
	{ ZEBRA_ROUTE_KERNEL,			"Kernel Route" },
	{ ZEBRA_ROUTE_CONNECT,			"Connected Route" },
	{ ZEBRA_ROUTE_STATIC,			"Static Route" },
	{ ZEBRA_ROUTE_RIP,			"RIP Route" },
	{ ZEBRA_ROUTE_RIPNG,			"RIPnG Route" },
	{ ZEBRA_ROUTE_OSPF,			"OSPF Route" },
	{ ZEBRA_ROUTE_OSPF6,			"OSPF6 Route" },
	{ QUAGGA_ROUTE_ISIS,			"ISIS Route" },
	{ QUAGGA_ROUTE_BGP,			"BGP Route" },
	{ FRR_ZAPI4_ROUTE_PIM,			"PIM Route" },
	{ FRR_ZAPI5_ROUTE_EIGRP,		"EIGRP Route" },
	{ FRR_ZAPI5_ROUTE_NHRP,			"NHRP Route" },
	{ FRR_ZAPI5_ROUTE_HSLS,			"HSLS Route" },
	{ FRR_ZAPI5_ROUTE_OLSR,			"OLSR Route" },
	{ FRR_ZAPI5_ROUTE_TABLE,		"Table Route" },
	{ FRR_ZAPI5_ROUTE_LDP,			"LDP Route" },
	{ FRR_ZAPI5_ROUTE_VNC,			"VNC Route" },
	{ FRR_ZAPI5_ROUTE_VNC_DIRECT,		"VNC Direct Route" },
	{ FRR_ZAPI5_ROUTE_VNC_DIRECT_RH,	"VNC RN Route" },
	{ FRR_ZAPI5_ROUTE_BGP_DIRECT,		"BGP Direct Route" },
	{ FRR_ZAPI5_ROUTE_BGP_DIRECT_EXT,	"BGP Direct to NVE groups Route" },
	{ FRR_ZAPI5_ROUTE_BABEL,		"BABEL Route" },
	{ FRR_ZAPI5_ROUTE_SHARP,		"SHARPd Route" },
	{ FRR_ZAPI5_ROUTE_PBR,			"PBR Route" },
	{ FRR_ZAPI6_ROUTE_BFD,			"BFD Route" },
	{ FRR_ZAPI6_ROUTE_OPENFABRIC,		"OpenFabric Route" },
	{ 0,					NULL },
};

/* Zebra's family types. */
#define ZEBRA_FAMILY_UNSPEC              0
#define ZEBRA_FAMILY_IPV4                2
#define ZEBRA_FAMILY_IPV6                10

static const value_string families[] = {
	{ ZEBRA_FAMILY_IPV4,			"IPv4" },
	{ ZEBRA_FAMILY_IPV6,			"IPv6" },
	{ 0,					NULL },
};

/* Zebra message flags */
#define ZEBRA_FLAG_INTERNAL              0x01
#define ZEBRA_FLAG_SELFROUTE             0x02
#define ZEBRA_FLAG_BLACKHOLE             0x04
#define ZEBRA_FLAG_IBGP                  0x08
#define ZEBRA_FLAG_SELECTED              0x10
#define ZEBRA_FLAG_FIB_OVERRIDE          0x20
#define ZEBRA_FLAG_STATIC                0x40
#define ZEBRA_FLAG_REJECT                0x80
/* ZAPI v4 (FRRouting v3) message flags */
#define ZEBRA_FLAG_SCOPE_LINK            0x100
#define FRR_FLAG_FIB_OVERRIDE            0x200
/* ZAPI v5 (FRRouting v5) message flags */
#define ZEBRA_FLAG_EVPN_ROUTE            0x400
#define FRR_FLAG_ALLOW_RECURSION         0x01
/* ZAPI v6 (FRRouting v7) message flags */
#define FRR_ZAPI6_FLAG_IBGP              0x04
#define FRR_ZAPI6_FLAG_SELECTED          0x08
#define FRR_ZAPI6_FLAG_FIB_OVERRIDE      0x10
#define FRR_ZAPI6_FLAG_EVPN_ROUTE        0x20
#define FRR_ZAPI6_FLAG_RR_USE_DISTANCE   0x40
#define FRR_ZAPI6_FLAG_ONLINk            0x40


/* Zebra API message flag. */
#define ZEBRA_ZAPI_MESSAGE_NEXTHOP       0x01
#define ZEBRA_ZAPI_MESSAGE_IFINDEX       0x02
#define ZEBRA_ZAPI_MESSAGE_DISTANCE      0x04
#define ZEBRA_ZAPI_MESSAGE_METRIC        0x08
#define ZEBRA_ZAPI_MESSAGE_MTU           0x10
#define ZEBRA_ZAPI_MESSAGE_TAG           0x20
/* ZAPI v4 (FRRouting v3) API message flags */
#define FRR_ZAPI4_MESSAGE_TAG            0x10
#define FRR_ZAPI4_MESSAGE_MTU            0x20
#define FRR_ZAPI4_MESSAGE_SRCPFX         0x40
/* ZAPI v5 (FRRouting v5) API message flags */
#define FRR_ZAPI5_MESSAGE_DISTANCE       0x02
#define FRR_ZAPI5_MESSAGE_METRIC         0x04
#define FRR_ZAPI5_MESSAGE_TAG            0x08
#define FRR_ZAPI5_MESSAGE_MTU            0x10
#define FRR_ZAPI5_MESSAGE_SRCPFX         0x20
#define FRR_ZAPI5_MESSAGE_LABEL          0x40
#define FRR_ZAPI5_MESSAGE_TABLEID        0x80

/* Zebra NextHop Types */
#define ZEBRA_NEXTHOP_TYPE_IFINDEX       0x01
#define ZEBRA_NEXTHOP_TYPE_IFNAME        0x02
#define ZEBRA_NEXTHOP_TYPE_IPV4          0x03
#define ZEBRA_NEXTHOP_TYPE_IPV4_IFINDEX  0x04
#define ZEBRA_NEXTHOP_TYPE_IPV4_IFNAME   0x05
#define ZEBRA_NEXTHOP_TYPE_IPV6          0x06
#define ZEBRA_NEXTHOP_TYPE_IPV6_IFINDEX  0x07
#define ZEBRA_NEXTHOP_TYPE_IPV6_IFNAME   0x08
#define ZEBRA_NEXTHOP_TYPE_BLACKHOLE     0x09

static const value_string zebra_nht[] = {
	{ ZEBRA_NEXTHOP_TYPE_IFINDEX,		"IFIndex" },
	{ ZEBRA_NEXTHOP_TYPE_IFNAME,		"IFName" },
	{ ZEBRA_NEXTHOP_TYPE_IPV4,		"IPv4" },
	{ ZEBRA_NEXTHOP_TYPE_IPV4_IFINDEX,	"IPv4 IFIndex" },
	{ ZEBRA_NEXTHOP_TYPE_IPV4_IFNAME,	"IPv4 IFName" },
	{ ZEBRA_NEXTHOP_TYPE_IPV6,		"IPv6 Nexthop" },
	{ ZEBRA_NEXTHOP_TYPE_IPV6_IFINDEX,	"IPv6 IFIndex" },
	{ ZEBRA_NEXTHOP_TYPE_IPV6_IFNAME,	"IPv6 IFName" },
	{ ZEBRA_NEXTHOP_TYPE_BLACKHOLE,		"Blackhole" },
	{ 0,					NULL },
};

/* FRR NextHop Types */
#define FRR_NEXTHOP_TYPE_IFINDEX         0x01
#define FRR_NEXTHOP_TYPE_IPV4            0x02
#define FRR_NEXTHOP_TYPE_IPV4_IFINDEX    0x03
#define FRR_NEXTHOP_TYPE_IPV6            0x04
#define FRR_NEXTHOP_TYPE_IPV6_IFINDEX    0x05
#define FRR_NEXTHOP_TYPE_BLACKHOLE       0x06
static const value_string frr_nht[] = {
	{ FRR_NEXTHOP_TYPE_IFINDEX,		"IFIndex" },
	{ FRR_NEXTHOP_TYPE_IPV4,		"IPv4" },
	{ FRR_NEXTHOP_TYPE_IPV4_IFINDEX,	"IPv4 IFIndex" },
	{ FRR_NEXTHOP_TYPE_IPV6,		"IPv6" },
	{ FRR_NEXTHOP_TYPE_IPV6_IFINDEX,	"IPv6 IFIndex" },
	{ FRR_NEXTHOP_TYPE_BLACKHOLE,		"Blackhole" },
	{ 0,					NULL },
};

/* Subsequent Address Family Identifier. */
#define ZEBRA_SAFI_UNICAST              1
#define ZEBRA_SAFI_MULTICAST            2
#define ZEBRA_SAFI_RESERVED_3           3
#define ZEBRA_SAFI_MPLS_VPN             4

static const value_string safi[] = {
	{ ZEBRA_SAFI_UNICAST,			"Unicast" },
	{ ZEBRA_SAFI_MULTICAST,			"Multicast" },
	{ ZEBRA_SAFI_RESERVED_3,		"Reserved" },
	{ ZEBRA_SAFI_MPLS_VPN,			"MPLS VPN" },
	{ 0,					NULL },
};

enum blackhole_type {
	BLACKHOLE_UNSPEC = 0,
	BLACKHOLE_NULL,
	BLACKHOLE_REJECT,
	BLACKHOLE_ADMINPROHIB,
};

static const value_string blackhole_type[] = {
	{ BLACKHOLE_UNSPEC,			"Unspec" },
	{ BLACKHOLE_NULL,			"NULL" },
	{ BLACKHOLE_REJECT,			"Reject" },
	{ BLACKHOLE_ADMINPROHIB,		"Adminisrative Prohibit" },
	{ 0,					NULL},
};

#define INTERFACE_NAMSIZ      20

#define PSIZE(a) (((a) + 7) / (8))

static int
zebra_route_nexthop(proto_tree *tree, gboolean request, tvbuff_t *tvb,
		    int offset, guint16 len, guint8 family, guint8 version)
{
	guint8 nexthoptype = 0, interfacenamelength;
	guint16 nexthopcount;
	if (version < 5) {
		nexthopcount = tvb_get_guint8(tvb, offset);
		proto_tree_add_uint(tree, hf_zebra_nexthopnum, tvb, offset, 1,
				    nexthopcount);
		offset += 1;
	} else {
		nexthopcount = tvb_get_ntohs(tvb, offset);
		proto_tree_add_uint(tree, hf_zebra_nexthopnum_u16, tvb, offset,
				    2, nexthopcount);
		offset += 2;
	}

	if (nexthopcount > len)
		return offset; /* Sanity */

	while (nexthopcount--) {
		if (version > 4) {
			proto_tree_add_item(tree, hf_zebra_vrfid, tvb, offset,
					    4, ENC_BIG_ENDIAN);
			offset += 4;
		}
		if (version < 4 && request) { /* Quagga */
			nexthoptype = tvb_get_guint8(tvb, offset);
			proto_tree_add_item(tree, hf_zebra_nexthoptype, tvb,
					    offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		} else if (version >= 4) { /* FRR */
			nexthoptype = tvb_get_guint8(tvb, offset);
			proto_tree_add_item(tree, hf_zebra_nexthoptype_frr, tvb,
					    offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
		if ((version < 4 &&
		     ((request &&
		       (nexthoptype == ZEBRA_NEXTHOP_TYPE_IPV4 ||
			nexthoptype == ZEBRA_NEXTHOP_TYPE_IPV4_IFINDEX ||
			nexthoptype == ZEBRA_NEXTHOP_TYPE_IPV4_IFNAME)) ||
		      (!request && family == ZEBRA_FAMILY_IPV4))) ||
		    (version >= 4 &&
		     (nexthoptype == FRR_NEXTHOP_TYPE_IPV4 ||
		      nexthoptype == FRR_NEXTHOP_TYPE_IPV4_IFINDEX))) {
			proto_tree_add_item(tree, hf_zebra_nexthop4, tvb,
					    offset, 4, ENC_NA);
			offset += 4;
		}
		if ((version < 4 &&
		     ((request &&
		       (nexthoptype == ZEBRA_NEXTHOP_TYPE_IPV6 ||
			nexthoptype == ZEBRA_NEXTHOP_TYPE_IPV6_IFINDEX ||
			nexthoptype == ZEBRA_NEXTHOP_TYPE_IPV6_IFNAME)) ||
		      (!request && family == ZEBRA_FAMILY_IPV6))) ||
		    (version >= 4 &&
		     (nexthoptype == FRR_NEXTHOP_TYPE_IPV6 ||
		      nexthoptype == FRR_NEXTHOP_TYPE_IPV6_IFINDEX))) {
			proto_tree_add_item(tree, hf_zebra_nexthop6, tvb,
					    offset, 16, ENC_NA);
			offset += 16;
		}
		if (nexthoptype == ZEBRA_NEXTHOP_TYPE_IFINDEX ||
		    (version < 4 &&
		     (nexthoptype == ZEBRA_NEXTHOP_TYPE_IPV4_IFINDEX ||
		      nexthoptype == ZEBRA_NEXTHOP_TYPE_IPV6_IFINDEX)) ||
		    (version >= 4 &&
		     (nexthoptype == FRR_NEXTHOP_TYPE_IPV4_IFINDEX ||
		      nexthoptype == FRR_NEXTHOP_TYPE_IPV6_IFINDEX))) {
			proto_tree_add_item(tree, hf_zebra_index, tvb, offset,
					    4, ENC_BIG_ENDIAN);
			offset += 4;
		}

		if (version < 4 &&
		    (nexthoptype == ZEBRA_NEXTHOP_TYPE_IFNAME ||
		     nexthoptype == ZEBRA_NEXTHOP_TYPE_IPV4_IFNAME ||
		     nexthoptype == ZEBRA_NEXTHOP_TYPE_IPV6_IFNAME)) {
			interfacenamelength = tvb_get_guint8(tvb, offset);
			offset += 1;
			proto_tree_add_item(tree, hf_zebra_interface, tvb,
					    offset, interfacenamelength,
					    ENC_ASCII | ENC_NA);
			offset += interfacenamelength;
		}
		if (version > 4 &&
		    (nexthoptype == FRR_NEXTHOP_TYPE_BLACKHOLE)) {
			proto_tree_add_item(tree, hf_zebra_bhtype, tvb, offset,
					    1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}
	return offset;
}

static int
zebra_route_ifindex(proto_tree *tree, tvbuff_t *tvb, int offset, guint16 len)
{
	guint16 indexcount = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tree, hf_zebra_indexnum,
			    tvb, offset, 1, indexcount);
	offset += 1;
	if (indexcount > len)
		return offset; /* Sanity */

	while (indexcount--) {
		proto_tree_add_item(tree, hf_zebra_index, tvb, offset, 4,
				ENC_BIG_ENDIAN);
		offset += 4;
	}
	return offset;
}

static int
zebra_route_message(proto_tree *tree, tvbuff_t *tvb, int offset, guint8 version)
{
	static int * const flags[] = {
		&hf_zebra_msg_nexthop,
		&hf_zebra_msg_index,
		&hf_zebra_msg_distance,
		&hf_zebra_msg_metric,
		&hf_zebra_msg_mtu,
		&hf_zebra_msg_tag,
		NULL
	};
	static int * const flags4[] = {
		&hf_zebra_msg_nexthop,
		&hf_zebra_msg_index,
		&hf_zebra_msg_distance,
		&hf_zebra_msg_metric,
		&hf_zebra_msg4_tag,
		&hf_zebra_msg4_mtu,
		&hf_zebra_msg4_srcpfx,
		NULL
	};
	static int * const flags5[] = {
		&hf_zebra_msg_nexthop,
		&hf_zebra_msg5_distance,
		&hf_zebra_msg5_metric,
		&hf_zebra_msg5_tag,
		&hf_zebra_msg5_mtu,
		&hf_zebra_msg5_srcpfx,
		&hf_zebra_msg_label,
		&hf_zebra_msg_tableid,
		NULL
	};
	if (version < 4) {
		proto_tree_add_bitmask(tree, tvb, offset, hf_zebra_message,
				       ett_message, flags, ENC_NA);
	} else if (version == 4) {
		proto_tree_add_bitmask(tree, tvb, offset, hf_zebra_message4,
				       ett_message, flags4, ENC_NA);
	} else {
		proto_tree_add_bitmask(tree, tvb, offset, hf_zebra_message5,
				       ett_message, flags5, ENC_NA);
	}

	offset += 1;

	return offset;
}

static int
zebra_route(proto_tree *tree, gboolean request, tvbuff_t *tvb, int offset,
	    guint16 len, guint8 family, guint16 command, guint8 version)
{
	guint32 prefix4, srcprefix4, rtflags = 0;
	guint8  message, prefixlen, buffer6[16], srcprefixlen, srcbuffer6[16];

	if (version == 0) {
		proto_tree_add_item(tree, hf_zebra_type_v0, tvb,
				    offset, 1, ENC_BIG_ENDIAN);
	} else if (version < 4) {
		proto_tree_add_item(tree, hf_zebra_type_v1, tvb,
				    offset, 1, ENC_BIG_ENDIAN);
	} else if (version == 4) {
		proto_tree_add_item(tree, hf_zebra_type_v4, tvb,
				    offset, 1, ENC_BIG_ENDIAN);
	} else {
		proto_tree_add_item(tree, hf_zebra_type_v5, tvb,
				    offset, 1, ENC_BIG_ENDIAN);
	}
	offset += 1;

	if (version > 3) {
		proto_tree_add_item(tree, hf_zebra_instance, tvb, offset, 2,
				    ENC_BIG_ENDIAN);
		offset += 2;
		rtflags = tvb_get_ntohl(tvb, offset);
		proto_tree_add_item(tree, hf_zebra_rtflags_u32, tvb, offset, 4,
				    ENC_BIG_ENDIAN);
		offset += 4;
	} else {
		proto_tree_add_item(tree, hf_zebra_rtflags, tvb, offset, 1,
				    ENC_BIG_ENDIAN);
		offset += 1;
	}

	message = tvb_get_guint8(tvb, offset);
	offset = zebra_route_message(tree, tvb, offset, version);

	if (version > 1 && version < 5) {
		/* version 2 added safi */
		if (((version == 2 || version == 3) && request)||
		    (version == 4 && (command == FRR_ZAPI4_IPV4_ROUTE_ADD ||
				      command == FRR_ZAPI4_IPV4_ROUTE_DELETE ||
				      command == FRR_ZAPI4_IPV6_ROUTE_ADD ||
				      command == FRR_ZAPI4_IPV6_ROUTE_DELETE))) {
			proto_tree_add_item(tree, hf_zebra_route_safi, tvb,
					    offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
		}
	} else if (version >= 5) {
		/* version 5: safi is 1 byte */
		proto_tree_add_item(tree, hf_zebra_route_safi_u8, tvb, offset,
				    1, ENC_BIG_ENDIAN);
		offset += 1;
		if ((version == 5 &&rtflags & ZEBRA_FLAG_EVPN_ROUTE) ||
		    (version > 5 &&rtflags & FRR_ZAPI6_FLAG_EVPN_ROUTE)) {
			proto_tree_add_item(tree, hf_zebra_rmac, tvb, offset, 6,
					    ENC_NA);
			offset += 6;
		}
		family = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(tree, hf_zebra_family, tvb, offset, 1,
				    ENC_BIG_ENDIAN);
		offset += 1;
	}

	prefixlen = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tree, hf_zebra_prefixlen, tvb,
			    offset, 1, prefixlen);
	offset += 1;

	if (family == ZEBRA_FAMILY_IPV6) {
		memset(buffer6, '\0', sizeof buffer6);
		tvb_memcpy(tvb, buffer6, offset,
			   MIN((unsigned) PSIZE(prefixlen), sizeof buffer6));
		proto_tree_add_ipv6(tree, hf_zebra_prefix6,
				    tvb, offset, PSIZE(prefixlen), (ws_in6_addr *)buffer6);
	} else if (family == ZEBRA_FAMILY_IPV4) {
		prefix4 = 0;
		tvb_memcpy(tvb, (guint8 *)&prefix4, offset,
			   MIN((unsigned) PSIZE(prefixlen), sizeof prefix4));
		proto_tree_add_ipv4(tree, hf_zebra_prefix4,
				    tvb, offset, PSIZE(prefixlen), prefix4);
	}
	offset += PSIZE(prefixlen);

	if ((version == 4 && family == ZEBRA_FAMILY_IPV6 &&
	     message & FRR_ZAPI4_MESSAGE_SRCPFX) ||
	    (version > 4 && message & FRR_ZAPI5_MESSAGE_SRCPFX)) {
		srcprefixlen = tvb_get_guint8(tvb, offset);
		proto_tree_add_uint(tree, hf_zebra_srcprefixlen, tvb, offset, 1,
				    srcprefixlen);
		offset += 1;

		if (family == ZEBRA_FAMILY_IPV6) {
			memset(srcbuffer6, '\0', sizeof srcbuffer6);
			tvb_memcpy(tvb, srcbuffer6, offset,
				   MIN((unsigned)PSIZE(srcprefixlen),
				       sizeof srcbuffer6));
			proto_tree_add_ipv6(tree, hf_zebra_srcprefix6, tvb,
					    offset, PSIZE(srcprefixlen),
					    (ws_in6_addr *)srcbuffer6);
		} else if (family == ZEBRA_FAMILY_IPV4) {
			prefix4 = 0;
			tvb_memcpy(tvb, (guint8 *)&srcprefix4, offset,
				   MIN((unsigned)PSIZE(srcprefixlen),
				       sizeof srcprefix4));
			proto_tree_add_ipv4(tree, hf_zebra_srcprefix4, tvb,
					    offset, PSIZE(srcprefixlen),
					    srcprefix4);
		}
		offset += PSIZE(srcprefixlen);
	}

	if (message & ZEBRA_ZAPI_MESSAGE_NEXTHOP) {
		if (version == 4 &&
		    (command == FRR_ZAPI4_REDISTRIBUTE_IPV4_ADD ||
		     command == FRR_ZAPI4_REDISTRIBUTE_IPV4_DEL)) {
			proto_tree_add_item(tree, hf_zebra_nexthopnum, tvb,
					    offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			proto_tree_add_item(tree, hf_zebra_nexthop4, tvb,
					    offset, 4, ENC_NA);
			offset += 4;
		} else if (version == 4 &&
			   (command == FRR_ZAPI4_REDISTRIBUTE_IPV6_ADD ||
			    command == FRR_ZAPI4_REDISTRIBUTE_IPV6_DEL)) {
			proto_tree_add_item(tree, hf_zebra_nexthopnum, tvb,
					    offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			proto_tree_add_item(tree, hf_zebra_nexthop6, tvb,
					    offset, 16, ENC_NA);
			offset += 16;
		} else {
			offset = zebra_route_nexthop(tree, request, tvb, offset,
						     len, family, version);
		}
	}
	if (version < 5 && message & ZEBRA_ZAPI_MESSAGE_IFINDEX) {
		offset = zebra_route_ifindex(tree, tvb, offset, len);
	}
	if ((version < 5 && message & ZEBRA_ZAPI_MESSAGE_DISTANCE) ||
	    (version >= 5 && message & FRR_ZAPI5_MESSAGE_DISTANCE)) {
		proto_tree_add_item(tree, hf_zebra_distance,
				    tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
	}
	if ((version < 5 && message & ZEBRA_ZAPI_MESSAGE_METRIC) ||
	    (version >= 5 && message & FRR_ZAPI5_MESSAGE_METRIC)) {
		proto_tree_add_item(tree, hf_zebra_metric,
				    tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}
	if ((version < 4 && message & ZEBRA_ZAPI_MESSAGE_MTU) ||
	    (version == 4 && message & FRR_ZAPI4_MESSAGE_MTU) ||
	    (version > 4 && message & FRR_ZAPI5_MESSAGE_MTU)) {
		proto_tree_add_item(tree, hf_zebra_mtu,
				    tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}
	if ((version < 4 && message & ZEBRA_ZAPI_MESSAGE_TAG) ||
	    (version == 4 && message & FRR_ZAPI4_MESSAGE_TAG) ||
	    (version > 4 && message & FRR_ZAPI5_MESSAGE_TAG)) {
		proto_tree_add_item(tree, hf_zebra_tag,
				    tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}
	if (version > 4 && message & FRR_ZAPI5_MESSAGE_TABLEID) {
		proto_tree_add_item(tree, hf_zebra_tableid,
				    tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}
	return offset;
}

static int
zebra_interface_address(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	guint8 family;
	proto_tree_add_item(tree, hf_zebra_index, tvb,
			    offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_zebra_flags, tvb,
			    offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_zebra_family, tvb,
			    offset, 1, ENC_BIG_ENDIAN);
	family = tvb_get_guint8(tvb, offset);
	offset += 1;
	if (family == ZEBRA_FAMILY_IPV4) {
		proto_tree_add_item(tree, hf_zebra_prefix4,
				    tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}
	else if (family == ZEBRA_FAMILY_IPV6) {
		proto_tree_add_item(tree, hf_zebra_prefix6,
				    tvb, offset, 16, ENC_NA);
		offset += 16;
	}
	else
		return offset;

	proto_tree_add_item(tree, hf_zebra_prefixlen, tvb,
			    offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	if (family == ZEBRA_FAMILY_IPV4) {
		proto_tree_add_item(tree, hf_zebra_dest4,
				    tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}
	else if (family == ZEBRA_FAMILY_IPV6) {
		proto_tree_add_item(tree, hf_zebra_dest6,
				    tvb, offset, 16, ENC_NA);
		offset += 16;
	}
	return offset;
}

static int zebra_hello(proto_tree *tree, tvbuff_t *tvb, int offset, int left,
		       guint8 version)
{
	proto_tree_add_item(tree, hf_zebra_redist_default, tvb, offset, 1,
			    ENC_BIG_ENDIAN);
	offset += 1;
	if (version > 3) {
		proto_tree_add_item(tree, hf_zebra_instance, tvb, offset, 2,
				    ENC_BIG_ENDIAN);
		offset += 2;
	}

	if (version > 4 && left > offset) {
		proto_tree_add_item(tree, hf_zebra_receive_notify, tvb, offset,
				    1, ENC_BIG_ENDIAN);
		offset += 1;
	}
	return offset;
}

static int zebra_redistribute(proto_tree *tree, tvbuff_t *tvb, int offset,
			      guint8 version)
{
	if (version > 3) {
		proto_tree_add_item(tree, hf_zebra_afi, tvb, offset, 1,
				    ENC_BIG_ENDIAN);
		offset += 1;
	}
	if (version == 0) {
		proto_tree_add_item(tree, hf_zebra_type_v0, tvb, offset, 1,
				    ENC_BIG_ENDIAN);
	} else if (version < 4) {
		proto_tree_add_item(tree, hf_zebra_type_v1, tvb, offset, 1,
				    ENC_BIG_ENDIAN);
	} else if (version == 4) {
		proto_tree_add_item(tree, hf_zebra_type_v4, tvb, offset, 1,
				    ENC_BIG_ENDIAN);
	} else {
		proto_tree_add_item(tree, hf_zebra_type_v5, tvb, offset, 1,
				    ENC_BIG_ENDIAN);
	}
	offset += 1;
	if (version > 3) {
		proto_tree_add_item(tree, hf_zebra_instance, tvb, offset, 2,
				    ENC_BIG_ENDIAN);
		offset += 2;
	}

	return offset;
}

static int zebra_vrf(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	proto_tree_add_item(tree, hf_zebra_vrf_table_id, tvb, offset, 4,
			    ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_zebra_vrf_netns_name, tvb, offset, 16,
			    ENC_ASCII | ENC_NA);
	offset += 16;
	proto_tree_add_item(tree, hf_zebra_vrf_name, tvb, offset, 36,
			    ENC_ASCII | ENC_NA);
	offset += 36;
	return offset;
}

static int zebra_label_manager_connect(proto_tree *tree, tvbuff_t *tvb,
				       int offset)
{
	proto_tree_add_item(tree, hf_zebra_proto, tvb, offset, 1,
			    ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_zebra_instance, tvb, offset, 2,
			    ENC_BIG_ENDIAN);
	offset += 2;
	return offset;
}

static int zebra_get_label_chunk(proto_tree *tree, gboolean request,
				 tvbuff_t *tvb, int offset)
{
	proto_tree_add_item(tree, hf_zebra_proto, tvb, offset, 1,
			    ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_zebra_instance, tvb, offset, 2,
			    ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(tree, hf_zebra_label_chunk_keep, tvb, offset, 1,
			    ENC_BIG_ENDIAN);
	offset += 1;
	if (request) {
		proto_tree_add_item(tree, hf_zebra_label_chunk_size, tvb,
				    offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	} else {
		proto_tree_add_item(tree, hf_zebra_label_chunk_start, tvb,
				    offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_zebra_label_chunk_end, tvb, offset,
				    4, ENC_BIG_ENDIAN);
		offset += 4;
	}

	return offset;
}

static int zebra_capabilties(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	proto_tree_add_item(tree, hf_zebra_mpls_enabled, tvb, offset, 1,
			    ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_zebra_multipath_num, tvb, offset, 4,
			    ENC_BIG_ENDIAN);
	offset += 4;
	return offset;
}

static int zebra_nexthop_register(proto_tree *tree, tvbuff_t *tvb, int offset,
				  guint16 len, int msg_offset)
{
	int     init_offset = offset, rest = (int)len - msg_offset;
	guint16 family = ZEBRA_FAMILY_UNSPEC;
	while (rest > offset - init_offset) {
		proto_tree_add_item(tree, hf_zebra_flags, tvb, offset, 1,
				    ENC_BIG_ENDIAN);
		offset += 1;
		family = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(tree, hf_zebra_family, tvb, offset, 2,
				    ENC_BIG_ENDIAN);
		offset += 2;
		proto_tree_add_item(tree, hf_zebra_prefixlen, tvb, offset, 1,
				    ENC_BIG_ENDIAN);
		offset += 1;
		if (family == ZEBRA_FAMILY_IPV6) {
			proto_tree_add_item(tree, hf_zebra_prefix6, tvb, offset,
					    16, ENC_NA);
			offset += 16;
		} else if (family == ZEBRA_FAMILY_IPV4) {
			proto_tree_add_item(tree, hf_zebra_prefix4, tvb, offset,
					    4, ENC_BIG_ENDIAN);
			offset += 4;
		}
	}
	return offset;
}

static int
zebra_interface(proto_tree *tree, tvbuff_t *tvb, int offset,
		guint16 command, guint8 version)
{
	gint maclen;
	proto_tree_add_item(tree, hf_zebra_interface,
			    tvb, offset, INTERFACE_NAMSIZ, ENC_ASCII|ENC_NA);
	offset += INTERFACE_NAMSIZ;
	proto_tree_add_item(tree, hf_zebra_index, tvb,
			    offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_zebra_intstatus, tvb,
			    offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	if (version != 0) {
		proto_tree_add_item(tree, hf_zebra_intflags, tvb,
				    offset, 8, ENC_BIG_ENDIAN);
		offset += 8;
	} else {
		proto_tree_add_item(tree, hf_zebra_intflags, tvb,
				    offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}
	if (version >= 4) {
		proto_tree_add_item(tree, hf_zebra_ptmenable, tvb, offset, 1,
				    ENC_BIG_ENDIAN);
		offset += 1;
		proto_tree_add_item(tree, hf_zebra_ptmstatus, tvb, offset, 1,
				    ENC_BIG_ENDIAN);
		offset += 1;
	}
	proto_tree_add_item(tree, hf_zebra_metric, tvb, offset, 4,
			    ENC_BIG_ENDIAN);
	offset += 4;
	if (version >= 4) {
		proto_tree_add_item(tree, hf_zebra_speed, tvb, offset, 4,
				    ENC_BIG_ENDIAN);
		offset += 4;
	}
	proto_tree_add_item(tree, hf_zebra_mtu, tvb,
			    offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	if (version != 0) {
		proto_tree_add_item(tree, hf_zebra_mtu6, tvb,
				    offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}
	proto_tree_add_item(tree, hf_zebra_bandwidth, tvb,
			    offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	if (version > 2 || (version <= 2 && command == ZEBRA_INTERFACE_ADD)) {
		if (version > 2) {
			proto_tree_add_item(tree, hf_zebra_lltype, tvb,
					    offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
		}
		if (version != 0) {
			maclen = (gint)tvb_get_ntohl(tvb, offset);
			proto_tree_add_item(tree, hf_zebra_maclen, tvb,
					    offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			if (maclen > 0)
				proto_tree_add_item(tree, hf_zebra_mac, tvb,
						    offset, maclen, ENC_NA);
			offset += maclen;
		}
		if (version > 2) {
			proto_tree_add_item(tree, hf_zebra_haslinkparam, tvb,
					    offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}
	return offset;
}

static int
zebra_nexthop_lookup(proto_tree *tree, gboolean request, tvbuff_t *tvb,
		     int offset, guint16 len, guint8 family, guint8 version)
{
	if (family == ZEBRA_FAMILY_IPV6) {
		proto_tree_add_item(tree, hf_zebra_dest6, tvb, offset, 16,
				    ENC_NA);
		offset += 16;
	}else {
		proto_tree_add_item(tree, hf_zebra_dest4, tvb, offset, 4,
				    ENC_BIG_ENDIAN);
		offset += 4;
	}
	if (!request) {
		proto_tree_add_item(tree, hf_zebra_metric,tvb, offset, 4,
				    ENC_BIG_ENDIAN);
		offset += 4;
		offset = zebra_route_nexthop(tree, request, tvb, offset, len,
					     family, version);
	}
	return offset;
}

static int
zerba_router_update(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	proto_tree_add_item(tree, hf_zebra_routeridfamily, tvb, offset, 1,
			    ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_zebra_routeridaddress, tvb,
			    offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_zebra_routeridmask, tvb,
			    offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	return offset;
}

static int
zebra_nexthop_update(proto_tree *tree, tvbuff_t *tvb, int offset,
		     guint8 version)
{
	guint16 family = tvb_get_ntohs(tvb, offset);
	guint8  prefixlen, nexthopcount, nexthoptype, labelnum;
	proto_tree_add_item(tree, hf_zebra_family, tvb, offset, 2,
			    ENC_BIG_ENDIAN);
	offset += 2;
	prefixlen = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tree, hf_zebra_prefixlen, tvb, offset, 1,
			    prefixlen);
	offset += 1;
	if (family == ZEBRA_FAMILY_IPV6) {
		proto_tree_add_item(tree, hf_zebra_prefix6, tvb, offset, 16,
				    ENC_NA);
		offset += 16;
	} else if (family == ZEBRA_FAMILY_IPV4) {
		proto_tree_add_item(tree, hf_zebra_prefix4, tvb, offset, 4,
				    ENC_BIG_ENDIAN);
		offset += 4;
	}

	if (version > 4) {
		proto_tree_add_item(tree, hf_zebra_type_v5, tvb, offset, 1,
				    ENC_BIG_ENDIAN);
		offset += 1;
	}

	if (version > 4) {
		proto_tree_add_item(tree, hf_zebra_instance, tvb, offset, 2,
				    ENC_BIG_ENDIAN);
		offset += 2;
	}
	if (version > 3) {
		proto_tree_add_item(tree, hf_zebra_distance, tvb, offset, 1,
				    ENC_BIG_ENDIAN);
		offset += 1;
	}

	proto_tree_add_item(tree, hf_zebra_metric, tvb, offset, 4,
			    ENC_BIG_ENDIAN);
	offset += 4;

	nexthopcount = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tree, hf_zebra_nexthopnum, tvb, offset, 1,
			    nexthopcount);
	offset += 1;

	while (nexthopcount--) {
		nexthoptype = tvb_get_guint8(tvb, offset);
		if (version > 3) {
			proto_tree_add_item(tree, hf_zebra_nexthoptype_frr, tvb,
					    offset, 1, ENC_BIG_ENDIAN);
		} else {
			proto_tree_add_item(tree, hf_zebra_nexthoptype, tvb,
					    offset, 1, ENC_BIG_ENDIAN);
		}
		offset += 1;

		if ((version < 4 &&
		     (nexthoptype == ZEBRA_NEXTHOP_TYPE_IPV6 ||
		      nexthoptype == ZEBRA_NEXTHOP_TYPE_IPV6_IFINDEX ||
		      nexthoptype == ZEBRA_NEXTHOP_TYPE_IPV6_IFNAME)) ||
		    (version >= 4 &&
		     (nexthoptype == FRR_NEXTHOP_TYPE_IPV6 ||
		      nexthoptype == FRR_NEXTHOP_TYPE_IPV6_IFINDEX))) {
			proto_tree_add_item(tree, hf_zebra_nexthop6, tvb,
					    offset, 16, ENC_NA);
			offset += 16;
		}
		if ((version < 4 &&
		     (nexthoptype == ZEBRA_NEXTHOP_TYPE_IPV4 ||
		      nexthoptype == ZEBRA_NEXTHOP_TYPE_IPV4_IFINDEX ||
		      nexthoptype == ZEBRA_NEXTHOP_TYPE_IPV4_IFNAME)) ||
		    (version >= 4 &&
		     (nexthoptype == FRR_NEXTHOP_TYPE_IPV4 ||
		      nexthoptype == FRR_NEXTHOP_TYPE_IPV4_IFINDEX))) {
			proto_tree_add_item(tree, hf_zebra_nexthop4, tvb,
					    offset, 4, ENC_NA);
			offset += 4;
		}
		if (nexthoptype == ZEBRA_NEXTHOP_TYPE_IFINDEX ||
		    (version < 4 &&
		     (nexthoptype == ZEBRA_NEXTHOP_TYPE_IFNAME ||
		      nexthoptype == ZEBRA_NEXTHOP_TYPE_IPV4_IFINDEX ||
		      nexthoptype == ZEBRA_NEXTHOP_TYPE_IPV4_IFNAME ||
		      nexthoptype == ZEBRA_NEXTHOP_TYPE_IPV6_IFINDEX ||
		      nexthoptype == ZEBRA_NEXTHOP_TYPE_IPV6_IFNAME)) ||
		    (version >= 4 &&
		     (nexthoptype == FRR_NEXTHOP_TYPE_IPV4 ||
		      nexthoptype == FRR_NEXTHOP_TYPE_IPV4_IFINDEX ||
		      nexthoptype == FRR_NEXTHOP_TYPE_IPV6 ||
		      nexthoptype == FRR_NEXTHOP_TYPE_IPV6_IFINDEX))) {
			proto_tree_add_item(tree, hf_zebra_index, tvb, offset,
					    4, ENC_BIG_ENDIAN);
			offset += 4;
		}
		if (version > 4) {
			labelnum = tvb_get_guint8(tvb, offset);
			proto_tree_add_uint(tree, hf_zebra_labelnum, tvb,
					    offset, 1, labelnum);
			offset += 1;
			while (labelnum--) {
				proto_tree_add_item(tree, hf_zebra_label, tvb,
						    offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}
		}
	}
	return offset;
}

static int
dissect_zebra_request(proto_tree *tree, gboolean request, tvbuff_t *tvb,
		      int offset, int left, guint16 len, guint16 command,
		      guint8 version)
{
	int init_offset = offset;
	proto_tree_add_uint(tree, hf_zebra_len, tvb, offset, 2, len);
	offset += 2;
	if (version != 0) {
		proto_tree_add_item(tree, hf_zebra_marker, tvb, offset, 1, ENC_NA);
		offset += 1;
		proto_tree_add_uint(tree, hf_zebra_version, tvb, offset, 1,
				    version);
		offset += 1;
		if (version == 3 || version == 4) {
			proto_tree_add_item(tree, hf_zebra_vrfid, tvb, offset,
					    2, ENC_BIG_ENDIAN);
			offset += 2;
		} else if (version > 4) {
			proto_tree_add_item(tree, hf_zebra_vrfid, tvb, offset,
					    4, ENC_BIG_ENDIAN);
			offset += 4;
		}
		if (version < 4) {
			proto_tree_add_uint(tree, hf_zebra_command, tvb, offset,
					    2, command);
		} else if (version == 4) {
			proto_tree_add_uint(tree, hf_zebra_command_v4, tvb,
					    offset, 2, command);
		} else if (version == 5) {
			proto_tree_add_uint(tree, hf_zebra_command_v5, tvb,
					    offset, 2, command);
		} else {
			proto_tree_add_uint(tree, hf_zebra_command_v6, tvb,
					    offset, 2, command);
		}
		offset += 2;
	} else {
		proto_tree_add_uint(tree, hf_zebra_command, tvb, offset, 1,
				    command);
		offset += 1;
	}

	if (version < 4) {
		switch (command) {
		case ZEBRA_INTERFACE_ADD:
		case ZEBRA_INTERFACE_DELETE:
		case ZEBRA_INTERFACE_UP:
		case ZEBRA_INTERFACE_DOWN:
			if (request)
				break; /* Request just subscribes to messages */
			offset = zebra_interface(tree, tvb, offset, command,
						 version);
			break;
		case ZEBRA_INTERFACE_ADDRESS_ADD:
		case ZEBRA_INTERFACE_ADDRESS_DELETE:
			offset = zebra_interface_address(tree, tvb, offset);
			break;
		case ZEBRA_IPV4_ROUTE_ADD:
		case ZEBRA_IPV4_ROUTE_DELETE:
			offset = zebra_route(tree, request, tvb, offset, len,
					     ZEBRA_FAMILY_IPV4, command, version);
			break;
		case ZEBRA_IPV6_ROUTE_ADD:
		case ZEBRA_IPV6_ROUTE_DELETE:
			offset = zebra_route(tree, request, tvb, offset, len,
					     ZEBRA_FAMILY_IPV6, command, version);
			break;
		case ZEBRA_REDISTRIBUTE_ADD:
		case ZEBRA_REDISTRIBUTE_DEFAULT_ADD:
			offset = zebra_redistribute(tree, tvb, offset, version);
			break;
		case ZEBRA_IPV4_IMPORT_LOOKUP:
		case ZEBRA_IPV4_NEXTHOP_LOOKUP:
			offset = zebra_nexthop_lookup(tree, request, tvb,
						      offset, len,
						      ZEBRA_FAMILY_IPV4,
						      version);
			break;
		case ZEBRA_IPV6_IMPORT_LOOKUP:
		case ZEBRA_IPV6_NEXTHOP_LOOKUP:
			offset = zebra_nexthop_lookup(tree, request, tvb,
						      offset, len,
						      ZEBRA_FAMILY_IPV6,
						      version);
			break;
		case ZEBRA_ROUTER_ID_UPDATE:
			offset = zerba_router_update(tree, tvb, offset);
			break;
		case ZEBRA_ROUTER_ID_ADD:
		case ZEBRA_ROUTER_ID_DELETE:
		case ZEBRA_REDISTRIBUTE_DEFAULT_DELETE:
			/* nothing to do */
			break;
		case ZEBRA_REDISTRIBUTE_DELETE:
			/* in version 1+, there's a route type field */
			if (version > 0) {
				proto_tree_add_item(tree, hf_zebra_type_v1, tvb,
						    offset, 1, ENC_BIG_ENDIAN);
			}
			break;
		case ZEBRA_HELLO:
			offset = zebra_hello(tree, tvb, offset, left, version);
			break;
		case ZEBRA_IPV4_NEXTHOP_LOOKUP_MRIB:
		case ZEBRA_VRF_UNREGISTER:
		case ZEBRA_INTERFACE_LINK_PARAMS:
			break;
		case ZEBRA_NEXTHOP_REGISTER:
		case ZEBRA_NEXTHOP_UNREGISTER:
			offset = zebra_nexthop_register(tree, tvb, offset, len,
							offset - init_offset);
			break;
		case ZEBRA_NEXTHOP_UPDATE:
			offset = zebra_nexthop_update(tree, tvb, offset, version);
			break;
		}
	} else if (version == 4) {
		switch (command) {
		case FRR_ZAPI4_INTERFACE_ADD:
		case FRR_ZAPI4_INTERFACE_UP:
		case FRR_ZAPI4_INTERFACE_DOWN:
		case FRR_ZAPI4_INTERFACE_DELETE:
			if (request)
				break; /* Request just subscribes to messages */
			offset = zebra_interface(tree, tvb, offset, command,
						 version);
			break;
		case FRR_ZAPI4_INTERFACE_ADDRESS_ADD:
		case FRR_ZAPI4_INTERFACE_ADDRESS_DELETE:
			offset = zebra_interface_address(tree, tvb, offset);
			break;
		case FRR_ZAPI4_IPV4_ROUTE_ADD:
		case FRR_ZAPI4_IPV4_ROUTE_DELETE:
		case FRR_ZAPI4_REDISTRIBUTE_IPV4_ADD:
		case FRR_ZAPI4_REDISTRIBUTE_IPV4_DEL:
			offset = zebra_route(tree, request, tvb, offset, len,
					     ZEBRA_FAMILY_IPV4, command,
					     version);
			break;
		case FRR_ZAPI4_IPV6_ROUTE_ADD:
		case FRR_ZAPI4_IPV6_ROUTE_DELETE:
		case FRR_ZAPI4_REDISTRIBUTE_IPV6_ADD:
		case FRR_ZAPI4_REDISTRIBUTE_IPV6_DEL:
			offset = zebra_route(tree, request, tvb, offset, len,
					     ZEBRA_FAMILY_IPV6, command,
					     version);
			break;
		case FRR_ZAPI4_REDISTRIBUTE_ADD:
		case FRR_ZAPI4_REDISTRIBUTE_DEFAULT_ADD:
			offset = zebra_redistribute(tree, tvb, offset, version);
			break;
		case FRR_ZAPI4_ROUTER_ID_UPDATE:
			offset = zerba_router_update(tree, tvb, offset);
			break;
		case FRR_ZAPI4_ROUTER_ID_ADD:
		case FRR_ZAPI4_ROUTER_ID_DELETE:
		case FRR_ZAPI4_REDISTRIBUTE_DEFAULT_DELETE:
			/* nothing to do */
			break;
		case FRR_ZAPI4_REDISTRIBUTE_DELETE:
			proto_tree_add_item(tree, hf_zebra_type_v4, tvb, offset,
					    1, ENC_BIG_ENDIAN);
			offset += 1;
			break;
		case FRR_ZAPI4_HELLO:
			offset = zebra_hello(tree, tvb, offset, left, version);
			break;
		case FRR_ZAPI4_NEXTHOP_REGISTER:
		case FRR_ZAPI4_NEXTHOP_UNREGISTER:
			offset = zebra_nexthop_register(tree, tvb, offset, len,
							offset - init_offset);
			break;
		case FRR_ZAPI4_NEXTHOP_UPDATE:
			offset = zebra_nexthop_update(tree, tvb, offset,
						      version);
			break;
		case FRR_ZAPI4_INTERFACE_NBR_ADDRESS_ADD:
		case FRR_ZAPI4_INTERFACE_NBR_ADDRESS_DELETE:
		case FRR_ZAPI4_INTERFACE_BFD_DEST_UPDATE:
		case FRR_ZAPI4_IMPORT_ROUTE_REGISTER:
		case FRR_ZAPI4_IMPORT_ROUTE_UNREGISTER:
		case FRR_ZAPI4_IMPORT_CHECK_UPDATE:
		case FRR_ZAPI4_IPV4_ROUTE_IPV6_NEXTHOP_ADD:
		case FRR_ZAPI4_BFD_DEST_REGISTER:
		case FRR_ZAPI4_BFD_DEST_DEREGISTER:
		case FRR_ZAPI4_BFD_DEST_UPDATE:
		case FRR_ZAPI4_BFD_DEST_REPLAY:
		case FRR_ZAPI4_VRF_UNREGISTER:
		case FRR_ZAPI4_VRF_ADD:
		case FRR_ZAPI4_VRF_DELETE:
		case FRR_ZAPI4_INTERFACE_VRF_UPDATE:
			break;
		case FRR_ZAPI4_BFD_CLIENT_REGISTER:
			proto_tree_add_item(tree, hf_zebra_pid, tvb, offset, 4,
					    ENC_BIG_ENDIAN);
			offset += 4;
			break;
		case FRR_ZAPI4_INTERFACE_ENABLE_RADV:
		case FRR_ZAPI4_INTERFACE_DISABLE_RADV:
		case FRR_ZAPI4_IPV4_NEXTHOP_LOOKUP_MRIB:
		case FRR_ZAPI4_INTERFACE_LINK_PARAMS:
		case FRR_ZAPI4_MPLS_LABELS_ADD:
		case FRR_ZAPI4_MPLS_LABELS_DELETE:
		case FRR_ZAPI4_IPV4_NEXTHOP_ADD:
		case FRR_ZAPI4_IPV4_NEXTHOP_DELETE:
		case FRR_ZAPI4_IPV6_NEXTHOP_ADD:
		case FRR_ZAPI4_IPV6_NEXTHOP_DELETE:
		case FRR_ZAPI4_IPMR_ROUTE_STATS:
		case FRR_ZAPI4_LABEL_MANAGER_CONNECT:
		case FRR_ZAPI4_GET_LABEL_CHUNK:
		case FRR_ZAPI4_RELEASE_LABEL_CHUNK:
		case FRR_ZAPI4_PW_ADD:
		case FRR_ZAPI4_PW_DELETE:
		case FRR_ZAPI4_PW_SET:
		case FRR_ZAPI4_PW_UNSET:
		case FRR_ZAPI4_PW_STATUS_UPDATE:
			break;
		}
	} else if (version == 5) {
		switch (command) {
		case FRR_ZAPI5_INTERFACE_ADD:
		case FRR_ZAPI5_INTERFACE_UP:
		case FRR_ZAPI5_INTERFACE_DOWN:
		case FRR_ZAPI5_INTERFACE_DELETE:
			if (request)
				break; /* Request just subscribes to messages */
			offset = zebra_interface(tree, tvb, offset, command,
						 version);
			break;
		case FRR_ZAPI5_INTERFACE_ADDRESS_ADD:
		case FRR_ZAPI5_INTERFACE_ADDRESS_DELETE:
			offset = zebra_interface_address(tree, tvb, offset);
			break;
		case FRR_ZAPI5_IPV4_ROUTE_ADD:
		case FRR_ZAPI5_IPV4_ROUTE_DELETE:
			offset = zebra_route(tree, request, tvb, offset, len,
					     ZEBRA_FAMILY_IPV4, command,
					     version);
			break;
		case FRR_ZAPI5_IPV6_ROUTE_ADD:
		case FRR_ZAPI5_IPV6_ROUTE_DELETE:
			offset = zebra_route(tree, request, tvb, offset, len,
					     ZEBRA_FAMILY_IPV6, command,
					     version);
			break;
		case FRR_ZAPI5_ROUTE_ADD:
		case FRR_ZAPI5_ROUTE_DELETE:
		case FRR_ZAPI5_REDISTRIBUTE_ROUTE_ADD:
		case FRR_ZAPI5_REDISTRIBUTE_ROUTE_DEL:
			offset = zebra_route(tree, request, tvb, offset, len,
					     ZEBRA_FAMILY_UNSPEC, command,
					     version);
			break;
		case FRR_ZAPI5_REDISTRIBUTE_ADD:
		case FRR_ZAPI5_REDISTRIBUTE_DEFAULT_ADD:
			offset = zebra_redistribute(tree, tvb, offset, version);
			break;
		case FRR_ZAPI5_ROUTER_ID_UPDATE:
			offset = zerba_router_update(tree, tvb, offset);
			break;
		case FRR_ZAPI5_ROUTER_ID_ADD:
		case FRR_ZAPI5_ROUTER_ID_DELETE:
		case FRR_ZAPI5_REDISTRIBUTE_DEFAULT_DELETE:
			/* nothing to do */
			break;
		case FRR_ZAPI5_REDISTRIBUTE_DELETE:
			proto_tree_add_item(tree, hf_zebra_type_v5, tvb, offset,
					    1, ENC_BIG_ENDIAN);
			offset += 1;
			break;
		case FRR_ZAPI5_HELLO:
			offset = zebra_hello(tree, tvb, offset, left, version);
			break;
		case FRR_ZAPI5_CAPABILITIES:
			offset = zebra_capabilties(tree, tvb, offset);
			break;
		case FRR_ZAPI5_NEXTHOP_REGISTER:
		case FRR_ZAPI5_NEXTHOP_UNREGISTER:
			offset = zebra_nexthop_register(tree, tvb, offset, len,
							offset - init_offset);
			break;
		case FRR_ZAPI5_NEXTHOP_UPDATE:
			offset = zebra_nexthop_update(tree, tvb, offset,
						      version);
			break;
		case FRR_ZAPI5_INTERFACE_NBR_ADDRESS_ADD:
		case FRR_ZAPI5_INTERFACE_NBR_ADDRESS_DELETE:
		case FRR_ZAPI5_INTERFACE_BFD_DEST_UPDATE:
		case FRR_ZAPI5_IMPORT_ROUTE_REGISTER:
		case FRR_ZAPI5_IMPORT_ROUTE_UNREGISTER:
		case FRR_ZAPI5_IMPORT_CHECK_UPDATE:
		case FRR_ZAPI5_IPV4_ROUTE_IPV6_NEXTHOP_ADD:
		case FRR_ZAPI5_BFD_DEST_REGISTER:
		case FRR_ZAPI5_BFD_DEST_DEREGISTER:
		case FRR_ZAPI5_BFD_DEST_UPDATE:
		case FRR_ZAPI5_BFD_DEST_REPLAY:
		case FRR_ZAPI5_VRF_UNREGISTER:
			break;
		case FRR_ZAPI5_VRF_ADD:
			offset = zebra_vrf(tree, tvb, offset);
			break;
		case FRR_ZAPI5_VRF_DELETE:
		case FRR_ZAPI5_VRF_LABEL:
		case FRR_ZAPI5_INTERFACE_VRF_UPDATE:
			break;
		case FRR_ZAPI5_BFD_CLIENT_REGISTER:
			proto_tree_add_item(tree, hf_zebra_pid, tvb, offset, 4,
					    ENC_BIG_ENDIAN);
			offset += 4;
			break;
		case FRR_ZAPI5_INTERFACE_ENABLE_RADV:
		case FRR_ZAPI5_INTERFACE_DISABLE_RADV:
		case FRR_ZAPI5_IPV4_NEXTHOP_LOOKUP_MRIB:
		case FRR_ZAPI5_INTERFACE_LINK_PARAMS:
		case FRR_ZAPI5_MPLS_LABELS_ADD:
		case FRR_ZAPI5_MPLS_LABELS_DELETE:
		case FRR_ZAPI5_IPMR_ROUTE_STATS:
			break;
		case FRR_ZAPI5_LABEL_MANAGER_CONNECT:
		case FRR_ZAPI5_LABEL_MANAGER_CONNECT_ASYNC:
			offset = zebra_label_manager_connect(tree, tvb, offset);
			break;
		case FRR_ZAPI5_GET_LABEL_CHUNK:
			offset =
			    zebra_get_label_chunk(tree, request, tvb, offset);
			break;
		case FRR_ZAPI5_RELEASE_LABEL_CHUNK:
		case FRR_ZAPI5_FEC_REGISTER:
		case FRR_ZAPI5_FEC_UNREGISTER:
		case FRR_ZAPI5_FEC_UPDATE:
		case FRR_ZAPI5_ADVERTISE_DEFAULT_GW:
		case FRR_ZAPI5_ADVERTISE_SUBNET:
		case FRR_ZAPI5_ADVERTISE_ALL_VNI:
		case FRR_ZAPI5_VNI_ADD:
		case FRR_ZAPI5_VNI_DEL:
		case FRR_ZAPI5_L3VNI_ADD:
		case FRR_ZAPI5_L3VNI_DEL:
		case FRR_ZAPI5_REMOTE_VTEP_ADD:
		case FRR_ZAPI5_REMOTE_VTEP_DEL:
		case FRR_ZAPI5_MACIP_ADD:
		case FRR_ZAPI5_MACIP_DEL:
		case FRR_ZAPI5_IP_PREFIX_ROUTE_ADD:
		case FRR_ZAPI5_IP_PREFIX_ROUTE_DEL:
		case FRR_ZAPI5_REMOTE_MACIP_ADD:
		case FRR_ZAPI5_REMOTE_MACIP_DEL:
		case FRR_ZAPI5_PW_ADD:
		case FRR_ZAPI5_PW_DELETE:
		case FRR_ZAPI5_PW_SET:
		case FRR_ZAPI5_PW_UNSET:
		case FRR_ZAPI5_PW_STATUS_UPDATE:
		case FRR_ZAPI5_RULE_ADD:
		case FRR_ZAPI5_RULE_DELETE:
		case FRR_ZAPI5_RULE_NOTIFY_OWNER:
		case FRR_ZAPI5_TABLE_MANAGER_CONNECT:
		case FRR_ZAPI5_GET_TABLE_CHUNK:
		case FRR_ZAPI5_RELEASE_TABLE_CHUNK:
		case FRR_ZAPI5_IPSET_CREATE:
		case FRR_ZAPI5_IPSET_DESTROY:
		case FRR_ZAPI5_IPSET_ENTRY_ADD:
		case FRR_ZAPI5_IPSET_ENTRY_DELETE:
		case FRR_ZAPI5_IPSET_NOTIFY_OWNER:
		case FRR_ZAPI5_IPSET_ENTRY_NOTIFY_OWNER:
		case FRR_ZAPI5_IPTABLE_ADD:
		case FRR_ZAPI5_IPTABLE_DELETE:
		case FRR_ZAPI5_IPTABLE_NOTIFY_OWNER:
			break;
		}
	} else { /* version 6 */
		switch (command) {
		case FRR_ZAPI6_INTERFACE_ADD:
		case FRR_ZAPI6_INTERFACE_UP:
		case FRR_ZAPI6_INTERFACE_DOWN:
		case FRR_ZAPI6_INTERFACE_DELETE:
			if (request)
				break; /* Request just subscribes to messages */
			offset = zebra_interface(tree, tvb, offset, command,
						 version);
			break;
		case FRR_ZAPI6_INTERFACE_ADDRESS_ADD:
		case FRR_ZAPI6_INTERFACE_ADDRESS_DELETE:
			offset = zebra_interface_address(tree, tvb, offset);
			break;
		case FRR_ZAPI6_ROUTE_ADD:
		case FRR_ZAPI6_ROUTE_DELETE:
		case FRR_ZAPI6_REDISTRIBUTE_ROUTE_ADD:
		case FRR_ZAPI6_REDISTRIBUTE_ROUTE_DEL:
			offset = zebra_route(tree, request, tvb, offset, len,
					     ZEBRA_FAMILY_UNSPEC, command,
					     version);
			break;
		case FRR_ZAPI6_REDISTRIBUTE_ADD:
		case FRR_ZAPI6_REDISTRIBUTE_DEFAULT_ADD:
			offset = zebra_redistribute(tree, tvb, offset, version);
			break;
		case FRR_ZAPI6_ROUTER_ID_UPDATE:
			offset = zerba_router_update(tree, tvb, offset);
			break;
		case FRR_ZAPI6_ROUTER_ID_ADD:
		case FRR_ZAPI6_ROUTER_ID_DELETE:
		case FRR_ZAPI6_REDISTRIBUTE_DEFAULT_DELETE:
			/* nothing to do */
			break;
		case FRR_ZAPI6_REDISTRIBUTE_DELETE:
			proto_tree_add_item(tree, hf_zebra_type_v5, tvb, offset,
					    1, ENC_BIG_ENDIAN);
			offset += 1;
			break;
		case FRR_ZAPI6_HELLO:
			offset = zebra_hello(tree, tvb, offset, left, version);
			break;
		case FRR_ZAPI6_CAPABILITIES:
			offset = zebra_capabilties(tree, tvb, offset);
			break;
		case FRR_ZAPI6_NEXTHOP_REGISTER:
		case FRR_ZAPI6_NEXTHOP_UNREGISTER:
			offset = zebra_nexthop_register(tree, tvb, offset, len,
							offset - init_offset);
			break;
		case FRR_ZAPI6_NEXTHOP_UPDATE:
			offset = zebra_nexthop_update(tree, tvb, offset,
						      version);
			break;
		case FRR_ZAPI6_INTERFACE_NBR_ADDRESS_ADD:
		case FRR_ZAPI6_INTERFACE_NBR_ADDRESS_DELETE:
		case FRR_ZAPI6_INTERFACE_BFD_DEST_UPDATE:
		case FRR_ZAPI6_IMPORT_ROUTE_REGISTER:
		case FRR_ZAPI6_IMPORT_ROUTE_UNREGISTER:
		case FRR_ZAPI6_IMPORT_CHECK_UPDATE:
		//case FRR_ZAPI6_IPV4_ROUTE_IPV6_NEXTHOP_ADD:
		case FRR_ZAPI6_BFD_DEST_REGISTER:
		case FRR_ZAPI6_BFD_DEST_DEREGISTER:
		case FRR_ZAPI6_BFD_DEST_UPDATE:
		case FRR_ZAPI6_BFD_DEST_REPLAY:
		case FRR_ZAPI6_VRF_UNREGISTER:
			break;
		case FRR_ZAPI6_VRF_ADD:
			offset = zebra_vrf(tree, tvb, offset);
			break;
		case FRR_ZAPI6_VRF_DELETE:
		case FRR_ZAPI6_VRF_LABEL:
		case FRR_ZAPI6_INTERFACE_VRF_UPDATE:
			break;
		case FRR_ZAPI6_BFD_CLIENT_REGISTER:
			proto_tree_add_item(tree, hf_zebra_pid, tvb, offset, 4,
					    ENC_BIG_ENDIAN);
			offset += 4;
			break;
		case FRR_ZAPI6_BFD_CLIENT_DEREGISTER:
		case FRR_ZAPI6_INTERFACE_ENABLE_RADV:
		case FRR_ZAPI6_INTERFACE_DISABLE_RADV:
		case FRR_ZAPI6_IPV4_NEXTHOP_LOOKUP_MRIB:
		case FRR_ZAPI6_INTERFACE_LINK_PARAMS:
		case FRR_ZAPI6_MPLS_LABELS_ADD:
		case FRR_ZAPI6_MPLS_LABELS_DELETE:
		case FRR_ZAPI6_IPMR_ROUTE_STATS:
			break;
		case FRR_ZAPI6_LABEL_MANAGER_CONNECT:
		case FRR_ZAPI6_LABEL_MANAGER_CONNECT_ASYNC:
			offset = zebra_label_manager_connect(tree, tvb, offset);
			break;
		case FRR_ZAPI6_GET_LABEL_CHUNK:
			offset =
			    zebra_get_label_chunk(tree, request, tvb, offset);
			break;
		case FRR_ZAPI6_RELEASE_LABEL_CHUNK:
		case FRR_ZAPI6_FEC_REGISTER:
		case FRR_ZAPI6_FEC_UNREGISTER:
		case FRR_ZAPI6_FEC_UPDATE:
		case FRR_ZAPI6_ADVERTISE_DEFAULT_GW:
		case FRR_ZAPI6_ADVERTISE_SUBNET:
		case FRR_ZAPI6_ADVERTISE_ALL_VNI:
		case FRR_ZAPI6_LOCAL_ES_ADD:
		case FRR_ZAPI6_LOCAL_ES_DEL:
		case FRR_ZAPI6_VNI_ADD:
		case FRR_ZAPI6_VNI_DEL:
		case FRR_ZAPI6_L3VNI_ADD:
		case FRR_ZAPI6_L3VNI_DEL:
		case FRR_ZAPI6_REMOTE_VTEP_ADD:
		case FRR_ZAPI6_REMOTE_VTEP_DEL:
		case FRR_ZAPI6_MACIP_ADD:
		case FRR_ZAPI6_MACIP_DEL:
		case FRR_ZAPI6_IP_PREFIX_ROUTE_ADD:
		case FRR_ZAPI6_IP_PREFIX_ROUTE_DEL:
		case FRR_ZAPI6_REMOTE_MACIP_ADD:
		case FRR_ZAPI6_REMOTE_MACIP_DEL:
		case FRR_ZAPI6_PW_ADD:
		case FRR_ZAPI6_PW_DELETE:
		case FRR_ZAPI6_PW_SET:
		case FRR_ZAPI6_PW_UNSET:
		case FRR_ZAPI6_PW_STATUS_UPDATE:
		case FRR_ZAPI6_RULE_ADD:
		case FRR_ZAPI6_RULE_DELETE:
		case FRR_ZAPI6_RULE_NOTIFY_OWNER:
		case FRR_ZAPI6_TABLE_MANAGER_CONNECT:
		case FRR_ZAPI6_GET_TABLE_CHUNK:
		case FRR_ZAPI6_RELEASE_TABLE_CHUNK:
		case FRR_ZAPI6_IPSET_CREATE:
		case FRR_ZAPI6_IPSET_DESTROY:
		case FRR_ZAPI6_IPSET_ENTRY_ADD:
		case FRR_ZAPI6_IPSET_ENTRY_DELETE:
		case FRR_ZAPI6_IPSET_NOTIFY_OWNER:
		case FRR_ZAPI6_IPSET_ENTRY_NOTIFY_OWNER:
		case FRR_ZAPI6_IPTABLE_ADD:
		case FRR_ZAPI6_IPTABLE_DELETE:
		case FRR_ZAPI6_IPTABLE_NOTIFY_OWNER:
		case FRR_ZAPI6_VXLAN_FLOOD_CONTROL:
			break;
		}
	}
	return offset;
}

/*
 Zebra Protocol header version 0:
	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-------------------------------+---------------+
	|           Length (2)          |   Command (1) |
	+-------------------------------+---------------+

 Zebra Protocol header version 1:
	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-------------------------------+---------------+-------------+
	|           Length (2)          |   Marker (1)  | Version (1) |
	+-------------------------------+---------------+-------------+
	|          Command (2)          |
	+-------------------------------+
 The Marker is 0xFF to distinguish it from a version 0 header.
 */
static int
dissect_zebra(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item	*ti;
	proto_tree	*zebra_tree;
	gboolean	request;
	int		left, offset;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ZEBRA");

	request = (pinfo->destport == pinfo->match_uint);
	left = tvb_reported_length(tvb);
	offset = 0;

	col_set_str(pinfo->cinfo, COL_INFO,
		    request? "Zebra Request" : "Zebra Reply");

	/* if (tree) */ {
		ti = proto_tree_add_item(tree, proto_zebra, tvb, offset, -1,
					 ENC_NA);
		zebra_tree = proto_item_add_subtree(ti, ett_zebra);
		ti = proto_tree_add_boolean(zebra_tree, hf_zebra_request,
					    tvb, offset, 0, request);
		proto_item_set_hidden(ti);

		for (;;) {
			guint8 		headermarker, version;
			guint16		command, len;
			proto_tree	*zebra_request_tree;

			if (left < 3)
				break;
			len = tvb_get_ntohs(tvb, offset);
			if (len < 3)
				break;

			headermarker = tvb_get_guint8(tvb,offset+2);
			// header marker is 255(0xFF) on version 1, 2 and 3
			// header marker is 254(0XFE) on version 4 and 5 (FRRouting)
			if (headermarker < 0xFE) { // version 0
				// header marker is not contained in vesion 0 header
				command = headermarker;
				version = 0;
			} else { // not version 0
				version = tvb_get_guint8(tvb, offset+3);
				if (version == 1 || version == 2) {
					command = tvb_get_ntohs(tvb, offset + 4);
				} else if (version == 3 || version == 4) {
					command = tvb_get_ntohs(tvb, offset + 6);
				} else {
					command = tvb_get_ntohs(tvb, offset + 8);
				}
			}

			if (version < 4) {
				col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
						val_to_str(command, messages,
							   "Command Type 0x%02d"));
				ti = proto_tree_add_uint(zebra_tree, hf_zebra_command,
							 tvb, offset, len, command);
			} else if (version == 4) {
				ti = proto_tree_add_uint(zebra_tree, hf_zebra_command_v4,
							 tvb, offset, len, command);
				col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
						val_to_str(command, frr_zapi4_messages,
							   "Command Type 0x%02d"));
			} else if (version == 5) {
				ti = proto_tree_add_uint(zebra_tree, hf_zebra_command_v5,
							 tvb, offset, len, command);
				col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
						val_to_str(command, frr_zapi5_messages,
							   "Command Type 0x%02d"));
			} else {
				ti = proto_tree_add_uint(zebra_tree, hf_zebra_command_v6,
							 tvb, offset, len, command);
				col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
						val_to_str(command, frr_zapi6_messages,
							   "Command Type 0x%02d"));
			}
			zebra_request_tree = proto_item_add_subtree(ti,
							ett_zebra_request);
			dissect_zebra_request(zebra_request_tree, request, tvb,
					      offset, left, len, command, version);
			offset += len;
			left -= len;
		}
	}

	return tvb_captured_length(tvb);
}

void
proto_register_zebra(void)
{

	static hf_register_info hf[] = {
		{ &hf_zebra_len,
		  { "Length",		"zebra.len",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Length of Zebra request", HFILL }},
		{ &hf_zebra_version,
		  { "Version", 		"zebra.version",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Zerbra srv version", HFILL }},
		{ &hf_zebra_marker,
		  { "Marker", 		"zebra.marker",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    "Zerbra srv marker", HFILL }},
		{ &hf_zebra_request,
		  { "Request",		"zebra.request",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    "TRUE if Zebra request", HFILL }},
		{ &hf_zebra_command,
		  { "Command",		"zebra.command",
		    FT_UINT8, BASE_DEC, VALS(messages), 0x0,
		    "Zebra command", HFILL }},
		{ &hf_zebra_interface,
		  { "Interface",		"zebra.interface",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Interface name of Zebra request", HFILL }},
		{ &hf_zebra_index,
		  { "Index",		"zebra.index",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Index of interface", HFILL }},
		{ &hf_zebra_intstatus,
		  { "Status",		"zebra.intstatus",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Status of interface", HFILL}},
		{ &hf_zebra_indexnum,
		  { "Index Number",		"zebra.indexnum",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Number of indices for route", HFILL }},
		{ &hf_zebra_intflags,
		  { "Flags",		"zebra.intflags",
		    FT_UINT64, BASE_DEC, NULL, 0x0,
		    "Flags of interface", HFILL }},
		{ &hf_zebra_rtflags,
		  { "Flags",		"zebra.rtflags",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Flags of route", HFILL }},
		{ &hf_zebra_message,
		  { "Message",		"zebra.message",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Message type of route", HFILL }},
		{ &hf_zebra_route_safi,
		  { "SAFI",		"zebra.safi",
		    FT_UINT16, BASE_DEC, VALS(safi), 0x0,
		    "Subsequent Address Family Identifier", HFILL }},
		{ &hf_zebra_msg_nexthop,
		  { "Message Nexthop",	"zebra.message.nexthop",
		    FT_BOOLEAN, 8, NULL, ZEBRA_ZAPI_MESSAGE_NEXTHOP,
		    "Message contains nexthop", HFILL }},
		{ &hf_zebra_msg_index,
		  { "Message Index",	"zebra.message.index",
		    FT_BOOLEAN, 8, NULL, ZEBRA_ZAPI_MESSAGE_IFINDEX,
		    "Message contains index", HFILL }},
		{ &hf_zebra_msg_distance,
		  { "Message Distance",	"zebra.message.distance",
		    FT_BOOLEAN, 8, NULL, ZEBRA_ZAPI_MESSAGE_DISTANCE,
		    "Message contains distance", HFILL }},
		{ &hf_zebra_msg_metric,
		  { "Message Metric",	"zebra.message.metric",
		    FT_BOOLEAN, 8, NULL, ZEBRA_ZAPI_MESSAGE_METRIC,
		    "Message contains metric", HFILL }},
		{ &hf_zebra_type_v0,
		  { "Type",			"zebra.type",
		    FT_UINT8, BASE_DEC, VALS(routes_v0), 0x0,
		    "Type of route", HFILL }},
		{ &hf_zebra_type_v1,
		  { "Type",			"zebra.type",
		    FT_UINT8, BASE_DEC, VALS(routes_v1), 0x0,
		    "Type of route", HFILL }},
		{ &hf_zebra_distance,
		  { "Distance",		"zebra.distance",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Distance of route", HFILL }},
		{ &hf_zebra_metric,
		  { "Metric",		"zebra.metric",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Metric of interface or route", HFILL }},
		{ &hf_zebra_mtu,
		  { "MTU",			"zebra.mtu",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "MTU of interface", HFILL }},
		{ &hf_zebra_mtu6,
		  { "MTUv6",		"zebra.mtu6",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "MTUv6 of interface", HFILL }},
		{ &hf_zebra_bandwidth,
		  { "Bandwidth",		"zebra.bandwidth",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Bandwidth of interface", HFILL }},
		{ &hf_zebra_family,
		  { "Family",		"zebra.family",
		    FT_UINT8, BASE_DEC, VALS(families), 0x0,
		    "Family of IP address", HFILL }},
		{ &hf_zebra_flags,
		  { "Flags",		"zebra.flags",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Flags of Address Info", HFILL }},
		{ &hf_zebra_dest4,
		  { "Destination",		"zebra.dest4",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    "Destination IPv4 field", HFILL }},
		{ &hf_zebra_dest6,
		  { "Destination",		"zebra.dest6",
		    FT_IPv6, BASE_NONE, NULL, 0x0,
		    "Destination IPv6 field", HFILL }},
		{ &hf_zebra_nexthopnum,
		  { "Nexthop Number",	"zebra.nexthopnum",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Number of nexthops in route", HFILL }},
		{ &hf_zebra_nexthop4,
		  { "Nexthop",		"zebra.nexthop4",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    "Nethop IPv4 field of route", HFILL }},
		{ &hf_zebra_nexthop6,
		  { "Nexthop",		"zebra.nexthop6",
		    FT_IPv6, BASE_NONE, NULL, 0x0,
		    "Nethop IPv6 field of route", HFILL }},
		{ &hf_zebra_prefixlen,
		  { "Prefix length",	"zebra.prefixlen",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_zebra_prefix4,
		  { "Prefix",		"zebra.prefix4",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    "Prefix IPv4", HFILL }},
		{ &hf_zebra_prefix6,
		  { "Prefix",		"zebra.prefix6",
		    FT_IPv6, BASE_NONE, NULL, 0x0,
		    "Prefix IPv6", HFILL }},
		{ &hf_zebra_routeridaddress,
		  { "Router ID address",	"zebra.routerIDAddress",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    "Router ID", HFILL }},
		{ &hf_zebra_routeridmask,
		  { "Router ID mask",	"zebra.routerIDMask",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "netmask of Router ID", HFILL }},
		{ &hf_zebra_mac,
		  { "MAC address",	"zebra.macaddress",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    "MAC address of interface", HFILL }},
		{ &hf_zebra_redist_default,
		  { "Redistribute default",		"zebra.redist_default",
		    FT_BOOLEAN,  BASE_NONE, NULL, 0x0,
		    "TRUE if redistribute default", HFILL }},
		{ &hf_zebra_vrfid,
		  { "VRF-ID",		"zebra.vrfid",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "VRF ID", HFILL }},
		{ &hf_zebra_routeridfamily,
		  { "Router ID Family",	"zebra.routeridfamily",
		    FT_UINT8, BASE_DEC, VALS(families), 0x0,
		    "Family of Router ID", HFILL }},
		{ &hf_zebra_nexthoptype,
		  { "Nexthop Type",	"zebra.nexthoptype",
		    FT_UINT8, BASE_DEC, VALS(zebra_nht), 0x0,
		    "Type of Nexthop", HFILL }},
		{ &hf_zebra_msg_mtu,
		  { "Message MTU",	"zebra.message.mtu",
		    FT_BOOLEAN, 8, NULL, ZEBRA_ZAPI_MESSAGE_MTU,
		    "Message contains MTU", HFILL }},
		{ &hf_zebra_msg_tag,
		  { "Message TAG",	"zebra.message.tag",
		    FT_BOOLEAN, 8, NULL, ZEBRA_ZAPI_MESSAGE_TAG,
		    "Message contains TAG", HFILL }},
		{ &hf_zebra_tag,
		  { "Tag",		"zebra.tag",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Route Tag", HFILL }},
		{ &hf_zebra_maclen,
		  { "MAC address length", "zebra.maclen",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Length of MAC address of interface", HFILL }},
		{ &hf_zebra_haslinkparam,
		  { "Message has link parameters", "zebra.haslinkparam",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    "Interface message has link parameters", HFILL }},
		/* FRRouting, Zebra API v4, v5 and v6 */
		{ &hf_zebra_command_v4,
		  { "Command",		"zebra.command",
		    FT_UINT8, BASE_DEC, VALS(frr_zapi4_messages), 0x0,
		    "Zebra command", HFILL }},
		{ &hf_zebra_command_v5,
		  { "Command",		"zebra.command",
		    FT_UINT8, BASE_DEC, VALS(frr_zapi5_messages), 0x0,
		    "Zebra command", HFILL }},
		{ &hf_zebra_command_v6,
		  { "Command",		"zebra.command",
		    FT_UINT8, BASE_DEC, VALS(frr_zapi6_messages), 0x0,
		    "Zebra command", HFILL }},
		{ &hf_zebra_type_v4,
		  { "Type",		"zebra.type",
		    FT_UINT8, BASE_DEC, VALS(routes_v4), 0x0,
		    "Type of route", HFILL }},
		{ &hf_zebra_type_v5,
		  { "Type",		"zebra.type",
		    FT_UINT8, BASE_DEC, VALS(routes_v5), 0x0,
		    "Type of route", HFILL }},
		{ &hf_zebra_ptmenable,
		  { "PTM Enable",	"zebra.ptmenable",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "PTM (Prescriptive Topology Manager) Enable", HFILL }},
		{ &hf_zebra_ptmstatus,
		  { "PTM Status",	"zebra.ptmstatus",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "PTM (Prescriptive Topology Manager) Status", HFILL }},
		{ &hf_zebra_instance,
		  { "Instance",		"zebra.instance",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Routing Instance", HFILL }},
		{ &hf_zebra_rtflags_u32,
		  { "Flags",		"zebra.rtflags",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Flags of route", HFILL }},
		{ &hf_zebra_speed,
		  { "Speed",		"zebra.speed",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Speed of interface", HFILL }},
		{ &hf_zebra_lltype,
		  { "LLType",		"zebra.lltype",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Link Layer Type", HFILL }},
		{ &hf_zebra_message4,
		  { "Message",		"zebra.message",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Message type of route", HFILL }},
		{ &hf_zebra_message5,
		  { "Message",		"zebra.message",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Message type of route", HFILL }},
		{ &hf_zebra_route_safi_u8,
		  { "SAFI",		"zebra.safi",
		    FT_UINT8, BASE_DEC, VALS(safi), 0x0,
		    "Subsequent Address Family Identifier", HFILL }},
		{ &hf_zebra_rmac,
		  { "RMAC",		"zebra.rmac",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    "Remote MAC", HFILL }},
		{ &hf_zebra_msg4_tag,
		  { "Message TAG",	"zebra.message.tag",
		    FT_BOOLEAN, 8, NULL, FRR_ZAPI4_MESSAGE_TAG,
		    "Message contains TAG", HFILL }},
		{ &hf_zebra_msg4_mtu,
		  { "Message MTU",	"zebra.message.mtu",
		    FT_BOOLEAN, 8, NULL, FRR_ZAPI4_MESSAGE_MTU,
		    "Message contains MTU", HFILL }},
		{ &hf_zebra_msg4_srcpfx,
		  { "Message Source Prefix", "zebra.message.srcpfx",
		    FT_BOOLEAN, 8, NULL, FRR_ZAPI4_MESSAGE_SRCPFX,
		    "Message contains Source Prefix",
		    HFILL }},
		{ &hf_zebra_msg5_distance,
		  { "Message Distance",	"zebra.message.distance",
		    FT_BOOLEAN, 8, NULL, FRR_ZAPI5_MESSAGE_DISTANCE,
		    "Message contains distance", HFILL }},
		{ &hf_zebra_msg5_metric,
		  { "Message Metric",	"zebra.message.metric",
		    FT_BOOLEAN, 8, NULL, FRR_ZAPI5_MESSAGE_METRIC,
		    "Message contains metric", HFILL }},
		{ &hf_zebra_msg5_tag,
		  { "Message TAG",	"zebra.message.tag",
		    FT_BOOLEAN, 8, NULL, FRR_ZAPI5_MESSAGE_TAG,
		    "Message contains TAG", HFILL }},
		{ &hf_zebra_msg5_mtu,
		  { "Message MTU",	"zebra.message.mtu",
		    FT_BOOLEAN, 8, NULL, FRR_ZAPI5_MESSAGE_MTU,
		    "Message contains MTU", HFILL }},
		{ &hf_zebra_msg5_srcpfx,
		  { "Message Source Prefix", "zebra.message.srcpfx",
		    FT_BOOLEAN, 8, NULL, FRR_ZAPI5_MESSAGE_SRCPFX,
		    "Message contains Source Prefix", HFILL }},
		{ &hf_zebra_msg_label,
		  { "Message Label",	"zebra.message.label",
		    FT_BOOLEAN, 8, NULL, FRR_ZAPI5_MESSAGE_LABEL,
		    "Message contains Label", HFILL }},
		{ &hf_zebra_msg_tableid,
		  { "Message Table ID",	"zebra.message.tableid",
		    FT_BOOLEAN, 8, NULL, FRR_ZAPI5_MESSAGE_TABLEID,
		    "Message contains Table ID", HFILL }},
		{ &hf_zebra_nexthopnum_u16,
		  { "Nexthop Number",	"zebra.nexthopnum",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Number of nexthops in route", HFILL }},
		{ &hf_zebra_nexthoptype_frr,
		  { "Nexthop Type",	"zebra.nexthoptype",
		    FT_UINT8, BASE_DEC, VALS(frr_nht), 0x0,
		    "Type of Nexthop", HFILL }},
		{ &hf_zebra_bhtype,
		  { "BHType",		"zebra.bhtype",
		    FT_UINT8, BASE_DEC, VALS(blackhole_type), 0x0,
		    "Bkackhole Type", HFILL }},
		{ &hf_zebra_srcprefixlen,
		  { "Source Prefix length", "zebra.srcprefixlen",
		    FT_UINT32, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_zebra_srcprefix4,
		  { "Source Prefix",	"zebra.srcprefix4",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    "Source Prefix IPv4", HFILL }},
		{ &hf_zebra_srcprefix6,
		  { "Source Prefix",	"zebra.srcprefix6",
		    FT_IPv6, BASE_NONE, NULL, 0x0,
		    "Source Prefix IPv6", HFILL }},
		{ &hf_zebra_tableid,
		  { "Table ID",		"zebra.tableid",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Routing Table ID", HFILL }},
		{ &hf_zebra_afi,
		  { "AFI",		"zebra.afi",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "AFI (Address Family Identifiers)", HFILL }},
		{ &hf_zebra_pid,
		  { "PID",		"zebra.pid",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Process ID", HFILL }},
		{ &hf_zebra_vrf_table_id,
		  { "VRF Table ID",	"zebra.vrftableid",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "VRF Routing Table ID", HFILL }},
		{ &hf_zebra_vrf_netns_name,
		  { "VRF NETNS Name",	"zebra.vrfnetnsname",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "VRF (Virtual Routing and Forwarding) Network Namespace Name",
		    HFILL }},
		{ &hf_zebra_vrf_name,
		  { "VRF Name",		"zebra.vrfname",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "VRF (Virtual Routing and Forwarding) Name", HFILL }},
		{ &hf_zebra_proto,
		  { "Protocol",		"zebra.proto",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Protocol of client", HFILL }},
		{ &hf_zebra_label_chunk_keep,
		  { "Label Chunk Keep",	"zebra.label_chunk_keep",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Keep of Lable Chunk", HFILL }},
		{ &hf_zebra_label_chunk_size,
		  { "Label Chunk Size",	"zebra.label_chunk_size",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Size of Lable Chunk", HFILL }},
		{ &hf_zebra_label_chunk_start,
		  { "Label Chunk Start","zebra.label_chunk_start",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Start of Lable Chunk", HFILL }},
		{ &hf_zebra_label_chunk_end,
		  { "Label Chunk End",	"zebra.label_chunk_end",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "End of Lable Chunk", HFILL }},
		{ &hf_zebra_mpls_enabled,
		  { "MPLS Enabled",	"zebra.mpls_enabled",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    "MPLS enabled capablity", HFILL }},
		{ &hf_zebra_multipath_num,
		  { "Multipath Number",	"zebra.multipath_num",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Number of Multipath", HFILL }},
		{ &hf_zebra_labelnum,
		  { "Label Number",	"zebra.labelnum",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Number of Labels", HFILL }},
		{ &hf_zebra_label,
		  { "Label",		"zebra.label",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "MPLS Label", HFILL }},
		{ &hf_zebra_receive_notify,
		  { "Receive Notify",	"zebra.receive_notify",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    "TRUE if receive notify", HFILL }}
	};

	static gint *ett[] = {
		&ett_zebra,
		&ett_zebra_request,
		&ett_message,
	};

	proto_zebra = proto_register_protocol("Zebra Protocol", "ZEBRA", "zebra");
	proto_register_field_array(proto_zebra, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_zebra(void)
{
	dissector_handle_t zebra_handle;

	zebra_handle = create_dissector_handle(dissect_zebra, proto_zebra);
	dissector_add_uint_with_preference("tcp.port", TCP_PORT_ZEBRA, zebra_handle);
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
