/* packet-netlink-route.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* man 7 rtnetlink */

#include "config.h"

#include <epan/packet.h>
#include <epan/aftypes.h>
#include <epan/to_str.h>

#include "packet-arp.h"
#include "packet-netlink.h"

void proto_register_netlink_route(void);
void proto_reg_handoff_netlink_route(void);

/*
 * The "legacy" flag indicates that the packet is a legacy dump
 * request message.
 *
 * Some legacy tools, including iproute2 < 3.9, issue shorter RTM_GETLINK
 * and RTM_GETADDR dump queries which only contain struct rtgenmsg rather
 * than struct ifinfomsg. As noted in kernel comment in rtnl_dump_ifinfo(),
 * these legacy requests will be (even with attributes) always shorter than
 * struct ifinfomsg so that they are easy to detect.
 *
 * Similar problem can be observed with tools using nl_rtgen_request()
 * function from libnl3; this also affects other RTM_GET* types.
 *
 * If such legacy message is detected by length shorter than expected data
 * structure, we parse it as this legacy version with (1-byte) struct
 * rtgenmsg so that it's shown as intended rather than as malformed.
 *
 * The legacy messages appear, from looking at the iproute2 3.1.0 code,
 * to be a structure containing a struct nlmsghdr followed by a struct
 * rtgenmsg.
 *
 * struct rtgenmsg contains only a 1-byte address family value, as noted.
 * *However*, a struct nlmsghdr has a 4-byte length field, and is, as a
 * result, aligned on a 4-byte boundary, so the structure containing those
 * two structures is also aligned on a 4-byte boundary, and thus has a
 * length that's a multiple of 4 bytes.  Therefore, there are 3 bytes of
 * padding following the address family byte.
 *
 * The message length, however, doesn't include those bytes.
 *
 * Legacy messages don't include any attributes - they're not large enough
 * to contain anything other than the netlink message header and the one-byte
 * address family.  For legacy messages, the attribute we hand to
 * dissect_netlink_route_attributes() is not aligned on a 4-byte boundary,
 * as it's the offset right after the 1-byte address family value;
 * dissect_netlink_route_attributes() will try to align that on a 4-byte
 * boundary, but that will go past the "immediately after the end of
 * the packet" offset, which can cause problems if any checking is done
 * to make sure the offset is valid.  Therefore, we don't try to dissect
 * the attributes, rather than relying on the attributes dissector to
 * discover that there's nothing left in the packet.
 */
struct netlink_route_info {
	packet_info *pinfo;
	bool legacy;
};

enum {
/* rtnetlink values for nlmsghdr.nlmsg_type from <include/uapi/linux/rtnetlink.h> */
	WS_RTM_NEWLINK      = 16,
	WS_RTM_DELLINK      = 17,
	WS_RTM_GETLINK      = 18,
	WS_RTM_SETLINK      = 19,
	WS_RTM_NEWADDR      = 20,
	WS_RTM_DELADDR      = 21,
	WS_RTM_GETADDR      = 22,
	WS_RTM_NEWROUTE     = 24,
	WS_RTM_DELROUTE     = 25,
	WS_RTM_GETROUTE     = 26,
	WS_RTM_NEWNEIGH     = 28,
	WS_RTM_DELNEIGH     = 29,
	WS_RTM_GETNEIGH     = 30,
	WS_RTM_NEWRULE      = 32,
	WS_RTM_DELRULE      = 33,
	WS_RTM_GETRULE      = 34,
	WS_RTM_NEWQDISC     = 36,
	WS_RTM_DELQDISC     = 37,
	WS_RTM_GETQDISC     = 38,
	WS_RTM_NEWTCLASS    = 40,
	WS_RTM_DELTCLASS    = 41,
	WS_RTM_GETTCLASS    = 42,
	WS_RTM_NEWTFILTER   = 44,
	WS_RTM_DELTFILTER   = 45,
	WS_RTM_GETTFILTER   = 46,
	WS_RTM_NEWACTION    = 48,
	WS_RTM_DELACTION    = 49,
	WS_RTM_GETACTION    = 50,
	WS_RTM_NEWPREFIX    = 52,
	WS_RTM_GETMULTICAST = 58,
	WS_RTM_GETANYCAST   = 62,
	WS_RTM_NEWNEIGHTBL  = 64,
	WS_RTM_GETNEIGHTBL  = 66,
	WS_RTM_SETNEIGHTBL  = 67,
	WS_RTM_NEWNDUSEROPT = 68,
	WS_RTM_NEWADDRLABEL = 72,
	WS_RTM_DELADDRLABEL = 73,
	WS_RTM_GETADDRLABEL = 74,
	WS_RTM_GETDCB       = 78,
	WS_RTM_SETDCB       = 79,
	WS_RTM_NEWNETCONF   = 80,
	WS_RTM_DELNETCONF   = 81,
	WS_RTM_GETNETCONF   = 82,
	WS_RTM_NEWMDB       = 84,
	WS_RTM_DELMDB       = 85,
	WS_RTM_GETMDB       = 86,
	WS_RTM_NEWNSID      = 88,
	WS_RTM_DELNSID      = 89,
	WS_RTM_GETNSID      = 90,
	WS_RTM_NEWSTATS     = 92,
	WS_RTM_GETSTATS     = 94,
	WS_RTM_NEWCACHEREPORT = 96,
	WS_RTM_NEWCHAIN     = 100,
	WS_RTM_DELCHAIN     = 101,
	WS_RTM_GETCHAIN     = 102,
	WS_RTM_NEWNEXTHOP   = 104,
	WS_RTM_DELNEXTHOP   = 105,
	WS_RTM_GETNEXTHOP   = 106,
	WS_RTM_NEWLINKPROP  = 108,
	WS_RTM_DELLINKPROP  = 109,
	WS_RTM_GETLINKPROP  = 110,
	WS_RTM_NEWVLAN      = 112,
	WS_RTM_DELVLAN      = 113,
	WS_RTM_GETVLAN      = 114,
	WS_RTM_NEWNEXTHOPBUCKET = 116,
	WS_RTM_DELNEXTHOPBUCKET = 117,
	WS_RTM_GETNEXTHOPBUCKET = 118,
	WS_RTM_NEWTUNNEL    = 120,
	WS_RTM_DELTUNNEL    = 121,
	WS_RTM_GETTUNNEL    = 122,
};

/* values for rta_type (network interface) from </include/uapi/linux/if_link.h> */
enum ws_ifla_attr_type {
	WS_IFLA_UNSPEC          =  0,
	WS_IFLA_ADDRESS         =  1,
	WS_IFLA_BROADCAST       =  2,
	WS_IFLA_IFNAME          =  3,
	WS_IFLA_MTU             =  4,
	WS_IFLA_LINK            =  5,
	WS_IFLA_QDISC           =  6,
	WS_IFLA_STATS           =  7,
	WS_IFLA_COST            =  8,
	WS_IFLA_PRIORITY        =  9,
	WS_IFLA_MASTER          = 10,
	WS_IFLA_WIRELESS        = 11,
	WS_IFLA_PROTINFO        = 12,
	WS_IFLA_TXQLEN          = 13,
	WS_IFLA_MAP             = 14,
	WS_IFLA_WEIGHT          = 15,
	WS_IFLA_OPERSTATE       = 16,
	WS_IFLA_LINKMODE        = 17,
	WS_IFLA_LINKINFO        = 18,
	WS_IFLA_NET_NS_PID      = 19,
	WS_IFLA_IFALIAS         = 20,
	WS_IFLA_NUM_VF          = 21,
	WS_IFLA_VFINFO_LIST     = 22,
	WS_IFLA_STATS64         = 23,
	WS_IFLA_VF_PORTS        = 24,
	WS_IFLA_PORT_SELF       = 25,
	WS_IFLA_AF_SPEC         = 26,
	WS_IFLA_GROUP           = 27,
	WS_IFLA_NET_NS_FD       = 28,
	WS_IFLA_EXT_MASK        = 29,
	WS_IFLA_PROMISCUITY     = 30,
	WS_IFLA_NUM_TX_QUEUES   = 31,
	WS_IFLA_NUM_RX_QUEUES   = 32,
	WS_IFLA_CARRIER         = 33,
	WS_IFLA_PHYS_PORT_ID    = 34,
	WS_IFLA_CARRIER_CHANGES = 35,
	WS_IFLA_PHYS_SWITCH_ID  = 36,
	WS_IFLA_LINK_NETNSID    = 37,
	WS_IFLA_PHYS_PORT_NAME  = 38,
	WS_IFLA_PROTO_DOWN      = 39,
	WS_IFLA_GSO_MAX_SEGS    = 40,
	WS_IFLA_GSO_MAX_SIZE    = 41,
	WS_IFLA_PAD             = 42,
	WS_IFLA_XDP             = 43,
	WS_IFLA_EVENT           = 44,
	WS_IFLA_NEW_NETNSID     = 45,
	WS_IFLA_IF_NETNSID      = 46,
	WS_IFLA_CARRIER_UP_COUNT   = 47,
	WS_IFLA_CARRIER_DOWN_COUNT = 48,
	WS_IFLA_NEW_IFINDEX     = 49,
	WS_IFLA_MIN_MTU         = 50,
	WS_IFLA_MAX_MTU         = 51,
	WS_IFLA_PROP_LIST       = 52,
	WS_IFLA_ALT_IFNAME      = 53,
	WS_IFLA_PERM_ADDRESS    = 54,
	WS_IFLA_PROTO_DOWN_REASON = 55,
	WS_IFLA_PARENT_DEV_NAME = 56,
	WS_IFLA_PARENT_DEV_BUS_NAME = 57,
	WS_IFLA_GRO_MAX_SIZE    = 58,
	WS_IFLA_TSO_MAX_SIZE    = 59,
	WS_IFLA_TSO_MAX_SEGS    = 60,
	WS_IFLA_ALLMULTI        = 61,
};

/* values for rta_type (ip address) from <include/uapi/linux/if_addr.h> */
enum ws_ifa_attr_type {
	WS_IFA_UNSPEC      = 0,
	WS_IFA_ADDRESS     = 1,
	WS_IFA_LOCAL       = 2,
	WS_IFA_LABEL       = 3,
	WS_IFA_BROADCAST   = 4,
	WS_IFA_ANYCAST     = 5,
	WS_IFA_CACHEINFO   = 6,
	WS_IFA_MULTICAST   = 7,
	WS_IFA_FLAGS       = 8,
	WS_IFA_RT_PRIORITY = 9,
	WS_IFA_TARGET_NETNSID = 10,
	WS_IFA_PROTO       = 11,
};

/* values for rta_type (route) from <include/uapi/linux/rtnetlink.h> */
enum ws_rta_attr_type {
	WS_RTA_UNSPEC    =  0,
	WS_RTA_DST       =  1,
	WS_RTA_SRC       =  2,
	WS_RTA_IIF       =  3,
	WS_RTA_OIF       =  4,
	WS_RTA_GATEWAY   =  5,
	WS_RTA_PRIORITY  =  6,
	WS_RTA_PREFSRC   =  7,
	WS_RTA_METRICS   =  8,
	WS_RTA_MULTIPATH =  9,
	WS_RTA_PROTOINFO = 10,
	WS_RTA_FLOW      = 11,
	WS_RTA_CACHEINFO = 12,
	WS_RTA_SESSION   = 13,
	WS_RTA_MP_ALGO   = 14,
	WS_RTA_TABLE     = 15,
	WS_RTA_MARK      = 16,
	WS_RTA_MFC_STATS = 17,
	WS_RTA_VIA       = 18,
	WS_RTA_NEWDST    = 19,
	WS_RTA_PREF      = 20,
	WS_RTA_ENCAP_TYPE= 21,
	WS_RTA_ENCAP     = 22,
	WS_RTA_EXPIRES   = 23,
	WS_RTA_PAD       = 24,
	WS_RTA_UID       = 25,
	WS_RTA_TTL_PROPAGATE = 26,
	WS_RTA_IP_PROTO  = 27,
	WS_RTA_SPORT     = 28,
	WS_RTA_DPORT     = 29,
	WS_RTA_NH_ID     = 30,
};


/* values for rtmsg.rtm_protocol from <include/uapi/linux/rtnetlink.h> */
enum {
/* kernel */
	WS_RTPROT_UNSPEC   =  0,
	WS_RTPROT_REDIRECT =  1,
	WS_RTPROT_KERNEL   =  2,
	WS_RTPROT_BOOT     =  3,
	WS_RTPROT_STATIC   =  4,
/* user */
	WS_RTPROT_GATED    =  8,
	WS_RTPROT_RA       =  9,
	WS_RTPROT_MRT      = 10,
	WS_RTPROT_ZEBRA    = 11,
	WS_RTPROT_BIRD     = 12,
	WS_RTPROT_DNROUTED = 13,
	WS_RTPROT_XORP     = 14,
	WS_RTPROT_NTK      = 15,
	WS_RTPROT_DHCP     = 16,
	WS_RTPROT_MROUTED  = 17,
	WS_RTPROT_KEEPALIVED = 18,
	WS_RTPROT_BABEL    = 42,
	WS_RTPROT_OPENR    = 99,
	WS_RTPROT_BGP      = 186,
	WS_RTPROT_ISIS     = 187,
	WS_RTPROT_OSPF     = 188,
	WS_RTPROT_RIP      = 189,
	WS_RTPROT_EIGRP    = 192,
};

/* values for rtmsg.rtm_scope from <include/uapi/linux/rtnetlink.h> */
enum {
	WS_RT_SCOPE_UNIVERSE =  0,
/* ... user defined (/etc/iproute2/rt_scopes) ... */
	WS_RT_SCOPE_SITE    = 200,
	WS_RT_SCOPE_LINK    = 253,
	WS_RT_SCOPE_HOST    = 254,
	WS_RT_SCOPE_NOWHERE = 255
};

/* values for rtmsg.rtm_type from <include/uapi/linux/rtnetlink.h> */
enum {
	WS_RTN_UNSPEC      =  0,
	WS_RTN_UNICAST     =  1,
	WS_RTN_LOCAL       =  2,
	WS_RTN_BROADCAST   =  3,
	WS_RTN_ANYCAST     =  4,
	WS_RTN_MULTICAST   =  5,
	WS_RTN_BLACKHOLE   =  6,
	WS_RTN_UNREACHABLE =  7,
	WS_RTN_PROHIBIT    =  8,
	WS_RTN_THROW       =  9,
	WS_RTN_NAT         = 10,
	WS_RTN_XRESOLVE    = 11
};

/* values for ifinfomsg.ifi_flags <include/uapi/linux/if.h> */
enum {
	WS_IFF_UP          =     0x1,
	WS_IFF_BROADCAST   =     0x2,
	WS_IFF_DEBUG       =     0x4,
	WS_IFF_LOOPBACK    =     0x8,
	WS_IFF_POINTOPOINT =    0x10,
	WS_IFF_NOTRAILERS  =    0x20,
	WS_IFF_RUNNING     =    0x40,
	WS_IFF_NOARP       =    0x80,
	WS_IFF_PROMISC     =   0x100,
	WS_IFF_ALLMULTI    =   0x200,
	WS_IFF_MASTER      =   0x400,
	WS_IFF_SLAVE       =   0x800,
	WS_IFF_MULTICAST   =  0x1000,
	WS_IFF_PORTSEL     =  0x2000,
	WS_IFF_AUTOMEDIA   =  0x4000,
	WS_IFF_DYNAMIC     =  0x8000,
	WS_IFF_LOWER_UP    = 0x10000,
	WS_IFF_DORMANT     = 0x20000,
	WS_IFF_ECHO        = 0x40000
};

/* values for ifaddrmsg.ifa_flags <include/uapi/linux/if_addr.h> */
enum {
	WS_IFA_F_SECONDARY    = 0x01,
	WS_IFA_F_NODAD        = 0x02,
	WS_IFA_F_OPTIMISTIC   = 0x04,
	WS_IFA_F_DADFAILED    = 0x08,
	WS_IFA_F_HOMEADDRESS  = 0x10,
	WS_IFA_F_DEPRECATED   = 0x20,
	WS_IFA_F_TENTATIVE    = 0x40,
	WS_IFA_F_PERMANENT    = 0x80,
	WS_IFA_F_MANAGETEMPADDR = 0x100,
	WS_IFA_F_NOPREFIXROUTE  = 0x200,
	WS_IFA_F_MCAUTOJOIN     = 0x400,
	WS_IFA_F_STABLE_PRIVACY = 0x800,
};

/* values for ndmsg.ndm_state <include/uapi/linux/neighbour.h> */
enum {
	WS_NUD_INCOMPLETE       = 0x01,
	WS_NUD_REACHABLE        = 0x02,
	WS_NUD_STALE            = 0x04,
	WS_NUD_DELAY            = 0x08,
	WS_NUD_PROBE            = 0x10,
	WS_NUD_FAILED           = 0x20,
/* Dummy states */
	WS_NUD_NOARP            = 0x40,
	WS_NUD_PERMANENT        = 0x80,
	WS_NUD_NONE             = 0x00
};

/* values for ifla.operstate <include/uapi/linux/if.h> */
enum {
	WS_IF_OPER_UNKNOWN,
	WS_IF_OPER_NOTPRESENT,
	WS_IF_OPER_DOWN,
	WS_IF_OPER_LOWERLAYERDOWN,
	WS_IF_OPER_TESTING,
	WS_IF_OPER_DORMANT,
	WS_IF_OPER_UP,
};

static int proto_netlink_route;

static dissector_handle_t netlink_route_handle;

static int hf_netlink_route_ifa_addr4;
static int hf_netlink_route_ifa_addr6;
static int hf_netlink_route_ifa_attr_type;
static int hf_netlink_route_ifa_family;
static int hf_netlink_route_ifa_flags;
static int hf_netlink_route_ifa_flags32;
static int hf_netlink_route_ifa_index;
static int hf_netlink_route_ifa_label;
static int hf_netlink_route_ifa_prefixlen;
static int hf_netlink_route_ifa_scope;
static int hf_netlink_route_ifi_change;
static int hf_netlink_route_ifi_family;
static int hf_netlink_route_ifi_flags;
static int hf_netlink_route_ifi_flags_iff_broadcast;
static int hf_netlink_route_ifi_flags_iff_up;
static int hf_netlink_route_ifi_index;
static int hf_netlink_route_ifi_type;
static int hf_netlink_route_ifla_attr_type;
static int hf_netlink_route_ifla_broadcast;
static int hf_netlink_route_ifla_carrier;
static int hf_netlink_route_ifla_carrier_changes;
static int hf_netlink_route_ifla_carrier_down_count;
static int hf_netlink_route_ifla_carrier_up_count;
static int hf_netlink_route_ifla_group;
static int hf_netlink_route_ifla_gso_maxsegs;
static int hf_netlink_route_ifla_gso_maxsize;
static int hf_netlink_route_ifla_hwaddr;
static int hf_netlink_route_ifla_ifname;
static int hf_netlink_route_ifla_linkstats_collisions;
static int hf_netlink_route_ifla_linkstats_multicast;
static int hf_netlink_route_ifla_linkstats_rx_crc_errs;
static int hf_netlink_route_ifla_linkstats_rx_fifo_errs;
static int hf_netlink_route_ifla_linkstats_rx_frame_errs;
static int hf_netlink_route_ifla_linkstats_rx_len_errs;
static int hf_netlink_route_ifla_linkstats_rx_miss_errs;
static int hf_netlink_route_ifla_linkstats_rx_over_errs;
static int hf_netlink_route_ifla_linkstats_rxbytes;
static int hf_netlink_route_ifla_linkstats_rxdropped;
static int hf_netlink_route_ifla_linkstats_rxerrors;
static int hf_netlink_route_ifla_linkstats_rxpackets;
static int hf_netlink_route_ifla_linkstats_tx_abort_errs;
static int hf_netlink_route_ifla_linkstats_tx_carrier_errs;
static int hf_netlink_route_ifla_linkstats_tx_fifo_errs;
static int hf_netlink_route_ifla_linkstats_tx_heartbeat_errs;
static int hf_netlink_route_ifla_linkstats_tx_window_errs;
static int hf_netlink_route_ifla_linkstats_txbytes;
static int hf_netlink_route_ifla_linkstats_txdropped;
static int hf_netlink_route_ifla_linkstats_txerrors;
static int hf_netlink_route_ifla_linkstats_txpackets;
static int hf_netlink_route_ifla_map_baseaddr;
static int hf_netlink_route_ifla_map_dma;
static int hf_netlink_route_ifla_map_irq;
static int hf_netlink_route_ifla_map_memend;
static int hf_netlink_route_ifla_map_memstart;
static int hf_netlink_route_ifla_map_port;
static int hf_netlink_route_ifla_max_mtu;
static int hf_netlink_route_ifla_min_mtu;
static int hf_netlink_route_ifla_mtu;
static int hf_netlink_route_ifla_operstate;
static int hf_netlink_route_ifla_promiscuity;
static int hf_netlink_route_ifla_qdisc;
static int hf_netlink_route_ifla_rxqnum;
static int hf_netlink_route_ifla_txqlen;
static int hf_netlink_route_ifla_txqnum;
static int hf_netlink_route_nd_family;
static int hf_netlink_route_nd_flags;
static int hf_netlink_route_nd_index;
static int hf_netlink_route_nd_state;
static int hf_netlink_route_nd_type;
static int hf_netlink_route_nltype;
static int hf_netlink_route_rt_dst_len;
static int hf_netlink_route_rt_family;
static int hf_netlink_route_rt_flags;
static int hf_netlink_route_rt_protocol;
static int hf_netlink_route_rt_scope;
static int hf_netlink_route_rt_src_len;
static int hf_netlink_route_rt_table;
static int hf_netlink_route_rt_tos;
static int hf_netlink_route_rt_type;
static int hf_netlink_route_rta_attr_type;
static int hf_netlink_route_rta_iif;
static int hf_netlink_route_rta_oif;

static int ett_netlink_route;
static int ett_netlink_route_attr;
static int ett_netlink_route_if_flags;
static int ett_netlink_route_attr_linkstats;
static int ett_netlink_route_attr_linkstats_rxerrs;
static int ett_netlink_route_attr_linkstats_txerrs;

static void
_fill_label_value_string_bitmask(char *label, uint32_t value, const value_string *vals)
{
	char tmp[16];

	label[0] = '\0';

	while (vals->strptr) {
		if (value & vals->value) {
			value &= ~(vals->value);
			if (label[0])
				(void) g_strlcat(label, ", ", ITEM_LABEL_LENGTH);

			(void) g_strlcat(label, vals->strptr, ITEM_LABEL_LENGTH);
		}

		vals++;
	}

	if (value) {
		if (label[0])
			(void) g_strlcat(label, ", ", ITEM_LABEL_LENGTH);
		snprintf(tmp, sizeof(tmp), "0x%x", value);
		(void) g_strlcat(label, tmp, ITEM_LABEL_LENGTH);
	}
}

static int
dissect_netlink_route_attributes(tvbuff_t *tvb, int hf_type, struct netlink_route_info *info, struct packet_netlink_data *nl_data, proto_tree *tree, int offset, netlink_attributes_cb_t cb)
{
	/* XXX, it's *almost* the same:
	 *  - rtnetlink is using struct rtattr with shorts
	 *  - generic netlink is using struct nlattr with __u16
	 */

	/* XXX, nice */
	return dissect_netlink_attributes_to_end(tvb, hf_type, ett_netlink_route_attr, info, nl_data, tree, offset, cb);
}

static void
hf_netlink_route_ifi_flags_label(char *label, uint32_t value)
{
	static const value_string iff_vals[] = {
		{ WS_IFF_UP,          "UP" },
		{ WS_IFF_BROADCAST,   "BROADCAST" },
		{ WS_IFF_DEBUG,       "DEBUG" },
		{ WS_IFF_LOOPBACK,    "LOOPBACK" },
		{ WS_IFF_POINTOPOINT, "POINTOPOINT" },
		{ WS_IFF_NOTRAILERS,  "NOTRAILERS" },
		{ WS_IFF_RUNNING,     "RUNNING" },
		{ WS_IFF_NOARP,       "NOARP" },
		{ WS_IFF_PROMISC,     "PROMISC" },
		{ WS_IFF_ALLMULTI,    "ALLMULTI" },
		{ WS_IFF_MASTER,      "MASTER" },
		{ WS_IFF_SLAVE,       "SLAVE" },
		{ WS_IFF_MULTICAST,   "MULTICAST" },
		{ WS_IFF_PORTSEL,     "PORTSEL" },
		{ WS_IFF_AUTOMEDIA,   "AUTOMEDIA" },
		{ WS_IFF_DYNAMIC,     "DYNAMIC" },
		{ WS_IFF_LOWER_UP,    "LOWER_UP" },
		{ WS_IFF_DORMANT,     "DORMANT" },
		{ WS_IFF_ECHO,        "ECHO" },
		{ 0, NULL }
	};

	char tmp[16];

	_fill_label_value_string_bitmask(label, value, iff_vals);

	snprintf(tmp, sizeof(tmp), " (0x%.8x)", value);
	(void) g_strlcat(label, tmp, ITEM_LABEL_LENGTH);
}

static int
dissect_netlink_route_ifinfomsg(tvbuff_t *tvb, struct netlink_route_info *info, struct packet_netlink_data *nl_data, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_tree *if_flags_tree;

	proto_tree_add_item(tree, hf_netlink_route_ifi_family, tvb, offset, 1, nl_data->encoding);
	offset += 1;

	if (info->legacy) {
		/*
		 * See the comment for the netlink_route_info structure,
		 * above.
		 */
		return offset;
	}

	/* XXX padding, check if 0 */
	offset += 1;

	proto_tree_add_item(tree, hf_netlink_route_ifi_type, tvb, offset, 2, nl_data->encoding);
	offset += 2;

	proto_tree_add_item(tree, hf_netlink_route_ifi_index, tvb, offset, 4, nl_data->encoding);
	offset += 4;

	ti = proto_tree_add_item(tree, hf_netlink_route_ifi_flags, tvb, offset, 4, nl_data->encoding);
	if_flags_tree = proto_item_add_subtree(ti, ett_netlink_route_if_flags);

	if (if_flags_tree) {
		proto_tree_add_item(if_flags_tree, hf_netlink_route_ifi_flags_iff_up, tvb, offset, 4, nl_data->encoding);
		proto_tree_add_item(if_flags_tree, hf_netlink_route_ifi_flags_iff_broadcast, tvb, offset, 4, nl_data->encoding);
		/* XXX */
	}
	offset += 4;

	proto_tree_add_item(tree, hf_netlink_route_ifi_change, tvb, offset, 4, nl_data->encoding);
	offset += 4;

	return offset;
}

/* Interface Attributes */

static const value_string netlink_route_ifla_attr_vals[] = {
	{ WS_IFLA_UNSPEC,         "Unspecified" },
	{ WS_IFLA_ADDRESS,        "HW Address" },
	{ WS_IFLA_BROADCAST,      "Broadcast" },
	{ WS_IFLA_IFNAME,         "Device name" },
	{ WS_IFLA_MTU,            "MTU" },
	{ WS_IFLA_LINK,           "Link type" },
	{ WS_IFLA_QDISC,          "Queueing discipline" },
	{ WS_IFLA_STATS,          "Interface Statistics" },
	{ WS_IFLA_COST,           "Cost" },
	{ WS_IFLA_PRIORITY,       "Priority" },
	{ WS_IFLA_MASTER,         "Master" },
	{ WS_IFLA_WIRELESS,       "Wireless" },
	{ WS_IFLA_PROTINFO,       "Prot info" },
	{ WS_IFLA_TXQLEN,         "TxQueue length"},
	{ WS_IFLA_MAP,            "Map"},
	{ WS_IFLA_WEIGHT,         "Weight"},
	{ WS_IFLA_OPERSTATE,      "Operstate"},
	{ WS_IFLA_LINKMODE,       "Link mode"},
	{ WS_IFLA_LINKINFO,       "Link info"},
	{ WS_IFLA_NET_NS_PID,     "NetNs id"},
	{ WS_IFLA_IFALIAS,        "Ifalias"},
	{ WS_IFLA_NUM_VF,         "Num VF"},
	{ WS_IFLA_VFINFO_LIST,    "VF Info"},
	{ WS_IFLA_STATS64,        "Stats" },
	{ WS_IFLA_VF_PORTS,       "VF ports" },
	{ WS_IFLA_PORT_SELF,      "Port self" },
	{ WS_IFLA_AF_SPEC,        "AF spec" },
	{ WS_IFLA_GROUP,          "Group" },
	{ WS_IFLA_NET_NS_FD,      "NetNs fd" },
	{ WS_IFLA_EXT_MASK,       "Ext mask" },
	{ WS_IFLA_PROMISCUITY,    "Promiscuity" },
	{ WS_IFLA_NUM_TX_QUEUES,  "Number of Tx queues" },
	{ WS_IFLA_NUM_RX_QUEUES,  "Number of Rx queues" },
	{ WS_IFLA_CARRIER,        "Carrier" },
	{ WS_IFLA_PHYS_PORT_ID,   "Physical port ID" },
	{ WS_IFLA_CARRIER_CHANGES,"Carrier changes" },
	{ WS_IFLA_PHYS_SWITCH_ID, "Physical switch ID" },
	{ WS_IFLA_LINK_NETNSID,   "Link network namespace ID" },
	{ WS_IFLA_PHYS_PORT_NAME, "Physical port name" },
	{ WS_IFLA_PROTO_DOWN,     "IFLA_PROTO_DOWN" },
	{ WS_IFLA_GSO_MAX_SEGS,   "Maximum GSO segment count" },
	{ WS_IFLA_GSO_MAX_SIZE,   "Maximum GSO size" },
	{ WS_IFLA_PAD,            "IFLA_PAD" },
	{ WS_IFLA_XDP,            "IFLA_XDP" },
	{ WS_IFLA_EVENT,          "IFLA_EVENT" },
	{ WS_IFLA_NEW_NETNSID,    "IFLA_NEW_NETNSID" },
	{ WS_IFLA_IF_NETNSID,     "IFLA_IF_NETNSID" },
	{ WS_IFLA_CARRIER_UP_COUNT,   "Carrier up count" },
	{ WS_IFLA_CARRIER_DOWN_COUNT, "Carrier down count" },
	{ WS_IFLA_NEW_IFINDEX,    "IFLA_NEW_IFINDEX" },
	{ WS_IFLA_MIN_MTU,        "Minimum MTU" },
	{ WS_IFLA_MAX_MTU,        "Maximum MTU" },
	{ WS_IFLA_PROP_LIST,      "Property list" },
	{ WS_IFLA_ALT_IFNAME,     "Alternative ifname" },
	{ WS_IFLA_PERM_ADDRESS,   "Permanent address" },
	{ WS_IFLA_PROTO_DOWN_REASON, "Protocol down reason" },
	{ WS_IFLA_PARENT_DEV_NAME, "Parent device name" },
	{ WS_IFLA_PARENT_DEV_BUS_NAME, "Parent device bus name" },
	{ WS_IFLA_GRO_MAX_SIZE,   "GRO maximum size" },
	{ WS_IFLA_TSO_MAX_SIZE,   "TSO maximum size" },
	{ WS_IFLA_TSO_MAX_SEGS,   "TSO maximum number of segments" },
	{ WS_IFLA_ALLMULTI,       "Allmulti count" },
	{ 0, NULL }
};

static const value_string netlink_route_ifla_operstate_vals[] = {
	{ WS_IF_OPER_UNKNOWN,        "Unknown" },
	{ WS_IF_OPER_NOTPRESENT,     "Not present" },
	{ WS_IF_OPER_DOWN,           "Down" },
	{ WS_IF_OPER_LOWERLAYERDOWN, "Lower layer down" },
	{ WS_IF_OPER_TESTING,        "Testing" },
	{ WS_IF_OPER_DORMANT,        "Dormant" },
	{ WS_IF_OPER_UP,             "Up"},
	{ 0, NULL }
};

static int *linkstat_root_hfs[] = {
	&hf_netlink_route_ifla_linkstats_rxpackets,
	&hf_netlink_route_ifla_linkstats_txpackets,
	&hf_netlink_route_ifla_linkstats_rxbytes,
	&hf_netlink_route_ifla_linkstats_txbytes,
	&hf_netlink_route_ifla_linkstats_rxerrors,
	&hf_netlink_route_ifla_linkstats_txerrors,
	&hf_netlink_route_ifla_linkstats_rxdropped,
	&hf_netlink_route_ifla_linkstats_txdropped,
	&hf_netlink_route_ifla_linkstats_multicast,
	&hf_netlink_route_ifla_linkstats_collisions,
};


static int *linkstat_rxerr_hfs[] = {
	&hf_netlink_route_ifla_linkstats_rx_len_errs,
	&hf_netlink_route_ifla_linkstats_rx_over_errs,
	&hf_netlink_route_ifla_linkstats_rx_crc_errs,
	&hf_netlink_route_ifla_linkstats_rx_frame_errs,
	&hf_netlink_route_ifla_linkstats_rx_fifo_errs,
	&hf_netlink_route_ifla_linkstats_rx_miss_errs,
};


static int *linkstat_txerr_hfs[] = {
	&hf_netlink_route_ifla_linkstats_tx_abort_errs,
	&hf_netlink_route_ifla_linkstats_tx_carrier_errs,
	&hf_netlink_route_ifla_linkstats_tx_fifo_errs,
	&hf_netlink_route_ifla_linkstats_tx_heartbeat_errs,
	&hf_netlink_route_ifla_linkstats_tx_window_errs,
};

static int
dissect_netlink_route_ifla_linkstats(tvbuff_t *tvb, struct netlink_route_info *info _U_, struct packet_netlink_data *nl_data, proto_tree *tree, int offset, int byte_size)
{
	proto_tree* rxerr_subtree;
	const int rxerr_hfs_len = array_length(linkstat_rxerr_hfs);
	proto_tree* txerr_subtree;
	const int txerr_hfs_len = array_length(linkstat_txerr_hfs);

	for (size_t i = 0; i < array_length(linkstat_root_hfs); i++) {
		proto_tree_add_item(tree, *linkstat_root_hfs[i], tvb, offset, byte_size, nl_data->encoding);
		offset += byte_size;
	}

	rxerr_subtree = proto_tree_add_subtree(tree, tvb, offset, byte_size * rxerr_hfs_len, ett_netlink_route_attr_linkstats_rxerrs, NULL, "Rx errors");
	for (int i = 0; i < rxerr_hfs_len; i++) {
		proto_tree_add_item(rxerr_subtree, *linkstat_rxerr_hfs[i], tvb, offset, byte_size, nl_data->encoding);
		offset += byte_size;
	}

	txerr_subtree = proto_tree_add_subtree(tree, tvb, offset, byte_size * txerr_hfs_len, ett_netlink_route_attr_linkstats_txerrs, NULL, "Tx errors");
	for (int i = 0; i < txerr_hfs_len; i++) {
		proto_tree_add_item(txerr_subtree, *linkstat_txerr_hfs[i], tvb, offset, byte_size, nl_data->encoding);
		offset += byte_size;
	}


	return 1;
}

static int
dissect_netlink_route_ifla_attrs(tvbuff_t *tvb, void *data, struct packet_netlink_data *nl_data, proto_tree *tree, int rta_type, int offset, int len)
{
	struct netlink_route_info *info = (struct netlink_route_info *)data;
	enum ws_ifla_attr_type type = (enum ws_ifla_attr_type) rta_type;
	const uint8_t* str;
	uint32_t value;
	bool flag;
	proto_tree* subtree;
	switch (type) {
		case WS_IFLA_IFNAME:
			proto_tree_add_item_ret_string(tree, hf_netlink_route_ifla_ifname, tvb, offset, len, ENC_ASCII | ENC_NA, wmem_packet_scope(), &str);
			proto_item_append_text(tree, ": %s", str);
			return 1;
		case WS_IFLA_MTU:
			proto_tree_add_item_ret_uint(tree, hf_netlink_route_ifla_mtu, tvb, offset, len, nl_data->encoding, &value);
			proto_item_append_text(tree, ": %u", value);
			return 1;
		case WS_IFLA_TXQLEN:
			proto_tree_add_item_ret_uint(tree, hf_netlink_route_ifla_txqlen, tvb, offset, len, nl_data->encoding, &value);
			proto_item_append_text(tree, ": %u", value);
			return 1;
		case WS_IFLA_OPERSTATE:
			proto_tree_add_item(tree, hf_netlink_route_ifla_operstate, tvb, offset, len, nl_data->encoding);
			return 1;
		case WS_IFLA_PROMISCUITY:
			proto_tree_add_item_ret_uint(tree, hf_netlink_route_ifla_promiscuity, tvb, offset, len, nl_data->encoding, &value);
			proto_item_append_text(tree, ": %u", value);
			return 1;
		case WS_IFLA_NUM_TX_QUEUES:
			proto_tree_add_item_ret_uint(tree, hf_netlink_route_ifla_txqnum, tvb, offset, len, nl_data->encoding, &value);
			proto_item_append_text(tree, ": %u", value);
			return 1;
		case WS_IFLA_NUM_RX_QUEUES:
			proto_tree_add_item_ret_uint(tree, hf_netlink_route_ifla_rxqnum, tvb, offset, len, nl_data->encoding, &value);
			proto_item_append_text(tree, ": %u", value);
			return 1;
		case WS_IFLA_GROUP:
			proto_tree_add_item_ret_uint(tree, hf_netlink_route_ifla_group, tvb, offset, len, nl_data->encoding, &value);
			proto_item_append_text(tree, ": %u", value);
			return 1;
		case WS_IFLA_GSO_MAX_SEGS:
			proto_tree_add_item_ret_uint(tree, hf_netlink_route_ifla_gso_maxsegs, tvb, offset, len, nl_data->encoding, &value);
			proto_item_append_text(tree, ": %u", value);
			return 1;
		case WS_IFLA_GSO_MAX_SIZE:
			proto_tree_add_item_ret_uint(tree, hf_netlink_route_ifla_gso_maxsize, tvb, offset, len, nl_data->encoding, &value);
			proto_item_append_text(tree, ": %u", value);
			return 1;
		case WS_IFLA_CARRIER:
			proto_tree_add_item_ret_boolean(tree, hf_netlink_route_ifla_carrier, tvb, offset, len, nl_data->encoding, &flag);
			proto_item_append_text(tree, ": %s", tfs_get_string(flag, &tfs_restricted_not_restricted));
			return 1;
		case WS_IFLA_CARRIER_CHANGES:
			proto_tree_add_item_ret_uint(tree, hf_netlink_route_ifla_carrier_changes, tvb, offset, len, nl_data->encoding, &value);
			proto_item_append_text(tree, ": %u", value);
			return 1;
		case WS_IFLA_ADDRESS:
			proto_item_append_text(tree, ": %s", tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, offset, len, ':'));
			proto_tree_add_item(tree, hf_netlink_route_ifla_hwaddr, tvb, offset, len, nl_data->encoding);
			return 1;
		case WS_IFLA_BROADCAST:
			proto_item_append_text(tree, ": %s", tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, offset, len, ':'));
			proto_tree_add_item(tree, hf_netlink_route_ifla_broadcast, tvb, offset, len, nl_data->encoding);
			return 1;
		case WS_IFLA_STATS:
			subtree = proto_tree_add_subtree(tree, tvb, offset, len, ett_netlink_route_attr_linkstats, NULL, "Statistics");
			return dissect_netlink_route_ifla_linkstats(tvb, info, nl_data, subtree, offset, 4);
		case WS_IFLA_STATS64:
			subtree = proto_tree_add_subtree(tree, tvb, offset, len, ett_netlink_route_attr_linkstats, NULL, "Statistics");
			return dissect_netlink_route_ifla_linkstats(tvb, info, nl_data, subtree, offset, 8);
		case WS_IFLA_QDISC:
			proto_tree_add_item_ret_string(tree, hf_netlink_route_ifla_qdisc, tvb, offset, len, ENC_ASCII | ENC_NA, wmem_packet_scope(), &str);
			proto_item_append_text(tree, ": %s", str);
			return 1;
		case WS_IFLA_MAP:
			proto_tree_add_item(tree, hf_netlink_route_ifla_map_memstart, tvb, offset, 8, nl_data->encoding);
			proto_tree_add_item(tree, hf_netlink_route_ifla_map_memend, tvb, offset + 8, 8, nl_data->encoding);
			proto_tree_add_item(tree, hf_netlink_route_ifla_map_baseaddr, tvb, offset + 16, 8, nl_data->encoding);
			proto_tree_add_item(tree, hf_netlink_route_ifla_map_irq, tvb, offset + 24, 2, nl_data->encoding);
			proto_tree_add_item(tree, hf_netlink_route_ifla_map_dma, tvb, offset + 26, 1, nl_data->encoding);
			proto_tree_add_item(tree, hf_netlink_route_ifla_map_port, tvb, offset + 27, 1, nl_data->encoding);
			return 1;
		case WS_IFLA_CARRIER_UP_COUNT:
			proto_tree_add_item_ret_uint(tree, hf_netlink_route_ifla_carrier_up_count, tvb, offset, len, nl_data->encoding, &value);
			proto_item_append_text(tree, ": %u", value);
			return 1;
		case WS_IFLA_CARRIER_DOWN_COUNT:
			proto_tree_add_item_ret_uint(tree, hf_netlink_route_ifla_carrier_down_count, tvb, offset, len, nl_data->encoding, &value);
			proto_item_append_text(tree, ": %u", value);
			return 1;
		case WS_IFLA_MIN_MTU:
			proto_tree_add_item_ret_uint(tree, hf_netlink_route_ifla_min_mtu, tvb, offset, len, nl_data->encoding, &value);
			proto_item_append_text(tree, ": %u", value);
			return 1;
		case WS_IFLA_MAX_MTU:
			proto_tree_add_item_ret_uint(tree, hf_netlink_route_ifla_max_mtu, tvb, offset, len, nl_data->encoding, &value);
			proto_item_append_text(tree, ": %u", value);
			return 1;

		default:
			return 0;
	}
}

/* IP address */

static void
netlink_route_ifa_flags_label(char *label, uint32_t value)
{
	static const value_string iff_vals[] = {
		{ WS_IFA_F_SECONDARY,       "secondary/temporary" },
		{ WS_IFA_F_NODAD,           "nodad" },
		{ WS_IFA_F_OPTIMISTIC,      "optimistic" },
		{ WS_IFA_F_DADFAILED,       "dadfailed" },
		{ WS_IFA_F_HOMEADDRESS,     "homeaddress" },
		{ WS_IFA_F_DEPRECATED,      "deprecated" },
		{ WS_IFA_F_TENTATIVE,       "tentative" },
		{ WS_IFA_F_PERMANENT,       "permanent" },
		/* 32-bit IFA_FLAGS (in attribute) */
		{ WS_IFA_F_MANAGETEMPADDR,  "mngtmpaddr" },
		{ WS_IFA_F_NOPREFIXROUTE,   "noprefixroute" },
		{ WS_IFA_F_MCAUTOJOIN,      "autojoin" },
		{ WS_IFA_F_STABLE_PRIVACY,  "stable_privacy" },
		{ 0, NULL }
	};

	char tmp[16];

	_fill_label_value_string_bitmask(label, value, iff_vals);

	snprintf(tmp, sizeof(tmp), " (0x%.8x)", value);
	(void) g_strlcat(label, tmp, ITEM_LABEL_LENGTH);
}

static int
dissect_netlink_route_ifaddrmsg(tvbuff_t *tvb, struct netlink_route_info *info, struct packet_netlink_data *nl_data, proto_tree *tree, int offset)
{
	proto_tree_add_item(tree, hf_netlink_route_ifa_family,    tvb, offset, 1, ENC_NA);
	offset += 1;

	if (info->legacy) {
		/*
		 * See the comment for the netlink_route_info structure,
		 * above.
		 */
		return offset;
	}

	proto_tree_add_item(tree, hf_netlink_route_ifa_prefixlen, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, hf_netlink_route_ifa_flags,     tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, hf_netlink_route_ifa_scope,     tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, hf_netlink_route_ifa_index,     tvb, offset, 4, nl_data->encoding);
	offset += 4;

	return offset;
}

/* IP address attributes */

static const value_string netlink_route_ifa_attr_vals[] = {
	{ WS_IFA_UNSPEC,    "Unspecified" },
	{ WS_IFA_ADDRESS,   "Interface address" },
	{ WS_IFA_LOCAL,     "Local address" },
	{ WS_IFA_LABEL,     "Name of interface" },
	{ WS_IFA_BROADCAST, "Broadcast address" },
	{ WS_IFA_ANYCAST,   "Anycast address" },
	{ WS_IFA_CACHEINFO, "Address information" },
	{ WS_IFA_MULTICAST, "Multicast address" },
	{ WS_IFA_FLAGS,     "Address flags" },
	{ WS_IFA_RT_PRIORITY, "IFA_RT_PRIORITY" },
	{ WS_IFA_TARGET_NETNSID, "IFA_TARGET_NETNSID" },
	{ WS_IFA_PROTO,     "IFA_PROTO" },
	{ 0, NULL }
};

static int
dissect_netlink_route_ifa_attrs(tvbuff_t *tvb, void *data _U_, struct packet_netlink_data *nl_data, proto_tree *tree, int rta_type, int offset, int len)
{
	enum ws_ifa_attr_type type = (enum ws_ifa_attr_type) rta_type;
	const uint8_t* str;

	switch (type) {
		case WS_IFA_LABEL:
			proto_tree_add_item_ret_string(tree, hf_netlink_route_ifa_label, tvb, offset, len, ENC_ASCII | ENC_NA, wmem_packet_scope(), &str);
			proto_item_append_text(tree, ": %s", str);
			return 1;

		case WS_IFA_FLAGS:
			proto_tree_add_item(tree, hf_netlink_route_ifa_flags32, tvb, offset, 4, nl_data->encoding);
			return 1;
		case WS_IFA_ADDRESS:
		case WS_IFA_LOCAL:
		case WS_IFA_BROADCAST:
			if (len == 4) {
				proto_item_append_text(tree, ": %s", tvb_ip_to_str(wmem_packet_scope(), tvb, offset));
				proto_tree_add_item(tree, hf_netlink_route_ifa_addr4, tvb, offset, len, ENC_BIG_ENDIAN);
			} else {
				proto_item_append_text(tree, ": %s", tvb_ip6_to_str(wmem_packet_scope(), tvb, offset));
				proto_tree_add_item(tree, hf_netlink_route_ifa_addr6, tvb, offset, len, ENC_NA);
			}
			return 1;
		default:
			return 0;
	}
}

/* Route */

static const value_string netlink_route_rt_protocol_vals[] = {
	{ WS_RTPROT_UNSPEC,   "unknown" },
	{ WS_RTPROT_REDIRECT, "ICMP redirects" },
	{ WS_RTPROT_KERNEL,   "kernel" },
	{ WS_RTPROT_BOOT,     "boot" },
	{ WS_RTPROT_STATIC,   "static" },
	{ WS_RTPROT_GATED,    "GateD" },
	{ WS_RTPROT_RA,       "RDISC/ND router advertisements" },
	{ WS_RTPROT_MRT,      "Merit MRT" },
	{ WS_RTPROT_ZEBRA,    "Zebra" },
	{ WS_RTPROT_BIRD,     "BIRD" },
	{ WS_RTPROT_DNROUTED, "DECnet routing daemon" },
	{ WS_RTPROT_XORP,     "XORP" },
	{ WS_RTPROT_NTK,      "Netsukuku" },
	{ WS_RTPROT_DHCP,     "DHCP client" },
	{ WS_RTPROT_MROUTED,  "Multicast daemon" },
	{ WS_RTPROT_KEEPALIVED, "Keepalived daemon" },
	{ WS_RTPROT_BABEL,    "Babel daemon" },
	{ WS_RTPROT_OPENR,    "Open Routing Routes" },
	{ WS_RTPROT_BGP,      "BGP" },
	{ WS_RTPROT_ISIS,     "ISIS" },
	{ WS_RTPROT_OSPF,     "OSPF" },
	{ WS_RTPROT_RIP,      "RIP" },
	{ WS_RTPROT_EIGRP,    "EIGRP" },
	{ 0, NULL }
};
static value_string_ext hf_netlink_route_rt_protocol_vals_ext =
	VALUE_STRING_EXT_INIT(netlink_route_rt_protocol_vals);

static const value_string netlink_route_rt_scope_vals[] = {
	{ WS_RT_SCOPE_UNIVERSE, "global route" },
	{ WS_RT_SCOPE_SITE,     "interior route in the local autonomous system" },
	{ WS_RT_SCOPE_LINK,     "route on this link" },
	{ WS_RT_SCOPE_HOST,     "route on the local host" },
	{ WS_RT_SCOPE_NOWHERE,  "destination doesn't exist" },
	{ 0, NULL }
};

static const value_string netlink_route_rt_type_vals[] = {
	{ WS_RTN_UNSPEC,      "Unknown route" },
	{ WS_RTN_UNICAST,     "Gateway or direct route" },
	{ WS_RTN_LOCAL,       "Local interface route" },
	{ WS_RTN_BROADCAST,   "Local broadcast route (send as broadcast)" },
	{ WS_RTN_ANYCAST,     "Local broadcast route (send as unicast)" },
	{ WS_RTN_MULTICAST,   "Multicast route" },
	{ WS_RTN_BLACKHOLE,   "Drop" },
	{ WS_RTN_UNREACHABLE, "Unreachable destination" },
	{ WS_RTN_PROHIBIT,    "Administratively prohibited" },
	{ WS_RTN_THROW,       "Routing lookup in another table" },
	{ WS_RTN_NAT,         "Network address translation rule" },
	{ WS_RTN_XRESOLVE,    "Use external resolver" },
	{ 0, NULL }
};

static int
dissect_netlink_route_rtmsg(tvbuff_t *tvb, struct netlink_route_info *info, struct packet_netlink_data *nl_data, proto_tree *tree, int offset)
{
	proto_tree_add_item(tree, hf_netlink_route_rt_family,   tvb, offset, 1, ENC_NA);
	offset += 1;

	if (info->legacy) {
		/*
		 * See the comment for the netlink_route_info structure,
		 * above.
		 */
		return offset;
	}

	proto_tree_add_item(tree, hf_netlink_route_rt_dst_len,  tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, hf_netlink_route_rt_src_len,  tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, hf_netlink_route_rt_tos,      tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, hf_netlink_route_rt_table,    tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, hf_netlink_route_rt_protocol, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, hf_netlink_route_rt_scope,    tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, hf_netlink_route_rt_type,     tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, hf_netlink_route_rt_flags,    tvb, offset, 4, nl_data->encoding);
	offset += 4;

	return offset;
}

/* Route Attributes */

static const value_string netlink_route_rta_attr_vals[] = {
	{ WS_RTA_UNSPEC,    "Unspecified" },
	{ WS_RTA_DST,       "Route destination address" },
	{ WS_RTA_SRC,       "Route source address" },
	{ WS_RTA_IIF,       "Input interface index" },
	{ WS_RTA_OIF,       "Output interface index" },
	{ WS_RTA_GATEWAY,   "Gateway of the route" },
	{ WS_RTA_PRIORITY,  "RTA_PRIORITY" },
	{ WS_RTA_PREFSRC,   "RTA_PREFSRC" },
	{ WS_RTA_METRICS,   "RTA_METRICS" },
	{ WS_RTA_MULTIPATH, "RTA_MULTIPATH" },
	{ WS_RTA_PROTOINFO, "RTA_PROTOINFO" },
	{ WS_RTA_FLOW,      "RTA_FLOW" },
	{ WS_RTA_CACHEINFO, "RTA_CACHEINFO" },
	{ WS_RTA_SESSION,   "RTA_SESSION" },
	{ WS_RTA_MP_ALGO,   "RTA_MP_ALGO" },
	{ WS_RTA_TABLE,     "RTA_TABLE" },
	{ WS_RTA_MARK,      "RTA_MARK" },
	{ WS_RTA_MFC_STATS, "RTA_MFC_STATS" },
	{ WS_RTA_VIA,       "RTA_VIA" },
	{ WS_RTA_NEWDST,    "RTA_NEWDST" },
	{ WS_RTA_PREF,      "RTA_PREF" },
	{ WS_RTA_ENCAP_TYPE,"RTA_ENCAP_TYPE" },
	{ WS_RTA_ENCAP,     "RTA_ENCAP" },
	{ WS_RTA_EXPIRES,   "RTA_EXPIRES" },
	{ WS_RTA_PAD,       "RTA_PAD" },
	{ WS_RTA_UID,       "RTA_UID" },
	{ WS_RTA_TTL_PROPAGATE, "RTA_TTL_PROPAGATE" },
	{ WS_RTA_IP_PROTO,  "RTA_IP_PROTO" },
	{ WS_RTA_SPORT,     "RTA_SPORT" },
	{ WS_RTA_DPORT,     "RTA_DPORT" },
	{ WS_RTA_NH_ID,     "RTA_NH_ID" },
	{ 0, NULL }
};

static int
dissect_netlink_route_route_attrs(tvbuff_t *tvb, void *data _U_, struct packet_netlink_data *nl_data, proto_tree *tree, int rta_type, int offset, int len)
{
	enum ws_rta_attr_type type = (enum ws_rta_attr_type) rta_type;
	uint32_t value;

	switch (type) {
		case WS_RTA_IIF:
			if (len == 4) {
				proto_tree_add_item_ret_uint(tree, hf_netlink_route_rta_iif, tvb, offset, 4, nl_data->encoding, &value);
				proto_item_append_text(tree, ": %u", value);
				return 1;
			}
			return 0;

		case WS_RTA_OIF:
			if (len == 4) {
				proto_tree_add_item_ret_uint(tree, hf_netlink_route_rta_oif, tvb, offset, 4, nl_data->encoding, &value);
				proto_item_append_text(tree, ": %u", value);
				return 1;
			}
			return 0;

		default:
			return 0;
	}
}

static void
netlink_route_nd_states_label(char *label, uint32_t value)
{
	static const value_string flags_vals[] = {
		{ WS_NUD_NONE,       "NONE" },
		{ WS_NUD_INCOMPLETE, "INCOMPLETE" },
		{ WS_NUD_REACHABLE,  "REACHABLE" },
		{ WS_NUD_STALE,      "STALE" },
		{ WS_NUD_DELAY,      "DELAY" },
		{ WS_NUD_PROBE,      "PROBE" },
		{ WS_NUD_FAILED,     "FAILED" },
		{ WS_NUD_NOARP,      "NOARP" },
		{ WS_NUD_PERMANENT,  "PERMANENT" },
		{ 0, NULL }
	};

	char tmp[16];

	_fill_label_value_string_bitmask(label, value, flags_vals);

	snprintf(tmp, sizeof(tmp), " (0x%.4x)", value);
	(void) g_strlcat(label, tmp, ITEM_LABEL_LENGTH);
}

static int
dissect_netlink_route_ndmsg(tvbuff_t *tvb, struct netlink_route_info *info, struct packet_netlink_data *nl_data, proto_tree *tree, int offset)
{
	proto_tree_add_item(tree, hf_netlink_route_nd_family, tvb, offset, 1, ENC_NA);
	offset += 1;

	if (info->legacy) {
		/*
		 * See the comment for the netlink_route_info structure,
		 * above.
		 */
		return offset;
	}

	/* XXX, 3B padding */
	offset += 3;

	proto_tree_add_item(tree, hf_netlink_route_nd_index, tvb, offset, 4, nl_data->encoding);
	offset += 4;

	proto_tree_add_item(tree, hf_netlink_route_nd_state, tvb, offset, 2, nl_data->encoding);
	offset += 2;

	proto_tree_add_item(tree, hf_netlink_route_nd_flags, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, hf_netlink_route_nd_type, tvb, offset, 1, ENC_NA);
	offset += 1;

	return offset;
}

static const value_string netlink_route_type_vals[] = {
	{ WS_RTM_NEWLINK,       "Create network interface" },
	{ WS_RTM_DELLINK,       "Remove network interface" },
	{ WS_RTM_GETLINK,       "Get network interface info" },
	{ WS_RTM_SETLINK,       "Set network interface info" },
	{ WS_RTM_NEWADDR,       "Add IP address" },
	{ WS_RTM_DELADDR,       "Delete IP address" },
	{ WS_RTM_GETADDR,       "Get IP address" },
	{ WS_RTM_NEWROUTE,      "Add network route" },
	{ WS_RTM_DELROUTE,      "Delete network route" },
	{ WS_RTM_GETROUTE,      "Get network route" },
	{ WS_RTM_NEWNEIGH,      "Add neighbor table entry" },
	{ WS_RTM_DELNEIGH,      "Delete neighbor table entry" },
	{ WS_RTM_GETNEIGH,      "Get neighbor table entry" },
	{ WS_RTM_NEWRULE,       "Add routing rule" },
	{ WS_RTM_DELRULE,       "Delete routing rule" },
	{ WS_RTM_GETRULE,       "Get routing rule" },
	{ WS_RTM_NEWQDISC,      "Add queueing discipline" },
	{ WS_RTM_DELQDISC,      "Delete queueing discipline" },
	{ WS_RTM_GETQDISC,      "Get queueing discipline" },
	{ WS_RTM_NEWTCLASS,     "Add traffic class" },
	{ WS_RTM_DELTCLASS,     "Delete traffic class" },
	{ WS_RTM_GETTCLASS,     "Get traffic class" },
	{ WS_RTM_NEWTFILTER,    "Add traffic class" },
	{ WS_RTM_DELTFILTER,    "Delete traffic class" },
	{ WS_RTM_GETTFILTER,    "Get traffic class" },
	{ WS_RTM_NEWACTION,     "New Action" },
	{ WS_RTM_DELACTION,     "Delete Action" },
	{ WS_RTM_GETACTION,     "Get Action" },
	{ WS_RTM_NEWPREFIX,     "New IPv6 prefix" },
	{ WS_RTM_GETMULTICAST,  "Get multicast address" },
	{ WS_RTM_GETANYCAST,    "Get anycast address" },
	{ WS_RTM_NEWNEIGHTBL,   "New Neighbour tables" },
	{ WS_RTM_GETNEIGHTBL,   "Get Neighbour tables" },
	{ WS_RTM_SETNEIGHTBL,   "Set Neighbour tables" },
	{ WS_RTM_NEWNDUSEROPT,  "New ND Userland options" },
	{ WS_RTM_NEWADDRLABEL,  "New IPv6 Address Label" },
	{ WS_RTM_DELADDRLABEL,  "Delete IPv6 Address Label" },
	{ WS_RTM_GETADDRLABEL,  "Get IPv6 Address Label" },
	{ WS_RTM_GETDCB,        "Get Data Center Bridging" },
	{ WS_RTM_SETDCB,        "Set Data Center Bridging" },
	{ WS_RTM_NEWNETCONF,    "RTM_NEWNETCONF" },
	{ WS_RTM_DELNETCONF,    "RTM_DELNETCONF" },
	{ WS_RTM_GETNETCONF,    "RTM_GETNETCONF" },
	{ WS_RTM_NEWMDB,        "Add multicast database entry" },
	{ WS_RTM_DELMDB,        "Delete multicast database entry" },
	{ WS_RTM_GETMDB,        "Get multicast database" },
	{ WS_RTM_NEWNSID,       "New network namespace ID" },
	{ WS_RTM_DELNSID,       "Delete network namespace ID" },
	{ WS_RTM_GETNSID,       "Get network namespace ID" },
	{ WS_RTM_NEWSTATS,      "New link statistics" },
	{ WS_RTM_GETSTATS,      "Get link statistics" },
	{ WS_RTM_NEWCACHEREPORT,"New cache report" },
	{ WS_RTM_NEWCHAIN,      "New chain" },
	{ WS_RTM_DELCHAIN,      "Delete chain" },
	{ WS_RTM_GETCHAIN,      "Get chain" },
	{ WS_RTM_NEWNEXTHOP,    "New next hop" },
	{ WS_RTM_DELNEXTHOP,    "Delete next hop" },
	{ WS_RTM_GETNEXTHOP,    "Get next hop" },
	{ WS_RTM_NEWLINKPROP,   "New link property" },
	{ WS_RTM_DELLINKPROP,   "Delete link property" },
	{ WS_RTM_GETLINKPROP,   "Get link property" },
	{ WS_RTM_NEWVLAN,       "New VLAN" },
	{ WS_RTM_DELVLAN,       "Delete VLAN" },
	{ WS_RTM_GETVLAN,       "Get VLAN" },
	{ WS_RTM_NEWNEXTHOPBUCKET, "New next hop bucket" },
	{ WS_RTM_DELNEXTHOPBUCKET, "Delete next hop bucket" },
	{ WS_RTM_GETNEXTHOPBUCKET, "Get next hop bucket" },
	{ WS_RTM_NEWTUNNEL,     "New tunnel" },
	{ WS_RTM_DELTUNNEL,     "Delete tunnel" },
	{ WS_RTM_GETTUNNEL,     "Get tunnel" },
	{ 0, NULL }
};
static value_string_ext netlink_route_type_vals_ext = VALUE_STRING_EXT_INIT(netlink_route_type_vals);

static int
dissect_netlink_route(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	struct netlink_route_info info;
	struct packet_netlink_data *nl_data = (struct packet_netlink_data *)data;
	proto_tree *nlmsg_tree;
	proto_item *pi;
	int offset = 0;

	DISSECTOR_ASSERT(nl_data && nl_data->magic == PACKET_NETLINK_MAGIC);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Netlink route");
	col_clear(pinfo->cinfo, COL_INFO);

	pi = proto_tree_add_item(tree, proto_netlink_route, tvb, 0, -1, ENC_NA);
	nlmsg_tree = proto_item_add_subtree(pi, ett_netlink_route);

	/* Netlink message header (nlmsghdr) */
	offset = dissect_netlink_header(tvb, nlmsg_tree, offset, nl_data->encoding, hf_netlink_route_nltype, NULL);

	info.pinfo = pinfo;

	switch (nl_data->type) {
		case WS_RTM_NEWLINK:
		case WS_RTM_DELLINK:
		case WS_RTM_GETLINK:
		case WS_RTM_SETLINK:
			/*
			 * Backward compatibility with legacy tools; 16 is
			 * sizeof(struct ifinfomsg).
			 *
			 * See the comment for the netlink_route_info
			 * structure, above.
			 */
			info.legacy = (nl_data->type == WS_RTM_GETLINK) && (tvb_reported_length_remaining(tvb, offset) < 16);
			offset = dissect_netlink_route_ifinfomsg(tvb, &info, nl_data, nlmsg_tree, offset);
			/* Optional attributes */
			offset = dissect_netlink_route_attributes(tvb, hf_netlink_route_ifla_attr_type, &info, nl_data, nlmsg_tree, offset, dissect_netlink_route_ifla_attrs);
			break;

		case WS_RTM_NEWADDR:
		case WS_RTM_DELADDR:
		case WS_RTM_GETADDR:
			/*
			 * Backward compatibility with legacy tools; 8 is
			 * sizeof(struct ifaddrmsg).
			 *
			 * See the comment for the netlink_route_info
			 * structure, above.
			 */
			info.legacy = (nl_data->type == WS_RTM_GETADDR) && (tvb_reported_length_remaining(tvb, offset) < 8);
			offset = dissect_netlink_route_ifaddrmsg(tvb, &info, nl_data, nlmsg_tree, offset);
			if (!info.legacy) {
				/*
				 * Optional attributes.
				 *
				 * Not present in legacy-tool messages;
				 * again, see the comment above.
				 */
				offset = dissect_netlink_route_attributes(tvb, hf_netlink_route_ifa_attr_type, &info, nl_data, nlmsg_tree, offset, dissect_netlink_route_ifa_attrs);
			}
			break;

		case WS_RTM_NEWROUTE:
		case WS_RTM_DELROUTE:
		case WS_RTM_GETROUTE:
			/*
			 * Backward compatibility with legacy tools; 12 is
			 * sizeof(struct rtmsg).
			 *
			 * See the comment for the netlink_route_info
			 * structure, above.
			 */
			info.legacy = (nl_data->type == WS_RTM_GETROUTE) && (tvb_reported_length_remaining(tvb, offset) < 12);
			offset = dissect_netlink_route_rtmsg(tvb, &info, nl_data, nlmsg_tree, offset);
			/* Optional attributes */
			if (!info.legacy) {
				/*
				 * Optional attributes.
				 *
				 * Not present in legacy-tool messages;
				 * again, see the comment above.
				 */
				offset = dissect_netlink_route_attributes(tvb, hf_netlink_route_rta_attr_type, &info, nl_data, nlmsg_tree, offset, dissect_netlink_route_route_attrs);
			}
			break;

		case WS_RTM_NEWNEIGH:
		case WS_RTM_DELNEIGH:
		case WS_RTM_GETNEIGH:
			/*
			 * Backward compatibility with legacy tools; 12 is
			 * sizeof(struct ndmsg).
			 *
			 * See the comment for the netlink_route_info
			 * structure, above.
			 */
			info.legacy = (nl_data->type == WS_RTM_GETNEIGH) && (tvb_reported_length_remaining(tvb, offset) < 12);
			if (!info.legacy) {
				/*
				 * Optional attributes.
				 *
				 * Not present in legacy-tool messages;
				 * again, see the comment above.
				 */
				offset = dissect_netlink_route_ndmsg(tvb, &info, nl_data, nlmsg_tree, offset);
			}
			break;
	}

	return offset;
}

void
proto_register_netlink_route(void)
{
	static hf_register_info hf[] = {
		{ &hf_netlink_route_ifi_family,
			{ "Interface family", "netlink-route.ifi_family",
			  FT_UINT8, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifi_type,
			{ "Device type", "netlink-route.ifi_type",
			  FT_UINT16, BASE_DEC, VALS(arp_hrd_vals), 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifi_index,
			{ "Interface index", "netlink-route.ifi_index",
			  FT_INT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifi_flags,
			{ "Device flags", "netlink-route.ifi_flags",
			  FT_UINT32, BASE_CUSTOM, CF_FUNC(hf_netlink_route_ifi_flags_label), 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifi_flags_iff_up,
			{ "Interface", "netlink-route.ifi_flags.iff_up",
			  FT_BOOLEAN, 32, TFS(&tfs_up_down), WS_IFF_UP,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifi_flags_iff_broadcast,
			{ "Broadcast", "netlink-route.ifi_flags.iff_broadcast",
			  FT_BOOLEAN, 32, TFS(&tfs_valid_invalid), WS_IFF_BROADCAST,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifi_change,
			{ "Device change flags", "netlink-route.ifi_change",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_attr_type,
			{ "Attribute type", "netlink-route.ifla_attr_type",
			  FT_UINT16, BASE_DEC, VALS(netlink_route_ifla_attr_vals), 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_ifname,
			{ "Device name", "netlink-route.ifla_ifname",
			  FT_STRINGZ, BASE_NONE, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_mtu,
			{ "MTU of device", "netlink-route.ifla_mtu",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_txqlen,
			{ "TxQueue length", "netlink-route.ifla_txqlen",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_operstate,
			{ "Operstate", "netlink-route.ifla_operstate",
			  FT_UINT8, BASE_DEC, VALS(netlink_route_ifla_operstate_vals), 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_promiscuity,
			{ "Promiscuity", "netlink-route.ifla_promiscuity",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_txqnum,
			{ "Number of Tx queues", "netlink-route.ifla_txqnum",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_rxqnum,
			{ "Number of Rx queues", "netlink-route.ifla_rxqnum",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_group,
			{ "Group", "netlink-route.ifla_group",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_gso_maxsize,
			{ "Maximum GSO size", "netlink-route.ifla_gso_maxsize",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_gso_maxsegs,
			{ "Maximum GSO segment count", "netlink-route.ifla_gso_maxsegs",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_carrier,
			{ "Carrier", "netlink-route.ifla_carrier",
			  FT_BOOLEAN, 32, TFS(&tfs_restricted_not_restricted), 0x00000001,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_qdisc,
			{ "Queueing discipline", "netlink-route.ifla_qdisc",
			  FT_STRINGZ, BASE_NONE, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_carrier_changes,
			{ "Carrier changes", "netlink-route.ifla_carrier_changes",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_hwaddr,
			{ "HW Address", "netlink-route.ifla_hwaddr",
			  FT_BYTES, SEP_COLON, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_broadcast,
			{ "Broadcast", "netlink-route.ifla_broadcast",
			  FT_BYTES, SEP_COLON, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_carrier_up_count,
			{ "Carrier changes to up", "netlink-route.ifla_carrier_up_count",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_carrier_down_count,
			{ "Carrier changes to down", "netlink-route.ifla_carrier_down_count",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_min_mtu,
			{ "Minimum MTU of device", "netlink-route.ifla_min_mtu",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_max_mtu,
			{ "Maximum MTU of device", "netlink-route.ifla_max_mtu",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_map_memstart,
			{ "Memory start", "netlink-route.ifla_map.mem_start",
			  FT_UINT64, BASE_HEX, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_map_memend,
			{ "Memory end", "netlink-route.ifla_map.mem_end",
			  FT_UINT64, BASE_HEX, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_map_baseaddr,
			{ "Base address", "netlink-route.ifla_map.base_addr",
			  FT_UINT64, BASE_HEX, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_map_irq,
			{ "IRQ", "netlink-route.ifla_map.irq",
			  FT_UINT16, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_map_dma,
			{ "DMA", "netlink-route.ifla_map.dma",
			  FT_UINT8, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_map_port,
			{ "Port", "netlink-route.ifla_map.port",
			  FT_UINT8, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_linkstats_rxpackets,
			{ "Rx packets", "netlink-route.ifla_linkstats.rxpackets",
			  FT_UINT64, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_linkstats_txpackets,
			{ "Tx packets", "netlink-route.ifla_linkstats.txpackets",
			  FT_UINT64, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_linkstats_rxbytes,
			{ "Rx bytes", "netlink-route.ifla_linkstats.rxbytes",
			  FT_UINT64, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_linkstats_txbytes,
			{ "Tx packets", "netlink-route.ifla_linkstats.txbytes",
			  FT_UINT64, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_linkstats_rxerrors,
			{ "Rx errors", "netlink-route.ifla_linkstats.rxerrors",
			  FT_UINT64, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_linkstats_txerrors,
			{ "Tx errors", "netlink-route.ifla_linkstats.txerrors",
			  FT_UINT64, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_linkstats_rxdropped,
			{ "Rx dropped", "netlink-route.ifla_linkstats.rxdropped",
			  FT_UINT64, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_linkstats_txdropped,
			{ "Tx dropped", "netlink-route.ifla_linkstats.txdropped",
			  FT_UINT64, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_linkstats_multicast,
			{ "Multicast Rx", "netlink-route.ifla_linkstats.multicast",
			  FT_UINT64, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_linkstats_collisions,
			{ "Collisions", "netlink-route.ifla_linkstats.collisions",
			  FT_UINT64, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_linkstats_rx_len_errs,
			{ "Length errors", "netlink-route.ifla_linkstats.rx_errors.length_errs",
			  FT_UINT64, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_linkstats_rx_over_errs,
			{ "Ring buffer overflow errors", "netlink-route.ifla_linkstats.rx_errors.over_errs",
			  FT_UINT64, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_linkstats_rx_crc_errs,
			{ "CRC errors", "netlink-route.ifla_linkstats.rx_errors.crc_errs",
			  FT_UINT64, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_linkstats_rx_frame_errs,
			{ "Frame alignment errors", "netlink-route.ifla_linkstats.rx_errors.frame_errs",
			  FT_UINT64, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_linkstats_rx_fifo_errs,
			{ "FIFO overrun errors", "netlink-route.ifla_linkstats.rx_errors.fifo_errs",
			  FT_UINT64, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_linkstats_rx_miss_errs,
			{ "Missed packet errors", "netlink-route.ifla_linkstats.rx_errors.miss_errs",
			  FT_UINT64, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_linkstats_tx_abort_errs,
			{ "Abort errors", "netlink-route.ifla_linkstats.rx_errors.abort_errs",
			  FT_UINT64, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_linkstats_tx_carrier_errs,
			{ "Carrier errors", "netlink-route.ifla_linkstats.rx_errors.carrier_errs",
			  FT_UINT64, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_linkstats_tx_fifo_errs,
			{ "FIFO errors", "netlink-route.ifla_linkstats.rx_errors.fifo_errs",
			  FT_UINT64, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_linkstats_tx_heartbeat_errs,
			{ "Heartbeat errors", "netlink-route.ifla_linkstats.rx_errors.heartbeat_errs",
			  FT_UINT64, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifla_linkstats_tx_window_errs,
			{ "Window errors", "netlink-route.ifla_linkstats.rx_errors.window_errs",
			  FT_UINT64, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifa_family,
			{ "Address type", "netlink-route.ifa_family",
			  FT_UINT8, BASE_DEC | BASE_EXT_STRING, &linux_af_vals_ext, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifa_prefixlen,
			{ "Address prefixlength", "netlink-route.ifa_prefixlen",
			  FT_UINT8, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifa_flags,
			{ "Address flags", "netlink-route.ifa_flags",
			  FT_UINT8, BASE_CUSTOM, CF_FUNC(netlink_route_ifa_flags_label), 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifa_scope,
			{ "Address scope", "netlink-route.ifa_scope",
			  FT_UINT8, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifa_index,
			{ "Interface index", "netlink-route.ifa_index",
			  FT_INT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifa_attr_type,
			{ "Attribute type", "netlink-route.ifa_attr_type",
			  FT_UINT16, BASE_DEC, VALS(netlink_route_ifa_attr_vals), 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifa_label,
			{ "Interface name", "netlink-route.ifa_label",
			  FT_STRINGZ, BASE_NONE, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifa_flags32,
			{ "Address flags", "netlink-route.ifa_flags32",
			  FT_UINT32, BASE_CUSTOM, CF_FUNC(netlink_route_ifa_flags_label), 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifa_addr6,
			{ "Address", "netlink-route.ifa_address.ipv6",
			  FT_IPv6, BASE_NONE, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_ifa_addr4,
			{ "Address", "netlink-route.ifa_address.ipv4",
			  FT_IPv4, BASE_NONE, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_rt_family,
			{ "Address family", "netlink-route.rt_family",
			  FT_UINT8, BASE_DEC | BASE_EXT_STRING, &linux_af_vals_ext, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_rt_dst_len,
			{ "Length of destination", "netlink-route.rt_dst_len",
			  FT_UINT8, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_rt_src_len,
			{ "Length of source", "netlink-route.rt_src_len",
			  FT_UINT8, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_rt_tos,
			{ "TOS filter", "netlink-route.rt_tos",
			  FT_UINT8, BASE_HEX, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_rt_table,
			{ "Routing table ID", "netlink-route.rt_table",
			  FT_UINT8, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_rt_protocol,
			{ "Routing protocol", "netlink-route.rt_protocol",
			  FT_UINT8, BASE_HEX | BASE_EXT_STRING, &hf_netlink_route_rt_protocol_vals_ext, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_rt_scope,
			{ "Route origin", "netlink-route.rt_scope",
			  FT_UINT8, BASE_HEX, VALS(netlink_route_rt_scope_vals), 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_rt_type,
			{ "Route type", "netlink-route.rt_type",
			  FT_UINT8, BASE_HEX, VALS(netlink_route_rt_type_vals), 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_rt_flags,
			{ "Route flags", "netlink-route.rt_flags",
			  FT_UINT32, BASE_HEX, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_rta_attr_type,
			{ "Attribute type", "netlink-route.rta_attr_type",
			  FT_UINT16, BASE_DEC, VALS(netlink_route_rta_attr_vals), 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_rta_iif,
			{ "Input interface index", "netlink-route.rta_iif",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_rta_oif,
			{ "Output interface index", "netlink-route.rta_oif",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_nd_family,
			{ "Family", "netlink-route.nd_family",
			  FT_UINT8, BASE_DEC | BASE_EXT_STRING, &linux_af_vals_ext, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_nd_index,
			{ "Interface index", "netlink-route.nd_index",
			  FT_INT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_nd_state,
			{ "State", "netlink-route.nd_state",
			  FT_UINT16, BASE_CUSTOM, CF_FUNC(netlink_route_nd_states_label), 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_nd_flags,
			{ "Flags", "netlink-route.nd_flags",
			  FT_UINT8, BASE_HEX, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_nd_type,
			{ "Type", "netlink-route.nd_type",
			  FT_UINT8, BASE_HEX, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_route_nltype,
			{ "Message type", "netlink-route.nltype",
			  FT_UINT16, BASE_DEC | BASE_EXT_STRING, &netlink_route_type_vals_ext, 0x00,
			  NULL, HFILL }
		},
	};

	static int *ett[] = {
		&ett_netlink_route,
		&ett_netlink_route_attr,
		&ett_netlink_route_if_flags,
		&ett_netlink_route_attr_linkstats,
		&ett_netlink_route_attr_linkstats_rxerrs,
		&ett_netlink_route_attr_linkstats_txerrs,
	};

	proto_netlink_route = proto_register_protocol("Linux rtnetlink (route netlink) protocol", "rtnetlink", "netlink-route" );
	proto_register_field_array(proto_netlink_route, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	netlink_route_handle = register_dissector("netlink-route", dissect_netlink_route, proto_netlink_route);
}

void
proto_reg_handoff_netlink_route(void)
{
	dissector_add_uint("netlink.protocol", WS_NETLINK_ROUTE, netlink_route_handle);
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
