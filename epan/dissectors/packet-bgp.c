/* packet-bgp.c
 * Routines for BGP packet dissection.
 * Copyright 1999, Jun-ichiro itojun Hagino <itojun@itojun.org>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
/* Supports:
 * RFC1771 A Border Gateway Protocol 4 (BGP-4)
 * RFC1965 Autonomous System Confederations for BGP
 * RFC1997 BGP Communities Attribute
 * RFC2547 BGP/MPLS VPNs
 * RFC2796 BGP Route Reflection An alternative to full mesh IBGP
 * RFC2842 Capabilities Advertisement with BGP-4
 * RFC2858 Multiprotocol Extensions for BGP-4
 * RFC2918 Route Refresh Capability for BGP-4
 * RFC3107 Carrying Label Information in BGP-4
 * RFC4486 Subcodes for BGP Cease Notification Message
 * RFC4724 Graceful Restart Mechanism for BGP
 * RFC5512 BGP Encapsulation SAFI and the BGP Tunnel Encapsulation Attribute
 * RFC5640 Load-Balancing for Mesh Softwires
 * RFC6608 Subcodes for BGP Finite State Machine Error
 * draft-ietf-idr-as4bytes-06
 * draft-ietf-idr-dynamic-cap-03
 * draft-ietf-idr-bgp-enhanced-route-refresh-02
 * draft-ietf-idr-bgp-ext-communities-05
 * draft-knoll-idr-qos-attribute-03
 * draft-nalawade-kapoor-tunnel-safi-05
 * draft-ietf-idr-add-paths-04 Additional-Path for BGP-4
 * http://www.iana.org/assignments/bgp-parameters/ (last updated 2012-04-26)

 * TODO:
 * Destination Preference Attribute for BGP (work in progress)
 * RFC1863 A BGP/IDRP Route Server alternative to a full mesh routing
 */

#include "config.h"

#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/addr_and_mask.h>
#include "packet-frame.h"
#include <epan/afn.h>
#include <epan/prefs.h>
#include <epan/emem.h>
#include <epan/expert.h>
#include <epan/etypes.h>

/* #define MAX_STR_LEN 256 */

/* some handy things to know */
#define BGP_MAX_PACKET_SIZE            4096
#define BGP_MARKER_SIZE                  16    /* size of BGP marker */
#define BGP_HEADER_SIZE                  19    /* size of BGP header, including marker */
#define BGP_MIN_OPEN_MSG_SIZE            29
#define BGP_MIN_UPDATE_MSG_SIZE          23
#define BGP_MIN_NOTIFICATION_MSG_SIZE    21
#define BGP_MIN_KEEPALVE_MSG_SIZE       BGP_HEADER_SIZE
#define BGP_TCP_PORT                    179
#define BGP_ROUTE_DISTINGUISHER_SIZE      8

/* BGP message types */
#define BGP_OPEN          1
#define BGP_UPDATE        2
#define BGP_NOTIFICATION  3
#define BGP_KEEPALIVE     4
#define BGP_ROUTE_REFRESH 5
#define BGP_CAPABILITY    6
#define BGP_ROUTE_REFRESH_CISCO 0x80


/* BGP ROUTE-REFRESH message */
struct bgp_route_refresh {
    guint8  bgpr_marker[BGP_MARKER_SIZE];
    guint16 bgpr_len;
    guint8  bgpr_type;
    guint16 bgpr_afi;
    guint8  bgpr_reserved;
    guint8  bgpr_safi;
};

#define BGP_SIZE_OF_PATH_ATTRIBUTE       2


/* attribute flags, from RFC1771 */
#define BGP_ATTR_FLAG_OPTIONAL        0x80
#define BGP_ATTR_FLAG_TRANSITIVE      0x40
#define BGP_ATTR_FLAG_PARTIAL         0x20
#define BGP_ATTR_FLAG_EXTENDED_LENGTH 0x10

/* SSA flags */
#define BGP_SSA_TRANSITIVE    0x8000
#define BGP_SSA_TYPE          0x7FFF

/* SSA Types */
#define BGP_SSA_L2TPv3          1
#define BGP_SSA_mGRE            2
#define BGP_SSA_IPSec           3
#define BGP_SSA_MPLS            4
#define BGP_SSA_L2TPv3_IN_IPSec 5
#define BGP_SSA_mGRE_IN_IPSec   6

/* AS_PATH segment types */
#define AS_SET             1   /* RFC1771 */
#define AS_SEQUENCE        2   /* RFC1771 */
#define AS_CONFED_SET      4   /* RFC1965 has the wrong values, corrected in  */
#define AS_CONFED_SEQUENCE 3   /* draft-ietf-idr-bgp-confed-rfc1965bis-01.txt */

/* OPEN message Optional Parameter types  */
#define BGP_OPTION_AUTHENTICATION    1   /* RFC1771 */
#define BGP_OPTION_CAPABILITY        2   /* RFC2842 */

/* BGP capability code */
#define BGP_CAPABILITY_RESERVED                    0    /* RFC2434 */
#define BGP_CAPABILITY_MULTIPROTOCOL               1    /* RFC2858 */
#define BGP_CAPABILITY_ROUTE_REFRESH               2    /* RFC2918 */
#define BGP_CAPABILITY_COOPERATIVE_ROUTE_FILTERING 3    /* draft-ietf-idr-route-filter-04.txt */
#define BGP_CAPABILITY_GRACEFUL_RESTART            0x40    /* draft-ietf-idr-restart-05  */
#define BGP_CAPABILITY_4_OCTET_AS_NUMBER           0x41    /* draft-ietf-idr-as4bytes-06 */
#define BGP_CAPABILITY_DYNAMIC_CAPABILITY          0x42    /* draft-ietf-idr-dynamic-cap-03 */
#define BGP_CAPABILITY_ADDITIONAL_PATHS            0x45    /* draft-ietf-idr-add-paths */
#define BGP_CAPABILITY_ENHANCED_ROUTE_REFRESH      0x46    /* draft-ietf-idr-bgp-enhanced-route-refresh-02 */
#define BGP_CAPABILITY_ORF_CISCO                   0x82    /* Cisco */
#define BGP_CAPABILITY_ROUTE_REFRESH_CISCO         0x80    /* Cisco */

#define BGP_ORF_PREFIX_CISCO    0x80 /* Cisco */
#define BGP_ORF_COMM_CISCO      0x81 /* Cisco */
#define BGP_ORF_EXTCOMM_CISCO   0x82 /* Cisco */
#define BGP_ORF_ASPATH_CISCO    0x83 /* Cisco */

#define BGP_ORF_COMM        0x02 /* draft-ietf-idr-route-filter-06.txt */
#define BGP_ORF_EXTCOMM     0x03 /* draft-ietf-idr-route-filter-06.txt */
#define BGP_ORF_ASPATH      0x04 /* draft-ietf-idr-aspath-orf-02.txt */
/* draft-ietf-idr-route-filter-06.txt */
#define BGP_ORF_ACTION      0xc0
#define BGP_ORF_ADD         0x00
#define BGP_ORF_REMOVE      0x40
#define BGP_ORF_REMOVEALL   0x80
#define BGP_ORF_MATCH       0x20
#define BGP_ORF_PERMIT      0x00
#define BGP_ORF_DENY        0x20

/* well-known communities, from RFC1997 */
#define BGP_COMM_NO_EXPORT           0xFFFFFF01
#define BGP_COMM_NO_ADVERTISE        0xFFFFFF02
#define BGP_COMM_NO_EXPORT_SUBCONFED 0xFFFFFF03
#define FOURHEX0                     0x00000000
#define FOURHEXF                     0xFFFF0000

/* attribute types */
#define BGPTYPE_ORIGIN              1 /* RFC1771           */
#define BGPTYPE_AS_PATH             2 /* RFC1771           */
#define BGPTYPE_NEXT_HOP            3 /* RFC1771           */
#define BGPTYPE_MULTI_EXIT_DISC     4 /* RFC1771           */
#define BGPTYPE_LOCAL_PREF          5 /* RFC1771           */
#define BGPTYPE_ATOMIC_AGGREGATE    6 /* RFC1771           */
#define BGPTYPE_AGGREGATOR          7 /* RFC1771           */
#define BGPTYPE_COMMUNITIES         8 /* RFC1997           */
#define BGPTYPE_ORIGINATOR_ID       9 /* RFC2796           */
#define BGPTYPE_CLUSTER_LIST       10 /* RFC2796           */
#define BGPTYPE_DPA                11 /* work in progress  */
#define BGPTYPE_ADVERTISER         12 /* RFC1863           */
#define BGPTYPE_RCID_PATH          13 /* RFC1863           */
#define BGPTYPE_MP_REACH_NLRI      14 /* RFC2858           */
#define BGPTYPE_MP_UNREACH_NLRI    15 /* RFC2858           */
#define BGPTYPE_EXTENDED_COMMUNITY 16 /* Draft Ramachandra */
#define BGPTYPE_NEW_AS_PATH        17 /* draft-ietf-idr-as4bytes */
#define BGPTYPE_NEW_AGGREGATOR     18 /* draft-ietf-idr-as4bytes */
#define BGPTYPE_SAFI_SPECIFIC_ATTR 19 /* draft-kapoor-nalawade-idr-bgp-ssa-00.txt */
#define BGPTYPE_TUNNEL_ENCAPS_ATTR 23 /* RFC5512 */

/* Extended community type */
/* according to IANA's number assignment at: http://www.iana.org/assignments/bgp-extended-communities */
#define BGP_EXT_COM_QOS_MARK_T  0x04    /* QoS Marking transitive attribute of regular type (8bit)           */
#define BGP_EXT_COM_QOS_MARK_NT 0x44    /* QoS Marking non-transitive attribute of regular type (8bit)       */
                                        /* Format Type(1byte):Flags(1byte):QoS Set(1byte):Tec. Type(1byte):  */
                                        /*        Marking O(2bytes):Marking A(1byte):Proc.Cnt(1byte)         */
#define BGP_EXT_COM_COS_CAP_T   0x05    /* CoS Capability - Format Type(1byte):Flags(1byte):remaining '0..0' */

                                        /* draft-ietf-idr-bgp-ext-communities */
#define BGP_EXT_COM_RT_0        0x0002  /* Route Target,Format AS(2bytes):AN(4bytes) */
#define BGP_EXT_COM_RT_1        0x0102  /* Route Target,Format IP address:AN(2bytes) */
#define BGP_EXT_COM_RT_2        0x0202  /* Route Target,Format AS(2bytes):AN(4bytes) */
#define BGP_EXT_COM_RO_0        0x0003  /* Route Origin,Format AS(2bytes):AN(4bytes) */
#define BGP_EXT_COM_RO_1        0x0103  /* Route Origin,Format IP address:AN(2bytes) */
#define BGP_EXT_COM_RO_2        0x0203  /* Route Origin,Format AS(2bytes):AN(4bytes) */
#define BGP_EXT_COM_LINKBAND    ((BGP_ATTR_FLAG_TRANSITIVE << 8) | 0x0004)
                                        /* Link Bandwidth,Format AS(2bytes):
                                         * Bandwidth(4bytes) */
                                        /* -2 version of the draft */
#define BGP_EXT_COM_VPN_ORIGIN  0x0005  /* OSPF Domin ID / VPN of Origin  */
                                        /* draft-rosen-vpns-ospf-bgp-mpls */
#define BGP_EXT_COM_OSPF_RTYPE  0x8000  /* OSPF Route Type,Format Area(4B):RouteType(1B):Options(1B) */
#define BGP_EXT_COM_OSPF_RID    0x8001  /* OSPF Router ID,Format RouterID(4B):Unused(2B) */
#define BGP_EXT_COM_L2INFO      0x800a  /* draft-kompella-ppvpn-l2vpn */

/* Extended community QoS Marking technology type */
#define QOS_TECH_TYPE_DSCP         0x00  /* DiffServ enabled IP (DSCP encoding) */
#define QOS_TECH_TYPE_802_1q       0x01  /* Ethernet using 802.1q priority tag */
#define QOS_TECH_TYPE_E_LSP        0x02  /* MPLS using E-LSP */
#define QOS_TECH_TYPE_VC           0x03  /* Virtual Channel (VC) encoding using separate channels for */
                                         /* QoS forwarding / one channel per class (e.g. ATM VCs, FR  */
                                         /* VCs, MPLS L-LSPs) */
#define QOS_TECH_TYPE_GMPLS_TIME   0x04   /* GMPLS - time slot encoding */
#define QOS_TECH_TYPE_GMPLS_LAMBDA 0x05  /* GMPLS - lambda encoding */
#define QOS_TECH_TYPE_GMPLS_FIBRE  0x06  /* GMPLS - fibre encoding */

/* OSPF codes for  BGP_EXT_COM_OSPF_RTYPE draft-rosen-vpns-ospf-bgp-mpls  */
#define BGP_OSPF_RTYPE_RTR      1 /* OSPF Router LSA */
#define BGP_OSPF_RTYPE_NET      2 /* OSPF Network LSA */
#define BGP_OSPF_RTYPE_SUM      3 /* OSPF Summary LSA */
#define BGP_OSPF_RTYPE_EXT      5 /* OSPF External LSA, note that ASBR doesn't apply to MPLS-VPN */
#define BGP_OSPF_RTYPE_NSSA     7 /* OSPF NSSA External*/
#define BGP_OSPF_RTYPE_SHAM     129 /* OSPF-MPLS-VPN Sham link */
#define BGP_OSPF_RTYPE_METRIC_TYPE 0x1 /* LSB of RTYPE Options Field */

/* Extended community & Route dinstinguisher formats */
#define FORMAT_AS2_LOC      0x00    /* Format AS(2bytes):AN(4bytes) */
#define FORMAT_IP_LOC       0x01    /* Format IP address:AN(2bytes) */
#define FORMAT_AS4_LOC      0x02    /* Format AS(4bytes):AN(2bytes) */

/* RFC 2858 subsequent address family numbers */
#define SAFNUM_UNICAST          1
#define SAFNUM_MULCAST          2
#define SAFNUM_UNIMULC          3
#define SAFNUM_MPLS_LABEL       4  /* rfc3107 */
#define SAFNUM_MCAST_VPN        5  /* draft-ietf-l3vpn-2547bis-mcast-bgp-08.txt */
#define SAFNUM_ENCAPSULATION    7  /* rfc5512 */
#define SAFNUM_TUNNEL          64  /* draft-nalawade-kapoor-tunnel-safi-02.txt */
#define SAFNUM_VPLS            65
#define SAFNUM_MDT             66  /* rfc6037 */
#define SAFNUM_LAB_VPNUNICAST 128  /* Draft-rosen-rfc2547bis-03 */
#define SAFNUM_LAB_VPNMULCAST 129
#define SAFNUM_LAB_VPNUNIMULC 130
#define SAFNUM_ROUTE_TARGET   132  /* RFC 4684 Constrained Route Distribution for BGP/MPLS IP VPN */

/* BGP Additional Paths Capability */
#define BGP_ADDPATH_RECEIVE  0x01
#define BGP_ADDPATH_SEND     0x02

/* mcast-vpn route types draft-ietf-l3vpn-2547bis-mcast-bgp-08.txt */
#define MCAST_VPN_RTYPE_INTRA_AS_IPMSI_AD 1
#define MCAST_VPN_RTYPE_INTER_AS_IPMSI_AD 2
#define MCAST_VPN_RTYPE_SPMSI_AD          3
#define MCAST_VPN_RTYPE_LEAF_AD           4
#define MCAST_VPN_RTYPE_SOURCE_ACTIVE_AD  5
#define MCAST_VPN_RTYPE_SHARED_TREE_JOIN  6
#define MCAST_VPN_RTYPE_SOURCE_TREE_JOIN  7

/* RFC 5512 Tunnel Types */
#define TUNNEL_TYPE_L2TP_OVER_IP 1
#define TUNNEL_TYPE_GRE          2
#define TUNNEL_TYPE_IP_IN_IP     7

/* RFC 5512/5640 Sub-TLV Types */
#define TUNNEL_SUBTLV_ENCAPSULATION 1
#define TUNNEL_SUBTLV_PROTO_TYPE    2
#define TUNNEL_SUBTLV_COLOR         4
#define TUNNEL_SUBTLV_LOAD_BALANCE  5

#ifndef offsetof
#define offsetof(type, member)  ((size_t)(&((type *)0)->member))
#endif


static const value_string bgptypevals[] = {
    { BGP_OPEN,                "OPEN Message" },
    { BGP_UPDATE,              "UPDATE Message" },
    { BGP_NOTIFICATION,        "NOTIFICATION Message" },
    { BGP_KEEPALIVE,           "KEEPALIVE Message" },
    { BGP_ROUTE_REFRESH,       "ROUTE-REFRESH Message" },
    { BGP_CAPABILITY,          "CAPABILITY Message" },
    { BGP_ROUTE_REFRESH_CISCO, "Cisco ROUTE-REFRESH Message" },
    { 0, NULL }
};

#define BGP_MAJOR_ERROR_MSG_HDR       1
#define BGP_MAJOR_ERROR_OPEN_MSG      2
#define BGP_MAJOR_ERROR_UPDATE_MSG    3
#define BGP_MAJOR_ERROR_HT_EXPIRED    4
#define BGP_MAJOR_ERROR_STATE_MACHINE 5
#define BGP_MAJOR_ERROR_CEASE         6
#define BGP_MAJOR_ERROR_CAP_MSG       7

static const value_string bgpnotify_major[] = {
    { BGP_MAJOR_ERROR_MSG_HDR,       "Message Header Error" },
    { BGP_MAJOR_ERROR_OPEN_MSG,      "OPEN Message Error" },
    { BGP_MAJOR_ERROR_UPDATE_MSG,    "UPDATE Message Error" },
    { BGP_MAJOR_ERROR_HT_EXPIRED,    "Hold Timer Expired" },
    { BGP_MAJOR_ERROR_STATE_MACHINE, "Finite State Machine Error" },
    { BGP_MAJOR_ERROR_CEASE,         "Cease" },
    { BGP_MAJOR_ERROR_CAP_MSG,       "CAPABILITY Message Error" },
    { 0, NULL }
};

static const value_string bgpnotify_minor_msg_hdr[] = {
    { 1, "Connection Not Synchronized" },
    { 2, "Bad Message Length" },
    { 3, "Bad Message Type" },
    { 0, NULL }
};

static const value_string bgpnotify_minor_open_msg[] = {
    { 1, "Unsupported Version Number" },
    { 2, "Bad Peer AS" },
    { 3, "Bad BGP Identifier" },
    { 4, "Unsupported Optional Parameter" },
    { 5, "Authentication Failure [Deprecated]" },
    { 6, "Unacceptable Hold Time" },
    { 7, "Unsupported Capability" },
    { 0, NULL }
};

static const value_string bgpnotify_minor_update_msg[] = {
    { 1,  "Malformed Attribute List" },
    { 2,  "Unrecognized Well-known Attribute" },
    { 3,  "Missing Well-known Attribute" },
    { 4,  "Attribute Flags Error" },
    { 5,  "Attribute Length Error" },
    { 6,  "Invalid ORIGIN Attribute" },
    { 7,  "AS Routing Loop [Deprecated]" },
    { 8,  "Invalid NEXT_HOP Attribute" },
    { 9,  "Optional Attribute Error" },
    { 10, "Invalid Network Field" },
    { 11, "Malformed AS_PATH" },
    { 0, NULL }
};
/* RFC6608 Subcodes for BGP Finite State Machine Error */
static const value_string bgpnotify_minor_state_machine[] = {
    { 1, "Receive Unexpected Message in OpenSent State" },
    { 2, "Receive Unexpected Message in OpenConfirm State" },
    { 3, "Receive Unexpected Message in Established State" },
    { 0, NULL }
};

/* RFC4486 Subcodes for BGP Cease Notification Message */
static const value_string bgpnotify_minor_cease[] = {
    { 1, "Maximum Number of Prefixes Reached"},
    { 2, "Administratively Shutdown"},
    { 3, "Peer De-configured"},
    { 4, "Administratively Reset"},
    { 5, "Connection Rejected"},
    { 6, "Other Configuration Change"},
    { 7, "Connection Collision Resolution"},
    { 8, "Out of Resources"},
    { 0, NULL }
};

static const value_string bgpnotify_minor_cap_msg[] = {
    { 1, "Invalid Action Value" },
    { 2, "Invalid Capability Length" },
    { 3, "Malformed Capability Value" },
    { 4, "Unsupported Capability Code" },
    { 0, NULL }
};

static const value_string bgpattr_origin[] = {
    { 0, "IGP" },
    { 1, "EGP" },
    { 2, "INCOMPLETE" },
    { 0, NULL }
};

static const value_string bgp_open_opt_vals[] = {
    { BGP_OPTION_AUTHENTICATION, "Authentication" },
    { BGP_OPTION_CAPABILITY, "Capability" },
    { 0, NULL }
};

static const value_string as_segment_type[] = {
    { 1, "AS_SET" },
    { 2, "AS_SEQUENCE" },
/* RFC1965 has the wrong values, corrected in  */
/* draft-ietf-idr-bgp-confed-rfc1965bis-01.txt */
    { 4, "AS_CONFED_SET" },
    { 3, "AS_CONFED_SEQUENCE" },
    { 0, NULL }
};

static const value_string bgpattr_type[] = {
    { BGPTYPE_ORIGIN,             "ORIGIN" },
    { BGPTYPE_AS_PATH,            "AS_PATH" },
    { BGPTYPE_NEXT_HOP,           "NEXT_HOP" },
    { BGPTYPE_MULTI_EXIT_DISC,    "MULTI_EXIT_DISC" },
    { BGPTYPE_LOCAL_PREF,         "LOCAL_PREF" },
    { BGPTYPE_ATOMIC_AGGREGATE,   "ATOMIC_AGGREGATE" },
    { BGPTYPE_AGGREGATOR,         "AGGREGATOR" },
    { BGPTYPE_COMMUNITIES,        "COMMUNITIES" },
    { BGPTYPE_ORIGINATOR_ID,      "ORIGINATOR_ID" },
    { BGPTYPE_CLUSTER_LIST,       "CLUSTER_LIST" },
    { BGPTYPE_MP_REACH_NLRI,      "MP_REACH_NLRI" },
    { BGPTYPE_MP_UNREACH_NLRI,    "MP_UNREACH_NLRI" },
    { BGPTYPE_EXTENDED_COMMUNITY, "EXTENDED_COMMUNITIES" },
    { BGPTYPE_NEW_AS_PATH,        "NEW_AS_PATH" },
    { BGPTYPE_NEW_AGGREGATOR,     "NEW_AGGREGATOR" },
    { BGPTYPE_SAFI_SPECIFIC_ATTR, "SAFI_SPECIFIC_ATTRIBUTE" },
    { BGPTYPE_TUNNEL_ENCAPS_ATTR, "TUNNEL_ENCAPSULATION_ATTRIBUTE" },
    { 0, NULL }
};

static const value_string tunnel_type[] = {
    { TUNNEL_TYPE_L2TP_OVER_IP, "L2TP_OVER_IP" },
    { TUNNEL_TYPE_GRE, "GRE" },
    { TUNNEL_TYPE_IP_IN_IP, "IP_IN_IP" },
    { 0, NULL }
};

static const value_string subtlv_type[] = {
    { TUNNEL_SUBTLV_ENCAPSULATION, "ENCAPSULATION" },
    { TUNNEL_SUBTLV_PROTO_TYPE,    "PROTOCOL_TYPE" },
    { TUNNEL_SUBTLV_COLOR,         "COLOR" },
    { TUNNEL_SUBTLV_LOAD_BALANCE,  "LOAD_BALANCE" },
    { 0, NULL }
};

static const value_string bgpext_com8_type[] = {
    { BGP_EXT_COM_QOS_MARK_T,  "QoS Marking - transitive" },
    { BGP_EXT_COM_QOS_MARK_NT, "QoS Marking - non-transitive" },
    { BGP_EXT_COM_COS_CAP_T,   "CoS Capability - transitive" },
    { 0, NULL }
};

static const value_string bgpext_com_type[] = {
    { BGP_EXT_COM_RT_0,       "two-octet AS specific Route Target" },
    { BGP_EXT_COM_RT_1,       "IPv4 address specific Route Target" },
    { BGP_EXT_COM_RT_2,       "four-octet AS specific Route Target" },
    { BGP_EXT_COM_RO_0,       "two-octet AS specific Route Origin" },
    { BGP_EXT_COM_RO_1,       "IPv4 address specific Route Origin" },
    { BGP_EXT_COM_RO_2,       "four-octet AS specific Route Origin" },
    { BGP_EXT_COM_LINKBAND,   "Link Bandwidth" },
    { BGP_EXT_COM_VPN_ORIGIN, "OSPF Domain" },
    { BGP_EXT_COM_OSPF_RTYPE, "OSPF Route Type" },
    { BGP_EXT_COM_OSPF_RID,   "OSPF Router ID" },
    { BGP_EXT_COM_L2INFO,     "Layer 2 Information" },
    { 0, NULL }
};

static const value_string qos_tech_type[] = {
    { QOS_TECH_TYPE_DSCP,         "DiffServ enabled IP (DSCP encoding)" },
    { QOS_TECH_TYPE_802_1q,       "Ethernet using 802.1q priority tag" },
    { QOS_TECH_TYPE_E_LSP,        "MPLS using E-LSP" },
    { QOS_TECH_TYPE_VC,           "Virtual Channel (VC) encoding" },
    { QOS_TECH_TYPE_GMPLS_TIME,   "GMPLS - time slot encoding" },
    { QOS_TECH_TYPE_GMPLS_LAMBDA, "GMPLS - lambda encoding" },
    { QOS_TECH_TYPE_GMPLS_FIBRE,  "GMPLS - fibre encoding" },
    { 0, NULL }
};

static const value_string bgp_ssa_type[] = {
    { BGP_SSA_L2TPv3 ,          "L2TPv3 Tunnel" },
    { BGP_SSA_mGRE ,            "mGRE Tunnel" },
    { BGP_SSA_IPSec ,           "IPSec Tunnel" },
    { BGP_SSA_MPLS ,            "MPLS Tunnel" },
    { BGP_SSA_L2TPv3_IN_IPSec , "L2TPv3 in IPSec Tunnel" },
    { BGP_SSA_mGRE_IN_IPSec ,   "mGRE in IPSec Tunnel" },
    { 0, NULL }
};

static const value_string bgp_l2vpn_encaps[] = {
    { 0,  "Reserved"},
    { 1,  "Frame Relay"},
    { 2,  "ATM AAL5 VCC transport"},
    { 3,  "ATM transparent cell transport"},
    { 4,  "Ethernet VLAN"},
    { 5,  "Ethernet"},
    { 6,  "Cisco-HDLC"},
    { 7,  "PPP"},
    { 8,  "CEM"},
    { 9,  "ATM VCC cell transport"},
    { 10, "ATM VPC cell transport"},
    { 11, "MPLS"},
    { 12, "VPLS"},
    { 64, "IP-interworking"},
    { 0, NULL }
};

static const value_string bgpext_ospf_rtype[] = {
  { BGP_OSPF_RTYPE_RTR, "Router" },
  { BGP_OSPF_RTYPE_NET, "Network" },
  { BGP_OSPF_RTYPE_SUM, "Summary" },
  { BGP_OSPF_RTYPE_EXT, "External" },
  { BGP_OSPF_RTYPE_NSSA,"NSSA External" },
  { BGP_OSPF_RTYPE_SHAM,"MPLS-VPN Sham" },
  { 0, NULL }
};

/* Subsequent address family identifier, RFC2858 */
static const value_string bgpattr_nlri_safi[] = {
    { 0,                     "Reserved" },
    { SAFNUM_UNICAST,        "Unicast" },
    { SAFNUM_MULCAST,        "Multicast" },
    { SAFNUM_UNIMULC,        "Unicast+Multicast" },
    { SAFNUM_MPLS_LABEL,     "Labeled Unicast"},
    { SAFNUM_MCAST_VPN,      "MCAST-VPN"},
    { SAFNUM_ENCAPSULATION,  "Encapsulation"},
    { SAFNUM_TUNNEL,         "Tunnel"},
    { SAFNUM_VPLS,           "VPLS"},
    { SAFNUM_LAB_VPNUNICAST, "Labeled VPN Unicast" },        /* draft-rosen-rfc2547bis-03 */
    { SAFNUM_LAB_VPNMULCAST, "Labeled VPN Multicast" },
    { SAFNUM_LAB_VPNUNIMULC, "Labeled VPN Unicast+Multicast" },
    { SAFNUM_ROUTE_TARGET,   "Route Target Filter" },
    { 0, NULL }
};

/* ORF Type, draft-ietf-idr-route-filter-04.txt */
static const value_string orf_type_vals[] = {
    {   2,      "Communities ORF-Type" },
    {   3,      "Extended Communities ORF-Type" },
    { 128,      "Cisco PrefixList ORF-Type" },
    { 129,      "Cisco CommunityList ORF-Type" },
    { 130,      "Cisco Extended CommunityList ORF-Type" },
    { 131,      "Cisco AsPathList ORF-Type" },
    { 0,        NULL }
};

/* ORF Send/Receive, draft-ietf-idr-route-filter-04.txt */
static const value_string orf_send_recv_vals[] = {
    { 1,        "Receive" },
    { 2,        "Send" },
    { 3,        "Both" },
    { 0,        NULL }
};

/* ORF Send/Receive, draft-ietf-idr-route-filter-04.txt */
static const value_string orf_when_vals[] = {
    { 1,        "Immediate" },
    { 2,        "Defer" },
    { 0,        NULL }
};

static const value_string orf_entry_action_vals[] = {
    { 0,        "Add" },
    { 0x40,     "Remove" },
    { 0x80,     "RemoveAll" },
    { 0,        NULL }
};

static const value_string orf_entry_match_vals[] = {
    { 0,        "Permit" },
    { 0x20,     "Deny" },
    { 0,        NULL }
};

static const value_string capability_vals[] = {
    { BGP_CAPABILITY_RESERVED,                    "Reserved capability" },
    { BGP_CAPABILITY_MULTIPROTOCOL,               "Multiprotocol extensions capability" },
    { BGP_CAPABILITY_ROUTE_REFRESH,               "Route refresh capability" },
    { BGP_CAPABILITY_COOPERATIVE_ROUTE_FILTERING, "Cooperative route filtering capability" },
    { BGP_CAPABILITY_GRACEFUL_RESTART,            "Graceful Restart capability" },
    { BGP_CAPABILITY_4_OCTET_AS_NUMBER,           "Support for 4-octet AS number capability" },
    { BGP_CAPABILITY_DYNAMIC_CAPABILITY,          "Support for Dynamic capability" },
    { BGP_CAPABILITY_ADDITIONAL_PATHS,            "Support for Additional Paths" },
    { BGP_CAPABILITY_ROUTE_REFRESH_CISCO,         "Route refresh capability" },
    { BGP_CAPABILITY_ORF_CISCO,                   "Cooperative route filtering capability" },
    { BGP_CAPABILITY_ENHANCED_ROUTE_REFRESH,      "Enhanced route refresh capability" },
    { 0, NULL }
};

/* Capability Message action code */
static const value_string bgpcap_action[] = {
    { 0, "advertising a capability" },
    { 1, "removing a capability" },
    { 0, NULL }
};

static const value_string mcast_vpn_route_type[] = {
    { MCAST_VPN_RTYPE_INTRA_AS_IPMSI_AD, "Intra-AS I-PMSI A-D route" },
    { MCAST_VPN_RTYPE_INTER_AS_IPMSI_AD, "Inter-AS I-PMSI A-D route" },
    { MCAST_VPN_RTYPE_SPMSI_AD         , "S-PMSI A-D route" },
    { MCAST_VPN_RTYPE_LEAF_AD          , "Leaf A-D route" },
    { MCAST_VPN_RTYPE_SOURCE_ACTIVE_AD , "Source Active A-D route" },
    { MCAST_VPN_RTYPE_SHARED_TREE_JOIN , "Shared Tree Join route" },
    { MCAST_VPN_RTYPE_SOURCE_TREE_JOIN , "Source Tree Join route" },
    { 0, NULL }
};

/* Subtype Route Refresh, draft-ietf-idr-bgp-enhanced-route-refresh-02 */
static const value_string route_refresh_subtype_vals[] = {
    { 0, "Normal route refresh request [RFC2918] with/without ORF [RFC5291]" },
    { 1, "Demarcation of the beginning of a route refresh" },
    { 2, "Demarcation of the ending of a route refresh" },
    { 0,  NULL }
};

static const true_false_string tfs_optional_wellknown = { "Optional", "Well-known" };
static const true_false_string tfs_transitive_non_transitive = { "Transitive", "Non-transitive" };
static const true_false_string tfs_partial_complete = { "Partial", "Complete" };
static const true_false_string tfs_extended_regular_length = { "Extended length", "Regular length" };

/* Maximal size of an IP address string */
#define MAX_SIZE_OF_IP_ADDR_STRING      16

static int proto_bgp = -1;
static int hf_bgp_marker = -1;
static int hf_bgp_length = -1;
static int hf_bgp_type = -1;
static int hf_bgp_open_version = -1;
static int hf_bgp_open_myas = -1;
static int hf_bgp_open_holdtime = -1;
static int hf_bgp_open_identifier = -1;
static int hf_bgp_open_opt_len = -1;
static int hf_bgp_open_opt_params = -1;
static int hf_bgp_open_opt_param = -1;
static int hf_bgp_open_opt_param_type = -1;
static int hf_bgp_open_opt_param_len = -1;
static int hf_bgp_open_opt_param_auth = -1;
static int hf_bgp_open_opt_param_unknown = -1;
static int hf_bgp_notify_major_error = -1;
static int hf_bgp_notify_minor_msg_hdr = -1;
static int hf_bgp_notify_minor_open_msg = -1;
static int hf_bgp_notify_minor_update_msg = -1;
static int hf_bgp_notify_minor_ht_expired = -1;
static int hf_bgp_notify_minor_state_machine = -1;
static int hf_bgp_notify_minor_cease = -1;
static int hf_bgp_notify_minor_cap_msg = -1;
static int hf_bgp_notify_minor_unknown = -1;
static int hf_bgp_notify_data = -1;
static int hf_bgp_route_refresh_afi = -1;
static int hf_bgp_route_refresh_subtype = -1;
static int hf_bgp_route_refresh_safi = -1;
static int hf_bgp_cap = -1;
static int hf_bgp_cap_type = -1;
static int hf_bgp_cap_length = -1;
static int hf_bgp_cap_action = -1;
static int hf_bgp_cap_unknown = -1;
static int hf_bgp_cap_reserved = -1;
static int hf_bgp_cap_mp_afi = -1;
static int hf_bgp_cap_mp_safi = -1;
static int hf_bgp_cap_gr_timers = -1;
static int hf_bgp_cap_gr_timers_restart_flag = -1;
static int hf_bgp_cap_gr_timers_restart_time = -1;
static int hf_bgp_cap_gr_afi = -1;
static int hf_bgp_cap_gr_safi = -1;
static int hf_bgp_cap_gr_flag = -1;
static int hf_bgp_cap_gr_flag_pfs = -1;
static int hf_bgp_cap_4as = -1;
static int hf_bgp_cap_dc = -1;
static int hf_bgp_cap_ap_afi = -1;
static int hf_bgp_cap_ap_safi = -1;
static int hf_bgp_cap_ap_sendreceive = -1;
static int hf_bgp_cap_orf_afi = -1;
static int hf_bgp_cap_orf_safi = -1;
static int hf_bgp_cap_orf_number = -1;
static int hf_bgp_cap_orf_type = -1;
static int hf_bgp_cap_orf_sendreceive = -1;

static int hf_bgp_next_hop = -1;
static int hf_bgp_as_path = -1;
static int hf_bgp_community_as = -1;
static int hf_bgp_community_value = -1;
static int hf_bgp_origin = -1;
static int hf_bgp_cluster_list = -1;
static int hf_bgp_originator_id = -1;
static int hf_bgp_ssa_t = -1;
static int hf_bgp_ssa_type = -1;
static int hf_bgp_ssa_len = -1;
static int hf_bgp_ssa_value = -1;
static int hf_bgp_ssa_l2tpv3_pref = -1;
static int hf_bgp_ssa_l2tpv3_s = -1;
static int hf_bgp_ssa_l2tpv3_unused = -1;
static int hf_bgp_ssa_l2tpv3_cookie_len = -1;
static int hf_bgp_ssa_l2tpv3_session_id = -1;
static int hf_bgp_ssa_l2tpv3_cookie = -1;
static int hf_bgp_local_pref = -1;
static int hf_bgp_multi_exit_disc = -1;
static int hf_bgp_aggregator_as = -1;
static int hf_bgp_aggregator_origin = -1;
static int hf_bgp_mp_reach_nlri_ipv4_prefix = -1;
static int hf_bgp_mp_unreach_nlri_ipv4_prefix = -1;
static int hf_bgp_mp_nlri_tnl_id = -1;
static int hf_bgp_withdrawn_prefix = -1;
static int hf_bgp_nlri_prefix = -1;
static int hf_bgp_nlri_path_id = -1;
static int hf_bgp_mcast_vpn_nlri_t = -1;
static int hf_bgp_mcast_vpn_nlri_route_type = -1;
static int hf_bgp_mcast_vpn_nlri_length = -1;
static int hf_bgp_mcast_vpn_nlri_rd = -1;
static int hf_bgp_mcast_vpn_nlri_origin_router_ipv4 = -1;
static int hf_bgp_mcast_vpn_nlri_origin_router_ipv6 = -1;
static int hf_bgp_mcast_vpn_nlri_source_as = -1;
static int hf_bgp_mcast_vpn_nlri_source_length = -1;
static int hf_bgp_mcast_vpn_nlri_group_length = -1;
static int hf_bgp_mcast_vpn_nlri_source_addr_ipv4 = -1;
static int hf_bgp_mcast_vpn_nlri_source_addr_ipv6 = -1;
static int hf_bgp_mcast_vpn_nlri_group_addr_ipv4 = -1;
static int hf_bgp_mcast_vpn_nlri_group_addr_ipv6 = -1;
static int hf_bgp_mcast_vpn_nlri_route_key = -1;
static int hf_bgp_encaps_tunnel_tlv_len = -1;
static int hf_bgp_encaps_tunnel_tlv_type = -1;
static int hf_bgp_encaps_tunnel_subtlv_len = -1;
static int hf_bgp_encaps_tunnel_subtlv_type = -1;
static int hf_bgp_mdt_safi_rd = -1;
static int hf_bgp_mdt_safi_ipv4_addr = -1;
static int hf_bgp_mdt_safi_group_addr = -1;
static int hf_bgp_flags_optional = -1;
static int hf_bgp_flags_transitive = -1;
static int hf_bgp_flags_partial = -1;
static int hf_bgp_flags_extended_length = -1;
static int hf_bgp_ext_com_qos_flags = -1;
static int hf_bgp_ext_com_qos_flags_remarking = -1;
static int hf_bgp_ext_com_qos_flags_ignore_remarking = -1;
static int hf_bgp_ext_com_qos_flags_agg_marking = -1;
static int hf_bgp_ext_com_cos_flags = -1;
static int hf_bgp_ext_com_cos_flags_be = -1;
static int hf_bgp_ext_com_cos_flags_ef = -1;
static int hf_bgp_ext_com_cos_flags_af = -1;
static int hf_bgp_ext_com_cos_flags_le = -1;
static int hf_bgp_ext_com_qos_set_number = -1;
static int hf_bgp_ext_com_qos_tech_type = -1;
static int hf_bgp_ext_com_qos_marking_o = -1;
static int hf_bgp_ext_com_qos_marking_a = -1;
static int hf_bgp_ext_com_qos_default_to_zero = -1;

static gint ett_bgp = -1;
static gint ett_bgp_prefix = -1;
static gint ett_bgp_unfeas = -1;
static gint ett_bgp_attrs = -1;
static gint ett_bgp_attr = -1;
static gint ett_bgp_attr_flags = -1;
static gint ett_bgp_mp_nhna = -1;
static gint ett_bgp_mp_reach_nlri = -1;
static gint ett_bgp_mp_unreach_nlri = -1;
static gint ett_bgp_mp_snpa = -1;
static gint ett_bgp_nlri = -1;
static gint ett_bgp_open = -1;
static gint ett_bgp_update = -1;
static gint ett_bgp_notification = -1;
static gint ett_bgp_route_refresh = -1; /* ROUTE-REFRESH message tree */
static gint ett_bgp_capability = -1;
static gint ett_bgp_as_paths = -1;
static gint ett_bgp_as_path_segments = -1;
static gint ett_bgp_communities = -1;
static gint ett_bgp_cluster_list = -1;  /* cluster list tree          */
static gint ett_bgp_options = -1;       /* optional parameters tree   */
static gint ett_bgp_option = -1;        /* an optional parameter tree */
static gint ett_bgp_cap = -1;           /* an cap parameter tree */
static gint ett_bgp_extended_communities = -1; /* extended communities list tree */
static gint ett_bgp_ext_com_flags = -1; /* extended communities flags tree */
static gint ett_bgp_ssa = -1;           /* safi specific attribute */
static gint ett_bgp_ssa_subtree = -1;   /* safi specific attribute Subtrees */
static gint ett_bgp_orf = -1;           /* orf (outbound route filter) tree */
static gint ett_bgp_orf_entry = -1;     /* orf entry tree */
static gint ett_bgp_mcast_vpn_nlri = -1;
static gint ett_bgp_tunnel_tlv = -1;
static gint ett_bgp_tunnel_tlv_subtree = -1;
static gint ett_bgp_tunnel_subtlv = -1;
static gint ett_bgp_tunnel_subtlv_subtree = -1;

/* desegmentation */
static gboolean bgp_desegment = TRUE;

static gint bgp_asn_len = 0;

/*
 * Detect IPv4 prefixes  conform to BGP Additional Path but NOT conform to standard BGP
 *
 * A real BGP speaker would rely on the BGP Additional Path in the BGP Open messages.
 * But it is not suitable for a packet analyse because the BGP sessions are not supposed to
 * restart very often, and Open messages from both sides of the session would be needed
 * to determine the result of the capability negociation.
 * Code inspired from the decode_prefix4 function
 */
static int
detect_add_path_prefix4(tvbuff_t *tvb, gint offset, gint end) {
    guint32 addr_len;
    guint8 prefix_len;
    gint o;
    /* Must be compatible with BGP Additional Path  */
    for (o = offset + 4; o < end; o += 4) {
        prefix_len = tvb_get_guint8(tvb, o);
        if( prefix_len > 32) {
            return 0; /* invalid prefix lenght - not BGP add-path */
        }
        addr_len = (prefix_len + 7) / 8;
        o += 1 + addr_len;
        if( o > end ) {
            return 0; /* invalid offset - not BGP add-path */
        }
        if (prefix_len % 8) {
            /* detect bits set after the end of the prefix */
            if( tvb_get_guint8(tvb, o - 1 )  & (0xFF >> (prefix_len % 8)) ) {
                return 0; /* invalid prefix content - not BGP add-path */
            }
        }
    }
    /* Must NOT be compatible with standard BGP */
    for (o = offset; o < end; ) {
        prefix_len = tvb_get_guint8(tvb, o);
        if( prefix_len > 32) {
            return 1; /* invalid prefix lenght - may be BGP add-path */
        }
        addr_len = (prefix_len + 7) / 8;
        o += 1 + addr_len;
        if( o > end ) {
            return 1; /* invalid offset - may be BGP add-path */
        }
        if (prefix_len % 8) {
            /* detect bits set after the end of the prefix */
            if( tvb_get_guint8(tvb, o - 1 ) & (0xFF >> (prefix_len % 8)) ) {
                return 1; /* invalid prefix content - may be BGP add-path (or a bug) */
            }
        }
    }
    return 0; /* valid - do not assume Additional Path */
}
/*
 * Decode an IPv4 prefix with Path Identifier
 * Code inspired from the decode_prefix4 function
 */
static int
decode_path_prefix4(proto_tree *tree, int hf_path_id, int hf_addr, tvbuff_t *tvb, gint offset,
                    const char *tag)
{
    proto_item *ti;
    proto_tree *prefix_tree;
    union {
       guint8 addr_bytes[4];
       guint32 addr;
    } ip_addr;        /* IP address                         */
    guint8 plen;      /* prefix length                      */
    int    length;    /* number of octets needed for prefix */
    guint32 path_identifier;
    /* snarf path identifier length and prefix */
    path_identifier = tvb_get_ntohl(tvb, offset);
    plen = tvb_get_guint8(tvb, offset + 4);
    length = ipv4_addr_and_mask(tvb, offset + 4 + 1, ip_addr.addr_bytes, plen);
    if (length < 0) {
        proto_tree_add_text(tree, tvb, offset + 4 , 1, "%s length %u invalid (> 32)",
            tag, plen);
        return -1;
    }
    /* put prefix into protocol tree */
    ti = proto_tree_add_text(tree, tvb, offset,
                             4 + 1 + length, "%s/%u PathId %u ",
                            ip_to_str(ip_addr.addr_bytes), plen, path_identifier);
    prefix_tree = proto_item_add_subtree(ti, ett_bgp_prefix);
    if (hf_path_id != -1) {
        proto_tree_add_uint(prefix_tree, hf_path_id, tvb, offset, 4,
                            path_identifier);
    } else {
        proto_tree_add_text(prefix_tree, tvb, offset, 4,
                            "%s Path Id: %u", tag, path_identifier);
    }
    proto_tree_add_text(prefix_tree, tvb, offset + 4, 1, "%s prefix length: %u",
                        tag, plen);
    if (hf_addr != -1) {
        proto_tree_add_ipv4(prefix_tree, hf_addr, tvb, offset + 4 + 1, length,
            ip_addr.addr);
    } else {
        proto_tree_add_text(prefix_tree, tvb, offset + 4 + 1, length,
            "%s prefix: %s", tag, ip_to_str(ip_addr.addr_bytes));
    }
    return(4 + 1 + length);
}

/*
 * Decode an IPv4 prefix.
 */
static int
decode_prefix4(proto_tree *tree, int hf_addr, tvbuff_t *tvb, gint offset,
               guint16 tlen, const char *tag)
{
    proto_item *ti;
    proto_tree *prefix_tree;
    union {
       guint8 addr_bytes[4];
       guint32 addr;
    } ip_addr;        /* IP address                         */
    guint8 plen;      /* prefix length                      */
    int    length;    /* number of octets needed for prefix */

    /* snarf length and prefix */
    plen = tvb_get_guint8(tvb, offset);
    length = ipv4_addr_and_mask(tvb, offset + 1, ip_addr.addr_bytes, plen);
    if (length < 0) {
        proto_tree_add_text(tree, tvb, offset, 1, "%s length %u invalid (> 32)",
            tag, plen);
        return -1;
    }

    /* put prefix into protocol tree */
    ti = proto_tree_add_text(tree, tvb, offset,
            tlen != 0 ? tlen : 1 + length, "%s/%u",
                             ip_to_str(ip_addr.addr_bytes), plen);
    prefix_tree = proto_item_add_subtree(ti, ett_bgp_prefix);
    proto_tree_add_text(prefix_tree, tvb, offset, 1, "%s prefix length: %u",
        tag, plen);
    if (hf_addr != -1) {
        proto_tree_add_ipv4(prefix_tree, hf_addr, tvb, offset + 1, length,
            ip_addr.addr);
    } else {
        proto_tree_add_text(prefix_tree, tvb, offset + 1, length,
            "%s prefix: %s", tag, ip_to_str(ip_addr.addr_bytes));
    }
    return(1 + length);
}

/*
 * Decode an IPv6 prefix.
 */
static int
decode_prefix6(proto_tree *tree, int hf_addr, tvbuff_t *tvb, gint offset,
               guint16 tlen, const char *tag)
{
    proto_item        *ti;
    proto_tree        *prefix_tree;
    struct e_in6_addr addr;     /* IPv6 address                       */
    int               plen;     /* prefix length                      */
    int               length;   /* number of octets needed for prefix */

    /* snarf length and prefix */
    plen = tvb_get_guint8(tvb, offset);
    length = ipv6_addr_and_mask(tvb, offset + 1, &addr, plen);
    if (length < 0) {
        proto_tree_add_text(tree, tvb, offset, 1, "%s length %u invalid",
            tag, plen);
        return -1;
    }

    /* put prefix into protocol tree */
    ti = proto_tree_add_text(tree, tvb, offset,
            tlen != 0 ? tlen : 1 + length, "%s/%u",
            ip6_to_str(&addr), plen);
    prefix_tree = proto_item_add_subtree(ti, ett_bgp_prefix);
    proto_tree_add_text(prefix_tree, tvb, offset, 1, "%s prefix length: %u",
        tag, plen);
    if (hf_addr != -1) {
        proto_tree_add_ipv6(prefix_tree, hf_addr, tvb, offset + 1, length,
            addr.bytes);
    } else {
        proto_tree_add_text(prefix_tree, tvb, offset + 1, length,
            "%s prefix: %s", tag, ip6_to_str(&addr));
    }
    return(1 + length);
}

static char*
decode_bgp_rd(tvbuff_t *tvb, gint offset)
{
    guint16 rd_type;
    emem_strbuf_t *strbuf;

    rd_type = tvb_get_ntohs(tvb,offset);
    strbuf = ep_strbuf_new_label(NULL);

    switch (rd_type) {
        case FORMAT_AS2_LOC:
            ep_strbuf_printf(strbuf, "%u:%u", tvb_get_ntohs(tvb, offset + 2),
                             tvb_get_ntohl(tvb, offset + 4));
            break;
        case FORMAT_IP_LOC:
            ep_strbuf_printf(strbuf, "%s:%u", tvb_ip_to_str(tvb, offset + 2),
                             tvb_get_ntohs(tvb, offset + 6));
            break ;
        case FORMAT_AS4_LOC:
            ep_strbuf_printf(strbuf, "%u:%u", tvb_get_ntohl(tvb, offset + 2),
                             tvb_get_ntohs(tvb, offset + 6));
            break ;
        default:
            ep_strbuf_printf(strbuf, "Unknown (0x%04x) RD type",rd_type);
            break;
    } /* switch (rd_type) */

    return strbuf->str;
}

static int
decode_mcast_vpn_nlri_addresses(proto_tree *tree, tvbuff_t *tvb,
                                gint offset)
{
    guint8 addr_len;

    /* Multicast Source Address */
    proto_tree_add_item(tree, hf_bgp_mcast_vpn_nlri_source_length, tvb, offset,
                        1, ENC_BIG_ENDIAN);
    addr_len = tvb_get_guint8(tvb, offset);
    if (addr_len != 32 && addr_len != 128)
        return -1;
    offset++;
    if (addr_len == 32) {
        proto_tree_add_item(tree, hf_bgp_mcast_vpn_nlri_source_addr_ipv4, tvb,
                            offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    } else {
        proto_tree_add_item(tree, hf_bgp_mcast_vpn_nlri_source_addr_ipv6, tvb,
                            offset, 16, ENC_NA);
        offset += 16;
    }

    /* Multicast Group Address */
    proto_tree_add_item(tree, hf_bgp_mcast_vpn_nlri_group_length, tvb, offset,
                        1, ENC_BIG_ENDIAN);
    addr_len = tvb_get_guint8(tvb, offset);
    if (addr_len != 32 && addr_len != 128)
        return -1;
    offset++;
    if (addr_len == 32) {
        proto_tree_add_item(tree, hf_bgp_mcast_vpn_nlri_group_addr_ipv4, tvb,
                            offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    } else {
        proto_tree_add_item(tree, hf_bgp_mcast_vpn_nlri_group_addr_ipv6, tvb,
                            offset, 16, ENC_NA);
        offset += 16;
    }

    return offset;
}

/*
 * Decode an MCAST-VPN nlri as defined in draft-ietf-l3vpn-2547bis-mcast-bgp-08.txt .
 */
static int
decode_mcast_vpn_nlri(proto_tree *tree, tvbuff_t *tvb, gint offset, guint16 afi)
{
    guint8 route_type, length, ip_length;
    proto_item *item;
    proto_tree *nlri_tree;
    guint32 route_key_length;
    int ret;

    ip_length = (afi == AFNUM_INET) ? 4 : 16;

    route_type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_bgp_mcast_vpn_nlri_route_type, tvb,
                               offset, 1, ENC_BIG_ENDIAN);
    offset++;

    length = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_bgp_mcast_vpn_nlri_length, tvb, offset,
                               1, ENC_BIG_ENDIAN);
    offset++;

    if (length < tvb_reported_length_remaining(tvb, offset))
        return -1;

    item = proto_tree_add_item(tree, hf_bgp_mcast_vpn_nlri_t, tvb, offset,
                               length, ENC_NA);
    proto_item_set_text(item, "%s (%u byte%s)",
                        val_to_str_const(route_type, mcast_vpn_route_type, "Unknown"),
                        length, plurality(length, "", "s"));

    nlri_tree = proto_item_add_subtree(item, ett_bgp_mcast_vpn_nlri);

    switch (route_type) {
        case MCAST_VPN_RTYPE_INTRA_AS_IPMSI_AD:
            item = proto_tree_add_item(nlri_tree, hf_bgp_mcast_vpn_nlri_rd, tvb,
                                       offset, BGP_ROUTE_DISTINGUISHER_SIZE,
                                       ENC_NA);
            proto_item_set_text(item, "Route Distinguisher: %s",
                                decode_bgp_rd(tvb, offset));
            offset += BGP_ROUTE_DISTINGUISHER_SIZE;

            if (afi == AFNUM_INET)
                proto_tree_add_item(nlri_tree,
                                           hf_bgp_mcast_vpn_nlri_origin_router_ipv4,
                                           tvb, offset, ip_length, ENC_BIG_ENDIAN);
            else
                proto_tree_add_item(nlri_tree,
                                           hf_bgp_mcast_vpn_nlri_origin_router_ipv6,
                                           tvb, offset, ip_length, ENC_NA);
            break;

        case MCAST_VPN_RTYPE_INTER_AS_IPMSI_AD:
            item = proto_tree_add_item(nlri_tree, hf_bgp_mcast_vpn_nlri_rd, tvb,
                                       offset, BGP_ROUTE_DISTINGUISHER_SIZE,
                                       ENC_NA);
            proto_item_set_text(item, "Route Distinguisher: %s",
                                decode_bgp_rd(tvb, offset));
            offset += BGP_ROUTE_DISTINGUISHER_SIZE;

            proto_tree_add_item(nlri_tree, hf_bgp_mcast_vpn_nlri_source_as, tvb,
                                offset, 4, ENC_BIG_ENDIAN);
            break;

        case MCAST_VPN_RTYPE_SPMSI_AD:
            item = proto_tree_add_item(nlri_tree, hf_bgp_mcast_vpn_nlri_rd, tvb,
                                       offset, BGP_ROUTE_DISTINGUISHER_SIZE,
                                       ENC_NA);
            proto_item_set_text(item, "Route Distinguisher: %s",
                                decode_bgp_rd(tvb, offset));
            offset += BGP_ROUTE_DISTINGUISHER_SIZE;

            ret = decode_mcast_vpn_nlri_addresses(nlri_tree, tvb, offset);
            if (ret < 0)
                return -1;
            break;

        case MCAST_VPN_RTYPE_LEAF_AD:
            route_key_length = length - ip_length;
            item = proto_tree_add_item(nlri_tree,
                                       hf_bgp_mcast_vpn_nlri_route_key, tvb,
                                       offset, route_key_length, ENC_NA);
            proto_item_set_text(item, "Route Key (%u byte%s)", route_key_length,
                                plurality(route_key_length, "", "s"));
            offset += route_key_length;

            if (afi == AFNUM_INET)
                proto_tree_add_item(nlri_tree,
                                           hf_bgp_mcast_vpn_nlri_origin_router_ipv4,
                                           tvb, offset, ip_length, ENC_BIG_ENDIAN);
            else
                proto_tree_add_item(nlri_tree,
                                           hf_bgp_mcast_vpn_nlri_origin_router_ipv6,
                                           tvb, offset, ip_length, ENC_NA);
            break;

        case MCAST_VPN_RTYPE_SOURCE_ACTIVE_AD:
            item = proto_tree_add_item(nlri_tree, hf_bgp_mcast_vpn_nlri_rd, tvb,
                                       offset, BGP_ROUTE_DISTINGUISHER_SIZE,
                                       ENC_NA);
            proto_item_set_text(item, "Route Distinguisher: %s",
                                decode_bgp_rd(tvb, offset));
            offset += BGP_ROUTE_DISTINGUISHER_SIZE;

            ret = decode_mcast_vpn_nlri_addresses(nlri_tree, tvb, offset);
            if (ret < 0)
                return -1;
            break;

        case MCAST_VPN_RTYPE_SHARED_TREE_JOIN:
        case MCAST_VPN_RTYPE_SOURCE_TREE_JOIN:
            item = proto_tree_add_item(nlri_tree, hf_bgp_mcast_vpn_nlri_rd, tvb,
                                       offset, BGP_ROUTE_DISTINGUISHER_SIZE,
                                       ENC_NA);
            proto_item_set_text(item, "Route Distinguisher: %s",
                                decode_bgp_rd(tvb, offset));
            offset += BGP_ROUTE_DISTINGUISHER_SIZE;

            proto_tree_add_item(nlri_tree, hf_bgp_mcast_vpn_nlri_source_as, tvb,
                                offset, 4, ENC_NA);
            offset += 4;

            ret = decode_mcast_vpn_nlri_addresses(nlri_tree, tvb, offset);
            if (ret < 0)
                return -1;
            break;
    }

    /* route type field (1 byte) + length field (1 byte) + length */
    return 2 + length;
}

/*
 * Decodes an MDT-SAFI message.
 */
static guint
decode_mdt_safi(proto_tree *tree, tvbuff_t *tvb, gint offset)
{
    const guint ip_length = 4;
    const guint mdt_safi_nlri_length_bits = 128;
    guint length; /* length in bits */
    gint  orig_offset = offset;
    proto_item *item;
        
    length = tvb_get_guint8(tvb, offset);
    if (length != mdt_safi_nlri_length_bits)
        return -1;
    offset++;

    item = proto_tree_add_item(tree, hf_bgp_mdt_safi_rd, tvb,
                               offset, BGP_ROUTE_DISTINGUISHER_SIZE, ENC_NA);
    proto_item_set_text(item, "Route Distinguisher: %s",
                        decode_bgp_rd(tvb, offset));
    offset += BGP_ROUTE_DISTINGUISHER_SIZE;

    proto_tree_add_item(tree, hf_bgp_mdt_safi_ipv4_addr, tvb,
                        offset, ip_length, ENC_BIG_ENDIAN);
    offset += ip_length;

    proto_tree_add_item(tree, hf_bgp_mdt_safi_group_addr, tvb,
                        offset, ip_length, ENC_BIG_ENDIAN);
    offset += ip_length;

    return offset - orig_offset;
}

/*
 * Decode an MPLS label stack
 * XXX - We should change *buf to **buf, use ep_alloc() and drop the buflen
 * argument.
 */
static guint
decode_MPLS_stack(tvbuff_t *tvb, gint offset, emem_strbuf_t *stack_strbuf)
{
    guint32     label_entry;    /* an MPLS label enrty (label + COS field + stack bit   */
    gint        indx;          /* index for the label stack */

    indx = offset ;
    label_entry = 0x000000 ;

    ep_strbuf_truncate(stack_strbuf, 0);

    while ((label_entry & 0x000001) == 0) {

        label_entry = tvb_get_ntoh24(tvb, indx) ;

        /* withdrawn routes may contain 0 or 0x800000 in the first label */
        if((indx-offset)==0&&(label_entry==0||label_entry==0x800000)) {
            ep_strbuf_append(stack_strbuf, "0 (withdrawn)");
            return (1);
        }

        ep_strbuf_append_printf(stack_strbuf, "%u%s", label_entry >> 4,
                ((label_entry & 0x000001) == 0) ? "," : " (bottom)");

        indx += 3 ;

        if ((label_entry & 0x000001) == 0) {
            /* real MPLS multi-label stack in BGP? - maybe later; for now, it must be a bogus packet */
            ep_strbuf_append(stack_strbuf, " (BOGUS: Bottom of Stack NOT set!)");
            break;
        }
    }

    return((indx - offset) / 3);
}

/*
 * Decode a multiprotocol address
 */

static int
mp_addr_to_str (guint16 afi, guint8 safi, tvbuff_t *tvb, gint offset, emem_strbuf_t *strbuf, gint nhlen)
{
    int                 length;                         /* length of the address in byte */
    guint32             ip4addr,ip4addr2;               /* IPv4 address                 */
    guint16             rd_type;                        /* Route Distinguisher type     */
    struct e_in6_addr   ip6addr;                        /* IPv6 address                 */

    switch (afi) {
        case AFNUM_INET:
            switch (safi) {
                case SAFNUM_UNICAST:
                case SAFNUM_MULCAST:
                case SAFNUM_UNIMULC:
                case SAFNUM_MPLS_LABEL:
                case SAFNUM_ENCAPSULATION:
                case SAFNUM_ROUTE_TARGET:
                    /* RTF NHop can be IPv4 or IPv6. They are differentiated by length of the field*/
                    length = nhlen;
                    if (nhlen == 4) {
                        ep_strbuf_append(strbuf, tvb_ip_to_str(tvb, offset));
                    } else if (nhlen == 16) {
                        ep_strbuf_append(strbuf, tvb_ip6_to_str(tvb, offset));
                    } else {
                        ep_strbuf_append(strbuf, "Unknown address");
                    }
                    break;
                case SAFNUM_TUNNEL:
                    length = 4 ;
                    ip4addr = tvb_get_ipv4(tvb, offset);
                    ep_strbuf_append(strbuf, ip_to_str((guint8 *)&ip4addr));
                    break;
                case SAFNUM_LAB_VPNUNICAST:
                case SAFNUM_LAB_VPNMULCAST:
                case SAFNUM_LAB_VPNUNIMULC:
                    rd_type=tvb_get_ntohs(tvb,offset) ;
                    switch (rd_type) {
                        case FORMAT_AS2_LOC:
                            length = 8 + sizeof(ip4addr);
                            ip4addr = tvb_get_ipv4(tvb, offset + 8);   /* Next Hop */
                            ep_strbuf_printf(strbuf, "Empty Label Stack RD=%u:%u IPv4=%s",
                                             tvb_get_ntohs(tvb, offset + 2),
                                             tvb_get_ntohl(tvb, offset + 4),
                                             ip_to_str((guint8 *)&ip4addr));
                            break;
                        case FORMAT_IP_LOC:
                            length = 8 + sizeof(ip4addr);
                            ip4addr = tvb_get_ipv4(tvb, offset + 2);   /* IP part of the RD            */
                            ip4addr2 = tvb_get_ipv4(tvb, offset + 8);  /* Next Hop   */
                            ep_strbuf_printf(strbuf, "Empty Label Stack RD=%s:%u IPv4=%s",
                                             ip_to_str((guint8 *)&ip4addr),
                                             tvb_get_ntohs(tvb, offset + 6),
                                             ip_to_str((guint8 *)&ip4addr2));
                            break ;
                        case FORMAT_AS4_LOC:
                            length = 8 + sizeof(ip4addr);
                            ip4addr = tvb_get_ipv4(tvb, offset + 8);  /* Next Hop   */
                            ep_strbuf_printf(strbuf, "Empty Label Stack RD=%u.%u:%u IPv4=%s",
                                             tvb_get_ntohs(tvb, offset + 2),
                                             tvb_get_ntohs(tvb, offset + 4),
                                             tvb_get_ntohs(tvb, offset + 6),
                                             ip_to_str((guint8 *)&ip4addr));
                            break ;
                        default:
                            length = 0 ;
                            ep_strbuf_printf(strbuf, "Unknown (0x%04x) labeled VPN IPv4 address format",rd_type);
                            break;
                    } /* switch (rd_type) */
                    break;
                default:
                    length = 0 ;
                    ep_strbuf_printf(strbuf, "Unknown SAFI (%u) for AFI %u", safi, afi);
                    break;
            } /* switch (safi) */
            break;
        case AFNUM_INET6:
            switch (safi) {
                case SAFNUM_UNICAST:
                case SAFNUM_MULCAST:
                case SAFNUM_UNIMULC:
                case SAFNUM_MPLS_LABEL:
                case SAFNUM_ENCAPSULATION:
                case SAFNUM_TUNNEL:
                    length = 16 ;
                    tvb_get_ipv6(tvb, offset, &ip6addr);
                    ep_strbuf_printf(strbuf, "%s", ip6_to_str(&ip6addr));
                    break;
                case SAFNUM_LAB_VPNUNICAST:
                case SAFNUM_LAB_VPNMULCAST:
                case SAFNUM_LAB_VPNUNIMULC:
                    rd_type=tvb_get_ntohs(tvb,offset) ;
                    switch (rd_type) {
                        case FORMAT_AS2_LOC:
                            length = 8 + 16;
                            tvb_get_ipv6(tvb, offset + 8, &ip6addr); /* Next Hop */
                            ep_strbuf_printf(strbuf, "Empty Label Stack RD=%u:%u IPv6=%s",
                                             tvb_get_ntohs(tvb, offset + 2),
                                             tvb_get_ntohl(tvb, offset + 4),
                                             ip6_to_str(&ip6addr));
                            break;
                        case FORMAT_IP_LOC:
                            length = 8 + 16;
                            ip4addr = tvb_get_ipv4(tvb, offset + 2);   /* IP part of the RD            */
                            tvb_get_ipv6(tvb, offset + 8, &ip6addr); /* Next Hop */
                            ep_strbuf_printf(strbuf, "Empty Label Stack RD=%s:%u IPv6=%s",
                                             ip_to_str((guint8 *)&ip4addr),
                                             tvb_get_ntohs(tvb, offset + 6),
                                             ip6_to_str(&ip6addr));
                            break ;
                        case FORMAT_AS4_LOC:
                            length = 8 + 16;
                            tvb_get_ipv6(tvb, offset + 8, &ip6addr); /* Next Hop */
                            ep_strbuf_printf(strbuf, "Empty Label Stack RD=%u:%u IPv6=%s",
                                             tvb_get_ntohl(tvb, offset + 2),
                                             tvb_get_ntohs(tvb, offset + 6),
                                             ip6_to_str(&ip6addr));
                            break ;
                        default:
                            length = 0 ;
                            ep_strbuf_printf(strbuf, "Unknown (0x%04x) labeled VPN IPv6 address format",rd_type);
                            break;
                    }  /* switch (rd_type) */
                    break;
                default:
                    length = 0 ;
                    ep_strbuf_printf(strbuf, "Unknown SAFI (%u) for AFI %u", safi, afi);
                    break;
            } /* switch (safi) */
            break;
       case AFNUM_L2VPN:
        case AFNUM_L2VPN_OLD:
            switch (safi) {
                case SAFNUM_LAB_VPNUNICAST: /* only labeles prefixes do make sense */
                case SAFNUM_LAB_VPNMULCAST:
                case SAFNUM_LAB_VPNUNIMULC:
                case SAFNUM_VPLS:
                    length = 4; /* the next-hop is simply an ipv4 addr */
                    ip4addr = tvb_get_ipv4(tvb, offset + 0);
                    ep_strbuf_printf(strbuf, "IPv4=%s",
                                     ip_to_str((guint8 *)&ip4addr));
                    break;
                default:
                    length = 0 ;
                    ep_strbuf_printf(strbuf, "Unknown SAFI (%u) for AFI %u", safi, afi);
                    break;
            } /* switch (safi) */
            break;
        default:
            length = 0 ;
            ep_strbuf_printf(strbuf, "Unknown AFI (%u) value", afi);
            break;
    } /* switch (afi) */
    return(length) ;
}

/*
 * Decode a multiprotocol prefix
 */
static int
decode_prefix_MP(proto_tree *tree, int hf_addr4, int hf_addr6,
                 guint16 afi, guint8 safi, tvbuff_t *tvb, gint offset,
                 const char *tag)
{
    int                 start_offset = offset;
    proto_item          *ti;
    proto_tree          *prefix_tree;
    int                 total_length;       /* length of the entire item */
    int                 length;             /* length of the prefix address, in bytes */
    guint               plen;               /* length of the prefix address, in bits */
    guint               labnum;             /* number of labels             */
    guint16             tnl_id;             /* Tunnel Identifier */
    int                 ce_id,labblk_off,labblk_size;
    union {
       guint8 addr_bytes[4];
       guint32 addr;
    } ip4addr, ip4addr2;                    /* IPv4 address                 */
    struct e_in6_addr   ip6addr;            /* IPv6 address                 */
    guint16             rd_type;            /* Route Distinguisher type     */
    emem_strbuf_t      *stack_strbuf;       /* label stack                  */
    emem_strbuf_t      *comm_strbuf;

    switch (afi) {

    case AFNUM_INET:
        switch (safi) {

            case SAFNUM_UNICAST:
            case SAFNUM_MULCAST:
            case SAFNUM_UNIMULC:
                total_length = decode_prefix4(tree, hf_addr4, tvb, offset, 0, tag);
                if (total_length < 0)
                    return -1;
                break;

            case SAFNUM_MPLS_LABEL:
                plen =  tvb_get_guint8(tvb, offset);
                stack_strbuf = ep_strbuf_new_label(NULL);
                labnum = decode_MPLS_stack(tvb, offset + 1, stack_strbuf);

                offset += (1 + labnum * 3);
                if (plen <= (labnum * 3*8)) {
                    proto_tree_add_text(tree, tvb, start_offset, 1,
                                        "%s Labeled IPv4 prefix length %u invalid",
                                        tag, plen);
                    return -1;
                }
                plen -= (labnum * 3*8);
                length = ipv4_addr_and_mask(tvb, offset, ip4addr.addr_bytes, plen);
                if (length < 0) {
                    proto_tree_add_text(tree, tvb, start_offset, 1,
                                        "%s Labeled IPv4 prefix length %u invalid",
                                        tag, plen + (labnum * 3*8));
                    return -1;
                }

                ti = proto_tree_add_text(tree, tvb, start_offset,
                                         (offset + length) - start_offset,
                                         "Label Stack=%s IPv4=%s/%u",
                                         stack_strbuf->str, ip_to_str(ip4addr.addr_bytes), plen);
                prefix_tree = proto_item_add_subtree(ti, ett_bgp_prefix);
                proto_tree_add_text(prefix_tree, tvb, start_offset, 1, "%s Prefix length: %u",
                                    tag, plen + labnum * 3 * 8);
                proto_tree_add_text(prefix_tree, tvb, start_offset + 1, 3 * labnum, "%s Label Stack: %s",
                                    tag, stack_strbuf->str);
                if (hf_addr4 != -1) {
                    proto_tree_add_ipv4(prefix_tree, hf_addr4, tvb, offset,
                                        length, ip4addr.addr);
                } else {
                    proto_tree_add_text(prefix_tree, tvb, offset, length,
                                        "%s IPv4 prefix: %s",
                                        tag, ip_to_str(ip4addr.addr_bytes));
                }
                total_length = (1 + labnum*3) + length;
                break;
            case SAFNUM_MCAST_VPN:
                total_length = decode_mcast_vpn_nlri(tree, tvb, offset, afi);
                if (total_length < 0)
                    return -1;
                break;
            case SAFNUM_MDT:
                total_length = decode_mdt_safi(tree, tvb, offset);
                if (total_length < 0)
                    return -1;
                break;
            case SAFNUM_ROUTE_TARGET:
                plen = tvb_get_guint8(tvb, offset);

                if (plen == 0) {
                    proto_tree_add_text(tree, tvb, offset, 1,
                                        "%s Wildcard route target", tag);
                    total_length = 1;
                    break;
                }

                if ((plen < 32) || (plen > 96)) {
                    proto_tree_add_text(tree, tvb, offset, 1,
                                        "%s Route target length %u invalid",
                                        tag, plen);
                    return -1;
                }

                length = (plen + 7)/8;
                comm_strbuf = ep_strbuf_new_label(NULL);

                switch (tvb_get_ntohs(tvb, offset + 1 + 4)) {
                case BGP_EXT_COM_RT_0:
                    ep_strbuf_printf(comm_strbuf, "%u:%u",
                                     tvb_get_ntohs(tvb, offset + 1 + 6),
                                     tvb_get_ntohl(tvb, offset + 1 + 8));
                    break;
                case BGP_EXT_COM_RT_1:
                    ep_strbuf_printf(comm_strbuf, "%s:%u",
                                     tvb_ip_to_str(tvb, offset + 1 + 6),
                                     tvb_get_ntohs(tvb, offset + 1 + 10));
                    break;
                case BGP_EXT_COM_RT_2:
                    ep_strbuf_printf(comm_strbuf, "%u:%u", 
                                     tvb_get_ntohl(tvb, 6), 
                                     tvb_get_ntohs(tvb, offset + 1 + 10));
                    break;
                default:
                    ep_strbuf_printf(comm_strbuf, "Invalid RT type");
                    break;
                }
                ti = proto_tree_add_text(tree, tvb, offset + 1, length, "%s %u:%s/%u", 
                                    tag, tvb_get_ntohl(tvb, offset + 1 + 0),
                                    comm_strbuf->str,
                                    plen);
                prefix_tree = proto_item_add_subtree(ti, ett_bgp_prefix);
                proto_tree_add_text(prefix_tree, tvb, offset, 1, "%s Prefix length: %u",
                                                    tag, plen);
                proto_tree_add_text(prefix_tree, tvb, offset + 1, 4, "%s Originating AS: %u",
                                                    tag, tvb_get_ntohl(tvb, offset + 1 + 0));
                proto_tree_add_text(prefix_tree, tvb, offset + 1 + 4, length - 4, "%s Community prefix: %s",
                                                    tag, comm_strbuf->str);
                total_length = 1 + length;
                break;
            case SAFNUM_ENCAPSULATION:
                plen =  tvb_get_guint8(tvb, offset);
                if (plen != 32){
                    proto_tree_add_text(tree, tvb, offset, 1,
                                        "%s IPv4 address length %u invalid",
                                        tag, plen);
                    return -1;
                }
                offset += 1;
                ip4addr.addr = tvb_get_ipv4(tvb, offset);

                proto_tree_add_text(tree, tvb, offset,
                                         offset + 4,
                                         "Endpoint Address: %s",
                                         ip_to_str((guint8 *)&ip4addr));

                total_length = 5; /* length(1 octet) + address(4 octets) */
                break;
            case SAFNUM_TUNNEL:
                plen =  tvb_get_guint8(tvb, offset);
                if (plen <= 16){
                    proto_tree_add_text(tree, tvb, start_offset, 1,
                                        "%s Tunnel IPv4 prefix length %u invalid",
                                        tag, plen);
                    return -1;
                }
                tnl_id = tvb_get_ntohs(tvb, offset + 1);
                offset += 3; /* Length + Tunnel Id */
                plen -= 16; /* 2-octet Identifier */
                length = ipv4_addr_and_mask(tvb, offset, ip4addr.addr_bytes, plen);
                if (length < 0) {
                    proto_tree_add_text(tree, tvb, start_offset, 1,
                                        "%s Tunnel IPv4 prefix length %u invalid",
                                        tag, plen + 16);
                    return -1;
                }
                ti = proto_tree_add_text(tree, tvb, start_offset,
                                         (offset + length) - start_offset,
                                         "Tunnel Identifier=0x%x IPv4=%s/%u",
                                         tnl_id, ip_to_str(ip4addr.addr_bytes), plen);
                prefix_tree = proto_item_add_subtree(ti, ett_bgp_prefix);

                proto_tree_add_text(prefix_tree, tvb, start_offset, 1, "%s Prefix length: %u",
                                    tag, plen + 16);
                proto_tree_add_item(prefix_tree, hf_bgp_mp_nlri_tnl_id, tvb,
                                    start_offset + 1, 2, ENC_BIG_ENDIAN);
                if (hf_addr4 != -1) {
                    proto_tree_add_ipv4(prefix_tree, hf_addr4, tvb, offset,
                                        length, ip4addr.addr);
                } else {
                    proto_tree_add_text(prefix_tree, tvb, offset, length,
                                        "%s IPv4 prefix: %s",
                                        tag, ip_to_str(ip4addr.addr_bytes));
                }
                total_length = 1 + 2 + length; /* length field + Tunnel Id + IPv4 len */
                break;

            case SAFNUM_LAB_VPNUNICAST:
            case SAFNUM_LAB_VPNMULCAST:
            case SAFNUM_LAB_VPNUNIMULC:
                plen =  tvb_get_guint8(tvb, offset);
                stack_strbuf = ep_strbuf_new_label(NULL);
                labnum = decode_MPLS_stack(tvb, offset + 1, stack_strbuf);

                offset += (1 + labnum * 3);
                if (plen <= (labnum * 3*8)) {
                    proto_tree_add_text(tree, tvb, start_offset, 1,
                                        "%s Labeled VPN IPv4 prefix length %u invalid",
                                        tag, plen);
                    return -1;
                }
                plen -= (labnum * 3*8);

                rd_type = tvb_get_ntohs(tvb, offset);
                if (plen < 8*8) {
                    proto_tree_add_text(tree, tvb, start_offset, 1,
                                        "%s Labeled VPN IPv4 prefix length %u invalid",
                                        tag, plen + (labnum * 3*8));
                    return -1;
                }
                plen -= 8*8;

                switch (rd_type) {

                    case FORMAT_AS2_LOC: /* Code borrowed from the decode_prefix4 function */
                        length = ipv4_addr_and_mask(tvb, offset + 8, ip4addr.addr_bytes, plen);
                        if (length < 0) {
                            proto_tree_add_text(tree, tvb, start_offset, 1,
                                                "%s Labeled VPN IPv4 prefix length %u invalid",
                                                tag, plen + (labnum * 3*8) + 8*8);
                            return -1;
                        }

                        ti = proto_tree_add_text(tree, tvb, start_offset,
                                                 (offset + 8 + length) - start_offset,
                                                 "Label Stack=%s RD=%u:%u, IPv4=%s/%u",
                                                 stack_strbuf->str,
                                                 tvb_get_ntohs(tvb, offset + 2),
                                                 tvb_get_ntohl(tvb, offset + 4),
                                                 ip_to_str(ip4addr.addr_bytes), plen);
                        prefix_tree = proto_item_add_subtree(ti, ett_bgp_prefix);
                        proto_tree_add_text(prefix_tree, tvb, start_offset, 1, "%s Prefix length: %u",
                                            tag, plen + labnum * 3 * 8 + 8 * 8);
                        proto_tree_add_text(prefix_tree, tvb, start_offset + 1, 3 * labnum,
                                            "%s Label Stack: %s", tag, stack_strbuf->str);
                        proto_tree_add_text(prefix_tree, tvb, start_offset + 1 + 3 * labnum, 8,
                                            "%s Route Distinguisher: %u:%u", tag, tvb_get_ntohs(tvb, offset + 2),
                                            tvb_get_ntohl(tvb, offset + 4));
                        if (hf_addr4 != -1) {
                            proto_tree_add_ipv4(prefix_tree, hf_addr4, tvb,
                                                offset + 8, length, ip4addr.addr);
                        } else {
                            proto_tree_add_text(prefix_tree, tvb, offset + 8,
                                                length, "%s IPv4 prefix: %s", tag,
                                                ip_to_str(ip4addr.addr_bytes));
                        }
                        total_length = (1 + labnum * 3 + 8) + length;
                        break;

                    case FORMAT_IP_LOC: /* Code borrowed from the decode_prefix4 function */
                        tvb_memcpy(tvb, ip4addr.addr_bytes, offset + 2, 4);

                        length = ipv4_addr_and_mask(tvb, offset + 8, ip4addr2.addr_bytes, plen);
                        if (length < 0) {
                            proto_tree_add_text(tree, tvb, start_offset, 1,
                                                "%s Labeled VPN IPv4 prefix length %u invalid",
                                                tag, plen + (labnum * 3*8) + 8*8);
                            return -1;
                        }

                        ti = proto_tree_add_text(tree, tvb, start_offset,
                                                 (offset + 8 + length) - start_offset,
                                                 "Label Stack=%s RD=%s:%u, IPv4=%s/%u",
                                                 stack_strbuf->str,
                                                 ip_to_str(ip4addr.addr_bytes),
                                                 tvb_get_ntohs(tvb, offset + 6),
                                                 ip_to_str(ip4addr2.addr_bytes),
                                                 plen);
                        prefix_tree = proto_item_add_subtree(ti, ett_bgp_prefix);
                        proto_tree_add_text(prefix_tree, tvb, start_offset, 1, "%s Prefix length: %u",
                                            tag, plen + labnum * 3 * 8 + 8 * 8);
                        proto_tree_add_text(prefix_tree, tvb, start_offset + 1, 3 * labnum,
                                            "%s Label Stack: %s", tag, stack_strbuf->str);
                        proto_tree_add_text(prefix_tree, tvb, start_offset + 1 + 3 * labnum, 8,
                                            "%s Route Distinguisher: %s:%u", tag, ip_to_str(ip4addr.addr_bytes),
                                            tvb_get_ntohs(tvb, offset + 6));
                        if (hf_addr4 != -1) {
                            proto_tree_add_ipv4(prefix_tree, hf_addr4, tvb,
                                                offset + 8, length, ip4addr2.addr);
                        } else {
                            proto_tree_add_text(prefix_tree, tvb, offset + 8,
                                                length, "%s IPv4 prefix: %s", tag,
                                                ip_to_str(ip4addr2.addr_bytes));
                        }
                        total_length = (1 + labnum * 3 + 8) + length;
                        break;

                    case FORMAT_AS4_LOC: /* Code borrowed from the decode_prefix4 function */
                        length = ipv4_addr_and_mask(tvb, offset + 8, ip4addr.addr_bytes, plen);
                        if (length < 0) {
                            proto_tree_add_text(tree, tvb, start_offset, 1,
                                                "%s Labeled VPN IPv4 prefix length %u invalid",
                                                tag, plen + (labnum * 3*8) + 8*8);
                            return -1;
                        }

                        ti = proto_tree_add_text(tree, tvb, start_offset,
                                                 (offset + 8 + length) - start_offset,
                                                 "Label Stack=%s RD=%u.%u:%u, IPv4=%s/%u",
                                                 stack_strbuf->str,
                                                 tvb_get_ntohs(tvb, offset + 2),
                                                 tvb_get_ntohs(tvb, offset + 4),
                                                 tvb_get_ntohs(tvb, offset + 6),
                                                 ip_to_str(ip4addr.addr_bytes), plen);
                        prefix_tree = proto_item_add_subtree(ti, ett_bgp_prefix);
                        proto_tree_add_text(prefix_tree, tvb, start_offset, 1, "%s Prefix length: %u",
                                            tag, plen + labnum * 3 * 8 + 8 * 8);
                        proto_tree_add_text(prefix_tree, tvb, start_offset + 1, 3 * labnum,
                                            "%s Label Stack: %s", tag, stack_strbuf->str);
                        proto_tree_add_text(prefix_tree, tvb, start_offset + 1 + 3 * labnum, 8,
                                            "%s Route Distinguisher: %u.%u:%u", tag, tvb_get_ntohs(tvb, offset + 2),
                                            tvb_get_ntohs(tvb, offset + 4), tvb_get_ntohs(tvb, offset + 6));
                        if (hf_addr4 != -1) {
                            proto_tree_add_ipv4(prefix_tree, hf_addr4, tvb,
                                                offset + 8, length, ip4addr.addr);
                        } else {
                            proto_tree_add_text(prefix_tree, tvb, offset + 8,
                                                length, "%s IPv4 prefix: %s", tag,
                                                ip_to_str(ip4addr.addr_bytes));
                        }
                        total_length = (1 + labnum * 3 + 8) + length;
                        break;

                    default:
                        proto_tree_add_text(tree, tvb, start_offset,
                                            (offset - start_offset) + 2,
                                            "Unknown labeled VPN IPv4 address format %u", rd_type);
                        return -1;
                } /* switch (rd_type) */
                break;

            default:
                proto_tree_add_text(tree, tvb, start_offset, 0,
                                    "Unknown SAFI (%u) for AFI %u", safi, afi);
                return -1;
        } /* switch (safi) */
        break;

    case AFNUM_INET6:
        switch (safi) {

            case SAFNUM_UNICAST:
            case SAFNUM_MULCAST:
            case SAFNUM_UNIMULC:
                total_length = decode_prefix6(tree, hf_addr6, tvb, offset, 0, tag);
                if (total_length < 0)
                    return -1;
                break;

            case SAFNUM_MPLS_LABEL:
                plen =  tvb_get_guint8(tvb, offset);
                stack_strbuf = ep_strbuf_new_label(NULL);
                labnum = decode_MPLS_stack(tvb, offset + 1, stack_strbuf);

                offset += (1 + labnum * 3);
                if (plen <= (labnum * 3*8)) {
                    proto_tree_add_text(tree, tvb, start_offset, 1,
                                        "%s Labeled IPv6 prefix length %u invalid", tag, plen);
                    return -1;
                }
                plen -= (labnum * 3*8);

                length = ipv6_addr_and_mask(tvb, offset, &ip6addr, plen);
                if (length < 0) {
                    proto_tree_add_text(tree, tvb, start_offset, 1,
                                        "%s Labeled IPv6 prefix length %u invalid",
                                        tag, plen  + (labnum * 3*8));
                    return -1;
                }

                proto_tree_add_text(tree, tvb, start_offset,
                                    (offset + length) - start_offset,
                                    "Label Stack=%s, IPv6=%s/%u",
                                    stack_strbuf->str,
                                    ip6_to_str(&ip6addr), plen);
                total_length = (1 + labnum * 3) + length;
                break;
            case SAFNUM_ENCAPSULATION:
                plen =  tvb_get_guint8(tvb, offset);
                if (plen != 128){
                    proto_tree_add_text(tree, tvb, offset, 1,
                                        "%s IPv6 address length %u invalid",
                                        tag, plen);
                    return -1;
                }
                offset += 1;
                tvb_get_ipv6(tvb, offset, &ip6addr);

                proto_tree_add_text(tree, tvb, offset,
                                         offset + 16,
                                         "Endpoint Address: %s",
                                         ip6_to_str(&ip6addr));

                total_length = 17; /* length(1 octet) + address(16 octets) */
                break;
            case SAFNUM_TUNNEL:
                plen =  tvb_get_guint8(tvb, offset);
                if (plen <= 16){
                    proto_tree_add_text(tree, tvb, start_offset, 1,
                                        "%s Tunnel IPv6 prefix length %u invalid",
                                        tag, plen);
                    return -1;
                }
                tnl_id = tvb_get_ntohs(tvb, offset + 1);
                offset += 3; /* Length + Tunnel Id */
                plen -= 16; /* 2-octet Identifier */
                length = ipv6_addr_and_mask(tvb, offset, &ip6addr, plen);
                if (length < 0) {
                    proto_tree_add_text(tree, tvb, start_offset, 1,
                                        "%s Tunnel IPv6 prefix length %u invalid",
                                        tag, plen + 16);
                    return -1;
                }
                proto_tree_add_text(tree, tvb, start_offset,
                                    (offset + length) - start_offset,
                                    "Tunnel Identifier=0x%x IPv6=%s/%u",
                                    tnl_id, ip6_to_str(&ip6addr), plen);
                total_length = (1 + 2) + length; /* length field + Tunnel Id + IPv4 len */
                break;

            case SAFNUM_LAB_VPNUNICAST:
            case SAFNUM_LAB_VPNMULCAST:
            case SAFNUM_LAB_VPNUNIMULC:
                plen =  tvb_get_guint8(tvb, offset);
                stack_strbuf = ep_strbuf_new_label(NULL);
                labnum = decode_MPLS_stack(tvb, offset + 1, stack_strbuf);

                offset += (1 + labnum * 3);
                if (plen <= (labnum * 3*8)) {
                    proto_tree_add_text(tree, tvb, start_offset, 1,
                                        "%s Labeled VPN IPv6 prefix length %u invalid", tag, plen);
                    return -1;
                }
                plen -= (labnum * 3*8);

                rd_type = tvb_get_ntohs(tvb,offset);
                if (plen < 8*8) {
                    proto_tree_add_text(tree, tvb, start_offset, 1,
                                        "%s Labeled VPN IPv6 prefix length %u invalid",
                                        tag, plen + (labnum * 3*8));
                    return -1;
                }
                plen -= 8*8;

                switch (rd_type) {

                    case FORMAT_AS2_LOC:
                        length = ipv6_addr_and_mask(tvb, offset + 8, &ip6addr, plen);
                        if (length < 0) {
                            proto_tree_add_text(tree, tvb, start_offset, 1,
                                                "%s Labeled VPN IPv6 prefix length %u invalid",
                                                tag, plen + (labnum * 3*8) + 8*8);
                            return -1;
                        }

                        proto_tree_add_text(tree, tvb, start_offset,
                                            (offset + 8 + length) - start_offset,
                                            "Label Stack=%s RD=%u:%u, IPv6=%s/%u",
                                            stack_strbuf->str,
                                            tvb_get_ntohs(tvb, offset + 2),
                                            tvb_get_ntohl(tvb, offset + 4),
                                            ip6_to_str(&ip6addr), plen);
                        total_length = (1 + labnum * 3 + 8) + length;
                        break;

                    case FORMAT_IP_LOC:
                        tvb_memcpy(tvb, ip4addr.addr_bytes, offset + 2, 4);

                        length = ipv6_addr_and_mask(tvb, offset + 8, &ip6addr, plen);
                        if (length < 0) {
                            proto_tree_add_text(tree, tvb, start_offset, 1,
                                                "%s Labeled VPN IPv6 prefix length %u invalid",
                                                tag, plen + (labnum * 3*8) + 8*8);
                            return -1;
                        }

                        proto_tree_add_text(tree, tvb, start_offset,
                                            (offset + 8 + length) - start_offset,
                                            "Label Stack=%s RD=%s:%u, IPv6=%s/%u",
                                            stack_strbuf->str,
                                            ip_to_str(ip4addr.addr_bytes),
                                            tvb_get_ntohs(tvb, offset + 6),
                                            ip6_to_str(&ip6addr), plen);
                        total_length = (1 + labnum * 3 + 8) + length;
                        break;

                    case FORMAT_AS4_LOC:
                        length = ipv6_addr_and_mask(tvb, offset + 8, &ip6addr, plen);
                        if (length < 0) {
                            proto_tree_add_text(tree, tvb, start_offset, 1,
                                                "%s Labeled VPN IPv6 prefix length %u invalid",
                                                tag, plen + (labnum * 3*8) + 8*8);
                            return -1;
                        }

                        proto_tree_add_text(tree, tvb, start_offset,
                                            (offset + 8 + length) - start_offset,
                                            "Label Stack=%s RD=%u.%u:%u, IPv6=%s/%u",
                                            stack_strbuf->str,
                                            tvb_get_ntohs(tvb, offset + 2),
                                            tvb_get_ntohs(tvb, offset + 4),
                                            tvb_get_ntohs(tvb, offset + 6),
                                            ip6_to_str(&ip6addr), plen);
                        total_length = (1 + labnum * 3 + 8) + length;
                        break;
                    default:
                        proto_tree_add_text(tree, tvb, start_offset, 0,
                                            "Unknown labeled VPN IPv6 address format %u", rd_type);
                        return -1;
                } /* switch (rd_type) */
                break;

            default:
                proto_tree_add_text(tree, tvb, start_offset, 0,
                                    "Unknown SAFI (%u) for AFI %u", safi, afi);
                return -1;
        } /* switch (safi) */
        break;

    case AFNUM_L2VPN:
    case AFNUM_L2VPN_OLD:
        switch (safi) {

            case SAFNUM_LAB_VPNUNICAST:
            case SAFNUM_LAB_VPNMULCAST:
            case SAFNUM_LAB_VPNUNIMULC:
            case SAFNUM_VPLS:
                plen =  tvb_get_ntohs(tvb,offset);
                rd_type=tvb_get_ntohs(tvb,offset+2);

                /* RFC6074 Section 7 BGP-AD and VPLS-BGP Interoperability
                   Both BGP-AD and VPLS-BGP [RFC4761] use the same AFI/SAFI.  In order
                   for both BGP-AD and VPLS-BGP to co-exist, the NLRI length must be
                   used as a demultiplexer.

                   The BGP-AD NLRI has an NLRI length of 12 bytes, containing only an
                   8-byte RD and a 4-byte VSI-ID. VPLS-BGP [RFC4761] uses a 17-byte
                   NLRI length.  Therefore, implementations of BGP-AD must ignore NLRI
                   that are greater than 12 bytes.
                */
                if(plen == 12) /* BGP-AD */
                {
                    switch (rd_type) {

                        case FORMAT_AS2_LOC:
                            proto_tree_add_text(tree, tvb, start_offset,
                                                (offset + plen + 2) - start_offset,
                                                "RD: %u:%u, PE_addr: %s",
                                                tvb_get_ntohs(tvb, offset + 4),
                                                tvb_get_ntohl(tvb, offset + 6),
                                                tvb_ip_to_str(tvb, offset + 10));
                            break;

                        case FORMAT_IP_LOC:
                            proto_tree_add_text(tree, tvb, offset,
                                                (offset + plen + 2) - start_offset,
                                                "RD: %s:%u, PE_addr: %s",
                                                tvb_ip_to_str(tvb, offset + 10),
                                                tvb_get_ntohs(tvb, offset + 8),
                                                tvb_ip_to_str(tvb, offset + 10));
                            break;
                        case FORMAT_AS4_LOC:
                            proto_tree_add_text(tree, tvb, start_offset,
                                                (offset + plen + 2) - start_offset,
                                                "RD: %u.%u:%u, PE_addr: %s",
                                                tvb_get_ntohs(tvb, offset + 4),
                                                tvb_get_ntohs(tvb, offset + 6),
                                                tvb_get_ntohs(tvb, offset + 8),
                                                tvb_ip_to_str(tvb, offset + 10));
                            break;
                        default:
                            proto_tree_add_text(tree, tvb, start_offset,
                                                (offset - start_offset) + 2,
                                                "Unknown labeled VPN address format %u", rd_type);
                            return -1;
                    } /* switch (rd_type) */
                }else{ /* VPLS-BGP */
                    ce_id=tvb_get_ntohs(tvb,offset+10);
                    labblk_off=tvb_get_ntohs(tvb,offset+12);
                    labblk_size=tvb_get_ntohs(tvb,offset+14);
                    stack_strbuf = ep_strbuf_new_label(NULL);
                    decode_MPLS_stack(tvb, offset + 16, stack_strbuf);
                    switch (rd_type) {

                        case FORMAT_AS2_LOC:
                            tvb_memcpy(tvb, ip4addr.addr_bytes, offset + 6, 4);
                            proto_tree_add_text(tree, tvb, start_offset,
                                                (offset + plen + 1) - start_offset,
                                                "RD: %u:%s, CE-ID: %u, Label-Block Offset: %u, "
                                                "Label-Block Size: %u Label Base %s",
                                                tvb_get_ntohs(tvb, offset + 4),
                                                ip_to_str(ip4addr.addr_bytes),
                                                ce_id,
                                                labblk_off,
                                                labblk_size,
                                                stack_strbuf->str);
                            break;

                        case FORMAT_IP_LOC:
                            tvb_memcpy(tvb, ip4addr.addr_bytes, offset + 4, 4);
                            proto_tree_add_text(tree, tvb, offset,
                                                (offset + plen + 1) - start_offset,
                                                "RD: %s:%u, CE-ID: %u, Label-Block Offset: %u, "
                                                "Label-Block Size: %u, Label Base %s",
                                                ip_to_str(ip4addr.addr_bytes),
                                                tvb_get_ntohs(tvb, offset + 8),
                                                ce_id,
                                                labblk_off,
                                                labblk_size,
                                                stack_strbuf->str);
                            break;
                        case FORMAT_AS4_LOC:
                            proto_tree_add_text(tree, tvb, offset,
                                                (offset + plen + 1) - start_offset,
                                                "RD: %u.%u:%u, CE-ID: %u, Label-Block Offset: %u, "
                                                "Label-Block Size: %u, Label Base %s",
                                                tvb_get_ntohs(tvb, offset + 4),
                                                tvb_get_ntohs(tvb, offset + 6),
                                                tvb_get_ntohs(tvb, offset + 8),
                                                ce_id,
                                                labblk_off,
                                                labblk_size,
                                                stack_strbuf->str);
                            break;
                        default:
                            proto_tree_add_text(tree, tvb, start_offset,
                                                (offset - start_offset) + 2,
                                                "Unknown labeled VPN address format %u", rd_type);
                            return -1;
                    } /* switch (rd_type) */
                }
                /* FIXME there are subTLVs left to decode ... for now lets omit them */
                total_length = plen+2;
                break;

            default:
                proto_tree_add_text(tree, tvb, start_offset, 0,
                                    "Unknown SAFI (%u) for AFI %u", safi, afi);
                return -1;
        } /* switch (safi) */
        break;

        default:
            proto_tree_add_text(tree, tvb, start_offset, 0,
                                "Unknown AFI (%u) value", afi);
            return -1;
    } /* switch (afi) */
    return(total_length);
}

/*
 * Dissect a BGP capability.
 */
static int
dissect_bgp_capability_item(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset, gboolean action)
{
    proto_tree *cap_tree;
    proto_item *ti;
    proto_item *ti_len;
    guint8 ctype;
    guint8 clen;

    ti = proto_tree_add_item(tree, hf_bgp_cap, tvb, offset, -1, ENC_NA);
    cap_tree = proto_item_add_subtree(ti, ett_bgp_cap);

    proto_tree_add_item(cap_tree, hf_bgp_cap_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    ctype = tvb_get_guint8(tvb, offset);
    proto_item_append_text(ti, ": %s", val_to_str(ctype, capability_vals, "Unknown capability %d"));
    offset += 1;

    ti_len = proto_tree_add_item(cap_tree, hf_bgp_cap_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    clen = tvb_get_guint8(tvb, offset);
    proto_item_set_len(ti, clen+2);
    offset += 1;

    if(action){
        proto_tree_add_item(cap_tree, hf_bgp_cap_action, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_item_set_len(ti, clen+3);
        offset += 1;
    }

    /* check the capability type */
    switch (ctype) {
        case BGP_CAPABILITY_RESERVED:
            if (clen != 0) {
                expert_add_info_format(pinfo, ti_len, PI_MALFORMED, PI_ERROR, "Capability length %u wrong, must be = 0", clen);
                proto_tree_add_item(cap_tree, hf_bgp_cap_unknown, tvb, offset, clen, ENC_NA);
            }
            offset += clen;
            break;
        case BGP_CAPABILITY_MULTIPROTOCOL:
            if (clen != 4) {
                expert_add_info_format(pinfo, ti_len, PI_MALFORMED, PI_ERROR, "Capability length %u is wrong, must be = 4", clen);
                proto_tree_add_item(cap_tree, hf_bgp_cap_unknown, tvb, offset, clen, ENC_NA);
                offset += clen;
            }
            else {
                /* AFI */
                proto_tree_add_item(cap_tree, hf_bgp_cap_mp_afi, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* Reserved */
                proto_tree_add_item(cap_tree, hf_bgp_cap_reserved, tvb, offset, 1, ENC_NA);
                offset += 1;

                /* SAFI */
                proto_tree_add_item(cap_tree, hf_bgp_cap_mp_safi, tvb, offset, 1, ENC_NA);
                offset += 1;

            }
            break;
        case BGP_CAPABILITY_GRACEFUL_RESTART:
            if ((clen < 6) && (clen != 2)) {
                expert_add_info_format(pinfo, ti_len, PI_MALFORMED, PI_ERROR, "Capability length %u too short, must be greater than 6", clen);
                proto_tree_add_item(cap_tree, hf_bgp_cap_unknown, tvb, offset, clen, ENC_NA);
                offset += clen;
            }
            else {
                int eclen = offset + clen;
                proto_tree *sub_tree;

                if (clen == 2){
                    expert_add_info_format(pinfo, ti_len, PI_REQUEST_CODE, PI_CHAT, "Graceful Restart Capability supported in Helper mode only");
                }

                /* Timers */
                ti = proto_tree_add_item(cap_tree, hf_bgp_cap_gr_timers, tvb, offset, 2, ENC_NA);
                sub_tree = proto_item_add_subtree(ti, ett_bgp_cap);
                proto_tree_add_item(sub_tree, hf_bgp_cap_gr_timers_restart_flag, tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(sub_tree, hf_bgp_cap_gr_timers_restart_time, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /*
                 * what follows is alist of AFI/SAFI/flag triplets
                 * read it until the TLV ends
                 */
                while (offset < eclen) {
                    /* AFI */
                    proto_tree_add_item(cap_tree, hf_bgp_cap_gr_afi, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;

                    /* SAFI */
                    proto_tree_add_item(cap_tree, hf_bgp_cap_gr_safi, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;

                    /* Flags */
                    ti = proto_tree_add_item(cap_tree, hf_bgp_cap_gr_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
                    sub_tree = proto_item_add_subtree(ti, ett_bgp_cap);
                    proto_tree_add_item(sub_tree, hf_bgp_cap_gr_flag_pfs, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;
                }
            }
            break;
        case BGP_CAPABILITY_4_OCTET_AS_NUMBER:
            if (clen != 4) {
                expert_add_info_format(pinfo, ti_len, PI_MALFORMED, PI_ERROR, "Capability length %u is wrong, must be = 4", clen);
                proto_tree_add_item(cap_tree, hf_bgp_cap_unknown, tvb, offset, clen, ENC_NA);
                offset += clen;
            }
            else {
                proto_tree_add_item(cap_tree, hf_bgp_cap_4as, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
            }
            break;
        case BGP_CAPABILITY_DYNAMIC_CAPABILITY:
            if (clen > 0) {
                int eclen = offset + clen;

                while (offset < eclen) {
                    proto_tree_add_item(cap_tree, hf_bgp_cap_dc, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;
                }
            }
            break;
        case BGP_CAPABILITY_ADDITIONAL_PATHS:
            if (clen != 4) {
                expert_add_info_format(pinfo, ti_len, PI_MALFORMED, PI_ERROR, "Capability length %u is wrong, must be = 4", clen);
                proto_tree_add_item(cap_tree, hf_bgp_cap_unknown, tvb, offset, clen, ENC_NA);
                offset += clen;
            }
            else { /* AFI SAFI Send-receive*/
                /* AFI */
                proto_tree_add_item(cap_tree, hf_bgp_cap_ap_afi, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* SAFI */
                proto_tree_add_item(cap_tree, hf_bgp_cap_ap_safi, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;

                /* Send-Receive */
                proto_tree_add_item(cap_tree, hf_bgp_cap_ap_sendreceive, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;

            }
            break;

        case BGP_CAPABILITY_ENHANCED_ROUTE_REFRESH:
        case BGP_CAPABILITY_ROUTE_REFRESH_CISCO:
        case BGP_CAPABILITY_ROUTE_REFRESH:
            if (clen != 0) {
                expert_add_info_format(pinfo, ti_len, PI_MALFORMED, PI_ERROR, "Capability length %u wrong, must be = 0", clen);
                proto_tree_add_item(cap_tree, hf_bgp_cap_unknown, tvb, offset, clen, ENC_NA);
            }
            offset += clen;
            break;
        case BGP_CAPABILITY_ORF_CISCO:
        case BGP_CAPABILITY_COOPERATIVE_ROUTE_FILTERING:
            if (clen < 6) {
                expert_add_info_format(pinfo, ti_len, PI_MALFORMED, PI_ERROR, "Capability length %u too short, must be greater than 6", clen);
                proto_tree_add_item(cap_tree, hf_bgp_cap_unknown, tvb, offset, clen, ENC_NA);
                offset += clen;
            }
            else {
                guint8 orfnum;       /* number of ORFs */
                int i;
                /* AFI */
                proto_tree_add_item(cap_tree, hf_bgp_cap_orf_afi, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* Reserved */
                proto_tree_add_item(cap_tree, hf_bgp_cap_reserved, tvb, offset, 1, ENC_NA);
                offset += 1;

                /* SAFI */
                proto_tree_add_item(cap_tree, hf_bgp_cap_orf_safi, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;

                /* Number of ORFs */
                orfnum = tvb_get_guint8(tvb, offset);
                proto_tree_add_item(cap_tree, hf_bgp_cap_orf_number, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                for (i=0; i<orfnum; i++) {
                    /* ORF Type */
                    proto_tree_add_item(cap_tree, hf_bgp_cap_orf_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;

                    /* Send/Receive */
                    proto_tree_add_item(cap_tree, hf_bgp_cap_orf_sendreceive, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;
                }
            }

            break;
            /* unknown capability */
        default:
            if (clen != 0) {
                proto_tree_add_item(cap_tree, hf_bgp_cap_unknown, tvb, offset, clen, ENC_NA);
            }
            offset += clen;
            break;
    } /* switch (ctype) */
    return offset;
}

/*
 * Dissect a BGP OPEN message.
 */
static const value_string community_vals[] = {
    { BGP_COMM_NO_EXPORT,           "NO_EXPORT" },
    { BGP_COMM_NO_ADVERTISE,        "NO_ADVERTISE" },
    { BGP_COMM_NO_EXPORT_SUBCONFED, "NO_EXPORT_SUBCONFED" },
    { 0,                            NULL }
};

static void
dissect_bgp_open(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo)
{
    guint8          optlen;    /* Option Length */
    int             ptype;     /* parameter type        */
    int             plen;      /* parameter length      */
    int             cend;      /* capabilities end      */
    int             oend;      /* options end           */
    int             offset;    /* tvb offset counter    */
    proto_item      *ti;       /* tree item             */
    proto_tree      *opt_tree;  /* subtree for options   */
    proto_tree      *par_tree;  /* subtree for par options   */

    offset = BGP_MARKER_SIZE + 2 + 1;

    proto_tree_add_item(tree, hf_bgp_open_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_bgp_open_myas, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_bgp_open_holdtime, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_bgp_open_identifier, tvb, offset, 4, ENC_NA);
    offset += 4;

    proto_tree_add_item(tree, hf_bgp_open_opt_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    optlen = tvb_get_guint8(tvb, offset);
    offset += 1;

    /* optional parameters */
    if (optlen > 0) {
        oend = offset + optlen;

        /* add a subtree */
        ti = proto_tree_add_item(tree, hf_bgp_open_opt_params, tvb, offset, optlen, ENC_NA);
        opt_tree = proto_item_add_subtree(ti, ett_bgp_options);

        /* step through all of the optional parameters */
        while (offset < oend) {

            /* add a subtree */
            ti = proto_tree_add_item(opt_tree, hf_bgp_open_opt_param, tvb, offset, -1, ENC_NA);
            par_tree = proto_item_add_subtree(ti, ett_bgp_options);

            /* display and grab the type ... */
            proto_tree_add_item(par_tree, hf_bgp_open_opt_param_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            ptype = tvb_get_guint8(tvb, offset);
            proto_item_append_text(ti, ": %s", val_to_str(ptype, bgp_open_opt_vals, "Unknown Parameter %d"));
            offset += 1;

            /* ... and length */
            proto_tree_add_item(par_tree, hf_bgp_open_opt_param_len, tvb, offset, 1, ENC_BIG_ENDIAN);
            plen = tvb_get_guint8(tvb, offset);
            proto_item_set_len(ti, plen+2);
            offset += 1;

            /* check the type */
            switch (ptype) {
                case BGP_OPTION_AUTHENTICATION:
                    proto_tree_add_item(par_tree, hf_bgp_open_opt_param_auth, tvb, offset, plen, ENC_NA);
                    offset += plen;
                    break;
                case BGP_OPTION_CAPABILITY:
                    /* grab the capability code */
                    cend = offset + plen;

                    /* step through all of the capabilities */
                    while (offset < cend) {
                        offset = dissect_bgp_capability_item(tvb, par_tree, pinfo, offset, FALSE);
                    }
                    break;
                default:
                    proto_tree_add_item(opt_tree, hf_bgp_open_opt_param_unknown, tvb, offset, plen, ENC_NA);
                    break;
            } /* switch (ptype) */
        }
    }
}

/*
 * Dissect a BGP UPDATE message.
 */
static void
dissect_bgp_update(tvbuff_t *tvb, proto_tree *tree)
{
    guint8          bgpa_flags;                 /* path attributes          */
    guint8          bgpa_type;
    guint16         hlen;                       /* message length           */
    gint            o;                          /* packet offset            */
    gint            q;                          /* tmp                      */
    gint            end;                        /* message end              */
    guint16         ext_com;                    /* EXTENDED COMMUNITY extended length type  */
    guint8          ext_com8;                   /* EXTENDED COMMUNITY regular type  */
    gboolean        is_regular_type;            /* flag for regular types   */
    gboolean        is_extended_type;           /* flag for extended types  */
    guint16         len;                        /* tmp                      */
    int             advance;                    /* tmp                      */
    proto_item      *ti;                        /* tree item                */
    proto_tree      *subtree;                   /* subtree for attributes   */
    proto_tree      *subtree2;                  /* subtree for attributes   */
    proto_tree      *subtree3;                  /* subtree for attributes   */
    proto_tree      *subtree4;                  /* subtree for attributes   */
    proto_tree      *subtree5;                  /* subtree for attributes   */
    proto_tree      *subtree6;                  /* subtree for attributes   */
    proto_tree      *as_paths_tree;             /* subtree for AS_PATHs     */
    proto_tree      *as_path_tree;              /* subtree for AS_PATH      */
    proto_tree      *as_path_segment_tree;      /* subtree for AS_PATH segments */
    proto_tree      *communities_tree;          /* subtree for COMMUNITIES  */
    proto_tree      *community_tree;            /* subtree for a community  */
    proto_tree      *cluster_list_tree;         /* subtree for CLUSTER_LIST */
    int             i, j;                       /* tmp                      */
    guint8          length;                     /* AS_PATH length           */
    guint8          type;                       /* AS_PATH type             */
    guint32         as_path_item;               /* item in AS_PATH segment  */
    emem_strbuf_t   *as_path_emstr = NULL;      /* AS_PATH                  */
    emem_strbuf_t   *communities_emstr = NULL;  /* COMMUNITIES              */
    emem_strbuf_t   *cluster_list_emstr = NULL; /* CLUSTER_LIST             */
    emem_strbuf_t   *junk_emstr;                /* tmp                      */
    guint32         ipaddr;                     /* IPv4 address             */
    guint32         aggregator_as;
    guint16         ssa_type;                   /* SSA T + Type */
    guint16         ssa_len;                    /* SSA TLV Length */
    guint8          ssa_v3_len;                 /* SSA L2TPv3 Cookie Length */
    gfloat          linkband;                   /* Link bandwidth           */
    guint16         as_num;                     /* Autonomous System Number */
    guint16         encaps_tunnel_type;         /* Encapsulation Tunnel Type */
    guint16         encaps_tunnel_len;          /* Encapsulation TLV Length */
    guint8          encaps_tunnel_subtype;      /* Encapsulation Tunnel Sub-TLV Type */
    guint8          encaps_tunnel_sublen;       /* Encapsulation TLV Sub-TLV Length */

    if (!tree)
        return;

    hlen = tvb_get_ntohs(tvb, BGP_MARKER_SIZE);
    o = BGP_HEADER_SIZE;
    junk_emstr = ep_strbuf_new_label(NULL);

    /* check for withdrawals */
    len = tvb_get_ntohs(tvb, o);
    proto_tree_add_text(tree, tvb, o, 2,
        "Unfeasible routes length: %u byte%s", len, plurality(len, "", "s"));
    o += 2;

    /* parse unfeasible prefixes */
    if (len > 0) {
        ti = proto_tree_add_text(tree, tvb, o, len, "Withdrawn routes:");
        subtree = proto_item_add_subtree(ti, ett_bgp_unfeas);
        /* parse each prefix */
                end = o + len;
        /* Heuristic to detect if IPv4 prefix are using Path Identifiers */
        if( detect_add_path_prefix4(tvb, o, end) ) {
            /* IPv4 prefixes with Path Id */
            while (o < end) {
                i = decode_path_prefix4(subtree, hf_bgp_nlri_path_id, hf_bgp_withdrawn_prefix, tvb, o,
                    "Withdrawn route");
                if (i < 0)
                    return;
                o += i;
            }
        } else {
            while (o < end) {
                i = decode_prefix4(subtree, hf_bgp_withdrawn_prefix, tvb, o, len,
                    "Withdrawn route");
                if (i < 0)
                    return;
                o += i;
            }
        }
   }

    /* check for advertisements */
    len = tvb_get_ntohs(tvb, o);
    proto_tree_add_text(tree, tvb, o, 2, "Total path attribute length: %u byte%s",
            len, plurality(len, "", "s"));

    /* path attributes */
    if (len > 0) {
        ti = proto_tree_add_text(tree, tvb, o + 2, len, "Path attributes");
        subtree = proto_item_add_subtree(ti, ett_bgp_attrs);
        i = 2;
        while (i < len) {
            proto_item *hidden_item;
            const char *msg;
            int     off;
            gint    k;
            guint16 alen, tlen, aoff, aoff_save;
            guint16 af;
            guint8  saf, snpa;
            guint8  nexthop_len;
            guint8  asn_len = 0;

            bgpa_flags = tvb_get_guint8(tvb, o + i);
            bgpa_type = tvb_get_guint8(tvb, o + i+1);

            /* check for the Extended Length bit */
            if (bgpa_flags & BGP_ATTR_FLAG_EXTENDED_LENGTH) {
                alen = tvb_get_ntohs(tvb, o + i + BGP_SIZE_OF_PATH_ATTRIBUTE);
                aoff = BGP_SIZE_OF_PATH_ATTRIBUTE+2;
            } else {
                alen = tvb_get_guint8(tvb, o + i + BGP_SIZE_OF_PATH_ATTRIBUTE);
                aoff = BGP_SIZE_OF_PATH_ATTRIBUTE+1;
            }
            tlen = alen;

            /* This is kind of ugly - similar code appears twice, but it
               helps browsing attrs.                                      */
            /* the first switch prints things in the title of the subtree */
            switch (bgpa_type) {
                case BGPTYPE_ORIGIN:
                    if (tlen != 1)
                        goto default_attribute_top;
                    msg = val_to_str_const(tvb_get_guint8(tvb, o + i + aoff), bgpattr_origin, "Unknown");
                    ti = proto_tree_add_text(subtree, tvb, o + i, tlen + aoff,
                                             "%s: %s (%u byte%s)",
                                             val_to_str_const(bgpa_type, bgpattr_type, "Unknown"),
                                             msg, tlen + aoff, plurality(tlen + aoff, "", "s"));
                    break;
                case BGPTYPE_AS_PATH:
                case BGPTYPE_NEW_AS_PATH:
                    /* (o + i + aoff) =
                       (o + current attribute + aoff bytes to first tuple) */
                    q = o + i + aoff;
                    end = q + tlen;
                    /* must be freed by second switch!                         */
                    /* "tlen * 11" (10 digits + space) should be a good estimate
                       of how long the AS path string could be                 */
                    if (as_path_emstr == NULL)
                        as_path_emstr = ep_strbuf_sized_new((tlen + 1) * 11, 0);
                    ep_strbuf_truncate(as_path_emstr, 0);

                    /* estimate the length of the AS number */
                    if (bgpa_type == BGPTYPE_NEW_AS_PATH)
                        asn_len = 4;
                    else {
                        if (bgp_asn_len == 0) {
                            guint unknown_segment_type = 0;
                            guint asn_is_null = 0;
                            guint d;
                            asn_len = 2;
                            k = q;
                            while ((k < end) && !unknown_segment_type && !asn_is_null)
                            {
                                type = tvb_get_guint8(tvb, k++);

                                /* type of segment is unknown */
                                if (type != AS_SET &&
                                    type != AS_SEQUENCE &&
                                    type != AS_CONFED_SEQUENCE &&
                                    type != AS_CONFED_SEQUENCE)
                                    unknown_segment_type = 1;

                                length = tvb_get_guint8(tvb, k++);

                                /* Check for invalid ASN */
                                for (d = 0; d < length && !unknown_segment_type && !asn_is_null; d++)
                                {
                                    if(tvb_get_ntohs(tvb, k) == 0)
                                        asn_is_null = 1;
                                    k += 2;
                                }
                            }
                            if(k != end || unknown_segment_type || asn_is_null)
                                asn_len = 4;
                        }
                        else {
                            asn_len = bgp_asn_len;
                        }
                    }

                    /* snarf each AS path */
                    while (q < end) {
                        type = tvb_get_guint8(tvb, q++);
                        if (as_path_emstr->len > 1 &&
                            as_path_emstr->str[as_path_emstr->len - 1] != ' ')
                            ep_strbuf_append_c(as_path_emstr, ' ');
                        if (type == AS_SET) {
                            ep_strbuf_append_c(as_path_emstr, '{');
                        }
                        else if (type == AS_CONFED_SET) {
                            ep_strbuf_append_c(as_path_emstr, '[');
                        }
                        else if (type == AS_CONFED_SEQUENCE) {
                            ep_strbuf_append_c(as_path_emstr, '(');
                        }
                        length = tvb_get_guint8(tvb, q++);

                        /* snarf each value in path */
                        for (j = 0; j < length; j++) {
                            ep_strbuf_append_printf(as_path_emstr, "%u%s",
                                                    (asn_len == 2) ?
                                                    tvb_get_ntohs(tvb, q) : tvb_get_ntohl(tvb, q),
                                                    (type == AS_SET || type == AS_CONFED_SET) ?
                                                    ", " : " ");
                            q += asn_len;
                        }

                        /* cleanup end of string */
                        if (type == AS_SET) {
                            ep_strbuf_truncate(as_path_emstr, as_path_emstr->len - 2);
                            ep_strbuf_append_c(as_path_emstr, '}');
                        }
                        else if (type == AS_CONFED_SET) {
                            ep_strbuf_truncate(as_path_emstr, as_path_emstr->len - 2);
                            ep_strbuf_append_c(as_path_emstr, ']');
                        }
                        else if (type == AS_CONFED_SEQUENCE) {
                            ep_strbuf_truncate(as_path_emstr, as_path_emstr->len - 1);
                            ep_strbuf_append_c(as_path_emstr, ')');
                        }
                        else {
                            ep_strbuf_truncate(as_path_emstr, as_path_emstr->len - 1);
                        }
                    }

                    /* check for empty AS_PATH */
                    if (tlen == 0)
                        ep_strbuf_printf(as_path_emstr, "empty");

                    ti = proto_tree_add_text(subtree, tvb, o + i, tlen + aoff,
                                             "%s: %s (%u byte%s)",
                                             val_to_str_const(bgpa_type, bgpattr_type, "Unknown"),
                                             as_path_emstr->str, tlen + aoff,
                                             plurality(tlen + aoff, "", "s"));
                    break;
                case BGPTYPE_NEXT_HOP:
                    if (tlen != 4)
                        goto default_attribute_top;
                    ipaddr = tvb_get_ipv4(tvb, o + i + aoff);
                    ti = proto_tree_add_text(subtree, tvb, o + i, tlen + aoff,
                                             "%s: %s (%u byte%s)",
                                             val_to_str_const(bgpa_type, bgpattr_type, "Unknown"),
                                             ip_to_str((guint8 *)&ipaddr), tlen + aoff,
                                             plurality(tlen + aoff, "", "s"));
                    break;
                case BGPTYPE_MULTI_EXIT_DISC:
                    if (tlen != 4)
                        goto default_attribute_top;
                    ti = proto_tree_add_text(subtree, tvb, o + i, tlen + aoff,
                                             "%s: %u (%u byte%s)",
                                             val_to_str_const(bgpa_type, bgpattr_type, "Unknown"),
                                             tvb_get_ntohl(tvb, o + i + aoff), tlen + aoff,
                                             plurality(tlen + aoff, "", "s"));
                    break;
                case BGPTYPE_LOCAL_PREF:
                    if (tlen != 4)
                        goto default_attribute_top;
                    ti = proto_tree_add_text(subtree, tvb, o + i, tlen + aoff,
                                             "%s: %u (%u byte%s)",
                                             val_to_str_const(bgpa_type, bgpattr_type, "Unknown"),
                                             tvb_get_ntohl(tvb, o + i + aoff), tlen + aoff,
                                             plurality(tlen + aoff, "", "s"));
                    break;
                case BGPTYPE_ATOMIC_AGGREGATE:
                    if (tlen != 0)
                        goto default_attribute_top;
                    ti = proto_tree_add_text(subtree, tvb, o + i, tlen + aoff,
                                             "%s (%u byte%s)",
                                             val_to_str_const(bgpa_type, bgpattr_type, "Unknown"),
                                             tlen + aoff, plurality(tlen + aoff, "", "s"));
                    break;
                case BGPTYPE_AGGREGATOR:
                    if (tlen != 6 && tlen != 8)
                        goto default_attribute_top;
                case BGPTYPE_NEW_AGGREGATOR:
                    if (bgpa_type == BGPTYPE_NEW_AGGREGATOR && tlen != 8)
                        goto default_attribute_top;
                    asn_len = tlen - 4;
                    ipaddr = tvb_get_ipv4(tvb, o + i + aoff + asn_len);
                    ti = proto_tree_add_text(subtree, tvb, o + i, tlen + aoff,
                                             "%s: AS: %u origin: %s (%u byte%s)",
                                             val_to_str_const(bgpa_type, bgpattr_type, "Unknown"),
                                             (asn_len == 2) ? tvb_get_ntohs(tvb, o + i + aoff) :
                                             tvb_get_ntohl(tvb, o + i + aoff),
                                             ip_to_str((guint8 *)&ipaddr),
                                             tlen + aoff, plurality(tlen + aoff, "", "s"));
                    break;
                case BGPTYPE_COMMUNITIES:
                    if (tlen % 4 != 0)
                        goto default_attribute_top;

                    /* (o + i + aoff) =
                       (o + current attribute + aoff bytes to first tuple) */
                    q = o + i + aoff;
                    end = q + tlen;
                    /* must be freed by second switch!                          */
                    /* "tlen * 12" (5 digits, a :, 5 digits + space ) should be
                       a good estimate of how long the communities string could
                       be                                                       */
                    if (communities_emstr == NULL)
                        communities_emstr = ep_strbuf_sized_new((tlen + 1) * 12, 0);
                    ep_strbuf_truncate(communities_emstr, 0);

                    /* snarf each community */
                    while (q < end) {
                        /* check for well-known communities */
                        if (tvb_get_ntohl(tvb, q) == BGP_COMM_NO_EXPORT)
                            ep_strbuf_append(communities_emstr, "NO_EXPORT ");
                        else if (tvb_get_ntohl(tvb, q) == BGP_COMM_NO_ADVERTISE)
                            ep_strbuf_append(communities_emstr, "NO_ADVERTISE ");
                        else if (tvb_get_ntohl(tvb, q) == BGP_COMM_NO_EXPORT_SUBCONFED)
                            ep_strbuf_append(communities_emstr, "NO_EXPORT_SUBCONFED ");
                        else {
                            ep_strbuf_append_printf(communities_emstr, "%u:%u ",
                                                    tvb_get_ntohs(tvb, q),
                                                    tvb_get_ntohs(tvb, q + 2));
                        }
                        q += 4;
                    }
                    /* cleanup end of string */
                    ep_strbuf_truncate(communities_emstr, communities_emstr->len - 1);

                    ti = proto_tree_add_text(subtree, tvb, o + i, tlen + aoff,
                                             "%s: %s (%u byte%s)",
                                             val_to_str_const(bgpa_type, bgpattr_type, "Unknown"),
                                             communities_emstr->str, tlen + aoff,
                                             plurality(tlen + aoff, "", "s"));
                    break;
                case BGPTYPE_ORIGINATOR_ID:
                    if (tlen != 4)
                        goto default_attribute_top;
                    ipaddr = tvb_get_ipv4(tvb, o + i + aoff);
                    ti = proto_tree_add_text(subtree, tvb, o + i, tlen + aoff,
                                             "%s: %s (%u byte%s)",
                                             val_to_str_const(bgpa_type, bgpattr_type, "Unknown"),
                                             ip_to_str((guint8 *)&ipaddr),
                                             tlen + aoff, plurality(tlen + aoff, "", "s"));
                    break;
                case BGPTYPE_CLUSTER_LIST:
                    if (tlen % 4 != 0)
                        goto default_attribute_top;

                    /* (o + i + aoff) =
                       (o + current attribute + aoff bytes to first tuple) */
                    q = o + i + aoff;
                    end = q + tlen;
                    /* must be freed by second switch!                          */
                    /* "tlen * 16" (12 digits, 3 dots + space ) should be
                       a good estimate of how long the cluster_list string could
                       be                                                       */
                    if (cluster_list_emstr == NULL)
                        cluster_list_emstr = ep_strbuf_sized_new((tlen + 1) * 16, 0);
                    ep_strbuf_truncate(cluster_list_emstr, 0);

                    /* snarf each cluster list */
                    while (q < end) {
                        ipaddr = tvb_get_ipv4(tvb, q);
                        ep_strbuf_append_printf(cluster_list_emstr, "%s ", ip_to_str((guint8 *)&ipaddr));
                        q += 4;
                    }
                    /* cleanup end of string */
                    ep_strbuf_truncate(cluster_list_emstr, cluster_list_emstr->len - 1);

                    ti = proto_tree_add_text(subtree, tvb, o + i, tlen + aoff,
                                             "%s: %s (%u byte%s)",
                                             val_to_str_const(bgpa_type, bgpattr_type, "Unknown"),
                                             cluster_list_emstr->str, tlen + aoff,
                                             plurality(tlen + aoff, "", "s"));
                    break;
                case BGPTYPE_EXTENDED_COMMUNITY:
                    if (tlen %8 != 0)
                        break;
                    ti = proto_tree_add_text(subtree,tvb,o+i,tlen+aoff,
                                             "%s: (%u byte%s)",
                                             val_to_str_const(bgpa_type,bgpattr_type,"Unknown"),
                                             tlen + aoff,
                                             plurality(tlen + aoff, "", "s"));
                    break;
                case BGPTYPE_SAFI_SPECIFIC_ATTR:
                    ti = proto_tree_add_text(subtree,tvb,o+i,tlen+aoff,
                                             "%s: (%u byte%s)",
                                             val_to_str_const(bgpa_type,bgpattr_type,"Unknown"),
                                             tlen + aoff,
                                             plurality(tlen + aoff, "", "s"));
                    break;
                default:
                default_attribute_top:
                    ti = proto_tree_add_text(subtree, tvb, o + i, tlen + aoff,
                                             "%s (%u byte%s)",
                                             val_to_str_const(bgpa_type, bgpattr_type, "Unknown"),
                                             tlen + aoff, plurality(tlen + aoff, "", "s"));
            } /* switch (bgpa.bgpa_type) */ /* end of first switch */
            subtree2 = proto_item_add_subtree(ti, ett_bgp_attr);

            /* figure out flags */
            ep_strbuf_truncate(junk_emstr, 0);
            if (bgpa_flags & BGP_ATTR_FLAG_OPTIONAL) {
                 ep_strbuf_append(junk_emstr, "Optional, ");
            }
            else {
                 ep_strbuf_append(junk_emstr, "Well-known, ");
            }
            if (bgpa_flags & BGP_ATTR_FLAG_TRANSITIVE) {
                 ep_strbuf_append(junk_emstr, "Transitive, ");
            }
            else {
                 ep_strbuf_append(junk_emstr, "Non-transitive, ");
            }
            if (bgpa_flags & BGP_ATTR_FLAG_PARTIAL) {
                 ep_strbuf_append(junk_emstr, "Partial");
            }
            else {
                 ep_strbuf_append(junk_emstr, "Complete");
            }
            if (bgpa_flags & BGP_ATTR_FLAG_EXTENDED_LENGTH) {
                 ep_strbuf_append(junk_emstr, ", Extended Length");
            }
            ti = proto_tree_add_text(subtree2, tvb, o + i, 1,
                    "Flags: 0x%02x (%s)", bgpa_flags, junk_emstr->str);
            subtree3 = proto_item_add_subtree(ti, ett_bgp_attr_flags);

            /* add flag bitfield subtrees */
            proto_tree_add_item(subtree3, hf_bgp_flags_optional, tvb, o + i, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(subtree3, hf_bgp_flags_transitive, tvb, o + i, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(subtree3, hf_bgp_flags_partial, tvb, o + i, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(subtree3, hf_bgp_flags_extended_length, tvb, o + i, 1, ENC_BIG_ENDIAN);

            proto_tree_add_text(subtree2, tvb,
                    o + i + 1, 1,
                    "Type code: %s (%u)",
                    val_to_str_const(bgpa_type, bgpattr_type, "Unknown"),
                    bgpa_type);

            proto_tree_add_text(subtree2, tvb, o + i + BGP_SIZE_OF_PATH_ATTRIBUTE,
                    aoff - BGP_SIZE_OF_PATH_ATTRIBUTE, "Length: %d byte%s", tlen,
                    plurality(tlen, "", "s"));

            /* the second switch prints things in the actual subtree of each
               attribute                                                     */
            switch (bgpa_type) {
                case BGPTYPE_ORIGIN:
                    if (tlen != 1) {
                        proto_tree_add_text(subtree2, tvb, o + i + aoff, tlen,
                                            "Origin (invalid): %u byte%s", tlen,
                                            plurality(tlen, "", "s"));
                    } else {
                        proto_tree_add_item(subtree2, hf_bgp_origin, tvb,
                                            o + i + aoff, 1, ENC_BIG_ENDIAN);
                    }
                    break;
                case BGPTYPE_AS_PATH:
                case BGPTYPE_NEW_AS_PATH:
                    ti = proto_tree_add_text(subtree2, tvb, o + i + aoff, tlen,
                                             "AS path: %s", as_path_emstr->str);
                    as_paths_tree = proto_item_add_subtree(ti, ett_bgp_as_paths);

                    /* (o + i + aoff) =
                       (o + current attribute + aoff bytes to first tuple) */
                    q = o + i + aoff;
                    end = q + tlen;

                    /* snarf each AS path tuple, we have to step through each one
                       again to make a separate subtree so we can't just reuse
                       as_path_gstr from above */
                    /* XXX - Can we use some g_string*() trickery instead, e.g.
                       g_string_erase()? */
                    while (q < end) {
                        ep_strbuf_truncate(as_path_emstr, 0);
                        type = tvb_get_guint8(tvb, q++);
                        if (type == AS_SET) {
                            ep_strbuf_append_c(as_path_emstr, '{');
                        }
                        else if (type == AS_CONFED_SET) {
                            ep_strbuf_append_c(as_path_emstr, '[');
                        }
                        else if (type == AS_CONFED_SEQUENCE) {
                            ep_strbuf_append_c(as_path_emstr, '(');
                        }
                        length = tvb_get_guint8(tvb, q++);

                        /* snarf each value in path */
                        for (j = 0; j < length; j++) {
                            ep_strbuf_append_printf(as_path_emstr, "%u%s",
                                                    (asn_len == 2) ?
                                                    tvb_get_ntohs(tvb, q) : tvb_get_ntohl(tvb, q),
                                                    (type == AS_SET || type == AS_CONFED_SET) ? ", " : " ");
                            q += asn_len;
                        }

                        /* cleanup end of string */
                        if (type == AS_SET) {
                            ep_strbuf_truncate(as_path_emstr, as_path_emstr->len - 2);
                            ep_strbuf_append_c(as_path_emstr, '}');
                        }
                        else if (type == AS_CONFED_SET) {
                            ep_strbuf_truncate(as_path_emstr, as_path_emstr->len - 2);
                            ep_strbuf_append_c(as_path_emstr, ']');
                        }
                        else if (type == AS_CONFED_SEQUENCE) {
                            ep_strbuf_truncate(as_path_emstr, as_path_emstr->len - 1);
                            ep_strbuf_append_c(as_path_emstr, ')');
                        }
                        else {
                            ep_strbuf_truncate(as_path_emstr, as_path_emstr->len - 1);
                        }

                        /* length here means number of ASs, ie length * 2 bytes */
                        ti = proto_tree_add_text(as_paths_tree, tvb,
                                                 q - length * asn_len - 2,
                                                 length * asn_len + 2, "AS path segment: %s", as_path_emstr->str);
                        as_path_tree = proto_item_add_subtree(ti, ett_bgp_as_paths);
                        proto_tree_add_text(as_path_tree, tvb, q - length * asn_len - 2,
                                            1, "Path segment type: %s (%u)",
                                            val_to_str_const(type, as_segment_type, "Unknown"), type);
                        proto_tree_add_text(as_path_tree, tvb, q - length * asn_len - 1,
                                            1, "Path segment length: %u AS%s", length,
                                            plurality(length, "", "s"));

                        /* backup and reprint path segment value(s) only */
                        q -= asn_len * length;
                        ti = proto_tree_add_text(as_path_tree, tvb, q,
                                                 length * asn_len, "Path segment value:");
                        as_path_segment_tree = proto_item_add_subtree(ti,
                                                                      ett_bgp_as_path_segments);
                        for (j = 0; j < length; j++) {
                            as_path_item = (asn_len == 2) ?
                                tvb_get_ntohs(tvb, q) : tvb_get_ntohl(tvb, q);
                            proto_item_append_text(ti, " %u", as_path_item);
                            hidden_item = proto_tree_add_uint(as_path_segment_tree, hf_bgp_as_path, tvb,
                                                              q, asn_len, as_path_item);
                            PROTO_ITEM_SET_HIDDEN(hidden_item);
                            q += asn_len;
                        }
                    }

                    break;
                case BGPTYPE_NEXT_HOP:
                    if (tlen != 4) {
                        proto_tree_add_text(subtree2, tvb, o + i + aoff, tlen,
                                            "Next hop (invalid): %u byte%s", tlen,
                                            plurality(tlen, "", "s"));
                    } else {
                        proto_tree_add_item(subtree2, hf_bgp_next_hop, tvb,
                                            o + i + aoff, tlen, ENC_BIG_ENDIAN);
                    }
                    break;
                case BGPTYPE_MULTI_EXIT_DISC:
                    if (tlen != 4) {
                        proto_tree_add_text(subtree2, tvb, o + i + aoff, tlen,
                                            "Multiple exit discriminator (invalid): %u byte%s",
                                            tlen, plurality(tlen, "", "s"));
                    } else {
                        proto_tree_add_item(subtree2, hf_bgp_multi_exit_disc, tvb,
                                            o + i + aoff, tlen, ENC_BIG_ENDIAN);
                    }
                    break;
                case BGPTYPE_LOCAL_PREF:
                    if (tlen != 4) {
                        proto_tree_add_text(subtree2, tvb, o + i + aoff, tlen,
                                            "Local preference (invalid): %u byte%s", tlen,
                                            plurality(tlen, "", "s"));
                    } else {
                        proto_tree_add_item(subtree2, hf_bgp_local_pref, tvb,
                                            o + i + aoff, tlen, ENC_BIG_ENDIAN);
                    }
                    break;
                case BGPTYPE_ATOMIC_AGGREGATE:
                    if (tlen != 0) {
                        proto_tree_add_text(subtree2, tvb, o + i + aoff, tlen,
                                            "Atomic aggregate (invalid): %u byte%s", tlen,
                                            plurality(tlen, "", "s"));
                    }
                    break;
                case BGPTYPE_AGGREGATOR:
                    if (tlen != 6 && tlen != 8) {
                        proto_tree_add_text(subtree2, tvb, o + i + aoff, tlen,
                                            "Aggregator (invalid): %u byte%s", tlen,
                                            plurality(tlen, "", "s"));
                        break;
                    }
                case BGPTYPE_NEW_AGGREGATOR:
                    if (bgpa_type == BGPTYPE_NEW_AGGREGATOR && tlen != 8)
                        proto_tree_add_text(subtree2, tvb, o + i + aoff, tlen,
                                            "Aggregator (invalid): %u byte%s", tlen,
                                            plurality(tlen, "", "s"));
                    else {
                        asn_len = tlen - 4;
                        aggregator_as = (asn_len == 2) ?
                            tvb_get_ntohs(tvb, o + i + aoff) :
                            tvb_get_ntohl(tvb, o + i + aoff);
                        proto_tree_add_uint(subtree2, hf_bgp_aggregator_as, tvb,
                                            o + i + aoff, asn_len, aggregator_as);
                        proto_tree_add_item(subtree2, hf_bgp_aggregator_origin, tvb,
                                            o + i + aoff + asn_len, 4, ENC_BIG_ENDIAN);
                    }
                    break;
                case BGPTYPE_COMMUNITIES:
                    if (tlen % 4 != 0) {
                        proto_tree_add_text(subtree2, tvb, o + i + aoff, tlen,
                                            "Communities (invalid): %u byte%s", tlen,
                                            plurality(tlen, "", "s"));
                        break;
                    }

                    ti = proto_tree_add_text(subtree2, tvb, o + i + aoff, tlen,
                                             "Communities: %s", communities_emstr ? communities_emstr->str : "<none>");
                    communities_tree = proto_item_add_subtree(ti,
                                                              ett_bgp_communities);

                    /* (o + i + aoff) =
                       (o + current attribute + aoff bytes to first tuple) */
                    q = o + i + aoff;
                    end = q + tlen;

                    /* snarf each community */
                    while (q < end) {
                        /* check for reserved values */
                        guint32 community = tvb_get_ntohl(tvb, q);
                        if ((community & 0xFFFF0000) == FOURHEX0 ||
                            (community & 0xFFFF0000) == FOURHEXF) {
                            proto_tree_add_text(communities_tree, tvb,
                                                q - 3 + aoff, 4,
                                                "Community: %s (0x%08x)",
                                                val_to_str_const(community, community_vals, "(reserved)"),
                                                community);
                        }
                        else {
                            ti = proto_tree_add_text(communities_tree, tvb,
                                                     q - 3 + aoff, 4, "Community: %u:%u",
                                                     tvb_get_ntohs(tvb, q), tvb_get_ntohs(tvb, q + 2));
                            community_tree = proto_item_add_subtree(ti,
                                                                    ett_bgp_communities);
                            proto_tree_add_item(community_tree, hf_bgp_community_as,
                                                tvb, q - 3 + aoff, 2, ENC_BIG_ENDIAN);
                            proto_tree_add_item(community_tree, hf_bgp_community_value,
                                                tvb, q - 1 + aoff, 2, ENC_BIG_ENDIAN);
                        }

                        q += 4;
                    }

                    break;
                case BGPTYPE_ORIGINATOR_ID:
                    if (tlen != 4) {
                        proto_tree_add_text(subtree2, tvb, o + i + aoff, tlen,
                                            "Originator identifier (invalid): %u byte%s", tlen,
                                            plurality(tlen, "", "s"));
                    } else {
                        proto_tree_add_item(subtree2, hf_bgp_originator_id, tvb,
                                            o + i + aoff, tlen, ENC_BIG_ENDIAN);
                    }
                    break;
                case BGPTYPE_MP_REACH_NLRI:
                    /*
                     * RFC 2545 specifies that there may be more than one
                     * address in the MP_REACH_NLRI attribute in section
                     * 3, "Constructing the Next Hop field".
                     *
                     * Yes, RFC 2858 says you can't do that, and, yes, RFC
                     * 2858 obsoletes RFC 2283, which says you can do that,
                     * but that doesn't mean we shouldn't dissect packets
                     * that conform to RFC 2283 but not RFC 2858, as some
                     * device on the network might implement the 2283-style
                     * BGP extensions rather than RFC 2858-style extensions.
                     */
                    af = tvb_get_ntohs(tvb, o + i + aoff);
                    proto_tree_add_text(subtree2, tvb, o + i + aoff, 2,
                                        "Address family: %s (%u)",
                                        val_to_str_const(af, afn_vals, "Unknown"), af);
                    saf = tvb_get_guint8(tvb, o + i + aoff + 2) ;
                    proto_tree_add_text(subtree2, tvb, o + i + aoff + 2, 1,
                                        "Subsequent address family identifier: %s (%u)",
                                        val_to_str_const(saf, bgpattr_nlri_safi, saf >= 128 ? "Vendor specific" : "Unknown"),
                                        saf);
                    nexthop_len = tvb_get_guint8(tvb, o + i + aoff + 3);
                    ti = proto_tree_add_text(subtree2, tvb, o + i + aoff + 3,
                                             nexthop_len + 1,
                                             "Next hop network address (%d byte%s)",
                                             nexthop_len, plurality(nexthop_len, "", "s"));
                    subtree3 = proto_item_add_subtree(ti, ett_bgp_mp_nhna);

                    /*
                     * The addresses don't contain lengths, so if we
                     * don't understand the address family type, we
                     * cannot parse the subsequent addresses as we
                     * don't know how long they are.
                     */
                    switch (af) {
                        default:
                            proto_tree_add_text(subtree3, tvb, o + i + aoff + 4,
                                                nexthop_len, "Unknown Address Family");
                            break;

                        case AFNUM_INET:
                        case AFNUM_INET6:
                        case AFNUM_L2VPN:
                        case AFNUM_L2VPN_OLD:

                            j = 0;
                            while (j < nexthop_len) {
                                advance = mp_addr_to_str(af, saf, tvb, o + i + aoff + 4 + j,
                                                         junk_emstr, nexthop_len) ;
                                if (advance == 0) /* catch if this is a unknown AFI type*/
                                    break;
                                if (j + advance > nexthop_len)
                                    break;
                                proto_tree_add_text(subtree3, tvb,o + i + aoff + 4 + j,
                                                    advance, "Next hop: %s (%u)", junk_emstr->str, advance);
                                j += advance;
                            }
                            break;
                    } /* switch (af) */

                    aoff_save = aoff;
                    tlen -= nexthop_len + 4;
                    aoff += nexthop_len + 4 ;

                    off = 0;
                    snpa = tvb_get_guint8(tvb, o + i + aoff);
                    ti = proto_tree_add_text(subtree2, tvb, o + i + aoff, 1,
                                             "Subnetwork points of attachment: %u", snpa);
                    off++;
                    if (snpa) {
                        subtree3 = proto_item_add_subtree(ti, ett_bgp_mp_snpa);
                        for (/*nothing*/; snpa > 0; snpa--) {
                            proto_tree_add_text(subtree3, tvb, o + i + aoff + off, 1,
                                                "SNPA length: %u", tvb_get_guint8(tvb, o + i + aoff + off));
                            off++;
                            proto_tree_add_text(subtree3, tvb, o + i + aoff + off,
                                                tvb_get_guint8(tvb, o + i + aoff + off - 1),
                                                "SNPA (%u byte%s)", tvb_get_guint8(tvb, o + i + aoff + off - 1),
                                                plurality(tvb_get_guint8(tvb, o + i + aoff + off - 1), "", "s"));
                            off += tvb_get_guint8(tvb, o + i + aoff + off - 1);
                        }
                    }
                    tlen -= off;
                    aoff += off;

                    ti = proto_tree_add_text(subtree2, tvb, o + i + aoff, tlen,
                                             "Network layer reachability information (%u byte%s)",
                                             tlen, plurality(tlen, "", "s"));
                    if (tlen)  {
                        subtree3 = proto_item_add_subtree(ti,ett_bgp_mp_reach_nlri);
                        if (af != AFNUM_INET && af != AFNUM_INET6 && af != AFNUM_L2VPN) {
                            proto_tree_add_text(subtree3, tvb, o + i + aoff,
                                                tlen, "Unknown Address Family");
                        } else {
                            while (tlen > 0) {
                                advance = decode_prefix_MP(subtree3,
                                                           hf_bgp_mp_reach_nlri_ipv4_prefix,
                                                           -1,
                                                           af, saf,
                                                           tvb, o + i + aoff, "MP Reach NLRI");
                                if (advance < 0)
                                    break;
                                tlen -= advance;
                                aoff += advance;
                            }
                        }
                    }
                    aoff = aoff_save;
                    break;
                case BGPTYPE_MP_UNREACH_NLRI:
                    af = tvb_get_ntohs(tvb, o + i + aoff);
                    proto_tree_add_text(subtree2, tvb, o + i + aoff, 2,
                                        "Address family: %s (%u)",
                                        val_to_str_const(af, afn_vals, "Unknown"), af);
                    saf = tvb_get_guint8(tvb, o + i + aoff + 2) ;
                    proto_tree_add_text(subtree2, tvb, o + i + aoff + 2, 1,
                                        "Subsequent address family identifier: %s (%u)",
                                        val_to_str_const(saf, bgpattr_nlri_safi, saf >= 128 ? "Vendor specific" : "Unknown"),
                                        saf);
                    ti = proto_tree_add_text(subtree2, tvb, o + i + aoff + 3,
                                             tlen - 3, "Withdrawn routes (%u byte%s)", tlen - 3,
                                             plurality(tlen - 3, "", "s"));

                    aoff_save = aoff;
                    tlen -= 3;
                    aoff += 3;
                    if (tlen > 0) {
                        subtree3 = proto_item_add_subtree(ti,ett_bgp_mp_unreach_nlri);

                        while (tlen > 0) {
                            advance = decode_prefix_MP(subtree3,
                                                       hf_bgp_mp_unreach_nlri_ipv4_prefix,
                                                       -1,
                                                       af, saf,
                                                       tvb, o + i + aoff, "MP Unreach NLRI");
                            if (advance < 0)
                                break;
                            tlen -= advance;
                            aoff += advance;
                        }
                    }
                    aoff = aoff_save;
                    break;
                case BGPTYPE_CLUSTER_LIST:
                    if (tlen % 4 != 0) {
                        proto_tree_add_text(subtree2, tvb, o + i + aoff, tlen,
                                            "Cluster list (invalid): %u byte%s", tlen,
                                            plurality(tlen, "", "s"));
                        break;
                    }

                    ti = proto_tree_add_text(subtree2, tvb, o + i + aoff, tlen,
                                             "Cluster list: %s", cluster_list_emstr ? cluster_list_emstr->str : "<none>");
                    cluster_list_tree = proto_item_add_subtree(ti,
                                                               ett_bgp_cluster_list);

                    /* (o + i + aoff) =
                       (o + current attribute + aoff bytes to first tuple) */
                    q = o + i + aoff;
                    end = q + tlen;

                    /* snarf each cluster identifier */
                    while (q < end) {
                        proto_tree_add_item(cluster_list_tree, hf_bgp_cluster_list,
                                            tvb, q - 3 + aoff, 4, ENC_NA);
                        q += 4;
                    }

                    break;
                case BGPTYPE_EXTENDED_COMMUNITY:
                    if (tlen %8 != 0) {
                        proto_tree_add_text(subtree3, tvb, o + i + aoff, tlen, "Extended community (invalid) : %u byte%s", tlen,
                                            plurality(tlen, "", "s"));
                    } else {
                        q = o + i + aoff ;
                        end = o + i + aoff + tlen ;
                        ti = proto_tree_add_text(subtree2,tvb,q,tlen, "Carried Extended communities");
                        subtree3 = proto_item_add_subtree(ti,ett_bgp_extended_communities);

                        while (q < end) {
                            ext_com8 = tvb_get_guint8(tvb,q); /* handle regular types (8 bit) */
                            ext_com  = tvb_get_ntohs(tvb,q);  /* handle extended length types (16 bit) */
                            ep_strbuf_printf(junk_emstr, "%s", val_to_str(ext_com8,bgpext_com8_type,"Unknown %d"));
                            is_regular_type = FALSE;
                            is_extended_type = FALSE;
                            /* handle regular types (8 bit) */
                            switch (ext_com8) {
                                case BGP_EXT_COM_QOS_MARK_T:
                                case BGP_EXT_COM_QOS_MARK_NT:
                                    is_regular_type = TRUE;
                                    ti = proto_tree_add_text(subtree3,tvb,q,8, "%s",junk_emstr->str);

                                    subtree4 = proto_item_add_subtree(ti,ett_bgp_extended_communities);
                                    proto_tree_add_text(subtree4, tvb, q, 1,
                                                             "Type: 0x%02x", tvb_get_guint8(tvb,q));
                                    ti = proto_tree_add_item(subtree4, hf_bgp_ext_com_qos_flags, tvb, q+1, 1, ENC_BIG_ENDIAN);
                                    subtree5 = proto_item_add_subtree(ti,ett_bgp_ext_com_flags);
                                    /* add flag bitfield */
                                    proto_tree_add_item(subtree5, hf_bgp_ext_com_qos_flags_remarking, tvb, q+1, 1, ENC_BIG_ENDIAN);
                                    proto_tree_add_item(subtree5, hf_bgp_ext_com_qos_flags_ignore_remarking, tvb, q+1, 1, ENC_BIG_ENDIAN);
                                    proto_tree_add_item(subtree5, hf_bgp_ext_com_qos_flags_agg_marking, tvb, q+1, 1, ENC_BIG_ENDIAN);

                                    proto_tree_add_item(subtree4, hf_bgp_ext_com_qos_set_number, tvb, q+2, 1, ENC_BIG_ENDIAN);
                                    proto_tree_add_item(subtree4, hf_bgp_ext_com_qos_tech_type, tvb, q+3, 1, ENC_BIG_ENDIAN);
                                    proto_tree_add_item(subtree4, hf_bgp_ext_com_qos_marking_o, tvb, q+4, 2, ENC_BIG_ENDIAN);
                                    proto_tree_add_item(subtree4, hf_bgp_ext_com_qos_marking_a, tvb, q+6, 1, ENC_BIG_ENDIAN);
                                    proto_tree_add_item(subtree4, hf_bgp_ext_com_qos_default_to_zero, tvb, q+7, 1, ENC_BIG_ENDIAN);
                                    break;
                                case BGP_EXT_COM_COS_CAP_T:
                                    is_regular_type = TRUE;
                                    ti = proto_tree_add_text(subtree3,tvb,q,8, "%s",junk_emstr->str);

                                    subtree4 = proto_item_add_subtree(ti,ett_bgp_extended_communities);
                                    proto_tree_add_text(subtree4, tvb, q, 1,
                                                        "Type: 0x%02x", tvb_get_guint8(tvb,q));
                                    ti = proto_tree_add_item(subtree4, hf_bgp_ext_com_cos_flags, tvb, q+1, 1, ENC_BIG_ENDIAN);
                                    subtree5 = proto_item_add_subtree(ti,ett_bgp_ext_com_flags);
                                    /* add flag bitfield */
                                    proto_tree_add_item(subtree5, hf_bgp_ext_com_cos_flags_be, tvb, q+1, 1, ENC_BIG_ENDIAN);
                                    proto_tree_add_item(subtree5, hf_bgp_ext_com_cos_flags_ef, tvb, q+1, 1, ENC_BIG_ENDIAN);
                                    proto_tree_add_item(subtree5, hf_bgp_ext_com_cos_flags_af, tvb, q+1, 1, ENC_BIG_ENDIAN);
                                    proto_tree_add_item(subtree5, hf_bgp_ext_com_cos_flags_le, tvb, q+1, 1, ENC_BIG_ENDIAN);
                                    proto_tree_add_text(subtree4, tvb, q+2, 1,
                                                        "Flags byte 2..7 : 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x",
                                                             tvb_get_guint8(tvb,q+2),tvb_get_guint8(tvb,q+3),tvb_get_guint8(tvb,q+4),
                                                             tvb_get_guint8(tvb,q+5),tvb_get_guint8(tvb,q+6),tvb_get_guint8(tvb,q+7));
                                    break;
                            } /* switch (ext_com8) */

                            if (!is_regular_type) {
                                ep_strbuf_printf(junk_emstr, "%s", val_to_str(ext_com,bgpext_com_type,"Unknown %d"));

                                /* handle extended length types (16 bit) */
                                switch (ext_com) {
                                    case BGP_EXT_COM_RT_0:
                                    case BGP_EXT_COM_RO_0:
                                        is_extended_type = TRUE;
                                        ep_strbuf_append_printf(junk_emstr, ": %u%s%d",
                                                                tvb_get_ntohs(tvb,q+2),":",tvb_get_ntohl(tvb,q+4));
                                        proto_tree_add_text(subtree3,tvb,q,8, "%s",junk_emstr->str);
                                        break ;
                                    case BGP_EXT_COM_RT_1:
                                    case BGP_EXT_COM_RO_1:
                                        is_extended_type = TRUE;
                                        ipaddr = tvb_get_ipv4(tvb,q+2);
                                        ep_strbuf_append_printf(junk_emstr, ": %s%s%u",
                                                                ip_to_str((guint8 *)&ipaddr),":",tvb_get_ntohs(tvb,q+6));
                                        proto_tree_add_text(subtree3,tvb,q,8, "%s",junk_emstr->str);
                                        break;
                                    case BGP_EXT_COM_RT_2:
                                    case BGP_EXT_COM_RO_2:
                                        is_extended_type = TRUE;
                                        ep_strbuf_append_printf(junk_emstr, ": %u.%u:%u",
                                                                tvb_get_ntohs(tvb,q+2),tvb_get_ntohs(tvb,q+4) ,tvb_get_ntohs(tvb,q+6));
                                        proto_tree_add_text(subtree3,tvb,q,8, "%s",junk_emstr->str);
                                        break;
                                    case BGP_EXT_COM_VPN_ORIGIN:
                                    case BGP_EXT_COM_OSPF_RID:
                                        is_extended_type = TRUE;
                                        ipaddr = tvb_get_ipv4(tvb,q+2);
                                        ep_strbuf_append_printf(junk_emstr, ": %s", ip_to_str((guint8 *)&ipaddr));
                                        proto_tree_add_text(subtree3,tvb,q,8, "%s",junk_emstr->str);
                                        break;
                                    case BGP_EXT_COM_OSPF_RTYPE:
                                        is_extended_type = TRUE;
                                        ipaddr = tvb_get_ipv4(tvb,q+2);
                                        ep_strbuf_append_printf(junk_emstr, ": Area: %s, Type: %s", ip_to_str((guint8 *)&ipaddr),
                                                                val_to_str_const(tvb_get_guint8(tvb,q+6),bgpext_ospf_rtype,"Unknown"));
                                        /* print OSPF Metric type if selected */
                                        /* always print E2 even if not external route -- receiving router should ignore */
                                        if ( (tvb_get_guint8(tvb,q+7)) & BGP_OSPF_RTYPE_METRIC_TYPE ) {
                                            ep_strbuf_append(junk_emstr, " E2");
                                        } else if ((tvb_get_guint8(tvb,q+6)==BGP_OSPF_RTYPE_EXT) || (tvb_get_guint8(tvb,q+6)==BGP_OSPF_RTYPE_NSSA)) {
                                            ep_strbuf_append(junk_emstr, " E1");
                                        } else {
                                            ep_strbuf_append(junk_emstr, ", no options");
                                        }
                                        proto_tree_add_text(subtree3,tvb,q,8, "%s",junk_emstr->str);
                                        break;
                                    case BGP_EXT_COM_LINKBAND:
                                        is_extended_type = TRUE;
                                        as_num = tvb_get_ntohs(tvb,q+2);
                                        linkband = tvb_get_ntohieee_float(tvb,q+4);
                                        ep_strbuf_append_printf(junk_emstr, ": ASN %u, %.3f Mbps", as_num,linkband*8/1000000);
                                        proto_tree_add_text(subtree3,tvb,q,8, "%s",junk_emstr->str);
                                        break;
                                    case BGP_EXT_COM_L2INFO:
                                        is_extended_type = TRUE;
                                        ep_strbuf_append_printf(junk_emstr,
                                                                ": %s, Control Flags: %s%s%s%s%s, MTU: %u byte%s",
                                                                val_to_str_const(tvb_get_guint8(tvb,q+2),bgp_l2vpn_encaps,"Unknown"),
                                                                tvb_get_guint8(tvb,q+3) ? "" : "none",
                                                                tvb_get_ntohs(tvb,q+3)&0x08 ? "Q" : "",
                                                                tvb_get_ntohs(tvb,q+3)&0x04 ? "F" : "",
                                                                tvb_get_ntohs(tvb,q+3)&0x02 ? "C" : "",
                                                                tvb_get_ntohs(tvb,q+3)&0x01 ? "S" : "",
                                                                tvb_get_ntohs(tvb,q+4),
                                                                plurality(tvb_get_ntohs(tvb,q+4), "", "s"));
                                        ti = proto_tree_add_text(subtree3,tvb,q,8, "%s",junk_emstr->str);

                                        subtree4 = proto_item_add_subtree(ti,ett_bgp_extended_communities);
                                        proto_tree_add_text(subtree4,tvb,q+2,1, "Encapsulation: %s",
                                                            val_to_str_const(tvb_get_guint8(tvb,q+2),bgp_l2vpn_encaps,"Unknown"));
                                        proto_tree_add_text(subtree4,tvb,q+3,1, "Control Flags: %s%sControl Word %s required, Sequenced delivery %s required",
                                                            tvb_get_ntohs(tvb,q+3)&0x08 ? "Q flag (Reserved) set" : "",
                                                            tvb_get_ntohs(tvb,q+3)&0x04 ? "F flag (reserved) set" : "",
                                                            tvb_get_ntohs(tvb,q+3)&0x02 ? "is" : "not",
                                                            tvb_get_ntohs(tvb,q+3)&0x01 ? "is" : "not");
                                        proto_tree_add_text(subtree4,tvb,q+4,2, "MTU: %u byte%s",
                                                            tvb_get_ntohs(tvb,q+4),
                                                            plurality(tvb_get_ntohs(tvb,q+4), "", "s"));
                                        break;
                                } /* switch (ext_com) */
                            }
                            if (!is_regular_type && !is_extended_type)
                                proto_tree_add_text(subtree3,tvb,q,8, "%s","Unknown");
                            q = q + 8;
                        }
                    }
                    break;
                case BGPTYPE_SAFI_SPECIFIC_ATTR:
                    q = o + i + aoff;
                    end = o + i + aoff + tlen ;

                    while(q < end) {
                        ssa_type = tvb_get_ntohs(tvb, q) & BGP_SSA_TYPE;
                        ssa_len = tvb_get_ntohs(tvb, q + 2);

                        ti = proto_tree_add_text(subtree2, tvb, q, MIN(ssa_len + 4, end - q),
                                                 "%s Information",
                                                 val_to_str_const(ssa_type, bgp_ssa_type, "Unknown SSA"));
                        subtree3 = proto_item_add_subtree(ti, ett_bgp_ssa);

                        proto_tree_add_item(subtree3, hf_bgp_ssa_t, tvb,
                                            q, 1, ENC_BIG_ENDIAN);
                        hidden_item = proto_tree_add_item(subtree3, hf_bgp_ssa_type, tvb,
                                                          q, 2, ENC_BIG_ENDIAN);
                        PROTO_ITEM_SET_HIDDEN(hidden_item);
                        proto_tree_add_text(subtree3, tvb, q, 2,
                                            "Type: %s", val_to_str_const(ssa_type, bgp_ssa_type, "Unknown"));
                        if ((ssa_len == 0) || (q + ssa_len > end)) {
                            proto_tree_add_text(subtree3, tvb, q + 2, end - q - 2,
                                                "Invalid Length of %u", ssa_len);
                            break;
                        }
                        proto_tree_add_item(subtree3, hf_bgp_ssa_len, tvb,
                                            q + 2, 2, ENC_BIG_ENDIAN);

                        switch (ssa_type) {
                            case BGP_SSA_L2TPv3:
                                proto_tree_add_item(subtree3, hf_bgp_ssa_l2tpv3_pref, tvb,
                                                    q + 4, 2, ENC_BIG_ENDIAN);

                                ti = proto_tree_add_text(subtree3, tvb, q + 6, 1, "Flags");
                                subtree4 = proto_item_add_subtree(ti, ett_bgp_ssa_subtree) ;
                                proto_tree_add_item(subtree4, hf_bgp_ssa_l2tpv3_s, tvb,
                                                    q + 6, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item(subtree4, hf_bgp_ssa_l2tpv3_unused, tvb,
                                                    q + 6, 1, ENC_BIG_ENDIAN);

                                ssa_v3_len = tvb_get_guint8(tvb, q + 7);
                                if (ssa_v3_len + 8 == ssa_len){
                                    proto_tree_add_item(subtree3, hf_bgp_ssa_l2tpv3_cookie_len, tvb,
                                                        q + 7, 1, ENC_BIG_ENDIAN);
                                } else {
                                    proto_tree_add_text(subtree3, tvb, q + 7, 1,
                                                        "Invalid Cookie Length of %u", ssa_v3_len);
                                    q += ssa_len + 4; /* 4 from type and length */
                                    break;
                                }
                                proto_tree_add_item(subtree3, hf_bgp_ssa_l2tpv3_session_id, tvb,
                                                    q + 8, 4, ENC_BIG_ENDIAN);
                                if (ssa_v3_len)
                                    proto_tree_add_item(subtree3, hf_bgp_ssa_l2tpv3_cookie, tvb,
                                                        q + 12, ssa_v3_len, ENC_NA);
                                q += ssa_len + 4; /* 4 from type and length */
                                break;
                            case BGP_SSA_mGRE:
                            case BGP_SSA_IPSec:
                            case BGP_SSA_MPLS:
                            default:
                                proto_tree_add_item(subtree3, hf_bgp_ssa_value, tvb,
                                                    q + 4, ssa_len, ENC_NA);
                                q += ssa_len + 4; /* 4 from type and length */
                                break;
                            case BGP_SSA_L2TPv3_IN_IPSec:
                            case BGP_SSA_mGRE_IN_IPSec:
                                /* These contain BGP_SSA_IPSec and BGP_SSA_L2TPv3/BGP_SSA_mGRE */
                                q += 4; /* 4 from type and length */
                                break;
                        } /* switch (bgpa.bgpa_type) */
                    }
                    break;
                case BGPTYPE_TUNNEL_ENCAPS_ATTR:
                    q = o + i + aoff;
                    end = o + i + aoff + tlen;

                    ti = proto_tree_add_text(subtree2, tvb, q, tlen, "TLV Encodings");
                    subtree3 = proto_item_add_subtree(ti, ett_bgp_tunnel_tlv);

                     while (q < end) {
                        encaps_tunnel_type = tvb_get_ntohs(tvb, q);
                        encaps_tunnel_len = tvb_get_ntohs(tvb, q + 2);

                        ti = proto_tree_add_text(subtree3, tvb, q, encaps_tunnel_len + 4, "%s (%u bytes)", val_to_str_const(encaps_tunnel_type, tunnel_type, "Unknown"), encaps_tunnel_len + 4);
                        subtree4 = proto_item_add_subtree(ti, ett_bgp_tunnel_tlv_subtree);

                        proto_tree_add_item(subtree4, hf_bgp_encaps_tunnel_tlv_type, tvb, q, 2, ENC_NA);
                        proto_tree_add_item(subtree4, hf_bgp_encaps_tunnel_tlv_len, tvb, q + 2, 2, ENC_NA);

                        ti = proto_tree_add_text(subtree4, tvb, q + 4, encaps_tunnel_len, "Sub-TLV Encodings");
                        subtree5 = proto_item_add_subtree(ti, ett_bgp_tunnel_subtlv);

                        q += 4;
                        j = q + encaps_tunnel_len;
                        while ( q < j ) {
                            encaps_tunnel_subtype = tvb_get_guint8(tvb, q);
                            encaps_tunnel_sublen = tvb_get_guint8(tvb, q + 1);

                            ti = proto_tree_add_text(subtree5, tvb, q, encaps_tunnel_sublen + 2, "%s (%u bytes)", val_to_str_const(encaps_tunnel_subtype, subtlv_type, "Unknown"), encaps_tunnel_sublen + 2);
                            subtree6 = proto_item_add_subtree(ti, ett_bgp_tunnel_tlv_subtree);

                            proto_tree_add_item(subtree6, hf_bgp_encaps_tunnel_subtlv_type, tvb, q, 1, ENC_NA);
                            proto_tree_add_item(subtree6, hf_bgp_encaps_tunnel_subtlv_len, tvb, q + 1, 1, ENC_NA);

                            switch (encaps_tunnel_subtype) {
                                case TUNNEL_SUBTLV_ENCAPSULATION:
                                    if (encaps_tunnel_type == TUNNEL_TYPE_L2TP_OVER_IP) {
                                        proto_tree_add_text(subtree6, tvb, q + 2, 4, "Session ID: %u", tvb_get_letohl(tvb, q + 2));
                                        proto_tree_add_text(subtree6, tvb, q + 6, encaps_tunnel_sublen - 4, "Cookie: %s", tvb_bytes_to_str(tvb, q + 6, encaps_tunnel_sublen - 4));
                                    } else if (encaps_tunnel_type == TUNNEL_TYPE_GRE) {
                                        proto_tree_add_text(subtree6, tvb, q + 2, encaps_tunnel_sublen, "GRE key: %x", tvb_get_letohl(tvb, q + 2));
                                    }
                                    break;
                                case TUNNEL_SUBTLV_PROTO_TYPE:
                                    proto_tree_add_text(subtree6, tvb, q + 2, encaps_tunnel_sublen, "Protocol type: %s (0x%x)", val_to_str_const(tvb_get_ntohs(tvb, q + 2), etype_vals, "Unknown"), tvb_get_ntohs(tvb, q + 2));
                                    break;
                                case TUNNEL_SUBTLV_COLOR:
                                    proto_tree_add_text(subtree6, tvb, q + 6, encaps_tunnel_sublen - 4, "Color value: %u", tvb_get_letohl(tvb, q + 6));
                                    break;
                                case TUNNEL_SUBTLV_LOAD_BALANCE:
                                    if (encaps_tunnel_type == TUNNEL_TYPE_L2TP_OVER_IP || encaps_tunnel_type == TUNNEL_TYPE_GRE) {
                                        proto_tree_add_text(subtree6, tvb, q + 2, encaps_tunnel_sublen, "Load-balancing block length: %u", tvb_get_ntohs(tvb, q + 2));
                                    }
                                    break;
                                default:
                                    break;
                            } /* switch (encaps_tunnel_subtype) */

                            q += 2 + encaps_tunnel_sublen; /* type and length + length of value */
                        }

                    }

                    break;

                default:
                    proto_tree_add_text(subtree2, tvb, o + i + aoff, tlen,
                                        "Unknown (%u byte%s)", tlen, plurality(tlen, "", "s"));
                    break;
            } /* switch (bgpa.bgpa_type) */ /* end of second switch */

            i += alen + aoff;
        }

        o += 2 + len;

        /* NLRI */
        len = hlen - o;

        /* parse prefixes */
        if (len > 0) {
            ti = proto_tree_add_text(tree, tvb, o, len,
                   "Network layer reachability information: %u byte%s", len,
                   plurality(len, "", "s"));
            subtree = proto_item_add_subtree(ti, ett_bgp_nlri);
            end = o + len;
            /* Heuristic to detect if IPv4 prefix are using Path Identifiers */
            if( detect_add_path_prefix4(tvb, o, end) ) {
                /* IPv4 prefixes with Path Id */
                while (o < end) {
                    i = decode_path_prefix4(subtree, hf_bgp_nlri_path_id, hf_bgp_nlri_prefix, tvb, o,
                                            "NLRI");
                    if (i < 0)
                       return;
                    o += i;
                }
            } else {
                /* Standard prefixes */
                while (o < end) {
                    i = decode_prefix4(subtree, hf_bgp_nlri_prefix, tvb, o, 0,
                           "NLRI");
                    if (i < 0)
                        return;
                    o += i;
                }
            }
        }
    }
}

/*
 * Dissect a BGP NOTIFICATION message.
 */
static void
dissect_bgp_notification(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo)
{
    int                     hlen;   /* message length           */
    int                     offset;
    guint                   major_error;
    proto_item              *ti;

    hlen =  tvb_get_ntohs(tvb, BGP_MARKER_SIZE);
    offset = BGP_MARKER_SIZE + 2 + 1;


    /* print error code */
    proto_tree_add_item(tree, hf_bgp_notify_major_error, tvb, offset, 1, ENC_NA);
    major_error = tvb_get_guint8(tvb, offset);
    offset += 1;

    switch(major_error){
        case BGP_MAJOR_ERROR_MSG_HDR:
            proto_tree_add_item(tree, hf_bgp_notify_minor_msg_hdr, tvb, offset, 1, ENC_NA);
        break;
        case BGP_MAJOR_ERROR_OPEN_MSG:
            proto_tree_add_item(tree, hf_bgp_notify_minor_open_msg, tvb, offset, 1, ENC_NA);
        break;
        case BGP_MAJOR_ERROR_UPDATE_MSG:
            proto_tree_add_item(tree,hf_bgp_notify_minor_update_msg, tvb, offset, 1, ENC_NA);
        break;
        case BGP_MAJOR_ERROR_HT_EXPIRED:
            proto_tree_add_item(tree, hf_bgp_notify_minor_ht_expired, tvb, offset,  1, ENC_NA);
        break;
        case BGP_MAJOR_ERROR_STATE_MACHINE:
            proto_tree_add_item(tree, hf_bgp_notify_minor_state_machine, tvb, offset, 1, ENC_NA);
        break;
        case BGP_MAJOR_ERROR_CEASE:
            proto_tree_add_item(tree, hf_bgp_notify_minor_cease, tvb, offset, 1, ENC_NA);
        break;
        case BGP_MAJOR_ERROR_CAP_MSG:
            proto_tree_add_item(tree, hf_bgp_notify_minor_cap_msg, tvb, offset, 1, ENC_NA);
        break;
        default:
            ti = proto_tree_add_item(tree, hf_bgp_notify_minor_unknown, tvb, offset, 1, ENC_NA);
            expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_NOTE, "Unknown notification error (%d)",major_error);
        break;
    }
    offset += 1;

    /* only print if there is optional data */
    if (hlen > BGP_MIN_NOTIFICATION_MSG_SIZE) {
        proto_tree_add_item(tree, hf_bgp_notify_data, tvb, offset, hlen - BGP_MIN_NOTIFICATION_MSG_SIZE, ENC_NA);
    }
}

/*
 * Dissect a BGP ROUTE-REFRESH message.
 */
static void
dissect_bgp_route_refresh(tvbuff_t *tvb, proto_tree *tree)
{
    int             p;         /* tvb offset counter    */
    int             pend;       /* end of list of entries for one orf type */
    guint16         hlen;       /* tvb RR msg length */
    proto_item      *ti;        /* tree item             */
    proto_item      *ti1;       /* tree item             */
    proto_tree      *subtree;   /* tree for orf   */
    proto_tree      *subtree1;  /* tree for orf entry */
    guint8          orftype;    /* ORF Type */
    guint8          orfwhen;    /* ORF flag: immediate, defer */
    guint16         orflen;     /* ORF len */
    guint8          entryflag;  /* ORF Entry flag: action(add,del,delall) match(permit,deny) */
    guint32         entryseq;   /* ORF Entry sequence number */
    int             entrylen;   /* ORF Entry length */
    guint8          pfx_ge;     /* ORF PrefixList mask lower bound */
    guint8          pfx_le;     /* ORF PrefixList mask upper bound */
    int             advance;    /* tmp                      */


/*
example 1
 00 1c 05       hlen=28
 00 01 00 01    afi,safi= ipv4-unicast
 02 80 00 01    defer, prefix-orf, len=1
    80            removeall
example 2
 00 25 05       hlen=37
 00 01 00 01    afi,saif= ipv4-unicast
 01 80 00 0a    immediate, prefix-orf, len=10
    00            add
    00 00 00 05   seqno = 5
    12            ge = 18
    18            le = 24
    10 07 02      prefix = 7.2.0.0/16
*/
    if (!tree)
        return;

    hlen = tvb_get_ntohs(tvb, BGP_MARKER_SIZE);
    p = BGP_HEADER_SIZE;

    /* AFI */
    proto_tree_add_item(tree, hf_bgp_route_refresh_afi, tvb, p, 2, ENC_BIG_ENDIAN);
    p += 2;

    /*  Subtype in draft-ietf-idr-bgp-enhanced-route-refresh-02 (for Enhanced Route Refresh Capability) before Reserved*/
    proto_tree_add_item(tree, hf_bgp_route_refresh_subtype, tvb, p, 1, ENC_BIG_ENDIAN);
    p++;

    /* SAFI */
    proto_tree_add_item(tree, hf_bgp_route_refresh_safi, tvb, p, 1, ENC_BIG_ENDIAN);
    p++;

    if ( hlen == BGP_HEADER_SIZE + 4 )
        return;
    while (p < hlen) {
        /* ORF type */
        orfwhen = tvb_get_guint8(tvb, p);
        orftype = tvb_get_guint8(tvb, p+1);
        orflen = tvb_get_ntohs(tvb, p+2);
        ti = proto_tree_add_text(tree, tvb, p , orflen + 4 , "ORF information (%u bytes)", orflen + 4);
        subtree = proto_item_add_subtree(ti, ett_bgp_orf);
        proto_tree_add_text(subtree, tvb, p , 1, "ORF flag: %s", val_to_str_const(orfwhen, orf_when_vals,"UNKNOWN"));
        proto_tree_add_text(subtree, tvb, p+1 , 1, "ORF type: %s", val_to_str_const(orftype, orf_type_vals,"UNKNOWN"));
        proto_tree_add_text(subtree, tvb, p+2 , 2, "ORF len: %u byte%s", orflen, plurality(orflen, "", "s"));
        p += 4;

        if (orftype != BGP_ORF_PREFIX_CISCO) {
            proto_tree_add_text(subtree, tvb, p, orflen,
                    "ORFEntry-Unknown (%u bytes)", orflen);
            p += orflen;
            continue;
        }
        pend = p + orflen;
        while (p < pend) {
            entryflag = tvb_get_guint8(tvb, p);
            if ((entryflag & BGP_ORF_ACTION) == BGP_ORF_REMOVEALL) {
                ti1 = proto_tree_add_text(subtree, tvb, p, 1,
                        "ORFEntry-PrefixList (1 byte)");
                subtree1 = proto_item_add_subtree(ti1, ett_bgp_orf_entry);
                proto_tree_add_text(subtree1, tvb, p , 1, "RemoveAll");
                p++;
            } else {
                ti1 = proto_tree_add_text(subtree, tvb, p, -1,
                        "ORFEntry-PrefixList");
                subtree1 = proto_item_add_subtree(ti1, ett_bgp_orf_entry);
                proto_tree_add_text(subtree1, tvb, p, 1,
                        "ACTION: %s MATCH: %s",
                        val_to_str_const(entryflag&BGP_ORF_ACTION,
                            orf_entry_action_vals, "UNKNOWN"),
                        val_to_str_const(entryflag&BGP_ORF_MATCH,
                            orf_entry_match_vals, "UNKNOWN"));
                p++;
                entryseq = tvb_get_ntohl(tvb, p);
                proto_tree_add_text(subtree1, tvb, p, 4,
                        "Entry Sequence No: %u", entryseq);
                p += 4;
                pfx_ge = tvb_get_guint8(tvb, p);
                proto_tree_add_text(subtree1, tvb, p, 1,
                        "PrefixMask length lower bound: %u", pfx_ge);
                p++;
                pfx_le = tvb_get_guint8(tvb, p);
                proto_tree_add_text(subtree1, tvb, p, 1,
                        "PrefixMask length upper bound: %u", pfx_le);
                p++;

                advance = decode_prefix4(subtree1, -1, tvb, p, 0, "ORF");
                if (advance < 0)
                        break;
                entrylen = 7 + 1 + advance;

                proto_item_append_text(ti1, " (%u bytes)", entrylen);
                proto_item_set_len(ti1, entrylen);
                p += advance;
            }
        }
    }
}

/*
 * Dissect a BGP CAPABILITY message.
 */
static void
dissect_bgp_capability(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo)
{
    int offset = 0;
    int mend;

    mend = offset + tvb_get_ntohs(tvb, offset + BGP_MARKER_SIZE);
    offset += BGP_HEADER_SIZE;
    /* step through all of the capabilities */
    while (offset < mend) {
        offset = dissect_bgp_capability_item(tvb, tree, pinfo, offset, TRUE);
    }
}

static void
dissect_bgp_pdu(tvbuff_t *volatile tvb, packet_info *pinfo, proto_tree *tree,
                gboolean first)
{
    guint16       bgp_len;          /* Message length             */
    guint8        bgp_type;         /* Message type               */
    const char    *typ;             /* Message type (string)      */
    proto_item    *ti_len = NULL;   /* length item                */
    proto_tree    *bgp_tree = NULL; /* BGP packet tree            */

    bgp_len = tvb_get_ntohs(tvb, BGP_MARKER_SIZE);
    bgp_type = tvb_get_guint8(tvb, BGP_MARKER_SIZE + 2);
    typ = val_to_str(bgp_type, bgptypevals, "Unknown message type (0x%02x)");

    if (first)
        col_add_str(pinfo->cinfo, COL_INFO, typ);
    else
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", typ);

    if (tree) {
        proto_item *ti;
        ti = proto_tree_add_item(tree, proto_bgp, tvb, 0, -1, ENC_NA);
        proto_item_append_text(ti, " - %s", typ);

        /* add a different tree for each message type */
        switch (bgp_type) {
            case BGP_OPEN:
                bgp_tree = proto_item_add_subtree(ti, ett_bgp_open);
                break;
            case BGP_UPDATE:
                bgp_tree = proto_item_add_subtree(ti, ett_bgp_update);
                break;
            case BGP_NOTIFICATION:
                bgp_tree = proto_item_add_subtree(ti, ett_bgp_notification);
                break;
            case BGP_KEEPALIVE:
                bgp_tree = proto_item_add_subtree(ti, ett_bgp);
                break;
            case BGP_ROUTE_REFRESH_CISCO:
            case BGP_ROUTE_REFRESH:
                bgp_tree = proto_item_add_subtree(ti, ett_bgp_route_refresh);
                break;
            case BGP_CAPABILITY:
                bgp_tree = proto_item_add_subtree(ti, ett_bgp_capability);
                break;
            default:
                bgp_tree = proto_item_add_subtree(ti, ett_bgp);
                break;
        }

        proto_tree_add_item(bgp_tree, hf_bgp_marker, tvb, 0, 16, ENC_NA);

        ti_len = proto_tree_add_item(bgp_tree, hf_bgp_length, tvb, 16, 2, ENC_BIG_ENDIAN);
    }

    if (bgp_len < BGP_HEADER_SIZE || bgp_len > BGP_MAX_PACKET_SIZE) {
        expert_add_info_format(pinfo, ti_len, PI_MALFORMED, PI_ERROR, "Length is invalid %u", bgp_len);
        return;
    }

    proto_tree_add_item(bgp_tree, hf_bgp_type, tvb, 16 + 2, 1, ENC_BIG_ENDIAN);

    switch (bgp_type) {
    case BGP_OPEN:
        dissect_bgp_open(tvb, bgp_tree, pinfo);
        break;
    case BGP_UPDATE:
        dissect_bgp_update(tvb, bgp_tree);
        break;
    case BGP_NOTIFICATION:
        dissect_bgp_notification(tvb, bgp_tree, pinfo);
        break;
    case BGP_KEEPALIVE:
        /* no data in KEEPALIVE messages */
        break;
    case BGP_ROUTE_REFRESH_CISCO:
    case BGP_ROUTE_REFRESH:
        dissect_bgp_route_refresh(tvb, bgp_tree);
        break;
    case BGP_CAPABILITY:
        dissect_bgp_capability(tvb, bgp_tree, pinfo);
        break;
    default:
        break;
    }
}

/*
 * Dissect a BGP packet.
 */
static void
dissect_bgp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    volatile int  offset = 0;   /* offset into the tvbuff           */
    gint          reported_length_remaining;
    guint8        bgp_marker[BGP_MARKER_SIZE];    /* Marker (should be all ones */
    static guchar marker[] = {   /* BGP message marker               */
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    proto_item    *ti;           /* tree item                        */
    proto_tree    *bgp_tree;     /* BGP packet tree                  */
    guint16       bgp_len;       /* Message length             */
    int           offset_before;
    guint         length_remaining;
    guint         length;
    volatile gboolean first = TRUE;  /* TRUE for the first BGP message in packet */
    tvbuff_t *volatile next_tvb;
    void *pd_save;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BGP");
    col_clear(pinfo->cinfo, COL_INFO);

    /*
     * Scan through the TCP payload looking for a BGP marker.
     */
    while ((reported_length_remaining = tvb_reported_length_remaining(tvb, offset))
                > 0) {
        /*
         * "reported_length_remaining" is the number of bytes of TCP payload
         * remaining.  If it's more than the length of a BGP marker,
         * we check only the number of bytes in a BGP marker.
         */
        if (reported_length_remaining > BGP_MARKER_SIZE)
            reported_length_remaining = BGP_MARKER_SIZE;

        /*
         * OK, is there a BGP marker starting at the specified offset -
         * or, at least, the beginning of a BGP marker running to the end
         * of the TCP payload?
         *
         * This will throw an exception if the frame is short; that's what
         * we want.
         */
        tvb_memcpy(tvb, bgp_marker, offset, reported_length_remaining);
        if (memcmp(bgp_marker, marker, reported_length_remaining) == 0) {
            /*
             * Yes - stop scanning and start processing BGP packets.
             */
            break;
        }

        /*
         * No - keep scanning through the tvbuff to try to find a marker.
         */
        offset++;
    }

    /*
     * If we skipped any bytes, mark it as a BGP continuation.
     */
    if (offset > 0) {
        ti = proto_tree_add_item(tree, proto_bgp, tvb, 0, -1, ENC_NA);
        bgp_tree = proto_item_add_subtree(ti, ett_bgp);

        proto_tree_add_text(bgp_tree, tvb, 0, offset, "Continuation");
    }

    /*
     * Now process the BGP packets in the TCP payload.
     *
     * XXX - perhaps "tcp_dissect_pdus()" should take a starting
     * offset, in which case we can replace the loop below with
     * a call to "tcp_dissect_pdus()".
     */
    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        /*
         * This will throw an exception if we don't have any data left.
         * That's what we want.  (See "tcp_dissect_pdus()", which is
         * similar.)
         */
        length_remaining = tvb_ensure_length_remaining(tvb, offset);

        /*
         * Can we do reassembly?
         */
        if (bgp_desegment && pinfo->can_desegment) {
            /*
             * Yes - would a BGP header starting at this offset be split
             * across segment boundaries?
             */
            if (length_remaining < BGP_HEADER_SIZE) {
                /*
                 * Yes.  Tell the TCP dissector where the data for this message
                 * starts in the data it handed us and that we need "some more
                 * data."  Don't tell it exactly how many bytes we need because
                 * if/when we ask for even more (after the header) that will
                 * break reassembly.
                 */
                pinfo->desegment_offset = offset;
                pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
                return;
            }
        }

        /*
         * Get the length and type from the BGP header.
         */
        bgp_len = tvb_get_ntohs(tvb, offset + BGP_MARKER_SIZE);
        if (bgp_len < BGP_HEADER_SIZE) {
            /*
             * The BGP length doesn't include the BGP header; report that
             * as an error.
             */
            show_reported_bounds_error(tvb, pinfo, tree);
            return;
        }

        /*
         * Can we do reassembly?
         */
        if (bgp_desegment && pinfo->can_desegment) {
            /*
             * Yes - is the PDU split across segment boundaries?
             */
            if (length_remaining < bgp_len) {
                /*
                 * Yes.  Tell the TCP dissector where the data for this
                 * message starts in the data it handed us, and how many
                 * more bytes we need, and return.
                 */
                pinfo->desegment_offset = offset;
                pinfo->desegment_len = bgp_len - length_remaining;
                return;
            }
        }

        /*
         * Construct a tvbuff containing the amount of the payload we have
         * available.  Make its reported length the amount of data in the PDU.
         *
         * XXX - if reassembly isn't enabled. the subdissector will throw a
         * BoundsError exception, rather than a ReportedBoundsError exception.
         * We really want a tvbuff where the length is "length", the reported
         * length is "plen", and the "if the snapshot length were infinite"
         * length is the minimum of the reported length of the tvbuff handed
         * to us and "plen", with a new type of exception thrown if the offset
         * is within the reported length but beyond that third length, with
         * that exception getting the "Unreassembled Packet" error.
         */
        length = length_remaining;
        if (length > bgp_len)
            length = bgp_len;
        next_tvb = tvb_new_subset(tvb, offset, length, bgp_len);

        /*
         * Dissect the PDU.
         *
         * Catch the ReportedBoundsError exception; if this particular message
         * happens to get a ReportedBoundsError exception, that doesn't mean
         * that we should stop dissecting PDUs within this frame or chunk of
         * reassembled data.
         *
         * If it gets a BoundsError, we can stop, as there's nothing more to
         * see, so we just re-throw it.
         */
        pd_save = pinfo->private_data;
        TRY {
            dissect_bgp_pdu(next_tvb, pinfo, tree, first);
        }
        CATCH(BoundsError) {
            RETHROW;
        }
        CATCH(ReportedBoundsError) {
            /*  Restore the private_data structure in case one of the
             *  called dissectors modified it (and, due to the exception,
             *  was unable to restore it).
             */
            pinfo->private_data = pd_save;

            show_reported_bounds_error(tvb, pinfo, tree);
        }
        ENDTRY;

        first = FALSE;

        /*
         * Step to the next PDU.
         * Make sure we don't overflow.
         */
        offset_before = offset;
        offset += bgp_len;
        if (offset <= offset_before)
            break;
    }
}

/*
 * Register ourselves.
 */
void
proto_register_bgp(void)
{

    static hf_register_info hf[] = {
      /* BGP Header */
      { &hf_bgp_marker,
        { "Marker", "bgp.marker", FT_BYTES, BASE_NONE,
          NULL, 0x0, "Must be set to all ones (16 Bytes)", HFILL }},
      { &hf_bgp_length,
        { "Length", "bgp.length", FT_UINT16, BASE_DEC,
          NULL, 0x0, "The total length of the message, including the header in octets", HFILL }},
      { &hf_bgp_type,
        { "Type", "bgp.type", FT_UINT8, BASE_DEC,
          VALS(bgptypevals), 0x0, "BGP message type", HFILL }},
      /* Open Message */
      { &hf_bgp_open_version,
        { "Version", "bgp.open.version", FT_UINT8, BASE_DEC,
          NULL, 0x0, "The protocol version number", HFILL }},
      { &hf_bgp_open_myas,
        { "My AS", "bgp.open.myas", FT_UINT16, BASE_DEC,
          NULL, 0x0, "The Autonomous System number of the sender", HFILL }},
      { &hf_bgp_open_holdtime,
        { "Hold Time", "bgp.open.holdtime", FT_UINT16, BASE_DEC,
          NULL, 0x0, "The number of seconds the sender proposes for Hold Time", HFILL }},
      { &hf_bgp_open_identifier,
        { "BGP Identifier", "bgp.open.identifier", FT_IPv4, BASE_NONE,
          NULL, 0x0, "The BGP Identifier of the sender", HFILL }},
      { &hf_bgp_open_opt_len,
        { "Optional Parameters Length", "bgp.open.opt.len", FT_UINT8, BASE_DEC,
          NULL, 0x0, "The total length of the Optional Parameters field in octets", HFILL }},
      { &hf_bgp_open_opt_params,
        { "Optional Parameters", "bgp.open.opt", FT_NONE, BASE_NONE,
          NULL, 0x0, "List of optional parameters", HFILL }},
      { &hf_bgp_open_opt_param,
        { "Optional Parameter", "bgp.open.opt.param", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_open_opt_param_type,
        { "Parameter Type", "bgp.open.opt.param.type", FT_UINT8, BASE_DEC,
          VALS(bgp_open_opt_vals), 0x0, "Unambiguously identifies individual parameters", HFILL }},
      { &hf_bgp_open_opt_param_len,
        { "Parameter Length", "bgp.open.opt.param.len", FT_UINT8, BASE_DEC,
          NULL, 0x0, "Length of the Parameter Value", HFILL }},
      { &hf_bgp_open_opt_param_auth,
        { "Authentification Data", "bgp.open.opt.param.auth", FT_BYTES, BASE_NONE,
          NULL, 0x0, "Deprecated", HFILL }},
      { &hf_bgp_open_opt_param_unknown,
        { "Unknown", "bgp.open.opt.param.unknown", FT_BYTES, BASE_NONE,
          NULL, 0x0, "Unknown Parameter", HFILL }},
        /* Notification error */
      { &hf_bgp_notify_major_error,
        { "Major error Code", "bgp.notify.major_error", FT_UINT8, BASE_DEC,
          VALS(bgpnotify_major), 0x0, NULL, HFILL }},
      { &hf_bgp_notify_minor_msg_hdr,
        { "Minor error Code (Message Header)", "bgp.notify.minor_error", FT_UINT8, BASE_DEC,
          VALS(bgpnotify_minor_msg_hdr), 0x0, NULL, HFILL }},
      { &hf_bgp_notify_minor_open_msg,
        { "Minor error Code (Open Message)", "bgp.notify.minor_error", FT_UINT8, BASE_DEC,
          VALS(bgpnotify_minor_open_msg), 0x0, NULL, HFILL }},
      { &hf_bgp_notify_minor_update_msg,
        { "Minor error Code (Update Message)", "bgp.notify.minor_error", FT_UINT8, BASE_DEC,
          VALS(bgpnotify_minor_update_msg), 0x0, NULL, HFILL }},
      { &hf_bgp_notify_minor_ht_expired,
        { "Minor error Code (Hold Timer Expired)", "bgp.notify.minor_error", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_notify_minor_state_machine,
        { "Minor error Code (State Machine)", "bgp.notify.minor_error", FT_UINT8, BASE_DEC,
          VALS(bgpnotify_minor_state_machine), 0x0, NULL, HFILL }},
      { &hf_bgp_notify_minor_cease,
        { "Minor error Code (Cease)", "bgp.notify.minor_error", FT_UINT8, BASE_DEC,
          VALS(bgpnotify_minor_cease), 0x0, NULL, HFILL }},
      { &hf_bgp_notify_minor_cap_msg,
        { "Minor error Code (Capability Message)", "bgp.notify.minor_error", FT_UINT8, BASE_DEC,
          VALS(bgpnotify_minor_cap_msg), 0x0, NULL, HFILL }},
      { &hf_bgp_notify_minor_unknown,
        { "Minor error Code (Unknown)", "bgp.notify.minor_error", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_notify_data,
        { "Data", "bgp.notify.minor_error", FT_BYTES, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},

        /* Route Refresh */
      { &hf_bgp_route_refresh_afi,
        { "Address family identifier (AFI)", "bgp.route_refresh.afi", FT_UINT16, BASE_DEC,
          VALS(afn_vals), 0x0, NULL, HFILL }},
      { &hf_bgp_route_refresh_subtype,
        { "Subtype", "bgp.route_refresh.subtype", FT_UINT8, BASE_DEC,
          VALS(route_refresh_subtype_vals), 0x0, NULL, HFILL }},
      { &hf_bgp_route_refresh_safi,
        { "Subsequent address family identifier (SAFI)", "bgp.route_refresh.safi", FT_UINT8, BASE_DEC,
          VALS(bgpattr_nlri_safi), 0x0, NULL, HFILL }},

        /* Capability */
      { &hf_bgp_cap,
        { "Capability", "bgp.cap", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_cap_type,
        { "Type", "bgp.cap.type", FT_UINT8, BASE_DEC,
          VALS(capability_vals), 0x0, NULL, HFILL }},
      { &hf_bgp_cap_length,
        { "Length", "bgp.cap.length", FT_UINT8, BASE_DEC,
         NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_cap_action,
        { "Action", "bgp.cap.action", FT_UINT8, BASE_DEC,
          VALS(bgpcap_action), 0x0, NULL, HFILL }},
      { &hf_bgp_cap_unknown,
        { "Unknown", "bgp.cap.unknown", FT_BYTES, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_cap_reserved,
        { "Reserved", "bgp.cap.reserved", FT_BYTES, BASE_NONE,
          NULL, 0x0, "Must be Zero", HFILL }},
      { &hf_bgp_cap_mp_afi,
        { "AFI", "bgp.cap.mp.afi", FT_UINT16, BASE_DEC,
          VALS(afn_vals), 0x0, NULL, HFILL }},
      { &hf_bgp_cap_mp_safi,
        { "SAFI", "bgp.cap.mp.safi", FT_UINT8, BASE_DEC,
          VALS(bgpattr_nlri_safi), 0x0, NULL, HFILL }},
      { &hf_bgp_cap_gr_timers,
        { "Restart Timers", "bgp.cap.gr.timers", FT_UINT16, BASE_HEX,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_cap_gr_timers_restart_flag,
        { "Restart", "bgp.cap.gr.timers.restart_flag", FT_BOOLEAN, 16,
          TFS(&tfs_yes_no), 0x8000, NULL, HFILL }},
      { &hf_bgp_cap_gr_timers_restart_time,
        { "Time", "bgp.cap.gr.timers.restart_time", FT_UINT16, BASE_DEC,
          NULL, 0x0FFF, "in us", HFILL }},
      { &hf_bgp_cap_gr_afi,
        { "AFI", "bgp.cap.gr.afi", FT_UINT16, BASE_DEC,
          VALS(afn_vals), 0x0, NULL, HFILL }},
      { &hf_bgp_cap_gr_safi,
        { "SAFI", "bgp.cap.gr.safi", FT_UINT8, BASE_DEC,
          VALS(bgpattr_nlri_safi), 0x0, NULL, HFILL }},
      { &hf_bgp_cap_gr_flag,
        { "Flag", "bgp.cap.gr.flag", FT_UINT8, BASE_HEX,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_cap_gr_flag_pfs,
        { "Preserve forwarding state", "bgp.cap.gr.flag.pfs", FT_BOOLEAN, 8,
          TFS(&tfs_yes_no), 0x80, NULL, HFILL }},
      { &hf_bgp_cap_4as,
        { "AS Number", "bgp.cap.4as", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_cap_dc,
        { "Capability Dynamic", "bgp.cap.dc", FT_UINT8, BASE_DEC,
          VALS(capability_vals), 0x0, NULL, HFILL }},
      { &hf_bgp_cap_ap_afi,
        { "AFI", "bgp.cap.ap.afi", FT_UINT16, BASE_DEC,
          VALS(afn_vals), 0x0, NULL, HFILL }},
      { &hf_bgp_cap_ap_safi,
        { "SAFI", "bgp.cap.ap.safi", FT_UINT8, BASE_DEC,
          VALS(bgpattr_nlri_safi), 0x0, NULL, HFILL }},
      { &hf_bgp_cap_ap_sendreceive,
        { "Send/Receive", "bgp.cap.ap.sendreceive", FT_UINT8, BASE_DEC,
          VALS(orf_send_recv_vals), 0x0, NULL, HFILL }},
      { &hf_bgp_cap_orf_afi,
        { "AFI", "bgp.cap.orf.afi", FT_UINT16, BASE_DEC,
          VALS(afn_vals), 0x0, NULL, HFILL }},
      { &hf_bgp_cap_orf_safi,
        { "SAFI", "bgp.cap.orf.safi", FT_UINT8, BASE_DEC,
          VALS(bgpattr_nlri_safi), 0x0, NULL, HFILL }},
      { &hf_bgp_cap_orf_number,
        { "Number", "bgp.cap.orf.number", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_cap_orf_type,
        { "Type", "bgp.cap.orf.type", FT_UINT8, BASE_DEC,
          VALS(orf_type_vals), 0x0, NULL, HFILL }},
      { &hf_bgp_cap_orf_sendreceive,
        { "Send Receive", "bgp.cap.orf.sendreceive", FT_UINT8, BASE_DEC,
          VALS(orf_send_recv_vals), 0x0, NULL, HFILL }},
      { &hf_bgp_aggregator_as,
        { "Aggregator AS", "bgp.aggregator_as", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_aggregator_origin,
        { "Aggregator origin", "bgp.aggregator_origin", FT_IPv4, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_as_path,
        { "AS Path", "bgp.as_path", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_community_as,
        { "Community AS", "bgp.community_as", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_community_value,
        { "Community value", "bgp.community_value", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_local_pref,
        { "Local preference", "bgp.local_pref", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_mp_reach_nlri_ipv4_prefix,
        { "MP Reach NLRI IPv4 prefix", "bgp.mp_reach_nlri_ipv4_prefix", FT_IPv4, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_mp_unreach_nlri_ipv4_prefix,
        { "MP Unreach NLRI IPv4 prefix", "bgp.mp_unreach_nlri_ipv4_prefix", FT_IPv4, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_mp_nlri_tnl_id,
        { "MP Reach NLRI Tunnel Identifier", "bgp.mp_nlri_tnl_id", FT_UINT16, BASE_HEX,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_multi_exit_disc,
        { "Multiple exit discriminator", "bgp.multi_exit_disc", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_next_hop,
        { "Next hop", "bgp.next_hop", FT_IPv4, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_nlri_prefix,
        { "NLRI prefix", "bgp.nlri_prefix", FT_IPv4, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_nlri_path_id,
        { "NLRI path id", "bgp.nlri_path_id", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_origin,
        { "Origin", "bgp.origin", FT_UINT8, BASE_DEC,
          VALS(bgpattr_origin), 0x0, NULL, HFILL}},
      { &hf_bgp_originator_id,
        { "Originator identifier", "bgp.originator_id", FT_IPv4, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ssa_t,
        { "Transitive bit", "bgp.ssa_t", FT_BOOLEAN, 8,
          NULL, 0x80, "SSA Transitive bit", HFILL}},
      { &hf_bgp_ssa_type,
        { "SSA Type", "bgp.ssa_type", FT_UINT16, BASE_DEC,
          VALS(bgp_ssa_type), 0x7FFF, NULL, HFILL}},
      { &hf_bgp_ssa_len,
        { "Length", "bgp.ssa_len", FT_UINT16, BASE_DEC,
          NULL, 0x0, "SSA Length", HFILL}},
      { &hf_bgp_ssa_value,
        { "Value", "bgp.ssa_value", FT_BYTES, BASE_NONE,
          NULL, 0x0, "SSA Value", HFILL}},
      { &hf_bgp_ssa_l2tpv3_pref,
        { "Preference", "bgp.ssa_l2tpv3_pref", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ssa_l2tpv3_s,
        { "Sequencing bit", "bgp.ssa_l2tpv3_s", FT_BOOLEAN, 8,
          NULL, 0x80, "Sequencing S-bit", HFILL}},
      { &hf_bgp_ssa_l2tpv3_unused,
        { "Unused", "bgp.ssa_l2tpv3_Unused", FT_BOOLEAN, 8,
          NULL, 0x7F, "Unused Flags", HFILL}},
      { &hf_bgp_ssa_l2tpv3_cookie_len,
        { "Cookie Length", "bgp.ssa_l2tpv3_cookie_len", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ssa_l2tpv3_session_id,
        { "Session ID", "bgp.ssa_l2tpv3_session_id", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ssa_l2tpv3_cookie,
        { "Cookie", "bgp.ssa_l2tpv3_cookie", FT_BYTES, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_withdrawn_prefix,
        { "Withdrawn prefix", "bgp.withdrawn_prefix", FT_IPv4, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_cluster_list,
        { "Cluster List", "bgp.cluster_list", FT_BYTES, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_mcast_vpn_nlri_t,
        { "MCAST-VPN nlri", "bgp.mcast_vpn_nlri", FT_BYTES, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_mcast_vpn_nlri_route_type,
        { "Route Type", "bgp.mcast_vpn_nlri_route_type", FT_UINT8,
          BASE_DEC, VALS(mcast_vpn_route_type), 0x0, NULL, HFILL}},
      { &hf_bgp_mcast_vpn_nlri_length,
        { "Length", "bgp.mcast_vpn_nlri_length", FT_UINT8,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_mcast_vpn_nlri_rd,
        { "Route Distinguisher", "bgp.mcast_vpn_nlri_rd", FT_BYTES,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_mcast_vpn_nlri_origin_router_ipv4,
        { "Originating Router", "bgp.mcast_vpn_nlri_origin_router_ipv4", FT_IPv4,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_mcast_vpn_nlri_origin_router_ipv6,
        { "Originating Router", "bgp.mcast_vpn_nlri_origin_router_ipv6", FT_IPv6,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_mcast_vpn_nlri_source_as,
        { "Source AS", "bgp.mcast_vpn_nlri_source_as", FT_UINT16,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
       { &hf_bgp_mcast_vpn_nlri_source_length,
        { "Multicast Source Length", "bgp.mcast_vpn_nlri_source_length", FT_UINT8,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
       { &hf_bgp_mcast_vpn_nlri_group_length,
        { "Multicast Group Length", "bgp.mcast_vpn_nlri_group_length", FT_UINT8,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_mcast_vpn_nlri_source_addr_ipv4,
        { "Multicast Source Address", "bgp.mcast_vpn_nlri_source_addr_ipv4", FT_IPv4,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_mcast_vpn_nlri_source_addr_ipv6,
        { "Multicast Source Address", "bgp.mcast_vpn_nlri_source_addr_ipv6", FT_IPv6,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_mcast_vpn_nlri_group_addr_ipv4,
        { "Multicast Group Address", "bgp.mcast_vpn_nlri_group_addr_ipv4", FT_IPv4,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_mcast_vpn_nlri_group_addr_ipv6,
        { "Group Address", "bgp.mcast_vpn_nlri_group_addr_ipv6", FT_IPv6,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_mcast_vpn_nlri_route_key,
        { "Route Key", "bgp.mcast_vpn_nlri_route_key", FT_BYTES,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_encaps_tunnel_tlv_len,
        { "Length", "bgp.encaps_tunnel_tlv_len", FT_UINT16,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_encaps_tunnel_tlv_type,
        { "Type code", "bgp.encaps_tunnel_tlv_type", FT_UINT16, BASE_DEC,
          VALS(tunnel_type), 0x0, NULL, HFILL}},
      { &hf_bgp_encaps_tunnel_subtlv_len,
        { "Length", "bgp.encaps_tunnel_tlv_sublen", FT_UINT8,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_encaps_tunnel_subtlv_type,
        { "Type code", "bgp.encaps_tunnel_subtlv_type", FT_UINT8, BASE_DEC,
          VALS(subtlv_type), 0x0, NULL, HFILL}},
      { &hf_bgp_mdt_safi_rd,
        { "Route Distinguisher", "bgp.mdt_safi_rd", FT_BYTES,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_mdt_safi_ipv4_addr,
        { "IPv4 Address", "bgp.mdt_safi_ipv4_addr", FT_IPv4,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
       { &hf_bgp_mdt_safi_group_addr,
        { "Group Address", "bgp.mdt_safi_group_addr", FT_IPv4,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_flags_optional,
        { "Optional", "bgp.flags.optional", FT_BOOLEAN, 8,
          TFS(&tfs_optional_wellknown), BGP_ATTR_FLAG_OPTIONAL, NULL, HFILL}},
      { &hf_bgp_flags_transitive,
        { "Transitive", "bgp.flags.transitive", FT_BOOLEAN, 8,
          TFS(&tfs_transitive_non_transitive), BGP_ATTR_FLAG_TRANSITIVE, NULL, HFILL}},
      { &hf_bgp_flags_partial,
        { "Partial", "bgp.flags.partial", FT_BOOLEAN, 8,
          TFS(&tfs_partial_complete), BGP_ATTR_FLAG_PARTIAL, NULL, HFILL}},
      { &hf_bgp_flags_extended_length,
        { "Length", "bgp.flags.extended_length", FT_BOOLEAN, 8,
          TFS(&tfs_extended_regular_length), BGP_ATTR_FLAG_EXTENDED_LENGTH, NULL, HFILL}},
      { &hf_bgp_ext_com_qos_flags,
        { "Flags", "bgp.ext_com_qos.flags", FT_UINT8, BASE_HEX,
          NULL, 0, NULL, HFILL}},
      { &hf_bgp_ext_com_qos_flags_remarking,
        { "Remarking", "bgp.ext_com_qos.flags.remarking", FT_BOOLEAN, 8,
          TFS(&tfs_yes_no), 0x10, NULL, HFILL}},
      { &hf_bgp_ext_com_qos_flags_ignore_remarking,
        { "Ignore remarking", "bgp.ext_com_qos.flags.ignore_remarking", FT_BOOLEAN, 8,
          TFS(&tfs_yes_no), 0x08, NULL, HFILL}},
      { &hf_bgp_ext_com_qos_flags_agg_marking,
        { "Aggegation of markins", "bgp.ext_com_qos.flags.agg_marking", FT_BOOLEAN, 8,
          TFS(&tfs_yes_no), 0x04, NULL, HFILL}},
      { &hf_bgp_ext_com_cos_flags,
        { "Flags byte 1", "bgp.ext_com_cos.flags", FT_UINT8, BASE_HEX,
          NULL, 0, NULL, HFILL}},
      { &hf_bgp_ext_com_cos_flags_be,
        { "BE class", "bgp.ext_com_cos.flags.be", FT_BOOLEAN, 8,
          TFS(&tfs_supported_not_supported), 0x80, NULL, HFILL}},
      { &hf_bgp_ext_com_cos_flags_ef,
        { "EF class", "bgp.ext_com_cos.flags.ef", FT_BOOLEAN, 8,
          TFS(&tfs_supported_not_supported), 0x40, NULL, HFILL}},
      { &hf_bgp_ext_com_cos_flags_af,
        { "AF class", "bgp.ext_com_cos.flags.af", FT_BOOLEAN, 8,
          TFS(&tfs_supported_not_supported), 0x20, NULL, HFILL}},
      { &hf_bgp_ext_com_cos_flags_le,
        { "LE class", "bgp.ext_com_cos.flags.le", FT_BOOLEAN, 8,
          TFS(&tfs_supported_not_supported), 0x10, NULL, HFILL}},
      { &hf_bgp_ext_com_qos_set_number,
        { "QoS Set Number", "bgp.ext_com_qos.set_number", FT_UINT8, BASE_HEX,
          NULL, 0, NULL, HFILL}},
      { &hf_bgp_ext_com_qos_tech_type,
        { "Technology Type", "bgp.ext_com_qos.tech_type", FT_UINT8, BASE_HEX,
          VALS(qos_tech_type), 0, NULL, HFILL}},
      { &hf_bgp_ext_com_qos_marking_o,
        { "QoS Marking O", "bgp.ext_com_qos.marking_o", FT_UINT16, BASE_HEX,
          NULL, 0, NULL, HFILL}},
      { &hf_bgp_ext_com_qos_marking_a,
        { "QoS Marking A", "bgp.ext_com_qos.marking_a", FT_UINT8, BASE_HEX_DEC,
          NULL, 0, NULL, HFILL}},
      { &hf_bgp_ext_com_qos_default_to_zero,
        { "Defaults to zero", "bgp.ext_com_qos.default_to_zero", FT_UINT8, BASE_HEX,
          NULL, 0, NULL, HFILL}},
    };

    static gint *ett[] = {
      &ett_bgp,
      &ett_bgp_prefix,
      &ett_bgp_unfeas,
      &ett_bgp_attrs,
      &ett_bgp_attr,
      &ett_bgp_attr_flags,
      &ett_bgp_mp_nhna,
      &ett_bgp_mp_reach_nlri,
      &ett_bgp_mp_unreach_nlri,
      &ett_bgp_mp_snpa,
      &ett_bgp_nlri,
      &ett_bgp_open,
      &ett_bgp_update,
      &ett_bgp_notification,
      &ett_bgp_route_refresh,
      &ett_bgp_capability,
      &ett_bgp_as_paths,
      &ett_bgp_as_path_segments,
      &ett_bgp_communities,
      &ett_bgp_cluster_list,
      &ett_bgp_options,
      &ett_bgp_option,
      &ett_bgp_cap,
      &ett_bgp_extended_communities,
      &ett_bgp_ext_com_flags,
      &ett_bgp_ssa,
      &ett_bgp_ssa_subtree,
      &ett_bgp_orf,
      &ett_bgp_orf_entry,
      &ett_bgp_mcast_vpn_nlri,
      &ett_bgp_tunnel_tlv,
      &ett_bgp_tunnel_tlv_subtree,
      &ett_bgp_tunnel_subtlv,
      &ett_bgp_tunnel_subtlv_subtree,
    };
    module_t *bgp_module;
    static enum_val_t asn_len[] = {
        {"auto-detect", "Auto-detect", 0},
        {"2", "2 octet", 2},
        {"4", "4 octet", 4},
        {NULL, NULL, -1}
    };

    proto_bgp = proto_register_protocol("Border Gateway Protocol",
                                        "BGP", "bgp");
    proto_register_field_array(proto_bgp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    bgp_module = prefs_register_protocol(proto_bgp, NULL);
    prefs_register_bool_preference(bgp_module, "desegment",
      "Reassemble BGP messages spanning multiple TCP segments",
      "Whether the BGP dissector should reassemble messages spanning multiple TCP segments."
      " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
      &bgp_desegment);
    prefs_register_enum_preference(bgp_module, "asn_len",
      "Length of the AS number",
      "BGP dissector detect the length of the AS number in AS_PATH attributes automatically or manually (NOTE: Automatic detection is not 100% accurate)",
      &bgp_asn_len, asn_len, FALSE);
}

void
proto_reg_handoff_bgp(void)
{
    dissector_handle_t bgp_handle;

    bgp_handle = create_dissector_handle(dissect_bgp, proto_bgp);
    dissector_add_uint("tcp.port", BGP_TCP_PORT, bgp_handle);
}
/*
* Editor modelines - http://www.wireshark.org/tools/modelines.html
*
* Local variables:
* c-basic-offset: 4
* tab-width: 8
* indent-tabs-mode: nil
* End:
*
* ex: set shiftwidth=4 tabstop=8 expandtab:
* :indentSize=4:tabSize=8:noTabs=true:
*/
