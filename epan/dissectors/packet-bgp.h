/* packet-bgp.c
 * Definitions for BGP packet disassembly structures and routine
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __PACKET_BGP_H__
#define __PACKET_BGP_H__

/* some handy things to know */
#define BGP_MAX_PACKET_SIZE        4096
#define BGP_MARKER_SIZE            16    /* size of BGP marker */
#define BGP_HEADER_SIZE            19    /* size of BGP header, including marker */
#define BGP_MIN_OPEN_MSG_SIZE      29
#define BGP_MIN_UPDATE_MSG_SIZE    23
#define BGP_MIN_NOTIFICATION_MSG_SIZE    21
#define BGP_MIN_KEEPALVE_MSG_SIZE    BGP_HEADER_SIZE
#define BGP_TCP_PORT            179

/* BGP message types */
#define BGP_OPEN          1
#define BGP_UPDATE        2
#define BGP_NOTIFICATION  3
#define BGP_KEEPALIVE     4
#define BGP_ROUTE_REFRESH 5
#define BGP_CAPABILITY    6
#define BGP_ROUTE_REFRESH_CISCO 0x80

/* BGP OPEN message */
struct bgp_open {
    guint8 bgpo_marker[BGP_MARKER_SIZE];
    guint16 bgpo_len;
    guint8 bgpo_type;
    guint8 bgpo_version;
    guint16 bgpo_myas;
    guint16 bgpo_holdtime;
    guint32 bgpo_id;
    guint8 bgpo_optlen;
    /* options should follow */
};

/* BGP NOTIFICATION message */
struct bgp_notification {
    guint8 bgpn_marker[BGP_MARKER_SIZE];
    guint16 bgpn_len;
    guint8 bgpn_type;
    guint8 bgpn_major;
    guint8 bgpn_minor;
    /* data should follow */
};

/* BGP ROUTE-REFRESH message */
struct bgp_route_refresh {
    guint8 bgpr_marker[BGP_MARKER_SIZE];
    guint16 bgpr_len;
    guint8 bgpr_type;
    guint16 bgpr_afi;
    guint8 bgpr_reserved;
    guint8 bgpr_safi;
};

/* path attribute */
struct bgp_attr {
    guint8 bgpa_flags;
    guint8 bgpa_type;
};

/* attribute flags, from RFC1771 */
#define BGP_ATTR_FLAG_OPTIONAL        0x80
#define BGP_ATTR_FLAG_TRANSITIVE      0x40
#define BGP_ATTR_FLAG_PARTIAL         0x20
#define BGP_ATTR_FLAG_EXTENDED_LENGTH 0x10

/* SSA flags */
#define BGP_SSA_TRANSITIVE    0x8000
#define BGP_SSA_TYPE          0x7FFF

/* SSA Types */
#define BGP_SSA_L2TPv3    1
#define BGP_SSA_mGRE      2
#define BGP_SSA_IPSec     3
#define BGP_SSA_MPLS      4
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
#define SAFNUM_UNICAST  1
#define SAFNUM_MULCAST  2
#define SAFNUM_UNIMULC  3
#define SAFNUM_MPLS_LABEL 4     /* rfc3107 */
#define SAFNUM_TUNNEL    64    /* draft-nalawade-kapoor-tunnel-safi-02.txt */
#define SAFNUM_VPLS     65
#define SAFNUM_LAB_VPNUNICAST  128    /* Draft-rosen-rfc2547bis-03 */
#define SAFNUM_LAB_VPNMULCAST  129
#define SAFNUM_LAB_VPNUNIMULC  130

/* BGP Additional Paths Capability */
#define BGP_ADDPATH_RECEIVE  0x01
#define BGP_ADDPATH_SEND     0x02


#ifndef offsetof
#define offsetof(type, member)  ((size_t)(&((type *)0)->member))
#endif

#endif

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
