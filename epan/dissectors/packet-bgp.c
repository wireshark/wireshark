/* packet-bgp.c
 * Routines for BGP packet dissection.
 * Copyright 1999, Jun-ichiro itojun Hagino <itojun@itojun.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
 * RFC4360 BGP Extended Communities Attribute
 * RFC4486 Subcodes for BGP Cease Notification Message
 * RFC4724 Graceful Restart Mechanism for BGP
 * RFC5512 The BGP Encapsulation Subsequent Address Family Identifier (SAFI)
 * RFC5575 Dissemination of flow specification rules
 * RFC5640 Load-Balancing for Mesh Softwires
 * RFC6368 Internal BGP as the Provider/Customer Edge Protocol for
           BGP/MPLS IP Virtual Private Networks (VPNs)
 * RFC6608 Subcodes for BGP Finite State Machine Error
 * RFC6793 BGP Support for Four-Octet Autonomous System (AS) Number Space
 * RFC7311 The Accumulated IGP Metric Attribute for BGP
 * RFC7432 BGP MPLS-Based Ethernet VPN
 * RFC7752 North-Bound Distribution of Link-State and Traffic Engineering (TE)
           Information Using BGP
 * RFC8092 BGP Large Communities Attribute
 * RFC8214 Virtual Private Wire Service Support in Ethernet VPN
 * draft-ietf-idr-dynamic-cap
 * draft-ietf-idr-bgp-enhanced-route-refresh-02
 * draft-knoll-idr-qos-attribute-03
 * draft-nalawade-kapoor-tunnel-safi-05
 * draft-ietf-idr-add-paths-04 Additional-Path for BGP-4
 * draft-gredler-idr-bgp-ls-segment-routing-ext-01
 * draft-ietf-idr-custom-decision-07 BGP Custom Decision Process
 * draft-rabadan-l2vpn-evpn-prefix-advertisement IP Prefix Advertisement
 *     in EVPN
 * RFC8669 Segment Routing Prefix Segment Identifier Extensions for BGP
 * http://www.iana.org/assignments/bgp-parameters/ (last updated 2012-04-26)
 * RFC8538 Notification Message Support for BGP Graceful Restart
 * draft-ietf-bess-evpn-igmp-mld-proxy-03
 * draft-ietf-idr-tunnel-encaps-15
 * draft-ietf-idr-segment-routing-te-policy-08
 * draft-yu-bess-evpn-l2-attributes-04
 * draft-ietf-bess-srv6-services-05
 * RFC9104 Distribution of Traffic Engineering Extended Administrative Groups
           Using the Border Gateway Protocol - Link State

 * TODO:
 * Destination Preference Attribute for BGP (work in progress)
 * RFC1863 A BGP/IDRP Route Server alternative to a full mesh routing
 */
/* (c) Copyright 2015, Pratik Yeole <pyeole@ncsu.edu>
   -  Fixed incorrect decoding of Network Layer Reachability Information (NLRI) in BGP UPDATE message with add-path support
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/addr_and_mask.h>
#include <epan/show_exception.h>
#include <epan/afn.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/etypes.h>
#include <epan/to_str.h>
#include <epan/proto_data.h>
#include <epan/ipproto.h>
#include <wsutil/str_util.h>
#include "packet-ip.h"
#include "packet-ldp.h"
#include "packet-bgp.h"
#include "packet-eigrp.h"

void proto_register_bgp(void);
void proto_reg_handoff_bgp(void);

static dissector_handle_t bgp_handle;

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

#define BGP_SIZE_OF_PATH_ATTRIBUTE       2


/* attribute flags, from RFC1771 */
#define BGP_ATTR_FLAG_OPTIONAL        0x80
#define BGP_ATTR_FLAG_TRANSITIVE      0x40
#define BGP_ATTR_FLAG_PARTIAL         0x20
#define BGP_ATTR_FLAG_EXTENDED_LENGTH 0x10
#define BGP_ATTR_FLAG_UNUSED          0x0F


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

/* BGP MPLS information */
#define BGP_MPLS_BOTTOM_L_STACK 0x000001
#define BGP_MPLS_TRAFFIC_CLASS  0x00000E
#define BGP_MPLS_LABEL          0xFFFFF0

/* AS_PATH segment types */
#define AS_SET             1   /* RFC1771 */
#define AS_SEQUENCE        2   /* RFC1771 */
#define AS_CONFED_SET      4   /* RFC1965 has the wrong values, corrected in  */
#define AS_CONFED_SEQUENCE 3   /* draft-ietf-idr-bgp-confed-rfc1965bis-01.txt */

/* BGPsec_PATH attributes */
#define SEC_PATH_SEG_SIZE 6

/* OPEN message Optional Parameter types  */
#define BGP_OPTION_AUTHENTICATION    1   /* RFC1771 */
#define BGP_OPTION_CAPABILITY        2   /* RFC2842 */

/* https://www.iana.org/assignments/capability-codes/capability-codes.xhtml (last updated 2018-08-21) */
/* BGP capability code */
#define BGP_CAPABILITY_RESERVED                      0  /* RFC5492 */
#define BGP_CAPABILITY_MULTIPROTOCOL                 1  /* RFC2858 */
#define BGP_CAPABILITY_ROUTE_REFRESH                 2  /* RFC2918 */
#define BGP_CAPABILITY_COOPERATIVE_ROUTE_FILTERING   3  /* RFC5291 */
#define BGP_CAPABILITY_MULTIPLE_ROUTE_DEST           4  /* RFC8277 Deprecated */
#define BGP_CAPABILITY_EXTENDED_NEXT_HOP             5  /* RFC5549 */
#define BGP_CAPABILITY_EXTENDED_MESSAGE              6  /* draft-ietf-idr-bgp-extended-messages */
#define BGP_CAPABILITY_BGPSEC                        7  /* RFC8205 */
#define BGP_CAPABILITY_MULTIPLE_LABELS               8  /* RFC8277 */
#define BGP_CAPABILITY_BGP_ROLE                      9  /* draft-ietf-idr-bgp-open-policy */
#define BGP_CAPABILITY_GRACEFUL_RESTART             64  /* RFC4724 */
#define BGP_CAPABILITY_4_OCTET_AS_NUMBER            65  /* RFC6793 */
#define BGP_CAPABILITY_DYNAMIC_CAPABILITY_CISCO     66  /* Cisco Dynamic capabaility*/
#define BGP_CAPABILITY_DYNAMIC_CAPABILITY           67  /* draft-ietf-idr-dynamic-cap */
#define BGP_CAPABILITY_MULTISESSION                 68  /* draft-ietf-idr-bgp-multisession */
#define BGP_CAPABILITY_ADDITIONAL_PATHS             69  /* [RFC7911] */
#define BGP_CAPABILITY_ENHANCED_ROUTE_REFRESH       70  /* [RFC7313] */
#define BGP_CAPABILITY_LONG_LIVED_GRACEFUL_RESTART  71  /* draft-uttaro-idr-bgp-persistence */
#define BGP_CAPABILITY_CP_ORF                       72  /* [RFC7543] */
#define BGP_CAPABILITY_FQDN                         73  /* draft-walton-bgp-hostname-capability */
#define BGP_CAPABILITY_ROUTE_REFRESH_CISCO         128  /* Cisco */
#define BGP_CAPABILITY_ORF_CISCO                   130  /* Cisco */
#define BGP_CAPABILITY_MULTISESSION_CISCO          131  /* Cisco */

#define BGP_ORF_PREFIX_CISCO    0x80 /* Cisco */
#define BGP_ORF_COMM_CISCO      0x81 /* Cisco */
#define BGP_ORF_EXTCOMM_CISCO   0x82 /* Cisco */
#define BGP_ORF_ASPATH_CISCO    0x83 /* Cisco */

#define BGP_ORF_COMM        0x02 /* RFC5291 */
#define BGP_ORF_EXTCOMM     0x03 /* RFC5291 */
#define BGP_ORF_ASPATH      0x04 /* draft-ietf-idr-aspath-orf-02.txt */
/* RFC5291 */
#define BGP_ORF_ACTION      0xc0
#define BGP_ORF_ADD         0x00
#define BGP_ORF_REMOVE      0x01
#define BGP_ORF_REMOVEALL   0x02

#define BGP_ORF_MATCH       0x20
#define BGP_ORF_PERMIT      0x00
#define BGP_ORF_DENY        0x01

/* well-known communities, as defined by IANA  */
/* https://www.iana.org/assignments/bgp-well-known-communities/bgp-well-known-communities.xhtml */
#define BGP_COMM_GRACEFUL_SHUTDOWN   0xFFFF0000
#define BGP_COMM_ACCEPT_OWN          0xFFFF0001
#define BGP_COMM_BLACKHOLE           0xFFFF029A
#define BGP_COMM_NO_EXPORT           0xFFFFFF01
#define BGP_COMM_NO_ADVERTISE        0xFFFFFF02
#define BGP_COMM_NO_EXPORT_SUBCONFED 0xFFFFFF03
#define BGP_COMM_NOPEER              0xFFFFFF04
#define FOURHEX0                     0x00000000
#define FOURHEXF                     0xFFFF0000

/* IANA assigned AS */
#define BGP_AS_TRANS        23456

/* attribute types */
#define BGPTYPE_ORIGIN               1 /* RFC4271           */
#define BGPTYPE_AS_PATH              2 /* RFC4271           */
#define BGPTYPE_NEXT_HOP             3 /* RFC4271           */
#define BGPTYPE_MULTI_EXIT_DISC      4 /* RFC4271           */
#define BGPTYPE_LOCAL_PREF           5 /* RFC4271           */
#define BGPTYPE_ATOMIC_AGGREGATE     6 /* RFC4271           */
#define BGPTYPE_AGGREGATOR           7 /* RFC4271           */
#define BGPTYPE_COMMUNITIES          8 /* RFC1997           */
#define BGPTYPE_ORIGINATOR_ID        9 /* RFC4456           */
#define BGPTYPE_CLUSTER_LIST        10 /* RFC4456           */
#define BGPTYPE_DPA                 11 /* DPA (deprecated) [RFC6938]  */
#define BGPTYPE_ADVERTISER          12 /* ADVERTISER (historic) (deprecated) [RFC1863][RFC4223][RFC6938] */
#define BGPTYPE_RCID_PATH           13 /* RCID_PATH / CLUSTER_ID (historic) (deprecated) [RFC1863][RFC4223][RFC6938] */
#define BGPTYPE_MP_REACH_NLRI       14 /* RFC4760           */
#define BGPTYPE_MP_UNREACH_NLRI     15 /* RFC4760           */
#define BGPTYPE_EXTENDED_COMMUNITY  16 /* RFC4360           */
#define BGPTYPE_AS4_PATH            17 /* RFC 6793          */
#define BGPTYPE_AS4_AGGREGATOR      18 /* RFC 6793          */
#define BGPTYPE_SAFI_SPECIFIC_ATTR  19 /* SAFI Specific Attribute (SSA) (deprecated) draft-kapoor-nalawade-idr-bgp-ssa-00.txt */
#define BGPTYPE_CONNECTOR_ATTRIBUTE 20 /* Connector Attribute (deprecated) [RFC6037] */
#define BGPTYPE_AS_PATHLIMIT        21 /* AS_PATHLIMIT (deprecated) [draft-ietf-idr-as-pathlimit] */
#define BGPTYPE_PMSI_TUNNEL_ATTR    22 /* RFC6514 */
#define BGPTYPE_TUNNEL_ENCAPS_ATTR  23 /* RFC5512 */
#define BGPTYPE_TRAFFIC_ENGINEERING 24 /* Traffic Engineering [RFC5543] */
#define BGPTYPE_IPV6_ADDR_SPEC_EC   25 /* IPv6 Address Specific Extended Community [RFC5701] */
#define BGPTYPE_AIGP                26 /* RFC7311 */
#define BGPTYPE_PE_DISTING_LABLES   27 /* PE Distinguisher Labels [RFC6514] */
#define BGPTYPE_BGP_ENTROPY_LABEL   28 /* BGP Entropy Label Capability Attribute (deprecated) [RFC6790][RFC7447] */
#define BGPTYPE_LINK_STATE_ATTR     29 /* RFC7752 */
#define BGPTYPE_30                  30 /* Deprecated [RFC8093] */
#define BGPTYPE_31                  31 /* Deprecated [RFC8093] */
#define BGPTYPE_LARGE_COMMUNITY     32 /* RFC8092 */
#define BGPTYPE_BGPSEC_PATH         33 /* BGPsec_PATH [RFC8205] */
#define BGPTYPE_D_PATH              36 /* https://tools.ietf.org/html/draft-rabadan-sajassi-bess-evpn-ipvpn-interworking-02 */
#define BGPTYPE_BGP_PREFIX_SID      40 /* BGP Prefix-SID [RFC8669] */
#define BGPTYPE_LINK_STATE_OLD_ATTR 99 /* squatted value used by at least 2
                                          implementations before IANA assignment */
#define BGPTYPE_ATTR_SET           128 /* RFC6368           */
#define BGPTYPE_129                129 /* Deprecated [RFC8093] */
#define BGPTYPE_241                241 /* Deprecated [RFC8093] */
#define BGPTYPE_242                242 /* Deprecated [RFC8093] */
#define BGPTYPE_243                243 /* Deprecated [RFC8093] */

/*EVPN Route Types */
#define EVPN_AD_ROUTE           1
#define EVPN_MAC_ROUTE          2
#define EVPN_INC_MCAST_TREE     3
#define EVPN_ETH_SEGMENT_ROUTE  4
#define EVPN_IP_PREFIX_ROUTE    5 /* draft-rabadan-l2vpn-evpn-prefix-advertisement */
#define EVPN_MC_ETHER_TAG_ROUTE 6 /* draft-ietf-bess-evpn-igmp-mld-proxy-03 */
#define EVPN_IGMP_JOIN_ROUTE    7 /* draft-ietf-bess-evpn-igmp-mld-proxy-03 */
#define EVPN_IGMP_LEAVE_ROUTE   8 /* draft-ietf-bess-evpn-igmp-mld-proxy-03 */
#define EVPN_S_PMSI_A_D_ROUTE   10 /* draft-ietf-bess-evpn-bum-procedure-updates-7 */

#define EVPN_IGMP_MC_FLAG_V1                0x01
#define EVPN_IGMP_MC_FLAG_V2                0x02
#define EVPN_IGMP_MC_FLAG_V3                0x04
#define EVPN_IGMP_MC_FLAG_IE                0x08
#define EVPN_IGMP_MC_FLAG_RESERVED          0xF0

/* NLRI type as define in BGP flow spec RFC */
#define BGPNLRI_FSPEC_DST_PFIX      1 /* RFC 5575         */
#define BGPNLRI_FSPEC_SRC_PFIX      2 /* RFC 5575         */
#define BGPNLRI_FSPEC_IP_PROTO      3 /* RFC 5575         */
#define BGPNLRI_FSPEC_PORT          4 /* RFC 5575         */
#define BGPNLRI_FSPEC_DST_PORT      5 /* RFC 5575         */
#define BGPNLRI_FSPEC_SRC_PORT      6 /* RFC 5575         */
#define BGPNLRI_FSPEC_ICMP_TP       7 /* RFC 5575         */
#define BGPNLRI_FSPEC_ICMP_CD       8 /* RFC 5575         */
#define BGPNLRI_FSPEC_TCP_FLAGS     9 /* RFC 5575         */
#define BGPNLRI_FSPEC_PCK_LEN      10 /* RFC 5575         */
#define BGPNLRI_FSPEC_DSCP         11 /* RFC 5575         */
#define BGPNLRI_FSPEC_FRAGMENT     12 /* RFC 5575         */

/* BGP flow spec NLRI operator bitmask */
#define BGPNLRI_FSPEC_END_OF_LST         0x80
#define BGPNLRI_FSPEC_AND_BIT            0x40
#define BGPNLRI_FSPEC_VAL_LEN            0x30
#define BGPNLRI_FSPEC_UNUSED_BIT4        0x08
#define BGPNLRI_FSPEC_UNUSED_BIT5        0x04
#define BGPNLRI_FSPEC_LESS_THAN          0x04
#define BGPNLRI_FSPEC_GREATER_THAN       0x02
#define BGPNLRI_FSPEC_EQUAL              0x01
#define BGPNLRI_FSPEC_TCPF_NOTBIT        0x02
#define BGPNLRI_FSPEC_TCPF_MATCHBIT      0x01
#define BGPNLRI_FSPEC_DSCP_BITMASK       0x3F

/* BGP flow spec specific filter value: TCP flags, Packet fragment ... */
#define BGPNLRI_FSPEC_TH_FIN  0x01
#define BGPNLRI_FSPEC_TH_SYN  0x02
#define BGPNLRI_FSPEC_TH_RST  0x04
#define BGPNLRI_FSPEC_TH_PUSH 0x08
#define BGPNLRI_FSPEC_TH_ACK  0x10
#define BGPNLRI_FSPEC_TH_URG  0x20
#define BGPNLRI_FSPEC_TH_ECN  0x40
#define BGPNLRI_FSPEC_TH_CWR  0x80

#define BGPNLRI_FSPEC_FG_DF   0x01
#define BGPNLRI_FSPEC_FG_ISF  0x02
#define BGPNLRI_FSPEC_FG_FF   0x04
#define BGPNLRI_FSPEC_FG_LF   0x08

/* Extended community type */
/* according to IANA's number assignment at: http://www.iana.org/assignments/bgp-extended-communities */
/* BGP transitive extended community type high octet */
/* Range 0x00-0x3f First Come First Served */
/* Range 0x80-0x8f Reserved for Experimental */
/* Range 0x90-0xbf Standards Action */

#define BGP_EXT_COM_TYPE_AUTH               0x80    /* FCFS or Standard/Early/Experimental allocated */
#define BGP_EXT_COM_TYPE_TRAN               0x40    /* Non-transitive or Transitive */

#define BGP_EXT_COM_TYPE_HIGH_TR_AS2        0x00    /* Transitive Two-Octet AS-Specific Extended Community */
#define BGP_EXT_COM_TYPE_HIGH_TR_IP4        0x01    /* Transitive IPv4-Address-specific Extended Community */
#define BGP_EXT_COM_TYPE_HIGH_TR_AS4        0x02    /* Transitive Four-Octet AS-Specific Extended Community */
#define BGP_EXT_COM_TYPE_HIGH_TR_OPAQUE     0x03    /* Transitive Opaque Extended Community */
#define BGP_EXT_COM_TYPE_HIGH_TR_QOS        0x04    /* QoS Marking [Thomas_Martin_Knoll] */
#define BGP_EXT_COM_TYPE_HIGH_TR_COS        0x05    /* CoS Capability [Thomas_Martin_Knoll] */
#define BGP_EXT_COM_TYPE_HIGH_TR_EVPN       0x06    /* EVPN (Sub-Types are defined in the "EVPN Extended Community Sub-Types" registry) */
#define BGP_EXT_COM_TYPE_HIGH_TR_FLOW_I     0x07    /* FlowSpec Transitive Extended Communities [draft-ietf-idr-flowspec-interfaceset] */
#define BGP_EXT_COM_TYPE_HIGH_TR_FLOW       0x08    /* Flow spec redirect/mirror to IP next-hop [draft-simpson-idr-flowspec-redirect] */
#define BGP_EXT_COM_TYPE_HIGH_TR_FLOW_R     0x09    /* FlowSpec Redirect to indirection-id Extended Community [draft-ietf-idr-flowspec-path-redirect] */
#define BGP_EXT_COM_TYPE_HIGH_TR_EXP        0x80    /* Generic Transitive Experimental Extended Community */
#define BGP_EXT_COM_TYPE_HIGH_TR_EXP_2      0x81    /* Generic Transitive Experimental Use Extended Community Part 2 [RFC7674] */
#define BGP_EXT_COM_TYPE_HIGH_TR_EXP_3      0x82    /* Generic Transitive Experimental Use Extended Community Part 3 [RFC7674] */
#define BGP_EXT_COM_TYPE_HIGH_TR_EXP_EIGRP  0x88    /* EIGRP attributes - http://www.cisco.com/c/en/us/td/docs/ios/12_0s/feature/guide/seipecec.html */

/* BGP non transitive extended community type high octet */
/* 0x40-0x7f First Come First Served */
/* 0xc0-0xcf Reserved for Experimental Use (see [RFC4360]) */
/* 0xd0-0xff Standards Action */
/* 0x45-0x7f Unassigned */
#define BGP_EXT_COM_TYPE_HIGH_NTR_AS2       0x40    /* Non-Transitive Two-Octet AS-Specific Extended Community */
#define BGP_EXT_COM_TYPE_HIGH_NTR_IP4       0x41    /* Non-Transitive IPv4-Address-specific Extended Community */
#define BGP_EXT_COM_TYPE_HIGH_NTR_AS4       0x42    /* Non-Transitive Four-Octet AS-Specific Extended Community */
#define BGP_EXT_COM_TYPE_HIGH_NTR_OPAQUE    0x43    /* Non-Transitive Opaque Extended Community */
#define BGP_EXT_COM_TYPE_HIGH_NTR_QOS       0x44    /* QoS Marking [Thomas_Martin_Knoll] */


/* EVPN Extended Community Sub-Types */
#define BGP_EXT_COM_STYPE_EVPN_MMAC         0x00    /* MAC Mobility [draft-ietf-l2vpn-pbb-evpn] */
#define BGP_EXT_COM_STYPE_EVPN_LABEL        0x01    /* ESI MPLS Label [draft-ietf-l2vpn-evpn] */
#define BGP_EXT_COM_STYPE_EVPN_IMP          0x02    /* ES Import [draft-sajassi-l2vpn-evpn-segment-route] */
#define BGP_EXT_COM_STYPE_EVPN_ROUTERMAC    0x03    /* draft-sajassi-l2vpn-evpn-inter-subnet-forwarding */
#define BGP_EXT_COM_STYPE_EVPN_L2ATTR       0x04    /* RFC 8214 */
#define BGP_EXT_COM_STYPE_EVPN_ETREE        0x05    /* RFC 8317 */
#define BGP_EXT_COM_STYPE_EVPN_DF           0x06    /* RFC 8584 */
#define BGP_EXT_COM_STYPE_EVPN_ISID         0x07    /* draft-sajassi-bess-evpn-virtual-eth-segment */
#define BGP_EXT_COM_STYPE_EVPN_ND           0x08    /* draft-snr-bess-evpn-na-flags */
#define BGP_EXT_COM_STYPE_EVPN_MCFLAGS      0x09    /* draft-ietf-bess-evpn-igmp-mld-proxy */
#define BGP_EXT_COM_STYPE_EVPN_EVIRT0       0x0a    /* draft-ietf-bess-evpn-igmp-mld-proxy */
#define BGP_EXT_COM_STYPE_EVPN_EVIRT1       0x0b    /* draft-ietf-bess-evpn-igmp-mld-proxy */
#define BGP_EXT_COM_STYPE_EVPN_EVIRT2       0x0c    /* draft-ietf-bess-evpn-igmp-mld-proxy */
#define BGP_EXT_COM_STYPE_EVPN_EVIRT3       0x0d    /* draft-ietf-bess-evpn-igmp-mld-proxy */
#define BGP_EXT_COM_STYPE_EVPN_ATTACHCIRT   0x0e    /* draft-sajassi-bess-evpn-ac-aware-bundling */

/* RFC 7432 Flag single active mode */
#define BGP_EXT_COM_ESI_LABEL_FLAGS         0x01    /* bitmask: set for single active multi-homing site */

/* RFC 7432 Flag Sticky/Static MAC */
#define BGP_EXT_COM_EVPN_MMAC_STICKY        0x01    /* Bitmask: Set for sticky/static MAC address */

/* RFC 8214 Flags EVPN L2 Attributes */
#define BGP_EXT_COM_EVPN_L2ATTR_FLAG_B         0x01    /* Backup PE */
#define BGP_EXT_COM_EVPN_L2ATTR_FLAG_P         0x02    /* Primary PE */
#define BGP_EXT_COM_EVPN_L2ATTR_FLAG_C         0x04    /* Control word required */
/* draft-yu-bess-evpn-l2-attributes-04 */
#define BGP_EXT_COM_EVPN_L2ATTR_FLAG_F         0x08    /* Send and receive flow label */
#define BGP_EXT_COM_EVPN_L2ATTR_FLAG_CI        0x10    /* CWI extended community can be included */
#define BGP_EXT_COM_EVPN_L2ATTR_FLAG_RESERVED  0xFFE0  /* Reserved */

/* RFC 8317 Flags EVPN E-Tree Attributes */
#define BGP_EXT_COM_EVPN_ETREE_FLAG_L         0x01  /* Leaf-Indication */
#define BGP_EXT_COM_EVPN_ETREE_FLAG_RESERVED  0xFE  /* Reserved */

/* EPVN route AD NLRI ESI type */
#define BGP_NLRI_EVPN_ESI_VALUE             0x00    /* ESI type 0, 9 bytes interger */
#define BGP_NLRI_EVPN_ESI_LACP              0x01    /* ESI type 1, LACP 802.1AX */
#define BGP_NLRI_EVPN_ESI_MSTP              0x02    /* ESI type 2, MSTP defined ESI */
#define BGP_NLRI_EVPN_ESI_MAC               0x03    /* ESI type 3, MAC allocated value */
#define BGP_NLRI_EVPN_ESI_RID               0x04    /* ESI type 4, Router ID as ESI */
#define BGP_NLRI_EVPN_ESI_ASN               0x05    /* ESI type 5, ASN as ESI */
#define BGP_NLRI_EVPN_ESI_RES               0xFF    /* ESI 0xFF reserved */


/* Transitive Two-Octet AS-Specific Extended Community Sub-Types */
/* 0x04 Unassigned */
/* 0x06-0x07 Unassigned */
/* 0x0b-0x0f Unassigned */
/* 0x11-0xff Unassigned */
#define BGP_EXT_COM_STYPE_AS2_RT        0x02    /* Route Target [RFC4360] */
#define BGP_EXT_COM_STYPE_AS2_RO        0x03    /* Route Origin [RFC4360] */
#define BGP_EXT_COM_STYPE_AS2_OSPF_DID  0x05    /* OSPF Domain Identifier [RFC4577] */
#define BGP_EXT_COM_STYPE_AS2_DCOLL     0x08    /* BGP Data Collection [RFC4384] */
#define BGP_EXT_COM_STYPE_AS2_SRC_AS    0x09    /* Source AS [RFC6514] */
#define BGP_EXT_COM_STYPE_AS2_L2VPN     0x0a    /* L2VPN Identifier [RFC6074] */
#define BGP_EXT_COM_STYPE_AS2_CVPND     0x0010  /* Cisco VPN-Distinguisher [Eric_Rosen] */

/* Non-Transitive Two-Octet AS-Specific Extended Community Sub-Types */
/* 0x00-0xbf First Come First Served */
/* 0xc0-0xff IETF Review*/

#define BGP_EXT_COM_STYPE_AS2_LBW       0x04    /* Link Bandwidth Extended Community [draft-ietf-idr-link-bandwidth-00] */
#define BGP_EXT_COM_STYPE_AS2_VNI       0x80    /* Virtual-Network Identifier Extended Community [draft-drao-bgp-l3vpn-virtual-network-overlays] */

/* Transitive Four-Octet AS-Specific Extended Community Sub-Types */
/* 0x00-0xbf First Come First Served */
/* 0xc0-0xff IETF Review */

#define BGP_EXT_COM_STYPE_AS4_RT        0x02    /* Route Target [RFC5668] */
#define BGP_EXT_COM_STYPE_AS4_RO        0x03    /* Route Origin [RFC5668] */
#define BGP_EXT_COM_STYPE_AS4_GEN       0x04    /* Generic (deprecated) [draft-ietf-idr-as4octet-extcomm-generic-subtype] */
#define BGP_EXT_COM_STYPE_AS4_OSPF_DID  0x05    /* OSPF Domain Identifier [RFC4577] */
#define BGP_EXT_COM_STYPE_AS4_BGP_DC    0x08    /* BGP Data Collection [RFC4384] */
#define BGP_EXT_COM_STYPE_AS4_S_AS      0x09    /* Source AS [RFC6514] */
#define BGP_EXT_COM_STYPE_AS4_CIS_V     0x10    /* Cisco VPN Identifier [Eric_Rosen] */
#define BGP_EXT_COM_STYPE_AS4_RT_REC    0x13    /* Route-Target Record [draft-ietf-bess-service-chaining] */

/* Non-Transitive Four-Octet AS-Specific Extended Community Sub-Types */

/*
 * #define BGP_EXT_COM_STYPE_AS4_GEN       0x04
 * Generic (deprecated) [draft-ietf-idr-as4octet-extcomm-generic-subtype]
*/

/* Transitive IPv4-Address-Specific Extended Community Sub-Types */

#define BGP_EXT_COM_STYPE_IP4_RT        0x02    /* Route Target [RFC4360] */
#define BGP_EXT_COM_STYPE_IP4_RO        0x03    /* Route Origin [RFC4360] */
#define BGP_EXT_COM_STYPE_IP4_OSPF_DID  0x05    /* OSPF Domain Identifier [RFC4577] */
#define BGP_EXT_COM_STYPE_IP4_OSPF_RID  0x07    /* OSPF Router ID [RFC4577] */
#define BGP_EXT_COM_STYPE_IP4_L2VPN     0x0a    /* L2VPN Identifier [RFC6074] */
#define BGP_EXT_COM_STYPE_IP4_VRF_I     0x0b    /* VRF Route Import [RFC6514] */
#define BGP_EXT_COM_STYPE_IP4_CIS_D     0x10    /* Cisco VPN-Distinguisher [Eric_Rosen] */
#define BGP_EXT_COM_STYPE_IP4_SEG_NH    0x12    /* Inter-area P2MP Segmented Next-Hop [draft-ietf-mpls-seamless-mcast] */

/* Transitive Opaque Extended Community Sub-Types */

#define BGP_EXT_COM_STYPE_OPA_COST      0x01    /* Cost Community [draft-ietf-idr-custom-decision] */
#define BGP_EXT_COM_STYPE_OPA_OSPF_RT   0x06    /* OSPF Route Type [RFC4577] */
#define BGP_EXT_COM_STYPE_OPA_COLOR     0x0b    /* Color Extended Community [RFC5512] */
#define BGP_EXT_COM_STYPE_OPA_ENCAP     0x0c    /* Encapsulation Extended Community [RFC5512] */
#define BGP_EXT_COM_STYPE_OPA_DGTW      0x0d    /* Default Gateway  [Yakov_Rekhter] */

/* BGP Cost Community Point of Insertion Types */

#define BGP_EXT_COM_COST_POI_ORIGIN     1       /* Evaluate after "Prefer lowest Origin" step */
#define BGP_EXT_COM_COST_POI_ASPATH     2       /* Evaluate after "Prefer shortest AS_PATH" step */
#define BGP_EXT_COM_COST_POI_MED        4       /* Evaluate after "Prefer lowest MED" step */
#define BGP_EXT_COM_COST_POI_LP         5       /* Evaluate after "Prefer highest Local Preference" step */
#define BGP_EXT_COM_COST_POI_AIGP       26      /* Evaluate after "Prefer lowest Accumulated IGP Cost" step */
#define BGP_EXT_COM_COST_POI_ABS        128     /* Pre-bestpath POI */
#define BGP_EXT_COM_COST_POI_IGP        129     /* Evaluate after "Prefer smallest IGP metric to next-hop" step */
#define BGP_EXT_COM_COST_POI_EI         130     /* Evaluate after "Prefer eBGP to iBGP" step */
#define BGP_EXT_COM_COST_POI_RID        131     /* Evaluate after "Prefer lowest BGP RID" step */

#define BGP_EXT_COM_COST_CID_REP        0x80    /* Bitmask - value replace/evaluate after bit */

/* BGP Tunnel Encapsulation Attribute Tunnel Types */

#define BGP_EXT_COM_TUNNEL_RESERVED     0       /* Reserved [RFC5512] */
#define BGP_EXT_COM_TUNNEL_L2TPV3       1       /* L2TPv3 over IP [RFC5512] */
#define BGP_EXT_COM_TUNNEL_GRE          2       /* GRE [RFC5512] */
#define BGP_EXT_COM_TUNNEL_ENDP         3       /* Transmit tunnel endpoint [RFC5566] */
#define BGP_EXT_COM_TUNNEL_IPSEC        4       /* IPsec in Tunnel-mode [RFC5566] */
#define BGP_EXT_COM_TUNNEL_IPIPSEC      5       /* IP in IP tunnel with IPsec Transport Mode [RFC5566] */
#define BGP_EXT_COM_TUNNEL_MPLSIP       6       /* MPLS-in-IP tunnel with IPsec Transport Mode [RFC5566] */
#define BGP_EXT_COM_TUNNEL_IPIP         7       /* IP in IP [RFC5512] */
#define BGP_EXT_COM_TUNNEL_VXLAN        8       /* VXLAN Encapsulation [draft-sd-l2vpn-evpn-overlay] */
#define BGP_EXT_COM_TUNNEL_NVGRE        9       /* NVGRE Encapsulation [draft-sd-l2vpn-evpn-overlay] */
#define BGP_EXT_COM_TUNNEL_MPLS         10      /* MPLS Encapsulation [draft-sd-l2vpn-evpn-overlay] */
#define BGP_EXT_COM_TUNNEL_MPLSGRE      11      /* MPLS in GRE Encapsulation [draft-sd-l2vpn-evpn-overlay] */
#define BGP_EXT_COM_TUNNEL_VXLANGPE     12      /* VxLAN GPE Encapsulation [draft-sd-l2vpn-evpn-overlay] */
#define BGP_EXT_COM_TUNNEL_MPLSUDP      13      /* MPLS in UDP Encapsulation [draft-ietf-l3vpn-end-system] */

/* Non-Transitive Opaque Extended Community Sub-Types */

#define BGP_EXT_COM_STYPE_OPA_OR_VAL_ST 0x00    /* BGP Origin Validation State [draft-ietf-sidr-origin-validation-signaling] */

/* BGP Generic Transitive Experimental Use Extended Community Sub-Types */

#define BGP_EXT_COM_STYPE_EXP_OSPF_RT   0x00    /* OSPF Route Type, deprecated [RFC4577] */
#define BGP_EXT_COM_STYPE_EXP_OSPF_RID  0x01    /* OSPF Router ID, deprecated [RFC4577] */
#define BGP_EXT_COM_STYPE_EXP_SEC_GROUP 0x04    /* Security Group [https://github.com/Juniper/contrail-controller/wiki/BGP-Extended-Communities#security-group] */
#define BGP_EXT_COM_STYPE_EXP_OSPF_DID  0x05    /* OSPF Domain ID, deprecated [RFC4577] */
#define BGP_EXT_COM_STYPE_EXP_F_TR      0x06    /* Flow spec traffic-rate [RFC5575] */
#define BGP_EXT_COM_STYPE_EXP_F_TA      0x07    /* Flow spec traffic-action [RFC5575] */
#define BGP_EXT_COM_STYPE_EXP_F_RED     0x08    /* Flow spec redirect [RFC5575] */
#define BGP_EXT_COM_STYPE_EXP_F_RMARK   0x09    /* Flow spec traffic-remarking [RFC5575] */
#define BGP_EXT_COM_STYPE_EXP_L2        0x0a    /* Layer2 Info Extended Community [RFC4761] */
#define BGP_EXT_COM_STYPE_EXP_ETREE     0x0b    /* E-Tree Info [RFC7796] */
#define BGP_EXT_COM_STYPE_EXP_TAG       0x84    /* Tag [https://github.com/Juniper/contrail-controller/wiki/BGP-Extended-Communities#tag] */
#define BGP_EXT_COM_STYPE_EXP_SUB_CLUS  0x85    /* Origin Sub-Cluster [https://github.com/robric/wiki-contrail-controller/blob/master/BGP-Extended-Communities.md] */

/* BGP Generic Transitive Experimental Use Extended Community Part 2 */

#define BGP_EXT_COM_STYPE_EXP_2_FLOW_RED 0x08

/* BGP Generic Transitive Experimental Use Extended Community Part 3 */

#define BGP_EXT_COM_STYPE_EXP_3_SEC_GROUP 0x04
#define BGP_EXT_COM_STYPE_EXP_3_FLOW_RED  0x08
#define BGP_EXT_COM_STYPE_EXP_3_TAG4      0x84
#define BGP_EXT_COM_STYPE_EXP_3_SUB_CLUS  0x85

/* BGP Transitive Experimental EIGRP route attribute Sub-Types */

#define BGP_EXT_COM_STYPE_EXP_EIGRP_FT  0x00    /* Route Flags, Route Tag */
#define BGP_EXT_COM_STYPE_EXP_EIGRP_AD  0x01    /* ASN, Delay */
#define BGP_EXT_COM_STYPE_EXP_EIGRP_RHB 0x02    /* Reliability, Hop Count, Bandwidth */
#define BGP_EXT_COM_STYPE_EXP_EIGRP_LM  0x03    /* Load, MTU */
#define BGP_EXT_COM_STYPE_EXP_EIGRP_EAR 0x04    /* External ASN, RID of the redistributing router */
#define BGP_EXT_COM_STYPE_EXP_EIGRP_EPM 0x05    /* External Protocol ID, metric */
#define BGP_EXT_COM_STYPE_EXP_EIGRP_RID 0x06    /* Originating EIGRP Router ID of the route */

#define BGP_EXT_COM_EXP_EIGRP_FLAG_RT   0x8000  /* Route flag - Internal/External */


/* according to IANA's number assignment at: http://www.iana.org/assignments/bgp-extended-communities */

                                        /* RFC 4360 */
#define BGP_EXT_COM_RT_AS2        0x0002  /* Route Target,Format AS(2bytes):AN(4bytes) */
#define BGP_EXT_COM_RT_IP4        0x0102  /* Route Target,Format IP address:AN(2bytes) */
#define BGP_EXT_COM_RT_AS4        0x0202  /* Route Target,Format AS(4bytes):AN(2bytes) */

/* extended community option flow flec action bit S and T */
#define BGP_EXT_COM_FSPEC_ACT_S 0x02
#define BGP_EXT_COM_FSPEC_ACT_T 0x01

/* extended community l2vpn flags */

#define BGP_EXT_COM_L2_FLAG_D     0x80
#define BGP_EXT_COM_L2_FLAG_Z1    0x40
#define BGP_EXT_COM_L2_FLAG_F     0x20
#define BGP_EXT_COM_L2_FLAG_Z345  0x1c
#define BGP_EXT_COM_L2_FLAG_C     0x02
#define BGP_EXT_COM_L2_FLAG_S     0x01

/* extended community E-Tree Info flags */

#define BGP_EXT_COM_ETREE_FLAG_RESERVED   0xFFFC
#define BGP_EXT_COM_ETREE_FLAG_P          0x0002
#define BGP_EXT_COM_ETREE_FLAG_V          0x0001

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
#define BGP_OSPF_RTYPE_METRIC_TYPE 0x1 /* Type-1 (clear) or Type-2 (set) external metric */

/* Extended community & Route distinguisher formats */
#define FORMAT_AS2_LOC      0x00    /* Format AS(2bytes):AN(4bytes) */
#define FORMAT_IP_LOC       0x01    /* Format IP address:AN(2bytes) */
#define FORMAT_AS4_LOC      0x02    /* Format AS(4bytes):AN(2bytes) */

/* RFC 4760 subsequent address family numbers (last updated 2021-03-23)
 * https://www.iana.org/assignments/safi-namespace/safi-namespace.xhtml
 */
#define SAFNUM_UNICAST          1  /* RFC4760 */
#define SAFNUM_MULCAST          2  /* RFC4760 */
#define SAFNUM_UNIMULC          3  /* Deprecated, see RFC4760 */
#define SAFNUM_MPLS_LABEL       4  /* RFC8277 */
#define SAFNUM_MCAST_VPN        5  /* RFC6514 */
#define SAFNUM_MULTISEG_PW      6  /* RFC7267 */
#define SAFNUM_ENCAPSULATION    7  /* RFC5512, obsolete and never deployed, see draft-ietf-idr-tunnel-encaps-22 */
#define SAFNUM_MCAST_VPLS       8  /* RFC7117 */
#define SAFNUM_TUNNEL          64  /* draft-nalawade-kapoor-tunnel-safi-05.txt (Expired) */
#define SAFNUM_VPLS            65  /* RFC4761, RFC6074 */
#define SAFNUM_MDT             66  /* RFC6037 */
#define SAFNUM_4OVER6          67  /* RFC5747 */
#define SAFNUM_6OVER4          68  /* Never specified? Cf. RFC5747 */
#define SAFNUM_L1VPN           69  /* RFC5195 */
#define SAFNUM_EVPN            70  /* RFC7432 */
#define SAFNUM_BGP_LS          71  /* RFC7752 */
#define SAFNUM_BGP_LS_VPN      72  /* RFC7752 */
#define SAFNUM_SR_POLICY       73  /* draft-ietf-idr-segment-routing-te-policy-11 */
#define SAFNUM_SD_WAN          74  /* draft-dunbar-idr-sdwan-port-safi-06, expired */
#define SAFNUM_RPD             75  /* draft-ietf-idr-rpd-10 */
#define SAFNUM_CT              76  /* draft-kaliraj-idr-bgp-classful-transport-planes-07 */
#define SAFNUM_FLOWSPEC        77  /* draft-ietf-idr-flowspec-nvo3-13 */
#define SAFNUM_MCAST_TREE      78  /* draft-ietf-bess-bgp-multicast-03 */
#define SAFNUM_LAB_VPNUNICAST 128  /* RFC4364, RFC8277 */
#define SAFNUM_LAB_VPNMULCAST 129  /* RFC6513, RFC6514 */
#define SAFNUM_LAB_VPNUNIMULC 130  /* Obsolete and reserved, see RFC4760 */
#define SAFNUM_ROUTE_TARGET   132  /* RFC 4684 Constrained Route Distribution for BGP/MPLS IP VPN */
#define SAFNUM_FSPEC_RULE     133  /* RFC 8955 BGP flow spec SAFI */
#define SAFNUM_FSPEC_VPN_RULE 134  /* RFC 8955 BGP flow spec SAFI VPN */
#define SAFNUM_L3VPN          140  /* Withdrawn, draft-ietf-l3vpn-bgpvpn-auto-09 */

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
#define TUNNEL_TYPE_TTE          3
#define TUNNEL_TYPE_IPSEC_IN_TM  4
#define TUNNEL_TYPE_IP_IN_IP_IPSEC 5
#define TUNNEL_TYPE_MPLS_IN_IP_IPSEC 6
#define TUNNEL_TYPE_IP_IN_IP     7
#define TUNNEL_TYPE_VXLAN        8
#define TUNNEL_TYPE_NVGRE        9
#define TUNNEL_TYPE_MPLS         10
#define TUNNEL_TYPE_MPLS_IN_GRE  11
#define TUNNEL_TYPE_VXLAN_GPE    12
#define TUNNEL_TYPE_MPLS_IN_UDP  13
#define TUNNEL_TYPE_IPV6_TUNNEL  14
#define TUNNEL_TYPE_SR_TE_POLICY 15
#define TUNNEL_TYPE_BARE         16
#define TUNNEL_TYPE_SR_TUNNEL    17

/*RFC 6514 PMSI Tunnel Types */
#define PMSI_TUNNEL_NOPRESENT    0
#define PMSI_TUNNEL_RSVPTE_P2MP  1
#define PMSI_TUNNEL_MLDP_P2MP    2
#define PMSI_TUNNEL_PIMSSM       3
#define PMSI_TUNNEL_PIMSM        4
#define PMSI_TUNNEL_BIDIR_PIM    5
#define PMSI_TUNNEL_INGRESS      6
#define PMSI_TUNNEL_MLDP_MP2MP   7

#define PMSI_MLDP_FEC_TYPE_RSVD         0
#define PMSI_MLDP_FEC_TYPE_GEN_LSP      1
#define PMSI_MLDP_FEC_TYPE_EXT_TYPE     255
#define PMSI_MLDP_FEC_ETYPE_RSVD        0

/* RFC 7311 AIGP types */
#define AIGP_TLV_TYPE           1

/* RFC 5512/5640 Sub-TLV Types */
#define TUNNEL_SUBTLV_ENCAPSULATION 1
#define TUNNEL_SUBTLV_PROTO_TYPE    2
#define TUNNEL_SUBTLV_IPSEC_TA      3
#define TUNNEL_SUBTLV_COLOR         4
#define TUNNEL_SUBTLV_LOAD_BALANCE  5
#define TUNNEL_SUBTLV_REMOTE_ENDPOINT 6
#define TUNNEL_SUBTLV_IPV4_DS_FIELD 7
#define TUNNEL_SUBTLV_UDP_DST_PORT  8
#define TUNNEL_SUBTLV_EMBEDDED_LABEL 9
#define TUNNEL_SUBTLV_MPLS_LABEL    10
#define TUNNEL_SUBTLV_PREFIX_SID    11
#define TUNNEL_SUBTLV_PREFERENCE    12
#define TUNNEL_SUBTLV_BINDING_SID   13
#define TUNNEL_SUBTLV_ENLP          14
#define TUNNEL_SUBTLV_PRIORITY      15
#define TUNNEL_SUBTLV_SEGMENT_LIST  128
#define TUNNEL_SUBTLV_POLICY_NAME   129

/* BGP Tunnel SubTLV VXLAN Flags bitmask */
#define TUNNEL_SUBTLV_VXLAN_VALID_VNID          0x80
#define TUNNEL_SUBTLV_VXLAN_VALID_MAC           0x40
#define TUNNEL_SUBTLV_VXLAN_RESERVED            0x3F

/* BGP Tunnel SubTLV VXLAN GPE Flags bitmask */
#define TUNNEL_SUBTLV_VXLAN_GPE_VERSION         0xC0
#define TUNNEL_SUBTLV_VXLAN_GPE_VALID_VNID      0x20
#define TUNNEL_SUBTLV_VXLAN_GPE_RESERVED        0x1F

/* BGP Tunnel SubTLV NVGRE Flags bitmask */
#define TUNNEL_SUBTLV_NVGRE_VALID_VNID          0x80
#define TUNNEL_SUBTLV_NVGRE_VALID_MAC           0x40
#define TUNNEL_SUBTLV_NVGRE_RESERVED            0x3F

/* BGP Tunnel SubTLV Binding SID Flags bitmask */
#define TUNNEL_SUBTLV_BINDING_SPECIFIED         0x80
#define TUNNEL_SUBTLV_BINDING_INVALID           0x40
#define TUNNEL_SUBTLV_BINDING_RESERVED          0x3F

/* BGP Segment List SubTLV Types */
#define TUNNEL_SUBTLV_SEGMENT_LIST_SUB_TYPE_A   1
#define TUNNEL_SUBTLV_SEGMENT_LIST_SUB_TYPE_B   2
#define TUNNEL_SUBTLV_SEGMENT_LIST_SUB_TYPE_C   3
#define TUNNEL_SUBTLV_SEGMENT_LIST_SUB_TYPE_D   4
#define TUNNEL_SUBTLV_SEGMENT_LIST_SUB_TYPE_E   5
#define TUNNEL_SUBTLV_SEGMENT_LIST_SUB_TYPE_F   6
#define TUNNEL_SUBTLV_SEGMENT_LIST_SUB_TYPE_G   7
#define TUNNEL_SUBTLV_SEGMENT_LIST_SUB_TYPE_H   8
#define TUNNEL_SUBTLV_SEGMENT_LIST_SUB_TYPE_WEIGHT   9
#define TUNNEL_SUBTLV_SEGMENT_LIST_SUB_TYPE_I   10
#define TUNNEL_SUBTLV_SEGMENT_LIST_SUB_TYPE_J   11
#define TUNNEL_SUBTLV_SEGMENT_LIST_SUB_TYPE_K   12

/* BGP Tunnel SubTLV Segment List SubTLV Flags bitmask */
#define TUNNEL_SUBTLV_SEGMENT_LIST_SUB_VERIFICATION      0x80
#define TUNNEL_SUBTLV_SEGMENT_LIST_SUB_ALGORITHM         0x40
#define TUNNEL_SUBTLV_SEGMENT_LIST_SUB_RESERVED          0x3F

/* Link-State NLRI types */
#define LINK_STATE_NODE_NLRI                    1
#define LINK_STATE_LINK_NLRI                    2
#define LINK_STATE_IPV4_TOPOLOGY_PREFIX_NLRI    3
#define LINK_STATE_IPV6_TOPOLOGY_PREFIX_NLRI    4

/* Link-State NLRI Protocol-ID values */
#define BGP_LS_NLRI_PROTO_ID_UNKNOWN       0
#define BGP_LS_NLRI_PROTO_ID_IS_IS_LEVEL_1 1
#define BGP_LS_NLRI_PROTO_ID_IS_IS_LEVEL_2 2
#define BGP_LS_NLRI_PROTO_ID_OSPF          3
#define BGP_LS_NLRI_PROTO_ID_DIRECT        4
#define BGP_LS_NLRI_PROTO_ID_STATIC        5
#define BGP_LS_NLRI_PROTO_ID_BGP           7

/* Link-State routing universes */
#define BGP_LS_NLRI_ROUTING_UNIVERSE_LEVEL_3     0
#define BGP_LS_NLRI_ROUTING_UNIVERSE_LEVEL_1     1

#define BGP_LS_PREFIX_OSPF_ROUTE_TYPE_UNKNOWN    0
#define BGP_LS_PREFIX_OSPF_ROUTE_TYPE_INTRA_AREA 1
#define BGP_LS_PREFIX_OSPF_ROUTE_TYPE_INTER_AREA 2
#define BGP_LS_PREFIX_OSPF_ROUTE_TYPE_EXTERNAL_1 3
#define BGP_LS_PREFIX_OSPF_ROUTE_TYPE_EXTERNAL_2 4
#define BGP_LS_PREFIX_OSPF_ROUTE_TYPE_NSSA_1     5
#define BGP_LS_PREFIX_OSPF_ROUTE_TYPE_NSSA_2     6

/* RFC7752 */
#define BGP_NLRI_TLV_LOCAL_NODE_DESCRIPTORS         256
#define BGP_NLRI_TLV_REMOTE_NODE_DESCRIPTORS        257
#define BGP_NLRI_TLV_LINK_LOCAL_REMOTE_IDENTIFIERS  258
#define BGP_NLRI_TLV_IPV4_INTERFACE_ADDRESS         259
#define BGP_NLRI_TLV_IPV4_NEIGHBOR_ADDRESS          260
#define BGP_NLRI_TLV_IPV6_INTERFACE_ADDRESS         261
#define BGP_NLRI_TLV_IPV6_NEIGHBOR_ADDRESS          262
#define BGP_NLRI_TLV_MULTI_TOPOLOGY_ID              263
#define BGP_NLRI_TLV_OSPF_ROUTE_TYPE                264
#define BGP_NLRI_TLV_IP_REACHABILITY_INFORMATION    265
#define BGP_NLRI_TLV_NODE_MSD                       266
#define BGP_NLRI_TLV_LINK_MSD                       267

#define BGP_NLRI_TLV_AUTONOMOUS_SYSTEM              512
#define BGP_NLRI_TLV_BGP_LS_IDENTIFIER              513
#define BGP_NLRI_TLV_AREA_ID                        514
#define BGP_NLRI_TLV_IGP_ROUTER_ID                  515
#define BGP_NLRI_TLV_BGP_ROUTER_ID                  516

#define BGP_NLRI_TLV_NODE_FLAG_BITS                 1024
#define BGP_NLRI_TLV_OPAQUE_NODE_PROPERTIES         1025
#define BGP_NLRI_TLV_NODE_NAME                      1026
#define BGP_NLRI_TLV_IS_IS_AREA_IDENTIFIER          1027
#define BGP_NLRI_TLV_IPV4_ROUTER_ID_OF_LOCAL_NODE   1028
#define BGP_NLRI_TLV_IPV6_ROUTER_ID_OF_LOCAL_NODE   1029
#define BGP_NLRI_TLV_IPV4_ROUTER_ID_OF_REMOTE_NODE  1030
#define BGP_NLRI_TLV_IPV6_ROUTER_ID_OF_REMOTE_NODE  1031

#define BGP_NLRI_TLV_ADMINISTRATIVE_GROUP_COLOR     1088
#define BGP_NLRI_TLV_MAX_LINK_BANDWIDTH             1089
#define BGP_NLRI_TLV_MAX_RESERVABLE_LINK_BANDWIDTH  1090
#define BGP_NLRI_TLV_UNRESERVED_BANDWIDTH           1091
#define BGP_NLRI_TLV_TE_DEFAULT_METRIC              1092
#define BGP_NLRI_TLV_LINK_PROTECTION_TYPE           1093
#define BGP_NLRI_TLV_MPLS_PROTOCOL_MASK             1094
#define BGP_NLRI_TLV_METRIC                         1095
#define BGP_NLRI_TLV_SHARED_RISK_LINK_GROUP         1096
#define BGP_NLRI_TLV_OPAQUE_LINK_ATTRIBUTE          1097
#define BGP_NLRI_TLV_LINK_NAME_ATTRIBUTE            1098

#define BGP_NLRI_TLV_IGP_FLAGS                      1152
#define BGP_NLRI_TLV_ROUTE_TAG                      1153
#define BGP_NLRI_TLV_EXTENDED_TAG                   1154
#define BGP_NLRI_TLV_PREFIX_METRIC                  1155
#define BGP_NLRI_TLV_OSPF_FORWARDING_ADDRESS        1156
#define BGP_NLRI_TLV_OPAQUE_PREFIX_ATTRIBUTE        1157
#define BGP_NLRI_TLV_EXTENDED_ADMINISTRATIVE_GROUP  1173


/* Link-State NLRI TLV lengths */
#define BGP_NLRI_TLV_LEN_AUTONOMOUS_SYSTEM              4
#define BGP_NLRI_TLV_LEN_BGP_LS_IDENTIFIER              4
#define BGP_NLRI_TLV_LEN_AREA_ID                        4
#define BGP_NLRI_TLV_LEN_IPV4_ROUTER_ID                 4
#define BGP_NLRI_TLV_LEN_IPV6_ROUTER_ID                 16
#define BGP_NLRI_TLV_LEN_IPV4_ROUTER_ID_OF_LOCAL_NODE   BGP_NLRI_TLV_LEN_IPV4_ROUTER_ID
#define BGP_NLRI_TLV_LEN_IPV6_ROUTER_ID_OF_LOCAL_NODE   BGP_NLRI_TLV_LEN_IPV6_ROUTER_ID
#define BGP_NLRI_TLV_LEN_IPV4_ROUTER_ID_OF_REMOTE_NODE  BGP_NLRI_TLV_LEN_IPV4_ROUTER_ID
#define BGP_NLRI_TLV_LEN_IPV6_ROUTER_ID_OF_REMOTE_NODE  BGP_NLRI_TLV_LEN_IPV6_ROUTER_ID
#define BGP_NLRI_TLV_LEN_LINK_LOCAL_REMOTE_IDENTIFIERS  8
#define BGP_NLRI_TLV_LEN_IPV4_INTERFACE_ADDRESS         4
#define BGP_NLRI_TLV_LEN_IPV4_NEIGHBOR_ADDRESS          4
#define BGP_NLRI_TLV_LEN_IPV6_INTERFACE_ADDRESS         16
#define BGP_NLRI_TLV_LEN_IPV6_NEIGHBOR_ADDRESS          16
#define BGP_NLRI_TLV_LEN_MULTI_TOPOLOGY_ID              2
#define BGP_NLRI_TLV_LEN_ADMINISTRATIVE_GROUP_COLOR     4
#define BGP_NLRI_TLV_LEN_MAX_LINK_BANDWIDTH             4
#define BGP_NLRI_TLV_LEN_MAX_RESERVABLE_LINK_BANDWIDTH  4
#define BGP_NLRI_TLV_LEN_UNRESERVED_BANDWIDTH           32
#define BGP_NLRI_TLV_LEN_TE_DEFAULT_METRIC_OLD          3
#define BGP_NLRI_TLV_LEN_TE_DEFAULT_METRIC_NEW          4
#define BGP_NLRI_TLV_LEN_LINK_PROTECTION_TYPE           2
#define BGP_NLRI_TLV_LEN_MPLS_PROTOCOL_MASK             1
#define BGP_NLRI_TLV_LEN_MAX_METRIC                     3
#define BGP_NLRI_TLV_LEN_IGP_FLAGS                      1
#define BGP_NLRI_TLV_LEN_PREFIX_METRIC                  4
#define BGP_NLRI_TLV_LEN_NODE_FLAG_BITS                 1

/* draft-gredler-idr-bgp-ls-segment-routing-ext-01 */
#define BGP_LS_SR_TLV_SR_CAPABILITY                 1034
#define BGP_LS_SR_TLV_SR_ALGORITHM                  1035
#define BGP_LS_SR_TLV_SR_LOCAL_BLOCK                1036
#define BGP_LS_SR_TLV_FLEX_ALGO_DEF                 1039
#define BGP_LS_SR_TLV_FLEX_ALGO_EXC_ANY_AFFINITY    1040
#define BGP_LS_SR_TLV_FLEX_ALGO_INC_ANY_AFFINITY    1041
#define BGP_LS_SR_TLV_FLEX_ALGO_INC_ALL_AFFINITY    1042
#define BGP_LS_SR_TLV_ADJ_SID                       1099
#define BGP_LS_SR_TLV_LAN_ADJ_SID                   1100
#define BGP_LS_SR_TLV_PEER_NODE_SID                 1101
#define BGP_LS_SR_TLV_PEER_ADJ_SID                  1102
#define BGP_LS_SR_TLV_PEER_SET_SID                  1103
#define BGP_LS_SR_TLV_PREFIX_SID                    1158
#define BGP_LS_SR_TLV_RANGE                         1159
#define BGP_LS_SR_TLV_BINDING_SID                   1160
#define BGP_LS_SR_SUBTLV_BINDING_SID_LABEL          1161
#define BGP_LS_SR_SUBTLV_BINDING_ERO_METRIC         1162
#define BGP_LS_SR_SUBTLV_BINDING_IPV4_ERO           1163
#define BGP_LS_SR_SUBTLV_BINDING_IPV6_ERO           1164
#define BGP_LS_SR_SUBTLV_BINDING_UNNUM_IFID_ERO     1165
#define BGP_LS_SR_SUBTLV_BINDING_IPV4_BAK_ERO       1166
#define BGP_LS_SR_SUBTLV_BINDING_IPV6_BAK_ERO       1167
#define BGP_LS_SR_SUBTLV_BINDING_UNNUM_IFID_BAK_ERO 1168
#define BGP_LS_SR_TLV_PREFIX_ATTR_FLAGS             1170

/* RFC8571 BGP-LS Advertisement of IGP TE Metric Extensions */
#define BGP_LS_IGP_TE_METRIC_DELAY                  1114
#define BGP_LS_IGP_TE_METRIC_DELAY_MIN_MAX          1115
#define BGP_LS_IGP_TE_METRIC_DELAY_VARIATION        1116
#define BGP_LS_IGP_TE_METRIC_LOSS                   1117
#define BGP_LS_IGP_TE_METRIC_BANDWIDTH_RESIDUAL     1118
#define BGP_LS_IGP_TE_METRIC_BANDWIDTH_AVAILABLE    1119
#define BGP_LS_IGP_TE_METRIC_BANDWIDTH_UTILIZED     1120

#define BGP_LS_IGP_TE_METRIC_FLAG_A                 0x80
#define BGP_LS_IGP_TE_METRIC_FLAG_RESERVED          0x7F

/* draft-ietf-idr-bgp-ls-app-specific-attr-07 */
#define BGP_LS_APP_SPEC_LINK_ATTR                   1122

/* Prefix-SID TLV flags, draft-gredler-idr-bgp-ls-segment-routing-ext-01:

                             0  1  2  3  4  5  6  7
                            +--+--+--+--+--+--+--+--+
   if Protocol-ID is IS-IS  |R |N |P |E |V |L |  |  |
                            +--+--+--+--+--+--+--+--+

                             0  1  2  3  4  5  6  7
                            +--+--+--+--+--+--+--+--+
   if Protocol-ID is OSPF   |  |NP|M |E |V |L |  |  |
                            +--+--+--+--+--+--+--+--+
*/
#define BGP_LS_SR_PREFIX_SID_FLAG_R  0x80
#define BGP_LS_SR_PREFIX_SID_FLAG_N  0x40
#define BGP_LS_SR_PREFIX_SID_FLAG_NP 0x40
#define BGP_LS_SR_PREFIX_SID_FLAG_P  0x20
#define BGP_LS_SR_PREFIX_SID_FLAG_M  0x20
#define BGP_LS_SR_PREFIX_SID_FLAG_E  0x10
#define BGP_LS_SR_PREFIX_SID_FLAG_V  0x08
#define BGP_LS_SR_PREFIX_SID_FLAG_L  0x04

/* Adjacency-SID TLV flags, draft-gredler-idr-bgp-ls-segment-routing-ext-01:

                             0  1  2  3  4  5  6  7
                            +--+--+--+--+--+--+--+--+
   if Protocol-ID is IS-IS  |F |B |V |L |S |  |  |  |
                            +--+--+--+--+--+--+--+--+

                             0  1  2  3  4  5  6  7
                            +--+--+--+--+--+--+--+--+
   if Protocol-ID is OSPF   |B |V |L |S |  |  |  |  |
                            +--+--+--+--+--+--+--+--+
*/
#define BGP_LS_SR_ADJACENCY_SID_FLAG_FI 0x80
#define BGP_LS_SR_ADJACENCY_SID_FLAG_BO 0x80
#define BGP_LS_SR_ADJACENCY_SID_FLAG_BI 0x40
#define BGP_LS_SR_ADJACENCY_SID_FLAG_VO 0x40
#define BGP_LS_SR_ADJACENCY_SID_FLAG_VI 0x20
#define BGP_LS_SR_ADJACENCY_SID_FLAG_LO 0x20
#define BGP_LS_SR_ADJACENCY_SID_FLAG_LI 0x10
#define BGP_LS_SR_ADJACENCY_SID_FLAG_SO 0x10
#define BGP_LS_SR_ADJACENCY_SID_FLAG_SI 0x08

/* BGP Peering SIDs TLV flags, rfc9086:

   0  1  2  3  4  5  6  7
   +--+--+--+--+--+--+--+--+
   |V |L |B |P |  |  |  |  | rfc9086
   +--+--+--+--+--+--+--+--+
*/
#define BGP_LS_SR_PEER_SID_FLAG_V   0x80
#define BGP_LS_SR_PEER_SID_FLAG_L   0x40
#define BGP_LS_SR_PEER_SID_FLAG_B   0x20
#define BGP_LS_SR_PEER_SID_FLAG_P   0x10

/* SR-Capabilities TLV flags, draft-gredler-idr-bgp-ls-segment-routing-ext-01:

                             0  1  2  3  4  5  6  7
                            +--+--+--+--+--+--+--+--+
   if Protocol-ID is IS-IS  |I |V |H |  |  |  |  |  |
                            +--+--+--+--+--+--+--+--+
*/
#define BGP_LS_SR_CAPABILITY_FLAG_I 0x80
#define BGP_LS_SR_CAPABILITY_FLAG_V 0x40
#define BGP_LS_SR_CAPABILITY_FLAG_H 0x20

/* Prefix Attribute Flags TLV flags, rfc9085:

                             0  1  2  3  4  5  6  7
                            +--+--+--+--+--+--+--+--+
   if Protocol-ID is IS-IS  |X |R |N |E |  |  |  |  | rfc7794,rfc9088
                            +--+--+--+--+--+--+--+--+

                             0  1  2  3  4  5  6  7
                            +--+--+--+--+--+--+--+--+
   if Protocol-ID is OSPF   |A |N |E |  |  |  |  |  | rfc7684,rfc9089
                            +--+--+--+--+--+--+--+--+
*/
#define BGP_LS_SR_PREFIX_ATTR_FLAGS_FLAG_XI 0x80
#define BGP_LS_SR_PREFIX_ATTR_FLAGS_FLAG_RI 0x40
#define BGP_LS_SR_PREFIX_ATTR_FLAGS_FLAG_NI 0x20
#define BGP_LS_SR_PREFIX_ATTR_FLAGS_FLAG_EI 0x10
#define BGP_LS_SR_PREFIX_ATTR_FLAGS_FLAG_AO 0x80
#define BGP_LS_SR_PREFIX_ATTR_FLAGS_FLAG_NO 0x40
#define BGP_LS_SR_PREFIX_ATTR_FLAGS_FLAG_EO 0x20

/* Link Attribute Application Identifiers, https://www.iana.org/assignments/igp-parameters/igp-parameters.xhtml:

   0  1  2  3  4  5  6  7
   +--+--+--+--+--+--+--+--+
   |R |S |F |X |  |  |  |  | rfc8919,rfc8920
   +--+--+--+--+--+--+--+--+
*/
#define BGP_LS_APP_SPEC_LINK_ATTRS_SABM_R  0x80000000
#define BGP_LS_APP_SPEC_LINK_ATTRS_SABM_S  0x40000000
#define BGP_LS_APP_SPEC_LINK_ATTRS_SABM_F  0x20000000
#define BGP_LS_APP_SPEC_LINK_ATTRS_SABM_X  0x10000000


/* BGP Prefix-SID TLV type */
#define BGP_PREFIX_SID_TLV_LABEL_INDEX     1 /* Label-Index [RFC8669]                           */
#define BGP_PREFIX_SID_TLV_2               2 /* Deprecated [RFC8669]                            */
#define BGP_PREFIX_SID_TLV_ORIGINATOR_SRGB 3 /* Originator SRGB [RFC8669]                       */
#define BGP_PREFIX_SID_TLV_4               4 /* Deprecated [draft-ietf-bess-srv6-services]      */
#define BGP_PREFIX_SID_TLV_SRV6_L3_SERVICE 5 /* SRv6 L3 Service [draft-ietf-bess-srv6-services] */
#define BGP_PREFIX_SID_TLV_SRV6_L2_SERVICE 6 /* SRv6 L2 Service [draft-ietf-bess-srv6-services] */

/* BGP_PREFIX_SID TLV lengths   */
#define BGP_PREFIX_SID_TLV_LEN_LABEL_INDEX 7

/* BGP SRv6 Service Sub-TLV */
#define SRV6_SERVICE_SRV6_SID_INFORMATION 1

/* BGP SRv6 Service Data Sub-Sub-TLV */
#define SRV6_SERVICE_DATA_SRV6_SID_STRUCTURE 1

/* SRv6 Endpoint behavior */
#define SRV6_ENDPOINT_BEHAVIOR_END                    0x0001 /* End [draft-ietf-spring-srv6-network-programming]                                         */
#define SRV6_ENDPOINT_BEHAVIOR_END_PSP                0x0002 /* End with PSP [draft-ietf-spring-srv6-network-programming]                                */
#define SRV6_ENDPOINT_BEHAVIOR_END_USP                0x0003 /* End with USP [draft-ietf-spring-srv6-network-programming]                                */
#define SRV6_ENDPOINT_BEHAVIOR_END_PSP_USP            0x0004 /* End with PSP & USP [draft-ietf-spring-srv6-network-programming]                          */
#define SRV6_ENDPOINT_BEHAVIOR_END_X                  0x0005 /* End.X [draft-ietf-spring-srv6-network-programming]                                       */
#define SRV6_ENDPOINT_BEHAVIOR_END_X_PSP              0x0006 /* End.X with PSP [draft-ietf-spring-srv6-network-programming]                              */
#define SRV6_ENDPOINT_BEHAVIOR_END_X_USP              0x0007 /* End.X with UPS [draft-ietf-spring-srv6-network-programming]                              */
#define SRV6_ENDPOINT_BEHAVIOR_END_X_PSP_USP          0x0008 /* End.X with PSP & USP [draft-ietf-spring-srv6-network-programming]                        */
#define SRV6_ENDPOINT_BEHAVIOR_END_T                  0x0009 /* End.T [draft-ietf-spring-srv6-network-programming]                                       */
#define SRV6_ENDPOINT_BEHAVIOR_END_T_PSP              0x000A /* End.T with PSP [draft-ietf-spring-srv6-network-programming]                              */
#define SRV6_ENDPOINT_BEHAVIOR_END_T_USP              0x000B /* End.T with USP [draft-ietf-spring-srv6-network-programming]                              */
#define SRV6_ENDPOINT_BEHAVIOR_END_T_PSP_USP          0x000C /* End.T with PSP & USP [draft-ietf-spring-srv6-network-programming]                        */
#define SRV6_ENDPOINT_BEHAVIOR_END_B6_ENCAPS          0x000E /* End.B6.Encaps [draft-ietf-spring-srv6-network-programming]                               */
#define SRV6_ENDPOINT_BEHAVIOR_END_BM                 0x000F /* End.BM [draft-ietf-spring-srv6-network-programming]                                      */
#define SRV6_ENDPOINT_BEHAVIOR_END_DX6                0x0010 /* End.DX6 [draft-ietf-spring-srv6-network-programming]                                     */
#define SRV6_ENDPOINT_BEHAVIOR_END_DX4                0x0011 /* End.DX4 [draft-ietf-spring-srv6-network-programming]                                     */
#define SRV6_ENDPOINT_BEHAVIOR_END_DT6                0x0012 /* End.DT6 [draft-ietf-spring-srv6-network-programming]                                     */
#define SRV6_ENDPOINT_BEHAVIOR_END_DT4                0x0013 /* End.DT4 [draft-ietf-spring-srv6-network-programming]                                     */
#define SRV6_ENDPOINT_BEHAVIOR_END_DT46               0x0014 /* End.DT46 [draft-ietf-spring-srv6-network-programming]                                    */
#define SRV6_ENDPOINT_BEHAVIOR_END_DX2                0x0015 /* End.DX2 [draft-ietf-spring-srv6-network-programming]                                     */
#define SRV6_ENDPOINT_BEHAVIOR_END_DX2V               0x0016 /* End.DX2V [draft-ietf-spring-srv6-network-programming]                                    */
#define SRV6_ENDPOINT_BEHAVIOR_END_DT2U               0x0017 /* End.DX2U [draft-ietf-spring-srv6-network-programming]                                    */
#define SRV6_ENDPOINT_BEHAVIOR_END_DT2M               0x0018 /* End.DT2M [draft-ietf-spring-srv6-network-programming]                                    */
#define SRV6_ENDPOINT_BEHAVIOR_END_B6_ENCAPS_RED      0x001B /* End.B6.Encaps.Red [draft-ietf-spring-srv6-network-programming]                           */
#define SRV6_ENDPOINT_BEHAVIOR_END_USD                0x001C /* End with USD [draft-ietf-spring-srv6-network-programming]                                */
#define SRV6_ENDPOINT_BEHAVIOR_END_PSP_USD            0x001D /* End with PSP & USD [draft-ietf-spring-srv6-network-programming]                          */
#define SRV6_ENDPOINT_BEHAVIOR_END_USP_USD            0x001E /* End with USP & USD [draft-ietf-spring-srv6-network-programming]                          */
#define SRV6_ENDPOINT_BEHAVIOR_END_PSP_USP_USD        0x001F /* End with PSP, USP & USD [draft-ietf-spring-srv6-network-programming]                     */
#define SRV6_ENDPOINT_BEHAVIOR_END_X_USD              0x0020 /* End.X with USD [draft-ietf-spring-srv6-network-programming]                              */
#define SRV6_ENDPOINT_BEHAVIOR_END_X_PSP_USD          0x0021 /* End.X with PSP & USD [draft-ietf-spring-srv6-network-programming]                        */
#define SRV6_ENDPOINT_BEHAVIOR_END_X_USP_USD          0x0022 /* End.X with USP & USD [draft-ietf-spring-srv6-network-programming]                        */
#define SRV6_ENDPOINT_BEHAVIOR_END_X_PSP_USP_USD      0x0023 /* End.X with PSP, USP & USD [draft-ietf-spring-srv6-network-programming]                   */
#define SRV6_ENDPOINT_BEHAVIOR_END_T_USD              0x0024 /* End.T with USD [draft-ietf-spring-srv6-network-programming]                              */
#define SRV6_ENDPOINT_BEHAVIOR_END_T_PSP_USD          0x0025 /* End.T with PSP & USD [draft-ietf-spring-srv6-network-programming]                        */
#define SRV6_ENDPOINT_BEHAVIOR_END_T_USP_USD          0x0026 /* End.T with USP & USD [draft-ietf-spring-srv6-network-programming]                        */
#define SRV6_ENDPOINT_BEHAVIOR_END_T_PSP_USP_USD      0x0027 /* End.T with PSP, USP & USD [draft-ietf-spring-srv6-network-programming]                   */
#define SRV6_ENDPOINT_BEHAVIOR_END_ONLY_CSID          0x002A /* End with NEXT-ONLY-CSID [draft-filsfils-spring-net-pgm-extension-srv6-usid]              */
#define SRV6_ENDPOINT_BEHAVIOR_END_CSID               0x002B /* End with NEXT-CSID [draft-filsfils-spring-net-pgm-extension-srv6-usid]                   */
#define SRV6_ENDPOINT_BEHAVIOR_END_CSID_PSP           0x002C /* End with NEXT-CSID & PSP [draft-filsfils-spring-net-pgm-extension-srv6-usid]             */
#define SRV6_ENDPOINT_BEHAVIOR_END_CSID_USP           0x002D /* End with NEXT-CSID & USP [draft-filsfils-spring-net-pgm-extension-srv6-usid]             */
#define SRV6_ENDPOINT_BEHAVIOR_END_CSID_PSP_USP       0x002E /* End with NEXT-CSID, PSP & USP [draft-filsfils-spring-net-pgm-extension-srv6-usid]        */
#define SRV6_ENDPOINT_BEHAVIOR_END_CSID_USD           0x002F /* End with NEXT-CSID & USD [draft-filsfils-spring-net-pgm-extension-srv6-usid]             */
#define SRV6_ENDPOINT_BEHAVIOR_END_CSID_PSP_USD       0x0030 /* End with NEXT-CSID, PSP & USD [draft-filsfils-spring-net-pgm-extension-srv6-usid]        */
#define SRV6_ENDPOINT_BEHAVIOR_END_CSID_USP_USD       0x0031 /* End with NEXT-CSID, USP & USD [draft-filsfils-spring-net-pgm-extension-srv6-usid]        */
#define SRV6_ENDPOINT_BEHAVIOR_END_CSID_PSP_USP_USD   0x0032 /* End with NEXT-CSID, PSP, USP & USD [draft-filsfils-spring-net-pgm-extension-srv6-usid]   */
#define SRV6_ENDPOINT_BEHAVIOR_END_X_ONLY_CSID        0x0033 /* End.X with NEXT-ONLY-CSID [draft-filsfils-spring-net-pgm-extension-srv6-usid]            */
#define SRV6_ENDPOINT_BEHAVIOR_END_X_CSID             0x0034 /* End.X with NEXT-CSID [draft-filsfils-spring-net-pgm-extension-srv6-usid]                 */
#define SRV6_ENDPOINT_BEHAVIOR_END_X_CSID_PSP         0x0035 /* End.X with NEXT-CSID & PSP [draft-filsfils-spring-net-pgm-extension-srv6-usid]           */
#define SRV6_ENDPOINT_BEHAVIOR_END_X_CSID_USP         0x0036 /* End.X with NEXT-CSID & USP [draft-filsfils-spring-net-pgm-extension-srv6-usid]           */
#define SRV6_ENDPOINT_BEHAVIOR_END_X_CSID_PSP_USP     0x0037 /* End.X with NEXT-CSID, PSP & USP [draft-filsfils-spring-net-pgm-extension-srv6-usid]      */
#define SRV6_ENDPOINT_BEHAVIOR_END_X_CSID_USD         0x0038 /* End.X with NEXT-CSID & USD [draft-filsfils-spring-net-pgm-extension-srv6-usid]           */
#define SRV6_ENDPOINT_BEHAVIOR_END_X_CSID_PSP_USD     0x0039 /* End.X with NEXT-CSID, PSP & USD [draft-filsfils-spring-net-pgm-extension-srv6-usid]      */
#define SRV6_ENDPOINT_BEHAVIOR_END_X_CSID_USP_USD     0x003A /* End.X with NEXT-CSID, USP & USD [draft-filsfils-spring-net-pgm-extension-srv6-usid]      */
#define SRV6_ENDPOINT_BEHAVIOR_END_X_CSID_PSP_USP_USD 0x003B /* End.X with NEXT-CSID, PSP, USP & USD [draft-filsfils-spring-net-pgm-extension-srv6-usid] */
#define SRV6_ENDPOINT_BEHAVIOR_END_DX6_CSID           0x003C /* End.DX6 with NEXT-CSID [draft-filsfils-spring-net-pgm-extension-srv6-usid]               */
#define SRV6_ENDPOINT_BEHAVIOR_END_DX4_CSID           0x003D /* End.DX4 with NEXT-CSID [draft-filsfils-spring-net-pgm-extension-srv6-usid]               */
#define SRV6_ENDPOINT_BEHAVIOR_END_DT6_CSID           0x003E /* End.DT6 with NEXT-CSID [draft-filsfils-spring-net-pgm-extension-srv6-usid]               */
#define SRV6_ENDPOINT_BEHAVIOR_END_DT4_CSID           0x003F /* End.DT4 with NEXT-CSID [draft-filsfils-spring-net-pgm-extension-srv6-usid]               */
#define SRV6_ENDPOINT_BEHAVIOR_END_DT46_CSID          0x0040 /* End.DT46 with NEXT-CSID [draft-filsfils-spring-net-pgm-extension-srv6-usid]              */
#define SRV6_ENDPOINT_BEHAVIOR_END_DX2_CSID           0x0041 /* End.DX2 with NEXT-CSID [draft-filsfils-spring-net-pgm-extension-srv6-usid]               */
#define SRV6_ENDPOINT_BEHAVIOR_END_DX2V_CSID          0x0042 /* End.DX2V with NEXT-CSID [draft-filsfils-spring-net-pgm-extension-srv6-usid]              */
#define SRV6_ENDPOINT_BEHAVIOR_END_DT2U_CSID          0x0043 /* End.DT2U with NEXT-CSID [draft-filsfils-spring-net-pgm-extension-srv6-usid]              */
#define SRV6_ENDPOINT_BEHAVIOR_END_DT2M_CSID          0x0044 /* End.DT2M with NEXT-CSID [draft-filsfils-spring-net-pgm-extension-srv6-usid]              */
#define SRV6_ENDPOINT_BEHAVIOR_OPAQUE                 0xFFFF /* Opaque [draft-ietf-spring-srv6-network-programming]                                      */

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

static const value_string evpnrtypevals[] = {
    { EVPN_AD_ROUTE,           "Ethernet AD Route" },
    { EVPN_MAC_ROUTE,          "MAC Advertisement Route" },
    { EVPN_INC_MCAST_TREE,     "Inclusive Multicast Route" },
    { EVPN_ETH_SEGMENT_ROUTE,  "Ethernet Segment Route" },
    { EVPN_IP_PREFIX_ROUTE,    "IP Prefix route" },
    { EVPN_MC_ETHER_TAG_ROUTE, "Selective Multicast Ethernet Tag Route" },
    { EVPN_IGMP_JOIN_ROUTE,    "IGMP Join Synch Route" },
    { EVPN_IGMP_LEAVE_ROUTE,   "IGMP Leave Synch Route" },
    { EVPN_S_PMSI_A_D_ROUTE,   "S-PMSI A-D Route" },
    { 0, NULL }
};

static const value_string evpn_nlri_esi_type[] = {
    { BGP_NLRI_EVPN_ESI_VALUE,      "ESI 9 bytes value" },
    { BGP_NLRI_EVPN_ESI_LACP,       "ESI LACP 802.1AX defined" },
    { BGP_NLRI_EVPN_ESI_MSTP,       "ESI MSTP defined" },
    { BGP_NLRI_EVPN_ESI_MAC,        "ESI MAC address defined" },
    { BGP_NLRI_EVPN_ESI_RID,        "ESI Router ID" },
    { BGP_NLRI_EVPN_ESI_ASN,        "ESI Autonomous System" },
    { BGP_NLRI_EVPN_ESI_RES,        "ESI reserved" },
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
    { 8, "No supported AFI/SAFI (Cisco)" },
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

#define BGP_CEASE_MINOR_MAX_REACHED       1
#define BGP_CEASE_MINOR_ADMIN_SHUTDOWN    2
#define BGP_CEASE_MINOR_PEER_DE_CONF      3
#define BGP_CEASE_MINOR_ADMIN_RESET       4
#define BGP_CEASE_MINOR_CONN_RESET        5
#define BGP_CEASE_MINOR_OTHER_CONF_CHANGE 6
#define BGP_CEASE_MINOR_CONN_COLLISION    7
#define BGP_CEASE_MINOR_OUT_RESOURCES     8
#define BGP_CEASE_MINOR_HARD_RESET        9

/* RFC4486 Subcodes for BGP Cease Notification Message */
static const value_string bgpnotify_minor_cease[] = {
    { BGP_CEASE_MINOR_MAX_REACHED,       "Maximum Number of Prefixes Reached"},
    { BGP_CEASE_MINOR_ADMIN_SHUTDOWN,    "Administratively Shutdown"},
    { BGP_CEASE_MINOR_PEER_DE_CONF,      "Peer De-configured"},
    { BGP_CEASE_MINOR_ADMIN_RESET,       "Administratively Reset"},
    { BGP_CEASE_MINOR_CONN_RESET,        "Connection Rejected"},
    { BGP_CEASE_MINOR_OTHER_CONF_CHANGE, "Other Configuration Change"},
    { BGP_CEASE_MINOR_CONN_COLLISION,    "Connection Collision Resolution"},
    { BGP_CEASE_MINOR_OUT_RESOURCES,     "Out of Resources"},
    { BGP_CEASE_MINOR_HARD_RESET,        "Hard Reset"},
    { 0,                                 NULL }
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
    { BGPTYPE_ORIGIN,              "ORIGIN" },
    { BGPTYPE_AS_PATH,             "AS_PATH" },
    { BGPTYPE_NEXT_HOP,            "NEXT_HOP" },
    { BGPTYPE_MULTI_EXIT_DISC,     "MULTI_EXIT_DISC" },
    { BGPTYPE_LOCAL_PREF,          "LOCAL_PREF" },
    { BGPTYPE_ATOMIC_AGGREGATE,    "ATOMIC_AGGREGATE" },
    { BGPTYPE_AGGREGATOR,          "AGGREGATOR" },
    { BGPTYPE_COMMUNITIES,         "COMMUNITIES" },
    { BGPTYPE_ORIGINATOR_ID,       "ORIGINATOR_ID" },
    { BGPTYPE_CLUSTER_LIST,        "CLUSTER_LIST" },
    { BGPTYPE_DPA,                 "DPA" },
    { BGPTYPE_ADVERTISER,          "ADVERTISER" },
    { BGPTYPE_RCID_PATH,           "RCID_PATH / CLUSTER_ID" },
    { BGPTYPE_MP_REACH_NLRI,       "MP_REACH_NLRI" },
    { BGPTYPE_MP_UNREACH_NLRI,     "MP_UNREACH_NLRI" },
    { BGPTYPE_EXTENDED_COMMUNITY,  "EXTENDED_COMMUNITIES" },
    { BGPTYPE_AS4_PATH,            "AS4_PATH" },
    { BGPTYPE_AS4_AGGREGATOR,      "AS4_AGGREGATOR" },
    { BGPTYPE_SAFI_SPECIFIC_ATTR,  "SAFI_SPECIFIC_ATTRIBUTE" },
    { BGPTYPE_CONNECTOR_ATTRIBUTE, "Connector Attribute" },
    { BGPTYPE_AS_PATHLIMIT,        "AS_PATHLIMIT "},
    { BGPTYPE_TUNNEL_ENCAPS_ATTR,  "TUNNEL_ENCAPSULATION_ATTRIBUTE" },
    { BGPTYPE_PMSI_TUNNEL_ATTR,    "PMSI_TUNNEL_ATTRIBUTE" },
    { BGPTYPE_TRAFFIC_ENGINEERING, "Traffic Engineering" },
    { BGPTYPE_IPV6_ADDR_SPEC_EC,   "IPv6 Address Specific Extended Community" },
    { BGPTYPE_AIGP,                "AIGP" },
    { BGPTYPE_PE_DISTING_LABLES,   "PE Distinguisher Labels" },
    { BGPTYPE_BGP_ENTROPY_LABEL,   "BGP Entropy Label Capability Attribute" },
    { BGPTYPE_LINK_STATE_ATTR,     "BGP-LS Attribute" },
    { BGPTYPE_30,                  "Deprecated" },
    { BGPTYPE_31,                  "Deprecated" },
    { BGPTYPE_LARGE_COMMUNITY,     "LARGE_COMMUNITY" },
    { BGPTYPE_BGPSEC_PATH,         "BGPsec_PATH" },
    { BGPTYPE_D_PATH,              "D_PATH" },
    { BGPTYPE_BGP_PREFIX_SID,      "BGP Prefix-SID" },
    { BGPTYPE_LINK_STATE_OLD_ATTR, "LINK_STATE (unofficial code point)" },
    { BGPTYPE_ATTR_SET,            "ATTR_SET" },
    { BGPTYPE_129,                 "Deprecated" },
    { BGPTYPE_241,                 "Deprecated" },
    { BGPTYPE_242,                 "Deprecated" },
    { BGPTYPE_243,                 "Deprecated" },
    { 0, NULL }
};

static const value_string pmsi_tunnel_type[] = {
    { PMSI_TUNNEL_NOPRESENT,      "Type is not present" },
    { PMSI_TUNNEL_RSVPTE_P2MP,    "RSVP-TE P2MP LSP" },
    { PMSI_TUNNEL_MLDP_P2MP,      "mLDP P2MP LSP" },
    { PMSI_TUNNEL_PIMSSM,         "PIM SSM Tree" },
    { PMSI_TUNNEL_PIMSM,          "PIM SM Tree" },
    { PMSI_TUNNEL_BIDIR_PIM,      "BIDIR-PIM Tree" },
    { PMSI_TUNNEL_INGRESS,        "Ingress Replication" },
    { PMSI_TUNNEL_MLDP_MP2MP,     "mLDP MP2MP LSP" },
    { 0, NULL }
};

static const value_string aigp_tlv_type[] = {
    { AIGP_TLV_TYPE,            "Type AIGP TLV" },
    { 0, NULL }
};

static const value_string pmsi_mldp_fec_opaque_value_type[] = {
    { PMSI_MLDP_FEC_TYPE_RSVD,          "Reserved" },
    { PMSI_MLDP_FEC_TYPE_GEN_LSP,       "Generic LSP Identifier" },
    { PMSI_MLDP_FEC_TYPE_EXT_TYPE,      "Extended Type field in the following two bytes" },
    { 0, NULL}
};

static const value_string pmsi_mldp_fec_opa_extented_type[] = {
    { PMSI_MLDP_FEC_ETYPE_RSVD,         "Reserved" },
    { 0, NULL}
};

static const value_string bgp_attr_tunnel_type[] = {
    { TUNNEL_TYPE_L2TP_OVER_IP, "L2TPv2 over IP" },
    { TUNNEL_TYPE_GRE,          "GRE" },
    { TUNNEL_TYPE_TTE,          "Transmit tunnel endpoint" },
    { TUNNEL_TYPE_IPSEC_IN_TM,  "IPsec in Tunnel-mode" },
    { TUNNEL_TYPE_IP_IN_IP_IPSEC, "IP in IP tunnel with IPsec Transport Mode" },
    { TUNNEL_TYPE_MPLS_IN_IP_IPSEC, "MPLS-in-IP tunnel with IPsec Transport Mode" },
    { TUNNEL_TYPE_IP_IN_IP,     "IP in IP" },
    { TUNNEL_TYPE_VXLAN,        "VXLAN Encapsulation" },
    { TUNNEL_TYPE_NVGRE,        "NVGRE Encapsulation" },
    { TUNNEL_TYPE_MPLS,         "MPLS Encapsulation" },
    { TUNNEL_TYPE_MPLS_IN_GRE,  "MPLS in GRE Encapsulation" },
    { TUNNEL_TYPE_VXLAN_GPE,    "VXLAN GPE Encapsulation" },
    { TUNNEL_TYPE_MPLS_IN_UDP,  "MPLS in UDP Encapsulation" },
    { TUNNEL_TYPE_IPV6_TUNNEL,  "IPv6 Tunnel" },
    { TUNNEL_TYPE_SR_TE_POLICY, "SR TE Policy Type" },
    { TUNNEL_TYPE_BARE,         "Bare" },
    { TUNNEL_TYPE_SR_TUNNEL,    "SR Tunnel" },
    { 0, NULL }
};

static const value_string subtlv_type[] = {
    { TUNNEL_SUBTLV_ENCAPSULATION,  "ENCAPSULATION" },
    { TUNNEL_SUBTLV_PROTO_TYPE,     "PROTOCOL_TYPE" },
    { TUNNEL_SUBTLV_IPSEC_TA,       "IPsec Tunnel Authenticator" },
    { TUNNEL_SUBTLV_COLOR,          "COLOR" },
    { TUNNEL_SUBTLV_LOAD_BALANCE,   "LOAD_BALANCE" },
    { TUNNEL_SUBTLV_REMOTE_ENDPOINT,"Tunnel Egress Endpoint" },
    { TUNNEL_SUBTLV_IPV4_DS_FIELD,  "IPv4 DS Field" },
    { TUNNEL_SUBTLV_UDP_DST_PORT,   "UDP Destination Port" },
    { TUNNEL_SUBTLV_EMBEDDED_LABEL, "Embedded Label Handling" },
    { TUNNEL_SUBTLV_MPLS_LABEL,     "MPLS Label Stack" },
    { TUNNEL_SUBTLV_PREFIX_SID,     "Prefix SID" },
    { TUNNEL_SUBTLV_PREFERENCE,     "Preference" },
    { TUNNEL_SUBTLV_BINDING_SID,    "Binding SID" },
    { TUNNEL_SUBTLV_ENLP,           "ENLP" },
    { TUNNEL_SUBTLV_PRIORITY,       "Priority" },
    { TUNNEL_SUBTLV_SEGMENT_LIST,   "Segment List" },
    { TUNNEL_SUBTLV_POLICY_NAME,    "Policy Name" },
    { 0, NULL }
};

static const value_string bgp_enlp_type[] = {
    { 0 , "Reserved" },
    { 1 , "Push IPv4, do not push IPv6" },
    { 2 , "Push IPv6, do not push IPv4" },
    { 3 , "Push IPv4, push IPv6" },
    { 4 , "Do not push" },
    { 0, NULL }
};

static const value_string bgp_sr_policy_list_type[] = {
    { TUNNEL_SUBTLV_SEGMENT_LIST_SUB_TYPE_A,      "Type A MPLS SID sub-TLV" },
    { TUNNEL_SUBTLV_SEGMENT_LIST_SUB_TYPE_B,      "Type B SRv6 SID sub-TLV" },
    { TUNNEL_SUBTLV_SEGMENT_LIST_SUB_TYPE_C,      "Type C IPv4 Node and SID sub-TLV" },
    { TUNNEL_SUBTLV_SEGMENT_LIST_SUB_TYPE_D,      "Type D IPv6 Node and SID for SR-MPLS sub-TLV" },
    { TUNNEL_SUBTLV_SEGMENT_LIST_SUB_TYPE_E,      "Type E IPv4 Node, index and SID sub-TLV" },
    { TUNNEL_SUBTLV_SEGMENT_LIST_SUB_TYPE_F,      "Type F IPv4 Local/Remote addresses and SID sub-TLV" },
    { TUNNEL_SUBTLV_SEGMENT_LIST_SUB_TYPE_G,      "Type G IPv6 Node, index for remote and local pair and SID for SR-MPLS sub-TLV" },
    { TUNNEL_SUBTLV_SEGMENT_LIST_SUB_TYPE_H,      "Type H IPv6 Local/Remote addresses and SID sub-TLV" },
    { TUNNEL_SUBTLV_SEGMENT_LIST_SUB_TYPE_WEIGHT, "Weight sub-TLV" },
    { TUNNEL_SUBTLV_SEGMENT_LIST_SUB_TYPE_I,      "Type I IPv6 Node and SID for SRv6 sub-TLV" },
    { TUNNEL_SUBTLV_SEGMENT_LIST_SUB_TYPE_J,      "Type J IPv6 Node, index for remote and local pair and SID for SRv6 sub-TLV" },
    { TUNNEL_SUBTLV_SEGMENT_LIST_SUB_TYPE_K,      "Type K IPv6 Local/Remote addresses and SID for SRv6 sub-TLV" },
    { 0, NULL }
};

static const true_false_string tfs_bgpext_com_type_auth = {
    "Allocated on First Come First Serve Basis",
    "Allocated on Standard Action, Early Allocation or Experimental Basis"
};

static const value_string bgpext_com_type_high[] = {
    { BGP_EXT_COM_TYPE_HIGH_TR_AS2,         "Transitive 2-Octet AS-Specific" },
    { BGP_EXT_COM_TYPE_HIGH_TR_IP4,         "Transitive IPv4-Address-Specific" },
    { BGP_EXT_COM_TYPE_HIGH_TR_AS4,         "Transitive 4-Octet AS-Specific" },
    { BGP_EXT_COM_TYPE_HIGH_TR_OPAQUE,      "Transitive Opaque" },
    { BGP_EXT_COM_TYPE_HIGH_TR_QOS,         "Transitive QoS Marking" },
    { BGP_EXT_COM_TYPE_HIGH_TR_COS,         "Transitive CoS Capability" },
    { BGP_EXT_COM_TYPE_HIGH_TR_EVPN,        "Transitive EVPN" },
    { BGP_EXT_COM_TYPE_HIGH_TR_FLOW_I,      "FlowSpec Transitive" },
    { BGP_EXT_COM_TYPE_HIGH_TR_FLOW,        "Transitive Flow spec redirect/mirror to IP next-hop" },
    { BGP_EXT_COM_TYPE_HIGH_TR_FLOW_R,      "Transitive FlowSpec Redirect to indirection-id" },
    { BGP_EXT_COM_TYPE_HIGH_TR_EXP,         "Generic Transitive Experimental Use"},
    { BGP_EXT_COM_TYPE_HIGH_TR_EXP_2,       "Generic Transitive Experimental Use Part 2"},
    { BGP_EXT_COM_TYPE_HIGH_TR_EXP_3,       "Generic Transitive Experimental Use Part 3 "},
    { BGP_EXT_COM_TYPE_HIGH_TR_EXP_EIGRP,   "Transitive Experimental EIGRP" },
    { BGP_EXT_COM_TYPE_HIGH_NTR_AS2,        "Non-Transitive 2-Octet AS-Specific" },
    { BGP_EXT_COM_TYPE_HIGH_NTR_IP4,        "Non-Transitive IPv4-Address-Specific" },
    { BGP_EXT_COM_TYPE_HIGH_NTR_AS4,        "Non-Transitive 4-Octet AS-Specific" },
    { BGP_EXT_COM_TYPE_HIGH_NTR_OPAQUE,     "Non-Transitive Opaque" },
    { BGP_EXT_COM_TYPE_HIGH_NTR_QOS,        "Non-Transitive QoS Marking" },
    { 0, NULL}
};

static const value_string bgpext_com_stype_tr_exp_2[] = {
    { BGP_EXT_COM_STYPE_EXP_2_FLOW_RED,      "Flow spec redirect IPv4 format"},
    { 0, NULL}
};

static const value_string bgpext_com_stype_tr_exp_3[] = {
    { BGP_EXT_COM_STYPE_EXP_3_SEC_GROUP,     "Security Group AS4"},
    { BGP_EXT_COM_STYPE_EXP_3_FLOW_RED,      "Flow spec redirect AS-4byte format"},
    { BGP_EXT_COM_STYPE_EXP_3_TAG4,          "Tag4"},
    { BGP_EXT_COM_STYPE_EXP_3_SUB_CLUS,      "Origin Sub-Cluster4"},
    { 0, NULL}
};

static const value_string bgpext_com_stype_tr_evpn[] = {
    { BGP_EXT_COM_STYPE_EVPN_MMAC,        "MAC Mobility" },
    { BGP_EXT_COM_STYPE_EVPN_LABEL,       "ESI MPLS Label" },
    { BGP_EXT_COM_STYPE_EVPN_IMP,         "ES Import" },
    { BGP_EXT_COM_STYPE_EVPN_ROUTERMAC,   "EVPN Router's MAC" },
    { BGP_EXT_COM_STYPE_EVPN_L2ATTR,      "Layer 2 Attributes" },
    { BGP_EXT_COM_STYPE_EVPN_ETREE,       "E-Tree" },
    { BGP_EXT_COM_STYPE_EVPN_DF,          "DF Election" },
    { BGP_EXT_COM_STYPE_EVPN_ISID,        "I-SID" },
    { BGP_EXT_COM_STYPE_EVPN_ND,          "ND" },
    { BGP_EXT_COM_STYPE_EVPN_MCFLAGS,     "Multicast Flags Extended Community" },
    { BGP_EXT_COM_STYPE_EVPN_EVIRT0,      "EVI-RT Type 0 Extended Community" },
    { BGP_EXT_COM_STYPE_EVPN_EVIRT1,      "EVI-RT Type 1 Extended Community" },
    { BGP_EXT_COM_STYPE_EVPN_EVIRT2,      "EVI-RT Type 2 Extended Community" },
    { BGP_EXT_COM_STYPE_EVPN_EVIRT3,      "EVI-RT Type 3 Extended Community" },
    { BGP_EXT_COM_STYPE_EVPN_ATTACHCIRT,  "EVPN Attachment Circuit" },
    { 0, NULL}
};

static const value_string bgpext_com_stype_tr_as2[] = {
    { BGP_EXT_COM_STYPE_AS2_RT,       "Route Target" },
    { BGP_EXT_COM_STYPE_AS2_RO,       "Route Origin" },
    { BGP_EXT_COM_STYPE_AS2_OSPF_DID, "OSPF Domain Identifier" },
    { BGP_EXT_COM_STYPE_AS2_DCOLL,    "BGP Data Collection" },
    { BGP_EXT_COM_STYPE_AS2_SRC_AS,   "Source AS" },
    { BGP_EXT_COM_STYPE_AS2_L2VPN,    "L2VPN Identifier" },
    { BGP_EXT_COM_STYPE_AS2_CVPND,    "Cisco VPN-Distinguisher" },
    { 0, NULL}
};

static const value_string bgpext_com_stype_ntr_as2[] = {
    { BGP_EXT_COM_STYPE_AS2_LBW, "Link Bandwidth" },
    { BGP_EXT_COM_STYPE_AS2_VNI, "Virtual-Network Identifier" },
    { 0, NULL}
};

static const value_string bgpext_com_stype_tr_as4[] = {
    { BGP_EXT_COM_STYPE_AS4_RT,       "Route Target" },
    { BGP_EXT_COM_STYPE_AS4_RO,       "Route Origin" },
    { BGP_EXT_COM_STYPE_AS4_GEN,      "Generic" },
    { BGP_EXT_COM_STYPE_AS4_BGP_DC,   "BGP Data Collection"},
    { BGP_EXT_COM_STYPE_AS4_OSPF_DID, "OSPF Domain Identifier" },
    { BGP_EXT_COM_STYPE_AS4_S_AS,     "Source AS" },
    { BGP_EXT_COM_STYPE_AS4_CIS_V,    "Cisco VPN Identifier" },
    { BGP_EXT_COM_STYPE_AS4_RT_REC,   "Route-Target Record"},
    { 0, NULL}
};

static const value_string bgpext_com_stype_ntr_as4[] = {
    { BGP_EXT_COM_STYPE_AS4_GEN, "Generic" },
    { 0, NULL}
};

static const value_string bgpext_com_stype_tr_IP4[] = {
    { BGP_EXT_COM_STYPE_IP4_RT,       "Route Target" },
    { BGP_EXT_COM_STYPE_IP4_RO,       "Route Origin" },
    { BGP_EXT_COM_STYPE_IP4_OSPF_DID, "OSPF Domain Identifier" },
    { BGP_EXT_COM_STYPE_IP4_OSPF_RID, "OSPF Router ID" },
    { BGP_EXT_COM_STYPE_IP4_L2VPN,    "L2VPN Identifier" },
    { BGP_EXT_COM_STYPE_IP4_VRF_I,    "VRF Route Import" },
    { BGP_EXT_COM_STYPE_IP4_CIS_D,    "Cisco VPN-Distinguisher" },
    { BGP_EXT_COM_STYPE_IP4_SEG_NH,   "Inter-area P2MP Segmented Next-Hop" },
    { 0, NULL}
};

static const value_string bgpext_com_stype_ntr_IP4[] = {
    { 0, NULL}
};

static const value_string bgpext_com_stype_tr_opaque[] = {
    { BGP_EXT_COM_STYPE_OPA_COST,    "Cost" },
    { BGP_EXT_COM_STYPE_OPA_OSPF_RT, "OSPF Route Type" },
    { BGP_EXT_COM_STYPE_OPA_COLOR,   "Color" },
    { BGP_EXT_COM_STYPE_OPA_ENCAP,   "Encapsulation" },
    { BGP_EXT_COM_STYPE_OPA_DGTW,    "Default Gateway" },
    { 0, NULL}
};

static const value_string bgpext_com_cost_poi_type[] = {
    { BGP_EXT_COM_COST_POI_ORIGIN,  "\"Lowest Origin code\" step" },
    { BGP_EXT_COM_COST_POI_ASPATH,  "\"Shortest AS_PATH\" step" },
    { BGP_EXT_COM_COST_POI_MED,     "\"Lowest MED\" step" },
    { BGP_EXT_COM_COST_POI_LP,      "\"Highest Local Preference\" step" },
    { BGP_EXT_COM_COST_POI_AIGP,    "\"Lowest Accumulated IGP Cost\" step" },
    { BGP_EXT_COM_COST_POI_ABS,     "Before BGP Best Path algorithm" },
    { BGP_EXT_COM_COST_POI_IGP,     "\"Smallest IGP Metric\" step" },
    { BGP_EXT_COM_COST_POI_EI,      "\"Prefer eBGP to iBGP\" step" },
    { BGP_EXT_COM_COST_POI_RID,     "\"Smallest BGP RID\" step" },
    { 0,NULL}
};

static const value_string bgpext_com_tunnel_type[] = {
    { BGP_EXT_COM_TUNNEL_RESERVED,      "Reserved" },
    { BGP_EXT_COM_TUNNEL_L2TPV3,        "L2TPv3 over IP" },
    { BGP_EXT_COM_TUNNEL_GRE,           "GRE" },
    { BGP_EXT_COM_TUNNEL_ENDP,          "Transmit tunnel endpoint" },
    { BGP_EXT_COM_TUNNEL_IPSEC,         "IPsec in Tunnel-mode" },
    { BGP_EXT_COM_TUNNEL_IPIPSEC,       "IP in IP tunnel with IPsec Transport Mode" },
    { BGP_EXT_COM_TUNNEL_MPLSIP,        "MPLS-in-IP tunnel with IPsec Transport Mode" },
    { BGP_EXT_COM_TUNNEL_IPIP,          "IP in IP" },
    { BGP_EXT_COM_TUNNEL_VXLAN,         "VXLAN Encapsulation" },
    { BGP_EXT_COM_TUNNEL_NVGRE,         "NVGRE Encapsulation" },
    { BGP_EXT_COM_TUNNEL_MPLS,          "MPLS Encapsulation" },
    { BGP_EXT_COM_TUNNEL_MPLSGRE,       "MPLS in GRE Encapsulation" },
    { BGP_EXT_COM_TUNNEL_VXLANGPE,      "VxLAN GPE Encapsulation" },
    { BGP_EXT_COM_TUNNEL_MPLSUDP,       "MPLS in UDP Encapsulation" },
    { 0, NULL}
};

static const value_string bgpext_com_stype_ntr_opaque[] = {
    { BGP_EXT_COM_STYPE_OPA_COST,       "Cost" },
    { BGP_EXT_COM_STYPE_OPA_OR_VAL_ST,  "BGP Origin Validation state" },
    { 0, NULL}
};

static const value_string bgpext_com_stype_tr_exp[] = {
    { BGP_EXT_COM_STYPE_EXP_OSPF_RT,    "OSPF Route Type" },
    { BGP_EXT_COM_STYPE_EXP_OSPF_RID,   "OSPF Router ID" },
    { BGP_EXT_COM_STYPE_EXP_SEC_GROUP,  "Security Group" },
    { BGP_EXT_COM_STYPE_EXP_OSPF_DID,   "OSPF Domain Identifier" },
    { BGP_EXT_COM_STYPE_EXP_F_TR,       "Flow spec traffic-rate" },
    { BGP_EXT_COM_STYPE_EXP_F_TA,       "Flow spec traffic-action" },
    { BGP_EXT_COM_STYPE_EXP_F_RED,      "Flow spec redirect AS 2 bytes" },
    { BGP_EXT_COM_STYPE_EXP_F_RMARK,    "Flow spec traffic-remarking" },
    { BGP_EXT_COM_STYPE_EXP_L2,         "Layer2 Info" },
    { BGP_EXT_COM_STYPE_EXP_ETREE,      "E-Tree Info" },
    { BGP_EXT_COM_STYPE_EXP_TAG,        "Tag" },
    { BGP_EXT_COM_STYPE_EXP_SUB_CLUS,   "Origin Sub-Cluster" },
    { 0, NULL}
};

static const value_string bgpext_com_stype_tr_eigrp[] = {
    { BGP_EXT_COM_STYPE_EXP_EIGRP_FT,   "EIGRP Route Flags, Route Tag" },
    { BGP_EXT_COM_STYPE_EXP_EIGRP_AD,   "EIGRP AS Number, Delay" },
    { BGP_EXT_COM_STYPE_EXP_EIGRP_RHB,  "EIGRP Reliability, Hop Count, Bandwidth" },
    { BGP_EXT_COM_STYPE_EXP_EIGRP_LM,   "EIGRP Load, MTU" },
    { BGP_EXT_COM_STYPE_EXP_EIGRP_EAR,  "EIGRP External AS Number, Router ID" },
    { BGP_EXT_COM_STYPE_EXP_EIGRP_EPM,  "EIGRP External Protocol, Metric" },
    { BGP_EXT_COM_STYPE_EXP_EIGRP_RID,  "EIGRP Originating Router ID" },
    { 0, NULL}
};

static const value_string flow_spec_op_len_val[] = {
    { 0, "1 byte: 1 <<"  },
    { 1, "2 bytes: 1 <<" },
    { 2, "4 bytes: 1 <<" },
    { 3, "8 bytes: 1 <<" },
    { 0, NULL  }
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

/*
 * BGP Layer 2 Encapsulation Types
 *
 * RFC 6624
 *
 * http://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-l2-encapsulation-types-registry
 */
static const value_string bgp_l2vpn_encaps[] = {
    { 0,  "Reserved"},
    { 1,  "Frame Relay"},
    { 2,  "ATM AAL5 SDU VCC transport"},
    { 3,  "ATM transparent cell transport"},
    { 4,  "Ethernet (VLAN) Tagged mode"},
    { 5,  "Ethernet raw mode"},
    { 6,  "Cisco-HDLC"},
    { 7,  "PPP"},
    { 8,  "SONET/SDH CES"},
    { 9,  "ATM n-to-one VCC cell transport"},
    { 10, "ATM n-to-one VPC cell transport"},
    { 11, "IP layer 2 transport"},
    { 15, "Frame relay port mode"},
    { 17, "Structure agnostic E1 over packet"},
    { 18, "Structure agnostic T1 over packet"},
    { 19, "VPLS"},
    { 20, "Structure agnostic T3 over packet"},
    { 21, "Nx64kbit/s Basic Service using Structure-aware"},
    { 25, "Frame Relay DLCI"},
    { 40, "Structure agnostic E3 over packet"},
    { 41, "Octet-aligned playload for structure-agnostic DS1 circuits"},
    { 42, "E1 Nx64kbit/s with CAS using Structure-aware"},
    { 43, "DS1 (ESF) Nx64kbit/s with CAS using Structure-aware"},
    { 44, "DS1 (SF) Nx64kbit/s with CAS using Structure-aware"},
    { 64, "IP-interworking"},
    { 0, NULL }
};

static const value_string bgpext_com_ospf_rtype[] = {
  { BGP_OSPF_RTYPE_RTR, "Router" },
  { BGP_OSPF_RTYPE_NET, "Network" },
  { BGP_OSPF_RTYPE_SUM, "Summary" },
  { BGP_OSPF_RTYPE_EXT, "External" },
  { BGP_OSPF_RTYPE_NSSA,"NSSA External" },
  { BGP_OSPF_RTYPE_SHAM,"MPLS-VPN Sham" },
  { 0, NULL }
};

/* Subsequent address family identifier, RFC4760 */
static const value_string bgpattr_nlri_safi[] = {
    { 0,                        "Reserved" },
    { SAFNUM_UNICAST,           "Unicast" },
    { SAFNUM_MULCAST,           "Multicast" },
    { SAFNUM_UNIMULC,           "Unicast+Multicast (Deprecated)" },
    { SAFNUM_MPLS_LABEL,        "Labeled Unicast" },
    { SAFNUM_MCAST_VPN,         "MCAST-VPN" },
    { SAFNUM_MULTISEG_PW,       "Multi-Segment Pseudowires" },
    { SAFNUM_ENCAPSULATION,     "Encapsulation (Deprecated)" },
    { SAFNUM_MCAST_VPLS,        "MCAST-VPLS" },
    { SAFNUM_TUNNEL,            "Tunnel (Deprecated)" },
    { SAFNUM_VPLS,              "VPLS" },
    { SAFNUM_MDT,               "Cisco MDT" },
    { SAFNUM_4OVER6,            "4over6" },
    { SAFNUM_6OVER4,            "6over4" },
    { SAFNUM_L1VPN,             "Layer-1 VPN" },
    { SAFNUM_EVPN,              "EVPN" },
    { SAFNUM_BGP_LS,            "BGP-LS" },
    { SAFNUM_BGP_LS_VPN,        "BGP-LS-VPN" },
    { SAFNUM_SR_POLICY,         "SR Policy" },
    { SAFNUM_SD_WAN,            "SD-WAN" },
    { SAFNUM_RPD,               "Routing Policy Distribution" },
    { SAFNUM_CT,                "Classful Transport Planes" },
    { SAFNUM_FLOWSPEC,          "Tunneled Traffic Flowspec" },
    { SAFNUM_MCAST_TREE,        "MCAST-TREE" },
    { SAFNUM_LAB_VPNUNICAST,    "Labeled VPN Unicast" },
    { SAFNUM_LAB_VPNMULCAST,    "Labeled VPN Multicast" },
    { SAFNUM_LAB_VPNUNIMULC,    "Labeled VPN Unicast+Multicast (Deprecated)" },
    { SAFNUM_ROUTE_TARGET,      "Route Target Filter" },
    { SAFNUM_FSPEC_RULE,        "Flow Spec Filter" },
    { SAFNUM_FSPEC_VPN_RULE,    "Flow Spec Filter VPN" },
    { SAFNUM_L3VPN,             "Layer-3 VPN (Deprecated)" },
    { 0, NULL }
};

/* ORF Type, RFC5291 */
static const value_string orf_type_vals[] = {
    {   2,      "Communities ORF-Type" },
    {   3,      "Extended Communities ORF-Type" },
    { 128,      "Cisco PrefixList ORF-Type" },
    { 129,      "Cisco CommunityList ORF-Type" },
    { 130,      "Cisco Extended CommunityList ORF-Type" },
    { 131,      "Cisco AsPathList ORF-Type" },
    { 0,        NULL }
};

/* ORF Send/Receive, RFC5291 */
static const value_string orf_send_recv_vals[] = {
    { 1,        "Receive" },
    { 2,        "Send" },
    { 3,        "Both" },
    { 0,        NULL }
};

/* ORF Send/Receive, RFC5291 */
static const value_string orf_when_vals[] = {
    { 1,        "Immediate" },
    { 2,        "Defer" },
    { 0,        NULL }
};

static const value_string orf_entry_action_vals[] = {
    { BGP_ORF_ADD,          "Add" },
    { BGP_ORF_REMOVE,       "Remove" },
    { BGP_ORF_REMOVEALL,    "RemoveAll" },
    { 0,        NULL }
};

static const value_string orf_entry_match_vals[] = {
    { BGP_ORF_PERMIT,   "Permit" },
    { BGP_ORF_DENY,     "Deny" },
    { 0,        NULL }
};

/* BGPsec Send/Receive, RFC8205 */
static const value_string bgpsec_send_receive_vals[] = {
    { 0,        "Receive" },
    { 1,        "Send" },
    { 0,        NULL }
};

static const value_string capability_vals[] = {
    { BGP_CAPABILITY_RESERVED,                      "Reserved capability" },
    { BGP_CAPABILITY_MULTIPROTOCOL,                 "Multiprotocol extensions capability" },
    { BGP_CAPABILITY_ROUTE_REFRESH,                 "Route refresh capability" },
    { BGP_CAPABILITY_COOPERATIVE_ROUTE_FILTERING,   "Cooperative route filtering capability" },
    { BGP_CAPABILITY_MULTIPLE_ROUTE_DEST,           "Multiple routes to a destination capability" },
    { BGP_CAPABILITY_EXTENDED_NEXT_HOP,             "Extended Next Hop Encoding" },
    { BGP_CAPABILITY_EXTENDED_MESSAGE,              "BGP-Extended Message" },
    { BGP_CAPABILITY_BGPSEC,                        "BGPsec capability" },
    { BGP_CAPABILITY_MULTIPLE_LABELS,               "Multiple Labels capability" },
    { BGP_CAPABILITY_BGP_ROLE,                      "BGP Role" },
    { BGP_CAPABILITY_GRACEFUL_RESTART,              "Graceful Restart capability" },
    { BGP_CAPABILITY_4_OCTET_AS_NUMBER,             "Support for 4-octet AS number capability" },
    { BGP_CAPABILITY_DYNAMIC_CAPABILITY_CISCO,      "Deprecated Dynamic Capability (Cisco)" },
    { BGP_CAPABILITY_DYNAMIC_CAPABILITY,            "Support for Dynamic capability" },
    { BGP_CAPABILITY_MULTISESSION,                  "Multisession BGP Capability" },
    { BGP_CAPABILITY_ADDITIONAL_PATHS,              "Support for Additional Paths" },
    { BGP_CAPABILITY_ENHANCED_ROUTE_REFRESH,        "Enhanced route refresh capability" },
    { BGP_CAPABILITY_LONG_LIVED_GRACEFUL_RESTART,   "Long-Lived Graceful Restart (LLGR) Capability" },
    { BGP_CAPABILITY_CP_ORF,                        "CP-ORF Capability" },
    { BGP_CAPABILITY_FQDN,                          "FQDN Capability" },
    { BGP_CAPABILITY_ROUTE_REFRESH_CISCO,           "Route refresh capability (Cisco)" },
    { BGP_CAPABILITY_ORF_CISCO,                     "Cooperative route filtering capability (Cisco)" },
    { BGP_CAPABILITY_MULTISESSION_CISCO,            "Multisession BGP Capability (Cisco)" },
    { 0, NULL }
};

static const value_string community_vals[] = {
    { BGP_COMM_GRACEFUL_SHUTDOWN,   "GRACEFUL_SHUTDOWN" },
    { BGP_COMM_ACCEPT_OWN,          "ACCEPT_OWN" },
    { BGP_COMM_BLACKHOLE,           "BLACKHOLE" },
    { BGP_COMM_NO_EXPORT,           "NO_EXPORT" },
    { BGP_COMM_NO_ADVERTISE,        "NO_ADVERTISE" },
    { BGP_COMM_NO_EXPORT_SUBCONFED, "NO_EXPORT_SUBCONFED" },
    { BGP_COMM_NOPEER,              "NOPEER" },
    { 0,                            NULL }
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

/* NLRI type value_string as defined in idr-ls */
static const value_string bgp_ls_nlri_type_vals[] = {
        { LINK_STATE_LINK_NLRI,                 "Link NLRI" },
        { LINK_STATE_NODE_NLRI,                 "Node NLRI" },
        { LINK_STATE_IPV4_TOPOLOGY_PREFIX_NLRI, "IPv4 Topology Prefix NLRI" },
        { LINK_STATE_IPV6_TOPOLOGY_PREFIX_NLRI, "IPv6 Topology Prefix NLRI" },
        {0, NULL },
};

/* Link-State NLRI Protocol-ID value strings */
static const value_string link_state_nlri_protocol_id_values[] = {
        {BGP_LS_NLRI_PROTO_ID_UNKNOWN, "Unknown" },
        {BGP_LS_NLRI_PROTO_ID_IS_IS_LEVEL_1, "IS-IS Level 1"},
        {BGP_LS_NLRI_PROTO_ID_IS_IS_LEVEL_2, "IS-IS Level 2"},
        {BGP_LS_NLRI_PROTO_ID_OSPF, "OSPF"},
        {BGP_LS_NLRI_PROTO_ID_DIRECT, "Direct"},
        {BGP_LS_NLRI_PROTO_ID_STATIC, "Static"},
        {BGP_LS_NLRI_PROTO_ID_BGP, "BGP"},
        {0, NULL},
};

/* Link-State routing universes */
static const val64_string link_state_nlri_routing_universe_values[] = {
        {BGP_LS_NLRI_ROUTING_UNIVERSE_LEVEL_3, "L3 packet topology" },
        {BGP_LS_NLRI_ROUTING_UNIVERSE_LEVEL_1, "L1 optical topology"},
        {0, NULL}
};

/* Link state prefix NLRI OSPF Route Type */
static const value_string link_state_prefix_descriptors_ospf_route_type[] = {
        {BGP_LS_PREFIX_OSPF_ROUTE_TYPE_UNKNOWN,     "Unknown" },
        {BGP_LS_PREFIX_OSPF_ROUTE_TYPE_INTRA_AREA,  "Intra-Area"},
        {BGP_LS_PREFIX_OSPF_ROUTE_TYPE_INTER_AREA,  "Inter Area"},
        {BGP_LS_PREFIX_OSPF_ROUTE_TYPE_EXTERNAL_1,  "External 1"},
        {BGP_LS_PREFIX_OSPF_ROUTE_TYPE_EXTERNAL_2,  "External 2"},
        {BGP_LS_PREFIX_OSPF_ROUTE_TYPE_NSSA_1,      "NSSA 1"},
        {BGP_LS_PREFIX_OSPF_ROUTE_TYPE_NSSA_2,      "NSSA 2"},
        {0, NULL}
};

/* Link state Flex Algo Metric Type: draft-ietf-lsr-flex-algo-17 */
static const value_string flex_algo_metric_types[] = {
    { 0, "IGP Metric"},
    { 1, "Min Unidirectional Link Delay"},
    { 2, "TE Metric"},
    { 0, NULL }
};

/* Link state IGP Algorithm Type: https://www.iana.org/assignments/igp-parameters/igp-parameters.xhtml */
static const value_string igp_algo_types[] = {
    { 0,   "Shortest Path First (SPF)" },
    { 1,   "Strict Shortest Path First (Strict SPF)" },
    { 0,   NULL }
};

/* Link state IGP MSD Type: https://www.iana.org/assignments/igp-parameters/igp-parameters.xhtml */
static const value_string igp_msd_types[] = {
    { 0,   "Reserved" },
    { 1,   "Base MPLS Imposition MSD" },
    { 2,   "ERLD-MSD" },
    { 41,  "SRH Max SL" },
    { 42,  "SRH Max End Pop" },
    { 44,  "SRH Max H.Encaps" },
    { 45,  "SRH Max End D" },
    { 0,   NULL }
};

/* NLRI type value_string as define in BGP flow spec RFC */

static const value_string flowspec_nlri_opvaluepair_type[] = {
    { BGPNLRI_FSPEC_DST_PFIX, "Destination prefix filter" },
    { BGPNLRI_FSPEC_SRC_PFIX, "Source prefix filter" },
    { BGPNLRI_FSPEC_IP_PROTO, "Protocol / Next Header filter" },
    { BGPNLRI_FSPEC_PORT,     "Port filter" },
    { BGPNLRI_FSPEC_DST_PORT, "Destination port filter" },
    { BGPNLRI_FSPEC_SRC_PORT, "Source port filter" },
    { BGPNLRI_FSPEC_ICMP_TP,  "ICMP type filter" },
    { BGPNLRI_FSPEC_ICMP_CD,  "ICMP code filter" },
    { BGPNLRI_FSPEC_TCP_FLAGS,"TCP flags filter" },
    { BGPNLRI_FSPEC_PCK_LEN,  "Packet Length filter" },
    { BGPNLRI_FSPEC_DSCP,     "DSCP marking filter" },
    { BGPNLRI_FSPEC_FRAGMENT, "IP fragment filter" },
    {0, NULL },
};

/* Subtype Route Refresh, draft-ietf-idr-bgp-enhanced-route-refresh-02 */
static const value_string route_refresh_subtype_vals[] = {
    { 0, "Normal route refresh request [RFC2918] with/without ORF [RFC5291]" },
    { 1, "Demarcation of the beginning of a route refresh" },
    { 2, "Demarcation of the ending of a route refresh" },
    { 0,  NULL }
};

static const value_string bgp_prefix_sid_type[] = {
    { BGP_PREFIX_SID_TLV_LABEL_INDEX,     "Label-Index" },
    { BGP_PREFIX_SID_TLV_2,               "Deprecated" },
    { BGP_PREFIX_SID_TLV_ORIGINATOR_SRGB, "Originator SRGB" },
    { BGP_PREFIX_SID_TLV_4,               "Deprecated" },
    { BGP_PREFIX_SID_TLV_SRV6_L3_SERVICE, "SRv6 L3 Service" },
    { BGP_PREFIX_SID_TLV_SRV6_L2_SERVICE, "SRv6 L2 Service" },
    { 0, NULL }
};

static const value_string srv6_service_sub_tlv_type[] = {
    { SRV6_SERVICE_SRV6_SID_INFORMATION,   "SRv6 SID Information" },
    { 0,  NULL }
};

static const value_string srv6_service_data_sub_sub_tlv_type[] = {
    { SRV6_SERVICE_DATA_SRV6_SID_STRUCTURE,   "SRv6 SID Structure" },
    { 0,  NULL }
};

/* SRv6 Endpoint behavior value_string [draft-ietf-spring-srv6-network-programming-24]. */
static const value_string srv6_endpoint_behavior[] = {
    { SRV6_ENDPOINT_BEHAVIOR_END,                    "End" },
    { SRV6_ENDPOINT_BEHAVIOR_END_PSP,                "End with PSP" },
    { SRV6_ENDPOINT_BEHAVIOR_END_USP,                "End with USP" },
    { SRV6_ENDPOINT_BEHAVIOR_END_PSP_USP,            "End with PSP & USP" },
    { SRV6_ENDPOINT_BEHAVIOR_END_X,                  "End.X" },
    { SRV6_ENDPOINT_BEHAVIOR_END_X_PSP,              "End.X with PSP" },
    { SRV6_ENDPOINT_BEHAVIOR_END_X_USP,              "End.X with USP" },
    { SRV6_ENDPOINT_BEHAVIOR_END_X_PSP_USP,          "End.X with PSP & USP" },
    { SRV6_ENDPOINT_BEHAVIOR_END_T,                  "End.T" },
    { SRV6_ENDPOINT_BEHAVIOR_END_T_PSP,              "End.T with PSP" },
    { SRV6_ENDPOINT_BEHAVIOR_END_T_USP,              "End.T with USP" },
    { SRV6_ENDPOINT_BEHAVIOR_END_T_PSP_USP,          "End.T with PSP & USP" },
    { SRV6_ENDPOINT_BEHAVIOR_END_B6_ENCAPS,          "End.B6.Encaps" },
    { SRV6_ENDPOINT_BEHAVIOR_END_BM,                 "End.BM" },
    { SRV6_ENDPOINT_BEHAVIOR_END_DX6,                "End.DX6" },
    { SRV6_ENDPOINT_BEHAVIOR_END_DX4,                "End.DX4" },
    { SRV6_ENDPOINT_BEHAVIOR_END_DT6,                "End.DT6" },
    { SRV6_ENDPOINT_BEHAVIOR_END_DT4,                "End.DT4" },
    { SRV6_ENDPOINT_BEHAVIOR_END_DT46,               "End.DT46" },
    { SRV6_ENDPOINT_BEHAVIOR_END_DX2,                "End.DX2" },
    { SRV6_ENDPOINT_BEHAVIOR_END_DX2V,               "End.DX2V" },
    { SRV6_ENDPOINT_BEHAVIOR_END_DT2U,               "End.DT2U" },
    { SRV6_ENDPOINT_BEHAVIOR_END_DT2M,               "End.DT2M" },
    { SRV6_ENDPOINT_BEHAVIOR_END_B6_ENCAPS_RED,      "End.B6.Encaps.Red" },
    { SRV6_ENDPOINT_BEHAVIOR_END_USD,                "End with USD" },
    { SRV6_ENDPOINT_BEHAVIOR_END_PSP_USD,            "End with PSP & USD" },
    { SRV6_ENDPOINT_BEHAVIOR_END_USP_USD,            "End with USP & USD" },
    { SRV6_ENDPOINT_BEHAVIOR_END_PSP_USP_USD,        "End with PSP, USP & USD" },
    { SRV6_ENDPOINT_BEHAVIOR_END_X_USD,              "End.X with USD" },
    { SRV6_ENDPOINT_BEHAVIOR_END_X_PSP_USD,          "End.X with PSP & USD" },
    { SRV6_ENDPOINT_BEHAVIOR_END_X_USP_USD,          "End.X with USP & USD" },
    { SRV6_ENDPOINT_BEHAVIOR_END_X_PSP_USP_USD,      "End.X with PSP, USP & USD" },
    { SRV6_ENDPOINT_BEHAVIOR_END_T_USD,              "End.T with USD" },
    { SRV6_ENDPOINT_BEHAVIOR_END_T_PSP_USD,          "End.T with PSP & USD" },
    { SRV6_ENDPOINT_BEHAVIOR_END_T_USP_USD,          "End.T with USP & USD" },
    { SRV6_ENDPOINT_BEHAVIOR_END_T_PSP_USP_USD,      "End.T with PSP, USP & USD" },
    { SRV6_ENDPOINT_BEHAVIOR_END_ONLY_CSID,          "End with NEXT-ONLY-CSID" },
    { SRV6_ENDPOINT_BEHAVIOR_END_CSID,               "End with NEXT-CSID" },
    { SRV6_ENDPOINT_BEHAVIOR_END_CSID_PSP,           "End with NEXT-CSID & PSP" },
    { SRV6_ENDPOINT_BEHAVIOR_END_CSID_USP,           "End with NEXT-CSID & USP" },
    { SRV6_ENDPOINT_BEHAVIOR_END_CSID_PSP_USP,       "End with NEXT-CSID, PSP & USP" },
    { SRV6_ENDPOINT_BEHAVIOR_END_CSID_USD,           "End with NEXT-CSID & USD" },
    { SRV6_ENDPOINT_BEHAVIOR_END_CSID_PSP_USD,       "End with NEXT-CSID, PSP & USD" },
    { SRV6_ENDPOINT_BEHAVIOR_END_CSID_USP_USD,       "End with NEXT-CSID, USP & USD" },
    { SRV6_ENDPOINT_BEHAVIOR_END_CSID_PSP_USP_USD,   "End with NEXT-CSID, PSP, USP & USD" },
    { SRV6_ENDPOINT_BEHAVIOR_END_X_ONLY_CSID,        "End.X with NEXT-ONLY-CSID" },
    { SRV6_ENDPOINT_BEHAVIOR_END_X_CSID,             "End.X with NEXT-CSID" },
    { SRV6_ENDPOINT_BEHAVIOR_END_X_CSID_PSP,         "End.X with NEXT-CSID & PSP" },
    { SRV6_ENDPOINT_BEHAVIOR_END_X_CSID_USP,         "End.X with NEXT-CSID & USP" },
    { SRV6_ENDPOINT_BEHAVIOR_END_X_CSID_PSP_USP,     "End.X with NEXT-CSID, PSP & USP" },
    { SRV6_ENDPOINT_BEHAVIOR_END_X_CSID_USD,         "End.X with NEXT-CSID & USD" },
    { SRV6_ENDPOINT_BEHAVIOR_END_X_CSID_PSP_USD,     "End.X with NEXT-CSID, PSP & USD" },
    { SRV6_ENDPOINT_BEHAVIOR_END_X_CSID_USP_USD,     "End.X with NEXT-CSID, USP & USD" },
    { SRV6_ENDPOINT_BEHAVIOR_END_X_CSID_PSP_USP_USD, "End.X with NEXT-CSID, PSP, USP & USD" },
    { SRV6_ENDPOINT_BEHAVIOR_END_DX6_CSID,           "End.DX6 with NEXT-CSID" },
    { SRV6_ENDPOINT_BEHAVIOR_END_DX4_CSID,           "End.DX4 with NEXT-CSID" },
    { SRV6_ENDPOINT_BEHAVIOR_END_DT6_CSID,           "End.DT6 with NEXT-CSID" },
    { SRV6_ENDPOINT_BEHAVIOR_END_DT4_CSID,           "End.DT4 with NEXT-CSID" },
    { SRV6_ENDPOINT_BEHAVIOR_END_DT46_CSID,          "End.DT46 with NEXT-CSID" },
    { SRV6_ENDPOINT_BEHAVIOR_END_DX2_CSID,           "End.DX2 with NEXT-CSID" },
    { SRV6_ENDPOINT_BEHAVIOR_END_DX2V_CSID,          "End.DX2V with NEXT-CSID" },
    { SRV6_ENDPOINT_BEHAVIOR_END_DT2U_CSID,          "End.DT2U with NEXT-CSID" },
    { SRV6_ENDPOINT_BEHAVIOR_END_DT2M_CSID,          "End.DT2M with NEXT-CSID" },
    { SRV6_ENDPOINT_BEHAVIOR_OPAQUE,                 "Opaque" },
    { 0,  NULL }
};

static const true_false_string tfs_non_transitive_transitive = { "Non-transitive", "Transitive" };
static const true_false_string tfs_esi_label_flag = { "Single-Active redundancy", "All-Active redundancy" };
static const true_false_string tfs_ospf_rt_mt = { "Type-2", "Type-1" };
static const true_false_string tfs_eigrp_rtype = { "Internal" , "External" };
static const true_false_string tfs_cost_replace = { "Replaces the original attribute value", "Evaluated after the original attribute value" };
static const true_false_string tfs_exclude_include = { "Exclude", "Include" };

/* Maximal size of an IP address string */
#define MAX_SIZE_OF_IP_ADDR_STRING      16

static int proto_bgp = -1;

/* BGP header field initialisation */

/* global BGP header filed */

static int hf_bgp_marker = -1;
static int hf_bgp_length = -1;
static int hf_bgp_prefix_length = -1;
static int hf_bgp_rd = -1;
static int hf_bgp_continuation = -1;
static int hf_bgp_originating_as = -1;
static int hf_bgp_community_prefix = -1;
static int hf_bgp_endpoint_address = -1;
static int hf_bgp_endpoint_address_ipv6 = -1;
static int hf_bgp_label_stack = -1;
static int hf_bgp_large_communities = -1;
static int hf_bgp_large_communities_ga = -1;
static int hf_bgp_large_communities_ldp1 = -1;
static int hf_bgp_large_communities_ldp2 = -1;
static int hf_bgp_vplsad_length = -1;
static int hf_bgp_vplsad_rd = -1;
static int hf_bgp_bgpad_pe_addr = -1;
static int hf_bgp_vplsbgp_ce_id = -1;
static int hf_bgp_vplsbgp_labelblock_offset = -1;
static int hf_bgp_vplsbgp_labelblock_size = -1;
static int hf_bgp_vplsbgp_labelblock_base = -1;
static int hf_bgp_wildcard_route_target = -1;
static int hf_bgp_type = -1;

/* BGP open message header filed */

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

/* BGP notify header field */

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
static int hf_bgp_notify_error_open_bad_peer_as = -1;
static int hf_bgp_notify_communication_length = -1;
static int hf_bgp_notify_communication = -1;

/* BGP route refresh header field */

static int hf_bgp_route_refresh_afi = -1;
static int hf_bgp_route_refresh_subtype = -1;
static int hf_bgp_route_refresh_safi = -1;
static int hf_bgp_route_refresh_orf = -1;
static int hf_bgp_route_refresh_orf_flag = -1;
static int hf_bgp_route_refresh_orf_type = -1;
static int hf_bgp_route_refresh_orf_length = -1;
static int hf_bgp_route_refresh_orf_entry_prefixlist = -1;
static int hf_bgp_route_refresh_orf_entry_action = -1;
static int hf_bgp_route_refresh_orf_entry_match = -1;
static int hf_bgp_route_refresh_orf_entry_sequence = -1;
static int hf_bgp_route_refresh_orf_entry_prefixmask_lower = -1;
static int hf_bgp_route_refresh_orf_entry_prefixmask_upper = -1;
static int hf_bgp_route_refresh_orf_entry_ip = -1;

/* BGP capabilities header field */

static int hf_bgp_cap = -1;
static int hf_bgp_cap_type = -1;
static int hf_bgp_cap_length = -1;
static int hf_bgp_cap_action = -1;
static int hf_bgp_cap_unknown = -1;
static int hf_bgp_cap_reserved = -1;
static int hf_bgp_cap_mp_afi = -1;
static int hf_bgp_cap_mp_safi = -1;
static int hf_bgp_cap_enh_afi = -1;
static int hf_bgp_cap_enh_safi = -1;
static int hf_bgp_cap_enh_nhafi = -1;
static int hf_bgp_cap_gr_timers = -1;
static int hf_bgp_cap_gr_timers_restart_flag = -1;
static int hf_bgp_cap_gr_timers_notification_flag = -1;
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
static int hf_bgp_cap_fqdn_hostname_len = -1;
static int hf_bgp_cap_fqdn_hostname = -1;
static int hf_bgp_cap_fqdn_domain_name_len = -1;
static int hf_bgp_cap_fqdn_domain_name = -1;
static int hf_bgp_cap_multisession_flags = -1;
static int hf_bgp_cap_bgpsec_flags = -1;
static int hf_bgp_cap_bgpsec_version = -1;
static int hf_bgp_cap_bgpsec_sendreceive = -1;
static int hf_bgp_cap_bgpsec_reserved = -1;
static int hf_bgp_cap_bgpsec_afi = -1;

/* BGP update global header field */
static int hf_bgp_update_withdrawn_routes_length = -1;
static int hf_bgp_update_withdrawn_routes = -1;


/* BGP update path attribute header field */
static int hf_bgp_update_total_path_attribute_length = -1;
static int hf_bgp_update_path_attributes = -1;
static int hf_bgp_update_path_attributes_unknown = -1;
static int hf_bgp_update_path_attribute_communities = -1;
static int hf_bgp_update_path_attribute_community_well_known = -1;
static int hf_bgp_update_path_attribute_community = -1;
static int hf_bgp_update_path_attribute_community_as = -1;
static int hf_bgp_update_path_attribute_community_value = -1;
static int hf_bgp_update_path_attribute = -1;
static int hf_bgp_update_path_attribute_flags = -1;
static int hf_bgp_update_path_attribute_flags_optional = -1;
static int hf_bgp_update_path_attribute_flags_transitive = -1;
static int hf_bgp_update_path_attribute_flags_partial = -1;
static int hf_bgp_update_path_attribute_flags_extended_length = -1;
static int hf_bgp_update_path_attribute_flags_unused = -1;
static int hf_bgp_update_path_attribute_type_code = -1;
static int hf_bgp_update_path_attribute_length = -1;
static int hf_bgp_update_path_attribute_next_hop = -1;
static int hf_bgp_update_path_attribute_as_path_segment = -1;
static int hf_bgp_update_path_attribute_as_path_segment_type = -1;
static int hf_bgp_update_path_attribute_as_path_segment_length = -1;
static int hf_bgp_update_path_attribute_as_path_segment_as2 = -1;
static int hf_bgp_update_path_attribute_as_path_segment_as4 = -1;
static int hf_bgp_update_path_attribute_origin = -1;
static int hf_bgp_update_path_attribute_cluster_list = -1;
static int hf_bgp_update_path_attribute_cluster_id = -1;
static int hf_bgp_update_path_attribute_originator_id = -1;
static int hf_bgp_update_path_attribute_local_pref = -1;
static int hf_bgp_update_path_attribute_attrset_origin_as = -1;
static int hf_bgp_update_path_attribute_multi_exit_disc = -1;
static int hf_bgp_update_path_attribute_aggregator_as = -1;
static int hf_bgp_update_path_attribute_aggregator_origin = -1;
static int hf_bgp_update_path_attribute_link_state = -1;
static int hf_bgp_update_path_attribute_mp_reach_nlri_address_family = -1;
static int hf_bgp_update_path_attribute_mp_reach_nlri_safi = -1;
static int hf_bgp_update_path_attribute_mp_reach_nlri_next_hop = -1;
static int hf_bgp_update_path_attribute_mp_reach_nlri_next_hop_rd = -1;
static int hf_bgp_update_path_attribute_mp_reach_nlri_next_hop_ipv4 = -1;
static int hf_bgp_update_path_attribute_mp_reach_nlri_next_hop_ipv6 = -1;
static int hf_bgp_update_path_attribute_mp_reach_nlri_next_hop_ipv6_link_local = -1;
static int hf_bgp_update_path_attribute_mp_reach_nlri_nbr_snpa = -1;
static int hf_bgp_update_path_attribute_mp_reach_nlri_snpa_length = -1;
static int hf_bgp_update_path_attribute_mp_reach_nlri_snpa = -1;
static int hf_bgp_update_path_attribute_mp_reach_nlri = -1;
static int hf_bgp_update_path_attribute_mp_unreach_nlri_address_family = -1;
static int hf_bgp_update_path_attribute_mp_unreach_nlri_safi = -1;
static int hf_bgp_update_path_attribute_mp_unreach_nlri = -1;
static int hf_bgp_update_path_attribute_aigp = -1;
static int hf_bgp_update_path_attribute_bgpsec_sb_len = -1;
static int hf_bgp_update_path_attribute_bgpsec_algo_id = -1;
static int hf_bgp_update_path_attribute_bgpsec_sps_pcount = -1;
static int hf_bgp_update_path_attribute_bgpsec_sps_flags = -1;
static int hf_bgp_update_path_attribute_bgpsec_sps_as = -1;
static int hf_bgp_update_path_attribute_bgpsec_sp_len = -1;
static int hf_bgp_update_path_attribute_bgpsec_ski = -1;
static int hf_bgp_update_path_attribute_bgpsec_sig_len = -1;
static int hf_bgp_update_path_attribute_bgpsec_sig = -1;
static int hf_bgp_update_path_attribute_d_path = -1;
static int hf_bgp_d_path_ga = -1;
static int hf_bgp_d_path_la = -1;
static int hf_bgp_d_path_length = -1;
static int hf_bgp_d_path_isf_safi = -1;
static int hf_bgp_evpn_nlri = -1;
static int hf_bgp_evpn_nlri_rt = -1;
static int hf_bgp_evpn_nlri_len = -1;
static int hf_bgp_evpn_nlri_rd = -1;
static int hf_bgp_evpn_nlri_esi = -1;
static int hf_bgp_evpn_nlri_esi_type = -1;
static int hf_bgp_evpn_nlri_esi_lacp_mac = -1;
static int hf_bgp_evpn_nlri_esi_portk = -1;
static int hf_bgp_evpn_nlri_esi_remain = -1;
static int hf_bgp_evpn_nlri_esi_value = -1;
static int hf_bgp_evpn_nlri_esi_value_type0 = -1;
static int hf_bgp_evpn_nlri_esi_rb_mac = -1;
static int hf_bgp_evpn_nlri_esi_rbprio = -1;
static int hf_bgp_evpn_nlri_esi_sys_mac = -1;
static int hf_bgp_evpn_nlri_esi_mac_discr = -1;
static int hf_bgp_evpn_nlri_esi_router_id = -1;
static int hf_bgp_evpn_nlri_esi_router_discr = -1;
static int hf_bgp_evpn_nlri_esi_asn = -1;
static int hf_bgp_evpn_nlri_esi_asn_discr = -1;
static int hf_bgp_evpn_nlri_esi_reserved = -1;
static int hf_bgp_evpn_nlri_etag = -1;
static int hf_bgp_evpn_nlri_mpls_ls1 = -1;
static int hf_bgp_evpn_nlri_mpls_ls2 = -1;
static int hf_bgp_evpn_nlri_vni = -1;
static int hf_bgp_evpn_nlri_maclen = -1;
static int hf_bgp_evpn_nlri_mac_addr = -1;
static int hf_bgp_evpn_nlri_iplen = -1;
static int hf_bgp_evpn_nlri_prefix_len = -1;
static int hf_bgp_evpn_nlri_ip_addr = -1;
static int hf_bgp_evpn_nlri_ipv6_addr = -1;
static int hf_bgp_evpn_nlri_ipv4_gtw = -1;
static int hf_bgp_evpn_nlri_ipv6_gtw = -1;
static int hf_bgp_evpn_nlri_igmp_mc_or_length = -1;
static int hf_bgp_evpn_nlri_igmp_mc_or_addr_ipv4 = -1;
static int hf_bgp_evpn_nlri_igmp_mc_or_addr_ipv6 = -1;
static int hf_bgp_evpn_nlri_igmp_mc_flags = -1;
static int hf_bgp_evpn_nlri_igmp_mc_flags_v1 = -1;
static int hf_bgp_evpn_nlri_igmp_mc_flags_v2 = -1;
static int hf_bgp_evpn_nlri_igmp_mc_flags_v3 = -1;
static int hf_bgp_evpn_nlri_igmp_mc_flags_ie = -1;
static int hf_bgp_evpn_nlri_igmp_mc_flags_reserved = -1;

static int * const evpn_nlri_igmp_mc_flags[] = {
       &hf_bgp_evpn_nlri_igmp_mc_flags_v1,
       &hf_bgp_evpn_nlri_igmp_mc_flags_v2,
       &hf_bgp_evpn_nlri_igmp_mc_flags_v3,
       &hf_bgp_evpn_nlri_igmp_mc_flags_ie,
       &hf_bgp_evpn_nlri_igmp_mc_flags_reserved,
       NULL
       };

/* BGP update tunnel encaps attribute RFC 5512 */

static int hf_bgp_update_encaps_tunnel_tlv_len = -1;
static int hf_bgp_update_encaps_tunnel_tlv_type = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_len = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_type = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_session_id = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_cookie = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_gre_key = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_color_value = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_lb_block_length = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_value = -1;

/* draft-ietf-idr-tunnel-encaps */
static int hf_bgp_update_encaps_tunnel_subtlv_vxlan_flags = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_vxlan_flags_valid_vnid = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_vxlan_flags_valid_mac = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_vxlan_flags_reserved = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_vxlan_vnid = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_vxlan_mac = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_vxlan_reserved = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_vxlan_gpe_flags = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_vxlan_gpe_flags_version = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_vxlan_gpe_flags_valid_vnid = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_vxlan_gpe_flags_reserved = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_vxlan_gpe_vnid = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_vxlan_gpe_reserved = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_nvgre_flags = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_nvgre_flags_valid_vnid = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_nvgre_flags_valid_mac = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_nvgre_flags_reserved = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_nvgre_vnid = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_nvgre_mac = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_nvgre_reserved = -1;

/* draft-ietf-idr-segment-routing-te-policy */
static int hf_bgp_update_encaps_tunnel_subtlv_pref_flags = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_pref_reserved = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_pref_preference = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_binding_sid_flags = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_binding_sid_flags_specified = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_binding_sid_flags_invalid = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_binding_sid_flags_reserved = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_binding_sid_reserved = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_binding_sid_sid= -1;
static int hf_bgp_update_encaps_tunnel_subtlv_enlp_flags = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_enlp_reserved = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_enlp_enlp = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_priority_priority = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_priority_reserved = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_segment_list_reserved = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv_type = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv_length = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv_data = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv_flags = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv_flags_verification = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv_flags_algorithm = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv_flags_reserved = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv_reserved = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv_mpls_label = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv_traffic_class = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv_bottom_stack = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv_ttl = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_policy_name_reserved = -1;
static int hf_bgp_update_encaps_tunnel_subtlv_policy_name_name = -1;

/* RFC 6514 PMSI Tunnel Attribute */
static int hf_bgp_pmsi_tunnel_flags = -1;
static int hf_bgp_pmsi_tunnel_type = -1;
static int hf_bgp_pmsi_tunnel_id = -1;
static int hf_bgp_pmsi_tunnel_not_present = -1;
static int hf_bgp_pmsi_tunnel_rsvp_p2mp_id = -1; /* RFC4875 section 19 */
static int hf_bgp_pmsi_tunnel_rsvp_p2mp_tunnel_id = -1;
static int hf_bgp_pmsi_tunnel_rsvp_p2mp_ext_tunnel_idv4 = -1;
static int hf_bgp_pmsi_tunnel_mldp_fec_el_type = -1; /* RFC 6388 section 2.3 */
static int hf_bgp_pmsi_tunnel_mldp_fec_el_afi = -1;
static int hf_bgp_pmsi_tunnel_mldp_fec_el_adr_len = -1;
static int hf_bgp_pmsi_tunnel_mldp_fec_el_root_nodev4 = -1;
static int hf_bgp_pmsi_tunnel_mldp_fec_el_root_nodev6 = -1;
static int hf_bgp_pmsi_tunnel_mldp_fec_el_opa_len = -1;
static int hf_bgp_pmsi_tunnel_mldp_fec_el_opa_val_type = -1;
static int hf_bgp_pmsi_tunnel_mldp_fec_el_opa_val_len = -1;
static int hf_bgp_pmsi_tunnel_mldp_fec_el_opa_value_rn = -1;
static int hf_bgp_pmsi_tunnel_mldp_fec_el_opa_value_str = -1;
static int hf_bgp_pmsi_tunnel_mldp_fec_el_opa_val_ext_type = -1;
static int hf_bgp_pmsi_tunnel_mldp_fec_el_opa_val_ext_len = -1;
static int hf_bgp_pmsi_tunnel_pimsm_sender = -1;
static int hf_bgp_pmsi_tunnel_pimsm_pmc_group = -1;
static int hf_bgp_pmsi_tunnel_pimssm_root_node = -1;
static int hf_bgp_pmsi_tunnel_pimssm_pmc_group = -1;
static int hf_bgp_pmsi_tunnel_pimbidir_sender = -1;
static int hf_bgp_pmsi_tunnel_pimbidir_pmc_group = -1;
static int hf_bgp_pmsi_tunnel_ingress_rep_addr = -1;

/* RFC 7311 attribute */
static int hf_bgp_aigp_type = -1;
static int hf_bgp_aigp_tlv_length = -1;
static int hf_bgp_aigp_accu_igp_metric = -1;


/* MPLS labels decoding */
static int hf_bgp_update_mpls_label = -1;
static int hf_bgp_update_mpls_label_value = -1;
static int hf_bgp_update_mpls_label_value_20bits = -1;
static int hf_bgp_update_mpls_traffic_class = -1;
static int hf_bgp_update_mpls_bottom_stack = -1;

/* BGP update path attribute SSA SAFI Specific attribute (deprecated should we keep it ?) */

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

/* BGP NLRI head field */
static int hf_bgp_update_nlri = -1;

static int hf_bgp_mp_reach_nlri_ipv4_prefix = -1;
static int hf_bgp_mp_unreach_nlri_ipv4_prefix = -1;
static int hf_bgp_mp_reach_nlri_ipv6_prefix = -1;
static int hf_bgp_mp_unreach_nlri_ipv6_prefix = -1;
static int hf_bgp_mp_nlri_tnl_id = -1;
static int hf_bgp_withdrawn_prefix = -1;
static int hf_bgp_nlri_prefix = -1;
static int hf_bgp_nlri_path_id = -1;

/* BGP mcast IP VPN nlri header field */

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

/* BGP SR policy nlri field */
static int hf_bgp_sr_policy_nlri_length = - 1;
static int hf_bgp_sr_policy_nlri_distinguisher = - 1;
static int hf_bgp_sr_policy_nlri_policy_color = - 1;
static int hf_bgp_sr_policy_nlri_endpoint_v4 = - 1;
static int hf_bgp_sr_policy_nlri_endpoint_v6 = - 1;

/* BGP-LS */

static int hf_bgp_ls_type = -1;
static int hf_bgp_ls_length = -1;

static int hf_bgp_ls_nlri = -1;
static int hf_bgp_ls_safi128_nlri = -1;
static int hf_bgp_ls_safi128_nlri_route_distinguisher = -1;
static int hf_bgp_ls_safi128_nlri_route_distinguisher_type = -1;
static int hf_bgp_ls_safi128_nlri_route_dist_admin_asnum_2 = -1;
static int hf_bgp_ls_safi128_nlri_route_dist_admin_ipv4 = -1;
static int hf_bgp_ls_safi128_nlri_route_dist_admin_asnum_4 = -1;
static int hf_bgp_ls_safi128_nlri_route_dist_asnum_2 = -1;
static int hf_bgp_ls_safi128_nlri_route_dist_asnum_4 = -1;
static int hf_bgp_ls_nlri_type = -1;
static int hf_bgp_ls_nlri_length = -1;
static int hf_bgp_ls_nlri_link_nlri_type = -1;
static int hf_bgp_ls_nlri_link_descriptors_tlv = -1;
static int hf_bgp_ls_nlri_prefix_descriptors_tlv = -1;
static int hf_bgp_ls_nlri_link_local_identifier = -1;
static int hf_bgp_ls_nlri_link_remote_identifier = -1;
static int hf_bgp_ls_nlri_ipv4_interface_address = -1;
static int hf_bgp_ls_nlri_ipv4_neighbor_address = -1;
static int hf_bgp_ls_nlri_ipv6_interface_address = -1;
static int hf_bgp_ls_nlri_ipv6_neighbor_address = -1;
static int hf_bgp_ls_nlri_multi_topology_id = -1;
static int hf_bgp_ls_nlri_ospf_route_type = -1;
static int hf_bgp_ls_nlri_ip_reachability_prefix_ip = -1;
static int hf_bgp_ls_nlri_ip_reachability_prefix_ip6 = -1;
static int hf_bgp_ls_nlri_node_nlri_type = -1;
static int hf_bgp_ls_nlri_node_protocol_id = -1;
static int hf_bgp_ls_nlri_node_identifier = -1;
static int hf_bgp_ls_ipv4_topology_prefix_nlri_type = -1;
static int hf_bgp_ls_ipv6_topology_prefix_nlri_type = -1;

/* BGP-LS + SR */
static int hf_bgp_ls_sr_tlv_capabilities = -1;
static int hf_bgp_ls_sr_tlv_capabilities_range_size = -1;
static int hf_bgp_ls_sr_tlv_capabilities_flags = -1;
static int hf_bgp_ls_sr_tlv_capabilities_flags_i = -1;
static int hf_bgp_ls_sr_tlv_capabilities_flags_v = -1;
static int hf_bgp_ls_sr_tlv_capabilities_flags_h = -1;
static int hf_bgp_ls_sr_tlv_capabilities_flags_reserved = -1;
static int hf_bgp_ls_sr_tlv_capabilities_sid_label = -1;
static int hf_bgp_ls_sr_tlv_capabilities_sid_index = -1;
static int hf_bgp_ls_sr_tlv_algorithm = -1;
static int hf_bgp_ls_sr_tlv_algorithm_value = -1;
static int hf_bgp_ls_sr_tlv_local_block = -1;                      /* 1036 */
static int hf_bgp_ls_sr_tlv_local_block_flags = -1;
static int hf_bgp_ls_sr_tlv_local_block_range_size = -1;
static int hf_bgp_ls_sr_tlv_local_block_sid_label = -1;
static int hf_bgp_ls_sr_tlv_local_block_sid_index = -1;
static int hf_bgp_ls_sr_tlv_flex_algo_def = -1;                    /* 1039 */
static int hf_bgp_ls_sr_tlv_flex_algo_algorithm = -1;
static int hf_bgp_ls_sr_tlv_flex_algo_metric_type = -1;
static int hf_bgp_ls_sr_tlv_flex_algo_calc_type = -1;
static int hf_bgp_ls_sr_tlv_flex_algo_priority = -1;
static int hf_bgp_ls_sr_tlv_flex_algo_exc_any_affinity = -1;       /* 1040 */
static int hf_bgp_ls_sr_tlv_flex_algo_inc_any_affinity = -1;       /* 1041 */
static int hf_bgp_ls_sr_tlv_flex_algo_inc_all_affinity = -1;       /* 1042 */
static int hf_bgp_ls_sr_tlv_prefix_sid = -1;
static int hf_bgp_ls_sr_tlv_prefix_sid_flags = -1;
static int hf_bgp_ls_sr_tlv_prefix_sid_flags_r = -1;
static int hf_bgp_ls_sr_tlv_prefix_sid_flags_n = -1;
static int hf_bgp_ls_sr_tlv_prefix_sid_flags_np = -1;
static int hf_bgp_ls_sr_tlv_prefix_sid_flags_p = -1;
static int hf_bgp_ls_sr_tlv_prefix_sid_flags_m = -1;
static int hf_bgp_ls_sr_tlv_prefix_sid_flags_e = -1;
static int hf_bgp_ls_sr_tlv_prefix_sid_flags_v = -1;
static int hf_bgp_ls_sr_tlv_prefix_sid_flags_l = -1;
static int hf_bgp_ls_sr_tlv_prefix_sid_algo = -1;
static int hf_bgp_ls_sr_tlv_prefix_sid_label = -1;
static int hf_bgp_ls_sr_tlv_prefix_sid_index = -1;
static int hf_bgp_ls_sr_tlv_adjacency_sid = -1;
static int hf_bgp_ls_sr_tlv_adjacency_sid_flags = -1;
static int hf_bgp_ls_sr_tlv_adjacency_sid_flags_fi = -1;
static int hf_bgp_ls_sr_tlv_adjacency_sid_flags_bi = -1;
static int hf_bgp_ls_sr_tlv_adjacency_sid_flags_bo = -1;
static int hf_bgp_ls_sr_tlv_adjacency_sid_flags_vi = -1;
static int hf_bgp_ls_sr_tlv_adjacency_sid_flags_vo = -1;
static int hf_bgp_ls_sr_tlv_adjacency_sid_flags_li = -1;
static int hf_bgp_ls_sr_tlv_adjacency_sid_flags_lo = -1;
static int hf_bgp_ls_sr_tlv_adjacency_sid_flags_si = -1;
static int hf_bgp_ls_sr_tlv_adjacency_sid_flags_so = -1;
static int hf_bgp_ls_sr_tlv_adjacency_sid_weight = -1;
static int hf_bgp_ls_sr_tlv_adjacency_sid_label = -1;
static int hf_bgp_ls_sr_tlv_adjacency_sid_index = -1;
static int hf_bgp_ls_sr_tlv_peer_node_sid = -1;                    /* 1101 */
static int hf_bgp_ls_sr_tlv_peer_adj_sid = -1;                     /* 1102 */
static int hf_bgp_ls_sr_tlv_peer_set_sid = -1;                     /* 1103 */
static int hf_bgp_ls_sr_tlv_peer_sid_flags = -1;
static int hf_bgp_ls_sr_tlv_peer_sid_flags_v = -1;
static int hf_bgp_ls_sr_tlv_peer_sid_flags_l = -1;
static int hf_bgp_ls_sr_tlv_peer_sid_flags_b = -1;
static int hf_bgp_ls_sr_tlv_peer_sid_flags_p = -1;
static int hf_bgp_ls_sr_tlv_peer_sid_weight = -1;
static int hf_bgp_ls_sr_tlv_peer_sid_label = -1;
static int hf_bgp_ls_sr_tlv_peer_sid_index = -1;
static int hf_bgp_ls_sr_tlv_prefix_attr_flags = -1;                /* 1170 */
static int hf_bgp_ls_sr_tlv_prefix_attr_flags_flags = -1;
static int hf_bgp_ls_sr_tlv_prefix_attr_flags_flags_unknown= -1;
static int hf_bgp_ls_sr_tlv_prefix_attr_flags_flags_ao = -1;
static int hf_bgp_ls_sr_tlv_prefix_attr_flags_flags_no = -1;
static int hf_bgp_ls_sr_tlv_prefix_attr_flags_flags_eo = -1;
static int hf_bgp_ls_sr_tlv_prefix_attr_flags_flags_xi = -1;
static int hf_bgp_ls_sr_tlv_prefix_attr_flags_flags_ri = -1;
static int hf_bgp_ls_sr_tlv_prefix_attr_flags_flags_ni = -1;
static int hf_bgp_ls_sr_tlv_prefix_attr_flags_flags_ei = -1;

/* RFC7752 TLVs */
static int hf_bgp_ls_tlv_local_node_descriptors = -1;              /* 256 */
static int hf_bgp_ls_tlv_remote_node_descriptors = -1;             /* 257 */
static int hf_bgp_ls_tlv_link_local_remote_identifiers = -1;       /* 258 */
static int hf_bgp_ls_tlv_ipv4_interface_address = -1;              /* 259 */
static int hf_bgp_ls_tlv_ipv4_neighbor_address = -1;               /* 260 */
static int hf_bgp_ls_tlv_ipv6_interface_address = -1;              /* 261 */
static int hf_bgp_ls_tlv_ipv6_neighbor_address = -1;               /* 262 */
static int hf_bgp_ls_tlv_multi_topology_id = -1;                   /* 263 */
static int hf_bgp_ls_tlv_ospf_route_type = -1;                     /* 264 */
static int hf_bgp_ls_tlv_ip_reachability_information = -1;         /* 265 */
static int hf_bgp_ls_tlv_node_msd = -1;                            /* 266 */
static int hf_bgp_ls_tlv_link_msd = -1;                            /* 267 */
static int hf_bgp_ls_tlv_igp_msd_type = -1;
static int hf_bgp_ls_tlv_igp_msd_value = -1;

static int hf_bgp_ls_tlv_autonomous_system = -1;                   /* 512 */
static int hf_bgp_ls_tlv_autonomous_system_id = -1;
static int hf_bgp_ls_tlv_bgp_ls_identifier = -1;                   /* 513 */
static int hf_bgp_ls_tlv_bgp_ls_identifier_id = -1;
static int hf_bgp_ls_tlv_area_id = -1;                             /* 514 */
static int hf_bgp_ls_tlv_area_id_id = -1;
static int hf_bgp_ls_tlv_igp_router = -1;                          /* 515 */
static int hf_bgp_ls_tlv_igp_router_id = -1;
static int hf_bgp_ls_tlv_bgp_router_id = -1;                       /* 516 */
static int hf_bgp_ls_tlv_bgp_router_id_id = -1;

static int hf_bgp_ls_tlv_node_flags_bits = -1;                     /* 1024 */
static int hf_bgp_ls_tlv_opaque_node_properties = -1;              /* 1025 */
static int hf_bgp_ls_tlv_opaque_node_properties_value = -1;
static int hf_bgp_ls_tlv_node_name = -1;                           /* 1026 */
static int hf_bgp_ls_tlv_node_name_value = -1;
static int hf_bgp_ls_tlv_is_is_area_identifier = -1;               /* 1027 */
static int hf_bgp_ls_tlv_is_is_area_identifier_value = -1;
static int hf_bgp_ls_tlv_ipv4_router_id_of_local_node = -1;        /* 1028 */
static int hf_bgp_ls_tlv_ipv4_router_id_value = -1;
static int hf_bgp_ls_tlv_ipv6_router_id_value = -1;
static int hf_bgp_ls_tlv_ipv6_router_id_of_local_node = -1;        /* 1029 */
static int hf_bgp_ls_tlv_ipv4_router_id_of_remote_node = -1;       /* 1030 */
static int hf_bgp_ls_tlv_ipv6_router_id_of_remote_node = -1;       /* 1031 */

static int hf_bgp_ls_tlv_administrative_group_color = -1;          /* 1088 */
static int hf_bgp_ls_tlv_administrative_group_color_value = -1;
static int hf_bgp_ls_tlv_administrative_group = -1;
static int hf_bgp_ls_tlv_max_link_bandwidth = -1;                  /* 1089 */
static int hf_bgp_ls_tlv_max_reservable_link_bandwidth = -1;       /* 1090 */
static int hf_bgp_ls_tlv_unreserved_bandwidth = -1;                /* 1091 */
static int hf_bgp_ls_bandwidth_value = -1;
static int hf_bgp_ls_tlv_te_default_metric = -1;                   /* 1092 */
static int hf_bgp_ls_tlv_te_default_metric_value_old = -1;
static int hf_bgp_ls_tlv_te_default_metric_value = -1;
static int hf_bgp_ls_tlv_link_protection_type = -1;                /* 1093 */
static int hf_bgp_ls_tlv_link_protection_type_value = -1;
static int hf_bgp_ls_tlv_mpls_protocol_mask = -1;                  /* 1094 */
static int hf_bgp_ls_tlv_metric = -1;                              /* 1095 */
static int hf_bgp_ls_tlv_metric_value1 = -1;
static int hf_bgp_ls_tlv_metric_value2 = -1;
static int hf_bgp_ls_tlv_metric_value3 = -1;
static int hf_bgp_ls_tlv_shared_risk_link_group = -1;              /* 1096 */
static int hf_bgp_ls_tlv_shared_risk_link_group_value = -1;
static int hf_bgp_ls_tlv_opaque_link_attribute = -1;               /* 1097 */
static int hf_bgp_ls_tlv_opaque_link_attribute_value = -1;
static int hf_bgp_ls_tlv_link_name_attribute = -1;                 /* 1098 */
static int hf_bgp_ls_tlv_link_name_attribute_value = -1;
static int hf_bgp_ls_tlv_app_spec_link_attrs = -1;                 /* 1122 */
static int hf_bgp_ls_tlv_app_spec_link_attrs_sabm_len = -1;
static int hf_bgp_ls_tlv_app_spec_link_attrs_udabm_len = -1;
static int hf_bgp_ls_tlv_app_spec_link_attrs_reserved = -1;
static int hf_bgp_ls_tlv_app_spec_link_attrs_sabm = -1;
static int hf_bgp_ls_tlv_app_spec_link_attrs_sabm_r = -1;
static int hf_bgp_ls_tlv_app_spec_link_attrs_sabm_s = -1;
static int hf_bgp_ls_tlv_app_spec_link_attrs_sabm_f = -1;
static int hf_bgp_ls_tlv_app_spec_link_attrs_sabm_x = -1;
static int hf_bgp_ls_tlv_app_spec_link_attrs_udabm = -1;

static int hf_bgp_ls_tlv_igp_flags = -1;                           /* 1152 */
static int hf_bgp_ls_tlv_route_tag = -1;                           /* 1153 */
static int hf_bgp_ls_tlv_route_tag_value = -1;
static int hf_bgp_ls_tlv_route_extended_tag = -1;                  /* 1154 */
static int hf_bgp_ls_tlv_route_extended_tag_value = -1;
static int hf_bgp_ls_tlv_prefix_metric = -1;                       /* 1155 */
static int hf_bgp_ls_tlv_prefix_metric_value = -1;
static int hf_bgp_ls_ospf_forwarding_address = -1;                 /* 1156 */
static int hf_bgp_ls_ospf_forwarding_address_ipv4_address = -1;
static int hf_bgp_ls_ospf_forwarding_address_ipv6_address = -1;
static int hf_bgp_ls_opaque_prefix_attribute = -1;                 /* 1157 */
static int hf_bgp_ls_opaque_prefix_attribute_value = -1;
static int hf_bgp_ls_extended_administrative_group = -1;           /* 1173 */
static int hf_bgp_ls_extended_administrative_group_value = -1;


/* Link Protection Types */
static int hf_bgp_ls_link_protection_type_extra_traffic = -1;
static int hf_bgp_ls_link_protection_type_unprotected = -1;
static int hf_bgp_ls_link_protection_type_shared = -1;
static int hf_bgp_ls_link_protection_type_dedicated_1to1 = -1;
static int hf_bgp_ls_link_protection_type_dedicated_1plus1 = -1;
static int hf_bgp_ls_link_protection_type_enhanced = -1;
/* MPLS Protocol Mask flags */
static int hf_bgp_ls_mpls_protocol_mask_flag_l = -1;
static int hf_bgp_ls_mpls_protocol_mask_flag_r = -1;
/* BGP-LS IGP Flags */
static int hf_bgp_ls_igp_flags_flag_d = -1;
/* Node Flag Bits TLV's flags */
static int hf_bgp_ls_node_flag_bits_overload = -1;
static int hf_bgp_ls_node_flag_bits_attached = -1;
static int hf_bgp_ls_node_flag_bits_external = -1;
static int hf_bgp_ls_node_flag_bits_abr = -1;

/* RFC8669 BGP Prefix-SID header field */
static int hf_bgp_prefix_sid_unknown = -1;
static int hf_bgp_prefix_sid_label_index = -1;
static int hf_bgp_prefix_sid_label_index_value = -1;
static int hf_bgp_prefix_sid_label_index_flags = -1;
static int hf_bgp_prefix_sid_originator_srgb = -1;
static int hf_bgp_prefix_sid_originator_srgb_blocks = -1;
static int hf_bgp_prefix_sid_originator_srgb_block = -1;
static int hf_bgp_prefix_sid_originator_srgb_flags = -1;
static int hf_bgp_prefix_sid_originator_srgb_base = -1;
static int hf_bgp_prefix_sid_originator_srgb_range = -1;
static int hf_bgp_prefix_sid_type = -1;
static int hf_bgp_prefix_sid_length = -1;
static int hf_bgp_prefix_sid_value = -1;
static int hf_bgp_prefix_sid_reserved = -1;

/* draft-ietf-bess-srv6-services-05 header field */
static int hf_bgp_prefix_sid_srv6_l3vpn = -1;
static int hf_bgp_prefix_sid_srv6_l3vpn_sub_tlvs = -1;
static int hf_bgp_prefix_sid_srv6_l3vpn_sub_tlv = -1;
static int hf_bgp_prefix_sid_srv6_l3vpn_sub_tlv_type = -1;
static int hf_bgp_prefix_sid_srv6_l3vpn_sub_tlv_length = -1;
static int hf_bgp_prefix_sid_srv6_l3vpn_sub_tlv_value = -1;
static int hf_bgp_prefix_sid_srv6_l3vpn_sub_tlv_reserved = -1;
static int hf_bgp_prefix_sid_srv6_l3vpn_sid_value = -1;
static int hf_bgp_prefix_sid_srv6_l3vpn_sid_flags = -1;
static int hf_bgp_prefix_sid_srv6_l3vpn_srv6_endpoint_behavior = -1;
static int hf_bgp_prefix_sid_srv6_l3vpn_reserved = -1;
static int hf_bgp_prefix_sid_srv6_l3vpn_sub_sub_tlvs = -1;
static int hf_bgp_prefix_sid_srv6_l3vpn_sub_sub_tlv = -1;
static int hf_bgp_prefix_sid_srv6_l3vpn_sub_sub_tlv_type = -1;
static int hf_bgp_prefix_sid_srv6_l3vpn_sub_sub_tlv_length = -1;
static int hf_bgp_prefix_sid_srv6_l3vpn_sub_sub_tlv_value = -1;
static int hf_bgp_prefix_sid_srv6_l3vpn_sid_locator_block_len = -1;
static int hf_bgp_prefix_sid_srv6_l3vpn_sid_locator_node_len = -1;
static int hf_bgp_prefix_sid_srv6_l3vpn_sid_func_len = -1;
static int hf_bgp_prefix_sid_srv6_l3vpn_sid_arg_len = -1;
static int hf_bgp_prefix_sid_srv6_l3vpn_sid_trans_len = -1;
static int hf_bgp_prefix_sid_srv6_l3vpn_sid_trans_offset = -1;
static int hf_bgp_prefix_sid_srv6_l2vpn = -1;
static int hf_bgp_prefix_sid_srv6_l2vpn_sub_tlvs = -1;
static int hf_bgp_prefix_sid_srv6_l2vpn_sub_tlv = -1;
static int hf_bgp_prefix_sid_srv6_l2vpn_sub_tlv_type = -1;
static int hf_bgp_prefix_sid_srv6_l2vpn_sub_tlv_length = -1;
static int hf_bgp_prefix_sid_srv6_l2vpn_sub_tlv_value = -1;
static int hf_bgp_prefix_sid_srv6_l2vpn_sub_tlv_reserved = -1;
static int hf_bgp_prefix_sid_srv6_l2vpn_sid_value = -1;
static int hf_bgp_prefix_sid_srv6_l2vpn_sid_flags = -1;
static int hf_bgp_prefix_sid_srv6_l2vpn_srv6_endpoint_behavior = -1;
static int hf_bgp_prefix_sid_srv6_l2vpn_reserved = -1;
static int hf_bgp_prefix_sid_srv6_l2vpn_sub_sub_tlvs = -1;
static int hf_bgp_prefix_sid_srv6_l2vpn_sub_sub_tlv = -1;
static int hf_bgp_prefix_sid_srv6_l2vpn_sub_sub_tlv_type = -1;
static int hf_bgp_prefix_sid_srv6_l2vpn_sub_sub_tlv_length = -1;
static int hf_bgp_prefix_sid_srv6_l2vpn_sub_sub_tlv_value = -1;
static int hf_bgp_prefix_sid_srv6_l2vpn_sid_locator_block_len = -1;
static int hf_bgp_prefix_sid_srv6_l2vpn_sid_locator_node_len = -1;
static int hf_bgp_prefix_sid_srv6_l2vpn_sid_func_len = -1;
static int hf_bgp_prefix_sid_srv6_l2vpn_sid_arg_len = -1;
static int hf_bgp_prefix_sid_srv6_l2vpn_sid_trans_len = -1;
static int hf_bgp_prefix_sid_srv6_l2vpn_sid_trans_offset = -1;

/* BGP flow spec nlri header field */

static int hf_bgp_flowspec_nlri_t = -1;
static int hf_bgp_flowspec_nlri_route_distinguisher = -1;
static int hf_bgp_flowspec_nlri_route_distinguisher_type = -1;
static int hf_bgp_flowspec_nlri_route_dist_admin_asnum_2 = -1;
static int hf_bgp_flowspec_nlri_route_dist_admin_ipv4 = -1;
static int hf_bgp_flowspec_nlri_route_dist_admin_asnum_4 = -1;
static int hf_bgp_flowspec_nlri_route_dist_asnum_2 = -1;
static int hf_bgp_flowspec_nlri_route_dist_asnum_4 = -1;
static int hf_bgp_flowspec_nlri_filter = -1;
static int hf_bgp_flowspec_nlri_filter_type = -1;
static int hf_bgp_flowspec_nlri_length = -1;
static int hf_bgp_flowspec_nlri_dst_pref_ipv4 = -1;
static int hf_bgp_flowspec_nlri_src_pref_ipv4 = -1;
static int hf_bgp_flowspec_nlri_op_flags = -1;
static int hf_bgp_flowspec_nlri_op_eol = -1;
static int hf_bgp_flowspec_nlri_op_and = -1;
static int hf_bgp_flowspec_nlri_op_val_len = -1;
static int hf_bgp_flowspec_nlri_op_un_bit4 = -1;
static int hf_bgp_flowspec_nlri_op_un_bit5 = -1;
static int hf_bgp_flowspec_nlri_op_lt = -1;
static int hf_bgp_flowspec_nlri_op_gt = -1;
static int hf_bgp_flowspec_nlri_op_eq = -1;
static int hf_bgp_flowspec_nlri_dec_val_8 = -1;
static int hf_bgp_flowspec_nlri_dec_val_16 = -1;
static int hf_bgp_flowspec_nlri_dec_val_32 = -1;
static int hf_bgp_flowspec_nlri_dec_val_64 = -1;
static int hf_bgp_flowspec_nlri_op_flg_not = -1;
static int hf_bgp_flowspec_nlri_op_flg_match = -1;
static int hf_bgp_flowspec_nlri_tcp_flags = -1;
static int hf_bgp_flowspec_nlri_tcp_flags_cwr = -1;
static int hf_bgp_flowspec_nlri_tcp_flags_ecn = -1;
static int hf_bgp_flowspec_nlri_tcp_flags_urg = -1;
static int hf_bgp_flowspec_nlri_tcp_flags_ack = -1;
static int hf_bgp_flowspec_nlri_tcp_flags_push = -1;
static int hf_bgp_flowspec_nlri_tcp_flags_reset = -1;
static int hf_bgp_flowspec_nlri_tcp_flags_syn = -1;
static int hf_bgp_flowspec_nlri_tcp_flags_fin = -1;
static int hf_bgp_flowspec_nlri_fflag = -1;
static int hf_bgp_flowspec_nlri_fflag_lf = -1;
static int hf_bgp_flowspec_nlri_fflag_ff = -1;
static int hf_bgp_flowspec_nlri_fflag_isf = -1;
static int hf_bgp_flowspec_nlri_fflag_df = -1;
static int hf_bgp_flowspec_nlri_dscp = -1;
static int hf_bgp_flowspec_nlri_src_ipv6_pref = -1;
static int hf_bgp_flowspec_nlri_dst_ipv6_pref = -1;
static int hf_bgp_flowspec_nlri_ipv6_pref_len = -1;
static int hf_bgp_flowspec_nlri_ipv6_pref_offset = -1;

/* BGP update safi ndt nlri  draft-nalawade-idr-mdt-safi-03 */

static int hf_bgp_mdt_nlri_safi_rd = -1;
static int hf_bgp_mdt_nlri_safi_ipv4_addr = -1;
static int hf_bgp_mdt_nlri_safi_group_addr = -1;

/* BGP update extended community header field */

static int hf_bgp_ext_communities = -1;
static int hf_bgp_ext_community = -1;
static int hf_bgp_ext_com_type_auth = -1;
static int hf_bgp_ext_com_type_tran = -1;

static int hf_bgp_ext_com_type_high = -1;
static int hf_bgp_ext_com_stype_low_unknown = -1;
static int hf_bgp_ext_com_stype_tr_evpn = -1;
static int hf_bgp_ext_com_stype_tr_as2 = -1;
static int hf_bgp_ext_com_stype_ntr_as2 = -1;
static int hf_bgp_ext_com_stype_tr_as4 = -1;
static int hf_bgp_ext_com_stype_ntr_as4 = -1;
static int hf_bgp_ext_com_stype_tr_IP4 = -1;
static int hf_bgp_ext_com_stype_ntr_IP4 = -1;
static int hf_bgp_ext_com_stype_tr_opaque = -1;
static int hf_bgp_ext_com_stype_ntr_opaque = -1;
static int hf_bgp_ext_com_tunnel_type = -1;
static int hf_bgp_ext_com_stype_tr_exp = -1;
static int hf_bgp_ext_com_stype_tr_exp_2 = -1;
static int hf_bgp_ext_com_stype_tr_exp_3 = -1;

static int hf_bgp_ext_com_value_as2 = -1;
static int hf_bgp_ext_com_value_as4 = -1;
static int hf_bgp_ext_com_value_IP4 = -1;
static int hf_bgp_ext_com_value_an2 = -1;
static int hf_bgp_ext_com_value_an4 = -1;
static int hf_bgp_ext_com_value_raw = -1;
static int hf_bgp_ext_com_value_link_bw = -1;
static int hf_bgp_ext_com_value_ospf_rt_area = -1;
static int hf_bgp_ext_com_value_ospf_rt_type = -1;
static int hf_bgp_ext_com_value_ospf_rt_options = -1;
static int hf_bgp_ext_com_value_ospf_rt_options_mt = -1;
static int hf_bgp_ext_com_value_ospf_rid = -1;
static int hf_bgp_ext_com_value_fs_remark = -1;

/* BGP QoS propagation draft-knoll-idr-qos-attribute */

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

/* BGP Flow spec extended community RFC 5575 */

static int hf_bgp_ext_com_flow_rate_float = -1;
static int hf_bgp_ext_com_flow_act_allset = -1;
static int hf_bgp_ext_com_flow_act_term_act = -1;
static int hf_bgp_ext_com_flow_act_samp_act = -1;

/* BGP L2 extended community RFC 4761, RFC 6624 */
/* draft-ietf-l2vpn-vpls-multihoming */

static int hf_bgp_ext_com_l2_encaps = -1;
static int hf_bgp_ext_com_l2_c_flags = -1;
static int hf_bgp_ext_com_l2_mtu = -1;
static int hf_bgp_ext_com_l2_flag_d = -1;
static int hf_bgp_ext_com_l2_flag_z1 = -1;
static int hf_bgp_ext_com_l2_flag_f = -1;
static int hf_bgp_ext_com_l2_flag_z345 = -1;
static int hf_bgp_ext_com_l2_flag_c = -1;
static int hf_bgp_ext_com_l2_flag_s = -1;
static int hf_bgp_ext_com_l2_esi_label_flag = -1;
static int hf_bgp_ext_com_evpn_mmac_flag = -1;
static int hf_bgp_ext_com_evpn_mmac_seq = -1;
static int hf_bgp_ext_com_evpn_esirt = -1;
static int hf_bgp_ext_com_evpn_routermac = -1;
static int hf_bgp_ext_com_evpn_mmac_flag_sticky = -1;

/* BGP E-Tree Info extended community RFC 7796 */

static int hf_bgp_ext_com_etree_flags = -1;
static int hf_bgp_ext_com_etree_root_vlan = -1;
static int hf_bgp_ext_com_etree_leaf_vlan = -1;
static int hf_bgp_ext_com_etree_flag_reserved = -1;
static int hf_bgp_ext_com_etree_flag_p = -1;
static int hf_bgp_ext_com_etree_flag_v = -1;

/* VPWS Support in EVPN  RFC 8214 */
/* draft-yu-bess-evpn-l2-attributes-04 */

static int hf_bgp_ext_com_evpn_l2attr_flags = -1;
static int hf_bgp_ext_com_evpn_l2attr_flag_reserved = -1;
static int hf_bgp_ext_com_evpn_l2attr_flag_ci = -1;
static int hf_bgp_ext_com_evpn_l2attr_flag_f = -1;
static int hf_bgp_ext_com_evpn_l2attr_flag_c = -1;
static int hf_bgp_ext_com_evpn_l2attr_flag_p = -1;
static int hf_bgp_ext_com_evpn_l2attr_flag_b = -1;
static int hf_bgp_ext_com_evpn_l2attr_l2_mtu = -1;
static int hf_bgp_ext_com_evpn_l2attr_reserved = -1;

/* E-Tree RFC8317 */

static int hf_bgp_ext_com_evpn_etree_flags = -1;
static int hf_bgp_ext_com_evpn_etree_flag_reserved = -1;
static int hf_bgp_ext_com_evpn_etree_flag_l = -1;
static int hf_bgp_ext_com_evpn_etree_reserved = -1;

/* BGP Cost Community */

static int hf_bgp_ext_com_cost_poi = -1;
static int hf_bgp_ext_com_cost_cid = -1;
static int hf_bgp_ext_com_cost_cost = -1;
static int hf_bgp_ext_com_cost_cid_rep = -1;

/* EIGRP route attributes extended communities */

static int hf_bgp_ext_com_stype_tr_exp_eigrp = -1;
static int hf_bgp_ext_com_eigrp_flags = -1;
static int hf_bgp_ext_com_eigrp_flags_rt = -1;
static int hf_bgp_ext_com_eigrp_rtag = -1;
static int hf_bgp_ext_com_eigrp_asn = -1;
static int hf_bgp_ext_com_eigrp_delay = -1;
static int hf_bgp_ext_com_eigrp_rly = -1;
static int hf_bgp_ext_com_eigrp_hops = -1;
static int hf_bgp_ext_com_eigrp_bw = -1;
static int hf_bgp_ext_com_eigrp_load = -1;
static int hf_bgp_ext_com_eigrp_mtu = -1;
static int hf_bgp_ext_com_eigrp_rid = -1;
static int hf_bgp_ext_com_eigrp_e_asn = -1;
static int hf_bgp_ext_com_eigrp_e_rid = -1;
static int hf_bgp_ext_com_eigrp_e_pid = -1;
static int hf_bgp_ext_com_eigrp_e_m = -1;

/* RFC8571 BGP-LS Advertisement of IGP TE Metric Extensions */
static int hf_bgp_ls_igp_te_metric_flags = -1;
static int hf_bgp_ls_igp_te_metric_flags_a = -1;
static int hf_bgp_ls_igp_te_metric_flags_reserved = -1;
static int hf_bgp_ls_igp_te_metric_delay = -1;
static int hf_bgp_ls_igp_te_metric_delay_value = -1;
static int hf_bgp_ls_igp_te_metric_delay_min_max = -1;
static int hf_bgp_ls_igp_te_metric_delay_min = -1;
static int hf_bgp_ls_igp_te_metric_delay_max = -1;
static int hf_bgp_ls_igp_te_metric_delay_variation = -1;
static int hf_bgp_ls_igp_te_metric_delay_variation_value = -1;
static int hf_bgp_ls_igp_te_metric_link_loss = -1;
static int hf_bgp_ls_igp_te_metric_link_loss_value = -1;
static int hf_bgp_ls_igp_te_metric_bandwidth_residual = -1;
static int hf_bgp_ls_igp_te_metric_bandwidth_residual_value = -1;
static int hf_bgp_ls_igp_te_metric_bandwidth_available = -1;
static int hf_bgp_ls_igp_te_metric_bandwidth_available_value = -1;
static int hf_bgp_ls_igp_te_metric_bandwidth_utilized = -1;
static int hf_bgp_ls_igp_te_metric_bandwidth_utilized_value = -1;
static int hf_bgp_ls_igp_te_metric_reserved = -1;

static int * const ls_igp_te_metric_flags[] = {
       &hf_bgp_ls_igp_te_metric_flags_a,
       &hf_bgp_ls_igp_te_metric_flags_reserved,
       NULL
       };

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
static gint ett_bgp_as_path_segment = -1;
static gint ett_bgp_as_path_segment_asn = -1;
static gint ett_bgp_communities = -1;
static gint ett_bgp_community = -1;
static gint ett_bgp_cluster_list = -1;  /* cluster list tree          */
static gint ett_bgp_options = -1;       /* optional parameters tree   */
static gint ett_bgp_option = -1;        /* an optional parameter tree */
static gint ett_bgp_cap = -1;           /* an cap parameter tree */
static gint ett_bgp_extended_communities = -1; /* extended communities list tree */
static gint ett_bgp_extended_community = -1; /* extended community tree for each community of BGP update */
static gint ett_bgp_ext_com_type = -1;  /* Extended Community Type High tree (IANA, Transitive bits) */
static gint ett_bgp_extended_com_fspec_redir = -1; /* extended communities BGP flow act redirect */
static gint ett_bgp_ext_com_flags = -1; /* extended communities flags tree */
static gint ett_bgp_ext_com_l2_flags = -1; /* extended commuties tree for l2 services flags */
static gint ett_bgp_ext_com_etree_flags = -1;
static gint ett_bgp_ext_com_evpn_mmac_flags = -1;
static gint ett_bgp_ext_com_evpn_l2attr_flags = -1;
static gint ett_bgp_ext_com_evpn_etree_flags = -1;
static gint ett_bgp_ext_com_cost_cid = -1; /* Cost community CommunityID tree (replace/evaluate after bit) */
static gint ett_bgp_ext_com_ospf_rt_opt = -1; /* Tree for Options bitfield of OSPF Route Type extended community */
static gint ett_bgp_ext_com_eigrp_flags = -1; /* Tree for EIGRP route flags */
static gint ett_bgp_ssa = -1;           /* safi specific attribute */
static gint ett_bgp_ssa_subtree = -1;   /* safi specific attribute Subtrees */
static gint ett_bgp_orf = -1;           /* orf (outbound route filter) tree */
static gint ett_bgp_orf_entry = -1;     /* orf entry tree */
static gint ett_bgp_mcast_vpn_nlri = -1;
static gint ett_bgp_flow_spec_nlri = -1;
static gint ett_bgp_flow_spec_nlri_filter = -1; /* tree decoding multiple op and value pairs */
static gint ett_bgp_flow_spec_nlri_op_flags = -1; /* tree decoding each op and val pair within the op and value set */
static gint ett_bgp_flow_spec_nlri_tcp = -1;
static gint ett_bgp_flow_spec_nlri_ff = -1;
static gint ett_bgp_tunnel_tlv = -1;
static gint ett_bgp_tunnel_tlv_subtree = -1;
static gint ett_bgp_tunnel_subtlv = -1;
static gint ett_bgp_tunnel_subtlv_subtree = -1;
static gint ett_bgp_link_state = -1;
static gint ett_bgp_evpn_nlri = -1;
static gint ett_bgp_evpn_nlri_esi = -1;
static gint ett_bgp_evpn_nlri_mc = -1;
static gint ett_bgp_mpls_labels = -1;
static gint ett_bgp_pmsi_tunnel_id = -1;
static gint ett_bgp_aigp_attr = -1;
static gint ett_bgp_large_communities = -1;
static gint ett_bgp_dpath = -1;
static gint ett_bgp_prefix_sid_originator_srgb = -1;
static gint ett_bgp_prefix_sid_originator_srgb_block = -1;
static gint ett_bgp_prefix_sid_originator_srgb_blocks = -1;
static gint ett_bgp_prefix_sid_label_index = -1;
static gint ett_bgp_prefix_sid_ipv6 = -1;
static gint ett_bgp_bgpsec_secure_path = -1;
static gint ett_bgp_bgpsec_secure_path_segment = -1;
static gint ett_bgp_bgpsec_signature_block = -1;
static gint ett_bgp_bgpsec_signature_segment = -1;
static gint ett_bgp_vxlan = -1;
static gint ett_bgp_binding_sid = -1;
static gint ett_bgp_segment_list = -1;
static gint ett_bgp_prefix_sid_unknown = -1;
static gint ett_bgp_prefix_sid_srv6_l3vpn = -1;
static gint ett_bgp_prefix_sid_srv6_l3vpn_sub_tlvs = -1;
static gint ett_bgp_prefix_sid_srv6_l3vpn_sid_information = -1;
static gint ett_bgp_prefix_sid_srv6_l3vpn_sub_sub_tlvs = -1;
static gint ett_bgp_prefix_sid_srv6_l3vpn_sid_structure = -1;
static gint ett_bgp_prefix_sid_srv6_l3vpn_sid_unknown = -1;
static gint ett_bgp_prefix_sid_srv6_l3vpn_unknown = -1;
static gint ett_bgp_prefix_sid_srv6_l2vpn = -1;
static gint ett_bgp_prefix_sid_srv6_l2vpn_sub_tlvs = -1;
static gint ett_bgp_prefix_sid_srv6_l2vpn_sid_information = -1;
static gint ett_bgp_prefix_sid_srv6_l2vpn_sub_sub_tlvs = -1;
static gint ett_bgp_prefix_sid_srv6_l2vpn_sid_structure = -1;
static gint ett_bgp_prefix_sid_srv6_l2vpn_sid_unknown = -1;
static gint ett_bgp_prefix_sid_srv6_l2vpn_unknown = -1;

static expert_field ei_bgp_marker_invalid = EI_INIT;
static expert_field ei_bgp_cap_len_bad = EI_INIT;
static expert_field ei_bgp_cap_gr_helper_mode_only = EI_INIT;
static expert_field ei_bgp_notify_minor_unknown = EI_INIT;
static expert_field ei_bgp_route_refresh_orf_type_unknown = EI_INIT;
static expert_field ei_bgp_length_invalid = EI_INIT;
static expert_field ei_bgp_prefix_length_invalid = EI_INIT;
static expert_field ei_bgp_afi_type_not_supported = EI_INIT;
static expert_field ei_bgp_unknown_afi = EI_INIT;
static expert_field ei_bgp_unknown_safi = EI_INIT;
static expert_field ei_bgp_unknown_label_vpn = EI_INIT;
static expert_field ei_bgp_ls_error = EI_INIT;
static expert_field ei_bgp_ls_warn = EI_INIT;
static expert_field ei_bgp_ext_com_len_bad = EI_INIT;
static expert_field ei_bgp_attr_pmsi_opaque_type = EI_INIT;
static expert_field ei_bgp_attr_pmsi_tunnel_type = EI_INIT;
static expert_field ei_bgp_prefix_length_err = EI_INIT;
static expert_field ei_bgp_attr_aigp_type = EI_INIT;
static expert_field ei_bgp_attr_as_path_as_len_err = EI_INIT;
static expert_field ei_bgp_next_hop_ipv6_scope = EI_INIT;
static expert_field ei_bgp_next_hop_rd_nonzero = EI_INIT;

static expert_field ei_bgp_evpn_nlri_rt_type_err = EI_INIT;
static expert_field ei_bgp_evpn_nlri_rt_len_err = EI_INIT;
static expert_field ei_bgp_evpn_nlri_esi_type_err = EI_INIT;
static expert_field ei_bgp_evpn_nlri_rt4_no_ip = EI_INIT;

/* desegmentation */
static gboolean bgp_desegment = TRUE;

static gint bgp_asn_len = 0;

/* FF: BGP-LS is just a collector of IGP link state information. Some
   fields are encoded "as-is" from the IGP, hence in order to dissect
   them properly we must be aware of their origin, e.g. IS-IS or OSPF.
   So, *before* dissecting LINK_STATE attributes we must get the
   'Protocol-ID' field that is present in the MP_[UN]REACH_NLRI
   attribute. The tricky thing is that there is no strict order
   for path attributes on the wire, hence we have to keep track
   of 1) the 'Protocol-ID' from the MP_[UN]REACH_NLRI and 2)
   the offset/len of the LINK_STATE attribute. We store them in
   per-packet proto_data and once we got both we are ready for the
   LINK_STATE attribute dissection.
*/
typedef struct _link_state_data {
    /* Link/Node NLRI Protocol-ID (e.g. OSPF or IS-IS) */
    guint8 protocol_id;
    /* LINK_STATE attribute coordinates */
    gint ostart;  /* offset at which the LINK_STATE path attribute starts */
    gint oend;    /* offset at which the LINK_STATE path attribute ends */
    guint16 tlen; /* length of the LINK_STATE path attribute */
    /* presence flag */
    gboolean link_state_attr_present;
    /* tree where add LINK_STATE items */
    proto_tree *subtree2;
} link_state_data;

#define LINK_STATE_DATA_KEY 0

static void
save_link_state_protocol_id(packet_info *pinfo, guint8 protocol_id) {
    link_state_data *data =
        (link_state_data*)p_get_proto_data(pinfo->pool, pinfo, proto_bgp, LINK_STATE_DATA_KEY);
    if (!data) {
        data = wmem_new0(pinfo->pool, link_state_data);
        data->ostart = -1;
        data->oend = -1;
        data->tlen = 0;
        data->link_state_attr_present = FALSE;
        data->subtree2 = NULL;
    }
    data->protocol_id = protocol_id;
    p_add_proto_data(pinfo->pool, pinfo, proto_bgp, LINK_STATE_DATA_KEY, data);
    return;
}

static void
save_link_state_attr_position(packet_info *pinfo, gint ostart, gint oend, guint16 tlen, proto_tree *subtree2) {
    link_state_data *data =
        (link_state_data*)p_get_proto_data(pinfo->pool, pinfo, proto_bgp, LINK_STATE_DATA_KEY);
    if (!data) {
        data = wmem_new0(pinfo->pool, link_state_data);
        data->protocol_id = BGP_LS_NLRI_PROTO_ID_UNKNOWN;
    }
    data->ostart = ostart;
    data->oend = oend;
    data->tlen = tlen;
    data->link_state_attr_present = TRUE;
    data->subtree2 = subtree2;
    p_add_proto_data(pinfo->pool, pinfo, proto_bgp, LINK_STATE_DATA_KEY, data);
    return;
}

static link_state_data*
load_link_state_data(packet_info *pinfo) {
    link_state_data *data =
        (link_state_data*)p_get_proto_data(pinfo->pool, pinfo, proto_bgp, LINK_STATE_DATA_KEY);
    return data;
}

typedef struct _path_attr_data {
    gboolean encaps_community_present;
    guint16 encaps_tunnel_type;
} path_attr_data;

#define PATH_ATTR_DATA_KEY 1

static void
save_path_attr_encaps_tunnel_type(packet_info *pinfo, guint32 encaps_tunnel_type) {
    path_attr_data *data =
        (path_attr_data*)p_get_proto_data(wmem_file_scope(), pinfo, proto_bgp, PATH_ATTR_DATA_KEY);
    if (!data) {
        data = wmem_new0(wmem_file_scope(), path_attr_data);
    }
    data->encaps_community_present = TRUE;
    data->encaps_tunnel_type = encaps_tunnel_type;
    p_add_proto_data(wmem_file_scope(), pinfo, proto_bgp, PATH_ATTR_DATA_KEY, data);
    return;
}

static path_attr_data*
load_path_attr_data(packet_info *pinfo) {
    path_attr_data *data =
        (path_attr_data*)p_get_proto_data(wmem_file_scope(), pinfo, proto_bgp, PATH_ATTR_DATA_KEY);
    return data;
}

/*
 * Detect IPv4/IPv6 prefixes  conform to BGP Additional Path but NOT conform to standard BGP
 *
 * A real BGP speaker would rely on the BGP Additional Path in the BGP Open messages.
 * But it is not suitable for a packet analyse because the BGP sessions are not supposed to
 * restart very often, and Open messages from both sides of the session would be needed
 * to determine the result of the capability negociation.
 * Code inspired from the decode_prefix4 function
 */
static int
detect_add_path_prefix46(tvbuff_t *tvb, gint offset, gint end, gint max_bit_length) {
    guint32 addr_len;
    guint8 prefix_len;
    gint o;
    /* Must be compatible with BGP Additional Path  */
    for (o = offset + 4; o < end; o += 4) {
        prefix_len = tvb_get_guint8(tvb, o);
        if( prefix_len > max_bit_length) {
            return 0; /* invalid prefix length - not BGP add-path */
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
        if( prefix_len == 0 && end - offset > 1 ) {
            return 1; /* prefix length is zero (i.e. matching all IP prefixes) and remaining bytes within the NLRI is greater than or equal to 1 - may be BGP add-path */
        }
        if( prefix_len > max_bit_length) {
            return 1; /* invalid prefix length - may be BGP add-path */
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
static int
detect_add_path_prefix4(tvbuff_t *tvb, gint offset, gint end) {
    return detect_add_path_prefix46(tvb, offset, end, 32);
}
static int
detect_add_path_prefix6(tvbuff_t *tvb, gint offset, gint end) {
    return detect_add_path_prefix46(tvb, offset, end, 128);
}
/*
 * Decode an IPv4 prefix with Path Identifier
 * Code inspired from the decode_prefix4 function
 */
static int
decode_path_prefix4(proto_tree *tree, packet_info *pinfo, int hf_path_id, int hf_addr, tvbuff_t *tvb, gint offset,
                    const char *tag)
{
    proto_tree *prefix_tree;
    ws_in4_addr ip_addr; /* IP address                         */
    guint8 plen;         /* prefix length                      */
    int    length;       /* number of octets needed for prefix */
    guint32 path_identifier;
    address addr;

    /* snarf path identifier length and prefix */
    path_identifier = tvb_get_ntohl(tvb, offset);
    plen = tvb_get_guint8(tvb, offset + 4);
    length = tvb_get_ipv4_addr_with_prefix_len(tvb, offset + 4 + 1, &ip_addr, plen);
    if (length < 0) {
        proto_tree_add_expert_format(tree, pinfo, &ei_bgp_length_invalid, tvb, offset + 4 , 1, "%s length %u invalid (> 32)",
            tag, plen);
        return -1;
    }
    /* put prefix into protocol tree */
    set_address(&addr, AT_IPv4, 4, &ip_addr);
    prefix_tree = proto_tree_add_subtree_format(tree, tvb, offset,  4 + 1 + length,
                            ett_bgp_prefix, NULL, "%s/%u PathId %u ",
                            address_to_str(pinfo->pool, &addr), plen, path_identifier);
    proto_tree_add_item(prefix_tree, hf_path_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(prefix_tree, hf_bgp_prefix_length, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
    proto_tree_add_ipv4(prefix_tree, hf_addr, tvb, offset + 4 + 1, length, ip_addr);
    return(4 + 1 + length);
}

/*
 * Decode an IPv4 prefix.
 */
static int
decode_prefix4(proto_tree *tree, packet_info *pinfo, proto_item *parent_item, int hf_addr, tvbuff_t *tvb, gint offset,
               const char *tag)
{
    proto_tree *prefix_tree;
    ws_in4_addr ip_addr; /* IP address                         */
    guint8 plen;         /* prefix length                      */
    int    length;       /* number of octets needed for prefix */
    address addr;

    /* snarf length and prefix */
    plen = tvb_get_guint8(tvb, offset);
    length = tvb_get_ipv4_addr_with_prefix_len(tvb, offset + 1, &ip_addr, plen);
    if (length < 0) {
        proto_tree_add_expert_format(tree, pinfo, &ei_bgp_length_invalid, tvb, offset, 1, "%s length %u invalid (> 32)",
            tag, plen);
        return -1;
    }

    /* put prefix into protocol tree */
    set_address(&addr, AT_IPv4, 4, &ip_addr);
    prefix_tree = proto_tree_add_subtree_format(tree, tvb, offset,
            1 + length, ett_bgp_prefix, NULL,
            "%s/%u", address_to_str(pinfo->pool, &addr), plen);

    proto_item_append_text(parent_item, " (%s/%u)",
                             address_to_str(pinfo->pool, &addr), plen);

    proto_tree_add_uint_format(prefix_tree, hf_bgp_prefix_length, tvb, offset, 1, plen, "%s prefix length: %u",
        tag, plen);
    proto_tree_add_ipv4(prefix_tree, hf_addr, tvb, offset + 1, length, ip_addr);
    return(1 + length);
}

/*
 * Decode an IPv6 prefix with path ID.
 */
static int
decode_path_prefix6(proto_tree *tree, packet_info *pinfo, int hf_path_id, int hf_addr, tvbuff_t *tvb, gint offset,
               const char *tag)
{
    proto_tree          *prefix_tree;
    guint32 path_identifier;
    ws_in6_addr   addr;     /* IPv6 address                       */
    address             addr_str;
    int                 plen;     /* prefix length                      */
    int                 length;   /* number of octets needed for prefix */

    /* snarf length and prefix */
    path_identifier = tvb_get_ntohl(tvb, offset);
    plen = tvb_get_guint8(tvb, offset + 4);
    length = tvb_get_ipv6_addr_with_prefix_len(tvb, offset + 4 + 1, &addr, plen);
    if (length < 0) {
        proto_tree_add_expert_format(tree, pinfo, &ei_bgp_length_invalid, tvb, offset + 4, 1, "%s length %u invalid",
            tag, plen);
        return -1;
    }

    /* put prefix into protocol tree */
    set_address(&addr_str, AT_IPv6, 16, addr.bytes);
    prefix_tree = proto_tree_add_subtree_format(tree, tvb, offset,  4 + 1 + length,
                            ett_bgp_prefix, NULL, "%s/%u PathId %u ",
                            address_to_str(pinfo->pool, &addr_str), plen, path_identifier);

    proto_tree_add_item(prefix_tree, hf_path_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_uint_format(prefix_tree, hf_bgp_prefix_length, tvb, offset + 4, 1, plen, "%s prefix length: %u",
        tag, plen);
    proto_tree_add_ipv6(prefix_tree, hf_addr, tvb, offset + 4 + 1, length, &addr);

    return(4 + 1 + length);
}

/*
 * Decode an IPv6 prefix.
 */
static int
decode_prefix6(proto_tree *tree, packet_info *pinfo, int hf_addr, tvbuff_t *tvb, gint offset,
               guint16 tlen, const char *tag)
{
    proto_tree          *prefix_tree;
    ws_in6_addr   addr;     /* IPv6 address                       */
    address             addr_str;
    int                 plen;     /* prefix length                      */
    int                 length;   /* number of octets needed for prefix */

    /* snarf length and prefix */
    plen = tvb_get_guint8(tvb, offset);
    length = tvb_get_ipv6_addr_with_prefix_len(tvb, offset + 1, &addr, plen);
    if (length < 0) {
        proto_tree_add_expert_format(tree, pinfo, &ei_bgp_length_invalid, tvb, offset, 1, "%s length %u invalid",
            tag, plen);
        return -1;
    }

    /* put prefix into protocol tree */
    set_address(&addr_str, AT_IPv6, 16, addr.bytes);
    prefix_tree = proto_tree_add_subtree_format(tree, tvb, offset,
            tlen != 0 ? tlen : 1 + length, ett_bgp_prefix, NULL, "%s/%u",
            address_to_str(pinfo->pool, &addr_str), plen);
    proto_tree_add_uint_format(prefix_tree, hf_bgp_prefix_length, tvb, offset, 1, plen, "%s prefix length: %u",
        tag, plen);
    proto_tree_add_ipv6(prefix_tree, hf_addr, tvb, offset + 1, length, &addr);
    return(1 + length);
}

static int
decode_fspec_match_prefix6(proto_tree *tree, proto_item *parent_item, int hf_addr,
                           tvbuff_t *tvb, gint offset, guint16 tlen, packet_info *pinfo)
{
    proto_tree        *prefix_tree;
    ws_in6_addr addr;     /* IPv6 address                       */
    address           addr_str;
    int               plen;     /* prefix length                      */
    int               length;   /* number of octets needed for prefix */
    int               poffset_place = 1;
    int               plength_place = 0;

    /* snarf length and prefix */
    plen = tvb_get_guint8(tvb, offset);
    if (plen == 0) /* I should be facing a draft 04 version where the prefix offset is switched with length */
    {
      plen =  tvb_get_guint8(tvb, offset+1);
      poffset_place = 0;
      plength_place = 1;
    }
    length = tvb_get_ipv6_addr_with_prefix_len(tvb, offset + 2, &addr, plen);
    if (length < 0) {
        expert_add_info_format(pinfo, parent_item, &ei_bgp_prefix_length_err, "Length is invalid %u", plen);
        return -1;
    }

    /* put prefix into protocol tree */
    set_address(&addr_str, AT_IPv6, 16, addr.bytes);
    prefix_tree = proto_tree_add_subtree_format(tree, tvb, offset,
            tlen != 0 ? tlen : 1 + length, ett_bgp_prefix, NULL, "%s/%u",
            address_to_str(pinfo->pool, &addr_str), plen);
    proto_tree_add_item(prefix_tree, hf_bgp_flowspec_nlri_ipv6_pref_len, tvb, offset + plength_place, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(prefix_tree, hf_bgp_flowspec_nlri_ipv6_pref_offset, tvb, offset + poffset_place, 1, ENC_BIG_ENDIAN);
    proto_tree_add_ipv6(prefix_tree, hf_addr, tvb, offset + 2, length, &addr);
    if (parent_item != NULL)
      proto_item_append_text(parent_item, " (%s/%u)",
                             address_to_str(pinfo->pool, &addr_str), plen);
    return(2 + length);
}

const char*
decode_bgp_rd(wmem_allocator_t *pool, tvbuff_t *tvb, gint offset)
{
    guint16 rd_type;
    wmem_strbuf_t *strbuf;

    rd_type = tvb_get_ntohs(tvb,offset);
    strbuf = wmem_strbuf_new_label(pool);

    switch (rd_type) {
        case FORMAT_AS2_LOC:
            wmem_strbuf_append_printf(strbuf, "%u:%u", tvb_get_ntohs(tvb, offset + 2),
                                      tvb_get_ntohl(tvb, offset + 4));
            break;
        case FORMAT_IP_LOC:
            wmem_strbuf_append_printf(strbuf, "%s:%u", tvb_ip_to_str(pool, tvb, offset + 2),
                                      tvb_get_ntohs(tvb, offset + 6));
            break ;
        case FORMAT_AS4_LOC:
            wmem_strbuf_append_printf(strbuf, "%u:%u", tvb_get_ntohl(tvb, offset + 2),
                                      tvb_get_ntohs(tvb, offset + 6));
            break ;
        default:
            wmem_strbuf_append_printf(strbuf, "Unknown (0x%04x) RD type",rd_type);
            break;
    } /* switch (rd_type) */

    return wmem_strbuf_get_str(strbuf);
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
    if (addr_len != 0 && addr_len != 32 && addr_len != 128)
        return -1;
    offset++;
    switch (addr_len) {
        case 32:
            proto_tree_add_item(tree, hf_bgp_mcast_vpn_nlri_source_addr_ipv4, tvb,
                                offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            break;
        case 128:
             proto_tree_add_item(tree, hf_bgp_mcast_vpn_nlri_source_addr_ipv6, tvb,
                                 offset, 16, ENC_NA);
             offset += 16;
             break;
    }

    /* Multicast Group Address */
    proto_tree_add_item(tree, hf_bgp_mcast_vpn_nlri_group_length, tvb, offset,
                        1, ENC_BIG_ENDIAN);
    addr_len = tvb_get_guint8(tvb, offset);
    if (addr_len != 0 && addr_len != 32 && addr_len != 128)
        return -1;
    offset++;
    switch(addr_len) {
        case 32:
            proto_tree_add_item(tree, hf_bgp_mcast_vpn_nlri_group_addr_ipv4, tvb,
                                offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            break;
        case 128:
            proto_tree_add_item(tree, hf_bgp_mcast_vpn_nlri_group_addr_ipv6, tvb,
                                offset, 16, ENC_NA);
            offset += 16;
            break;
    }

    return offset;
}

/*
 * function to decode operator in BGP flow spec NLRI when it address decimal values (TCP ports, UDP ports, ports, ...)
 */

static void
decode_bgp_flow_spec_dec_operator(proto_tree *tree, tvbuff_t *tvb, gint offset)
{
    static int * const flags[] = {
        &hf_bgp_flowspec_nlri_op_eol,
        &hf_bgp_flowspec_nlri_op_and,
        &hf_bgp_flowspec_nlri_op_val_len,
        &hf_bgp_flowspec_nlri_op_un_bit4,
        &hf_bgp_flowspec_nlri_op_lt,
        &hf_bgp_flowspec_nlri_op_gt,
        &hf_bgp_flowspec_nlri_op_eq,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, offset, hf_bgp_flowspec_nlri_op_flags, ett_bgp_flow_spec_nlri_op_flags, flags, ENC_NA);
}

/*
 * Decode an operator and decimal values of BGP flow spec NLRI
 */
static int
decode_bgp_nlri_op_dec_value(proto_tree *parent_tree, proto_item *parent_item, tvbuff_t *tvb, gint offset)
{
    guint8 nlri_operator;
    guint cursor_op_val=0;
    guint8 value_len=0;
    guint value=0;
    guint8 shift_amount=0;
    guint first_loop=0;

    proto_item_append_text(parent_item," (");

    do {
        nlri_operator = tvb_get_guint8(tvb, offset+cursor_op_val);
        shift_amount = nlri_operator&0x30;
        shift_amount = shift_amount >> 4;
        value_len = 1 << shift_amount; /* as written in RFC 5575 section 4 */
        /* call to a operator decode function */
        decode_bgp_flow_spec_dec_operator(parent_tree, tvb, offset+cursor_op_val);
        if (first_loop == 0)
        {
            /* If first operator we remoe a white space and or (||) is not relevant */
            /* BGP flow spec NLRI operator bitmask */
            proto_item_append_text(parent_item,"%s%s%s%s",
                 ((nlri_operator & BGPNLRI_FSPEC_AND_BIT) == 0) ? "" : "&& ",
                 ((nlri_operator & BGPNLRI_FSPEC_GREATER_THAN) == 0) ? "" : ">",
                 ((nlri_operator & BGPNLRI_FSPEC_LESS_THAN) == 0) ? "" : "<",
                 ((nlri_operator & BGPNLRI_FSPEC_EQUAL) == 0) ? "" : "=");
            first_loop = 1;
        }
        else
        {
            proto_item_append_text(parent_item," %s%s%s%s",
                 ((nlri_operator & BGPNLRI_FSPEC_AND_BIT) == 0) ? "|| " : "&& ",
                 ((nlri_operator & BGPNLRI_FSPEC_GREATER_THAN) == 0) ? "" : ">",
                 ((nlri_operator & BGPNLRI_FSPEC_LESS_THAN) == 0) ? "" : "<",
                 ((nlri_operator & BGPNLRI_FSPEC_EQUAL) == 0) ? "" : "=");
        }
        cursor_op_val++;  /* we manage this operator we move to the value */
        switch (value_len) {
            case 1:
                proto_tree_add_item(parent_tree, hf_bgp_flowspec_nlri_dec_val_8, tvb, offset+cursor_op_val, 1,ENC_BIG_ENDIAN);
                value = tvb_get_guint8(tvb,offset+cursor_op_val);
                break;
            case 2:
                proto_tree_add_item(parent_tree, hf_bgp_flowspec_nlri_dec_val_16, tvb, offset+cursor_op_val, 2,ENC_BIG_ENDIAN);
                value = tvb_get_ntohs(tvb,offset+cursor_op_val);
                break;
            case 3:
                proto_tree_add_item(parent_tree, hf_bgp_flowspec_nlri_dec_val_32, tvb, offset+cursor_op_val, 4, ENC_BIG_ENDIAN);
                value = tvb_get_ntohl(tvb,offset+cursor_op_val);
                break;
            case 4:
                proto_tree_add_item(parent_tree, hf_bgp_flowspec_nlri_dec_val_64, tvb, offset+cursor_op_val, 8, ENC_BIG_ENDIAN);
                break;
            default:
                return -1;
        }
        cursor_op_val = cursor_op_val + value_len;
        proto_item_append_text(parent_item,"%u", value);
    } while ((nlri_operator&BGPNLRI_FSPEC_END_OF_LST) == 0);
    proto_item_append_text(parent_item,")");
    return (cursor_op_val);
}


/*
 * function to decode operator in BGP flow spec NLRI when it address a bitmask values (TCP flags, fragmentation flags,...)
 */

static void
decode_bgp_flow_spec_bitmask_operator(proto_tree *tree, tvbuff_t *tvb, gint offset)
{
    static int * const flags[] = {
        &hf_bgp_flowspec_nlri_op_eol,
        &hf_bgp_flowspec_nlri_op_and,
        &hf_bgp_flowspec_nlri_op_val_len,
        &hf_bgp_flowspec_nlri_op_un_bit4,
        &hf_bgp_flowspec_nlri_op_un_bit5,
        &hf_bgp_flowspec_nlri_op_flg_not,
        &hf_bgp_flowspec_nlri_op_flg_match,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, offset, hf_bgp_flowspec_nlri_op_flags, ett_bgp_flow_spec_nlri_op_flags, flags, ENC_NA);
}

/*
 * Decode an operator and tcp flags bitmask of BGP flow spec NLRI
 */
static int
decode_bgp_nlri_op_tcpf_value(proto_tree *parent_tree, proto_item *parent_item, tvbuff_t *tvb, gint offset)
{
    guint8 nlri_operator;
    guint8 tcp_flags;
    guint cursor_op_val=0;
    guint8 value_len=0;
    guint8 shift_amount=0;
    guint first_loop=0;

    static int * const nlri_tcp_flags[] = {
        &hf_bgp_flowspec_nlri_tcp_flags_cwr,
        &hf_bgp_flowspec_nlri_tcp_flags_ecn,
        &hf_bgp_flowspec_nlri_tcp_flags_urg,
        &hf_bgp_flowspec_nlri_tcp_flags_ack,
        &hf_bgp_flowspec_nlri_tcp_flags_push,
        &hf_bgp_flowspec_nlri_tcp_flags_reset,
        &hf_bgp_flowspec_nlri_tcp_flags_syn,
        &hf_bgp_flowspec_nlri_tcp_flags_fin,
        NULL
    };

    proto_item_append_text(parent_item," (");

    do {
        nlri_operator = tvb_get_guint8(tvb, offset+cursor_op_val);
        shift_amount = nlri_operator&0x30;
        shift_amount = shift_amount >> 4;
        value_len = 1 << shift_amount; /* as written in RFC 5575 section 4 */
        decode_bgp_flow_spec_bitmask_operator(parent_tree, tvb, offset+cursor_op_val); /* call to a operator decode function */
        if (first_loop == 0)
        {
            /* If first operator we remove a white space and or (||) is not relevant */
            proto_item_append_text(parent_item,"%s%s%s%s",
                 ((nlri_operator & BGPNLRI_FSPEC_AND_BIT) == 0) ? "" : "&& ",
                 ((nlri_operator & BGPNLRI_FSPEC_GREATER_THAN) == 0) ? "" : ">",
                 ((nlri_operator & BGPNLRI_FSPEC_LESS_THAN) == 0) ? "" : "<",
                 ((nlri_operator & BGPNLRI_FSPEC_EQUAL) == 0) ? "" : "=");
            first_loop = 1;
        }
        else
        {
            proto_item_append_text(parent_item," %s%s%s%s",
                 ((nlri_operator & BGPNLRI_FSPEC_AND_BIT) == 0) ? "|| " : "&& ",
                 ((nlri_operator & BGPNLRI_FSPEC_GREATER_THAN) == 0) ? "" : ">",
                 ((nlri_operator & BGPNLRI_FSPEC_LESS_THAN) == 0) ? "" : "<",
                 ((nlri_operator & BGPNLRI_FSPEC_EQUAL) == 0) ? "" : "=");
        }
        cursor_op_val++;  /* we manage this operator we move to the value */
        if (value_len == 2) {
            cursor_op_val++; /* tcp flags are coded over 2 bytes only the second one is significant, we move to second byte */
        }

        proto_tree_add_bitmask(parent_tree, tvb, offset+cursor_op_val, hf_bgp_flowspec_nlri_tcp_flags, ett_bgp_flow_spec_nlri_tcp, nlri_tcp_flags, ENC_NA);
        tcp_flags = tvb_get_guint8(tvb,offset+cursor_op_val);

        proto_item_append_text(parent_item," %s%s%s%s%s%s",
             ((tcp_flags & BGPNLRI_FSPEC_TH_URG) == 0) ? "" : "U",
             ((tcp_flags & BGPNLRI_FSPEC_TH_ACK) == 0) ? "" : "A",
             ((tcp_flags & BGPNLRI_FSPEC_TH_PUSH) == 0) ? "" : "P",
             ((tcp_flags & BGPNLRI_FSPEC_TH_RST) == 0) ? "" : "R",
             ((tcp_flags & BGPNLRI_FSPEC_TH_SYN) == 0) ? "" : "S",
             ((tcp_flags & BGPNLRI_FSPEC_TH_FIN) == 0) ? "" : "F");
        cursor_op_val = cursor_op_val + value_len;
    } while ((nlri_operator&BGPNLRI_FSPEC_END_OF_LST) == 0);
    proto_item_append_text(parent_item,")");
    return (cursor_op_val);
}


/*
 * Decode an operator and fragmentation bitmask of BGP flow spec NLRI
 */
static int
decode_bgp_nlri_op_fflag_value(proto_tree *parent_tree, proto_item *parent_item, tvbuff_t *tvb, gint offset)
{
    guint8 nlri_operator;
    guint8 fragment_flags;
    guint cursor_op_val=0;
    guint8 value_len=0;
    guint8 shift_amount=0;
    guint first_loop=0;

    static int * const nlri_flags[] = {
        &hf_bgp_flowspec_nlri_fflag_lf,
        &hf_bgp_flowspec_nlri_fflag_ff,
        &hf_bgp_flowspec_nlri_fflag_isf,
        &hf_bgp_flowspec_nlri_fflag_df,
        NULL
    };

    proto_item_append_text(parent_item," (");

    do {
        nlri_operator = tvb_get_guint8(tvb, offset+cursor_op_val);
        shift_amount = nlri_operator&0x30;
        shift_amount = shift_amount >> 4;
        value_len = 1 << shift_amount; /* as written in RFC 5575 section 4 */
        /* call a function to decode operator addressing bitmaks */
        decode_bgp_flow_spec_bitmask_operator(parent_tree, tvb, offset+cursor_op_val);
        if (first_loop == 0)
        {
            /* If first operator we remove a white space and or (||) is not relevant */
            proto_item_append_text(parent_item,"%s%s%s%s",
                 ((nlri_operator & BGPNLRI_FSPEC_AND_BIT) == 0) ? "" : "&& ",
                 ((nlri_operator & BGPNLRI_FSPEC_GREATER_THAN) == 0) ? "" : ">",
                 ((nlri_operator & BGPNLRI_FSPEC_LESS_THAN) == 0) ? "" : "<",
                 ((nlri_operator & BGPNLRI_FSPEC_EQUAL) == 0) ? "" : "=");
            first_loop = 1;
        }
        else
        {
            proto_item_append_text(parent_item," %s%s%s%s",
                 ((nlri_operator & BGPNLRI_FSPEC_AND_BIT) == 0) ? "|| " : "&& ",
                 ((nlri_operator & BGPNLRI_FSPEC_GREATER_THAN) == 0) ? "" : ">",
                 ((nlri_operator & BGPNLRI_FSPEC_LESS_THAN) == 0) ? "" : "<",
                 ((nlri_operator & BGPNLRI_FSPEC_EQUAL) == 0) ? "" : "=");
        }
        cursor_op_val++;  /* we manage this operator we move to the value */
        if (value_len != 1) {
            return -1; /* frag flags have to be coded in 1 byte */
        }
        fragment_flags = tvb_get_guint8(tvb,offset+cursor_op_val);

        proto_tree_add_bitmask(parent_tree, tvb, offset+cursor_op_val, hf_bgp_flowspec_nlri_fflag, ett_bgp_flow_spec_nlri_ff, nlri_flags, ENC_NA);

        proto_item_append_text(parent_item," %s%s%s%s",
             ((fragment_flags & BGPNLRI_FSPEC_FG_DF) == 0) ? "" : "DF",
             ((fragment_flags & BGPNLRI_FSPEC_FG_ISF) == 0) ? "" : "IsF",
             ((fragment_flags & BGPNLRI_FSPEC_FG_FF) == 0) ? "" : "FF",
             ((fragment_flags & BGPNLRI_FSPEC_FG_LF) == 0) ? "" : "LF");
        cursor_op_val = cursor_op_val + value_len;
    } while ((nlri_operator&BGPNLRI_FSPEC_END_OF_LST) == 0);
    proto_item_append_text(parent_item,")");
    return (cursor_op_val);
}

/*
 * Decode an operator and DSCP value of BGP flow spec NLRI
 */
static int
decode_bgp_nlri_op_dscp_value(proto_tree *parent_tree, proto_item *parent_item, tvbuff_t *tvb, gint offset)
{
    guint8 nlri_operator;
    guint8 dscp_flags;
    guint cursor_op_val=0;
    guint8 value_len=0;
    guint8 shift_amount=0;
    guint first_loop=0;

    proto_item_append_text(parent_item," (");

    do {
        nlri_operator = tvb_get_guint8(tvb, offset+cursor_op_val);
        shift_amount = nlri_operator&0x30;
        shift_amount = shift_amount >> 4;
        value_len = 1 << shift_amount; /* as written in RFC 5575 section 4 */
        /* call a function to decode operator addressing bitmaks */
        decode_bgp_flow_spec_bitmask_operator(parent_tree, tvb, offset+cursor_op_val);
        if (first_loop == 0)
        {
            /* If first operator we remove a white space and or (||) is not relevant */
            proto_item_append_text(parent_item,"%s%s%s%s",
                 ((nlri_operator & BGPNLRI_FSPEC_AND_BIT) == 0) ? "" : "&& ",
                 ((nlri_operator & BGPNLRI_FSPEC_GREATER_THAN) == 0) ? "" : ">",
                 ((nlri_operator & BGPNLRI_FSPEC_LESS_THAN) == 0) ? "" : "<",
                 ((nlri_operator & BGPNLRI_FSPEC_EQUAL) == 0) ? "" : "=");
            first_loop = 1;
        }
        else
        {
            proto_item_append_text(parent_item," %s%s%s%s",
                 ((nlri_operator & BGPNLRI_FSPEC_AND_BIT) == 0) ? "|| " : "&& ",
                 ((nlri_operator & BGPNLRI_FSPEC_GREATER_THAN) == 0) ? "" : ">",
                 ((nlri_operator & BGPNLRI_FSPEC_LESS_THAN) == 0) ? "" : "<",
                 ((nlri_operator & BGPNLRI_FSPEC_EQUAL) == 0) ? "" : "=");
        }
        cursor_op_val++;  /* we manage this operator we move to the value */
        if (value_len != 1) {
            return -1; /* frag flags have to be coded in 1 byte */
        }
        dscp_flags = tvb_get_guint8(tvb,offset+cursor_op_val);
        proto_tree_add_item(parent_tree, hf_bgp_flowspec_nlri_dscp, tvb, offset+cursor_op_val, 1, ENC_BIG_ENDIAN);
        proto_item_append_text(parent_item,"%s",val_to_str_ext_const(dscp_flags,&dscp_vals_ext, "Unknown DSCP"));
        cursor_op_val = cursor_op_val + value_len;
    } while ((nlri_operator&BGPNLRI_FSPEC_END_OF_LST) == 0);
    proto_item_append_text(parent_item,")");
    return (cursor_op_val);
}



/*
 * Decode an FLOWSPEC nlri as define in RFC 5575
 */
static int
decode_flowspec_nlri(proto_tree *tree, tvbuff_t *tvb, gint offset, guint16 afi, guint8 safi, packet_info *pinfo)
{
    guint     tot_flow_len;       /* total length of the flow spec NLRI */
    guint     offset_len;         /* offset of the flow spec NLRI itself could be 1 or 2 bytes */
    guint     cursor_fspec;       /* cursor to move into flow spec nlri */
    gint      filter_len = -1;
    guint16   len_16;
    guint32   rd_type;
    proto_item *item;
    proto_item *filter_item;
    proto_item *disting_item;
    proto_tree *nlri_tree;
    proto_tree *disting_tree;
    proto_tree *filter_tree;


    if (afi != AFNUM_INET && afi != AFNUM_INET6)
    {
        expert_add_info(pinfo, NULL, &ei_bgp_afi_type_not_supported);
        return(-1);
    }

    tot_flow_len = tvb_get_guint8(tvb, offset);
    /* if nlri length is greater than 240 bytes, it is encoded over 2 bytes */
    /* with most significant nibble all in one. 240 is encoded 0xf0f0, 241 0xf0f1 */
    /* max possible value value is 4095 Oxffff */

    if (tot_flow_len >= 240)
    {
        len_16 = tvb_get_ntohs(tvb, offset);
        tot_flow_len = len_16 & 0x0FFF; /* remove most significant nibble */
        offset_len = 2;
    } else {
        offset_len = 1;
    }

    item = proto_tree_add_item(tree, hf_bgp_flowspec_nlri_t, tvb, offset,
                               tot_flow_len+offset_len, ENC_NA);
    proto_item_set_text(item, "FLOW_SPEC_NLRI (%u byte%s)",
                        tot_flow_len+offset_len, plurality(tot_flow_len+offset_len, "", "s"));

    nlri_tree = proto_item_add_subtree(item, ett_bgp_flow_spec_nlri);

    proto_tree_add_uint(nlri_tree, hf_bgp_flowspec_nlri_length, tvb, offset,
                        offset_len, tot_flow_len);

    offset = offset + offset_len;
    cursor_fspec = 0;

    /* when SAFI is VPN Flow Spec, then write route distinguisher */
    if (safi == SAFNUM_FSPEC_VPN_RULE)
    {
        disting_item = proto_tree_add_item(nlri_tree, hf_bgp_flowspec_nlri_route_distinguisher,
                                           tvb, offset, BGP_ROUTE_DISTINGUISHER_SIZE, ENC_NA);
        disting_tree = proto_item_add_subtree(disting_item, ett_bgp_flow_spec_nlri);
        proto_tree_add_item_ret_uint(disting_tree, hf_bgp_flowspec_nlri_route_distinguisher_type,
                                     tvb, offset, 2, ENC_BIG_ENDIAN, &rd_type);
        /* Route Distinguisher Type */
        switch (rd_type) {
        case FORMAT_AS2_LOC:
            proto_tree_add_item(disting_tree, hf_bgp_flowspec_nlri_route_dist_admin_asnum_2,
                                tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(disting_tree, hf_bgp_flowspec_nlri_route_dist_asnum_4,
                                tvb, offset + 4, 4, ENC_BIG_ENDIAN);
            break;

        case FORMAT_IP_LOC:
            proto_tree_add_item(disting_tree, hf_bgp_flowspec_nlri_route_dist_admin_ipv4,
                                tvb, offset + 2, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(disting_tree, hf_bgp_flowspec_nlri_route_dist_asnum_2,
                                tvb, offset + 6, 2, ENC_BIG_ENDIAN);
            break;

        case FORMAT_AS4_LOC:
            proto_tree_add_item(disting_tree, hf_bgp_flowspec_nlri_route_dist_admin_asnum_4,
                                tvb, offset + 2, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(disting_tree, hf_bgp_flowspec_nlri_route_dist_asnum_2,
                                tvb, offset + 6, 2, ENC_BIG_ENDIAN);
            break;

        default:
            expert_add_info_format(pinfo, disting_tree, &ei_bgp_length_invalid,
                                   "Unknown Route Distinguisher type (%u)", rd_type);
        }
        cursor_fspec += BGP_ROUTE_DISTINGUISHER_SIZE;
    }

    while (cursor_fspec < tot_flow_len)
    {
        filter_item = proto_tree_add_item(nlri_tree, hf_bgp_flowspec_nlri_filter, tvb, offset+cursor_fspec, 1, ENC_NA);
        filter_tree = proto_item_add_subtree(filter_item, ett_bgp_flow_spec_nlri_filter);
        proto_tree_add_item(filter_tree, hf_bgp_flowspec_nlri_filter_type, tvb, offset+cursor_fspec, 1, ENC_BIG_ENDIAN);
        proto_item_append_text(filter_item, ": %s", val_to_str(tvb_get_guint8(tvb,offset+cursor_fspec), flowspec_nlri_opvaluepair_type, "Unknown filter %d"));
        switch (tvb_get_guint8(tvb,offset+cursor_fspec)) {
        case BGPNLRI_FSPEC_DST_PFIX:
            cursor_fspec++;
            if (afi == AFNUM_INET)
                filter_len = decode_prefix4(filter_tree, pinfo, filter_item, hf_bgp_flowspec_nlri_dst_pref_ipv4,
                                            tvb, offset+cursor_fspec, "Destination IP filter");
            else /* AFNUM_INET6 */
                filter_len = decode_fspec_match_prefix6(filter_tree, filter_item, hf_bgp_flowspec_nlri_dst_ipv6_pref,
                                                        tvb, offset+cursor_fspec, 0, pinfo);
            if (filter_len == -1)
                cursor_fspec= tot_flow_len;
            break;
        case BGPNLRI_FSPEC_SRC_PFIX:
            cursor_fspec++;
            if (afi == AFNUM_INET)
                filter_len = decode_prefix4(filter_tree, pinfo, filter_item, hf_bgp_flowspec_nlri_src_pref_ipv4,
                                            tvb, offset+cursor_fspec, "Source IP filter");
            else /* AFNUM_INET6 */
                filter_len = decode_fspec_match_prefix6(filter_tree, filter_item, hf_bgp_flowspec_nlri_src_ipv6_pref,
                                                        tvb, offset+cursor_fspec, 0, pinfo);
            if (filter_len == -1)
              cursor_fspec= tot_flow_len;
            break;
        case BGPNLRI_FSPEC_IP_PROTO:
            cursor_fspec++;
            filter_len = decode_bgp_nlri_op_dec_value(filter_tree, filter_item, tvb, offset+cursor_fspec);
            break;
        case BGPNLRI_FSPEC_PORT:
            cursor_fspec++;
            filter_len = decode_bgp_nlri_op_dec_value(filter_tree, filter_item, tvb, offset+cursor_fspec);
            break;
        case BGPNLRI_FSPEC_DST_PORT:
            cursor_fspec++;
            filter_len = decode_bgp_nlri_op_dec_value(filter_tree, filter_item, tvb, offset+cursor_fspec);
            break;
        case BGPNLRI_FSPEC_SRC_PORT:
            cursor_fspec++;
            filter_len = decode_bgp_nlri_op_dec_value(filter_tree, filter_item, tvb, offset+cursor_fspec);
            break;
        case BGPNLRI_FSPEC_ICMP_TP:
            cursor_fspec++;
            filter_len = decode_bgp_nlri_op_dec_value(filter_tree, filter_item, tvb, offset+cursor_fspec);
            break;
        case BGPNLRI_FSPEC_ICMP_CD:
            cursor_fspec++;
            filter_len = decode_bgp_nlri_op_dec_value(filter_tree, filter_item, tvb, offset+cursor_fspec);
            break;
        case BGPNLRI_FSPEC_TCP_FLAGS:
            cursor_fspec++;
            filter_len = decode_bgp_nlri_op_tcpf_value(filter_tree, filter_item, tvb, offset+cursor_fspec);
            break;
        case BGPNLRI_FSPEC_PCK_LEN:
            cursor_fspec++;
            filter_len = decode_bgp_nlri_op_dec_value(filter_tree, filter_item, tvb, offset+cursor_fspec);
            break;
        case BGPNLRI_FSPEC_DSCP:
            cursor_fspec++;
            filter_len = decode_bgp_nlri_op_dscp_value(filter_tree, filter_item, tvb, offset+cursor_fspec);
            break;
        case BGPNLRI_FSPEC_FRAGMENT:
            cursor_fspec++;
            filter_len = decode_bgp_nlri_op_fflag_value(filter_tree, filter_item, tvb, offset+cursor_fspec);
            break;
        default:
            return -1;
      }
      if (filter_len>0)
          cursor_fspec += filter_len;
      else
          break;
      proto_item_set_len(filter_item,filter_len+1);
    }
    return(tot_flow_len+offset_len-1);
}

/*
 * Decode an MCAST-VPN nlri as defined in draft-ietf-l3vpn-2547bis-mcast-bgp-08.txt .
 */
static int
decode_mcast_vpn_nlri(proto_tree *tree, tvbuff_t *tvb, gint offset, guint16 afi, packet_info *pinfo)
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

    if (length > tvb_reported_length_remaining(tvb, offset))
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
                                decode_bgp_rd(pinfo->pool, tvb, offset));
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
                                decode_bgp_rd(pinfo->pool, tvb, offset));
            offset += BGP_ROUTE_DISTINGUISHER_SIZE;

            proto_tree_add_item(nlri_tree, hf_bgp_mcast_vpn_nlri_source_as, tvb,
                                offset, 4, ENC_BIG_ENDIAN);
            break;

        case MCAST_VPN_RTYPE_SPMSI_AD:
            item = proto_tree_add_item(nlri_tree, hf_bgp_mcast_vpn_nlri_rd, tvb,
                                       offset, BGP_ROUTE_DISTINGUISHER_SIZE,
                                       ENC_NA);
            proto_item_set_text(item, "Route Distinguisher: %s",
                                decode_bgp_rd(pinfo->pool, tvb, offset));
            offset += BGP_ROUTE_DISTINGUISHER_SIZE;

            ret = decode_mcast_vpn_nlri_addresses(nlri_tree, tvb, offset);
            if (ret < 0)
                return -1;

            offset = ret;

            if (afi == AFNUM_INET)
                proto_tree_add_item(nlri_tree,
                                           hf_bgp_mcast_vpn_nlri_origin_router_ipv4,
                                           tvb, offset, ip_length, ENC_BIG_ENDIAN);
            else
                proto_tree_add_item(nlri_tree,
                                           hf_bgp_mcast_vpn_nlri_origin_router_ipv6,
                                           tvb, offset, ip_length, ENC_NA);
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
                                decode_bgp_rd(pinfo->pool, tvb, offset));
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
                                decode_bgp_rd(pinfo->pool, tvb, offset));
            offset += BGP_ROUTE_DISTINGUISHER_SIZE;

            proto_tree_add_item(nlri_tree, hf_bgp_mcast_vpn_nlri_source_as, tvb,
                                offset, 4, ENC_BIG_ENDIAN);
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
 * Decode an SR Policy SAFI as defined in draft-ietf-idr-segment-routing-te-policy-08
 */
static int
decode_sr_policy_nlri(proto_tree *tree, tvbuff_t *tvb, gint offset, guint16 afi)
{
   proto_tree_add_item(tree, hf_bgp_sr_policy_nlri_length, tvb, offset, 1, ENC_BIG_ENDIAN);
   offset += 1;
   proto_tree_add_item(tree, hf_bgp_sr_policy_nlri_distinguisher, tvb, offset, 4, ENC_NA);
   offset += 4;
   proto_tree_add_item(tree, hf_bgp_sr_policy_nlri_policy_color, tvb, offset, 4, ENC_NA);
   offset += 4;
   if (afi == AFNUM_INET) {
       proto_tree_add_item(tree, hf_bgp_sr_policy_nlri_endpoint_v4, tvb, offset, 4, ENC_BIG_ENDIAN);
       return 13;
   } else {
       proto_tree_add_item(tree, hf_bgp_sr_policy_nlri_endpoint_v6, tvb, offset, 4, ENC_NA);
       return 25;
   }
}

/*
 * Decodes an MDT-SAFI message.
 */
static guint
decode_mdt_safi(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, gint offset)
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

    item = proto_tree_add_item(tree, hf_bgp_mdt_nlri_safi_rd, tvb,
                               offset, BGP_ROUTE_DISTINGUISHER_SIZE, ENC_NA);
    proto_item_set_text(item, "Route Distinguisher: %s",
                        decode_bgp_rd(pinfo->pool, tvb, offset));
    offset += BGP_ROUTE_DISTINGUISHER_SIZE;

    proto_tree_add_item(tree, hf_bgp_mdt_nlri_safi_ipv4_addr, tvb,
                        offset, ip_length, ENC_BIG_ENDIAN);
    offset += ip_length;

    proto_tree_add_item(tree, hf_bgp_mdt_nlri_safi_group_addr, tvb,
                        offset, ip_length, ENC_BIG_ENDIAN);
    offset += ip_length;

    return offset - orig_offset;
}

/*
 * Decode an MPLS label stack
 * XXX - We should change *buf to **buf, use wmem_alloc() and drop the buflen
 * argument.
 */
static guint
decode_MPLS_stack(tvbuff_t *tvb, gint offset, wmem_strbuf_t *stack_strbuf)
{
    guint32     label_entry;    /* an MPLS label entry (label + COS field + stack bit   */
    gint        indx;          /* index for the label stack */

    indx = offset ;
    label_entry = 0x000000 ;

    wmem_strbuf_truncate(stack_strbuf, 0);

    while ((label_entry & BGP_MPLS_BOTTOM_L_STACK) == 0) {

        label_entry = tvb_get_ntoh24(tvb, indx) ;

        /* withdrawn routes may contain 0 or 0x800000 in the first label */
        if((indx == offset)&&(label_entry==0||label_entry==0x800000)) {
            wmem_strbuf_append(stack_strbuf, "0 (withdrawn)");
            return (1);
        }

        wmem_strbuf_append_printf(stack_strbuf, "%u%s", label_entry >> 4,
                ((label_entry & BGP_MPLS_BOTTOM_L_STACK) == 0) ? "," : " (bottom)");

        indx += 3 ;
    }

    return((indx - offset) / 3);
}

static guint
decode_MPLS_stack_tree(tvbuff_t *tvb, gint offset, proto_tree *parent_tree)
{
    guint32     label_entry=0;    /* an MPLS label entry (label + COS field + stack bit)   */
    gint        indx;          /* index for the label stack */
    proto_tree  *labels_tree=NULL;
    proto_item  *labels_item=NULL;
    proto_item  *label_item=NULL;
    indx = offset ;
    label_entry = 0x000000 ;

    labels_item = proto_tree_add_item(parent_tree, hf_bgp_update_mpls_label, tvb, offset, 3, ENC_NA);
    proto_item_append_text(labels_item, ": ");
    labels_tree = proto_item_add_subtree(labels_item, ett_bgp_mpls_labels);
    while ((label_entry & BGP_MPLS_BOTTOM_L_STACK) == 0) {

        label_entry = tvb_get_ntoh24(tvb, indx);
        label_item = proto_tree_add_item(labels_tree, hf_bgp_update_mpls_label_value, tvb, indx, 3, ENC_BIG_ENDIAN);
        /* withdrawn routes may contain 0 or 0x800000 in the first label */
        if((indx == offset)&&(label_entry==0||label_entry==0x800000)) {
            proto_item_append_text(labels_item, " (withdrawn)");
            proto_item_append_text(label_item, " (withdrawn)");
            return (1);
        }

        proto_item_append_text(labels_item, "%u%s", label_entry >> 4,
                ((label_entry & BGP_MPLS_BOTTOM_L_STACK) == 0) ? "," : " (bottom)");
        proto_item_append_text(label_item, "%u%s", label_entry >> 4,
                ((label_entry & BGP_MPLS_BOTTOM_L_STACK) == 0) ? "," : " (bottom)");
        indx += 3 ;

        if ((label_entry & BGP_MPLS_BOTTOM_L_STACK) == 0) {
            /* real MPLS multi-label stack in BGP? - maybe later; for now, it must be a bogus packet */
            proto_item_append_text(labels_item, " (BOGUS: Bottom of Stack NOT set!)");
            break;
        }
    }
    proto_item_set_len(labels_item, (indx - offset));
    return((indx - offset) / 3);
}

/*
 * Decode a multiprotocol next hop address that expected to be IPv4.
 * Returns 0 on failure (invalid length).
 */
static int
decode_mp_next_hop_ipv4(tvbuff_t *tvb, proto_tree *tree, gint offset, packet_info *pinfo _U_, wmem_strbuf_t *strbuf, gint nhlen)
{
    switch (nhlen) {
        case (FT_IPv4_LEN):
            proto_tree_add_item(tree, hf_bgp_update_path_attribute_mp_reach_nlri_next_hop_ipv4, tvb, offset, FT_IPv4_LEN, ENC_BIG_ENDIAN);
            wmem_strbuf_append(strbuf, tvb_ip_to_str(pinfo->pool, tvb, offset));
            break;
        default:
            return 0;
    }
    return nhlen;
}

/*
 * Decode a multiprotocol next hop address expected to be VPN-IPv4.
 * Note that the Route Distinguisher is always 0. Returns 0 on failure
 * (invalid length).
 */
static int
decode_mp_next_hop_vpn_ipv4(tvbuff_t *tvb, proto_tree *tree, gint offset, packet_info *pinfo, wmem_strbuf_t *strbuf, gint nhlen)
{
    proto_item    *ti;
    const char    *rd_string;
    const guint8   rd_zero[] = {0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00 };

    switch (nhlen) {
        case (BGP_ROUTE_DISTINGUISHER_SIZE + FT_IPv4_LEN):
            rd_string = decode_bgp_rd(pinfo->pool, tvb, offset);
            ti = proto_tree_add_string(tree, hf_bgp_update_path_attribute_mp_reach_nlri_next_hop_rd, tvb, offset, BGP_ROUTE_DISTINGUISHER_SIZE, rd_string);
            if (tvb_memeql(tvb, offset, rd_zero, BGP_ROUTE_DISTINGUISHER_SIZE) != 0) {
                expert_add_info(pinfo, ti, &ei_bgp_next_hop_rd_nonzero);
            }
            wmem_strbuf_append_printf(strbuf, " RD=%s", rd_string);
            offset += BGP_ROUTE_DISTINGUISHER_SIZE;
            proto_tree_add_item(tree, hf_bgp_update_path_attribute_mp_reach_nlri_next_hop_ipv4, tvb, offset, FT_IPv4_LEN, ENC_BIG_ENDIAN);
            wmem_strbuf_append_printf(strbuf, " IPv4=%s", tvb_ip_to_str(pinfo->pool, tvb, offset));
            break;
        default:
            return 0;
    }
    return nhlen;
}

/*
 * Decode a multiprotocol next hop address that is expected to be IPv6,
 * optionally including a second, link-local, address, differentiating by
 * length. Returns 0 on failure (invalid length).
 */
static int
decode_mp_next_hop_ipv6(tvbuff_t *tvb, proto_tree *tree, gint offset, packet_info *pinfo, wmem_strbuf_t *strbuf, gint nhlen)
{
    proto_item    *ti;
    ws_in6_addr    ipv6_addr;
    char           ipv6_buffer[WS_INET6_ADDRSTRLEN];

    switch (nhlen) {
        case (FT_IPv6_LEN):
            proto_tree_add_item(tree, hf_bgp_update_path_attribute_mp_reach_nlri_next_hop_ipv6, tvb, offset, FT_IPv6_LEN, ENC_NA);
            wmem_strbuf_append(strbuf, tvb_ip6_to_str(pinfo->pool, tvb, offset));
            break;
        case (2*FT_IPv6_LEN):
            /* global address followed by link-local */
            proto_tree_add_item(tree, hf_bgp_update_path_attribute_mp_reach_nlri_next_hop_ipv6, tvb, offset, FT_IPv6_LEN, ENC_NA);
            wmem_strbuf_append_printf(strbuf, "IPv6=%s", tvb_ip6_to_str(pinfo->pool, tvb, offset));
            offset += FT_IPv6_LEN;
            ti = proto_tree_add_item(tree, hf_bgp_update_path_attribute_mp_reach_nlri_next_hop_ipv6_link_local, tvb, offset, FT_IPv6_LEN, ENC_NA);
            tvb_get_ipv6(tvb, offset, &ipv6_addr);
            if (!in6_addr_is_linklocal(&ipv6_addr)) {
                expert_add_info_format(pinfo, ti, &ei_bgp_next_hop_ipv6_scope, "Invalid IPv6 address scope; should be link-local");
            }
            ip6_to_str_buf(&ipv6_addr, ipv6_buffer, WS_INET6_ADDRSTRLEN);
            wmem_strbuf_append_printf(strbuf, " Link-local=%s", ipv6_buffer);
            break;
        default:
            return 0;
    }
    return nhlen;
}

/*
 * Decode a multiprotocol next hop address that is expected to be VPN-IPv6,
 * optionally including a second, link-local, address. Note that the Route
 * Distinguisher is always 0. Returns 0 on failure (invalid length).
 */
static int
decode_mp_next_hop_vpn_ipv6(tvbuff_t *tvb, proto_tree *tree, gint offset, packet_info *pinfo, wmem_strbuf_t *strbuf, gint nhlen)
{
    proto_item    *ti;
    const char    *rd_string;
    const guint8   rd_zero[] = {0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00 };
    ws_in6_addr    ipv6_addr;
    char           ipv6_buffer[WS_INET6_ADDRSTRLEN];

    switch (nhlen) {
        case (BGP_ROUTE_DISTINGUISHER_SIZE + FT_IPv6_LEN):
            rd_string = decode_bgp_rd(pinfo->pool, tvb, offset);
            ti = proto_tree_add_string(tree, hf_bgp_update_path_attribute_mp_reach_nlri_next_hop_rd, tvb, offset, BGP_ROUTE_DISTINGUISHER_SIZE, rd_string);
            if (tvb_memeql(tvb, offset, rd_zero, BGP_ROUTE_DISTINGUISHER_SIZE) != 0) {
                expert_add_info(pinfo, ti, &ei_bgp_next_hop_rd_nonzero);
            }
            wmem_strbuf_append_printf(strbuf, " RD=%s", rd_string);
            offset += BGP_ROUTE_DISTINGUISHER_SIZE;
            proto_tree_add_item(tree, hf_bgp_update_path_attribute_mp_reach_nlri_next_hop_ipv6, tvb, offset, FT_IPv6_LEN, ENC_NA);
            wmem_strbuf_append_printf(strbuf, " IPv6=%s", tvb_ip6_to_str(pinfo->pool, tvb, offset));
            break;
        case (2*(BGP_ROUTE_DISTINGUISHER_SIZE + FT_IPv6_LEN)):
            rd_string = decode_bgp_rd(pinfo->pool, tvb, offset);
            ti = proto_tree_add_string(tree, hf_bgp_update_path_attribute_mp_reach_nlri_next_hop_rd, tvb, offset, BGP_ROUTE_DISTINGUISHER_SIZE, rd_string);
            if (tvb_memeql(tvb, offset, rd_zero, BGP_ROUTE_DISTINGUISHER_SIZE) != 0) {
                expert_add_info(pinfo, ti, &ei_bgp_next_hop_rd_nonzero);
            }
            wmem_strbuf_append_printf(strbuf, " RD=%s", rd_string);
            offset += BGP_ROUTE_DISTINGUISHER_SIZE;
            proto_tree_add_item(tree, hf_bgp_update_path_attribute_mp_reach_nlri_next_hop_ipv6, tvb, offset, FT_IPv6_LEN, ENC_NA);
            wmem_strbuf_append_printf(strbuf, " IPv6=%s", tvb_ip6_to_str(pinfo->pool, tvb, offset));
            offset += FT_IPv6_LEN;
            rd_string = decode_bgp_rd(pinfo->pool, tvb, offset);
            ti = proto_tree_add_string(tree, hf_bgp_update_path_attribute_mp_reach_nlri_next_hop_rd, tvb, offset, BGP_ROUTE_DISTINGUISHER_SIZE, rd_string);
            if (tvb_memeql(tvb, offset, rd_zero, BGP_ROUTE_DISTINGUISHER_SIZE) != 0) {
                expert_add_info(pinfo, ti, &ei_bgp_next_hop_rd_nonzero);
            }
            wmem_strbuf_append_printf(strbuf, " RD=%s", rd_string);
            offset += BGP_ROUTE_DISTINGUISHER_SIZE;
            ti = proto_tree_add_item(tree, hf_bgp_update_path_attribute_mp_reach_nlri_next_hop_ipv6_link_local, tvb, offset, FT_IPv6_LEN, ENC_NA);
            tvb_get_ipv6(tvb, offset, &ipv6_addr);
            if (!in6_addr_is_linklocal(&ipv6_addr)) {
                expert_add_info_format(pinfo, ti, &ei_bgp_next_hop_ipv6_scope, "Invalid IPv6 address scope; should be link-local");
            }
            ip6_to_str_buf(&ipv6_addr, ipv6_buffer, WS_INET6_ADDRSTRLEN);
            wmem_strbuf_append_printf(strbuf, " Link-local=%s", ipv6_buffer);
            break;
        default:
            return 0;
    }
    return nhlen;
}

/*
 * Decode a multiprotocol next hop address
 */
static int
decode_mp_next_hop(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint16 afi, guint8 safi, gint nhlen)
{
    proto_item    *ti;
    proto_tree    *next_hop_t;
    int            length, offset = 0;
    wmem_strbuf_t *strbuf;

    strbuf = wmem_strbuf_new_label(pinfo->pool);

    /* BGP Multiprotocol Next Hop Principles
     *
     * BGP Multiprotocol support is specified over a large variety of
     * RFCs for different <AFI, SAFI> pairs, which leaves some theoretical
     * pairings undefined (e.g., the Abstract of RFC 4760 contemplates
     * supporting the IPX address family) as well as leading to some
     * omissions, contradictions, and inconsistencies. However, some general
     * principles that apply across (nearly) all extant pairs exist.
     *
     * 1. Global IPv6 addresses can be followed by a link-local IPv6 address
     *
     * RFC 2545 specifies in section 3, "Constructing the Next Hop field,"
     * that when the next hop address type is IPv6, the address given should
     * be in global (or site-local) unicast address scope, and it shall be
     * followed by the link-local address if and only if the BGP speaker shares
     * a common subnet with the address and the peer the route is being
     * advertised to.
     *
     * The wording implies that this holds for any <AFI, SAFI> pair where
     * a IPv6 address is used, and RFCs 5549, 7752, and 8950 demonstrate that
     * this explicitly holds for the most common ones, including for VPN-IPv6
     * addresses (where the route distinguisher field also appears, see
     * RFC 4659). Sometimes the possibility is elided where it is known to
     * exist e.g. RFC 7606 7.11 MP_REACH_NLRI "For example, if RFC5549 is in
     * use, then the next hop would have to have a length of 4 or 16." Thus
     * it is possible that its omission in other RFCs covering new <AFI, SAFI>
     * pairs is an oversight.
     *
     * 2. [VPN-]IPv4 NLRI can have [VPN-]IPv6 Next Hop addresses
     *
     * RFCs 5549 and 8950 declare that the next hop address may not necessarily
     * belong to the address family specified by the AFI, updating RFC 2858,
     * specifically addressing the case of IPv6 islands across a IPv4 core
     * and vice versa.
     *
     * IPv4 addresses can easily be mapped into IPv6 addresses, and that
     * is the solution for one case, but in the other the Next Hop must be an
     * IPv6 (or VPN-IPv6) address even though the NLRI is IPv4.
     *
     * The wording of RFC 8950 strongly implies that the intent is to allow
     * IPv6 Net Hop addresses for any case of IPv4 or VPN-IPv4 NLRI, providing
     * a BGP Capability to declare that the BGP speakers supports a different
     * Next Hop AFI for <AFI, SAFI> pairs defined without this capability,
     * and noting those (like <1, 132>, SAFNUM_ROUTE_TARGET, RFC 4684) that
     * consider the possibility from the start.
     *
     * 3. Next Hop Route Distinguisher (RD) is 0 or omitted
     *
     * RDs do not have a meaning in the Next Hop network address. However, when
     * RFC 2547 introduced the VPN-IPv4 address family, at that point the Next
     * Hop address family had to be the same as the NLRI address family, so the
     * RD was set to all 0. Later defined <AFI, SAFI> pairs with RDs in their
     * NLRI have either used this custom of a 0 RD, or else omitted it and
     * only had the IP address in the Next Hop.
     */

    ti = proto_tree_add_item(tree, hf_bgp_update_path_attribute_mp_reach_nlri_next_hop, tvb, offset, nhlen + 1, ENC_NA);
    next_hop_t = proto_item_add_subtree(ti, ett_bgp_mp_nhna);
    offset += 1;

    switch (afi) {
        case AFNUM_INET:
            switch (safi) {
                case SAFNUM_UNICAST:       /* RFC 8950 */
                case SAFNUM_MULCAST:       /* RFC 8950 */
                case SAFNUM_UNIMULC:       /* Deprecated, but as above */
                case SAFNUM_MPLS_LABEL:    /* RFC 8277 */
                case SAFNUM_MCAST_VPN:     /* RFC 6514 */
                case SAFNUM_ENCAPSULATION: /* RFC 5512, but "never been used"
                                            * according to
                                            * draft-ietf-idr-tunnel-encaps-22
                                            */
                case SAFNUM_ROUTE_TARGET:  /* RFC 4684 */
                    /* IPv4 or IPv6, differentiated by field length, according
                     * to the RFCs cited above. RFC 8950 explicitly addresses
                     * the possible link-local IPv6 address. RFC 6514 depending
                     * on the situation either the Next Hop MUST be the same
                     * as in the IP Address field lower in the network stack,
                     * or simply SHOULD be "a routeable address" of the ASBR/
                     * local PE. */
                    if ((length = decode_mp_next_hop_ipv4(tvb, next_hop_t, offset, pinfo, strbuf, nhlen)) == 0) {
                        length = decode_mp_next_hop_ipv6(tvb, next_hop_t, offset, pinfo, strbuf, nhlen);
                    }
                    break;
                case SAFNUM_TUNNEL:
                    /* Internet Draft draft-nalawade-kapoor-tunnel-safi-05
                     * long expired, but "[NLRI] network address... SHOULD be
                     * the same as the [Next Hop] network address."
                     */
                    length = decode_mp_next_hop_ipv4(tvb, next_hop_t, offset, pinfo, strbuf, nhlen);
                    break;
                case SAFNUM_LAB_VPNUNICAST: /* RFC 8950 */
                case SAFNUM_LAB_VPNMULCAST: /* RFC 8950 */
                case SAFNUM_LAB_VPNUNIMULC: /* Deprecated, but as above */
                    /* RFC 8950 indicates that the next hop can be VPN-IPv4 or
                     * VPN-IPv6 (with RD all 0), and in the latter case the
                     * link-local IPv6 address can be included. Note that RFC
                     * 5549 incorrectly did not include the RD in the Next Hop
                     * for VPN-IPv6 (see Erratum ID 5253), but according to
                     * RFC 8950 2. "Changes Compared to RFC 5549":
                     * "As all known and deployed implementations are
                     * interoperable today and use the new proposed encoding,
                     * the change does not break existing interoperability,"
                     * and thus we need not test for a missing RD.
                     */
                    if ((length = decode_mp_next_hop_vpn_ipv4(tvb, next_hop_t, offset, pinfo, strbuf, nhlen)) == 0) {
                        length = decode_mp_next_hop_vpn_ipv6(tvb, next_hop_t, offset, pinfo, strbuf, nhlen);
                    }
                    break;
                case SAFNUM_FSPEC_RULE:
                case SAFNUM_FSPEC_VPN_RULE:
                    length = 0;
                    /* When advertising Flow Specifications, the Length of the
                     * Next-Hop Address MUST be set 0. The Network Address of
                     * the Next-Hop field MUST be ignored.
                     */
                    if (nhlen != 0) {
                        expert_add_info_format(pinfo, ti, &ei_bgp_length_invalid,
                                               "The length (%d) of Next Hop (FlowSpec) is not zero", nhlen);
                        break;
                    }
                    length++;
                    break;
                default:
                    length = 0;
                    expert_add_info_format(pinfo, ti, &ei_bgp_unknown_safi,
                                    "Unknown SAFI (%u) for AFI %u", safi, afi);
                    break;
            } /* switch (safi) */
            break;
        case AFNUM_INET6:
            switch (safi) {
                case SAFNUM_UNICAST:       /* RFC 8950 */
                case SAFNUM_MULCAST:       /* RFC 8950 */
                case SAFNUM_UNIMULC:       /* Deprecated, but as above */
                case SAFNUM_MPLS_LABEL:    /* RFC 8277 */
                case SAFNUM_MCAST_VPN:     /* RFC 6514 */
                case SAFNUM_ENCAPSULATION: /* RFC 5512, but "never been used" */
                case SAFNUM_TUNNEL:        /* Expired Internet Draft */
                    /* IPv6 address, possibly followed by link-local address */
                    length = decode_mp_next_hop_ipv6(tvb, next_hop_t, offset, pinfo, strbuf, nhlen);
                    break;
                case SAFNUM_LAB_VPNUNICAST: /* RFC 8950 */
                case SAFNUM_LAB_VPNMULCAST: /* RFC 8950 */
                case SAFNUM_LAB_VPNUNIMULC: /* Deprecated, but as above */
                    /* VPN-IPv6 address, possibly followed by link-local addr */
                    length = decode_mp_next_hop_vpn_ipv6(tvb, next_hop_t, offset, pinfo, strbuf, nhlen);
                    break;
                case SAFNUM_FSPEC_RULE:
                case SAFNUM_FSPEC_VPN_RULE:
                    length = 0;
                    /* When advertising Flow Specifications, the Length of the
                     * Next-Hop Address MUST be set 0. The Network Address of
                     * the Next-Hop field MUST be ignored.
                     */
                    if (nhlen != 0) {
                        expert_add_info_format(pinfo, ti, &ei_bgp_length_invalid,
                                               "The length (%d) of Next Hop (FlowSpec) is not zero", nhlen);
                        break;
                    }
                    length++;
                    break;
                default:
                    length = 0;
                    expert_add_info_format(pinfo, ti, &ei_bgp_unknown_safi,
                                    "Unknown SAFI (%u) for AFI %u", safi, afi);
                    break;
            } /* switch (safi) */
            break;
        case AFNUM_L2VPN:
        case AFNUM_L2VPN_OLD:
            switch (safi) {
                /* XXX: Do these first three really appear with L2VPN AFI? */
                case SAFNUM_LAB_VPNUNICAST:
                case SAFNUM_LAB_VPNMULCAST:
                case SAFNUM_LAB_VPNUNIMULC:
                case SAFNUM_VPLS: /* RFC 4761 (VPLS) and RFC 6074 (BGP-AD) */
                case SAFNUM_EVPN: /* RFC 7432 */
                    /* The RFCs above specify that the next-hop is simply the
                     * address of the PE (loopback address in some cases for
                     * BGP-AD), either IPv4 or IPv6, differentiated by length.
                     * A RD is included in the NLRI in these cases, but not in
                     * the Next Hop address unlike in AFI 1 or 2.
                     */
                    if ((length = decode_mp_next_hop_ipv4(tvb, next_hop_t, offset, pinfo, strbuf, nhlen)) == 0) {
                        length = decode_mp_next_hop_ipv6(tvb, next_hop_t, offset, pinfo, strbuf, nhlen);
                    }
                    break;
                default:
                    length = 0;
                    expert_add_info_format(pinfo, ti, &ei_bgp_unknown_safi,
                                    "Unknown SAFI (%u) for AFI %u", safi, afi);
                    break;
            } /* switch (safi) */
            break;
        case AFNUM_BGP_LS:
            /* RFC 7752 section 3.4 "BGP Next-Hop Information" explains that
             * the next-hop address length field specifes the next-hop address
             * family. "If the next-hop length is 4, then the next hop is an
             * IPv4 address; if the next-hop length is 16, then it is a global
             * IPv6 address; and if the next-hop length is 32, then there is
             * one global IPv6 address followed by a link-local IPv6 address"
             */
            switch (safi) {
                case SAFNUM_BGP_LS:
                    if ((length = decode_mp_next_hop_ipv4(tvb, next_hop_t, offset, pinfo, strbuf, nhlen)) == 0) {
                        length = decode_mp_next_hop_ipv6(tvb, next_hop_t, offset, pinfo, strbuf, nhlen);
                    }
                    break;
                case SAFNUM_BGP_LS_VPN:
                    /* RFC 7752 3.4: "For VPN SAFI, as per custom, an 8-byte
                     * Route Distinguisher set to all zero is prepended to the
                     * next hop."
                     */
                    if ((length = decode_mp_next_hop_vpn_ipv4(tvb, next_hop_t, offset, pinfo, strbuf, nhlen)) == 0) {
                        length = decode_mp_next_hop_vpn_ipv6(tvb, next_hop_t, offset, pinfo, strbuf, nhlen);
                    }
                    break;
                default:
                    length = 0;
                    expert_add_info_format(pinfo, ti, &ei_bgp_unknown_safi,
                                    "Unknown SAFI (%u) for AFI %u", safi, afi);
                    break;
            } /* switch (safi) */
            break;
        default:
            length = 0;
            expert_add_info(pinfo, ti, &ei_bgp_unknown_afi);
            break;
    } /* switch (af) */

    if (length) {
        proto_item_append_text(ti, ": %s", wmem_strbuf_get_str(strbuf));
    } else {
        expert_add_info_format(pinfo, ti, &ei_bgp_length_invalid, "Unknown Next Hop length (%u byte%s)", nhlen, plurality(nhlen, "", "s"));
        if (nhlen > 0) {
            proto_item_append_text(ti, ": %s", tvb_bytes_to_str(pinfo->pool, tvb, offset, nhlen));
        }
    }

    return length;
}

static int decode_bgp_link_node_descriptor(tvbuff_t *tvb, proto_tree *tree, gint offset, packet_info *pinfo, int length)
{
    guint16 sub_length;
    guint16 type;
    guint16 diss_length;

    proto_item* tlv_item;
    proto_tree* tlv_tree;

    diss_length = 0;

    while (length > 0 ) {
    if (length < 4) {
        expert_add_info_format(pinfo, tree, &ei_bgp_ls_error,
            "Unknown data in Link-State Link NLRI!");
        diss_length += length;
        break;
    }
    type = tvb_get_ntohs(tvb, offset);
    sub_length = tvb_get_ntohs(tvb, offset + 2);

    switch (type) {
        case BGP_NLRI_TLV_AUTONOMOUS_SYSTEM:
              tlv_item = proto_tree_add_item(tree, hf_bgp_ls_tlv_autonomous_system, tvb, offset, sub_length+4, ENC_NA);
              tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_mp_reach_nlri);
              proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
              proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
              if (sub_length != BGP_NLRI_TLV_LEN_AUTONOMOUS_SYSTEM) {
                  expert_add_info_format(pinfo, tree, &ei_bgp_ls_error,
                                         "Autonomous system TLV length should be %u bytes! (%u)",
                                         BGP_NLRI_TLV_LEN_AUTONOMOUS_SYSTEM, sub_length);
                  break;
              }
              proto_tree_add_item(tlv_tree, hf_bgp_ls_tlv_autonomous_system_id, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
          break;
          case BGP_NLRI_TLV_BGP_LS_IDENTIFIER:
              tlv_item = proto_tree_add_item(tree, hf_bgp_ls_tlv_bgp_ls_identifier, tvb, offset, sub_length+4, ENC_NA);
              tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_mp_reach_nlri);
              proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
              proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
              if (sub_length != BGP_NLRI_TLV_LEN_BGP_LS_IDENTIFIER) {
                  expert_add_info_format(pinfo, tree, &ei_bgp_ls_error,
                                         "BGP-LS TLV length should be %u bytes! (%u)",
                                         BGP_NLRI_TLV_LEN_BGP_LS_IDENTIFIER, sub_length);
                  break;
              }
              proto_tree_add_item(tlv_tree, hf_bgp_ls_tlv_bgp_ls_identifier_id, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
          break;
          case BGP_NLRI_TLV_AREA_ID:
              tlv_item = proto_tree_add_item(tree, hf_bgp_ls_tlv_area_id, tvb, offset, sub_length+4, ENC_NA);
              tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_mp_reach_nlri);
              proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
              proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
              if (sub_length != BGP_NLRI_TLV_LEN_AREA_ID) {
                  expert_add_info_format(pinfo, tree, &ei_bgp_ls_error,
                                         "Area ID TLV length should be %u bytes! (%u)",
                                         BGP_NLRI_TLV_LEN_AREA_ID, sub_length);
                  break;
              }
              proto_tree_add_item(tlv_tree, hf_bgp_ls_tlv_area_id_id, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
          break;
          case BGP_NLRI_TLV_IGP_ROUTER_ID:
              tlv_item = proto_tree_add_item(tree, hf_bgp_ls_tlv_igp_router, tvb, offset, sub_length+4, ENC_NA);
              tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_mp_reach_nlri);
              proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
              proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
              proto_tree_add_item(tlv_tree, hf_bgp_ls_tlv_igp_router_id, tvb, offset + 4, sub_length, ENC_NA);
          break;
          case BGP_NLRI_TLV_BGP_ROUTER_ID:
              tlv_item = proto_tree_add_item(tree, hf_bgp_ls_tlv_bgp_router_id, tvb, offset, sub_length+4, ENC_NA);
              tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_mp_reach_nlri);
              proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
              proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
              proto_tree_add_item(tlv_tree, hf_bgp_ls_tlv_bgp_router_id_id, tvb, offset + 4, sub_length, ENC_NA);
          break;
          default:
              expert_add_info_format(pinfo, tree, &ei_bgp_ls_warn, "Undefined node Descriptor Sub-TLV type (%u)!", type);
    }

    length -= 4 + sub_length;
    offset += 4 + sub_length;
    diss_length += 4 + sub_length;
    }
    return diss_length;
}


/*
 * Decode BGP Link State Local and Remote NODE Descriptors
 */
static int decode_bgp_link_node_nlri_tlvs(tvbuff_t *tvb, proto_tree *tree, gint offset, packet_info *pinfo, guint16 expected_sub_tlv)
{
    guint16 length;
    guint16 type;
    proto_tree* tlv_tree;
    proto_item* tlv_item;

    type = tvb_get_ntohs(tvb, offset);
    length = tvb_get_ntohs(tvb, offset + 2);

    if (expected_sub_tlv != type) {
        expert_add_info_format(pinfo, tree, &ei_bgp_ls_error, "Expected/actual tlv mismatch, expected: %u, actual: %u", expected_sub_tlv, type);
    }

    switch(type){

        /*local and remote node descriptors */
        case BGP_NLRI_TLV_LOCAL_NODE_DESCRIPTORS:
            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_tlv_local_node_descriptors, tvb, offset, length+4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_mp_reach_nlri);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            decode_bgp_link_node_descriptor(tvb, tlv_tree, offset + 4, pinfo, length);
        break;

        case BGP_NLRI_TLV_REMOTE_NODE_DESCRIPTORS:
            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_tlv_remote_node_descriptors, tvb, offset, length+4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_mp_reach_nlri);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            decode_bgp_link_node_descriptor(tvb, tlv_tree, offset + 4, pinfo, length);
        break;
        }

    return length +4 ;
}

/*
 * Dissect Link and Node NLRI common fields (Protocol-ID, Identifier, Local Node Desc.)
 */
static int decode_bgp_link_node_nlri_common_fields(tvbuff_t *tvb,
        proto_tree *tree, gint offset, packet_info *pinfo, int length) {
    int dissected_length;
    int tmp_length;

    /* dissect Link NLRI header */
    if (length < 12) {
        expert_add_info_format(pinfo, tree, &ei_bgp_ls_error,
                "Link State NLRI length is lower than 12 bytes! (%d)", length);
        return length;
    }

    proto_tree_add_item(tree, hf_bgp_ls_nlri_node_protocol_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    save_link_state_protocol_id(pinfo, tvb_get_guint8(tvb, offset));
    proto_tree_add_item(tree, hf_bgp_ls_nlri_node_identifier, tvb, offset + 1, 8, ENC_BIG_ENDIAN);

    dissected_length = 9;
    offset += dissected_length;
    length -= dissected_length;

    /* dissect Local Node Descriptors TLV */
    if (length > 0 && length < 4) {
        expert_add_info_format(pinfo, tree, &ei_bgp_ls_error,
                "Unknown data in Link-State Link NLRI! length = %d bytes", length);
        return dissected_length;
    }

    tmp_length = decode_bgp_link_node_nlri_tlvs(tvb, tree, offset, pinfo,
                                                BGP_NLRI_TLV_LOCAL_NODE_DESCRIPTORS);
    if (tmp_length < 0) {
       return -1;
    }
    dissected_length += tmp_length;

    return dissected_length;
}


/*
 * Decode Link Descriptors
 */
static int decode_bgp_link_nlri_link_descriptors(tvbuff_t *tvb,
        proto_tree *tree, gint offset, packet_info *pinfo, int length) {

    guint16 sub_length;
    guint16 type;
    guint16 diss_length;
    guint16 tmp16;

    proto_item* tlv_item;
    proto_tree* tlv_tree;
    proto_item* tlv_sub_item;
    proto_tree* tlv_sub_tree;

    tlv_item = proto_tree_add_item(tree, hf_bgp_ls_nlri_link_descriptors_tlv, tvb, offset, length + 4, ENC_NA);
    tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_mp_reach_nlri);

    diss_length = 0;
    while (length > 0) {
        if (length < 4) {
            expert_add_info_format(pinfo, tree, &ei_bgp_ls_error,
                    "Unknown data in Link-State Link NLRI!");
            diss_length += length;
            break;
        }

        type = tvb_get_ntohs(tvb, offset);
        sub_length = tvb_get_ntohs(tvb, offset + 2);
        switch (type) {
            case BGP_NLRI_TLV_LINK_LOCAL_REMOTE_IDENTIFIERS:
                if(sub_length != BGP_NLRI_TLV_LEN_LINK_LOCAL_REMOTE_IDENTIFIERS){
                    expert_add_info_format(pinfo, tlv_tree, &ei_bgp_ls_error,
                                           "Unexpected Link Local/Remote Identifiers TLV's length (%u), it must be %u bytes!",
                                           sub_length, BGP_NLRI_TLV_LEN_LINK_LOCAL_REMOTE_IDENTIFIERS);
                    return -1;
                }
                tlv_sub_item = proto_tree_add_item(tlv_tree,
                                                   hf_bgp_ls_tlv_link_local_remote_identifiers, tvb, offset,
                                                   sub_length + 4, ENC_NA);
                tlv_sub_tree = proto_item_add_subtree(tlv_sub_item, ett_bgp_mp_reach_nlri);
            break;

            case BGP_NLRI_TLV_IPV4_INTERFACE_ADDRESS:
                if(sub_length != BGP_NLRI_TLV_LEN_IPV4_INTERFACE_ADDRESS){
                    expert_add_info_format(pinfo, tlv_tree, &ei_bgp_ls_error,
                                           "Unexpected IPv4 Interface Address TLV's length (%u), it must be %u bytes!",
                                           sub_length, BGP_NLRI_TLV_LEN_IPV4_INTERFACE_ADDRESS);
                    return -1;
                }
                tlv_sub_item = proto_tree_add_item(tlv_tree,
                                                   hf_bgp_ls_tlv_ipv4_interface_address, tvb, offset,
                                                   sub_length + 4, ENC_NA);
                tlv_sub_tree = proto_item_add_subtree(tlv_sub_item, ett_bgp_mp_reach_nlri);
            break;

            case BGP_NLRI_TLV_IPV4_NEIGHBOR_ADDRESS:
                if(sub_length != BGP_NLRI_TLV_LEN_IPV4_NEIGHBOR_ADDRESS){
                    expert_add_info_format(pinfo, tlv_tree, &ei_bgp_ls_error,
                                           "Unexpected IPv4 Neighbor Address TLV's length (%u), it must be %u bytes!",
                                           sub_length, BGP_NLRI_TLV_LEN_IPV4_NEIGHBOR_ADDRESS);
                    return -1;
                }
                tlv_sub_item = proto_tree_add_item(tlv_tree,
                                                   hf_bgp_ls_tlv_ipv4_neighbor_address, tvb, offset,
                                                   sub_length + 4, ENC_NA);
                tlv_sub_tree = proto_item_add_subtree(tlv_sub_item, ett_bgp_mp_reach_nlri);
            break;

            case BGP_NLRI_TLV_IPV6_INTERFACE_ADDRESS:
                if(sub_length != BGP_NLRI_TLV_LEN_IPV6_INTERFACE_ADDRESS){
                    expert_add_info_format(pinfo, tlv_tree, &ei_bgp_ls_error,
                                           "Unexpected IPv6 Interface Address TLV's length (%u), it must be %u bytes!",
                                           sub_length, BGP_NLRI_TLV_LEN_IPV6_INTERFACE_ADDRESS);
                    return -1;
                }
                tlv_sub_item = proto_tree_add_item(tlv_tree,
                                                   hf_bgp_ls_tlv_ipv6_interface_address, tvb, offset,
                                                   sub_length + 4, ENC_NA);
                tlv_sub_tree = proto_item_add_subtree(tlv_sub_item, ett_bgp_mp_reach_nlri);
            break;

            case BGP_NLRI_TLV_IPV6_NEIGHBOR_ADDRESS:
                if(sub_length != BGP_NLRI_TLV_IPV6_NEIGHBOR_ADDRESS){
                    expert_add_info_format(pinfo, tlv_tree, &ei_bgp_ls_error,
                                           "Unexpected IPv6 Neighbor Address TLV's length (%u), it must be %u bytes!",
                                           sub_length, BGP_NLRI_TLV_IPV6_NEIGHBOR_ADDRESS);
                    return -1;
                }
                tlv_sub_item = proto_tree_add_item(tlv_tree,
                                                   hf_bgp_ls_tlv_ipv6_neighbor_address, tvb, offset,
                                                   sub_length + 4, ENC_NA);
                tlv_sub_tree = proto_item_add_subtree(tlv_sub_item, ett_bgp_mp_reach_nlri);
            break;

            case BGP_NLRI_TLV_MULTI_TOPOLOGY_ID:
                if(sub_length != BGP_NLRI_TLV_LEN_MULTI_TOPOLOGY_ID){
                    expert_add_info_format(pinfo, tlv_tree, &ei_bgp_ls_error,
                                           "Unexpected Multi Topology ID TLV's length (%u), it must be %u bytes!",
                                           sub_length, BGP_NLRI_TLV_LEN_MULTI_TOPOLOGY_ID);
                    return -1;
                }
                tlv_sub_item = proto_tree_add_item(tlv_tree,
                        hf_bgp_ls_tlv_multi_topology_id, tvb, offset, sub_length + 4,
                        ENC_NA);
                tlv_sub_tree = proto_item_add_subtree(tlv_sub_item, ett_bgp_mp_reach_nlri);
            break;

            default:
                expert_add_info_format(pinfo, tlv_tree, &ei_bgp_ls_error,
                        "Unknown Link Descriptor TLV Code (%u)!", type);
                return -1;
        }

        proto_tree_add_item(tlv_sub_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tlv_sub_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

        switch (type) {
            case BGP_NLRI_TLV_LINK_LOCAL_REMOTE_IDENTIFIERS:
                proto_tree_add_item(tlv_sub_tree, hf_bgp_ls_nlri_link_local_identifier, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_sub_tree, hf_bgp_ls_nlri_link_remote_identifier, tvb, offset + 8, 4, ENC_BIG_ENDIAN);
            break;

            case BGP_NLRI_TLV_IPV4_INTERFACE_ADDRESS:
                proto_tree_add_item(tlv_sub_tree, hf_bgp_ls_nlri_ipv4_interface_address, tvb, offset + 4,
                                    BGP_NLRI_TLV_LEN_IPV4_INTERFACE_ADDRESS, ENC_BIG_ENDIAN);
            break;

            case BGP_NLRI_TLV_IPV4_NEIGHBOR_ADDRESS:
                proto_tree_add_item(tlv_sub_tree, hf_bgp_ls_nlri_ipv4_neighbor_address, tvb, offset + 4,
                                    BGP_NLRI_TLV_LEN_IPV4_INTERFACE_ADDRESS, ENC_BIG_ENDIAN);
            break;

            case BGP_NLRI_TLV_IPV6_INTERFACE_ADDRESS:
                proto_tree_add_item(tlv_sub_tree, hf_bgp_ls_nlri_ipv6_interface_address, tvb, offset + 4,
                                    BGP_NLRI_TLV_LEN_IPV6_INTERFACE_ADDRESS, ENC_NA);
            break;

            case BGP_NLRI_TLV_IPV6_NEIGHBOR_ADDRESS:
                proto_tree_add_item(tlv_sub_tree, hf_bgp_ls_nlri_ipv6_neighbor_address, tvb, offset + 4,
                                    BGP_NLRI_TLV_LEN_IPV6_INTERFACE_ADDRESS, ENC_NA);
            break;

            case BGP_NLRI_TLV_MULTI_TOPOLOGY_ID:
                tmp16 = tvb_get_ntohs(tvb, offset + 4);
                tmp16 >>= 12;
                if(tmp16){
                    expert_add_info_format(pinfo, tlv_sub_tree, &ei_bgp_ls_error, "Reserved bits of Multi Topology ID must be set to zero! (%u)", tmp16);
                }
                proto_tree_add_item(tlv_sub_tree, hf_bgp_ls_nlri_multi_topology_id, tvb, offset + 4,
                                    BGP_NLRI_TLV_LEN_MULTI_TOPOLOGY_ID, ENC_BIG_ENDIAN);
            break;
        }

        length -= 4 + sub_length;
        offset += 4 + sub_length;
        diss_length += 4 + sub_length;
    }
    return diss_length;
}

/*
 * Decode Prefix Descriptors
 */
static int decode_bgp_link_nlri_prefix_descriptors(tvbuff_t *tvb,
        proto_tree *tree, gint offset, packet_info *pinfo, int length, int proto) {

    guint16 sub_length;
    guint16 type;
    guint16 diss_length;
    guint16 tmp16;

    proto_item* tlv_item;
    proto_tree* tlv_tree;
    proto_item* tlv_sub_item;
    proto_tree* tlv_sub_tree;

    tlv_item = proto_tree_add_item(tree, hf_bgp_ls_nlri_prefix_descriptors_tlv, tvb, offset, length + 4, ENC_NA);
    tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_mp_reach_nlri);

    diss_length = 0;
    while (length > 0) {
        if (length < 4) {
            expert_add_info_format(pinfo, tree, &ei_bgp_ls_error,
                    "Unknown data in Link-State Link NLRI!");
            diss_length += length;
            break;
        }

        type = tvb_get_ntohs(tvb, offset);
        sub_length = tvb_get_ntohs(tvb, offset + 2);
        switch (type) {
            case BGP_NLRI_TLV_MULTI_TOPOLOGY_ID:
                if(sub_length != BGP_NLRI_TLV_LEN_MULTI_TOPOLOGY_ID){
                    expert_add_info_format(pinfo, tlv_tree, &ei_bgp_ls_error,
                                           "Unexpected Multi Topology ID TLV's length (%u), it must be %u bytes!",
                                           sub_length, BGP_NLRI_TLV_LEN_MULTI_TOPOLOGY_ID);
                    return -1;
                }
                tlv_sub_item = proto_tree_add_item(tlv_tree,
                        hf_bgp_ls_tlv_multi_topology_id, tvb, offset, sub_length + 4,
                        ENC_NA);
                tlv_sub_tree = proto_item_add_subtree(tlv_sub_item, ett_bgp_mp_reach_nlri);
            break;

            case BGP_NLRI_TLV_OSPF_ROUTE_TYPE:
                tlv_sub_item = proto_tree_add_item(tlv_tree,
                        hf_bgp_ls_tlv_ospf_route_type, tvb, offset, sub_length + 4,
                        ENC_NA);
                tlv_sub_tree = proto_item_add_subtree(tlv_sub_item, ett_bgp_mp_reach_nlri);
            break;
            case BGP_NLRI_TLV_IP_REACHABILITY_INFORMATION:
                tlv_sub_item = proto_tree_add_item(tlv_tree,
                        hf_bgp_ls_tlv_ip_reachability_information, tvb, offset, sub_length + 4,
                        ENC_NA);
                tlv_sub_tree = proto_item_add_subtree(tlv_sub_item, ett_bgp_mp_reach_nlri);
            break;

            default:
                expert_add_info_format(pinfo, tlv_tree, &ei_bgp_ls_error,
                        "Unknown Prefix Descriptor TLV Code (%u)!", type);
                return -1;
        }

        proto_tree_add_item(tlv_sub_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tlv_sub_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

        switch (type) {
            case BGP_NLRI_TLV_MULTI_TOPOLOGY_ID:
                tmp16 = tvb_get_ntohs(tvb, offset + 4);
                tmp16 >>= 12;
                if(tmp16){
                    expert_add_info_format(pinfo, tlv_sub_tree, &ei_bgp_ls_error, "Reserved bits of Multi Topology ID must be set to zero! (%u)", tmp16);
                }
                proto_tree_add_item(tlv_sub_tree, hf_bgp_ls_nlri_multi_topology_id, tvb, offset + 4,
                                    BGP_NLRI_TLV_LEN_MULTI_TOPOLOGY_ID, ENC_BIG_ENDIAN);
            break;

            case BGP_NLRI_TLV_OSPF_ROUTE_TYPE:

                if (sub_length != 1) {
                    expert_add_info_format(pinfo, tlv_sub_tree, &ei_bgp_ls_error, "OSPF Route Type length must be \"1\"");
                    break;
                }
                proto_tree_add_item(tlv_sub_tree, hf_bgp_ls_nlri_ospf_route_type, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
            break;

            case BGP_NLRI_TLV_IP_REACHABILITY_INFORMATION:
                if (( proto == IP_PROTO_IPV4 ) && (decode_prefix4(tlv_sub_tree, pinfo, tlv_sub_item, hf_bgp_ls_nlri_ip_reachability_prefix_ip,
                               tvb, offset + 4, "Reachability") == -1))
                    return diss_length;
                if (( proto == IP_PROTO_IPV6 ) && (decode_prefix6(tlv_sub_tree, pinfo, hf_bgp_ls_nlri_ip_reachability_prefix_ip6,
                               tvb, offset + 4, 0, "Reachability") == -1))
                    return diss_length;
            break;
        }

        length -= 4 + sub_length;
        offset += 4 + sub_length;
        diss_length += 4 + sub_length;
    }
    return diss_length;
}

/*
 * Decode Flex Algo sub-TLVs in BGP-LS attributes
 */
static int
decode_link_state_attribute_flex_algo_subtlv(proto_tree *tree, tvbuff_t *tvb, gint offset, packet_info *pinfo, guint8 _U_ protocol_id)
{
    guint16 type;
    guint16 length;
    guint16 tmp16;

    proto_item* tlv_item;
    proto_tree* tlv_tree;

    type = tvb_get_ntohs(tvb, offset);
    length = tvb_get_ntohs(tvb, offset + 2);

    switch (type) {
    case BGP_LS_SR_TLV_FLEX_ALGO_EXC_ANY_AFFINITY:
    case BGP_LS_SR_TLV_FLEX_ALGO_INC_ANY_AFFINITY:
    case BGP_LS_SR_TLV_FLEX_ALGO_INC_ALL_AFFINITY:
        tlv_item = proto_tree_add_item(tree,
                                       (type == BGP_LS_SR_TLV_FLEX_ALGO_EXC_ANY_AFFINITY) ?
                                       hf_bgp_ls_sr_tlv_flex_algo_exc_any_affinity :
                                       ((type == BGP_LS_SR_TLV_FLEX_ALGO_INC_ANY_AFFINITY) ?
                                        hf_bgp_ls_sr_tlv_flex_algo_inc_any_affinity :
                                        hf_bgp_ls_sr_tlv_flex_algo_inc_all_affinity),
                                       tvb, offset, length + 4, ENC_NA);
        tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
        proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
        if (length % 4 != 0) {
            expert_add_info_format(pinfo, tlv_tree, &ei_bgp_ls_error, "Unexpected Extended Administrative Group TLV's length (%u mod 4 != 0)",
                                   length);
            break;
        }
        tmp16 = length;
        while (tmp16) {
            proto_tree_add_item(tlv_tree, hf_bgp_ls_extended_administrative_group_value, tvb, offset + 4 + (length - tmp16), 4, ENC_NA);
            tmp16 -= 4;
        }
        break;

    default:
        expert_add_info_format(pinfo, tree, &ei_bgp_ls_warn,
                               "Unknown BGP-LS Flex-Algo sub-TLV Code (%u)!", type);
        break;
    }

    return length + 4;
}

/*
 * Decode a multiprotocol prefix
 */
static int
decode_link_state_attribute_tlv(proto_tree *tree, tvbuff_t *tvb, gint offset, packet_info *pinfo, guint8 protocol_id)
{
    guint16 type;
    guint16 length;
    guint8  tmp8;
    guint16 tmp16;
    guint32 tmp32;
    gfloat  tmp_float;
    guint32 mask;
    gint local_offset, local_length;
    int n;
    guint8  sabm_len, udabm_len;
    int     advance;

    proto_item* tlv_item;
    proto_tree* tlv_tree;
    proto_item* tlv_sub_item;
    proto_tree* tlv_sub_tree;
    proto_item* ti;

    type = tvb_get_ntohs(tvb, offset);
    length = tvb_get_ntohs(tvb, offset + 2);

    switch (type) {

        /* NODE ATTRIBUTE TLVs */
        case BGP_NLRI_TLV_MULTI_TOPOLOGY_ID:
            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_tlv_multi_topology_id, tvb, offset, length + 4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);

            for (n = 0; n < (length / BGP_NLRI_TLV_LEN_MULTI_TOPOLOGY_ID); n++) {
                tmp16 = tvb_get_ntohs(tvb, offset + 4 + (n * BGP_NLRI_TLV_LEN_MULTI_TOPOLOGY_ID));
                tmp16 >>= 12;
                if(tmp16){
                    expert_add_info_format(pinfo, tlv_tree, &ei_bgp_ls_error, "Reserved bits of Multi Topology ID must be set to zero! (%u)", tmp16);
                }
                proto_tree_add_item(tlv_tree, hf_bgp_ls_nlri_multi_topology_id, tvb, offset + 4 + (n * BGP_NLRI_TLV_LEN_MULTI_TOPOLOGY_ID),
                                                    BGP_NLRI_TLV_LEN_MULTI_TOPOLOGY_ID, ENC_BIG_ENDIAN);
            }
            break;

        case BGP_NLRI_TLV_NODE_FLAG_BITS:
            {
            static int * const flags[] = {
                &hf_bgp_ls_node_flag_bits_overload,
                &hf_bgp_ls_node_flag_bits_attached,
                &hf_bgp_ls_node_flag_bits_external,
                &hf_bgp_ls_node_flag_bits_abr,
                NULL
            };

            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_tlv_node_flags_bits, tvb, offset, length+4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
            if(length != BGP_NLRI_TLV_LEN_NODE_FLAG_BITS){
                expert_add_info_format(pinfo, tlv_tree, &ei_bgp_ls_error, "Unexpected Node Flags Bits TLV's length (%u), it must be %u bytes!",
                                       length, BGP_NLRI_TLV_LEN_NODE_FLAG_BITS);
                break;
            }
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_bitmask_list(tlv_tree, tvb, offset+4, 1, flags, ENC_NA);
            tmp8 = tvb_get_guint8(tvb, offset+4) & 0x0f;
            if(tmp8){
                expert_add_info_format(pinfo, tlv_tree, &ei_bgp_ls_error, "Reserved flag bits are not set to zero (%u).", tmp8);
            }
            }
            break;

        case BGP_NLRI_TLV_OPAQUE_NODE_PROPERTIES:
            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_tlv_opaque_node_properties, tvb, offset, length+4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_tlv_opaque_node_properties_value, tvb, offset + 4, length, ENC_NA);
            break;

        case BGP_NLRI_TLV_NODE_NAME:
            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_tlv_node_name, tvb, offset, length+4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_tlv_node_name_value, tvb, offset + 4, length, ENC_ASCII);
            break;

        case BGP_NLRI_TLV_IS_IS_AREA_IDENTIFIER:
            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_tlv_is_is_area_identifier, tvb, offset, length+4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_tlv_is_is_area_identifier_value, tvb, offset + 4, length, ENC_NA);
            break;

        case BGP_LS_SR_TLV_SR_CAPABILITY:
            {
                /*
                  0  1  2  3  4  5  6  7
                  +--+--+--+--+--+--+--+--+
                  |I |V |H |  |  |  |  |  |
                  +--+--+--+--+--+--+--+--+
                */
                static int * const sr_capabilities_flags[] = {
                    &hf_bgp_ls_sr_tlv_capabilities_flags_i,
                    &hf_bgp_ls_sr_tlv_capabilities_flags_v,
                    &hf_bgp_ls_sr_tlv_capabilities_flags_h,
                    &hf_bgp_ls_sr_tlv_capabilities_flags_reserved,
                    NULL
                };
                gint offset2;
                gint remaining_data;
                tlv_item = proto_tree_add_item(tree, hf_bgp_ls_sr_tlv_capabilities, tvb, offset, length + 4, ENC_NA);
                tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
                proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
                proto_tree_add_bitmask(tlv_tree, tvb, offset + 4, hf_bgp_ls_sr_tlv_capabilities_flags,
                                       ett_bgp_link_state, sr_capabilities_flags, ENC_BIG_ENDIAN);
                /* past flags and reserved byte, we got one or more range + SID/Label Sub-TLV entries */
                offset2 = offset + 4 + 2;
                remaining_data = length - 2;
                while (remaining_data > 0) {
                    guint16 sid_len = 0;
                    /* parse and consume the range field */
                    proto_tree_add_item(tlv_tree, hf_bgp_ls_sr_tlv_capabilities_range_size, tvb, offset2, 3, ENC_BIG_ENDIAN);
                    offset2 += 3;
                    /* parse and consume type/len fields */
                    proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset2, 2, ENC_BIG_ENDIAN);
                    offset2 += 2;
                    proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset2, 2, ENC_BIG_ENDIAN);
                    sid_len = tvb_get_ntohs(tvb, offset2);
                    offset2 += 2;
                    if (sid_len == 3) {
                        /* parse and consume the SID/Label field */
                        proto_tree_add_item(tlv_tree, hf_bgp_ls_sr_tlv_capabilities_sid_label, tvb, offset2, 3, ENC_BIG_ENDIAN);
                        offset2 += 3;
                        remaining_data -= 10;
                    } else {
                        /* parse and consume the SID/Index field */
                        proto_tree_add_item(tlv_tree, hf_bgp_ls_sr_tlv_capabilities_sid_index, tvb, offset2, 4, ENC_BIG_ENDIAN);
                        offset2 += 4;
                        remaining_data -= 11;
                    }
                }
            }
            break;

        case BGP_LS_SR_TLV_SR_LOCAL_BLOCK:
            {
                gint offset2;
                gint remaining_data;
                tlv_item = proto_tree_add_item(tree, hf_bgp_ls_sr_tlv_local_block, tvb, offset, length + 4, ENC_NA);
                tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
                proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_bgp_ls_sr_tlv_local_block_flags, tvb, offset + 4, 1, ENC_NA);
                /* past flags and reserved byte, we got one or more range + SID/Label Sub-TLV entries */
                offset2 = offset + 4 + 2;
                remaining_data = length - 2;
                while (remaining_data > 0) {
                    guint16 sid_len = 0;
                    /* parse and consume the range field */
                    proto_tree_add_item(tlv_tree, hf_bgp_ls_sr_tlv_local_block_range_size, tvb, offset2, 3, ENC_BIG_ENDIAN);
                    offset2 += 3;
                    /* parse and consume type/len fields */
                    proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset2, 2, ENC_BIG_ENDIAN);
                    offset2 += 2;
                    proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset2, 2, ENC_BIG_ENDIAN);
                    sid_len = tvb_get_ntohs(tvb, offset2);
                    offset2 += 2;
                    if (sid_len == 3) {
                        /* parse and consume the SID/Label field */
                        proto_tree_add_item(tlv_tree, hf_bgp_ls_sr_tlv_local_block_sid_label, tvb, offset2, 3, ENC_BIG_ENDIAN);
                        offset2 += 3;
                        remaining_data -= 10;
                    } else {
                        /* parse and consume the SID/Index field */
                        proto_tree_add_item(tlv_tree, hf_bgp_ls_sr_tlv_local_block_sid_index, tvb, offset2, 4, ENC_BIG_ENDIAN);
                        offset2 += 4;
                        remaining_data -= 11;
                    }
                }
            }
            break;

        case BGP_LS_SR_TLV_SR_ALGORITHM:
            {
                gint offset2;
                gint remaining_data;
                tlv_item = proto_tree_add_item(tree, hf_bgp_ls_sr_tlv_algorithm, tvb, offset, length+4, ENC_NA);
                tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
                proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
                /* past type-length fields, we got one or more 'Algorithm N' value */
                offset2 = offset + 4;
                remaining_data = length;
                while (remaining_data > 0) {
                    proto_tree_add_item(tlv_tree, hf_bgp_ls_sr_tlv_algorithm_value, tvb, offset2, 1, ENC_NA);
                    offset2 += 1;
                    remaining_data -= 1;
                }
            }
            break;

        case BGP_LS_SR_TLV_FLEX_ALGO_DEF:
            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_sr_tlv_flex_algo_def, tvb, offset, length+4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_sr_tlv_flex_algo_algorithm, tvb, offset + 4, 1, ENC_NA);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_sr_tlv_flex_algo_metric_type, tvb, offset + 5, 1, ENC_NA);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_sr_tlv_flex_algo_calc_type, tvb, offset + 6, 1, ENC_NA);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_sr_tlv_flex_algo_priority, tvb, offset + 7, 1, ENC_NA);
            local_offset = offset + 8;
            while (local_offset < offset + length) {
                advance = decode_link_state_attribute_flex_algo_subtlv(tlv_tree, tvb, local_offset, pinfo, protocol_id);
                if (advance < 0) {
                    break;
                }
                local_offset += advance;
            }
            break;

        /* NODE & LINK ATTRIBUTE TLVs */
        case BGP_NLRI_TLV_NODE_MSD:
        case BGP_NLRI_TLV_LINK_MSD:
            tlv_item = proto_tree_add_item(tree,
                                           (type == BGP_NLRI_TLV_NODE_MSD ?
                                            hf_bgp_ls_tlv_node_msd : hf_bgp_ls_tlv_link_msd),
                                            tvb, offset, length + 4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_mp_reach_nlri);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            local_offset = offset + 4;
            local_length = length;
            while (local_length >= 2) {
                proto_tree_add_item(tlv_tree, hf_bgp_ls_tlv_igp_msd_type, tvb, local_offset, 1, ENC_NA);
                proto_tree_add_item(tlv_tree, hf_bgp_ls_tlv_igp_msd_value, tvb, local_offset+1, 1, ENC_NA);
                local_length -= 2;
                local_offset += 2;
            }
            break;

        case BGP_NLRI_TLV_IPV4_ROUTER_ID_OF_LOCAL_NODE:
            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_tlv_ipv4_router_id_of_local_node, tvb, offset, length+4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            if(length != BGP_NLRI_TLV_LEN_IPV4_ROUTER_ID_OF_LOCAL_NODE){
                expert_add_info_format(pinfo, tlv_tree, &ei_bgp_ls_error, "Unexpected IPv4 Router-ID TLV's length (%u), it must be %u bytes!",
                                    length, BGP_NLRI_TLV_LEN_IPV4_ROUTER_ID_OF_LOCAL_NODE);
                break;
            }
            proto_tree_add_item(tlv_tree, hf_bgp_ls_tlv_ipv4_router_id_value, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
            break;
        case BGP_NLRI_TLV_IPV6_ROUTER_ID_OF_LOCAL_NODE:
            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_tlv_ipv6_router_id_of_local_node, tvb, offset, length+4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            if(length != BGP_NLRI_TLV_LEN_IPV6_ROUTER_ID_OF_LOCAL_NODE){
                expert_add_info_format(pinfo, tlv_tree, &ei_bgp_ls_error, "Unexpected IPv6 Router-ID TLV's length (%u), it must be %u bytes!",
                                    length, BGP_NLRI_TLV_LEN_IPV6_ROUTER_ID_OF_LOCAL_NODE);
                break;
            }
            proto_tree_add_item(tlv_tree, hf_bgp_ls_tlv_ipv6_router_id_value, tvb, offset + 4, BGP_NLRI_TLV_LEN_IPV6_ROUTER_ID_OF_LOCAL_NODE, ENC_NA);
            break;

        /* Link Attribute TLVs */
        case BGP_NLRI_TLV_LINK_LOCAL_REMOTE_IDENTIFIERS:
            if (length != BGP_NLRI_TLV_LEN_LINK_LOCAL_REMOTE_IDENTIFIERS) {
                expert_add_info_format(pinfo, tree, &ei_bgp_ls_error,
                                       "Unexpected Link Local/Remote Identifiers TLV's length (%u), it must be %u bytes!",
                                       length, BGP_NLRI_TLV_LEN_LINK_LOCAL_REMOTE_IDENTIFIERS);
                break;
            }
            tlv_item = proto_tree_add_item(tree,
                                           hf_bgp_ls_tlv_link_local_remote_identifiers, tvb, offset,
                                           length + 4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_mp_reach_nlri);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_nlri_link_local_identifier, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_nlri_link_remote_identifier, tvb, offset + 8, 4, ENC_BIG_ENDIAN);
            break;

        case BGP_NLRI_TLV_IPV4_ROUTER_ID_OF_REMOTE_NODE:
            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_tlv_ipv4_router_id_of_remote_node, tvb, offset, length+4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            if(length != BGP_NLRI_TLV_LEN_IPV4_ROUTER_ID_OF_REMOTE_NODE){
                expert_add_info_format(pinfo, tlv_tree, &ei_bgp_ls_error, "Unexpected IPv4 Router-ID TLV's length (%u), it must be %u bytes!",
                                    length, BGP_NLRI_TLV_LEN_IPV4_ROUTER_ID_OF_REMOTE_NODE);
                break;
            }
            proto_tree_add_item(tlv_tree, hf_bgp_ls_tlv_ipv4_router_id_value, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
            break;

        case BGP_NLRI_TLV_IPV6_ROUTER_ID_OF_REMOTE_NODE:
            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_tlv_ipv6_router_id_of_remote_node, tvb, offset, length+4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            if(length != BGP_NLRI_TLV_LEN_IPV6_ROUTER_ID_OF_REMOTE_NODE){
                expert_add_info_format(pinfo, tlv_tree, &ei_bgp_ls_error, "Unexpected IPv6 Router-ID TLV's length (%u), it must be %u bytes!",
                                    length, BGP_NLRI_TLV_LEN_IPV6_ROUTER_ID_OF_REMOTE_NODE);
                break;
            }
            proto_tree_add_item(tlv_tree, hf_bgp_ls_tlv_ipv6_router_id_value, tvb, offset + 4, BGP_NLRI_TLV_LEN_IPV6_ROUTER_ID_OF_REMOTE_NODE, ENC_NA);
            break;

        case BGP_NLRI_TLV_ADMINISTRATIVE_GROUP_COLOR:
            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_tlv_administrative_group_color, tvb, offset, length+4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
            if(length != BGP_NLRI_TLV_LEN_ADMINISTRATIVE_GROUP_COLOR){
                expert_add_info_format(pinfo, tlv_tree, &ei_bgp_ls_error, "Unexpected Administrative group (color) TLV's length (%u), it must be %u bytes!",
                                       length, BGP_NLRI_TLV_LEN_ADMINISTRATIVE_GROUP_COLOR);
                break;
            }
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            tmp32 = tvb_get_ntohl(tvb, offset + 4);
            tlv_sub_item = proto_tree_add_item(tlv_tree, hf_bgp_ls_tlv_administrative_group_color_value, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
            tlv_sub_tree = proto_item_add_subtree(tlv_sub_item, ett_bgp_prefix);
            mask = 1;
            for(n = 0; n<32; n++){
                if( tmp32 & mask ) proto_tree_add_uint(tlv_sub_tree, hf_bgp_ls_tlv_administrative_group, tvb, offset + 4, 4, n);
                mask <<= 1;
            }
            break;

        case BGP_NLRI_TLV_MAX_LINK_BANDWIDTH:
            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_tlv_max_link_bandwidth, tvb, offset, length+4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
            if(length != BGP_NLRI_TLV_LEN_MAX_LINK_BANDWIDTH){
                expert_add_info_format(pinfo, tlv_tree, &ei_bgp_ls_error, "Unexpected Maximum link bandwidth TLV's length (%u), it must be %u bytes!",
                                       length, BGP_NLRI_TLV_LEN_MAX_LINK_BANDWIDTH);
                break;
            }
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            tmp_float = tvb_get_ntohieee_float(tvb, offset + 4)*8/1000000;
            proto_tree_add_float_format(tlv_tree, hf_bgp_ls_bandwidth_value, tvb, offset + 4, 4, tmp_float, "Maximum link bandwidth: %.2f Mbps", tmp_float);
            break;

        case BGP_NLRI_TLV_MAX_RESERVABLE_LINK_BANDWIDTH:
            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_tlv_max_reservable_link_bandwidth, tvb, offset, length+4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
            if(length != BGP_NLRI_TLV_LEN_MAX_RESERVABLE_LINK_BANDWIDTH){
                expert_add_info_format(pinfo, tlv_tree, &ei_bgp_ls_error, "Unexpected Maximum reservable link bandwidth TLV's length (%u), it must be %u bytes!",
                                       length, BGP_NLRI_TLV_LEN_MAX_RESERVABLE_LINK_BANDWIDTH);
                break;
            }
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            tmp_float = tvb_get_ntohieee_float(tvb, offset + 4)*8/1000000;
            proto_tree_add_float_format(tlv_tree, hf_bgp_ls_bandwidth_value, tvb, offset + 4, 4, tmp_float, "Maximum reservable link bandwidth: %.2f Mbps", tmp_float);
            break;

        case BGP_NLRI_TLV_UNRESERVED_BANDWIDTH:
            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_tlv_unreserved_bandwidth, tvb, offset, length+4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
            if(length != BGP_NLRI_TLV_LEN_UNRESERVED_BANDWIDTH){
                expert_add_info_format(pinfo, tlv_tree, &ei_bgp_ls_error, "Unexpected Unreserved bandwidth TLV's length (%u), it must be %u bytes!",
                                       length, BGP_NLRI_TLV_LEN_UNRESERVED_BANDWIDTH);
                break;
            }
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            for(n = 0; n<8; n++){
                tmp_float = tvb_get_ntohieee_float(tvb, offset + 4 + (4 * n))*8/1000000;
                tlv_sub_item = proto_tree_add_float_format(tlv_tree, hf_bgp_ls_bandwidth_value, tvb, offset + 4 + (4 * n), 4, tmp_float, "Unreserved Bandwidth: %.2f Mbps", tmp_float);
                proto_item_prepend_text(tlv_sub_item, "Priority %u, ", n);
            }
            break;

        case BGP_NLRI_TLV_TE_DEFAULT_METRIC:
            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_tlv_te_default_metric, tvb, offset, length+4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
            /* FF: The 'TE Default Metric TLV's length changed. From draft-ietf-idr-ls-distribution-00 to 04
               was 3 bytes as per RFC5305/3.7, since version 05 is 4 bytes. Here we try to parse both formats
               without complain because there are real implementations out there based on the 3 bytes size. At
               the same time we clearly highlight that 3 is "old" and 4 is correct via expert info. */
            if (length == BGP_NLRI_TLV_LEN_TE_DEFAULT_METRIC_OLD) {
                expert_add_info_format(pinfo, tlv_tree, &ei_bgp_ls_warn,
                                       "Old TE Default Metric TLV's length (%u), it should be %u bytes!",
                                       length,
                                       BGP_NLRI_TLV_LEN_TE_DEFAULT_METRIC_NEW);
                /* just a warning do not give up dissection */
            }
            if (length != BGP_NLRI_TLV_LEN_TE_DEFAULT_METRIC_OLD && length != BGP_NLRI_TLV_LEN_TE_DEFAULT_METRIC_NEW) {
                expert_add_info_format(pinfo, tlv_tree, &ei_bgp_ls_error,
                                       "Unexpected TE Default Metric TLV's length (%u), it must be %u or %u bytes!",
                                       length,
                                       BGP_NLRI_TLV_LEN_TE_DEFAULT_METRIC_OLD,
                                       BGP_NLRI_TLV_LEN_TE_DEFAULT_METRIC_NEW);
                /* major error give up dissection */
                break;
            }
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            if (length == BGP_NLRI_TLV_LEN_TE_DEFAULT_METRIC_OLD) {
                proto_tree_add_item(tlv_tree, hf_bgp_ls_tlv_te_default_metric_value_old, tvb, offset + 4, 3, ENC_BIG_ENDIAN);
            } else if (length == BGP_NLRI_TLV_LEN_TE_DEFAULT_METRIC_NEW) {
                proto_tree_add_item(tlv_tree, hf_bgp_ls_tlv_te_default_metric_value, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
            }
            break;

        case BGP_NLRI_TLV_LINK_PROTECTION_TYPE:
            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_tlv_link_protection_type, tvb, offset, length+4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
            if(length != BGP_NLRI_TLV_LEN_LINK_PROTECTION_TYPE){
                expert_add_info_format(pinfo, tlv_tree, &ei_bgp_ls_error, "Unexpected Link Protection Type TLV's length (%u), it must be %u bytes!",
                                       length, BGP_NLRI_TLV_LEN_LINK_PROTECTION_TYPE);
                break;
            }
            else {
                static int * const nlri_flags[] = {
                    &hf_bgp_ls_link_protection_type_extra_traffic,
                    &hf_bgp_ls_link_protection_type_unprotected,
                    &hf_bgp_ls_link_protection_type_shared,
                    &hf_bgp_ls_link_protection_type_dedicated_1to1,
                    &hf_bgp_ls_link_protection_type_dedicated_1plus1,
                    &hf_bgp_ls_link_protection_type_enhanced,
                    NULL
                };

                proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
                tmp8 = tvb_get_guint8(tvb, offset + 4);

                tlv_sub_item = proto_tree_add_bitmask(tlv_tree, tvb, offset + 4, hf_bgp_ls_tlv_link_protection_type_value, ett_bgp_mp_reach_nlri, nlri_flags, ENC_NA);
                tmp8 >>= 6;
                if(tmp8){
                    expert_add_info_format(pinfo, tlv_sub_item, &ei_bgp_ls_error, "Reserved Protection Capabilities bits are not set to zero (%u).", tmp8);
                }
                tmp8 = tvb_get_guint8(tvb, offset + 4 + 1);
                if(tmp8){
                    expert_add_info_format(pinfo, tlv_tree, &ei_bgp_ls_error, "Reserved field is not set to zero. (%u)", tmp8);
                }
            }
            break;
        case BGP_NLRI_TLV_MPLS_PROTOCOL_MASK:
            {
            static int * const flags[] = {
                &hf_bgp_ls_mpls_protocol_mask_flag_l,
                &hf_bgp_ls_mpls_protocol_mask_flag_r,
                NULL
            };

            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_tlv_mpls_protocol_mask, tvb, offset, length+4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
            if(length != BGP_NLRI_TLV_LEN_MPLS_PROTOCOL_MASK){
                expert_add_info_format(pinfo, tlv_tree, &ei_bgp_ls_error, "Unexpected MPLS Protocol Mask TLV's length (%u), it must be %u bytes!",
                                       length, BGP_NLRI_TLV_LEN_MPLS_PROTOCOL_MASK);
                break;
            }
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_bitmask_list(tlv_tree, tvb, offset+4, 1, flags, ENC_NA);
            tmp8 = tvb_get_guint8(tvb, offset + 4) & 0x3f;
            if(tmp8){
                proto_tree_add_expert_format(tlv_tree, pinfo, &ei_bgp_ls_error, tvb, offset + 4, 1,
                                             "Reserved flags are not set to zero (%u).", tmp8);
            }
            }
            break;
        case BGP_NLRI_TLV_METRIC:
            /* FF: The IGP 'Metric TLV's length changed. From draft-ietf-idr-ls-distribution-00 to 02
               was fixed at 3 bytes, since version 03 is variable 1/2/3 bytes. We cannot complain if
               length is not fixed at 3. */
            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_tlv_metric, tvb, offset, length + 4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
            if (length > BGP_NLRI_TLV_LEN_MAX_METRIC) {
                expert_add_info_format(pinfo, tlv_tree, &ei_bgp_ls_error,
                                       "Unexpected Metric TLV's length (%u), it must be less than %u bytes!",
                                       length, BGP_NLRI_TLV_LEN_MAX_METRIC);
                break;
            }
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            if (length == 1) {
                proto_tree_add_item(tlv_tree, hf_bgp_ls_tlv_metric_value1, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
            } else if (length == 2) {
                proto_tree_add_item(tlv_tree, hf_bgp_ls_tlv_metric_value2, tvb, offset + 4, 2, ENC_BIG_ENDIAN);
            } else if (length == 3) {
                proto_tree_add_item(tlv_tree, hf_bgp_ls_tlv_metric_value3, tvb, offset + 4, 3, ENC_BIG_ENDIAN);
            }
            break;
        case BGP_NLRI_TLV_SHARED_RISK_LINK_GROUP:
            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_tlv_shared_risk_link_group, tvb, offset, length+4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            tmp16 = length;
            n = 0;
            while(tmp16 > 0){
                if(tmp16 < 4) {
                    proto_tree_add_expert_format(tlv_tree, pinfo, &ei_bgp_ls_error,
                                                 tvb, offset + 4 + (n * 4), tmp16,
                                                 "Shared Risk Link Group Value must be 4 bytes long (%u).", tmp16);
                    break;
                }
                proto_tree_add_item(tlv_tree, hf_bgp_ls_tlv_shared_risk_link_group_value, tvb, offset + 4 + (n * 4), 4, ENC_BIG_ENDIAN);
                tmp16 -= 4;
                n++;
            }
            break;

        case BGP_NLRI_TLV_OPAQUE_LINK_ATTRIBUTE:
            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_tlv_opaque_link_attribute, tvb, offset, length+4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_tlv_opaque_link_attribute_value, tvb,  offset + 4, length, ENC_NA);
            break;

        case BGP_NLRI_TLV_LINK_NAME_ATTRIBUTE:
            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_tlv_link_name_attribute, tvb, offset, length+4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_tlv_link_name_attribute_value, tvb, offset + 4, length, ENC_ASCII);
            break;

        case BGP_LS_SR_TLV_ADJ_SID:
            {
                /*
                   0  1  2  3  4  5  6  7
                  +--+--+--+--+--+--+--+--+
                  |F |B |V |L |S |  |  |  |
                  +--+--+--+--+--+--+--+--+
                */
                static int * const adj_sid_isis_flags[] = {
                    &hf_bgp_ls_sr_tlv_adjacency_sid_flags_fi,
                    &hf_bgp_ls_sr_tlv_adjacency_sid_flags_bi,
                    &hf_bgp_ls_sr_tlv_adjacency_sid_flags_vi,
                    &hf_bgp_ls_sr_tlv_adjacency_sid_flags_li,
                    &hf_bgp_ls_sr_tlv_adjacency_sid_flags_si,
                    NULL
                };
                /*
                   0  1  2  3  4  5  6  7
                  +--+--+--+--+--+--+--+--+
                  |B |V |L |S |  |  |  |  |
                  +--+--+--+--+--+--+--+--+
                */
                static int * const adj_sid_ospf_flags[] = {
                    &hf_bgp_ls_sr_tlv_adjacency_sid_flags_bo,
                    &hf_bgp_ls_sr_tlv_adjacency_sid_flags_vo,
                    &hf_bgp_ls_sr_tlv_adjacency_sid_flags_lo,
                    &hf_bgp_ls_sr_tlv_adjacency_sid_flags_so,
                    NULL
                };

                tlv_item = proto_tree_add_item(tree, hf_bgp_ls_sr_tlv_adjacency_sid, tvb, offset, length + 4, ENC_NA);
                tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
                proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
                if (protocol_id == BGP_LS_NLRI_PROTO_ID_OSPF) {
                    proto_tree_add_bitmask(tlv_tree, tvb, offset + 4, hf_bgp_ls_sr_tlv_adjacency_sid_flags,
                                           ett_bgp_link_state, adj_sid_ospf_flags, ENC_BIG_ENDIAN);
                } else {
                    /* FF: most common case is IS-IS, so if it is not OSPF we go that way */
                    proto_tree_add_bitmask(tlv_tree, tvb, offset + 4, hf_bgp_ls_sr_tlv_adjacency_sid_flags,
                                           ett_bgp_link_state, adj_sid_isis_flags, ENC_BIG_ENDIAN);
                }
                proto_tree_add_item(tlv_tree, hf_bgp_ls_sr_tlv_adjacency_sid_weight, tvb, offset + 5, 1, ENC_BIG_ENDIAN);
                if (length == 7) {
                    proto_tree_add_item(tlv_tree, hf_bgp_ls_sr_tlv_adjacency_sid_label, tvb, offset + 8, 3, ENC_BIG_ENDIAN);
                } else {
                    proto_tree_add_item(tlv_tree, hf_bgp_ls_sr_tlv_adjacency_sid_index, tvb, offset + 8, 4, ENC_BIG_ENDIAN);
                }
            }
            break;

        case BGP_LS_SR_TLV_LAN_ADJ_SID:
            break;

        case BGP_LS_SR_TLV_PEER_NODE_SID:
        case BGP_LS_SR_TLV_PEER_ADJ_SID:
        case BGP_LS_SR_TLV_PEER_SET_SID:
            {
                /*
                   0  1  2  3  4  5  6  7
                  +--+--+--+--+--+--+--+--+
                  |V |L |B |P |  |  |  |  | rfc9086
                  +--+--+--+--+--+--+--+--+
                */
                static int * const peer_sid_flags[] = {
                    &hf_bgp_ls_sr_tlv_peer_sid_flags_v,
                    &hf_bgp_ls_sr_tlv_peer_sid_flags_l,
                    &hf_bgp_ls_sr_tlv_peer_sid_flags_b,
                    &hf_bgp_ls_sr_tlv_peer_sid_flags_p,
                    NULL
                };

                tlv_item = proto_tree_add_item(tree,
                                               (type == BGP_LS_SR_TLV_PEER_NODE_SID ?
                                                hf_bgp_ls_sr_tlv_peer_node_sid :
                                                (type == BGP_LS_SR_TLV_PEER_ADJ_SID ?
                                                 hf_bgp_ls_sr_tlv_peer_adj_sid :
                                                 hf_bgp_ls_sr_tlv_peer_set_sid)),
                                               tvb, offset, length + 4, ENC_NA);
                tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
                proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
                ti = proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
                if (length != 7 && length != 8) {
                    expert_add_info_format(pinfo, ti, &ei_bgp_ls_error,
                                           "Unexpected TLV Length (%u) in BGP-LS Peer SID TLV, it must be either 7 or 8 bytes!",
                                           length);
                    break;
                }
                proto_tree_add_bitmask(tlv_tree, tvb, offset + 4, hf_bgp_ls_sr_tlv_peer_sid_flags,
                                       ett_bgp_link_state, peer_sid_flags, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_bgp_ls_sr_tlv_peer_sid_weight, tvb, offset + 5, 1, ENC_BIG_ENDIAN);
                if (length == 7) {
                    proto_tree_add_item(tlv_tree, hf_bgp_ls_sr_tlv_peer_sid_label, tvb, offset + 8, 3, ENC_BIG_ENDIAN);
                } else {
                    proto_tree_add_item(tlv_tree, hf_bgp_ls_sr_tlv_peer_sid_index, tvb, offset + 8, 4, ENC_BIG_ENDIAN);
                }
            }
            break;

        case BGP_LS_APP_SPEC_LINK_ATTR:
            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_tlv_app_spec_link_attrs, tvb, offset, length + 4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            sabm_len = tvb_get_guint8(tvb, offset + 4);
            ti = proto_tree_add_item(tlv_tree, hf_bgp_ls_tlv_app_spec_link_attrs_sabm_len, tvb, offset + 4, 1, ENC_NA);
            if (sabm_len != 0 && sabm_len != 4 && sabm_len != 8) {
                expert_add_info_format(pinfo, ti, &ei_bgp_ls_error,
                                       "Unexpected SABM Length (%u) in BGP-LS Application-Specific Link Attributes TLV, it must be 0/4/8 bytes!",
                                       sabm_len);
                break;
            }
            udabm_len = tvb_get_guint8(tvb, offset + 5);
            ti = proto_tree_add_item(tlv_tree, hf_bgp_ls_tlv_app_spec_link_attrs_udabm_len, tvb, offset + 5, 1, ENC_NA);
            if (udabm_len != 0 && udabm_len != 4 && udabm_len != 8) {
                expert_add_info_format(pinfo, ti, &ei_bgp_ls_error,
                                       "Unexpected UDABM Length (%u) in BGP-LS Application Specific Link Attributes TLV, it must be 0/4/8 bytes!",
                                       sabm_len);
                break;
            }
            tmp16 = tvb_get_guint16(tvb, offset + 6, ENC_BIG_ENDIAN);
            ti = proto_tree_add_item(tlv_tree, hf_bgp_ls_tlv_app_spec_link_attrs_reserved, tvb, offset + 6, 2, ENC_BIG_ENDIAN);
            if (tmp16 != 0) {
                expert_add_info_format(pinfo, ti, &ei_bgp_ls_warn,
                                       "Reserved field must be 0 in BGP-LS Application-Specific Link Attributes TLV");
            }
            if (sabm_len > 0) {
                static int * const app_spec_link_attrs_sabm[] = {
                    &hf_bgp_ls_tlv_app_spec_link_attrs_sabm_r,
                    &hf_bgp_ls_tlv_app_spec_link_attrs_sabm_s,
                    &hf_bgp_ls_tlv_app_spec_link_attrs_sabm_f,
                    &hf_bgp_ls_tlv_app_spec_link_attrs_sabm_x,
                    NULL
                };
                proto_tree_add_bitmask(tlv_tree, tvb, offset + 8, hf_bgp_ls_tlv_app_spec_link_attrs_sabm,
                                       ett_bgp_link_state, app_spec_link_attrs_sabm, ENC_BIG_ENDIAN);
            }
            if (udabm_len > 0) {
                proto_tree_add_item(tlv_tree, hf_bgp_ls_tlv_app_spec_link_attrs_udabm,
                                    tvb, offset + 8 + sabm_len, udabm_len, ENC_NA);
            }
            /* Decode Link Attribute sub-TLVs */
            local_offset = offset + 8 + sabm_len + udabm_len;
            while (local_offset < offset + length) {
                advance = decode_link_state_attribute_tlv(tlv_tree, tvb, local_offset, pinfo, protocol_id);
                if (advance < 0) {
                    break;
                }
                local_offset += advance;
            }
            break;

        /* Prefix Attribute TLVs */
        case BGP_NLRI_TLV_IGP_FLAGS:
            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_tlv_igp_flags, tvb, offset, length+4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
            if(length != BGP_NLRI_TLV_LEN_IGP_FLAGS){
                expert_add_info_format(pinfo, tlv_tree, &ei_bgp_ls_error, "Unexpected IGP Flags TLV's length (%u), it must be %u bytes!",
                                       length, BGP_NLRI_TLV_IGP_FLAGS);
                break;
            }
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_igp_flags_flag_d, tvb, offset + 4, 1, ENC_NA);
            tmp8 = tvb_get_guint8(tvb, offset + 4) & 0x7F;
            if(tmp8){
                expert_add_info_format(pinfo, tlv_tree, &ei_bgp_ls_error, "Reserved flags are not set to zero (%u).", tmp8);
            }
            break;

        case BGP_NLRI_TLV_ROUTE_TAG:
            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_tlv_route_tag, tvb, offset, length+4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
            if(length % 4 != 0) {
                expert_add_info_format(pinfo, tlv_tree, &ei_bgp_ls_error, "Unexpected Route Tag TLV's length (%u mod 4 != 0) ",
                                       length);
                break;
            }
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            tmp16 = length;
            n = 0;
            while(tmp16){
                if(tmp16 < 4) {
                    expert_add_info_format(pinfo, tlv_tree, &ei_bgp_ls_error, "Route Tag must be 4 bytes long (%u).", tmp16);
                    break;
                }
                proto_tree_add_item(tlv_tree, hf_bgp_ls_tlv_route_tag_value, tvb, offset + 4 + (n * 4), 4, ENC_BIG_ENDIAN);
                tmp16 -= 4;
                n++;
            }
            break;

        case BGP_NLRI_TLV_EXTENDED_TAG:
            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_tlv_route_extended_tag, tvb, offset, length+4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
            if(length % 8 != 0) {
                expert_add_info_format(pinfo, tlv_tree, &ei_bgp_ls_error, "Unexpected Route Extended Tag TLV's length (%u mod 8 != 0) ",
                                       length);
                break;
            }
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            tmp16 = length;
            n = 0;
            while(tmp16){
                if(tmp16 < 8) {
                    expert_add_info_format(pinfo, tlv_tree, &ei_bgp_ls_error, "Route Extended Tag must be 8 bytes long (%u).", tmp16);
                    break;
                }
                proto_tree_add_item(tlv_tree, hf_bgp_ls_tlv_route_extended_tag_value, tvb, offset + 4 + (n * 8), 8, ENC_BIG_ENDIAN);
                tmp16 -= 8;
                n++;
            }
            break;

        case BGP_NLRI_TLV_PREFIX_METRIC:
            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_tlv_prefix_metric, tvb, offset, length+4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
            if(length != BGP_NLRI_TLV_LEN_PREFIX_METRIC){
                expert_add_info_format(pinfo, tlv_tree, &ei_bgp_ls_error, "Unexpected Prefix Metric TLV's length (%u), it must be %u bytes!",
                                       length, BGP_NLRI_TLV_LEN_PREFIX_METRIC);
                break;
            }
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_tlv_prefix_metric_value, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
            break;

        case BGP_NLRI_TLV_OSPF_FORWARDING_ADDRESS:
            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_ospf_forwarding_address, tvb, offset, length+4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            if (length == 4) {
                proto_tree_add_item(tlv_tree, hf_bgp_ls_ospf_forwarding_address_ipv4_address, tvb, offset + 4, length, ENC_BIG_ENDIAN);
            }
            else if (length == 16) {
                proto_tree_add_item(tlv_tree, hf_bgp_ls_ospf_forwarding_address_ipv6_address, tvb, offset + 4, length,  ENC_NA);
            }
            else {
                expert_add_info_format(pinfo, tlv_tree, &ei_bgp_ls_error, "Unexpected Prefix Metric TLV's length (%u), it must be 4 or 16 bytes!", length);
                break;
            }
            break;

        case BGP_NLRI_TLV_OPAQUE_PREFIX_ATTRIBUTE:
            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_opaque_prefix_attribute, tvb, offset, length+4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_opaque_prefix_attribute_value, tvb, offset + 4, length, ENC_NA);
            break;

        case BGP_NLRI_TLV_EXTENDED_ADMINISTRATIVE_GROUP:
            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_extended_administrative_group, tvb, offset, length+4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            if(length % 4 != 0) {
                expert_add_info_format(pinfo, tlv_tree, &ei_bgp_ls_error, "Unexpected Extended Administrative Group TLV's length (%u mod 4 != 0)",
                                       length);
                break;
            }
            tmp16 = length;
            while(tmp16){
                proto_tree_add_item(tlv_tree, hf_bgp_ls_extended_administrative_group_value, tvb, offset + 4 + (length - tmp16), 4, ENC_NA);
                tmp16 -= 4;
            }
            break;

        case BGP_LS_SR_TLV_PREFIX_SID:
            {
                /*
                   0  1  2  3  4  5  6  7
                  +--+--+--+--+--+--+--+--+
                  |R |N |P |E |V |L |  |  |
                  +--+--+--+--+--+--+--+--+
                */
                static int * const prefix_sid_isis_flags[] = {
                    &hf_bgp_ls_sr_tlv_prefix_sid_flags_r,
                    &hf_bgp_ls_sr_tlv_prefix_sid_flags_n,
                    &hf_bgp_ls_sr_tlv_prefix_sid_flags_p,
                    &hf_bgp_ls_sr_tlv_prefix_sid_flags_e,
                    &hf_bgp_ls_sr_tlv_prefix_sid_flags_v,
                    &hf_bgp_ls_sr_tlv_prefix_sid_flags_l,
                    NULL
                };
                /*
                   0  1  2  3  4  5  6  7
                  +--+--+--+--+--+--+--+--+
                  |  |NP|M |E |V |L |  |  |
                  +--+--+--+--+--+--+--+--+
                */
                static int * const prefix_sid_ospf_flags[] = {
                    &hf_bgp_ls_sr_tlv_prefix_sid_flags_np,
                    &hf_bgp_ls_sr_tlv_prefix_sid_flags_m,
                    &hf_bgp_ls_sr_tlv_prefix_sid_flags_e,
                    &hf_bgp_ls_sr_tlv_prefix_sid_flags_v,
                    &hf_bgp_ls_sr_tlv_prefix_sid_flags_l,
                    NULL
                };

                tlv_item = proto_tree_add_item(tree, hf_bgp_ls_sr_tlv_prefix_sid, tvb, offset, length + 4, ENC_NA);
                tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
                proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
                if (protocol_id == BGP_LS_NLRI_PROTO_ID_OSPF) {
                    proto_tree_add_bitmask(tlv_tree, tvb, offset + 4, hf_bgp_ls_sr_tlv_prefix_sid_flags,
                                           ett_bgp_link_state, prefix_sid_ospf_flags, ENC_BIG_ENDIAN);
                } else {
                    /* FF: most common case is IS-IS, so if it is not OSPF we go that way */
                    proto_tree_add_bitmask(tlv_tree, tvb, offset + 4, hf_bgp_ls_sr_tlv_prefix_sid_flags,
                                           ett_bgp_link_state, prefix_sid_isis_flags, ENC_BIG_ENDIAN);
                }
                proto_tree_add_item(tlv_tree, hf_bgp_ls_sr_tlv_prefix_sid_algo, tvb, offset + 5, 1, ENC_BIG_ENDIAN);
                if (length == 7) {
                    proto_tree_add_item(tlv_tree, hf_bgp_ls_sr_tlv_prefix_sid_label, tvb, offset + 8, 3, ENC_BIG_ENDIAN);
                } else {
                    proto_tree_add_item(tlv_tree, hf_bgp_ls_sr_tlv_prefix_sid_index, tvb, offset + 8, 4, ENC_BIG_ENDIAN);
                }
            }
            break;

        case BGP_LS_SR_TLV_RANGE:
            break;

        case BGP_LS_SR_TLV_BINDING_SID:
            break;

        case BGP_LS_SR_TLV_PREFIX_ATTR_FLAGS:
            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_sr_tlv_prefix_attr_flags, tvb, offset, length+4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            if (protocol_id == BGP_LS_NLRI_PROTO_ID_OSPF) {
                /* rfc7684, rfc9089 */
                static int * const prefix_attr_ospf_flags[] = {
                    &hf_bgp_ls_sr_tlv_prefix_attr_flags_flags_ao,
                    &hf_bgp_ls_sr_tlv_prefix_attr_flags_flags_no,
                    &hf_bgp_ls_sr_tlv_prefix_attr_flags_flags_eo,
                    NULL
                };
                proto_tree_add_bitmask(tlv_tree, tvb, offset + 4, hf_bgp_ls_sr_tlv_prefix_attr_flags_flags,
                                       ett_bgp_link_state, prefix_attr_ospf_flags, ENC_BIG_ENDIAN);
            } else if (protocol_id == BGP_LS_NLRI_PROTO_ID_IS_IS_LEVEL_1 ||
                       protocol_id == BGP_LS_NLRI_PROTO_ID_IS_IS_LEVEL_2) {
                /* rfc7794, rfc9088 */
                static int * const prefix_attr_isis_flags[] = {
                    &hf_bgp_ls_sr_tlv_prefix_attr_flags_flags_xi,
                    &hf_bgp_ls_sr_tlv_prefix_attr_flags_flags_ri,
                    &hf_bgp_ls_sr_tlv_prefix_attr_flags_flags_ni,
                    &hf_bgp_ls_sr_tlv_prefix_attr_flags_flags_ei,
                    NULL
                };
                proto_tree_add_bitmask(tlv_tree, tvb, offset + 4, hf_bgp_ls_sr_tlv_prefix_attr_flags_flags,
                                       ett_bgp_link_state, prefix_attr_isis_flags, ENC_BIG_ENDIAN);
            } else {
                proto_tree_add_item(tlv_tree, hf_bgp_ls_sr_tlv_prefix_attr_flags_flags_unknown,
                                    tvb, offset + 4, tvb_get_guint16(tvb, offset + 2, ENC_BIG_ENDIAN), ENC_NA);
                expert_add_info_format(pinfo, tlv_tree, &ei_bgp_ls_warn,
                                       "Unknown Protocol-ID (%u) for Prefix Attribute Flags TLV",
                                       protocol_id);
            }
            break;

        case BGP_LS_IGP_TE_METRIC_DELAY:
            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_igp_te_metric_delay, tvb, offset, length+4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_bitmask(tlv_tree, tvb, offset + 4, hf_bgp_ls_igp_te_metric_flags,
                                   ett_bgp_link_state, ls_igp_te_metric_flags, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_igp_te_metric_delay_value, tvb, offset + 5, 3, ENC_BIG_ENDIAN);
            break;
        case BGP_LS_IGP_TE_METRIC_DELAY_MIN_MAX:
            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_igp_te_metric_delay_min_max, tvb, offset, length+4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_bitmask(tlv_tree, tvb, offset + 4, hf_bgp_ls_igp_te_metric_flags,
                                   ett_bgp_link_state, ls_igp_te_metric_flags, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_igp_te_metric_delay_min, tvb, offset + 5, 3, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_igp_te_metric_reserved, tvb, offset + 8, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_igp_te_metric_delay_max, tvb, offset + 9, 3, ENC_BIG_ENDIAN);
            break;
        case BGP_LS_IGP_TE_METRIC_DELAY_VARIATION:
            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_igp_te_metric_delay_variation, tvb, offset, length+4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_igp_te_metric_reserved, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_igp_te_metric_delay_variation_value, tvb, offset + 5, 3, ENC_BIG_ENDIAN);
            break;
        case BGP_LS_IGP_TE_METRIC_LOSS:
            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_igp_te_metric_link_loss, tvb, offset, length+4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_bitmask(tlv_tree, tvb, offset + 4, hf_bgp_ls_igp_te_metric_flags,
                                   ett_bgp_link_state, ls_igp_te_metric_flags, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_igp_te_metric_link_loss_value, tvb, offset + 5, 3, ENC_BIG_ENDIAN);
            break;
        case BGP_LS_IGP_TE_METRIC_BANDWIDTH_RESIDUAL:
            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_igp_te_metric_bandwidth_residual, tvb, offset, length+4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_igp_te_metric_bandwidth_residual_value, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
            break;
        case BGP_LS_IGP_TE_METRIC_BANDWIDTH_AVAILABLE:
            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_igp_te_metric_bandwidth_available, tvb, offset, length+4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_igp_te_metric_bandwidth_available_value, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
            break;
        case BGP_LS_IGP_TE_METRIC_BANDWIDTH_UTILIZED:
            tlv_item = proto_tree_add_item(tree, hf_bgp_ls_igp_te_metric_bandwidth_utilized, tvb, offset, length+4, ENC_NA);
            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_link_state);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_bgp_ls_igp_te_metric_bandwidth_utilized_value, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
            break;

        default:
            expert_add_info_format(pinfo, tree, &ei_bgp_ls_warn,
                "Unknown BGP-LS Attribute TLV Code (%u)!", type);
            break;
    }
    return length + 4;
}

static int decode_evpn_nlri_esi(proto_tree *tree, tvbuff_t *tvb, gint offset, packet_info *pinfo) {
    guint8 esi_type = 0;
    proto_tree *esi_tree;
    proto_item *ti;

    ti = proto_tree_add_item(tree, hf_bgp_evpn_nlri_esi, tvb, offset, 10, ENC_NA);
    esi_tree = proto_item_add_subtree(ti, ett_bgp_evpn_nlri_esi);
    proto_tree_add_item(esi_tree, hf_bgp_evpn_nlri_esi_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    esi_type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(esi_tree, hf_bgp_evpn_nlri_esi_value, tvb, offset+1, 9, ENC_NA);
    switch (esi_type) {
        case BGP_NLRI_EVPN_ESI_VALUE :
            proto_tree_add_item(esi_tree, hf_bgp_evpn_nlri_esi_value_type0, tvb,
                                offset+1, 9, ENC_NA);
            break;
        case BGP_NLRI_EVPN_ESI_LACP :
            proto_tree_add_item(esi_tree, hf_bgp_evpn_nlri_esi_lacp_mac, tvb,
                                offset+1, 6, ENC_NA);
            proto_tree_add_item(esi_tree, hf_bgp_evpn_nlri_esi_portk, tvb,
                                offset+7, 2, ENC_NA);
            proto_tree_add_item(esi_tree, hf_bgp_evpn_nlri_esi_remain, tvb,
                                offset+9, 1, ENC_NA);
            break;
        case BGP_NLRI_EVPN_ESI_MSTP :
            proto_tree_add_item(esi_tree, hf_bgp_evpn_nlri_esi_rb_mac, tvb,
                                offset+1, 6, ENC_NA);
            proto_tree_add_item(esi_tree, hf_bgp_evpn_nlri_esi_rbprio, tvb,
                                offset+7, 2, ENC_NA);
            proto_tree_add_item(esi_tree, hf_bgp_evpn_nlri_esi_remain, tvb,
                                offset+9, 1, ENC_NA);
            break;
        case BGP_NLRI_EVPN_ESI_MAC :
            proto_tree_add_item(esi_tree, hf_bgp_evpn_nlri_esi_sys_mac, tvb,
                                offset+1, 6, ENC_NA);
            proto_tree_add_item(esi_tree, hf_bgp_evpn_nlri_esi_mac_discr, tvb,
                                offset+7, 2, ENC_NA);
            proto_tree_add_item(esi_tree, hf_bgp_evpn_nlri_esi_remain, tvb,
                                offset+9, 1, ENC_NA);
            break;
        case BGP_NLRI_EVPN_ESI_RID :
            proto_tree_add_item(esi_tree, hf_bgp_evpn_nlri_esi_router_id, tvb,
                                offset+1, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(esi_tree, hf_bgp_evpn_nlri_esi_router_discr, tvb,
                                offset+5, 4, ENC_NA);
            proto_tree_add_item(esi_tree, hf_bgp_evpn_nlri_esi_remain, tvb,
                                offset+9, 1, ENC_NA);
            break;
        case BGP_NLRI_EVPN_ESI_ASN :
            proto_tree_add_item(esi_tree, hf_bgp_evpn_nlri_esi_asn, tvb,
                                offset+1, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(esi_tree, hf_bgp_evpn_nlri_esi_asn_discr, tvb,
                                offset+5, 4, ENC_NA);
            proto_tree_add_item(esi_tree, hf_bgp_evpn_nlri_esi_remain, tvb,
                                offset+9, 1, ENC_NA);
            break;
        case BGP_NLRI_EVPN_ESI_RES :
            proto_tree_add_item(esi_tree, hf_bgp_evpn_nlri_esi_reserved, tvb,
                                offset+1, 9, ENC_NA);
            break;
        default :
            expert_add_info_format(pinfo, tree, &ei_bgp_evpn_nlri_esi_type_err,
                                   "Invalid EVPN ESI (%u)!", esi_type);
            return (-1);
    }
    return(0);
}

/*
 * Decode EVPN NLRI, RFC 7432 section 7.7
 */
static int decode_evpn_nlri(proto_tree *tree, tvbuff_t *tvb, gint offset, packet_info *pinfo) {
    int reader_offset = offset;
    int start_offset = offset+2;
    proto_tree *prefix_tree;
    proto_item *ti;
    guint8 route_type;
    guint8 nlri_len;
    guint8 ip_len;
    guint32 total_length = 0;
    guint32 or_length;
    path_attr_data *data = NULL;
    proto_item *item;
    int ret;

    route_type = tvb_get_guint8(tvb, offset);

    nlri_len = tvb_get_guint8(tvb, offset + 1);

    ti = proto_tree_add_item(tree, hf_bgp_evpn_nlri, tvb, reader_offset,
                               nlri_len+2, ENC_NA);

    prefix_tree = proto_item_add_subtree(ti, ett_bgp_evpn_nlri);

    proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_rt, tvb, reader_offset,
                        1, ENC_BIG_ENDIAN);
    proto_item_append_text(ti, ": %s", val_to_str(tvb_get_guint8(tvb, offset), evpnrtypevals, "Unknown capability %d"));
    /* moving to next field */
    reader_offset++;

    proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_len, tvb, reader_offset,
                        1, ENC_BIG_ENDIAN);
    reader_offset++;

    switch (route_type) {
    case EVPN_AD_ROUTE:
    /*
                +---------------------------------------+
                |      RD   (8 octets)                  |
                +---------------------------------------+
                |Ethernet Segment Identifier (10 octets)|
                +---------------------------------------+
                |  Ethernet Tag ID (4 octets)           |
                +---------------------------------------+
                |  MPLS Label (3 octets)                |
                +---------------------------------------+
   */

        if (nlri_len < 25) {
            expert_add_info_format(pinfo, prefix_tree, &ei_bgp_evpn_nlri_rt_len_err,
                                   "Invalid length (%u) of EVPN NLRI Route Type 1 (Ethernet Auto-discovery Route)", nlri_len);
            return -1;
        }
        item = proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_rd, tvb, reader_offset,
                                   8, ENC_NA);
        proto_item_append_text(item, " (%s)", decode_bgp_rd(pinfo->pool, tvb, reader_offset));
        reader_offset += 8;

        decode_evpn_nlri_esi(prefix_tree, tvb, reader_offset, pinfo);
        reader_offset += 10;
        proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_etag, tvb, reader_offset,
                                   4, ENC_BIG_ENDIAN);
        reader_offset += 4;
        data = load_path_attr_data(pinfo);
        if (data && data->encaps_community_present &&
                (data->encaps_tunnel_type == BGP_EXT_COM_TUNNEL_VXLAN || data->encaps_tunnel_type == BGP_EXT_COM_TUNNEL_VXLANGPE)) {
            proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_vni, tvb, reader_offset, 3, ENC_BIG_ENDIAN);
            reader_offset += 3;
        } else {
            proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_mpls_ls1, tvb, reader_offset, 3, ENC_BIG_ENDIAN);
            reader_offset += 3;
        }
        total_length = reader_offset - offset;
        break;

    case EVPN_MAC_ROUTE:
/*
        +---------------------------------------+
        |      RD   (8 octets)                  |
        +---------------------------------------+
        |Ethernet Segment Identifier (10 octets)|
        +---------------------------------------+
        |  Ethernet Tag ID (4 octets)           |
        +---------------------------------------+
        |  MAC Address Length (1 octet)         |
        +---------------------------------------+
        |  MAC Address (6 octets)               |
        +---------------------------------------+
        |  IP Address Length (1 octet)          |
        +---------------------------------------+
        |  IP Address (0 or 4 or 16 octets)     |
        +---------------------------------------+
        |  MPLS Label1 (3 octets)               |
        +---------------------------------------+
        |  MPLS Label2 (0 or 3 octets)          |
        +---------------------------------------+

*/

        if (nlri_len < 33) {
            expert_add_info_format(pinfo, prefix_tree, &ei_bgp_evpn_nlri_rt_len_err,
                                   "Invalid length (%u) of EVPN NLRI Route Type 2 (MAC/IP Advertisement Route)", nlri_len);
            return -1;
        }
        item = proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_rd, tvb, reader_offset,
                                   8, ENC_NA);
        proto_item_append_text(item, " (%s)", decode_bgp_rd(pinfo->pool, tvb, reader_offset));
        reader_offset += 8;

        decode_evpn_nlri_esi(prefix_tree, tvb, reader_offset, pinfo);
        reader_offset += 10;

        proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_etag, tvb, reader_offset,
                            4, ENC_BIG_ENDIAN);
        reader_offset += 4;

        proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_maclen, tvb, reader_offset,
                            1, ENC_BIG_ENDIAN);
        reader_offset += 1;

        proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_mac_addr, tvb, reader_offset,
                            6, ENC_NA);
        reader_offset += 6;

        ip_len = tvb_get_guint8(tvb, reader_offset) / 8;
        proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_iplen, tvb, reader_offset,
                            1, ENC_BIG_ENDIAN);
        reader_offset++;

        if (ip_len == 4) {
            /*IPv4 address*/
            if (nlri_len < 37) {
                expert_add_info_format(pinfo, prefix_tree, &ei_bgp_evpn_nlri_rt_len_err,
                                       "Invalid length (%u) of EVPN NLRI Route Type 2 (MAC/IP Advertisement Route)", nlri_len);
                return -1;
            }
            proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_ip_addr, tvb, reader_offset,
                                4, ENC_NA);
            reader_offset += 4;
        } else if (ip_len == 16) {
            /*IPv6 address*/
            if (nlri_len < 49) {
                expert_add_info_format(pinfo, prefix_tree, &ei_bgp_evpn_nlri_rt_len_err,
                                       "Invalid length (%u) of EVPN NLRI Route Type 2 (MAC/IP Advertisement Route)", nlri_len);
                return -1;
            }
            proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_ipv6_addr, tvb, reader_offset,
                                16, ENC_NA);
            reader_offset += 16;
        } else if (ip_len == 0) {
            /*IP not included*/
            proto_tree_add_expert(prefix_tree, pinfo, &ei_bgp_evpn_nlri_rt4_no_ip, tvb, reader_offset-1, 1);
        } else {
            return -1;
        }
        data = load_path_attr_data(pinfo);
        if (data && data->encaps_community_present &&
                (data->encaps_tunnel_type == BGP_EXT_COM_TUNNEL_VXLAN || data->encaps_tunnel_type == BGP_EXT_COM_TUNNEL_VXLANGPE)) {
            proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_vni, tvb, reader_offset, 3, ENC_BIG_ENDIAN);
            reader_offset += 3;
            if (reader_offset - start_offset < nlri_len) {
                proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_vni, tvb, reader_offset, 3, ENC_BIG_ENDIAN);
                reader_offset += 3;
            }
        } else {
            proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_mpls_ls1, tvb, reader_offset, 3, ENC_BIG_ENDIAN);
            reader_offset += 3;
            /* we check if we reached the end of the nlri reading fields one by one */
            /* if not, the second optional label is in the payload */
            if (reader_offset - start_offset < nlri_len) {
                proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_mpls_ls2, tvb, reader_offset, 3, ENC_BIG_ENDIAN);
                reader_offset += 3;
            }
        }
        total_length = reader_offset - offset;
        break;

    case EVPN_INC_MCAST_TREE:
/*
        +---------------------------------------+
        |      RD   (8 octets)                  |
        +---------------------------------------+
        |  Ethernet Tag ID (4 octets)           |
        +---------------------------------------+
        |  IP Address Length (1 octet)          |
        +---------------------------------------+
        |   Originating Router's IP Addr        |
        |          (4 or 16 octets)             |
        +---------------------------------------+
*/

        if (nlri_len < 13) {
            expert_add_info_format(pinfo, prefix_tree, &ei_bgp_evpn_nlri_rt_len_err,
                                   "Invalid length (%u) of EVPN NLRI Route Type 3 (Inclusive Multicast Ethernet Tag Route)", nlri_len);
            return -1;
        }
        item = proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_rd, tvb, reader_offset,
                                   8, ENC_NA);
        proto_item_append_text(item, " (%s)", decode_bgp_rd(pinfo->pool, tvb, reader_offset));
        reader_offset += 8;

        proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_etag, tvb, reader_offset,
                            4, ENC_BIG_ENDIAN);
        /* move to next field */
        reader_offset += 4;
        ip_len = tvb_get_guint8(tvb, reader_offset) / 8;
        proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_iplen, tvb, reader_offset,
                            1, ENC_BIG_ENDIAN);
        reader_offset += 1;

        if (ip_len == 4) {
            /*IPv4 address*/
            if (nlri_len < 17) {
                expert_add_info_format(pinfo, prefix_tree, &ei_bgp_evpn_nlri_rt_len_err,
                                       "Invalid length (%u) of EVPN NLRI Route Type 3 (Inclusive Multicast Ethernet Tag Route)", nlri_len);
                return -1;
            }
            proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_ip_addr, tvb, reader_offset,
                                4, ENC_NA);
            reader_offset += 4;
        } else if (ip_len == 16) {
            /*IPv6 address*/
            if (nlri_len < 29) {
                expert_add_info_format(pinfo, prefix_tree, &ei_bgp_evpn_nlri_rt_len_err,
                                       "Invalid length (%u) of EVPN NLRI Route Type 3 (Inclusive Multicast Ethernet Tag Route)", nlri_len);
                return -1;
            }
            proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_ipv6_addr, tvb, reader_offset,
                                16, ENC_NA);
            reader_offset += 16;
        } else if (ip_len == 0) {
            /*IP not included*/
            proto_tree_add_expert(prefix_tree, pinfo, &ei_bgp_evpn_nlri_rt4_no_ip, tvb, reader_offset, 1);
        } else {
            return -1;
        }
        total_length = reader_offset - offset;
        break;

    case EVPN_ETH_SEGMENT_ROUTE:
/*
        +---------------------------------------+
        |      RD   (8 octets)                  |
        +---------------------------------------+
        |Ethernet Segment Identifier (10 octets)|
        +---------------------------------------+
        |  IP Address Length (1 octet)          |
        +---------------------------------------+
        |   Originating Router's IP Addr        |
        |          (4 or 16 octets)             |
        +---------------------------------------+
*/

        if (nlri_len < 19) {
            expert_add_info_format(pinfo, prefix_tree, &ei_bgp_evpn_nlri_rt_len_err,
                                   "Invalid length (%u) of EVPN NLRI Route Type 4 (Ethernet Segment Route)", nlri_len);
            return -1;
        }
        item = proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_rd, tvb, reader_offset,
                                   8, ENC_NA);
        proto_item_append_text(item, " (%s)", decode_bgp_rd(pinfo->pool, tvb, reader_offset));
        reader_offset += 8;

        decode_evpn_nlri_esi(prefix_tree, tvb, reader_offset, pinfo);
        /* move to next field */
        reader_offset += 10;

        ip_len = tvb_get_guint8(tvb, reader_offset) / 8;
        proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_iplen, tvb, reader_offset,
                            1, ENC_BIG_ENDIAN);
        reader_offset++;

        if (ip_len == 4) {
            /*IPv4 address*/
            if (nlri_len < 23) {
                expert_add_info_format(pinfo, prefix_tree, &ei_bgp_evpn_nlri_rt_len_err,
                                       "Invalid length (%u) of EVPN NLRI Route Type 4 (Ethernet Segment Route)", nlri_len);
                return -1;
            }
            proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_ip_addr, tvb, reader_offset,
                                4, ENC_NA);
            reader_offset += 4;
        } else if (ip_len == 16) {
            /*IPv6 address*/
            if (nlri_len < 35) {
                expert_add_info_format(pinfo, prefix_tree, &ei_bgp_evpn_nlri_rt_len_err,
                                       "Invalid length (%u) of EVPN NLRI Route Type 4 (Ethernet Segment Route)", nlri_len);
                return -1;
            }
            proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_ipv6_addr, tvb, reader_offset,
                                16, ENC_NA);
            reader_offset += 16;
        } else if (ip_len == 0) {
            /*IP not included*/
            proto_tree_add_expert(prefix_tree, pinfo, &ei_bgp_evpn_nlri_rt4_no_ip, tvb, reader_offset, 1);
        } else {
            return -1;
        }
        total_length = reader_offset - offset;
        break;
    case EVPN_IP_PREFIX_ROUTE:

/*
    +---------------------------------------+
    |      RD   (8 octets)                  |
    +---------------------------------------+
    |Ethernet Segment Identifier (10 octets)|
    +---------------------------------------+
    |  Ethernet Tag ID (4 octets)           |
    +---------------------------------------+
    |  IP Prefix Length (1 octet)           |
    +---------------------------------------+
    |  IP Prefix (4 or 16 octets)           |
    +---------------------------------------+
    |  GW IP Address (4 or 16 octets)       |
    +---------------------------------------+
    |  MPLS Label (3 octets)                |
    +---------------------------------------+
*/

        if (nlri_len < 26) {
            expert_add_info_format(pinfo, prefix_tree, &ei_bgp_evpn_nlri_rt_len_err,
                                   "Invalid length (%u) of EVPN NLRI Route Type 4 (Ethernet Segment Route)", nlri_len);
            return -1;
        }
        item = proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_rd, tvb, reader_offset,
                                   8, ENC_NA);
        proto_item_append_text(item, " (%s)", decode_bgp_rd(pinfo->pool, tvb, reader_offset));
        reader_offset += 8;

        decode_evpn_nlri_esi(prefix_tree, tvb, reader_offset, pinfo);
        reader_offset += 10;

        proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_etag, tvb, reader_offset,
                            4, ENC_BIG_ENDIAN);
        reader_offset += 4;

        proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_prefix_len, tvb, reader_offset,
                            1, ENC_BIG_ENDIAN);
        reader_offset++;

        switch (nlri_len) {
            case 34 :
                /* IPv4 address */
                proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_ip_addr, tvb, reader_offset,
                                    4, ENC_NA);
                reader_offset += 4;

                proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_ipv4_gtw, tvb, reader_offset,
                                    4, ENC_NA);
                reader_offset += 4;

                data = load_path_attr_data(pinfo);
                if (data && data->encaps_community_present &&
                        (data->encaps_tunnel_type == BGP_EXT_COM_TUNNEL_VXLAN || data->encaps_tunnel_type == BGP_EXT_COM_TUNNEL_VXLANGPE)) {
                    proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_vni, tvb, reader_offset, 3, ENC_BIG_ENDIAN);
                } else {
                    decode_MPLS_stack_tree(tvb, reader_offset, prefix_tree);
                }
                total_length = 36;
                break;
            case 58 :
                /* IPv6 address */
                proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_ipv6_addr, tvb, reader_offset,
                                    16, ENC_NA);
                reader_offset += 16;

                proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_ipv6_gtw, tvb, reader_offset,
                                    16, ENC_NA);
                reader_offset += 16;

                data = load_path_attr_data(pinfo);
                if (data && data->encaps_community_present &&
                        (data->encaps_tunnel_type == BGP_EXT_COM_TUNNEL_VXLAN || data->encaps_tunnel_type == BGP_EXT_COM_TUNNEL_VXLANGPE)) {
                    proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_vni, tvb, reader_offset, 3, ENC_BIG_ENDIAN);
                } else {
                    decode_MPLS_stack_tree(tvb, reader_offset, prefix_tree);
                }
                total_length = 60;
                break;
            default :
                expert_add_info_format(pinfo, prefix_tree, &ei_bgp_evpn_nlri_rt_len_err,
                                       "Invalid length (%u) of EVPN NLRI Route Type 5 (IP Prefix Route)", nlri_len);
                return -1;
        }
        break;

    case EVPN_MC_ETHER_TAG_ROUTE:
    case EVPN_IGMP_JOIN_ROUTE:
    case EVPN_IGMP_LEAVE_ROUTE:
    case EVPN_S_PMSI_A_D_ROUTE:
/*
          +---------------------------------------+
          |  RD (8 octets)                        |
          +---------------------------------------+
          |  Ethernet Tag ID (4 octets)           |
          +---------------------------------------+
          |  Multicast Source Length (1 octet)    |
          +---------------------------------------+
          |  Multicast Source Address (variable)  |
          +---------------------------------------+
          |  Multicast Group Length (1 octet)     |
          +---------------------------------------+
          |  Multicast Group Address (Variable)   |
          +---------------------------------------+
          |  Originator Router Length (1 octet)   |
          +---------------------------------------+
          |  Originator Router Address (variable) |
          +---------------------------------------+
          |  Flags (1 octets) (optional)          |
          +---------------------------------------+

          +--------------------------------------------------+
          |  RD (8 octets)                                   |
          +--------------------------------------------------+
          | Ethernet Segment Identifier (10 octets)          |
          +--------------------------------------------------+
          |  Ethernet Tag ID  (4 octets)                     |
          +--------------------------------------------------+
          |  Multicast Source Length (1 octet)               |
          +--------------------------------------------------+
          |  Multicast Source Address (variable)             |
          +--------------------------------------------------+
          |  Multicast Group Length (1 octet)                |
          +--------------------------------------------------+
          |  Multicast Group Address (Variable)              |
          +--------------------------------------------------+
          |  Originator Router Length (1 octet)              |
          +--------------------------------------------------+
          |  Originator Router Address (variable)            |
          +--------------------------------------------------+
          |  Flags (1 octet)                                 |
          +--------------------------------------------------+
*/

        if (nlri_len < 15) {
            expert_add_info_format(pinfo, prefix_tree, &ei_bgp_evpn_nlri_rt_len_err,
                                   "Invalid length (%u) of EVPN NLRI Route Type %u", nlri_len, route_type);
            return -1;
        }
        item = proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_rd, tvb, reader_offset,
                                   8, ENC_NA);
        proto_item_append_text(item, " (%s)", decode_bgp_rd(pinfo->pool, tvb, reader_offset));
        reader_offset += 8;

        if (route_type == EVPN_IGMP_JOIN_ROUTE || route_type == EVPN_IGMP_LEAVE_ROUTE) {
            decode_evpn_nlri_esi(prefix_tree, tvb, reader_offset, pinfo);
            reader_offset += 10;
        }

        proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_etag, tvb, reader_offset,
                            4, ENC_BIG_ENDIAN);
        reader_offset += 4;

        ret = decode_mcast_vpn_nlri_addresses(prefix_tree, tvb, reader_offset);
        if (ret < 0)
            return -1;

        reader_offset = ret;
        proto_tree_add_item_ret_uint(prefix_tree, hf_bgp_evpn_nlri_igmp_mc_or_length, tvb,
                                     reader_offset, 1, ENC_BIG_ENDIAN, &or_length);
        reader_offset += 1;
        switch(or_length) {
            case 32:
                proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_igmp_mc_or_addr_ipv4, tvb,
                                    reader_offset, 4, ENC_BIG_ENDIAN);
                reader_offset += 4;
                break;
            case 128:
                 proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_igmp_mc_or_addr_ipv6, tvb,
                                     reader_offset, 16, ENC_NA);
                 offset += 16;
                 break;
        }
        if (reader_offset - start_offset < nlri_len) {
            proto_tree_add_bitmask(prefix_tree, tvb, offset, hf_bgp_evpn_nlri_igmp_mc_flags,
                                   ett_bgp_evpn_nlri_mc, evpn_nlri_igmp_mc_flags, ENC_BIG_ENDIAN);
            reader_offset += 1;
        }
        total_length = reader_offset - offset;
        break;

    default:
        expert_add_info_format(pinfo, tree, &ei_bgp_evpn_nlri_rt_type_err,
                               "Invalid EVPN Route Type (%u)", route_type);
        return -1;
    }

    return total_length;
}


/*
 * Decode a multiprotocol prefix
 */
static int
decode_prefix_MP(proto_tree *tree, int hf_path_id, int hf_addr4, int hf_addr6,
                 guint16 afi, guint8 safi, gint tlen, tvbuff_t *tvb, gint offset,
                 const char *tag, packet_info *pinfo)
{
    int                 start_offset = offset;
    proto_item          *ti;
    proto_tree          *prefix_tree;
    proto_item          *nlri_ti;
    proto_tree          *nlri_tree;
    proto_item          *disting_item;
    proto_tree          *disting_tree;

    int                 total_length=0;     /* length of the entire item */
    int                 length;             /* length of the prefix address, in bytes */
    int                 tmp_length;
    guint               plen;               /* length of the prefix address, in bits */
    guint               labnum;             /* number of labels             */
    guint16             tnl_id;             /* Tunnel Identifier */
    ws_in4_addr         ip4addr;            /* IPv4 address                 */
    address addr;
    ws_in6_addr         ip6addr;            /* IPv6 address                 */
    guint16             rd_type;            /* Route Distinguisher type     */
    guint16             nlri_type;          /* NLRI Type                    */
    guint16             tmp16;
    guint32             path_identifier=0;
    gint                end=0;              /* Message End                  */

    wmem_strbuf_t      *stack_strbuf;       /* label stack                  */
    wmem_strbuf_t      *comm_strbuf;

    switch (afi) {

    case AFNUM_INET:
        switch (safi) {

            case SAFNUM_UNICAST:
            case SAFNUM_MULCAST:
            case SAFNUM_UNIMULC:
                /* parse each prefix */

                end = offset + tlen;

                /* Heuristic to detect if IPv4 prefix are using Path Identifiers */
                if( detect_add_path_prefix4(tvb, offset, end) ) {
                    /* IPv4 prefixes with Path Id */
                    total_length = decode_path_prefix4(tree, pinfo, hf_path_id, hf_addr4, tvb, offset, tag);
                } else {
                    total_length = decode_prefix4(tree, pinfo, NULL,hf_addr4, tvb, offset, tag);
                }
                if (total_length < 0)
                    return -1;
                break;

            case SAFNUM_MPLS_LABEL:
                end = offset + tlen;
                /* Heuristic to detect if IPv4 prefix are using Path Identifiers */
                if( detect_add_path_prefix46(tvb, offset, end, 255) ) {
                    /* snarf path identifier */
                    path_identifier = tvb_get_ntohl(tvb, offset);
                    offset += 4;
                    total_length += 4;
                }
                /* snarf length */
                plen =  tvb_get_guint8(tvb, offset);
                stack_strbuf = wmem_strbuf_new_label(pinfo->pool);
                labnum = decode_MPLS_stack(tvb, offset + 1, stack_strbuf);

                offset += (1 + labnum * 3);
                if (plen <= (labnum * 3*8)) {
                    proto_tree_add_expert_format(tree, pinfo, &ei_bgp_prefix_length_invalid, tvb, start_offset, 1,
                                        "%s Labeled IPv4 prefix length %u invalid",
                                        tag, plen);
                    return -1;
                }
                plen -= (labnum * 3*8);
                length = tvb_get_ipv4_addr_with_prefix_len(tvb, offset, &ip4addr, plen);
                if (length < 0) {
                    proto_tree_add_expert_format(tree, pinfo, &ei_bgp_prefix_length_invalid, tvb, start_offset, 1,
                                        "%s Labeled IPv4 prefix length %u invalid",
                                        tag, plen + (labnum * 3*8));
                    return -1;
                }

                set_address(&addr, AT_IPv4, 4, &ip4addr);
                if (total_length > 0) {
                    prefix_tree = proto_tree_add_subtree_format(tree, tvb, start_offset,
                                         (offset + length) - start_offset,
                                         ett_bgp_prefix, NULL,
                                         "Label Stack=%s IPv4=%s/%u PathID %u",
                                         wmem_strbuf_get_str(stack_strbuf),
                                         address_to_str(pinfo->pool, &addr), plen, path_identifier);
                    proto_tree_add_item(prefix_tree, hf_path_id, tvb, start_offset, 4, ENC_BIG_ENDIAN);
                    start_offset += 4;
                } else {
                    prefix_tree = proto_tree_add_subtree_format(tree, tvb, start_offset,
                                        (offset + length) - start_offset,
                                        ett_bgp_prefix, NULL,
                                        "Label Stack=%s IPv4=%s/%u",
                                        wmem_strbuf_get_str(stack_strbuf),
                                        address_to_str(pinfo->pool, &addr), plen);
                }
                proto_tree_add_uint_format(prefix_tree, hf_bgp_prefix_length, tvb, start_offset, 1, plen + labnum * 3 * 8,
                                        "%s Prefix length: %u", tag, plen + labnum * 3 * 8);
                proto_tree_add_string_format(prefix_tree, hf_bgp_label_stack, tvb, start_offset + 1, 3 * labnum, wmem_strbuf_get_str(stack_strbuf),
                                        "%s Label Stack: %s", tag, wmem_strbuf_get_str(stack_strbuf));
                total_length += (1 + labnum*3) + length;
                proto_tree_add_ipv4(prefix_tree, hf_addr4, tvb, offset, length, ip4addr);
                break;
            case SAFNUM_MCAST_VPN:
                total_length = decode_mcast_vpn_nlri(tree, tvb, offset, afi, pinfo);
                if (total_length < 0)
                    return -1;
                break;
            case SAFNUM_MDT:
                total_length = decode_mdt_safi(pinfo, tree, tvb, offset);
                if (total_length < 0)
                    return -1;
                break;
            case SAFNUM_ROUTE_TARGET:
                plen = tvb_get_guint8(tvb, offset);

                if (plen == 0) {
                    proto_tree_add_string(tree, hf_bgp_wildcard_route_target, tvb, offset, 1, tag);
                    total_length = 1;
                    break;
                }

                if ((plen < 32) || (plen > 96)) {
                    proto_tree_add_expert_format(tree, pinfo, &ei_bgp_length_invalid, tvb, offset, 1,
                                        "%s Route target length %u invalid",
                                        tag, plen);
                    return -1;
                }

                length = (plen + 7)/8;
                comm_strbuf = wmem_strbuf_new_label(pinfo->pool);

                switch (tvb_get_ntohs(tvb, offset + 1 + 4)) {
                case BGP_EXT_COM_RT_AS2:
                    wmem_strbuf_append_printf(comm_strbuf, "%u:%u",
                                              tvb_get_ntohs(tvb, offset + 1 + 6),
                                              tvb_get_ntohl(tvb, offset + 1 + 8));
                    break;
                case BGP_EXT_COM_RT_IP4:
                    wmem_strbuf_append_printf(comm_strbuf, "%s:%u",
                                              tvb_ip_to_str(pinfo->pool, tvb, offset + 1 + 6),
                                              tvb_get_ntohs(tvb, offset + 1 + 10));
                    break;
                case BGP_EXT_COM_RT_AS4:
                    wmem_strbuf_append_printf(comm_strbuf, "%u:%u",
                                              tvb_get_ntohl(tvb, 6),
                                              tvb_get_ntohs(tvb, offset + 1 + 10));
                    break;
                default:
                    wmem_strbuf_append_printf(comm_strbuf, "Invalid RT type");
                    break;
                }
                prefix_tree = proto_tree_add_subtree_format(tree, tvb, offset + 1, length,
                                    ett_bgp_prefix, NULL, "%s %u:%s/%u",
                                    tag, tvb_get_ntohl(tvb, offset + 1 + 0),
                                    wmem_strbuf_get_str(comm_strbuf),
                                    plen);
                proto_tree_add_item(prefix_tree, hf_bgp_prefix_length, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(prefix_tree, hf_bgp_originating_as, tvb, offset + 1, 4, ENC_BIG_ENDIAN);
                proto_tree_add_string(prefix_tree, hf_bgp_community_prefix, tvb, offset + 1 + 4, length - 4, wmem_strbuf_get_str(comm_strbuf));
                total_length = 1 + length;
                break;
            case SAFNUM_ENCAPSULATION:
                plen =  tvb_get_guint8(tvb, offset);
                if (plen != 32){
                    proto_tree_add_expert_format(tree, pinfo, &ei_bgp_length_invalid, tvb, offset, 1,
                                        "%s IPv4 address length %u invalid",
                                        tag, plen);
                    return -1;
                }
                offset += 1;

                proto_tree_add_item(tree, hf_bgp_endpoint_address, tvb, offset, 4, ENC_NA);

                total_length = 5; /* length(1 octet) + address(4 octets) */
                break;
            case SAFNUM_TUNNEL:
                plen =  tvb_get_guint8(tvb, offset);
                if (plen <= 16){
                    proto_tree_add_expert_format(tree, pinfo, &ei_bgp_prefix_length_invalid, tvb, start_offset, 1,
                                        "%s Tunnel IPv4 prefix length %u invalid",
                                        tag, plen);
                    return -1;
                }
                tnl_id = tvb_get_ntohs(tvb, offset + 1);
                offset += 3; /* Length + Tunnel Id */
                plen -= 16; /* 2-octet Identifier */
                length = tvb_get_ipv4_addr_with_prefix_len(tvb, offset, &ip4addr, plen);
                if (length < 0) {
                    proto_tree_add_expert_format(tree, pinfo, &ei_bgp_prefix_length_invalid, tvb, start_offset, 1,
                                        "%s Tunnel IPv4 prefix length %u invalid",
                                        tag, plen + 16);
                    return -1;
                }
                set_address(&addr, AT_IPv4, 4, &ip4addr);
                prefix_tree = proto_tree_add_subtree_format(tree, tvb, start_offset,
                                         (offset + length) - start_offset,
                                         ett_bgp_prefix, NULL,
                                         "Tunnel Identifier=0x%x IPv4=%s/%u",
                                         tnl_id, address_to_str(pinfo->pool, &addr), plen);

                proto_tree_add_item(prefix_tree, hf_bgp_prefix_length, tvb, start_offset, 1, ENC_BIG_ENDIAN);

                proto_tree_add_item(prefix_tree, hf_bgp_mp_nlri_tnl_id, tvb,
                                    start_offset + 1, 2, ENC_BIG_ENDIAN);
                proto_tree_add_ipv4(prefix_tree, hf_addr4, tvb, offset, length, ip4addr);
                total_length = 1 + 2 + length; /* length field + Tunnel Id + IPv4 len */
                break;
            case SAFNUM_SR_POLICY:
                total_length = decode_sr_policy_nlri(tree, tvb, offset, afi);
                if (total_length < 0)
                    return -1;
                break;
            case SAFNUM_LAB_VPNUNICAST:
            case SAFNUM_LAB_VPNMULCAST:
            case SAFNUM_LAB_VPNUNIMULC:
                plen =  tvb_get_guint8(tvb, offset);
                stack_strbuf = wmem_strbuf_new_label(pinfo->pool);
                labnum = decode_MPLS_stack(tvb, offset + 1, stack_strbuf);

                offset += (1 + labnum * 3);
                if (plen <= (labnum * 3*8)) {
                    proto_tree_add_expert_format(tree, pinfo, &ei_bgp_prefix_length_invalid, tvb, start_offset, 1,
                                        "%s Labeled VPN IPv4 prefix length %u invalid",
                                        tag, plen);
                    return -1;
                }
                plen -= (labnum * 3*8);

                if (plen < 8*8) {
                    proto_tree_add_expert_format(tree, pinfo, &ei_bgp_prefix_length_invalid, tvb, start_offset, 1,
                                        "%s Labeled VPN IPv4 prefix length %u invalid",
                                        tag, plen + (labnum * 3*8));
                    return -1;
                }
                plen -= 8*8;

                length = tvb_get_ipv4_addr_with_prefix_len(tvb, offset + 8, &ip4addr, plen);
                if (length < 0) {
                proto_tree_add_expert_format(tree, pinfo, &ei_bgp_prefix_length_invalid, tvb, start_offset, 1,
                                             "%s Labeled VPN IPv4 prefix length %u invalid",
                                             tag, plen + (labnum * 3*8) + 8*8);
                     return -1;
                }
                set_address(&addr, AT_IPv4, 4, &ip4addr);
                prefix_tree = proto_tree_add_subtree_format(tree, tvb, start_offset,
                                                 (offset + 8 + length) - start_offset,
                                                 ett_bgp_prefix, NULL, "BGP Prefix");

                proto_tree_add_item(prefix_tree, hf_bgp_prefix_length, tvb, start_offset, 1, ENC_NA);
                proto_tree_add_string(prefix_tree, hf_bgp_label_stack, tvb, start_offset + 1, 3 * labnum, wmem_strbuf_get_str(stack_strbuf));
                proto_tree_add_string(prefix_tree, hf_bgp_rd, tvb, start_offset + 1 + 3 * labnum, 8, decode_bgp_rd(pinfo->pool, tvb, offset));

                proto_tree_add_ipv4(prefix_tree, hf_addr4, tvb, offset + 8, length, ip4addr);

                total_length = (1 + labnum * 3 + 8) + length;
                break;

           case SAFNUM_FSPEC_RULE:
           case SAFNUM_FSPEC_VPN_RULE:
             total_length = decode_flowspec_nlri(tree, tvb, offset, afi, safi, pinfo);
             if(total_length < 0)
               return(-1);
             total_length++;
           break;
           default:
                proto_tree_add_expert_format(tree, pinfo, &ei_bgp_unknown_safi, tvb, start_offset, 0,
                                    "Unknown SAFI (%u) for AFI %u", safi, afi);
                return -1;
        } /* switch (safi) */
        break;

    case AFNUM_INET6:
        switch (safi) {

            case SAFNUM_UNICAST:
            case SAFNUM_MULCAST:
            case SAFNUM_UNIMULC:
                /* parse each prefix */

                end = offset + tlen;

                /* Heuristic to detect if IPv6 prefix are using Path Identifiers */
                if( detect_add_path_prefix6(tvb, offset, end) ) {
                    /* IPv6 prefixes with Path Id */
                    total_length = decode_path_prefix6(tree, pinfo, hf_path_id, hf_addr6, tvb, offset, tag);
                } else {
                    total_length = decode_prefix6(tree, pinfo, hf_addr6, tvb, offset, 0, tag);
                }
                if (total_length < 0)
                    return -1;
                break;

            case SAFNUM_MPLS_LABEL:
                end = offset + tlen;
                /* Heuristic to detect if IPv6 prefix are using Path Identifiers */
                if( detect_add_path_prefix46(tvb, offset, end, 255) ) {
                    /* snarf path identifier */
                    path_identifier = tvb_get_ntohl(tvb, offset);
                    offset += 4;
                    total_length += 4;
                }
                /* snarf length */
                plen =  tvb_get_guint8(tvb, offset);
                stack_strbuf = wmem_strbuf_new_label(pinfo->pool);
                labnum = decode_MPLS_stack(tvb, offset + 1, stack_strbuf);

                offset += (1 + labnum * 3);
                if (plen <= (labnum * 3*8)) {
                    proto_tree_add_expert_format(tree, pinfo, &ei_bgp_prefix_length_invalid, tvb, start_offset, 1,
                                        "%s Labeled IPv6 prefix length %u invalid", tag, plen);
                    return -1;
                }
                plen -= (labnum * 3*8);

                length = tvb_get_ipv6_addr_with_prefix_len(tvb, offset, &ip6addr, plen);
                if (length < 0) {
                    proto_tree_add_expert_format(tree, pinfo, &ei_bgp_prefix_length_invalid, tvb, start_offset, 1,
                                        "%s Labeled IPv6 prefix length %u invalid",
                                        tag, plen  + (labnum * 3*8));
                    return -1;
                }

                set_address(&addr, AT_IPv6, 16, ip6addr.bytes);
                if (total_length > 0) {
                    prefix_tree = proto_tree_add_subtree_format(tree, tvb, start_offset,
                                    (offset + length) - start_offset,
                                    ett_bgp_prefix, NULL,
                                    "Label Stack=%s, IPv6=%s/%u PathId %u",
                                    wmem_strbuf_get_str(stack_strbuf),
                                    address_to_str(pinfo->pool, &addr), plen, path_identifier);
                    proto_tree_add_item(prefix_tree, hf_path_id, tvb, start_offset, 4, ENC_BIG_ENDIAN);
                    start_offset += 4;
                } else {
                    prefix_tree = proto_tree_add_subtree_format(tree, tvb, start_offset,
                                    (offset + length) - start_offset,
                                    ett_bgp_prefix, NULL,
                                    "Label Stack=%s, IPv6=%s/%u",
                                    wmem_strbuf_get_str(stack_strbuf),
                                    address_to_str(pinfo->pool, &addr), plen);
                }
                proto_tree_add_uint_format(prefix_tree, hf_bgp_prefix_length, tvb, start_offset, 1, plen + labnum * 3 * 8,
                                        "%s Prefix length: %u", tag, plen + labnum * 3 * 8);
                proto_tree_add_string_format(prefix_tree, hf_bgp_label_stack, tvb, start_offset + 1, 3 * labnum, wmem_strbuf_get_str(stack_strbuf),
                                        "%s Label Stack: %s", tag, wmem_strbuf_get_str(stack_strbuf));
                total_length += (1 + labnum*3) + length;
                proto_tree_add_ipv6(prefix_tree, hf_addr6, tvb, offset, length, &ip6addr);
                break;
            case SAFNUM_MCAST_VPN:
                total_length = decode_mcast_vpn_nlri(tree, tvb, offset, afi, pinfo);
                if (total_length < 0)
                    return -1;
                break;
            case SAFNUM_ENCAPSULATION:
                plen =  tvb_get_guint8(tvb, offset);
                if (plen != 128){
                    proto_tree_add_expert_format(tree, pinfo, &ei_bgp_length_invalid, tvb, offset, 1,
                                        "%s IPv6 address length %u invalid",
                                        tag, plen);
                    return -1;
                }
                offset += 1;

                proto_tree_add_item(tree, hf_bgp_endpoint_address_ipv6, tvb, offset, 16, ENC_NA);

                total_length = 17; /* length(1 octet) + address(16 octets) */
                break;
            case SAFNUM_TUNNEL:
                plen =  tvb_get_guint8(tvb, offset);
                if (plen <= 16){
                    proto_tree_add_expert_format(tree, pinfo, &ei_bgp_prefix_length_invalid, tvb, start_offset, 1,
                                        "%s Tunnel IPv6 prefix length %u invalid",
                                        tag, plen);
                    return -1;
                }
                tnl_id = tvb_get_ntohs(tvb, offset + 1);
                offset += 3; /* Length + Tunnel Id */
                plen -= 16; /* 2-octet Identifier */
                length = tvb_get_ipv6_addr_with_prefix_len(tvb, offset, &ip6addr, plen);
                if (length < 0) {
                    proto_tree_add_expert_format(tree, pinfo, &ei_bgp_prefix_length_invalid, tvb, start_offset, 1,
                                        "%s Tunnel IPv6 prefix length %u invalid",
                                        tag, plen + 16);
                    return -1;
                }
                set_address(&addr, AT_IPv6, 16, ip6addr.bytes);
                prefix_tree = proto_tree_add_subtree_format(tree, tvb, start_offset,
                                    (offset + length) - start_offset,
                                    ett_bgp_prefix, NULL,
                                    "Tunnel Identifier=0x%x IPv6=%s/%u",
                                    tnl_id, address_to_str(pinfo->pool, &addr), plen);
                proto_tree_add_item(prefix_tree, hf_bgp_prefix_length, tvb, start_offset, 1, ENC_BIG_ENDIAN);

                proto_tree_add_item(prefix_tree, hf_bgp_mp_nlri_tnl_id, tvb,
                                    start_offset + 1, 2, ENC_BIG_ENDIAN);
                proto_tree_add_ipv6(prefix_tree, hf_addr6, tvb, offset, length, &ip6addr);

                total_length = (1 + 2) + length; /* length field + Tunnel Id + IPv4 len */
                break;

            case SAFNUM_SR_POLICY:
                total_length = decode_sr_policy_nlri(tree, tvb, offset, afi);
                if (total_length < 0)
                    return -1;
                break;

            case SAFNUM_LAB_VPNUNICAST:
            case SAFNUM_LAB_VPNMULCAST:
            case SAFNUM_LAB_VPNUNIMULC:
                plen =  tvb_get_guint8(tvb, offset);
                stack_strbuf = wmem_strbuf_new_label(pinfo->pool);
                labnum = decode_MPLS_stack(tvb, offset + 1, stack_strbuf);

                offset += (1 + labnum * 3);
                if (plen <= (labnum * 3*8)) {
                    proto_tree_add_expert_format(tree, pinfo, &ei_bgp_prefix_length_invalid, tvb, start_offset, 1,
                                        "%s Labeled VPN IPv6 prefix length %u invalid", tag, plen);
                    return -1;
                }
                plen -= (labnum * 3*8);

                rd_type = tvb_get_ntohs(tvb,offset);
                if (plen < 8*8) {
                    proto_tree_add_expert_format(tree, pinfo, &ei_bgp_prefix_length_invalid, tvb, start_offset, 1,
                                        "%s Labeled VPN IPv6 prefix length %u invalid",
                                        tag, plen + (labnum * 3*8));
                    return -1;
                }
                plen -= 8*8;

                switch (rd_type) {

                    case FORMAT_AS2_LOC:
                        length = tvb_get_ipv6_addr_with_prefix_len(tvb, offset + 8, &ip6addr, plen);
                        if (length < 0) {
                            proto_tree_add_expert_format(tree, pinfo, &ei_bgp_prefix_length_invalid, tvb, start_offset, 1,
                                                "%s Labeled VPN IPv6 prefix length %u invalid",
                                                tag, plen + (labnum * 3*8) + 8*8);
                            return -1;
                        }

                        /* XXX - break up into multiple fields */
                        set_address(&addr, AT_IPv6, 16, ip6addr.bytes);
                        proto_tree_add_string_format(tree, hf_bgp_label_stack, tvb, start_offset,
                                            (offset + 8 + length) - start_offset,
                                            wmem_strbuf_get_str(stack_strbuf), "Label Stack=%s RD=%u:%u, IPv6=%s/%u",
                                            wmem_strbuf_get_str(stack_strbuf),
                                            tvb_get_ntohs(tvb, offset + 2),
                                            tvb_get_ntohl(tvb, offset + 4),
                                            address_to_str(pinfo->pool, &addr), plen);
                        total_length = (1 + labnum * 3 + 8) + length;
                        break;

                    case FORMAT_IP_LOC:
                        length = tvb_get_ipv6_addr_with_prefix_len(tvb, offset + 8, &ip6addr, plen);
                        if (length < 0) {
                            proto_tree_add_expert_format(tree, pinfo, &ei_bgp_prefix_length_invalid, tvb, start_offset, 1,
                                                "%s Labeled VPN IPv6 prefix length %u invalid",
                                                tag, plen + (labnum * 3*8) + 8*8);
                            return -1;
                        }

                        /* XXX - break up into multiple fields */
                        set_address(&addr, AT_IPv6, 16, &ip6addr);
                        proto_tree_add_string_format(tree, hf_bgp_label_stack, tvb, start_offset,
                                            (offset + 8 + length) - start_offset,
                                            wmem_strbuf_get_str(stack_strbuf), "Label Stack=%s RD=%s:%u, IPv6=%s/%u",
                                            wmem_strbuf_get_str(stack_strbuf),
                                            tvb_ip_to_str(pinfo->pool, tvb, offset + 2),
                                            tvb_get_ntohs(tvb, offset + 6),
                                            address_to_str(pinfo->pool, &addr), plen);
                        total_length = (1 + labnum * 3 + 8) + length;
                        break;

                    case FORMAT_AS4_LOC:
                        length = tvb_get_ipv6_addr_with_prefix_len(tvb, offset + 8, &ip6addr, plen);
                        if (length < 0) {
                            proto_tree_add_expert_format(tree, pinfo, &ei_bgp_prefix_length_invalid, tvb, start_offset, 1,
                                                "%s Labeled VPN IPv6 prefix length %u invalid",
                                                tag, plen + (labnum * 3*8) + 8*8);
                            return -1;
                        }

                        /* XXX - break up into multiple fields */
                        set_address(&addr, AT_IPv6, 16, ip6addr.bytes);
                        proto_tree_add_string_format(tree, hf_bgp_label_stack, tvb, start_offset,
                                            (offset + 8 + length) - start_offset,
                                            "Label Stack=%s RD=%u.%u:%u, IPv6=%s/%u",
                                            wmem_strbuf_get_str(stack_strbuf),
                                            tvb_get_ntohs(tvb, offset + 2),
                                            tvb_get_ntohs(tvb, offset + 4),
                                            tvb_get_ntohs(tvb, offset + 6),
                                            address_to_str(pinfo->pool, &addr), plen);
                        total_length = (1 + labnum * 3 + 8) + length;
                        break;
                    default:
                        proto_tree_add_expert_format(tree, pinfo, &ei_bgp_unknown_label_vpn, tvb, start_offset, 0,
                                            "Unknown labeled VPN IPv6 address format %u", rd_type);
                        return -1;
                } /* switch (rd_type) */
                break;
            case SAFNUM_FSPEC_RULE:
            case SAFNUM_FSPEC_VPN_RULE:
                total_length = decode_flowspec_nlri(tree, tvb, offset, afi, safi, pinfo);
                if(total_length < 0)
                    return(-1);
                total_length++;
                break;
            default:
                proto_tree_add_expert_format(tree, pinfo, &ei_bgp_unknown_safi, tvb, start_offset, 0,
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
                proto_tree_add_item(tree, hf_bgp_vplsad_length, tvb, offset, 2, ENC_BIG_ENDIAN);

                proto_tree_add_string(tree, hf_bgp_vplsad_rd, tvb, offset+2, 8, decode_bgp_rd(pinfo->pool, tvb, offset+2));
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
                    proto_tree_add_item(tree, hf_bgp_bgpad_pe_addr, tvb, offset+10, 4, ENC_NA);
                }else{ /* VPLS-BGP */

                    proto_tree_add_item(tree, hf_bgp_vplsbgp_ce_id, tvb, offset+10, 2, ENC_BIG_ENDIAN);

                    proto_tree_add_item(tree, hf_bgp_vplsbgp_labelblock_offset, tvb, offset+12, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tree, hf_bgp_vplsbgp_labelblock_size, tvb, offset+14, 2, ENC_BIG_ENDIAN);
                    stack_strbuf = wmem_strbuf_new_label(pinfo->pool);
                    decode_MPLS_stack(tvb, offset + 16, stack_strbuf);
                    proto_tree_add_string(tree, hf_bgp_vplsbgp_labelblock_base, tvb, offset+16, plen-14, wmem_strbuf_get_str(stack_strbuf));

                }
                /* FIXME there are subTLVs left to decode ... for now lets omit them */
                total_length = plen+2;
                break;

            case SAFNUM_EVPN:
                total_length = decode_evpn_nlri(tree, tvb, offset, pinfo);
                break;

            default:
                proto_tree_add_expert_format(tree, pinfo, &ei_bgp_unknown_safi, tvb, start_offset, 0,
                                    "Unknown SAFI (%u) for AFI %u", safi, afi);
                return -1;
        } /* switch (safi) */
        break;
    case AFNUM_BGP_LS:
        nlri_type = tvb_get_ntohs(tvb, offset);
        total_length = tvb_get_ntohs(tvb, offset + 2);
        length = total_length;
        total_length += 4;

        if (safi == SAFNUM_BGP_LS || safi == SAFNUM_BGP_LS_VPN) {
            ti = proto_tree_add_item(tree, hf_bgp_ls_nlri, tvb, offset, total_length , ENC_NA);
        } else if (safi == SAFNUM_LAB_VPNUNICAST) {
            ti = proto_tree_add_item(tree, hf_bgp_ls_safi128_nlri, tvb, offset, total_length , ENC_NA);
        } else
            return -1;

        prefix_tree = proto_item_add_subtree(ti, ett_bgp_mp_reach_nlri);
        proto_tree_add_item(prefix_tree, hf_bgp_ls_nlri_type, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(prefix_tree, hf_bgp_ls_nlri_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
        offset += 4;

        /* when SAFI 128, then write route distinguisher */
        if (safi == SAFNUM_LAB_VPNUNICAST) {
            if (length < BGP_ROUTE_DISTINGUISHER_SIZE) {
                if (length == 0) {
                    expert_add_info_format(pinfo, prefix_tree, &ei_bgp_ls_error,
                                           "Unexpected end of SAFI 128 NLRI, Route Distinguisher field is required!");
                }
                if (length > 0) {
                    expert_add_info_format(pinfo, prefix_tree, &ei_bgp_ls_error,
                                           "Unexpected Route Distinguisher length (%u)!",
                                           length);
                }
                break;
            }
            disting_item = proto_tree_add_item(prefix_tree, hf_bgp_ls_safi128_nlri_route_distinguisher,
                                               tvb, offset, BGP_ROUTE_DISTINGUISHER_SIZE, ENC_NA);
            disting_tree = proto_item_add_subtree(disting_item, ett_bgp_mp_reach_nlri);
            tmp16 = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(disting_tree, hf_bgp_ls_safi128_nlri_route_distinguisher_type,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
            /* Route Distinguisher Type */
            switch (tmp16) {
            case 0:
                proto_tree_add_item(disting_tree, hf_bgp_ls_safi128_nlri_route_dist_admin_asnum_2,
                                    tvb, offset + 2, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(disting_tree, hf_bgp_ls_safi128_nlri_route_dist_asnum_4,
                                    tvb, offset + 4, 4, ENC_BIG_ENDIAN);
                break;

            case 1:
                proto_tree_add_item(disting_tree, hf_bgp_ls_safi128_nlri_route_dist_admin_ipv4,
                                    tvb, offset + 2, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(disting_tree, hf_bgp_ls_safi128_nlri_route_dist_asnum_2,
                                    tvb, offset + 6, 2, ENC_BIG_ENDIAN);
                break;

            case 2:
                proto_tree_add_item(disting_tree, hf_bgp_ls_safi128_nlri_route_dist_admin_asnum_4,
                                    tvb, offset + 2, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(disting_tree, hf_bgp_ls_safi128_nlri_route_dist_asnum_2,
                                    tvb, offset + 6, 2, ENC_BIG_ENDIAN);
                break;

            default:
                expert_add_info_format(pinfo, disting_tree, &ei_bgp_ls_error,
                                       "Unknown Route Distinguisher type (%u)", tmp16);
            }
            offset += BGP_ROUTE_DISTINGUISHER_SIZE;
            length -= BGP_ROUTE_DISTINGUISHER_SIZE;
        }

        switch (nlri_type) {
        case LINK_STATE_LINK_NLRI:

            nlri_ti = proto_tree_add_item(prefix_tree,
                    hf_bgp_ls_nlri_link_nlri_type, tvb, offset, length,
                    ENC_NA);
            nlri_tree = proto_item_add_subtree(nlri_ti, ett_bgp_mp_reach_nlri);
            tmp_length = decode_bgp_link_node_nlri_common_fields(tvb, nlri_tree,
                    offset, pinfo, length);
            if (tmp_length < 1)
                return -1;

            offset += tmp_length;
            length -= tmp_length;

            /* dissect Remote Node descriptors TLV */
            if (length > 0 && length < 4) {
                expert_add_info_format(pinfo, nlri_tree, &ei_bgp_ls_error,
                        "Unknown data in Link-State Link NLRI!");
                break;
            }
            if (length < 1)
                break;

           tmp_length = decode_bgp_link_node_nlri_tlvs(tvb, nlri_tree, offset,
                                                       pinfo, BGP_NLRI_TLV_REMOTE_NODE_DESCRIPTORS);
           if (tmp_length < 1)
               return -1;

           offset += tmp_length;
           length -= tmp_length;

           /* dissect Link Descriptor NLRI */
           if (length > 0 && length < 4) {
               expert_add_info_format(pinfo, nlri_tree, &ei_bgp_ls_error,
                       "Unknown data in Link-State Link NLRI, length = %d bytes.", length);
               break;
           }
           if (length < 1)
               break;

           tmp_length = decode_bgp_link_nlri_link_descriptors(tvb, nlri_tree,
                   offset, pinfo, length);
           if (tmp_length < 1)
               return -1;

           break;

       case LINK_STATE_NODE_NLRI:
            nlri_ti = proto_tree_add_item(prefix_tree,
                    hf_bgp_ls_nlri_node_nlri_type, tvb, offset, length,
                    ENC_NA);
            nlri_tree = proto_item_add_subtree(nlri_ti, ett_bgp_mp_reach_nlri);
            tmp_length = decode_bgp_link_node_nlri_common_fields(tvb, nlri_tree,
                    offset, pinfo, length);
            if (tmp_length < 1)
                return -1;

            break;

        case LINK_STATE_IPV4_TOPOLOGY_PREFIX_NLRI:
            nlri_ti = proto_tree_add_item(prefix_tree,
                    hf_bgp_ls_ipv4_topology_prefix_nlri_type, tvb, offset, length,
                    ENC_NA);
            nlri_tree = proto_item_add_subtree(nlri_ti, ett_bgp_mp_reach_nlri);
            tmp_length = decode_bgp_link_node_nlri_common_fields(tvb, nlri_tree,
                                                                 offset, pinfo, length);
            if (tmp_length < 1)
                return -1;

            offset += tmp_length;
            length -= tmp_length;

            /* dissect Prefix Descriptors NLRI */
            if (length > 0 && length < 4) {
                expert_add_info_format(pinfo, nlri_tree, &ei_bgp_ls_error,
                        "Unknown data in Link-State Link NLRI, length = %d bytes.", length);
                break;
            }
            if (length < 1)
                break;

            tmp_length = decode_bgp_link_nlri_prefix_descriptors(tvb, nlri_tree,
                    offset, pinfo, length, IP_PROTO_IPV4);
            if (tmp_length < 1)
                return -1;

            break;

        case LINK_STATE_IPV6_TOPOLOGY_PREFIX_NLRI:
            nlri_ti = proto_tree_add_item(prefix_tree,
                    hf_bgp_ls_ipv6_topology_prefix_nlri_type, tvb, offset, length,
                    ENC_NA);
            nlri_tree = proto_item_add_subtree(nlri_ti, ett_bgp_mp_reach_nlri);
            tmp_length = decode_bgp_link_node_nlri_common_fields(tvb, nlri_tree,
                    offset, pinfo, length);
            if (tmp_length < 1)
                return -1;

            offset += tmp_length;
            length -= tmp_length;

            /* dissect Prefix Descriptors NLRI */
            if (length > 0 && length < 4) {
                expert_add_info_format(pinfo, nlri_tree, &ei_bgp_ls_error,
                        "Unknown data in Link-State Link NLRI!");
                break;
            }
            if (length < 1)
                break;

            tmp_length = decode_bgp_link_nlri_prefix_descriptors(tvb, nlri_tree,
                    offset, pinfo, length, IP_PROTO_IPV6);
            if (tmp_length < 1)
                return -1;

            break;

        default:
            proto_tree_add_expert_format(tree, pinfo,  &ei_bgp_ls_error, tvb, start_offset, 0,
                                         "Unknown Link-State NLRI type (%u)", afi);

        }
        break;

        default:
            proto_tree_add_expert_format(tree, pinfo, &ei_bgp_unknown_afi, tvb, start_offset, 0,
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
                expert_add_info_format(pinfo, ti_len, &ei_bgp_cap_len_bad, "Capability length %u wrong, must be = 0", clen);
                proto_tree_add_item(cap_tree, hf_bgp_cap_unknown, tvb, offset, clen, ENC_NA);
            }
            offset += clen;
            break;
        case BGP_CAPABILITY_MULTIPROTOCOL:
            if (clen != 4) {
                expert_add_info_format(pinfo, ti_len, &ei_bgp_cap_len_bad, "Capability length %u is wrong, must be = 4", clen);
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
                proto_tree_add_item(cap_tree, hf_bgp_cap_mp_safi, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
            }
            break;
        case BGP_CAPABILITY_EXTENDED_NEXT_HOP: {
            int eclen = offset + clen;
                while (offset <= eclen - 6) {
                    /* AFI */
                    proto_tree_add_item(cap_tree, hf_bgp_cap_enh_afi, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;

                    /* SAFI */
                    proto_tree_add_item(cap_tree, hf_bgp_cap_enh_safi, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;

                    /* AFI */
                    proto_tree_add_item(cap_tree, hf_bgp_cap_enh_nhafi, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                }
                if (offset != eclen) {
                    expert_add_info_format(pinfo, ti_len, &ei_bgp_cap_len_bad, "Capability length %u is wrong, must be multiple of 6", clen);
                    proto_tree_add_item(cap_tree, hf_bgp_cap_unknown, tvb, offset, eclen - offset, ENC_NA);
                    offset = eclen;
                }
            }
            break;
        case BGP_CAPABILITY_GRACEFUL_RESTART:
            if ((clen < 6) && (clen != 2)) {
                expert_add_info_format(pinfo, ti_len, &ei_bgp_cap_len_bad, "Capability length %u too short, must be greater than 6", clen);
                proto_tree_add_item(cap_tree, hf_bgp_cap_unknown, tvb, offset, clen, ENC_NA);
                offset += clen;
            }
            else {
                int eclen = offset + clen;

                static int * const timer_flags[] = {
                    &hf_bgp_cap_gr_timers_restart_flag,
                    &hf_bgp_cap_gr_timers_notification_flag,
                    &hf_bgp_cap_gr_timers_restart_time,
                    NULL
                };

                if (clen == 2){
                    expert_add_info(pinfo, ti_len, &ei_bgp_cap_gr_helper_mode_only);
                }

                /* Timers */
                proto_tree_add_bitmask(cap_tree, tvb, offset, hf_bgp_cap_gr_timers, ett_bgp_cap, timer_flags, ENC_BIG_ENDIAN);
                offset += 2;

                /*
                 * what follows is alist of AFI/SAFI/flag triplets
                 * read it until the TLV ends
                 */
                while (offset < eclen) {
                    static int * const flags[] = {
                        &hf_bgp_cap_gr_flag_pfs,
                        NULL
                    };

                    /* AFI */
                    proto_tree_add_item(cap_tree, hf_bgp_cap_gr_afi, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;

                    /* SAFI */
                    proto_tree_add_item(cap_tree, hf_bgp_cap_gr_safi, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;

                    /* Flags */
                    proto_tree_add_bitmask(cap_tree, tvb, offset, hf_bgp_cap_gr_flag, ett_bgp_cap, flags, ENC_BIG_ENDIAN);
                    offset += 1;
                }
            }
            break;
        case BGP_CAPABILITY_4_OCTET_AS_NUMBER:
            if (clen != 4) {
                expert_add_info_format(pinfo, ti_len, &ei_bgp_cap_len_bad, "Capability length %u is wrong, must be = 4", clen);
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
            if (clen % 4 != 0) {
                expert_add_info_format(pinfo, ti_len, &ei_bgp_cap_len_bad, "Capability length %u is wrong, must be multiple of  4", clen);
                proto_tree_add_item(cap_tree, hf_bgp_cap_unknown, tvb, offset, clen, ENC_NA);
                offset += clen;
            }
            else { /* AFI SAFI Send-receive*/
                int eclen = offset + clen;

                while (offset < eclen){
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
            }
            break;

        case BGP_CAPABILITY_FQDN:{
            guint8 hostname_len, domain_name_len;

            proto_tree_add_item(cap_tree, hf_bgp_cap_fqdn_hostname_len, tvb, offset, 1, ENC_NA);
            hostname_len = tvb_get_guint8(tvb, offset);
            offset += 1;

            proto_tree_add_item(cap_tree, hf_bgp_cap_fqdn_hostname, tvb, offset, hostname_len, ENC_ASCII);
            offset += hostname_len;

            proto_tree_add_item(cap_tree, hf_bgp_cap_fqdn_domain_name_len, tvb, offset, 1, ENC_NA);
            domain_name_len = tvb_get_guint8(tvb, offset);
            offset += 1;

            proto_tree_add_item(cap_tree, hf_bgp_cap_fqdn_domain_name, tvb, offset, domain_name_len, ENC_ASCII);
            offset += domain_name_len;

            }
            break;

        case BGP_CAPABILITY_ENHANCED_ROUTE_REFRESH:
        case BGP_CAPABILITY_ROUTE_REFRESH_CISCO:
        case BGP_CAPABILITY_ROUTE_REFRESH:
        case BGP_CAPABILITY_CP_ORF:
            if (clen != 0) {
                expert_add_info_format(pinfo, ti_len, &ei_bgp_cap_len_bad, "Capability length %u wrong, must be = 0", clen);
                proto_tree_add_item(cap_tree, hf_bgp_cap_unknown, tvb, offset, clen, ENC_NA);
            }
            offset += clen;
            break;
        case BGP_CAPABILITY_ORF_CISCO:
        case BGP_CAPABILITY_COOPERATIVE_ROUTE_FILTERING:
            if (clen < 6) {
                expert_add_info_format(pinfo, ti_len, &ei_bgp_cap_len_bad, "Capability length %u too short, must be greater than 6", clen);
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
        case BGP_CAPABILITY_MULTISESSION_CISCO:
            if (clen < 1) {
                expert_add_info_format(pinfo, ti_len, &ei_bgp_cap_len_bad, "Capability length %u too short, must be greater than 1", clen);
                proto_tree_add_item(cap_tree, hf_bgp_cap_unknown, tvb, offset, clen, ENC_NA);
                offset += clen;
            }
            else {
                proto_tree_add_item(cap_tree, hf_bgp_cap_multisession_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
            }

            break;
        case BGP_CAPABILITY_BGPSEC:
            if (clen != 3) {
                expert_add_info_format(pinfo, ti_len, &ei_bgp_cap_len_bad, "Capability length %u is wrong, must be = 3", clen);
                proto_tree_add_item(cap_tree, hf_bgp_cap_unknown, tvb, offset, clen, ENC_NA);
                offset += clen;
            }
            else {
                static int * const bgpsec_flags[] = {
                    &hf_bgp_cap_bgpsec_version,
                    &hf_bgp_cap_bgpsec_sendreceive,
                    &hf_bgp_cap_bgpsec_reserved,
                    NULL
                };

                /* BGPsec Flags */
                proto_tree_add_bitmask(cap_tree, tvb, offset, hf_bgp_cap_bgpsec_flags, ett_bgp_cap, bgpsec_flags, ENC_BIG_ENDIAN);
                offset += 1;

                /* BGPsec AFI */
                proto_tree_add_item(cap_tree, hf_bgp_cap_bgpsec_afi, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
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

static void
dissect_bgp_open(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo)
{
    guint8          optlen;    /* Option Length */
    int             ptype;     /* parameter type        */
    int             plen;      /* parameter length      */
    int             cend;      /* capabilities end      */
    int             oend;      /* options end           */
    int             offset;    /* tvb offset counter    */
    guint32         as_num;    /* AS Number             */
    proto_item      *ti;       /* tree item             */
    proto_tree      *opt_tree;  /* subtree for options   */
    proto_tree      *par_tree;  /* subtree for par options   */

    offset = BGP_MARKER_SIZE + 2 + 1;

    proto_tree_add_item(tree, hf_bgp_open_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    ti = proto_tree_add_item_ret_uint(tree, hf_bgp_open_myas, tvb, offset, 2, ENC_BIG_ENDIAN, &as_num);
    if (as_num == BGP_AS_TRANS) {
        proto_item_append_text(ti, " (AS_TRANS)");
    }
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
 * Heuristic for auto-detection of ASN length 2 or 4 bytes
 */

static guint8
heuristic_as2_or_4_from_as_path(tvbuff_t *tvb, gint as_path_offset, gint end_attr_offset, guint8 bgpa_type, gint *number_as_segment)
{
    gint counter_as_segment=0;
    gint offset_check=0;
    guint8 assumed_as_len=0;
    gint asn_is_null=0;
    gint j=0;
    gint k=0;
    gint k_save=0;
    guint8 next_type=0;
    guint8 length=0;
    /* Heuristic is done in two phases
     * First we try to identify the as length (2 or 4 bytes)
     * then we do check that our assumption is ok
     * recalculating the offset and checking we end up with the right result
    * k is used to navigate into the AS_PATH */
    k = as_path_offset;
    /* case of AS_PATH type being explicitly 4 bytes ASN */
    if (bgpa_type == BGPTYPE_AS4_PATH) {
        /* We calculate numbers of segments and return the as length */
        assumed_as_len = 4;
        while (k < end_attr_offset)
        {
            /* we skip segment type and point to length */
            k++;
            length = tvb_get_guint8(tvb, k);
            /* length read let's move to first ASN */
            k++;
            /* we move to the next segment */
            k = k + (length*assumed_as_len);
            counter_as_segment++;
        }
        *number_as_segment = counter_as_segment;
        return(4);
    }
    /* case of user specified ASN length */
    if (bgp_asn_len != 0) {
        /* We calculate numbers of segments and return the as length */
        assumed_as_len = bgp_asn_len;
        while (k < end_attr_offset)
        {
            /* we skip segment type and point to length */
            k++;
            length = tvb_get_guint8(tvb, k);
            /* length read let's move to first ASN */
            k++;
            /* we move to the next segment */
            k = k + (length*assumed_as_len);
            /* if I am not facing the last segment k need to point to next length */
            counter_as_segment++;
        }
        *number_as_segment = counter_as_segment;
        return(bgp_asn_len);
    }
    /* case of a empty path attribute */
    if (as_path_offset == end_attr_offset)
    {
        *number_as_segment = 0;
        return(bgp_asn_len);
    }
    /* case of we run the heuristic to find the as length */
    k_save = k;
    /* we do run the heuristic on first segment and look at next segment if it exists */
    k++;
    length = tvb_get_guint8(tvb, k++);
    /* let's do some checking with an as length 2 bytes */
    offset_check = k + 2*length;
    next_type = tvb_get_guint8(tvb, offset_check);
    /* we do have one segment made of 2 bytes ASN we do reach the end of the attribute taking
     * 2 bytes ASN for our calculation */
    if (offset_check == end_attr_offset)
        assumed_as_len = 2;
    /* else we do check if we see a valid AS segment type after (length * AS 2 bytes) */
    else if (next_type == AS_SET ||
            next_type == AS_SEQUENCE ||
            next_type == AS_CONFED_SEQUENCE ||
            next_type == AS_CONFED_SET) {
        /* that's a good sign to assume ASN 2 bytes let's check that 2 first bytes of each ASN doesn't eq 0 to confirm */
            for (j=0; j < length && !asn_is_null; j++) {
                if(tvb_get_ntohs(tvb, k+(2*j)) == 0) {
                    asn_is_null = 1;
                }
            }
            if (asn_is_null == 0)
                assumed_as_len = 2;
            else
                assumed_as_len = 4;
        }
    else
    /* we didn't find a valid AS segment type in the next coming segment assuming 2 bytes ASN */
        assumed_as_len = 4;
    /* now that we have our assumed as length let's check we can calculate the attribute length properly */
    k = k_save;
    while (k < end_attr_offset)
    {
        /* we skip the AS type */
        k++;
        /* we get the length of the AS segment */
        length = tvb_get_guint8(tvb, k);
        /* let's point to the fist byte of the AS segment */
        k++;
        /* we move to the next segment */
        k = k + (length*assumed_as_len);
        counter_as_segment++;
    }
    if (k == end_attr_offset) {
    /* success */
        *number_as_segment = counter_as_segment;
        return(assumed_as_len);
    } else
    /* we are in trouble */
    return(-1);
}

/*
 * Dissect BGP update extended communities
 */

static int
dissect_bgp_update_ext_com(proto_tree *parent_tree, tvbuff_t *tvb, guint16 tlen, guint tvb_off, packet_info *pinfo)
{
    int             offset=0;
    int             end=0;
    guint8          com_type_high_byte;
    guint8          com_stype_low_byte;
    proto_tree      *communities_tree;
    proto_tree      *community_tree;
    proto_tree      *community_type_tree;
    proto_item      *communities_item=NULL;
    proto_item      *community_item=NULL;
    proto_item      *community_type_item=NULL;
    guint32         encaps_tunnel_type;

    offset = tvb_off ;
    end = tvb_off + tlen ;
    communities_item = proto_tree_add_item(parent_tree, hf_bgp_ext_communities, tvb, offset, tlen, ENC_NA);
    communities_tree = proto_item_add_subtree(communities_item, ett_bgp_extended_communities);
    proto_item_append_text(communities_item, ": (%u communit%s)", tlen/8, plurality(tlen/8, "y", "ies"));
    while (offset < end) {
        com_type_high_byte = tvb_get_guint8(tvb,offset); /* high community type octet */
        com_stype_low_byte = tvb_get_guint8(tvb,offset+1); /* sub type low community type octet */
        community_item = proto_tree_add_item(communities_tree, hf_bgp_ext_community, tvb, offset, 8, ENC_NA);
        community_tree = proto_item_add_subtree(community_item,ett_bgp_extended_community);

        /* Add the Type octet as a decoded item to the community_tree right away,
         * and also dissect its two top bits in a subtree.
         */

        community_type_item = proto_tree_add_item(community_tree, hf_bgp_ext_com_type_high, tvb, offset, 1, ENC_BIG_ENDIAN);
        community_type_tree = proto_item_add_subtree(community_type_item, ett_bgp_ext_com_type);
        proto_tree_add_item(community_type_tree, hf_bgp_ext_com_type_auth, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(community_type_tree, hf_bgp_ext_com_type_tran, tvb, offset, 1, ENC_BIG_ENDIAN);

        /* In the switch(), handlers of individual types and subtypes should
         * add and dissect the remaining 7 octets. Dissectors should use the
         * proto_item_set_text() on the community_item to set the community
         * name in the displayed label as specifically as possible, and
         * proto_item_append_text() to add reasonable details.
         *
         * The intended text label of the community_item for each extended
         * community attribute is:
         *
         * Community Name: Values [General Community Type Name]
         *
         * For example:
         * Route Target: 1:1 [Transitive 2-Octet AS-Specific]
         * Unknown subtype 0x01: 0x8081 0x0000 0x2800 [Non-Transitive Opaque]
         * Unknown type 0x88 subtype 0x00: 0x0000 0x0000 0x0000 [Unknown community]
         *
         * The [] part with general community name is added at the end
         * of the switch().
         *
         * The first option (Route Target) shows a fully recognized and
         * dissected extended community. Note that the line immediately calls
         * the community by its most specific known type (Route Target), while
         * the general type is shown in the brackets. The second option shows a
         * community whose Type is recognized (Non-Transitive Opaque) but whose
         * Subtype is not known. The third option shows an unrecognized
         * extended community.
         *
         * Printing out the community raw value as 3 short ints is intentional:
         * With an unknown community, we cannot assume any particular internal
         * value format, and dumping the value in short ints provides for easy
         * readability.
         */

        switch (com_type_high_byte) {
            case BGP_EXT_COM_TYPE_HIGH_TR_AS2: /* Transitive Two-Octet AS-Specific Extended Community */
                proto_tree_add_item(community_tree, hf_bgp_ext_com_stype_tr_as2, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_value_as2, tvb, offset+2, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_value_an4, tvb, offset+4, 4, ENC_BIG_ENDIAN);

                proto_item_set_text(community_item, "%s: %u:%u",
                        val_to_str(com_stype_low_byte, bgpext_com_stype_tr_as2, "Unknown subtype 0x%02x"),
                        tvb_get_ntohs(tvb,offset+2), tvb_get_ntohl(tvb, offset+4));
                break;

            case BGP_EXT_COM_TYPE_HIGH_NTR_AS2: /* Non-Transitive Two-Octet AS-Specific Extended Community */
                proto_tree_add_item(community_tree, hf_bgp_ext_com_stype_ntr_as2, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_value_as2, tvb, offset+2, 2, ENC_BIG_ENDIAN);

                proto_item_set_text(community_item, "%s:",
                        val_to_str(com_stype_low_byte, bgpext_com_stype_ntr_as2, "Unknown subtype 0x%02x"));

                switch (com_stype_low_byte) {
                    case BGP_EXT_COM_STYPE_AS2_LBW:
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_value_link_bw, tvb, offset+4, 4, ENC_BIG_ENDIAN);

                        proto_item_append_text(community_item, " ASN %u, %.3f Mbps",
                                tvb_get_ntohs(tvb,offset+2),
                                tvb_get_ntohieee_float(tvb,offset+4)*8/1000000);
                        break;

                    default:
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_value_an4, tvb, offset+4, 4, ENC_BIG_ENDIAN);

                        proto_item_append_text(community_item, " %u:%u",
                                tvb_get_ntohs(tvb,offset+2), tvb_get_ntohl(tvb,offset+4));
                    break;
                }
                break;

            case BGP_EXT_COM_TYPE_HIGH_TR_IP4: /* Transitive IPv4-Address-specific Extended Community */
                proto_tree_add_item(community_tree, hf_bgp_ext_com_stype_tr_IP4, tvb, offset+1, 1, ENC_BIG_ENDIAN);

                proto_item_set_text(community_item, "%s: %s:%u",
                        val_to_str(com_stype_low_byte, bgpext_com_stype_tr_IP4, "Unknown subtype 0x%02x"),
                        tvb_ip_to_str(pinfo->pool, tvb, offset+2), tvb_get_ntohs(tvb,offset+6));

                switch(com_stype_low_byte) {
                    case BGP_EXT_COM_STYPE_IP4_OSPF_RID:
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_value_ospf_rid, tvb, offset+2, 4, ENC_BIG_ENDIAN);
                        break;

                    default:
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_value_IP4, tvb, offset+2, 4, ENC_BIG_ENDIAN);
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_value_an2, tvb, offset+6, 2, ENC_BIG_ENDIAN);
                        break;
                }
                break;

            case BGP_EXT_COM_TYPE_HIGH_NTR_IP4: /* Non-Transitive IPv4-Address-specific Extended Community */
                proto_tree_add_item(community_tree, hf_bgp_ext_com_stype_ntr_IP4, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_value_IP4, tvb, offset+2, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_value_an2, tvb, offset+6, 2, ENC_BIG_ENDIAN);

                proto_item_set_text(community_item, "%s: %s:%u",
                        val_to_str(com_stype_low_byte, bgpext_com_stype_ntr_IP4, "Unknown subtype 0x%02x"),
                        tvb_ip_to_str(pinfo->pool, tvb, offset+2), tvb_get_ntohs(tvb,offset+6));
                break;

            case BGP_EXT_COM_TYPE_HIGH_TR_AS4: /* Transitive Four-Octet AS-Specific Extended Community */
                proto_tree_add_item(community_tree, hf_bgp_ext_com_stype_tr_as4, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_value_as4, tvb, offset+2, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_value_an2, tvb, offset+6, 2, ENC_BIG_ENDIAN);

                proto_item_set_text(community_item, "%s: %u.%u(%u):%u",
                        val_to_str(com_stype_low_byte, bgpext_com_stype_tr_as4, "Unknown subtype 0x%02x"),
                        tvb_get_ntohs(tvb,offset+2), tvb_get_ntohs(tvb,offset+4), tvb_get_ntohl(tvb,offset+2),
                        tvb_get_ntohs(tvb,offset+6));
                break;

            case BGP_EXT_COM_TYPE_HIGH_NTR_AS4: /* Non-Transitive Four-Octet AS-Specific Extended Community */
                proto_tree_add_item(community_tree, hf_bgp_ext_com_stype_ntr_as4, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_value_as4, tvb, offset+2, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_value_an2, tvb, offset+6, 2, ENC_BIG_ENDIAN);

                proto_item_set_text(community_item, "%s: %u.%u(%u):%u",
                        val_to_str(com_stype_low_byte, bgpext_com_stype_ntr_as4, "Unknown subtype 0x%02x"),
                        tvb_get_ntohs(tvb,offset+2), tvb_get_ntohs(tvb,offset+4), tvb_get_ntohl(tvb,offset+2),
                        tvb_get_ntohs(tvb,offset+6));
                break;

            case BGP_EXT_COM_TYPE_HIGH_TR_OPAQUE: /* Transitive Opaque Extended Community */
                proto_tree_add_item(community_tree, hf_bgp_ext_com_stype_tr_opaque, tvb, offset+1, 1, ENC_BIG_ENDIAN);

                proto_item_set_text(community_item, "%s:",
                        val_to_str(com_stype_low_byte, bgpext_com_stype_tr_opaque, "Unknown subtype 0x%02x"));

                switch(com_stype_low_byte) {
                    case BGP_EXT_COM_STYPE_OPA_COST:
                        {
                        proto_item *cost_com_item;
                        proto_tree *cost_com_cid_tree;

                        proto_tree_add_item(community_tree, hf_bgp_ext_com_cost_poi, tvb, offset+2, 1, ENC_BIG_ENDIAN);
                        cost_com_item = proto_tree_add_item(community_tree, hf_bgp_ext_com_cost_cid, tvb, offset+3, 1, ENC_BIG_ENDIAN);
                        cost_com_cid_tree = proto_item_add_subtree(cost_com_item, ett_bgp_ext_com_cost_cid);
                        proto_tree_add_item(cost_com_cid_tree, hf_bgp_ext_com_cost_cid_rep, tvb, offset+3, 1, ENC_BIG_ENDIAN);
                        cost_com_item = proto_tree_add_item(community_tree, hf_bgp_ext_com_cost_cost, tvb,
                            offset+4, 4, ENC_BIG_ENDIAN);
                        proto_item_append_text(cost_com_item, " (%s)",
                            tfs_get_string(tvb_get_guint8(tvb, offset+3) & BGP_EXT_COM_COST_CID_REP, &tfs_cost_replace));

                        proto_item_append_text(community_item, " %u, POI: %s (%s)",
                                tvb_get_ntohl(tvb, offset+4),
                                val_to_str(tvb_get_guint8(tvb, offset+2), bgpext_com_cost_poi_type, "Unknown subtype 0x%02x"),
                                (tvb_get_guint8(tvb, offset+3) & BGP_EXT_COM_COST_CID_REP) ? "Replaces attribute value" : "Evaluated after");
                        }
                        break;

                    case BGP_EXT_COM_STYPE_OPA_OSPF_RT:
                        {
                        proto_item *ospf_rt_opt_item;
                        proto_tree *ospf_rt_opt_tree;

                        proto_tree_add_item(community_tree, hf_bgp_ext_com_value_ospf_rt_area, tvb, offset+2, 4, ENC_BIG_ENDIAN);
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_value_ospf_rt_type, tvb, offset+6, 1, ENC_BIG_ENDIAN);
                        ospf_rt_opt_item = proto_tree_add_item(community_tree,
                                hf_bgp_ext_com_value_ospf_rt_options, tvb, offset+7, 1, ENC_BIG_ENDIAN);
                        ospf_rt_opt_tree = proto_item_add_subtree(ospf_rt_opt_item, ett_bgp_ext_com_ospf_rt_opt);
                        proto_tree_add_item(ospf_rt_opt_tree, hf_bgp_ext_com_value_ospf_rt_options_mt,
                                tvb, offset+7, 1, ENC_BIG_ENDIAN);
                        proto_item_append_text(ospf_rt_opt_item, " (Metric: %s)",
                                tfs_get_string(tvb_get_guint8(tvb,offset+7) & BGP_OSPF_RTYPE_METRIC_TYPE, &tfs_ospf_rt_mt));

                        proto_item_append_text(community_item, " Area: %s, Type: %s",
                                tvb_ip_to_str(pinfo->pool, tvb,offset+2),
                                val_to_str_const(tvb_get_guint8(tvb,offset+6), bgpext_com_ospf_rtype, "Unknown"));
                        }
                        break;

                    case BGP_EXT_COM_STYPE_OPA_ENCAP:
                        /* Community octets 2 through 5 are reserved and carry no useful value according to RFC 5512. */
                        proto_tree_add_item_ret_uint(community_tree, hf_bgp_ext_com_tunnel_type, tvb, offset+6, 2, ENC_BIG_ENDIAN, &encaps_tunnel_type);
                        save_path_attr_encaps_tunnel_type(pinfo, encaps_tunnel_type);

                        proto_item_append_text(community_item, " %s",
                                val_to_str_const(tvb_get_ntohs(tvb,offset+6), bgpext_com_tunnel_type, "Unknown"));
                        break;

                    case BGP_EXT_COM_STYPE_OPA_COLOR:
                    case BGP_EXT_COM_STYPE_OPA_DGTW:
                    default:
                        /* The particular Opaque subtype is unknown or the
                         * dissector is not written yet. We will dump the
                         * entire community value in 2-byte short words.
                         */
                        proto_tree_add_uint64_format_value(community_tree, hf_bgp_ext_com_value_raw, tvb, offset+2, 6,
                                tvb_get_ntoh48 (tvb, offset+2), "0x%04x 0x%04x 0x%04x",
                                tvb_get_ntohs(tvb,offset+2),
                                tvb_get_ntohs(tvb,offset+4),
                                tvb_get_ntohs(tvb,offset+6));

                        proto_item_append_text(community_item, " 0x%04x 0x%04x 0x%04x",
                                tvb_get_ntohs(tvb,offset+2), tvb_get_ntohs(tvb,offset+4), tvb_get_ntohs(tvb,offset+6));
                        break;
                }
                break;

            case BGP_EXT_COM_TYPE_HIGH_NTR_OPAQUE: /* Non-Transitive Opaque Extended Community */
                proto_tree_add_item(community_tree, hf_bgp_ext_com_stype_ntr_opaque, tvb, offset+1, 1, ENC_BIG_ENDIAN);

                proto_item_set_text(community_item, "%s:",
                        val_to_str(com_stype_low_byte, bgpext_com_stype_ntr_opaque, "Unknown subtype 0x%02x"));

                switch(com_stype_low_byte) {
                    case BGP_EXT_COM_STYPE_OPA_COST:
                        {
                        proto_item *cost_com_item;
                        proto_tree *cost_com_cid_tree;

                        proto_tree_add_item(community_tree, hf_bgp_ext_com_cost_poi, tvb, offset+2, 1, ENC_BIG_ENDIAN);
                        cost_com_item = proto_tree_add_item(community_tree, hf_bgp_ext_com_cost_cid, tvb, offset+3, 1, ENC_BIG_ENDIAN);
                        cost_com_cid_tree = proto_item_add_subtree(cost_com_item, ett_bgp_ext_com_cost_cid);
                        proto_tree_add_item(cost_com_cid_tree, hf_bgp_ext_com_cost_cid_rep, tvb, offset+3, 1, ENC_BIG_ENDIAN);
                        cost_com_item = proto_tree_add_item(community_tree, hf_bgp_ext_com_cost_cost, tvb,
                            offset+4, 4, ENC_BIG_ENDIAN);
                        proto_item_append_text(cost_com_item, " (%s)",
                            tfs_get_string(tvb_get_guint8(tvb, offset+3) & BGP_EXT_COM_COST_CID_REP, &tfs_cost_replace));

                        proto_item_append_text(community_item, " %u, POI: %s (%s)",
                                tvb_get_ntohl(tvb, offset+4),
                                val_to_str(tvb_get_guint8(tvb, offset+2), bgpext_com_cost_poi_type, "Unknown subtype 0x%02x"),
                                (tvb_get_guint8(tvb, offset+3) & BGP_EXT_COM_COST_CID_REP) ? "Replaces attribute value" : "Evaluated after");
                        }
                        break;

                    default:
                            /* The particular Opaque subtype is unknown or the
                             * dissector is not written yet. We will dump the
                             * entire community value in 2-byte short words.
                             */
                        proto_tree_add_uint64_format_value(community_tree, hf_bgp_ext_com_value_raw, tvb, offset+2, 6,
                                tvb_get_ntoh48 (tvb, offset+2), "0x%04x 0x%04x 0x%04x",
                                tvb_get_ntohs(tvb,offset+2),
                                tvb_get_ntohs(tvb,offset+4),
                                tvb_get_ntohs(tvb,offset+6));

                        proto_item_append_text(community_item, " 0x%04x 0x%04x 0x%04x",
                                tvb_get_ntohs(tvb,offset+2), tvb_get_ntohs(tvb,offset+4), tvb_get_ntohs(tvb,offset+6));
                        break;
                }
                break;

            case BGP_EXT_COM_TYPE_HIGH_TR_QOS: /* QoS Marking [Thomas_Martin_Knoll] */
            case BGP_EXT_COM_TYPE_HIGH_NTR_QOS: /* QoS Marking [Thomas_Martin_Knoll] */
                {
                static int * const qos_flags[] = {
                    &hf_bgp_ext_com_qos_flags_remarking,
                    &hf_bgp_ext_com_qos_flags_ignore_remarking,
                    &hf_bgp_ext_com_qos_flags_agg_marking,
                    NULL
                };

                proto_item_set_text(community_item, "QoS Marking");

                proto_tree_add_bitmask(community_tree, tvb, offset, hf_bgp_ext_com_qos_flags,
                        ett_bgp_ext_com_flags, qos_flags, ENC_BIG_ENDIAN);

                proto_tree_add_item(community_tree, hf_bgp_ext_com_qos_set_number, tvb, offset+2, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_qos_tech_type, tvb, offset+3, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_qos_marking_o, tvb, offset+4, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_qos_marking_a, tvb, offset+6, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_qos_default_to_zero, tvb, offset+7, 1, ENC_BIG_ENDIAN);
                }
                break;

            case BGP_EXT_COM_TYPE_HIGH_TR_COS: /* CoS Capability [Thomas_Martin_Knoll] */
                {
                int i;

                proto_item_set_text(community_item, "CoS Capability");

                for (i=1; i < 8; i++) {
                    static int * const cos_flags[] = {
                        &hf_bgp_ext_com_cos_flags_be,
                        &hf_bgp_ext_com_cos_flags_ef,
                        &hf_bgp_ext_com_cos_flags_af,
                        &hf_bgp_ext_com_cos_flags_le,
                        NULL
                    };

                    proto_tree_add_bitmask(community_tree, tvb, offset+i, hf_bgp_ext_com_cos_flags,
                            ett_bgp_ext_com_flags, cos_flags, ENC_BIG_ENDIAN);
                }
                }
                break;

            case BGP_EXT_COM_TYPE_HIGH_TR_EVPN: /* EVPN (Sub-Types are defined in the "EVPN Extended Community Sub-Types" registry) */
                proto_tree_add_item(community_tree, hf_bgp_ext_com_stype_tr_evpn, tvb, offset+1, 1, ENC_BIG_ENDIAN);

                proto_item_set_text(community_item, "%s:",
                        val_to_str(com_stype_low_byte, bgpext_com_stype_tr_evpn, "Unknown subtype 0x%02x"));

                switch (com_stype_low_byte) {
                    case BGP_EXT_COM_STYPE_EVPN_MMAC:
                        {
                        proto_tree *evpn_mmac_flag_tree;
                        proto_item *evpn_mmac_flag_item;

                        evpn_mmac_flag_item = proto_tree_add_item(community_tree, hf_bgp_ext_com_evpn_mmac_flag, tvb, offset+2, 1, ENC_BIG_ENDIAN);
                        evpn_mmac_flag_tree = proto_item_add_subtree(evpn_mmac_flag_item, ett_bgp_ext_com_evpn_mmac_flags);
                        proto_tree_add_item (evpn_mmac_flag_tree, hf_bgp_ext_com_evpn_mmac_flag_sticky, tvb, offset+2, 1, ENC_BIG_ENDIAN);
                        /* Octet at offset 3 is reserved per RFC 7432 Section 7.7 */
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_evpn_mmac_seq, tvb, offset+4, 4, ENC_BIG_ENDIAN);

                        proto_item_append_text(community_item, " %s MAC",
                          (tvb_get_guint8(tvb,offset+2) & BGP_EXT_COM_EVPN_MMAC_STICKY) ? "Sticky" : "Movable");
                        }
                        break;

                    case BGP_EXT_COM_STYPE_EVPN_LABEL:
                        {
                        proto_item *ti;

                        proto_tree_add_item(community_tree, hf_bgp_ext_com_l2_esi_label_flag, tvb, offset+2, 1, ENC_BIG_ENDIAN);
                        /* Octets at offsets 3 and 4 are reserved perf RFC 7432 Section 7.5 */
                        proto_tree_add_item(community_tree, hf_bgp_update_mpls_label_value, tvb, offset+5, 3, ENC_BIG_ENDIAN);
                        ti = proto_tree_add_item(community_tree, hf_bgp_update_mpls_label_value_20bits, tvb, offset+5, 3, ENC_BIG_ENDIAN);
                        proto_item_set_generated(ti);
                        ti = proto_tree_add_item(community_tree, hf_bgp_update_mpls_traffic_class, tvb, offset+5, 3, ENC_BIG_ENDIAN);
                        proto_item_set_generated(ti);
                        ti = proto_tree_add_item(community_tree, hf_bgp_update_mpls_bottom_stack, tvb, offset+5, 3, ENC_BIG_ENDIAN);
                        proto_item_set_generated(ti);

                        proto_item_append_text(community_item, " %s, Label: %u",
                                tfs_get_string(tvb_get_guint8(tvb, offset+2) & BGP_EXT_COM_ESI_LABEL_FLAGS, &tfs_esi_label_flag),
                                tvb_get_ntoh24(tvb,offset+5) >> 4);
                        }
                        break;

                    case BGP_EXT_COM_STYPE_EVPN_IMP:
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_evpn_esirt, tvb, offset+2, 6, ENC_NA);

                        proto_item_append_text(community_item, " RT: %s", tvb_ether_to_str(pinfo->pool, tvb, offset+2));
                        break;

                    case BGP_EXT_COM_STYPE_EVPN_ROUTERMAC:
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_evpn_routermac, tvb, offset+2, 6, ENC_NA);

                        proto_item_append_text(community_item, " Router's MAC: %s", tvb_ether_to_str(pinfo->pool, tvb, offset+2));
                        break;

                    case BGP_EXT_COM_STYPE_EVPN_L2ATTR:
                        {
                        static int * const l2attr_flags[] = {
                            &hf_bgp_ext_com_evpn_l2attr_flag_reserved,
                            &hf_bgp_ext_com_evpn_l2attr_flag_ci,
                            &hf_bgp_ext_com_evpn_l2attr_flag_f,
                            &hf_bgp_ext_com_evpn_l2attr_flag_c,
                            &hf_bgp_ext_com_evpn_l2attr_flag_p,
                            &hf_bgp_ext_com_evpn_l2attr_flag_b,
                            NULL
                        };

                        proto_tree_add_bitmask(community_tree, tvb, offset+2, hf_bgp_ext_com_evpn_l2attr_flags,
                            ett_bgp_ext_com_evpn_l2attr_flags, l2attr_flags, ENC_BIG_ENDIAN);
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_evpn_l2attr_l2_mtu, tvb, offset+4, 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_evpn_l2attr_reserved, tvb, offset+6, 2, ENC_NA);

                        proto_item_append_text(community_item, " flags: 0x%04x, L2 MTU: %u", tvb_get_ntohs(tvb, offset+2), tvb_get_ntohs(tvb, offset+4));
                        }
                        break;

                    case BGP_EXT_COM_STYPE_EVPN_ETREE:
                        {
                        static int * const etree_flags[] = {
                            &hf_bgp_ext_com_evpn_etree_flag_reserved,
                            &hf_bgp_ext_com_evpn_etree_flag_l,
                            NULL
                        };

                        proto_tree_add_bitmask(community_tree, tvb, offset+2, hf_bgp_ext_com_evpn_etree_flags,
                            ett_bgp_ext_com_evpn_etree_flags, etree_flags, ENC_BIG_ENDIAN);
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_evpn_etree_reserved, tvb, offset+3, 2, ENC_NA);

                        proto_tree_add_item(community_tree, hf_bgp_update_mpls_label_value_20bits, tvb, offset+5, 3, ENC_BIG_ENDIAN);
                        proto_tree_add_item(community_tree, hf_bgp_update_mpls_traffic_class, tvb, offset+5, 3, ENC_BIG_ENDIAN);
                        proto_tree_add_item(community_tree, hf_bgp_update_mpls_bottom_stack, tvb, offset+5, 3, ENC_BIG_ENDIAN);
                        }
                        break;

                    default:
                        /* The particular EVPN subtype is unknown or the
                         * dissector is not written yet. We will dump the
                         * entire community value in 2-byte short words.
                         */
                        proto_tree_add_uint64_format_value(community_tree, hf_bgp_ext_com_value_raw, tvb, offset+2, 6,
                                tvb_get_ntoh48 (tvb, offset+2), "0x%04x 0x%04x 0x%04x",
                                tvb_get_ntohs(tvb,offset+2),
                                tvb_get_ntohs(tvb,offset+4),
                                tvb_get_ntohs(tvb,offset+6));

                        proto_item_append_text(community_item, " 0x%04x 0x%04x 0x%04x",
                                tvb_get_ntohs(tvb,offset+2), tvb_get_ntohs(tvb,offset+4), tvb_get_ntohs(tvb,offset+6));
                        break;
                }
                break;

            case BGP_EXT_COM_TYPE_HIGH_TR_EXP: /* Generic Transitive Experimental Extended Community */
                proto_tree_add_item(community_tree, hf_bgp_ext_com_stype_tr_exp, tvb, offset+1, 1, ENC_BIG_ENDIAN);

                proto_item_set_text(community_item, "%s:",
                        val_to_str(com_stype_low_byte, bgpext_com_stype_tr_exp, "Unknown subtype 0x%02x"));

                switch (com_stype_low_byte) {
                    case BGP_EXT_COM_STYPE_EXP_OSPF_RT:
                        {
                        proto_item *ospf_rt_opt_item;
                        proto_tree *ospf_rt_opt_tree;

                        proto_tree_add_item(community_tree, hf_bgp_ext_com_value_ospf_rt_area, tvb, offset+2, 4, ENC_BIG_ENDIAN);
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_value_ospf_rt_type, tvb, offset+6, 1, ENC_BIG_ENDIAN);
                        ospf_rt_opt_item = proto_tree_add_item(community_tree,
                                hf_bgp_ext_com_value_ospf_rt_options, tvb, offset+7, 1, ENC_BIG_ENDIAN);
                        ospf_rt_opt_tree = proto_item_add_subtree(ospf_rt_opt_item, ett_bgp_ext_com_ospf_rt_opt);
                        proto_tree_add_item(ospf_rt_opt_tree, hf_bgp_ext_com_value_ospf_rt_options_mt,
                                tvb, offset+7, 1, ENC_BIG_ENDIAN);
                        proto_item_append_text(ospf_rt_opt_item, " (Metric: %s)",
                                tfs_get_string(tvb_get_guint8(tvb,offset+7) & BGP_OSPF_RTYPE_METRIC_TYPE, &tfs_ospf_rt_mt));

                        proto_item_append_text(community_item, " Area: %s, Type: %s",
                                tvb_ip_to_str(pinfo->pool, tvb,offset+2),
                                val_to_str_const(tvb_get_guint8(tvb,offset+6), bgpext_com_ospf_rtype, "Unknown"));
                        }
                        break;

                    case BGP_EXT_COM_STYPE_EXP_OSPF_RID:
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_value_ospf_rid, tvb, offset+2, 4, ENC_BIG_ENDIAN);

                        proto_item_append_text(community_item, " %s", tvb_ip_to_str(pinfo->pool, tvb, offset+2));
                        break;

                    case BGP_EXT_COM_STYPE_EXP_OSPF_DID:
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_stype_tr_as2, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_value_as2, tvb, offset+2, 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_value_an4, tvb, offset+4, 4, ENC_BIG_ENDIAN);

                        proto_item_set_text(community_item, "%s: %u:%u",
                                val_to_str(com_stype_low_byte, bgpext_com_stype_tr_exp, "Unknown subtype 0x%02x"),
                                tvb_get_ntohs(tvb,offset+2), tvb_get_ntohl(tvb, offset+4));
                        break;

                    case BGP_EXT_COM_STYPE_EXP_F_TR:  /* Flow spec traffic-rate [RFC5575] */
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_value_as2,
                                tvb, offset+2, 2, ENC_BIG_ENDIAN);
                        /* remaining 4 bytes gives traffic rate in IEEE floating point */
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_flow_rate_float, tvb, offset+4, 4, ENC_BIG_ENDIAN);

                        proto_item_append_text(community_item, " ASN %u, %.3f Mbps",
                                tvb_get_ntohs(tvb,offset+2),
                                tvb_get_ntohieee_float(tvb,offset+4)*8/1000000);
                        break;

                    case BGP_EXT_COM_STYPE_EXP_F_TA:  /* Flow spec traffic-action [RFC5575] */
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_flow_act_allset, tvb, offset+2, 5, ENC_NA);
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_flow_act_samp_act, tvb, offset+7, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_flow_act_term_act, tvb, offset+7, 1, ENC_BIG_ENDIAN);

                        proto_item_append_text(community_item, " Sample: %s, Terminal: %s",
                                tfs_get_string(tvb_get_guint8(tvb,offset+7) & BGP_EXT_COM_FSPEC_ACT_S, &tfs_yes_no),
                                tfs_get_string(tvb_get_guint8(tvb,offset+7) & BGP_EXT_COM_FSPEC_ACT_T, &tfs_yes_no));
                        break;

                    case BGP_EXT_COM_STYPE_EXP_F_RED: /* Flow spec redirect [RFC5575] */
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_value_as2, tvb, offset+2, 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_value_an4, tvb, offset+4, 4, ENC_BIG_ENDIAN);

                        proto_item_append_text(community_item, " RT %u:%u",
                                tvb_get_ntohs(tvb,offset+2), tvb_get_ntohl(tvb,offset+4));
                        break;

                    case BGP_EXT_COM_STYPE_EXP_F_RMARK: /* Flow spec traffic-remarking [RFC5575] */
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_value_fs_remark, tvb, offset+7, 1, ENC_BIG_ENDIAN);

                        proto_item_append_text(community_item, " %s",
                                val_to_str_ext_const(tvb_get_guint8(tvb,offset+7), &dscp_vals_ext, "Unknown DSCP"));
                        break;

                    case BGP_EXT_COM_STYPE_EXP_L2:
                        {
                        static int * const com_l2_flags[] = {
                            &hf_bgp_ext_com_l2_flag_d,
                            &hf_bgp_ext_com_l2_flag_z1,
                            &hf_bgp_ext_com_l2_flag_f,
                            &hf_bgp_ext_com_l2_flag_z345,
                            &hf_bgp_ext_com_l2_flag_c,
                            &hf_bgp_ext_com_l2_flag_s,
                            NULL
                        };

                        proto_tree_add_item(community_tree, hf_bgp_ext_com_l2_encaps,tvb,offset+2, 1, ENC_BIG_ENDIAN);

                        proto_tree_add_bitmask(community_tree, tvb, offset+3, hf_bgp_ext_com_l2_c_flags, ett_bgp_ext_com_l2_flags, com_l2_flags, ENC_BIG_ENDIAN);
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_l2_mtu, tvb, offset+4, 2, ENC_BIG_ENDIAN);
                        }
                        break;

                    case BGP_EXT_COM_STYPE_EXP_ETREE:
                        {
                        static int * const com_etree_flags[] = {
                            &hf_bgp_ext_com_etree_flag_reserved,
                            &hf_bgp_ext_com_etree_flag_p,
                            &hf_bgp_ext_com_etree_flag_v,
                            NULL
                        };

                        proto_tree_add_item(community_tree, hf_bgp_ext_com_etree_root_vlan,tvb,offset+2, 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_etree_leaf_vlan,tvb,offset+4, 2, ENC_BIG_ENDIAN);
                        proto_tree_add_bitmask(community_tree, tvb, offset+6, hf_bgp_ext_com_etree_flags, ett_bgp_ext_com_etree_flags, com_etree_flags, ENC_BIG_ENDIAN);
                        }
                        break;

                    default:
                        /* The particular Experimental subtype is unknown or
                         * the dissector is not written yet. We will dump the
                         * entire community value in 2-byte short words.
                         */
                        proto_tree_add_uint64_format_value(community_tree, hf_bgp_ext_com_value_raw, tvb, offset+2, 6,
                                tvb_get_ntoh48 (tvb, offset+2), "0x%04x 0x%04x 0x%04x",
                                tvb_get_ntohs(tvb,offset+2),
                                tvb_get_ntohs(tvb,offset+4),
                                tvb_get_ntohs(tvb,offset+6));

                        proto_item_append_text(community_item, " 0x%04x 0x%04x 0x%04x",
                                tvb_get_ntohs(tvb,offset+2), tvb_get_ntohs(tvb,offset+4), tvb_get_ntohs(tvb,offset+6));
                        break;
                }
                break;

            case BGP_EXT_COM_TYPE_HIGH_TR_EXP_2:
                proto_tree_add_item(community_tree, hf_bgp_ext_com_stype_tr_exp_2, tvb, offset+1, 1, ENC_BIG_ENDIAN);

                proto_item_set_text(community_item, "%s:",
                        val_to_str(com_stype_low_byte, bgpext_com_stype_tr_exp_2, "Unknown subtype 0x%02x"));

                switch (com_stype_low_byte) {
                    case BGP_EXT_COM_STYPE_EXP_2_FLOW_RED:
                        {
                                proto_tree_add_item(community_tree, hf_bgp_ext_com_value_IP4, tvb, offset+2, 4, ENC_NA);
                                proto_tree_add_item(community_tree, hf_bgp_ext_com_value_an2, tvb, offset+6, 2, ENC_BIG_ENDIAN);
                        }
                        break;

                    default:
                        /* The particular Experimental subtype is unknown or
                         * the dissector is not written yet. We will dump the
                         * entire community value in 2-byte short words.
                         */
                        proto_tree_add_uint64_format_value(community_tree, hf_bgp_ext_com_value_raw, tvb, offset+2, 6,
                                tvb_get_ntoh48 (tvb, offset+2), "0x%04x 0x%04x 0x%04x",
                                tvb_get_ntohs(tvb,offset+2),
                                tvb_get_ntohs(tvb,offset+4),
                                tvb_get_ntohs(tvb,offset+6));

                        proto_item_append_text(community_item, " 0x%04x 0x%04x 0x%04x",
                                tvb_get_ntohs(tvb,offset+2), tvb_get_ntohs(tvb,offset+4), tvb_get_ntohs(tvb,offset+6));
                        break;
                }
                break;

            case BGP_EXT_COM_TYPE_HIGH_TR_EXP_3:
                proto_tree_add_item(community_tree, hf_bgp_ext_com_stype_tr_exp_3, tvb, offset+1, 1, ENC_BIG_ENDIAN);

                proto_item_set_text(community_item, "%s:",
                        val_to_str(com_stype_low_byte, bgpext_com_stype_tr_exp_3, "Unknown subtype 0x%02x"));

                switch (com_stype_low_byte) {
                    case BGP_EXT_COM_STYPE_EXP_3_FLOW_RED:
                        {
                                proto_tree_add_item(community_tree, hf_bgp_ext_com_value_as4, tvb, offset+2, 4, ENC_BIG_ENDIAN);
                                proto_tree_add_item(community_tree, hf_bgp_ext_com_value_an2, tvb, offset+6, 2, ENC_BIG_ENDIAN);
                        }
                        break;

                    default:
                        /* The particular Experimental subtype is unknown or
                         * the dissector is not written yet. We will dump the
                         * entire community value in 2-byte short words.
                         */
                        proto_tree_add_uint64_format_value(community_tree, hf_bgp_ext_com_value_raw, tvb, offset+2, 6,
                                tvb_get_ntoh48 (tvb, offset+2), "0x%04x 0x%04x 0x%04x",
                                tvb_get_ntohs(tvb,offset+2),
                                tvb_get_ntohs(tvb,offset+4),
                                tvb_get_ntohs(tvb,offset+6));

                        proto_item_append_text(community_item, " 0x%04x 0x%04x 0x%04x",
                                tvb_get_ntohs(tvb,offset+2), tvb_get_ntohs(tvb,offset+4), tvb_get_ntohs(tvb,offset+6));
                        break;
                }
                break;

            case BGP_EXT_COM_TYPE_HIGH_TR_EXP_EIGRP:
                proto_tree_add_item(community_tree, hf_bgp_ext_com_stype_tr_exp_eigrp, tvb, offset+1, 1, ENC_BIG_ENDIAN);

                proto_item_set_text(community_item, "%s:",
                        val_to_str(com_stype_low_byte, bgpext_com_stype_tr_eigrp, "Unknown subtype 0x%02x"));

                switch(com_stype_low_byte) {
                    case BGP_EXT_COM_STYPE_EXP_EIGRP_FT:
                        {
                        proto_item *eigrp_flags_item;
                        proto_tree *eigrp_flags_tree;

                        eigrp_flags_item = proto_tree_add_item(community_tree, hf_bgp_ext_com_eigrp_flags, tvb, offset+2, 2, ENC_BIG_ENDIAN);
                        eigrp_flags_tree = proto_item_add_subtree(eigrp_flags_item, ett_bgp_ext_com_eigrp_flags);

                        proto_tree_add_item(eigrp_flags_tree, hf_bgp_ext_com_eigrp_flags_rt, tvb, offset+2, 2, ENC_BIG_ENDIAN);
                        proto_item_append_text(eigrp_flags_tree, " (%s)",
                                tfs_get_string(tvb_get_ntohs(tvb, offset+2) & BGP_EXT_COM_EXP_EIGRP_FLAG_RT, &tfs_eigrp_rtype));
                        proto_item_append_text(community_tree, " %s route",
                                tfs_get_string(tvb_get_ntohs(tvb, offset+2) & BGP_EXT_COM_EXP_EIGRP_FLAG_RT, &tfs_eigrp_rtype));

                        proto_tree_add_item(community_tree, hf_bgp_ext_com_eigrp_rtag, tvb, offset+4, 4, ENC_BIG_ENDIAN);
                        proto_item_append_text(community_tree, ", Tag: %u", tvb_get_ntohl(tvb, offset+4));
                        }
                        break;

                    case BGP_EXT_COM_STYPE_EXP_EIGRP_AD:
                        {
                        guint32 raw_value;

                        proto_tree_add_item(community_tree, hf_bgp_ext_com_eigrp_asn, tvb, offset+2, 2, ENC_BIG_ENDIAN);

                        raw_value = tvb_get_ntohl(tvb, offset+4);
                        proto_tree_add_uint_format_value(community_tree, hf_bgp_ext_com_eigrp_delay,
                                tvb, offset+4, 4, raw_value, "%u (%u usec)", raw_value, raw_value * 10 / 256);

                        proto_item_append_text(community_item, " ASN: %u, D: %u",
                                tvb_get_ntohs(tvb, offset+2), raw_value);
                        }
                        break;

                    case BGP_EXT_COM_STYPE_EXP_EIGRP_RHB:
                        {
                        guint32 raw_value;

                        raw_value = tvb_get_guint8(tvb, offset+2);
                        proto_tree_add_uint_format_value(community_tree, hf_bgp_ext_com_eigrp_rly,
                                tvb, offset+2, 1, raw_value, "%u (%u%%)", raw_value, (raw_value * 100) / 255);
                        proto_item_append_text(community_item, " R: %u", raw_value);

                        proto_tree_add_item(community_tree, hf_bgp_ext_com_eigrp_hops, tvb, offset+3, 1, ENC_BIG_ENDIAN);
                        proto_item_append_text(community_tree, ", H: %u", tvb_get_guint8(tvb, offset+3));

                        raw_value = tvb_get_ntohl(tvb, offset+4);
                        proto_tree_add_uint_format_value(community_tree, hf_bgp_ext_com_eigrp_bw,
                                tvb, offset+4, 4, raw_value, "%u (%u Kbps)", raw_value, raw_value ? (2560000000U / raw_value) : 0);
                        proto_item_append_text(community_tree, ", B: %u", raw_value);
                        }
                        break;

                    case BGP_EXT_COM_STYPE_EXP_EIGRP_LM:
                        {
                        guint32 raw_value;

                        raw_value = tvb_get_guint8(tvb, offset+3);
                        proto_tree_add_uint_format_value(community_tree, hf_bgp_ext_com_eigrp_load,
                                tvb, offset+3, 1, raw_value, "%u (%u%%)", raw_value, (raw_value * 100) / 255);
                        proto_item_append_text(community_tree, " L: %u", raw_value);

                        proto_tree_add_item(community_tree, hf_bgp_ext_com_eigrp_mtu, tvb, offset+4, 4, ENC_BIG_ENDIAN);
                        proto_item_append_text(community_tree, ", M: %u", tvb_get_ntohl(tvb, offset+4));
                        }
                        break;

                    case BGP_EXT_COM_STYPE_EXP_EIGRP_EAR:
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_eigrp_e_asn, tvb, offset+2, 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_eigrp_e_rid, tvb, offset+4, 4, ENC_BIG_ENDIAN);

                        proto_item_append_text(community_tree, " ASN: %u, RID: %s",
                                tvb_get_ntohs(tvb, offset+2), tvb_ip_to_str(pinfo->pool, tvb, offset+4));
                        break;

                    case BGP_EXT_COM_STYPE_EXP_EIGRP_EPM:
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_eigrp_e_pid, tvb, offset+2, 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_eigrp_e_m, tvb, offset+4, 4, ENC_BIG_ENDIAN);

                        proto_item_append_text(community_tree, " %s, Metric: %u",
                          val_to_str(tvb_get_ntohs(tvb, offset+2), eigrp_proto2string, "Unknown protocol %u"),
                          tvb_get_ntohl(tvb, offset+4));
                        break;

                    case BGP_EXT_COM_STYPE_EXP_EIGRP_RID:
                       proto_tree_add_item(community_tree, hf_bgp_ext_com_eigrp_rid, tvb, offset+4, 4, ENC_NA);
                       proto_item_append_text(community_tree, " %s", tvb_ip_to_str(pinfo->pool, tvb, offset+4));
                     break;
                }
                break;

            case BGP_EXT_COM_TYPE_HIGH_TR_FLOW: /* Flow spec redirect/mirror to IP next-hop [draft-simpson-idr-flowspec-redirect] */
            default:
                proto_tree_add_item(community_tree, hf_bgp_ext_com_stype_low_unknown, tvb, offset+1, 1, ENC_BIG_ENDIAN);

                proto_tree_add_uint64_format_value(community_tree, hf_bgp_ext_com_value_raw, tvb, offset+2, 6,
                        tvb_get_ntoh48 (tvb, offset+2), "0x%04x 0x%04x 0x%04x",
                        tvb_get_ntohs(tvb,offset+2),
                        tvb_get_ntohs(tvb,offset+4),
                        tvb_get_ntohs(tvb,offset+6));

                proto_item_set_text(community_item, "Unknown type 0x%02x subtype 0x%02x: 0x%04x 0x%04x 0x%04x",
                        com_type_high_byte, com_stype_low_byte,
                        tvb_get_ntohs(tvb,offset+2), tvb_get_ntohs(tvb,offset+4), tvb_get_ntohs(tvb,offset+6));
                break;
        }
        proto_item_append_text (community_item, " [%s]", val_to_str(com_type_high_byte, bgpext_com_type_high, "Unknown community"));
        offset = offset + 8;
    }
    return(0);
}

static int
dissect_bgp_update_pmsi_attr(packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, guint16 tlen, guint tvb_off)
{
    int             offset=0;
    guint8          tunnel_type=0;
    guint8          opaque_value_type=0;
    guint8          rn_addr_length=0;
    guint16         tunnel_id_len=0;
    guint16         opaque_value_length=0;
    proto_item      *tunnel_id_item=NULL;
    proto_item      *opaque_value_type_item=NULL;
    proto_item      *pmsi_tunnel_type_item=NULL;
    proto_tree      *tunnel_id_tree=NULL;
    path_attr_data  *data = NULL;

    offset = tvb_off ;
    tunnel_id_len = tlen - 5;

    proto_tree_add_item(parent_tree, hf_bgp_pmsi_tunnel_flags, tvb, offset,
                        1, ENC_BIG_ENDIAN);

    pmsi_tunnel_type_item = proto_tree_add_item(parent_tree, hf_bgp_pmsi_tunnel_type, tvb, offset+1,
                                                1, ENC_BIG_ENDIAN);

    data = load_path_attr_data(pinfo);
    if (data && data->encaps_community_present &&
            (data->encaps_tunnel_type == BGP_EXT_COM_TUNNEL_VXLAN || data->encaps_tunnel_type == BGP_EXT_COM_TUNNEL_VXLANGPE)) {
        proto_tree_add_item(parent_tree, hf_bgp_evpn_nlri_vni, tvb, offset+2, 3, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(parent_tree, hf_bgp_update_mpls_label_value_20bits, tvb, offset+2, 3, ENC_BIG_ENDIAN);
    }

    tunnel_id_item = proto_tree_add_item(parent_tree, hf_bgp_pmsi_tunnel_id, tvb, offset+5,
                        tunnel_id_len, ENC_NA);
    tunnel_id_tree = proto_item_add_subtree(tunnel_id_item, ett_bgp_pmsi_tunnel_id);

    tunnel_type = tvb_get_guint8(tvb, offset+1);
    switch(tunnel_type) {
        case PMSI_TUNNEL_NOPRESENT:
            proto_tree_add_item(tunnel_id_tree, hf_bgp_pmsi_tunnel_not_present, tvb, offset+1, 1, ENC_NA);
            break;
        case PMSI_TUNNEL_RSVPTE_P2MP:
            proto_tree_add_item(tunnel_id_tree, hf_bgp_pmsi_tunnel_rsvp_p2mp_id, tvb, offset+5, 4, ENC_NA);
            proto_tree_add_item(tunnel_id_tree, hf_bgp_pmsi_tunnel_rsvp_p2mp_tunnel_id, tvb, offset+11, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tunnel_id_tree, hf_bgp_pmsi_tunnel_rsvp_p2mp_ext_tunnel_idv4, tvb, offset+13, 4, ENC_NA);
            proto_item_append_text(tunnel_id_item, ": Id %u, Ext Id %s",
                                tvb_get_ntohs(tvb, offset+11), tvb_ip_to_str(pinfo->pool, tvb, offset+13));
            break;
        case PMSI_TUNNEL_MLDP_P2MP:
        case PMSI_TUNNEL_MLDP_MP2MP:
            proto_tree_add_item(tunnel_id_tree, hf_bgp_pmsi_tunnel_mldp_fec_el_type, tvb, offset+5, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tunnel_id_tree, hf_bgp_pmsi_tunnel_mldp_fec_el_afi, tvb, offset+6, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tunnel_id_tree, hf_bgp_pmsi_tunnel_mldp_fec_el_adr_len, tvb, offset+8, 1, ENC_BIG_ENDIAN);
            rn_addr_length = tvb_get_guint8(tvb, offset+8);
            if( rn_addr_length ==4)
                proto_tree_add_item(tunnel_id_tree, hf_bgp_pmsi_tunnel_mldp_fec_el_root_nodev4, tvb, offset+9, 4, ENC_NA);
            else
                proto_tree_add_item(tunnel_id_tree, hf_bgp_pmsi_tunnel_mldp_fec_el_root_nodev6, tvb, offset+9, 4, ENC_NA);

            proto_tree_add_item(tunnel_id_tree, hf_bgp_pmsi_tunnel_mldp_fec_el_opa_len, tvb, offset+9+rn_addr_length, 2, ENC_BIG_ENDIAN);
            opaque_value_type_item = proto_tree_add_item(tunnel_id_tree, hf_bgp_pmsi_tunnel_mldp_fec_el_opa_val_type,
                                                         tvb, offset+11+rn_addr_length, 1, ENC_BIG_ENDIAN);
            opaque_value_type = tvb_get_guint8(tvb, offset+11+rn_addr_length);
            if(opaque_value_type == PMSI_MLDP_FEC_TYPE_GEN_LSP) {
                proto_tree_add_item(tunnel_id_tree, hf_bgp_pmsi_tunnel_mldp_fec_el_opa_val_len, tvb, offset+12+rn_addr_length, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tunnel_id_tree, hf_bgp_pmsi_tunnel_mldp_fec_el_opa_value_rn, tvb, offset+14+rn_addr_length, 4, ENC_BIG_ENDIAN);
                proto_item_append_text(tunnel_id_item, ": Type: %s root node: %s Id: %u",
                                       val_to_str_const(tvb_get_guint8(tvb, offset+5), fec_types_vals, "Unknown"),
                                       tvb_ip_to_str(pinfo->pool, tvb, offset+9),
                                       tvb_get_ntohl(tvb, offset+14+rn_addr_length));
            } else if (opaque_value_type == PMSI_MLDP_FEC_TYPE_EXT_TYPE) {
                proto_tree_add_item(tunnel_id_tree, hf_bgp_pmsi_tunnel_mldp_fec_el_opa_val_ext_type, tvb, offset+12+rn_addr_length, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tunnel_id_tree, hf_bgp_pmsi_tunnel_mldp_fec_el_opa_val_ext_len, tvb, offset+14+rn_addr_length, 2, ENC_BIG_ENDIAN);
                opaque_value_length = tvb_get_ntohs(tvb, offset+14+rn_addr_length);
                proto_tree_add_item(tunnel_id_tree, hf_bgp_pmsi_tunnel_mldp_fec_el_opa_value_str, tvb, offset+16+rn_addr_length,
                                    opaque_value_length, ENC_ASCII);
            }
            else {
                /* This covers situation when opaque id is 0 (reserved) or any other value */
                expert_add_info_format(pinfo, opaque_value_type_item, &ei_bgp_attr_pmsi_opaque_type,
                                            "Opaque Value type %u wrong, must be modulo 1 or 255", opaque_value_type);
            }
            break;
        case PMSI_TUNNEL_PIMSSM:
            proto_tree_add_item(tunnel_id_tree, hf_bgp_pmsi_tunnel_pimssm_root_node, tvb, offset+5, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(tunnel_id_tree, hf_bgp_pmsi_tunnel_pimssm_pmc_group, tvb, offset+9, 4, ENC_BIG_ENDIAN);
            proto_item_append_text(tunnel_id_item, ": < %s, %s >",
                                   tvb_ip_to_str(pinfo->pool, tvb, offset+5),
                                   tvb_ip_to_str(pinfo->pool, tvb, offset+9));
            break;
        case PMSI_TUNNEL_PIMSM:
            proto_tree_add_item(tunnel_id_tree, hf_bgp_pmsi_tunnel_pimsm_sender, tvb, offset+5, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(tunnel_id_tree, hf_bgp_pmsi_tunnel_pimsm_pmc_group, tvb, offset+9, 4, ENC_BIG_ENDIAN);
            proto_item_append_text(tunnel_id_item, ": < %s, %s >",
                                   tvb_ip_to_str(pinfo->pool, tvb, offset+5),
                                   tvb_ip_to_str(pinfo->pool, tvb, offset+9));
            break;
        case PMSI_TUNNEL_BIDIR_PIM:
            proto_tree_add_item(tunnel_id_tree, hf_bgp_pmsi_tunnel_pimbidir_sender, tvb, offset+5, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(tunnel_id_tree, hf_bgp_pmsi_tunnel_pimbidir_pmc_group, tvb, offset+9, 4, ENC_BIG_ENDIAN);
            proto_item_append_text(tunnel_id_item, ": < %s, %s >",
                                   tvb_ip_to_str(pinfo->pool, tvb, offset+5),
                                   tvb_ip_to_str(pinfo->pool, tvb, offset+9));
            break;
        case PMSI_TUNNEL_INGRESS:
            proto_tree_add_item(tunnel_id_tree, hf_bgp_pmsi_tunnel_ingress_rep_addr, tvb, offset+5, 4, ENC_BIG_ENDIAN);
            proto_item_append_text(tunnel_id_item, ": tunnel end point -> %s",
                                   tvb_ip_to_str(pinfo->pool, tvb, offset+5));
            break;
        default:
            expert_add_info_format(pinfo, pmsi_tunnel_type_item, &ei_bgp_attr_pmsi_tunnel_type,
                                            "Tunnel type %u wrong", tunnel_type);
            break;
    }


    return(0);
}

/*
 * Dissect BGP path attributes
 *
 */
void
dissect_bgp_path_attr(proto_tree *subtree, tvbuff_t *tvb, guint16 path_attr_len, guint tvb_off, packet_info *pinfo)
{
    guint8        bgpa_flags;                 /* path attributes          */
    guint8        bgpa_type;
    gint          o;                          /* packet offset            */
    gint          q=0;                        /* tmp                      */
    gint          end=0;                      /* message end              */
    int           advance;                    /* tmp                      */
    proto_item    *ti;                        /* tree item                */
    proto_item    *ti_communities;            /* tree communities         */
    proto_item    *ti_community;              /* tree for each community  */
    proto_item    *ti_as;                     /* tree for each as         */
    proto_item    *attr_len_item;
    proto_item    *aigp_type_item;
    proto_tree    *subtree2;                  /* path attribute subtree   */
    proto_tree    *subtree3;                  /* subtree for attributes   */
    proto_tree    *subtree4;                  /* subtree for attributes   */
    proto_tree    *subtree5;                  /* subtree for attributes   */
    proto_tree    *subtree6;                  /* subtree for attributes   */
    proto_tree    *subtree7;                  /* subtree for attributes   */
    proto_tree    *subtree8;                  /* subtree for attributes   */
    proto_tree    *attr_set_subtree;          /* subtree for attr_set     */
    proto_tree    *as_path_segment_tree;      /* subtree for AS_PATH segments */
    gint          number_as_segment=0;        /* Number As segment        */
    proto_tree    *communities_tree;          /* subtree for COMMUNITIES  */
    proto_tree    *community_tree;            /* subtree for a community  */
    proto_tree    *cluster_list_tree;         /* subtree for CLUSTER_LIST */
    int           i=0, j, k;                  /* tmp                      */
    guint8        type=0;                     /* AS_PATH segment type     */
    guint8        length=0;                   /* AS_PATH segment length   */
    guint32       aggregator_as;
    guint16       ssa_type;                   /* SSA T + Type */
    guint16       ssa_len;                    /* SSA TLV Length */
    guint8        ssa_v3_len;                 /* SSA L2TPv3 Cookie Length */
    guint16       encaps_tunnel_type;         /* Encapsulation Tunnel Type */
    guint16       encaps_tunnel_len;          /* Encapsulation TLV Length */
    guint8        encaps_tunnel_subtype;      /* Encapsulation Tunnel Sub-TLV Type */
    guint16       encaps_tunnel_sublen;       /* Encapsulation TLV Sub-TLV Length */
    guint16       encaps_tunnel_sub_totallen; /* Encapsulation TLV Sub-TLV Length + Type + Length field */
    guint8        aigp_type;                  /* AIGP TLV type from AIGP attribute */
    guint8        prefix_sid_subtype;         /* BGP Prefix-SID TLV Type */
    guint16       prefix_sid_sublen;          /* BGP Prefix-SID TLV Length */
    gint          prefix_sid_sub_tlv_offset;  /* BGP Prefix-SID SRGB Length */
    gint          check_srgb;                 /* BGP Prefix-SID SRGB counter */
    guint16       secpathlen;                 /* BGPsec Secure Path length */
    guint16       sigblocklen;                /* BGPsec Signature Block length */
    guint8        secpathcount;               /* Number of Secure Path Segments */
    guint16       sig_len;                    /* Length of BGPsec Signature */
    guint32       segment_subtlv_type;        /* Segment List SubTLV Type */
    guint32       segment_subtlv_length;      /* Segment List SubTLV Length */
    guint8        srv6_service_subtlv_type;         /* SRv6 Service Sub-TLV type */
    guint16       srv6_service_subtlv_len;          /* SRv6 Service Sub-TLV length */
    guint8        srv6_service_data_subsubtlv_type; /* SRv6 Service Data Sub-Sub-TLV type */
    guint16       srv6_service_data_subsubtlv_len;  /* SRv6 Service Data Sub-Sub-TLV length */

    o = tvb_off;

    while (i < path_attr_len) {
        proto_item *ti_pa, *ti_flags;
        int     off;
        gint    alen, aoff, tlen, aoff_save;
        guint8  snpa;
        guint8  nexthop_len;
        guint8  asn_len = 0;
        guint32 af, saf, as_num;

        static int * const path_flags[] = {
            &hf_bgp_update_path_attribute_flags_optional,
            &hf_bgp_update_path_attribute_flags_transitive,
            &hf_bgp_update_path_attribute_flags_partial,
            &hf_bgp_update_path_attribute_flags_extended_length,
            &hf_bgp_update_path_attribute_flags_unused,
            NULL
        };

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

        ti_pa = proto_tree_add_item(subtree, hf_bgp_update_path_attribute, tvb, o + i, tlen + aoff, ENC_NA);
        proto_item_append_text(ti_pa, " - %s", val_to_str(bgpa_type, bgpattr_type, "Unknown (%u)"));

        subtree2 = proto_item_add_subtree(ti_pa, ett_bgp_attr);

        ti_flags = proto_tree_add_bitmask(subtree2, tvb, o + i, hf_bgp_update_path_attribute_flags, ett_bgp_attr_flags, path_flags, ENC_NA);

        if ((bgpa_flags & BGP_ATTR_FLAG_OPTIONAL) == 0)
            proto_item_append_text(ti_flags, "%s", ", Well-known");
        if ((bgpa_flags & BGP_ATTR_FLAG_TRANSITIVE) == 0)
            proto_item_append_text(ti_flags, "%s", ", Non-transitive");
        if ((bgpa_flags & BGP_ATTR_FLAG_PARTIAL) == 0)
            proto_item_append_text(ti_flags, "%s", ", Complete");

        proto_tree_add_item(subtree2, hf_bgp_update_path_attribute_type_code, tvb, o + i + 1, 1, ENC_BIG_ENDIAN);

        attr_len_item = proto_tree_add_item(subtree2, hf_bgp_update_path_attribute_length, tvb, o + i + BGP_SIZE_OF_PATH_ATTRIBUTE,
                                            aoff - BGP_SIZE_OF_PATH_ATTRIBUTE, ENC_BIG_ENDIAN);
        if (aoff + tlen > path_attr_len - i) {
            proto_tree_add_expert_format(subtree2, pinfo, &ei_bgp_length_invalid, tvb, o + i + aoff, tlen,
                                         "Path attribute length is invalid: %u byte%s", tlen,
                                         plurality(tlen, "", "s"));
            return;
        }

        /* Path Attribute Type */
        switch (bgpa_type) {
            case BGPTYPE_ORIGIN:
                if (tlen != 1) {
                    proto_tree_add_expert_format(subtree2, pinfo, &ei_bgp_length_invalid, tvb, o + i + aoff, tlen,
                                                 "Origin (invalid): %u byte%s", tlen,
                                                 plurality(tlen, "", "s"));
                } else {
                    proto_tree_add_item(subtree2, hf_bgp_update_path_attribute_origin, tvb,
                                        o + i + aoff, 1, ENC_BIG_ENDIAN);
                    proto_item_append_text(ti_pa, ": %s", val_to_str_const(tvb_get_guint8(tvb, o + i + aoff), bgpattr_origin, "Unknown"));
                }
                break;
            case BGPTYPE_AS_PATH:
            case BGPTYPE_AS4_PATH:
                /* Apply heuristic to guess if we are facing 2 or 4 bytes ASN
                   (o + i + aoff) =
                   (o + current attribute + aoff bytes to first tuple)
                   heuristic also tell us how many AS segments we have */
                asn_len = heuristic_as2_or_4_from_as_path(tvb, o+i+aoff, o+i+aoff+tlen,
                                                          bgpa_type, &number_as_segment);
                if (asn_len == 255)
                    {
                        expert_add_info_format(pinfo, ti_pa, &ei_bgp_attr_as_path_as_len_err,
                                               "ASN length uncalculated by heuristic : %u", asn_len);
                        break;
                    }
                proto_item_append_text(ti_pa,": ");
                if(tlen == 0) {
                    proto_item_append_text(ti_pa,"empty");
                }
                q = o + i + aoff;
                for (k=0; k < number_as_segment; k++)
                {
                    type = tvb_get_guint8(tvb, q);
                    length = tvb_get_guint8(tvb, q+1);
                    ti = proto_tree_add_item(subtree2, hf_bgp_update_path_attribute_as_path_segment, tvb,
                                             q, length * asn_len + 2, ENC_NA);
                    proto_item_append_text(ti,": ");
                    as_path_segment_tree = proto_item_add_subtree(ti, ett_bgp_as_path_segment);
                    proto_tree_add_item(as_path_segment_tree, hf_bgp_update_path_attribute_as_path_segment_type, tvb,
                                        q, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(as_path_segment_tree, hf_bgp_update_path_attribute_as_path_segment_length, tvb,
                                        q+1, 1, ENC_BIG_ENDIAN);
                    switch(type)
                    {
                        case AS_SET:
                            proto_item_append_text(ti_pa, "{");
                            proto_item_append_text(ti, "{");
                            break;
                        case AS_CONFED_SET:
                            proto_item_append_text(ti_pa, "[");
                            proto_item_append_text(ti, "[");
                            break;
                        case AS_CONFED_SEQUENCE:
                            proto_item_append_text(ti_pa, "(");
                            proto_item_append_text(ti, "(");
                            break;
                    }

                    q = q + 2;
                    for (j = 0; j < length; j++)
                    {
                        if(asn_len == 2) {
                            ti_as = proto_tree_add_item_ret_uint(as_path_segment_tree,
                                                hf_bgp_update_path_attribute_as_path_segment_as2,
                                                tvb, q, 2, ENC_BIG_ENDIAN, &as_num);
                            if (as_num == BGP_AS_TRANS) {
                                proto_item_append_text(ti_as, " (AS_TRANS)");
                            }
                            proto_item_append_text(ti_pa, "%u",
                                                   tvb_get_ntohs(tvb, q));
                            proto_item_append_text(ti, "%u",
                                                   tvb_get_ntohs(tvb, q));
                        }
                        else if (asn_len == 4) {
                            proto_tree_add_item(as_path_segment_tree,
                                                hf_bgp_update_path_attribute_as_path_segment_as4,
                                                tvb, q, 4, ENC_BIG_ENDIAN);
                            proto_item_append_text(ti_pa, "%u",
                                                   tvb_get_ntohl(tvb, q));
                            proto_item_append_text(ti, "%u",
                                                   tvb_get_ntohl(tvb, q));
                        }
                        if (j != length-1)
                        {
                            proto_item_append_text(ti_pa, "%s",
                                                   (type == AS_SET || type == AS_CONFED_SET) ?
                                                   ", " : " ");
                            proto_item_append_text(ti, "%s",
                                                   (type == AS_SET || type == AS_CONFED_SET) ?
                                                   ", " : " ");
                        }
                        q += asn_len;
                    }
                    switch(type)
                    {
                        case AS_SET:
                            proto_item_append_text(ti_pa, "} ");
                            proto_item_append_text(ti, "}");
                            break;
                        case AS_CONFED_SET:
                            proto_item_append_text(ti_pa, "] ");
                            proto_item_append_text(ti, "]");
                            break;
                        case AS_CONFED_SEQUENCE:
                            proto_item_append_text(ti_pa, ") ");
                            proto_item_append_text(ti, ")");
                            break;
                        default:
                            proto_item_append_text(ti_pa, " ");
                            break;
                    }
                }

                break;
            case BGPTYPE_NEXT_HOP:
                if (tlen != 4) {
                    proto_tree_add_expert_format(subtree2, pinfo, &ei_bgp_length_invalid, tvb, o + i + aoff, tlen,
                                                 "Next hop (invalid): %u byte%s", tlen,
                                                 plurality(tlen, "", "s"));
                } else {
                    proto_tree_add_item(subtree2, hf_bgp_update_path_attribute_next_hop, tvb,
                                        o + i + aoff, 4, ENC_BIG_ENDIAN);
                    proto_item_append_text(ti_pa, ": %s ", tvb_ip_to_str(pinfo->pool, tvb, o + i + aoff));
                }
                break;
            case BGPTYPE_MULTI_EXIT_DISC:
                if (tlen != 4) {
                    proto_tree_add_expert_format(subtree2, pinfo, &ei_bgp_length_invalid, tvb, o + i + aoff, tlen,
                                                 "Multiple exit discriminator (invalid): %u byte%s",
                                                 tlen, plurality(tlen, "", "s"));
                } else {
                    proto_tree_add_item(subtree2, hf_bgp_update_path_attribute_multi_exit_disc, tvb,
                                        o + i + aoff, tlen, ENC_BIG_ENDIAN);
                    proto_item_append_text(ti_pa,": %u", tvb_get_ntohl(tvb, o + i + aoff));
                }
                break;
            case BGPTYPE_LOCAL_PREF:
                if (tlen != 4) {
                    proto_tree_add_expert_format(subtree2, pinfo, &ei_bgp_length_invalid, tvb, o + i + aoff, tlen,
                                                 "Local preference (invalid): %u byte%s", tlen,
                                                 plurality(tlen, "", "s"));
                } else {
                    proto_tree_add_item(subtree2, hf_bgp_update_path_attribute_local_pref, tvb,
                                        o + i + aoff, tlen, ENC_BIG_ENDIAN);
                    proto_item_append_text(ti_pa, ": %u", tvb_get_ntohl(tvb, o + i + aoff));
                }
                break;
            case BGPTYPE_ATOMIC_AGGREGATE:
                if (tlen != 0) {
                    proto_tree_add_expert_format(subtree2, pinfo, &ei_bgp_length_invalid, tvb, o + i + aoff, tlen,
                                                 "Atomic aggregate (invalid): %u byte%s", tlen,
                                                 plurality(tlen, "", "s"));
                }
                break;
            case BGPTYPE_AGGREGATOR:
                if (tlen != 6 && tlen != 8) {
                    proto_tree_add_expert_format(subtree2, pinfo, &ei_bgp_length_invalid, tvb, o + i + aoff, tlen,
                                                 "Aggregator (invalid): %u byte%s", tlen,
                                                 plurality(tlen, "", "s"));
                    break;
                }
                /* FALL THROUGH */
            case BGPTYPE_AS4_AGGREGATOR:
                if (bgpa_type == BGPTYPE_AS4_AGGREGATOR && tlen != 8)
                    proto_tree_add_expert_format(subtree2, pinfo, &ei_bgp_length_invalid, tvb, o + i + aoff, tlen,
                                                 "Aggregator (invalid): %u byte%s", tlen,
                                                 plurality(tlen, "", "s"));
                else {
                    asn_len = tlen - 4;
                    aggregator_as = (asn_len == 2) ?
                        tvb_get_ntohs(tvb, o + i + aoff) :
                        tvb_get_ntohl(tvb, o + i + aoff);
                    proto_tree_add_uint(subtree2, hf_bgp_update_path_attribute_aggregator_as, tvb,
                                        o + i + aoff, asn_len, aggregator_as);
                    proto_tree_add_item(subtree2, hf_bgp_update_path_attribute_aggregator_origin, tvb,
                                        o + i + aoff + asn_len, 4, ENC_BIG_ENDIAN);

                    proto_item_append_text(ti_pa, ": AS: %u origin: %s", aggregator_as,
                                           tvb_ip_to_str(pinfo->pool, tvb, o + i + aoff + asn_len));
                }
                break;
            case BGPTYPE_COMMUNITIES:
                if (tlen % 4 != 0) {
                    proto_tree_add_expert_format(subtree2, pinfo, &ei_bgp_length_invalid, tvb, o + i + aoff, tlen,
                                                 "Communities (invalid): %u byte%s", tlen,
                                                 plurality(tlen, "", "s"));
                    break;
                }

                proto_item_append_text(ti_pa, ": ");

                ti_communities = proto_tree_add_item(subtree2, hf_bgp_update_path_attribute_communities,
                                                     tvb, o + i + aoff, tlen, ENC_NA);

                communities_tree = proto_item_add_subtree(ti_communities,
                                                          ett_bgp_communities);
                proto_item_append_text(ti_communities, ": ");
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
                        proto_tree_add_item(communities_tree, hf_bgp_update_path_attribute_community_well_known,
                                            tvb, q, 4, ENC_BIG_ENDIAN);
                        proto_item_append_text(ti_pa, "%s ", val_to_str_const(community, community_vals, "Reserved"));
                        proto_item_append_text(ti_communities, "%s ", val_to_str_const(community, community_vals, "Reserved"));
                    }
                    else {
                        ti_community = proto_tree_add_item(communities_tree, hf_bgp_update_path_attribute_community, tvb,
                                                           q, 4, ENC_NA);
                        community_tree = proto_item_add_subtree(ti_community,
                                                                ett_bgp_community);
                        proto_tree_add_item(community_tree, hf_bgp_update_path_attribute_community_as,
                                            tvb, q, 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(community_tree, hf_bgp_update_path_attribute_community_value,
                                            tvb, q+2, 2, ENC_BIG_ENDIAN);
                        proto_item_append_text(ti_pa, "%u:%u ",tvb_get_ntohs(tvb, q),
                                               tvb_get_ntohs(tvb, q+2));
                        proto_item_append_text(ti_communities, "%u:%u ",tvb_get_ntohs(tvb, q),
                                               tvb_get_ntohs(tvb, q+2));
                        proto_item_append_text(ti_community, ": %u:%u ",tvb_get_ntohs(tvb, q),
                                               tvb_get_ntohs(tvb, q+2));
                    }

                    q += 4;
                }


                break;
            case BGPTYPE_ORIGINATOR_ID:
                if (tlen != 4) {
                    proto_tree_add_expert_format(subtree2, pinfo, &ei_bgp_length_invalid, tvb, o + i + aoff, tlen,
                                                 "Originator identifier (invalid): %u byte%s", tlen,
                                                 plurality(tlen, "", "s"));
                } else {
                    proto_tree_add_item(subtree2, hf_bgp_update_path_attribute_originator_id, tvb,
                                        o + i + aoff, tlen, ENC_BIG_ENDIAN);
                    proto_item_append_text(ti_pa, ": %s ", tvb_ip_to_str(pinfo->pool, tvb, o + i + aoff));
                }
                break;
            case BGPTYPE_MP_REACH_NLRI:
                /* RFC 2283 says that a MP_[UN]REACH_NLRI path attribute can
                 * have more than one <AFI, SAFI, Next Hop, ..., NLRI> tuple.
                 * However, that doesn't work because the NLRI is also a
                 * variable number of <length, prefix> fields without a field
                 * for the overall length of the NLRI. Thus one would have to
                 * guess whether a particular byte were the length of the next
                 * prefix or a new AFI. So no one ever implemented that, and
                 * RFC 2858, obsoleting 2283, says you can't do that.
                 */
                proto_tree_add_item_ret_uint(subtree2, hf_bgp_update_path_attribute_mp_reach_nlri_address_family, tvb,
                                    o + i + aoff, 2, ENC_BIG_ENDIAN, &af);
                proto_tree_add_item_ret_uint(subtree2, hf_bgp_update_path_attribute_mp_reach_nlri_safi, tvb,
                                    o + i + aoff + 2, 1, ENC_BIG_ENDIAN, &saf);
                nexthop_len = tvb_get_guint8(tvb, o + i + aoff + 3);

                decode_mp_next_hop(tvb_new_subset_length(tvb, o + i + aoff + 3, nexthop_len + 1), subtree2, pinfo, af, saf, nexthop_len);

                aoff_save = aoff;
                tlen -= nexthop_len + 4;
                aoff += nexthop_len + 4;

                off = 0;
                snpa = tvb_get_guint8(tvb, o + i + aoff);
                ti = proto_tree_add_item(subtree2, hf_bgp_update_path_attribute_mp_reach_nlri_nbr_snpa, tvb,
                                         o + i + aoff, 1, ENC_BIG_ENDIAN);
                off++;
                if (snpa) {
                    subtree3 = proto_item_add_subtree(ti, ett_bgp_mp_snpa);
                    for (/*nothing*/; snpa > 0; snpa--) {
                        guint8 snpa_length = tvb_get_guint8(tvb, o + i + aoff + off);
                        proto_tree_add_item(subtree3, hf_bgp_update_path_attribute_mp_reach_nlri_snpa_length, tvb,
                                            o + i + aoff + off, 1, ENC_BIG_ENDIAN);
                        off++;
                        proto_tree_add_item(subtree3, hf_bgp_update_path_attribute_mp_reach_nlri_snpa, tvb,
                                            o + i + aoff + off, snpa_length, ENC_NA);
                        off += snpa_length;
                    }
                }
                tlen -= off;
                aoff += off;

                ti = proto_tree_add_item(subtree2, hf_bgp_update_path_attribute_mp_reach_nlri, tvb, o + i + aoff, tlen, ENC_NA);
                subtree3 = proto_item_add_subtree(ti, ett_bgp_mp_reach_nlri);

                if (tlen)  {
                    if (af != AFNUM_INET && af != AFNUM_INET6 && af != AFNUM_L2VPN && af != AFNUM_BGP_LS) {
                        proto_tree_add_expert(subtree3, pinfo, &ei_bgp_unknown_afi, tvb, o + i + aoff, tlen);
                    } else {
                        while (tlen > 0) {
                            advance = decode_prefix_MP(subtree3,
                                                       hf_bgp_nlri_path_id,
                                                       hf_bgp_mp_reach_nlri_ipv4_prefix,
                                                       hf_bgp_mp_reach_nlri_ipv6_prefix,
                                                       af, saf, tlen,
                                                       tvb, o + i + aoff, "MP Reach NLRI", pinfo);
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
                proto_tree_add_item(subtree2, hf_bgp_update_path_attribute_mp_unreach_nlri_address_family, tvb,
                                    o + i + aoff, 2, ENC_BIG_ENDIAN);
                saf = tvb_get_guint8(tvb, o + i + aoff + 2) ;
                proto_tree_add_item(subtree2, hf_bgp_update_path_attribute_mp_unreach_nlri_safi, tvb,
                                    o + i + aoff+2, 1, ENC_BIG_ENDIAN);

                ti = proto_tree_add_item(subtree2, hf_bgp_update_path_attribute_mp_unreach_nlri, tvb, o + i + aoff + 3, tlen - 3, ENC_NA);
                subtree3 = proto_item_add_subtree(ti, ett_bgp_mp_unreach_nlri);

                aoff_save = aoff;
                tlen -= 3;
                aoff += 3;
                if (tlen > 0) {

                    while (tlen > 0) {
                        advance = decode_prefix_MP(subtree3,
                                                   hf_bgp_nlri_path_id,
                                                   hf_bgp_mp_unreach_nlri_ipv4_prefix,
                                                   hf_bgp_mp_unreach_nlri_ipv6_prefix,
                                                   af, saf, tlen,
                                                   tvb, o + i + aoff, "MP Unreach NLRI", pinfo);
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
                    proto_tree_add_expert_format(subtree2, pinfo, &ei_bgp_length_invalid, tvb, o + i + aoff, tlen,
                                                 "Cluster list (invalid): %u byte%s", tlen,
                                                 plurality(tlen, "", "s"));
                    break;
                }

                ti = proto_tree_add_item(subtree2, hf_bgp_update_path_attribute_cluster_list,
                                         tvb, o + i + aoff, tlen, ENC_NA);
                cluster_list_tree = proto_item_add_subtree(ti,
                                                               ett_bgp_cluster_list);

                /* (o + i + aoff) =
                   (o + current attribute + aoff bytes to first tuple) */
                q = o + i + aoff;
                end = q + tlen;
                proto_item_append_text(ti, ":");
                proto_item_append_text(ti_pa, ":");
                /* snarf each cluster identifier */
                while (q < end) {
                    proto_tree_add_item(cluster_list_tree, hf_bgp_update_path_attribute_cluster_id,
                                        tvb, q - 3 + aoff, 4, ENC_NA);
                    proto_item_append_text(ti, " %s", tvb_ip_to_str(pinfo->pool, tvb, q-3+aoff));
                    proto_item_append_text(ti_pa, " %s", tvb_ip_to_str(pinfo->pool, tvb, q-3+aoff));
                    q += 4;
                }

                break;
            case BGPTYPE_EXTENDED_COMMUNITY:
                if (tlen %8 != 0) {
                    expert_add_info_format(pinfo, attr_len_item, &ei_bgp_ext_com_len_bad,
                                           "Community length %u wrong, must be modulo 8", tlen);
                } else {
                    dissect_bgp_update_ext_com(subtree2, tvb, tlen, o+i+aoff, pinfo);
                }
                break;
            case BGPTYPE_SAFI_SPECIFIC_ATTR:
                q = o + i + aoff;
                end = o + i + aoff + tlen ;

                while(q < end) {
                    ssa_type = tvb_get_ntohs(tvb, q) & BGP_SSA_TYPE;
                    ssa_len = tvb_get_ntohs(tvb, q + 2);

                    subtree3 = proto_tree_add_subtree_format(subtree2, tvb, q, MIN(ssa_len + 4, end - q),
                                                             ett_bgp_ssa, NULL, "%s Information",
                                                             val_to_str_const(ssa_type, bgp_ssa_type, "Unknown SSA"));

                    proto_tree_add_item(subtree3, hf_bgp_ssa_t, tvb,
                                        q, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(subtree3, hf_bgp_ssa_type, tvb, q, 2, ENC_BIG_ENDIAN);

                    proto_tree_add_item(subtree3, hf_bgp_ssa_len, tvb, q + 2, 2, ENC_BIG_ENDIAN);

                    if ((ssa_len == 0) || (q + ssa_len > end)) {
                        proto_tree_add_expert_format(subtree3, pinfo, &ei_bgp_length_invalid, tvb, q + 2,
                                                     end - q - 2, "Invalid Length of %u", ssa_len);
                        break;
                    }

                    switch (ssa_type) {
                        case BGP_SSA_L2TPv3:
                            proto_tree_add_item(subtree3, hf_bgp_ssa_l2tpv3_pref, tvb,
                                                q + 4, 2, ENC_BIG_ENDIAN);

                            subtree4 = proto_tree_add_subtree(subtree3, tvb, q + 6, 1, ett_bgp_ssa_subtree, NULL, "Flags");
                            proto_tree_add_item(subtree4, hf_bgp_ssa_l2tpv3_s, tvb,
                                                q + 6, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(subtree4, hf_bgp_ssa_l2tpv3_unused, tvb,
                                                q + 6, 1, ENC_BIG_ENDIAN);

                            ssa_v3_len = tvb_get_guint8(tvb, q + 7);
                            if (ssa_v3_len + 8 == ssa_len){
                                proto_tree_add_item(subtree3, hf_bgp_ssa_l2tpv3_cookie_len, tvb,
                                                    q + 7, 1, ENC_BIG_ENDIAN);
                            } else {
                                proto_tree_add_expert_format(subtree3, pinfo, &ei_bgp_length_invalid, tvb, q + 7, 1,
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

                subtree3 = proto_tree_add_subtree(subtree2, tvb, q, tlen, ett_bgp_tunnel_tlv, NULL, "TLV Encodings");

                while (q < end) {
                    encaps_tunnel_type = tvb_get_ntohs(tvb, q);
                    encaps_tunnel_len = tvb_get_ntohs(tvb, q + 2);

                    subtree4 = proto_tree_add_subtree_format(subtree3, tvb, q, encaps_tunnel_len + 4,
                                         ett_bgp_tunnel_tlv_subtree, NULL, "%s (%u bytes)",
                                         val_to_str_const(encaps_tunnel_type, bgp_attr_tunnel_type, "Unknown"), encaps_tunnel_len + 4);

                    proto_tree_add_item(subtree4, hf_bgp_update_encaps_tunnel_tlv_type, tvb, q, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(subtree4, hf_bgp_update_encaps_tunnel_tlv_len, tvb, q + 2, 2, ENC_BIG_ENDIAN);

                    subtree5 = proto_tree_add_subtree(subtree4, tvb, q + 4, encaps_tunnel_len, ett_bgp_tunnel_subtlv, NULL, "Sub-TLV Encodings");

                    q += 4;
                    j = q + encaps_tunnel_len;
                    while ( q < j ) {
                        encaps_tunnel_subtype = tvb_get_guint8(tvb, q);
                        if (encaps_tunnel_subtype < 128) {
                            encaps_tunnel_sublen = tvb_get_guint8(tvb, q + 1);
                            encaps_tunnel_sub_totallen = encaps_tunnel_sublen + 2;
                        } else {
                            encaps_tunnel_sublen = tvb_get_ntohs(tvb, q + 1);
                            encaps_tunnel_sub_totallen = encaps_tunnel_sublen + 3;
                        }
                        subtree6 = proto_tree_add_subtree_format(subtree5, tvb, q, encaps_tunnel_sub_totallen,
                                             ett_bgp_tunnel_tlv_subtree, NULL, "%s (%u bytes)",
                                             val_to_str_const(encaps_tunnel_subtype, subtlv_type, "Unknown"), encaps_tunnel_sub_totallen);
                        proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_type, tvb, q, 1, ENC_BIG_ENDIAN);
                        q += 1;
                        if (encaps_tunnel_subtype < 128) {
                            proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_len, tvb, q, 1, ENC_BIG_ENDIAN);
                            q += 1;
                        } else {
                            proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_len, tvb, q, 2, ENC_BIG_ENDIAN);
                            q += 2;
                        }

                        switch (encaps_tunnel_subtype) {
                            case TUNNEL_SUBTLV_ENCAPSULATION:
                                {
                                static int * const vxlan_flags[] = {
                                    &hf_bgp_update_encaps_tunnel_subtlv_vxlan_flags_valid_vnid,
                                    &hf_bgp_update_encaps_tunnel_subtlv_vxlan_flags_valid_mac,
                                    &hf_bgp_update_encaps_tunnel_subtlv_vxlan_flags_reserved,
                                    NULL
                                    };
                                static int * const vxlan_gpe_flags[] = {
                                    &hf_bgp_update_encaps_tunnel_subtlv_vxlan_gpe_flags_version,
                                    &hf_bgp_update_encaps_tunnel_subtlv_vxlan_gpe_flags_valid_vnid,
                                    &hf_bgp_update_encaps_tunnel_subtlv_vxlan_gpe_flags_reserved,
                                    NULL
                                    };
                                static int * const nvgre_flags[] = {
                                    &hf_bgp_update_encaps_tunnel_subtlv_nvgre_flags_valid_vnid,
                                    &hf_bgp_update_encaps_tunnel_subtlv_nvgre_flags_valid_mac,
                                    &hf_bgp_update_encaps_tunnel_subtlv_nvgre_flags_reserved,
                                    NULL
                                    };
                                if (encaps_tunnel_type == TUNNEL_TYPE_L2TP_OVER_IP) {
                                    proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_session_id, tvb, q, 4, ENC_BIG_ENDIAN);
                                    q += 4;
                                    proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_cookie, tvb, q, encaps_tunnel_sublen - 4, ENC_NA);
                                    q += (encaps_tunnel_sublen - 4);
                                } else if (encaps_tunnel_type == TUNNEL_TYPE_GRE || encaps_tunnel_type == TUNNEL_TYPE_MPLS_IN_GRE) {
                                    proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_gre_key, tvb, q, 4, ENC_BIG_ENDIAN);
                                    q += 4;
                                } else if (encaps_tunnel_type == TUNNEL_TYPE_VXLAN) {
                                    proto_tree_add_bitmask(subtree6, tvb, q, hf_bgp_update_encaps_tunnel_subtlv_vxlan_flags,
                                            ett_bgp_vxlan, vxlan_flags, ENC_BIG_ENDIAN);
                                    q += 1;
                                    proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_vxlan_vnid, tvb, q, 3, ENC_BIG_ENDIAN);
                                    q += 3;
                                    proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_vxlan_mac, tvb, q, 6, ENC_NA);
                                    q += 6;
                                    proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_vxlan_reserved, tvb, q, 2, ENC_BIG_ENDIAN);
                                    q += 2;
                                } else if (encaps_tunnel_type == TUNNEL_TYPE_VXLAN_GPE) {
                                    proto_tree_add_bitmask(subtree6, tvb, q, hf_bgp_update_encaps_tunnel_subtlv_vxlan_gpe_flags,
                                            ett_bgp_vxlan, vxlan_gpe_flags, ENC_BIG_ENDIAN);
                                    q += 1;
                                    proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_vxlan_gpe_reserved, tvb, q, 2, ENC_BIG_ENDIAN);
                                    q += 2;
                                    proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_vxlan_gpe_vnid, tvb, q, 3, ENC_BIG_ENDIAN);
                                    q += 3;
                                    proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_vxlan_gpe_reserved, tvb, q, 1, ENC_BIG_ENDIAN);
                                    q += 1;
                                } else if (encaps_tunnel_type == TUNNEL_TYPE_NVGRE) {
                                    proto_tree_add_bitmask(subtree6, tvb, q, hf_bgp_update_encaps_tunnel_subtlv_nvgre_flags,
                                            ett_bgp_vxlan, nvgre_flags, ENC_BIG_ENDIAN);
                                    q += 1;
                                    proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_nvgre_vnid, tvb, q, 3, ENC_BIG_ENDIAN);
                                    q += 3;
                                    proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_nvgre_mac, tvb, q, 6, ENC_NA);
                                    q += 6;
                                    proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_nvgre_reserved, tvb, q, 2, ENC_BIG_ENDIAN);
                                    q += 2;
                                }
                                }
                                break;
                            case TUNNEL_SUBTLV_PROTO_TYPE:
                                proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_gre_key, tvb, q, 2, ENC_BIG_ENDIAN);
                                q += 2;
                                break;
                            case TUNNEL_SUBTLV_COLOR:
                                proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_color_value, tvb, q, 4, ENC_BIG_ENDIAN);
                                q += 4;
                                break;
                            case TUNNEL_SUBTLV_LOAD_BALANCE:
                                if (encaps_tunnel_type == TUNNEL_TYPE_L2TP_OVER_IP || encaps_tunnel_type == TUNNEL_TYPE_GRE) {
                                    proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_lb_block_length, tvb, q, 4, ENC_BIG_ENDIAN);
                                    q += 4;
                                }
                                break;
                            case TUNNEL_SUBTLV_PREFERENCE:
                                proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_pref_flags, tvb, q, 1, ENC_BIG_ENDIAN);
                                q += 1;
                                proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_pref_reserved, tvb, q, 1, ENC_BIG_ENDIAN);
                                q += 1;
                                proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_pref_preference, tvb, q, 4, ENC_NA);
                                q += 4;
                                break;
                            case TUNNEL_SUBTLV_BINDING_SID:
                                {
                                static int * const flags[] = {
                                    &hf_bgp_update_encaps_tunnel_subtlv_binding_sid_flags_specified,
                                    &hf_bgp_update_encaps_tunnel_subtlv_binding_sid_flags_invalid,
                                    &hf_bgp_update_encaps_tunnel_subtlv_binding_sid_flags_reserved,
                                    NULL
                                    };

                                proto_tree_add_bitmask(subtree6, tvb, q, hf_bgp_update_encaps_tunnel_subtlv_binding_sid_flags,
                                        ett_bgp_binding_sid, flags, ENC_BIG_ENDIAN);
                                q += 1;
                                proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_binding_sid_reserved,
                                        tvb, q, 1, ENC_BIG_ENDIAN);
                                q += 1;
                                if (encaps_tunnel_sublen > 2) {
                                    proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_binding_sid_sid, tvb, q,
                                            encaps_tunnel_sublen - 2, ENC_NA);
                                    q += (encaps_tunnel_sublen - 2);
                                }
                                }
                                break;
                            case TUNNEL_SUBTLV_ENLP:
                                proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_enlp_flags, tvb, q, 1, ENC_BIG_ENDIAN);
                                q += 1;
                                proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_enlp_reserved, tvb, q, 1, ENC_BIG_ENDIAN);
                                q += 1;
                                proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_enlp_enlp, tvb, q, 1, ENC_BIG_ENDIAN);
                                q += 1;
                                break;
                            case TUNNEL_SUBTLV_PRIORITY:
                                proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_priority_priority, tvb, q, 1, ENC_BIG_ENDIAN);
                                q += 1;
                                proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_priority_reserved, tvb, q, 1, ENC_BIG_ENDIAN);
                                q += 1;
                                break;
                            case TUNNEL_SUBTLV_SEGMENT_LIST:
                                {
                                static int * const flags[] = {
                                    &hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv_flags_verification,
                                    &hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv_flags_algorithm,
                                    &hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv_flags_reserved,
                                    NULL
                                    };

                                proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_segment_list_reserved, tvb, q, 1, ENC_BIG_ENDIAN);
                                q += 1;
                                ti = proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv, tvb, q,
                                        encaps_tunnel_sublen - 1, ENC_NA);
                                encaps_tunnel_sublen -= 1;
                                subtree7 = proto_item_add_subtree(ti, ett_bgp_segment_list);
                                while (encaps_tunnel_sublen > 2) {
                                    segment_subtlv_type = tvb_get_guint8(tvb, q);
                                    segment_subtlv_length = tvb_get_guint8(tvb, q + 1);
                                    subtree8 = proto_tree_add_subtree_format(subtree7, tvb, q, segment_subtlv_length + 2,
                                            ett_bgp_segment_list, NULL, "SubTLV: %s", val_to_str_const(segment_subtlv_type,
                                            bgp_sr_policy_list_type, "Unknown"));
                                    proto_tree_add_item(subtree8, hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv_type, tvb, q, 1, ENC_BIG_ENDIAN);
                                    q += 1;
                                    proto_tree_add_item(subtree8, hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv_length, tvb, q, 1, ENC_BIG_ENDIAN);
                                    q += 1;
                                    if (segment_subtlv_length > 0) {
                                        switch(segment_subtlv_type) {
                                            /* TODO: Dissect further subTLVs data as defined in draft-ietf-idr-segment-routing-te-policy-08 section 2.4.3.2 */
                                            case TUNNEL_SUBTLV_SEGMENT_LIST_SUB_TYPE_A:
                                                proto_tree_add_bitmask(subtree8, tvb, q, hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv_flags,
                                                        ett_bgp_segment_list, flags, ENC_BIG_ENDIAN);
                                                q += 1;
                                                proto_tree_add_item(subtree8, hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv_reserved,
                                                        tvb, q, 1, ENC_NA);
                                                q += 1;
                                                proto_tree_add_item(subtree8, hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv_mpls_label,
                                                        tvb, q, 3, ENC_BIG_ENDIAN);
                                                q += 2;
                                                proto_tree_add_item(subtree8, hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv_traffic_class,
                                                        tvb, q, 1, ENC_BIG_ENDIAN);
                                                proto_tree_add_item(subtree8, hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv_bottom_stack,
                                                        tvb, q, 1, ENC_BIG_ENDIAN);
                                                q += 1;
                                                proto_tree_add_item(subtree8, hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv_ttl,
                                                        tvb, q, 1, ENC_BIG_ENDIAN);
                                                q += 1;
                                                break;
                                            default:
                                                proto_tree_add_item(subtree8, hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv_data,
                                                        tvb, q, segment_subtlv_length, ENC_NA);
                                                q += segment_subtlv_length;
                                                break;
                                        }
                                    }
                                    encaps_tunnel_sublen -= (segment_subtlv_length + 2);
                                }
                                }
                                break;
                            case TUNNEL_SUBTLV_POLICY_NAME:
                                proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_policy_name_reserved, tvb, q, 1, ENC_BIG_ENDIAN);
                                q += 1;
                                proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_policy_name_name, tvb, q,
                                        encaps_tunnel_sublen - 1, ENC_ASCII);
                                q += (encaps_tunnel_sublen - 1);
                                break;
                            default:
                                proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_value, tvb, q, encaps_tunnel_sublen, ENC_NA);
                                q += encaps_tunnel_sublen;
                                break;
                        } /* switch (encaps_tunnel_subtype) */
                    }
                }
                break;
            case BGPTYPE_AIGP:
                q = o + i + aoff;
                ti = proto_tree_add_item(subtree2, hf_bgp_update_path_attribute_aigp, tvb, q, tlen, ENC_NA);
                subtree3 = proto_item_add_subtree(ti, ett_bgp_aigp_attr);
                aigp_type_item =  proto_tree_add_item(subtree3, hf_bgp_aigp_type, tvb, q, 1, ENC_BIG_ENDIAN);
                aigp_type = tvb_get_guint8(tvb,q);
                switch (aigp_type) {
                    case AIGP_TLV_TYPE :
                        proto_tree_add_item(subtree3, hf_bgp_aigp_tlv_length, tvb, q+1, 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(subtree3, hf_bgp_aigp_accu_igp_metric, tvb, q+3, 8, ENC_BIG_ENDIAN);
                        proto_item_append_text(ti, ": %" PRIu64, tvb_get_ntoh64(tvb, q+3));
                        proto_item_append_text(ti_pa, ": %" PRIu64, tvb_get_ntoh64(tvb, q+3));
                        break;
                    default :
                        expert_add_info_format(pinfo, aigp_type_item, &ei_bgp_attr_aigp_type,
                                               "AIGP type %u unknown", aigp_type);
                }
                break;
            case BGPTYPE_LINK_STATE_ATTR:
            case BGPTYPE_LINK_STATE_OLD_ATTR:
                q = o + i + aoff;
                end = o + i + aoff + tlen;
                /* FF: BGPTYPE_LINK_STATE_ATTR body dissection is moved after the while.
                   Here we just save the TLV coordinates and the subtree. */
                save_link_state_attr_position(pinfo, q, end, tlen, subtree2);
                break;

            case BGPTYPE_LARGE_COMMUNITY:
                if(tlen == 0 || tlen % 12){
                    break;
                }
                q = o + i + aoff;
                end = q + tlen;
                wmem_strbuf_t *comm_strbuf;
                comm_strbuf = wmem_strbuf_new_label(pinfo->pool);
                while (q < end) {
                    guint32 ga, ldp1, ldp2;
                    ga = tvb_get_ntohl(tvb, q);
                    ldp1 = tvb_get_ntohl(tvb, q+4);
                    ldp2 = tvb_get_ntohl(tvb, q+8);
                    ti = proto_tree_add_string_format(subtree2, hf_bgp_large_communities, tvb, q, 12, NULL, "Large communities: %u:%u:%u", ga, ldp1, ldp2);
                    subtree3 = proto_item_add_subtree(ti, ett_bgp_large_communities);
                    proto_tree_add_item(subtree3, hf_bgp_large_communities_ga, tvb,
                                            q, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(subtree3, hf_bgp_large_communities_ldp1, tvb,
                                            q + 4, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(subtree3, hf_bgp_large_communities_ldp2, tvb,
                                            q + 8, 4, ENC_BIG_ENDIAN);
                    wmem_strbuf_append_printf(comm_strbuf, " %u:%u:%u", ga, ldp1, ldp2);
                    q += 12;
                }

                proto_item_append_text(ti_pa, ":%s", wmem_strbuf_get_str(comm_strbuf));

                break;
            case BGPTYPE_BGPSEC_PATH:
                q = o + i + aoff;
                end = q + tlen;
                secpathlen = tvb_get_ntohs(tvb, q); /* Secure Path Length */

                if (((secpathlen - 2) % SEC_PATH_SEG_SIZE) != 0) { /* SEC_PATH_SEG_SIZE = 6 */
                    proto_tree_add_expert_format(subtree2, pinfo, &ei_bgp_length_invalid, tvb, o + i + aoff, alen,
                        "Invalid BGPsec Secure Path length: %u bytes", secpathlen);
                }

                subtree3 = proto_tree_add_subtree_format(subtree2, tvb, q, secpathlen,
                                                         ett_bgp_bgpsec_secure_path,
                                                         NULL,
                                                         "Secure Path (%d byte%s)",
                                                         secpathlen,
                                                         plurality(secpathlen, "", "s"));

                /* Secure Path Length */
                proto_tree_add_item(subtree3, hf_bgp_update_path_attribute_bgpsec_sp_len, tvb, q, 2, ENC_BIG_ENDIAN);
                q += 2;

                secpathcount = (secpathlen - 2) / SEC_PATH_SEG_SIZE; /* Amount of Secure Path Segments */
                j = 0;
                while (j < secpathcount) {
                    subtree4 = proto_tree_add_subtree_format(subtree3, tvb, q, SEC_PATH_SEG_SIZE,
                                                             ett_bgp_bgpsec_secure_path_segment,
                                                             NULL,
                                                             "Secure Path Segment (%d byte%s)",
                                                             SEC_PATH_SEG_SIZE,
                                                             plurality(SEC_PATH_SEG_SIZE, "", "s"));

                    /* pCount field */
                    proto_tree_add_item(subtree4, hf_bgp_update_path_attribute_bgpsec_sps_pcount, tvb,
                                        q, 1, ENC_BIG_ENDIAN);
                    q += 1;

                    /* Flags field */
                    proto_tree_add_item(subtree4, hf_bgp_update_path_attribute_bgpsec_sps_flags, tvb,
                                        q, 1, ENC_BIG_ENDIAN);
                    q += 1;

                    /* ASN field */
                    proto_tree_add_item(subtree4, hf_bgp_update_path_attribute_bgpsec_sps_as, tvb,
                                        q, 4, ENC_BIG_ENDIAN);
                    q += 4;
                    j++;
                }

                sigblocklen = tvb_get_ntohs(tvb, q); /* Signature Block Length */

                subtree3 = proto_tree_add_subtree_format(subtree2, tvb, q, sigblocklen,
                                                         ett_bgp_bgpsec_signature_block,
                                                         NULL,
                                                         "Signature Block (%d byte%s)",
                                                         sigblocklen,
                                                         plurality(sigblocklen, "", "s"));

                /* Signature Block Length */
                proto_tree_add_item(subtree3, hf_bgp_update_path_attribute_bgpsec_sb_len, tvb, q, 2, ENC_BIG_ENDIAN);
                q += 2;

                /* Algorithm Suite ID */
                proto_tree_add_item(subtree3, hf_bgp_update_path_attribute_bgpsec_algo_id, tvb, q, 1, ENC_BIG_ENDIAN);
                q += 1;

                while (q < end) {
                    sig_len = tvb_get_ntohs(tvb, q+20); /* Signature Length of current Segment */

                    subtree4 = proto_tree_add_subtree_format(subtree3, tvb, q, 22+sig_len,
                                                             ett_bgp_bgpsec_signature_segment,
                                                             NULL,
                                                             "Signature Segment (%d byte%s)",
                                                             22+sig_len,
                                                             plurality(22+sig_len, "", "s"));

                    /* Subject Key Identifier */
                    proto_tree_add_item(subtree4, hf_bgp_update_path_attribute_bgpsec_ski, tvb,
                                        q, 20, ENC_NA);
                    q += 20;

                    /* Signature Length */
                    proto_tree_add_item(subtree4, hf_bgp_update_path_attribute_bgpsec_sig_len, tvb,
                                        q, 2, ENC_BIG_ENDIAN);
                    q += 2;

                    /* Signature */
                    proto_tree_add_item(subtree4, hf_bgp_update_path_attribute_bgpsec_sig, tvb,
                                        q, sig_len, ENC_NA);
                    q += sig_len;
                }

                break;
            case BGPTYPE_BGP_PREFIX_SID:
                q = o + i + aoff;
                end = q + tlen;
                proto_item    *tlv_item, *stlv_item, *sstlv_item;
                proto_tree    *tlv_tree, *stlv_tree, *sstlv_tree;
                proto_item    *srgb_tlv_item;
                proto_tree    *srgb_tlv_tree;
                proto_item    *srv6_stlv_item;
                proto_tree    *srv6_stlv_tree;
                proto_item    *srv6_data_sstlv_item;
                proto_tree    *srv6_data_sstlv_tree;
                gint sub_pnt, sub_end;
                gint sub_sub_pnt, sub_sub_end;
                while (q < end) {
                    prefix_sid_subtype = tvb_get_guint8(tvb, q);
                    prefix_sid_sublen = tvb_get_ntohs(tvb, q + 1);
                    switch (prefix_sid_subtype) {
                        case BGP_PREFIX_SID_TLV_LABEL_INDEX:
                            tlv_item = proto_tree_add_item(subtree2, hf_bgp_prefix_sid_label_index, tvb, q , prefix_sid_sublen + 3, ENC_NA);
                            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_prefix_sid_label_index);
                            proto_tree_add_item(tlv_tree, hf_bgp_prefix_sid_type, tvb, q, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(tlv_tree, hf_bgp_prefix_sid_length, tvb, q + 1, 2, ENC_BIG_ENDIAN);
                            if (prefix_sid_sublen != BGP_PREFIX_SID_TLV_LEN_LABEL_INDEX){
                                proto_tree_add_expert_format(subtree2, pinfo, &ei_bgp_length_invalid, tvb, o + i + aoff, alen,
                                    "Invalid BGP Prefix-SID Label Index length: %u bytes", prefix_sid_sublen);
                                q += 3 + prefix_sid_sublen;
                                break;
                            }
                            proto_tree_add_item(tlv_tree, hf_bgp_prefix_sid_reserved, tvb, q + 3, 1, ENC_NA);
                            proto_tree_add_item(tlv_tree, hf_bgp_prefix_sid_label_index_flags, tvb, q + 4, 2, ENC_BIG_ENDIAN);
                            proto_tree_add_item(tlv_tree, hf_bgp_prefix_sid_label_index_value, tvb, q + 6, 4, ENC_BIG_ENDIAN);
                            proto_item_append_text(tlv_tree, ": %u ", tvb_get_ntohl(tvb, q + 6));
                            q += 10;
                            break;
                        case BGP_PREFIX_SID_TLV_ORIGINATOR_SRGB:
                            check_srgb = prefix_sid_sublen - 2;
                            prefix_sid_sub_tlv_offset = 0;
                            tlv_item = proto_tree_add_item(subtree2, hf_bgp_prefix_sid_originator_srgb, tvb, q , prefix_sid_sublen + 3, ENC_NA);
                            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_prefix_sid_originator_srgb);
                            proto_tree_add_item(tlv_tree, hf_bgp_prefix_sid_type, tvb, q, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(tlv_tree, hf_bgp_prefix_sid_length, tvb, q + 1, 2, ENC_BIG_ENDIAN);
                            if(check_srgb % 3 || check_srgb % 2){
                                proto_tree_add_expert_format(subtree2, pinfo, &ei_bgp_length_invalid, tvb, o + i + aoff, alen,
                                    "Invalid BGP Prefix-SID SRGB Originator length: %u bytes", prefix_sid_sublen);
                                q += 3 + prefix_sid_sublen;
                                break;
                            }
                            proto_tree_add_item(tlv_tree, hf_bgp_prefix_sid_originator_srgb_flags, tvb, q + 3, 2, ENC_BIG_ENDIAN);
                            q += 2;
                            tlv_item = proto_tree_add_item(tlv_tree, hf_bgp_prefix_sid_originator_srgb_blocks, tvb, q , prefix_sid_sublen - 2, ENC_NA);
                            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_prefix_sid_originator_srgb_blocks);
                            while (prefix_sid_sublen > prefix_sid_sub_tlv_offset + 2) {
                                srgb_tlv_item = proto_tree_add_item(tlv_tree, hf_bgp_prefix_sid_originator_srgb_block, tvb, q , prefix_sid_sublen - 2, ENC_NA);
                                srgb_tlv_tree = proto_item_add_subtree(srgb_tlv_item, ett_bgp_prefix_sid_originator_srgb_block);
                                prefix_sid_sub_tlv_offset += 3;
                                proto_tree_add_item(srgb_tlv_tree, hf_bgp_prefix_sid_originator_srgb_base, tvb, q + prefix_sid_sub_tlv_offset, 3, ENC_BIG_ENDIAN);
                                prefix_sid_sub_tlv_offset += 3;
                                proto_tree_add_item(srgb_tlv_tree, hf_bgp_prefix_sid_originator_srgb_range, tvb, q + prefix_sid_sub_tlv_offset, 3, ENC_BIG_ENDIAN);
                                proto_item_append_text(srgb_tlv_tree, "(%u:%u)", tvb_get_ntoh24(tvb, q + prefix_sid_sub_tlv_offset - 3),
                                    tvb_get_ntoh24(tvb, q + prefix_sid_sub_tlv_offset));
                            }
                            q += 3 + prefix_sid_sublen;
                            break;
                        case BGP_PREFIX_SID_TLV_SRV6_L3_SERVICE:
                            tlv_item = proto_tree_add_item(subtree2, hf_bgp_prefix_sid_srv6_l3vpn, tvb, q , prefix_sid_sublen + 3, ENC_NA);
                            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_prefix_sid_srv6_l3vpn);
                            proto_tree_add_item(tlv_tree, hf_bgp_prefix_sid_type, tvb, q, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(tlv_tree, hf_bgp_prefix_sid_length, tvb, q + 1, 2, ENC_BIG_ENDIAN);
                            proto_tree_add_item(tlv_tree, hf_bgp_prefix_sid_reserved, tvb, q + 3, 1, ENC_NA);

                            srv6_stlv_item = proto_tree_add_item(tlv_tree, hf_bgp_prefix_sid_srv6_l3vpn_sub_tlvs, tvb, q + 4, prefix_sid_sublen - 1, ENC_NA);
                            srv6_stlv_tree = proto_item_add_subtree(srv6_stlv_item, ett_bgp_prefix_sid_srv6_l3vpn_sub_tlvs);

                            sub_pnt = q + 4;
                            sub_end = q + 3 + prefix_sid_sublen;
                            while (sub_pnt < sub_end) {
                                srv6_service_subtlv_type = tvb_get_guint8(tvb, sub_pnt);
                                srv6_service_subtlv_len = tvb_get_ntohs(tvb, sub_pnt + 1);

                                switch (srv6_service_subtlv_type) {
                                    case SRV6_SERVICE_SRV6_SID_INFORMATION:
                                        stlv_item = proto_tree_add_item(srv6_stlv_tree,
                                                                        hf_bgp_prefix_sid_srv6_l3vpn_sub_tlv,
                                                                        tvb, sub_pnt , srv6_service_subtlv_len + 3, ENC_NA);
                                        proto_item_append_text(stlv_item, " - %s",
                                                               val_to_str(srv6_service_subtlv_type, srv6_service_sub_tlv_type, "Unknown (%u)"));
                                        stlv_tree = proto_item_add_subtree(stlv_item, ett_bgp_prefix_sid_srv6_l3vpn_sid_information);

                                        proto_tree_add_item(stlv_tree, hf_bgp_prefix_sid_srv6_l3vpn_sub_tlv_type, tvb, sub_pnt, 1, ENC_BIG_ENDIAN);
                                        proto_tree_add_item(stlv_tree, hf_bgp_prefix_sid_srv6_l3vpn_sub_tlv_length, tvb, sub_pnt + 1, 2, ENC_BIG_ENDIAN);
                                        proto_tree_add_item(stlv_tree, hf_bgp_prefix_sid_srv6_l3vpn_sub_tlv_reserved, tvb, sub_pnt + 3, 1, ENC_NA);
                                        proto_tree_add_item(stlv_tree, hf_bgp_prefix_sid_srv6_l3vpn_sid_value, tvb, sub_pnt + 4, 16, ENC_NA);
                                        proto_tree_add_item(stlv_tree, hf_bgp_prefix_sid_srv6_l3vpn_sid_flags, tvb, sub_pnt + 20, 1, ENC_NA);
                                        proto_tree_add_item(stlv_tree, hf_bgp_prefix_sid_srv6_l3vpn_srv6_endpoint_behavior, tvb, sub_pnt + 21, 2, ENC_NA);
                                        proto_tree_add_item(stlv_tree, hf_bgp_prefix_sid_srv6_l3vpn_reserved, tvb, sub_pnt + 23, 1, ENC_NA);

                                        srv6_data_sstlv_item = proto_tree_add_item(stlv_tree,
                                                                                   hf_bgp_prefix_sid_srv6_l3vpn_sub_sub_tlvs,
                                                                                   tvb, sub_pnt + 24, srv6_service_subtlv_len - 21, ENC_NA);
                                        srv6_data_sstlv_tree = proto_item_add_subtree(srv6_data_sstlv_item, ett_bgp_prefix_sid_srv6_l3vpn_sub_sub_tlvs);

                                        sub_sub_pnt = sub_pnt + 24;
                                        sub_sub_end = sub_pnt + 3 + srv6_service_subtlv_len;
                                        while (sub_sub_pnt < sub_sub_end) {
                                            srv6_service_data_subsubtlv_type = tvb_get_guint8(tvb, sub_sub_pnt);
                                            srv6_service_data_subsubtlv_len = tvb_get_ntohs(tvb, sub_sub_pnt + 1);

                                            switch (srv6_service_data_subsubtlv_type) {
                                                case SRV6_SERVICE_DATA_SRV6_SID_STRUCTURE:
                                                    sstlv_item = proto_tree_add_item(srv6_data_sstlv_tree,
                                                                                     hf_bgp_prefix_sid_srv6_l3vpn_sub_sub_tlv,
                                                                                     tvb, sub_sub_pnt , srv6_service_data_subsubtlv_len + 3, ENC_NA);
                                                    proto_item_append_text(sstlv_item, " - %s",
                                                                           val_to_str(srv6_service_data_subsubtlv_type, srv6_service_data_sub_sub_tlv_type, "Unknown (%u)"));
                                                    sstlv_tree = proto_item_add_subtree(sstlv_item, ett_bgp_prefix_sid_srv6_l3vpn_sid_structure);

                                                    proto_tree_add_item(sstlv_tree, hf_bgp_prefix_sid_srv6_l3vpn_sub_sub_tlv_type, tvb, sub_sub_pnt, 1, ENC_BIG_ENDIAN);
                                                    proto_tree_add_item(sstlv_tree, hf_bgp_prefix_sid_srv6_l3vpn_sub_sub_tlv_length, tvb, sub_sub_pnt + 1, 2, ENC_BIG_ENDIAN);
                                                    proto_tree_add_item(sstlv_tree, hf_bgp_prefix_sid_srv6_l3vpn_sid_locator_block_len, tvb, sub_sub_pnt + 3, 1, ENC_BIG_ENDIAN);
                                                    proto_tree_add_item(sstlv_tree, hf_bgp_prefix_sid_srv6_l3vpn_sid_locator_node_len, tvb, sub_sub_pnt + 4, 1, ENC_BIG_ENDIAN);
                                                    proto_tree_add_item(sstlv_tree, hf_bgp_prefix_sid_srv6_l3vpn_sid_func_len, tvb, sub_sub_pnt + 5, 1, ENC_BIG_ENDIAN);
                                                    proto_tree_add_item(sstlv_tree, hf_bgp_prefix_sid_srv6_l3vpn_sid_arg_len, tvb, sub_sub_pnt + 6, 1, ENC_BIG_ENDIAN);
                                                    proto_tree_add_item(sstlv_tree, hf_bgp_prefix_sid_srv6_l3vpn_sid_trans_len, tvb, sub_sub_pnt + 7, 1, ENC_BIG_ENDIAN);
                                                    proto_tree_add_item(sstlv_tree, hf_bgp_prefix_sid_srv6_l3vpn_sid_trans_offset, tvb, sub_sub_pnt + 8, 1, ENC_BIG_ENDIAN);
                                                    break;
                                                default:
                                                    sstlv_item = proto_tree_add_item(srv6_data_sstlv_tree,
                                                                                     hf_bgp_prefix_sid_srv6_l3vpn_sub_sub_tlv,
                                                                                     tvb, sub_sub_pnt , srv6_service_data_subsubtlv_len + 3, ENC_NA);
                                                    proto_item_append_text(sstlv_item, " - %s",
                                                                           val_to_str(srv6_service_data_subsubtlv_type, srv6_service_data_sub_sub_tlv_type, "Unknown (%u)"));
                                                    sstlv_tree = proto_item_add_subtree(sstlv_item, ett_bgp_prefix_sid_srv6_l3vpn_sid_unknown);

                                                    proto_tree_add_item(sstlv_tree, hf_bgp_prefix_sid_srv6_l3vpn_sub_sub_tlv_type, tvb, sub_sub_pnt, 1, ENC_BIG_ENDIAN);
                                                    proto_tree_add_item(sstlv_tree, hf_bgp_prefix_sid_srv6_l3vpn_sub_sub_tlv_length, tvb, sub_sub_pnt + 1, 2, ENC_BIG_ENDIAN);
                                                    proto_tree_add_item(sstlv_tree, hf_bgp_prefix_sid_srv6_l3vpn_sub_sub_tlv_value, tvb, sub_sub_pnt + 3, srv6_service_data_subsubtlv_len, ENC_NA);
                                                    break;
                                            }
                                            sub_sub_pnt += 3 + srv6_service_data_subsubtlv_len;
                                        }
                                        break;
                                    default:
                                        stlv_item = proto_tree_add_item(srv6_stlv_tree,
                                                                        hf_bgp_prefix_sid_srv6_l3vpn_sub_tlv,
                                                                        tvb, sub_pnt , srv6_service_subtlv_len + 3, ENC_NA);
                                        proto_item_append_text(stlv_item, " - %s", val_to_str(srv6_service_subtlv_type, srv6_service_sub_tlv_type, "Unknown (%u)"));
                                        stlv_tree = proto_item_add_subtree(stlv_item, ett_bgp_prefix_sid_srv6_l3vpn_unknown);

                                        proto_tree_add_item(stlv_tree, hf_bgp_prefix_sid_srv6_l3vpn_sub_tlv_type, tvb, sub_pnt, 1, ENC_BIG_ENDIAN);
                                        proto_tree_add_item(stlv_tree, hf_bgp_prefix_sid_srv6_l3vpn_sub_tlv_length, tvb, sub_pnt + 1, 2, ENC_BIG_ENDIAN);
                                        proto_tree_add_item(stlv_tree, hf_bgp_prefix_sid_srv6_l3vpn_sub_tlv_value, tvb, sub_pnt + 3, srv6_service_subtlv_len, ENC_NA);
                                        break;
                                }
                                sub_pnt += 3 + srv6_service_subtlv_len;
                            }
                            q += (3 + prefix_sid_sublen);
                            break;
                        case BGP_PREFIX_SID_TLV_SRV6_L2_SERVICE:
                            tlv_item = proto_tree_add_item(subtree2, hf_bgp_prefix_sid_srv6_l2vpn, tvb, q , prefix_sid_sublen + 3, ENC_NA);
                            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_prefix_sid_srv6_l2vpn);
                            proto_tree_add_item(tlv_tree, hf_bgp_prefix_sid_type, tvb, q, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(tlv_tree, hf_bgp_prefix_sid_length, tvb, q + 1, 2, ENC_BIG_ENDIAN);
                            proto_tree_add_item(tlv_tree, hf_bgp_prefix_sid_reserved, tvb, q + 3, 1, ENC_NA);

                            srv6_stlv_item = proto_tree_add_item(tlv_tree, hf_bgp_prefix_sid_srv6_l2vpn_sub_tlvs, tvb, q + 4, prefix_sid_sublen - 1, ENC_NA);
                            srv6_stlv_tree = proto_item_add_subtree(srv6_stlv_item, ett_bgp_prefix_sid_srv6_l2vpn_sub_tlvs);

                            sub_pnt = q + 4;
                            sub_end = q + 3 + prefix_sid_sublen;
                            while (sub_pnt < sub_end) {
                                srv6_service_subtlv_type = tvb_get_guint8(tvb, sub_pnt);
                                srv6_service_subtlv_len = tvb_get_ntohs(tvb, sub_pnt + 1);

                                switch (srv6_service_subtlv_type) {
                                    case SRV6_SERVICE_SRV6_SID_INFORMATION:
                                        stlv_item = proto_tree_add_item(srv6_stlv_tree,
                                                                        hf_bgp_prefix_sid_srv6_l2vpn_sub_tlv,
                                                                        tvb, sub_pnt , srv6_service_subtlv_len + 3, ENC_NA);
                                        proto_item_append_text(stlv_item, " - %s",
                                                               val_to_str(srv6_service_subtlv_type, srv6_service_sub_tlv_type, "Unknown (%u)"));
                                        stlv_tree = proto_item_add_subtree(stlv_item, ett_bgp_prefix_sid_srv6_l2vpn_sid_information);

                                        proto_tree_add_item(stlv_tree, hf_bgp_prefix_sid_srv6_l2vpn_sub_tlv_type, tvb, sub_pnt, 1, ENC_BIG_ENDIAN);
                                        proto_tree_add_item(stlv_tree, hf_bgp_prefix_sid_srv6_l2vpn_sub_tlv_length, tvb, sub_pnt + 1, 2, ENC_BIG_ENDIAN);
                                        proto_tree_add_item(stlv_tree, hf_bgp_prefix_sid_srv6_l2vpn_sub_tlv_reserved, tvb, sub_pnt + 3, 1, ENC_NA);
                                        proto_tree_add_item(stlv_tree, hf_bgp_prefix_sid_srv6_l2vpn_sid_value, tvb, sub_pnt + 4, 16, ENC_NA);
                                        proto_tree_add_item(stlv_tree, hf_bgp_prefix_sid_srv6_l2vpn_sid_flags, tvb, sub_pnt + 20, 1, ENC_NA);
                                        proto_tree_add_item(stlv_tree, hf_bgp_prefix_sid_srv6_l2vpn_srv6_endpoint_behavior, tvb, sub_pnt + 21, 2, ENC_NA);
                                        proto_tree_add_item(stlv_tree, hf_bgp_prefix_sid_srv6_l2vpn_reserved, tvb, sub_pnt + 23, 1, ENC_NA);

                                        srv6_data_sstlv_item = proto_tree_add_item(stlv_tree,
                                                                                   hf_bgp_prefix_sid_srv6_l2vpn_sub_sub_tlvs,
                                                                                   tvb, sub_pnt + 24, srv6_service_subtlv_len - 21, ENC_NA);
                                        srv6_data_sstlv_tree = proto_item_add_subtree(srv6_data_sstlv_item, ett_bgp_prefix_sid_srv6_l2vpn_sub_sub_tlvs);

                                        sub_sub_pnt = sub_pnt + 24;
                                        sub_sub_end = sub_pnt + 3 + srv6_service_subtlv_len;
                                        while (sub_sub_pnt < sub_sub_end) {
                                            srv6_service_data_subsubtlv_type = tvb_get_guint8(tvb, sub_sub_pnt);
                                            srv6_service_data_subsubtlv_len = tvb_get_ntohs(tvb, sub_sub_pnt + 1);

                                            switch (srv6_service_data_subsubtlv_type) {
                                                case SRV6_SERVICE_DATA_SRV6_SID_STRUCTURE:
                                                    sstlv_item = proto_tree_add_item(srv6_data_sstlv_tree,
                                                                                     hf_bgp_prefix_sid_srv6_l2vpn_sub_sub_tlv,
                                                                                     tvb, sub_sub_pnt , srv6_service_data_subsubtlv_len + 3, ENC_NA);
                                                    proto_item_append_text(sstlv_item, " - %s",
                                                                           val_to_str(srv6_service_data_subsubtlv_type, srv6_service_data_sub_sub_tlv_type, "Unknown (%u)"));
                                                    sstlv_tree = proto_item_add_subtree(sstlv_item, ett_bgp_prefix_sid_srv6_l2vpn_sid_structure);

                                                    proto_tree_add_item(sstlv_tree, hf_bgp_prefix_sid_srv6_l2vpn_sub_sub_tlv_type, tvb, sub_sub_pnt, 1, ENC_BIG_ENDIAN);
                                                    proto_tree_add_item(sstlv_tree, hf_bgp_prefix_sid_srv6_l2vpn_sub_sub_tlv_length, tvb, sub_sub_pnt + 1, 2, ENC_BIG_ENDIAN);
                                                    proto_tree_add_item(sstlv_tree, hf_bgp_prefix_sid_srv6_l2vpn_sid_locator_block_len, tvb, sub_sub_pnt + 3, 1, ENC_BIG_ENDIAN);
                                                    proto_tree_add_item(sstlv_tree, hf_bgp_prefix_sid_srv6_l2vpn_sid_locator_node_len, tvb, sub_sub_pnt + 4, 1, ENC_BIG_ENDIAN);
                                                    proto_tree_add_item(sstlv_tree, hf_bgp_prefix_sid_srv6_l2vpn_sid_func_len, tvb, sub_sub_pnt + 5, 1, ENC_BIG_ENDIAN);
                                                    proto_tree_add_item(sstlv_tree, hf_bgp_prefix_sid_srv6_l2vpn_sid_arg_len, tvb, sub_sub_pnt + 6, 1, ENC_BIG_ENDIAN);
                                                    proto_tree_add_item(sstlv_tree, hf_bgp_prefix_sid_srv6_l2vpn_sid_trans_len, tvb, sub_sub_pnt + 7, 1, ENC_BIG_ENDIAN);
                                                    proto_tree_add_item(sstlv_tree, hf_bgp_prefix_sid_srv6_l2vpn_sid_trans_offset, tvb, sub_sub_pnt + 8, 1, ENC_BIG_ENDIAN);
                                                    break;
                                                default:
                                                    sstlv_item = proto_tree_add_item(srv6_data_sstlv_tree,
                                                                                     hf_bgp_prefix_sid_srv6_l2vpn_sub_sub_tlv,
                                                                                     tvb, sub_sub_pnt , srv6_service_data_subsubtlv_len + 3, ENC_NA);
                                                    proto_item_append_text(sstlv_item, " - %s",
                                                                           val_to_str(srv6_service_data_subsubtlv_type, srv6_service_data_sub_sub_tlv_type, "Unknown (%u)"));
                                                    sstlv_tree = proto_item_add_subtree(sstlv_item, ett_bgp_prefix_sid_srv6_l2vpn_sid_unknown);

                                                    proto_tree_add_item(sstlv_tree, hf_bgp_prefix_sid_srv6_l2vpn_sub_sub_tlv_type, tvb, sub_sub_pnt, 1, ENC_BIG_ENDIAN);
                                                    proto_tree_add_item(sstlv_tree, hf_bgp_prefix_sid_srv6_l2vpn_sub_sub_tlv_length, tvb, sub_sub_pnt + 1, 2, ENC_BIG_ENDIAN);
                                                    proto_tree_add_item(sstlv_tree, hf_bgp_prefix_sid_srv6_l2vpn_sub_sub_tlv_value, tvb, sub_sub_pnt + 3, srv6_service_data_subsubtlv_len, ENC_NA);
                                                    break;
                                            }
                                            sub_sub_pnt += 3 + srv6_service_data_subsubtlv_len;
                                        }
                                        break;
                                    default:
                                        stlv_item = proto_tree_add_item(srv6_stlv_tree,
                                                                        hf_bgp_prefix_sid_srv6_l2vpn_sub_tlv,
                                                                        tvb, sub_pnt , srv6_service_subtlv_len + 3, ENC_NA);
                                        proto_item_append_text(stlv_item, " - %s", val_to_str(srv6_service_subtlv_type, srv6_service_sub_tlv_type, "Unknown (%u)"));
                                        stlv_tree = proto_item_add_subtree(stlv_item, ett_bgp_prefix_sid_srv6_l2vpn_unknown);

                                        proto_tree_add_item(stlv_tree, hf_bgp_prefix_sid_srv6_l2vpn_sub_tlv_type, tvb, sub_pnt, 1, ENC_BIG_ENDIAN);
                                        proto_tree_add_item(stlv_tree, hf_bgp_prefix_sid_srv6_l2vpn_sub_tlv_length, tvb, sub_pnt + 1, 2, ENC_BIG_ENDIAN);
                                        proto_tree_add_item(stlv_tree, hf_bgp_prefix_sid_srv6_l2vpn_sub_tlv_value, tvb, sub_pnt + 3, srv6_service_subtlv_len, ENC_NA);
                                        break;
                                }
                                sub_pnt += 3 + srv6_service_subtlv_len;
                            }
                            q += (3 + prefix_sid_sublen);
                            break;
                        default:
                            tlv_item = proto_tree_add_item(subtree2, hf_bgp_prefix_sid_unknown, tvb, q, prefix_sid_sublen + 3, ENC_NA);
                            proto_item_append_text(tlv_item, " (%s)", val_to_str(prefix_sid_subtype, bgp_prefix_sid_type, "%u"));
                            tlv_tree = proto_item_add_subtree(tlv_item, ett_bgp_prefix_sid_unknown);
                            proto_tree_add_item(tlv_tree, hf_bgp_prefix_sid_type, tvb, q, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(tlv_tree, hf_bgp_prefix_sid_length, tvb, q + 1, 2, ENC_BIG_ENDIAN);
                            proto_tree_add_item(tlv_tree, hf_bgp_prefix_sid_value, tvb, q + 3, prefix_sid_sublen - 3, ENC_NA);
                            q += (3 + prefix_sid_sublen);
                            break;
                    }
                }
                break;
            case BGPTYPE_PMSI_TUNNEL_ATTR:
                dissect_bgp_update_pmsi_attr(pinfo, subtree2, tvb, tlen, o+i+aoff);
                break;

            case BGPTYPE_ATTR_SET:
                if (alen >= 4) {
                    proto_tree_add_item(subtree2, hf_bgp_update_path_attribute_attrset_origin_as, tvb,
                                        o + i + aoff, 4, ENC_BIG_ENDIAN);
                    if (alen > 4) {
                        ti =  proto_tree_add_item(subtree2, hf_bgp_update_path_attributes, tvb, o+i+aoff+4, alen-4, ENC_NA);
                        attr_set_subtree = proto_item_add_subtree(ti, ett_bgp_attrs);
                        dissect_bgp_path_attr(attr_set_subtree, tvb, alen-4, o+i+aoff+4, pinfo);
                    }
                } else {
                    proto_tree_add_expert_format(subtree2, pinfo, &ei_bgp_length_invalid, tvb, o + i + aoff, alen,
                                                 "Attribute set (invalid): %u bytes%s",
                                                 alen, plurality(alen, "", "s"));
                }
                break;
            case BGPTYPE_D_PATH:
                if(tlen < 8){
                    proto_tree_add_expert_format(subtree2, pinfo, &ei_bgp_length_invalid, tvb, o + i + aoff, tlen,
                                                 "D-PATH attribute has invalid length (invalid): %u byte%s", tlen,
                                                 plurality(tlen, "", "s"));
                    break;
                }
                q = o + i + aoff;
                end = q + tlen;
                wmem_strbuf_t *dpath_strbuf;
                dpath_strbuf = wmem_strbuf_new_label(pinfo->pool);
                guint8 dpath_len;
                dpath_len = tvb_get_guint8(tvb, q);
                proto_tree_add_item(subtree2, hf_bgp_d_path_length, tvb,
                                        q, 1, ENC_BIG_ENDIAN);
                q += 1;
                while (dpath_len > 0 && q < end) {
                    guint32 ad;
                    guint16 ld;
                    ad = tvb_get_ntohl(tvb, q);
                    ld = tvb_get_ntohs(tvb, q+4);
                    ti = proto_tree_add_string_format(subtree2, hf_bgp_update_path_attribute_d_path, tvb, q, 6, NULL, "Domain ID: %u:%u", ad, ld);
                    subtree3 = proto_item_add_subtree(ti, ett_bgp_dpath);
                    proto_tree_add_item(subtree3, hf_bgp_d_path_ga, tvb,
                                        q, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(subtree3, hf_bgp_d_path_la, tvb,
                                        q + 4, 2, ENC_BIG_ENDIAN);
                    wmem_strbuf_append_printf(dpath_strbuf, " %u:%u", ad, ld);
                    q += 6;
                    dpath_len -= 1;
                }
                if (dpath_len != 0 || q >= end) {
                    proto_tree_add_expert_format(subtree2, pinfo, &ei_bgp_length_invalid, tvb, o + i + aoff, tlen,
                                                 "D-PATH list (invalid): %u byte%s", tlen,
                                                 plurality(tlen, "", "s"));
                    break;
                }
                proto_item_append_text(ti_pa, ":%s", wmem_strbuf_get_str(dpath_strbuf));

                proto_tree_add_item(subtree2, hf_bgp_d_path_isf_safi, tvb,
                                    q, 1, ENC_BIG_ENDIAN);
                break;
            default:
                proto_tree_add_item(subtree2, hf_bgp_update_path_attributes_unknown, tvb, o + i + aoff, tlen, ENC_NA);
                break;
        } /* switch (bgpa.bgpa_type) */ /* end of second switch */

        i += alen + aoff;
    }
    {
        /* FF: postponed BGPTYPE_LINK_STATE_ATTR dissection */
        link_state_data *data = load_link_state_data(pinfo);
        if (data && data->link_state_attr_present) {
            ti = proto_tree_add_item(data->subtree2, hf_bgp_update_path_attribute_link_state, tvb, data->ostart, data->tlen, ENC_NA);
            subtree3 = proto_item_add_subtree(ti, ett_bgp_link_state);
            while (data->ostart < data->oend) {
                advance = decode_link_state_attribute_tlv(subtree3, tvb, data->ostart, pinfo, data->protocol_id);
                if (advance < 0) {
                    break;
                }
                data->ostart += advance;
            }
        }
    }
}
/*
 * Dissect a BGP UPDATE message.
 */
static void
dissect_bgp_update(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo)
{
    guint16         hlen;                       /* message length           */
    gint            o;                          /* packet offset            */
    gint            end=0;                      /* message end              */
    guint16         len;                        /* tmp                      */
    proto_item      *ti;                        /* tree item                */
    proto_tree      *subtree;                   /* subtree for attributes   */
    int             i;                          /* tmp                      */

    hlen = tvb_get_ntohs(tvb, BGP_MARKER_SIZE);
    o = BGP_HEADER_SIZE;


    /* check for withdrawals */
    len = tvb_get_ntohs(tvb, o);
    proto_tree_add_item(tree, hf_bgp_update_withdrawn_routes_length, tvb, o, 2, ENC_BIG_ENDIAN);
    o += 2;

    /* parse unfeasible prefixes */
    if (len > 0) {
        ti = proto_tree_add_item(tree, hf_bgp_update_withdrawn_routes, tvb, o, len, ENC_NA);
        subtree = proto_item_add_subtree(ti, ett_bgp_unfeas);

        /* parse each prefix */
        end = o + len;

        /* Heuristic to detect if IPv4 prefix are using Path Identifiers */
        if( detect_add_path_prefix4(tvb, o, end) ) {
            /* IPv4 prefixes with Path Id */
            while (o < end) {
                i = decode_path_prefix4(subtree, pinfo, hf_bgp_nlri_path_id, hf_bgp_withdrawn_prefix, tvb, o,
                    "Withdrawn route");
                if (i < 0)
                    return;
                o += i;
            }
        } else {
            while (o < end) {
                i = decode_prefix4(subtree, pinfo, NULL, hf_bgp_withdrawn_prefix, tvb, o,
                    "Withdrawn route");
                if (i < 0)
                    return;
                o += i;
            }
        }
    }

    /* check for advertisements */
    len = tvb_get_ntohs(tvb, o);
    proto_tree_add_item(tree, hf_bgp_update_total_path_attribute_length, tvb, o, 2, ENC_BIG_ENDIAN);

    /* path attributes */
    if (len > 0) {
        ti =  proto_tree_add_item(tree, hf_bgp_update_path_attributes, tvb, o+2, len, ENC_NA);
        subtree = proto_item_add_subtree(ti, ett_bgp_attrs);

        dissect_bgp_path_attr(subtree, tvb, len, o+2, pinfo);

        o += 2 + len;

        /* NLRI */
        len = hlen - o;

        /* parse prefixes */
        if (len > 0) {
            ti = proto_tree_add_item(tree, hf_bgp_update_nlri, tvb, o, len, ENC_NA);
            subtree = proto_item_add_subtree(ti, ett_bgp_nlri);
            end = o + len;
            /*
             * Heuristic to detect if IPv4 prefix are using Path Identifiers
             * we need at least 5 bytes for Add-path prefixes
             */
            if( len > 4 && detect_add_path_prefix4(tvb, o, end) ) {
                /* IPv4 prefixes with Path Id */
                while (o < end) {
                    i = decode_path_prefix4(subtree, pinfo, hf_bgp_nlri_path_id, hf_bgp_nlri_prefix, tvb, o,
                                            "NLRI");
                    if (i < 0)
                       return;
                    o += i;
                }
            } else {
                /* Standard prefixes */
                while (o < end) {
                    i = decode_prefix4(subtree, pinfo, NULL, hf_bgp_nlri_prefix, tvb, o, "NLRI");
                    if (i < 0)
                        return;
                    o += i;
                }
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
    guint8                  clen;
    guint8                  minor_cease;


    hlen =  tvb_get_ntohs(tvb, BGP_MARKER_SIZE);
    offset = BGP_MARKER_SIZE + 2 + 1;


    /* print error code */
    proto_tree_add_item(tree, hf_bgp_notify_major_error, tvb, offset, 1, ENC_BIG_ENDIAN);
    major_error = tvb_get_guint8(tvb, offset);
    offset += 1;

    switch(major_error){
        case BGP_MAJOR_ERROR_MSG_HDR:
            proto_tree_add_item(tree, hf_bgp_notify_minor_msg_hdr, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
        case BGP_MAJOR_ERROR_OPEN_MSG:
            proto_tree_add_item(tree, hf_bgp_notify_minor_open_msg, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
        case BGP_MAJOR_ERROR_UPDATE_MSG:
            proto_tree_add_item(tree,hf_bgp_notify_minor_update_msg, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
        case BGP_MAJOR_ERROR_HT_EXPIRED:
            proto_tree_add_item(tree, hf_bgp_notify_minor_ht_expired, tvb, offset,  1, ENC_BIG_ENDIAN);
        break;
        case BGP_MAJOR_ERROR_STATE_MACHINE:
            proto_tree_add_item(tree, hf_bgp_notify_minor_state_machine, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
        case BGP_MAJOR_ERROR_CEASE:
            proto_tree_add_item(tree, hf_bgp_notify_minor_cease, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
        case BGP_MAJOR_ERROR_CAP_MSG:
            proto_tree_add_item(tree, hf_bgp_notify_minor_cap_msg, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
        default:
            ti = proto_tree_add_item(tree, hf_bgp_notify_minor_unknown, tvb, offset, 1, ENC_BIG_ENDIAN);
            expert_add_info_format(pinfo, ti, &ei_bgp_notify_minor_unknown, "Unknown notification error (%d)",major_error);
        break;
    }
    offset += 1;

    /* only print if there is optional data */
    if (hlen > BGP_MIN_NOTIFICATION_MSG_SIZE) {
        minor_cease = tvb_get_guint8(tvb, offset - 1);
        clen = tvb_get_guint8(tvb, offset);
        /* Might be a idr-shutdown communication, first byte is length */
        if (hlen - BGP_MIN_NOTIFICATION_MSG_SIZE - 1 == clen && major_error == BGP_MAJOR_ERROR_CEASE &&
                (minor_cease == BGP_CEASE_MINOR_ADMIN_SHUTDOWN || minor_cease == BGP_CEASE_MINOR_ADMIN_RESET) ) {
            proto_tree_add_item(tree, hf_bgp_notify_communication_length, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(tree, hf_bgp_notify_communication, tvb, offset, clen, ENC_UTF_8);
        /* otherwise just dump the hex data */
        } else if ( major_error == BGP_MAJOR_ERROR_OPEN_MSG && minor_cease == 7 ) {
            while (offset < hlen) {
                offset = dissect_bgp_capability_item(tvb, tree, pinfo, offset, FALSE);
            }
        } else if (major_error == BGP_MAJOR_ERROR_OPEN_MSG && minor_cease == 2 ) { /* Display Bad Peer AS Number */
            proto_tree_add_item(tree, hf_bgp_notify_error_open_bad_peer_as, tvb, offset, hlen - BGP_MIN_NOTIFICATION_MSG_SIZE, ENC_NA);
        } else {
            proto_tree_add_item(tree, hf_bgp_notify_data, tvb, offset, hlen - BGP_MIN_NOTIFICATION_MSG_SIZE, ENC_NA);
        }
    }
}

/*
 * Dissect a BGP ROUTE-REFRESH message.
 */
static void
dissect_bgp_route_refresh(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo)
{
    int             p;         /* tvb offset counter    */
    int             pend;       /* end of list of entries for one orf type */
    guint16         hlen;       /* tvb RR msg length */
    proto_item      *ti;        /* tree item             */
    proto_item      *ti1;       /* tree item             */
    proto_tree      *subtree;   /* tree for orf   */
    proto_tree      *subtree1;  /* tree for orf entry */
    guint8          orftype;    /* ORF Type */
    guint16         orflen;     /* ORF len */
    guint8          entryflag;  /* ORF Entry flag: action(add,del,delall) match(permit,deny) */
    int             entrylen;   /* ORF Entry length */
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

        ti = proto_tree_add_item(tree, hf_bgp_route_refresh_orf, tvb, p, 4, ENC_NA);
        subtree = proto_item_add_subtree(ti, ett_bgp_orf);

        proto_tree_add_item(subtree, hf_bgp_route_refresh_orf_flag, tvb, p, 1, ENC_BIG_ENDIAN);
        p += 1;

        ti1 = proto_tree_add_item(subtree, hf_bgp_route_refresh_orf_type, tvb, p , 1, ENC_BIG_ENDIAN);
        orftype = tvb_get_guint8(tvb, p);
        p += 1;

        proto_tree_add_item(subtree, hf_bgp_route_refresh_orf_length, tvb, p , 2, ENC_BIG_ENDIAN);
        orflen = tvb_get_ntohs(tvb, p);
        proto_item_set_len(ti, orflen + 4);
        p += 2;

        if (orftype != BGP_ORF_PREFIX_CISCO) {
            expert_add_info_format(pinfo, ti1, &ei_bgp_route_refresh_orf_type_unknown, "ORFEntry-Unknown (type %u)", orftype);
            p += orflen;
            continue;
        }
        pend = p + orflen;
        while (p < pend) {

            ti1 = proto_tree_add_item(subtree, hf_bgp_route_refresh_orf_entry_prefixlist, tvb, p, 1, ENC_NA);
            subtree1 = proto_item_add_subtree(ti1, ett_bgp_orf_entry);
            proto_tree_add_item(subtree1, hf_bgp_route_refresh_orf_entry_action, tvb, p, 1, ENC_BIG_ENDIAN);
            entryflag = tvb_get_guint8(tvb, p);
            if (((entryflag & BGP_ORF_ACTION) >> 6) == BGP_ORF_REMOVEALL) {
                p++;
                continue;
            }
            proto_tree_add_item(subtree1, hf_bgp_route_refresh_orf_entry_match, tvb, p, 1, ENC_BIG_ENDIAN);
            p++;

            proto_tree_add_item(subtree1, hf_bgp_route_refresh_orf_entry_sequence, tvb, p, 4, ENC_BIG_ENDIAN);
            p +=4;

            proto_tree_add_item(subtree1, hf_bgp_route_refresh_orf_entry_prefixmask_lower, tvb, p, 1, ENC_BIG_ENDIAN);
            p++;

            proto_tree_add_item(subtree1, hf_bgp_route_refresh_orf_entry_prefixmask_upper, tvb, p, 1, ENC_BIG_ENDIAN);
            p++;

            advance = decode_prefix4(subtree1, pinfo, NULL, hf_bgp_route_refresh_orf_entry_ip, tvb, p, "ORF");
            if (advance < 0)
                    break;
            entrylen = 7 + 1 + advance;

            proto_item_set_len(ti1, entrylen);
            p += advance;

        }
    }
}

static void
dissect_bgp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                gboolean first)
{
    guint16       bgp_len;          /* Message length             */
    guint8        bgp_type;         /* Message type               */
    const char    *typ;             /* Message type (string)      */
    proto_item    *ti_marker = NULL;/* marker item                */
    proto_item    *ti_len = NULL;   /* length item                */
    proto_tree    *bgp_tree = NULL; /* BGP packet tree            */
    static const guint8 valid_marker[BGP_MARKER_SIZE] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };

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

        ti_marker = proto_tree_add_item(bgp_tree, hf_bgp_marker, tvb, 0,
          BGP_MARKER_SIZE, ENC_NA);
        if (tvb_memeql(tvb, 0, valid_marker, BGP_MARKER_SIZE) != 0) {
             expert_add_info(pinfo, ti_marker, &ei_bgp_marker_invalid);
        }

        ti_len = proto_tree_add_item(bgp_tree, hf_bgp_length, tvb, 16, 2, ENC_BIG_ENDIAN);
    }

    if (bgp_len < BGP_HEADER_SIZE || bgp_len > BGP_MAX_PACKET_SIZE) {
        expert_add_info_format(pinfo, ti_len, &ei_bgp_length_invalid, "Length is invalid %u", bgp_len);
        return;
    }

    proto_tree_add_item(bgp_tree, hf_bgp_type, tvb, 16 + 2, 1, ENC_BIG_ENDIAN);

    switch (bgp_type) {
    case BGP_OPEN:
        dissect_bgp_open(tvb, bgp_tree, pinfo);
        break;
    case BGP_UPDATE:
        dissect_bgp_update(tvb, bgp_tree, pinfo);
        break;
    case BGP_NOTIFICATION:
        dissect_bgp_notification(tvb, bgp_tree, pinfo);
        break;
    case BGP_KEEPALIVE:
        /* no data in KEEPALIVE messages */
        break;
    case BGP_ROUTE_REFRESH_CISCO:
    case BGP_ROUTE_REFRESH:
        dissect_bgp_route_refresh(tvb, bgp_tree, pinfo);
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
static int
dissect_bgp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
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

        proto_tree_add_item(bgp_tree, hf_bgp_continuation, tvb, 0, offset, ENC_NA);
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
        length_remaining = tvb_ensure_captured_length_remaining(tvb, offset);

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
                return tvb_captured_length(tvb);
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
            return tvb_captured_length(tvb);
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
                pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
                return tvb_captured_length(tvb);
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
        next_tvb = tvb_new_subset_length_caplen(tvb, offset, length, bgp_len);

        /*
         * Dissect the PDU.
         *
         * If it gets an error that means there's no point in
         * dissecting any more PDUs, rethrow the exception in
         * question.
         *
         * If it gets any other error, report it and continue, as that
         * means that PDU got an error, but that doesn't mean we should
         * stop dissecting PDUs within this frame or chunk of reassembled
         * data.
         */
        TRY {
            dissect_bgp_pdu(next_tvb, pinfo, tree, first);
        }
        CATCH_NONFATAL_ERRORS {
            show_exception(tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);
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
    return tvb_captured_length(tvb);
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
      { &hf_bgp_prefix_length,
        { "Prefix Length", "bgp.prefix_length", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_rd,
        { "Route Distinguisher", "bgp.rd", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_continuation,
        { "Continuation", "bgp.continuation", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_originating_as,
        { "Originating AS", "bgp.originating_as", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_community_prefix,
        { "Community Prefix", "bgp.community_prefix", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_endpoint_address,
        { "Endpoint Address", "bgp.endpoint_address", FT_IPv4, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_endpoint_address_ipv6,
        { "Endpoint Address", "bgp.endpoint_address_ipv6", FT_IPv6, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_label_stack,
        { "Label Stack", "bgp.label_stack", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_vplsad_length,
        { "Length", "bgp.vplsad.length", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_vplsad_rd,
        { "RD", "bgp.vplsad.rd", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_bgpad_pe_addr,
        { "PE Addr", "bgp.ad.pe_addr", FT_IPv4, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_vplsbgp_ce_id,
        { "CE-ID", "bgp.vplsbgp.ce_id", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_vplsbgp_labelblock_offset,
        { "Label Block Offset", "bgp.vplsbgp.labelblock.offset", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_vplsbgp_labelblock_size,
        { "Label Block Size", "bgp.vplsbgp.labelblock.size", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_vplsbgp_labelblock_base,
        { "Label Block Base", "bgp.vplsbgp.labelblock.base", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_wildcard_route_target,
        { "Wildcard route target", "bgp.wildcard_route_target", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
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
        { "Authentication Data", "bgp.open.opt.param.auth", FT_BYTES, BASE_NONE,
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
        { "Minor error Code (Open Message)", "bgp.notify.minor_error_open", FT_UINT8, BASE_DEC,
          VALS(bgpnotify_minor_open_msg), 0x0, NULL, HFILL }},
      { &hf_bgp_notify_minor_update_msg,
        { "Minor error Code (Update Message)", "bgp.notify.minor_error_update", FT_UINT8, BASE_DEC,
          VALS(bgpnotify_minor_update_msg), 0x0, NULL, HFILL }},
      { &hf_bgp_notify_minor_ht_expired,
        { "Minor error Code (Hold Timer Expired)", "bgp.notify.minor_error_expired", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_notify_minor_state_machine,
        { "Minor error Code (State Machine)", "bgp.notify.minor_error_state", FT_UINT8, BASE_DEC,
          VALS(bgpnotify_minor_state_machine), 0x0, NULL, HFILL }},
      { &hf_bgp_notify_minor_cease,
        { "Minor error Code (Cease)", "bgp.notify.minor_error_cease", FT_UINT8, BASE_DEC,
          VALS(bgpnotify_minor_cease), 0x0, NULL, HFILL }},
      { &hf_bgp_notify_minor_cap_msg,
        { "Minor error Code (Capability Message)", "bgp.notify.minor_error_capability", FT_UINT8, BASE_DEC,
          VALS(bgpnotify_minor_cap_msg), 0x0, NULL, HFILL }},
      { &hf_bgp_notify_minor_unknown,
        { "Minor error Code (Unknown)", "bgp.notify.minor_error_unknown", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_notify_data,
        { "Data", "bgp.notify.minor_data", FT_BYTES, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_notify_error_open_bad_peer_as,
        { "Bad Peer AS", "bgp.notify.error_open.bad_peer_as", FT_UINT32, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_notify_communication_length,
        { "BGP Shutdown Communication Length", "bgp.notify.communication_length", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_notify_communication,
        { "Shutdown Communication", "bgp.notify.communication", FT_STRING, BASE_NONE,
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
      { &hf_bgp_route_refresh_orf,
        { "ORF information", "bgp.route_refresh.orf", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_route_refresh_orf_flag,
        { "ORF flag", "bgp.route_refresh.orf.flag", FT_UINT8, BASE_DEC,
          VALS(orf_when_vals), 0x0, NULL, HFILL }},
      { &hf_bgp_route_refresh_orf_type,
        { "ORF type", "bgp.route_refresh.orf.type", FT_UINT8, BASE_DEC,
          VALS(orf_type_vals), 0x0, NULL, HFILL }},
      { &hf_bgp_route_refresh_orf_length,
        { "ORF length", "bgp.route_refresh.orf.length", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_route_refresh_orf_entry_prefixlist,
        { "ORFEntry PrefixList", "bgp.route_refresh.orf.entry", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_route_refresh_orf_entry_action,
        { "ORFEntry Action", "bgp.route_refresh.orf.entry.action", FT_UINT8, BASE_DEC,
          VALS(orf_entry_action_vals), BGP_ORF_ACTION, NULL, HFILL }},
      { &hf_bgp_route_refresh_orf_entry_match,
        { "ORFEntry Match", "bgp.route_refresh.orf.entry.match", FT_UINT8, BASE_DEC,
          VALS(orf_entry_match_vals), BGP_ORF_MATCH, NULL, HFILL }},
      { &hf_bgp_route_refresh_orf_entry_sequence,
        { "ORFEntry Sequence", "bgp.route_refresh.orf.entry.sequence", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_route_refresh_orf_entry_prefixmask_lower,
        { "ORFEntry PrefixMask length lower bound", "bgp.route_refresh.orf.entry.prefixmask_lower", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_route_refresh_orf_entry_prefixmask_upper,
        { "ORFEntry PrefixMask length upper bound", "bgp.route_refresh.orf.entry.prefixmask_upper", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_route_refresh_orf_entry_ip,
        { "ORFEntry IP address", "bgp.route_refresh.orf.entry.ip", FT_IPv4, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},

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
      { &hf_bgp_cap_enh_afi,
        { "AFI", "bgp.cap.enh.afi", FT_UINT16, BASE_DEC,
          VALS(afn_vals), 0x0, NULL, HFILL }},
      { &hf_bgp_cap_enh_safi,
        { "SAFI", "bgp.cap.enh.safi", FT_UINT16, BASE_DEC,
          VALS(bgpattr_nlri_safi), 0x0, NULL, HFILL }},
      { &hf_bgp_cap_enh_nhafi,
        { "Next hop AFI", "bgp.cap.enh.nhafi", FT_UINT16, BASE_DEC,
          VALS(afn_vals), 0x0, NULL, HFILL }},
      { &hf_bgp_cap_gr_timers,
        { "Restart Timers", "bgp.cap.gr.timers", FT_UINT16, BASE_HEX,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_cap_gr_timers_restart_flag,
        { "Restart state", "bgp.cap.gr.timers.restart_flag", FT_BOOLEAN, 16,
          TFS(&tfs_yes_no), 0x8000, NULL, HFILL }},
      { &hf_bgp_cap_gr_timers_notification_flag,
        { "Graceful notification", "bgp.cap.gr.timers.notification_flag", FT_BOOLEAN, 16,
          TFS(&tfs_yes_no), 0x4000, NULL, HFILL }},
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
      { &hf_bgp_cap_fqdn_hostname_len,
        { "Hostname Length", "bgp.cap.orf.fqdn.hostname.len", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_cap_fqdn_hostname,
        { "Hostname", "bgp.cap.orf.fqdn.hostname", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_cap_fqdn_domain_name_len,
        { "Domain Name Length", "bgp.cap.orf.fqdn.domain_name.len", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_cap_fqdn_domain_name,
        { "Domain Name", "bgp.cap.orf.fqdn.domain_name", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_cap_multisession_flags,
        { "Flag", "bgp.cap.multisession.flags", FT_UINT8, BASE_HEX,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_cap_bgpsec_flags,
        { "Flag", "bgp.cap.bgpsec.flags", FT_UINT8, BASE_HEX,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_cap_bgpsec_version,
        { "Version", "bgp.cap.bgpsec.version", FT_UINT8, BASE_DEC,
          NULL, 0xF0, NULL, HFILL }},
      { &hf_bgp_cap_bgpsec_sendreceive,
        { "Send/Receive", "bgp.cap.bgpsec.sendreceive", FT_UINT8, BASE_DEC,
          VALS(bgpsec_send_receive_vals), 0x8, NULL, HFILL }},
      { &hf_bgp_cap_bgpsec_reserved,
        { "Reserved", "bgp.cap.bgpsec.reserved", FT_UINT8, BASE_HEX,
          NULL, 0x7, "Must be Zero", HFILL }},
      { &hf_bgp_cap_bgpsec_afi,
        { "AFI", "bgp.cap.bgpsec.afi", FT_UINT16, BASE_DEC,
          VALS(afn_vals), 0x0, NULL, HFILL }},
      /* BGP update */

      { &hf_bgp_update_withdrawn_routes_length,
        { "Withdrawn Routes Length", "bgp.update.withdrawn_routes.length", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_withdrawn_routes,
        { "Withdrawn Routes", "bgp.update.withdrawn_routes", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},

      { &hf_bgp_update_path_attribute_aggregator_as,
        { "Aggregator AS", "bgp.update.path_attribute.aggregator_as", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
      /* BGP update path attributes */
      { &hf_bgp_update_path_attributes,
        { "Path attributes", "bgp.update.path_attributes", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_path_attributes_unknown,
        { "Unknown Path attributes", "bgp.update.path_attributes.unknown", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_total_path_attribute_length,
        { "Total Path Attribute Length", "bgp.update.path_attributes.length", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_aggregator_origin,
        { "Aggregator origin", "bgp.update.path_attribute.aggregator_origin", FT_IPv4, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_as_path_segment,
        { "AS Path segment", "bgp.update.path_attribute.as_path_segment", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_as_path_segment_type,
        { "Segment type", "bgp.update.path_attribute.as_path_segment.type", FT_UINT8, BASE_DEC,
          VALS(as_segment_type), 0x0, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_as_path_segment_length,
        { "Segment length (number of ASN)", "bgp.update.path_attribute.as_path_segment.length", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_as_path_segment_as2,
        { "AS2", "bgp.update.path_attribute.as_path_segment.as2", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_as_path_segment_as4,
        { "AS4", "bgp.update.path_attribute.as_path_segment.as4", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_communities,
        { "Communities", "bgp.update.path_attribute.communities", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_community,
        { "Community", "bgp.update.path_attribute.community", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_community_well_known,
        { "Community Well-known", "bgp.update.path_attribute.community_wellknown", FT_UINT32, BASE_HEX,
          VALS(community_vals), 0x0, "Reserved", HFILL}},
      { &hf_bgp_update_path_attribute_community_as,
        { "Community AS", "bgp.update.path_attribute.community_as", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_community_value,
        { "Community value", "bgp.update.path_attribute.community_value", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_local_pref,
        { "Local preference", "bgp.update.path_attribute.local_pref", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_attrset_origin_as,
        { "Origin AS", "bgp.update.path_attribute.attr_set.origin_as", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_multi_exit_disc,
        { "Multiple exit discriminator", "bgp.update.path_attribute.multi_exit_disc", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_next_hop,
        { "Next hop", "bgp.update.path_attribute.next_hop", FT_IPv4, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_origin,
        { "Origin", "bgp.update.path_attribute.origin", FT_UINT8, BASE_DEC,
          VALS(bgpattr_origin), 0x0, NULL, HFILL}},
      { &hf_bgp_update_path_attribute,
        { "Path Attribute", "bgp.update.path_attribute", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_flags,
        { "Flags", "bgp.update.path_attribute.flags", FT_UINT8, BASE_HEX,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_flags_optional,
        { "Optional", "bgp.update.path_attribute.flags.optional", FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), BGP_ATTR_FLAG_OPTIONAL, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_flags_transitive,
        { "Transitive", "bgp.update.path_attribute.flags.transitive", FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), BGP_ATTR_FLAG_TRANSITIVE, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_flags_partial,
        { "Partial", "bgp.update.path_attribute.flags.partial", FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), BGP_ATTR_FLAG_PARTIAL, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_flags_extended_length,
        { "Extended-Length", "bgp.update.path_attribute.flags.extended_length", FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), BGP_ATTR_FLAG_EXTENDED_LENGTH, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_flags_unused,
        { "Unused", "bgp.update.path_attribute.flags.unused", FT_UINT8, BASE_HEX,
          NULL, BGP_ATTR_FLAG_UNUSED, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_type_code,
        { "Type Code", "bgp.update.path_attribute.type_code", FT_UINT8, BASE_DEC,
          VALS(bgpattr_type), 0x0, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_length,
        { "Length", "bgp.update.path_attribute.length", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_link_state,
        { "Link State", "bgp.update.path_attribute.link_state", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},

      /* BGPsec Path Attributes, RFC8205*/
      { &hf_bgp_update_path_attribute_bgpsec_sp_len,
        { "Length", "bgp.update.path_attribute.bgpsec.sp.length", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_bgpsec_sps_pcount,
        { "pCount", "bgp.update.path_attribute.bgpsec.sps.pcount", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_bgpsec_sps_flags,
        { "Flags", "bgp.update.path_attribute.bgpsec.sps.flags", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_bgpsec_sps_as,
        { "AS Number", "bgp.update.path_attribute.bgpsec.sps.as", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_bgpsec_sb_len,
        { "Length", "bgp.update.path_attribute.bgpsec.sb.length", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_bgpsec_algo_id,
        { "Algo ID", "bgp.update.path_attribute.bgpsec.sb.algo_id", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_bgpsec_ski,
        { "SKI", "bgp.update.path_attribute.bgpsec.ss.ski", FT_BYTES, SEP_SPACE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_bgpsec_sig_len,
        { "Length", "bgp.update.path_attribute.bgpsec.ss.length", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_bgpsec_sig,
        { "Signature", "bgp.update.path_attribute.bgpsec.ss.sig", FT_BYTES, SEP_SPACE,
          NULL, 0x0, NULL, HFILL}},

      { &hf_bgp_update_path_attribute_mp_reach_nlri_address_family,
        { "Address family identifier (AFI)", "bgp.update.path_attribute.mp_reach_nlri.afi", FT_UINT16, BASE_DEC,
          VALS(afn_vals), 0x0, NULL, HFILL }},
      { &hf_bgp_update_path_attribute_mp_reach_nlri_safi,
        { "Subsequent address family identifier (SAFI)", "bgp.update.path_attribute.mp_reach_nlri.safi", FT_UINT8, BASE_DEC,
          VALS(bgpattr_nlri_safi), 0x0, NULL, HFILL }},
      { &hf_bgp_update_path_attribute_mp_reach_nlri_next_hop,
        { "Next hop", "bgp.update.path_attribute.mp_reach_nlri.next_hop", FT_BYTES, BASE_NO_DISPLAY_VALUE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_update_path_attribute_mp_reach_nlri_next_hop_rd,
        { "Route Distinguisher", "bgp.update.path_attribute.mp_reach_nlri.next_hop.rd", FT_STRING, BASE_NONE,
          NULL, 0x0, "RD is always zero in the Next Hop", HFILL }},
      { &hf_bgp_update_path_attribute_mp_reach_nlri_next_hop_ipv4,
        { "IPv4 Address", "bgp.update.path_attribute.mp_reach_nlri.next_hop.ipv4", FT_IPv4, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_mp_reach_nlri_next_hop_ipv6,
        { "IPv6 Address", "bgp.update.path_attribute.mp_reach_nlri.next_hop.ipv6", FT_IPv6, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_mp_reach_nlri_next_hop_ipv6_link_local,
        { "Link-local Address", "bgp.update.path_attribute.mp_reach_nlri.next_hop.ipv6.link_local", FT_IPv6, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_mp_reach_nlri_nbr_snpa,
        { "Number of Subnetwork points of attachment (SNPA)", "bgp.update.path_attribute.mp_reach_nlri.nbr_snpa", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_update_path_attribute_mp_reach_nlri_snpa_length,
        { "SNPA Length", "bgp.update.path_attribute.mp_reach_nlri.snpa_length", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_update_path_attribute_mp_reach_nlri_snpa,
        { "SNPA", "bgp.update.path_attribute.mp_reach_nlri.snpa", FT_BYTES, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_update_path_attribute_mp_reach_nlri,
        { "Network Layer Reachability Information (NLRI)", "bgp.update.path_attribute.mp_reach_nlri", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},

      { &hf_bgp_update_path_attribute_mp_unreach_nlri_address_family,
        { "Address family identifier (AFI)", "bgp.update.path_attribute.mp_unreach_nlri.afi", FT_UINT16, BASE_DEC,
          VALS(afn_vals), 0x0, NULL, HFILL }},
      { &hf_bgp_update_path_attribute_mp_unreach_nlri_safi,
        { "Subsequent address family identifier (SAFI)", "bgp.update.path_attribute.mp_unreach_nlri.safi", FT_UINT8, BASE_DEC,
          VALS(bgpattr_nlri_safi), 0x0, NULL, HFILL }},
      { &hf_bgp_update_path_attribute_mp_unreach_nlri,
        { "Withdrawn Routes", "bgp.update.path_attribute.mp_unreach_nlri", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},

      { &hf_bgp_pmsi_tunnel_flags,
        { "Flags", "bgp.update.path_attribute.pmsi.tunnel.flags", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_pmsi_tunnel_type,
        { "Tunnel Type", "bgp.update.path_attribute.pmsi.tunnel.type", FT_UINT8, BASE_DEC,
          VALS(pmsi_tunnel_type), 0x0, NULL, HFILL}},
      { &hf_bgp_pmsi_tunnel_id,
        { "Tunnel ID", "bgp.update.path_attribute.pmsi.tunnel.id", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_pmsi_tunnel_not_present,
        { "Tunnel ID not present", "bgp.update.path_attribute.pmsi.tunnel_id.not_present", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_mpls_label,
        { "MPLS Label Stack", "bgp.update.path_attribute.mpls_label", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_mpls_label_value_20bits,
        { "MPLS Label", "bgp.update.path_attribute.mpls_label_value_20bits", FT_UINT24,
          BASE_DEC, NULL, BGP_MPLS_LABEL, NULL, HFILL}},
      { &hf_bgp_update_mpls_label_value,
        { "MPLS Label", "bgp.update.path_attribute.mpls_label_value", FT_UINT24,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_mpls_traffic_class,
        { "Traffic Class", "bgp.update.path_attribute.mpls_traffic_class", FT_UINT24,
          BASE_HEX, NULL, BGP_MPLS_TRAFFIC_CLASS, NULL, HFILL}},
      { &hf_bgp_update_mpls_bottom_stack,
        { "Bottom-of-Stack", "bgp.update.path_attribute.mpls_bottom_stack", FT_BOOLEAN,
          24, NULL, BGP_MPLS_BOTTOM_L_STACK, NULL, HFILL}},
      { &hf_bgp_pmsi_tunnel_rsvp_p2mp_id, /* RFC4875 section 19 */
        { "RSVP P2MP id", "bgp.update.path_attribute.pmsi.rsvp.id", FT_IPv4, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_pmsi_tunnel_rsvp_p2mp_tunnel_id,
        { "RSVP P2MP tunnel id", "bgp.update.path_attribute.pmsi.rsvp.tunnel_id", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_pmsi_tunnel_rsvp_p2mp_ext_tunnel_idv4,
        { "RSVP P2MP extended tunnel id", "bgp.update.path_attribute.pmsi.rsvp.ext_tunnel_idv4", FT_IPv4, BASE_NONE,
         NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_pmsi_tunnel_mldp_fec_el_type,
        { "mLDP P2MP FEC element type", "bgp.update.path_attribute.pmsi.mldp.fec.type", FT_UINT8, BASE_DEC,
         VALS(fec_types_vals), 0x0, NULL, HFILL}},
      { &hf_bgp_pmsi_tunnel_mldp_fec_el_afi,
        {"mLDP P2MP FEC element address family", "bgp.update.path_attribute.pmsi.mldp.fec.address_family", FT_UINT16, BASE_DEC,
         VALS(afn_vals), 0x0, NULL, HFILL}},
      { &hf_bgp_pmsi_tunnel_mldp_fec_el_adr_len,
        {"mLDP P2MP FEC element address length", "bgp.update.path_attribute.pmsi.mldp.fec.address_length", FT_UINT8, BASE_DEC,
         NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_pmsi_tunnel_mldp_fec_el_root_nodev4,
        {"mLDP P2MP FEC element root node address", "bgp.update.path_attribute.pmsi.mldp.fec.root_nodev4", FT_IPv4, BASE_NONE,
         NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_pmsi_tunnel_mldp_fec_el_root_nodev6,
        {"mLDP P2MP FEC element root node address", "bgp.update.path_attribute.pmsi.mldp.fec.root_nodev6", FT_IPv6, BASE_NONE,
         NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_pmsi_tunnel_mldp_fec_el_opa_len,
        {"mLDP P2MP FEC element opaque length", "bgp.update.path_attribute.pmsi.mldp.fec.opaque_length", FT_UINT16, BASE_DEC,
         NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_pmsi_tunnel_mldp_fec_el_opa_val_type,
        {"mLDP P2MP FEC element opaque value type", "bgp.update.path_attribute.pmsi.mldp.fec.opaque_value_type", FT_UINT8, BASE_DEC,
         VALS(pmsi_mldp_fec_opaque_value_type), 0x0, NULL, HFILL}},
      { &hf_bgp_pmsi_tunnel_mldp_fec_el_opa_val_len,
        {"mLDP P2MP FEC element opaque value length", "bgp.update.path_attribute.pmsi.mldp.fec.opaque_value_length", FT_UINT16, BASE_DEC,
         NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_pmsi_tunnel_mldp_fec_el_opa_value_rn,
        {"mLDP P2MP FEC element opaque value unique Id", "bgp.update.path_attribute.pmsi.mldp.fec.opaque_value_unique_id_rn", FT_UINT32, BASE_DEC,
         NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_pmsi_tunnel_mldp_fec_el_opa_value_str,
        {"mLDP P2MP FEC element opaque value unique Id", "bgp.update.path_attribute.pmsi.mldp.fec.opaque_value_unique_id_str", FT_STRING, BASE_NONE,
         NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_pmsi_tunnel_mldp_fec_el_opa_val_ext_type,
        {"mLDP P2MP FEC element opaque extended value type", "bgp.update.path_attribute.pmsi.mldp.fec.opaque_ext_value_type", FT_UINT16, BASE_DEC,
         VALS(pmsi_mldp_fec_opa_extented_type), 0x0, NULL, HFILL}},
      { &hf_bgp_pmsi_tunnel_mldp_fec_el_opa_val_ext_len,
        {"mLDP P2MP FEC element opaque extended length", "bgp.update.path_attribute.pmsi.mldp.fec.opaque_ext_length", FT_UINT16, BASE_DEC,
         NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_pmsi_tunnel_pimsm_sender,
        {"PIM-SM Tree tunnel sender address", "bgp.update.path_attribute.pmsi.pimsm.sender_address", FT_IPv4, BASE_NONE,
         NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_pmsi_tunnel_pimsm_pmc_group,
        {"PIM-SM Tree tunnel P-multicast group", "bgp.update.path_attribute.pmsi.pimsm.pmulticast_group", FT_IPv4, BASE_NONE,
         NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_pmsi_tunnel_pimssm_root_node,
        {"PIM-SSM Tree tunnel Root Node", "bgp.update.path_attribute.pmsi.pimssm.root_node", FT_IPv4, BASE_NONE,
         NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_pmsi_tunnel_pimssm_pmc_group,
        {"PIM-SSM Tree tunnel P-multicast group", "bgp.update.path_attribute.pmsi.pimssm.pmulticast_group", FT_IPv4, BASE_NONE,
         NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_pmsi_tunnel_pimbidir_sender,
        {"BIDIR-PIM Tree Tunnel sender address", "bgp.update.path_attribute.pmsi.bidir_pim_tree.sender", FT_IPv4, BASE_NONE,
         NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_pmsi_tunnel_pimbidir_pmc_group,
        {"BIDIR-PIM Tree Tunnel P-multicast group", "bgp.update.path_attribute.pmsi.bidir_pim_tree.pmulticast_group", FT_IPv4, BASE_NONE,
         NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_pmsi_tunnel_ingress_rep_addr,
        {"Tunnel type ingress replication IP end point", "bgp.update.path_attribute.pmsi.ingress_rep_ip", FT_IPv4, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},

        /* https://tools.ietf.org/html/draft-rabadan-sajassi-bess-evpn-ipvpn-interworking-02 */
      { &hf_bgp_update_path_attribute_d_path,
        { "Domain Path Attribute", "bgp.update.path_attribute.dpath", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_d_path_length,
        {"Domain Path Attribute length", "bgp.update.attribute.dpath.length", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_d_path_ga,
        { "Global Administrator", "bgp.update.attribute.dpath.ga", FT_UINT32, BASE_DEC,
          NULL, 0x0, "A four-octet namespace identifier. This SHOULD be an Autonomous System Number", HFILL }},
      { &hf_bgp_d_path_la,
        { "Local Administrator", "bgp.update.attribute.dpath.la", FT_UINT16, BASE_DEC,
          NULL, 0x0, "A two-octet operator-defined value", HFILL }},
      { &hf_bgp_d_path_isf_safi,
        { "Inter-Subnet Forwarding SAFI type", "bgp.update.attribute.dpath.isf.safi", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

        /* RFC7311 */
      { &hf_bgp_update_path_attribute_aigp,
        { "AIGP Attribute", "bgp.update.path_attribute.aigp", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_aigp_type,
        {"AIGP attribute type", "bgp.update.attribute.aigp.type", FT_UINT8, BASE_DEC,
        VALS(aigp_tlv_type), 0x0, NULL, HFILL }},
      { &hf_bgp_aigp_tlv_length,
        {"AIGP TLV length", "bgp.update.attribute.aigp.length", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_aigp_accu_igp_metric,
        {"AIGP Accumulated IGP Metric", "bgp.update.attribute.aigp.accu_igp_metric", FT_UINT64, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},

        /* RFC8092 */
      { &hf_bgp_large_communities,
        { "Large Communities", "bgp.large_communities", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_large_communities_ga,
        { "Global Administrator", "bgp.large_communities.ga", FT_UINT32, BASE_DEC,
          NULL, 0x0, "A four-octet namespace identifier. This SHOULD be an Autonomous System Number", HFILL }},
      { &hf_bgp_large_communities_ldp1,
        { "Local Data Part 1", "bgp.large_communities.ldp1", FT_UINT32, BASE_DEC,
          NULL, 0x0, "A four-octet operator-defined value", HFILL }},
      { &hf_bgp_large_communities_ldp2,
        { "Local Data Part 2", "bgp.large_communities.ldp2", FT_UINT32, BASE_DEC,
          NULL, 0x0, "A four-octet operator-defined value", HFILL }},

        /* RFC4456 */
       { &hf_bgp_update_path_attribute_originator_id,
        { "Originator identifier", "bgp.update.path_attribute.originator_id", FT_IPv4, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_cluster_list,
        { "Cluster List", "bgp.path_attribute.cluster_list", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_cluster_id,
        { "Cluster ID", "bgp.path_attribute.cluster_id", FT_IPv4, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},

        /* RFC8669 */
      { &hf_bgp_prefix_sid_unknown,
        { "Unknown TLV", "bgp.prefix_sid.unknown", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_prefix_sid_label_index,
        { "Label-Index", "bgp.prefix_sid.label_index", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_prefix_sid_label_index_value,
        { "Label-Index Value", "bgp.prefix_sid.label_index.value", FT_UINT32, BASE_DEC,
          NULL, 0x0, "4-octet label index value", HFILL }},
      { &hf_bgp_prefix_sid_label_index_flags,
        { "Label-Index Flags", "bgp.prefix_sid.label_index.flags", FT_UINT16, BASE_HEX,
          NULL, 0x0, "2-octet flags, None is defined", HFILL }},
      { &hf_bgp_prefix_sid_originator_srgb_flags,
        { "Originator SRGB Flags", "bgp.prefix_sid.originator_srgb.flags", FT_UINT16, BASE_HEX,
          NULL, 0x0, "2-octet flags, None is defined", HFILL }},
      { &hf_bgp_prefix_sid_originator_srgb,
        { "Originator SRGB", "bgp.prefix_sid.originator_srgb", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_prefix_sid_originator_srgb_blocks,
        { "SRGB Blocks", "bgp.prefix_sid.originator_srgb_blocks", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_prefix_sid_originator_srgb_block,
        { "SRGB Block", "bgp.prefix_sid.originator_srgb_block", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_prefix_sid_originator_srgb_base,
        { "SRGB Base", "bgp.prefix_sid.originator_srgb_base", FT_UINT24, BASE_DEC,
          NULL, 0x0, "A three-octet value", HFILL }},
      { &hf_bgp_prefix_sid_originator_srgb_range,
        { "SRGB Range", "bgp.prefix_sid.originator_srgb_range", FT_UINT24, BASE_DEC,
          NULL, 0x0, "A three-octet value", HFILL }},
      { &hf_bgp_prefix_sid_type,
        { "Type", "bgp.prefix_sid.type", FT_UINT8, BASE_DEC,
          VALS(bgp_prefix_sid_type), 0x0, "BGP Prefix-SID message type", HFILL }},
      { &hf_bgp_prefix_sid_length,
        { "Length", "bgp.prefix_sid.length", FT_UINT16, BASE_DEC,
          NULL, 0x0, "BGP Prefix-SID message payload", HFILL }},
      { &hf_bgp_prefix_sid_value,
        { "Value", "bgp.prefix_sid.value", FT_BYTES, BASE_NONE,
          NULL, 0x0, "BGP Prefix-SID message value", HFILL }},
      { &hf_bgp_prefix_sid_reserved,
        { "Reserved", "bgp.prefix_sid.reserved", FT_BYTES,
          BASE_NONE, NULL, 0x0, "Unused (must be clear)", HFILL }},

        /* draft-ietf-bess-srv6-services-05 */
      { &hf_bgp_prefix_sid_srv6_l3vpn,
        { "SRv6 L3 Service", "bgp.prefix_sid.srv6_l3vpn", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_prefix_sid_srv6_l3vpn_sub_tlvs,
        { "SRv6 Service Sub-TLVs", "bgp.prefix_sid.srv6_l3vpn.sub_tlvs", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_prefix_sid_srv6_l3vpn_sub_tlv,
        { "SRv6 Service Sub-TLV", "bgp.prefix_sid.srv6_l3vpn.sub_tlv", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_prefix_sid_srv6_l3vpn_sub_tlv_type,
        { "Type", "bgp.prefix_sid.srv6_l3vpn.sub_tlv.type", FT_UINT8, BASE_DEC,
          VALS(srv6_service_sub_tlv_type), 0x0, "SRv6 Service Sub-TLV type", HFILL }},
      { &hf_bgp_prefix_sid_srv6_l3vpn_sub_tlv_length,
        { "Length", "bgp.prefix_sid.srv6_l3vpn.sub_tlv.length", FT_UINT16, BASE_DEC,
          NULL, 0x0, "SRv6 Service Sub-TLV length", HFILL }},
      { &hf_bgp_prefix_sid_srv6_l3vpn_sub_tlv_value,
        { "Value", "bgp.prefix_sid.srv6_l3vpn.sub_tlv.value", FT_BYTES, BASE_NONE,
          NULL, 0x0, "SRv6 Service Sub-TLV value", HFILL }},
      { &hf_bgp_prefix_sid_srv6_l3vpn_sub_tlv_reserved,
        { "Reserved", "bgp.prefix_sid.srv6_l3vpn.sub_tlv.reserved", FT_BYTES,
          BASE_NONE, NULL, 0x0, "Unused (must be clear)", HFILL }},
      { &hf_bgp_prefix_sid_srv6_l3vpn_sid_value,
        { "SRv6 SID Value", "bgp.prefix_sid.srv6_l3vpn.sid_value", FT_IPv6, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_prefix_sid_srv6_l3vpn_sid_flags,
        { "SRv6 SID Flags", "bgp.prefix_sid.srv6_l3vpn.sid_flags", FT_UINT8, BASE_HEX,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_prefix_sid_srv6_l3vpn_srv6_endpoint_behavior,
        { "SRv6 Endpoint Behavior", "bgp.prefix_sid.srv6_l3vpn.srv6_endpoint_behavior", FT_UINT16, BASE_HEX,
          VALS(srv6_endpoint_behavior), 0x0, NULL, HFILL }},
      { &hf_bgp_prefix_sid_srv6_l3vpn_reserved,
        { "Reserved", "bgp.prefix_sid.srv6_l3vpn.reserved", FT_BYTES,
          BASE_NONE, NULL, 0x0, "Unused (must be clear)", HFILL }},
      { &hf_bgp_prefix_sid_srv6_l3vpn_sub_sub_tlvs,
        { "SRv6 Service Data Sub-Sub-TLVs", "bgp.prefix_sid.srv6_l3vpn.sub_sub_tlvs", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_prefix_sid_srv6_l3vpn_sub_sub_tlv,
        { "SRv6 Service Data Sub-Sub-TLV", "bgp.prefix_sid.srv6_l3vpn.sub_sub_tlv", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_prefix_sid_srv6_l3vpn_sub_sub_tlv_type,
        { "Type", "bgp.prefix_sid.srv6_l3vpn.sub_sub_tlv.type", FT_UINT8, BASE_DEC,
          VALS(srv6_service_data_sub_sub_tlv_type), 0x0, "SRv6 Service Data Sub-Sub-TLV type", HFILL }},
      { &hf_bgp_prefix_sid_srv6_l3vpn_sub_sub_tlv_length,
        { "Length", "bgp.prefix_sid.srv6_l3vpn.sub_sub_tlv.length", FT_UINT16, BASE_DEC,
          NULL, 0x0, "SRv6 Service Data Sub-Sub-TLV length", HFILL }},
      { &hf_bgp_prefix_sid_srv6_l3vpn_sub_sub_tlv_value,
        { "Value", "bgp.prefix_sid.srv6_l3vpn.sub_sub_tlv.value", FT_BYTES, BASE_NONE,
          NULL, 0x0, "SRv6 Service Data Sub-Sub-TLV value", HFILL }},
      { &hf_bgp_prefix_sid_srv6_l3vpn_sid_locator_block_len,
        { "Locator Block Length", "bgp.prefix_sid.srv6_l3vpn.sid.locator_block_len", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_prefix_sid_srv6_l3vpn_sid_locator_node_len,
        { "Locator Node Length", "bgp.prefix_sid.srv6_l3vpn.sid.locator_node_len", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_prefix_sid_srv6_l3vpn_sid_func_len,
        { "Function Length", "bgp.prefix_sid.srv6_l3vpn.sid.func_len", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_prefix_sid_srv6_l3vpn_sid_arg_len,
        { "Argument Length", "bgp.prefix_sid.srv6_l3vpn.sid.arg_len", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_prefix_sid_srv6_l3vpn_sid_trans_len,
        { "Transposition Length", "bgp.prefix_sid.srv6_l3vpn.sid.trans_len", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_prefix_sid_srv6_l3vpn_sid_trans_offset,
        { "Transposition Offset", "bgp.prefix_sid.srv6_l3vpn.sid.trans_offset", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_prefix_sid_srv6_l2vpn,
        { "SRv6 L3 Service", "bgp.prefix_sid.srv6_l2vpn", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_prefix_sid_srv6_l2vpn_sub_tlvs,
        { "SRv6 Service Sub-TLVs", "bgp.prefix_sid.srv6_l2vpn.sub_tlvs", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_prefix_sid_srv6_l2vpn_sub_tlv,
        { "SRv6 Service Sub-TLV", "bgp.prefix_sid.srv6_l2vpn.sub_tlv", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_prefix_sid_srv6_l2vpn_sub_tlv_type,
        { "Type", "bgp.prefix_sid.srv6_l2vpn.sub_tlv.type", FT_UINT8, BASE_DEC,
          VALS(srv6_service_sub_tlv_type), 0x0, "SRv6 Service Sub-TLV type", HFILL }},
      { &hf_bgp_prefix_sid_srv6_l2vpn_sub_tlv_length,
        { "Length", "bgp.prefix_sid.srv6_l2vpn.sub_tlv.length", FT_UINT16, BASE_DEC,
          NULL, 0x0, "SRv6 Service Sub-TLV length", HFILL }},
      { &hf_bgp_prefix_sid_srv6_l2vpn_sub_tlv_value,
        { "Value", "bgp.prefix_sid.srv6_l2vpn.sub_tlv.value", FT_BYTES, BASE_NONE,
          NULL, 0x0, "SRv6 Service Sub-TLV value", HFILL }},
      { &hf_bgp_prefix_sid_srv6_l2vpn_sub_tlv_reserved,
        { "Reserved", "bgp.prefix_sid.srv6_l2vpn.sub_tlv.reserved", FT_BYTES,
          BASE_NONE, NULL, 0x0, "Unused (must be clear)", HFILL }},
      { &hf_bgp_prefix_sid_srv6_l2vpn_sid_value,
        { "SRv6 SID Value", "bgp.prefix_sid.srv6_l2vpn.sid_value", FT_IPv6, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_prefix_sid_srv6_l2vpn_sid_flags,
        { "SRv6 SID Flags", "bgp.prefix_sid.srv6_l2vpn.sid_flags", FT_UINT8, BASE_HEX,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_prefix_sid_srv6_l2vpn_srv6_endpoint_behavior,
        { "SRv6 Endpoint Behavior", "bgp.prefix_sid.srv6_l2vpn.srv6_endpoint_behavior", FT_UINT16, BASE_HEX,
          VALS(srv6_endpoint_behavior), 0x0, NULL, HFILL }},
      { &hf_bgp_prefix_sid_srv6_l2vpn_reserved,
        { "Reserved", "bgp.prefix_sid.srv6_l2vpn.reserved", FT_BYTES,
          BASE_NONE, NULL, 0x0, "Unused (must be clear)", HFILL }},
      { &hf_bgp_prefix_sid_srv6_l2vpn_sub_sub_tlvs,
        { "SRv6 Service Data Sub-Sub-TLVs", "bgp.prefix_sid.srv6_l2vpn.sub_sub_tlvs", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_prefix_sid_srv6_l2vpn_sub_sub_tlv,
        { "SRv6 Service Data Sub-Sub-TLV", "bgp.prefix_sid.srv6_l2vpn.sub_sub_tlv", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_prefix_sid_srv6_l2vpn_sub_sub_tlv_type,
        { "Type", "bgp.prefix_sid.srv6_l2vpn.sub_sub_tlv.type", FT_UINT8, BASE_DEC,
          VALS(srv6_service_data_sub_sub_tlv_type), 0x0, "SRv6 Service Data Sub-Sub-TLV type", HFILL }},
      { &hf_bgp_prefix_sid_srv6_l2vpn_sub_sub_tlv_length,
        { "Length", "bgp.prefix_sid.srv6_l2vpn.sub_sub_tlv.length", FT_UINT16, BASE_DEC,
          NULL, 0x0, "SRv6 Service Data Sub-Sub-TLV length", HFILL }},
      { &hf_bgp_prefix_sid_srv6_l2vpn_sub_sub_tlv_value,
        { "Value", "bgp.prefix_sid.srv6_l2vpn.sub_sub_tlv.value", FT_BYTES, BASE_NONE,
          NULL, 0x0, "SRv6 Service Data Sub-Sub-TLV value", HFILL }},
      { &hf_bgp_prefix_sid_srv6_l2vpn_sid_locator_block_len,
        { "Locator Block Length", "bgp.prefix_sid.srv6_l2vpn.sid.locator_block_len", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_prefix_sid_srv6_l2vpn_sid_locator_node_len,
        { "Locator Node Length", "bgp.prefix_sid.srv6_l2vpn.sid.locator_node_len", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_prefix_sid_srv6_l2vpn_sid_func_len,
        { "Function Length", "bgp.prefix_sid.srv6_l2vpn.sid.func_len", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_prefix_sid_srv6_l2vpn_sid_arg_len,
        { "Argument Length", "bgp.prefix_sid.srv6_l2vpn.sid.arg_len", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_prefix_sid_srv6_l2vpn_sid_trans_len,
        { "Transposition Length", "bgp.prefix_sid.srv6_l2vpn.sid.trans_len", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_prefix_sid_srv6_l2vpn_sid_trans_offset,
        { "Transposition Offset", "bgp.prefix_sid.srv6_l2vpn.sid.trans_offset", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

        /* RFC5512 : BGP Encapsulation SAFI and the BGP Tunnel Encapsulation Attribute  */
      { &hf_bgp_update_encaps_tunnel_tlv_len,
        { "length", "bgp.update.encaps_tunnel_tlv_len", FT_UINT16,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_tlv_type,
        { "Type code", "bgp.update.encaps_tunnel_tlv_type", FT_UINT16, BASE_DEC,
          VALS(bgp_attr_tunnel_type), 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_len,
        { "length", "bgp.update.encaps_tunnel_tlv_sublen", FT_UINT16,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_type,
        { "Type code", "bgp.update.encaps_tunnel_subtlv_type", FT_UINT8, BASE_DEC,
          VALS(subtlv_type), 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_session_id,
        { "Session ID", "bgp.update.encaps_tunnel_tlv_subtlv_session_id", FT_UINT32,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_cookie,
        { "Cookie", "bgp.update.encaps_tunnel_tlv_subtlv_cookie", FT_BYTES,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_gre_key,
        { "GRE Key", "bgp.update.encaps_tunnel_tlv_subtlv_gre_key", FT_UINT32,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_color_value,
        { "Color Value", "bgp.update.encaps_tunnel_tlv_subtlv_color_value", FT_UINT32,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_lb_block_length,
        { "Load-balancing block length", "bgp.update.encaps_tunnel_tlv_subtlv_lb_block_length", FT_UINT32,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_vxlan_flags,
        { "Flags", "bgp.update.encaps_tunnel_tlv_subtlv.vxlan.flags", FT_UINT8,
          BASE_HEX, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_vxlan_flags_valid_vnid,
        { "Valid VN-ID", "bgp.update.encaps_tunnel_tlv_subtlv.vxlan.flags.valid_vnid", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), TUNNEL_SUBTLV_VXLAN_VALID_VNID, NULL, HFILL }},
      { &hf_bgp_update_encaps_tunnel_subtlv_vxlan_flags_valid_mac,
        { "Valid MAC address", "bgp.update.encaps_tunnel_tlv_subtlv.vxlan.flags.valid_mac", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), TUNNEL_SUBTLV_VXLAN_VALID_MAC, NULL, HFILL }},
      { &hf_bgp_update_encaps_tunnel_subtlv_vxlan_flags_reserved,
        { "Reserved", "bgp.update.encaps_tunnel_tlv_subtlv.vxlan.flags.reserved", FT_UINT8,
          BASE_HEX, NULL, TUNNEL_SUBTLV_VXLAN_RESERVED, NULL, HFILL }},
      { &hf_bgp_update_encaps_tunnel_subtlv_vxlan_vnid,
        { "VN-ID", "bgp.update.encaps_tunnel_tlv_subtlv.vxlan.vnid", FT_UINT24,
          BASE_HEX, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_vxlan_mac,
        { "MAC", "bgp.update.encaps_tunnel_tlv_subtlv.vxlan.mac", FT_ETHER,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_vxlan_reserved,
        { "Reserved", "bgp.update.encaps_tunnel_tlv_subtlv.vxlan.reserved", FT_UINT16,
          BASE_HEX, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_vxlan_gpe_flags,
        { "Flags", "bgp.update.encaps_tunnel_tlv_subtlv.vxlan_gpe.flags", FT_UINT8,
          BASE_HEX, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_vxlan_gpe_flags_version,
        { "Version", "bgp.update.encaps_tunnel_tlv_subtlv.vxlan_gpe.flags.version", FT_UINT8,
          BASE_DEC, NULL, TUNNEL_SUBTLV_VXLAN_GPE_VERSION, NULL, HFILL }},
      { &hf_bgp_update_encaps_tunnel_subtlv_vxlan_gpe_flags_valid_vnid,
        { "Valid VN-ID", "bgp.update.encaps_tunnel_tlv_subtlv.vxlan_gpe.flags.valid_vnid", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), TUNNEL_SUBTLV_VXLAN_GPE_VALID_VNID, NULL, HFILL }},
      { &hf_bgp_update_encaps_tunnel_subtlv_vxlan_gpe_flags_reserved,
        { "Reserved", "bgp.update.encaps_tunnel_tlv_subtlv.vxlan_gpe.flags.reserved", FT_UINT8,
          BASE_HEX, NULL, TUNNEL_SUBTLV_VXLAN_GPE_RESERVED, NULL, HFILL }},
      { &hf_bgp_update_encaps_tunnel_subtlv_vxlan_gpe_vnid,
        { "VN-ID", "bgp.update.encaps_tunnel_tlv_subtlv.vxlan_gpe.vnid", FT_UINT24,
          BASE_HEX, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_vxlan_gpe_reserved,
        { "Reserved", "bgp.update.encaps_tunnel_tlv_subtlv.vxlan_gpe.reserved", FT_UINT16,
          BASE_HEX, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_nvgre_flags,
        { "Flags", "bgp.update.encaps_tunnel_tlv_subtlv.nvgre.flags", FT_UINT8,
          BASE_HEX, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_nvgre_flags_valid_vnid,
        { "Valid VN-ID", "bgp.update.encaps_tunnel_tlv_subtlv.nvgre.flags.valid_vnid", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), TUNNEL_SUBTLV_NVGRE_VALID_VNID, NULL, HFILL }},
      { &hf_bgp_update_encaps_tunnel_subtlv_nvgre_flags_valid_mac,
        { "Valid MAC address", "bgp.update.encaps_tunnel_tlv_subtlv.nvgre.flags.valid_mac", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), TUNNEL_SUBTLV_NVGRE_VALID_MAC, NULL, HFILL }},
      { &hf_bgp_update_encaps_tunnel_subtlv_nvgre_flags_reserved,
        { "Reserved", "bgp.update.encaps_tunnel_tlv_subtlv.nvgre.flags.reserved", FT_UINT8,
          BASE_HEX, NULL, TUNNEL_SUBTLV_NVGRE_RESERVED, NULL, HFILL }},
      { &hf_bgp_update_encaps_tunnel_subtlv_nvgre_vnid,
        { "VN-ID", "bgp.update.encaps_tunnel_tlv_subtlv.nvgre.vnid", FT_UINT24,
          BASE_HEX, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_nvgre_mac,
        { "MAC", "bgp.update.encaps_tunnel_tlv_subtlv.nvgre.mac", FT_ETHER,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_nvgre_reserved,
        { "Reserved", "bgp.update.encaps_tunnel_tlv_subtlv.nvgre.reserved", FT_UINT16,
          BASE_HEX, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_value,
        { "Value", "bgp.update.encaps_tunnel_tlv_subtlv.value", FT_BYTES,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_pref_flags,
        { "Flags", "bgp.update.encaps_tunnel_tlv_subtlv.pref.flags", FT_UINT8,
          BASE_HEX, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_pref_reserved,
        { "Reserved", "bgp.update.encaps_tunnel_tlv_subtlv.pref.reserved", FT_UINT8,
          BASE_HEX, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_pref_preference,
        { "Preference", "bgp.update.encaps_tunnel_tlv_subtlv.pref.preference", FT_BYTES,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_binding_sid_flags,
        { "Flags", "bgp.update.encaps_tunnel_tlv_subtlv.binding_sid.flags", FT_UINT8,
          BASE_HEX, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_binding_sid_flags_specified,
        { "Specified-BSID-only", "bgp.update.encaps_tunnel_tlv_subtlv.binding_sid.flags.specified", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), TUNNEL_SUBTLV_BINDING_SPECIFIED, NULL, HFILL }},
      { &hf_bgp_update_encaps_tunnel_subtlv_binding_sid_flags_invalid,
        { "Drop Upon Invalid", "bgp.update.encaps_tunnel_tlv_subtlv.binding_sid.flags.invalid", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), TUNNEL_SUBTLV_BINDING_INVALID, NULL, HFILL }},
      { &hf_bgp_update_encaps_tunnel_subtlv_binding_sid_flags_reserved,
        { "Reserved", "bgp.update.encaps_tunnel_tlv_subtlv.binding_sid.flags.reserved", FT_UINT8,
          BASE_HEX, NULL, TUNNEL_SUBTLV_BINDING_RESERVED, NULL, HFILL }},
      { &hf_bgp_update_encaps_tunnel_subtlv_binding_sid_reserved,
        { "Reserved", "bgp.update.encaps_tunnel_tlv_subtlv.binding_sid.reserved", FT_UINT8,
          BASE_HEX, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_binding_sid_sid,
        { "Binding SID", "bgp.update.encaps_tunnel_tlv_subtlv.binding_sid.sid", FT_BYTES,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_enlp_flags,
        { "Flags", "bgp.update.encaps_tunnel_tlv_subtlv.enlp.flags", FT_UINT8,
          BASE_HEX, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_enlp_reserved,
        { "Reserved", "bgp.update.encaps_tunnel_tlv_subtlv.enlp.reserved", FT_UINT8,
          BASE_HEX, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_enlp_enlp,
        { "ENLP", "bgp.update.encaps_tunnel_tlv_subtlv.enlp.preference", FT_UINT8,
          BASE_DEC, VALS(bgp_enlp_type), 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_priority_priority,
        { "Priority", "bgp.update.encaps_tunnel_tlv_subtlv.priority.priority", FT_UINT8,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_priority_reserved,
        { "Reserved", "bgp.update.encaps_tunnel_tlv_subtlv.priority.reserved", FT_UINT8,
          BASE_HEX, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_segment_list_reserved,
        { "Reserved", "bgp.update.encaps_tunnel_tlv_subtlv.segment_list.reserved", FT_UINT8,
          BASE_HEX, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv,
        { "sub-TLVs", "bgp.update.encaps_tunnel_tlv_subtlv.segment_list.subtlv", FT_BYTES,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv_type,
        { "Type", "bgp.update.encaps_tunnel_tlv_subtlv.segment_list.subtlv.type", FT_UINT8,
          BASE_DEC, VALS(bgp_sr_policy_list_type), 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv_length,
        { "Length", "bgp.update.encaps_tunnel_tlv_subtlv.segment_list.subtlv.length", FT_UINT8,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv_flags,
        { "Flags", "bgp.update.encaps_tunnel_tlv_subtlv.segment_list_subtlv.flags", FT_UINT8,
          BASE_HEX, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv_flags_verification,
        { "SID verification", "bgp.update.encaps_tunnel_tlv_subtlv.segment_list_subtlv.flags.verification", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), TUNNEL_SUBTLV_SEGMENT_LIST_SUB_VERIFICATION, NULL, HFILL }},
      { &hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv_flags_algorithm,
        { "SR Algorithm id", "bgp.update.encaps_tunnel_tlv_subtlv.segment_list_subtlv.flags.algorithm", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), TUNNEL_SUBTLV_SEGMENT_LIST_SUB_ALGORITHM, NULL, HFILL }},
      { &hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv_flags_reserved,
        { "Reserved", "bgp.update.encaps_tunnel_tlv_subtlv.segment_list_subtlv.flags.reserved", FT_UINT8,
          BASE_HEX, NULL, TUNNEL_SUBTLV_SEGMENT_LIST_SUB_RESERVED, NULL, HFILL }},
      { &hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv_reserved,
        { "Reserved", "bgp.update.encaps_tunnel_tlv_subtlv.segment_list_subtlv.reserved", FT_BYTES,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv_mpls_label,
        { "MPLS Label", "bgp.update.encaps_tunnel_tlv_subtlv.segment_list_subtlv.mpls_label", FT_UINT24,
          BASE_HEX, NULL, BGP_MPLS_LABEL, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv_traffic_class,
        { "Traffic Class", "bgp.update.encaps_tunnel_tlv_subtlv.segment_list_subtlv.traffic_class", FT_UINT8,
          BASE_HEX, NULL, BGP_MPLS_TRAFFIC_CLASS, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv_bottom_stack,
        { "Bottom-of-Stack", "bgp.update.encaps_tunnel_tlv_subtlv.segment_list_subtlv.bottom_stack", FT_BOOLEAN,
          8, NULL, BGP_MPLS_BOTTOM_L_STACK, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv_ttl,
        { "TTL", "bgp.update.encaps_tunnel_tlv_subtlv.segment_list_subtlv.ttl", FT_UINT8,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_segment_list_subtlv_data,
        { "Data", "bgp.update.encaps_tunnel_tlv_subtlv.segment_list.subtlv.data", FT_BYTES,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_policy_name_reserved,
        { "Reserved", "bgp.update.encaps_tunnel_tlv_subtlv.policy_name.reserved", FT_UINT8,
          BASE_HEX, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_policy_name_name,
        { "Policy name", "bgp.update.encaps_tunnel_tlv_subtlv.policy_name.name", FT_STRING,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},

      /* BGP update path attribut SSA SAFI (deprecated IETF draft) */
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

      /* NLRI header description */
      { &hf_bgp_update_nlri,
        { "Network Layer Reachability Information (NLRI)", "bgp.update.nlri", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      /* Global NLRI description */
      { &hf_bgp_mp_reach_nlri_ipv4_prefix,
        { "MP Reach NLRI IPv4 prefix", "bgp.mp_reach_nlri_ipv4_prefix", FT_IPv4, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_mp_unreach_nlri_ipv4_prefix,
        { "MP Unreach NLRI IPv4 prefix", "bgp.mp_unreach_nlri_ipv4_prefix", FT_IPv4, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_mp_reach_nlri_ipv6_prefix,
        { "MP Reach NLRI IPv6 prefix", "bgp.mp_reach_nlri_ipv6_prefix", FT_IPv6, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_mp_unreach_nlri_ipv6_prefix,
        { "MP Unreach NLRI IPv6 prefix", "bgp.mp_unreach_nlri_ipv6_prefix", FT_IPv6, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_mp_nlri_tnl_id,
        { "MP Reach NLRI Tunnel Identifier", "bgp.mp_nlri_tnl_id", FT_UINT16, BASE_HEX,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_nlri_prefix,
        { "NLRI prefix", "bgp.nlri_prefix", FT_IPv4, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_nlri_path_id,
        { "NLRI path id", "bgp.nlri_path_id", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},

      /* mcast vpn nlri and capability */
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
      /* sr policy nlri*/
      { &hf_bgp_sr_policy_nlri_length,
        { "NLRI length", "bgp.sr_policy_nlri_length", FT_UINT8,
          BASE_DEC, NULL, 0x0, "NLRI length in bits", HFILL}},
      { &hf_bgp_sr_policy_nlri_distinguisher,
        { "Distinguisher", "bgp.sr_policy_nlri_distinguisher", FT_BYTES,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_sr_policy_nlri_policy_color,
        { "Policy color", "bgp.sr_policy_nlri_policy_color", FT_BYTES,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_sr_policy_nlri_endpoint_v4,
        { "Endpoint", "bgp.sr_policy_nlri_endpoint_ipv4", FT_IPv4,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_sr_policy_nlri_endpoint_v6,
        { "Endpoint", "bgp.sr_policy_nlri_endpoint_ipv6", FT_IPv6,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
        /* Bgp flow spec nlri and capability */
      { &hf_bgp_flowspec_nlri_t,
        { "FLOW-SPEC nlri", "bgp.flowspec_nlri", FT_BYTES, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_flowspec_nlri_route_distinguisher,
        { "Route Distinguisher", "bgp.flowspec_route_distinguisher", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_flowspec_nlri_route_distinguisher_type,
        { "Route Distinguisher Type", "bgp.flowspec_route_distinguisher_type", FT_UINT16,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_flowspec_nlri_route_dist_admin_asnum_2,
        { "Administrator Subfield", "bgp.flowspec_route_distinguisher_admin_as_num_2", FT_UINT16,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_flowspec_nlri_route_dist_admin_ipv4,
        { "Administrator Subfield", "bgp.flowspec_route_distinguisher_admin_ipv4", FT_IPv4,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_flowspec_nlri_route_dist_admin_asnum_4,
        { "Administrator Subfield", "bgp.flowspec_route_distinguisher_admin_as_num_4", FT_UINT32,
          BASE_HEX_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_flowspec_nlri_route_dist_asnum_2,
        { "Assigned Number Subfield", "bgp.flowspec_route_distinguisher_asnum_2", FT_UINT16,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_flowspec_nlri_route_dist_asnum_4,
        { "Assigned Number Subfield", "bgp.flowspec_route_distinguisher_asnum_4", FT_UINT32,
          BASE_HEX_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_flowspec_nlri_filter,
        { "Filter", "bgp.flowspec_nlri.filter", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_flowspec_nlri_filter_type,
        { "Filter type", "bgp.flowspec_nlri.filter_type", FT_UINT8, BASE_DEC,
          VALS(flowspec_nlri_opvaluepair_type), 0x0, NULL, HFILL }},
      { &hf_bgp_flowspec_nlri_length,
        { "NRLI length", "bgp.flowspec_nlri.length", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_flowspec_nlri_op_flags,
        { "Operator flags", "bgp.flowspec_nlri.opflags", FT_UINT8, BASE_HEX,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_flowspec_nlri_dst_pref_ipv4,
        { "Destination IP filter", "bgp.flowspec_nlri.dst_prefix_filter", FT_IPv4,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_flowspec_nlri_src_pref_ipv4,
        { "Source IP filter", "bgp.flowspec_nlri.src_prefix_filter", FT_IPv4,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_flowspec_nlri_op_eol,
        { "end-of-list", "bgp.flowspec_nlri.op.eol", FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), BGPNLRI_FSPEC_END_OF_LST, NULL, HFILL }},
      { &hf_bgp_flowspec_nlri_op_and,
        { "and", "bgp.flowspec_nlri.op.and", FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), BGPNLRI_FSPEC_AND_BIT, NULL, HFILL }},
      { &hf_bgp_flowspec_nlri_op_val_len,
        { "Value length", "bgp.flowspec_nlri.op.val_len", FT_UINT8, BASE_DEC,
          VALS(flow_spec_op_len_val), BGPNLRI_FSPEC_VAL_LEN, NULL, HFILL }},
      { &hf_bgp_flowspec_nlri_op_un_bit4,
        { "Reserved", "bgp.flowspec_nlri.op.un_bit4", FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), BGPNLRI_FSPEC_UNUSED_BIT4, "Unused (must be zero)",HFILL}},
      { &hf_bgp_flowspec_nlri_op_un_bit5,
        { "Reserved", "bgp.flowspec_nlri.op.un_bit5", FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), BGPNLRI_FSPEC_UNUSED_BIT5, "Unused (must be zero)", HFILL}},
      { &hf_bgp_flowspec_nlri_dec_val_8,
        { "Decimal value", "bgp.flowspec_nlri.dec_val_8", FT_UINT8, BASE_DEC,
          NULL, 0X0, NULL, HFILL }},
      { &hf_bgp_flowspec_nlri_dec_val_16,
        { "Decimal value", "bgp.flowspec_nlri.dec_val_16", FT_UINT16, BASE_DEC,
          NULL, 0X0, NULL, HFILL }},
      { &hf_bgp_flowspec_nlri_dec_val_32,
        { "Decimal value", "bgp.flowspec_nlri.dec_val_32", FT_UINT32, BASE_DEC,
          NULL, 0X0, NULL, HFILL }},
      { &hf_bgp_flowspec_nlri_dec_val_64,
        { "Decimal value", "bgp.flowspec_nlri.dec_val_64", FT_UINT64, BASE_DEC,
          NULL, 0X0, NULL, HFILL }},
      { &hf_bgp_flowspec_nlri_op_lt,
        { "less than", "bgp.flowspec_nlri.op.lt", FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), BGPNLRI_FSPEC_LESS_THAN, NULL, HFILL }},
      { &hf_bgp_flowspec_nlri_op_gt,
        { "greater than", "bgp.flowspec_nlri.op.gt", FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), BGPNLRI_FSPEC_GREATER_THAN, NULL, HFILL }},
      { &hf_bgp_flowspec_nlri_op_eq,
        { "equal", "bgp.flowspec_nlri.op.equal", FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), BGPNLRI_FSPEC_EQUAL, NULL, HFILL }},
      { &hf_bgp_flowspec_nlri_op_flg_not,
        { "logical negation", "bgp.flowspec_nlri.op.flg_not", FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), BGPNLRI_FSPEC_TCPF_NOTBIT, NULL, HFILL }},
      { &hf_bgp_flowspec_nlri_op_flg_match,
        { "Match bit", "bgp.flowspec_nlri.op.flg_match", FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), BGPNLRI_FSPEC_TCPF_MATCHBIT, NULL, HFILL }},
      { &hf_bgp_flowspec_nlri_tcp_flags,
        { "TCP flags", "bgp.flowspec_nlri.val_tcp.flags", FT_UINT8, BASE_HEX,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_flowspec_nlri_tcp_flags_cwr,
        { "Congestion Window Reduced (CWR)", "bgp.flowspec_nlri.val_tcp.flags.cwr", FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), BGPNLRI_FSPEC_TH_CWR, NULL, HFILL }},
      { &hf_bgp_flowspec_nlri_tcp_flags_ecn,
        { "ECN-Echo", "bgp.flowspec_nlri.val_tcp.flags.ecn", FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), BGPNLRI_FSPEC_TH_ECN, NULL, HFILL }},
      { &hf_bgp_flowspec_nlri_tcp_flags_urg,
        { "Urgent",  "bgp.flowspec_nlri.val_tcp.flags.urg", FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), BGPNLRI_FSPEC_TH_URG, NULL, HFILL }},
      { &hf_bgp_flowspec_nlri_tcp_flags_ack,
        { "Acknowledgment", "bgp.flowspec_nlri.val_tcp.flags.ack", FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), BGPNLRI_FSPEC_TH_ACK, NULL, HFILL }},
      { &hf_bgp_flowspec_nlri_tcp_flags_push,
        { "Push", "bgp.flowspec_nlri.val_tcp.flags.push", FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), BGPNLRI_FSPEC_TH_PUSH, NULL, HFILL }},
      { &hf_bgp_flowspec_nlri_tcp_flags_reset,
        { "Reset", "bgp.flowspec_nlri.val_tcp.flags.reset", FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), BGPNLRI_FSPEC_TH_RST, NULL, HFILL }},
      { &hf_bgp_flowspec_nlri_tcp_flags_syn,
        { "Syn", "bgp.flowspec_nlri.val_tcp.flags.syn", FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), BGPNLRI_FSPEC_TH_SYN, NULL, HFILL }},
      { &hf_bgp_flowspec_nlri_tcp_flags_fin,
        { "Fin", "bgp.flowspec_nlri.val_tcp.flags.fin", FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), BGPNLRI_FSPEC_TH_FIN, NULL, HFILL }},
      { &hf_bgp_flowspec_nlri_fflag,
        { "Fragment Flag", "bgp.flowspec_nlri.val_frag", FT_UINT8, BASE_HEX,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_flowspec_nlri_fflag_lf,
        { "Last fragment", "bgp.flowspec_nlri.val_frag_lf", FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), BGPNLRI_FSPEC_FG_LF, NULL, HFILL }},
      { &hf_bgp_flowspec_nlri_fflag_ff,
        { "First fragment", "bgp.flowspec_nlri.val_frag_ff", FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), BGPNLRI_FSPEC_FG_FF, NULL, HFILL }},
      { &hf_bgp_flowspec_nlri_fflag_isf,
        { "Is a fragment", "bgp.flowspec_nlri.val_frag_isf", FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), BGPNLRI_FSPEC_FG_ISF, NULL, HFILL }},
      { &hf_bgp_flowspec_nlri_fflag_df,
        { "Don't fragment", "bgp.flowspec_nlri.val_frag_df", FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), BGPNLRI_FSPEC_FG_DF, NULL, HFILL }},
      { &hf_bgp_flowspec_nlri_dscp,
        { "Differentiated Services Codepoint", "bgp.flowspec_nlri.val_dsfield", FT_UINT8, BASE_HEX | BASE_EXT_STRING,
          &dscp_vals_ext, BGPNLRI_FSPEC_DSCP_BITMASK, NULL, HFILL }},
      { &hf_bgp_flowspec_nlri_src_ipv6_pref,
        { "Source IPv6 prefix", "bgp.flowspec_nlri.src_ipv6_pref", FT_IPv6, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_flowspec_nlri_dst_ipv6_pref,
        { "Destination IPv6 prefix", "bgp.flowspec_nlri.dst_ipv6_pref", FT_IPv6, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_flowspec_nlri_ipv6_pref_len,
        { "IPv6 prefix length", "bgp.flowspec_nlri.ipv6_pref_length", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_flowspec_nlri_ipv6_pref_offset,
        { "IPv6 prefix offset", "bgp.flowspec_nlri.ipv6_pref_offset", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
        /* end of bgp flow spec */
        /* BGP update safi ndt nlri  draft-nalawade-idr-mdt-safi-03 */
      { &hf_bgp_mdt_nlri_safi_rd,
        { "Route Distinguisher", "bgp.mdt_safi_rd", FT_BYTES,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_mdt_nlri_safi_ipv4_addr,
        { "IPv4 Address", "bgp.mdt_safi_ipv4_addr", FT_IPv4,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_mdt_nlri_safi_group_addr,
        { "Group Address", "bgp.mdt_safi_group_addr", FT_IPv4,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
        /* BGP update extended community header field */
      { &hf_bgp_ext_communities,
        { "Carried extended communities", "bgp.ext_communities", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_ext_community,
        { "Community", "bgp.ext_community", FT_NONE, BASE_NONE,
          NULL, 0x0, "Extended Community attribute", HFILL }},
      { &hf_bgp_ext_com_type_high,
        { "Type", "bgp.ext_com.type", FT_UINT8, BASE_HEX,
          VALS(bgpext_com_type_high), 0x0, "Extended Community type", HFILL }},
      { &hf_bgp_ext_com_type_auth,
        { "IANA Authority", "bgp.ext_com.type.auth", FT_BOOLEAN, 8,
          TFS(&tfs_bgpext_com_type_auth), BGP_EXT_COM_TYPE_AUTH, "IANA Type Allocation Policy", HFILL }},
      {&hf_bgp_ext_com_type_tran,
        { "Transitive across AS", "bgp.ext_com.type.tran", FT_BOOLEAN, 8,
          TFS(&tfs_non_transitive_transitive), BGP_EXT_COM_TYPE_TRAN, "Transitivity of the attribute across autonomous systems", HFILL }},
      { &hf_bgp_ext_com_stype_low_unknown,
        { "Subtype", "bgp.ext_com.stype_unknown", FT_UINT8, BASE_HEX,
          NULL, 0x0, "Extended Community subtype", HFILL }},
      { &hf_bgp_ext_com_stype_tr_evpn,
        { "Subtype (EVPN)", "bgp.ext_com.stype_tr_evpn", FT_UINT8, BASE_HEX,
          VALS(bgpext_com_stype_tr_evpn), 0x0, "EVPN Extended Community subtype", HFILL}},
      { &hf_bgp_ext_com_stype_tr_as2,
        { "Subtype (AS2)", "bgp.ext_com.stype_tr_as2", FT_UINT8, BASE_HEX,
          VALS(bgpext_com_stype_tr_as2), 0x0, "2-Octet AS-Specific Transitive Extended Community subtype", HFILL}},
      { &hf_bgp_ext_com_stype_ntr_as2,
        { "Subtype (Non-transitive AS2)", "bgp.ext_com.stype_ntr_as2", FT_UINT8, BASE_HEX,
          VALS(bgpext_com_stype_ntr_as2), 0x0, "2-Octet AS-Specific Non-transitive Extended Community subtype", HFILL}},
      { &hf_bgp_ext_com_stype_tr_as4,
        { "Subtype (AS4)", "bgp.ext_com.stype_tr_as4", FT_UINT8, BASE_HEX,
          VALS(bgpext_com_stype_tr_as4), 0x0, "4-Octet AS-Specific Transitive Extended Community subtype", HFILL}},
      { &hf_bgp_ext_com_stype_ntr_as4,
        { "Subtype (Non-transitive AS4)", "bgp.ext_com.stype_ntr_as4", FT_UINT8, BASE_HEX,
          VALS(bgpext_com_stype_ntr_as4), 0x0, "4-Octet AS-Specific Non-transitive Extended Community subtype", HFILL}},
      { &hf_bgp_ext_com_stype_tr_IP4,
        { "Subtype (IPv4)", "bgp.ext_com.stype_tr_IP4", FT_UINT8, BASE_HEX,
          VALS(bgpext_com_stype_tr_IP4), 0x0, "IPv4-Address-Specific Transitive Extended Community subtype", HFILL}},
      { &hf_bgp_ext_com_stype_ntr_IP4,
        { "Subtype (Non-transitive IPv4)", "bgp.ext_com.stype_ntr_IP4", FT_UINT8, BASE_HEX,
          VALS(bgpext_com_stype_ntr_IP4), 0x0, "IPv4-Address-Specific Non-transitive Extended Community subtype", HFILL}},
      { &hf_bgp_ext_com_stype_tr_opaque,
        { "Subtype (Opaque)", "bgp.ext_com.stype_tr_opaque", FT_UINT8, BASE_HEX,
          VALS(bgpext_com_stype_tr_opaque), 0x0, "Opaque Transitive Extended Community subtype", HFILL}},
      { &hf_bgp_ext_com_stype_ntr_opaque,
        { "Subtype (Non-transitive Opaque)", "bgp.ext_com.stype_ntr_opaque", FT_UINT8, BASE_HEX,
          VALS(bgpext_com_stype_ntr_opaque), 0x0, "Opaque Non-transitive Extended Community subtype", HFILL}},
      { &hf_bgp_ext_com_tunnel_type,
        { "Tunnel type", "bgp.ext_com.tunnel_type", FT_UINT16, BASE_DEC,
          VALS(bgpext_com_tunnel_type), 0x0, "Tunnel encapsulation type", HFILL}},
      { &hf_bgp_ext_com_stype_tr_exp,
        { "Subtype (Experimental)", "bgp.ext_com.stype_tr_exp", FT_UINT8, BASE_HEX,
          VALS(bgpext_com_stype_tr_exp), 0x0, "Experimental Transitive Extended Community subtype", HFILL}},
      { &hf_bgp_ext_com_stype_tr_exp_2,
        { "Subtype (Experimental Part 2)", "bgp.ext_com.stype_tr_exp_2", FT_UINT8, BASE_HEX,
          VALS(bgpext_com_stype_tr_exp_2), 0x0, "Generic Transitive Experimental Use Extended Community Part 2 Sub-Types", HFILL}},
      { &hf_bgp_ext_com_stype_tr_exp_3,
        { "Subtype (Experimental Part 3)", "bgp.ext_com.stype_tr_exp_3", FT_UINT8, BASE_HEX,
          VALS(bgpext_com_stype_tr_exp_3), 0x0, "Generic Transitive Experimental Use Extended Community Part 3 Sub-Types", HFILL}},
      { &hf_bgp_ext_com_value_as2,
        { "2-Octet AS", "bgp.ext_com.value_as2", FT_UINT16, BASE_DEC,
          NULL, 0x0, "Global Administrator Field value (2B Autonomous System Number)", HFILL }},
      { &hf_bgp_ext_com_value_as4,
        { "4-Octet AS", "bgp.ext_com.value_as4", FT_UINT32, BASE_DEC,
          NULL, 0x0, "Global Administrator Field value (4B Autonomous System Number)", HFILL }},
      { &hf_bgp_ext_com_value_IP4,
        { "IPv4 address", "bgp.ext_com.value_IP4", FT_IPv4, BASE_NONE,
          NULL, 0x0, "Global Administrator Field value (IPv4 Address)", HFILL }},
      { &hf_bgp_ext_com_value_an2,
        { "2-Octet AN", "bgp.ext_com.value_an2", FT_UINT16, BASE_DEC,
          NULL, 0x0, "Local Administrator Field value (2B Assigned Number)", HFILL }},
      { &hf_bgp_ext_com_value_an4,
        { "4-Octet AN", "bgp.ext_com.value_an4", FT_UINT32, BASE_DEC,
          NULL, 0x0, "Local Administrator Field value (4B Assigned Number)", HFILL }},
      { &hf_bgp_ext_com_value_link_bw,
        { "Link bandwidth", "bgp.ext_com.value_link_bw", FT_FLOAT, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ext_com_value_ospf_rt_area,
        { "Area ID", "bgp.ext_com.value_ospf_rtype.area", FT_IPv4, BASE_NONE,
          NULL, 0x0, "Original OSPF Area ID this route comes from", HFILL }},
      { &hf_bgp_ext_com_value_ospf_rt_type,
        { "Route type", "bgp.ext_com.value_ospf_rtype.type", FT_UINT8, BASE_DEC,
          VALS(bgpext_com_ospf_rtype), 0x0, "Original OSPF LSA Type that carried this route", HFILL}},
      { &hf_bgp_ext_com_value_ospf_rt_options,
        { "Options", "bgp.ext_com.value_ospf_rtype.options", FT_UINT8, BASE_HEX,
          NULL, 0x0, "OSPF Route Type Options bitfield", HFILL }},
      { &hf_bgp_ext_com_value_ospf_rt_options_mt,
        { "Metric type", "bgp.ext_com.value_ospf_rtype.options.mt", FT_BOOLEAN, 8,
          TFS(&tfs_ospf_rt_mt), BGP_OSPF_RTYPE_METRIC_TYPE, "OSPF metric type (Type-1 or Type-2) of the original route", HFILL }},
      { &hf_bgp_ext_com_value_ospf_rid,
        { "Router ID", "bgp.ext_com.value_ospf_rid", FT_IPv4, BASE_NONE,
          NULL, 0x0, "OSPF Router ID of the redistributing PE router", HFILL }},
      { &hf_bgp_ext_com_value_fs_remark,
        { "Remarking value", "bgp.ext_com.value_fs_dscp", FT_UINT8, BASE_HEX | BASE_EXT_STRING,
          &dscp_vals_ext, BGPNLRI_FSPEC_DSCP_BITMASK, NULL, HFILL }},
      { &hf_bgp_ext_com_value_raw,
        { "Raw Value", "bgp.ext_com.value_raw", FT_UINT48, BASE_HEX,
          NULL, 0x0, "Raw value of the lowmost 6 octets of the Extended Community attribute", HFILL }},
            /* BGP update extended community flow spec RFC 5575 */
      { &hf_bgp_ext_com_flow_act_samp_act,
        { "Sample", "bgp.ext_com_flow.sample", FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), BGP_EXT_COM_FSPEC_ACT_S, NULL, HFILL }},
      { &hf_bgp_ext_com_flow_act_term_act,
        { "Terminal action", "bgp.ext_com_flow.traff_act", FT_BOOLEAN, 8,
          TFS(&tfs_set_notset),BGP_EXT_COM_FSPEC_ACT_T,NULL, HFILL}},
      { &hf_bgp_ext_com_flow_rate_float,
        { "Rate shaper", "bgp.ext_com_flow.rate_limit", FT_FLOAT, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ext_com_flow_act_allset,
        { "5 Bytes", "bgp.flowspec_ext_com.emptybytes", FT_BYTES, BASE_NONE,
          NULL, 0x0, "Must be set to all 0", HFILL }},
            /* BGP QoS propagation draft-knoll-idr-qos-attribute */
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
        { "Aggregation of markins", "bgp.ext_com_qos.flags.agg_marking", FT_BOOLEAN, 8,
          TFS(&tfs_yes_no), 0x04, NULL, HFILL}},
      { &hf_bgp_ext_com_cos_flags,
        { "Flags byte", "bgp.ext_com_cos.flags", FT_UINT8, BASE_HEX,
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
      /* BGP L2 extended community RFC 4761, RFC 6624 */
            /* draft-ietf-l2vpn-vpls-multihoming */
      { &hf_bgp_ext_com_l2_encaps,
        { "Encaps Type", "bgp.ext_com_l2.encaps_type", FT_UINT8, BASE_DEC,
          VALS(bgp_l2vpn_encaps), 0, NULL, HFILL}},
      { &hf_bgp_ext_com_l2_c_flags,
        { "Control Flags", "bgp.ext_com_l2.c_flags", FT_UINT8, BASE_HEX,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_ext_com_l2_flag_d,
        { "Down flag", "bgp.ext_com_l2.flag_d",FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), BGP_EXT_COM_L2_FLAG_D, NULL, HFILL }},
      { &hf_bgp_ext_com_l2_flag_z1,
        { "Unassigned", "bgp.ext_com_l2.flag_z1",FT_UINT8, BASE_DEC,
          NULL, BGP_EXT_COM_L2_FLAG_Z1, "Must be Zero", HFILL }},
      { &hf_bgp_ext_com_l2_flag_f,
        { "Flush flag", "bgp.ext_com_l2.flag_f",FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), BGP_EXT_COM_L2_FLAG_F, NULL, HFILL }},
      { &hf_bgp_ext_com_l2_flag_z345,
        { "Unassigned", "bgp.ext_com_l2.flag_z345",FT_UINT8, BASE_DEC,
          NULL, BGP_EXT_COM_L2_FLAG_Z345, "Must be Zero", HFILL }},
      { &hf_bgp_ext_com_l2_flag_c,
        { "C flag", "bgp.ext_com_l2.flag_c",FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), BGP_EXT_COM_L2_FLAG_C, NULL, HFILL }},
      { &hf_bgp_ext_com_l2_flag_s,
        { "S flag", "bgp.ext_com_l2.flag_s",FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), BGP_EXT_COM_L2_FLAG_S, NULL, HFILL }},
      { &hf_bgp_ext_com_l2_mtu,
        { "Layer-2 MTU", "bgp.ext_com_l2.l2_mtu", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ext_com_l2_esi_label_flag,
        { "Single active bit", "bgp.ext_com_l2.esi_label_flag",FT_BOOLEAN, 8,
          TFS(&tfs_esi_label_flag), BGP_EXT_COM_ESI_LABEL_FLAGS, NULL, HFILL }},
      { &hf_bgp_ext_com_etree_root_vlan,
        { "Root VLAN", "bgp.ext_com_etree.root_vlan", FT_UINT16, BASE_DEC,
          NULL, 0x0FFF, NULL, HFILL }},
      { &hf_bgp_ext_com_etree_leaf_vlan,
        { "Leaf VLAN", "bgp.ext_com_etree.leaf_vlan", FT_UINT16, BASE_DEC,
          NULL, 0x0FFF, NULL, HFILL }},
      { &hf_bgp_ext_com_etree_flags,
        { "Flags", "bgp.ext_com_etree.flags", FT_UINT16, BASE_HEX,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_ext_com_etree_flag_reserved,
        { "Reserved", "bgp.ext_com_etree.flag_reserved",FT_UINT16, BASE_HEX,
          NULL, BGP_EXT_COM_ETREE_FLAG_RESERVED, NULL, HFILL }},
      { &hf_bgp_ext_com_etree_flag_p,
        { "P", "bgp.ext_com_etree.flag_p",FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), BGP_EXT_COM_ETREE_FLAG_P, "PE is attached with leaf nodes only", HFILL }},
      { &hf_bgp_ext_com_etree_flag_v,
        { "V", "bgp.ext_com_etree.flag_v",FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), BGP_EXT_COM_ETREE_FLAG_V, "VLAN mapping", HFILL }},
      { &hf_bgp_ext_com_evpn_mmac_flag,
        { "Flags", "bgp.ext_com_evpn.mmac.flags", FT_UINT8, BASE_HEX,
          NULL, 0x0, "MAC Mobility flags", HFILL }},
      { &hf_bgp_ext_com_evpn_mmac_flag_sticky,
        { "Sticky/Static MAC", "bgp.ext_com_evpn.mmac.flags.sticky", FT_BOOLEAN, 8,
          TFS(&tfs_yes_no), BGP_EXT_COM_EVPN_MMAC_STICKY, "Indicates whether the MAC address is fixed or movable", HFILL }},
      { &hf_bgp_ext_com_evpn_mmac_seq,
        { "Sequence number", "bgp.ext_com_evpn.mmac.seq", FT_UINT32, BASE_DEC,
          NULL, 0x0, "MAC Mobility Update Sequence number", HFILL }},
      { &hf_bgp_ext_com_evpn_esirt,
        { "ES-Import Route Target", "bgp.ext_com_evpn.esi.rt", FT_ETHER, BASE_NONE,
          NULL, 0x0, "Route Target as a MAC Address", HFILL }},
      { &hf_bgp_ext_com_evpn_routermac,
        { "Router's MAC", "bgp.ext_com_evpn.esi.router_mac", FT_ETHER, BASE_NONE,
          NULL, 0x0, "Router's MAC Address", HFILL }},
      { &hf_bgp_ext_com_evpn_l2attr_flags,
        { "Flags", "bgp.ext_com_evpn.l2attr.flags", FT_UINT16, BASE_HEX,
          NULL, 0x0, "EVPN L2 attribute flags", HFILL }},
      { &hf_bgp_ext_com_evpn_l2attr_flag_reserved,
        { "Reserved", "bgp.ext_com_evpn.l2attr.flag_reserved", FT_UINT16, BASE_HEX,
          NULL, BGP_EXT_COM_EVPN_L2ATTR_FLAG_RESERVED, NULL, HFILL }},
      { &hf_bgp_ext_com_evpn_l2attr_flag_ci,
        { "CI flag", "bgp.ext_com_evpn.l2attr.flag_ci", FT_BOOLEAN, 16,
          TFS(&tfs_set_notset), BGP_EXT_COM_EVPN_L2ATTR_FLAG_CI, "Control Word Indicator Extended Community can be advertised", HFILL }},
      { &hf_bgp_ext_com_evpn_l2attr_flag_f,
        { "F flag", "bgp.ext_com_evpn.l2attr.flag_f", FT_BOOLEAN, 16,
          TFS(&tfs_set_notset), BGP_EXT_COM_EVPN_L2ATTR_FLAG_F, "PE is capable to send and receive flow label", HFILL }},
      { &hf_bgp_ext_com_evpn_l2attr_flag_c,
        { "C flag", "bgp.ext_com_evpn.l2attr.flag_c", FT_BOOLEAN, 16,
          TFS(&tfs_set_notset), BGP_EXT_COM_EVPN_L2ATTR_FLAG_C, "Control word must be present when sending EVPN packets to this PE", HFILL }},
      { &hf_bgp_ext_com_evpn_l2attr_flag_p,
        { "P flag", "bgp.ext_com_evpn.l2attr.flag_p", FT_BOOLEAN, 16,
          TFS(&tfs_set_notset), BGP_EXT_COM_EVPN_L2ATTR_FLAG_P, "Primary PE", HFILL }},
      { &hf_bgp_ext_com_evpn_l2attr_flag_b,
        { "B flag", "bgp.ext_com_evpn.l2attr.flag_b", FT_BOOLEAN, 16,
          TFS(&tfs_set_notset), BGP_EXT_COM_EVPN_L2ATTR_FLAG_B, "Backup PE", HFILL }},
      { &hf_bgp_ext_com_evpn_l2attr_l2_mtu,
        { "L2 MTU", "bgp.ext_com_evpn.l2attr.l2_mtu", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_ext_com_evpn_l2attr_reserved,
        { "Reserved", "bgp.ext_com_evpn.l2attr.reserved", FT_BYTES, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_ext_com_evpn_etree_flags,
        { "Flags", "bgp.ext_com_evpn.etree.flags", FT_UINT8, BASE_HEX,
          NULL, 0x0, "EVPN E-Tree attribute flags", HFILL }},
      { &hf_bgp_ext_com_evpn_etree_flag_reserved,
        { "Reserved", "bgp.ext_com_evpn.etree.flag_reserved", FT_UINT8, BASE_HEX,
          NULL, BGP_EXT_COM_EVPN_ETREE_FLAG_RESERVED, NULL, HFILL }},
      { &hf_bgp_ext_com_evpn_etree_flag_l,
        { "L flag", "bgp.ext_com_evpn.etree.flag_l", FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), BGP_EXT_COM_EVPN_ETREE_FLAG_L, "Leaf-Indication", HFILL }},
      { &hf_bgp_ext_com_evpn_etree_reserved,
        { "Reserved", "bgp.ext_com_evpn.etree.reserved", FT_BYTES, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      /* BGP Cost Community */
      { &hf_bgp_ext_com_cost_poi,
        { "Point of insertion", "bgp.ext_com_cost.poi", FT_UINT8, BASE_DEC,
          VALS(bgpext_com_cost_poi_type), 0x0, "Placement of the Cost value in the BGP Best Path algorithm", HFILL }},
      { &hf_bgp_ext_com_cost_cid,
        { "Community ID", "bgp.ext_com_cost.cid", FT_UINT8, BASE_DEC,
          NULL, 0x0, "Community instance ID to distinguish between multiple Cost communities", HFILL }},
      { &hf_bgp_ext_com_cost_cost,
        { "Cost", "bgp.ext_com_cost.cost", FT_UINT32, BASE_DEC,
          NULL, 0x0, "Cost value", HFILL }},
      { &hf_bgp_ext_com_cost_cid_rep,
        { "Cost use", "bgp.ext_com_cost.cid.use", FT_BOOLEAN, 8,
          TFS(&tfs_cost_replace), BGP_EXT_COM_COST_CID_REP, "Indicates whether the Cost value will replace the original attribute value", HFILL }},
      /* EIGRP Route Metrics Extended Communities */
      { &hf_bgp_ext_com_stype_tr_exp_eigrp,
        { "Route Attributes", "bgp.ext_com_eigrp", FT_UINT8, BASE_DEC,
          VALS(bgpext_com_stype_tr_eigrp), 0x0, "Original EIGRP route attributes", HFILL }},
      { &hf_bgp_ext_com_eigrp_flags,
        { "Route flags", "bgp.ext_com_eigrp.flags", FT_UINT16, BASE_HEX,
          NULL, 0x0, "EIGRP Route flags bitfield", HFILL }},
      { &hf_bgp_ext_com_eigrp_flags_rt,
        { "Route type", "bgp.ext_com_eigrp.flags.rt", FT_BOOLEAN, 16,
          TFS(&tfs_eigrp_rtype), BGP_EXT_COM_EXP_EIGRP_FLAG_RT, "Original EIGRP route type (internal/external)", HFILL }},
      { &hf_bgp_ext_com_eigrp_rtag,
        { "Route tag", "bgp.ext_com_eigrp.rtag", FT_UINT32, BASE_DEC,
          NULL, 0x0, "Original EIGRP route tag", HFILL }},
      { &hf_bgp_ext_com_eigrp_asn,
        { "AS Number", "bgp.ext_com_eigrp.asn", FT_UINT16, BASE_DEC,
          NULL, 0x0, "Original EIGRP Autonomous System Number this route comes from", HFILL }},
      { &hf_bgp_ext_com_eigrp_delay,
        { "Delay", "bgp.ext_com_eigrp.dly", FT_UINT32, BASE_DEC,
          NULL, 0x0, "Original EIGRP route delay metric", HFILL }},
      { &hf_bgp_ext_com_eigrp_rly,
        { "Reliability", "bgp.ext_com_eigrp.rly", FT_UINT8, BASE_DEC,
          NULL, 0x0, "Original EIGRP route reliability metric", HFILL }},
      { &hf_bgp_ext_com_eigrp_hops,
        { "Hop count", "bgp.ext_com_eigrp.hops", FT_UINT8, BASE_DEC,
          NULL, 0x0, "Original EIGRP route hop count", HFILL }},
      { &hf_bgp_ext_com_eigrp_bw,
        { "Bandwidth", "bgp.ext_com_eigrp.bw", FT_UINT32, BASE_DEC,
          NULL, 0x0, "Original EIGRP route bandwidth metric", HFILL }},
      { &hf_bgp_ext_com_eigrp_load,
        { "Load", "bgp.ext_com_eigrp.load", FT_UINT8, BASE_DEC,
          NULL, 0x0, "Original EIGRP route load metric", HFILL }},
      { &hf_bgp_ext_com_eigrp_mtu,
        { "MTU", "bgp.ext_com_eigrp.mtu", FT_UINT32, BASE_DEC,
          NULL, 0x0, "Original EIGRP route path MTU", HFILL }},
      { &hf_bgp_ext_com_eigrp_rid,
        { "Router ID", "bgp.ext_com_eigrp.rid", FT_IPv4, BASE_NONE,
          NULL, 0x0, "EIGRP Router ID of the router that originated the route", HFILL }},
      { &hf_bgp_ext_com_eigrp_e_asn,
        { "External AS Number", "bgp.ext_com_eigrp.e_asn", FT_UINT16, BASE_DEC,
          NULL, 0x0, "Original AS Number of the route before its redistribution into EIGRP", HFILL }},
      { &hf_bgp_ext_com_eigrp_e_rid,
        { "External Router ID", "bgp.ext_com_eigrp.e_rid", FT_IPv4, BASE_NONE,
          NULL, 0x0, "EIGRP Router ID of the router that redistributed this route into EIGRP", HFILL }},
      { &hf_bgp_ext_com_eigrp_e_pid,
        { "External protocol", "bgp.ext_com_eigrp.e_pid", FT_UINT16, BASE_DEC,
          VALS(eigrp_proto2string), 0x0, "Original routing protocol from which this route was redistributed into EIGRP", HFILL }},
      { &hf_bgp_ext_com_eigrp_e_m,
        { "External metric", "bgp.ext_com_eigrp.e_metric", FT_UINT32, BASE_DEC,
          NULL, 0x0, "Original metric of the route before its redistribution into EIGRP", HFILL }},
      /* idr-ls-03 */
      { &hf_bgp_ls_type,
        { "Type", "bgp.ls.type", FT_UINT16, BASE_DEC,
          NULL, 0x0, "BGP-LS message type", HFILL }},
      { &hf_bgp_ls_length,
        { "Length", "bgp.ls.length", FT_UINT16, BASE_DEC,
          NULL, 0x0, "The total length of the message payload in octets", HFILL }},
      { &hf_bgp_ls_nlri,
        { "BGP-LS NLRI", "bgp.ls.nlri", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_safi128_nlri,
        { "Link State SAFI 128 NLRI", "bgp.ls.nlri_safi128", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_safi128_nlri_route_distinguisher,
        { "Route Distinguisher", "bgp.ls.nlri_safi128_route_distinguisher", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_safi128_nlri_route_distinguisher_type,
        { "Route Distinguisher Type", "bgp.ls.nlri_safi128_route_distinguisher_type", FT_UINT16,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_safi128_nlri_route_dist_admin_asnum_2,
        { "Administrator Subfield", "bgp.ls.nlri_safi128_route_distinguisher_admin_as_num_2", FT_UINT16,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_safi128_nlri_route_dist_admin_ipv4,
        { "Administrator Subfield", "bgp.ls.nlri_safi128_route_distinguisher_admin_ipv4", FT_IPv4,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_safi128_nlri_route_dist_admin_asnum_4,
        { "Administrator Subfield", "bgp.ls.nlri_safi128_route_distinguisher_admin_as_num_4", FT_UINT32,
          BASE_HEX_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_safi128_nlri_route_dist_asnum_2,
        { "Assigned Number Subfield", "bgp.ls.nlri_safi128_route_distinguisher_asnum_2", FT_UINT16,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_safi128_nlri_route_dist_asnum_4,
        { "Assigned Number Subfield", "bgp.ls.nlri_safi128_route_distinguisher_asnum_4", FT_UINT32,
          BASE_HEX_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_nlri_type,
        { "NLRI Type", "bgp.ls.nlri_type", FT_UINT16,
          BASE_DEC, VALS(bgp_ls_nlri_type_vals), 0x0, NULL, HFILL}},
      { &hf_bgp_ls_nlri_length,
        { "NLRI Length", "bgp.ls.nlri_length", FT_UINT16,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_nlri_link_nlri_type,
        { "Link-State NLRI Link NLRI", "bgp.ls.nlri_link", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_nlri_link_descriptors_tlv,
        { "Link Descriptors TLV", "bgp.ls.nlri_link_descriptors_tlv", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_nlri_prefix_descriptors_tlv,
        { "Prefix Descriptors TLV", "bgp.ls.nlri_prefix_descriptors_tlv", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_nlri_link_local_identifier,
        { "Link Local Identifier", "bgp.ls.nlri_link_local_identifier", FT_UINT32,
          BASE_HEX_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_nlri_link_remote_identifier,
        { "Link Remote Identifier", "bgp.ls.nlri_link_remote_identifier", FT_UINT32,
          BASE_HEX_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_nlri_ipv4_interface_address,
        { "IPv4 Interface Address", "bgp.ls.nlri_ipv4_interface_address", FT_IPv4,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_nlri_ipv4_neighbor_address,
        { "IPv4 Neighbor Address", "bgp.ls.nlri_ipv4_neighbor_address", FT_IPv4,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_nlri_ipv6_interface_address,
        { "IPv6 Interface Address", "bgp.ls.nlri_ipv6_interface_address", FT_IPv6,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_nlri_ipv6_neighbor_address,
        { "IPv6 Neighbor Address", "bgp.ls.nlri_ipv6_neighbor_address", FT_IPv6,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_nlri_multi_topology_id,
        { "Multi Topology ID", "bgp.ls.nlri_multi_topology_id", FT_UINT16,
          BASE_DEC_HEX, NULL, 0x0fff, NULL, HFILL}},
      { &hf_bgp_ls_nlri_ospf_route_type,
        { "OSPF Route Type", "bgp.ls.nlri_ospf_route_type", FT_UINT8,
          BASE_DEC, VALS(link_state_prefix_descriptors_ospf_route_type), 0x0, NULL, HFILL}},
      { &hf_bgp_ls_nlri_ip_reachability_prefix_ip,
       { "Reachability prefix", "bgp.ls.nlri_ip_reachability_prefix_ip", FT_IPv4,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_nlri_ip_reachability_prefix_ip6,
       { "Reachability prefix", "bgp.ls.nlri_ip_reachability_prefix_ip6", FT_IPv6,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_nlri_node_nlri_type,
        { "Link-State NLRI Node NLRI", "bgp.ls.nlri_node", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_nlri_node_protocol_id,
        { "Protocol ID", "bgp.ls.nlri_node.protocol_id", FT_UINT8,
          BASE_DEC, VALS(link_state_nlri_protocol_id_values), 0x0, NULL, HFILL }},
      { &hf_bgp_ls_nlri_node_identifier,
        { "Identifier", "bgp.ls.nlri_node.identifier", FT_UINT64,
          BASE_DEC | BASE_VAL64_STRING, VALS64(link_state_nlri_routing_universe_values), 0x0, NULL, HFILL }},
      { &hf_bgp_ls_ipv4_topology_prefix_nlri_type,
        { "Link-State NLRI IPv4 Topology Prefix", "bgp.ls.ipv4_topology_prefix", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_ipv6_topology_prefix_nlri_type,
        { "Link-State NLRI IPv6 Topology Prefix", "bgp.ls.ipv6_topology_prefix", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
       /* NLRI TLVs */
      { &hf_bgp_ls_tlv_local_node_descriptors,
        { "Local Node Descriptors TLV", "bgp.ls.tlv.local_node_descriptors", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_remote_node_descriptors,
        { "Remote Node Descriptors TLV", "bgp.ls.tlv.remote_node_descriptors", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_autonomous_system,
        { "Autonomous System TLV", "bgp.ls.tlv.autonomous_system", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_autonomous_system_id,
        { "AS ID", "bgp.ls.tlv.autonomous_system.id", FT_UINT32,
          BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_bgp_ls_identifier,
        { "BGP-LS Identifier TLV", "bgp.ls.tlv.bgp_ls_identifier", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_bgp_ls_identifier_id,
        { "BGP-LS ID", "bgp.ls.tlv.bgp_ls_identifier_id", FT_UINT32,
          BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_area_id,
        { "Area ID TLV", "bgp.ls.tlv.area_id", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_area_id_id,
        { "Area ID", "bgp.ls.tlv.area_id.id", FT_UINT32,
          BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_ipv4_router_id_of_local_node,
        { "IPv4 Router-ID of Local Node TLV", "bgp.ls.tlv.ipv4_router_id_of_local_node", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_ls_tlv_ipv4_router_id_value,
        { "IPv4 Router-ID", "bgp.ls.tlv.ipv4_router_id_value", FT_IPv4,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_ipv6_router_id_of_local_node,
        { "IPv6 Router-ID of Local Node TLV", "bgp.ls.tlv.ipv6_router_id_of_local_node", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_ls_tlv_ipv6_router_id_value,
        { "IPv6 Router-ID", "bgp.ls.tlv.ipv6_router_id_of_local_node_value", FT_IPv6,
          BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_ls_tlv_ipv4_router_id_of_remote_node,
        { "IPv4 Router-ID of Remote Node TLV", "bgp.ls.tlv.ipv4_router_id_of_remote_node", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_ls_tlv_ipv6_router_id_of_remote_node,
        { "IPv6 Router-ID of Remote Node TLV", "bgp.ls.tlv.ipv6_router_id_of_remote_node", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_ls_tlv_link_local_remote_identifiers,
        { "Link Local/Remote Identifiers TLV", "bgp.ls.tlv.link_local_remote_identifiers", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_ls_tlv_ipv4_interface_address,
        {  "IPv4 interface address TLV", "bgp.ls.tlv.ipv4_interface_address", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_ls_tlv_ipv4_neighbor_address,
        { "IPv4 neighbor address TLV", "bgp.ls.tlv.ipv4_neighbor_address", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_ipv6_interface_address,
        { "IPv6 interface address TLV", "bgp.ls.tlv.ipv6_interface_address", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_ipv6_neighbor_address,
        { "IPv6 neighbor address TLV", "bgp.ls.tlv.ipv6_neighbor_address", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_node_msd,
        { "Node MSD", "bgp.ls.tlv.node_msd", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_link_msd,
        { "Link MSD", "bgp.ls.tlv.link_msd", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_igp_msd_type,
        { "MSD Type", "bgp.ls.tlv.igp_msd_type", FT_UINT8,
          BASE_DEC, VALS(igp_msd_types), 0x0, NULL, HFILL }},
      { &hf_bgp_ls_tlv_igp_msd_value,
        { "MSD Value", "bgp.ls.tlv.igp_msd_value", FT_UINT8,
          BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_ls_tlv_multi_topology_id,
        { "Multi Topology ID TLV", "bgp.ls.tlv.multi_topology_id", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_ospf_route_type,
        { "OSPF Route Type TLV", "bgp.ls.tlv.ospf_route_type", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_ip_reachability_information,
        { "IP Reachability Information TLV", "bgp.ls.tlv.ip_reachability_information", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_administrative_group_color,
        { "Administrative group (color) TLV", "bgp.ls.tlv.administrative_group_color", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_administrative_group_color_value,
        { "Group Mask", "bgp.ls.tlv.administrative_group_color_value", FT_UINT32,
         BASE_DEC, NULL, 0xffff, NULL, HFILL}},
      { &hf_bgp_ls_tlv_administrative_group,
        { "Group", "bgp.ls.tlv.administrative_group", FT_UINT32,
         BASE_DEC, NULL, 0xffff, NULL, HFILL}},
      { &hf_bgp_ls_tlv_max_link_bandwidth,
        { "Maximum link bandwidth TLV", "bgp.ls.tlv.maximum_link_bandwidth", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_max_reservable_link_bandwidth,
        { "Maximum reservable link bandwidth TLV", "bgp.ls.tlv.maximum_reservable_link_bandwidth", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_unreserved_bandwidth,
        { "Unreserved bandwidth TLV", "bgp.ls.tlv.unreserved_bandwidth", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_bandwidth_value,
        {"Bandwidth", "bgp.ls.bandwidth_value", FT_FLOAT,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_te_default_metric,
        { "TE Default Metric TLV", "bgp.ls.tlv.te_default_metric", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_te_default_metric_value_old,
        { "TE Default Metric (old format)", "bgp.ls.tlv.te_default_metric_value", FT_UINT24,
          BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_ls_tlv_te_default_metric_value,
        { "TE Default Metric", "bgp.ls.tlv.te_default_metric_value", FT_UINT32,
          BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_ls_tlv_link_protection_type,
        { "Link Protection Type TLV", "bgp.ls.tlv.link_protection_type", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_link_protection_type_value,
        { "Protection Capabilities", "bgp.ls.tlv.link_protection_type_value", FT_UINT8,
          BASE_HEX, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_mpls_protocol_mask,
        { "MPLS Protocol Mask TLV", "bgp.ls.tlv.mpls_protocol_mask", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_metric,
        { "Metric TLV", "bgp.ls.tlv.metric", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_metric_value1,
        { "IGP Metric", "bgp.ls.tlv.metric_value", FT_UINT8,
          BASE_HEX_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_metric_value2,
        { "IGP Metric", "bgp.ls.tlv.metric_value", FT_UINT16,
          BASE_HEX_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_metric_value3,
        { "IGP Metric", "bgp.ls.tlv.metric_value", FT_UINT24,
          BASE_HEX_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_shared_risk_link_group,
        { "Shared Risk Link Group TLV", "bgp.ls.tlv.shared_risk_link_group", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_shared_risk_link_group_value,
        { "Shared Risk Link Group Value", "bgp.ls.tlv.shared_risk_link_group_value", FT_UINT32,
          BASE_HEX_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_opaque_link_attribute,
        { "Opaque Link Attribute TLV", "bgp.ls.tlv.opaque_link_attribute", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_opaque_link_attribute_value,
        { "Opaque link attributes", "bgp.ls.tlv.opaque_link_attribute_value", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_link_name_attribute,
        { "Opaque Link Attribute TLV", "bgp.ls.tlv.link_name_attribute", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_link_name_attribute_value,
        {"Link Name", "bgp.ls.tlv.link_name_attribute_value", FT_STRING,
          BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_bgp_ls_tlv_igp_flags,
        { "IGP Flags TLV", "bgp.ls.tlv.igp_flags", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_route_tag,
        { "Route Tag TLV", "bgp.ls.tlv.route_tag", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_route_tag_value,
        { "Route Tag Value", "bgp.ls.tlv.route_tag_value", FT_UINT32,
          BASE_HEX_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_route_extended_tag,
        { "Extended Route Tag TLV", "bgp.ls.tlv.route_extended_tag", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_route_extended_tag_value,
        {"Extended Route Tag", "bgp.ls.tlv.extended_route_tag_value", FT_UINT64,
          BASE_HEX_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_prefix_metric,
        { "Prefix Metric TLV", "bgp.ls.tlv.prefix_metric", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_prefix_metric_value,
        { "Prefix Metric", "bgp.ls.tlv.prefix_metric_value", FT_UINT32,
          BASE_HEX_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_ospf_forwarding_address,
        { "OSPF Forwarding Address TLV", "bgp.ls.tlv.ospf_forwarding_address", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_ospf_forwarding_address_ipv4_address,
        { "OSPF forwarding IPv4 address", "bgp.ls.tlv.ospf_forwarding_address_ipv4", FT_IPv4,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_ospf_forwarding_address_ipv6_address,
        { "OSPF forwarding IPv6 address", "bgp.ls.tlv.ospf_forwarding_address_ipv6", FT_IPv6,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_opaque_prefix_attribute,
        { "Opaque Prefix Attribute TLV", "bgp.ls.tlv.opaque_prefix_attribute", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_opaque_prefix_attribute_value,
        { "Opaque prefix attributes", "bgp.ls.tlv.opaque_prefix_attribute_value", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_extended_administrative_group,
        { "Extended Administrative Group TLV", "bgp.ls.tlv.extended_administrative_group", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_extended_administrative_group_value,
        { "Extended Administrative Group", "bgp.ls.tlv.extended_administrative_group_value", FT_BYTES,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_igp_router,
        { "IGP Router-ID", "bgp.ls.tlv.igp_router", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_igp_router_id,
        { "IGP ID", "bgp.ls.tlv.igp_router_id", FT_BYTES,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_bgp_router_id,
        { "BGP Router-ID TLV", "bgp.ls.tlv.bgp_router_id", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_bgp_router_id_id,
        { "BGP Router-ID", "bgp.ls.tlv.bgp_router_id.id", FT_IPv4,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_node_flags_bits,
        { "Node Flags Bits TLV", "bgp.ls.tlv.node_flags_bits", FT_NONE,
         BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_opaque_node_properties,
        { "Opaque Node Properties TLV", "bgp.ls.tlv.opaque_node_properties", FT_NONE,
         BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_opaque_node_properties_value,
        { "Opaque Node Properties", "bgp.ls.tlv.opaque_node_properties_value", FT_NONE,
         BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_node_name,
        { "Node Name TLV", "bgp.ls.tlv.node_name", FT_NONE,
         BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_node_name_value,
        {"Node name", "bgp.ls.tlv.node_name_value", FT_STRING,
         BASE_NONE, NULL, 0, NULL, HFILL }},
      { &hf_bgp_ls_tlv_is_is_area_identifier,
        { "IS-IS Area Identifier TLV", "bgp.ls.tlv.is_is_area_identifier", FT_NONE,
         BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_is_is_area_identifier_value,
        { "IS-IS Area Identifier", "bgp.ls.tlv.is_is_area_identifier_value", FT_BYTES,
         BASE_NONE, NULL, 0x0, NULL, HFILL}},
      /* Link Protection Types */
      { &hf_bgp_ls_link_protection_type_enhanced,
        { "Enhanced", "bgp.ls.link_protection_type.enhanced", FT_BOOLEAN, 8,
          TFS(&tfs_capable_not_capable), 0x20, NULL, HFILL }},
      { &hf_bgp_ls_link_protection_type_dedicated_1plus1,
        { "Dedicated 1+1", "bgp.ls.link_protection_type.dedicated_1plus1", FT_BOOLEAN, 8,
          TFS(&tfs_capable_not_capable), 0x10, NULL, HFILL }},
      { &hf_bgp_ls_link_protection_type_dedicated_1to1,
        { "Dedicated 1:1", "bgp.ls.link_protection_type.dedicated_1colon1", FT_BOOLEAN, 8,
          TFS(&tfs_capable_not_capable), 0x08, NULL, HFILL }},
      { &hf_bgp_ls_link_protection_type_shared,
        { "Shared", "bgp.ls.link_protection_type.shared", FT_BOOLEAN, 8,
          TFS(&tfs_capable_not_capable), 0x04, NULL, HFILL }},
      { &hf_bgp_ls_link_protection_type_unprotected,
        { "Unprotected", "bgp.ls.link_protection_type.unprotected", FT_BOOLEAN, 8,
          TFS(&tfs_capable_not_capable), 0x02, NULL, HFILL }},
      { &hf_bgp_ls_link_protection_type_extra_traffic,
        { "Extra Traffic", "bgp.ls.link_protection_type.extra_traffic", FT_BOOLEAN, 8,
          TFS(&tfs_capable_not_capable), 0x01, NULL, HFILL }},
      /* MPLS Protocol Mask flags */
      { &hf_bgp_ls_mpls_protocol_mask_flag_l,
        { "Label Distribution Protocol (LDP)", "bgp.ls.protocol_mask_tlv.mpls_protocol.l", FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), 0x80, NULL, HFILL}},
      { &hf_bgp_ls_mpls_protocol_mask_flag_r,
        { "Extension to RSVP for LSP Tunnels (RSVP-TE)", "bgp.ls.protocol_mask_tlv.mpls_protocol.r", FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), 0x40, NULL, HFILL}},
      /* IGP Flags TLV */
      { &hf_bgp_ls_igp_flags_flag_d,
        { "IS-IS Up/Down Bit", "bgp.ls.protocol_mask_tlv.igp_flags_flag_d.d", FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), 0x80, NULL, HFILL}},
      /* Node Flag Bits TLV flags */
      { &hf_bgp_ls_node_flag_bits_overload,
        { "Overload Bit", "bgp.ls.node_flag_bits.overload", FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), 0x80, NULL, HFILL}},
      { &hf_bgp_ls_node_flag_bits_attached,
        { "Attached Bit", "bgp.ls.node_flag_bits.attached", FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), 0x40, NULL, HFILL}},
      { &hf_bgp_ls_node_flag_bits_external,
        { "External Bit", "bgp.ls.node_flag_bits.external", FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), 0x20, NULL, HFILL}},
      { &hf_bgp_ls_node_flag_bits_abr,
        { "ABR Bit", "bgp.ls.node_flag_bits.abr", FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), 0x10, NULL, HFILL}},
      { &hf_bgp_evpn_nlri,
        { "EVPN NLRI", "bgp.evpn.nlri", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_evpn_nlri_rt,
        { "Route Type", "bgp.evpn.nlri.rt", FT_UINT8, BASE_DEC,
          VALS(evpnrtypevals), 0x0, NULL, HFILL }},
      { &hf_bgp_evpn_nlri_len,
        { "Length", "bgp.evpn.nlri.len", FT_UINT8,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_evpn_nlri_rd,
        { "Route Distinguisher", "bgp.evpn.nlri.rd", FT_BYTES,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_evpn_nlri_esi,
        { "ESI", "bgp.evpn.nlri.esi", FT_BYTES,
          SEP_COLON, NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_evpn_nlri_esi_type,
        { "ESI Type", "bgp.evpn.nlri.esi.type", FT_UINT8,
          BASE_DEC, VALS(evpn_nlri_esi_type), 0x0, "EVPN ESI type", HFILL }},
      { &hf_bgp_evpn_nlri_esi_lacp_mac,
        { "CE LACP system MAC", "bgp.evpn.nlri.esi.lacp_mac", FT_ETHER,
          BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_evpn_nlri_esi_portk,
        { "LACP port key", "bgp.evpn.nlri.esi.lacp_portkey", FT_UINT16,
          BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_evpn_nlri_esi_remain,
        { "Remaining bytes", "bgp.evpn.nlri.esi.remaining", FT_BYTES,
          BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_evpn_nlri_esi_reserved,
        { "Reserved value all 0xff", "bgp.evpn.nlri.esi.reserved", FT_BYTES,
         BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_evpn_nlri_esi_value,
        { "ESI Value", "bgp.evpn.nlri.esi.value", FT_BYTES,
          SEP_SPACE, NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_evpn_nlri_esi_value_type0,
        { "ESI 9 bytes value", "bgp.evpn.nlri.esi.type0", FT_BYTES,
          SEP_SPACE, NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_evpn_nlri_esi_rb_mac,
        { "ESI root bridge MAC", "bgp.evpn.nlri.esi.root_bridge", FT_ETHER,
          BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_evpn_nlri_esi_rbprio,
        { "ESI root bridge priority", "bgp.evpn.nlri.esi.rb_prio", FT_UINT16,
          BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_evpn_nlri_esi_sys_mac,
        { "ESI system MAC", "bgp.evpn.nlri.esi.system_mac", FT_ETHER,
          BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_evpn_nlri_esi_mac_discr,
        { "ESI system mac discriminator", "bgp.evpn.nlri.esi.system_mac_discr", FT_BYTES,
          SEP_SPACE, NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_evpn_nlri_esi_router_id,
        { "ESI router ID", "bgp.evpn.nlri.esi.router_id", FT_IPv4,
          BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_evpn_nlri_esi_router_discr,
        { "ESI router discriminator", "bgp.evpn.nlri.esi.router_discr", FT_BYTES,
          SEP_SPACE, NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_evpn_nlri_esi_asn,
        { "ESI ASN", "bgp.evpn.nlri.esi.asn", FT_UINT32,
          BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_evpn_nlri_esi_asn_discr,
        { "ESI ASN discriminator", "bgp.evpn.nlri.esi.asn_discr", FT_BYTES,
          SEP_SPACE, NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_evpn_nlri_etag,
       { "Ethernet Tag ID", "bgp.evpn.nlri.etag", FT_UINT32,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_evpn_nlri_mpls_ls1,
        { "MPLS Label 1", "bgp.evpn.nlri.mpls_ls1", FT_UINT24,
          BASE_DEC, NULL, BGP_MPLS_LABEL, NULL, HFILL}},
      { &hf_bgp_evpn_nlri_mpls_ls2,
        { "MPLS Label 2", "bgp.evpn.nlri.mpls_ls2", FT_UINT24,
          BASE_DEC, NULL, BGP_MPLS_LABEL, NULL, HFILL}},
      { &hf_bgp_evpn_nlri_vni,
        { "VNI", "bgp.evpn.nlri.vni", FT_UINT24,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_evpn_nlri_maclen,
       { "MAC Address Length", "bgp.evpn.nlri.maclen", FT_UINT8,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_evpn_nlri_mac_addr,
        { "MAC Address", "bgp.evpn.nlri.mac_addr", FT_ETHER,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_evpn_nlri_iplen,
        { "IP Address Length", "bgp.evpn.nlri.iplen", FT_UINT8,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_evpn_nlri_prefix_len,
        { "IP prefix length", "bgp.evpn.nlri.prefix_len", FT_UINT8,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_evpn_nlri_ip_addr,
        { "IPv4 address", "bgp.evpn.nlri.ip.addr", FT_IPv4,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_evpn_nlri_ipv6_addr,
        { "IPv6 address", "bgp.evpn.nlri.ipv6.addr", FT_IPv6,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_evpn_nlri_ipv4_gtw,
        { "IPv4 Gateway address", "bgp.evpn.nlri.ipv4.gtw_addr", FT_IPv4,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_evpn_nlri_ipv6_gtw,
        { "IPv6 Gateway address", "bgp.evpn.nlri.ipv6.gtw_addr", FT_IPv6,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
     /* segment routing extentions to link state */
     /* Node Attributes TLVs */
      { &hf_bgp_ls_sr_tlv_capabilities,
        { "SR Capabilities", "bgp.ls.sr.tlv.capabilities", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_capabilities_flags,
        { "Flags", "bgp.ls.sr.tlv.capabilities.flags", FT_UINT8,
          BASE_HEX, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_capabilities_flags_i,
        { "MPLS IPv4 flag (I)", "bgp.ls.sr.tlv.capabilities.flags.i", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), BGP_LS_SR_CAPABILITY_FLAG_I, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_capabilities_flags_v,
        { "MPLS IPv6 flag (V)", "bgp.ls.sr.tlv.capabilities.flags.v", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), BGP_LS_SR_CAPABILITY_FLAG_V, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_capabilities_flags_h,
        { "SR-IPv6 flag (H)", "bgp.ls.sr.tlv.capabilities.flags.h", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), BGP_LS_SR_CAPABILITY_FLAG_H, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_capabilities_flags_reserved,
        { "Reserved", "bgp.ls.sr.tlv.capabilities.flags.reserved", FT_UINT8,
          BASE_HEX, NULL, 0x1F, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_capabilities_range_size,
        { "Range Size", "bgp.ls.sr.tlv.capabilities.range_size", FT_UINT24,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_capabilities_sid_label,
        { "From Label", "bgp.ls.sr.tlv.capabilities.sid.label", FT_UINT24,
          BASE_DEC, NULL, 0x0FFFFF, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_capabilities_sid_index,
        { "From Index", "bgp.ls.sr.tlv.capabilities.sid.index", FT_UINT32,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_algorithm,
        { "SR Algorithm", "bgp.ls.sr.tlv.algorithm", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_algorithm_value,
        { "SR Algorithm", "bgp.ls.sr.tlv.algorithm.value", FT_UINT8,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_local_block,
        { "SR Local Block", "bgp.ls.sr.tlv.local_block", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_local_block_flags,
        { "Flags", "bgp.ls.sr.tlv.local_block.flags", FT_UINT8,
          BASE_HEX, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_local_block_range_size,
        { "Range Size", "bgp.ls.sr.tlv.local_block.range_size", FT_UINT24,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_local_block_sid_label,
        { "From Label", "bgp.ls.sr.tlv.local_block.sid.label", FT_UINT24,
          BASE_DEC, NULL, 0x0FFFFF, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_local_block_sid_index,
        { "From Index", "bgp.ls.sr.tlv.local_block.sid.index", FT_UINT32,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_flex_algo_def,
        { "Flexible Algorithm Definition TLV", "bgp.ls.sr.tlv.flex_algo", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_flex_algo_algorithm,
        { "Flex-Algorithm", "bgp.ls.sr.tlv.flex_algo.flex_algorithm", FT_UINT8,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_flex_algo_metric_type,
        { "Metric-Type", "bgp.ls.sr.tlv.flex_algo.metric_type", FT_UINT8,
          BASE_DEC, VALS(flex_algo_metric_types), 0x0, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_flex_algo_calc_type,
        { "Calculation-Type", "bgp.ls.sr.tlv.flex_algo.calculation_type", FT_UINT8,
          BASE_DEC, VALS(igp_algo_types), 0x0, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_flex_algo_priority,
        { "Priority", "bgp.ls.sr.tlv.flex_algo.priority", FT_UINT8,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_flex_algo_exc_any_affinity,
        { "Flex Algo Exclude Any Affinity TLV", "bgp.ls.sr.tlv.flex_algo.exclude_any_affinity", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_flex_algo_inc_any_affinity,
        { "Flex Algo Include Any Affinity TLV", "bgp.ls.sr.tlv.flex_algo.include_any_affinity", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_flex_algo_inc_all_affinity,
        { "Flex Algo Include All Affinity TLV", "bgp.ls.sr.tlv.flex_algo.include_all_affinity", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
     /* Prefix Attribute TLVs */
      { &hf_bgp_ls_sr_tlv_prefix_sid,
        { "Prefix SID TLV", "bgp.ls.sr.tlv.prefix.sid", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_prefix_sid_flags,
        { "Flags", "bgp.ls.sr.tlv.prefix.sid.flags", FT_UINT8,
          BASE_HEX, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_prefix_sid_flags_r,
        { "Re-advertisement (R)", "bgp.ls.sr.tlv.prefix.sid.flags.r", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), BGP_LS_SR_PREFIX_SID_FLAG_R, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_prefix_sid_flags_n,
        { "Node-SID (N)", "bgp.ls.sr.tlv.prefix.sid.flags.n", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), BGP_LS_SR_PREFIX_SID_FLAG_N, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_prefix_sid_flags_np,
        { "No-PHP (NP)", "bgp.ls.sr.tlv.prefix.sid.flags.np", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), BGP_LS_SR_PREFIX_SID_FLAG_NP, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_prefix_sid_flags_p,
        { "No-PHP (P)", "bgp.ls.sr.tlv.prefix.sid.flags.p", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), BGP_LS_SR_PREFIX_SID_FLAG_P, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_prefix_sid_flags_m,
        { "Mapping Server Flag (M)", "bgp.ls.sr.tlv.prefix.sid.flags.m", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), BGP_LS_SR_PREFIX_SID_FLAG_M, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_prefix_sid_flags_e,
        { "Explicit-Null (E)", "bgp.ls.sr.tlv.prefix.sid.flags.e", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), BGP_LS_SR_PREFIX_SID_FLAG_E, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_prefix_sid_flags_v,
        { "Value (V)", "bgp.ls.sr.tlv.prefix.sid.flags.v", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), BGP_LS_SR_PREFIX_SID_FLAG_V, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_prefix_sid_flags_l,
        { "Local (L)", "bgp.ls.sr.tlv.prefix.sid.flags.l", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), BGP_LS_SR_PREFIX_SID_FLAG_L, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_prefix_sid_algo,
        { "Algorithm", "bgp.ls.sr.tlv.prefix.sid.algo", FT_UINT8,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_prefix_sid_label,
        { "SID/Label", "bgp.ls.sr.tlv.prefix.sid.label", FT_UINT24,
          BASE_DEC, NULL, 0x0FFFFF, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_prefix_sid_index,
        { "SID/Index", "bgp.ls.sr.tlv.prefix.sid.index", FT_UINT32,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_prefix_attr_flags,
        { "Prefix Attribute Flags TLV", "bgp.ls.sr.tlv.prefix.attribute_flags", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_prefix_attr_flags_flags,
        { "Flags", "bgp.ls.sr.tlv.prefix.attribute_flags.flags", FT_UINT8,
          BASE_HEX, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_prefix_attr_flags_flags_unknown,
        { "Flags", "bgp.ls.sr.tlv_prefix.attribute_flags.flags.unknown", FT_BYTES,
          SEP_SPACE, NULL, 0x0,NULL, HFILL }},
      { &hf_bgp_ls_sr_tlv_prefix_attr_flags_flags_ao,
        { "Attach (A)", "bgp.ls.sr.tlv.prefix.attribute_flags.flags.a", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), BGP_LS_SR_PREFIX_ATTR_FLAGS_FLAG_AO, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_prefix_attr_flags_flags_no,
        { "Node (N)", "bgp.ls.sr.tlv.prefix.attribute_flags.flags.n", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), BGP_LS_SR_PREFIX_ATTR_FLAGS_FLAG_NO, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_prefix_attr_flags_flags_eo,
        { "ELC (E)", "bgp.ls.sr.tlv.prefix.attribute_flags.flags.e", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), BGP_LS_SR_PREFIX_ATTR_FLAGS_FLAG_EO, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_prefix_attr_flags_flags_xi,
        { "External Prefix (X)", "bgp.ls.sr.tlv.prefix.attribute_flags.flags.x", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), BGP_LS_SR_PREFIX_ATTR_FLAGS_FLAG_XI, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_prefix_attr_flags_flags_ri,
        { "Re-advertisement (X)", "bgp.ls.sr.tlv.prefix.attribute_flags.flags.r", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), BGP_LS_SR_PREFIX_ATTR_FLAGS_FLAG_RI, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_prefix_attr_flags_flags_ni,
        { "Node (N)", "bgp.ls.sr.tlv.prefix.attribute_flags.flags.n", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), BGP_LS_SR_PREFIX_ATTR_FLAGS_FLAG_NI, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_prefix_attr_flags_flags_ei,
        { "ELC (E)", "bgp.ls.sr.tlv.prefix.attribute_flags.flags.e", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), BGP_LS_SR_PREFIX_ATTR_FLAGS_FLAG_EI, NULL, HFILL}},
     /* Adjacency Attribute TLVs */
      { &hf_bgp_ls_sr_tlv_adjacency_sid,
        { "Adjacency SID TLV", "bgp.ls.sr.tlv.adjacency.sid", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_adjacency_sid_flags,
        { "Flags", "bgp.ls.sr.tlv.adjacency.sid.flags", FT_UINT8,
          BASE_HEX, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_adjacency_sid_flags_fi,
        { "Address-Family flag (F)", "bgp.ls.sr.tlv.adjacency.sid.flags.f", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), BGP_LS_SR_ADJACENCY_SID_FLAG_FI, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_adjacency_sid_flags_bo,
        { "Backup Flag (B)", "bgp.ls.sr.tlv.adjacency.sid.flags.b", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), BGP_LS_SR_ADJACENCY_SID_FLAG_BO, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_adjacency_sid_flags_bi,
        { "Backup Flag (B)", "bgp.ls.sr.tlv.adjacency.sid.flags.b", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), BGP_LS_SR_ADJACENCY_SID_FLAG_BI, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_adjacency_sid_flags_vo,
        { "Value Flag (V)", "bgp.ls.sr.tlv.adjacency.sid.flags.v", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), BGP_LS_SR_ADJACENCY_SID_FLAG_VO, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_adjacency_sid_flags_vi,
        { "Value Flag (V)", "bgp.ls.sr.tlv.adjacency.sid.flags.v", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), BGP_LS_SR_ADJACENCY_SID_FLAG_VI, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_adjacency_sid_flags_lo,
        { "Local Flag (L)", "bgp.ls.sr.tlv.adjacency.sid.flags.l", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), BGP_LS_SR_ADJACENCY_SID_FLAG_LO, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_adjacency_sid_flags_li,
        { "Local Flag (L)", "bgp.ls.sr.tlv.adjacency.sid.flags.l", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), BGP_LS_SR_ADJACENCY_SID_FLAG_LI, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_adjacency_sid_flags_so,
        { "Set Flag (S)", "bgp.ls.sr.tlv.adjacency.sid.flags.s", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), BGP_LS_SR_ADJACENCY_SID_FLAG_SO, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_adjacency_sid_flags_si,
        { "Set Flag (S)", "bgp.ls.sr.tlv.adjacency.sid.flags.s", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), BGP_LS_SR_ADJACENCY_SID_FLAG_SI, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_adjacency_sid_weight,
        { "Weight", "bgp.ls.sr.tlv.adjacency.sid.weight", FT_UINT8,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_adjacency_sid_label,
        { "SID/Label", "bgp.ls.sr.tlv.adjacency.sid.label", FT_UINT24,
          BASE_DEC, NULL, 0x0FFFFF, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_adjacency_sid_index,
        { "SID/Index", "bgp.ls.sr.tlv.adjacency.sid.index", FT_UINT32,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_peer_node_sid,
        { "PeerNode SID TLV", "bgp.ls.sr.tlv.peer_node.sid", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_peer_adj_sid,
        { "PeerAdj SID TLV", "bgp.ls.sr.tlv.peer_adj.sid", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_peer_set_sid,
        { "PeerSet SID TLV", "bgp.ls.sr.tlv.peer_set.sid", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_peer_sid_flags,
        { "Flags", "bgp.ls.sr.tlv.peer.sid.flags", FT_UINT8,
          BASE_HEX, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_peer_sid_flags_v,
        { "Value flag (V)", "bgp.ls.sr.tlv.peer.sid.flags.v", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), BGP_LS_SR_PEER_SID_FLAG_V, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_peer_sid_flags_l,
        { "Local flag (L)", "bgp.ls.sr.tlv.peer.sid.flags.l", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), BGP_LS_SR_PEER_SID_FLAG_L, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_peer_sid_flags_b,
        { "Backup flag (B)", "bgp.ls.sr.tlv.peer.sid.flags.b", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), BGP_LS_SR_PEER_SID_FLAG_B, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_peer_sid_flags_p,
        { "Persistent flag (P)", "bgp.ls.sr.tlv.peer.sid.flags.p", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), BGP_LS_SR_PEER_SID_FLAG_P, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_peer_sid_weight,
        { "Weight", "bgp.ls.sr.tlv.peer.sid.weight", FT_UINT8,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_peer_sid_label,
        { "SID/Label", "bgp.ls.sr.tlv.peer.sid.label", FT_UINT24,
          BASE_DEC, NULL, 0x0FFFFF, NULL, HFILL}},
      { &hf_bgp_ls_sr_tlv_peer_sid_index,
        { "SID/Index", "bgp.ls.sr.tlv.peer.sid.index", FT_UINT32,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_igp_te_metric_flags,
        { "TE Metric Flags", "bgp.ls.igp_te_metric.flags", FT_UINT8,
          BASE_HEX, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_igp_te_metric_flags_a,
        { "Anomalous (A) bit", "bgp.ls.igp_te_metric.flags.a", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), BGP_LS_IGP_TE_METRIC_FLAG_A, NULL, HFILL}},
      { &hf_bgp_ls_igp_te_metric_flags_reserved,
        { "Reserved", "bgp.ls.igp_te_metric.flags.reserved", FT_UINT8,
          BASE_HEX, NULL, BGP_LS_IGP_TE_METRIC_FLAG_RESERVED, NULL, HFILL}},
      { &hf_bgp_ls_igp_te_metric_delay,
        { "Unidirectional Link Delay TLV", "bgp.ls.igp_te_metric.delay", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_igp_te_metric_delay_value,
        { "Delay", "bgp.ls.igp_te_metric.delay_value", FT_UINT24,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_igp_te_metric_delay_min_max,
        { "Min/Max Unidirectional Link Delay TLV", "bgp.ls.igp_te_metric.delay_min_max", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_igp_te_metric_delay_min,
        { "Min Delay", "bgp.ls.igp_te_metric.delay_min", FT_UINT24,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_igp_te_metric_delay_max,
        { "Max Delay", "bgp.ls.igp_te_metric.delay_max", FT_UINT24,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_igp_te_metric_delay_variation,
        { "Unidirectional Delay Variation TLV", "bgp.ls.igp_te_metric.delay_variation", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_igp_te_metric_delay_variation_value,
        { "Delay Variation", "bgp.ls.igp_te_metric.delay_variation_value", FT_UINT24,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_igp_te_metric_link_loss,
        { "Unidirectional Link Loss TLV", "bgp.ls.igp_te_metric.link_loss", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_igp_te_metric_link_loss_value,
        { "Link Loss", "bgp.ls.igp_te_metric.link_loss_value", FT_UINT24,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_igp_te_metric_bandwidth_residual,
        { "Unidirectional Residual Bandwidth TLV", "bgp.ls.igp_te_metric.residual_bandwidth", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_igp_te_metric_bandwidth_residual_value,
        { "Residual Bandwidth", "bgp.ls.igp_te_metric.residual_bandwidth_value", FT_UINT32,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_igp_te_metric_bandwidth_available,
        { "Unidirectional Available Bandwidth TLV", "bgp.ls.igp_te_metric.available_bandwidth", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_igp_te_metric_bandwidth_available_value,
        { "Residual Bandwidth", "bgp.ls.igp_te_metric.available_bandwidth_value", FT_UINT32,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_igp_te_metric_bandwidth_utilized,
        { "Unidirectional Utilized Bandwidth TLV", "bgp.ls.igp_te_metric.utilized_bandwidth", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_igp_te_metric_bandwidth_utilized_value,
        { "Utilized Bandwidth", "bgp.ls.igp_te_metric.utilized_bandwidth_value", FT_UINT32,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_igp_te_metric_reserved,
        { "Reserved", "bgp.ls.igp_te_metric.reserved", FT_UINT8,
          BASE_HEX, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_app_spec_link_attrs,
        { "Application-Specific Link Attributes TLV", "bgp.ls.tlv.application_specific_link_attributes", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_app_spec_link_attrs_sabm_len,
        { "SABM Length", "bgp.ls.tlv.application_specific_link_attributes.sabm_length", FT_UINT8,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_app_spec_link_attrs_udabm_len,
        { "UDABM Length", "bgp.ls.tlv.application_specific_link_attributes.udabm_length", FT_UINT8,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_app_spec_link_attrs_reserved,
        { "Reserved", "bgp.ls.tlv.application_specific_link_attributes.reserved", FT_UINT16,
          BASE_HEX, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_app_spec_link_attrs_sabm,
        { "Standard Application Identifier Bit Mask", "bgp.ls.tlv.application_specific_link_attributes.sabm", FT_UINT32,
          BASE_HEX, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_app_spec_link_attrs_sabm_r,
        { "RSVP-TE (R)", "bgp.ls.tlv.application_specific_link_attributes.sabm.r", FT_BOOLEAN,
          32, TFS(&tfs_set_notset), BGP_LS_APP_SPEC_LINK_ATTRS_SABM_R, NULL, HFILL}},
      { &hf_bgp_ls_tlv_app_spec_link_attrs_sabm_s,
        { "Segment Routing Policy (S)", "bgp.ls.tlv.application_specific_link_attributes.sabm.s", FT_BOOLEAN,
          32, TFS(&tfs_set_notset), BGP_LS_APP_SPEC_LINK_ATTRS_SABM_S, NULL, HFILL}},
      { &hf_bgp_ls_tlv_app_spec_link_attrs_sabm_f,
        { "Loop Free Alternate (F)", "bgp.ls.tlv.application_specific_link_attributes.sabm.f", FT_BOOLEAN,
          32, TFS(&tfs_set_notset), BGP_LS_APP_SPEC_LINK_ATTRS_SABM_F, NULL, HFILL}},
      { &hf_bgp_ls_tlv_app_spec_link_attrs_sabm_x,
        { "Flexible Algorithm (X)", "bgp.ls.tlv.application_specific_link_attributes.sabm.x", FT_BOOLEAN,
          32, TFS(&tfs_set_notset), BGP_LS_APP_SPEC_LINK_ATTRS_SABM_X, NULL, HFILL}},
      { &hf_bgp_ls_tlv_app_spec_link_attrs_udabm,
        { "User-Defined Application Identifier Bit Mask", "bgp.ls.tlv.application_specific_link_attributes.udabm", FT_BYTES,
          SEP_SPACE, NULL, 0x0,NULL, HFILL }},

      { &hf_bgp_evpn_nlri_igmp_mc_or_length,
       { "Originator Router Length", "bgp.evpn.nlri.or_length", FT_UINT8,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_evpn_nlri_igmp_mc_or_addr_ipv4,
       { "Originator Router Address IPv4", "bgp.evpn.nlri.or_addr_ipv4", FT_IPv4,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_evpn_nlri_igmp_mc_or_addr_ipv6,
       { "Originator Router Address IPv6", "bgp.evpn.nlri.or_addr_ipv6", FT_IPv6,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_evpn_nlri_igmp_mc_flags,
       { "Flags", "bgp.evpn.nlri.igmp_mc_flags", FT_UINT8,
          BASE_HEX, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_evpn_nlri_igmp_mc_flags_v1,
        { "IGMP Version 1", "bgp.evpn.nlri.igmp_mc_flags.v1", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), EVPN_IGMP_MC_FLAG_V1, NULL, HFILL}},
      { &hf_bgp_evpn_nlri_igmp_mc_flags_v2,
        { "IGMP Version 2", "bgp.evpn.nlri.igmp_mc_flags.v2", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), EVPN_IGMP_MC_FLAG_V2, NULL, HFILL}},
      { &hf_bgp_evpn_nlri_igmp_mc_flags_v3,
        { "IGMP Version 3", "bgp.evpn.nlri.igmp_mc_flags.v3", FT_BOOLEAN,
          8, TFS(&tfs_set_notset), EVPN_IGMP_MC_FLAG_V3, NULL, HFILL}},
      { &hf_bgp_evpn_nlri_igmp_mc_flags_ie,
        { "Group Type (IE Flag)", "bgp.evpn.nlri.igmp_mc_flags.ie", FT_BOOLEAN,
          8, TFS(&tfs_exclude_include), EVPN_IGMP_MC_FLAG_IE, "Group Type (Include/Exclude Flag)", HFILL}},
      { &hf_bgp_evpn_nlri_igmp_mc_flags_reserved,
        { "Reserved", "bgp.evpn.nlri.igmp_mc_flags.reserved", FT_UINT8,
          BASE_HEX, NULL, EVPN_IGMP_MC_FLAG_RESERVED, NULL, HFILL}}
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
      &ett_bgp_as_path_segment,
      &ett_bgp_as_path_segment_asn,
      &ett_bgp_communities,
      &ett_bgp_community,
      &ett_bgp_cluster_list,
      &ett_bgp_options,
      &ett_bgp_option,
      &ett_bgp_cap,
      &ett_bgp_extended_communities,
      &ett_bgp_extended_community,
      &ett_bgp_ext_com_type,
      &ett_bgp_extended_com_fspec_redir,
      &ett_bgp_ext_com_flags,
      &ett_bgp_ext_com_l2_flags,
      &ett_bgp_ext_com_etree_flags,
      &ett_bgp_ext_com_evpn_mmac_flags,
      &ett_bgp_ext_com_evpn_l2attr_flags,
      &ett_bgp_ext_com_evpn_etree_flags,
      &ett_bgp_ext_com_cost_cid,
      &ett_bgp_ext_com_ospf_rt_opt,
      &ett_bgp_ext_com_eigrp_flags,
      &ett_bgp_ssa,
      &ett_bgp_ssa_subtree,
      &ett_bgp_orf,
      &ett_bgp_orf_entry,
      &ett_bgp_mcast_vpn_nlri,
      &ett_bgp_flow_spec_nlri,
      &ett_bgp_flow_spec_nlri_filter,
      &ett_bgp_flow_spec_nlri_op_flags,
      &ett_bgp_flow_spec_nlri_tcp,
      &ett_bgp_flow_spec_nlri_ff,
      &ett_bgp_tunnel_tlv,
      &ett_bgp_tunnel_tlv_subtree,
      &ett_bgp_tunnel_subtlv,
      &ett_bgp_tunnel_subtlv_subtree,
      &ett_bgp_link_state,
      &ett_bgp_evpn_nlri,
      &ett_bgp_evpn_nlri_esi,
      &ett_bgp_evpn_nlri_mc,
      &ett_bgp_mpls_labels,
      &ett_bgp_pmsi_tunnel_id,
      &ett_bgp_aigp_attr,
      &ett_bgp_large_communities,
      &ett_bgp_dpath,
      &ett_bgp_prefix_sid_label_index,
      &ett_bgp_prefix_sid_ipv6,
      &ett_bgp_prefix_sid_originator_srgb,
      &ett_bgp_prefix_sid_originator_srgb_block,
      &ett_bgp_prefix_sid_originator_srgb_blocks,
      &ett_bgp_bgpsec_secure_path,
      &ett_bgp_bgpsec_secure_path_segment,
      &ett_bgp_bgpsec_signature_block,
      &ett_bgp_bgpsec_signature_segment,
      &ett_bgp_vxlan,
      &ett_bgp_binding_sid,
      &ett_bgp_segment_list,
      &ett_bgp_prefix_sid_unknown,
      &ett_bgp_prefix_sid_srv6_l3vpn,
      &ett_bgp_prefix_sid_srv6_l3vpn_sub_tlvs,
      &ett_bgp_prefix_sid_srv6_l3vpn_sid_information,
      &ett_bgp_prefix_sid_srv6_l3vpn_sub_sub_tlvs,
      &ett_bgp_prefix_sid_srv6_l3vpn_sid_structure,
      &ett_bgp_prefix_sid_srv6_l3vpn_sid_unknown,
      &ett_bgp_prefix_sid_srv6_l3vpn_unknown,
      &ett_bgp_prefix_sid_srv6_l2vpn,
      &ett_bgp_prefix_sid_srv6_l2vpn_sub_tlvs,
      &ett_bgp_prefix_sid_srv6_l2vpn_sid_information,
      &ett_bgp_prefix_sid_srv6_l2vpn_sub_sub_tlvs,
      &ett_bgp_prefix_sid_srv6_l2vpn_sid_structure,
      &ett_bgp_prefix_sid_srv6_l2vpn_sid_unknown,
      &ett_bgp_prefix_sid_srv6_l2vpn_unknown,
    };
    static ei_register_info ei[] = {
        { &ei_bgp_marker_invalid, { "bgp.marker_invalid", PI_MALFORMED, PI_ERROR, "Marker is not all ones", EXPFILL }},
        { &ei_bgp_cap_len_bad, { "bgp.cap.length.bad", PI_MALFORMED, PI_ERROR, "Capability length is wrong", EXPFILL }},
        { &ei_bgp_cap_gr_helper_mode_only, { "bgp.cap.gr.helper_mode_only", PI_REQUEST_CODE, PI_CHAT, "Graceful Restart Capability supported in Helper mode only", EXPFILL }},
        { &ei_bgp_notify_minor_unknown, { "bgp.notify.minor_error.unknown", PI_UNDECODED, PI_NOTE, "Unknown notification error", EXPFILL }},
        { &ei_bgp_route_refresh_orf_type_unknown, { "bgp.route_refresh.orf.type.unknown", PI_MALFORMED, PI_ERROR, "ORFEntry-Unknown", EXPFILL }},
        { &ei_bgp_length_invalid, { "bgp.length.invalid", PI_MALFORMED, PI_ERROR, "Length is invalid", EXPFILL }},
        { &ei_bgp_prefix_length_invalid, { "bgp.prefix_length.invalid", PI_MALFORMED, PI_ERROR, "Prefix length is invalid", EXPFILL }},
        { &ei_bgp_afi_type_not_supported, { "bgp.afi_type_not_supported", PI_PROTOCOL, PI_ERROR, "AFI Type not supported", EXPFILL }},
        { &ei_bgp_unknown_afi, { "bgp.unknown_afi", PI_PROTOCOL, PI_ERROR, "Unknown Address Family", EXPFILL }},
        { &ei_bgp_unknown_safi, { "bgp.unknown_safi", PI_PROTOCOL, PI_ERROR, "Unknown SAFI", EXPFILL }},
        { &ei_bgp_unknown_label_vpn, { "bgp.unknown_label", PI_PROTOCOL, PI_ERROR, "Unknown Label VPN", EXPFILL }},
        { &ei_bgp_ls_error, { "bgp.ls.error", PI_PROTOCOL, PI_ERROR, "Link State error", EXPFILL }},
        { &ei_bgp_ls_warn, { "bgp.ls.warn", PI_PROTOCOL, PI_WARN, "Link State warning", EXPFILL }},
        { &ei_bgp_ext_com_len_bad, { "bgp.ext_com.length.bad", PI_PROTOCOL, PI_ERROR, "Extended community length is wrong", EXPFILL }},
        { &ei_bgp_evpn_nlri_rt_type_err, { "bgp.evpn.type", PI_MALFORMED, PI_ERROR, "EVPN Route Type is invalid", EXPFILL }},
        { &ei_bgp_evpn_nlri_rt_len_err, { "bgp.evpn.len", PI_MALFORMED, PI_ERROR, "EVPN Length is invalid", EXPFILL }},
        { &ei_bgp_evpn_nlri_esi_type_err, { "bgp.evpn.esi_type", PI_MALFORMED, PI_ERROR, "EVPN ESI Type is invalid", EXPFILL }},
        { &ei_bgp_evpn_nlri_rt4_no_ip, { "bgp.evpn.no_ip", PI_PROTOCOL, PI_NOTE, "IP Address: NOT INCLUDED", EXPFILL }},
        { &ei_bgp_attr_pmsi_tunnel_type, { "bgp.attr.pmsi.tunnel_type", PI_PROTOCOL, PI_ERROR, "Unknown Tunnel type", EXPFILL }},
        { &ei_bgp_attr_pmsi_opaque_type, { "bgp.attr.pmsi.opaque_type", PI_PROTOCOL, PI_ERROR, "Invalid pmsi opaque type", EXPFILL }},
        { &ei_bgp_attr_aigp_type, { "bgp.attr.aigp.type", PI_MALFORMED, PI_NOTE, "Unknown AIGP attribute type", EXPFILL}},
        { &ei_bgp_prefix_length_err, { "bgp.prefix.length", PI_MALFORMED, PI_ERROR, "Invalid IPv6 prefix length", EXPFILL}},
        { &ei_bgp_attr_as_path_as_len_err, { "bgp.attr.as_path.as_len", PI_UNDECODED, PI_ERROR, "unable to determine 4 or 2 bytes ASN", EXPFILL}},
        { &ei_bgp_next_hop_ipv6_scope, { "bgp.next_hop.ipv6.scope", PI_PROTOCOL, PI_WARN, "Invalid IPv6 address scope", EXPFILL}},
        { &ei_bgp_next_hop_rd_nonzero, { "bgp.next_hop.rd.nonzero", PI_PROTOCOL, PI_WARN, "Route Distinguisher in Next Hop Network Address nonzero", EXPFILL}},
    };

    module_t *bgp_module;
    expert_module_t* expert_bgp;

    static const enum_val_t asn_len[] = {
        {"auto-detect", "Auto-detect", 0},
        {"2", "2 octet", 2},
        {"4", "4 octet", 4},
        {NULL, NULL, -1}
    };

    proto_bgp = proto_register_protocol("Border Gateway Protocol",
                                        "BGP", "bgp");
    proto_register_field_array(proto_bgp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_bgp = expert_register_protocol(proto_bgp);
    expert_register_field_array(expert_bgp, ei, array_length(ei));

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

    bgp_handle = register_dissector("bgp", dissect_bgp, proto_bgp);
}

void
proto_reg_handoff_bgp(void)
{
    dissector_add_uint_with_preference("tcp.port", BGP_TCP_PORT, bgp_handle);
}
/*
* Editor modelines - https://www.wireshark.org/tools/modelines.html
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
