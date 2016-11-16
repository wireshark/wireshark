/* packet-bgp.c
 * Routines for BGP packet dissection.
 * Copyright 1999, Jun-ichiro itojun Hagino <itojun@itojun.org>
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
 * RFC5575 Dissemination of flow specification rules
 * RFC5640 Load-Balancing for Mesh Softwires
 * RFC6368 Internal BGP as the Provider/Customer Edge Protocol for
           BGP/MPLS IP Virtual Private Networks (VPNs)
 * RFC6608 Subcodes for BGP Finite State Machine Error
 * RFC6793 BGP Support for Four-Octet Autonomous System (AS) Number Space
 * RFC5512 The BGP Encapsulation Subsequent Address Family Identifier (SAFI)
 * draft-ietf-idr-dynamic-cap
 * draft-ietf-idr-bgp-enhanced-route-refresh-02
 * draft-ietf-idr-bgp-ext-communities-05
 * draft-knoll-idr-qos-attribute-03
 * draft-nalawade-kapoor-tunnel-safi-05
 * draft-ietf-idr-add-paths-04 Additional-Path for BGP-4
 * draft-ietf-l2vpn-evpn-05 BGP MPLS Based Ethernet VPN
 * draft-ietf-idr-aigp-18 for BGP
 * draft-gredler-idr-bgp-ls-segment-routing-ext-01
 * http://www.iana.org/assignments/bgp-parameters/ (last updated 2012-04-26)

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
#include <wsutil/str_util.h>
#include "packet-ip.h"
#include "packet-ldp.h"
#include "packet-bgp.h"

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

/* AS_PATH segment types */
#define AS_SET             1   /* RFC1771 */
#define AS_SEQUENCE        2   /* RFC1771 */
#define AS_CONFED_SET      4   /* RFC1965 has the wrong values, corrected in  */
#define AS_CONFED_SEQUENCE 3   /* draft-ietf-idr-bgp-confed-rfc1965bis-01.txt */

/* OPEN message Optional Parameter types  */
#define BGP_OPTION_AUTHENTICATION    1   /* RFC1771 */
#define BGP_OPTION_CAPABILITY        2   /* RFC2842 */

/* https://www.iana.org/assignments/capability-codes/ (last updated 2015-09-30) */
/* BGP capability code */
#define BGP_CAPABILITY_RESERVED                     0   /* RFC2434 */
#define BGP_CAPABILITY_MULTIPROTOCOL                1   /* RFC2858 */
#define BGP_CAPABILITY_ROUTE_REFRESH                2   /* RFC2918 */
#define BGP_CAPABILITY_COOPERATIVE_ROUTE_FILTERING  3   /* RFC5291 */
#define BGP_CAPABILITY_MULTIPLE_ROUTE_DEST          4   /* RFC3107 */
#define BGP_CAPABILITY_EXTENDED_NEXT_HOP            5   /* RFC5549 */
#define BGP_CAPABILITY_EXTENDED_MESSAGE             6   /* draft-ietf-idr-bgp-extended-messages */
#define BGP_CAPABILITY_GRACEFUL_RESTART             64  /* RFC4724 */
#define BGP_CAPABILITY_4_OCTET_AS_NUMBER            65  /* RFC6793 */
#define BGP_CAPABILITY_DYNAMIC_CAPABILITY           67  /* draft-ietf-idr-dynamic-cap */
#define BGP_CAPABILITY_MULTISESSION                 68  /* draft-ietf-idr-bgp-multisession */
#define BGP_CAPABILITY_ADDITIONAL_PATHS             69  /* draft-ietf-idr-add-paths */
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

/* well-known communities, from RFC1997 */
#define BGP_COMM_NO_EXPORT           0xFFFFFF01
#define BGP_COMM_NO_ADVERTISE        0xFFFFFF02
#define BGP_COMM_NO_EXPORT_SUBCONFED 0xFFFFFF03
#define FOURHEX0                     0x00000000
#define FOURHEXF                     0xFFFF0000

/* attribute types */
#define BGPTYPE_ORIGIN               1 /* RFC1771           */
#define BGPTYPE_AS_PATH              2 /* RFC1771           */
#define BGPTYPE_NEXT_HOP             3 /* RFC1771           */
#define BGPTYPE_MULTI_EXIT_DISC      4 /* RFC1771           */
#define BGPTYPE_LOCAL_PREF           5 /* RFC1771           */
#define BGPTYPE_ATOMIC_AGGREGATE     6 /* RFC1771           */
#define BGPTYPE_AGGREGATOR           7 /* RFC1771           */
#define BGPTYPE_COMMUNITIES          8 /* RFC1997           */
#define BGPTYPE_ORIGINATOR_ID        9 /* RFC2796           */
#define BGPTYPE_CLUSTER_LIST        10 /* RFC2796           */
#define BGPTYPE_DPA                 11 /* work in progress  */
#define BGPTYPE_ADVERTISER          12 /* RFC1863           */
#define BGPTYPE_RCID_PATH           13 /* RFC1863           */
#define BGPTYPE_MP_REACH_NLRI       14 /* RFC2858           */
#define BGPTYPE_MP_UNREACH_NLRI     15 /* RFC2858           */
#define BGPTYPE_EXTENDED_COMMUNITY  16 /* Draft Ramachandra */
#define BGPTYPE_AS4_PATH            17 /* RFC 6793          */
#define BGPTYPE_AS4_AGGREGATOR      18 /* RFC 6793          */
#define BGPTYPE_SAFI_SPECIFIC_ATTR  19 /* draft-kapoor-nalawade-idr-bgp-ssa-00.txt */
#define BGPTYPE_PMSI_TUNNEL_ATTR    22 /* RFC6514 */
#define BGPTYPE_TUNNEL_ENCAPS_ATTR  23 /* RFC5512 */
#define BGPTYPE_AIGP                26 /* draft-ietf-idr-aigp-18 */
#define BGPTYPE_LINK_STATE_ATTR     29 /* draft-ietf-idr-ls-distribution */
#define BGPTYPE_LINK_STATE_OLD_ATTR 99 /* squatted value used by at least 2
                                          implementations before IANA assignment */
#define BGPTYPE_ATTR_SET           128 /* RFC6368           */

/*EVPN Route Types */
#define EVPN_AD_ROUTE           1
#define EVPN_MAC_ROUTE          2
#define EVPN_INC_MCAST_TREE     3
#define EVPN_ETH_SEGMENT_ROUTE  4
#define EVPN_IP_PREFIX_ROUTE    5 /* draft-rabadan-l2vpn-evpn-prefix-advertisement */

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
/* BGP trasnsitive extended community type high octet */
/* Range 0x00-0x3f First Come First Served */
/* Range 0x80-0x8f Reserved for Experimental */
/* Range 0x90-0xbf  Standards Action */

#define BGP_EXT_COM_TYPE_HIGH_TR_AS2        0x00    /* Transitive Two-Octet AS-Specific Extended Community */
#define BGP_EXT_COM_TYPE_HIGH_TR_IP4        0x01    /* Transitive IPv4-Address-specific Extended Community */
#define BGP_EXT_COM_TYPE_HIGH_TR_AS4        0x02    /* Transitive Four-Octet AS-Specific Extended Community */
#define BGP_EXT_COM_TYPE_HIGH_TR_OPAQUE     0x03    /* Transitive Opaque Extended Community */
#define BGP_EXT_COM_TYPE_HIGH_TR_QOS        0x04    /* QoS Marking [Thomas_Martin_Knoll] */
#define BGP_EXT_COM_TYPE_HIGH_TR_COS        0x05    /* CoS Capability [Thomas_Martin_Knoll] */
#define BGP_EXT_COM_TYPE_HIGH_TR_EVPN       0x06    /* EVPN (Sub-Types are defined in the "EVPN Extended Community Sub-Types" registry) */
/* 0x07 Unassigned */
#define BGP_EXT_COM_TYPE_HIGH_TR_FLOW       0x08    /* Flow spec redirect/mirror to IP next-hop [draft-simpson-idr-flowspec-redirect] */
#define BGP_EXT_COM_TYPE_HIGH_TR_EXP        0x80    /* Generic Transitive Experimental Extended Community */
#define BGP_EXT_COM_TYPE_HIGH_TR_EXP_FSIP4  0x81    /* http://tools.ietf.org/html/draft-haas-idr-flowspec-redirect-rt-bis-00 */
#define BGP_EXT_COM_TYPE_HIGH_TR_EXP_FSAS4  0x82    /* http://tools.ietf.org/html/draft-haas-idr-flowspec-redirect-rt-bis-00 */

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
#define BGP_EXT_COM_STYPE_EPVN_MMAC         0x00    /* MAC Mobility [draft-ietf-l2vpn-pbb-evpn] */
#define BGP_EXT_COM_STYPE_EVPN_LABEL        0x01    /* ESI MPLS Label [draft-ietf-l2vpn-evpn] */
#define BGP_EXT_COM_STYPE_EVPN_IMP          0x02    /* ES Import [draft-sajassi-l2vpn-evpn-segment-route] */

/* RFC 7432 Flag single active mode */
#define BGP_EXT_COM_ESI_LABEL_FLAGS         0x01    /* bitmask: set for single active multi-homing site */

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
#define BGP_EXT_COM_STYPE_AS2_OSPF      0x05    /* OSPF Domain Identifier [RFC4577] */
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
#define BGP_EXT_COM_STYPE_AS4_GEN       0x04    /* Generic [draft-ietf-idr-as4octet-extcomm-generic-subtype] */
#define BGP_EXT_COM_STYPE_AS4_OSPF      0x05    /* OSPF Domain Identifier [RFC4577] */
#define BGP_EXT_COM_STYPE_AS4_S_AS      0x09    /* Source AS [RFC6514] */
#define BGP_EXT_COM_STYPE_AS4_CIS_V     0x10    /* Cisco VPN Identifier [Eric_Rosen] */

/* Non-Transitive Four-Octet AS-Specific Extended Community Sub-Types */

#define BGP_EXT_COM_STYPE_AS4_GEN       0x04    /* Generic [draft-ietf-idr-as4octet-extcomm-generic-subtype] */

/* Transitive IPv4-Address-Specific Extended Community Sub-Types */

#define BGP_EXT_COM_STYPE_IP4_RT        0x02    /* Route Target [RFC4360] */
#define BGP_EXT_COM_STYPE_IP4_RO        0x03    /* Route Origin [RFC4360] */
#define BGP_EXT_COM_STYPE_IP4_OSPF_D    0x05    /* OSPF Domain Identifier [RFC4577] */
#define BGP_EXT_COM_STYPE_IP4_OSPF_R    0x07    /* OSPF Route ID [RFC4577] */
#define BGP_EXT_COM_STYPE_IP4_L2VPN     0x0a    /* L2VPN Identifier [RFC6074] */
#define BGP_EXT_COM_STYPE_IP4_VRF_I     0x0b    /* VRF Route Import [RFC6514] */
#define BGP_EXT_COM_STYPE_IP4_CIS_D     0x10    /* Cisco VPN-Distinguisher [Eric_Rosen] */
#define BGP_EXT_COM_STYPE_IP4_SEG_NH    0x12    /* Inter-area P2MP Segmented Next-Hop [draft-ietf-mpls-seamless-mcast] */

/* Transitive Opaque Extended Community Sub-Types */

#define BGP_EXT_COM_STYPE_OPA_OSPF      0x06    /* OSPF Route Type [RFC4577] */
#define BGP_EXT_COM_STYPE_OPA_COLOR     0x0b    /* Color Extended Community [RFC5512] */
#define BGP_EXT_COM_STYPE_OPA_ENCAP     0x0c    /* Encapsulation Extended Community [RFC5512] */
#define BGP_EXT_COM_STYPE_OPA_DGTW      0x0d    /* Default Gateway  [Yakov_Rekhter] */

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

#define BGP_EXT_COM_STYPE_EXP_F_TR      0x06    /* Flow spec traffic-rate [RFC5575] */
#define BGP_EXT_COM_STYPE_EXP_F_TA      0x07    /* Flow spec traffic-action [RFC5575] */
#define BGP_EXT_COM_STYPE_EXP_F_RED     0x08    /* Flow spec redirect [RFC5575] */
#define BGP_EXT_COM_STYPE_EXP_F_RMARK   0x09    /* Flow spec traffic-remarking [RFC5575] */
#define BGP_EXT_COM_STYPE_EXP_L2        0x0a    /* Layer2 Info Extended Community [RFC4761] */

/* BGP Generic Transitive Experimental redirect RT format IPv4:2 bytes Use Extended Community Sub-Types */

#define BGP_EXT_COM_STYPE_EXP_F_RED_IP4 0x08

/* BGP Generic Transitive Experimental redirect RT format AS4:2 bytes Use Extended Community Sub-Types */

#define BGP_EXT_COM_STYPE_EXP_F_RED_AS4 0x08

/* according to IANA's number assignment at: http://www.iana.org/assignments/bgp-extended-communities */

                                        /* draft-ietf-idr-bgp-ext-communities */
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
#define SAFNUM_EVPN            70  /* EVPN RFC */
#define SAFNUM_LINK_STATE      71  /* draft-ietf-idr-ls-distribution */
#define SAFNUM_LAB_VPNUNICAST 128  /* Draft-rosen-rfc2547bis-03 */
#define SAFNUM_LAB_VPNMULCAST 129
#define SAFNUM_LAB_VPNUNIMULC 130
#define SAFNUM_ROUTE_TARGET   132  /* RFC 4684 Constrained Route Distribution for BGP/MPLS IP VPN */
#define SAFNUM_FSPEC_RULE     133  /* RFC 5575 BGP flow spec SAFI */
#define SAFNUM_FSPEC_VPN_RULE 134  /* RFC 5575 BGP flow spec SAFI VPN */


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

/* draft-ietf-idr-aigp-18 AIGP types */
#define AIGP_TLV_TYPE           1

/* RFC 5512/5640 Sub-TLV Types */
#define TUNNEL_SUBTLV_ENCAPSULATION 1
#define TUNNEL_SUBTLV_PROTO_TYPE    2
#define TUNNEL_SUBTLV_COLOR         4
#define TUNNEL_SUBTLV_LOAD_BALANCE  5

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

/* draft-ietf-idr-ls-distribution-03 */
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

#define BGP_NLRI_TLV_AUTONOMOUS_SYSTEM              512
#define BGP_NLRI_TLV_BGP_LS_IDENTIFIER              513
#define BGP_NLRI_TLV_AREA_ID                        514
#define BGP_NLRI_TLV_IGP_ROUTER_ID                  515

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
#define BGP_NLRI_TLV_LEN_AREA_ID                        4
#define BGP_NLRI_TLV_LEN_NODE_FLAG_BITS                 1

/* draft-gredler-idr-bgp-ls-segment-routing-ext-01 */
#define BGP_LS_SR_TLV_SR_CAPABILITY                 1034
#define BGP_LS_SR_TLV_SR_ALGORITHM                  1035
#define BGP_LS_SR_TLV_ADJ_SID                       1099
#define BGP_LS_SR_TLV_LAN_ADJ_SID                   1100
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

/* SR-Capabilities TLV flags, draft-gredler-idr-bgp-ls-segment-routing-ext-01:

                             0  1  2  3  4  5  6  7
                            +--+--+--+--+--+--+--+--+
   if Protocol-ID is IS-IS  |I |V |H |  |  |  |  |  |
                            +--+--+--+--+--+--+--+--+
*/
#define BGP_LS_SR_CAPABILITY_FLAG_I 0x80
#define BGP_LS_SR_CAPABILITY_FLAG_V 0x40
#define BGP_LS_SR_CAPABILITY_FLAG_H 0x20

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
    { EVPN_IP_PREFIX_ROUTE,    "IP Prefix route"},
    { 0, NULL }
};

static const value_string evpn_nlri_esi_type[] = {
    { BGP_NLRI_EVPN_ESI_VALUE,      "ESI 9 bytes value" },
    { BGP_NLRI_EVPN_ESI_LACP,       "ESI LACP 802.1AX defined" },
    { BGP_NLRI_EVPN_ESI_MSTP,       "ESI mSTP defined" },
    { BGP_NLRI_EVPN_ESI_MAC,        "ESI MAC address defined" },
    { BGP_NLRI_EVPN_ESI_RID,        "ESI Router ID" },
    { BGP_NLRI_EVPN_ESI_ASN,        "ESI autonomous system" },
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
    { BGPTYPE_MP_REACH_NLRI,       "MP_REACH_NLRI" },
    { BGPTYPE_MP_UNREACH_NLRI,     "MP_UNREACH_NLRI" },
    { BGPTYPE_EXTENDED_COMMUNITY,  "EXTENDED_COMMUNITIES" },
    { BGPTYPE_AS4_PATH,            "AS4_PATH" },
    { BGPTYPE_AS4_AGGREGATOR,      "AS4_AGGREGATOR" },
    { BGPTYPE_SAFI_SPECIFIC_ATTR,  "SAFI_SPECIFIC_ATTRIBUTE" },
    { BGPTYPE_TUNNEL_ENCAPS_ATTR,  "TUNNEL_ENCAPSULATION_ATTRIBUTE" },
    { BGPTYPE_PMSI_TUNNEL_ATTR,    "PMSI_TUNNEL_ATTRIBUTE" },
    { BGPTYPE_AIGP,                "AIGP"},
    { BGPTYPE_LINK_STATE_ATTR,     "LINK_STATE" },
    { BGPTYPE_LINK_STATE_OLD_ATTR, "LINK_STATE (unofficial code point)" },
    { BGPTYPE_ATTR_SET,            "ATTR_SET" },
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
    { TUNNEL_TYPE_L2TP_OVER_IP, "L2TP_OVER_IP" },
    { TUNNEL_TYPE_GRE,          "GRE" },
    { TUNNEL_TYPE_IP_IN_IP,     "IP_IN_IP" },
    { 0, NULL }
};

static const value_string subtlv_type[] = {
    { TUNNEL_SUBTLV_ENCAPSULATION, "ENCAPSULATION" },
    { TUNNEL_SUBTLV_PROTO_TYPE,    "PROTOCOL_TYPE" },
    { TUNNEL_SUBTLV_COLOR,         "COLOR" },
    { TUNNEL_SUBTLV_LOAD_BALANCE,  "LOAD_BALANCE" },
    { 0, NULL }
};

static const value_string bgpext_com_type_high[] = {
    { BGP_EXT_COM_TYPE_HIGH_TR_AS2,         "Transitive Two-Octet AS" },
    { BGP_EXT_COM_TYPE_HIGH_TR_IP4,         "Transitive IPv4-Address" },
    { BGP_EXT_COM_TYPE_HIGH_TR_AS4,         "Transitive Four-Octet AS" },
    { BGP_EXT_COM_TYPE_HIGH_TR_OPAQUE,      "Transitive Opaque" },
    { BGP_EXT_COM_TYPE_HIGH_TR_QOS,         "Transitive QoS Marking" },
    { BGP_EXT_COM_TYPE_HIGH_TR_COS,         "Transitive CoS Capability" },
    { BGP_EXT_COM_TYPE_HIGH_TR_EVPN,        "Transitive EVPN" },
    { BGP_EXT_COM_TYPE_HIGH_TR_FLOW,        "Transitive Flow spec redirect/mirror to IP next-hop" },
    { BGP_EXT_COM_TYPE_HIGH_TR_EXP,         "Transitive Experimental"},
    { BGP_EXT_COM_TYPE_HIGH_TR_EXP_FSIP4,   "Transitive Experimental Redirect IPv4"},
    { BGP_EXT_COM_TYPE_HIGH_TR_EXP_FSAS4,   "Transitive Experimental Redirect AS4"},
    { BGP_EXT_COM_TYPE_HIGH_NTR_AS2,        "Non-Transitive Two-Octet AS" },
    { BGP_EXT_COM_TYPE_HIGH_NTR_IP4,        "Non-Transitive IPv4-Address" },
    { BGP_EXT_COM_TYPE_HIGH_NTR_AS4,        "Non-Transitive Four-Octet AS" },
    { BGP_EXT_COM_TYPE_HIGH_NTR_OPAQUE,     "Non-Transitive Opaque" },
    { BGP_EXT_COM_TYPE_HIGH_NTR_QOS,        "Non-Transive QoS Marking" },
    { 0, NULL}
};

static const value_string bgpext_com_stype_tr_exp_fs_ip4[] = {
    { BGP_EXT_COM_STYPE_EXP_F_RED_IP4,      "Route Target"},
    { 0, NULL}
};

static const value_string bgpext_com_stype_tr_exp_fs_as4[] = {
    { BGP_EXT_COM_STYPE_EXP_F_RED_AS4,      "Route Target"},
    { 0, NULL}
};

static const value_string bgpext_com_stype_tr_evpn[] = {
    { BGP_EXT_COM_STYPE_EPVN_MMAC,  "MAC Mobility" },
    { BGP_EXT_COM_STYPE_EVPN_LABEL, "ESI MPLS Label" },
    { BGP_EXT_COM_STYPE_EVPN_IMP,   "ES Import" },
    { 0, NULL}
};

static const value_string bgpext_com_stype_tr_as2[] = {
    { BGP_EXT_COM_STYPE_AS2_RT,     "Route Target" },
    { BGP_EXT_COM_STYPE_AS2_RO,     "Route Origin" },
    { BGP_EXT_COM_STYPE_AS2_OSPF,   "OSPF Domain Identifier" },
    { BGP_EXT_COM_STYPE_AS2_DCOLL,  "BGP Data Collection" },
    { BGP_EXT_COM_STYPE_AS2_SRC_AS, "Source AS" },
    { BGP_EXT_COM_STYPE_AS2_L2VPN,  "L2VPN Identifier" },
    { BGP_EXT_COM_STYPE_AS2_CVPND,  "Cisco VPN-Distinguisher" },
    { 0, NULL}
};

static const value_string bgpext_com_stype_ntr_as2[] = {
    { BGP_EXT_COM_STYPE_AS2_LBW, "Link Bandwidth" },
    { BGP_EXT_COM_STYPE_AS2_VNI, "Virtual-Network Identifier" },
    { 0, NULL}
};

static const value_string bgpext_com_stype_tr_as4[] = {
    { BGP_EXT_COM_STYPE_AS4_RT,     "Route Target" },
    { BGP_EXT_COM_STYPE_AS4_RO,     "Route Origin" },
    { BGP_EXT_COM_STYPE_AS4_GEN,    "Generic" },
    { BGP_EXT_COM_STYPE_AS4_OSPF,   "OSPF Domain Identifier" },
    { BGP_EXT_COM_STYPE_AS4_S_AS,   "Source AS" },
    { BGP_EXT_COM_STYPE_AS4_CIS_V,  "Cisco VPN Identifier" },
    { 0, NULL}
};

static const value_string bgpext_com_stype_ntr_as4[] = {
    { BGP_EXT_COM_STYPE_AS4_GEN, "Generic" },
    { 0, NULL}
};

static const value_string bgpext_com_stype_tr_IP4[] = {
    { BGP_EXT_COM_STYPE_IP4_RT,     "Route Target" },
    { BGP_EXT_COM_STYPE_IP4_RO,     "Route Origin" },
    { BGP_EXT_COM_STYPE_IP4_OSPF_D, "OSPF Domain Identifier" },
    { BGP_EXT_COM_STYPE_IP4_OSPF_R, "OSPF Route ID" },
    { BGP_EXT_COM_STYPE_IP4_L2VPN,  "L2VPN Identifier" },
    { BGP_EXT_COM_STYPE_IP4_VRF_I,  "VRF Route Import" },
    { BGP_EXT_COM_STYPE_IP4_CIS_D,  "Cisco VPN-Distinguisher" },
    { BGP_EXT_COM_STYPE_IP4_SEG_NH, "Inter-area P2MP Segmented Next-Hop" },
    { 0, NULL}
};

static const value_string bgpext_com_stype_tr_opaque[] = {
    { BGP_EXT_COM_STYPE_OPA_OSPF,   "OSPF Route Type" },
    { BGP_EXT_COM_STYPE_OPA_COLOR,  "Color" },
    { BGP_EXT_COM_STYPE_OPA_ENCAP,  "Encapsulation" },
    { BGP_EXT_COM_STYPE_OPA_DGTW,   "Default Gateway" },
    { 0, NULL}
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
    { BGP_EXT_COM_STYPE_OPA_OR_VAL_ST,  "BGP Origin Validation state" },
    { 0, NULL}
};

static const value_string bgpext_com_stype_tr_exp[] = {
    { BGP_EXT_COM_STYPE_EXP_F_TR,       "Flow spec traffic-rate" },
    { BGP_EXT_COM_STYPE_EXP_F_TA,       "Flow spec traffic-action" },
    { BGP_EXT_COM_STYPE_EXP_F_RED,      "Flow spec redirect AS 2 bytes" },
    { BGP_EXT_COM_STYPE_EXP_F_RMARK,    "Flow spec traffic-remarking" },
    { BGP_EXT_COM_STYPE_EXP_L2,         "Layer2 Info" },
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

/* Subsequent address family identifier, RFC2858 */
static const value_string bgpattr_nlri_safi[] = {
    { 0,                        "Reserved" },
    { SAFNUM_UNICAST,           "Unicast" },
    { SAFNUM_MULCAST,           "Multicast" },
    { SAFNUM_UNIMULC,           "Unicast+Multicast" },
    { SAFNUM_MPLS_LABEL,        "Labeled Unicast"},
    { SAFNUM_MCAST_VPN,         "MCAST-VPN"},
    { SAFNUM_ENCAPSULATION,     "Encapsulation"},
    { SAFNUM_TUNNEL,            "Tunnel"},
    { SAFNUM_VPLS,              "VPLS"},
    { SAFNUM_LINK_STATE,        "Link State"},
    { SAFNUM_LAB_VPNUNICAST,    "Labeled VPN Unicast" },        /* draft-rosen-rfc2547bis-03 */
    { SAFNUM_LAB_VPNMULCAST,    "Labeled VPN Multicast" },
    { SAFNUM_LAB_VPNUNIMULC,    "Labeled VPN Unicast+Multicast" },
    { SAFNUM_ROUTE_TARGET,      "Route Target Filter" },
    { SAFNUM_EVPN,              "EVPN" },
    { SAFNUM_FSPEC_RULE,        "Flow Spec Filter" },
    { SAFNUM_FSPEC_VPN_RULE,    "Flow Spec Filter VPN" },
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

static const value_string capability_vals[] = {
    { BGP_CAPABILITY_RESERVED,                      "Reserved capability" },
    { BGP_CAPABILITY_MULTIPROTOCOL,                 "Multiprotocol extensions capability" },
    { BGP_CAPABILITY_ROUTE_REFRESH,                 "Route refresh capability" },
    { BGP_CAPABILITY_COOPERATIVE_ROUTE_FILTERING,   "Cooperative route filtering capability" },
    { BGP_CAPABILITY_MULTIPLE_ROUTE_DEST,           "Multiple routes to a destination capability" },
    { BGP_CAPABILITY_EXTENDED_NEXT_HOP,             "Extended Next Hop Encoding" },
    { BGP_CAPABILITY_EXTENDED_MESSAGE,              "BGP-Extended Message" },
    { BGP_CAPABILITY_GRACEFUL_RESTART,              "Graceful Restart capability" },
    { BGP_CAPABILITY_4_OCTET_AS_NUMBER,             "Support for 4-octet AS number capability" },
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
    { BGP_COMM_NO_EXPORT,           "NO_EXPORT" },
    { BGP_COMM_NO_ADVERTISE,        "NO_ADVERTISE" },
    { BGP_COMM_NO_EXPORT_SUBCONFED, "NO_EXPORT_SUBCONFED" },
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
#define BGPNLRI_FSPEC_FRAGMENT     12 /* RFC 5575         */

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
static const true_false_string tfs_esi_label_flag = { "Single-Active redundancy", "All-Active redundancy" };

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
static int hf_bgp_cap_fqdn_hostname_len = -1;
static int hf_bgp_cap_fqdn_hostname = -1;
static int hf_bgp_cap_fqdn_domain_name_len = -1;
static int hf_bgp_cap_fqdn_domain_name = -1;
static int hf_bgp_cap_multisession_flags = -1;

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
static int hf_bgp_update_path_attribute_mp_reach_nlri_nbr_snpa = -1;
static int hf_bgp_update_path_attribute_mp_reach_nlri_snpa_length = -1;
static int hf_bgp_update_path_attribute_mp_reach_nlri_snpa = -1;
static int hf_bgp_update_path_attribute_mp_unreach_nlri_address_family = -1;
static int hf_bgp_update_path_attribute_mp_unreach_nlri_safi = -1;
static int hf_bgp_update_path_attribute_aigp = -1;
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
static int hf_bgp_evpn_nlri_mpls_ls = -1;
static int hf_bgp_evpn_nlri_maclen = -1;
static int hf_bgp_evpn_nlri_mac_addr = -1;
static int hf_bgp_evpn_nlri_iplen = -1;
static int hf_bgp_evpn_nlri_prefix_len = -1;
static int hf_bgp_evpn_nlri_ip_addr = -1;
static int hf_bgp_evpn_nlri_ipv6_addr = -1;
static int hf_bgp_evpn_nlri_ipv4_gtw = -1;
static int hf_bgp_evpn_nlri_ipv6_gtw = -1;

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

/* draft-ietf-idr-aigp-18 attribute */
static int hf_bgp_aigp_type = -1;
static int hf_bgp_aigp_tlv_length = -1;
static int hf_bgp_aigp_accu_igp_metric = -1;


/* MPLS labels decoding */
static int hf_bgp_update_mpls_label = -1;
static int hf_bgp_update_mpls_label_value = -1;
static int hf_bgp_update_mpls_label_value_20bits = -1;

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

/* BGP-LS */

static int hf_bgp_ls_type = -1;
static int hf_bgp_ls_length = -1;

static int hf_bgp_ls_safi72_nlri = -1;
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

/* draft-ietf-idr-ls-distribution-03 TLVs */
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

static int hf_bgp_ls_tlv_autonomous_system = -1;                   /* 512 */
static int hf_bgp_ls_tlv_autonomous_system_id = -1;
static int hf_bgp_ls_tlv_bgp_ls_identifier = -1;                   /* 513 */
static int hf_bgp_ls_tlv_bgp_ls_identifier_id = -1;
static int hf_bgp_ls_tlv_area_id = -1;                             /* 514 */
static int hf_bgp_ls_tlv_area_id_id = -1;
static int hf_bgp_ls_tlv_igp_router = -1;                          /* 515 */
static int hf_bgp_ls_tlv_igp_router_id = -1;

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

/* BGP flow spec nlri header field */

static int hf_bgp_flowspec_nlri_t = -1;
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

static int hf_bgp_ext_com_type_high = -1;
static int hf_bgp_ext_com_stype_low_unknown = -1;
static int hf_bgp_ext_com_stype_tr_evpn = -1;
static int hf_bgp_ext_com_stype_tr_as2 = -1;
static int hf_bgp_ext_com_stype_ntr_as2 = -1;
static int hf_bgp_ext_com_stype_tr_as4 = -1;
static int hf_bgp_ext_com_stype_ntr_as4 = -1;
static int hf_bgp_ext_com_stype_tr_IP4 = -1;
static int hf_bgp_ext_com_stype_tr_opaque = -1;
static int hf_bgp_ext_com_stype_ntr_opaque = -1;
static int hf_bgp_ext_com_tunnel_type = -1;
static int hf_bgp_ext_com_stype_tr_exp = -1;
static int hf_bgp_ext_com_stype_tr_exp_fs_ip4 = -1;
static int hf_bgp_ext_com_stype_tr_exp_fs_as4 = -1;

static int hf_bgp_ext_com_value_as2 = -1;
static int hf_bgp_ext_com_value_as4 = -1;
static int hf_bgp_ext_com_value_IP4 = -1;
static int hf_bgp_ext_com_value_an2 = -1;
static int hf_bgp_ext_com_value_an4 = -1;
static int hf_bgp_ext_com_value_unknown16 = -1;
static int hf_bgp_ext_com_value_unknown32 = -1;
static int hf_bgp_ext_com_value_link_bw = -1;
static int hf_bgp_ext_com_value_ospf_rtype = -1;
static int hf_bgp_ext_com_value_ospf_rtype_option = -1;
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
static gint ett_bgp_extended_community = -1; /* extended comminiy tree for each community of BGP update */
static gint ett_bgp_extended_com_fspec_redir = -1; /* extended communities BGP flow act redirect */
static gint ett_bgp_ext_com_flags = -1; /* extended communities flags tree */
static gint ett_bgp_ext_com_l2_flags = -1; /* extended commuties tree for l2 services flags */
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
static gint ett_bgp_mpls_labels = -1;
static gint ett_bgp_pmsi_tunnel_id = -1;
static gint ett_bgp_aigp_attr = -1;

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

static expert_field ei_bgp_evpn_nlri_rt4_no_ip = EI_INIT;
static expert_field ei_bgp_evpn_nlri_rt4_len_err = EI_INIT;
static expert_field ei_bgp_evpn_nlri_rt_type_err = EI_INIT;
static expert_field ei_bgp_evpn_nlri_esi_type_err = EI_INIT;
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
        if( prefix_len > 32) {
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
/*
 * Decode an IPv4 prefix with Path Identifier
 * Code inspired from the decode_prefix4 function
 */
static int
decode_path_prefix4(proto_tree *tree, packet_info *pinfo, int hf_path_id, int hf_addr, tvbuff_t *tvb, gint offset,
                    const char *tag)
{
    proto_tree *prefix_tree;
    union {
       guint8 addr_bytes[4];
       guint32 addr;
    } ip_addr;        /* IP address                         */
    guint8 plen;      /* prefix length                      */
    int    length;    /* number of octets needed for prefix */
    guint32 path_identifier;
    address addr;

    /* snarf path identifier length and prefix */
    path_identifier = tvb_get_ntohl(tvb, offset);
    plen = tvb_get_guint8(tvb, offset + 4);
    length = tvb_get_ipv4_addr_with_prefix_len(tvb, offset + 4 + 1, ip_addr.addr_bytes, plen);
    if (length < 0) {
        proto_tree_add_expert_format(tree, pinfo, &ei_bgp_length_invalid, tvb, offset + 4 , 1, "%s length %u invalid (> 32)",
            tag, plen);
        return -1;
    }
    /* put prefix into protocol tree */
    set_address(&addr, AT_IPv4, 4, ip_addr.addr_bytes);
    prefix_tree = proto_tree_add_subtree_format(tree, tvb, offset,  4 + 1 + length,
                            ett_bgp_prefix, NULL, "%s/%u PathId %u ",
                            address_to_str(wmem_packet_scope(), &addr), plen, path_identifier);
    proto_tree_add_item(prefix_tree, hf_path_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(prefix_tree, hf_bgp_prefix_length, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
    proto_tree_add_ipv4(prefix_tree, hf_addr, tvb, offset + 4 + 1, length, ip_addr.addr);
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
    union {
       guint8 addr_bytes[4];
       guint32 addr;
    } ip_addr;        /* IP address                         */
    guint8 plen;      /* prefix length                      */
    int    length;    /* number of octets needed for prefix */
    address addr;

    /* snarf length and prefix */
    plen = tvb_get_guint8(tvb, offset);
    length = tvb_get_ipv4_addr_with_prefix_len(tvb, offset + 1, ip_addr.addr_bytes, plen);
    if (length < 0) {
        proto_tree_add_expert_format(tree, pinfo, &ei_bgp_length_invalid, tvb, offset, 1, "%s length %u invalid (> 32)",
            tag, plen);
        return -1;
    }

    /* put prefix into protocol tree */
    set_address(&addr, AT_IPv4, 4, ip_addr.addr_bytes);
    prefix_tree = proto_tree_add_subtree_format(tree, tvb, offset,
            1 + length, ett_bgp_prefix, NULL,
            "%s/%u", address_to_str(wmem_packet_scope(), &addr), plen);

    proto_item_append_text(parent_item, " (%s/%u)",
                             address_to_str(wmem_packet_scope(), &addr), plen);

    proto_tree_add_uint_format(prefix_tree, hf_bgp_prefix_length, tvb, offset, 1, plen, "%s prefix length: %u",
        tag, plen);
    proto_tree_add_ipv4(prefix_tree, hf_addr, tvb, offset + 1, length,
            ip_addr.addr);
    return(1 + length);
}

/*
 * Decode an IPv6 prefix.
 */
static int
decode_prefix6(proto_tree *tree, packet_info *pinfo, int hf_addr, tvbuff_t *tvb, gint offset,
               guint16 tlen, const char *tag)
{
    proto_tree          *prefix_tree;
    struct e_in6_addr   addr;     /* IPv6 address                       */
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
            address_to_str(wmem_packet_scope(), &addr_str), plen);
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
    struct e_in6_addr addr;     /* IPv6 address                       */
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
            address_to_str(wmem_packet_scope(), &addr_str), plen);
    proto_tree_add_item(prefix_tree, hf_bgp_flowspec_nlri_ipv6_pref_len, tvb, offset + plength_place, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(prefix_tree, hf_bgp_flowspec_nlri_ipv6_pref_offset, tvb, offset + poffset_place, 1, ENC_BIG_ENDIAN);
    proto_tree_add_ipv6(prefix_tree, hf_addr, tvb, offset + 2, length, &addr);
    if (parent_item != NULL)
      proto_item_append_text(parent_item, " (%s/%u)",
                             address_to_str(wmem_packet_scope(), &addr_str), plen);
    return(2 + length);
}

const char*
decode_bgp_rd(tvbuff_t *tvb, gint offset)
{
    guint16 rd_type;
    wmem_strbuf_t *strbuf;

    rd_type = tvb_get_ntohs(tvb,offset);
    strbuf = wmem_strbuf_new_label(wmem_packet_scope());

    switch (rd_type) {
        case FORMAT_AS2_LOC:
            wmem_strbuf_append_printf(strbuf, "%u:%u", tvb_get_ntohs(tvb, offset + 2),
                                      tvb_get_ntohl(tvb, offset + 4));
            break;
        case FORMAT_IP_LOC:
            wmem_strbuf_append_printf(strbuf, "%s:%u", tvb_ip_to_str(tvb, offset + 2),
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
 * function to decode operator in BGP flow spec NLRI when it address decimal values (TCP ports, UDP ports, ports, ...)
 */

static void
decode_bgp_flow_spec_dec_operator(proto_tree *tree, tvbuff_t *tvb, gint offset)
{
    static const int * flags[] = {
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
    static const int * flags[] = {
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

    static const int * nlri_tcp_flags[] = {
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

    static const int * nlri_flags[] = {
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
decode_flowspec_nlri(proto_tree *tree, tvbuff_t *tvb, gint offset, guint16 afi, packet_info *pinfo)
{
    guint     tot_flow_len;       /* total length of the flow spec NLRI */
    guint     offset_len;         /* offset of the flow spec NLRI itself could be 1 or 2 bytes */
    guint     cursor_fspec;       /* cursor to move into flow spec nlri */
    gint      filter_len = -1;
    guint16   len_16;
    proto_item *item;
    proto_item *filter_item;
    proto_tree *nlri_tree;
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
            else if (afi == AFNUM_INET6)
                filter_len = decode_fspec_match_prefix6(filter_tree, filter_item, hf_bgp_flowspec_nlri_dst_ipv6_pref,
                                                        tvb, offset+cursor_fspec, 0, pinfo);
            else cursor_fspec = tot_flow_len;
            if (filter_len == -1)
                cursor_fspec= tot_flow_len;
            break;
        case BGPNLRI_FSPEC_SRC_PFIX:
            cursor_fspec++;
            if (afi == AFNUM_INET)
                filter_len = decode_prefix4(filter_tree, pinfo, filter_item, hf_bgp_flowspec_nlri_src_pref_ipv4,
                                            tvb, offset+cursor_fspec, "Source IP filter");
            else if (afi == AFNUM_INET6)
                filter_len = decode_fspec_match_prefix6(filter_tree, filter_item, hf_bgp_flowspec_nlri_src_ipv6_pref,
                                                        tvb, offset+cursor_fspec, 0, pinfo);
            else cursor_fspec = tot_flow_len;
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

    item = proto_tree_add_item(tree, hf_bgp_mdt_nlri_safi_rd, tvb,
                               offset, BGP_ROUTE_DISTINGUISHER_SIZE, ENC_NA);
    proto_item_set_text(item, "Route Distinguisher: %s",
                        decode_bgp_rd(tvb, offset));
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

        if ((label_entry & BGP_MPLS_BOTTOM_L_STACK) == 0) {
            /* real MPLS multi-label stack in BGP? - maybe later; for now, it must be a bogus packet */
            wmem_strbuf_append(stack_strbuf, " (BOGUS: Bottom of Stack NOT set!)");
            break;
        }
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
 * Decode a multiprotocol address
 */

static int
mp_addr_to_str (guint16 afi, guint8 safi, tvbuff_t *tvb, gint offset, wmem_strbuf_t *strbuf, gint nhlen)
{
    int                 length;                         /* length of the address in byte */
    guint16             rd_type;                        /* Route Distinguisher type     */

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
                        wmem_strbuf_append(strbuf, tvb_ip_to_str(tvb, offset));
                    } else if (nhlen == 16) {
                        wmem_strbuf_append(strbuf, tvb_ip6_to_str(tvb, offset));
                    } else {
                        wmem_strbuf_append(strbuf, "Unknown address");
                    }
                    break;
                case SAFNUM_TUNNEL:
                    length = 4;
                    wmem_strbuf_append(strbuf, tvb_ip_to_str(tvb, offset));
                    break;
                case SAFNUM_LAB_VPNUNICAST:
                case SAFNUM_LAB_VPNMULCAST:
                case SAFNUM_LAB_VPNUNIMULC:
                    rd_type=tvb_get_ntohs(tvb,offset) ;
                    wmem_strbuf_truncate(strbuf, 0);
                    switch (rd_type) {
                        case FORMAT_AS2_LOC:
                            length = 12;
                            wmem_strbuf_append_printf(strbuf, "Empty Label Stack RD=%u:%u IPv4=%s",
                                                      tvb_get_ntohs(tvb, offset + 2),
                                                      tvb_get_ntohl(tvb, offset + 4),
                                                      tvb_ip_to_str(tvb, offset + 8)); /* Next Hop */
                            break;
                        case FORMAT_IP_LOC:
                            length = 12;
                            wmem_strbuf_append_printf(strbuf, "Empty Label Stack RD=%s:%u IPv4=%s",
                                                      tvb_ip_to_str(tvb, offset + 2), /* IP part of the RD */
                                                      tvb_get_ntohs(tvb, offset + 6),
                                                      tvb_ip_to_str(tvb, offset + 8)); /* Next Hop */
                            break ;
                        case FORMAT_AS4_LOC:
                            length = 12;
                            wmem_strbuf_append_printf(strbuf, "Empty Label Stack RD=%u.%u:%u IPv4=%s",
                                                      tvb_get_ntohs(tvb, offset + 2),
                                                      tvb_get_ntohs(tvb, offset + 4),
                                                      tvb_get_ntohs(tvb, offset + 6),
                                                      tvb_ip_to_str(tvb, offset + 8)); /* Next Hop   */
                            break ;
                        default:
                            length = 0 ;
                            wmem_strbuf_append_printf(strbuf, "Unknown (0x%04x) labeled VPN IPv4 address format",rd_type);
                            break;
                    } /* switch (rd_type) */
                    break;
                default:
                    length = 0 ;
                    wmem_strbuf_truncate(strbuf, 0);
                    wmem_strbuf_append_printf(strbuf, "Unknown SAFI (%u) for AFI %u", safi, afi);
                    break;
            } /* switch (safi) */
            break;
        case AFNUM_INET6:
            wmem_strbuf_truncate(strbuf, 0);
            switch (safi) {
                case SAFNUM_UNICAST:
                case SAFNUM_MULCAST:
                case SAFNUM_UNIMULC:
                case SAFNUM_MPLS_LABEL:
                case SAFNUM_ENCAPSULATION:
                case SAFNUM_TUNNEL:
                    length = 16;
                    wmem_strbuf_append_printf(strbuf, "%s", tvb_ip6_to_str(tvb, offset));
                    break;
                case SAFNUM_LAB_VPNUNICAST:
                case SAFNUM_LAB_VPNMULCAST:
                case SAFNUM_LAB_VPNUNIMULC:
                    rd_type=tvb_get_ntohs(tvb,offset) ;
                    switch (rd_type) {
                        case FORMAT_AS2_LOC:
                            length = 8 + 16;
                            wmem_strbuf_append_printf(strbuf, "Empty Label Stack RD=%u:%u IPv6=%s",
                                                      tvb_get_ntohs(tvb, offset + 2),
                                                      tvb_get_ntohl(tvb, offset + 4),
                                                      tvb_ip6_to_str(tvb, offset + 8)); /* Next Hop */
                            break;
                        case FORMAT_IP_LOC:
                            length = 8 + 16;
                            wmem_strbuf_append_printf(strbuf, "Empty Label Stack RD=%s:%u IPv6=%s",
                                                      tvb_ip_to_str(tvb, offset + 2), /* IP part of the RD */
                                                      tvb_get_ntohs(tvb, offset + 6),
                                                      tvb_ip6_to_str(tvb, offset + 8)); /* Next Hop */
                            break ;
                        case FORMAT_AS4_LOC:
                            length = 8 + 16;
                            wmem_strbuf_append_printf(strbuf, "Empty Label Stack RD=%u:%u IPv6=%s",
                                                      tvb_get_ntohl(tvb, offset + 2),
                                                      tvb_get_ntohs(tvb, offset + 6),
                                                      tvb_ip6_to_str(tvb, offset + 8)); /* Next Hop */
                            break ;
                        default:
                            length = 0 ;
                            wmem_strbuf_append_printf(strbuf, "Unknown (0x%04x) labeled VPN IPv6 address format",rd_type);
                            break;
                    }  /* switch (rd_type) */
                    break;
                default:
                    length = 0 ;
                    wmem_strbuf_append_printf(strbuf, "Unknown SAFI (%u) for AFI %u", safi, afi);
                    break;
            } /* switch (safi) */
            break;
        case AFNUM_L2VPN:
        case AFNUM_L2VPN_OLD:
            wmem_strbuf_truncate(strbuf, 0);
            switch (safi) {
                case SAFNUM_LAB_VPNUNICAST: /* only labeles prefixes do make sense */
                case SAFNUM_LAB_VPNMULCAST:
                case SAFNUM_LAB_VPNUNIMULC:
                case SAFNUM_VPLS:
                    length = 4; /* the next-hop is simply an ipv4 addr */
                    wmem_strbuf_append_printf(strbuf, "IPv4=%s",
                                              tvb_ip_to_str(tvb, offset));
                    break;
                default:
                    length = 0 ;
                    wmem_strbuf_append_printf(strbuf, "Unknown SAFI (%u) for AFI %u", safi, afi);
                    break;
            } /* switch (safi) */
            break;
        case AFNUM_LINK_STATE:
            length = nhlen;
            if (nhlen == 4) {
                wmem_strbuf_append(strbuf, tvb_ip_to_str(tvb, offset));
            } else if (nhlen == 16) {
                wmem_strbuf_append(strbuf, tvb_ip6_to_str(tvb, offset));
            } else {
                wmem_strbuf_append(strbuf, "Unknown address");
            }
            break;
        default:
            length = 0 ;
            wmem_strbuf_truncate(strbuf, 0);
            wmem_strbuf_append_printf(strbuf, "Unknown AFI (%u) value", afi);
            break;
    } /* switch (afi) */
    return(length) ;
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
          default:
              expert_add_info_format(pinfo, tree, &ei_bgp_ls_error, "Undefined node Descriptor Sub-TLV type (%u)!", type);
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
    if (length < 1)
        return dissected_length;

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
        proto_tree *tree, gint offset, packet_info *pinfo, int length) {

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
                if (decode_prefix4(tlv_sub_tree, pinfo, tlv_sub_item, hf_bgp_ls_nlri_ip_reachability_prefix_ip,
                               tvb, offset + 4, "Reachability") == -1)
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
    int n;

    proto_item* tlv_item;
    proto_tree* tlv_tree;
    proto_item* tlv_sub_item;
    proto_tree* tlv_sub_tree;

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
            static const int * flags[] = {
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
            proto_tree_add_item(tlv_tree, hf_bgp_ls_tlv_node_name_value, tvb, offset + 4, length, ENC_ASCII|ENC_NA);
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
                static const int *sr_capabilities_flags[] = {
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

        /* NODE & LINK ATTRIBUTE TLVs */
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
                static const int * nlri_flags[] = {
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
            static const int * flags[] = {
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
            proto_tree_add_item(tlv_tree, hf_bgp_ls_tlv_link_name_attribute_value, tvb, offset + 4, length, ENC_ASCII|ENC_NA);
            break;

        case BGP_LS_SR_TLV_ADJ_SID:
            {
                /*
                   0  1  2  3  4  5  6  7
                  +--+--+--+--+--+--+--+--+
                  |F |B |V |L |S |  |  |  |
                  +--+--+--+--+--+--+--+--+
                */
                static const int *adj_sid_isis_flags[] = {
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
                static const int *adj_sid_ospf_flags[] = {
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

        case BGP_LS_SR_TLV_PREFIX_SID:
            {
                /*
                   0  1  2  3  4  5  6  7
                  +--+--+--+--+--+--+--+--+
                  |R |N |P |E |V |L |  |  |
                  +--+--+--+--+--+--+--+--+
                */
                static const int *prefix_sid_isis_flags[] = {
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
                static const int *prefix_sid_ospf_flags[] = {
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

        default:
            expert_add_info_format(pinfo, tree, &ei_bgp_ls_error,
                "Unknown Prefix Descriptor TLV Code (%u)!", type);
            break;
    }
    return length + 4;
}

static int decode_evpn_nlri_esi(proto_tree *tree, tvbuff_t *tvb, gint offset, packet_info *pinfo) {
    guint8 esi_type = 0;
    proto_tree *esi_tree;
    proto_item *ti;
    wmem_allocator_t *buffer_value_string = NULL;

    ti = proto_tree_add_item(tree, hf_bgp_evpn_nlri_esi, tvb, offset, 10, ENC_NA);
    esi_tree = proto_item_add_subtree(ti, ett_bgp_evpn_nlri_esi);
    proto_tree_add_item(esi_tree, hf_bgp_evpn_nlri_esi_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    esi_type = tvb_get_guint8(tvb, offset);
    switch (esi_type) {
        case BGP_NLRI_EVPN_ESI_VALUE :
            proto_tree_add_item(esi_tree, hf_bgp_evpn_nlri_esi_value, tvb,
                                offset+1, 9, ENC_NA);
            proto_item_append_text(ti, ": %s",
                                   tvb_bytes_to_str_punct(buffer_value_string, tvb, offset + 1, 9, ' '));
            break;
        case BGP_NLRI_EVPN_ESI_LACP :
            proto_tree_add_item(esi_tree, hf_bgp_evpn_nlri_esi_lacp_mac, tvb,
                                offset+1, 6, ENC_NA);
            proto_tree_add_item(esi_tree, hf_bgp_evpn_nlri_esi_portk, tvb,
                                offset+7, 2, ENC_NA);
            proto_tree_add_item(esi_tree, hf_bgp_evpn_nlri_esi_remain, tvb,
                                offset+9, 1, ENC_NA);
            proto_item_append_text(ti, ": %s, Key: %s",
                                   tvb_ether_to_str(tvb,offset+1),
                                   tvb_bytes_to_str_punct(buffer_value_string, tvb, offset + 7, 2, ' '));
            break;
        case BGP_NLRI_EVPN_ESI_MSTP :
            proto_tree_add_item(esi_tree, hf_bgp_evpn_nlri_esi_rb_mac, tvb,
                                offset+1, 6, ENC_NA);
            proto_tree_add_item(esi_tree, hf_bgp_evpn_nlri_esi_rbprio, tvb,
                                offset+7, 2, ENC_NA);
            proto_tree_add_item(esi_tree, hf_bgp_evpn_nlri_esi_remain, tvb,
                                offset+9, 1, ENC_NA);
            proto_item_append_text(ti, ": %s, Priority: %s",
                                   tvb_ether_to_str(tvb,offset+1),
                                   tvb_bytes_to_str_punct(buffer_value_string, tvb, offset + 7, 2, ' '));
            break;
        case BGP_NLRI_EVPN_ESI_MAC :
            proto_tree_add_item(esi_tree, hf_bgp_evpn_nlri_esi_sys_mac, tvb,
                                offset+1, 6, ENC_NA);
            proto_tree_add_item(esi_tree, hf_bgp_evpn_nlri_esi_mac_discr, tvb,
                                offset+7, 2, ENC_NA);
            proto_tree_add_item(esi_tree, hf_bgp_evpn_nlri_esi_remain, tvb,
                                offset+9, 1, ENC_NA);
            proto_item_append_text(ti, ": %s, Discriminator: %s",
                                   tvb_ether_to_str(tvb,offset+1),
                                   tvb_bytes_to_str_punct(buffer_value_string, tvb, offset + 7, 2, ' '));
            break;
        case BGP_NLRI_EVPN_ESI_RID :
            proto_tree_add_item(esi_tree, hf_bgp_evpn_nlri_esi_router_id, tvb,
                                offset+1, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(esi_tree, hf_bgp_evpn_nlri_esi_router_discr, tvb,
                                offset+5, 4, ENC_NA);
            proto_tree_add_item(esi_tree, hf_bgp_evpn_nlri_esi_remain, tvb,
                                offset+9, 1, ENC_NA);
            proto_item_append_text(ti, ": %s, Discriminator: %s",
                                   tvb_ip_to_str(tvb,offset+1),
                                   tvb_bytes_to_str_punct(buffer_value_string, tvb, offset + 5, 4, ' '));
            break;
        case BGP_NLRI_EVPN_ESI_ASN :
            proto_tree_add_item(esi_tree, hf_bgp_evpn_nlri_esi_asn, tvb,
                                offset+1, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(esi_tree, hf_bgp_evpn_nlri_esi_asn_discr, tvb,
                                offset+5, 4, ENC_NA);
            proto_tree_add_item(esi_tree, hf_bgp_evpn_nlri_esi_remain, tvb,
                                offset+9, 1, ENC_NA);
            proto_item_append_text(ti, ": %u, Discriminator: %s",
                                   tvb_get_ntohl(tvb,offset+1),
                                   tvb_bytes_to_str_punct(buffer_value_string, tvb, offset + 5, 4, ' '));
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
 *  * Decode EVPN NLRI, http://tools.ietf.org/html/draft-ietf-l2vpn-evpn-05#section-7.1
 *   */
static int decode_evpn_nlri(proto_tree *tree, tvbuff_t *tvb, gint offset, packet_info *pinfo) {
    int start_offset = offset;
    proto_tree *prefix_tree;
    proto_item *ti;
    guint8 route_type;
    guint labnum;
    guint8 nlri_len;
    guint8 ip_len;
    guint32 total_length = 0;
    proto_item *item;
    wmem_strbuf_t *stack_strbuf; /* label stack                  */

    route_type = tvb_get_guint8(tvb, offset);

    if (route_type == 0 || route_type > 5) {
        expert_add_info_format(pinfo, tree, &ei_bgp_evpn_nlri_rt_type_err,
                               "Invalid EVPN Route Type (%u)!", route_type);
        return -1;
    }

    nlri_len = tvb_get_guint8(tvb, offset + 1);

    ti = proto_tree_add_item(tree, hf_bgp_evpn_nlri, tvb, start_offset,
                               nlri_len+2, ENC_NA);

    prefix_tree = proto_item_add_subtree(ti, ett_bgp_evpn_nlri);

    proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_rt, tvb, start_offset,
                        1, ENC_BIG_ENDIAN);
    proto_item_append_text(ti, ": %s", val_to_str(tvb_get_guint8(tvb, offset), evpnrtypevals, "Unknown capability %d"));

    proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_len, tvb, start_offset+1,
                        1, ENC_BIG_ENDIAN);

    if (route_type == EVPN_ETH_SEGMENT_ROUTE && nlri_len < 21) {
        expert_add_info_format(pinfo, prefix_tree, &ei_bgp_evpn_nlri_rt4_len_err,
                               "Invalid length (%u) of EVPN NLRI Route Type 4 (Ethernet Segment Route)!", nlri_len);
        return -1;
    }

    item = proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_rd, tvb, start_offset+2,
                               8, ENC_NA);
    proto_item_append_text(item, " (%s)", decode_bgp_rd(tvb, offset + 2));

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

        decode_evpn_nlri_esi(prefix_tree, tvb, start_offset+10, pinfo);

        proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_etag, tvb, start_offset+20,
                                   4, ENC_BIG_ENDIAN);

        stack_strbuf = wmem_strbuf_new_label(wmem_packet_scope());
        labnum = decode_MPLS_stack(tvb, offset + 24,
                stack_strbuf);
        proto_tree_add_string(prefix_tree, hf_bgp_evpn_nlri_mpls_ls, tvb, start_offset+24,
                                   labnum*3, wmem_strbuf_get_str(stack_strbuf));

        /*Add 2 for Route Type and Length fields*/
        total_length = 25 + 2;
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

        decode_evpn_nlri_esi(prefix_tree, tvb, start_offset+10, pinfo);

        proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_etag, tvb, start_offset+20,
                            4, ENC_BIG_ENDIAN);

        proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_maclen, tvb, start_offset+24,
                            1, ENC_BIG_ENDIAN);

        proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_mac_addr, tvb, start_offset+25,
                            6, ENC_NA);

        ip_len = tvb_get_guint8(tvb, offset + 31) / 8;
        proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_iplen, tvb, start_offset+31,
                            1, ENC_BIG_ENDIAN);

        total_length = 31;

        if (ip_len == 4) {
            /*IPv4 address*/
            proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_ip_addr, tvb, start_offset+32,
                                4, ENC_NA);
            total_length += 4;
        } else if (ip_len == 16) {
            /*IPv6 address*/
            proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_ipv6_addr, tvb, start_offset+32,
                                16, ENC_NA);
            total_length += 16;
        } else if (ip_len == 0) {
            /*IP not included*/
            proto_tree_add_expert(prefix_tree, pinfo, &ei_bgp_evpn_nlri_rt4_no_ip, tvb, start_offset+32, 1);
        } else {
            return -1;
        }

        stack_strbuf = wmem_strbuf_new_label(wmem_packet_scope());
        labnum = decode_MPLS_stack(tvb, offset + total_length + 1,
                stack_strbuf);
        proto_tree_add_string(prefix_tree, hf_bgp_evpn_nlri_mpls_ls, tvb, start_offset+total_length+1,
                                   labnum*3, wmem_strbuf_get_str(stack_strbuf));

        total_length = total_length + 4;
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

        proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_etag, tvb, start_offset+10,
                            4, ENC_BIG_ENDIAN);

        ip_len = tvb_get_guint8(tvb, offset + 14) / 8;
        proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_iplen, tvb, start_offset+14,
                            1, ENC_BIG_ENDIAN);

        total_length = 15;

        if (ip_len == 4) {
            /*IPv4 address*/
            proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_ip_addr, tvb, start_offset+15,
                                4, ENC_NA);
            total_length += 4;
        } else if (ip_len == 16) {
            /*IPv6 address*/
            proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_ipv6_addr, tvb, start_offset+15,
                                16, ENC_NA);
            total_length += 16;
        } else if (ip_len == 0) {
            /*IP not included*/
            proto_tree_add_expert(prefix_tree, pinfo, &ei_bgp_evpn_nlri_rt4_no_ip, tvb, start_offset, 1);
        } else {
            expert_add_info_format(pinfo, prefix_tree, &ei_bgp_evpn_nlri_rt4_len_err,
                                   "Invalid length of IP Address (%u) in EVPN NLRI Route Type 3 (Iclusive Multicast Tree Route)!", ip_len);
            return -1;
        }
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

        decode_evpn_nlri_esi(prefix_tree, tvb, start_offset+10, pinfo);

        ip_len = tvb_get_guint8(tvb, offset + 20) / 8;
        proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_iplen, tvb, start_offset+20,
                            1, ENC_BIG_ENDIAN);

        total_length = 21;

        if (ip_len == 4) {
            /*IPv4 address*/
            proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_ip_addr, tvb, start_offset+21,
                                4, ENC_NA);
            total_length += 4;
        } else if (ip_len == 16) {
            /*IPv6 address*/
            proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_ipv6_addr, tvb, start_offset+21,
                                16, ENC_NA);
            total_length += 16;
        } else if (ip_len == 0) {
            /*IP not included*/
            proto_tree_add_expert(prefix_tree, pinfo, &ei_bgp_evpn_nlri_rt4_no_ip, tvb, start_offset, 1);
        } else {
            expert_add_info_format(pinfo, prefix_tree, &ei_bgp_evpn_nlri_rt4_len_err,
                                   "Invalid length of IP Address (%u) in EVPN NLRI Route Type 4 (Ethernet Segment Route)!", ip_len);
            return -1;
        }

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

        decode_evpn_nlri_esi(prefix_tree, tvb, start_offset+10, pinfo);

        proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_etag, tvb, start_offset+20,
                            4, ENC_BIG_ENDIAN);
        proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_prefix_len, tvb, start_offset+24,
                            1, ENC_BIG_ENDIAN);
        switch (nlri_len) {
            case 34 :
                /* IPv4 address */
                proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_ip_addr, tvb, start_offset+25,
                                    4, ENC_NA);
                proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_ipv4_gtw, tvb, start_offset+29,
                                    4, ENC_NA);
                decode_MPLS_stack_tree(tvb, start_offset+33, prefix_tree);
                total_length = 36;
                break;
            case 58 :
                /* IPv6 address */
                proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_ipv6_addr, tvb, start_offset+25,
                                    16, ENC_NA);
                proto_tree_add_item(prefix_tree, hf_bgp_evpn_nlri_ipv6_gtw, tvb, start_offset+41,
                                    16, ENC_NA);
                decode_MPLS_stack_tree(tvb, start_offset+57, prefix_tree);
                total_length = 60;
                break;
            default :
                expert_add_info_format(pinfo, prefix_tree, &ei_bgp_evpn_nlri_rt4_len_err,
                                   "Invalid total nlri length (%u) in EVPN NLRI Route Type 5 (IP prefix Route)!", nlri_len);
                return -1;
        }
        break;
    default:
        return -1;
    }

    return total_length;
}


/*
 * Decode a multiprotocol prefix
 */
static int
decode_prefix_MP(proto_tree *tree, int hf_addr4, int hf_addr6,
                 guint16 afi, guint8 safi, tvbuff_t *tvb, gint offset,
                 const char *tag, packet_info *pinfo)
{
    int                 start_offset = offset;
    proto_item          *ti;
    proto_tree          *prefix_tree;
    proto_item          *nlri_ti;
    proto_tree          *nlri_tree;
    proto_item          *disting_item;
    proto_tree          *disting_tree;

    int                 total_length;       /* length of the entire item */
    int                 length;             /* length of the prefix address, in bytes */
    int                 tmp_length;
    guint               plen;               /* length of the prefix address, in bits */
    guint               labnum;             /* number of labels             */
    guint16             tnl_id;             /* Tunnel Identifier */
    union {
       guint8 addr_bytes[4];
       guint32 addr;
    } ip4addr;                              /* IPv4 address                 */
    address addr;
    struct e_in6_addr   ip6addr;            /* IPv6 address                 */
    guint16             rd_type;            /* Route Distinguisher type     */
    guint16             nlri_type;          /* NLRI Type                    */
    guint16             tmp16;

    wmem_strbuf_t      *stack_strbuf;       /* label stack                  */
    wmem_strbuf_t      *comm_strbuf;

    switch (afi) {

    case AFNUM_INET:
        switch (safi) {

            case SAFNUM_UNICAST:
            case SAFNUM_MULCAST:
            case SAFNUM_UNIMULC:
                total_length = decode_prefix4(tree, pinfo, NULL,hf_addr4, tvb, offset, tag);
                if (total_length < 0)
                    return -1;
                break;

            case SAFNUM_MPLS_LABEL:
                plen =  tvb_get_guint8(tvb, offset);
                stack_strbuf = wmem_strbuf_new_label(wmem_packet_scope());
                labnum = decode_MPLS_stack(tvb, offset + 1, stack_strbuf);

                offset += (1 + labnum * 3);
                if (plen <= (labnum * 3*8)) {
                    proto_tree_add_expert_format(tree, pinfo, &ei_bgp_prefix_length_invalid, tvb, start_offset, 1,
                                        "%s Labeled IPv4 prefix length %u invalid",
                                        tag, plen);
                    return -1;
                }
                plen -= (labnum * 3*8);
                length = tvb_get_ipv4_addr_with_prefix_len(tvb, offset, ip4addr.addr_bytes, plen);
                if (length < 0) {
                    proto_tree_add_expert_format(tree, pinfo, &ei_bgp_prefix_length_invalid, tvb, start_offset, 1,
                                        "%s Labeled IPv4 prefix length %u invalid",
                                        tag, plen + (labnum * 3*8));
                    return -1;
                }

                set_address(&addr, AT_IPv4, 4, ip4addr.addr_bytes);
                prefix_tree = proto_tree_add_subtree_format(tree, tvb, start_offset,
                                         (offset + length) - start_offset,
                                         ett_bgp_prefix, NULL,
                                         "Label Stack=%s IPv4=%s/%u",
                                         wmem_strbuf_get_str(stack_strbuf),
                                         address_to_str(wmem_packet_scope(), &addr), plen);
                proto_tree_add_uint_format(prefix_tree, hf_bgp_prefix_length, tvb, start_offset, 1, plen + labnum * 3 * 8,
                                    "%s Prefix length: %u", tag, plen + labnum * 3 * 8);
                proto_tree_add_string_format(prefix_tree, hf_bgp_label_stack, tvb, start_offset + 1, 3 * labnum, wmem_strbuf_get_str(stack_strbuf),
                                    "%s Label Stack: %s", tag, wmem_strbuf_get_str(stack_strbuf));
                proto_tree_add_ipv4(prefix_tree, hf_addr4, tvb, offset,
                                        length, ip4addr.addr);
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
                comm_strbuf = wmem_strbuf_new_label(wmem_packet_scope());

                switch (tvb_get_ntohs(tvb, offset + 1 + 4)) {
                case BGP_EXT_COM_RT_AS2:
                    wmem_strbuf_append_printf(comm_strbuf, "%u:%u",
                                              tvb_get_ntohs(tvb, offset + 1 + 6),
                                              tvb_get_ntohl(tvb, offset + 1 + 8));
                    break;
                case BGP_EXT_COM_RT_IP4:
                    wmem_strbuf_append_printf(comm_strbuf, "%s:%u",
                                              tvb_ip_to_str(tvb, offset + 1 + 6),
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
                length = tvb_get_ipv4_addr_with_prefix_len(tvb, offset, ip4addr.addr_bytes, plen);
                if (length < 0) {
                    proto_tree_add_expert_format(tree, pinfo, &ei_bgp_prefix_length_invalid, tvb, start_offset, 1,
                                        "%s Tunnel IPv4 prefix length %u invalid",
                                        tag, plen + 16);
                    return -1;
                }
                set_address(&addr, AT_IPv4, 4, ip4addr.addr_bytes);
                prefix_tree = proto_tree_add_subtree_format(tree, tvb, start_offset,
                                         (offset + length) - start_offset,
                                         ett_bgp_prefix, NULL,
                                         "Tunnel Identifier=0x%x IPv4=%s/%u",
                                         tnl_id, address_to_str(wmem_packet_scope(), &addr), plen);

                proto_tree_add_item(prefix_tree, hf_bgp_prefix_length, tvb, start_offset, 1, ENC_BIG_ENDIAN);

                proto_tree_add_item(prefix_tree, hf_bgp_mp_nlri_tnl_id, tvb,
                                    start_offset + 1, 2, ENC_BIG_ENDIAN);
                proto_tree_add_ipv4(prefix_tree, hf_addr4, tvb, offset,
                                        length, ip4addr.addr);
                total_length = 1 + 2 + length; /* length field + Tunnel Id + IPv4 len */
                break;

            case SAFNUM_LAB_VPNUNICAST:
            case SAFNUM_LAB_VPNMULCAST:
            case SAFNUM_LAB_VPNUNIMULC:
                plen =  tvb_get_guint8(tvb, offset);
                stack_strbuf = wmem_strbuf_new_label(wmem_packet_scope());
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

                length = tvb_get_ipv4_addr_with_prefix_len(tvb, offset + 8, ip4addr.addr_bytes, plen);
                if (length < 0) {
                proto_tree_add_expert_format(tree, pinfo, &ei_bgp_prefix_length_invalid, tvb, start_offset, 1,
                                             "%s Labeled VPN IPv4 prefix length %u invalid",
                                             tag, plen + (labnum * 3*8) + 8*8);
                     return -1;
                }
                set_address(&addr, AT_IPv4, 4, ip4addr.addr_bytes);
                prefix_tree = proto_tree_add_subtree_format(tree, tvb, start_offset,
                                                 (offset + 8 + length) - start_offset,
                                                 ett_bgp_prefix, NULL, "BGP Prefix");

                proto_tree_add_item(prefix_tree, hf_bgp_prefix_length, tvb, start_offset, 1, ENC_NA);
                proto_tree_add_string(prefix_tree, hf_bgp_label_stack, tvb, start_offset + 1, 3 * labnum, wmem_strbuf_get_str(stack_strbuf));
                proto_tree_add_string(prefix_tree, hf_bgp_rd, tvb, start_offset + 1 + 3 * labnum, 8, decode_bgp_rd(tvb, offset));

                proto_tree_add_ipv4(prefix_tree, hf_addr4, tvb, offset + 8, length, ip4addr.addr);

                total_length = (1 + labnum * 3 + 8) + length;
                break;

           case SAFNUM_FSPEC_RULE:
           case SAFNUM_FSPEC_VPN_RULE:
             total_length = decode_flowspec_nlri(tree, tvb, offset, afi, pinfo);
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
                total_length = decode_prefix6(tree, pinfo, hf_addr6, tvb, offset, 0, tag);
                if (total_length < 0)
                    return -1;
                break;

            case SAFNUM_MPLS_LABEL:
                plen =  tvb_get_guint8(tvb, offset);
                stack_strbuf = wmem_strbuf_new_label(wmem_packet_scope());
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

                /* XXX - break off IPv6 into its own field */
                set_address(&addr, AT_IPv6, 16, ip6addr.bytes);
                proto_tree_add_string_format(tree, hf_bgp_label_stack, tvb, start_offset,
                                    (offset + length) - start_offset,
                                    wmem_strbuf_get_str(stack_strbuf), "Label Stack=%s, IPv6=%s/%u",
                                    wmem_strbuf_get_str(stack_strbuf),
                                    address_to_str(wmem_packet_scope(), &addr), plen);
                total_length = (1 + labnum * 3) + length;
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
                                    tnl_id, address_to_str(wmem_packet_scope(), &addr), plen);
                proto_tree_add_item(prefix_tree, hf_bgp_prefix_length, tvb, start_offset, 1, ENC_BIG_ENDIAN);

                proto_tree_add_item(prefix_tree, hf_bgp_mp_nlri_tnl_id, tvb,
                                    start_offset + 1, 2, ENC_BIG_ENDIAN);
                proto_tree_add_ipv6(prefix_tree, hf_addr6, tvb, offset, length, &ip6addr);

                total_length = (1 + 2) + length; /* length field + Tunnel Id + IPv4 len */
                break;

            case SAFNUM_LAB_VPNUNICAST:
            case SAFNUM_LAB_VPNMULCAST:
            case SAFNUM_LAB_VPNUNIMULC:
                plen =  tvb_get_guint8(tvb, offset);
                stack_strbuf = wmem_strbuf_new_label(wmem_packet_scope());
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
                                            address_to_str(wmem_packet_scope(), &addr), plen);
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
                                            tvb_ip_to_str(tvb, offset + 2),
                                            tvb_get_ntohs(tvb, offset + 6),
                                            address_to_str(wmem_packet_scope(), &addr), plen);
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
                                            address_to_str(wmem_packet_scope(), &addr), plen);
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
                total_length = decode_flowspec_nlri(tree, tvb, offset, afi, pinfo);
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

                proto_tree_add_string(tree, hf_bgp_vplsad_rd, tvb, offset+2, 8, decode_bgp_rd(tvb, offset+2));
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
                    stack_strbuf = wmem_strbuf_new_label(wmem_packet_scope());
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
    case AFNUM_LINK_STATE:
        nlri_type = tvb_get_ntohs(tvb, offset);
        total_length = tvb_get_ntohs(tvb, offset + 2);
        length = total_length;
        total_length += 4;

        if (safi == SAFNUM_LINK_STATE) {
            ti = proto_tree_add_item(tree, hf_bgp_ls_safi72_nlri, tvb, offset, total_length , ENC_NA);
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
                    offset, pinfo, length);
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
                    offset, pinfo, length);
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
        case BGP_CAPABILITY_GRACEFUL_RESTART:
            if ((clen < 6) && (clen != 2)) {
                expert_add_info_format(pinfo, ti_len, &ei_bgp_cap_len_bad, "Capability length %u too short, must be greater than 6", clen);
                proto_tree_add_item(cap_tree, hf_bgp_cap_unknown, tvb, offset, clen, ENC_NA);
                offset += clen;
            }
            else {
                int eclen = offset + clen;

                static const int * timer_flags[] = {
                    &hf_bgp_cap_gr_timers_restart_flag,
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
                    static const int * flags[] = {
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
            if (clen != 4) {
                expert_add_info_format(pinfo, ti_len, &ei_bgp_cap_len_bad, "Capability length %u is wrong, must be = 4", clen);
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

        case BGP_CAPABILITY_FQDN:{
            guint8 hostname_len, domain_name_len;

            proto_tree_add_item(cap_tree, hf_bgp_cap_fqdn_hostname_len, tvb, offset, 1, ENC_NA);
            hostname_len = tvb_get_guint8(tvb, offset);
            offset += 1;

            proto_tree_add_item(cap_tree, hf_bgp_cap_fqdn_hostname, tvb, offset, hostname_len, ENC_ASCII|ENC_NA);
            offset += hostname_len;

            proto_tree_add_item(cap_tree, hf_bgp_cap_fqdn_domain_name_len, tvb, offset, 1, ENC_NA);
            domain_name_len = tvb_get_guint8(tvb, offset);
            offset += 1;

            proto_tree_add_item(cap_tree, hf_bgp_cap_fqdn_domain_name, tvb, offset, domain_name_len, ENC_ASCII|ENC_NA);
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
dissect_bgp_update_ext_com(proto_tree *parent_tree, tvbuff_t *tvb, guint16 tlen, guint tvb_off)
{
    int             offset=0;
    int             end=0;
    int             i=0;
    guint8          com_type_high_byte;
    guint8          com_stype_low_byte;
    guint8          dscp_flags;
    guint8          esi_label_flag;
    proto_tree      *communities_tree;
    proto_tree      *community_tree;
    proto_item      *communities_item=NULL;
    proto_item      *community_item=NULL;
    gfloat          linkband;                   /* Link bandwidth           */
    guint16         as_num;
    guint16         tunnel_type=0;

    offset = tvb_off ;
    end = tvb_off + tlen ;
    communities_item = proto_tree_add_item(parent_tree, hf_bgp_ext_communities, tvb, offset, tlen, ENC_NA);
    communities_tree = proto_item_add_subtree(communities_item, ett_bgp_extended_communities);
    proto_item_append_text(communities_item, ": (%u communit%s)", tlen/8, plurality(tlen/8, "y", "ies"));
    while (offset < end) {
        com_type_high_byte = tvb_get_guint8(tvb,offset); /* high community type octet */
        com_stype_low_byte = tvb_get_guint8(tvb,offset+1); /* sur type low community type octet */
        community_item = proto_tree_add_item(communities_tree, hf_bgp_ext_community, tvb, offset, 8, ENC_NA);
        community_tree = proto_item_add_subtree(community_item,ett_bgp_extended_community);
        switch (com_type_high_byte) {
            case BGP_EXT_COM_TYPE_HIGH_TR_AS2: /* Transitive Two-Octet AS-Specific Extended Community */
                proto_tree_add_item(community_tree, hf_bgp_ext_com_type_high, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_stype_tr_as2, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_value_as2, tvb, offset+2, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_value_an4, tvb, offset+4, 4, ENC_BIG_ENDIAN);
                proto_item_append_text(community_item, " %s %s: %u%s%d",
                        val_to_str_const(com_type_high_byte, bgpext_com_type_high, "Unknown"),
                        val_to_str_const(com_stype_low_byte, bgpext_com_stype_tr_as2, "Unknown"),
                        tvb_get_ntohs(tvb,offset+2),":",tvb_get_ntohl(tvb,offset+4));
                break;

            case BGP_EXT_COM_TYPE_HIGH_NTR_AS2: /* Non-Transitive Two-Octet AS-Specific Extended Community */
                proto_tree_add_item(community_tree, hf_bgp_ext_com_type_high, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_stype_ntr_as2, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_value_as2, tvb, offset+2, 2, ENC_BIG_ENDIAN);
                if (com_stype_low_byte == BGP_EXT_COM_STYPE_AS2_LBW) {
                    proto_tree_add_item(community_tree, hf_bgp_ext_com_value_link_bw, tvb, offset+4, 4, ENC_BIG_ENDIAN);
                    linkband = tvb_get_ntohieee_float(tvb,offset+4);
                    as_num = tvb_get_ntohs(tvb,offset+2);
                    proto_item_append_text(community_item, ": ASN %u, %.3f Mbps", as_num,linkband*8/1000000);
                } else {
                proto_tree_add_item(community_tree, hf_bgp_ext_com_value_an4, tvb, offset+4, 4, ENC_BIG_ENDIAN);
                proto_item_append_text(community_item, " %s %s: %u%s%d",
                        val_to_str_const(com_type_high_byte, bgpext_com_type_high, "Unknown"),
                        val_to_str_const(com_stype_low_byte, bgpext_com_stype_ntr_as2, "Unknown"),
                        tvb_get_ntohs(tvb,offset+2),":",tvb_get_ntohl(tvb,offset+4));
                }
                break;

            case BGP_EXT_COM_TYPE_HIGH_TR_IP4: /* Transitive IPv4-Address-specific Extended Community */
                proto_tree_add_item(community_tree, hf_bgp_ext_com_type_high, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_stype_tr_IP4, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_value_IP4, tvb, offset+2, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_value_an2, tvb, offset+6, 2, ENC_BIG_ENDIAN);
                proto_item_append_text(community_item, " %s %s: %s%s%u",
                                        val_to_str_const(com_type_high_byte, bgpext_com_type_high, "Unknown"),
                                        val_to_str_const(com_stype_low_byte, bgpext_com_stype_tr_IP4, "Unknown"),
                                        tvb_ip_to_str(tvb, offset+2),":",tvb_get_ntohs(tvb,offset+6));
                break;

            case BGP_EXT_COM_TYPE_HIGH_NTR_IP4: /* Non-Transitive IPv4-Address-specific Extended Community */
                proto_tree_add_item(community_tree, hf_bgp_ext_com_type_high, tvb, offset, 1, ENC_BIG_ENDIAN);
                /* no subtype defined in IANA */
                proto_tree_add_item(community_tree, hf_bgp_ext_com_value_IP4, tvb, offset+2, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_value_an2, tvb, offset+6, 2, ENC_BIG_ENDIAN);
                proto_item_append_text(community_item, " %s: %s%s%u",
                                        val_to_str_const(com_type_high_byte, bgpext_com_type_high, "Unknown"),
                                        tvb_ip_to_str(tvb, offset+2),":",tvb_get_ntohs(tvb,offset+6));
                break;

            case BGP_EXT_COM_TYPE_HIGH_TR_AS4: /* Transitive Four-Octet AS-Specific Extended Community */
                proto_tree_add_item(community_tree, hf_bgp_ext_com_type_high, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_stype_tr_as4, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_value_as4, tvb, offset+2, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_value_an2, tvb, offset+6, 2, ENC_BIG_ENDIAN);
                proto_item_append_text(community_item, " %s %s: %u.%u(%u):%u",
                                        val_to_str_const(com_type_high_byte, bgpext_com_type_high, "Unknown"),
                                        val_to_str_const(com_stype_low_byte, bgpext_com_stype_tr_as4, "Unknown"),
                                        tvb_get_ntohs(tvb,offset+2),tvb_get_ntohs(tvb,offset+4) ,tvb_get_ntohl(tvb,offset+2),
                                        tvb_get_ntohs(tvb,offset+6));
                break;

            case BGP_EXT_COM_TYPE_HIGH_NTR_AS4: /* Non-Transitive Four-Octet AS-Specific Extended Community */
                proto_tree_add_item(community_tree, hf_bgp_ext_com_type_high, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_stype_ntr_as4, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_value_as4, tvb, offset+2, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_value_an2, tvb, offset+6, 2, ENC_BIG_ENDIAN);
                proto_item_append_text(community_item, " %s %s: %u.%u:%u",
                                        val_to_str_const(com_type_high_byte, bgpext_com_type_high, "Unknown"),
                                        val_to_str_const(com_stype_low_byte, bgpext_com_stype_ntr_as4, "Unknown"),
                                        tvb_get_ntohs(tvb,offset+2),tvb_get_ntohs(tvb,offset+4), tvb_get_ntohs(tvb,offset+6));
                break;

            case BGP_EXT_COM_TYPE_HIGH_TR_OPAQUE: /* Transitive Opaque Extended Community */
                proto_tree_add_item(community_tree, hf_bgp_ext_com_type_high, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_stype_tr_opaque, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                switch (com_stype_low_byte) {
                    case BGP_EXT_COM_STYPE_OPA_OSPF:
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_value_IP4, tvb, offset+2, 4, ENC_BIG_ENDIAN);
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_value_ospf_rtype, tvb, offset+6, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_value_ospf_rtype_option, tvb, offset+7, 1, ENC_BIG_ENDIAN);
                        proto_item_append_text(community_item, " Area: %s, Type: %s", tvb_ip_to_str(tvb,offset+2),
                                               val_to_str_const(tvb_get_guint8(tvb,offset+6),
                                               bgpext_com_ospf_rtype, "Unknown"));
                        break;
                    case BGP_EXT_COM_STYPE_OPA_ENCAP:
                        tunnel_type = tvb_get_ntohs(tvb,offset+6);
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_value_unknown32, tvb, offset+2, 4, ENC_BIG_ENDIAN);
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_tunnel_type, tvb, offset+6, 2, ENC_BIG_ENDIAN);
                        proto_item_append_text(community_item, " %s %s: %s",
                                                val_to_str_const(com_type_high_byte, bgpext_com_type_high, "Unknown"),
                                                val_to_str_const(com_stype_low_byte, bgpext_com_stype_tr_opaque, "Unknown"),
                                                val_to_str_const(tunnel_type, bgpext_com_tunnel_type, "Unknown"));
                        break;
                    case BGP_EXT_COM_STYPE_OPA_COLOR:
                    case BGP_EXT_COM_STYPE_OPA_DGTW:
                    default:
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_value_unknown16, tvb, offset+2, 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_value_unknown32, tvb, offset+4, 4, ENC_BIG_ENDIAN);
                        proto_item_append_text(community_item, " %s %s: 0x%02x 0x%04x",
                                                val_to_str_const(com_type_high_byte, bgpext_com_type_high, "Unknown"),
                                                val_to_str_const(com_stype_low_byte, bgpext_com_stype_tr_opaque, "Unknown"),
                                                tvb_get_ntohs(tvb,offset+2) ,tvb_get_ntohl(tvb,offset+4));
                        break;
                }
                break;

            case BGP_EXT_COM_TYPE_HIGH_NTR_OPAQUE: /* Non-Transitive Opaque Extended Community */
                proto_tree_add_item(community_tree, hf_bgp_ext_com_type_high, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_stype_ntr_opaque, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_value_unknown16, tvb, offset+2, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_value_unknown32, tvb, offset+6, 2, ENC_BIG_ENDIAN);
                proto_item_append_text(community_item, " %s %s: 0x%02x 0x%04x",
                                            val_to_str_const(com_type_high_byte, bgpext_com_type_high, "Unknown"),
                                            val_to_str_const(com_stype_low_byte, bgpext_com_stype_ntr_opaque, "Unknown"),
                                            tvb_get_ntohs(tvb,offset+2) ,tvb_get_ntohl(tvb,offset+4));
                break;

            case BGP_EXT_COM_TYPE_HIGH_TR_QOS: /* QoS Marking [Thomas_Martin_Knoll] */
            case BGP_EXT_COM_TYPE_HIGH_NTR_QOS: /* QoS Marking [Thomas_Martin_Knoll] */
                {
                static const int * qos_flags[] = {
                    &hf_bgp_ext_com_qos_flags_remarking,
                    &hf_bgp_ext_com_qos_flags_ignore_remarking,
                    &hf_bgp_ext_com_qos_flags_agg_marking,
                    NULL
                };

                proto_tree_add_item(community_tree, hf_bgp_ext_com_type_high, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_item_append_text(community_item, " %s: 0x%02x",val_to_str(com_type_high_byte, bgpext_com_type_high,
                                        "Unknown type: 0x%02x"),com_type_high_byte);

                proto_tree_add_bitmask(community_tree, tvb, offset, hf_bgp_ext_com_qos_flags, ett_bgp_ext_com_flags, qos_flags, ENC_BIG_ENDIAN);

                proto_tree_add_item(community_tree, hf_bgp_ext_com_qos_set_number, tvb, offset+2, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_qos_tech_type, tvb, offset+3, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_qos_marking_o, tvb, offset+4, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_qos_marking_a, tvb, offset+6, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_qos_default_to_zero, tvb, offset+7, 1, ENC_BIG_ENDIAN);
                }
                break;

            case BGP_EXT_COM_TYPE_HIGH_TR_COS: /* CoS Capability [Thomas_Martin_Knoll] */
                proto_tree_add_item(community_tree, hf_bgp_ext_com_type_high, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_item_append_text(community_item, " %s: 0x%02x",val_to_str(com_type_high_byte, bgpext_com_type_high,
                                    "Unknown type: 0x%02x"),com_type_high_byte);
                for (i=1; i < 8; i++) {
                    static const int * cos_flags[] = {
                        &hf_bgp_ext_com_cos_flags_be,
                        &hf_bgp_ext_com_cos_flags_ef,
                        &hf_bgp_ext_com_cos_flags_af,
                        &hf_bgp_ext_com_cos_flags_le,
                        NULL
                    };

                    proto_tree_add_bitmask(community_tree, tvb, offset+i, hf_bgp_ext_com_cos_flags, ett_bgp_ext_com_flags, cos_flags, ENC_BIG_ENDIAN);
                }
                break;

            case BGP_EXT_COM_TYPE_HIGH_TR_EVPN: /* EVPN (Sub-Types are defined in the "EVPN Extended Community Sub-Types" registry) */
                proto_tree_add_item(community_tree, hf_bgp_ext_com_type_high, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_stype_tr_evpn, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_l2_esi_label_flag, tvb, offset+2, 1, ENC_BIG_ENDIAN);
                esi_label_flag = tvb_get_guint8(tvb, offset+2);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_value_unknown16, tvb, offset+3, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_update_mpls_label_value, tvb, offset+5, 3, ENC_BIG_ENDIAN);
                proto_item_append_text(community_item, " %s %s: %s Label: %u",
                                            val_to_str_const(com_type_high_byte, bgpext_com_type_high, "Unknown"),
                                            val_to_str_const(com_stype_low_byte, bgpext_com_stype_tr_evpn, "Unknown"),
                                            ((esi_label_flag & BGP_EXT_COM_ESI_LABEL_FLAGS) == 0) ? "All active redundancy" : "Single Active redundancy",
                                            tvb_get_ntoh24(tvb,offset+5));
                break;

            case BGP_EXT_COM_TYPE_HIGH_TR_EXP: /* Generic Transitive Experimental Extended Community */
                proto_tree_add_item(community_tree, hf_bgp_ext_com_type_high, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_stype_tr_exp, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                proto_item_append_text(community_item, " %s %s",
                                        val_to_str_const(com_type_high_byte, bgpext_com_type_high, "Unknown"),
                                        val_to_str_const(com_stype_low_byte, bgpext_com_stype_tr_exp, "Unknown"));

                switch (com_stype_low_byte) {
                    case BGP_EXT_COM_STYPE_EXP_F_TR:  /* Flow spec traffic-rate [RFC5575] */
                        proto_tree_add_item(community_tree, hf_bgp_update_path_attribute_community_as,
                                            tvb, offset+2, 2, ENC_BIG_ENDIAN);
                        /* remaining 4 bytes gives traffic rate in IEEE floating point */
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_flow_rate_float, tvb, offset+4, 4, ENC_BIG_ENDIAN);
                        break;

                    case BGP_EXT_COM_STYPE_EXP_F_TA:  /* Flow spec traffic-action [RFC5575] */
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_flow_act_allset, tvb, offset+2, 5, ENC_NA);
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_flow_act_samp_act, tvb, offset+7, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_flow_act_term_act, tvb, offset+7, 1, ENC_BIG_ENDIAN);
                        break;

                    case BGP_EXT_COM_STYPE_EXP_F_RED: /* Flow spec redirect [RFC5575] */
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_value_as2, tvb, offset+2, 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_value_an4, tvb, offset+4, 4, ENC_BIG_ENDIAN);
                        proto_item_append_text(community_item, " RT %u:%u", tvb_get_ntohs(tvb,offset+2), tvb_get_ntohl(tvb,offset+4));
                        break;

                    case BGP_EXT_COM_STYPE_EXP_F_RMARK: /* Flow spec traffic-remarking [RFC5575] */
                        proto_tree_add_item(community_tree, hf_bgp_ext_com_value_fs_remark, tvb, offset+7, 1, ENC_BIG_ENDIAN);
                        dscp_flags = tvb_get_guint8(tvb,offset+7);
                        proto_item_append_text(community_item, "%s", val_to_str_ext_const(dscp_flags,&dscp_vals_ext, "Unknown DSCP"));
                        break;

                    case BGP_EXT_COM_STYPE_EXP_L2:
                        {
                        static const int * com_l2_flags[] = {
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
                }
                break;

            case BGP_EXT_COM_TYPE_HIGH_TR_EXP_FSIP4:
                proto_tree_add_item(community_tree, hf_bgp_ext_com_type_high, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_stype_tr_exp_fs_ip4, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_value_IP4, tvb, offset+2, 4, ENC_NA);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_value_an2, tvb, offset+6, 2, ENC_BIG_ENDIAN);
                proto_item_append_text(community_item, " %s %s: %s%s%u",
                                        val_to_str_const(com_type_high_byte, bgpext_com_type_high, "Unknown"),
                                        val_to_str_const(com_stype_low_byte, bgpext_com_stype_tr_exp_fs_ip4, "Unknown"),
                                        tvb_ip_to_str(tvb, offset+2),":",tvb_get_ntohs(tvb,offset+6));
                break;

            case BGP_EXT_COM_TYPE_HIGH_TR_EXP_FSAS4:
                proto_tree_add_item(community_tree, hf_bgp_ext_com_type_high, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_stype_tr_exp_fs_as4, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_value_as4, tvb, offset+2, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_value_an2, tvb, offset+6, 2, ENC_BIG_ENDIAN);
                proto_item_append_text(community_item, " %s %s: %u.%u(%u):%u",
                                        val_to_str_const(com_type_high_byte, bgpext_com_type_high, "Unknown"),
                                        val_to_str_const(com_stype_low_byte, bgpext_com_stype_tr_exp_fs_as4, "Unknown"),
                                        tvb_get_ntohs(tvb,offset+2),tvb_get_ntohs(tvb,offset+4) ,tvb_get_ntohl(tvb,offset+2),
                                        tvb_get_ntohs(tvb,offset+6));
                break;

            case BGP_EXT_COM_TYPE_HIGH_TR_FLOW: /* Flow spec redirect/mirror to IP next-hop [draft-simpson-idr-flowspec-redirect] */
            default:
                proto_tree_add_item(community_tree, hf_bgp_ext_com_type_high, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_stype_low_unknown, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_value_unknown16, tvb, offset+2, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(community_tree, hf_bgp_ext_com_value_unknown32, tvb, offset+4, 4, ENC_BIG_ENDIAN);
                proto_item_append_text(community_item, " %s : 0x%02x 0x%04x",
                                            val_to_str_const(com_type_high_byte, bgpext_com_type_high, "Unknown"),
                                            tvb_get_ntohs(tvb,offset+2) ,tvb_get_ntohl(tvb,offset+4));
                break;
        }
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

    offset = tvb_off ;
    tunnel_id_len = tlen - 5;

    proto_tree_add_item(parent_tree, hf_bgp_pmsi_tunnel_flags, tvb, offset,
                        1, ENC_BIG_ENDIAN);

    pmsi_tunnel_type_item = proto_tree_add_item(parent_tree, hf_bgp_pmsi_tunnel_type, tvb, offset+1,
                                                1, ENC_BIG_ENDIAN);

    proto_tree_add_item(parent_tree, hf_bgp_update_mpls_label_value_20bits, tvb, offset+2, 3, ENC_BIG_ENDIAN);

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
                                tvb_get_ntohs(tvb, offset+11), tvb_ip_to_str(tvb, offset+13));
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
                                       tvb_ip_to_str(tvb, offset+9),
                                       tvb_get_ntohl(tvb, offset+14+rn_addr_length));
            } else if (opaque_value_type == PMSI_MLDP_FEC_TYPE_EXT_TYPE) {
                proto_tree_add_item(tunnel_id_tree, hf_bgp_pmsi_tunnel_mldp_fec_el_opa_val_ext_type, tvb, offset+12+rn_addr_length, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tunnel_id_tree, hf_bgp_pmsi_tunnel_mldp_fec_el_opa_val_ext_len, tvb, offset+14+rn_addr_length, 2, ENC_BIG_ENDIAN);
                opaque_value_length = tvb_get_ntohs(tvb, offset+14+rn_addr_length);
                proto_tree_add_item(tunnel_id_tree, hf_bgp_pmsi_tunnel_mldp_fec_el_opa_value_str, tvb, offset+16+rn_addr_length,
                                    opaque_value_length, ENC_ASCII|ENC_NA);
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
                                   tvb_ip_to_str(tvb, offset+5),
                                   tvb_ip_to_str(tvb, offset+9));
            break;
        case PMSI_TUNNEL_PIMSM:
            proto_tree_add_item(tunnel_id_tree, hf_bgp_pmsi_tunnel_pimsm_sender, tvb, offset+5, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(tunnel_id_tree, hf_bgp_pmsi_tunnel_pimsm_pmc_group, tvb, offset+9, 4, ENC_BIG_ENDIAN);
            proto_item_append_text(tunnel_id_item, ": < %s, %s >",
                                   tvb_ip_to_str(tvb, offset+5),
                                   tvb_ip_to_str(tvb, offset+9));
            break;
        case PMSI_TUNNEL_BIDIR_PIM:
            proto_tree_add_item(tunnel_id_tree, hf_bgp_pmsi_tunnel_pimbidir_sender, tvb, offset+5, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(tunnel_id_tree, hf_bgp_pmsi_tunnel_pimbidir_pmc_group, tvb, offset+9, 4, ENC_BIG_ENDIAN);
            proto_item_append_text(tunnel_id_item, ": < %s, %s >",
                                   tvb_ip_to_str(tvb, offset+5),
                                   tvb_ip_to_str(tvb, offset+9));
            break;
        case PMSI_TUNNEL_INGRESS:
            proto_tree_add_item(tunnel_id_tree, hf_bgp_pmsi_tunnel_ingress_rep_addr, tvb, offset+5, 4, ENC_BIG_ENDIAN);
            proto_item_append_text(tunnel_id_item, ": tunnel end point -> %s",
                                   tvb_ip_to_str(tvb, offset+5));
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
static void
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
    proto_item    *attr_len_item;
    proto_item    *aigp_type_item;
    proto_tree    *subtree2;                  /* path attribute subtree   */
    proto_tree    *subtree3;                  /* subtree for attributes   */
    proto_tree    *subtree4;                  /* subtree for attributes   */
    proto_tree    *subtree5;                  /* subtree for attributes   */
    proto_tree    *subtree6;                  /* subtree for attributes   */
    proto_tree    *attr_set_subtree;          /* subtree for attr_set     */
    proto_tree    *as_path_segment_tree;      /* subtree for AS_PATH segments */
    gint          number_as_segment=0;        /* Number As segment        */
    proto_tree    *communities_tree;          /* subtree for COMMUNITIES  */
    proto_tree    *community_tree;            /* subtree for a community  */
    proto_tree    *cluster_list_tree;         /* subtree for CLUSTER_LIST */
    int           i=0, j, k;                  /* tmp                      */
    guint8        type=0;                     /* AS_PATH segment type     */
    guint8        length=0;                   /* AS_PATH segment length   */
    wmem_strbuf_t *junk_emstr;                /* tmp                      */
    guint32       aggregator_as;
    guint16       ssa_type;                   /* SSA T + Type */
    guint16       ssa_len;                    /* SSA TLV Length */
    guint8        ssa_v3_len;                 /* SSA L2TPv3 Cookie Length */
    guint16       encaps_tunnel_type;         /* Encapsulation Tunnel Type */
    guint16       encaps_tunnel_len;          /* Encapsulation TLV Length */
    guint8        encaps_tunnel_subtype;      /* Encapsulation Tunnel Sub-TLV Type */
    guint8        encaps_tunnel_sublen;       /* Encapsulation TLV Sub-TLV Length */
    guint8        aigp_type;                  /* AIGP TLV type from AIGP attribute */

    o = tvb_off;
    junk_emstr = wmem_strbuf_new_label(wmem_packet_scope());

    while (i < path_attr_len) {
        proto_item *ti_pa, *ti_flags;
        int     off;
        guint16 alen, aoff, tlen, aoff_save;
        guint16 af;
        guint8  saf, snpa;
        guint8  nexthop_len;
        guint8  asn_len = 0;

        static const int * path_flags[] = {
            &hf_bgp_update_path_attribute_flags_optional,
            &hf_bgp_update_path_attribute_flags_transitive,
            &hf_bgp_update_path_attribute_flags_partial,
            &hf_bgp_update_path_attribute_flags_extended_length,
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

        proto_item_append_text(ti_flags,"%s%s%s%s",
                 ((bgpa_flags & BGP_ATTR_FLAG_OPTIONAL) == 0) ? ": Well-known" : ": Optional",
                 ((bgpa_flags & BGP_ATTR_FLAG_TRANSITIVE) == 0) ? ", Non-transitive" : ", Transitive",
                 ((bgpa_flags & BGP_ATTR_FLAG_PARTIAL) == 0) ? ", Complete" : ", Partial",
                 ((bgpa_flags & BGP_ATTR_FLAG_EXTENDED_LENGTH) == 0) ? "" : ", Extended Length");

        proto_tree_add_item(subtree2, hf_bgp_update_path_attribute_type_code, tvb, o + i + 1, 1, ENC_BIG_ENDIAN);

        attr_len_item = proto_tree_add_item(subtree2, hf_bgp_update_path_attribute_length, tvb, o + i + BGP_SIZE_OF_PATH_ATTRIBUTE,
                                            aoff - BGP_SIZE_OF_PATH_ATTRIBUTE, ENC_BIG_ENDIAN);

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
                            proto_tree_add_item(as_path_segment_tree,
                                                hf_bgp_update_path_attribute_as_path_segment_as2,
                                                tvb, q, 2, ENC_BIG_ENDIAN);
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
                    proto_item_append_text(ti_pa, ": %s ", tvb_ip_to_str(tvb, o + i + aoff));
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
                                           tvb_ip_to_str(tvb, o + i + aoff + asn_len));
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
                                            tvb, q - 3 + aoff, 4, ENC_BIG_ENDIAN);
                        proto_item_append_text(ti_pa, "%s ", val_to_str_const(community, community_vals, "Reserved"));
                        proto_item_append_text(ti_communities, "%s ", val_to_str_const(community, community_vals, "Reserved"));
                    }
                    else {
                        ti_community = proto_tree_add_item(communities_tree, hf_bgp_update_path_attribute_community, tvb,
                                                           q - 3 + aoff, 4, ENC_NA);
                        community_tree = proto_item_add_subtree(ti_community,
                                                                ett_bgp_community);
                        proto_tree_add_item(community_tree, hf_bgp_update_path_attribute_community_as,
                                            tvb, q - 3 + aoff, 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(community_tree, hf_bgp_update_path_attribute_community_value,
                                            tvb, q - 1 + aoff, 2, ENC_BIG_ENDIAN);
                        proto_item_append_text(ti_pa, "%u:%u ",tvb_get_ntohs(tvb, q - 3 + aoff),
                                               tvb_get_ntohs(tvb, q -1 + aoff));
                        proto_item_append_text(ti_communities, "%u:%u ",tvb_get_ntohs(tvb, q - 3 + aoff),
                                               tvb_get_ntohs(tvb, q -1 + aoff));
                        proto_item_append_text(ti_community, ": %u:%u ",tvb_get_ntohs(tvb, q - 3 + aoff),
                                               tvb_get_ntohs(tvb, q -1 + aoff));
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
                    proto_item_append_text(ti_pa, ": %s ", tvb_ip_to_str(tvb, o + i + aoff));
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
                proto_tree_add_item(subtree2, hf_bgp_update_path_attribute_mp_reach_nlri_address_family, tvb,
                                    o + i + aoff, 2, ENC_BIG_ENDIAN);
                saf = tvb_get_guint8(tvb, o + i + aoff + 2) ;
                proto_tree_add_item(subtree2, hf_bgp_update_path_attribute_mp_reach_nlri_safi, tvb,
                                    o + i + aoff+2, 1, ENC_BIG_ENDIAN);
                nexthop_len = tvb_get_guint8(tvb, o + i + aoff + 3);
                subtree3 = proto_tree_add_subtree_format(subtree2, tvb, o + i + aoff + 3,
                                                         nexthop_len + 1, ett_bgp_mp_nhna, NULL,
                                                         "Next hop network address (%d byte%s)",
                                                         nexthop_len, plurality(nexthop_len, "", "s"));

                /*
                 * The addresses don't contain lengths, so if we
                 * don't understand the address family type, we
                 * cannot parse the subsequent addresses as we
                 * don't know how long they are.
                 */
                switch (af) {
                    default:
                    proto_tree_add_expert(subtree3, pinfo, &ei_bgp_unknown_afi, tvb, o + i + aoff + 4, nexthop_len);
                    break;

                    case AFNUM_INET:
                    case AFNUM_INET6:
                    case AFNUM_L2VPN:
                    case AFNUM_L2VPN_OLD:
                    case AFNUM_LINK_STATE:

                        j = 0;
                        while (j < nexthop_len) {
                            advance = mp_addr_to_str(af, saf, tvb, o + i + aoff + 4 + j,
                                                     junk_emstr, nexthop_len) ;
                            if (advance == 0) /* catch if this is a unknown AFI type*/
                                break;
                            if (j + advance > nexthop_len)
                                break;
                            proto_tree_add_string(subtree3, hf_bgp_update_path_attribute_mp_reach_nlri_next_hop, tvb,
                                                 o + i + aoff + 4 + j, advance, wmem_strbuf_get_str(junk_emstr));

                            j += advance;
                        }
                        break;
                } /* switch (af) */

                aoff_save = aoff;
                tlen -= nexthop_len + 4;
                aoff += nexthop_len + 4 ;

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

                subtree3 = proto_tree_add_subtree_format(subtree2, tvb, o + i + aoff, tlen,
                                                         ett_bgp_mp_reach_nlri, NULL, "Network layer reachability information (%u byte%s)",
                                                         tlen, plurality(tlen, "", "s"));
                if (tlen)  {
                    if (af != AFNUM_INET && af != AFNUM_INET6 && af != AFNUM_L2VPN && af != AFNUM_LINK_STATE) {
                        proto_tree_add_expert(subtree3, pinfo, &ei_bgp_unknown_afi, tvb, o + i + aoff, tlen);
                    } else {
                        while (tlen > 0) {
                            advance = decode_prefix_MP(subtree3,
                                                       hf_bgp_mp_reach_nlri_ipv4_prefix,
                                                       hf_bgp_mp_reach_nlri_ipv6_prefix,
                                                       af, saf,
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

                subtree3 = proto_tree_add_subtree_format(subtree2, tvb, o + i + aoff + 3,
                                                         tlen - 3, ett_bgp_mp_unreach_nlri, NULL, "Withdrawn routes (%u byte%s)", tlen - 3,
                                                         plurality(tlen - 3, "", "s"));

                aoff_save = aoff;
                tlen -= 3;
                aoff += 3;
                if (tlen > 0) {

                    while (tlen > 0) {
                        advance = decode_prefix_MP(subtree3,
                                                   hf_bgp_mp_unreach_nlri_ipv4_prefix,
                                                   hf_bgp_mp_unreach_nlri_ipv6_prefix,
                                                   af, saf,
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
                    proto_item_append_text(ti, " %s", tvb_ip_to_str(tvb, q-3+aoff));
                    proto_item_append_text(ti_pa, " %s", tvb_ip_to_str(tvb, q-3+aoff));
                    q += 4;
                }

                break;
            case BGPTYPE_EXTENDED_COMMUNITY:
                if (tlen %8 != 0) {
                    expert_add_info_format(pinfo, attr_len_item, &ei_bgp_ext_com_len_bad,
                                           "Community length %u wrong, must be modulo 8", tlen);
                } else {
                    dissect_bgp_update_ext_com(subtree2, tvb, tlen, o+i+aoff);
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
                        encaps_tunnel_sublen = tvb_get_guint8(tvb, q + 1);

                        subtree6 = proto_tree_add_subtree_format(subtree5, tvb, q, encaps_tunnel_sublen + 2, ett_bgp_tunnel_tlv_subtree, NULL, "%s (%u bytes)", val_to_str_const(encaps_tunnel_subtype, subtlv_type, "Unknown"), encaps_tunnel_sublen + 2);

                        proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_type, tvb, q, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_len, tvb, q + 1, 1, ENC_BIG_ENDIAN);

                        switch (encaps_tunnel_subtype) {
                            case TUNNEL_SUBTLV_ENCAPSULATION:
                                if (encaps_tunnel_type == TUNNEL_TYPE_L2TP_OVER_IP) {
                                    proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_session_id, tvb, q + 2, 4, ENC_BIG_ENDIAN);
                                    proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_cookie, tvb, q + 6, encaps_tunnel_sublen - 4, ENC_NA);
                                } else if (encaps_tunnel_type == TUNNEL_TYPE_GRE) {
                                    proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_gre_key, tvb, q + 2, 4, ENC_BIG_ENDIAN);
                                }
                                break;
                            case TUNNEL_SUBTLV_PROTO_TYPE:
                                proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_gre_key, tvb, q + 2, 2, ENC_BIG_ENDIAN);
                                break;
                            case TUNNEL_SUBTLV_COLOR:
                                proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_color_value, tvb, q + 6, 4, ENC_BIG_ENDIAN);
                               break;
                            case TUNNEL_SUBTLV_LOAD_BALANCE:
                                if (encaps_tunnel_type == TUNNEL_TYPE_L2TP_OVER_IP || encaps_tunnel_type == TUNNEL_TYPE_GRE) {
                                    proto_tree_add_item(subtree6, hf_bgp_update_encaps_tunnel_subtlv_lb_block_length, tvb, q + 2, 4, ENC_BIG_ENDIAN);
                                }
                                break;
                            default:
                                break;
                        } /* switch (encaps_tunnel_subtype) */

                        q += 2 + encaps_tunnel_sublen; /* type and length + length of value */
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
                        proto_item_append_text(ti, ": %" G_GINT64_MODIFIER "u", tvb_get_ntoh64(tvb, q+3));
                        proto_item_append_text(ti_pa, ": %" G_GINT64_MODIFIER "u", tvb_get_ntoh64(tvb, q+3));
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

        dissect_bgp_path_attr(subtree, tvb, len-4, o+2, pinfo);

        o += 2 + len;

        /* NLRI */
        len = hlen - o;

        /* parse prefixes */
        if (len > 0) {
            ti = proto_tree_add_item(tree, hf_bgp_update_nlri, tvb, o, len, ENC_NA);
            subtree = proto_item_add_subtree(ti, ett_bgp_nlri);
            end = o + len;
            /* Heuristic to detect if IPv4 prefix are using Path Identifiers */
            if( detect_add_path_prefix4(tvb, o, end) ) {
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
        proto_tree_add_item(tree, hf_bgp_notify_data, tvb, offset, hlen - BGP_MIN_NOTIFICATION_MSG_SIZE, ENC_NA);
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
dissect_bgp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
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
                pinfo->desegment_len = bgp_len - length_remaining;
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
        next_tvb = tvb_new_subset(tvb, offset, length, bgp_len);

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
        { "ORFEntry Sequence", "bgp.route_refresh.orf.entry.sequence", FT_UINT8, BASE_DEC,
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
      /* BGP update */

      { &hf_bgp_update_withdrawn_routes_length,
        { "Withdrawn Routes Length", "bgp.update.withdrawn_routes.length", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_withdrawn_routes,
        { "Withdrawn Routes", "bgp.update.withdrawn_routes", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},

      { &hf_bgp_update_path_attribute_aggregator_as,
        { "Aggregator AS", "bgp.update.path_attribute.aggregator_as", FT_UINT16, BASE_DEC,
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
          TFS(&tfs_optional_wellknown), BGP_ATTR_FLAG_OPTIONAL, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_flags_transitive,
        { "Transitive", "bgp.update.path_attribute.flags.transitive", FT_BOOLEAN, 8,
          TFS(&tfs_transitive_non_transitive), BGP_ATTR_FLAG_TRANSITIVE, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_flags_partial,
        { "Partial", "bgp.update.path_attribute.flags.partial", FT_BOOLEAN, 8,
          TFS(&tfs_partial_complete), BGP_ATTR_FLAG_PARTIAL, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_flags_extended_length,
        { "Length", "bgp.update.path_attribute.flags.extended_length", FT_BOOLEAN, 8,
          TFS(&tfs_extended_regular_length), BGP_ATTR_FLAG_EXTENDED_LENGTH, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_type_code,
        { "Type Code", "bgp.update.path_attribute.type_code", FT_UINT8, BASE_DEC,
          VALS(bgpattr_type), 0x0, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_length,
        { "Length", "bgp.update.path_attribute.length", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_path_attribute_link_state,
        { "Link State", "bgp.update.path_attribute.link_state", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},

      { &hf_bgp_update_path_attribute_mp_reach_nlri_address_family,
        { "Address family identifier (AFI)", "bgp.update.path_attribute.mp_reach_nlri.afi", FT_UINT16, BASE_DEC,
          VALS(afn_vals), 0x0, NULL, HFILL }},
      { &hf_bgp_update_path_attribute_mp_reach_nlri_safi,
        { "Subsequent address family identifier (SAFI)", "bgp.update.path_attribute.mp_reach_nlri.afi", FT_UINT8, BASE_DEC,
          VALS(bgpattr_nlri_safi), 0x0, NULL, HFILL }},
      { &hf_bgp_update_path_attribute_mp_reach_nlri_next_hop,
        { "Next Hop", "bgp.update.path_attribute.mp_reach_nlri.next_hop", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_update_path_attribute_mp_reach_nlri_nbr_snpa,
        { "Number of Subnetwork points of attachment (SNPA)", "bgp.update.path_attribute.mp_reach_nlri.nbr_snpa", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_update_path_attribute_mp_reach_nlri_snpa_length,
        { "SNPA Length", "bgp.update.path_attribute.mp_reach_nlri.snpa_length", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_update_path_attribute_mp_reach_nlri_snpa,
        { "SNPA", "bgp.update.path_attribute.mp_reach_nlri.snpa", FT_BYTES, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},

      { &hf_bgp_update_path_attribute_mp_unreach_nlri_address_family,
        { "Address family identifier (AFI)", "bgp.update.path_attribute.mp_unreach_nlri.afi", FT_UINT16, BASE_DEC,
          VALS(afn_vals), 0x0, NULL, HFILL }},
      { &hf_bgp_update_path_attribute_mp_unreach_nlri_safi,
        { "Subsequent address family identifier (SAFI)", "bgp.update.path_attribute.mp_unreach_nlri.afi", FT_UINT8, BASE_DEC,
          VALS(bgpattr_nlri_safi), 0x0, NULL, HFILL }},

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
          BASE_DEC, NULL, 0xFFFFF0, NULL, HFILL}},
      { &hf_bgp_update_mpls_label_value,
        { "MPLS Label", "bgp.update.path_attribute.mpls_label_value", FT_UINT24,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
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

        /* draft-ietf-idr-aigp-18 */
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

        /* RFC5512 : BGP Encapsulation SAFI and the BGP Tunnel Encapsulation Attribute  */
      { &hf_bgp_update_encaps_tunnel_tlv_len,
        { "length", "bgp.update.encaps_tunnel_tlv_len", FT_UINT16,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_tlv_type,
        { "Type code", "bgp.update.encaps_tunnel_tlv_type", FT_UINT16, BASE_DEC,
          VALS(bgp_attr_tunnel_type), 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_len,
        { "length", "bgp.update.encaps_tunnel_tlv_sublen", FT_UINT8,
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
        { "GRE Key", "bgp.update.encaps_tunnel_tlv_subtlv_gre_key", FT_UINT16,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_color_value,
        { "Color Value", "bgp.update.encaps_tunnel_tlv_subtlv_color_value", FT_UINT32,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_update_encaps_tunnel_subtlv_lb_block_length,
        { "Load-balancing block length", "bgp.update.encaps_tunnel_tlv_subtlv_lb_block_length", FT_UINT16,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},

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
        /* Bgp flow spec nlri and capability */
      { &hf_bgp_flowspec_nlri_t,
        { "FLOW-SPEC nlri", "bgp.flowspec_nlri", FT_BYTES, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
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
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_ext_com_type_high,
        { "Community type high", "bgp.ext_com.type_high", FT_UINT8, BASE_HEX,
          VALS(bgpext_com_type_high), 0x0, "Type high unknown", HFILL }},
      { &hf_bgp_ext_com_stype_low_unknown,
        { "Community subtype low: unknown", "bgp.ext_com.type_low", FT_UINT8, BASE_HEX,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_ext_com_stype_tr_evpn,
        { "Subtype evpn", "bgp.ext_com.stype_tr_evpn", FT_UINT8, BASE_HEX,
          VALS(bgpext_com_stype_tr_evpn), 0x0, "Subtype unknown", HFILL}},
      { &hf_bgp_ext_com_stype_tr_as2,
        { "Subtype as2", "bgp.ext_com.stype_tr_as2", FT_UINT8, BASE_HEX,
          VALS(bgpext_com_stype_tr_as2), 0x0, "Subtype unknown", HFILL}},
      { &hf_bgp_ext_com_stype_ntr_as2,
        { "Subtype non-transitive as2", "bgp.ext_com.stype_ntr_as2", FT_UINT8, BASE_HEX,
          VALS(bgpext_com_stype_ntr_as2), 0x0, "Subtype unknown", HFILL}},
      { &hf_bgp_ext_com_stype_tr_as4,
        { "Subtype as4", "bgp.ext_com.stype_tr_as4", FT_UINT8, BASE_HEX,
          VALS(bgpext_com_stype_tr_as4), 0x0, "Subtype unknown", HFILL}},
      { &hf_bgp_ext_com_stype_ntr_as4,
        { "Subtype non-transitive as4", "bgp.ext_com.stype_ntr_as4", FT_UINT8, BASE_HEX,
          VALS(bgpext_com_stype_ntr_as4), 0x0, "Subtype unknown", HFILL}},
      { &hf_bgp_ext_com_stype_tr_IP4,
        { "Subtype IPv4", "bgp.ext_com.stype_tr_IP4", FT_UINT8, BASE_HEX,
          VALS(bgpext_com_stype_tr_IP4), 0x0, "Subtype unknown", HFILL}},
      { &hf_bgp_ext_com_stype_tr_opaque,
        { "Subtype opaque", "bgp.ext_com.stype_tr_opaque", FT_UINT8, BASE_HEX,
          VALS(bgpext_com_stype_tr_opaque), 0x0, "Subtype unknown", HFILL}},
      { &hf_bgp_ext_com_stype_ntr_opaque,
        { "Subtype opaque", "bgp.ext_com.stype_ntr_opaque", FT_UINT8, BASE_HEX,
          VALS(bgpext_com_stype_ntr_opaque), 0x0, "Subtype unknown", HFILL}},
      { &hf_bgp_ext_com_tunnel_type,
        { "Tunnel types", "bgp.ext_com.tunnel_type", FT_UINT16, BASE_DEC,
          VALS(bgpext_com_tunnel_type), 0x0, "Type unknown", HFILL}},
      { &hf_bgp_ext_com_stype_tr_exp,
        { "Subtype Experimental", "bgp.ext_com.stype_tr_exp", FT_UINT8, BASE_HEX,
          VALS(bgpext_com_stype_tr_exp), 0x0, "Subtype unknown", HFILL}},
      { &hf_bgp_ext_com_stype_tr_exp_fs_ip4,
        { "Subtype Experimental Flow spec", "bgp.ext_com.stype_tr_exp_fs_ip4", FT_UINT8, BASE_HEX,
          VALS(bgpext_com_stype_tr_exp_fs_ip4), 0x0, "Subtype unknown", HFILL}},
      { &hf_bgp_ext_com_stype_tr_exp_fs_as4,
        { "Subtype Experimental Flow spec", "bgp.ext_com.stype_tr_exp_fs_as4", FT_UINT8, BASE_HEX,
          VALS(bgpext_com_stype_tr_exp_fs_as4), 0x0, "Subtype unknown", HFILL}},
      { &hf_bgp_ext_com_value_as2,
        { "Two octets AS specific", "bgp.ext_com.value_as2", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_ext_com_value_as4,
        { "Four octets AS specific", "bgp.ext_com.value_as4", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_ext_com_value_IP4,
        { "IPv4 address specific", "bgp.ext_com.value_IP4", FT_IPv4, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_ext_com_value_an2,
        { "Two octets AN specific", "bgp.ext_com.value_an2", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_ext_com_value_an4,
        { "Four octets AN specific", "bgp.ext_com.value_an4", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_bgp_ext_com_value_link_bw,
        { "Link bandwidth", "bgp.ext_com.value_link_bw", FT_FLOAT, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ext_com_value_ospf_rtype,
        { "OSPF route type", "bgp.ext_com.value_ospf_rtype", FT_UINT8, BASE_DEC,
          VALS(bgpext_com_ospf_rtype), 0x0, "OSPF route type unknown", HFILL}},
      { &hf_bgp_ext_com_value_ospf_rtype_option,
        { "OSPF route option", "bgp.ext_com.value_ospf_rtype_option", FT_BOOLEAN, 8,
          TFS(&tfs_set_notset), BGP_OSPF_RTYPE_METRIC_TYPE, NULL, HFILL }},
      { &hf_bgp_ext_com_value_fs_remark,
        { "Remarking value", "bgp.ext_com.value_fs_dscp", FT_UINT8, BASE_HEX | BASE_EXT_STRING,
          &dscp_vals_ext, BGPNLRI_FSPEC_DSCP_BITMASK, NULL, HFILL }},
      { &hf_bgp_ext_com_value_unknown16,
        { "Two octets Value specific", "bgp.ext_com.value_2octets", FT_UINT16, BASE_HEX,
          NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ext_com_value_unknown32,
        { "Four octets Value specific", "bgp.ext_com.value_4octets", FT_UINT32, BASE_HEX,
          NULL, 0x0, NULL, HFILL}},
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
        { "Aggegation of markins", "bgp.ext_com_qos.flags.agg_marking", FT_BOOLEAN, 8,
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
      /* idr-ls-03 */
      { &hf_bgp_ls_type,
        { "Type", "bgp.ls.type", FT_UINT16, BASE_DEC,
          NULL, 0x0, "BGP-LS message type", HFILL }},
      { &hf_bgp_ls_length,
        { "Length", "bgp.ls.length", FT_UINT16, BASE_DEC,
          NULL, 0x0, "The total length of the message payload in octets", HFILL }},
      { &hf_bgp_ls_safi72_nlri,
        { "Link State SAFI 72 NLRI", "bgp.ls.nlri_safi72", FT_NONE,
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
          BASE_DEC_HEX, NULL, 0xfff, NULL, HFILL}},
      { &hf_bgp_ls_nlri_ospf_route_type,
        { "OSPF Route Type", "bgp.ls.nlri_ospf_route_type", FT_UINT8,
          BASE_DEC, VALS(link_state_prefix_descriptors_ospf_route_type), 0x0, NULL, HFILL}},
      { &hf_bgp_ls_nlri_ip_reachability_prefix_ip,
       { "Reachability prefix", "bgp.ls.nlri_ip_reachability_prefix_ip", FT_IPv4,
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
          STR_ASCII, NULL, 0, NULL, HFILL }},
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
      { &hf_bgp_ls_tlv_igp_router,
        { "IGP Router-ID", "bgp.ls.tlv.igp_router", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
      { &hf_bgp_ls_tlv_igp_router_id,
        { "IGP ID", "bgp.ls.tlv.igp_router_id", FT_BYTES,
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
         STR_ASCII, NULL, 0, NULL, HFILL }},
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
        { "AFI", "bgp.evpn.nlri.rt", FT_UINT8, BASE_DEC,
          VALS(evpnrtypevals), 0x0, "EVPN Route Type", HFILL }},
     { &hf_bgp_evpn_nlri_len,
       { "Length", "bgp.evpn.nlri.len", FT_UINT8,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
     { &hf_bgp_evpn_nlri_rd,
        { "Route Distinguisher", "bgp.evpn.nlri.rd", FT_BYTES,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
     { &hf_bgp_evpn_nlri_esi,
        { "ESI", "bgp.evpn.nlri.esi", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL }},
     { &hf_bgp_evpn_nlri_esi_type,
        { "ESI Type", "bgp.evpn.nlri.esi.type", FT_UINT8,
          BASE_DEC, VALS(evpn_nlri_esi_type), 0x0, "EVPN ESI type", HFILL }},
     { &hf_bgp_evpn_nlri_esi_lacp_mac,
        { "CE LACP system MAC", "bgp.evpn.nlri.esi.lacp_mac", FT_ETHER,
          BASE_NONE, NULL, 0x0, NULL, HFILL }},
     { &hf_bgp_evpn_nlri_esi_portk,
        { "LACP port key", "bgp.evpn.nlri.esi.lacp_portkey", FT_BYTES,
          SEP_SPACE, NULL, 0x0, NULL, HFILL }},
     { &hf_bgp_evpn_nlri_esi_remain,
        { "Remaining bytes", "bgp.evpn.nlri.esi.remaining", FT_BYTES,
          BASE_NONE, NULL, 0x0, NULL, HFILL }},
     { &hf_bgp_evpn_nlri_esi_reserved,
        { "Reserved value all 0xff", "bgp.evpn.nlri.esi.reserved", FT_BYTES,
         BASE_NONE, NULL, 0x0, NULL, HFILL }},
     { &hf_bgp_evpn_nlri_esi_value,
        { "ESI 9 bytes value", "bgp.evpn.nlri.esi.arbitrary_bytes", FT_BYTES,
          SEP_SPACE, NULL, 0x0, NULL, HFILL }},
     { &hf_bgp_evpn_nlri_esi_rb_mac,
        { "ESI root bridge MAC", "bgp.evpn.nlri.esi.root_brige", FT_ETHER,
          BASE_NONE, NULL, 0x0, NULL, HFILL }},
     { &hf_bgp_evpn_nlri_esi_rbprio,
        { "ESI root bridge priority", "bgp.evpn.nlri.esi.rb_prio", FT_BYTES,
          SEP_SPACE, NULL, 0x0, NULL, HFILL }},
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
     { &hf_bgp_evpn_nlri_mpls_ls,
        { "MPLS Label Stack", "bgp.evpn.nlri.mpls_ls", FT_STRING,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
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
          BASE_DEC, NULL, 0x0, NULL, HFILL}}
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
      &ett_bgp_extended_com_fspec_redir,
      &ett_bgp_ext_com_flags,
      &ett_bgp_ext_com_l2_flags,
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
      &ett_bgp_mpls_labels,
      &ett_bgp_pmsi_tunnel_id,
      &ett_bgp_aigp_attr,
    };
    static ei_register_info ei[] = {
        { &ei_bgp_cap_len_bad, { "bgp.cap.length.bad", PI_MALFORMED, PI_ERROR, "Capability length is wrong", EXPFILL }},
        { &ei_bgp_cap_gr_helper_mode_only, { "bgp.cap.gr.helper_mode_only", PI_REQUEST_CODE, PI_CHAT, "Graceful Restart Capability supported in Helper mode only", EXPFILL }},
        { &ei_bgp_notify_minor_unknown, { "bgp.notify.minor_error.unknown", PI_UNDECODED, PI_NOTE, "Unknown notification error", EXPFILL }},
        { &ei_bgp_route_refresh_orf_type_unknown, { "bgp.route_refresh.orf.type.unknown", PI_CHAT, PI_ERROR, "ORFEntry-Unknown", EXPFILL }},
        { &ei_bgp_length_invalid, { "bgp.length.invalid", PI_MALFORMED, PI_ERROR, "Length is invalid", EXPFILL }},
        { &ei_bgp_prefix_length_invalid, { "bgp.prefix_length.invalid", PI_MALFORMED, PI_ERROR, "Prefix length is invalid", EXPFILL }},
        { &ei_bgp_afi_type_not_supported, { "bgp.afi_type_not_supported", PI_PROTOCOL, PI_ERROR, "AFI Type not supported", EXPFILL }},
        { &ei_bgp_unknown_afi, { "bgp.unknown_afi", PI_PROTOCOL, PI_ERROR, "Unknown Address Family", EXPFILL }},
        { &ei_bgp_unknown_safi, { "bgp.unknown_safi", PI_PROTOCOL, PI_ERROR, "Unknown SAFI", EXPFILL }},
        { &ei_bgp_unknown_label_vpn, { "bgp.unknown_label", PI_PROTOCOL, PI_ERROR, "Unknown Label VPN", EXPFILL }},
        { &ei_bgp_ls_error, { "bgp.ls.error", PI_PROTOCOL, PI_ERROR, "Link State error", EXPFILL }},
        { &ei_bgp_ls_warn, { "bgp.ls.warn", PI_PROTOCOL, PI_WARN, "Link State warning", EXPFILL }},
        { &ei_bgp_ext_com_len_bad, { "bgp.ext_com.length.bad", PI_PROTOCOL, PI_ERROR, "Extended community length is wrong", EXPFILL }},
        { &ei_bgp_evpn_nlri_rt4_len_err, { "bgp.evpn.len", PI_MALFORMED, PI_ERROR, "Length is invalid", EXPFILL }},
        { &ei_bgp_evpn_nlri_rt_type_err, { "bgp.evpn.type", PI_MALFORMED, PI_ERROR, "EVPN Route Type is invalid", EXPFILL }},
        { &ei_bgp_evpn_nlri_esi_type_err, { "bgp.evpn.esi_type", PI_MALFORMED, PI_ERROR, "EVPN ESI Type is invalid", EXPFILL }},
        { &ei_bgp_evpn_nlri_rt4_no_ip, { "bgp.evpn.no_ip", PI_PROTOCOL, PI_NOTE, "IP Address: NOT INCLUDED", EXPFILL }},
        { &ei_bgp_attr_pmsi_tunnel_type, { "bgp.attr.pmsi.tunnel_type", PI_PROTOCOL, PI_ERROR, "Unknown Tunnel type", EXPFILL }},
        { &ei_bgp_attr_pmsi_opaque_type, { "bgp.attr.pmsi.opaque_type", PI_PROTOCOL, PI_ERROR, "Unvalid pmsi opaque type", EXPFILL }},
        { &ei_bgp_attr_aigp_type, { "bgp.attr.aigp.type", PI_MALFORMED, PI_NOTE, "Unknown AIGP attribute type", EXPFILL}},
        { &ei_bgp_prefix_length_err, { "bgp.prefix.length", PI_MALFORMED, PI_ERROR, "Unvalid IPv6 prefix length", EXPFILL}},
        { &ei_bgp_attr_as_path_as_len_err, { "bgp.attr.as_path.as_len", PI_UNDECODED, PI_ERROR, "unable to determine 4 or 2 bytes ASN", EXPFILL}}
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
