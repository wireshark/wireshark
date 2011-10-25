/* packet-eigrp.c
 * Routines for EIGRP dissection
 * Copyright 2011, Donnie V Savage <dsavage@cisco.com>
 *
 * Complete re-write and replaces previous file of same name authored by:
 *    Copyright 2009, Jochen Bartl <jochen.bartl@gmail.co
 *    Copyright 2000, Paul Ionescu <paul@acorp.ro>
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
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/guid-utils.h>
#include <epan/addr_resolv.h>
#include <epan/atalk-utils.h>
#include <epan/addr_and_mask.h>
#include <epan/ipproto.h>
#include <epan/tfs.h>
#include <epan/expert.h>
#include <epan/reassemble.h>

#include "packet-ipx.h"
#include "packet-osi.h"

/**
 * EIGRP Header size in bytes
 */
#define EIGRP_HEADER_LENGTH 	20

/**
 * EIGRP Packet Opcodes
 */
#define EIGRP_OPC_UPDATE	1	/*!< packet containing routing information */
#define EIGRP_OPC_REQUEST	2	/*!< sent to request one or more routes */
#define EIGRP_OPC_QUERY		3	/*!< sent when a routing is in active start */
#define EIGRP_OPC_REPLY		4	/*!< sent in response to a query */
#define EIGRP_OPC_HELLO		5	/*!< sent to maintain a peering session */
#define EIGRP_OPC_IPXSAP	6	/*!< IPX SAP information */
#define EIGRP_OPC_PROBE		7	/*!< for test purposes	 */
#define EIGRP_OPC_ACK		8	/*!< acknowledge	 */
#define EIGRP_OPC_STUB		9	/*!< peering operating in restricted mode */
#define EIGRP_OPC_SIAQUERY	10	/*!< QUERY - with relaxed restrictions */
#define EIGRP_OPC_SIAREPLY	11	/*!< REPLY - may contain old routing information */

/**
 * EIGRP TLV Range definitions
 *	PDM		TLV Range
 *	General		0x0000
 *	IPv4		0x0100		** TLVs for one and all
 *	ATALK		0x0200		** legacy
 *	IPX		0x0300		** discontinued
 *	IPv6		0x0400		** legacy
 *	Multiprotocol	0x0600		** wide metrics
 *	MultiTopology	0x00f0		** deprecated
 */
#define EIGRP_TLV_RANGEMASK	0xfff0	/*!< should be 0xff00 - opps	 */
#define EIGRP_TLV_GENERAL	0x0000

/**
 * 1.2 TLV Definitions	** legacy
 * These have been deprecated and should not be used for future packets
 */
#define EIGRP_TLV_IPv4		0x0100		/*!< Classic IPv4 TLV encoding */
#define EIGRP_TLV_ATALK		0x0200		/*!< Classic Appletalk TLV encoding*/
#define EIGRP_TLV_IPX		0x0300		/*!< Classic IPX TLV encoding */
#define EIGRP_TLV_IPv6		0x0400		/*!< Classic IPv6 TLV encoding */

/**
 * 2.0 Multi-Protocol TLV Definitions
 * These have been deprecated and should not be used for future packets
 */
#define EIGRP_TLV_MP		0x0600	/*!< Non-PDM specific encoding */

/**
 * 3.0 TLV Definitions	** deprecated
 * These have been deprecated and should not be used for future packets
 */
#define EIGRP_TLV_MTR		0x00f0		/*!< MTR TLV encoding */

/**
 * TLV type definitions.  Generic (protocol-independent) TLV types are
 * defined here.  Protocol-specific ones are defined elsewhere.
 */
#define EIGRP_TLV_PARAMETER		(EIGRP_TLV_GENERAL | 0x0001)	/*!< eigrp parameters */
#define EIGRP_TLV_AUTH			(EIGRP_TLV_GENERAL | 0x0002)	/*!< authentication */
#define EIGRP_TLV_SEQ			(EIGRP_TLV_GENERAL | 0x0003)	/*!< sequenced packet */
#define EIGRP_TLV_SW_VERSION		(EIGRP_TLV_GENERAL | 0x0004)	/*!< software version */
#define EIGRP_TLV_NEXT_MCAST_SEQ	(EIGRP_TLV_GENERAL | 0x0005)	/*!< */
#define EIGRP_TLV_PEER_STUBINFO		(EIGRP_TLV_GENERAL | 0x0006)	/*!< stub information */
#define EIGRP_TLV_PEER_TERMINATION	(EIGRP_TLV_GENERAL | 0x0007)	/*!< peer termination */
#define EIGRP_TLV_PEER_TIDLIST		(EIGRP_TLV_GENERAL | 0x0008)	/*!< peer sub-topology list */

/**
 * Route Based TLVs
 */
#define EIGRP_TLV_TYPEMASK	0x000f
#define EIGRP_TLV_REQUEST	0x0001
#define EIGRP_TLV_INTERNAL	0x0002
#define EIGRP_TLV_EXTERNAL	0x0003
#define EIGRP_TLV_COMMUNITY	0x0004

/* Legacy TLV formats */
#define EIGRP_TLV_IPv4_REQ	(EIGRP_TLV_IPv4 | EIGRP_TLV_REQUEST)
#define EIGRP_TLV_IPv4_INT	(EIGRP_TLV_IPv4 | EIGRP_TLV_INTERNAL)
#define EIGRP_TLV_IPv4_EXT	(EIGRP_TLV_IPv4 | EIGRP_TLV_EXTERNAL)
#define EIGRP_TLV_IPv4_COM	(EIGRP_TLV_IPv4 | EIGRP_TLV_COMMUNITY)
#define EIGRP_TLV_IPX_INT	(EIGRP_TLV_IPX | EIGRP_TLV_INTERNAL)
#define EIGRP_TLV_IPX_EXT	(EIGRP_TLV_IPX | EIGRP_TLV_EXTERNAL)
#define EIGRP_TLV_IPX_COM	(EIGRP_TLV_IPX | EIGRP_TLV_COMMUNITY)
#define EIGRP_TLV_IPv6_INT	(EIGRP_TLV_IPv6 | EIGRP_TLV_INTERNAL)
#define EIGRP_TLV_IPv6_EXT	(EIGRP_TLV_IPv6 | EIGRP_TLV_EXTERNAL)
#define EIGRP_TLV_IPv6_COM	(EIGRP_TLV_IPv6 | EIGRP_TLV_COMMUNITY)

/* Deprecated TLV formats */
#define EIGRP_TLV_AT_INT	(EIGRP_TLV_ATALK | EIGRP_TLV_INTERNAL)
#define EIGRP_TLV_AT_EXT	(EIGRP_TLV_ATALK | EIGRP_TLV_EXTERNAL)
#define EIGRP_TLV_AT_CBL	(EIGRP_TLV_ATALK | 0x04)
#define EIGRP_TLV_MTR_REQ	(EIGRP_TLV_MTR | EIGRP_TLV_REQUEST)
#define EIGRP_TLV_MTR_INT	(EIGRP_TLV_MTR | EIGRP_TLV_INTERNAL)
#define EIGRP_TLV_MTR_EXT	(EIGRP_TLV_MTR | EIGRP_TLV_EXTERNAL)
#define EIGRP_TLV_MTR_COM	(EIGRP_TLV_MTR | EIGRP_TLV_COMMUNITY)
#define EIGRP_TLV_MTR_TIDLIST	(EIGRP_TLV_MTR | 0x0005)

/* Current "Wide Metric" TLV formats */
#define EIGRP_TLV_MP_REQ	(EIGRP_TLV_MP | EIGRP_TLV_REQUEST)
#define EIGRP_TLV_MP_INT	(EIGRP_TLV_MP | EIGRP_TLV_INTERNAL)
#define EIGRP_TLV_MP_EXT	(EIGRP_TLV_MP | EIGRP_TLV_EXTERNAL)
#define EIGRP_TLV_MP_COM	(EIGRP_TLV_MP | EIGRP_TLV_COMMUNITY)

/**
 * External routes originate from some other protocol - these are them
 */
#define NULL_PROTID	0	/*!< unknown protocol */
#define IGRP1_PROTID	1	/*!< IGRP.. whos your daddy! */
#define IGRP2_PROTID	2	/*!< EIGRP - Just flat out the best */
#define STATIC_PROTID	3	/*!< Staticly configured source */
#define RIP_PROTID	4	/*!< Routing Information Protocol */
#define HELLO_PROTID	5	/*!< Hello? RFC-891 you there? */
#define OSPF_PROTID	6	/*!< OSPF - Open Shortest Path First */
#define ISIS_PROTID	7	/*!< Intermediate System To Intermediate System */
#define EGP_PROTID	8	/*!< Exterior Gateway Protocol */
#define BGP_PROTID	9	/*!< Border Gateway Protocol */
#define IDRP_PROTID	10	/*!< InterDomain Routing Protocol */
#define CONN_PROTID	11	/*!< Connected source */

/**
 *
 * extdata flag field definitions
 */
#define EIGRP_OPAQUE_EXT      0x01   /*!< Route is external */
#define EIGRP_OPAQUE_CD       0x02   /*!< Candidate default route */

/**
 * Address-Family types are taken from:
 *       http://www.iana.org/assignments/address-family-numbers
 * to provide a standards based exchange of AFI information between
 * EIGRP routers.
 */
#define EIGRP_AF_IPv4		1	/*!< IPv4 (IP version 4) */
#define EIGRP_AF_IPv6		2	/*!< IPv6 (IP version 6) */
#define EIGRP_AF_IPX		11	/*!< IPX */
#define EIGRP_AF_ATALK		12	/*!< Appletalk */
#define EIGRP_SF_COMMON		16384	/*!< Cisco Service Family */
#define EIGRP_SF_IPv4		16385	/*!< Cisco IPv4 Service Family */
#define EIGRP_SF_IPv6		16386	/*!< Cisco IPv6 Service Family */

/**
 * Authentication types supported by EIGRP
 */
#define EIGRP_AUTH_TYPE_NONE		0
#define EIGRP_AUTH_TYPE_TEXT		1
#define EIGRP_AUTH_TYPE_MD5		2
#define EIGRP_AUTH_TYPE_MD5_LEN		16
#define EIGRP_AUTH_TYPE_SHA256		3
#define EIGRP_AUTH_TYPE_SHA256_LEN	32

/**
 * opaque flag field definitions
 */
#define EIGRP_OPAQUE_SRCWD    0x01   /*!< Route Source Withdraw */
#define EIGRP_OPAQUE_ACTIVE   0x04   /*!< Route is currently in active state */
#define EIGRP_OPAQUE_REPL     0x08   /*!< Route is replicated from different tableid */

/**
 * pak flag bit field definitions - 0 (none)-7 source priority
 */
#define EIGRP_PRIV_DEFAULT	0x00   /* 0 (none)-7 source priority */
#define EIGRP_PRIV_LOW		0x01
#define EIGRP_PRIV_MEDIUM	0x04
#define EIGRP_PRIV_HIGH		0x07

/**
 * stub bit definitions
 */
#define EIGRP_PEER_ALLOWS_CONNECTED	0x0001
#define EIGRP_PEER_ALLOWS_STATIC	0x0002
#define EIGRP_PEER_ALLOWS_SUMMARY	0x0004
#define EIGRP_PEER_ALLOWS_REDIST	0x0008
#define EIGRP_PEER_ALLOWS_LEAKING	0x0010
#define EIGRP_PEER_ALLOWS_RCVONLY	0x0020

/*
 * Init bit definition. First unicast transmitted Update has this
 * bit set in the flags field of the fixed header. It tells the neighbor
 * to down-load his topology table.
 */
#define EIGRP_INIT_FLAG 0x01

/*
 * CR bit (Conditionally Received) definition in flags field on header. Any
 * packets with the CR-bit set can be accepted by an EIGRP speaker if and
 * only if a previous Hello was received with the SEQUENCE_TYPE TLV present.
 *
 * This allows multicasts to be transmitted in order and reliably at the
 * same time as unicasts are transmitted.
 */
#define EIGRP_CR_FLAG 0x02

/*
 * RS bit.  The Restart flag is set in the hello and the init
 * update packets during the nsf signaling period.  A nsf-aware
 * router looks at the RS flag to detect if a peer is restarting
 * and maintain the adjacency. A restarting router looks at
 * this flag to determine if the peer is helping out with the restart.
 */
#define EIGRP_RS_FLAG 0x04

/*
 * EOT bit.  The End-of-Table flag marks the end of the start-up updates
 * sent to a new peer.  A nsf restarting router looks at this flag to
 * determine if it has finished receiving the start-up updates from all
 * peers.  A nsf-aware router waits for this flag before cleaning up
 * the stale routes from the restarting peer.
 */
#define EIGRP_EOT_FLAG 0x08

/**
 * EIGRP Virtual Router ID
 *
 * Define values to deal with EIGRP virtual router ids.  Virtual
 * router IDs are stored in the upper short of the EIGRP fixed packet
 * header.  The lower short of the packet header continues to be used
 * as asystem number.
 *
 * Virtual Router IDs are PDM-independent.  All PDMs will use
 * VRID_BASE to indicate the 'base' or 'legacy' EIGRP instance.
 * All PDMs need to initialize their vrid to VRID_BASE for compatibility
 * with legacy routers.
 * Once IPv6 supports 'MTR Multicast', it will use the same VRID as
 * IPv4.  No current plans to support VRIDs on IPX. :)
 * Initial usage of VRID is to signal usage of Multicast topology for
 * MTR.
 *
 * VRID_MCAST is a well known constant, other VRIDs will be determined
 * programmatic...
 *
 * With the addition of SAF the VRID space has been divided into two
 * segments 0x0000-0x7fff is for EIGRP and vNets, 0x8000-0xffff is
 * for saf and it's associated vNets.
 */
#define EIGRP_VRID_MASK		0x8001
#define EIGRP_VRID_AF_BASE	0x0000
#define EIGRP_VRID_MCAST_BASE	0x0001
#define EIGRP_VRID_SF_BASE	0x8000

/* Extended Attributes for a destination */
#define EIGRP_ATTR_HDRLEN (2)
#define EIGRP_ATTR_MAXDATA (512)

#define EIGRP_ATTR_NOOP		0	/*!< No-Op used as offset padding */
#define EIGRP_ATTR_SCALED	1	/*!< Scaled metric values */
#define EIGRP_ATTR_TAG		2	/*!< Tag assigned by Admin for dest */
#define EIGRP_ATTR_COMM		3	/*!< Community attribute for dest */
#define EIGRP_ATTR_JITTER	4	/*!< Variation in path delay */
#define EIGRP_ATTR_QENERGY	5	/*!< Non-Active energy usage along path */
#define EIGRP_ATTR_ENERGY	6	/*!< Active energy usage along path */

/*
 * Begin EIGRP-BGP interoperability communities
 */
#define EIGRP_EXTCOMM_SOO_ASFMT		0x0003 /* Site-of-Origin, BGP AS format */
#define EIGRP_EXTCOMM_SOO_ADRFMT	0x0103 /* Site-of-Origin, BGP/EIGRP addr format */

/*
 * EIGRP Specific communities
 */
#define EIGRP_EXTCOMM_EIGRP		0x8800 /* EIGRP route information appended*/
#define EIGRP_EXTCOMM_DAD		0x8801 /* EIGRP AS + Delay           */
#define EIGRP_EXTCOMM_VRHB		0x8802 /* EIGRP Vector: Reliability + Hop + BW */
#define EIGRP_EXTCOMM_SRLM		0x8803 /* EIGRP System: Reserve +Load + MTU   */
#define EIGRP_EXTCOMM_SAR		0x8804 /* EIGRP System: Remote AS + Remote ID  */
#define EIGRP_EXTCOMM_RPM		0x8805 /* EIGRP Remote: Protocol + Metric    */
#define EIGRP_EXTCOMM_VRR		0x8806 /* EIGRP Vecmet: Rsvd + (internal) Routerid */

/* SAF types */
#define EIGRP_SVCDATA_COMPLETE		0x01	/*!< Data is attached */
#define EIGRP_SVCDATA_TRIMMED		0x02	/*!< Data was trimmed from service */

/* SAF Defined Numbers */
#define SAF_SERVICE_ID_CAPMAN	100		/*!< Capabilities Manager */
#define SAF_SERVICE_ID_UC	101		/*!< Unified Communications */
#define SAF_SERVICE_ID_PFR	102		/*!< Performance Routing */

/* Forward declaration we need below (if using proto_reg_handoff...
   as a prefs callback)       */
void proto_reg_handoff_eigrp(void);

/* Initialize the protocol and registered fields */
static int proto_eigrp = -1;

/* header */
static gint hf_eigrp_version = -1;
static gint hf_eigrp_opcode = -1;
static gint hf_eigrp_flags = -1;
static gint hf_eigrp_sequence = -1;
static gint hf_eigrp_acknowledge = -1;
static gint hf_eigrp_vrid = -1;
static gint hf_eigrp_as = -1;
static gint ett_eigrp = -1;

/* packet header flags */
static gint hf_eigrp_flags_init = -1;
static gint hf_eigrp_flags_restart = -1;
static gint hf_eigrp_flags_eot = -1;
static gint hf_eigrp_flags_condrecv = -1;

static gint ett_eigrp_flags = -1;
static const int *eigrp_flag_fields[] = {
    &hf_eigrp_flags_init,
    &hf_eigrp_flags_condrecv,
    &hf_eigrp_flags_restart,
    &hf_eigrp_flags_eot,
    NULL
};

/* tlv */
static gint hf_eigrp_tlv_type = -1;
static gint hf_eigrp_tlv_len = -1;
static gint hf_eigrp_tid = -1;
static gint hf_eigrp_afi = -1;
static gint hf_eigrp_nullpad = -1;

static gint ett_eigrp_tlv = -1;
static gint ett_eigrp_tlv_metric = -1;
static gint ett_eigrp_tlv_attr = -1;
static gint ett_eigrp_tlv_extdata = -1;

/* param */
static gint hf_eigrp_par_k1 = -1;
static gint hf_eigrp_par_k2 = -1;
static gint hf_eigrp_par_k3 = -1;
static gint hf_eigrp_par_k4 = -1;
static gint hf_eigrp_par_k5 = -1;
static gint hf_eigrp_par_k6 = -1;
static gint hf_eigrp_par_holdtime = -1;

/* auth */
static gint hf_eigrp_auth_type = -1;
static gint hf_eigrp_auth_len = -1;
static gint hf_eigrp_auth_keyid = -1;
static gint hf_eigrp_auth_keyseq = -1;
static gint hf_eigrp_auth_digest = -1;

/* seq */
static gint hf_eigrp_seq_addrlen = -1;
static gint hf_eigrp_seq_ipv4addr = -1;
static gint hf_eigrp_seq_ipv6addr = -1;

/* multicast seq */
static gint hf_eigrp_next_mcast_seq = -1;

/* stub flags */
static gint hf_eigrp_stub_flags = -1;
static gint hf_eigrp_stub_flags_connected = -1;
static gint hf_eigrp_stub_flags_static = -1;
static gint hf_eigrp_stub_flags_summary = -1;
static gint hf_eigrp_stub_flags_recvonly = -1;
static gint hf_eigrp_stub_flags_redist = -1;
static gint hf_eigrp_stub_flags_leakmap = -1;

static gint ett_eigrp_stub_flags = -1;
static const int *eigrp_stub_flag_fields[] = {
    &hf_eigrp_stub_flags_connected,
    &hf_eigrp_stub_flags_static,
    &hf_eigrp_stub_flags_summary,
    &hf_eigrp_stub_flags_redist,
    &hf_eigrp_stub_flags_leakmap,
    &hf_eigrp_stub_flags_recvonly,
    NULL
};

/* tid */
static gint hf_eigrp_tidlist = -1;
static gint hf_eigrp_tidlist_flags = -1;
static gint hf_eigrp_tidlist_len = -1;
static gint ett_eigrp_tidlist_flags = -1;

/* 1.2 and 3.0 metric */
static gint hf_eigrp_legacy_metric_delay = -1;
static gint hf_eigrp_legacy_metric_bw = -1;
static gint hf_eigrp_legacy_metric_mtu = -1;
static gint hf_eigrp_legacy_metric_hopcount = -1;
static gint hf_eigrp_legacy_metric_rel = -1;
static gint hf_eigrp_legacy_metric_load = -1;
static gint hf_eigrp_legacy_metric_intag = -1;

/* 3.0 metric */
static gint hf_eigrp_legacy_metric_tag = -1;

/* 2.0 metric */
static gint hf_eigrp_metric_offset = -1;
static gint hf_eigrp_metric_priority = -1;
static gint hf_eigrp_metric_rel = -1;
static gint hf_eigrp_metric_load = -1;
static gint hf_eigrp_metric_mtu = -1;
static gint hf_eigrp_metric_hopcount = -1;
static gint hf_eigrp_metric_reserved = -1;

/* router id*/
static gint hf_eigrp_routerid = -1;

/* protocol dependent module route flags */
static gint hf_eigrp_metric_flags_srcwd = -1;
static gint hf_eigrp_metric_flags_active = -1;
static gint hf_eigrp_metric_flags_repl = -1;
static gint ett_eigrp_metric_flags = -1;

/* extended metrics */
static gint hf_eigrp_attr_opcode = -1;
static gint hf_eigrp_attr_offset = -1;
static gint hf_eigrp_attr_scaled = -1;
static gint hf_eigrp_attr_tag = -1;
static gint hf_eigrp_attr_jitter = -1;
static gint hf_eigrp_attr_qenergy = -1;
static gint hf_eigrp_attr_energy = -1;

/* route external data */
static gint hf_eigrp_extdata_origrid = -1;
static gint hf_eigrp_extdata_as = -1;
static gint hf_eigrp_extdata_tag = -1;
static gint hf_eigrp_extdata_metric = -1;
static gint hf_eigrp_extdata_reserved = -1;
static gint hf_eigrp_extdata_proto = -1;

static gint hf_eigrp_extdata_flag_ext = -1;
static gint hf_eigrp_extdata_flag_cd = -1;
static gint ett_eigrp_extdata_flags = -1;

/* ipv4 address */
static gint hf_eigrp_ipv4_nexthop = -1;
static gint hf_eigrp_ipv4_prefixlen = -1;

/* ipv6 address */
static gint hf_eigrp_ipv6_nexthop = -1;
static gint hf_eigrp_ipv6_prefixlen = -1;

/* ipx address */
static gint hf_eigrp_ipx_nexthop_net = -1;
static gint hf_eigrp_ipx_nexthop_host = -1;
static gint hf_eigrp_ipx_extdata_routerid = -1;
static gint hf_eigrp_ipx_extdata_delay = -1;
static gint hf_eigrp_ipx_extdata_metric = -1;
static gint hf_eigrp_ipx_dest = -1;

/* appletalk address */
static gint hf_eigrp_atalk_routerid = -1;

/* SAF services */
static gint hf_eigrp_saf_service = -1;
static gint hf_eigrp_saf_subservice = -1;
static gint hf_eigrp_saf_guid = -1;

static gint hf_eigrp_saf_reachability_afi = -1;
static gint hf_eigrp_saf_reachability_port = -1;
static gint hf_eigrp_saf_reachability_protocol = -1;
static gint hf_eigrp_saf_reachability_addr_ipv4 = -1;
static gint hf_eigrp_saf_reachability_addr_ipv6 = -1;
static gint hf_eigrp_saf_reachability_addr_hex = -1;
static gint ett_eigrp_saf_reachability = -1;

static gint hf_eigrp_saf_data_length = -1;
static gint hf_eigrp_saf_data_sequence = -1;
static gint hf_eigrp_saf_data_type = -1;

/* some extra handle that might be needed */
static dissector_handle_t ipxsap_handle = NULL;
static dissector_table_t media_type_table = NULL;

static const value_string eigrp_opcode2string[] = {
    { EIGRP_OPC_UPDATE,		"Update" },
    { EIGRP_OPC_REQUEST,	"Request" },
    { EIGRP_OPC_QUERY, 		"Query" },
    { EIGRP_OPC_REPLY, 		"Reply" },
    { EIGRP_OPC_HELLO,		"Hello" },
    { EIGRP_OPC_IPXSAP,		"IPX/SAP Update" },
    { EIGRP_OPC_PROBE,		"Route Probe" },
    { EIGRP_OPC_ACK,		"Hello (Ack)" },
    { EIGRP_OPC_STUB,		"Stub-Info" },
    { EIGRP_OPC_SIAQUERY, 	"SIA-Query" },
    { EIGRP_OPC_SIAREPLY, 	"SIA-Reply" },
    { 0, NULL }
};

static const value_string eigrp_tlv2string[] = {
    /* General TLV formats */
    { EIGRP_TLV_PARAMETER,		"Parameters"},
    { EIGRP_TLV_AUTH,			"Authentication"},
    { EIGRP_TLV_SEQ,			"Sequence"},
    { EIGRP_TLV_SW_VERSION,		"Software Version"},
    { EIGRP_TLV_NEXT_MCAST_SEQ,		"Next multicast sequence"},
    { EIGRP_TLV_PEER_STUBINFO,		"Peer Stub Information"},
    { EIGRP_TLV_PEER_TERMINATION,	"Peer Termination"},
    { EIGRP_TLV_PEER_TIDLIST,		"Peer Topology ID List"},

    /* Legacy TLV formats */
    { EIGRP_TLV_IPv4_INT,		"Internal Route(IPv4)"},
    { EIGRP_TLV_IPv4_EXT,		"External Route(IPv4)"},
    { EIGRP_TLV_IPv4_COM,		"Ext-Community(IPv4)"},
    { EIGRP_TLV_IPv6_INT,		"Internal Route(IPv6)"},
    { EIGRP_TLV_IPv6_EXT,		"External Route(IPv6)"},
    { EIGRP_TLV_IPv6_COM,		"Ext-Community(IPv6)"},
    { EIGRP_TLV_IPX_INT,		"IPX Internal Route(IPX)"},
    { EIGRP_TLV_IPX_EXT,		"IPX External Route(IPX)"},

    /* Deprecated TLV formats */
    { EIGRP_TLV_AT_INT,			"Internal Route(ATALK)"},
    { EIGRP_TLV_AT_EXT,			"External Route(ATALK)"},
    { EIGRP_TLV_AT_CBL,			"Cable Configuration(ATALK)"},
    { EIGRP_TLV_MTR_REQ,		"Request(MTR)"},
    { EIGRP_TLV_MTR_INT,		"Internal Route(MTR)"},
    { EIGRP_TLV_MTR_EXT,		"External Route(MTR)"},
    { EIGRP_TLV_MTR_COM,		"Ext-Community(MTR)"},
    { EIGRP_TLV_MTR_TIDLIST,		"TopologyID List"},

    /* Current "Wide Metric" TLV formats */
    { EIGRP_TLV_MP_REQ,			"Request"},
    { EIGRP_TLV_MP_INT,			"Internal Route"},
    { EIGRP_TLV_MP_EXT,			"External Route"},
    { EIGRP_TLV_MP_COM,			"Ext-Community"},

    { 0, NULL}
};

static const value_string eigrp_proto2string[] = {
    { IGRP1_PROTID,		"IGRP"},
    { IGRP2_PROTID,		"EIGRP"},
    { STATIC_PROTID,		"Static Route"},
    { RIP_PROTID,		"RIP"},
    { HELLO_PROTID,		"Hello"},
    { OSPF_PROTID,		"OSPF"},
    { ISIS_PROTID,		"IS-IS"},
    { EGP_PROTID,		"EGP"},
    { BGP_PROTID,		"BGP"},
    { IDRP_PROTID,		"IDRP"},
    { CONN_PROTID,		"Connected Route"},
    { 0, NULL}
};

static const value_string eigrp_auth2string[] = {
    { EIGRP_AUTH_TYPE_TEXT,	"TEXT"},
    { EIGRP_AUTH_TYPE_MD5,	"MD5"},
    { EIGRP_AUTH_TYPE_SHA256,	"SHA256"},
    { 0, NULL},
};

static const value_string eigrp_vrid2string[] = {
    { EIGRP_VRID_AF_BASE,	"(Address-Family)"},
    { EIGRP_VRID_SF_BASE,	"(Service-Family)"},
    { EIGRP_VRID_MCAST_BASE,	"(Multi-Cast)"},
    { -1, NULL}
};

static const value_string eigrp_afi2string[] = {
    { EIGRP_AF_IPv4,		"IPv4"},
    { EIGRP_AF_IPv6,		"IPv6"},
    { EIGRP_AF_IPX,		"IPX"},
    { EIGRP_AF_ATALK,		"Appletalk"},
    { EIGRP_SF_COMMON,		"Service Family"},
    { EIGRP_SF_IPv4,		"IPv4 Service Family"},
    { EIGRP_SF_IPv6,		"IPv6 Service Family"},
    { -1, NULL}
};

static const value_string eigrp_attr_opcode2string[] = {
    { EIGRP_ATTR_NOOP,		"NO-OP for padding"},
    { EIGRP_ATTR_SCALED,	"Scaled Metric"},
    { EIGRP_ATTR_TAG,		"Admin Tag"},
    { EIGRP_ATTR_COMM,		"Community"},
    { EIGRP_ATTR_JITTER,	"Jitter"},
    { EIGRP_ATTR_QENERGY,	"Non-Active energy"},
    { EIGRP_ATTR_ENERGY,	"Active energy"},
    { 0, NULL}
};

static const value_string eigrp_saf_type2string[] = {
    { EIGRP_SVCDATA_COMPLETE,	"Attached Service Data"},
    { EIGRP_SVCDATA_TRIMMED,	"Trimmed Service Data"},
    { 0, NULL}
};

static const value_string eigrp_saf_srv2string[] = {
    { SAF_SERVICE_ID_CAPMAN,	"Capabilities Manager"},
    { SAF_SERVICE_ID_UC,	"Unified Communications"},
    { SAF_SERVICE_ID_PFR,	"Performance Routing"},
    { 0, NULL}
};

/**
 *@fn void dissect_eigrp_parameter (proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
 *
 *
 * @param[in|out] tree	detail dissection result
 * @param[in] tvb	packet data
 * @param[in] pinfo	general data about the protocol
 * @param[in] ti	protocol item
 *
 * @return void
 *
 * @par
 * Dissect the Parameter TLV, which is used to convey metric weights and the
 * hold time.
 *
 * @usage
 * Note the addition of K6 for the new extended metrics, and does not apply to
 * older TLV packet formats.
 */
static void
dissect_eigrp_parameter (proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
			 proto_item *ti)
{
    int offset = 0;
    guint8 k1, k2, k3, k4, k5;

    k1 = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_eigrp_par_k1, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;
    k2 = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_eigrp_par_k2, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;
    k3 = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_eigrp_par_k3, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;
    k4 = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_eigrp_par_k4, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;
    k5 = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_eigrp_par_k5, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;
    proto_tree_add_item(tree, hf_eigrp_par_k6, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;
    proto_tree_add_item(tree, hf_eigrp_par_holdtime, tvb, offset, 2, ENC_BIG_ENDIAN);

    if (k1 == 255 && k2 == 255 && k3 == 255 && k4 == 255 && k5 == 255) {
	proto_item_append_text(ti, ": Peer Termination");
	expert_add_info_format(pinfo, ti, PI_RESPONSE_CODE, PI_NOTE,
			       "Peer Termination");
    }
}

/**
 *@fn void dissect_eigrp_auth_tlv (proto_tree *tree, tvbuff_t *tvb,
 *				   packet_info *pinfo, proto_item *ti)
 *
 * @param[in|out] tree	detail dissection result
 * @param[in] tvb	packet data
 * @param[in] pinfo	general data about the protocol
 * @param[in] ti	protocol item
 *
 * @return void
 *
 * @par
 * Dissect the Authentication TLV and display digest. Currently MD5 and SHA256
 * HMAC is supported.  For SHA256, a "secret key" with the HMAC-SHA-256
 * password, the source address from which the packet is sent. This combined
 * string is used as the key for hash calculation.
 */
static void
dissect_eigrp_auth_tlv (proto_tree *tree, tvbuff_t *tvb,
			packet_info *pinfo, proto_item *ti)
{
    proto_item *ti_auth_type, *ti_auth_len;
    int offset = 0;
    guint16 auth_type, auth_len;

    /* print out what family we dealing with... */

    auth_type = tvb_get_ntohs(tvb, 0);
    auth_len = tvb_get_ntohs(tvb, 2);

    proto_item_append_text(ti, " %s", val_to_str(auth_type, eigrp_auth2string, ""));

    ti_auth_type = proto_tree_add_item(tree, hf_eigrp_auth_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    ti_auth_len = proto_tree_add_item(tree, hf_eigrp_auth_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_eigrp_auth_keyid, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eigrp_auth_keyseq, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_eigrp_nullpad, tvb, offset, 8, ENC_NA);
    offset += 8;

    switch (auth_type) {
    case EIGRP_AUTH_TYPE_MD5:
	if (EIGRP_AUTH_TYPE_MD5_LEN != auth_len) {
	    expert_add_info_format(pinfo, ti_auth_len, PI_UNDECODED, PI_WARN,
				   "Invalid auth len %u:", auth_len);
	} else {
	    proto_tree_add_item(tree, hf_eigrp_auth_digest, tvb, offset,
				EIGRP_AUTH_TYPE_MD5_LEN, ENC_NA);
	}
	break;

    case EIGRP_AUTH_TYPE_SHA256:
	if (EIGRP_AUTH_TYPE_SHA256_LEN != auth_len) {
	    expert_add_info_format(pinfo, ti_auth_len, PI_UNDECODED, PI_WARN,
				   "Invalid auth len %u:", auth_len);

	} else {
	    proto_tree_add_item(tree, hf_eigrp_auth_digest, tvb, offset,
				EIGRP_AUTH_TYPE_SHA256_LEN, ENC_NA);
	}
	break;

    case EIGRP_AUTH_TYPE_NONE:
    case EIGRP_AUTH_TYPE_TEXT:
    default:
	expert_add_info_format(pinfo, ti_auth_type, PI_UNDECODED, PI_WARN,
			       "Invalid auth type %u:", auth_type);
	break;
    }
}

/**
 *@fn void dissect_eigrp_seq_tlv (proto_tree *tree, tvbuff_t *tvb,
 *				  packet_info *pinfo)
 *
 * @param[in|out] tree	detail dissection result
 * @param[in] tvb	packet data
 * @param[in] pinfo	general data about the protocol
 *
 * @return void
 *
 * @par
 * Dissect the Sequence TLV which consist of the address of peers that must
 * not receive the next multicast packet transmitted.
 */
static void
dissect_eigrp_seq_tlv (proto_tree *tree, tvbuff_t *tvb,
		       packet_info *pinfo)
{
    proto_item *ti_addrlen;
    int offset = 0;
    guint8 addr_len;

    addr_len = tvb_get_guint8(tvb, 0);
    ti_addrlen = proto_tree_add_item(tree, hf_eigrp_seq_addrlen, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    switch (addr_len) {
    case 4:
	/* IPv4 */
	proto_tree_add_item(tree, hf_eigrp_seq_ipv4addr, tvb, offset, addr_len, ENC_BIG_ENDIAN);
	break;
    case 10:
	/* IPX */
	proto_tree_add_text(tree, tvb, offset, addr_len,
			    "IPX Address = %08x.%04x.%04x.%04x",
			    tvb_get_ntohl(tvb, 1), tvb_get_ntohs(tvb, 5),
			    tvb_get_ntohs(tvb, 7), tvb_get_ntohs(tvb, 9));
	break;
    case 16:
	/* IPv6 */
	proto_tree_add_item(tree, hf_eigrp_seq_ipv6addr, tvb, offset, addr_len,
			    ENC_NA);
	break;
    default:
	expert_add_info_format(pinfo, ti_addrlen, PI_MALFORMED, PI_ERROR,
			       "Invalid address length");
    }
}

/**
 *@fn void dissect_eigrp_sw_version (tvbuff_t *tvb, proto_tree *tree,
 *				     proto_item *ti)
 *
 * @param[in|out] tree	detail dissection result
 * @param[in] tvb	packet data
 * @param[in] ti	protocol item
 *
 * @return void
 *
 * @par
 * Dissect Software Version TLV.  The older versions of EIGRP sent the IOS
 * version along with the TLV Version.   When EIGRP "plugins" were created,
 * this as change to send the "Release" of EIGRP to better identify where fixes
 * are present(missing)
 */
static void
dissect_eigrp_sw_version (tvbuff_t *tvb, proto_tree *tree,
			  proto_item *ti)
{
    int offset = 0;
    guint8 ios_rel_major, ios_rel_minor;
    guint8 eigrp_rel_major, eigrp_rel_minor;

    ios_rel_major = tvb_get_guint8(tvb, 0);
    ios_rel_minor = tvb_get_guint8(tvb, 1);
    proto_tree_add_text(tree, tvb, offset, 2, "EIGRP Release: %u.%u",
			ios_rel_major, ios_rel_minor);
    offset += 2;
    proto_item_append_text(ti, ": EIGRP=%u.%u", ios_rel_major, ios_rel_minor);

    eigrp_rel_major = tvb_get_guint8(tvb, 2);
    eigrp_rel_minor = tvb_get_guint8(tvb, 3);
    proto_tree_add_text(tree,tvb,offset, 2, "EIGRP TLV version: %u.%u",
			eigrp_rel_major, eigrp_rel_minor);
    proto_item_append_text(ti, ", TLV=%u.%u",
			   eigrp_rel_major, eigrp_rel_minor);
}

/**
 *@fn void dissect_eigrp_next_mcast_seq (tvbuff_t *tvb, proto_tree *tree,
 *					proto_item *ti)
 *
 * @param[in|out] tree	detail dissection result
 * @param[in] tvb	packet data
 * @param[in] ti	protocol item
 *
 * @return void
 *
 * @par
 * Dissect Next Multicast Sequence TLV, which is part of the Hello with a
 * Sequence TLV;  this gives a two-way binding between the packets and plugs a
 * hole where a multicast could be received  by the wrong peers (due to a
 * string of lost packets).
 */
static void
dissect_eigrp_next_mcast_seq (tvbuff_t *tvb, proto_tree *tree,
			      proto_item *ti)
{
    proto_tree_add_item(tree, hf_eigrp_next_mcast_seq, tvb, 0, 4,
			ENC_BIG_ENDIAN);
    proto_item_append_text(ti, ": %u", tvb_get_ntohl(tvb, 0));
}

/**
 *@fn void dissect_eigrp_peer_stubinfo (tvbuff_t *tvb, proto_tree *tree)
 *
 *
 * @param[in|out] tree	detail dissection result
 * @param[in] tvb	packet data
 * @param[in] pinfo	general data about the protocol
 * @param[in] ti	protocol item
 * @param[out] None
 *
 * @return void
 *
 * @par
 * Dissect the PEER STUB TLV which contains the route types which the Peer will
 * advertise. This is used to suppress QUERYs from being sent to the Peer
 */
static void
dissect_eigrp_peer_stubinfo (tvbuff_t *tvb, proto_tree *tree)
{
    proto_tree_add_bitmask(tree, tvb, 0, hf_eigrp_stub_flags, ett_eigrp_stub_flags,
			   eigrp_stub_flag_fields, ENC_BIG_ENDIAN);
}

/**
 *@fn void dissect_eigrp_peer_termination (packet_info *pinfo, proto_item *ti)
 *
 * @param[in] pinfo	general data about the protocol
 * @param[in] ti	protocol item
 * @param[out] None
 *
 * @return void
 *
 * @par
 * Dissect Peer Termination TLV.  This TLV has no parameters and is used to
 * signal an adjacency should be tore down
 */
static void
dissect_eigrp_peer_termination (packet_info *pinfo, proto_item *ti)
{
    expert_add_info_format(pinfo, ti, PI_RESPONSE_CODE, PI_NOTE, "Peer Termination (Graceful Shutdown)");
}

/**
 *@fn void dissect_eigrp_peer_tidlist (proto_tree *tree, tvbuff_t *tvb)
 *
 * @param[in|out] tree	detail dissection result
 * @param[in] tvb	packet data
 *
 * @return void
 *
 * @par
 *  Dissect the Topology Identifier List TLV.  This TLV was introduced as part
 *  of the "MTR (Multi-Topology Routing) Project to support sub topologies
 *  within a given Autonomous System. The following represents the format of
 *  the TID list
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |            Flags             |         Length                 |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |        Variable Length TID (two bytes) list                   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static void
dissect_eigrp_peer_tidlist (proto_tree *tree, tvbuff_t *tvb)
{
    proto_item *sub_ti;
    int offset = 0;
    guint16 size, tid ;

    proto_tree_add_item(tree, hf_eigrp_tidlist_flags, tvb, offset, 2,
			ENC_BIG_ENDIAN);
    offset += 2;

    size = tvb_get_ntohs(tvb, offset) / 2;
    proto_tree_add_item(tree, hf_eigrp_tidlist_len, tvb, offset, 2,
			ENC_BIG_ENDIAN);
    offset += 2;

    sub_ti = proto_tree_add_item(tree, hf_eigrp_tidlist, tvb, offset,
				 (size * 2), ENC_BIG_ENDIAN);
    for (; size ; size--) {
	tid = tvb_get_ntohs(tvb, offset);
	proto_item_append_text(sub_ti, " %u", tid);
	offset += 2;
    }
}

/**
 *@fn int dissect_eigrp_extdata_flags (proto_tree *tree, tvbuff_t *tvb, int offset)
 *
 * @param[in|out] tree	detail dissection result
 * @param[in] tvb	packet data
 * @param[in] offset	current byte offset in packet being processed
 *
 * @return int		number of bytes process
 *
 * @par
 * Dissect the Flags field in the external data section of an external
 * route.The following represents the format of the bit field
 *
 *    7 6 5 4 3 2 1 0
 *   +-+-+-+-+-+-+-+-+
 *   |   Flags       |
 *   +-+-+-+-+-+-+-+-+
 *                | |
 *                | +- Route is External *not used*
 *                +--- Route is Candidate Default
 */
static int
dissect_eigrp_extdata_flags (proto_tree *tree, tvbuff_t *tvb, int offset)
{
    proto_item *sub_ti;
    proto_tree *sub_tree;
    tvbuff_t *sub_tvb;

    /* Decode the route flags field */
    sub_ti = proto_tree_add_text(tree, tvb, offset, 1, "External Flags");
    sub_tree = proto_item_add_subtree(sub_ti, ett_eigrp_extdata_flags);
    sub_tvb = tvb_new_subset(tvb, offset, 1, -1);

    proto_tree_add_item(sub_tree, hf_eigrp_extdata_flag_ext, sub_tvb, 0, 1,
			ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_eigrp_extdata_flag_cd, sub_tvb, 0, 1,
			ENC_BIG_ENDIAN);

    offset += 1;
    return(offset);
}

/**
 *@fn int dissect_eigrp_metric_flags (proto_tree *tree, tvbuff_t *tvb, int offset, int limit)
 *
 * @param[in|out] tree	detail dissection result
 * @param[in] tvb	packet data
 * @param[in] offset	current byte offset in packet being processed
 * @param[in] limit	maximum number of bytes which can be process
 *
 * @return int		number of bytes process
 *
 * @par
 * Dissect Protocol Dependent Module (PDM) Flags field in the route metric
 * section of an internal and external route. The following represents the
 * format of the bit field
 *
 *       MSB             LSB
 *    7 6 5 4 3 2 1 0 7 6 5 4 3 2 1 0
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   Flags       |    MP Flags   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *              | | |
 *              | | +- Route is Replicated
 *              | +--- Route is Active
 *              +----- Source Withdraw
 */
static int
dissect_eigrp_metric_flags (proto_tree *tree, tvbuff_t *tvb, int offset, int limit)
{
    proto_item *sub_ti;
    proto_tree *sub_tree;
    tvbuff_t *sub_tvb;

    /* Decode the route flags field */
    sub_ti = proto_tree_add_text(tree, tvb, offset, limit, "Flags");
    sub_tree = proto_item_add_subtree(sub_ti, ett_eigrp_metric_flags);
    sub_tvb = tvb_new_subset(tvb, offset, limit, -1);

    /* just care about 'flags' byte, there are no MP flags for now */
    proto_tree_add_item(sub_tree, hf_eigrp_metric_flags_srcwd, sub_tvb, 0, 1,
			ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_eigrp_metric_flags_active, sub_tvb, 0, 1,
			ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_eigrp_metric_flags_repl, sub_tvb, 0, 1,
			ENC_BIG_ENDIAN);

    offset += limit;
    return(offset);
}

/**
 *@fn int dissect_eigrp_ipv4_addr (proto_item *ti, proto_tree *tree, tvbuff_t *tvb,
 *				   packet_info *pinfo, int offset, int unreachable)
 *
 * @param[in|out] tree	detail dissection result
 * @param[in] tvb	packet data
 * @param[in] pinfo	general data about the protocol
 * @param[in] offset	current byte offset in packet being processed
 *
 * @return int		number of bytes process
 *
 * @par
 * Dissect all IPv4 address from offset though the end of the packet
 */
static int
dissect_eigrp_ipv4_addr (proto_item *ti, proto_tree *tree, tvbuff_t *tvb,
			 packet_info *pinfo, int offset, int unreachable)
{
    guint8 ip_addr[4], length;
    int addr_len;
    proto_item *ti_prefixlen, *ti_dst;
    int first = TRUE;

    for (; tvb_length_remaining(tvb, offset) > 0; offset += (1 + addr_len)) {
	length = tvb_get_guint8(tvb, offset);
	addr_len = ipv4_addr_and_mask(tvb, offset + 1, ip_addr, length);

	if (addr_len < 0) {
	    ti_prefixlen = proto_tree_add_item(tree, hf_eigrp_ipv4_prefixlen,
					       tvb, offset, 1, ENC_BIG_ENDIAN);
	    expert_add_info_format(pinfo, ti_prefixlen, PI_UNDECODED, PI_WARN,
				   "Invalid prefix length %u, must be <= 32",
				   length);
	    addr_len = 4; /* assure we can exit the loop */

	} else {
	    proto_tree_add_item(tree, hf_eigrp_ipv4_prefixlen, tvb, offset, 1,
				ENC_BIG_ENDIAN);
	    offset += 1;
	    ti_dst = proto_tree_add_text(tree, tvb, offset, addr_len,
					 "Destination: %s", ip_to_str(ip_addr));

	    /* add it to the top level line */
	    proto_item_append_text(ti,"  %c   %s/%u", first ? '=':',',
				   ip_to_str(ip_addr), length);

	    if (unreachable) {
		expert_add_info_format(pinfo, ti_dst, PI_RESPONSE_CODE, PI_NOTE, "Unreachable");
	    }
	}
	first = FALSE;
    }
    return (offset);
}

/**
 *@fn int dissect_eigrp_ipv6_addr (proto_item *ti, proto_tree *tree, tvbuff_t *tvb,
 *				   packet_info *pinfo, int offset, int unreachable)
 *
 * @param[in|out] tree	detail dissection result
 * @param[in] tvb	packet data
 * @param[in] pinfo	general data about the protocol
 * @param[in] offset	current byte offset in packet being processed
 *
 * @return int		number of bytes process
 *
 * @par
 * Dissect all IPv6 address from offset though the end of the packet
 */
static int
dissect_eigrp_ipv6_addr (proto_item *ti, proto_tree *tree, tvbuff_t *tvb,
			 packet_info *pinfo, int offset, int unreachable)
{
    guint8 length;
    int addr_len;
    struct e_in6_addr addr;
    proto_item *ti_prefixlen, *ti_dst;
    int first = TRUE;

    for (; tvb_length_remaining(tvb, offset) > 0; offset += (1 + addr_len)) {
	length = tvb_get_guint8(tvb, offset);
	addr_len = ipv6_addr_and_mask(tvb, offset + 1, &addr, length);

	if (addr_len < 0) {
	    ti_prefixlen = proto_tree_add_item(tree, hf_eigrp_ipv6_prefixlen,
					       tvb, offset, 1, ENC_BIG_ENDIAN);
	    expert_add_info_format(pinfo, ti_prefixlen, PI_UNDECODED, PI_WARN,
				   "Invalid prefix length %u, must be <= 128",
				   length);
	    addr_len = 16; /* assure we can exit the loop */
	} else {
	    proto_tree_add_item(tree, hf_eigrp_ipv6_prefixlen, tvb, offset, 1,
				ENC_BIG_ENDIAN);
	    offset += 1;

	    if ((length < 128) && (length % 8 == 0)) {
		addr_len++;
	    }

	    ti_dst = proto_tree_add_text(tree, tvb, offset, addr_len,
					 "Destination: %s", ip6_to_str(&addr));

	    /* add it to the top level line */
	    proto_item_append_text(ti,"  %c   %s/%u", first ? '=':',',
				   ip6_to_str(&addr), length);

	    if (unreachable) {
		expert_add_info_format(pinfo, ti_dst, PI_RESPONSE_CODE, PI_NOTE, "Unreachable");
	    }
	}
	first = FALSE;
    }
    return(offset);
}

/**
 *@fn int dissect_eigrp_ipx_addr (proto_item *ti, proto_tree *tree, tvbuff_t *tvb,
 *				  packet_info *pinfo, int offset, int unreachable)
 *
 * @param[in|out] tree	detail dissection result
 * @param[in] tvb	packet data
 * @param[in] pinfo	general data about the protocol
 * @param[in] offset	current byte offset in packet being processed
 *
 * @return int		number of bytes process
 *
 * @par
 * Dissect all IPX address from offset though the end of the packet
 */
static int
dissect_eigrp_ipx_addr (proto_item *ti, proto_tree *tree, tvbuff_t *tvb,
			packet_info *pinfo, int offset, int unreachable)
{
    proto_item *ti_dst;

    ti_dst = proto_tree_add_item(tree, hf_eigrp_ipx_dest, tvb, offset, 4,
				 ENC_NA);

    /* add it to the top level line */
    proto_item_append_text(ti,"  =   %s",
			   ipxnet_to_string(tvb_get_ptr(tvb, offset, 4)));

    if (unreachable) {
	expert_add_info_format(pinfo, ti_dst, PI_RESPONSE_CODE, PI_NOTE,
			       "Unreachable");
    }

    offset +=4;
    return(offset);
}

/**
 *@fn int dissect_eigrp_service (proto_item *ti, proto_tree *tree, tvbuff_t *tvb,
 *			         packet_info *pinfo, int offset)
 *
 * @param[in|out] tree	detail dissection result
 * @param[in] tvb	packet data
 * @param[in] pinfo	general data about the protocol
 * @param[in] ti	protocol item
 * @param[in] offset	current byte offset in packet being processed
 *
 * @return int		number of bytes process
 *
 * @par
 * Dissect all SAF Services from offset though the end of the packet. The
 * following represents the format of  a SAF Service:
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |            Service            |         SubService            |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                             GUID                              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                             GUID(cont)                        |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                             GUID(cont)                        |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                             GUID(cont)                        |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |            Type               |           Length              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |        Reachability AFI       |    Reachability Port          |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |     Reachability Protocol     |    Reachability Addr          |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                      Reachability Addr(cont)                  |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                      Reachability Addr(cont)                  |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                      Reachability Addr(cont)                  |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |    Reachability Addr(cont)    |           Sequence            |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           Sequence(cont)      |\/\/\/    Service Data   \/\/\/|
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
static int
dissect_eigrp_service (proto_item *ti, proto_tree *tree, tvbuff_t *tvb,
		       packet_info *pinfo, int offset)
{
    int afi, length, remaining;
    int sub_offset;
    proto_item *sub_ti, *reach_ti;
    proto_tree *sub_tree, *reach_tree;
    tvbuff_t *sub_tvb, *reach_tvb;
    guint16 service, sub_service;

    remaining = tvb_length_remaining(tvb, offset);
    sub_ti = proto_tree_add_text(tree, tvb, offset, remaining, "SAF Service ");
    sub_tree = proto_item_add_subtree(sub_ti, ett_eigrp_tlv_metric);
    sub_tvb = tvb_new_subset(tvb, offset, remaining, -1);
    sub_offset = 0;

    for (; tvb_length_remaining(sub_tvb, sub_offset) > 0; ) {
	service = tvb_get_ntohs(sub_tvb, sub_offset);
	proto_item_append_text(sub_ti, "%c %s", (sub_offset == 0 ? '=':','),
			       val_to_str(service, eigrp_saf_srv2string, ""));

	sub_service = tvb_get_ntohs(sub_tvb, sub_offset+2);
	proto_item_append_text(ti, "%c %u:%u", (sub_offset == 0 ? '=':','),
			       service, sub_service);

	proto_tree_add_item(sub_tree, hf_eigrp_saf_service, sub_tvb,
			    sub_offset, 2, ENC_BIG_ENDIAN);
	sub_offset += 2;
	proto_tree_add_item(sub_tree, hf_eigrp_saf_subservice, sub_tvb,
			    sub_offset, 2, ENC_BIG_ENDIAN);
	sub_offset += 2;
	proto_tree_add_item(sub_tree, hf_eigrp_saf_guid, sub_tvb,
			    sub_offset, GUID_LEN, ENC_BIG_ENDIAN);
	sub_offset += GUID_LEN;

	proto_tree_add_item(sub_tree, hf_eigrp_saf_data_type, sub_tvb,
			    sub_offset, 2, ENC_BIG_ENDIAN);
	sub_offset += 2;
	length = tvb_get_ntohs(sub_tvb, sub_offset);
	proto_tree_add_item(sub_tree, hf_eigrp_saf_data_length, sub_tvb,
			    sub_offset, 2, ENC_BIG_ENDIAN);
	sub_offset += 2;

	/*
	 * Reachability information
	 */
	reach_ti = proto_tree_add_text(sub_tree, sub_tvb, sub_offset, 22,
				       "Reachability");
	reach_tree = proto_item_add_subtree(reach_ti, ett_eigrp_saf_reachability);
	reach_tvb = tvb_new_subset(sub_tvb, sub_offset, 22, -1);

	afi = tvb_get_ntohs(reach_tvb, 0);
	proto_tree_add_item(reach_tree, hf_eigrp_saf_reachability_afi,
			    reach_tvb, 0, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(reach_tree, hf_eigrp_saf_reachability_port,
			    reach_tvb, 2, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(reach_tree, hf_eigrp_saf_reachability_protocol,
			    reach_tvb, 4, 2, ENC_BIG_ENDIAN);

	switch (afi) {
	case EIGRP_AF_IPv4:
	    proto_tree_add_item(reach_tree, hf_eigrp_saf_reachability_addr_ipv4,
				reach_tvb, 6, 4, ENC_BIG_ENDIAN);
	    proto_tree_add_item(reach_tree, hf_eigrp_nullpad, reach_tvb, 10, 12,
				ENC_NA);
	    break;

	case EIGRP_AF_IPv6:
	    proto_tree_add_item(reach_tree, hf_eigrp_saf_reachability_addr_ipv6,
				reach_tvb, 6, 16, ENC_NA);
	    break;
	default:
	    /* just print zeros... */
	    proto_tree_add_item(reach_tree, hf_eigrp_saf_reachability_addr_hex,
				reach_tvb, 6, 16, ENC_NA);
	    break;
	}
	sub_offset += 22;

	proto_tree_add_item(sub_tree, hf_eigrp_saf_data_sequence, sub_tvb,
			    sub_offset, 4, ENC_BIG_ENDIAN);
	sub_offset += 4;

	if (length > 0) {
	    tvbuff_t *xml_tvb;
	    guint8 *test_string, *tok;

	    /*
	     * Service-Data is usually (but not always) plain text, specifically
	     * XML. If it "looks like" XML (begins with optional white-space
	     * followed by a '<'), try XML. Otherwise, try plain-text.
	     */
	    xml_tvb = tvb_new_subset(sub_tvb, sub_offset, length, length);
	    test_string = tvb_get_ephemeral_string(xml_tvb, 0, (length < 32 ?
								length : 32));
	    tok = strtok(test_string, " \t\r\n");

	    if (tok && tok[0] == '<') {
		/* Looks like XML */
		dissector_try_string(media_type_table, "application/xml",
				     xml_tvb, pinfo, sub_tree);
	    } else {
		/* Try plain text */
		dissector_try_string(media_type_table, "text/plain",
				     xml_tvb, pinfo, sub_tree);
	    }
	}
	sub_offset += length;
    }

    offset += sub_offset;
    return(offset);
}

/**
 *@fn int dissect_eigrp_legacy_metric (proto_tree *tree, tvbuff_t *tvb, int offset)
 *
 * @param[in|out] tree	detail dissection result
 * @param[in] tvb	packet data
 * @param[in] offset	current byte offset in packet being processed
 *
 * @return int		number of bytes process
 *
 * @par
 * Dissect the TLV Versions 1.2 (legacy) and 3.0 (deprecated) metric
 * sections. The following represents the format
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                       Scaled Delay                            |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                    Scaled Bandwidth                           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |         MTU                                    |   Hopcount   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   | Reliability  |      Load     |  Internal Tag   |    Flag      |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
static int
dissect_eigrp_legacy_metric (proto_tree *tree, tvbuff_t *tvb, int offset)
{
    proto_item *sub_ti;
    proto_tree *sub_tree;
    tvbuff_t *sub_tvb;

    sub_ti = proto_tree_add_text(tree, tvb, offset, 16, "Legacy Metric");
    sub_tree = proto_item_add_subtree(sub_ti, ett_eigrp_tlv_metric);
    sub_tvb = tvb_new_subset(tvb, offset, 16, -1);

    proto_tree_add_item(sub_tree, hf_eigrp_legacy_metric_delay, sub_tvb,
			0, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_eigrp_legacy_metric_bw, sub_tvb,
			4, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_eigrp_legacy_metric_mtu, sub_tvb,
			8, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_eigrp_legacy_metric_hopcount, sub_tvb,
			11, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_eigrp_legacy_metric_rel, sub_tvb,
			12, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_eigrp_legacy_metric_load, sub_tvb,
			13, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_eigrp_legacy_metric_intag, sub_tvb,
			14, 1, ENC_BIG_ENDIAN);

    /* Decode the route flags field */
    dissect_eigrp_metric_flags(sub_tree, sub_tvb, 15, 1);

    offset += 16;
    return(offset);
}

/**
 *@fn int dissect_eigrp_ipx_extdata (proto_tree *tree, tvbuff_t *tvb, int offset)
 *
 * @param[in|out] tree	detail dissection result
 * @param[in] tvb	packet data
 * @param[in] offset	current byte offset in packet being processed
 *
 * @return int		number of bytes process
 *
 * @par
 * Dissect the IPX External data for the TLV versions 1.2 and 3.0.
 * The following represents the format
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *                                   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                                   |          Ext RouterID         |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                       Ext Router ID                           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                Ext Autonomous System Number                   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                        Route Tag                              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |  Ext Protocol  | Ext Flags    |     External Metric           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |      External Delay           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static int
dissect_eigrp_ipx_extdata (proto_tree *tree, tvbuff_t *tvb, int offset)
{
    proto_item *sub_ti;
    proto_tree *sub_tree;
    tvbuff_t *sub_tvb;
    int sub_offset = 0;

    sub_ti = proto_tree_add_text(tree, tvb, offset, 20, "External Data");
    sub_tree = proto_item_add_subtree(sub_ti, ett_eigrp_tlv_extdata);
    sub_tvb = tvb_new_subset(tvb, offset, 20, -1);

    /* Decode the external route source info */
    proto_tree_add_item(sub_tree, hf_eigrp_ipx_extdata_routerid, sub_tvb,
			sub_offset, 6, ENC_NA);
    sub_offset += 6;
    proto_tree_add_item(sub_tree, hf_eigrp_extdata_as, sub_tvb,
			sub_offset, 4, ENC_BIG_ENDIAN);
    sub_offset += 4;
    proto_tree_add_item(sub_tree, hf_eigrp_extdata_tag, sub_tvb,
			sub_offset, 4, ENC_BIG_ENDIAN);
    sub_offset += 4;
    proto_tree_add_item(sub_tree, hf_eigrp_extdata_proto, sub_tvb,
			sub_offset, 1, ENC_BIG_ENDIAN);
    sub_offset += 1;

    /* Decode the external route flags */
    dissect_eigrp_extdata_flags(sub_tree, sub_tvb, sub_offset);
    sub_offset += 1;

    /* and the rest of it... */
    proto_tree_add_item(sub_tree, hf_eigrp_ipx_extdata_metric,
			sub_tvb, sub_offset, 2, ENC_BIG_ENDIAN);
    sub_offset += 2;
    proto_tree_add_item(sub_tree, hf_eigrp_ipx_extdata_delay,
			sub_tvb, sub_offset, 2, ENC_BIG_ENDIAN);
    sub_offset += 2;

    offset += sub_offset;
    return(offset);
}

/**
 *@fn int dissect_eigrp_extdata (proto_tree *tree, tvbuff_t *tvb, int offset)
 *
 * @param[in|out] tree	detail dissection result
 * @param[in] tvb	packet data
 * @param[in] offset	current byte offset in packet being processed
 *
 * @return int		number of bytes process
 *
 * @par
 * Dissect the external route data for TLV versions 1.2 and 3.0 for all
 * protocols except IPX. The following represents the format
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                       Ext Router ID                           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                Ext Autonomous System Number                   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                        Route Tag                              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                    External Metric                            |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |         Reserved             |   Ext Protocol  | Ext Flags    |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static int
dissect_eigrp_extdata (proto_tree *tree, tvbuff_t *tvb, int offset)
{
    proto_item *sub_ti;
    proto_tree *sub_tree;
    tvbuff_t *sub_tvb;
    int sub_offset = 0;

    sub_ti = proto_tree_add_text(tree, tvb, offset, 20, "External Data");
    sub_tree = proto_item_add_subtree(sub_ti, ett_eigrp_tlv_extdata);
    sub_tvb = tvb_new_subset(tvb, offset, 20, -1);

    /* Decode the external route source info */
    proto_tree_add_item(sub_tree, hf_eigrp_extdata_origrid, sub_tvb,
			sub_offset, 4, ENC_BIG_ENDIAN);
    sub_offset += 4;
    proto_tree_add_item(sub_tree, hf_eigrp_extdata_as, sub_tvb,
			sub_offset, 4, ENC_BIG_ENDIAN);
    sub_offset += 4;
    proto_tree_add_item(sub_tree, hf_eigrp_extdata_tag, sub_tvb,
			sub_offset, 4, ENC_BIG_ENDIAN);
    sub_offset += 4;
    proto_tree_add_item(sub_tree, hf_eigrp_extdata_metric, sub_tvb,
			sub_offset, 4, ENC_BIG_ENDIAN);
    sub_offset += 4;
    proto_tree_add_item(sub_tree, hf_eigrp_extdata_reserved, sub_tvb,
			sub_offset, 2, ENC_BIG_ENDIAN);
    sub_offset += 2;
    proto_tree_add_item(sub_tree, hf_eigrp_extdata_proto, sub_tvb,
			sub_offset, 1, ENC_BIG_ENDIAN);
    sub_offset += 1;

    /* Decode the external route flags */
    dissect_eigrp_extdata_flags(sub_tree, sub_tvb, sub_offset);
    sub_offset += 1;

    offset += sub_offset;
    return(offset);
}

/**
 *@fn int dissect_eigrp_nexthop (proto_tree *tree, tvbuff_t *tvb, guint16 afi, int offset)
 *
 * @param[in|out] tree	detail dissection result
 * @param[in] tvb	packet data
 * @param[in] afi	IANA address family indicator
 * @param[in] offset	current byte offset in packet being processed
 *
 * @return int		number of bytes process
 *
 * @par
 * Dissect the next hop field which is in the "route TLVs".  This function will
 * handle all the various protocol AFIs and return the appropriate number of
 * bytes processed
 */
static int
dissect_eigrp_nexthop (proto_tree *tree, tvbuff_t *tvb, guint16 afi, int offset)
{
    /* dissect dest information */
    switch (afi) {
    case EIGRP_SF_IPv4:
    case EIGRP_AF_IPv4:
	proto_tree_add_item(tree, hf_eigrp_ipv4_nexthop, tvb, offset, 4,
			    ENC_BIG_ENDIAN);
	offset += 4;
	break;

    case EIGRP_SF_IPv6:
    case EIGRP_AF_IPv6:
	proto_tree_add_item(tree, hf_eigrp_ipv6_nexthop, tvb, offset, 16,
			    ENC_NA);
	offset += 16;
	break;

    case EIGRP_AF_IPX:
	proto_tree_add_item(tree, hf_eigrp_ipx_nexthop_net, tvb, offset, 4,
			    ENC_NA);
	offset += 4;
	proto_tree_add_item(tree, hf_eigrp_ipx_nexthop_host, tvb, offset, 6,
			    ENC_NA);
	offset += 6;
	break;

    case EIGRP_SF_COMMON:
	break;

    default:
	break;
    }

    return(offset);
}

/**
 *@fn void dissect_eigrp_general_tlv (proto_item *ti, proto_tree *tree, tvbuff_t *tvb,
 *				      packet_info *pinfo, guint16 tlv)
 *
 * @param[in|out] tree	detail dissection result
 * @param[in] tvb	packet data
 * @param[in] pinfo	general data about the protocol
 * @param[in] ti	protocol item
 * @param[in] tlv	Specific TLV in to be dissected
 * @param[out] None
 *
 * @return void
 *
 * @par
 * General EIGRP parameters carry EIGRP management information and are not
 * specific to any one routed protocol.
 *
 */
static void
dissect_eigrp_general_tlv (proto_item *ti, proto_tree *tree, tvbuff_t *tvb,
			   packet_info *pinfo, guint16 tlv)
{
    switch (tlv) {
    case EIGRP_TLV_PARAMETER:
	dissect_eigrp_parameter(tree, tvb, pinfo, ti);
	break;
    case EIGRP_TLV_AUTH:
	dissect_eigrp_auth_tlv(tree, tvb, pinfo, ti);
	break;
    case EIGRP_TLV_SEQ:
	dissect_eigrp_seq_tlv(tree, tvb, pinfo);
	break;
    case EIGRP_TLV_SW_VERSION:
	dissect_eigrp_sw_version(tvb, tree, ti);
	break;
    case EIGRP_TLV_NEXT_MCAST_SEQ:
	dissect_eigrp_next_mcast_seq(tvb, tree, ti);
	break;
    case EIGRP_TLV_PEER_STUBINFO:
	dissect_eigrp_peer_stubinfo(tvb, tree);
	break;
    case EIGRP_TLV_PEER_TERMINATION:
	dissect_eigrp_peer_termination(pinfo, ti);
	break;
    case EIGRP_TLV_PEER_TIDLIST:
	dissect_eigrp_peer_tidlist(tree, tvb);
	break;
    default:
	expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_WARN,
			       "Unknown Generic TLV (0x%04x)", tlv);
	break;
    }
}

/**
 *@fn void dissect_eigrp_ipv4_tlv (proto_item *ti, proto_tree *tree, tvbuff_t *tvb,
 *				   packet_info *pinfo, guint16 tlv)
 *
 * @param[in|out] tree	detail dissection result
 * @param[in] tvb	packet data
 * @param[in] pinfo	general data about the protocol
 * @param[in] tlv	Specific TLV in to be dissected
 *
 * @return void
 *
 * @par
 * Dissect the Legacy IPv4 route TLV; handles both the internal and external
 * TLV types; This packet format is being deprecated and replaced with the
 * Multi-Protocol packet formats as of EIGRP Release-8.  This TLV format is used
 * to maintain backward compatibility between older version so EIGRP, "MTR"
 * EIGRP, and current shipping code.
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                      IPv4 Nexthop                             |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                       Scaled Delay                            |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                    Scaled Bandwidth                           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |         MTU                                    |   Hopcount   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   | Reliability  |      Load     |  Internal Tag   |   Flag       |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static void
dissect_eigrp_ipv4_tlv (proto_item *ti, proto_tree *tree, tvbuff_t *tvb,
			packet_info *pinfo, guint16 tlv)
{
    int offset = 0;
    int unreachable = FALSE;

    proto_tree_add_item(tree, hf_eigrp_ipv4_nexthop, tvb, offset, 4,
			ENC_BIG_ENDIAN);
    offset += 4;

    /* dissect external data if needed */
    if ((tlv & EIGRP_TLV_TYPEMASK) == EIGRP_TLV_EXTERNAL) {
	offset = dissect_eigrp_extdata(tree, tvb, offset);
    }

    /* dissect the metric */
    offset = dissect_eigrp_legacy_metric(tree, tvb, offset);

    /* dissect addresses */
    offset = dissect_eigrp_ipv4_addr(ti, tree, tvb, pinfo, offset, unreachable);
}

/**
 *@fn void dissect_eigrp_atalk_tlv (proto_item *ti, proto_tree *tree, tvbuff_t *tvb,
 *				    proto_item *ti, guint16 tlv)
 *
 * @param[in|out] tree	detail dissection result
 * @param[in] tvb	packet data
 * @param[in] pinfo	general data about the protocol
 * @param[in] tlv	Specific TLV in to be dissected
 *
 * @return void
 *
 * @par
 * Dissect the legacy AppleTalk route TLV; handles both the internal and external
 * TLV type.  The following represents the format
 */
static void
dissect_eigrp_atalk_tlv (proto_item *ti, proto_tree *tree, tvbuff_t *tvb,
			 guint16 tlv)
{
    int offset = 0;

    /* cable tlv? */
    if (EIGRP_TLV_AT_CBL == tlv) {
	proto_tree_add_text(tree, tvb, 0, 4, "AppleTalk Cable Range = %u-%u",
			    tvb_get_ntohs(tvb, 0), tvb_get_ntohs(tvb, 2));
	proto_tree_add_item(tree, hf_eigrp_atalk_routerid, tvb, 4, 4,
			    ENC_BIG_ENDIAN);
	proto_item_append_text(ti, ": Cable range= %u-%u, Router ID= %u",
			       tvb_get_ntohs(tvb, 0), tvb_get_ntohs(tvb, 2),
			       tvb_get_ntohl(tvb, 4));

    } else {
	proto_tree_add_text(tree, tvb, offset, 4, "NextHop Address = %u.%u",
			    tvb_get_ntohs(tvb, 0), tvb_get_ntohs(tvb, 2));
	offset += 4;

	/* dissect external data if needed */
	if ((tlv & EIGRP_TLV_TYPEMASK) == EIGRP_TLV_EXTERNAL) {
	    offset = dissect_eigrp_extdata(tree, tvb,offset);
	}

	/* dissect the metric */
	offset = dissect_eigrp_legacy_metric(tree, tvb, offset);

	/* dissect cable range */
	proto_tree_add_text(tree, tvb, offset, 4, "Cable range = %u-%u",
			    tvb_get_ntohs(tvb, 36), tvb_get_ntohs(tvb, 38));
	proto_item_append_text(ti, ": %u-%u",
			       tvb_get_ntohs(tvb, 36), tvb_get_ntohs(tvb, 38));
    }
    return;
}

/**
 *@fn void dissect_eigrp_ipv6_tlv (proto_item *ti, proto_tree *tree, tvbuff_t *tvb,
 *				   packet_info *pinfo, guint16 tlv)
 *
 * @param[in|out] tree	detail dissection result
 * @param[in] tvb	packet data
 * @param[in] pinfo	general data about the protocol
 * @param[in] tlv	Specific TLV in to be dissected
 *
 * @return void
 *
 * @par
 * Dissect the Legacy IPv6 route TLV; handles both the internal and external
 * TLV types; This packet format is being deprecated and replaced with the
 * Multi-Protocol packet formats as of EIGRP Release-8.  This TLV format is used
 * to maintain backward compatibility between older version so EIGRP, "MTR"
 * EIGRP, and current shipping code.
 */
static void
dissect_eigrp_ipv6_tlv (proto_item *ti, proto_tree *tree, tvbuff_t *tvb,
			packet_info *pinfo, guint16 tlv)
{
    int offset = 0;
    int unreachable = FALSE;

    proto_tree_add_item(tree, hf_eigrp_ipv6_nexthop, tvb, offset, 16,
			ENC_NA);
    offset += 16;

    /* dissect external data if needed */
    if ((tlv & EIGRP_TLV_TYPEMASK) == EIGRP_TLV_EXTERNAL) {
	offset = dissect_eigrp_extdata(tree, tvb, offset);
    }

    /* dissect the metric */
    offset = dissect_eigrp_legacy_metric(tree, tvb, offset);

    /* dissect addresses */
    dissect_eigrp_ipv6_addr(ti, tree, tvb, pinfo, offset, unreachable);
    return;
}

/**
 *@fn void dissect_eigrp_ipx_tlv (proto_item *ti, proto_tree *tree, tvbuff_t *tvb,
 *				  packet_info *pinfo, guint16 tlv)
 *
 * @param[in|out] tree	detail dissection result
 * @param[in] tvb	packet data
 * @param[in] pinfo	general data about the protocol
 * @param[in] tlv	Specific TLV in to be dissected
 *
 * @return void
 *
 * @par
 * Dissect the legacy IPX route TLV; handles both the internal and external
 * TLV type.  The following represents the format
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                         Nexthop Net                           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                        Nexthop Host                           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |  Nexthop Host(cont)           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Optional External Data:
 *                                   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                                   |          Ext RouterID         |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                       Ext Router ID                           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                Ext Autonomous System Number                   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                        Route Tag                              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |  Ext Protocol  | Ext Flags    |    External Metric            |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |     External Delay            |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *                                   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                                   |           Scaled Delay        |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           Scaled Delay        |      Scaled Bandwidth         |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |         Scaled Bandwidth      |             MTU               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   MTU(cont)   |    Hopcount   | Reliability   |     Load      |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   | Internal Tag |      Flag      |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *
 */
static void
dissect_eigrp_ipx_tlv (proto_item *ti, proto_tree *tree, tvbuff_t *tvb,
		       packet_info *pinfo, guint16 tlv)
{
    int offset = 0;
    int unreachable = FALSE;

    /* nexthop for route... */
    offset = dissect_eigrp_nexthop(tree, tvb, EIGRP_AF_IPX, offset);

    /* dissect external data if needed */
    if ((tlv & EIGRP_TLV_TYPEMASK) == EIGRP_TLV_EXTERNAL) {
	offset = dissect_eigrp_ipx_extdata(tree, tvb, offset);
    }

    /* dissect the metric */
    offset = dissect_eigrp_legacy_metric(tree, tvb, offset);

    /* dissect addresses */
    offset = dissect_eigrp_ipx_addr(ti, tree, tvb, pinfo, offset, unreachable);
}

/**
 *@fn void dissect_eigrp_ipv4_tlv (proto_item *ti, proto_tree *tree, tvbuff_t *tvb,
 *				   packet_info *pinfo, proto_item *ti, guint16 tlv)
 *
 * @param[in|out] tree	detail dissection result
 * @param[in] tvb	packet data
 * @param[in] pinfo	general data about the protocol
 * @param[in] ti	protocol item
 * @param[in] tlv	Specific TLV in to be dissected
 *
 * @return void
 *
 * @par
 * Dissect the Multi-Topology route TLV; This packet format has been deprecated
 * and replaced with the Multi-Protocol packet formats as of EIGRP Release-8. Of
 * course this means it will be around for a long long while. The following
 * represents the format
 *
 *    1       2                   3   0                   1         1
 *    6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
 *                                   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                                   |           Reserved            |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   Topology Identifier         |       Family Identifier       |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                       Router ID                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                       Route Tag                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                       Scaled Delay                            |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                    Scaled Bandwidth                           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |         MTU                                    |   Hopcount   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   | Reliability  |      Load      |  Internal Tag   |    Flag     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |\/\/\/         NextHop (Family Specific Length)          \/\/\/|
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |\/\/\/          External Route Data (Optional)           \/\/\/|
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |\/\/\/       Destination (Family Specific Length)        \/\/\/|
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
static void
dissect_eigrp_multi_topology_tlv (proto_item *ti, proto_tree *tree, tvbuff_t *tvb,
				  packet_info *pinfo, guint16 tlv)
{
    proto_item *sub_ti;
    guint16 afi;
    int offset = 2;
    int unreachable = FALSE;

    /* tid for you */
    proto_tree_add_item(tree, hf_eigrp_tid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* now its all about the family */
    afi = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_eigrp_afi, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* gota have an id... */
    proto_tree_add_item(tree, hf_eigrp_routerid, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* tag.. your it! */
    proto_tree_add_item(tree, hf_eigrp_legacy_metric_tag, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* dissect the metric */
    offset = dissect_eigrp_legacy_metric(tree, tvb, offset);

    /* dissect nexthop */
    offset = dissect_eigrp_nexthop(tree, tvb, afi, offset);

    /* dissect external data if needed */
    if ((tlv & EIGRP_TLV_TYPEMASK) == EIGRP_TLV_EXTERNAL) {
	if (afi == EIGRP_AF_IPX) {
	    offset = dissect_eigrp_ipx_extdata(tree, tvb, offset);
	} else {
	    offset = dissect_eigrp_extdata(tree, tvb, offset);
	}
    }

    /* dissect dest information */
    switch (afi) {
    case EIGRP_AF_IPv4:
	offset = dissect_eigrp_ipv4_addr(ti, tree, tvb, pinfo, offset, unreachable);
	break;
    case EIGRP_AF_IPv6:
	offset = dissect_eigrp_ipv6_addr(ti, tree, tvb, pinfo, offset, unreachable);
	break;
    case EIGRP_AF_IPX:
	offset = dissect_eigrp_ipx_addr(ti, tree, tvb, pinfo, offset, unreachable);
	break;

    case EIGRP_SF_COMMON:
    case EIGRP_SF_IPv4:
    case EIGRP_SF_IPv6:
	offset = dissect_eigrp_service(ti, tree, tvb, pinfo, offset);
	break;

    default:
	sub_ti = proto_tree_add_text(tree, tvb, offset, -1, "Unknown AFI");
	expert_add_info_format(pinfo, sub_ti, PI_MALFORMED, PI_ERROR, "Unknown AFI");
    }

    return;
}

/**
 *@fn int dissect_eigrp_metric_comm (proto_tree *tree, tvbuff_t *tvb, int offset, int limit)
 *
 * @param[in|out] tree	detail dissection result
 * @param[in] tvb	packet data
 * @param[in] offset	current byte offset in packet being processed
 * @param[in] limit	maximum number of bytes which can be process
 *
 * @return int		number of bytes process
 *
 * @par
 * Dissect extended community attached to metric TLVs to support VPNv4
 * deployments, The following represents the format
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Type high    |  Type low(*)  |                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+          Value                |
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static int
dissect_eigrp_metric_comm (proto_tree *tree, tvbuff_t *tvb, int offset, int limit)
{
    int comm_type;

    while (limit > 0) {
	comm_type = tvb_get_ntohs(tvb, offset);
	offset++;

	switch (comm_type) {
	    /*
	     * Tag for this route. It is present for all EIGRP VPNv4
	     * routes, internal and external
	     */
	case EIGRP_EXTCOMM_EIGRP:
	    proto_tree_add_text(tree, tvb, offset, 8,
				"Type(EIGRP_EXTCOMM_EIGRP): Flag(0x%02x) Tag(%u)",
				tvb_get_ntohs(tvb, 0),
				tvb_get_ntohl(tvb, 2));
	    break;
	case EIGRP_EXTCOMM_VRR:
	    proto_tree_add_text(tree, tvb, offset, 8,
				"Type(EIGRP_EXTCOMM_VRR)): RES(0x%02x) RID(0x%04x)",
				tvb_get_ntohs(tvb, 0),
				tvb_get_ntohl(tvb, 2));
	    break;

	    /*
	     * Vecmetric information for given EIGRP VPNv4 route,
	     * applies to both internal and external
	     */
	case EIGRP_EXTCOMM_DAD:
	    proto_tree_add_text(tree, tvb, offset, 8,
				"Type(EIGRP_EXTCOMM_DAD): AS(%u):SDLY(%u)",
				tvb_get_ntohs(tvb, 0),
				tvb_get_ntohl(tvb, 2));
	    break;
	case EIGRP_EXTCOMM_VRHB:
	    proto_tree_add_text(tree, tvb, offset, 8,
				"Type(EIGRP_EXTCOMM_VRHB): REL(%u) HOP(%u) SBW(%u)",
				tvb_get_guint8(tvb, 0),
				tvb_get_guint8(tvb, 1),
				tvb_get_ntohl(tvb, 2));
	    break;
	case EIGRP_EXTCOMM_SRLM:
	    proto_tree_add_text(tree, tvb, offset, 8,
				"Type(EIGRP_EXTCOMM_SRLM): RES(%u) LOAD(%u) MTU(%u)",
				tvb_get_guint8(tvb, 0),
				tvb_get_guint8(tvb, 1),
				tvb_get_ntohl(tvb, 2));
	    break;

	    /*
	     * External information for given EIGRP VPNv4 route,
	     * applies to only to external routes
	     */
	case EIGRP_EXTCOMM_SAR:
	    proto_tree_add_text(tree, tvb, offset, 8,
				"Type(EIGRP_EXTCOMM_SAR): xAS(%u) xRID(%u)",
				tvb_get_ntohs(tvb, 0),
				tvb_get_ntohl(tvb, 2));
	    break;
	case EIGRP_EXTCOMM_RPM:
	    proto_tree_add_text(tree, tvb, offset, 8,
				"Type(EIGRP_EXTCOMM_RPM): xProto(%u) xMETRIC(%u)",
				tvb_get_ntohs(tvb, 0),
				tvb_get_ntohl(tvb, 2));
	    break;

	case EIGRP_EXTCOMM_SOO_ASFMT:
	case EIGRP_EXTCOMM_SOO_ADRFMT:
	    proto_tree_add_text(tree, tvb, offset, 8,
				"Type(EIGRP_EXTCOMM_SOO): AS(%u) TAG(%u)",
				tvb_get_ntohs(tvb, 0),
				tvb_get_ntohl(tvb, 2));
	    break;
	}

	/*on to the next */
	offset += 8;
	limit -= 8;

	if (0 != limit%8) {
	    break;
	}

    }

    return(offset);
}

/**
 *@fn int dissect_eigrp_wide_metric_attr (proto_tree *tree, tvbuff_t *tvb,
 *					  int offset, int limit)
 *
 * @param[in|out] tree	detail dissection result
 * @param[in] tvb	packet data
 * @param[in] offset	current byte offset in packet being processed
 * @param[in] limit	maximum number of words which should be process
 *
 * @return int		number of bytes process
 *
 * @par
 * Dissect the Metric Attributes which (optionally) are part of the wide-metric
 * route TLV.  Some of the attributes which effect the metric is controlled by
 * K6 which is now part of the Parameter TLV.  Also, eh extended community TLV is
 * no longer used, as its now append to the route
 */
static int
dissect_eigrp_wide_metric_attr (proto_tree *tree, tvbuff_t *tvb,
				int offset, int limit)
{
    proto_item *sub_ti;
    proto_tree *sub_tree;
    tvbuff_t *sub_tvb;
    int sub_offset;

    gint8 attr_offset = 0;
    gint8 attr_opcode = 0;

    limit *= 2;   /* words to bytes */

    sub_ti = proto_tree_add_text(tree, tvb, offset, limit, "Attributes");
    sub_tree = proto_item_add_subtree(sub_ti, ett_eigrp_tlv_attr);
    sub_tvb = tvb_new_subset(tvb, offset, limit, -1);
    sub_offset = 0;

    while (limit > 0) {
	attr_opcode = tvb_get_guint8(sub_tvb, sub_offset);
	proto_tree_add_item(sub_tree, hf_eigrp_attr_opcode, sub_tvb,
			    sub_offset, 1, ENC_BIG_ENDIAN);
	sub_offset += 1;

	attr_offset = tvb_get_guint8(sub_tvb, sub_offset) * 2;
	proto_tree_add_item(sub_tree, hf_eigrp_attr_offset, sub_tvb,
			    sub_offset, 1, ENC_BIG_ENDIAN);
	sub_offset += 1;

	switch (attr_opcode) {
	case EIGRP_ATTR_NOOP:
	    break;

	case EIGRP_ATTR_SCALED:
	    proto_tree_add_item(sub_tree, hf_eigrp_attr_scaled, sub_tvb,
				sub_offset, 4, ENC_BIG_ENDIAN);
	    break;

	case EIGRP_ATTR_TAG:
	    proto_tree_add_item(sub_tree, hf_eigrp_attr_tag, sub_tvb,
				sub_offset, 4, ENC_BIG_ENDIAN);
	    break;

	case EIGRP_ATTR_COMM:
	    dissect_eigrp_metric_comm(sub_tree,
				      tvb_new_subset(sub_tvb, sub_offset, 8, -1),
				      sub_offset, limit);
	    break;

	case EIGRP_ATTR_JITTER:
	    proto_tree_add_item(sub_tree, hf_eigrp_attr_jitter, sub_tvb,
				sub_offset, 4, ENC_BIG_ENDIAN);
	    break;

	case EIGRP_ATTR_QENERGY:
	    proto_tree_add_item(sub_tree, hf_eigrp_attr_qenergy, sub_tvb,
				sub_offset, 4, ENC_BIG_ENDIAN);
	    break;

	case EIGRP_ATTR_ENERGY:
	    proto_tree_add_item(sub_tree, hf_eigrp_attr_energy, sub_tvb,
				sub_offset, 4, ENC_BIG_ENDIAN);
	    break;

	default:
	    break;
	}
	sub_offset += attr_offset;
	limit -= (EIGRP_ATTR_HDRLEN + attr_offset);
    }

    offset += sub_offset;
    return(offset);
}

/**
 *@fn int dissect_eigrp_wide_metric (proto_tree *tree, tvbuff_t *tvb, int offset)
 *
 * @param[in|out] tree	detail dissection result
 * @param[in] tvb	packet data
 * @param[in] offset	current byte offset in packet being processed
 *
 * @return int		number of bytes process
 *
 * @par
 * Dissect the latest-n-greatest "Wide"Metric" definition for EIGRP. This
 * definition was created to address the higher speed links and should handle
 * things until we break the speed of light *wink*
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |    Offset    |   Priority     |  Reliability  |     Load      |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |         MTU                                    |   Hopcount   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                            Delay                              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |         Delay                 |         Bandwidth             |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                        Bandwidth                              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |         Reserved              |           Flags               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |\/\/\/        Extended Metrics (Variable Length)         \/\/\/|
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
static int
dissect_eigrp_wide_metric (proto_tree *tree, tvbuff_t *tvb, int offset)
{
    proto_item *sub_ti;
    proto_tree *sub_tree;
    tvbuff_t *sub_tvb;
    gint8 attr_size = 0;
    guint64 big_num;

    sub_ti = proto_tree_add_text(tree, tvb, offset, 24, "Wide Metric");
    sub_tree = proto_item_add_subtree(sub_ti, ett_eigrp_tlv_metric);
    sub_tvb = tvb_new_subset(tvb, offset, 24, -1);

    attr_size = tvb_get_guint8(sub_tvb, 0);

    proto_tree_add_item(sub_tree, hf_eigrp_metric_offset,
			sub_tvb, 0,  1, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_eigrp_metric_priority,
			sub_tvb, 1,  1, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_eigrp_metric_rel,
			sub_tvb, 2,  1, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_eigrp_metric_load,
			sub_tvb, 3,  1, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_eigrp_metric_mtu,
			sub_tvb, 4,  3, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_eigrp_metric_hopcount,
			sub_tvb, 7,  1, ENC_BIG_ENDIAN);

    /* The one-way latency along an unloaded path to the destination
     * expressed in units of nanoseconds per kilobyte. This number is not
     * scaled, as is the case with scaled delay. A delay of 0xFFFFFFFFFFFF
     * indicates an unreachable route. */
    big_num = tvb_get_ntoh64(sub_tvb, 8);
    big_num >>= 16;
    if (big_num == G_GINT64_CONSTANT(0x0000ffffffffffffU)) {
        proto_tree_add_text(sub_tree, sub_tvb, 8, 6, "Delay: Infinity");
    } else {
        proto_tree_add_text(sub_tree, sub_tvb, 8, 6, "Delay: %" G_GINT64_MODIFIER "u", big_num);
    }

    /* The path bandwidth measured in kilobyte per second as presented by
     * the interface.  This number is not scaled, as is the case with scaled
     * bandwidth. A bandwidth of 0xFFFFFFFFFFFF indicates an unreachable
     * route.
     */
    big_num = tvb_get_ntoh64(sub_tvb, 14);
    big_num >>= 16;
    if (big_num == G_GINT64_CONSTANT(0x0000ffffffffffffU)) {
	proto_tree_add_text(sub_tree, sub_tvb, 14, 6, "Bandwidth: Infinity");
    } else {
	proto_tree_add_text(sub_tree, sub_tvb, 14, 6, "Bandwidth: %" G_GINT64_MODIFIER "u", big_num);
    }
    proto_tree_add_item(sub_tree, hf_eigrp_metric_reserved, sub_tvb, 20, 2,
			ENC_BIG_ENDIAN);

    /* Decode the route flags field */
    dissect_eigrp_metric_flags(sub_tree, sub_tvb, 22, 2);
    offset += 24;

    /* any extended metric attributes? */
    if (attr_size > 0) {
	offset = dissect_eigrp_wide_metric_attr(tree, tvb, offset, attr_size);
    }

    return(offset);
}

/**
 *@fn void dissect_eigrp_multi_protocol_tlv (proto_item *ti, proto_tree *tree, tvbuff_t *tvb,
 *					     packet_info *pinfo, guint16 tlv)

 *
 * @param[in|out] tree	detail dissection result
 * @param[in] tvb	packet data
 * @param[in] ti	protocol item
 * @param[in] pinfo	general data about the protocol
 *
 * @return void
 *
 * @par
 * Dissect the Multi-Protocol (TLV Version 2.0) TLV format definition. The following
 * represents the format
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   Topology Identifier         |         Family Identifier     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                       Router ID                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                      Wide Metric                              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |\/\/\/        Extended Metrics (Variable Length)         \/\/\/|
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |\/\/\/         NextHop (Family Specific Length)          \/\/\/|
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |\/\/\/          External Route Data (Optional)           \/\/\/|
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |\/\/\/       Destination (Family Specific Length)        \/\/\/|
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static void
dissect_eigrp_multi_protocol_tlv (proto_item *ti, proto_tree *tree, tvbuff_t *tvb,
				  packet_info *pinfo, guint16 tlv)
{
    proto_item *sub_ti;
    int offset = 0;
    guint16 afi;
    int unreachable = FALSE;

    /* tid for you */
    proto_tree_add_item(tree, hf_eigrp_tid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* now its all about the family */
    afi = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_eigrp_afi, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* gota have an id... */
    proto_tree_add_item(tree, hf_eigrp_routerid, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* decode the wide metric */
    offset = dissect_eigrp_wide_metric(tree, tvb, offset);

    /* dissect nexthop */
    offset = dissect_eigrp_nexthop(tree, tvb, afi, offset);

    /* dissect external data if needed */
    if ((tlv & EIGRP_TLV_TYPEMASK) == EIGRP_TLV_EXTERNAL) {
	if (afi == EIGRP_AF_IPX) {
	    offset = dissect_eigrp_ipx_extdata(tree, tvb, offset);
	} else {
	    offset = dissect_eigrp_extdata(tree, tvb, offset);
	}
    }

    /* dissect dest information */
    switch (afi) {
    case EIGRP_AF_IPv4:
	offset = dissect_eigrp_ipv4_addr(ti, tree, tvb, pinfo, offset, unreachable);
	break;

    case EIGRP_AF_IPv6:
	offset = dissect_eigrp_ipv6_addr(ti, tree, tvb, pinfo, offset, unreachable);
	break;

    case EIGRP_AF_IPX:
	offset = dissect_eigrp_ipx_addr(ti, tree, tvb, pinfo, offset, unreachable);
	break;

    case EIGRP_SF_COMMON:
    case EIGRP_SF_IPv4:
    case EIGRP_SF_IPv6:
	offset = dissect_eigrp_service(ti, tree, tvb, pinfo, offset);
	break;

    default:
	sub_ti = proto_tree_add_text(tree, tvb, offset, -1, "Unknown AFI");
	expert_add_info_format(pinfo, sub_ti, PI_MALFORMED, PI_ERROR, "Unknown AFI");
    }

    return;
}

/**
 *@fn int dissect_eigrp (proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo)
 *
 * @param[in] tvb	packet data
 * @param[in] pinfo	general data about the protocol
 * @param[in|out] tree	detail dissection result
 * @param[out] None
 *
 * @return int		0 if packet is not for this decoder
 *
 * @par
 * This function is called to dissect the packets presented to it. The packet
 * data is held in a special buffer referenced here as tvb. The packet info
 * structure contains general data about the protocol, and can update
 * information here. The tree parameter is where the detail dissection takes
 * place.
 */
#include <epan/in_cksum.h>

static guint16 ip_checksum(const guint8 *ptr, int len)
{
	vec_t cksum_vec[1];

	cksum_vec[0].ptr = ptr;
	cksum_vec[0].len = len;
	return in_cksum(&cksum_vec[0], 1);
}
static int
dissect_eigrp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *eigrp_tree = NULL, *tlv_tree;
    guint opcode, vrid;
    guint16 tlv, checksum, cacl_checksum;
    guint32 ack, size, offset = EIGRP_HEADER_LENGTH;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "EIGRP");

    /* This field shows up as the "Info" column in the display; you should use
     * it, if possible, to summarize what's in the packet, so that a user
     * looking at the list of packets can tell what type of packet it is. See
     * section 1.5 for more information.
     */
    col_clear(pinfo->cinfo, COL_INFO);

    opcode = tvb_get_guint8(tvb, 1);
    ack = tvb_get_ntohl(tvb, 12);
    if ((opcode == EIGRP_OPC_HELLO) && (0 != ack)) {
	opcode = EIGRP_OPC_ACK;
    }

    col_add_str(pinfo->cinfo, COL_INFO,
		val_to_str(opcode, eigrp_opcode2string, "Unknown OpCode (0x%04x)"));

    /* A protocol dissector may be called in 2 different ways - with, or
     * without a non-null "tree" argument.
     * Note also that there is no guarantee, the first time the dissector is
     * called, whether "tree" will be null or not; your dissector must work
     * correctly, building or updating whatever state information is necessary,
     * in either case.
     */
    if (tree) {
	/* NOTE: The offset and length values in the call to
	 * "proto_tree_add_item()" define what data bytes to highlight in the
	 * hex display window when the line in the protocol tree display
	 * corresponding to that item is selected.
	 */

	/* create display subtree for the protocol */
	ti = proto_tree_add_protocol_format(tree, proto_eigrp, tvb, 0, -1,
					    "Cisco EIGRP");
	eigrp_tree = proto_item_add_subtree(ti, ett_eigrp);
	proto_tree_add_item(eigrp_tree, hf_eigrp_version, tvb, 0, 1,
			    ENC_BIG_ENDIAN);
	proto_tree_add_item(eigrp_tree, hf_eigrp_opcode, tvb, 1, 1,
			    ENC_BIG_ENDIAN);

	size = tvb_length(tvb);
	checksum = tvb_get_ntohs(tvb, 2);
	cacl_checksum = ip_checksum(tvb_get_ptr(tvb, 0, size), size);

	if (cacl_checksum == checksum) {
	    proto_tree_add_text(eigrp_tree, tvb, 2, 2,
				"Checksum: 0x%02x [incorrect]",
				checksum);
	    expert_add_info_format(pinfo, ti, PI_RESPONSE_CODE, PI_NOTE,
				"Checksum: 0x%02x [incorrect, should be 0x%02x]",
				checksum, cacl_checksum);
	} else {
	    proto_tree_add_text(eigrp_tree, tvb, 2, 2,
				"Checksum: 0x%02x [correct]", checksum);
	}

	/* Decode the EIGRP Flags Field */
	proto_tree_add_bitmask(eigrp_tree, tvb, 4, hf_eigrp_flags, ett_eigrp_flags,
			       eigrp_flag_fields, ENC_BIG_ENDIAN);

	proto_tree_add_item(eigrp_tree, hf_eigrp_sequence, tvb, 8, 4,
			    ENC_BIG_ENDIAN);
	proto_tree_add_item(eigrp_tree, hf_eigrp_acknowledge, tvb, 12, 4,
			    ENC_BIG_ENDIAN);

	/* print out what family we dealing with... */
	ti = proto_tree_add_item(eigrp_tree, hf_eigrp_vrid, tvb, 16, 2,
				 ENC_BIG_ENDIAN);
	vrid = (tvb_get_ntohs(tvb, 16) & EIGRP_VRID_MASK);
	proto_item_append_text(ti, " %s", val_to_str(vrid, eigrp_vrid2string,
						     ""));

	/* print autonomous-system */
	proto_tree_add_item(eigrp_tree, hf_eigrp_as, tvb, 18, 2,
			    ENC_BIG_ENDIAN);

	switch (opcode) {
	case EIGRP_OPC_IPXSAP:
	    call_dissector(ipxsap_handle,
			   tvb_new_subset(tvb, EIGRP_HEADER_LENGTH, -1, -1), pinfo,
			   eigrp_tree);
	    break;

	default:
	    while (tvb_reported_length_remaining(tvb, offset) > 0) {
		tlv = tvb_get_ntohs(tvb, offset);

		/* its a rose by the wrong name... */
		if (tlv == EIGRP_TLV_MTR_TIDLIST) {
		    tlv = EIGRP_TLV_PEER_TIDLIST;
		}

		size =  tvb_get_ntohs(tvb, offset + 2);
		if (size == 0) {
		    ti = proto_tree_add_text(eigrp_tree, tvb, offset, -1,
					     "Corrupt TLV (Zero Size)");
		    expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
					   "Corrupt TLV (Zero Size)");
		    return(tvb_length(tvb));
		}

		ti = proto_tree_add_text(eigrp_tree, tvb, offset, size, "%s",
					 val_to_str(tlv, eigrp_tlv2string, "Unknown TLV (0x%04x)"));

		tlv_tree = proto_item_add_subtree(ti, ett_eigrp_tlv);
		proto_tree_add_item(tlv_tree, hf_eigrp_tlv_type, tvb,
				    offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tlv_tree, hf_eigrp_tlv_len, tvb,
				    (offset + 2), 2, ENC_BIG_ENDIAN);

		switch (tlv & EIGRP_TLV_RANGEMASK) {
		case EIGRP_TLV_GENERAL:
		    dissect_eigrp_general_tlv(ti, tlv_tree, tvb_new_subset(tvb, (offset + 4), (size - 4), -1), pinfo, tlv);
		    break;

		case EIGRP_TLV_IPv4:
		    dissect_eigrp_ipv4_tlv(ti, tlv_tree, tvb_new_subset(tvb, (offset + 4), (size - 4), -1), pinfo, tlv);
		    break;

		case EIGRP_TLV_ATALK:
		    dissect_eigrp_atalk_tlv(ti, tlv_tree, tvb_new_subset(tvb, (offset + 4), (size - 4), -1), tlv);
		    break;

		case EIGRP_TLV_IPX:
		    dissect_eigrp_ipx_tlv(ti, tlv_tree, tvb_new_subset(tvb, (offset + 4), (size - 4), -1), pinfo, tlv);
		    break;

		case EIGRP_TLV_IPv6:
		    dissect_eigrp_ipv6_tlv(ti, tlv_tree, tvb_new_subset(tvb, (offset + 4), (size - 4), -1), pinfo, tlv);
		    break;

		case EIGRP_TLV_MP:
		    dissect_eigrp_multi_protocol_tlv(ti, tlv_tree, tvb_new_subset(tvb, (offset + 4), (size - 4), -1),
						     pinfo, tlv);
		    break;

		case EIGRP_TLV_MTR:
		    dissect_eigrp_multi_topology_tlv(ti, tlv_tree, tvb_new_subset(tvb, (offset + 4), (size - 4), -1),
						     pinfo, tlv);
		    break;

		default:
		    expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_WARN,
					   "Unknown TLV Group (0x%04x)", tlv);
		}

		offset += size;
	    }
	    break;
	}
    }

    /* Return the amount of data this dissector was able to dissect */
    return(tvb_length(tvb));
}

/**
 *@fn void proto _ register _ eigrp (void)
 *
 * @param[in] void
 * @param[out] None
 *
 * @return void
 *
 * @usage
 *	you can not have the function name inside a comment or else Wireshark
 *	will fail with "duplicate protocol" error.  Dont you hate it when tools
 *	try to be to smart :(
 *
 * @par
 *	Register the protocol with Wireshark
 *	this format is require because a script is used to build the C function
 *	that calls all the protocol registration.
 */
void
proto_register_eigrp(void)
{
    /* Setup list of header fields  See Section 1.6.1 for details
     */
    static hf_register_info hf[] = {
	/*
	 *
	 * EIGRP Packet Header definitions
	 *
	 *    0                   1                   2                   3
	 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *   |Ver              |  Opcode       |          Checksum           |
	 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *   |                          Flags                                |
	 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *   |                      Sequence number                          |
	 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *   |                    Acknowledgement number                     |
	 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *   |  Virtual Router ID              | Autonomous system number    |
	 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	{ &hf_eigrp_version,
	  { "Version", "eigrp.version",
	    FT_UINT8, BASE_DEC, NULL, 0x0,
	    "Version - Version of EIGRP packet format", HFILL }
	},
	{ &hf_eigrp_opcode,
	  { "Opcode", "eigrp.opcode",
	    FT_UINT8, BASE_DEC, VALS(eigrp_opcode2string), 0x0,
	    "Opcode - Operation code indicating the message type", HFILL }
	},
	{ &hf_eigrp_flags,
	  { "Flags", "eigrp.flags",
	    FT_UINT32, BASE_HEX, NULL, 0x0,
	    "Flag - Initialization bit and is used in establishing "
	    "a new neighbor relationship", HFILL }
	},
	{ &hf_eigrp_sequence,
	  { "Sequence", "eigrp.seq",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "Sequence number -- used to send messages reliably", HFILL }
	},
	{ &hf_eigrp_acknowledge,
	  { "Acknowledge", "eigrp.ack",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "Acknowledge number -- used to send messages reliably", HFILL }
	},
	{ &hf_eigrp_vrid,
	  { "Virtual Router ID", "eigrp.vrid",
	    FT_UINT16, BASE_DEC, NULL, 0,
	    "Virtual Router ID - For each Virtual Router, there is a separate topology "
	    "table and routing/service table; even for matching AS. "
	    "This field allows the gateway to select which set router to use.", HFILL }
	},
	{ &hf_eigrp_as,
	  { "Autonomous System", "eigrp.as",
	    FT_UINT16, BASE_DEC, NULL, 0x0,
	    "Autonomous system number - Each AS has a separate topology table "
	    "which for a give routing/service table. A gateway can participate "
	    "in more than one AS. This field allows the gateway to"
	    "select which set of topology tables to use.", HFILL }
	},

	/*
	 * Define eigrp_flags bits here
	 *
	 * Init bit definition. First unicast transmitted Update has this
	 * bit set in the flags field of the fixed header. It tells the neighbor
	 * to send its full topology table.
	 */
	{ &hf_eigrp_flags_init,
	  { "Init", "eigrp.flags.init",
	    FT_BOOLEAN, 32, TFS(&tfs_set_notset), EIGRP_INIT_FLAG,
	    "Init - tells the neighbor to send its full topology table", HFILL }
	},

	/*
	 * Conditionally Received - Any packet with the CR-bit set can
	 * be accepted by an EIGRP speaker if and only if a previous Hello was
	 * received with the SEQUENCE_TYPE TLV present.
	 * This allows multicasts to be transmitted in order and reliably at the
	 * same time as unicasts are transmitted.
	 */
	{ &hf_eigrp_flags_condrecv,
	  { "Conditional Receive", "eigrp.flags.condrecv",
	    FT_BOOLEAN, 32, TFS(&tfs_set_notset), EIGRP_CR_FLAG,
	    "Conditionally Received the next packet if address was in listed "
	    "in the previous HELLO", HFILL }
	},

	/*
	 * Restart flag is set in the hello and the init update
	 * packets during the nsf signaling period.  A nsf-aware
	 * router looks at the RS flag to detect if a peer is restarting
	 * and maintain the adjacency. A restarting router looks at
	 * this flag to determine if the peer is helping out with the restart.
	 */
	{ &hf_eigrp_flags_restart,
	  { "Restart", "eigrp.flags.restart",
	    FT_BOOLEAN, 32, TFS(&tfs_set_notset), EIGRP_RS_FLAG,
	    "Restart flag - Set in the HELLO and the initial "
	    "UPDATE packets during the nsf signaling period.", HFILL },
	},

	/*
	 * EOT bit.  The End-of-Table flag marks the end of the start-up updates
	 * sent to a new peer.  A nsf restarting router looks at this flag to
	 * determine if it has finished receiving the start-up updates from all
	 * peers.  A nsf-aware router waits for this flag before cleaning up
	 * the stale routes from the restarting peer.
	 */
	{ &hf_eigrp_flags_eot,
	  { "End Of Table", "eigrp.flags.eot",
	    FT_BOOLEAN, 32, TFS(&tfs_set_notset), EIGRP_EOT_FLAG,
	    "End-of-Table - Marks the end of the start-up UPDATES indicating the "
	    "complete topology database has been sent to a new peer", HFILL }
	},

	/**
	 * TLV type definitions.  Generic (protocol-independent) TLV types are
	 * defined here.  Protocol-specific ones are defined later
	 *
	 *     +-----+------------------+
	 *     |     |     |            |
	 *     | Type| Len |    Vector  |
	 *     |     |     |            |
	 *     +-----+------------------+
	 *
	 * TLV type definitions.  Generic (protocol-independent) TLV types are
	 * defined here.  Protocol-specific ones are defined elsewhere.
	 *
	 * EIGRP_PARAMETER		0x0001		parameter
	 * EIGRP_AUTH			0x0002		authentication
	 * EIGRP_SEQUENCE		0x0003		sequenced packet
	 * EIGRP_SW_VERSION		0x0004		software version
	 * EIGRP_NEXT_MCAST_SEQ		0x0005		multicast sequence
	 * EIGRP_PEER_STUBINFO		0x0006		stub information
	 * EIGRP_PEER_TERMINATION	0x0007		peer termination
	 */
	{ &hf_eigrp_tlv_type,
	  { "Type", "eigrp.tlv_type",
	    FT_UINT16, BASE_HEX, VALS(eigrp_tlv2string), 0x0,
	    "TLV Type", HFILL }
	},
	{ &hf_eigrp_tlv_len,
	  { "Length", "eigrp.tlv.len",
	    FT_UINT16, BASE_DEC, NULL, 0x0,
	    "TLV Length", HFILL }
	},

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Parameters TLV
 */
	{ &hf_eigrp_par_k1, { "K1", "eigrp.par.k1", FT_UINT8, BASE_DEC, NULL, 0x0,
			      "Bandwidth/Throughput Coefficient", HFILL }},
	{ &hf_eigrp_par_k2, { "K2", "eigrp.par.k2", FT_UINT8, BASE_DEC, NULL, 0x0,
			      "Load Coefficient", HFILL }},
	{ &hf_eigrp_par_k3, { "K3", "eigrp.par.k3", FT_UINT8, BASE_DEC, NULL, 0x0,
			      "Delay/Latency Coefficient", HFILL }},
	{ &hf_eigrp_par_k4, { "K4", "eigrp.par.k4", FT_UINT8, BASE_DEC, NULL, 0x0,
			      "Reliability Coefficient", HFILL }},
	{ &hf_eigrp_par_k5, { "K5", "eigrp.par.k5", FT_UINT8, BASE_DEC, NULL, 0x0,
			      "Reliability Coefficient", HFILL }},
	{ &hf_eigrp_par_k6, { "K6", "eigrp.par.k6", FT_UINT8, BASE_DEC, NULL, 0x0,
			      "Extended Metric Coefficient", HFILL }},
	{ &hf_eigrp_par_holdtime,
	  { "Hold Time", "eigrp.par.holdtime", FT_UINT16, BASE_DEC, NULL, 0x0,
	    "How long to ignore lost HELLO's", HFILL }
	},

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Authentication TLV
 */
	{ &hf_eigrp_auth_type,
	  { "Type", "eigrp.auth.type",
	    FT_UINT16, BASE_DEC, VALS(eigrp_auth2string), 0x0,
	    NULL, HFILL }
	},
	{ &hf_eigrp_auth_len,
	  { "Length", "eigrp.auth.length",
	    FT_UINT16, BASE_DEC, NULL, 0x0,
	    NULL, HFILL }
	},
	{ &hf_eigrp_auth_keyid,
	  { "Key ID", "eigrp.auth.keyid",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    NULL, HFILL }
	},
	{ &hf_eigrp_auth_keyseq,
	  { "Key Sequence", "eigrp.auth.keyseq",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    NULL, HFILL }
	},
	{ &hf_eigrp_auth_digest,
	  { "Digest", "eigrp.auth.digest",
	    FT_BYTES, BASE_NONE, NULL, 0x0,
	    NULL, HFILL }
	},

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Sequence TLV
 */
	{ &hf_eigrp_seq_addrlen,
	  { "Address length", "eigrp.seq.addrlen",
	    FT_UINT8, BASE_DEC, NULL, 0x0,
	    NULL, HFILL }
	},
	{ &hf_eigrp_seq_ipv4addr,
	  { "IP Address", "eigrp.seq.ipv4addr",
	    FT_IPv4, BASE_NONE, NULL, 0x0,
	    NULL, HFILL }
	},
	{ &hf_eigrp_seq_ipv6addr,
	  { "IPv6 Address", "eigrp.seq.ipv6addr",
	    FT_IPv6, BASE_NONE, NULL, 0x0,
	    NULL, HFILL }
	},

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Next Multicast Sequence
 */
	/*
	 * This was added to the hello containing the sequence TLV so that the
	 * hello packet could be more tightly bound to the multicast packet bearing
	 * the CR bit that follows it.  The sequence number of the impending multicast
	 * is carried herein.
	 */
	{ &hf_eigrp_next_mcast_seq,
	  { "Multicast Sequence", "eigrp.next_mcast_seq",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    NULL, HFILL }
	},

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Peer Stub Information TLV
 */
	{ &hf_eigrp_stub_flags,
	  { "Stub Options", "eigrp.stub_options",
	    FT_UINT16, BASE_HEX, NULL, 0x0,
	    NULL, HFILL }
	},

	/*
	 * Define eigrp_stub_flags bits here
	 */
	{ &hf_eigrp_stub_flags_connected,
	  { "Connected", "eigrp.stub_options.connected",
	    FT_BOOLEAN, 16, TFS(&tfs_set_notset), EIGRP_PEER_ALLOWS_CONNECTED,
	    NULL, HFILL }
	},
	{ &hf_eigrp_stub_flags_static,
	  { "Static", "eigrp.stub_options.static",
	    FT_BOOLEAN, 16, TFS(&tfs_set_notset), EIGRP_PEER_ALLOWS_STATIC,
	    NULL, HFILL }
	},
	{ &hf_eigrp_stub_flags_summary,
	  { "Summary", "eigrp.stub_options.summary",
	    FT_BOOLEAN, 16, TFS(&tfs_set_notset), EIGRP_PEER_ALLOWS_SUMMARY,
	    NULL, HFILL }
	},
	{ &hf_eigrp_stub_flags_redist,
	  { "Redistributed", "eigrp.stub_options.redist",
	    FT_BOOLEAN, 16, TFS(&tfs_set_notset), EIGRP_PEER_ALLOWS_REDIST,
	    NULL, HFILL }
	},
	{ &hf_eigrp_stub_flags_leakmap,
	  { "Leak-Map", "eigrp.stub_options.leakmap",
	    FT_BOOLEAN, 16, TFS(&tfs_set_notset), EIGRP_PEER_ALLOWS_LEAKING,
	    NULL, HFILL }
	},
	{ &hf_eigrp_stub_flags_recvonly,
	  { "Receive-Only", "eigrp.stub_options.recvonly",
	    FT_BOOLEAN, 16, TFS(&tfs_set_notset), EIGRP_PEER_ALLOWS_RCVONLY,
	    NULL, HFILL }
	},

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Peer Termination TLV
 */
	/* Place holder - this TLV has no options */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * EIGRP 3.0 Vector Header  (deprecated)
 */
	/*
	 * common header for all version 3 tlvs
	 */
	{ &hf_eigrp_tid,
	  { "Topology", "eigrp.tid",
	    FT_UINT16, BASE_DEC, NULL, 0x0,
	    NULL, HFILL }
	},
	{ &hf_eigrp_afi,
	  { "AFI", "eigrp.afi",
	    FT_UINT16, BASE_DEC, VALS(eigrp_afi2string), 0x0,
	    NULL, HFILL }
	},

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * EIGRP TLV 1.2 (legacy) and TLV 3.0 Metric (deprecated) definition
 */
	{ &hf_eigrp_legacy_metric_delay,
	  { "Scaled Delay", "eigrp.old_metric.delay",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "delay, in 39.1 nanosec interments", HFILL }
	},
	{ &hf_eigrp_legacy_metric_bw,
	  { "Scaled BW", "eigrp.old_metric.bw",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "bandwidth, in units of 1 Kbit/sec", HFILL }
	},
	{ &hf_eigrp_legacy_metric_mtu,
	  { "MTU", "eigrp.old_metric.mtu",
	    FT_UINT24, BASE_DEC, NULL, 0x0,
	    "MTU, in octets", HFILL }
	},
	{ &hf_eigrp_legacy_metric_hopcount,
	  { "Hop Count", "eigrp.old_metric.hopcount",
	    FT_UINT8, BASE_DEC, NULL, 0x0,
	    "Number of hops to destination", HFILL }
	},
	{ &hf_eigrp_legacy_metric_rel,
	  { "Reliability", "eigrp.old_metric.rel",
	    FT_UINT8, BASE_DEC, NULL, 0x0,
	    "percent packets successfully tx/rx", HFILL }
	},
	{ &hf_eigrp_legacy_metric_load,
	  { "Load", "eigrp.old_metric.load",
	    FT_UINT8, BASE_DEC, NULL, 0x0,
	    "percent of channel occupied", HFILL }
	},
	{ &hf_eigrp_legacy_metric_intag,
	  { "Route Tag", "eigrp.old_metric.intag",
	    FT_UINT8, BASE_DEC, NULL, 0x0,
	    "Internal Route Tag", HFILL }
	},

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * EIGRP 3.0 TIDLIST TLV  (only survivor in MTR)
 */
	{ &hf_eigrp_tidlist,
	  { "TID List", "eigrp.tidlist",
	    FT_UINT16, BASE_DEC, NULL, 0x0,
	    NULL, HFILL }
	},
	{ &hf_eigrp_tidlist_flags,
	  { "TID List Flags", "eigrp.tidlist.flags",
	    FT_UINT16, BASE_HEX, NULL, 0x0,
	    NULL, HFILL }
	},
	{ &hf_eigrp_tidlist_len,
	  { "TID List Size", "eigrp.tidlist.len",
	    FT_UINT16, BASE_DEC, NULL, 0x0,
	    NULL, HFILL }
	},
	{ &hf_eigrp_routerid,
	  { "RouterID", "eigrp.routerid",
	    FT_IPv4, BASE_NONE, NULL, 0x0,
	    "Router ID of injecting router", HFILL }
	},
	{ &hf_eigrp_legacy_metric_tag,
	  { "Tag", "eigrp.old_metric.tag",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "route tag", HFILL }
	},

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 * PDM opaque flag field definitions
 */
	{ &hf_eigrp_metric_flags_srcwd,
	  { "Source Withdraw", "eigrp.metric.flags.srcwd",
	    FT_BOOLEAN, 8, TFS(&tfs_true_false), EIGRP_OPAQUE_SRCWD,
	    "Route Source Withdraw", HFILL }
	},
	{ &hf_eigrp_metric_flags_active,
	  { "Route is Active", "eigrp.metric.flags.active",
	    FT_BOOLEAN, 8, TFS(&tfs_true_false), EIGRP_OPAQUE_ACTIVE,
	    "Route is currently in active state", HFILL }
	},
	{ &hf_eigrp_metric_flags_repl,
	  { "Route is Replicated", "eigrp.metric.flags.repl",
	    FT_BOOLEAN, 8, TFS(&tfs_true_false), EIGRP_OPAQUE_REPL,
	    "Route is replicated from different tableid", HFILL }
	},

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * EIGRP TLV 1.2/3.0 ExtData Definitions
 */
	{ &hf_eigrp_extdata_origrid,
	  { "Originating RouterID", "eigrp.extdata.origrid",
	    FT_IPv4, BASE_NONE, NULL, 0x0,
	    "Router ID of redistributing router", HFILL }
	},

	{ &hf_eigrp_extdata_as,
	  { "Originating A.S.", "eigrp.extdata.as",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "Autonomous System of redistributing protocol", HFILL }
	},

	{ &hf_eigrp_extdata_tag,
	  { "Administrative Tag", "eigrp.extdata.tag",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "Administrative Route Tag", HFILL }
	},
	{ &hf_eigrp_extdata_metric,
	  { "External Metric", "eigrp.extdata.metric",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "Metric reported by redistributing protocol", HFILL }
	},
	{ &hf_eigrp_extdata_reserved,
	  { "Reserved", "eigrp.extdata.reserved",
	    FT_UINT16, BASE_DEC, NULL, 0x0,
	    NULL, HFILL }
	},

	/* IPX ExtData Definitions */
	{ &hf_eigrp_ipx_extdata_delay,
	  { "External Delay", "eigrp.extdata.ipx_delay",
	    FT_UINT16, BASE_DEC, NULL, 0x0,
	    "Delay reported by redistributing protocol", HFILL }
	},
	{ &hf_eigrp_ipx_extdata_metric,
	  { "External Metric", "eigrp.extdata.ipx_metric",
	    FT_UINT16, BASE_DEC, NULL, 0x0,
	    "Delay reported by redistributing protocol", HFILL }
	},

	{ &hf_eigrp_extdata_proto,
	  { "External Protocol ID", "eigrp.extdata.proto",
	    FT_UINT8, BASE_DEC, VALS(eigrp_proto2string), 0x0,
	    NULL, HFILL }
	},

	{ &hf_eigrp_extdata_flag_ext,
	  { "Route is External", "eigrp.opaque.flag.ext",
	    FT_BOOLEAN, 8, TFS(&tfs_true_false), EIGRP_OPAQUE_EXT,
	    "External route", HFILL }
	},
	{ &hf_eigrp_extdata_flag_cd,
	  { "Route is Candidate Default", "eigrp.opaque.flag.cd",
	    FT_BOOLEAN, 8, TFS(&tfs_true_false), EIGRP_OPAQUE_CD,
	    "Candidate-Default route", HFILL }
	},

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * EIGRP TLV 2.0 "Wide" Metric format definition
 */
	/* Number of 16bit words in the metric section, used to determine the
	 * start of the destination/attribute information.
	 */
	{ &hf_eigrp_metric_offset,
	  { "Offset", "eigrp.metric.offset",
	    FT_UINT8, BASE_DEC, NULL, 0x0,
	    "Number of 16bit words to reach the start of the"
	    "destination/attribute information", HFILL }
	},

	/* Priority of the prefix when transmitting a group of destination
	 * addresses to neighboring routers. A priority of zero indicates no
	 * priority is set.
	 */
	{ &hf_eigrp_metric_priority,
	  { "Priority", "eigrp.metric.priority",
	    FT_UINT8, BASE_DEC, NULL, 0x0,
	    "Priority of the prefix for ordering transmission", HFILL }
	},

	/** The current error rate for the path. Measured as an error
	 * percentage. A value of 255 indicates 100% reliability
	 */
	{ &hf_eigrp_metric_rel,
	  { "Reliability", "eigrp.metric.reliability",
	    FT_UINT8, BASE_DEC, NULL, 0x0,
	    "percent packets successfully tx/rx", HFILL }
	},

	/** The load utilization of the path to the destination. Measured as a
	 * percentage of load. A value of 255 indicates 100% load.
	 */
	{ &hf_eigrp_metric_load,
	  { "Load", "eigrp.metric.load",
	    FT_UINT8, BASE_DEC, NULL, 0x0,
	    "percent of channel occupied", HFILL }
	},

	/** The minimum maximum transmission unit size for the path to the
	 * destination. Not used in metric calculation, but available to
	 * underlying protocols
	 */
	{ &hf_eigrp_metric_mtu,
	  { "MTU", "eigrp.metric.mtu",
	    FT_UINT24, BASE_DEC, NULL, 0x0,
	    "MTU, in octets", HFILL }
	},

	/** number of router traversals to the destination */
	{ &hf_eigrp_metric_hopcount,
	  { "Hop Count", "eigrp.metric.hopcount",
	    FT_UINT8, BASE_DEC, NULL, 0x0,
	    "Number of hops to destination", HFILL }
	},

	/* Reserved - Transmitted as 0x0000 */
	{ &hf_eigrp_metric_reserved,
	  { "Reserved", "eigrp.metric.reserved",
	    FT_UINT16, BASE_HEX, NULL, 0x0,
	    NULL, HFILL }
	},

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * EIGRP TLV 2.0 Extended Metric Attributes
 */
	{ &hf_eigrp_attr_opcode,
	  { "Opcode", "eigrp.attr.opcode",
	    FT_UINT8, BASE_DEC, VALS(eigrp_attr_opcode2string), 0x0,
	    "Opcode - Operation code indicating the attribute type", HFILL }
	},
	{ &hf_eigrp_attr_offset,
	  { "Offset", "eigrp.attr.offset",
	    FT_UINT8, BASE_DEC, NULL, 0x0,
	    "Number of 2 byte words of data", HFILL }
	},
	{ &hf_eigrp_attr_scaled,
	  { "Legacy Metric", "eigrp.attr.scaled",
	    FT_UINT16, BASE_DEC, NULL, 0x0,
	    "Metric calculated from legacy TLVs", HFILL }
	},
	{ &hf_eigrp_attr_tag,
	  { "Tag", "eigrp.attr.tag",
	    FT_UINT16, BASE_DEC, NULL, 0x0,
	    "Tag assigned by admin for dest", HFILL }
	},
	{ &hf_eigrp_attr_jitter,
	  { "Jitter", "eigrp.attr.jitter",
	    FT_UINT16, BASE_DEC, NULL, 0x0,
	    "Variation in path delay", HFILL }
	},
	{ &hf_eigrp_attr_qenergy,
	  { "Q-Energy", "eigrp.attr.qenergy",
	    FT_UINT16, BASE_DEC, NULL, 0x0,
	    "Non-Active energy usage along path", HFILL }
	},
	{ &hf_eigrp_attr_energy,
	  { "Energy", "eigrp.attr.energy",
	    FT_UINT16, BASE_DEC, NULL, 0x0,
	    "Active energy usage along path", HFILL }
	},

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 * IPv4 specific address definitions
 */
	{ &hf_eigrp_ipv4_nexthop,
	  { "NextHop", "eigrp.ipv4.nexthop",
	    FT_IPv4, BASE_NONE, NULL, 0x0,
	    NULL, HFILL }
	},
	{ &hf_eigrp_ipv4_prefixlen,
	  { "Prefix Length", "eigrp.ipv4.prefixlen",
	    FT_UINT8, BASE_DEC, NULL, 0x0,
	    NULL, HFILL }
	},

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 * IPv6 specific address definitions
 */
	{ &hf_eigrp_ipv6_nexthop,
	  { "NextHop", "eigrp.ipv6.nexthop",
	    FT_IPv6, BASE_NONE, NULL, 0x0,
	    NULL, HFILL }
	},

	{ &hf_eigrp_ipv6_prefixlen,
	  { "Prefix Length", "eigrp.ipv6.prefixlen",
	    FT_UINT8, BASE_DEC, NULL, 0x0,
	    NULL, HFILL }
	},

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 * IPX specific address definitions
 */
	{ &hf_eigrp_ipx_nexthop_net,
	  { "NextHop Net", "eigrp.ipx.nexthop_net",
	    FT_IPXNET, BASE_NONE, NULL, 0x0,
	    NULL, HFILL }
	},
	{ &hf_eigrp_ipx_nexthop_host,
	  { "NextHop Host", "eigrp.ipx.nexthop_host",
	    FT_ETHER, BASE_NONE, NULL, 0x0,
	    NULL, HFILL }
	},
	{ &hf_eigrp_ipx_extdata_routerid,
	  { "External RouterID", "eigrp.ipx.routerid",
	    FT_ETHER, BASE_NONE, NULL, 0x0,
	    "Router ID of redistributing router", HFILL }
	},
	{ &hf_eigrp_ipx_dest,
	  { "Destination", "eigrp.ipx.dest",
	    FT_IPXNET, BASE_NONE, NULL, 0x0,
	    NULL, HFILL }
	},

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 * AppleTalk specific address definitions
 */
	{ &hf_eigrp_atalk_routerid,
	  { "AppleTalk Router ID", "eigrp.atalk.routerid",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    NULL, HFILL }
	},

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Service Advertisement Framework definitions
 */
	{ &hf_eigrp_saf_service,
	  { "Service", "eigrp.saf.service",
	    FT_UINT16, BASE_DEC, VALS(eigrp_saf_srv2string), 0x0,
	    NULL, HFILL }
	},
	{ &hf_eigrp_saf_subservice,
	  { "Sub-Service", "eigrp.saf.subservice",
	    FT_UINT16, BASE_DEC, NULL, 0x0,
	    NULL, HFILL }
	},
	{ &hf_eigrp_saf_guid,
	  { "GUID", "eigrp.saf.guid",
	    FT_GUID, BASE_NONE, NULL, 0x0,
	    NULL, HFILL }
	},
	{ &hf_eigrp_saf_data_type,
	  { "Type", "eigrp.saf.data.type",
	    FT_UINT16, BASE_HEX, VALS(eigrp_saf_type2string), 0x0,
	    "SAF Message Data Type", HFILL }
	},
	{ &hf_eigrp_saf_data_length,
	  { "Length", "eigrp.saf.data.length",
	    FT_UINT16, BASE_DEC, NULL, 0x0,
	    NULL, HFILL }
	},
	{ &hf_eigrp_saf_data_sequence,
	  { "Sequence", "eigrp.saf.data.sequence",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    NULL, HFILL }
	},
	{ &hf_eigrp_saf_reachability_afi,
	  { "AFI", "eigrp.saf.data.reachability.afi",
	    FT_UINT16, BASE_DEC, VALS(eigrp_afi2string), 0x0,
	    NULL, HFILL }
	},
	{ &hf_eigrp_saf_reachability_port,
	  { "Port", "eigrp.saf.data.reachability.port",
	    FT_UINT16, BASE_DEC, NULL, 0x0,
	    NULL, HFILL }
	},
	{ &hf_eigrp_saf_reachability_protocol,
	  { "Protocol", "eigrp.saf.data.reachability.protocol",
	    FT_UINT16, BASE_DEC, NULL, 0x0,
	    NULL, HFILL }
	},
	{ &hf_eigrp_saf_reachability_addr_ipv4,
	  { "IPv4 Addr", "eigrp.saf.data.reachability.addr_ipv4",
	    FT_IPv4, BASE_NONE, NULL, 0x0,
	    NULL, HFILL }
	},
	{ &hf_eigrp_saf_reachability_addr_ipv6,
	  { "IPv6 Addr", "eigrp.saf.data.reachability.addr_ipv6",
	    FT_IPv6, BASE_NONE, NULL, 0x0,
	    NULL, HFILL }
	},
	{ &hf_eigrp_saf_reachability_addr_hex,
	  { "Addr", "eigrp.saf.data.reachability.addr_hex",
	    FT_BYTES, BASE_NONE, NULL, 0x0,
	    NULL, HFILL }
	},

	/* misc field used in a couple places */
	{ &hf_eigrp_nullpad,
	  { "Nullpad", "eigrp.nullpad",
	    FT_BYTES, BASE_NONE, NULL, 0x0,
	    NULL, HFILL }
	},
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
	/* header flag */
	&ett_eigrp,
	&ett_eigrp_flags,

	/* tlv specific */
	&ett_eigrp_tlv,
	&ett_eigrp_tlv_metric,
	&ett_eigrp_tlv_attr,
	&ett_eigrp_tlv_extdata,

	&ett_eigrp_tidlist_flags,
	&ett_eigrp_stub_flags,
	&ett_eigrp_saf_reachability,

	/* metric tlv specific */
	&ett_eigrp_metric_flags,
	&ett_eigrp_extdata_flags,
    };

    /* Register the protocol name and description */
    proto_eigrp = proto_register_protocol(
 	"Enhanced Interior Gateway Routing Protocol",	/* name		*/
 	"EIGRP",					/* short name	*/
 	"eigrp"						/* abbrev	*/
 	);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_eigrp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

/**
 *@fn void proto_reg_handoff_eigrp(void)
 *
 * @param[in] void
 * @param[out] None
 *
 * @return void
 *
 * @usage
 * This exact format is required because a script is used to find these
 * routines and create the code that calls these routines.
 *
 * @par
 * If this dissector uses sub-dissector registration add a registration routine.
 *
 * This form of the reg_handoff function is used if if you perform registration
 * functions which are dependent upon prefs.  If this function is registered as
 * a prefs callback (see prefs_register_protocol above) this function is also
 * called by preferences whenever "Apply" is pressed;
 *
 * In that case, it should accommodate being called more than once.
 */
void
proto_reg_handoff_eigrp(void)
{
	dissector_handle_t eigrp_handle;

	ipxsap_handle = find_dissector("ipxsap");
	media_type_table = find_dissector_table("media_type");

	eigrp_handle = new_create_dissector_handle(dissect_eigrp, proto_eigrp);

	dissector_add_uint("ip.proto", IP_PROTO_EIGRP, eigrp_handle);
	dissector_add_uint("ddp.type", DDP_EIGRP, eigrp_handle);
	dissector_add_uint("ipx.socket", IPX_SOCKET_EIGRP, eigrp_handle);
}
