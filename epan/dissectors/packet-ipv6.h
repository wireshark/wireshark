/* packet-ipv6.h
 * Definitions for IPv6 packet disassembly
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 *
 * Copyright 1998 Gerald Combs
 *
 * MobileIPv6 support added by Tomislav Borosa <tomislav.borosa@siemens.hr>
 *
 * HMIPv6 support added by Martti Kuparinen <martti.kuparinen@iki.fi>
 *
 * FMIPv6 support added by Martin Andre <andre@clarinet.u-strasbg.fr>
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

#ifndef __PACKET_IPV6_H_DEFINED__
#define __PACKET_IPV6_H_DEFINED__

#include <epan/ipv6-utils.h>

#define INET6_ADDRSTRLEN	46

/*
 * Definition for internet protocol version 6.
 * RFC 1883
 */
struct ip6_hdr {
	union {
		struct ip6_hdrctl {
			guint32 ip6_un1_flow;	/* 20 bits of flow-ID */
			guint16 ip6_un1_plen;	/* payload length */
			guint8  ip6_un1_nxt;	/* next header */
			guint8  ip6_un1_hlim;	/* hop limit */
		} ip6_un1;
		guint8 ip6_un2_vfc;	/* 4 bits version, 4 bits class */
	} ip6_ctlun;
	struct e_in6_addr ip6_src;	/* source address */
	struct e_in6_addr ip6_dst;	/* destination address */
};

#define ip6_vfc		ip6_ctlun.ip6_un2_vfc
#define ip6_flow	ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen	ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt		ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim	ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops	ip6_ctlun.ip6_un1.ip6_un1_hlim

/* Offsets of fields within an IPv6 header. */
#define	IP6H_CTL	0
#define	IP6H_CTL_FLOW	0
#define	IP6H_CTL_PLEN	4
#define	IP6H_CTL_NXT	6
#define	IP6H_CTL_HLIM	7
#define	IP6H_CTL_VFC	0
#define	IP6H_SRC	8
#define	IP6H_DST	24

#define IPV6_FLOWINFO_MASK	0x0fffffff	/* flow info (28 bits) */
#define IPV6_FLOWLABEL_MASK	0x000fffff	/* flow label (20 bits) */

/*
 * Extension Headers
 */

struct	ip6_ext {
	guchar	ip6e_nxt;
	guchar	ip6e_len;
};

/* Hop-by-Hop options header */
/* XXX should we pad it to force alignment on an 8-byte boundary? */
struct ip6_hbh {
	guint8 ip6h_nxt;	/* next header */
	guint8 ip6h_len;	/* length in units of 8 octets */
	/* followed by options */
};

/* Destination options header */
/* XXX should we pad it to force alignment on an 8-byte boundary? */
struct ip6_dest {
	guint8 ip6d_nxt;	/* next header */
	guint8 ip6d_len;	/* length in units of 8 octets */
	/* followed by options */
};

/* Option types and related macros */
#define IP6OPT_PAD1		0x00	/* 00 0 00000 */
#define IP6OPT_PADN		0x01	/* 00 0 00001 */
#define IP6OPT_JUMBO		0xC2	/* 11 0 00010 = 194 */
#define IP6OPT_JUMBO_LEN	6
#define IP6OPT_RTALERT		0x05	/* 00 0 00101 */

#define IP6OPT_RTALERT_LEN	4
#define IP6OPT_RTALERT_MLD	0	/* Datagram contains MLD message */
#define IP6OPT_RTALERT_RSVP	1	/* Datagram contains RSVP message */
#define IP6OPT_RTALERT_ACTNET	2	/* contains an Active Networks msg */
#define IP6OPT_MINLEN		2

#define IP6OPT_HOME_ADDRESS	0xC9  /* 11 0 01001 */

#define IP6OPT_TYPE(o)		((o) & 0xC0)
#define IP6OPT_TYPE_SKIP	0x00
#define IP6OPT_TYPE_DISCARD	0x40
#define IP6OPT_TYPE_FORCEICMP	0x80
#define IP6OPT_TYPE_ICMP	0xC0

#define IP6OPT_MUTABLE		0x20

/* Routing header */
struct ip6_rthdr {
	guint8  ip6r_nxt;	/* next header */
	guint8  ip6r_len;	/* length in units of 8 octets */
	guint8  ip6r_type;	/* routing type */
	guint8  ip6r_segleft;	/* segments left */
	/* followed by routing type specific data */
};

/* Type 0 Routing header */
struct ip6_rthdr0 {
	guint8  ip6r0_nxt;		/* next header */
	guint8  ip6r0_len;		/* length in units of 8 octets */
	guint8  ip6r0_type;		/* always zero */
	guint8  ip6r0_segleft;	/* segments left */
	guint8  ip6r0_reserved;	/* reserved field */
	guint8  ip6r0_slmap[3];	/* strict/loose bit map */
	struct e_in6_addr  ip6r0_addr[1];	/* up to 23 addresses */
};

/* Fragment header */
struct ip6_frag {
	guint8  ip6f_nxt;		/* next header */
	guint8  ip6f_reserved;	/* reserved field */
	guint16 ip6f_offlg;		/* offset, reserved, and flag */
	guint32 ip6f_ident;		/* identification */
};

#define IP6F_OFF_MASK		0xfff8	/* mask out offset from _offlg */
#define IP6F_RESERVED_MASK	0x0006	/* reserved bits in ip6f_offlg */
#define IP6F_MORE_FRAG		0x0001	/* more-fragments flag */

/*
 * Definition for ICMPv6.
 * RFC 1885
 */

#define ICMPV6_PLD_MAXLEN	1232	/* IPV6_MMTU - sizeof(struct ip6_hdr)
					   - sizeof(struct icmp6_hdr) */

struct icmp6_hdr {
	guint8	icmp6_type;	/* type field */
	guint8	icmp6_code;	/* code field */
	guint16	icmp6_cksum;	/* checksum field */
	union {
		guint32	icmp6_un_data32[1]; /* type-specific field */
		guint16	icmp6_un_data16[2]; /* type-specific field */
		guint8	icmp6_un_data8[4];  /* type-specific field */
	} icmp6_dataun;
};

#define icmp6_data32	icmp6_dataun.icmp6_un_data32
#define icmp6_data16	icmp6_dataun.icmp6_un_data16
#define icmp6_data8	icmp6_dataun.icmp6_un_data8
#define icmp6_pptr	icmp6_data32[0]		/* parameter prob */
#define icmp6_mtu	icmp6_data32[0]		/* packet too big */
#define icmp6_id	icmp6_data16[0]		/* echo request/reply */
#define icmp6_seq	icmp6_data16[1]		/* echo request/reply */
#define icmp6_maxdelay	icmp6_data16[0]		/* mcast group membership */

#define ICMP6_DST_UNREACH		1	/* dest unreachable, codes: */
#define ICMP6_PACKET_TOO_BIG		2	/* packet too big */
#define ICMP6_TIME_EXCEEDED		3	/* time exceeded, code: */
#define ICMP6_PARAM_PROB		4	/* ip6 header bad */

#define ICMP6_ECHO_REQUEST		128	/* echo service */
#define ICMP6_ECHO_REPLY		129	/* echo reply */
#define ICMP6_MEMBERSHIP_QUERY		130	/* group membership query */
#define MLD6_LISTENER_QUERY		130 	/* multicast listener query */
#define ICMP6_MEMBERSHIP_REPORT		131	/* group membership report */
#define MLD6_LISTENER_REPORT		131	/* multicast listener report */
#define ICMP6_MEMBERSHIP_REDUCTION	132	/* group membership termination */
#define MLD6_LISTENER_DONE		132	/* multicast listener done */

#define ND_ROUTER_SOLICIT		133	/* router solicitation */
#define ND_ROUTER_ADVERT		134	/* router advertisment */
#define ND_NEIGHBOR_SOLICIT		135	/* neighbor solicitation */
#define ND_NEIGHBOR_ADVERT		136	/* neighbor advertisment */
#define ND_REDIRECT			137	/* redirect */

#define ICMP6_ROUTER_RENUMBERING	138	/* router renumbering */

#define ICMP6_WRUREQUEST		139	/* who are you request */
#define ICMP6_WRUREPLY			140	/* who are you reply */
#define ICMP6_FQDN_QUERY		139	/* FQDN query */
#define ICMP6_FQDN_REPLY		140	/* FQDN reply */
#define ICMP6_NI_QUERY			139	/* node information request */
#define ICMP6_NI_REPLY			140	/* node information reply */
#define ICMP6_IND_SOLICIT		141	/* Inverse ND Solicitation */
#define ICMP6_IND_ADVERT		142	/* Inverse ND advertisement */
#define ICMP6_MLDV2_REPORT		143	/* MLD v2 report message : draft-vida-mld-v2-08.txt */

#define ICMP6_MIP6_DHAAD_REQUEST	144	/* Mobile IPv6 DHAAD */
#define ICMP6_MIP6_DHAAD_REPLY		145	/* Mobile IPv6 DHAAD */
#define ICMP6_MIP6_MPS			146	/* Mobile IPv6 MPS */
#define ICMP6_MIP6_MPA			147	/* Mobile IPv6 MPA */

#define ICMP6_MAXTYPE			153

#define ICMP6_DST_UNREACH_NOROUTE	0	/* no route to destination */
#define ICMP6_DST_UNREACH_ADMIN	 	1	/* administratively prohibited */
#define ICMP6_DST_UNREACH_NOTNEIGHBOR	2	/* not a neighbor(obsolete) */
#define ICMP6_DST_UNREACH_BEYONDSCOPE	2	/* beyond scope of source address */
#define ICMP6_DST_UNREACH_ADDR		3	/* address unreachable */
#define ICMP6_DST_UNREACH_NOPORT	4	/* port unreachable */

#define ICMP6_TIME_EXCEED_TRANSIT 	0	/* ttl==0 in transit */
#define ICMP6_TIME_EXCEED_REASSEMBLY	1	/* ttl==0 in reass */

#define ICMP6_PARAMPROB_HEADER 	 	0	/* erroneous header field */
#define ICMP6_PARAMPROB_NEXTHEADER	1	/* unrecognized next header */
#define ICMP6_PARAMPROB_OPTION		2	/* unrecognized option */

#define ICMP6_INFOMSG_MASK		0x80	/* all informational messages */

#define ICMP6_NI_SUBJ_IPV6	0	/* Query Subject is an IPv6 address */
#define ICMP6_NI_SUBJ_FQDN	1	/* Query Subject is a Domain name */
#define ICMP6_NI_SUBJ_IPV4	2	/* Query Subject is an IPv4 address */

#define ICMP6_NI_SUCCESS	0	/* node information successful reply */
#define ICMP6_NI_REFUSED	1	/* node information request is refused */
#define ICMP6_NI_UNKNOWN	2	/* unknown Qtype */

#define ICMP6_ROUTER_RENUMBERING_COMMAND  0	/* rr command */
#define ICMP6_ROUTER_RENUMBERING_RESULT   1	/* rr result */
#define ICMP6_ROUTER_RENUMBERING_SEQNUM_RESET   255	/* rr seq num reset */

/*
 * Multicast Listener Discovery
 */
struct mld6_hdr {
	struct icmp6_hdr	mld6_hdr;
	struct e_in6_addr		mld6_addr; /* multicast address */
};

#define mld6_type	mld6_hdr.icmp6_type
#define mld6_code	mld6_hdr.icmp6_code
#define mld6_cksum	mld6_hdr.icmp6_cksum
#define mld6_maxdelay	mld6_hdr.icmp6_data16[0]
#define mld6_reserved	mld6_hdr.icmp6_data16[1]

/*
 * Neighbor Discovery
 */

struct nd_router_solicit {	/* router solicitation */
	struct icmp6_hdr 	nd_rs_hdr;
	/* could be followed by options */
};

#define nd_rs_type	nd_rs_hdr.icmp6_type
#define nd_rs_code	nd_rs_hdr.icmp6_code
#define nd_rs_cksum	nd_rs_hdr.icmp6_cksum
#define nd_rs_reserved	nd_rs_hdr.icmp6_data32[0]

struct nd_router_advert {	/* router advertisement */
	struct icmp6_hdr	nd_ra_hdr;
	guint32		nd_ra_reachable;	/* reachable time */
	guint32		nd_ra_retransmit;	/* retransmit timer */
	/* could be followed by options */
};

#define nd_ra_type		nd_ra_hdr.icmp6_type
#define nd_ra_code		nd_ra_hdr.icmp6_code
#define nd_ra_cksum		nd_ra_hdr.icmp6_cksum
#define nd_ra_curhoplimit	nd_ra_hdr.icmp6_data8[0]
#define nd_ra_flags_reserved	nd_ra_hdr.icmp6_data8[1]
#define ND_RA_FLAG_MANAGED	0x80
#define ND_RA_FLAG_OTHER	0x40
#define ND_RA_FLAG_HOME_AGENT	0x20

/*
 * Router preference values based on draft-draves-ipngwg-router-selection-01.
 * These are non-standard definitions.
 */
#define ND_RA_FLAG_RTPREF_MASK	0x18 /* 00011000 */

#define ND_RA_FLAG_RTPREF_HIGH	0x08 /* 00001000 */
#define ND_RA_FLAG_RTPREF_MEDIUM	0x00 /* 00000000 */
#define ND_RA_FLAG_RTPREF_LOW	0x18 /* 00011000 */
#define ND_RA_FLAG_RTPREF_RSV	0x10 /* 00010000 */

#define nd_ra_router_lifetime	nd_ra_hdr.icmp6_data16[1]

struct nd_neighbor_solicit {	/* neighbor solicitation */
	struct icmp6_hdr	nd_ns_hdr;
	struct e_in6_addr		nd_ns_target;	/*target address */
	/* could be followed by options */
};

#define nd_ns_type		nd_ns_hdr.icmp6_type
#define nd_ns_code		nd_ns_hdr.icmp6_code
#define nd_ns_cksum		nd_ns_hdr.icmp6_cksum
#define nd_ns_reserved		nd_ns_hdr.icmp6_data32[0]

struct nd_neighbor_advert {	/* neighbor advertisement */
	struct icmp6_hdr	nd_na_hdr;
	struct e_in6_addr		nd_na_target;	/* target address */
	/* could be followed by options */
};

#define nd_na_type		nd_na_hdr.icmp6_type
#define nd_na_code		nd_na_hdr.icmp6_code
#define nd_na_cksum		nd_na_hdr.icmp6_cksum
#define nd_na_flags_reserved	nd_na_hdr.icmp6_data32[0]
#define ND_NA_FLAG_ROUTER		0x80000000
#define ND_NA_FLAG_SOLICITED		0x40000000
#define ND_NA_FLAG_OVERRIDE		0x20000000

struct nd_redirect {		/* redirect */
	struct icmp6_hdr	nd_rd_hdr;
	struct e_in6_addr		nd_rd_target;	/* target address */
	struct e_in6_addr		nd_rd_dst;	/* destination address */
	/* could be followed by options */
};

#define nd_rd_type		nd_rd_hdr.icmp6_type
#define nd_rd_code		nd_rd_hdr.icmp6_code
#define nd_rd_cksum		nd_rd_hdr.icmp6_cksum
#define nd_rd_reserved		nd_rd_hdr.icmp6_data32[0]

struct nd_opt_hdr {		/* Neighbor discovery option header */
	guint8	nd_opt_type;
	guint8	nd_opt_len;
	/* followed by option specific data*/
};

#define ND_OPT_SOURCE_LINKADDR		1
#define ND_OPT_TARGET_LINKADDR		2
#define ND_OPT_PREFIX_INFORMATION	3
#define ND_OPT_REDIRECTED_HEADER	4
#define ND_OPT_MTU			5
#define ND_OPT_ADVINTERVAL		7
#define ND_OPT_HOMEAGENT_INFO		8
#define ND_OPT_SOURCE_ADDRLIST		9
#define ND_OPT_TARGET_ADDRLIST		10

/* draft-ietf-ipngwg-router-preference, not officially assigned yet */
#define ND_OPT_ROUTE_INFO		200
/* draft-ietf-mobileip-hmipv6, not officially assigned yet */
#define ND_OPT_MAP			201

struct nd_opt_prefix_info {	/* prefix information */
	guint8	nd_opt_pi_type;
	guint8	nd_opt_pi_len;
	guint8	nd_opt_pi_prefix_len;
	guint8	nd_opt_pi_flags_reserved;
	guint32	nd_opt_pi_valid_time;
	guint32	nd_opt_pi_preferred_time;
	guint32	nd_opt_pi_reserved2;
	struct e_in6_addr	nd_opt_pi_prefix;
};

#define ND_OPT_PI_FLAG_ONLINK		0x80
#define ND_OPT_PI_FLAG_AUTO		0x40
#define ND_OPT_PI_FLAG_ROUTER		0x20
#define ND_OPT_PI_FLAG_SITEPREF		0x10

struct nd_opt_rd_hdr {         /* redirected header */
	guint8	nd_opt_rh_type;
	guint8	nd_opt_rh_len;
	guint16	nd_opt_rh_reserved1;
	guint32	nd_opt_rh_reserved2;
	/* followed by IP header and data */
};

struct nd_opt_mtu {		/* MTU option */
	guint8	nd_opt_mtu_type;
	guint8	nd_opt_mtu_len;
	guint16	nd_opt_mtu_reserved;
	guint32	nd_opt_mtu_mtu;
};

struct nd_opt_adv_int {		/* Advertisement Interval option */
	guint8	nd_opt_adv_int_type;
	guint8	nd_opt_adv_int_len;
	guint16	nd_opt_adv_int_reserved;
	guint32	nd_opt_adv_int_advint;
};

struct nd_opt_ha_info {		/* Home Agent Information option */
	guint8	nd_opt_ha_info_type;
	guint8	nd_opt_ha_info_len;
	guint16	nd_opt_ha_info_reserved;
	guint16	nd_opt_ha_info_ha_pref;
	guint16	nd_opt_ha_info_ha_life;
};

struct nd_opt_route_info {	/* route info */
	guint8	nd_opt_rti_type;
	guint8	nd_opt_rti_len;
	guint8	nd_opt_rti_prefixlen;
	guint8	nd_opt_rti_flags;
	guint32	nd_opt_rti_lifetime;
	/* prefix follows */
};

struct nd_opt_map_info {	/* HMIPv6 MAP option */
	guint8			nd_opt_map_type;
	guint8			nd_opt_map_len;
	guint8			nd_opt_map_dist_and_pref;
	guint8			nd_opt_map_flags;
	guint32			nd_opt_map_lifetime;
	struct e_in6_addr	nd_opt_map_address;
};

#define ND_OPT_MAP_FLAG_R	0x80
#define ND_OPT_MAP_FLAG_M	0x40
#define ND_OPT_MAP_FLAG_I	0x20
#define ND_OPT_MAP_FLAG_T	0x10
#define ND_OPT_MAP_FLAG_P	0x08
#define ND_OPT_MAP_FLAG_V	0x04

/*
 * icmp6 node information
 */
struct icmp6_nodeinfo {
	struct icmp6_hdr icmp6_ni_hdr;
	guint8 icmp6_ni_nonce[8];
	/* could be followed by reply data */
};

#define ni_type		icmp6_ni_hdr.icmp6_type
#define ni_code		icmp6_ni_hdr.icmp6_code
#define ni_cksum	icmp6_ni_hdr.icmp6_cksum
#define ni_qtype	icmp6_ni_hdr.icmp6_data16[0]
#define ni_flags	icmp6_ni_hdr.icmp6_data16[1]

#define NI_QTYPE_NOOP		0 /* NOOP  */
#define NI_QTYPE_SUPTYPES	1 /* Supported Qtypes */
#define NI_QTYPE_FQDN		2 /* FQDN (draft 04) */
#define NI_QTYPE_DNSNAME	2 /* DNS Name */
#define NI_QTYPE_NODEADDR	3 /* Node Addresses */
#define NI_QTYPE_IPV4ADDR	4 /* IPv4 Addresses */

#define NI_SUPTYPE_FLAG_COMPRESS	0x1
#define NI_FQDN_FLAG_VALIDTTL		0x1

#define NI_NODEADDR_FLAG_TRUNCATE	0x1
#define NI_NODEADDR_FLAG_ALL		0x2
#define NI_NODEADDR_FLAG_COMPAT		0x4
#define NI_NODEADDR_FLAG_LINKLOCAL	0x8
#define NI_NODEADDR_FLAG_SITELOCAL	0x10
#define NI_NODEADDR_FLAG_GLOBAL		0x20
#define NI_NODEADDR_FLAG_ANYCAST	0x40 /* just experimental. not in spec */

struct ni_reply_fqdn {
	guint32	ni_fqdn_ttl;	/* TTL */
	guint8	ni_fqdn_namelen; /* length in octets of the FQDN */
	guint8	ni_fqdn_name[3]; /* XXX: alignment */
};

/*
 * Router Renumbering. as router-renum-05.txt
 */
struct icmp6_router_renum {	/* router renumbering header */
	struct icmp6_hdr	rr_hdr;
	guint8		rr_segnum;
	guint8		rr_flags;
	guint16		rr_maxdelay;
	guint32		rr_reserved;
};

#define rr_type			rr_hdr.icmp6_type
#define rr_code			rr_hdr.icmp6_code
#define rr_cksum		rr_hdr.icmp6_cksum
#define rr_seqnum 		rr_hdr.icmp6_data32[0]

struct rr_pco_match {		/* match prefix part */
	guint8	rpm_code;
	guint8	rpm_len;
	guint8	rpm_ordinal;
	guint8	rpm_matchlen;
	guint8	rpm_minlen;
	guint8	rpm_maxlen;
	guint16	rpm_reserved;
	struct e_in6_addr	rpm_prefix;
};

#define RPM_PCO_ADD		1
#define RPM_PCO_CHANGE		2
#define RPM_PCO_SETGLOBAL	3
#define RPM_PCO_MAX		4

struct rr_pco_use {		/* use prefix part */
	guint8	rpu_uselen;
	guint8	rpu_keeplen;
	guint8	rpu_ramask;
	guint8	rpu_raflags;
	guint32	rpu_vltime;
	guint32	rpu_pltime;
	guint32	rpu_flags;
	struct e_in6_addr rpu_prefix;
};

#define ICMP6_RR_PCOUSE_RAFLAGS_ONLINK  0x80
#define ICMP6_RR_PCOUSE_RAFLAGS_AUTO    0x40

/* network endian */
#define ICMP6_RR_PCOUSE_FLAGS_DECRVLTIME	0x80000000
#define ICMP6_RR_PCOUSE_FLAGS_DECRPLTIME	0x40000000

struct rr_result {		/* router renumbering result message */
	guint16	rrr_flags;
	guint8	rrr_ordinal;
	guint8	rrr_matchedlen;
	guint32	rrr_ifid;
	struct e_in6_addr rrr_prefix;
};

/* network endian */
#define ICMP6_RR_RESULT_FLAGS_OOB		0x0002
#define ICMP6_RR_RESULT_FLAGS_FORBIDDEN		0x0001


/*
 * FMIPv6
 */

#define ICMP6_EXPERIMENTAL_MOBILITY	150	/* ICMP Experimental Mobility Protocol Type */

#define FMIP6_SUBTYPE_RTSOLPR   2   /* Router Solicitation for Proxy Advertisement                  */
#define FMIP6_RTSOLPR_CODE      0   /* Currently the only code for RTSOLPR                          */

#define FMIP6_SUBTYPE_PRRTADV   3   /* Proxy Router Advertisement                                   */
#define FMIP6_PRRTADV_MNTUP     0   /* MN should use AP-ID, AR-info tuple                           */
#define FMIP6_PRRTADV_NI_HOVER  1   /* LLA of the AP is present, Network Initiated Handover trigger */
#define FMIP6_PRRTADV_NORTINFO  2   /* No new router information is present                         */
#define FMIP6_PRRTADV_LIMRTINFO 3   /* Limited new router information is present                    */
#define FMIP6_PRRTADV_UNSOL     4   /* Subnet info for neighbor Access Points are sent unsolicited  */

#define FMIP6_SUBTYPE_HI        4   /* Handover Initiate                                            */
#define FMIP6_HI_PCOA           0   /* PAR receives FBU with PCoA as source IP address              */
#define FMIP6_HI_NOTPCOA        1   /* PAR receives FBU whose source IP address is not PCoA         */

#define FMIP6_SUBTYPE_HACK      5   /* Handover Acknowledge                                         */
#define FMIP6_HACK_VALID        0   /* Handover Accepted, NCoA valid                                */
#define FMIP6_HACK_INVALID      1   /* Handover Accepted, NCoA not valid                            */
#define FMIP6_HACK_INUSE        2   /* Handover Accepted, NCoA in use                               */
#define FMIP6_HACK_ASSIGNED     3   /* Handover Accepted, NCoA assigned                             */
#define FMIP6_HACK_NOTASSIGNED  4   /* Handover Accepted, NCoA not assigned                         */
#define FMIP6_HACK_NOTACCEPTED  128 /* Handover Not Accepted, reason unspecified                    */
#define FMIP6_HACK_PROHIBITED   129 /* Administratively prohibited                                  */
#define FMIP6_HACK_INSUFFICIENT 130 /* Insufficient resources                                       */

/* Fast Handover Mobile IPv6 extension: Router Solicitation for Proxy Advertisement (RtSolPr).  */
struct fmip6_rtsolpr {
	struct icmp6_hdr fmip6_rtsolpr_hdr;
};
#define fmip6_rtsolpr_type     fmip6_rtsolpr_hdr.icmp6_type
#define fmip6_rtsolpr_code     fmip6_rtsolpr_hdr.icmp6_code
#define fmip6_rtsolpr_cksum    fmip6_rtsolpr_hdr.icmp6_cksum
#define fmip6_rtsolpr_subtype  fmip6_rtsolpr_hdr.icmp6_data8[0]
#define fmip6_rtsolpr_reserved fmip6_rtsolpr_hdr.icmp6_data8[1]
#define fmip6_rtsolpr_id       fmip6_rtsolpr_hdr.icmp6_data16[1]

/* Fast Handover Mobile IPv6 extension: Proxy Router Advertisement (PrRtAdv).  */
struct fmip6_prrtadv {
	struct icmp6_hdr fmip6_prrtadv_hdr;
};

#define fmip6_prrtadv_type     fmip6_prrtadv_hdr.icmp6_type
#define fmip6_prrtadv_code     fmip6_prrtadv_hdr.icmp6_code
#define fmip6_prrtadv_cksum    fmip6_prrtadv_hdr.icmp6_cksum
#define fmip6_prrtadv_subtype  fmip6_prrtadv_hdr.icmp6_data8[0]
#define fmip6_prrtadv_reserved fmip6_prrtadv_hdr.icmp6_data8[1]
#define fmip6_prrtadv_id       fmip6_prrtadv_hdr.icmp6_data16[1]

/* Fast Handover Mobile IPv6 extension: Handover Initiate (HI).  */
struct fmip6_hi {
	struct icmp6_hdr fmip6_hi_hdr;
};

#define fmip6_hi_type           fmip6_hi_hdr.icmp6_type
#define fmip6_hi_code           fmip6_hi_hdr.icmp6_code
#define fmip6_hi_cksum          fmip6_hi_hdr.icmp6_cksum
#define fmip6_hi_subtype        fmip6_hi_hdr.icmp6_data8[0]
#define fmip6_hi_flags_reserved fmip6_hi_hdr.icmp6_data8[1]
#define fmip6_hi_id             fmip6_hi_hdr.icmp6_data16[1]

#if BYTE_ORDER == BIG_ENDIAN
#define FMIP_HI_FLAG_ASSIGNED 0x8000
#define FMIP_HI_FLAG_BUFFER   0x4000
#endif /* BIG_ENDIAN */
#if BYTE_ORDER == LITTLE_ENDIAN
#define FMIP_HI_FLAG_ASSIGNED 0x0080
#define FMIP_HI_FLAG_BUFFER   0x0040
#endif /* LITTLE_ENDIAN */

/* Fast Handover Mobile IPv6 extension: Handover Acknowledge (HAck).  */
struct fmip6_hack {
	struct icmp6_hdr fmip6_hack_hdr;
};

#define fmip6_hack_type		fmip6_hack_hdr.icmp6_type
#define fmip6_hack_code		fmip6_hack_hdr.icmp6_code
#define fmip6_hack_cksum	fmip6_hack_hdr.icmp6_cksum
#define fmip6_hack_subtype	fmip6_hack_hdr.icmp6_data8[0]
#define fmip6_hack_reserved	fmip6_hack_hdr.icmp6_data8[1]
#define fmip6_hack_id		fmip6_hack_hdr.icmp6_data16[1]

#define FMIP6_OPT_IP_ADDRESS             17 /* IP Address Option                            */
#define FMIP6_OPT_NEW_ROUTER_PREFIX_INFO 18 /* New Router Prefix Information Option         */
#define FMIP6_OPT_LINK_LAYER_ADDRESS     19 /* Link-Layer Address Option                    */
#define FMIP6_OPT_NEIGHBOR_ADV_ACK       20 /* Neighbor Advertisement Acknowledgment Option */

struct fmip6_opt_hdr {
    guint8 fmip6_opt_type;
    guint8 fmip6_opt_len;     /* size of this option in 8 octets including opt_hdr */
    guint8 fmip6_opt_optcode; /* Option-Code see the definition below              */
};

/* IP Address Option */
struct fmip6_opt_ip_address {
    guint8 fmip6_opt_type;                   /* Type = 17                                         */
    guint8 fmip6_opt_len;                    /* size of this option in 8 octets including opt_hdr */
    guint8 fmip6_opt_optcode;                /* Option-Code see the definition below              */
    guint8 fmip6_opt_prefix_len;             /* Prefix length for the address                     */
    guint32 fmip6_opt_reserved;              /* Reserved                                          */
    struct e_in6_addr fmip6_opt_ip6_address; /* IP address                                        */
};

#define FMIP6_OPT_IP_ADDRESS_OPTCODE_PCOA 1 /* Old Care-of Address                                 */
#define FMIP6_OPT_IP_ADDRESS_OPTCODE_NCOA 2 /* New Care-of Address                                 */
#define FMIP6_OPT_IP_ADDRESS_OPTCODE_NAR  3 /* NAR's IP address                                    */
#define FMIP6_OPT_IP_ADDRESS_LEN          3 /* Length of this option in 8 octets including opt_hdr */

/* New Router Prefix Information Option */
struct fmip6_opt_new_router_prefix_info {
	guint8 fmip6_opt_type;              /* Type = 18 */
	guint8 fmip6_opt_len;               /* size of this option in 8 octets including opt_hdr */
	guint8 fmip6_opt_optcode;           /* Opt-Code see the definition below */
	guint8 fmip6_opt_prefix_len;        /* Prefix length for the address */
	guint32 fmip6_opt_reserved;         /* Reserved */	
	struct e_in6_addr fmip6_opt_prefix; /* Could be either IPaddr or Prefix, if prefix left should be zero cleared */
};

#define FMIP6_OPT_NEW_ROUTER_PREFIX_INFO_OPTCODE 0 /* Currently no other sub-type                         */
#define FMIP6_OPT_NEW_ROUTER_PREFIX_INFO_LEN     3 /* Length of this option in 8 octets including opt_hdr */

/* Link-layer Address (LLA) Option */
struct fmip6_opt_link_layer_address {
    guint8 fmip6_opt_type;    /* Type = 19                                         */
    guint8 fmip6_opt_len;     /* size of this option in 8 octets including opt_hdr */
    guint8 fmip6_opt_optcode; /* Opt-Code see the definition below                 */
    guchar fmip6_opt_lla[6];  /* The variable length link-layer address            */
};

#define FMIP6_OPT_LINK_LAYER_ADDRESS_OPTCODE_WILDCARD	0	/* wildcard requesting resolution for all nearby access points */
#define FMIP6_OPT_LINK_LAYER_ADDRESS_OPTCODE_NAP	1	/* Link-layer Address of the New Access Point */
#define FMIP6_OPT_LINK_LAYER_ADDRESS_OPTCODE_MN		2	/* Link-layer Address of the MN */
#define FMIP6_OPT_LINK_LAYER_ADDRESS_OPTCODE_NAR	3	/* Link-layer Address of the NAR (i.e., Proxied Originator) */
#define FMIP6_OPT_LINK_LAYER_ADDRESS_OPTCODE_SRC	4	/* Link-layer Address of the source of RtSolPr or PrRtAdv message */
#define FMIP6_OPT_LINK_LAYER_ADDRESS_OPTCODE_CURROUTER	5	/* The access point identified by the LLA belongs to the current interface of the router */
#define FMIP6_OPT_LINK_LAYER_ADDRESS_OPTCODE_NOPREFIX	6	/* No prefix information available for the access point identified by the LLA */
#define FMIP6_OPT_LINK_LAYER_ADDRESS_OPTCODE_NOSUPPORT	7	/* No fast handovers support available for the access point identified by the LLA */
/* Length of this option in 8 octets including opt_hdr, is variable */

/* Neighbor Advertisement Acknowledgment (NAACK) */
struct fmip6_opt_neighbor_advertisement_ack {
	guint8 fmip6_opt_type; 	/* Type = 20 */
	guint8 fmip6_opt_len;		/* size of this option in 8 octets including opt_hdr (1 or 3), because NAACK is caried in a RA (ICMP, not MH) */
	guint8 fmip6_opt_optcode;	/* Sub-types see the definition below */
	guint8 fmip6_opt_status;	/* See the below definitions */
	guint32 fmip6_opt_reserved;	/* Reserved */
	/* could be followed by New CoA */
};

#define FMIP6_OPT_NEIGHBOR_ADV_ACK_OPTCODE		0	/* Currently no other sub-type */
#define	FMIP6_OPT_NEIGHBOR_ADV_ACK_STATUS_INVALID 	1	/* New CoA is invalid */
#define	FMIP6_OPT_NEIGHBOR_ADV_ACK_STATUS_INVALID_NEW 	2	/* New CoA is invalid, use the supplied CoA in reserved field */
#define	FMIP6_OPT_NEIGHBOR_ADV_ACK_STATUS_UNRECOGNIZED 	128	/* LLA is unrecognized */
#define FMIP6_OPT_NEIGHBOR_ADV_ACK_LEN_NO_COA		1	/* No CoA included */
#define FMIP6_OPT_NEIGHBOR_ADV_ACK_LEN_COA		3	/* CoA included */


void capture_ipv6(const guchar *, int, int, packet_counts *);


#endif /* __PACKET_IPV6_H_DEFINED__ */
