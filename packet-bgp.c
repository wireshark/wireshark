/* packet-bgp.c
 * Routines for BGP packet dissection.
 * Copyright 1999, Jun-ichiro itojun Hagino <itojun@itojun.org>
 *
 * $Id: packet-bgp.c,v 1.51 2002/01/15 10:12:17 guy Exp $
 *
 * Supports:
 * RFC1771 A Border Gateway Protocol 4 (BGP-4)
 * RFC1965 Autonomous System Confederations for BGP
 * RFC1997 BGP Communities Attribute
 * RFC2796 BGP Route Reflection An alternative to full mesh IBGP
 * RFC2842 Capabilities Advertisement with BGP-4
 * RFC2858 Multiprotocol Extensions for BGP-4
 * RFC2918 Route Refresh Capability for BGP-4
 * Draft Ramahandra on Extended Communities Extentions
 *
 * TODO:
 * Destination Preference Attribute for BGP (work in progress)
 * RFC1863 A BGP/IDRP Route Server alternative to a full mesh routing
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include <string.h>
#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include "packet.h"
#include "packet-bgp.h"
#include "packet-ipv6.h"
#include "afn.h"

static const value_string bgptypevals[] = {
    { BGP_OPEN, "OPEN Message" },
    { BGP_UPDATE, "UPDATE Message" },
    { BGP_NOTIFICATION, "NOTIFICATION Message" },
    { BGP_KEEPALIVE, "KEEPALIVE Message" },
    { BGP_ROUTE_REFRESH, "ROUTE-REFRESH Message" },
    { BGP_ROUTE_REFRESH_CISCO, "Cisco ROUTE-REFRESH Message" },
    { 0, NULL },
};

static const value_string bgpnotify_major[] = {
    { 1, "Message Header Error" },
    { 2, "OPEN Message Error" },
    { 3, "UPDATE Message Error" },
    { 4, "Hold Timer Expired" },
    { 5, "Finite State Machine Error" },
    { 6, "Cease" },
    { 0, NULL },
};

static const value_string bgpnotify_minor_1[] = {
    { 1, "Connection Not Synchronized" },
    { 2, "Bad Message Length" },
    { 3, "Bad Message Type" },
    { 0, NULL },
};

static const value_string bgpnotify_minor_2[] = {
    { 1, "Unsupported Version Number" },
    { 2, "Bad Peer AS" },
    { 3, "Bad BGP Identifier" },
    { 4, "Unsupported Optional Parameter" },
    { 5, "Authentication Failure" },
    { 6, "Unacceptable Hold Time" },
    { 7, "Unsupported Capability" },
    { 0, NULL },
};

static const value_string bgpnotify_minor_3[] = {
    { 1, "Malformed Attribute List" },
    { 2, "Unrecognized Well-known Attribute" },
    { 3, "Missing Well-known Attribute" },
    { 4, "Attribute Flags Error" },
    { 5, "Attribute Length Error" },
    { 6, "Invalid ORIGIN Attribute" },
    { 7, "AS Routing Loop" },
    { 8, "Invalid NEXT_HOP Attribute" },
    { 9, "Optional Attribute Error" },
    { 10, "Invalid Network Field" },
    { 11, "Malformed AS_PATH" },
    { 0, NULL },
};

static const value_string *bgpnotify_minor[] = {
    NULL, bgpnotify_minor_1, bgpnotify_minor_2, bgpnotify_minor_3,
};

static const value_string bgpattr_origin[] = {
    { 0, "IGP" },
    { 1, "EGP" },
    { 2, "INCOMPLETE" },
    { 0, NULL },
};

static const value_string as_segment_type[] = {
    { 1, "AS_SET" },
    { 2, "AS_SEQUENCE" },
/* RFC1965 has the wrong values, corrected in  */
/* draft-ietf-idr-bgp-confed-rfc1965bis-01.txt */
    { 4, "AS_CONFED_SET" },
    { 3, "AS_CONFED_SEQUENCE" },
    { 0, NULL },
};

static const value_string bgpattr_type[] = {
    { BGPTYPE_ORIGIN, "ORIGIN" },
    { BGPTYPE_AS_PATH, "AS_PATH" },
    { BGPTYPE_NEXT_HOP, "NEXT_HOP" },
    { BGPTYPE_MULTI_EXIT_DISC, "MULTI_EXIT_DISC" },
    { BGPTYPE_LOCAL_PREF, "LOCAL_PREF" },
    { BGPTYPE_ATOMIC_AGGREGATE, "ATOMIC_AGGREGATE" },
    { BGPTYPE_AGGREGATOR, "AGGREGATOR" },
    { BGPTYPE_COMMUNITIES, "COMMUNITIES" },
    { BGPTYPE_ORIGINATOR_ID, "ORIGINATOR_ID" },
    { BGPTYPE_CLUSTER_LIST, "CLUSTER_LIST" },
    { BGPTYPE_MP_REACH_NLRI, "MP_REACH_NLRI" },
    { BGPTYPE_MP_UNREACH_NLRI, "MP_UNREACH_NLRI" },
    { BGPTYPE_EXTENDED_COMMUNITY, "EXTENDED_COMMUNITIES" },
    { 0, NULL },
};

/* Beware : See also MAX_SIZE_OF_EXT_COM_NAMES */
static const value_string bgpext_com_type[] = {
    { BGP_EXT_COM_RT_0, "Route Target" },
    { BGP_EXT_COM_RT_1, "Route Target" },
    { BGP_EXT_COM_RO_0, "Route Origin" },
    { BGP_EXT_COM_RO_1, "Route Origin" },
    { BGP_EXT_COM_LINKBAND, "Link Bandwidth" },
    { BGP_EXT_COM_VPN_ORIGIN, "OSPF Domain" },
    { BGP_EXT_COM_OSPF_RTYPE, "OSPF Route Type" },
    { BGP_EXT_COM_OSPF_RID, "OSPF Router ID" },
    { 0, NULL },
};

static const value_string bgpext_ospf_rtype[] = {
  { BGP_OSPF_RTYPE_RTR, "Router" },  
  { BGP_OSPF_RTYPE_NET, "Network" },  
  { BGP_OSPF_RTYPE_SUM, "Summary" },  
  { BGP_OSPF_RTYPE_EXT, "External" },  
  { BGP_OSPF_RTYPE_NSSA,"NSSA External" },
  { BGP_OSPF_RTYPE_SHAM,"MPLS-VPN Sham" },  
  { 0, NULL },
};


/* MUST be resized if a longer named extended community is added */
#define MAX_SIZE_OF_EXT_COM_NAMES       20

/* Subsequent address family identifier, RFC2858 */
static const value_string bgpattr_nlri_safi[] = {
    { 0, "Reserved" },
    { SAFNUM_UNICAST, "Unicast" },
    { SAFNUM_MULCAST, "Multicast" },
    { SAFNUM_UNIMULC, "Unicast+Multicast" },
    { SAFNUM_MPLS_LABEL, "MPLS Labeled Prefix"},
    { SAFNUM_LBVPNIP, "Labeled VPN-IPv4" },        /* draft-rosen-rfc2547bis-03 */
    { 0, NULL },
};

/* ORF Type, draft-ietf-idr-route-filter-04.txt */
static const value_string orf_type_vals[] = {
    { 2,	"Communities ORF-Type" },
    { 3,	"Extended Communities ORF-Type" },
    { 0,	NULL },
};

/* ORF Send/Receive, draft-ietf-idr-route-filter-04.txt */
static const value_string orf_send_recv_vals[] = {
    { 1,	"Receive" },
    { 2,	"Send" },
    { 3,	"Both" },
    { 0,	NULL },
};

/* Maximal size of an IP address string */
#define MAX_SIZE_OF_IP_ADDR_STRING      16

static int proto_bgp = -1;
static int hf_bgp_type = -1;

static gint ett_bgp = -1;
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
static gint ett_bgp_as_paths = -1;
static gint ett_bgp_communities = -1;
static gint ett_bgp_cluster_list = -1;  /* cluster list tree          */
static gint ett_bgp_options = -1;       /* optional parameters tree   */
static gint ett_bgp_option = -1;        /* an optional parameter tree */
static gint ett_bgp_extended_communities = -1 ; /* extended communities list tree */
/*
 * Decode an IPv4 prefix.
 */
static int
decode_prefix4(tvbuff_t *tvb, gint offset, char *buf, int buflen)
{
    guint8 addr[4];   /* IP address                         */
    int    plen;      /* prefix length                      */
    int    length;    /* number of octets needed for prefix */

    /* snarf length */
    plen = tvb_get_guint8(tvb, offset);
    if (plen < 0 || 32 < plen)
	return -1;
    length = (plen + 7) / 8;

    /* snarf prefix */
    memset(addr, 0, sizeof(addr));
    tvb_memcpy(tvb, addr, offset + 1, length);
    if (plen % 8)
	addr[length - 1] &= ((0xff00 >> (plen % 8)) & 0xff);

    /* hand back a formatted string */
    snprintf(buf, buflen, "%s/%d", ip_to_str(addr), plen);
    return(1 + length);
}

/*
 * Decode an IPv6 prefix.
 */
static int
decode_prefix6(tvbuff_t *tvb, gint offset, char *buf, int buflen)
{
    struct e_in6_addr addr;     /* IPv6 address                       */
    int               plen;     /* prefix length                      */
    int               length;   /* number of octets needed for prefix */

    /* snarf length */
    plen = tvb_get_guint8(tvb, offset);
    if (plen < 0 || 128 < plen)
	return -1;
    length = (plen + 7) / 8;

    /* snarf prefix */
    memset(&addr, 0, sizeof(addr));
    tvb_memcpy(tvb, (guint8 *)&addr, offset + 1, length);
    if (plen % 8)
	addr.s6_addr[length - 1] &= ((0xff00 >> (plen % 8)) & 0xff);

    /* hand back a formatted string */
    snprintf(buf, buflen, "%s/%d", ip6_to_str(&addr), plen);
    return(1 + length);
}

/*
 * Decode an MPLS label stack
 */
static int
decode_MPLS_stack(tvbuff_t *tvb, gint offset, char *buf, int buflen)
{
    guint32     label_entry;    /* an MPLS label enrty (label + COS field + stack bit   */
    gint        index;          /* index for the label stack                            */

    index = offset ;
    label_entry = 0x000000 ;

    buf[0] = '\0' ;

    while ((label_entry && 0x000001) == 0) {

        label_entry = tvb_get_ntoh24(tvb, index) ;
        snprintf(buf, buflen,"%s%u%s", buf, (label_entry >> 4), ((label_entry && 0x000001) == 0) ? "," : " (bottom)");
        index += 3 ;
    }

    return((index - offset) / 3);
}

/*
 * Decode a multiprotocol address
 */

static int
mp_addr_to_str (guint16 afi, guint8 safi, tvbuff_t *tvb, gint offset, char *buf, int buflen)
{
    int                 length;                         /* length of the address in byte */
    guint8              ip4addr[4],ip4addr2[4];         /* IPv4 address                 */
    guint16             rd_type;                        /* Route Distinguisher type     */
    struct e_in6_addr   ip6addr;                        /* IPv6 address                 */

    length = 0 ;
    switch (afi) {
        case AFNUM_INET:
                switch (safi) {
                        case SAFNUM_UNICAST:
                        case SAFNUM_MULCAST:
                        case SAFNUM_UNIMULC:
                                length = 4 ;
                                tvb_memcpy(tvb, ip4addr, offset, 4);
			        snprintf(buf, buflen, "%s", ip_to_str(ip4addr));
                                break;
                        case SAFNUM_LBVPNIP:
                                rd_type=tvb_get_ntohs(tvb,offset) ;
                                switch (rd_type) {
                                        case FORMAT_AS2_LOC:
                                                length = 12;
                                                tvb_memcpy(tvb, ip4addr, offset + 8, 4);
                                                snprintf(buf, buflen, "Empty Label Stack RD=%u:%u IP=%s",
                                                                tvb_get_ntohs(tvb, offset + 2),
                                                                tvb_get_ntohl(tvb, offset + 4),
                                                                ip_to_str(ip4addr));
                                                break;
                                        case FORMAT_IP_LOC:
                                                length = 12;
                                                tvb_memcpy(tvb, ip4addr, offset + 2, 4);   /* IP part of the RD            */
                                                tvb_memcpy(tvb, ip4addr2, offset +6, 4);   /* IP address of the VPN-IPv4   */
                                                snprintf(buf, buflen, "Empty Label Stack RD=%s:%u IP=%s",
                                                                ip_to_str(ip4addr),
                                                                tvb_get_ntohs(tvb, offset + 6),
                                                                ip_to_str(ip4addr2));
                                                break ;
                                        default:
                                                length = 0 ;
                                                snprintf(buf, buflen, "Unknown labeled VPN-IPv4 address format");
                                                break;
                                }
                                break;
                        default:
                                length = 0 ;
                                snprintf(buf, buflen, "Unknown SAFI value for AFI %u", afi);
                                break;
                }
                break;
        case AFNUM_INET6:
                length = 16 ;
                tvb_memcpy(tvb, ip6addr.u6_addr.u6_addr8,offset, sizeof(ip6addr));
                snprintf(buf, buflen, "%s", ip6_to_str(&ip6addr));
                break;
        default:
                length = 0 ;
                snprintf(buf, buflen, "Unknown AFI value");
                break;
    }
    return(length) ;
}

/*
 * Decode a multiprotocol prefix
 */
static int
decode_prefix_MP(guint16 afi, guint8 safi, tvbuff_t *tvb, gint offset, char *buf, int buflen)
{
    int                 length;                         /* length of the prefix in byte */
    int                 plen;                           /* length of the prefix in bit  */
    int                 labnum;                         /* number of labels             */
    guint8              ip4addr[4],ip4addr2[4];         /* IPv4 address                 */
    guint16             rd_type;                        /* Route Distinguisher type     */
    char                lab_stk[256];                   /* label stack                  */

    length = 0 ;

    switch (afi) {
        case AFNUM_INET:
                switch (safi) {
                        case SAFNUM_UNICAST:
                        case SAFNUM_MULCAST:
                        case SAFNUM_UNIMULC:
                                length = decode_prefix4(tvb, offset, buf, buflen) - 1 ;
                                break;
                        case SAFNUM_LBVPNIP:
                                plen =  tvb_get_guint8(tvb,offset) ;

                                labnum = decode_MPLS_stack(tvb, offset + 1, lab_stk, sizeof(lab_stk));

                                offset += (1 + labnum * 3);
                                plen -= (labnum * 3*8);

                                rd_type=tvb_get_ntohs(tvb,offset) ;
                                plen -= 8*8;

                                switch (rd_type) {
                                        case FORMAT_AS2_LOC: /* Code borrowed from the decode_prefix4 function */
                                                if (plen < 0 || 32 < plen) {
                                                        length = 0 ;
                                                        break ;
                                                }

                                                length = (plen + 7) / 8;
                                                memset(ip4addr, 0, sizeof(ip4addr));
                                                tvb_memcpy(tvb, ip4addr, offset + 8, length);
                                                if (plen % 8)
                                                        ip4addr[length - 1] &= ((0xff00 >> (plen % 8)) & 0xff);

                                                snprintf(buf,buflen, "Label Stack=%s RD=%u:%u, IP=%s/%d",
                                                        lab_stk,
                                                        tvb_get_ntohs(tvb, offset + 2),
                                                        tvb_get_ntohl(tvb, offset + 4),
                                                        ip_to_str(ip4addr),
                                                        plen);
                                                length += (labnum * 3 + 8) ;
                                                break ;
                                        case FORMAT_IP_LOC: /* Code borrowed from the decode_prefix4 function */
                                                tvb_memcpy(tvb, ip4addr, offset + 2, 4);

                                                if (plen < 0 || 32 < plen) {
                                                        length = 0 ;
                                                        break ;
                                                }

                                                length = (plen + 7) / 8;
                                                memset(ip4addr2, 0, sizeof(ip4addr2));
                                                tvb_memcpy(tvb, ip4addr2, offset + 8, length);
                                                if (plen % 8)
                                                        ip4addr2[length - 1] &= ((0xff00 >> (plen % 8)) & 0xff);

                                                snprintf(buf,buflen, "Label Stack=%s RD=%s:%u, IP=%s/%d",
                                                        lab_stk,
                                                        ip_to_str(ip4addr),
                                                        tvb_get_ntohs(tvb, offset + 6),
                                                        ip_to_str(ip4addr2),
                                                        plen);
                                                length += (labnum * 3 + 8) ;
                                                break ;
                                        default:
                                                length = 0 ;
                                                snprintf(buf,buflen, "Unkown labeled VPN-IPv4 address format");
                                                break;
                                }
                                break;
                default:
                        length = 0 ;
                        snprintf(buf,buflen, "Unkown SAFI value for AFI %u", afi);
                        break;
                }
                break;
        case AFNUM_INET6:
                 length = decode_prefix6(tvb, offset, buf, buflen) - 1 ;
                 break;
        default:
                length = 0 ;
                snprintf(buf,buflen, "Unkown AFI value");
                break;
    }
    return(1 + length) ;
}

/*
 * Dissect a BGP OPEN message.
 */
static void
dissect_bgp_open(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    struct bgp_open bgpo;      /* BGP OPEN message      */
    int             hlen;      /* message length        */
    u_int           i;         /* tmp                   */
    int             ptype;     /* parameter type        */
    int             plen;      /* parameter length      */
    int             ctype;     /* capability type       */
    int             clen;      /* capability length     */
    int             cend;      /* capabilities end      */
    int             ostart;    /* options start         */
    int             oend;      /* options end           */
    int             p;         /* tvb offset counter    */
    proto_item      *ti;       /* tree item             */
    proto_tree      *subtree;  /* subtree for options   */
    proto_tree      *subtree1; /* subtree for an option */
    proto_tree      *subtree2; /* subtree for an option */
    proto_tree      *subtree3; /* subtree for an option */
    guint8          orfnum;    /* number of ORFs */
    guint8          orftype;        /* ORF Type */
    guint8          orfsendrecv;    /* ORF Send/Receive */

    /* snarf OPEN message */
    tvb_memcpy(tvb, bgpo.bgpo_marker, offset, BGP_MIN_OPEN_MSG_SIZE);
    hlen = ntohs(bgpo.bgpo_len);

    proto_tree_add_text(tree, tvb,
	offset + offsetof(struct bgp_open, bgpo_version), 1,
	"Version: %u", bgpo.bgpo_version);
    proto_tree_add_text(tree, tvb,
	offset + offsetof(struct bgp_open, bgpo_myas), 2,
	"My AS: %u", ntohs(bgpo.bgpo_myas));
    proto_tree_add_text(tree, tvb,
	offset + offsetof(struct bgp_open, bgpo_holdtime), 2,
	"Hold time: %u", ntohs(bgpo.bgpo_holdtime));
    proto_tree_add_text(tree, tvb,
	offset + offsetof(struct bgp_open, bgpo_id), 4,
	"BGP identifier: %s", ip_to_str((guint8 *)&bgpo.bgpo_id));
    proto_tree_add_text(tree, tvb,
	offset + offsetof(struct bgp_open, bgpo_optlen), 1,
	"Optional parameters length: %u %s", bgpo.bgpo_optlen,
        (bgpo.bgpo_optlen == 1) ? "byte" : "bytes");

    /* optional parameters */
    if (bgpo.bgpo_optlen > 0) {
        /* add a subtree and setup some offsets */
        ostart = offset + BGP_MIN_OPEN_MSG_SIZE;
        ti = proto_tree_add_text(tree, tvb, ostart, bgpo.bgpo_optlen,
             "Optional parameters");
        subtree = proto_item_add_subtree(ti, ett_bgp_options);
        p = offset + ostart;
        oend = p + bgpo.bgpo_optlen;

        /* step through all of the optional parameters */
        while (p < oend) {

            /* grab the type and length */
            ptype = tvb_get_guint8(tvb, p++);
            plen = tvb_get_guint8(tvb, p++);

            /* check the type */
            switch (ptype) {
            case BGP_OPTION_AUTHENTICATION:
                proto_tree_add_text(subtree, tvb, p - 2, 2 + plen,
                    "Authentication information (%u %s)", plen,
                    (plen == 1) ? "byte" : "bytes");
                break;
            case BGP_OPTION_CAPABILITY:
                /* grab the capability code */
	        cend = p - 1 + plen;
                ctype = tvb_get_guint8(tvb, p++);
                clen = tvb_get_guint8(tvb, p++);
		ti = proto_tree_add_text(subtree, tvb, p - 4,
                     2 + plen, "Capabilities Advertisement (%u bytes)",
		     2 + plen);
		subtree1 = proto_item_add_subtree(ti, ett_bgp_option);
		proto_tree_add_text(subtree1, tvb, p - 4,
                     1, "Parameter type: Capabilities (2)");
		proto_tree_add_text(subtree1, tvb, p - 3,
                     1, "Parameter length: %u %s", plen,
                     (plen == 1) ? "byte" : "bytes");
		p -= 2;

		/* step through all of the capabilities */
		while (p < cend) {
		    ctype = tvb_get_guint8(tvb, p++);
		    clen = tvb_get_guint8(tvb, p++);

		    /* check the capability type */
		    switch (ctype) {
		    case BGP_CAPABILITY_RESERVED:
			ti = proto_tree_add_text(subtree1, tvb, p - 2,
                             2 + clen, "Reserved capability (%u %s)", 2 + clen,
                             (clen == 1) ? "byte" : "bytes");
			subtree2 = proto_item_add_subtree(ti, ett_bgp_option);
			proto_tree_add_text(subtree2, tvb, p - 2,
                             1, "Capability code: Reserved (0)");
			proto_tree_add_text(subtree2, tvb, p - 1,
                             1, "Capability length: %u %s", clen,
                             (clen == 1) ? "byte" : "bytes");
			if (clen != 0) {
			    proto_tree_add_text(subtree2, tvb, p,
                                 clen, "Capability value: Unknown");
			}
			p += clen;
			break;
		    case BGP_CAPABILITY_MULTIPROTOCOL:
			ti = proto_tree_add_text(subtree1, tvb, p - 2,
                             2 + clen,
                             "Multiprotocol extensions capability (%u %s)",
                             2 + clen, (clen == 1) ? "byte" : "bytes");
			subtree2 = proto_item_add_subtree(ti, ett_bgp_option);
			proto_tree_add_text(subtree2, tvb, p - 2,
                             1, "Capability code: Multiprotocol extensions (%d)",
                             ctype);
			if (clen != 4) {
			    proto_tree_add_text(subtree2, tvb, p - 1,
                                 1, "Capability length: Invalid");
			    proto_tree_add_text(subtree2, tvb, p,
                                 clen, "Capability value: Unknown");
			}
			else {
			    proto_tree_add_text(subtree2, tvb, p - 1,
                                 1, "Capability length: %u %s", clen,
                                 (clen == 1) ? "byte" : "bytes");
			    ti = proto_tree_add_text(subtree2, tvb, p,
                                 clen, "Capability value");
			    subtree3 = proto_item_add_subtree(ti,
                                       ett_bgp_option);
			    /* AFI */
			    i = tvb_get_ntohs(tvb, p);
			    proto_tree_add_text(subtree3, tvb, p,
                                 2, "Address family identifier: %s (%u)",
                                 val_to_str(i, afn_vals, "Unknown"), i);
			    p += 2;
			    /* Reserved */
			    proto_tree_add_text(subtree3, tvb, p,
                                 1, "Reserved: 1 byte");
			    p++;
			    /* SAFI */
			    i = tvb_get_guint8(tvb, p);
			    proto_tree_add_text(subtree3, tvb, p,
                                 1, "Subsequent address family identifier: %s (%u)",
                                 val_to_str(i, bgpattr_nlri_safi,
                                    i >= 128 ? "Vendor specific" : "Unknown"), i);
			    p++;
			}
			break;
		    case BGP_CAPABILITY_ROUTE_REFRESH_CISCO:
		    case BGP_CAPABILITY_ROUTE_REFRESH:
			ti = proto_tree_add_text(subtree1, tvb, p - 2,
                             2 + clen, "Route refresh capability (%u %s)", 2 + clen,
                             (clen == 1) ? "byte" : "bytes");
			subtree2 = proto_item_add_subtree(ti, ett_bgp_option);
			proto_tree_add_text(subtree2, tvb, p - 2,
                             1, "Capability code: Route refresh (%d)", ctype);
			if (clen != 0) {
			    proto_tree_add_text(subtree2, tvb, p,
                                 clen, "Capability value: Invalid");
			}
			else {
			    proto_tree_add_text(subtree2, tvb, p - 1,
                                 1, "Capability length: %u %s", clen,
                                 (clen == 1) ? "byte" : "bytes");
			}
			p += clen;
			break;
		    case BGP_CAPABILITY_COOPERATIVE_ROUTE_FILTERING:
			ti = proto_tree_add_text(subtree1, tvb, p - 2,
                             2 + clen,
                             "Cooperative route filtering capability (%u %s)",
                             2 + clen, (clen == 1) ? "byte" : "bytes");
			subtree2 = proto_item_add_subtree(ti, ett_bgp_option);
			proto_tree_add_text(subtree2, tvb, p - 2,
                             1, "Capability code: Cooperative route filtering (%d)",
                             ctype);
			proto_tree_add_text(subtree2, tvb, p - 1,
			     1, "Capability length: %u %s", clen,
			     (clen == 1) ? "byte" : "bytes");
			ti = proto_tree_add_text(subtree2, tvb, p,
                             clen, "Capability value");
			subtree3 = proto_item_add_subtree(ti, ett_bgp_option);
			/* AFI */
			i = tvb_get_ntohs(tvb, p);
			proto_tree_add_text(subtree3, tvb, p,
			     2, "Address family identifier: %s (%u)",
                             val_to_str(i, afn_vals, "Unknown"), i);
			p += 2;
			/* Reserved */
			proto_tree_add_text(subtree3, tvb, p, 
			     1, "Reserved: 1 byte");
			p++;
			/* SAFI */
			i = tvb_get_guint8(tvb, p);
			proto_tree_add_text(subtree3, tvb, p,
			     1, "Subsequent address family identifier: %s (%u)",
			     val_to_str(i, bgpattr_nlri_safi,
			     i >= 128 ? "Vendor specific" : "Unknown"), i);
			p++;
			/* Number of ORFs */
			orfnum = tvb_get_guint8(tvb, p);
			proto_tree_add_text(subtree3, tvb, p,
					    1, "Number of ORFs: %u", orfnum);
			p++;
			for (i=0; i<orfnum; i++) {
			    /* ORF Type */
			    orftype = tvb_get_guint8(tvb, p);
			    proto_tree_add_text(subtree3, tvb, p,
				1, "ORF Type: %s (%u)",
				val_to_str(orftype, orf_type_vals,"Unknown"),
				orftype);
			    p++;
			    /* Send/Receive */
			    orfsendrecv = tvb_get_guint8(tvb, p);
			    proto_tree_add_text(subtree3, tvb, p,
				1, "Send/Receive: %s (%u)",
				val_to_str(orfsendrecv, orf_send_recv_vals, 
				"Uknown"), orfsendrecv);
			    p++;
			}
			break;
		    /* unknown capability */
		    default:
			ti = proto_tree_add_text(subtree, tvb, p - 2,
                             2 + clen, "Unknown capability (%u %s)", 2 + clen,
                             (clen == 1) ? "byte" : "bytes");
			subtree2 = proto_item_add_subtree(ti, ett_bgp_option);
			proto_tree_add_text(subtree2, tvb, p - 2,
                             1, "Capability code: %s (%d)",
                             ctype >= 128 ? "Private use" : "Unknown", ctype);
			proto_tree_add_text(subtree2, tvb, p - 1,
                             1, "Capability length: %u %s", clen,
                             (clen == 1) ? "byte" : "bytes");
			if (clen != 0) {
			    proto_tree_add_text(subtree2, tvb, p,
                                 clen, "Capability value: Unknown");
			}
			p += clen;
			break;
		    }
		}
                break;
            default:
                proto_tree_add_text(subtree, tvb, p - 2, 2 + plen,
                    "Unknown optional parameter");
                break;
            }
        }
    }
}

/*
 * Dissect a BGP UPDATE message.
 */
static void
dissect_bgp_update(tvbuff_t *tvb, int offset, proto_tree *tree)
 {
    struct bgp_attr bgpa;                       /* path attributes          */
    int             hlen;                       /* message length           */
    gint            o;                          /* packet offset            */
    gint            q;                          /* tmp                      */
    gint            end;                        /* message end              */
    gint            ext_com;                    /* EXTENDED COMMUNITY type  */
    int             len;                        /* tmp                      */
    int             advance;                    /* tmp                      */
    proto_item      *ti;                        /* tree item                */
    proto_tree      *subtree;                   /* subtree for attributes   */
    proto_tree      *subtree2;                  /* subtree for attributes   */
    proto_tree      *subtree3;                  /* subtree for attributes   */
    proto_tree      *as_paths_tree;             /* subtree for AS_PATHs     */
    proto_tree      *as_path_tree;              /* subtree for AS_PATH      */
    proto_tree      *communities_tree;          /* subtree for COMMUNITIES  */
    proto_tree      *community_tree;            /* subtree for a community  */
    proto_tree      *cluster_list_tree;         /* subtree for CLUSTER_LIST */
    int             i, j;                       /* tmp                      */
    guint8          length;                     /* AS_PATH length           */
    guint8          type;                       /* AS_PATH type             */
    char            *as_path_str = NULL;        /* AS_PATH string           */
    char            *communities_str = NULL;    /* COMMUNITIES string       */
    char            *cluster_list_str = NULL;   /* CLUSTER_LIST string      */
    char            *ext_com_str = NULL;        /* EXTENDED COMMUNITY list  */
    char            junk_buf[256];              /* tmp                      */
    guint8          ipaddr[4];                  /* IPv4 address             */

    hlen = tvb_get_ntohs(tvb, offset + BGP_MARKER_SIZE);
    o = offset + BGP_HEADER_SIZE;

    /* check for withdrawals */
    len = tvb_get_ntohs(tvb, o);
    proto_tree_add_text(tree, tvb, o, 2,
	"Unfeasible routes length: %u %s", len, (len == 1) ? "byte" : "bytes");
    o += 2;

    /* parse unfeasible prefixes */
    if (len > 0) {
        ti = proto_tree_add_text(tree, tvb, o, len, "Withdrawn routes:");
	subtree = proto_item_add_subtree(ti, ett_bgp_unfeas);

        /* parse each prefixes */
        end = o + len;
        while (o < end) {
            i = decode_prefix4(tvb, o, junk_buf, sizeof(junk_buf));
            proto_tree_add_text(subtree, tvb, o, i, "%s", junk_buf);
            o += i;
        }
    }
    else {
        o += len;
    }
    /* check for advertisements */
    len = tvb_get_ntohs(tvb, o);
    proto_tree_add_text(tree, tvb, o, 2, "Total path attribute length: %u %s",
            len, (len == 1) ? "byte" : "bytes");

    /* path attributes */
    if (len > 0) {
        ti = proto_tree_add_text(tree, tvb, o + 2, len, "Path attributes");
	subtree = proto_item_add_subtree(ti, ett_bgp_attrs);
	i = 2;
	while (i < len) {
	    int alen, aoff;
	    char *msg;
	    guint16 af;
            guint8 saf;
	    int off, snpa;
	    int nexthop_len;

	    tvb_memcpy(tvb, (guint8 *)&bgpa, o + i, sizeof(bgpa));
            /* check for the Extended Length bit */
	    if (bgpa.bgpa_flags & BGP_ATTR_FLAG_EXTENDED_LENGTH) {
		alen = tvb_get_ntohs(tvb, o + i + sizeof(bgpa));
		aoff = sizeof(bgpa) + 2;
	    } else {
		alen = tvb_get_guint8(tvb, o + i + sizeof(bgpa));
		aoff = sizeof(bgpa) + 1;
	    }

	    /* This is kind of ugly - similar code appears twice, but it
               helps browsing attrs.                                      */
            /* the first switch prints things in the title of the subtree */
	    switch (bgpa.bgpa_type) {
	    case BGPTYPE_ORIGIN:
		if (alen != 1)
		    goto default_attribute_top;
		msg = val_to_str(tvb_get_guint8(tvb, o + i + aoff), bgpattr_origin, "Unknown");
		ti = proto_tree_add_text(subtree, tvb, o + i, alen + aoff,
			"%s: %s (%u %s)",
			val_to_str(bgpa.bgpa_type, bgpattr_type, "Unknown"),
			msg, alen + aoff, (alen + aoff == 1) ? "byte" :
                        "bytes");
		break;
	    case BGPTYPE_AS_PATH:
                /* (o + i + aoff) =
                   (o + current attribute + aoff bytes to first tuple) */
                q = o + i + aoff;
                end = q + alen;
                /* must be freed by second switch!                         */
                /* "alen * 6" (5 digits + space) should be a good estimate
                   of how long the AS path string could be                 */
                as_path_str = malloc((alen + 1) * 6);
                if (as_path_str == NULL) break;
                as_path_str[0] = '\0';

                /* snarf each AS path */
                while (q < end) {
                    type = tvb_get_guint8(tvb, q++);
                    if (type == AS_SET) {
                        snprintf(as_path_str, 2, "{");
                    }
                    else if (type == AS_CONFED_SET) {
                        snprintf(as_path_str, 2, "[");
                    }
                    else if (type == AS_CONFED_SEQUENCE) {
                        snprintf(as_path_str, 2, "(");
                    }
                    length = tvb_get_guint8(tvb, q++);

                    /* snarf each value in path */
                    for (j = 0; j < length; j++) {
                        snprintf(junk_buf, sizeof(junk_buf), "%u%s", tvb_get_ntohs(tvb, q),
                                (type == AS_SET || type == AS_CONFED_SET)
                                ? ", " : " ");
                        strncat(as_path_str, junk_buf, sizeof(junk_buf));
                        q += 2;
                    }

                    /* cleanup end of string */
                    if (type == AS_SET) {
                        as_path_str[strlen(as_path_str) - 2] = '}';
                    }
                    else if (type == AS_CONFED_SET) {
                        as_path_str[strlen(as_path_str) - 2] = ']';
                    }
                    else if (type == AS_CONFED_SEQUENCE) {
                        as_path_str[strlen(as_path_str) - 1] = ')';
                    }
                    else {
                        as_path_str[strlen(as_path_str) - 1] = '\0';
                    }
                }

                /* check for empty AS_PATH */
		if (alen == 0)
                    strncpy(as_path_str, "empty", 6);

		ti = proto_tree_add_text(subtree, tvb, o + i, alen + aoff,
                        "%s: %s (%u %s)",
                        val_to_str(bgpa.bgpa_type, bgpattr_type, "Unknown"),
                        as_path_str, alen + aoff,
                        (alen + aoff == 1) ? "byte" : "bytes");
		break;
	    case BGPTYPE_NEXT_HOP:
		if (alen != 4)
		    goto default_attribute_top;
		tvb_memcpy(tvb, ipaddr, o + i + aoff, 4);
		ti = proto_tree_add_text(subtree, tvb, o + i, alen + aoff,
			"%s: %s (%u %s)",
			val_to_str(bgpa.bgpa_type, bgpattr_type, "Unknown"),
			ip_to_str(ipaddr), alen + aoff, (alen + aoff == 1)
                        ? "byte" : "bytes");
		break;
	    case BGPTYPE_MULTI_EXIT_DISC:
		if (alen != 4)
		    goto default_attribute_top;
		ti = proto_tree_add_text(subtree, tvb, o + i, alen + aoff,
			"%s: %u (%u %s)",
			val_to_str(bgpa.bgpa_type, bgpattr_type, "Unknown"),
			tvb_get_ntohl(tvb, o + i + aoff), alen + aoff,
                        (alen + aoff == 1) ? "byte" : "bytes");
		break;
	    case BGPTYPE_LOCAL_PREF:
		if (alen != 4)
		    goto default_attribute_top;
		ti = proto_tree_add_text(subtree, tvb, o + i, alen + aoff,
			"%s: %u (%u %s)",
			val_to_str(bgpa.bgpa_type, bgpattr_type, "Unknown"),
			tvb_get_ntohl(tvb, o + i + aoff), alen + aoff,
                        (alen + aoff == 1) ? "byte" : "bytes");
		break;
            case BGPTYPE_ATOMIC_AGGREGATE:
                if (alen != 0)
		    goto default_attribute_top;
		ti = proto_tree_add_text(subtree, tvb, o + i, alen + aoff,
			"%s (%u %s)",
			val_to_str(bgpa.bgpa_type, bgpattr_type, "Unknown"),
			alen + aoff, (alen + aoff == 1) ? "byte" : "bytes");
		break;
	    case BGPTYPE_AGGREGATOR:
                if (alen != 6)
		    goto default_attribute_top;
		tvb_memcpy(tvb, ipaddr, o + i + aoff + 2, 4);
		ti = proto_tree_add_text(subtree, tvb, o + i, alen + aoff,
			"%s: AS: %u origin: %s (%u %s)",
			val_to_str(bgpa.bgpa_type, bgpattr_type, "Unknown"),
			tvb_get_ntohs(tvb, o + i + aoff),
			ip_to_str(ipaddr), alen + aoff,
                        (alen + aoff == 1) ? "byte" : "bytes");
		break;
            case BGPTYPE_COMMUNITIES:
		if (alen % 4 != 0)
		    goto default_attribute_top;

                /* (o + i + aoff) =
                   (o + current attribute + aoff bytes to first tuple) */
                q = o + i + aoff;
                end = q + alen;
                /* must be freed by second switch!                          */
                /* "alen * 12" (5 digits, a :, 5 digits + space ) should be
                   a good estimate of how long the communities string could
                   be                                                       */
                communities_str = malloc((alen + 1) * 12);
                if (communities_str == NULL) break;
                communities_str[0] = '\0';
                memset(junk_buf, 0, sizeof(junk_buf));

                /* snarf each community */
                while (q < end) {
                    /* check for well-known communities */
		    if (tvb_get_ntohl(tvb, q) == BGP_COMM_NO_EXPORT)
                        strncpy(junk_buf, "NO_EXPORT ", 10);
		    else if (tvb_get_ntohl(tvb, q) == BGP_COMM_NO_ADVERTISE)
                        strncpy(junk_buf, "NO_ADVERTISE ", 13);
		    else if (tvb_get_ntohl(tvb, q) == BGP_COMM_NO_EXPORT_SUBCONFED)
                        strncpy(junk_buf, "NO_EXPORT_SUBCONFED ", 20);
                    else {
                        snprintf(junk_buf, sizeof(junk_buf), "%u:%u ",
		                tvb_get_ntohs(tvb, q),
                                tvb_get_ntohs(tvb, q + 2));
                    }
                    q += 4;

                    strncat(communities_str, junk_buf, sizeof(junk_buf));
                }
                /* cleanup end of string */
                communities_str[strlen(communities_str) - 1] = '\0';

		ti = proto_tree_add_text(subtree, tvb, o + i, alen + aoff,
			"%s: %s (%u %s)",
			val_to_str(bgpa.bgpa_type, bgpattr_type, "Unknown"),
                        communities_str, alen + aoff,
                        (alen + aoff == 1) ? "byte" : "bytes");
		break;
	    case BGPTYPE_ORIGINATOR_ID:
		if (alen != 4)
		    goto default_attribute_top;
		tvb_memcpy(tvb, ipaddr, o + i + aoff, 4);
		ti = proto_tree_add_text(subtree, tvb, o + i, alen + aoff,
			"%s: %s (%u %s)",
			val_to_str(bgpa.bgpa_type, bgpattr_type, "Unknown"),
			ip_to_str(ipaddr), alen + aoff, (alen + aoff == 1)
                        ? "byte" : "bytes");
		break;
	    case BGPTYPE_CLUSTER_LIST:
		if (alen % 4 != 0)
		    goto default_attribute_top;

                /* (o + i + aoff) =
                   (o + current attribute + aoff bytes to first tuple) */
                q = o + i + aoff;
                end = q + alen;
                /* must be freed by second switch!                          */
                /* "alen * 16" (12 digits, 3 dots + space ) should be
                   a good estimate of how long the cluster_list string could
                   be                                                       */
                cluster_list_str = malloc((alen + 1) * 16);
                if (cluster_list_str == NULL) break;
                cluster_list_str[0] = '\0';
                memset(junk_buf, 0, sizeof(junk_buf));

                /* snarf each cluster list */
		tvb_memcpy(tvb, ipaddr, q, 4);
                while (q < end) {
                    snprintf(junk_buf, sizeof(junk_buf), "%s ", ip_to_str(ipaddr));
                    strncat(cluster_list_str, junk_buf, sizeof(junk_buf));
                    q += 4;
                }
                /* cleanup end of string */
                cluster_list_str[strlen(cluster_list_str) - 1] = '\0';

		ti = proto_tree_add_text(subtree, tvb, o + i, alen + aoff,
			"%s: %s (%u %s)",
			val_to_str(bgpa.bgpa_type, bgpattr_type, "Unknown"),
                        cluster_list_str, alen + aoff,
                        (alen + aoff == 1) ? "byte" : "bytes");
		break;
	    case BGPTYPE_EXTENDED_COMMUNITY:
		if (alen %8 != 0)
		    goto default_attribute_top;

                /* (o + i + aoff) =
                   (o + current attribute + aoff bytes to first tuple) */
                q = o + i + aoff;
                end = q + alen;
                ext_com_str = malloc((alen / 8)*MAX_SIZE_OF_EXT_COM_NAMES);
                if (ext_com_str == NULL) break;
                ext_com_str[0] = '\0';
                while (q < end) {
                        ext_com = tvb_get_ntohs(tvb, q);
                        snprintf(junk_buf, sizeof(junk_buf), "%s", val_to_str(ext_com,bgpext_com_type,"Unknown"));
                        strncat(ext_com_str, junk_buf, sizeof(junk_buf));
                        q = q + 8;
                        if (q < end) strncat(ext_com_str, ",", 1);
                }
                ti = proto_tree_add_text(subtree,tvb,o+i,alen+aoff,
                        "%s : %s (%u %s)",
                        val_to_str(bgpa.bgpa_type,bgpattr_type,"Unknown"),
                        ext_com_str,
                        alen,
                        (alen == 1) ? "byte" : "bytes");
                free(ext_com_str);
                break;

	    default:
	    default_attribute_top:
		ti = proto_tree_add_text(subtree, tvb, o + i, alen + aoff,
			"%s (%u %s)",
			val_to_str(bgpa.bgpa_type, bgpattr_type, "Unknown"),
			alen + aoff, (alen + aoff == 1) ? "byte" : "bytes");
	    } /* end of first switch */
	    subtree2 = proto_item_add_subtree(ti, ett_bgp_attr);

            /* figure out flags */
            junk_buf[0] = '\0';
            if (bgpa.bgpa_flags & BGP_ATTR_FLAG_OPTIONAL) {
                 strncat(junk_buf, "Optional, ", 10);
            }
            else {
                 strncat(junk_buf, "Well-known, ", 12);
            }
            if (bgpa.bgpa_flags & BGP_ATTR_FLAG_TRANSITIVE) {
                 strncat(junk_buf, "Transitive, ", 12);
            }
            else {
                 strncat(junk_buf, "Non-transitive, ", 16);
            }
            if (bgpa.bgpa_flags & BGP_ATTR_FLAG_PARTIAL) {
                 strncat(junk_buf, "Partial, ", 9);
            }
            else {
                 strncat(junk_buf, "Complete, ", 10);
            }
            if (bgpa.bgpa_flags & BGP_ATTR_FLAG_EXTENDED_LENGTH) {
                 strncat(junk_buf, "Extended Length, ", 17);
            }
            /* stomp last ", " */
            j = strlen(junk_buf);
            junk_buf[j - 2] = '\0';
	    ti = proto_tree_add_text(subtree2, tvb,
		    o + i + offsetof(struct bgp_attr, bgpa_flags), 1,
		    "Flags: 0x%02x (%s)", bgpa.bgpa_flags, junk_buf);
	    subtree3 = proto_item_add_subtree(ti, ett_bgp_attr_flags);

            /* add flag bitfield subtrees */
	    proto_tree_add_text(subtree3, tvb,
		    o + i + offsetof(struct bgp_attr, bgpa_flags), 1,
		    "%s", decode_boolean_bitfield(bgpa.bgpa_flags,
			BGP_ATTR_FLAG_OPTIONAL, 8, "Optional", "Well-known"));
	    proto_tree_add_text(subtree3, tvb,
		    o + i + offsetof(struct bgp_attr, bgpa_flags), 1,
		    "%s", decode_boolean_bitfield(bgpa.bgpa_flags,
			BGP_ATTR_FLAG_TRANSITIVE, 8, "Transitive",
                        "Non-transitive"));
	    proto_tree_add_text(subtree3, tvb,
		    o + i + offsetof(struct bgp_attr, bgpa_flags), 1,
		    "%s", decode_boolean_bitfield(bgpa.bgpa_flags,
			BGP_ATTR_FLAG_PARTIAL, 8, "Partial", "Complete"));
	    proto_tree_add_text(subtree3, tvb,
		    o + i + offsetof(struct bgp_attr, bgpa_flags), 1,
		    "%s", decode_boolean_bitfield(bgpa.bgpa_flags,
			BGP_ATTR_FLAG_EXTENDED_LENGTH, 8, "Extended length",
                        "Regular length"));

	    proto_tree_add_text(subtree2, tvb,
		    o + i + offsetof(struct bgp_attr, bgpa_type), 1,
		    "Type code: %s (%u)",
		    val_to_str(bgpa.bgpa_type, bgpattr_type, "Unknown"),
		    bgpa.bgpa_type);

            proto_tree_add_text(subtree2, tvb, o + i + sizeof(bgpa),
                    aoff - sizeof(bgpa), "Length: %d %s", alen,
                    (alen == 1) ? "byte" : "bytes");

            /* the second switch prints things in the actual subtree of each
               attribute                                                     */
	    switch (bgpa.bgpa_type) {
	    case BGPTYPE_ORIGIN:
		if (alen != 1) {
		    proto_tree_add_text(subtree2, tvb, o + i + aoff, alen,
			    "Origin (invalid): %u %s", alen,
                             (alen == 1) ? "byte" : "bytes");
		} else {
		    msg = val_to_str(tvb_get_guint8(tvb, o + i + aoff), bgpattr_origin, "Unknown");
		    proto_tree_add_text(subtree2, tvb, o + i + aoff, 1,
			    "Origin: %s (%u)", msg, tvb_get_guint8(tvb, o + i + aoff));
		}
		break;
	    case BGPTYPE_AS_PATH:
                /* check for empty AS_PATH */
                if (alen == 0) {
                    free(as_path_str);
                    break;
                }

	        ti = proto_tree_add_text(subtree2, tvb, o + i + aoff, alen,
                        "AS path: %s", as_path_str);
	        as_paths_tree = proto_item_add_subtree(ti, ett_bgp_as_paths);

                /* (o + i + aoff) =
                   (o + current attribute + aoff bytes to first tuple) */
                q = o + i + aoff;
                end = q + alen;

                /* snarf each AS path tuple, we have to step through each one
                   again to make a separate subtree so we can't just reuse
                   as_path_str from above */
                while (q < end) {
                    as_path_str[0] = '\0';
                    type = tvb_get_guint8(tvb, q++);
                    if (type == AS_SET) {
                        snprintf(as_path_str, 2, "{");
                    }
                    else if (type == AS_CONFED_SET) {
                        snprintf(as_path_str, 2, "[");
                    }
                    else if (type == AS_CONFED_SEQUENCE) {
                        snprintf(as_path_str, 2, "(");
                    }
                    length = tvb_get_guint8(tvb, q++);

                    /* snarf each value in path, we're just going to reuse
                       as_path_str since we already have it malloced       */
                    for (j = 0; j < length; j++) {
                        snprintf(junk_buf, sizeof(junk_buf), "%u%s", tvb_get_ntohs(tvb, q),
                                (type == AS_SET || type == AS_CONFED_SET)
                                ? ", " : " ");
                        strncat(as_path_str, junk_buf, sizeof(junk_buf));
                        q += 2;
                    }

                    /* cleanup end of string */
                    if (type == AS_SET) {
                        as_path_str[strlen(as_path_str) - 2] = '}';
                    }
                    else if (type == AS_CONFED_SET) {
                        as_path_str[strlen(as_path_str) - 2] = ']';
                    }
                    else if (type == AS_CONFED_SEQUENCE) {
                        as_path_str[strlen(as_path_str) - 1] = ')';
                    }
                    else {
                        as_path_str[strlen(as_path_str) - 1] = '\0';
                    }

                    /* length here means number of ASs, ie length * 2 bytes */
	            ti = proto_tree_add_text(as_paths_tree, tvb,
                            q - length * 2 - 2,
                            length * 2 + 2, "AS path segment: %s", as_path_str);
	            as_path_tree = proto_item_add_subtree(ti, ett_bgp_as_paths);
	            proto_tree_add_text(as_path_tree, tvb, q - length * 2 - 2,
                            1, "Path segment type: %s (%u)",
                            val_to_str(type, as_segment_type, "Unknown"), type);
	            proto_tree_add_text(as_path_tree, tvb, q - length * 2 - 1,
                            1, "Path segment length: %u %s", length,
                            (length == 1) ? "AS" : "ASs");

                    /* backup and reprint path segment value(s) only */
                    q -= 2 * length;
                    as_path_str[0] = '\0';
                    for (j = 0; j < length; j++) {
                        snprintf(junk_buf, sizeof(junk_buf), "%u ", tvb_get_ntohs(tvb, q));
                        strncat(as_path_str, junk_buf, sizeof(junk_buf));
                        q += 2;
                    }
                    as_path_str[strlen(as_path_str) - 1] = '\0';

                    proto_tree_add_text(as_path_tree, tvb, q - length * 2,
                            length * 2, "Path segment value: %s", as_path_str);
                }

                free(as_path_str);
		break;
	    case BGPTYPE_NEXT_HOP:
		if (alen != 4) {
		    proto_tree_add_text(subtree2, tvb, o + i + aoff, alen,
			    "Next hop (invalid): %u %s", alen,
                            (alen == 1) ? "byte" : "bytes");
		} else {
		    tvb_memcpy(tvb, ipaddr, o + i + aoff, 4);
		    proto_tree_add_text(subtree2, tvb, o + i + aoff, alen,
			    "Next hop: %s", ip_to_str(ipaddr));
		}
		break;
	    case BGPTYPE_MULTI_EXIT_DISC:
		if (alen != 4) {
		    proto_tree_add_text(subtree2, tvb, o + i + aoff, alen,
			    "Multiple exit discriminator (invalid): %u %s",
			    alen, (alen == 1) ? "byte" : "bytes");
		} else {
		    proto_tree_add_text(subtree2, tvb, o + i + aoff, alen,
			    "Multiple exit discriminator: %u",
			    tvb_get_ntohl(tvb, o + i + aoff));
		}
		break;
	    case BGPTYPE_LOCAL_PREF:
		if (alen != 4) {
		    proto_tree_add_text(subtree2, tvb, o + i + aoff, alen,
			    "Local preference (invalid): %u %s", alen,
                             (alen == 1) ? "byte" : "bytes");
		} else {
		    proto_tree_add_text(subtree2, tvb, o + i + aoff, alen,
			    "Local preference: %u", tvb_get_ntohl(tvb, o + i + aoff));
		}
		break;
	    case BGPTYPE_ATOMIC_AGGREGATE:
		if (alen != 0) {
		    proto_tree_add_text(subtree2, tvb, o + i + aoff, alen,
			    "Atomic aggregate (invalid): %u %s", alen,
                            (alen == 1) ? "byte" : "bytes");
                }
		break;
	    case BGPTYPE_AGGREGATOR:
		if (alen != 6) {
		    proto_tree_add_text(subtree2, tvb, o + i + aoff, alen,
			    "Aggregator (invalid): %u %s", alen,
                            (alen == 1) ? "byte" : "bytes");
		} else {
		    proto_tree_add_text(subtree2, tvb, o + i + aoff, 2,
			    "Aggregator AS: %u", tvb_get_ntohs(tvb, o + i + aoff));
		    tvb_memcpy(tvb, ipaddr, o + i + aoff + 2, 4);
		    proto_tree_add_text(subtree2, tvb, o + i + aoff + 2, 4,
			    "Aggregator origin: %s",
			    ip_to_str(ipaddr));
		}
		break;
            case BGPTYPE_COMMUNITIES:
		if (alen % 4 != 0) {
		    proto_tree_add_text(subtree2, tvb, o + i + aoff, alen,
			    "Communities (invalid): %u %s", alen,
                            (alen == 1) ? "byte" : "bytes");
                    free(communities_str);
                    break;
                }

                ti = proto_tree_add_text(subtree2, tvb, o + i + aoff, alen,
                        "Communities: %s", communities_str);
                communities_tree = proto_item_add_subtree(ti,
                        ett_bgp_communities);

                /* (o + i + aoff) =
                   (o + current attribute + aoff bytes to first tuple) */
                q = o + i + aoff;
                end = q + alen;

                /* snarf each community */
                while (q < end) {
                    /* check for reserved values */
		    if (tvb_get_ntohs(tvb, q) == FOURHEX0 || tvb_get_ntohs(tvb, q) == FOURHEXF) {
                        /* check for well-known communities */
		        if (tvb_get_ntohl(tvb, q) == BGP_COMM_NO_EXPORT)
		            proto_tree_add_text(communities_tree, tvb,
                                   q - 3 + aoff, 4,
                                   "Community: NO_EXPORT (0x%x)", tvb_get_ntohl(tvb, q));
		        else if (tvb_get_ntohl(tvb, q) == BGP_COMM_NO_ADVERTISE)
		            proto_tree_add_text(communities_tree, tvb,
                                   q - 3 + aoff, 4,
                                   "Community: NO_ADVERTISE (0x%x)", pntohl(q));
		        else if (tvb_get_ntohl(tvb, q) == BGP_COMM_NO_EXPORT_SUBCONFED)
		            proto_tree_add_text(communities_tree, tvb,
                                    q - 3 + aoff, 4,
                                    "Community: NO_EXPORT_SUBCONFED (0x%x)",
                                    tvb_get_ntohl(tvb, q));
                        else
		            proto_tree_add_text(communities_tree, tvb,
                                    q - 3 + aoff, 4,
                                    "Community (reserved): 0x%x", tvb_get_ntohl(tvb, q));
                    }
                    else {

                        ti = proto_tree_add_text(communities_tree, tvb,
                                q - 3 + aoff, 4, "Community: %u:%u",
                                tvb_get_ntohs(tvb, q), tvb_get_ntohs(tvb, q + 2));
                        community_tree = proto_item_add_subtree(ti,
                            ett_bgp_communities);
		        proto_tree_add_text(community_tree, tvb, q - 3 + aoff,
                                2, "Community AS: %u", tvb_get_ntohs(tvb, q));
		        proto_tree_add_text(community_tree, tvb, q - 1 + aoff,
                                2, "Community value: %u", tvb_get_ntohs(tvb, q + 2));
                    }

                    q += 4;
                }

                free(communities_str);
		break;
	    case BGPTYPE_ORIGINATOR_ID:
		if (alen != 4) {
		    proto_tree_add_text(subtree2, tvb, o + i + aoff, alen,
			    "Originator identifier (invalid): %u %s", alen,
                            (alen == 1) ? "byte" : "bytes");
		} else {
		    tvb_memcpy(tvb, ipaddr, o + i + aoff, 4);
		    proto_tree_add_text(subtree2, tvb, o + i + aoff, alen,
			    "Originator identifier: %s",
                            ip_to_str(ipaddr));
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
		    val_to_str(af, afn_vals, "Unknown"), af);
                saf = tvb_get_guint8(tvb, o + i + aoff + 2) ;
		proto_tree_add_text(subtree2, tvb, o + i + aoff + 2, 1,
		    "Subsequent address family identifier: %s (%u)",
		    val_to_str(saf, bgpattr_nlri_safi, saf >= 128 ? "Vendor specific" : "Unknown"),
		    saf);
                nexthop_len = tvb_get_guint8(tvb, o + i + aoff + 3);
		ti = proto_tree_add_text(subtree2, tvb, o + i + aoff + 3, 1,
			"Next hop network address (%d %s)",
			nexthop_len, plurality(nexthop_len, "byte", "bytes"));
		subtree3 = proto_item_add_subtree(ti, ett_bgp_mp_nhna);
		j = 0;
		while (j < nexthop_len) {
                    advance = mp_addr_to_str(af, saf, tvb, o + i + aoff + 4 + j,
		        junk_buf, sizeof(junk_buf)) ;
                    if (j + advance > nexthop_len)
			    break;
                    proto_tree_add_text(subtree3, tvb,o + i + aoff + 4 + j,
                        advance, "Next hop: %s (%u)", junk_buf, advance);
		    j += advance;
		}
                alen -= nexthop_len + 4;
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
			                "SNPA (%u %s)", tvb_get_guint8(tvb, o + i + aoff + off - 1),
                                        (tvb_get_guint8(tvb, o + i + aoff + off - 1) == 1) ? "byte" : "bytes");
		                off += tvb_get_guint8(tvb, o + i + aoff + off - 1);
		        }
                }
                alen -= off;
		aoff += off;

		ti = proto_tree_add_text(subtree2, tvb, o + i + aoff, alen,
			"Network layer reachability information (%u %s)",
			alen, (alen == 1) ? "byte" : "bytes");
		if (alen)  {
	                subtree3 = proto_item_add_subtree(ti,ett_bgp_mp_reach_nlri);

      		        while (alen > 0) {
                                advance = decode_prefix_MP(af, saf, tvb, o + i + aoff , junk_buf, sizeof(junk_buf)) ;
                                proto_tree_add_text(subtree3, tvb, o + i + aoff, advance, "%s", junk_buf) ;
		                alen -= advance;
		                aoff += advance;
                        }
                }
		break;
	   case BGPTYPE_MP_UNREACH_NLRI:
	        af = tvb_get_ntohs(tvb, o + i + aoff);
		proto_tree_add_text(subtree2, tvb, o + i + aoff, 2,
		    "Address family: %s (%u)",
		    val_to_str(af, afn_vals, "Unknown"), af);
                saf = tvb_get_guint8(tvb, o + i + aoff + 2) ;
		proto_tree_add_text(subtree2, tvb, o + i + aoff + 2, 1,
		    "Subsequent address family identifier: %s (%u)",
		    val_to_str(saf, bgpattr_nlri_safi, saf >= 128 ? "Vendor specific" : "Unknown"),
		    saf);
		ti = proto_tree_add_text(subtree2, tvb, o + i + aoff + 3,
			alen - 3, "Withdrawn routes (%u %s)", alen - 3,
                        (alen - 3 == 1) ? "byte" : "bytes");

		alen -= 3;
		aoff += 3;
		if (alen > 0) {
                        subtree3 = proto_item_add_subtree(ti,ett_bgp_mp_unreach_nlri);

                        while (alen > 0) {
                                advance = decode_prefix_MP(af, saf, tvb, o + i + aoff , junk_buf, sizeof(junk_buf)) ;

                                proto_tree_add_text(subtree3, tvb, o + i + aoff, advance, "%s", junk_buf) ;
		                alen -= advance;
		                aoff += advance;
                        }
                }
                break;
	    case BGPTYPE_CLUSTER_LIST:
		if (alen % 4 != 0) {
		    proto_tree_add_text(subtree2, tvb, o + i + aoff, alen,
			    "Cluster list (invalid): %u %s", alen,
                            (alen == 1) ? "byte" : "bytes");
                    free(cluster_list_str);
                    break;
                }

                ti = proto_tree_add_text(subtree2, tvb, o + i + aoff, alen,
                        "Cluster list: %s", cluster_list_str);
                cluster_list_tree = proto_item_add_subtree(ti,
                        ett_bgp_cluster_list);

                /* (o + i + aoff) =
                   (o + current attribute + aoff bytes to first tuple) */
                q = o + i + aoff;
                end = q + alen;

                /* snarf each cluster identifier */
                while (q < end) {
		    tvb_memcpy(tvb, ipaddr, q, 4);
                    ti = proto_tree_add_text(cluster_list_tree, tvb,
                            q - 3 + aoff, 4, "Cluster identifier: %s",
                            ip_to_str(ipaddr));

                    q += 4;
                }

                free(cluster_list_str);
		break;
                case BGPTYPE_EXTENDED_COMMUNITY:
		if (alen %8 != 0) {
                        proto_tree_add_text(subtree3, tvb, o + i + aoff, alen, "Extended community (invalid) : %u %s", alen,
                                (alen == 1) ? "byte" : "bytes") ;
                } else {
                        q = o + i + aoff ;
                        end = o + i + aoff + alen ;
                        ext_com_str = malloc(MAX_SIZE_OF_EXT_COM_NAMES+MAX_SIZE_OF_IP_ADDR_STRING*2+1) ;
                        if (ext_com_str == NULL) break ;
                        ti = proto_tree_add_text(subtree2,tvb,q,alen, "Carried Extended communities");
                        subtree3 = proto_item_add_subtree(ti,ett_bgp_extended_communities) ;

                        while (q < end) {
			  ext_com_str[0] = '\0' ;
			  ext_com = tvb_get_ntohs(tvb,q) ;
			  snprintf(junk_buf, sizeof(junk_buf), "%s", val_to_str(ext_com,bgpext_com_type,"Unknown"));
			  strncat(ext_com_str,junk_buf,sizeof(junk_buf));
			  switch (ext_com) {
			  case BGP_EXT_COM_RT_0:
			  case BGP_EXT_COM_RO_0:
			    snprintf(junk_buf, sizeof(junk_buf), ": %u%s%d",tvb_get_ntohs(tvb,q+2),":",tvb_get_ntohl(tvb,q+4));
			    break ;
			  case BGP_EXT_COM_RT_1:
			  case BGP_EXT_COM_RO_1:
			    tvb_memcpy(tvb,ipaddr,q+2,4);
			    snprintf(junk_buf, sizeof(junk_buf), ": %s%s%u",ip_to_str(ipaddr),":",tvb_get_ntohs(tvb,q+6));
			    break;
			  case BGP_EXT_COM_VPN_ORIGIN:
			  case BGP_EXT_COM_OSPF_RID:
			    tvb_memcpy(tvb,ipaddr,q+2,4);
			    snprintf(junk_buf, sizeof(junk_buf), ": %s",ip_to_str(ipaddr));
			    break;
			  case BGP_EXT_COM_OSPF_RTYPE: 
			    tvb_memcpy(tvb,ipaddr,q+2,4);
			    snprintf(junk_buf, sizeof(junk_buf), ": Area:%s %s",ip_to_str(ipaddr),val_to_str(tvb_get_guint8(tvb,q+6),bgpext_ospf_rtype,"Unknown"));
				/* print OSPF Metric type if selected */
				/* always print E2 even if not external route -- receiving router should ignore */
			    if ( (tvb_get_guint8(tvb,q+7)) & BGP_OSPF_RTYPE_METRIC_TYPE ) { 
			      strcat(junk_buf," E2");
			    } else if (tvb_get_guint8(tvb,q+6)==(BGP_OSPF_RTYPE_EXT ||BGP_OSPF_RTYPE_NSSA ) ) {
			      strcat(junk_buf, " E1");
			    }
			    break;
			  case BGP_EXT_COM_LINKBAND:
			    tvb_memcpy(tvb,ipaddr,q+2,4); /* need to check on IEEE format on all platforms */
			    snprintf(junk_buf, sizeof(junk_buf), ": %f bytes per second",(double)*ipaddr);
			    break;
			  default:
			    snprintf(junk_buf, sizeof(junk_buf), " ");
			    break ;
			  }
			  strncat(ext_com_str,junk_buf,sizeof(junk_buf));
			  proto_tree_add_text(subtree3,tvb,q,8, "%s",ext_com_str);
			  q = q + 8 ;
                        }
                        free(ext_com_str) ;
                }
                break;
	    default:
		proto_tree_add_text(subtree2, tvb, o + i + aoff, alen,
			"Unknown (%d %s)", alen, (alen == 1) ? "byte" :
                        "bytes");
		break;
	    } /* end of second switch */

	    i += alen + aoff;
	}

        o += 2 + len;

        /* NLRI */
        len = offset + hlen - o;

        /* parse prefixes */
        if (len > 0) {
           ti = proto_tree_add_text(tree, tvb, o, len,
                   "Network layer reachability information: %u %s", len,
                   (len == 1) ? "byte" : "bytes");
	    subtree = proto_item_add_subtree(ti, ett_bgp_nlri);
            end = o + len;
            while (o < end) {
                i = decode_prefix4(tvb, o, junk_buf, sizeof(junk_buf));
                proto_tree_add_text(subtree, tvb, o, i, "%s", junk_buf);
                o += i;
            }
        }
    }
}

/*
 * Dissect a BGP NOTIFICATION message.
 */
static void
dissect_bgp_notification(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    struct bgp_notification bgpn;   /* BGP NOTIFICATION message */
    int                     hlen;   /* message length           */
    char                    *p;     /* string pointer           */

    /* snarf message */
    tvb_memcpy(tvb, bgpn.bgpn_marker, offset, BGP_MIN_NOTIFICATION_MSG_SIZE);
    hlen = ntohs(bgpn.bgpn_len);

    /* print error code */
    proto_tree_add_text(tree, tvb,
	offset + offsetof(struct bgp_notification, bgpn_major), 1,
	"Error code: %s (%u)",
	val_to_str(bgpn.bgpn_major, bgpnotify_major, "Unknown"),
	bgpn.bgpn_major);

    /* print error subcode */
    if (bgpn.bgpn_major < array_length(bgpnotify_minor)
     && bgpnotify_minor[bgpn.bgpn_major] != NULL) {
	p = val_to_str(bgpn.bgpn_minor, bgpnotify_minor[bgpn.bgpn_major],
	    "Unknown");
    } else if (bgpn.bgpn_minor == 0)
	p = "Unspecified";
    else
        p = "Unknown";
    proto_tree_add_text(tree, tvb,
	offset + offsetof(struct bgp_notification, bgpn_minor), 1,
	"Error subcode: %s (%u)", p, bgpn.bgpn_minor);

    /* only print if there is optional data */
    if (hlen > BGP_MIN_NOTIFICATION_MSG_SIZE) {
        proto_tree_add_text(tree, tvb, offset + BGP_MIN_NOTIFICATION_MSG_SIZE,
	    hlen - BGP_MIN_NOTIFICATION_MSG_SIZE, "Data");
    }
}

/*
 * Dissect a BGP ROUTE-REFRESH message.
 */
static void
dissect_bgp_route_refresh(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    u_int        i;    /* tmp            */

    /* AFI */
    i = tvb_get_ntohs(tvb, offset + BGP_HEADER_SIZE);
    proto_tree_add_text(tree, tvb, offset + BGP_HEADER_SIZE, 2, 
                        "Address family identifier: %s (%u)",
                        val_to_str(i, afn_vals, "Unknown"), i);
    offset += 2;
    /* Reserved */
    proto_tree_add_text(tree, tvb, offset + BGP_HEADER_SIZE, 1, 
                        "Reserved: 1 byte");
    offset++;
    /* SAFI */
    i = tvb_get_guint8(tvb, offset + BGP_HEADER_SIZE);
    proto_tree_add_text(tree, tvb, offset + BGP_HEADER_SIZE, 1, 
                        "Subsequent address family identifier: %s (%u)",
                        val_to_str(i, bgpattr_nlri_safi,
                        i >= 128 ? "Vendor specific" : "Unknown"),
                        i);
}

/*
 * Dissect a BGP packet.
 */
static void
dissect_bgp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item    *ti;           /* tree item                        */
    proto_tree    *bgp_tree;     /* BGP packet tree                  */
    proto_tree    *bgp1_tree;    /* BGP message tree                 */
    int           l, i;          /* tmp                              */
    int           found;         /* number of BGP messages in packet */
    static u_char marker[] = {   /* BGP message marker               */
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    struct bgp    bgp;           /* BGP header                       */
    int           hlen;          /* BGP header length                */
    char          *typ;          /* BGP message type                 */

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BGP");
    if (check_col(pinfo->cinfo, COL_INFO))
	col_clear(pinfo->cinfo, COL_INFO);

    l = tvb_length(tvb);
    i = 0;
    found = -1;
    /* run through the TCP packet looking for BGP headers         */
    /* this is done twice, but this way each message type can be 
       printed in the COL_INFO field                              */
    while (i + BGP_HEADER_SIZE <= l) {
	tvb_memcpy(tvb, bgp.bgp_marker, i, BGP_HEADER_SIZE);

	/* look for bgp header */
	if (memcmp(bgp.bgp_marker, marker, sizeof(marker)) != 0) {
	    i++;
	    continue;
	}

	found++;
	hlen = ntohs(bgp.bgp_len);
	typ = val_to_str(bgp.bgp_type, bgptypevals, "Unknown Message");

	if (check_col(pinfo->cinfo, COL_INFO)) {
	    if (found == 0)
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s", typ);
	    else
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", typ);
	}

	i += hlen;
    }

    if (tree) {
        ti = proto_tree_add_item(tree, proto_bgp, tvb, 0,
				 l, FALSE);
	bgp_tree = proto_item_add_subtree(ti, ett_bgp);

	i = 0;
        /* now, run through the TCP packet again, this time dissect */
        /* each message that we find */
	while (i + BGP_HEADER_SIZE <= l) {
	    tvb_memcpy(tvb, bgp.bgp_marker, i, BGP_HEADER_SIZE);

	    /* look for bgp header */
	    if (memcmp(bgp.bgp_marker, marker, sizeof(marker)) != 0) {
		i++;
		continue;
	    }

	    hlen = ntohs(bgp.bgp_len);
	    typ = val_to_str(bgp.bgp_type, bgptypevals, "Unknown Message");
	    if (l < hlen) {
		ti = proto_tree_add_text(bgp_tree, tvb, i,
                     l, "%s (truncated)", typ);
	    } else {
		ti = proto_tree_add_text(bgp_tree, tvb, i, hlen,
			    "%s", typ);
	    }
	    /* add a different tree for each message type */
	    switch (bgp.bgp_type) {
	    case BGP_OPEN:
	        bgp1_tree = proto_item_add_subtree(ti, ett_bgp_open);
		break;
	    case BGP_UPDATE:
	        bgp1_tree = proto_item_add_subtree(ti, ett_bgp_update);
		break;
	    case BGP_NOTIFICATION:
	        bgp1_tree = proto_item_add_subtree(ti, ett_bgp_notification);
		break;
	    case BGP_KEEPALIVE:
	        bgp1_tree = proto_item_add_subtree(ti, ett_bgp);
		break;
            case BGP_ROUTE_REFRESH_CISCO:
	    case BGP_ROUTE_REFRESH:
	        bgp1_tree = proto_item_add_subtree(ti, ett_bgp_route_refresh);
		break;
	    default:
	        bgp1_tree = proto_item_add_subtree(ti, ett_bgp);
		break;
	    }

	    proto_tree_add_text(bgp1_tree, tvb, i, BGP_MARKER_SIZE,
		"Marker: 16 bytes");

	    if (hlen < BGP_HEADER_SIZE || hlen > BGP_MAX_PACKET_SIZE) {
		proto_tree_add_text(bgp1_tree, tvb,
		    i + offsetof(struct bgp, bgp_len), 2,
		    "Length (invalid): %u %s", hlen,
		    (hlen == 1) ? "byte" : "bytes");
	    } else {
		proto_tree_add_text(bgp1_tree, tvb,
		    i + offsetof(struct bgp, bgp_len), 2,
		    "Length: %u %s", hlen,
		    (hlen == 1) ? "byte" : "bytes");
	    }

	    proto_tree_add_uint_format(bgp1_tree, hf_bgp_type, tvb,
				       i + offsetof(struct bgp, bgp_type), 1,
				       bgp.bgp_type,
				       "Type: %s (%u)", typ, bgp.bgp_type);

	    switch (bgp.bgp_type) {
	    case BGP_OPEN:
		dissect_bgp_open(tvb, i, bgp1_tree);
		break;
	    case BGP_UPDATE:
		dissect_bgp_update(tvb, i, bgp1_tree);
		break;
	    case BGP_NOTIFICATION:
		dissect_bgp_notification(tvb, i, bgp1_tree);
		break;
	    case BGP_KEEPALIVE:
		/* no data in KEEPALIVE messages */
		break;
            case BGP_ROUTE_REFRESH_CISCO:
	    case BGP_ROUTE_REFRESH:
		dissect_bgp_route_refresh(tvb, i, bgp1_tree);
		break;
	    default:
		break;
	    }

	    i += hlen;
	}
    }
}

/*
 * Register ourselves.
 */
void
proto_register_bgp(void)
{

    static hf_register_info hf[] = {
      { &hf_bgp_type,
	{ "BGP message type", "bgp.type", FT_UINT8, BASE_HEX,
	  VALS(bgptypevals), 0x0, "BGP message type", HFILL }},
    };

    static gint *ett[] = {
      &ett_bgp,
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
      &ett_bgp_as_paths,
      &ett_bgp_communities,
      &ett_bgp_cluster_list,
      &ett_bgp_options,
      &ett_bgp_option,
      &ett_bgp_extended_communities
    };

    proto_bgp = proto_register_protocol("Border Gateway Protocol",
					"BGP", "bgp");
    proto_register_field_array(proto_bgp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_bgp(void)
{
    dissector_handle_t bgp_handle;

    bgp_handle = create_dissector_handle(dissect_bgp, proto_bgp);
    dissector_add("tcp.port", BGP_TCP_PORT, bgp_handle);
}
