/* packet-bgp.c
 * Routines for BGP packet dissection.
 * Copyright 1999, Jun-ichiro itojun Hagino <itojun@itojun.org>
 *
 * $Id: packet-bgp.c,v 1.36 2001/05/16 18:52:35 guy Exp $
 * 
 * Supports:
 * RFC1771 A Border Gateway Protocol 4 (BGP-4)
 * RFC1965 Autonomous System Confederations for BGP 
 * RFC1997 BGP Communities Attribute
 * RFC2796 BGP Route Reflection An alternative to full mesh IBGP
 * RFC2842 Capabilities Advertisement with BGP-4
 * RFC2858 Multiprotocol Extensions for BGP-4
 * RFC2918 Route Refresh Capability for BGP-4
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
    { 0, NULL },
};

/* Subsequent address family identifier, RFC2283 section 7 */
static const value_string bgpattr_nlri_safi[] = {
    { 0, "Reserved" },
    { 1, "Unicast" },
    { 2, "Multicast" },
    { 3, "Unicast+Multicast" },
    { 0, NULL },
};

static const value_string afnumber[] = {
    { 0, "Reserved" },
    { AFNUM_INET, "IPv4" },
    { AFNUM_INET6, "IPv6" },
    { AFNUM_NSAP, "NSAP" },
    { AFNUM_HDLC, "HDLC" },
    { AFNUM_BBN1822, "BBN 1822" },
    { AFNUM_802, "802" },
    { AFNUM_E163, "E.163" },
    { AFNUM_E164, "E.164" },
    { AFNUM_F69, "F.69" },
    { AFNUM_X121, "X.121" },
    { AFNUM_IPX, "IPX" },
    { AFNUM_ATALK, "Appletalk" },
    { AFNUM_DECNET, "Decnet IV" },
    { AFNUM_BANYAN, "Banyan Vines" },
    { AFNUM_E164NSAP, "E.164 with NSAP subaddress" },
    { 65535, "Reserved" },
    { 0, NULL },
};

static int proto_bgp = -1;
static int hf_bgp_type = -1;

static gint ett_bgp = -1;
static gint ett_bgp_unfeas = -1;
static gint ett_bgp_attrs = -1;
static gint ett_bgp_attr = -1;
static gint ett_bgp_attr_flags = -1;
static gint ett_bgp_mp_reach_nlri = -1;
static gint ett_bgp_mp_unreach_nlri = -1;
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
    int             ostart;    /* options start         */
    int             oend;      /* options end           */
    int             p;         /* tvb offset counter    */
    proto_item      *ti;       /* tree item             */
    proto_tree      *subtree;  /* subtree for options   */
    proto_tree      *subtree2; /* subtree for an option */
    proto_tree      *subtree3; /* subtree for an option */

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
                ctype = tvb_get_guint8(tvb, p++);
                clen = tvb_get_guint8(tvb, p++);

                /* check the capability type */
                switch (ctype) {
                case BGP_CAPABILITY_RESERVED:
                    ti = proto_tree_add_text(subtree, tvb, p - 4, 
                         2 + plen, "Reserved capability (%u %s)", 2 + plen,
                         (plen == 1) ? "byte" : "bytes");
                    subtree2 = proto_item_add_subtree(ti, ett_bgp_option);
                    proto_tree_add_text(subtree2, tvb, p - 4, 
                         1, "Parameter type: Capabilities (2)");
                    proto_tree_add_text(subtree2, tvb, p - 3, 
                         1, "Parameter length: %u %s", plen, 
                         (plen == 1) ? "byte" : "bytes");
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
                    ti = proto_tree_add_text(subtree, tvb, p - 4, 
                         2 + plen, 
                         "Multiprotocol extensions capability (%u %s)",  
                         2 + plen, (plen == 1) ? "byte" : "bytes");
                    subtree2 = proto_item_add_subtree(ti, ett_bgp_option);
                    proto_tree_add_text(subtree2, tvb, p - 4, 
                         1, "Parameter type: Capabilities (2)");
                    proto_tree_add_text(subtree2, tvb, p - 3, 
                         1, "Parameter length: %u %s", plen, 
                         (plen == 1) ? "byte" : "bytes");
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
                             val_to_str(i, afnumber, "Unknown"), i);
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
                    ti = proto_tree_add_text(subtree, tvb, p - 4, 
                         2 + plen, "Route refresh capability (%u %s)", 2 + plen,
                         (plen == 1) ? "byte" : "bytes");
                    subtree2 = proto_item_add_subtree(ti, ett_bgp_option);
                    proto_tree_add_text(subtree2, tvb, p - 4, 
                         1, "Parameter type: Capabilities (2)");
                    proto_tree_add_text(subtree2, tvb, p - 3, 
                         1, "Parameter length: %u %s", plen, 
                         (plen == 1) ? "byte" : "bytes");
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
                /* unknown capability */
                default:
                    ti = proto_tree_add_text(subtree, tvb, p - 4, 
                         2 + plen, "Unknown capability (%u %s)", 2 + plen,
                         (plen == 1) ? "byte" : "bytes");
                    subtree2 = proto_item_add_subtree(ti, ett_bgp_option);
                    proto_tree_add_text(subtree2, tvb, p - 4, 
                         1, "Parameter type: Capabilities (2)");
                    proto_tree_add_text(subtree2, tvb, p - 3, 
                         1, "Parameter length: %u %s", plen, 
                         (plen == 1) ? "byte" : "bytes");
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
    int             len;                        /* tmp                      */
    proto_item      *ti;                        /* tree item                */
    proto_tree      *subtree;                   /* subtree for attibutes    */ 
    proto_tree      *subtree2;                  /* subtree for attibutes    */ 
    proto_tree      *subtree3;                  /* subtree for attibutes    */
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
    char            junk_buf[256];              /* tmp                      */
    guint8          ipaddr[4];                  /* IPv4 address             */
    struct e_in6_addr ip6addr;                  /* IPv6 address             */

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
	    int off, snpa;

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
                /* (o + i + 3) =
                   (o + current attribute + 3 bytes to first tuple) */ 
                end = o + alen + i + 3;
                q = o + i + 3;
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

                /* (o + i + 3) =
                   (o + current attribute + 3 bytes to first tuple) */ 
                end = o + alen + i + 3;
                q = o + i + 3;
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

                /* (o + i + 3) =
                   (o + current attribute + 3 bytes to first tuple) */ 
                end = o + alen + i + 3;
                q = o + i + 3;
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

                /* (o + i + 3) =
                   (o + current attribute + 3 bytes to first tuple) */ 
                end = o + alen + i + 3;
                q = o + i + 3;
   
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

                /* (o + i + 3) =
                   (o + current attribute + 3 bytes to first tuple) */
                end = o + alen + i + 3;
                q = o + i + 3;

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
		af = tvb_get_ntohs(tvb, o + i + aoff);
		proto_tree_add_text(subtree2, tvb, o + i + aoff, 2,
		    "Address family: %s (%u)",
		    val_to_str(af, afnumber, "Unknown"), af);
		proto_tree_add_text(subtree2, tvb, o + i + aoff + 2, 1,
		    "Subsequent address family identifier: %s (%u)",
		    val_to_str(tvb_get_guint8(tvb, o + i + aoff + 2), bgpattr_nlri_safi,
			tvb_get_guint8(tvb, o + i + aoff + 2) >= 128 ? "Vendor specific" : "Unknown"),
		    tvb_get_guint8(tvb, o + i + aoff + 2));
		ti = proto_tree_add_text(subtree2, tvb, o + i + aoff + 3, 1,
			"Next hop network address (%d %s)",
			tvb_get_guint8(tvb, o + i + aoff + 3),
			(tvb_get_guint8(tvb, o + i + aoff + 3) == 1) ? "byte" : "bytes");
		if (af == AFNUM_INET || af == AFNUM_INET6) {
		    int j, advance;
		    const char *s;

		    subtree3 = proto_item_add_subtree(ti, 
                            ett_bgp_mp_reach_nlri);

		    j = 0;
		    while (j < tvb_get_guint8(tvb, o + i + aoff + 3)) {
			if (af == AFNUM_INET)
			    advance = 4;
			else if (af == AFNUM_INET6)
			    advance = 16;
			else
			    break;
			if (j + advance > tvb_get_guint8(tvb, o + i + aoff + 3))
			    break;

			if (af == AFNUM_INET) {
			    tvb_memcpy(tvb, ipaddr, o + i + aoff + 4 + j, 4);
			    s = ip_to_str(ipaddr);
			} else {
			    tvb_memcpy(tvb, ip6addr.u6_addr.u6_addr8,
				       o + i + aoff + 4 + j, sizeof ip6addr);
			    s = ip6_to_str(&ip6addr);
			}
			proto_tree_add_text(subtree3, tvb,
			    o + i + aoff + 4 + j, advance,
			    "Next hop: %s", s);
			j += advance;
		    }
		}

		alen -= tvb_get_guint8(tvb, o + i + aoff + 3) + 4;
		aoff += tvb_get_guint8(tvb, o + i + aoff + 3) + 4;
		off = 0;
		snpa = tvb_get_guint8(tvb, o + i + aoff);
		ti = proto_tree_add_text(subtree2, tvb, o + i + aoff, 1,
			"Subnetwork points of attachment: %u", snpa);
		off++;
		if (snpa)
		    subtree3 = proto_item_add_subtree(ti, 
                            ett_bgp_mp_reach_nlri);
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

		alen -= off;
		aoff += off;
		ti = proto_tree_add_text(subtree2, tvb, o + i + aoff, alen,
			"Network layer reachability information (%u %s)",
			alen, (alen == 1) ? "byte" : "bytes");
		if (alen)
		    subtree3 = proto_item_add_subtree(ti, 
                            ett_bgp_mp_unreach_nlri);
		while (alen > 0) {
		    int advance;
		    char buf[256];

		    if (af == AFNUM_INET) {
			advance = decode_prefix4(tvb, o + i + aoff, buf,
			    sizeof(buf));
		    } else if (af == AFNUM_INET6) {
			advance = decode_prefix6(tvb, o + i + aoff, buf,
			    sizeof(buf));
		    } else
			break;
		    if (advance < 0)
			break;
		    if (alen < advance)
			break;
		    proto_tree_add_text(subtree3, tvb, o + i + aoff, advance,
			"Network layer reachability information: %s", buf);

		    alen -= advance;
		    aoff += advance;
		}

		break;
	    case BGPTYPE_MP_UNREACH_NLRI:
	        af = tvb_get_ntohs(tvb, o + i + aoff);	
		proto_tree_add_text(subtree2, tvb, o + i + aoff, 2,
		    "Address family: %s (%u)",
		    val_to_str(af, afnumber, "Unknown"), af);
		proto_tree_add_text(subtree2, tvb, o + i + aoff + 2, 1,
		    "Subsequent address family identifier: %s (%u)",
		    val_to_str(tvb_get_guint8(tvb, o + i + aoff + 2), bgpattr_nlri_safi,
			tvb_get_guint8(tvb, o + i + aoff + 2) >= 128 ? "Vendor specific" : "Unknown"),
		    tvb_get_guint8(tvb, o + i + aoff + 2));
		ti = proto_tree_add_text(subtree2, tvb, o + i + aoff + 3,
			alen - 3, "Withdrawn routes (%u %s)", alen - 3,
                        (alen - 3 == 1) ? "byte" : "bytes");

		alen -= 3;
		aoff += 3;
		if (alen > 0)
		    subtree3 = proto_item_add_subtree(ti, 
                            ett_bgp_mp_unreach_nlri);
		while (alen > 0) {
		    int advance;
		    char buf[256];

		    if (af == AFNUM_INET) {
			advance = decode_prefix4(tvb, o + i + aoff, buf,
			    sizeof(buf));
		    } else if (af == AFNUM_INET6) {
			advance = decode_prefix6(tvb, o + i + aoff, buf,
			    sizeof(buf));
		    } else
			break;
		    if (advance < 0)
			break;
		    if (alen < advance)
			break;
		    proto_tree_add_text(subtree3, tvb, o + i + aoff, advance,
			"Withdrawn route: %s", buf);

		    alen -= advance;
		    aoff += advance;
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

                /* (p + i + 3) =
                   (p + current attribute + 3 bytes to first tuple) */
                end = o + alen + i + 3;
                q = o + i + 3;

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
                        val_to_str(i, afnumber, "Unknown"), i);
    offset += 2;
    /* Reserved */
    proto_tree_add_text(tree, tvb, offset + BGP_HEADER_SIZE + 2, 1, 
                        "Reserved: 1 byte");
    offset++;
    /* SAFI */
    i = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(tree, tvb, offset + BGP_HEADER_SIZE + 3, 1, 
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

    pinfo->current_proto = "BGP";
    if (check_col(pinfo->fd, COL_PROTOCOL))
	col_set_str(pinfo->fd, COL_PROTOCOL, "BGP");
    if (check_col(pinfo->fd, COL_INFO))
	col_clear(pinfo->fd, COL_INFO);

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

	if (check_col(pinfo->fd, COL_INFO)) {
	    if (found == 0) 
		col_add_fstr(pinfo->fd, COL_INFO, "%s", typ);
	    else
		col_append_fstr(pinfo->fd, COL_INFO, ", %s", typ);
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
	  VALS(bgptypevals), 0x0, "BGP message type" }},
    };

    static gint *ett[] = {
      &ett_bgp,
      &ett_bgp_unfeas,
      &ett_bgp_attrs,
      &ett_bgp_attr,
      &ett_bgp_attr_flags,
      &ett_bgp_mp_reach_nlri,
      &ett_bgp_mp_unreach_nlri,
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
    };

    proto_bgp = proto_register_protocol("Border Gateway Protocol",
					"BGP", "bgp");
    proto_register_field_array(proto_bgp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_bgp(void)
{
    dissector_add("tcp.port", BGP_TCP_PORT, dissect_bgp, proto_bgp);
}
