/* packet-icmpv6.c
 * Routines for ICMPv6 packet disassembly 
 *
 * $Id: packet-icmpv6.c,v 1.23 2000/08/22 08:30:00 itojun Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include "packet.h"
#include "packet-ipv6.h"
#include "packet-ip.h"
#include "packet-dns.h"
#include "resolv.h"

#ifndef offsetof
#define	offsetof(type, member)	((size_t)(&((type *)0)->member))
#endif

static int proto_icmpv6 = -1;
static int hf_icmpv6_type = -1;
static int hf_icmpv6_code = -1;
static int hf_icmpv6_checksum = -1;

static gint ett_icmpv6 = -1;
static gint ett_icmpv6opt = -1;
static gint ett_icmpv6flag = -1;
static gint ett_nodeinfo_flag = -1;
static gint ett_nodeinfo_subject4 = -1;
static gint ett_nodeinfo_subject6 = -1;
static gint ett_nodeinfo_node4 = -1;
static gint ett_nodeinfo_node6 = -1;
static gint ett_nodeinfo_nodebitmap = -1;
static gint ett_nodeinfo_nodedns = -1;

static const value_string names_nodeinfo_qtype[] = {
    { NI_QTYPE_NOOP,		"NOOP" },
    { NI_QTYPE_SUPTYPES,	"Supported query types" },
    { NI_QTYPE_DNSNAME,		"DNS name" },
    { NI_QTYPE_NODEADDR,	"Node addresses" },
    { NI_QTYPE_IPV4ADDR, 	"IPv4 node addresses" },
    { 0,			NULL }
};

static void
dissect_icmpv6opt(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
    proto_tree *icmp6opt_tree, *field_tree;
	proto_item *ti, *tf;
    struct nd_opt_hdr *opt;
    int len;
    char *typename;

    if (!tree)
	return;

again:
    if (!IS_DATA_IN_FRAME(offset))
	return;

    opt = (struct nd_opt_hdr *)&pd[offset];
    len = opt->nd_opt_len << 3;

    /* !!! specify length */
    ti = proto_tree_add_text(tree, NullTVB, offset, len, "ICMPv6 options");
    icmp6opt_tree = proto_item_add_subtree(ti, ett_icmpv6opt);

    switch (opt->nd_opt_type) {
    case ND_OPT_SOURCE_LINKADDR:
	typename = "Source link-layer address";
	break;
    case ND_OPT_TARGET_LINKADDR:
	typename = "Target link-layer address";
	break;
    case ND_OPT_PREFIX_INFORMATION:
	typename = "Prefix information";
	break;
    case ND_OPT_REDIRECTED_HEADER:
	typename = "Redirected header";
	break;
    case ND_OPT_MTU:
	typename = "MTU";
	break;
    default:
	typename = "Unknown";
	break;
    }

    proto_tree_add_text(icmp6opt_tree, NullTVB,
	offset + offsetof(struct nd_opt_hdr, nd_opt_type), 1,
	"Type: 0x%02x (%s)", opt->nd_opt_type, typename);
    proto_tree_add_text(icmp6opt_tree, NullTVB,
	offset + offsetof(struct nd_opt_hdr, nd_opt_len), 1,
	"Length: %d bytes (0x%02x)", opt->nd_opt_len << 3, opt->nd_opt_len);

    /* decode... */
    switch (opt->nd_opt_type) {
    case ND_OPT_SOURCE_LINKADDR:
    case ND_OPT_TARGET_LINKADDR:
      {
	char *t;
	const char *p;
	int len, i;
	len = (opt->nd_opt_len << 3) - sizeof(*opt);
	t = (char *)malloc(len * 3);
	memset(t, 0, len * 3);
	p = &pd[offset + sizeof(*opt)];
	for (i = 0; i < len; i++) {
	    if (i)
		t[i * 3 - 1] = ':';
	    sprintf(&t[i * 3], "%02x", p[i] & 0xff);
	}
	proto_tree_add_text(icmp6opt_tree, NullTVB,
	    offset + sizeof(*opt), len, "Link-layer address: %s", t);
	break;
      }
    case ND_OPT_PREFIX_INFORMATION:
      {
	struct nd_opt_prefix_info *pi = (struct nd_opt_prefix_info *)opt;
	int flagoff;
	proto_tree_add_text(icmp6opt_tree, NullTVB,
	    offset + offsetof(struct nd_opt_prefix_info, nd_opt_pi_prefix_len),
	    1, "Prefix length: %d", pi->nd_opt_pi_prefix_len);

	flagoff = offsetof(struct nd_opt_prefix_info, nd_opt_pi_flags_reserved);
	tf = proto_tree_add_text(icmp6opt_tree, NullTVB, flagoff, 1, "Flags: 0x%02x",
	    pntohl(&pi->nd_opt_pi_flags_reserved));
	field_tree = proto_item_add_subtree(tf, ett_icmpv6flag);
	proto_tree_add_text(field_tree, NullTVB, flagoff, 1, "%s",
	    decode_boolean_bitfield(pi->nd_opt_pi_flags_reserved,
		    0x80, 8, "Onlink", "Not onlink"));
	proto_tree_add_text(field_tree, NullTVB, flagoff, 1, "%s",
	    decode_boolean_bitfield(pi->nd_opt_pi_flags_reserved,
		    0x40, 8, "Auto", "Not auto"));

	proto_tree_add_text(icmp6opt_tree, NullTVB,
	    offset + offsetof(struct nd_opt_prefix_info, nd_opt_pi_valid_time),
	    4, "Valid lifetime: 0x%08x",
	    pntohl(&pi->nd_opt_pi_valid_time));
	proto_tree_add_text(icmp6opt_tree, NullTVB,
	    offset + offsetof(struct nd_opt_prefix_info, nd_opt_pi_preferred_time),
	    4, "Preferred lifetime: 0x%08x",
	    pntohl(&pi->nd_opt_pi_preferred_time));
	proto_tree_add_text(icmp6opt_tree, NullTVB,
	    offset + offsetof(struct nd_opt_prefix_info, nd_opt_pi_prefix),
	    16, "Prefix: %s", ip6_to_str(&pi->nd_opt_pi_prefix));
	break;
      }
    case ND_OPT_REDIRECTED_HEADER:
	proto_tree_add_text(icmp6opt_tree, NullTVB,
	    offset + 8, (opt->nd_opt_len << 3) - 8, "Redirected packet");
	/* tiny sanity check */
	if ((pd[offset + 8] & 0xf0) == 0x60)
	    dissect_ipv6(pd, offset + 8, fd, icmp6opt_tree);
	else
	    old_dissect_data(pd, offset + 8, fd, icmp6opt_tree);
	break;
    case ND_OPT_MTU:
      {
	struct nd_opt_mtu *pi = (struct nd_opt_mtu *)opt;
	proto_tree_add_text(icmp6opt_tree, NullTVB,
	    offset + offsetof(struct nd_opt_mtu, nd_opt_mtu_mtu), 4,
	    "MTU: %d", pntohl(&pi->nd_opt_mtu_mtu));
	break;
      }
    }

    offset += (opt->nd_opt_len << 3);
    goto again;
}

/*
 * draft-ietf-ipngwg-icmp-name-lookups-06.txt
 * Note that the packet format was changed several times in the past.
 */

static const char *
bitrange0(v, s, buf, buflen)
	u_int32_t v;
	int s;
	char *buf;
	int buflen;
{
	u_int32_t v0;
	char *p, *ep;
	int off;
	int i, l;

	if (buflen < 1)
		return NULL;
	if (buflen == 1) {
		buf[0] = '\0';
		return NULL;
	}

	v0 = v;
	p = buf;
	ep = buf + buflen - 1;
	memset(buf, 0, buflen);
	off = 0;
	while (off < 32) {
		/* shift till we have 0x01 */
		if ((v & 0x01) == 0) {
			switch (v & 0x0f) {
			case 0x00:
				v >>= 4; off += 4; continue;
			case 0x08:
				v >>= 3; off += 3; continue;
			case 0x04: case 0x0c:
				v >>= 2; off += 2; continue;
			default:
				v >>= 1; off += 1; continue;
			}
		}

		/* we have 0x01 with us */
		for (i = 0; i < 32 - off; i++) {
			if ((v & (0x01 << i)) == 0)
				break;
		}
		if (i == 1)
			l = snprintf(p, ep - p, ",%d", s + off);
		else {
			l = snprintf(p, ep - p, ",%d-%d", s + off,
			    s + off + i - 1);
		}
		if (l > ep - p) {
			buf[0] = '\0';
			return NULL;
		}
		v >>= i; off += i;
	}

	return buf;
}

static const char *
bitrange(u_char *p, int l, int s)
{
    static char buf[1024];
    char *q, *eq;
    int i;

    memset(buf, 0, sizeof(buf));
    q = buf;
    eq = buf + sizeof(buf) - 1;
    for (i = 0; i < l; i++) {
	if (bitrange0(pntohl(p + i * 4), s + i * 4, q, eq - q) == NULL) {
	    if (q != buf && q + 5 < buf + sizeof(buf))
		strncpy(q, ",...", 5);
	    return buf;
	}
    }

    return buf + 1;
}

static void
dissect_nodeinfo(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
    proto_tree *field_tree;
	proto_item *tf;
    struct icmp6_nodeinfo *ni;
    int off;
    int i, n, l;
    guint16 flags;
    u_char *p;
    char dname[MAXDNAME];

    ni = (struct icmp6_nodeinfo *)&pd[offset];

    /* flags */
    flags = pntohs(&ni->ni_flags);
    tf = proto_tree_add_text(tree, NullTVB,
	offset + offsetof(struct icmp6_nodeinfo, ni_flags),
	sizeof(ni->ni_flags), "Flags: 0x%04x", flags);
    field_tree = proto_item_add_subtree(tf, ett_nodeinfo_flag);
    switch (pntohs(&ni->ni_qtype)) {
    case NI_QTYPE_SUPTYPES:
	if (ni->ni_type == ICMP6_NI_QUERY) {
	    proto_tree_add_text(field_tree, NullTVB,
		offset + offsetof(struct icmp6_nodeinfo, ni_flags),
		sizeof(ni->ni_flags), "%s",
		decode_boolean_bitfield(flags, 0x0001, sizeof(flags) * 8,
		    "Compressed reply supported",
		    "No compressed reply support"));
	} else {
	    proto_tree_add_text(field_tree, NullTVB,
		offset + offsetof(struct icmp6_nodeinfo, ni_flags),
		sizeof(ni->ni_flags), "%s",
		decode_boolean_bitfield(flags, 0x0001, sizeof(flags) * 8,
		    "Compressed", "Not compressed"));
	}
	break;
    case NI_QTYPE_DNSNAME:
	if (ni->ni_type == ICMP6_NI_REPLY) {
	    proto_tree_add_text(field_tree, NullTVB,
		offset + offsetof(struct icmp6_nodeinfo, ni_flags),
		sizeof(ni->ni_flags), "%s",
		decode_boolean_bitfield(flags, 0x0001, sizeof(flags) * 8,
		    "Valid TTL field", "Meaningless TTL field"));
	}
	break;
    case NI_QTYPE_NODEADDR:
	proto_tree_add_text(field_tree, NullTVB,
	    offset + offsetof(struct icmp6_nodeinfo, ni_flags),
	    sizeof(ni->ni_flags), "%s",
	    decode_boolean_bitfield(flags, 0x0020, sizeof(flags) * 8,
		"Global address",
		"Not global address"));
	proto_tree_add_text(field_tree, NullTVB,
	    offset + offsetof(struct icmp6_nodeinfo, ni_flags),
	    sizeof(ni->ni_flags), "%s",
	    decode_boolean_bitfield(flags, 0x0010, sizeof(flags) * 8,
		"Site-local address",
		"Not site-local address"));
	proto_tree_add_text(field_tree, NullTVB,
	    offset + offsetof(struct icmp6_nodeinfo, ni_flags),
	    sizeof(ni->ni_flags), "%s",
	    decode_boolean_bitfield(flags, 0x0008, sizeof(flags) * 8,
		"Link-local address",
		"Not link-local address"));
	proto_tree_add_text(field_tree, NullTVB,
	    offset + offsetof(struct icmp6_nodeinfo, ni_flags),
	    sizeof(ni->ni_flags), "%s",
	    decode_boolean_bitfield(flags, 0x0004, sizeof(flags) * 8,
		"IPv4 compatible/mapped address",
		"Not IPv4 compatible/mapped address"));
	/* fall through */
    case NI_QTYPE_IPV4ADDR:
	proto_tree_add_text(field_tree, NullTVB,
	    offset + offsetof(struct icmp6_nodeinfo, ni_flags),
	    sizeof(ni->ni_flags), "%s",
	    decode_boolean_bitfield(flags, 0x0002, sizeof(flags) * 8,
		"All unicast address",
		"Unicast addresses on the queried interface"));
	proto_tree_add_text(field_tree, NullTVB,
	    offset + offsetof(struct icmp6_nodeinfo, ni_flags),
	    sizeof(ni->ni_flags), "%s",
	    decode_boolean_bitfield(flags, 0x0001, sizeof(flags) * 8,
		"Truncated", "Not truncated"));
	break;
    }

    /* nonce */
    proto_tree_add_text(tree, NullTVB,
	offset + offsetof(struct icmp6_nodeinfo, icmp6_ni_nonce[0]),
	sizeof(ni->icmp6_ni_nonce), "Nonce: 0x%08x%08x",
	pntohl(&ni->icmp6_ni_nonce[0]), pntohl(&ni->icmp6_ni_nonce[4]));

    /* offset for "the rest of data" */
    off = sizeof(*ni);

    /* rest of data */
    if (!IS_DATA_IN_FRAME(offset + sizeof(*ni)))
	goto nodata;
    if (ni->ni_type == ICMP6_NI_QUERY) {
	switch (ni->ni_code) {
	case ICMP6_NI_SUBJ_IPV6:
	    n = pi.captured_len - (offset + sizeof(*ni));
	    n /= sizeof(struct e_in6_addr);
	    tf = proto_tree_add_text(tree, NullTVB,
		offset + sizeof(*ni), END_OF_FRAME, "IPv6 subject addresses");
	    field_tree = proto_item_add_subtree(tf, ett_nodeinfo_subject6);
	    p = (u_char *)(ni + 1);
	    for (i = 0; i < n; i++) {
		proto_tree_add_text(field_tree, NullTVB,
		    p - pd, sizeof(struct e_in6_addr),
		    "%s", ip6_to_str((struct e_in6_addr *)p));
		p += sizeof(struct e_in6_addr);
	    }
	    off = pi.captured_len - offset;
	    break;
	case ICMP6_NI_SUBJ_FQDN:
	    l = get_dns_name(pd, offset + sizeof(*ni), offset + sizeof(*ni),
		dname, sizeof(dname));
	    if (IS_DATA_IN_FRAME(offset + sizeof(*ni) + l) &&
	        pd[offset + sizeof(*ni) + l] == 0) {
		l++;
		proto_tree_add_text(tree, NullTVB, offset + sizeof(*ni), l,
		    "DNS label: %s (truncated)", dname);
	    } else {
		proto_tree_add_text(tree, NullTVB, offset + sizeof(*ni), l,
		    "DNS label: %s", dname);
	    }
	    off = offset + sizeof(*ni) + l;
	    break;
	case ICMP6_NI_SUBJ_IPV4:
	    n = pi.captured_len - (offset + sizeof(*ni));
	    n /= sizeof(guint32);
	    tf = proto_tree_add_text(tree, NullTVB,
		offset + sizeof(*ni), END_OF_FRAME, "IPv4 subject addresses");
	    field_tree = proto_item_add_subtree(tf, ett_nodeinfo_subject4);
	    p = (u_char *)(ni + 1);
	    for (i = 0; i < n; i++) {
		proto_tree_add_text(field_tree, NullTVB,
		    p - pd, sizeof(guint32), "%s", ip_to_str(p));
		p += sizeof(guint32);
	    }
	    off = pi.captured_len - offset;
	    break;
	}
    } else {
	switch (pntohs(&ni->ni_qtype)) {
	case NI_QTYPE_NOOP:
	    break;
	case NI_QTYPE_SUPTYPES:
	    p = (u_char *)(ni + 1);
	    tf = proto_tree_add_text(tree, NullTVB,
		offset + sizeof(*ni), END_OF_FRAME,
		"Supported type bitmap%s",
		(flags & 0x0001) ? ", compressed" : "");
	    field_tree = proto_item_add_subtree(tf,
		ett_nodeinfo_nodebitmap);
	    n = 0;
	    while (IS_DATA_IN_FRAME(p - pd)) {
		if ((flags & 0x0001) == 0) {
		    l = pi.captured_len - (offset + sizeof(*ni));
		    l /= sizeof(guint32);
		    i = 0;
		} else {
		    if (!IS_DATA_IN_FRAME(p + sizeof(guint32) - 1 - pd))
			break;
		    l = pntohs(p);
		    i = pntohs(p + sizeof(guint16));	/*skip*/
		}
		if (n + l * 32 > (1 << 16))
		    break;
		if (n + (l + i) * 32 > (1 << 16))
		    break;
		if ((flags & 0x0001) == 0) {
		    proto_tree_add_text(field_tree, NullTVB, p - pd,
			l * 4, "Bitmap (%d to %d): %s", n, n + l * 32 - 1,
			bitrange(p, l, n));
		    p += l * 4;
		} else {
		    proto_tree_add_text(field_tree, NullTVB, p - pd,
			4 + l * 4, "Bitmap (%d to %d): %s", n, n + l * 32 - 1,
			bitrange(p + 4, l, n));
		    p += (4 + l * 4);
		}
		n += l * 32 + i * 32;
	    }
	    off = pi.captured_len - offset;
	    break;
	case NI_QTYPE_DNSNAME:
	    proto_tree_add_text(tree, NullTVB, offset + sizeof(*ni),
		sizeof(gint32), "TTL: %d", (gint32)pntohl(ni + 1));
	    tf = proto_tree_add_text(tree, NullTVB,
		offset + sizeof(*ni) + sizeof(guint32), END_OF_FRAME,
		"DNS labels");
	    field_tree = proto_item_add_subtree(tf, ett_nodeinfo_nodedns);
	    n = pi.captured_len;
	    i = offset + sizeof(*ni) + sizeof(guint32);
	    while (i < pi.captured_len) {
		l = get_dns_name(pd, i, offset + sizeof(*ni), dname,
		    sizeof(dname));
		if (IS_DATA_IN_FRAME(i + l) && pd[i + l] == 0) {
		    l++;
		    proto_tree_add_text(field_tree, NullTVB, i, l,
			"DNS label: %s (truncated)", dname);
		} else {
		    proto_tree_add_text(field_tree, NullTVB, i, l,
			"DNS label: %s", dname);
		}
		i += l;
	    }
	    off = pi.captured_len - offset;
	    break;
	case NI_QTYPE_NODEADDR:
	    n = pi.captured_len - (offset + sizeof(*ni));
	    n /= sizeof(struct e_in6_addr);
	    tf = proto_tree_add_text(tree, NullTVB,
		offset + sizeof(*ni), END_OF_FRAME, "IPv6 node addresses");
	    field_tree = proto_item_add_subtree(tf, ett_nodeinfo_node6);
	    p = (u_char *)(ni + 1);
	    for (i = 0; i < n; i++) {
		proto_tree_add_text(field_tree, NullTVB,
		    p - pd, sizeof(struct e_in6_addr),
		    "%s", ip6_to_str((struct e_in6_addr *)p));
		p += sizeof(struct e_in6_addr);
	    }
	    off = pi.captured_len - offset;
	    break;
	case NI_QTYPE_IPV4ADDR:
	    n = pi.captured_len - (offset + sizeof(*ni));
	    n /= sizeof(guint32);
	    tf = proto_tree_add_text(tree, NullTVB,
		offset + sizeof(*ni), END_OF_FRAME, "IPv4 node addresses");
	    field_tree = proto_item_add_subtree(tf, ett_nodeinfo_node4);
	    p = (u_char *)(ni + 1);
	    for (i = 0; i < n; i++) {
		proto_tree_add_text(field_tree, NullTVB,
		    p - pd, sizeof(guint32), "%s", ip_to_str(p));
		p += sizeof(guint32);
	    }
	    off = pi.captured_len - offset;
	    break;
	}
    }
nodata:;

    /* the rest of data */
    old_dissect_data(pd, offset + off, fd, tree);
}

static void
dissect_icmpv6(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
    proto_tree *icmp6_tree, *field_tree;
	proto_item *ti, *tf = NULL;
    struct icmp6_hdr *dp;
    struct icmp6_nodeinfo *ni = NULL;
    char *codename, *typename;
    char *colcodename, *coltypename;
    int len;

    OLD_CHECK_DISPLAY_AS_DATA(proto_icmpv6, pd, offset, fd, tree);

    dp = (struct icmp6_hdr *)&pd[offset];
    codename = typename = colcodename = coltypename = "Unknown";
    len = sizeof(*dp);
    switch (dp->icmp6_type) {
    case ICMP6_DST_UNREACH:
	typename = coltypename = "Unreachable";
	switch (dp->icmp6_code) {
	case ICMP6_DST_UNREACH_NOROUTE:
	    codename = colcodename = "Route unreachable";
	    break;
	case ICMP6_DST_UNREACH_ADMIN:
	    codename = colcodename = "Administratively prohibited";
	    break;
	case ICMP6_DST_UNREACH_NOTNEIGHBOR:
	    codename = colcodename = "Not a neighbor";
	    break;
	case ICMP6_DST_UNREACH_ADDR:
	    codename = colcodename = "Address unreachable";
	    break;
	case ICMP6_DST_UNREACH_NOPORT:
	    codename = colcodename = "Port unreachable";
	    break;
	}
	break;
    case ICMP6_PACKET_TOO_BIG:
	typename = coltypename = "Too big";
	codename = colcodename = NULL;
	break;
    case ICMP6_TIME_EXCEEDED:
	typename = coltypename = "Time exceeded";
	switch (dp->icmp6_code) {
	case ICMP6_TIME_EXCEED_TRANSIT:
	    codename = colcodename = "In-transit";
	    break;
	case ICMP6_TIME_EXCEED_REASSEMBLY:
	    codename = colcodename = "Reassembly";
	    break;
	}
        break;
    case ICMP6_PARAM_PROB:
	typename = coltypename = "Parameter problem";
	switch (dp->icmp6_code) {
	case ICMP6_PARAMPROB_HEADER:
	    codename = colcodename = "Header";
	    break;
	case ICMP6_PARAMPROB_NEXTHEADER:
	    codename = colcodename = "Next header";
	    break;
	case ICMP6_PARAMPROB_OPTION:
	    codename = colcodename = "Option";
	    break;
	}
        break;
    case ICMP6_ECHO_REQUEST:
	typename = coltypename = "Echo request";
	codename = colcodename = NULL;
	break;
    case ICMP6_ECHO_REPLY:
	typename = coltypename = "Echo reply";
	codename = colcodename = NULL;
	break;
    case ICMP6_MEMBERSHIP_QUERY:
	typename = coltypename = "Multicast listener query";
	codename = colcodename = NULL;
	break;
    case ICMP6_MEMBERSHIP_REPORT:
	typename = coltypename = "Multicast listener report";
	codename = colcodename = NULL;
	break;
    case ICMP6_MEMBERSHIP_REDUCTION:
	typename = coltypename = "Multicast listener done";
	codename = colcodename = NULL;
	break;
    case ND_ROUTER_SOLICIT:
	typename = coltypename = "Router solicitation";
	codename = colcodename = NULL;
	len = sizeof(struct nd_router_solicit);
	break;
    case ND_ROUTER_ADVERT:
	typename = coltypename = "Router advertisement";
	codename = colcodename = NULL;
	len = sizeof(struct nd_router_advert);
	break;
    case ND_NEIGHBOR_SOLICIT:
	typename = coltypename = "Neighbor solicitation";
	codename = colcodename = NULL;
	len = sizeof(struct nd_neighbor_solicit);
	break;
    case ND_NEIGHBOR_ADVERT:
	typename = coltypename = "Neighbor advertisement";
	codename = colcodename = NULL;
	len = sizeof(struct nd_neighbor_advert);
	break;
    case ND_REDIRECT:
	typename = coltypename = "Redirect";
	codename = colcodename = NULL;
	len = sizeof(struct nd_redirect);
	break;
    case ICMP6_ROUTER_RENUMBERING:
	typename = coltypename = "Router renumbering";
	switch (dp->icmp6_code) {
	case ICMP6_ROUTER_RENUMBERING_COMMAND:
	    codename = colcodename = "Command";
	    break;
	case ICMP6_ROUTER_RENUMBERING_RESULT:
	    codename = colcodename = "Result";
	    break;
	}
	len = sizeof(struct icmp6_router_renum);
	break;
    case ICMP6_NI_QUERY:
    case ICMP6_NI_REPLY:
	ni = (struct icmp6_nodeinfo *)dp;
	if (ni->ni_type == ICMP6_NI_QUERY) {
	    typename = coltypename = "Node information query";
	    switch (ni->ni_code) {
	    case ICMP6_NI_SUBJ_IPV6:
		codename = "Query subject = IPv6 addresses";
		break;
	    case ICMP6_NI_SUBJ_FQDN:
		if (IS_DATA_IN_FRAME(offset + sizeof(*ni)))
		    codename = "Query subject = DNS name";
		else
		    codename = "Query subject = empty";
		break;
	    case ICMP6_NI_SUBJ_IPV4:
		codename = "Query subject = IPv4 addresses";
		break;
	    }
	} else {
	    typename = coltypename = "Node information reply";
	    switch (ni->ni_code) {
	    case ICMP6_NI_SUCCESS:
		codename = "Successful";
		break;
	    case ICMP6_NI_REFUSED:
		codename = "Refused";
		break;
	    case ICMP6_NI_UNKNOWN:
		codename = "Unknown query type";
		break;
	    }
	}
	colcodename = val_to_str(pntohs(&ni->ni_qtype), names_nodeinfo_qtype,
	    "Unknown");
	len = sizeof(struct icmp6_nodeinfo);
	break;
    }

    if (check_col(fd, COL_PROTOCOL))
	col_add_str(fd, COL_PROTOCOL, "ICMPv6");
    if (check_col(fd, COL_INFO)) {
	char typebuf[256], codebuf[256];

	if (coltypename && strcmp(coltypename, "Unknown") == 0) {
	    snprintf(typebuf, sizeof(typebuf), "Unknown (0x%02x)",
		dp->icmp6_type);
	    coltypename = typebuf;
	}
	if (colcodename && strcmp(colcodename, "Unknown") == 0) {
	    snprintf(codebuf, sizeof(codebuf), "Unknown (0x%02x)",
		dp->icmp6_code);
	    colcodename = codebuf;
	}
	if (colcodename) {
	    col_add_fstr(fd, COL_INFO, "%s (%s)", coltypename, colcodename);
	} else {
	    col_add_fstr(fd, COL_INFO, "%s", coltypename);
	}
    }

    if (tree) {
	/* !!! specify length */
	ti = proto_tree_add_item(tree, proto_icmpv6, NullTVB, offset, len, FALSE);
	icmp6_tree = proto_item_add_subtree(ti, ett_icmpv6);

	proto_tree_add_uint_format(icmp6_tree, hf_icmpv6_type, NullTVB,
	    offset + offsetof(struct icmp6_hdr, icmp6_type), 1,
	    dp->icmp6_type,
	    "Type: 0x%02x (%s)", dp->icmp6_type, typename);
	if (codename) {
	    proto_tree_add_uint_format(icmp6_tree, hf_icmpv6_code, NullTVB,
		offset + offsetof(struct icmp6_hdr, icmp6_code), 1,
		dp->icmp6_code,
		"Code: 0x%02x (%s)", dp->icmp6_code, codename);
	} else {
	    proto_tree_add_uint_format(icmp6_tree, hf_icmpv6_code, NullTVB,
		offset + offsetof(struct icmp6_hdr, icmp6_code), 1,
		dp->icmp6_code,
		"Code: 0x%02x", dp->icmp6_code);
	}
	proto_tree_add_uint(icmp6_tree, hf_icmpv6_checksum, NullTVB,
	    offset + offsetof(struct icmp6_hdr, icmp6_cksum), 2,
	    (guint16)htons(dp->icmp6_cksum));

	/* decode... */
	switch (dp->icmp6_type) {
	case ICMP6_DST_UNREACH:
	case ICMP6_TIME_EXCEEDED:
	    /* tiny sanity check */
	    if ((pd[offset + sizeof(*dp)] & 0xf0) == 0x60) {
		dissect_ipv6(pd, offset + sizeof(*dp), fd, icmp6_tree);
	    } else {
		old_dissect_data(pd, offset + sizeof(*dp), fd, icmp6_tree);
	    }
	    break;
	case ICMP6_PACKET_TOO_BIG:
	    proto_tree_add_text(icmp6_tree, NullTVB,
		offset + offsetof(struct icmp6_hdr, icmp6_mtu), 4,
		"MTU: %d", pntohl(&dp->icmp6_mtu));
	    /* tiny sanity check */
	    if ((pd[offset + sizeof(*dp)] & 0xf0) == 0x60) {
		dissect_ipv6(pd, offset + sizeof(*dp), fd, icmp6_tree);
	    } else {
		old_dissect_data(pd, offset + sizeof(*dp), fd, icmp6_tree);
	    }
	    break;
	case ICMP6_PARAM_PROB:
	    proto_tree_add_text(icmp6_tree, NullTVB,
		offset + offsetof(struct icmp6_hdr, icmp6_pptr), 4,
		"Problem pointer: 0x%04x", pntohl(&dp->icmp6_pptr));
	    /* tiny sanity check */
	    if ((pd[offset + sizeof(*dp)] & 0xf0) == 0x60) {
		dissect_ipv6(pd, offset + sizeof(*dp), fd, icmp6_tree);
	    } else {
		old_dissect_data(pd, offset + sizeof(*dp), fd, icmp6_tree);
	    }
	    break;
	case ICMP6_ECHO_REQUEST:
	case ICMP6_ECHO_REPLY:
	    proto_tree_add_text(icmp6_tree, NullTVB,
		offset + offsetof(struct icmp6_hdr, icmp6_id), 2,
		"ID: 0x%04x", (guint16)ntohs(dp->icmp6_id));
	    proto_tree_add_text(icmp6_tree, NullTVB,
		offset + offsetof(struct icmp6_hdr, icmp6_seq), 2,
		"Sequence: 0x%04x", (guint16)ntohs(dp->icmp6_seq));
	    old_dissect_data(pd, offset + sizeof(*dp), fd, icmp6_tree);
	    break;
	case ICMP6_MEMBERSHIP_QUERY:
	case ICMP6_MEMBERSHIP_REPORT:
	case ICMP6_MEMBERSHIP_REDUCTION:
	    proto_tree_add_text(icmp6_tree, NullTVB,
		offset + offsetof(struct icmp6_hdr, icmp6_maxdelay), 2,
		"Maximum response delay: %d",
		(guint16)ntohs(dp->icmp6_maxdelay));
	    proto_tree_add_text(icmp6_tree, NullTVB, offset + sizeof(*dp), 16,
		"Multicast Address: %s",
		ip6_to_str((struct e_in6_addr *)(dp + 1)));
	    break;
	case ND_ROUTER_SOLICIT:
	    dissect_icmpv6opt(pd, offset + sizeof(*dp), fd, icmp6_tree);
	    break;
	case ND_ROUTER_ADVERT:
	  {
	    struct nd_router_advert *ra = (struct nd_router_advert *)dp;
	    int flagoff;
	    guint32 ra_flags;

	    proto_tree_add_text(icmp6_tree, NullTVB,
		offset + offsetof(struct nd_router_advert, nd_ra_curhoplimit),
		1, "Cur hop limit: %d", ra->nd_ra_curhoplimit);

	    flagoff = offset + offsetof(struct nd_router_advert, nd_ra_flags_reserved);
	    ra_flags = pntohl(&pd[flagoff]);
	    tf = proto_tree_add_text(icmp6_tree, NullTVB, flagoff, 4, "Flags: 0x%08x", ra_flags);
	    field_tree = proto_item_add_subtree(tf, ett_icmpv6flag);
	    proto_tree_add_text(field_tree, NullTVB, flagoff, 4, "%s",
		decode_boolean_bitfield(ra_flags,
			0x80000000, 32, "Managed", "Not managed"));
	    proto_tree_add_text(field_tree, NullTVB, flagoff, 4, "%s",
		decode_boolean_bitfield(ra_flags,
			0x40000000, 32, "Other", "Not other"));

	    proto_tree_add_text(icmp6_tree, NullTVB,
		offset + offsetof(struct nd_router_advert, nd_ra_router_lifetime),
		2, "Router lifetime: %d",
		(guint16)ntohs(ra->nd_ra_router_lifetime));
	    proto_tree_add_text(icmp6_tree, NullTVB,
		offset + offsetof(struct nd_router_advert, nd_ra_reachable), 4,
		"Reachable time: %d", pntohl(&ra->nd_ra_reachable));
	    proto_tree_add_text(icmp6_tree, NullTVB,
		offset + offsetof(struct nd_router_advert, nd_ra_retransmit), 4,
		"Retrans time: %d", pntohl(&ra->nd_ra_retransmit));
	    dissect_icmpv6opt(pd, offset + sizeof(struct nd_router_advert), fd, icmp6_tree);
	    break;
	  }
	case ND_NEIGHBOR_SOLICIT:
	  {
	    struct nd_neighbor_solicit *ns = (struct nd_neighbor_solicit *)dp;

	    proto_tree_add_text(icmp6_tree, NullTVB,
			offset + offsetof(struct nd_neighbor_solicit, nd_ns_target), 16,
#ifdef INET6
			"Target: %s (%s)",
			get_hostname6(&ns->nd_ns_target),
#else
			"Target: %s",
#endif
			ip6_to_str(&ns->nd_ns_target));

	    dissect_icmpv6opt(pd, offset + sizeof(*ns), fd, icmp6_tree);
	    break;
	  }
	case ND_NEIGHBOR_ADVERT:
	  {
	    int flagoff, targetoff;
	    guint32 na_flags;
		struct e_in6_addr *na_target_p;

	    flagoff = offset + offsetof(struct nd_neighbor_advert, nd_na_flags_reserved);
	    na_flags = pntohl(&pd[flagoff]);

	    tf = proto_tree_add_text(icmp6_tree, NullTVB, flagoff, 4, "Flags: 0x%08x", na_flags);
	    field_tree = proto_item_add_subtree(tf, ett_icmpv6flag);
	    proto_tree_add_text(field_tree, NullTVB, flagoff, 4, "%s",
		decode_boolean_bitfield(na_flags,
			0x80000000, 32, "Router", "Not router"));
	    proto_tree_add_text(field_tree, NullTVB, flagoff, 4, "%s",
		decode_boolean_bitfield(na_flags,
			0x40000000, 32, "Solicited", "Not adverted"));
	    proto_tree_add_text(field_tree, NullTVB, flagoff, 4, "%s",
		decode_boolean_bitfield(na_flags,
			0x20000000, 32, "Override", "Not override"));

		targetoff = offset + offsetof(struct nd_neighbor_advert, nd_na_target);
	    na_target_p = (struct e_in6_addr*) &pd[targetoff];
	    proto_tree_add_text(icmp6_tree, NullTVB, targetoff, 16,
#ifdef INET6
			"Target: %s (%s)",
			get_hostname6(na_target_p),
#else
			"Target: %s",
#endif
			ip6_to_str(na_target_p));

	    dissect_icmpv6opt(pd, offset + sizeof(struct nd_neighbor_advert), fd, icmp6_tree);
	    break;
	  }
	case ND_REDIRECT:
	  {
	    struct nd_redirect *rd = (struct nd_redirect *)dp;

	    proto_tree_add_text(icmp6_tree, NullTVB,
			offset + offsetof(struct nd_redirect, nd_rd_target), 16,
#ifdef INET6
			"Target: %s (%s)",
			get_hostname6(&rd->nd_rd_target),
#else
			"Target: %s",
#endif
			ip6_to_str(&rd->nd_rd_target));

	    proto_tree_add_text(icmp6_tree, NullTVB,
			offset + offsetof(struct nd_redirect, nd_rd_dst), 16,
#ifdef INET6
			"Destination: %s (%s)",
			get_hostname6(&rd->nd_rd_dst),
#else
			"Destination: %s",
#endif
			ip6_to_str(&rd->nd_rd_dst));

	    dissect_icmpv6opt(pd, offset + sizeof(*rd), fd, icmp6_tree);
	    break;
	  }
	case ICMP6_ROUTER_RENUMBERING:
	  {
	    struct icmp6_router_renum *rr = (struct icmp6_router_renum *)dp;
	    int flagoff;
	    proto_tree_add_text(icmp6_tree, NullTVB,
		offset + offsetof(struct icmp6_router_renum, rr_seqnum), 4,
		/*"Sequence number: 0x%08x", (u_int32_t)htonl(rr->rr_seqnum));*/
		"Sequence number: 0x%08x", pntohl(&rr->rr_seqnum));
	    proto_tree_add_text(icmp6_tree, NullTVB,
		offset + offsetof(struct icmp6_router_renum, rr_segnum), 1,
		"Segment number: 0x%02x", rr->rr_segnum);

	    flagoff = offset + offsetof(struct icmp6_router_renum, rr_segnum) + 1;
	    tf = proto_tree_add_text(icmp6_tree, NullTVB, flagoff, 4, "Flags: 0x%08x",
		pd[flagoff]);
	    field_tree = proto_item_add_subtree(tf, ett_icmpv6flag);
	    proto_tree_add_text(field_tree, NullTVB, flagoff, 1, "%s",
		decode_boolean_bitfield(pd[flagoff], 0x80, 8,
		    "Test command", "Not test command"));
	    proto_tree_add_text(field_tree, NullTVB, flagoff, 1, "%s",
		decode_boolean_bitfield(pd[flagoff], 0x40, 8,
		    "Result requested", "Result not requested"));
	    proto_tree_add_text(field_tree, NullTVB, flagoff, 1, "%s",
		decode_boolean_bitfield(pd[flagoff], 0x20, 8,
		    "All interfaces", "Not all interfaces"));
	    proto_tree_add_text(field_tree, NullTVB, flagoff, 1, "%s",
		decode_boolean_bitfield(pd[flagoff], 0x10, 8,
		    "Site specific", "Not site specific"));
	    proto_tree_add_text(field_tree, NullTVB, flagoff, 1, "%s",
		decode_boolean_bitfield(pd[flagoff], 0x08, 8,
		    "Processed previously", "Complete result"));

	    proto_tree_add_text(icmp6_tree, NullTVB,
		offset + offsetof(struct icmp6_router_renum, rr_segnum), 2,
		"Max delay: 0x%04x", pntohs(&rr->rr_maxdelay));
	    old_dissect_data(pd, offset + sizeof(*rr), fd, tree);	/*XXX*/
	  }
	case ICMP6_NI_QUERY:
	case ICMP6_NI_REPLY:
	    ni = (struct icmp6_nodeinfo *)dp;
	    proto_tree_add_text(icmp6_tree, NullTVB,
		offset + offsetof(struct icmp6_nodeinfo, ni_qtype),
		sizeof(ni->ni_qtype),
		"Query type: 0x%04x (%s)", pntohs(&ni->ni_qtype),
		val_to_str(pntohs(&ni->ni_qtype), names_nodeinfo_qtype,
		"Unknown"));
	    dissect_nodeinfo(pd, offset, fd, icmp6_tree);
	    break;
	default:
	    old_dissect_data(pd, offset + sizeof(*dp), fd, tree);
	    break;
	}
    }
}

void
proto_register_icmpv6(void)
{
  static hf_register_info hf[] = {
    { &hf_icmpv6_type,
      { "Type",           "icmpv6.type",	FT_UINT8,  BASE_HEX, NULL, 0x0,
      	"" }},
    { &hf_icmpv6_code,
      { "Code",           "icmpv6.code",	FT_UINT8,  BASE_HEX, NULL, 0x0,
      	"" }},
    { &hf_icmpv6_checksum,
      { "Checksum",       "icmpv6.checksum",	FT_UINT16, BASE_HEX, NULL, 0x0,
      	"" }}
  };
  static gint *ett[] = {
    &ett_icmpv6,
    &ett_icmpv6opt,
    &ett_icmpv6flag,
    &ett_nodeinfo_flag,
    &ett_nodeinfo_subject4,
    &ett_nodeinfo_subject6,
    &ett_nodeinfo_node4,
    &ett_nodeinfo_node6,
    &ett_nodeinfo_nodebitmap,
    &ett_nodeinfo_nodedns,
  };

  proto_icmpv6 = proto_register_protocol("Internet Control Message Protocol v6",
					 "icmpv6");
  proto_register_field_array(proto_icmpv6, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_icmpv6(void)
{
  old_dissector_add("ip.proto", IP_PROTO_ICMPV6, dissect_icmpv6);
}

