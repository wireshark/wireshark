/* packet-ipv6.c
 * Routines for IPv6 packet disassembly 
 *
 * $Id: packet-ipv6.c,v 1.18 1999/10/13 06:47:47 guy Exp $
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_h
#include <sys/socket.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>
#include <stdio.h>
#include <glib.h>
#include "packet.h"
#include "packet-ip.h"
#include "packet-ipv6.h"
#include "resolv.h"

static int proto_ipv6 = -1;
static int hf_ipv6_src = -1;
static int hf_ipv6_dst = -1;

#ifndef offsetof
#define	offsetof(type, member)	((size_t)(&((type *)0)->member))
#endif

static const char *
inet_ntop6(const u_char *src, char *dst, size_t size);

static const char *
inet_ntop4(const u_char *src, char *dst, size_t size);

static int
dissect_routing6(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
    struct ip6_rthdr rt;
    int len;
    proto_tree *rthdr_tree;
	proto_item *ti;
    char buf[sizeof(struct ip6_rthdr0) + sizeof(struct e_in6_addr) * 23];

    memcpy(&rt, (void *) &pd[offset], sizeof(rt));
    len = (rt.ip6r_len + 1) << 3;

    if (tree) {
	/* !!! specify length */
	ti = proto_tree_add_text(tree, offset, len,
	    "Routing Header, Type %d", rt.ip6r_type);
	rthdr_tree = proto_item_add_subtree(ti, ETT_IPv6);

	proto_tree_add_text(rthdr_tree,
	    offset + offsetof(struct ip6_rthdr, ip6r_nxt), 1,
	    "Next header: 0x%02x", rt.ip6r_nxt);
	proto_tree_add_text(rthdr_tree,
	    offset + offsetof(struct ip6_rthdr, ip6r_len), 1,
	    "Length: %d (%d bytes)", rt.ip6r_len, len);
	proto_tree_add_text(rthdr_tree,
	    offset + offsetof(struct ip6_rthdr, ip6r_type), 1,
	    "Type: %d", rt.ip6r_type, len);
	proto_tree_add_text(rthdr_tree,
	    offset + offsetof(struct ip6_rthdr, ip6r_segleft), 1,
	    "Segments left: %d", rt.ip6r_segleft, len);

	if (rt.ip6r_type == 0 && len <= sizeof(buf)) {
	    struct e_in6_addr *a;
	    int n;
	    struct ip6_rthdr0 *rt0;

	    memcpy(buf, (void *) &pd[offset], len);
	    rt0 = (struct ip6_rthdr0 *)buf;
	    for (a = rt0->ip6r0_addr, n = 0;
		 a < (struct e_in6_addr *)(buf + len);
		 a++, n++) {
		proto_tree_add_text(rthdr_tree,
		    offset + offsetof(struct ip6_rthdr0, ip6r0_addr) + n * sizeof(struct e_in6_addr),
		    sizeof(struct e_in6_addr),
#ifdef INET6
		    "address %d: %s (%s)",
		    n, get_hostname6(a), ip6_to_str(a)
#else
		    "address %d: %s", n, ip6_to_str(a)
#endif
		    );
	    }
	}
  
	/* decode... */
    }

    return len;
}

static int
dissect_frag6(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
    struct ip6_frag frag;
    int len;

    memcpy(&frag, (void *) &pd[offset], sizeof(frag));
    len = sizeof(frag);

    if (check_col(fd, COL_INFO)) {
	col_add_fstr(fd, COL_INFO,
	    "IPv6 fragment (nxt=0x%02x off=0x%04x id=0x%x)",
	    frag.ip6f_nxt, (frag.ip6f_offlg >> 3) & 0x1fff, frag.ip6f_ident);
    }
    return len;
}

static int
dissect_opts(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
    char *optname) {
    struct ip6_ext ext;
    int len;
    proto_tree *dstopt_tree;
	proto_item *ti;
    u_char *p;

    memcpy(&ext, (void *) &pd[offset], sizeof(ext)); 
    len = (ext.ip6e_len + 1) << 3;

    if (tree) {
	/* !!! specify length */
	ti = proto_tree_add_text(tree, offset, len,
	    "%s Header", optname);
	dstopt_tree = proto_item_add_subtree(ti, ETT_IPv6);

	proto_tree_add_text(dstopt_tree,
	    offset + offsetof(struct ip6_ext, ip6e_nxt), 1,
	    "Next header: 0x%02x", ext.ip6e_nxt);
	proto_tree_add_text(dstopt_tree,
	    offset + offsetof(struct ip6_ext, ip6e_len), 1,
	    "Length: %d (%d bytes)", ext.ip6e_len, len);

	p = (u_char *)(pd + offset + 2);
	while (p < pd + offset + len) {
	    switch (p[0]) {
	    case IP6OPT_PAD1:
		proto_tree_add_text(dstopt_tree, p - pd, 1,
		    "Pad1");
		p++;
		break;
	    case IP6OPT_PADN:
		proto_tree_add_text(dstopt_tree, p - pd, p[1] + 2,
		    "PadN: %d bytes", p[1] + 2);
		p += p[1];
		p += 2;
		break;
	    case IP6OPT_JUMBO:
		if (p[1] == 4) {
		    proto_tree_add_text(dstopt_tree, p - pd, p[1] + 2,
			"Jumbo payload: %u (%d bytes)",
			ntohl(*(guint32 *)&p[2]), p[1] + 2);
		} else {
		    proto_tree_add_text(dstopt_tree, p - pd, p[1] + 2,
			"Jumbo payload: invalid length (%d bytes)",
			p[1] + 2);
		}
		p += p[1];
		p += 2;
		break;
	    case IP6OPT_RTALERT:
	      {
		char *rta;

		if (p[1] == 2) {
		    switch (ntohs(*(guint16 *)&p[2])) {
		    case IP6OPT_RTALERT_MLD:
			rta = "MLD";
			break;
		    case IP6OPT_RTALERT_RSVP:
			rta = "RSVP";
			break;
		    default:
			rta = "unknown";
			break;
		    }
		} else
		    rta = "invalid length";
		ti = proto_tree_add_text(dstopt_tree, p - pd, p[1] + 2,
		    "Router alert: %s (%d bytes)", rta, p[1] + 2);
		p += p[1];
		p += 2;
		break;
	      }
	    default:
		p = (u_char *)(pd + offset + len);
		break;
	    }
	}

	/* decode... */
    }

    return len;
}

static int
dissect_hopopts(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
    return dissect_opts(pd, offset, fd, tree, "Hop-by-hop Option");
}

static int
dissect_dstopts(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
    return dissect_opts(pd, offset, fd, tree, "Destination Option");
}

void
dissect_ipv6(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  proto_tree *ipv6_tree;
  proto_item *ti;
  guint8 nxt;
  int advance;

  struct ip6_hdr ipv6;

  memcpy(&ipv6, (void *) &pd[offset], sizeof(ipv6)); 

  if (check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "IPv6");
  if (check_col(fd, COL_RES_NET_SRC))
    col_add_str(fd, COL_RES_NET_SRC, get_hostname6(&ipv6.ip6_src));
  if (check_col(fd, COL_UNRES_NET_SRC))
    col_add_str(fd, COL_UNRES_NET_SRC, ip6_to_str(&ipv6.ip6_src));
  if (check_col(fd, COL_RES_NET_DST))
    col_add_str(fd, COL_RES_NET_DST, get_hostname6(&ipv6.ip6_dst));
  if (check_col(fd, COL_UNRES_NET_DST))
    col_add_str(fd, COL_UNRES_NET_DST, ip6_to_str(&ipv6.ip6_dst));

  if (tree) {
    /* !!! specify length */
    ti = proto_tree_add_item(tree, proto_ipv6, offset, 40, NULL);
    ipv6_tree = proto_item_add_subtree(ti, ETT_IPv6);

    /* !!! warning: version also contains 4 Bit priority */
    proto_tree_add_text(ipv6_tree,
		offset + offsetof(struct ip6_hdr, ip6_vfc), 1,
		"Version: %d", ipv6.ip6_vfc >> 4);

    proto_tree_add_text(ipv6_tree,
		offset + offsetof(struct ip6_hdr, ip6_flow), 4,
		"Traffic class: 0x%02lx",
		(unsigned long)((ntohl(ipv6.ip6_flow) >> 20) & 0xff));

    /* there should be no alignment problems for ip6_flow, since it's the first
    guint32 in the ipv6 struct */
    proto_tree_add_text(ipv6_tree,
		offset + offsetof(struct ip6_hdr, ip6_flow), 4,
		"Flowlabel: 0x%05lx",
		(unsigned long)(ntohl(ipv6.ip6_flow & IPV6_FLOWLABEL_MASK)));

    proto_tree_add_text(ipv6_tree,
		offset + offsetof(struct ip6_hdr, ip6_plen), 2,
		"Payload Length: %d", ntohs(ipv6.ip6_plen));

    proto_tree_add_text(ipv6_tree,
		offset + offsetof(struct ip6_hdr, ip6_nxt), 1,
		"Next header: 0x%02x", ipv6.ip6_nxt);

    proto_tree_add_text(ipv6_tree,
		offset + offsetof(struct ip6_hdr, ip6_hlim), 1,
		"Hop limit: %d", ipv6.ip6_hlim);

    proto_tree_add_item_format(ipv6_tree, hf_ipv6_src,
		offset + offsetof(struct ip6_hdr, ip6_src), 16,
		&ipv6.ip6_src,
#ifdef INET6
		"Source address: %s (%s)",
		get_hostname6(&ipv6.ip6_src),
#else
		"Source address: %s",
#endif
		ip6_to_str(&ipv6.ip6_src));

    proto_tree_add_item_format(ipv6_tree, hf_ipv6_dst,
		offset + offsetof(struct ip6_hdr, ip6_dst), 16,
		&ipv6.ip6_dst,
#ifdef INET6
		"Destination address: %s (%s)",
		get_hostname6(&ipv6.ip6_dst),
#else
		"Destination address: %s",
#endif
		ip6_to_str(&ipv6.ip6_dst));
  }

  /* start of the new header (could be a extension header) */
  offset += 40;
  nxt = ipv6.ip6_nxt;

again:
    switch (nxt) {
    case IP_PROTO_HOPOPTS:
	advance = dissect_hopopts(pd, offset, fd, tree);
	nxt = pd[offset];
	offset += advance;
	goto again;
    case IP_PROTO_IPIP:
	dissect_ip(pd, offset, fd, tree);
	break;
    case IP_PROTO_ROUTING:
	advance =dissect_routing6(pd, offset, fd, tree);
	nxt = pd[offset];
	offset += advance;
	goto again;
    case IP_PROTO_FRAGMENT:
	advance = dissect_frag6(pd, offset, fd, tree);
	nxt = pd[offset];
	offset += advance;
	goto again;
    case IP_PROTO_ICMPV6:
	dissect_icmpv6(pd, offset, fd, tree);
	break;
    case IP_PROTO_NONE:
	if (check_col(fd, COL_INFO)) {
	    col_add_fstr(fd, COL_INFO, "IPv6 no next header");
	}
	break;
    case IP_PROTO_AH:
	advance = dissect_ah(pd, offset, fd, tree);
	nxt = pd[offset];
	offset += advance;
	goto again;
    case IP_PROTO_ESP:
	dissect_esp(pd, offset, fd, tree);
	break;
    case IP_PROTO_DSTOPTS:
	advance = dissect_dstopts(pd, offset, fd, tree);
	nxt = pd[offset];
	offset += advance;
	goto again;
    case IP_PROTO_TCP:
	dissect_tcp(pd, offset, fd, tree);
	break;
    case IP_PROTO_UDP:
	dissect_udp(pd, offset, fd, tree);
	break;
    case IP_PROTO_PIM:
	dissect_pim(pd, offset, fd, tree);
	break;
    default:
	if (check_col(fd, COL_INFO)) {
	    col_add_fstr(fd, COL_INFO, "Unknown IPv6 protocol (0x%02x)",
		ipv6.ip6_nxt);
	}
	dissect_data(pd, offset, fd, tree);
    }
}

gchar *
ip6_to_str(struct e_in6_addr *ad) {
  static gchar buf[4 * 8 + 8];

  inet_ntop6((u_char*)ad, (gchar*)buf, sizeof(buf));
  return buf;
}

#ifndef NS_IN6ADDRSZ
#define NS_IN6ADDRSZ	16
#endif

#ifndef NS_INT16SZ
#define NS_INT16SZ	(sizeof(guint16))
#endif

#define SPRINTF(x) ((size_t)sprintf x)

/*
 * Copyright (c) 1996-1999 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/* const char *
 * inet_ntop4(src, dst, size)
 *	format an IPv4 address
 * return:
 *	`dst' (as a const)
 * notes:
 *	(1) uses no statics
 *	(2) takes a u_char* not an in_addr as input
 * author:
 *	Paul Vixie, 1996.
 */
static const char *
inet_ntop4(src, dst, size)
	const u_char *src;
	char *dst;
	size_t size;
{
	static const char fmt[] = "%u.%u.%u.%u";
	char tmp[sizeof "255.255.255.255"];

	if (SPRINTF((tmp, fmt, src[0], src[1], src[2], src[3])) > size) {
		return (NULL);
	}
	strcpy(dst, tmp);
	return (dst);
}

/* const char *
 * inet_ntop6(src, dst, size)
 *	convert IPv6 binary address into presentation (printable) format
 * author:
 *	Paul Vixie, 1996.
 */
static const char *
inet_ntop6(src, dst, size)
	const u_char *src;
	char *dst;
	size_t size;
{
	/*
	 * Note that int32_t and int16_t need only be "at least" large enough
	 * to contain a value of the specified size.  On some systems, like
	 * Crays, there is no such thing as an integer variable with 16 bits.
	 * Keep this in mind if you think this function should have been coded
	 * to use pointer overlays.  All the world's not a VAX.
	 */
	char tmp[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"], *tp;
	struct { int base, len; } best, cur;
	u_int words[NS_IN6ADDRSZ / NS_INT16SZ];
	int i;

	/*
	 * Preprocess:
	 *	Copy the input (bytewise) array into a wordwise array.
	 *	Find the longest run of 0x00's in src[] for :: shorthanding.
	 */
	memset(words, '\0', sizeof words);
	for (i = 0; i < NS_IN6ADDRSZ; i++)
		words[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));
	best.base = -1;
	cur.base = -1;
	for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
		if (words[i] == 0) {
			if (cur.base == -1)
				cur.base = i, cur.len = 1;
			else
				cur.len++;
		} else {
			if (cur.base != -1) {
				if (best.base == -1 || cur.len > best.len)
					best = cur;
				cur.base = -1;
			}
		}
	}
	if (cur.base != -1) {
		if (best.base == -1 || cur.len > best.len)
			best = cur;
	}
	if (best.base != -1 && best.len < 2)
		best.base = -1;

	/*
	 * Format the result.
	 */
	tp = tmp;
	for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
		/* Are we inside the best run of 0x00's? */
		if (best.base != -1 && i >= best.base &&
		    i < (best.base + best.len)) {
			if (i == best.base)
				*tp++ = ':';
			continue;
		}
		/* Are we following an initial run of 0x00s or any real hex? */
		if (i != 0)
			*tp++ = ':';
		/* Is this address an encapsulated IPv4? */
		if (i == 6 && best.base == 0 &&
		    (best.len == 6 || (best.len == 5 && words[5] == 0xffff))) {
			if (!inet_ntop4(src+12, tp, sizeof tmp - (tp - tmp)))
				return (NULL);
			tp += strlen(tp);
			break;
		}
		tp += SPRINTF((tp, "%x", words[i]));
	}
	/* Was it a trailing run of 0x00's? */
	if (best.base != -1 && (best.base + best.len) == 
	    (NS_IN6ADDRSZ / NS_INT16SZ))
		*tp++ = ':';
	*tp++ = '\0';

	/*
	 * Check for overflow, copy, and we're done.
	 */
	if ((size_t)(tp - tmp) > size) {
		return (NULL);
	}
	strcpy(dst, tmp);
	return (dst);
}

void
proto_register_ipv6(void)
{
  static hf_register_info hf[] = {
    { &hf_ipv6_src,
      { "Source",		"ipv6.src",	FT_IPv6,	BASE_NONE, NULL, 0x0,
      	"Source IPv6 Address" }},
    { &hf_ipv6_dst,
      { "Destination",		"ipv6.dst",	FT_IPv6,	BASE_NONE, NULL, 0x0,
      	"Destination IPv6 Address" }}
  };

  proto_ipv6 = proto_register_protocol("Internet Protocol Version 6", "ipv6");
  proto_register_field_array(proto_ipv6, hf, array_length(hf));
}
