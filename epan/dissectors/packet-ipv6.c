/* packet-ipv6.c
 * Routines for IPv6 packet disassembly
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * MobileIPv6 support added by Tomislav Borosa <tomislav.borosa@siemens.hr>
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

#include <string.h>
#include <stdio.h>
#include <glib.h>
#include <epan/packet.h>
#include "packet-ipsec.h"
#include "packet-ipv6.h"
#include "ip_opts.h"
#include <epan/addr_resolv.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/ipproto.h>
#include "etypes.h"
#include "ppptypes.h"
#include "aftypes.h"
#include "nlpid.h"
#include "arcnet_pids.h"

/*
 * NOTE: ipv6.nxt is not very useful as we will have chained header.
 * now testing ipv6.final, but it raises SEGV.
#define TEST_FINALHDR
 */

static int proto_ipv6 = -1;
static int hf_ipv6_version = -1;
static int hf_ipv6_class = -1;
static int hf_ipv6_flow = -1;
static int hf_ipv6_plen = -1;
static int hf_ipv6_nxt = -1;
static int hf_ipv6_hlim = -1;
static int hf_ipv6_src = -1;
static int hf_ipv6_dst = -1;
static int hf_ipv6_addr = -1;
#ifdef TEST_FINALHDR
static int hf_ipv6_final = -1;
#endif
static int hf_ipv6_fragments = -1;
static int hf_ipv6_fragment = -1;
static int hf_ipv6_fragment_overlap = -1;
static int hf_ipv6_fragment_overlap_conflict = -1;
static int hf_ipv6_fragment_multiple_tails = -1;
static int hf_ipv6_fragment_too_long_fragment = -1;
static int hf_ipv6_fragment_error = -1;
static int hf_ipv6_reassembled_in = -1;

static int hf_ipv6_mipv6_type = -1;
static int hf_ipv6_mipv6_length = -1;
static int hf_ipv6_mipv6_home_address = -1;

static gint ett_ipv6 = -1;
static gint ett_ipv6_fragments = -1;
static gint ett_ipv6_fragment  = -1;

static const fragment_items ipv6_frag_items = {
	&ett_ipv6_fragment,
	&ett_ipv6_fragments,
	&hf_ipv6_fragments,
	&hf_ipv6_fragment,
	&hf_ipv6_fragment_overlap,
	&hf_ipv6_fragment_overlap_conflict,
	&hf_ipv6_fragment_multiple_tails,
	&hf_ipv6_fragment_too_long_fragment,
	&hf_ipv6_fragment_error,
	&hf_ipv6_reassembled_in,
	"fragments"
};

static dissector_handle_t data_handle;

static dissector_table_t ip_dissector_table;

/* Reassemble fragmented datagrams */
static gboolean ipv6_reassemble = FALSE;

#ifndef offsetof
#define	offsetof(type, member)	((size_t)(&((type *)0)->member))
#endif

/*
 * defragmentation of IPv6
 */
static GHashTable *ipv6_fragment_table = NULL;
static GHashTable *ipv6_reassembled_table = NULL;

void
capture_ipv6(const guchar *pd, int offset, int len, packet_counts *ld)
{
  guint8 nxt;
  int advance;

  if (!BYTES_ARE_IN_FRAME(offset, len, 4+4+16+16)) {
    ld->other++;
    return;
  }
  nxt = pd[offset+6];		/* get the "next header" value */
  offset += 4+4+16+16;		/* skip past the IPv6 header */

again:
   switch (nxt) {
   case IP_PROTO_HOPOPTS:
   case IP_PROTO_ROUTING:
   case IP_PROTO_DSTOPTS:
     if (!BYTES_ARE_IN_FRAME(offset, len, 2)) {
       ld->other++;
       return;
     }
     nxt = pd[offset];
     advance = (pd[offset+1] + 1) << 3;
     if (!BYTES_ARE_IN_FRAME(offset, len, advance)) {
       ld->other++;
       return;
     }
     offset += advance;
     goto again;
   case IP_PROTO_FRAGMENT:
     if (!BYTES_ARE_IN_FRAME(offset, len, 2)) {
       ld->other++;
       return;
     }
     nxt = pd[offset];
     advance = 8;
     if (!BYTES_ARE_IN_FRAME(offset, len, advance)) {
       ld->other++;
       return;
     }
     offset += advance;
     goto again;
   case IP_PROTO_AH:
     if (!BYTES_ARE_IN_FRAME(offset, len, 2)) {
       ld->other++;
       return;
     }
     nxt = pd[offset];
     advance = 8 + ((pd[offset+1] - 1) << 2);
     if (!BYTES_ARE_IN_FRAME(offset, len, advance)) {
       ld->other++;
       return;
     }
     offset += advance;
     goto again;
   }

  switch(nxt) {
    case IP_PROTO_SCTP:
      ld->sctp++;
      break;
    case IP_PROTO_TCP:
      ld->tcp++;
      break;
    case IP_PROTO_UDP:
      ld->udp++;
      break;
    case IP_PROTO_ICMP:
    case IP_PROTO_ICMPV6:	/* XXX - separate counters? */
      ld->icmp++;
      break;
    case IP_PROTO_OSPF:
      ld->ospf++;
      break;
    case IP_PROTO_GRE:
      ld->gre++;
      break;
    case IP_PROTO_VINES:
      ld->vines++;
      break;
    default:
      ld->other++;
  }
}

static void
ipv6_reassemble_init(void)
{
  fragment_table_init(&ipv6_fragment_table);
  reassembled_table_init(&ipv6_reassembled_table);
}

static int
dissect_routing6(tvbuff_t *tvb, int offset, proto_tree *tree) {
    struct ip6_rthdr rt;
    guint len;
    proto_tree *rthdr_tree;
    proto_item *ti;
    guint8 buf[sizeof(struct ip6_rthdr0) + sizeof(struct e_in6_addr) * 23];

    tvb_memcpy(tvb, (guint8 *)&rt, offset, sizeof(rt));
    len = (rt.ip6r_len + 1) << 3;

    if (tree) {
	/* !!! specify length */
	ti = proto_tree_add_text(tree, tvb, offset, len,
	    "Routing Header, Type %u", rt.ip6r_type);
	rthdr_tree = proto_item_add_subtree(ti, ett_ipv6);

	proto_tree_add_text(rthdr_tree, tvb,
	    offset + offsetof(struct ip6_rthdr, ip6r_nxt), 1,
	    "Next header: %s (0x%02x)", ipprotostr(rt.ip6r_nxt), rt.ip6r_nxt);
	proto_tree_add_text(rthdr_tree, tvb,
	    offset + offsetof(struct ip6_rthdr, ip6r_len), 1,
	    "Length: %u (%d bytes)", rt.ip6r_len, len);
	proto_tree_add_text(rthdr_tree, tvb,
	    offset + offsetof(struct ip6_rthdr, ip6r_type), 1,
	    "Type: %u", rt.ip6r_type);
	proto_tree_add_text(rthdr_tree, tvb,
	    offset + offsetof(struct ip6_rthdr, ip6r_segleft), 1,
	    "Segments left: %u", rt.ip6r_segleft);

	if (rt.ip6r_type == 0 && len <= sizeof(buf)) {
	    struct e_in6_addr *a;
	    int n;
	    struct ip6_rthdr0 *rt0;

	    tvb_memcpy(tvb, buf, offset, len);
	    rt0 = (struct ip6_rthdr0 *)buf;
	    for (a = rt0->ip6r0_addr, n = 0;
		 a < (struct e_in6_addr *)(buf + len);
		 a++, n++) {
		proto_tree_add_text(rthdr_tree, tvb,
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
	if (rt.ip6r_type == 2) {
	    proto_tree_add_ipv6(rthdr_tree, hf_ipv6_mipv6_home_address,
				       tvb, offset + 8, 16,
				       tvb_get_ptr(tvb, offset + 8, 16));
	}
    }

    return len;
}

static int
dissect_frag6(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree,
    guint16 *offlg, guint32 *ident) {
    struct ip6_frag frag;
    int len;
    proto_item *ti;
    proto_tree *rthdr_tree;

    tvb_memcpy(tvb, (guint8 *)&frag, offset, sizeof(frag));
    len = sizeof(frag);
    frag.ip6f_offlg = g_ntohs(frag.ip6f_offlg);
    frag.ip6f_ident = g_ntohl(frag.ip6f_ident);
    *offlg = frag.ip6f_offlg;
    *ident = frag.ip6f_ident;
    if (check_col(pinfo->cinfo, COL_INFO)) {
	col_add_fstr(pinfo->cinfo, COL_INFO,
	    "IPv6 fragment (nxt=%s (0x%02x) off=%u id=0x%x)",
	    ipprotostr(frag.ip6f_nxt), frag.ip6f_nxt,
	    frag.ip6f_offlg & IP6F_OFF_MASK, frag.ip6f_ident);
    }
    if (tree) {
	   ti = proto_tree_add_text(tree, tvb, offset, len,
			   "Fragmentation Header");
	   rthdr_tree = proto_item_add_subtree(ti, ett_ipv6);

	   proto_tree_add_text(rthdr_tree, tvb,
			 offset + offsetof(struct ip6_frag, ip6f_nxt), 1,
			 "Next header: %s (0x%02x)",
			 ipprotostr(frag.ip6f_nxt), frag.ip6f_nxt);

#if 0
	   proto_tree_add_text(rthdr_tree, tvb,
			 offset + offsetof(struct ip6_frag, ip6f_reserved), 1,
			 "Reserved: %u",
			 frag.ip6f_reserved);
#endif

	   proto_tree_add_text(rthdr_tree, tvb,
			 offset + offsetof(struct ip6_frag, ip6f_offlg), 2,
			 "Offset: %u",
			 frag.ip6f_offlg & IP6F_OFF_MASK);

	   proto_tree_add_text(rthdr_tree, tvb,
			 offset + offsetof(struct ip6_frag, ip6f_offlg), 2,
			 "More fragments: %s",
				frag.ip6f_offlg & IP6F_MORE_FRAG ?
				"Yes" : "No");

	   proto_tree_add_text(rthdr_tree, tvb,
			 offset + offsetof(struct ip6_frag, ip6f_ident), 4,
			 "Identification: 0x%08x",
			 frag.ip6f_ident);
    }
    return len;
}

static int
dissect_mipv6_hoa(tvbuff_t *tvb, proto_tree *dstopt_tree, int offset)
{
    int len = 0;

    proto_tree_add_uint_format(dstopt_tree, hf_ipv6_mipv6_type, tvb,
	offset + len, 1,
	tvb_get_guint8(tvb, offset + len),
	"Option Type: %u (0x%02x) - Home Address Option",
	tvb_get_guint8(tvb, offset + len),
	tvb_get_guint8(tvb, offset + len));
    len += 1;

    proto_tree_add_uint(dstopt_tree, hf_ipv6_mipv6_length, tvb, offset + len,
	1, tvb_get_guint8(tvb, offset + len));
    len += 1;

    proto_tree_add_ipv6(dstopt_tree, hf_ipv6_mipv6_home_address, tvb,
	offset + len, 16, tvb_get_ptr(tvb, offset + len, 16));
    len += 16;
    return len;
}

static const value_string rtalertvals[] = {
    { IP6OPT_RTALERT_MLD, "MLD" },
    { IP6OPT_RTALERT_RSVP, "RSVP" },
    { 0, NULL },
};

/* Like "dissect_ip_tcp_options()", but assumes the length of an option
   *doesn't* include the type and length bytes. */
void
dissect_ipv6_options(tvbuff_t *tvb, int offset, guint length,
			const ip_tcp_opt *opttab, int nopts, int eol,
			packet_info *pinfo, proto_tree *opt_tree)
{
  guchar            opt;
  const ip_tcp_opt *optp;
  opt_len_type      len_type;
  unsigned int      optlen;
  const char       *name;
  char              name_str[7+1+1+2+2+1+1];	/* "Unknown (0x%02x)" */
  void            (*dissect)(const struct ip_tcp_opt *, tvbuff_t *,
				int, guint, packet_info *, proto_tree *);
  guint             len;

  while (length > 0) {
    opt = tvb_get_guint8(tvb, offset);
    for (optp = &opttab[0]; optp < &opttab[nopts]; optp++) {
      if (optp->optcode == opt)
        break;
    }
    if (optp == &opttab[nopts]) {
      /* We assume that the only NO_LENGTH options are Pad1 options,
         so that we can treat unknown options as VARIABLE_LENGTH with a
	 minimum of 0, and at least be able to move on to the next option
	 by using the length in the option. */
      optp = NULL;	/* indicate that we don't know this option */
      len_type = VARIABLE_LENGTH;
      optlen = 0;
      g_snprintf(name_str, sizeof name_str, "Unknown (0x%02x)", opt);
      name = name_str;
      dissect = NULL;
    } else {
      len_type = optp->len_type;
      optlen = optp->optlen;
      name = optp->name;
      dissect = optp->dissect;
    }
    --length;      /* account for type byte */
    if (len_type != NO_LENGTH) {
      /* Option has a length. Is it in the packet? */
      if (length == 0) {
        /* Bogus - packet must at least include option code byte and
           length byte! */
        proto_tree_add_text(opt_tree, tvb, offset,      1,
              "%s (length byte past end of options)", name);
        return;
      }
      len = tvb_get_guint8(tvb, offset + 1);  /* total including type, len */
      --length;    /* account for length byte */
      if (len > length) {
        /* Bogus - option goes past the end of the header. */
        proto_tree_add_text(opt_tree, tvb, offset,      length,
              "%s (option length = %u byte%s says option goes past end of options)",
	      name, len, plurality(len, "", "s"));
        return;
      } else if (len_type == FIXED_LENGTH && len != optlen) {
        /* Bogus - option length isn't what it's supposed to be for this
           option. */
        proto_tree_add_text(opt_tree, tvb, offset,      2 + len,
              "%s (with option length = %u byte%s; should be %u)", name,
              len, plurality(len, "", "s"), optlen);
        return;
      } else if (len_type == VARIABLE_LENGTH && len < optlen) {
        /* Bogus - option length is less than what it's supposed to be for
           this option. */
        proto_tree_add_text(opt_tree, tvb, offset,      2 + len,
              "%s (with option length = %u byte%s; should be >= %u)", name,
              len, plurality(len, "", "s"), optlen);
        return;
      } else {
        if (optp == NULL) {
          proto_tree_add_text(opt_tree, tvb, offset,    2 + len, "%s (%u byte%s)",
				name, len, plurality(len, "", "s"));
        } else {
          if (dissect != NULL) {
            /* Option has a dissector. */
            (*dissect)(optp, tvb, offset,          2 + len, pinfo, opt_tree);
          } else {
            /* Option has no data, hence no dissector. */
            proto_tree_add_text(opt_tree, tvb, offset,  2 + len, "%s", name);
          }
        }
        offset += 2 + len;
      }
      length -= len;
    } else {
      proto_tree_add_text(opt_tree, tvb, offset,      1, "%s", name);
      offset += 1;
    }
    if (opt == eol)
      break;
  }
}

static int
dissect_opts(tvbuff_t *tvb, int offset, proto_tree *tree, const char *optname)
{
    struct ip6_ext ext;
    int len;
    proto_tree *dstopt_tree;
    proto_item *ti;
    gint p;
    guint8 tmp;
    int mip_offset = 0, delta = 0;

    tvb_memcpy(tvb, (guint8 *)&ext, offset, sizeof(ext));
    len = (ext.ip6e_len + 1) << 3;

    if (tree) {
	/* !!! specify length */
	ti = proto_tree_add_text(tree, tvb, offset, len, "%s Header ", optname);

	dstopt_tree = proto_item_add_subtree(ti, ett_ipv6);

	proto_tree_add_text(dstopt_tree, tvb,
	    offset + offsetof(struct ip6_ext, ip6e_nxt), 1,
	    "Next header: %s (0x%02x)", ipprotostr(ext.ip6e_nxt), ext.ip6e_nxt);
	proto_tree_add_text(dstopt_tree, tvb,
	    offset + offsetof(struct ip6_ext, ip6e_len), 1,
	    "Length: %u (%d bytes)", ext.ip6e_len, len);

	mip_offset = offset;
	mip_offset += 2;

	p = offset + 2;

	while (p < offset + len) {
	    switch (tvb_get_guint8(tvb, p)) {
	    case IP6OPT_PAD1:
		proto_tree_add_text(dstopt_tree, tvb, p, 1, "Pad1");
		p++;
		mip_offset++;
		break;
	    case IP6OPT_PADN:
		tmp = tvb_get_guint8(tvb, p + 1);
		proto_tree_add_text(dstopt_tree, tvb, p, tmp + 2,
		    "PadN: %u bytes", tmp + 2);
		p += tmp;
		p += 2;
		mip_offset += tvb_get_guint8(tvb, mip_offset + 1) + 2;
		break;
	    case IP6OPT_JUMBO:
		tmp = tvb_get_guint8(tvb, p + 1);
		if (tmp == 4) {
		    proto_tree_add_text(dstopt_tree, tvb, p, tmp + 2,
			"Jumbo payload: %u (%u bytes)",
			tvb_get_ntohl(tvb, p + 2), tmp + 2);
		} else {
		    proto_tree_add_text(dstopt_tree, tvb, p, tmp + 2,
			"Jumbo payload: Invalid length (%u bytes)",
			tmp + 2);
		}
		p += tmp;
		p += 2;
		mip_offset += tvb_get_guint8(tvb, mip_offset+1)+2;
		break;
	    case IP6OPT_RTALERT:
	      {
		const char *rta;

		tmp = tvb_get_guint8(tvb, p + 1);
		if (tmp == 2) {
		    rta = val_to_str(tvb_get_ntohs(tvb, p + 2), rtalertvals,
			"Unknown");
		} else
		    rta = "Invalid length";
		ti = proto_tree_add_text(dstopt_tree, tvb, p , tmp + 2,
		    "Router alert: %s (%u bytes)", rta, tmp + 2);
		p += tmp;
		p += 2;
		mip_offset += tvb_get_guint8(tvb, mip_offset + 1) + 2;
		break;
	      }
	    case IP6OPT_HOME_ADDRESS:
		delta = dissect_mipv6_hoa(tvb, dstopt_tree, mip_offset);
		p += delta;
		mip_offset += delta;
		break;
	    default:
		p = offset + len;
		break;
	    }
	}

	/* decode... */
    }
    return len;
}

static int
dissect_hopopts(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    return dissect_opts(tvb, offset, tree, "Hop-by-hop Option");
}

static int
dissect_dstopts(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    return dissect_opts(tvb, offset, tree, "Destination Option");
}

static void
dissect_ipv6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *ipv6_tree = NULL;
  proto_item *ti;
  guint8 nxt;
  int advance;
  int poffset;
  guint16 plen;
  gboolean hopopts, routing, frag, ah, dstopts;
  guint16 offlg;
  guint32 ident;
  int offset;
  fragment_data *ipfd_head;
  tvbuff_t   *next_tvb;
  gboolean update_col_info = TRUE;
  gboolean save_fragmented;

  struct ip6_hdr ipv6;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPv6");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  offset = 0;
  tvb_memcpy(tvb, (guint8 *)&ipv6, offset, sizeof(ipv6));

  pinfo->ipproto = ipv6.ip6_nxt; /* XXX make work TCP follow (ipproto = 6) */

  /* Get the payload length */
  plen = g_ntohs(ipv6.ip6_plen);

  /* Adjust the length of this tvbuff to include only the IPv6 datagram. */
  set_actual_length(tvb, plen + sizeof (struct ip6_hdr));

  SET_ADDRESS(&pinfo->net_src, AT_IPv6, 16, tvb_get_ptr(tvb, offset + IP6H_SRC, 16));
  SET_ADDRESS(&pinfo->src, AT_IPv6, 16, tvb_get_ptr(tvb, offset + IP6H_SRC, 16));
  SET_ADDRESS(&pinfo->net_dst, AT_IPv6, 16, tvb_get_ptr(tvb, offset + IP6H_DST, 16));
  SET_ADDRESS(&pinfo->dst, AT_IPv6, 16, tvb_get_ptr(tvb, offset + IP6H_DST, 16));

  if (tree) {
    /* !!! specify length */
    ti = proto_tree_add_item(tree, proto_ipv6, tvb, offset, 40, FALSE);
    ipv6_tree = proto_item_add_subtree(ti, ett_ipv6);

    /* !!! warning: version also contains 4 Bit priority */
    proto_tree_add_uint(ipv6_tree, hf_ipv6_version, tvb,
		offset + offsetof(struct ip6_hdr, ip6_vfc), 1,
		(ipv6.ip6_vfc >> 4) & 0x0f);

    proto_tree_add_uint(ipv6_tree, hf_ipv6_class, tvb,
		offset + offsetof(struct ip6_hdr, ip6_flow), 4,
		(guint8)((g_ntohl(ipv6.ip6_flow) >> 20) & 0xff));

    /*
     * there should be no alignment problems for ip6_flow, since it's the first
     * guint32 in the ipv6 struct
     */
    proto_tree_add_uint_format(ipv6_tree, hf_ipv6_flow, tvb,
		offset + offsetof(struct ip6_hdr, ip6_flow), 4,
		(unsigned long)(g_ntohl(ipv6.ip6_flow) & IPV6_FLOWLABEL_MASK),
		"Flowlabel: 0x%05lx",
		(unsigned long)(g_ntohl(ipv6.ip6_flow) & IPV6_FLOWLABEL_MASK));

    proto_tree_add_uint(ipv6_tree, hf_ipv6_plen, tvb,
		offset + offsetof(struct ip6_hdr, ip6_plen), 2,
		plen);

    proto_tree_add_uint_format(ipv6_tree, hf_ipv6_nxt, tvb,
		offset + offsetof(struct ip6_hdr, ip6_nxt), 1,
		ipv6.ip6_nxt,
		"Next header: %s (0x%02x)",
		ipprotostr(ipv6.ip6_nxt), ipv6.ip6_nxt);

    proto_tree_add_uint(ipv6_tree, hf_ipv6_hlim, tvb,
		offset + offsetof(struct ip6_hdr, ip6_hlim), 1,
		ipv6.ip6_hlim);

    proto_tree_add_ipv6_hidden(ipv6_tree, hf_ipv6_addr, tvb,
			       offset + offsetof(struct ip6_hdr, ip6_src), 16,
			       ipv6.ip6_src.bytes);
    proto_tree_add_ipv6_hidden(ipv6_tree, hf_ipv6_addr, tvb,
			       offset + offsetof(struct ip6_hdr, ip6_dst), 16,
			       ipv6.ip6_dst.bytes);

    proto_tree_add_ipv6_format(ipv6_tree, hf_ipv6_src, tvb,
		offset + offsetof(struct ip6_hdr, ip6_src), 16,
		(guint8 *)&ipv6.ip6_src,
#ifdef INET6
		"Source address: %s (%s)",
		get_hostname6(&ipv6.ip6_src),
#else
		"Source address: %s",
#endif
		ip6_to_str(&ipv6.ip6_src));

    proto_tree_add_ipv6_format(ipv6_tree, hf_ipv6_dst, tvb,
		offset + offsetof(struct ip6_hdr, ip6_dst), 16,
		(guint8 *)&ipv6.ip6_dst,
#ifdef INET6
		"Destination address: %s (%s)",
		get_hostname6(&ipv6.ip6_dst),
#else
		"Destination address: %s",
#endif
		ip6_to_str(&ipv6.ip6_dst));
  }

  /* start of the new header (could be a extension header) */
  poffset = offset + offsetof(struct ip6_hdr, ip6_nxt);
  nxt = tvb_get_guint8(tvb, poffset);
  offset += sizeof(struct ip6_hdr);
  offlg = 0;
  ident = 0;

/* start out assuming this isn't fragmented, and has none of the other
   non-final headers */
  hopopts = FALSE;
  routing = FALSE;
  frag = FALSE;
  ah = FALSE;
  dstopts = FALSE;

again:
   switch (nxt) {
   case IP_PROTO_HOPOPTS:
			hopopts = TRUE;
			advance = dissect_hopopts(tvb, offset, tree);
			nxt = tvb_get_guint8(tvb, offset);
			poffset = offset;
			offset += advance;
			plen -= advance;
			goto again;
    case IP_PROTO_ROUTING:
			routing = TRUE;
			advance = dissect_routing6(tvb, offset, tree);
			nxt = tvb_get_guint8(tvb, offset);
			poffset = offset;
			offset += advance;
			plen -= advance;
			goto again;
    case IP_PROTO_FRAGMENT:
			frag = TRUE;
			advance = dissect_frag6(tvb, offset, pinfo, tree,
			    &offlg, &ident);
			nxt = tvb_get_guint8(tvb, offset);
			poffset = offset;
			offset += advance;
			plen -= advance;
			goto again;
    case IP_PROTO_AH:
			ah = TRUE;
			advance = dissect_ah_header(
				  tvb_new_subset(tvb, offset, -1, -1),
				  pinfo, tree, NULL, NULL);
			nxt = tvb_get_guint8(tvb, offset);
			poffset = offset;
			offset += advance;
			plen -= advance;
			goto again;
    case IP_PROTO_DSTOPTS:
			dstopts = TRUE;
			advance = dissect_dstopts(tvb, offset, tree);
			nxt = tvb_get_guint8(tvb, offset);
			poffset = offset;
			offset += advance;
			plen -= advance;
			goto again;
    }

#ifdef TEST_FINALHDR
  proto_tree_add_uint_hidden(ipv6_tree, hf_ipv6_final, tvb, poffset, 1, nxt);
#endif

  /* If ipv6_reassemble is on, this is a fragment, and we have all the data
   * in the fragment, then just add the fragment to the hashtable.
   */
  save_fragmented = pinfo->fragmented;
  if (ipv6_reassemble && frag && tvb_bytes_exist(tvb, offset, plen)) {
    ipfd_head = fragment_add_check(tvb, offset, pinfo, ident,
			     ipv6_fragment_table,
			     ipv6_reassembled_table,
			     offlg & IP6F_OFF_MASK,
			     plen,
			     offlg & IP6F_MORE_FRAG);

    next_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled IPv6",
          ipfd_head, &ipv6_frag_items, &update_col_info, ipv6_tree);
  } else {
    /* If this is the first fragment, dissect its contents, otherwise
       just show it as a fragment.

       XXX - if we eventually don't save the reassembled contents of all
       fragmented datagrams, we may want to always reassemble. */
    if (offlg & IP6F_OFF_MASK) {
      /* Not the first fragment - don't dissect it. */
      next_tvb = NULL;
    } else {
      /* First fragment, or not fragmented.  Dissect what we have here. */

      /* Get a tvbuff for the payload. */
      next_tvb = tvb_new_subset(tvb, offset, -1, -1);

      /*
       * If this is the first fragment, but not the only fragment,
       * tell the next protocol that.
       */
      if (offlg & IP6F_MORE_FRAG)
        pinfo->fragmented = TRUE;
      else
        pinfo->fragmented = FALSE;
    }
  }

  if (next_tvb == NULL) {
    /* Just show this as a fragment. */
    /* COL_INFO was filled in by "dissect_frag6()" */
    call_dissector(data_handle, tvb_new_subset(tvb, offset, -1, -1), pinfo, tree);

    /* As we haven't reassembled anything, we haven't changed "pi", so
       we don't have to restore it. */
    pinfo->fragmented = save_fragmented;
    return;
  }

  /* do lookup with the subdissector table */
  if (!dissector_try_port(ip_dissector_table, nxt, next_tvb, pinfo, tree)) {
    /* Unknown protocol.
       Handle "no next header" specially. */
    if (nxt == IP_PROTO_NONE) {
      if (check_col(pinfo->cinfo, COL_INFO)) {
        /* If we had an Authentication Header, the AH dissector already
           put something in the Info column; leave it there. */
      	if (!ah) {
          if (hopopts || routing || dstopts) {
            const char *sep = "IPv6 ";
            if (hopopts) {
              col_append_fstr(pinfo->cinfo, COL_INFO, "%shop-by-hop options",
                             sep);
              sep = ", ";
            }
            if (routing) {
              col_append_fstr(pinfo->cinfo, COL_INFO, "%srouting", sep);
              sep = ", ";
            }
            if (dstopts) {
              col_append_fstr(pinfo->cinfo, COL_INFO, "%sdestination options",
                              sep);
            }
          } else
            col_set_str(pinfo->cinfo, COL_INFO, "IPv6 no next header");
	}
      }
    } else {
      if (check_col(pinfo->cinfo, COL_INFO))
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s (0x%02x)", ipprotostr(nxt),nxt);
    }
    call_dissector(data_handle, next_tvb, pinfo, tree);
  }
  pinfo->fragmented = save_fragmented;
}

void
proto_register_ipv6(void)
{
  static hf_register_info hf[] = {
    { &hf_ipv6_version,
      { "Version",		"ipv6.version",
				FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_ipv6_class,
      { "Traffic class",	"ipv6.class",
				FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_ipv6_flow,
      { "Flowlabel",		"ipv6.flow",
				FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_ipv6_plen,
      { "Payload length",	"ipv6.plen",
				FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_ipv6_nxt,
      { "Next header",		"ipv6.nxt",
				FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_ipv6_hlim,
      { "Hop limit",		"ipv6.hlim",
				FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_ipv6_src,
      { "Source",		"ipv6.src",
				FT_IPv6, BASE_NONE, NULL, 0x0,
				"Source IPv6 Address", HFILL }},
    { &hf_ipv6_dst,
      { "Destination",		"ipv6.dst",
				FT_IPv6, BASE_NONE, NULL, 0x0,
				"Destination IPv6 Address", HFILL }},
    { &hf_ipv6_addr,
      { "Address",		"ipv6.addr",
				FT_IPv6, BASE_NONE, NULL, 0x0,
				"Source or Destination IPv6 Address", HFILL }},

    { &hf_ipv6_fragment_overlap,
      { "Fragment overlap",	"ipv6.fragment.overlap",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0,
				"Fragment overlaps with other fragments", HFILL }},

    { &hf_ipv6_fragment_overlap_conflict,
      { "Conflicting data in fragment overlap",	"ipv6.fragment.overlap.conflict",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0,
				"Overlapping fragments contained conflicting data", HFILL }},

    { &hf_ipv6_fragment_multiple_tails,
      { "Multiple tail fragments found", "ipv6.fragment.multipletails",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0,
				"Several tails were found when defragmenting the packet", HFILL }},

    { &hf_ipv6_fragment_too_long_fragment,
      { "Fragment too long",	"ipv6.fragment.toolongfragment",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0,
				"Fragment contained data past end of packet", HFILL }},

    { &hf_ipv6_fragment_error,
      { "Defragmentation error", "ipv6.fragment.error",
				FT_FRAMENUM, BASE_NONE, NULL, 0x0,
				"Defragmentation error due to illegal fragments", HFILL }},

    { &hf_ipv6_fragment,
      { "IPv6 Fragment",	"ipv6.fragment",
				FT_FRAMENUM, BASE_NONE, NULL, 0x0,
				"IPv6 Fragment", HFILL }},

    { &hf_ipv6_fragments,
      { "IPv6 Fragments",	"ipv6.fragments",
				FT_NONE, BASE_NONE, NULL, 0x0,
				"IPv6 Fragments", HFILL }},

    { &hf_ipv6_reassembled_in,
      { "Reassembled IPv6 in frame", "ipv6.reassembled_in",
				FT_FRAMENUM, BASE_NONE, NULL, 0x0,
				"This IPv6 packet is reassembled in this frame", HFILL }},

    /* Mobile IPv6 */
    { &hf_ipv6_mipv6_type,
      { "Option Type ",		"ipv6.mipv6_type",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				"", HFILL }},
    { &hf_ipv6_mipv6_length,
      { "Option Length ",	"ipv6.mipv6_length",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				"", HFILL }},
    { &hf_ipv6_mipv6_home_address,
      { "Home Address ",	"ipv6.mipv6_home_address",
				FT_IPv6, BASE_HEX, NULL, 0x0,
				"", HFILL }},

#ifdef TEST_FINALHDR
    { &hf_ipv6_final,
      { "Final next header",	"ipv6.final",
				FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }},
#endif
  };
  static gint *ett[] = {
    &ett_ipv6,
    &ett_ipv6_fragments,
    &ett_ipv6_fragment,
  };
  module_t *ipv6_module;

  proto_ipv6 = proto_register_protocol("Internet Protocol Version 6", "IPv6", "ipv6");
  proto_register_field_array(proto_ipv6, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register configuration options */
  ipv6_module = prefs_register_protocol(proto_ipv6, NULL);
  prefs_register_bool_preference(ipv6_module, "defragment",
	"Reassemble fragmented IPv6 datagrams",
	"Whether fragmented IPv6 datagrams should be reassembled",
	&ipv6_reassemble);

  register_dissector("ipv6", dissect_ipv6, proto_ipv6);
  register_init_routine(ipv6_reassemble_init);
}

void
proto_reg_handoff_ipv6(void)
{
  dissector_handle_t ipv6_handle;

  data_handle = find_dissector("data");
  ipv6_handle = find_dissector("ipv6");
  dissector_add("ethertype", ETHERTYPE_IPv6, ipv6_handle);
  dissector_add("ppp.protocol", PPP_IPV6, ipv6_handle);
  dissector_add("ppp.protocol", ETHERTYPE_IPv6, ipv6_handle);
  dissector_add("gre.proto", ETHERTYPE_IPv6, ipv6_handle);
  dissector_add("ip.proto", IP_PROTO_IPV6, ipv6_handle);
  dissector_add("null.type", BSD_AF_INET6_BSD, ipv6_handle);
  dissector_add("null.type", BSD_AF_INET6_FREEBSD, ipv6_handle);
  dissector_add("null.type", BSD_AF_INET6_DARWIN, ipv6_handle);
  dissector_add("chdlctype", ETHERTYPE_IPv6, ipv6_handle);
  dissector_add("fr.ietf", NLPID_IP6, ipv6_handle);
  dissector_add("osinl.excl", NLPID_IP6, ipv6_handle);
  dissector_add("x.25.spi", NLPID_IP6, ipv6_handle);
  dissector_add("arcnet.protocol_id", ARCNET_PROTO_IPv6, ipv6_handle);

  ip_dissector_table = find_dissector_table("ip.proto");
}
