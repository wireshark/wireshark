/* packet-icmpv6.c
 * Routines for ICMPv6 packet disassembly 
 *
 * $Id: packet-icmpv6.c,v 1.17 2000/05/31 05:07:06 guy Exp $
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

#ifdef NEED_SNPRINTF_H
# ifdef HAVE_STDARG_H
#  include <stdarg.h>
# else
#  include <varargs.h>
# endif
# include "snprintf.h"
#endif

#include <glib.h>
#include "packet.h"
#include "packet-ipv6.h"
#include "packet-ip.h"
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
	    dissect_data(pd, offset + 8, fd, icmp6opt_tree);
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

static void
dissect_icmpv6(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
    proto_tree *icmp6_tree, *field_tree;
	proto_item *ti, *tf = NULL;
    struct icmp6_hdr *dp;
    char *codename, *typename;
    int len;

    dp = (struct icmp6_hdr *)&pd[offset];
    codename = typename = "Unknown";
    len = sizeof(*dp);
    switch (dp->icmp6_type) {
    case ICMP6_DST_UNREACH:
	typename = "Unreachable";
	switch (dp->icmp6_code) {
	case ICMP6_DST_UNREACH_NOROUTE:
	    codename = "Route unreachable";
	    break;
	case ICMP6_DST_UNREACH_ADMIN:
	    codename = "Administratively prohibited";
	    break;
	case ICMP6_DST_UNREACH_NOTNEIGHBOR:
	    codename = "Not a neighbor";
	    break;
	case ICMP6_DST_UNREACH_ADDR:
	    codename = "Address unreachable";
	    break;
	case ICMP6_DST_UNREACH_NOPORT:
	    codename = "Port unreachable";
	    break;
	}
	break;
    case ICMP6_PACKET_TOO_BIG:
	typename = "Too big";
	codename = NULL;
	break;
    case ICMP6_TIME_EXCEEDED:
	typename = "Time exceeded";
	switch (dp->icmp6_code) {
	case ICMP6_TIME_EXCEED_TRANSIT:
	    codename = "In-transit";
	    break;
	case ICMP6_TIME_EXCEED_REASSEMBLY:
	    codename = "Reassembly";
	    break;
	}
        break;
    case ICMP6_PARAM_PROB:
	typename = "Parameter problem";
	switch (dp->icmp6_code) {
	case ICMP6_PARAMPROB_HEADER:
	    codename = "Header";
	    break;
	case ICMP6_PARAMPROB_NEXTHEADER:
	    codename = "Next header";
	    break;
	case ICMP6_PARAMPROB_OPTION:
	    codename = "Option";
	    break;
	}
        break;
    case ICMP6_ECHO_REQUEST:
	typename = "Echo request";
	codename = NULL;
	break;
    case ICMP6_ECHO_REPLY:
	typename = "Echo reply";
	codename = NULL;
	break;
    case ICMP6_MEMBERSHIP_QUERY:
	typename = "Multicast listener query";
	codename = NULL;
	break;
    case ICMP6_MEMBERSHIP_REPORT:
	typename = "Multicast listener report";
	codename = NULL;
	break;
    case ICMP6_MEMBERSHIP_REDUCTION:
	typename = "Multicast listener done";
	codename = NULL;
	break;
    case ND_ROUTER_SOLICIT:
	typename = "Router solicitation";
	codename = NULL;
	len = sizeof(struct nd_router_solicit);
	break;
    case ND_ROUTER_ADVERT:
	typename = "Router advertisement";
	codename = NULL;
	len = sizeof(struct nd_router_advert);
	break;
    case ND_NEIGHBOR_SOLICIT:
	typename = "Neighbor solicitation";
	codename = NULL;
	len = sizeof(struct nd_neighbor_solicit);
	break;
    case ND_NEIGHBOR_ADVERT:
	typename = "Neighbor advertisement";
	codename = NULL;
	len = sizeof(struct nd_neighbor_advert);
	break;
    case ND_REDIRECT:
	typename = "Redirect";
	codename = NULL;
	len = sizeof(struct nd_redirect);
	break;
    case ICMP6_ROUTER_RENUMBERING:
	typename = "Router renumbering";
	switch (dp->icmp6_code) {
	case ICMP6_ROUTER_RENUMBERING_COMMAND:
	    codename = "Command";
	    break;
	case ICMP6_ROUTER_RENUMBERING_RESULT:
	    codename = "Result";
	    break;
	}
	len = sizeof(struct icmp6_router_renum);
	break;
    }

    if (check_col(fd, COL_PROTOCOL))
	col_add_str(fd, COL_PROTOCOL, "ICMPv6");
    if (check_col(fd, COL_INFO)) {
	char typebuf[256], codebuf[256];

	if (typename && strcmp(typename, "Unknown") == 0) {
	    snprintf(typebuf, sizeof(typebuf), "Unknown (0x%02x)",
		dp->icmp6_type);
	    typename = typebuf;
	}
	if (codename && strcmp(codename, "Unknown") == 0) {
	    snprintf(codebuf, sizeof(codebuf), "Unknown (0x%02x)",
		dp->icmp6_code);
	    codename = codebuf;
	}
	if (codename) {
	    col_add_fstr(fd, COL_INFO, "%s (%s)",
		typename, codename);
	} else {
	    col_add_fstr(fd, COL_INFO, "%s", typename);
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
		dissect_data(pd, offset + sizeof(*dp), fd, icmp6_tree);
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
		dissect_data(pd, offset + sizeof(*dp), fd, icmp6_tree);
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
		dissect_data(pd, offset + sizeof(*dp), fd, icmp6_tree);
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
	    dissect_data(pd, offset + sizeof(*dp), fd, icmp6_tree);
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
	    dissect_data(pd, offset + sizeof(*rr), fd, tree);	/*XXX*/
	  }
	default:
	    dissect_data(pd, offset + sizeof(*dp), fd, tree);
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
  };

  proto_icmpv6 = proto_register_protocol("Internet Control Message Protocol v6",
					 "icmpv6");
  proto_register_field_array(proto_icmpv6, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_icmpv6(void)
{
  dissector_add("ip.proto", IP_PROTO_ICMPV6, dissect_icmpv6);
}

