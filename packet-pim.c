/* packet-pim.c
 * Routines for PIM disassembly
 * (c) Copyright Jun-ichiro itojun Hagino <itojun@itojun.org>
 *
 * $Id: packet-pim.c,v 1.24 2001/02/08 08:38:58 guy Exp $
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
#include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <string.h>
#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include "packet.h"
#include "packet-ip.h"
#include "packet-ipv6.h"
#include "in_cksum.h"

#define PIM_TYPE(x)	((x) & 0x0f)
#define PIM_VER(x)	(((x) & 0xf0) >> 4)

enum pimv2_addrtype {
	pimv2_unicast, pimv2_group, pimv2_source
};

static int proto_pim = -1;
static int hf_pim_version = -1;
static int hf_pim_type = -1;
static int hf_pim_cksum = -1;

static gint ett_pim = -1;

static dissector_handle_t ip_handle;

/*
 * Address family values.
 */
#define PIM_AF_RESERVED		0
#define PIM_AF_IP		1	/* IPv4 */
#define PIM_AF_IPV6		2	/* IPv6 */
#define PIM_AF_NSAP		3	/* NSAP */
#define PIM_AF_HDLC		4	/* HDLC (8-bit multidrop) */
#define PIM_AF_BBN_1822		5	/* BBN 1822 */
#define PIM_AF_802		6	/* 802 (D/I/X Ethernet, 802.x, FDDI) */
#define PIM_AF_E_163		7	/* E.163 */
#define PIM_AF_E_164		8	/* E.164 (SMDS, Frame Relay, ATM) */
#define PIM_AF_F_69		9	/* F.69 (Telex) */
#define PIM_AF_X_121		10	/* X.121 (X.25, Frame Relay) */
#define PIM_AF_IPX		11	/* IPX */
#define PIM_AF_ATALK		12	/* Appletalk */
#define PIM_AF_DECNET_IV	13	/* DECnet Phase IV */
#define PIM_AF_VINES		14	/* Banyan Vines */
#define PIM_AF_E_164_NSAP	15	/* E.164 with NSAP format subaddress */

static const char *
dissect_pim_addr(tvbuff_t *tvb, int offset, enum pimv2_addrtype at,
	int *advance) {
    static char buf[512];
    guint8 af;
    guint8 et;
    guint8 flags;
    guint8 mask_len;
    int len = 0;

    af = tvb_get_guint8(tvb, offset);
    if (af != PIM_AF_IP && af != PIM_AF_IPV6) {
	/*
	 * We don't handle the other formats, and addresses don't include
	 * a length field, so we can't even show them as raw bytes.
	 */
	return NULL;
    }

    et = tvb_get_guint8(tvb, offset + 1);
    if (et != 0) {
	/*
	 * The only defined encoding type is 0, for the native encoding;
	 * again, as addresses don't include a length field, we can't
	 * even show addresses with a different encoding type as raw
	 * bytes.
	 */
	return NULL;
    }

    switch (at) {
    case pimv2_unicast:
	switch (af) {
	case PIM_AF_IP:
	    len = 4;
	    (void)snprintf(buf, sizeof(buf), "%s",
	        ip_to_str(tvb_get_ptr(tvb, offset + 2, len)));
	    break;

	case PIM_AF_IPV6:
	    len = 16;
	    (void)snprintf(buf, sizeof(buf), "%s",
		ip6_to_str((struct e_in6_addr *)tvb_get_ptr(tvb, offset + 2, len)));
	    break;
	}
	if (advance)
	    *advance = 2 + len;
	break;

    case pimv2_group:
	mask_len = tvb_get_guint8(tvb, offset + 3);
	switch (af) {
	case PIM_AF_IP:
	    len = 4;
	    (void)snprintf(buf, sizeof(buf), "%s/%u",
		ip_to_str(tvb_get_ptr(tvb, offset + 4, len)), mask_len);
	    break;

	case PIM_AF_IPV6:
	    len = 16;
	    (void)snprintf(buf, sizeof(buf), "%s/%u",
		ip6_to_str((struct e_in6_addr *)tvb_get_ptr(tvb, offset + 4, len)), mask_len);
	    break;
	}
	if (advance)
	    *advance = 4 + len;
	break;

    case pimv2_source:
	flags = tvb_get_guint8(tvb, offset + 2);
	mask_len = tvb_get_guint8(tvb, offset + 3);
	switch (af) {
	case PIM_AF_IP:
	    len = 4;
	    (void)snprintf(buf, sizeof(buf), "%s/%u",
		ip_to_str(tvb_get_ptr(tvb, offset + 4, len)), mask_len);
	    break;

	case PIM_AF_IPV6:
	    len = 16;
	    (void)snprintf(buf, sizeof(buf), "%s/%u",
		ip6_to_str((struct e_in6_addr *)tvb_get_ptr(tvb, offset + 4, len)), mask_len);
	    break;
	}
	if (flags) {
	    (void)snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf),
		" (%s%s%s)",
		flags & 0x04 ? "S" : "",
		flags & 0x02 ? "W" : "",
		flags & 0x01 ? "R" : "");
	}
	if (advance)
	    *advance = 4 + len;
	break;
    default:
	return NULL;
    }

    return buf;
}

static void 
dissect_pim(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    int offset = 0;
    guint8 pim_typever;
    guint length, pim_length;
    guint16 pim_cksum, computed_cksum;
    vec_t cksum_vec[1];
    static const value_string type1vals[] = {
	{ 0, "Query" },
	{ 1, "Register" },
	{ 2, "Register-stop" },
	{ 3, "Join/Prune" },
	{ 4, "RP-Reachable" },
	{ 5, "Assert" },
	{ 6, "Graft" },
	{ 7, "Graft-Ack" },
	{ 8, "Mode" },
	{ 0, NULL },
    };
    static const value_string type2vals[] = {
	{ 0, "Hello" },
	{ 1, "Register" },
	{ 2, "Register-stop" },
	{ 3, "Join/Prune" },
	{ 4, "Bootstrap" },
	{ 5, "Assert" },
	{ 6, "Graft" },
	{ 7, "Graft-Ack" },
	{ 8, "Candidate-RP-Advertisement" },
	{ 0, NULL },
    };
    char *typestr;
    proto_tree *pim_tree = NULL;
    proto_item *ti; 
    proto_tree *pimopt_tree = NULL;
    proto_item *tiopt; 

    if (check_col(pinfo->fd, COL_PROTOCOL))
        col_set_str(pinfo->fd, COL_PROTOCOL, "PIM");
    if (check_col(pinfo->fd, COL_INFO))
	col_clear(pinfo->fd, COL_INFO);

    pim_typever = tvb_get_guint8(tvb, 0);

    switch (PIM_VER(pim_typever)) {
    case 1:
	typestr = val_to_str(PIM_TYPE(pim_typever), type1vals, "Unknown");
	break;
    case 2:
	typestr = val_to_str(PIM_TYPE(pim_typever), type2vals, "Unknown");
	break;
    default:
	typestr = "Unknown";
	break;
    }

    if (check_col(pinfo->fd, COL_PROTOCOL)) {
        col_add_fstr(pinfo->fd, COL_PROTOCOL, "PIM version %d",
	    PIM_VER(pim_typever));
    }
    if (check_col(pinfo->fd, COL_INFO))
	col_add_fstr(pinfo->fd, COL_INFO, "%s", typestr); 

    if (tree) {
	ti = proto_tree_add_item(tree, proto_pim, tvb, offset,
	    tvb_length_remaining(tvb, offset), FALSE);
	pim_tree = proto_item_add_subtree(ti, ett_pim);

	proto_tree_add_uint(pim_tree, hf_pim_version, tvb, offset, 1,
	    PIM_VER(pim_typever)); 
	proto_tree_add_uint_format(pim_tree, hf_pim_type, tvb, offset, 1,
	    PIM_TYPE(pim_typever),
	    "Type: %s (%u)", typestr, PIM_TYPE(pim_typever)); 

	pim_cksum = tvb_get_ntohs(tvb, offset + 2);
	length = tvb_length(tvb);
	if (PIM_VER(pim_typever) == 2) {
	    /*
	     * Well, it's PIM v2, so we can check whether this is a Register
	     * mesage, and thus can figure out how much to checksum.
	     */
	    if (PIM_TYPE(pim_typever) == 1) {
		/*
		 * Register message - the PIM header is 8 bytes long.
		 */
		pim_length = 8;
	    } else {
		/*
		 * Other message - checksum the entire packet.
		 */
		pim_length = tvb_reported_length(tvb);
	    }
	} else {
	    /*
	     * We don't know what type of message this is, so say that
	     * the length is 0, to force it not to be checksummed.
	     */
	    pim_length = 0;
	}
	if (!pinfo->fragmented && length >= pim_length) {
	    /*
	     * The packet isn't part of a fragmented datagram and isn't
	     * truncated, so we can checksum it.
	     */
	    cksum_vec[0].ptr = tvb_get_ptr(tvb, 0, pim_length);
	    cksum_vec[0].len = pim_length;
	    computed_cksum = in_cksum(&cksum_vec[0], 1);
	    if (computed_cksum == 0) {
		proto_tree_add_uint_format(pim_tree, hf_pim_cksum, tvb,
			offset + 2, 2, pim_cksum,
			"Checksum: 0x%04x (correct)",
			pim_cksum);
	    } else {
		proto_tree_add_uint_format(pim_tree, hf_pim_cksum, tvb,
			offset + 2, 2, pim_cksum,
			"Checksum: 0x%04x (incorrect, should be 0x%04x)",
			pim_cksum, in_cksum_shouldbe(pim_cksum, computed_cksum));
	    }
	} else {
	    proto_tree_add_uint(pim_tree, hf_pim_cksum, tvb,
		offset + 2, 2, pim_cksum);
	}

	offset += 4;

	if (tvb_reported_length_remaining(tvb, offset) > 0) {
	    tiopt = proto_tree_add_text(pim_tree, tvb, offset,
	        tvb_length_remaining(tvb, offset), "PIM parameters");
	    pimopt_tree = proto_item_add_subtree(tiopt, ett_pim);
	} else
	    goto done;

	if (PIM_VER(pim_typever) != 2)
	    goto done;

	/* version 2 decoder */
	switch (PIM_TYPE(pim_typever)) {
	case 0:	/*hello*/
	  {
	    while (tvb_reported_length_remaining(tvb, offset) >= 2) {
		if (tvb_get_ntohs(tvb, offset) == 1 &&
		    tvb_get_ntohs(tvb, offset + 2) == 2) {
		    guint16 holdtime;

		    holdtime = tvb_get_ntohs(tvb, offset + 4);
		    proto_tree_add_text(pimopt_tree, tvb, offset, 6,
			"Holdtime: %u%s", holdtime,
			holdtime == 0xffff ? " (infty)" : "");
		    offset += 6;
		} else
		    break;
	    }
	    break;
	  }

	case 1:	/* register */
	  {
	    guint32 flags;
	    guint8 v_hl;
	    tvbuff_t *next_tvb;
	    const guint8 *next_pd;
	    int next_offset;
	    proto_tree *flag_tree = NULL;
	    proto_item *tiflag; 

	    flags = tvb_get_ntohl(tvb, offset);
	    tiflag = proto_tree_add_text(pimopt_tree, tvb, offset, 4,
		"Flags: 0x%08x", flags);
	    flag_tree = proto_item_add_subtree(tiflag, ett_pim);
	    proto_tree_add_text(flag_tree, tvb, offset, 1, "%s",
		decode_boolean_bitfield(flags, 0x80000000, 32,
		    "Border", "Not border"));
	    proto_tree_add_text(flag_tree, tvb, offset, 1, "%s",
		decode_boolean_bitfield(flags, 0x40000000, 32,
		    "Null-Register", "Not Null-Register"));
	    offset += 4;
	    
	    /*
	     * The rest of the packet is a multicast data packet.
	     */
	    next_tvb = tvb_new_subset(tvb, offset, -1, -1);

	    /*
	     * It's an IP packet - determine whether it's IPv4 or IPv6.
	     */
	    v_hl = tvb_get_guint8(tvb, offset);
	    switch((v_hl & 0xf0) >> 4) {
	    case 4:	/* IPv4 */
#if 0
		    call_dissector(ip_handle, next_tvb, pinfo, tree);
#else
		    call_dissector(ip_handle, next_tvb, pinfo, pimopt_tree);
#endif
		    break;
	    case 6:	/* IPv6 */
	    	    tvb_compat(next_tvb, &next_pd, &next_offset);
#if 0
		    dissect_ipv6(next_pd, next_offset, pinfo->fd, tree);
#else
		    dissect_ipv6(next_pd, next_offset, pinfo->fd, pimopt_tree);
#endif
		    break;
	    default:
		    proto_tree_add_text(pimopt_tree, tvb,
			offset, tvb_length_remaining(tvb, offset),
			"Unknown IP version %d", (v_hl & 0xf0) >> 4);
		    break;
	    }
	    break;
	  }

	case 2:	/* register-stop */
	  {
	    int advance;
	    const char *s;

	    s = dissect_pim_addr(tvb, offset, pimv2_group, &advance);
	    if (s == NULL)
		break;
	    proto_tree_add_text(pimopt_tree, tvb, offset, advance, "Group: %s", s);
	    offset += advance;
	    s = dissect_pim_addr(tvb, offset, pimv2_unicast, &advance);
	    if (s == NULL)
		break;
	    proto_tree_add_text(pimopt_tree, tvb, offset, advance, "Source: %s", s);
	    break;
	  }

	case 3:	/* join/prune */
	case 6:	/* graft */
	case 7:	/* graft-ack */
	  {
	    int advance;
	    int off;
	    const char *s;
	    int ngroup, i, njoin, nprune, j;
	    guint16 holdtime;
	    proto_tree *grouptree = NULL;
	    proto_item *tigroup; 
	    proto_tree *subtree = NULL;
	    proto_item *tisub; 

	    if (PIM_TYPE(pim_typever) != 7) {
		/* not graft-ack */
		s = dissect_pim_addr(tvb, offset, pimv2_unicast, &advance);
		if (s == NULL)
		    break;
		proto_tree_add_text(pimopt_tree, tvb, offset, advance,
		    "Upstream-neighbor: %s", s);
		offset += advance;
	    }

	    offset += 1;	/* skip reserved field */

	    ngroup = tvb_get_guint8(tvb, offset);
	    proto_tree_add_text(pimopt_tree, tvb, offset, 1,
		"Groups: %u", ngroup);
	    offset += 1;

	    if (PIM_TYPE(pim_typever) != 7)	{
		/* not graft-ack */
		holdtime = tvb_get_ntohs(tvb, offset);
		proto_tree_add_text(pimopt_tree, tvb, offset, 2,
		    "Holdtime: %u%s", holdtime,
		    holdtime == 0xffff ? " (infty)" : "");
	    }
	    offset += 2;

	    for (i = 0; i < ngroup; i++) {
		s = dissect_pim_addr(tvb, offset, pimv2_group, &advance);
		if (s == NULL)
		    goto breakbreak3;
		tigroup = proto_tree_add_text(pimopt_tree, tvb, offset, advance,
		    "Group %d: %s", i, s);
		grouptree = proto_item_add_subtree(tigroup, ett_pim);
		offset += advance;

		njoin = tvb_get_ntohs(tvb, offset);
		nprune = tvb_get_ntohs(tvb, offset + 2);

		tisub = proto_tree_add_text(grouptree, tvb, offset, 2,
		    "Join: %d", njoin);
		subtree = proto_item_add_subtree(tisub, ett_pim);
		off = offset + 4;
		for (j = 0; j < nprune; j++) {
		    s = dissect_pim_addr(tvb, off, pimv2_source,
			&advance);
		    if (s == NULL)
			goto breakbreak3;
		    proto_tree_add_text(subtree, tvb, off, advance,
			"IP address: %s", s);
		    off += advance;
		}

		tisub = proto_tree_add_text(grouptree, tvb, offset + 2, 2,
		    "Prune: %d", nprune);
		subtree = proto_item_add_subtree(tisub, ett_pim);
		for (j = 0; j < nprune; j++) {
		    s = dissect_pim_addr(tvb, off, pimv2_source,
			&advance);
		    if (s == NULL)
			goto breakbreak3;
		    proto_tree_add_text(subtree, tvb, off, advance,
			"IP address: %s", s);
		    off += advance;
		}
	    }
    breakbreak3:
	    break;
	  }

	case 4:	/* bootstrap */
	  {
	    const char *s;
	    int advance;
	    int i, j;
	    int frpcnt;
	    guint16 holdtime;
	    proto_tree *grouptree = NULL;
	    proto_item *tigroup; 

	    proto_tree_add_text(pimopt_tree, tvb, offset, 2,
		"Fragment tag: 0x%04x", tvb_get_ntohs(tvb, offset));
	    offset += 2;

	    proto_tree_add_text(pimopt_tree, tvb, offset, 1,
		"Hash mask len: %u", tvb_get_guint8(tvb, offset));
	    offset += 1;
	    proto_tree_add_text(pimopt_tree, tvb, offset, 1,
		"BSR priority: %u", tvb_get_guint8(tvb, offset));
	    offset += 1;

	    s = dissect_pim_addr(tvb, offset, pimv2_unicast, &advance);
	    if (s == NULL)
		break;
	    proto_tree_add_text(pimopt_tree, tvb, offset, advance, "BSR: %s", s);
	    offset += advance;

	    for (i = 0; tvb_reported_length_remaining(tvb, offset) > 0; i++) {
		s = dissect_pim_addr(tvb, offset, pimv2_group, &advance);
		if (s == NULL)
		    goto breakbreak4;
		tigroup = proto_tree_add_text(pimopt_tree, tvb, offset, advance,
		    "Group %d: %s", i, s);
		grouptree = proto_item_add_subtree(tigroup, ett_pim);
		offset += advance;

		proto_tree_add_text(grouptree, tvb, offset, 1,
		    "RP count: %u", tvb_get_guint8(tvb, offset));
		offset += 1;
		frpcnt = tvb_get_guint8(tvb, offset);
		proto_tree_add_text(grouptree, tvb, offset, 1,
		    "FRP count: %u", frpcnt);
		offset += 3;

		for (j = 0; j < frpcnt; j++) {
		    s = dissect_pim_addr(tvb, offset, pimv2_unicast, &advance);
		    if (s == NULL)
			goto breakbreak4;
		    proto_tree_add_text(grouptree, tvb, offset, advance,
			"RP %d: %s", j, s);
		    offset += advance;

		    holdtime = tvb_get_ntohs(tvb, offset);
		    proto_tree_add_text(grouptree, tvb, offset, 2,
			"Holdtime: %u%s", holdtime,
			holdtime == 0xffff ? " (infty)" : "");
		    offset += 2;
		    proto_tree_add_text(grouptree, tvb, offset, 1,
			"Priority: %u", tvb_get_guint8(tvb, offset));
		    offset += 2;	/* also skips reserved field */
		}
	    }

    breakbreak4:
	    break;
	  }

	case 5:	/* assert */
	  {
	    const char *s;
	    int advance;

	    s = dissect_pim_addr(tvb, offset, pimv2_group, &advance);
	    if (s == NULL)
		break;
	    proto_tree_add_text(pimopt_tree, tvb, offset, advance, "Group: %s", s);
	    offset += advance;

	    s = dissect_pim_addr(tvb, offset, pimv2_unicast, &advance);
	    if (s == NULL)
		break;
	    proto_tree_add_text(pimopt_tree, tvb, offset, advance, "Source: %s", s);
	    offset += advance;

	    proto_tree_add_text(pimopt_tree, tvb, offset, 1, "%s",
		decode_boolean_bitfield(tvb_get_guint8(tvb, offset), 0x80, 8,
		    "RP Tree", "Not RP Tree"));
	    proto_tree_add_text(pimopt_tree, tvb, offset, 4, "Preference: %u",
		tvb_get_ntohl(tvb, offset) & 0x7fffffff);
	    offset += 4;

	    proto_tree_add_text(pimopt_tree, tvb, offset, 4, "Metric: %u",
		tvb_get_ntohl(tvb, offset));

	    break;
	  }

	case 8:	/* Candidate-RP-Advertisement */
	  {
	    const char *s;
	    int advance;
	    int pfxcnt;
	    guint16 holdtime;
	    int i;

	    pfxcnt = tvb_get_guint8(tvb, offset);
	    proto_tree_add_text(pimopt_tree, tvb, offset, 1,
		"Prefix-count: %u", pfxcnt);
	    offset += 1;
	    proto_tree_add_text(pimopt_tree, tvb, offset, 1,
		"Priority: %u", tvb_get_guint8(tvb, offset));
	    offset += 1;
	    holdtime = tvb_get_ntohs(tvb, offset);
	    proto_tree_add_text(pimopt_tree, tvb, offset, 2,
		"Holdtime: %u%s", holdtime,
		holdtime == 0xffff ? " (infty)" : "");
	    offset += 2;

	    s = dissect_pim_addr(tvb, offset, pimv2_unicast, &advance);
	    if (s == NULL)
		break;
	    proto_tree_add_text(pimopt_tree, tvb, offset, advance, "RP: %s", s);
	    offset += advance;

	    for (i = 0; i < pfxcnt; i++) {
		s = dissect_pim_addr(tvb, offset, pimv2_group, &advance);
		if (s == NULL)
		    goto breakbreak8;
		proto_tree_add_text(pimopt_tree, tvb, offset, advance,
		    "Group %d: %s", i, s);
		offset += advance;
	    }
    breakbreak8:
	    break;
	  }

	default:
	    break;
	}
    }
done:;
}

void
proto_register_pim(void)
{
    static hf_register_info hf[] = {
      { &hf_pim_version,
	{ "Version",		"pim.version",
				FT_UINT8, BASE_DEC, NULL, 0x0, "" }},
      { &hf_pim_type,
	{ "Type",			"pim.type",
				FT_UINT8, BASE_DEC, NULL, 0x0, "" }},
      { &hf_pim_cksum,
	{ "Checksum",		"pim.cksum",
				FT_UINT16, BASE_HEX, NULL, 0x0, "" }},
    };
    static gint *ett[] = {
        &ett_pim,
    };

    proto_pim = proto_register_protocol("Protocol Independent Multicast",
	"PIM", "pim");
    proto_register_field_array(proto_pim, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_pim(void)
{
    dissector_add("ip.proto", IP_PROTO_PIM, dissect_pim, proto_pim);

    /*
     * Get a handle for the IP dissector.
     */
    ip_handle = find_dissector("ip");
}
