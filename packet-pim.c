/* packet-pim.c
 * Routines for PIM disassembly
 * (c) Copyright Jun-ichiro itojun Hagino <itojun@itojun.org>
 *
 * $Id: packet-pim.c,v 1.1 1999/10/13 06:47:45 guy Exp $
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
 
#include "config.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <glib.h>
#include "packet.h"
#include "packet-ipv6.h"

#ifndef offsetof
#define	offsetof(type, member)	((size_t)(&((type *)0)->member))
#endif

struct pim {
	guint8	pim_typever;
#define PIM_TYPE(x)	((x) & 0x0f)
#define PIM_VER(x)	(((x) & 0xf0) >> 4)
	guint8  pim_rsv;	/* Reserved */
	guint16	pim_cksum;	/* IP style check sum */
};

enum pimv2_addrtype {
	pimv2_unicast, pimv2_group, pimv2_source
};

static int proto_pim = -1;

static const char *
dissect_pim_addr(const u_char *bp, const u_char *ep, enum pimv2_addrtype at,
	int *advance) {
    static char buf[512];
    int af;
    int len = 0;

    if (bp >= ep)
	return NULL;

    switch (bp[0]) {
    case 1:
	af = 4;
	break;
    case 2:
	af = 6;
	break;
    default:
	return NULL;
    }

    if (bp[1] != 0)
	return NULL;

    switch (at) {
    case pimv2_unicast:
	if (af == 4) {
	    len = 4;
	    if (bp + 2 + len > ep)
		return NULL;
	    (void)snprintf(buf, sizeof(buf), "%s", ip_to_str(bp + 2));
	}
	else if (af == 6) {
	    len = 16;
	    if (bp + 2 + len > ep)
		return NULL;
	    (void)snprintf(buf, sizeof(buf), "%s",
		ip6_to_str((struct e_in6_addr *)(bp + 2)));
	}
	if (advance)
	    *advance = 2 + len;
	break;

    case pimv2_group:
	if (af == 4) {
	    len = 4;
	    if (bp + 4 + len > ep)
		return NULL;
	    (void)snprintf(buf, sizeof(buf), "%s/%u", ip_to_str(bp + 4), bp[3]);
	}
	else if (af == 6) {
	    len = 16;
	    if (bp + 4 + len > ep)
		return NULL;
	    (void)snprintf(buf, sizeof(buf), "%s/%u",
		ip6_to_str((struct e_in6_addr *)(bp + 4)), bp[3]);
	}
	if (advance)
	    *advance = 4 + len;
	break;
    case pimv2_source:
	if (af == 4) {
	    len = 4;
	    if (bp + 4 + len > ep)
		return NULL;
	    (void)snprintf(buf, sizeof(buf), "%s/%u", ip_to_str(bp + 4), bp[3]);
	}
	else if (af == 6) {
	    len = 16;
	    if (bp + 4 + len > ep)
		return NULL;
	    (void)snprintf(buf, sizeof(buf), "%s/%u",
		ip6_to_str((struct e_in6_addr *)(bp + 4)), bp[3]);
	}
	if (bp[2]) {
	    (void)snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf),
		" (%s%s%s)",
		bp[2] & 0x04 ? "S" : "",
		bp[2] & 0x02 ? "W" : "",
		bp[2] & 0x01 ? "R" : "");
	}
	if (advance)
	    *advance = 4 + len;
	break;
    default:
	return NULL;
    }

    return buf;
}

void 
dissect_pim(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
    struct pim pim;
    char *packet_type1[] = {
	"Query", "Register", "Register-Stop", "Join/Prune", "RP-Reachable",
	"Assert", "Graft", "Graft-Ack", "Mode"
    };
    char *packet_type2[] = {
	"Hello", "Register", "Register-Stop", "Join/Prune", "Bootstrap",
	"Assert", "Graft", "Graft-Ack", "Candidate-RP-Advertisement"
    };
    char *typestr;
    proto_tree *pim_tree = NULL;
	proto_item *ti; 
    proto_tree *pimopt_tree = NULL;
	proto_item *tiopt; 

    /* avoid alignment problem */
    memcpy(&pim, &pd[offset], sizeof(pim));

    typestr = NULL;
    switch (PIM_VER(pim.pim_typever)) {
    case 1:
	if (PIM_TYPE(pim.pim_typever) < sizeof(packet_type1) / sizeof(packet_type1[0])) {
	    typestr = packet_type1[PIM_TYPE(pim.pim_typever)];
	}
	break;
    case 2:
	if (PIM_TYPE(pim.pim_typever) < sizeof(packet_type2) / sizeof(packet_type2[0])) {
	    typestr = packet_type2[PIM_TYPE(pim.pim_typever)];
	}
	break;
    }

    if (check_col(fd, COL_PROTOCOL)) {
        col_add_fstr(fd, COL_PROTOCOL, "PIM version %d",
	    PIM_VER(pim.pim_typever));
    }
    if (check_col(fd, COL_INFO)) {
	if (typestr)
	    col_add_str(fd, COL_INFO, typestr); 
	else {
	    col_add_fstr(fd, COL_INFO, "unknown type %d",
		PIM_TYPE(pim.pim_typever)); 
	}
    }

    if (tree) {
	ti = proto_tree_add_item(tree, proto_pim, offset, END_OF_FRAME, NULL);
	pim_tree = proto_item_add_subtree(ti, ETT_PIM);

	proto_tree_add_text(pim_tree, offset, 1,
	    "Version: %d", PIM_VER(pim.pim_typever)); 
	if (typestr) {
	    proto_tree_add_text(pim_tree, offset, 1,
		"Type: %d (%s)", PIM_TYPE(pim.pim_typever), typestr); 
	} else {
	    proto_tree_add_text(pim_tree, offset, 1,
		"Type: %d (unknown)", PIM_TYPE(pim.pim_typever)); 
	}

	proto_tree_add_text(pim_tree, offset + offsetof(struct pim, pim_cksum),
	    sizeof(pim.pim_cksum),
	    "Checksum: 0x%04x", ntohs(pim.pim_cksum));

	if (sizeof(struct pim) < END_OF_FRAME) {
	    tiopt = proto_tree_add_text(pim_tree,
		offset + sizeof(struct pim), END_OF_FRAME,
		"PIM parameters", PIM_TYPE(pim.pim_typever), typestr);
	    pimopt_tree = proto_item_add_subtree(tiopt, ETT_PIM);
	} else
	    goto done;

	if (PIM_VER(pim.pim_typever) != 2)
	    goto done;

	/* version 2 decoder */
	switch (PIM_TYPE(pim.pim_typever)) {
	case 0:	/*hello*/
	  {
	    guint16 *w;
	    w = (guint16 *)&pd[offset + sizeof(struct pim)];
	    while ((guint8 *)w < &pd[offset + END_OF_FRAME]) {
		if (ntohs(w[0]) == 1 && ntohs(w[1]) == 2
		 && (guint8 *)&w[3] <= &pd[offset + END_OF_FRAME]) {
		    proto_tree_add_text(pimopt_tree, (guint8 *)w - pd, 6,
			"Holdtime: %u%s", ntohs(w[2]),
			ntohs(w[2]) == 0xffff ? " (infty)" : "");
		    w += 3;
		} else
		    break;
	    }
	    break;
	  }

	case 1:	/* register */
	  {
	    const guint8 *ip;
	    proto_tree *flag_tree = NULL;
		proto_item *tiflag; 
	    int flagoff;

	    flagoff = offset + sizeof(struct pim);
	    tiflag = proto_tree_add_text(pimopt_tree, flagoff, 4,
		"Flags: 0x%08x", ntohl(*(guint32 *)&pd[flagoff]));
	    flag_tree = proto_item_add_subtree(tiflag, ETT_PIM);
	    proto_tree_add_text(flag_tree, flagoff, 1, "%s",
		decode_boolean_bitfield(pd[flagoff], 0x80000000, 32,
		    "Border", "Not border"));
	    proto_tree_add_text(flag_tree, flagoff, 1, "%s",
		decode_boolean_bitfield(pd[flagoff], 0x40000000, 32,
		    "Null-Register", "Not Null-Register"));

	    ip = &pd[flagoff + sizeof(guint32)];
	    switch((*ip & 0xf0) >> 4) {
	    case 4:	/* IPv4 */
		    dissect_ip(pd, ip - pd, fd, pimopt_tree);
		    break;
	    case 6:	/* IPv6 */
		    dissect_ipv6(pd, ip - pd, fd, pimopt_tree);
		    break;
	    default:
		    proto_tree_add_text(pimopt_tree,
			ip - pd, END_OF_FRAME,
			"Unknown IP version %d", (*ip & 0xf0) >> 4);
		    break;
	    }
	    break;
	  }

	case 2:	/* register-stop */
	  {
	    int advance;
	    const guint8 *ep;
	    const char *s;

	    ep = &pd[offset + END_OF_FRAME];
	    offset += sizeof(struct pim);
	    s = dissect_pim_addr(&pd[offset], ep, pimv2_group, &advance);
	    if (s == NULL)
		break;
	    proto_tree_add_text(pimopt_tree, offset, advance, "Group: %s", s);
	    offset += advance;
	    s = dissect_pim_addr(&pd[offset], ep, pimv2_unicast, &advance);
	    if (s == NULL)
		break;
	    proto_tree_add_text(pimopt_tree, offset, advance, "Source: %s", s);
	    break;
	  }

	case 3:	/* join/prune */
	case 6:	/* graft */
	case 7:	/* graft-ack */
	  {
	    int advance;
	    const guint8 *ep;
	    int off;
	    const char *s;
	    int ngroup, i, njoin, nprune, j;
	    proto_tree *grouptree = NULL;
		proto_item *tigroup; 
	    proto_tree *subtree = NULL;
		proto_item *tisub; 

	    ep = &pd[offset + END_OF_FRAME];
	    offset += sizeof(struct pim);
	    if (PIM_TYPE(pim.pim_typever) != 7)	{
		/* not graft-ack */
		s = dissect_pim_addr(&pd[offset], ep, pimv2_unicast, &advance);
		if (s == NULL)
		    break;
		proto_tree_add_text(pimopt_tree, offset, advance,
		    "Upstream-neighbor: %s", s);
		offset += advance;
	    }

	    if (&pd[offset + 2] > ep)
		break;
	    ngroup = pd[offset + 1];
	    proto_tree_add_text(pimopt_tree, offset + 1, 1,
		"Groups: %u", pd[offset + 1]);
	    offset += 2;

	    if (&pd[offset + 2] > ep)
		break;
	    if (PIM_TYPE(pim.pim_typever) != 7)	{
		/* not graft-ack */
		proto_tree_add_text(pimopt_tree, offset, 2,
		    "Holdtime: %u%s", ntohs(*(guint16 *)&pd[offset]),
		    ntohs(*(guint16 *)&pd[offset]) == 0xffff ? " (infty)" : "");
	    }
	    offset += 2;

	    for (i = 0; i < ngroup; i++) {
		if (&pd[offset] >= ep)
		    goto breakbreak3;

		s = dissect_pim_addr(&pd[offset], ep, pimv2_group, &advance);
		if (s == NULL)
		    goto breakbreak3;
		tigroup = proto_tree_add_text(pimopt_tree, offset, advance,
		    "Group %d: %s", i, s);
		grouptree = proto_item_add_subtree(tigroup, ETT_PIM);
		offset += advance;

		if (&pd[offset + 4] > ep)
		    goto breakbreak3;
		njoin = ntohs(*(guint16 *)&pd[offset]);
		nprune = ntohs(*(guint16 *)&pd[offset + 2]);

		tisub = proto_tree_add_text(grouptree, offset, 2,
		    "Join: %d", njoin);
		subtree = proto_item_add_subtree(tisub, ETT_PIM);
		off = offset + 4;
		for (j = 0; j < nprune; j++) {
		    s = dissect_pim_addr(&pd[off], ep, pimv2_source,
			&advance);
		    if (s == NULL)
			goto breakbreak3;
		    proto_tree_add_text(subtree, off, advance,
			"IP address: %s", s);
		    off += advance;
		}

		tisub = proto_tree_add_text(grouptree, offset + 2, 2,
		    "Prune: %d", nprune);
		subtree = proto_item_add_subtree(tisub, ETT_PIM);
		for (j = 0; j < nprune; j++) {
		    s = dissect_pim_addr(&pd[off], ep, pimv2_source,
			&advance);
		    if (s == NULL)
			goto breakbreak3;
		    proto_tree_add_text(subtree, off, advance,
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
	    proto_tree *grouptree = NULL;
		proto_item *tigroup; 

	    offset += sizeof(struct pim);

	    if (END_OF_FRAME < 2)
		break;
	    proto_tree_add_text(pimopt_tree, offset, 2,
		"Fragment tag: 0x%04x", ntohs(*(guint16 *)&pd[offset]));
	    offset += 2;

	    if (END_OF_FRAME < 2)
		break;
	    proto_tree_add_text(pimopt_tree, offset, 1,
		"Hash mask len: %u", pd[offset]);
	    proto_tree_add_text(pimopt_tree, offset + 1, 1,
		"BSR priority: %u", pd[offset + 1]);
	    offset += 2;

	    s = dissect_pim_addr(&pd[offset], &pd[offset + END_OF_FRAME],
		pimv2_unicast, &advance);
	    if (s == NULL)
		break;
	    proto_tree_add_text(pimopt_tree, offset, advance, "BSR: %s", s);
	    offset += advance;

	    for (i = 0; END_OF_FRAME > 0; i++) {
		s = dissect_pim_addr(&pd[offset], &pd[offset + END_OF_FRAME],
		    pimv2_group, &advance);
		if (s == NULL)
		    goto breakbreak4;
		tigroup = proto_tree_add_text(pimopt_tree, offset, advance,
		    "Group %d: %s", i, s);
		grouptree = proto_item_add_subtree(tigroup, ETT_PIM);
		offset += advance;

		if (END_OF_FRAME < 2)
		    goto breakbreak4;
		proto_tree_add_text(grouptree, offset, 1,
		    "RP count: %u", pd[offset]);
		proto_tree_add_text(grouptree, offset + 1, 1,
		    "FRP count: %u", pd[offset + 1]);
		frpcnt = pd[offset + 1];
		offset += 4;

		for (j = 0; j < frpcnt && END_OF_FRAME > 0; j++) {
		    s = dissect_pim_addr(&pd[offset],
			&pd[offset + END_OF_FRAME], pimv2_unicast, &advance);
		    if (s == NULL)
			goto breakbreak4;
		    proto_tree_add_text(grouptree, offset, advance,
			"RP %d: %s", j, s);
		    offset += advance;

		    if (END_OF_FRAME < 4)
			goto breakbreak4;
		    proto_tree_add_text(grouptree, offset, 2,
			"Holdtime: %u%s", ntohs(*(guint16 *)&pd[offset]),
			ntohs(*(guint16 *)&pd[offset]) == 0xffff ? " (infty)" : "");
		    proto_tree_add_text(grouptree, offset + 3, 1,
			"Priority: %u", pd[offset + 3]);

		    offset += 4;
		}
	    }

    breakbreak4:
	    break;
	  }

	case 5:	/* assert */
	  {
	    const char *s;
	    int advance;

	    offset += sizeof(struct pim);

	    s = dissect_pim_addr(&pd[offset], &pd[offset + END_OF_FRAME],
		pimv2_group, &advance);
	    if (s == NULL)
		break;
	    proto_tree_add_text(pimopt_tree, offset, advance, "Group: %s", s);
	    offset += advance;

	    s = dissect_pim_addr(&pd[offset], &pd[offset + END_OF_FRAME],
		pimv2_unicast, &advance);
	    if (s == NULL)
		break;
	    proto_tree_add_text(pimopt_tree, offset, advance, "Source: %s", s);
	    offset += advance;

	    if (END_OF_FRAME < 4)
		break;
	    proto_tree_add_text(pimopt_tree, offset, 1, "%s",
		decode_boolean_bitfield(pd[offset], 0x80, 8,
		    "RP Tree", "Not RP Tree"));
	    proto_tree_add_text(pimopt_tree, offset, 4, "Preference: %u",
		ntohl(*(guint32 *)&pd[offset] & 0x7fffffff));
	    offset += 4;

	    if (END_OF_FRAME < 4)
		break;
	    proto_tree_add_text(pimopt_tree, offset, 4, "Metric: %u",
		ntohl(*(guint32 *)&pd[offset]));

	    break;
	  }

	case 8:	/* Candidate-RP-Advertisement */
	  {
	    const char *s;
	    int advance;
	    int pfxcnt;
	    int i;

	    offset += sizeof(struct pim);
	    if (END_OF_FRAME < 4)
		break;
	    pfxcnt = pd[offset];
	    proto_tree_add_text(pimopt_tree, offset, 1,
		"Prefix-count: %u", pd[offset]);
	    proto_tree_add_text(pimopt_tree, offset + 1, 1,
		"Priority: %u", pd[offset + 1]);
	    proto_tree_add_text(pimopt_tree, offset + 2, 2,
		"Holdtime: %u%s", ntohs(*(guint16 *)&pd[offset + 2]),
		ntohs(*(guint16 *)&pd[offset + 2]) == 0xffff ? " (infty)" : "");
	    offset += 4;

	    if (END_OF_FRAME <= 0)
		break;
	    s = dissect_pim_addr(&pd[offset], &pd[offset + END_OF_FRAME],
		pimv2_unicast, &advance);
	    if (s == NULL)
		break;
	    proto_tree_add_text(pimopt_tree, offset, advance, "RP: %s", s);
	    offset += advance;

	    for (i = 0; i < pfxcnt && END_OF_FRAME > 0; i++) {
		s = dissect_pim_addr(&pd[offset], &pd[offset + END_OF_FRAME],
		    pimv2_group, &advance);
		if (s == NULL)
		    goto breakbreak8;
		proto_tree_add_text(pimopt_tree, offset, advance,
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
    proto_pim = proto_register_protocol("Protocol Independent Multicast",
	"pim");
}
