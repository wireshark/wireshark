/* packet-bgp.c
 * Routines for BGP packet dissection
 * Copyright 1999, Jun-ichiro itojun Hagino <itojun@itojun.org>
 *
 * $Id: packet-bgp.c,v 1.1 1999/10/15 17:00:46 itojun Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
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

#include <string.h>
#include <glib.h>
#include "packet.h"

struct bgp {
    guint8 bgp_marker[16];
    guint16 bgp_len;
    guint8 bgp_type;
};
#define BGP_SIZE		19

#define BGP_OPEN		1
#define BGP_UPDATE		2
#define BGP_NOTIFICATION	3
#define BGP_KEEPALIVE		4

struct bgp_open {
    guint8 bgpo_marker[16];
    guint16 bgpo_len;
    guint8 bgpo_type;
    guint8 bgpo_version;
    guint16 bgpo_myas;
    guint16 bgpo_holdtime;
    guint32 bgpo_id;
    guint8 bgpo_optlen;
    /* options should follow */
};

struct bgp_notification {
    guint8 bgpn_marker[16];
    guint16 bgpn_len;
    guint8 bgpn_type;
    guint8 bgpn_major;
    guint8 bgpn_minor;
    /* data should follow */
};

struct bgp_attr {
    guint8 bgpa_flags;
    guint8 bgpa_type;
};

static const value_string bgptypevals[] = {
    { BGP_OPEN, "OPEN" },
    { BGP_UPDATE, "UPDATE" },
    { BGP_NOTIFICATION, "NOTIFICATION" },
    { BGP_KEEPALIVE, "KEEPALIVE" },
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

static const value_string bgpattr_flags[] = {
    { 0x80, "Optional" },
    { 0x40, "Transitive" },
    { 0x20, "Partial" },
    { 0x10, "Extended length" },
    { 0, NULL },
};

static const value_string bgpattr_origin[] = {
    { 0, "IGP" },
    { 1, "EGP" },
    { 2, "INCOMPLETE" },
    { 0, NULL },
};

#define BGPTYPE_ORIGIN		1
#define BGPTYPE_AS_PATH		2
#define BGPTYPE_NEXT_HOP	3
#define BGPTYPE_MULTI_EXIT_DISC	4
#define BGPTYPE_LOCAL_PREF	5
#define BGPTYPE_ATOMIC_AGGREGATE	6
#define BGPTYPE_AGGREGATOR	7

static const value_string bgpattr_type[] = {
    { BGPTYPE_ORIGIN, "ORIGIN" },
    { BGPTYPE_AS_PATH, "AS_PATH" },
    { BGPTYPE_NEXT_HOP, "NEXT_HOP" },
    { BGPTYPE_MULTI_EXIT_DISC, "MULTI_EXIT_DISC" },
    { BGPTYPE_LOCAL_PREF, "LOCAL_PREF" },
    { BGPTYPE_ATOMIC_AGGREGATE, "ATOMIC_AGGREGATE" },
    { BGPTYPE_AGGREGATOR, "AGGREGATOR" },
    { 0, NULL },
};


static int proto_bgp = -1;

#ifndef offsetof
#define	offsetof(type, member)	((size_t)(&((type *)0)->member))
#endif

static void
dissect_bgp_open(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
    struct bgp_open bgpo;
    int hlen;

    memcpy(&bgpo, &pd[offset], sizeof(bgpo));
    hlen = ntohs(bgpo.bgpo_len);

    proto_tree_add_text(tree,
	offset + offsetof(struct bgp_open, bgpo_version), 1,
	"Version: %u", bgpo.bgpo_version);
    proto_tree_add_text(tree,
	offset + offsetof(struct bgp_open, bgpo_myas), 2,
	"My AS: %u", ntohs(bgpo.bgpo_myas));
    proto_tree_add_text(tree,
	offset + offsetof(struct bgp_open, bgpo_holdtime), 2,
	"Holdtime: %u", ntohs(bgpo.bgpo_holdtime));
    proto_tree_add_text(tree,
	offset + offsetof(struct bgp_open, bgpo_id), 4,
	"ID: %s", ip_to_str((guint8 *)&bgpo.bgpo_id));
    proto_tree_add_text(tree,
	offset + offsetof(struct bgp_open, bgpo_optlen), 1,
	"Option length: %u", bgpo.bgpo_optlen);
    if (hlen > sizeof(struct bgp_open)) {
	proto_tree_add_text(tree,
	    offset + sizeof(struct bgp_open), hlen - sizeof(struct bgp_open),
	    "Option data%s");
    }
}

static void
dissect_bgp_update(const u_char *pd, int offset, frame_data *fd,
    proto_tree *tree)
{
    struct bgp bgp;
    struct bgp_attr bgpa;
    int hlen;
    const u_char *p;
    int len;
    proto_item *ti;
    proto_tree *subtree, *subtree2, *subtree3;
    int i;

    memcpy(&bgp, &pd[offset], sizeof(bgp));
    hlen = ntohs(bgp.bgp_len);

    p = &pd[offset + BGP_SIZE];	/*XXX*/
    proto_tree_add_text(tree, p - pd, 2, 
	"Unfeasible routes length: %d", len = ntohs(*(guint16 *)p));
    ti = proto_tree_add_text(tree, p - pd, len,
	    "Withdrawn routes (%u bytes)", len);
    if (len) {
	subtree = proto_item_add_subtree(ti, ETT_BGP);
    }
    p += 2 + len;
    proto_tree_add_text(tree, p - pd, 2, 
	"Total path attribute length: %d", len = ntohs(*(guint16 *)p));
    ti = proto_tree_add_text(tree, p - pd + 2, len,
	    "Path attributes (%u bytes)", len);
    if (len) {
	subtree = proto_item_add_subtree(ti, ETT_BGP);
	i = 2;
	while (i < len) {
	    int alen, aoff;
	    char *msg;

	    memcpy(&bgpa, &p[i], sizeof(bgpa));
	    if (bgpa.bgpa_flags & 0x10) {
		alen = ntohs(*(guint16 *)&p[i + sizeof(bgpa)]);
		aoff = sizeof(bgpa) + 2;
	    } else {
		alen = p[i + sizeof(bgpa)];
		aoff = sizeof(bgpa) + 1;
	    }

	    ti = proto_tree_add_text(subtree, p - pd + i, alen + aoff,
		    "Attribute: %s (%u bytes)",
		    val_to_str(bgpa.bgpa_type, bgpattr_type, "Unknown"),
		    alen + aoff);
	    subtree2 = proto_item_add_subtree(ti, ETT_BGP);

	    ti = proto_tree_add_text(subtree2,
		    p - pd + i + offsetof(struct bgp_attr, bgpa_flags), 1,
		    "Flags: 0x%02x", bgpa.bgpa_flags);
	    subtree3 = proto_item_add_subtree(ti, ETT_BGP);
	    proto_tree_add_text(subtree3,
		    p - pd + i + offsetof(struct bgp_attr, bgpa_flags), 1,
		    "%s", decode_boolean_bitfield(bgpa.bgpa_flags,
			0x80, 8, "Optional", "not Optional"));
	    proto_tree_add_text(subtree3,
		    p - pd + i + offsetof(struct bgp_attr, bgpa_flags), 1,
		    "%s", decode_boolean_bitfield(bgpa.bgpa_flags,
			0x40, 8, "Transitive", "not Transitive"));
	    proto_tree_add_text(subtree3,
		    p - pd + i + offsetof(struct bgp_attr, bgpa_flags), 1,
		    "%s", decode_boolean_bitfield(bgpa.bgpa_flags,
			0x20, 8, "Partial", "not Partial"));
	    proto_tree_add_text(subtree3,
		    p - pd + i + offsetof(struct bgp_attr, bgpa_flags), 1,
		    "%s", decode_boolean_bitfield(bgpa.bgpa_flags,
			0x10, 8, "Extended length", "not Extended length"));

	    proto_tree_add_text(subtree2,
		    p - pd + i + offsetof(struct bgp_attr, bgpa_type), 1,
		    "Type code: %s (0x%02x)",
		    val_to_str(bgpa.bgpa_type, bgpattr_type, "Unknown"),
		    bgpa.bgpa_type);

	    switch (bgpa.bgpa_type) {
	    case BGPTYPE_ORIGIN:
		if (alen != 1) {
		    proto_tree_add_text(subtree2, p - pd + i + aoff, alen,
			    "Origin: Invalid (%d bytes)", alen);
		} else {
		    msg = val_to_str(p[i + aoff], bgpattr_origin, "Unknown");
		    proto_tree_add_text(subtree2, p - pd + i + aoff, 1,
			    "Origin: %s (0x%02x)", msg, p[i + aoff]);
		}
		break;
	    case BGPTYPE_AS_PATH:
		if (alen % 2) {
		    proto_tree_add_text(subtree2, p - pd + i + aoff, alen,
			    "AS path: Invalid (%d bytes)", alen);
		} else {
		    int j, n;
		    char *q;
		    msg = malloc(alen / 2 * 6 + 10);
		    if (!msg) {
			proto_tree_add_text(subtree2, p - pd + i + aoff, alen,
				"AS path (%d bytes)", alen);
		    } else {
			q = msg;
			for (j = 0; j < alen; j += 2) {
			    n = sprintf(q, "%d ",
				    ntohs(*(guint16 *)&p[i + aoff + j]));
			    q += n;
			}
			proto_tree_add_text(subtree2, p - pd + i + aoff, alen,
				"AS path: %s(%d ASes, %d bytes)",
				msg, alen / 2, alen);
			free(msg);
		    }
		    break;
		}
	    case BGPTYPE_NEXT_HOP:
		if (alen != 4) {
		    proto_tree_add_text(subtree2, p - pd + i + aoff, alen,
			    "Next hop: Invalid (%d bytes)", alen);
		} else {
		    proto_tree_add_text(subtree2, p - pd + i + aoff, alen,
			    "Next hop: %s", ip_to_str(&p[i + aoff]));
		}
		break;
	    case BGPTYPE_MULTI_EXIT_DISC:
		if (alen != 4) {
		    proto_tree_add_text(subtree2, p - pd + i + aoff, alen,
			    "Multi exit discriminator: Invalid (%d bytes)",
			    alen);
		} else {
		    proto_tree_add_text(subtree2, p - pd + i + aoff, alen,
			    "Multi exit discriminator: %u",
			    ntohl(*(guint32 *)&p[i + aoff]));
		}
		break;
	    case BGPTYPE_LOCAL_PREF:
		if (alen != 4) {
		    proto_tree_add_text(subtree2, p - pd + i + aoff, alen,
			    "Local preference: Invalid (%d bytes)", alen);
		} else {
		    proto_tree_add_text(subtree2, p - pd + i + aoff, alen,
			    "Local preference: %u",
			    ntohl(*(guint32 *)&p[i + aoff]));
		}
		break;
	    case BGPTYPE_ATOMIC_AGGREGATE:
		if (alen != 0) {
		    proto_tree_add_text(subtree2, p - pd + i + aoff, alen,
			    "Atomic aggregate: Invalid (%d bytes)", alen);
		} else {
		    proto_tree_add_text(subtree2, p - pd + i + aoff, 0,
			    "Atomic aggregate");
		}
		break;
	    case BGPTYPE_AGGREGATOR:
		if (alen != 6) {
		    proto_tree_add_text(subtree2, p - pd + i + aoff, alen,
			    "Aggregator: Invalid (%d bytes)", alen);
		} else {
		    proto_tree_add_text(subtree2, p - pd + i + aoff, 2,
			    "Aggregator AS: %u",
			    ntohs(*(guint16 *)&p[i + aoff]));
		    proto_tree_add_text(subtree2, p - pd + i + aoff + 2, 4,
			    "Aggregator origin: %s",
			    ip_to_str(&p[i + aoff + 2]));
		}
		break;
	    }

	    i += alen + aoff;
	}
    }
    p += 2 + len;
    len = hlen - (p - &pd[offset]);
    ti = proto_tree_add_text(tree, p - pd, len,
	    "Network layer reachability information (%d bytes)", len);
    if (len) {
	subtree = proto_item_add_subtree(ti, ETT_BGP);
    }
}

static void
dissect_bgp_notification(const u_char *pd, int offset, frame_data *fd,
    proto_tree *tree)
{
    struct bgp_notification bgpn;
    int hlen;
    char *p;

    memcpy(&bgpn, &pd[offset], sizeof(bgpn));
    hlen = ntohs(bgpn.bgpn_len);

    proto_tree_add_text(tree,
	offset + offsetof(struct bgp_notification, bgpn_major), 1,
	"Error code: %s (%u)",
	val_to_str(bgpn.bgpn_major, bgpnotify_major, "Unknown"),
	bgpn.bgpn_major);

    if (bgpn.bgpn_major < array_length(bgpnotify_minor)
     && bgpnotify_minor[bgpn.bgpn_major] != NULL) {
	p = val_to_str(bgpn.bgpn_minor, bgpnotify_minor[bgpn.bgpn_major],
	    "Unknown");
    } else
	p = "Unknown";
    proto_tree_add_text(tree,
	offset + offsetof(struct bgp_notification, bgpn_minor), 1,
	"Error subcode: %s (%u)", p, bgpn.bgpn_minor);
    proto_tree_add_text(tree, offset + sizeof(struct bgp_notification),
	hlen - sizeof(struct bgp_notification), "Data");
}

void
dissect_bgp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *bgp_tree;
    proto_tree *bgp1_tree;
    const u_char *p;
    int l, i;
    static u_char marker[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    struct bgp bgp;
    int hlen;
    char *typ;

    if (check_col(fd, COL_PROTOCOL))
	col_add_str(fd, COL_PROTOCOL, "BGP");

    if (check_col(fd, COL_INFO))
	col_add_fstr(fd, COL_INFO, "BGP Data ...");

    if (tree) {
	ti = proto_tree_add_text(tree, offset, END_OF_FRAME,
		    "Border Gateway Protocol");
	bgp_tree = proto_item_add_subtree(ti, ETT_BGP);

#define CHECK_SIZE(x, s, l) \
do {				\
    if ((x) + (s) > (l))	\
	return;			\
} while (0)

	p = &pd[offset];
	l = END_OF_FRAME;
	i = 0;
	while (i < l) {
	    /* look for bgp header */
	    if (p[i] != 0xff) {
		i++;
		continue;
	    }
	    CHECK_SIZE(i, sizeof(marker), l);
	    if (memcmp(&p[i], marker, sizeof(marker)) != 0) {
		i++;
		continue;
	    }

	    memcpy(&bgp, &p[i], sizeof(bgp));
	    hlen = ntohs(bgp.bgp_len);
	    typ = val_to_str(bgp.bgp_type, bgptypevals, "Unknown");
	    if (END_OF_FRAME < hlen) {
		ti = proto_tree_add_text(bgp_tree, offset + i, END_OF_FRAME,
			    "BGP header, truncated: %s (%u)",
			    typ, bgp.bgp_type);
	    } else {
		ti = proto_tree_add_text(bgp_tree, offset + i, hlen,
			    "BGP header: %s (%u)",
			    typ, bgp.bgp_type);
	    }
	    bgp1_tree = proto_item_add_subtree(ti, ETT_BGP);

	    if (hlen < 19 || hlen > 4096) {
		proto_tree_add_text(bgp1_tree,
		    offset + i + offsetof(struct bgp, bgp_len), 2,
		    "Length, out of range: %u", hlen);
	    } else {
		proto_tree_add_text(bgp1_tree,
		    offset + i + offsetof(struct bgp, bgp_len), 2,
		    "Length: %u", hlen);
	    }
	    proto_tree_add_text(bgp1_tree,
		offset + i + offsetof(struct bgp, bgp_type), 1,
		"Type: %s (%u)", typ, bgp.bgp_type);

	    CHECK_SIZE(i, hlen, l);

	    switch (bgp.bgp_type) {
	    case BGP_OPEN:
		dissect_bgp_open(pd, offset + i, fd, bgp1_tree);
		break;
	    case BGP_UPDATE:
		dissect_bgp_update(pd, offset + i, fd, bgp1_tree);
		break;
	    case BGP_NOTIFICATION:
		dissect_bgp_notification(pd, offset + i, fd, bgp1_tree);
		break;
	    }

	    i += hlen;
	}
    }
}

void
proto_register_bgp(void)
{
    proto_bgp = proto_register_protocol("Border Gateway Protocol", "bgp");
}
