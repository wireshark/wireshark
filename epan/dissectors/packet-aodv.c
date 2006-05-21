/* packet-aodv.c
 * Routines for AODV dissection
 * Copyright 2000, Erik Nordström <erik.nordstrom@it.uu.se>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_STDDEF_H
#include <stddef.h>
#endif
#include <string.h>

#include <glib.h>

#include <epan/packet.h>

#ifndef offsetof
#define	offsetof(type, member)	((size_t)(&((type *)0)->member))
#endif

/*
 * See
 *
 *	RFC 3561 (which indicates that, for IPv6, the only change is that
 *	the address fields are enlarged)
 *
 *	http://www.cs.ucsb.edu/~ebelding/txt/aodv6.txt
 *
 *	http://www.tcs.hut.fi/~anttit/manet/drafts/draft-perkins-aodv6-01.txt
 *
 *	(both of the above two are draft-perkins-manet-aodv6-01.txt, which
 *	is from November 2000)
 */

#define INET6_ADDRLEN	16
#define UDP_PORT_AODV	654

/* Message Types */
#define RREQ			1
#define RREP			2
#define RERR			3
#define RREP_ACK		4
#define DRAFT_01_V6_RREQ	16
#define DRAFT_01_V6_RREP	17
#define DRAFT_01_V6_RERR	18
#define DRAFT_01_V6_RREP_ACK	19

/* Extension Types */
#define AODV_EXT	1
#define AODV_EXT_INT	2
#define AODV_EXT_NTP	3

/* Flag bits: */
#define RREQ_UNKNSEQ	0x08
#define RREQ_DESTONLY	0x10
#define RREQ_GRATRREP	0x20
#define RREQ_REP	0x40
#define RREQ_JOIN	0x80

#define RREP_ACK_REQ	0x40
#define RREP_REP	0x80

#define RERR_NODEL	0x80

static const value_string type_vals[] = {
    { RREQ,                 "Route Request" },
    { RREP,                 "Route Reply" },
    { RERR,                 "Route Error" },
    { RREP_ACK,             "Route Reply Acknowledgment"},
    { DRAFT_01_V6_RREQ,     "draft-perkins-manet-aodv6-01 IPv6 Route Request"},
    { DRAFT_01_V6_RREP,     "draft-perkins-manet-aodv6-01 IPv6 Route Reply"},
    { DRAFT_01_V6_RERR,     "draft-perkins-manet-aodv6-01 IPv6 Route Error"},
    { DRAFT_01_V6_RREP_ACK, "draft-perkins-manet-aodv6-01 IPv6 Route Reply Acknowledgment"},
    { 0,                    NULL }
};

static const value_string exttype_vals[] = {
    { AODV_EXT,     "None"},
    { AODV_EXT_INT, "Hello Interval"},
    { AODV_EXT_NTP, "Timestamp"},
    { 0,            NULL}
};

typedef struct v6_ext {
    guint8 type;
    guint8 length;
} aodv_ext_t;

/* Initialize the protocol and registered fields */
static int proto_aodv = -1;
static int hf_aodv_type = -1;
static int hf_aodv_flags = -1;
static int hf_aodv_prefix_sz = -1;
static int hf_aodv_hopcount = -1;
static int hf_aodv_rreq_id = -1;
static int hf_aodv_dest_ip = -1;
static int hf_aodv_dest_ipv6 = -1;
static int hf_aodv_dest_seqno = -1;
static int hf_aodv_orig_ip = -1;
static int hf_aodv_orig_ipv6 = -1;
static int hf_aodv_orig_seqno = -1;
static int hf_aodv_lifetime = -1;
static int hf_aodv_destcount = -1;
static int hf_aodv_unreach_dest_ip = -1;
static int hf_aodv_unreach_dest_ipv6 = -1;
static int hf_aodv_unreach_dest_seqno = -1;
static int hf_aodv_flags_rreq_join = -1;
static int hf_aodv_flags_rreq_repair = -1;
static int hf_aodv_flags_rreq_gratuitous = -1;
static int hf_aodv_flags_rreq_destinationonly = -1;
static int hf_aodv_flags_rreq_unknown = -1;
static int hf_aodv_flags_rrep_repair = -1;
static int hf_aodv_flags_rrep_ack = -1;
static int hf_aodv_flags_rerr_nodelete = -1;
static int hf_aodv_ext_type = -1;
static int hf_aodv_ext_length = -1;
static int hf_aodv_ext_interval = -1;
static int hf_aodv_ext_timestamp = -1;

/* Initialize the subtree pointers */
static gint ett_aodv = -1;
static gint ett_aodv_flags = -1;
static gint ett_aodv_unreach_dest = -1;
static gint ett_aodv_extensions = -1;

/* Code to actually dissect the packets */

static void
dissect_aodv_ext(tvbuff_t * tvb, int offset, proto_tree * tree)
{
    proto_tree *ext_tree;
    proto_item *ti;
    aodv_ext_t aodvext, *ext;
    int len;

    if (!tree)
	return;

  again:
    if ((int) tvb_reported_length(tvb) <= offset)
	return;			/* No more options left */

    ext = &aodvext;
    tvb_memcpy(tvb, (guint8 *) ext, offset, sizeof(*ext));
    len = ext->length;

    ti = proto_tree_add_text(tree, tvb, offset, sizeof(aodv_ext_t) +
			     len, "Extensions");
    ext_tree = proto_item_add_subtree(ti, ett_aodv_extensions);

    if (len == 0) {
	proto_tree_add_text(ext_tree, tvb,
			    offset + offsetof(aodv_ext_t, length), 1,
			    "Invalid option length: %u", ext->length);
	return;			/* we must not try to decode this */
    }

    proto_tree_add_text(ext_tree, tvb,
			offset + offsetof(aodv_ext_t, type), 1,
			"Type: %u (%s)", ext->type,
			val_to_str(ext->type, exttype_vals, "Unknown"));
    proto_tree_add_text(ext_tree, tvb,
			offset + offsetof(aodv_ext_t, length), 1,
			"Length: %u bytes", ext->length);

    offset += sizeof(aodv_ext_t);

    switch (ext->type) {
    case AODV_EXT_INT:
	proto_tree_add_uint(ext_tree, hf_aodv_ext_interval,
			    tvb, offset, 4, tvb_get_ntohl(tvb, offset));
	break;
    case AODV_EXT_NTP:
	proto_tree_add_item(ext_tree, hf_aodv_ext_timestamp,
			    tvb, offset, 8, FALSE);
	break;
    default:
	break;
    }
    /* If multifield extensions appear, we need more
     * sophisticated handler.  For now, this is okay. */

    offset += ext->length;
    goto again;
}

static void
dissect_aodv_rreq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *aodv_tree,
		  proto_item *ti, gboolean is_ipv6)
{
    int offset = 1;
    proto_item *tj;
    proto_tree *aodv_flags_tree;
    guint8 flags;
    guint8 hop_count;
    guint32 rreq_id;
    guint32 dest_addr_v4;
    struct e_in6_addr dest_addr_v6;
    guint32 dest_seqno;
    guint32 orig_addr_v4;
    struct e_in6_addr orig_addr_v6;
    guint32 orig_seqno;
    int extlen;

    flags = tvb_get_guint8(tvb, offset);
    if (aodv_tree) {
	tj = proto_tree_add_text(aodv_tree, tvb, offset, 1, "Flags:");
	aodv_flags_tree = proto_item_add_subtree(tj, ett_aodv_flags);
	proto_tree_add_boolean(aodv_flags_tree, hf_aodv_flags_rreq_join,
			       tvb, offset, 1, flags);
	proto_tree_add_boolean(aodv_flags_tree, hf_aodv_flags_rreq_repair,
			       tvb, offset, 1, flags);
	proto_tree_add_boolean(aodv_flags_tree, hf_aodv_flags_rreq_gratuitous,
			       tvb, offset, 1, flags);
	proto_tree_add_boolean(aodv_flags_tree, hf_aodv_flags_rreq_destinationonly,
			       tvb, offset, 1, flags);
	proto_tree_add_boolean(aodv_flags_tree, hf_aodv_flags_rreq_unknown,
			       tvb, offset, 1, flags);
	if (flags & RREQ_JOIN)
	    proto_item_append_text(tj, " J");
	if (flags & RREQ_REP)
	    proto_item_append_text(tj, " R");
	if (flags & RREQ_GRATRREP)
	    proto_item_append_text(tj, " G");
	if (flags & RREQ_DESTONLY)
	    proto_item_append_text(tj, " D");
	if (flags & RREQ_UNKNSEQ)
	    proto_item_append_text(tj, " U");
    }
    offset += 2;	/* skip reserved byte */

    hop_count = tvb_get_guint8(tvb, offset);
    if (aodv_tree)
	proto_tree_add_uint(aodv_tree, hf_aodv_hopcount, tvb, offset, 1,
			    hop_count);
    offset += 1;

    rreq_id = tvb_get_ntohl(tvb, offset);
    if (aodv_tree)
	proto_tree_add_uint(aodv_tree, hf_aodv_rreq_id, tvb, offset, 4,
			    rreq_id);
    offset += 4;

    if (is_ipv6) {
	tvb_get_ipv6(tvb, offset, &dest_addr_v6);
	if (aodv_tree) {
	    proto_tree_add_ipv6(aodv_tree, hf_aodv_dest_ipv6, tvb, offset,
				INET6_ADDRLEN, (guint8 *)&dest_addr_v6);
	    proto_item_append_text(ti, ", Dest IP: %s",
				   ip6_to_str(&dest_addr_v6));
	}
	if (check_col(pinfo->cinfo, COL_INFO))
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", D: %s",
			    ip6_to_str(&dest_addr_v6));
	offset += INET6_ADDRLEN;
    } else {
	dest_addr_v4 = tvb_get_ipv4(tvb, offset);
	if (aodv_tree) {
	    proto_tree_add_ipv4(aodv_tree, hf_aodv_dest_ip, tvb, offset, 4,
				dest_addr_v4);
	    proto_item_append_text(ti, ", Dest IP: %s",
				   ip_to_str((guint8 *)&dest_addr_v4));
	}
	if (check_col(pinfo->cinfo, COL_INFO))
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", D: %s",
			    ip_to_str((guint8 *)&dest_addr_v4));
	offset += 4;
    }

    dest_seqno = tvb_get_ntohl(tvb, offset);
    if (aodv_tree)
	proto_tree_add_uint(aodv_tree, hf_aodv_dest_seqno, tvb, offset, 4,
			    dest_seqno);
    offset += 4;

    if (is_ipv6) {
	tvb_get_ipv6(tvb, offset, &orig_addr_v6);
	if (aodv_tree) {
	    proto_tree_add_ipv6(aodv_tree, hf_aodv_orig_ipv6, tvb, offset,
				INET6_ADDRLEN, (guint8 *)&orig_addr_v6);
	    proto_item_append_text(ti, ", Orig IP: %s",
				   ip6_to_str(&orig_addr_v6));
	}
	if (check_col(pinfo->cinfo, COL_INFO))
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", O: %s",
			    ip6_to_str(&orig_addr_v6));
	offset += INET6_ADDRLEN;
    } else {
	orig_addr_v4 = tvb_get_ipv4(tvb, offset);
	if (aodv_tree) {
	    proto_tree_add_ipv4(aodv_tree, hf_aodv_orig_ip, tvb, offset, 4,
				orig_addr_v4);
	    proto_item_append_text(ti, ", Orig IP: %s",
				   ip_to_str((guint8 *)&orig_addr_v4));
	}
	if (check_col(pinfo->cinfo, COL_INFO))
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", O: %s",
			    ip_to_str((guint8 *)&orig_addr_v4));
	offset += 4;
    }

    orig_seqno = tvb_get_ntohl(tvb, offset);
    if (aodv_tree)
	proto_tree_add_uint(aodv_tree, hf_aodv_orig_seqno, tvb, offset, 4,
			    orig_seqno);
    if (check_col(pinfo->cinfo, COL_INFO))
	col_append_fstr(pinfo->cinfo, COL_INFO, " Id=%u Hcnt=%u DSN=%u OSN=%u",
			rreq_id,
			hop_count,
			dest_seqno,
			orig_seqno);
    offset += 4;

    if (aodv_tree) {
	extlen = tvb_reported_length_remaining(tvb, offset);
	if (extlen > 0)
	    dissect_aodv_ext(tvb, offset, aodv_tree);
    }
}

static void
dissect_aodv_rrep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *aodv_tree,
		  proto_item *ti, gboolean is_ipv6)
{
    int offset = 1;
    proto_item *tj;
    proto_tree *aodv_flags_tree;
    guint8 flags;
    guint8 prefix_sz;
    guint8 hop_count;
    guint32 dest_addr_v4;
    struct e_in6_addr dest_addr_v6;
    guint32 dest_seqno;
    guint32 orig_addr_v4;
    struct e_in6_addr orig_addr_v6;
    guint32 lifetime;
    int extlen;

    flags = tvb_get_guint8(tvb, offset);
    if (aodv_tree) {
	tj = proto_tree_add_text(aodv_tree, tvb, offset, 1, "Flags:");
	aodv_flags_tree = proto_item_add_subtree(tj, ett_aodv_flags);
	proto_tree_add_boolean(aodv_flags_tree, hf_aodv_flags_rrep_repair,
			       tvb, offset, 1, flags);
	proto_tree_add_boolean(aodv_flags_tree, hf_aodv_flags_rrep_ack, tvb,
			       offset, 1, flags);
	if (flags & RREP_REP)
	    proto_item_append_text(tj, " R");
	if (flags & RREP_ACK_REQ)
	    proto_item_append_text(tj, " A");
    }
    offset += 1;

    prefix_sz = tvb_get_guint8(tvb, offset) & 0x1F;
    if (aodv_tree)
	proto_tree_add_uint(aodv_tree, hf_aodv_prefix_sz, tvb, offset, 1,
			    prefix_sz);
    offset += 1;

    hop_count = tvb_get_guint8(tvb, offset);
    if (aodv_tree)
	proto_tree_add_uint(aodv_tree, hf_aodv_hopcount, tvb, offset, 1,
			    hop_count);
    offset += 1;

    if (is_ipv6) {
	tvb_get_ipv6(tvb, offset, &dest_addr_v6);
	if (aodv_tree) {
	    proto_tree_add_ipv6(aodv_tree, hf_aodv_dest_ipv6, tvb, offset,
				INET6_ADDRLEN, (guint8 *)&dest_addr_v6);
	    proto_item_append_text(ti, ", Dest IP: %s",
				   ip6_to_str(&dest_addr_v6));
	}
	if (check_col(pinfo->cinfo, COL_INFO))
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", D: %s",
			    ip6_to_str(&dest_addr_v6));
	offset += INET6_ADDRLEN;
    } else {
	dest_addr_v4 = tvb_get_ipv4(tvb, offset);
	if (aodv_tree) {
	    proto_tree_add_ipv4(aodv_tree, hf_aodv_dest_ip, tvb, offset, 4,
				dest_addr_v4);
	    proto_item_append_text(ti, ", Dest IP: %s",
				   ip_to_str((guint8 *)&dest_addr_v4));
	}
	if (check_col(pinfo->cinfo, COL_INFO))
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", D: %s",
			    ip_to_str((guint8 *)&dest_addr_v4));
	offset += 4;
    }

    dest_seqno = tvb_get_ntohl(tvb, offset);
    if (aodv_tree)
	proto_tree_add_uint(aodv_tree, hf_aodv_dest_seqno, tvb, offset, 4,
			    dest_seqno);
    offset += 4;

    if (is_ipv6) {
	tvb_get_ipv6(tvb, offset, &orig_addr_v6);
	if (aodv_tree) {
	    proto_tree_add_ipv6(aodv_tree, hf_aodv_orig_ipv6, tvb, offset,
				INET6_ADDRLEN, (guint8 *)&orig_addr_v6);
	    proto_item_append_text(ti, ", Orig IP: %s",
				   ip6_to_str(&orig_addr_v6));
	}
	if (check_col(pinfo->cinfo, COL_INFO))
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", O: %s",
			    ip6_to_str(&orig_addr_v6));
	offset += INET6_ADDRLEN;
    } else {
	orig_addr_v4 = tvb_get_ipv4(tvb, offset);
	if (aodv_tree) {
	    proto_tree_add_ipv4(aodv_tree, hf_aodv_orig_ip, tvb, offset, 4,
				orig_addr_v4);
	    proto_item_append_text(ti, ", Orig IP: %s",
				   ip_to_str((guint8 *)&orig_addr_v4));
	}
	if (check_col(pinfo->cinfo, COL_INFO))
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", O: %s",
			    ip_to_str((guint8 *)&orig_addr_v4));
	offset += 4;
    }

    lifetime = tvb_get_ntohl(tvb, offset);
    if (aodv_tree) {
	proto_tree_add_uint(aodv_tree, hf_aodv_lifetime, tvb, offset, 4,
			    lifetime);
	proto_item_append_text(ti, ", Lifetime=%u", lifetime);
    }
    if (check_col(pinfo->cinfo, COL_INFO))
	col_append_fstr(pinfo->cinfo, COL_INFO, " Hcnt=%u DSN=%u Lifetime=%u",
			hop_count,
			dest_seqno,
			lifetime);
    offset += 4;

    if (aodv_tree) {
	extlen = tvb_reported_length_remaining(tvb, offset);
	if (extlen > 0)
	    dissect_aodv_ext(tvb, offset, aodv_tree);
    }
}

static void
dissect_aodv_rerr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *aodv_tree,
		  gboolean is_ipv6)
{
    int offset = 1;
    proto_item *tj;
    proto_tree *aodv_flags_tree;
    proto_tree *aodv_unreach_dest_tree;
    guint8 flags;
    guint8 dest_count;
    int i;

    flags = tvb_get_guint8(tvb, offset);
    if (aodv_tree) {
	tj = proto_tree_add_text(aodv_tree, tvb, offset, 1, "Flags:");
	aodv_flags_tree = proto_item_add_subtree(tj, ett_aodv_flags);
	proto_tree_add_boolean(aodv_flags_tree, hf_aodv_flags_rerr_nodelete,
			       tvb, offset, 1, flags);
	if (flags & RERR_NODEL)
	    proto_item_append_text(tj, " N");
    }
    offset += 2;	/* skip reserved byte */

    dest_count = tvb_get_guint8(tvb, offset);
    if (aodv_tree)
	proto_tree_add_uint(aodv_tree, hf_aodv_destcount, tvb, offset, 1,
			    dest_count);
    if (check_col(pinfo->cinfo, COL_INFO))
	col_append_fstr(pinfo->cinfo, COL_INFO, ", Dest Count=%u",
			dest_count);
    offset += 1;

    if (is_ipv6) {
	tj = proto_tree_add_text(aodv_tree, tvb, offset,
				 (INET6_ADDRLEN + 4)*dest_count,
				 "Unreachable Destinations");
	aodv_unreach_dest_tree = proto_item_add_subtree(tj, ett_aodv_unreach_dest);
	for (i = 0; i < dest_count; i++) {
	    proto_tree_add_item(aodv_unreach_dest_tree,
				hf_aodv_unreach_dest_ipv6,
				tvb, offset, INET6_ADDRLEN, FALSE);
	    offset += INET6_ADDRLEN;
	    proto_tree_add_item(aodv_unreach_dest_tree, hf_aodv_dest_seqno,
				tvb, offset, 4, FALSE);
	    offset += 4;
	}
    } else {
	tj = proto_tree_add_text(aodv_tree, tvb, offset, (4 + 4)*dest_count,
				 "Unreachable Destinations");
	aodv_unreach_dest_tree = proto_item_add_subtree(tj, ett_aodv_unreach_dest);
	for (i = 0; i < dest_count; i++) {
	    proto_tree_add_item(aodv_unreach_dest_tree, hf_aodv_unreach_dest_ip,
				tvb, offset, 4, FALSE);
	    offset += 4;
	    proto_tree_add_item(aodv_unreach_dest_tree, hf_aodv_dest_seqno,
				tvb, offset, 4, FALSE);
	    offset += 4;
	}
    }
}

static void
dissect_aodv_draft_01_v6_rreq(tvbuff_t *tvb, packet_info *pinfo,
			      proto_tree *aodv_tree, proto_item *ti)
{
    int offset = 1;
    proto_item *tj;
    proto_tree *aodv_flags_tree;
    guint8 flags;
    guint8 hop_count;
    guint32 rreq_id;
    guint32 dest_seqno;
    guint32 orig_seqno;
    struct e_in6_addr dest_addr_v6;
    struct e_in6_addr orig_addr_v6;
    int extlen;

    flags = tvb_get_guint8(tvb, offset);
    if (aodv_tree) {
	tj = proto_tree_add_text(aodv_tree, tvb, offset, 1, "Flags:");
	aodv_flags_tree = proto_item_add_subtree(tj, ett_aodv_flags);
	proto_tree_add_boolean(aodv_flags_tree, hf_aodv_flags_rreq_join,
			       tvb, offset, 1, flags);
	proto_tree_add_boolean(aodv_flags_tree, hf_aodv_flags_rreq_repair,
			       tvb, offset, 1, flags);
	proto_tree_add_boolean(aodv_flags_tree, hf_aodv_flags_rreq_gratuitous,
			       tvb, offset, 1, flags);
	proto_tree_add_boolean(aodv_flags_tree, hf_aodv_flags_rreq_destinationonly,
			       tvb, offset, 1, flags);
	proto_tree_add_boolean(aodv_flags_tree, hf_aodv_flags_rreq_unknown,
			       tvb, offset, 1, flags);
	if (flags & RREQ_JOIN)
	    proto_item_append_text(tj, " J");
	if (flags & RREQ_REP)
	    proto_item_append_text(tj, " R");
	if (flags & RREQ_GRATRREP)
	    proto_item_append_text(tj, " G");
	if (flags & RREQ_DESTONLY)
	    proto_item_append_text(tj, " D");
	if (flags & RREQ_UNKNSEQ)
	    proto_item_append_text(tj, " U");
    }
    offset += 2;	/* skip reserved byte */

    hop_count = tvb_get_guint8(tvb, offset);
    if (aodv_tree)
	proto_tree_add_uint(aodv_tree, hf_aodv_hopcount, tvb, offset, 1,
			     hop_count);
    offset += 1;

    rreq_id = tvb_get_ntohl(tvb, offset);
    if (aodv_tree)
	proto_tree_add_uint(aodv_tree, hf_aodv_rreq_id, tvb, offset, 4,
			    rreq_id);
    offset += 4;

    dest_seqno = tvb_get_ntohl(tvb, offset);
    if (aodv_tree)
	proto_tree_add_uint(aodv_tree, hf_aodv_dest_seqno, tvb, offset, 4,
			    dest_seqno);
    offset += 4;

    orig_seqno = tvb_get_ntohl(tvb, offset);
    if (aodv_tree)
	proto_tree_add_uint(aodv_tree, hf_aodv_orig_seqno, tvb, offset, 4,
			    orig_seqno);
    offset += 4;

    tvb_get_ipv6(tvb, offset, &dest_addr_v6);
    if (aodv_tree) {
	proto_tree_add_ipv6(aodv_tree, hf_aodv_dest_ipv6, tvb, offset,
			    INET6_ADDRLEN, (guint8 *)&dest_addr_v6);
	proto_item_append_text(ti, ", Dest IP: %s",
			       ip6_to_str(&dest_addr_v6));
    }
    if (check_col(pinfo->cinfo, COL_INFO))
	col_append_fstr(pinfo->cinfo, COL_INFO, ", D: %s",
			ip6_to_str(&dest_addr_v6));
    offset += INET6_ADDRLEN;

    tvb_get_ipv6(tvb, offset, &orig_addr_v6);
    if (aodv_tree) {
	proto_tree_add_ipv6(aodv_tree, hf_aodv_orig_ipv6, tvb, offset,
			    INET6_ADDRLEN, (guint8 *)&orig_addr_v6);
	proto_item_append_text(ti, ", Orig IP: %s",
			       ip6_to_str(&orig_addr_v6));
    }
    if (check_col(pinfo->cinfo, COL_INFO))
	col_append_fstr(pinfo->cinfo, COL_INFO,
			", O: %s Id=%u Hcnt=%u DSN=%u OSN=%u",
			ip6_to_str(&orig_addr_v6),
			rreq_id,
			hop_count,
			dest_seqno,
			orig_seqno);
    offset += INET6_ADDRLEN;

    if (aodv_tree) {
	extlen = tvb_reported_length_remaining(tvb, offset);
	if (extlen > 0)
	    dissect_aodv_ext(tvb, offset, aodv_tree);
    }
}

static void
dissect_aodv_draft_01_v6_rrep(tvbuff_t *tvb, packet_info *pinfo,
			      proto_tree *aodv_tree, proto_item *ti)
{
    int offset = 1;
    proto_item *tj;
    proto_tree *aodv_flags_tree;
    guint8 flags;
    guint8 prefix_sz;
    guint8 hop_count;
    guint32 dest_seqno;
    struct e_in6_addr dest_addr_v6;
    struct e_in6_addr orig_addr_v6;
    guint32 lifetime;
    int extlen;

    flags = tvb_get_guint8(tvb, offset);
    if (aodv_tree) {
	tj = proto_tree_add_text(aodv_tree, tvb, offset, 1, "Flags:");
	aodv_flags_tree = proto_item_add_subtree(tj, ett_aodv_flags);
	proto_tree_add_boolean(aodv_flags_tree, hf_aodv_flags_rrep_repair,
			       tvb, offset, 1, flags);
	proto_tree_add_boolean(aodv_flags_tree, hf_aodv_flags_rrep_ack, tvb,
			       offset, 1, flags);
	if (flags & RREP_REP)
	    proto_item_append_text(tj, " R");
	if (flags & RREP_ACK_REQ)
	    proto_item_append_text(tj, " A");
    }
    offset += 1;

    prefix_sz = tvb_get_guint8(tvb, offset) & 0x7F;
    if (aodv_tree)
	proto_tree_add_uint(aodv_tree, hf_aodv_prefix_sz, tvb, offset, 1,
			    prefix_sz);
    offset += 1;

    hop_count = tvb_get_guint8(tvb, offset);
    if (aodv_tree)
	proto_tree_add_uint(aodv_tree, hf_aodv_hopcount, tvb, offset, 1,
			    hop_count);
    offset += 1;

    dest_seqno = tvb_get_ntohl(tvb, offset);
    if (aodv_tree)
	proto_tree_add_uint(aodv_tree, hf_aodv_dest_seqno, tvb, offset, 4,
			    dest_seqno);
    offset += 4;

    tvb_get_ipv6(tvb, offset, &dest_addr_v6);
    if (aodv_tree) {
	proto_tree_add_ipv6(aodv_tree, hf_aodv_dest_ipv6, tvb, offset,
			    INET6_ADDRLEN, (guint8 *)&dest_addr_v6);
	proto_item_append_text(ti, ", Dest IP: %s",
			       ip6_to_str(&dest_addr_v6));
    }
    if (check_col(pinfo->cinfo, COL_INFO))
	col_append_fstr(pinfo->cinfo, COL_INFO, ", D: %s",
			ip6_to_str(&dest_addr_v6));
    offset += INET6_ADDRLEN;

    tvb_get_ipv6(tvb, offset, &orig_addr_v6);
    if (aodv_tree) {
	proto_tree_add_ipv6(aodv_tree, hf_aodv_orig_ipv6, tvb, offset,
			    INET6_ADDRLEN, (guint8 *)&orig_addr_v6);
	proto_item_append_text(ti, ", Orig IP: %s",
			       ip6_to_str(&orig_addr_v6));
    }
    if (check_col(pinfo->cinfo, COL_INFO))
	col_append_fstr(pinfo->cinfo, COL_INFO, ", O: %s",
			ip6_to_str(&orig_addr_v6));
    offset += INET6_ADDRLEN;

    lifetime = tvb_get_ntohl(tvb, offset);
    if (aodv_tree) {
	proto_tree_add_uint(aodv_tree, hf_aodv_lifetime, tvb, offset, 4,
			    lifetime);
	proto_item_append_text(ti, ", Lifetime=%u", lifetime);
    }
    if (check_col(pinfo->cinfo, COL_INFO))
	col_append_fstr(pinfo->cinfo, COL_INFO, " Hcnt=%u DSN=%u Lifetime=%u",
			hop_count,
			dest_seqno,
			lifetime);
    offset += 4;

    if (aodv_tree) {
	extlen = tvb_reported_length_remaining(tvb, offset);
	if (extlen > 0)
	    dissect_aodv_ext(tvb, offset, aodv_tree);
    }
}

static void
dissect_aodv_draft_01_v6_rerr(tvbuff_t *tvb, packet_info *pinfo,
			      proto_tree *aodv_tree)
{
    int offset = 1;
    proto_item *tj;
    proto_tree *aodv_flags_tree;
    proto_tree *aodv_unreach_dest_tree;
    guint8 flags;
    guint8 dest_count;
    int i;

    flags = tvb_get_guint8(tvb, offset);
    if (aodv_tree) {
	tj = proto_tree_add_text(aodv_tree, tvb, offset, 1, "Flags:");
	aodv_flags_tree = proto_item_add_subtree(tj, ett_aodv_flags);
	proto_tree_add_boolean(aodv_flags_tree, hf_aodv_flags_rerr_nodelete,
			       tvb, offset, 1, flags);
	if (flags & RERR_NODEL)
	    proto_item_append_text(tj, " N");
    }
    offset += 2;	/* skip reserved byte */

    dest_count = tvb_get_guint8(tvb, offset);
    if (aodv_tree)
	proto_tree_add_uint(aodv_tree, hf_aodv_destcount, tvb, offset, 1,
			    dest_count);
    if (check_col(pinfo->cinfo, COL_INFO))
	col_append_fstr(pinfo->cinfo, COL_INFO, ", Dest Count=%u",
			dest_count);
    offset += 1;

    tj = proto_tree_add_text(aodv_tree, tvb, offset,
			     (4 + INET6_ADDRLEN)*dest_count,
			     "Unreachable Destinations");
    aodv_unreach_dest_tree = proto_item_add_subtree(tj, ett_aodv_unreach_dest);
    for (i = 0; i < dest_count; i++) {
	proto_tree_add_item(aodv_unreach_dest_tree, hf_aodv_dest_seqno,
			    tvb, offset, 4, FALSE);
	offset += 4;
	proto_tree_add_item(aodv_unreach_dest_tree,
			    hf_aodv_unreach_dest_ipv6,
			    tvb, offset, INET6_ADDRLEN, FALSE);
	offset += INET6_ADDRLEN;
    }
}

static int
dissect_aodv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_tree *aodv_tree = NULL;
    gboolean is_ipv6;
    guint8 type;

/* Make entries in Protocol column and Info column on summary display */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "AODV");

    if (check_col(pinfo->cinfo, COL_INFO))
	col_clear(pinfo->cinfo, COL_INFO);

    /* Is this running over IPv6? */
    is_ipv6 = (pinfo->src.type == AT_IPv6);

    /* Check the type of AODV packet. */
    type = tvb_get_guint8(tvb, 0);
    if (match_strval(type, type_vals) == NULL) {
	/*
	 * We assume this is not an AODV packet.
	 */
	return 0;
    }

    if (check_col(pinfo->cinfo, COL_INFO))
	col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
		     val_to_str(type, type_vals,
				"Unknown AODV Packet Type (%u)"));
    if (tree) {
	ti = proto_tree_add_protocol_format(tree, proto_aodv, tvb, 0, -1,
	    "Ad hoc On-demand Distance Vector Routing Protocol, %s",
	    val_to_str(type, type_vals, "Unknown AODV Packet Type (%u)"));
	aodv_tree = proto_item_add_subtree(ti, ett_aodv);

	proto_tree_add_uint(aodv_tree, hf_aodv_type, tvb, 0, 1, type);
    }

    switch (type) {
    case RREQ:
	dissect_aodv_rreq(tvb, pinfo, aodv_tree, ti, is_ipv6);
	break;
    case RREP:
	dissect_aodv_rrep(tvb, pinfo, aodv_tree, ti, is_ipv6);
	break;
    case RERR:
	dissect_aodv_rerr(tvb, pinfo, aodv_tree, is_ipv6);
	break;
    case RREP_ACK:
	break;
    case DRAFT_01_V6_RREQ:
	dissect_aodv_draft_01_v6_rreq(tvb, pinfo, aodv_tree, ti);
	break;
    case DRAFT_01_V6_RREP:
	dissect_aodv_draft_01_v6_rrep(tvb, pinfo, aodv_tree, ti);
	break;
    case DRAFT_01_V6_RERR:
	dissect_aodv_draft_01_v6_rerr(tvb, pinfo, aodv_tree);
	break;
    case DRAFT_01_V6_RREP_ACK:
	break;
    default:
	proto_tree_add_text(aodv_tree, tvb, 0, -1,
			    "Unknown AODV Packet Type (%u)", type);
    }

    return tvb_length(tvb);
}


/* Register the protocol with Wireshark */
void
proto_register_aodv(void)
{
    static hf_register_info hf[] = {
	{ &hf_aodv_type,
	  { "Type", "aodv.type",
	    FT_UINT8, BASE_DEC, VALS(type_vals), 0x0,
	    "AODV packet type", HFILL }
	},
	{ &hf_aodv_flags,
	  { "Flags", "aodv.flags",
	    FT_UINT16, BASE_DEC, NULL, 0x0,
	    "Flags", HFILL }
	},
	{ &hf_aodv_flags_rreq_join,
	  { "RREQ Join", "aodv.flags.rreq_join",
	    FT_BOOLEAN, 8, TFS(&flags_set_truth), RREQ_JOIN,
	    "", HFILL }
	},
	{ &hf_aodv_flags_rreq_repair,
	  { "RREQ Repair", "aodv.flags.rreq_repair",
	    FT_BOOLEAN, 8, TFS(&flags_set_truth), RREQ_REP,
	    "", HFILL }
	},
	{ &hf_aodv_flags_rreq_gratuitous,
	  { "RREQ Gratuitous RREP", "aodv.flags.rreq_gratuitous",
	    FT_BOOLEAN, 8, TFS(&flags_set_truth), RREQ_GRATRREP,
	    "", HFILL }
	},
	{ &hf_aodv_flags_rreq_destinationonly,
	  { "RREQ Destination only", "aodv.flags.rreq_destinationonly",
	    FT_BOOLEAN, 8, TFS(&flags_set_truth), RREQ_DESTONLY,
	    "", HFILL }
	},
	{ &hf_aodv_flags_rreq_unknown,
	  { "RREQ Unknown Sequence Number", "aodv.flags.rreq_unknown",
	    FT_BOOLEAN, 8, TFS(&flags_set_truth), RREQ_UNKNSEQ,
	    "", HFILL }
	},
	{ &hf_aodv_flags_rrep_repair,
	  { "RREP Repair", "aodv.flags.rrep_repair",
	    FT_BOOLEAN, 8, TFS(&flags_set_truth), RREP_REP,
	    "", HFILL }
	},
	{ &hf_aodv_flags_rrep_ack,
	  { "RREP Acknowledgement", "aodv.flags.rrep_ack",
	    FT_BOOLEAN, 8, TFS(&flags_set_truth), RREP_ACK_REQ,
	    "", HFILL }
	},
	{ &hf_aodv_flags_rerr_nodelete,
	  { "RERR No Delete", "aodv.flags.rerr_nodelete",
	    FT_BOOLEAN, 8, TFS(&flags_set_truth), RERR_NODEL,
	    "", HFILL }
	},
	{ &hf_aodv_prefix_sz,
	  { "Prefix Size", "aodv.prefix_sz",
	    FT_UINT8, BASE_DEC, NULL, 0x0,
	    "Prefix Size", HFILL }
	},
	{ &hf_aodv_hopcount,
	  { "Hop Count", "aodv.hopcount",
	    FT_UINT8, BASE_DEC, NULL, 0x0,
	    "Hop Count", HFILL }
	},
	{ &hf_aodv_rreq_id,
	  { "RREQ Id", "aodv.rreq_id",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "RREQ Id", HFILL }
	},
	{ &hf_aodv_dest_ip,
	  { "Destination IP", "aodv.dest_ip",
	    FT_IPv4, BASE_NONE, NULL, 0x0,
	    "Destination IP Address", HFILL }
	},
	{ &hf_aodv_dest_ipv6,
	  { "Destination IPv6", "aodv.dest_ipv6",
	    FT_IPv6, BASE_NONE, NULL, 0x0,
	    "Destination IPv6 Address", HFILL}
	},
	{ &hf_aodv_dest_seqno,
	  { "Destination Sequence Number", "aodv.dest_seqno",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "Destination Sequence Number", HFILL }
	},
	{ &hf_aodv_orig_ip,
	  { "Originator IP", "aodv.orig_ip",
	    FT_IPv4, BASE_NONE, NULL, 0x0,
	    "Originator IP Address", HFILL }
	},
	{ &hf_aodv_orig_ipv6,
	  { "Originator IPv6", "aodv.orig_ipv6",
	    FT_IPv6, BASE_NONE, NULL, 0x0,
	    "Originator IPv6 Address", HFILL}
	},
	{ &hf_aodv_orig_seqno,
	  { "Originator Sequence Number", "aodv.orig_seqno",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "Originator Sequence Number", HFILL }
	},
	{ &hf_aodv_lifetime,
	  { "Lifetime", "aodv.lifetime",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "Lifetime", HFILL }
	},
	{ &hf_aodv_destcount,
	  { "Destination Count", "aodv.destcount",
	    FT_UINT8, BASE_DEC, NULL, 0x0,
	    "Unreachable Destinations Count", HFILL }
	},
	{ &hf_aodv_unreach_dest_ip,
	  { "Unreachable Destination IP", "aodv.unreach_dest_ip",
	    FT_IPv4, BASE_NONE, NULL, 0x0,
	    "Unreachable Destination IP Address", HFILL }
	},
	{ &hf_aodv_unreach_dest_ipv6,
	  { "Unreachable Destination IPv6", "aodv.unreach_dest_ipv6",
	    FT_IPv6, BASE_NONE, NULL, 0x0,
	    "Unreachable Destination IPv6 Address", HFILL}
	},
	{ &hf_aodv_unreach_dest_seqno,
	  { "Unreachable Destination Sequence Number", "aodv.unreach_dest_seqno",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "Unreachable Destination Sequence Number", HFILL }
	},
	{ &hf_aodv_ext_type,
	  { "Extension Type", "aodv.ext_type",
	    FT_UINT8, BASE_DEC, NULL, 0x0,
	    "Extension Format Type", HFILL}
	},
	{ &hf_aodv_ext_length,
	  { "Extension Length", "aodv.ext_length",
	    FT_UINT8, BASE_DEC, NULL, 0x0,
	    "Extension Data Length", HFILL}
	},
	{ &hf_aodv_ext_interval,
	  { "Hello Interval", "aodv.hello_interval",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "Hello Interval Extension", HFILL}
	 },
	{ &hf_aodv_ext_timestamp,
	  { "Timestamp", "aodv.timestamp",
	    FT_UINT64, BASE_DEC, NULL, 0x0,
	    "Timestamp Extension", HFILL}
	 },
    };

/* Setup protocol subtree array */
    static gint *ett[] = {
	&ett_aodv,
	&ett_aodv_flags,
	&ett_aodv_unreach_dest,
	&ett_aodv_extensions,
    };

/* Register the protocol name and description */
    proto_aodv = proto_register_protocol("Ad hoc On-demand Distance Vector Routing Protocol", "AODV", "aodv");

/* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_aodv, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}


void
proto_reg_handoff_aodv(void)
{
    dissector_handle_t aodv_handle;

    aodv_handle = new_create_dissector_handle(dissect_aodv,
					      proto_aodv);
    dissector_add("udp.port", UDP_PORT_AODV, aodv_handle);
}
