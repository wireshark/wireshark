/* packet-aodv.c
 * Routines for AODV dissection
 * Copyright 2000, Erik Nordström <erik.nordstrom@it.uu.se>
 *
 * $Id: packet-aodv.c,v 1.8 2003/07/09 03:59:59 guy Exp $
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

#include <epan/int-64bit.h>
#include <epan/packet.h>
#include <epan/ipv6-utils.h>

#ifndef offsetof
#define	offsetof(type, member)	((size_t)(&((type *)0)->member))
#endif

/*
 * See
 *
 *	http://www.ietf.org/internet-drafts/draft-ietf-manet-aodv-13.txt
 *
 *	http://www.cs.ucsb.edu/~ebelding/txt/aodv6.txt
 *
 *	http://www.tcs.hut.fi/~anttit/manet/drafts/draft-perkins-aodv6-01.txt
 */

#define INET6_ADDRLEN	16
#define UDP_PORT_AODV	654

/* Message Types */
#define RREQ		1
#define RREP		2
#define RERR		3
#define V6_RREQ		16
#define V6_RREP		17
#define V6_RERR		18
#define V6_RREP_ACK	19

/* Extension Types */
#define AODV_EXT	1
#define AODV_EXT_INT	2
#define AODV_EXT_NTP	3

/* Flag bits: */
#define RREQ_GRAT    0x20
#define RREQ_REP     0x40
#define RREQ_JOIN    0x80

#define RREP_ACK     0x40
#define RREP_REP     0x80

#define RERR_NODEL   0x80

static const value_string type_vals[] = {
    { RREQ,        "Route Request" },
    { RREP,        "Route Reply" },
    { RERR,        "Route Error" },
    { V6_RREQ,     "IPv6 Route Request"},
    { V6_RREP,     "IPv6 Route Reply"},
    { V6_RERR,     "IPv6 Route Error"},
    { V6_RREP_ACK, "IPv6 Route Reply Acknowledgment"},
    { 0,           NULL }
};

static const value_string exttype_vals[] = {
    { AODV_EXT,     "None"},
    { AODV_EXT_INT, "Hello Interval"},
    { AODV_EXT_NTP, "Timestamp"},
    { 0,            NULL}
};

struct aodv_rreq {
    guint8 type;
    guint8 flags;
    guint8 res;
    guint8 hop_count;
    guint32 rreq_id;
    guint32 dest_addr;
    guint32 dest_seqno;
    guint32 orig_addr;
    guint32 orig_seqno;
};

struct aodv_rrep {
    guint8 type;
    guint8 flags;
    guint8 prefix_sz;
    guint8 hop_count;
    guint32 dest_addr;
    guint32 dest_seqno;
    guint32 orig_addr;
    guint32 lifetime;
};

struct aodv_rerr {
    guint8 type;
    guint8 flags;
    guint8 res;
    guint8 dest_count;
    guint32 dest_addr;
    guint32 dest_seqno;
};

typedef struct v6_rreq {
    guint8 type;
    guint8 flags;
    guint8 res;
    guint8 hop_count;
    guint32 rreq_id;
    guint32 dest_seqno;
    guint32 orig_seqno;
    struct e_in6_addr dest_addr;
    struct e_in6_addr orig_addr;
} v6_rreq_t;

typedef struct v6_rrep {
    guint8 type;
    guint8 flags;
    guint8 prefix_sz;
    guint8 hop_count;
    guint32 dest_seqno;
    struct e_in6_addr dest_addr;
    struct e_in6_addr orig_addr;
    guint32 lifetime;
} v6_rrep_t;

typedef struct v6_rerr {
    guint8 type;
    guint8 flags;
    guint8 res;
    guint8 dest_count;
    guint32 dest_seqno;
    struct e_in6_addr dest_addr;
} v6_rerr_t;

typedef struct v6_rrep_ack {
    guint8 type;
    guint8 res;
} v6_rrep_ack_t;

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

static int
dissect_aodv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti = NULL, *tj = NULL, *tk = NULL;
    proto_tree *aodv_tree = NULL, *aodv_flags_tree = NULL,
	*aodv_unreach_dest_tree = NULL;
    guint8 type;
    guint8 flags;
    int i, extlen;
    struct aodv_rreq rreq;
    struct aodv_rrep rrep;
    struct aodv_rerr rerr;
    v6_rreq_t v6_rreq;
    v6_rrep_t v6_rrep;
    v6_rerr_t v6_rerr;

/* Make entries in Protocol column and Info column on summary display */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "AODV");

    if (check_col(pinfo->cinfo, COL_INFO))
	col_clear(pinfo->cinfo, COL_INFO);

    /* Check the type of AODV packet. */
    type = tvb_get_guint8(tvb, 0);
    if (match_strval(type, type_vals) == NULL) {
	/*
	 * We assume this is not an AODV packet.
	 */
	return 0;
    }

    if (tree) {
	ti = proto_tree_add_protocol_format(tree, proto_aodv, tvb, 0, -1,
	    "Ad hoc On-demand Distance Vector Routing Protocol, %s",
	    val_to_str(type, type_vals, "Unknown AODV Packet Type (%u)"));
	aodv_tree = proto_item_add_subtree(ti, ett_aodv);

	proto_tree_add_uint(aodv_tree, hf_aodv_type, tvb, 0, 1, type);
	tj = proto_tree_add_text(aodv_tree, tvb, 1, 1, "Flags:");
	aodv_flags_tree = proto_item_add_subtree(tj, ett_aodv_flags);
    }


    switch (type) {
    case RREQ:
	flags = tvb_get_guint8(tvb, 1);
	rreq.hop_count = tvb_get_guint8(tvb, 3);
	rreq.rreq_id = tvb_get_ntohl(tvb, 4);
	tvb_memcpy(tvb, (guint8 *)&rreq.dest_addr, 8, 4);
	rreq.dest_seqno = tvb_get_ntohl(tvb, 12);
	tvb_memcpy(tvb, (guint8 *)&rreq.orig_addr, 16, 4);
	rreq.orig_seqno = tvb_get_ntohl(tvb, 20);

	if (tree) {
	    proto_tree_add_boolean(aodv_flags_tree, hf_aodv_flags_rreq_join, tvb, 1, 1, flags);
	    proto_tree_add_boolean(aodv_flags_tree, hf_aodv_flags_rreq_repair, tvb, 1, 1, flags);
	    proto_tree_add_boolean(aodv_flags_tree, hf_aodv_flags_rreq_gratuitous, tvb, 1, 1, flags);
	    if (flags & RREQ_JOIN)
		proto_item_append_text(tj, " J");
	    if (flags & RREQ_REP)
		proto_item_append_text(tj, " R");
	    if (flags & RREQ_GRAT)
		proto_item_append_text(tj, " G");
	    proto_tree_add_uint(aodv_tree, hf_aodv_hopcount, tvb, 3, 1, rreq.hop_count);
	    proto_tree_add_uint(aodv_tree, hf_aodv_rreq_id, tvb, 4, 4, rreq.rreq_id);
	    proto_tree_add_ipv4(aodv_tree, hf_aodv_dest_ip, tvb, 8, 4, rreq.dest_addr);
	    proto_tree_add_uint(aodv_tree, hf_aodv_dest_seqno, tvb, 12, 4, rreq.dest_seqno);
	    proto_tree_add_ipv4(aodv_tree, hf_aodv_orig_ip, tvb, 16, 4, rreq.orig_addr);
	    proto_tree_add_uint(aodv_tree, hf_aodv_orig_seqno, tvb, 20, 4, rreq.orig_seqno);
	    proto_item_append_text(ti, ", Dest IP: %s, Orig IP: %s, Id=%u", ip_to_str(tvb_get_ptr(tvb, 8, 4)), ip_to_str(tvb_get_ptr(tvb, 16, 4)), rreq.rreq_id);
	    extlen = ((int) tvb_reported_length(tvb) - sizeof(struct aodv_rreq));
	    if (extlen > 0) {
		dissect_aodv_ext(tvb, sizeof(struct aodv_rreq), aodv_tree);
	    }
	}

	if (check_col(pinfo->cinfo, COL_INFO))
	    col_add_fstr(pinfo->cinfo, COL_INFO, "%s, D: %s O: %s Id=%u Hcnt=%u DSN=%u OSN=%u",
			 val_to_str(type, type_vals,
				    "Unknown AODV Packet Type (%u)"),
			 ip_to_str(tvb_get_ptr(tvb, 8, 4)),
			 ip_to_str(tvb_get_ptr(tvb, 16, 4)),
			 rreq.rreq_id,
			 rreq.hop_count,
			 rreq.dest_seqno,
			 rreq.orig_seqno);

	break;
    case RREP:
	flags = tvb_get_guint8(tvb, 1);
	rrep.prefix_sz = tvb_get_guint8(tvb, 2) & 0x1F;
	rrep.hop_count = tvb_get_guint8(tvb, 3);
	tvb_memcpy(tvb, (guint8 *)&rrep.dest_addr, 4, 4);
	rrep.dest_seqno = tvb_get_ntohl(tvb, 8);
	tvb_memcpy(tvb, (guint8 *)&rrep.orig_addr, 12, 4);
	rrep.lifetime = tvb_get_ntohl(tvb, 16);

	if (tree) {
	    proto_tree_add_boolean(aodv_flags_tree, hf_aodv_flags_rrep_repair, tvb, 1, 1, flags);
	    proto_tree_add_boolean(aodv_flags_tree, hf_aodv_flags_rrep_ack, tvb, 1, 1, flags);
	    if (flags & RREP_REP)
		proto_item_append_text(tj, " R");
	    if (flags & RREP_ACK)
		proto_item_append_text(tj, " A");
	    proto_tree_add_uint(aodv_tree, hf_aodv_prefix_sz, tvb, 3, 1, rrep.prefix_sz);
	    proto_tree_add_uint(aodv_tree, hf_aodv_hopcount, tvb, 3, 1, rrep.hop_count);
	    proto_tree_add_ipv4(aodv_tree, hf_aodv_dest_ip, tvb, 4, 4, rrep.dest_addr);
	    proto_tree_add_uint(aodv_tree, hf_aodv_dest_seqno, tvb, 8, 4, rrep.dest_seqno);
	    proto_tree_add_ipv4(aodv_tree, hf_aodv_orig_ip, tvb, 12, 4, rrep.orig_addr);
	    proto_tree_add_uint(aodv_tree, hf_aodv_lifetime, tvb, 16, 4, rrep.lifetime);
	    proto_item_append_text(ti, ", Dest IP: %s, Orig IP: %s, Lifetime=%u", ip_to_str(tvb_get_ptr(tvb, 4, 4)), ip_to_str(tvb_get_ptr(tvb, 12, 4)), rrep.lifetime);
	    extlen = ((int) tvb_reported_length(tvb) - sizeof(struct aodv_rrep));
	    if (extlen > 0) {
		dissect_aodv_ext(tvb, sizeof(struct aodv_rrep), aodv_tree);
	    }
	}

	if (check_col(pinfo->cinfo, COL_INFO))
	    col_add_fstr(pinfo->cinfo, COL_INFO, "%s D: %s O: %s Hcnt=%u DSN=%u Lifetime=%u",
			 val_to_str(type, type_vals,
				    "Unknown AODV Packet Type (%u)"),
			 ip_to_str(tvb_get_ptr(tvb, 4, 4)),
			 ip_to_str(tvb_get_ptr(tvb, 12, 4)),
			 rrep.hop_count,
			 rrep.dest_seqno,
			 rrep.lifetime);
	break;
    case RERR:
	flags = tvb_get_guint8(tvb, 1);
	rerr.dest_count = tvb_get_guint8(tvb, 3);

	if (tree) {
	    proto_tree_add_boolean(aodv_flags_tree, hf_aodv_flags_rerr_nodelete, tvb, 1, 1, flags);
	    if (flags & RERR_NODEL)
		proto_item_append_text(tj, " N");
	    proto_tree_add_uint(aodv_tree, hf_aodv_destcount, tvb, 3, 1, rerr.dest_count);
	    tk = proto_tree_add_text(aodv_tree, tvb, 4, 8*rerr.dest_count, "Unreachable Destinations:");

	    aodv_unreach_dest_tree = proto_item_add_subtree(tk, ett_aodv_unreach_dest);
	    for (i = 0; i < rerr.dest_count; i++) {
		tvb_memcpy(tvb, (guint8 *)&rerr.dest_addr, 4+8*i, 4);
		rerr.dest_seqno = tvb_get_ntohl(tvb, 8+8*i);
		proto_tree_add_ipv4(aodv_unreach_dest_tree, hf_aodv_dest_ip, tvb, 4+8*i, 4, rerr.dest_addr);
		proto_tree_add_uint(aodv_unreach_dest_tree, hf_aodv_dest_seqno, tvb, 8+8*i, 4, rerr.dest_seqno);
	    }
	}

	if (check_col(pinfo->cinfo, COL_INFO))
	    col_add_fstr(pinfo->cinfo, COL_INFO, "%s, Dest Count=%u",
			 val_to_str(type, type_vals,
				    "Unknown AODV Packet Type (%u)"),
			 rerr.dest_count);
	break;
    case V6_RREQ:
	flags = tvb_get_guint8(tvb, offsetof(v6_rreq_t, flags));
	v6_rreq.hop_count = tvb_get_guint8(tvb, offsetof(v6_rreq_t, hop_count));
	v6_rreq.rreq_id = tvb_get_ntohl(tvb, offsetof(v6_rreq_t, rreq_id));
	v6_rreq.dest_seqno = tvb_get_ntohl(tvb, offsetof(v6_rreq_t, dest_seqno));
	v6_rreq.orig_seqno = tvb_get_ntohl(tvb, offsetof(v6_rreq_t, orig_seqno));
	tvb_memcpy(tvb, (guint8 *) & v6_rreq.dest_addr,
		   offsetof(v6_rreq_t, dest_addr), INET6_ADDRLEN);
	tvb_memcpy(tvb, (guint8 *) & v6_rreq.orig_addr,
		   offsetof(v6_rreq_t, orig_addr), INET6_ADDRLEN);

	if (tree) {
	    proto_tree_add_boolean(aodv_flags_tree,
				   hf_aodv_flags_rreq_join, tvb,
				   offsetof(v6_rreq_t, flags), 1, flags);
	    proto_tree_add_boolean(aodv_flags_tree,
				   hf_aodv_flags_rreq_repair, tvb,
				   offsetof(v6_rreq_t, flags), 1, flags);
	    proto_tree_add_boolean(aodv_flags_tree,
				   hf_aodv_flags_rreq_gratuitous, tvb,
				   offsetof(v6_rreq_t, flags), 1, flags);
	    if (flags & RREQ_JOIN)
		proto_item_append_text(tj, " J");
	    if (flags & RREQ_REP)
		proto_item_append_text(tj, " R");
	    if (flags & RREQ_GRAT)
		proto_item_append_text(tj, " G");
	    proto_tree_add_uint(aodv_tree, hf_aodv_hopcount, tvb,
				offsetof(v6_rreq_t, hop_count), 1,
				v6_rreq.hop_count);
	    proto_tree_add_uint(aodv_tree, hf_aodv_rreq_id, tvb,
				offsetof(v6_rreq_t, rreq_id), 4,
				v6_rreq.rreq_id);
	    proto_tree_add_uint(aodv_tree, hf_aodv_dest_seqno, tvb,
				offsetof(v6_rreq_t, dest_seqno), 4,
				v6_rreq.dest_seqno);
	    proto_tree_add_uint(aodv_tree, hf_aodv_orig_seqno, tvb,
				offsetof(v6_rreq_t, orig_seqno), 4,
				v6_rreq.orig_seqno);
	    proto_tree_add_ipv6(aodv_tree, hf_aodv_dest_ipv6, tvb,
				offsetof(v6_rreq_t, dest_addr),
				INET6_ADDRLEN,
				(guint8 *) & v6_rreq.dest_addr);
	    proto_tree_add_ipv6(aodv_tree, hf_aodv_orig_ipv6, tvb,
				offsetof(v6_rreq_t, orig_addr),
				INET6_ADDRLEN,
				(guint8 *) & v6_rreq.orig_addr);
	    proto_item_append_text(ti,
				   ", Dest IP: %s, Orig IP: %s, Id=%u",
				   ip6_to_str(&v6_rreq.dest_addr),
				   ip6_to_str(&v6_rreq.orig_addr),
				   v6_rreq.rreq_id);
	    extlen = ((int) tvb_reported_length(tvb) - sizeof(v6_rreq_t));
	    if (extlen > 0) {
		dissect_aodv_ext(tvb, sizeof(v6_rreq_t), aodv_tree);
	    }
	}

	if (check_col(pinfo->cinfo, COL_INFO))
	    col_add_fstr(pinfo->cinfo, COL_INFO,
			 "%s, D: %s O: %s Id=%u Hcnt=%u DSN=%u OSN=%u",
			 val_to_str(type, type_vals,
				    "Unknown AODV Packet Type (%u)"),
			 ip6_to_str(&v6_rreq.dest_addr),
			 ip6_to_str(&v6_rreq.orig_addr),
			 v6_rreq.rreq_id,
			 v6_rreq.hop_count, v6_rreq.dest_seqno, v6_rreq.orig_seqno);
	break;
    case V6_RREP:
	flags = tvb_get_guint8(tvb, offsetof(v6_rrep_t, flags));
	v6_rrep.prefix_sz = tvb_get_guint8(tvb, offsetof(v6_rrep_t, prefix_sz)) & 0x1F;
	v6_rrep.hop_count = tvb_get_guint8(tvb, offsetof(v6_rrep_t, hop_count));
	v6_rrep.dest_seqno = tvb_get_ntohl(tvb, offsetof(v6_rrep_t, dest_seqno));
	tvb_memcpy(tvb, (guint8 *) & v6_rrep.dest_addr,
		   offsetof(v6_rrep_t, dest_addr), INET6_ADDRLEN);
	tvb_memcpy(tvb, (guint8 *) & v6_rrep.orig_addr,
		   offsetof(v6_rrep_t, orig_addr), INET6_ADDRLEN);
	v6_rrep.lifetime = tvb_get_ntohl(tvb, offsetof(v6_rrep_t, lifetime));

	if (tree) {
	    proto_tree_add_boolean(aodv_flags_tree,
				   hf_aodv_flags_rrep_repair, tvb,
				   offsetof(v6_rrep_t, flags), 1, flags);
	    proto_tree_add_boolean(aodv_flags_tree,
				   hf_aodv_flags_rrep_ack, tvb,
				   offsetof(v6_rrep_t, flags), 1, flags);
	    if (flags & RREP_REP)
		proto_item_append_text(tj, " R");
	    if (flags & RREP_ACK)
		proto_item_append_text(tj, " A");
	    proto_tree_add_uint(aodv_tree, hf_aodv_prefix_sz,
				tvb, offsetof(v6_rrep_t, prefix_sz), 1,
				v6_rrep.prefix_sz);
	    proto_tree_add_uint(aodv_tree, hf_aodv_hopcount,
				tvb, offsetof(v6_rrep_t, hop_count), 1,
				v6_rrep.hop_count);
	    proto_tree_add_uint(aodv_tree, hf_aodv_dest_seqno,
				tvb, offsetof(v6_rrep_t, dest_seqno), 4,
				v6_rrep.dest_seqno);
	    proto_tree_add_ipv6(aodv_tree, hf_aodv_dest_ipv6,
				tvb, offsetof(v6_rrep_t, dest_addr),
				INET6_ADDRLEN,
				(guint8 *) & v6_rrep.dest_addr);
	    proto_tree_add_ipv6(aodv_tree, hf_aodv_orig_ipv6, tvb,
				offsetof(v6_rrep_t, orig_addr),
				INET6_ADDRLEN,
				(guint8 *) & v6_rrep.orig_addr);
	    proto_tree_add_uint(aodv_tree, hf_aodv_lifetime, tvb,
				offsetof(v6_rrep_t, lifetime), 4,
				v6_rrep.lifetime);
	    proto_item_append_text(ti,
				   ", Dest IP: %s, Orig IP: %s, Lifetime=%u",
				   ip6_to_str(&v6_rrep.dest_addr),
				   ip6_to_str(&v6_rrep.orig_addr),
				   v6_rrep.lifetime);
	    extlen = ((int) tvb_reported_length(tvb) - sizeof(v6_rrep_t));
	    if (extlen > 0) {
		dissect_aodv_ext(tvb, sizeof(v6_rrep_t), aodv_tree);
	    }
	}

	if (check_col(pinfo->cinfo, COL_INFO))
	    col_add_fstr(pinfo->cinfo, COL_INFO,
			 "%s D: %s O: %s Hcnt=%u DSN=%u Lifetime=%u",
			 val_to_str(type, type_vals,
				    "Unknown AODV Packet Type (%u)"),
			 ip6_to_str(&v6_rrep.dest_addr),
			 ip6_to_str(&v6_rrep.orig_addr),
			 v6_rrep.hop_count, v6_rrep.dest_seqno, v6_rrep.lifetime);
	break;
    case V6_RERR:
	flags = tvb_get_guint8(tvb, offsetof(v6_rerr_t, flags));
	v6_rerr.dest_count =
	    tvb_get_guint8(tvb, offsetof(v6_rerr_t, dest_count));

	if (tree) {
	    proto_tree_add_boolean(aodv_flags_tree,
				   hf_aodv_flags_rerr_nodelete, tvb,
				   offsetof(v6_rerr_t, flags), 1, flags);
	    if (flags & RERR_NODEL)
		proto_item_append_text(tj, " N");
	    proto_tree_add_uint(aodv_tree, hf_aodv_destcount, tvb,
				offsetof(v6_rerr_t, dest_count), 1,
				v6_rerr.dest_count);
	    tk = proto_tree_add_text(aodv_tree, tvb,
				     offsetof(v6_rerr_t, dest_addr),
				     (4 +
				      INET6_ADDRLEN) * v6_rerr.dest_count,
				     "Unreachable Destinations");

	    aodv_unreach_dest_tree =
		proto_item_add_subtree(tk, ett_aodv_unreach_dest);
	    for (i = 0; i < v6_rerr.dest_count; i++) {
		v6_rerr.dest_seqno =
		    tvb_get_ntohl(tvb, offsetof(v6_rerr_t, dest_seqno)
				  + (4 + INET6_ADDRLEN) * i);
		tvb_memcpy(tvb, (guint8 *) & v6_rerr.dest_addr,
			   offsetof(v6_rerr_t, dest_addr)
			   + (4 + INET6_ADDRLEN) * i, INET6_ADDRLEN);
		proto_tree_add_uint(aodv_unreach_dest_tree,
				    hf_aodv_dest_seqno, tvb,
				    offsetof(v6_rerr_t, dest_seqno)
				    + (4 + INET6_ADDRLEN) * i, 4,
				    v6_rerr.dest_seqno);
		proto_tree_add_ipv6(aodv_unreach_dest_tree,
				    hf_aodv_unreach_dest_ipv6, tvb,
				    offsetof(v6_rerr_t, dest_addr)
				    + (4 + INET6_ADDRLEN) * i,
				    INET6_ADDRLEN,
				    (guint8 *) & v6_rerr.dest_addr);
	    }
	}

	if (check_col(pinfo->cinfo, COL_INFO))
	    col_add_fstr(pinfo->cinfo, COL_INFO,
			 "%s, Dest Count=%u",
			 val_to_str(type, type_vals,
				    "Unknown AODV Packet Type (%u)"),
			 v6_rerr.dest_count);
	break;
    case V6_RREP_ACK:
	if (check_col(pinfo->cinfo, COL_INFO))
	    col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
			 val_to_str(type, type_vals,
				    "Unknown AODV Packet Type (%u)"));
	break;
    default:
	proto_tree_add_text(aodv_tree, tvb, 0,
			    1, "Unknown AODV Packet Type (%u)",
			    type);
    }

    return tvb_length(tvb);
}


/* Register the protocol with Ethereal */
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
	  { "RREQ Gratuitous", "aodv.flags.rreq_gratuitous",
	    FT_BOOLEAN, 8, TFS(&flags_set_truth), RREQ_GRAT,
	    "", HFILL }
	},
	{ &hf_aodv_flags_rrep_repair,
	  { "RREP Repair", "aodv.flags.rrep_repair",
	    FT_BOOLEAN, 8, TFS(&flags_set_truth), RREP_REP,
	    "", HFILL }
	},
	{ &hf_aodv_flags_rrep_ack,
	  { "RREP Acknowledgement", "aodv.flags.rrep_ack",
	    FT_BOOLEAN, 8, TFS(&flags_set_truth), RREP_ACK,
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
