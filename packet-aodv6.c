/* packet-aodv6.c
 * Routines for AODV6 dissection
 * Copyright 2002, Antti J. Tuominen <ajtuomin@tml.hut.fi>
 * Loosely based on packet-aodv.c.
 *
 * $Id: packet-aodv6.c,v 1.4 2002/08/22 07:32:22 guy Exp $
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

#include <string.h>
#include <glib.h>
#include <epan/int-64bit.h>
#include <epan/packet.h>
#include <epan/ipv6-utils.h>

#ifndef offsetof
#define	offsetof(type, member)	((size_t)(&((type *)0)->member))
#endif

#define INET6_ADDRLEN	16
#define UDP_PORT_AODV6	654

/* Message Types */
#define AODV6_RREQ	16
#define AODV6_RREP	17
#define AODV6_RERR	18
#define AODV6_RREP_ACK	19

/* Extension Types */
#define AODV6_EXT	1
#define AODV6_EXT_INT	2
#define AODV6_EXT_NTP	3

/* Flag bits: */
#define RREQ_GRAT    0x20
#define RREQ_REP     0x40
#define RREQ_JOIN    0x80

#define RREP_ACK     0x40
#define RREP_REP     0x80

#define RERR_NODEL   0x80

static const value_string type_vals[] = {
    {AODV6_RREQ, "Route Request"},
    {AODV6_RREP, "Route Reply"},
    {AODV6_RERR, "Route Error"},
    {AODV6_RREP_ACK, "Route Reply Acknowledgment"},
    {0, NULL}
};

static const value_string exttype_vals[] = {
    {AODV6_EXT, "None"},
    {AODV6_EXT_INT, "Hello Interval"},
    {AODV6_EXT_NTP, "Timestamp"},
    {0, NULL}
};

typedef struct aodv6_rreq {
    guint8 type;
    guint8 flags;
    guint8 res;
    guint8 hop_count;
    guint32 rreq_id;
    guint32 dest_seqno;
    guint32 orig_seqno;
    struct e_in6_addr dest_addr;
    struct e_in6_addr orig_addr;
} rreq_t;

typedef struct aodv6_rrep {
    guint8 type;
    guint8 flags;
    guint8 prefix_sz;
    guint8 hop_count;
    guint32 dest_seqno;
    struct e_in6_addr dest_addr;
    struct e_in6_addr orig_addr;
    guint32 lifetime;
} rrep_t;

typedef struct aodv6_rerr {
    guint8 type;
    guint8 flags;
    guint8 res;
    guint8 dest_count;
    guint32 dest_seqno;
    struct e_in6_addr dest_addr;
} rerr_t;

typedef struct aodv6_rrep_ack {
    guint8 type;
    guint8 res;
} rrep_ack_t;

typedef struct aodv6_ext {
    guint8 type;
    guint8 length;
} aodv6_ext_t;

/* Initialize the protocol and registered fields */
static int proto_aodv6 = -1;
static int hf_aodv6_type = -1;
static int hf_aodv6_flags = -1;
static int hf_aodv6_prefix_sz = -1;
static int hf_aodv6_hopcount = -1;
static int hf_aodv6_rreq_id = -1;
static int hf_aodv6_dest_ip = -1;
static int hf_aodv6_dest_seqno = -1;
static int hf_aodv6_orig_ip = -1;
static int hf_aodv6_orig_seqno = -1;
static int hf_aodv6_lifetime = -1;
static int hf_aodv6_destcount = -1;
static int hf_aodv6_unreach_dest_ip = -1;
static int hf_aodv6_unreach_dest_seqno = -1;
static int hf_aodv6_flags_rreq_join = -1;
static int hf_aodv6_flags_rreq_repair = -1;
static int hf_aodv6_flags_rreq_gratuitous = -1;
static int hf_aodv6_flags_rrep_repair = -1;
static int hf_aodv6_flags_rrep_ack = -1;
static int hf_aodv6_flags_rerr_nodelete = -1;
static int hf_aodv6_ext_type = -1;
static int hf_aodv6_ext_length = -1;
static int hf_aodv6_ext_interval = -1;
static int hf_aodv6_ext_timestamp = -1;

/* Initialize the subtree pointers */
static gint ett_aodv6 = -1;
static gint ett_aodv6_flags = -1;
static gint ett_aodv6_unreach_dest = -1;
static gint ett_aodv6_extensions = -1;


static void
dissect_aodv6ext(tvbuff_t * tvb, int offset, proto_tree * tree)
{
    proto_tree *aodv6ext_tree;
    proto_item *ti;
    aodv6_ext_t aodv6ext, *ext;
    char *typename;
    int len;

    if (!tree)
	return;

  again:
    if ((int) tvb_reported_length(tvb) <= offset)
	return;			/* No more options left */

    ext = &aodv6ext;
    tvb_memcpy(tvb, (guint8 *) ext, offset, sizeof(*ext));
    len = ext->length;

    ti = proto_tree_add_text(tree, tvb, offset, sizeof(aodv6_ext_t) +
			     len, "AODV6 Extensions");
    aodv6ext_tree = proto_item_add_subtree(ti, ett_aodv6_extensions);

    if (len == 0) {
	proto_tree_add_text(aodv6ext_tree, tvb,
			    offset + offsetof(aodv6_ext_t, length), 1,
			    "Invalid option length: %u", ext->length);
	return;			/* we must not try to decode this */
    }

    switch (ext->type) {
    case AODV6_EXT_INT:
	typename = "Hello Interval";
	break;
    case AODV6_EXT_NTP:
	typename = "Timestamp";
	break;
    default:
	typename = "Unknown";
	break;
    }
    proto_tree_add_text(aodv6ext_tree, tvb,
			offset + offsetof(aodv6_ext_t, type), 1,
			"Type: %u (%s)", ext->type, typename);
    proto_tree_add_text(aodv6ext_tree, tvb,
			offset + offsetof(aodv6_ext_t, length), 1,
			"Length: %u bytes", ext->length);

    offset += sizeof(aodv6_ext_t);

    switch (ext->type) {
    case AODV6_EXT_INT:
	proto_tree_add_uint(aodv6ext_tree, hf_aodv6_ext_interval,
			    tvb, offset, 4, tvb_get_ntohl(tvb, offset));
	break;
    case AODV6_EXT_NTP:
	proto_tree_add_item(aodv6ext_tree, hf_aodv6_ext_timestamp,
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
dissect_aodv6(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
    proto_item *ti = NULL, *tj = NULL, *tk = NULL;
    proto_tree *aodv6_tree = NULL, *aodv6_flags_tree = NULL,
	*aodv6_unreach_dest_tree = NULL;
    guint8 type;
    int i, extlen;
    rreq_t rreq;
    rrep_t rrep;
    rerr_t rerr;

    /* Make entries in Protocol column and Info column on summary
     * display 
     */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "AODV6");

    if (check_col(pinfo->cinfo, COL_INFO))
	col_clear(pinfo->cinfo, COL_INFO);

    /* Check the type of AODV6 packet. */
    type = tvb_get_guint8(tvb, 0);
    if (type < AODV6_RREQ || type > AODV6_RREP_ACK) {
	return 0;		/* don't process */
    }

    if (tree) {
	ti = proto_tree_add_protocol_format(tree, proto_aodv6, tvb, 0, -1,
					    "Ad hoc On-demand Distance Vector v6, %s",
					    val_to_str(type, type_vals,
						       "Unknown AODV6 Packet Type (%u)"));
	aodv6_tree = proto_item_add_subtree(ti, ett_aodv6);

	proto_tree_add_uint(aodv6_tree, hf_aodv6_type, tvb, 0, 1, type);
	tj = proto_tree_add_text(aodv6_tree, tvb, 1, 1, "Flags:");
	aodv6_flags_tree = proto_item_add_subtree(tj, ett_aodv6_flags);
    }


    switch (type) {
    case AODV6_RREQ:
	rreq.type = type;
	rreq.flags = tvb_get_guint8(tvb, offsetof(rreq_t, flags));
	rreq.hop_count = tvb_get_guint8(tvb, offsetof(rreq_t, hop_count));
	rreq.rreq_id = tvb_get_ntohl(tvb, offsetof(rreq_t, rreq_id));
	rreq.dest_seqno = tvb_get_ntohl(tvb, offsetof(rreq_t, dest_seqno));
	rreq.orig_seqno = tvb_get_ntohl(tvb, offsetof(rreq_t, orig_seqno));
	tvb_memcpy(tvb, (guint8 *) & rreq.dest_addr,
		   offsetof(rreq_t, dest_addr), INET6_ADDRLEN);
	tvb_memcpy(tvb, (guint8 *) & rreq.orig_addr,
		   offsetof(rreq_t, orig_addr), INET6_ADDRLEN);

	if (tree) {
	    proto_tree_add_boolean(aodv6_flags_tree,
				   hf_aodv6_flags_rreq_join, tvb,
				   offsetof(rreq_t, flags), 1, rreq.flags);
	    proto_tree_add_boolean(aodv6_flags_tree,
				   hf_aodv6_flags_rreq_repair, tvb,
				   offsetof(rreq_t, flags), 1, rreq.flags);
	    proto_tree_add_boolean(aodv6_flags_tree,
				   hf_aodv6_flags_rreq_gratuitous, tvb,
				   offsetof(rreq_t, flags), 1, rreq.flags);
	    if (rreq.flags & RREQ_JOIN)
		proto_item_append_text(tj, " J");
	    if (rreq.flags & RREQ_REP)
		proto_item_append_text(tj, " R");
	    if (rreq.flags & RREQ_GRAT)
		proto_item_append_text(tj, " G");
	    proto_tree_add_uint(aodv6_tree, hf_aodv6_hopcount, tvb,
				offsetof(rreq_t, hop_count), 1,
				rreq.hop_count);
	    proto_tree_add_uint(aodv6_tree, hf_aodv6_rreq_id, tvb,
				offsetof(rreq_t, rreq_id), 4,
				rreq.rreq_id);
	    proto_tree_add_uint(aodv6_tree, hf_aodv6_dest_seqno, tvb,
				offsetof(rreq_t, dest_seqno), 4,
				rreq.dest_seqno);
	    proto_tree_add_uint(aodv6_tree, hf_aodv6_orig_seqno, tvb,
				offsetof(rreq_t, orig_seqno), 4,
				rreq.orig_seqno);
	    proto_tree_add_ipv6(aodv6_tree, hf_aodv6_dest_ip, tvb,
				offsetof(rreq_t, dest_addr),
				INET6_ADDRLEN,
				(guint8 *) & rreq.dest_addr);
	    proto_tree_add_ipv6(aodv6_tree, hf_aodv6_orig_ip, tvb,
				offsetof(rreq_t, orig_addr),
				INET6_ADDRLEN,
				(guint8 *) & rreq.orig_addr);
	    proto_item_append_text(ti,
				   ", Dest IP: %s, Orig IP: %s, Id=%u",
				   ip6_to_str(&rreq.dest_addr),
				   ip6_to_str(&rreq.orig_addr),
				   rreq.rreq_id);
	    extlen = ((int) tvb_reported_length(tvb) - sizeof(rreq_t));
	    if (extlen > 0) {
		dissect_aodv6ext(tvb, sizeof(rreq_t), aodv6_tree);
	    }
	}

	if (check_col(pinfo->cinfo, COL_INFO))
	    col_add_fstr(pinfo->cinfo, COL_INFO,
			 "%s, D: %s O: %s Id=%u Hcnt=%u DSN=%u OSN=%u",
			 val_to_str(type, type_vals,
				    "Unknown AODV6 Packet Type (%u)"),
			 ip6_to_str(&rreq.dest_addr),
			 ip6_to_str(&rreq.orig_addr),
			 rreq.rreq_id,
			 rreq.hop_count, rreq.dest_seqno, rreq.orig_seqno);
	break;
    case AODV6_RREP:
	rrep.type = type;
	rrep.flags = tvb_get_guint8(tvb, offsetof(rrep_t, flags));
	rrep.prefix_sz = tvb_get_guint8(tvb, offsetof(rrep_t, prefix_sz)) & 0x1F;
	rrep.hop_count = tvb_get_guint8(tvb, offsetof(rrep_t, hop_count));
	rrep.dest_seqno = tvb_get_ntohl(tvb, offsetof(rrep_t, dest_seqno));
	tvb_memcpy(tvb, (guint8 *) & rrep.dest_addr,
		   offsetof(rrep_t, dest_addr), INET6_ADDRLEN);
	tvb_memcpy(tvb, (guint8 *) & rrep.orig_addr,
		   offsetof(rrep_t, orig_addr), INET6_ADDRLEN);
	rrep.lifetime = tvb_get_ntohl(tvb, offsetof(rrep_t, lifetime));

	if (tree) {
	    proto_tree_add_boolean(aodv6_flags_tree,
				   hf_aodv6_flags_rrep_repair, tvb,
				   offsetof(rrep_t, flags), 1, rrep.flags);
	    proto_tree_add_boolean(aodv6_flags_tree,
				   hf_aodv6_flags_rrep_ack, tvb,
				   offsetof(rrep_t, flags), 1, rrep.flags);
	    if (rrep.flags & RREP_REP)
		proto_item_append_text(tj, " R");
	    if (rrep.flags & RREP_ACK)
		proto_item_append_text(tj, " A");
	    proto_tree_add_uint(aodv6_tree, hf_aodv6_prefix_sz,
				tvb, offsetof(rrep_t, prefix_sz), 1,
				rrep.prefix_sz);
	    proto_tree_add_uint(aodv6_tree, hf_aodv6_hopcount,
				tvb, offsetof(rrep_t, hop_count), 1,
				rrep.hop_count);
	    proto_tree_add_uint(aodv6_tree, hf_aodv6_dest_seqno,
				tvb, offsetof(rrep_t, dest_seqno), 4,
				rrep.dest_seqno);
	    proto_tree_add_ipv6(aodv6_tree, hf_aodv6_dest_ip,
				tvb, offsetof(rrep_t, dest_addr),
				INET6_ADDRLEN,
				(guint8 *) & rrep.dest_addr);
	    proto_tree_add_ipv6(aodv6_tree, hf_aodv6_orig_ip, tvb,
				offsetof(rrep_t, orig_addr),
				INET6_ADDRLEN,
				(guint8 *) & rrep.orig_addr);
	    proto_tree_add_uint(aodv6_tree, hf_aodv6_lifetime, tvb,
				offsetof(rrep_t, lifetime), 4,
				rrep.lifetime);
	    proto_item_append_text(ti,
				   ", Dest IP: %s, Orig IP: %s, Lifetime=%u",
				   ip6_to_str(&rrep.dest_addr),
				   ip6_to_str(&rrep.orig_addr),
				   rrep.lifetime);
	    extlen = ((int) tvb_reported_length(tvb) - sizeof(rrep_t));
	    if (extlen > 0) {
		dissect_aodv6ext(tvb, sizeof(rrep_t), aodv6_tree);
	    }
	}

	if (check_col(pinfo->cinfo, COL_INFO))
	    col_add_fstr(pinfo->cinfo, COL_INFO,
			 "%s D: %s O: %s Hcnt=%u DSN=%u Lifetime=%u",
			 val_to_str(type, type_vals,
				    "Unknown AODV6 Packet Type (%u)"),
			 ip6_to_str(&rrep.dest_addr),
			 ip6_to_str(&rrep.orig_addr),
			 rrep.hop_count, rrep.dest_seqno, rrep.lifetime);
	break;
    case AODV6_RERR:
	rerr.type = type;
	rerr.flags = tvb_get_guint8(tvb, offsetof(rerr_t, flags));
	rerr.dest_count =
	    tvb_get_guint8(tvb, offsetof(rerr_t, dest_count));

	if (tree) {
	    proto_tree_add_boolean(aodv6_flags_tree,
				   hf_aodv6_flags_rerr_nodelete, tvb,
				   offsetof(rerr_t, flags), 1, rerr.flags);
	    if (rerr.flags & RERR_NODEL)
		proto_item_append_text(tj, " N");
	    proto_tree_add_uint(aodv6_tree, hf_aodv6_destcount, tvb,
				offsetof(rerr_t, dest_count), 1,
				rerr.dest_count);
	    tk = proto_tree_add_text(aodv6_tree, tvb,
				     offsetof(rerr_t, dest_addr),
				     (4 +
				      INET6_ADDRLEN) * rerr.dest_count,
				     "Unreachable Destinations");

	    aodv6_unreach_dest_tree =
		proto_item_add_subtree(tk, ett_aodv6_unreach_dest);
	    for (i = 0; i < rerr.dest_count; i++) {
		rerr.dest_seqno =
		    tvb_get_ntohl(tvb, offsetof(rerr_t, dest_seqno)
				  + (4 + INET6_ADDRLEN) * i);
		tvb_memcpy(tvb, (guint8 *) & rerr.dest_addr,
			   offsetof(rerr_t, dest_addr)
			   + (4 + INET6_ADDRLEN) * i, INET6_ADDRLEN);
		proto_tree_add_uint(aodv6_unreach_dest_tree,
				    hf_aodv6_dest_seqno, tvb,
				    offsetof(rerr_t, dest_seqno)
				    + (4 + INET6_ADDRLEN) * i, 4,
				    rerr.dest_seqno);
		proto_tree_add_ipv6(aodv6_unreach_dest_tree,
				    hf_aodv6_dest_ip, tvb,
				    offsetof(rerr_t, dest_addr)
				    + (4 + INET6_ADDRLEN) * i,
				    INET6_ADDRLEN,
				    (guint8 *) & rerr.dest_addr);
	    }
	}

	if (check_col(pinfo->cinfo, COL_INFO))
	    col_add_fstr(pinfo->cinfo, COL_INFO,
			 "%s, Dest Count=%u",
			 val_to_str(type, type_vals,
				    "Unknown AODV6 Packet Type (%u)"),
			 rerr.dest_count);
	break;
    case AODV6_RREP_ACK:
	if (check_col(pinfo->cinfo, COL_INFO))
	    col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
			 val_to_str(type, type_vals,
				    "Unknown AODV6 Packet Type (%u)"));
	break;
    default:
	proto_tree_add_text(aodv6_tree, tvb, 0, 1,
			    "Unknown AODV6 Packet Type (%u)", type);
    }

    return tvb_length(tvb);
}

/* Register the protocol with Ethereal */
void
proto_register_aodv6(void)
{
    static hf_register_info hf[] = {
	{&hf_aodv6_type,
	 {"Type", "aodv6.type",
	  FT_UINT8, BASE_DEC, VALS(type_vals), 0x0,
	  "AODV6 packet type", HFILL}
	 },
	{&hf_aodv6_flags,
	 {"Flags", "aodv6.flags",
	  FT_UINT16, BASE_DEC, NULL, 0x0,
	  "Flags", HFILL}
	 },
	{&hf_aodv6_flags_rreq_join,
	 {"RREQ Join", "aodv6.flags.rreq_join",
	  FT_BOOLEAN, 8, TFS(&flags_set_truth), RREQ_JOIN,
	  "", HFILL}
	 },
	{&hf_aodv6_flags_rreq_repair,
	 {"RREQ Repair", "aodv6.flags.rreq_repair",
	  FT_BOOLEAN, 8, TFS(&flags_set_truth), RREQ_REP,
	  "", HFILL}
	 },
	{&hf_aodv6_flags_rreq_gratuitous,
	 {"RREQ Gratuitous", "aodv6.flags.rreq_gratuitous",
	  FT_BOOLEAN, 8, TFS(&flags_set_truth), RREQ_GRAT,
	  "", HFILL}
	 },
	{&hf_aodv6_flags_rrep_repair,
	 {"RREP Repair", "aodv6.flags.rrep_repair",
	  FT_BOOLEAN, 8, TFS(&flags_set_truth), RREP_REP,
	  "", HFILL}
	 },
	{&hf_aodv6_flags_rrep_ack,
	 {"RREP Acknowledgment", "aodv6.flags.rrep_ack",
	  FT_BOOLEAN, 8, TFS(&flags_set_truth), RREP_ACK,
	  "", HFILL}
	 },
	{&hf_aodv6_flags_rerr_nodelete,
	 {"RERR No Delete", "aodv6.flags.rerr_nodelete",
	  FT_BOOLEAN, 8, TFS(&flags_set_truth), RERR_NODEL,
	  "", HFILL}
	 },
	{&hf_aodv6_prefix_sz,
	 {"Prefix Size", "aodv6.prefix_sz",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  "Prefix Size", HFILL}
	 },
	{&hf_aodv6_hopcount,
	 {"Hop Count", "aodv6.hopcount",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  "Hop Count", HFILL}
	 },
	{&hf_aodv6_rreq_id,
	 {"RREQ ID", "aodv6.rreq_id",
	  FT_UINT32, BASE_DEC, NULL, 0x0,
	  "RREQ ID", HFILL}
	 },
	{&hf_aodv6_dest_seqno,
	 {"Destination Sequence Number", "aodv6.dest_seqno",
	  FT_UINT32, BASE_DEC, NULL, 0x0,
	  "Destination Sequence Number", HFILL}
	 },
	{&hf_aodv6_orig_seqno,
	 {"Originator Sequence Number", "aodv6.orig_seqno",
	  FT_UINT32, BASE_DEC, NULL, 0x0,
	  "Originator Sequence Number", HFILL}
	 },
	{&hf_aodv6_dest_ip,
	 {"Destination IP", "aodv6.dest_ip",
	  FT_IPv6, BASE_DEC, NULL, 0x0,
	  "Destination IP Address", HFILL}
	 },
	{&hf_aodv6_orig_ip,
	 {"Originator IP", "aodv6.orig_ip",
	  FT_IPv6, BASE_DEC, NULL, 0x0,
	  "Originator IP Address", HFILL}
	 },
	{&hf_aodv6_lifetime,
	 {"Lifetime", "aodv6.lifetime",
	  FT_UINT32, BASE_DEC, NULL, 0x0,
	  "Lifetime", HFILL}
	 },
	{&hf_aodv6_destcount,
	 {"Destination Count", "aodv6.destcount",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  "Unreachable Destinations Count", HFILL}
	 },
	{&hf_aodv6_unreach_dest_seqno,
	 {"Unreachable Destination Sequence Number",
	  "aodv6.unreach_dest_seqno",
	  FT_UINT32, BASE_DEC, NULL, 0x0,
	  "Unreachable Destination Sequence Number", HFILL}
	 },
	{&hf_aodv6_unreach_dest_ip,
	 {"Unreachable Destination IP", "aodv6.unreach_dest_ip",
	  FT_IPv6, BASE_DEC, NULL, 0x0,
	  "Unreachable Destination  IP Address", HFILL}
	 },
	{&hf_aodv6_ext_type,
	 {"Extension Type", "aodv6.ext_type",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  "Extension Format Type", HFILL}
	 },
	{&hf_aodv6_ext_length,
	 {"Extension Length", "aodv6.ext_length",
	  FT_UINT8, BASE_DEC, NULL, 0x0,
	  "Extension Data Length", HFILL}
	 },
	{&hf_aodv6_ext_interval,
	 {"Hello Interval", "aodv6.hello_interval",
	  FT_UINT32, BASE_DEC, NULL, 0x0,
	  "Hello Interval Extension", HFILL}
	 },
	{&hf_aodv6_ext_timestamp,
	 {"Timestamp", "aodv6.timestamp",
	  FT_UINT64, BASE_DEC, NULL, 0x0,
	  "Timestamp Extension", HFILL}
	 },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
	&ett_aodv6,
	&ett_aodv6_flags,
	&ett_aodv6_unreach_dest,
	&ett_aodv6_extensions,
    };

    /* Register the protocol name and description */
    proto_aodv6 =
	proto_register_protocol
	("Ad hoc On-demand Distance Vector Routing Protocol v6", "AODV6",
	 "aodv6");

    /* Required function calls to register the header fields and
     * subtrees
     */
    proto_register_field_array(proto_aodv6, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_aodv6(void)
{
    dissector_handle_t aodv6_handle;

    aodv6_handle = new_create_dissector_handle(dissect_aodv6, proto_aodv6);
    dissector_add("udp.port", UDP_PORT_AODV6, aodv6_handle);
}
