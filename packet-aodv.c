/* packet-aodv.c
 * Routines for AODV dissection
 * Copyright 2000, Erik Nordström <erik.nordstrom@it.uu.se>
 *
 * $Id: packet-aodv.c,v 1.3 2002/08/02 23:35:47 jmayer Exp $
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>

#define UDP_PORT_AODV 654

#define RREQ 1
#define RREP 2
#define RERR 3

/* Flag bits: */
#define RREQ_GRAT    0x20
#define RREQ_REP     0x40
#define RREQ_JOIN    0x80

#define RREP_ACK     0x40
#define RREP_REP     0x80

#define RERR_NODEL   0x80

static const true_false_string flags_set_truth = {
    "Set",
    "Not set"
};

static const value_string type_vals[] = {
    { RREQ, "RREQ" },
    { RREP, "RREP" },
    { RERR, "RERR" },
    { 0, NULL }
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
    guint8 res2:3;
    guint8 prefix:5;
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

static struct aodv_rreq rreq;
static struct aodv_rrep rrep;
static struct aodv_rerr rerr;
		    
/* Initialize the protocol and registered fields */
static int proto_aodv = -1;
static int hf_aodv_type = -1;
static int hf_aodv_flags = -1;
static int hf_aodv_hopcount = -1;
static int hf_aodv_rreq_id = -1;
static int hf_aodv_dest_ip = -1;
static int hf_aodv_dest_seqno = -1;
static int hf_aodv_orig_ip = -1;
static int hf_aodv_orig_seqno = -1;
static int hf_aodv_lifetime = -1;
static int hf_aodv_destcount = -1;
static int hf_aodv_unreach_dest_ip = -1;
static int hf_aodv_unreach_dest_seqno = -1;
static int hf_aodv_flags_rreq_join = -1;
static int hf_aodv_flags_rreq_repair = -1;
static int hf_aodv_flags_rreq_gratuitous = -1;
static int hf_aodv_flags_rrep_repair = -1;
static int hf_aodv_flags_rrep_ack = -1;
static int hf_aodv_flags_rerr_nodelete = -1;

/* Initialize the subtree pointers */
static gint ett_aodv = -1;
static gint ett_aodv_flags = -1;
static gint ett_aodv_unreach_dest = -1;

/* Code to actually dissect the packets */
static int
dissect_aodv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti = NULL, *tj = NULL, *tk = NULL;
    proto_tree *aodv_tree = NULL, *aodv_flags_tree = NULL, 
	*aodv_unreach_dest_tree = NULL;
    guint8 type;
    int i;

/* Make entries in Protocol column and Info column on summary display */
    if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "AODV");

    if (check_col(pinfo->cinfo, COL_INFO)) 
	col_clear(pinfo->cinfo, COL_INFO);
	
    /* Check the type of AODV packet. */
    type = tvb_get_guint8(tvb, 0);
    if (type < 1 || type > 3) {
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
	rreq.type = type;
	rreq.flags = tvb_get_guint8(tvb, 1);
	rreq.hop_count = tvb_get_guint8(tvb, 3);
	rreq.rreq_id = tvb_get_ntohl(tvb, 4);
	tvb_memcpy(tvb, (guint8 *)&rreq.dest_addr, 8, 4);
	rreq.dest_seqno = tvb_get_ntohl(tvb, 12);
	tvb_memcpy(tvb, (guint8 *)&rreq.orig_addr, 16, 4);
	rreq.orig_seqno = tvb_get_ntohl(tvb, 20);
	    
	if (tree) {
	    proto_tree_add_boolean(aodv_flags_tree, hf_aodv_flags_rreq_join, tvb, 1, 1, rreq.flags);
	    proto_tree_add_boolean(aodv_flags_tree, hf_aodv_flags_rreq_repair, tvb, 1, 1, rreq.flags);
	    proto_tree_add_boolean(aodv_flags_tree, hf_aodv_flags_rreq_gratuitous, tvb, 1, 1, rreq.flags);
	    if (rreq.flags & RREQ_JOIN)
		proto_item_append_text(tj, " J");
	    if (rreq.flags & RREQ_REP)
		proto_item_append_text(tj, " R");
	    if (rreq.flags & RREQ_GRAT)
		proto_item_append_text(tj, " G");
	    proto_tree_add_uint(aodv_tree, hf_aodv_hopcount, tvb, 3, 1, rreq.hop_count);
	    proto_tree_add_uint(aodv_tree, hf_aodv_rreq_id, tvb, 4, 4, rreq.rreq_id);
	    proto_tree_add_ipv4(aodv_tree, hf_aodv_dest_ip, tvb, 8, 4, rreq.dest_addr);
	    proto_tree_add_uint(aodv_tree, hf_aodv_dest_seqno, tvb, 12, 4, rreq.dest_seqno);
	    proto_tree_add_ipv4(aodv_tree, hf_aodv_orig_ip, tvb, 16, 4, rreq.orig_addr);
	    proto_tree_add_uint(aodv_tree, hf_aodv_orig_seqno, tvb, 20, 4, rreq.orig_seqno);
	    proto_item_append_text(ti, ", Dest IP: %s, Orig IP: %s, Id=%u", ip_to_str(tvb_get_ptr(tvb, 8, 4)), ip_to_str(tvb_get_ptr(tvb, 16, 4)), rreq.rreq_id);
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
	rrep.type = type;
	rrep.flags = tvb_get_guint8(tvb, 1);
	rrep.hop_count = tvb_get_guint8(tvb, 3);
	tvb_memcpy(tvb, (guint8 *)&rrep.dest_addr, 4, 4);
	rrep.dest_seqno = tvb_get_ntohl(tvb, 8);
	tvb_memcpy(tvb, (guint8 *)&rrep.orig_addr, 12, 4);
	rrep.lifetime = tvb_get_ntohl(tvb, 16);

	if (tree) {
	    proto_tree_add_boolean(aodv_flags_tree, hf_aodv_flags_rrep_repair, tvb, 1, 1, rrep.flags);
	    proto_tree_add_boolean(aodv_flags_tree, hf_aodv_flags_rrep_ack, tvb, 1, 1, rrep.flags);
	    if (rrep.flags & RREP_REP)
		proto_item_append_text(tj, " R");
	    if (rrep.flags & RREP_ACK)
		proto_item_append_text(tj, " A");
	    proto_tree_add_uint(aodv_tree, hf_aodv_hopcount, tvb, 3, 1, rrep.hop_count);
	    proto_tree_add_ipv4(aodv_tree, hf_aodv_dest_ip, tvb, 4, 4, rrep.dest_addr);
	    proto_tree_add_uint(aodv_tree, hf_aodv_dest_seqno, tvb, 8, 4, rrep.dest_seqno);
	    proto_tree_add_ipv4(aodv_tree, hf_aodv_orig_ip, tvb, 12, 4, rrep.orig_addr);
	    proto_tree_add_uint(aodv_tree, hf_aodv_lifetime, tvb, 16, 4, rrep.lifetime);
	    proto_item_append_text(ti, ", Dest IP: %s, Orig IP: %s, Lifetime=%u", ip_to_str(tvb_get_ptr(tvb, 4, 4)), ip_to_str(tvb_get_ptr(tvb, 12, 4)), rrep.lifetime);
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
	rerr.type = type;
	rerr.flags = tvb_get_guint8(tvb, 1);
	rerr.dest_count = tvb_get_guint8(tvb, 3);
		    
	if (tree) {
	    proto_tree_add_boolean(aodv_flags_tree, hf_aodv_flags_rerr_nodelete, tvb, 1, 1, rerr.flags);
	    if (rerr.flags & RERR_NODEL)
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
	    FT_IPv4, BASE_DEC, NULL, 0x0,    
	    "Destination IP Address", HFILL }
	},
	{ &hf_aodv_dest_seqno,
	  { "Destination Sequence Number", "aodv.dest_seqno",
	    FT_UINT32, BASE_DEC, NULL, 0x0,    
	    "Destination Sequence Number", HFILL }
	},
	{ &hf_aodv_orig_ip,
	  { "Originator IP", "aodv.orig_ip",
	    FT_IPv4, BASE_DEC, NULL, 0x0,    
	    "Originator IP Address", HFILL }
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
	    FT_IPv4, BASE_DEC, NULL, 0x0,    
	    "Unreachable Destination  IP Address", HFILL }
	},
	{ &hf_aodv_unreach_dest_seqno,
	  { "Unreachable Destination Sequence Number", "aodv.unreach_dest_seqno",
	    FT_UINT32, BASE_DEC, NULL, 0x0,    
	    "Unreachable Destination Sequence Number", HFILL }
	},
    };

/* Setup protocol subtree array */
    static gint *ett[] = {
	&ett_aodv,
	&ett_aodv_flags,
	&ett_aodv_unreach_dest,
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
