/* packet-ospf.c
 * Routines for OSPF packet disassembly
 * (c) Copyright Hannes R. Boehm <hannes@boehm.org>
 *
 * $Id: packet-ospf.c,v 1.34 2001/01/03 16:41:07 gram Exp $
 *
 * At this time, this module is able to analyze OSPF
 * packets as specified in RFC2328. MOSPF (RFC1584) and other
 * OSPF Extensions which introduce new Packet types
 * (e.g the External Atributes LSA) are not supported.
 *
 * TOS - support is not fully implemented
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

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <stdio.h>
#include <string.h>

#include <glib.h>
#include "packet.h"
#include "packet-ip.h"
#include "in_cksum.h"
#include "ieee-float.h"

#define OSPF_HEADER_LENGTH	24

#define OSPF_HELLO	1
#define OSPF_DB_DESC	2
#define OSPF_LS_REQ	3
#define OSPF_LS_UPD	4
#define OSPF_LS_ACK	5

static const value_string pt_vals[] = {
	{OSPF_HELLO,   "Hello Packet"   },
	{OSPF_DB_DESC, "DB Descr."      },
	{OSPF_LS_REQ,  "LS Request"     },
	{OSPF_LS_UPD,  "LS Update"      },
	{OSPF_LS_ACK,  "LS Acknowledge" },
	{0,             NULL            }
};

#define OSPF_AUTH_NONE		0
#define OSPF_AUTH_SIMPLE	1
#define OSPF_AUTH_CRYPT		2

static const value_string auth_vals[] = {
	{OSPF_AUTH_NONE,   "Null"            },
	{OSPF_AUTH_SIMPLE, "Simple password" },
	{OSPF_AUTH_CRYPT,  "Cryptographic"   },
	{0,                NULL              }
};

#define OSPF_OPTIONS_E		0x02
#define OSPF_OPTIONS_MC		0x04
#define OSPF_OPTIONS_NP		0x08
#define OSPF_OPTIONS_EA		0x10
#define OSPF_OPTIONS_DC		0x20

#define OSPF_DBD_FLAG_MS	1
#define OSPF_DBD_FLAG_M		2
#define OSPF_DBD_FLAG_I		4

#define OSPF_LS_REQ_LENGTH	12

#define OSPF_LSTYPE_ROUTER	1
#define OSPF_LSTYPE_NETWORK	2
#define OSPF_LSTYPE_SUMMERY	3
#define OSPF_LSTYPE_ASBR	4
#define OSPF_LSTYPE_ASEXT	5
#define OSPF_LSTYPE_ASEXT7	7

/* Opaque LSA types */
#define OSPF_LSTYPE_OP_LINKLOCAL 9
#define OSPF_LSTYPE_OP_AREALOCAL 10
#define OSPF_LSTYPE_OP_ASWIDE    11

#define OSPF_LINK_PTP		1
#define OSPF_LINK_TRANSIT	2
#define OSPF_LINK_STUB		3
#define OSPF_LINK_VIRTUAL	4

#define OSPF_LSA_HEADER_LENGTH	20

/* Known opaque LSAs */
#define OSPF_LSA_MPLS_TE        1

static const value_string ls_type_vals[] = {
	{OSPF_LSTYPE_ROUTER,  "Router-LSA"               },
	{OSPF_LSTYPE_NETWORK, "Network-LSA"              },
	{OSPF_LSTYPE_SUMMERY, "Summary-LSA (IP network)" },
	{OSPF_LSTYPE_ASBR,    "Summary-LSA (ASBR)"       },
	{OSPF_LSTYPE_ASEXT,   "AS-External-LSA (ASBR)"   },
	{0,                    NULL                      }
};

static int proto_ospf = -1;

static gint ett_ospf = -1;
static gint ett_ospf_hdr = -1;
static gint ett_ospf_hello = -1;
static gint ett_ospf_desc = -1;
static gint ett_ospf_lsr = -1;
static gint ett_ospf_lsa = -1;
static gint ett_ospf_lsa_upd = -1;

/* Trees for opaque LSAs */
static gint ett_ospf_lsa_mpls = -1;
static gint ett_ospf_lsa_mpls_router = -1;
static gint ett_ospf_lsa_mpls_link = -1;
static gint ett_ospf_lsa_mpls_link_stlv = -1;

static void dissect_ospf_hello(tvbuff_t*, int, proto_tree*);
static void dissect_ospf_db_desc(tvbuff_t*, int, proto_tree*); 
static void dissect_ospf_ls_req(tvbuff_t*, int, proto_tree*); 
static void dissect_ospf_ls_upd(tvbuff_t*, int, proto_tree*); 
static void dissect_ospf_ls_ack(tvbuff_t*, int, proto_tree*); 

/* dissect_ospf_lsa returns the offset of the next LSA
 * if disassemble_body is set to FALSE (e.g. in LSA ACK 
 * packets), the offset is set to the offset of the next
 * LSA header
 */
static int dissect_ospf_lsa(tvbuff_t*, int, proto_tree*, gboolean disassemble_body); 

static void dissect_ospf_options(tvbuff_t *, int, proto_tree *);

static void 
dissect_ospf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *ospf_tree = NULL;
    proto_item *ti; 
    proto_tree *ospf_header_tree;
    guint8  version;
    guint8  packet_type;
    guint16 ospflen;
    vec_t cksum_vec[2];
    int cksum_vec_len;
    guint16 cksum, computed_cksum;
    guint length, reported_length;
    guint16 auth_type;
    char auth_data[8];
    int crypto_len;
 
    CHECK_DISPLAY_AS_DATA(proto_ospf, tvb, pinfo, tree);

    pinfo->current_proto = "OSPF";

    version = tvb_get_guint8(tvb, 0);
    packet_type = tvb_get_guint8(tvb, 1);
    if (check_col(pinfo->fd, COL_PROTOCOL))
	col_set_str(pinfo->fd, COL_PROTOCOL, "OSPF");
    if (check_col(pinfo->fd, COL_INFO)) {
	col_add_str(pinfo->fd, COL_INFO,
		    val_to_str(packet_type, pt_vals, "Unknown (%u)"));
    }  

    if (tree) {
	ospflen = tvb_get_ntohs(tvb, 2);

	ti = proto_tree_add_item(tree, proto_ospf, tvb, 0, ospflen, FALSE);
	ospf_tree = proto_item_add_subtree(ti, ett_ospf);

	ti = proto_tree_add_text(ospf_tree, tvb, 0, OSPF_HEADER_LENGTH,
				 "OSPF Header"); 
	ospf_header_tree = proto_item_add_subtree(ti, ett_ospf_hdr);

        proto_tree_add_text(ospf_header_tree, tvb, 0, 1, "OSPF Version: %u",
			    version);  
	proto_tree_add_text(ospf_header_tree, tvb, 1, 1, "OSPF Packet Type: %u (%s)",
			    packet_type,
			    val_to_str(packet_type, pt_vals, "Unknown"));
	proto_tree_add_text(ospf_header_tree, tvb, 2, 2, "Packet Length: %u",
			    ospflen);
	proto_tree_add_text(ospf_header_tree, tvb, 4, 4, "Source OSPF Router ID: %s",
			    ip_to_str(tvb_get_ptr(tvb, 4, 4)));
	if (tvb_get_ntohl(tvb, 8) == 0) {
	   proto_tree_add_text(ospf_header_tree, tvb, 8, 4, "Area ID: Backbone");
	} else {
	   proto_tree_add_text(ospf_header_tree, tvb, 8, 4, "Area ID: %s",
			       ip_to_str(tvb_get_ptr(tvb, 8, 4)));
	}
	cksum = tvb_get_ntohs(tvb, 12);
	length = tvb_length(tvb);
	/* XXX - include only the length from the OSPF header? */
	reported_length = tvb_reported_length(tvb);
	if (!pi.fragmented && length >= reported_length
		&& length >= OSPF_HEADER_LENGTH) {
	    /* The packet isn't part of a fragmented datagram and isn't
	       truncated, so we can checksum it. */

	    /* Header, not including the authentication data (the OSPF
	       checksum excludes the 64-bit authentication field). */
	    cksum_vec[0].ptr = tvb_get_ptr(tvb, 0, 16);
	    cksum_vec[0].len = 16;
	    if (length > OSPF_HEADER_LENGTH) {
		/* Rest of the packet, again not including the
		   authentication data. */
		reported_length -= OSPF_HEADER_LENGTH;
		cksum_vec[1].ptr = tvb_get_ptr(tvb, OSPF_HEADER_LENGTH, reported_length);
		cksum_vec[1].len = reported_length;
		cksum_vec_len = 2;
	    } else {
		/* There's nothing but a header. */
		cksum_vec_len = 1;
	    }
	    computed_cksum = in_cksum(cksum_vec, cksum_vec_len);
	    if (computed_cksum == 0) {
		proto_tree_add_text(ospf_header_tree, tvb, 12, 2,
			"Packet Checksum: 0x%04x (correct)", cksum);
	    } else {
		proto_tree_add_text(ospf_header_tree, tvb, 12, 2,
			"Packet Checksum: 0x%04x (incorrect, should be 0x%04x)",
			cksum, in_cksum_shouldbe(cksum, computed_cksum));
	    }
	} else {
	    proto_tree_add_text(ospf_header_tree, tvb, 12, 2,
	    	"Packet Checksum: 0x%04x", cksum);
	}
	auth_type = tvb_get_ntohs(tvb, 14);
	proto_tree_add_text(ospf_header_tree, tvb, 14, 2, "Auth Type: %s",
			    val_to_str(auth_type, auth_vals, "Unknown (%u)"));
	switch (auth_type) {

	case OSPF_AUTH_NONE:
	    proto_tree_add_text(ospf_header_tree, tvb, 16, 8, "Auth Data (none)");
	    break;

	case OSPF_AUTH_SIMPLE:
	    tvb_get_nstringz0(tvb, 16, 8, auth_data);
	    proto_tree_add_text(ospf_header_tree, tvb, 16, 8, "Auth Data: %s", auth_data);
	    break;

	case OSPF_AUTH_CRYPT:
	    proto_tree_add_text(ospf_header_tree, tvb, 18, 1, "Auth Key ID: %u",
				tvb_get_guint8(tvb, 18));
	    crypto_len = tvb_get_guint8(tvb, 19);
	    proto_tree_add_text(ospf_header_tree, tvb, 19, 1, "Auth Data Length: %u",
				crypto_len);
	    proto_tree_add_text(ospf_header_tree, tvb, 20, 4, "Auth Crypto Sequence Number: 0x%x",
				tvb_get_ntohl(tvb, 20));
  
	    /* Show the message digest that was appended to the end of the
	       OSPF message - but only if it's present (we don't want
	       to get an exception before we've tried dissecting OSPF
	       message). */
	    if (tvb_bytes_exist(tvb, ospflen, crypto_len)) {
		proto_tree_add_text(ospf_header_tree, tvb, ospflen, crypto_len,
				    "Auth Data: %s",
				    tvb_bytes_to_str(tvb, ospflen, crypto_len));
	    }
	    break;

	default:
	    proto_tree_add_text(ospf_header_tree, tvb, 16, 8, "Auth Data (unknown)");
	    break;
	}

	/* Adjust the length of the tvbuff to match the size of the OSPF
	 * packet (since the dissect routines use it to work out where the
	 * end of the OSPF packet is).
	 */
	tvb_set_reported_length(tvb, ospflen);

	switch (packet_type){

	case OSPF_HELLO:
	    dissect_ospf_hello(tvb, OSPF_HEADER_LENGTH, ospf_tree);
	    break;

	case OSPF_DB_DESC:
	    dissect_ospf_db_desc(tvb, OSPF_HEADER_LENGTH, ospf_tree);
	    break;

	case OSPF_LS_REQ:
	    dissect_ospf_ls_req(tvb, OSPF_HEADER_LENGTH, ospf_tree);
	    break;

	case OSPF_LS_UPD:
	    dissect_ospf_ls_upd(tvb, OSPF_HEADER_LENGTH, ospf_tree);
	    break;

	case OSPF_LS_ACK:
	    dissect_ospf_ls_ack(tvb, OSPF_HEADER_LENGTH, ospf_tree);
	    break;

	default:
	    dissect_data(tvb, OSPF_HEADER_LENGTH, pinfo, tree);
	    break;
	}
    }
}

static void
dissect_ospf_hello(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    proto_tree *ospf_hello_tree;
    proto_item *ti; 

    ti = proto_tree_add_text(tree, tvb, offset,
			     tvb_length_remaining(tvb, offset),
			     "OSPF Hello Packet");
    ospf_hello_tree = proto_item_add_subtree(ti, ett_ospf_hello);

    proto_tree_add_text(ospf_hello_tree, tvb, offset, 4, "Network Mask: %s",
			ip_to_str(tvb_get_ptr(tvb, offset, 4)));
    proto_tree_add_text(ospf_hello_tree, tvb, offset + 4, 2,
			"Hello Interval: %u seconds",
			tvb_get_ntohs(tvb, offset + 4));

    dissect_ospf_options(tvb, offset + 6, ospf_hello_tree);
    proto_tree_add_text(ospf_hello_tree, tvb, offset + 7, 1, "Router Priority: %u",
			tvb_get_guint8(tvb, offset + 7));
    proto_tree_add_text(ospf_hello_tree, tvb, offset + 8, 4, "Router Dead Interval: %u seconds",
			tvb_get_ntohl(tvb, offset + 8));
    proto_tree_add_text(ospf_hello_tree, tvb, offset + 12, 4, "Designated Router: %s",
			ip_to_str(tvb_get_ptr(tvb, offset + 12, 4)));
    proto_tree_add_text(ospf_hello_tree, tvb, offset + 16, 4, "Backup Designated Router: %s",
			ip_to_str(tvb_get_ptr(tvb, offset + 16, 4)));

    offset += 20;
    while (tvb_reported_length_remaining(tvb, offset) != 0) {
	proto_tree_add_text(ospf_hello_tree, tvb, offset, 4,
			    "Active Neighbor: %s",
			    ip_to_str(tvb_get_ptr(tvb, offset, 4)));
	offset += 4;
    }
}

static void
dissect_ospf_db_desc(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    proto_tree *ospf_db_desc_tree=NULL;
    proto_item *ti; 
    guint8 flags;
    char flags_string[20] = "";

    if (tree) {
	ti = proto_tree_add_text(tree, tvb, offset,
				 tvb_length_remaining(tvb, offset),
				 "OSPF DB Description"); 
	ospf_db_desc_tree = proto_item_add_subtree(ti, ett_ospf_desc);

	proto_tree_add_text(ospf_db_desc_tree, tvb, offset, 2, "Interface MTU: %u",
			    tvb_get_ntohs(tvb, offset));

	dissect_ospf_options(tvb, offset + 2, ospf_db_desc_tree);

	flags = tvb_get_guint8(tvb, offset + 3);
	if (flags & OSPF_DBD_FLAG_MS)
	    strcat(flags_string, "MS");
	if (flags & OSPF_DBD_FLAG_M) {
	    if (flags_string[0] != '\0')
		strcat(flags_string, "/");
	    strcat(flags_string, "M");
	}
	if (flags & OSPF_DBD_FLAG_I) {
	    if (flags_string[0] != '\0')
		strcat(flags_string, "/");
	    strcat(flags_string, "I");
	}
	proto_tree_add_text(ospf_db_desc_tree, tvb, offset + 3, 1, "Flags: 0x%x (%s)",
			    flags, flags_string);
	proto_tree_add_text(ospf_db_desc_tree, tvb, offset + 4, 4, "DD Sequence: %u",
			    tvb_get_ntohl(tvb, offset + 4));
    }

    /* LS Headers will be processed here */
    /* skip to the end of DB-Desc header */
    offset += 8;
    while (tvb_reported_length_remaining(tvb, offset) != 0)
	offset = dissect_ospf_lsa(tvb, offset, tree, FALSE);
}

static void
dissect_ospf_ls_req(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    proto_tree *ospf_lsr_tree;
    proto_item *ti;
    guint32 ls_type;

    /* zero or more LS requests may be within a LS Request */
    /* we place every request for a LSA in a single subtree */
    while (tvb_reported_length_remaining(tvb, offset) != 0) {
	ti = proto_tree_add_text(tree, tvb, offset, OSPF_LS_REQ_LENGTH,
				 "Link State Request"); 
	ospf_lsr_tree = proto_item_add_subtree(ti, ett_ospf_lsr);

	ls_type = tvb_get_ntohl(tvb, offset);
	proto_tree_add_text(ospf_lsr_tree, tvb, offset, 4, "LS Type: %s (%u)",
			    val_to_str(ls_type, ls_type_vals, "Unknown"),
			    ls_type);

	proto_tree_add_text(ospf_lsr_tree, tvb, offset + 4, 4, "Link State ID: %s", 
			    ip_to_str(tvb_get_ptr(tvb, offset + 4, 4)));
	proto_tree_add_text(ospf_lsr_tree, tvb, offset + 8, 4, "Advertising Router: %s", 
			    ip_to_str(tvb_get_ptr(tvb, offset + 8, 4)));

	offset += 12;
    }
}

static void
dissect_ospf_ls_upd(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    proto_tree *ospf_lsa_upd_tree=NULL;
    proto_item *ti;
    guint32 lsa_nr;
    guint32 lsa_counter; 

    ti = proto_tree_add_text(tree, tvb, offset,
			     tvb_length_remaining(tvb, offset),
			     "LS Update Packet");
    ospf_lsa_upd_tree = proto_item_add_subtree(ti, ett_ospf_lsa_upd);

    lsa_nr = tvb_get_ntohl(tvb, offset);
    proto_tree_add_text(ospf_lsa_upd_tree, tvb, offset, 4, "Number of LSAs: %u",
    			lsa_nr);
    /* skip to the beginning of the first LSA */
    offset += 4; /* the LS Upd Packet contains only a 32 bit #LSAs field */
    
    lsa_counter = 0;
    while (lsa_counter < lsa_nr) {
	offset = dissect_ospf_lsa(tvb, offset, ospf_lsa_upd_tree, TRUE);
        lsa_counter += 1;
    }
}

static void
dissect_ospf_ls_ack(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    /* the body of a LS Ack packet simply contains zero or more LSA Headers */
    while (tvb_reported_length_remaining(tvb, offset) != 0)
	offset = dissect_ospf_lsa(tvb, offset, tree, FALSE);
}

/*
 * Returns if an LSA is opaque, i.e. requires special treatment 
 */
static int
is_opaque(int lsa_type)
{
    return (lsa_type >= OSPF_LSTYPE_OP_LINKLOCAL &&
        lsa_type <= OSPF_LSTYPE_OP_ASWIDE);
}

/* MPLS/TE TLV types */
#define MPLS_TLV_ROUTER    1
#define MPLS_TLV_LINK      2

/* MPLS/TE Link STLV types */
enum {
    MPLS_LINK_TYPE       = 1,
    MPLS_LINK_ID,
    MPLS_LINK_LOCAL_IF,
    MPLS_LINK_REMOTE_IF,
    MPLS_LINK_TE_METRIC,
    MPLS_LINK_MAX_BW,
    MPLS_LINK_MAX_RES_BW,
    MPLS_LINK_UNRES_BW,
    MPLS_LINK_COLOR,
};

static const value_string mpls_link_stlv_str[] = {
    {MPLS_LINK_TYPE, "Link Type"},
    {MPLS_LINK_ID, "Link ID"},
    {MPLS_LINK_LOCAL_IF, "Local Interface IP Address"},
    {MPLS_LINK_REMOTE_IF, "Remote Interface IP Address"},
    {MPLS_LINK_TE_METRIC, "Traffic Engineering Metric"},
    {MPLS_LINK_MAX_BW, "Maximum Bandwidth"},
    {MPLS_LINK_MAX_RES_BW, "Maximum Reservable Bandwidth"},
    {MPLS_LINK_UNRES_BW, "Unreserved Bandwidth"},
    {MPLS_LINK_COLOR, "Resource Class/Color"},
    {0, NULL},
};

/* 
 * Dissect MPLS/TE opaque LSA 
 */
static void
dissect_ospf_lsa_mpls(tvbuff_t *tvb, int offset, proto_tree *tree,
		      guint32 length)
{
    proto_item *ti; 
    proto_tree *mpls_tree;
    proto_tree *tlv_tree;
    proto_tree *stlv_tree;

    int tlv_type;
    int tlv_length;
    int tlv_end_offset;

    int stlv_type, stlv_len, stlv_offset;
    char *stlv_name;
    int i;

    ti = proto_tree_add_text(tree, tvb, offset, length,
			     "MPLS Traffic Engineering LSA");
    mpls_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls);

    while (length != 0) {
	tlv_type = tvb_get_ntohs(tvb, offset);
	tlv_length = tvb_get_ntohs(tvb, offset + 2);
	tlv_end_offset = offset + tlv_length + 4;

	switch (tlv_type) {

	case MPLS_TLV_ROUTER:
	    ti = proto_tree_add_text(mpls_tree, tvb, offset, tlv_length+4,
				     "Router Address: %s", 
				     ip_to_str(tvb_get_ptr(tvb, offset+4, 4)));
	    tlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_router);
	    proto_tree_add_text(tlv_tree, tvb, offset, 2, "TLV Type: 1 - Router Address");
	    proto_tree_add_text(tlv_tree, tvb, offset+2, 2, "TLV Length: %u",
	    			tlv_length);
	    proto_tree_add_text(tlv_tree, tvb, offset+4, 4, "Router Address: %s",
				ip_to_str(tvb_get_ptr(tvb, offset+4, 4)));
	    break;

	case MPLS_TLV_LINK:
	    ti = proto_tree_add_text(mpls_tree, tvb, offset, tlv_length+4,
				     "Link Information");
	    tlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link);
	    proto_tree_add_text(tlv_tree, tvb, offset, 2, "TLV Type: 2 - Link Information");
	    proto_tree_add_text(tlv_tree, tvb, offset+2, 2, "TLV Length: %u",
				tlv_length);
	    stlv_offset = offset + 4;

	    /* Walk down the sub-TLVs for link information */
	    while (stlv_offset < tlv_end_offset) {
		stlv_type = tvb_get_ntohs(tvb, stlv_offset);
		stlv_len = tvb_get_ntohs(tvb, stlv_offset + 2);
		stlv_name = val_to_str(stlv_type, mpls_link_stlv_str, "Unknown sub-TLV");
		switch (stlv_type) {

		case MPLS_LINK_TYPE:
		    ti = proto_tree_add_text(tlv_tree, tvb, stlv_offset, stlv_len+4,
					     "%s: %u", stlv_name,
					     tvb_get_guint8(tvb, stlv_offset + 4));
		    stlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link_stlv);
		    proto_tree_add_text(stlv_tree, tvb, stlv_offset, 2,
					"TLV Type: %u: %s", stlv_type, stlv_name);
		    proto_tree_add_text(stlv_tree, tvb, stlv_offset+2, 2, "TLV Length: %u",
		    			stlv_len);
		    proto_tree_add_text(stlv_tree, tvb, stlv_offset+4, 1, "%s: %u", stlv_name,
					tvb_get_guint8(tvb, stlv_offset + 4));
		    break;

		case MPLS_LINK_ID:
		    ti = proto_tree_add_text(tlv_tree, tvb, stlv_offset, stlv_len+4,
					     "%s: %s (%x)", stlv_name,
					     ip_to_str(tvb_get_ptr(tvb, stlv_offset + 4, 4)),
					     tvb_get_ntohl(tvb, stlv_offset + 4));
		    stlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link_stlv);
		    proto_tree_add_text(stlv_tree, tvb, stlv_offset, 2,
					"TLV Type: %u: %s", stlv_type, stlv_name);
		    proto_tree_add_text(stlv_tree, tvb, stlv_offset+2, 2, "TLV Length: %u",
					stlv_len);
		    proto_tree_add_text(stlv_tree, tvb, stlv_offset+4, 4, "%s: %s (%x)", stlv_name,
					ip_to_str(tvb_get_ptr(tvb, stlv_offset + 4, 4)),
					tvb_get_ntohl(tvb, stlv_offset + 4));
		    break;

		case MPLS_LINK_LOCAL_IF:
		case MPLS_LINK_REMOTE_IF:
		    ti = proto_tree_add_text(tlv_tree, tvb, stlv_offset, stlv_len+4,
					     "%s: %s", stlv_name,
					     ip_to_str(tvb_get_ptr(tvb, stlv_offset+4, 4)));
		    stlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link_stlv);
		    proto_tree_add_text(stlv_tree, tvb, stlv_offset, 2,
					"TLV Type: %u: %s", stlv_type, stlv_name);
		    proto_tree_add_text(stlv_tree, tvb, stlv_offset+2, 2, "TLV Length: %u",
					stlv_len);
		    proto_tree_add_text(stlv_tree, tvb, stlv_offset+4, 4, "%s: %s", stlv_name,
					ip_to_str(tvb_get_ptr(tvb, stlv_offset+4, 4)));
		    break;

		case MPLS_LINK_TE_METRIC:
		case MPLS_LINK_COLOR:
		    ti = proto_tree_add_text(tlv_tree, tvb, stlv_offset, stlv_len+4,
					     "%s: %u", stlv_name,
					     tvb_get_ntohl(tvb, stlv_offset + 4));
		    stlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link_stlv);
		    proto_tree_add_text(stlv_tree, tvb, stlv_offset, 2,
					"TLV Type: %u: %s", stlv_type, stlv_name);
		    proto_tree_add_text(stlv_tree, tvb, stlv_offset+2, 2, "TLV Length: %u",
					stlv_len);
		    proto_tree_add_text(stlv_tree, tvb, stlv_offset+4, 4, "%s: %u", stlv_name,
					tvb_get_ntohl(tvb, stlv_offset + 4));
		    break;

		case MPLS_LINK_MAX_BW:
		case MPLS_LINK_MAX_RES_BW:
		    ti = proto_tree_add_text(tlv_tree, tvb, stlv_offset, stlv_len+4,
					     "%s: %ld", stlv_name,
					     pieee_to_long(tvb_get_ptr(tvb, stlv_offset + 4, 4)));
		    stlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link_stlv);
		    proto_tree_add_text(stlv_tree, tvb, stlv_offset, 2,
					"TLV Type: %u: %s", stlv_type, stlv_name);
		    proto_tree_add_text(stlv_tree, tvb, stlv_offset+2, 2, "TLV Length: %u",
					stlv_len);
		    proto_tree_add_text(stlv_tree, tvb, stlv_offset+4, 4, "%s: %ld", stlv_name,
					pieee_to_long(tvb_get_ptr(tvb, stlv_offset + 4, 4)));
		    break;

		case MPLS_LINK_UNRES_BW:
		    ti = proto_tree_add_text(tlv_tree, tvb, stlv_offset, stlv_len+4,
					     "%s", stlv_name);
		    stlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link_stlv);
		    proto_tree_add_text(stlv_tree, tvb, stlv_offset, 2,
					"TLV Type: %u: %s", stlv_type, stlv_name);
		    proto_tree_add_text(stlv_tree, tvb, stlv_offset+2, 2, "TLV Length: %u",
					stlv_len);
		    for (i = 0; i < 8; i++) {
			proto_tree_add_text(stlv_tree, tvb, stlv_offset+4+(i*4), 4,
					    "Pri %d: %ld", i,
					    pieee_to_long(tvb_get_ptr(tvb, stlv_offset + 4 + i*4, 4)));
		    }
		    break;

		default:
		    proto_tree_add_text(tlv_tree, tvb, stlv_offset, stlv_len+4,
					"Unknown Link sub-TLV: %u", stlv_type);
		    break;
		}
		stlv_offset += ((stlv_len+4+3)/4)*4;
	    }
	    break;

	default:
	    ti = proto_tree_add_text(mpls_tree, tvb, offset, tlv_length+4, 
				     "Unknown LSA: %u", tlv_type);
	    tlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link);
	    proto_tree_add_text(tlv_tree, tvb, offset, 2, "TLV Type: %u - Unknown",
				tlv_type);
	    proto_tree_add_text(tlv_tree, tvb, offset+2, 2, "TLV Length: %u",
				tlv_length);
	    proto_tree_add_text(tlv_tree, tvb, offset+4, tlv_length, "TLV Data");
	    break;
	}

	offset += tlv_length + 4;
	length -= tlv_length + 4;
    }
}

/*
 * Dissect opaque LSAs
 */
void
dissect_ospf_lsa_opaque(tvbuff_t *tvb, int offset, proto_tree *tree,
			guint8 ls_id_type, guint32 length)
{
    switch (ls_id_type) {

    case OSPF_LSA_MPLS_TE:
	dissect_ospf_lsa_mpls(tvb, offset, tree, length);
	break;

    default:
	proto_tree_add_text(tree, tvb, offset, length,
			    "Unknown LSA Type %u", ls_id_type);
	break;
    } /* switch on opaque LSA id */
}

static int
dissect_ospf_lsa(tvbuff_t *tvb, int offset, proto_tree *tree,
		 gboolean disassemble_body)
{
    proto_tree *ospf_lsa_tree;
    proto_item *ti; 

    guint8		 ls_type;
    guint16		 ls_length;
    int			 end_offset;
    char		*lsa_type;
    guint8		 nr_links;
    guint16		 nr_tos;

    /* router LSA */
    guint8		 link_type;
    guint16 		 link_counter;
    guint8 		 tos_counter;
    char  		*link_type_str;
    char  		*link_id;

    /* AS-external LSA */
    guint8		 options;

    /* opaque LSA */
    guint8		 ls_id_type;

    ls_type = tvb_get_guint8(tvb, offset + 3);
    ls_length = tvb_get_ntohs(tvb, offset + 18);
    end_offset = offset + ls_length;
    switch(ls_type) {

    case OSPF_LSTYPE_ROUTER:
	lsa_type="Router LSA";
        break;

    case OSPF_LSTYPE_NETWORK:
	lsa_type="Network LSA";
        break;

    case OSPF_LSTYPE_SUMMERY:
	lsa_type="Summary LSA";
        break;

    case OSPF_LSTYPE_ASBR:
	lsa_type="ASBR LSA";
        break;

    case OSPF_LSTYPE_ASEXT:
	lsa_type="AS-external-LSA";
        break;

    case OSPF_LSTYPE_ASEXT7:
	lsa_type="AS-external-LSA Type 7/NSSA";
        break;

    case OSPF_LSTYPE_OP_LINKLOCAL:
	lsa_type="Opaque LSA, Link-local scope";
        break;

    case OSPF_LSTYPE_OP_AREALOCAL:
	lsa_type="Opaque LSA, Area-local scope";
        break;

    case OSPF_LSTYPE_OP_ASWIDE:
	lsa_type="Opaque LSA, AS-wide scope";
        break;

    default:
	lsa_type="Unknown";
	break;
    }

    if (disassemble_body) {
	ti = proto_tree_add_text(tree, tvb, offset, ls_length,
				 "%s (Type: %u)", lsa_type, ls_type); 
    } else {
	ti = proto_tree_add_text(tree, tvb, offset, OSPF_LSA_HEADER_LENGTH,
				 "LSA Header"); 
    }
    ospf_lsa_tree = proto_item_add_subtree(ti, ett_ospf_lsa);

    proto_tree_add_text(ospf_lsa_tree, tvb, offset, 2, "LS Age: %u seconds",
			tvb_get_ntohs(tvb, offset));
    dissect_ospf_options(tvb, offset + 2, ospf_lsa_tree);
    proto_tree_add_text(ospf_lsa_tree, tvb, offset + 3, 1, "LSA Type: %u (%s)",
			ls_type, lsa_type);

    if (is_opaque(ls_type)) {
    	ls_id_type = tvb_get_guint8(tvb, offset + 4);
	proto_tree_add_text(ospf_lsa_tree, tvb, offset + 4, 1, "Link State ID Opaque Type: %u",
			    ls_id_type);
	proto_tree_add_text(ospf_lsa_tree, tvb, offset + 5, 3, "Link State ID Opaque ID: %u",
			    tvb_get_ntoh24(tvb, offset + 5));
    } else {
	ls_id_type = 0;
	proto_tree_add_text(ospf_lsa_tree, tvb, offset + 4, 4, "Link State ID: %s",
			    ip_to_str(tvb_get_ptr(tvb, offset + 4, 4)));
    }

    proto_tree_add_text(ospf_lsa_tree, tvb, offset + 8, 4, "Advertising Router: %s",
			ip_to_str(tvb_get_ptr(tvb, offset + 8, 4)));
    proto_tree_add_text(ospf_lsa_tree, tvb, offset + 12, 4, "LS Sequence Number: 0x%04x",
			tvb_get_ntohl(tvb, offset + 12));
    proto_tree_add_text(ospf_lsa_tree, tvb, offset + 16, 2, "LS Checksum: %04x",
			tvb_get_ntohs(tvb, offset + 16));

    proto_tree_add_text(ospf_lsa_tree, tvb, offset + 18, 2, "Length: %u",
			ls_length);

    /* skip past the LSA header to the body */
    offset += OSPF_LSA_HEADER_LENGTH;
    ls_length -= OSPF_LSA_HEADER_LENGTH;

    if (!disassemble_body)
	return offset;

    switch (ls_type){

    case OSPF_LSTYPE_ROUTER:
	/* again: flags should be secified in detail */
	proto_tree_add_text(ospf_lsa_tree, tvb, offset, 1, "Flags: 0x%02x",
			    tvb_get_guint8(tvb, offset));
	nr_links = tvb_get_ntohs(tvb, offset + 2);
	proto_tree_add_text(ospf_lsa_tree, tvb, offset + 2, 2, "Number of Links: %u",
			    nr_links);
	offset += 4;
	/* nr_links links follow 
	 * maybe we should put each of the links into its own subtree ???
	 */
	for (link_counter = 1; link_counter <= nr_links; link_counter++) {
	    /* check the Link Type and ID */
	    link_type = tvb_get_guint8(tvb, offset + 8);
	    switch (link_type) {

	    case OSPF_LINK_PTP:
                link_type_str="Point-to-point connection to another router";
		link_id="Neighboring router's Router ID";
		break;

	    case OSPF_LINK_TRANSIT:
		link_type_str="Connection to a transit network";
		link_id="IP address of Designated Router";
		break;

	    case OSPF_LINK_STUB:
		link_type_str="Connection to a stub network";
		link_id="IP network/subnet number";
		break;

	    case OSPF_LINK_VIRTUAL:
		link_type_str="Virtual link";
		link_id="Neighboring router's Router ID";
		break;

	    default:
		link_type_str="Unknown link type";
		link_id="Unknown link ID";
		break;
	    }

	    proto_tree_add_text(ospf_lsa_tree, tvb, offset, 4, "%s: %s", link_id,
				ip_to_str(tvb_get_ptr(tvb, offset, 4)));

	    /* link_data should be specified in detail (e.g. network mask) (depends on link type)*/
	    proto_tree_add_text(ospf_lsa_tree, tvb, offset + 4, 4, "Link Data: %s",
				ip_to_str(tvb_get_ptr(tvb, offset + 4, 4)));

	    proto_tree_add_text(ospf_lsa_tree, tvb, offset + 8, 1, "Link Type: %u - %s",
				link_type, link_type_str);
	    nr_tos = tvb_get_guint8(tvb, offset + 9);
	    proto_tree_add_text(ospf_lsa_tree, tvb, offset + 9, 1, "Number of TOS metrics: %u",
				nr_tos);
	    proto_tree_add_text(ospf_lsa_tree, tvb, offset + 10, 2, "TOS 0 metric: %u",
				tvb_get_ntohs(tvb, offset + 10));

	    offset += 12;

	    /* nr_tos metrics may follow each link 
	     * ATTENTION: TOS metrics are not tested (I don't have TOS
	     * based routing)
	     * please send me a mail if it is/isn't working
	     */
	    for (tos_counter = 1; tos_counter <= nr_tos; tos_counter++) {
		proto_tree_add_text(ospf_lsa_tree, tvb, offset, 4, "TOS: %u, Metric: %u",
				    tvb_get_guint8(tvb, offset),
				    tvb_get_ntohs(tvb, offset + 2));
		offset += 4;
	    }
	}
	break;

    case OSPF_LSTYPE_NETWORK:
	proto_tree_add_text(ospf_lsa_tree, tvb, offset, 4, "Netmask: %s",
				ip_to_str(tvb_get_ptr(tvb, offset, 4)));
	offset += 4;

	while (offset < end_offset) {
	    proto_tree_add_text(ospf_lsa_tree, tvb, offset, 4, "Attached Router: %s",
				ip_to_str(tvb_get_ptr(tvb, offset, 4)));
	    offset += 4;
	}
	break;

    case OSPF_LSTYPE_SUMMERY:
    /* Type 3 and 4 LSAs have the same format */
    case OSPF_LSTYPE_ASBR:
	proto_tree_add_text(ospf_lsa_tree, tvb, offset, 4, "Netmask: %s",
			    ip_to_str(tvb_get_ptr(tvb, offset, 4)));
	offset += 4;

	proto_tree_add_text(ospf_lsa_tree, tvb, offset, 4, "Metric: %u",
			    tvb_get_ntoh24(tvb, offset + 1));
	offset += 4;

	/* TOS-specific information, if any */
	while (offset < end_offset) {
	    proto_tree_add_text(ospf_lsa_tree, tvb, offset, 4, "TOS: %u, Metric: %u",
				tvb_get_guint8(tvb, offset),
				tvb_get_ntoh24(tvb, offset + 1));
	    offset += 4;
	}
	break;

    case OSPF_LSTYPE_ASEXT:
    case OSPF_LSTYPE_ASEXT7:
	proto_tree_add_text(ospf_lsa_tree, tvb, offset, 4, "Netmask: %s", 
			    ip_to_str(tvb_get_ptr(tvb, offset, 4)));
	offset += 4;

	options = tvb_get_guint8(tvb, offset);
	if (options & 0x80) { /* check wether or not E bit is set */
	    proto_tree_add_text(ospf_lsa_tree, tvb, offset, 1,
		    "External Type: Type 2 (metric is larger than any other link state path)");
	} else {
	    proto_tree_add_text(ospf_lsa_tree, tvb, offset, 1,
		    "External Type: Type 1 (metric is specified in the same units as interface cost)");
	}
	/* the metric field of a AS-external LAS is specified in 3 bytes */
	proto_tree_add_text(ospf_lsa_tree, tvb, offset + 1, 3, "Metric: %u",
			    tvb_get_ntoh24(tvb, offset + 1));
	offset += 4;

	proto_tree_add_text(ospf_lsa_tree, tvb, offset, 4, "Forwarding Address: %s", 
			    ip_to_str(tvb_get_ptr(tvb, offset, 4)));
	offset += 4;

	proto_tree_add_text(ospf_lsa_tree, tvb, offset, 4, "External Route Tag: %u",
			    tvb_get_ntohl(tvb, offset));
	offset += 4;

	/* TOS-specific information, if any */
	while (offset < end_offset) {
	    options = tvb_get_guint8(tvb, offset);
	    if (options & 0x80) { /* check wether or not E bit is set */
		proto_tree_add_text(ospf_lsa_tree, tvb, offset, 1,
			"External Type: Type 2 (metric is larger than any other link state path)");
	    } else {
		proto_tree_add_text(ospf_lsa_tree, tvb, offset, 1,
			"External Type: Type 1 (metric is specified in the same units as interface cost)");
	    }
	    proto_tree_add_text(ospf_lsa_tree, tvb, offset, 4, "TOS: %u, Metric: %u",
				options & 0x7F,
				tvb_get_ntoh24(tvb, offset + 1));
	    offset += 4;

	    proto_tree_add_text(ospf_lsa_tree, tvb, offset, 4, "Forwarding Address: %s", 
				ip_to_str(tvb_get_ptr(tvb, offset, 4)));
	    offset += 4;

	    proto_tree_add_text(ospf_lsa_tree, tvb, offset, 4, "External Route Tag: %u",
				tvb_get_ntohl(tvb, offset));
	    offset += 4;
	}
	break;

    case OSPF_LSTYPE_OP_LINKLOCAL:
    case OSPF_LSTYPE_OP_AREALOCAL:
    case OSPF_LSTYPE_OP_ASWIDE:
	dissect_ospf_lsa_opaque(tvb, offset, ospf_lsa_tree, ls_id_type,
				ls_length);
	offset += ls_length;
	break;

    default:
	/* unknown LSA type */
	proto_tree_add_text(ospf_lsa_tree, tvb, offset, ls_length,
			    "Unknown LSA Type");
	offset += ls_length;
	break;
    }
    /* return the offset of the next LSA */
    return offset;
}

static void
dissect_ospf_options(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    guint8 options;
    char options_string[20] = "";

    /* ATTENTION !!! no check for length of options string */
    options = tvb_get_guint8(tvb, offset);
    if (options & OSPF_OPTIONS_E)
	strcat(options_string, "E");
    if (options & OSPF_OPTIONS_MC) {
	if (options_string[0] != '\0')
	    strcat(options_string, "/");
	strcat(options_string, "MC");
    }
    if (options & OSPF_OPTIONS_NP) {
	if (options_string[0] != '\0')
	    strcat(options_string, "/");
	strcat(options_string, "NP");
    }
    if (options & OSPF_OPTIONS_EA) {
	if (options_string[0] != '\0')
	    strcat(options_string, "/");
	strcat(options_string, "EA");
    }
    if (options & OSPF_OPTIONS_DC) {
	if (options_string[0] != '\0')
	    strcat(options_string, "/");
	strcat(options_string, "DC");
    }

    proto_tree_add_text(tree, tvb, offset, 1, "Options: 0x%x (%s)",
			options, options_string);
}

void
proto_register_ospf(void)
{
/*        static hf_register_info hf[] = {
                { &variable,
                { "Name",           "ospf.abbreviation", TYPE, VALS_POINTER }},
        };*/
    static gint *ett[] = {
	&ett_ospf,
	&ett_ospf_hdr,
	&ett_ospf_hello,
	&ett_ospf_desc,
	&ett_ospf_lsr,
	&ett_ospf_lsa,
	&ett_ospf_lsa_upd,
	&ett_ospf_lsa_mpls,
	&ett_ospf_lsa_mpls_router,
	&ett_ospf_lsa_mpls_link,
	&ett_ospf_lsa_mpls_link_stlv
    };

    proto_ospf = proto_register_protocol("Open Shortest Path First",
					 "OSPF", "ospf");
 /*       proto_register_field_array(proto_ospf, hf, array_length(hf));*/
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ospf(void)
{
    dissector_add("ip.proto", IP_PROTO_OSPF, dissect_ospf);
}
