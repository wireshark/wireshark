/* packet-ospf.c
 * Routines for OSPF packet disassembly
 * (c) Copyright Hannes R. Boehm <hannes@boehm.org>
 *
 * $Id: packet-ospf.c,v 1.46 2001/09/14 06:30:42 guy Exp $
 *
 * At this time, this module is able to analyze OSPF
 * packets as specified in RFC2328. MOSPF (RFC1584) and other
 * OSPF Extensions which introduce new Packet types
 * (e.g the External Atributes LSA) are not supported.
 * Furthermore RFC2740 (OSPFv3 - OSPF for IPv6) is now supported
 *   - (c) 2001 Palle Lyckegaard <palle[AT]lyckegaard.dk>
 *
 * TOS - support is not fully implemented
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
#include "ipproto.h"
#include "in_cksum.h"
#include "ieee-float.h"

#define OSPF_VERSION_2 2
#define OSPF_VERSION_3 3
#define OSPF_VERSION_2_HEADER_LENGTH	24
#define OSPF_VERSION_3_HEADER_LENGTH    16


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

#define OSPF_V2_OPTIONS_E		0x02
#define OSPF_V2_OPTIONS_MC		0x04
#define OSPF_V2_OPTIONS_NP		0x08
#define OSPF_V2_OPTIONS_EA		0x10
#define OSPF_V2_OPTIONS_DC		0x20
#define OSPF_V2_OPTIONS_O		0x40
#define OSPF_V2_OPTIONS_DN          0x01
#define OSPF_V3_OPTIONS_V6              0x01    
#define OSPF_V3_OPTIONS_E		0x02
#define OSPF_V3_OPTIONS_MC		0x04
#define OSPF_V3_OPTIONS_N		0x08
#define OSPF_V3_OPTIONS_R		0x10
#define OSPF_V3_OPTIONS_DC		0x20


#define OSPF_DBD_FLAG_MS	1
#define OSPF_DBD_FLAG_M		2
#define OSPF_DBD_FLAG_I		4

#define OSPF_LS_REQ_LENGTH	12

#define OSPF_LSTYPE_ROUTER	1
#define OSPF_LSTYPE_NETWORK	2
#define OSPF_LSTYPE_SUMMERY	3
#define OSPF_LSTYPE_ASBR	4
#define OSPF_LSTYPE_ASEXT	5
#define OSPF_LSTYPE_GRPMEMBER	6
#define OSPF_LSTYPE_ASEXT7	7
#define OSPF_LSTYPE_EXTATTR	8
#define OSPF_V3_LSTYPE_ROUTER                0x2001
#define OSPF_V3_LSTYPE_NETWORK	             0x2002
#define OSPF_V3_LSTYPE_INTER_AREA_PREFIX     0x2003
#define OSPF_V3_LSTYPE_INTER_AREA_ROUTER     0x2004
#define OSPF_V3_LSTYPE_AS_EXTERNAL           0x4005
#define OSPF_V3_LSTYPE_GROUP_MEMBERSHIP      0x2006     
#define OSPF_V3_LSTYPE_TYPE_7                0x2007
#define OSPF_V3_LSTYPE_LINK                  0x0008
#define OSPF_V3_LSTYPE_INTRA_AREA_PREFIX     0x2009

/* Opaque LSA types */
#define OSPF_LSTYPE_OP_LINKLOCAL 9
#define OSPF_LSTYPE_OP_AREALOCAL 10
#define OSPF_LSTYPE_OP_ASWIDE    11

#define OSPF_LINK_PTP		1
#define OSPF_LINK_TRANSIT	2
#define OSPF_LINK_STUB		3
#define OSPF_LINK_VIRTUAL	4

#define OSPF_V3_LINK_PTP	1
#define OSPF_V3_LINK_TRANSIT	2
#define OSPF_V3_LINK_RESERVED	3
#define OSPF_V3_LINK_VIRTUAL	4

#define OSPF_LSA_HEADER_LENGTH	20

/* Known opaque LSAs */
#define OSPF_LSA_MPLS_TE        1


static const value_string ls_type_vals[] = {
	{OSPF_LSTYPE_ROUTER,                  "Router-LSA"                   },
	{OSPF_LSTYPE_NETWORK,                 "Network-LSA"                  },
	{OSPF_LSTYPE_SUMMERY,                 "Summary-LSA (IP network)"     },
	{OSPF_LSTYPE_ASBR,                    "Summary-LSA (ASBR)"           },
	{OSPF_LSTYPE_ASEXT,                   "AS-External-LSA (ASBR)"       },
	{OSPF_LSTYPE_GRPMEMBER,               "Group Membership LSA"         },
	{OSPF_LSTYPE_ASEXT7,                  "NSSA AS-External-LSA"         },
	{OSPF_LSTYPE_EXTATTR,                 "External Attributes LSA"      },
	{OSPF_LSTYPE_OP_LINKLOCAL,            "Opaque LSA, Link-local scope" },
	{OSPF_LSTYPE_OP_AREALOCAL,            "Opaque LSA, Area-local scope" },
	{0,                                   NULL                           }

};

static const value_string v3_ls_type_vals[] = {
  	{OSPF_V3_LSTYPE_ROUTER,               "Router-LSA"                   }, 
  	{OSPF_V3_LSTYPE_NETWORK,              "Network-LSA"                  }, 
  	{OSPF_V3_LSTYPE_INTER_AREA_PREFIX,    "Inter-Area-Prefix-LSA"        }, 
  	{OSPF_V3_LSTYPE_INTER_AREA_ROUTER,    "Inter-Area-Router-LSA"        }, 
  	{OSPF_V3_LSTYPE_AS_EXTERNAL,          "AS-External-LSA"              }, 
  	{OSPF_V3_LSTYPE_GROUP_MEMBERSHIP,     "Group-Membership-LSA"         }, 
  	{OSPF_V3_LSTYPE_TYPE_7,               "Type-LSA"                     }, 
	{OSPF_V3_LSTYPE_LINK,                 "Link-LSA"                     },
	{OSPF_V3_LSTYPE_INTRA_AREA_PREFIX,    "Intra-Area-Prefix-LSA"        },
	{0,                                   NULL                           }

};


#define OSPF_V3_ROUTER_LSA_FLAG_B 0x01
#define OSPF_V3_ROUTER_LSA_FLAG_E 0x02
#define OSPF_V3_ROUTER_LSA_FLAG_V 0x04
#define OSPF_V3_ROUTER_LSA_FLAG_W 0x08

#define OSPF_V3_PREFIX_OPTION_NU 0x01
#define OSPF_V3_PREFIX_OPTION_LA 0x02
#define OSPF_V3_PREFIX_OPTION_MC 0x04
#define OSPF_V3_PREFIX_OPTION_P  0x08

#define OSPF_V3_AS_EXTERNAL_FLAG_T 0x01
#define OSPF_V3_AS_EXTERNAL_FLAG_F 0x02
#define OSPF_V3_AS_EXTERNAL_FLAG_E 0x04


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

static void dissect_ospf_hello(tvbuff_t*, int, proto_tree*, guint8);
static void dissect_ospf_db_desc(tvbuff_t*, int, proto_tree*, guint8); 
static void dissect_ospf_ls_req(tvbuff_t*, int, proto_tree*, guint8); 
static void dissect_ospf_ls_upd(tvbuff_t*, int, proto_tree*, guint8); 
static void dissect_ospf_ls_ack(tvbuff_t*, int, proto_tree*, guint8); 

/* dissect_ospf_v[23]lsa returns the offset of the next LSA
 * if disassemble_body is set to FALSE (e.g. in LSA ACK 
 * packets), the offset is set to the offset of the next
 * LSA header
 */
static int dissect_ospf_v2_lsa(tvbuff_t*, int, proto_tree*, gboolean disassemble_body); 
static int dissect_ospf_v3_lsa(tvbuff_t*, int, proto_tree*, gboolean disassemble_body); 

static void dissect_ospf_options(tvbuff_t *, int, proto_tree *, guint8);

static void dissect_ospf_v3_prefix_options(tvbuff_t *, int, proto_tree *);

static void dissect_ospf_v3_address_prefix(tvbuff_t *, int, int, proto_tree *);

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
    unsigned int ospf_header_length;
    guint8 instance_ID;
    guint8 reserved;
    guint32 areaid;


    if (check_col(pinfo->fd, COL_PROTOCOL))
	col_set_str(pinfo->fd, COL_PROTOCOL, "OSPF");
    if (check_col(pinfo->fd, COL_INFO))
	col_clear(pinfo->fd, COL_INFO);

    version = tvb_get_guint8(tvb, 0);
    switch (version) {
        case OSPF_VERSION_2:
            ospf_header_length = OSPF_VERSION_2_HEADER_LENGTH;
            break;
        case OSPF_VERSION_3:
            ospf_header_length = OSPF_VERSION_3_HEADER_LENGTH;
            break;
        default:
	    ospf_header_length = 0;
            break;
    }

    packet_type = tvb_get_guint8(tvb, 1);
    if (check_col(pinfo->fd, COL_INFO)) {
	col_add_str(pinfo->fd, COL_INFO,
		    val_to_str(packet_type, pt_vals, "Unknown (%u)"));
    }  

    if (tree) {
	ospflen = tvb_get_ntohs(tvb, 2);

	ti = proto_tree_add_item(tree, proto_ospf, tvb, 0, ospflen, FALSE);
	ospf_tree = proto_item_add_subtree(ti, ett_ospf);

	ti = proto_tree_add_text(ospf_tree, tvb, 0, ospf_header_length,
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
	areaid=tvb_get_ntohl(tvb,8);
	proto_tree_add_text(ospf_header_tree, tvb, 8, 4, "Area ID: %s%s",
			       ip_to_str(tvb_get_ptr(tvb, 8, 4)), areaid == 0 ? " (Backbone)" : "");
	cksum = tvb_get_ntohs(tvb, 12);
	length = tvb_length(tvb);
	/* XXX - include only the length from the OSPF header? */
	reported_length = tvb_reported_length(tvb);
	if (!pinfo->fragmented && length >= reported_length
		&& length >= ospf_header_length) {
	    /* The packet isn't part of a fragmented datagram and isn't
	       truncated, so we can checksum it. */

	    /* Header, not including the authentication data (the OSPF
	       checksum excludes the 64-bit authentication field (which is an OSPFv2-only field)). */
	    cksum_vec[0].ptr = tvb_get_ptr(tvb, 0, 16);
	    cksum_vec[0].len = 16;
	    if (length > ospf_header_length) {
		/* Rest of the packet, again not including the
		   authentication data. */
		reported_length -= ospf_header_length;
		cksum_vec[1].ptr = tvb_get_ptr(tvb, ospf_header_length, reported_length);
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


	/* Authentication is only valid for OSPFv2 */
        if ( version == OSPF_VERSION_2 ) {        
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

        }

	/* Instance ID and "reserved" is OSPFv3-only */
        if ( version == OSPF_VERSION_3 ) {
	    instance_ID = tvb_get_guint8(tvb, 14);
 	    proto_tree_add_text(ospf_header_tree, tvb, 14, 1, "Instance ID: %u",
			    instance_ID);
 	    reserved = tvb_get_guint8(tvb, 15);
	    proto_tree_add_text(ospf_header_tree, tvb, 15, 1, (reserved == 0 ? "Reserved: %u" : "Reserved: %u (incorrect, should be 0)"),
				reserved);

	}

	/* Adjust the length of the tvbuff to match the size of the OSPF
	 * packet (since the dissect routines use it to work out where the
	 * end of the OSPF packet is).
	 */
	tvb_set_reported_length(tvb, ospflen);

	switch (packet_type){

	case OSPF_HELLO:
	    dissect_ospf_hello(tvb, ospf_header_length, ospf_tree, version);
	    break;

	case OSPF_DB_DESC:
	    dissect_ospf_db_desc(tvb, ospf_header_length, ospf_tree, version);
	    break;

	case OSPF_LS_REQ:
	    dissect_ospf_ls_req(tvb, ospf_header_length, ospf_tree, version);
	    break;

	case OSPF_LS_UPD:
	    dissect_ospf_ls_upd(tvb, ospf_header_length, ospf_tree, version);
	    break;

	case OSPF_LS_ACK:
	    dissect_ospf_ls_ack(tvb, ospf_header_length, ospf_tree, version);
	    break;

	default:
	    dissect_data(tvb, ospf_header_length, pinfo, tree);
	    break;
	}
    }
}

static void
dissect_ospf_hello(tvbuff_t *tvb, int offset, proto_tree *tree, guint8 version)
{
    proto_tree *ospf_hello_tree;
    proto_item *ti; 

    ti = proto_tree_add_text(tree, tvb, offset,
			     tvb_length_remaining(tvb, offset),
			     "OSPF Hello Packet");
    ospf_hello_tree = proto_item_add_subtree(ti, ett_ospf_hello);
    
    switch (version ) {
        case OSPF_VERSION_2:
            proto_tree_add_text(ospf_hello_tree, tvb, offset, 4, "Network Mask: %s",
			ip_to_str(tvb_get_ptr(tvb, offset, 4)));
            proto_tree_add_text(ospf_hello_tree, tvb, offset + 4, 2,
			"Hello Interval: %u seconds",
			tvb_get_ntohs(tvb, offset + 4));

            dissect_ospf_options(tvb, offset + 6, ospf_hello_tree, version);
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
            break;
        case OSPF_VERSION_3:
            proto_tree_add_text(ospf_hello_tree, tvb, offset + 0, 4, "Interface ID: %u",
			tvb_get_ntohl(tvb, offset + 0));
            proto_tree_add_text(ospf_hello_tree, tvb, offset + 4, 1, "Router Priority: %u",
			tvb_get_guint8(tvb, offset + 4));
            dissect_ospf_options(tvb, offset + 5, ospf_hello_tree, version);
            proto_tree_add_text(ospf_hello_tree, tvb, offset + 8, 2,
			"Hello Interval: %u seconds",
			tvb_get_ntohs(tvb, offset + 8));
            proto_tree_add_text(ospf_hello_tree, tvb, offset + 10, 2, "Router Dead Interval: %u seconds",
			tvb_get_ntohs(tvb, offset + 10));
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

	    break;

        default:    
            break;
    }
}

static void
dissect_ospf_db_desc(tvbuff_t *tvb, int offset, proto_tree *tree, guint8 version)
{
    proto_tree *ospf_db_desc_tree=NULL;
    proto_item *ti; 
    guint8 flags;
    guint8 reserved;
    char flags_string[20] = "";

    if (tree) {
	ti = proto_tree_add_text(tree, tvb, offset,
				 tvb_length_remaining(tvb, offset),
				 "OSPF DB Description"); 
	ospf_db_desc_tree = proto_item_add_subtree(ti, ett_ospf_desc);

        switch (version ) {
 
	    case OSPF_VERSION_2:

                proto_tree_add_text(ospf_db_desc_tree, tvb, offset, 2, "Interface MTU: %u",
			    tvb_get_ntohs(tvb, offset));

	        dissect_ospf_options(tvb, offset + 2, ospf_db_desc_tree, version);

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

                offset += 8;
                break;

            case OSPF_VERSION_3:

	        reserved = tvb_get_guint8(tvb, offset);
	        proto_tree_add_text(ospf_db_desc_tree, tvb, offset, 1, (reserved == 0 ? "Reserved: %u" : "Reserved: %u (incorrect, should be 0)"),
				reserved);

	        dissect_ospf_options(tvb, offset + 1, ospf_db_desc_tree, version);

                proto_tree_add_text(ospf_db_desc_tree, tvb, offset + 4, 2, "Interface MTU: %u",
			    tvb_get_ntohs(tvb, offset+4));

	        reserved = tvb_get_guint8(tvb, offset + 6);
	        proto_tree_add_text(ospf_db_desc_tree, tvb, offset + 6, 1, (reserved == 0 ? "Reserved: %u" : "Reserved: %u (incorrect, should be 0)"),
				reserved);

	        flags = tvb_get_guint8(tvb, offset + 7);
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
	        proto_tree_add_text(ospf_db_desc_tree, tvb, offset + 7, 1, "Flags: 0x%x (%s)",
			    flags, flags_string);

	        proto_tree_add_text(ospf_db_desc_tree, tvb, offset + 8, 4, "DD Sequence: %u",
			    tvb_get_ntohl(tvb, offset + 8));

                offset += 12;
                break;

            default:
                break;
	}
    }

    /* LS Headers will be processed here */
    /* skip to the end of DB-Desc header */
    while (tvb_reported_length_remaining(tvb, offset) != 0) {
      if ( version == OSPF_VERSION_2)
          offset = dissect_ospf_v2_lsa(tvb, offset, tree, FALSE);
      else
	  if ( version == OSPF_VERSION_3)
              offset = dissect_ospf_v3_lsa(tvb, offset, tree, FALSE);
    }

}

static void
dissect_ospf_ls_req(tvbuff_t *tvb, int offset, proto_tree *tree, guint8 version)
{
    proto_tree *ospf_lsr_tree;
    proto_item *ti;
    guint32 ls_type;
    guint8 reserved;

    /* zero or more LS requests may be within a LS Request */
    /* we place every request for a LSA in a single subtree */
    while (tvb_reported_length_remaining(tvb, offset) != 0) {
	ti = proto_tree_add_text(tree, tvb, offset, OSPF_LS_REQ_LENGTH,
				 "Link State Request"); 
	ospf_lsr_tree = proto_item_add_subtree(ti, ett_ospf_lsr);
      
        reserved = tvb_get_guint8(tvb, offset);
        proto_tree_add_text(ospf_lsr_tree, tvb, offset, 1,
           (reserved == 0 ? "Reserved: %u" : "Reserved: %u (incorrect, should be 0)"),
				reserved);

        switch ( version ) {

    	    case OSPF_VERSION_2:
 	        ls_type = tvb_get_ntohl(tvb, offset);
  	        proto_tree_add_text(ospf_lsr_tree, tvb, offset, 4, "LS Type: %s (%u)",
			    val_to_str(ls_type, ls_type_vals, "Unknown"),
			    ls_type);
	        break;
    	    case OSPF_VERSION_3:
 	        ls_type = tvb_get_ntohs(tvb, offset+2);
	        proto_tree_add_text(ospf_lsr_tree, tvb, offset+2, 2, "LS Type: %s (0x%04x)",
			    val_to_str(ls_type, v3_ls_type_vals, "Unknown"),
			    ls_type);
		  break;
	    default:
	         ls_type=0;
                 break;
        }


	proto_tree_add_text(ospf_lsr_tree, tvb, offset + 4, 4, "Link State ID: %s", 
			    ip_to_str(tvb_get_ptr(tvb, offset + 4, 4)));
	proto_tree_add_text(ospf_lsr_tree, tvb, offset + 8, 4, "Advertising Router: %s", 
			    ip_to_str(tvb_get_ptr(tvb, offset + 8, 4)));

	offset += 12;
    }
}

static void
dissect_ospf_ls_upd(tvbuff_t *tvb, int offset, proto_tree *tree, guint8 version)
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
        if ( version == OSPF_VERSION_2)
	    offset = dissect_ospf_v2_lsa(tvb, offset, ospf_lsa_upd_tree, TRUE);
        else
            if ( version == OSPF_VERSION_3)
	        offset = dissect_ospf_v3_lsa(tvb, offset, ospf_lsa_upd_tree, TRUE);
        lsa_counter += 1;
    }
}

static void
dissect_ospf_ls_ack(tvbuff_t *tvb, int offset, proto_tree *tree, guint8 version)
{
    /* the body of a LS Ack packet simply contains zero or more LSA Headers */
    while (tvb_reported_length_remaining(tvb, offset) != 0) {
        if ( version == OSPF_VERSION_2)
	    offset = dissect_ospf_v2_lsa(tvb, offset, tree, FALSE);
        else
	    if ( version == OSPF_VERSION_3)
	      offset = dissect_ospf_v3_lsa(tvb, offset, tree, FALSE);
    }
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
					     "%s", stlv_name);
		    stlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link_stlv);
		    proto_tree_add_text(stlv_tree, tvb, stlv_offset, 2,
					"TLV Type: %u: %s", stlv_type, stlv_name);
		    proto_tree_add_text(stlv_tree, tvb, stlv_offset+2, 2, "TLV Length: %u",
					stlv_len);
		    /*   The Local/Remote Interface IP Address sub-TLV is TLV type 3/4, and is 4N
		       octets in length, where N is the number of neighbor addresses. */
		    for (i=0; i < stlv_len; i+=4)
		      proto_tree_add_text(stlv_tree, tvb, stlv_offset+4+i, 4, "%s: %s", stlv_name,
					  ip_to_str(tvb_get_ptr(tvb, stlv_offset+4+i, 4)));
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
					     tvb_ieee_to_long(tvb, stlv_offset + 4));
		    stlv_tree = proto_item_add_subtree(ti, ett_ospf_lsa_mpls_link_stlv);
		    proto_tree_add_text(stlv_tree, tvb, stlv_offset, 2,
					"TLV Type: %u: %s", stlv_type, stlv_name);
		    proto_tree_add_text(stlv_tree, tvb, stlv_offset+2, 2, "TLV Length: %u",
					stlv_len);
		    proto_tree_add_text(stlv_tree, tvb, stlv_offset+4, 4, "%s: %ld", stlv_name,
					tvb_ieee_to_long(tvb, stlv_offset + 4));
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
					    tvb_ieee_to_long(tvb, stlv_offset + 4 + i*4));
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
dissect_ospf_v2_lsa(tvbuff_t *tvb, int offset, proto_tree *tree,
		 gboolean disassemble_body)
{
    proto_tree *ospf_lsa_tree;
    proto_item *ti; 

    guint8		 ls_type;
    guint16		 ls_length;
    int			 end_offset;
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

    if (disassemble_body) {
	ti = proto_tree_add_text(tree, tvb, offset, ls_length,
				 "%s (Type: %u)", val_to_str(ls_type, ls_type_vals,"Unkown"), ls_type); 
    } else {
	ti = proto_tree_add_text(tree, tvb, offset, OSPF_LSA_HEADER_LENGTH,
				 "LSA Header"); 
    }
    ospf_lsa_tree = proto_item_add_subtree(ti, ett_ospf_lsa);

    proto_tree_add_text(ospf_lsa_tree, tvb, offset, 2, "LS Age: %u seconds",
			tvb_get_ntohs(tvb, offset));
    dissect_ospf_options(tvb, offset + 2, ospf_lsa_tree, OSPF_VERSION_2);
    proto_tree_add_text(ospf_lsa_tree, tvb, offset + 3, 1, "LSA Type: %u (%s)",
			ls_type, val_to_str(ls_type,ls_type_vals,"Unknown"));

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

static int
dissect_ospf_v3_lsa(tvbuff_t *tvb, int offset, proto_tree *tree,
		 gboolean disassemble_body)
{
    proto_tree *ospf_lsa_tree;
    proto_item *ti; 

    guint16		 ls_type;
    guint16		 ls_length;
    int			 end_offset;
    guint8		 nr_links;
    guint16		 nr_tos;
    guint8               reserved;

    /* router LSA */
    guint8		 link_type;
    guint16 		 link_counter;
    guint8 		 tos_counter;
    char  		*link_type_str;
    guint32              metric;

    guint8               router_lsa_flags;
    char                 router_lsa_flags_string[5];

    /* AS-external LSA */
    guint8		 options;

    /* opaque LSA */
    guint8		 ls_id_type;

    guint8               router_priority;
    guint32              number_prefixes;
    guint8               prefix_length;
    guint16              reserved16;

    guint16              referenced_ls_type;
    char                 *referenced_ls_type_str;

    guint8               flags;
    guint8               flags_string[4];
    guint32              external_route_tag;


    ls_type = tvb_get_ntohs(tvb, offset + 2);
    ls_length = tvb_get_ntohs(tvb, offset + 18);
    end_offset = offset + ls_length;

    if (disassemble_body) {
	ti = proto_tree_add_text(tree, tvb, offset, ls_length,
				 "%s (Type: 0x%04x)", val_to_str(ls_type, v3_ls_type_vals,"Unknown"), ls_type); 
    } else {
	ti = proto_tree_add_text(tree, tvb, offset, OSPF_LSA_HEADER_LENGTH,
				 "LSA Header"); 
    }
    ospf_lsa_tree = proto_item_add_subtree(ti, ett_ospf_lsa);

    proto_tree_add_text(ospf_lsa_tree, tvb, offset, 2, "LS Age: %u seconds",
			tvb_get_ntohs(tvb, offset));

    proto_tree_add_text(ospf_lsa_tree, tvb, offset + 2, 2, "LSA Type: 0x%04x (%s)",
			ls_type, val_to_str(ls_type, v3_ls_type_vals,"Unkown"));

    ls_id_type = 0;
    proto_tree_add_text(ospf_lsa_tree, tvb, offset + 4, 4, "Link State ID: %s",
			    ip_to_str(tvb_get_ptr(tvb, offset + 4, 4)));

    proto_tree_add_text(ospf_lsa_tree, tvb, offset + 8, 4, "Advertising Router: %s",
			ip_to_str(tvb_get_ptr(tvb, offset + 8, 4)));
    proto_tree_add_text(ospf_lsa_tree, tvb, offset + 12, 4, "LS Sequence Number: %d",
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


    case OSPF_V3_LSTYPE_ROUTER:

      /* flags field in an router-lsa */
        router_lsa_flags=tvb_get_guint8(tvb,offset);
        if (router_lsa_flags & OSPF_V3_ROUTER_LSA_FLAG_B)
	    router_lsa_flags_string[3] = 'B';
        else
	    router_lsa_flags_string[3] = '.';
        if (router_lsa_flags & OSPF_V3_ROUTER_LSA_FLAG_E)
	    router_lsa_flags_string[2] = 'E';
        else
	    router_lsa_flags_string[2] = '.';
        if (router_lsa_flags & OSPF_V3_ROUTER_LSA_FLAG_V)
	    router_lsa_flags_string[1] = 'V';
        else
	    router_lsa_flags_string[1] = '.';
        if (router_lsa_flags & OSPF_V3_ROUTER_LSA_FLAG_W)
	    router_lsa_flags_string[0] = 'W';
        else
	    router_lsa_flags_string[0] = '.';

        router_lsa_flags_string[4]=0;

	proto_tree_add_text(ospf_lsa_tree, tvb, offset, 1, "Flags: 0x%02x (%s)",
			    router_lsa_flags, router_lsa_flags_string);

        /* options field in an router-lsa */
        dissect_ospf_options(tvb, offset + 1, ospf_lsa_tree, OSPF_VERSION_3);

        /* skip the router-lsa flags and options */
        offset+=4;
        ls_length-=4;

        if (ls_length > 0)
	     proto_tree_add_text(ospf_lsa_tree, tvb, offset, ls_length,
		   "Router Interfaces:"); 

        /* scan all router-lsa router interfaces */
	/* maybe we should put each of the links into its own subtree ??? */
        while (ls_length > 0 ) {

	    /* check the type */
	    link_type = tvb_get_guint8(tvb, offset);
	    switch (link_type) {

   	        case OSPF_V3_LINK_PTP:
                    link_type_str="Point-to-point connection to another router";
		    break;

	        case OSPF_V3_LINK_TRANSIT:
		    link_type_str="Connection to a transit network";
		    break;

	        case OSPF_V3_LINK_RESERVED:
		    link_type_str="Connection to a stub network";
		    break;

	        case OSPF_V3_LINK_VIRTUAL:
		    link_type_str="Virtual link";
		    break;

	        default:
		    link_type_str="Unknown link type";
		    break;
	    }

	    proto_tree_add_text(ospf_lsa_tree, tvb, offset, 1, "Type: %u (%s)", link_type,link_type_str);

	    /* reserved field */
 	    reserved = tvb_get_guint8(tvb, offset+1);
	    proto_tree_add_text(ospf_lsa_tree, tvb, offset+1, 1,
	       (reserved == 0 ? "Reserved: %u" : "Reserved: %u (incorrect, should be 0)"),reserved);

	    /* metric */
            metric=tvb_get_ntohs(tvb, offset+2);
	    proto_tree_add_text(ospf_lsa_tree, tvb, offset + 2, 2,"Metric: %u",metric);

	    /* Interface ID */
            proto_tree_add_text(ospf_lsa_tree, tvb, offset + 4, 4, "Interface ID: %u",
			tvb_get_ntohl(tvb, offset + 4));

	    /* Neighbor Interface ID */
            proto_tree_add_text(ospf_lsa_tree, tvb, offset + 8, 4, "Neighbor Interface ID: %u",
			tvb_get_ntohl(tvb, offset + 8));

	    /* Neighbor Router ID */
            proto_tree_add_text(ospf_lsa_tree, tvb, offset + 12, 4, "Neighbor Router ID: %s",
		ip_to_str(tvb_get_ptr(tvb, offset + 12, 4)));

            /* skip to the (possible) next entry */
            offset+=16;
            ls_length-=16;

        }
	break;

    case OSPF_V3_LSTYPE_NETWORK:

	/* reserved field */
 	reserved = tvb_get_guint8(tvb, offset);
	proto_tree_add_text(ospf_lsa_tree, tvb, offset, 1,
	       (reserved == 0 ? "Reserved: %u" : "Reserved: %u (incorrect, should be 0)"),reserved);

        /* options field in an network-lsa */
        dissect_ospf_options(tvb, offset + 1, ospf_lsa_tree, OSPF_VERSION_3);

	offset += 4;
        ls_length-=4;

	while (ls_length > 0 ) {
	    proto_tree_add_text(ospf_lsa_tree, tvb, offset, 4, "Attached Router: %s",
				ip_to_str(tvb_get_ptr(tvb, offset, 4)));
            ls_length-=4;
	    offset += 4;
	}
	break;


    case OSPF_V3_LSTYPE_INTER_AREA_PREFIX:

	/* reserved field */
 	reserved = tvb_get_guint8(tvb, offset);
	proto_tree_add_text(ospf_lsa_tree, tvb, offset, 1,
	       (reserved == 0 ? "Reserved: %u" : "Reserved: %u (incorrect, should be 0)"),reserved);

	/* metric */
        metric=tvb_get_ntoh24(tvb, offset+11);
	proto_tree_add_text(ospf_lsa_tree, tvb, offset + 1, 3,"Metric: %u",metric);

	/* prefix length */
	prefix_length=tvb_get_guint8(tvb, offset+4);
	proto_tree_add_text(ospf_lsa_tree, tvb, offset+4, 1, "PrefixLength: %u",prefix_length);

	/* prefix options */
        dissect_ospf_v3_prefix_options(tvb, offset+5, ospf_lsa_tree);

        /* 16 bits reserved */
	reserved16=tvb_get_ntohs(tvb, offset+6);
	proto_tree_add_text(ospf_lsa_tree, tvb, offset+6, 2,
	       (reserved16 == 0 ? "Reserved: %u" : "Reserved: %u (incorrect, should be 0)"),reserved16);

        offset+=8;

        /* address_prefix */
        dissect_ospf_v3_address_prefix(tvb, offset, prefix_length, ospf_lsa_tree);

        offset+=(prefix_length+31)/32*4;

        break;


    case OSPF_V3_LSTYPE_INTER_AREA_ROUTER:

	/* reserved field */
 	reserved = tvb_get_guint8(tvb, offset);
	proto_tree_add_text(ospf_lsa_tree, tvb, offset, 1,
	       (reserved == 0 ? "Reserved: %u" : "Reserved: %u (incorrect, should be 0)"),reserved);

        /* options field in an inter-area-router-lsa */
        dissect_ospf_options(tvb, offset + 1, ospf_lsa_tree, OSPF_VERSION_3);

	/* reserved field */
 	reserved = tvb_get_guint8(tvb, offset+4);
	proto_tree_add_text(ospf_lsa_tree, tvb, offset+4, 1,
	       (reserved == 0 ? "Reserved: %u" : "Reserved: %u (incorrect, should be 0)"),reserved);

	/* metric */
        metric=tvb_get_ntoh24(tvb, offset+6);
	proto_tree_add_text(ospf_lsa_tree, tvb, offset + 6, 3,"Metric: %u",metric);

	/* Destination Router ID */
        proto_tree_add_text(ospf_lsa_tree, tvb, offset + 8, 4, "Destination Router ID: %s",
		ip_to_str(tvb_get_ptr(tvb, offset + 8, 4)));

	offset+=12;
	break;


    case OSPF_V3_LSTYPE_AS_EXTERNAL:

        /* flags */
        flags=tvb_get_guint8(tvb, offset);
        if (flags & OSPF_V3_AS_EXTERNAL_FLAG_E)
	    flags_string[0] = 'E';
        else
	    flags_string[0] = '.';
        if (flags & OSPF_V3_AS_EXTERNAL_FLAG_F)
	    flags_string[1] = 'F';
        else
	    flags_string[1] = '.';
        if (flags & OSPF_V3_AS_EXTERNAL_FLAG_T)
	    flags_string[2] = 'T';
        else
	    flags_string[2] = '.';

        flags_string[3]=0;

	proto_tree_add_text(ospf_lsa_tree, tvb, offset, 1, "Flags: 0x%02x (%s)",
			    flags, flags_string);
        
	/* 24 bits metric */
	metric=tvb_get_ntohs(tvb, offset+1);
	proto_tree_add_text(ospf_lsa_tree, tvb, offset+1, 3,
				"Metric: %u", metric);

	/* prefix length */
	prefix_length=tvb_get_guint8(tvb, offset+4);
	proto_tree_add_text(ospf_lsa_tree, tvb, offset+4, 1, "PrefixLength: %u",prefix_length);

	/* prefix options */
        dissect_ospf_v3_prefix_options(tvb, offset+5, ospf_lsa_tree);

        /* referenced LS type */
        referenced_ls_type=tvb_get_ntohs(tvb, offset+6);
	proto_tree_add_text(ospf_lsa_tree, tvb, offset+2, 2,"Referenced LS type  0x%04x (%s)",
			    referenced_ls_type, val_to_str(referenced_ls_type, v3_ls_type_vals, "Unknown"));

        offset+=8;

        /* address_prefix */
        dissect_ospf_v3_address_prefix(tvb, offset, prefix_length, ospf_lsa_tree);
       
        offset+=(prefix_length+31)/32*4;

        /* Forwarding Address (optional - only if F-flag is on) */
        if ( (offset < end_offset) && (flags & OSPF_V3_AS_EXTERNAL_FLAG_F) ) {
	    proto_tree_add_text(ospf_lsa_tree, tvb, offset, 16,"Forwarding Address: %s",
              ip6_to_str((struct e_in6_addr *)tvb_get_ptr(tvb, offset, 16)));

	    offset+=16;
        }

        /* External Route Tag (optional - only if T-flag is on) */
        if ( (offset < end_offset) && (flags & OSPF_V3_AS_EXTERNAL_FLAG_T) ) {
	    external_route_tag=tvb_get_ntohl(tvb, offset);
	    proto_tree_add_text(ospf_lsa_tree, tvb, offset, 4,"External Route Tag: 0x%04x",
				external_route_tag);

	    offset+=4;
        }

        /* Referenced Link State ID (optional - only if Referenced LS type is non-zero */
        if ( (offset < end_offset) && (referenced_ls_type != 0) ) {
	    proto_tree_add_text(ospf_lsa_tree, tvb, offset, 4, "Referenced Link State ID: %s", 
			    ip_to_str(tvb_get_ptr(tvb, offset, 4)));
	    offset+=4;
        }

        break;

    case OSPF_V3_LSTYPE_LINK:

        /* router priority */
        router_priority=tvb_get_guint8(tvb, offset);
        proto_tree_add_text(ospf_lsa_tree, tvb, offset, 1, "Router Priority: %u", router_priority);

        /* options field in an link-lsa */
        dissect_ospf_options(tvb, offset + 1, ospf_lsa_tree, OSPF_VERSION_3);

        /* Link-local Interface Address */
        proto_tree_add_text(ospf_lsa_tree, tvb, offset + 4, 16, "Link-local Interface Address: %s",
           ip6_to_str((struct e_in6_addr *)tvb_get_ptr(tvb, offset + 4, 16)));

        /* Number prefixes */
        number_prefixes=tvb_get_ntohl(tvb, offset + 20);
	proto_tree_add_text(ospf_lsa_tree, tvb, offset+20, 4, "# prefixes: %d",number_prefixes);

        offset+=24;

        while (number_prefixes > 0) {

	    /* prefix length */
	    prefix_length=tvb_get_guint8(tvb, offset);
	    proto_tree_add_text(ospf_lsa_tree, tvb, offset, 1, "PrefixLength: %u",prefix_length);

	    /* prefix options */
            dissect_ospf_v3_prefix_options(tvb, offset+1, ospf_lsa_tree);

	    /* 16 bits reserved */
	    reserved16=tvb_get_ntohs(tvb, offset+2);
	    proto_tree_add_text(ospf_lsa_tree, tvb, offset+2, 2,
	       (reserved16 == 0 ? "Reserved: %u" : "Reserved: %u (incorrect, should be 0)"),reserved16);

            offset+=4;

            /* address_prefix */
            dissect_ospf_v3_address_prefix(tvb, offset, prefix_length, ospf_lsa_tree);
       
            offset+=(prefix_length+31)/32*4;

            number_prefixes--;

        }             
        break;

    case OSPF_V3_LSTYPE_INTRA_AREA_PREFIX:

        /* # prefixes */
        number_prefixes=tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(ospf_lsa_tree, tvb, offset, 2,"# prefixes: %u",number_prefixes);

        /* referenced LS type */
        referenced_ls_type=tvb_get_ntohs(tvb, offset+2);
	proto_tree_add_text(ospf_lsa_tree, tvb, offset+2, 2,"Referenced LS type  0x%04x (%s)",
			    referenced_ls_type, val_to_str(referenced_ls_type, v3_ls_type_vals, "Unknown"));

        /* Referenced Link State ID */
	proto_tree_add_text(ospf_lsa_tree, tvb, offset + 4, 4, "Referenced Link State ID: %s", 
			    ip_to_str(tvb_get_ptr(tvb, offset + 4, 4)));

        /* Referenced Advertising Router */
	proto_tree_add_text(ospf_lsa_tree, tvb, offset + 8, 4, "Referenced Advertising Router: %s", 
			    ip_to_str(tvb_get_ptr(tvb, offset + 8, 4)));

        offset+=12;

        while (number_prefixes > 0) {

	    /* prefix length */
	    prefix_length=tvb_get_guint8(tvb, offset);
	    proto_tree_add_text(ospf_lsa_tree, tvb, offset, 1, "PrefixLength: %u",prefix_length);

	    /* prefix options */
            dissect_ospf_v3_prefix_options(tvb, offset+1, ospf_lsa_tree);

	    /* 16 bits metric */
	    metric=tvb_get_ntohs(tvb, offset+2);
	    proto_tree_add_text(ospf_lsa_tree, tvb, offset+2, 2,
				"Metric: %u", metric);

            offset+=4;

            /* address_prefix */
            dissect_ospf_v3_address_prefix(tvb, offset, prefix_length, ospf_lsa_tree);
       
            offset+=(prefix_length+31)/32*4;

            number_prefixes--;
        }
        break;

    default:
	/* unknown LSA type */
	proto_tree_add_text(ospf_lsa_tree, tvb, offset, ls_length,
			    "Unknown LSA Type 0x%04x",ls_type);
	offset += ls_length;
	break;
    }
    /* return the offset of the next LSA */
    return offset;
}


static void
dissect_ospf_options(tvbuff_t *tvb, int offset, proto_tree *tree, guint8 version)
{
    guint8 options_ospfv2;
    guint32 options_ospfv3;
    char options_string[20] = "";

    /* ATTENTION !!! no check for length of options string  - with OSPFv3 maximum length is 14 characters */

    switch ( version ) {

        case OSPF_VERSION_2:

            options_ospfv2 = tvb_get_guint8(tvb, offset);

            if (options_ospfv2 & OSPF_V2_OPTIONS_E)
	        strcat(options_string, "E");

            if (options_ospfv2 & OSPF_V2_OPTIONS_MC) {
	        if (options_string[0] != '\0')
	            strcat(options_string, "/");
	        strcat(options_string, "MC");
            }

            if (options_ospfv2 & OSPF_V2_OPTIONS_NP) {
	        if (options_string[0] != '\0')
	            strcat(options_string, "/");
	        strcat(options_string, "NP");
            }

            if (options_ospfv2 & OSPF_V2_OPTIONS_EA) {
	        if (options_string[0] != '\0')
	            strcat(options_string, "/");
	        strcat(options_string, "EA");
            }

            if (options_ospfv2 & OSPF_V2_OPTIONS_DC) {
	        if (options_string[0] != '\0')
	            strcat(options_string, "/");
	        strcat(options_string, "DC");
            }

            if (options_ospfv2 & OSPF_V2_OPTIONS_O) {
	        if (options_string[0] != '\0')
	            strcat(options_string, "/");
	        strcat(options_string, "O");
            }

            if (options_ospfv2 & OSPF_V2_OPTIONS_DN) {
    	        if (options_string[0] != '\0')
	            strcat(options_string, "/");
	        strcat(options_string, "DN");  
            }

            proto_tree_add_text(tree, tvb, offset, 1, "Options: 0x%x (%s)",
			options_ospfv2, options_string);
	    break;


        case OSPF_VERSION_3:

            options_ospfv3 = tvb_get_ntoh24(tvb, offset);

            if (options_ospfv3 & OSPF_V3_OPTIONS_V6)
	        strcat(options_string, "V6");

            if (options_ospfv3 & OSPF_V3_OPTIONS_E)
	        if (options_string[0] != '\0')
	            strcat(options_string, "/");
	        strcat(options_string, "E");

            if (options_ospfv3 & OSPF_V3_OPTIONS_MC) {
	        if (options_string[0] != '\0')
	            strcat(options_string, "/");
	        strcat(options_string, "MC");
            }

            if (options_ospfv3 & OSPF_V3_OPTIONS_N) {
	        if (options_string[0] != '\0')
	            strcat(options_string, "/");
	        strcat(options_string, "N");
            }

            if (options_ospfv3 & OSPF_V3_OPTIONS_R) {
	        if (options_string[0] != '\0')
	            strcat(options_string, "/");
	        strcat(options_string, "R");
            }

            if (options_ospfv3 & OSPF_V3_OPTIONS_DC) {
	        if (options_string[0] != '\0')
	            strcat(options_string, "/");
	        strcat(options_string, "DC");
            }

            proto_tree_add_text(tree, tvb, offset, 3, "Options: 0x%x (%s)",
			options_ospfv3, options_string);
            break;

        default:
            break;
    }

}


static void dissect_ospf_v3_prefix_options(tvbuff_t *tvb, int offset, proto_tree *tree)
{

    guint8 prefix_options;
    char prefix_options_string[11];
    guint8 position;

    position=0;
    
    prefix_options=tvb_get_guint8(tvb, offset);

    strcpy(prefix_options_string,"");

    if (prefix_options & OSPF_V3_PREFIX_OPTION_P) {
        strcat(prefix_options_string, "P");
        position++;
    }

    if (prefix_options & OSPF_V3_PREFIX_OPTION_MC) {
        if ( (position > 0) && (prefix_options_string[position-1] != '/') ) {
            strcat(prefix_options_string, "/");
            position++;
        }
        strcat(prefix_options_string, "MC");
        position+=2;
    }

    if (prefix_options & OSPF_V3_PREFIX_OPTION_LA) {
        if ( (position > 0) && (prefix_options_string[position-1] != '/') ) {
            strcat(prefix_options_string, "/");
            position++;
        }
        strcat(prefix_options_string, "LA");
        position+=2;
    }

    if (prefix_options & OSPF_V3_PREFIX_OPTION_NU) {
        if ( (position > 0) && (prefix_options_string[position-1] != '/') ) {
            strcat(prefix_options_string, "/");
            position++;
        }
        strcat(prefix_options_string, "NU");
    }

    prefix_options_string[10]=0;

    proto_tree_add_text(tree, tvb, offset, 1, "PrefixOptions: 0x%02x (%s)",prefix_options, prefix_options_string);

}


static void dissect_ospf_v3_address_prefix(tvbuff_t *tvb, int offset, int prefix_length, proto_tree *tree)
{

    guint8 value;
    guint8 position;
    guint8 bufpos;
    gchar  buffer[32+7];
    gchar  bytebuf[3];
    guint8 bytes_to_process;
    int start_offset;

    start_offset=offset;
    position=0;
    bufpos=0;
    bytes_to_process=((prefix_length+31)/32)*4;

    while (bytes_to_process > 0 ) {

        value=tvb_get_guint8(tvb, offset);

        if ( (position > 0) && ( (position%2) == 0 ) )
	    buffer[bufpos++]=':';

        sprintf(bytebuf,"%02x",value);
        buffer[bufpos++]=bytebuf[0];        
        buffer[bufpos++]=bytebuf[1];        
        
	position++;
	offset++;
        bytes_to_process--;
    }

    buffer[bufpos]=0;  
    proto_tree_add_text(tree, tvb, start_offset, ((prefix_length+31)/32)*4, "Address Prefix: %s",buffer);

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
    dissector_add("ip.proto", IP_PROTO_OSPF, dissect_ospf, proto_ospf);
}
