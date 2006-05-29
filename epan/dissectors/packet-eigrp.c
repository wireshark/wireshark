/* packet-eigrp.c
 * Routines for EIGRP dissection
 * Copyright 2000, Paul Ionescu <paul@acorp.ro>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/addr_resolv.h>

#include <epan/atalk-utils.h>
#include <epan/addr_and_mask.h>
#include <epan/ipproto.h>
#include "packet-ipx.h"

/*
 * See
 *
 *	http://www.rhyshaden.com/eigrp.htm
 */

#define EIGRP_UPDATE    0x01
#define EIGRP_REQUEST   0x02
#define EIGRP_QUERY     0x03
#define EIGRP_REPLY     0x04
#define EIGRP_HELLO     0x05
#define EIGRP_SAP	0x06
#define EIGRP_HI	0x20  /* This value is for my own need to make a difference between Hello and Ack */
#define EIGRP_ACK	0x40  /* This value is for my own need to make a difference between Hello and Ack */

#define TLV_PAR		0x0001
#define TLV_AUTH	0x0002
#define TLV_SEQ		0x0003
#define TLV_SV		0x0004
#define TLV_NMS		0x0005
#define TLV_IP_INT	0x0102
#define TLV_IP_EXT	0x0103
#define TLV_AT_INT	0x0202
#define TLV_AT_EXT	0x0203
#define TLV_AT_CBL	0x0204
#define TLV_IPX_INT	0x0302
#define TLV_IPX_EXT	0x0303

#define EIGRP_HEADER_LENGTH	20

static gint proto_eigrp = -1;

static gint hf_eigrp_opcode = -1;
static gint hf_eigrp_as = -1;
static gint hf_eigrp_tlv = -1;

static gint ett_eigrp = -1;
static gint ett_tlv = -1;

static dissector_handle_t ipxsap_handle;


static const value_string eigrp_opcode_vals[] = {
	{ EIGRP_HELLO,		"Hello/Ack" },
	{ EIGRP_UPDATE,		"Update" },
   	{ EIGRP_REPLY, 		"Reply" },
   	{ EIGRP_QUERY, 		"Query" },
	{ EIGRP_REQUEST,	"Request" },
	{ EIGRP_SAP,		"IPX/SAP Update" },
	{ EIGRP_HI,		"Hello" },
	{ EIGRP_ACK,		"Acknowledge" },
	{ 0,				NULL }
};

static const value_string eigrp_tlv_vals[] = {
	{ TLV_PAR,     "EIGRP Parameters"},
	{ TLV_AUTH,    "Authentication data"},
	{ TLV_SEQ ,    "Sequence"},
	{ TLV_SV,      "Software Version"},
	{ TLV_NMS   ,  "Next multicast sequence"},
	{ TLV_IP_INT,  "IP internal route"},
	{ TLV_IP_EXT,  "IP external route"},
	{ TLV_AT_INT,  "AppleTalk internal route"},
	{ TLV_AT_EXT,  "AppleTalk external route"},
	{ TLV_AT_CBL,  "AppleTalk cable configuration"},
	{ TLV_IPX_INT, "IPX internal route"},
	{ TLV_IPX_EXT, "IPX external route"},
	{ 0,		NULL}
};

static const value_string eigrp_pid_vals[] = {
	{ 1,	"IGRP"},
	{ 2,	"EIGRP"},
	{ 3,	"Static Route"},
	{ 4,	"RIP"},
	{ 5,	"Hello"},
	{ 6,	"OSPF"},
	{ 7,	"IS-IS"},
	{ 8,	"EGP"},
	{ 9,	"BGP"},
	{ 10,	"IDRP"},
	{ 11,	"Connected link"},
	{ 0,	NULL}
};


static void dissect_eigrp_par (tvbuff_t *tvb, proto_tree *tree);
static void dissect_eigrp_seq (tvbuff_t *tvb, proto_tree *tree);
static void dissect_eigrp_sv  (tvbuff_t *tvb, proto_tree *tree, proto_item *ti);
static void dissect_eigrp_nms (tvbuff_t *tvb, proto_tree *tree, proto_item *ti);

static void dissect_eigrp_ip_int (tvbuff_t *tvb, proto_tree *tree, proto_item *ti);
static void dissect_eigrp_ip_ext (tvbuff_t *tvb, proto_tree *tree, proto_item *ti);

static void dissect_eigrp_ipx_int (tvbuff_t *tvb, proto_tree *tree, proto_item *ti);
static void dissect_eigrp_ipx_ext (tvbuff_t *tvb, proto_tree *tree, proto_item *ti);

static void dissect_eigrp_at_cbl (tvbuff_t *tvb, proto_tree *tree, proto_item *ti);
static void dissect_eigrp_at_int (tvbuff_t *tvb, proto_tree *tree, proto_item *ti);
static void dissect_eigrp_at_ext (tvbuff_t *tvb, proto_tree *tree, proto_item *ti);

static void
dissect_eigrp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {

  proto_tree *eigrp_tree,*tlv_tree;
  proto_item *ti;

  guint opcode,opcode_tmp;
  guint16 tlv;
  guint32 ack, size, offset = EIGRP_HEADER_LENGTH;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "EIGRP");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  opcode_tmp=opcode=tvb_get_guint8(tvb,1);
  ack = tvb_get_ntohl(tvb,12);
  if (opcode==EIGRP_HELLO) { if (ack == 0) opcode_tmp=EIGRP_HI; else opcode_tmp=EIGRP_ACK; }

  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_str(pinfo->cinfo, COL_INFO,
	val_to_str(opcode_tmp , eigrp_opcode_vals, "Unknown (0x%04x)"));




  if (tree) {

     ti = proto_tree_add_protocol_format(tree, proto_eigrp, tvb, 0, -1,
              "Cisco EIGRP");

     eigrp_tree = proto_item_add_subtree(ti, ett_eigrp);

     proto_tree_add_text (eigrp_tree, tvb, 0,1,"Version    = %u",tvb_get_guint8(tvb,0)) ;
     proto_tree_add_uint_format (eigrp_tree, hf_eigrp_opcode, tvb, 1,1,opcode,"Opcode = %u (%s)",opcode,val_to_str(opcode_tmp,eigrp_opcode_vals, "Unknown")) ;
     proto_tree_add_text (eigrp_tree, tvb, 2,2,"Checksum   = 0x%04x",tvb_get_ntohs(tvb,2)) ;
     proto_tree_add_text (eigrp_tree, tvb, 4,4,"Flags      = 0x%08x",tvb_get_ntohl(tvb,4)) ;
     proto_tree_add_text (eigrp_tree, tvb, 8,4,"Sequence   = %u",tvb_get_ntohl(tvb,8)) ;
     proto_tree_add_text (eigrp_tree, tvb, 12,4,"Acknowledge  = %u",tvb_get_ntohl(tvb,12)) ;
     proto_tree_add_uint (eigrp_tree, hf_eigrp_as, tvb, 16,4,tvb_get_ntohl(tvb,16)) ;

     if (opcode==EIGRP_SAP)
     	{
	call_dissector(ipxsap_handle, tvb_new_subset(tvb, EIGRP_HEADER_LENGTH, -1, -1), pinfo, eigrp_tree);
	return;
	}

     while ( tvb_reported_length_remaining(tvb,offset)>0 ) {

	     tlv = tvb_get_ntohs(tvb,offset);
	     size =  tvb_get_ntohs(tvb,offset+2);
	     if ( size == 0 )
		{
		proto_tree_add_text(eigrp_tree,tvb,offset,-1,"Unknown data (maybe authentication)");
		return;
		}

	     ti = proto_tree_add_text (eigrp_tree, tvb, offset,size,
	         "%s",val_to_str(tlv, eigrp_tlv_vals, "Unknown (0x%04x)"));

	     tlv_tree = proto_item_add_subtree (ti, ett_tlv);
	     proto_tree_add_uint_format (tlv_tree,hf_eigrp_tlv, tvb,offset,2,tlv,"Type = 0x%04x (%s)",tlv,val_to_str(tlv,eigrp_tlv_vals, "Unknown")) ;
	     proto_tree_add_text (tlv_tree,tvb,offset+2,2,"Size = %u bytes",size) ;


	     switch (tlv){
	     	case TLV_PAR:
	     		dissect_eigrp_par(tvb_new_subset(tvb, offset+4, size-4, -1), tlv_tree);
	     		break;
	     	case TLV_SEQ:
	     		dissect_eigrp_seq(tvb_new_subset(tvb, offset+4, size-4, -1), tlv_tree);
	     		break;
	     	case TLV_SV:
	     		dissect_eigrp_sv(tvb_new_subset(tvb, offset+4, size-4, -1), tlv_tree, ti);
     			break;
	     	case TLV_NMS:
     			dissect_eigrp_nms(tvb_new_subset(tvb, offset+4, size-4, -1), tlv_tree, ti);
     			break;

	     	case TLV_IP_INT:
     			dissect_eigrp_ip_int(tvb_new_subset(tvb, offset+4, size-4, -1), tlv_tree, ti);
     			break;
	     	case TLV_IP_EXT:
     			dissect_eigrp_ip_ext(tvb_new_subset(tvb, offset+4, size-4, -1), tlv_tree, ti);
     			break;

	     	case TLV_IPX_INT:
     			dissect_eigrp_ipx_int(tvb_new_subset(tvb, offset+4, size-4, -1), tlv_tree, ti);
     			break;
	     	case TLV_IPX_EXT:
     			dissect_eigrp_ipx_ext(tvb_new_subset(tvb, offset+4, size-4, -1), tlv_tree, ti);
     			break;

	     	case TLV_AT_CBL:
     			dissect_eigrp_at_cbl(tvb_new_subset(tvb, offset+4, size-4, -1), tlv_tree, ti);
     			break;
	     	case TLV_AT_INT:
     			dissect_eigrp_at_int(tvb_new_subset(tvb, offset+4, size-4, -1), tlv_tree, ti);
     			break;
	     	case TLV_AT_EXT:
     			dissect_eigrp_at_ext(tvb_new_subset(tvb, offset+4, size-4, -1), tlv_tree, ti);
     			break;
		case TLV_AUTH:
			proto_tree_add_text(tlv_tree,tvb,offset+4,size-4,"Authentication data");
			break;
	     }

	     offset+=size;
     }

   }
}



static void dissect_eigrp_par (tvbuff_t *tvb, proto_tree *tree)	{
	proto_tree_add_text (tree,tvb,0,1,"K1 = %u",tvb_get_guint8(tvb,0));
	proto_tree_add_text (tree,tvb,1,1,"K2 = %u",tvb_get_guint8(tvb,1));
	proto_tree_add_text (tree,tvb,2,1,"K3 = %u",tvb_get_guint8(tvb,2));
	proto_tree_add_text (tree,tvb,3,1,"K4 = %u",tvb_get_guint8(tvb,3));
	proto_tree_add_text (tree,tvb,4,1,"K5 = %u",tvb_get_guint8(tvb,4));
	proto_tree_add_text (tree,tvb,5,1,"Reserved");
	proto_tree_add_text (tree,tvb,6,2,"Hold Time = %u",tvb_get_ntohs(tvb,6));
}

static void dissect_eigrp_seq (tvbuff_t *tvb, proto_tree *tree)
{	guint8 addr_len;
	addr_len=tvb_get_guint8(tvb,0);
        proto_tree_add_text (tree,tvb,0,1,"Address length = %u",addr_len);
	switch (addr_len){
		case 4:
		        proto_tree_add_text (tree,tvb,1,addr_len,"IP Address = %u.%u.%u.%u",tvb_get_guint8(tvb,1),tvb_get_guint8(tvb,2),tvb_get_guint8(tvb,3),tvb_get_guint8(tvb,4));
			break;
		case 10:
			proto_tree_add_text (tree,tvb,1,addr_len,"IPX Address = %08x.%04x.%04x.%04x",tvb_get_ntohl(tvb,1),tvb_get_ntohs(tvb,5),tvb_get_ntohs(tvb,7),tvb_get_ntohs(tvb,9));
			break;
		default:
			/* nothing */
			;
		}
}

static void dissect_eigrp_sv (tvbuff_t *tvb, proto_tree *tree, proto_item *ti)
{
        guint8 ios_rel_major, ios_rel_minor;
        guint8 eigrp_rel_major, eigrp_rel_minor;

        ios_rel_major = tvb_get_guint8(tvb,0);
        ios_rel_minor = tvb_get_guint8(tvb,1);
        proto_tree_add_text (tree,tvb,0,2," IOS  release version = %u.%u",
                             ios_rel_major, ios_rel_minor);
        proto_item_append_text (ti,": IOS=%u.%u", ios_rel_major, ios_rel_minor);

        eigrp_rel_major = tvb_get_guint8(tvb,2);
        eigrp_rel_minor = tvb_get_guint8(tvb,3);
        proto_tree_add_text (tree,tvb,2,2,"EIGRP release version = %u.%u",
                             eigrp_rel_major, eigrp_rel_minor);
        proto_item_append_text (ti,", EIGRP=%u.%u",
                                eigrp_rel_major, eigrp_rel_minor);
}

static void dissect_eigrp_nms (tvbuff_t *tvb, proto_tree *tree, proto_item *ti)
{
        proto_tree_add_text (tree,tvb,0,4,"Next Multicast Sequence = %u",tvb_get_ntohl(tvb,0));
	proto_item_append_text (ti,": %u",tvb_get_ntohl(tvb,0));
}



static void dissect_eigrp_ip_int (tvbuff_t *tvb, proto_tree *tree, proto_item *ti)
{
	guint8 ip_addr[4],length;
	int addr_len;

	tvb_memcpy(tvb,ip_addr,0,4);
	proto_tree_add_text (tree,tvb,0,4, "Next Hop    = %s",ip_to_str(ip_addr));
	proto_tree_add_text (tree,tvb,4,4, "Delay       = %u",tvb_get_ntohl(tvb,4));
	proto_tree_add_text (tree,tvb,8,4, "Bandwidth   = %u",tvb_get_ntohl(tvb,8));
	proto_tree_add_text (tree,tvb,12,3,"MTU         = %u",tvb_get_ntoh24(tvb,12));
	proto_tree_add_text (tree,tvb,15,1,"Hop Count   = %u",tvb_get_guint8(tvb,15));
	proto_tree_add_text (tree,tvb,16,1,"Reliability = %u",tvb_get_guint8(tvb,16));
	proto_tree_add_text (tree,tvb,17,1,"Load        = %u",tvb_get_guint8(tvb,17));
	proto_tree_add_text (tree,tvb,18,2,"Reserved ");
	length=tvb_get_guint8(tvb,20);
	/* XXX - the EIGRP page whose URL appears at the top says this
	   field is 24 bits; what if the prefix length is > 24? */
	addr_len=ipv4_addr_and_mask (tvb,21,ip_addr,length);
	if (addr_len < 0) {
	    proto_tree_add_text (tree,tvb,20,1,"Prefix length = %u (invalid, must be <= 32)",length);
	    proto_item_append_text (ti,"  [Invalid prefix length %u > 32]",length);
	} else {
	    proto_tree_add_text (tree,tvb,20,1,"Prefix Length = %u",length);
	    proto_tree_add_text (tree,tvb,21,addr_len,"Destination = %s",ip_to_str(ip_addr));
	    proto_item_append_text (ti,"  =   %s/%u%s",ip_to_str(ip_addr),length,((tvb_get_ntohl(tvb,4)==0xffffffff)?" - Destination unreachable":""));
	}
}

static void dissect_eigrp_ip_ext (tvbuff_t *tvb, proto_tree *tree, proto_item *ti)
{
	guint8 ip_addr[4],length;
	int addr_len;

	tvb_memcpy(tvb,ip_addr,0,4);
	proto_tree_add_text (tree,tvb,0,4,"Next Hop = %s",ip_to_str(ip_addr));
	tvb_memcpy(tvb,ip_addr,4,4);
	proto_tree_add_text (tree,tvb,4,4,"Originating router = %s",ip_to_str(ip_addr));
	proto_tree_add_text (tree,tvb,8,4,"Originating A.S. = %u",tvb_get_ntohl(tvb,8));
	proto_tree_add_text (tree,tvb,12,4,"Arbitrary tag = %u",tvb_get_ntohl(tvb,12));
	proto_tree_add_text (tree,tvb,16,4,"External protocol metric = %u",tvb_get_ntohl(tvb,16));
	proto_tree_add_text (tree,tvb,20,2,"Reserved");
	proto_tree_add_text (tree,tvb,22,1,"External protocol ID = %u (%s)",tvb_get_guint8(tvb,22),val_to_str(tvb_get_guint8(tvb,22),eigrp_pid_vals, "Unknown"));
	proto_tree_add_text (tree,tvb,23,1,"Flags = 0x%0x",tvb_get_guint8(tvb,23));

	proto_tree_add_text (tree,tvb,24,4,"Delay     = %u",tvb_get_ntohl(tvb,24));
	proto_tree_add_text (tree,tvb,28,4,"Bandwidth = %u",tvb_get_ntohl(tvb,28));
	proto_tree_add_text (tree,tvb,32,3,"MTU    = %u",tvb_get_ntoh24(tvb,32));
	proto_tree_add_text (tree,tvb,35,1,"Hop Count = %u",tvb_get_guint8(tvb,35));
	proto_tree_add_text (tree,tvb,36,1,"Reliability = %u",tvb_get_guint8(tvb,36));
	proto_tree_add_text (tree,tvb,37,1,"Load = %u",tvb_get_guint8(tvb,37));
	proto_tree_add_text (tree,tvb,38,2,"Reserved ");
	length=tvb_get_guint8(tvb,40);
	/* XXX - the EIGRP page whose URL appears at the top says this
	   field is 24 bits; what if the prefix length is > 24? */
	addr_len=ipv4_addr_and_mask (tvb,41,ip_addr,length);
	if (addr_len < 0) {
	    proto_tree_add_text (tree,tvb,40,1,"Prefix length = %u (invalid, must be <= 32)",length);
	    proto_item_append_text (ti,"  [Invalid prefix length %u > 32]",length);
	} else {
	    proto_tree_add_text (tree,tvb,40,1,"Prefix Length = %u",length);
	    proto_tree_add_text (tree,tvb,41,addr_len,"Destination = %s",ip_to_str(ip_addr));
	    proto_item_append_text (ti,"  =   %s/%u%s",ip_to_str(ip_addr),length,((tvb_get_ntohl(tvb,4)==0xffffffff)?" - Destination unreachable":""));
	}
}



static void dissect_eigrp_ipx_int (tvbuff_t *tvb, proto_tree *tree, proto_item *ti)
{
	proto_tree_add_text (tree,tvb,0,4,"Next Hop Address = %08x",tvb_get_ntohl(tvb,4));
	proto_tree_add_text (tree,tvb,4,6,"Next Hop ID      = %04x:%04x:%04x",tvb_get_ntohs(tvb,4),tvb_get_ntohs(tvb,6),tvb_get_ntohs(tvb,8));
	proto_tree_add_text (tree,tvb,10,4,"Delay     = %u",tvb_get_ntohl(tvb,10));
	proto_tree_add_text (tree,tvb,14,4,"Bandwidth = %u",tvb_get_ntohl(tvb,14));
	proto_tree_add_text (tree,tvb,18,3,"MTU    = %u",tvb_get_ntoh24(tvb,18));
	proto_tree_add_text (tree,tvb,21,1,"Hop Count = %u",tvb_get_guint8(tvb,21));
	proto_tree_add_text (tree,tvb,22,1,"Reliability = %u",tvb_get_guint8(tvb,22));
	proto_tree_add_text (tree,tvb,23,1,"Load = %u",tvb_get_guint8(tvb,23));
	proto_tree_add_text (tree,tvb,24,2,"Reserved ");
        proto_tree_add_text (tree,tvb,26,4,"Destination Address =  %08x",tvb_get_ntohl(tvb,26));
        proto_item_append_text (ti,"  =   %08x%s",tvb_get_ntohl(tvb,26),((tvb_get_ntohl(tvb,10)==0xffffffff)?" - Destination unreachable":""));
}

static void dissect_eigrp_ipx_ext (tvbuff_t *tvb, proto_tree *tree, proto_item *ti)
{
	proto_tree_add_text (tree,tvb,0,4,"Next Hop Address = %08x",tvb_get_ntohl(tvb,4));
	proto_tree_add_text (tree,tvb,4,6,"Next Hop ID      = %04x:%04x:%04x",tvb_get_ntohs(tvb,4),tvb_get_ntohs(tvb,6),tvb_get_ntohs(tvb,8));

        proto_tree_add_text (tree,tvb,10,6,"Originating router ID = %04x:%04x:%04x",tvb_get_ntohs(tvb,10),tvb_get_ntohs(tvb,12),tvb_get_ntohs(tvb,14));
        proto_tree_add_text (tree,tvb,16,4,"Originating A.S. = %u",tvb_get_ntohl(tvb,16));
        proto_tree_add_text (tree,tvb,20,4,"Arbitrary tag = %u",tvb_get_ntohl(tvb,20));
        proto_tree_add_text (tree,tvb,24,1,"External protocol  = %u",tvb_get_guint8(tvb,24));
        proto_tree_add_text (tree,tvb,25,1,"Reserved");
        proto_tree_add_text (tree,tvb,26,2,"External metric = %u ",tvb_get_ntohs(tvb,26));
        proto_tree_add_text (tree,tvb,28,2,"External delay  = %u ",tvb_get_ntohs(tvb,28));

	proto_tree_add_text (tree,tvb,30,4,"Delay     = %u",tvb_get_ntohl(tvb,30));
	proto_tree_add_text (tree,tvb,34,4,"Bandwidth = %u",tvb_get_ntohl(tvb,34));
	proto_tree_add_text (tree,tvb,38,3,"MTU    = %u",tvb_get_ntoh24(tvb,38));
	proto_tree_add_text (tree,tvb,41,1,"Hop Count = %u",tvb_get_guint8(tvb,41));
	proto_tree_add_text (tree,tvb,42,1,"Reliability = %u",tvb_get_guint8(tvb,42));
	proto_tree_add_text (tree,tvb,43,1,"Load = %u",tvb_get_guint8(tvb,43));
	proto_tree_add_text (tree,tvb,44,2,"Reserved ");
        proto_tree_add_text (tree,tvb,46,4,"Destination Address =  %08x",tvb_get_ntohl(tvb,46));
        proto_item_append_text (ti,"  =   %08x%s",tvb_get_ntohl(tvb,46),((tvb_get_ntohl(tvb,30)==0xffffffff)?" - Destination unreachable":""));

}



static void dissect_eigrp_at_cbl (tvbuff_t *tvb, proto_tree *tree, proto_item *ti)
{
        proto_tree_add_text (tree,tvb,0,4,"AppleTalk Cable Range = %u-%u",tvb_get_ntohs(tvb,0),tvb_get_ntohs(tvb,2));
        proto_tree_add_text (tree,tvb,4,4,"AppleTalk Router ID   = %u",tvb_get_ntohl(tvb,4));
        proto_item_append_text (ti,": Cable range= %u-%u, Router ID= %u",tvb_get_ntohs(tvb,0),tvb_get_ntohs(tvb,2),tvb_get_ntohl(tvb,4));

}

static void dissect_eigrp_at_int (tvbuff_t *tvb, proto_tree *tree, proto_item *ti)
{
	proto_tree_add_text (tree,tvb,0,4,"Next Hop Address = %u.%u",tvb_get_ntohs(tvb,0),tvb_get_ntohs(tvb,2));

	proto_tree_add_text (tree,tvb,4,4,"Delay     = %u",tvb_get_ntohl(tvb,4));
	proto_tree_add_text (tree,tvb,8,4,"Bandwidth = %u",tvb_get_ntohl(tvb,8));
	proto_tree_add_text (tree,tvb,12,3,"MTU    = %u",tvb_get_ntoh24(tvb,12));
	proto_tree_add_text (tree,tvb,15,1,"Hop Count = %u",tvb_get_guint8(tvb,15));
	proto_tree_add_text (tree,tvb,16,1,"Reliability = %u",tvb_get_guint8(tvb,16));
	proto_tree_add_text (tree,tvb,17,1,"Load = %u",tvb_get_guint8(tvb,17));
	proto_tree_add_text (tree,tvb,18,2,"Reserved ");
	proto_tree_add_text (tree,tvb,20,4,"Cable range = %u-%u",tvb_get_ntohs(tvb,20),tvb_get_ntohs(tvb,22));

        proto_item_append_text (ti,": %u-%u",tvb_get_ntohs(tvb,20),tvb_get_ntohs(tvb,22));

}

static void dissect_eigrp_at_ext (tvbuff_t *tvb, proto_tree *tree, proto_item *ti)
{
	proto_tree_add_text (tree,tvb,0,4,"Next Hop Address = %u.%u",tvb_get_ntohs(tvb,0),tvb_get_ntohs(tvb,2));
	proto_tree_add_text (tree,tvb,4,4,"Originating router ID = %u",tvb_get_ntohl(tvb,4));
	proto_tree_add_text (tree,tvb,8,4,"Originating A.S. = %u",tvb_get_ntohl(tvb,8));
	proto_tree_add_text (tree,tvb,12,4,"Arbitrary tag = %u",tvb_get_ntohl(tvb,12));
	proto_tree_add_text (tree,tvb,16,1,"External protocol ID = %u ",tvb_get_guint8(tvb,16));
	proto_tree_add_text (tree,tvb,17,1,"Flags = 0x%0x",tvb_get_guint8(tvb,17));
	proto_tree_add_text (tree,tvb,18,2,"External protocol metric = %u",tvb_get_ntohs(tvb,18));

	proto_tree_add_text (tree,tvb,20,4,"Delay     = %u",tvb_get_ntohl(tvb,20));
	proto_tree_add_text (tree,tvb,24,4,"Bandwidth = %u",tvb_get_ntohl(tvb,24));
	proto_tree_add_text (tree,tvb,28,3,"MTU    = %u",tvb_get_ntoh24(tvb,28));
	proto_tree_add_text (tree,tvb,31,1,"Hop Count = %u",tvb_get_guint8(tvb,31));
	proto_tree_add_text (tree,tvb,32,1,"Reliability = %u",tvb_get_guint8(tvb,32));
	proto_tree_add_text (tree,tvb,33,1,"Load = %u",tvb_get_guint8(tvb,33));
	proto_tree_add_text (tree,tvb,34,2,"Reserved ");
	proto_tree_add_text (tree,tvb,36,4,"Cable range = %u-%u",tvb_get_ntohs(tvb,36),tvb_get_ntohs(tvb,38));

        proto_item_append_text (ti,": %u-%u",tvb_get_ntohs(tvb,36),tvb_get_ntohs(tvb,38));
}




void
proto_register_eigrp(void)
{
  static hf_register_info hf[] = {
   { &hf_eigrp_opcode,
    { "Opcode", "eigrp.opcode",
     FT_UINT8, BASE_DEC, NULL, 0x0 ,
     "Opcode number", HFILL }
     },
   { &hf_eigrp_as,
    { "Autonomous System  ", "eigrp.as",
      FT_UINT16, BASE_DEC, NULL, 0x0 ,
     "Autonomous System number", HFILL }
    },
   { &hf_eigrp_tlv,
    { "Entry  ",           "eigrp.tlv",
      FT_UINT16, BASE_DEC, NULL, 0x0 ,
     "Type/Length/Value", HFILL }
    },
   };

   static gint *ett[] = {
     &ett_eigrp,
     &ett_tlv,
   };
   proto_eigrp = proto_register_protocol("Enhanced Interior Gateway Routing Protocol",
					 "EIGRP", "eigrp");
   proto_register_field_array(proto_eigrp, hf, array_length(hf));
   proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_eigrp(void)
{
    dissector_handle_t eigrp_handle;

    ipxsap_handle = find_dissector("ipxsap");
    eigrp_handle = create_dissector_handle(dissect_eigrp, proto_eigrp);
    dissector_add("ip.proto", IP_PROTO_EIGRP, eigrp_handle);
    dissector_add("ddp.type", DDP_EIGRP, eigrp_handle);
    dissector_add("ipx.socket", IPX_SOCKET_EIGRP, eigrp_handle);
}
