/* packet-igrp.c
 * Routines for IGRP dissection
 * Copyright 2000, Paul Ionescu <paul@acorp.ro>
 *
 * See
 *
 *	http://www.cisco.com/en/US/tech/tk365/technologies_white_paper09186a00800c8ae1.shtml
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-syslog.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/to_str.h>
#include <epan/ipproto.h>

void proto_register_igrp(void);
void proto_reg_handoff_igrp(void);

#define IGRP_HEADER_LENGTH 12
#define IGRP_ENTRY_LENGTH 14

static gint proto_igrp = -1;
static gint hf_igrp_update = -1;
static gint hf_igrp_as = -1;

static gint ett_igrp = -1;
static gint ett_igrp_vektor = -1;
static gint ett_igrp_net = -1;

static void dissect_vektor_igrp (tvbuff_t *tvb, proto_tree *igrp_vektor_tree, guint8 network);

static void dissect_igrp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint8 ver_and_opcode,version,opcode,network;
  gint offset=IGRP_HEADER_LENGTH;
  guint16 ninterior,nsystem,nexterior;
  const guint8 *ipsrc;
  proto_item *ti;
  proto_tree *igrp_tree, *igrp_vektor_tree;
  tvbuff_t   *next_tvb;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "IGRP");
  col_clear(pinfo->cinfo, COL_INFO);

  ver_and_opcode = tvb_get_guint8(tvb,0);


  switch (ver_and_opcode) {
  case 0x11:
	col_set_str(pinfo->cinfo, COL_INFO, "Response" );
	break;
  case 0x12:
	col_set_str(pinfo->cinfo, COL_INFO, "Request" );
	break;
  default:
	col_set_str(pinfo->cinfo, COL_INFO, "Unknown version or opcode");
  }




  if (tree) {
    ti = proto_tree_add_protocol_format(tree, proto_igrp, tvb, 0, -1,
                                        "Cisco IGRP");

    igrp_tree = proto_item_add_subtree(ti, ett_igrp);

    version = (ver_and_opcode&0xf0)>>4 ; /* version is the fist half of the byte */
    opcode = ver_and_opcode&0x0f ;       /* opcode is the last half of the byte */

    proto_tree_add_text(igrp_tree,  tvb, 0,1,"IGRP Version  : %d %s",version,(version==1?" ":" -  Unknown Version, The dissection may be inaccurate"));
    proto_tree_add_text(igrp_tree,  tvb, 0,1,"Command       : %d %s",opcode,(opcode==1?"(Response)":"(Request)"));
    proto_tree_add_item(igrp_tree, hf_igrp_update, tvb, 1,1, ENC_BIG_ENDIAN);
    proto_tree_add_item(igrp_tree, hf_igrp_as, tvb, 2,2, ENC_BIG_ENDIAN);

    ninterior = tvb_get_ntohs(tvb,4);
    nsystem = tvb_get_ntohs(tvb,6);
    nexterior = tvb_get_ntohs(tvb,8);

    /* this is a ugly hack to find the first byte of the IP source address */
    if (pinfo->net_src.type == AT_IPv4) {
      ipsrc = (const guint8 *)pinfo->net_src.data;
      network = ipsrc[0];
    } else
      network = 0; /* XXX - shouldn't happen */

    ti = proto_tree_add_text(igrp_tree,  tvb, 4,2,"Interior routes : %d",ninterior);
    for( ; ninterior>0 ; ninterior-- ) {
      igrp_vektor_tree =  proto_item_add_subtree(ti,ett_igrp_vektor);
      next_tvb = tvb_new_subset(tvb, offset, IGRP_ENTRY_LENGTH, -1);
      dissect_vektor_igrp (next_tvb,igrp_vektor_tree,network);
      offset+=IGRP_ENTRY_LENGTH;
    }

    ti = proto_tree_add_text(igrp_tree,  tvb, 6,2,"System routes   : %d",nsystem);
    for( ; nsystem>0 ; nsystem-- ) {
      igrp_vektor_tree =  proto_item_add_subtree(ti,ett_igrp_vektor);
      next_tvb = tvb_new_subset(tvb, offset, IGRP_ENTRY_LENGTH, -1);
      dissect_vektor_igrp (next_tvb,igrp_vektor_tree,0);
      offset+=IGRP_ENTRY_LENGTH;
    }

    ti = proto_tree_add_text(igrp_tree,  tvb, 8,2,"Exterior routes : %d",nexterior);
    for( ; nexterior>0 ; nexterior-- ) {
      igrp_vektor_tree =  proto_item_add_subtree(ti,ett_igrp_vektor);
      next_tvb = tvb_new_subset(tvb, offset, IGRP_ENTRY_LENGTH, -1);
      dissect_vektor_igrp (next_tvb,igrp_vektor_tree,0);
      offset+=IGRP_ENTRY_LENGTH;
    }

    proto_tree_add_text(igrp_tree, tvb, 10,2,"Checksum = 0x%4x",tvb_get_ntohs(tvb,10));
  }
}

static void dissect_vektor_igrp (tvbuff_t *tvb, proto_tree *igrp_vektor_tree, guint8 network)
{
	proto_item *ti;
	guint8 *ptr_addr,addr[5];

	addr[0]=network;
	addr[1]=tvb_get_guint8(tvb,0);
	addr[2]=tvb_get_guint8(tvb,1);
	addr[3]=tvb_get_guint8(tvb,2);
	addr[4]=0;

	ptr_addr=addr;
	if (network==0) ptr_addr=&addr[1];

	ti = proto_tree_add_text (igrp_vektor_tree, tvb, 0 ,14,
	  "Entry for network %s", ip_to_str(ptr_addr)) ;
	igrp_vektor_tree =  proto_item_add_subtree(ti,ett_igrp_net);
	proto_tree_add_text (igrp_vektor_tree, tvb, 0 ,3,"Network     = %s",ip_to_str(ptr_addr)) ;
	proto_tree_add_text (igrp_vektor_tree, tvb, 3 ,3,"Delay       = %d",tvb_get_ntoh24(tvb,3)) ;
	proto_tree_add_text (igrp_vektor_tree, tvb, 6 ,3,"Bandwidth   = %d",tvb_get_ntoh24(tvb,6)) ;
	proto_tree_add_text (igrp_vektor_tree, tvb, 9 ,2,"MTU         = %d  bytes",tvb_get_ntohs(tvb,9)) ;
	proto_tree_add_text (igrp_vektor_tree, tvb, 11,1,"Reliability = %d",tvb_get_guint8(tvb,11)) ;
	proto_tree_add_text (igrp_vektor_tree, tvb, 12,1,"Load        = %d",tvb_get_guint8(tvb,12)) ;
	proto_tree_add_text (igrp_vektor_tree, tvb, 13,1,"Hop count   = %d  hops",tvb_get_guint8(tvb,13)) ;
}


/* Register the protocol with Wireshark */
void proto_register_igrp(void)
{

  /* Setup list of header fields */
  static hf_register_info hf[] = {

    { &hf_igrp_update,
      { "Update Release",           "igrp.update",
      FT_UINT8, BASE_DEC, NULL, 0x0 ,
      "Update Release number", HFILL }
    },
    { &hf_igrp_as,
      { "Autonomous System",           "igrp.as",
      FT_UINT16, BASE_DEC, NULL, 0x0 ,
      "Autonomous System number", HFILL }
    }
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_igrp,
    &ett_igrp_vektor,
    &ett_igrp_net
  };

  /* Register the protocol name and description */
  proto_igrp = proto_register_protocol("Cisco Interior Gateway Routing Protocol",
				       "IGRP", "igrp");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_igrp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_igrp(void)
{
  dissector_handle_t igrp_handle;

  igrp_handle = create_dissector_handle(dissect_igrp, proto_igrp);
  dissector_add_uint("ip.proto", IP_PROTO_IGRP, igrp_handle);
}

/*	IGRP Packet structure:

HEADER structure + k * VECTOR structure
where: k = (Number of Interior routes) + (Number of System routes) + (Number of Exterior routes)

HEADER structure is 12 bytes as follows :

4  bits		Version (only version 1 is defined)
4  bits		Opcode (1=Replay, 2=Request)
8  bits		Update Release
16 bits		Autonomous system number
16 bits		Number of Interior routes
16 bits		Number of System routes
16 bits		Number of Exterior routes
16 bits		Checksum
-------
12 bytes in header

VECTOR structure is 14 bytes as follows :
24 bits		Network
24 bits		Delay
24 bits		Bandwidth
16 bits		MTU
8  bits		Reliability
8  bits		Load
8  bits		Hop count
-------
14 bytes in 1 vector

It is interesting how is coded an ip network address in 3 bytes because IGRP is a classful routing protocol:
If it is a interior route then this 3 bytes are the final bytes, and the first one is taken from the source ip address of the ip packet
If it is a system route or a exterior route then this 3 bytes are the first three and the last byte is not important

If the Delay is 0xFFFFFF then the network is unreachable

*/
