/* packet-fr.c
 * Routines for Frame Relay  dissection
 *
 * Copyright 2001, Paul Ionescu	<paul@acorp.ro>
 *
 * $Id: packet-fr.c,v 1.3 2001/01/08 22:18:21 guy Exp $
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

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include <string.h>
#include <glib.h>
#include "packet.h"
#include "packet-ip.h"
#include "packet-ipx.h"
#include "packet-arp.h"


static gint proto_fr    = -1;
static gint ett_fr      = -1;
static gint hf_fr_dlci  = -1;
static gint hf_fr_cr	= -1;
static gint hf_fr_becn  = -1;
static gint hf_fr_fecn  = -1;
static gint hf_fr_de    = -1;
static gint hf_fr_proto = -1;

static void dissect_fr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *fr_tree;
  guint16 fr_header,fr_proto;
  tvbuff_t   *next_tvb; 
    
  CHECK_DISPLAY_AS_DATA(proto_fr, tvb, pinfo, tree);

  pinfo->current_proto = "Frame Relay";
  if (check_col(pinfo->fd, COL_PROTOCOL)) 
      col_set_str(pinfo->fd, COL_PROTOCOL, "FR");
  if (check_col(pinfo->fd, COL_INFO)) 
      col_clear(pinfo->fd, COL_INFO);

  fr_header = tvb_get_ntohs( tvb, 0 );
  fr_proto  = tvb_get_ntohs( tvb, 2 );
  if (check_col(pinfo->fd, COL_INFO)) 
      col_add_fstr(pinfo->fd, COL_INFO, "DLCI %u, proto 0x%04x",
		   ((fr_header&0x00FF)>>4)+((fr_header&0xFC00)>>6),
		   fr_proto);
  
  if (tree) {
	
      ti = proto_tree_add_protocol_format(tree, proto_fr, tvb, 0, 4, "Frame Relay");
      fr_tree = proto_item_add_subtree(ti, ett_fr);
     
      proto_tree_add_text(fr_tree,tvb,0,2,"The real DLCI is %u",((fr_header&0x00FF)>>4)+((fr_header&0xFC00)>>6));
      proto_tree_add_uint(fr_tree, hf_fr_dlci, tvb, 0, 2, fr_header);
      proto_tree_add_boolean(fr_tree, hf_fr_cr,   tvb, 0, 1, fr_header);
      proto_tree_add_boolean(fr_tree, hf_fr_fecn, tvb, 1, 1, fr_header);
      proto_tree_add_boolean(fr_tree, hf_fr_becn, tvb, 1, 1, fr_header);
      proto_tree_add_boolean(fr_tree, hf_fr_de,   tvb, 1, 1, fr_header);
      proto_tree_add_uint(fr_tree, hf_fr_proto,tvb, 2, 2, fr_proto );
  }

  next_tvb =  tvb_new_subset(tvb, 4, -1, -1);

  switch (fr_proto){
/*    case 0x0703:
	dissect_lmi(next_tvb,pinfo,tree);
	break;
	this is not yet implemented
*/
      case 0x0800:
	dissect_ip(next_tvb,pinfo,tree);
	break;
      case 0x8137:
	dissect_ipx(next_tvb,pinfo,tree);
	break;
      default:
	dissect_data(next_tvb,0,pinfo,tree);
	break;	                                
  }
  return;
}
 
/* Register the protocol with Ethereal */
void proto_register_fr(void)
{                 
  static hf_register_info hf[] = {
        { &hf_fr_dlci, { 
           "DLCI", "fr.dlci", FT_UINT16, BASE_DEC, 
            NULL, 0xFCF0, "Data-Link Connection Identifier" }},
        { &hf_fr_cr, { 
           "CR", "fr.cr", FT_BOOLEAN, 16, 
            NULL, 0x0200, "Command/Response" }},
        { &hf_fr_fecn, { 
           "FECN", "fr.fecn", FT_BOOLEAN, 16, 
            NULL, 0x0008, "Forward Explicit Congestion Notification" }},
        { &hf_fr_becn, { 
           "BECN", "fr.becn", FT_BOOLEAN, 16, 
            NULL, 0x0004, "Backward Explicit Congestion Notification" }},
        { &hf_fr_de, { 
           "DE", "fr.de", FT_BOOLEAN, 16, 
            NULL, 0x0002, "Discard Eligibility" }},
        { &hf_fr_proto, { 
           "Encapsulated Protocol", "fr.proto", FT_UINT16, BASE_HEX, 
            NULL, 0x0, "FrameRelay Encapsulated Protocol" }},
  };


  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_fr,
  };

  proto_fr = proto_register_protocol("Frame Relay", "FR", "fr");
  proto_register_field_array(proto_fr, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_dissector("fr", dissect_fr);
};

void proto_reg_handoff_fr(void)
{
  dissector_add("wtap_encap", WTAP_ENCAP_FRELAY, dissect_fr);
}
