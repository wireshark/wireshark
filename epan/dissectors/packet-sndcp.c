/* packet-sndcp.c
 * Routines for Subnetwork Dependent Convergence Protocol (SNDCP) dissection
 * Copyright 2000, Christian Falckenberg <christian.falckenberg@nortelnetworks.com>
 *
 * $Id$
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
#include <epan/reassemble.h>

/* Bitmasks for the bits in the address field
*/
#define MASK_X      0x80
#define MASK_F      0x40
#define MASK_T      0x20
#define MASK_M      0x10

/* Initialize the protocol and registered fields 
*/
static int proto_sndcp       = -1;
static int hf_sndcp_x        = -1;
static int hf_sndcp_f        = -1;
static int hf_sndcp_t        = -1;
static int hf_sndcp_m        = -1;
static int hf_sndcp_nsapi    = -1;
static int hf_sndcp_nsapib   = -1;
static int hf_sndcp_dcomp    = -1;
static int hf_sndcp_pcomp    = -1;
static int hf_sndcp_segment  = -1;
static int hf_sndcp_npdu1    = -1;
static int hf_sndcp_npdu2    = -1;

/* These fields are used when reassembling N-PDU fragments 
*/
static int hf_npdu_fragments			= -1;
static int hf_npdu_fragment			= -1;
static int hf_npdu_fragment_overlap		= -1;
static int hf_npdu_fragment_overlap_conflict	= -1;
static int hf_npdu_fragment_multiple_tails	= -1;
static int hf_npdu_fragment_too_long_fragment	= -1;
static int hf_npdu_fragment_error		= -1;
static int hf_npdu_reassembled_in		= -1;

/* Initialize the subtree pointers 
*/
static gint ett_sndcp                   = -1;
static gint ett_sndcp_address_field     = -1;
static gint ett_sndcp_compression_field = -1;
static gint ett_sndcp_npdu_field        = -1;
static gint ett_npdu_fragment           = -1;
static gint ett_npdu_fragments          = -1;

/* Structure needed for the fragmentation routines in reassemble.c
*/
static const fragment_items npdu_frag_items = {
    &ett_npdu_fragment,
    &ett_npdu_fragments,
    &hf_npdu_fragments,
    &hf_npdu_fragment,
    &hf_npdu_fragment_overlap,
    &hf_npdu_fragment_overlap_conflict,
    &hf_npdu_fragment_multiple_tails,
    &hf_npdu_fragment_too_long_fragment,
    &hf_npdu_fragment_error,
    &hf_npdu_reassembled_in,
    "fragments"
};

/* dissectors for the data portion of this protocol
 */
static dissector_handle_t data_handle;
static dissector_handle_t ip_handle;

/* reassembly of N-PDU
 */
static GHashTable	*npdu_fragment_table = NULL;
static void
sndcp_defragment_init(void)
{
  fragment_table_init(&npdu_fragment_table);
}

/* value strings
 */
static const value_string nsapi_t[] = {
	{  0, "Escape mechanism for future extensions"},
	{  1, "Point-to-Multipoint (PTM-M) Information" },
	{  2, "Reserved for future use" },
	{  3, "Reserved for future use" },
	{  4, "Reserved for future use" },
	{  5, "Dynamically allocated"},
	{  6, "Dynamically allocated"},
	{  7, "Dynamically allocated"},
	{  8, "Dynamically allocated"},
	{  9, "Dynamically allocated"},
	{ 10, "Dynamically allocated"},
	{ 11, "Dynamically allocated"},
	{ 12, "Dynamically allocated"},
	{ 13, "Dynamically allocated"},
	{ 14, "Dynamically allocated"},
	{ 15, "Dynamically allocated"},
	{  0, NULL },
};

static const value_string nsapi_abrv[] = {
	{  0, "0"},
	{  1, "PTM-M" },
	{  2, "2" },
	{  3, "3"},
	{  4, "4" },
	{  5, "DYN5" },
	{  6, "DYN6" },
	{  7, "DYN7" },
	{  8, "DYN8" },
	{  9, "DYN9" },
	{ 10, "DYN10" },
	{ 11, "DYN11" },
	{ 12, "DYN12" },
	{ 13, "DYN13" },
	{ 14, "DYN14" },
	{ 15, "DYN15" },
	{  0, NULL },
};

static const value_string compression_vals[] = {
	{  0, "No compression"},
	{  1, "Pointer to selected protocol/data compression mechanism" },
	{  2, "Pointer to selected protocol/data compression mechanism" },
	{  3, "Pointer to selected protocol/data compression mechanism" },
	{  4, "Pointer to selected protocol/data compression mechanism" },
	{  5, "Pointer to selected protocol/data compression mechanism" },
	{  6, "Pointer to selected protocol/data compression mechanism" },
	{  7, "Pointer to selected protocol/data compression mechanism" },
	{  8, "Pointer to selected protocol/data compression mechanism" },
	{  9, "Pointer to selected protocol/data compression mechanism" },
	{ 10, "Pointer to selected protocol/data compression mechanism" },
	{ 11, "Pointer to selected protocol/data compression mechanism" },
	{ 12, "Pointer to selected protocol/data compression mechanism" },
	{ 13, "Pointer to selected protocol/data compression mechanism" },
	{ 14, "Pointer to selected protocol/data compression mechanism" },
	{ 15, "Pointer to selected protocol/data compression mechanism" },
	{ 0, NULL },
};

static const true_false_string x_bit = {
  "Invalid",
  "Set to 0 by transmitting SNDCP entity (ignored by receiver)"
};
static const true_false_string f_bit = {
  "This SN-PDU is the first segment of an N-PDU",
  "This SN-PDU is not the first segment of an N-PDU"
};
static const true_false_string t_bit = {
  "SN-UNITDATA PDU",
  "SN-DATA PDU"
};
static const true_false_string m_bit = {
  "Not the last segment of N-PDU, more segments to follow",
  "Last segment of N-PDU"
};

/* Code to actually dissect the packets 
*/
static void
dissect_sndcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint8         addr_field, comp_field, npdu_field1, nsapi, dcomp=0, pcomp=0;
  guint16        offset=0, npdu=0, segment=0, npdu_field2;
  tvbuff_t	*next_tvb, *npdu_tvb;
  gint           len;
  gboolean       first, more_frags, unack;

  /* Set up structures needed to add the protocol subtree and manage it 
   */
  proto_item *ti, *address_field_item, *compression_field_item, *npdu_field_item;
  proto_tree *sndcp_tree = NULL, *address_field_tree, *compression_field_tree, *npdu_field_tree;

  /* Make entries in Protocol column and clear Info column on summary display 
   */
  if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SNDCP");
  if (check_col(pinfo->cinfo, COL_INFO)) 
    col_clear(pinfo->cinfo, COL_INFO);
  
  /* create display subtree for the protocol 
   */
  if (tree) {
    ti         = proto_tree_add_item(tree, proto_sndcp, tvb, 0, -1, FALSE);
    sndcp_tree = proto_item_add_subtree(ti, ett_sndcp);
  }
   
  /* get address field from next byte
   */
  addr_field = tvb_get_guint8(tvb,offset);
  nsapi      = addr_field & 0xF;
  first      = addr_field & MASK_F;
  more_frags = addr_field & MASK_M;
  unack      = addr_field & MASK_T;

  /* add subtree for the address field 
   */
  if (tree) {
    address_field_item = proto_tree_add_uint_format(sndcp_tree,hf_sndcp_nsapi,
						    tvb, offset,1, nsapi, 
						    "Address field  NSAPI: %d", nsapi );
    address_field_tree = proto_item_add_subtree(address_field_item, ett_sndcp_address_field);
    proto_tree_add_boolean(address_field_tree, hf_sndcp_x, tvb,offset,1, addr_field );
    proto_tree_add_boolean(address_field_tree, hf_sndcp_f, tvb,offset,1, addr_field );
    proto_tree_add_boolean(address_field_tree, hf_sndcp_t, tvb,offset,1, addr_field );
    proto_tree_add_boolean(address_field_tree, hf_sndcp_m, tvb,offset,1, addr_field );
    proto_tree_add_uint(address_field_tree, hf_sndcp_nsapib, tvb, offset, 1, addr_field ); 
  }
  offset++;

  /* get compression pointers from next byte if this is the first segment
   */
  if (first) {
    comp_field = tvb_get_guint8(tvb,offset);
    dcomp      = comp_field & 0xF0;
    pcomp      = comp_field & 0x0F;
    
    /* add subtree for the compression field 
     */
    if (tree) {
      if (!pcomp) { 
	if (!dcomp) {
	  compression_field_item = proto_tree_add_text(sndcp_tree, tvb, offset,1, "No compression");
	}
	else { 
	  compression_field_item = proto_tree_add_text(sndcp_tree, tvb, offset,1, "Data compression");
	}
      }
      else { 
	if (!dcomp) {
	  compression_field_item = proto_tree_add_text(sndcp_tree, tvb, offset,1, "Protocol compression");
	}
	else { 
	  compression_field_item = proto_tree_add_text(sndcp_tree, tvb, offset,1, "Data and Protocol compression");
	}
      }
      compression_field_tree = proto_item_add_subtree(compression_field_item, ett_sndcp_compression_field);
      proto_tree_add_uint(compression_field_tree, hf_sndcp_dcomp, tvb, offset, 1, comp_field );
      proto_tree_add_uint(compression_field_tree, hf_sndcp_pcomp, tvb, offset, 1, comp_field );
    }
    offset++;

    /* get N-PDU number from next byte for acknowledged mode (only for first segment)
     */
    if (!unack) {
      npdu = npdu_field1 = tvb_get_guint8(tvb,offset);
      if (check_col(pinfo->cinfo, COL_INFO))
	col_add_fstr(pinfo->cinfo, COL_INFO, "SN-DATA N-PDU %d", npdu_field1);
      if (tree) {
	npdu_field_item = proto_tree_add_text(sndcp_tree, tvb, offset,1, "Acknowledged mode, N-PDU %d", npdu_field1 );
	npdu_field_tree = proto_item_add_subtree(npdu_field_item, ett_sndcp_npdu_field);
	proto_tree_add_uint(npdu_field_tree, hf_sndcp_npdu1, tvb, offset, 1, npdu_field1 );
      }
      offset++;
    }
  }

  /* get segment and N-PDU number from next two bytes for unacknowledged mode 
   */
  if (unack) {
    npdu_field2     = tvb_get_ntohs(tvb, offset);
    segment         = (npdu_field2 & 0xF000) >> 12;
    npdu            = (npdu_field2 & 0x0FFF);
    if (check_col(pinfo->cinfo, COL_INFO)) 
      col_add_fstr(pinfo->cinfo, COL_INFO, "SN-UNITDATA N-PDU %d (segment %d)", npdu, segment);
    if (tree) {
      npdu_field_item = proto_tree_add_text(sndcp_tree, tvb, offset,2, "Unacknowledged mode, N-PDU %d (segment %d)", npdu, segment );
      npdu_field_tree = proto_item_add_subtree(npdu_field_item, ett_sndcp_npdu_field);
      proto_tree_add_uint(npdu_field_tree, hf_sndcp_segment, tvb, offset, 2, npdu_field2 );
      proto_tree_add_uint(npdu_field_tree, hf_sndcp_npdu2, tvb, offset, 2, npdu_field2 );
    }
    offset         += 2;
  }

  /* handle N-PDU data, reassemble if necessary 
   */
  if (first && !more_frags) {
    next_tvb = tvb_new_subset (tvb, offset, -1, -1);
    
    if (!dcomp && !pcomp) {
      call_dissector(ip_handle, next_tvb, pinfo, tree);
    }
    else {
      call_dissector(data_handle, next_tvb, pinfo, tree);
    }
  }
  else {
    /* Try reassembling fragments 
     */
    fragment_data  *fd_npdu         = NULL;
    guint32         reassembled_in  = 0;
    gboolean        save_fragmented = pinfo->fragmented;
    
    len = tvb_length_remaining(tvb, offset);
    if(len<=0){
        return;
    }

    pinfo->fragmented = TRUE;

    if (unack) 
      fd_npdu  = fragment_add_seq(tvb, offset, pinfo, npdu,
				  npdu_fragment_table, segment, len, more_frags);
    else
      fd_npdu  = fragment_add(tvb, offset, pinfo, npdu,
				  npdu_fragment_table, offset, len, more_frags);

    npdu_tvb = process_reassembled_data(tvb, offset, pinfo,
					"Reassembled N-PDU", fd_npdu, &npdu_frag_items,
					NULL, sndcp_tree);
    if (fd_npdu) {
      /* Reassembled 
       */
      reassembled_in = fd_npdu->reassembled_in;
      if (pinfo->fd->num == reassembled_in) {
	/* Reassembled in this very packet:
	 * We can safely hand the tvb to the IP dissector 
	 */
	call_dissector(ip_handle, npdu_tvb, pinfo, tree);
      } 
      else {
	/* Not reassembled in this packet 
	 */
	if (check_col(pinfo->cinfo, COL_INFO)) {
	  col_append_fstr(pinfo->cinfo, COL_INFO,
			  " (N-PDU payload reassembled in packet %u)",
			  fd_npdu->reassembled_in);
	}
	if (tree) {
	  proto_tree_add_text(sndcp_tree, tvb, offset, -1, "Payload");
	}
      }
    } else {
      /* Not reassembled yet, or not reassembled at all 
       */
      if (check_col(pinfo->cinfo, COL_INFO)) {
	if (unack)
	  col_append_fstr(pinfo->cinfo, COL_INFO, " (Unreassembled fragment %u)", segment);
	else
	  col_append_str(pinfo->cinfo, COL_INFO, " (Unreassembled fragment)");
      }
      if (tree) {
	proto_tree_add_text(sndcp_tree, tvb, offset, -1, "Payload");
      }
    }
    /* Now reset fragmentation information in pinfo 
     */
    pinfo->fragmented = save_fragmented;
  }
}


/* Register the protocol with Ethereal 
   this format is required because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_sndcp(void)
{                 
  /* Setup list of header fields
   */
  static hf_register_info hf[] = {
    { &hf_sndcp_nsapi,
      { "NSAPI", 
	"sndcp.nsapi", 
	FT_UINT8, BASE_DEC, VALS(nsapi_abrv), 0x0,
	"Network Layer Service Access Point Identifier", HFILL 
      }
    },
    { &hf_sndcp_x, 
      { "Spare bit",
	"sndcp.x", 
	FT_BOOLEAN,8, TFS(&x_bit), MASK_X, 
	"Spare bit (should be 0)", HFILL 
      }
    },
    { &hf_sndcp_f, 
      { "First segment indicator bit", 
	"sndcp.f", 
	FT_BOOLEAN,8, TFS(&f_bit), MASK_F, 
	"First segment indicator bit", HFILL 
      }
    },
    { &hf_sndcp_t, 
      { "Type", 
	"sndcp.t", 
	FT_BOOLEAN,8, TFS(&t_bit), MASK_T, 
	"SN-PDU Type", HFILL 
      }
    },
    { &hf_sndcp_m, 
      { "More bit", 
	"sndcp.m", 
	FT_BOOLEAN,8, TFS(&m_bit), MASK_M, 
	"More bit", HFILL 
      }
    },
    { &hf_sndcp_dcomp, 
      { "DCOMP", 
	"sndcp.dcomp", 
	FT_UINT8, BASE_DEC, VALS(compression_vals), 0xF0, 
	"Data compression coding", HFILL 
      }
    },
    { &hf_sndcp_pcomp, 
      { "PCOMP", 
	"sndcp.pcomp", 
	FT_UINT8, BASE_DEC, VALS(compression_vals), 0x0F, 
	"Protocol compression coding", HFILL 
      }
    },
    { &hf_sndcp_nsapib,
      { "NSAPI", 
	"sndcp.nsapib", 
	FT_UINT8, BASE_DEC , VALS(nsapi_t), 0xf, 
	"Network Layer Service Access Point Identifier ",HFILL 
      }
    },	
    { &hf_sndcp_segment, 
      { "Segment", 
	"sndcp.segment", 
	FT_UINT16, BASE_DEC, NULL, 0xF000, 
	"Segment number", HFILL 
      }
    },
    { &hf_sndcp_npdu1, 
      { "N-PDU", 
	"sndcp.npdu", 
	FT_UINT8, BASE_DEC, NULL, 0, 
	"N-PDU", HFILL 
      }
    },
    { &hf_sndcp_npdu2, 
      { "N-PDU", 
	"sndcp.npdu", 
	FT_UINT16, BASE_DEC, NULL, 0x0FFF, 
	"N-PDU", HFILL 
      }
    },

    /* Fragment fields 
     */
    { &hf_npdu_fragment_overlap,
      {	"Fragment overlap",
	"npdu.fragment.overlap",
	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	"Fragment overlaps with other fragments", HFILL
      }
    },
    { &hf_npdu_fragment_overlap_conflict,
      {	"Conflicting data in fragment overlap",
	"npdu.fragment.overlap.conflict",
	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	"Overlapping fragments contained conflicting data", HFILL
      }
    },
    { &hf_npdu_fragment_multiple_tails,
      {	"Multiple tail fragments found",
	"npdu.fragment.multipletails",
	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	"Several tails were found when defragmenting the packet", HFILL
      }
    },
    { &hf_npdu_fragment_too_long_fragment,
      {	"Fragment too long",
	"npdu.fragment.toolongfragment",
	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	"Fragment contained data past end of packet", HFILL
      }
    },
    { &hf_npdu_fragment_error,
      {	"Defragmentation error",
	"npdu.fragment.error",
	FT_FRAMENUM, BASE_NONE, NULL, 0x0,
	"Defragmentation error due to illegal fragments", HFILL
      }
    },
    { &hf_npdu_reassembled_in,
      {	"Reassembled in",
	"npdu.reassembled.in",
	FT_FRAMENUM, BASE_NONE, NULL, 0x0,
	"N-PDU fragments are reassembled in the given packet", HFILL
      }
    },
    { &hf_npdu_fragment,
      {	"N-PDU Fragment",
	"npdu.fragment",
	FT_FRAMENUM, BASE_NONE, NULL, 0x0,
	"N-PDU Fragment", HFILL
      }
    },
    { &hf_npdu_fragments,
      {	"N-PDU Fragments",
	"npdu.fragments",
	FT_NONE, BASE_NONE, NULL, 0x0,
	"N-PDU Fragments", HFILL
      }
    }
  };
    
    /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_sndcp     ,
    &ett_sndcp_address_field,
    &ett_sndcp_compression_field,
    &ett_sndcp_npdu_field,
    &ett_npdu_fragment,
    &ett_npdu_fragments,
  };

  /* Register the protocol name and description */
  proto_sndcp = proto_register_protocol("Subnetwork Dependent Convergence Protocol",
					"SNDCP", "sndcp");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_sndcp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_dissector("sndcp", dissect_sndcp, proto_sndcp);
  register_init_routine(sndcp_defragment_init);
}

/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_sndcp(void)
{
  dissector_handle_t sndcp_handle;

  sndcp_handle = find_dissector("sndcp"); 

  /* Register SNDCP dissector with LLC layer for SAPI 3,5,9 and 11 
   */
  dissector_add("llcgprs.sapi",  3, sndcp_handle);
  dissector_add("llcgprs.sapi",  5, sndcp_handle);
  dissector_add("llcgprs.sapi",  9, sndcp_handle);
  dissector_add("llcgprs.sapi", 11, sndcp_handle);

  /* Find IP and data handle for upper layer dissectors 
   */
  ip_handle   = find_dissector("ip"); 
  data_handle = find_dissector("data");
}
