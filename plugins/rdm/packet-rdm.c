/* packet-rdm.c
 * Routines for RDM packet disassembly
 *
 * $Id$
 *
 * Copyright (c) 2003 by Erwin Rol <erwin@erwinrol.com>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1999 Gerald Combs
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

/* Include files */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/etypes.h>
#include <epan/strutil.h>

/*
 * See http://www.esta.org/tsp/E1-20inst.htm
 *
 */

void proto_reg_handoff_rdm(void);

/* Define the rdm proto */
static int proto_rdm = -1;

/* Header */
static int hf_rdm_sub_start_code = -1;
static int hf_rdm_slot_count = -1;
static int hf_rdm_dest_uid = -1;
static int hf_rdm_src_uid = -1;
static int hf_rdm_seq_nr = -1;
static int hf_rdm_res_type = -1;
static int hf_rdm_msg_count = -1;
static int hf_rdm_sub_device = -1;
static int hf_rdm_mdb = -1;
static int hf_rdm_checksum = -1;

/* Define the tree for rdm */
static int ett_rdm = -1;

static void
dissect_rdm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  gint offset = 0, start_offset,i;
  guint16 checksum,calc_checksum;
  gint mdb_size;
  proto_tree *ti=NULL,*rdm_tree=NULL;
  proto_item* item;
  
  /* Set the protocol column */
  if(check_col(pinfo->cinfo,COL_PROTOCOL)){
    col_set_str(pinfo->cinfo,COL_PROTOCOL,"RDM");
  }
                                                                                                                                                                                                     
  /* Clear out stuff in the info column */
  if(check_col(pinfo->cinfo,COL_INFO)){
    col_clear(pinfo->cinfo,COL_INFO);
  }
                                                                                                                                                                                                     
  if (tree) {
    ti = proto_tree_add_item(tree, proto_rdm, tvb, offset, -1, FALSE);
    rdm_tree = proto_item_add_subtree(ti, ett_rdm);
  }
                                                                                                                                                                                                     
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s",
                    "RDM");
  }
                                                                                                                                                                                                     
  if (tree)
  {
    start_offset = offset;
  
    proto_tree_add_item(rdm_tree, hf_rdm_sub_start_code, tvb,
                        offset, 1, FALSE);
    offset += 1;

    mdb_size = tvb_get_guint8(tvb, offset) - 19;

    if (mdb_size < 20) {
      proto_tree_add_text(rdm_tree, tvb, offset, 1, "Invalid MDB size: %d", 
			mdb_size + 19);
      return;
    }

    proto_tree_add_item(rdm_tree, hf_rdm_slot_count, tvb,
                        offset, 1, FALSE);
    offset += 1;

    proto_tree_add_item(rdm_tree, hf_rdm_dest_uid, tvb,
                        offset, 6, FALSE);
    offset += 6;

    proto_tree_add_item(rdm_tree, hf_rdm_src_uid, tvb,
                        offset, 6, FALSE);
    offset += 6;

    proto_tree_add_item(rdm_tree, hf_rdm_seq_nr, tvb,
                        offset, 1, FALSE);
    offset += 1;

    proto_tree_add_item(rdm_tree, hf_rdm_res_type, tvb,
                        offset, 1, FALSE);
    offset += 1;

    proto_tree_add_item(rdm_tree, hf_rdm_msg_count, tvb,
                        offset, 1, FALSE);
    offset += 1;

    proto_tree_add_item(rdm_tree, hf_rdm_sub_device, tvb,
                        offset, 1, FALSE);
    offset += 1;

    tvb_ensure_bytes_exist(tvb, offset, mdb_size);
    proto_tree_add_item(rdm_tree, hf_rdm_mdb, tvb,
                        offset, mdb_size, FALSE);
    offset += mdb_size;

    calc_checksum = 0x00f0;
    for( i = start_offset; i < offset; i++)
    {
      calc_checksum += tvb_get_guint8( tvb, i );    
    }

    checksum = tvb_get_ntohs( tvb, offset );
    item = proto_tree_add_item(rdm_tree, hf_rdm_checksum, tvb,
                        offset, 2, FALSE);

    if( calc_checksum != checksum )
      proto_item_append_text( item, " ( INCORRECT should be 0x%04x )", calc_checksum );
    else
      proto_item_append_text( item, " ( CORRECT )" );
  
    offset += 2;
  }
}

void
proto_register_rdm(void) {
  static hf_register_info hf[] = {
    { &hf_rdm_sub_start_code,
      { "Sub Start Code",
        "rdm.sub_start_code",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Sub Start Code", HFILL }},
        
    { &hf_rdm_slot_count,
      { "Slot Count",
        "rdm.slot_count",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Slot Count", HFILL }},
        
   { &hf_rdm_dest_uid,
      { "Dest. UID",
        "rdm.dest_uid",
        FT_BYTES, BASE_HEX, NULL, 0x0,
        "Dest. UID", HFILL }},        

   { &hf_rdm_src_uid,
      { "Source UID",
        "rdm.src_uid",
        FT_BYTES, BASE_HEX, NULL, 0x0,
        "Source UID", HFILL }}, 
        
    { &hf_rdm_seq_nr,
      { "Sequence Number",
        "rdm.seq_nr",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Sequence Number", HFILL }},

    { &hf_rdm_res_type,
      { "Response Type",
        "rdm.res_type",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Response Type", HFILL }},

    { &hf_rdm_msg_count,
      { "Message Count",
        "rdm.msg_count",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Message Count", HFILL }},

    { &hf_rdm_sub_device,
      { "Sub Device",
        "rdm.sub_device",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Sub Device", HFILL }},
        
   { &hf_rdm_mdb,
      { "MDB",
        "rdm.mdb",
        FT_BYTES, BASE_HEX, NULL, 0x0,
        "MDB", HFILL }}, 

    { &hf_rdm_checksum,
      { "Checksum",
        "rdm.checksum",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        "Checksum", HFILL }}
  };

  static gint *ett[] = {
    &ett_rdm,
  };

  proto_rdm = proto_register_protocol("RDM","RDM","rdm");

  proto_register_field_array(proto_rdm,hf,array_length(hf));
  proto_register_subtree_array(ett,array_length(ett));

  register_dissector("rdm", dissect_rdm, proto_rdm);
}

/* The registration hand-off routing */

void
proto_reg_handoff_rdm(void) {
  static int rdm_initialized = FALSE;
  static dissector_handle_t rdm_handle;
     
  if(!rdm_initialized) {
    rdm_handle = create_dissector_handle(dissect_rdm,proto_rdm);
    rdm_initialized = TRUE;
  } else {
    dissector_delete("udp.port",0,rdm_handle);
  }
                           
  dissector_add("udp.port",0,rdm_handle);
}
