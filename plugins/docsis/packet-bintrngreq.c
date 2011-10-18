/* packet-bintrngreq.c
 * Routines for DOCSIS 3.0 Bonded Intial Ranging Request Message dissection.
 * Copyright 2009, Geoffrey Kimball <gekimbal[AT]cisco.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <epan/packet.h>

/* Initialize the protocol and registered fields */
static int proto_docsis_bintrngreq = -1;
static int hf_docsis_bintrngreq_down_chid = -1;
static int hf_docsis_bintrngreq_mddsgid = -1;
static int hf_docsis_bintrngreq_capflags = -1;
static int hf_docsis_bintrngreq_up_chid = -1;
static int hf_docsis_bintrngreq_capflags_frag = -1;
static int hf_docsis_bintrngreq_capflags_encrypt = -1;


/* Initialize the subtree pointers */
static gint ett_docsis_bintrngreq = -1;

/* Code to actually dissect the packets */
static void
dissect_bintrngreq (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  proto_item *bintrngreq_item;
  proto_tree *bintrngreq_tree;
  guint16 md_ds_sg_id;

  md_ds_sg_id = tvb_get_ntohs (tvb, 0);

  col_clear (pinfo->cinfo, COL_INFO);
  col_add_fstr (pinfo->cinfo, COL_INFO, "Bonded Ranging Request: MD-DS-SG-ID = %u (0x%X)",
					md_ds_sg_id, md_ds_sg_id );

  if (tree)
  {
    guint16 offset = 0;
    bintrngreq_item = proto_tree_add_protocol_format (tree, proto_docsis_bintrngreq,
										   tvb, offset, tvb_length_remaining (tvb, 0),
										   "Bonded Initial Ranging Request");
    bintrngreq_tree = proto_item_add_subtree (bintrngreq_item, ett_docsis_bintrngreq);
    proto_tree_add_item (bintrngreq_tree, hf_docsis_bintrngreq_capflags,
						   tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item( bintrngreq_tree, hf_docsis_bintrngreq_capflags_frag,
						   tvb, offset, 1, ENC_BIG_ENDIAN );
    proto_tree_add_item( bintrngreq_tree, hf_docsis_bintrngreq_capflags_encrypt,
						   tvb, offset, 1, ENC_BIG_ENDIAN );
    offset++;
    proto_tree_add_item (bintrngreq_tree, hf_docsis_bintrngreq_mddsgid,
						   tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item (bintrngreq_tree, hf_docsis_bintrngreq_down_chid,
						   tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item (bintrngreq_tree, hf_docsis_bintrngreq_up_chid,
						   tvb, offset, 1, ENC_BIG_ENDIAN);
  }
}

/* Register the protocol with Wireshark */

/*
 * this format is required because a script is used to build the C function
 * that calls all the protocol registration.
 */
void
proto_register_docsis_bintrngreq (void)
{
  /* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    {&hf_docsis_bintrngreq_capflags,
     {"Capability Flags", "docsis_bintrngreq.capflags",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    { &hf_docsis_bintrngreq_capflags_frag,
     {"Pre-3.0 Fragmentation", "docsis_bintrngreq.capflags.frag",
      FT_BOOLEAN, 8, NULL, (1<<7),
      "Pre-3.0 DOCSIS fragmentation is supported prior to registration", HFILL }
    },
    { &hf_docsis_bintrngreq_capflags_encrypt,
     {"Early Auth. & Encrypt", "docsis_bintrngreq.capflags.encrypt",
      FT_BOOLEAN, 8, NULL, (1<<6),
      "Early Authentication and Encryption supported", HFILL }
    },
    {&hf_docsis_bintrngreq_mddsgid,
     {"MD-DS-SG-ID", "docsis_bintrngreq.mddsgid",
      FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
      "MAC Domain Downstream Service Group Identifier", HFILL}
    },
    {&hf_docsis_bintrngreq_down_chid,
     {"DS Chan ID", "docsis_bintrngreq.downchid",
      FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bintrngreq_up_chid,
     {"US Chan ID", "docsis_bintrngreq.upchid",
      FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
      NULL, HFILL}
    },
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_docsis_bintrngreq,
  };

/* Register the protocol name and description */
  proto_docsis_bintrngreq = proto_register_protocol ("DOCSIS Bonded Initial Ranging Message",
						 "DOCSIS B-INT-RNG-REQ",
						 "docsis_bintrngreq");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array (proto_docsis_bintrngreq, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  register_dissector ("docsis_bintrngreq", dissect_bintrngreq, proto_docsis_bintrngreq);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_docsis_bintrngreq (void)
{
  dissector_handle_t docsis_bintrngreq_handle;

  docsis_bintrngreq_handle = find_dissector ("docsis_bintrngreq");
  dissector_add_uint ("docsis_mgmt", 0x22, docsis_bintrngreq_handle);
}
