/* packet-dbcack.c
 * Routines for DOCSIS 3.0 Dynamic Bonding Change Acknowledge Message dissection.
 * Copyright 2010, Guido Reismueller <g.reismueller[AT]avm.de>
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
static int proto_docsis_dbcack = -1;
static int hf_docsis_dbcack_tranid = -1;
static dissector_handle_t docsis_tlv_handle;

/* Initialize the subtree pointers */
static gint ett_docsis_dbcack = -1;

/* Code to actually dissect the packets */
static void
dissect_dbcack (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  proto_item *dbcack_item;
  proto_tree *dbcack_tree = NULL;
  guint16 transid;
  tvbuff_t *next_tvb;

  transid = tvb_get_ntohs (tvb, 0);

  col_clear (pinfo->cinfo, COL_INFO);
  col_add_fstr (pinfo->cinfo, COL_INFO,
	    "Dynamic Bonding Change Acknowledge: Tran-Id = %u", transid);

  if (tree)
  {
    dbcack_item = proto_tree_add_protocol_format (tree, proto_docsis_dbcack,
										   tvb, 0, -1,
										   "Dynamic Bonding Change Acknowledge");
    dbcack_tree = proto_item_add_subtree (dbcack_item, ett_docsis_dbcack);
    proto_tree_add_item (dbcack_tree, hf_docsis_dbcack_tranid,
						   tvb, 0, 2, ENC_BIG_ENDIAN);
  }
  /* Call Dissector for Appendix C TLV's */
  next_tvb = tvb_new_subset_remaining (tvb, 2);
  call_dissector (docsis_tlv_handle, next_tvb, pinfo, dbcack_tree);
}

/* Register the protocol with Wireshark */

/*
 * this format is required because a script is used to build the C function
 * that calls all the protocol registration.
 */
void
proto_register_docsis_dbcack (void)
{
  /* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    {&hf_docsis_dbcack_tranid,
     {"Transaction Id", "docsis_dbcack.tranid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_docsis_dbcack,
  };

/* Register the protocol name and description */
  proto_docsis_dbcack = proto_register_protocol ("DOCSIS Dynamic Bonding Change Acknowledge",
						 "DOCSIS DBC-ACK",
						 "docsis_dbcack");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array (proto_docsis_dbcack, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  register_dissector ("docsis_dbcack", dissect_dbcack, proto_docsis_dbcack);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_docsis_dbcack (void)
{
  dissector_handle_t docsis_dbcack_handle;

  docsis_dbcack_handle = find_dissector ("docsis_dbcack");
  docsis_tlv_handle = find_dissector ("docsis_tlv");
  dissector_add_uint ("docsis_mgmt", 0x26, docsis_dbcack_handle);
}
