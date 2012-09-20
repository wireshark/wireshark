/* packet-dbcrsp.c
 * Routines for DOCSIS 3.0 Dynamic Bonding Change Response Message dissection.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>

extern value_string docsis_conf_code[];

/* Initialize the protocol and registered fields */
static int proto_docsis_dbcrsp = -1;
static int hf_docsis_dbcrsp_tranid = -1;
static int hf_docsis_dbcrsp_conf_code = -1;
static dissector_handle_t docsis_tlv_handle;

/* Initialize the subtree pointers */
static gint ett_docsis_dbcrsp = -1;

/* Code to actually dissect the packets */
static void
dissect_dbcrsp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  proto_item *dbcrsp_item;
  proto_tree *dbcrsp_tree = NULL;
  guint16 transid;
  guint8 confcode;
  tvbuff_t *next_tvb;

  transid = tvb_get_ntohs (tvb, 0);
  confcode = tvb_get_guint8 (tvb, 2);

  col_clear (pinfo->cinfo, COL_INFO);
  col_add_fstr (pinfo->cinfo, COL_INFO,
	    "Dynamic Bonding Change Response: Tran-Id = %u (%s)", transid,
		 val_to_str (confcode, docsis_conf_code, "%d"));

  if (tree)
  {
    dbcrsp_item = proto_tree_add_protocol_format (tree, proto_docsis_dbcrsp,
										   tvb, 0, -1,
										   "Dynamic Bonding Change Response");
    dbcrsp_tree = proto_item_add_subtree (dbcrsp_item, ett_docsis_dbcrsp);
    proto_tree_add_item (dbcrsp_tree, hf_docsis_dbcrsp_tranid,
						   tvb, 0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item( dbcrsp_tree, hf_docsis_dbcrsp_conf_code,
						   tvb, 2, 1, ENC_BIG_ENDIAN );
  }
  /* Call Dissector for Appendix C TLV's */
  next_tvb = tvb_new_subset_remaining (tvb, 3);
  call_dissector (docsis_tlv_handle, next_tvb, pinfo, dbcrsp_tree);
}

/* Register the protocol with Wireshark */

/*
 * this format is required because a script is used to build the C function
 * that calls all the protocol registration.
 */
void
proto_register_docsis_dbcrsp (void)
{
  /* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    {&hf_docsis_dbcrsp_tranid,
     {"Transaction Id", "docsis_dbcrsp.tranid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_dbcrsp_conf_code,
     {"Confirmation Code", "docsis_dbcrsp.conf_code",
      FT_UINT8, BASE_DEC, VALS (docsis_conf_code), 0x0,
      NULL, HFILL}
    },
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_docsis_dbcrsp,
  };

/* Register the protocol name and description */
  proto_docsis_dbcrsp = proto_register_protocol ("DOCSIS Dynamic Bonding Change Response",
						 "DOCSIS DBC-RSP",
						 "docsis_dbcrsp");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array (proto_docsis_dbcrsp, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  register_dissector ("docsis_dbcrsp", dissect_dbcrsp, proto_docsis_dbcrsp);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_docsis_dbcrsp (void)
{
  dissector_handle_t docsis_dbcrsp_handle;

  docsis_dbcrsp_handle = find_dissector ("docsis_dbcrsp");
  docsis_tlv_handle = find_dissector ("docsis_tlv");
  dissector_add_uint ("docsis_mgmt", 0x25, docsis_dbcrsp_handle);
}
