/* packet-dscack.c
 * Routines for Dynamic Service Change Acknowledge dissection
 * Copyright 2002, Anand V. Narwani <anand[AT]narwani.org>
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

void proto_register_docsis_dscack(void);
void proto_reg_handoff_docsis_dscack(void);

/* Initialize the protocol and registered fields */
static int proto_docsis_dscack = -1;
static int hf_docsis_dscack_tranid = -1;
static int hf_docsis_dscack_response = -1;
static dissector_handle_t docsis_tlv_handle;


/* Initialize the subtree pointers */
static gint ett_docsis_dscack = -1;

extern value_string docsis_conf_code[];

/* Code to actually dissect the packets */
static void
dissect_dscack (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{

  proto_item *it;
  proto_tree *dscack_tree = NULL;
  guint16 transid;
  guint8 response;
  tvbuff_t *next_tvb;

  transid = tvb_get_ntohs (tvb, 0);
  response = tvb_get_guint8 (tvb, 2);

  col_add_fstr (pinfo->cinfo, COL_INFO,
	    "Dynamic Service Change Ack ID = %u (%s)", transid,
	    val_to_str (response, docsis_conf_code, "%d"));

  if (tree)
    {
      it =
	proto_tree_add_protocol_format (tree, proto_docsis_dscack, tvb, 0, -1,
					"DSC Acknowledge");
      dscack_tree = proto_item_add_subtree (it, ett_docsis_dscack);
      proto_tree_add_item (dscack_tree, hf_docsis_dscack_tranid, tvb, 0, 2,
			   ENC_BIG_ENDIAN);
      proto_tree_add_item (dscack_tree, hf_docsis_dscack_response, tvb, 2, 1,
			   ENC_BIG_ENDIAN);
    }
    /* Call Dissector for Appendix C TLV's */
    next_tvb = tvb_new_subset_remaining (tvb, 3);
    call_dissector (docsis_tlv_handle, next_tvb, pinfo, dscack_tree);



}




/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/


void
proto_register_docsis_dscack (void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    {&hf_docsis_dscack_tranid,
     {"Transaction Id", "docsis_dscack.tranid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Service Identifier", HFILL}
     },
    {&hf_docsis_dscack_response,
     {"Confirmation Code", "docsis_dscack.confcode",
      FT_UINT8, BASE_DEC, VALS (docsis_conf_code), 0x0,
      NULL, HFILL}
     },
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_docsis_dscack,
  };

/* Register the protocol name and description */
  proto_docsis_dscack =
    proto_register_protocol ("DOCSIS Dynamic Service Change Acknowledgement",
			     "DOCSIS DSC-ACK", "docsis_dscack");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array (proto_docsis_dscack, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  register_dissector ("docsis_dscack", dissect_dscack, proto_docsis_dscack);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_docsis_dscack (void)
{
  dissector_handle_t docsis_dscack_handle;

  docsis_dscack_handle = find_dissector ("docsis_dscack");
  docsis_tlv_handle = find_dissector ("docsis_tlv");
  dissector_add_uint ("docsis_mgmt", 0x14, docsis_dscack_handle);

}
