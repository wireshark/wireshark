/* packet-regack.c
 * Routines for Registration Acknowledge Message dissection
 * Copyright 2002, Anand V. Narwani <anand[AT]narwani.org>
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

/* Initialize the protocol and registered fields */
static int proto_docsis_regack = -1;
static int hf_docsis_regack_sid = -1;
static int hf_docsis_regack_response = -1;
static dissector_handle_t docsis_tlv_handle;

/* Defined in packet-tlv.c */
extern value_string docsis_conf_code[];

/* Initialize the subtree pointers */
static gint ett_docsis_regack = -1;

/* Code to actually dissect the packets */
static void
dissect_regack (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{

  proto_item *it;
  proto_tree *regack_tree = NULL;
  guint16 sid;
  guint8 response;
  tvbuff_t *next_tvb;

  sid = tvb_get_ntohs (tvb, 0);
  response = tvb_get_guint8 (tvb, 2);

  col_add_fstr (pinfo->cinfo, COL_INFO,
	    "Registration Acknowledge SID = %u (%s)", sid,
	    val_to_str (response, docsis_conf_code, "%d"));
  if (tree)
    {
      it =
	proto_tree_add_protocol_format (tree, proto_docsis_regack, tvb, 0, -1,
					"Registration Acknowledge");
      regack_tree = proto_item_add_subtree (it, ett_docsis_regack);
      proto_tree_add_item (regack_tree, hf_docsis_regack_sid, tvb, 0, 2,
			   ENC_BIG_ENDIAN);
      proto_tree_add_item (regack_tree, hf_docsis_regack_response, tvb, 2, 1,
			   ENC_BIG_ENDIAN);

    }
    /* Call Dissector for Appendix C TLV's */
    next_tvb = tvb_new_subset_remaining (tvb, 3);
    call_dissector (docsis_tlv_handle, next_tvb, pinfo, regack_tree);

}




/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/


void
proto_register_docsis_regack (void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    {&hf_docsis_regack_sid,
     {"Service Identifier", "docsis_regack.sid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_regack_response,
     {"Response Code", "docsis_regack.respnse",
      FT_UINT8, BASE_DEC, VALS (docsis_conf_code), 0x0,
      NULL, HFILL}
     },
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_docsis_regack,
  };

/* Register the protocol name and description */
  proto_docsis_regack =
    proto_register_protocol ("DOCSIS Registration Acknowledge",
			     "DOCSIS REG-ACK", "docsis_regack");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array (proto_docsis_regack, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  register_dissector ("docsis_regack", dissect_regack, proto_docsis_regack);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_docsis_regack (void)
{
  dissector_handle_t docsis_regack_handle;

  docsis_regack_handle = find_dissector ("docsis_regack");
  docsis_tlv_handle = find_dissector ("docsis_tlv");
  dissector_add_uint ("docsis_mgmt", 0x0e, docsis_regack_handle);

}
