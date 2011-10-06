/* packet-dsarsp.c
 * Routines for Dynamic Service Addition Response dissection
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>

/* Initialize the protocol and registered fields */
static int proto_docsis_dsarsp = -1;
static int hf_docsis_dsarsp_tranid = -1;
static int hf_docsis_dsarsp_response = -1;
static dissector_handle_t docsis_tlv_handle;


/* Initialize the subtree pointers */
static gint ett_docsis_dsarsp = -1;

extern value_string docsis_conf_code[];

/* Code to actually dissect the packets */
static void
dissect_dsarsp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{

  proto_item *it;
  proto_tree *dsarsp_tree = NULL;
  guint16 transid;
  guint8 response;
  tvbuff_t *next_tvb;

  transid = tvb_get_ntohs (tvb, 0);
  response = tvb_get_guint8 (tvb, 2);

  col_add_fstr (pinfo->cinfo, COL_INFO,
	    "Dynamic Service Add Response ID = %u (%s)", transid,
	    val_to_str (response, docsis_conf_code, "%d"));

  if (tree)
    {
      it =
	proto_tree_add_protocol_format (tree, proto_docsis_dsarsp, tvb, 0, -1,
					"DSA Response");
      dsarsp_tree = proto_item_add_subtree (it, ett_docsis_dsarsp);
      proto_tree_add_item (dsarsp_tree, hf_docsis_dsarsp_tranid, tvb, 0, 2,
			   ENC_BIG_ENDIAN);
      proto_tree_add_item (dsarsp_tree, hf_docsis_dsarsp_response, tvb, 2, 1,
			   ENC_BIG_ENDIAN);

    }
    /* Call dissector for Appendix C TLV's */
    next_tvb = tvb_new_subset_remaining (tvb, 3);
    call_dissector (docsis_tlv_handle, next_tvb, pinfo, dsarsp_tree);



}




/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/


void
proto_register_docsis_dsarsp (void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    {&hf_docsis_dsarsp_tranid,
     {"Transaction Id", "docsis_dsarsp.tranid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Service Identifier", HFILL}
     },
    {&hf_docsis_dsarsp_response,
     {"Confirmation Code", "docsis_dsarsp.confcode",
      FT_UINT8, BASE_DEC, VALS (docsis_conf_code), 0x0,
      NULL, HFILL}
     },
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_docsis_dsarsp,
  };

/* Register the protocol name and description */
  proto_docsis_dsarsp =
    proto_register_protocol ("DOCSIS Dynamic Service Addition Response",
			     "DOCSIS DSA-RSP", "docsis_dsarsp");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array (proto_docsis_dsarsp, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  register_dissector ("docsis_dsarsp", dissect_dsarsp, proto_docsis_dsarsp);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_docsis_dsarsp (void)
{
  dissector_handle_t docsis_dsarsp_handle;

  docsis_dsarsp_handle = find_dissector ("docsis_dsarsp");
  docsis_tlv_handle = find_dissector ("docsis_tlv");
  dissector_add_uint ("docsis_mgmt", 0x10, docsis_dsarsp_handle);

}
