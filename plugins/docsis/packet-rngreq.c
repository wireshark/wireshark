/* packet-rngreq.c
 * Routines for Ranging Request Message dissection
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
#include "config.h"
#endif

#include <epan/packet.h>


/* Initialize the protocol and registered fields */
static int proto_docsis_rngreq = -1;
static int hf_docsis_rngreq_down_chid = -1;
static int hf_docsis_rngreq_sid = -1;
static int hf_docsis_rngreq_pend_compl = -1;


/* Initialize the subtree pointers */
static gint ett_docsis_rngreq = -1;

/* Code to actually dissect the packets */
static void
dissect_rngreq (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  proto_item *it;
  proto_tree *rngreq_tree;
  guint16 sid;

  sid = tvb_get_ntohs (tvb, 0);

  col_clear (pinfo->cinfo, COL_INFO);
  if (sid > 0)
	col_add_fstr (pinfo->cinfo, COL_INFO, "Ranging Request: SID = %u",
		      sid);
  else
	col_set_str(pinfo->cinfo, COL_INFO, "Initial Ranging Request SID = 0");

  if (tree)
    {
      it =
	proto_tree_add_protocol_format (tree, proto_docsis_rngreq, tvb, 0, -1,
					"Ranging Request");
      rngreq_tree = proto_item_add_subtree (it, ett_docsis_rngreq);
      proto_tree_add_item (rngreq_tree, hf_docsis_rngreq_sid, tvb, 0, 2,
			   ENC_BIG_ENDIAN);
      proto_tree_add_item (rngreq_tree, hf_docsis_rngreq_down_chid, tvb, 2, 1,
			   ENC_BIG_ENDIAN);
      proto_tree_add_item (rngreq_tree, hf_docsis_rngreq_pend_compl, tvb, 3,
			   1, ENC_BIG_ENDIAN);
    }


}




/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/


void
proto_register_docsis_rngreq (void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    {&hf_docsis_rngreq_sid,
     {"Service Identifier", "docsis_rngreq.sid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_rngreq_down_chid,
     {"Downstream Channel ID", "docsis_rngreq.downchid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_rngreq_pend_compl,
     {"Pending Till Complete", "docsis_rngreq.pendcomp",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Upstream Channel ID", HFILL}
     },

  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_docsis_rngreq,
  };

/* Register the protocol name and description */
  proto_docsis_rngreq = proto_register_protocol ("DOCSIS Range Request Message",
						 "DOCSIS RNG-REQ",
						 "docsis_rngreq");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array (proto_docsis_rngreq, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  register_dissector ("docsis_rngreq", dissect_rngreq, proto_docsis_rngreq);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_docsis_rngreq (void)
{
  dissector_handle_t docsis_rngreq_handle;

  docsis_rngreq_handle = find_dissector ("docsis_rngreq");
  dissector_add_uint ("docsis_mgmt", 0x04, docsis_rngreq_handle);

}
