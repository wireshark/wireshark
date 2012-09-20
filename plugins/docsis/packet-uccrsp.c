/* packet-uccrsp.c
 * Routines for Upstream Channel Change Response dissection
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
static int proto_docsis_uccrsp = -1;
static int hf_docsis_uccrsp_upchid = -1;


/* Initialize the subtree pointers */
static gint ett_docsis_uccrsp = -1;

/* Code to actually dissect the packets */
static void
dissect_uccrsp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{

  proto_item *it;
  proto_tree *uccrsp_tree;
  guint8 chid;

  chid = tvb_get_guint8 (tvb, 0);

  col_clear (pinfo->cinfo, COL_INFO);
  col_add_fstr (pinfo->cinfo, COL_INFO,
	    "Upstream Channel Change response  Channel ID = %u (U%u)",
	    chid, (chid > 0 ? chid - 1 : chid));

  if (tree)
    {
      it =
	proto_tree_add_protocol_format (tree, proto_docsis_uccrsp, tvb, 0, -1,
					"UCC Response");
      uccrsp_tree = proto_item_add_subtree (it, ett_docsis_uccrsp);
      proto_tree_add_item (uccrsp_tree, hf_docsis_uccrsp_upchid, tvb, 0, 1,
			   ENC_BIG_ENDIAN);
    }

}




/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/


void
proto_register_docsis_uccrsp (void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    {&hf_docsis_uccrsp_upchid,
     {"Upstream Channel Id", "docsis_uccrsp.upchid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_docsis_uccrsp,
  };

/* Register the protocol name and description */
  proto_docsis_uccrsp =
    proto_register_protocol ("DOCSIS Upstream Channel Change Response",
			     "DOCSIS UCC-RSP", "docsis_uccrsp");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array (proto_docsis_uccrsp, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  register_dissector ("docsis_uccrsp", dissect_uccrsp, proto_docsis_uccrsp);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_docsis_uccrsp (void)
{
  dissector_handle_t docsis_uccrsp_handle;

  docsis_uccrsp_handle = find_dissector ("docsis_uccrsp");
  dissector_add_uint ("docsis_mgmt", 0x09, docsis_uccrsp_handle);

}
