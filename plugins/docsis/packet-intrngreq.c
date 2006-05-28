/* packet-intrngreq.c
 * Routines for Intial Ranging Request Message dissection
 * Copyright 2003, Brian Wheeler <brian.wheeler[AT]arrisi.com>
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

#include "moduleinfo.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gmodule.h>

#include <epan/packet.h>


/* Initialize the protocol and registered fields */
static int proto_docsis_intrngreq = -1;
static int hf_docsis_intrngreq = -1;
static int hf_docsis_intrngreq_down_chid = -1;
static int hf_docsis_intrngreq_sid = -1;
static int hf_docsis_intrngreq_up_chid = -1;


/* Initialize the subtree pointers */
static gint ett_docsis_intrngreq = -1;

/* Code to actually dissect the packets */
static void
dissect_intrngreq (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  proto_item *intrngreq_item;
  proto_tree *intrngreq_tree;
  guint16 sid;

  sid = tvb_get_ntohs (tvb, 0);

  if (check_col (pinfo->cinfo, COL_INFO))
    {
      col_clear (pinfo->cinfo, COL_INFO);
      col_add_fstr (pinfo->cinfo, COL_INFO, "Ranging Request: SID = %u",sid);
    }

  if (tree)
    {
      intrngreq_item =
	proto_tree_add_protocol_format (tree, proto_docsis_intrngreq, tvb, 0,
					tvb_length_remaining (tvb, 0),
					"Initial Ranging Request");
      intrngreq_tree = proto_item_add_subtree (intrngreq_item, ett_docsis_intrngreq);
      proto_tree_add_item (intrngreq_tree, hf_docsis_intrngreq_sid, tvb, 0, 2,
			   FALSE);
      proto_tree_add_item (intrngreq_tree, hf_docsis_intrngreq_down_chid, tvb, 2, 1,
			   FALSE);
      proto_tree_add_item (intrngreq_tree, hf_docsis_intrngreq_up_chid, tvb, 3,
			   1, FALSE);
    }


}




/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/


void
proto_register_docsis_intrngreq (void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    {&hf_docsis_intrngreq,
     {"RNG-REQ Message", "docsis.intrngreq",
      FT_BYTES, BASE_HEX, NULL, 0x0,
      "Ranging Request Message", HFILL}
     },
    {&hf_docsis_intrngreq_sid,
     {"Service Identifier", "docsis.intrngreq.sid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Service Identifier", HFILL}
     },
    {&hf_docsis_intrngreq_down_chid,
     {"Downstream Channel ID", "docsis.intrngreq.downchid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Downstream Channel ID", HFILL}
     },
    {&hf_docsis_intrngreq_up_chid,
     {"Upstream Channel ID", "docsis.intrngreq.upchid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Upstream Channel ID", HFILL}
     },

  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_docsis_intrngreq,
  };

/* Register the protocol name and description */
  proto_docsis_intrngreq = proto_register_protocol ("DOCSIS Initial Ranging Message",
						 "DOCSIS INT-RNG-REQ",
						 "docsis_intrngreq");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array (proto_docsis_intrngreq, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  register_dissector ("docsis_intrngreq", dissect_intrngreq, proto_docsis_intrngreq);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_docsis_intrngreq (void)
{
  dissector_handle_t docsis_intrngreq_handle;

  docsis_intrngreq_handle = find_dissector ("docsis_intrngreq");
  dissector_add ("docsis_mgmt", 0x1E, docsis_intrngreq_handle);

}
