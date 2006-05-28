/* packet-dscrsp.c
 * Routines for Dynamic Service Change Response dissection
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

#include "moduleinfo.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gmodule.h>

#include <epan/packet.h>

/* Initialize the protocol and registered fields */
static int proto_docsis_dscrsp = -1;
static int hf_docsis_dscrsp = -1;
static int hf_docsis_dscrsp_tranid = -1;
static int hf_docsis_dscrsp_response = -1;
static dissector_handle_t docsis_tlv_handle;


/* Initialize the subtree pointers */
static gint ett_docsis_dscrsp = -1;

extern value_string docsis_conf_code[];

/* Code to actually dissect the packets */
static void
dissect_dscrsp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{

  proto_item *it;
  proto_tree *dscrsp_tree;
  guint16 transid;
  guint8 response;
  tvbuff_t *next_tvb;


  transid = tvb_get_ntohs (tvb, 0);
  response = tvb_get_guint8 (tvb, 2);

  if (check_col (pinfo->cinfo, COL_INFO))
    {
      col_clear (pinfo->cinfo, COL_INFO);
      col_add_fstr (pinfo->cinfo, COL_INFO,
		    "Dynamic Service Change Response ID = %u (%s)", transid,
		    val_to_str (response, docsis_conf_code, "%s"));
    }

  if (tree)
    {
      it =
	proto_tree_add_protocol_format (tree, proto_docsis_dscrsp, tvb, 0, -1,
					"DSC Response");
      dscrsp_tree = proto_item_add_subtree (it, ett_docsis_dscrsp);
      proto_tree_add_item (dscrsp_tree, hf_docsis_dscrsp_tranid, tvb, 0, 2,
			   FALSE);
      proto_tree_add_item (dscrsp_tree, hf_docsis_dscrsp_response, tvb, 2, 1,
			   FALSE);

      /* Call Dissector for Appendix C TLV's */
      next_tvb = tvb_new_subset (tvb, 3, -1, -1);
      call_dissector (docsis_tlv_handle, next_tvb, pinfo, dscrsp_tree);
    }
}




/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/


void
proto_register_docsis_dscrsp (void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    {&hf_docsis_dscrsp,
     {"Dynamic Service Change Request", "docsis.dscrsp",
      FT_BYTES, BASE_HEX, NULL, 0x0,
      "Dynamic Service Add Request", HFILL}
     },
    {&hf_docsis_dscrsp_tranid,
     {"Transaction Id", "docsis.dscrsp.tranid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Service Identifier", HFILL}
     },
    {&hf_docsis_dscrsp_response,
     {"Confirmation Code", "docsis.dscrsp.confcode",
      FT_UINT8, BASE_DEC, VALS (docsis_conf_code), 0x0,
      "Confirmation Code", HFILL}
     },
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_docsis_dscrsp,
  };

/* Register the protocol name and description */
  proto_docsis_dscrsp =
    proto_register_protocol ("DOCSIS Dynamic Service Change Response",
			     "DOCSIS DSC-RSP", "docsis_dscrsp");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array (proto_docsis_dscrsp, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  register_dissector ("docsis_dscrsp", dissect_dscrsp, proto_docsis_dscrsp);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_docsis_dscrsp (void)
{
  dissector_handle_t docsis_dscrsp_handle;

  docsis_dscrsp_handle = find_dissector ("docsis_dscrsp");
  docsis_tlv_handle = find_dissector ("docsis_tlv");
  dissector_add ("docsis_mgmt", 0x13, docsis_dscrsp_handle);

}
