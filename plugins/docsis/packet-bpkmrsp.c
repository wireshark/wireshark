/* packet-bpkmrsp.c
 * Routines for Baseline Privacy Key Management Response dissection
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
static int proto_docsis_bpkmrsp = -1;
static int hf_docsis_bpkmrsp_code = -1;
static int hf_docsis_bpkmrsp_length = -1;
static int hf_docsis_bpkmrsp_ident = -1;

static const value_string code_field_vals[] = {
  {0, "Reserved"},
  {1, "Reserved"},
  {2, "Reserved"},
  {3, "Reserved"},
  {4, "Auth Response"},
  {5, "Auth Reply"},
  {6, "Auth Reject"},
  {7, "Key Response"},
  {8, "Key Reply"},
  {9, "Key Reject"},
  {10, "Auth Invalid"},
  {11, "TEK Invalid"},
  {12, "Authent Info"},
  {13, "Map Response"},
  {14, "Map Reply"},
  {15, "Map Reject"},
  {0, NULL},
};


/* Initialize the subtree pointers */
static gint ett_docsis_bpkmrsp = -1;

static dissector_handle_t attrs_handle;

/* Code to actually dissect the packets */
static void
dissect_bpkmrsp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{

  proto_item *it;
  proto_tree *bpkmrsp_tree;
  guint8 code;
  tvbuff_t *attrs_tvb;


  code = tvb_get_guint8 (tvb, 0);

  col_add_fstr (pinfo->cinfo, COL_INFO, "BPKM Response (%s)",
	    val_to_str (code, code_field_vals, "Unknown code %u"));

  if (tree)
    {
      it =
	proto_tree_add_protocol_format (tree, proto_docsis_bpkmrsp, tvb, 0, -1,
					"BPKM Response Message");
      bpkmrsp_tree = proto_item_add_subtree (it, ett_docsis_bpkmrsp);
      proto_tree_add_item (bpkmrsp_tree, hf_docsis_bpkmrsp_code, tvb, 0, 1,
			   ENC_BIG_ENDIAN);
      proto_tree_add_item (bpkmrsp_tree, hf_docsis_bpkmrsp_ident, tvb, 1, 1,
			   ENC_BIG_ENDIAN);
      proto_tree_add_item (bpkmrsp_tree, hf_docsis_bpkmrsp_length, tvb, 2, 2,
			   ENC_BIG_ENDIAN);
    }

  /* Code to Call subdissector */
  attrs_tvb = tvb_new_subset_remaining (tvb, 4);
  call_dissector (attrs_handle, attrs_tvb, pinfo, tree);
}




/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/


void
proto_register_docsis_bpkmrsp (void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    {&hf_docsis_bpkmrsp_code,
     {"BPKM Code", "docsis_bpkmrsp.code",
      FT_UINT8, BASE_DEC, VALS (code_field_vals), 0x0,
      "BPKM Response Message", HFILL}
     },
    {&hf_docsis_bpkmrsp_ident,
     {"BPKM Identifier", "docsis_bpkmrsp.ident",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_bpkmrsp_length,
     {"BPKM Length", "docsis_bpkmrsp.length",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_docsis_bpkmrsp,
  };

/* Register the protocol name and description */
  proto_docsis_bpkmrsp =
    proto_register_protocol
    ("DOCSIS Baseline Privacy Key Management Response", "DOCSIS BPKM-RSP",
     "docsis_bpkmrsp");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array (proto_docsis_bpkmrsp, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  register_dissector ("docsis_bpkmrsp", dissect_bpkmrsp,
		      proto_docsis_bpkmrsp);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_docsis_bpkmrsp (void)
{
  dissector_handle_t docsis_bpkmrsp_handle;

  docsis_bpkmrsp_handle = find_dissector ("docsis_bpkmrsp");
  attrs_handle = find_dissector ("docsis_bpkmattr");
  dissector_add_uint ("docsis_mgmt", 0x0D, docsis_bpkmrsp_handle);

}
