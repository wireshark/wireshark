/* packet-bpkmreq.c
 * Routines for Baseline Privacy Key Management Request dissection
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
static int proto_docsis_bpkmreq = -1;
static int hf_docsis_bpkmreq = -1;
static int hf_docsis_bpkmreq_code = -1;
static int hf_docsis_bpkmreq_length = -1;
static int hf_docsis_bpkmreq_ident = -1;

static const value_string code_field_vals[] = {
  {0, "Reserved"},
  {1, "Reserved"},
  {2, "Reserved"},
  {3, "Reserved"},
  {4, "Auth Request"},
  {5, "Auth Reply"},
  {6, "Auth Reject"},
  {7, "Key Request"},
  {8, "Key Reply"},
  {9, "Key Reject"},
  {10, "Auth Invalid"},
  {11, "TEK Invalid"},
  {12, "Authent Info"},
  {13, "Map Request"},
  {14, "Map Reply"},
  {15, "Map Reject"},
  {0, NULL},
};


/* Initialize the subtree pointers */
static gint ett_docsis_bpkmreq = -1;

static dissector_handle_t attrs_handle;

/* Code to actually dissect the packets */
static void
dissect_bpkmreq (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{

  proto_item *it;
  proto_tree *bpkmreq_tree;
  guint8 code;
  tvbuff_t *attrs_tvb;

  code = tvb_get_guint8 (tvb, 0);

  if (check_col (pinfo->cinfo, COL_INFO))
    {
      col_clear (pinfo->cinfo, COL_INFO);
      col_add_fstr (pinfo->cinfo, COL_INFO, "BPKM Request (%s)",
		    val_to_str (code, code_field_vals, "%s"));
    }

  if (tree)
    {
      it =
	proto_tree_add_protocol_format (tree, proto_docsis_bpkmreq, tvb, 0, -1,
					"BPKM Request Message");
      bpkmreq_tree = proto_item_add_subtree (it, ett_docsis_bpkmreq);
      proto_tree_add_item (bpkmreq_tree, hf_docsis_bpkmreq_code, tvb, 0, 1,
			   FALSE);
      proto_tree_add_item (bpkmreq_tree, hf_docsis_bpkmreq_ident, tvb, 1, 1,
			   FALSE);
      proto_tree_add_item (bpkmreq_tree, hf_docsis_bpkmreq_length, tvb, 2, 2,
			   FALSE);
    }

  /* Code to Call subdissector */
  attrs_tvb = tvb_new_subset (tvb, 4, -1, -1);
  call_dissector (attrs_handle, attrs_tvb, pinfo, tree);



}




/* Register the protocol with Ethereal */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/


void
proto_register_docsis_bpkmreq (void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    {&hf_docsis_bpkmreq,
     {"BPKM Request Message", "docsis.bpkmreq",
      FT_BYTES, BASE_HEX, NULL, 0x0,
      "BPKM Request Message", HFILL}
     },
    {&hf_docsis_bpkmreq_code,
     {"BPKM Code", "docsis.bpkmreq.code",
      FT_UINT8, BASE_DEC, VALS (code_field_vals), 0x0,
      "BPKM Request Message", HFILL}
     },
    {&hf_docsis_bpkmreq_ident,
     {"BPKM Identifier", "docsis.bpkmreq.ident",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "BPKM Identifier", HFILL}
     },
    {&hf_docsis_bpkmreq_length,
     {"BPKM Length", "docsis.bpkmreq.length",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "BPKM Length", HFILL}
     },
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_docsis_bpkmreq,
  };

/* Register the protocol name and description */
  proto_docsis_bpkmreq =
    proto_register_protocol ("DOCSIS Baseline Privacy Key Management Request",
			     "DOCSIS BPKM-REQ", "docsis_bpkmreq");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array (proto_docsis_bpkmreq, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  register_dissector ("docsis_bpkmreq", dissect_bpkmreq,
		      proto_docsis_bpkmreq);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_docsis_bpkmreq (void)
{
  dissector_handle_t docsis_bpkmreq_handle;

  docsis_bpkmreq_handle = find_dissector ("docsis_bpkmreq");
  attrs_handle = find_dissector ("docsis_bpkmattr");
  dissector_add ("docsis_mgmt", 0x0C, docsis_bpkmreq_handle);

}
