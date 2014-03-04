/* packet-dpvrsp.c
 * Routines for DOCSIS 3.0 DOCSIS Path Verify Request Message dissection.
 * Copyright 2010, Guido Reismueller <g.reismueller[AT]avm.de>
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

void proto_register_docsis_dpvrsp(void);
void proto_reg_handoff_docsis_dpvrsp(void);

/* Initialize the protocol and registered fields */
static int proto_docsis_dpvrsp = -1;
static int hf_docsis_dpvrsp_tranid = -1;
static int hf_docsis_dpvrsp_dschan = -1;
static int hf_docsis_dpvrsp_flags = -1;
static int hf_docsis_dpvrsp_us_sf = -1;
static int hf_docsis_dpvrsp_n = -1;
static int hf_docsis_dpvrsp_start = -1;
static int hf_docsis_dpvrsp_end = -1;
static int hf_docsis_dpvrsp_ts_start = -1;
static int hf_docsis_dpvrsp_ts_end = -1;

/* Initialize the subtree pointers */
static gint ett_docsis_dpvrsp = -1;

/* Code to actually dissect the packets */
static void
dissect_dpvrsp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  proto_item *it;
  proto_tree *dpvrsp_tree = NULL;
  guint16 transid;
  guint8 dschan;

  transid = tvb_get_ntohs (tvb, 0);
  dschan = tvb_get_guint8 (tvb, 2);

  col_add_fstr (pinfo->cinfo, COL_INFO,
	    "DOCSIS Path Verify Response: Transaction-Id = %u DS-Ch %d",
		transid, dschan);

  if (tree)
    {
      it =
	proto_tree_add_protocol_format (tree, proto_docsis_dpvrsp, tvb, 0, -1,
					"DPV Response");
      dpvrsp_tree = proto_item_add_subtree (it, ett_docsis_dpvrsp);
      proto_tree_add_item (dpvrsp_tree, hf_docsis_dpvrsp_tranid, tvb,
			  0, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item (dpvrsp_tree, hf_docsis_dpvrsp_dschan, tvb,
			  2, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item (dpvrsp_tree, hf_docsis_dpvrsp_flags, tvb,
			  3, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item (dpvrsp_tree, hf_docsis_dpvrsp_us_sf, tvb,
			  4, 4, ENC_BIG_ENDIAN);
      proto_tree_add_item (dpvrsp_tree, hf_docsis_dpvrsp_n, tvb,
			  8, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item (dpvrsp_tree, hf_docsis_dpvrsp_start, tvb,
			  10, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item (dpvrsp_tree, hf_docsis_dpvrsp_end, tvb,
			  11, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item (dpvrsp_tree, hf_docsis_dpvrsp_ts_start, tvb,
			  12, 4, ENC_BIG_ENDIAN);
      proto_tree_add_item (dpvrsp_tree, hf_docsis_dpvrsp_ts_end, tvb,
			  16, 4, ENC_BIG_ENDIAN);
    }
}




/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_docsis_dpvrsp (void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    {&hf_docsis_dpvrsp_tranid,
     {"Transaction Id", "docsis_dpvrsp.tranid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_dpvrsp_dschan,
     {"Downstream Channel ID", "docsis_dpvrsp.dschan",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_dpvrsp_flags,
     {"Flags", "docsis_dpvrsp.flags",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_dpvrsp_us_sf,
     {"Upstream Service Flow ID", "docsis_dpvrsp.us_sf",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_dpvrsp_n,
     {"N (Measurement avaraging factor)", "docsis_dpvrsp.n",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_dpvrsp_start,
     {"Start Reference Point", "docsis_dpvrsp.start",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_dpvrsp_end,
     {"End Reference Point", "docsis_dpvrsp.end",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_dpvrsp_ts_start,
     {"Timestamp Start", "docsis_dpvrsp.ts_start",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_dpvrsp_ts_end,
     {"Timestamp End", "docsis_dpvrsp.ts_end",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_docsis_dpvrsp,
  };

/* Register the protocol name and description */
  proto_docsis_dpvrsp =
    proto_register_protocol ("DOCSIS Path Verify Response",
			     "DOCSIS DPV-RSP", "docsis_dpvrsp");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array (proto_docsis_dpvrsp, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  register_dissector ("docsis_dpvrsp", dissect_dpvrsp, proto_docsis_dpvrsp);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_docsis_dpvrsp (void)
{
  dissector_handle_t docsis_dpvrsp_handle;

  docsis_dpvrsp_handle = find_dissector ("docsis_dpvrsp");
  dissector_add_uint ("docsis_mgmt", 0x28, docsis_dpvrsp_handle);
}
