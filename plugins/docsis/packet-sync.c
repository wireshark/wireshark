/* packet-sync.c
 * $Id$
 * Routines for Sync Message dissection
 * Copyright 2007, Bruno Verstuyft  <bruno.verstuyft@excentis.com>
 *
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
static int proto_docsis_sync = -1;
static int hf_docsis_sync_cmts_timestamp = -1;


/* Initialize the subtree pointers */
static gint ett_docsis_sync = -1;

static void
dissect_sync (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
	proto_item *it;
	proto_tree *sync_tree;

	col_set_str(pinfo->cinfo, COL_INFO, "Sync Message:");

	if (tree)
	{
	it = proto_tree_add_protocol_format (tree, proto_docsis_sync, tvb, 0, -1,"SYNC Message");
	sync_tree = proto_item_add_subtree (it, ett_docsis_sync);

	proto_tree_add_item (sync_tree, hf_docsis_sync_cmts_timestamp, tvb, 0, 4,
			ENC_BIG_ENDIAN);
	}				/* if(tree) */
}




/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/


void
proto_register_docsis_sync (void)
{
	/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{&hf_docsis_sync_cmts_timestamp,
		{"CMTS Timestamp", "docsis_sync.cmts_timestamp",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		"Sync CMTS Timestamp", HFILL}
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_docsis_sync,
	};

	/* Register the protocol name and description */
	proto_docsis_sync =
		proto_register_protocol ("DOCSIS Synchronisation Message",
					"DOCSIS Sync", "docsis_sync");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array (proto_docsis_sync, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));

	register_dissector ("docsis_sync", dissect_sync, proto_docsis_sync);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_docsis_sync (void)
{
	dissector_handle_t docsis_sync_handle;

	docsis_sync_handle = find_dissector ("docsis_sync");
	dissector_add_uint ("docsis_mgmt", 1, docsis_sync_handle);
}
