/* packet-arcnet.c
 * Routines for arcnet dissection
 * Copyright 2001-2002, Peter Fales <ethereal@fales-lorenz.net>
 *
 * $Id: packet-arcnet.c,v 1.2 2002/10/18 21:10:38 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include "arcnet_pids.h"

/* Initialize the protocol and registered fields */
static int proto_arcnet = -1;
static int hf_arcnet_src = -1;
static int hf_arcnet_dst = -1;
static int hf_arcnet_protID = -1;

/* Initialize the subtree pointers */
static gint ett_arcnet = -1;

static dissector_table_t arcnet_dissector_table;
static dissector_handle_t data_handle;

/* Code to actually dissect the packets */
static void
dissect_arcnet (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  guint8 dst, src, protID;
  tvbuff_t *next_tvb;

/* Set up structures needed to add the protocol subtree and manage it */
  proto_item *ti;
  proto_tree *arcnet_tree;

/* Make entries in Protocol column and Info column on summary display */
  if (check_col (pinfo->cinfo, COL_PROTOCOL))
    col_set_str (pinfo->cinfo, COL_PROTOCOL, "ARCNET");

  if (check_col (pinfo->cinfo, COL_INFO))
    col_set_str (pinfo->cinfo, COL_INFO, "ARCNET");

  src = tvb_get_guint8 (tvb, 0);
  dst = tvb_get_guint8 (tvb, 1);
  protID = tvb_get_guint8 (tvb, 4);

/* In the interest of speed, if "tree" is NULL, don't do any work not
   necessary to generate protocol tree items. */
  if (tree)
    {

/* create display subtree for the protocol */
      ti =
	proto_tree_add_item (tree, proto_arcnet, tvb, 0, tvb_length (tvb),
			     FALSE);

      arcnet_tree = proto_item_add_subtree (ti, ett_arcnet);

      proto_tree_add_uint (tree, hf_arcnet_src, tvb, 0, 1, src);
      proto_tree_add_uint (tree, hf_arcnet_dst, tvb, 1, 1, dst);
      proto_tree_add_uint (tree, hf_arcnet_protID, tvb, 4, 1, protID);
    }

/* If this protocol has a sub-dissector call it here, see section 1.8 */

  next_tvb = tvb_new_subset (tvb, 8, -1, -1);

  if (!dissector_try_port (arcnet_dissector_table, protID,
			   next_tvb, pinfo, tree))
    {
      if (check_col (pinfo->cinfo, COL_PROTOCOL))
	{
	  col_add_fstr (pinfo->cinfo, COL_PROTOCOL, "0x%04x", protID);
	}
      call_dissector (data_handle, next_tvb, pinfo, tree);
    }

}


/* Register the protocol with Ethereal */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

static const value_string arcnet_prot_id_vals[] = {
  {ARCNET_PROTO_IP, "IP packet"},
  {ARCNET_PROTO_ARP, "ARP packet"},
  {ARCNET_PROTO_IPX, "IPX packet"},
  {0, NULL}
};

void
proto_register_arcnet (void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    {&hf_arcnet_src,
     {"Source", "arcnet.src",
      FT_UINT8, BASE_HEX, NULL, 0,
      "Source ID", HFILL}
     },
    {&hf_arcnet_dst,
     {"Dest", "arcnet.dst",
      FT_UINT8, BASE_HEX, NULL, 0,
      "Dest ID", HFILL}
     },
    {&hf_arcnet_protID,
     {"Protocol ID", "arcnet.protID",
      FT_UINT8, BASE_HEX, VALS(arcnet_prot_id_vals), 0,
      "Proto type", HFILL}
     },
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_arcnet,
  };

  arcnet_dissector_table = register_dissector_table ("arcnet.protocol_id",
						     "ARCNET Protocol ID",
						     FT_UINT8, BASE_HEX);

/* Register the protocol name and description */
  proto_arcnet = proto_register_protocol ("ARCNET", "ARCNET", "arcnet");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array (proto_arcnet, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
}


void
proto_reg_handoff_arcnet (void)
{
  dissector_handle_t arcnet_handle;

  arcnet_handle = create_dissector_handle (dissect_arcnet, proto_arcnet);

  dissector_add ("wtap_encap", WTAP_ENCAP_ARCNET, arcnet_handle);
  data_handle = find_dissector ("data");
}
