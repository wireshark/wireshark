/* packet-mesh-header.c
 * Routines for Mesh Header dissection
 * Javier Cardona <javier@cozybit.com>
 * Copyright 2007, Marvell Semiconductors Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>

#include <glib.h>

#include <epan/packet.h>

/* Initialize the protocol and registered fields */
static int proto_mesh = -1;
static int hf_mesh_ttl = -1;
static int hf_mesh_e2eseq = -1;

/* Initialize the subtree pointers */
static gint ett_mesh = -1;

/* Code to actually dissect the packets */
static int
dissect_mesh(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  /* Set up structures needed to add the protocol subtree and manage it */
  proto_item *ti;
  proto_tree *mesh_tree;
  guint8 mesh_ttl;
  guint16 mesh_e2eseq;

  /* Make entries in Protocol column and Info column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Mesh");

  if (tree) {
    ti = proto_tree_add_item(tree, proto_mesh, tvb, 0, 5, ENC_NA);
    mesh_tree = proto_item_add_subtree(ti, ett_mesh);

    /* add an item to the subtree, see section 1.6 for more information */
    mesh_ttl = tvb_get_guint8(tvb, 2);
    proto_tree_add_uint(mesh_tree, hf_mesh_ttl, tvb, 2, 1, mesh_ttl);

    mesh_e2eseq = tvb_get_ntohs(tvb, 3);
    proto_tree_add_uint(mesh_tree, hf_mesh_e2eseq, tvb, 3, 2, mesh_e2eseq);
  }

  /* Return the amount of data this dissector was able to dissect */
  return 5;
}


/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_mesh(void)
{
  /* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    { &hf_mesh_ttl,
      { "Mesh TTL", "mesh.ttl", FT_UINT8, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},

    { &hf_mesh_e2eseq,
      { "Mesh End-to-end Seq", "mesh.e2eseq", FT_UINT16, BASE_HEX,
        NULL, 0x0, NULL, HFILL }},
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_mesh
  };

  /* Register the protocol name and description */
  proto_mesh = proto_register_protocol("Mesh Header", "Mesh", "mesh");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_mesh, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  new_register_dissector("mesh", dissect_mesh, proto_mesh);
}
