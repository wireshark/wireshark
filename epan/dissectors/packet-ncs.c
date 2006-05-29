/* packet-ncs.c
 * Routines for Novell Cluster Services
 * Greg Morris <gmorris@novell.com>
 * Copyright (c) Novell, Inc. 2002-2005
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
 
 
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/ipproto.h>

static gint ett_ncs = -1;

static int proto_ncs = -1;

static int hf_panning_id = -1;
static int hf_incarnation = -1;

static void
dissect_ncs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree	    *ncs_tree = NULL;
    proto_item	    *ti;
    
    if (tree) {
        ti = proto_tree_add_item(tree, proto_ncs, tvb, 0, -1, FALSE);
        ncs_tree = proto_item_add_subtree(ti, ett_ncs);
    }


    if (check_col(pinfo->cinfo, COL_PROTOCOL))
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "NCS");
    if (check_col(pinfo->cinfo, COL_INFO))
    {
      col_clear(pinfo->cinfo, COL_INFO);
      col_set_str(pinfo->cinfo, COL_INFO, "Novell Cluster Services Heartbeat");
    }

    proto_tree_add_item(ncs_tree, hf_panning_id, tvb, 4, 4, FALSE);
    proto_tree_add_item(ncs_tree, hf_incarnation, tvb, 8, 4, FALSE);
}

void
proto_register_ncs(void)
{
  static hf_register_info hf[] = {

    { &hf_panning_id,
      { "Panning ID",		"ncs.pan_id",		FT_UINT32, BASE_HEX,	NULL, 0x0,
      	"", HFILL }},

    { &hf_incarnation,
      { "Incarnation",		"ncs.incarnation",		FT_UINT32, BASE_HEX,	NULL, 0x0,
      	"", HFILL }},

  };
  static gint *ett[] = {
    &ett_ncs,
  };

  proto_ncs = proto_register_protocol("Novell Cluster Services",
				       "NCS", "ncs");
  proto_register_field_array(proto_ncs, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}



void
proto_reg_handoff_ncs(void)
{
  dissector_handle_t ncs_handle;
  dissector_handle_t ip_handle;
  /*
   * Get handle for the IP dissector.
   */
  ip_handle = find_dissector("ip");

  ncs_handle = create_dissector_handle(dissect_ncs, proto_ncs);
  dissector_add("ip.proto", IP_PROTO_NCS_HEARTBEAT, ncs_handle);
}
