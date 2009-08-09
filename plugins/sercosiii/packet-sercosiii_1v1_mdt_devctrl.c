/* packet-sercosiii_1v1_mdt_devctrl.c
 * Routines for SERCOS III dissection
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

#include <glib.h>

#include <epan/packet.h>

#include "packet-sercosiii.h"

static gint hf_siii_mdt_dev_control_top_control = -1;
static gint hf_siii_at_dev_control_ident = -1;
static gint hf_siii_mdt_dev_control_change_topology = -1;
static gint hf_siii_mdt_dev_control = -1;

static gint ett_siii_mdt_devctrl = -1;

static const value_string siii_mdt_devcontrol_topcontrol_text[]=
{
  {0x00, "Fast Forward on P/S-Channel"},
  {0x01, "Loopback on P-Channel and Fast Forward"},
  {0x02, "Loopback on S-Channel and Fast Forward"},
  {0, NULL}
};

void dissect_siii_mdt_devctrl(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_tree* subtree;
  proto_item* ti;

  ti = proto_tree_add_item(tree, hf_siii_mdt_dev_control, tvb, 0, 2, TRUE);
  subtree = proto_item_add_subtree(ti, ett_siii_mdt_devctrl);

  proto_tree_add_item(subtree, hf_siii_at_dev_control_ident, tvb, 0, 2, TRUE);
  proto_tree_add_item(subtree, hf_siii_mdt_dev_control_change_topology, tvb, 0, 2, TRUE);
  proto_tree_add_item(subtree, hf_siii_mdt_dev_control_top_control, tvb, 0, 2, TRUE);
}

void dissect_siii_mdt_devctrl_init(gint proto_siii)
{
  /* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf_siii_header[] = {
    { &hf_siii_mdt_dev_control_top_control,
      { "Topology Control", "siii.mdt.devcontrol.topcontrol",
      FT_UINT16, BASE_DEC, VALS(siii_mdt_devcontrol_topcontrol_text), 3<<(12),
      NULL, HFILL }
    },
    { &hf_siii_at_dev_control_ident,
      { "Identification", "siii.mdt.devcontrol.identrequest",
      FT_UINT16, BASE_DEC, NULL, 0x8000,
      NULL, HFILL }
    },
    { &hf_siii_mdt_dev_control_change_topology,
      { "Changing Topology", "siii.mdt.devcontrol.topologychange",
      FT_UINT16, BASE_DEC, NULL, 1<<14,
      NULL, HFILL }
    },
    { &hf_siii_mdt_dev_control,
      { "Word", "siii.mdt.devcontrol",
      FT_UINT16, BASE_DEC, NULL, 0,
      NULL, HFILL }
    }
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_siii_mdt_devctrl
  };

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_siii, hf_siii_header, array_length(hf_siii_header));
  proto_register_subtree_array(ett, array_length(ett));
}
