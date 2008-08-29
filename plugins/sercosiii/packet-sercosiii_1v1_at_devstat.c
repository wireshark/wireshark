/* packet-sercosiii_1v1_at_devstat.c
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>

#include "packet-sercosiii.h"

static gint hf_siii_at_dev_status = -1;
static gint hf_siii_at_dev_status_commwarning = -1;
static gint hf_siii_at_dev_status_change_topology = -1;
static gint hf_siii_at_dev_status_top_status = -1;
static gint hf_siii_at_dev_status_inactive_port_status = -1;
static gint hf_siii_at_dev_status_errorconnection = -1;
static gint hf_siii_at_dev_status_slave_valid = -1;
static gint hf_siii_at_dev_status_proc_command_change = -1;
static gint hf_siii_at_dev_status_parameterization_level_active = -1;

static gint ett_siii_at_devstatus = -1;

static const value_string siii_at_devstatus_errorconnection_text[]=
{
  {0x00, "Error-free connection"},
  {0x01, "Error in the connection occurs"},
  {0, NULL}
};

static const value_string siii_at_devstatus_topstatus_text[]=
{
  {0x00, "Fast Forward on P/S-Channel"},
  {0x01, "Loopback on P-Channel and Fast Forward"},
  {0x02, "Loopback on S-Channel and Fast Forward"},
  {0, NULL}
};

static const value_string siii_at_devstatus_inactiveportstatus_text[]=
{
  {0x00, "No link on port"},
  {0x01, "Link on port"},
  {0x02, "S III P-Telegramm on port"},
  {0x03, "S III S-Telegramm on port"},
  {0, NULL}
};

static const value_string siii_at_dev_status_proc_command_change_text[]=
{
  {0x00, "No change in procedure command acknowledgement"},
  {0x01, "Changing procedure command acknowledgement"},
  {0, NULL}
};


void dissect_siii_at_devstat(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_tree* subtree;
  proto_item* ti;

  ti = proto_tree_add_item(tree, hf_siii_at_dev_status, tvb, 0, 2, TRUE);
  subtree = proto_item_add_subtree(ti, ett_siii_at_devstatus);

  proto_tree_add_item(subtree, hf_siii_at_dev_status_commwarning, tvb, 0, 2, TRUE);
  proto_tree_add_item(subtree, hf_siii_at_dev_status_change_topology, tvb, 0, 2, TRUE);
  proto_tree_add_item(subtree, hf_siii_at_dev_status_top_status, tvb, 0, 2, TRUE);
  proto_tree_add_item(subtree, hf_siii_at_dev_status_inactive_port_status, tvb, 0, 2, TRUE);
  proto_tree_add_item(subtree, hf_siii_at_dev_status_errorconnection, tvb, 0, 2, TRUE);
  proto_tree_add_item(subtree, hf_siii_at_dev_status_slave_valid, tvb, 0, 2, TRUE);
  proto_tree_add_item(subtree, hf_siii_at_dev_status_proc_command_change, tvb, 0, 2, TRUE);
  proto_tree_add_item(subtree, hf_siii_at_dev_status_parameterization_level_active, tvb, 0, 2, TRUE);
}

void dissect_siii_at_devstat_init(gint proto_siii)
{
  /* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf_siii_header[] = {
    { &hf_siii_at_dev_status,
      { "Word", "siii.at.devstatus",
      FT_UINT16, BASE_HEX, NULL, 0,
      NULL, HFILL }
    },

    { &hf_siii_at_dev_status_commwarning,
      { "Communication Warning", "siii.at.devstatus.commwarning",
      FT_UINT16, BASE_DEC, NULL, 1<<15,
      NULL, HFILL }
    },

    { &hf_siii_at_dev_status_change_topology,
      { "Topology Change", "siii.at.devstatus.topologychanged",
      FT_UINT16, BASE_DEC, NULL, 1<<14,
      NULL, HFILL }
    },
    { &hf_siii_at_dev_status_top_status,
      { "Topology Status", "siii.at.devstatus.topstatus",
      FT_UINT16, BASE_DEC, VALS(siii_at_devstatus_topstatus_text), 0x3<<(12),
      NULL, HFILL }
    },
    { &hf_siii_at_dev_status_inactive_port_status,
      { "Port 1 Status", "siii.at.devstatus.inactportstatus",
      FT_UINT16, BASE_DEC, VALS(siii_at_devstatus_inactiveportstatus_text), 0x3<<(10),
      NULL, HFILL }
    },
    { &hf_siii_at_dev_status_errorconnection,
      { "Topology Status", "siii.at.devstatus.errorconnection",
      FT_UINT16, BASE_DEC, VALS(siii_at_devstatus_errorconnection_text), 1<<9,
      NULL, HFILL }
    },
    { &hf_siii_at_dev_status_slave_valid,
      { "Slave data valid", "siii.at.devstatus.slavevalid",
      FT_UINT16, BASE_DEC, NULL, 1<<8,
      NULL, HFILL }
    },
    { &hf_siii_at_dev_status_proc_command_change,
      { "Procedure Command Change", "siii.at.devstatus.proccmdchange",
      FT_UINT16, BASE_DEC, VALS(siii_at_dev_status_proc_command_change_text), 1<<5,
      NULL, HFILL }
    },
    { &hf_siii_at_dev_status_parameterization_level_active,
      { "Parameterization level active", "siii.at.devstatus.paralevelactive",
      FT_UINT16, BASE_DEC, NULL, 1<<4,
      NULL, HFILL }
    }
  };
  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_siii_at_devstatus
  };

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_siii, hf_siii_header, array_length(hf_siii_header));
  proto_register_subtree_array(ett, array_length(ett));
}
