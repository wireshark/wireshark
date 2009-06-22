/* packet-sercosiii_1v1_hp.c
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

static gint hf_siii_mdt_hotplug_address = -1;
static gint hf_siii_mdt_hp_ctrl = -1;
static gint hf_siii_mdt_hp_info = -1;
static gint hf_siii_at_hotplug_address = -1;
static gint hf_siii_at_hp_stat = -1;
static gint hf_siii_at_hp_info = -1;
static gint hf_siii_mdt_hotplug_control_param = -1;
static gint hf_siii_mdt_hotplug_control_svc_switch = -1;
static gint hf_siii_at_hotplug_status_param = -1;
static gint hf_siii_at_hotplug_status_hp0_finished = -1;
static gint hf_siii_at_hotplug_status_error = -1;

static gint ett_siii_mdt_hp = -1;
static gint ett_siii_at_hp = -1;
static gint ett_siii_mdt_hp_ctrl = -1;
static gint ett_siii_mdt_hp_info = -1;
static gint ett_siii_at_hp_stat = -1;
static gint ett_siii_at_hp_info = -1;

static const value_string siii_mdt_hotplug_control_functioncode_text[]=
{
  {0x00, "No data"},
  {0x01, "tScyc"},
  {0x02, "t1"},
  {0x03, "t6"},
  {0x04, "t7"},
  {0x05, "Communication Version"},
  {0x06, "Communication timeout"},
  {0x10, "MDT0 Length"},
  {0x11, "MDT1 Length"},
  {0x12, "MDT2 Length"},
  {0x13, "MDT3 Length"},
  {0x20, "AT0 Length"},
  {0x21, "AT1 Length"},
  {0x22, "AT2 Length"},
  {0x23, "AT3 Length"},
  {0x80, "MDT-SVC pointer"},
  {0x81, "MDT-RTD pointer"},
  {0x82, "AT-SVC pointer"},
  {0x83, "AT-RTD pointer"},
  {0, NULL}
};

static const value_string siii_mdt_hotplug_control_svc_switch_text[]=
{
  {0, "Transmission via HP-field"},
  {1, "Switch to SVC"},
  {0, NULL}
};

static const value_string siii_mdt_hotplug_status_ackcode_text[]=
{
  {0x80, "MDT-SVC pointer"},
  {0x81, "MDT-RTD pointer"},
  {0x82, "AT-SVC pointer"},
  {0x83, "AT-RTD pointer"},
  {255, "Next Sercos Slave has same address"},
  {0, NULL}
};

static const value_string siii_at_hotplug_status_error_text[]=
{
  {0, "Acknowledgement in HP-1"},
  {1, "Error in HP-1"},
  {0, NULL}
};

void dissect_siii_mdt_hp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_tree* subtree;
  proto_tree* subtree2;
  proto_item* ti;

  ti = proto_tree_add_text(tree, tvb, 0, 8, "Hot-Plug");
  subtree = proto_item_add_subtree(ti, ett_siii_mdt_hp);

  proto_tree_add_item(subtree, hf_siii_mdt_hotplug_address, tvb, 2, 2, TRUE);

  ti = proto_tree_add_item(subtree, hf_siii_mdt_hp_ctrl, tvb, 2, 2, TRUE);
  subtree2 = proto_item_add_subtree(ti, ett_siii_mdt_hp_ctrl);

  proto_tree_add_item(subtree2, hf_siii_mdt_hotplug_control_svc_switch, tvb, 2, 2, TRUE);
  proto_tree_add_item(subtree2, hf_siii_mdt_hotplug_control_param, tvb, 2, 2, TRUE);

  proto_tree_add_item(subtree, hf_siii_mdt_hp_info, tvb, 4, 4, TRUE);
}

void dissect_siii_at_hp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_tree* subtree;
  proto_tree* subtree2;
  proto_item* ti;

  ti = proto_tree_add_text(tree, tvb, 0, 8, "Hot-Plug");
  subtree = proto_item_add_subtree(ti, ett_siii_at_hp);

  proto_tree_add_item(subtree, hf_siii_at_hotplug_address, tvb, 2, 2, TRUE);

  ti = proto_tree_add_item(subtree, hf_siii_at_hp_stat, tvb, 2, 2, TRUE);
  subtree2 = proto_item_add_subtree(ti, ett_siii_at_hp_stat);

  proto_tree_add_item(subtree2, hf_siii_at_hotplug_status_error, tvb, 2, 2, TRUE);
  proto_tree_add_item(subtree2, hf_siii_at_hotplug_status_hp0_finished, tvb, 2, 2, TRUE);
  proto_tree_add_item(subtree2, hf_siii_at_hotplug_status_param, tvb, 2, 2, TRUE);

  proto_tree_add_item(subtree, hf_siii_at_hp_info, tvb, 4, 4, TRUE);
}

void dissect_siii_hp_init(gint proto_siii)
{
  /* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf_siii_header[] = {
    { &hf_siii_mdt_hotplug_address,
      {"Sercos address", "siii.mdt.hp.sercosaddress",
        FT_UINT16, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },
    { &hf_siii_mdt_hp_ctrl,
      {"HP control", "siii.mdt.hp.ctrl",
        FT_UINT16, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },
    { &hf_siii_mdt_hp_info,
      {"HP info", "siii.mdt.hp.info",
        FT_BYTES, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },
    { &hf_siii_at_hotplug_address,
      {"Sercos address", "siii.at.hp.sercosaddress",
        FT_UINT16, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },
    { &hf_siii_at_hp_stat,
      {"HP status", "siii.mdt.hp.stat",
        FT_UINT16, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },
    { &hf_siii_at_hp_info,
      {"HP info", "siii.at.hp.info",
        FT_BYTES, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },
    { &hf_siii_mdt_hotplug_control_param,
      {"Parameter", "siii.mdt.hp.parameter",
        FT_UINT16, BASE_DEC, VALS(siii_mdt_hotplug_control_functioncode_text), 0xFF,
        NULL, HFILL }
    },
    { &hf_siii_mdt_hotplug_control_svc_switch,
      {"Switch to SVC", "siii.mdt.hp.switch",
        FT_UINT16, BASE_DEC, VALS(siii_mdt_hotplug_control_svc_switch_text), 0x100,
        NULL, HFILL }
    },

    { &hf_siii_at_hotplug_status_param,
      {"Parameter Received", "siii.at.hp.parameter",
        FT_UINT16, BASE_DEC, VALS(siii_mdt_hotplug_status_ackcode_text), 0xFF,
        NULL, HFILL }
    },
    { &hf_siii_at_hotplug_status_hp0_finished,
      {"HP/SVC", "siii.at.hp.hp0_finished",
        FT_UINT16, BASE_DEC, NULL, 0x100,
        NULL, HFILL }
    },
    { &hf_siii_at_hotplug_status_error,
      {"Error", "siii.at.hp.error",
        FT_UINT16, BASE_DEC, VALS(siii_at_hotplug_status_error_text), 0x200,
        NULL, HFILL }
    }
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_siii_mdt_hp,
    &ett_siii_at_hp,
    &ett_siii_mdt_hp_ctrl,
    &ett_siii_mdt_hp_info,
    &ett_siii_at_hp_stat,
    &ett_siii_at_hp_info
  };

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_siii, hf_siii_header, array_length(hf_siii_header));
  proto_register_subtree_array(ett, array_length(ett));
}
