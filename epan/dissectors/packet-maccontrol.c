/* packet-maccontrol.c
 * Routines for MAC Control ethernet header disassembly
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
#include "packet-ieee8023.h"
#include "packet-llc.h"
#include <epan/etypes.h>

static int proto_macctrl = -1;

static gint ett_macctrl = -1;
static int hf_macctrl_pause = -1;
static int hf_macctrl_quanta = -1;


static void
dissect_macctrl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *ti;
  proto_tree *volatile macctrl_tree;
	guint16 pause;
	guint16 pause_quanta;

	pause = tvb_get_ntohs(tvb, 0);
	pause_quanta = tvb_get_ntohs(tvb, 2);

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CTRL");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  if (pause==1){
    if (check_col(pinfo->cinfo, COL_INFO)) {
      col_add_fstr(pinfo->cinfo, COL_INFO, "MAC PAUSE: Quanta %d", pause_quanta);
    }
  } 

  macctrl_tree = NULL;

  if (tree) {
		ti = proto_tree_add_item(tree, proto_macctrl, tvb, 0, 4, FALSE);
		macctrl_tree = proto_item_add_subtree(ti, ett_macctrl);
		
		proto_tree_add_uint(macctrl_tree, hf_macctrl_pause, tvb, 0, 2, pause);
    proto_tree_add_uint(macctrl_tree, hf_macctrl_quanta, tvb, 2, 2, pause_quanta);
	}

}


void
proto_register_macctrl(void)
{
	static hf_register_info hf[] = {
        { &hf_macctrl_pause, 
        {  "Pause", "macctrl.pause", FT_UINT16, BASE_HEX,
           NULL, 0x0, "MAC control Pause", HFILL}},

        { &hf_macctrl_quanta,
        { "Quanta", "macctrl.quanta", FT_UINT16, BASE_DEC,
          NULL, 0x0, "MAC control quanta", HFILL }}
	};

  static gint *ett[] = {
        &ett_macctrl,
  };
  proto_macctrl = proto_register_protocol("MAC Control", "MACC", "macc");
	proto_register_field_array(proto_macctrl, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_macctrl(void)
{
  dissector_handle_t macctrl_handle;

  macctrl_handle = create_dissector_handle(dissect_macctrl, proto_macctrl);
  dissector_add("ethertype", ETHERTYPE_MAC_CONTROL, macctrl_handle);
}
