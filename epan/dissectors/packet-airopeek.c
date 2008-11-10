/* packet-airopeek.c
 *
 * Routines for the disassembly airopeek encapsulated wireless
 * traces (tested with frames captured from a Cisco WCS).
 *
 * $Id$
 *
 * Copyright 2007 Joerg Mayer (see AUTHORS file)
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

/*
 * TODO: Decode meta information.
 *       Check on fillup bytes in capture (fcs sometimes wrong)
 * From:
 * http://www.cisco.com/univercd/cc/td/doc/product/wireless/pahcont/oweb.pdf
 * "It will include information on timestamp, signal strength, packet size
 *  and so on"
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <glib.h>
#include <epan/packet.h>

static int proto_airopeek = -1;
static gint hf_airopeek_unknown1 = -1;
static gint hf_airopeek_unknown2 = -1;
static gint hf_airopeek_unknown3 = -1;
static gint hf_airopeek_unknown4 = -1;
static gint ett_airopeek = -1;

static dissector_handle_t ieee80211_handle;

static void
dissect_airopeek(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  tvbuff_t *next_tvb;
  proto_tree *airopeek_tree = NULL;
  proto_item *ti = NULL;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "AIROPEEK");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_airopeek, tvb, 0, -1, FALSE);
    airopeek_tree = proto_item_add_subtree(ti, ett_airopeek);

    proto_tree_add_item(airopeek_tree, hf_airopeek_unknown1, tvb, 0, 2,  FALSE);
    proto_tree_add_item(airopeek_tree, hf_airopeek_unknown2, tvb, 2, 2,  FALSE);
    proto_tree_add_item(airopeek_tree, hf_airopeek_unknown3, tvb, 4, 2,  FALSE);
    proto_tree_add_item(airopeek_tree, hf_airopeek_unknown4, tvb, 6, 14, FALSE);
  }
  next_tvb = tvb_new_subset(tvb, 20, -1, -1);
  call_dissector(ieee80211_handle, next_tvb, pinfo, tree);
}

void
proto_register_airopeek(void)
{
  static hf_register_info hf[] = {
	{ &hf_airopeek_unknown1,
           { "Unknown1",      "airopeek.unknown1", FT_BYTES, BASE_NONE, NULL,
             0x0, "", HFILL }},

	{ &hf_airopeek_unknown2,
           { "caplength1",      "airopeek.unknown2", FT_UINT16, BASE_DEC, NULL,
             0x0, "", HFILL }},

	{ &hf_airopeek_unknown3,
           { "caplength2",      "airopeek.unknown3", FT_UINT16, BASE_DEC, NULL,
             0x0, "", HFILL }},

	{ &hf_airopeek_unknown4,
           { "Unknown4",      "airopeek.unknown4", FT_BYTES, BASE_NONE, NULL,
             0x0, "", HFILL }},

  };
  static gint *ett[] = {
    &ett_airopeek,
  };

  proto_airopeek = proto_register_protocol(
	"Airopeek encapsulated IEEE 802.11", "AIROPEEK", "airopeek");
  proto_register_field_array(proto_airopeek, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_airopeek(void)
{
  dissector_handle_t airopeek_handle;

  ieee80211_handle = find_dissector("wlan_datapad");

  airopeek_handle = create_dissector_handle(dissect_airopeek, proto_airopeek);
  dissector_add("udp.port", 5000, airopeek_handle);
}
