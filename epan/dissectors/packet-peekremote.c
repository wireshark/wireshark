/* packet-peekremote.c
 *
 * Routines for the disassembly of packets sent from Cisco WLAN
 * Controllers, possibly other Cisco access points, and possibly
 * other devices such as Aruba access points.  See
 *
 *	http://www.wildpackets.com/elements/omnipeek/OmniPeek_UserGuide.pdf
 *
 * which speaks of Aruba access points supporting remote capture and
 * defaulting to port 5000 for this, and also speaks of Cisco access
 * points supporting remote capture without any reference to a port
 * number.  The two types of remote capture are described separately;
 * there's no indication of whether they use the same protocol for
 * streaming packets but perhaps other protocols for, for example,
 * discovery and setup, or whether they use different protocols
 * for streaming packets.
 *
 * Tested with frames captured from a Cisco WCS.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * TODO: Decode meta information.
 *       Check on fillup bytes in capture (fcs sometimes wrong)
 * From:
 * http://www.cisco.com/univercd/cc/td/doc/product/wireless/pahcont/oweb.pdf
 * "It will include information on timestamp, signal strength, packet size
 *  and so on"
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>

static int proto_peekremote = -1;
static gint hf_peekremote_unknown1 = -1;
static gint hf_peekremote_unknown2 = -1;
static gint hf_peekremote_unknown3 = -1;
static gint hf_peekremote_unknown4 = -1;
static gint hf_peekremote_unknown5 = -1;
static gint hf_peekremote_unknown6 = -1;
static gint hf_peekremote_channel = -1;
static gint hf_peekremote_timestamp = -1;
static gint ett_peekremote = -1;

static dissector_handle_t ieee80211_handle;

static void
dissect_peekremote(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  tvbuff_t *next_tvb;
  proto_tree *peekremote_tree = NULL;
  proto_item *ti = NULL;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "AIROPEEK");
  col_clear(pinfo->cinfo, COL_INFO);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_peekremote, tvb, 0, -1, ENC_NA);
    peekremote_tree = proto_item_add_subtree(ti, ett_peekremote);

    proto_tree_add_item(peekremote_tree, hf_peekremote_unknown1, tvb, 0, 2,  ENC_NA);
    proto_tree_add_item(peekremote_tree, hf_peekremote_unknown2, tvb, 2, 2,  ENC_BIG_ENDIAN);
    proto_tree_add_item(peekremote_tree, hf_peekremote_unknown3, tvb, 4, 2,  ENC_BIG_ENDIAN);
    proto_tree_add_item(peekremote_tree, hf_peekremote_unknown4, tvb, 6, 5, ENC_NA);
    proto_tree_add_item(peekremote_tree, hf_peekremote_timestamp, tvb, 11, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(peekremote_tree, hf_peekremote_unknown5, tvb, 15, 2, ENC_NA);
    proto_tree_add_item(peekremote_tree, hf_peekremote_channel, tvb, 17, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(peekremote_tree, hf_peekremote_unknown6, tvb, 18, 2, ENC_NA);
  }
  next_tvb = tvb_new_subset_remaining(tvb, 20);
  pinfo->pseudo_header->ieee_802_11.fcs_len = 4;
  call_dissector(ieee80211_handle, next_tvb, pinfo, tree);
}

void
proto_register_peekremote(void)
{
  static hf_register_info hf[] = {
    { &hf_peekremote_unknown1,
      { "Unknown1",      "peekremote.unknown1", FT_BYTES, BASE_NONE, NULL,
        0x0, NULL, HFILL }},

    { &hf_peekremote_unknown2,
      { "caplength1",      "peekremote.unknown2", FT_UINT16, BASE_DEC, NULL,
        0x0, NULL, HFILL }},

    { &hf_peekremote_unknown3,
      { "caplength2",      "peekremote.unknown3", FT_UINT16, BASE_DEC, NULL,
        0x0, NULL, HFILL }},

    { &hf_peekremote_unknown4,
      { "Unknown4",      "peekremote.unknown4", FT_BYTES, BASE_NONE, NULL,
        0x0, NULL, HFILL }},

    { &hf_peekremote_unknown5,
      { "Unknown5",      "peekremote.unknown5", FT_BYTES, BASE_NONE, NULL,
        0x0, NULL, HFILL }},

    { &hf_peekremote_unknown6,
      { "Unknown6",      "peekremote.unknown6", FT_BYTES, BASE_NONE, NULL,
        0x0, NULL, HFILL }},

    { &hf_peekremote_timestamp,
      { "Timestamp?",       "peekremote.timestamp", FT_UINT32, BASE_DEC, NULL,
        0x0, NULL, HFILL }},

    { &hf_peekremote_channel,
      { "Channel",       "peekremote.channel", FT_UINT8, BASE_DEC, NULL,
        0x0, NULL, HFILL }},

  };
  static gint *ett[] = {
    &ett_peekremote,
  };

  proto_peekremote = proto_register_protocol(
    "AiroPeek/OmniPeek encapsulated IEEE 802.11", "PEEKREMOTE", "peekremote");
  proto_register_field_array(proto_peekremote, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_peekremote(void)
{
  dissector_handle_t peekremote_handle;

  ieee80211_handle = find_dissector("wlan_datapad");

  peekremote_handle = create_dissector_handle(dissect_peekremote, proto_peekremote);
  dissector_add_uint("udp.port", 5000, peekremote_handle);
}
