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

#define NEW_PROTO_TREE_API

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <wiretap/wtap.h>

void proto_register_peekremote(void);
void proto_reg_handoff_peekremote(void);

/* hfi elements */
#define THIS_HF_INIT HFI_INIT(proto_peekremote)
static header_field_info *hfi_peekremote = NULL;

static header_field_info hfi_peekremote_signal THIS_HF_INIT =
      { "Signal [dBm]",      "peekremote.signal", FT_INT8, BASE_DEC, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_noise THIS_HF_INIT =
      { "Noise [dBm]",      "peekremote.noise", FT_INT8, BASE_DEC, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_packetlength THIS_HF_INIT =
      { "Packet length",      "peekremote.packetlength", FT_UINT16, BASE_DEC, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_slicelength THIS_HF_INIT =
      { "Slice length",      "peekremote.slicelength", FT_UINT16, BASE_DEC, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_unknown4 THIS_HF_INIT =
      { "Unknown4",      "peekremote.unknown4", FT_BYTES, BASE_NONE, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_speed THIS_HF_INIT =
      { "Speed [500kHz]",      "peekremote.speed", FT_UINT8, BASE_DEC, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_unknown6 THIS_HF_INIT =
      { "Unknown6",      "peekremote.unknown6", FT_BYTES, BASE_NONE, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_channel THIS_HF_INIT =
      { "Channel",       "peekremote.channel", FT_UINT8, BASE_DEC, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_timestamp THIS_HF_INIT =
      { "Timestamp?",       "peekremote.timestamp", FT_UINT32, BASE_DEC, NULL,
        0x0, NULL, HFILL };

static gint ett_peekremote = -1;

static dissector_handle_t peekremote_handle;
static dissector_handle_t ieee80211_handle;

static int
dissect_peekremote(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *u _U_)
{
  tvbuff_t *next_tvb;
  proto_tree *peekremote_tree = NULL;
  proto_item *ti = NULL;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "AIROPEEK");
  col_clear(pinfo->cinfo, COL_INFO);

  if (tree) {
    ti = proto_tree_add_item(tree, hfi_peekremote, tvb, 0, -1, ENC_NA);
    peekremote_tree = proto_item_add_subtree(ti, ett_peekremote);

    proto_tree_add_item(peekremote_tree, &hfi_peekremote_signal, tvb, 0, 1,  ENC_NA);
    proto_tree_add_item(peekremote_tree, &hfi_peekremote_noise, tvb, 1, 1,  ENC_NA);
    proto_tree_add_item(peekremote_tree, &hfi_peekremote_packetlength, tvb, 2, 2,  ENC_BIG_ENDIAN);
    proto_tree_add_item(peekremote_tree, &hfi_peekremote_slicelength, tvb, 4, 2,  ENC_BIG_ENDIAN);
    proto_tree_add_item(peekremote_tree, &hfi_peekremote_unknown4, tvb, 6, 6, ENC_NA);
    proto_tree_add_item(peekremote_tree, &hfi_peekremote_timestamp, tvb, 12, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(peekremote_tree, &hfi_peekremote_speed, tvb, 16, 1, ENC_NA);
    proto_tree_add_item(peekremote_tree, &hfi_peekremote_channel, tvb, 17, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(peekremote_tree, &hfi_peekremote_unknown6, tvb, 18, 2, ENC_NA);
  }
  next_tvb = tvb_new_subset_remaining(tvb, 20);
  pinfo->pseudo_header->ieee_802_11.fcs_len = 4;
  return 20 + call_dissector(ieee80211_handle, next_tvb, pinfo, tree);
}

void
proto_register_peekremote(void)
{
#ifndef HAVE_HFI_SECTION_INIT
  static header_field_info *hfi[] = {
    &hfi_peekremote_signal,
    &hfi_peekremote_noise,
    &hfi_peekremote_packetlength,
    &hfi_peekremote_slicelength,
    &hfi_peekremote_unknown4,
    &hfi_peekremote_speed,
    &hfi_peekremote_unknown6,
    &hfi_peekremote_timestamp,
    &hfi_peekremote_channel,
  };
#endif
  static gint *ett[] = {
    &ett_peekremote,
  };

  int proto_peekremote;

  proto_peekremote = proto_register_protocol(
    "AiroPeek/OmniPeek encapsulated IEEE 802.11", "PEEKREMOTE", "peekremote");
  hfi_peekremote = proto_registrar_get_nth(proto_peekremote);
  proto_register_fields(proto_peekremote, hfi, array_length(hfi));
  proto_register_subtree_array(ett, array_length(ett));

  peekremote_handle = new_create_dissector_handle(dissect_peekremote, proto_peekremote);
}

void
proto_reg_handoff_peekremote(void)
{
  ieee80211_handle = find_dissector("wlan_datapad");

  dissector_add_uint("udp.port", 5000, peekremote_handle);
}
