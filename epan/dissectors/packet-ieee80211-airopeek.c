/* packet-ieee80211-airopeek.c
 * Routines for pre-V9 WildPackets AiroPeek header dissection
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

#include "config.h"

#include <epan/packet.h>
#include <wiretap/wtap.h>

#include "packet-ieee80211.h"

void proto_register_ieee80211_airopeek(void);
void proto_reg_handoff_ieee80211_airopeek(void);

static dissector_handle_t ieee80211_handle;

static int proto_airopeek = -1;

static int hf_data_rate = -1;
static int hf_channel = -1;
static int hf_signal_strength = -1;

static gint ett_airopeek = -1;

static void
dissect_airopeek(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *airopeek_tree = NULL;
  proto_item *ti;
  guint8 data_rate;
  guint8 signal_level;
  tvbuff_t *next_tvb;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "AiroPeek");
  col_clear(pinfo->cinfo, COL_INFO);

  /* Dissect the header */
  if (tree) {
    ti = proto_tree_add_item(tree, proto_airopeek, tvb, 0, 4, ENC_NA);
    airopeek_tree = proto_item_add_subtree(ti, ett_airopeek);
  }

  data_rate = tvb_get_guint8(tvb, 0);
  /* Add the radio information to the column information */
  col_add_fstr(pinfo->cinfo, COL_TX_RATE, "%u.%u",
               data_rate / 2,
               data_rate & 1 ? 5 : 0);
  if (tree) {
    proto_tree_add_uint64_format_value(airopeek_tree, hf_data_rate, tvb, 0, 1,
                                 (guint64)data_rate * 500000,
                                 "%u.%u Mb/s",
                                 data_rate / 2,
                                 data_rate & 1 ? 5 : 0);
  }

  if (tree)
    proto_tree_add_item(airopeek_tree, hf_channel, tvb, 1, 1, ENC_NA);

  signal_level = tvb_get_guint8(tvb, 2);
  /*
   * This is signal strength as a percentage of the maximum, i.e.
   * (RXVECTOR RSSI/RXVECTOR RSSI_Max)*100, or, at least, that's
   * what I infer it is, given what the WildPackets note "Converting
   * Signal Strength Percentage to dBm Values" says.
   *
   * It also says that the conversion the percentage to a dBm value is
   * an adapter-dependent process, so, as we don't know what type of
   * adapter was used to do the capture, we can't do the conversion.
   */
  col_add_fstr(pinfo->cinfo, COL_RSSI, "%u%%", signal_level);

  proto_tree_add_uint_format_value(airopeek_tree, hf_signal_strength, tvb, 2, 1,
                               signal_level,
                               "%u%%",
                               signal_level);

  /* dissect the 802.11 header next */
  pinfo->current_proto = "IEEE 802.11";
  next_tvb = tvb_new_subset_remaining(tvb, 4);
  call_dissector(ieee80211_handle, next_tvb, pinfo, tree);
}

void proto_register_ieee80211_airopeek(void)
{
  static hf_register_info hf[] = {
      {&hf_data_rate,
       {"Data Rate", "airopeek.data_rate", FT_UINT64, BASE_DEC, NULL, 0,
        "Data rate (b/s)", HFILL }},

      {&hf_channel,
       {"Channel", "airopeek.channel", FT_UINT8, BASE_DEC, NULL, 0,
        "802.11 channel number that this frame was sent/received on", HFILL }},

      {&hf_signal_strength,
       {"Signal Strength", "airopeek.signal_strength", FT_UINT8, BASE_DEC, NULL, 0,
        "Signal strength (Percentage)", HFILL }}
  };

  static gint *tree_array[] = {
    &ett_airopeek
  };

  proto_airopeek = proto_register_protocol("AiroPeek 802.11 radio information",
                                           "AiroPeek",
                                           "airopeek");
  proto_register_field_array(proto_airopeek, hf, array_length(hf));
  proto_register_subtree_array(tree_array, array_length(tree_array));
}

void proto_reg_handoff_ieee80211_airopeek(void)
{
  dissector_handle_t airopeek_handle;

  /* Register handoff to airopeek-header dissectors */
  airopeek_handle = create_dissector_handle(dissect_airopeek, proto_airopeek);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_IEEE_802_11_AIROPEEK,
                     airopeek_handle);
  ieee80211_handle = find_dissector("wlan");
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
