/* packet-ieee80211-radio.c
 * Routines for pseudo 802.11 header dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer
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

void proto_register_ieee80211_radio(void);
void proto_reg_handoff_ieee80211_radio(void);

static dissector_handle_t ieee80211_handle;

static int proto_radio = -1;

/* ************************************************************************* */
/*                Header field info values for radio information             */
/* ************************************************************************* */
static int hf_data_rate = -1;
static int hf_channel = -1;
static int hf_signal_strength = -1;

static gint ett_radio = -1;

/*
 * Dissect 802.11 with a variable-length link-layer header and a pseudo-
 * header containing radio information.
 */
static void
dissect_radio (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  proto_item *ti = NULL;
  proto_tree *radio_tree = NULL;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Radio");
  col_clear(pinfo->cinfo, COL_INFO);

  /* Add the radio information to the column information */
  col_add_fstr(pinfo->cinfo, COL_TX_RATE, "%u.%u",
        pinfo->pseudo_header->ieee_802_11.data_rate / 2,
        pinfo->pseudo_header->ieee_802_11.data_rate & 1 ? 5 : 0);
  /*
   * For tagged Peek files, this is presumably signal strength as a
   * percentage of the maximum, as it is for classic Peek files,
   * i.e. (RXVECTOR RSSI/RXVECTOR RSSI_Max)*100, or, at least, that's
   * what I infer it is, given what the WildPackets note "Converting
   * Signal Strength Percentage to dBm Values" says.
   *
   * It also says that the conversion the percentage to a dBm value is
   * an adapter-dependent process, so, as we don't know what type of
   * adapter was used to do the capture, we can't do the conversion.
   *
   * It's *probably* something similar for other capture file formats.
   */
  col_add_fstr(pinfo->cinfo, COL_RSSI, "%u%%",
        pinfo->pseudo_header->ieee_802_11.signal_level);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_radio, tvb, 0, 0, ENC_NA);
    radio_tree = proto_item_add_subtree (ti, ett_radio);

    proto_tree_add_uint64_format_value(radio_tree, hf_data_rate, tvb, 0, 0,
             (guint64)pinfo->pseudo_header->ieee_802_11.data_rate * 500000,
             "%u.%u Mb/s",
             pinfo->pseudo_header->ieee_802_11.data_rate / 2,
             pinfo->pseudo_header->ieee_802_11.data_rate & 1 ? 5 : 0);

    proto_tree_add_uint(radio_tree, hf_channel, tvb, 0, 0,
            pinfo->pseudo_header->ieee_802_11.channel);

    proto_tree_add_uint_format_value(radio_tree, hf_signal_strength, tvb, 0, 0,
            pinfo->pseudo_header->ieee_802_11.signal_level,
            "%u%%",
            pinfo->pseudo_header->ieee_802_11.signal_level);
  }

  /* dissect the 802.11 header next */
  pinfo->current_proto = "IEEE 802.11";
  call_dissector(ieee80211_handle, tvb, pinfo, tree);
}

static hf_register_info hf_radio[] = {
    {&hf_data_rate,
     {"Data Rate", "wlan.data_rate", FT_UINT64, BASE_DEC, NULL, 0,
      "Data rate (b/s)", HFILL }},

    {&hf_channel,
     {"Channel", "wlan.channel", FT_UINT8, BASE_DEC, NULL, 0,
      "802.11 channel number that this frame was sent/received on", HFILL }},

    {&hf_signal_strength,
     {"Signal Strength", "wlan.signal_strength", FT_UINT8, BASE_DEC, NULL, 0,
      "Signal strength (Percentage)", HFILL }}
};

static gint *tree_array[] = {
  &ett_radio
};

void proto_register_ieee80211_radio(void)
{
  proto_radio = proto_register_protocol("802.11 radio information", "Radio",
                                        "radio");
  proto_register_field_array(proto_radio, hf_radio, array_length(hf_radio));
  proto_register_subtree_array(tree_array, array_length(tree_array));
}

void proto_reg_handoff_ieee80211_radio(void)
{
  dissector_handle_t radio_handle;

  /* Register handoff to radio-header dissectors */
  radio_handle = create_dissector_handle(dissect_radio, proto_radio);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_IEEE_802_11_WITH_RADIO,
                     radio_handle);
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
