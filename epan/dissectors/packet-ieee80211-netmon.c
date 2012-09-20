/*
 *  packet-ieee80211-netmon.c
 *       Decode packets with a Network Monitor 802.11 radio header
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>

/* protocol */
static int proto_netmon_802_11 = -1;

#define MIN_HEADER_LEN  32

/* op_mode */
#define OP_MODE_STA     0x00000001      /* station mode */
#define OP_MODE_AP      0x00000002      /* AP mode */
#define OP_MODE_STA_EXT 0x00000004      /* extensible station mode */
#define OP_MODE_MON     0x80000000      /* monitor mode */

/* phy_type */
#define PHY_TYPE_11A    4
#define PHY_TYPE_11B    5
#define PHY_TYPE_11G    6
#define PHY_TYPE_11N    7

static int hf_netmon_802_11_version = -1;
static int hf_netmon_802_11_length = -1;
static int hf_netmon_802_11_op_mode = -1;
static int hf_netmon_802_11_op_mode_sta = -1;
static int hf_netmon_802_11_op_mode_ap = -1;
static int hf_netmon_802_11_op_mode_sta_ext = -1;
static int hf_netmon_802_11_op_mode_mon = -1;
static int hf_netmon_802_11_flags = -1;
static int hf_netmon_802_11_phy_type = -1;
static int hf_netmon_802_11_channel = -1;
static int hf_netmon_802_11_frequency = -1;
static int hf_netmon_802_11_rssi = -1;
static int hf_netmon_802_11_datarate = -1;
static int hf_netmon_802_11_timestamp = -1;

static gint ett_netmon_802_11 = -1;
static gint ett_netmon_802_11_op_mode = -1;

static dissector_handle_t ieee80211_handle;

static int
dissect_netmon_802_11(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_tree *wlan_tree, *opmode_tree;
  proto_item *ti;
  tvbuff_t   *next_tvb;
  int         offset;
  guint8      version;
  guint16     length;
  guint32     flags;
  guint32     channel;
  gint32      rssi;
  guint8      rate;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "WLAN");
  col_clear(pinfo->cinfo, COL_INFO);
  offset = 0;

  version = tvb_get_guint8(tvb, offset);
  length = tvb_get_letohs(tvb, offset+1);
  col_add_fstr(pinfo->cinfo, COL_INFO, "NetMon WLAN Capture v%u, Length %u",
               version, length);
  if (version != 2) {
    /* XXX - complain */
    goto skip;
  }
  if (length < MIN_HEADER_LEN) {
    /* XXX - complain */
    goto skip;
  }

  /* Dissect the packet */
  if (tree) {
    ti = proto_tree_add_item(tree, proto_netmon_802_11, tvb, 0, length,
                             ENC_NA);
    wlan_tree = proto_item_add_subtree(ti, ett_netmon_802_11);
    proto_tree_add_item(wlan_tree, hf_netmon_802_11_version, tvb, offset, 1,
                        ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(wlan_tree, hf_netmon_802_11_length, tvb, offset, 2,
                        ENC_LITTLE_ENDIAN);
    offset += 2;
    ti = proto_tree_add_item(wlan_tree, hf_netmon_802_11_op_mode, tvb, offset,
                        4, ENC_LITTLE_ENDIAN);
    opmode_tree = proto_item_add_subtree(ti, ett_netmon_802_11_op_mode);
    proto_tree_add_item(opmode_tree, hf_netmon_802_11_op_mode_sta, tvb, offset,
                        4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(opmode_tree, hf_netmon_802_11_op_mode_ap, tvb, offset,
                        4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(opmode_tree, hf_netmon_802_11_op_mode_sta_ext, tvb,
                        offset, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(opmode_tree, hf_netmon_802_11_op_mode_mon, tvb, offset,
                        4, ENC_LITTLE_ENDIAN);
    offset += 4;
    flags = tvb_get_letohl(tvb, offset);
    offset += 4;
    if (flags != 0xffffffff) {
      proto_tree_add_item(wlan_tree, hf_netmon_802_11_phy_type, tvb, offset, 4,
                          ENC_LITTLE_ENDIAN);
      offset += 4;
      channel = tvb_get_letohl(tvb, offset);
      if (channel < 1000) {
        proto_tree_add_uint(wlan_tree, hf_netmon_802_11_channel,
                            tvb, offset, 4, channel);
      } else {
        proto_tree_add_uint_format_value(wlan_tree, hf_netmon_802_11_frequency,
                                         tvb, offset, 4, channel,
                                         "%u Mhz", channel);
      }
      offset += 4;
      rssi = tvb_get_letohl(tvb, offset);
      proto_tree_add_int_format_value(wlan_tree, hf_netmon_802_11_rssi,
                                      tvb, offset, 4, rssi,
                                      "%d dBm", rssi);
      offset += 4;
      rate = tvb_get_guint8(tvb, offset);
      if (rate == 0) {
        proto_tree_add_uint_format_value(wlan_tree, hf_netmon_802_11_datarate,
                                         tvb, offset, 1, rate,
                                         "Unknown");
      } else {
        proto_tree_add_uint_format_value(wlan_tree, hf_netmon_802_11_datarate,
                                         tvb, offset, 1, rate,
                                         "%f Mb/s", rate*.5);
      }
      offset += 1;
    } else
      offset += 13;
    proto_tree_add_item(wlan_tree, hf_netmon_802_11_timestamp, tvb, offset, 8,
                        ENC_LITTLE_ENDIAN);
    offset += 8;

  }

  /* no return */

skip:
  offset = length;

  /* dissect the 802.11 header next */
  next_tvb = tvb_new_subset_remaining(tvb, offset);
  call_dissector(ieee80211_handle, next_tvb, pinfo, tree);
  return offset;
}

void
proto_register_netmon_802_11(void)
{
  static const value_string phy_type[] = {
    { PHY_TYPE_11A, "802.11a" },
    { PHY_TYPE_11B, "802.11b" },
    { PHY_TYPE_11G, "802.11g" },
    { PHY_TYPE_11N, "802.11n" },
    { 0, NULL },
  };

  static hf_register_info hf[] = {
    { &hf_netmon_802_11_version, { "Header revision", "netmon_802_11.version", FT_UINT8,
                          BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_netmon_802_11_length, { "Header length", "netmon_802_11.length", FT_UINT16,
                          BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_netmon_802_11_op_mode, { "Operation mode", "netmon_802_11.op_mode", FT_UINT32,
                          BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_netmon_802_11_op_mode_sta, { "Station mode", "netmon_802_11.op_mode.sta", FT_UINT32,
                          BASE_HEX, NULL, OP_MODE_STA, NULL, HFILL } },
    { &hf_netmon_802_11_op_mode_ap, { "AP mode", "netmon_802_11.op_mode.ap", FT_UINT32,
                          BASE_HEX, NULL, OP_MODE_AP, NULL, HFILL } },
    { &hf_netmon_802_11_op_mode_sta_ext, { "Extensible station mode", "netmon_802_11.op_mode.sta_ext", FT_UINT32,
                          BASE_HEX, NULL, OP_MODE_STA_EXT, NULL, HFILL } },
    { &hf_netmon_802_11_op_mode_mon, { "Monitor mode", "netmon_802_11.op_mode.on", FT_UINT32,
                          BASE_HEX, NULL, OP_MODE_MON, NULL, HFILL } },
    { &hf_netmon_802_11_flags, { "Flags", "netmon_802_11.flags", FT_UINT32,
                          BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_netmon_802_11_phy_type, { "PHY type", "netmon_802_11.phy_type", FT_UINT32,
                          BASE_DEC, VALS(phy_type), 0x0, NULL, HFILL } },
    { &hf_netmon_802_11_channel, { "Channel", "netmon_802_11.channel", FT_UINT32,
                          BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_netmon_802_11_frequency, { "Center frequency", "netmon_802_11.frequency", FT_UINT32,
                          BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_netmon_802_11_rssi, { "RSSI", "netmon_802_11.rssi", FT_INT32,
                          BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_netmon_802_11_datarate, { "Data rate", "netmon_802_11.datarate", FT_UINT32,
                          BASE_DEC, NULL, 0x0, NULL, HFILL } },
    /*
     * XXX - is this host, or MAC, time stamp?
     * It might be a FILETIME.
     */
    { &hf_netmon_802_11_timestamp, { "Timestamp", "netmon_802_11.timestamp", FT_UINT64,
                          BASE_DEC, NULL, 0x0, NULL, HFILL } },
  };
  static gint *ett[] = {
    &ett_netmon_802_11,
    &ett_netmon_802_11_op_mode
  };

  proto_netmon_802_11 = proto_register_protocol("NetMon 802.11 capture header",
                                                "NetMon 802.11",
                                                "netmon_802_11");
  proto_register_field_array(proto_netmon_802_11, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_netmon_802_11(void)
{
  dissector_handle_t netmon_802_11_handle;

  /* handle for 802.11 dissector */
  ieee80211_handle = find_dissector("wlan");
  netmon_802_11_handle = new_create_dissector_handle(dissect_netmon_802_11,
                                                 proto_netmon_802_11);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_IEEE_802_11_NETMON, netmon_802_11_handle);
}
