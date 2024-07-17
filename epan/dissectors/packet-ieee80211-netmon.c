/*
 *  packet-ieee80211-netmon.c
 *       Decode packets with a Network Monitor 802.11 radio header
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

#include <wiretap/wtap.h>

#include <wsutil/802_11-utils.h>

void proto_register_netmon_802_11(void);
void proto_reg_handoff_netmon_802_11(void);

/* protocol */
static int proto_netmon_802_11;

/* Dissector */
static dissector_handle_t netmon_802_11_handle;

#define MIN_HEADER_LEN  32

/* op_mode */
#define OP_MODE_STA     0x00000001      /* station mode */
#define OP_MODE_AP      0x00000002      /* AP mode */
#define OP_MODE_STA_EXT 0x00000004      /* extensible station mode */
#define OP_MODE_MON     0x80000000      /* monitor mode */

/* phy_type */
/*
 * Augmented with phy types from
 *
 *    https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/windot11/ne-windot11-_dot11_phy_type
 */
#define PHY_TYPE_UNKNOWN     0
#define PHY_TYPE_FHSS        1
#define PHY_TYPE_DSSS        2
#define PHY_TYPE_IR_BASEBAND 3
#define PHY_TYPE_OFDM        4 /* 802.11a */
#define PHY_TYPE_HR_DSSS     5 /* 802.11b */
#define PHY_TYPE_ERP         6 /* 802.11g */
#define PHY_TYPE_HT          7 /* 802.11n */
#define PHY_TYPE_VHT         8 /* 802.11ac */

static int hf_netmon_802_11_version;
static int hf_netmon_802_11_length;
static int hf_netmon_802_11_op_mode;
static int hf_netmon_802_11_op_mode_sta;
static int hf_netmon_802_11_op_mode_ap;
static int hf_netmon_802_11_op_mode_sta_ext;
static int hf_netmon_802_11_op_mode_mon;
/* static int hf_netmon_802_11_flags; */
static int hf_netmon_802_11_phy_type;
static int hf_netmon_802_11_channel;
static int hf_netmon_802_11_frequency;
static int hf_netmon_802_11_rssi;
static int hf_netmon_802_11_datarate;
static int hf_netmon_802_11_timestamp;

static int ett_netmon_802_11;
static int ett_netmon_802_11_op_mode;

static dissector_handle_t ieee80211_radio_handle;

static int
dissect_netmon_802_11(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  struct ieee_802_11_phdr phdr;
  proto_tree *wlan_tree = NULL, *opmode_tree;
  proto_item *ti;
  tvbuff_t   *next_tvb;
  int         offset;
  uint8_t     version;
  uint16_t    length;
  uint32_t    phy_type;
  uint32_t    monitor_mode;
  uint32_t    flags;
  uint32_t    channel;
  int         calc_channel;
  int32_t     rssi;
  uint8_t     rate;

  /*
   * It appears to be the case that management frames (and control and
   * extension frames ?) may or may not have an FCS and data frames don't.
   * (Netmon capture files have been seen for this encapsulation
   * management frames either completely with or without an FCS. Also:
   * instances have been  seen where both Management and Control frames
   * do not have an FCS).  An "FCS length" of -2 means "NetMon weirdness".
   *
   * The metadata header also has a bit indicating whether the adapter
   * was in monitor mode or not; if it isn't, we set "decrypted" to true,
   * as, for those frames, the Protected bit is preserved in received
   * frames, but the frame is decrypted.
   */
  memset(&phdr, 0, sizeof(phdr));
  phdr.fcs_len = -2;
  phdr.decrypted = false;
  phdr.datapad = false;
  phdr.phy = PHDR_802_11_PHY_UNKNOWN;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "WLAN");
  col_clear(pinfo->cinfo, COL_INFO);
  offset = 0;

  version = tvb_get_uint8(tvb, offset);
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
  ti = proto_tree_add_item(tree, proto_netmon_802_11, tvb, 0, length,
                           ENC_NA);
  wlan_tree = proto_item_add_subtree(ti, ett_netmon_802_11);

  /*
   * XXX - is this the NDIS_OBJECT_HEADER structure:
   *
   *    https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/ntddndis/ns-ntddndis-_ndis_object_header
   *
   * at the beginning of a DOT11_EXTSTA_RECV_CONTEXT structure:
   *
   *    https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/windot11/ns-windot11-dot11_extsta_recv_context
   *
   * If so, the byte at an offset of 0 would be the appropriate type for the
   * structure following it, i.e. NDIS_OBJECT_TYPE_DEFAULT.
   */
  proto_tree_add_item(wlan_tree, hf_netmon_802_11_version, tvb, offset, 1,
                      ENC_LITTLE_ENDIAN);
  offset += 1;
  proto_tree_add_item(wlan_tree, hf_netmon_802_11_length, tvb, offset, 2,
                      ENC_LITTLE_ENDIAN);
  offset += 2;

  /*
   * This isn't in the DOT11_EXTSTA_RECV_CONTEXT structure.
   */
  ti = proto_tree_add_item(wlan_tree, hf_netmon_802_11_op_mode, tvb, offset,
                      4, ENC_LITTLE_ENDIAN);
  opmode_tree = proto_item_add_subtree(ti, ett_netmon_802_11_op_mode);
  proto_tree_add_item(opmode_tree, hf_netmon_802_11_op_mode_sta, tvb, offset,
                      4, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(opmode_tree, hf_netmon_802_11_op_mode_ap, tvb, offset,
                      4, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(opmode_tree, hf_netmon_802_11_op_mode_sta_ext, tvb,
                      offset, 4, ENC_LITTLE_ENDIAN);
  proto_tree_add_item_ret_uint(opmode_tree, hf_netmon_802_11_op_mode_mon, tvb, offset,
                               4, ENC_LITTLE_ENDIAN, &monitor_mode);
  if (!monitor_mode) {
    /*
     * If a NetMon capture is not done in monitor mode, we may see frames
     * with the Protect bit set (because they were encrypted on the air)
     * but that aren't encrypted (because they've been decrypted before
     * being written to the file).  This wasn't done in monitor mode, as
     * the "monitor mode" flag wasn't set, so supporess treating the
     * Protect flag as an indication that the frame was encrypted.
     */
    phdr.decrypted = true;

    /*
     * Furthermore, we may see frames with the A-MSDU Present flag set
     * in the QoS Control field but that have a regular frame, not a
     * sequence of A-MSDUs, in the payload.
     */
    phdr.no_a_msdus = true;
  }
  offset += 4;

  /*
   * uReceiveFlags?
   */
  flags = tvb_get_letohl(tvb, offset);
  offset += 4;
  if (flags != 0xffffffff) {
    /*
     * uPhyId?
     */
    phy_type = tvb_get_letohl(tvb, offset);
    memset(&phdr.phy_info, 0, sizeof(phdr.phy_info));

    /*
     * Unlike the channel flags in radiotap, this appears
     * to correctly indicate the modulation for this packet
     * (no cases seen where this doesn't match the data rate).
     */
    switch (phy_type) {

    case PHY_TYPE_UNKNOWN:
        phdr.phy = PHDR_802_11_PHY_UNKNOWN;
        break;

    case PHY_TYPE_FHSS:
        phdr.phy = PHDR_802_11_PHY_11_FHSS;
        break;

    case PHY_TYPE_IR_BASEBAND:
        phdr.phy = PHDR_802_11_PHY_11_IR;
        break;

    case PHY_TYPE_DSSS:
        phdr.phy = PHDR_802_11_PHY_11_DSSS;
        break;

    case PHY_TYPE_HR_DSSS:
        phdr.phy = PHDR_802_11_PHY_11B;
        break;

    case PHY_TYPE_OFDM:
        phdr.phy = PHDR_802_11_PHY_11A;
        break;

    case PHY_TYPE_ERP:
        phdr.phy = PHDR_802_11_PHY_11G;
        break;

    case PHY_TYPE_HT:
        phdr.phy = PHDR_802_11_PHY_11N;
        break;

    case PHY_TYPE_VHT:
        phdr.phy = PHDR_802_11_PHY_11AC;
        break;

    default:
        phdr.phy = PHDR_802_11_PHY_UNKNOWN;
        break;
    }
    proto_tree_add_item(wlan_tree, hf_netmon_802_11_phy_type, tvb, offset, 4,
                        ENC_LITTLE_ENDIAN);
    offset += 4;

    /*
     * uChCenterFrequency?
     */
    channel = tvb_get_letohl(tvb, offset);
    if (channel < 1000) {
      if (channel == 0) {
        proto_tree_add_uint_format_value(wlan_tree, hf_netmon_802_11_channel,
                                         tvb, offset, 4, channel,
                                         "Unknown");
      } else {
        unsigned frequency;

        phdr.has_channel = true;
        phdr.channel = channel;
        proto_tree_add_uint(wlan_tree, hf_netmon_802_11_channel,
                            tvb, offset, 4, channel);
        switch (phdr.phy) {

        case PHDR_802_11_PHY_11B:
        case PHDR_802_11_PHY_11G:
          /* 2.4 GHz channel */
          frequency = ieee80211_chan_to_mhz(channel, true);
          break;

        case PHDR_802_11_PHY_11A:
          /* 5 GHz channel */
          frequency = ieee80211_chan_to_mhz(channel, false);
          break;

        default:
          frequency = 0;
          break;
        }
        if (frequency != 0) {
          phdr.has_frequency = true;
          phdr.frequency = frequency;
        }
      }
    } else {
      phdr.has_frequency = true;
      phdr.frequency = channel;
      proto_tree_add_uint(wlan_tree, hf_netmon_802_11_frequency,
                                       tvb, offset, 4, channel);
      calc_channel = ieee80211_mhz_to_chan(channel);
      if (calc_channel != -1) {
        phdr.has_channel = true;
        phdr.channel = calc_channel;
      }
    }
    offset += 4;

    /*
     * usNumberOfMPDUsReceived is missing.
     */

    /*
     * lRSSI?
     */
    rssi = tvb_get_letohl(tvb, offset);
    if (rssi == 0) {
      proto_tree_add_int_format_value(wlan_tree, hf_netmon_802_11_rssi,
                                      tvb, offset, 4, rssi,
                                      "Unknown");
    } else {
      phdr.has_signal_dbm = true;
      phdr.signal_dbm = rssi;
      proto_tree_add_int_format_value(wlan_tree, hf_netmon_802_11_rssi,
                                      tvb, offset, 4, rssi,
                                      "%d dBm", rssi);
    }
    offset += 4;

    /*
     * ucDataRate?
     */
    rate = tvb_get_uint8(tvb, offset);
    if (rate == 0) {
      proto_tree_add_uint_format_value(wlan_tree, hf_netmon_802_11_datarate,
                                       tvb, offset, 1, rate,
                                       "Unknown");
    } else {
      phdr.has_data_rate = true;
      phdr.data_rate = rate;
      proto_tree_add_uint_format_value(wlan_tree, hf_netmon_802_11_datarate,
                                       tvb, offset, 1, rate,
                                       "%f Mb/s", rate*.5);
    }
    offset += 1;
  } else
    offset += 13;

  /*
   * ullTimestamp?
   *
   * If so, should this check the presence flag in flags?
   */
  phdr.has_tsf_timestamp = true;
  phdr.tsf_timestamp = tvb_get_letoh64(tvb, offset);
  proto_tree_add_item(wlan_tree, hf_netmon_802_11_timestamp, tvb, offset, 8,
                      ENC_LITTLE_ENDIAN);
  /*offset += 8;*/

skip:
  offset = length;

  /* dissect the 802.11 packet next */
  next_tvb = tvb_new_subset_remaining(tvb, offset);
  call_dissector_with_data(ieee80211_radio_handle, next_tvb, pinfo, tree, &phdr);
  return offset;
}

void
proto_register_netmon_802_11(void)
{
  static const value_string phy_type[] = {
    { PHY_TYPE_UNKNOWN,     "Unknown" },
    { PHY_TYPE_FHSS,        "802.11 FHSS" },
    { PHY_TYPE_DSSS,        "802.11 DSSS" },
    { PHY_TYPE_IR_BASEBAND, "802.11 IR" },
    { PHY_TYPE_OFDM,        "802.11a" },
    { PHY_TYPE_HR_DSSS,     "802.11b" },
    { PHY_TYPE_ERP,         "802.11g" },
    { PHY_TYPE_HT,          "802.11n" },
    { PHY_TYPE_VHT,         "802.11ac" },
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
    { &hf_netmon_802_11_op_mode_mon, { "Monitor mode", "netmon_802_11.op_mode.mon", FT_UINT32,
                          BASE_HEX, NULL, OP_MODE_MON, NULL, HFILL } },
#if 0
    { &hf_netmon_802_11_flags, { "Flags", "netmon_802_11.flags", FT_UINT32,
                          BASE_HEX, NULL, 0x0, NULL, HFILL } },
#endif
    { &hf_netmon_802_11_phy_type, { "PHY type", "netmon_802_11.phy_type", FT_UINT32,
                          BASE_DEC, VALS(phy_type), 0x0, NULL, HFILL } },
    { &hf_netmon_802_11_channel, { "Channel", "netmon_802_11.channel", FT_UINT32,
                          BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_netmon_802_11_frequency, { "Center frequency", "netmon_802_11.frequency", FT_UINT32,
                          BASE_DEC|BASE_UNIT_STRING, &units_mhz, 0x0, NULL, HFILL } },
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
  static int *ett[] = {
    &ett_netmon_802_11,
    &ett_netmon_802_11_op_mode
  };

  proto_netmon_802_11 = proto_register_protocol("NetMon 802.11 capture header",
                                                "NetMon 802.11",
                                                "netmon_802_11");
  netmon_802_11_handle = register_dissector("netmon_802_11", dissect_netmon_802_11, proto_netmon_802_11);
  proto_register_field_array(proto_netmon_802_11, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_netmon_802_11(void)
{
  /* handle for 802.11+radio information dissector */
  ieee80211_radio_handle = find_dissector_add_dependency("wlan_radio", proto_netmon_802_11);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_IEEE_802_11_NETMON, netmon_802_11_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
