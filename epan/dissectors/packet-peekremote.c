/* packet-peekremote.c
 *
 * Routines for the disassembly of packets sent from Cisco WLAN
 * Controllers, possibly other Cisco access points, and possibly
 * other devices such as Aruba access points.  See
 *
 *    https://web.archive.org/web/20130117041444/http://www.wildpackets.com/elements/omnipeek/OmniPeek_UserGuide.pdf
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
 * A later manual at
 *
 *    https://community.liveaction.com/wp-content/uploads/2020/02/Omnipeek-UserGuide-2-20.pdf
 *
 * speaks of Aruba and Cisco access points together, mentioning port 5000.
 *
 * Apparently Aruba supports several protocols, including Peek remote.
 * See the packet-aruba-erm dissector.
 *
 * Tested with frames captured from a Cisco WCS.
 *
 * Copyright 2007 Joerg Mayer (see AUTHORS file)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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

#include <wiretap/wtap.h>

#include <epan/packet.h>
#include <epan/expert.h>

#include <wsutil/802_11-utils.h>
#include <packet-ieee80211-radiotap-defs.h>

#define IS_ARUBA 0x01

#define PEEKREMOTE_PORT 5000 /* Not IANA registered */

#define PEEKREMOTE_V3   3
#define PEEKRMEOTE_NEW_BASE_LEN 9
#define PEEKREMOTE_V3_HDR_LEN 13

#define PEEKREMOTE_V0_6GHZ_BAND_VALID 0x08
#define PEEKREMOTE_V0_IS_6GHZ_BAND    0x10


void proto_register_peekremote(void);
void proto_reg_handoff_peekremote(void);

static int proto_peekremote;
static dissector_handle_t peekremote_handle;

/*
 * XXX - we don't have all the MCS index values here.
 * We should probably just show the MCS index as a number (those
 * numbers are used in 802.11), and have separate items for the
 * number of spatial streams, the modulation type, and the coding rate.
 * Note that some modes with more than one spatial stream use *different*
 * modulation types for the different streams.  See section 20.6
 * "Parameters for HT MCSs" in 802.11-2012.
 */
static const value_string peekremote_mcs_index_vals[] = {
  { 0, "Spatial streams: 1, Modulation type: BPSK, Codingrate: 1/2" },
  { 1, "Spatial streams: 1, Modulation type: QPSK, Codingrate: 1/2" },
  { 2, "Spatial streams: 1, Modulation type: QPSK, Codingrate: 3/4" },
  { 3, "Spatial streams: 1, Modulation type: 16-QAM, Codingrate: 1/2" },
  { 4, "Spatial streams: 1, Modulation type: 16-QAM, Codingrate: 3/4" },
  { 5, "Spatial streams: 1, Modulation type: 64-QAM, Codingrate: 2/3" },
  { 6, "Spatial streams: 1, Modulation type: 64-QAM, Codingrate: 3/4" },
  { 7, "Spatial streams: 1, Modulation type: 64-QAM, Codingrate: 5/6" },
  { 8, "Spatial streams: 2, Modulation type: BPSK, Codingrate: 1/2" },
  { 9, "Spatial streams: 2, Modulation type: QPSK, Codingrate: 1/2" },
  { 10, "Spatial streams: 2, Modulation type: QPSK, Codingrate: 3/4" },
  { 11, "Spatial streams: 2, Modulation type: 16-QAM, Codingrate: 1/2" },
  { 12, "Spatial streams: 2, Modulation type: 16-QAM, Codingrate: 3/4" },
  { 13, "Spatial streams: 2, Modulation type: 64-QAM, Codingrate: 2/3" },
  { 14, "Spatial streams: 2, Modulation type: 64-QAM, Codingrate: 3/4" },
  { 15, "Spatial streams: 2, Modulation type: 64-QAM, Codingrate: 5/6" },
  { 16, "Spatial streams: 3, Modulation type: BPSK, Codingrate: 1/2" },
  { 17, "Spatial streams: 3, Modulation type: QPSK, Codingrate: 1/2" },
  { 18, "Spatial streams: 3, Modulation type: QPSK, Codingrate: 3/4" },
  { 19, "Spatial streams: 3, Modulation type: 16-QAM, Codingrate: 1/2" },
  { 20, "Spatial streams: 3, Modulation type: 16-QAM, Codingrate: 3/4" },
  { 21, "Spatial streams: 3, Modulation type: 64-QAM, Codingrate: 2/3" },
  { 22, "Spatial streams: 3, Modulation type: 64-QAM, Codingrate: 3/4" },
  { 23, "Spatial streams: 3, Modulation type: 64-QAM, Codingrate: 5/6" },
  { 24, "Spatial streams: 4, Modulation type: BPSK, Codingrate: 1/2" },
  { 25, "Spatial streams: 4, Modulation type: QPSK, Codingrate: 1/2" },
  { 26, "Spatial streams: 4, Modulation type: QPSK, Codingrate: 3/4" },
  { 27, "Spatial streams: 4, Modulation type: 16-QAM, Codingrate: 1/2" },
  { 28, "Spatial streams: 4, Modulation type: 16-QAM, Codingrate: 3/4" },
  { 29, "Spatial streams: 4, Modulation type: 64-QAM, Codingrate: 2/3" },
  { 30, "Spatial streams: 4, Modulation type: 64-QAM, Codingrate: 3/4" },
  { 31, "Spatial streams: 4, Modulation type: 64-QAM, Codingrate: 5/6" },
  { 0, NULL }
};

static value_string_ext peekremote_mcs_index_vals_ext = VALUE_STRING_EXT_INIT(peekremote_mcs_index_vals);
/* There is no reason to define a separate set of constants for HE(11ax) as it only adds a MCS 10 and 11. MCS0-9 stay the same. We could even imagine an 11ac implementation with MCS10 and 11 (nonstandard)
 * Also defining mcs rates for 11be in the same table. */
static const value_string peekremote_mcs_index_vals_ac[] = {
  { 0, "Modulation type: BPSK, Codingrate: 1/2" },
  { 1, "Modulation type: QPSK, Codingrate: 1/2" },
  { 2, "Modulation type: QPSK, Codingrate: 3/4" },
  { 3, "Modulation type: 16-QAM, Codingrate: 1/2" },
  { 4, "Modulation type: 16-QAM, Codingrate: 3/4" },
  { 5, "Modulation type: 64-QAM, Codingrate: 2/3" },
  { 6, "Modulation type: 64-QAM, Codingrate: 3/4" },
  { 7, "Modulation type: 64-QAM, Codingrate: 5/6" },
  { 8, "Modulation type: 256-QAM, Codingrate: 3/4" },
  { 9, "Modulation type: 256-QAM, Codingrate: 5/6" },
  { 10, "Modulation type: 1024-QAM, Codingrate: 3/4" },
  { 11, "Modulation type: 1024-QAM, Codingrate: 5/6" },
  { 12, "Modulation type: 4096-QAM, Codingrate: 3/4" },
  { 13, "Modulation type: 4096-QAM, Codingrate: 5/6" },
  { 14, "Modulation type: BPSK-DCM-DUP, Codingrate: 1/2" },
  { 15, "Modulation type: BPSK-DCM, Codingrate: 1/2" },
  { 0, NULL}
};


static const value_string spatialstreams_vals[] = {
  { 0, "1" },
  { 1, "2" },
  { 2, "3" },
  { 3, "4" },
  { 4, "5" },
  { 5, "6" },
  { 6, "7" },
  { 7, "8" },
  { 0, NULL }
};

static const value_string peekremote_type_vals[] = {
  { 6, "kMediaSpecificHdrType_Wireless3" },
  { 0, NULL }
};

/*
 * Extended flags.
 *
 * Some determined from bug 10637, some determined from bug 9586,
 * and the ones present in both agree, so we're assuming that
 * the "remote Peek" protocol and the "Peek tagged" file format
 * use the same bits (which wouldn't be too surprising, as they
 * both come from Wildpackets).
 */
#define EXT_FLAG_20_MHZ_LOWER                   0x00000001
#define EXT_FLAG_20_MHZ_UPPER                   0x00000002
#define EXT_FLAG_40_MHZ                         0x00000004
#define EXT_FLAGS_BANDWIDTH                     0x00000007
#define EXT_FLAG_HALF_GI                        0x00000008
#define EXT_FLAG_FULL_GI                        0x00000010
#define EXT_FLAGS_GI                            0x00200018
#define EXT_FLAG_AMPDU                          0x00000020
#define EXT_FLAG_AMSDU                          0x00000040
#define EXT_FLAG_802_11ac                       0x00000080
#define EXT_FLAG_MCS_INDEX_USED                 0x00000100
#define EXT_FLAG_80MHZ                          0x00000200
#define EXT_FLAG_SHORTPREAMBLE                  0x00000400
#define EXT_FLAG_SPATIALSTREAMS                 0x0001C000
#define EXT_FLAG_HEFLAG                         0x00020000
#define EXT_FLAG_160MHZ                         0x00040000
#define EXT_FLAG_EHTFLAG                        0x00080000
#define EXT_FLAG_320MHZ                         0x00100000
#define EXT_FLAG_QUARTER_GI                     0x00200000
#define EXT_FLAGS_RESERVED                      0xFFC00000

#define EXT_FLAG_SPATIALSTREAMS_SHIFT           14

static int hf_peekremote_band;
static int hf_peekremote_channel;
static int hf_peekremote_extflags;
static int hf_peekremote_extflags_11ac;
static int hf_peekremote_extflags_160mhz;
static int hf_peekremote_extflags_320mhz;
static int hf_peekremote_extflags_20mhz_lower;
static int hf_peekremote_extflags_20mhz_upper;
static int hf_peekremote_extflags_40mhz;
static int hf_peekremote_extflags_80mhz;
static int hf_peekremote_extflags_ampdu;
static int hf_peekremote_extflags_amsdu;
static int hf_peekremote_extflags_full_gi;
static int hf_peekremote_extflags_future_use;
static int hf_peekremote_extflags_half_gi;
static int hf_peekremote_extflags_heflag;
static int hf_peekremote_extflags_ehtflag;
static int hf_peekremote_extflags_quarter_gi;
static int hf_peekremote_extflags_reserved;
static int hf_peekremote_extflags_shortpreamble;
static int hf_peekremote_extflags_spatialstreams;
static int hf_peekremote_flags;
static int hf_peekremote_flags_control_frame;
static int hf_peekremote_flags_crc_error;
static int hf_peekremote_flags_frame_error;
static int hf_peekremote_flags_6ghz_band_valid;
static int hf_peekremote_flags_6ghz;
static int hf_peekremote_flags_reserved;
static int hf_peekremote_frequency;
static int hf_peekremote_header_size;
static int hf_peekremote_header_version;
static int hf_peekremote_magic_number;
static int hf_peekremote_mcs_index;
static int hf_peekremote_mcs_index_ac;
static int hf_peekremote_noise_1_dbm;
static int hf_peekremote_noise_2_dbm;
static int hf_peekremote_noise_3_dbm;
static int hf_peekremote_noise_4_dbm;
static int hf_peekremote_noise_dbm;
static int hf_peekremote_noise_percent;
static int hf_peekremote_packetlength;
static int hf_peekremote_signal_1_dbm;
static int hf_peekremote_signal_2_dbm;
static int hf_peekremote_signal_3_dbm;
static int hf_peekremote_signal_4_dbm;
static int hf_peekremote_signal_dbm;
static int hf_peekremote_signal_percent;
static int hf_peekremote_slicelength;
static int hf_peekremote_speed;
static int hf_peekremote_status;
static int hf_peekremote_status_protected;
static int hf_peekremote_status_reserved;
static int hf_peekremote_status_with_decrypt_error;
static int hf_peekremote_status_with_short_preamble;
static int hf_peekremote_timestamp;
static int hf_peekremote_type;

static expert_field ei_peekremote_unknown_header_version;
static expert_field ei_peekremote_invalid_header_size;

static int ett_peekremote;
static int ett_peekremote_flags;
static int ett_peekremote_status;
static int ett_peekremote_extflags;

static dissector_handle_t wlan_radio_handle;
static dissector_handle_t radiotap_handle;

static int
dissect_peekremote_extflags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
  proto_tree *extflags_tree;
  proto_item *ti_extflags, *item=NULL;

  uint32_t extflags = tvb_get_ntohl(tvb, offset);

  ti_extflags = proto_tree_add_item(tree, hf_peekremote_extflags, tvb, offset, 4, ENC_BIG_ENDIAN);
  extflags_tree = proto_item_add_subtree(ti_extflags, ett_peekremote_extflags);
  proto_tree_add_item(extflags_tree, hf_peekremote_extflags_20mhz_lower, tvb, offset, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(extflags_tree, hf_peekremote_extflags_20mhz_upper, tvb, offset, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(extflags_tree, hf_peekremote_extflags_40mhz, tvb, offset, 4, ENC_BIG_ENDIAN);
  item = proto_tree_add_item(extflags_tree, hf_peekremote_extflags_half_gi, tvb, offset, 4, ENC_BIG_ENDIAN);
  if ((extflags & EXT_FLAG_HEFLAG) || (extflags & EXT_FLAG_EHTFLAG)) {
    proto_item_append_text(item, " (1.6uS)");
  } else {
    proto_item_append_text(item, " (0.4uS)");
  }
  item = proto_tree_add_item(extflags_tree, hf_peekremote_extflags_full_gi, tvb, offset, 4, ENC_BIG_ENDIAN);
  if ((extflags & EXT_FLAG_HEFLAG) || (extflags & EXT_FLAG_EHTFLAG)) {
    proto_item_append_text(item, " (3.2uS)");
  } else {
    proto_item_append_text(item, " (0.8uS)");
  }
  proto_tree_add_item(extflags_tree, hf_peekremote_extflags_ampdu, tvb, offset, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(extflags_tree, hf_peekremote_extflags_amsdu, tvb, offset, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(extflags_tree, hf_peekremote_extflags_11ac, tvb, offset, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(extflags_tree, hf_peekremote_extflags_future_use, tvb, offset, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(extflags_tree, hf_peekremote_extflags_80mhz, tvb, offset, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(extflags_tree, hf_peekremote_extflags_shortpreamble, tvb, offset, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(extflags_tree, hf_peekremote_extflags_spatialstreams, tvb, offset, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(extflags_tree, hf_peekremote_extflags_heflag, tvb, offset, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(extflags_tree, hf_peekremote_extflags_160mhz, tvb, offset, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(extflags_tree, hf_peekremote_extflags_ehtflag, tvb, offset, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(extflags_tree, hf_peekremote_extflags_320mhz, tvb, offset, 4, ENC_BIG_ENDIAN);
  if ((extflags & EXT_FLAG_HEFLAG) || (extflags & EXT_FLAG_EHTFLAG)) {
    item = proto_tree_add_item(extflags_tree, hf_peekremote_extflags_quarter_gi, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_item_append_text(item, " (0.8uS)");
  }
  proto_tree_add_item(extflags_tree, hf_peekremote_extflags_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);

  return 4;
}

static int
dissect_peekremote_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
  proto_tree *flags_tree;
  proto_item *ti_flags;

  ti_flags = proto_tree_add_item(tree, hf_peekremote_flags, tvb, offset, 1, ENC_NA);
  flags_tree = proto_item_add_subtree(ti_flags, ett_peekremote_flags);
  proto_tree_add_item(flags_tree, hf_peekremote_flags_control_frame, tvb, offset, 1, ENC_NA);
  proto_tree_add_item(flags_tree, hf_peekremote_flags_crc_error, tvb, offset, 1, ENC_NA);
  proto_tree_add_item(flags_tree, hf_peekremote_flags_frame_error, tvb, offset, 1, ENC_NA);
  proto_tree_add_item(flags_tree, hf_peekremote_flags_6ghz_band_valid, tvb, offset, 1, ENC_NA);
  proto_tree_add_item(flags_tree, hf_peekremote_flags_6ghz, tvb, offset, 1, ENC_NA);
  proto_tree_add_item(flags_tree, hf_peekremote_flags_reserved, tvb, offset, 1, ENC_NA);

  return 1;
}

static int
dissect_peekremote_status(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
  proto_tree *status_tree;
  proto_item *ti_status;

  ti_status = proto_tree_add_item(tree, hf_peekremote_status, tvb, offset, 1, ENC_NA);
  status_tree = proto_item_add_subtree(ti_status, ett_peekremote_status);
  proto_tree_add_item(status_tree, hf_peekremote_status_protected, tvb, offset, 1, ENC_NA);
  proto_tree_add_item(status_tree, hf_peekremote_status_with_decrypt_error, tvb, offset, 1, ENC_NA);
  proto_tree_add_item(status_tree, hf_peekremote_status_with_short_preamble, tvb, offset, 1, ENC_NA);
  proto_tree_add_item(status_tree, hf_peekremote_status_reserved, tvb, offset, 1, ENC_NA);

  return 1;
}

static bool
dissect_peekremote_new(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *u _U_)
{
  static const uint8_t magic[4] = { 0x00, 0xFF, 0xAB, 0xCD };
  int offset = 0;
  proto_tree *peekremote_tree = NULL;
  proto_item *ti = NULL;
  proto_item *ti_header_version, *ti_header_size;
  uint8_t header_version;
  int header_size;
  struct ieee_802_11_phdr phdr;
  uint32_t extflags;
  uint16_t frequency;
  uint16_t mcs_index;
  uint8_t nss;
  tvbuff_t *next_tvb;

  if (tvb_memeql(tvb, 0, magic, 4) == -1) {
    /*
     * Not big enough to hold the magic number, or doesn't start
     * with the magic number.
     */
    return false;
  }

  /* We don't have any 802.11 metadata yet. */
  memset(&phdr, 0, sizeof(phdr));
  phdr.fcs_len = 4; /* has an FCS */
  phdr.decrypted = false;
  phdr.datapad = false;
  phdr.phy = PHDR_802_11_PHY_UNKNOWN;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "PEEKREMOTE");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_peekremote, tvb, 0, -1, ENC_NA);
  peekremote_tree = proto_item_add_subtree(ti, ett_peekremote);

  proto_tree_add_item(peekremote_tree, hf_peekremote_magic_number, tvb, offset, 4,  ENC_BIG_ENDIAN);
  offset += 4;
  header_version = tvb_get_uint8(tvb, offset);
  ti_header_version = proto_tree_add_uint(peekremote_tree, hf_peekremote_header_version, tvb, offset, 1,  header_version);
  offset += 1;
  header_size = tvb_get_ntohl(tvb, offset);
  ti_header_size = proto_tree_add_uint(peekremote_tree, hf_peekremote_header_size, tvb, offset, 4, header_size);
  offset += 4;
  switch (header_version) {

  case 2:
    if (header_size != 55) {
      expert_add_info(pinfo, ti_header_size, &ei_peekremote_invalid_header_size);
      if (header_size > 9)
        offset += (header_size - 9);
    } else {
      /* Initialize bandwidth as 20Mhz, overwrite later based on extflags, if needed*/
      int bandwidth_vht = IEEE80211_RADIOTAP_VHT_BW_20;
      int bandwidth_he  = IEEE80211_RADIOTAP_HE_DATA_BANDWIDTH_RU_20;
      int bandwidth_eht  = IEEE80211_RADIOTAP_USIG_BW_20;

      proto_tree_add_item(peekremote_tree, hf_peekremote_type, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      mcs_index = tvb_get_ntohs(tvb, offset);
      extflags = tvb_get_ntohl(tvb, offset+12);
      /* Encoded value is NSS - 1 */
      nss = ((extflags & EXT_FLAG_SPATIALSTREAMS) >> EXT_FLAG_SPATIALSTREAMS_SHIFT) + 1;

      if (extflags & EXT_FLAG_40_MHZ) {
        bandwidth_vht = IEEE80211_RADIOTAP_VHT_BW_40;
        bandwidth_he = IEEE80211_RADIOTAP_HE_DATA_BANDWIDTH_RU_40;
        bandwidth_eht = IEEE80211_RADIOTAP_USIG_BW_40;
      } else if (extflags & EXT_FLAG_80MHZ) {
        bandwidth_vht = IEEE80211_RADIOTAP_VHT_BW_80;
        bandwidth_he = IEEE80211_RADIOTAP_HE_DATA_BANDWIDTH_RU_80;
        bandwidth_eht = IEEE80211_RADIOTAP_USIG_BW_80;
      } else if (extflags & EXT_FLAG_160MHZ) {
        bandwidth_vht = IEEE80211_RADIOTAP_VHT_BW_160;
        bandwidth_he = IEEE80211_RADIOTAP_HE_DATA_BANDWIDTH_RU_160;
        bandwidth_eht = IEEE80211_RADIOTAP_USIG_BW_160;
      } else if (extflags & EXT_FLAG_320MHZ) {
         bandwidth_eht = IEEE80211_RADIOTAP_USIG_BW_320_1;
      }

      if (extflags & EXT_FLAG_EHTFLAG) {
        proto_tree_add_item(peekremote_tree, hf_peekremote_mcs_index_ac, tvb, offset, 2, ENC_BIG_ENDIAN);
        phdr.phy = PHDR_802_11_PHY_11BE;
        if (extflags & EXT_FLAGS_GI) {
        /* Quarter GI  : 0.8uS
            Half GI    : 1.6uS
            Full GI    : 3.2uS */
          phdr.phy_info.info_11be.has_gi = true;
          phdr.phy_info.info_11be.gi = ((extflags & EXT_FLAG_FULL_GI) != 0) ? 2 :
                                        ((extflags & EXT_FLAG_HALF_GI) != 0) ? 1 :
                                        0;
        }
        phdr.phy_info.info_11be.has_bandwidth = true;
        phdr.phy_info.info_11be.bandwidth     = bandwidth_eht;
        /* Peekremote does not have per-user fields, so fill data as if it is SU and for user0 */
        phdr.phy_info.info_11be.num_users = 1;
        phdr.phy_info.info_11be.user[0].mcs_known  = true;
        phdr.phy_info.info_11be.user[0].mcs   = mcs_index;
        phdr.phy_info.info_11be.user[0].nsts_known = true;
        phdr.phy_info.info_11be.user[0].nsts  = nss;

      } else if (extflags & EXT_FLAG_HEFLAG) {
        proto_tree_add_item(peekremote_tree, hf_peekremote_mcs_index_ac, tvb, offset, 2, ENC_BIG_ENDIAN);
        phdr.phy = PHDR_802_11_PHY_11AX;
        if (extflags & EXT_FLAGS_GI) {
        /* Quarter GI  : 0.8uS
            Half GI    : 1.6uS
            Full GI    : 3.2uS */
          phdr.phy_info.info_11ax.has_gi = true;
          phdr.phy_info.info_11ax.gi = ((extflags & EXT_FLAG_FULL_GI) != 0) ? 2 :
                                        ((extflags & EXT_FLAG_HALF_GI) != 0) ? 1 :
                                        0;
        }
        phdr.phy_info.info_11ax.has_bwru = true;
        phdr.phy_info.info_11ax.bwru = bandwidth_he;
        phdr.phy_info.info_11ax.has_mcs_index = true;
        phdr.phy_info.info_11ax.mcs = mcs_index;
        phdr.phy_info.info_11ax.nsts = nss;

      } else {
        if (extflags & EXT_FLAG_802_11ac) {
          proto_tree_add_item(peekremote_tree, hf_peekremote_mcs_index_ac, tvb, offset, 2, ENC_BIG_ENDIAN);
          phdr.phy = PHDR_802_11_PHY_11AC;
          if (extflags & EXT_FLAGS_GI) {
            /* Half GI     : 0.4uS
               Full GI     : 0.8uS */
            phdr.phy_info.info_11ac.has_short_gi = true;
            phdr.phy_info.info_11ac.short_gi = ((extflags & EXT_FLAG_HALF_GI) != 0);
          }

          phdr.phy_info.info_11ac.has_bandwidth = true;
          phdr.phy_info.info_11ac.bandwidth = bandwidth_vht;
          /* Set FEC/ STBC to defaults to suppress warnings in 80211-radio dissector */
          phdr.phy_info.info_11ac.has_fec = true;
          phdr.phy_info.info_11ac.fec     = 0;
          phdr.phy_info.info_11ac.has_stbc = true;
          phdr.phy_info.info_11ac.stbc    = 0;
          /* Peekremote does not have per-user fields, so fill data as if it is SU and for user0 */
          phdr.phy_info.info_11ac.mcs[0]  = mcs_index;
          phdr.phy_info.info_11ac.nss[0]  = nss;

        } else { /* 11n */
          proto_tree_add_item(peekremote_tree, hf_peekremote_mcs_index, tvb, offset, 2, ENC_BIG_ENDIAN);
          phdr.phy = PHDR_802_11_PHY_11N;
          if (extflags & EXT_FLAGS_GI) {
            /* Half GI     : 0.4uS
               Full GI     : 0.8uS */
            phdr.phy_info.info_11ac.has_short_gi = true;
            phdr.phy_info.info_11ac.short_gi = ((extflags & EXT_FLAG_HALF_GI) != 0);
          }
          phdr.phy_info.info_11n.has_bandwidth = true;
          if (extflags & EXT_FLAG_40_MHZ) {
            phdr.phy_info.info_11n.bandwidth = IEEE80211_RADIOTAP_MCS_BW_40;
          } else {
            phdr.phy_info.info_11n.bandwidth = IEEE80211_RADIOTAP_MCS_BW_20;
          }
          /* Set FEC/ STBC/ Greenfield to defaults to suppress warnings in 80211-radio dissector */
          phdr.phy_info.info_11n.has_fec      = true;
          phdr.phy_info.info_11n.fec          = 0;
          phdr.phy_info.info_11n.has_stbc_streams = true;
          phdr.phy_info.info_11n.stbc_streams   = 0;
          phdr.phy_info.info_11n.has_greenfield = true;
          phdr.phy_info.info_11n.greenfield     = false;
          phdr.phy_info.info_11n.has_ness       = true;
          phdr.phy_info.info_11n.ness           = 0;

          phdr.phy_info.info_11n.has_mcs_index  = true;
          phdr.phy_info.info_11n.mcs_index      = mcs_index;
        }
      }
      offset += 2;
      phdr.has_channel = true;
      phdr.channel = tvb_get_ntohs(tvb, offset);
      proto_tree_add_item(peekremote_tree, hf_peekremote_channel, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      frequency = tvb_get_ntohl(tvb, offset);
      if (frequency != 0) {
        phdr.has_frequency = true;
        phdr.frequency = frequency;
      }
      proto_tree_add_item(peekremote_tree, hf_peekremote_frequency, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(peekremote_tree, hf_peekremote_band, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset +=4;
      offset += dissect_peekremote_extflags(tvb, pinfo, peekremote_tree, offset);
      phdr.has_signal_percent = true;
      phdr.signal_percent = tvb_get_uint8(tvb, offset);
      proto_tree_add_item(peekremote_tree, hf_peekremote_signal_percent, tvb, offset, 1, ENC_NA);
      offset += 1;
      phdr.has_noise_percent = true;
      phdr.noise_percent = tvb_get_uint8(tvb, offset);
      proto_tree_add_item(peekremote_tree, hf_peekremote_noise_percent, tvb, offset, 1, ENC_NA);
      offset += 1;
      phdr.has_signal_dbm = true;
      phdr.signal_dbm = tvb_get_uint8(tvb, offset);
      proto_tree_add_item(peekremote_tree, hf_peekremote_signal_dbm, tvb, offset, 1, ENC_NA);
      offset += 1;
      phdr.has_noise_dbm = true;
      phdr.noise_dbm = tvb_get_uint8(tvb, offset);
      proto_tree_add_item(peekremote_tree, hf_peekremote_noise_dbm, tvb, offset, 1, ENC_NA);
      offset += 1;
      proto_tree_add_item(peekremote_tree, hf_peekremote_signal_1_dbm, tvb, offset, 1, ENC_NA);
      offset += 1;
      proto_tree_add_item(peekremote_tree, hf_peekremote_signal_2_dbm, tvb, offset, 1, ENC_NA);
      offset += 1;
      proto_tree_add_item(peekremote_tree, hf_peekremote_signal_3_dbm, tvb, offset, 1, ENC_NA);
      offset += 1;
      proto_tree_add_item(peekremote_tree, hf_peekremote_signal_4_dbm, tvb, offset, 1, ENC_NA);
      offset += 1;
      proto_tree_add_item(peekremote_tree, hf_peekremote_noise_1_dbm, tvb, offset, 1, ENC_NA);
      offset += 1;
      proto_tree_add_item(peekremote_tree, hf_peekremote_noise_2_dbm, tvb, offset, 1, ENC_NA);
      offset += 1;
      proto_tree_add_item(peekremote_tree, hf_peekremote_noise_3_dbm, tvb, offset, 1, ENC_NA);
      offset += 1;
      proto_tree_add_item(peekremote_tree, hf_peekremote_noise_4_dbm, tvb, offset, 1, ENC_NA);
      offset += 1;
      proto_tree_add_item(peekremote_tree, hf_peekremote_packetlength, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      proto_tree_add_item(peekremote_tree, hf_peekremote_slicelength, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      offset += dissect_peekremote_flags(tvb, pinfo, peekremote_tree, offset);
      offset += dissect_peekremote_status(tvb, pinfo, peekremote_tree, offset);
      proto_tree_add_item(peekremote_tree, hf_peekremote_timestamp, tvb, offset, 8, ENC_BIG_ENDIAN);
      phdr.has_tsf_timestamp = true;
      phdr.tsf_timestamp = tvb_get_ntoh64(tvb, offset);
      offset += 8;
    }
    break;
  /* With LiveAction's consent (via Issue #19533) new version Peekremote v3 encapsulation is defined as:
  *  [ UDP [ PEEKREMOTE v3 [ RADIOTAP [ 80211 ]]]]
  */
  case PEEKREMOTE_V3:
    if (header_size != PEEKREMOTE_V3_HDR_LEN) {
      expert_add_info(pinfo, ti_header_size, &ei_peekremote_invalid_header_size);
      if (header_size > PEEKRMEOTE_NEW_BASE_LEN) {
        offset += (header_size - PEEKRMEOTE_NEW_BASE_LEN);
      }
    } else {
      proto_tree_add_item(peekremote_tree, hf_peekremote_type, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_item_set_end(ti, tvb, offset);
      next_tvb = tvb_new_subset_remaining(tvb, offset);
      call_dissector(radiotap_handle, next_tvb, pinfo, tree);
      return true;
    }
    break;
  default:
    expert_add_info(pinfo, ti_header_version, &ei_peekremote_unknown_header_version);
    if (header_size > 9)
      offset += (header_size - 9);
    break;
  }

  proto_item_set_end(ti, tvb, offset);
  next_tvb = tvb_new_subset_remaining(tvb, offset);
  call_dissector_with_data(wlan_radio_handle, next_tvb, pinfo, tree, &phdr);
  return true;
}

static int
dissect_peekremote_legacy(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  tvbuff_t *next_tvb;
  proto_tree *peekremote_tree = NULL;
  proto_item *ti = NULL;
  struct ieee_802_11_phdr phdr;
  uint8_t signal_percent;
  uint8_t flags = 0;
  bool is_6ghz = false;
  memset(&phdr, 0, sizeof(phdr));

  /*
   * Check whether this is peekremote-ng, and dissect it as such if it
   * is.
   */
  if (dissect_peekremote_new(tvb, pinfo, tree, data)) {
    /* Yup, it was peekremote-ng, and it's been dissected as such. */
    return tvb_reported_length(tvb);
  }

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "PEEKREMOTE");
  col_clear(pinfo->cinfo, COL_INFO);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_peekremote, tvb, 0, -1, ENC_NA);
    peekremote_tree = proto_item_add_subtree(ti, ett_peekremote);

    proto_tree_add_item(peekremote_tree, hf_peekremote_signal_dbm, tvb, 0, 1, ENC_NA);
    proto_tree_add_item(peekremote_tree, hf_peekremote_noise_dbm, tvb, 1, 1, ENC_NA);
    proto_tree_add_item(peekremote_tree, hf_peekremote_packetlength, tvb, 2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(peekremote_tree, hf_peekremote_slicelength, tvb, 4, 2, ENC_BIG_ENDIAN);
    dissect_peekremote_flags(tvb, pinfo, peekremote_tree, 6);
    dissect_peekremote_status(tvb, pinfo, peekremote_tree, 7);
    proto_tree_add_item(peekremote_tree, hf_peekremote_timestamp, tvb, 8, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(peekremote_tree, hf_peekremote_speed, tvb, 16, 1, ENC_NA);
    proto_tree_add_item(peekremote_tree, hf_peekremote_channel, tvb, 17, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(peekremote_tree, hf_peekremote_signal_percent, tvb, 18, 1, ENC_NA);
    proto_tree_add_item(peekremote_tree, hf_peekremote_noise_percent, tvb, 19, 1, ENC_NA);
  }
  signal_percent = tvb_get_uint8(tvb, 18);
  proto_item_set_end(ti, tvb, 20);
  next_tvb = tvb_new_subset_remaining(tvb, 20);
  /* When signal = 100 % and coming from ARUBA ERM, it is TX packet and there is no FCS */
  if (GPOINTER_TO_INT(data) == IS_ARUBA && signal_percent == 100) {
    phdr.fcs_len = 0; /* TX packet, no FCS */
  } else {
    phdr.fcs_len = 4; /* We have an FCS */
  }
  phdr.decrypted = false;
  phdr.phy = PHDR_802_11_PHY_UNKNOWN;
  phdr.has_channel = true;
  phdr.channel = tvb_get_uint8(tvb, 17);
  phdr.has_data_rate = true;
  phdr.data_rate = tvb_get_uint8(tvb, 16);
  phdr.has_signal_percent = true;
  phdr.signal_percent = tvb_get_uint8(tvb, 18);
  phdr.has_noise_percent = true;
  phdr.noise_percent = tvb_get_uint8(tvb, 18);
  phdr.has_signal_dbm = true;
  phdr.signal_dbm = tvb_get_uint8(tvb, 0);
  phdr.has_noise_dbm = true;
  phdr.noise_dbm = tvb_get_uint8(tvb, 1);
  phdr.has_tsf_timestamp = true;
  phdr.tsf_timestamp = tvb_get_ntoh64(tvb, 8);

  flags = tvb_get_uint8(tvb, 6);
  if (flags & PEEKREMOTE_V0_6GHZ_BAND_VALID) {
    bool is_bg;
    is_6ghz = flags & PEEKREMOTE_V0_IS_6GHZ_BAND;
    is_bg   = is_6ghz ? false : CHAN_IS_BG(phdr.channel);
    phdr.has_frequency = true;
    phdr.frequency = ieee80211_chan_band_to_mhz(phdr.channel, is_bg, is_6ghz);
  }
  /*
   * We don't know they PHY, but we do have the data rate;
   * try to guess the PHY based on the data rate and channel.
   */
  if (RATE_IS_DSSS(phdr.data_rate)) {
    /* 11b */
    phdr.phy = PHDR_802_11_PHY_11B;
    phdr.phy_info.info_11b.has_short_preamble = false;
  } else if (RATE_IS_OFDM(phdr.data_rate)) {
    /* 11a or 11g, depending on the band. */
    if (CHAN_IS_BG(phdr.channel) && !is_6ghz) {
      /* 11g */
      phdr.phy = PHDR_802_11_PHY_11G;
      phdr.phy_info.info_11g.has_mode = false;
    } else {
      /* 11a */
      phdr.phy = PHDR_802_11_PHY_11A;
      phdr.phy_info.info_11a.has_channel_type = false;
      phdr.phy_info.info_11a.has_turbo_type = false;
    }
  }

  return 20 + call_dissector_with_data(wlan_radio_handle, next_tvb, pinfo, tree, &phdr);
}

void
proto_register_peekremote(void)
{
  static hf_register_info hf[] = {
    { &hf_peekremote_channel,
      { "Channel", "peekremote.channel",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_peekremote_signal_dbm,
      { "Signal [dBm]", "peekremote.signal_dbm",
        FT_INT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_peekremote_noise_dbm,
      { "Noise [dBm]", "peekremote.noise_dbm",
        FT_INT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_peekremote_packetlength,
      { "Packet length", "peekremote.packetlength",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_peekremote_slicelength,
      { "Slice length", "peekremote.slicelength",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_peekremote_flags,
      { "Flags", "peekremote.flags",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_peekremote_flags_control_frame,
      { "Is a Control frame", "peekremote.flags.control_frame",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
        NULL, HFILL }
    },
    { &hf_peekremote_flags_crc_error,
      { "Has CRC error", "peekremote.flags.has_crc_error",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
        NULL, HFILL }
    },
    { &hf_peekremote_flags_frame_error,
      { "Has frame error", "peekremote.flags.has_frame_error",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
        NULL, HFILL }
    },
    { &hf_peekremote_flags_6ghz_band_valid,
      { "Is 6GHz band flag valid", "peekremote.flags.6ghzband_valid",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
        NULL, HFILL }
    },
    { &hf_peekremote_flags_6ghz,
      { "6GHz band", "peekremote.flags.6ghz",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
        NULL, HFILL }
    },
    { &hf_peekremote_flags_reserved,
      { "Reserved", "peekremote.flags.reserved",
        FT_UINT8, BASE_HEX, NULL, 0xE0,
        "Must be zero", HFILL }
    },
    { &hf_peekremote_status,
      { "Status", "peekremote.status",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_peekremote_status_protected,
      { "Protected", "peekremote.status.protected",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
        NULL, HFILL }
    },
    { &hf_peekremote_status_with_decrypt_error,
      { "With decrypt error", "peekremote.status.with_decrypt_error",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
        NULL, HFILL }
    },
    { &hf_peekremote_status_with_short_preamble,
      { "With short preamble", "peekremote.status.with_short_preamble",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
        NULL, HFILL }
    },
    { &hf_peekremote_status_reserved,
      { "Reserved", "peekremote.status.reserved",
        FT_UINT8, BASE_HEX, NULL, 0xB3,
        "Must be zero", HFILL }
    },
    { &hf_peekremote_timestamp,
      { "TSF timestamp", "peekremote.timestamp",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_peekremote_mcs_index,
      { "MCS index", "peekremote.mcs_index",
        FT_UINT16, BASE_DEC|BASE_EXT_STRING, &peekremote_mcs_index_vals_ext, 0x0,
        NULL, HFILL }
    },
    { &hf_peekremote_mcs_index_ac,
      { "11ac/11ax/11be MCS index", "peekremote.mcs_index_ac",
        FT_UINT16, BASE_DEC, VALS(peekremote_mcs_index_vals_ac), 0x0,
        NULL, HFILL }
    },
    { &hf_peekremote_signal_percent,
      { "Signal [percent]", "peekremote.signal_percent",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_peekremote_noise_percent,
      { "Noise [percent]", "peekremote.noise_percent",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_peekremote_speed,
      { "Data rate [500kHz]", "peekremote.data_rate",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_peekremote_magic_number,
      { "Magic number", "peekremote.magic_number",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_peekremote_header_version,
      { "Header version", "peekremote.header_version",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_peekremote_header_size,
      { "Header size", "peekremote.header_size",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_peekremote_type,
      { "Type", "peekremote.type",
        FT_UINT32, BASE_DEC, VALS(peekremote_type_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_peekremote_frequency,
      { "Frequency [Mhz]", "peekremote.frequency",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_peekremote_band,
      { "Band", "peekremote.band",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_peekremote_extflags,
      { "Extended flags", "peekremote.extflags",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_peekremote_extflags_20mhz_lower,
      { "20 MHz Lower", "peekremote.extflags.20mhz_lower",
        FT_BOOLEAN, 32, TFS(&tfs_yes_no), EXT_FLAG_20_MHZ_LOWER,
        NULL, HFILL }
    },
    { &hf_peekremote_extflags_20mhz_upper,
      { "20 MHz Upper", "peekremote.extflags.20mhz_upper",
        FT_BOOLEAN, 32, TFS(&tfs_yes_no), EXT_FLAG_20_MHZ_UPPER,
        NULL, HFILL }
    },
    { &hf_peekremote_extflags_40mhz,
      { "40 MHz", "peekremote.extflags.40mhz",
        FT_BOOLEAN, 32, TFS(&tfs_yes_no), EXT_FLAG_40_MHZ,
        NULL, HFILL }
    },
    { &hf_peekremote_extflags_half_gi,
      { "Half Guard Interval", "peekremote.extflags.half_gi",
        FT_BOOLEAN, 32, TFS(&tfs_yes_no), EXT_FLAG_HALF_GI,
        NULL, HFILL }
    },
    { &hf_peekremote_extflags_full_gi,
      { "Full Guard Interval", "peekremote.extflags.full_gi",
        FT_BOOLEAN, 32, TFS(&tfs_yes_no), EXT_FLAG_FULL_GI,
        NULL, HFILL }
    },
    { &hf_peekremote_extflags_ampdu,
      { "AMPDU", "peekremote.extflags.ampdu",
        FT_BOOLEAN, 32, TFS(&tfs_yes_no), EXT_FLAG_AMPDU,
        NULL, HFILL }
    },
    { &hf_peekremote_extflags_amsdu,
      { "AMSDU", "peekremote.extflags.amsdu",
        FT_BOOLEAN, 32, TFS(&tfs_yes_no), EXT_FLAG_AMSDU,
        NULL, HFILL }
    },
    { &hf_peekremote_extflags_11ac,
      { "802.11ac", "peekremote.extflags.11ac",
        FT_BOOLEAN, 32, TFS(&tfs_yes_no), EXT_FLAG_802_11ac,
        NULL, HFILL }
    },
    { &hf_peekremote_extflags_future_use,
      { "MCS index used", "peekremote.extflags.future_use",
        FT_BOOLEAN, 32, TFS(&tfs_yes_no), EXT_FLAG_MCS_INDEX_USED,
        NULL, HFILL }
    },
    { &hf_peekremote_extflags_80mhz,
      { "80 Mhz", "peekremote.extflags.80mhz",
        FT_BOOLEAN, 32, TFS(&tfs_yes_no), EXT_FLAG_80MHZ,
        NULL, HFILL }
    },
    { &hf_peekremote_extflags_shortpreamble,
      { "Short preamble", "peekremote.extflags.shortpreamble",
        FT_BOOLEAN, 32, TFS(&tfs_yes_no), EXT_FLAG_SHORTPREAMBLE,
        NULL, HFILL }
    },
    { &hf_peekremote_extflags_spatialstreams,
      { "Spatial streams", "peekremote.extflags.spatialstreams",
        FT_UINT32, BASE_DEC, VALS(spatialstreams_vals), EXT_FLAG_SPATIALSTREAMS,
        NULL, HFILL }
    },
    { &hf_peekremote_extflags_heflag,
      { "802.11ax", "peekremote.extflags.11ax",
        FT_BOOLEAN, 32, TFS(&tfs_yes_no), EXT_FLAG_HEFLAG,
        NULL, HFILL }
    },
    { &hf_peekremote_extflags_160mhz,
      { "160Mhz", "peekremote.extflags.160mhz",
        FT_BOOLEAN, 32, TFS(&tfs_yes_no), EXT_FLAG_160MHZ,
        NULL, HFILL }
    },
    { &hf_peekremote_extflags_ehtflag,
      { "802.11be", "peekremote.extflags.11be",
        FT_BOOLEAN, 32, TFS(&tfs_yes_no), EXT_FLAG_EHTFLAG,
        NULL, HFILL }
    },
    { &hf_peekremote_extflags_320mhz,
      { "320Mhz", "peekremote.extflags.320mhz",
        FT_BOOLEAN, 32, TFS(&tfs_yes_no), EXT_FLAG_320MHZ,
        NULL, HFILL }
    },
    { &hf_peekremote_extflags_quarter_gi,
      { "Quarter Guard Interval", "peekremote.extflags.quarter_gi",
        FT_BOOLEAN, 32, TFS(&tfs_yes_no), EXT_FLAG_QUARTER_GI,
        NULL, HFILL }
    },
    { &hf_peekremote_extflags_reserved,
      { "Reserved", "peekremote.extflags.reserved",
        FT_UINT32, BASE_HEX, NULL, EXT_FLAGS_RESERVED,
        "Must be zero", HFILL }
    },
    { &hf_peekremote_signal_1_dbm,
      { "Signal 1 [dBm]", "peekremote.signal_1_dbm",
        FT_INT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_peekremote_signal_2_dbm,
      { "Signal 2 [dBm]", "peekremote.signal_2_dbm",
        FT_INT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_peekremote_signal_3_dbm,
      { "Signal 3 [dBm]", "peekremote.signal_3_dbm",
        FT_INT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_peekremote_signal_4_dbm,
      { "Signal 4 [dBm]", "peekremote.signal_4_dbm",
        FT_INT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_peekremote_noise_1_dbm,
      { "Noise 1 [dBm]", "peekremote.noise_1_dbm",
        FT_INT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_peekremote_noise_2_dbm,
      { "Noise 2 [dBm]", "peekremote.noise_2_dbm",
        FT_INT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_peekremote_noise_3_dbm,
      { "Noise 3 [dBm]", "peekremote.noise_3_dbm",
        FT_INT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_peekremote_noise_4_dbm,
      { "Noise 4 [dBm]", "peekremote.noise_4_dbm",
        FT_INT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
  };
  static int *ett[] = {
    &ett_peekremote,
    &ett_peekremote_flags,
    &ett_peekremote_status,
    &ett_peekremote_extflags
  };
  static ei_register_info ei[] = {
     { &ei_peekremote_unknown_header_version, { "peekremote.unknown_header_version", PI_UNDECODED, PI_ERROR, "Unknown header version", EXPFILL }},
     { &ei_peekremote_invalid_header_size, { "peekremote.invalid_header_size", PI_UNDECODED, PI_ERROR, "Invalid header size for that header version", EXPFILL }},
  };
  expert_module_t *expert_peekremote;

  proto_peekremote = proto_register_protocol("AiroPeek/OmniPeek encapsulated IEEE 802.11", "PEEKREMOTE", "peekremote");
  proto_register_field_array(proto_peekremote, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_peekremote = expert_register_protocol(proto_peekremote);
  expert_register_field_array(expert_peekremote, ei, array_length(ei));

  peekremote_handle = register_dissector("peekremote", dissect_peekremote_legacy, proto_peekremote);
}

void
proto_reg_handoff_peekremote(void)
{
  /* Peekremote V0/V2 */
  wlan_radio_handle = find_dissector_add_dependency("wlan_radio", proto_peekremote);
  /* Peekremote V3 */
  radiotap_handle = find_dissector_add_dependency("radiotap", proto_peekremote);
  dissector_add_uint_with_preference("udp.port", PEEKREMOTE_PORT, peekremote_handle);

  heur_dissector_add("udp", dissect_peekremote_new, "OmniPeek Remote over UDP", "peekremote_udp", proto_peekremote, HEURISTIC_ENABLE);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
