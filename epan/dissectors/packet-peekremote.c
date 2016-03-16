/* packet-peekremote.c
 *
 * Routines for the disassembly of packets sent from Cisco WLAN
 * Controllers, possibly other Cisco access points, and possibly
 * other devices such as Aruba access points.  See
 *
 *    http://www.wildpackets.com/elements/omnipeek/OmniPeek_UserGuide.pdf
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

#include <wiretap/wtap.h>

#include <epan/packet.h>
#include <epan/expert.h>

#define IS_ARUBA 0x01

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
#define EXT_FLAGS_GI                            0x00000018
#define EXT_FLAG_AMPDU                          0x00000020
#define EXT_FLAG_AMSDU                          0x00000040
#define EXT_FLAG_802_11ac                       0x00000080
#define EXT_FLAG_MCS_INDEX_USED                 0x00000100
#define EXT_FLAGS_RESERVED                      0xFFFFFE00

/* hfi elements */
#define THIS_HF_INIT HFI_INIT(proto_peekremote)
static header_field_info *hfi_peekremote = NULL;

/* Common to both headers */
static header_field_info hfi_peekremote_channel THIS_HF_INIT =
      { "Channel",       "peekremote.channel", FT_UINT16, BASE_DEC, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_signal_dbm THIS_HF_INIT =
      { "Signal [dBm]",     "peekremote.signal_dbm", FT_INT8, BASE_DEC, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_noise_dbm THIS_HF_INIT =
      { "Noise [dBm]",      "peekremote.noise_dbm", FT_INT8, BASE_DEC, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_packetlength THIS_HF_INIT =
      { "Packet length",      "peekremote.packetlength", FT_UINT16, BASE_DEC, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_slicelength THIS_HF_INIT =
      { "Slice length",      "peekremote.slicelength", FT_UINT16, BASE_DEC, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_flags THIS_HF_INIT =
      { "Flags",     "peekremote.flags", FT_UINT8, BASE_HEX, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_flags_control_frame THIS_HF_INIT =
      { "Is a Control frame",     "peekremote.flags.control_frame", FT_BOOLEAN, 8, TFS(&tfs_yes_no),
        0x01, NULL, HFILL };

static header_field_info hfi_peekremote_flags_crc_error THIS_HF_INIT =
      { "Has CRC error",     "peekremote.flags.has_crc_error", FT_BOOLEAN, 8, TFS(&tfs_yes_no),
        0x02, NULL, HFILL };

static header_field_info hfi_peekremote_flags_frame_error THIS_HF_INIT =
      { "Has frame error",     "peekremote.flags.has_frame_error", FT_BOOLEAN, 8, TFS(&tfs_yes_no),
        0x04, NULL, HFILL };

static header_field_info hfi_peekremote_flags_reserved THIS_HF_INIT =
      { "Reserved",     "peekremote.flags.reserved", FT_UINT8, BASE_HEX, NULL,
        0xF8, "Must be zero", HFILL };

static header_field_info hfi_peekremote_status THIS_HF_INIT =
      { "Status",     "peekremote.status", FT_UINT8, BASE_HEX, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_status_protected THIS_HF_INIT =
      { "Protected",     "peekremote.status.protected", FT_BOOLEAN, 8, TFS(&tfs_yes_no),
        0x04, NULL, HFILL };

static header_field_info hfi_peekremote_status_with_decrypt_error THIS_HF_INIT =
      { "With decrypt error",     "peekremote.status.with_decrypt_error", FT_BOOLEAN, 8, TFS(&tfs_yes_no),
        0x08, NULL, HFILL };

static header_field_info hfi_peekremote_status_with_short_preamble THIS_HF_INIT =
      { "With short preamble",     "peekremote.status.with_short_preamble", FT_BOOLEAN, 8, TFS(&tfs_yes_no),
        0x40, NULL, HFILL };

static header_field_info hfi_peekremote_status_reserved THIS_HF_INIT =
      { "Reserved",     "peekremote.status.reserved", FT_UINT8, BASE_HEX, NULL,
        0xB3, "Must be zero", HFILL };

static header_field_info hfi_peekremote_timestamp THIS_HF_INIT =
      { "TSF timestamp",       "peekremote.timestamp", FT_UINT64, BASE_DEC, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_mcs_index THIS_HF_INIT =
      { "MCS index",         "peekremote.mcs_index", FT_UINT16,  BASE_DEC|BASE_EXT_STRING, &peekremote_mcs_index_vals_ext,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_signal_percent THIS_HF_INIT =
      { "Signal [percent]",     "peekremote.signal_percent", FT_UINT8, BASE_DEC, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_noise_percent THIS_HF_INIT =
      { "Noise [percent]",     "peekremote.noise_percent", FT_UINT8, BASE_DEC, NULL,
        0x0, NULL, HFILL };

/* Legacy header only */
static header_field_info hfi_peekremote_speed THIS_HF_INIT =
      { "Data rate [500kHz]", "peekremote.data_rate", FT_UINT8, BASE_DEC, NULL,
        0x0, NULL, HFILL };

/* New header only */
static header_field_info hfi_peekremote_magic_number THIS_HF_INIT =
      { "Magic number",      "peekremote.magic_number", FT_UINT32, BASE_HEX, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_header_version THIS_HF_INIT =
      { "Header version",    "peekremote.header_version", FT_UINT8, BASE_DEC, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_header_size THIS_HF_INIT =
      { "Header size",       "peekremote.header_size", FT_UINT32, BASE_DEC, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_type THIS_HF_INIT =
      { "Type",              "peekremote.type", FT_UINT32, BASE_DEC, VALS(peekremote_type_vals),
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_frequency THIS_HF_INIT =
      { "Frequency [Mhz]",   "peekremote.frequency", FT_UINT32, BASE_DEC, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_band THIS_HF_INIT =
      { "Band",     "peekremote.band", FT_UINT32, BASE_DEC, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_extflags THIS_HF_INIT =
      { "Extended flags",     "peekremote.extflags", FT_UINT32, BASE_HEX, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_extflags_20mhz_lower THIS_HF_INIT =
      { "20 MHz Lower",     "peekremote.extflags.20mhz_lower", FT_BOOLEAN, 32, TFS(&tfs_yes_no),
        EXT_FLAG_20_MHZ_LOWER, NULL, HFILL };

static header_field_info hfi_peekremote_extflags_20mhz_upper THIS_HF_INIT =
      { "20 MHz Upper",     "peekremote.extflags.20mhz_upper", FT_BOOLEAN, 32, TFS(&tfs_yes_no),
        EXT_FLAG_20_MHZ_UPPER, NULL, HFILL };

static header_field_info hfi_peekremote_extflags_40mhz THIS_HF_INIT =
      { "40 MHz",     "peekremote.extflags.40mhz", FT_BOOLEAN, 32, TFS(&tfs_yes_no),
        EXT_FLAG_40_MHZ, NULL, HFILL };

static header_field_info hfi_peekremote_extflags_half_gi THIS_HF_INIT =
      { "Half Guard Interval",     "peekremote.extflags.half_gi", FT_BOOLEAN, 32, TFS(&tfs_yes_no),
        EXT_FLAG_HALF_GI, NULL, HFILL };

static header_field_info hfi_peekremote_extflags_full_gi THIS_HF_INIT =
      { "Full Guard Interval",     "peekremote.extflags.full_gi", FT_BOOLEAN, 32, TFS(&tfs_yes_no),
        EXT_FLAG_FULL_GI, NULL, HFILL };

static header_field_info hfi_peekremote_extflags_ampdu THIS_HF_INIT =
      { "AMPDU",     "peekremote.extflags.ampdu", FT_BOOLEAN, 32, TFS(&tfs_yes_no),
        EXT_FLAG_AMPDU, NULL, HFILL };

static header_field_info hfi_peekremote_extflags_amsdu THIS_HF_INIT =
      { "AMSDU",     "peekremote.extflags.amsdu", FT_BOOLEAN, 32, TFS(&tfs_yes_no),
        EXT_FLAG_AMSDU, NULL, HFILL };

static header_field_info hfi_peekremote_extflags_11ac THIS_HF_INIT =
      { "802.11ac",     "peekremote.extflags.11ac", FT_BOOLEAN, 32, TFS(&tfs_yes_no),
        EXT_FLAG_802_11ac, NULL, HFILL };

static header_field_info hfi_peekremote_extflags_future_use THIS_HF_INIT =
      { "MCS index used",     "peekremote.extflags.future_use", FT_BOOLEAN, 32, TFS(&tfs_yes_no),
        EXT_FLAG_MCS_INDEX_USED, NULL, HFILL };

static header_field_info hfi_peekremote_extflags_reserved THIS_HF_INIT =
      { "Reserved",     "peekremote.extflags.reserved", FT_UINT32, BASE_HEX, NULL,
        EXT_FLAGS_RESERVED, "Must be zero", HFILL };

/* XXX - are the numbers antenna numbers? */
static header_field_info hfi_peekremote_signal_1_dbm THIS_HF_INIT =
      { "Signal 1 [dBm]",     "peekremote.signal_1_dbm", FT_INT8, BASE_DEC, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_signal_2_dbm THIS_HF_INIT =
      { "Signal 2 [dBm]",     "peekremote.signal_2_dbm", FT_INT8, BASE_DEC, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_signal_3_dbm THIS_HF_INIT =
      { "Signal 3 [dBm]",     "peekremote.signal_3_dbm", FT_INT8, BASE_DEC, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_signal_4_dbm THIS_HF_INIT =
      { "Signal 4 [dBm]",     "peekremote.signal_4_dbm", FT_INT8, BASE_DEC, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_noise_1_dbm THIS_HF_INIT =
      { "Noise 1 [dBm]",     "peekremote.noise_1_dbm", FT_INT8, BASE_DEC, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_noise_2_dbm THIS_HF_INIT =
      { "Noise 2 [dBm]",     "peekremote.noise_2_dbm", FT_INT8, BASE_DEC, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_noise_3_dbm THIS_HF_INIT =
      { "Noise 3 [dBm]",     "peekremote.noise_3_dbm", FT_INT8, BASE_DEC, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_noise_4_dbm THIS_HF_INIT =
      { "Noise 4 [dBm]",     "peekremote.noise_4_dbm", FT_INT8, BASE_DEC, NULL,
        0x0, NULL, HFILL };

static expert_field ei_peekremote_unknown_header_version = EI_INIT;
static expert_field ei_peekremote_invalid_header_size = EI_INIT;

static gint ett_peekremote = -1;
static gint ett_peekremote_flags = -1;
static gint ett_peekremote_status = -1;
static gint ett_peekremote_extflags = -1;

static dissector_handle_t wlan_radio_handle;


static int
dissect_peekremote_extflags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
  proto_tree *extflags_tree;
  proto_item *ti_extflags;

  ti_extflags = proto_tree_add_item(tree, &hfi_peekremote_extflags, tvb, offset, 4, ENC_BIG_ENDIAN);
  extflags_tree = proto_item_add_subtree(ti_extflags, ett_peekremote_extflags);
  proto_tree_add_item(extflags_tree, &hfi_peekremote_extflags_20mhz_lower, tvb, offset, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(extflags_tree, &hfi_peekremote_extflags_20mhz_upper, tvb, offset, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(extflags_tree, &hfi_peekremote_extflags_40mhz, tvb, offset, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(extflags_tree, &hfi_peekremote_extflags_half_gi, tvb, offset, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(extflags_tree, &hfi_peekremote_extflags_full_gi, tvb, offset, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(extflags_tree, &hfi_peekremote_extflags_ampdu, tvb, offset, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(extflags_tree, &hfi_peekremote_extflags_amsdu, tvb, offset, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(extflags_tree, &hfi_peekremote_extflags_11ac, tvb, offset, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(extflags_tree, &hfi_peekremote_extflags_future_use, tvb, offset, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(extflags_tree, &hfi_peekremote_extflags_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);

  return 4;
}

static int
dissect_peekremote_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
  proto_tree *flags_tree;
  proto_item *ti_flags;

  ti_flags = proto_tree_add_item(tree, &hfi_peekremote_flags, tvb, offset, 1, ENC_NA);
  flags_tree = proto_item_add_subtree(ti_flags, ett_peekremote_flags);
  proto_tree_add_item(flags_tree, &hfi_peekremote_flags_control_frame, tvb, offset, 1, ENC_NA);
  proto_tree_add_item(flags_tree, &hfi_peekremote_flags_crc_error, tvb, offset, 1, ENC_NA);
  proto_tree_add_item(flags_tree, &hfi_peekremote_flags_frame_error, tvb, offset, 1, ENC_NA);
  proto_tree_add_item(flags_tree, &hfi_peekremote_flags_reserved, tvb, offset, 1, ENC_NA);

  return 1;
}

static int
dissect_peekremote_status(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
  proto_tree *status_tree;
  proto_item *ti_status;

  ti_status = proto_tree_add_item(tree, &hfi_peekremote_status, tvb, offset, 1, ENC_NA);
  status_tree = proto_item_add_subtree(ti_status, ett_peekremote_status);
  proto_tree_add_item(status_tree, &hfi_peekremote_status_protected, tvb, offset, 1, ENC_NA);
  proto_tree_add_item(status_tree, &hfi_peekremote_status_with_decrypt_error, tvb, offset, 1, ENC_NA);
  proto_tree_add_item(status_tree, &hfi_peekremote_status_with_short_preamble, tvb, offset, 1, ENC_NA);
  proto_tree_add_item(status_tree, &hfi_peekremote_status_reserved, tvb, offset, 1, ENC_NA);

  return 1;
}

static gboolean
dissect_peekremote_new(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *u _U_)
{
  static const guint8 magic[4] = { 0x00, 0xFF, 0xAB, 0xCD };
  int offset = 0;
  proto_tree *peekremote_tree = NULL;
  proto_item *ti = NULL;
  proto_item *ti_header_version, *ti_header_size;
  guint8 header_version;
  guint header_size;
  struct ieee_802_11_phdr phdr;
  guint32 extflags;
  guint16 frequency;
  guint16 mcs_index;
  tvbuff_t *next_tvb;

  if (tvb_memeql(tvb, 0, magic, 4) == -1) {
    /*
     * Not big enough to hold the magic number, or doesn't start
     * with the magic number.
     */
    return FALSE;
  }

  /* We don't have any 802.11 metadata yet. */
  memset(&phdr, 0, sizeof(phdr));
  phdr.fcs_len = 4; /* has an FCS */
  phdr.decrypted = FALSE;
  phdr.datapad = FALSE;
  phdr.phy = PHDR_802_11_PHY_UNKNOWN;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "PEEKREMOTE");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, hfi_peekremote, tvb, 0, -1, ENC_NA);
  peekremote_tree = proto_item_add_subtree(ti, ett_peekremote);

  proto_tree_add_item(peekremote_tree, &hfi_peekremote_magic_number, tvb, offset, 4,  ENC_BIG_ENDIAN);
  offset += 4;
  header_version = tvb_get_guint8(tvb, offset);
  ti_header_version = proto_tree_add_uint(peekremote_tree, &hfi_peekremote_header_version, tvb, offset, 1,  header_version);
  offset += 1;
  header_size = tvb_get_ntohl(tvb, offset);
  ti_header_size = proto_tree_add_uint(peekremote_tree, &hfi_peekremote_header_size, tvb, offset, 4, header_size);
  offset += 4;
  switch (header_version) {

  case 2:
    if (header_size != 55) {
      expert_add_info(pinfo, ti_header_size, &ei_peekremote_invalid_header_size);
      if (header_size > 9)
        offset += (header_size - 9);
    } else {
      proto_tree_add_item(peekremote_tree, &hfi_peekremote_type, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      mcs_index = tvb_get_ntohs(tvb, offset);
      proto_tree_add_item(peekremote_tree, &hfi_peekremote_mcs_index, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      phdr.has_channel = TRUE;
      phdr.channel = tvb_get_ntohs(tvb, offset);
      proto_tree_add_item(peekremote_tree, &hfi_peekremote_channel, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      frequency = tvb_get_ntohl(tvb, offset);
      if (frequency != 0) {
        phdr.has_frequency = TRUE;
        phdr.frequency = frequency;
      }
      proto_tree_add_item(peekremote_tree, &hfi_peekremote_frequency, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(peekremote_tree, &hfi_peekremote_band, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset +=4;
      extflags = tvb_get_ntohl(tvb, offset);
      if (extflags & EXT_FLAG_802_11ac) {
        guint i;
        phdr.phy = PHDR_802_11_PHY_11AC;
        /*
         * XXX - this probably has only one user, so only one MCS index
         * and only one NSS, but where's the NSS?
         */
        for (i = 0; i < 4; i++) {
          phdr.phy_info.info_11ac.nss[i] = 0;
        }
      } else {
        phdr.phy = PHDR_802_11_PHY_11N;
        phdr.phy_info.info_11n.has_mcs_index = TRUE;
        phdr.phy_info.info_11n.mcs_index = mcs_index;
      }
      offset += dissect_peekremote_extflags(tvb, pinfo, peekremote_tree, offset);
      phdr.has_signal_percent = TRUE;
      phdr.signal_percent = tvb_get_guint8(tvb, offset);
      proto_tree_add_item(peekremote_tree, &hfi_peekremote_signal_percent, tvb, offset, 1, ENC_NA);
      offset += 1;
      phdr.has_noise_percent = TRUE;
      phdr.noise_percent = tvb_get_guint8(tvb, offset);
      proto_tree_add_item(peekremote_tree, &hfi_peekremote_noise_percent, tvb, offset, 1, ENC_NA);
      offset += 1;
      phdr.has_signal_dbm = TRUE;
      phdr.signal_dbm = tvb_get_guint8(tvb, offset);
      proto_tree_add_item(peekremote_tree, &hfi_peekremote_signal_dbm, tvb, offset, 1, ENC_NA);
      offset += 1;
      phdr.has_noise_dbm = TRUE;
      phdr.noise_dbm = tvb_get_guint8(tvb, offset);
      proto_tree_add_item(peekremote_tree, &hfi_peekremote_noise_dbm, tvb, offset, 1, ENC_NA);
      offset += 1;
      proto_tree_add_item(peekremote_tree, &hfi_peekremote_signal_1_dbm, tvb, offset, 1, ENC_NA);
      offset += 1;
      proto_tree_add_item(peekremote_tree, &hfi_peekremote_signal_2_dbm, tvb, offset, 1, ENC_NA);
      offset += 1;
      proto_tree_add_item(peekremote_tree, &hfi_peekremote_signal_3_dbm, tvb, offset, 1, ENC_NA);
      offset += 1;
      proto_tree_add_item(peekremote_tree, &hfi_peekremote_signal_4_dbm, tvb, offset, 1, ENC_NA);
      offset += 1;
      proto_tree_add_item(peekremote_tree, &hfi_peekremote_noise_1_dbm, tvb, offset, 1, ENC_NA);
      offset += 1;
      proto_tree_add_item(peekremote_tree, &hfi_peekremote_noise_2_dbm, tvb, offset, 1, ENC_NA);
      offset += 1;
      proto_tree_add_item(peekremote_tree, &hfi_peekremote_noise_3_dbm, tvb, offset, 1, ENC_NA);
      offset += 1;
      proto_tree_add_item(peekremote_tree, &hfi_peekremote_noise_4_dbm, tvb, offset, 1, ENC_NA);
      offset += 1;
      proto_tree_add_item(peekremote_tree, &hfi_peekremote_packetlength, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      proto_tree_add_item(peekremote_tree, &hfi_peekremote_slicelength, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      offset += dissect_peekremote_flags(tvb, pinfo, peekremote_tree, offset);
      offset += dissect_peekremote_status(tvb, pinfo, peekremote_tree, offset);
      proto_tree_add_item(peekremote_tree, &hfi_peekremote_timestamp, tvb, offset, 8, ENC_BIG_ENDIAN);
      phdr.has_tsf_timestamp = TRUE;
      phdr.tsf_timestamp = tvb_get_ntoh64(tvb, offset);
      offset += 8;
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
  return TRUE;
}

static int
dissect_peekremote_legacy(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  tvbuff_t *next_tvb;
  proto_tree *peekremote_tree = NULL;
  proto_item *ti = NULL;
  struct ieee_802_11_phdr phdr;
  guint8 signal_percent;

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
    ti = proto_tree_add_item(tree, hfi_peekremote, tvb, 0, -1, ENC_NA);
    peekremote_tree = proto_item_add_subtree(ti, ett_peekremote);

    proto_tree_add_item(peekremote_tree, &hfi_peekremote_signal_dbm, tvb, 0, 1, ENC_NA);
    proto_tree_add_item(peekremote_tree, &hfi_peekremote_noise_dbm, tvb, 1, 1, ENC_NA);
    proto_tree_add_item(peekremote_tree, &hfi_peekremote_packetlength, tvb, 2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(peekremote_tree, &hfi_peekremote_slicelength, tvb, 4, 2, ENC_BIG_ENDIAN);
    dissect_peekremote_flags(tvb, pinfo, peekremote_tree, 6);
    dissect_peekremote_status(tvb, pinfo, peekremote_tree, 7);
    proto_tree_add_item(peekremote_tree, &hfi_peekremote_timestamp, tvb, 8, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(peekremote_tree, &hfi_peekremote_speed, tvb, 16, 1, ENC_NA);
    proto_tree_add_item(peekremote_tree, &hfi_peekremote_channel, tvb, 17, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(peekremote_tree, &hfi_peekremote_signal_percent, tvb, 18, 1, ENC_NA);
    proto_tree_add_item(peekremote_tree, &hfi_peekremote_noise_percent, tvb, 19, 1, ENC_NA);
  }
  signal_percent = tvb_get_guint8(tvb, 18);
  proto_item_set_end(ti, tvb, 20);
  next_tvb = tvb_new_subset_remaining(tvb, 20);
  /* When signal = 100 % and coming from ARUBA ERM, it is TX packet and there is no FCS */
  if (GPOINTER_TO_INT(data) == IS_ARUBA && signal_percent == 100) {
    phdr.fcs_len = 0; /* TX packet, no FCS */
  } else {
    phdr.fcs_len = 4; /* We have an FCS */
  }
  phdr.decrypted = FALSE;
  phdr.phy = PHDR_802_11_PHY_UNKNOWN;
  phdr.has_channel = TRUE;
  phdr.channel = tvb_get_guint8(tvb, 17);
  phdr.has_data_rate = TRUE;
  phdr.data_rate = tvb_get_guint8(tvb, 16);
  phdr.has_signal_percent = TRUE;
  phdr.signal_percent = tvb_get_guint8(tvb, 18);
  phdr.has_noise_percent = TRUE;
  phdr.noise_percent = tvb_get_guint8(tvb, 18);
  phdr.has_signal_dbm = TRUE;
  phdr.signal_dbm = tvb_get_guint8(tvb, 0);
  phdr.has_noise_dbm = TRUE;
  phdr.noise_dbm = tvb_get_guint8(tvb, 1);
  phdr.has_tsf_timestamp = TRUE;
  phdr.tsf_timestamp = tvb_get_ntoh64(tvb, 8);

  return 20 + call_dissector_with_data(wlan_radio_handle, next_tvb, pinfo, tree, &phdr);
}

void
proto_register_peekremote(void)
{
#ifndef HAVE_HFI_SECTION_INIT
  static header_field_info *hfi[] = {
    &hfi_peekremote_signal_dbm,
    &hfi_peekremote_noise_dbm,
    &hfi_peekremote_packetlength,
    &hfi_peekremote_slicelength,
    &hfi_peekremote_flags,
    &hfi_peekremote_flags_control_frame,
    &hfi_peekremote_flags_crc_error,
    &hfi_peekremote_flags_frame_error,
    &hfi_peekremote_flags_reserved,
    &hfi_peekremote_status,
    &hfi_peekremote_status_protected,
    &hfi_peekremote_status_with_decrypt_error,
    &hfi_peekremote_status_with_short_preamble,
    &hfi_peekremote_status_reserved,
    &hfi_peekremote_timestamp,
    &hfi_peekremote_speed,
    &hfi_peekremote_channel,
    &hfi_peekremote_magic_number,
    &hfi_peekremote_header_version,
    &hfi_peekremote_header_size,
    &hfi_peekremote_type,
    &hfi_peekremote_mcs_index,
    &hfi_peekremote_signal_percent,
    &hfi_peekremote_noise_percent,
    &hfi_peekremote_frequency,
    &hfi_peekremote_band,
    &hfi_peekremote_extflags,
    &hfi_peekremote_extflags_20mhz_lower,
    &hfi_peekremote_extflags_20mhz_upper,
    &hfi_peekremote_extflags_40mhz,
    &hfi_peekremote_extflags_half_gi,
    &hfi_peekremote_extflags_full_gi,
    &hfi_peekremote_extflags_ampdu,
    &hfi_peekremote_extflags_amsdu,
    &hfi_peekremote_extflags_11ac,
    &hfi_peekremote_extflags_future_use,
    &hfi_peekremote_extflags_reserved,
    &hfi_peekremote_signal_1_dbm,
    &hfi_peekremote_signal_2_dbm,
    &hfi_peekremote_signal_3_dbm,
    &hfi_peekremote_signal_4_dbm,
    &hfi_peekremote_noise_1_dbm,
    &hfi_peekremote_noise_2_dbm,
    &hfi_peekremote_noise_3_dbm,
    &hfi_peekremote_noise_4_dbm,
  };
#endif
  static gint *ett[] = {
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

  proto_peekremote = proto_register_protocol(
    "AiroPeek/OmniPeek encapsulated IEEE 802.11", "PEEKREMOTE", "peekremote");
  hfi_peekremote = proto_registrar_get_nth(proto_peekremote);
  proto_register_fields(proto_peekremote, hfi, array_length(hfi));
  proto_register_subtree_array(ett, array_length(ett));
  expert_peekremote = expert_register_protocol(proto_peekremote);
  expert_register_field_array(expert_peekremote, ei, array_length(ei));

  peekremote_handle = register_dissector("peekremote", dissect_peekremote_legacy, proto_peekremote);
}

void
proto_reg_handoff_peekremote(void)
{
  wlan_radio_handle = find_dissector_add_dependency("wlan_radio", proto_peekremote);

  dissector_add_uint("udp.port", 5000, peekremote_handle);

  heur_dissector_add("udp", dissect_peekremote_new, "OmniPeek Remote over UDP", "peekremote_udp", proto_peekremote, HEURISTIC_ENABLE);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
