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
#include <expert.h>

#include <wiretap/wtap.h>

void proto_register_peekremote(void);
void proto_reg_handoff_peekremote(void);

static int proto_peekremote;

/* hfi elements */
#define THIS_HF_INIT HFI_INIT(proto_peekremote)
static header_field_info *hfi_peekremote = NULL;

/* Common to both headers */
static header_field_info hfi_peekremote_channel THIS_HF_INIT =
      { "Channel",       "peekremote.channel", FT_UINT16, BASE_DEC, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_signal_noise_dbm THIS_HF_INIT =
      { "Signal/noise [dBm]",     "peekremote.signal_noise_dbm", FT_INT8, BASE_DEC, NULL,
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

static header_field_info hfi_peekremote_status THIS_HF_INIT =
      { "Status",     "peekremote.status", FT_UINT8, BASE_HEX, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_timestamp_secs THIS_HF_INIT =
      { "Timestamp (seconds)",       "peekremote.timestamp_secs", FT_UINT32, BASE_DEC, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_timestamp_usecs THIS_HF_INIT =
      { "Timestamp (microseconds)",       "peekremote.timestamp_usecs", FT_UINT32, BASE_DEC, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_data_rate THIS_HF_INIT =
      { "Data rate",         "peekremote.data_rate", FT_UINT16, BASE_DEC, NULL,
        0x0, NULL, HFILL };

/* Legacy header only */
static header_field_info hfi_peekremote_speed THIS_HF_INIT =
      { "Data rate [500kHz]", "peekremote.data_rate", FT_UINT8, BASE_DEC, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_signal THIS_HF_INIT =
      { "Signal",     "peekremote.signal", FT_UINT8, BASE_DEC, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_noise THIS_HF_INIT =
      { "Noise",     "peekremote.noise", FT_UINT8, BASE_DEC, NULL,
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
      { "Type",              "peekremote.type", FT_UINT32, BASE_DEC, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_frequency THIS_HF_INIT =
      { "Frequency",     "peekremote.frequency", FT_UINT32, BASE_DEC, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_band THIS_HF_INIT =
      { "Band",     "peekremote.band", FT_UINT32, BASE_DEC, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_flagsn THIS_HF_INIT =
      { "FlagsN",     "peekremote.flagsn", FT_UINT32, BASE_HEX, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_signal_percent THIS_HF_INIT =
      { "Signal [percent]",     "peekremote.signal_percent", FT_UINT8, BASE_DEC, NULL,
        0x0, NULL, HFILL };

static header_field_info hfi_peekremote_noise_percent THIS_HF_INIT =
      { "Noise [percent]",     "peekremote.noise_percent", FT_UINT8, BASE_DEC, NULL,
        0x0, NULL, HFILL };

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

static dissector_handle_t ieee80211_handle;

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
  tvbuff_t *next_tvb;

  if (tvb_memeql(tvb, 0, magic, 4) == -1) {
    /*
     * Not big enough to hold the magic number, or doesn't start
     * with the magic number.
     */
    return FALSE;
  }

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
      proto_tree_add_item(peekremote_tree, &hfi_peekremote_data_rate, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      proto_tree_add_item(peekremote_tree, &hfi_peekremote_channel, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      proto_tree_add_item(peekremote_tree, &hfi_peekremote_frequency, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(peekremote_tree, &hfi_peekremote_band, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(peekremote_tree, &hfi_peekremote_flagsn, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(peekremote_tree, &hfi_peekremote_signal_percent, tvb, offset, 1, ENC_NA);
      offset += 1;
      proto_tree_add_item(peekremote_tree, &hfi_peekremote_noise_percent, tvb, offset, 1, ENC_NA);
      offset += 1;
      proto_tree_add_item(peekremote_tree, &hfi_peekremote_signal_noise_dbm, tvb, offset, 1, ENC_NA);
      offset += 1;
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
      proto_tree_add_item(peekremote_tree, &hfi_peekremote_flags, tvb, offset, 1, ENC_NA);
      offset += 1;
      proto_tree_add_item(peekremote_tree, &hfi_peekremote_status, tvb, offset, 1, ENC_NA);
      offset += 1;
      proto_tree_add_item(peekremote_tree, &hfi_peekremote_timestamp_secs, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(peekremote_tree, &hfi_peekremote_timestamp_usecs, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
    }
    break;

  default:
    expert_add_info(pinfo, ti_header_size, &ei_peekremote_unknown_header_version);
    if (header_size > 9)
      offset += (header_size - 9);
    break;
  }

  next_tvb = tvb_new_subset_remaining(tvb, offset);
  pinfo->pseudo_header->ieee_802_11.fcs_len = 4;
  call_dissector(ieee80211_handle, next_tvb, pinfo, tree);
  return TRUE;
}

static int
dissect_peekremote_legacy(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *u)
{
  tvbuff_t *next_tvb;
  proto_tree *peekremote_tree = NULL;
  proto_item *ti = NULL;

  /*
   * Check whether this is peekremote-ng, and dissect it as such if it
   * is.
   */
  if (dissect_peekremote_new(tvb, pinfo, tree, u)) {
    /* Yup, it was peekremote-ng, and it's been dissected as such. */
    return tvb_length(tvb);
  }

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "PEEKREMOTE");
  col_clear(pinfo->cinfo, COL_INFO);

  if (tree) {
    ti = proto_tree_add_item(tree, hfi_peekremote, tvb, 0, -1, ENC_NA);
    peekremote_tree = proto_item_add_subtree(ti, ett_peekremote);

    proto_tree_add_item(peekremote_tree, &hfi_peekremote_signal_noise_dbm, tvb, 0, 1,  ENC_NA);
    proto_tree_add_item(peekremote_tree, &hfi_peekremote_noise_dbm, tvb, 1, 1,  ENC_NA);
    proto_tree_add_item(peekremote_tree, &hfi_peekremote_packetlength, tvb, 2, 2,  ENC_BIG_ENDIAN);
    proto_tree_add_item(peekremote_tree, &hfi_peekremote_slicelength, tvb, 4, 2,  ENC_BIG_ENDIAN);
    proto_tree_add_item(peekremote_tree, &hfi_peekremote_flags, tvb, 6, 1, ENC_NA);
    proto_tree_add_item(peekremote_tree, &hfi_peekremote_status, tvb, 7, 1, ENC_NA);
    proto_tree_add_item(peekremote_tree, &hfi_peekremote_timestamp_secs, tvb, 8, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(peekremote_tree, &hfi_peekremote_timestamp_usecs, tvb, 12, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(peekremote_tree, &hfi_peekremote_speed, tvb, 16, 1, ENC_NA);
    proto_tree_add_item(peekremote_tree, &hfi_peekremote_channel, tvb, 17, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(peekremote_tree, &hfi_peekremote_signal, tvb, 18, 1, ENC_NA);
    proto_tree_add_item(peekremote_tree, &hfi_peekremote_noise, tvb, 19, 1, ENC_NA);
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
    &hfi_peekremote_signal_noise_dbm,
    &hfi_peekremote_noise_dbm,
    &hfi_peekremote_packetlength,
    &hfi_peekremote_slicelength,
    &hfi_peekremote_flags,
    &hfi_peekremote_status,
    &hfi_peekremote_timestamp_secs,
    &hfi_peekremote_timestamp_usecs,
    &hfi_peekremote_speed,
    &hfi_peekremote_channel,
    &hfi_peekremote_signal,
    &hfi_peekremote_noise,
    &hfi_peekremote_magic_number,
    &hfi_peekremote_header_version,
    &hfi_peekremote_header_size,
    &hfi_peekremote_type,
    &hfi_peekremote_data_rate,
    &hfi_peekremote_frequency,
    &hfi_peekremote_band,
    &hfi_peekremote_flagsn,
    &hfi_peekremote_signal_percent,
    &hfi_peekremote_noise_percent,
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
}

void
proto_reg_handoff_peekremote(void)
{
  dissector_handle_t peekremote_handle;

  ieee80211_handle = find_dissector("wlan_datapad");

  peekremote_handle = new_create_dissector_handle(dissect_peekremote_legacy, proto_peekremote);
  dissector_add_uint("udp.port", 5000, peekremote_handle);

  heur_dissector_add("udp", dissect_peekremote_new, proto_peekremote);
}
