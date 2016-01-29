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

static dissector_handle_t wlan_radio_handle;
static dissector_handle_t ieee80211_handle;

static int proto_wlan_radio = -1;

/* ************************************************************************* */
/*                Header field info values for radio information             */
/* ************************************************************************* */
static int hf_wlan_radio_phy = -1;
static int hf_wlan_radio_11_fhss_hop_set = -1;
static int hf_wlan_radio_11_fhss_hop_pattern = -1;
static int hf_wlan_radio_11_fhss_hop_index = -1;
static int hf_wlan_radio_11a_channel_type = -1;
static int hf_wlan_radio_11a_turbo_type = -1;
static int hf_wlan_radio_11g_mode = -1;
static int hf_wlan_radio_11n_mcs_index = -1;
static int hf_wlan_radio_11n_bandwidth = -1;
static int hf_wlan_radio_11n_short_gi = -1;
static int hf_wlan_radio_11n_greenfield = -1;
static int hf_wlan_radio_11n_fec = -1;
static int hf_wlan_radio_11n_stbc_streams = -1;
static int hf_wlan_radio_11n_ness = -1;
static int hf_wlan_radio_11ac_stbc = -1;
static int hf_wlan_radio_11ac_txop_ps_not_allowed = -1;
static int hf_wlan_radio_11ac_short_gi = -1;
static int hf_wlan_radio_11ac_short_gi_nsym_disambig = -1;
static int hf_wlan_radio_11ac_ldpc_extra_ofdm_symbol = -1;
static int hf_wlan_radio_11ac_beamformed = -1;
static int hf_wlan_radio_11ac_bandwidth = -1;
static int hf_wlan_radio_11ac_user = -1;
static int hf_wlan_radio_11ac_nsts = -1;
static int hf_wlan_radio_11ac_mcs = -1;
static int hf_wlan_radio_11ac_nss = -1;
static int hf_wlan_radio_11ac_fec = -1;
static int hf_wlan_radio_11ac_gid = -1;
static int hf_wlan_radio_11ac_p_aid = -1;
static int hf_wlan_radio_data_rate = -1;
static int hf_wlan_radio_channel = -1;
static int hf_wlan_radio_frequency = -1;
static int hf_wlan_radio_short_preamble = -1;
static int hf_wlan_radio_signal_percent = -1;
static int hf_wlan_radio_signal_dbm = -1;
static int hf_wlan_radio_noise_percent = -1;
static int hf_wlan_radio_noise_dbm = -1;
static int hf_wlan_radio_timestamp = -1;
static int hf_wlan_last_part_of_a_mpdu = -1;
static int hf_wlan_a_mpdu_delim_crc_error = -1;
static int hf_wlan_a_mpdu_aggregate_id = -1;

static const value_string phy_vals[] = {
    { PHDR_802_11_PHY_11_FHSS,       "802.11 FHSS" },
    { PHDR_802_11_PHY_11_IR,         "802.11 IR" },
    { PHDR_802_11_PHY_11_DSSS,       "802.11 DSSS" },
    { PHDR_802_11_PHY_11B,           "802.11b" },
    { PHDR_802_11_PHY_11A,           "802.11a" },
    { PHDR_802_11_PHY_11G,           "802.11g" },
    { PHDR_802_11_PHY_11N,           "802.11n" },
    { PHDR_802_11_PHY_11AC,          "802.11ac" },
    { 0, NULL }
};

static const value_string channel_type_11a_vals[] = {
    { PHDR_802_11A_CHANNEL_TYPE_NORMAL,          "Normal" },
    { PHDR_802_11A_CHANNEL_TYPE_HALF_CLOCKED,    "Half-clocked" },
    { PHDR_802_11A_CHANNEL_TYPE_QUARTER_CLOCKED, "Quarter-clocked" },
    { 0, NULL }
};

static const value_string turbo_type_11a_vals[] = {
    { PHDR_802_11A_TURBO_TYPE_NORMAL,        "Non-turbo" },
    { PHDR_802_11A_TURBO_TYPE_TURBO,         "Turbo" },
    { PHDR_802_11A_TURBO_TYPE_DYNAMIC_TURBO, "Dynamic turbo" },
    { PHDR_802_11A_TURBO_TYPE_STATIC_TURBO,  "Static turbo" },
    { 0, NULL }
};

static const value_string mode_11g_vals[] = {
    { PHDR_802_11G_MODE_NORMAL,  "None" },
    { PHDR_802_11G_MODE_SUPER_G, "Super G" },
    { 0, NULL }
};

static const value_string bandwidth_vals[] = {
    { PHDR_802_11_BANDWIDTH_20_MHZ,  "20 MHz" },
    { PHDR_802_11_BANDWIDTH_40_MHZ,  "40 MHz" },
    { PHDR_802_11_BANDWIDTH_20_20L,  "20 MHz + 20 MHz lower" },
    { PHDR_802_11_BANDWIDTH_20_20U,  "20 MHz + 20 MHz upper" },
    { PHDR_802_11_BANDWIDTH_80_MHZ,  "80 MHz" },
    { PHDR_802_11_BANDWIDTH_40_40L,  "40 MHz + 40 MHz lower" },
    { PHDR_802_11_BANDWIDTH_40_40U,  "40 MHz + 40 MHz upper" },
    { PHDR_802_11_BANDWIDTH_20LL,    "20 MHz, channel 1/4" },
    { PHDR_802_11_BANDWIDTH_20LU,    "20 MHz, channel 2/4" },
    { PHDR_802_11_BANDWIDTH_20UL,    "20 MHz, channel 3/4" },
    { PHDR_802_11_BANDWIDTH_20UU,    "20 MHz, channel 4/4" },
    { PHDR_802_11_BANDWIDTH_160_MHZ, "160 MHz" },
    { PHDR_802_11_BANDWIDTH_80_80L,  "80 MHz + 80 MHz lower" },
    { PHDR_802_11_BANDWIDTH_80_80U,  "80 MHz + 80 MHz upper" },
    { PHDR_802_11_BANDWIDTH_40LL,    "40 MHz, channel 1/4" },
    { PHDR_802_11_BANDWIDTH_40LU,    "40 MHz, channel 2/4" },
    { PHDR_802_11_BANDWIDTH_40UL,    "40 MHz, channel 3/4" },
    { PHDR_802_11_BANDWIDTH_40UU,    "40 MHz, channel 4/4" },
    { PHDR_802_11_BANDWIDTH_20LLL,   "20 MHz, channel 1/8" },
    { PHDR_802_11_BANDWIDTH_20LLU,   "20 MHz, channel 2/8" },
    { PHDR_802_11_BANDWIDTH_20LUL,   "20 MHz, channel 3/8" },
    { PHDR_802_11_BANDWIDTH_20LUU,   "20 MHz, channel 4/8" },
    { PHDR_802_11_BANDWIDTH_20ULL,   "20 MHz, channel 5/8" },
    { PHDR_802_11_BANDWIDTH_20ULU,   "20 MHz, channel 6/8" },
    { PHDR_802_11_BANDWIDTH_20UUL,   "20 MHz, channel 7/8" },
    { PHDR_802_11_BANDWIDTH_20UUU,   "20 MHz, channel 8/8" },
    { 0, NULL }
};

static const value_string fec_vals[] = {
    { 0, "BEC" },
    { 1, "LDPC" },
    { 0, NULL }
};

/*
 * Lookup for the MCS index (0-76)
 * returning the number of data bits per symbol
 * assumes 52 subcarriers (20MHz)
 * symbols are 4us for long guard interval, 3.6us for short guard interval
 * Note: MCS 32 is special - only valid for 40Mhz channel.
 */
WS_DLL_PUBLIC_DEF const guint16 ieee80211_ht_Dbps[MAX_MCS_INDEX+1] = {
	/* MCS  0 - 1 stream */
	26, 52, 78, 104, 156, 208, 234, 260,

	/* MCS  8 - 2 stream */
	52, 104, 156, 208, 312, 416, 468, 520,

	/* MCS 16 - 3 stream */
	78, 156, 234, 312, 468, 624, 702, 780,

	/* MCS 24 - 4 stream */
	104, 208, 312, 416, 624, 832, 936, 1040,

	/* MCS 32 - 1 stream */
	12, /* only valid for 40Mhz - 11a/g DUP mode */

	/* MCS 33 - 2 stream */
	156, 208, 260, 234, 312, 390,

	/* MCS 39 - 3 stream */
	208, 260, 260, 312, 364, 364, 416, 312, 390, 390, 468, 546, 546, 624,

	/* MCS 53 - 4 stream */
	260, 312, 364, 312, 364, 416, 468, 416, 468, 520, 520, 572,
	390, 468, 546, 468, 546, 624, 702, 624, 702, 780, 780, 858
};

/*
 * Calculates data rate corresponding to a given 802.11n MCS index,
 * bandwidth, and guard interval.
 */
float ieee80211_htrate(int mcs_index, gboolean bandwidth, gboolean short_gi)
{
    return (float)(ieee80211_ht_Dbps[mcs_index] * (bandwidth ? 108 : 52) / 52.0 / (short_gi ? 3.6 : 4.0));
}


#define MAX_MCS_VHT_INDEX     9

/*
 * Maps a VHT bandwidth index to ieee80211_vhtinfo.rates index.
 */
static const int ieee80211_vht_bw2rate_index[] = {
  /*  20Mhz total */ 0,
  /*  40Mhz total */ 1, 0, 0,
  /*  80Mhz total */ 2, 1, 1, 0, 0, 0, 0,
  /* 160Mhz total */ 3, 2, 2, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0
};

struct mcs_vht_info {
  const char *modulation;
  const char *coding_rate;
  float data_bits_per_symbol; /* assuming 20MHz / 52 subcarriers */
};

static const struct mcs_vht_info ieee80211_vhtinfo[MAX_MCS_VHT_INDEX+1] = {
  /* MCS  0  */
  { "BPSK",  "1/2", 26 },
  /* MCS  1  */
  { "QPSK",  "1/2", 52 },
  /* MCS  2  */
  { "QPSK",  "3/4", 78 },
  /* MCS  3  */
  { "16-QAM", "1/2", 104 },
  /* MCS  4  */
  { "16-QAM", "3/4", 156 },
  /* MCS  5  */
  { "64-QAM", "2/3", 208 },
  /* MCS  6  */
  { "64-QAM", "3/4", 234 },
  /* MCS  7  */
  { "64-QAM", "5/6", 260 },
  /* MCS  8  */
  { "256-QAM", "3/4", 312 },
  /* MCS  9  */
  { "256-QAM", "5/6", (float)(1040/3.0) }
};

/* map a bandwidth index to the number of data subcarriers */
static const guint subcarriers[4] = { 52, 108, 234, 468 };

/*
 * Calculates data rate corresponding to a given 802.11ac MCS index,
 * bandwidth, and guard interval.
 */
static float ieee80211_vhtrate(int mcs_index, guint bandwidth_index, gboolean short_gi)
{
    return (float)(ieee80211_vhtinfo[mcs_index].data_bits_per_symbol * subcarriers[bandwidth_index] / (short_gi ? 3.6 : 4.0) / 52.0);
}

static gint ett_wlan_radio = -1;
static gint ett_wlan_radio_11ac_user = -1;

/*
 * Dissect 802.11 with a variable-length link-layer header and a pseudo-
 * header containing radio information.
 */
static int
dissect_wlan_radio (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void *data)
{
  struct ieee_802_11_phdr *phdr = (struct ieee_802_11_phdr *)data;
  proto_item *ti = NULL;
  proto_tree *radio_tree = NULL;
  float data_rate = 0.0f;
  gboolean have_data_rate = FALSE;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Radio");
  col_clear(pinfo->cinfo, COL_INFO);

  /* Calculate the data rate, if we have the necessary data */
  if (phdr->has_data_rate) {
    data_rate = phdr->data_rate * 0.5f;
    have_data_rate = TRUE;
  }

  if (phdr->has_signal_dbm) {
    col_add_fstr(pinfo->cinfo, COL_RSSI, "%d dBm", phdr->signal_dbm);
  } else if (phdr->has_signal_percent) {
    col_add_fstr(pinfo->cinfo, COL_RSSI, "%u%%", phdr->signal_percent);
  }

  if (tree) {
    ti = proto_tree_add_item(tree, proto_wlan_radio, tvb, 0, 0, ENC_NA);
    radio_tree = proto_item_add_subtree (ti, ett_wlan_radio);

    if (phdr->phy != PHDR_802_11_PHY_UNKNOWN) {
      proto_tree_add_uint(radio_tree, hf_wlan_radio_phy, tvb, 0, 0,
               phdr->phy);

      switch (phdr->phy) {

      case PHDR_802_11_PHY_11_FHSS:
        if (phdr->phy_info.info_11_fhss.has_hop_set) {
          proto_tree_add_uint(radio_tree, hf_wlan_radio_11_fhss_hop_set, tvb, 0, 0,
                   phdr->phy_info.info_11_fhss.hop_set);
        }
        if (phdr->phy_info.info_11_fhss.has_hop_pattern) {
          proto_tree_add_uint(radio_tree, hf_wlan_radio_11_fhss_hop_pattern, tvb, 0, 0,
                   phdr->phy_info.info_11_fhss.hop_pattern);
        }
        if (phdr->phy_info.info_11_fhss.has_hop_index) {
          proto_tree_add_uint(radio_tree, hf_wlan_radio_11_fhss_hop_index, tvb, 0, 0,
                   phdr->phy_info.info_11_fhss.hop_index);
        }
        break;

      case PHDR_802_11_PHY_11B:
        if (phdr->phy_info.info_11b.has_short_preamble) {
          proto_tree_add_boolean(radio_tree, hf_wlan_radio_short_preamble, tvb, 0, 0,
                   phdr->phy_info.info_11b.short_preamble);
        }
        break;

      case PHDR_802_11_PHY_11A:
        if (phdr->phy_info.info_11a.has_channel_type) {
          proto_tree_add_uint(radio_tree, hf_wlan_radio_11a_channel_type, tvb, 0, 0,
                   phdr->phy_info.info_11a.channel_type);
        }
        if (phdr->phy_info.info_11a.has_turbo_type) {
          proto_tree_add_uint(radio_tree, hf_wlan_radio_11a_turbo_type, tvb, 0, 0,
                   phdr->phy_info.info_11a.turbo_type);
        }
        break;

      case PHDR_802_11_PHY_11G:
        if (phdr->phy_info.info_11g.has_short_preamble) {
          proto_tree_add_boolean(radio_tree, hf_wlan_radio_short_preamble, tvb, 0, 0,
                   phdr->phy_info.info_11g.short_preamble);
        }
        if (phdr->phy_info.info_11g.has_mode) {
          proto_tree_add_uint(radio_tree, hf_wlan_radio_11g_mode, tvb, 0, 0,
                   phdr->phy_info.info_11g.mode);
        }
        break;

      case PHDR_802_11_PHY_11N:
        {
          guint bandwidth_40;

          if (phdr->phy_info.info_11n.has_mcs_index) {
            proto_tree_add_uint(radio_tree, hf_wlan_radio_11n_mcs_index, tvb, 0, 0,
                     phdr->phy_info.info_11n.mcs_index);
          }

          if (phdr->phy_info.info_11n.has_bandwidth) {
            proto_tree_add_uint(radio_tree, hf_wlan_radio_11n_bandwidth, tvb, 0, 0,
                     phdr->phy_info.info_11n.bandwidth);
          }

          if (phdr->phy_info.info_11n.has_short_gi) {
            proto_tree_add_boolean(radio_tree, hf_wlan_radio_11n_short_gi, tvb, 0, 0,
                     phdr->phy_info.info_11n.short_gi);
          }

          if (phdr->phy_info.info_11n.has_greenfield) {
            proto_tree_add_boolean(radio_tree, hf_wlan_radio_11n_greenfield, tvb, 0, 0,
                     phdr->phy_info.info_11n.greenfield);
          }

          if (phdr->phy_info.info_11n.has_fec) {
            proto_tree_add_uint(radio_tree, hf_wlan_radio_11n_fec, tvb, 0, 0,
                     phdr->phy_info.info_11n.fec);
          }

          if (phdr->phy_info.info_11n.has_stbc_streams) {
            proto_tree_add_uint(radio_tree, hf_wlan_radio_11n_stbc_streams, tvb, 0, 0,
                     phdr->phy_info.info_11n.stbc_streams);
          }

          if (phdr->phy_info.info_11n.has_ness) {
            proto_tree_add_uint(radio_tree, hf_wlan_radio_11n_ness, tvb, 0, 0,
                     phdr->phy_info.info_11n.ness);
          }

          /*
           * If we have all the fields needed to look up the data rate,
           * do so.
           */
          if (phdr->phy_info.info_11n.has_mcs_index &&
              phdr->phy_info.info_11n.has_bandwidth &&
              phdr->phy_info.info_11n.has_short_gi) {
            bandwidth_40 =
              (phdr->phy_info.info_11n.bandwidth == PHDR_802_11_BANDWIDTH_40_MHZ) ?
               1 : 0;
            if (phdr->phy_info.info_11n.mcs_index < MAX_MCS_INDEX) {
              data_rate = ieee80211_htrate(phdr->phy_info.info_11n.mcs_index, bandwidth_40, phdr->phy_info.info_11n.short_gi);
              have_data_rate = TRUE;
            }
          }
        }
        break;

      case PHDR_802_11_PHY_11AC:
        {
          gboolean can_calculate_rate;
          guint bandwidth = 0;
          guint i;

          if (phdr->phy_info.info_11ac.has_stbc) {
            proto_tree_add_boolean(radio_tree, hf_wlan_radio_11ac_stbc, tvb, 0, 0,
                     phdr->phy_info.info_11ac.stbc);
          }

          if (phdr->phy_info.info_11ac.has_txop_ps_not_allowed) {
            proto_tree_add_boolean(radio_tree, hf_wlan_radio_11ac_txop_ps_not_allowed, tvb, 0, 0,
                     phdr->phy_info.info_11ac.txop_ps_not_allowed);
          }

          if (phdr->phy_info.info_11ac.has_short_gi) {
            can_calculate_rate = TRUE;  /* well, if we also have the bandwidth */
            proto_tree_add_boolean(radio_tree, hf_wlan_radio_11ac_short_gi, tvb, 0, 0,
                     phdr->phy_info.info_11ac.short_gi);
          } else {
            can_calculate_rate = FALSE; /* unknown GI length */
          }

          if (phdr->phy_info.info_11ac.has_short_gi_nsym_disambig) {
            proto_tree_add_boolean(radio_tree, hf_wlan_radio_11ac_short_gi_nsym_disambig, tvb, 0, 0,
                     phdr->phy_info.info_11ac.short_gi_nsym_disambig);
          }

          if (phdr->phy_info.info_11ac.has_ldpc_extra_ofdm_symbol) {
            proto_tree_add_boolean(radio_tree, hf_wlan_radio_11ac_ldpc_extra_ofdm_symbol, tvb, 0, 0,
                     phdr->phy_info.info_11ac.ldpc_extra_ofdm_symbol);
          }

          if (phdr->phy_info.info_11ac.has_beamformed) {
            proto_tree_add_boolean(radio_tree, hf_wlan_radio_11ac_beamformed, tvb, 0, 0,
                     phdr->phy_info.info_11ac.beamformed);
          }

          if (phdr->phy_info.info_11ac.has_bandwidth) {
            if (phdr->phy_info.info_11ac.bandwidth < G_N_ELEMENTS(ieee80211_vht_bw2rate_index))
              bandwidth = ieee80211_vht_bw2rate_index[phdr->phy_info.info_11ac.bandwidth];
            else
              can_calculate_rate = FALSE; /* unknown bandwidth */
            proto_tree_add_uint(radio_tree, hf_wlan_radio_11ac_bandwidth, tvb, 0, 0,
                     phdr->phy_info.info_11ac.bandwidth);
          } else {
            can_calculate_rate = FALSE;   /* no bandwidth */
          }

          for (i = 0; i < 4; i++) {

            if (phdr->phy_info.info_11ac.nss[i] != 0) {
              proto_item *it;
              proto_tree *user_tree;

              it = proto_tree_add_item(radio_tree, hf_wlan_radio_11ac_user, tvb, 0, 0, ENC_NA);
              proto_item_append_text(it, " %d: MCS %u", i, phdr->phy_info.info_11ac.mcs[i]);
              user_tree = proto_item_add_subtree(it, ett_wlan_radio_11ac_user);

              it = proto_tree_add_uint(user_tree, hf_wlan_radio_11ac_mcs, tvb, 0, 0,
                      phdr->phy_info.info_11ac.mcs[i]);
              if (phdr->phy_info.info_11ac.mcs[i] > MAX_MCS_VHT_INDEX) {
                proto_item_append_text(it, " (invalid)");
              } else {
                proto_item_append_text(it, " (%s %s)",
                  ieee80211_vhtinfo[phdr->phy_info.info_11ac.mcs[i]].modulation,
                  ieee80211_vhtinfo[phdr->phy_info.info_11ac.mcs[i]].coding_rate);
              }

              proto_tree_add_uint(user_tree, hf_wlan_radio_11ac_nss, tvb, 0, 0,
                       phdr->phy_info.info_11ac.nss[i]);
              /*
               * If we don't know whether space-time block coding is being
               * used, we don't know the number of space-time streams.
               */
              if (phdr->phy_info.info_11ac.has_stbc) {
                guint nsts;

                if (phdr->phy_info.info_11ac.stbc)
                  nsts = 2 * phdr->phy_info.info_11ac.nss[i];
                else
                  nsts = phdr->phy_info.info_11ac.nss[i];
                proto_tree_add_uint(user_tree, hf_wlan_radio_11ac_nsts, tvb, 0, 0,
                       nsts);
              }
              if (phdr->phy_info.info_11ac.has_fec) {
                  proto_tree_add_uint(user_tree, hf_wlan_radio_11ac_fec, tvb, 0, 0,
                           (phdr->phy_info.info_11ac.fec >> i) & 0x01);
              }

              /*
               * If we can calculate the data rate for this user, do so.
               */
              if (can_calculate_rate && phdr->phy_info.info_11ac.mcs[i] <= MAX_MCS_VHT_INDEX) {
                data_rate = ieee80211_vhtrate(phdr->phy_info.info_11ac.mcs[i], bandwidth, phdr->phy_info.info_11ac.short_gi) * phdr->phy_info.info_11ac.nss[i];
                if (data_rate != 0.0f) {
                  proto_tree_add_float_format_value(user_tree, hf_wlan_radio_data_rate, tvb, 0, 0,
                        data_rate,
                        "%.1f Mb/s",
                       data_rate);
                }
              }
            }
          }

          if (phdr->phy_info.info_11ac.has_group_id) {
            proto_tree_add_uint(radio_tree, hf_wlan_radio_11ac_gid, tvb, 0, 0,
                     phdr->phy_info.info_11ac.group_id);
          }

          if (phdr->phy_info.info_11ac.has_partial_aid) {
            proto_tree_add_uint(radio_tree, hf_wlan_radio_11ac_p_aid, tvb, 0, 0,
                     phdr->phy_info.info_11ac.partial_aid);
          }
        }
        break;
      }
    }

    if (have_data_rate) {
      col_add_fstr(pinfo->cinfo, COL_TX_RATE, "%.1f", data_rate);
      proto_tree_add_float_format_value(radio_tree, hf_wlan_radio_data_rate, tvb, 0, 0,
               data_rate,
               "%.1f Mb/s",
               data_rate);
    }

    if (phdr->has_channel) {
      col_add_fstr(pinfo->cinfo, COL_FREQ_CHAN, "%u", phdr->channel);
      proto_tree_add_uint(radio_tree, hf_wlan_radio_channel, tvb, 0, 0,
              phdr->channel);
    }

    if (phdr->has_frequency) {
      col_add_fstr(pinfo->cinfo, COL_FREQ_CHAN, "%u MHz", phdr->frequency);
      proto_tree_add_uint_format_value(radio_tree, hf_wlan_radio_frequency, tvb, 0, 0,
              phdr->frequency,
              "%u MHz",
              phdr->frequency);
    }

    if (phdr->has_signal_percent) {
      col_add_fstr(pinfo->cinfo, COL_RSSI, "%u%%", phdr->signal_percent);
      proto_tree_add_uint_format_value(radio_tree, hf_wlan_radio_signal_percent, tvb, 0, 0,
              phdr->signal_percent,
              "%u%%",
              phdr->signal_percent);
    }

    if (phdr->has_signal_dbm) {
      col_add_fstr(pinfo->cinfo, COL_RSSI, "%d dBm", phdr->signal_dbm);
      proto_tree_add_int_format_value(radio_tree, hf_wlan_radio_signal_dbm, tvb, 0, 0,
              phdr->signal_dbm,
              "%d dBm",
              phdr->signal_dbm);
    }

    if (phdr->has_noise_percent) {
      proto_tree_add_uint_format_value(radio_tree, hf_wlan_radio_noise_percent, tvb, 0, 0,
              phdr->noise_percent,
              "%u%%",
              phdr->noise_percent);
    }

    if (phdr->has_noise_dbm) {
      proto_tree_add_int_format_value(radio_tree, hf_wlan_radio_noise_dbm, tvb, 0, 0,
              phdr->noise_dbm,
              "%d dBm",
              phdr->noise_dbm);
    }

    if (phdr->has_tsf_timestamp) {
      proto_tree_add_uint64(radio_tree, hf_wlan_radio_timestamp, tvb, 0, 0,
              phdr->tsf_timestamp);
    }
    if (phdr->has_aggregate_info) {
      proto_tree_add_boolean(radio_tree, hf_wlan_last_part_of_a_mpdu, tvb, 0, 0,
              (phdr->aggregate_flags & PHDR_802_11_LAST_PART_OF_A_MPDU) ?
               TRUE : FALSE);
      proto_tree_add_boolean(radio_tree, hf_wlan_a_mpdu_delim_crc_error, tvb, 0, 0,
              (phdr->aggregate_flags & PHDR_802_11_A_MPDU_DELIM_CRC_ERROR) ?
               TRUE : FALSE);
      proto_tree_add_uint(radio_tree, hf_wlan_a_mpdu_aggregate_id, tvb, 0, 0,
              phdr->aggregate_id);
    }
  }

  /* dissect the 802.11 packet next */
  return call_dissector_with_data(ieee80211_handle, tvb, pinfo, tree, data);
}

static hf_register_info hf_wlan_radio[] = {
    {&hf_wlan_radio_phy,
     {"PHY type", "wlan_radio.phy", FT_UINT32, BASE_DEC, VALS(phy_vals), 0,
      NULL, HFILL }},

    {&hf_wlan_radio_11_fhss_hop_set,
     {"Hop set", "wlan_radio.fhss.hop_set", FT_UINT8, BASE_HEX, NULL, 0,
      NULL, HFILL }},

    {&hf_wlan_radio_11_fhss_hop_pattern,
     {"Hop pattern", "wlan_radio.fhss.hop_pattern", FT_UINT8, BASE_HEX, NULL, 0,
      NULL, HFILL }},

    {&hf_wlan_radio_11_fhss_hop_index,
     {"Hop index", "wlan_radio.fhss.hop_index", FT_UINT8, BASE_HEX, NULL, 0,
      NULL, HFILL }},

    {&hf_wlan_radio_11a_channel_type,
     {"Channel type", "wlan_radio.11a.channel_type", FT_UINT32, BASE_DEC, VALS(channel_type_11a_vals), 0,
      NULL, HFILL }},

    {&hf_wlan_radio_11a_turbo_type,
     {"Turbo type", "wlan_radio.11a.turbo_type", FT_UINT32, BASE_DEC, VALS(turbo_type_11a_vals), 0,
      NULL, HFILL }},

    {&hf_wlan_radio_11g_mode,
     {"Proprietary mode", "wlan_radio.11g.mode", FT_UINT32, BASE_DEC, VALS(mode_11g_vals), 0,
      NULL, HFILL }},

    {&hf_wlan_radio_11n_mcs_index,
     {"MCS index", "wlan_radio.11n.mcs_index", FT_UINT32, BASE_DEC, NULL, 0,
      "Modulation and Coding Scheme index", HFILL }},

    {&hf_wlan_radio_11n_bandwidth,
     {"Bandwidth", "wlan_radio.11n.bandwidth", FT_UINT32, BASE_DEC, VALS(bandwidth_vals), 0,
      NULL, HFILL }},

    {&hf_wlan_radio_11n_short_gi,
     {"Short GI", "wlan_radio.11n.short_gi", FT_BOOLEAN, 0, NULL, 0,
      NULL, HFILL }},

    {&hf_wlan_radio_11n_greenfield,
     {"Greenfield", "wlan_radio.11n.greenfield", FT_BOOLEAN, BASE_NONE, NULL, 0,
      NULL, HFILL }},

    {&hf_wlan_radio_11n_fec,
     {"FEC", "wlan_radio.11n.fec", FT_UINT32, BASE_DEC, VALS(fec_vals), 0,
      NULL, HFILL }},

    {&hf_wlan_radio_11n_stbc_streams,
     {"Number of STBC streams", "wlan_radio.11n.stbc_streams", FT_UINT32, BASE_DEC, NULL, 0,
      NULL, HFILL }},

    {&hf_wlan_radio_11n_ness,
     {"Number of extension spatial streams", "wlan_radio.11n.ness", FT_UINT32, BASE_DEC, NULL, 0,
      NULL, HFILL }},

    {&hf_wlan_radio_11ac_stbc,
     {"STBC", "wlan_radio.11ac.stbc", FT_BOOLEAN, 0, TFS(&tfs_on_off), 0x0,
      "Space Time Block Coding flag", HFILL }},

    {&hf_wlan_radio_11ac_txop_ps_not_allowed,
     {"TXOP_PS_NOT_ALLOWED", "wlan_radio_11ac.txop_ps_not_allowed", FT_BOOLEAN, 0, NULL, 0x0,
      "Flag indicating whether STAs may doze during TXOP", HFILL }},

    {&hf_wlan_radio_11ac_short_gi,
     {"Short GI", "wlan_radio.11ac.short_gi", FT_BOOLEAN, 0, NULL, 0,
      NULL, HFILL }},

    {&hf_wlan_radio_11ac_short_gi_nsym_disambig,
     {"Short GI Nsym disambiguation", "wlan_radio.11ac.short_gi_nsym_disambig", FT_BOOLEAN, 0, NULL, 0x0,
      "Short Guard Interval Nsym disambiguation", HFILL }},

    {&hf_wlan_radio_11ac_ldpc_extra_ofdm_symbol,
     {"LDPC extra OFDM symbol", "wlan_radio.11ac.ldpc_extra_ofdm_symbol", FT_BOOLEAN, 0, NULL, 0x0,
      NULL, HFILL }},

    {&hf_wlan_radio_11ac_beamformed,
     {"Beamformed", "wlan_radio.11ac.beamformed", FT_BOOLEAN, 0, NULL, 0x0,
      NULL, HFILL }},

    {&hf_wlan_radio_11ac_bandwidth,
     {"Bandwidth", "wlan_radio.11ac.bandwidth", FT_UINT32, BASE_DEC, VALS(bandwidth_vals), 0,
      NULL, HFILL }},

    {&hf_wlan_radio_11ac_user,
     {"User", "wlan_radio.11ac.user", FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

    {&hf_wlan_radio_11ac_nsts,
     {"Space-time streams", "wlan_radio.11ac.nsts", FT_UINT32, BASE_DEC, NULL, 0x0,
      "Number of Space-time streams", HFILL }},

    {&hf_wlan_radio_11ac_mcs,
     {"MCS index", "wlan_radio.11ac.mcs", FT_UINT32, BASE_DEC, NULL, 0x0,
      "Modulation and Coding Scheme index", HFILL }},

    {&hf_wlan_radio_11ac_nss,
     {"Spatial streams", "wlan_radio.11ac.nss", FT_UINT32, BASE_DEC, NULL, 0x0,
      "Number of spatial streams", HFILL }},

    {&hf_wlan_radio_11ac_fec,
     {"FEC", "wlan_radio.11ac.fec", FT_UINT32, BASE_DEC, VALS(fec_vals), 0x0,
      "Type of FEC", HFILL }},

    {&hf_wlan_radio_11ac_gid,
     {"Group Id", "wlan_radio.11ac.gid", FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }},

    {&hf_wlan_radio_11ac_p_aid,
     {"Partial AID", "wlan_radio.11ac.paid", FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL }},

    {&hf_wlan_radio_data_rate,
     {"Data rate", "wlan_radio.data_rate", FT_FLOAT, BASE_NONE, NULL, 0,
      "Speed at which this frame was sent/received", HFILL }},

    {&hf_wlan_radio_channel,
     {"Channel", "wlan_radio.channel", FT_UINT32, BASE_DEC, NULL, 0,
      "802.11 channel number that this frame was sent/received on", HFILL }},

    {&hf_wlan_radio_frequency,
     {"Frequency", "wlan_radio.frequency", FT_UINT16, BASE_DEC, NULL, 0,
      "Center frequency of the 802.11 channel that this frame was sent/received on", HFILL }},

    {&hf_wlan_radio_short_preamble,
     {"Short preamble", "wlan_radio.short_preamble", FT_BOOLEAN, BASE_NONE, NULL, 0,
      NULL, HFILL }},

    {&hf_wlan_radio_signal_percent,
     {"Signal strength (percentage)", "wlan_radio.signal_percentage", FT_UINT32, BASE_DEC, NULL, 0,
      "Signal strength, as percentage of maximum RSSI", HFILL }},

    {&hf_wlan_radio_signal_dbm,
     {"Signal strength (dBm)", "wlan_radio.signal_dbm", FT_INT8, BASE_DEC, NULL, 0,
      NULL, HFILL }},

    {&hf_wlan_radio_noise_percent,
     {"Noise level (percentage)", "wlan_radio.noise_percentage", FT_UINT32, BASE_DEC, NULL, 0,
      NULL, HFILL }},

    {&hf_wlan_radio_noise_dbm,
     {"Noise level (dBm)", "wlan_radio.noise_dbm", FT_INT8, BASE_DEC, NULL, 0,
      NULL, HFILL }},

    {&hf_wlan_radio_timestamp,
     {"TSF timestamp", "wlan_radio.timestamp", FT_UINT64, BASE_DEC, NULL, 0,
      NULL, HFILL }},

    {&hf_wlan_last_part_of_a_mpdu,
     {"Last part of an A-MPDU", "wlan_radio.last_part_of_an_ampdu", FT_BOOLEAN, 0, NULL, 0,
      "This is the last part of an A-MPDU", HFILL }},

    {&hf_wlan_a_mpdu_delim_crc_error,
     {"A-MPDU delimiter CRC error", "wlan_radio.a_mpdu_delim_crc_error", FT_BOOLEAN, 0, NULL, 0,
      NULL, HFILL }},

    {&hf_wlan_a_mpdu_aggregate_id,
     {"A-MPDU aggregate ID", "wlan_radio.a_mpdu_aggregate_id", FT_UINT32, BASE_DEC, NULL, 0,
      NULL, HFILL }},
};

static gint *tree_array[] = {
  &ett_wlan_radio,
  &ett_wlan_radio_11ac_user
};

void proto_register_ieee80211_radio(void)
{
  proto_wlan_radio = proto_register_protocol("802.11 radio information", "802.11 Radio",
                                             "wlan_radio");
  proto_register_field_array(proto_wlan_radio, hf_wlan_radio, array_length(hf_wlan_radio));
  proto_register_subtree_array(tree_array, array_length(tree_array));

  wlan_radio_handle = register_dissector("wlan_radio", dissect_wlan_radio, proto_wlan_radio);
}

void proto_reg_handoff_ieee80211_radio(void)
{
  /* Register handoff to radio-header dissectors */
  dissector_add_uint("wtap_encap", WTAP_ENCAP_IEEE_802_11_WITH_RADIO,
                     wlan_radio_handle);
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
