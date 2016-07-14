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
#include <epan/expert.h>
#include <wiretap/wtap.h>

#include "packet-ieee80211.h"
#include "math.h"

void proto_register_ieee80211_radio(void);
void proto_reg_handoff_ieee80211_radio(void);

static dissector_handle_t wlan_radio_handle;
static dissector_handle_t wlan_noqos_radio_handle;
static dissector_handle_t ieee80211_handle;
static dissector_handle_t ieee80211_noqos_handle;

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
static int hf_wlan_radio_duration = -1;
static int hf_wlan_radio_preamble = -1;


static expert_field ei_wlan_radio_assumed_short_preamble = EI_INIT;
static expert_field ei_wlan_radio_assumed_non_greenfield = EI_INIT;
static expert_field ei_wlan_radio_assumed_no_stbc = EI_INIT;
static expert_field ei_wlan_radio_assumed_no_extension_streams = EI_INIT;
static expert_field ei_wlan_radio_assumed_bcc_fec = EI_INIT;

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

static const guint8 ieee80211_ht_streams[MAX_MCS_INDEX+1] = {
       1,1,1,1,1,1,1,1,2,2,2,2,2,2,2,2,3,3,3,3,3,3,3,3,4,4,4,4,4,4,4,4,
       1,2,2,2,2,2,2,3,3,3,3,3,3,3,3,3,3,3,3,3,3,4,4,4,4,4,4,4,4,4,4,4,
       4,4,4,4,4,4,4,4,4,4,4,4,4
};

static const guint8 ieee80211_ht_Nes[MAX_MCS_INDEX+1] = {
       1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,
       1,1,1,1,1,2,2,2, 1,1,1,1,2,2,2,2,
       1,
       1,1,1,1,1,1,
       1,1,1,1,1,1,1,1,1,1,1,1,1,1,
       1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,2,2,2,2,2,2,2
};


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

#define MAX_VHT_NSS             8

struct mcs_vht_valid {
    gboolean valid[4][MAX_VHT_NSS]; /* indexed by bandwidth and NSS-1 */
};

static const struct mcs_vht_valid ieee80211_vhtvalid[MAX_MCS_VHT_INDEX+1] = {
        /* MCS  0  */
        {
            {   /* 20 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
                /* 40 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
                /* 80 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
                /* 160 Mhz */ { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
            }
        },
        /* MCS  1  */
        {
            {   /* 20 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
                /* 40 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
                /* 80 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
                /* 160 Mhz */ { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
            }
        },
        /* MCS  2  */
        {
            {   /* 20 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
                /* 40 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
                /* 80 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
                /* 160 Mhz */ { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
            }
        },
        /* MCS  3  */
        {
            {   /* 20 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
                /* 40 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
                /* 80 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
                /* 160 Mhz */ { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
            }
        },
        /* MCS  4  */
        {
            {   /* 20 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
                /* 40 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
                /* 80 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
                /* 160 Mhz */ { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
            }
        },
        /* MCS  5  */
        {
            {   /* 20 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
                /* 40 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
                /* 80 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
                /* 160 Mhz */ { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
            }
        },
        /* MCS  6  */
        {
            {   /* 20 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
                /* 40 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
                /* 80 Mhz */  { TRUE,  TRUE,  FALSE, TRUE,  TRUE,  TRUE,  FALSE, TRUE },
                /* 160 Mhz */ { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
            }
        },
        /* MCS  7  */
        {
            {   /* 20 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
                /* 40 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
                /* 80 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
                /* 160 Mhz */ { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
            }
        },
        /* MCS  8  */
        {
            {   /* 20 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
                /* 40 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
                /* 80 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
                /* 160 Mhz */ { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
            }
        },
        /* MCS  9  */
        {
            {   /* 20 Mhz */  { FALSE, FALSE, TRUE,  FALSE, FALSE, TRUE,  FALSE, FALSE },
                /* 40 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
                /* 80 Mhz */  { TRUE,  TRUE,  TRUE,  TRUE,  TRUE,  FALSE, TRUE,  TRUE },
                /* 160 Mhz */ { TRUE,  TRUE,  FALSE, TRUE,  TRUE,  TRUE,  TRUE,  TRUE },
            }
        }
};

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
static gint ett_wlan_radio_duration = -1;

/*
 * Dissect 802.11 pseudo-header containing radio information.
 */
static void
dissect_wlan_radio_phdr (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void *data)
{
  struct ieee_802_11_phdr *phdr = (struct ieee_802_11_phdr *)data;
  proto_item *ti = NULL;
  proto_tree *radio_tree = NULL;
  float data_rate = 0.0f;
  gboolean have_data_rate = FALSE;
  gboolean has_short_preamble = FALSE;
  gboolean short_preamble = 1;

  guint frame_length = tvb_reported_length(tvb); /* length of 802.11 frame data */

  /* durations in microseconds */
  guint preamble = 0; /* duration of plcp */
  guint duration = 0; /* duration of whole frame (plcp + mac data + any trailing parts) */

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
      {
        struct ieee_802_11_fhss *info_fhss = &phdr->phy_info.info_11_fhss;

        if (info_fhss->has_hop_set) {
          proto_tree_add_uint(radio_tree, hf_wlan_radio_11_fhss_hop_set, tvb, 0, 0,
                   info_fhss->hop_set);
        }
        if (info_fhss->has_hop_pattern) {
          proto_tree_add_uint(radio_tree, hf_wlan_radio_11_fhss_hop_pattern, tvb, 0, 0,
                   info_fhss->hop_pattern);
        }
        if (info_fhss->has_hop_index) {
          proto_tree_add_uint(radio_tree, hf_wlan_radio_11_fhss_hop_index, tvb, 0, 0,
                   info_fhss->hop_index);
        }
        break;
      }

      case PHDR_802_11_PHY_11B:
      {
        struct ieee_802_11b *info_b = &phdr->phy_info.info_11b;

        has_short_preamble = info_b->has_short_preamble;
        short_preamble = info_b->short_preamble;

        if (has_short_preamble) {
          proto_tree_add_boolean(radio_tree, hf_wlan_radio_short_preamble, tvb, 0, 0,
                   short_preamble);
        }
        break;
      }

      case PHDR_802_11_PHY_11A:
      {
        struct ieee_802_11a *info_a = &phdr->phy_info.info_11a;

        if (info_a->has_channel_type) {
          proto_tree_add_uint(radio_tree, hf_wlan_radio_11a_channel_type, tvb, 0, 0,
                   info_a->channel_type);
        }
        if (info_a->has_turbo_type) {
          proto_tree_add_uint(radio_tree, hf_wlan_radio_11a_turbo_type, tvb, 0, 0,
                   info_a->turbo_type);
        }
        break;
      }

      case PHDR_802_11_PHY_11G:
      {
        struct ieee_802_11g *info_g = &phdr->phy_info.info_11g;

        has_short_preamble = info_g->has_short_preamble;
        short_preamble = info_g->short_preamble;

        if (has_short_preamble) {
          proto_tree_add_boolean(radio_tree, hf_wlan_radio_short_preamble, tvb, 0, 0,
                   short_preamble);
        }
        if (info_g->has_mode) {
          proto_tree_add_uint(radio_tree, hf_wlan_radio_11g_mode, tvb, 0, 0,
                   info_g->mode);
        }
        break;
      }

      case PHDR_802_11_PHY_11N:
        {
          struct ieee_802_11n *info_n = &phdr->phy_info.info_11n;
          guint bandwidth_40;

          if (info_n->has_mcs_index) {
            proto_tree_add_uint(radio_tree, hf_wlan_radio_11n_mcs_index, tvb, 0, 0,
                     info_n->mcs_index);
          }

          if (info_n->has_bandwidth) {
            proto_tree_add_uint(radio_tree, hf_wlan_radio_11n_bandwidth, tvb, 0, 0,
                     info_n->bandwidth);
          }

          if (info_n->has_short_gi) {
            proto_tree_add_boolean(radio_tree, hf_wlan_radio_11n_short_gi, tvb, 0, 0,
                     info_n->short_gi);
          }

          if (info_n->has_greenfield) {
            proto_tree_add_boolean(radio_tree, hf_wlan_radio_11n_greenfield, tvb, 0, 0,
                     info_n->greenfield);
          }

          if (info_n->has_fec) {
            proto_tree_add_uint(radio_tree, hf_wlan_radio_11n_fec, tvb, 0, 0,
                     info_n->fec);
          }

          if (info_n->has_stbc_streams) {
            proto_tree_add_uint(radio_tree, hf_wlan_radio_11n_stbc_streams, tvb, 0, 0,
                     info_n->stbc_streams);
          }

          if (info_n->has_ness) {
            proto_tree_add_uint(radio_tree, hf_wlan_radio_11n_ness, tvb, 0, 0,
                     info_n->ness);
          }

          /*
           * If we have all the fields needed to look up the data rate,
           * do so.
           */
          if (info_n->has_mcs_index &&
              info_n->has_bandwidth &&
              info_n->has_short_gi) {
            bandwidth_40 =
              (info_n->bandwidth == PHDR_802_11_BANDWIDTH_40_MHZ) ?
               1 : 0;
            if (info_n->mcs_index <= MAX_MCS_INDEX) {
              data_rate = ieee80211_htrate(info_n->mcs_index, bandwidth_40, info_n->short_gi);
              have_data_rate = TRUE;
            }
          }
        }
        break;

      case PHDR_802_11_PHY_11AC:
        {
          struct ieee_802_11ac *info_ac = &phdr->phy_info.info_11ac;
          gboolean can_calculate_rate;
          guint bandwidth = 0;
          guint i;

          if (info_ac->has_stbc) {
            proto_tree_add_boolean(radio_tree, hf_wlan_radio_11ac_stbc, tvb, 0, 0,
                     info_ac->stbc);
          }

          if (info_ac->has_txop_ps_not_allowed) {
            proto_tree_add_boolean(radio_tree, hf_wlan_radio_11ac_txop_ps_not_allowed, tvb, 0, 0,
                     info_ac->txop_ps_not_allowed);
          }

          if (info_ac->has_short_gi) {
            can_calculate_rate = TRUE;  /* well, if we also have the bandwidth */
            proto_tree_add_boolean(radio_tree, hf_wlan_radio_11ac_short_gi, tvb, 0, 0,
                     info_ac->short_gi);
          } else {
            can_calculate_rate = FALSE; /* unknown GI length */
          }

          if (info_ac->has_short_gi_nsym_disambig) {
            proto_tree_add_boolean(radio_tree, hf_wlan_radio_11ac_short_gi_nsym_disambig, tvb, 0, 0,
                     info_ac->short_gi_nsym_disambig);
          }

          if (info_ac->has_ldpc_extra_ofdm_symbol) {
            proto_tree_add_boolean(radio_tree, hf_wlan_radio_11ac_ldpc_extra_ofdm_symbol, tvb, 0, 0,
                     info_ac->ldpc_extra_ofdm_symbol);
          }

          if (info_ac->has_beamformed) {
            proto_tree_add_boolean(radio_tree, hf_wlan_radio_11ac_beamformed, tvb, 0, 0,
                     info_ac->beamformed);
          }

          if (info_ac->has_bandwidth) {
            if (info_ac->bandwidth < G_N_ELEMENTS(ieee80211_vht_bw2rate_index))
              bandwidth = ieee80211_vht_bw2rate_index[info_ac->bandwidth];
            else
              can_calculate_rate = FALSE; /* unknown bandwidth */
            proto_tree_add_uint(radio_tree, hf_wlan_radio_11ac_bandwidth, tvb, 0, 0,
                     info_ac->bandwidth);
          } else {
            can_calculate_rate = FALSE;   /* no bandwidth */
          }

          for (i = 0; i < 4; i++) {

            if (info_ac->nss[i] != 0) {
              proto_item *it;
              proto_tree *user_tree;

              it = proto_tree_add_item(radio_tree, hf_wlan_radio_11ac_user, tvb, 0, 0, ENC_NA);
              proto_item_append_text(it, " %d: MCS %u", i, info_ac->mcs[i]);
              user_tree = proto_item_add_subtree(it, ett_wlan_radio_11ac_user);

              it = proto_tree_add_uint(user_tree, hf_wlan_radio_11ac_mcs, tvb, 0, 0,
                      info_ac->mcs[i]);
              if (info_ac->mcs[i] > MAX_MCS_VHT_INDEX) {
                proto_item_append_text(it, " (invalid)");
              } else {
                proto_item_append_text(it, " (%s %s)",
                  ieee80211_vhtinfo[info_ac->mcs[i]].modulation,
                  ieee80211_vhtinfo[info_ac->mcs[i]].coding_rate);
              }

              proto_tree_add_uint(user_tree, hf_wlan_radio_11ac_nss, tvb, 0, 0,
                       info_ac->nss[i]);
              /*
               * If we don't know whether space-time block coding is being
               * used, we don't know the number of space-time streams.
               */
              if (info_ac->has_stbc) {
                guint nsts;

                if (info_ac->stbc)
                  nsts = 2 * info_ac->nss[i];
                else
                  nsts = info_ac->nss[i];
                proto_tree_add_uint(user_tree, hf_wlan_radio_11ac_nsts, tvb, 0, 0,
                       nsts);
              }
              if (info_ac->has_fec) {
                  proto_tree_add_uint(user_tree, hf_wlan_radio_11ac_fec, tvb, 0, 0,
                           (info_ac->fec >> i) & 0x01);
              }

              /*
               * If we can calculate the data rate for this user, do so.
               */
              if (can_calculate_rate && info_ac->mcs[i] <= MAX_MCS_VHT_INDEX &&
                  info_ac->nss[i] <= MAX_VHT_NSS &&
                  ieee80211_vhtvalid[info_ac->mcs[i]].valid[bandwidth][info_ac->nss[i]-1]) {
                data_rate = ieee80211_vhtrate(info_ac->mcs[i], bandwidth, info_ac->short_gi) * info_ac->nss[i];
                if (data_rate != 0.0f) {
                  proto_tree_add_float_format_value(user_tree, hf_wlan_radio_data_rate, tvb, 0, 0,
                        data_rate,
                        "%.1f Mb/s",
                       data_rate);
                }
              }
            }
          }

          if (info_ac->has_group_id) {
            proto_tree_add_uint(radio_tree, hf_wlan_radio_11ac_gid, tvb, 0, 0,
                     info_ac->group_id);
          }

          if (info_ac->has_partial_aid) {
            proto_tree_add_uint(radio_tree, hf_wlan_radio_11ac_p_aid, tvb, 0, 0,
                     info_ac->partial_aid);
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

    if (have_data_rate) {
      gboolean assumed_short_preamble = FALSE;
      gboolean assumed_non_greenfield = FALSE;
      gboolean assumed_no_stbc = FALSE;
      gboolean assumed_no_extension_streams = FALSE;
      gboolean assumed_bcc_fec = FALSE;

        /* some generators report CCK frames as 'dynamic-cck-ofdm', which are converted
         * into the 11g PHY type, so we need to be smart and recognize which ones are
         * DSSS/CCK and which are OFDM. Use the data_rate to do this. */
        int phy = phdr->phy;
        if (phy == PHDR_802_11_PHY_11G &&
          (data_rate == 1.0f || data_rate == 2.0f ||
          data_rate == 5.5f || data_rate == 11.0f ||
          data_rate == 22.0f || data_rate == 33.0f)) {
          phy = PHDR_802_11_PHY_11B;
        }

        switch (phy) {

        case PHDR_802_11_PHY_11_FHSS:
          break;

        case PHDR_802_11_PHY_11B:
          if (!has_short_preamble) {
              assumed_short_preamble = TRUE;
          }
          preamble = short_preamble ? 72 + 24 : 144 + 48;

          /* calculation of frame duration
           * Things we need to know to calculate accurate duration
           * 802.11 / 802.11b (DSSS or CCK modulation)
           * - length of preamble
           * - rate
           */
          /* round up to whole microseconds */
          duration = (guint) ceil(preamble + frame_length * 8 / data_rate);
          break;

        case PHDR_802_11_PHY_11A:
        case PHDR_802_11_PHY_11G:
        {
          /* OFDM rate */
          /* calculation of frame duration
           * Things we need to know to calculate accurate duration
           * 802.11a / 802.11g (OFDM modulation)
           * - rate
           */

          /* 16 service bits, data and 6 tail bits */
          guint bits = 16 + 8 * frame_length + 6;
          guint symbols = (guint) ceil(bits / (data_rate * 4));

          /* preamble + signal */
          preamble = 16 + 4;

          duration = preamble + symbols * 4;
          break;
        }

        case PHDR_802_11_PHY_11N:
        {
          struct ieee_802_11n *info_n = &phdr->phy_info.info_11n;
          guint bandwidth_40;

          /* We have all the fields required to calculate the duration */
          static const guint Nhtdltf[4] = {1, 2, 4, 4};
          static const guint Nhteltf[4] = {0, 1, 2, 4};
          guint Nsts, bits, Mstbc, bits_per_symbol, symbols;
          guint stbc_streams;
          guint ness;
          gboolean fec;

          /*
           * If we don't have necessary fields, or if we have them but
           * they have invalid values, then bail.
           */
          if (!info_n->has_mcs_index ||
            info_n->mcs_index > MAX_MCS_INDEX ||
            !info_n->has_bandwidth ||
            !info_n->has_short_gi)
              break;

          bandwidth_40 = info_n->bandwidth == PHDR_802_11_BANDWIDTH_40_MHZ;

          /* calculation of frame duration
           * Things we need to know to calculate accurate duration
           * 802.11n / HT
           * - whether frame preamble is mixed or greenfield, (assume mixed)
           * - guard interval, 800ns or 400ns
           * - bandwidth, 20Mhz or 40Mhz
           * - MCS index - used with previous 2 to calculate rate
           * - how many additional STBC streams are used (assume 0)
           * - how many optional extension spatial streams are used (assume 0)
           * - whether BCC or LDCP coding is used (assume BCC)
           */

          /* preamble duration
           * see ieee802.11n-2009 Figure 20-1 - PPDU format
           * for HT-mixed format
           * L-STF 8us, L-LTF 8us, L-SIG 4us, HT-SIG 8us, HT_STF 4us
           * for HT-greenfield
           * HT-GF-STF 8us, HT-LTF1 8us, HT_SIG 8us
           */
          if (info_n->has_greenfield) {
            preamble = info_n->greenfield ? 24 : 32;
          } else {
            preamble = 32;
            assumed_non_greenfield = TRUE;
          }

          if (info_n->has_stbc_streams) {
            stbc_streams = info_n->stbc_streams;
          } else {
            stbc_streams = 0;
            assumed_no_stbc = TRUE;
          }

          if (info_n->has_ness) {
            ness = info_n->ness;
            if (ness >= G_N_ELEMENTS(Nhteltf)) {
                /* Not valid */
                break;
            }
          } else {
            ness = 0;
            assumed_no_extension_streams = TRUE;
          }

          /* calculate number of HT-LTF training symbols.
           * see ieee80211n-2009 20.3.9.4.6 table 20-11 */
          Nsts = ieee80211_ht_streams[info_n->mcs_index] + stbc_streams;
          if (Nsts == 0 || Nsts - 1 >= G_N_ELEMENTS(Nhtdltf)) {
              /* Not usable */
              break;
          }
          preamble += 4 * (Nhtdltf[Nsts-1] + Nhteltf[ness]);

          if (info_n->has_fec) {
            fec = info_n->fec;
          } else {
            fec = 0;
            assumed_bcc_fec = TRUE;
          }

          /* data field calculation */
          if (fec == 0) {
            /* see ieee80211n-2009 20.3.11 (20-32) - for BCC FEC */
            bits = 8 * frame_length + 16 + ieee80211_ht_Nes[info_n->mcs_index] * 6;
            Mstbc = stbc_streams ? 2 : 1;
            bits_per_symbol = ieee80211_ht_Dbps[info_n->mcs_index] * (bandwidth_40 ? 2 : 1);
            symbols = bits / (bits_per_symbol * Mstbc);
          } else {
            /* TODO: handle LDPC FEC, it changes the rounding
             * Currently this is the same logic as BCC */
            bits = 8 * frame_length + 16 + ieee80211_ht_Nes[info_n->mcs_index] * 6;
            Mstbc = stbc_streams ? 2 : 1;
            bits_per_symbol = ieee80211_ht_Dbps[info_n->mcs_index] * (bandwidth_40 ? 2 : 1);
            symbols = bits / (bits_per_symbol * Mstbc);
          }

          /* round up to whole symbols */
          if((bits % (bits_per_symbol * Mstbc)) > 0)
            symbols++;

          symbols *= Mstbc;
          duration = preamble + (symbols * (info_n->short_gi ? 36 : 40) + 5) / 10;
          break;
        }

        case PHDR_802_11_PHY_11AC:
        {
          struct ieee_802_11ac *info_ac = &phdr->phy_info.info_11ac;
          int bits, stbc;

          /* TODO: this is a crude quick hack, need proper calculation of bits/symbols/FEC/rounding/etc */
          if (info_ac->has_stbc) {
            stbc = info_ac->stbc;
          } else {
            stbc = 0;
            assumed_no_stbc = TRUE;
          }

          preamble = 32 + 4 * info_ac->nss[0] * (stbc+1);
          bits = 8 * frame_length + 16;
          duration = (guint) (preamble + bits / data_rate);
          break;
        }
      }

    if (duration) {
        proto_item *item = proto_tree_add_uint_format_value(radio_tree, hf_wlan_radio_duration, tvb, 0, 0,
                duration,
                "%d us",
                duration);
        PROTO_ITEM_SET_GENERATED(item);

        if (assumed_short_preamble)
          expert_add_info(pinfo, item, &ei_wlan_radio_assumed_short_preamble);
        if (assumed_non_greenfield)
          expert_add_info(pinfo, item, &ei_wlan_radio_assumed_non_greenfield);
        if (assumed_no_stbc)
          expert_add_info(pinfo, item, &ei_wlan_radio_assumed_no_stbc);
        if (assumed_no_extension_streams)
          expert_add_info(pinfo, item, &ei_wlan_radio_assumed_no_extension_streams);
        if (assumed_bcc_fec)
          expert_add_info(pinfo, item, &ei_wlan_radio_assumed_bcc_fec);

        if (preamble) {
          proto_tree *d_tree = proto_item_add_subtree(item, ett_wlan_radio_duration);
          proto_item *p_item = proto_tree_add_uint_format_value(d_tree, hf_wlan_radio_preamble, tvb, 0, 0,
                    preamble,
                    "%d us",
                    preamble);
            PROTO_ITEM_SET_GENERATED(p_item);
        }
      }
    }
  } /* if (tree) */
}

/*
 * Dissect 802.11 with a variable-length link-layer header and a pseudo-
 * header containing radio information.
 */
static int
dissect_wlan_radio (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void *data)
{
  dissect_wlan_radio_phdr (tvb, pinfo, tree, data);

  /* dissect the 802.11 packet next */
  return call_dissector_with_data(ieee80211_handle, tvb, pinfo, tree, data);
}

/*
 * Dissect 802.11 with a variable-length link-layer header without qos elements and
 * a pseudo-header containing radio information.
 */
static int
dissect_wlan_noqos_radio (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void *data)
{
  dissect_wlan_radio_phdr (tvb, pinfo, tree, data);

  /* dissect the 802.11 packet next */
  return call_dissector_with_data(ieee80211_noqos_handle, tvb, pinfo, tree, data);
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

    {&hf_wlan_radio_duration,
     {"Duration", "wlan_radio.duration", FT_UINT32, BASE_DEC, NULL, 0,
      "Total duration of the frame in microseconds, including any preamble or plcp header. "
      "Calculated from the frame length, modulation and other phy data.", HFILL }},

    {&hf_wlan_radio_preamble,
     {"Preamble", "wlan_radio.preamble", FT_UINT32, BASE_DEC, NULL, 0,
      "Duration of the PLCP or preamble in microseconds, calculated from PHY data", HFILL }},

};

static ei_register_info ei[] = {
    { &ei_wlan_radio_assumed_short_preamble,
      { "wlan_radio.assumed.short_preamble", PI_ASSUMPTION, PI_WARN,
        "No preamble length information was available, assuming short preamble.", EXPFILL }},

    { &ei_wlan_radio_assumed_non_greenfield,
      { "wlan_radio.assumed.non_greenfield", PI_ASSUMPTION, PI_WARN,
        "No plcp type information was available, assuming non greenfield.", EXPFILL }},

    { &ei_wlan_radio_assumed_no_stbc,
      { "wlan_radio.assumed.no_stbc", PI_ASSUMPTION, PI_WARN,
        "No stbc information was available, assuming no stbc.", EXPFILL }},

    { &ei_wlan_radio_assumed_no_extension_streams,
      { "wlan_radio.assumed.no_extension_streams", PI_ASSUMPTION, PI_WARN,
        "No extension stream information was available, assuming no extension streams.", EXPFILL }},

    { &ei_wlan_radio_assumed_bcc_fec,
      { "wlan_radio.assumed.bcc_fec", PI_ASSUMPTION, PI_WARN,
        "No fec type information was available, assuming bcc fec.", EXPFILL }},
};

expert_module_t* expert_wlan_radio;

static gint *tree_array[] = {
  &ett_wlan_radio,
  &ett_wlan_radio_11ac_user,
  &ett_wlan_radio_duration
};

void proto_register_ieee80211_radio(void)
{
  proto_wlan_radio = proto_register_protocol("802.11 radio information", "802.11 Radio",
                                             "wlan_radio");
  proto_register_field_array(proto_wlan_radio, hf_wlan_radio, array_length(hf_wlan_radio));
  proto_register_subtree_array(tree_array, array_length(tree_array));

  expert_wlan_radio = expert_register_protocol(proto_wlan_radio);
  expert_register_field_array(expert_wlan_radio, ei, array_length(ei));

  wlan_radio_handle = register_dissector("wlan_radio", dissect_wlan_radio, proto_wlan_radio);
  wlan_noqos_radio_handle = register_dissector("wlan_noqos_radio", dissect_wlan_noqos_radio, proto_wlan_radio);
}

void proto_reg_handoff_ieee80211_radio(void)
{
  /* Register handoff to radio-header dissectors */
  dissector_add_uint("wtap_encap", WTAP_ENCAP_IEEE_802_11_WITH_RADIO,
                     wlan_radio_handle);
  ieee80211_handle = find_dissector_add_dependency("wlan", proto_wlan_radio);
  ieee80211_noqos_handle = find_dissector_add_dependency("wlan_noqos", proto_wlan_radio);
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
